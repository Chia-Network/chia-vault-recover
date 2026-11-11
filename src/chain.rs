//! Blockchain backends: coinset (default) and optional full-node RPC.

use std::fmt::Display;
use std::future::Future;
use std::time::Duration;

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzle_types::{EveProof, LineageProof, Proof};
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_sdk_coinset::{ChiaRpcClient, CoinRecord, CoinsetClient};
use chia_sdk_driver::{Layer, SingletonLayer, SpendContext};

use crate::error::{Error, Result};
use crate::network::{Backend, Network};
use crate::scan::HeightRange;

/// Longest wait for one RPC response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest wait for one page of a launcher scan; a busy 5-day range takes about 100s on coinset.
const SCAN_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// Most pages followed for one launcher scan before giving up.
const MAX_SCAN_PAGES: usize = 100;
/// Most 32-block windows searched for a transaction block's timestamp.
const MAX_TIMESTAMP_WINDOWS: u32 = 8;
/// Most coin records buffered for one paged request. A busy 5-day launcher scan
/// stays well below this.
const MAX_SCAN_RECORDS: usize = 500_000;

/// Per-page timeout and error hint for one paged coin-record request.
#[derive(Debug, Clone, Copy)]
struct PageLimits {
    timeout: Duration,
    hint: &'static str,
    max_records: usize,
}

const COIN_PAGE_LIMITS: PageLimits = PageLimits {
    timeout: REQUEST_TIMEOUT,
    hint: "",
    max_records: MAX_SCAN_RECORDS,
};

const SCAN_PAGE_LIMITS: PageLimits = PageLimits {
    timeout: SCAN_REQUEST_TIMEOUT,
    hint: "; try a narrower range",
    max_records: MAX_SCAN_RECORDS,
};

pub struct ChainClient<C = CoinsetClient> {
    inner: C,
}

impl ChainClient {
    pub fn new(network: Network, backend: &Backend) -> Self {
        let url = match backend {
            Backend::Coinset => network.coinset_url().to_string(),
            Backend::FullNode { url } => url.trim_end_matches('/').to_string(),
        };
        Self {
            inner: CoinsetClient::new(url),
        }
    }
}

impl<C> ChainClient<C>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    #[cfg(test)]
    pub(crate) fn with_rpc(inner: C) -> Self {
        Self { inner }
    }

    /// Await one RPC call, failing after [`REQUEST_TIMEOUT`].
    async fn call<T>(
        &self,
        method: &str,
        request: impl Future<Output = std::result::Result<T, C::Error>>,
    ) -> Result<T> {
        self.call_within(method, REQUEST_TIMEOUT, "", request).await
    }

    /// Await one RPC call, failing after `limit` with `timeout_hint` appended to the error.
    async fn call_within<T>(
        &self,
        method: &str,
        limit: Duration,
        timeout_hint: &str,
        request: impl Future<Output = std::result::Result<T, C::Error>>,
    ) -> Result<T> {
        match tokio::time::timeout(limit, request).await {
            Ok(response) => response.map_err(|e| Error::msg(format!("{method} failed: {e}"))),
            Err(_) => Err(Error::msg(format!(
                "{method} timed out after {}s{timeout_hint}",
                limit.as_secs()
            ))),
        }
    }

    pub async fn find_unspent_by_puzzle_hash(&self, puzzle_hash: Bytes32) -> Result<Option<Coin>> {
        Ok(self
            .find_coins_by_puzzle_hash(puzzle_hash, false)
            .await?
            .into_iter()
            .find(|r| !r.spent)
            .map(|r| r.coin))
    }

    /// Coins at `puzzle_hash`, following the cursor for at most 8 pages.
    ///
    /// A partial list is acceptable for every caller: each needs only one matching
    /// record, every candidate is checked against the address, and when none matches
    /// the lookup falls through to its next step or the opt-in launcher scan. When
    /// the node leaves pages unread, the records read so far are returned.
    pub async fn find_coins_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>> {
        let (records, _) = self
            .paged_coin_records(puzzle_hash, None, None, include_spent, 8, COIN_PAGE_LIMITS)
            .await?;
        Ok(records)
    }

    /// Every singleton launcher coin confirmed in `range`.
    /// Fails rather than return a partial list.
    pub async fn find_launchers_between(&self, range: HeightRange) -> Result<Vec<CoinRecord>> {
        let (records, complete) = self
            .paged_coin_records(
                SINGLETON_LAUNCHER_HASH.into(),
                Some(range.start()),
                Some(range.end()),
                true,
                MAX_SCAN_PAGES,
                SCAN_PAGE_LIMITS,
            )
            .await?;
        if !complete {
            return Err(Error::msg(format!(
                "could not list every launcher in {range}: the node stopped paging or sent over \
                 {MAX_SCAN_PAGES} pages; try a narrower range"
            )));
        }
        Ok(records)
    }

    /// Coin records at `puzzle_hash`, following the cursor for at most `max_pages`.
    /// The flag is false when pages remain, or the node truncated without a new cursor.
    async fn paged_coin_records(
        &self,
        puzzle_hash: Bytes32,
        start_height: Option<u32>,
        end_height: Option<u32>,
        include_spent: bool,
        max_pages: usize,
        limits: PageLimits,
    ) -> Result<(Vec<CoinRecord>, bool)> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..max_pages {
            let response = self
                .call_within(
                    "get_coin_records_by_puzzle_hash",
                    limits.timeout,
                    limits.hint,
                    self.inner.get_coin_records_by_puzzle_hash(
                        puzzle_hash,
                        start_height,
                        end_height,
                        Some(include_spent),
                        cursor.clone(),
                    ),
                )
                .await?;
            all.extend(response.coin_records.unwrap_or_default());
            if all.len() > limits.max_records {
                return Err(Error::msg(format!(
                    "the node returned over {} coin records; narrow the request",
                    limits.max_records
                )));
            }
            if response.truncated != Some(true) {
                return Ok((all, true));
            }
            match response.next_cursor {
                Some(next) if cursor.as_ref() != Some(&next) => cursor = Some(next),
                _ => return Ok((all, false)),
            }
        }
        Ok((all, false))
    }

    async fn peak_height(&self) -> Result<u32> {
        let state = self
            .call("get_blockchain_state", self.inner.get_blockchain_state())
            .await?;
        Ok(state
            .blockchain_state
            .ok_or_else(|| Error::msg("get_blockchain_state returned no state"))?
            .peak
            .height)
    }

    /// Lowest height whose transaction block is at or after `timestamp` (unix seconds).
    /// Returns one past the peak when every block is earlier, so an exclusive end keeps the tip.
    pub async fn height_at_or_after(&self, timestamp: u64) -> Result<u32> {
        let peak = self.peak_height().await?;
        first_height_at_or_after(peak, timestamp, |height| {
            self.transaction_timestamp_from(height, peak)
        })
        .await
    }

    /// Block-height bounds `(start, end)` from a `from` timestamp (inclusive) to a
    /// `to` timestamp (exclusive). Reads the peak once so both bounds use the same
    /// chain tip. `start >= end` when the timestamps fall outside the chain's block times.
    pub async fn height_range_for_timestamps(&self, from: u64, to: u64) -> Result<(u32, u32)> {
        let peak = self.peak_height().await?;
        let start = first_height_at_or_after(peak, from, |height| {
            self.transaction_timestamp_from(height, peak)
        })
        .await?;
        let end = first_height_at_or_after(peak, to, |height| {
            self.transaction_timestamp_from(height, peak)
        })
        .await?;
        Ok((start, end))
    }

    /// Timestamp of the first transaction block at or above `height` (only those carry one).
    /// `None` when no transaction block is left up to `peak`.
    async fn transaction_timestamp_from(&self, height: u32, peak: u32) -> Result<Option<u64>> {
        const WINDOW: u32 = 32;
        let mut start = height;
        for _ in 0..MAX_TIMESTAMP_WINDOWS {
            if start > peak {
                return Ok(None);
            }
            let end = start.saturating_add(WINDOW).min(peak + 1);
            let response = self
                .call(
                    "get_block_records",
                    self.inner.get_block_records(start, end),
                )
                .await?;
            if let Some(ts) = response
                .block_records
                .unwrap_or_default()
                .iter()
                .filter(|r| r.height >= height && r.timestamp.is_some())
                .min_by_key(|r| r.height)
                .and_then(|r| r.timestamp)
            {
                return Ok(Some(ts));
            }
            start = end;
        }
        if start > peak {
            return Ok(None);
        }
        Err(Error::msg(format!(
            "no block timestamps in blocks {height}..{start}; the node may not serve block records"
        )))
    }

    /// Hint index is optional. Any RPC failure other than a timeout is treated as
    /// "hint index unavailable" and returns an empty list. A timeout is reported as
    /// an error.
    pub async fn find_coins_by_hint(
        &self,
        hint: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>> {
        self.find_coins_by_hint_within(hint, include_spent, REQUEST_TIMEOUT)
            .await
    }

    async fn find_coins_by_hint_within(
        &self,
        hint: Bytes32,
        include_spent: bool,
        limit: Duration,
    ) -> Result<Vec<CoinRecord>> {
        let request =
            self.inner
                .get_coin_records_by_hint(hint, None, None, Some(include_spent), None);
        match tokio::time::timeout(limit, request).await {
            Ok(Ok(response)) => Ok(response.coin_records.unwrap_or_default()),
            Ok(Err(_)) => Ok(Vec::new()),
            Err(_) => Err(Error::msg(format!(
                "get_coin_records_by_hint timed out after {}s",
                limit.as_secs()
            ))),
        }
    }

    pub async fn get_coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>> {
        let response = self
            .call(
                "get_coin_record_by_name",
                self.inner.get_coin_record_by_name(coin_id),
            )
            .await?;
        Ok(response.coin_record)
    }

    pub async fn get_children(&self, parent_id: Bytes32) -> Result<Vec<CoinRecord>> {
        let response = self
            .call(
                "get_coin_records_by_parent_ids",
                self.inner.get_coin_records_by_parent_ids(
                    vec![parent_id],
                    None,
                    None,
                    Some(true),
                    None,
                ),
            )
            .await?;
        Ok(response.coin_records.unwrap_or_default())
    }

    pub async fn get_spend(
        &self,
        coin_id: Bytes32,
        spent_height: u32,
    ) -> Result<Option<CoinSpend>> {
        let response = self
            .call(
                "get_puzzle_and_solution",
                self.inner
                    .get_puzzle_and_solution(coin_id, Some(spent_height)),
            )
            .await?;
        Ok(response.coin_solution)
    }

    /// Walk the singleton from `launcher_id` to the current unspent coin.
    /// Returns `(spent_ancestors, current_unspent)`.
    pub async fn walk_singleton_chain(
        &self,
        launcher_id: Bytes32,
    ) -> Result<(Vec<CoinRecord>, CoinRecord)> {
        let mut parent = launcher_id;
        let mut spent = Vec::new();
        for _ in 0..1024 {
            let children = self.get_children(parent).await?;
            let Some(child) = children.into_iter().find(|r| r.coin.amount % 2 == 1) else {
                return Err(Error::msg(
                    "no singleton child found — launcher id may be wrong or the vault was never launched",
                ));
            };
            if !child.spent {
                return Ok((spent, child));
            }
            parent = child.coin.coin_id();
            spent.push(child);
        }
        Err(Error::msg("singleton chain exceeded 1024 coins"))
    }

    /// Build a lineage (or eve) proof for a singleton coin from its parent spend.
    pub async fn lineage_proof_for_coin(&self, coin: &Coin) -> Result<Proof> {
        let parent_record = self
            .get_coin_record(coin.parent_coin_info)
            .await?
            .ok_or_else(|| Error::msg("parent coin record not found"))?;

        let Some(coin_solution) = self
            .get_spend(coin.parent_coin_info, parent_record.spent_block_index)
            .await?
        else {
            return Ok(Proof::Eve(EveProof {
                parent_parent_coin_info: parent_record.coin.parent_coin_info,
                parent_amount: parent_record.coin.amount,
            }));
        };

        match singleton_inner_puzzle_hash(&coin_solution.puzzle_reveal) {
            Ok(inner_puzzle_hash) => Ok(Proof::Lineage(LineageProof {
                parent_parent_coin_info: parent_record.coin.parent_coin_info,
                parent_inner_puzzle_hash: inner_puzzle_hash,
                parent_amount: parent_record.coin.amount,
            })),
            Err(_) => Ok(Proof::Eve(EveProof {
                parent_parent_coin_info: parent_record.coin.parent_coin_info,
                parent_amount: parent_record.coin.amount,
            })),
        }
    }

    pub async fn push_tx(&self, spend_bundle: &SpendBundle) -> Result<String> {
        // A node can accept the bundle and still answer late, so a timeout is not a failure.
        let response = self
            .call_within(
                "push_tx",
                REQUEST_TIMEOUT,
                "; the transaction may still have been submitted, so check the vault on chain before retrying",
                self.inner.push_tx(spend_bundle.clone()),
            )
            .await?;
        if let Some(status) = response.status
            && status != "SUCCESS"
        {
            return Err(Error::msg(format!(
                "push_tx status {status}: {:?}",
                response.error
            )));
        }
        let id = spend_bundle
            .coin_spends
            .first()
            .map(|cs: &CoinSpend| hex::encode(cs.coin.coin_id()))
            .unwrap_or_default();
        Ok(id)
    }
}

/// Binary search over `0..=peak + 1`. `timestamp_from(h)` is the timestamp of the first
/// transaction block at or above `h`, or `None` when there is none up to `peak`.
async fn first_height_at_or_after<F, Fut>(
    peak: u32,
    timestamp: u64,
    mut timestamp_from: F,
) -> Result<u32>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<Option<u64>>>,
{
    let (mut lo, mut hi) = (0, peak.saturating_add(1));
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match timestamp_from(mid).await? {
            Some(ts) if ts >= timestamp => hi = mid,
            Some(_) => lo = mid + 1,
            None => hi = mid,
        }
    }
    Ok(lo)
}

fn singleton_inner_puzzle_hash(puzzle: &chia_protocol::Program) -> Result<Bytes32> {
    use chia_sdk_driver::Puzzle;

    let mut ctx = SpendContext::new();
    let ptr = ctx
        .alloc(puzzle)
        .map_err(|e| Error::msg(format!("alloc parent puzzle: {e}")))?;
    let puzzle = Puzzle::parse(&ctx, ptr);
    let layer = SingletonLayer::<clvmr::NodePtr>::parse_puzzle(&ctx, puzzle)
        .map_err(|e| Error::msg(format!("parse singleton layer: {e}")))?
        .ok_or_else(|| Error::msg("parent puzzle is not a singleton"))?;
    Ok(ctx.tree_hash(layer.inner_puzzle).into())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chia_sdk_coinset::ChiaRpcClient;
    use serde_json::json;

    use super::*;
    use crate::test_rpc::{ScriptedRpc, block_record, page, record};

    struct NeverRpc;

    impl ChiaRpcClient for NeverRpc {
        type Error = String;

        fn base_url(&self) -> &str {
            "never"
        }

        async fn make_post_request<R, B>(
            &self,
            _endpoint: &str,
            _body: B,
        ) -> std::result::Result<R, String>
        where
            B: serde::Serialize + Send,
            R: serde::de::DeserializeOwned + Send,
        {
            std::future::pending().await
        }
    }

    struct FailingRpc(&'static str);

    impl ChiaRpcClient for FailingRpc {
        type Error = String;

        fn base_url(&self) -> &str {
            "failing"
        }

        async fn make_post_request<R, B>(
            &self,
            _endpoint: &str,
            _body: B,
        ) -> std::result::Result<R, String>
        where
            B: serde::Serialize + Send,
            R: serde::de::DeserializeOwned + Send,
        {
            Err(self.0.to_string())
        }
    }

    /// Transaction blocks at every third height up to 99, timestamped `1000 + 10 * height`.
    async fn height_for(timestamp: u64) -> u32 {
        first_height_at_or_after(99, timestamp, |height| async move {
            let tx = height.div_ceil(3) * 3;
            Ok((tx <= 99).then(|| 1000 + 10 * u64::from(tx)))
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn height_search_finds_the_first_block_at_or_after() {
        assert_eq!(height_for(0).await, 0);
        assert_eq!(height_for(1000).await, 0);
        assert_eq!(height_for(1005).await, 1);
        assert_eq!(height_for(1030).await, 1);
        assert_eq!(height_for(1031).await, 4);
        assert_eq!(height_for(1990).await, 97);
        // Every block is earlier: one past the peak, so a window ending later keeps the tip.
        assert_eq!(height_for(5000).await, 100);
    }

    #[tokio::test]
    async fn call_within_times_out_when_the_node_does_not_respond() {
        let client = ChainClient::with_rpc(NeverRpc);
        let err = client
            .call_within(
                "get_blockchain_state",
                Duration::from_millis(10),
                "",
                client.inner.get_blockchain_state(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[tokio::test]
    async fn repeated_cursor_stops_the_scan() {
        let rpc = ScriptedRpc::new(|endpoint, _| match endpoint {
            "get_coin_records_by_puzzle_hash" => Some(page(&[], Some("same"), true)),
            _ => None,
        });
        let err = ChainClient::with_rpc(rpc)
            .find_launchers_between(HeightRange::new(1, 2).unwrap())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("narrower range"), "{err}");
    }

    #[tokio::test]
    async fn scan_stops_after_the_page_cap() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let rpc = ScriptedRpc::new(move |endpoint, _| match endpoint {
            "get_coin_records_by_puzzle_hash" => {
                let next = counter.fetch_add(1, Ordering::Relaxed);
                let cursor = format!("cursor-{next}");
                Some(page(&[], Some(&cursor), true))
            }
            _ => None,
        });
        let err = ChainClient::with_rpc(rpc)
            .find_launchers_between(HeightRange::new(1, 2).unwrap())
            .await
            .unwrap_err();
        assert_eq!(calls.load(Ordering::Relaxed), MAX_SCAN_PAGES);
        assert!(err.to_string().contains("narrower range"), "{err}");
    }

    #[tokio::test]
    async fn repeated_cursor_returns_coin_records_read_so_far() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let coin = Coin::new(Bytes32::new([1; 32]), Bytes32::default(), 1);
        let rpc = ScriptedRpc::new(move |endpoint, _| match endpoint {
            "get_coin_records_by_puzzle_hash" => {
                counter.fetch_add(1, Ordering::Relaxed);
                Some(page(&[record(coin, None)], Some("same"), true))
            }
            _ => None,
        });
        let records = ChainClient::with_rpc(rpc)
            .find_coins_by_puzzle_hash(Bytes32::default(), false)
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn paged_records_stop_at_the_record_cap() {
        let records = [
            record(
                Coin::new(Bytes32::new([1; 32]), Bytes32::default(), 1),
                None,
            ),
            record(
                Coin::new(Bytes32::new([2; 32]), Bytes32::default(), 1),
                None,
            ),
            record(
                Coin::new(Bytes32::new([3; 32]), Bytes32::default(), 1),
                None,
            ),
        ];
        let rpc = ScriptedRpc::new(move |endpoint, _| match endpoint {
            "get_coin_records_by_puzzle_hash" => Some(page(&records, None, false)),
            _ => None,
        });
        let limits = PageLimits {
            timeout: Duration::from_secs(1),
            hint: "",
            max_records: 2,
        };
        let err = ChainClient::with_rpc(rpc)
            .paged_coin_records(Bytes32::default(), None, None, false, 1, limits)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("over 2 coin records"), "{err}");
    }

    #[tokio::test]
    async fn timestamp_search_stops_after_the_window_cap() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let rpc = ScriptedRpc::new(move |endpoint, body| match endpoint {
            "get_block_records" => {
                counter.fetch_add(1, Ordering::Relaxed);
                let start = body["start"].as_u64()? as u32;
                let end = body["end"].as_u64()? as u32;
                let records: Vec<_> = (start..end).map(|h| block_record(h, None)).collect();
                Some(json!({ "block_records": records, "success": true }))
            }
            _ => None,
        });
        let err = ChainClient::with_rpc(rpc)
            .transaction_timestamp_from(0, 10_000)
            .await
            .unwrap_err();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            MAX_TIMESTAMP_WINDOWS as usize
        );
        assert!(err.to_string().contains("no block timestamps"), "{err}");
    }

    #[tokio::test]
    async fn hint_rpc_error_is_empty() {
        let client = ChainClient::with_rpc(FailingRpc("connection reset"));
        let records = client
            .find_coins_by_hint(Bytes32::default(), false)
            .await
            .unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn hint_timeout_is_returned() {
        let client = ChainClient::with_rpc(NeverRpc);
        let err = client
            .find_coins_by_hint_within(Bytes32::default(), false, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }
}
