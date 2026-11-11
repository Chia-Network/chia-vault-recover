//! Blockchain backends: coinset (default) and optional full-node RPC.

use std::fmt::Display;
use std::future::Future;
use std::ops::ControlFlow;
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
const MAX_RECORDS: usize = 500_000;
/// How often a launcher match yields to the runtime so a cancelled task or a
/// deadline can take effect.
const YIELD_AFTER_RECORDS: usize = 64;

/// Per-page limits and error hint for one paged coin-record request.
#[derive(Debug, Clone, Copy)]
struct PageLimits {
    timeout: Duration,
    hint: &'static str,
    max_pages: usize,
    max_records: usize,
}

const COIN_PAGE_LIMITS: PageLimits = PageLimits {
    timeout: REQUEST_TIMEOUT,
    hint: "",
    max_pages: 8,
    max_records: MAX_RECORDS,
};

const SCAN_PAGE_LIMITS: PageLimits = PageLimits {
    timeout: SCAN_REQUEST_TIMEOUT,
    hint: "; try a narrower range",
    max_pages: MAX_SCAN_PAGES,
    max_records: MAX_RECORDS,
};

/// How one paged request ended: the listing finished, ran out of pages or
/// records, or a visitor stopped it with a match.
enum Paged {
    Complete,
    Incomplete,
    Matched(Bytes32),
}

/// The coin records to page through.
#[derive(Debug, Clone, Copy)]
struct CoinQuery {
    puzzle_hash: Bytes32,
    start_height: Option<u32>,
    end_height: Option<u32>,
    include_spent: bool,
}

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
        self.call_within_raw(method, limit, timeout_hint, request)
            .await
            .map_err(RpcFailure::into_error)
    }

    /// Like [`Self::call_within`], but keeps a timeout distinguishable from another failure.
    async fn call_within_raw<T>(
        &self,
        method: &str,
        limit: Duration,
        timeout_hint: &str,
        request: impl Future<Output = std::result::Result<T, C::Error>>,
    ) -> std::result::Result<T, RpcFailure> {
        match tokio::time::timeout(limit, request).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(e)) => Err(RpcFailure::Failed(Error::msg(format!(
                "{method} failed: {e}"
            )))),
            Err(_) => Err(RpcFailure::Timeout(Error::msg(format!(
                "{method} timed out after {}s{timeout_hint}",
                limit.as_secs()
            )))),
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

    /// Coins at `puzzle_hash`, following the cursor for at most 8 pages and
    /// stopping at the record cap.
    ///
    /// A partial list is acceptable for every caller: each needs only one matching
    /// record, every candidate is checked against the address, and when none matches
    /// the lookup falls through to its next step or the opt-in launcher scan. When
    /// the node leaves pages unread, the record cap is reached, or the node truncates
    /// without a new cursor, the records read so far are returned.
    pub async fn find_coins_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>> {
        self.find_coins_by_puzzle_hash_with(puzzle_hash, include_spent, COIN_PAGE_LIMITS)
            .await
    }

    async fn find_coins_by_puzzle_hash_with(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
        limits: PageLimits,
    ) -> Result<Vec<CoinRecord>> {
        let query = CoinQuery {
            puzzle_hash,
            start_height: None,
            end_height: None,
            include_spent,
        };
        let mut records = Vec::new();
        self.paged_coin_records(query, limits, |record| {
            records.push(*record);
            ControlFlow::Continue(())
        })
        .await?;
        Ok(records)
    }

    /// The first singleton launcher in `range` for which `matches` is true.
    /// Fails rather than report no match when the listing was incomplete.
    pub async fn find_launcher_matching(
        &self,
        range: HeightRange,
        matches: impl FnMut(Bytes32) -> bool,
    ) -> Result<Option<Bytes32>> {
        self.find_launcher_matching_with(range, SCAN_PAGE_LIMITS, matches)
            .await
    }

    async fn find_launcher_matching_with(
        &self,
        range: HeightRange,
        limits: PageLimits,
        mut matches: impl FnMut(Bytes32) -> bool,
    ) -> Result<Option<Bytes32>> {
        let query = CoinQuery {
            puzzle_hash: SINGLETON_LAUNCHER_HASH.into(),
            start_height: Some(range.start()),
            end_height: Some(range.end()),
            include_spent: true,
        };
        let paged = self
            .paged_coin_records(query, limits, |record| {
                let id = record.coin.coin_id();
                if matches(id) {
                    ControlFlow::Break(id)
                } else {
                    ControlFlow::Continue(())
                }
            })
            .await?;
        match paged {
            Paged::Matched(launcher) => Ok(Some(launcher)),
            Paged::Complete => Ok(None),
            Paged::Incomplete => Err(incomplete_scan(range, limits)),
        }
    }

    /// Page through coin records, calling `visit` for each one until it returns
    /// [`ControlFlow::Break`]. Yields to the runtime every few records so a
    /// cancelled task or a deadline can take effect.
    async fn paged_coin_records(
        &self,
        query: CoinQuery,
        limits: PageLimits,
        mut visit: impl FnMut(&CoinRecord) -> ControlFlow<Bytes32>,
    ) -> Result<Paged> {
        let mut count = 0;
        let mut cursor: Option<String> = None;
        for _ in 0..limits.max_pages {
            let response = self
                .call_within(
                    "get_coin_records_by_puzzle_hash",
                    limits.timeout,
                    limits.hint,
                    self.inner.get_coin_records_by_puzzle_hash(
                        query.puzzle_hash,
                        query.start_height,
                        query.end_height,
                        Some(query.include_spent),
                        cursor.clone(),
                    ),
                )
                .await?;
            let page = response.coin_records.unwrap_or_default();
            for record in &page {
                if count % YIELD_AFTER_RECORDS == 0 {
                    tokio::task::yield_now().await;
                }
                count += 1;
                if let ControlFlow::Break(id) = visit(record) {
                    return Ok(Paged::Matched(id));
                }
            }
            if count > limits.max_records {
                return Ok(Paged::Incomplete);
            }
            if response.truncated != Some(true) {
                return Ok(Paged::Complete);
            }
            match response.next_cursor {
                Some(next) if cursor.as_ref() != Some(&next) => cursor = Some(next),
                _ => return Ok(Paged::Incomplete),
            }
        }
        Ok(Paged::Incomplete)
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

    /// Block-height bounds from a `from` timestamp (inclusive) to a `to` timestamp
    /// (exclusive). Reads the peak once so both bounds use the same chain tip.
    /// `None` when the timestamps fall outside the chain's block times.
    pub async fn height_range_for_timestamps(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Option<HeightRange>> {
        let peak = self.peak_height().await?;
        let timestamp_from = |height| self.transaction_timestamp_from(height, peak);
        let start = first_height_at_or_after(peak, from, timestamp_from).await?;
        let end = first_height_at_or_after(peak, to, timestamp_from).await?;
        Ok(HeightRange::new(start, end).ok())
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
        match self
            .call_within_raw("get_coin_records_by_hint", limit, "", request)
            .await
        {
            Ok(response) => Ok(response.coin_records.unwrap_or_default()),
            Err(RpcFailure::Timeout(e)) => Err(e),
            Err(RpcFailure::Failed(_)) => Ok(Vec::new()),
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

enum RpcFailure {
    Timeout(Error),
    Failed(Error),
}

impl RpcFailure {
    fn into_error(self) -> Error {
        match self {
            Self::Timeout(error) | Self::Failed(error) => error,
        }
    }
}

fn incomplete_scan(range: HeightRange, limits: PageLimits) -> Error {
    Error::msg(format!(
        "could not list every launcher in {range}: the node stopped paging or sent over {} pages or {} coin records; try a narrower range",
        limits.max_pages, limits.max_records
    ))
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
    use crate::test_rpc::{NeverRpc, ScriptedRpc, block_record, page, record};

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
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            client.call_within(
                "get_blockchain_state",
                Duration::from_millis(10),
                "",
                client.inner.get_blockchain_state(),
            ),
        )
        .await
        .expect("call_within should apply its timeout")
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
            .find_launcher_matching(HeightRange::new(1, 2).unwrap(), |_| false)
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
            .find_launcher_matching(HeightRange::new(1, 2).unwrap(), |_| false)
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

    fn capped_page(records: &[CoinRecord]) -> ScriptedRpc {
        let records = records.to_vec();
        ScriptedRpc::new(move |endpoint, _| match endpoint {
            "get_coin_records_by_puzzle_hash" => Some(page(&records, None, false)),
            _ => None,
        })
    }

    fn small_limits(max_records: usize) -> PageLimits {
        PageLimits {
            timeout: Duration::from_secs(1),
            hint: "",
            max_pages: 8,
            max_records,
        }
    }

    fn coins(count: usize) -> Vec<CoinRecord> {
        (0..count)
            .map(|index| {
                record(
                    Coin::new(Bytes32::new([index as u8; 32]), Bytes32::default(), 1),
                    None,
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn record_cap_accepts_exactly_the_cap_for_address() {
        let records = ChainClient::with_rpc(capped_page(&coins(2)))
            .find_coins_by_puzzle_hash_with(Bytes32::default(), false, small_limits(2))
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
    }

    #[tokio::test]
    async fn record_cap_accepts_exactly_the_cap_for_scan() {
        let launcher = ChainClient::with_rpc(capped_page(&coins(2)))
            .find_launcher_matching_with(HeightRange::new(1, 2).unwrap(), small_limits(2), |_| {
                false
            })
            .await
            .unwrap();
        assert_eq!(launcher, None);
    }

    #[tokio::test]
    async fn record_cap_makes_a_launcher_scan_error() {
        let err = ChainClient::with_rpc(capped_page(&coins(3)))
            .find_launcher_matching_with(HeightRange::new(1, 2).unwrap(), small_limits(2), |_| {
                false
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("2 coin records"), "{err}");
        assert!(err.to_string().contains("narrower range"), "{err}");
    }

    #[tokio::test]
    async fn record_cap_returns_a_partial_address_list() {
        let records = ChainClient::with_rpc(capped_page(&coins(3)))
            .find_coins_by_puzzle_hash_with(Bytes32::default(), false, small_limits(2))
            .await
            .unwrap();
        assert_eq!(records.len(), 3);
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
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            client.find_coins_by_hint_within(Bytes32::default(), false, Duration::from_millis(10)),
        )
        .await
        .expect("hint lookup should apply its timeout")
        .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }
}
