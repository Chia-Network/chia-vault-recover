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

/// Longest wait for one RPC response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest wait for one page of a launcher scan; a busy 5-day range takes about 100s on coinset.
const SCAN_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
/// Most pages followed for one launcher scan before giving up.
const MAX_SCAN_PAGES: usize = 100;
/// Most 32-block windows searched for a transaction block's timestamp.
const MAX_TIMESTAMP_WINDOWS: u32 = 8;

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

    /// Coins at `puzzle_hash`, at most 8 pages; later pages are dropped.
    pub async fn find_coins_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>> {
        let (records, _complete) = self
            .paged_coin_records(
                puzzle_hash,
                None,
                None,
                include_spent,
                8,
                REQUEST_TIMEOUT,
                "",
            )
            .await?;
        Ok(records)
    }

    /// Every singleton launcher coin confirmed in `[start_height, end_height)`.
    /// Fails rather than return a partial list.
    pub async fn find_launchers_between(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> Result<Vec<CoinRecord>> {
        let (records, complete) = self
            .paged_coin_records(
                SINGLETON_LAUNCHER_HASH.into(),
                Some(start_height),
                Some(end_height),
                true,
                MAX_SCAN_PAGES,
                SCAN_REQUEST_TIMEOUT,
                "; try a narrower range",
            )
            .await?;
        if !complete {
            return Err(Error::msg(format!(
                "could not list every launcher in blocks {start_height}..{end_height}: the node \
                 stopped paging or sent over {MAX_SCAN_PAGES} pages; try a narrower range"
            )));
        }
        Ok(records)
    }

    /// Coin records at `puzzle_hash`, following the cursor for at most `max_pages`,
    /// each page within `page_timeout`.
    /// The flag is false when pages remain, or the node truncated without a new cursor.
    #[allow(clippy::too_many_arguments)]
    async fn paged_coin_records(
        &self,
        puzzle_hash: Bytes32,
        start_height: Option<u32>,
        end_height: Option<u32>,
        include_spent: bool,
        max_pages: usize,
        page_timeout: Duration,
        timeout_hint: &str,
    ) -> Result<(Vec<CoinRecord>, bool)> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..max_pages {
            let response = self
                .call_within(
                    "get_coin_records_by_puzzle_hash",
                    page_timeout,
                    timeout_hint,
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

    /// Lowest height whose transaction block is at or after `timestamp` (unix seconds).
    /// Returns one past the peak when every block is earlier, so an exclusive end keeps the tip.
    pub async fn height_at_or_after(&self, timestamp: u64) -> Result<u32> {
        let state = self
            .call("get_blockchain_state", self.inner.get_blockchain_state())
            .await?;
        let peak = state
            .blockchain_state
            .ok_or_else(|| Error::msg("get_blockchain_state returned no state"))?
            .peak
            .height;
        first_height_at_or_after(peak, timestamp, |height| {
            self.transaction_timestamp_from(height, peak)
        })
        .await
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

    /// Hint index is optional; backends that lack it return an empty list.
    pub async fn find_coins_by_hint(
        &self,
        hint: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>> {
        match self
            .call(
                "get_coin_records_by_hint",
                self.inner
                    .get_coin_records_by_hint(hint, None, None, Some(include_spent), None),
            )
            .await
        {
            Ok(response) => Ok(response.coin_records.unwrap_or_default()),
            Err(_) => Ok(Vec::new()),
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
    use super::*;

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
}
