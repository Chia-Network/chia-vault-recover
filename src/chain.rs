//! Blockchain backends: coinset (default) and optional full-node RPC.

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzle_types::{EveProof, LineageProof, Proof};
use chia_sdk_coinset::{ChiaRpcClient, CoinRecord, CoinsetClient};
use chia_sdk_driver::{Layer, SingletonLayer, SpendContext};

use crate::error::{Error, Result};
use crate::network::{Backend, Network};

pub struct ChainClient {
    inner: CoinsetClient,
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

    pub async fn find_unspent_by_puzzle_hash(&self, puzzle_hash: Bytes32) -> Result<Option<Coin>> {
        Ok(self
            .find_coins_by_puzzle_hash(puzzle_hash, false)
            .await?
            .into_iter()
            .find(|r| !r.spent)
            .map(|r| r.coin))
    }

    pub async fn find_coins_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>> {
        let mut all = Vec::new();
        let mut cursor = None;
        for _ in 0..8 {
            let response = self
                .inner
                .get_coin_records_by_puzzle_hash(
                    puzzle_hash,
                    None,
                    None,
                    Some(include_spent),
                    cursor,
                )
                .await
                .map_err(|e| Error::msg(format!("get_coin_records_by_puzzle_hash failed: {e}")))?;
            all.extend(response.coin_records.unwrap_or_default());
            if response.truncated == Some(true) {
                cursor = response.next_cursor;
                if cursor.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(all)
    }

    /// Hint index is optional; backends that lack it return an empty list.
    pub async fn find_coins_by_hint(
        &self,
        hint: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>> {
        match self
            .inner
            .get_coin_records_by_hint(hint, None, None, Some(include_spent), None)
            .await
        {
            Ok(response) => Ok(response.coin_records.unwrap_or_default()),
            Err(_) => Ok(Vec::new()),
        }
    }

    pub async fn get_coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>> {
        let response = self
            .inner
            .get_coin_record_by_name(coin_id)
            .await
            .map_err(|e| Error::msg(format!("get_coin_record_by_name failed: {e}")))?;
        Ok(response.coin_record)
    }

    pub async fn get_children(&self, parent_id: Bytes32) -> Result<Vec<CoinRecord>> {
        let response = self
            .inner
            .get_coin_records_by_parent_ids(vec![parent_id], None, None, Some(true), None)
            .await
            .map_err(|e| Error::msg(format!("get_coin_records_by_parent_ids failed: {e}")))?;
        Ok(response.coin_records.unwrap_or_default())
    }

    pub async fn get_spend(
        &self,
        coin_id: Bytes32,
        spent_height: u32,
    ) -> Result<Option<CoinSpend>> {
        let response = self
            .inner
            .get_puzzle_and_solution(coin_id, Some(spent_height))
            .await
            .map_err(|e| Error::msg(format!("get_puzzle_and_solution failed: {e}")))?;
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

        let parent_spend = self
            .inner
            .get_puzzle_and_solution(coin.parent_coin_info, Some(parent_record.spent_block_index))
            .await
            .map_err(|e| Error::msg(format!("get_puzzle_and_solution failed: {e}")))?;

        let Some(coin_solution) = parent_spend.coin_solution else {
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
        let response = self
            .inner
            .push_tx(spend_bundle.clone())
            .await
            .map_err(|e| Error::msg(format!("push_tx failed: {e}")))?;
        // A rejected spend comes back as `success: false` with an `error` and no `status`.
        if !response.success {
            return Err(Error::msg(format!(
                "push_tx rejected: {}",
                response.error.as_deref().unwrap_or("no error message")
            )));
        }
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
