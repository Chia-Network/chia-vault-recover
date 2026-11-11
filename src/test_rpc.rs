//! Scripted RPC client for chain lookup tests.

use chia_protocol::{BlockRecord, Bytes32, ClassgroupElement, Coin};
use chia_sdk_coinset::{ChiaRpcClient, CoinRecord};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

type Handler = Box<dyn Fn(&str, &Value) -> Option<Value> + Send + Sync>;

/// Answers each request from `handler(endpoint, body)`; `None` fails the request.
pub struct ScriptedRpc {
    handler: Handler,
}

impl ScriptedRpc {
    pub fn new(handler: impl Fn(&str, &Value) -> Option<Value> + Send + Sync + 'static) -> Self {
        Self {
            handler: Box::new(handler),
        }
    }
}

impl ChiaRpcClient for ScriptedRpc {
    type Error = String;

    fn base_url(&self) -> &str {
        "scripted"
    }

    async fn make_post_request<R, B>(&self, endpoint: &str, body: B) -> Result<R, String>
    where
        B: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        let body = serde_json::to_value(body).map_err(|e| e.to_string())?;
        let response = (self.handler)(endpoint, &body)
            .ok_or_else(|| format!("unscripted {endpoint} {body}"))?;
        serde_json::from_value(response).map_err(|e| e.to_string())
    }
}

/// An RPC client that never answers, for timeout tests.
pub struct NeverRpc;

impl ChiaRpcClient for NeverRpc {
    type Error = String;

    fn base_url(&self) -> &str {
        "never"
    }

    async fn make_post_request<R, B>(&self, _endpoint: &str, _body: B) -> Result<R, String>
    where
        B: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        std::future::pending().await
    }
}

pub fn hex_id(id: Bytes32) -> String {
    format!("0x{}", hex::encode(id))
}

pub fn record(coin: Coin, spent_at: Option<u32>) -> CoinRecord {
    CoinRecord {
        coin,
        coinbase: false,
        confirmed_block_index: 1,
        spent: spent_at.is_some(),
        spent_block_index: spent_at.unwrap_or(0),
        timestamp: 0,
    }
}

/// A `get_coin_records_*` page.
pub fn page(records: &[CoinRecord], next_cursor: Option<&str>, truncated: bool) -> Value {
    json!({
        "coin_records": records,
        "success": true,
        "truncated": truncated,
        "next_cursor": next_cursor,
    })
}

/// A block record with a timestamp only when `timestamp` is set.
pub fn block_record(height: u32, timestamp: Option<u64>) -> BlockRecord {
    BlockRecord::new(
        Bytes32::default(),
        Bytes32::default(),
        height,
        u128::from(height),
        u128::from(height),
        0,
        ClassgroupElement::default(),
        None,
        Bytes32::default(),
        Bytes32::default(),
        1,
        Bytes32::default(),
        Bytes32::default(),
        0,
        15,
        false,
        0,
        timestamp,
        timestamp.map(|_| Bytes32::default()),
        timestamp.map(|_| 0),
        timestamp.map(|_| Vec::new()),
        None,
        None,
        None,
        None,
    )
}

/// A `get_blockchain_state` response whose peak is `peak`.
pub fn blockchain_state(peak: BlockRecord) -> Value {
    let height = peak.height;
    json!({
        "blockchain_state": {
            "average_block_time": 1,
            "block_max_cost": 11_000_000_000u64,
            "difficulty": 1,
            "genesis_challenge_initialized": true,
            "mempool_cost": 0,
            "mempool_fees": 0,
            "mempool_max_total_cost": 110_000_000_000u64,
            "mempool_min_fees": { "cost_5000000": 0 },
            "mempool_size": 0,
            "node_id": hex_id(Bytes32::default()),
            "peak": peak,
            "space": 0,
            "sub_slot_iters": 1,
            "sync": {
                "sync_mode": false,
                "sync_progress_height": height,
                "sync_tip_height": height,
                "synced": true,
            },
        },
        "error": null,
        "success": true,
    })
}
