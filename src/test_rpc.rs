//! Scripted RPC client for chain lookup tests.

use chia_protocol::{Bytes32, Coin};
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
