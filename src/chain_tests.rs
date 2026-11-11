use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chia_sdk_coinset::{ChiaRpcClient, MempoolItem};
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

struct CountPendings<F> {
    inner: std::pin::Pin<Box<F>>,
    pending: Arc<AtomicUsize>,
}

impl<F: Future> Future for CountPendings<F> {
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        match this.inner.as_mut().poll(cx) {
            std::task::Poll::Pending => {
                this.pending.fetch_add(1, Ordering::Relaxed);
                std::task::Poll::Pending
            }
            ready => ready,
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn launcher_scan_yields_between_records() {
    let record_count = YIELD_AFTER_RECORDS * 4;
    let page_records = coins(record_count);
    let rpc = ScriptedRpc::new(move |endpoint, _| match endpoint {
        "get_coin_records_by_puzzle_hash" => Some(page(&page_records, None, false)),
        _ => None,
    });
    let pending = Arc::new(AtomicUsize::new(0));
    let client = ChainClient::with_rpc(rpc);
    let scan = CountPendings {
        inner: Box::pin(client.find_launcher_matching_with(
            HeightRange::new(1, 2).unwrap(),
            SCAN_PAGE_LIMITS,
            |_| false,
        )),
        pending: Arc::clone(&pending),
    };
    assert_eq!(scan.await.unwrap(), None);
    let pendings = pending.load(Ordering::Relaxed);
    assert!(
        pendings >= record_count / YIELD_AFTER_RECORDS,
        "scan yielded {pendings} times for {record_count} records"
    );
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
        .find_launcher_matching_with(HeightRange::new(1, 2).unwrap(), small_limits(2), |_| false)
        .await
        .unwrap();
    assert_eq!(launcher, None);
}

#[tokio::test]
async fn record_cap_makes_a_launcher_scan_error() {
    let err = ChainClient::with_rpc(capped_page(&coins(3)))
        .find_launcher_matching_with(HeightRange::new(1, 2).unwrap(), small_limits(2), |_| false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("2 coin records"), "{err}");
    assert!(err.to_string().contains("narrower range"), "{err}");
}

#[tokio::test]
async fn record_cap_returns_a_partial_address_list() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let page_records = coins(3);
    let rpc = ScriptedRpc::new(move |endpoint, _| match endpoint {
        "get_coin_records_by_puzzle_hash" => {
            let next = counter.fetch_add(1, Ordering::Relaxed);
            let cursor = format!("cursor-{next}");
            Some(page(&page_records, Some(&cursor), true))
        }
        _ => None,
    });
    let records = ChainClient::with_rpc(rpc)
        .find_coins_by_puzzle_hash_with(Bytes32::default(), false, small_limits(2))
        .await
        .unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
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

#[tokio::test]
async fn pending_spend_rpc_failure_is_unknown() {
    let client = ChainClient::with_rpc(ScriptedRpc::new(|_, _| None));
    assert_eq!(
        client.coin_has_pending_spend(Bytes32::default()).await,
        PendingSpend::Unknown
    );
}

#[tokio::test]
async fn pending_spend_unsuccessful_response_is_unknown() {
    let rpc = ScriptedRpc::new(|endpoint, _| match endpoint {
        "get_mempool_items_by_coin_name" => {
            Some(json!({"success": false, "error": "method not available"}))
        }
        _ => None,
    });
    let client = ChainClient::with_rpc(rpc);
    assert_eq!(
        client.coin_has_pending_spend(Bytes32::default()).await,
        PendingSpend::Unknown
    );
}

#[tokio::test]
async fn pending_spend_unsuccessful_without_error_is_unknown() {
    let rpc = ScriptedRpc::new(|endpoint, _| match endpoint {
        "get_mempool_items_by_coin_name" => Some(json!({"success": false})),
        _ => None,
    });
    let client = ChainClient::with_rpc(rpc);
    assert_eq!(
        client.coin_has_pending_spend(Bytes32::default()).await,
        PendingSpend::Unknown
    );
}

#[tokio::test]
async fn pending_spend_with_items_is_pending() {
    let item = MempoolItem {
        spend_bundle: SpendBundle::aggregate(&[]),
        fee: 0,
    };
    let rpc = ScriptedRpc::new(move |endpoint, _| match endpoint {
        "get_mempool_items_by_coin_name" => {
            Some(json!({"mempool_items": [item.clone()], "success": true}))
        }
        _ => None,
    });
    let client = ChainClient::with_rpc(rpc);
    assert_eq!(
        client.coin_has_pending_spend(Bytes32::default()).await,
        PendingSpend::Pending
    );
}

#[tokio::test]
async fn child_listing_reports_incomplete_at_the_page_cap() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let rpc = ScriptedRpc::new(move |endpoint, _| match endpoint {
        "get_coin_records_by_parent_ids" => {
            let next = counter.fetch_add(1, Ordering::Relaxed);
            let cursor = format!("cursor-{next}");
            Some(page(&[], Some(&cursor), true))
        }
        _ => None,
    });
    let err = ChainClient::with_rpc(rpc)
        .get_children(Bytes32::default())
        .await
        .unwrap_err();
    assert_eq!(calls.load(Ordering::Relaxed), COIN_PAGE_LIMITS.max_pages);
    assert!(
        err.to_string().contains("could not list every child"),
        "{err}"
    );
    assert!(err.to_string().contains("stopped paging after"), "{err}");
}

#[tokio::test]
async fn child_listing_reports_a_repeated_cursor() {
    let rpc = ScriptedRpc::new(|endpoint, _| match endpoint {
        "get_coin_records_by_parent_ids" => Some(page(&[], Some("same-cursor"), true)),
        _ => None,
    });
    let err = ChainClient::with_rpc(rpc)
        .get_children(Bytes32::default())
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("stopped paging before the listing completed"),
        "{err}"
    );
    assert!(!err.to_string().contains("coin records"), "{err}");
}
