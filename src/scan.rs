//! Opt-in launcher scan for a vault that has never been spent.

use std::fmt::{self, Display};

use chia_sdk_coinset::ChiaRpcClient;

use crate::chain::ChainClient;
use crate::error::{Error, Result};

/// Chia targets 4608 blocks a day.
const BLOCKS_PER_DAY: u32 = 4608;
/// Largest height-range scan without `force`.
pub const MAX_SCAN_DAYS: u32 = 5;

/// Block heights to scan, `start` inclusive and `end` exclusive. Never empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeightRange {
    start: u32,
    end: u32,
}

impl HeightRange {
    pub fn new(start: u32, end: u32) -> Result<Self> {
        if start >= end {
            return Err(Error::msg(format!(
                "scan range start height {start} must be below end height {end}"
            )));
        }
        Ok(Self { start, end })
    }

    pub fn start(self) -> u32 {
        self.start
    }

    pub fn end(self) -> u32 {
        self.end
    }

    /// Refuse ranges over [`MAX_SCAN_DAYS`] unless `force` is set.
    fn check_limit(self, force: bool) -> Result<Self> {
        let blocks = self.end - self.start;
        let limit = MAX_SCAN_DAYS * BLOCKS_PER_DAY;
        if !force && blocks > limit {
            return Err(Error::msg(format!(
                "scan range is {blocks} blocks, over the {MAX_SCAN_DAYS}-day limit of {limit} \
                 blocks; narrow it or allow a longer scan"
            )));
        }
        Ok(self)
    }
}

impl Display for HeightRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blocks {}..{}", self.start, self.end)
    }
}

/// A requested launcher scan. Lookup turns it into block heights only when nothing
/// at the address reveals the launcher. Height ranges are held to [`MAX_SCAN_DAYS`]
/// when built. A created-on window is about two days, and its resolved range is
/// rejected when it exceeds twice that limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherScan(Window);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Window {
    CreatedOn { date: String, from: u64, to: u64 },
    Heights(HeightRange),
}

impl LauncherScan {
    /// Every launcher from `date` (`YYYY-MM-DD`) in any timezone.
    pub fn created_on(date: &str) -> Result<Self> {
        let (from, to) = created_on_timestamps(date)?;
        let date = date.trim().to_string();
        Ok(Self(Window::CreatedOn { date, from, to }))
    }

    /// Every launcher in `start..end`; over [`MAX_SCAN_DAYS`] only with `force`.
    pub fn heights(start: u32, end: u32, force: bool) -> Result<Self> {
        let range = HeightRange::new(start, end)?.check_limit(force)?;
        Ok(Self(Window::Heights(range)))
    }

    pub(crate) async fn resolve<C>(&self, client: &ChainClient<C>) -> Result<HeightRange>
    where
        C: ChiaRpcClient,
        C::Error: Display,
    {
        match &self.0 {
            Window::Heights(range) => Ok(*range),
            Window::CreatedOn { date, from, to } => {
                match client.height_range_for_timestamps(*from, *to).await? {
                    Some(range) => check_created_on_range(range, date),
                    None => Err(Error::msg(format!(
                        "no blocks found for {date}: it is before the first block or after the latest"
                    ))),
                }
            }
        }
    }
}

/// Refuse a created-on range wider than twice the explicit height-range limit.
/// Block times from a node that misreports them must not widen the scan.
fn check_created_on_range(range: HeightRange, date: &str) -> Result<HeightRange> {
    let blocks = range.end() - range.start();
    let limit = 2 * MAX_SCAN_DAYS * BLOCKS_PER_DAY;
    if blocks > limit {
        return Err(Error::msg(format!(
            "blocks for {date} span {blocks} blocks, over the {limit}-block sanity cap for a \
             created-on scan; check the node's block times or use a height range"
        )));
    }
    Ok(range)
}

/// Unix-second bounds of `date` in every timezone, UTC-12 to UTC+14, plus an hour each side.
fn created_on_timestamps(date: &str) -> Result<(u64, u64)> {
    const HOUR: i64 = 3600;
    let bad = || Error::msg(format!("created date must be YYYY-MM-DD, got {date:?}"));
    let mut parts = date.trim().splitn(3, '-');
    let mut next = |len: usize| -> Result<i64> {
        let part = parts.next().filter(|p| p.len() == len).ok_or_else(bad)?;
        part.parse().map_err(|_| bad())
    };
    let (year, month, day) = (next(4)?, next(2)?, next(2)?);
    if !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&day) {
        return Err(bad());
    }
    let day_start = days_from_civil(year, month, day) * 24 * HOUR;
    let from = day_start - 14 * HOUR - HOUR;
    let to = day_start + 24 * HOUR + 12 * HOUR + HOUR;
    Ok((from.max(0) as u64, to.max(0) as u64))
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_on_covers_the_date_in_every_timezone() {
        // 2026-01-15 00:00 UTC is 1_768_435_200.
        let (from, to) = created_on_timestamps("2026-01-15").unwrap();
        assert_eq!(from, 1_768_435_200 - 15 * 3600);
        assert_eq!(to, 1_768_435_200 + 37 * 3600);
        // Well inside the height-range limit, which is why created-on has none.
        assert!(to - from < u64::from(MAX_SCAN_DAYS) * 86_400 / 2);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
        for bad in [
            "2026-8-03",
            "2026-13-01",
            "2026-02-29",
            "2026/08/03",
            "",
            "2026-01-15-1",
        ] {
            assert!(LauncherScan::created_on(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn height_range_rejects_empty_ranges() {
        assert!(HeightRange::new(10, 10).is_err());
        assert!(HeightRange::new(11, 10).is_err());
        assert!(LauncherScan::heights(11, 10, true).is_err());
        let range = HeightRange::new(1, 2).unwrap();
        assert_eq!((range.start(), range.end()), (1, 2));
        assert_eq!(range.to_string(), "blocks 1..2");
    }

    #[test]
    fn scan_limit_is_five_days_unless_forced() {
        let limit = MAX_SCAN_DAYS * BLOCKS_PER_DAY;
        assert!(LauncherScan::heights(100, 100 + limit, false).is_ok());
        let over = LauncherScan::heights(100, 101 + limit, false).unwrap_err();
        assert!(
            !over.to_string().contains("--"),
            "no CLI flag in shared text"
        );
        assert!(LauncherScan::heights(100, 101 + limit, true).is_ok());
    }

    use chia_protocol::BlockRecord;
    use serde_json::json;

    use crate::test_rpc::{ScriptedRpc, block_record, blockchain_state};

    fn timestamped_chain(
        peak: u32,
        timestamp: impl Fn(u32) -> Option<u64> + Send + Sync + 'static,
    ) -> ScriptedRpc {
        ScriptedRpc::new(move |endpoint, body| match endpoint {
            "get_blockchain_state" => Some(blockchain_state(block_record(peak, timestamp(peak)))),
            "get_block_records" => {
                let start = body["start"].as_u64()? as u32;
                let end = body["end"].as_u64()? as u32;
                let records: Vec<BlockRecord> = (start..end)
                    .filter_map(|height| timestamp(height).map(|ts| block_record(height, Some(ts))))
                    .collect();
                Some(json!({ "block_records": records, "success": true }))
            }
            _ => None,
        })
    }

    async fn resolved_range(scan: &LauncherScan, rpc: ScriptedRpc) -> Result<HeightRange> {
        scan.resolve(&ChainClient::with_rpc(rpc)).await
    }

    #[tokio::test]
    async fn created_on_resolves_a_past_date_to_a_non_empty_range() {
        let rpc = timestamped_chain(1000, |height| Some(u64::from(height) * 1000));
        let scan = LauncherScan::created_on("1970-01-01").unwrap();
        let range = resolved_range(&scan, rpc).await.unwrap();
        assert_eq!(range, HeightRange::new(0, 134).unwrap());
    }

    #[tokio::test]
    async fn created_on_rejects_a_future_date_without_widening_it() {
        let rpc = timestamped_chain(1000, |height| Some(u64::from(height) * 1000));
        let scan = LauncherScan::created_on("2100-01-01").unwrap();
        let err = resolved_range(&scan, rpc).await.unwrap_err();
        assert!(err.to_string().contains("no blocks found"), "{err}");
    }

    #[tokio::test]
    async fn created_on_propagates_block_record_errors() {
        let rpc = ScriptedRpc::new(|endpoint, _| match endpoint {
            "get_blockchain_state" => Some(blockchain_state(block_record(1000, Some(0)))),
            _ => None,
        });
        let scan = LauncherScan::created_on("1970-01-01").unwrap();
        let err = resolved_range(&scan, rpc).await.unwrap_err();
        assert!(err.to_string().contains("get_block_records"), "{err}");
        assert!(!err.to_string().contains("no blocks found"), "{err}");
    }

    #[tokio::test]
    async fn created_on_rejects_a_range_over_the_sanity_cap() {
        let rpc = timestamped_chain(1_000_000, |height| {
            Some(if height == 0 { 200_000 } else { 0 })
        });
        let scan = LauncherScan::created_on("1970-01-01").unwrap();
        let err = resolved_range(&scan, rpc).await.unwrap_err();
        assert!(err.to_string().contains("sanity cap"), "{err}");
    }

    #[test]
    fn created_on_range_cap_is_twice_the_height_limit() {
        let limit = 2 * MAX_SCAN_DAYS * BLOCKS_PER_DAY;
        assert!(check_created_on_range(HeightRange::new(0, limit).unwrap(), "d").is_ok());
        assert!(check_created_on_range(HeightRange::new(0, limit + 1).unwrap(), "d").is_err());
    }
}
