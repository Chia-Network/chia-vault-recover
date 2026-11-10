//! Resolve a vault launcher id from a receive address or hex launcher id.

use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_sdk_coinset::CoinRecord;
use chia_sdk_driver::{
    CatLayer, Layer, P2SingletonLayer, Puzzle, SingletonLayer, SpendContext, mips_puzzle_hash,
};
use chia_sdk_types::Mod;
use chia_sdk_types::puzzles::{OneOfNSolution, SingletonMember};
use clvm_traits::FromClvm;
use clvm_utils::tree_hash;
use clvmr::NodePtr;

use crate::address::{decode_address, network_from_address_prefix};
use crate::chain::ChainClient;
use crate::config::parse_bytes32;
use crate::error::{Error, Result};
use crate::mips::{CloudWalletP2, alloc_spend};
use crate::network::{Backend, Network};

#[derive(Debug, Clone)]
pub struct ResolvedLauncher {
    pub launcher_id: Bytes32,
    pub source: String,
}

/// Parse a vault address (`xch1…` / `txch1…`) or a 32-byte launcher id.
pub fn parse_vault_locator(input: &str) -> Result<VaultLocator> {
    let input = input.trim();
    if input.to_ascii_lowercase().starts_with("xch1")
        || input.to_ascii_lowercase().starts_with("txch1")
    {
        let (hrp, puzzle_hash) = decode_address(input)?;
        return Ok(VaultLocator::Address {
            original: input.to_string(),
            hrp,
            puzzle_hash,
        });
    }
    Ok(VaultLocator::LauncherId(parse_bytes32(input)?))
}

#[derive(Debug, Clone)]
pub enum VaultLocator {
    LauncherId(Bytes32),
    Address {
        original: String,
        hrp: String,
        puzzle_hash: Bytes32,
    },
}

impl VaultLocator {
    pub fn inferred_network(&self) -> Option<Network> {
        match self {
            Self::LauncherId(_) => None,
            Self::Address { hrp, .. } => network_from_address_prefix(hrp),
        }
    }
}

pub fn client_for_vault(vault: &str, backend: &Backend) -> Result<(ChainClient, Network)> {
    let locator = parse_vault_locator(vault)?;
    let network = locator.inferred_network().ok_or_else(|| {
        Error::msg(
            "pass the vault Receive address (xch1… for mainnet, or txch1… for testnet11) so the network is known",
        )
    })?;
    Ok((ChainClient::new(network, backend), network))
}

/// Block heights to scan for the vault launcher, `start` inclusive and `end` exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeightRange {
    pub start: u32,
    pub end: u32,
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

    /// Refuse ranges over [`MAX_SCAN_DAYS`] unless `force` is set; each 1,000 blocks is a request.
    pub fn check_limit(self, force: bool) -> Result<Self> {
        let blocks = self.end - self.start;
        if !force && blocks > MAX_SCAN_DAYS * BLOCKS_PER_DAY {
            return Err(Error::msg(format!(
                "scan range is {blocks} blocks, over the {MAX_SCAN_DAYS}-day limit of {} blocks; narrow it or pass --force-scan",
                MAX_SCAN_DAYS * BLOCKS_PER_DAY
            )));
        }
        Ok(self)
    }
}

/// Heights covering `date` (`YYYY-MM-DD`) in every timezone, UTC-12 to UTC+14, plus an hour each side.
pub async fn heights_for_created_on(client: &ChainClient, date: &str) -> Result<HeightRange> {
    let (from, to) = created_on_timestamps(date)?;
    let start = client.height_at_or_after(from).await?;
    let end = client.height_at_or_after(to).await?.saturating_add(1);
    HeightRange::new(start, end)
}

/// Unix-second bounds for [`heights_for_created_on`].
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

/// `scan` opts in to checking every launcher in that range when no spend reveals the launcher.
pub async fn resolve_launcher_id(
    client: &ChainClient,
    locator: &VaultLocator,
    scan: Option<HeightRange>,
) -> Result<Option<ResolvedLauncher>> {
    match locator {
        VaultLocator::LauncherId(id) => Ok(Some(ResolvedLauncher {
            launcher_id: *id,
            source: format!("launcher id 0x{}", hex::encode(id)),
        })),
        VaultLocator::Address {
            original,
            puzzle_hash,
            ..
        } => Ok(launcher_from_puzzle_hash(client, *puzzle_hash, scan)
            .await?
            .map(|id| ResolvedLauncher {
                launcher_id: id,
                source: format!("address {original}"),
            })),
    }
}

/// Highest receive-address nonce tried when rebuilding an address. Cloud Wallet derives
/// addresses at nonces 1 to 100 on top of the default address at 0.
const MAX_P2_NONCE: usize = 100;
/// Chia targets 4608 blocks a day.
const BLOCKS_PER_DAY: u32 = 4608;
/// Largest launcher scan without `force`.
pub const MAX_SCAN_DAYS: u32 = 5;

async fn launcher_from_puzzle_hash(
    client: &ChainClient,
    puzzle_hash: Bytes32,
    scan: Option<HeightRange>,
) -> Result<Option<Bytes32>> {
    let exact = client.find_coins_by_puzzle_hash(puzzle_hash, true).await?;
    if let Some(id) = launcher_from_spent_records(client, &exact, puzzle_hash).await? {
        return Ok(Some(id));
    }

    let hinted = client.find_coins_by_hint(puzzle_hash, true).await?;
    if let Some(id) = launcher_from_spent_records(client, &hinted, puzzle_hash).await? {
        return Ok(Some(id));
    }

    // A vault that has only received funds never reveals its launcher at the address.
    // When asked, check every launcher in the given range against the address.
    if let Some(range) = scan
        && let Some(id) = scan_launchers(client, puzzle_hash, range).await?
    {
        return Ok(Some(id));
    }

    if let Some(id) = launcher_from_unspent_records(client, &exact, puzzle_hash).await? {
        return Ok(Some(id));
    }
    launcher_from_unspent_records(client, &hinted, puzzle_hash).await
}

async fn launcher_from_spent_records(
    client: &ChainClient,
    records: &[CoinRecord],
    puzzle_hash: Bytes32,
) -> Result<Option<Bytes32>> {
    for rec in records.iter().filter(|r| r.spent) {
        if let Some(spend) = client
            .get_spend(rec.coin.coin_id(), rec.spent_block_index)
            .await?
            && let Some(id) = launcher_from_spend(&spend)
            && spend_belongs_to_address(&spend, id, puzzle_hash)
        {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

async fn launcher_from_unspent_records(
    client: &ChainClient,
    records: &[CoinRecord],
    puzzle_hash: Bytes32,
) -> Result<Option<Bytes32>> {
    for rec in records.iter().filter(|r| !r.spent) {
        if rec.coin.amount % 2 == 1
            && let Some(id) = walk_parents_to_launcher(client, rec.coin.parent_coin_info).await?
            && launcher_matches_address(id, puzzle_hash)
        {
            return Ok(Some(id));
        }
        if let Some(parent) = client.get_coin_record(rec.coin.parent_coin_info).await?
            && parent.spent
            && let Some(spend) = client
                .get_spend(parent.coin.coin_id(), parent.spent_block_index)
                .await?
            && let Some(id) = launcher_from_spend(&spend)
            && spend_belongs_to_address(&spend, id, puzzle_hash)
        {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

async fn scan_launchers(
    client: &ChainClient,
    puzzle_hash: Bytes32,
    range: HeightRange,
) -> Result<Option<Bytes32>> {
    let launchers = client
        .find_launchers_between(range.start, range.end)
        .await?;
    Ok(launchers
        .iter()
        .map(|r| r.coin.coin_id())
        .find(|id| launcher_matches_address(*id, puzzle_hash)))
}

/// A spend whose revealed p2 puzzle (under any CAT layer) hashes to the address
/// proves the launcher directly, whatever receive puzzle Cloud Wallet used.
/// Otherwise fall back to rebuilding the known receive puzzles.
fn spend_belongs_to_address(spend: &CoinSpend, launcher_id: Bytes32, puzzle_hash: Bytes32) -> bool {
    revealed_p2_puzzle_hash(spend) == Some(puzzle_hash)
        || launcher_matches_address(launcher_id, puzzle_hash)
}

fn revealed_p2_puzzle_hash(spend: &CoinSpend) -> Option<Bytes32> {
    let (ctx, puzzle, _) = alloc_spend(spend).ok()?;
    let p2 = match CatLayer::<Puzzle>::parse_puzzle(&ctx, puzzle) {
        Ok(Some(cat)) => cat.inner_puzzle,
        _ => puzzle,
    };
    Some(tree_hash(&ctx, p2.ptr()).into())
}

/// Whether `puzzle_hash` is the receive address of the singleton `launcher_id`
/// (Cloud Wallet p2 at any nonce from 0 to `MAX_P2_NONCE`, or classic p2-singleton).
///
/// The receive address depends only on the launcher id, not on the vault singleton's
/// inner puzzle, so it holds however Cloud Wallet changes that puzzle. If Cloud
/// Wallet changes the receive (p2) puzzle itself, add the new shape here and in
/// `launcher_from_puzzle`; until then those vaults report "not found", never a wrong id.
pub fn launcher_matches_address(launcher_id: Bytes32, puzzle_hash: Bytes32) -> bool {
    let mut ctx = SpendContext::new();
    if let Ok(ptr) = P2SingletonLayer::new(launcher_id).construct_puzzle(&mut ctx)
        && Bytes32::from(ctx.tree_hash(ptr)) == puzzle_hash
    {
        return true;
    }
    (0..=MAX_P2_NONCE).any(|nonce| cloud_wallet_p2_hash(launcher_id, nonce) == puzzle_hash)
}

/// Top-level singleton member at `nonce`, as Cloud Wallet builds each receive address.
fn cloud_wallet_p2_hash(launcher_id: Bytes32, nonce: usize) -> Bytes32 {
    mips_puzzle_hash(
        nonce,
        Vec::new(),
        SingletonMember::new(launcher_id).curry_tree_hash(),
        true,
    )
    .into()
}

async fn walk_parents_to_launcher(
    client: &ChainClient,
    mut parent_id: Bytes32,
) -> Result<Option<Bytes32>> {
    for _ in 0..64 {
        let Some(parent) = client.get_coin_record(parent_id).await? else {
            return Ok(None);
        };
        if parent.coin.puzzle_hash == SINGLETON_LAUNCHER_HASH.into() {
            return Ok(Some(parent.coin.coin_id()));
        }
        if parent.spent
            && let Some(spend) = client
                .get_spend(parent.coin.coin_id(), parent.spent_block_index)
                .await?
            && let Some(id) = launcher_from_spend(&spend)
        {
            return Ok(Some(id));
        }
        if parent.coin.parent_coin_info == parent_id {
            break;
        }
        parent_id = parent.coin.parent_coin_info;
    }
    Ok(None)
}

/// Pull a launcher id out of a revealed puzzle (p2-singleton, Cloud Wallet p2, or vault singleton).
pub fn launcher_from_spend(spend: &CoinSpend) -> Option<Bytes32> {
    let (ctx, puzzle, solution_ptr) = alloc_spend(spend).ok()?;
    launcher_from_puzzle(&ctx, puzzle, solution_ptr)
}

fn launcher_from_puzzle(
    alloc: &clvmr::Allocator,
    puzzle: Puzzle,
    solution: NodePtr,
) -> Option<Bytes32> {
    if let Ok(Some(cat)) = CatLayer::<Puzzle>::parse_puzzle(alloc, puzzle) {
        let inner_solution =
            chia_puzzle_types::cat::CatSolution::<NodePtr>::from_clvm(alloc, solution)
                .map(|s| s.inner_puzzle_solution)
                .unwrap_or(solution);
        return launcher_from_puzzle(alloc, cat.inner_puzzle, inner_solution);
    }

    if let Ok(Some(singleton)) = SingletonLayer::<Puzzle>::parse_puzzle(alloc, puzzle) {
        return Some(singleton.launcher_id);
    }

    if let Ok(Some(p2)) = P2SingletonLayer::parse_puzzle(alloc, puzzle) {
        return Some(p2.launcher_id);
    }

    if let Ok(Some(p2)) = CloudWalletP2::parse_puzzle(alloc, puzzle) {
        return Some(p2.inner_puzzle.inner_puzzle.launcher_id);
    }

    if let Some(curried) = puzzle.as_curried()
        && curried.mod_hash == chia_puzzles::ONE_OF_N_HASH.into()
        && let Ok(one) = OneOfNSolution::<NodePtr, NodePtr>::from_clvm(alloc, solution)
    {
        return launcher_from_puzzle(
            alloc,
            Puzzle::parse(alloc, one.member_puzzle),
            one.member_solution,
        );
    }

    None
}

#[cfg(test)]
mod tests {
    use chia_sdk_driver::SpendContext;
    use chia_sdk_types::puzzles::{DelegatedPuzzleFeederArgs, IndexWrapperArgs};

    use super::*;
    use crate::address::encode_address;

    #[test]
    fn parse_locator_accepts_address_and_hex() {
        let ph = Bytes32::new([0x11; 32]);
        let addr = encode_address(ph, "xch").unwrap();
        match parse_vault_locator(&addr).unwrap() {
            VaultLocator::Address { puzzle_hash, .. } => assert_eq!(puzzle_hash, ph),
            VaultLocator::LauncherId(_) => panic!("expected address"),
        }
        let id = Bytes32::new([0x22; 32]);
        match parse_vault_locator(&format!("0x{}", hex::encode(id))).unwrap() {
            VaultLocator::LauncherId(parsed) => assert_eq!(parsed, id),
            VaultLocator::Address { .. } => panic!("expected launcher"),
        }
    }

    #[test]
    fn launcher_from_cloud_wallet_p2_spend() {
        let launcher = Bytes32::new([0x42; 32]);
        let mut ctx = SpendContext::new();
        let member = ctx.curry(SingletonMember::new(launcher)).unwrap();
        let feeder = ctx
            .curry(chia_sdk_types::puzzles::DelegatedPuzzleFeederArgs::new(
                member,
            ))
            .unwrap();
        let wrapped = ctx
            .curry(chia_sdk_types::puzzles::IndexWrapperArgs::new(
                0usize, feeder,
            ))
            .unwrap();
        let puzzle = Puzzle::parse(&ctx, wrapped);
        let id = launcher_from_puzzle(&ctx, puzzle, NodePtr::NIL);
        assert_eq!(id, Some(launcher));
    }

    #[test]
    fn launcher_from_classic_p2_singleton() {
        let launcher = Bytes32::new([0x43; 32]);
        let mut ctx = SpendContext::new();
        let ptr = P2SingletonLayer::new(launcher)
            .construct_puzzle(&mut ctx)
            .unwrap();
        let puzzle = Puzzle::parse(&ctx, ptr);
        assert_eq!(
            launcher_from_puzzle(&ctx, puzzle, NodePtr::NIL),
            Some(launcher)
        );
    }

    #[test]
    fn address_matches_its_own_launcher_only() {
        let launcher = Bytes32::new([0x44; 32]);
        let other = Bytes32::new([0x45; 32]);
        let mut ctx = SpendContext::new();
        for nonce in [0, 1, MAX_P2_NONCE] {
            // Same layers `launcher_from_puzzle` parses, built out explicitly.
            let member = ctx.curry(SingletonMember::new(launcher)).unwrap();
            let feeder = ctx.curry(DelegatedPuzzleFeederArgs::new(member)).unwrap();
            let wrapped = ctx.curry(IndexWrapperArgs::new(nonce, feeder)).unwrap();
            let address = Bytes32::from(ctx.tree_hash(wrapped));
            assert_eq!(cloud_wallet_p2_hash(launcher, nonce), address);
            assert!(launcher_matches_address(launcher, address));
            assert!(!launcher_matches_address(other, address));
        }
        assert!(!launcher_matches_address(
            launcher,
            cloud_wallet_p2_hash(launcher, MAX_P2_NONCE + 1)
        ));
        let classic = P2SingletonLayer::new(launcher)
            .construct_puzzle(&mut ctx)
            .unwrap();
        let classic = Bytes32::from(ctx.tree_hash(classic));
        assert!(launcher_matches_address(launcher, classic));
        assert!(!launcher_matches_address(other, classic));
    }

    #[test]
    fn revealed_receive_puzzle_proves_launcher_beyond_rebuilt_nonces() {
        let launcher = Bytes32::new([0x46; 32]);
        let mut ctx = SpendContext::new();
        let member = ctx.curry(SingletonMember::new(launcher)).unwrap();
        let feeder = ctx.curry(DelegatedPuzzleFeederArgs::new(member)).unwrap();
        let wrapped = ctx
            .curry(IndexWrapperArgs::new(MAX_P2_NONCE + 100, feeder))
            .unwrap();
        let address = Bytes32::from(ctx.tree_hash(wrapped));
        let spend = CoinSpend::new(
            chia_protocol::Coin::new(Bytes32::default(), address, 1),
            ctx.serialize(&wrapped).unwrap(),
            ctx.serialize(&NodePtr::NIL).unwrap(),
        );
        assert_eq!(launcher_from_spend(&spend), Some(launcher));
        assert!(!launcher_matches_address(launcher, address));
        assert!(spend_belongs_to_address(&spend, launcher, address));
        assert!(!spend_belongs_to_address(
            &spend,
            launcher,
            Bytes32::new([0x47; 32])
        ));
    }

    #[test]
    fn created_on_covers_the_date_in_every_timezone() {
        // 2026-01-15 00:00 UTC is 1_768_435_200.
        let (from, to) = created_on_timestamps("2026-01-15").unwrap();
        assert_eq!(from, 1_768_435_200 - 15 * 3600);
        assert_eq!(to, 1_768_435_200 + 37 * 3600);
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
            assert!(created_on_timestamps(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn height_range_rejects_empty_ranges() {
        assert!(HeightRange::new(10, 10).is_err());
        assert!(HeightRange::new(11, 10).is_err());
        assert_eq!(
            HeightRange::new(1, 2).unwrap(),
            HeightRange { start: 1, end: 2 }
        );
    }

    #[test]
    fn scan_limit_is_five_days_unless_forced() {
        let limit = MAX_SCAN_DAYS * BLOCKS_PER_DAY;
        let at_limit = HeightRange::new(100, 100 + limit).unwrap();
        let over = HeightRange::new(100, 101 + limit).unwrap();
        assert!(at_limit.check_limit(false).is_ok());
        assert!(over.check_limit(false).is_err());
        assert!(over.check_limit(true).is_ok());
    }

    #[test]
    fn parse_locator_infers_testnet_from_txch() {
        let ph = Bytes32::new([0x11; 32]);
        let addr = encode_address(ph, "txch").unwrap();
        let locator = parse_vault_locator(&addr).unwrap();
        assert_eq!(locator.inferred_network(), Some(Network::Testnet11));
    }

    #[test]
    fn client_for_address_uses_prefix() {
        let ph = Bytes32::new([0x11; 32]);
        let mainnet = encode_address(ph, "xch").unwrap();
        let testnet = encode_address(ph, "txch").unwrap();
        let (_, network) = client_for_vault(&mainnet, &Backend::coinset()).unwrap();
        assert_eq!(network, Network::Mainnet);
        let (_, network) = client_for_vault(&testnet, &Backend::coinset()).unwrap();
        assert_eq!(network, Network::Testnet11);
    }

    #[test]
    fn client_for_launcher_id_needs_an_address() {
        let id = format!("0x{}", hex::encode([0x22; 32]));
        match client_for_vault(&id, &Backend::coinset()) {
            Err(err) => assert!(err.to_string().contains("txch1")),
            Ok(_) => panic!("a launcher id does not select a network"),
        }
    }
}
