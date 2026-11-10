//! Resolve a vault launcher id from a receive address or hex launcher id.

use std::fmt::Display;

use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_sdk_coinset::{ChiaRpcClient, CoinRecord};
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
use crate::guidance::LookupGap;
use crate::mips::{CloudWalletP2, alloc_spend};
use crate::network::{Backend, Network};
use crate::scan::{HeightRange, LauncherScan};

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

/// `scan` opts in to checking every launcher in a block range when no spend reveals
/// the launcher. `Err(gap)` means the lookup ran but found no launcher.
pub async fn resolve_launcher_id<C>(
    client: &ChainClient<C>,
    locator: &VaultLocator,
    scan: Option<&LauncherScan>,
) -> Result<std::result::Result<ResolvedLauncher, LookupGap>>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    let (original, puzzle_hash) = match locator {
        VaultLocator::LauncherId(id) => {
            return Ok(Ok(ResolvedLauncher {
                launcher_id: *id,
                source: format!("launcher id 0x{}", hex::encode(id)),
            }));
        }
        VaultLocator::Address {
            original,
            puzzle_hash,
            ..
        } => (original, *puzzle_hash),
    };
    let resolved = |launcher_id, source| {
        Ok(Ok(ResolvedLauncher {
            launcher_id,
            source,
        }))
    };
    match launcher_from_puzzle_hash(client, puzzle_hash, scan).await? {
        Found::Launcher(id) => resolved(id, format!("address {original}")),
        Found::InScan(id, range) => {
            resolved(id, format!("address {original}, launcher scan of {range}"))
        }
        Found::Nothing(None) => Ok(Err(LookupGap::LauncherNotFound)),
        Found::Nothing(Some(range)) => Ok(Err(LookupGap::NoLauncherInScan {
            start: range.start(),
            end: range.end(),
        })),
    }
}

/// Highest receive-address nonce tried when rebuilding an address. Cloud Wallet
/// derives addresses at nonces 1 to 100 on top of the default address at 0. An
/// address above that is still found from any spend that reveals its puzzle.
const MAX_P2_NONCE: usize = 100;

enum Found {
    Launcher(Bytes32),
    InScan(Bytes32, HeightRange),
    /// Holds the scanned range when a scan ran.
    Nothing(Option<HeightRange>),
}

async fn launcher_from_puzzle_hash<C>(
    client: &ChainClient<C>,
    puzzle_hash: Bytes32,
    scan: Option<&LauncherScan>,
) -> Result<Found>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    let exact = client.find_coins_by_puzzle_hash(puzzle_hash, true).await?;
    if let Some(id) = launcher_from_spent_records(client, &exact, puzzle_hash).await? {
        return Ok(Found::Launcher(id));
    }

    let hinted = client.find_coins_by_hint(puzzle_hash, true).await?;
    if let Some(id) = launcher_from_spent_records(client, &hinted, puzzle_hash).await? {
        return Ok(Found::Launcher(id));
    }

    // A vault that has only received funds never reveals its launcher at the address.
    // When asked, check every launcher in the given range against the address.
    let mut scanned = None;
    if let Some(scan) = scan {
        let range = scan.resolve(client).await?;
        if let Some(id) = scan_launchers(client, puzzle_hash, range).await? {
            return Ok(Found::InScan(id, range));
        }
        scanned = Some(range);
    }

    if let Some(id) = launcher_from_unspent_records(client, &exact, puzzle_hash).await? {
        return Ok(Found::Launcher(id));
    }
    Ok(
        match launcher_from_unspent_records(client, &hinted, puzzle_hash).await? {
            Some(id) => Found::Launcher(id),
            None => Found::Nothing(scanned),
        },
    )
}

async fn launcher_from_spent_records<C>(
    client: &ChainClient<C>,
    records: &[CoinRecord],
    puzzle_hash: Bytes32,
) -> Result<Option<Bytes32>>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
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

/// Fetches each unspent coin's parent once. A parent spend that reveals a launcher is
/// checked against the address. For an odd (singleton) coin whose parent spend reveals
/// none, the walk goes on toward the launcher.
async fn launcher_from_unspent_records<C>(
    client: &ChainClient<C>,
    records: &[CoinRecord],
    puzzle_hash: Bytes32,
) -> Result<Option<Bytes32>>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    for rec in records.iter().filter(|r| !r.spent) {
        let Some(parent) = client.get_coin_record(rec.coin.parent_coin_info).await? else {
            continue;
        };
        let spend = if parent.spent {
            client
                .get_spend(parent.coin.coin_id(), parent.spent_block_index)
                .await?
        } else {
            None
        };
        if let Some(spend) = &spend
            && let Some(id) = launcher_from_spend(spend)
        {
            if spend_belongs_to_address(spend, id, puzzle_hash) {
                return Ok(Some(id));
            }
            continue;
        }
        if rec.coin.amount % 2 == 0 {
            continue;
        }
        let walked = if parent.coin.puzzle_hash == SINGLETON_LAUNCHER_HASH.into() {
            Some(parent.coin.coin_id())
        } else {
            walk_parents_to_launcher(client, parent.coin.parent_coin_info).await?
        };
        if let Some(id) = walked
            && launcher_matches_address(id, puzzle_hash)
        {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

async fn scan_launchers<C>(
    client: &ChainClient<C>,
    puzzle_hash: Bytes32,
    range: HeightRange,
) -> Result<Option<Bytes32>>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    let launchers = client
        .find_launchers_between(range.start(), range.end())
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

async fn walk_parents_to_launcher<C>(
    client: &ChainClient<C>,
    mut parent_id: Bytes32,
) -> Result<Option<Bytes32>>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
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
    use chia_protocol::Coin;
    use chia_sdk_driver::SpendContext;
    use chia_sdk_types::puzzles::{DelegatedPuzzleFeederArgs, IndexWrapperArgs};
    use serde_json::json;

    use super::*;
    use crate::address::encode_address;
    use crate::test_rpc::{ScriptedRpc, hex_id, page, record};

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

    fn vault_launcher() -> Coin {
        Coin::new(Bytes32::new([0x50; 32]), SINGLETON_LAUNCHER_HASH.into(), 1)
    }

    fn nft_launcher() -> Coin {
        Coin::new(Bytes32::new([0x60; 32]), SINGLETON_LAUNCHER_HASH.into(), 1)
    }

    /// A spent singleton of `launcher_id` and its spend, as an NFT reveals when it moves.
    fn singleton_spend(launcher_id: Bytes32, parent: Bytes32) -> CoinSpend {
        let mut ctx = SpendContext::new();
        let inner = ctx.alloc(&1).unwrap();
        let puzzle = SingletonLayer::new(launcher_id, Puzzle::parse(&ctx, inner))
            .construct_puzzle(&mut ctx)
            .unwrap();
        CoinSpend::new(
            Coin::new(parent, ctx.tree_hash(puzzle).into(), 1),
            ctx.serialize(&puzzle).unwrap(),
            ctx.serialize(&NodePtr::NIL).unwrap(),
        )
    }

    fn address(locator_ph: Bytes32) -> VaultLocator {
        VaultLocator::Address {
            original: "test address".into(),
            hrp: "xch".into(),
            puzzle_hash: locator_ph,
        }
    }

    async fn resolve(
        rpc: ScriptedRpc,
        puzzle_hash: Bytes32,
        scan: Option<&LauncherScan>,
    ) -> Result<std::result::Result<ResolvedLauncher, LookupGap>> {
        resolve_launcher_id(&ChainClient::with_rpc(rpc), &address(puzzle_hash), scan).await
    }

    #[tokio::test]
    async fn nft_at_the_address_is_not_the_vault_launcher() {
        let address_ph = cloud_wallet_p2_hash(vault_launcher().coin_id(), 0);
        let nft_id = nft_launcher().coin_id();
        // A moved NFT: its parent spend reveals the NFT singleton.
        let moved_parent = singleton_spend(nft_id, nft_id);
        let moved = Coin::new(moved_parent.coin.coin_id(), Bytes32::new([0x61; 32]), 1);
        // A fresh NFT: its parent is the NFT launcher itself.
        let fresh = Coin::new(nft_id, Bytes32::new([0x62; 32]), 1);
        // The spent NFT coin is hinted too, as the NFT moved through the address.
        let hinted = [
            record(moved_parent.coin, Some(5)),
            record(moved, None),
            record(fresh, None),
        ];
        let parents = [
            record(moved_parent.coin, Some(5)),
            record(nft_launcher(), Some(4)),
        ];
        let rpc = ScriptedRpc::new(move |endpoint, body| match endpoint {
            "get_coin_records_by_puzzle_hash" => Some(page(&[], None, false)),
            "get_coin_records_by_hint" => Some(page(&hinted, None, false)),
            "get_coin_record_by_name" => parents
                .iter()
                .find(|r| body["name"] == hex_id(r.coin.coin_id()))
                .map(|r| json!({ "coin_record": r, "success": true })),
            "get_puzzle_and_solution" if body["coin_id"] == hex_id(moved_parent.coin.coin_id()) => {
                Some(json!({ "coin_solution": moved_parent, "success": true }))
            }
            "get_puzzle_and_solution" => Some(json!({ "coin_solution": null, "success": true })),
            _ => None,
        });
        let found = resolve(rpc, address_ph, None).await.unwrap();
        assert!(
            matches!(found, Err(LookupGap::LauncherNotFound)),
            "{found:?}"
        );
    }

    #[tokio::test]
    async fn vault_singleton_hinted_to_its_address_is_found() {
        let vault = vault_launcher().coin_id();
        let address_ph = cloud_wallet_p2_hash(vault, 0);
        let eve = Coin::new(vault, Bytes32::new([0x63; 32]), 1);
        let rpc = ScriptedRpc::new(move |endpoint, body| match endpoint {
            "get_coin_records_by_puzzle_hash" => Some(page(&[], None, false)),
            "get_coin_records_by_hint" => Some(page(&[record(eve, None)], None, false)),
            "get_coin_record_by_name" if body["name"] == hex_id(vault) => {
                Some(json!({ "coin_record": record(vault_launcher(), Some(4)), "success": true }))
            }
            "get_puzzle_and_solution" => Some(json!({ "coin_solution": null, "success": true })),
            _ => None,
        });
        let found = resolve(rpc, address_ph, None).await.unwrap().unwrap();
        assert_eq!(found.launcher_id, vault);
    }

    #[tokio::test]
    async fn hinted_cat_spend_proves_its_launcher() {
        let vault = vault_launcher().coin_id();
        let mut ctx = SpendContext::new();
        // Past the rebuilt nonces, so only the revealed inner puzzle can match.
        let member = ctx.curry(SingletonMember::new(vault)).unwrap();
        let feeder = ctx.curry(DelegatedPuzzleFeederArgs::new(member)).unwrap();
        let p2 = ctx
            .curry(IndexWrapperArgs::new(MAX_P2_NONCE + 1, feeder))
            .unwrap();
        let address_ph = Bytes32::from(ctx.tree_hash(p2));
        let cat = CatLayer::new(Bytes32::new([0x70; 32]), Puzzle::parse(&ctx, p2))
            .construct_puzzle(&mut ctx)
            .unwrap();
        let spend = CoinSpend::new(
            Coin::new(Bytes32::new([0x71; 32]), ctx.tree_hash(cat).into(), 10),
            ctx.serialize(&cat).unwrap(),
            ctx.serialize(&NodePtr::NIL).unwrap(),
        );
        assert_eq!(revealed_p2_puzzle_hash(&spend), Some(address_ph));
        assert!(!launcher_matches_address(vault, address_ph));

        let coin = record(spend.coin, Some(9));
        let rpc = ScriptedRpc::new(move |endpoint, _| match endpoint {
            "get_coin_records_by_puzzle_hash" => Some(page(&[], None, false)),
            "get_coin_records_by_hint" => Some(page(&[coin], None, false)),
            "get_puzzle_and_solution" => Some(json!({ "coin_solution": spend, "success": true })),
            _ => None,
        });
        let found = resolve(rpc, address_ph, None).await.unwrap().unwrap();
        assert_eq!(found.launcher_id, vault);
    }

    /// Launcher pages for blocks 100..200: an NFT launcher, then (behind a cursor) `second`.
    fn launcher_pages(second: Option<Coin>, cursor: Option<&'static str>) -> ScriptedRpc {
        ScriptedRpc::new(move |endpoint, body| {
            let launchers = body["puzzle_hash"] == hex_id(SINGLETON_LAUNCHER_HASH.into());
            match endpoint {
                "get_coin_records_by_puzzle_hash" if launchers => {
                    assert_eq!(
                        (body["start_height"].as_u64(), body["end_height"].as_u64()),
                        (Some(100), Some(200))
                    );
                    Some(match body.get("cursor") {
                        None => page(&[record(nft_launcher(), Some(150))], cursor, true),
                        Some(_) => page(
                            &second
                                .map(|c| record(c, Some(160)))
                                .into_iter()
                                .collect::<Vec<_>>(),
                            None,
                            false,
                        ),
                    })
                }
                "get_coin_records_by_puzzle_hash" | "get_coin_records_by_hint" => {
                    Some(page(&[], None, false))
                }
                _ => None,
            }
        })
    }

    #[tokio::test]
    async fn scan_finds_the_vault_launcher_on_a_later_page() {
        let vault = vault_launcher().coin_id();
        let address_ph = cloud_wallet_p2_hash(vault, 3);
        let scan = LauncherScan::heights(100, 200, false).unwrap();
        let rpc = launcher_pages(Some(vault_launcher()), Some("next"));
        let found = resolve(rpc, address_ph, Some(&scan))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.launcher_id, vault);
        assert!(found.source.contains("blocks 100..200"), "{}", found.source);
    }

    #[tokio::test]
    async fn scan_without_a_match_reports_the_range() {
        let address_ph = cloud_wallet_p2_hash(vault_launcher().coin_id(), 0);
        let scan = LauncherScan::heights(100, 200, false).unwrap();
        let rpc = launcher_pages(None, Some("next"));
        let found = resolve(rpc, address_ph, Some(&scan)).await.unwrap();
        assert!(
            matches!(
                found,
                Err(LookupGap::NoLauncherInScan {
                    start: 100,
                    end: 200
                })
            ),
            "{found:?}"
        );
    }

    #[tokio::test]
    async fn scan_fails_on_a_truncated_page_without_a_cursor() {
        let address_ph = cloud_wallet_p2_hash(vault_launcher().coin_id(), 0);
        let scan = LauncherScan::heights(100, 200, false).unwrap();
        let rpc = launcher_pages(Some(vault_launcher()), None);
        let err = resolve(rpc, address_ph, Some(&scan)).await.unwrap_err();
        assert!(err.to_string().contains("narrower range"), "{err}");
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
