//! Resolve a vault launcher id from a receive address or hex launcher id.

use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_sdk_coinset::CoinRecord;
use chia_sdk_driver::{CatLayer, Layer, P2SingletonLayer, Puzzle, SingletonLayer};
use chia_sdk_types::puzzles::OneOfNSolution;
use clvm_traits::FromClvm;
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

pub async fn resolve_launcher_id(
    client: &ChainClient,
    locator: &VaultLocator,
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
        } => Ok(launcher_from_puzzle_hash(client, *puzzle_hash)
            .await?
            .map(|id| ResolvedLauncher {
                launcher_id: id,
                source: format!("address {original}"),
            })),
    }
}

async fn launcher_from_puzzle_hash(
    client: &ChainClient,
    puzzle_hash: Bytes32,
) -> Result<Option<Bytes32>> {
    let exact = client.find_coins_by_puzzle_hash(puzzle_hash, true).await?;
    if let Some(id) = launcher_from_records(client, &exact).await? {
        return Ok(Some(id));
    }

    let hinted = client.find_coins_by_hint(puzzle_hash, true).await?;
    if let Some(id) = launcher_from_records(client, &hinted).await? {
        return Ok(Some(id));
    }

    Ok(None)
}

async fn launcher_from_records(
    client: &ChainClient,
    records: &[CoinRecord],
) -> Result<Option<Bytes32>> {
    for rec in records.iter().filter(|r| r.spent) {
        if let Some(spend) = client
            .get_spend(rec.coin.coin_id(), rec.spent_block_index)
            .await?
            && let Some(id) = launcher_from_spend(&spend)
        {
            return Ok(Some(id));
        }
    }

    for rec in records.iter().filter(|r| !r.spent) {
        if rec.coin.amount % 2 == 1
            && let Some(id) = walk_parents_to_launcher(client, rec.coin.parent_coin_info).await?
        {
            return Ok(Some(id));
        }
        if let Some(parent) = client.get_coin_record(rec.coin.parent_coin_info).await?
            && parent.spent
            && let Some(spend) = client
                .get_spend(parent.coin.coin_id(), parent.spent_block_index)
                .await?
            && let Some(id) = launcher_from_spend(&spend)
        {
            return Ok(Some(id));
        }
    }

    Ok(None)
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
    use chia_sdk_types::puzzles::SingletonMember;

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
