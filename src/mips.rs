//! Shared MIPS layer types for address lookup and custody discovery.

use chia_protocol::{Bytes32, CoinSpend};
use chia_sdk_driver::{
    DelegatedPuzzleFeederLayer, IndexWrapperLayer, Layer, P2SingletonLayer, Puzzle, SingletonLayer,
    SingletonMemberLayer, SpendContext, mips_puzzle_hash,
};
use chia_sdk_types::Mod;
use chia_sdk_types::puzzles::{P2SingletonArgs, SingletonMember};
use clvmr::NodePtr;

use crate::error::Result;

pub type CloudWalletP2 = IndexWrapperLayer<usize, DelegatedPuzzleFeederLayer<SingletonMemberLayer>>;
pub type VaultMipsInner = IndexWrapperLayer<usize, DelegatedPuzzleFeederLayer<Puzzle>>;
pub type VaultSingleton = SingletonLayer<VaultMipsInner>;

/// Highest receive-address nonce tried when rebuilding an address.
///
/// The repository does not record a Cloud Wallet limit behind this value, so 100
/// is a chosen search bound for the address-derived walk. Cloud Wallet's default
/// address is nonce 0. An address at a higher nonce is still found from any spend
/// that reveals its puzzle, which does not depend on this bound.
pub const MAX_P2_NONCE: usize = 100;

// Receive addresses. The parser and the matcher below are the only places that know
// the receive (p2) puzzle shapes: classic p2-singleton and [`CloudWalletP2`]. The vault
// singleton's own puzzle never enters the address, so changes to it need nothing here.
// A new receive shape is added to both functions; until then those vaults report
// "not found", never a wrong launcher.

/// Cloud Wallet's receive puzzle for `launcher_id` at `nonce`.
pub fn cloud_wallet_p2(launcher_id: Bytes32, nonce: usize) -> CloudWalletP2 {
    IndexWrapperLayer::new(
        nonce,
        DelegatedPuzzleFeederLayer::new(SingletonMemberLayer::new(launcher_id)),
    )
}

/// The launcher a receive puzzle pays to, if `puzzle` is one.
pub fn receive_puzzle_launcher(alloc: &clvmr::Allocator, puzzle: Puzzle) -> Option<Bytes32> {
    if let Ok(Some(p2)) = P2SingletonLayer::parse_puzzle(alloc, puzzle) {
        return Some(p2.launcher_id);
    }
    CloudWalletP2::parse_puzzle(alloc, puzzle)
        .ok()
        .flatten()
        .map(|p2| p2.inner_puzzle.inner_puzzle.launcher_id)
}

/// Whether `puzzle_hash` is a receive address of `launcher_id`: classic p2-singleton,
/// or [`cloud_wallet_p2`] at any nonce up to [`MAX_P2_NONCE`].
pub fn launcher_matches_address(launcher_id: Bytes32, puzzle_hash: Bytes32) -> bool {
    if Bytes32::from(P2SingletonArgs::curry_tree_hash(launcher_id)) == puzzle_hash {
        return true;
    }
    // The hash of `cloud_wallet_p2`, with the member hashed once for every nonce.
    let member = SingletonMember::new(launcher_id).curry_tree_hash();
    (0..=MAX_P2_NONCE).any(|nonce| {
        Bytes32::from(mips_puzzle_hash(nonce, Vec::new(), member, true)) == puzzle_hash
    })
}

pub fn alloc_spend(spend: &CoinSpend) -> Result<(SpendContext, Puzzle, NodePtr)> {
    let mut ctx = SpendContext::new();
    let puzzle_ptr = ctx.alloc(&spend.puzzle_reveal)?;
    let solution_ptr = ctx.alloc(&spend.solution)?;
    let puzzle = Puzzle::parse(&ctx, puzzle_ptr);
    Ok((ctx, puzzle, solution_ptr))
}

/// Peel singleton + index wrapper + delegated feeder.
/// Returns the inner puzzle (typically OneOfN) and its solution.
pub fn peel_vault_mips(
    alloc: &clvmr::Allocator,
    puzzle: Puzzle,
    solution: NodePtr,
) -> Result<Option<(Puzzle, NodePtr)>> {
    let Some(vault) = VaultSingleton::parse_puzzle(alloc, puzzle)? else {
        return Ok(None);
    };
    let sol = VaultSingleton::parse_solution(alloc, solution)?;
    Ok(Some((
        vault.inner_puzzle.inner_puzzle.inner_puzzle,
        sol.inner_solution.inner_solution,
    )))
}

pub fn peel_index_wrapper(alloc: &clvmr::Allocator, puzzle: Puzzle) -> Puzzle {
    IndexWrapperLayer::<usize, Puzzle>::parse_puzzle(alloc, puzzle)
        .ok()
        .flatten()
        .map(|wrapped| wrapped.inner_puzzle)
        .unwrap_or(puzzle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(ctx: &mut SpendContext, layer: &impl Layer) -> Bytes32 {
        let ptr = layer.construct_puzzle(ctx).unwrap();
        ctx.tree_hash(ptr).into()
    }

    /// Pins the chosen nonce bound and the revealed-puzzle fallback for higher nonces.
    #[test]
    fn address_matches_its_own_launcher_only() {
        let launcher = Bytes32::new([0x44; 32]);
        let other = Bytes32::new([0x45; 32]);
        let mut ctx = SpendContext::new();
        for nonce in [0, 1, MAX_P2_NONCE] {
            let address = hash(&mut ctx, &cloud_wallet_p2(launcher, nonce));
            assert!(launcher_matches_address(launcher, address), "{nonce}");
            assert!(!launcher_matches_address(other, address), "{nonce}");
        }
        let beyond = hash(&mut ctx, &cloud_wallet_p2(launcher, MAX_P2_NONCE + 1));
        assert!(!launcher_matches_address(launcher, beyond));
        let classic = hash(&mut ctx, &P2SingletonLayer::new(launcher));
        assert!(launcher_matches_address(launcher, classic));
        assert!(!launcher_matches_address(other, classic));
    }

    #[test]
    fn receive_puzzles_parse_to_their_launcher() {
        let launcher = Bytes32::new([0x42; 32]);
        let mut ctx = SpendContext::new();
        for ptr in [
            cloud_wallet_p2(launcher, 7)
                .construct_puzzle(&mut ctx)
                .unwrap(),
            P2SingletonLayer::new(launcher)
                .construct_puzzle(&mut ctx)
                .unwrap(),
        ] {
            let puzzle = Puzzle::parse(&ctx, ptr);
            assert_eq!(receive_puzzle_launcher(&ctx, puzzle), Some(launcher));
        }
        let other = ctx.alloc(&1).unwrap();
        assert_eq!(
            receive_puzzle_launcher(&ctx, Puzzle::parse(&ctx, other)),
            None
        );
    }
}
