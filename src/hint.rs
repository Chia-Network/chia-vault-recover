//! Read the Cloud Wallet CHIP-0043 memo that hints vault recovery details.
//!
//! A vault singleton spend (including the launcher mint) attaches this memo to
//! the recreated singleton. It reveals custody and recovery members and commits
//! to the clawback timelock. That memo is the primary source for the public layout.

use std::collections::HashSet;

use chia_protocol::{Bytes32, CoinSpend};
use chia_sdk_driver::{
    Force1of2RestrictedVariableMemo, InnerPuzzleMemo, MemberMemo, MemoKind, MipsMemo,
    MipsMemoContext, MofNMemo, ParsedMember, SpendContext,
};
use chia_sdk_types::Mod;
use chia_sdk_types::puzzles::Timelock;
use clvm_traits::FromClvm;
use clvm_utils::ToTreeHash;
use clvmr::{Allocator, NodePtr, ObjectType, SExp};

use crate::config::{VaultConfig, VaultConfigRecovery, VaultConfigSide, config_members_from_keys};
use crate::vault::{VaultMemberKey, get_vault_internals};

const CHIP_NAMESPACE: &[u8] = b"CHIP-0043";

/// Public layout from a CHIP-0043 memo whose singleton puzzle matches `full_puzzle_hash`.
///
/// `timelock_candidates` are the only seconds tried against the committed timelock hash.
pub fn hinted_config_from_spend(
    spend: &CoinSpend,
    launcher_id: Bytes32,
    full_puzzle_hash: Bytes32,
    timelock_candidates: &[u64],
) -> Option<VaultConfig> {
    let mut ctx = SpendContext::new();
    let puzzle = ctx.alloc(&spend.puzzle_reveal).ok()?;
    let solution = ctx.alloc(&spend.solution).ok()?;
    let mut memos = Vec::new();
    collect_mips_memos(&ctx, puzzle, &mut memos);
    collect_mips_memos(&ctx, solution, &mut memos);
    for memo in memos {
        let Some(config) = config_from_mips_memo(&ctx, launcher_id, &memo, timelock_candidates)
        else {
            continue;
        };
        let Ok(keys) = config.to_vault_keys() else {
            continue;
        };
        let Ok(internals) = get_vault_internals(launcher_id, &keys) else {
            continue;
        };
        if internals.full_puzzle_hash == full_puzzle_hash {
            return Some(config);
        }
    }
    None
}

pub fn config_from_mips_memo(
    allocator: &Allocator,
    launcher_id: Bytes32,
    memo: &MipsMemo,
    timelock_candidates: &[u64],
) -> Option<VaultConfig> {
    let MemoKind::MofN(MofNMemo { required: 1, items }) = &memo.inner_puzzle.kind else {
        return None;
    };
    if items.len() != 2 {
        return None;
    }
    let left_timelock = recovery_timelock(allocator, &items[0], timelock_candidates);
    let right_timelock = recovery_timelock(allocator, &items[1], timelock_candidates);
    let (custody, recovery, timelock) = match (left_timelock, right_timelock) {
        (None, Some(secs)) => (&items[0], &items[1], secs),
        (Some(secs), None) => (&items[1], &items[0], secs),
        _ => return None,
    };
    let (custody_threshold, custody_keys, custody_vaults) = parse_side(allocator, custody)?;
    let (recovery_threshold, recovery_keys, recovery_vaults) = parse_side(allocator, recovery)?;
    if custody_keys.is_empty() && custody_vaults.is_empty() {
        return None;
    }
    if recovery_keys.is_empty() && recovery_vaults.is_empty() {
        return None;
    }
    let recovery_members = config_members_from_keys(&recovery_keys, &recovery_vaults);
    Some(VaultConfig {
        launcher_id: format!("0x{}", hex::encode(launcher_id)),
        custody: VaultConfigSide {
            threshold: custody_threshold,
            members: config_members_from_keys(&custody_keys, &custody_vaults),
            hash: None,
        },
        recovery: VaultConfigRecovery {
            threshold: recovery_threshold,
            clawback_timelock: timelock,
            members: recovery_members,
        },
    })
}

fn collect_mips_memos(alloc: &Allocator, root: NodePtr, out: &mut Vec<MipsMemo>) {
    let mut stack = vec![root];
    let mut seen = HashSet::new();
    let mut steps = 0u32;
    while let Some(node) = stack.pop() {
        steps += 1;
        if steps > 200_000 {
            break;
        }
        if !seen.insert(node.index()) {
            continue;
        }
        let SExp::Pair(first, rest) = alloc.sexp(node) else {
            continue;
        };
        if is_chip_namespace(alloc, first)
            && let Ok(memo) = MipsMemo::from_clvm(alloc, node)
        {
            out.push(memo);
        }
        stack.push(first);
        stack.push(rest);
    }
}

fn is_chip_namespace(alloc: &Allocator, node: NodePtr) -> bool {
    node.object_type() == ObjectType::Bytes && alloc.atom(node).as_ref() == CHIP_NAMESPACE
}

fn recovery_timelock(
    allocator: &Allocator,
    inner: &InnerPuzzleMemo,
    timelock_candidates: &[u64],
) -> Option<u64> {
    // `enforce_delegated_puzzle_wrappers` stores wrapper inner memos, not
    // `WrapperMemo` pairs, so `RestrictionMemo::parse` does not see them.
    for restriction in &inner.restrictions {
        let Ok(memos) = Vec::<NodePtr>::from_clvm(allocator, restriction.memo) else {
            continue;
        };
        if let Some(secs) = timelock_from_wrapper_memos(allocator, &memos, timelock_candidates) {
            return Some(secs);
        }
    }
    None
}

fn timelock_from_wrapper_memos(
    allocator: &Allocator,
    memos: &[NodePtr],
    timelock_candidates: &[u64],
) -> Option<u64> {
    for ptr in memos {
        if let Ok(force) = Force1of2RestrictedVariableMemo::from_clvm(allocator, *ptr)
            && let Some(secs) =
                timelock_for_list_hash(force.member_validator_list_hash, timelock_candidates)
        {
            return Some(secs);
        }
    }
    None
}

fn timelock_for_list_hash(hash: Bytes32, timelock_candidates: &[u64]) -> Option<u64> {
    let target = clvm_utils::TreeHash::from(hash);
    timelock_candidates
        .iter()
        .copied()
        .find(|&secs| vec![Timelock::new(secs).curry_tree_hash()].tree_hash() == target)
}

fn parse_side(
    allocator: &Allocator,
    inner: &InnerPuzzleMemo,
) -> Option<(u32, Vec<VaultMemberKey>, Vec<Bytes32>)> {
    match &inner.kind {
        MemoKind::Member(member) => {
            let mut keys = Vec::new();
            let mut vaults = Vec::new();
            push_member(allocator, member, &mut keys, &mut vaults)?;
            Some((1, keys, vaults))
        }
        MemoKind::MofN(m_of_n) => {
            if m_of_n.required == 0 || m_of_n.items.is_empty() {
                return None;
            }
            let mut keys = Vec::new();
            let mut vaults = Vec::new();
            for item in &m_of_n.items {
                let MemoKind::Member(member) = &item.kind else {
                    return None;
                };
                push_member(allocator, member, &mut keys, &mut vaults)?;
            }
            Some((u32::try_from(m_of_n.required).ok()?, keys, vaults))
        }
    }
}

enum MemoMember {
    Key(VaultMemberKey),
    Vault(Bytes32),
}

fn push_member(
    allocator: &Allocator,
    member: &MemberMemo,
    keys: &mut Vec<VaultMemberKey>,
    vaults: &mut Vec<Bytes32>,
) -> Option<()> {
    match one_member(allocator, member)? {
        MemoMember::Key(key) => keys.push(key),
        MemoMember::Vault(id) => vaults.push(id),
    }
    Some(())
}

fn one_member(allocator: &Allocator, member: &MemberMemo) -> Option<MemoMember> {
    let parsed = member.parse(allocator, &MipsMemoContext::default())?;
    Some(match parsed {
        ParsedMember::Bls(member) => MemoMember::Key(VaultMemberKey::Bls(member.public_key)),
        ParsedMember::BlsPuzzleAssert(member) => {
            MemoMember::Key(VaultMemberKey::Bls(member.public_key))
        }
        ParsedMember::BlsTaproot(member) => {
            MemoMember::Key(VaultMemberKey::Bls(member.synthetic_key))
        }
        ParsedMember::BlsTaprootPuzzleAssert(member) => {
            MemoMember::Key(VaultMemberKey::Bls(member.synthetic_key))
        }
        ParsedMember::K1(member) => MemoMember::Key(VaultMemberKey::K1(member.public_key)),
        ParsedMember::K1PuzzleAssert(member) => {
            MemoMember::Key(VaultMemberKey::K1(member.public_key))
        }
        ParsedMember::R1(member) => MemoMember::Key(VaultMemberKey::R1(member.public_key)),
        ParsedMember::R1PuzzleAssert(member) => {
            MemoMember::Key(VaultMemberKey::R1(member.public_key))
        }
        ParsedMember::Passkey(member) => {
            MemoMember::Key(VaultMemberKey::Passkey(member.public_key))
        }
        ParsedMember::PasskeyPuzzleAssert(member) => {
            MemoMember::Key(VaultMemberKey::Passkey(member.public_key))
        }
        ParsedMember::Singleton(member) => MemoMember::Vault(member.singleton_struct.launcher_id),
        ParsedMember::SingletonWithMode(member) => {
            MemoMember::Vault(member.singleton_struct.launcher_id)
        }
        ParsedMember::FixedPuzzle(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use chia_bls::SecretKey;
    use chia_protocol::{Bytes32, Coin, CoinSpend};
    use chia_sdk_driver::{
        InnerPuzzleMemo, MemberMemo, MemoKind, MipsMemo, MofNMemo, RestrictionMemo, SpendContext,
        WrapperMemo,
    };
    use chia_sdk_test::K1Pair;
    use chia_sdk_types::Mod;
    use clvm_utils::ToTreeHash;
    use clvmr::NodePtr;

    use super::*;
    use crate::vault::prevent_vault_side_effect_opcodes;

    fn cloud_wallet_memo(
        ctx: &mut SpendContext,
        custody: chia_secp::K1PublicKey,
        recovery: chia_bls::PublicKey,
        timelock: u64,
    ) -> MipsMemo {
        let custody_member = MemberMemo::k1(ctx, custody, true, true).unwrap();
        let custody_inner = InnerPuzzleMemo::new(0, vec![], MemoKind::Member(custody_member));
        let custody_hash = custody_inner.inner_puzzle_hash(false);
        let recovery_member = MemberMemo::bls(ctx, recovery, false, false, true).unwrap();
        let restriction = recovery_wrappers(ctx, custody_hash, timelock);
        let recovery_inner =
            InnerPuzzleMemo::new(0, vec![restriction], MemoKind::Member(recovery_member));
        MipsMemo::new(InnerPuzzleMemo::new(
            0,
            vec![],
            MemoKind::MofN(MofNMemo::new(1, vec![custody_inner, recovery_inner])),
        ))
    }

    fn recovery_wrappers(
        ctx: &mut SpendContext,
        custody_hash: clvm_utils::TreeHash,
        timelock: u64,
    ) -> RestrictionMemo {
        let list_hash = vec![Timelock::new(timelock).curry_tree_hash()].tree_hash();
        let force = RestrictionMemo::force_1_of_2_restricted_variable(
            ctx,
            custody_hash.into(),
            0,
            list_hash.into(),
            ().tree_hash().into(),
        )
        .unwrap();
        let mut wrappers = vec![WrapperMemo::new(force.puzzle_hash, force.memo)];
        for opcode in prevent_vault_side_effect_opcodes() {
            wrappers.push(WrapperMemo::prevent_condition_opcode(ctx, opcode, true).unwrap());
        }
        wrappers.push(WrapperMemo::prevent_multiple_create_coins());
        RestrictionMemo::enforce_delegated_puzzle_wrappers(ctx, &wrappers).unwrap()
    }

    #[test]
    fn memo_round_trip_matches_vault_puzzle() {
        let mut ctx = SpendContext::new();
        let custody = K1Pair::default();
        let recovery = SecretKey::from_seed(&[7; 32]).public_key();
        let launcher = Bytes32::new([0x44; 32]);
        let memo = cloud_wallet_memo(&mut ctx, custody.pk, recovery, 43_200);
        let config = config_from_mips_memo(&ctx, launcher, &memo, &[43_200]).expect("hint");
        assert_eq!(config.recovery.clawback_timelock, 43_200);
        assert_eq!(config.custody.threshold, 1);
        let internals = get_vault_internals(launcher, &config.to_vault_keys().unwrap()).unwrap();
        assert_eq!(internals.inner_puzzle_hash, memo.inner_puzzle_hash());
    }

    #[test]
    fn spend_solution_yields_matching_config() {
        let mut ctx = SpendContext::new();
        let custody = K1Pair::default();
        let recovery = SecretKey::from_seed(&[9; 32]).public_key();
        let launcher = Bytes32::new([0x55; 32]);
        let memo = cloud_wallet_memo(&mut ctx, custody.pk, recovery, 10);
        let config = config_from_mips_memo(&ctx, launcher, &memo, &[10]).unwrap();
        let internals = get_vault_internals(launcher, &config.to_vault_keys().unwrap()).unwrap();
        let solution = ctx.serialize(&vec![memo]).unwrap();
        let puzzle = ctx.serialize(&NodePtr::NIL).unwrap();
        let coin = Coin::new(Bytes32::default(), internals.full_puzzle_hash, 1);
        let spend = CoinSpend::new(coin, puzzle, solution);
        let parsed = hinted_config_from_spend(&spend, launcher, internals.full_puzzle_hash, &[10])
            .expect("hint on spend");
        assert_eq!(parsed.recovery.clawback_timelock, 10);
    }

    #[test]
    fn custom_timelock_matches_only_when_supplied() {
        let mut ctx = SpendContext::new();
        let custody = K1Pair::default();
        let recovery = SecretKey::from_seed(&[3; 32]).public_key();
        let memo = cloud_wallet_memo(&mut ctx, custody.pk, recovery, 1_234);
        assert!(config_from_mips_memo(&ctx, Bytes32::default(), &memo, &[43_200]).is_none());
        let config = config_from_mips_memo(&ctx, Bytes32::default(), &memo, &[1_234]).unwrap();
        assert_eq!(config.recovery.clawback_timelock, 1_234);
        assert!(matches!(
            config.recovery.members.first(),
            Some(crate::config::VaultConfigMember::PublicKey {
                key_type: None,
                curve: crate::config::Curve::Bls12_381,
                ..
            })
        ));
    }
}
