//! Vault topology hashes matching Cloud Wallet / ent-wallet `getVaultInternals`.

use chia_bls::PublicKey as BlsPublicKey;
use chia_protocol::Bytes32;
use chia_puzzle_types::{Memos, singleton::SingletonArgs};
use chia_puzzles::PREVENT_MULTIPLE_CREATE_COINS_HASH;
use chia_sdk_driver::{MofN, Restriction, RestrictionKind, Spend, SpendContext, mips_puzzle_hash};
use chia_sdk_types::{
    Conditions, Mod,
    puzzles::{
        AddDelegatedPuzzleWrapper, AddDelegatedPuzzleWrapperSolution, BlsMember,
        Force1of2RestrictedVariable, Force1of2RestrictedVariableSolution, K1Member,
        K1MemberPuzzleAssert, PasskeyMember, PasskeyMemberPuzzleAssert, PreventConditionOpcode,
        PreventMultipleCreateCoinsMod, R1Member, R1MemberPuzzleAssert, SingletonMember, Timelock,
    },
};
use chia_secp::{K1PublicKey, R1PublicKey};
use clvm_utils::{ToTreeHash, TreeHash};
use clvmr::NodePtr;

use crate::error::{Error, Result};
use crate::finish_member::{empty_delegated_spend, member_spend};

#[derive(Debug, Clone)]
pub enum VaultMemberKey {
    Bls(BlsPublicKey),
    K1(K1PublicKey),
    R1(R1PublicKey),
    Passkey(R1PublicKey),
}

#[derive(Debug, Clone)]
pub struct SignerSet {
    pub keys: Vec<VaultMemberKey>,
    pub vault_launcher_ids: Vec<Bytes32>,
    pub threshold: usize,
}

/// Custody as either a full signer set or a hash-only path from a previous spend.
#[derive(Debug, Clone)]
pub enum CustodyPath {
    Signers(SignerSet),
    Hash(TreeHash),
}

impl CustodyPath {
    pub fn hash(&self) -> Result<TreeHash> {
        match self {
            Self::Hash(hash) => Ok(*hash),
            Self::Signers(set) => custody_member_hash(set),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoverySignerSet {
    pub set: SignerSet,
    pub clawback_timelock: u64,
}

#[derive(Debug, Clone)]
pub struct VaultKeys {
    pub custody: CustodyPath,
    pub recovery: RecoverySignerSet,
}

#[derive(Debug, Clone)]
pub struct VaultInternals {
    pub launcher_id: Bytes32,
    pub inner_puzzle_hash: TreeHash,
    pub full_puzzle_hash: Bytes32,
    pub custody_hash: TreeHash,
    pub recovery_hash: TreeHash,
    pub recovery_restrictions: Vec<Restriction>,
    pub clawback_timelock: u64,
}

/// Hashes for the intermediate RECOVERY-state vault (no spend allocated).
#[derive(Debug, Clone)]
pub struct RecoveryStateHashes {
    pub internals: VaultInternals,
    /// Puzzle hash of the right-hand finish member.
    pub finish_member_hash: TreeHash,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedFinish {
    pub state: RecoveryStateHashes,
    pub member: Spend,
    pub delegated: Spend,
}

pub fn get_vault_internals(launcher_id: Bytes32, keys: &VaultKeys) -> Result<VaultInternals> {
    let custody_hash = keys.custody.hash()?;
    let (recovery_hash, recovery_restrictions) = ready_recovery_hash(custody_hash, &keys.recovery)?;

    let inner_puzzle_hash = top_level_hash(custody_hash, recovery_hash);
    let full_puzzle_hash = SingletonArgs::curry_tree_hash(launcher_id, inner_puzzle_hash).into();

    Ok(VaultInternals {
        launcher_id,
        inner_puzzle_hash,
        full_puzzle_hash,
        custody_hash,
        recovery_hash,
        recovery_restrictions,
        clawback_timelock: keys.recovery.clawback_timelock,
    })
}

/// Compute RECOVERY-state puzzle hashes committed to `post_recovery_inner`.
pub fn recovery_state_hashes(
    launcher_id: Bytes32,
    keys: &VaultKeys,
    post_recovery_inner: TreeHash,
    amount: u64,
) -> Result<RecoveryStateHashes> {
    let mut ctx = SpendContext::new();
    Ok(prepare_finish(&mut ctx, launcher_id, keys, post_recovery_inner, amount)?.state)
}

/// Allocates the finish member and its delegated puzzle.
pub(crate) fn prepare_finish(
    ctx: &mut SpendContext,
    launcher_id: Bytes32,
    keys: &VaultKeys,
    post_recovery_inner: TreeHash,
    amount: u64,
) -> Result<PreparedFinish> {
    let (conditions, timelock_restriction) =
        finish_output(post_recovery_inner, amount, keys.recovery.clawback_timelock);
    let inner = empty_delegated_spend(ctx)?;
    let inner_hash = ctx.tree_hash(inner.puzzle);
    let wrapped = wrap_finish_delegated(ctx, inner)?;
    let member = member_spend(
        ctx,
        &wrapped.wrapper_stack,
        ctx.tree_hash(wrapped.spend.puzzle),
        inner_hash,
        &conditions,
    )?;
    let state = recovery_state_from_member_hash(
        launcher_id,
        keys,
        ctx.tree_hash(member.puzzle),
        timelock_restriction,
    )?;
    Ok(PreparedFinish {
        state,
        member,
        delegated: wrapped.spend,
    })
}

/// Recreation output and the timelock member validator, both from one [`Timelock`].
fn finish_output(
    post_recovery_inner: TreeHash,
    amount: u64,
    seconds: u64,
) -> (Conditions, Restriction) {
    let timelock = Timelock::new(seconds);
    let conditions = Conditions::new()
        .create_coin(post_recovery_inner.into(), amount, Memos::None)
        .assert_seconds_relative(timelock.seconds);
    let restriction = Restriction {
        kind: RestrictionKind::MemberCondition,
        puzzle_hash: timelock.curry_tree_hash(),
    };
    (conditions, restriction)
}

pub(crate) struct WrappedDelegated {
    pub spend: Spend,
    pub wrapper_stack: Vec<TreeHash>,
}

/// Wrap a finish delegated puzzle with the ready-branch opcode bans.
///
/// The single-`CREATE_COIN` wrapper is not applied. It requires exactly one
/// `CREATE_COIN`, and this delegated puzzle returns none: the recreation coin is
/// in the member output.
pub(crate) fn wrap_finish_delegated(
    ctx: &mut SpendContext,
    inner: Spend,
) -> Result<WrappedDelegated> {
    let mut stack = Vec::new();
    let mut wrappers = Vec::new();
    for opcode in prevent_vault_side_effect_opcodes() {
        let restriction = PreventConditionOpcode::new(opcode);
        stack.push(restriction.curry_tree_hash());
        let puzzle = ctx.curry(restriction)?;
        let solution = ctx.alloc(&NodePtr::NIL)?;
        wrappers.push(Spend::new(puzzle, solution));
    }

    // First opcode is outermost, matching `MipsSpend`'s wrapper application.
    let mut delegated = inner;
    for wrapper in wrappers.into_iter().rev() {
        let puzzle = ctx.curry(AddDelegatedPuzzleWrapper::new(
            wrapper.puzzle,
            delegated.puzzle,
        ))?;
        let solution = ctx.alloc(&AddDelegatedPuzzleWrapperSolution::new(
            wrapper.solution,
            delegated.solution,
        ))?;
        delegated = Spend::new(puzzle, solution);
    }

    Ok(WrappedDelegated {
        spend: delegated,
        wrapper_stack: stack,
    })
}

fn recovery_state_from_member_hash(
    launcher_id: Bytes32,
    keys: &VaultKeys,
    finish_member_hash: TreeHash,
    timelock_restriction: Restriction,
) -> Result<RecoveryStateHashes> {
    let custody_hash = keys.custody.hash()?;
    let timelock = keys.recovery.clawback_timelock;
    let recovery_hash = mips_puzzle_hash(0, vec![timelock_restriction], finish_member_hash, false);
    let inner_puzzle_hash = top_level_hash(custody_hash, recovery_hash);
    let full_puzzle_hash = SingletonArgs::curry_tree_hash(launcher_id, inner_puzzle_hash).into();

    Ok(RecoveryStateHashes {
        internals: VaultInternals {
            launcher_id,
            inner_puzzle_hash,
            full_puzzle_hash,
            custody_hash,
            recovery_hash,
            recovery_restrictions: vec![timelock_restriction],
            clawback_timelock: timelock,
        },
        finish_member_hash,
    })
}

/// Side-effect bans used on the READY recovery branch (typed — used for both hash and spend).
pub fn prevent_vault_side_effect_opcodes() -> [u16; 4] {
    [60, 62, 66, 67]
}

pub fn recovery_restrictions(custody_hash: TreeHash, clawback_timelock: u64) -> Vec<Restriction> {
    let mut restrictions = vec![force_1_of_2_restriction(custody_hash, clawback_timelock)];
    for opcode in prevent_vault_side_effect_opcodes() {
        restrictions.push(Restriction {
            kind: RestrictionKind::DelegatedPuzzleWrapper,
            puzzle_hash: PreventConditionOpcode::new(opcode).curry_tree_hash(),
        });
    }
    restrictions.push(Restriction {
        kind: RestrictionKind::DelegatedPuzzleWrapper,
        puzzle_hash: PREVENT_MULTIPLE_CREATE_COINS_HASH.into(),
    });
    restrictions
}

fn force_1_of_2_restriction(custody_hash: TreeHash, clawback_timelock: u64) -> Restriction {
    let timelock = Timelock::new(clawback_timelock);
    Restriction {
        kind: RestrictionKind::DelegatedPuzzleWrapper,
        puzzle_hash: Force1of2RestrictedVariable::new(
            custody_hash.into(),
            0,
            vec![timelock.curry_tree_hash()].tree_hash().into(),
            ().tree_hash().into(),
        )
        .curry_tree_hash(),
    }
}

/// Insert Force1of2 + prevent-side-effects restriction spends from the same typed constructors
/// used for puzzle hashes (no reverse hash lookup).
pub fn insert_recovery_restriction_spends(
    ctx: &mut SpendContext,
    mips: &mut chia_sdk_driver::MipsSpend,
    custody_hash: TreeHash,
    clawback_timelock: u64,
    finish_member_hash: TreeHash,
) -> Result<()> {
    let force = Force1of2RestrictedVariable::new(
        custody_hash.into(),
        0,
        vec![Timelock::new(clawback_timelock).curry_tree_hash()]
            .tree_hash()
            .into(),
        ().tree_hash().into(),
    );
    let force_hash = force.curry_tree_hash();
    let force_puzzle = ctx.curry(force)?;
    let force_solution = ctx.alloc(&Force1of2RestrictedVariableSolution::new(
        finish_member_hash.into(),
    ))?;
    mips.restrictions
        .insert(force_hash, Spend::new(force_puzzle, force_solution));

    for opcode in prevent_vault_side_effect_opcodes() {
        let restriction = PreventConditionOpcode::new(opcode);
        let ph = restriction.curry_tree_hash();
        let puzzle = ctx.curry(restriction)?;
        let solution = ctx.alloc(&NodePtr::NIL)?;
        mips.restrictions.insert(ph, Spend::new(puzzle, solution));
    }

    let multi_ph: TreeHash = PREVENT_MULTIPLE_CREATE_COINS_HASH.into();
    let puzzle = ctx.alloc_mod::<PreventMultipleCreateCoinsMod>()?;
    let solution = ctx.alloc(&NodePtr::NIL)?;
    mips.restrictions
        .insert(multi_ph, Spend::new(puzzle, solution));

    Ok(())
}

fn custody_member_hash(custody: &SignerSet) -> Result<TreeHash> {
    let mut hashes = member_hashes(custody, true)?;
    sort_hashes(&mut hashes);
    if hashes.len() == 1 && custody.threshold == 1 {
        Ok(hashes[0])
    } else {
        Ok(mips_puzzle_hash(
            0,
            Vec::new(),
            MofN::new(custody.threshold, hashes).inner_puzzle_hash(),
            false,
        ))
    }
}

fn ready_recovery_hash(
    custody_hash: TreeHash,
    recovery: &RecoverySignerSet,
) -> Result<(TreeHash, Vec<Restriction>)> {
    let restrictions = recovery_restrictions(custody_hash, recovery.clawback_timelock);
    let mut bare_hashes = member_hashes(&recovery.set, true)?;
    sort_hashes(&mut bare_hashes);

    let recovery_hash = if bare_hashes.len() == 1 && recovery.set.threshold == 1 {
        let inner = bare_inner_hash(&recovery.set.keys[0], true);
        mips_puzzle_hash(0, restrictions.clone(), inner, false)
    } else {
        mips_puzzle_hash(
            0,
            restrictions.clone(),
            MofN::new(recovery.set.threshold, bare_hashes).inner_puzzle_hash(),
            false,
        )
    };
    Ok((recovery_hash, restrictions))
}

fn member_hashes(set: &SignerSet, fast_forward: bool) -> Result<Vec<TreeHash>> {
    let mut out = Vec::new();
    for key in &set.keys {
        out.push(mips_puzzle_hash(
            0,
            Vec::new(),
            bare_inner_hash(key, fast_forward),
            false,
        ));
    }
    for launcher_id in &set.vault_launcher_ids {
        out.push(mips_puzzle_hash(
            0,
            Vec::new(),
            SingletonMember::new(*launcher_id).curry_tree_hash(),
            false,
        ));
    }
    if out.is_empty() {
        return Err(Error::msg("signer set has no members"));
    }
    Ok(out)
}

fn bare_inner_hash(key: &VaultMemberKey, fast_forward: bool) -> TreeHash {
    match key {
        VaultMemberKey::Bls(pk) => BlsMember::new(*pk).curry_tree_hash(),
        VaultMemberKey::K1(pk) => {
            if fast_forward {
                K1MemberPuzzleAssert::new(*pk).curry_tree_hash()
            } else {
                K1Member::new(*pk).curry_tree_hash()
            }
        }
        VaultMemberKey::R1(pk) => {
            if fast_forward {
                R1MemberPuzzleAssert::new(*pk).curry_tree_hash()
            } else {
                R1Member::new(*pk).curry_tree_hash()
            }
        }
        VaultMemberKey::Passkey(pk) => {
            if fast_forward {
                PasskeyMemberPuzzleAssert::new(*pk).curry_tree_hash()
            } else {
                PasskeyMember::new(*pk).curry_tree_hash()
            }
        }
    }
}

fn top_level_hash(custody_hash: TreeHash, recovery_hash: TreeHash) -> TreeHash {
    mips_puzzle_hash(
        0,
        Vec::new(),
        MofN::new(1, vec![custody_hash, recovery_hash]).inner_puzzle_hash(),
        true,
    )
}

fn sort_hashes(hashes: &mut [TreeHash]) {
    hashes.sort_by(|a, b| {
        let a: [u8; 32] = (*a).into();
        let b: [u8; 32] = (*b).into();
        a.cmp(&b)
    });
}

#[cfg(test)]
mod wrapper_tests {
    use chia_protocol::{Bytes, Bytes32, CoinSpend};
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::SpendContext;
    use chia_sdk_test::Simulator;
    use chia_sdk_types::conditions::{
        Condition, Conditions, CreateCoinAnnouncement, CreatePuzzleAnnouncement, ReceiveMessage,
        SendMessage,
    };
    use clvmr::NodePtr;

    use super::*;

    fn spend_wrapped(conditions: Conditions) -> anyhow::Result<()> {
        let mut ctx = SpendContext::new();
        let inner = ctx.delegated_spend(conditions)?;
        let wrapped = wrap_finish_delegated(&mut ctx, inner)?;
        let puzzle_hash = ctx.tree_hash(wrapped.spend.puzzle);
        let mut sim = Simulator::new();
        let coin = sim.new_coin(puzzle_hash.into(), 1);
        let puzzle = ctx.serialize(&wrapped.spend.puzzle)?;
        let solution = ctx.serialize(&wrapped.spend.solution)?;
        sim.spend_coins(vec![CoinSpend::new(coin, puzzle, solution)], &[])?;
        Ok(())
    }

    fn recreation() -> Conditions {
        Conditions::new().create_coin(Bytes32::from([1; 32]), 1, Memos::None)
    }

    fn banned(opcode: u16) -> Condition {
        let message = Bytes::new(vec![1]);
        match opcode {
            60 => CreateCoinAnnouncement::new(message).into(),
            62 => CreatePuzzleAnnouncement::new(message).into(),
            66 => SendMessage::new(0, message, Vec::<NodePtr>::new()).into(),
            67 => ReceiveMessage::new(0, message, Vec::<NodePtr>::new()).into(),
            _ => panic!("unexpected opcode {opcode}"),
        }
    }

    #[test]
    fn opcode_wrappers_reject_each_banned_opcode() {
        spend_wrapped(recreation()).expect("recreation coin");
        for opcode in prevent_vault_side_effect_opcodes() {
            let conditions = recreation().with(banned(opcode));
            assert!(
                spend_wrapped(conditions).is_err(),
                "opcode {opcode} was spent"
            );
        }
    }
}
