//! Vault topology hashes matching Cloud Wallet / ent-wallet `getVaultInternals`.

use chia_bls::PublicKey as BlsPublicKey;
use chia_protocol::Bytes32;
use chia_puzzle_types::{Memos, singleton::SingletonArgs};
use chia_puzzles::PREVENT_MULTIPLE_CREATE_COINS_HASH;
use chia_sdk_driver::{MofN, Restriction, RestrictionKind, Spend, SpendContext, mips_puzzle_hash};
use chia_sdk_types::{
    Conditions, Mod,
    puzzles::{
        BlsMember, Force1of2RestrictedVariable, Force1of2RestrictedVariableSolution, K1Member,
        K1MemberPuzzleAssert, PasskeyMember, PasskeyMemberPuzzleAssert, PreventConditionOpcode,
        PreventMultipleCreateCoinsMod, R1Member, R1MemberPuzzleAssert, SingletonMember, Timelock,
    },
};
use chia_secp::{K1PublicKey, R1PublicKey};
use clvm_utils::{ToTreeHash, TreeHash};
use clvmr::NodePtr;

use crate::error::{Error, Result};
use crate::finish_member::{empty_delegated_spend, pinned_member};

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

/// How the finish member is bound to the delegated puzzle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryLayout {
    /// Returns the recreation conditions when the delegated puzzle hash matches.
    Pinned,
    /// The member is the quoted recreation conditions.
    Quoted,
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

/// Compute pinned RECOVERY-state puzzle hashes committed to `post_recovery_inner`.
pub fn recovery_state_hashes(
    launcher_id: Bytes32,
    keys: &VaultKeys,
    post_recovery_inner: TreeHash,
    amount: u64,
) -> Result<RecoveryStateHashes> {
    recovery_state_for(
        launcher_id,
        keys,
        post_recovery_inner,
        amount,
        RecoveryLayout::Pinned,
    )
}

pub(crate) fn recovery_state_for(
    launcher_id: Bytes32,
    keys: &VaultKeys,
    post_recovery_inner: TreeHash,
    amount: u64,
    layout: RecoveryLayout,
) -> Result<RecoveryStateHashes> {
    let mut ctx = SpendContext::new();
    Ok(prepare_finish(
        &mut ctx,
        launcher_id,
        keys,
        post_recovery_inner,
        amount,
        layout,
    )?
    .state)
}

/// Allocates the finish member and delegated puzzle for `layout`.
pub(crate) fn prepare_finish(
    ctx: &mut SpendContext,
    launcher_id: Bytes32,
    keys: &VaultKeys,
    post_recovery_inner: TreeHash,
    amount: u64,
    layout: RecoveryLayout,
) -> Result<PreparedFinish> {
    let conditions =
        recreation_conditions(post_recovery_inner, keys.recovery.clawback_timelock, amount);
    let (member, delegated) = match layout {
        RecoveryLayout::Pinned => {
            let delegated = empty_delegated_spend(ctx)?;
            let member = pinned_member(ctx, ctx.tree_hash(delegated.puzzle), &conditions)?;
            (member, delegated)
        }
        RecoveryLayout::Quoted => {
            let member = ctx.delegated_spend(conditions)?;
            (member, Spend::new(NodePtr::NIL, NodePtr::NIL))
        }
    };
    let state = recovery_state_from_member_hash(launcher_id, keys, ctx.tree_hash(member.puzzle))?;
    Ok(PreparedFinish {
        state,
        member,
        delegated,
    })
}

fn recreation_conditions(post_recovery_inner: TreeHash, timelock: u64, amount: u64) -> Conditions {
    Conditions::new()
        .create_coin(post_recovery_inner.into(), amount, Memos::None)
        .assert_seconds_relative(timelock)
}

fn recovery_state_from_member_hash(
    launcher_id: Bytes32,
    keys: &VaultKeys,
    finish_member_hash: TreeHash,
) -> Result<RecoveryStateHashes> {
    let custody_hash = keys.custody.hash()?;
    let timelock = keys.recovery.clawback_timelock;
    let timelock_restriction = Restriction {
        kind: RestrictionKind::MemberCondition,
        puzzle_hash: Timelock::new(timelock).curry_tree_hash(),
    };
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
            recovery_restrictions: Vec::new(),
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
