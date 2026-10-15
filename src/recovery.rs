//! Delayed vault recovery spend construction.

use chia_bls::{PublicKey as BlsPublicKey, SecretKey, sign};
use chia_protocol::{Bytes32, Coin, SpendBundle};
use chia_puzzle_types::{Memos, Proof};
use chia_sdk_coinset::CoinRecord;
use chia_sdk_driver::{
    InnerPuzzleSpend, MipsSpend, Spend, SpendContext, Vault, VaultInfo,
    calculate_vault_start_recovery_message,
};
use chia_sdk_types::{Conditions, Mod, puzzles::BlsMember, puzzles::Timelock};
use clvm_utils::TreeHash;
use clvmr::NodePtr;

use crate::chain::{SingletonIndex, walk_singleton};
use crate::config::VaultConfig;
use crate::error::{Error, Result};
use crate::keys::{MnemonicWordCount, generate_mnemonic, key_from_mnemonic};
use crate::network::Network;
use crate::vault::{
    VaultKeys, VaultMemberKey, get_vault_internals, insert_recovery_restriction_spends,
    prepare_finish, recovery_state_hashes,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPhase {
    Ready,
    InRecovery,
    /// Unspent singleton is the post-recovery custody puzzle.
    Finished,
    /// Unspent singleton is the original custody puzzle, created by the recovery coin.
    ClawedBack,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct InspectReport {
    pub launcher_id: Bytes32,
    pub expected_ready_puzzle_hash: Bytes32,
    pub expected_recovery_puzzle_hash: Option<Bytes32>,
    pub on_chain_puzzle_hash: Option<Bytes32>,
    pub on_chain_coin: Option<Coin>,
    pub phase: VaultPhase,
    pub clawback_timelock: u64,
    pub guidance: String,
    /// Set when the confirmed coin has a mempool spend. Does not change `phase`.
    pub pending_note: Option<String>,
}

pub(crate) const PENDING_FINISH_OR_CLAWBACK: &str =
    "A pending spend of this vault is in the mempool and may finish recovery or claw it back.";

/// Confirmed singleton tip and the parent record the walk just read.
pub(crate) struct ObservedSingleton {
    pub tip: CoinRecord,
    pub parent: CoinRecord,
}

pub(crate) async fn load_singleton(
    index: &impl SingletonIndex,
    launcher_id: Bytes32,
) -> Result<ObservedSingleton> {
    let (_spent, walked) = walk_singleton(index, launcher_id).await?;
    let parent = index
        .coin_record(walked.coin.parent_coin_info)
        .await?
        .ok_or_else(|| Error::msg("parent coin record not found for the vault singleton"))?;
    let again = index
        .coin_record(walked.coin.coin_id())
        .await?
        .ok_or_else(|| Error::msg("vault singleton changed while reading; try again"))?;
    if again.spent || again.coin != walked.coin {
        return Err(Error::msg(
            "vault singleton changed while reading; try again",
        ));
    }
    Ok(ObservedSingleton { tip: again, parent })
}

#[derive(Debug, Clone)]
pub struct StartRecoveryParams<'a> {
    pub config: &'a VaultConfig,
    pub vault_coin: Coin,
    pub lineage_proof: Proof,
    pub recovery_mnemonic: &'a str,
    pub new_custody_mnemonic: &'a str,
    pub new_recovery_mnemonic: Option<&'a str>,
    pub new_clawback_timelock: Option<u64>,
    pub new_word_count: MnemonicWordCount,
    pub network: Network,
}

#[derive(Debug, Clone)]
pub struct StartRecoveryResult {
    pub spend_bundle: SpendBundle,
    pub post_recovery_config: VaultConfig,
    /// Generated recovery phrase when the caller did not supply one. Show once; do not write to config.
    pub generated_recovery_mnemonic: Option<String>,
    pub recovery_state_puzzle_hash: Bytes32,
    pub clawback_timelock: u64,
}

#[derive(Debug, Clone)]
pub struct FinishRecoveryParams<'a> {
    pub config: &'a VaultConfig,
    pub post_recovery_config: &'a VaultConfig,
    pub vault_coin: Coin,
    pub lineage_proof: Proof,
    pub network: Network,
}

pub(crate) fn classify_singleton(
    config: &VaultConfig,
    post_recovery: Option<&VaultConfig>,
    observed: &ObservedSingleton,
    pending: bool,
) -> Result<InspectReport> {
    let launcher_id = config.launcher_id_bytes()?;
    let keys = config.to_vault_keys()?;
    let ready = get_vault_internals(launcher_id, &keys)?;
    let tip = &observed.tip;
    let parent = &observed.parent;

    let (tip_recovery, parent_recovery, finished_hash) = match post_recovery {
        Some(post) => {
            let post_ready = get_vault_internals(launcher_id, &post.to_vault_keys()?)?;
            let tip_recovery = recovery_state_hashes(
                launcher_id,
                &keys,
                post_ready.inner_puzzle_hash,
                tip.coin.amount,
            )?
            .internals
            .full_puzzle_hash;
            let parent_recovery = recovery_state_hashes(
                launcher_id,
                &keys,
                post_ready.inner_puzzle_hash,
                parent.coin.amount,
            )?
            .internals
            .full_puzzle_hash;
            (
                Some(tip_recovery),
                Some(parent_recovery),
                Some(post_ready.full_puzzle_hash),
            )
        }
        None => (None, None, None),
    };

    let (phase, guidance) = phase_of(
        tip.coin.puzzle_hash,
        ready.full_puzzle_hash,
        tip_recovery,
        parent.coin.puzzle_hash,
        parent_recovery,
        finished_hash,
    );
    let settled = matches!(phase, VaultPhase::Finished | VaultPhase::ClawedBack);
    if settled && !parent.spent {
        return Err(Error::msg("parent of the vault singleton is not spent"));
    }

    let pending_note = (pending && phase == VaultPhase::InRecovery)
        .then(|| PENDING_FINISH_OR_CLAWBACK.to_string());

    Ok(InspectReport {
        launcher_id,
        expected_ready_puzzle_hash: ready.full_puzzle_hash,
        expected_recovery_puzzle_hash: if settled {
            parent_recovery
        } else {
            tip_recovery
        },
        on_chain_puzzle_hash: Some(tip.coin.puzzle_hash),
        on_chain_coin: Some(tip.coin),
        phase,
        clawback_timelock: ready.clawback_timelock,
        guidance: guidance.to_string(),
        pending_note,
    })
}

fn phase_of(
    tip_puzzle: Bytes32,
    ready_hash: Bytes32,
    tip_recovery: Option<Bytes32>,
    parent_puzzle: Bytes32,
    parent_recovery: Option<Bytes32>,
    finished_hash: Option<Bytes32>,
) -> (VaultPhase, &'static str) {
    if Some(tip_puzzle) == tip_recovery {
        return (
            VaultPhase::InRecovery,
            "Vault is already in RECOVERY. Wait for the clawback timelock, then use `finish`.",
        );
    }

    let parent_is_recovery = parent_recovery.is_some() && Some(parent_puzzle) == parent_recovery;
    let finished_is_distinct = finished_hash.is_some() && finished_hash != Some(ready_hash);
    if finished_is_distinct && Some(tip_puzzle) == finished_hash && parent_is_recovery {
        return (
            VaultPhase::Finished,
            "Vault is under the recovered custody configuration.",
        );
    }
    if tip_puzzle == ready_hash && parent_is_recovery {
        return (
            VaultPhase::ClawedBack,
            "Vault is under the original custody configuration.",
        );
    }
    if tip_puzzle == ready_hash {
        return (
            VaultPhase::Ready,
            "Vault is READY. Use `start` to begin delayed recovery.",
        );
    }
    (
        VaultPhase::Unknown,
        "On-chain puzzle hash does not match this config.",
    )
}

pub fn start_recovery(params: StartRecoveryParams<'_>) -> Result<StartRecoveryResult> {
    let launcher_id = params.config.launcher_id_bytes()?;
    let current_keys = params.config.to_vault_keys()?;
    let current = get_vault_internals(launcher_id, &current_keys)?;
    if params.vault_coin.puzzle_hash != current.full_puzzle_hash {
        return Err(Error::msg(format!(
            "vault coin puzzle hash {} does not match READY config hash {}",
            hex::encode(params.vault_coin.puzzle_hash),
            hex::encode(current.full_puzzle_hash)
        )));
    }

    let recovery_key = key_from_mnemonic(params.recovery_mnemonic)?;
    ensure_recovery_key_matches(&current_keys, &recovery_key.public_key)?;

    let custody_key = key_from_mnemonic(params.new_custody_mnemonic)?;
    let (recovery_pair, generated_recovery_mnemonic) =
        if let Some(words) = params.new_recovery_mnemonic {
            (key_from_mnemonic(words)?, None)
        } else {
            let generated = generate_mnemonic(params.new_word_count)?;
            (generated.key_pair, Some(generated.words))
        };

    let clawback = params
        .new_clawback_timelock
        .unwrap_or(current_keys.recovery.clawback_timelock);
    let post_recovery_config =
        VaultConfig::from_bls_pair(launcher_id, &custody_key, &recovery_pair, clawback);
    let post_ready = get_vault_internals(launcher_id, &post_recovery_config.to_vault_keys()?)?;

    let mut ctx = SpendContext::new();
    let prepared = prepare_finish(
        &mut ctx,
        launcher_id,
        &current_keys,
        post_ready.inner_puzzle_hash,
        params.vault_coin.amount,
    )?;

    let vault = Vault {
        coin: params.vault_coin,
        proof: params.lineage_proof,
        info: VaultInfo::new(launcher_id, current.inner_puzzle_hash),
    };

    let spend_bundle = build_start_spend_bundle(
        &mut ctx,
        &vault,
        &current,
        &prepared.state.internals,
        prepared.state.finish_member_hash,
        &recovery_key.secret_key,
        params.network,
    )?;

    Ok(StartRecoveryResult {
        spend_bundle,
        post_recovery_config,
        generated_recovery_mnemonic,
        recovery_state_puzzle_hash: prepared.state.internals.full_puzzle_hash,
        clawback_timelock: current.clawback_timelock,
    })
}

pub fn finish_recovery(params: FinishRecoveryParams<'_>) -> Result<SpendBundle> {
    let launcher_id = params.config.launcher_id_bytes()?;
    let current_keys = params.config.to_vault_keys()?;
    let post_ready =
        get_vault_internals(launcher_id, &params.post_recovery_config.to_vault_keys()?)?;

    let mut ctx = SpendContext::new();
    let prepared = prepare_finish(
        &mut ctx,
        launcher_id,
        &current_keys,
        post_ready.inner_puzzle_hash,
        params.vault_coin.amount,
    )?;
    if params.vault_coin.puzzle_hash != prepared.state.internals.full_puzzle_hash {
        return Err(Error::msg(format!(
            "vault coin puzzle hash {} does not match expected RECOVERY hash {}",
            hex::encode(params.vault_coin.puzzle_hash),
            hex::encode(prepared.state.internals.full_puzzle_hash)
        )));
    }

    let vault = Vault {
        coin: params.vault_coin,
        proof: params.lineage_proof,
        info: VaultInfo::new(launcher_id, prepared.state.internals.inner_puzzle_hash),
    };

    build_finish_spend_bundle(
        &mut ctx,
        &vault,
        &prepared.state.internals,
        prepared.member,
        prepared.delegated,
    )
}

fn ensure_recovery_key_matches(keys: &VaultKeys, pk: &BlsPublicKey) -> Result<()> {
    for key in &keys.recovery.set.keys {
        if let VaultMemberKey::Bls(existing) = key
            && existing == pk
        {
            return Ok(());
        }
    }
    Err(Error::msg(
        "recovery phrase public key does not match any BLS recovery member in the vault config",
    ))
}

fn build_start_spend_bundle(
    ctx: &mut SpendContext,
    vault: &Vault,
    ready: &crate::vault::VaultInternals,
    recovery_state: &crate::vault::VaultInternals,
    finish_member_hash: TreeHash,
    recovery_sk: &SecretKey,
    network: Network,
) -> Result<SpendBundle> {
    let conditions = Conditions::new().create_coin(
        recovery_state.inner_puzzle_hash.into(),
        vault.coin.amount,
        Memos::None,
    );
    let delegated = ctx.delegated_spend(conditions)?;
    let delegated_ph = ctx.tree_hash(delegated.puzzle);

    let mut mips = MipsSpend::new(delegated);

    mips.members.insert(
        ready.inner_puzzle_hash,
        InnerPuzzleSpend::m_of_n(
            0,
            Vec::new(),
            1,
            vec![ready.custody_hash, ready.recovery_hash],
        ),
    );

    let restrictions = ready.recovery_restrictions.clone();
    let bls_member = BlsMember::new(recovery_sk.public_key());
    let bls_puzzle = ctx.curry(bls_member)?;
    let bls_solution = ctx.alloc(&NodePtr::NIL)?;
    mips.members.insert(
        ready.recovery_hash,
        InnerPuzzleSpend::new(0, restrictions, Spend::new(bls_puzzle, bls_solution)),
    );

    insert_recovery_restriction_spends(
        ctx,
        &mut mips,
        ready.custody_hash,
        ready.clawback_timelock,
        finish_member_hash,
    )?;

    let message = calculate_vault_start_recovery_message(
        delegated_ph.into(),
        ready.custody_hash.into(),
        ready.clawback_timelock,
        vault.coin.coin_id(),
        Bytes32::new(network.genesis_challenge()),
    );
    let signature = sign(recovery_sk, message);

    vault.spend(ctx, &mips)?;
    Ok(SpendBundle::new(ctx.take(), signature))
}

fn build_finish_spend_bundle(
    ctx: &mut SpendContext,
    vault: &Vault,
    recovery_state: &crate::vault::VaultInternals,
    member: Spend,
    delegated: Spend,
) -> Result<SpendBundle> {
    let mut mips = MipsSpend::new(delegated);

    mips.members.insert(
        recovery_state.inner_puzzle_hash,
        InnerPuzzleSpend::m_of_n(
            0,
            Vec::new(),
            1,
            vec![recovery_state.custody_hash, recovery_state.recovery_hash],
        ),
    );

    mips.members.insert(
        recovery_state.recovery_hash,
        InnerPuzzleSpend::new(0, recovery_state.recovery_restrictions.clone(), member),
    );

    let timelock = Timelock::new(recovery_state.clawback_timelock);
    let timelock_puzzle = ctx.curry(timelock)?;
    mips.restrictions.insert(
        timelock.curry_tree_hash(),
        Spend::new(timelock_puzzle, NodePtr::NIL),
    );

    vault.spend(ctx, &mips)?;
    Ok(SpendBundle::new(ctx.take(), chia_bls::Signature::default()))
}

#[cfg(test)]
mod key_match_tests {
    use super::*;
    use crate::vault::{RecoverySignerSet, SignerSet};

    #[test]
    fn rejects_wrong_recovery_mnemonic() {
        let right = key_from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let keys = VaultKeys {
            custody: crate::vault::CustodyPath::Signers(SignerSet {
                keys: vec![VaultMemberKey::Bls(right.public_key)],
                vault_launcher_ids: vec![],
                threshold: 1,
            }),
            recovery: RecoverySignerSet {
                set: SignerSet {
                    keys: vec![VaultMemberKey::Bls(right.public_key)],
                    vault_launcher_ids: vec![],
                    threshold: 1,
                },
                clawback_timelock: 1,
            },
        };
        let wrong = key_from_mnemonic(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        assert!(ensure_recovery_key_matches(&keys, &wrong.public_key).is_err());
        assert!(ensure_recovery_key_matches(&keys, &right.public_key).is_ok());
    }
}

#[cfg(test)]
#[path = "recovery_finish_tests.rs"]
mod finish_tests;
