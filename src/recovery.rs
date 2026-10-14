//! Delayed vault recovery spend construction.

use chia_bls::{PublicKey as BlsPublicKey, SecretKey, sign};
use chia_protocol::{Bytes32, Coin, SpendBundle};
use chia_puzzle_types::{Memos, Proof};
use chia_sdk_driver::{
    InnerPuzzleSpend, MipsSpend, Spend, SpendContext, Vault, VaultInfo,
    calculate_vault_start_recovery_message,
};
use chia_sdk_types::{Conditions, Mod, puzzles::BlsMember, puzzles::Timelock};
use clvm_utils::TreeHash;
use clvmr::NodePtr;

use crate::config::VaultConfig;
use crate::error::{Error, Result};
use crate::keys::{MnemonicWordCount, generate_mnemonic, key_from_mnemonic};
use crate::network::Network;
use crate::vault::{
    PreparedFinish, RecoveryLayout, VaultKeys, VaultMemberKey, get_vault_internals,
    insert_recovery_restriction_spends, prepare_finish, recovery_state_for, recovery_state_hashes,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultPhase {
    Ready,
    InRecovery,
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

pub fn inspect_vault(
    config: &VaultConfig,
    on_chain_coin: Option<Coin>,
    post_recovery_inner: Option<TreeHash>,
) -> Result<InspectReport> {
    let launcher_id = config.launcher_id_bytes()?;
    let keys = config.to_vault_keys()?;
    let ready = get_vault_internals(launcher_id, &keys)?;

    let (pinned_hash, quoted_hash) = if let Some(post_inner) = post_recovery_inner {
        let amount = on_chain_coin.map(|c| c.amount).unwrap_or(1);
        let pinned = recovery_state_hashes(launcher_id, &keys, post_inner, amount)?
            .internals
            .full_puzzle_hash;
        let quoted = recovery_state_for(
            launcher_id,
            &keys,
            post_inner,
            amount,
            RecoveryLayout::Quoted,
        )?
        .internals
        .full_puzzle_hash;
        (Some(pinned), Some(quoted))
    } else {
        (None, None)
    };
    let on_chain_hash = on_chain_coin.map(|c| c.puzzle_hash);
    let expected_recovery_puzzle_hash = if on_chain_hash == quoted_hash {
        quoted_hash
    } else {
        pinned_hash
    };

    let (phase, guidance) = match &on_chain_coin {
        None => (
            VaultPhase::Unknown,
            "No unspent vault singleton found for this config.".to_string(),
        ),
        Some(coin) if coin.puzzle_hash == ready.full_puzzle_hash => (
            VaultPhase::Ready,
            "Vault is READY. Use `start` to begin delayed recovery.".to_string(),
        ),
        Some(coin)
            if Some(coin.puzzle_hash) == pinned_hash || Some(coin.puzzle_hash) == quoted_hash =>
        {
            (
                VaultPhase::InRecovery,
                "Vault is already in RECOVERY. Wait for the clawback timelock, then use `finish`."
                    .to_string(),
            )
        }
        Some(_) => (
            VaultPhase::Unknown,
            "On-chain puzzle hash does not match READY (or expected RECOVERY if a post-recovery config was provided)."
                .to_string(),
        ),
    };

    Ok(InspectReport {
        launcher_id,
        expected_ready_puzzle_hash: ready.full_puzzle_hash,
        expected_recovery_puzzle_hash,
        on_chain_puzzle_hash: on_chain_coin.map(|c| c.puzzle_hash),
        on_chain_coin,
        phase,
        clawback_timelock: ready.clawback_timelock,
        guidance,
    })
}

pub fn start_recovery(params: StartRecoveryParams<'_>) -> Result<StartRecoveryResult> {
    start_with_layout(params, RecoveryLayout::Pinned)
}

fn start_with_layout(
    params: StartRecoveryParams<'_>,
    layout: RecoveryLayout,
) -> Result<StartRecoveryResult> {
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
        layout,
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
    let prepared = select_finish(
        &mut ctx,
        launcher_id,
        &current_keys,
        post_ready.inner_puzzle_hash,
        params.vault_coin,
    )?;

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
        current_keys.recovery.clawback_timelock,
    )
}

fn select_finish(
    ctx: &mut SpendContext,
    launcher_id: Bytes32,
    keys: &VaultKeys,
    post_recovery_inner: TreeHash,
    vault_coin: Coin,
) -> Result<PreparedFinish> {
    let pinned = prepare_finish(
        ctx,
        launcher_id,
        keys,
        post_recovery_inner,
        vault_coin.amount,
        RecoveryLayout::Pinned,
    )?;
    if vault_coin.puzzle_hash == pinned.state.internals.full_puzzle_hash {
        return Ok(pinned);
    }
    let quoted = prepare_finish(
        ctx,
        launcher_id,
        keys,
        post_recovery_inner,
        vault_coin.amount,
        RecoveryLayout::Quoted,
    )?;
    if vault_coin.puzzle_hash == quoted.state.internals.full_puzzle_hash {
        return Ok(quoted);
    }
    Err(Error::msg(format!(
        "vault coin puzzle hash {} does not match expected RECOVERY hash {} or {}",
        hex::encode(vault_coin.puzzle_hash),
        hex::encode(pinned.state.internals.full_puzzle_hash),
        hex::encode(quoted.state.internals.full_puzzle_hash)
    )))
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
    clawback_timelock: u64,
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

    let timelock = Timelock::new(clawback_timelock);
    let timelock_restriction = chia_sdk_driver::Restriction {
        kind: chia_sdk_driver::RestrictionKind::MemberCondition,
        puzzle_hash: timelock.curry_tree_hash(),
    };

    mips.members.insert(
        recovery_state.recovery_hash,
        InnerPuzzleSpend::new(0, vec![timelock_restriction], member),
    );

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
mod layout_tests {
    use super::*;
    use chia_sdk_driver::{Launcher, StandardLayer};
    use chia_sdk_test::{K1Pair, Simulator};
    use clvmr::NodePtr;

    use crate::config::{Curve, KeyType, VaultConfigMember, VaultConfigRecovery, VaultConfigSide};
    use crate::keys::{MnemonicWordCount, generate_mnemonic, public_key_to_hex};
    use crate::vault::{
        CustodyPath, RecoverySignerSet, SignerSet, get_vault_internals, recovery_state_for,
    };

    fn mint_vault(
        sim: &mut Simulator,
        ctx: &mut SpendContext,
        custody_hash: TreeHash,
    ) -> anyhow::Result<Vault> {
        let alice = sim.bls(1);
        let alice_p2 = StandardLayer::new(alice.pk);
        let (mint_vault, vault) =
            Launcher::new(alice.coin.coin_id(), 1).mint_vault(ctx, custody_hash, ())?;
        alice_p2.spend(ctx, alice.coin, mint_vault)?;
        sim.spend_coins(ctx.take(), &[alice.sk])?;
        Ok(vault)
    }

    struct Started {
        sim: Simulator,
        config: VaultConfig,
        post: VaultConfig,
        child: Vault,
        keys: crate::vault::VaultKeys,
        post_inner: TreeHash,
    }

    fn start_layout(layout: RecoveryLayout) -> anyhow::Result<Started> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let custody = K1Pair::default();
        let recovery = generate_mnemonic(MnemonicWordCount::Words24)?;
        let words = recovery.words.clone();
        let keys = crate::vault::VaultKeys {
            custody: CustodyPath::Signers(SignerSet {
                keys: vec![VaultMemberKey::K1(custody.pk)],
                vault_launcher_ids: vec![],
                threshold: 1,
            }),
            recovery: RecoverySignerSet {
                set: SignerSet {
                    keys: vec![VaultMemberKey::Bls(recovery.key_pair.public_key)],
                    vault_launcher_ids: vec![],
                    threshold: 1,
                },
                clawback_timelock: 10,
            },
        };
        let prelim = get_vault_internals(Bytes32::default(), &keys)?;
        let vault = mint_vault(&mut sim, ctx, prelim.inner_puzzle_hash)?;
        let launcher_id = vault.info.launcher_id;
        let config = VaultConfig {
            launcher_id: format!("0x{}", hex::encode(launcher_id)),
            custody: VaultConfigSide {
                threshold: 1,
                members: vec![VaultConfigMember::PublicKey {
                    public_key: format!("0x{}", hex::encode(custody.pk.to_bytes())),
                    curve: Curve::Secp256k1,
                    key_type: None,
                }],
                hash: None,
            },
            recovery: VaultConfigRecovery {
                threshold: 1,
                clawback_timelock: 10,
                members: vec![VaultConfigMember::PublicKey {
                    public_key: public_key_to_hex(&recovery.key_pair.public_key),
                    curve: Curve::Bls12_381,
                    key_type: Some(KeyType::RecoveryPhrase),
                }],
            },
            receive_address: None,
        };
        let new_custody = generate_mnemonic(MnemonicWordCount::Words24)?;
        let start = start_with_layout(
            StartRecoveryParams {
                config: &config,
                vault_coin: vault.coin,
                lineage_proof: vault.proof,
                recovery_mnemonic: &words,
                new_custody_mnemonic: &new_custody.words,
                new_recovery_mnemonic: None,
                new_clawback_timelock: Some(10),
                new_word_count: MnemonicWordCount::Words24,
                network: Network::Testnet11,
            },
            layout,
        )?;
        sim.spend_coins(
            start.spend_bundle.coin_spends,
            std::slice::from_ref(&recovery.key_pair.secret_key),
        )?;
        let post_keys = start.post_recovery_config.to_vault_keys()?;
        let post_inner = get_vault_internals(launcher_id, &post_keys)?.inner_puzzle_hash;
        let state = recovery_state_for(launcher_id, &keys, post_inner, 1, layout)?;
        assert_eq!(
            state.internals.full_puzzle_hash,
            start.recovery_state_puzzle_hash
        );
        let child = vault.child(state.internals.inner_puzzle_hash, 1);
        Ok(Started {
            sim,
            config,
            post: start.post_recovery_config,
            child,
            keys,
            post_inner,
        })
    }

    fn nil_program(ctx: &mut SpendContext) -> anyhow::Result<Spend> {
        // `(i 1 () ())` returns nil and is not the empty quoted puzzle.
        let nil = NodePtr::NIL;
        let one = ctx.new_atom(&[1])?;
        let op_if = ctx.new_atom(&[3])?;
        let tails = ctx.new_pair(nil, nil)?;
        let tails = ctx.new_pair(nil, tails)?;
        let args = ctx.new_pair(one, tails)?;
        let puzzle = ctx.new_pair(op_if, args)?;
        Ok(Spend::new(puzzle, nil))
    }

    #[test]
    fn quoted_layout_still_finishes() -> anyhow::Result<()> {
        let mut started = start_layout(RecoveryLayout::Quoted)?;
        let pinned = recovery_state_for(
            started.config.launcher_id_bytes()?,
            &started.keys,
            started.post_inner,
            1,
            RecoveryLayout::Pinned,
        )?;
        assert_ne!(
            pinned.internals.full_puzzle_hash,
            started.child.coin.puzzle_hash
        );
        started.sim.pass_time(10);
        let bundle = finish_recovery(FinishRecoveryParams {
            config: &started.config,
            post_recovery_config: &started.post,
            vault_coin: started.child.coin,
            lineage_proof: started.child.proof,
            network: Network::Testnet11,
        })?;
        started.sim.spend_coins(bundle.coin_spends, &[])?;
        Ok(())
    }

    #[test]
    fn pinned_finish_runs_only_the_committed_delegated_puzzle() -> anyhow::Result<()> {
        let mut started = start_layout(RecoveryLayout::Pinned)?;
        let mut ctx = SpendContext::new();
        let prepared = prepare_finish(
            &mut ctx,
            started.config.launcher_id_bytes()?,
            &started.keys,
            started.post_inner,
            1,
            RecoveryLayout::Pinned,
        )?;
        let alt = nil_program(&mut ctx)?;
        let honest = ctx.run(prepared.delegated.puzzle, prepared.delegated.solution)?;
        let alt_out = ctx.run(alt.puzzle, alt.solution)?;
        assert_eq!(ctx.tree_hash(honest), ctx.tree_hash(alt_out));
        assert_ne!(
            ctx.tree_hash(prepared.delegated.puzzle),
            ctx.tree_hash(alt.puzzle)
        );
        let rejected = build_finish_spend_bundle(
            &mut ctx,
            &started.child,
            &prepared.state.internals,
            prepared.member,
            alt,
            started.keys.recovery.clawback_timelock,
        )?;
        started.sim.pass_time(10);
        assert!(started.sim.spend_coins(rejected.coin_spends, &[]).is_err());

        let bundle = finish_recovery(FinishRecoveryParams {
            config: &started.config,
            post_recovery_config: &started.post,
            vault_coin: started.child.coin,
            lineage_proof: started.child.proof,
            network: Network::Testnet11,
        })?;
        started.sim.spend_coins(bundle.coin_spends, &[])?;
        Ok(())
    }
}
