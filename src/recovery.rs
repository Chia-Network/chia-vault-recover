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
    post_recovery: Option<&VaultConfig>,
    parent_puzzle_hash: Option<Bytes32>,
) -> Result<InspectReport> {
    let launcher_id = config.launcher_id_bytes()?;
    let keys = config.to_vault_keys()?;
    let ready = get_vault_internals(launcher_id, &keys)?;

    let (recovery_hash, finished_hash) = match post_recovery {
        Some(post) => {
            let post_ready = get_vault_internals(launcher_id, &post.to_vault_keys()?)?;
            let amount = on_chain_coin.map(|c| c.amount).unwrap_or(1);
            let recovery =
                recovery_state_hashes(launcher_id, &keys, post_ready.inner_puzzle_hash, amount)?
                    .internals
                    .full_puzzle_hash;
            (Some(recovery), Some(post_ready.full_puzzle_hash))
        }
        None => (None, None),
    };

    let (phase, guidance) = phase_of(
        on_chain_coin.map(|c| c.puzzle_hash),
        ready.full_puzzle_hash,
        recovery_hash,
        finished_hash,
        parent_puzzle_hash,
    );

    Ok(InspectReport {
        launcher_id,
        expected_ready_puzzle_hash: ready.full_puzzle_hash,
        expected_recovery_puzzle_hash: recovery_hash,
        on_chain_puzzle_hash: on_chain_coin.map(|c| c.puzzle_hash),
        on_chain_coin,
        phase,
        clawback_timelock: ready.clawback_timelock,
        guidance: guidance.to_string(),
    })
}

fn phase_of(
    puzzle_hash: Option<Bytes32>,
    ready_hash: Bytes32,
    recovery_hash: Option<Bytes32>,
    finished_hash: Option<Bytes32>,
    parent_puzzle_hash: Option<Bytes32>,
) -> (VaultPhase, &'static str) {
    let Some(puzzle_hash) = puzzle_hash else {
        return (
            VaultPhase::Unknown,
            "No unspent vault singleton found for this config.",
        );
    };
    if Some(puzzle_hash) == recovery_hash {
        return (
            VaultPhase::InRecovery,
            "Vault is already in RECOVERY. Wait for the clawback timelock, then use `finish`.",
        );
    }

    let parent_is_recovery = recovery_hash.is_some() && parent_puzzle_hash == recovery_hash;
    let finished_is_distinct = finished_hash.is_some() && finished_hash != Some(ready_hash);
    if finished_is_distinct && Some(puzzle_hash) == finished_hash && parent_is_recovery {
        return (
            VaultPhase::Finished,
            "Vault is under the recovered custody configuration.",
        );
    }
    if puzzle_hash == ready_hash && parent_is_recovery {
        return (
            VaultPhase::ClawedBack,
            "Vault is under the original custody configuration.",
        );
    }
    if puzzle_hash == ready_hash {
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
mod finish_tests {
    use super::*;
    use chia_bls::SecretKey;
    use chia_protocol::{Coin, CoinSpend};
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{InnerPuzzleSpend, Launcher, MipsSpend, Spend, StandardLayer};
    use chia_sdk_test::Simulator;
    use chia_sdk_types::{Conditions, puzzles::BlsMember};
    use clvmr::NodePtr;

    use crate::config::{Curve, KeyType, VaultConfigMember, VaultConfigRecovery, VaultConfigSide};
    use crate::keys::{MnemonicWordCount, generate_mnemonic, public_key_to_hex};
    use crate::vault::{
        CustodyPath, RecoverySignerSet, SignerSet, VaultMemberKey, get_vault_internals,
        recovery_state_hashes,
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
        custody_sk: SecretKey,
        recovery_sk: SecretKey,
    }

    fn start_on_sim() -> anyhow::Result<Started> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();
        let custody = generate_mnemonic(MnemonicWordCount::Words24)?;
        let recovery = generate_mnemonic(MnemonicWordCount::Words24)?;
        let words = recovery.words.clone();
        let keys = crate::vault::VaultKeys {
            custody: CustodyPath::Signers(SignerSet {
                keys: vec![VaultMemberKey::Bls(custody.key_pair.public_key)],
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
                    public_key: public_key_to_hex(&custody.key_pair.public_key),
                    curve: Curve::Bls12_381,
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
        let start = start_recovery(StartRecoveryParams {
            config: &config,
            vault_coin: vault.coin,
            lineage_proof: vault.proof,
            recovery_mnemonic: &words,
            new_custody_mnemonic: &new_custody.words,
            new_recovery_mnemonic: None,
            new_clawback_timelock: Some(10),
            new_word_count: MnemonicWordCount::Words24,
            network: Network::Testnet11,
        })?;
        sim.spend_coins(
            start.spend_bundle.coin_spends,
            std::slice::from_ref(&recovery.key_pair.secret_key),
        )?;
        let post_keys = start.post_recovery_config.to_vault_keys()?;
        let post_inner = get_vault_internals(launcher_id, &post_keys)?.inner_puzzle_hash;
        let state = recovery_state_hashes(launcher_id, &keys, post_inner, 1)?;
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
            custody_sk: custody.key_pair.secret_key,
            recovery_sk: recovery.key_pair.secret_key,
        })
    }

    fn custody_clawback_spends(started: &Started) -> anyhow::Result<Vec<CoinSpend>> {
        let mut ctx = SpendContext::new();
        let launcher = started.config.launcher_id_bytes()?;
        let ready = get_vault_internals(launcher, &started.keys)?;
        let state = recovery_state_hashes(launcher, &started.keys, started.post_inner, 1)?;
        let conditions =
            Conditions::new().create_coin(ready.inner_puzzle_hash.into(), 1, Memos::None);
        let mut mips = MipsSpend::new(ctx.delegated_spend(conditions)?);
        mips.members.insert(
            state.internals.inner_puzzle_hash,
            InnerPuzzleSpend::m_of_n(
                0,
                Vec::new(),
                1,
                vec![state.internals.custody_hash, state.internals.recovery_hash],
            ),
        );
        let CustodyPath::Signers(set) = &started.keys.custody else {
            anyhow::bail!("custody member is not a BLS key");
        };
        let Some(VaultMemberKey::Bls(pk)) = set.keys.first() else {
            anyhow::bail!("custody member is not a BLS key");
        };
        let puzzle = ctx.curry(BlsMember::new(*pk))?;
        let solution = ctx.alloc(&NodePtr::NIL)?;
        mips.members.insert(
            state.internals.custody_hash,
            InnerPuzzleSpend::new(0, Vec::new(), Spend::new(puzzle, solution)),
        );
        started.child.spend(&mut ctx, &mips)?;
        Ok(ctx.take())
    }

    fn nil_program(ctx: &mut SpendContext) -> anyhow::Result<Spend> {
        // `(i 1 () ())` returns nil and is a different puzzle.
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
    fn finish_rejects_a_different_delegated_puzzle() -> anyhow::Result<()> {
        let mut started = start_on_sim()?;
        let mut ctx = SpendContext::new();
        let prepared = prepare_finish(
            &mut ctx,
            started.config.launcher_id_bytes()?,
            &started.keys,
            started.post_inner,
            1,
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
        let finished = started.child.child(started.post_inner, 1);
        let report = inspect_vault(
            &started.config,
            Some(finished.coin),
            Some(&started.post),
            Some(started.child.coin.puzzle_hash),
        )?;
        assert_eq!(report.phase, VaultPhase::Finished);
        Ok(())
    }

    #[test]
    fn clawback_during_timelock_requires_the_custody_key() -> anyhow::Result<()> {
        let mut started = start_on_sim()?;
        let launcher = started.config.launcher_id_bytes()?;
        let ready = get_vault_internals(launcher, &started.keys)?;

        let early = finish_recovery(FinishRecoveryParams {
            config: &started.config,
            post_recovery_config: &started.post,
            vault_coin: started.child.coin,
            lineage_proof: started.child.proof,
            network: Network::Testnet11,
        })?;
        assert!(started.sim.spend_coins(early.coin_spends, &[]).is_err());

        let mut ctx = SpendContext::new();
        let prepared = prepare_finish(&mut ctx, launcher, &started.keys, started.post_inner, 1)?;
        let clawback_delegated = ctx.delegated_spend(Conditions::new().create_coin(
            ready.inner_puzzle_hash.into(),
            1,
            Memos::None,
        ))?;
        let redirected = build_finish_spend_bundle(
            &mut ctx,
            &started.child,
            &prepared.state.internals,
            prepared.member,
            clawback_delegated,
        )?;
        assert!(
            started
                .sim
                .spend_coins(redirected.coin_spends, &[])
                .is_err()
        );

        let spends = custody_clawback_spends(&started)?;
        assert!(started.sim.spend_coins(spends.clone(), &[]).is_err());
        assert!(
            started
                .sim
                .spend_coins(spends.clone(), std::slice::from_ref(&started.recovery_sk))
                .is_err()
        );
        started
            .sim
            .spend_coins(spends, std::slice::from_ref(&started.custody_sk))?;

        let restored = started.child.child(ready.inner_puzzle_hash, 1);
        assert_eq!(restored.coin.puzzle_hash, ready.full_puzzle_hash);
        assert!(
            started
                .sim
                .children(started.child.coin.coin_id())
                .iter()
                .any(|child| child.coin.coin_id() == restored.coin.coin_id())
        );
        let report = inspect_vault(
            &started.config,
            Some(restored.coin),
            Some(&started.post),
            Some(started.child.coin.puzzle_hash),
        )?;
        assert_eq!(report.phase, VaultPhase::ClawedBack);

        let ready_coin = Coin::new(Bytes32::new([9; 32]), ready.full_puzzle_hash, 1);
        let still_ready = inspect_vault(
            &started.config,
            Some(ready_coin),
            Some(&started.post),
            Some(Bytes32::new([1; 32])),
        )?;
        assert_eq!(still_ready.phase, VaultPhase::Ready);
        Ok(())
    }

    #[test]
    fn settled_phase_follows_the_recovery_parent_and_coin_amount() -> anyhow::Result<()> {
        let started = start_on_sim()?;
        let launcher = started.config.launcher_id_bytes()?;
        let ready = get_vault_internals(launcher, &started.keys)?;
        let post_ready = get_vault_internals(launcher, &started.post.to_vault_keys()?)?;
        let recovery_parent = started.child.coin.puzzle_hash;

        let dust = Coin::new(Bytes32::new([7; 32]), post_ready.full_puzzle_hash, 1);
        let dust_report = inspect_vault(
            &started.config,
            Some(dust),
            Some(&started.post),
            Some(Bytes32::new([8; 32])),
        )?;
        assert_ne!(dust_report.phase, VaultPhase::Finished);

        let finished = Coin::new(recovery_parent, post_ready.full_puzzle_hash, 1);
        let finished_report = inspect_vault(
            &started.config,
            Some(finished),
            Some(&started.post),
            Some(recovery_parent),
        )?;
        assert_eq!(finished_report.phase, VaultPhase::Finished);

        let untouched = Coin::new(Bytes32::new([4; 32]), ready.full_puzzle_hash, 1);
        let same_hash = inspect_vault(
            &started.config,
            Some(untouched),
            Some(&started.config),
            Some(Bytes32::new([5; 32])),
        )?;
        assert_eq!(same_hash.phase, VaultPhase::Ready);

        let same_inner =
            recovery_state_hashes(launcher, &started.keys, ready.inner_puzzle_hash, 1)?;
        let settled = inspect_vault(
            &started.config,
            Some(untouched),
            Some(&started.config),
            Some(same_inner.internals.full_puzzle_hash),
        )?;
        assert_eq!(settled.phase, VaultPhase::ClawedBack);
        assert_eq!(
            settled.guidance,
            "Vault is under the original custody configuration."
        );

        let at_one = recovery_state_hashes(launcher, &started.keys, started.post_inner, 1)?;
        let at_three = recovery_state_hashes(launcher, &started.keys, started.post_inner, 3)?;
        assert_ne!(
            at_one.internals.full_puzzle_hash,
            at_three.internals.full_puzzle_hash
        );
        let amount_three = Coin::new(
            Bytes32::new([3; 32]),
            at_three.internals.full_puzzle_hash,
            3,
        );
        let report_three = inspect_vault(
            &started.config,
            Some(amount_three),
            Some(&started.post),
            None,
        )?;
        assert_eq!(report_three.phase, VaultPhase::InRecovery);

        let amount_one_hash =
            Coin::new(Bytes32::new([3; 32]), at_one.internals.full_puzzle_hash, 3);
        let report_mismatch = inspect_vault(
            &started.config,
            Some(amount_one_hash),
            Some(&started.post),
            None,
        )?;
        assert_ne!(report_mismatch.phase, VaultPhase::InRecovery);
        Ok(())
    }
}
