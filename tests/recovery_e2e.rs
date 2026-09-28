//! End-to-end delayed recovery on the chia-sdk-test Simulator (no mocks).

use chia_bls::SecretKey;
use chia_puzzle_types::Memos;
use chia_sdk_driver::{InnerPuzzleSpend, Launcher, MipsSpend, SpendContext, StandardLayer, Vault};
use chia_sdk_test::{K1Pair, Simulator};
use chia_sdk_types::Conditions;
use clvm_utils::TreeHash;

use chia_vault_recover::config::VaultConfig;
use chia_vault_recover::discover::{
    ClawbackGuess, FoundVault, custody_from_vault_spend, reconstruct, reconstruct_config,
};
use chia_vault_recover::keys::{
    MnemonicWordCount, generate_mnemonic, key_from_mnemonic, public_key_to_hex,
};
use chia_vault_recover::locate::launcher_from_spend;
use chia_vault_recover::network::Network;
use chia_vault_recover::recovery::{
    FinishRecoveryParams, StartRecoveryParams, VaultPhase, finish_recovery, inspect_vault,
    start_recovery,
};
use chia_vault_recover::vault::{
    CustodyPath, RecoverySignerSet, SignerSet, VaultKeys, VaultMemberKey, get_vault_internals,
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

#[test]
fn delayed_recovery_bls_phrase_to_new_bls_custody() -> anyhow::Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();

    let custody = K1Pair::default();
    let recovery = generate_mnemonic(MnemonicWordCount::Words24)?;
    let recovery_words = recovery.words.clone();

    let keys = VaultKeys {
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

    let prelim = get_vault_internals(chia_protocol::Bytes32::default(), &keys)?;
    let vault = mint_vault(&mut sim, ctx, prelim.inner_puzzle_hash)?;
    let launcher_id = vault.info.launcher_id;

    let ready = get_vault_internals(launcher_id, &keys)?;
    assert_eq!(vault.info.custody_hash, ready.inner_puzzle_hash);

    let config = VaultConfig {
        launcher_id: format!("0x{}", hex::encode(launcher_id)),
        custody: chia_vault_recover::config::VaultConfigSide {
            threshold: 1,
            members: vec![chia_vault_recover::config::VaultConfigMember::PublicKey {
                public_key: format!("0x{}", hex::encode(custody.pk.to_bytes())),
                curve: chia_vault_recover::config::Curve::Secp256k1,
                key_type: None,
            }],
            hash: None,
        },
        recovery: chia_vault_recover::config::VaultConfigRecovery {
            threshold: 1,
            clawback_timelock: 10,
            members: vec![chia_vault_recover::config::VaultConfigMember::PublicKey {
                public_key: public_key_to_hex(&recovery.key_pair.public_key),
                curve: chia_vault_recover::config::Curve::Bls12_381,
                key_type: Some(chia_vault_recover::config::KeyType::RecoveryPhrase),
            }],
        },
        receive_address: None,
    };

    let report = inspect_vault(&config, Some(vault.coin), None)?;
    assert_eq!(report.phase, VaultPhase::Ready);

    let new_custody = generate_mnemonic(MnemonicWordCount::Words24)?;
    let start = start_recovery(StartRecoveryParams {
        config: &config,
        vault_coin: vault.coin,
        lineage_proof: vault.proof,
        recovery_mnemonic: &recovery_words,
        new_custody_mnemonic: &new_custody.words,
        new_recovery_mnemonic: None,
        new_clawback_timelock: Some(10),
        new_word_count: MnemonicWordCount::Words24,
        network: Network::Testnet11,
    })?;

    assert!(start.generated_recovery_mnemonic.is_some());
    let serialized = serde_json::to_string(&start.post_recovery_config)?;
    assert!(!serialized.contains(&new_custody.words));
    assert!(!serialized.contains(start.generated_recovery_mnemonic.as_ref().unwrap()));

    sim.spend_coins(
        start.spend_bundle.coin_spends.clone(),
        std::slice::from_ref(&recovery.key_pair.secret_key),
    )?;

    let post_keys = start.post_recovery_config.to_vault_keys()?;
    let post_ready = get_vault_internals(launcher_id, &post_keys)?;
    let recovery_hashes =
        recovery_state_hashes(launcher_id, &keys, post_ready.inner_puzzle_hash, 1)?;
    let vault_after_start = vault.child(recovery_hashes.internals.inner_puzzle_hash, 1);

    let report2 = inspect_vault(
        &config,
        Some(vault_after_start.coin),
        Some(post_ready.inner_puzzle_hash),
    )?;
    assert_eq!(report2.phase, VaultPhase::InRecovery);
    assert!(report2.guidance.contains("finish"));

    // Without post-recovery config, mismatched PH must be Unknown (not a guessed InRecovery).
    let report_unknown = inspect_vault(&config, Some(vault_after_start.coin), None)?;
    assert_eq!(report_unknown.phase, VaultPhase::Unknown);

    sim.pass_time(10);

    let finish_bundle = finish_recovery(FinishRecoveryParams {
        config: &config,
        post_recovery_config: &start.post_recovery_config,
        vault_coin: vault_after_start.coin,
        lineage_proof: vault_after_start.proof,
        network: Network::Testnet11,
    })?;

    sim.spend_coins(finish_bundle.coin_spends, &[])?;

    let post_ready = get_vault_internals(launcher_id, &post_keys)?;
    let vault_final = vault_after_start.child(post_ready.inner_puzzle_hash, 1);

    let conditions =
        Conditions::new().create_coin(vault_final.info.custody_hash.into(), 1, Memos::None);
    let mut spend = MipsSpend::new(ctx.delegated_spend(conditions)?);
    spend.members.insert(
        post_ready.inner_puzzle_hash,
        InnerPuzzleSpend::m_of_n(
            0,
            Vec::new(),
            1,
            vec![post_ready.custody_hash, post_ready.recovery_hash],
        ),
    );
    let bls = chia_sdk_types::puzzles::BlsMember::new(new_custody.key_pair.public_key);
    let bls_puzzle = ctx.curry(bls)?;
    let bls_solution = ctx.alloc(&clvmr::NodePtr::NIL)?;
    spend.members.insert(
        post_ready.custody_hash,
        InnerPuzzleSpend::new(
            0,
            Vec::new(),
            chia_sdk_driver::Spend::new(bls_puzzle, bls_solution),
        ),
    );
    vault_final.spend(ctx, &spend)?;
    sim.spend_coins(ctx.take(), &[new_custody.key_pair.secret_key])?;

    Ok(())
}

#[test]
fn discover_custody_from_previous_spend() -> anyhow::Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();

    let custody = generate_mnemonic(MnemonicWordCount::Words24)?;
    let recovery = generate_mnemonic(MnemonicWordCount::Words24)?;
    let recovery_words = recovery.words.clone();

    let keys = VaultKeys {
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

    let prelim = get_vault_internals(chia_protocol::Bytes32::default(), &keys)?;
    let vault = mint_vault(&mut sim, ctx, prelim.inner_puzzle_hash)?;
    let launcher_id = vault.info.launcher_id;
    let ready = get_vault_internals(launcher_id, &keys)?;

    let conditions = Conditions::new().create_coin(ready.inner_puzzle_hash.into(), 1, Memos::None);
    let mut spend = MipsSpend::new(ctx.delegated_spend(conditions)?);
    spend.members.insert(
        ready.inner_puzzle_hash,
        InnerPuzzleSpend::m_of_n(
            0,
            Vec::new(),
            1,
            vec![ready.custody_hash, ready.recovery_hash],
        ),
    );
    let bls = chia_sdk_types::puzzles::BlsMember::new(custody.key_pair.public_key);
    let bls_puzzle = ctx.curry(bls)?;
    let bls_solution = ctx.alloc(&clvmr::NodePtr::NIL)?;
    spend.members.insert(
        ready.custody_hash,
        InnerPuzzleSpend::new(
            0,
            Vec::new(),
            chia_sdk_driver::Spend::new(bls_puzzle, bls_solution),
        ),
    );
    vault.spend(ctx, &spend)?;
    let coin_spends = ctx.take();
    let vault_spend = coin_spends
        .iter()
        .find(|cs| cs.coin.coin_id() == vault.coin.coin_id())
        .expect("vault spend");

    assert_eq!(
        launcher_from_spend(vault_spend).expect("launcher from vault spend"),
        launcher_id
    );

    let path = custody_from_vault_spend(vault_spend)?.expect("custody path from spend");
    assert_eq!(path.custody_hash, ready.custody_hash);
    assert!(
        matches!(path.members.first(), Some(VaultMemberKey::Bls(_))),
        "expected parsed BLS custody key, got {:?}",
        path.members
    );

    let reconstructed = reconstruct_config(launcher_id, &path, &recovery_words, 10)?;
    let reconstructed_keys = reconstructed.to_vault_keys()?;
    assert!(matches!(reconstructed_keys.custody, CustodyPath::Hash(_)));
    let reconstructed_ready = get_vault_internals(launcher_id, &reconstructed_keys)?;
    assert_eq!(reconstructed_ready.full_puzzle_hash, ready.full_puzzle_hash);
    assert_eq!(reconstructed_ready.custody_hash, ready.custody_hash);
    assert!(matches!(
        reconstructed.custody.members.first(),
        Some(chia_vault_recover::VaultConfigMember::PublicKey {
            key_type: None,
            curve: chia_vault_recover::Curve::Bls12_381,
            ..
        })
    ));

    let found = FoundVault {
        launcher_id,
        launcher_source: "test".into(),
        custody: path.clone(),
        current_coin: vault.coin,
        ancestor_puzzle_hashes: vec![ready.full_puzzle_hash],
    };
    let rebuilt = reconstruct(&found, &recovery_words, ClawbackGuess::Unknown)?;
    assert_eq!(rebuilt.config.recovery.clawback_timelock, 10);
    assert!(rebuilt.found.custody.members_complete());
    assert!(rebuilt.matches_current);

    let hash_only = chia_vault_recover::DiscoveredCustodyPath {
        custody_hash: path.custody_hash,
        members: vec![],
        vault_launcher_ids: vec![],
    };
    let hash_config = reconstruct_config(launcher_id, &hash_only, &recovery_words, 10)?;
    assert!(hash_config.custody.members.is_empty());
    assert!(hash_config.custody.hash.is_some());
    let hash_keys = hash_config.to_vault_keys()?;
    assert!(matches!(hash_keys.custody, CustodyPath::Hash(_)));
    assert_eq!(
        get_vault_internals(launcher_id, &hash_keys)?.full_puzzle_hash,
        ready.full_puzzle_hash
    );

    sim.spend_coins(coin_spends, &[custody.key_pair.secret_key])?;

    Ok(())
}

#[test]
fn cloud_wallet_style_key_derivation_stable() {
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let a = key_from_mnemonic(words).unwrap();
    let b = key_from_mnemonic(words).unwrap();
    assert_eq!(a.public_key.to_bytes(), b.public_key.to_bytes());
    let _sk: SecretKey = a.secret_key;
}
