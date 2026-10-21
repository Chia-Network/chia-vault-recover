use std::collections::HashMap;

use super::*;
use chia_bls::SecretKey;
use chia_protocol::{Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_sdk_coinset::CoinRecord;
use chia_sdk_driver::{InnerPuzzleSpend, Launcher, MipsSpend, Spend, StandardLayer};
use chia_sdk_test::Simulator;
use chia_sdk_types::{Conditions, puzzles::BlsMember};
use clvmr::NodePtr;

use crate::chain::SingletonIndex;

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
    amount: u64,
) -> anyhow::Result<Vault> {
    let alice = sim.bls(amount);
    let alice_p2 = StandardLayer::new(alice.pk);
    let (mint_vault, vault) =
        Launcher::new(alice.coin.coin_id(), amount).mint_vault(ctx, custody_hash, ())?;
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
    start_with_amount(1)
}

fn start_with_amount(amount: u64) -> anyhow::Result<Started> {
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
    let vault = mint_vault(&mut sim, ctx, prelim.inner_puzzle_hash, amount)?;
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
    let state = recovery_state_hashes(launcher_id, &keys, post_inner, amount)?;
    assert_eq!(
        state.internals.full_puzzle_hash,
        start.recovery_state_puzzle_hash
    );
    let child = vault.child(state.internals.inner_puzzle_hash, amount);
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
    let amount = started.child.coin.amount;
    let state = recovery_state_hashes(launcher, &started.keys, started.post_inner, amount)?;
    let conditions =
        Conditions::new().create_coin(ready.inner_puzzle_hash.into(), amount, Memos::None);
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

    let restored = started
        .child
        .child(ready.inner_puzzle_hash, started.child.coin.amount);
    assert_eq!(restored.coin.puzzle_hash, ready.full_puzzle_hash);
    assert!(
        started
            .sim
            .children(started.child.coin.coin_id())
            .iter()
            .any(|child| child.coin.coin_id() == restored.coin.coin_id())
    );
    let report = inspect_sim(&started.sim, &started.config, Some(&started.post))?;
    assert_eq!(report.phase, VaultPhase::ClawedBack);
    assert_eq!(
        report.on_chain_coin.map(|coin| coin.coin_id()),
        Some(restored.coin.coin_id())
    );
    Ok(())
}

struct SimChain<'a> {
    sim: &'a Simulator,
    pending: Option<Bytes32>,
}

fn record_of(state: chia_protocol::CoinState) -> CoinRecord {
    CoinRecord {
        coin: state.coin,
        coinbase: false,
        confirmed_block_index: state.created_height.unwrap_or(0),
        spent: state.spent_height.is_some(),
        spent_block_index: state.spent_height.unwrap_or(0),
        timestamp: 0,
    }
}

impl SingletonIndex for SimChain<'_> {
    async fn children_of(&self, parent_id: Bytes32) -> Result<Vec<CoinRecord>> {
        Ok(self
            .sim
            .children(parent_id)
            .into_iter()
            .map(record_of)
            .collect())
    }

    async fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>> {
        Ok(self.sim.coin_state(coin_id).map(record_of))
    }

    async fn coin_has_pending_spend(&self, coin_id: Bytes32) -> Result<bool> {
        Ok(self.pending == Some(coin_id))
    }
}

fn inspect_sim(
    sim: &Simulator,
    config: &VaultConfig,
    post: Option<&VaultConfig>,
) -> Result<InspectReport> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(crate::workflow::inspect(
        &SimChain { sim, pending: None },
        config,
        post,
    ))
}

fn stored(coin: Coin, spent: bool) -> CoinRecord {
    CoinRecord {
        coin,
        coinbase: false,
        confirmed_block_index: 1,
        spent,
        spent_block_index: u32::from(spent),
        timestamp: 1,
    }
}

struct MapChain {
    children: HashMap<Bytes32, Vec<CoinRecord>>,
    records: HashMap<Bytes32, CoinRecord>,
    reread: HashMap<Bytes32, CoinRecord>,
}

impl SingletonIndex for MapChain {
    async fn children_of(&self, parent_id: Bytes32) -> Result<Vec<CoinRecord>> {
        Ok(self.children.get(&parent_id).cloned().unwrap_or_default())
    }

    async fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>> {
        if let Some(record) = self.reread.get(&coin_id) {
            return Ok(Some(*record));
        }
        Ok(self.records.get(&coin_id).copied())
    }

    async fn coin_has_pending_spend(&self, _coin_id: Bytes32) -> Result<bool> {
        Ok(false)
    }
}

fn inspect_map(
    chain: &MapChain,
    config: &VaultConfig,
    post: Option<&VaultConfig>,
) -> Result<InspectReport> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(crate::workflow::inspect(chain, config, post))
}

#[test]
fn walk_reports_the_recovery_coin_not_dust_at_the_same_hash() -> anyhow::Result<()> {
    let mut started = start_on_sim()?;
    let launcher = started.config.launcher_id_bytes()?;
    let post_ready = get_vault_internals(launcher, &started.post.to_vault_keys()?)?;
    let dust_parent = Coin::new(Bytes32::new([4; 32]), Bytes32::new([5; 32]), 2);
    let dust = Coin::new(dust_parent.coin_id(), post_ready.full_puzzle_hash, 1);
    started.sim.insert_coin(dust_parent);
    started.sim.insert_coin(dust);

    let report = inspect_sim(&started.sim, &started.config, Some(&started.post))?;
    assert_eq!(report.phase, VaultPhase::InRecovery);
    assert_eq!(
        report.on_chain_coin.map(|coin| coin.coin_id()),
        Some(started.child.coin.coin_id())
    );
    assert!(report.pending_note.is_none());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let dust_observed = runtime.block_on(load_singleton(
        &SimChain {
            sim: &started.sim,
            pending: None,
        },
        dust_parent.coin_id(),
    ))?;
    assert_eq!(dust_observed.tip.coin.coin_id(), dust.coin_id());
    let dust_report =
        classify_singleton(&started.config, Some(&started.post), &dust_observed, false)?;
    assert_eq!(dust_report.phase, VaultPhase::Unknown);

    let pending = runtime.block_on(crate::workflow::inspect(
        &SimChain {
            sim: &started.sim,
            pending: Some(started.child.coin.coin_id()),
        },
        &started.config,
        Some(&started.post),
    ))?;
    assert_eq!(pending.phase, VaultPhase::InRecovery);
    assert_eq!(
        pending.pending_note.as_deref(),
        Some(PENDING_FINISH_OR_CLAWBACK)
    );
    Ok(())
}

#[test]
fn amount_changing_clawback_uses_the_parent_amount() -> anyhow::Result<()> {
    let mut started = start_with_amount(5)?;
    let launcher = started.config.launcher_id_bytes()?;
    let ready = get_vault_internals(launcher, &started.keys)?;
    let at_five = recovery_state_hashes(launcher, &started.keys, started.post_inner, 5)?;
    let at_three = recovery_state_hashes(launcher, &started.keys, started.post_inner, 3)?;
    assert_ne!(
        at_five.internals.full_puzzle_hash,
        at_three.internals.full_puzzle_hash
    );

    let mut ctx = SpendContext::new();
    let state = recovery_state_hashes(launcher, &started.keys, started.post_inner, 5)?;
    let conditions = Conditions::new()
        .create_coin(ready.inner_puzzle_hash.into(), 3, Memos::None)
        .create_coin(Bytes32::new([7; 32]), 2, Memos::None);
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
    started
        .sim
        .spend_coins(ctx.take(), std::slice::from_ref(&started.custody_sk))?;

    let report = inspect_sim(&started.sim, &started.config, Some(&started.post))?;
    assert_eq!(report.phase, VaultPhase::ClawedBack);
    let coin = report.on_chain_coin.expect("walked coin");
    assert_eq!(coin.amount, 3);
    assert_eq!(coin.puzzle_hash, ready.full_puzzle_hash);
    Ok(())
}

#[test]
fn parent_record_and_reread_gate_settled_phases() -> anyhow::Result<()> {
    let started = start_on_sim()?;
    let launcher = started.config.launcher_id_bytes()?;
    let ready = get_vault_internals(launcher, &started.keys)?;
    let recovery_at_one = recovery_state_hashes(launcher, &started.keys, started.post_inner, 1)?;
    let recovery_coin = Coin::new(launcher, recovery_at_one.internals.full_puzzle_hash, 1);
    let child = Coin::new(recovery_coin.coin_id(), ready.full_puzzle_hash, 1);

    let missing = MapChain {
        children: HashMap::from([(launcher, vec![stored(child, false)])]),
        records: HashMap::from([(child.coin_id(), stored(child, false))]),
        reread: HashMap::new(),
    };
    let err = inspect_map(&missing, &started.config, Some(&started.post)).unwrap_err();
    assert!(
        err.to_string()
            .contains("parent coin record not found for the vault singleton"),
        "{err}"
    );

    let unspent_parent = MapChain {
        children: HashMap::from([(launcher, vec![stored(child, false)])]),
        records: HashMap::from([
            (recovery_coin.coin_id(), stored(recovery_coin, false)),
            (child.coin_id(), stored(child, false)),
        ]),
        reread: HashMap::new(),
    };
    let err = inspect_map(&unspent_parent, &started.config, Some(&started.post)).unwrap_err();
    assert!(
        err.to_string()
            .contains("parent of the vault singleton is not spent"),
        "{err}"
    );

    let changed = MapChain {
        children: HashMap::from([(launcher, vec![stored(child, false)])]),
        records: HashMap::from([(recovery_coin.coin_id(), stored(recovery_coin, true))]),
        reread: HashMap::from([(child.coin_id(), stored(child, true))]),
    };
    let err = inspect_map(&changed, &started.config, Some(&started.post)).unwrap_err();
    assert!(
        err.to_string()
            .contains("vault singleton changed while reading"),
        "{err}"
    );

    let same_recovery = recovery_state_hashes(launcher, &started.keys, ready.inner_puzzle_hash, 1)?;
    let same_parent = Coin::new(launcher, same_recovery.internals.full_puzzle_hash, 1);
    let same_child = Coin::new(same_parent.coin_id(), ready.full_puzzle_hash, 1);
    let settled = MapChain {
        children: HashMap::from([(launcher, vec![stored(same_child, false)])]),
        records: HashMap::from([
            (same_parent.coin_id(), stored(same_parent, true)),
            (same_child.coin_id(), stored(same_child, false)),
        ]),
        reread: HashMap::new(),
    };
    let same = inspect_map(&settled, &started.config, Some(&started.config))?;
    assert_eq!(same.phase, VaultPhase::ClawedBack);
    assert_eq!(
        same.guidance,
        "Vault is under the original custody configuration."
    );

    let ready_child = Coin::new(Bytes32::new([6; 32]), ready.full_puzzle_hash, 1);
    let untouched = MapChain {
        children: HashMap::from([(launcher, vec![stored(ready_child, false)])]),
        records: HashMap::from([
            (
                ready_child.parent_coin_info,
                stored(
                    Coin::new(Bytes32::new([8; 32]), Bytes32::new([9; 32]), 1),
                    true,
                ),
            ),
            (ready_child.coin_id(), stored(ready_child, false)),
        ]),
        reread: HashMap::new(),
    };
    let ready_report = inspect_map(&untouched, &started.config, Some(&started.config))?;
    assert_eq!(ready_report.phase, VaultPhase::Ready);
    Ok(())
}
