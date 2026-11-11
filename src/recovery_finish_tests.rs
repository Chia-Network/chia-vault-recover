use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use chia_bls::SecretKey;
use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzle_types::Memos;
use chia_sdk_coinset::{ChiaRpcClient, CoinRecord, MempoolItem};
use chia_sdk_driver::{InnerPuzzleSpend, Launcher, MipsSpend, Spend, StandardLayer};
use chia_sdk_test::Simulator;
use chia_sdk_types::{Conditions, puzzles::BlsMember};
use clvmr::NodePtr;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::chain::{ChainClient, PendingSpend};
use crate::config::{Curve, KeyType, VaultConfigMember, VaultConfigRecovery, VaultConfigSide};
use crate::keys::{MnemonicWordCount, generate_mnemonic, public_key_to_hex};
use crate::test_rpc::{ScriptedRpc, page};
use crate::vault::{
    CustodyPath, RecoverySignerSet, SignerSet, VaultMemberKey, get_vault_internals,
    recovery_state_hashes,
};
use crate::workflow::FinishAction;

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

fn return_to_custody_spends(started: &Started) -> anyhow::Result<Vec<CoinSpend>> {
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
fn returning_the_vault_needs_the_custody_signature() -> anyhow::Result<()> {
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

    let spends = return_to_custody_spends(&started)?;
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

struct SimRpc<'a> {
    sim: &'a Simulator,
    pending: Option<Bytes32>,
    pushes: Arc<AtomicUsize>,
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

fn body_id(body: &Value, field: &str) -> Option<Bytes32> {
    let text = body.get(field)?.as_str()?;
    let bytes: [u8; 32] = hex::decode(text.trim_start_matches("0x"))
        .ok()?
        .try_into()
        .ok()?;
    Some(Bytes32::new(bytes))
}

impl ChiaRpcClient for SimRpc<'_> {
    type Error = String;

    fn base_url(&self) -> &str {
        "sim"
    }

    async fn make_post_request<R, B>(
        &self,
        endpoint: &str,
        body: B,
    ) -> std::result::Result<R, String>
    where
        B: Serialize + Send,
        R: DeserializeOwned + Send,
    {
        let body = serde_json::to_value(body).map_err(|e| e.to_string())?;
        let response = match endpoint {
            "get_coin_records_by_parent_ids" => {
                let parent = body
                    .get("parent_ids")
                    .and_then(Value::as_array)
                    .and_then(|ids| ids.first())
                    .and_then(Value::as_str)
                    .and_then(|text| {
                        let bytes: [u8; 32] = hex::decode(text.trim_start_matches("0x"))
                            .ok()?
                            .try_into()
                            .ok()?;
                        Some(Bytes32::new(bytes))
                    })
                    .ok_or_else(|| "missing parent id".to_string())?;
                let records: Vec<_> = self
                    .sim
                    .children(parent)
                    .into_iter()
                    .map(record_of)
                    .collect();
                json!({"coin_records": records, "success": true})
            }
            "get_coin_record_by_name" => {
                let id = body_id(&body, "name").ok_or_else(|| "missing coin name".to_string())?;
                let record = self.sim.coin_state(id).map(record_of);
                json!({"coin_record": record, "success": true})
            }
            "get_mempool_items_by_coin_name" => {
                let id =
                    body_id(&body, "coin_name").ok_or_else(|| "missing coin name".to_string())?;
                let items = if self.pending == Some(id) {
                    vec![MempoolItem {
                        spend_bundle: SpendBundle::aggregate(&[]),
                        fee: 0,
                    }]
                } else {
                    Vec::new()
                };
                json!({"mempool_items": items, "success": true})
            }
            "get_puzzle_and_solution" => {
                let id = body_id(&body, "coin_id").ok_or_else(|| "missing coin id".to_string())?;
                json!({"coin_solution": self.sim.coin_spend(id), "success": true})
            }
            "push_tx" => {
                self.pushes.fetch_add(1, Ordering::Relaxed);
                json!({"status": "SUCCESS", "success": true})
            }
            _ => return Err(format!("unscripted {endpoint}")),
        };
        serde_json::from_value(response).map_err(|e| e.to_string())
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
    let client = ChainClient::with_rpc(SimRpc {
        sim,
        pending: None,
        pushes: Arc::new(AtomicUsize::new(0)),
    });
    runtime.block_on(crate::workflow::inspect(&client, config, post))
}

fn finish_sim(
    sim: &Simulator,
    pushes: &Arc<AtomicUsize>,
    config: &VaultConfig,
    post: &VaultConfig,
) -> Result<crate::workflow::FinishOutcome> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = ChainClient::with_rpc(SimRpc {
        sim,
        pending: None,
        pushes: Arc::clone(pushes),
    });
    runtime.block_on(crate::workflow::finish(
        &client,
        config,
        post,
        Network::Testnet11,
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

fn map_rpc(chain: &MapChain) -> ScriptedRpc {
    let children = chain.children.clone();
    let records = chain.records.clone();
    let reread = chain.reread.clone();
    ScriptedRpc::new(move |endpoint, body| match endpoint {
        "get_coin_records_by_parent_ids" => {
            let parent = body
                .get("parent_ids")
                .and_then(Value::as_array)
                .and_then(|ids| ids.first())
                .and_then(Value::as_str)
                .and_then(|text| {
                    let bytes: [u8; 32] = hex::decode(text.trim_start_matches("0x"))
                        .ok()?
                        .try_into()
                        .ok()?;
                    Some(Bytes32::new(bytes))
                })?;
            let page_records = children.get(&parent).map(Vec::as_slice).unwrap_or(&[]);
            Some(page(page_records, None, false))
        }
        "get_coin_record_by_name" => {
            let id = body_id(body, "name")?;
            let record = reread.get(&id).or_else(|| records.get(&id)).copied();
            Some(json!({"coin_record": record, "success": true}))
        }
        "get_mempool_items_by_coin_name" => Some(json!({"mempool_items": [], "success": true})),
        _ => None,
    })
}

fn inspect_map(
    chain: &MapChain,
    config: &VaultConfig,
    post: Option<&VaultConfig>,
) -> Result<InspectReport> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = ChainClient::with_rpc(map_rpc(chain));
    runtime.block_on(crate::workflow::inspect(&client, config, post))
}

#[test]
fn walk_ignores_an_unrelated_coin_at_the_same_puzzle_hash() -> anyhow::Result<()> {
    let mut started = start_on_sim()?;
    let launcher = started.config.launcher_id_bytes()?;
    let post_ready = get_vault_internals(launcher, &started.post.to_vault_keys()?)?;
    let unrelated_parent = Coin::new(Bytes32::new([4; 32]), Bytes32::new([5; 32]), 2);
    let unrelated = Coin::new(unrelated_parent.coin_id(), post_ready.full_puzzle_hash, 1);
    started.sim.insert_coin(unrelated_parent);
    started.sim.insert_coin(unrelated);

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
    let unrelated_client = ChainClient::with_rpc(SimRpc {
        sim: &started.sim,
        pending: None,
        pushes: Arc::new(AtomicUsize::new(0)),
    });
    let unrelated_observed = runtime.block_on(load_singleton(
        &unrelated_client,
        unrelated_parent.coin_id(),
    ))?;
    assert_eq!(unrelated_observed.tip.coin.coin_id(), unrelated.coin_id());
    let unrelated_report = classify_singleton(
        &started.config,
        Some(&started.post),
        &unrelated_observed,
        PendingSpend::None,
    )?;
    assert_eq!(unrelated_report.phase, VaultPhase::Unknown);

    let pending_client = ChainClient::with_rpc(SimRpc {
        sim: &started.sim,
        pending: Some(started.child.coin.coin_id()),
        pushes: Arc::new(AtomicUsize::new(0)),
    });
    let pending = runtime.block_on(crate::workflow::inspect(
        &pending_client,
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
fn settled_coin_uses_the_parent_amount() -> anyhow::Result<()> {
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

#[test]
fn pending_check_failure_is_reported_without_failing_inspect() -> anyhow::Result<()> {
    let started = start_on_sim()?;
    let launcher = started.config.launcher_id_bytes()?;
    let client = ChainClient::with_rpc(SimRpc {
        sim: &started.sim,
        pending: None,
        pushes: Arc::new(AtomicUsize::new(0)),
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let observed = runtime.block_on(load_singleton(&client, launcher))?;
    let report = classify_singleton(
        &started.config,
        Some(&started.post),
        &observed,
        PendingSpend::Unknown,
    )?;
    assert_eq!(report.phase, VaultPhase::InRecovery);
    let note = report.pending_note.expect("unknown pending note");
    assert!(
        note.contains("Could not check for a pending spend"),
        "{note}"
    );
    Ok(())
}

#[test]
fn finish_after_recovery_finished_pushes_nothing() -> anyhow::Result<()> {
    let mut started = start_on_sim()?;
    started.sim.pass_time(10);
    let bundle = finish_recovery(FinishRecoveryParams {
        config: &started.config,
        post_recovery_config: &started.post,
        vault_coin: started.child.coin,
        lineage_proof: started.child.proof,
        network: Network::Testnet11,
    })?;
    started.sim.spend_coins(bundle.coin_spends, &[])?;

    let report = inspect_sim(&started.sim, &started.config, Some(&started.post))?;
    assert_eq!(report.phase, VaultPhase::Finished);

    let pushes = Arc::new(AtomicUsize::new(0));
    let outcome = finish_sim(&started.sim, &pushes, &started.config, &started.post)?;
    assert_eq!(outcome.action, FinishAction::AlreadyFinished);
    assert_eq!(pushes.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn finish_after_clawback_pushes_nothing() -> anyhow::Result<()> {
    let mut started = start_on_sim()?;
    let spends = return_to_custody_spends(&started)?;
    started
        .sim
        .spend_coins(spends, std::slice::from_ref(&started.custody_sk))?;

    let report = inspect_sim(&started.sim, &started.config, Some(&started.post))?;
    assert_eq!(report.phase, VaultPhase::ClawedBack);

    let pushes = Arc::new(AtomicUsize::new(0));
    let outcome = finish_sim(&started.sim, &pushes, &started.config, &started.post)?;
    assert_eq!(outcome.action, FinishAction::ClawedBack);
    assert_eq!(pushes.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn finish_in_recovery_pushes_once() -> anyhow::Result<()> {
    let mut started = start_on_sim()?;
    started.sim.pass_time(10);

    let pushes = Arc::new(AtomicUsize::new(0));
    let outcome = finish_sim(&started.sim, &pushes, &started.config, &started.post)?;
    assert!(matches!(outcome.action, FinishAction::Pushed(_)));
    assert_eq!(pushes.load(Ordering::Relaxed), 1);
    Ok(())
}
