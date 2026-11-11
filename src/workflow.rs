//! End-to-end recovery workflows shared by CLI and GUI.

use std::fmt::Display;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use chia_protocol::Coin;
use chia_puzzle_types::Proof;
use chia_sdk_coinset::ChiaRpcClient;

use crate::cache::{LookupCache, VaultLookup};
use crate::chain::ChainClient;
use crate::config::VaultConfig;
use crate::discover::{
    ClawbackGuess, DEFAULT_TIMELOCK_CANDIDATES, FoundVault, ReconstructedVault,
    confirm_hinted_config, custody_from_vault_spend, reconstruct,
};
use crate::error::{Error, Result};
use crate::guidance::{KnownLauncher, LookupGap};
use crate::hint::hinted_config_from_spend;
use crate::keys::MnemonicWordCount;
use crate::locate::{parse_vault_locator, resolve_launcher_id};
use crate::network::Network;
use crate::recovery::{
    FinishRecoveryParams, InspectReport, StartRecoveryParams, StartRecoveryResult, VaultPhase,
    classify_singleton, finish_recovery, load_singleton, start_recovery,
};
use crate::scan::LauncherScan;

/// What `finish` did with a vault that may already have left recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishOutcome {
    pub action: FinishAction,
    /// Present when the confirmed coin is in recovery and also has a mempool spend.
    pub pending_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishAction {
    /// Unsigned finish spend was submitted.
    Pushed(String),
    /// The unspent coin is already the recovered custody puzzle.
    AlreadyFinished,
    /// The unspent coin is the original custody puzzle, created by the recovery coin.
    ClawedBack,
}

#[derive(Debug, Clone)]
pub struct ResolvedVault {
    pub coin: Coin,
    pub proof: Proof,
    pub phase: VaultPhase,
}

/// Find the live singleton from its launcher and its lineage proof.
///
/// With a post-recovery config, that coin is settled only when its parent is the recovery coin.
pub async fn resolve_vault<C>(
    client: &ChainClient<C>,
    config: &VaultConfig,
    post_recovery: Option<&VaultConfig>,
) -> Result<ResolvedVault>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    let report = inspect(client, config, post_recovery).await?;
    let Some(coin) = report.on_chain_coin else {
        return Err(Error::msg(
            "vault singleton not found on chain for this config",
        ));
    };
    if report.phase == VaultPhase::Unknown {
        return Err(Error::msg("on-chain vault does not match this config"));
    }
    let proof = client.lineage_proof_for_coin(&coin).await?;
    Ok(ResolvedVault {
        coin,
        proof,
        phase: report.phase,
    })
}

pub async fn inspect<C>(
    client: &ChainClient<C>,
    config: &VaultConfig,
    post_recovery: Option<&VaultConfig>,
) -> Result<InspectReport>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    with_deadline(
        INSPECT_DEADLINE,
        "vault inspection",
        "; the node may be slow",
        inspect_inner(client, config, post_recovery),
    )
    .await
}

async fn inspect_inner<C>(
    client: &ChainClient<C>,
    config: &VaultConfig,
    post_recovery: Option<&VaultConfig>,
) -> Result<InspectReport>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    let launcher_id = config.launcher_id_bytes()?;
    let observed = load_singleton(client, launcher_id).await?;
    let pending = client
        .coin_has_pending_spend(observed.tip.coin.coin_id())
        .await;
    classify_singleton(config, post_recovery, &observed, pending)
}

pub struct StartWorkflow<'a> {
    pub config: &'a VaultConfig,
    pub recovery_mnemonic: &'a str,
    pub new_custody_mnemonic: &'a str,
    pub new_recovery_mnemonic: Option<&'a str>,
    pub new_clawback_timelock: Option<u64>,
    pub new_word_count: MnemonicWordCount,
    pub network: Network,
    pub out_config: &'a Path,
}

pub async fn start<C>(
    client: &ChainClient<C>,
    params: StartWorkflow<'_>,
) -> Result<StartRecoveryResult>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    let resolved = resolve_vault(client, params.config, None).await?;
    if resolved.phase != VaultPhase::Ready {
        return Err(Error::msg(
            "vault is not in READY state; cannot start recovery",
        ));
    }

    let mut result = start_recovery(StartRecoveryParams {
        config: params.config,
        vault_coin: resolved.coin,
        lineage_proof: resolved.proof,
        recovery_mnemonic: params.recovery_mnemonic,
        new_custody_mnemonic: params.new_custody_mnemonic,
        new_recovery_mnemonic: params.new_recovery_mnemonic,
        new_clawback_timelock: params.new_clawback_timelock,
        new_word_count: params.new_word_count,
        network: params.network,
    })?;

    result.post_recovery_config.receive_address = params.config.receive_address.clone();
    result.post_recovery_config.save(params.out_config)?;
    client.push_tx(&result.spend_bundle).await?;
    Ok(result)
}

pub async fn finish<C>(
    client: &ChainClient<C>,
    config: &VaultConfig,
    post_recovery: &VaultConfig,
    network: Network,
) -> Result<FinishOutcome>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    with_deadline(
        INSPECT_DEADLINE,
        "finish",
        "; the node may be slow",
        finish_inner(client, config, post_recovery, network),
    )
    .await
}

async fn finish_inner<C>(
    client: &ChainClient<C>,
    config: &VaultConfig,
    post_recovery: &VaultConfig,
    network: Network,
) -> Result<FinishOutcome>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    let report = inspect_inner(client, config, Some(post_recovery)).await?;
    let pending_note = report.pending_note.clone();
    let action = match report.phase {
        VaultPhase::InRecovery => {
            let coin = report
                .on_chain_coin
                .ok_or_else(|| Error::msg("vault singleton not found on chain for this config"))?;
            let proof = client.lineage_proof_for_coin(&coin).await?;
            let bundle = finish_recovery(FinishRecoveryParams {
                config,
                post_recovery_config: post_recovery,
                vault_coin: coin,
                lineage_proof: proof,
                network,
            })?;
            FinishAction::Pushed(client.push_tx(&bundle).await?)
        }
        VaultPhase::Finished => FinishAction::AlreadyFinished,
        VaultPhase::ClawedBack => FinishAction::ClawedBack,
        VaultPhase::Ready | VaultPhase::Unknown => {
            return Err(Error::msg(
                "vault is not in RECOVERY state; cannot finish (did start confirm? is post-recovery config correct?)",
            ));
        }
    };
    Ok(FinishOutcome {
        action,
        pending_note,
    })
}

/// Lookup inputs beyond the vault address.
#[derive(Debug, Clone, Copy, Default)]
pub struct LookupOptions<'a> {
    /// Clawback seconds tried before the common Cloud Wallet values.
    pub extra_timelocks: &'a [u64],
    /// Opt-in launcher scan when nothing at the address reveals the launcher.
    pub scan: Option<&'a LauncherScan>,
}

/// Overall limit for the address lookup and its optional launcher scan.
pub const LOOKUP_DEADLINE: Duration = Duration::from_secs(30 * 60);
/// Overall limit for inspecting a vault and for finishing recovery.
pub const INSPECT_DEADLINE: Duration = Duration::from_secs(10 * 60);

async fn with_deadline<T>(
    limit: Duration,
    operation: &str,
    hint: &str,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(limit, work).await {
        Ok(result) => result,
        Err(_) => Err(Error::msg(format!(
            "{operation} did not finish within {} minutes{hint}",
            limit.as_secs() / 60
        ))),
    }
}

/// Result of looking up a vault from its receive address (or launcher id).
///
/// A hint is a finished public layout. A found vault still needs
/// [`crate::discover::reconstruct`] at Start.
#[derive(Debug, Clone)]
pub enum LookupReport {
    Ready(VaultLookup),
    NeedFallback(LookupGap),
}

/// Layout ready to sign, either from the hint or from custody reconstruction.
#[derive(Debug, Clone)]
pub enum PreparedStart {
    Hinted(VaultConfig),
    Reconstructed(Box<ReconstructedVault>),
}

impl PreparedStart {
    pub fn config(&self) -> &VaultConfig {
        match self {
            Self::Hinted(config) => config,
            Self::Reconstructed(rebuilt) => &rebuilt.config,
        }
    }
}

/// Start from the cached hint, or reconstruct when the cache holds a custody spend.
pub fn prepare_start(
    cache: &mut LookupCache,
    address: &str,
    recovery_mnemonic: &str,
    typed_clawback: Option<u64>,
) -> Result<PreparedStart> {
    let recorded = Some(address.trim().to_string());
    match cache.require(address)?.lookup {
        VaultLookup::Hinted(mut config) => {
            confirm_hinted_config(&config, Some(recovery_mnemonic), typed_clawback)?;
            config.receive_address = recorded;
            Ok(PreparedStart::Hinted(config))
        }
        VaultLookup::Found(found, clawback) => {
            let mut rebuilt = reconstruct(
                &found,
                recovery_mnemonic,
                clawback.with_typed(typed_clawback),
            )?;
            cache.persist_guess(
                address,
                ClawbackGuess::Known(rebuilt.config.recovery.clawback_timelock),
            )?;
            rebuilt.config.receive_address = recorded;
            Ok(PreparedStart::Reconstructed(Box::new(rebuilt)))
        }
    }
}

/// Use a cached lookup when the address matches; otherwise look up and persist.
pub async fn resolve_found<C>(
    client: &ChainClient<C>,
    cache: &mut LookupCache,
    vault: &str,
    network: Network,
    options: LookupOptions<'_>,
) -> Result<LookupReport>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    if let Some(cached) = cache.matching(vault) {
        return Ok(LookupReport::Ready(cached.lookup.clone()));
    }
    let report = lookup(client, vault, options).await?;
    persist_report(cache, vault, network, &report)?;
    Ok(report)
}

/// Address-first lookup. The parent spend is the only hint source.
///
/// `options.extra_timelocks` are tried before the common Cloud Wallet values.
/// Seconds outside that set are not recovered from the hint. `options.scan` opts in
/// to checking every launcher in a block range when no spend reveals the launcher
/// (a never-spent vault). The whole launcher resolve, scan, and hint read share one
/// deadline.
pub async fn lookup<C>(
    client: &ChainClient<C>,
    vault: &str,
    options: LookupOptions<'_>,
) -> Result<LookupReport>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    lookup_within(LOOKUP_DEADLINE, client, vault, options).await
}

pub(crate) async fn lookup_within<C>(
    limit: Duration,
    client: &ChainClient<C>,
    vault: &str,
    options: LookupOptions<'_>,
) -> Result<LookupReport>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    with_deadline(
        limit,
        "lookup",
        "; the node may be slow, or narrow the launcher scan range",
        lookup_inner(client, vault, options),
    )
    .await
}

async fn lookup_inner<C>(
    client: &ChainClient<C>,
    vault: &str,
    options: LookupOptions<'_>,
) -> Result<LookupReport>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    let locator = parse_vault_locator(vault)?;
    let resolved = match resolve_launcher_id(client, &locator, options.scan).await? {
        Ok(resolved) => resolved,
        Err(gap) => return Ok(LookupReport::NeedFallback(gap)),
    };

    let (spent, current) = client.walk_singleton_chain(resolved.launcher_id).await?;
    let ancestor_puzzle_hashes: Vec<chia_protocol::Bytes32> =
        spent.iter().map(|r| r.coin.puzzle_hash).collect();
    let candidates = timelock_candidates(options.extra_timelocks);

    if let Some(config) =
        hinted_config_from_parent(client, resolved.launcher_id, &current, &candidates).await?
    {
        return Ok(LookupReport::Ready(VaultLookup::Hinted(config)));
    }

    let mut custody = None;
    for record in spent.iter().rev() {
        let Some(spend) = client
            .get_spend(record.coin.coin_id(), record.spent_block_index)
            .await?
        else {
            continue;
        };
        if let Some(path) = custody_from_vault_spend(&spend)? {
            custody = Some(path);
            break;
        }
    }

    Ok(classify_lookup(
        resolved.launcher_id,
        resolved.source,
        current.coin,
        ancestor_puzzle_hashes,
        custody,
    ))
}

fn persist_report(
    cache: &mut LookupCache,
    vault: &str,
    network: Network,
    report: &LookupReport,
) -> Result<()> {
    if let LookupReport::Ready(lookup) = report {
        cache.persist(vault, network, lookup.clone())?;
    }
    Ok(())
}

fn timelock_candidates(extra: &[u64]) -> Vec<u64> {
    let mut out = extra.to_vec();
    for &secs in DEFAULT_TIMELOCK_CANDIDATES {
        if !out.contains(&secs) {
            out.push(secs);
        }
    }
    out
}

async fn hinted_config_from_parent<C>(
    client: &ChainClient<C>,
    launcher_id: chia_protocol::Bytes32,
    current: &chia_sdk_coinset::CoinRecord,
    timelock_candidates: &[u64],
) -> Result<Option<VaultConfig>>
where
    C: ChiaRpcClient,
    C::Error: Display,
{
    let Some(parent) = client
        .get_coin_record(current.coin.parent_coin_info)
        .await?
    else {
        return Ok(None);
    };
    if !parent.spent {
        return Ok(None);
    }
    let Some(spend) = client
        .get_spend(parent.coin.coin_id(), parent.spent_block_index)
        .await?
    else {
        return Ok(None);
    };
    Ok(hinted_config_from_spend(
        &spend,
        launcher_id,
        current.coin.puzzle_hash,
        timelock_candidates,
    ))
}

pub(crate) fn classify_lookup(
    launcher_id: chia_protocol::Bytes32,
    launcher_source: String,
    current_coin: chia_protocol::Coin,
    ancestor_puzzle_hashes: Vec<chia_protocol::Bytes32>,
    custody: Option<crate::discover::DiscoveredCustodyPath>,
) -> LookupReport {
    if ancestor_puzzle_hashes.is_empty() {
        return LookupReport::NeedFallback(LookupGap::SingletonNeverSpent(KnownLauncher {
            id: launcher_id,
            source: launcher_source,
        }));
    }
    match custody {
        Some(custody) => LookupReport::Ready(VaultLookup::Found(
            FoundVault {
                launcher_id,
                launcher_source,
                custody,
                current_coin,
                ancestor_puzzle_hashes,
            },
            ClawbackGuess::Unknown,
        )),
        None => LookupReport::NeedFallback(LookupGap::NoCustodySpend(KnownLauncher {
            id: launcher_id,
            source: launcher_source,
        })),
    }
}

#[cfg(test)]
mod tests {
    use chia_protocol::{Bytes32, Coin};
    use clvm_utils::TreeHash;

    use super::*;
    use crate::cache::LookupCache;
    use crate::discover::DiscoveredCustodyPath;
    use crate::test_rpc::NeverRpc;

    fn coin() -> Coin {
        Coin::new(Bytes32::new([0x01; 32]), Bytes32::new([0x02; 32]), 1)
    }

    fn custody() -> DiscoveredCustodyPath {
        DiscoveredCustodyPath {
            custody_hash: TreeHash::from(Bytes32::new([0x03; 32])),
            members: vec![],
            vault_launcher_ids: vec![],
        }
    }

    #[tokio::test]
    async fn lookup_deadline_reports_a_clear_error() {
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            with_deadline(
                Duration::from_millis(10),
                "lookup",
                "",
                std::future::pending::<Result<()>>(),
            ),
        )
        .await
        .expect("with_deadline should apply its limit")
        .unwrap_err();
        assert!(err.to_string().contains("did not finish within"), "{err}");
    }

    #[tokio::test]
    async fn lookup_applies_the_deadline_to_the_whole_lookup() {
        let client = ChainClient::with_rpc(NeverRpc);
        let vault = format!("0x{}", hex::encode([0x11; 32]));
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            lookup_within(
                Duration::from_millis(10),
                &client,
                &vault,
                LookupOptions::default(),
            ),
        )
        .await
        .expect("lookup_within should apply its deadline")
        .unwrap_err();
        assert!(err.to_string().contains("did not finish within"), "{err}");
    }

    #[test]
    fn classify_empty_ancestors_is_never_spent() {
        let launcher = Bytes32::new([0xaa; 32]);
        match classify_lookup(launcher, "test".into(), coin(), vec![], Some(custody())) {
            LookupReport::NeedFallback(LookupGap::SingletonNeverSpent(known)) => {
                assert_eq!(known.id, launcher);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn classify_spent_without_custody_needs_fallback() {
        match classify_lookup(
            Bytes32::new([0xaa; 32]),
            "test".into(),
            coin(),
            vec![Bytes32::new([0x04; 32])],
            None,
        ) {
            LookupReport::NeedFallback(LookupGap::NoCustodySpend(_)) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn prepare_start_requires_cached_vault() {
        let path = std::env::temp_dir().join(format!(
            "cvr-workflow-unbound-{}-{}.json",
            std::process::id(),
            "prepare"
        ));
        let _ = std::fs::remove_file(&path);
        let mut cache = LookupCache::open_at(&path);
        let err = prepare_start(&mut cache, "xch1abc", "abandon abandon", None).unwrap_err();
        assert!(err.to_string().contains("look up"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn classify_custody_is_found() {
        match classify_lookup(
            Bytes32::new([0xaa; 32]),
            "address xch1…".into(),
            coin(),
            vec![Bytes32::new([0x04; 32])],
            Some(custody()),
        ) {
            LookupReport::Ready(VaultLookup::Found(found, _)) => {
                assert_eq!(found.launcher_source, "address xch1…");
                assert!(!found.custody.members_complete());
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
