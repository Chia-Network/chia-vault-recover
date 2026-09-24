//! End-to-end recovery workflows shared by CLI and GUI.

use std::path::Path;

use chia_protocol::Coin;
use chia_puzzle_types::Proof;
use clvm_utils::TreeHash;

use crate::cache::LookupCache;
use crate::chain::ChainClient;
use crate::config::VaultConfig;
use crate::discover::{
    ClawbackGuess, DEFAULT_TIMELOCK_CANDIDATES, FoundVault,
    ReconstructedVault, confirm_hinted_config, custody_from_vault_spend, reconstruct,
};
use crate::error::{Error, Result};
use crate::guidance::{KnownLauncher, LookupGap};
use crate::hint::hinted_config_from_spend;
use crate::keys::MnemonicWordCount;
use crate::locate::{parse_vault_locator, resolve_launcher_id};
use crate::network::Network;
use crate::recovery::{
    FinishRecoveryParams, InspectReport, StartRecoveryParams, StartRecoveryResult, VaultPhase,
    finish_recovery, inspect_vault, start_recovery,
};
use crate::vault::{get_vault_internals, recovery_state_hashes};

#[derive(Debug, Clone)]
pub struct ResolvedVault {
    pub coin: Coin,
    pub proof: Proof,
    pub phase: VaultPhase,
}

/// Find the unspent vault singleton and its lineage proof.
///
/// If `post_recovery` is set, also checks the expected RECOVERY puzzle hash when READY is absent.
pub async fn resolve_vault(
    client: &ChainClient,
    config: &VaultConfig,
    post_recovery: Option<&VaultConfig>,
) -> Result<ResolvedVault> {
    let launcher_id = config.launcher_id_bytes()?;
    let keys = config.to_vault_keys()?;
    let ready = get_vault_internals(launcher_id, &keys)?;

    if let Some(coin) = client
        .find_unspent_by_puzzle_hash(ready.full_puzzle_hash)
        .await?
    {
        let proof = client.lineage_proof_for_coin(&coin).await?;
        return Ok(ResolvedVault {
            coin,
            proof,
            phase: VaultPhase::Ready,
        });
    }

    if let Some(post) = post_recovery {
        let post_ready = get_vault_internals(launcher_id, &post.to_vault_keys()?)?;
        // Prefer coin.amount when we find it; for lookup we try amount=1 first (vault singleton).
        let hashes = recovery_state_hashes(launcher_id, &keys, post_ready.inner_puzzle_hash, 1)?;
        if let Some(coin) = client
            .find_unspent_by_puzzle_hash(hashes.internals.full_puzzle_hash)
            .await?
        {
            // Recompute with actual amount if it differs (rare for vaults).
            let hashes = if coin.amount != 1 {
                recovery_state_hashes(
                    launcher_id,
                    &keys,
                    post_ready.inner_puzzle_hash,
                    coin.amount,
                )?
            } else {
                hashes
            };
            if coin.puzzle_hash != hashes.internals.full_puzzle_hash {
                return Err(Error::msg(
                    "found coin amount implies a different RECOVERY puzzle hash",
                ));
            }
            let proof = client.lineage_proof_for_coin(&coin).await?;
            return Ok(ResolvedVault {
                coin,
                proof,
                phase: VaultPhase::InRecovery,
            });
        }
    }

    Err(Error::msg(
        "vault singleton not found on chain (checked READY; checked RECOVERY if post-recovery config given)",
    ))
}

pub async fn inspect(
    client: &ChainClient,
    config: &VaultConfig,
    post_recovery: Option<&VaultConfig>,
) -> Result<InspectReport> {
    let launcher_id = config.launcher_id_bytes()?;
    let keys = config.to_vault_keys()?;
    let ready = get_vault_internals(launcher_id, &keys)?;

    let mut coin = client
        .find_unspent_by_puzzle_hash(ready.full_puzzle_hash)
        .await?;

    let post_inner: Option<TreeHash> = if let Some(post) = post_recovery {
        let post_ready = get_vault_internals(launcher_id, &post.to_vault_keys()?)?;
        if coin.is_none() {
            let amount = 1u64;
            let hashes =
                recovery_state_hashes(launcher_id, &keys, post_ready.inner_puzzle_hash, amount)?;
            coin = client
                .find_unspent_by_puzzle_hash(hashes.internals.full_puzzle_hash)
                .await?;
        }
        Some(post_ready.inner_puzzle_hash)
    } else {
        None
    };

    inspect_vault(config, coin, post_inner)
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

pub async fn start(client: &ChainClient, params: StartWorkflow<'_>) -> Result<StartRecoveryResult> {
    let resolved = resolve_vault(client, params.config, None).await?;
    if resolved.phase != VaultPhase::Ready {
        return Err(Error::msg(
            "vault is not in READY state; cannot start recovery",
        ));
    }

    let result = start_recovery(StartRecoveryParams {
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

    result.post_recovery_config.save(params.out_config)?;
    client.push_tx(&result.spend_bundle).await?;
    Ok(result)
}

pub async fn finish(
    client: &ChainClient,
    config: &VaultConfig,
    post_recovery: &VaultConfig,
    network: Network,
) -> Result<String> {
    let resolved = resolve_vault(client, config, Some(post_recovery)).await?;
    if resolved.phase != VaultPhase::InRecovery {
        return Err(Error::msg(
            "vault is not in RECOVERY state; cannot finish (did start confirm? is post-recovery config correct?)",
        ));
    }

    let bundle = finish_recovery(FinishRecoveryParams {
        config,
        post_recovery_config: post_recovery,
        vault_coin: resolved.coin,
        lineage_proof: resolved.proof,
        network,
    })?;
    client.push_tx(&bundle).await
}

/// Result of looking up a vault from its receive address (or launcher id).
///
/// A hint is a finished public layout. A found vault still needs
/// [`crate::discover::reconstruct`] at Start.
#[derive(Debug, Clone)]
pub enum LookupReport {
    Hinted(VaultConfig),
    Found(FoundVault),
    NeedFallback(LookupGap),
}

/// Layout ready to sign, either from the hint or from custody reconstruction.
#[derive(Debug, Clone)]
pub enum PreparedStart {
    Hinted(VaultConfig),
    Reconstructed(ReconstructedVault),
}

impl PreparedStart {
    pub fn config(&self) -> &VaultConfig {
        match self {
            Self::Hinted(config) => config,
            Self::Reconstructed(rebuilt) => &rebuilt.config,
        }
    }
}

/// Rebuild the public layout from a cached custody-spend vault and persist the verified clawback.
pub fn rebuild_for_start(
    cache: &mut LookupCache,
    address: &str,
    recovery_mnemonic: &str,
    typed_clawback: Option<u64>,
) -> Result<ReconstructedVault> {
    let entry = cache.require_found(address)?;
    let rebuilt = reconstruct(
        &entry.found,
        recovery_mnemonic,
        entry.clawback.with_typed(typed_clawback),
    )?;
    cache.persist_guess(
        address,
        ClawbackGuess::Known(rebuilt.config.recovery.clawback_timelock),
    )?;
    Ok(rebuilt)
}

/// Start from the cached hint, or reconstruct when the cache holds a custody spend.
pub fn prepare_start(
    cache: &mut LookupCache,
    address: &str,
    recovery_mnemonic: &str,
    typed_clawback: Option<u64>,
) -> Result<PreparedStart> {
    let entry = cache.require(address)?;
    match entry.layout {
        crate::cache::CachedLayout::Hinted(config) => {
            confirm_hinted_config(&config, Some(recovery_mnemonic), typed_clawback)?;
            Ok(PreparedStart::Hinted(config))
        }
        crate::cache::CachedLayout::Found(_) => Ok(PreparedStart::Reconstructed(
            rebuild_for_start(cache, address, recovery_mnemonic, typed_clawback)?,
        )),
    }
}

/// Use a cached lookup when the address matches; otherwise look up and persist.
pub async fn resolve_found(
    client: &ChainClient,
    cache: &mut LookupCache,
    vault: &str,
    network: Network,
    extra_timelocks: &[u64],
) -> Result<LookupReport> {
    if let Some(cached) = cache.matching(vault) {
        return Ok(match &cached.layout {
            crate::cache::CachedLayout::Hinted(config) => LookupReport::Hinted(config.clone()),
            crate::cache::CachedLayout::Found(found) => LookupReport::Found(found.clone()),
        });
    }
    let report = lookup(client, vault, extra_timelocks).await?;
    persist_report(cache, vault, network, &report)?;
    Ok(report)
}

/// Address-first lookup. The parent spend is the only hint source.
///
/// `extra_timelocks` are tried before the common Cloud Wallet values. Seconds
/// outside that set are not recovered from the hint.
pub async fn lookup(
    client: &ChainClient,
    vault: &str,
    extra_timelocks: &[u64],
) -> Result<LookupReport> {
    let locator = parse_vault_locator(vault)?;
    let Some(resolved) = resolve_launcher_id(client, &locator).await? else {
        return Ok(LookupReport::NeedFallback(LookupGap::LauncherNotFound));
    };

    let (spent, current) = client.walk_singleton_chain(resolved.launcher_id).await?;
    let ancestor_puzzle_hashes: Vec<chia_protocol::Bytes32> =
        spent.iter().map(|r| r.coin.puzzle_hash).collect();
    let candidates = timelock_candidates(extra_timelocks);

    if let Some(config) =
        hinted_config_from_parent(client, resolved.launcher_id, &current, &candidates).await?
    {
        return Ok(LookupReport::Hinted(config));
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
    match report {
        LookupReport::Hinted(config) => {
            cache.persist_hinted(vault, network, config.clone())?;
        }
        LookupReport::Found(found) => {
            cache.persist_found(vault, network, found.clone())?;
        }
        LookupReport::NeedFallback(_) => {}
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

async fn hinted_config_from_parent(
    client: &ChainClient,
    launcher_id: chia_protocol::Bytes32,
    current: &chia_sdk_coinset::CoinRecord,
    timelock_candidates: &[u64],
) -> Result<Option<VaultConfig>> {
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
        Some(custody) => LookupReport::Found(FoundVault {
            launcher_id,
            launcher_source,
            custody,
            current_coin,
            ancestor_puzzle_hashes,
        }),
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
    fn rebuild_for_start_requires_cached_vault() {
        let path = std::env::temp_dir().join(format!(
            "cvr-workflow-unbound-{}-{}.json",
            std::process::id(),
            "rebuild"
        ));
        let _ = std::fs::remove_file(&path);
        let mut cache = LookupCache::open_at(&path);
        let err = rebuild_for_start(&mut cache, "xch1abc", "abandon abandon", None).unwrap_err();
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
            LookupReport::Found(found) => {
                assert_eq!(found.launcher_source, "address xch1…");
                assert!(!found.custody.members_complete());
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
