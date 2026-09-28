//! On-disk lookup cache shared by the GUI and CLI.
//!
//! One current lookup. The recovery phrase is never written. A hinted layout
//! stores the clawback from the on-chain memo. A custody-spend lookup stores a
//! clawback guess only when the user supplies one. Missing or unreadable files
//! are treated as empty.

use std::fs;
use std::path::{Path, PathBuf};

use chia_protocol::{Bytes32, Coin};
use clvm_utils::TreeHash;
use serde::{Deserialize, Serialize};

use crate::config::{
    VaultConfig, VaultConfigMember, config_members_from_keys, keys_from_config_members,
    parse_bytes32,
};
use crate::discover::{ClawbackGuess, DiscoveredCustodyPath, FoundVault};
use crate::error::{Error, Result};
use crate::network::Network;

const CACHE_ENV: &str = "CHIA_VAULT_RECOVER_CACHE";
const DIR_ENV: &str = "CHIA_VAULT_RECOVER_DIR";

/// Directory for the lookup cache, GUI session, and default vault-config files.
///
/// Override with `CHIA_VAULT_RECOVER_DIR`. Otherwise `~/.chia-vault-recover`
/// (or `.chia-vault-recover` under the process home fallback).
///
/// Independent of [`CACHE_ENV`], which only relocates the lookup-cache file.
pub fn app_dir() -> PathBuf {
    if let Ok(path) = std::env::var(DIR_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    home_dir().join(".chia-vault-recover")
}

/// A successful lookup. The clawback guess exists only for a custody-spend vault.
#[derive(Debug, Clone)]
pub enum VaultLookup {
    Hinted(VaultConfig),
    Found(FoundVault, ClawbackGuess),
}

impl VaultLookup {
    pub fn launcher_id(&self) -> Result<Bytes32> {
        match self {
            Self::Hinted(config) => config.launcher_id_bytes(),
            Self::Found(found, _) => Ok(found.launcher_id),
        }
    }

    /// Seconds to show. A hint uses the config. A custody spend uses its guess.
    pub fn clawback(&self) -> ClawbackGuess {
        match self {
            Self::Hinted(config) => ClawbackGuess::Known(config.recovery.clawback_timelock),
            Self::Found(_, guess) => *guess,
        }
    }

    fn replace_found(self, found: FoundVault) -> Self {
        let guess = match &self {
            Self::Found(existing, guess) if existing.launcher_id == found.launcher_id => *guess,
            _ => ClawbackGuess::Unknown,
        };
        Self::Found(found, guess)
    }
}

/// The last successful lookup.
#[derive(Debug, Clone)]
pub struct CachedLookup {
    pub receive_address: String,
    pub network: Network,
    pub lookup: VaultLookup,
}

impl CachedLookup {
    pub fn new(address: &str, network: Network, lookup: VaultLookup) -> Self {
        Self {
            receive_address: address.trim().to_string(),
            network,
            lookup,
        }
    }

    pub fn launcher_id(&self) -> Result<Bytes32> {
        self.lookup.launcher_id()
    }

    /// Replace a custody-spend lookup. Keeps a clawback guess only when the launcher is unchanged.
    pub fn replace_found(self, address: &str, network: Network, found: FoundVault) -> Self {
        Self {
            receive_address: address.trim().to_string(),
            network,
            lookup: self.lookup.replace_found(found),
        }
    }

    fn matches_address(&self, address: &str) -> bool {
        addresses_match(&self.receive_address, address)
    }
}

/// True when two receive addresses name the same vault (trim + case).
fn addresses_match(left: &str, right: &str) -> bool {
    cache_key(left) == cache_key(right)
}

/// Single-vault lookup cache.
pub struct LookupCache {
    path: PathBuf,
    entry: Option<CachedLookup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CacheFile {
    receive_address: String,
    network: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    launcher_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    launcher_source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    custody_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    custody_members: Vec<VaultConfigMember>,
    #[serde(default, skip_serializing_if = "CoinRecord::is_blank")]
    current_coin: CoinRecord,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ancestor_puzzle_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hinted_config: Option<VaultConfig>,
    #[serde(default, skip_serializing_if = "ClawbackGuess::is_unknown")]
    clawback: ClawbackGuess,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoinRecord {
    #[serde(default)]
    parent_coin_info: String,
    #[serde(default)]
    puzzle_hash: String,
    #[serde(default)]
    amount: u64,
}

impl CoinRecord {
    fn is_blank(&self) -> bool {
        self.parent_coin_info.is_empty() && self.puzzle_hash.is_empty()
    }
}

impl LookupCache {
    pub fn default_path() -> PathBuf {
        if let Ok(path) = std::env::var(CACHE_ENV) {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
        app_dir().join("lookup-cache.json")
    }

    pub fn open() -> Self {
        Self::open_at(Self::default_path())
    }

    pub fn open_at(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let entry = fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<CacheFile>(&text).ok())
            .and_then(|file| file.into_cached().ok());
        Self { path, entry }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn current(&self) -> Option<&CachedLookup> {
        self.entry.as_ref()
    }

    pub fn matching(&self, address: &str) -> Option<&CachedLookup> {
        self.entry
            .as_ref()
            .filter(|entry| entry.matches_address(address))
    }

    pub fn store(&mut self, entry: CachedLookup) -> Result<()> {
        let file = CacheFile::from_cached(&entry);
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_string_pretty(&file)?)?;
        self.entry = Some(entry);
        Ok(())
    }

    pub(crate) fn require(&self, address: &str) -> Result<CachedLookup> {
        self.matching(address)
            .cloned()
            .ok_or_else(|| Error::msg("no cached lookup for this address; look up the vault first"))
    }

    /// Store a successful lookup. A new custody spend keeps a clawback guess when the launcher is unchanged.
    pub fn persist(
        &mut self,
        address: &str,
        network: Network,
        lookup: VaultLookup,
    ) -> Result<CachedLookup> {
        let entry = match (&lookup, self.matching(address)) {
            (VaultLookup::Found(found, _), Some(existing)) => {
                existing
                    .clone()
                    .replace_found(address, network, found.clone())
            }
            _ => CachedLookup::new(address, network, lookup),
        };
        self.store(entry.clone())?;
        Ok(entry)
    }

    /// Update the clawback guess on a cached custody spend.
    pub fn persist_guess(
        &mut self,
        address: &str,
        clawback: ClawbackGuess,
    ) -> Result<CachedLookup> {
        let mut entry = self.require(address)?;
        let VaultLookup::Found(found, _) = entry.lookup else {
            return Err(Error::msg(
                "cached lookup is an on-chain hint; its clawback comes from that layout",
            ));
        };
        entry.lookup = VaultLookup::Found(found, clawback);
        self.store(entry.clone())?;
        Ok(entry)
    }
}

fn cache_key(address: &str) -> String {
    address.trim().to_ascii_lowercase()
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn hex_id(id: &Bytes32) -> String {
    format!("0x{}", hex::encode(id))
}

impl CacheFile {
    fn from_cached(entry: &CachedLookup) -> Self {
        let base = Self {
            receive_address: entry.receive_address.clone(),
            network: entry.network.as_str().to_string(),
            launcher_id: String::new(),
            launcher_source: String::new(),
            custody_hash: String::new(),
            custody_members: Vec::new(),
            current_coin: CoinRecord {
                parent_coin_info: String::new(),
                puzzle_hash: String::new(),
                amount: 0,
            },
            ancestor_puzzle_hashes: Vec::new(),
            hinted_config: None,
            clawback: ClawbackGuess::Unknown,
        };
        match &entry.lookup {
            VaultLookup::Hinted(config) => Self {
                hinted_config: Some(config.clone()),
                ..base
            },
            VaultLookup::Found(found, guess) => Self {
                clawback: *guess,
                launcher_id: hex_id(&found.launcher_id),
                launcher_source: found.launcher_source.clone(),
                custody_hash: format!("0x{}", hex::encode(found.custody.custody_hash)),
                custody_members: config_members_from_keys(
                    &found.custody.members,
                    &found.custody.vault_launcher_ids,
                ),
                current_coin: CoinRecord {
                    parent_coin_info: hex_id(&found.current_coin.parent_coin_info),
                    puzzle_hash: hex_id(&found.current_coin.puzzle_hash),
                    amount: found.current_coin.amount,
                },
                ancestor_puzzle_hashes: found.ancestor_puzzle_hashes.iter().map(hex_id).collect(),
                ..base
            },
        }
    }

    fn into_cached(self) -> Result<CachedLookup> {
        let network = Network::parse(&self.network).ok_or_else(|| {
            Error::msg(format!("lookup cache has unknown network {}", self.network))
        })?;
        if let Some(config) = self.hinted_config {
            return Ok(CachedLookup::new(
                &self.receive_address,
                network,
                VaultLookup::Hinted(config),
            ));
        }
        let (members, vault_launcher_ids) = keys_from_config_members(&self.custody_members)?;
        let mut ancestor_puzzle_hashes = Vec::new();
        for ph in &self.ancestor_puzzle_hashes {
            ancestor_puzzle_hashes.push(parse_bytes32(ph)?);
        }
        Ok(CachedLookup::new(
            &self.receive_address,
            network,
            VaultLookup::Found(
                FoundVault {
                    launcher_id: parse_bytes32(&self.launcher_id)?,
                    launcher_source: self.launcher_source,
                    custody: DiscoveredCustodyPath {
                        custody_hash: TreeHash::from(parse_bytes32(&self.custody_hash)?),
                        members,
                        vault_launcher_ids,
                    },
                    current_coin: Coin::new(
                        parse_bytes32(&self.current_coin.parent_coin_info)?,
                        parse_bytes32(&self.current_coin.puzzle_hash)?,
                        self.current_coin.amount,
                    ),
                    ancestor_puzzle_hashes,
                },
                self.clawback,
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Bytes32;
    use clvm_utils::TreeHash;

    fn found(launcher: u8) -> FoundVault {
        FoundVault {
            launcher_id: Bytes32::new([launcher; 32]),
            launcher_source: "address xch1test".into(),
            custody: DiscoveredCustodyPath {
                custody_hash: TreeHash::from(Bytes32::new([0x11; 32])),
                members: vec![],
                vault_launcher_ids: vec![],
            },
            current_coin: Coin::new(Bytes32::new([0x22; 32]), Bytes32::new([0x33; 32]), 1),
            ancestor_puzzle_hashes: vec![Bytes32::new([0x33; 32])],
        }
    }

    fn temp_path() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cvr-lookup-cache-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn roundtrip_found_without_clawback() {
        let path = temp_path();
        let mut cache = LookupCache::open_at(&path);
        cache
            .store(CachedLookup::new(
                "XCH1ABC",
                Network::Mainnet,
                VaultLookup::Found(found(0xaa), ClawbackGuess::Unknown),
            ))
            .unwrap();
        drop(cache);

        let loaded = LookupCache::open_at(&path);
        let entry = loaded.matching("xch1abc").expect("cached");
        assert_eq!(entry.receive_address, "XCH1ABC");
        assert_eq!(entry.network, Network::Mainnet);
        assert_eq!(entry.launcher_id().unwrap(), Bytes32::new([0xaa; 32]));
        assert_eq!(entry.lookup.clawback(), ClawbackGuess::Unknown);
        assert!(!fs::read_to_string(&path).unwrap().contains("mnemonic"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn store_replaces_the_only_entry() {
        let path = temp_path();
        let mut cache = LookupCache::open_at(&path);
        cache
            .store(CachedLookup::new(
                "xch1aaa",
                Network::Mainnet,
                VaultLookup::Found(found(0xaa), ClawbackGuess::Unknown),
            ))
            .unwrap();
        cache
            .store(CachedLookup::new(
                "txch1bbb",
                Network::Testnet11,
                VaultLookup::Found(found(0xbb), ClawbackGuess::Unknown),
            ))
            .unwrap();
        let current = cache.current().unwrap();
        assert_eq!(current.receive_address, "txch1bbb");
        assert!(cache.matching("xch1aaa").is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn addresses_match_trims_and_ignores_case() {
        assert!(addresses_match("  XCH1ABC  ", "xch1abc"));
        assert!(!addresses_match("xch1abc", "xch1abd"));
    }

    #[test]
    fn persist_found_keeps_clawback_for_same_launcher() {
        let path = temp_path();
        let mut cache = LookupCache::open_at(&path);
        cache
            .persist(
                "xch1abc",
                Network::Mainnet,
                VaultLookup::Found(found(0xaa), ClawbackGuess::Unknown),
            )
            .unwrap();
        cache
            .persist_guess("xch1abc", ClawbackGuess::Known(43_200))
            .unwrap();
        cache
            .persist(
                "xch1abc",
                Network::Mainnet,
                VaultLookup::Found(found(0xaa), ClawbackGuess::Unknown),
            )
            .unwrap();
        assert_eq!(
            cache.current().unwrap().lookup.clawback(),
            ClawbackGuess::Known(43_200)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persist_guess_refuses_unbound_address() {
        let path = temp_path();
        let mut cache = LookupCache::open_at(&path);
        cache
            .persist(
                "xch1abc",
                Network::Mainnet,
                VaultLookup::Found(found(0xaa), ClawbackGuess::Unknown),
            )
            .unwrap();
        let err = cache
            .persist_guess("xch1other", ClawbackGuess::Hint(1))
            .unwrap_err();
        assert!(err.to_string().contains("look up"));
        assert!(cache.matching("xch1other").is_none());
        assert_eq!(cache.current().unwrap().receive_address, "xch1abc");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn replace_found_keeps_clawback_for_same_launcher() {
        let kept = CachedLookup::new(
            "xch1abc",
            Network::Mainnet,
            VaultLookup::Found(found(0xaa), ClawbackGuess::Known(43_200)),
        )
        .replace_found("xch1abc", Network::Mainnet, found(0xaa));
        assert_eq!(kept.lookup.clawback(), ClawbackGuess::Known(43_200));

        let cleared = CachedLookup::new(
            "xch1abc",
            Network::Mainnet,
            VaultLookup::Found(found(0xaa), ClawbackGuess::Known(43_200)),
        )
        .replace_found("xch1abc", Network::Mainnet, found(0xbb));
        assert_eq!(cleared.lookup.clawback(), ClawbackGuess::Unknown);
    }

    #[test]
    fn unreadable_file_is_empty() {
        let path = temp_path();
        fs::write(&path, "{not json").unwrap();
        assert!(LookupCache::open_at(&path).current().is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn default_path_uses_dot_dir_under_home() {
        if std::env::var(CACHE_ENV)
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
            || std::env::var(DIR_ENV)
                .ok()
                .is_some_and(|value| !value.trim().is_empty())
        {
            return;
        }
        let path = LookupCache::default_path();
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("lookup-cache.json")
        );
        assert_eq!(
            path.parent()
                .and_then(|parent| parent.file_name())
                .and_then(|name| name.to_str()),
            Some(".chia-vault-recover")
        );
        assert_eq!(path.parent().map(PathBuf::from), Some(app_dir()));
    }
}
