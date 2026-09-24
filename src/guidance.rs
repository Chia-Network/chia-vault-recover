//! End-user guidance for the address-first lookup flow.

use chia_protocol::Bytes32;

/// Launcher known from a successful resolve (not from the address alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownLauncher {
    pub id: Bytes32,
    pub source: String,
}

/// Why chain lookup could not rebuild the vault layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupGap {
    /// Address unused, never spent, or parent spends did not reveal a launcher.
    LauncherNotFound,
    /// Launcher is known but the singleton has never been spent (eve only).
    SingletonNeverSpent(KnownLauncher),
    /// Singleton spends exist but none used the current custody path.
    NoCustodySpend(KnownLauncher),
}

impl LookupGap {
    pub fn headline(&self) -> &'static str {
        match self {
            Self::LauncherNotFound => {
                "Could not find this vault’s launcher id from the address alone."
            }
            Self::SingletonNeverSpent(_) => {
                "Found the launcher, but this vault has never been spent with the current setup."
            }
            Self::NoCustodySpend(_) => {
                "Found the launcher, but no previous custody spend is on chain."
            }
        }
    }

    pub fn detail(&self) -> &'static str {
        match self {
            Self::LauncherNotFound => {
                "A Cloud Wallet receive address does not contain the launcher id. \
                 The tool can only recover it from a spent coin at that address \
                 (or from a parent vault spend)."
            }
            Self::SingletonNeverSpent(_) => {
                "An unspent eve singleton has no Cloud Wallet recovery hint yet. \
                 One send from the vault publishes that hint."
            }
            Self::NoCustodySpend(_) => {
                "This vault has no Cloud Wallet recovery hint and no custody spend. \
                 A send that uses the vault’s passkey or Chia Signer App publishes the hint."
            }
        }
    }

    pub fn known_launcher(&self) -> Option<&KnownLauncher> {
        match self {
            Self::LauncherNotFound => None,
            Self::SingletonNeverSpent(launcher) | Self::NoCustodySpend(launcher) => Some(launcher),
        }
    }
}

/// What to do when the chain has no recovery hint and no custody spend.
pub fn fallback_guidance(gap: &LookupGap) -> String {
    format!("{}\n{}\n\n{}", gap.headline(), gap.detail(), FALLBACK_STEPS)
}

pub const FALLBACK_STEPS: &str = "\
Recovery uses the on-chain hint Cloud Wallet writes onto the vault singleton.

If you can still open this vault at https://vault.chia.net:

Send any amount from the vault back to the same Receive address (or any address \
you control). A self-send is enough. Cloud Wallet spends the vault singleton with \
your passkey or the Chia Signer App, which publishes the recovery hint. Wait \
until that transaction confirms, then look up the same address again.

If you cannot access Cloud Wallet and the hint is not on chain, this tool cannot \
recover the vault from the address alone.";

pub const RECONSTRUCT_SUCCESS: &str =
    "Vault layout rebuilt from the previous custody spend and recovery phrase.";

/// Address-only lookup succeeded from the on-chain hint.
pub const LOOKUP_FROM_HINT: &str = "\
This vault can be recovered from the on-chain hint. The public layout and \
clawback timelock were read from the Cloud Wallet memo. The lookup is saved \
on disk. The recovery phrase is only needed to Start recovery, and it is never \
written to disk.";

/// Address-only lookup succeeded from a custody spend, without the hint.
pub const LOOKUP_CAN_RECOVER: &str = "\
This vault can be recovered from a previous custody spend. The lookup is saved \
on disk, so you can close the app and come back without searching the chain \
again. Optionally enter the clawback window and/or recovery phrase now to \
check the clawback — or skip and do that when you Start recovery. The recovery \
phrase is never written to disk.";

/// Restarted with a saved lookup.
pub const CACHE_LOADED: &str = "\
Loaded a saved lookup. Chain search was skipped. You can Start recovery, \
optionally confirm clawback now, or Look up vault again to refresh from the chain. \
The recovery phrase is never stored.";

/// Optional clawback / phrase check after lookup is on disk.
pub const OPTIONAL_CONFIRM_HELP: &str = "\
Optional now: enter the clawback window in seconds and/or the recovery phrase \
to check the clawback against the chain. You can skip this and enter them later \
when you Start recovery. The recovery phrase is never saved to disk.";

/// Optional current-vault clawback seconds (Start only).
pub const CLAWBACK_SECS_HELP: &str = "\
If the on-chain hint includes this vault’s clawback timelock, that value is used. \
Otherwise enter it in seconds, or leave it empty. The app then tries a saved hint \
(if any), then common Cloud Wallet values (including 43200 / 12 hours) until the \
reconstructed spend matches the chain.";

pub fn reconstruct_success_guidance(matches_current: bool) -> String {
    let note = if matches_current {
        "Reconstructed config matches the current unspent singleton (READY)."
    } else {
        "Reconstructed config matches a previous singleton state (vault may be in RECOVERY)."
    };
    format!("{RECONSTRUCT_SUCCESS} {note}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launcher() -> KnownLauncher {
        KnownLauncher {
            id: Bytes32::new([0xaa; 32]),
            source: "test".into(),
        }
    }

    #[test]
    fn fallback_mentions_self_send_not_a_download() {
        for gap in [
            LookupGap::LauncherNotFound,
            LookupGap::SingletonNeverSpent(launcher()),
            LookupGap::NoCustodySpend(launcher()),
        ] {
            let text = fallback_guidance(&gap);
            assert!(text.contains("self-send"), "{gap:?}");
            assert!(text.contains("on-chain hint"), "{gap:?}");
            assert!(text.contains("vault.chia.net"), "{gap:?}");
            assert!(!text.contains("download"), "{gap:?}");
            assert!(!text.contains("vault-config"), "{gap:?}");
        }
    }

    #[test]
    fn lookup_can_recover_does_not_ask_for_phrase() {
        assert!(LOOKUP_CAN_RECOVER.contains("Start recovery"));
        assert!(LOOKUP_CAN_RECOVER.contains("never written to disk"));
        assert!(!LOOKUP_CAN_RECOVER.contains("look up again"));
        assert!(CLAWBACK_SECS_HELP.contains("43200"));
        assert!(OPTIONAL_CONFIRM_HELP.contains("skip"));
        assert!(CACHE_LOADED.contains("skipped"));
    }

    #[test]
    fn launcher_only_on_gaps_that_resolved_it() {
        assert!(LookupGap::LauncherNotFound.known_launcher().is_none());
        assert_eq!(
            LookupGap::SingletonNeverSpent(launcher())
                .known_launcher()
                .map(|l| l.id),
            Some(Bytes32::new([0xaa; 32]))
        );
    }
}
