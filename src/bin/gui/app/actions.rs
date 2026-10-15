//! Chain / workflow actions for the wizard.

use std::path::Path;

use chia_vault_recover::LookupGap;
use chia_vault_recover::cache::VaultLookup;
use chia_vault_recover::config::VaultConfig;
use chia_vault_recover::discover::{ClawbackCheck, check_clawback, confirm_hinted_config};
use chia_vault_recover::error::Result;
use chia_vault_recover::keys::MnemonicWordCount;
use chia_vault_recover::locate::client_for_vault;
use chia_vault_recover::network::Network;
use chia_vault_recover::workflow::{self, FinishAction, LookupReport, StartWorkflow};

use crate::session::GuiSession;

use super::{App, Phase, runtime};

impl App {
    pub(super) fn apply_lookup(&mut self, lookup: VaultLookup, network: Network) {
        let secs = lookup.clawback().secs();
        let summary = match &lookup {
            VaultLookup::Hinted(config) => {
                format!("Launcher {} from the on-chain hint.", config.launcher_id)
            }
            VaultLookup::Found(found, _) => format!(
                "Launcher 0x{} from {}.",
                hex::encode(found.launcher_id),
                found.launcher_source
            ),
        };
        let address = self.vault_address.trim().to_string();
        GuiSession::clear();
        self.generated_recovery_mnemonic = None;
        match self.cache.persist(&address, network, lookup) {
            Ok(_) => {
                if let Some(secs) = secs {
                    self.clawback_secs = secs.to_string();
                }
                self.phase = Phase::Start;
                self.set_ok(format!(
                    "{summary} Lookup saved. You can close the app and come back to Start, or continue now."
                ));
            }
            Err(e) => self.set_err(format!("{summary} Could not save lookup cache: {e}")),
        }
    }

    pub(super) fn apply_fallback(&mut self, gap: LookupGap) {
        let launcher = match gap.known_launcher() {
            Some(known) => format!(" launcher 0x{} ({}).", hex::encode(known.id), known.source),
            None => String::new(),
        };
        self.set_err(format!(
            "Lookup needs a self-send so Cloud Wallet can publish the recovery hint.{launcher} {}",
            gap.headline()
        ));
        self.phase = Phase::Fallback(gap);
    }

    pub(super) fn run_lookup(&mut self) {
        let result = self.lookup_inner();
        self.report("Lookup error", result);
    }

    fn lookup_inner(&mut self) -> Result<()> {
        let vault = self.vault_address.trim();
        if vault.is_empty() {
            return Err(chia_vault_recover::Error::msg(
                "enter the vault Receive address (xch1… / txch1…) first",
            ));
        }
        let (client, network) = client_for_vault(vault, &self.backend())?;
        let extra = self.parsed_clawback()?.into_iter().collect::<Vec<_>>();
        let report = runtime().block_on(workflow::lookup(&client, vault, &extra))?;
        match report {
            LookupReport::Ready(lookup) => self.apply_lookup(lookup, network),
            LookupReport::NeedFallback(gap) => self.apply_fallback(gap),
        }
        Ok(())
    }

    pub(super) fn run_confirm_clawback(&mut self) {
        let result = self.confirm_clawback_inner();
        self.report("Clawback check", result);
    }

    fn confirm_clawback_inner(&mut self) -> Result<()> {
        let Some(entry) = self.cached_vault() else {
            return Err(chia_vault_recover::Error::msg(
                "look up the vault before checking clawback",
            ));
        };
        let address = entry.receive_address.clone();
        let layout = entry.lookup.clone();
        let words = self.recovery_mnemonic.trim();
        let phrase = if words.is_empty() { None } else { Some(words) };
        let typed = self.parsed_clawback()?;
        let found = match layout {
            VaultLookup::Hinted(config) => {
                confirm_hinted_config(&config, phrase, typed)?;
                let secs = config.recovery.clawback_timelock;
                self.clawback_secs = secs.to_string();
                self.set_ok(format!(
                    "Clawback {secs}s comes from the on-chain hint. The recovery phrase was not written to disk. You can Start recovery when ready."
                ));
                return Ok(());
            }
            VaultLookup::Found(found, _) => found,
        };
        let check = check_clawback(&found, phrase, typed)?;
        self.cache.persist_guess(&address, check.guess())?;
        let message = match check {
            ClawbackCheck::Hint(secs) => {
                format!(
                    "Saved clawback {secs}s as a hint. Enter the recovery phrase later to confirm it matches the chain. The phrase is never written to disk."
                )
            }
            ClawbackCheck::Verified(rebuilt) => {
                let secs = rebuilt.config.recovery.clawback_timelock;
                self.clawback_secs = secs.to_string();
                let match_note = if rebuilt.matches_current {
                    "Matches the current unspent singleton."
                } else {
                    "Matches a previous singleton state."
                };
                format!(
                    "Clawback {secs}s confirmed and saved. {match_note} The recovery phrase was not written to disk. You can Start recovery when ready."
                )
            }
        };
        self.set_ok(message);
        Ok(())
    }

    pub(super) fn run_inspect(&mut self) {
        let result = self.inspect_inner();
        self.report("Inspect error", result);
    }

    fn inspect_inner(&mut self) -> Result<()> {
        let config = VaultConfig::load(self.vault_config_path())?;
        let post = {
            let path = self.post_recovery_config_path();
            if path.is_empty() || !Path::new(path).is_file() {
                None
            } else {
                Some(VaultConfig::load(path)?)
            }
        };
        let (client, _) = self.chain_client()?;
        let report = runtime().block_on(workflow::inspect(&client, &config, post.as_ref()))?;
        self.detail = report.guidance.clone();
        let mut message = format!("Phase: {:?} — {}", report.phase, report.guidance);
        if let Some(note) = &report.pending_note {
            message.push(' ');
            message.push_str(note);
        }
        self.set_ok(message);
        Ok(())
    }

    pub(super) fn run_start(&mut self) {
        let result = self.start_inner();
        self.report("Start error", result);
    }

    fn start_inner(&mut self) -> Result<()> {
        if self.recovery_mnemonic.trim().is_empty() {
            return Err(chia_vault_recover::Error::msg(
                "enter the Cloud Wallet recovery phrase (12 or 24 words) to start recovery",
            ));
        }
        if self.new_custody_mnemonic.trim().is_empty() {
            return Err(chia_vault_recover::Error::msg(
                "enter a new custody phrase (12 or 24 words) to start recovery",
            ));
        }
        let out = self.resolve_post_path();
        let lookup_out = self.resolve_config_path();
        Self::ensure_parent_dir(&out)?;
        Self::ensure_parent_dir(&lookup_out)?;
        let word_count = if self.generate_12_words {
            MnemonicWordCount::Words12
        } else {
            MnemonicWordCount::Words24
        };
        let new_recovery = {
            let trimmed = self.new_recovery_mnemonic.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        };
        let recovery_mnemonic = self.recovery_mnemonic.trim();
        let new_custody_mnemonic = self.new_custody_mnemonic.trim();
        let typed_clawback = self.parsed_clawback()?;
        let (client, network) = self.chain_client()?;
        let push_start = |config: &VaultConfig| {
            runtime().block_on(workflow::start(
                &client,
                StartWorkflow {
                    config,
                    recovery_mnemonic,
                    new_custody_mnemonic,
                    new_recovery_mnemonic: new_recovery,
                    new_clawback_timelock: None,
                    new_word_count: word_count,
                    network,
                    out_config: &out,
                },
            ))
        };
        let start = if self.cached_vault().is_some() {
            let prepared = workflow::prepare_start(
                &mut self.cache,
                self.vault_address.trim(),
                recovery_mnemonic,
                typed_clawback,
            )?;
            self.clawback_secs = prepared.config().recovery.clawback_timelock.to_string();
            prepared.config().save(&lookup_out)?;
            self.config_path = lookup_out.display().to_string();
            push_start(prepared.config())?
        } else {
            return Err(chia_vault_recover::Error::msg(
                "look up the vault before Start recovery",
            ));
        };
        self.post_recovery_path = out.display().to_string();
        self.generated_recovery_mnemonic = start.generated_recovery_mnemonic.clone();
        self.detail =
            "Vault entering RECOVERY. After the clawback period, click Finish recovery.".into();
        self.set_ok(format!(
            "Start pushed. Wait {}s then Finish. Config: {}",
            start.clawback_timelock,
            out.display()
        ));
        self.begin_wait(start.clawback_timelock);
        self.recovery_mnemonic.clear();
        self.new_custody_mnemonic.clear();
        self.new_recovery_mnemonic.clear();
        Ok(())
    }

    pub(super) fn run_finish(&mut self) {
        let result = self.finish_inner();
        self.report("Finish error", result);
    }

    fn finish_inner(&mut self) -> Result<()> {
        let (config_path, post_path) = match &self.phase {
            Phase::Wait(session) => (
                session.config_path.clone(),
                session.post_recovery_path.clone(),
            ),
            _ => {
                return Err(chia_vault_recover::Error::msg(
                    "finish is only available after Start recovery",
                ));
            }
        };
        let config = VaultConfig::load(&config_path)?;
        let post = VaultConfig::load(&post_path)?;
        let (client, network) = self.chain_client()?;
        let outcome = runtime().block_on(workflow::finish(&client, &config, &post, network))?;
        self.settle_finish(
            outcome.action,
            outcome.pending_note.as_deref(),
            &GuiSession::default_path(),
        );
        Ok(())
    }

    /// Every settled finish leaves the wizard on Done and deletes the on-disk session.
    fn settle_finish(
        &mut self,
        action: FinishAction,
        pending_note: Option<&str>,
        session_path: &Path,
    ) {
        GuiSession::clear_at(session_path);
        self.generated_recovery_mnemonic = None;
        self.phase = Phase::Done;
        self.set_ok(finish_status(&action, pending_note));
    }
}

fn finish_status(action: &FinishAction, pending_note: Option<&str>) -> String {
    let text = match action {
        FinishAction::Pushed(handle) => {
            format!("Finish pushed ({handle}). Vault custody is now the new BLS key.")
        }
        FinishAction::AlreadyFinished => {
            "Vault is under the recovered custody configuration.".to_string()
        }
        FinishAction::ClawedBack => {
            "Vault is under the original custody configuration.".to_string()
        }
    };
    match pending_note.map(str::trim).filter(|note| !note.is_empty()) {
        Some(note) => format!("{note} {text}"),
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use chia_vault_recover::cache::LookupCache;
    use chia_vault_recover::workflow::FinishAction;

    use super::super::{App, Phase, resumable_session};
    use super::finish_status;
    use crate::session::GuiSession;

    fn temp_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "cvr-gui-finish-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn started_session(dir: &Path) -> GuiSession {
        let config = dir.join("vault-config.json");
        let post = dir.join("post.json");
        fs::write(&config, "{}").unwrap();
        fs::write(&post, "{}").unwrap();
        GuiSession {
            receive_address: "txch1test".into(),
            config_path: config.display().to_string(),
            post_recovery_path: post.display().to_string(),
            clawback_secs: Some(60),
            started_at: Some(1_700_000_000),
        }
    }

    fn app_waiting(session: GuiSession) -> App {
        App {
            vault_address: session.receive_address.clone(),
            config_path: String::new(),
            post_recovery_path: String::new(),
            clawback_secs: String::new(),
            recovery_mnemonic: String::new(),
            new_custody_mnemonic: String::new(),
            new_recovery_mnemonic: String::new(),
            generate_12_words: false,
            full_node_url: String::new(),
            status: super::super::Status::Empty,
            generated_recovery_mnemonic: Some("shown recovery phrase".into()),
            phase: Phase::Wait(session),
            detail: String::new(),
            cache: LookupCache::open_at(temp_dir().join("cache.json")),
            smoke: true,
            logged_first_frame: true,
        }
    }

    #[test]
    fn settled_finish_closes_the_recovery_session() {
        let cases = [
            (
                FinishAction::Pushed("tx-1".into()),
                "Finish pushed (tx-1). Vault custody is now the new BLS key.",
            ),
            (
                FinishAction::AlreadyFinished,
                "Vault is under the recovered custody configuration.",
            ),
            (
                FinishAction::ClawedBack,
                "Vault is under the original custody configuration.",
            ),
        ];
        for (action, expected) in cases {
            let dir = temp_dir();
            fs::create_dir_all(&dir).unwrap();
            let session_path = dir.join("gui-session.json");
            let session = started_session(&dir);
            session.save_at(&session_path).unwrap();

            let mut app = app_waiting(session.clone());
            assert!(resumable_session(Some(session), &app.cache).is_some());
            assert!(app.waiting_session().is_some());

            app.settle_finish(action, None, &session_path);

            assert!(matches!(app.phase, Phase::Done));
            assert!(app.waiting_session().is_none());
            assert!(app.generated_recovery_mnemonic.is_none());
            assert_eq!(app.status.text(), expected);
            assert_eq!(app.subtitle(), super::super::DONE_SUBTITLE);
            assert!(!app.subtitle().contains("new BLS"));
            assert!(resumable_session(GuiSession::load_at(&session_path), &app.cache).is_none());
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn finish_status_prefixes_a_pending_note() {
        let note = "A pending spend of this vault is in the mempool and may finish recovery or claw it back.";
        let status = finish_status(&FinishAction::ClawedBack, Some(note));
        assert_eq!(
            status,
            format!("{note} Vault is under the original custody configuration.")
        );
        assert_eq!(
            finish_status(&FinishAction::ClawedBack, Some("  ")),
            "Vault is under the original custody configuration."
        );
    }
}
