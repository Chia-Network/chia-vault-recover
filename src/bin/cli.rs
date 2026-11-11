use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chia_vault_recover::address::parse_receive_address;
use chia_vault_recover::cache::{LookupCache, VaultLookup};
use chia_vault_recover::chain::ChainClient;
use chia_vault_recover::config::VaultConfig;
use chia_vault_recover::discover::{
    ClawbackCheck, FoundVault, ReconstructedVault, check_clawback, confirm_hinted_config,
};
use chia_vault_recover::guidance::{
    LOOKUP_CAN_RECOVER, LOOKUP_FROM_HINT, fallback_guidance, reconstruct_success_guidance,
};
use chia_vault_recover::keys::MnemonicWordCount;
use chia_vault_recover::locate::client_for_vault;
use chia_vault_recover::network::{Backend, Network};
use chia_vault_recover::recovery::{StartRecoveryResult, VaultPhase};
use chia_vault_recover::scan::LauncherScan;
use chia_vault_recover::workflow::{
    self, FinishAction, LookupOptions, LookupReport, PreparedStart, StartWorkflow,
};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "chia-vault-recover",
    version,
    about = "Recover a Chia Cloud Wallet vault from its receive address"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Look up a vault from its receive address (start here)
    #[command(visible_alias = "discover", visible_alias = "resolve")]
    Lookup {
        /// Vault Receive address. `xch1…` is mainnet and `txch1…` is testnet11.
        #[arg(long, alias = "address")]
        vault: String,
        #[command(flatten)]
        backend: BackendArgs,
        /// Optional clawback window. Saved as a hint unless a recovery phrase is also given.
        #[arg(long)]
        clawback_secs: Option<u64>,
        /// Optional 12- or 24-word recovery phrase. Used only to verify `--clawback-secs` (or discover it). Never written to the cache.
        #[arg(long, env = "CHIA_VAULT_RECOVERY_MNEMONIC")]
        recovery_mnemonic: Option<String>,
        /// File containing the 12- or 24-word recovery phrase.
        #[arg(long)]
        recovery_mnemonic_file: Option<PathBuf>,
        /// Opt-in launcher scan for a vault that has never been spent: the date the vault
        /// was created (`YYYY-MM-DD`). Checks every launcher from that day in any timezone.
        #[arg(long, conflicts_with_all = ["scan_from_height", "scan_to_height", "force_scan"])]
        created_on: Option<String>,
        /// First block height to scan for the vault launcher (use with `--scan-to-height`).
        #[arg(long, requires = "scan_to_height")]
        scan_from_height: Option<u32>,
        /// Block height to stop scanning at, exclusive (use with `--scan-from-height`).
        #[arg(long, requires = "scan_from_height")]
        scan_to_height: Option<u32>,
        /// Allow a height-range scan over the 5-day limit.
        #[arg(long, requires = "scan_from_height")]
        force_scan: bool,
    },
    /// Start delayed recovery (signs with the 12- or 24-word Cloud Wallet recovery phrase)
    Start(Box<StartArgs>),
    /// Finish delayed recovery after the clawback timelock.
    ///
    /// Uses the network saved from the vault Receive address (`xch1…` or `txch1…`).
    Finish {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        post_recovery_config: PathBuf,
        #[command(flatten)]
        backend: BackendArgs,
    },
    /// Verify a public vault layout file against the on-chain singleton.
    ///
    /// Uses the network saved from the vault Receive address (`xch1…` or `txch1…`).
    Inspect {
        #[arg(long)]
        config: PathBuf,
        #[command(flatten)]
        backend: BackendArgs,
        #[arg(long)]
        post_recovery_config: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, clap::Args)]
struct StartArgs {
    /// Vault Receive address (`xch1…` mainnet or `txch1…` testnet11). Looks up the vault if `--config` is omitted.
    #[arg(long, alias = "address")]
    vault: Option<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    /// Cloud Wallet recovery phrase (12 or 24 words).
    #[arg(long, env = "CHIA_VAULT_RECOVERY_MNEMONIC")]
    recovery_mnemonic: Option<String>,
    /// File containing the Cloud Wallet recovery phrase (12 or 24 words).
    #[arg(long)]
    recovery_mnemonic_file: Option<PathBuf>,
    /// New custody phrase (12 or 24 words).
    #[arg(long, env = "CHIA_VAULT_NEW_CUSTODY_MNEMONIC")]
    new_custody_mnemonic: Option<String>,
    /// File containing the new custody phrase (12 or 24 words).
    #[arg(long)]
    new_custody_mnemonic_file: Option<PathBuf>,
    /// New recovery phrase (12 or 24 words). Leave unset to auto-generate one.
    #[arg(long)]
    new_recovery_mnemonic: Option<String>,
    /// File containing the new recovery phrase (12 or 24 words).
    #[arg(long)]
    new_recovery_mnemonic_file: Option<PathBuf>,
    /// Word count for an auto-generated recovery phrase: 12 or 24 (default 24).
    #[arg(long, default_value = "24")]
    word_count: u8,
    #[arg(long)]
    new_clawback_secs: Option<u64>,
    /// Current vault clawback window in seconds.
    /// The on-chain hint is used when it includes one. Otherwise an explicit
    /// value is tried alone; if omitted, a cached known/hint value is used, then
    /// common Cloud Wallet values (including 43200 / 12h).
    #[arg(long)]
    clawback_secs: Option<u64>,
    #[command(flatten)]
    backend: BackendArgs,
    #[arg(long, default_value = "post-recovery-vault-config.json")]
    out_config: PathBuf,
    /// Where to write the rebuilt public layout when starting from `--vault`.
    #[arg(long, default_value = "vault-config.json")]
    lookup_config: PathBuf,
}

#[derive(Clone, Debug, clap::Args)]
struct BackendArgs {
    #[arg(long, default_value = "coinset")]
    backend: BackendKind,
    #[arg(long)]
    full_node_url: Option<String>,
}

#[derive(Clone, Debug, ValueEnum)]
enum BackendKind {
    Coinset,
    Rpc,
}

impl BackendArgs {
    fn into_backend(self) -> Result<Backend> {
        match self.backend {
            BackendKind::Coinset => Ok(Backend::Coinset),
            BackendKind::Rpc => Ok(Backend::FullNode {
                url: self
                    .full_node_url
                    .context("--full-node-url is required with --backend rpc")?,
            }),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Lookup {
            vault,
            backend,
            clawback_secs,
            recovery_mnemonic,
            recovery_mnemonic_file,
            created_on,
            scan_from_height,
            scan_to_height,
            force_scan,
        } => {
            let (client, network) = client_for(&vault, backend)?;
            let extra = clawback_secs.into_iter().collect::<Vec<_>>();
            let scan = match (created_on, scan_from_height, scan_to_height) {
                (Some(date), _, _) => Some(LauncherScan::created_on(&date)?),
                (None, Some(start), Some(end)) => {
                    Some(LauncherScan::heights(start, end, force_scan)?)
                }
                _ => None,
            };
            let report = workflow::lookup(
                &client,
                &vault,
                LookupOptions {
                    extra_timelocks: &extra,
                    scan: scan.as_ref(),
                },
            )
            .await?;
            match report {
                LookupReport::NeedFallback(gap) => {
                    let code = report_need_fallback(
                        &mut std::io::stdout(),
                        &mut std::io::stderr(),
                        network,
                        &gap,
                        || LookupCache::open().discard(&vault),
                    );
                    std::process::exit(code);
                }
                LookupReport::Ready(lookup) => {
                    print_lookup(&lookup, network);
                    let mut cache = LookupCache::open();
                    cache.persist(&vault, network, lookup.clone())?;
                    println!("lookup cache: {}", cache.path().display());
                    let words = optional_mnemonic(recovery_mnemonic, recovery_mnemonic_file)?;
                    if clawback_secs.is_some() || words.is_some() {
                        confirm_saved_lookup(
                            &mut cache,
                            &vault,
                            &lookup,
                            words.as_deref(),
                            clawback_secs,
                        );
                    }
                    println!(
                        "{}",
                        match &lookup {
                            VaultLookup::Hinted(_) => LOOKUP_FROM_HINT,
                            VaultLookup::Found(_, _) => LOOKUP_CAN_RECOVER,
                        }
                    );
                    println!(
                        "When you are ready: chia-vault-recover start --vault <address> \
                         --recovery-mnemonic-file … --new-custody-mnemonic-file …"
                    );
                }
            }
        }
        Commands::Start(start) => {
            let StartArgs {
                vault,
                config,
                recovery_mnemonic,
                recovery_mnemonic_file,
                new_custody_mnemonic,
                new_custody_mnemonic_file,
                new_recovery_mnemonic,
                new_recovery_mnemonic_file,
                word_count,
                new_clawback_secs,
                clawback_secs,
                backend,
                out_config,
                lookup_config,
            } = *start;
            let recovery_mnemonic =
                read_mnemonic(recovery_mnemonic, recovery_mnemonic_file, "recovery")?;
            let new_custody_mnemonic = read_mnemonic(
                new_custody_mnemonic,
                new_custody_mnemonic_file,
                "new custody",
            )?;
            let new_recovery_mnemonic = match (new_recovery_mnemonic, new_recovery_mnemonic_file) {
                (None, None) => None,
                (m, f) => Some(read_mnemonic(m, f, "new recovery")?),
            };
            let word_count = match word_count {
                12 => MnemonicWordCount::Words12,
                24 => MnemonicWordCount::Words24,
                _ => bail!("word_count must be 12 or 24"),
            };
            let (client, network, config) = match (vault, config) {
                (Some(_), Some(_)) => {
                    bail!("pass --vault <xch1…> or --config <vault-config.json>, not both")
                }
                (Some(vault), None) => {
                    let (client, network) = client_for(&vault, backend)?;
                    let mut cache = LookupCache::open();
                    let from_cache = cache.matching(&vault).is_some();
                    let extra = clawback_secs.into_iter().collect::<Vec<_>>();
                    let resolved = workflow::resolve_found(
                        &client,
                        &mut cache,
                        &vault,
                        network,
                        LookupOptions {
                            extra_timelocks: &extra,
                            scan: None,
                        },
                    )
                    .await?;
                    if matches!(resolved, LookupReport::NeedFallback(_)) {
                        require_layout(network, resolved)?;
                    }
                    if from_cache {
                        println!(
                            "using cached lookup ({}); run lookup again to refresh from the chain",
                            cache.path().display()
                        );
                    } else {
                        println!("lookup cache: {}", cache.path().display());
                    }
                    let prepared = workflow::prepare_start(
                        &mut cache,
                        &vault,
                        &recovery_mnemonic,
                        clawback_secs,
                    )?;
                    prepared.config().save(&lookup_config)?;
                    print_prepared(&prepared, network, Some(&lookup_config));
                    if from_cache {
                        println!("skipped chain search (cached lookup)");
                    }
                    (client, network, prepared.config().clone())
                }
                (None, Some(path)) => {
                    let mut config = VaultConfig::load(&path)?;
                    let address = match config.recorded_receive_address() {
                        Ok(address) => address.to_string(),
                        Err(_) => {
                            let cache = LookupCache::open();
                            let launcher_id = config.launcher_id_bytes()?;
                            let Some(entry) = cache.current() else {
                                bail!(
                                    "no saved lookup; run lookup with the vault Receive address (xch1… or txch1…) first"
                                );
                            };
                            if entry.launcher_id()? != launcher_id {
                                bail!(
                                    "saved lookup is for a different vault; look up this vault's Receive address (xch1… or txch1…) first"
                                );
                            }
                            let address = parse_receive_address(&entry.receive_address)
                                .map_err(|_| {
                                    anyhow::anyhow!(
                                        "saved lookup has no Receive address; run lookup with the vault Receive address (xch1… or txch1…) first"
                                    )
                                })?;
                            config.receive_address = Some(address.clone());
                            config.save(&path)?;
                            address
                        }
                    };
                    let (client, network) = client_for(&address, backend)?;
                    (client, network, config)
                }
                (None, None) => {
                    bail!("pass --vault <xch1…> (recommended) or --config <vault-config.json>")
                }
            };
            let result = workflow::start(
                &client,
                StartWorkflow {
                    config: &config,
                    recovery_mnemonic: &recovery_mnemonic,
                    new_custody_mnemonic: &new_custody_mnemonic,
                    new_recovery_mnemonic: new_recovery_mnemonic.as_deref(),
                    new_clawback_timelock: new_clawback_secs,
                    new_word_count: word_count,
                    network,
                    out_config: &out_config,
                },
            )
            .await?;
            print_start_result(&out_config, &result);
        }
        Commands::Finish {
            config,
            post_recovery_config,
            backend,
        } => {
            let config = VaultConfig::load(&config)?;
            let post = VaultConfig::load(&post_recovery_config)?;
            let (client, network) = client_for(config.recorded_receive_address()?, backend)?;
            let outcome = workflow::finish(&client, &config, &post, network).await?;
            if let Some(note) = &outcome.pending_note {
                println!("{note}");
            }
            match outcome.action {
                FinishAction::Pushed(handle) => {
                    println!("pushed finish recovery spend (handle): {handle}");
                }
                FinishAction::AlreadyFinished => {
                    println!("vault is under the recovered custody configuration");
                }
                FinishAction::ClawedBack => {
                    println!("vault is under the original custody configuration");
                }
            }
        }
        Commands::Inspect {
            config,
            backend,
            post_recovery_config,
        } => {
            let config = VaultConfig::load(&config)?;
            let (client, _) = client_for(config.recorded_receive_address()?, backend)?;
            let post = post_recovery_config
                .as_ref()
                .map(VaultConfig::load)
                .transpose()?;
            let report = workflow::inspect(&client, &config, post.as_ref()).await?;
            println!("launcher_id: 0x{}", hex::encode(report.launcher_id));
            println!(
                "expected_ready_ph: 0x{}",
                hex::encode(report.expected_ready_puzzle_hash)
            );
            println!(
                "on_chain_ph: 0x{}",
                hex::encode(report.on_chain_coin.puzzle_hash)
            );
            println!("phase: {:?}", report.phase);
            println!("clawback_timelock_secs: {}", report.clawback_timelock);
            println!("{}", report.guidance);
            if let Some(note) = &report.pending_note {
                println!("{note}");
            }
            if report.phase == VaultPhase::InRecovery {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

fn client_for(vault: &str, backend: BackendArgs) -> Result<(ChainClient, Network)> {
    client_for_vault(vault, &backend.into_backend()?)
        .context("invalid --vault (expected an xch1… mainnet or txch1… testnet11 Receive address)")
}

fn require_layout(network: Network, report: LookupReport) -> Result<()> {
    match report {
        LookupReport::NeedFallback(gap) => {
            let _ = print_fallback(&mut std::io::stdout(), network, &gap);
            bail!("cannot start recovery until lookup finds the vault layout");
        }
        LookupReport::Ready(_) => Ok(()),
    }
}

fn print_lookup(lookup: &VaultLookup, network: Network) {
    match lookup {
        VaultLookup::Hinted(config) => print_hinted(config, network),
        VaultLookup::Found(found, _) => print_found(found, network),
    }
}

fn confirm_saved_lookup(
    cache: &mut LookupCache,
    vault: &str,
    lookup: &VaultLookup,
    words: Option<&str>,
    clawback_secs: Option<u64>,
) {
    match lookup {
        VaultLookup::Hinted(config) => match confirm_hinted_config(config, words, clawback_secs) {
            Ok(()) => println!(
                "verified clawback_timelock_secs: {}",
                config.recovery.clawback_timelock
            ),
            Err(e) => println!("clawback check: {e}"),
        },
        VaultLookup::Found(found, _) => match check_clawback(found, words, clawback_secs) {
            Ok(check) => {
                if let Err(e) = cache.persist_guess(vault, check.guess()) {
                    println!("clawback check: {e}");
                    return;
                }
                match check {
                    ClawbackCheck::Hint(secs) => {
                        println!(
                            "saved clawback {secs}s as a hint (not verified without the recovery phrase)"
                        );
                    }
                    ClawbackCheck::Verified(rebuilt) => {
                        println!(
                            "verified clawback_timelock_secs: {}",
                            rebuilt.config.recovery.clawback_timelock
                        );
                        println!("{}", reconstruct_success_guidance(rebuilt.matches_current));
                    }
                }
            }
            Err(e) => println!("clawback check: {e}"),
        },
    }
}

fn print_lookup_header(network: Network, found: &FoundVault) {
    println!("network: {}", network.as_str());
    println!("launcher_id: 0x{}", hex::encode(found.launcher_id));
    println!("resolved_from: {}", found.launcher_source);
}

fn print_custody_members(found: &FoundVault) {
    if found.custody.members_complete() {
        println!("custody members: parsed from spend");
    } else {
        println!("custody members: hash only (M-of-N or unparsed); enough for delayed recovery");
    }
}

fn print_hinted(config: &chia_vault_recover::VaultConfig, network: Network) {
    println!("network: {}", network.as_str());
    println!("launcher_id: {}", config.launcher_id);
    println!("layout: on-chain Cloud Wallet hint");
    println!(
        "clawback_timelock_secs: {}",
        config.recovery.clawback_timelock
    );
}

fn print_found(found: &FoundVault, network: Network) {
    print_lookup_header(network, found);
    print_custody_members(found);
}

fn print_start_result(out_config: &std::path::Path, result: &StartRecoveryResult) {
    println!("pushed start recovery spend");
    println!(
        "wrote public post-recovery config: {}",
        out_config.display()
    );
    println!(
        "clawback_timelock_secs: {} — wait, then run finish",
        result.clawback_timelock
    );
    if let Some(words) = &result.generated_recovery_mnemonic {
        println!();
        println!("*** SAVE THIS NEW RECOVERY PHRASE (shown once, not written to config) ***");
        println!("{words}");
        println!("***");
    }
}

fn print_prepared(
    prepared: &PreparedStart,
    network: Network,
    out_config: Option<&std::path::Path>,
) {
    if let Some(path) = out_config {
        println!("wrote vault config: {}", path.display());
    }
    match prepared {
        PreparedStart::Hinted(config) => {
            print_hinted(config, network);
            println!("{LOOKUP_FROM_HINT}");
        }
        PreparedStart::Reconstructed(rebuilt) => print_reconstructed(rebuilt, network),
    }
}

fn print_reconstructed(rebuilt: &ReconstructedVault, network: Network) {
    print_lookup_header(network, &rebuilt.found);
    println!(
        "custody_hash: 0x{}",
        hex::encode(rebuilt.found.custody.custody_hash)
    );
    println!(
        "clawback_timelock_secs: {}",
        rebuilt.config.recovery.clawback_timelock
    );
    println!(
        "current_coin: 0x{}",
        hex::encode(rebuilt.found.current_coin.coin_id())
    );
    print_custody_members(&rebuilt.found);
    println!("{}", reconstruct_success_guidance(rebuilt.matches_current));
}

fn print_fallback(
    out: &mut impl Write,
    network: Network,
    gap: &chia_vault_recover::LookupGap,
) -> std::io::Result<()> {
    writeln!(out, "network: {}", network.as_str())?;
    if let Some(launcher) = gap.known_launcher() {
        writeln!(out, "launcher_id: 0x{}", hex::encode(launcher.id))?;
        writeln!(out, "resolved_from: {}", launcher.source)?;
    }
    writeln!(out, "{}", fallback_guidance(gap))?;
    if gap.launcher_unknown() {
        writeln!(
            out,
            "\nTo search launchers: lookup --vault <address> --created-on YYYY-MM-DD \
             (or --scan-from-height and --scan-to-height)."
        )?;
    }
    Ok(())
}

fn report_need_fallback<E: std::fmt::Display>(
    out: &mut impl Write,
    err: &mut impl Write,
    network: Network,
    gap: &chia_vault_recover::LookupGap,
    discard: impl FnOnce() -> std::result::Result<(), E>,
) -> i32 {
    let _ = print_fallback(out, network, gap);
    if let Err(e) = discard() {
        let _ = writeln!(err, "could not clear the saved lookup: {e}");
    }
    2
}

fn read_mnemonic(inline: Option<String>, file: Option<PathBuf>, label: &str) -> Result<String> {
    if let Some(path) = file {
        return Ok(std::fs::read_to_string(path)?.trim().to_string());
    }
    inline.with_context(|| format!("{label} phrase required (--*-mnemonic or --*-mnemonic-file)"))
}

fn optional_mnemonic(inline: Option<String>, file: Option<PathBuf>) -> Result<Option<String>> {
    if let Some(path) = file {
        return Ok(Some(std::fs::read_to_string(path)?.trim().to_string()));
    }
    Ok(inline)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    struct SharedWriter(Rc<RefCell<String>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().push_str(&String::from_utf8_lossy(buf));
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn need_fallback_writes_guidance_before_discard_warning() {
        let events = Rc::new(RefCell::new(String::new()));
        let mut out = SharedWriter(Rc::clone(&events));
        let mut err = SharedWriter(Rc::clone(&events));
        let gap = chia_vault_recover::LookupGap::LauncherNotFound;
        let code = report_need_fallback(&mut out, &mut err, Network::Mainnet, &gap, || {
            Err(anyhow::anyhow!("disk full"))
        });
        assert_eq!(code, 2);
        let text = events.borrow();
        let guidance = text
            .find(&fallback_guidance(&gap))
            .expect("guidance should be written");
        let warning = text
            .find("could not clear the saved lookup")
            .expect("warning should be written");
        assert!(guidance < warning, "{text}");
    }
}
