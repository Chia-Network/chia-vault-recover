use std::path::PathBuf;

use anyhow::{Context, Result, bail};
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
use chia_vault_recover::workflow::{self, LookupReport, PreparedStart, StartWorkflow};
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
        /// Vault Receive address (`xch1…` / `txch1…`). A hex launcher id also works.
        #[arg(long, alias = "address", alias = "launcher-id")]
        vault: String,
        #[arg(long, default_value = "mainnet")]
        network: NetworkArg,
        #[command(flatten)]
        backend: BackendArgs,
        /// Optional clawback window. Saved as a hint unless a recovery phrase is also given.
        #[arg(long)]
        clawback_secs: Option<u64>,
        /// Optional. Used only to verify `--clawback-secs` (or discover it). Never written to the cache.
        #[arg(long, env = "CHIA_VAULT_RECOVERY_MNEMONIC")]
        recovery_mnemonic: Option<String>,
        #[arg(long)]
        recovery_mnemonic_file: Option<PathBuf>,
    },
    /// Start delayed recovery (signs with the Cloud Wallet recovery phrase)
    Start(Box<StartArgs>),
    /// Finish delayed recovery after the clawback timelock
    Finish {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        post_recovery_config: PathBuf,
        #[arg(long, default_value = "mainnet")]
        network: NetworkArg,
        #[command(flatten)]
        backend: BackendArgs,
    },
    /// Verify a public vault layout file against the on-chain singleton
    Inspect {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "mainnet")]
        network: NetworkArg,
        #[command(flatten)]
        backend: BackendArgs,
        #[arg(long)]
        post_recovery_config: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, clap::Args)]
struct StartArgs {
    /// Vault Receive address. Looks up the vault and rebuilds layout if `--config` is omitted.
    #[arg(long, alias = "address")]
    vault: Option<String>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, env = "CHIA_VAULT_RECOVERY_MNEMONIC")]
    recovery_mnemonic: Option<String>,
    #[arg(long)]
    recovery_mnemonic_file: Option<PathBuf>,
    #[arg(long, env = "CHIA_VAULT_NEW_CUSTODY_MNEMONIC")]
    new_custody_mnemonic: Option<String>,
    #[arg(long)]
    new_custody_mnemonic_file: Option<PathBuf>,
    #[arg(long)]
    new_recovery_mnemonic: Option<String>,
    #[arg(long)]
    new_recovery_mnemonic_file: Option<PathBuf>,
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
    #[arg(long, default_value = "mainnet")]
    network: NetworkArg,
    #[command(flatten)]
    backend: BackendArgs,
    #[arg(long, default_value = "post-recovery-vault-config.json")]
    out_config: PathBuf,
    /// Where to write the rebuilt public layout when starting from `--vault`.
    #[arg(long, default_value = "vault-config.json")]
    lookup_config: PathBuf,
}

#[derive(Clone, Debug, ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet11,
}

impl From<NetworkArg> for Network {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Testnet11 => Network::Testnet11,
        }
    }
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
            network,
            backend,
            clawback_secs,
            recovery_mnemonic,
            recovery_mnemonic_file,
        } => {
            let (client, network) = client_for(&vault, network, backend)?;
            let extra = clawback_secs.into_iter().collect::<Vec<_>>();
            let report = workflow::lookup(&client, &vault, &extra).await?;
            match report {
                LookupReport::NeedFallback(gap) => {
                    print_fallback(network, &gap);
                    std::process::exit(2);
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
                network,
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
                    let (client, network) = client_for(&vault, network, backend)?;
                    let mut cache = LookupCache::open();
                    let from_cache = cache.matching(&vault).is_some();
                    let extra = clawback_secs.into_iter().collect::<Vec<_>>();
                    let resolved =
                        workflow::resolve_found(&client, &mut cache, &vault, network, &extra)
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
                    let network = Network::from(network);
                    let client = ChainClient::new(network, &backend.into_backend()?);
                    (client, network, VaultConfig::load(&path)?)
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
            network,
            backend,
        } => {
            let network = Network::from(network);
            let client = ChainClient::new(network, &backend.into_backend()?);
            let config = VaultConfig::load(&config)?;
            let post = VaultConfig::load(&post_recovery_config)?;
            let handle = workflow::finish(&client, &config, &post, network).await?;
            println!("pushed finish recovery spend (handle): {handle}");
        }
        Commands::Inspect {
            config,
            network,
            backend,
            post_recovery_config,
        } => {
            let client = ChainClient::new(network.into(), &backend.into_backend()?);
            let config = VaultConfig::load(&config)?;
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
            match report.on_chain_puzzle_hash {
                Some(ph) => println!("on_chain_ph: 0x{}", hex::encode(ph)),
                None => println!("on_chain_ph: (not found)"),
            }
            println!("phase: {:?}", report.phase);
            println!("clawback_timelock_secs: {}", report.clawback_timelock);
            println!("{}", report.guidance);
            if report.phase == VaultPhase::InRecovery {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}

fn client_for(
    vault: &str,
    network: NetworkArg,
    backend: BackendArgs,
) -> Result<(ChainClient, Network)> {
    client_for_vault(vault, network.into(), &backend.into_backend()?)
        .context("invalid --vault (expected xch1…/txch1… Receive address or 0x launcher id)")
}

fn require_layout(network: Network, report: LookupReport) -> Result<()> {
    match report {
        LookupReport::NeedFallback(gap) => {
            print_fallback(network, &gap);
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
        println!("*** SAVE THIS NEW RECOVERY MNEMONIC (shown once, not written to config) ***");
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

fn print_fallback(network: Network, gap: &chia_vault_recover::LookupGap) {
    println!("network: {}", network.as_str());
    if let Some(launcher) = gap.known_launcher() {
        println!("launcher_id: 0x{}", hex::encode(launcher.id));
        println!("resolved_from: {}", launcher.source);
    }
    println!("{}", fallback_guidance(gap));
}

fn read_mnemonic(inline: Option<String>, file: Option<PathBuf>, label: &str) -> Result<String> {
    if let Some(path) = file {
        return Ok(std::fs::read_to_string(path)?.trim().to_string());
    }
    inline.with_context(|| format!("{label} mnemonic required (--*-mnemonic or --*-mnemonic-file)"))
}

fn optional_mnemonic(inline: Option<String>, file: Option<PathBuf>) -> Result<Option<String>> {
    if let Some(path) = file {
        return Ok(Some(std::fs::read_to_string(path)?.trim().to_string()));
    }
    Ok(inline)
}
