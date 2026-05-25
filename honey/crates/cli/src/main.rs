use anyhow::Result;
use clap::{Parser, Subcommand};
use honey_config::Config;
use honey_identity::Identity;
use std::time::Duration;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "honey", version, about = "Cowrie honeypot federation + jobs")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Federation control surface (peers, reputation, identity, daemon).
    Federation {
        #[command(subcommand)]
        command: FederationCmd,
    },
    /// Scheduled jobs (wordlists, stats).
    Jobs {
        #[command(subcommand)]
        command: JobsCmd,
    },
    /// One-shot initialisers (bloom filter, GeoIP DBs, …).
    Init {
        #[command(subcommand)]
        command: InitCmd,
    },
    /// Bulk-import data from external sources.
    Import {
        #[command(subcommand)]
        command: ImportCmd,
    },
    /// Host-level operational helpers (iptables, ipset, certbot).
    Ops {
        #[command(subcommand)]
        command: OpsCmd,
    },
    /// Database connectivity check (uses POSTGRES_* env vars).
    DbPing,
}

#[derive(Subcommand)]
enum OpsCmd {
    /// Add iptables NAT rules: 22→2222 (SSH), 23→2223 (Telnet).
    PortRedirect,
    /// Build a Brazil-IPv4 ipset and apply iptables rules for a TCP port.
    BrazilIpset {
        /// Port to restrict. Default matches the legacy Grafana setup.
        #[arg(long, default_value_t = 47321)]
        port: u16,
        /// ipset name.
        #[arg(long, default_value = "br-grafana")]
        set_name: String,
    },
    /// Obtain a Let's Encrypt cert for $TARGET_HOST via docker certbot.
    Letsencrypt {
        #[arg(long, env = "TARGET_HOST")]
        target_host: String,
        #[arg(long, env = "CERTBOT_EMAIL")]
        email: String,
    },
}

#[derive(Subcommand)]
enum ImportCmd {
    /// Import one or more Cowrie JSON log files into Postgres.
    CowrieJson {
        /// Paths to cowrie.json files. Globs are NOT expanded — let the shell do it.
        #[arg(required = true)]
        files: Vec<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum FederationCmd {
    /// Print this node's fingerprint + pubkey. Generates the keypair on first run.
    Info,
    /// Run the federation HTTP daemon (api + nonce GC tasks).
    Daemon,
    /// Manage peer trust state.
    Peers {
        #[command(subcommand)]
        command: PeersCmd,
    },
    /// Inspect reputation as seen by a remote peer.
    Reputation {
        #[command(subcommand)]
        command: ReputationCmd,
    },
}

#[derive(Subcommand)]
enum ReputationCmd {
    /// Ask <peer> for their view of <target>. Both are fingerprints.
    Query {
        peer: String,
        target: String,
    },
}

#[derive(Subcommand)]
enum PeersCmd {
    /// Send a peering request to a remote node URL via the local daemon.
    Request {
        /// Remote base URL, e.g. `https://peer.example.com`.
        #[arg(long)]
        url: String,
        #[arg(long, default_value = "")]
        node_name: String,
        #[arg(long, default_value = "")]
        contact: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// List configured peers.
    List,
    /// List requests awaiting our approval.
    Pending,
    /// Approve a pending peering request by fingerprint.
    Approve {
        fingerprint: String,
    },
    /// Reject a pending peering request by fingerprint.
    Reject {
        fingerprint: String,
    },
    /// Revoke a previously-approved peer.
    Revoke {
        fingerprint: String,
        /// Also delete every federated entry attributed to this peer (cascade).
        #[arg(long)]
        purge: bool,
    },
    /// Adjust a peer's local reputation score by a delta (clamped to ±100).
    Score {
        fingerprint: String,
        delta: i32,
    },
}

#[derive(Subcommand)]
enum JobsCmd {
    /// Generate per-window wordlists + mutation rules from the `auth` table.
    Wordlists {
        /// Run continuously, sleeping between passes.
        #[arg(long)]
        r#loop: bool,
        /// Seconds between passes when --loop is set. Default: 6 hours.
        #[arg(long, default_value_t = 21_600)]
        interval_secs: u64,
    },
    /// Precompute per-window stats JSON files for the dashboard.
    Stats {
        /// Run continuously, sleeping between passes.
        #[arg(long)]
        r#loop: bool,
        /// Seconds between passes when --loop is set. Default: 5 minutes.
        #[arg(long, default_value_t = 300)]
        interval_secs: u64,
    },
}

#[derive(Subcommand)]
enum InitCmd {
    /// Build the reference Bloom filter from BLOOM_WORDLIST_URLS.
    Bloom {
        /// Override BLOOM_WORDLIST_URLS (space-separated).
        #[arg(long, env = "BLOOM_WORDLIST_URLS", default_value = "")]
        urls: String,
    },
    /// Download db-ip.com GeoIP Country + ASN MMDBs.
    Geoip,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Cmd::Federation { command } => match command {
            FederationCmd::Info => cmd_info(),
            FederationCmd::Daemon => cmd_daemon().await,
            FederationCmd::Peers { command } => match command {
                PeersCmd::Request {
                    url,
                    node_name,
                    contact,
                    description,
                } => cmd_peers_request(url, node_name, contact, description).await,
                PeersCmd::List => cmd_peers_list().await,
                PeersCmd::Pending => cmd_peers_pending().await,
                PeersCmd::Approve { fingerprint } => cmd_peers_approve(fingerprint).await,
                PeersCmd::Reject { fingerprint } => cmd_peers_reject(fingerprint).await,
                PeersCmd::Revoke { fingerprint, purge } => {
                    cmd_peers_revoke(fingerprint, purge).await
                }
                PeersCmd::Score { fingerprint, delta } => {
                    cmd_peers_score(fingerprint, delta).await
                }
            },
            FederationCmd::Reputation { command } => match command {
                ReputationCmd::Query { peer, target } => {
                    cmd_reputation_query(peer, target).await
                }
            },
        },
        Cmd::Jobs { command } => match command {
            JobsCmd::Wordlists { r#loop, interval_secs } => {
                cmd_jobs_wordlists(r#loop, interval_secs).await
            }
            JobsCmd::Stats { r#loop, interval_secs } => {
                cmd_jobs_stats(r#loop, interval_secs).await
            }
        },
        Cmd::Init { command } => match command {
            InitCmd::Bloom { urls } => cmd_init_bloom(urls).await,
            InitCmd::Geoip => cmd_init_geoip().await,
        },
        Cmd::Import { command } => match command {
            ImportCmd::CowrieJson { files } => cmd_import_cowrie_json(files).await,
        },
        Cmd::Ops { command } => match command {
            OpsCmd::PortRedirect => honey_jobs::ops::port_redirect(),
            OpsCmd::BrazilIpset { port, set_name } => {
                honey_jobs::ops::brazil_ipset(port, &set_name)
            }
            OpsCmd::Letsencrypt { target_host, email } => {
                honey_jobs::ops::letsencrypt(&target_host, &email)
            }
        },
        Cmd::DbPing => cmd_db_ping().await,
    }
}

fn cmd_info() -> Result<()> {
    let cfg = Config::from_env()?;
    let identity = Identity::load_or_create(&cfg.data_dir)?;

    let bar = "═".repeat(74);
    println!("{bar}");
    println!("  honey node identity");
    println!("{bar}");
    println!();
    println!("  Fingerprint:  {}", identity.fingerprint());
    println!("  Pubkey (b64): {}", identity.pubkey_b64());
    println!();
    if !cfg.node_name.is_empty() {
        println!("  Node name:    {}", cfg.node_name);
    }
    if !cfg.contact.is_empty() {
        println!("  Contact:      {}", cfg.contact);
    }
    println!("  Data dir:     {}", cfg.data_dir.display());
    println!();
    println!("{bar}");
    println!();
    println!("  Share the FINGERPRINT (not the pubkey) with peers,");
    println!("  then verify it OUT-OF-BAND before approving any peering request.");
    println!();
    Ok(())
}

async fn cmd_db_ping() -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    honey_db::ping(&pool).await?;
    println!("postgres: ok");
    Ok(())
}

async fn cmd_jobs_wordlists(loop_forever: bool, interval_secs: u64) -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;

    if !loop_forever {
        return honey_jobs::wordlists::run_once(&pool, &cfg.wordlist_dir, &cfg.bloom_dir).await;
    }

    let interval = Duration::from_secs(interval_secs.max(1));
    info!(?interval, "wordlist loop start");
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match honey_jobs::wordlists::run_once(&pool, &cfg.wordlist_dir, &cfg.bloom_dir).await {
            Ok(()) => info!("wordlist pass ok"),
            Err(e) => error!(error = ?e, "wordlist pass failed"),
        }
    }
}

async fn cmd_jobs_stats(loop_forever: bool, interval_secs: u64) -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    let paths = honey_jobs::stats::Paths {
        stats_dir: cfg.stats_dir.clone(),
        wordlist_dir: cfg.wordlist_dir.clone(),
        geoip_country_db: Some(cfg.geoip_country_db.clone())
            .filter(|p| p.exists()),
        geoip_asn_db: Some(cfg.geoip_asn_db.clone()).filter(|p| p.exists()),
    };

    if !loop_forever {
        return honey_jobs::stats::run_once(&pool, &paths).await;
    }

    let interval = Duration::from_secs(interval_secs.max(1));
    info!(?interval, "stats loop start");
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match honey_jobs::stats::run_once(&pool, &paths).await {
            Ok(()) => info!("stats pass ok"),
            Err(e) => error!(error = ?e, "stats pass failed"),
        }
    }
}

async fn cmd_init_bloom(urls: String) -> Result<()> {
    let cfg = Config::from_env()?;
    let urls = honey_jobs::init::bloom::parse_urls(&urls);
    honey_jobs::init::bloom::run(&cfg.bloom_dir, &urls).await
}

async fn cmd_init_geoip() -> Result<()> {
    let cfg = Config::from_env()?;
    honey_jobs::init::geoip::run(&cfg.geoip_dir).await
}

async fn cmd_import_cowrie_json(files: Vec<std::path::PathBuf>) -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    let totals = honey_jobs::cowrie_import::import_files(&pool, &files).await?;
    println!("Total:");
    println!("  sensors      {}", totals.sensors);
    println!("  clients      {}", totals.clients);
    println!("  sessions     {}", totals.sessions);
    println!("  auth         {}", totals.auth);
    println!("  input        {}", totals.input);
    println!("  ttylog       {}", totals.ttylog);
    println!("  downloads    {}", totals.downloads);
    println!("  fingerprints {}", totals.fingerprints);
    Ok(())
}

async fn cmd_daemon() -> Result<()> {
    let cfg = Config::from_env()?;
    let identity = Identity::load_or_create(&cfg.data_dir)?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    let state = honey_server::AppState::new(cfg, identity, pool);
    honey_server::run(state).await
}

async fn cmd_peers_request(url: String, node_name: String, contact: String, description: String) -> Result<()> {
    let cfg = Config::from_env()?;
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "url": url,
        "node_name": node_name,
        "contact": contact,
        "description": description,
    });
    let endpoint = format!("{}/internal/peer/request", cfg.daemon_internal_url.trim_end_matches('/'));
    let resp = client.post(&endpoint).json(&body).send().await?;
    if resp.status().is_success() {
        println!("peering request sent to {url}");
        Ok(())
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon returned {status}: {text}");
    }
}

async fn cmd_peers_list() -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    let peers = honey_db::federation::list_peers(&pool).await?;
    if peers.is_empty() {
        println!("(no peers)");
        return Ok(());
    }
    println!("{:<52}  {:<10}  {:>6}  {:<5}/{:<5}  url", "fingerprint", "status", "score", "we", "they");
    for p in peers {
        println!(
            "{:<52}  {:<10}  {:>6}  {:<5}/{:<5}  {}",
            p.fingerprint,
            p.status,
            p.local_score,
            yn(p.we_approved_them),
            yn(p.they_approved_us),
            p.url,
        );
    }
    Ok(())
}

async fn cmd_peers_pending() -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    let rows = honey_db::federation::list_pending(&pool).await?;
    if rows.is_empty() {
        println!("(no pending requests)");
        return Ok(());
    }
    for r in rows {
        let bar = "─".repeat(74);
        println!("{bar}");
        println!("  FINGERPRINT (verify out-of-band before approving):");
        println!("    {}", r.fingerprint);
        println!("  Node:    {}", if r.node_name.is_empty() { "(unnamed)" } else { &r.node_name });
        println!("  Contact: {}", if r.contact.is_empty() { "(none)" } else { &r.contact });
        println!("  URL:     {}", r.url);
        if !r.description.is_empty() {
            println!("  Notes:   {}", r.description);
        }
        println!("  Received: {}", r.received_at);
    }
    Ok(())
}

async fn cmd_peers_approve(fp: String) -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    if honey_db::federation::approve(&pool, &fp).await? {
        println!("approved: {fp}");
    } else {
        anyhow::bail!("no pending request with fingerprint {fp}");
    }
    Ok(())
}

async fn cmd_peers_reject(fp: String) -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    if honey_db::federation::reject(&pool, &fp).await? {
        println!("rejected: {fp}");
    } else {
        anyhow::bail!("no pending request with fingerprint {fp}");
    }
    Ok(())
}

async fn cmd_peers_revoke(fp: String, purge: bool) -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    let changed = if purge {
        honey_db::federation::revoke_and_purge(&pool, &fp).await?
    } else {
        honey_db::federation::revoke(&pool, &fp).await?
    };
    if !changed {
        anyhow::bail!("no peer with fingerprint {fp}");
    }
    if purge {
        println!("revoked + purged entries: {fp}");
    } else {
        println!("revoked: {fp}");
    }
    Ok(())
}

async fn cmd_peers_score(fp: String, delta: i32) -> Result<()> {
    let cfg = Config::from_env()?;
    let pool = honey_db::connect(cfg.database_url()?).await?;
    match honey_db::federation::adjust_score(&pool, &fp, delta).await? {
        Some(new) => println!("score adjusted: {fp} → {new}"),
        None => anyhow::bail!("no peer with fingerprint {fp}"),
    }
    Ok(())
}

fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

async fn cmd_reputation_query(peer: String, target: String) -> Result<()> {
    let cfg = Config::from_env()?;
    let client = reqwest::Client::new();
    let endpoint = format!(
        "{}/internal/reputation/query/{}/{}",
        cfg.daemon_internal_url.trim_end_matches('/'),
        peer,
        target,
    );
    let resp = client.post(&endpoint).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon returned {status}: {text}");
    }
    let body: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}
