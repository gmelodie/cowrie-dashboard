use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub node_name: String,
    pub contact: String,
    pub federation_bind: String,
    pub public_url: String,
    pub daemon_internal_url: String,
    pub poll_interval_secs: u64,
    pub wordlist_dir: PathBuf,
    pub bloom_dir: PathBuf,
    pub stats_dir: PathBuf,
    pub geoip_dir: PathBuf,
    pub geoip_country_db: PathBuf,
    pub geoip_asn_db: PathBuf,
    database_url: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            data_dir: env_or("HONEY_DATA_DIR", "/data/honey").into(),
            node_name: env_or("HONEY_NODE_NAME", ""),
            contact: env_or("HONEY_CONTACT", ""),
            federation_bind: env_or("HONEY_FEDERATION_BIND", "127.0.0.1:8088"),
            public_url: env_or("HONEY_PUBLIC_URL", "http://127.0.0.1:8088"),
            daemon_internal_url: env_or("HONEY_DAEMON_INTERNAL_URL", "http://127.0.0.1:8088"),
            poll_interval_secs: env_or("HONEY_POLL_INTERVAL_SECS", "10")
                .parse()
                .context("HONEY_POLL_INTERVAL_SECS must be a non-negative integer")?,
            wordlist_dir: env_or("WORDLIST_DIR", "/wordlists").into(),
            bloom_dir: env_or("BLOOM_DIR", "/bloom").into(),
            stats_dir: env_or("STATS_DIR", "/stats").into(),
            geoip_dir: env_or("GEOIP_DIR", "/geoip").into(),
            geoip_country_db: env_or("GEOIP_COUNTRY_DB", "/geoip/country.mmdb").into(),
            geoip_asn_db: env_or("GEOIP_ASN_DB", "/geoip/asn.mmdb").into(),
            database_url: build_database_url().ok(),
        })
    }

    pub fn database_url(&self) -> Result<&str> {
        self.database_url
            .as_deref()
            .context("POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB are not set")
    }
}

fn env_required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing env var: {key}"))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn build_database_url() -> Result<String> {
    let host = env_or("POSTGRES_HOST", "127.0.0.1");
    let port = env_or("POSTGRES_PORT", "5432");
    let user = env_required("POSTGRES_USER")?;
    let pass = env_required("POSTGRES_PASSWORD")?;
    let db = env_required("POSTGRES_DB")?;
    Ok(format!(
        "postgres://{}:{}@{host}:{port}/{}",
        urlencode(&user),
        urlencode(&pass),
        urlencode(&db),
    ))
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
