//! `honey init geoip` — download db-ip.com free Country + ASN MMDBs.
//! Replaces scripts/geoip-init.sh. Tries the current month, falls back to the
//! previous month, never blocks dependent services (always exits Ok).

use anyhow::{Context, Result};
use chrono::{Datelike, Months, Utc};
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

const BASE_URL: &str = "https://download.db-ip.com/free";

pub async fn run(geoip_dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(geoip_dir).await
        .with_context(|| format!("creating geoip dir {}", geoip_dir.display()))?;

    let country = geoip_dir.join("country.mmdb");
    let asn = geoip_dir.join("asn.mmdb");

    if country.exists() && asn.exists() {
        info!("geoip databases already exist, skipping");
        return Ok(());
    }

    let now = Utc::now();
    let cur = format!("{:04}-{:02}", now.year(), now.month());
    let prev_dt = now.checked_sub_months(Months::new(1));
    let prev = prev_dt.map(|d| format!("{:04}-{:02}", d.year(), d.month()));

    let client = reqwest::Client::builder()
        .user_agent("honey-init/0.1")
        .build()
        .context("building http client")?;

    let candidates: Vec<String> = std::iter::once(cur).chain(prev).collect();

    if !country.exists() {
        if let Err(e) = download_mmdb(&client, "country", &candidates, &country).await {
            warn!(error = ?e, "country GeoIP unavailable — stats-gen will run without geo");
        }
    }
    if !asn.exists() {
        if let Err(e) = download_mmdb(&client, "asn", &candidates, &asn).await {
            warn!(error = ?e, "ASN GeoIP unavailable — stats-gen will run without ASN");
        }
    }

    Ok(())
}

async fn download_mmdb(
    client: &reqwest::Client,
    kind: &str,
    months: &[String],
    dest: &Path,
) -> Result<()> {
    for month in months {
        let url = format!("{BASE_URL}/dbip-{kind}-lite-{month}.mmdb.gz");
        info!(%url, "trying mmdb");
        match download_and_gunzip(client, &url, dest).await {
            Ok(()) => {
                info!(kind, path = %dest.display(), "mmdb ready");
                return Ok(());
            }
            Err(e) => {
                warn!(%url, error = ?e, "mmdb download failed; trying next");
                let _ = std::fs::remove_file(dest);
            }
        }
    }
    anyhow::bail!("all candidate months failed for {kind}")
}

async fn download_and_gunzip(client: &reqwest::Client, url: &str, dest: &Path) -> Result<()> {
    let resp = client.get(url).send().await.context("GET")?;
    let resp = resp.error_for_status().context("response status")?;

    let gz_path: PathBuf = dest.with_extension("mmdb.gz");
    {
        let mut out = tokio::fs::File::create(&gz_path).await
            .with_context(|| format!("creating {}", gz_path.display()))?;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("reading chunk")?;
            out.write_all(&chunk).await
                .with_context(|| format!("writing {}", gz_path.display()))?;
        }
        out.flush().await.ok();
    }

    // gunzip to dest atomically: decode to dest.tmp, then rename.
    let tmp = dest.with_extension("mmdb.tmp");
    {
        let gz = std::fs::File::open(&gz_path)
            .with_context(|| format!("opening {}", gz_path.display()))?;
        let mut decoder = GzDecoder::new(gz);
        let mut out = std::fs::File::create(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = decoder.read(&mut buf).context("gunzip read")?;
            if n == 0 { break; }
            std::io::Write::write_all(&mut out, &buf[..n])
                .with_context(|| format!("writing {}", tmp.display()))?;
        }
    }
    std::fs::rename(&tmp, dest)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), dest.display()))?;
    let _ = std::fs::remove_file(&gz_path);
    Ok(())
}
