//! `honey init bloom` — download reference wordlists one at a time, stream
//! each into the Bloom filter, then write the result. Replaces bloom-init.py.

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::bloom;

pub async fn run(bloom_dir: &Path, urls: &[String]) -> Result<()> {
    let final_path = bloom::path_in(bloom_dir);
    if final_path.exists() {
        info!(path = %final_path.display(), "bloom filter already exists, skipping");
        return Ok(());
    }
    if urls.is_empty() {
        return Err(anyhow!("BLOOM_WORDLIST_URLS is empty — nothing to build"));
    }

    let client = reqwest::Client::builder()
        .user_agent("honey-init/0.1 (+https://github.com/)")
        .build()
        .context("building http client")?;

    let mut filter = bloom::new_filter();
    let mut total: u64 = 0;

    let n = urls.len();
    for (i, url) in urls.iter().enumerate() {
        info!(idx = i + 1, of = n, url, "downloading wordlist");
        let tmp = tempfile::Builder::new()
            .prefix("honey-bloom-")
            .suffix(".txt")
            .tempfile()
            .context("creating tmp file")?;
        let tmp_path = tmp.path().to_owned();

        download_to(&client, url, &tmp_path).await
            .with_context(|| format!("downloading {url}"))?;

        let added = tokio::task::spawn_blocking({
            let path = tmp_path.clone();
            let mut filter = std::mem::replace(&mut filter, bloom::new_filter());
            move || -> Result<(u64, growable_bloom_filter::GrowableBloom)> {
                let n = bloom::ingest_file(&mut filter, &path)?;
                Ok((n, filter))
            }
        })
        .await
        .context("bloom ingest task")??;
        total += added.0;
        filter = added.1;

        drop(tmp); // explicit unlink
        info!(idx = i + 1, items = total, "tmp deleted; running total");
    }

    let dir = bloom_dir.to_path_buf();
    let path = tokio::task::spawn_blocking(move || bloom::save(&dir, &filter))
        .await
        .context("bloom save task")??;

    info!(items = total, path = %path.display(), "bloom filter written");
    Ok(())
}

async fn download_to(client: &reqwest::Client, url: &str, dest: &Path) -> Result<u64> {
    let resp = client.get(url).send().await.context("GET")?;
    let resp = resp.error_for_status().context("response status")?;
    let mut out = tokio::fs::File::create(dest).await
        .with_context(|| format!("creating {}", dest.display()))?;
    let mut stream = resp.bytes_stream();
    let mut bytes: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading response chunk")?;
        out.write_all(&chunk).await
            .with_context(|| format!("writing {}", dest.display()))?;
        bytes += chunk.len() as u64;
    }
    out.flush().await.ok();
    info!(bytes, "downloaded");
    Ok(bytes)
}

pub fn parse_urls(env_val: &str) -> Vec<String> {
    env_val
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_urls;

    #[test]
    fn parse_urls_splits_on_whitespace() {
        let v = parse_urls("https://a/x.txt  https://b/y.txt\nhttps://c/z.txt");
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], "https://a/x.txt");
        assert_eq!(v[2], "https://c/z.txt");
    }

    #[test]
    fn parse_urls_empty() {
        assert!(parse_urls("").is_empty());
        assert!(parse_urls("   ").is_empty());
    }
}
