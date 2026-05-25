//! Reference Bloom filter for the wordlist generator.
//!
//! File format: bincode-encoded `GrowableBloom`. Not compatible with the
//! Python `pybloom_live` ScalableBloomFilter that lived here before — Phase 2
//! rebuilds the filter from scratch on first run.

use anyhow::{Context, Result};
use growable_bloom_filter::GrowableBloom;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const FILTER_FILE: &str = "reference.bloom";
// 0.001 false-positive matches the Python original.
const DESIRED_FPR: f64 = 0.001;
// Initial capacity hint — the filter grows automatically.
const INITIAL_ITEMS: usize = 1_000_000;

pub fn path_in(dir: &Path) -> PathBuf {
    dir.join(FILTER_FILE)
}

pub fn load(dir: &Path) -> Result<Option<GrowableBloom>> {
    let p = path_in(dir);
    if !p.exists() {
        return Ok(None);
    }
    let f = fs::File::open(&p).with_context(|| format!("opening {}", p.display()))?;
    let filter: GrowableBloom = bincode::deserialize_from(BufReader::new(f))
        .with_context(|| format!("decoding {}", p.display()))?;
    Ok(Some(filter))
}

pub fn save(dir: &Path, filter: &GrowableBloom) -> Result<PathBuf> {
    fs::create_dir_all(dir)
        .with_context(|| format!("creating bloom dir {}", dir.display()))?;
    let final_path = path_in(dir);
    let tmp = final_path.with_extension("bloom.tmp");
    {
        let f = fs::File::create(&tmp)
            .with_context(|| format!("creating tmp {}", tmp.display()))?;
        bincode::serialize_into(BufWriter::new(f), filter)
            .with_context(|| format!("encoding {}", tmp.display()))?;
    }
    fs::rename(&tmp, &final_path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), final_path.display()))?;
    Ok(final_path)
}

/// Stream each word in `text_path` (one per line) into the filter. Skips blanks.
/// Returns the count of items added.
pub fn ingest_file(filter: &mut GrowableBloom, text_path: &Path) -> Result<u64> {
    let f = fs::File::open(text_path)
        .with_context(|| format!("opening {}", text_path.display()))?;
    let r = BufReader::new(f);
    let mut count = 0u64;
    for line in r.split(b'\n') {
        let line = line.with_context(|| format!("reading {}", text_path.display()))?;
        let trimmed = line
            .strip_suffix(b"\r")
            .unwrap_or(&line);
        if trimmed.is_empty() {
            continue;
        }
        // pybloom_live hashes the literal bytes — match that by inserting bytes,
        // not a lossy-UTF8 string. growable-bloom-filter accepts AsRef<[u8]>.
        filter.insert(trimmed);
        count += 1;
        if count % 100_000 == 0 {
            info!(items = count, "bloom ingest progress");
        }
    }
    Ok(count)
}

pub fn new_filter() -> GrowableBloom {
    GrowableBloom::new(DESIRED_FPR, INITIAL_ITEMS)
}

pub fn warn_if_legacy(dir: &Path) {
    let p = path_in(dir);
    if let Ok(meta) = fs::metadata(&p) {
        // Quick heuristic: try to deserialize. If it fails, it's the Python format.
        if let Ok(f) = fs::File::open(&p) {
            if bincode::deserialize_from::<_, GrowableBloom>(BufReader::new(f)).is_err() {
                warn!(
                    path = %p.display(),
                    bytes = meta.len(),
                    "existing bloom file is not in the Rust format \
                     (likely legacy pybloom_live) — delete it to rebuild",
                );
            }
        }
    }
}
