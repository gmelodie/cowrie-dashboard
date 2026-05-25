//! Wordlist generation job. Reads from the `auth` table (every login attempt)
//! and writes the same per-window files the existing Flask app expects:
//!
//!   {WORDLIST_DIR}/{daily,weekly,monthly,alltime}/{passwords,usernames,
//!     passwords_usernames,trending_passwords,dying_passwords}.txt
//!   {WORDLIST_DIR}/{daily,weekly,monthly,alltime}/{hashcat.rule,john.rule}
//!
//! `novel_passwords.txt` is owned by Phase 2 (bloom filter).
//! `federated_wordlist_entries` merge is owned by Phase 6 — the read path here
//! is structured so that hook will land in one place.

use anyhow::{Context, Result};
use sqlx::PgPool;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::{bloom, rules};

#[derive(Copy, Clone, Debug)]
pub enum Window {
    Daily,
    Weekly,
    Monthly,
    Alltime,
}

impl Window {
    pub const ALL: [Window; 4] = [Self::Daily, Self::Weekly, Self::Monthly, Self::Alltime];

    pub fn subdir(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Alltime => "alltime",
        }
    }

    fn time_filter(self) -> &'static str {
        match self {
            Self::Daily => r#" AND "timestamp" >= NOW() - INTERVAL '1 day'"#,
            Self::Weekly => r#" AND "timestamp" >= NOW() - INTERVAL '7 days'"#,
            Self::Monthly => r#" AND "timestamp" >= NOW() - INTERVAL '30 days'"#,
            Self::Alltime => "",
        }
    }

    /// Time filter on federated rows. Federated entries are pre-aggregated
    /// (count + first_seen/last_seen), so we approximate "recently active" by
    /// filtering on `last_seen`. For windowed lists this may slightly over-
    /// count: a row's full historical count contributes whenever its `last_seen`
    /// falls inside the window. Good enough for v1.
    fn federated_time_filter(self) -> &'static str {
        match self {
            Self::Daily => " AND last_seen >= NOW() - INTERVAL '1 day'",
            Self::Weekly => " AND last_seen >= NOW() - INTERVAL '7 days'",
            Self::Monthly => " AND last_seen >= NOW() - INTERVAL '30 days'",
            Self::Alltime => "",
        }
    }

    fn trend_window(self) -> Option<TrendWindow> {
        match self {
            Self::Daily => Some(TrendWindow { recent: "1 day", baseline: "2 days" }),
            Self::Weekly => Some(TrendWindow { recent: "7 days", baseline: "14 days" }),
            Self::Monthly => Some(TrendWindow { recent: "30 days", baseline: "60 days" }),
            Self::Alltime => None,
        }
    }
}

#[derive(Copy, Clone)]
struct TrendWindow {
    recent: &'static str,
    baseline: &'static str,
}

/// Fetch credentials ranked by frequency, descending (local `auth` rows
/// counted as 1 each + federated rows weighted by their stored `count`).
/// Ties break alphabetically.
async fn fetch_ranked(pool: &PgPool, column: Column, w: Window) -> Result<Vec<String>> {
    let col = column.as_sql();
    let sql = format!(
        r#"WITH combined AS (
               SELECT {col} AS v, 1::BIGINT AS cnt
               FROM auth
               WHERE {col} IS NOT NULL AND {col} <> ''{filter_auth}
               UNION ALL
               SELECT {col} AS v, count AS cnt
               FROM federated_wordlist_entries
               WHERE {col} IS NOT NULL AND {col} <> ''{filter_fed}
           )
           SELECT v
           FROM combined
           GROUP BY v
           ORDER BY SUM(cnt) DESC, v"#,
        col = col,
        filter_auth = w.time_filter(),
        filter_fed = w.federated_time_filter(),
    );
    sqlx::query_scalar::<_, String>(&sql)
        .fetch_all(pool)
        .await
        .with_context(|| format!("fetch_ranked column={col} window={:?}", w))
}

#[derive(Copy, Clone)]
enum Column {
    Password,
    Username,
}

impl Column {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Username => "username",
        }
    }
}

async fn fetch_pairs(pool: &PgPool, w: Window) -> Result<Vec<String>> {
    let sql = format!(
        r#"WITH combined AS (
               SELECT password || ':' || username AS pair, 1::BIGINT AS cnt
               FROM auth
               WHERE username IS NOT NULL AND username <> ''
                 AND password IS NOT NULL AND password <> ''{filter_auth}
               UNION ALL
               SELECT password || ':' || username AS pair, count AS cnt
               FROM federated_wordlist_entries
               WHERE username IS NOT NULL AND username <> ''
                 AND password IS NOT NULL AND password <> ''{filter_fed}
           )
           SELECT pair
           FROM combined
           GROUP BY pair
           ORDER BY SUM(cnt) DESC, pair"#,
        filter_auth = w.time_filter(),
        filter_fed = w.federated_time_filter(),
    );
    sqlx::query_scalar::<_, String>(&sql)
        .fetch_all(pool)
        .await
        .with_context(|| format!("fetch_pairs window={:?}", w))
}

#[derive(Default)]
struct Trends {
    trending: Vec<String>,
    dying: Vec<String>,
    floor: u32,
}

async fn fetch_trends(pool: &PgPool, t: TrendWindow) -> Result<Trends> {
    let sql = format!(
        r#"SELECT
               password,
               COUNT(*) FILTER (WHERE "timestamp" >= NOW() - INTERVAL '{recent}')::BIGINT AS recent_cnt,
               COUNT(*) FILTER (WHERE "timestamp" >= NOW() - INTERVAL '{baseline}'
                            AND "timestamp" <  NOW() - INTERVAL '{recent}')::BIGINT AS baseline_cnt
           FROM auth
           WHERE password IS NOT NULL
             AND password <> ''
             AND "timestamp" >= NOW() - INTERVAL '{baseline}'
           GROUP BY password"#,
        recent = t.recent,
        baseline = t.baseline,
    );
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(&sql)
        .fetch_all(pool)
        .await
        .with_context(|| format!("fetch_trends recent={} baseline={}", t.recent, t.baseline))?;

    if rows.is_empty() {
        return Ok(Trends { floor: 2, ..Default::default() });
    }

    // Poisson floor: for random arrivals std ≈ sqrt(mean), so sqrt(mean) is
    // the noise magnitude expected per password. Anything below it is noise.
    let total: f64 = rows.iter().map(|(_, r, b)| (r + b) as f64).sum();
    let mean = total / rows.len() as f64;
    let floor = 2u32.max(mean.sqrt().round() as u32);

    let mut trending: Vec<(String, i64, i64)> = Vec::new();
    let mut dying: Vec<(String, i64, i64)> = Vec::new();
    for (pw, recent, baseline) in rows {
        if (recent as u32) >= floor && recent > baseline {
            trending.push((pw, recent, baseline));
        } else if (baseline as u32) >= floor && baseline > recent {
            dying.push((pw, recent, baseline));
        }
    }

    // Trending by relative growth (new passwords baseline=0 float to top).
    trending.sort_by(|a, b| {
        let ar = a.1 as f64 / (a.2 as f64).max(0.1);
        let br = b.1 as f64 / (b.2 as f64).max(0.1);
        br.partial_cmp(&ar).unwrap_or(std::cmp::Ordering::Equal)
    });
    // Dying by absolute decline.
    dying.sort_by(|a, b| (b.2 - b.1).cmp(&(a.2 - a.1)));

    Ok(Trends {
        trending: trending.into_iter().map(|(pw, _, _)| pw).collect(),
        dying: dying.into_iter().map(|(pw, _, _)| pw).collect(),
        floor,
    })
}

fn write_lines(path: &Path, lines: &[String]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating wordlist dir {}", parent.display()))?;
    }
    let tmp = path.with_extension(extension_with_tmp(path));
    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("creating tmp {}", tmp.display()))?;
        for line in lines {
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
        }
        f.sync_all().ok();
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn extension_with_tmp(path: &Path) -> String {
    // Build "<original-extension>.tmp" so atomic rename stays on the same dir.
    match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => format!("{ext}.tmp"),
        None => "tmp".to_string(),
    }
}

fn write_rule_lines(path: &Path, rendered: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating wordlist dir {}", parent.display()))?;
    }
    let tmp = path.with_extension(extension_with_tmp(path));
    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("creating tmp {}", tmp.display()))?;
        f.write_all(rendered.as_bytes())?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Run one full pass: every window, every file.
pub async fn run_once(pool: &PgPool, wordlist_dir: &Path, bloom_dir: &Path) -> Result<()> {
    info!(dir = %wordlist_dir.display(), "wordlist generation start");

    bloom::warn_if_legacy(bloom_dir);
    let filter = match bloom::load(bloom_dir) {
        Ok(opt) => opt,
        Err(e) => {
            warn!(error = ?e, "could not load bloom filter; novel_passwords.txt skipped");
            None
        }
    };

    for w in Window::ALL {
        let subdir: PathBuf = wordlist_dir.join(w.subdir());

        let passwords = fetch_ranked(pool, Column::Password, w).await?;
        let usernames = fetch_ranked(pool, Column::Username, w).await?;
        let pairs = fetch_pairs(pool, w).await?;

        write_lines(&subdir.join("passwords.txt"), &passwords)?;
        write_lines(&subdir.join("usernames.txt"), &usernames)?;
        write_lines(&subdir.join("passwords_usernames.txt"), &pairs)?;

        let rs = rules::generate(&passwords);
        write_rule_lines(&subdir.join("hashcat.rule"), &rs.hashcat)?;
        write_rule_lines(&subdir.join("john.rule"), &rs.john)?;

        let mut novel_count = 0usize;
        if let Some(ref f) = filter {
            let novel: Vec<String> = passwords
                .iter()
                .filter(|p| !f.contains(p.as_bytes()))
                .cloned()
                .collect();
            novel_count = novel.len();
            write_lines(&subdir.join("novel_passwords.txt"), &novel)?;
        }

        let trends = match w.trend_window() {
            Some(tw) => fetch_trends(pool, tw).await?,
            None => Trends::default(),
        };
        write_lines(&subdir.join("trending_passwords.txt"), &trends.trending)?;
        write_lines(&subdir.join("dying_passwords.txt"), &trends.dying)?;

        info!(
            window = w.subdir(),
            passwords = passwords.len(),
            usernames = usernames.len(),
            pairs = pairs.len(),
            novel = novel_count,
            trending = trends.trending.len(),
            dying = trends.dying.len(),
            floor = trends.floor,
            "wordlist window done",
        );
    }

    info!("wordlist generation done");
    Ok(())
}
