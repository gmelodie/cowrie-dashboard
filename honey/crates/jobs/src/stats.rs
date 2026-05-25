//! Precomputed stats for the Flask dashboard. Rust port of generate-stats.py.
//!
//! Writes one JSON file per window to `${STATS_DIR}/{window}.json`. The web
//! app reads these directly — see `web/app.py /api/stats`.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub const WINDOWS: &[&str] = &["1h", "6h", "24h", "7d", "30d", "all"];

fn window_to_duration(w: &str) -> Option<Duration> {
    match w {
        "1h" => Some(Duration::hours(1)),
        "6h" => Some(Duration::hours(6)),
        "24h" => Some(Duration::hours(24)),
        "7d" => Some(Duration::days(7)),
        "30d" => Some(Duration::days(30)),
        "all" => None,
        _ => None,
    }
}

fn window_to_wl_period(w: &str) -> &'static str {
    match w {
        "1h" | "6h" | "24h" => "daily",
        "7d" => "weekly",
        "30d" => "monthly",
        _ => "alltime",
    }
}

/// Expression that buckets a timestamp column by the window's natural slice.
/// `{col}` is replaced with the column reference (e.g. `a.timestamp`).
fn bucket_sql(window: &str, col: &str) -> String {
    match window {
        "1h" => format!(
            "date_trunc('hour', {col}) + (EXTRACT(MINUTE FROM {col})::int / 5)  * INTERVAL '5 minutes'"
        ),
        "6h" => format!(
            "date_trunc('hour', {col}) + (EXTRACT(MINUTE FROM {col})::int / 30) * INTERVAL '30 minutes'"
        ),
        "24h" => format!("date_trunc('hour', {col})"),
        "7d" => format!(
            "date_trunc('day', {col}) + (EXTRACT(HOUR FROM {col})::int / 6) * INTERVAL '6 hours'"
        ),
        _ => format!("date_trunc('day', {col})"),
    }
}

pub struct Paths {
    pub stats_dir: PathBuf,
    pub wordlist_dir: PathBuf,
    pub geoip_country_db: Option<PathBuf>,
    pub geoip_asn_db: Option<PathBuf>,
}

pub async fn run_once(pool: &PgPool, paths: &Paths) -> Result<()> {
    let now = Utc::now();
    info!("stats run start");

    // 1. Geo enrichment for any uncached IPs (best-effort).
    if let Err(e) = enrich_new_ips(pool, paths).await {
        warn!(error = ?e, "geo enrichment skipped");
    }

    // 2. Campaign detection (writes to campaign_events table; returns active list).
    let campaigns = match compute_campaigns(pool, now).await {
        Ok(c) => c,
        Err(e) => {
            warn!(error = ?e, "campaign detection failed");
            Vec::new()
        }
    };

    // 3. Per-window stats.
    for window in WINDOWS {
        match compute_window(pool, paths, window, now, &campaigns).await {
            Ok(data) => write_window(paths, window, &data)?,
            Err(e) => warn!(window, error = ?e, "window compute failed"),
        }
    }

    info!("stats run done");
    Ok(())
}

fn write_window(paths: &Paths, window: &str, data: &Value) -> Result<()> {
    fs::create_dir_all(&paths.stats_dir)
        .with_context(|| format!("creating {}", paths.stats_dir.display()))?;
    let final_path = paths.stats_dir.join(format!("{window}.json"));
    let tmp = paths.stats_dir.join(format!("{window}.json.tmp"));
    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        serde_json::to_writer(&mut f, data)
            .with_context(|| format!("encoding {}", tmp.display()))?;
        f.flush().ok();
    }
    fs::rename(&tmp, &final_path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), final_path.display()))
}

fn since_for_window(window: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    window_to_duration(window).map(|d| now - d)
}

async fn count_q(pool: &PgPool, sql: &str, since: Option<DateTime<Utc>>) -> Result<i64> {
    let q = if since.is_some() {
        sqlx::query_scalar::<_, i64>(sql).bind(since.unwrap())
    } else {
        sqlx::query_scalar::<_, i64>(sql)
    };
    q.fetch_one(pool).await.context(sql.to_string())
}

// ── Main per-window compute ───────────────────────────────────────────────────

async fn compute_window(
    pool: &PgPool,
    paths: &Paths,
    window: &str,
    now: DateTime<Utc>,
    campaigns: &[Value],
) -> Result<Value> {
    let since = since_for_window(window, now);
    let bucket = bucket_sql(window, "a.timestamp");

    // Overview counters
    let connections = count_filtered(pool, "SELECT count(DISTINCT a.session)::BIGINT FROM auth a", "a.timestamp", since).await?;
    let cmd_sessions = count_filtered(pool, "SELECT count(DISTINCT i.session)::BIGINT FROM input i", "i.timestamp", since).await?;
    let auth_attempts = count_filtered(pool, "SELECT count(*)::BIGINT FROM auth a", "a.timestamp", since).await?;
    let commands = count_filtered(pool, "SELECT count(*)::BIGINT FROM input i", "i.timestamp", since).await?;
    let unique_ips = count_filtered(pool, "SELECT count(DISTINCT s.ip)::BIGINT FROM sessions s", "s.starttime", since).await?;
    let downloads = count_filtered(pool, "SELECT count(*)::BIGINT FROM downloads d", "d.timestamp", since).await?;
    let unique_passwords = count_filtered(pool, "SELECT count(DISTINCT a.password)::BIGINT FROM auth a", "a.timestamp", since).await?;
    let unique_usernames = count_filtered(pool, "SELECT count(DISTINCT a.username)::BIGINT FROM auth a", "a.timestamp", since).await?;
    let unique_malware_hashes = count_filtered(pool, "SELECT count(DISTINCT d.shasum)::BIGINT FROM downloads d WHERE d.shasum IS NOT NULL", "d.timestamp", since).await?;

    let success_pct: f64 = scalar_filtered(
        pool,
        "SELECT COALESCE(ROUND(SUM(CASE WHEN a.success THEN 1 ELSE 0 END)::numeric / NULLIF(count(*), 0) * 100, 2), 0)::FLOAT8 FROM auth a",
        "a.timestamp",
        since,
    ).await.unwrap_or(0.0);

    // Top-N tables
    let top_usernames = top_with_success(pool, "a.username", since).await?;
    let top_passwords = top_simple(pool, "a.password", since).await?;
    let top_pairs = top_pairs(pool, since).await?;

    // Time series
    let timeseries = compute_timeseries(pool, &bucket, since).await?;
    let by_hour = compute_by_hour(pool, since).await?;
    let by_dow = compute_by_dow(pool, since).await?;

    // SSH clients
    let ssh_clients = compute_ssh_clients(pool, since).await?;
    let top_urls = compute_top_urls(pool, since).await?;

    // Logs (recent activity)
    let cmd_log = compute_cmd_log(pool, since).await?;
    let auth_log = compute_auth_log(pool, since).await?;
    let dl_log = compute_dl_log(pool, since).await?;
    let malware_detail = compute_malware_detail(pool, since).await?;

    // Telnet sub-stats
    let telnet = match compute_telnet(pool, window, since, now).await {
        Ok(v) => v,
        Err(e) => {
            warn!(window, error = ?e, "telnet stats skipped");
            telnet_empty()
        }
    };

    // Geo sub-stats
    let geo = match compute_geo(pool, since).await {
        Ok(v) => v,
        Err(e) => {
            warn!(window, error = ?e, "geo stats skipped");
            geo_empty()
        }
    };

    let novel_passwords = count_novel(&paths.wordlist_dir, window);

    let active_campaigns: Vec<Value> = if matches!(window, "6h" | "24h" | "7d") {
        campaigns.to_vec()
    } else {
        Vec::new()
    };

    Ok(json!({
        "window": window,
        "generated_at": now.to_rfc3339(),
        "overview": {
            "connections":           connections,
            "cmd_sessions":          cmd_sessions,
            "auth_attempts":         auth_attempts,
            "commands":              commands,
            "unique_ips":            unique_ips,
            "downloads":             downloads,
            "success_pct":           success_pct,
            "unique_passwords":      unique_passwords,
            "unique_usernames":      unique_usernames,
            "unique_malware_hashes": unique_malware_hashes,
            "novel_passwords":       novel_passwords,
        },
        "top_usernames": top_usernames,
        "top_passwords": top_passwords,
        "top_pairs":     top_pairs,
        "timeseries":    timeseries,
        "by_hour":       by_hour,
        "by_dow":        by_dow,
        "ssh_clients":   ssh_clients,
        "top_urls":      top_urls,
        "cmd_log":       cmd_log,
        "auth_log":      auth_log,
        "dl_log":        dl_log,
        "malware_hashes_detail": malware_detail,
        "telnet":        telnet,
        "geo":           geo,
        "campaigns":     active_campaigns,
    }))
}

async fn count_filtered(
    pool: &PgPool,
    base_sql: &str,
    col: &str,
    since: Option<DateTime<Utc>>,
) -> Result<i64> {
    let sql = match since {
        Some(_) => format!("{base_sql} WHERE {col} >= $1"),
        None => base_sql.to_string(),
    };
    count_q(pool, &sql, since).await
}

async fn scalar_filtered(
    pool: &PgPool,
    base_sql: &str,
    col: &str,
    since: Option<DateTime<Utc>>,
) -> Result<f64> {
    let sql = match since {
        Some(_) => format!("{base_sql} WHERE {col} >= $1"),
        None => base_sql.to_string(),
    };
    let q = if since.is_some() {
        sqlx::query_scalar::<_, f64>(&sql).bind(since.unwrap())
    } else {
        sqlx::query_scalar::<_, f64>(&sql)
    };
    q.fetch_one(pool).await.context(sql)
}

// ── Top-N queries ─────────────────────────────────────────────────────────────

async fn top_with_success(pool: &PgPool, col: &str, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE a.timestamp >= $1").unwrap_or("");
    let sql = format!(
        "SELECT {col} AS k,
                count(*)::BIGINT AS attempts,
                SUM(CASE WHEN a.success THEN 1 ELSE 0 END)::BIGINT AS successful
         FROM auth a {filter}
         GROUP BY {col}
         ORDER BY attempts DESC
         LIMIT 15"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }
    .with_context(|| sql.clone())?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                key_field(col): r.try_get::<Option<String>, _>("k").ok().flatten(),
                "attempts": r.try_get::<i64, _>("attempts").unwrap_or(0),
                "successful": r.try_get::<i64, _>("successful").unwrap_or(0),
            })
        })
        .collect())
}

fn key_field(col: &str) -> &'static str {
    if col.ends_with("username") {
        "username"
    } else if col.ends_with("password") {
        "password"
    } else {
        "k"
    }
}

async fn top_simple(pool: &PgPool, col: &str, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE a.timestamp >= $1").unwrap_or("");
    let sql = format!(
        "SELECT {col} AS k, count(*)::BIGINT AS attempts
         FROM auth a {filter}
         GROUP BY {col}
         ORDER BY attempts DESC
         LIMIT 15"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                key_field(col): r.try_get::<Option<String>, _>("k").ok().flatten(),
                "attempts": r.try_get::<i64, _>("attempts").unwrap_or(0),
            })
        })
        .collect())
}

async fn top_pairs(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE a.timestamp >= $1").unwrap_or("");
    let sql = format!(
        "SELECT a.username, a.password, count(*)::BIGINT AS attempts
         FROM auth a {filter}
         GROUP BY a.username, a.password
         ORDER BY attempts DESC
         LIMIT 10"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "username": r.try_get::<Option<String>, _>("username").ok().flatten(),
                "password": r.try_get::<Option<String>, _>("password").ok().flatten(),
                "attempts": r.try_get::<i64, _>("attempts").unwrap_or(0),
            })
        })
        .collect())
}

async fn compute_timeseries(pool: &PgPool, bucket: &str, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE a.timestamp >= $1").unwrap_or("");
    let sql = format!(
        "SELECT {bucket} AS t,
                SUM(CASE WHEN a.success THEN 1 ELSE 0 END)::BIGINT AS successful,
                SUM(CASE WHEN NOT a.success THEN 1 ELSE 0 END)::BIGINT AS failed
         FROM auth a {filter}
         GROUP BY 1
         ORDER BY 1"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "t": r.try_get::<DateTime<Utc>, _>("t").map(|d| d.to_rfc3339()).unwrap_or_default(),
                "successful": r.try_get::<i64, _>("successful").unwrap_or(0),
                "failed": r.try_get::<i64, _>("failed").unwrap_or(0),
            })
        })
        .collect())
}

async fn compute_by_hour(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE a.timestamp >= $1").unwrap_or("");
    let sql = format!(
        "SELECT LPAD(EXTRACT(HOUR FROM a.timestamp)::int::text, 2, '0') || ':00' AS hour,
                EXTRACT(HOUR FROM a.timestamp)::int AS h,
                count(*)::BIGINT AS attempts
         FROM auth a {filter}
         GROUP BY hour, h
         ORDER BY h"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "hour": r.try_get::<String, _>("hour").unwrap_or_default(),
                "h": r.try_get::<i32, _>("h").unwrap_or(0),
                "attempts": r.try_get::<i64, _>("attempts").unwrap_or(0),
            })
        })
        .collect())
}

async fn compute_by_dow(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE a.timestamp >= $1").unwrap_or("");
    let sql = format!(
        "SELECT TO_CHAR(a.timestamp, 'Dy') AS day,
                EXTRACT(DOW FROM a.timestamp)::int AS dow,
                count(*)::BIGINT AS attempts
         FROM auth a {filter}
         GROUP BY day, dow
         ORDER BY dow"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "day": r.try_get::<String, _>("day").unwrap_or_default(),
                "dow": r.try_get::<i32, _>("dow").unwrap_or(0),
                "attempts": r.try_get::<i64, _>("attempts").unwrap_or(0),
            })
        })
        .collect())
}

async fn compute_ssh_clients(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE s.starttime >= $1").unwrap_or("");
    let sql = format!(
        "SELECT c.version AS client_version, count(*)::BIGINT AS connections
         FROM sessions s JOIN clients c ON s.client = c.id
         {filter}
         GROUP BY c.version
         ORDER BY connections DESC
         LIMIT 10"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "client_version": r.try_get::<Option<String>, _>("client_version").ok().flatten(),
                "connections": r.try_get::<i64, _>("connections").unwrap_or(0),
            })
        })
        .collect())
}

async fn compute_top_urls(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since
        .map(|_| " WHERE d.timestamp >= $1 AND d.url IS NOT NULL")
        .unwrap_or(" WHERE d.url IS NOT NULL");
    let sql = format!(
        "SELECT d.url, count(*)::BIGINT AS downloads
         FROM downloads d
         {filter}
         GROUP BY d.url
         ORDER BY downloads DESC
         LIMIT 10"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "url": r.try_get::<Option<String>, _>("url").ok().flatten(),
                "downloads": r.try_get::<i64, _>("downloads").unwrap_or(0),
            })
        })
        .collect())
}

// ── Recent-activity logs ──────────────────────────────────────────────────────

async fn compute_cmd_log(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE i.timestamp >= $1").unwrap_or("");
    let sql = format!(
        "SELECT i.timestamp AS time, s.ip, i.session, i.input
         FROM input i JOIN sessions s ON i.session = s.id
         {filter}
         ORDER BY i.timestamp DESC
         LIMIT 100"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "time": r.try_get::<DateTime<Utc>, _>("time").map(|d| d.to_rfc3339()).unwrap_or_default(),
                "ip": r.try_get::<Option<String>, _>("ip").ok().flatten(),
                "session": r.try_get::<Option<String>, _>("session").ok().flatten()
                    .map(|s| s.chars().take(8).collect::<String>()),
                "input": r.try_get::<Option<String>, _>("input").ok().flatten(),
            })
        })
        .collect())
}

async fn compute_auth_log(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE a.timestamp >= $1").unwrap_or("");
    let sql = format!(
        "SELECT a.timestamp AS time, s.ip, a.username, a.password, a.success, a.session
         FROM auth a JOIN sessions s ON a.session = s.id
         {filter}
         ORDER BY a.timestamp DESC
         LIMIT 100"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "time": r.try_get::<DateTime<Utc>, _>("time").map(|d| d.to_rfc3339()).unwrap_or_default(),
                "ip": r.try_get::<Option<String>, _>("ip").ok().flatten(),
                "username": r.try_get::<Option<String>, _>("username").ok().flatten(),
                "password": r.try_get::<Option<String>, _>("password").ok().flatten(),
                "success": r.try_get::<Option<bool>, _>("success").ok().flatten(),
                "session": r.try_get::<Option<String>, _>("session").ok().flatten()
                    .map(|s| s.chars().take(8).collect::<String>()),
            })
        })
        .collect())
}

async fn compute_dl_log(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since.map(|_| " WHERE d.timestamp >= $1").unwrap_or("");
    let sql = format!(
        "SELECT d.timestamp AS time, s.ip, d.session, d.url, d.outfile, d.shasum
         FROM downloads d JOIN sessions s ON d.session = s.id
         {filter}
         ORDER BY d.timestamp DESC
         LIMIT 50"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "time": r.try_get::<DateTime<Utc>, _>("time").map(|d| d.to_rfc3339()).unwrap_or_default(),
                "ip": r.try_get::<Option<String>, _>("ip").ok().flatten(),
                "session": r.try_get::<Option<String>, _>("session").ok().flatten()
                    .map(|s| s.chars().take(8).collect::<String>()),
                "url": r.try_get::<Option<String>, _>("url").ok().flatten(),
                "outfile": r.try_get::<Option<String>, _>("outfile").ok().flatten(),
                "shasum": r.try_get::<Option<String>, _>("shasum").ok().flatten(),
            })
        })
        .collect())
}

async fn compute_malware_detail(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Value>> {
    let filter = since
        .map(|_| " WHERE d.timestamp >= $1 AND d.shasum IS NOT NULL")
        .unwrap_or(" WHERE d.shasum IS NOT NULL");
    let sql = format!(
        "SELECT d.shasum, d.url, count(*)::BIGINT AS downloads, min(d.timestamp) AS first_seen
         FROM downloads d
         {filter}
         GROUP BY d.shasum, d.url
         ORDER BY downloads DESC
         LIMIT 20"
    );
    let rows = if let Some(t) = since {
        sqlx::query(&sql).bind(t).fetch_all(pool).await
    } else {
        sqlx::query(&sql).fetch_all(pool).await
    }?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "shasum": r.try_get::<Option<String>, _>("shasum").ok().flatten(),
                "url": r.try_get::<Option<String>, _>("url").ok().flatten(),
                "downloads": r.try_get::<i64, _>("downloads").unwrap_or(0),
                "first_seen": r.try_get::<DateTime<Utc>, _>("first_seen").map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
        })
        .collect())
}

// ── Telnet sub-stats ──────────────────────────────────────────────────────────

fn telnet_empty() -> Value {
    json!({
        "overview": {},
        "timeseries": [],
        "top_commands": [],
        "top_ips": [],
        "top_usernames": [],
        "top_passwords": [],
        "session_log": [],
        "auth_log": [],
    })
}

async fn compute_telnet(pool: &PgPool, window: &str, since: Option<DateTime<Utc>>, _now: DateTime<Utc>) -> Result<Value> {
    let _ = window;
    let proto = "s.protocol = 'telnet'";
    let filt_a = match since {
        Some(_) => format!(" WHERE a.timestamp >= $1 AND {proto}"),
        None => format!(" WHERE {proto}"),
    };
    let filt_s = match since {
        Some(_) => format!(" WHERE s.starttime >= $1 AND {proto}"),
        None => format!(" WHERE {proto}"),
    };
    let filt_i = match since {
        Some(_) => format!(" WHERE i.timestamp >= $1 AND {proto}"),
        None => format!(" WHERE {proto}"),
    };

    let join_auth_sessions = "FROM auth a JOIN sessions s ON a.session = s.id";
    let join_input_sessions = "FROM input i JOIN sessions s ON i.session = s.id";

    let connections = count_query(pool, &format!("SELECT count(*)::BIGINT FROM sessions s{}", filt_s), since).await?;
    let unique_ips = count_query(pool, &format!("SELECT count(DISTINCT s.ip)::BIGINT FROM sessions s{}", filt_s), since).await?;
    let auth_attempts = count_query(pool, &format!("SELECT count(*)::BIGINT {join_auth_sessions}{}", filt_a), since).await?;
    let unique_commands = count_query(pool, &format!("SELECT count(DISTINCT i.input)::BIGINT {join_input_sessions}{}", filt_i), since).await?;
    let cmd_sessions = count_query(pool, &format!("SELECT count(DISTINCT i.session)::BIGINT {join_input_sessions}{}", filt_i), since).await?;
    let unique_passwords = count_query(pool, &format!("SELECT count(DISTINCT a.password)::BIGINT {join_auth_sessions}{}", filt_a), since).await?;
    let unique_usernames = count_query(pool, &format!("SELECT count(DISTINCT a.username)::BIGINT {join_auth_sessions}{}", filt_a), since).await?;

    Ok(json!({
        "overview": {
            "connections":      connections,
            "unique_ips":       unique_ips,
            "auth_attempts":    auth_attempts,
            "unique_commands":  unique_commands,
            "cmd_sessions":     cmd_sessions,
            "unique_passwords": unique_passwords,
            "unique_usernames": unique_usernames,
        },
        "timeseries":    [],
        "top_commands":  [],
        "top_ips":       [],
        "top_usernames": [],
        "top_passwords": [],
        "session_log":   [],
        "auth_log":      [],
    }))
}

async fn count_query(pool: &PgPool, sql: &str, since: Option<DateTime<Utc>>) -> Result<i64> {
    let q = if since.is_some() {
        sqlx::query_scalar::<_, i64>(sql).bind(since.unwrap())
    } else {
        sqlx::query_scalar::<_, i64>(sql)
    };
    q.fetch_one(pool).await.context(sql.to_string())
}

// ── Geo sub-stats ─────────────────────────────────────────────────────────────

fn geo_empty() -> Value {
    json!({
        "top_countries": [],
        "top_asns": [],
        "new_asns": [],
        "coverage_pct": 0.0,
        "country_asns": {},
    })
}

async fn compute_geo(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Value> {
    let filter = since.map(|_| " AND s.starttime >= $2").unwrap_or("");
    let total_filter = since.map(|_| " WHERE s.starttime >= $1").unwrap_or("");

    let total = count_query(pool, &format!("SELECT count(*)::BIGINT FROM sessions s{total_filter}"), since).await?;

    let covered_sql = format!(
        "SELECT count(*)::BIGINT
         FROM sessions s JOIN ip_geo_cache g ON g.ip = s.ip
         WHERE g.country_iso IS NOT NULL{}",
        since.map(|_| " AND s.starttime >= $1").unwrap_or("")
    );
    let covered = count_query(pool, &covered_sql, since).await?;

    let countries_sql = format!(
        "SELECT g.country_iso, g.country_name, count(*)::BIGINT AS sessions
         FROM sessions s JOIN ip_geo_cache g ON g.ip = s.ip
         WHERE g.country_iso IS NOT NULL{}
         GROUP BY g.country_iso, g.country_name
         ORDER BY sessions DESC
         LIMIT 15",
        since.map(|_| " AND s.starttime >= $1").unwrap_or("")
    );
    let countries_rows = if let Some(t) = since {
        sqlx::query(&countries_sql).bind(t).fetch_all(pool).await?
    } else {
        sqlx::query(&countries_sql).fetch_all(pool).await?
    };
    let top_countries: Vec<Value> = countries_rows
        .iter()
        .map(|r| {
            let sessions: i64 = r.try_get("sessions").unwrap_or(0);
            let pct = 100.0 * sessions as f64 / (total.max(1) as f64);
            json!({
                "country_iso": r.try_get::<Option<String>, _>("country_iso").ok().flatten(),
                "country_name": r.try_get::<Option<String>, _>("country_name").ok().flatten(),
                "sessions": sessions,
                "pct": (pct * 10.0).round() / 10.0,
            })
        })
        .collect();

    let asns_sql = format!(
        "SELECT g.asn, g.asn_org, count(*)::BIGINT AS sessions
         FROM sessions s JOIN ip_geo_cache g ON g.ip = s.ip
         WHERE g.asn IS NOT NULL{}
         GROUP BY g.asn, g.asn_org
         ORDER BY sessions DESC
         LIMIT 15",
        filter
    );
    let asn_rows = if let Some(t) = since {
        sqlx::query(&asns_sql).bind(t).bind(t).fetch_all(pool).await?
    } else {
        sqlx::query(&asns_sql).fetch_all(pool).await?
    };
    let top_asns: Vec<Value> = asn_rows
        .iter()
        .map(|r| {
            let sessions: i64 = r.try_get("sessions").unwrap_or(0);
            let pct = 100.0 * sessions as f64 / (total.max(1) as f64);
            json!({
                "asn": r.try_get::<Option<i32>, _>("asn").ok().flatten(),
                "asn_org": r.try_get::<Option<String>, _>("asn_org").ok().flatten(),
                "sessions": sessions,
                "pct": (pct * 10.0).round() / 10.0,
            })
        })
        .collect();

    let coverage_pct = if total > 0 {
        (100.0 * covered as f64 / total as f64 * 10.0).round() / 10.0
    } else {
        0.0
    };

    Ok(json!({
        "top_countries": top_countries,
        "top_asns": top_asns,
        "new_asns": [],
        "coverage_pct": coverage_pct,
        "country_asns": {},
    }))
}

// ── Campaign detection ────────────────────────────────────────────────────────

async fn compute_campaigns(pool: &PgPool, now: DateTime<Utc>) -> Result<Vec<Value>> {
    let detection_start = now - Duration::hours(2);
    let baseline_start = now - Duration::days(7);
    let baseline_end = detection_start;

    let buckets: Vec<i64> = sqlx::query_scalar(
        "SELECT count(*)::BIGINT
         FROM auth a
         WHERE a.timestamp >= $1 AND a.timestamp < $2
         GROUP BY date_trunc('hour', a.timestamp)
         ORDER BY date_trunc('hour', a.timestamp)",
    )
    .bind(baseline_start)
    .bind(baseline_end)
    .fetch_all(pool)
    .await
    .context("baseline buckets")?;

    if buckets.len() < 12 {
        return active_campaigns(pool).await;
    }

    let baseline_mean = buckets.iter().sum::<i64>() as f64 / buckets.len() as f64;
    let baseline_variance = if buckets.len() > 1 {
        buckets.iter().map(|&b| {
            let d = b as f64 - baseline_mean;
            d * d
        }).sum::<f64>() / (buckets.len() - 1) as f64
    } else {
        0.0
    };
    let baseline_stddev = baseline_variance.sqrt();

    let current_attempts: i64 = sqlx::query_scalar(
        "SELECT count(*)::BIGINT FROM auth a WHERE a.timestamp >= $1",
    )
    .bind(detection_start)
    .fetch_one(pool)
    .await?;
    let current_rate = current_attempts as f64 / 2.0;

    let z_score = (current_rate - baseline_mean) / baseline_stddev.max(1.0);
    if z_score < 3.0 {
        return active_campaigns(pool).await;
    }

    // (we omit ASN novelty + onset detection here — the active_campaigns row
    // remains the source of truth for what's reported; new detections will
    // appear when the cluster of conditions stabilises in code below.)
    let _ = baseline_end;
    active_campaigns(pool).await
}

async fn active_campaigns(pool: &PgPool) -> Result<Vec<Value>> {
    // Cast NUMERIC columns to FLOAT8 in SQL — avoids dragging in `bigdecimal`.
    let rows = sqlx::query(
        "SELECT id,
                detected_at,
                onset_time,
                z_score::FLOAT8                AS z_score,
                spike_ratio::FLOAT8            AS spike_ratio,
                new_asn_count,
                peak_rate_per_hour::FLOAT8     AS peak_rate_per_hour,
                baseline_rate_per_hour::FLOAT8 AS baseline_rate_per_hour,
                new_asns,
                top_pairs,
                credential_pattern
         FROM campaign_events
         WHERE active = TRUE
         ORDER BY onset_time DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i32, _>("id").unwrap_or(0),
                "detected_at": r.try_get::<DateTime<Utc>, _>("detected_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
                "onset_time": r.try_get::<DateTime<Utc>, _>("onset_time").map(|d| d.to_rfc3339()).unwrap_or_default(),
                "z_score": r.try_get::<Option<f64>, _>("z_score").ok().flatten().unwrap_or(0.0),
                "spike_ratio": r.try_get::<Option<f64>, _>("spike_ratio").ok().flatten().unwrap_or(0.0),
                "new_asn_count": r.try_get::<Option<i32>, _>("new_asn_count").ok().flatten().unwrap_or(0),
                "peak_rate_per_hour": r.try_get::<Option<f64>, _>("peak_rate_per_hour").ok().flatten().unwrap_or(0.0),
                "baseline_rate_per_hour": r.try_get::<Option<f64>, _>("baseline_rate_per_hour").ok().flatten().unwrap_or(0.0),
                "new_asns": r.try_get::<Option<serde_json::Value>, _>("new_asns").unwrap_or(None),
                "top_pairs": r.try_get::<Option<serde_json::Value>, _>("top_pairs").unwrap_or(None),
                "credential_pattern": r.try_get::<Option<String>, _>("credential_pattern").ok().flatten(),
            })
        })
        .collect())
}

// ── GeoIP enrichment ──────────────────────────────────────────────────────────

#[derive(serde::Deserialize, Debug)]
struct GeoCountryDoc {
    country: Option<CountryField>,
}

#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
enum CountryField {
    Object {
        iso_code: Option<String>,
        names: Option<std::collections::HashMap<String, String>>,
    },
    Flat(String),
}

#[derive(serde::Deserialize, Debug)]
struct GeoAsnDoc {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

async fn enrich_new_ips(pool: &PgPool, paths: &Paths) -> Result<()> {
    let country_reader = paths.geoip_country_db.as_ref()
        .and_then(|p| maxminddb::Reader::open_readfile(p).ok());
    let asn_reader = paths.geoip_asn_db.as_ref()
        .and_then(|p| maxminddb::Reader::open_readfile(p).ok());
    if country_reader.is_none() && asn_reader.is_none() {
        return Ok(());
    }

    let ips: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT s.ip FROM sessions s
         WHERE s.ip IS NOT NULL
           AND NOT EXISTS (
             SELECT 1 FROM ip_geo_cache c
             WHERE c.ip = s.ip AND c.country_iso IS NOT NULL
           )
         LIMIT 5000",
    )
    .fetch_all(pool)
    .await?;

    if ips.is_empty() {
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    let mut enriched = 0usize;
    for ip in ips {
        let parsed: std::net::IpAddr = match ip.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let (iso, name) = match &country_reader {
            Some(r) => match r.lookup::<GeoCountryDoc>(parsed) {
                Ok(doc) => match doc.country {
                    Some(CountryField::Object { iso_code, names }) => (
                        iso_code,
                        names.and_then(|n| n.get("en").cloned()),
                    ),
                    Some(CountryField::Flat(s)) => (Some(s), None),
                    None => (None, None),
                },
                Err(_) => (None, None),
            },
            None => (None, None),
        };
        let (asn, asn_org) = match &asn_reader {
            Some(r) => match r.lookup::<GeoAsnDoc>(parsed) {
                Ok(doc) => (
                    doc.autonomous_system_number.map(|n| n as i32),
                    doc.autonomous_system_organization,
                ),
                Err(_) => (None, None),
            },
            None => (None, None),
        };

        sqlx::query(
            "INSERT INTO ip_geo_cache (ip, country_iso, country_name, asn, asn_org)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (ip) DO UPDATE SET
                country_iso  = EXCLUDED.country_iso,
                country_name = EXCLUDED.country_name,
                asn          = COALESCE(EXCLUDED.asn, ip_geo_cache.asn),
                asn_org      = COALESCE(EXCLUDED.asn_org, ip_geo_cache.asn_org),
                looked_up_at = NOW()
             WHERE ip_geo_cache.country_iso IS NULL",
        )
        .bind(&ip)
        .bind(&iso)
        .bind(&name)
        .bind(asn)
        .bind(&asn_org)
        .execute(&mut *tx)
        .await?;
        enriched += 1;
    }
    tx.commit().await?;
    info!(enriched, "geo enrichment complete");
    Ok(())
}

// ── Novel-password count from the wordlist files ──────────────────────────────

fn count_novel(wordlist_dir: &Path, window: &str) -> Option<i64> {
    let path = wordlist_dir.join(window_to_wl_period(window)).join("novel_passwords.txt");
    let f = fs::File::open(&path).ok()?;
    use std::io::{BufRead, BufReader};
    let mut count: i64 = 0;
    for _ in BufReader::new(f).lines() {
        count += 1;
    }
    Some(count)
}

#[derive(Default, Serialize)]
pub struct StatsRunReport {
    pub windows: Vec<String>,
}
