//! Bulk-import Cowrie JSON logs into Postgres. Rust port of import-cowrie-json.py.
//! Idempotent via `ON CONFLICT DO NOTHING` everywhere — safe to re-run.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use tracing::{info, warn};

#[derive(Default, Debug)]
pub struct Counts {
    pub sensors: usize,
    pub clients: usize,
    pub sessions: usize,
    pub auth: usize,
    pub input: usize,
    pub ttylog: usize,
    pub downloads: usize,
    pub fingerprints: usize,
}

pub async fn import_files(pool: &PgPool, paths: &[std::path::PathBuf]) -> Result<Counts> {
    let mut totals = Counts::default();
    for path in paths {
        info!(path = %path.display(), "processing");
        let collected = collect_from_file(path)?;
        let counts = import_collected(pool, collected).await?;
        info!(
            sessions = counts.sessions,
            auth = counts.auth,
            input = counts.input,
            "file done",
        );
        totals.sensors += counts.sensors;
        totals.clients += counts.clients;
        totals.sessions += counts.sessions;
        totals.auth += counts.auth;
        totals.input += counts.input;
        totals.ttylog += counts.ttylog;
        totals.downloads += counts.downloads;
        totals.fingerprints += counts.fingerprints;
    }
    Ok(totals)
}

#[derive(Debug)]
struct Session {
    id: String,
    sensor: String,
    ip: Option<String>,
    starttime: Option<DateTime<Utc>>,
    endtime: Option<DateTime<Utc>>,
    termsize: String,
    client: Option<String>,
}

#[derive(Debug)]
struct AuthRow {
    session: String,
    success: bool,
    username: Option<String>,
    password: Option<String>,
    timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct InputRow {
    session: String,
    timestamp: Option<DateTime<Utc>>,
    realm: String,
    input: String,
    success: bool,
}

#[derive(Debug)]
struct DownloadRow {
    session: String,
    timestamp: Option<DateTime<Utc>>,
    url: Option<String>,
    outfile: String,
    shasum: String,
}

#[derive(Default)]
struct Collected {
    sensors: HashSet<String>,
    clients: HashSet<String>,
    sessions: HashMap<String, Session>,
    auth: Vec<AuthRow>,
    input: Vec<InputRow>,
    ttylog: Vec<(String, String)>,
    downloads: Vec<DownloadRow>,
    fingerprints: Vec<(String, Option<String>, Option<String>)>,
}

fn collect_from_file(path: &Path) -> Result<Collected> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut c = Collected::default();
    let mut tty_seen = HashSet::new();
    for (lineno, line) in BufReader::new(f).lines().enumerate() {
        let line = line.with_context(|| format!("reading {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let ev: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                warn!(path = %path.display(), line = lineno + 1, error = ?e, "skipping malformed event");
                continue;
            }
        };
        ingest_event(&mut c, &mut tty_seen, &ev);
    }
    Ok(c)
}

fn ingest_event(c: &mut Collected, tty_seen: &mut HashSet<(String, String)>, ev: &Value) {
    let eid = ev.get("eventid").and_then(Value::as_str).unwrap_or("");
    let sid = ev
        .get("session")
        .and_then(Value::as_str)
        .map(|s| clean(s));
    let sensor = ev
        .get("sensor")
        .and_then(Value::as_str)
        .map(|s| clean(s))
        .unwrap_or_else(|| "cowrie".to_string());
    let timestamp = ev
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc));
    let src_ip = ev.get("src_ip").and_then(Value::as_str).map(|s| clean(s));

    c.sensors.insert(sensor.clone());

    if let Some(sid_ref) = &sid {
        c.sessions
            .entry(sid_ref.clone())
            .or_insert_with(|| Session {
                id: sid_ref.clone(),
                sensor: sensor.clone(),
                ip: src_ip.clone(),
                starttime: None,
                endtime: None,
                termsize: String::new(),
                client: None,
            });
    }

    let s_opt = sid.as_ref().and_then(|sid| c.sessions.get_mut(sid));

    match eid {
        "cowrie.session.connect" => {
            if let Some(s) = s_opt {
                s.starttime = timestamp;
                s.ip = src_ip;
            }
        }
        "cowrie.session.closed" => {
            if let Some(s) = s_opt {
                s.endtime = timestamp;
            }
        }
        "cowrie.client.version" => {
            let version = ev
                .get("version")
                .and_then(Value::as_str)
                .map(|s| clean(s).chars().take(50).collect::<String>())
                .unwrap_or_default();
            if !version.is_empty() {
                c.clients.insert(version.clone());
            }
            if let Some(s) = s_opt {
                s.client = if version.is_empty() { None } else { Some(version) };
            }
        }
        "cowrie.client.size" => {
            if let Some(s) = s_opt {
                let w = ev.get("width").and_then(Value::as_i64).unwrap_or(0);
                let h = ev.get("height").and_then(Value::as_i64).unwrap_or(0);
                s.termsize = format!("{w}x{h}");
            }
        }
        "cowrie.login.success" | "cowrie.login.failed" => {
            if let Some(sid) = &sid {
                c.auth.push(AuthRow {
                    session: sid.clone(),
                    success: eid == "cowrie.login.success",
                    username: ev.get("username").and_then(Value::as_str).map(clean),
                    password: ev.get("password").and_then(Value::as_str).map(clean),
                    timestamp,
                });
            }
        }
        "cowrie.command.input" => {
            if let Some(sid) = &sid {
                c.input.push(InputRow {
                    session: sid.clone(),
                    timestamp,
                    realm: ev
                        .get("realm")
                        .and_then(Value::as_str)
                        .map(|s| clean(s).chars().take(20).collect())
                        .unwrap_or_default(),
                    input: ev
                        .get("input")
                        .and_then(Value::as_str)
                        .map(clean)
                        .unwrap_or_default(),
                    success: ev.get("success").and_then(Value::as_bool).unwrap_or(false),
                });
            }
        }
        "cowrie.log.open" | "cowrie.log.closed" => {
            let tty = ev
                .get("ttylog")
                .or_else(|| ev.get("filename"))
                .and_then(Value::as_str)
                .map(clean);
            if let (Some(sid), Some(tty)) = (&sid, tty) {
                let key = (sid.clone(), tty.clone());
                if tty_seen.insert(key) {
                    c.ttylog.push((sid.clone(), tty));
                }
            }
        }
        "cowrie.session.file_download" => {
            if let Some(sid) = &sid {
                c.downloads.push(DownloadRow {
                    session: sid.clone(),
                    timestamp,
                    url: ev.get("url").and_then(Value::as_str).map(clean),
                    outfile: ev
                        .get("outfile")
                        .and_then(Value::as_str)
                        .map(clean)
                        .unwrap_or_default(),
                    shasum: ev
                        .get("shasum")
                        .and_then(Value::as_str)
                        .map(clean)
                        .unwrap_or_default(),
                });
            }
        }
        "cowrie.client.fingerprint" => {
            if let Some(sid) = &sid {
                c.fingerprints.push((
                    sid.clone(),
                    ev.get("username").and_then(Value::as_str).map(clean),
                    ev.get("fingerprint").and_then(Value::as_str).map(clean),
                ));
            }
        }
        _ => {}
    }
}

fn clean(s: &str) -> String {
    // Postgres TEXT rejects NUL bytes — strip them like the Python script does.
    s.replace('\0', "")
}

async fn import_collected(pool: &PgPool, c: Collected) -> Result<Counts> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let counts = Counts {
        sensors: c.sensors.len(),
        clients: c.clients.len(),
        sessions: c.sessions.len(),
        auth: c.auth.len(),
        input: c.input.len(),
        ttylog: c.ttylog.len(),
        downloads: c.downloads.len(),
        fingerprints: c.fingerprints.len(),
    };

    for name in &c.sensors {
        sqlx::query("INSERT INTO sensors (ip) VALUES ($1) ON CONFLICT (ip) DO NOTHING")
            .bind(name)
            .execute(&mut *tx)
            .await?;
    }
    let sensor_id: HashMap<String, i32> = sqlx::query_as("SELECT ip, id FROM sensors")
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|(ip, id): (String, i32)| (ip, id))
        .collect();

    for v in c.clients.iter().filter(|v| !v.is_empty()) {
        sqlx::query("INSERT INTO clients (version) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(v)
            .execute(&mut *tx)
            .await?;
    }
    let client_id: HashMap<String, i32> = sqlx::query_as::<_, (Option<String>, i32)>(
        "SELECT version, id FROM clients",
    )
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .filter_map(|(v, id)| v.map(|v| (v, id)))
    .collect();

    for s in c.sessions.values() {
        sqlx::query(
            "INSERT INTO sessions (id, starttime, endtime, sensor, ip, termsize, client)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&s.id)
        .bind(s.starttime)
        .bind(s.endtime)
        .bind(sensor_id.get(&s.sensor))
        .bind(&s.ip)
        .bind(&s.termsize)
        .bind(s.client.as_ref().and_then(|c| client_id.get(c)))
        .execute(&mut *tx)
        .await?;
    }

    for a in &c.auth {
        sqlx::query(
            "INSERT INTO auth (session, success, username, password, timestamp)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING",
        )
        .bind(&a.session)
        .bind(a.success)
        .bind(&a.username)
        .bind(&a.password)
        .bind(a.timestamp)
        .execute(&mut *tx)
        .await?;
    }

    for i in &c.input {
        sqlx::query(
            "INSERT INTO input (session, timestamp, realm, input, success)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING",
        )
        .bind(&i.session)
        .bind(i.timestamp)
        .bind(&i.realm)
        .bind(&i.input)
        .bind(i.success)
        .execute(&mut *tx)
        .await?;
    }

    for (session, tty) in &c.ttylog {
        sqlx::query(
            "INSERT INTO ttylog (session, ttylog) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(session)
        .bind(tty)
        .execute(&mut *tx)
        .await?;
    }

    for d in &c.downloads {
        sqlx::query(
            "INSERT INTO downloads (session, timestamp, url, outfile, shasum)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING",
        )
        .bind(&d.session)
        .bind(d.timestamp)
        .bind(&d.url)
        .bind(&d.outfile)
        .bind(&d.shasum)
        .execute(&mut *tx)
        .await?;
    }

    for (session, username, fingerprint) in &c.fingerprints {
        sqlx::query(
            "INSERT INTO keyfingerprints (session, username, fingerprint)
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(session)
        .bind(username)
        .bind(fingerprint)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(counts)
}
