//! Federation table accessors. Used by the HTTP server, the poller, and the
//! CLI peer subcommands. The Flask admin panel also writes to some of these
//! rows directly — when it does, the daemon picks the change up on its next
//! poll cycle.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PeerRow {
    pub fingerprint: String,
    pub pubkey_b64: String,
    pub url: String,
    pub node_name: String,
    pub contact: String,
    pub status: String,
    pub they_approved_us: bool,
    pub we_approved_them: bool,
    pub local_score: i32,
    pub added_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub last_pull_at: Option<DateTime<Utc>>,
    pub entries_received: i64,
    pub bad_signatures: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PendingRequest {
    pub fingerprint: String,
    pub pubkey_b64: String,
    pub url: String,
    pub node_name: String,
    pub contact: String,
    pub description: String,
    pub received_at: DateTime<Utc>,
}

pub async fn upsert_pending(pool: &PgPool, p: &PendingRequest) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO federation_pending_requests
              (fingerprint, pubkey_b64, url, node_name, contact, description, received_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW())
           ON CONFLICT (fingerprint) DO UPDATE SET
              pubkey_b64  = EXCLUDED.pubkey_b64,
              url         = EXCLUDED.url,
              node_name   = EXCLUDED.node_name,
              contact     = EXCLUDED.contact,
              description = EXCLUDED.description,
              received_at = EXCLUDED.received_at"#,
    )
    .bind(&p.fingerprint)
    .bind(&p.pubkey_b64)
    .bind(&p.url)
    .bind(&p.node_name)
    .bind(&p.contact)
    .bind(&p.description)
    .execute(pool)
    .await
    .context("INSERT federation_pending_requests")?;
    Ok(())
}

pub async fn list_pending(pool: &PgPool) -> Result<Vec<PendingRequest>> {
    sqlx::query_as::<_, PendingRequest>(
        "SELECT * FROM federation_pending_requests ORDER BY received_at DESC",
    )
    .fetch_all(pool)
    .await
    .context("SELECT federation_pending_requests")
}

pub async fn get_pending(pool: &PgPool, fp: &str) -> Result<Option<PendingRequest>> {
    sqlx::query_as::<_, PendingRequest>(
        "SELECT * FROM federation_pending_requests WHERE fingerprint = $1",
    )
    .bind(fp)
    .fetch_optional(pool)
    .await
    .context("SELECT federation_pending_requests")
}

pub async fn list_peers(pool: &PgPool) -> Result<Vec<PeerRow>> {
    sqlx::query_as::<_, PeerRow>("SELECT * FROM federation_peers ORDER BY added_at ASC")
        .fetch_all(pool)
        .await
        .context("SELECT federation_peers")
}

pub async fn get_peer(pool: &PgPool, fp: &str) -> Result<Option<PeerRow>> {
    sqlx::query_as::<_, PeerRow>("SELECT * FROM federation_peers WHERE fingerprint = $1")
        .bind(fp)
        .fetch_optional(pool)
        .await
        .context("SELECT federation_peers WHERE fingerprint")
}

pub async fn get_trusted_peer(pool: &PgPool, fp: &str) -> Result<Option<PeerRow>> {
    sqlx::query_as::<_, PeerRow>(
        "SELECT * FROM federation_peers WHERE fingerprint = $1 AND status = 'trusted'",
    )
    .bind(fp)
    .fetch_optional(pool)
    .await
    .context("SELECT trusted federation_peers")
}

/// Move a pending request into `federation_peers` as trusted, setting
/// `we_approved_them=true`. If the peer row already exists, just bump that flag.
pub async fn approve(pool: &PgPool, fp: &str) -> Result<bool> {
    let mut tx = pool.begin().await.context("BEGIN approve")?;

    let pending = sqlx::query_as::<_, PendingRequest>(
        "SELECT * FROM federation_pending_requests WHERE fingerprint = $1",
    )
    .bind(fp)
    .fetch_optional(&mut *tx)
    .await
    .context("SELECT pending in approve")?;

    let Some(p) = pending else {
        return Ok(false);
    };

    sqlx::query(
        r#"INSERT INTO federation_peers
              (fingerprint, pubkey_b64, url, node_name, contact, status,
               we_approved_them, added_at)
           VALUES ($1, $2, $3, $4, $5, 'trusted', TRUE, NOW())
           ON CONFLICT (fingerprint) DO UPDATE SET
              pubkey_b64       = EXCLUDED.pubkey_b64,
              url              = EXCLUDED.url,
              node_name        = EXCLUDED.node_name,
              contact          = EXCLUDED.contact,
              status           = 'trusted',
              we_approved_them = TRUE"#,
    )
    .bind(&p.fingerprint)
    .bind(&p.pubkey_b64)
    .bind(&p.url)
    .bind(&p.node_name)
    .bind(&p.contact)
    .execute(&mut *tx)
    .await
    .context("INSERT federation_peers in approve")?;

    sqlx::query("DELETE FROM federation_pending_requests WHERE fingerprint = $1")
        .bind(fp)
        .execute(&mut *tx)
        .await
        .context("DELETE pending in approve")?;

    tx.commit().await.context("COMMIT approve")?;
    Ok(true)
}

pub async fn reject(pool: &PgPool, fp: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM federation_pending_requests WHERE fingerprint = $1")
        .bind(fp)
        .execute(pool)
        .await
        .context("DELETE federation_pending_requests")?;
    Ok(r.rows_affected() > 0)
}

pub async fn revoke(pool: &PgPool, fp: &str) -> Result<bool> {
    let r = sqlx::query(
        "UPDATE federation_peers SET status = 'revoked' WHERE fingerprint = $1",
    )
    .bind(fp)
    .execute(pool)
    .await
    .context("UPDATE federation_peers SET status=revoked")?;
    Ok(r.rows_affected() > 0)
}

/// Cascading delete: removes the peer row; FK ON DELETE CASCADE wipes their
/// `federated_wordlist_entries` in one shot.
pub async fn revoke_and_purge(pool: &PgPool, fp: &str) -> Result<bool> {
    let r = sqlx::query("DELETE FROM federation_peers WHERE fingerprint = $1")
        .bind(fp)
        .execute(pool)
        .await
        .context("DELETE federation_peers (purge)")?;
    Ok(r.rows_affected() > 0)
}

/// Manual reputation adjustment, clamped to [-100, +100].
pub async fn adjust_score(pool: &PgPool, fp: &str, delta: i32) -> Result<Option<i32>> {
    let new_score: Option<(i32,)> = sqlx::query_as(
        r#"UPDATE federation_peers
           SET local_score = GREATEST(-100, LEAST(100, local_score + $2))
           WHERE fingerprint = $1
           RETURNING local_score"#,
    )
    .bind(fp)
    .bind(delta)
    .fetch_optional(pool)
    .await
    .context("UPDATE federation_peers SET local_score")?;
    Ok(new_score.map(|(s,)| s))
}

pub async fn bump_bad_signature(pool: &PgPool, fp: &str) -> Result<()> {
    sqlx::query(
        r#"UPDATE federation_peers
           SET bad_signatures = bad_signatures + 1,
               local_score = GREATEST(-100, local_score - 1)
           WHERE fingerprint = $1"#,
    )
    .bind(fp)
    .execute(pool)
    .await
    .context("UPDATE bad_signatures")?;
    Ok(())
}

pub async fn record_pull_success(
    pool: &PgPool,
    fp: &str,
    entries_added: i64,
    pulled_at: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(
        r#"UPDATE federation_peers
           SET last_pull_at = $2,
               last_seen = $2,
               entries_received = entries_received + $3,
               local_score = LEAST(100, local_score + 1)
           WHERE fingerprint = $1"#,
    )
    .bind(fp)
    .bind(pulled_at)
    .bind(entries_added)
    .execute(pool)
    .await
    .context("UPDATE peer pull stats")?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct LocalEntry {
    pub username: String,
    pub password: String,
    pub cnt: i64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Aggregate local-only auth rows since `since`, ordered by `MAX(timestamp)`
/// ascending so the puller can resume from `last_seen` deterministically.
///
/// INVARIANT: this NEVER reads `federated_wordlist_entries`. Don't change that
/// — relaying peer data would cascade trust mistakes across the network.
pub async fn fetch_local_entries(
    pool: &PgPool,
    since: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<LocalEntry>> {
    sqlx::query_as::<_, LocalEntry>(
        r#"SELECT username,
                  password,
                  COUNT(*)::BIGINT AS cnt,
                  MIN("timestamp") AS first_seen,
                  MAX("timestamp") AS last_seen
           FROM auth
           WHERE username IS NOT NULL AND username <> ''
             AND password IS NOT NULL AND password <> ''
             AND "timestamp" >= $1
           GROUP BY username, password
           ORDER BY MAX("timestamp") ASC, username, password
           LIMIT $2"#,
    )
    .bind(since)
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("SELECT auth aggregated entries")
}

/// Upsert one federated entry. Returns true if the row was newly inserted.
pub async fn upsert_federated_entry(
    pool: &PgPool,
    source_fp: &str,
    username: &str,
    password: &str,
    count: i64,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
) -> Result<bool> {
    let r = sqlx::query(
        r#"INSERT INTO federated_wordlist_entries
              (username, password, source_fingerprint, count, first_seen, last_seen)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (username, password, source_fingerprint) DO UPDATE SET
              count      = federated_wordlist_entries.count + EXCLUDED.count,
              last_seen  = GREATEST(federated_wordlist_entries.last_seen, EXCLUDED.last_seen),
              first_seen = LEAST(federated_wordlist_entries.first_seen, EXCLUDED.first_seen)"#,
    )
    .bind(username)
    .bind(password)
    .bind(source_fp)
    .bind(count)
    .bind(first_seen)
    .bind(last_seen)
    .execute(pool)
    .await
    .context("INSERT federated_wordlist_entries")?;
    Ok(r.rows_affected() > 0)
}

/// Trusted peers we've approved — i.e., we can pull from them.
pub async fn pollable_peers(pool: &PgPool) -> Result<Vec<PeerRow>> {
    sqlx::query_as::<_, PeerRow>(
        "SELECT * FROM federation_peers
         WHERE status = 'trusted' AND we_approved_them = TRUE",
    )
    .fetch_all(pool)
    .await
    .context("SELECT pollable peers")
}
