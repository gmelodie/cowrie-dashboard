//! Nonce dedup table operations.
//!
//! Schema: `federation_seen_nonces` (nonce PK, sender, expires_at).
//! Inserts are racey-safe via PK conflict; the table is GC'd on a timer in
//! the daemon so it doesn't grow unbounded.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

#[derive(Debug, PartialEq, Eq)]
pub enum NonceStatus {
    Fresh,
    Duplicate,
}

/// Atomically check + record a nonce. Returns Fresh if newly inserted, Duplicate
/// if it had already been seen within its retention window.
pub async fn check_and_record(
    pool: &PgPool,
    nonce: &str,
    sender: &str,
    expires_at: DateTime<Utc>,
) -> Result<NonceStatus> {
    let res = sqlx::query(
        r#"INSERT INTO federation_seen_nonces (nonce, sender, expires_at)
           VALUES ($1, $2, $3)
           ON CONFLICT (nonce) DO NOTHING"#,
    )
    .bind(nonce)
    .bind(sender)
    .bind(expires_at)
    .execute(pool)
    .await
    .context("INSERT federation_seen_nonces")?;
    if res.rows_affected() == 0 {
        Ok(NonceStatus::Duplicate)
    } else {
        Ok(NonceStatus::Fresh)
    }
}

/// Delete expired rows. Run on a 60-second tokio interval from the daemon.
pub async fn gc_expired(pool: &PgPool) -> Result<u64> {
    let res = sqlx::query("DELETE FROM federation_seen_nonces WHERE expires_at < NOW()")
        .execute(pool)
        .await
        .context("DELETE expired federation_seen_nonces")?;
    Ok(res.rows_affected())
}
