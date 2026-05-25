use anyhow::{Context, Result};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

pub use sqlx;

pub mod federation;

pub async fn connect(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .context("connecting to postgres")
}

pub async fn ping(pool: &PgPool) -> Result<()> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(pool)
        .await
        .context("postgres SELECT 1")?;
    Ok(())
}
