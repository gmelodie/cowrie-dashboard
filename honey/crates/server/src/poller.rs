//! Peer-pull loop. Every `poll_interval_secs`, ask every peer where
//! `we_approved_them` for entries since `last_pull_at`. Insert their entries
//! into `federated_wordlist_entries` with `source_fingerprint = peer.fingerprint`.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use honey_db::federation::{self, PeerRow};
use honey_protocol::{
    messages::{WordlistFetch, WordlistFetchResponse},
    sign,
};
use tracing::{info, warn};

use crate::state::AppState;

const PAGE_LIMIT: u32 = 5000;

pub async fn run_loop(state: AppState) {
    let interval = std::time::Duration::from_secs(state.config.poll_interval_secs.max(1));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!(?interval, "poller start");
    loop {
        ticker.tick().await;
        if let Err(e) = pull_round(&state).await {
            warn!(error = ?e, "poller round failed");
        }
    }
}

async fn pull_round(state: &AppState) -> Result<()> {
    let peers = federation::pollable_peers(&state.pool).await?;
    for peer in peers {
        if let Err(e) = pull_one(state, &peer).await {
            warn!(fp = %peer.fingerprint, error = ?e, "peer pull failed");
            let _ = federation::bump_bad_signature(&state.pool, &peer.fingerprint).await;
        }
    }
    Ok(())
}

/// Pull from a single peer until either the response is empty or the
/// high-watermark stops advancing. Returns the total number of entries upserted.
pub async fn pull_one(state: &AppState, peer: &PeerRow) -> Result<u64> {
    let mut total: u64 = 0;
    let mut since = peer
        .last_pull_at
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());

    loop {
        let payload = WordlistFetch {
            since: honey_protocol::format_timestamp(since),
            limit: PAGE_LIMIT,
        };
        let env = sign(
            payload,
            &state.fingerprint(),
            state.identity.signing_key(),
            Utc::now(),
        )
        .context("sign wordlist/fetch")?;

        let url = format!("{}/wordlist/fetch", peer.url.trim_end_matches('/'));
        let resp = state
            .http
            .post(&url)
            .json(&env)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("peer returned {status}: {body}"));
        }
        let body: WordlistFetchResponse = resp.json().await.context("decode response")?;

        let n = body.entries.len() as u64;
        for entry in &body.entries {
            let first = honey_protocol::parse_timestamp(&entry.first_seen)
                .ok_or_else(|| anyhow!("bad first_seen"))?;
            let last = honey_protocol::parse_timestamp(&entry.last_seen)
                .ok_or_else(|| anyhow!("bad last_seen"))?;
            federation::upsert_federated_entry(
                &state.pool,
                &peer.fingerprint,
                &entry.username,
                &entry.password,
                entry.count,
                first,
                last,
            )
            .await?;
        }
        total += n;

        let next_since = honey_protocol::parse_timestamp(&body.high_watermark);
        federation::record_pull_success(&state.pool, &peer.fingerprint, n as i64, Utc::now())
            .await?;

        // Stop conditions: empty page, or watermark didn't advance, or short page.
        if n == 0 || body.count < PAGE_LIMIT {
            break;
        }
        let advanced = match next_since {
            Some(t) if t > since => {
                since = t;
                true
            }
            _ => false,
        };
        if !advanced {
            break;
        }
    }

    if total > 0 {
        info!(fp = %peer.fingerprint, entries = total, "peer pull complete");
    }
    Ok(total)
}
