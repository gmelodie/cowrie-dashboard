//! Outbound HTTP — signed envelopes the daemon sends to other peers.

use anyhow::{Context, Result};
use chrono::Utc;
use honey_db::federation::PeerRow;
use honey_protocol::{
    messages::{PeerRequest, ReputationQuery, ReputationView},
    sign,
};

use crate::state::AppState;

pub async fn send_peer_request(
    state: &AppState,
    target_url: &str,
    node_name: &str,
    contact: &str,
    description: &str,
) -> Result<()> {
    let payload = PeerRequest {
        pubkey_b64: state.identity.pubkey_b64(),
        url: state.config.public_url.clone(),
        node_name: if node_name.is_empty() {
            state.config.node_name.clone()
        } else {
            node_name.to_string()
        },
        contact: if contact.is_empty() {
            state.config.contact.clone()
        } else {
            contact.to_string()
        },
        description: description.to_string(),
    };
    let env = sign(
        payload,
        &state.fingerprint(),
        state.identity.signing_key(),
        Utc::now(),
    )
    .context("signing peer request")?;

    let url = format!("{}/peer/request", target_url.trim_end_matches('/'));
    let resp = state
        .http
        .post(&url)
        .json(&env)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("peer returned {status}: {body}");
    }
    Ok(())
}

pub async fn query_reputation(
    state: &AppState,
    peer: &PeerRow,
    target_fp: &str,
) -> Result<ReputationView> {
    let payload = ReputationQuery { fingerprint: target_fp.to_string() };
    let env = sign(
        payload,
        &state.fingerprint(),
        state.identity.signing_key(),
        Utc::now(),
    )
    .context("signing reputation query")?;
    let url = format!("{}/reputation/query", peer.url.trim_end_matches('/'));
    let resp = state.http.post(&url).json(&env).send().await
        .with_context(|| format!("POST {url}"))?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("peer returned {s}: {body}");
    }
    let view: ReputationView = resp.json().await.context("decode response")?;
    Ok(view)
}
