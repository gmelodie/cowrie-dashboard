use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use honey_db::federation as fed;
use honey_identity::fingerprint_of;
use honey_protocol::{
    messages::{
        PeerRequest, ReputationQuery, ReputationView, WordlistEntry, WordlistFetch,
        WordlistFetchResponse,
    },
    nonce::{check_and_record, NonceStatus},
    parse_timestamp, verify, Envelope, VerifyError,
};
use std::sync::Arc;
use tracing::{info, warn};

use crate::{outbound, state::AppState};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/info", get(info_route))
        .route("/peer/request", post(peer_request))
        .route("/wordlist/fetch", post(wordlist_fetch))
        .route("/reputation/query", post(reputation_query))
        .route("/internal/peer/request", post(internal_peer_request))
        .route("/internal/wordlist/pull-now/{fp}", post(internal_pull_now))
        .route(
            "/internal/reputation/query/{peer_fp}/{target_fp}",
            post(internal_reputation_query),
        )
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

#[derive(serde::Serialize)]
struct NodeInfo {
    fingerprint: String,
    pubkey_b64: String,
    node_name: String,
    contact: String,
    version: &'static str,
}

async fn info_route(State(state): State<Arc<AppState>>) -> Json<NodeInfo> {
    Json(NodeInfo {
        fingerprint: state.fingerprint(),
        pubkey_b64: state.identity.pubkey_b64(),
        node_name: state.config.node_name.clone(),
        contact: state.config.contact.clone(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Self-signed peering request. The inline pubkey is the trust root for this
/// endpoint — every other request resolves the sender via a `peers` row.
async fn peer_request(
    State(state): State<Arc<AppState>>,
    Json(env): Json<Envelope<PeerRequest>>,
) -> impl IntoResponse {
    // 1. Decode inline pubkey.
    let pubkey_bytes = match B64.decode(&env.payload.pubkey_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return drop_silently("inline pubkey: bad base64 or length"),
    };

    // 2. sha256(pubkey) must equal the sender fingerprint. Non-negotiable.
    let expected_fp = fingerprint_of(&pubkey_bytes);
    if expected_fp != env.sender {
        return drop_silently("inline pubkey ⇄ fingerprint mismatch");
    }

    // 3. Build a VerifyingKey from the inline pubkey and verify the signature.
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().unwrap();
    let pubkey = match ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr) {
        Ok(p) => p,
        Err(_) => return drop_silently("inline pubkey: not a valid Ed25519 point"),
    };
    let now = Utc::now();
    if let Err(e) = verify(
        &env,
        &pubkey,
        now,
        honey_protocol::default_max_skew(),
    ) {
        if matches!(e, VerifyError::Skew { .. }) {
            warn!(error = ?e, "peer/request: timestamp skew (check NTP)");
        } else {
            warn!(error = ?e, "peer/request: verify failed");
        }
        return drop_silently("verify failed");
    }

    // 4. Nonce dedup. Window = 2 * max_skew.
    let expires = now + honey_protocol::default_max_skew() * 2;
    match check_and_record(&state.pool, &env.nonce, &env.sender, expires).await {
        Ok(NonceStatus::Fresh) => {}
        Ok(NonceStatus::Duplicate) => return drop_silently("duplicate nonce"),
        Err(e) => {
            tracing::error!(error = ?e, "nonce check failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    }

    // 5. Idempotent upsert into pending.
    let pending = fed::PendingRequest {
        fingerprint: env.sender.clone(),
        pubkey_b64: env.payload.pubkey_b64.clone(),
        url: env.payload.url.clone(),
        node_name: env.payload.node_name.clone(),
        contact: env.payload.contact.clone(),
        description: env.payload.description.clone(),
        received_at: Utc::now(),
    };
    if let Err(e) = fed::upsert_pending(&state.pool, &pending).await {
        tracing::error!(error = ?e, "pending upsert failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
    }
    info!(fp = %env.sender, "peer request stored as pending");
    (StatusCode::ACCEPTED, "queued").into_response()
}

/// Returns an opaque 400 — no information leakage about why the request was rejected.
fn drop_silently(reason: &str) -> axum::response::Response {
    tracing::debug!(reason, "peer/request dropped silently");
    (StatusCode::BAD_REQUEST, "bad request").into_response()
}

async fn wordlist_fetch(
    State(state): State<Arc<AppState>>,
    Json(env): Json<Envelope<WordlistFetch>>,
) -> impl IntoResponse {
    // 1. Resolve sender via trusted peers table.
    let peer = match honey_db::federation::get_trusted_peer(&state.pool, &env.sender).await {
        Ok(Some(p)) => p,
        Ok(None) => return drop_silently("sender not trusted"),
        Err(e) => {
            tracing::error!(error = ?e, "peer lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };

    let pubkey_bytes = match B64.decode(&peer.pubkey_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return drop_silently("peer pubkey malformed"),
    };
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().unwrap();
    let pubkey = match ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr) {
        Ok(p) => p,
        Err(_) => return drop_silently("peer pubkey not on curve"),
    };

    // 2. Verify envelope signature + timestamp skew.
    let now = Utc::now();
    if let Err(e) = verify(&env, &pubkey, now, honey_protocol::default_max_skew()) {
        warn!(error = ?e, fp = %env.sender, "wordlist/fetch verify failed");
        let _ = honey_db::federation::bump_bad_signature(&state.pool, &env.sender).await;
        return drop_silently("verify failed");
    }

    // 3. Nonce dedup (write endpoint → record).
    let expires = now + honey_protocol::default_max_skew() * 2;
    match check_and_record(&state.pool, &env.nonce, &env.sender, expires).await {
        Ok(NonceStatus::Fresh) => {}
        Ok(NonceStatus::Duplicate) => return drop_silently("duplicate nonce"),
        Err(e) => {
            tracing::error!(error = ?e, "nonce check failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    }

    let since = match parse_timestamp(&env.payload.since) {
        Some(t) => t,
        None => return (StatusCode::BAD_REQUEST, "bad `since` timestamp").into_response(),
    };
    let limit = env.payload.limit.min(5000) as i64;

    let entries = match honey_db::federation::fetch_local_entries(&state.pool, since, limit).await
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = ?e, "fetch_local_entries failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response();
        }
    };

    let high_watermark = entries
        .last()
        .map(|e| honey_protocol::format_timestamp(e.last_seen))
        .unwrap_or_else(|| env.payload.since.clone());
    let count = entries.len() as u32;

    let response = WordlistFetchResponse {
        entries: entries
            .into_iter()
            .map(|e| WordlistEntry {
                username: e.username,
                password: e.password,
                count: e.cnt,
                first_seen: honey_protocol::format_timestamp(e.first_seen),
                last_seen: honey_protocol::format_timestamp(e.last_seen),
            })
            .collect(),
        count,
        high_watermark,
    };
    Json(response).into_response()
}

async fn reputation_query(
    State(state): State<Arc<AppState>>,
    Json(env): Json<Envelope<ReputationQuery>>,
) -> impl IntoResponse {
    // Same auth wall as /wordlist/fetch: sender must be trusted, otherwise
    // /reputation/query becomes an enumeration oracle for the peer table.
    let peer = match honey_db::federation::get_trusted_peer(&state.pool, &env.sender).await {
        Ok(Some(p)) => p,
        Ok(None) => return drop_silently("sender not trusted"),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };
    let pubkey_bytes = match B64.decode(&peer.pubkey_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return drop_silently("peer pubkey malformed"),
    };
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().unwrap();
    let pubkey = match ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr) {
        Ok(p) => p,
        Err(_) => return drop_silently("peer pubkey not on curve"),
    };
    let now = Utc::now();
    if let Err(_) = verify(&env, &pubkey, now, honey_protocol::default_max_skew()) {
        let _ = honey_db::federation::bump_bad_signature(&state.pool, &env.sender).await;
        return drop_silently("verify failed");
    }
    let expires = now + honey_protocol::default_max_skew() * 2;
    if let Ok(NonceStatus::Duplicate) =
        check_and_record(&state.pool, &env.nonce, &env.sender, expires).await
    {
        return drop_silently("duplicate nonce");
    }

    // Look up our local view of the requested fingerprint.
    let target = match honey_db::federation::get_peer(&state.pool, &env.payload.fingerprint).await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Json(ReputationView {
                fingerprint: env.payload.fingerprint.clone(),
                status: "unknown".to_string(),
                local_score: 0,
                peered_since: None,
                last_seen: None,
                entries_received: 0,
                bad_signatures: 0,
            })
            .into_response();
        }
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };
    Json(ReputationView {
        fingerprint: target.fingerprint,
        status: target.status,
        local_score: target.local_score,
        peered_since: Some(honey_protocol::format_timestamp(target.added_at)),
        last_seen: target.last_seen.map(honey_protocol::format_timestamp),
        entries_received: target.entries_received,
        bad_signatures: target.bad_signatures,
    })
    .into_response()
}

async fn internal_reputation_query(
    State(state): State<Arc<AppState>>,
    axum::extract::Path((peer_fp, target_fp)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    let peer = match honey_db::federation::get_trusted_peer(&state.pool, &peer_fp).await {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such trusted peer").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };
    match crate::outbound::query_reputation(&state, &peer, &target_fp).await {
        Ok(view) => Json(view).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e}")).into_response(),
    }
}

async fn internal_pull_now(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(fp): axum::extract::Path<String>,
) -> impl IntoResponse {
    let peer = match honey_db::federation::get_trusted_peer(&state.pool, &fp).await {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such trusted peer").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "db error").into_response(),
    };
    match crate::poller::pull_one(&state, &peer).await {
        Ok(n) => (StatusCode::OK, format!("pulled {n} entries")).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e}")).into_response(),
    }
}

// ── Loopback / admin-panel-facing endpoints ───────────────────────────────────

#[derive(serde::Deserialize)]
struct InternalPeerRequest {
    url: String,
    #[serde(default)]
    node_name: String,
    #[serde(default)]
    contact: String,
    #[serde(default)]
    description: String,
}

async fn internal_peer_request(
    State(state): State<Arc<AppState>>,
    Json(body): Json<InternalPeerRequest>,
) -> impl IntoResponse {
    let parsed_ts = parse_timestamp;
    let _ = parsed_ts; // keep import live; used in tests

    match outbound::send_peer_request(
        &state,
        &body.url,
        &body.node_name,
        &body.contact,
        &body.description,
    )
    .await
    {
        Ok(()) => (StatusCode::ACCEPTED, "sent").into_response(),
        Err(e) => {
            warn!(error = ?e, url = %body.url, "internal/peer/request failed");
            (StatusCode::BAD_GATEWAY, format!("{e}")).into_response()
        }
    }
}
