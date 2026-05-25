//! Wire payload types. Wrapped in `Envelope<P>` on the wire.

use serde::{Deserialize, Serialize};

/// `POST /peer/request` body.
/// The sender's pubkey is INLINE here; the receiver must check
/// `sha256(b64decode(pubkey_b64)) == fingerprint(envelope.sender)` before
/// trusting anything else in the request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRequest {
    pub pubkey_b64: String,
    pub url: String,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub contact: String,
    #[serde(default)]
    pub description: String,
}

/// `POST /wordlist/fetch` body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WordlistFetch {
    /// RFC3339 inclusive lower bound. Compare against the server's `last_seen`.
    pub since: String,
    /// Server caps at this; client should re-poll if returned count == limit.
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WordlistEntry {
    pub username: String,
    pub password: String,
    pub count: i64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WordlistFetchResponse {
    pub entries: Vec<WordlistEntry>,
    pub count: u32,
    pub high_watermark: String,
}

/// `POST /reputation/query` body. Sender must be a trusted peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationQuery {
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationView {
    pub fingerprint: String,
    pub status: String,
    pub local_score: i32,
    pub peered_since: Option<String>,
    pub last_seen: Option<String>,
    pub entries_received: i64,
    pub bad_signatures: i64,
}
