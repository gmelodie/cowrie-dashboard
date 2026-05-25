//! Signed-envelope wire protocol for honey federation.
//!
//! - Canonical JSON (RFC 8785 JCS): sorted keys, no whitespace, UTF-8.
//! - Ed25519 signature over `canonical_json({v, sender, timestamp, nonce, payload})`.
//! - Nonce dedup window: `2 * MAX_SKEW`.
//! - Bad-sig from KNOWN peer → caller bumps `peers.bad_signatures`; from
//!   unknown sender → silent drop (caller's responsibility).

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

pub mod messages;
pub mod nonce;

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_MAX_SKEW_SECS: i64 = 300;
pub const NONCE_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("envelope version {got} unsupported (expected {expected})")]
    BadVersion { got: u32, expected: u32 },

    #[error("invalid base64 in {field}")]
    Base64 { field: &'static str },

    #[error("invalid signature")]
    BadSignature,

    #[error("timestamp skew {skew_secs}s exceeds limit {max_secs}s")]
    Skew { skew_secs: i64, max_secs: i64 },

    #[error("invalid timestamp")]
    BadTimestamp,

    #[error("canonicalization failed: {0}")]
    Canonical(String),

    #[error("malformed payload: {0}")]
    Payload(String),
}

/// Outer envelope sent over the wire. `payload` is endpoint-specific.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<P> {
    pub v: u32,
    pub sender: String,
    pub timestamp: String,
    pub nonce: String,
    pub payload: P,
    pub signature: String,
}

/// The signed portion (everything except `signature`). The wire format orders
/// fields alphabetically after JCS — Serialize order here doesn't matter.
#[derive(Debug, Serialize)]
struct SignedView<'a, P: Serialize> {
    v: u32,
    sender: &'a str,
    timestamp: &'a str,
    nonce: &'a str,
    payload: &'a P,
}

pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, VerifyError> {
    serde_jcs::to_vec(value).map_err(|e| VerifyError::Canonical(e.to_string()))
}

/// Build a fresh signed envelope. Caller supplies the payload + current time.
pub fn sign<P: Serialize>(
    payload: P,
    sender_fingerprint: &str,
    signing_key: &SigningKey,
    now: DateTime<Utc>,
) -> anyhow::Result<Envelope<P>> {
    let nonce = generate_nonce_b64();
    let timestamp = format_timestamp(now);
    let signed_bytes = canonicalize(&SignedView {
        v: PROTOCOL_VERSION,
        sender: sender_fingerprint,
        timestamp: &timestamp,
        nonce: &nonce,
        payload: &payload,
    })
    .context("canonicalize for sign")?;
    let sig: Signature = signing_key.sign(&signed_bytes);
    Ok(Envelope {
        v: PROTOCOL_VERSION,
        sender: sender_fingerprint.to_string(),
        timestamp,
        nonce,
        payload,
        signature: B64.encode(sig.to_bytes()),
    })
}

/// Verify everything except trust state (caller resolves the pubkey from a
/// `peers` row or — for /peer/request — from the inline pubkey in `payload`).
pub fn verify<P>(
    env: &Envelope<P>,
    pubkey: &VerifyingKey,
    now: DateTime<Utc>,
    max_skew: chrono::Duration,
) -> Result<(), VerifyError>
where
    P: Serialize,
{
    if env.v != PROTOCOL_VERSION {
        return Err(VerifyError::BadVersion {
            got: env.v,
            expected: PROTOCOL_VERSION,
        });
    }

    let ts = parse_timestamp(&env.timestamp).ok_or(VerifyError::BadTimestamp)?;
    let skew = (now - ts).num_seconds().abs();
    if chrono::Duration::seconds(skew) > max_skew {
        return Err(VerifyError::Skew {
            skew_secs: skew,
            max_secs: max_skew.num_seconds(),
        });
    }

    let signed_bytes = canonicalize(&SignedView {
        v: env.v,
        sender: &env.sender,
        timestamp: &env.timestamp,
        nonce: &env.nonce,
        payload: &env.payload,
    })?;
    let sig_bytes = B64
        .decode(&env.signature)
        .map_err(|_| VerifyError::Base64 { field: "signature" })?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_array);
    pubkey
        .verify(&signed_bytes, &sig)
        .map_err(|_| VerifyError::BadSignature)?;
    Ok(())
}

/// Decode the payload from a verified envelope into a concrete type.
/// Use after `verify()` succeeds. For untyped pass-through, P is already correct.
pub fn payload_as<T: DeserializeOwned>(payload: &serde_json::Value) -> Result<T, VerifyError> {
    serde_json::from_value(payload.clone()).map_err(|e| VerifyError::Payload(e.to_string()))
}

pub fn generate_nonce_b64() -> String {
    let mut buf = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut buf);
    B64.encode(buf)
}

pub fn format_timestamp(t: DateTime<Utc>) -> String {
    // RFC3339 with millisecond precision, Z suffix.
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

pub fn default_max_skew() -> chrono::Duration {
    chrono::Duration::seconds(DEFAULT_MAX_SKEW_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde::{Deserialize, Serialize};

    fn deterministic_key() -> SigningKey {
        // Fixed seed so signing is reproducible across runs.
        let seed = [0x42u8; 32];
        SigningKey::from_bytes(&seed)
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct WordlistFetch {
        since: String,
        limit: u32,
    }

    #[test]
    fn canonicalize_sorts_keys_and_omits_whitespace() {
        let v = serde_json::json!({"b": 2, "a": 1});
        let bytes = canonicalize(&v).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(s, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let key = deterministic_key();
        let pub_key = key.verifying_key();
        let env = sign(
            WordlistFetch { since: "2026-05-24T00:00:00Z".into(), limit: 100 },
            "fp-sender",
            &key,
            DateTime::parse_from_rfc3339("2026-05-24T12:34:56.789Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        let now = DateTime::parse_from_rfc3339("2026-05-24T12:35:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        verify(&env, &pub_key, now, default_max_skew()).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = deterministic_key();
        let pub_key = key.verifying_key();
        let now = DateTime::parse_from_rfc3339("2026-05-24T12:34:56.789Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut env = sign(
            WordlistFetch { since: "x".into(), limit: 1 },
            "fp", &key, now,
        ).unwrap();
        env.payload.limit = 999_999;
        let result = verify(&env, &pub_key, now, default_max_skew());
        assert!(matches!(result, Err(VerifyError::BadSignature)));
    }

    #[test]
    fn verify_rejects_skewed_timestamp() {
        let key = deterministic_key();
        let pub_key = key.verifying_key();
        let signed_at = DateTime::parse_from_rfc3339("2026-05-24T12:00:00.000Z")
            .unwrap().with_timezone(&Utc);
        let env = sign(
            WordlistFetch { since: "x".into(), limit: 1 },
            "fp", &key, signed_at,
        ).unwrap();
        // 10 minutes later → 600 s skew, default max 300 s
        let now = DateTime::parse_from_rfc3339("2026-05-24T12:10:00.000Z")
            .unwrap().with_timezone(&Utc);
        let result = verify(&env, &pub_key, now, default_max_skew());
        assert!(matches!(result, Err(VerifyError::Skew { .. })));
    }

    #[test]
    fn verify_rejects_wrong_version() {
        let key = deterministic_key();
        let pub_key = key.verifying_key();
        let mut env = sign(
            WordlistFetch { since: "x".into(), limit: 1 },
            "fp", &key, Utc::now(),
        ).unwrap();
        env.v = 99;
        let result = verify(&env, &pub_key, Utc::now(), default_max_skew());
        assert!(matches!(result, Err(VerifyError::BadVersion { .. })));
    }

    /// Golden bytes — if this test changes you may have broken
    /// wire compatibility with every existing peer. Don't update lightly.
    #[test]
    fn golden_canonical_bytes() {
        let view = SignedView {
            v: 1,
            sender: "l2si6s22uumewahdqiwqs3jct66b5uz2ab4sk52z6ow4bhgvrhea",
            timestamp: "2026-05-24T12:34:56.789Z",
            nonce: "Yw3qg+iVZ5XSUq7w8gZmIw==",
            payload: &WordlistFetch {
                since: "2026-05-23T00:00:00Z".to_string(),
                limit: 5000,
            },
        };
        let bytes = canonicalize(&view).unwrap();
        let expected = concat!(
            "{",
            r#""nonce":"Yw3qg+iVZ5XSUq7w8gZmIw==","#,
            r#""payload":{"limit":5000,"since":"2026-05-23T00:00:00Z"},"#,
            r#""sender":"l2si6s22uumewahdqiwqs3jct66b5uz2ab4sk52z6ow4bhgvrhea","#,
            r#""timestamp":"2026-05-24T12:34:56.789Z","#,
            r#""v":1"#,
            "}",
        );
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected);
    }
}
