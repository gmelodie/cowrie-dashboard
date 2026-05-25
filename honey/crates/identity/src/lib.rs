use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

const KEY_FILE: &str = "node.key";

pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(KEY_FILE);
        if path.exists() {
            Self::load_from(&path)
        } else {
            Self::create_at(data_dir)
        }
    }

    fn load_from(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("reading identity key {}", path.display()))?;
        if bytes.len() != SECRET_KEY_LENGTH {
            anyhow::bail!(
                "identity key at {} is {} bytes, expected {SECRET_KEY_LENGTH}",
                path.display(),
                bytes.len()
            );
        }
        let mut secret = [0u8; SECRET_KEY_LENGTH];
        secret.copy_from_slice(&bytes);
        Ok(Self {
            signing_key: SigningKey::from_bytes(&secret),
        })
    }

    fn create_at(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data dir {}", data_dir.display()))?;
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let path = data_dir.join(KEY_FILE);
        write_secret(&path, signing_key.as_bytes())?;
        Ok(Self { signing_key })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn pubkey_b64(&self) -> String {
        B64.encode(self.verifying_key().as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_of(self.verifying_key().as_bytes())
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

pub fn fingerprint_of(pubkey: &[u8]) -> String {
    let hash = Sha256::digest(pubkey);
    let mut s = BASE32_NOPAD.encode(&hash).to_ascii_lowercase();
    s.truncate(52);
    s
}

#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating identity key {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing identity key {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("writing identity key {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_52_lowercase_base32_chars() {
        let pubkey = [0u8; 32];
        let fp = fingerprint_of(&pubkey);
        assert_eq!(fp.len(), 52);
        assert!(fp.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let pubkey = b"deterministic-input-of-32-bytes!";
        assert_eq!(fingerprint_of(pubkey), fingerprint_of(pubkey));
    }
}
