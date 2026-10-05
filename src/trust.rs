//! Pinned seal keys: `keys/trusted.json`, a list of `{public_key, label, added_ms}`.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::canon::canonical;
use crate::now_ms;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trusted {
    /// Lowercase hex ed25519 public key.
    pub public_key: String,
    pub label: String,
    pub added_ms: i64,
}

pub fn trusted_path(home: &Path) -> PathBuf {
    home.join("keys").join("trusted.json")
}

/// Normalize a hex public key to lowercase, rejecting anything that is not a valid ed25519 key.
pub fn parse_key(hex_key: &str) -> anyhow::Result<String> {
    let lower = hex_key.trim().to_ascii_lowercase();
    let Some(bytes) = hex::decode(&lower).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
        bail!("public key must be 64 hex chars");
    };
    if VerifyingKey::from_bytes(&bytes).is_err() {
        bail!("not a valid ed25519 public key");
    }
    Ok(lower)
}

/// The pinned keys; an absent file is an empty list.
pub fn load(home: &Path) -> anyhow::Result<Vec<Trusted>> {
    let path = trusted_path(home);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).with_context(|| format!("parse {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Pin `hex_key` under `label`. Returns the entry and whether it was newly added;
/// a key already pinned keeps its existing entry.
pub fn add(home: &Path, hex_key: &str, label: &str) -> anyhow::Result<(Trusted, bool)> {
    let public_key = parse_key(hex_key)?;
    if label.trim().is_empty() {
        bail!("label is empty");
    }
    let mut list = load(home)?;
    if let Some(t) = list.iter().find(|t| t.public_key == public_key) {
        return Ok((t.clone(), false));
    }
    let entry = Trusted { public_key, label: label.to_string(), added_ms: now_ms() };
    list.push(entry.clone());
    save(home, &list)?;
    Ok((entry, true))
}

/// Write via a temporary file and rename, so readers never see a partial list.
fn save(home: &Path, list: &[Trusted]) -> anyhow::Result<()> {
    crate::home::ensure(home)?;
    let path = trusted_path(home);
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    std::fs::write(&tmp, canonical(list)?).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_hex(seed: u8) -> String {
        hex::encode(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes())
    }

    #[test]
    fn add_then_list_round_trips() {
        let t = tempfile::tempdir().unwrap();
        assert!(load(t.path()).unwrap().is_empty());
        let k = key_hex(1);
        let (e, added) = add(t.path(), &k.to_ascii_uppercase(), "laptop").unwrap();
        assert!(added);
        assert_eq!(e.public_key, k);
        let (again, added) = add(t.path(), &k, "other label").unwrap();
        assert!(!added);
        assert_eq!(again, e);
        add(t.path(), &key_hex(2), "ci").unwrap();
        let list = load(t.path()).unwrap();
        assert_eq!(list.iter().map(|t| t.label.as_str()).collect::<Vec<_>>(), ["laptop", "ci"]);
        // The file is canonical JSON.
        let text = std::fs::read_to_string(trusted_path(t.path())).unwrap();
        assert_eq!(text, canonical(&serde_json::from_str::<serde_json::Value>(&text).unwrap()).unwrap());
    }

    #[test]
    fn bad_keys_and_labels_are_rejected() {
        let t = tempfile::tempdir().unwrap();
        assert!(add(t.path(), "abcd", "x").is_err());
        assert!(add(t.path(), &"zz".repeat(32), "x").is_err());
        assert!(add(t.path(), &key_hex(1), " ").is_err());
        assert!(!trusted_path(t.path()).exists());
    }

    #[test]
    fn device_key_is_pinned_on_first_use() {
        let t = tempfile::tempdir().unwrap();
        crate::home::ensure(t.path()).unwrap();
        let k = crate::keys::load_or_create(t.path()).unwrap();
        crate::keys::load_or_create(t.path()).unwrap();
        let list = load(t.path()).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].public_key, hex::encode(k.verifying_key().to_bytes()));
        assert_eq!(list[0].label, "device");
    }
}
