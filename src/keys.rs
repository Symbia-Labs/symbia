//! Device signing key: ed25519, stored as a raw 32-byte seed at `keys/device.ed25519`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use ed25519_dalek::SigningKey;

pub fn device_key_path(home: &Path) -> PathBuf {
    home.join("keys").join("device.ed25519")
}

/// Load the device key, generating it with mode 0600 on first use.
pub fn load_or_create(home: &Path) -> anyhow::Result<SigningKey> {
    let path = device_key_path(home);
    if !path.exists() {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(mut f) => {
                f.write_all(&seed)?;
                f.sync_all()?;
                return Ok(SigningKey::from_bytes(&seed));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("create {}", path.display())),
        }
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        bail!("{} is not a 32-byte ed25519 seed", path.display());
    };
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_once_with_mode_0600() {
        let t = tempfile::tempdir().unwrap();
        crate::home::ensure(t.path()).unwrap();
        let a = load_or_create(t.path()).unwrap();
        let b = load_or_create(t.path()).unwrap();
        assert_eq!(a.verifying_key(), b.verifying_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(device_key_path(t.path())).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn rejects_malformed_key_file() {
        let t = tempfile::tempdir().unwrap();
        crate::home::ensure(t.path()).unwrap();
        std::fs::write(device_key_path(t.path()), b"short").unwrap();
        assert!(load_or_create(t.path()).is_err());
    }
}
