//! Data directory resolution and layout.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

/// Resolve the data directory from explicit inputs.
///
/// `SYMBIA_HOME` wins. Otherwise macOS uses `~/Library/Application Support/Symbia`
/// and other systems use `$XDG_DATA_HOME/symbia`, falling back to `~/.local/share/symbia`.
pub fn resolve(
    symbia_home: Option<OsString>,
    home: Option<OsString>,
    xdg_data_home: Option<OsString>,
    macos: bool,
) -> anyhow::Result<PathBuf> {
    if let Some(p) = symbia_home.filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let home = home.filter(|p| !p.is_empty()).map(PathBuf::from);
    if macos {
        let Some(home) = home else { bail!("HOME is not set") };
        return Ok(home.join("Library/Application Support/Symbia"));
    }
    if let Some(x) = xdg_data_home.filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(x).join("symbia"));
    }
    let Some(home) = home else { bail!("neither XDG_DATA_HOME nor HOME is set") };
    Ok(home.join(".local/share/symbia"))
}

/// Resolve the data directory from the process environment.
pub fn from_env() -> anyhow::Result<PathBuf> {
    resolve(
        std::env::var_os("SYMBIA_HOME"),
        std::env::var_os("HOME"),
        std::env::var_os("XDG_DATA_HOME"),
        cfg!(target_os = "macos"),
    )
}

/// Create `keys/`, `sessions/`, `seals/` and `evidence/` under `home`.
pub fn ensure(home: &Path) -> anyhow::Result<()> {
    for sub in ["keys", "sessions", "seals", "evidence"] {
        let dir = home.join(sub);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home.join("keys"), std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<OsString> {
        Some(OsString::from(v))
    }

    #[test]
    fn symbia_home_wins() {
        let p = resolve(s("/x/sym"), s("/home/u"), s("/xdg"), true).unwrap();
        assert_eq!(p, PathBuf::from("/x/sym"));
    }

    #[test]
    fn macos_default() {
        let p = resolve(None, s("/Users/u"), s("/xdg"), true).unwrap();
        assert_eq!(p, PathBuf::from("/Users/u/Library/Application Support/Symbia"));
    }

    #[test]
    fn linux_xdg_then_fallback() {
        assert_eq!(resolve(None, s("/home/u"), s("/xdg"), false).unwrap(), PathBuf::from("/xdg/symbia"));
        assert_eq!(
            resolve(None, s("/home/u"), None, false).unwrap(),
            PathBuf::from("/home/u/.local/share/symbia")
        );
        assert!(resolve(None, None, None, false).is_err());
    }

    #[test]
    fn ensure_creates_layout() {
        let t = tempfile::tempdir().unwrap();
        ensure(t.path()).unwrap();
        for sub in ["keys", "sessions", "seals", "evidence"] {
            assert!(t.path().join(sub).is_dir());
        }
    }
}
