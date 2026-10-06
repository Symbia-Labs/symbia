//! Path policy for the file and shell tools: allowed roots, a fixed deny list and a
//! symlink defense ported from v1's pathguard.

use std::path::{Component, Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

/// Denied even inside a root, relative to the user's home directory.
pub const DENY_IN_HOME: [&str; 5] = [".ssh", ".gnupg", ".aws", "Library/Keychains", "Library/Application Support/Claude"];

/// What a tool wants to do at a path. Reads may also reach `$SYMBIA_HOME/evidence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// A path kept both as given (lexically resolved) and realpath'd; `/tmp` and `/private/tmp` differ.
#[derive(Debug, Clone)]
struct Spelled {
    lex: PathBuf,
    real: PathBuf,
}

impl Spelled {
    fn new(p: &Path) -> anyhow::Result<Self> {
        let lex = lexical(p);
        let real = real(&lex).with_context(|| format!("resolve {}", p.display()))?;
        Ok(Self { lex, real })
    }

    fn holds(&self, p: &Path) -> bool {
        p.starts_with(&self.lex) || p.starts_with(&self.real)
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    roots: Vec<Spelled>,
    /// Extra roots for reads only: the evidence folder.
    read_roots: Vec<Spelled>,
    deny: Vec<Spelled>,
    user_home: PathBuf,
}

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    roots: Option<Vec<String>>,
}

/// Resolve `.` and `..` without touching the filesystem. `..` at `/` stays at `/`.
pub fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(p) => out.push(p),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// Realpath the closest existing ancestor of an absolute, lexical path and append the rest.
pub fn real(path: &Path) -> std::io::Result<PathBuf> {
    let mut existing = path.to_path_buf();
    loop {
        match std::fs::canonicalize(&existing) {
            Ok(r) => {
                let rest = path.strip_prefix(&existing).unwrap_or(Path::new(""));
                return Ok(if rest.as_os_str().is_empty() { r } else { r.join(rest) });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.kind() == std::io::ErrorKind::NotADirectory => {
                match existing.parent() {
                    Some(p) => existing = p.to_path_buf(),
                    None => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    }
}

impl Policy {
    /// Load roots from `$SYMBIA_HOME/config.json` (`{"roots": [...]}`); the default root is `user_home`.
    pub fn load(symbia_home: &Path, user_home: &Path) -> anyhow::Result<Self> {
        let cfg = symbia_home.join("config.json");
        let roots = match std::fs::read(&cfg) {
            Ok(bytes) => {
                let c: Config = serde_json::from_slice(&bytes).with_context(|| format!("parse {}", cfg.display()))?;
                c.roots.unwrap_or_else(|| vec![user_home.display().to_string()])
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![user_home.display().to_string()],
            Err(e) => return Err(e).with_context(|| format!("read {}", cfg.display())),
        };
        let roots: Vec<PathBuf> = roots.iter().map(|r| expand(r, user_home)).collect::<anyhow::Result<_>>()?;
        Self::new(&roots, symbia_home, user_home)
    }

    /// Load from the process environment: `HOME` is the user's home directory.
    pub fn from_env(symbia_home: &Path) -> anyhow::Result<Self> {
        let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).context("HOME is not set")?;
        Self::load(symbia_home, Path::new(&home))
    }

    pub fn new(roots: &[PathBuf], symbia_home: &Path, user_home: &Path) -> anyhow::Result<Self> {
        let roots = roots.iter().map(|r| Spelled::new(r)).collect::<anyhow::Result<_>>()?;
        let read_roots = vec![Spelled::new(&symbia_home.join("evidence"))?];
        let deny = DENY_IN_HOME
            .iter()
            .map(|d| user_home.join(d))
            .chain([symbia_home.join("keys")])
            .map(|d| Spelled::new(&d))
            .collect::<anyhow::Result<_>>()?;
        Ok(Self { roots, read_roots, deny, user_home: user_home.to_path_buf() })
    }

    /// A path falls on the deny list. Walks use this on every entry they visit.
    pub fn denied(&self, path: &Path) -> bool {
        self.deny.iter().any(|d| d.holds(path))
    }

    /// Check `path` for `access`. Returns the realpath to operate on.
    pub fn check(&self, path: &str, access: Access) -> Result<PathBuf, String> {
        let lex = lexical(&expand(path, &self.user_home).map_err(|e| e.to_string())?);
        let resolved = real(&lex).map_err(|e| format!("cannot resolve {}: {e}", lex.display()))?;
        if self.denied(&lex) || self.denied(&resolved) {
            return Err(format!("denied: {} is on the deny list", lex.display()));
        }
        let extra: &[Spelled] = if access == Access::Read { &self.read_roots } else { &[] };
        let roots = || self.roots.iter().chain(extra);
        if !roots().any(|r| r.holds(&lex)) {
            return Err(format!("denied: {} is outside the allowed roots", lex.display()));
        }
        // Symlink defense: the realpath must sit in a realpath'd root too.
        if !roots().any(|r| resolved.starts_with(&r.real)) {
            return Err(format!("denied: {} resolves to {}, outside the allowed roots", lex.display(), resolved.display()));
        }
        Ok(resolved)
    }
}

/// Expand a leading `~` and require an absolute path.
fn expand(p: &str, user_home: &Path) -> anyhow::Result<PathBuf> {
    let path = if p == "~" {
        user_home.to_path_buf()
    } else if let Some(rest) = p.strip_prefix("~/") {
        user_home.join(rest)
    } else {
        PathBuf::from(p)
    };
    if !path.is_absolute() {
        anyhow::bail!("path must be absolute: {p:?}");
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake user home that is also the only root, plus a separate `SYMBIA_HOME`.
    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, Policy) {
        let t = tempfile::tempdir().unwrap();
        let user = t.path().join("user");
        let sym = t.path().join("sym");
        std::fs::create_dir_all(user.join("work")).unwrap();
        std::fs::create_dir_all(sym.join("keys")).unwrap();
        std::fs::create_dir_all(sym.join("evidence")).unwrap();
        std::fs::create_dir_all(t.path().join("outside")).unwrap();
        let p = Policy::new(std::slice::from_ref(&user), &sym, &user).unwrap();
        (t, user, sym, p)
    }

    fn s(p: &Path) -> String {
        p.display().to_string()
    }

    #[test]
    fn lexical_resolves_dots() {
        assert_eq!(lexical(Path::new("/a/b/../c/./d")), PathBuf::from("/a/c/d"));
        assert_eq!(lexical(Path::new("/../../x")), PathBuf::from("/x"));
    }

    #[test]
    fn inside_a_root_is_allowed_even_if_missing() {
        let (_t, user, _sym, p) = setup();
        let got = p.check(&s(&user.join("work/new/file.txt")), Access::Write).unwrap();
        assert!(got.ends_with("work/new/file.txt"));
        assert!(p.check(&s(&user), Access::Read).is_ok());
    }

    #[test]
    fn dotdot_escape_is_refused() {
        let (_t, user, _sym, p) = setup();
        let e = p.check(&format!("{}/work/../../outside/x", user.display()), Access::Read).unwrap_err();
        assert!(e.contains("outside the allowed roots"), "{e}");
    }

    #[test]
    fn absolute_path_outside_roots_is_refused() {
        let (t, _user, _sym, p) = setup();
        assert!(p.check(&s(&t.path().join("outside/x")), Access::Read).unwrap_err().contains("outside the allowed roots"));
        assert!(p.check("/etc/hosts", Access::Read).is_err());
        assert!(p.check("relative/path", Access::Read).unwrap_err().contains("must be absolute"));
    }

    #[test]
    fn sibling_sharing_a_prefix_is_refused() {
        let (t, _user, _sym, p) = setup();
        std::fs::create_dir_all(t.path().join("user2")).unwrap();
        assert!(p.check(&s(&t.path().join("user2/x")), Access::Read).is_err());
    }

    #[test]
    fn symlink_pointing_outside_is_refused() {
        let (t, user, _sym, p) = setup();
        std::fs::write(t.path().join("outside/secret"), "s").unwrap();
        std::os::unix::fs::symlink(t.path().join("outside"), user.join("work/link")).unwrap();
        std::os::unix::fs::symlink(t.path().join("outside/secret"), user.join("work/filelink")).unwrap();
        for target in ["work/link/secret", "work/link/new-file", "work/filelink", "work/link"] {
            let e = p.check(&s(&user.join(target)), Access::Read).unwrap_err();
            assert!(e.contains("resolves to"), "{target}: {e}");
        }
        // A symlink that stays inside is fine.
        std::os::unix::fs::symlink(user.join("work"), user.join("inner")).unwrap();
        assert!(p.check(&s(&user.join("inner/x")), Access::Write).is_ok());
    }

    #[test]
    fn every_deny_entry_is_refused() {
        let (_t, user, sym, p) = setup();
        // Create some deny targets and leave others missing: both must be refused.
        std::fs::create_dir_all(user.join(".ssh")).unwrap();
        std::fs::create_dir_all(user.join("Library/Keychains")).unwrap();
        let mut targets: Vec<PathBuf> = DENY_IN_HOME.iter().map(|d| user.join(d)).collect();
        targets.push(sym.join("keys"));
        for d in &targets {
            for p_ in [d.clone(), d.join("inner/file")] {
                for access in [Access::Read, Access::Write] {
                    let e = p.check(&s(&p_), access).unwrap_err();
                    assert!(e.contains("deny list"), "{}: {e}", p_.display());
                }
            }
        }
        // Reaching a denied dir through `..` or a symlink is refused too.
        assert!(p.check(&format!("{}/work/../.ssh/id_ed25519", user.display()), Access::Read).unwrap_err().contains("deny list"));
        std::os::unix::fs::symlink(user.join(".ssh"), user.join("work/ssh")).unwrap();
        assert!(p.check(&s(&user.join("work/ssh/id_ed25519")), Access::Read).unwrap_err().contains("deny list"));
        // `~` expands to the user's home.
        assert!(p.check("~/.aws/credentials", Access::Read).unwrap_err().contains("deny list"));
    }

    #[test]
    fn evidence_is_readable_but_not_writable_outside_roots() {
        let (_t, _user, sym, p) = setup();
        let ev = s(&sym.join("evidence/abc"));
        assert!(p.check(&ev, Access::Read).is_ok());
        assert!(p.check(&ev, Access::Write).is_err());
    }

    #[test]
    fn config_sets_roots_and_defaults_to_home() {
        let (t, user, sym, _p) = setup();
        let p = Policy::load(&sym, &user).unwrap();
        assert!(p.check(&s(&user.join("x")), Access::Read).is_ok());
        let other = t.path().join("outside");
        std::fs::write(sym.join("config.json"), serde_json::json!({"roots": [other]}).to_string()).unwrap();
        let p = Policy::load(&sym, &user).unwrap();
        assert!(p.check(&s(&other.join("x")), Access::Write).is_ok());
        assert!(p.check(&s(&user.join("x")), Access::Read).is_err());
    }
}
