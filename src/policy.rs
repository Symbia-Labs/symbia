//! Path policy for the file and shell tools: allowed roots, a fixed deny list and a
//! symlink defense ported from v1's pathguard.

use std::path::{Component, Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

/// Denied even inside a root, relative to the user's home directory. These hold keys and
/// credentials and stay refused in every mode, for the file tools and exec alike.
pub const DENY_IN_HOME: [&str; 13] = [
    ".ssh",
    ".gnupg",
    ".aws",
    "Library/Keychains",
    "Library/Application Support/Claude",
    ".config/gh",
    ".netrc",
    ".docker/config.json",
    ".kube",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "Library/Cookies",
];

/// Default `read_roots`: toolchain source the file tools may read but not write.
pub const READ_ROOTS_DEFAULT: [&str; 2] = ["~/.cargo/registry", "~/.rustup/toolchains"];

/// Default `exec_read_allow`: files in the home a shell and toolchain need under `exec_read: "home"`.
/// `~/.npmrc` is left out on purpose: it holds tokens.
pub const EXEC_READ_ALLOW_DEFAULT: [&str; 8] =
    ["~/.zshenv", "~/.zprofile", "~/.zlogin", "~/.cargo", "~/.rustup", "~/.local/bin", "~/.gitconfig", "~/.config/git"];

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

    /// As [`Spelled::new`], but a path that can't be resolved for lack of permission keeps its
    /// lexical spelling as its realpath. For deny-list entries: inside the exec sandbox `~/.ssh`
    /// can't be resolved, and that must not stop the policy from loading.
    fn lenient(p: &Path) -> anyhow::Result<Self> {
        let lex = lexical(p);
        match real(&lex) {
            Ok(real) => Ok(Self { lex, real }),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(Self { real: lex.clone(), lex }),
            Err(e) => Err(e).with_context(|| format!("resolve {}", p.display())),
        }
    }

    fn holds(&self, p: &Path) -> bool {
        p.starts_with(&self.lex) || p.starts_with(&self.real)
    }

    fn both(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.lex.as_path()).chain((self.real != self.lex).then_some(self.real.as_path()))
    }
}

/// Whether `symbia_exec` commands may open network connections (`exec_network` in config.json).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Allow,
    Deny,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Allow => "allow",
            Network::Deny => "deny",
        }
    }
}

/// What `symbia_exec` commands may read (`exec_read` in config.json).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum ExecRead {
    /// Nothing under the user's home except the roots, the read allowances and the evidence folder.
    #[default]
    #[serde(rename = "home")]
    Home,
    /// Everything but the deny list (R2).
    #[serde(rename = "deny_list")]
    DenyList,
}

/// `$SYMBIA_HOME/config.json`. Every key is optional.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Read-write roots for the tools; default the user's home.
    pub roots: Option<Vec<String>>,
    pub exec_network: Network,
    pub exec_read: ExecRead,
    /// Paths under the home exec may still read with `exec_read: "home"`.
    pub exec_read_allow: Vec<String>,
    /// Exec command rules in Claude Code's syntax: `"chmod:*"` or an exact command.
    pub exec_deny: Vec<String>,
    /// Also load `Bash(...)` deny rules from Claude Code's settings files.
    pub exec_import_claude_rules: bool,
    /// Read-only roots for the file tools.
    pub read_roots: Vec<String>,
    /// Deny-list entries re-opened for exec only (a logged stopgap, e.g. `".config/gh"`).
    pub exec_unlock: Vec<String>,
    /// How recent the last write must be for `symbia mcp` to resume a session; 0 turns resume off.
    pub resume_window_ms: i64,
    /// Programs `symbia_exec` may run outside the sandbox when a call asks (`unsandboxed: true`).
    pub exec_unsandboxed: Vec<crate::unsandboxed::RuleConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            roots: None,
            exec_network: Network::Allow,
            exec_read: ExecRead::Home,
            exec_read_allow: EXEC_READ_ALLOW_DEFAULT.iter().map(|s| s.to_string()).collect(),
            exec_deny: Vec::new(),
            exec_import_claude_rules: true,
            read_roots: READ_ROOTS_DEFAULT.iter().map(|s| s.to_string()).collect(),
            exec_unlock: Vec::new(),
            resume_window_ms: crate::session::RESUME_WINDOW_DEFAULT_MS,
            exec_unsandboxed: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    roots: Vec<Spelled>,
    /// `$SYMBIA_HOME/evidence`: readable by the file tools and exec, never writable.
    evidence: Spelled,
    /// Extra roots for the file tools, reads only.
    read_roots: Vec<Spelled>,
    deny: Vec<Spelled>,
    /// `$SYMBIA_HOME`: readable where a root covers it, never writable.
    own: Spelled,
    user_home: Spelled,
    network: Network,
    exec_read: ExecRead,
    exec_read_allow: Vec<Spelled>,
    exec_deny: Vec<String>,
    import_claude_rules: bool,
    /// `exec_unlock` entries as configured, and the deny-list paths they re-open for exec.
    exec_unlock: Vec<String>,
    unlocked: Vec<Spelled>,
    resume_window_ms: i64,
    unsandboxed: Vec<crate::unsandboxed::Rule>,
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
    /// Load [`Config`] from `$SYMBIA_HOME/config.json`; a missing file means every default.
    /// The default root is `user_home`.
    pub fn load(symbia_home: &Path, user_home: &Path) -> anyhow::Result<Self> {
        let cfg = symbia_home.join("config.json");
        let c: Config = match std::fs::read(&cfg) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parse {}", cfg.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(e).with_context(|| format!("read {}", cfg.display())),
        };
        let roots = c.roots.clone().unwrap_or_else(|| vec![user_home.display().to_string()]);
        let roots: Vec<PathBuf> = roots.iter().map(|r| expand(r, user_home)).collect::<anyhow::Result<_>>()?;
        Self::with_config(&roots, symbia_home, user_home, &c)
    }

    /// Load from the process environment: `HOME` is the user's home directory.
    pub fn from_env(symbia_home: &Path) -> anyhow::Result<Self> {
        let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).context("HOME is not set")?;
        Self::load(symbia_home, Path::new(&home))
    }

    /// A policy with these roots and every other setting at its default.
    pub fn new(roots: &[PathBuf], symbia_home: &Path, user_home: &Path) -> anyhow::Result<Self> {
        Self::with_config(roots, symbia_home, user_home, &Config::default())
    }

    /// A policy with these roots and the rest of `c` (its `roots` key is ignored).
    pub fn with_config(roots: &[PathBuf], symbia_home: &Path, user_home: &Path, c: &Config) -> anyhow::Result<Self> {
        let spell = |list: &[String]| -> anyhow::Result<Vec<Spelled>> { list.iter().map(|p| Spelled::new(&expand(p, user_home)?)).collect() };
        let roots = roots.iter().map(|r| Spelled::new(r)).collect::<anyhow::Result<_>>()?;
        let deny = DENY_IN_HOME
            .iter()
            .map(|d| user_home.join(d))
            .chain([symbia_home.join("keys")])
            .map(|d| Spelled::lenient(&d))
            .collect::<anyhow::Result<_>>()?;
        if let Some(bad) = c.exec_unlock.iter().find(|u| !DENY_IN_HOME.contains(&u.as_str())) {
            anyhow::bail!("exec_unlock: {bad:?} is not a deny-list entry; allowed: {}", DENY_IN_HOME.join(", "));
        }
        if c.resume_window_ms < 0 {
            anyhow::bail!("resume_window_ms must be 0 or more, got {}", c.resume_window_ms);
        }
        let unlocked = c.exec_unlock.iter().map(|u| Spelled::lenient(&user_home.join(u))).collect::<anyhow::Result<_>>()?;
        let unsandboxed = c
            .exec_unsandboxed
            .iter()
            .map(|r| crate::unsandboxed::Rule::load(r, |p| expand(p, user_home)))
            .collect::<anyhow::Result<_>>()?;
        Ok(Self {
            roots,
            evidence: Spelled::new(&symbia_home.join("evidence"))?,
            read_roots: spell(&c.read_roots)?,
            deny,
            own: Spelled::new(symbia_home)?,
            user_home: Spelled::new(user_home)?,
            network: c.exec_network,
            exec_read: c.exec_read,
            exec_read_allow: spell(&c.exec_read_allow)?,
            exec_deny: c.exec_deny.clone(),
            import_claude_rules: c.exec_import_claude_rules,
            exec_unlock: c.exec_unlock.clone(),
            unlocked,
            resume_window_ms: c.resume_window_ms,
            unsandboxed,
        })
    }

    /// `exec_unsandboxed` rules, checked at load.
    pub fn exec_unsandboxed(&self) -> &[crate::unsandboxed::Rule] {
        &self.unsandboxed
    }

    /// `resume_window_ms` from config.json.
    pub fn resume_window_ms(&self) -> i64 {
        self.resume_window_ms
    }

    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn exec_read(&self) -> ExecRead {
        self.exec_read
    }

    /// `exec_deny` rules from config.json.
    pub fn exec_deny(&self) -> &[String] {
        &self.exec_deny
    }

    pub fn import_claude_rules(&self) -> bool {
        self.import_claude_rules
    }

    /// The user's home directory as given.
    pub fn user_home(&self) -> &Path {
        &self.user_home.lex
    }

    /// Every deny-list path, as spelled and as its realpath when that differs.
    pub fn deny_paths(&self) -> Vec<&Path> {
        self.deny.iter().flat_map(Spelled::both).collect()
    }

    /// `exec_unlock` entries as configured (empty unless the stopgap is on).
    pub fn exec_unlock(&self) -> &[String] {
        &self.exec_unlock
    }

    /// The deny list as the exec sandbox applies it: every entry except those in `exec_unlock`.
    /// The file tools keep using the full list through [`Policy::denied`].
    pub fn exec_deny_paths(&self) -> Vec<&Path> {
        self.deny.iter().filter(|d| !self.unlocked.iter().any(|u| u.lex == d.lex)).flat_map(Spelled::both).collect()
    }

    /// `$SYMBIA_HOME`, as spelled and as its realpath when that differs.
    pub fn own_paths(&self) -> Vec<&Path> {
        self.own.both().collect()
    }

    /// The user's home, both spellings.
    pub fn home_paths(&self) -> Vec<&Path> {
        self.user_home.both().collect()
    }

    /// What exec may read under the home with `exec_read: "home"`: the roots, the read
    /// allowances and the evidence folder, both spellings.
    pub fn exec_read_paths(&self) -> Vec<&Path> {
        self.roots.iter().chain(&self.exec_read_allow).chain(&self.unlocked).chain([&self.evidence]).flat_map(Spelled::both).collect()
    }

    /// Folders strictly between the home and each root or read allowance inside it, both
    /// spellings: exec may read their metadata, so paths through them resolve.
    pub fn exec_ancestor_paths(&self) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        let homes: Vec<&Path> = self.home_paths();
        for p in self.roots.iter().chain(&self.exec_read_allow).chain(&self.unlocked).flat_map(Spelled::both) {
            let Some(home) = homes.iter().copied().find(|h| p.starts_with(h) && p != *h) else { continue };
            for a in p.ancestors().skip(1).take_while(|a| *a != home) {
                if !out.iter().any(|o| o == a) {
                    out.push(a.to_path_buf());
                }
            }
        }
        out
    }

    /// A path falls on the deny list. Walks use this on every entry they visit.
    pub fn denied(&self, path: &Path) -> bool {
        self.deny.iter().any(|d| d.holds(path))
    }

    /// Check `path` for `access`. Returns the realpath to operate on.
    pub fn check(&self, path: &str, access: Access) -> Result<PathBuf, String> {
        let lex = lexical(&expand(path, &self.user_home.lex).map_err(|e| e.to_string())?);
        let resolved = real(&lex).map_err(|e| format!("cannot resolve {}: {e}", lex.display()))?;
        if self.denied(&lex) || self.denied(&resolved) {
            return Err(format!("denied: {} is on the deny list", lex.display()));
        }
        if access == Access::Write && (self.own.holds(&lex) || self.own.holds(&resolved)) {
            return Err(format!("denied: {} is inside $SYMBIA_HOME, which the tools may not write", lex.display()));
        }
        let extra: &[Spelled] = if access == Access::Read { &self.read_roots } else { &[] };
        let evidence = (access == Access::Read).then_some(&self.evidence);
        let roots = || self.roots.iter().chain(extra).chain(evidence);
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
    fn symbia_home_is_read_only_even_inside_a_root() {
        let t = tempfile::tempdir().unwrap();
        let user = t.path().join("user");
        let sym = user.join("Library/Application Support/Symbia");
        crate::home::ensure(&sym).unwrap();
        std::fs::create_dir_all(user.join("work")).unwrap();
        let p = Policy::new(std::slice::from_ref(&user), &sym, &user).unwrap();
        std::os::unix::fs::symlink(&sym, user.join("work/sym")).unwrap();
        for target in ["sessions/s.jsonl", "seals/s.seal", "evidence/abc", "config.json", "", "new/x"] {
            for p_ in [sym.join(target), user.join("work/sym").join(target)] {
                let e = p.check(&s(&p_), Access::Write).unwrap_err();
                assert!(e.contains("$SYMBIA_HOME"), "{}: {e}", p_.display());
            }
            if !target.is_empty() {
                assert!(p.check(&s(&sym.join(target)), Access::Read).is_ok(), "{target}");
            }
        }
        assert!(p.check(&s(&sym.join("keys/device.ed25519")), Access::Read).unwrap_err().contains("deny list"));
        assert!(p.check(&s(&user.join("work/x")), Access::Write).is_ok());
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

    #[test]
    fn config_sets_exec_network() {
        let (_t, user, sym, p) = setup();
        assert_eq!(p.network(), Network::Allow);
        assert_eq!(Policy::load(&sym, &user).unwrap().network(), Network::Allow);
        std::fs::write(sym.join("config.json"), r#"{"exec_network": "deny"}"#).unwrap();
        let p = Policy::load(&sym, &user).unwrap();
        assert_eq!(p.network(), Network::Deny);
        assert!(p.check(&s(&user.join("x")), Access::Read).is_ok(), "roots still default to home");
        std::fs::write(sym.join("config.json"), r#"{"exec_network": "allow"}"#).unwrap();
        assert_eq!(Policy::load(&sym, &user).unwrap().network(), Network::Allow);
        std::fs::write(sym.join("config.json"), r#"{"exec_network": "off"}"#).unwrap();
        assert!(Policy::load(&sym, &user).is_err());
    }

    #[test]
    fn deny_paths_list_both_spellings() {
        let (_t, user, sym, p) = setup();
        let deny = p.deny_paths();
        for d in DENY_IN_HOME.iter().map(|d| user.join(d)).chain([sym.join("keys")]) {
            assert!(deny.contains(&d.as_path()), "{}", d.display());
            assert!(deny.contains(&real(&d).unwrap().as_path()), "{}", d.display());
        }
        assert!(p.own_paths().contains(&sym.as_path()));
        assert!(p.own_paths().contains(&std::fs::canonicalize(&sym).unwrap().as_path()));
    }

    #[test]
    fn read_roots_are_readable_but_not_writable() {
        let (_t, user, sym, _p) = setup();
        let reg = user.join(".cargo/registry/src/index/serde-1.0.0/src/lib.rs");
        std::fs::create_dir_all(reg.parent().unwrap()).unwrap();
        std::fs::write(&reg, "pub fn f() {}").unwrap();
        std::fs::create_dir_all(user.join(".rustup/toolchains/stable/lib")).unwrap();
        // Roots that do not cover the home: only the read roots reach the toolchain.
        std::fs::write(sym.join("config.json"), serde_json::json!({"roots": [user.join("work")]}).to_string()).unwrap();
        let p = Policy::load(&sym, &user).unwrap();
        for f in [reg.clone(), user.join(".rustup/toolchains/stable/lib")] {
            assert!(p.check(&s(&f), Access::Read).is_ok(), "{}", f.display());
            assert!(p.check(&s(&f), Access::Write).unwrap_err().contains("outside the allowed roots"), "{}", f.display());
        }
        assert!(p.check("~/.cargo/registry/x", Access::Read).is_ok());
        assert!(p.check("~/.cargo/config.toml", Access::Read).is_err());
        // Configurable, `~` expanded; the deny list still wins.
        std::fs::write(sym.join("config.json"), serde_json::json!({"roots": [user.join("work")], "read_roots": ["~/ref", "~"]}).to_string()).unwrap();
        let p = Policy::load(&sym, &user).unwrap();
        assert!(p.check(&s(&user.join("ref/a")), Access::Read).is_ok());
        assert!(p.check(&s(&reg), Access::Read).is_ok(), "~ covers the registry now");
        assert!(p.check(&s(&user.join(".ssh/id")), Access::Read).unwrap_err().contains("deny list"));
        assert!(p.check(&s(&user.join(".config/gh/hosts.yml")), Access::Read).unwrap_err().contains("deny list"));
        assert!(p.check(&s(&user.join("ref/a")), Access::Write).is_err());
    }

    #[test]
    fn config_sets_exec_read_rules_and_imports() {
        let (_t, user, sym, p) = setup();
        assert_eq!((p.exec_read(), p.import_claude_rules(), p.exec_deny().len()), (ExecRead::Home, true, 0));
        std::fs::write(
            sym.join("config.json"),
            r#"{"exec_read": "deny_list", "exec_deny": ["chmod:*"], "exec_import_claude_rules": false, "exec_read_allow": ["~/.tool"]}"#,
        )
        .unwrap();
        let p = Policy::load(&sym, &user).unwrap();
        assert_eq!((p.exec_read(), p.import_claude_rules(), p.exec_deny()), (ExecRead::DenyList, false, &["chmod:*".to_string()][..]));
        assert!(p.exec_read_paths().contains(&user.join(".tool").as_path()));
        assert!(!p.exec_read_paths().contains(&user.join(".zshrc").as_path()));
        std::fs::write(sym.join("config.json"), r#"{"exec_read": "everything"}"#).unwrap();
        assert!(Policy::load(&sym, &user).is_err());
    }

    #[test]
    fn exec_read_paths_and_ancestors() {
        let (_t, user, sym, _p) = setup();
        let root = user.join("work/a/proj");
        std::fs::create_dir_all(&root).unwrap();
        let p = Policy::new(std::slice::from_ref(&root), &sym, &user).unwrap();
        let reads = p.exec_read_paths();
        for want in [root.clone(), user.join(".zprofile"), user.join(".cargo"), user.join(".config/git"), sym.join("evidence")] {
            assert!(reads.contains(&want.as_path()), "{}", want.display());
        }
        // `zsh -lc` never reads .zshrc, and people keep tokens there.
        assert!(!reads.contains(&user.join(".zshrc").as_path()));
        assert!(!reads.contains(&user.join(".npmrc").as_path()));
        let anc = p.exec_ancestor_paths();
        for want in [user.join("work"), user.join("work/a"), user.join(".config"), user.join(".local")] {
            assert!(anc.contains(&want), "{}", want.display());
        }
        assert!(!anc.contains(&user) && !anc.contains(&root));
        let real_user = std::fs::canonicalize(&user).unwrap();
        assert!(anc.contains(&real_user.join("work/a")), "realpath spelling too");
        assert!(p.home_paths().contains(&real_user.as_path()));
    }

    #[test]
    fn exec_unlock_takes_only_deny_list_entries() {
        let (_t, user, sym, p) = setup();
        assert!(p.exec_unlock().is_empty());
        for bad in [r#"["Documents"]"#, r#"["/etc"]"#, r#"["keys"]"#, r#"["../.ssh"]"#, r#"[".config"]"#] {
            std::fs::write(sym.join("config.json"), format!(r#"{{"exec_unlock": {bad}}}"#)).unwrap();
            assert!(Policy::load(&sym, &user).is_err(), "{bad} accepted");
        }
        std::fs::write(sym.join("config.json"), r#"{"exec_unlock": [".config/gh"]}"#).unwrap();
        assert_eq!(Policy::load(&sym, &user).unwrap().exec_unlock(), &[".config/gh".to_string()][..]);
    }

    #[test]
    fn exec_unlock_reopens_for_exec_only() {
        let (_t, user, sym, _p) = setup();
        std::fs::write(sym.join("config.json"), r#"{"exec_unlock": [".config/gh"]}"#).unwrap();
        let p = Policy::load(&sym, &user).unwrap();
        let gh = user.join(".config/gh");
        // Exec: out of the sandbox deny rules, into the read allowances (with its ancestors).
        assert!(!p.exec_deny_paths().contains(&gh.as_path()));
        assert!(p.exec_deny_paths().contains(&user.join(".ssh").as_path()));
        assert!(p.exec_deny_paths().contains(&sym.join("keys").as_path()));
        assert!(p.exec_read_paths().contains(&gh.as_path()));
        assert!(p.exec_ancestor_paths().contains(&user.join(".config")));
        // File tools: still denied.
        assert!(p.denied(&gh.join("hosts.yml")));
        assert!(p.check(&s(&gh.join("hosts.yml")), Access::Read).unwrap_err().contains("deny list"));
    }

    #[test]
    fn resume_window_defaults_to_four_hours_and_refuses_negatives() {
        let (_t, user, sym, p) = setup();
        assert_eq!(p.resume_window_ms(), 14_400_000);
        std::fs::write(sym.join("config.json"), r#"{"resume_window_ms": 0}"#).unwrap();
        assert_eq!(Policy::load(&sym, &user).unwrap().resume_window_ms(), 0);
        std::fs::write(sym.join("config.json"), r#"{"resume_window_ms": -1}"#).unwrap();
        assert!(Policy::load(&sym, &user).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn config_loads_exec_unsandboxed_rules() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, user, sym, p) = setup();
        assert!(p.exec_unsandboxed().is_empty());
        let tool = user.join("bin/tool");
        std::fs::create_dir_all(tool.parent().unwrap()).unwrap();
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = serde_json::json!({"exec_unsandboxed": [{"program": "~/bin/tool", "args": ["push", "*"], "cwd": "~/work"}]});
        std::fs::write(sym.join("config.json"), cfg.to_string()).unwrap();
        let p = Policy::load(&sym, &user).unwrap();
        let rules = p.exec_unsandboxed();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].program, tool);
        assert_eq!(rules[0].cwd.as_deref(), Some(std::fs::canonicalize(user.join("work")).unwrap().as_path()));
        for bad in [
            serde_json::json!([{"program": "bin/tool", "args": []}]),
            serde_json::json!([{"program": "~/bin/missing", "args": []}]),
            serde_json::json!([{"program": "~/work", "args": []}]),
            serde_json::json!([{"program": "~/bin/tool"}]),
        ] {
            std::fs::write(sym.join("config.json"), serde_json::json!({"exec_unsandboxed": bad}).to_string()).unwrap();
            assert!(Policy::load(&sym, &user).is_err(), "{bad} accepted");
        }
    }

    #[cfg(unix)]
    #[test]
    fn deny_entries_that_cannot_be_resolved_still_load() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions. Root searches any folder, so the error never comes.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (t, user, sym, _p) = setup();
        let locked = t.path().join("locked");
        std::fs::create_dir_all(locked.join("inner")).unwrap();
        std::os::unix::fs::symlink(locked.join("inner"), user.join(".ssh")).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unresolvable = real(&user.join(".ssh")).unwrap_err().kind();
        let p = Policy::load(&sym, &user);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(unresolvable, std::io::ErrorKind::PermissionDenied);
        let p = p.unwrap();
        assert!(p.deny_paths().contains(&user.join(".ssh").as_path()));
        assert!(p.check(&s(&user.join(".ssh/id")), Access::Read).unwrap_err().contains("deny list"));
    }
}
