//! `symbia_exec`: run `/bin/zsh -lc <command>` in its own process group, keep the full
//! output as evidence and reply with its tail. On macOS the shell runs under
//! `sandbox-exec` with a profile built from the path policy.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::files::Facts;
use crate::policy::{Access, Network, Policy};
use crate::store::Evidence;

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
/// `sandbox` in the facts: what confined the command.
pub const SANDBOX: &str = if cfg!(target_os = "macos") { "seatbelt" } else { "none" };
pub const TIMEOUT_DEFAULT_MS: u64 = 120_000;
pub const TIMEOUT_MAX_MS: u64 = 600_000;
pub const TAIL_BYTES: usize = 8 * 1024;
/// After the shell exits, how long to wait for its pipes to close (a background child may hold them).
const PIPE_GRACE: Duration = Duration::from_secs(2);
pub const MEDIA: &str = "text/plain";

/// One output stream being copied to a temp file in `evidence/` while it is hashed.
struct Capture {
    file: std::fs::File,
    tmp: PathBuf,
    hasher: Sha256,
    tail: Vec<u8>,
    bytes: u64,
    error: Option<String>,
}

impl Capture {
    fn new(dir: &Path, name: &str) -> std::io::Result<Self> {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).map_err(|e| std::io::Error::other(e.to_string()))?;
        let tmp = dir.join(format!(".{name}-{}.tmp", hex::encode(r)));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        Ok(Self { file, tmp, hasher: Sha256::new(), tail: Vec::new(), bytes: 0, error: None })
    }

    fn push(&mut self, chunk: &[u8]) {
        if let Err(e) = self.file.write_all(chunk)
            && self.error.is_none()
        {
            self.error = Some(e.to_string());
        }
        self.hasher.update(chunk);
        self.bytes += chunk.len() as u64;
        self.tail.extend_from_slice(chunk);
        if self.tail.len() > 2 * TAIL_BYTES {
            self.tail.drain(..self.tail.len() - TAIL_BYTES);
        }
    }

    /// Move the temp file to `evidence/<sha256>` and describe it.
    fn finish(self, dir: &Path) -> Result<Stream, String> {
        if let Some(e) = self.error {
            let _ = std::fs::remove_file(&self.tmp);
            return Err(format!("evidence write failed: {e}"));
        }
        self.file.sync_all().map_err(|e| e.to_string())?;
        let sha256: [u8; 32] = self.hasher.finalize().into();
        let path = dir.join(hex::encode(sha256));
        if path.exists() {
            let _ = std::fs::remove_file(&self.tmp);
        } else {
            std::fs::rename(&self.tmp, &path).map_err(|e| format!("evidence rename failed: {e}"))?;
        }
        let cut = self.bytes > TAIL_BYTES as u64;
        let mut tail = &self.tail[self.tail.len().saturating_sub(TAIL_BYTES)..];
        if cut {
            // Do not start in the middle of a UTF-8 sequence.
            while tail.first().is_some_and(|b| b & 0xC0 == 0x80) {
                tail = &tail[1..];
            }
        }
        let tail = String::from_utf8_lossy(tail).into_owned();
        Ok(Stream { sha256, bytes: self.bytes, path, tail, cut })
    }
}

/// One captured stream after the command ends.
pub struct Stream {
    pub sha256: [u8; 32],
    pub bytes: u64,
    pub path: PathBuf,
    pub tail: String,
    pub cut: bool,
}

impl Stream {
    pub fn evidence(&self) -> Evidence {
        Evidence { sha256: self.sha256, bytes: i64::try_from(self.bytes).unwrap_or(i64::MAX), media: MEDIA }
    }

    fn reply(&self) -> Value {
        json!({"tail": self.tail, "bytes": self.bytes, "cut": self.cut, "evidence": self.path.display().to_string()})
    }
}

type Shared = Arc<Mutex<Option<Capture>>>;

async fn pump(mut r: impl AsyncRead + Unpin, cap: Shared) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if let Ok(mut g) = cap.lock()
                    && let Some(c) = g.as_mut()
                {
                    c.push(&buf[..n]);
                }
            }
        }
    }
}

fn take(cap: &Shared, dir: &Path) -> Result<Stream, String> {
    let c = cap.lock().map_err(|_| "capture lock poisoned")?.take().ok_or("capture already taken")?;
    c.finish(dir)
}

fn kill_group(pgid: i32) {
    // SAFETY: killpg only sends a signal; a stale or empty group yields ESRCH, which is ignored.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

/// `p` as an SBPL string literal.
fn sbpl_str(p: &Path) -> Result<String, String> {
    let s = p.to_str().ok_or_else(|| format!("{} is not UTF-8 and cannot go in the sandbox profile", p.display()))?;
    Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// The seatbelt profile for one call: deny-list paths neither readable nor writable,
/// `$SYMBIA_HOME` not writable, and with `exec_network: "deny"` no outbound IP traffic.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn profile(policy: &Policy) -> Result<String, String> {
    let mut p = String::from("(version 1)\n(allow default)\n");
    for d in policy.deny_paths() {
        p.push_str(&format!("(deny file-read* file-write* (subpath {}))\n", sbpl_str(d)?));
    }
    for o in policy.own_paths() {
        p.push_str(&format!("(deny file-write* (subpath {}))\n", sbpl_str(o)?));
    }
    if policy.network() == Network::Deny {
        p.push_str("(deny network-outbound)\n(allow network-outbound (remote unix-socket))\n");
    }
    Ok(p)
}

/// The shell for `command`: under `sandbox_exec` on macOS, refused if that is missing.
#[cfg(target_os = "macos")]
fn shell(policy: &Policy, sandbox_exec: &Path, command: &str) -> Result<tokio::process::Command, String> {
    if !sandbox_exec.is_file() {
        return Err(format!("refused: {} is missing; exec does not run unsandboxed", sandbox_exec.display()));
    }
    let mut c = tokio::process::Command::new(sandbox_exec);
    c.arg("-p").arg(profile(policy)?).arg("/bin/zsh").arg("-lc").arg(command);
    Ok(c)
}

/// No sandbox off macOS yet. A network deny cannot be enforced, so it is refused.
#[cfg(not(target_os = "macos"))]
fn shell(policy: &Policy, _sandbox_exec: &Path, command: &str) -> Result<tokio::process::Command, String> {
    if policy.network() == Network::Deny {
        return Err("refused: exec_network \"deny\" needs the macOS sandbox".into());
    }
    let mut c = tokio::process::Command::new("/bin/zsh");
    c.arg("-lc").arg(command);
    Ok(c)
}

/// What a finished command left behind: the reply and the two evidence streams.
pub struct Ran {
    pub reply: String,
    pub stdout: Stream,
    pub stderr: Stream,
}

/// Run `command` in `cwd`. On timeout the whole process group is killed and what was
/// captured so far is returned.
pub async fn exec(policy: &Policy, home: &Path, command: &str, cwd: &str, timeout_ms: Option<u64>, facts: &mut Facts) -> Result<Ran, String> {
    facts.command = Some(command.to_string());
    facts.sandbox = Some(SANDBOX);
    facts.network = Some(policy.network().as_str());
    let timeout_ms = timeout_ms.unwrap_or(TIMEOUT_DEFAULT_MS);
    if !(1..=TIMEOUT_MAX_MS).contains(&timeout_ms) {
        return Err(format!("timeout_ms must be 1 to {TIMEOUT_MAX_MS}"));
    }
    let dir = crate::files::checked(policy, cwd, Access::Write, &mut facts.cwd)?;
    if !dir.is_dir() {
        return Err(format!("cwd {} is not a directory", dir.display()));
    }
    let mut shell = shell(policy, Path::new(SANDBOX_EXEC), command)?;
    let evidence = home.join("evidence");
    std::fs::create_dir_all(&evidence).map_err(|e| e.to_string())?;
    let out: Shared = Arc::new(Mutex::new(Some(Capture::new(&evidence, "stdout").map_err(|e| e.to_string())?)));
    let err: Shared = Arc::new(Mutex::new(Some(Capture::new(&evidence, "stderr").map_err(|e| e.to_string())?)));

    let started = Instant::now();
    // sandbox-exec applies the profile and execs the shell in place, so the group is the shell's.
    let mut child = shell
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn shell: {e}"))?;
    let pgid = child.id().and_then(|id| i32::try_from(id).ok()).ok_or("child has no pid")?;
    let mut pumps = Vec::new();
    if let Some(o) = child.stdout.take() {
        pumps.push(tokio::spawn(pump(o, out.clone())));
    }
    if let Some(e) = child.stderr.take() {
        pumps.push(tokio::spawn(pump(e, err.clone())));
    }

    let exit = match tokio::time::timeout(Duration::from_millis(timeout_ms), child.wait()).await {
        Ok(Ok(status)) => {
            use std::os::unix::process::ExitStatusExt;
            match (status.code(), status.signal()) {
                (Some(c), _) => json!(c),
                (None, Some(s)) => json!(format!("signal {s}")),
                (None, None) => json!(null),
            }
        }
        Ok(Err(e)) => {
            kill_group(pgid);
            return Err(format!("wait: {e}"));
        }
        Err(_) => {
            kill_group(pgid);
            let _ = child.wait().await;
            json!("timeout")
        }
    };
    let _ = tokio::time::timeout(PIPE_GRACE, async {
        for p in &mut pumps {
            let _ = p.await;
        }
    })
    .await;
    for p in &pumps {
        p.abort();
    }
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let stdout = take(&out, &evidence)?;
    let stderr = take(&err, &evidence)?;
    facts.exit = Some(exit.clone());
    facts.stdout_sha256 = Some(hex::encode(stdout.sha256));
    facts.stderr_sha256 = Some(hex::encode(stderr.sha256));
    facts.truncated = stdout.cut || stderr.cut;
    let reply = json!({"exit": exit, "duration_ms": duration_ms, "stdout": stdout.reply(), "stderr": stderr.reply()}).to_string();
    Ok(Ran { reply, stdout, stderr })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, Policy) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let sym = t.path().join("sym");
        std::fs::create_dir_all(&root).unwrap();
        crate::home::ensure(&sym).unwrap();
        let p = Policy::new(std::slice::from_ref(&root), &sym, t.path()).unwrap();
        (t, root, sym, p)
    }

    async fn run(p: &Policy, sym: &Path, cmd: &str, cwd: &Path, timeout: Option<u64>) -> (Value, Ran, Facts) {
        let mut facts = Facts::default();
        let ran = exec(p, sym, cmd, &cwd.display().to_string(), timeout, &mut facts).await.unwrap();
        (serde_json::from_str(&ran.reply).unwrap(), ran, facts)
    }

    fn alive(pid: i32) -> bool {
        // SAFETY: signal 0 only checks that the process exists.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[tokio::test]
    async fn exit_codes_and_output_pass_through() {
        let (_t, root, sym, p) = setup();
        let (r, _ran, facts) = run(&p, &sym, "echo out; echo err >&2; pwd", &root, None).await;
        assert_eq!(r["exit"], 0);
        assert_eq!(r["stdout"]["tail"], format!("out\n{}\n", std::fs::canonicalize(&root).unwrap().display()));
        assert_eq!(r["stderr"]["tail"], "err\n");
        assert_eq!(facts.exit, Some(json!(0)));
        let (r, _, _) = run(&p, &sym, "exit 7", &root, None).await;
        assert_eq!(r["exit"], 7);
        let (r, _, _) = run(&p, &sym, "false", &root, None).await;
        assert_eq!(r["exit"], 1);
    }

    #[tokio::test]
    async fn full_output_lands_in_evidence_with_matching_sha256() {
        let (_t, root, sym, p) = setup();
        let (r, ran, facts) = run(&p, &sym, "for i in $(seq 1 5000); do echo \"line $i\"; done", &root, None).await;
        let full: String = (1..=5000).map(|i| format!("line {i}\n")).collect();
        let sha = hex::encode(crate::canon::sha256(full.as_bytes()));
        let path = sym.join("evidence").join(&sha);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), full);
        assert_eq!(r["stdout"]["evidence"], path.display().to_string());
        assert_eq!(r["stdout"]["bytes"], full.len());
        assert_eq!(r["stdout"]["cut"], true);
        let tail = r["stdout"]["tail"].as_str().unwrap();
        assert!(tail.len() <= TAIL_BYTES && full.ends_with(tail) && tail.ends_with("line 5000\n"));
        assert_eq!(facts.stdout_sha256.as_deref(), Some(sha.as_str()));
        assert!(facts.truncated);
        assert_eq!(hex::encode(ran.stdout.sha256), sha);
        // The empty stderr is evidence too; no temp files are left.
        assert!(sym.join("evidence").join(hex::encode(crate::canon::sha256(b""))).exists());
        assert!(std::fs::read_dir(sym.join("evidence")).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
    }

    #[tokio::test]
    async fn timeout_kills_the_group_and_returns_partial_output() {
        let (_t, root, sym, p) = setup();
        let pidfile = root.join("child.pid");
        let cmd = format!("sleep 60 & echo $! > {}; echo started; echo oops >&2; wait", pidfile.display());
        let t0 = Instant::now();
        let (r, _, facts) = run(&p, &sym, &cmd, &root, Some(1500)).await;
        assert!(t0.elapsed() < Duration::from_secs(10));
        assert_eq!(r["exit"], "timeout");
        assert_eq!(facts.exit, Some(json!("timeout")));
        assert_eq!(r["stdout"]["tail"], "started\n");
        assert_eq!(r["stderr"]["tail"], "oops\n");
        assert!(r["duration_ms"].as_u64().unwrap() >= 1500);
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        // The background sleep was in the group: it is gone (reaped by launchd once orphaned).
        let gone = (0..50).any(|_| {
            std::thread::sleep(Duration::from_millis(100));
            !alive(pid)
        });
        assert!(gone, "child {pid} still running");
    }

    #[tokio::test]
    async fn cwd_is_checked_and_bad_timeouts_refused() {
        let (t, root, sym, p) = setup();
        let mut facts = Facts::default();
        let e = exec(&p, &sym, "true", &t.path().display().to_string(), None, &mut facts).await.err().unwrap();
        assert!(e.starts_with("denied"), "{e}");
        let e = exec(&p, &sym, "true", &sym.join("keys").display().to_string(), None, &mut facts).await.err().unwrap();
        assert!(e.starts_with("denied"), "{e}");
        let r = root.display().to_string();
        assert!(exec(&p, &sym, "true", &r, Some(600_001), &mut facts).await.is_err());
        assert!(exec(&p, &sym, "true", &r, Some(0), &mut facts).await.is_err());
    }

    #[tokio::test]
    async fn cwd_inside_symbia_home_is_refused() {
        let (t, root, sym, _p) = setup();
        // The root covers `SYMBIA_HOME`, yet no cwd under it is allowed, directly or via a symlink.
        let p = Policy::new(&[t.path().to_path_buf()], &sym, t.path()).unwrap();
        std::os::unix::fs::symlink(&sym, root.join("sym")).unwrap();
        for cwd in [sym.clone(), sym.join("sessions"), sym.join("evidence"), root.join("sym/seals")] {
            let e = exec(&p, &sym, "touch x", &cwd.display().to_string(), None, &mut Facts::default()).await.err().unwrap();
            assert!(e.contains("$SYMBIA_HOME"), "{}: {e}", cwd.display());
        }
        assert!(!sym.join("sessions/x").exists());
        run(&p, &sym, "true", &root, None).await;
    }

    #[test]
    fn facts_name_the_command_sandbox_and_network() {
        let (_t, root, sym, p) = setup();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (_, _, facts) = rt.block_on(run(&p, &sym, "echo 'a b'", &root, None));
        assert_eq!(facts.command.as_deref(), Some("echo 'a b'"));
        assert_eq!(facts.sandbox, Some(SANDBOX));
        assert_eq!(facts.network, Some("allow"));
        // A refused call still says what was asked.
        let mut facts = Facts::default();
        assert!(rt.block_on(exec(&p.with_network(Network::Deny), &sym, "ls", "/etc", None, &mut facts)).is_err());
        assert_eq!((facts.command.as_deref(), facts.network), (Some("ls"), Some("deny")));
    }

    #[test]
    fn profile_quotes_paths_and_follows_the_network_setting() {
        let t = tempfile::tempdir().unwrap();
        let user = t.path().join("we\"ird \\home");
        let sym = t.path().join("sym");
        std::fs::create_dir_all(&user).unwrap();
        let p = Policy::new(std::slice::from_ref(&user), &sym, &user).unwrap();
        let prof = profile(&p).unwrap();
        assert!(prof.starts_with("(version 1)\n(allow default)\n"));
        let quoted = |d: &Path| format!("\"{}\"", d.to_str().unwrap().replace('\\', "\\\\").replace('"', "\\\""));
        for d in crate::policy::DENY_IN_HOME.iter().map(|d| user.join(d)).chain([sym.join("keys")]) {
            assert!(prof.contains(&format!("(deny file-read* file-write* (subpath {}))", quoted(&d))), "{prof}");
        }
        assert!(prof.contains("we\\\"ird \\\\home/.ssh"), "{prof}");
        assert!(prof.contains(&format!("(deny file-write* (subpath {}))", quoted(&sym))));
        assert!(!prof.contains("network"));
        let prof = profile(&p.with_network(Network::Deny)).unwrap();
        assert!(prof.ends_with("(deny network-outbound)\n(allow network-outbound (remote unix-socket))\n"));
    }

    #[cfg(target_os = "macos")]
    mod sandbox {
        use super::*;

        const SECRET: &str = "SECRET-7c1f-not-for-exec";

        /// A user home named `user` holding `.ssh/id_test`, a root beside it and `SYMBIA_HOME`
        /// with a key file. The policy's user home is the temp one, not the real `$HOME`.
        fn setup(user: &str) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, Policy) {
            let t = tempfile::tempdir().unwrap();
            let user = t.path().join(user);
            let root = t.path().join("root");
            let sym = t.path().join("sym");
            std::fs::create_dir_all(user.join(".ssh")).unwrap();
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(user.join(".ssh/id_test"), SECRET).unwrap();
            crate::home::ensure(&sym).unwrap();
            std::fs::write(sym.join("keys/test.key"), SECRET).unwrap();
            let p = Policy::new(std::slice::from_ref(&root), &sym, &user).unwrap();
            (t, user, root, sym, p)
        }

        fn quote(p: &Path) -> String {
            format!("'{}'", p.display().to_string().replace('\'', "'\\''"))
        }

        /// The command failed and the secret is nowhere in the reply or the evidence.
        fn refused(r: &Value, ran: &Ran) {
            assert_ne!(r["exit"], 0, "{r}");
            for s in [&ran.stdout, &ran.stderr] {
                assert!(!s.tail.contains(SECRET));
                assert!(!std::fs::read_to_string(&s.path).unwrap().contains(SECRET));
            }
        }

        #[tokio::test]
        async fn deny_list_paths_cannot_be_read() {
            for user in ["user", "we\"ird home"] {
                let (_t, home, root, sym, p) = setup(user);
                for f in [home.join(".ssh/id_test"), sym.join("keys/test.key")] {
                    let (r, ran, _) = run(&p, &sym, &format!("cat {}", quote(&f)), &root, None).await;
                    refused(&r, &ran);
                    assert!(r["stderr"]["tail"].as_str().unwrap().contains("Operation not permitted"), "{r}");
                    // Through the realpath, `..` or a symlink inside the root: still refused.
                    let real = std::fs::canonicalize(&f).unwrap();
                    std::os::unix::fs::symlink(&f, root.join("link")).unwrap();
                    let (r, ran, _) = run(&p, &sym, &format!("cat {} || cat link", quote(&real)), &root, None).await;
                    refused(&r, &ran);
                    std::fs::remove_file(root.join("link")).unwrap();
                }
                // The profile with an odd home still runs ordinary commands.
                let (r, _, _) = run(&p, &sym, "echo ok", &root, None).await;
                assert_eq!((r["exit"].clone(), r["stdout"]["tail"].clone()), (json!(0), json!("ok\n")), "{user}");
            }
        }

        #[tokio::test]
        async fn symbia_home_cannot_be_written() {
            let (_t, _home, root, sym, p) = setup("user");
            let (r, _, _) = run(&p, &sym, &format!("echo x > {}", quote(&sym.join("x"))), &root, None).await;
            assert_ne!(r["exit"], 0, "{r}");
            assert!(!sym.join("x").exists());
            let file = std::fs::read_dir(sym.join("sessions")).unwrap().count();
            let (r, _, _) = run(&p, &sym, &format!("touch {}", quote(&sym.join("sessions/new.sqlite"))), &root, None).await;
            assert_ne!(r["exit"], 0, "{r}");
            assert_eq!(std::fs::read_dir(sym.join("sessions")).unwrap().count(), file);
            // Reading it outside the keys is still allowed.
            std::fs::write(sym.join("config.json"), "{}").unwrap();
            let (r, _, _) = run(&p, &sym, &format!("cat {}", quote(&sym.join("config.json"))), &root, None).await;
            assert_eq!(r["stdout"]["tail"], "{}");
        }

        #[tokio::test]
        async fn roots_and_tools_still_work() {
            let (_t, _home, root, sym, p) = setup("user");
            let (r, _, _) = run(&p, &sym, "mkdir -p d && echo hi > d/f && cat d/f && rm d/f", &root, None).await;
            assert_eq!((r["exit"].clone(), r["stdout"]["tail"].clone()), (json!(0), json!("hi\n")), "{r}");
            let (r, _, _) = run(&p, &sym, "cargo --version", &root, None).await;
            assert_eq!(r["exit"], 0, "{r}");
            assert!(r["stdout"]["tail"].as_str().unwrap().starts_with("cargo "), "{r}");
        }

        /// A loopback HTTP server that counts connections.
        async fn listener() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
            use tokio::io::AsyncWriteExt;
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = l.local_addr().unwrap().port();
            let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let s = seen.clone();
            tokio::spawn(async move {
                while let Ok((mut c, _)) = l.accept().await {
                    s.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut buf = [0u8; 1024];
                    let _ = c.read(&mut buf).await;
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                }
            });
            (port, seen)
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn exec_network_deny_blocks_loopback() {
            let (_t, home, root, sym, _p) = setup("user");
            let curl = |port: u16| format!("curl -s -m 3 http://127.0.0.1:{port}/");

            // Default: no `exec_network` key.
            std::fs::write(sym.join("config.json"), json!({"roots": [root]}).to_string()).unwrap();
            let p = Policy::load(&sym, &home).unwrap();
            let (port, seen) = listener().await;
            let (r, _, facts) = run(&p, &sym, &curl(port), &root, None).await;
            assert_eq!((r["exit"].clone(), r["stdout"]["tail"].clone()), (json!(0), json!("ok")), "{r}");
            assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(facts.network, Some("allow"));

            std::fs::write(sym.join("config.json"), json!({"roots": [root], "exec_network": "deny"}).to_string()).unwrap();
            let p = Policy::load(&sym, &home).unwrap();
            let (port, seen) = listener().await;
            let (r, _, facts) = run(&p, &sym, &curl(port), &root, None).await;
            assert_ne!(r["exit"], 0, "{r}");
            assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0, "the listener saw a connection");
            assert_eq!(facts.network, Some("deny"));
            // Local files and processes are unaffected.
            let (r, _, _) = run(&p, &sym, "echo hi | cat", &root, None).await;
            assert_eq!(r["stdout"]["tail"], "hi\n");
        }

        #[test]
        fn missing_sandbox_exec_refuses() {
            let (_t, _home, _root, _sym, p) = setup("user");
            let e = shell(&p, Path::new("/nonexistent/sandbox-exec"), "true").err().unwrap();
            assert!(e.contains("does not run unsandboxed"), "{e}");
        }
    }
}
