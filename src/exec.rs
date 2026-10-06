//! `symbia_exec`: run `/bin/zsh -lc <command>` in its own process group, keep the full
//! output as evidence and reply with its tail.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::files::Facts;
use crate::policy::{Access, Policy};
use crate::store::Evidence;

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

/// What a finished command left behind: the reply and the two evidence streams.
pub struct Ran {
    pub reply: String,
    pub stdout: Stream,
    pub stderr: Stream,
}

/// Run `command` in `cwd`. On timeout the whole process group is killed and what was
/// captured so far is returned.
pub async fn exec(policy: &Policy, home: &Path, command: &str, cwd: &str, timeout_ms: Option<u64>, facts: &mut Facts) -> Result<Ran, String> {
    let timeout_ms = timeout_ms.unwrap_or(TIMEOUT_DEFAULT_MS);
    if !(1..=TIMEOUT_MAX_MS).contains(&timeout_ms) {
        return Err(format!("timeout_ms must be 1 to {TIMEOUT_MAX_MS}"));
    }
    let dir = crate::files::checked(policy, cwd, Access::Write, &mut facts.cwd)?;
    if !dir.is_dir() {
        return Err(format!("cwd {} is not a directory", dir.display()));
    }
    let evidence = home.join("evidence");
    std::fs::create_dir_all(&evidence).map_err(|e| e.to_string())?;
    let out: Shared = Arc::new(Mutex::new(Some(Capture::new(&evidence, "stdout").map_err(|e| e.to_string())?)));
    let err: Shared = Arc::new(Mutex::new(Some(Capture::new(&evidence, "stderr").map_err(|e| e.to_string())?)));

    let started = Instant::now();
    let mut child = tokio::process::Command::new("/bin/zsh")
        .arg("-lc")
        .arg(command)
        .current_dir(&dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn /bin/zsh: {e}"))?;
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
}
