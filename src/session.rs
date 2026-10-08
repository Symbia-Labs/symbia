//! Opening the stdio session: a lock beside each open session file, resuming the previous
//! session after a server restart, and removing empty files left by duplicate starts.

use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Context;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::now_ms;
use crate::record::RecordInput;
use crate::store::{DEFAULT_TTL_MS, Store, new_session_id};

pub const RESUME_WINDOW_DEFAULT_MS: i64 = 4 * 60 * 60 * 1000;
pub const RESUMED_KEY: &str = "session.resumed";
const MODEL: &str = "symbia";
const LANE_REASON: &str = "written by symbia on resume";

/// The process holding a session: the content of its `.lock` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    pub pid: u32,
    pub started_ms: i64,
}

impl Holder {
    pub fn this_process(started_ms: i64) -> Self {
        Self { pid: std::process::id(), started_ms }
    }
}

/// `sessions/<id>.lock`, held with an exclusive `flock` until dropped. Dropping it deletes
/// the file, then releases the lock.
#[derive(Debug)]
pub struct Lock {
    file: File,
    path: PathBuf,
    /// What the file held when taken: the last holder, if it died without cleaning up.
    previous: Option<Holder>,
}

pub fn lock_path(home: &Path, session: &str) -> PathBuf {
    home.join("sessions").join(format!("{session}.lock"))
}

impl Lock {
    /// Take the lock at `path`, creating the file; `None` if another process holds it.
    pub fn try_take(path: &Path) -> anyhow::Result<Option<Self>> {
        // A holder that deletes the file between our open and our flock leaves us locking
        // an orphan inode; check the path still names it, and retry if not.
        for _ in 0..8 {
            let mut file = File::options().read(true).write(true).create(true).truncate(false).open(path).with_context(|| format!("open {}", path.display()))?;
            // SAFETY: flock on a descriptor we own.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    return Ok(None);
                }
                return Err(e).with_context(|| format!("flock {}", path.display()));
            }
            let same = std::fs::metadata(path).is_ok_and(|m| file.metadata().is_ok_and(|f| f.ino() == m.ino() && f.dev() == m.dev()));
            if !same {
                continue;
            }
            let mut text = String::new();
            let previous = file.read_to_string(&mut text).ok().and_then(|_| serde_json::from_str(&text).ok());
            return Ok(Some(Self { file, path: path.to_path_buf(), previous }));
        }
        anyhow::bail!("lock {} keeps changing", path.display())
    }

    /// The holder named in the file when it was taken.
    pub fn previous(&self) -> Option<Holder> {
        self.previous
    }

    /// Record this process as the holder.
    pub fn write(&mut self, h: Holder) -> anyhow::Result<()> {
        self.file.set_len(0)?;
        self.file.rewind()?;
        self.file.write_all(serde_json::to_string(&h)?.as_bytes())?;
        Ok(())
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The holder written into the session file itself, so it survives the `.lock` file's removal.
fn last_holder(conn: &Connection) -> Option<Holder> {
    conn.query_row("SELECT pid, started_ms FROM holder", [], |r| Ok(Holder { pid: r.get(0)?, started_ms: r.get(1)? })).optional().ok()?
}

fn set_holder(conn: &Connection, h: Holder) -> anyhow::Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS holder (pid INTEGER NOT NULL, started_ms INTEGER NOT NULL) STRICT; DELETE FROM holder;")?;
    conn.execute("INSERT INTO holder (pid, started_ms) VALUES (?1, ?2)", rusqlite::params![h.pid, h.started_ms])?;
    Ok(())
}

/// Session files under `home/sessions`.
fn session_files(home: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(home.join("sessions")) else { return Vec::new() };
    entries.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "sqlite")).collect()
}

fn session_of(path: &Path) -> Option<String> {
    path.file_stem()?.to_str().map(String::from)
}

/// What a session file says about itself, read without writing.
struct Facts {
    rows: i64,
    last_at_ms: Option<i64>,
    retention: String,
    expires_ms: Option<i64>,
    /// `file_meta.format`; 1 for a file from before the column.
    format: i64,
}

fn facts(path: &Path) -> Option<Facts> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).ok()?;
    let (rows, last_at_ms) = conn.query_row("SELECT COUNT(*), MAX(at_ms) FROM chain", [], |r| Ok((r.get(0)?, r.get(1)?))).ok()?;
    let (retention, expires_ms) = conn.query_row("SELECT retention, expires_ms FROM file_meta", [], |r| Ok((r.get(0)?, r.get(1)?))).ok()?;
    let format = conn.query_row("SELECT format FROM file_meta", [], |r| r.get(0)).unwrap_or(1);
    Some(Facts { rows, last_at_ms, retention, expires_ms, format })
}

/// Delete session files with no chain rows whose lock is free (left by duplicate starts).
/// A file that cannot be read is kept. Returns the sessions removed.
pub fn clean_empty(home: &Path) -> Vec<String> {
    let mut removed = Vec::new();
    for path in session_files(home) {
        let Some(session) = session_of(&path) else { continue };
        if facts(&path).is_none_or(|f| f.rows > 0) {
            continue;
        }
        let Ok(Some(lock)) = Lock::try_take(&lock_path(home, &session)) else { continue };
        // Re-check under the lock: a holder may have written since.
        if facts(&path).is_some_and(|f| f.rows == 0) && std::fs::remove_file(&path).is_ok() {
            for ext in ["sqlite-wal", "sqlite-shm"] {
                let _ = std::fs::remove_file(path.with_extension(ext));
            }
            removed.push(session);
        }
        drop(lock);
    }
    removed
}

/// Why the previous session was not resumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotResumed {
    InUse,
    OutsideWindow,
    Expired,
    Sealed,
    ResumeOff,
    /// Written by an earlier build in an older file format, which this build doesn't extend.
    OlderFormat,
}

impl NotResumed {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InUse => "in use",
            Self::OutsideWindow => "outside the resume window",
            Self::Expired => "expired",
            Self::Sealed => "sealed",
            Self::ResumeOff => "resume off",
            Self::OlderFormat => "older file format",
        }
    }
}

/// How the session was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    Resumed { gap_ms: i64, seq: i64, resumes: i64 },
    New { previous: Option<(String, NotResumed)> },
}

impl Opened {
    /// The one-time `notice` for the first tool reply.
    pub fn notice(&self, session: &str) -> String {
        match self {
            Self::Resumed { gap_ms, seq, .. } => format!("session {session} resumed after a server restart; gap {} s; seq continues at {seq}", gap_ms / 1000),
            Self::New { previous: Some((p, why)) } => format!("new session {session}; the previous one ({p}) was not resumed: {}", why.as_str()),
            Self::New { previous: None } => format!("new session {session}"),
        }
    }

    pub fn previous_session(&self) -> Option<&str> {
        match self {
            Self::New { previous: Some((p, _)) } => Some(p),
            _ => None,
        }
    }
}

/// Open the stdio session under `home`: resume the newest session file if it qualifies,
/// otherwise create a new one. Either way the returned store holds its lock.
pub fn open(home: &Path, resume_window_ms: i64, me: Holder) -> anyhow::Result<(Store, Opened)> {
    crate::home::ensure(home)?;
    let now = now_ms();
    let newest = session_files(home)
        .into_iter()
        .filter_map(|p| {
            let f = facts(&p)?;
            Some((f.last_at_ms?, p, f))
        })
        .max_by_key(|(at, _, _)| *at);
    let mut previous = None;
    if let Some((last_at, path, f)) = newest {
        let session = session_of(&path).context("session file name is not UTF-8")?;
        let why = if resume_window_ms == 0 {
            Some(NotResumed::ResumeOff)
        } else if f.retention != "session" {
            Some(NotResumed::Sealed)
        } else if f.format != crate::record::FORMAT {
            Some(NotResumed::OlderFormat)
        } else if f.expires_ms.is_some_and(|e| e <= now) {
            Some(NotResumed::Expired)
        } else if now - last_at > resume_window_ms {
            Some(NotResumed::OutsideWindow)
        } else {
            match Lock::try_take(&lock_path(home, &session))? {
                Some(lock) => return resume(home, &path, lock, last_at, me),
                None => Some(NotResumed::InUse),
            }
        };
        previous = why.map(|w| (session, w));
    }
    let session = new_session_id(now)?;
    let mut lock = Lock::try_take(&lock_path(home, &session))?.context("new session lock is held")?;
    lock.write(me)?;
    let mut store = Store::create_with(home, &session, now + DEFAULT_TTL_MS, None)?;
    set_holder(store.conn(), me)?;
    store.hold(lock);
    Ok((store, Opened::New { previous }))
}

fn resume(home: &Path, path: &Path, mut lock: Lock, last_at: i64, me: Holder) -> anyhow::Result<(Store, Opened)> {
    let mut store = Store::open(home, path)?;
    let prev = lock.previous().or_else(|| last_holder(store.conn()));
    let earlier: i64 = store.conn().query_row("SELECT COUNT(*) FROM records WHERE key = ?1", [RESUMED_KEY], |r| r.get(0))?;
    let resumes = earlier + 1;
    let gap_ms = now_ms() - last_at;
    let input = RecordInput {
        key: RESUMED_KEY.into(),
        kind: "observation".into(),
        lane: "apocryphal".into(),
        lane_reason: LANE_REASON.into(),
        body: json!({
            "previous_pid": prev.map(|h| h.pid),
            "previous_started_ms": prev.map(|h| h.started_ms),
            "gap_ms": gap_ms,
            "resumes": resumes,
        }),
        model: MODEL.into(),
        est_host_ms: None,
        est_chars: None,
        links: None,
    };
    let w = store.write(&input, Instant::now())?;
    lock.write(me)?;
    set_holder(store.conn(), me)?;
    store.hold(lock);
    Ok((store, Opened::Resumed { gap_ms, seq: w.seq, resumes }))
}

/// `session.resumed` records in this session so far.
pub fn resumes(store: &Store) -> anyhow::Result<i64> {
    Ok(store.conn().query_row("SELECT COUNT(*) FROM records WHERE key = ?1", [RESUMED_KEY], |r| r.get(0))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn me() -> Holder {
        Holder::this_process(now_ms())
    }

    fn obs(key: &str) -> RecordInput {
        RecordInput {
            key: key.into(),
            kind: "observation".into(),
            lane: "canonical".into(),
            lane_reason: "t".into(),
            body: json!({}),
            model: "m".into(),
            est_host_ms: None,
            est_chars: None,
            links: None,
        }
    }

    #[test]
    fn a_lock_excludes_a_second_taker_and_vanishes_on_drop() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.lock");
        let mut a = Lock::try_take(&p).unwrap().unwrap();
        assert!(a.previous().is_none());
        a.write(Holder { pid: 7, started_ms: 9 }).unwrap();
        assert!(Lock::try_take(&p).unwrap().is_none());
        assert_eq!(serde_json::from_str::<Value>(&std::fs::read_to_string(&p).unwrap()).unwrap(), json!({"pid": 7, "started_ms": 9}));
        drop(a);
        assert!(!p.exists());
        // A stale file from a dead holder is free and names it.
        std::fs::write(&p, r#"{"pid": 3, "started_ms": 4}"#).unwrap();
        let b = Lock::try_take(&p).unwrap().unwrap();
        assert_eq!(b.previous(), Some(Holder { pid: 3, started_ms: 4 }));
    }

    #[test]
    fn resume_continues_the_newest_session_and_counts_resumes() {
        let t = tempfile::tempdir().unwrap();
        let first = Holder { pid: 11, started_ms: 22 };
        let (mut s, o) = open(t.path(), RESUME_WINDOW_DEFAULT_MS, first).unwrap();
        assert_eq!(o, Opened::New { previous: None });
        assert!(o.notice(s.session()).starts_with("new session "));
        s.write(&obs("a"), Instant::now()).unwrap();
        let id = s.session().to_string();
        drop(s);
        assert!(!lock_path(t.path(), &id).exists());

        let (s, o) = open(t.path(), RESUME_WINDOW_DEFAULT_MS, me()).unwrap();
        assert_eq!(s.session(), id);
        let Opened::Resumed { seq, resumes, .. } = o else { panic!("{o:?}") };
        assert_eq!((seq, resumes), (2, 1));
        let rid = s.id_for_key(RESUMED_KEY, None).unwrap().unwrap();
        let rec = s.get(&rid).unwrap().unwrap();
        assert_eq!((rec["kind"].as_str(), rec["lane"].as_str()), (Some("observation"), Some("apocryphal")));
        assert_eq!((rec["body"]["previous_pid"].clone(), rec["body"]["previous_started_ms"].clone()), (json!(11), json!(22)));
        assert!(rec["body"]["gap_ms"].as_i64().unwrap() >= 0);
        assert!(o.notice(&id).contains("seq continues at 2"));
        drop(s);
        let (s, o) = open(t.path(), RESUME_WINDOW_DEFAULT_MS, me()).unwrap();
        assert!(matches!(o, Opened::Resumed { seq: 3, resumes: 2, .. }), "{o:?}");
        assert_eq!(super::resumes(&s).unwrap(), 2);
    }

    #[test]
    fn each_reason_opens_a_new_session() {
        let t = tempfile::tempdir().unwrap();
        let (mut a, _) = open(t.path(), RESUME_WINDOW_DEFAULT_MS, me()).unwrap();
        a.write(&obs("a"), Instant::now()).unwrap();
        let id = a.session().to_string();
        let why = |window| match open(t.path(), window, me()).unwrap() {
            (s, Opened::New { previous: Some((p, w)) }) => {
                assert_eq!(p, id);
                assert_ne!(s.session(), id);
                // The new session is empty: remove it so `a` stays the newest.
                let path = s.path().to_path_buf();
                drop(s);
                std::fs::remove_file(path).unwrap();
                w
            }
            (_, other) => panic!("{other:?}"),
        };
        assert_eq!(why(RESUME_WINDOW_DEFAULT_MS), NotResumed::InUse);
        assert_eq!(why(0), NotResumed::ResumeOff);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(why(1), NotResumed::OutsideWindow);
        a.conn().execute("UPDATE file_meta SET expires_ms = 1", []).unwrap();
        assert_eq!(why(RESUME_WINDOW_DEFAULT_MS), NotResumed::Expired);
        a.conn().execute("UPDATE file_meta SET retention = 'seal'", []).unwrap();
        assert_eq!(why(RESUME_WINDOW_DEFAULT_MS), NotResumed::Sealed);
        // A file from an earlier build is left alone.
        a.conn().execute("UPDATE file_meta SET retention = 'session', expires_ms = NULL, format = 2", []).unwrap();
        assert_eq!(why(RESUME_WINDOW_DEFAULT_MS), NotResumed::OlderFormat);
        assert_eq!(NotResumed::OlderFormat.as_str(), "older file format");
    }

    #[test]
    fn cleanup_removes_only_free_empty_files() {
        let t = tempfile::tempdir().unwrap();
        let empty = Store::create(t.path()).unwrap();
        let mut full = Store::create(t.path()).unwrap();
        full.write(&obs("a"), Instant::now()).unwrap();
        let (held, _) = open(t.path(), 0, me()).unwrap();
        let (e, f, h) = (empty.path().to_path_buf(), full.path().to_path_buf(), held.path().to_path_buf());
        let empty_id = empty.session().to_string();
        drop((empty, full));
        assert_eq!(clean_empty(t.path()), vec![empty_id.clone()]);
        assert!(!e.exists() && f.exists() && h.exists());
        assert!(!lock_path(t.path(), &empty_id).exists());
        // A garbage file is kept.
        let junk = t.path().join("sessions").join("junk.sqlite");
        std::fs::write(&junk, "not sqlite").unwrap();
        drop(held);
        let removed = clean_empty(t.path());
        assert_eq!(removed.len(), 1);
        assert!(junk.exists() && !h.exists());
    }
}
