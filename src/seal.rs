//! Sealing a session file into a signed copy, and verifying sealed copies.

use std::path::{Path, PathBuf};

use anyhow::Context;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canon::{canonical, sha256};
use crate::now_ms;
use crate::record::{FORMAT, GENESIS, IdFields, Link, RowFields, chain_hash, chain_hash_v2, chain_hash_v3, check_thread, record_id, row_digest, thread_sha256};
use crate::store::{Store, chain_head};

/// The `.seal.json` sidecar. Byte fields are lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sidecar {
    pub session: String,
    pub file_sha256: String,
    pub chain_head: String,
    pub chain_seq: i64,
    pub public_key: String,
    pub signature: String,
    pub at_ms: i64,
    /// Set on a thread seal only, so full-seal sidecars are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    /// Why the seal was made: explicit, prediction, checkpoint, exit or ledger. Absent on seals
    /// from builds before R10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Why a seal is made. Checkpoint and exit seals are pruned once a newer full seal covers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Explicit,
    Prediction,
    Checkpoint,
    Exit,
    Ledger,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Prediction => "prediction",
            Self::Checkpoint => "checkpoint",
            Self::Exit => "exit",
            Self::Ledger => "ledger",
        }
    }
}

/// Reasons whose seals a newer full seal of the same session replaces.
const PRUNABLE: [&str; 2] = ["checkpoint", "exit"];

#[derive(Debug, Clone)]
pub struct Sealed {
    pub path: PathBuf,
    pub sidecar: Sidecar,
    pub verified: bool,
}

/// A thread seal and what it holds.
#[derive(Debug, Clone)]
pub struct ThreadSealed {
    pub sealed: Sealed,
    /// Records of the thread kept in the copy.
    pub records: i64,
    /// Chain rows of other threads whose records were withheld.
    pub withheld: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub session: String,
    pub chain_seq: i64,
    pub chain_head: String,
    /// Links to records in other sessions: hashed with the row, target not checked here.
    pub external: Vec<External>,
    /// The thread a thread seal covers; `None` for a full seal.
    pub thread: Option<String>,
    /// Records present in the file.
    pub records: i64,
    /// Chain rows whose records a thread seal withheld.
    pub withheld: i64,
}

/// A link whose target lives in another session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct External {
    pub from_id: String,
    pub to_id: String,
    pub rel: String,
    pub session: String,
}

/// `seals/<session>-<seq>.sqlite` → `seals/<session>-<seq>.seal.json`.
pub fn sidecar_path(sealed: &Path) -> PathBuf {
    sealed.with_extension("seal.json")
}

/// The message a seal signature covers: `file_sha256 || chain_head`.
pub fn signed_message(file_sha256: &[u8; 32], chain_head: &[u8; 32]) -> [u8; 64] {
    let mut m = [0u8; 64];
    m[..32].copy_from_slice(file_sha256);
    m[32..].copy_from_slice(chain_head);
    m
}

pub fn read_sidecar(sealed: &Path) -> anyhow::Result<Sidecar> {
    let p = sidecar_path(sealed);
    let text = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    Ok(serde_json::from_str(&text)?)
}

/// Checkpoint the live file, copy it with `VACUUM INTO`, mark the copy `seal`, hash it and sign.
///
/// Sealing again at an unchanged chain seq returns the existing seal.
pub fn seal(store: &Store, key: &SigningKey) -> anyhow::Result<Sealed> {
    seal_for(store, key, Reason::Explicit)
}

/// As [`seal`], noting why. A new seal is written to the witness (when the store has one), and
/// once it verifies, older checkpoint and exit seals of the same session are removed.
pub fn seal_for(store: &Store, key: &SigningKey, reason: Reason) -> anyhow::Result<Sealed> {
    let conn = store.conn();
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    let (seq, _) = chain_head(conn)?;
    let path = store.home().join("seals").join(format!("{}-{seq}.sqlite", store.session()));
    if path.exists() {
        if let Ok(mut sidecar) = read_sidecar(&path) {
            // A seal asked for on purpose at the head of a checkpoint or exit seal keeps it from pruning.
            if matches!(reason, Reason::Explicit | Reason::Prediction) && sidecar.reason.as_deref().is_some_and(|r| PRUNABLE.contains(&r)) {
                sidecar.reason = Some(reason.as_str().into());
                std::fs::write(sidecar_path(&path), canonical(&sidecar)?)?;
            }
            let verified = verify(&path).is_ok();
            return Ok(Sealed { path, sidecar, verified });
        }
        // A copy without a sidecar is an interrupted seal; redo it.
        std::fs::remove_file(&path)?;
    }
    let path_str = path.to_str().context("seal path is not UTF-8")?;
    conn.execute("VACUUM INTO ?1", [path_str])?;

    let head = {
        let copy = Connection::open(&path)?;
        copy.query_row("PRAGMA journal_mode=DELETE", [], |_| Ok(()))?;
        copy.execute("UPDATE file_meta SET retention = 'seal'", [])?;
        let (copy_seq, head) = chain_head(&copy)?;
        anyhow::ensure!(copy_seq == seq, "chain moved during seal");
        copy.close().map_err(|(_, e)| e)?;
        head
    };
    let file_sha = sha256(&std::fs::read(&path)?);
    let signature = key.sign(&signed_message(&file_sha, &head));
    let sidecar = Sidecar {
        session: store.session().to_string(),
        file_sha256: hex::encode(file_sha),
        chain_head: hex::encode(head),
        chain_seq: seq,
        public_key: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
        at_ms: now_ms(),
        thread: None,
        reason: Some(reason.as_str().into()),
    };
    std::fs::write(sidecar_path(&path), canonical(&sidecar)?)?;
    let verified = verify(&path).is_ok();
    witness(store, &sidecar);
    if verified {
        prune_superseded(store.home(), store.session(), seq);
    }
    Ok(Sealed { path, sidecar, verified })
}

/// What a legacy cleanup did, or would do, for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPrune {
    pub session: String,
    /// The newest full seal, kept.
    pub kept: PathBuf,
    /// Older reason-less full seals that the kept one covers: removed, or to be removed.
    pub superseded: Vec<PathBuf>,
    /// Why the session was left alone, when it was.
    pub skipped: Option<String>,
}

/// Remove full seals made before seals recorded a reason, where a newer full seal of the same
/// session covers them. For each session the newest full seal is kept; an older reason-less
/// seal goes only if the newest verifies and its chain holds the older seal's head at the
/// older seq. Each removed seal is first written to the witness folder (with reason `legacy`),
/// so its signed head and time outlive the file. Nothing is removed unless `confirm`.
pub fn prune_legacy(home: &Path, witness: &Path, confirm: bool) -> anyhow::Result<Vec<LegacyPrune>> {
    let mut by_session: std::collections::BTreeMap<String, Vec<(i64, PathBuf)>> = std::collections::BTreeMap::new();
    for e in std::fs::read_dir(home.join("seals"))?.flatten() {
        let path = e.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".sqlite")) else { continue };
        if stem.contains(".thread-") {
            continue;
        }
        let Some((session, n)) = stem.rsplit_once('-').and_then(|(s, n)| n.parse::<i64>().ok().map(|n| (s.to_string(), n))) else { continue };
        by_session.entry(session).or_default().push((n, path));
    }
    let mut out = Vec::new();
    for (session, mut files) in by_session {
        files.sort();
        let Some((newest_seq, newest)) = files.pop() else { continue };
        let mut report = LegacyPrune { session, kept: newest.clone(), superseded: Vec::new(), skipped: None };
        if let Err(e) = verify(&newest) {
            report.skipped = Some(format!("newest seal does not verify: {e}"));
            out.push(report);
            continue;
        }
        let conn = Connection::open_with_flags(&newest, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        for (seq, path) in files {
            let Ok(sc) = read_sidecar(&path) else { continue };
            if sc.reason.is_some() || seq >= newest_seq {
                continue;
            }
            let head: Option<Vec<u8>> = if seq == 0 {
                Some(GENESIS.to_vec())
            } else {
                conn.query_row("SELECT hash FROM chain WHERE seq = ?1", [seq], |r| r.get(0)).optional()?
            };
            if head.map(hex::encode).as_deref() != Some(sc.chain_head.as_str()) {
                continue;
            }
            if confirm {
                let mut entry = crate::witness::Entry::from_sidecar(&sc);
                entry.reason = Some("legacy".into());
                crate::witness::append(witness, &entry)?;
                std::fs::remove_file(&path)?;
                let _ = std::fs::remove_file(sidecar_path(&path));
            }
            report.superseded.push(path);
        }
        out.push(report);
    }
    Ok(out)
}

/// How long a seal waits for its witness line. The witness folder may sit behind a macOS
/// privacy prompt (Documents, Desktop, iCloud Drive), and opening a file there blocks until
/// someone answers the prompt.
pub const WITNESS_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Write a new seal to the store's witness folder; a failure goes to stderr.
fn witness(store: &Store, sidecar: &Sidecar) {
    if let Some(dir) = store.witness() {
        witness_within(dir, sidecar, WITNESS_WAIT);
    }
}

/// Append the seal's witness line on a thread of its own and wait at most `wait` for it. A
/// write still blocked after that is left to finish by itself and the seal goes ahead, so one
/// stuck folder can't hold the store. Returns whether the line landed in time.
fn witness_within(dir: &Path, sidecar: &Sidecar, wait: std::time::Duration) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    let (to, entry) = (dir.to_path_buf(), crate::witness::Entry::from_sidecar(sidecar));
    std::thread::spawn(move || {
        let _ = tx.send(crate::witness::append(&to, &entry).map_err(|e| format!("{e:#}")));
    });
    match rx.recv_timeout(wait) {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            eprintln!("symbia: witness write to {} failed: {e}", dir.display());
            false
        }
        Err(_) => {
            eprintln!(
                "symbia: witness write to {} did not finish within {} ms; the seal stands, and the line is written if the folder becomes writable",
                dir.display(),
                wait.as_millis()
            );
            false
        }
    }
}

/// Remove full seals of `session` older than `seq` whose reason is checkpoint or exit. Explicit,
/// prediction, thread and reason-less seals stay. Returns the files removed.
pub fn prune_superseded(home: &Path, session: &str, seq: i64) -> Vec<PathBuf> {
    let prefix = format!("{session}-");
    let Ok(entries) = std::fs::read_dir(home.join("seals")) else { return Vec::new() };
    let mut removed = Vec::new();
    for e in entries.flatten() {
        let path = e.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
        let Some(n) = name.strip_prefix(&prefix).and_then(|r| r.strip_suffix(".sqlite")).and_then(|r| r.parse::<i64>().ok()) else { continue };
        if n >= seq {
            continue;
        }
        let prunable = read_sidecar(&path).ok().and_then(|s| s.reason).is_some_and(|r| PRUNABLE.contains(&r.as_str()));
        if prunable && std::fs::remove_file(&path).is_ok() {
            let _ = std::fs::remove_file(sidecar_path(&path));
            removed.push(path);
        }
    }
    removed
}

/// The format 2 row digest of record `rid`, read from `conn`, with `at_ms` from its chain row.
fn stored_row_digest(conn: &Connection, rid: &str, at_ms: i64) -> anyhow::Result<[u8; 32]> {
    type Row = (String, i64, String, String, String, String, String, String, Option<i64>, Option<i64>, Option<i64>);
    let r: Row = conn.query_row(
        "SELECT key, version, kind, lane, lane_reason, json(body), model, session, expires_ms, est_host_ms, est_chars FROM records WHERE id = ?1",
        [rid],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?)),
    )?;
    let links: Vec<Link> = conn
        .prepare("SELECT to_id, rel, to_session FROM links WHERE from_id = ?1")?
        .query_map([rid], |l| Ok((l.get(0)?, l.get(1)?, l.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let body: Value = serde_json::from_str(&r.5)?;
    row_digest(&RowFields {
        id: rid,
        key: &r.0,
        version: r.1,
        kind: &r.2,
        lane: &r.3,
        lane_reason: &r.4,
        body: &body,
        model: &r.6,
        session: &r.7,
        at_ms,
        expires_ms: r.8,
        est_host_ms: r.9,
        est_chars: r.10,
        links: &links,
    })
}

/// `seals/<session>-<seq>.thread-<first 8 hex of the thread's sha256>.sqlite`.
pub fn thread_seal_path(store: &Store, seq: i64, thread: &str) -> PathBuf {
    let tag = &hex::encode(thread_sha256(thread))[..8];
    store.home().join("seals").join(format!("{}-{seq}.thread-{tag}.sqlite", store.session()))
}

/// Seal one thread: a copy of the whole chain in which every other thread's records are
/// withheld, leaving only their chain rows and row digests. The copy proves the thread's
/// records and their place in the chain; its head is the full chain's head at the same seq.
pub fn seal_thread(store: &Store, key: &SigningKey, thread: &str) -> anyhow::Result<ThreadSealed> {
    check_thread(thread).map_err(anyhow::Error::msg)?;
    let conn = store.conn();
    let format = file_format(conn)?;
    anyhow::ensure!(format >= 3, "this session predates threads (file format {format})");
    let records: i64 = conn.query_row("SELECT COUNT(*) FROM chain WHERE thread = ?1", [thread], |r| r.get(0))?;
    anyhow::ensure!(records > 0, "thread {thread} has no records");
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    let (seq, head) = chain_head(conn)?;
    let path = thread_seal_path(store, seq, thread);
    if path.exists() {
        if let Ok(sidecar) = read_sidecar(&path) {
            let v = verify(&path);
            let withheld = v.as_ref().map_or(0, |v| v.withheld);
            return Ok(ThreadSealed { sealed: Sealed { path, sidecar, verified: v.is_ok() }, records, withheld });
        }
        std::fs::remove_file(&path)?;
    }
    let path_str = path.to_str().context("seal path is not UTF-8")?;
    conn.execute("VACUUM INTO ?1", [path_str])?;

    let withheld = {
        let copy = Connection::open(&path)?;
        copy.query_row("PRAGMA journal_mode=DELETE", [], |_| Ok(()))?;
        let others: Vec<(i64, String, i64)> = copy
            .prepare("SELECT seq, record_id, at_ms FROM chain WHERE thread IS NOT ?1 AND record_id IS NOT NULL ORDER BY seq")?
            .query_map([thread], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        for (row_seq, rid, at_ms) in &others {
            let digest = stored_row_digest(&copy, rid, *at_ms)?;
            copy.execute("UPDATE chain SET row_digest = ?1, thread = NULL WHERE seq = ?2", rusqlite::params![digest.as_slice(), row_seq])?;
        }
        let gone = "(SELECT record_id FROM chain WHERE thread IS NULL AND record_id IS NOT NULL)";
        copy.execute(&format!("DELETE FROM links WHERE from_id IN {gone}"), [])?;
        copy.execute(&format!("DELETE FROM records_fts WHERE id IN {gone}"), [])?;
        copy.execute(&format!("DELETE FROM records WHERE id IN {gone}"), [])?;
        copy.execute("DELETE FROM evidence WHERE NOT EXISTS (SELECT 1 FROM records r WHERE instr(json(r.body), lower(hex(evidence.sha256))) > 0)", [])?;
        // Merge the full-text index so withheld text is not left in old segments.
        copy.execute("INSERT INTO records_fts (records_fts) VALUES ('optimize')", [])?;
        copy.execute("UPDATE file_meta SET retention = 'seal', thread = ?1", [thread])?;
        // Drop the deleted content from free pages.
        copy.execute_batch("VACUUM")?;
        let (copy_seq, copy_head) = chain_head(&copy)?;
        anyhow::ensure!(copy_seq == seq && copy_head == head, "chain moved during seal");
        copy.close().map_err(|(_, e)| e)?;
        i64::try_from(others.len())?
    };
    let file_sha = sha256(&std::fs::read(&path)?);
    let signature = key.sign(&signed_message(&file_sha, &head));
    let sidecar = Sidecar {
        session: store.session().to_string(),
        file_sha256: hex::encode(file_sha),
        chain_head: hex::encode(head),
        chain_seq: seq,
        public_key: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
        at_ms: now_ms(),
        thread: Some(thread.to_string()),
        reason: Some(Reason::Explicit.as_str().into()),
    };
    std::fs::write(sidecar_path(&path), canonical(&sidecar)?)?;
    let verified = verify(&path).is_ok();
    witness(store, &sidecar);
    Ok(ThreadSealed { sealed: Sealed { path, sidecar, verified }, records, withheld })
}

/// Seal `store` if a record was written after its last seal. `None` for an empty session
/// or one already sealed at its head.
pub fn seal_pending(store: &Store, key: &SigningKey) -> anyhow::Result<Option<Sealed>> {
    let (seq, _) = store.head()?;
    if seq == 0 || last_seal(store.home(), store.session()).is_some_and(|(_, s)| s.chain_seq >= seq) {
        return Ok(None);
    }
    seal_for(store, key, Reason::Exit).map(Some)
}

/// Records written since the last seal that trigger a checkpoint seal.
pub const CHECKPOINT_RECORDS: i64 = 50;

/// After a write of a record of `kind`: seal if it is a `prediction` (so a prediction is sealed
/// before the work it predicts) or if [`CHECKPOINT_RECORDS`] records were written since the
/// last seal. A checkpoint is an ordinary seal; `None` when none was due.
pub fn checkpoint(store: &Store, key: &SigningKey, kind: &str) -> anyhow::Result<Option<Sealed>> {
    let (seq, _) = store.head()?;
    let sealed = last_seal(store.home(), store.session()).map_or(0, |(_, s)| s.chain_seq);
    if seq > sealed && (kind == "prediction" || seq - sealed >= CHECKPOINT_RECORDS) {
        let reason = if kind == "prediction" { Reason::Prediction } else { Reason::Checkpoint };
        return seal_for(store, key, reason).map(Some);
    }
    Ok(None)
}

/// The newest seal of `session` under `home/seals`, by chain seq.
pub fn last_seal(home: &Path, session: &str) -> Option<(PathBuf, Sidecar)> {
    let prefix = format!("{session}-");
    std::fs::read_dir(home.join("seals"))
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let seq: i64 = name.strip_prefix(&prefix)?.strip_suffix(".sqlite")?.parse().ok()?;
            let sidecar = read_sidecar(&e.path()).ok()?;
            Some((seq, e.path(), sidecar))
        })
        .max_by_key(|(seq, _, _)| *seq)
        .map(|(_, p, s)| (p, s))
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    hex::decode(s).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| format!("sidecar {what} is malformed"))
}

/// A record row as stored, read back for verification.
struct StoredRow {
    key: String,
    version: i64,
    kind: String,
    lane: String,
    lane_reason: String,
    body: String,
    model: String,
    session: String,
    at_ms: i64,
    expires_ms: Option<i64>,
    est_host_ms: Option<i64>,
    est_chars: Option<i64>,
    host_ms: Option<i64>,
    chars: Option<i64>,
}

/// `file_meta.format`; a file without the column predates it and is format 1.
fn file_format(conn: &Connection) -> rusqlite::Result<i64> {
    let has: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('file_meta') WHERE name = 'format'", [], |r| r.get(0))?;
    if has == 0 {
        return Ok(1);
    }
    conn.query_row("SELECT format FROM file_meta", [], |r| r.get(0))
}

/// Verify a sealed copy, accepting only a sidecar key in `trusted` (lowercase hex).
pub fn verify_trusted(path: &Path, trusted: &[String]) -> Result<Verified, String> {
    let sc = read_sidecar(path).map_err(|e| format!("sidecar unreadable: {e}"))?;
    let pk = sc.public_key.to_ascii_lowercase();
    if !trusted.contains(&pk) {
        let mut short = pk;
        short.truncate(12);
        return Err(format!("untrusted key {short}"));
    }
    verify(path)
}

/// Verify a sealed copy against its sidecar, whatever key signed it. `Err` carries a one-line reason.
pub fn verify(path: &Path) -> Result<Verified, String> {
    let sc = read_sidecar(path).map_err(|e| format!("sidecar unreadable: {e}"))?;
    let want_sha = hex32(&sc.file_sha256, "file_sha256")?;
    let want_head = hex32(&sc.chain_head, "chain_head")?;
    let pk = hex32(&sc.public_key, "public_key")?;
    let sig = hex::decode(&sc.signature)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or("sidecar signature is malformed")?;

    let bytes = std::fs::read(path).map_err(|e| format!("cannot read sealed file: {e}"))?;
    if sha256(&bytes) != want_sha {
        return Err("file sha256 mismatch".into());
    }
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "sidecar public_key is not a valid ed25519 key")?;
    vk.verify(&signed_message(&want_sha, &want_head), &Signature::from_bytes(&sig))
        .map_err(|_| "signature invalid")?;

    let db = |e: rusqlite::Error| format!("sealed file unreadable: {e}");
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).map_err(db)?;
    let retention: String = conn.query_row("SELECT retention FROM file_meta", [], |r| r.get(0)).map_err(db)?;
    if retention != "seal" {
        return Err(format!("retention is {retention:?}, not \"seal\""));
    }

    let format = file_format(&conn).map_err(db)?;
    if !(1..=FORMAT).contains(&format) {
        return Err(format!("unknown file format {format}"));
    }

    // Format 3 adds the thread columns; a thread seal names its thread in file_meta.
    let scope: Option<String> = if format >= 3 { conn.query_row("SELECT thread FROM file_meta", [], |r| r.get(0)).map_err(db)? } else { None };
    if scope != sc.thread {
        return Err("sidecar thread does not match the file".into());
    }
    if let Some(t) = &scope {
        check_thread(t)?;
    }
    let chain_sql = if format >= 3 {
        "SELECT seq, prev_hash, hash, at_ms, record_id, thread, thread_sha256, row_digest FROM chain ORDER BY seq"
    } else {
        "SELECT seq, prev_hash, hash, at_ms, record_id, NULL, NULL, NULL FROM chain ORDER BY seq"
    };
    let mut chain = conn.prepare(chain_sql).map_err(db)?;
    let mut rec = conn
        .prepare(
            "SELECT key, version, kind, lane, lane_reason, json(body), model, session, at_ms, expires_ms, est_host_ms, est_chars, host_ms, chars
             FROM records WHERE id = ?1",
        )
        .map_err(db)?;
    // Files from before cross-session links have no `to_session` column; every link is local there.
    let has_to_session: i64 =
        conn.query_row("SELECT COUNT(*) FROM pragma_table_info('links') WHERE name = 'to_session'", [], |r| r.get(0)).map_err(db)?;
    let links_sql = if has_to_session > 0 {
        "SELECT to_id, rel, to_session FROM links WHERE from_id = ?1"
    } else {
        "SELECT to_id, rel, NULL FROM links WHERE from_id = ?1"
    };
    let mut links = conn.prepare(links_sql).map_err(db)?;
    let mut external = Vec::new();
    let rows = chain
        .query_map([], |r| {
            Ok(ChainRow {
                seq: r.get(0)?,
                prev_hash: r.get(1)?,
                hash: r.get(2)?,
                at_ms: r.get(3)?,
                record_id: r.get(4)?,
                thread: r.get(5)?,
                thread_sha256: r.get(6)?,
                row_digest: r.get(7)?,
            })
        })
        .map_err(db)?;
    let mut prev = GENESIS;
    let mut seq_expected = 1i64;
    let mut on_chain = 0i64;
    let mut withheld = 0i64;
    for row in rows {
        let ChainRow { seq, prev_hash, hash, at_ms, record_id: rid, thread, thread_sha256: thread_digest, row_digest: stored_digest } = row.map_err(db)?;
        if seq != seq_expected {
            return Err(format!("chain seq gap at {seq_expected}"));
        }
        if prev_hash != prev {
            return Err(format!("chain prev_hash mismatch at seq {seq}"));
        }
        let Some(rid) = rid else {
            // Format 1 hashed a record-less chain row as an empty id; format 2 has no such rows.
            if format != 1 {
                return Err(format!("chain row without record at seq {seq}"));
            }
            let computed = chain_hash(&prev, "", at_ms);
            if hash != computed {
                return Err(format!("chain hash mismatch at seq {seq}"));
            }
            prev = computed;
            seq_expected += 1;
            continue;
        };
        let tsha: Option<[u8; 32]> = match (format >= 3, thread_digest) {
            (false, _) => None,
            (true, d) => Some(d.and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()).ok_or_else(|| format!("chain thread digest malformed at seq {seq}"))?),
        };
        let r = rec
            .query_row([&rid], |r| {
                Ok(StoredRow {
                    key: r.get(0)?,
                    version: r.get(1)?,
                    kind: r.get(2)?,
                    lane: r.get(3)?,
                    lane_reason: r.get(4)?,
                    body: r.get(5)?,
                    model: r.get(6)?,
                    session: r.get(7)?,
                    at_ms: r.get(8)?,
                    expires_ms: r.get(9)?,
                    est_host_ms: r.get(10)?,
                    est_chars: r.get(11)?,
                    host_ms: r.get(12)?,
                    chars: r.get(13)?,
                })
            })
            .optional()
            .map_err(db)?;
        let Some(r) = r else {
            // Only a thread seal withholds records, and never one of its own thread.
            let (Some(scope), Some(tsha)) = (&scope, tsha) else {
                return Err(format!("record missing at seq {seq}"));
            };
            if thread.is_some() {
                return Err(format!("withheld row names its thread at seq {seq}"));
            }
            if tsha == thread_sha256(scope) {
                return Err(format!("a record of thread {scope} was withheld at seq {seq}"));
            }
            let digest = stored_digest
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| format!("withheld row has no digest at seq {seq}"))?;
            let computed = chain_hash_v3(&prev, &digest, at_ms, &tsha);
            if hash != computed {
                return Err(format!("chain hash mismatch at seq {seq}"));
            }
            withheld += 1;
            prev = computed;
            seq_expected += 1;
            continue;
        };
        on_chain += 1;
        if let Some(tsha) = tsha {
            let t = thread.as_deref().ok_or_else(|| format!("chain row without thread at seq {seq}"))?;
            if thread_sha256(t) != tsha {
                return Err(format!("thread digest mismatch at seq {seq}"));
            }
            if let Some(scope) = &scope
                && t != scope
            {
                return Err(format!("record of thread {t} in a seal of thread {scope} at seq {seq}"));
            }
            if stored_digest.is_some() {
                return Err(format!("row digest stored beside its record at seq {seq}"));
            }
        }
        let body: Value = serde_json::from_str(&r.body).map_err(|_| format!("record body unreadable at seq {seq}"))?;
        let id = record_id(&IdFields {
            key: &r.key,
            version: r.version,
            kind: &r.kind,
            lane: &r.lane,
            body: &body,
            model: &r.model,
            session: &r.session,
        })
        .map_err(|e| format!("cannot canonicalize record at seq {seq}: {e}"))?;
        if id != rid {
            return Err(format!("record id mismatch at seq {seq}"));
        }
        let computed = if format == 1 {
            chain_hash(&prev, &rid, at_ms)
        } else {
            let row_links: Vec<Link> =
                links.query_map([&rid], |l| Ok((l.get(0)?, l.get(1)?, l.get(2)?))).map_err(db)?.collect::<Result<_, _>>().map_err(db)?;
            for (to_id, rel, to_session) in &row_links {
                if let Some(s) = to_session {
                    external.push(External { from_id: rid.clone(), to_id: to_id.clone(), rel: rel.clone(), session: s.clone() });
                }
            }
            // The chain row's at_ms stands in for the record's; the two are compared below.
            let digest = row_digest(&RowFields {
                id: &rid,
                key: &r.key,
                version: r.version,
                kind: &r.kind,
                lane: &r.lane,
                lane_reason: &r.lane_reason,
                body: &body,
                model: &r.model,
                session: &r.session,
                at_ms,
                expires_ms: r.expires_ms,
                est_host_ms: r.est_host_ms,
                est_chars: r.est_chars,
                links: &row_links,
            })
            .map_err(|e| format!("cannot canonicalize record at seq {seq}: {e}"))?;
            match tsha {
                Some(t) => chain_hash_v3(&prev, &digest, at_ms, &t),
                None => chain_hash_v2(&prev, &digest, at_ms),
            }
        };
        if hash != computed {
            return Err(format!("chain hash mismatch at seq {seq}"));
        }
        if r.at_ms != at_ms {
            return Err(format!("record at_ms mismatch at seq {seq}"));
        }
        if r.session != sc.session {
            return Err(format!("record session mismatch at seq {seq}"));
        }
        if r.host_ms.is_none() || r.chars.is_none() {
            return Err(format!("record cost fields missing at seq {seq}"));
        }
        prev = computed;
        seq_expected += 1;
    }
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0)).map_err(db)?;
    if total != on_chain {
        return Err(format!("{} record(s) not on the chain", total - on_chain));
    }
    let stray: i64 = conn
        .query_row("SELECT COUNT(*) FROM links WHERE from_id NOT IN (SELECT record_id FROM chain WHERE record_id IS NOT NULL)", [], |r| r.get(0))
        .map_err(db)?;
    if stray != 0 {
        return Err(format!("{stray} link(s) not on the chain"));
    }
    let last_seq = seq_expected - 1;
    if last_seq != sc.chain_seq {
        return Err(format!("chain seq mismatch: file {last_seq}, sidecar {}", sc.chain_seq));
    }
    if prev != want_head {
        return Err("chain head mismatch".into());
    }
    Ok(Verified { session: sc.session, chain_seq: last_seq, chain_head: sc.chain_head, external, thread: scope, records: on_chain, withheld })
}

/// One chain row as read for verification; the last three columns are format 3 only.
struct ChainRow {
    seq: i64,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
    at_ms: i64,
    record_id: Option<String>,
    thread: Option<String>,
    thread_sha256: Option<Vec<u8>>,
    row_digest: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{LinkInput, RecordInput};
    use serde_json::json;
    use std::time::Instant;

    fn input(key: &str, body: Value) -> RecordInput {
        RecordInput {
            key: key.into(),
            kind: "observation".into(),
            lane: "conditional".into(),
            lane_reason: "test".into(),
            body,
            model: "m".into(),
            est_host_ms: None,
            est_chars: None,
            links: None,
        }
    }

    struct Fx {
        _t: tempfile::TempDir,
        store: Store,
        key: SigningKey,
    }

    fn fx() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let mut store = Store::create(t.path()).unwrap();
        let key = crate::keys::load_or_create(t.path()).unwrap();
        // Tricky bodies: unicode, escapes, float forms, large integers.
        let a1 = store.write(&input("a", json!({"t": "café \u{1F600} \"q\" \\ \n", "f": 0.1, "e": 1e21, "n": -0.0})), Instant::now()).unwrap();
        store.write(&input("b", json!({"big": 9007199254740993u64, "neg": -42, "arr": [1.5, "x", null]})), Instant::now()).unwrap();
        let mut a2 = input("a", json!(["v2"]));
        a2.links = Some(vec![LinkInput { to_id: a1.id, rel: "revises".into() }]);
        store.write(&a2, Instant::now()).unwrap();
        Fx { _t: t, store, key }
    }

    /// Re-hash and re-sign the sidecar so checks past the signature run.
    fn resign(path: &Path, key: &SigningKey) {
        let mut sc = read_sidecar(path).unwrap();
        let sha = sha256(&std::fs::read(path).unwrap());
        let head = hex32(&sc.chain_head, "h").unwrap();
        sc.file_sha256 = hex::encode(sha);
        sc.signature = hex::encode(key.sign(&signed_message(&sha, &head)).to_bytes());
        std::fs::write(sidecar_path(path), canonical(&sc).unwrap()).unwrap();
    }

    fn tamper(path: &Path, sql: &str) {
        let c = Connection::open(path).unwrap();
        assert_eq!(c.execute(sql, []).unwrap(), 1, "{sql}");
    }

    #[test]
    fn seal_round_trip_verifies() {
        let f = fx();
        let s = seal(&f.store, &f.key).unwrap();
        assert!(s.verified);
        assert_eq!(s.path, f.store.home().join("seals").join(format!("{}-3.sqlite", f.store.session())));
        assert_eq!(s.sidecar.chain_seq, 3);
        assert_eq!(s.sidecar.chain_head, hex::encode(f.store.head().unwrap().1));
        assert_eq!(s.sidecar.public_key, hex::encode(f.key.verifying_key().to_bytes()));
        let v = verify(&s.path).unwrap();
        assert_eq!((v.session.as_str(), v.chain_seq), (f.store.session(), 3));
        // The copy says seal; the live file still says session.
        let c = Connection::open_with_flags(&s.path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let r: String = c.query_row("SELECT retention FROM file_meta", [], |r| r.get(0)).unwrap();
        assert_eq!(r, "seal");
        assert_eq!(f.store.retention().unwrap(), "session");
        // The sidecar is canonical JSON.
        let text = std::fs::read_to_string(sidecar_path(&s.path)).unwrap();
        assert_eq!(text, canonical(&serde_json::from_str::<Value>(&text).unwrap()).unwrap());
        // Hash covers the file as it sits on disk, after the retention write.
        assert_eq!(s.sidecar.file_sha256, hex::encode(sha256(&std::fs::read(&s.path).unwrap())));
    }

    #[test]
    fn sealing_twice_at_same_seq_reuses_the_seal() {
        let f = fx();
        let a = seal(&f.store, &f.key).unwrap();
        let b = seal(&f.store, &f.key).unwrap();
        assert_eq!(a.path, b.path);
        assert_eq!(a.sidecar, b.sidecar);
        assert_eq!(last_seal(f.store.home(), f.store.session()).unwrap().1, a.sidecar);
    }

    #[test]
    fn empty_session_seals_at_seq_zero() {
        let t = tempfile::tempdir().unwrap();
        let store = Store::create(t.path()).unwrap();
        let key = crate::keys::load_or_create(t.path()).unwrap();
        let s = seal(&store, &key).unwrap();
        assert!(s.verified);
        assert_eq!(s.sidecar.chain_seq, 0);
        assert_eq!(s.sidecar.chain_head, hex::encode(GENESIS));
    }

    #[test]
    fn tampered_row_fails_file_hash() {
        let f = fx();
        let s = seal(&f.store, &f.key).unwrap();
        tamper(&s.path, "UPDATE records SET lane = 'canonical' WHERE key = 'b'");
        assert_eq!(verify(&s.path).unwrap_err(), "file sha256 mismatch");
    }

    #[test]
    fn rehashed_without_key_fails_signature() {
        let f = fx();
        let s = seal(&f.store, &f.key).unwrap();
        tamper(&s.path, "UPDATE records SET lane = 'canonical' WHERE key = 'b'");
        let mut sc = read_sidecar(&s.path).unwrap();
        sc.file_sha256 = hex::encode(sha256(&std::fs::read(&s.path).unwrap()));
        std::fs::write(sidecar_path(&s.path), canonical(&sc).unwrap()).unwrap();
        assert_eq!(verify(&s.path).unwrap_err(), "signature invalid");
    }

    #[test]
    fn tampered_record_fields_fail_record_id() {
        for sql in [
            "UPDATE records SET lane = 'canonical' WHERE key = 'b'",
            "UPDATE records SET body = jsonb('{\"big\":1}') WHERE key = 'b'",
            "UPDATE records SET model = 'other' WHERE key = 'b'",
            "UPDATE records SET version = 7 WHERE key = 'b'",
        ] {
            let f = fx();
            let s = seal(&f.store, &f.key).unwrap();
            tamper(&s.path, sql);
            resign(&s.path, &f.key);
            assert_eq!(verify(&s.path).unwrap_err(), "record id mismatch at seq 2", "{sql}");
        }
    }

    #[test]
    fn tampered_chain_rows_fail_with_position() {
        let cases = [
            ("UPDATE chain SET at_ms = at_ms + 1 WHERE seq = 2", "chain hash mismatch at seq 2"),
            ("UPDATE chain SET prev_hash = zeroblob(32) WHERE seq = 3", "chain prev_hash mismatch at seq 3"),
            ("DELETE FROM chain WHERE seq = 2", "chain seq gap at 2"),
            ("UPDATE records SET at_ms = at_ms + 1 WHERE key = 'b'", "record at_ms mismatch at seq 2"),
            ("UPDATE records SET id = 'x' WHERE key = 'b'", "record missing at seq 2"),
            ("UPDATE file_meta SET retention = 'session'", "retention is \"session\", not \"seal\""),
        ];
        for (sql, want) in cases {
            let f = fx();
            let s = seal(&f.store, &f.key).unwrap();
            tamper(&s.path, sql);
            resign(&s.path, &f.key);
            assert_eq!(verify(&s.path).unwrap_err(), want, "{sql}");
        }
    }

    #[test]
    fn off_chain_record_is_detected() {
        let f = fx();
        let s = seal(&f.store, &f.key).unwrap();
        tamper(
            &s.path,
            "INSERT INTO records (id, key, version, kind, lane, lane_reason, body, model, session, at_ms)
             VALUES ('x', 'z', 1, 'claim', 'canonical', 'r', jsonb('1'), 'm', 's', 0)",
        );
        resign(&s.path, &f.key);
        assert_eq!(verify(&s.path).unwrap_err(), "1 record(s) not on the chain");
    }

    #[test]
    fn tampered_write_time_fields_fail_chain_hash() {
        let cases = [
            ("UPDATE records SET lane_reason = 'other' WHERE key = 'b'", 2),
            ("UPDATE links SET rel = 'cites'", 3),
            ("UPDATE links SET to_id = (SELECT id FROM records WHERE key = 'b')", 3),
            ("UPDATE records SET expires_ms = expires_ms + 1 WHERE key = 'b'", 2),
            ("UPDATE records SET est_host_ms = 1 WHERE key = 'b'", 2),
            ("UPDATE records SET est_chars = 1 WHERE key = 'b'", 2),
        ];
        for (sql, seq) in cases {
            let f = fx();
            let s = seal(&f.store, &f.key).unwrap();
            tamper(&s.path, sql);
            resign(&s.path, &f.key);
            assert_eq!(verify(&s.path).unwrap_err(), format!("chain hash mismatch at seq {seq}"), "{sql}");
        }
    }

    #[test]
    fn sealed_records_need_cost_fields_and_no_stray_links() {
        let cases = [
            ("UPDATE records SET host_ms = NULL WHERE key = 'b'", "record cost fields missing at seq 2"),
            ("UPDATE records SET chars = NULL WHERE key = 'b'", "record cost fields missing at seq 2"),
            ("INSERT INTO links (from_id, to_id, rel) VALUES ('x', 'y', 'cites')", "1 link(s) not on the chain"),
            ("UPDATE file_meta SET format = 4", "unknown file format 4"),
        ];
        for (sql, want) in cases {
            let f = fx();
            let s = seal(&f.store, &f.key).unwrap();
            tamper(&s.path, sql);
            resign(&s.path, &f.key);
            assert_eq!(verify(&s.path).unwrap_err(), want, "{sql}");
        }
    }

    /// A seal written by the part 1 build: no `format` column, chain over record ids only.
    fn format1_fixture() -> (tempfile::TempDir, PathBuf) {
        fixture("format1")
    }

    /// `tests/fixtures/<name>.sqlite` and its sidecar, copied to a temp dir.
    fn fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let dst = t.path().join(format!("{name}.sqlite"));
        std::fs::copy(src.join(format!("{name}.sqlite")), &dst).unwrap();
        std::fs::copy(src.join(format!("{name}.seal.json")), sidecar_path(&dst)).unwrap();
        (t, dst)
    }

    #[test]
    fn format2_seal_still_verifies() {
        // Written by the R7 binary: three records, a resume record and one link.
        let (_t, path) = fixture("format2");
        let c = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(file_format(&c).unwrap(), 2);
        let v = verify(&path).unwrap();
        assert_eq!((v.chain_seq, v.records, v.withheld, v.thread), (4, 4, 0, None));
    }

    const SECRET: &str = "SECRET-b-4f1e-withheld";

    /// Threads `a` and `b` interleaved, then one record in `main`. `b` holds a secret; `a2`
    /// links to `b1` and cites evidence of its own.
    fn threaded() -> (tempfile::TempDir, Store, SigningKey) {
        use crate::store::Evidence;
        let t = tempfile::tempdir().unwrap();
        let mut s = Store::create(t.path()).unwrap();
        let key = crate::keys::load_or_create(t.path()).unwrap();
        let now = Instant::now;
        let a1 = s.write_in("a", &input("a1", json!({"text": "alpha one"})), now(), None, &[]).unwrap();
        let ev_b = Evidence { sha256: [0xab; 32], bytes: 3, media: "text/plain" };
        let b1 = s.write_in("b", &input("b1", json!({"text": SECRET, "stdout_sha256": hex::encode([0xab; 32])})), now(), None, &[ev_b]).unwrap();
        let ev_a = Evidence { sha256: [0xcd; 32], bytes: 4, media: "text/plain" };
        let mut a2 = input("a2", json!({"stdout_sha256": hex::encode([0xcd; 32])}));
        a2.links = Some(vec![LinkInput { to_id: b1.id, rel: "cites".into() }, LinkInput { to_id: a1.id, rel: "revises".into() }]);
        s.write_in("a", &a2, now(), None, &[ev_a]).unwrap();
        s.write_in("b", &input("b2", json!({"text": SECRET})), now(), None, &[]).unwrap();
        s.write(&input("m", json!(1)), now()).unwrap();
        (t, s, key)
    }

    fn contains(path: &Path, needle: &str) -> bool {
        std::fs::read(path).unwrap().windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    #[test]
    fn thread_seal_keeps_one_thread_and_withholds_the_rest() {
        let (_t, s, key) = threaded();
        let full = seal(&s, &key).unwrap();
        let ts = seal_thread(&s, &key, "a").unwrap();
        assert!(ts.sealed.verified);
        assert_eq!((ts.records, ts.withheld), (2, 3));
        // Same head as the full chain at the same seq.
        assert_eq!((ts.sealed.sidecar.chain_seq, &ts.sealed.sidecar.chain_head), (5, &full.sidecar.chain_head));
        assert_eq!(ts.sealed.sidecar.thread.as_deref(), Some("a"));
        let tag = &hex::encode(thread_sha256("a"))[..8];
        assert_eq!(ts.sealed.path, s.home().join("seals").join(format!("{}-5.thread-{tag}.sqlite", s.session())));
        let v = verify(&ts.sealed.path).unwrap();
        assert_eq!((v.thread.as_deref(), v.records, v.withheld), (Some("a"), 2, 3));
        let vf = verify(&full.path).unwrap();
        assert_eq!((vf.thread, vf.records, vf.withheld), (None, 5, 0));
        // The other thread's text is gone from every page of the file; the full seal is the control.
        assert!(contains(&full.path, SECRET));
        assert!(!contains(&ts.sealed.path, SECRET));
        // Evidence rows cited only by withheld records are dropped.
        let c = Connection::open_with_flags(&ts.sealed.path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let ev: Vec<Vec<u8>> = c.prepare("SELECT sha256 FROM evidence").unwrap().query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(ev, vec![vec![0xcd; 32]]);
        // Thread seals don't count as the session's last seal, and sealing again reuses the file.
        assert_eq!(last_seal(s.home(), s.session()).unwrap().1, full.sidecar);
        assert_eq!(seal_thread(&s, &key, "a").unwrap().sealed.sidecar, ts.sealed.sidecar);
        // The main thread seals on its own too.
        let m = seal_thread(&s, &key, "main").unwrap();
        assert_eq!((m.records, m.withheld, m.sealed.verified), (1, 4, true));
    }

    #[test]
    fn thread_seal_refusals() {
        let (_t, s, key) = threaded();
        assert!(seal_thread(&s, &key, "nobody").unwrap_err().to_string().contains("thread nobody has no records"));
        assert_eq!(seal_thread(&s, &key, "a b").unwrap_err().to_string(), crate::record::THREAD_RULE);
    }

    #[test]
    fn tampered_thread_seals_fail() {
        let (t, s, key) = threaded();
        let ts = seal_thread(&s, &key, "a").unwrap();
        let relabel = format!("UPDATE chain SET thread = 'b', thread_sha256 = X'{}' WHERE seq = 1", hex::encode(thread_sha256("b")));
        let cases = [
            ("DELETE FROM records WHERE key = 'a2'", "withheld row names its thread at seq 3".to_string()),
            (
                "DELETE FROM records WHERE key = 'a2'; UPDATE chain SET thread = NULL, row_digest = zeroblob(32) WHERE seq = 3",
                "a record of thread a was withheld at seq 3".to_string(),
            ),
            ("UPDATE chain SET thread = 'b' WHERE seq = 1", "thread digest mismatch at seq 1".to_string()),
            (relabel.as_str(), "record of thread b in a seal of thread a at seq 1".to_string()),
            ("UPDATE chain SET row_digest = zeroblob(32) WHERE seq = 2", "chain hash mismatch at seq 2".to_string()),
            ("UPDATE chain SET thread_sha256 = zeroblob(32) WHERE seq = 2", "chain hash mismatch at seq 2".to_string()),
            ("UPDATE file_meta SET thread = 'b'", "sidecar thread does not match the file".to_string()),
        ];
        for (sql, want) in cases {
            let copy = t.path().join("copy.sqlite");
            std::fs::copy(&ts.sealed.path, &copy).unwrap();
            std::fs::copy(sidecar_path(&ts.sealed.path), sidecar_path(&copy)).unwrap();
            Connection::open(&copy).unwrap().execute_batch(sql).unwrap();
            resign(&copy, &key);
            assert_eq!(verify(&copy).unwrap_err(), want, "{sql}");
        }
    }

    #[test]
    fn tampered_threads_in_a_full_seal_fail() {
        let (t, s, key) = threaded();
        let full = seal(&s, &key).unwrap();
        let sha_b = hex::encode(thread_sha256("b"));
        let cases = [
            ("UPDATE chain SET thread = 'b' WHERE seq = 1".to_string(), "thread digest mismatch at seq 1"),
            // Moving a record to another thread, digest and all, breaks the chain.
            (format!("UPDATE chain SET thread = 'b', thread_sha256 = X'{sha_b}' WHERE seq = 1"), "chain hash mismatch at seq 1"),
            ("UPDATE chain SET row_digest = zeroblob(32) WHERE seq = 1".to_string(), "row digest stored beside its record at seq 1"),
            ("DELETE FROM records WHERE key = 'm'".to_string(), "record missing at seq 5"),
        ];
        for (sql, want) in cases {
            let copy = t.path().join("copy.sqlite");
            std::fs::copy(&full.path, &copy).unwrap();
            std::fs::copy(sidecar_path(&full.path), sidecar_path(&copy)).unwrap();
            Connection::open(&copy).unwrap().execute_batch(&sql).unwrap();
            resign(&copy, &key);
            assert_eq!(verify(&copy).unwrap_err(), want, "{sql}");
        }
    }

    #[test]
    fn format1_seal_still_verifies() {
        let (_t, path) = format1_fixture();
        let c = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(file_format(&c).unwrap(), 1);
        let links: i64 = c.query_row("SELECT COUNT(*) FROM links", [], |r| r.get(0)).unwrap();
        assert_eq!(links, 1);
        let v = verify(&path).unwrap();
        assert_eq!(v.chain_seq, 2);
    }

    #[test]
    fn verify_trusted_rejects_unpinned_keys() {
        let f = fx();
        let s = seal(&f.store, &f.key).unwrap();
        let own = hex::encode(f.key.verifying_key().to_bytes());
        assert!(verify_trusted(&s.path, std::slice::from_ref(&own)).is_ok());
        // Re-signed with a fresh key: the file is internally consistent but the key is not pinned.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let mut sc = read_sidecar(&s.path).unwrap();
        sc.public_key = hex::encode(other.verifying_key().to_bytes());
        std::fs::write(sidecar_path(&s.path), canonical(&sc).unwrap()).unwrap();
        resign(&s.path, &other);
        assert!(verify(&s.path).is_ok());
        assert_eq!(verify_trusted(&s.path, &[own]).unwrap_err(), format!("untrusted key {}", &sc.public_key[..12]));
        assert!(verify_trusted(&s.path, &[sc.public_key.clone()]).is_ok());
    }

    #[test]
    fn missing_sidecar_fails() {
        let f = fx();
        let s = seal(&f.store, &f.key).unwrap();
        std::fs::remove_file(sidecar_path(&s.path)).unwrap();
        assert!(verify(&s.path).unwrap_err().starts_with("sidecar unreadable"));
    }

    #[test]
    fn seal_pending_skips_empty_and_already_sealed_sessions() {
        let t = tempfile::tempdir().unwrap();
        let mut store = Store::create(t.path()).unwrap();
        let key = crate::keys::load_or_create(t.path()).unwrap();
        assert!(seal_pending(&store, &key).unwrap().is_none());
        assert_eq!(std::fs::read_dir(t.path().join("seals")).unwrap().count(), 0);
        store.write(&input("a", json!(1)), Instant::now()).unwrap();
        let s = seal_pending(&store, &key).unwrap().unwrap();
        assert_eq!((s.sidecar.chain_seq, s.verified), (1, true));
        assert!(seal_pending(&store, &key).unwrap().is_none());
        store.write(&input("a", json!(2)), Instant::now()).unwrap();
        assert_eq!(seal_pending(&store, &key).unwrap().unwrap().sidecar.chain_seq, 2);
    }

    #[test]
    fn cross_session_links_verify_as_external() {
        let t = tempfile::tempdir().unwrap();
        let key = crate::keys::load_or_create(t.path()).unwrap();
        let mut a = Store::create(t.path()).unwrap();
        let mut p = input("p", json!("rain"));
        p.kind = "prediction".into();
        let pw = a.write(&p, Instant::now()).unwrap();
        seal(&a, &key).unwrap();
        let mut b = Store::create(t.path()).unwrap();
        let local = b.write(&input("l", json!(1)), Instant::now()).unwrap();
        let mut r = input("r", json!("rain"));
        r.links = Some(vec![LinkInput { to_id: pw.id.clone(), rel: "results_of".into() }, LinkInput { to_id: local.id, rel: "cites".into() }]);
        let rw = b.write(&r, Instant::now()).unwrap();
        let s = seal(&b, &key).unwrap();
        assert!(s.verified);
        let v = verify(&s.path).unwrap();
        assert_eq!(v.external, [External { from_id: rw.id, to_id: pw.id, rel: "results_of".into(), session: a.session().into() }]);
        // The session is hashed with the row: dropping or changing it breaks the chain.
        for sql in ["UPDATE links SET to_session = NULL WHERE rel = 'results_of'", "UPDATE links SET to_session = 'other' WHERE rel = 'results_of'", "UPDATE links SET to_session = 'x' WHERE rel = 'cites'"] {
            let copy = t.path().join("copy.sqlite");
            std::fs::copy(&s.path, &copy).unwrap();
            std::fs::copy(sidecar_path(&s.path), sidecar_path(&copy)).unwrap();
            tamper(&copy, sql);
            resign(&copy, &key);
            assert_eq!(verify(&copy).unwrap_err(), "chain hash mismatch at seq 2", "{sql}");
        }
    }

    fn seal_files(home: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(home.join("seals"))
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".sqlite"))
            .collect();
        v.sort_by_key(|n| n.split('-').nth(2).and_then(|x| x.split('.').next()).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0));
        v
    }

    #[test]
    fn checkpoint_and_exit_seals_are_pruned_and_the_rest_kept() {
        let t = tempfile::tempdir().unwrap();
        let mut s = Store::create(t.path()).unwrap();
        let key = crate::keys::load_or_create(t.path()).unwrap();
        let sid = s.session().to_string();
        let w = |s: &mut Store, k: &str| {
            s.write(&input(k, json!(1)), Instant::now()).unwrap();
        };
        w(&mut s, "a");
        let e1 = seal_for(&s, &key, Reason::Exit).unwrap();
        assert_eq!(e1.sidecar.reason.as_deref(), Some("exit"));
        w(&mut s, "b");
        seal_for(&s, &key, Reason::Checkpoint).unwrap();
        // The checkpoint at seq 2 replaced the exit seal at seq 1.
        assert_eq!(seal_files(t.path()), [format!("{sid}-2.sqlite")]);
        w(&mut s, "c");
        seal_for(&s, &key, Reason::Prediction).unwrap();
        w(&mut s, "d");
        seal(&s, &key).unwrap();
        w(&mut s, "e");
        seal_thread(&s, &key, "main").unwrap();
        // A pre-R10 seal (no reason) is never pruned.
        w(&mut s, "f");
        let old = seal_for(&s, &key, Reason::Checkpoint).unwrap();
        let mut sc = old.sidecar.clone();
        sc.reason = None;
        std::fs::write(sidecar_path(&old.path), canonical(&sc).unwrap()).unwrap();
        w(&mut s, "g");
        let last = seal_for(&s, &key, Reason::Exit).unwrap();
        assert!(last.verified);
        let tag = &hex::encode(thread_sha256("main"))[..8];
        assert_eq!(
            seal_files(t.path()),
            [format!("{sid}-3.sqlite"), format!("{sid}-4.sqlite"), format!("{sid}-5.thread-{tag}.sqlite"), format!("{sid}-6.sqlite"), format!("{sid}-7.sqlite")]
        );
        // Sidecars went with their files, and what remains verifies.
        assert!(!sidecar_path(&e1.path).exists());
        for f in seal_files(t.path()) {
            assert!(verify(&t.path().join("seals").join(&f)).is_ok(), "{f}");
        }
        // Sealing explicitly at the head of an exit seal keeps it from later pruning.
        let again = seal(&s, &key).unwrap();
        assert_eq!((again.sidecar.chain_seq, again.sidecar.reason.as_deref()), (7, Some("explicit")));
        assert!(verify(&again.path).is_ok(), "the reason is not signed, so rewriting it keeps the seal valid");
    }

    /// A witness file that can't be opened yet (here a FIFO with no reader, as a privacy
    /// prompt holds an open in a protected folder) doesn't hold the seal past the wait, and
    /// the line still arrives once the file opens.
    #[test]
    fn a_blocked_witness_does_not_hold_the_seal() {
        use std::io::Read;
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("sym");
        let mut s = Store::create(&home).unwrap();
        let key = crate::keys::load_or_create(&home).unwrap();
        s.write(&input("a", json!(1)), Instant::now()).unwrap();
        let sealed = seal(&s, &key).unwrap();
        let wdir = t.path().join("witness");
        std::fs::create_dir_all(&wdir).unwrap();
        let fifo = std::ffi::CString::new(wdir.join(crate::witness::FILE).to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let started = Instant::now();
        assert!(!witness_within(&wdir, &sealed.sidecar, std::time::Duration::from_millis(200)));
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "the seal waited {:?}", started.elapsed());

        let mut line = String::new();
        std::fs::File::open(wdir.join(crate::witness::FILE)).unwrap().read_to_string(&mut line).unwrap();
        let e: crate::witness::Entry = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(e, crate::witness::Entry::from_sidecar(&sealed.sidecar));
    }

    #[test]
    fn every_seal_is_witnessed_and_checked() {
        let t = tempfile::tempdir().unwrap();
        let wdir = t.path().join("elsewhere/witness");
        let home = t.path().join("sym");
        let mut s = Store::create(&home).unwrap();
        s.set_witness(Some(wdir.clone()));
        let key = crate::keys::load_or_create(&home).unwrap();
        s.write(&input("a", json!(1)), Instant::now()).unwrap();
        let first = seal(&s, &key).unwrap();
        s.write_in("chat", &input("b", json!(2)), Instant::now(), None, &[]).unwrap();
        let ts = seal_thread(&s, &key, "chat").unwrap();
        s.write(&input("c", json!(3)), Instant::now()).unwrap();
        let second = seal_for(&s, &key, Reason::Checkpoint).unwrap();
        let entries = crate::witness::read(&wdir.join(crate::witness::FILE)).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], crate::witness::Entry::from_sidecar(&first.sidecar));
        assert_eq!((entries[1].thread.as_deref(), entries[2].reason.as_deref()), (Some("chat"), Some("checkpoint")));
        use crate::witness::{Check, check};
        let sid = s.session().to_string();
        assert_eq!(check(&second.path, &sid, 3, &entries), Ok(Check::Ok { entries: 3 }));
        // The earlier seal is behind what the witness saw: a rollback, if offered as the latest.
        assert_eq!(check(&first.path, &sid, 1, &entries), Ok(Check::Behind { entries: 1, seen_seq: 3 }));
        assert_eq!(check(&ts.sealed.path, &sid, 2, &entries), Ok(Check::Behind { entries: 2, seen_seq: 3 }));
        assert_eq!(check(&second.path, "other", 3, &entries), Ok(Check::NotWitnessed));
        // Rewrite a record and its chain from there on, then re-sign: the file is consistent and
        // verifies on its own, but the witness remembers the old heads.
        let copy = t.path().join("rewritten.sqlite");
        std::fs::copy(&second.path, &copy).unwrap();
        std::fs::copy(sidecar_path(&second.path), sidecar_path(&copy)).unwrap();
        {
            let c = Connection::open(&copy).unwrap();
            c.execute("UPDATE records SET lane_reason = 'rewritten' WHERE key = 'a'", []).unwrap();
            let rows: Vec<(i64, String, i64, Option<String>)> =
                c.prepare("SELECT seq, record_id, at_ms, thread FROM chain ORDER BY seq").unwrap().query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap().collect::<Result<_, _>>().unwrap();
            let mut prev = GENESIS;
            for (seq, rid, at_ms, thread) in rows {
                let d = stored_row_digest(&c, &rid, at_ms).unwrap();
                let h = chain_hash_v3(&prev, &d, at_ms, &thread_sha256(thread.as_deref().unwrap()));
                c.execute("UPDATE chain SET prev_hash = ?1, hash = ?2 WHERE seq = ?3", rusqlite::params![prev.as_slice(), h.as_slice(), seq]).unwrap();
                prev = h;
            }
            let mut sc = read_sidecar(&copy).unwrap();
            sc.chain_head = hex::encode(prev);
            std::fs::write(sidecar_path(&copy), canonical(&sc).unwrap()).unwrap();
        }
        resign(&copy, &key);
        assert!(verify(&copy).is_ok(), "re-signed with the device key, the rewrite is self-consistent");
        assert_eq!(check(&copy, &sid, 3, &entries), Err("witness mismatch at seq 1".into()));
    }

    #[test]
    fn legacy_seals_are_pruned_only_when_covered_and_witnessed_first() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("sym");
        let wdir = t.path().join("witness");
        let mut s = Store::create(&home).unwrap();
        let key = crate::keys::load_or_create(&home).unwrap();
        let mut legacy = Vec::new();
        for k in ["a", "b", "c"] {
            s.write(&input(k, json!(1)), Instant::now()).unwrap();
            // An explicit seal with its reason removed stands in for one made before R10.
            let x = seal(&s, &key).unwrap();
            let mut sc = x.sidecar.clone();
            sc.reason = None;
            std::fs::write(sidecar_path(&x.path), canonical(&sc).unwrap()).unwrap();
            legacy.push(x);
        }
        s.write(&input("d", json!(1)), Instant::now()).unwrap();
        let kept = seal(&s, &key).unwrap();
        // A seal of another chain under the same session name is not covered, and stays.
        let other_home = t.path().join("other");
        let mut o = Store::create_with(&other_home, s.session(), i64::MAX, None).unwrap();
        o.write(&input("zz", json!(9)), Instant::now()).unwrap();
        let foreign = seal(&o, &key).unwrap();
        let mut sc = foreign.sidecar.clone();
        sc.reason = None;
        std::fs::write(sidecar_path(&foreign.path), canonical(&sc).unwrap()).unwrap();
        let alien = home.join("seals").join(format!("{}-1.sqlite", s.session()));
        std::fs::remove_file(&alien).unwrap();
        std::fs::copy(&foreign.path, &alien).unwrap();
        std::fs::copy(sidecar_path(&foreign.path), sidecar_path(&alien)).unwrap();

        let dry = prune_legacy(&home, &wdir, false).unwrap();
        assert_eq!(dry.len(), 1);
        assert_eq!(dry[0].kept, kept.path);
        assert_eq!(dry[0].superseded, vec![legacy[1].path.clone(), legacy[2].path.clone()]);
        assert!(legacy[1].path.exists() && !wdir.exists(), "a dry run changes nothing");
        let done = prune_legacy(&home, &wdir, true).unwrap();
        assert_eq!(done[0].superseded.len(), 2);
        assert!(!legacy[1].path.exists() && !sidecar_path(&legacy[2].path).exists());
        assert!(alien.exists() && kept.path.exists());
        let lines = crate::witness::read(&wdir.join(crate::witness::FILE)).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!((lines[0].chain_seq, lines[0].reason.as_deref(), lines[0].signature.as_str()), (2, Some("legacy"), legacy[1].sidecar.signature.as_str()));
        // The kept seal still checks out against the lines written for the removed ones.
        assert_eq!(crate::witness::check(&kept.path, s.session(), 4, &lines), Ok(crate::witness::Check::Ok { entries: 2 }));
        // Running again finds nothing more.
        assert!(prune_legacy(&home, &wdir, true).unwrap()[0].superseded.is_empty());
    }

    #[test]
    fn old_sidecars_without_reason_still_parse() {
        let (_t, path) = fixture("format2");
        let sc = read_sidecar(&path).unwrap();
        assert_eq!((sc.reason, sc.thread), (None, None));
        assert!(verify(&path).is_ok());
    }

    #[test]
    fn checkpoint_seals_every_50_records_and_after_predictions() {
        let t = tempfile::tempdir().unwrap();
        let mut store = Store::create(t.path()).unwrap();
        let key = crate::keys::load_or_create(t.path()).unwrap();
        for i in 1..=120 {
            store.write(&input("a", json!(i)), Instant::now()).unwrap();
            let s = checkpoint(&store, &key, "observation").unwrap();
            assert_eq!(s.is_some(), i % 50 == 0, "at {i}");
        }
        // A prediction seals at once; again at the same head does nothing.
        let mut p = input("p", json!("rain"));
        p.kind = "prediction".into();
        store.write(&p, Instant::now()).unwrap();
        let s = checkpoint(&store, &key, "prediction").unwrap().unwrap();
        assert_eq!((s.sidecar.chain_seq, s.verified), (121, true));
        assert!(checkpoint(&store, &key, "prediction").unwrap().is_none());
        assert!(seal_pending(&store, &key).unwrap().is_none());
        // The count runs from the last seal, whatever made it.
        for _ in 0..49 {
            store.write(&input("b", json!(0)), Instant::now()).unwrap();
            assert!(checkpoint(&store, &key, "observation").unwrap().is_none());
        }
        store.write(&input("b", json!(0)), Instant::now()).unwrap();
        assert_eq!(checkpoint(&store, &key, "observation").unwrap().unwrap().sidecar.chain_seq, 171);
    }
}
