//! The witness: one line per seal in `<folder>/witness.jsonl`, kept outside the data folder, so
//! a session deleted or rolled back on this machine can be caught later.

use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::record::GENESIS;
use crate::seal::Sidecar;

pub const FILE: &str = "witness.jsonl";

/// One witness line. Byte fields are lowercase hex, as in the sidecar it copies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub session: String,
    pub chain_seq: i64,
    pub chain_head: String,
    pub file_sha256: String,
    pub public_key: String,
    pub signature: String,
    pub at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
}

impl Entry {
    pub fn from_sidecar(s: &Sidecar) -> Self {
        Self {
            session: s.session.clone(),
            chain_seq: s.chain_seq,
            chain_head: s.chain_head.clone(),
            file_sha256: s.file_sha256.clone(),
            public_key: s.public_key.clone(),
            signature: s.signature.clone(),
            at_ms: s.at_ms,
            reason: s.reason.clone(),
            thread: s.thread.clone(),
        }
    }
}

/// Append `e` to `<dir>/witness.jsonl`, creating both as needed.
pub fn append(dir: &Path, e: &Entry) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join(FILE))?;
    let mut line = serde_json::to_string(e)?;
    line.push('\n');
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    Ok(())
}

/// The witness file for a configured folder or a file path given directly.
pub fn file_of(path: &Path) -> PathBuf {
    if path.is_dir() { path.join(FILE) } else { path.to_path_buf() }
}

/// Every entry in a witness file; unreadable lines are skipped. A missing file is empty.
pub fn read(path: &Path) -> anyhow::Result<Vec<Entry>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// What the witness says about a sealed file that already verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// Every entry for the session up to the file's seq matches its chain.
    Ok { entries: usize },
    /// The entries match, but the witness has seen the session further than this file goes.
    Behind { entries: usize, seen_seq: i64 },
    /// No entry names this session.
    NotWitnessed,
}

impl Check {
    pub fn describe(&self) -> String {
        match self {
            Self::Ok { entries } => format!("ok ({entries} entries)"),
            Self::Behind { seen_seq, .. } => format!("behind (seen seq {seen_seq})"),
            Self::NotWitnessed => "not witnessed".into(),
        }
    }
}

/// Check the sealed file at `path` (already verified) against `entries`. `Err` is a mismatch:
/// the file's chain hash at some witnessed seq differs from what the witness recorded.
pub fn check(path: &Path, session: &str, file_seq: i64, entries: &[Entry]) -> Result<Check, String> {
    let mine: Vec<&Entry> = entries.iter().filter(|e| e.session == session).collect();
    if mine.is_empty() {
        return Ok(Check::NotWitnessed);
    }
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).map_err(|e| e.to_string())?;
    let mut seen = 0usize;
    let mut max_seq = i64::MIN;
    for e in &mine {
        max_seq = max_seq.max(e.chain_seq);
        if e.chain_seq > file_seq {
            continue;
        }
        let head: Vec<u8> = if e.chain_seq == 0 {
            GENESIS.to_vec()
        } else {
            conn.query_row("SELECT hash FROM chain WHERE seq = ?1", [e.chain_seq], |r| r.get(0)).optional().map_err(|x| x.to_string())?.unwrap_or_default()
        };
        if hex::encode(head) != e.chain_head.to_ascii_lowercase() {
            return Err(format!("witness mismatch at seq {}", e.chain_seq));
        }
        seen += 1;
    }
    if max_seq > file_seq {
        return Ok(Check::Behind { entries: seen, seen_seq: max_seq });
    }
    Ok(Check::Ok { entries: seen })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(session: &str, seq: i64, head: &str) -> Entry {
        Entry {
            session: session.into(),
            chain_seq: seq,
            chain_head: head.into(),
            file_sha256: "f".repeat(64),
            public_key: "k".into(),
            signature: "s".into(),
            at_ms: 1,
            reason: Some("checkpoint".into()),
            thread: None,
        }
    }

    #[test]
    fn append_and_read_round_trip() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("w/nested");
        append(&dir, &entry("s", 1, "aa")).unwrap();
        append(&dir, &entry("s", 2, "bb")).unwrap();
        std::fs::OpenOptions::new().append(true).open(dir.join(FILE)).unwrap().write_all(b"not json\n").unwrap();
        let got = read(&dir.join(FILE)).unwrap();
        assert_eq!(got, vec![entry("s", 1, "aa"), entry("s", 2, "bb")]);
        assert_eq!(file_of(&dir), dir.join(FILE));
        assert!(read(&t.path().join("none.jsonl")).unwrap().is_empty());
        // Lines are compact JSON, one per seal; the optional fields are left out when empty.
        let line = std::fs::read_to_string(dir.join(FILE)).unwrap().lines().next().unwrap().to_string();
        assert!(!line.contains("thread"), "{line}");
    }
}
