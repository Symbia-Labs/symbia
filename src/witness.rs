//! The witness: one line per seal in `<folder>/witness.jsonl`, kept outside the data folder, so
//! a session deleted or rolled back on this machine can be caught later.
//!
//! Lines written since 0.2 are version 2: each names the sha256 of the line before it (`prev`)
//! and is signed whole by the device key (`line_sig`), so a line can't be edited, forged,
//! reordered or taken out of the middle unnoticed. Taking lines off the end can't be seen from
//! the file alone; a copy kept elsewhere can show it.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::canon::{canonical, sha256};
use crate::seal::{Sidecar, signed_message};

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
    /// 2 for a signed, chained line; absent on lines from before 0.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<i64>,
    /// sha256 of the previous line's bytes, or 64 zeros for the first line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// Signature over the RFC 8785 JSON of every other field of the line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_sig: Option<String>,
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
            v: None,
            prev: None,
            line_sig: None,
        }
    }

    /// The fields copied from the seal, without what version 2 adds.
    pub fn seal_part(&self) -> Self {
        Self { v: None, prev: None, line_sig: None, ..self.clone() }
    }

    /// The bytes `line_sig` covers.
    fn signed_text(&self) -> anyhow::Result<String> {
        canonical(&Self { line_sig: None, ..self.clone() })
    }
}

const NO_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append `e` to `<dir>/witness.jsonl` as a version 2 line signed by `key`, creating both as
/// needed. The file is locked while the last line is read and the new one written, so two
/// processes can't both chain onto the same line.
pub fn append(dir: &Path, e: &Entry, key: &SigningKey) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::create_dir_all(dir)?;
    // Non-blocking open and a regular-file check: a FIFO or device in its place can't hang us.
    let mut f = std::fs::OpenOptions::new().create(true).read(true).append(true).custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW).open(dir.join(FILE))?;
    anyhow::ensure!(f.metadata()?.is_file(), "{} is not a regular file", dir.join(FILE).display());
    let _lock = FileLock::exclusive(&f)?;
    let mut text = String::new();
    f.read_to_string(&mut text)?;
    let prev = match text.lines().filter(|l| !l.trim().is_empty()).next_back() {
        Some(l) => hex::encode(sha256(l.as_bytes())),
        None => NO_PREV.into(),
    };
    let mut line = Entry { v: Some(2), prev: Some(prev), line_sig: None, ..e.seal_part() };
    line.line_sig = Some(hex::encode(key.sign(line.signed_text()?.as_bytes()).to_bytes()));
    let mut out = String::new();
    if !text.is_empty() && !text.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&serde_json::to_string(&line)?);
    out.push('\n');
    f.write_all(out.as_bytes())?;
    f.sync_data()?;
    Ok(())
}

/// An exclusive `flock` held until dropped.
struct FileLock(i32);

impl FileLock {
    fn exclusive(f: &std::fs::File) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let fd = f.as_raw_fd();
        // SAFETY: flock on a descriptor this process holds open; failure is reported.
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(fd))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: unlock the descriptor locked above; it is still open while the guard lives.
        unsafe {
            libc::flock(self.0, libc::LOCK_UN);
        }
    }
}

/// The witness file for a configured folder or a file path given directly.
pub fn file_of(path: &Path) -> PathBuf {
    if path.is_dir() { path.join(FILE) } else { path.to_path_buf() }
}

/// Every entry in a witness file, in order. A line that doesn't parse is an error, not
/// skipped: a corrupted line would otherwise vanish quietly. A missing file is empty. Nothing
/// is checked here beyond parsing; see [`load`].
pub fn read(path: &Path) -> anyhow::Result<Vec<Entry>> {
    Ok(lines(path)?.into_iter().map(|(_, e, _)| e).collect())
}

/// `(line number, entry, raw line)` for each non-empty line.
fn lines(path: &Path) -> anyhow::Result<Vec<(usize, Entry, String)>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for (i, l) in text.lines().enumerate() {
        if l.trim().is_empty() {
            continue;
        }
        let e: Entry = serde_json::from_str(l).map_err(|_| anyhow::anyhow!("witness line {} is unreadable", i + 1))?;
        out.push((i + 1, e, l.to_string()));
    }
    Ok(out)
}

/// Read a witness file and check every line before trusting any of it: each line's key is in
/// `trusted` (lowercase hex) and its seal signature holds; each version 2 line follows the one
/// before it and its own signature holds; and no unsigned line comes after a signed one.
pub fn load(path: &Path, trusted: &[String]) -> Result<Vec<Entry>, String> {
    let all = lines(path).map_err(|e| format!("{e:#}"))?;
    let mut prev_raw: Option<&str> = None;
    let mut signed_seen = false;
    for (n, e, raw) in &all {
        let bad = |what: &str| format!("witness line {n}: {what}");
        let pk = e.public_key.to_ascii_lowercase();
        if !trusted.contains(&pk) {
            return Err(bad(&format!("untrusted key {}", crate::canon::short(&pk, 12))));
        }
        let vk = hex::decode(&pk).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()).and_then(|b| VerifyingKey::from_bytes(&b).ok()).ok_or_else(|| bad("malformed key"))?;
        let h32 = |s: &str| hex::decode(s).ok().and_then(|b| <[u8; 32]>::try_from(b).ok());
        let sig = |s: &str| hex::decode(s).ok().and_then(|b| <[u8; 64]>::try_from(b).ok()).map(|b| Signature::from_bytes(&b));
        let (Some(sha), Some(head), Some(s)) = (h32(&e.file_sha256), h32(&e.chain_head), sig(&e.signature)) else {
            return Err(bad("malformed seal fields"));
        };
        if vk.verify(&signed_message(&sha, &head), &s).is_err() {
            return Err(bad("seal signature invalid"));
        }
        match e.v {
            Some(2) => {
                let want = prev_raw.map_or_else(|| NO_PREV.to_string(), |p| hex::encode(sha256(p.as_bytes())));
                if e.prev.as_deref() != Some(want.as_str()) {
                    return Err(bad("does not follow the line before it"));
                }
                let ls = e.line_sig.as_deref().and_then(sig).ok_or_else(|| bad("line signature missing"))?;
                let text = e.signed_text().map_err(|x| bad(&x.to_string()))?;
                if vk.verify(text.as_bytes(), &ls).is_err() {
                    return Err(bad("line signature invalid"));
                }
                signed_seen = true;
            }
            None if signed_seen => return Err(bad("unsigned line after signed lines")),
            None => {}
            Some(v) => return Err(bad(&format!("unknown line version {v}"))),
        }
        prev_raw = Some(raw);
    }
    Ok(all.into_iter().map(|(_, e, _)| e).collect())
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

/// Check a verified sealed copy, open as `conn`, against `entries`. `Err` is a mismatch: the
/// file's chain hash at some witnessed seq differs from what the witness recorded.
pub fn check(conn: &Connection, session: &str, file_seq: i64, entries: &[Entry]) -> Result<Check, String> {
    let mine: Vec<&Entry> = entries.iter().filter(|e| e.session == session).collect();
    if mine.is_empty() {
        return Ok(Check::NotWitnessed);
    }
    let mut seen = 0usize;
    let mut max_seq = i64::MIN;
    for e in &mine {
        max_seq = max_seq.max(e.chain_seq);
        if e.chain_seq > file_seq {
            continue;
        }
        let head: Vec<u8> = if e.chain_seq == 0 {
            crate::store::chain_genesis(conn).map_err(|x| x.to_string())?.to_vec()
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

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn pk(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().to_bytes())
    }

    /// An entry whose seal signature holds under `k`, as a real seal's would.
    fn entry(k: &SigningKey, session: &str, seq: i64, head: u8) -> Entry {
        let (sha, head) = ([0xf0u8; 32], [head; 32]);
        Entry {
            session: session.into(),
            chain_seq: seq,
            chain_head: hex::encode(head),
            file_sha256: hex::encode(sha),
            public_key: pk(k),
            signature: hex::encode(k.sign(&signed_message(&sha, &head)).to_bytes()),
            at_ms: 1,
            reason: Some("checkpoint".into()),
            thread: None,
            v: None,
            prev: None,
            line_sig: None,
        }
    }

    fn write_lines(path: &Path, lines: &[String]) {
        std::fs::write(path, lines.iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    }

    #[test]
    fn append_and_load_round_trip() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("w/nested");
        let k = key();
        for (seq, h) in [(1, 0xaa), (2, 0xbb), (3, 0xcc)] {
            append(&dir, &entry(&k, "s", seq, h), &k).unwrap();
        }
        let path = dir.join(FILE);
        let got = load(&path, &[pk(&k)]).unwrap();
        assert_eq!(got.iter().map(Entry::seal_part).collect::<Vec<_>>(), vec![entry(&k, "s", 1, 0xaa), entry(&k, "s", 2, 0xbb), entry(&k, "s", 3, 0xcc)]);
        let raw: Vec<String> = std::fs::read_to_string(&path).unwrap().lines().map(String::from).collect();
        assert_eq!(got[0].prev.as_deref(), Some(NO_PREV));
        assert_eq!(got[1].prev, Some(hex::encode(sha256(raw[0].as_bytes()))));
        assert!(got.iter().all(|e| e.v == Some(2) && e.line_sig.is_some()));
        assert_eq!(file_of(&dir), path);
        assert!(read(&t.path().join("none.jsonl")).unwrap().is_empty());
        // Compact JSON, one line per seal; empty optional fields are left out.
        assert!(!raw[0].contains("thread"), "{}", raw[0]);
    }

    /// Review finding: witness lines weren't chained or signature-checked, and unreadable lines
    /// were skipped, so lines could be removed, edited or forged without a trace.
    #[test]
    fn edited_removed_reordered_or_forged_lines_fail() {
        let t = tempfile::tempdir().unwrap();
        let k = key();
        let path = t.path().join(FILE);
        for (seq, h) in [(1, 0xaa), (2, 0xbb), (3, 0xcc)] {
            append(t.path(), &entry(&k, "s", seq, h), &k).unwrap();
        }
        let good: Vec<String> = std::fs::read_to_string(&path).unwrap().lines().map(String::from).collect();
        let trusted = [pk(&k)];
        let edited = good[0].replace("\"chain_seq\":1", "\"chain_seq\":9");
        let legacy = serde_json::to_string(&entry(&k, "s", 4, 0xdd)).unwrap();
        let mut forged = entry(&k, "s", 4, 0xdd);
        forged.chain_head = "ee".repeat(32);
        let forged = serde_json::to_string(&forged).unwrap();
        let cases: Vec<(Vec<String>, &str)> = vec![
            (vec![edited, good[1].clone(), good[2].clone()], "witness line 1: line signature invalid"),
            (vec![good[0].clone(), good[2].clone()], "witness line 2: does not follow the line before it"),
            (vec![good[1].clone(), good[0].clone(), good[2].clone()], "witness line 1: does not follow the line before it"),
            (vec![good[0].clone(), good[1].clone(), good[2].clone(), legacy], "witness line 4: unsigned line after signed lines"),
            (vec![forged], "witness line 1: seal signature invalid"),
            (vec![good[0].clone(), "not json".into()], "witness line 2 is unreadable"),
        ];
        for (lines, want) in cases {
            write_lines(&path, &lines);
            assert_eq!(load(&path, &trusted).unwrap_err(), want);
        }
        write_lines(&path, &good);
        assert!(load(&path, &["00".repeat(32)]).unwrap_err().starts_with("witness line 1: untrusted key "));
        assert!(read(&path).is_ok());
    }

    /// Lines from before 0.2 still read, and the first signed line chains onto them.
    #[test]
    fn unsigned_lines_from_before_0_2_still_load() {
        let t = tempfile::tempdir().unwrap();
        let k = key();
        let path = t.path().join(FILE);
        let old = serde_json::to_string(&entry(&k, "s", 1, 0xaa)).unwrap();
        write_lines(&path, std::slice::from_ref(&old));
        append(t.path(), &entry(&k, "s", 2, 0xbb), &k).unwrap();
        let got = load(&path, &[pk(&k)]).unwrap();
        assert_eq!((got[0].v, got[1].v), (None, Some(2)));
        assert_eq!(got[1].prev, Some(hex::encode(sha256(old.as_bytes()))));
    }
}
