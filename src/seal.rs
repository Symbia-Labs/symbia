//! Sealing a session file into a signed copy, and verifying sealed copies.

use std::path::{Path, PathBuf};

use anyhow::Context;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canon::{canonical, sha256};
use crate::now_ms;
use crate::record::{FORMAT, GENESIS, IdFields, RowFields, chain_hash, chain_hash_v2, record_id, row_digest};
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
}

#[derive(Debug, Clone)]
pub struct Sealed {
    pub path: PathBuf,
    pub sidecar: Sidecar,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub session: String,
    pub chain_seq: i64,
    pub chain_head: String,
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
    let conn = store.conn();
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    let (seq, _) = chain_head(conn)?;
    let path = store.home().join("seals").join(format!("{}-{seq}.sqlite", store.session()));
    if path.exists() {
        if let Ok(sidecar) = read_sidecar(&path) {
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
    };
    std::fs::write(sidecar_path(&path), canonical(&sidecar)?)?;
    let verified = verify(&path).is_ok();
    Ok(Sealed { path, sidecar, verified })
}

/// Seal `store` if a record was written after its last seal. `None` for an empty session
/// or one already sealed at its head.
pub fn seal_pending(store: &Store, key: &SigningKey) -> anyhow::Result<Option<Sealed>> {
    let (seq, _) = store.head()?;
    if seq == 0 || last_seal(store.home(), store.session()).is_some_and(|(_, s)| s.chain_seq >= seq) {
        return Ok(None);
    }
    seal(store, key).map(Some)
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

    let mut chain = conn.prepare("SELECT seq, prev_hash, hash, at_ms, record_id FROM chain ORDER BY seq").map_err(db)?;
    let mut rec = conn
        .prepare(
            "SELECT key, version, kind, lane, lane_reason, json(body), model, session, at_ms, expires_ms, est_host_ms, est_chars, host_ms, chars
             FROM records WHERE id = ?1",
        )
        .map_err(db)?;
    let mut links = conn.prepare("SELECT to_id, rel FROM links WHERE from_id = ?1").map_err(db)?;
    let rows = chain
        .query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, i64>(3)?, r.get::<_, Option<String>>(4)?))
        })
        .map_err(db)?;
    let mut prev = GENESIS;
    let mut seq_expected = 1i64;
    let mut on_chain = 0i64;
    for row in rows {
        let (seq, prev_hash, hash, at_ms, rid) = row.map_err(db)?;
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
        on_chain += 1;
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
            return Err(format!("record missing at seq {seq}"));
        };
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
            let row_links: Vec<(String, String)> =
                links.query_map([&rid], |l| Ok((l.get(0)?, l.get(1)?))).map_err(db)?.collect::<Result<_, _>>().map_err(db)?;
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
            chain_hash_v2(&prev, &digest, at_ms)
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
    Ok(Verified { session: sc.session, chain_seq: last_seq, chain_head: sc.chain_head })
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
            ("UPDATE file_meta SET format = 3", "unknown file format 3"),
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
        let t = tempfile::tempdir().unwrap();
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let dst = t.path().join("format1.sqlite");
        std::fs::copy(src.join("format1.sqlite"), &dst).unwrap();
        std::fs::copy(src.join("format1.seal.json"), sidecar_path(&dst)).unwrap();
        (t, dst)
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
}
