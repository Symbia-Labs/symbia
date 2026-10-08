//! One SQLite file per session: records, chain, links, evidence and a full-text index.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, bail};
use rusqlite::{Connection, OpenFlags, OptionalExtension, ToSql, params};
use serde_json::{Value, json};

use crate::canon::{canonical, hex_prefix};
use crate::now_ms;
use crate::record::{FORMAT, GENESIS, IdFields, Link, MAIN_THREAD, RecordInput, RowFields, chain_hash_v3, check_thread, record_id, row_digest, thread_sha256};
use crate::session::Lock;

pub const DEFAULT_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// The ledger file's session id.
pub const LEDGER: &str = "ledger";
pub const FIND_LIMIT_MAX: u32 = 50;
const FIND_LIMIT_DEFAULT: u32 = 20;

pub const SCHEMA: &str = "
CREATE TABLE file_meta (retention TEXT NOT NULL, expires_ms INTEGER, embed_runtime TEXT, format INTEGER NOT NULL, mcp_session_id TEXT, thread TEXT) STRICT;
CREATE TABLE chain (seq INTEGER PRIMARY KEY, prev_hash BLOB NOT NULL, hash BLOB NOT NULL, at_ms INTEGER NOT NULL, record_id TEXT,
  thread TEXT, thread_sha256 BLOB NOT NULL, row_digest BLOB) STRICT;
CREATE TABLE records (
  id TEXT PRIMARY KEY, key TEXT NOT NULL, version INTEGER NOT NULL, kind TEXT NOT NULL,
  lane TEXT NOT NULL, lane_reason TEXT NOT NULL, body BLOB NOT NULL, model TEXT NOT NULL,
  session TEXT NOT NULL, at_ms INTEGER NOT NULL, expires_ms INTEGER,
  est_host_ms INTEGER, est_chars INTEGER, host_ms INTEGER, chars INTEGER,
  UNIQUE (key, version)) STRICT;
CREATE TABLE links (from_id TEXT NOT NULL, to_id TEXT NOT NULL, rel TEXT NOT NULL, to_session TEXT) STRICT;
CREATE TABLE evidence (sha256 BLOB PRIMARY KEY, bytes INTEGER NOT NULL, media TEXT NOT NULL) STRICT;
CREATE VIRTUAL TABLE records_fts USING fts5(id UNINDEXED, key, body);
CREATE INDEX links_from ON links (from_id);
CREATE INDEX links_to ON links (to_id);
CREATE INDEX chain_record ON chain (record_id);
CREATE INDEX chain_thread ON chain (thread);
";

pub struct Store {
    conn: Connection,
    home: PathBuf,
    session: String,
    path: PathBuf,
    started_ms: i64,
    /// Where each seal of this file is also written down (config `witness`).
    witness: Option<PathBuf>,
    /// The stdio session lock; last, so it is released after the connection closes.
    lock: Option<Lock>,
}

/// Reference returned for a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub id: String,
    pub version: i64,
    pub seq: i64,
    /// First 12 hex chars of the chain hash after this write.
    pub head: String,
}

impl Written {
    /// The terse tool reply for this write.
    pub fn reply(&self) -> String {
        json!({"id": self.id, "version": self.version, "seq": self.seq, "head": self.head}).to_string()
    }
}

/// A row of the `evidence` table: a file stored under `evidence/<sha256 hex>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub sha256: [u8; 32],
    pub bytes: i64,
    pub media: &'static str,
}

#[derive(Debug, Default, Clone)]
pub struct FindQuery {
    pub query: Option<String>,
    pub kind: Option<String>,
    pub lane: Option<String>,
    pub key_prefix: Option<String>,
    pub limit: Option<u32>,
    /// Only records in this thread.
    pub thread: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FindHit {
    pub id: String,
    pub key: String,
    pub version: i64,
    pub kind: String,
    pub lane: String,
    pub thread: String,
}

/// One thread's share of a session: how many records it holds and its newest seq.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ThreadSummary {
    pub thread: String,
    pub records: i64,
    pub last_seq: i64,
}

pub fn new_session_id(at_ms: i64) -> anyhow::Result<String> {
    let mut r = [0u8; 4];
    getrandom::fill(&mut r).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    Ok(format!("{at_ms}-{}", hex::encode(r)))
}

/// Latest chain `(seq, hash)`, or `(0, GENESIS)` for an empty chain.
pub fn chain_head(conn: &Connection) -> anyhow::Result<(i64, [u8; 32])> {
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row("SELECT seq, hash FROM chain ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    match row {
        None => Ok((0, GENESIS)),
        Some((seq, hash)) => {
            let hash = <[u8; 32]>::try_from(hash.as_slice()).map_err(|_| anyhow::anyhow!("chain hash at seq {seq} is not 32 bytes"))?;
            Ok((seq, hash))
        }
    }
}

/// The session holding record `id` in another session file or seal under `home`, newest file
/// first; `own` (the current session file) is skipped. Files that cannot be read are skipped.
pub fn find_elsewhere(home: &Path, own: &Path, id: &str) -> Option<String> {
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for dir in ["sessions", "seals"] {
        let Ok(entries) = std::fs::read_dir(home.join(dir)) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "sqlite") && p != own {
                let mtime = e.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
                files.push((mtime, p));
            }
        }
    }
    files.sort_by_key(|f| std::cmp::Reverse(f.0));
    files.into_iter().find_map(|(_, p)| {
        let conn = Connection::open_with_flags(&p, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).ok()?;
        conn.query_row("SELECT session FROM records WHERE id = ?1", [id], |r| r.get(0)).optional().ok()?
    })
}

/// Quote each whitespace-separated term as an FTS5 phrase so user text is never parsed as query syntax.
fn fts_query(q: &str) -> Option<String> {
    let terms: Vec<String> = q.split_whitespace().map(|t| format!("\"{}\"", t.replace('"', "\"\""))).collect();
    (!terms.is_empty()).then(|| terms.join(" "))
}

impl Store {
    /// Create a new session file under `home/sessions/` with a fresh session id.
    pub fn create(home: &Path) -> anyhow::Result<Self> {
        Self::create_for_mcp(home, None)
    }

    /// Create a new session file bound to an MCP session id (streamable HTTP), or to none (stdio).
    pub fn create_for_mcp(home: &Path, mcp_session_id: Option<&str>) -> anyhow::Result<Self> {
        let now = now_ms();
        Self::create_with(home, &new_session_id(now)?, now + DEFAULT_TTL_MS, mcp_session_id)
    }

    pub fn create_with(home: &Path, session: &str, expires_ms: i64, mcp_session_id: Option<&str>) -> anyhow::Result<Self> {
        crate::home::ensure(home)?;
        let path = home.join("sessions").join(format!("{session}.sqlite"));
        if path.exists() {
            bail!("session file {} already exists", path.display());
        }
        let conn = Connection::open(&path).with_context(|| format!("open {}", path.display()))?;
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            bail!("could not enable WAL (got {mode})");
        }
        conn.execute_batch(SCHEMA)?;
        conn.execute(
            "INSERT INTO file_meta (retention, expires_ms, embed_runtime, format, mcp_session_id) VALUES ('session', ?1, NULL, ?2, ?3)",
            params![expires_ms, FORMAT, mcp_session_id],
        )?;
        Ok(Self { conn, home: home.to_path_buf(), session: session.to_string(), path, started_ms: now_ms(), witness: None, lock: None })
    }

    /// `home/ledger/ledger.sqlite`: the long-lived ledger, opened or created. Its records are
    /// promotions; it has no expiry and lives outside `sessions/`, so it is never resumed.
    pub fn ledger(home: &Path) -> anyhow::Result<Self> {
        let dir = home.join("ledger");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("ledger.sqlite");
        if path.exists() {
            return Self::open(home, &path);
        }
        let conn = Connection::open(&path).with_context(|| format!("open {}", path.display()))?;
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        conn.execute_batch(SCHEMA)?;
        conn.execute("INSERT INTO file_meta (retention, expires_ms, embed_runtime, format, mcp_session_id) VALUES ('ledger', NULL, NULL, ?1, NULL)", [FORMAT])?;
        Ok(Self { conn, home: home.to_path_buf(), session: LEDGER.to_string(), path, started_ms: now_ms(), witness: None, lock: None })
    }

    /// Also write each seal of this file to the witness folder.
    pub fn set_witness(&mut self, dir: Option<PathBuf>) {
        self.witness = dir;
    }

    pub fn witness(&self) -> Option<&Path> {
        self.witness.as_deref()
    }

    /// Reopen an existing session file to continue its chain. The session id is the file
    /// name; the start time is the id's millisecond prefix.
    pub fn open(home: &Path, path: &Path) -> anyhow::Result<Self> {
        let session = path.file_stem().and_then(|s| s.to_str()).context("session file name is not UTF-8")?.to_string();
        let started_ms = session.split('-').next().and_then(|ms| ms.parse().ok()).unwrap_or_else(now_ms);
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).with_context(|| format!("open {}", path.display()))?;
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            bail!("could not enable WAL (got {mode})");
        }
        Ok(Self { conn, home: home.to_path_buf(), session, path: path.to_path_buf(), started_ms, witness: None, lock: None })
    }

    /// Keep `lock` for as long as this store is open.
    pub fn hold(&mut self, lock: Lock) {
        self.lock = Some(lock);
    }

    /// When this session file was created.
    pub fn started_ms(&self) -> i64 {
        self.started_ms
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }
    pub fn home(&self) -> &Path {
        &self.home
    }
    pub fn session(&self) -> &str {
        &self.session
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn retention(&self) -> anyhow::Result<String> {
        Ok(self.conn.query_row("SELECT retention FROM file_meta", [], |r| r.get(0))?)
    }

    pub fn expires_ms(&self) -> anyhow::Result<Option<i64>> {
        Ok(self.conn.query_row("SELECT expires_ms FROM file_meta", [], |r| r.get(0))?)
    }

    pub fn mcp_session_id(&self) -> anyhow::Result<Option<String>> {
        Ok(self.conn.query_row("SELECT mcp_session_id FROM file_meta", [], |r| r.get(0))?)
    }

    pub fn head(&self) -> anyhow::Result<(i64, [u8; 32])> {
        chain_head(&self.conn)
    }

    /// Write a record, its chain row and its links in one transaction.
    ///
    /// `started` marks when handling began; `host_ms` and `chars` are measured against the reply.
    pub fn write(&mut self, input: &RecordInput, started: Instant) -> anyhow::Result<Written> {
        self.write_with(input, started, None, &[])
    }

    /// As [`Store::write`], for a record that describes another tool's reply: `reply_chars` is
    /// that reply's length (`None` measures this write's own reply), and `evidence` rows are
    /// added in the same transaction.
    pub fn write_with(&mut self, input: &RecordInput, started: Instant, reply_chars: Option<usize>, evidence: &[Evidence]) -> anyhow::Result<Written> {
        self.write_in(MAIN_THREAD, input, started, reply_chars, evidence)
    }

    /// As [`Store::write_with`], in `thread`.
    pub fn write_in(&mut self, thread: &str, input: &RecordInput, started: Instant, reply_chars: Option<usize>, evidence: &[Evidence]) -> anyhow::Result<Written> {
        check_thread(thread).map_err(anyhow::Error::msg)?;
        input.validate()?;
        let tx = self.conn.transaction()?;
        let version: i64 = tx.query_row("SELECT COALESCE(MAX(version), 0) + 1 FROM records WHERE key = ?1", [&input.key], |r| r.get(0))?;
        let id = record_id(&IdFields {
            key: &input.key,
            version,
            kind: &input.kind,
            lane: &input.lane,
            body: &input.body,
            model: &input.model,
            session: &self.session,
        })?;
        let mut links: Vec<Link> = Vec::new();
        for l in input.links.iter().flatten() {
            let found: Option<i64> = tx.query_row("SELECT 1 FROM records WHERE id = ?1", [&l.to_id], |r| r.get(0)).optional()?;
            let to_session = match found {
                Some(_) => None,
                None => match find_elsewhere(&self.home, &self.path, &l.to_id) {
                    Some(s) => Some(s),
                    None => bail!("link target {} not found", l.to_id),
                },
            };
            links.push((l.to_id.clone(), l.rel.clone(), to_session));
        }
        let (prev_seq, prev_hash) = chain_head(&tx)?;
        let at_ms = now_ms();
        let seq = prev_seq + 1;
        let expires_ms: Option<i64> = tx.query_row("SELECT expires_ms FROM file_meta", [], |r| r.get(0))?;
        let digest = row_digest(&RowFields {
            id: &id,
            key: &input.key,
            version,
            kind: &input.kind,
            lane: &input.lane,
            lane_reason: &input.lane_reason,
            body: &input.body,
            model: &input.model,
            session: &self.session,
            at_ms,
            expires_ms,
            est_host_ms: input.est_host_ms,
            est_chars: input.est_chars,
            links: &links,
        })?;
        let thread_digest = thread_sha256(thread);
        let hash = chain_hash_v3(&prev_hash, &digest, at_ms, &thread_digest);
        let body_text = canonical(&input.body)?;
        tx.execute(
            "INSERT INTO records (id, key, version, kind, lane, lane_reason, body, model, session, at_ms, expires_ms, est_host_ms, est_chars)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, jsonb(?7), ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                id,
                input.key,
                version,
                input.kind,
                input.lane,
                input.lane_reason,
                body_text,
                input.model,
                self.session,
                at_ms,
                expires_ms,
                input.est_host_ms,
                input.est_chars
            ],
        )?;
        tx.execute(
            "INSERT INTO chain (seq, prev_hash, hash, at_ms, record_id, thread, thread_sha256) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![seq, prev_hash.as_slice(), hash.as_slice(), at_ms, id, thread, thread_digest.as_slice()],
        )?;
        for (to_id, rel, to_session) in &links {
            tx.execute("INSERT INTO links (from_id, to_id, rel, to_session) VALUES (?1, ?2, ?3, ?4)", params![id, to_id, rel, to_session])?;
        }
        tx.execute("INSERT INTO records_fts (id, key, body) VALUES (?1, ?2, ?3)", params![id, input.key, body_text])?;
        for e in evidence {
            tx.execute(
                "INSERT OR IGNORE INTO evidence (sha256, bytes, media) VALUES (?1, ?2, ?3)",
                params![e.sha256.as_slice(), e.bytes, e.media],
            )?;
        }
        let written = Written { id, version, seq, head: hex_prefix(&hash, 12) };
        let chars = i64::try_from(reply_chars.unwrap_or_else(|| written.reply().chars().count()))?;
        let host_ms = i64::try_from(started.elapsed().as_millis())?;
        tx.execute("UPDATE records SET host_ms = ?1, chars = ?2 WHERE id = ?3", params![host_ms, chars, written.id])?;
        tx.commit()?;
        Ok(written)
    }

    pub fn find(&self, q: &FindQuery) -> anyhow::Result<Vec<FindHit>> {
        let limit = q.limit.unwrap_or(FIND_LIMIT_DEFAULT).clamp(1, FIND_LIMIT_MAX);
        let mut sql = String::from("SELECT r.id, r.key, r.version, r.kind, r.lane, c.thread FROM records r JOIN chain c ON c.record_id = r.id");
        let mut args: Vec<Box<dyn ToSql>> = Vec::new();
        let fts = q.query.as_deref().and_then(fts_query);
        if fts.is_some() {
            sql.push_str(" JOIN records_fts ON records_fts.id = r.id");
        }
        sql.push_str(" WHERE 1 = 1");
        if let Some(m) = fts.clone() {
            sql.push_str(" AND records_fts MATCH ?");
            args.push(Box::new(m));
        }
        if let Some(k) = &q.kind {
            sql.push_str(" AND r.kind = ?");
            args.push(Box::new(k.clone()));
        }
        if let Some(l) = &q.lane {
            sql.push_str(" AND r.lane = ?");
            args.push(Box::new(l.clone()));
        }
        if let Some(p) = &q.key_prefix {
            sql.push_str(" AND substr(r.key, 1, length(?)) = ?");
            args.push(Box::new(p.clone()));
            args.push(Box::new(p.clone()));
        }
        if let Some(t) = &q.thread {
            sql.push_str(" AND c.thread = ?");
            args.push(Box::new(t.clone()));
        }
        sql.push_str(if fts.is_some() { " ORDER BY records_fts.rank, c.seq DESC" } else { " ORDER BY c.seq DESC" });
        sql.push_str(" LIMIT ?");
        args.push(Box::new(limit));
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok(FindHit { id: r.get(0)?, key: r.get(1)?, version: r.get(2)?, kind: r.get(3)?, lane: r.get(4)?, thread: r.get(5)? })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Threads by newest write first, at most `limit`.
    pub fn threads(&self, limit: u32) -> anyhow::Result<Vec<ThreadSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT thread, COUNT(*), MAX(seq) FROM chain WHERE thread IS NOT NULL GROUP BY thread ORDER BY MAX(seq) DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| Ok(ThreadSummary { thread: r.get(0)?, records: r.get(1)?, last_seq: r.get(2)? }))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Resolve `(key, version)` to an id; the latest version when `version` is `None`.
    pub fn id_for_key(&self, key: &str, version: Option<i64>) -> anyhow::Result<Option<String>> {
        let id = match version {
            Some(v) => self.conn.query_row("SELECT id FROM records WHERE key = ?1 AND version = ?2", params![key, v], |r| r.get(0)),
            None => self.conn.query_row("SELECT id FROM records WHERE key = ?1 ORDER BY version DESC LIMIT 1", [key], |r| r.get(0)),
        };
        Ok(id.optional()?)
    }

    /// The full record with its links, or `None`.
    pub fn get(&self, id: &str) -> anyhow::Result<Option<Value>> {
        get_in(&self.conn, id)
    }
}

/// The full record `id` in any session or sealed file, with its links; older formats have no
/// thread column, and their records read as `main`.
pub fn get_in(conn: &Connection, id: &str) -> anyhow::Result<Option<Value>> {
    let has_thread: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('chain') WHERE name = 'thread'", [], |r| r.get(0))?;
    let thread = if has_thread > 0 { "c.thread" } else { "'main'" };
    let has_to_session: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('links') WHERE name = 'to_session'", [], |r| r.get(0))?;
    let to_session = if has_to_session > 0 { "to_session" } else { "NULL" };
    {
        let rec = conn
            .query_row(
                &format!(
                    "SELECT r.id, r.key, r.version, r.kind, r.lane, r.lane_reason, json(r.body), r.model, r.session, r.at_ms, r.expires_ms,
                            r.est_host_ms, r.est_chars, r.host_ms, r.chars, c.seq, {thread}
                     FROM records r LEFT JOIN chain c ON c.record_id = r.id WHERE r.id = ?1"
                ),
                [id],
                |r| {
                    let body: String = r.get(6)?;
                    Ok((
                        json!({
                            "id": r.get::<_, String>(0)?,
                            "key": r.get::<_, String>(1)?,
                            "version": r.get::<_, i64>(2)?,
                            "kind": r.get::<_, String>(3)?,
                            "lane": r.get::<_, String>(4)?,
                            "lane_reason": r.get::<_, String>(5)?,
                            "model": r.get::<_, String>(7)?,
                            "session": r.get::<_, String>(8)?,
                            "at_ms": r.get::<_, i64>(9)?,
                            "expires_ms": r.get::<_, Option<i64>>(10)?,
                            "est_host_ms": r.get::<_, Option<i64>>(11)?,
                            "est_chars": r.get::<_, Option<i64>>(12)?,
                            "host_ms": r.get::<_, Option<i64>>(13)?,
                            "chars": r.get::<_, Option<i64>>(14)?,
                            "seq": r.get::<_, Option<i64>>(15)?,
                            "thread": r.get::<_, Option<String>>(16)?,
                        }),
                        body,
                    ))
                },
            )
            .optional()?;
        let Some((mut rec, body)) = rec else { return Ok(None) };
        rec["body"] = serde_json::from_str(&body)?;
        let mut stmt = conn.prepare(&format!("SELECT to_id, rel, {to_session} FROM links WHERE from_id = ?1 ORDER BY rowid"))?;
        let links: Vec<Value> = stmt
            .query_map([id], |r| {
                Ok(json!({"to_id": r.get::<_, String>(0)?, "rel": r.get::<_, String>(1)?, "to_session": r.get::<_, Option<String>>(2)?}))
            })?
            .collect::<Result<_, _>>()?;
        let mut stmt = conn.prepare("SELECT from_id, rel FROM links WHERE to_id = ?1 ORDER BY rowid")?;
        let linked_from: Vec<Value> = stmt
            .query_map([id], |r| Ok(json!({"from_id": r.get::<_, String>(0)?, "rel": r.get::<_, String>(1)?})))?
            .collect::<Result<_, _>>()?;
        rec["links"] = links.into();
        rec["linked_from"] = linked_from.into();
        Ok(Some(rec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::LinkInput;

    fn store() -> (tempfile::TempDir, Store) {
        let t = tempfile::tempdir().unwrap();
        let s = Store::create(t.path()).unwrap();
        (t, s)
    }

    fn input(key: &str, kind: &str, body: Value) -> RecordInput {
        RecordInput {
            key: key.into(),
            kind: kind.into(),
            lane: "canonical".into(),
            lane_reason: "test".into(),
            body,
            model: "test-model".into(),
            est_host_ms: Some(5),
            est_chars: Some(100),
            links: None,
        }
    }

    #[test]
    fn new_file_is_wal_session_with_expiry() {
        let (_t, s) = store();
        let mode: String = s.conn().query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(s.retention().unwrap(), "session");
        let exp: i64 = s.conn().query_row("SELECT expires_ms FROM file_meta", [], |r| r.get(0)).unwrap();
        let delta = exp - now_ms();
        assert!(delta > DEFAULT_TTL_MS - 60_000 && delta <= DEFAULT_TTL_MS, "{delta}");
        assert!(s.path().starts_with(s.home().join("sessions")));
        assert_eq!(s.path().file_name().unwrap().to_str().unwrap(), format!("{}.sqlite", s.session()));
        let format: i64 = s.conn().query_row("SELECT format FROM file_meta", [], |r| r.get(0)).unwrap();
        assert_eq!(format, 3);
        assert_eq!(s.expires_ms().unwrap(), Some(exp));
        assert_eq!(s.mcp_session_id().unwrap(), None);
    }

    #[test]
    fn mcp_session_id_is_stored_in_file_meta() {
        let t = tempfile::tempdir().unwrap();
        let s = Store::create_for_mcp(t.path(), Some("abc-123")).unwrap();
        assert_eq!(s.mcp_session_id().unwrap().as_deref(), Some("abc-123"));
    }

    #[test]
    fn tables_are_strict() {
        let (_t, s) = store();
        let err = s.conn().execute("INSERT INTO evidence (sha256, bytes, media) VALUES (x'00', 'many', 'text/plain')", []);
        assert!(err.is_err());
    }

    #[test]
    fn bundled_sqlite_stores_jsonb() {
        let (_t, mut s) = store();
        let w = s.write(&input("k", "observation", json!({"a": 1})), Instant::now()).unwrap();
        let (is_text, valid): (bool, i64) = s
            .conn()
            .query_row("SELECT typeof(body) = 'text', json_valid(body, 8) FROM records WHERE id = ?1", [&w.id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert!(!is_text);
        assert_eq!(valid, 1);
    }

    #[test]
    fn versions_increment_per_key() {
        let (_t, mut s) = store();
        let a1 = s.write(&input("a", "observation", json!(1)), Instant::now()).unwrap();
        let b1 = s.write(&input("b", "observation", json!(1)), Instant::now()).unwrap();
        let a2 = s.write(&input("a", "observation", json!(1)), Instant::now()).unwrap();
        let a3 = s.write(&input("a", "observation", json!(2)), Instant::now()).unwrap();
        assert_eq!((a1.version, b1.version, a2.version, a3.version), (1, 1, 2, 3));
        assert_eq!((a1.seq, b1.seq, a2.seq, a3.seq), (1, 2, 3, 4));
        assert_ne!(a1.id, a2.id);
        assert_eq!(s.id_for_key("a", None).unwrap(), Some(a3.id.clone()));
        assert_eq!(s.id_for_key("a", Some(2)).unwrap(), Some(a2.id));
        assert_eq!(s.id_for_key("a", Some(9)).unwrap(), None);
    }

    #[test]
    fn chain_links_each_write_to_the_last() {
        let (_t, mut s) = store();
        let w1 = s.write(&input("a", "observation", json!(1)), Instant::now()).unwrap();
        let w2 = s.write(&input("b", "observation", json!(2)), Instant::now()).unwrap();
        type ChainRow = (i64, Vec<u8>, Vec<u8>, i64, String);
        let rows: Vec<ChainRow> = s
            .conn()
            .prepare("SELECT seq, prev_hash, hash, at_ms, record_id FROM chain ORDER BY seq")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1, GENESIS.to_vec());
        let r1 = s.get(&w1.id).unwrap().unwrap();
        let digest = row_digest(&RowFields {
            id: &w1.id,
            key: "a",
            version: 1,
            kind: "observation",
            lane: "canonical",
            lane_reason: "test",
            body: &json!(1),
            model: "test-model",
            session: s.session(),
            at_ms: rows[0].3,
            expires_ms: r1["expires_ms"].as_i64(),
            est_host_ms: Some(5),
            est_chars: Some(100),
            links: &[],
        })
        .unwrap();
        assert_eq!(rows[0].2, chain_hash_v3(&GENESIS, &digest, rows[0].3, &thread_sha256("main")).to_vec());
        assert_eq!(rows[1].1, rows[0].2);
        assert_eq!(rows[1].4, w2.id);
        assert_eq!(hex_prefix(&rows[1].2, 12), w2.head);
    }

    #[test]
    fn cost_fields_are_filled() {
        let (_t, mut s) = store();
        let w = s.write(&input("a", "tool_call", json!({"tool": "x"})), Instant::now()).unwrap();
        let rec = s.get(&w.id).unwrap().unwrap();
        assert_eq!(rec["est_host_ms"], 5);
        assert_eq!(rec["est_chars"], 100);
        assert!(rec["host_ms"].as_i64().unwrap() >= 0);
        assert_eq!(rec["chars"].as_i64().unwrap() as usize, w.reply().chars().count());
    }

    #[test]
    fn write_with_measures_the_given_reply_and_adds_evidence() {
        let (_t, mut s) = store();
        let ev = Evidence { sha256: [9u8; 32], bytes: 42, media: "text/plain" };
        let w = s.write_with(&input("tool.x", "tool_call", json!({"tool": "x"})), Instant::now(), Some(777), &[ev.clone(), ev]).unwrap();
        assert_eq!(s.get(&w.id).unwrap().unwrap()["chars"], 777);
        let (n, bytes): (i64, i64) = s.conn().query_row("SELECT COUNT(*), MAX(bytes) FROM evidence", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!((n, bytes), (1, 42));
    }

    #[test]
    fn links_round_trip_and_unknown_targets_fail() {
        let (_t, mut s) = store();
        let p = s.write(&input("p", "prediction", json!("rain")), Instant::now()).unwrap();
        let mut r = input("r", "result", json!("rain"));
        r.links = Some(vec![LinkInput { to_id: p.id.clone(), rel: "results_of".into() }]);
        let rw = s.write(&r, Instant::now()).unwrap();
        let got = s.get(&rw.id).unwrap().unwrap();
        assert_eq!(got["links"], json!([{"to_id": p.id, "rel": "results_of", "to_session": null}]));
        assert_eq!(got["body"], json!("rain"));
        assert_eq!(got["seq"], 2);
        let back = s.get(&p.id).unwrap().unwrap();
        assert_eq!(back["linked_from"], json!([{"from_id": rw.id, "rel": "results_of"}]));

        let mut bad = input("x", "result", json!(0));
        bad.links = Some(vec![LinkInput { to_id: "0".repeat(64), rel: "cites".into() }]);
        assert!(s.write(&bad, Instant::now()).is_err());
        // A failed write leaves no trace on the chain.
        assert_eq!(s.head().unwrap().0, 2);
    }

    #[test]
    fn links_reach_records_in_earlier_sessions() {
        let t = tempfile::tempdir().unwrap();
        let key = crate::keys::load_or_create(t.path()).unwrap();
        let mut a = Store::create(t.path()).unwrap();
        let p = a.write(&input("p", "prediction", json!("rain")), Instant::now()).unwrap();
        crate::seal::seal(&a, &key).unwrap();
        // Only the seal holds A's prediction: the live file is gone.
        let a_session = a.session().to_string();
        let a_path = a.path().to_path_buf();
        drop(a);
        std::fs::remove_file(&a_path).unwrap();

        let mut b = Store::create(t.path()).unwrap();
        assert!(b.started_ms() > 0 && b.started_ms() <= now_ms());
        let mut r = input("r", "result", json!("rain"));
        r.links = Some(vec![LinkInput { to_id: p.id.clone(), rel: "results_of".into() }]);
        let rw = b.write(&r, Instant::now()).unwrap();
        let got = b.get(&rw.id).unwrap().unwrap();
        assert_eq!(got["links"], json!([{"to_id": p.id, "rel": "results_of", "to_session": a_session}]));
        // A same-session link next to it has no session.
        let mut r2 = input("r2", "result", json!(1));
        r2.links = Some(vec![LinkInput { to_id: rw.id.clone(), rel: "cites".into() }, LinkInput { to_id: p.id.clone(), rel: "cites".into() }]);
        let w2 = b.write(&r2, Instant::now()).unwrap();
        let links = &b.get(&w2.id).unwrap().unwrap()["links"];
        assert_eq!(links[0]["to_session"], Value::Null);
        assert_eq!(links[1]["to_session"], a_session.as_str());
        // Unknown anywhere: refused, nothing written.
        let mut bad = input("x", "result", json!(0));
        bad.links = Some(vec![LinkInput { to_id: "f".repeat(64), rel: "results_of".into() }]);
        assert!(b.write(&bad, Instant::now()).unwrap_err().to_string().contains("not found"));
        assert_eq!(b.head().unwrap().0, 2);
    }

    #[test]
    fn invalid_input_is_rejected_before_writing() {
        let (_t, mut s) = store();
        let mut bad = input("a", "observation", json!(1));
        bad.lane = "main".into();
        assert!(s.write(&bad, Instant::now()).is_err());
        assert_eq!(s.head().unwrap().0, 0);
    }

    #[test]
    fn fts_find_returns_expected_records() {
        let (_t, mut s) = store();
        let a = s.write(&input("map.run1.pressure", "prediction", json!({"text": "boiler pressure stays under 12 bar"})), Instant::now()).unwrap();
        let b = s.write(&input("map.run1.flow", "prediction", json!({"text": "condensate flow doubles"})), Instant::now()).unwrap();
        let c = s.write(&input("other.note", "observation", json!({"text": "pressure gauge replaced"})), Instant::now()).unwrap();

        let ids = |q: FindQuery| s.find(&q).unwrap().into_iter().map(|h| h.id).collect::<Vec<_>>();
        let mut pressure = ids(FindQuery { query: Some("pressure".into()), ..Default::default() });
        pressure.sort();
        let mut want = vec![a.id.clone(), c.id.clone()];
        want.sort();
        assert_eq!(pressure, want);
        assert_eq!(ids(FindQuery { query: Some("boiler pressure".into()), ..Default::default() }), vec![a.id.clone()]);
        assert_eq!(ids(FindQuery { query: Some("pressure".into()), kind: Some("observation".into()), ..Default::default() }), vec![c.id.clone()]);
        assert_eq!(ids(FindQuery { query: Some("flow".into()), ..Default::default() }), vec![b.id.clone()]);
        // Keys are indexed too.
        assert_eq!(ids(FindQuery { query: Some("other".into()), ..Default::default() }), vec![c.id.clone()]);
        // Without a query: newest first, filtered.
        assert_eq!(ids(FindQuery { key_prefix: Some("map.run1.".into()), ..Default::default() }), vec![b.id.clone(), a.id.clone()]);
        assert_eq!(ids(FindQuery { lane: Some("apocryphal".into()), ..Default::default() }), Vec::<String>::new());
        assert_eq!(ids(FindQuery { limit: Some(1), ..Default::default() }), vec![c.id.clone()]);
        // FTS syntax in user text is treated as literal terms.
        assert!(s.find(&FindQuery { query: Some("\"unbalanced AND (".into()), ..Default::default() }).unwrap().is_empty());
        let hit = &s.find(&FindQuery { query: Some("condensate".into()), ..Default::default() }).unwrap()[0];
        assert_eq!((hit.key.as_str(), hit.version, hit.kind.as_str(), hit.lane.as_str()), ("map.run1.flow", 1, "prediction", "canonical"));
    }

    #[test]
    fn find_limit_is_capped_at_50() {
        let (_t, mut s) = store();
        for i in 0..60 {
            s.write(&input(&format!("k{i}"), "observation", json!(i)), Instant::now()).unwrap();
        }
        assert_eq!(s.find(&FindQuery { limit: Some(500), ..Default::default() }).unwrap().len(), 50);
    }

    #[test]
    fn get_missing_is_none() {
        let (_t, s) = store();
        assert!(s.get("nope").unwrap().is_none());
    }

    #[test]
    fn writes_carry_their_thread() {
        let (_t, mut s) = store();
        let a = s.write_in("chat-a", &input("x", "observation", json!(1)), Instant::now(), None, &[]).unwrap();
        let m = s.write(&input("y", "observation", json!(2)), Instant::now()).unwrap();
        let b = s.write_in("chat-b", &input("z", "observation", json!(3)), Instant::now(), None, &[]).unwrap();
        let a2 = s.write_in("chat-a", &input("x", "observation", json!(4)), Instant::now(), None, &[]).unwrap();
        let row = |seq: i64| -> (String, Vec<u8>, Option<Vec<u8>>) {
            s.conn().query_row("SELECT thread, thread_sha256, row_digest FROM chain WHERE seq = ?1", [seq], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
        };
        assert_eq!(row(1), ("chat-a".to_string(), thread_sha256("chat-a").to_vec(), None));
        assert_eq!(row(2).0, "main");
        assert_eq!(s.get(&b.id).unwrap().unwrap()["thread"], "chat-b");
        assert_eq!(s.get(&m.id).unwrap().unwrap()["thread"], "main");
        let ids = |t: &str| s.find(&FindQuery { thread: Some(t.into()), ..Default::default() }).unwrap().into_iter().map(|h| h.id).collect::<Vec<_>>();
        assert_eq!(ids("chat-a"), vec![a2.id.clone(), a.id.clone()]);
        assert_eq!(ids("chat-b"), vec![b.id.clone()]);
        assert!(ids("nobody").is_empty());
        assert_eq!(s.find(&FindQuery::default()).unwrap()[0].thread, "chat-a");
        let sums = s.threads(20).unwrap();
        let got: Vec<(&str, i64, i64)> = sums.iter().map(|t| (t.thread.as_str(), t.records, t.last_seq)).collect();
        assert_eq!(got, [("chat-a", 2, 4), ("chat-b", 1, 3), ("main", 1, 2)]);
        assert_eq!(s.threads(1).unwrap().len(), 1);
        // A bad name is refused before anything is written.
        let e = s.write_in("a b", &input("w", "observation", json!(0)), Instant::now(), None, &[]).unwrap_err();
        assert_eq!(e.to_string(), crate::record::THREAD_RULE);
        assert_eq!(s.head().unwrap().0, 4);
    }
}
