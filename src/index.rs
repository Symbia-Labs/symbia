//! The search index, `$SYMBIA_HOME/index.sqlite`: one document per record from every session
//! file and full seal, with full-text search, vectors and the sums behind `symbia_report`.
//!
//! The index is derived data. It can be deleted at any time and is rebuilt on the next search;
//! it is never sealed and is not part of any chain. Sources are opened read-only.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use rusqlite::{Connection, OpenFlags, OptionalExtension, ToSql, params};
use serde::Serialize;
use serde_json::{Value, json};

pub const FILE: &str = "index.sqlite";
/// Document text cap, in characters.
pub const TEXT_MAX: usize = 8_000;
/// Evidence bytes appended to a `tool_call` record's text, per stream.
pub const EVIDENCE_MAX: usize = 16 * 1024;
/// How long a refresh may run before it stops and leaves the rest for the next one.
pub const REFRESH_BUDGET: Duration = Duration::from_secs(2);
/// Rows read from a source per transaction.
const BATCH: i64 = 500;
/// Reciprocal-rank fusion constant.
pub const RRF_K: f64 = 60.0;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sources (path TEXT PRIMARY KEY, last_seq INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS docs (
  id INTEGER PRIMARY KEY, record_id TEXT NOT NULL, session TEXT NOT NULL, seq INTEGER NOT NULL,
  key TEXT NOT NULL, version INTEGER NOT NULL, kind TEXT NOT NULL, lane TEXT NOT NULL, thread TEXT NOT NULL,
  at_ms INTEGER NOT NULL, model TEXT NOT NULL,
  est_chars INTEGER, chars INTEGER, est_host_ms INTEGER, host_ms INTEGER,
  tool TEXT, error TEXT, held INTEGER NOT NULL, broke INTEGER NOT NULL, text TEXT NOT NULL,
  UNIQUE (session, record_id)) STRICT;
CREATE INDEX IF NOT EXISTS docs_session ON docs (session, seq);
CREATE INDEX IF NOT EXISTS docs_record ON docs (record_id);
CREATE TABLE IF NOT EXISTS links (from_doc INTEGER NOT NULL, to_id TEXT NOT NULL, rel TEXT NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS links_to ON links (to_id, rel);
CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(text, content='docs', content_rowid='id');
CREATE TABLE IF NOT EXISTS vectors (doc INTEGER PRIMARY KEY, model TEXT NOT NULL, dim INTEGER NOT NULL, v BLOB NOT NULL) STRICT;
";

/// Which documents a search or report covers.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub session: Option<String>,
    pub kind: Option<String>,
    pub lane: Option<String>,
    pub key_prefix: Option<String>,
    pub thread: Option<String>,
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
}

impl Filter {
    /// ` AND ...` clauses over `docs d`, with their arguments.
    fn sql(&self) -> (String, Vec<Box<dyn ToSql>>) {
        let mut s = String::new();
        let mut a: Vec<Box<dyn ToSql>> = Vec::new();
        for (col, v) in [("d.session", &self.session), ("d.kind", &self.kind), ("d.lane", &self.lane), ("d.thread", &self.thread)] {
            if let Some(v) = v {
                s.push_str(&format!(" AND {col} = ?"));
                a.push(Box::new(v.clone()));
            }
        }
        if let Some(p) = &self.key_prefix {
            s.push_str(" AND substr(d.key, 1, length(?)) = ?");
            a.push(Box::new(p.clone()));
            a.push(Box::new(p.clone()));
        }
        if let Some(t) = self.since_ms {
            s.push_str(" AND d.at_ms >= ?");
            a.push(Box::new(t));
        }
        if let Some(t) = self.until_ms {
            s.push_str(" AND d.at_ms < ?");
            a.push(Box::new(t));
        }
        (s, a)
    }
}

/// A search hit. `session` is filled for every hit; callers drop it in session scope.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Hit {
    #[serde(skip)]
    pub doc: i64,
    pub id: String,
    pub key: String,
    pub version: i64,
    pub kind: String,
    pub lane: String,
    pub thread: String,
    pub session: String,
    pub score: f64,
}

/// How `symbia_report` groups records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By {
    Thread,
    Tool,
    Kind,
    Model,
    Day,
}

impl By {
    pub fn parse(s: Option<&str>) -> Result<Self, String> {
        Ok(match s.unwrap_or("thread") {
            "thread" => Self::Thread,
            "tool" => Self::Tool,
            "kind" => Self::Kind,
            "model" => Self::Model,
            "day" => Self::Day,
            other => return Err(format!("by must be thread, tool, kind, model or day, not {other:?}")),
        })
    }

    fn expr(self) -> &'static str {
        match self {
            Self::Thread => "d.thread",
            Self::Tool => "COALESCE(d.tool, '-')",
            Self::Kind => "d.kind",
            Self::Model => "d.model",
            Self::Day => "strftime('%Y-%m-%d', d.at_ms / 1000, 'unixepoch')",
        }
    }
}

/// The text a record is searched by: its key, then the string values of its body in order,
/// capped at [`TEXT_MAX`] characters.
pub fn record_text(key: &str, body: &Value) -> String {
    fn walk(v: &Value, out: &mut String) {
        match v {
            Value::String(s) => {
                out.push(' ');
                out.push_str(s);
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = key.to_string();
    walk(body, &mut out);
    cap(out, TEXT_MAX)
}

fn cap(s: String, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_string(),
        None => s,
    }
}

/// The first [`EVIDENCE_MAX`] bytes of an evidence file, if they are UTF-8 (a sequence cut at
/// the end is trimmed; anything invalid before that means binary, and nothing is returned).
pub fn evidence_text(home: &Path, sha256_hex: &str) -> Option<String> {
    if sha256_hex.len() != 64 || !sha256_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    use std::io::Read;
    let mut buf = Vec::with_capacity(EVIDENCE_MAX);
    std::fs::File::open(home.join("evidence").join(sha256_hex)).ok()?.take(EVIDENCE_MAX as u64).read_to_end(&mut buf).ok()?;
    match std::str::from_utf8(&buf) {
        Ok(s) => Some(s.to_string()),
        Err(e) if e.error_len().is_none() => Some(String::from_utf8_lossy(&buf[..e.valid_up_to()]).into_owned()),
        Err(_) => None,
    }
}

/// `(held, broke)` verdicts in a result body: `"held": bool`, or `"verdicts"` / `"predictions"`
/// maps whose string values start with `held` or `broke`.
pub fn verdicts(body: &Value) -> (i64, i64) {
    let (mut held, mut broke) = (0, 0);
    if let Some(b) = body.get("held").and_then(Value::as_bool) {
        if b {
            held += 1;
        } else {
            broke += 1;
        }
    }
    for k in ["verdicts", "predictions"] {
        for v in body.get(k).and_then(Value::as_object).into_iter().flat_map(|m| m.values()) {
            let s = v.as_str().map(|s| s.trim_start().to_ascii_lowercase()).unwrap_or_default();
            if s.starts_with("held") {
                held += 1;
            } else if s.starts_with("broke") {
                broke += 1;
            }
        }
    }
    (held, broke)
}

pub struct Index {
    conn: Connection,
    home: PathBuf,
}

/// Session files, full seals and the ledger (its file and promoted copies) under `home`;
/// thread seals are subsets and are skipped.
fn source_files(home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in ["sessions", "seals", "ledger"] {
        let Ok(entries) = std::fs::read_dir(home.join(dir)) else { continue };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "sqlite") && !p.to_string_lossy().contains(".thread-"))
            .collect();
        files.sort();
        out.extend(files);
    }
    out
}

fn has_column(conn: &Connection, table: &str, col: &str) -> rusqlite::Result<bool> {
    conn.query_row("SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2", params![table, col], |r| r.get::<_, i64>(0)).map(|n| n > 0)
}

/// One record row read from a source.
struct Row {
    seq: i64,
    id: String,
    key: String,
    version: i64,
    kind: String,
    lane: String,
    thread: String,
    at_ms: i64,
    model: String,
    est_chars: Option<i64>,
    chars: Option<i64>,
    est_host_ms: Option<i64>,
    host_ms: Option<i64>,
    body: String,
    session: String,
}

impl Index {
    /// Open (creating) `home/index.sqlite`.
    pub fn open(home: &Path) -> anyhow::Result<Self> {
        let path = home.join(FILE);
        let conn = Connection::open(&path).with_context(|| format!("open {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn, home: home.to_path_buf() })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Read new rows from every source, for at most `budget`. Returns true when it stopped
    /// before reaching the end of every source (the index is behind).
    pub fn refresh(&mut self, budget: Duration) -> anyhow::Result<bool> {
        let deadline = Instant::now() + budget;
        for path in source_files(&self.home) {
            if Instant::now() >= deadline {
                return Ok(true);
            }
            match self.index_source(&path, deadline) {
                Ok(true) => {}
                Ok(false) => return Ok(true),
                // A source that can't be read now (busy, half-written) is retried next time.
                Err(e) => eprintln!("symbia: index skipped {}: {e:#}", path.display()),
            }
        }
        Ok(false)
    }

    /// Index `path` from where it was left; false if the deadline came first.
    fn index_source(&mut self, path: &Path, deadline: Instant) -> anyhow::Result<bool> {
        let key = path.display().to_string();
        let src = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        src.busy_timeout(Duration::from_secs(1))?;
        let Some(session): Option<String> =
            src.query_row("SELECT r.session FROM chain c JOIN records r ON r.id = c.record_id ORDER BY c.seq LIMIT 1", [], |r| r.get(0)).optional()?
        else {
            return Ok(true);
        };
        let last: i64 = self.conn.query_row("SELECT last_seq FROM sources WHERE path = ?1", [&key], |r| r.get(0)).optional()?.unwrap_or(0);
        // Seals are prefixes of their session's chain: never re-read what another file gave.
        let have: i64 = self.conn.query_row("SELECT COALESCE(MAX(seq), 0) FROM docs WHERE session = ?1", [&session], |r| r.get(0))?;
        let mut from = last.max(have);
        let thread = if has_column(&src, "chain", "thread")? { "COALESCE(c.thread, 'main')" } else { "'main'" };
        let sql = format!(
            "SELECT c.seq, r.id, r.key, r.version, r.kind, r.lane, {thread}, r.at_ms, r.model, r.est_chars, r.chars, r.est_host_ms, r.host_ms,
                    json(r.body), r.session
             FROM chain c JOIN records r ON r.id = c.record_id WHERE c.seq > ?1 ORDER BY c.seq LIMIT ?2"
        );
        loop {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            let rows: Vec<Row> = src
                .prepare(&sql)?
                .query_map(params![from, BATCH], |r| {
                    Ok(Row {
                        seq: r.get(0)?,
                        id: r.get(1)?,
                        key: r.get(2)?,
                        version: r.get(3)?,
                        kind: r.get(4)?,
                        lane: r.get(5)?,
                        thread: r.get(6)?,
                        at_ms: r.get(7)?,
                        model: r.get(8)?,
                        est_chars: r.get(9)?,
                        chars: r.get(10)?,
                        est_host_ms: r.get(11)?,
                        host_ms: r.get(12)?,
                        body: r.get(13)?,
                        session: r.get(14)?,
                    })
                })?
                .collect::<Result<_, _>>()?;
            let Some(top) = rows.last().map(|r| r.seq) else { break };
            let tx = self.conn.transaction()?;
            for row in &rows {
                let links: Vec<(String, String)> = src
                    .prepare_cached("SELECT to_id, rel FROM links WHERE from_id = ?1")?
                    .query_map([&row.id], |l| Ok((l.get(0)?, l.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                insert_doc(&tx, &self.home, row, &links)?;
            }
            tx.execute("INSERT INTO sources (path, last_seq) VALUES (?1, ?2) ON CONFLICT (path) DO UPDATE SET last_seq = excluded.last_seq", params![key, top])?;
            tx.commit()?;
            from = top;
        }
        self.conn.execute("INSERT INTO sources (path, last_seq) VALUES (?1, ?2) ON CONFLICT (path) DO UPDATE SET last_seq = MAX(last_seq, excluded.last_seq)", params![key, from])?;
        Ok(true)
    }

    /// Keyword search, best first (bm25), at most `limit`.
    pub fn search_text(&self, query: &str, f: &Filter, limit: u32) -> anyhow::Result<Vec<Hit>> {
        let Some(q) = fts_query(query) else { return Ok(Vec::new()) };
        let (clauses, mut args) = f.sql();
        let sql = format!(
            "SELECT d.id, d.record_id, d.key, d.version, d.kind, d.lane, d.thread, d.session, bm25(docs_fts)
             FROM docs_fts JOIN docs d ON d.id = docs_fts.rowid WHERE docs_fts MATCH ?{clauses} ORDER BY bm25(docs_fts), d.at_ms DESC LIMIT ?"
        );
        args.insert(0, Box::new(q));
        args.push(Box::new(limit));
        // bm25 is lower for better matches; report a score where higher is better.
        self.hits(&sql, &args, |s| -s)
    }

    /// The newest documents passing `f`, at most `limit` (a search with filters only).
    pub fn recent(&self, f: &Filter, limit: u32) -> anyhow::Result<Vec<Hit>> {
        let (clauses, mut args) = f.sql();
        args.push(Box::new(limit));
        let sql = format!(
            "SELECT d.id, d.record_id, d.key, d.version, d.kind, d.lane, d.thread, d.session, 0.0
             FROM docs d WHERE 1 = 1{clauses} ORDER BY d.at_ms DESC, d.id DESC LIMIT ?"
        );
        self.hits(&sql, &args, |_| 0.0)
    }

    /// Documents passing `f` with no vector from `model`, at most `cap`, oldest first.
    pub fn unembedded(&self, model: &str, f: &Filter, cap: u32) -> anyhow::Result<(Vec<(i64, String)>, i64)> {
        let (clauses, mut args) = f.sql();
        let base = format!("FROM docs d LEFT JOIN vectors v ON v.doc = d.id AND v.model = ? WHERE v.doc IS NULL{clauses}");
        args.insert(0, Box::new(model.to_string()));
        let total: i64 = self.conn.query_row(&format!("SELECT COUNT(*) {base}"), rusqlite::params_from_iter(args.iter()), |r| r.get(0))?;
        args.push(Box::new(cap));
        let todo = self
            .conn
            .prepare(&format!("SELECT d.id, d.text {base} ORDER BY d.id LIMIT ?"))?
            .query_map(rusqlite::params_from_iter(args.iter()), |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok((todo, total))
    }

    /// Store vectors from `model`, replacing any older vector of the same documents.
    pub fn store_vectors(&mut self, model: &str, docs: &[i64], vectors: &[Vec<f32>]) -> anyhow::Result<()> {
        anyhow::ensure!(docs.len() == vectors.len(), "{} documents, {} vectors", docs.len(), vectors.len());
        let tx = self.conn.transaction()?;
        for (doc, v) in docs.iter().zip(vectors) {
            let blob: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
            tx.execute(
                "INSERT INTO vectors (doc, model, dim, v) VALUES (?1, ?2, ?3, ?4) ON CONFLICT (doc) DO UPDATE SET model = excluded.model, dim = excluded.dim, v = excluded.v",
                params![doc, model, i64::try_from(v.len())?, blob],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Cosine similarity to `query` over documents passing `f` with a vector from `model`, best first.
    pub fn search_vector(&self, query: &[f32], model: &str, f: &Filter, limit: u32) -> anyhow::Result<Vec<Hit>> {
        let (clauses, mut args) = f.sql();
        args.insert(0, Box::new(model.to_string()));
        let sql = format!(
            "SELECT d.id, d.record_id, d.key, d.version, d.kind, d.lane, d.thread, d.session, v.v
             FROM docs d JOIN vectors v ON v.doc = d.id AND v.model = ? WHERE 1 = 1{clauses}"
        );
        let qn = norm(query);
        let mut stmt = self.conn.prepare(&sql)?;
        let mut hits: Vec<Hit> = stmt
            .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                let blob: Vec<u8> = r.get(8)?;
                Ok((hit_from(r)?, blob))
            })?
            .filter_map(Result::ok)
            .filter_map(|(mut h, blob)| {
                let v: Vec<f32> = blob.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
                (v.len() == query.len()).then(|| {
                    let dot: f32 = v.iter().zip(query).map(|(a, b)| a * b).sum();
                    let d = norm(&v) * qn;
                    h.score = if d > 0.0 { f64::from(dot / d) } else { 0.0 };
                    h
                })
            })
            .collect();
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then(b.doc.cmp(&a.doc)));
        hits.truncate(limit as usize);
        Ok(hits)
    }

    fn hits(&self, sql: &str, args: &[Box<dyn ToSql>], score: impl Fn(f64) -> f64) -> anyhow::Result<Vec<Hit>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            let mut h = hit_from(r)?;
            h.score = score(r.get(8)?);
            Ok(h)
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The `symbia_report` body for documents passing `f`, grouped `by`.
    pub fn report(&self, f: &Filter, by: By) -> anyhow::Result<Value> {
        let (clauses, args) = f.sql();
        let p = rusqlite::params_from_iter(args.iter());
        let (records, sessions): (i64, i64) =
            self.conn.query_row(&format!("SELECT COUNT(*), COUNT(DISTINCT d.session) FROM docs d WHERE 1 = 1{clauses}"), p, |r| Ok((r.get(0)?, r.get(1)?)))?;
        let sql = format!(
            "SELECT {g}, COUNT(*), SUM(d.kind = 'tool_call'), COALESCE(SUM(d.chars), 0), COALESCE(SUM(d.host_ms), 0),
                    SUM(d.error IS NOT NULL), COALESCE(SUM(d.error LIKE 'refused%' OR d.error LIKE 'denied%'), 0),
                    SUM(d.est_chars IS NOT NULL OR d.est_host_ms IS NOT NULL),
                    SUM(CASE WHEN d.est_chars IS NOT NULL THEN d.chars END), SUM(d.est_chars),
                    SUM(CASE WHEN d.est_host_ms IS NOT NULL THEN d.host_ms END), SUM(d.est_host_ms)
             FROM docs d WHERE 1 = 1{clauses} GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 50",
            g = by.expr()
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let groups: Vec<Value> = stmt
            .query_map(rusqlite::params_from_iter(args.iter()), |r| {
                let ratio = |a: Option<i64>, e: Option<i64>| match (a, e) {
                    (Some(a), Some(e)) if e > 0 => Some(a as f64 / e as f64),
                    _ => None,
                };
                let mut est = json!({"records": r.get::<_, i64>(7)?});
                if let Some(x) = ratio(r.get(8)?, r.get(9)?) {
                    est["chars_ratio"] = x.into();
                }
                if let Some(x) = ratio(r.get(10)?, r.get(11)?) {
                    est["host_ms_ratio"] = x.into();
                }
                Ok(json!({
                    "group": r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    "records": r.get::<_, i64>(1)?,
                    "tool_calls": r.get::<_, i64>(2)?,
                    "chars": r.get::<_, i64>(3)?,
                    "host_ms": r.get::<_, i64>(4)?,
                    "errors": r.get::<_, i64>(5)?,
                    "refused": r.get::<_, i64>(6)?,
                    "estimated": est,
                }))
            })?
            .collect::<Result<_, _>>()?;
        let (preds, resulted): (i64, i64) = self.conn.query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(EXISTS (SELECT 1 FROM links l JOIN docs r ON r.id = l.from_doc
                                                       WHERE l.to_id = d.record_id AND l.rel = 'results_of' AND r.kind = 'result')), 0)
                 FROM docs d WHERE d.kind = 'prediction'{clauses}"
            ),
            rusqlite::params_from_iter(args.iter()),
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (held, broke): (i64, i64) = self.conn.query_row(
            &format!("SELECT COALESCE(SUM(d.held), 0), COALESCE(SUM(d.broke), 0) FROM docs d WHERE d.kind = 'result'{clauses}"),
            rusqlite::params_from_iter(args.iter()),
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(json!({
            "records": records,
            "sessions": sessions,
            "groups": groups,
            "predictions": {"records": preds, "with_results": resulted, "open": preds - resulted, "held": held, "broke": broke},
        }))
    }
}

fn hit_from(r: &rusqlite::Row) -> rusqlite::Result<Hit> {
    Ok(Hit {
        doc: r.get(0)?,
        id: r.get(1)?,
        key: r.get(2)?,
        version: r.get(3)?,
        kind: r.get(4)?,
        lane: r.get(5)?,
        thread: r.get(6)?,
        session: r.get(7)?,
        score: 0.0,
    })
}

fn norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

/// Quote each whitespace-separated term as an FTS5 phrase so user text is never query syntax.
fn fts_query(q: &str) -> Option<String> {
    let terms: Vec<String> = q.split_whitespace().map(|t| format!("\"{}\"", t.replace('"', "\"\""))).collect();
    (!terms.is_empty()).then(|| terms.join(" "))
}

fn insert_doc(tx: &rusqlite::Transaction, home: &Path, row: &Row, links: &[(String, String)]) -> anyhow::Result<()> {
    let body: Value = serde_json::from_str(&row.body)?;
    let mut text = record_text(&row.key, &body);
    let (mut tool, mut error) = (None, None);
    if row.kind == "tool_call" {
        tool = body.get("tool").and_then(Value::as_str).map(String::from);
        error = body.get("error").and_then(Value::as_str).map(String::from);
        for k in ["stdout_sha256", "stderr_sha256"] {
            if let Some(t) = body.get(k).and_then(Value::as_str).and_then(|h| evidence_text(home, h)) {
                text.push(' ');
                text.push_str(&t);
            }
        }
    }
    let (held, broke) = if row.kind == "result" { verdicts(&body) } else { (0, 0) };
    let n = tx.execute(
        "INSERT OR IGNORE INTO docs (record_id, session, seq, key, version, kind, lane, thread, at_ms, model,
                                     est_chars, chars, est_host_ms, host_ms, tool, error, held, broke, text)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        params![
            row.id,
            row.session,
            row.seq,
            row.key,
            row.version,
            row.kind,
            row.lane,
            row.thread,
            row.at_ms,
            row.model,
            row.est_chars,
            row.chars,
            row.est_host_ms,
            row.host_ms,
            tool,
            error,
            held,
            broke,
            text
        ],
    )?;
    if n == 1 {
        let doc = tx.last_insert_rowid();
        tx.execute("INSERT INTO docs_fts (rowid, text) VALUES (?1, ?2)", params![doc, text])?;
        for (to_id, rel) in links {
            tx.execute("INSERT INTO links (from_doc, to_id, rel) VALUES (?1, ?2, ?3)", params![doc, to_id, rel])?;
        }
    }
    Ok(())
}

/// Reciprocal-rank fusion of two rankings: each hit scores the sum of `1 / (k + rank)` over the
/// lists it appears in (rank from 1). Best first, at most `limit`.
pub fn fuse(a: &[Hit], b: &[Hit], limit: usize) -> Vec<Hit> {
    let mut out: Vec<Hit> = Vec::new();
    for list in [a, b] {
        for (i, h) in list.iter().enumerate() {
            let s = 1.0 / (RRF_K + (i + 1) as f64);
            match out.iter_mut().find(|o| o.doc == h.doc) {
                Some(o) => o.score += s,
                None => out.push(Hit { score: s, ..h.clone() }),
            }
        }
    }
    out.sort_by(|x, y| y.score.total_cmp(&x.score).then(y.doc.cmp(&x.doc)));
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RecordInput;
    use crate::store::{Evidence, Store};

    pub fn rec(key: &str, kind: &str, body: Value) -> RecordInput {
        RecordInput {
            key: key.into(),
            kind: kind.into(),
            lane: "canonical".into(),
            lane_reason: "t".into(),
            body,
            model: "m".into(),
            est_host_ms: None,
            est_chars: None,
            links: None,
        }
    }

    fn count(ix: &Index, sql: &str) -> i64 {
        ix.conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn text_follows_the_body_in_order_and_is_capped() {
        let t = record_text("k.1", &json!({"a": "alpha", "b": [1, "beta", {"c": "gamma"}], "d": true}));
        assert_eq!(t, "k.1 alpha beta gamma");
        let long = record_text("k", &json!("é".repeat(9_000)));
        assert_eq!(long.chars().count(), TEXT_MAX);
    }

    #[test]
    fn verdict_forms() {
        assert_eq!(verdicts(&json!({"held": true})), (1, 0));
        assert_eq!(verdicts(&json!({"held": false})), (0, 1));
        assert_eq!(verdicts(&json!({"verdicts": {"a": "held", "b": "broke", "c": "unclear"}})), (1, 1));
        assert_eq!(verdicts(&json!({"predictions": {"P1": "BROKE: 203 < 205", "P2": "held: ok", "P3": " Held"}})), (2, 1));
        assert_eq!(verdicts(&json!({"x": 1})), (0, 0));
    }

    #[test]
    fn evidence_text_reads_utf8_only() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("evidence")).unwrap();
        let hex_a = "a".repeat(64);
        std::fs::write(t.path().join("evidence").join(&hex_a), "compiler said: unused import").unwrap();
        assert_eq!(evidence_text(t.path(), &hex_a).as_deref(), Some("compiler said: unused import"));
        let hex_b = "b".repeat(64);
        std::fs::write(t.path().join("evidence").join(&hex_b), [0xffu8, 0x00, 0x41]).unwrap();
        assert_eq!(evidence_text(t.path(), &hex_b), None);
        // A multibyte character cut at the 16 KB mark is trimmed, not refused.
        let hex_c = "c".repeat(64);
        let mut s = "x".repeat(EVIDENCE_MAX - 1);
        s.push('é');
        std::fs::write(t.path().join("evidence").join(&hex_c), &s).unwrap();
        assert_eq!(evidence_text(t.path(), &hex_c).unwrap().len(), EVIDENCE_MAX - 1);
        assert_eq!(evidence_text(t.path(), "../etc"), None);
    }

    /// Two sessions, a full seal of the first, a thread seal of the second, and evidence.
    fn corpus() -> (tempfile::TempDir, String, String) {
        let t = tempfile::tempdir().unwrap();
        let key = crate::keys::load_or_create(t.path()).unwrap();
        let mut a = Store::create(t.path()).unwrap();
        let p = a.write(&rec("boiler.pressure", "prediction", json!({"text": "boiler pressure stays under 12 bar"})), Instant::now()).unwrap();
        let mut r = rec("boiler.result", "result", json!({"held": true}));
        r.links = Some(vec![crate::record::LinkInput { to_id: p.id, rel: "results_of".into() }]);
        a.write(&r, Instant::now()).unwrap();
        crate::seal::seal(&a, &key).unwrap();
        std::fs::create_dir_all(t.path().join("evidence")).unwrap();
        let ev = "e".repeat(64);
        std::fs::write(t.path().join("evidence").join(&ev), "warning: condensate trap stuck open").unwrap();
        let mut b = Store::create(t.path()).unwrap();
        b.write_in("chat-b", &rec("tool.symbia_exec", "tool_call", json!({"tool": "symbia_exec", "stdout_sha256": ev})), Instant::now(), None, &[Evidence { sha256: [0xee; 32], bytes: 1, media: "text/plain" }])
            .unwrap();
        b.write(&rec("tool.symbia_fs_read", "tool_call", json!({"tool": "symbia_fs_read", "error": "denied: ~/.ssh/id is on the deny list"})), Instant::now()).unwrap();
        b.write(&rec("open.prediction", "prediction", json!({"text": "flow doubles"})), Instant::now()).unwrap();
        crate::seal::seal_thread(&b, &key, "chat-b").unwrap();
        let ids = (a.session().to_string(), b.session().to_string());
        (t, ids.0, ids.1)
    }

    #[test]
    fn refresh_indexes_every_source_once_and_only_new_rows() {
        let (t, sa, sb) = corpus();
        let mut ix = Index::open(t.path()).unwrap();
        assert!(!ix.refresh(REFRESH_BUDGET).unwrap());
        assert_eq!(count(&ix, "SELECT COUNT(*) FROM docs"), 5);
        assert_eq!(count(&ix, &format!("SELECT COUNT(*) FROM docs WHERE session = '{sa}'")), 2);
        assert_eq!(count(&ix, &format!("SELECT COUNT(*) FROM docs WHERE session = '{sb}'")), 3);
        // The thread seal is not a source; the full seal and both session files are.
        assert_eq!(count(&ix, "SELECT COUNT(*) FROM sources WHERE path LIKE '%.thread-%'"), 0);
        assert_eq!(count(&ix, "SELECT COUNT(*) FROM sources"), 3);
        // A new row is picked up, nothing else is re-read.
        let path = t.path().join("sessions").join(format!("{sb}.sqlite"));
        let mut b = Store::open(t.path(), &path).unwrap();
        b.write(&rec("late", "observation", json!({"text": "late note"})), Instant::now()).unwrap();
        assert!(!ix.refresh(REFRESH_BUDGET).unwrap());
        assert_eq!(count(&ix, "SELECT COUNT(*) FROM docs"), 6);
        assert_eq!(count(&ix, "SELECT COUNT(*) FROM docs_fts"), 6);
        // Deleted, it rebuilds the same.
        drop(ix);
        for f in [FILE, "index.sqlite-wal", "index.sqlite-shm"] {
            let _ = std::fs::remove_file(t.path().join(f));
        }
        let mut ix = Index::open(t.path()).unwrap();
        ix.refresh(REFRESH_BUDGET).unwrap();
        assert_eq!(count(&ix, "SELECT COUNT(*) FROM docs"), 6);
        // A zero budget leaves it behind.
        drop(ix);
        let _ = std::fs::remove_file(t.path().join(FILE));
        let mut ix = Index::open(t.path()).unwrap();
        assert!(ix.refresh(Duration::ZERO).unwrap());
    }

    #[test]
    fn text_search_reaches_bodies_evidence_and_filters() {
        let (t, sa, sb) = corpus();
        let mut ix = Index::open(t.path()).unwrap();
        ix.refresh(REFRESH_BUDGET).unwrap();
        let hits = ix.search_text("boiler pressure", &Filter::default(), 10).unwrap();
        assert_eq!((hits[0].key.as_str(), hits[0].session.as_str()), ("boiler.pressure", sa.as_str()));
        assert!(hits[0].score > 0.0);
        // Command output is searchable through its tool_call record.
        let hits = ix.search_text("condensate trap", &Filter::default(), 10).unwrap();
        assert_eq!((hits.len(), hits[0].thread.as_str(), hits[0].session.as_str()), (1, "chat-b", sb.as_str()));
        let f = Filter { session: Some(sa.clone()), ..Default::default() };
        assert!(ix.search_text("condensate", &f, 10).unwrap().is_empty());
        let f = Filter { kind: Some("prediction".into()), ..Default::default() };
        assert_eq!(ix.search_text("flow", &f, 10).unwrap().len(), 1);
        assert!(ix.search_text("   ", &Filter::default(), 10).unwrap().is_empty());
        assert!(ix.search_text("\"unbalanced AND (", &Filter::default(), 10).unwrap().is_empty());
    }

    #[test]
    fn older_formats_index_as_main() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("seals")).unwrap();
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        for f in ["format1.sqlite", "format2.sqlite"] {
            std::fs::copy(src.join(f), t.path().join("seals").join(f)).unwrap();
        }
        let mut ix = Index::open(t.path()).unwrap();
        ix.refresh(REFRESH_BUDGET).unwrap();
        assert!(count(&ix, "SELECT COUNT(*) FROM docs") >= 6);
        assert_eq!(count(&ix, "SELECT COUNT(*) FROM docs WHERE thread <> 'main'"), 0);
    }

    #[test]
    fn report_groups_sums_and_predictions() {
        let (t, sa, _sb) = corpus();
        let mut ix = Index::open(t.path()).unwrap();
        ix.refresh(REFRESH_BUDGET).unwrap();
        let r = ix.report(&Filter::default(), By::Thread).unwrap();
        assert_eq!((r["records"].as_i64(), r["sessions"].as_i64()), (Some(5), Some(2)));
        assert_eq!(r["groups"][0]["group"], "main");
        assert_eq!(r["groups"][0]["records"], 4);
        assert_eq!(r["groups"][1]["group"], "chat-b");
        assert_eq!(r["predictions"], json!({"records": 2, "with_results": 1, "open": 1, "held": 1, "broke": 0}));
        let by_tool = ix.report(&Filter::default(), By::Tool).unwrap();
        let fs = by_tool["groups"].as_array().unwrap().iter().find(|g| g["group"] == "symbia_fs_read").unwrap();
        assert_eq!((fs["tool_calls"].as_i64(), fs["errors"].as_i64(), fs["refused"].as_i64()), (Some(1), Some(1), Some(1)));
        let one = ix.report(&Filter { session: Some(sa), ..Default::default() }, By::Kind).unwrap();
        assert_eq!(one["records"], 2);
        let kinds: Vec<&str> = one["groups"].as_array().unwrap().iter().map(|g| g["group"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["prediction", "result"]);
        let thread = ix.report(&Filter { thread: Some("chat-b".into()), ..Default::default() }, By::Thread).unwrap();
        assert_eq!(thread["records"], 1);
        assert_eq!(By::parse(Some("week")).unwrap_err(), "by must be thread, tool, kind, model or day, not \"week\"");
    }

    #[test]
    fn report_days_are_utc_and_estimates_compare_to_actuals() {
        let t = tempfile::tempdir().unwrap();
        let mut s = Store::create(t.path()).unwrap();
        let mut e = rec("e", "observation", json!(1));
        e.est_chars = Some(50);
        e.est_host_ms = Some(0);
        s.write(&e, Instant::now()).unwrap();
        s.write(&rec("f", "observation", json!(2)), Instant::now()).unwrap();
        // Pin the times: 2026-01-01T23:30Z and 2026-01-02T00:30Z, a minute either side of midnight UTC.
        s.conn().execute("UPDATE records SET at_ms = 1767310200000 WHERE key = 'e'", []).unwrap();
        s.conn().execute("UPDATE records SET at_ms = 1767313800000 WHERE key = 'f'", []).unwrap();
        let mut ix = Index::open(t.path()).unwrap();
        ix.refresh(REFRESH_BUDGET).unwrap();
        let r = ix.report(&Filter::default(), By::Day).unwrap();
        let days: Vec<&str> = r["groups"].as_array().unwrap().iter().map(|g| g["group"].as_str().unwrap()).collect();
        assert_eq!(days, ["2026-01-01", "2026-01-02"]);
        let chars: i64 = s.get(&s.id_for_key("e", None).unwrap().unwrap()).unwrap().unwrap()["chars"].as_i64().unwrap();
        let est = &r["groups"][0]["estimated"];
        assert_eq!(est["records"], 1);
        assert!((est["chars_ratio"].as_f64().unwrap() - chars as f64 / 50.0).abs() < 1e-9, "{est}");
        assert!(est.get("host_ms_ratio").is_none(), "an estimate sum of zero gives no ratio");
        let f = Filter { since_ms: Some(1767312000000), ..Default::default() };
        assert_eq!(ix.report(&f, By::Day).unwrap()["records"], 1);
    }

    #[test]
    fn vectors_store_rank_and_go_stale_with_the_model() {
        let (t, _, _) = corpus();
        let mut ix = Index::open(t.path()).unwrap();
        ix.refresh(REFRESH_BUDGET).unwrap();
        let (todo, total) = ix.unembedded("m1", &Filter::default(), 3).unwrap();
        assert_eq!((todo.len(), total), (3, 5));
        let (all, _) = ix.unembedded("m1", &Filter::default(), 100).unwrap();
        let docs: Vec<i64> = all.iter().map(|d| d.0).collect();
        let vecs: Vec<Vec<f32>> = all.iter().map(|(_, text)| if text.contains("pressure") { vec![1.0, 0.0] } else { vec![0.0, 1.0] }).collect();
        ix.store_vectors("m1", &docs, &vecs).unwrap();
        assert_eq!(ix.unembedded("m1", &Filter::default(), 100).unwrap().1, 0);
        let hits = ix.search_vector(&[0.9, 0.1], "m1", &Filter::default(), 2).unwrap();
        assert_eq!(hits[0].key, "boiler.pressure");
        assert!(hits[0].score > hits[1].score);
        let blob: Vec<u8> = ix.conn.query_row("SELECT v FROM vectors LIMIT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(blob.len(), 8);
        // Another model's vectors don't count: everything is due again.
        assert_eq!(ix.unembedded("m2", &Filter::default(), 100).unwrap().1, 5);
        // A dimension mismatch is skipped, not an error.
        assert!(ix.search_vector(&[1.0, 0.0, 0.0], "m1", &Filter::default(), 5).unwrap().is_empty());
        assert!(ix.store_vectors("m1", &[1], &[]).is_err());
    }

    #[test]
    fn fusion_rewards_agreement() {
        let h = |doc: i64| Hit { doc, id: doc.to_string(), key: String::new(), version: 1, kind: String::new(), lane: String::new(), thread: String::new(), session: String::new(), score: 0.0 };
        let a = [h(1), h(2), h(3)];
        let b = [h(3), h(4)];
        let f = fuse(&a, &b, 10);
        let order: Vec<i64> = f.iter().map(|x| x.doc).collect();
        assert_eq!(order, [3, 1, 4, 2]);
        assert!((f[0].score - (1.0 / 63.0 + 1.0 / 61.0)).abs() < 1e-12);
        assert_eq!(fuse(&a, &b, 2).len(), 2);
    }
}
