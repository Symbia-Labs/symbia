//! Reading a sealed copy without writing SQL: what `symbia show` and `symbia get` print. The
//! caller verifies the seal first; nothing here checks it.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

/// Open a sealed copy read-only.
pub fn open(path: &Path) -> anyhow::Result<Connection> {
    Ok(Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?)
}

/// `chain.thread`, or `'main'` in files from before threads.
fn thread_col(conn: &Connection) -> rusqlite::Result<&'static str> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('chain') WHERE name = 'thread'", [], |r| r.get(0))?;
    Ok(if n > 0 { "c.thread" } else { "'main'" })
}

/// Every chain row in order: seq, thread, kind, lane, key. A row whose record a thread seal
/// withheld shows `(withheld)` as its key.
pub fn chain(conn: &Connection) -> anyhow::Result<Vec<Vec<String>>> {
    let sql = format!(
        "SELECT c.seq, {}, r.kind, r.lane, r.key FROM chain c LEFT JOIN records r ON r.id = c.record_id ORDER BY c.seq",
        thread_col(conn)?
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| {
        let key: Option<String> = r.get(4)?;
        Ok(vec![
            r.get::<_, i64>(0)?.to_string(),
            r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            key.unwrap_or_else(|| "(withheld)".into()),
        ])
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Each prediction in chain order: key, verdict and claim. The verdict sums the results linked
/// to it with `results_of`: `held`, `broke`, `mixed`, `linked` when the results carry no
/// verdict, or `open` when none is linked yet.
pub fn predictions(conn: &Connection) -> anyhow::Result<Vec<Vec<String>>> {
    let mut stmt = conn.prepare(
        "SELECT r.id, r.key, json(r.body) FROM records r JOIN chain c ON c.record_id = r.id WHERE r.kind = 'prediction' ORDER BY c.seq",
    )?;
    let preds: Vec<(String, String, String)> = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
    let mut results = conn.prepare("SELECT json(r.body) FROM links l JOIN records r ON r.id = l.from_id WHERE l.to_id = ?1 AND l.rel = 'results_of'")?;
    let mut out = Vec::new();
    for (id, key, body) in preds {
        let (mut held, mut broke, mut linked) = (0, 0, 0);
        for b in results.query_map([&id], |r| r.get::<_, String>(0))? {
            let (h, k) = crate::index::verdicts(&serde_json::from_str(&b?)?);
            (held, broke, linked) = (held + h, broke + k, linked + 1);
        }
        let verdict = match (linked, held, broke) {
            (0, _, _) => "open",
            (_, h, 0) if h > 0 => "held",
            (_, 0, b) if b > 0 => "broke",
            (_, 0, 0) => "linked",
            _ => "mixed",
        };
        let claim = serde_json::from_str::<Value>(&body)?.get("claim").and_then(Value::as_str).unwrap_or_default().to_string();
        out.push(vec![key, verdict.to_string(), claim]);
    }
    Ok(out)
}

/// The shell commands run through `exec`, in chain order: command, exit, host_ms, chars.
pub fn commands(conn: &Connection) -> anyhow::Result<Vec<Vec<String>>> {
    let mut stmt = conn.prepare(
        "SELECT json(r.body), r.host_ms, r.chars FROM records r JOIN chain c ON c.record_id = r.id
         WHERE r.kind = 'tool_call' AND json_extract(r.body, '$.tool') = 'exec' ORDER BY c.seq",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?, r.get::<_, Option<i64>>(2)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (body, host_ms, chars) = row?;
        let body: Value = serde_json::from_str(&body)?;
        let text = |v: Option<&Value>| match v {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
        };
        let num = |n: Option<i64>| n.map(|n| n.to_string()).unwrap_or_default();
        out.push(vec![text(body.get("command")), text(body.get("exit")), num(host_ms), num(chars)]);
    }
    Ok(out)
}

/// The record `key_or_id` names, in full: an id, or else the newest version of a key.
pub fn record(conn: &Connection, key_or_id: &str) -> anyhow::Result<Option<Value>> {
    if let Some(r) = crate::store::get_in(conn, key_or_id)? {
        return Ok(Some(r));
    }
    let id: Option<String> = rusqlite::OptionalExtension::optional(conn.query_row(
        "SELECT r.id FROM records r JOIN chain c ON c.record_id = r.id WHERE r.key = ?1 ORDER BY r.version DESC LIMIT 1",
        [key_or_id],
        |r| r.get(0),
    ))?;
    match id {
        Some(id) => crate::store::get_in(conn, &id),
        None => Ok(None),
    }
}

/// Left-aligned columns two spaces apart, with a header row; no trailing spaces.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut width: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (w, c) in width.iter_mut().zip(r) {
            *w = (*w).max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let mut s = String::new();
        for (i, (c, w)) in cells.iter().zip(&width).enumerate() {
            s.push_str(c);
            if i + 1 < cells.len() {
                s.push_str(&" ".repeat(w - c.chars().count() + 2));
            }
        }
        s.trim_end().to_string()
    };
    let mut out = vec![line(header.to_vec())];
    out.extend(rows.iter().map(|r| line(r.iter().map(String::as_str).collect())));
    out.join("\n")
}

/// Everything `symbia show` prints after the verify line: the chain, then the predictions and
/// the commands when there are any, separated by blank lines.
pub fn show(conn: &Connection) -> anyhow::Result<String> {
    let mut parts = vec![table(&["seq", "thread", "kind", "lane", "key"], &chain(conn)?)];
    let p = predictions(conn)?;
    if !p.is_empty() {
        parts.push(table(&["prediction", "verdict", "claim"], &p));
    }
    let c = commands(conn)?;
    if !c.is_empty() {
        parts.push(table(&["command", "exit", "host_ms", "chars"], &c));
    }
    Ok(parts.join("\n\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_pads_every_column_but_the_last() {
        let t = table(&["a", "bb"], &[vec!["xyz".into(), "1".into()], vec!["".into(), "".into()]]);
        assert_eq!(t, "a    bb\nxyz  1\n");
    }
}
