//! File tools: read, list, search, write and edit, each checked against the path policy.
//!
//! Every tool fills [`Facts`] as it goes, so a refused or failed call is still described
//! in its `tool_call` record.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use globset::GlobMatcher;
use grep::regex::RegexMatcherBuilder;
use grep::searcher::{BinaryDetection, SearcherBuilder, Sink, SinkContext, SinkContextKind, SinkMatch};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::canon::hex_prefix;
use crate::policy::{Access, Policy};

pub const READ_LINES_MAX: u64 = 2_000;
pub const READ_BYTES_MAX: usize = 256 * 1024;
pub const LIST_DEPTH_MAX: usize = 5;
pub const LIST_ENTRIES_MAX: usize = 1_000;
pub const SEARCH_CONTEXT_MAX: usize = 5;
pub const SEARCH_MATCHES_MAX: usize = 200;
const SEARCH_MATCHES_DEFAULT: usize = 50;
pub const SEARCH_DEADLINE: Duration = Duration::from_secs(30);
/// Matched and context lines are clipped to this many bytes in search replies.
const SEARCH_LINE_MAX: usize = 400;
const PREFIX: usize = 12;

/// What a `tool_call` record says about a call, besides the tool, args digest and reply size.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Facts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_sha256: Option<String>,
    pub truncated: bool,
}

fn io(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn show(p: &Path) -> String {
    p.display().to_string()
}

/// Check `path` and note it in `slot`: the path as given if refused, else its realpath.
pub fn checked(policy: &Policy, path: &str, access: Access, slot: &mut Option<String>) -> Result<PathBuf, String> {
    *slot = Some(path.to_string());
    let real = policy.check(path, access)?;
    *slot = Some(show(&real));
    Ok(real)
}

/// sha256 of a file, streamed.
pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finalize().into());
        }
        h.update(&buf[..n]);
    }
}

/// Write `bytes` to a temp file beside `path`, then rename it over `path`. With `create_only`
/// the temp file is hard-linked instead, which fails if `path` already exists.
pub fn atomic_write(path: &Path, bytes: &[u8], create_only: bool) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| std::io::Error::other("path has no parent"))?;
    let name = path.file_name().ok_or_else(|| std::io::Error::other("path has no file name"))?;
    let mut r = [0u8; 4];
    getrandom::fill(&mut r).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp = dir.join(format!(".{}.symbia-{}.tmp", name.to_string_lossy(), hex::encode(r)));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        if let Ok(meta) = std::fs::metadata(path) {
            f.set_permissions(meta.permissions())?;
        }
        f.sync_all()?;
        if create_only { std::fs::hard_link(&tmp, path) } else { std::fs::rename(&tmp, path) }
    })();
    if create_only || result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

// ---------------------------------------------------------------- read

/// Text with 1-based line numbers, from line `offset` (default 1), at most `limit` lines
/// (default and cap 2,000) and 256 KB. Binary files (NUL bytes or not UTF-8) are refused.
pub fn read(policy: &Policy, path: &str, offset: Option<u64>, limit: Option<u64>, facts: &mut Facts) -> Result<String, String> {
    let real = checked(policy, path, Access::Read, &mut facts.path)?;
    if real.is_dir() {
        return Err(format!("{} is a directory; use symbia_fs_list", real.display()));
    }
    let start = offset.unwrap_or(1).max(1);
    let limit = limit.unwrap_or(READ_LINES_MAX).clamp(1, READ_LINES_MAX);
    let mut reader = BufReader::new(std::fs::File::open(&real).map_err(io)?);
    let mut hasher = Sha256::new();
    let mut buf = Vec::new();
    let (mut n, mut total_bytes, mut shown) = (0u64, 0u64, 0u64);
    let mut binary = false;
    let mut cut: Option<String> = None;
    let mut out = String::new();
    loop {
        buf.clear();
        let k = reader.read_until(b'\n', &mut buf).map_err(io)?;
        if k == 0 {
            break;
        }
        hasher.update(&buf);
        total_bytes += k as u64;
        n += 1;
        // A UTF-8 sequence never spans a newline, so checking line by line checks the file.
        let text = match std::str::from_utf8(&buf) {
            Ok(t) if !binary && !t.contains('\0') => t,
            _ => {
                binary = true;
                continue;
            }
        };
        if n < start || cut.is_some() {
            continue;
        }
        if shown == limit {
            cut = Some(format!("{READ_LINES_MAX}-line cap"));
            continue;
        }
        let line = text.strip_suffix('\n').unwrap_or(text);
        let line = line.strip_suffix('\r').unwrap_or(line);
        let entry = format!("{n:>6}\t{line}\n");
        if out.len() + entry.len() > READ_BYTES_MAX {
            if shown == 0 {
                let mut end = READ_BYTES_MAX - 16;
                while !entry.is_char_boundary(end) {
                    end -= 1;
                }
                out.push_str(&entry[..end]);
                out.push('\n');
                shown = 1;
                cut = Some(format!("256 KB cap; line {n} itself was cut"));
            } else {
                cut = Some("256 KB cap".into());
            }
            continue;
        }
        out.push_str(&entry);
        shown += 1;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    facts.sha256_before = Some(hex::encode(digest));
    if binary {
        return Err(format!("binary file refused: {total_bytes} bytes, sha256 {}", hex::encode(digest)));
    }
    if let Some(why) = cut {
        facts.truncated = true;
        let next = start + shown;
        out.push_str(&format!("[cut at the {why}: lines {start}-{} of {n} shown; continue with offset {next}]\n", next - 1));
    } else if n == 0 {
        out.push_str("[empty file]\n");
    } else if start > n {
        out.push_str(&format!("[offset {start} is past the end: the file has {n} lines]\n"));
    }
    Ok(out)
}

// ---------------------------------------------------------------- list

fn glob(g: Option<&str>) -> Result<Option<GlobMatcher>, String> {
    g.map(|g| globset::Glob::new(g).map(|g| g.compile_matcher()).map_err(|e| format!("bad glob: {e}"))).transpose()
}

fn rel(root: &Path, p: &Path) -> String {
    match p.strip_prefix(root) {
        Ok(r) if !r.as_os_str().is_empty() => show(r),
        _ => p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
    }
}

fn mtime_ms(meta: &std::fs::Metadata) -> Option<i64> {
    let d = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(d.as_millis()).ok()
}

/// Entries under a directory to `depth` (default 1, at most 5), optionally filtered by a glob
/// on the relative path. Symlinks are listed, not followed. Denied paths are skipped.
pub fn list(policy: &Policy, path: &str, depth: Option<usize>, glob_: Option<&str>, facts: &mut Facts) -> Result<String, String> {
    let depth = depth.unwrap_or(1);
    if !(1..=LIST_DEPTH_MAX).contains(&depth) {
        return Err(format!("depth must be 1 to {LIST_DEPTH_MAX}"));
    }
    let root = checked(policy, path, Access::Read, &mut facts.path)?;
    if !root.is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }
    let matcher = glob(glob_)?;
    let deny = policy.clone();
    let walk = ignore::WalkBuilder::new(&root)
        .standard_filters(false)
        .follow_links(false)
        .max_depth(Some(depth))
        .sort_by_file_name(|a, b| a.cmp(b))
        .filter_entry(move |e| !deny.denied(e.path()))
        .build();
    let mut entries = Vec::new();
    let mut skipped = 0u64;
    for e in walk {
        let Ok(e) = e else {
            skipped += 1;
            continue;
        };
        if e.depth() == 0 {
            continue;
        }
        let r = rel(&root, e.path());
        if matcher.as_ref().is_some_and(|m| !m.is_match(&r)) {
            continue;
        }
        if entries.len() == LIST_ENTRIES_MAX {
            facts.truncated = true;
            break;
        }
        let Ok(meta) = e.path().symlink_metadata() else {
            skipped += 1;
            continue;
        };
        let ft = meta.file_type();
        let kind = if ft.is_symlink() {
            "symlink"
        } else if ft.is_dir() {
            "dir"
        } else if ft.is_file() {
            "file"
        } else {
            "other"
        };
        entries.push(json!({"path": r, "type": kind, "size": meta.len(), "mtime_ms": mtime_ms(&meta)}));
    }
    let mut reply = json!({"path": show(&root), "entries": entries, "truncated": facts.truncated});
    if skipped > 0 {
        reply["unreadable"] = skipped.into();
    }
    Ok(reply.to_string())
}

// ---------------------------------------------------------------- search

#[derive(Debug, Default)]
pub struct SearchArgs<'a> {
    pub pattern: &'a str,
    pub path: &'a str,
    pub glob: Option<&'a str>,
    pub literal: bool,
    pub ignore_case: bool,
    pub context: Option<usize>,
    pub max_matches: Option<usize>,
}

#[derive(Debug, Serialize)]
struct Hit {
    file: String,
    line: u64,
    text: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    before: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    after: Vec<String>,
}

fn clip(bytes: &[u8]) -> String {
    let b = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let b = b.strip_suffix(b"\r").unwrap_or(b);
    let s = String::from_utf8_lossy(b);
    if s.len() <= SEARCH_LINE_MAX {
        return s.into_owned();
    }
    let mut end = SEARCH_LINE_MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

struct Collect<'a> {
    file: String,
    hits: &'a mut Vec<Hit>,
    /// Index of this file's first hit in `hits`.
    first: usize,
    before: Vec<String>,
    max: usize,
    deadline: Instant,
    capped: &'a mut bool,
    timed_out: &'a mut bool,
}

impl Collect<'_> {
    fn go_on(&mut self) -> bool {
        if Instant::now() >= self.deadline {
            *self.timed_out = true;
        }
        !*self.timed_out && !*self.capped
    }
}

impl Sink for Collect<'_> {
    type Error = std::io::Error;

    fn matched(&mut self, _: &grep::searcher::Searcher, m: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        if self.hits.len() >= self.max {
            *self.capped = true;
            return Ok(false);
        }
        let before = std::mem::take(&mut self.before);
        self.hits.push(Hit { file: self.file.clone(), line: m.line_number().unwrap_or(0), text: clip(m.bytes()), before, after: Vec::new() });
        Ok(self.go_on())
    }

    fn context(&mut self, _: &grep::searcher::Searcher, c: &SinkContext<'_>) -> Result<bool, Self::Error> {
        match c.kind() {
            SinkContextKind::Before => self.before.push(clip(c.bytes())),
            SinkContextKind::After => {
                if self.hits.len() > self.first
                    && let Some(h) = self.hits.last_mut()
                {
                    h.after.push(clip(c.bytes()));
                }
            }
            SinkContextKind::Other => {}
        }
        Ok(self.go_on())
    }
}

/// Regex (or literal) search under a file or directory, respecting `.gitignore` and skipping
/// hidden and binary files. Stops at `max_matches` (default 50, at most 200) or at `deadline`.
pub fn search(policy: &Policy, a: &SearchArgs, deadline: Duration, facts: &mut Facts) -> Result<String, String> {
    let started = Instant::now();
    let context = a.context.unwrap_or(0);
    if context > SEARCH_CONTEXT_MAX {
        return Err(format!("context must be at most {SEARCH_CONTEXT_MAX}"));
    }
    let max = a.max_matches.unwrap_or(SEARCH_MATCHES_DEFAULT);
    if !(1..=SEARCH_MATCHES_MAX).contains(&max) {
        return Err(format!("max_matches must be 1 to {SEARCH_MATCHES_MAX}"));
    }
    if a.pattern.is_empty() {
        return Err("pattern is empty".into());
    }
    let root = checked(policy, a.path, Access::Read, &mut facts.path)?;
    let matcher = RegexMatcherBuilder::new()
        .case_insensitive(a.ignore_case)
        .fixed_strings(a.literal)
        .line_terminator(Some(b'\n'))
        .build(a.pattern)
        .map_err(|e| format!("bad pattern: {e}"))?;
    let globm = glob(a.glob)?;
    let mut searcher = SearcherBuilder::new()
        .binary_detection(BinaryDetection::quit(0))
        .line_number(true)
        .before_context(context)
        .after_context(context)
        .build();
    let deny = policy.clone();
    let walk = ignore::WalkBuilder::new(&root)
        .require_git(false)
        .follow_links(false)
        .sort_by_file_name(|a, b| a.cmp(b))
        .filter_entry(move |e| !deny.denied(e.path()))
        .build();
    let at = started + deadline;
    let (mut hits, mut capped, mut timed_out, mut files) = (Vec::new(), false, false, 0u64);
    for e in walk {
        if Instant::now() >= at {
            timed_out = true;
        }
        if capped || timed_out {
            break;
        }
        let Ok(e) = e else { continue };
        if !e.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let r = rel(&root, e.path());
        if globm.as_ref().is_some_and(|m| !m.is_match(&r)) {
            continue;
        }
        files += 1;
        let first = hits.len();
        let sink = Collect { file: r, hits: &mut hits, first, before: Vec::new(), max, deadline: at, capped: &mut capped, timed_out: &mut timed_out };
        // Unreadable files are skipped, as ripgrep does.
        let _ = searcher.search_path(&matcher, e.path(), sink);
    }
    facts.truncated = capped || timed_out;
    Ok(json!({"matches": hits, "files_searched": files, "truncated": capped, "timed_out": timed_out}).to_string())
}

// ---------------------------------------------------------------- write and edit

fn prepare_write(policy: &Policy, path: &str, facts: &mut Facts) -> Result<PathBuf, String> {
    let real = checked(policy, path, Access::Write, &mut facts.path)?;
    if real.is_dir() {
        return Err(format!("{} is a directory", real.display()));
    }
    if real.exists() {
        facts.sha256_before = Some(hex::encode(sha256_file(&real).map_err(io)?));
    }
    Ok(real)
}

/// Write `content` atomically, creating parent directories. With `create_only`, refuse an existing file.
pub fn write(policy: &Policy, path: &str, content: &str, create_only: bool, facts: &mut Facts) -> Result<String, String> {
    let real = prepare_write(policy, path, facts)?;
    if create_only && facts.sha256_before.is_some() {
        return Err(format!("{} exists and create_only is set", real.display()));
    }
    if let Some(dir) = real.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    atomic_write(&real, content.as_bytes(), create_only).map_err(|e| format!("write {}: {e}", real.display()))?;
    let after = crate::canon::sha256(content.as_bytes());
    facts.sha256_after = Some(hex::encode(after));
    Ok(json!({"path": show(&real), "bytes": content.len(), "sha256": hex_prefix(&after, PREFIX)}).to_string())
}

/// Byte offsets of every occurrence of `needle`, overlapping ones included.
fn occurrences(hay: &str, needle: &str) -> Vec<usize> {
    let step = needle.chars().next().map_or(1, char::len_utf8);
    let mut found = Vec::new();
    let mut i = 0;
    while let Some(p) = hay[i..].find(needle) {
        found.push(i + p);
        i += p + step;
    }
    found
}

/// Replace the one exact occurrence of `old` with `new`, atomically.
pub fn edit(policy: &Policy, path: &str, old: &str, new: &str, facts: &mut Facts) -> Result<String, String> {
    if old.is_empty() {
        return Err("old is empty".into());
    }
    let real = prepare_write(policy, path, facts)?;
    let bytes = std::fs::read(&real).map_err(|e| format!("read {}: {e}", real.display()))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8 text", real.display()))?;
    let found = occurrences(text, old);
    let [pos] = found[..] else {
        return Err(format!("old matches {} times in {}; it must match exactly once", found.len(), real.display()));
    };
    let edited = format!("{}{new}{}", &text[..pos], &text[pos + old.len()..]);
    atomic_write(&real, edited.as_bytes(), false).map_err(|e| format!("write {}: {e}", real.display()))?;
    let before = crate::canon::sha256(&bytes);
    let after = crate::canon::sha256(edited.as_bytes());
    facts.sha256_after = Some(hex::encode(after));
    let line = text[..pos].matches('\n').count() + 1;
    Ok(json!({
        "path": show(&real),
        "line": line,
        "sha256_before": hex_prefix(&before, PREFIX),
        "sha256_after": hex_prefix(&after, PREFIX),
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, PathBuf, Policy) {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("root");
        let sym = t.path().join("sym");
        std::fs::create_dir_all(&root).unwrap();
        crate::home::ensure(&sym).unwrap();
        let p = Policy::new(std::slice::from_ref(&root), &sym, t.path()).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        (t, root, p)
    }

    fn s(p: &Path) -> String {
        show(p)
    }

    fn v(reply: &str) -> Value {
        serde_json::from_str(reply).unwrap()
    }

    #[test]
    fn read_numbers_lines_and_continues_past_the_line_cap() {
        let (_t, root, p) = setup();
        let f = root.join("big.txt");
        let text: String = (1..=4500).map(|i| format!("line {i}\n")).collect();
        std::fs::write(&f, &text).unwrap();
        let mut facts = Facts::default();
        let out = read(&p, &s(&f), None, None, &mut facts).unwrap();
        assert!(out.starts_with("     1\tline 1\n"));
        assert!(out.contains("  2000\tline 2000\n"));
        assert!(!out.contains("line 2001\n"));
        assert!(out.ends_with("[cut at the 2000-line cap: lines 1-2000 of 4500 shown; continue with offset 2001]\n"), "{}", &out[out.len() - 120..]);
        assert!(facts.truncated);
        assert_eq!(facts.sha256_before.as_deref(), Some(hex::encode(crate::canon::sha256(text.as_bytes()))).as_deref());

        let mut facts = Facts::default();
        let out = read(&p, &s(&f), Some(4001), None, &mut facts).unwrap();
        assert!(out.starts_with("  4001\tline 4001\n") && out.ends_with("  4500\tline 4500\n"));
        assert!(!facts.truncated);
        let out = read(&p, &s(&f), Some(10), Some(2), &mut Facts::default()).unwrap();
        assert_eq!(out, "    10\tline 10\n    11\tline 11\n[cut at the 2000-line cap: lines 10-11 of 4500 shown; continue with offset 12]\n");
        let out = read(&p, &s(&f), Some(9000), None, &mut Facts::default()).unwrap();
        assert!(out.contains("past the end: the file has 4500 lines"));
    }

    #[test]
    fn read_stops_at_256_kb() {
        let (_t, root, p) = setup();
        let f = root.join("wide.txt");
        let line = "x".repeat(1000);
        std::fs::write(&f, format!("{line}\n").repeat(400)).unwrap();
        let mut facts = Facts::default();
        let out = read(&p, &s(&f), None, None, &mut facts).unwrap();
        assert!(out.len() <= READ_BYTES_MAX + 200);
        let shown = out.lines().filter(|l| l.contains('\t')).count();
        assert_eq!(shown, READ_BYTES_MAX / 1008);
        assert!(out.ends_with(&format!("continue with offset {}]\n", shown + 1)), "{}", &out[out.len() - 100..]);
        assert!(facts.truncated);
        // One line longer than the cap is cut and the reply says so.
        std::fs::write(&f, "y".repeat(300 * 1024)).unwrap();
        let out = read(&p, &s(&f), None, None, &mut Facts::default()).unwrap();
        assert!(out.len() <= READ_BYTES_MAX + 200);
        assert!(out.contains("line 1 itself was cut") && out.contains("continue with offset 2"));
    }

    #[test]
    fn read_refuses_binary_with_size_and_sha256() {
        let (_t, root, p) = setup();
        let f = root.join("blob.bin");
        let bytes = [b'a', b'\n', 0, 1, 2, 0xff];
        std::fs::write(&f, bytes).unwrap();
        let mut facts = Facts::default();
        let e = read(&p, &s(&f), None, None, &mut facts).unwrap_err();
        assert_eq!(e, format!("binary file refused: 6 bytes, sha256 {}", hex::encode(crate::canon::sha256(&bytes))));
        assert!(facts.sha256_before.is_some());
        // Invalid UTF-8 without NULs is binary too.
        std::fs::write(&f, [b'o', b'k', 0xc3, b'\n']).unwrap();
        assert!(read(&p, &s(&f), None, None, &mut Facts::default()).unwrap_err().starts_with("binary file refused: 4 bytes"));
    }

    #[test]
    fn list_reports_entries_depth_glob_and_cap() {
        let (_t, root, p) = setup();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/one.rs"), "1").unwrap();
        std::fs::write(root.join("a/b/two.rs"), "22").unwrap();
        std::fs::write(root.join("top.txt"), "333").unwrap();
        std::os::unix::fs::symlink("/etc", root.join("etc-link")).unwrap();
        let mut facts = Facts::default();
        let r = v(&list(&p, &s(&root), None, None, &mut facts).unwrap());
        let names: Vec<_> = r["entries"].as_array().unwrap().iter().map(|e| (e["path"].as_str().unwrap().to_string(), e["type"].as_str().unwrap().to_string())).collect();
        assert_eq!(names, [("a".into(), "dir".into()), ("etc-link".into(), "symlink".into()), ("top.txt".into(), "file".into())]);
        assert_eq!(r["entries"][2]["size"], 3);
        assert!(r["entries"][2]["mtime_ms"].as_i64().unwrap() > 0);
        assert_eq!(r["truncated"], false);
        let r = v(&list(&p, &s(&root), Some(3), Some("**/*.rs"), &mut Facts::default()).unwrap());
        let paths: Vec<_> = r["entries"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
        assert_eq!(paths, ["a/b/two.rs", "a/one.rs"]);
        assert!(list(&p, &s(&root), Some(6), None, &mut Facts::default()).is_err());

        for i in 0..1005 {
            std::fs::write(root.join(format!("many-{i:04}")), "").unwrap();
        }
        let mut facts = Facts::default();
        let r = v(&list(&p, &s(&root), None, None, &mut facts).unwrap());
        assert_eq!(r["entries"].as_array().unwrap().len(), LIST_ENTRIES_MAX);
        assert_eq!(r["truncated"], true);
        assert!(facts.truncated);
    }

    #[test]
    fn list_and_search_skip_denied_paths() {
        let t = tempfile::tempdir().unwrap();
        let user = t.path().join("user");
        let sym = user.join("Library/Application Support/Symbia");
        crate::home::ensure(&sym).unwrap();
        std::fs::create_dir_all(user.join(".ssh")).unwrap();
        std::fs::write(user.join(".ssh/id_ed25519"), "SECRET").unwrap();
        std::fs::write(sym.join("keys/device.ed25519"), "SECRET").unwrap();
        std::fs::write(user.join("notes.txt"), "SECRET").unwrap();
        let p = Policy::new(std::slice::from_ref(&user), &sym, &user).unwrap();
        let r = v(&list(&p, &s(&user), Some(5), None, &mut Facts::default()).unwrap());
        let paths: Vec<_> = r["entries"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap().to_string()).collect();
        assert!(!paths.iter().any(|p| p.starts_with(".ssh") || p.contains("keys")), "{paths:?}");
        assert!(paths.contains(&"notes.txt".to_string()));
        let a = SearchArgs { pattern: "SECRET", path: &s(&user), ..Default::default() };
        let r = v(&search(&p, &SearchArgs { ..a }, SEARCH_DEADLINE, &mut Facts::default()).unwrap());
        let files: Vec<_> = r["matches"].as_array().unwrap().iter().map(|m| m["file"].as_str().unwrap()).collect();
        assert_eq!(files, ["notes.txt"]);
    }

    #[test]
    fn search_respects_gitignore_context_and_cap() {
        let (_t, root, p) = setup();
        std::fs::write(root.join(".gitignore"), "ignored/\n*.log\n").unwrap();
        std::fs::create_dir_all(root.join("ignored")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("ignored/x.txt"), "needle\n").unwrap();
        std::fs::write(root.join("run.log"), "needle\n").unwrap();
        std::fs::write(root.join("src/a.rs"), "zero\none\nNeedle two\nthree\nfour\n").unwrap();
        std::fs::write(root.join("src/b.txt"), "needle\n").unwrap();
        let args = |pattern| SearchArgs { pattern, path: "", ..Default::default() };
        let rs = s(&root);
        let r = v(&search(&p, &SearchArgs { path: &rs, ..args("needle") }, SEARCH_DEADLINE, &mut Facts::default()).unwrap());
        let files: Vec<_> = r["matches"].as_array().unwrap().iter().map(|m| m["file"].as_str().unwrap()).collect();
        assert_eq!(files, ["src/b.txt"]);

        let r = v(&search(&p, &SearchArgs { path: &rs, ignore_case: true, context: Some(1), glob: Some("*.rs"), ..args("needle") }, SEARCH_DEADLINE, &mut Facts::default()).unwrap());
        assert_eq!(r["matches"], json!([{"file": "src/a.rs", "line": 3, "text": "Needle two", "before": ["one"], "after": ["three"]}]));
        // Literal: regex metacharacters match themselves.
        std::fs::write(root.join("src/re.txt"), "a.c\nabc\n").unwrap();
        let r = v(&search(&p, &SearchArgs { path: &rs, literal: true, ..args("a.c") }, SEARCH_DEADLINE, &mut Facts::default()).unwrap());
        assert_eq!(r["matches"].as_array().unwrap().len(), 1);

        std::fs::write(root.join("src/many.txt"), "hit\n".repeat(300)).unwrap();
        let mut facts = Facts::default();
        let r = v(&search(&p, &SearchArgs { path: &rs, max_matches: Some(200), ..args("hit") }, SEARCH_DEADLINE, &mut facts).unwrap());
        assert_eq!(r["matches"].as_array().unwrap().len(), 200);
        assert_eq!((r["truncated"].clone(), r["timed_out"].clone()), (json!(true), json!(false)));
        assert!(facts.truncated);
        let r = v(&search(&p, &SearchArgs { path: &rs, max_matches: Some(10), ..args("hit") }, SEARCH_DEADLINE, &mut Facts::default()).unwrap());
        assert_eq!(r["matches"].as_array().unwrap().len(), 10);
        assert!(search(&p, &SearchArgs { path: &rs, max_matches: Some(201), ..args("hit") }, SEARCH_DEADLINE, &mut Facts::default()).is_err());
        assert!(search(&p, &SearchArgs { path: &rs, context: Some(6), ..args("hit") }, SEARCH_DEADLINE, &mut Facts::default()).is_err());
    }

    #[test]
    fn search_deadline_returns_partial_results_flagged() {
        let (_t, root, p) = setup();
        std::fs::write(root.join("a.txt"), "hit\n").unwrap();
        let mut facts = Facts::default();
        let r = v(&search(&p, &SearchArgs { pattern: "hit", path: &s(&root), ..Default::default() }, Duration::ZERO, &mut facts).unwrap());
        assert_eq!(r["timed_out"], true);
        assert!(facts.truncated);
    }

    #[test]
    fn write_is_atomic_and_create_only_refuses_existing() {
        let (_t, root, p) = setup();
        let f = root.join("new/dir/f.txt");
        let mut facts = Facts::default();
        let r = v(&write(&p, &s(&f), "hello", false, &mut facts).unwrap());
        assert_eq!(r["bytes"], 5);
        assert_eq!(r["sha256"], hex_prefix(&crate::canon::sha256(b"hello"), 12));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "hello");
        assert!(facts.sha256_before.is_none() && facts.sha256_after.is_some());
        let e = write(&p, &s(&f), "x", true, &mut Facts::default()).unwrap_err();
        assert!(e.contains("create_only"), "{e}");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "hello");
        write(&p, &s(&root.join("fresh.txt")), "x", true, &mut Facts::default()).unwrap();
        let mut facts = Facts::default();
        write(&p, &s(&f), "bye", false, &mut facts).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "bye");
        assert_eq!(facts.sha256_before, Some(hex::encode(crate::canon::sha256(b"hello"))));
        // No temp files are left behind.
        let left: Vec<_> = std::fs::read_dir(f.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, ["f.txt"]);
        assert!(std::fs::read_dir(&root).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
    }

    #[test]
    fn edit_needs_exactly_one_match() {
        let (_t, root, p) = setup();
        let f = root.join("e.txt");
        std::fs::write(&f, "alpha\nbeta\ngamma beta\n").unwrap();
        let e = edit(&p, &s(&f), "delta", "x", &mut Facts::default()).unwrap_err();
        assert!(e.starts_with("old matches 0 times"), "{e}");
        let e = edit(&p, &s(&f), "beta", "x", &mut Facts::default()).unwrap_err();
        assert!(e.starts_with("old matches 2 times"), "{e}");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "alpha\nbeta\ngamma beta\n");

        let mut facts = Facts::default();
        let r = v(&edit(&p, &s(&f), "gamma beta", "gamma delta", &mut facts).unwrap());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "alpha\nbeta\ngamma delta\n");
        assert_eq!(r["line"], 3);
        assert_ne!(r["sha256_before"], r["sha256_after"]);
        assert_eq!(r["sha256_before"], hex_prefix(&crate::canon::sha256(b"alpha\nbeta\ngamma beta\n"), 12));
        assert_eq!(r["sha256_after"], hex_prefix(&sha256_file(&f).unwrap(), 12));
        assert_ne!(facts.sha256_before, facts.sha256_after);
        // Overlapping occurrences count.
        std::fs::write(&f, "aaa").unwrap();
        assert!(edit(&p, &s(&f), "aa", "b", &mut Facts::default()).unwrap_err().starts_with("old matches 2 times"));
    }

    #[test]
    fn file_tools_refuse_policy_violations() {
        let (t, _root, p) = setup();
        let outside = s(&t.path().join("outside.txt"));
        std::fs::write(&outside, "x").unwrap();
        let mut facts = Facts::default();
        assert!(read(&p, &outside, None, None, &mut facts).unwrap_err().starts_with("denied"));
        assert_eq!(facts.path.as_deref(), Some(outside.as_str()));
        assert!(write(&p, &outside, "y", false, &mut Facts::default()).unwrap_err().starts_with("denied"));
        assert!(edit(&p, &outside, "x", "y", &mut Facts::default()).unwrap_err().starts_with("denied"));
        assert!(list(&p, &s(t.path()), None, None, &mut Facts::default()).unwrap_err().starts_with("denied"));
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "x");
    }
}
