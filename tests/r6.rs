//! R6: `symbia mcp` opens its session on the first tool call, resumes the previous session
//! after a restart, tells the agent once, and cleans up empty files and locks.

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::stdio::{BIN, Mcp, seals};
use serde_json::{Value, json};

fn record(key: &str) -> Value {
    json!({"key": key, "kind": "observation", "lane": "canonical", "lane_reason": "r6", "body": {}, "model": "m"})
}

/// Files under `home/sessions`, sorted.
fn session_dir(home: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(home.join("sessions")).map(|d| d.map(|e| e.unwrap().path()).collect()).unwrap_or_default();
    v.sort();
    v
}

fn set_window(home: &Path, ms: i64) {
    std::fs::write(home.join("config.json"), json!({"resume_window_ms": ms}).to_string()).unwrap();
}

/// SIGTERM the server and wait for it to exit.
async fn sigterm(mut m: Mcp) {
    let pid = i32::try_from(m.child.id().unwrap()).unwrap();
    // SAFETY: signalling our own child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    tokio::time::timeout(Duration::from_secs(10), m.child.wait()).await.expect("exit after SIGTERM").unwrap();
}

fn notice(v: &Value) -> &str {
    v["notice"].as_str().unwrap_or_else(|| panic!("no notice in {v}"))
}

fn cli_verify(home: &Path, seal: &Path) -> std::process::Output {
    std::process::Command::new(BIN).args(["verify", seal.to_str().unwrap()]).env("SYMBIA_HOME", home).output().unwrap()
}

#[tokio::test]
async fn a_restart_after_sigterm_resumes_the_session() {
    let t = tempfile::tempdir().unwrap();
    let mut a = Mcp::start(t.path()).await;
    let w = a.tool(1, "record", record("before")).await.unwrap();
    assert_eq!(w["seq"], 1);
    let session = a.tool(2, "status", json!({})).await.unwrap()["session"].as_str().unwrap().to_string();
    assert!(notice(&w).starts_with(&format!("new session {session}")), "{w}");
    sigterm(a).await;
    assert!(!t.path().join("sessions").join(format!("{session}.lock")).exists());

    let mut b = Mcp::start(t.path()).await;
    let w = b.tool(1, "record", record("after")).await.unwrap();
    assert_eq!(w["seq"], 3, "{w}");
    let n = notice(&w);
    assert!(n.starts_with(&format!("session {session} resumed after a server restart; gap ")), "{n}");
    assert!(n.ends_with("s; seq continues at 2"), "{n}");
    let st = b.tool(2, "status", json!({})).await.unwrap();
    assert_eq!(st["session"], session.as_str());
    assert_eq!(st["resumes"], 1);
    assert_eq!(st["previous_session"], Value::Null);
    let found = b.tool(3, "find", json!({"key_prefix": "session.resumed"})).await.unwrap();
    assert_eq!(found.as_array().unwrap().len(), 1, "{found}");
    let rec = b.tool(4, "get", json!({"id": found[0]["id"]})).await.unwrap();
    assert_eq!((rec["kind"].as_str(), rec["lane"].as_str(), rec["seq"].as_i64()), (Some("observation"), Some("apocryphal"), Some(2)));
    let body = &rec["body"];
    assert!(body["previous_pid"].as_i64().unwrap() > 0, "{body}");
    assert!(body["previous_started_ms"].as_i64().unwrap() > 0, "{body}");
    assert!(body["gap_ms"].as_i64().unwrap() >= 0, "{body}");
    assert_eq!(body["resumes"], 1);
    b.close().await;

    // One session file; the latest seal covers both processes' records (the find's own record
    // makes four) and verifies.
    let files = session_dir(t.path());
    assert!(files.iter().all(|p| p.file_name().unwrap().to_str().unwrap().starts_with(&session)), "{files:?}");
    assert!(files.iter().all(|p| p.extension().is_none_or(|x| x != "lock")), "{files:?}");
    let latest = seals(t.path()).into_iter().max_by_key(|p| std::fs::metadata(p).unwrap().modified().unwrap()).unwrap();
    assert!(latest.to_str().unwrap().ends_with(&format!("{session}-4.sqlite")), "{latest:?}");
    let out = cli_verify(t.path(), &latest);
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).starts_with(&format!("ok {session} seq 4 ")));
}

#[tokio::test]
async fn a_second_live_process_gets_its_own_session() {
    let t = tempfile::tempdir().unwrap();
    let mut a = Mcp::start(t.path()).await;
    a.tool(1, "record", record("a")).await.unwrap();
    let a_session = a.tool(2, "status", json!({})).await.unwrap()["session"].as_str().unwrap().to_string();

    let mut b = Mcp::start(t.path()).await;
    let w = b.tool(1, "record", record("b")).await.unwrap();
    assert_eq!(w["seq"], 1);
    let n = notice(&w);
    assert!(n.starts_with("new session ") && n.ends_with(&format!("; the previous one ({a_session}) was not resumed: in use")), "{n}");
    let st = b.tool(2, "status", json!({})).await.unwrap();
    assert_ne!(st["session"], a_session.as_str());
    assert_eq!(st["previous_session"], a_session.as_str());
    assert_eq!(st["resumes"], 0);
    // A still writes to its own chain.
    assert_eq!(a.tool(3, "record", record("a2")).await.unwrap()["seq"], 2);
    a.close().await;
    b.close().await;
}

#[tokio::test]
async fn outside_the_window_or_with_resume_off_a_new_session_opens() {
    for (window, reason) in [(1, "outside the resume window"), (0, "resume off")] {
        let t = tempfile::tempdir().unwrap();
        set_window(t.path(), window);
        let mut a = Mcp::start(t.path()).await;
        a.tool(1, "record", record("a")).await.unwrap();
        let a_session = a.tool(2, "status", json!({})).await.unwrap()["session"].as_str().unwrap().to_string();
        a.close().await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut b = Mcp::start(t.path()).await;
        let st = b.tool(1, "status", json!({})).await.unwrap();
        assert_ne!(st["session"], a_session.as_str());
        assert_eq!(st["seq"], 0);
        assert!(notice(&st).ends_with(&format!("; the previous one ({a_session}) was not resumed: {reason}")), "{st}");
        b.close().await;
    }
}

#[tokio::test]
async fn a_start_without_a_tool_call_leaves_no_session_file() {
    let t = tempfile::tempdir().unwrap();
    // The desktop app's duplicate start: two servers within a second, neither called.
    let a = Mcp::start(t.path()).await;
    let b = Mcp::start(t.path()).await;
    a.close().await;
    b.close().await;
    assert!(session_dir(t.path()).is_empty(), "{:?}", session_dir(t.path()));
    assert!(seals(t.path()).is_empty());
}

#[tokio::test]
async fn empty_leftover_files_are_removed_at_startup() {
    let t = tempfile::tempdir().unwrap();
    let empty = symbia::store::Store::create(t.path()).unwrap();
    let mut full = symbia::store::Store::create(t.path()).unwrap();
    full.write(&serde_json::from_value(record("kept")).unwrap(), Instant::now()).unwrap();
    let (empty_path, full_path) = (empty.path().to_path_buf(), full.path().to_path_buf());
    drop((empty, full));

    let m = Mcp::start(t.path()).await;
    m.close().await;
    assert!(!empty_path.exists());
    assert!(full_path.exists());
    assert!(session_dir(t.path()).iter().all(|p| p.extension().is_some_and(|x| x != "lock")));
}

#[tokio::test]
async fn the_notice_comes_with_the_first_reply_only() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    let first = m.tool(1, "status", json!({})).await.unwrap();
    assert_eq!(notice(&first), format!("new session {}", first["session"].as_str().unwrap()));
    let second = m.tool(2, "status", json!({})).await.unwrap();
    assert!(second.get("notice").is_none(), "{second}");
    let third = m.tool(3, "record", record("x")).await.unwrap();
    assert!(third.get("notice").is_none(), "{third}");
    m.close().await;

    // A reply that is not a JSON object gets the notice as a block of its own.
    let mut m = Mcp::start(t.path()).await;
    m.send(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get", "arguments": {"id": "nope"}}})).await;
    let r = m.reply(1).await;
    assert_eq!(r["result"]["isError"], true);
    assert_eq!(r["result"]["content"][0]["text"], "no such record");
    let extra: Value = serde_json::from_str(r["result"]["content"][1]["text"].as_str().unwrap()).unwrap();
    assert!(extra["notice"].as_str().unwrap().contains("resumed after a server restart"), "{extra}");
    m.close().await;
}
