//! R2: the real binary seals its session when the stdio transport closes, and never seals an
//! empty session. The exec record names the command, sandbox and network setting.

mod common;

use common::stdio::{BIN, Mcp, seals};
use serde_json::json;

#[tokio::test]
async fn closing_stdin_seals_a_session_with_records() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    let w = m
        .tool(1, "record", json!({"key": "r2", "kind": "observation", "lane": "canonical", "lane_reason": "r2", "body": {}, "model": "m"}))
        .await
        .unwrap();
    assert_eq!(w["seq"], 1);
    let stderr = m.close().await;
    assert!(stderr.is_empty(), "{stderr}");

    let s = seals(t.path());
    assert_eq!(s.len(), 1, "{s:?}");
    assert!(s[0].file_name().unwrap().to_str().unwrap().ends_with("-1.sqlite"));
    let out = std::process::Command::new(BIN).args(["verify", s[0].to_str().unwrap()]).env("SYMBIA_HOME", t.path()).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ok "));
}

#[tokio::test]
async fn an_empty_session_leaves_no_seal() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    // Reads write nothing.
    assert_eq!(m.tool(1, "status", json!({})).await.unwrap()["seq"], 0);
    m.close().await;
    assert!(seals(t.path()).is_empty());
}

#[tokio::test]
async fn a_session_sealed_at_its_head_is_not_sealed_again() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    m.tool(1, "record", json!({"key": "a", "kind": "observation", "lane": "canonical", "lane_reason": "r", "body": {}, "model": "m"}))
        .await
        .unwrap();
    m.tool(2, "seal", json!({})).await.unwrap();
    m.close().await;
    assert_eq!(seals(t.path()).len(), 1);
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn exec_record_names_command_sandbox_and_network() {
    let t = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("config.json"), json!({"roots": [root.path()], "exec_network": "deny"}).to_string()).unwrap();
    let mut m = Mcp::start(t.path()).await;
    let x = m.tool(1, "exec", json!({"command": "echo 'it ran'", "cwd": root.path()})).await.unwrap();
    assert_eq!(x["exit"], 0);
    let found = m.tool(2, "find", json!({"kind": "tool_call"})).await.unwrap();
    let id = found[0]["id"].as_str().unwrap().to_string();
    let rec = m.tool(3, "get", json!({"id": id})).await.unwrap();
    assert_eq!(rec["body"]["command"], "echo 'it ran'");
    assert_eq!(rec["body"]["sandbox"], if cfg!(target_os = "macos") { "seatbelt" } else { "none" });
    assert_eq!(rec["body"]["network"], "deny");
    m.close().await;
    // The exec call was sealed on exit, so an auditor with only the seal sees the command.
    let s = seals(t.path());
    assert_eq!(s.len(), 1);
    let c = rusqlite::Connection::open_with_flags(&s[0], rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let body: String = c.query_row("SELECT json(body) FROM records WHERE kind = 'tool_call'", [], |r| r.get(0)).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["command"], "echo 'it ran'");
}
