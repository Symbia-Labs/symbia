//! R3, through the real binary: seal before shutdown, checkpoint seals, links across a server
//! restart, and exec command rules imported from Claude Code's settings.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::stdio::{BIN, Mcp, seals};
use serde_json::{Value, json};

fn record(key: &str, kind: &str) -> Value {
    json!({"key": key, "kind": kind, "lane": "canonical", "lane_reason": "r3", "body": {"k": key}, "model": "m"})
}

fn cli_verify(home: &Path, seal: &Path) -> (bool, String) {
    let out = std::process::Command::new(BIN).arg("verify").arg(seal).env("SYMBIA_HOME", home).output().unwrap();
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[tokio::test]
async fn sigterm_seals_within_one_second() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    m.tool(1, "symbia_record", record("before.term", "observation")).await.unwrap();
    assert!(seals(t.path()).is_empty());
    let pid = i32::try_from(m.child.id().unwrap()).unwrap();
    let sent = Instant::now();
    // SAFETY: signals our own child.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let sealed = loop {
        if let Some(s) = seals(t.path()).first().filter(|s| symbia::seal::verify(s).is_ok()) {
            break s.clone();
        }
        assert!(sent.elapsed() < Duration::from_secs(1), "no verified seal 1 s after SIGTERM");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let (ok, line) = cli_verify(t.path(), &sealed);
    assert!(ok && line.contains(" seq 1 "), "{line}");
    let status = tokio::time::timeout(Duration::from_secs(20), m.child.wait()).await.unwrap().unwrap();
    assert!(status.success(), "{status:?}");
    assert_eq!(seals(t.path()).len(), 1, "the post-drain seal found nothing new");
}

#[tokio::test]
async fn fifty_records_and_a_prediction_make_checkpoint_seals() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    for i in 1..=50 {
        m.tool(i, "symbia_record", record(&format!("k{i}"), "observation")).await.unwrap();
    }
    assert_eq!(seals(t.path()).len(), 1);
    m.tool(51, "symbia_record", record("p", "prediction")).await.unwrap();
    let s = seals(t.path());
    assert_eq!(s.len(), 2);
    assert!(s.iter().all(|p| cli_verify(t.path(), p).0));
    // Sealed at its head: EOF adds no seal.
    m.close().await;
    assert_eq!(seals(t.path()).len(), 2);
}

#[tokio::test]
async fn a_result_links_to_a_prediction_from_before_the_restart() {
    let t = tempfile::tempdir().unwrap();
    let mut a = Mcp::start(t.path()).await;
    let pred = a.tool(1, "symbia_record", record("map.p", "prediction")).await.unwrap();
    let a_status = a.tool(2, "symbia_status", json!({})).await.unwrap();
    a.close().await;

    let mut b = Mcp::start(t.path()).await;
    let b_status = b.tool(1, "symbia_status", json!({})).await.unwrap();
    assert_ne!(a_status["session"], b_status["session"]);
    assert!(b_status["session_started_ms"].as_i64().unwrap() >= a_status["session_started_ms"].as_i64().unwrap());

    let mut res = record("map.r", "result");
    res["links"] = json!([{"to_id": pred["id"], "rel": "results_of"}]);
    let r = b.tool(2, "symbia_record", res).await.unwrap();
    let got = b.tool(3, "symbia_get", json!({"id": r["id"]})).await.unwrap();
    assert_eq!(got["links"], json!([{"to_id": pred["id"], "rel": "results_of", "to_session": a_status["session"]}]));

    let mut bad = record("map.r2", "result");
    bad["links"] = json!([{"to_id": "0".repeat(64), "rel": "results_of"}]);
    let e = b.tool(4, "symbia_record", bad).await.unwrap_err();
    assert!(e.contains("not found"), "{e}");

    let s = b.tool(5, "symbia_seal", json!({})).await.unwrap();
    b.close().await;
    let (ok, out) = cli_verify(t.path(), Path::new(s["path"].as_str().unwrap()));
    assert!(ok, "{out}");
    let want = format!(
        "external {} results_of {} session {}",
        &r["id"].as_str().unwrap()[..12],
        &pred["id"].as_str().unwrap()[..12],
        a_status["session"].as_str().unwrap()
    );
    assert!(out.lines().any(|l| l == want), "{out}");
}

#[tokio::test]
async fn exec_refuses_commands_matching_imported_claude_rules() {
    let t = tempfile::tempdir().unwrap();
    let home = t.path().join("home");
    let root = t.path().join("root");
    let sym = t.path().join("sym");
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&sym).unwrap();
    std::fs::write(home.join(".claude/settings.json"), r#"{"permissions": {"deny": ["Bash(chmod:*)"]}}"#).unwrap();
    std::fs::write(sym.join("config.json"), json!({"roots": [root]}).to_string()).unwrap();
    let mut m = Mcp::start_with(&sym, &[("HOME", &home)]).await;
    let cwd = root.display().to_string();
    let e = m.tool(1, "symbia_exec", json!({"command": "mkdir x && chmod 600 x", "cwd": cwd})).await.unwrap_err();
    assert!(e.contains("chmod:*") && e.contains(".claude/settings.json"), "{e}");
    assert!(!root.join("x").exists());
    let ok = m.tool(2, "symbia_exec", json!({"command": "echo \"a && chmod\"", "cwd": cwd})).await.unwrap();
    assert_eq!(ok["stdout"]["tail"], "a && chmod\n");
    assert!(ok.get("stderr").is_none(), "{ok}");
    // The refused call is recorded with its command and error.
    let found = m.tool(3, "symbia_find", json!({"kind": "tool_call"})).await.unwrap();
    let oldest = found.as_array().unwrap().last().unwrap()["id"].clone();
    let rec = m.tool(4, "symbia_get", json!({"id": oldest})).await.unwrap();
    assert_eq!(rec["body"]["command"], "mkdir x && chmod 600 x");
    assert_eq!(rec["body"]["error"], e);
    m.close().await;
}
