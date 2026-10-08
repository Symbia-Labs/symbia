//! R9 over stdio: a find across two sessions, and a report over both.

mod common;

use common::stdio::Mcp;
use serde_json::{Value, json};

fn rec(key: &str, kind: &str, body: Value) -> Value {
    json!({"key": key, "kind": kind, "lane": "canonical", "lane_reason": "r9", "body": body, "model": "m"})
}

#[tokio::test]
async fn find_and_report_across_sessions() {
    let t = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("config.json"), r#"{"resume_window_ms": 0}"#).unwrap();
    let mut a = Mcp::start(t.path()).await;
    let p = a.tool(1, "symbia_record", rec("valve.prediction", "prediction", json!({"text": "the relief valve lifts at 15 bar"}))).await.unwrap();
    let first = a.tool(2, "symbia_status", json!({})).await.unwrap()["session"].as_str().unwrap().to_string();
    a.close().await;

    let mut b = Mcp::start(t.path()).await;
    let mut r = rec("valve.result", "result", json!({"held": false, "text": "lifted at 13.5 bar"}));
    r["links"] = json!([{"to_id": p["id"], "rel": "results_of"}]);
    b.tool(3, "symbia_record", r).await.unwrap();
    assert_eq!(b.tool(4, "symbia_find", json!({"query": "relief valve"})).await.unwrap(), json!([]));
    let all = b.tool(5, "symbia_find", json!({"query": "relief valve", "scope": "all"})).await.unwrap();
    assert_eq!((all[0]["key"].as_str(), all[0]["session"].as_str()), (Some("valve.prediction"), Some(first.as_str())), "{all}");

    let rep = b.tool(6, "symbia_report", json!({"scope": "all", "by": "kind"})).await.unwrap();
    assert_eq!(rep["sessions"], 2, "{rep}");
    assert_eq!(rep["predictions"], json!({"records": 1, "with_results": 1, "open": 0, "held": 0, "broke": 1}));
    let kinds: Vec<&str> = rep["groups"].as_array().unwrap().iter().map(|g| g["group"].as_str().unwrap()).collect();
    for k in ["prediction", "result", "tool_call"] {
        assert!(kinds.contains(&k), "{kinds:?}");
    }
    // A stale client sends a boolean as a string; it is read as the boolean.
    let st = b.tool(7, "symbia_find", json!({"scope": "all", "kind": "prediction", "limit": "5"})).await.unwrap();
    assert_eq!(st.as_array().unwrap().len(), 1);
    assert!(t.path().join("index.sqlite").exists());
    b.close().await;
}
