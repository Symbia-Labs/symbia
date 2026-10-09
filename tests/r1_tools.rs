//! Tool titles and annotations as an MCP client sees them from the real binary over stdio.

mod common;

use common::Client;
use rmcp::ServiceExt;
use rmcp::transport::TokioChildProcess;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_symbia");

async fn spawn(home: &std::path::Path) -> Client {
    let mut cmd = tokio::process::Command::new(BIN);
    cmd.arg("mcp").env("SYMBIA_HOME", home);
    ().serve(TokioChildProcess::new(cmd).unwrap()).await.unwrap()
}

#[tokio::test]
async fn every_tool_has_a_title_and_annotations() {
    let t = tempfile::tempdir().unwrap();
    let client = spawn(t.path()).await;
    let tools: Vec<Value> = client.list_all_tools().await.unwrap().iter().map(|t| serde_json::to_value(t).unwrap()).collect();
    assert_eq!(tools.len(), 15);

    // (name, title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint); null = not set.
    let want = [
        ("status", "Session status", json!(true), Value::Null, Value::Null, json!(false)),
        ("find", "Find records", json!(true), Value::Null, Value::Null, json!(false)),
        ("get", "Get a record", json!(true), Value::Null, Value::Null, json!(false)),
        ("report", "Report", json!(true), Value::Null, Value::Null, json!(false)),
        ("open", "Open a seal", json!(true), Value::Null, Value::Null, json!(false)),
        ("promote", "Promote a seal", json!(false), json!(false), json!(true), json!(false)),
        ("read", "Read a file", json!(true), Value::Null, Value::Null, json!(false)),
        ("list", "List a folder", json!(true), Value::Null, Value::Null, json!(false)),
        ("search", "Search files", json!(true), Value::Null, Value::Null, json!(false)),
        ("record", "Write a record", json!(false), json!(false), json!(false), json!(false)),
        ("seal", "Seal the session", json!(false), json!(false), json!(true), json!(false)),
        ("write", "Write a file", json!(false), json!(true), json!(true), json!(false)),
        ("edit", "Edit a file", json!(false), json!(true), json!(false), json!(false)),
        ("exec", "Run a command", json!(false), json!(true), json!(false), json!(true)),
        ("job", "Check a job", json!(false), json!(true), json!(false), json!(false)),
    ];
    for (name, title, ro, destructive, idempotent, open) in want {
        let tool = tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("missing {name}"));
        let a = &tool["annotations"];
        // The rule every tool must meet: a title, and read-only or an explicit destructiveHint.
        assert!(tool["title"].as_str().is_some_and(|s| !s.is_empty()), "{name}: no title");
        assert!(a["readOnlyHint"] == true || a["destructiveHint"].is_boolean(), "{name}: neither readOnlyHint true nor destructiveHint");
        // And the values from the table.
        assert_eq!(tool["title"], title, "{name}");
        assert_eq!(a["title"], title, "{name}");
        assert_eq!(
            (&a["readOnlyHint"], &a["destructiveHint"], &a["idempotentHint"], &a["openWorldHint"]),
            (&ro, &destructive, &idempotent, &open),
            "{name}"
        );
    }
    assert!(tools.iter().all(|t| !t["name"].as_str().unwrap().starts_with("symbia_")));
    client.cancel().await.unwrap();
}

/// R11: a client holding a tool list from before the rename still reaches each tool by its old
/// name, and the call is recorded under the new one.
#[tokio::test]
async fn old_names_still_reach_their_tools() {
    let t = tempfile::tempdir().unwrap();
    let client = spawn(t.path()).await;
    let rec = json!({"key": "r11", "kind": "observation", "lane": "canonical", "lane_reason": "r11", "body": {}, "model": "m"});
    let w = common::call(&client, "symbia_record", rec).await.unwrap();
    assert_eq!(w["version"], 1);
    let status = common::call(&client, "symbia_status", json!({})).await.unwrap();
    assert_eq!(status["seq"], 1);
    common::call(&client, "symbia_report", json!({"by": "tool"})).await.unwrap();
    let hits = common::call(&client, "find", json!({"kind": "tool_call"})).await.unwrap();
    let keys: Vec<&str> = hits.as_array().unwrap().iter().map(|h| h["key"].as_str().unwrap()).collect();
    assert_eq!(keys, ["tool.report"]);
    assert!(common::call(&client, "symbia_nope", json!({})).await.is_err());
    assert!(common::call(&client, "status_", json!({})).await.is_err());
    client.cancel().await.unwrap();
}
