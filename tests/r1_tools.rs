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
    assert_eq!(tools.len(), 11);

    // (name, title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint); null = not set.
    let want = [
        ("symbia_status", "Session status", json!(true), Value::Null, Value::Null, json!(false)),
        ("symbia_find", "Find records", json!(true), Value::Null, Value::Null, json!(false)),
        ("symbia_get", "Get a record", json!(true), Value::Null, Value::Null, json!(false)),
        ("symbia_fs_read", "Read a file", json!(true), Value::Null, Value::Null, json!(false)),
        ("symbia_fs_list", "List a folder", json!(true), Value::Null, Value::Null, json!(false)),
        ("symbia_fs_search", "Search files", json!(true), Value::Null, Value::Null, json!(false)),
        ("symbia_record", "Write a record", json!(false), json!(false), json!(false), json!(false)),
        ("symbia_seal", "Seal the session", json!(false), json!(false), json!(true), json!(false)),
        ("symbia_fs_write", "Write a file", json!(false), json!(true), json!(true), json!(false)),
        ("symbia_fs_edit", "Edit a file", json!(false), json!(true), json!(false), json!(false)),
        ("symbia_exec", "Run a command", json!(false), json!(true), json!(false), json!(true)),
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
    client.cancel().await.unwrap();
}
