//! R8: threads over stdio. The `thread` argument on any tool, the refusal of a bad name, `_meta`
//! key names on tool_call records, a thread seal, and the CLI's verify line for it.

mod common;

use common::stdio::{BIN, Mcp};
use serde_json::{Value, json};

fn rec(key: &str, thread: &str, body: Value) -> Value {
    json!({"key": key, "kind": "observation", "lane": "canonical", "lane_reason": "r8", "body": body, "model": "m", "thread": thread})
}

#[tokio::test]
async fn threads_over_stdio() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    m.tool(1, "symbia_record", rec("a1", "chat-a", json!({"text": "alpha"}))).await.unwrap();
    m.tool(2, "symbia_record", rec("b1", "chat-b", json!({"text": "SECRET-r8-bravo"}))).await.unwrap();
    m.tool(3, "symbia_record", rec("a2", "chat-a", json!({"text": "alpha two"}))).await.unwrap();
    let st = m.tool(4, "symbia_status", json!({})).await.unwrap();
    assert_eq!(st["thread"], "main");
    assert_eq!(st["threads"].as_array().unwrap().len(), 2);

    // A bad name is refused before the tool runs; the refusal is recorded in main.
    let e = m.tool(5, "symbia_record", rec("x", "a b", json!(0))).await.unwrap_err();
    assert_eq!(e, "thread must be 1-64 characters from A-Z a-z 0-9 . _ : -");
    let found = m.tool(6, "symbia_find", json!({"kind": "tool_call", "in_thread": "main"})).await.unwrap();
    assert_eq!(found.as_array().unwrap().len(), 1, "{found}");
    assert!(m.tool(7, "symbia_find", json!({"key_prefix": "x"})).await.unwrap().as_array().unwrap().is_empty());

    // `_meta` key names, not values, land on the tool_call record.
    let list = json!({"path": t.path().join("seals"), "thread": "chat-a"});
    m.send(json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
        "params": {"name": "symbia_fs_list", "arguments": list, "_meta": {"progressToken": 8, "example/chat": "c-1"}}}))
        .await;
    m.reply(8).await;
    let found = m.tool(9, "symbia_find", json!({"kind": "tool_call", "in_thread": "chat-a"})).await.unwrap();
    let call = m.tool(10, "symbia_get", json!({"id": found[0]["id"]})).await.unwrap();
    assert_eq!(call["body"]["client_meta_keys"], json!(["example/chat", "progressToken"]));
    assert!(!call.to_string().contains("c-1"));

    // Seal chat-a: a1, a2 and the listing are kept; b1, the refusal and three finds (recorded in main) are withheld.
    let s = m.tool(11, "symbia_seal", json!({"in_thread": "chat-a"})).await.unwrap();
    assert_eq!((s["records"].as_i64(), s["withheld"].as_i64(), s["verified"].as_bool()), (Some(3), Some(5), Some(true)), "{s}");
    let path = s["path"].as_str().unwrap().to_string();
    let out = std::process::Command::new(BIN).args(["verify", &path]).env("SYMBIA_HOME", t.path()).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let line = String::from_utf8_lossy(&out.stdout);
    assert!(line.trim_end().ends_with("thread chat-a: 3 records, 5 withheld"), "{line}");
    assert!(!std::fs::read(&path).unwrap().windows(15).any(|w| w == b"SECRET-r8-bravo"));

    // Every tool in the list takes `thread`.
    m.send(json!({"jsonrpc": "2.0", "id": 12, "method": "tools/list"})).await;
    let l = m.reply(12).await;
    let tools = l["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 13);
    for tool in tools {
        assert!(tool["inputSchema"]["properties"]["thread"].is_object(), "{}", tool["name"]);
    }
    m.close().await;
}
