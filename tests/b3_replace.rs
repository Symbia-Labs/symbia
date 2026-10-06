//! B3 end to end over stdio MCP with the real binary, in a temp root:
//! list → search → read → write → edit → exec, then seal. Each call leaves exactly one
//! `tool_call` record, and the seal verifies.

mod common;

use std::path::Path;
use std::process::Command as StdCommand;

use common::{Client, call};
use rmcp::ServiceExt;
use rmcp::transport::TokioChildProcess;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_symbia");

async fn spawn(home: &Path) -> Client {
    let mut cmd = tokio::process::Command::new(BIN);
    cmd.arg("mcp").env("SYMBIA_HOME", home);
    ().serve(TokioChildProcess::new(cmd).unwrap()).await.unwrap()
}

async fn seq(client: &Client) -> i64 {
    call(client, "symbia_status", json!({})).await.unwrap()["seq"].as_i64().unwrap()
}

/// Raw text of a tool reply, error or not.
async fn text(client: &Client, name: &'static str, args: Value) -> (bool, String) {
    let mut p = rmcp::model::CallToolRequestParams::new(name);
    if let Value::Object(map) = args {
        p = p.with_arguments(map);
    }
    let r = client.call_tool(p).await.unwrap();
    (r.is_error != Some(true), r.content[0].as_text().unwrap().text.clone())
}

#[tokio::test]
async fn b3_replace_runs_end_to_end_and_seals() {
    let t = tempfile::tempdir().unwrap();
    let home = t.path().join("symbia");
    let root = t.path().join("work");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("config.json"), json!({"roots": [root]}).to_string()).unwrap();
    std::fs::write(root.join(".gitignore"), "target/\n").unwrap();
    std::fs::create_dir_all(root.join("target")).unwrap();
    std::fs::write(root.join("target/junk.rs"), "fn pressure() {}\n").unwrap();
    std::fs::write(root.join("src/boiler.rs"), "fn main() {\n    let pressure = 11;\n    println!(\"{pressure}\");\n}\n").unwrap();
    let r = |p: &str| root.join(p).display().to_string();

    let client = spawn(&home).await;
    let session = call(&client, "symbia_status", json!({})).await.unwrap()["session"].as_str().unwrap().to_string();
    let mut calls: Vec<&str> = Vec::new();
    let mut expect_seq = seq(&client).await;
    assert_eq!(expect_seq, 0);

    // list
    let listed = call(&client, "symbia_fs_list", json!({"path": r(""), "depth": 2})).await.unwrap();
    let paths: Vec<&str> = listed["entries"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert!(paths.contains(&"src/boiler.rs"), "{paths:?}");
    calls.push("symbia_fs_list");
    expect_seq += 1;
    assert_eq!(seq(&client).await, expect_seq);

    // search: .gitignore keeps target/ out
    let found = call(&client, "symbia_fs_search", json!({"pattern": "pressure =", "path": r(""), "literal": true, "context": 1})).await.unwrap();
    let m = &found["matches"].as_array().unwrap()[..];
    assert_eq!(m.len(), 1);
    assert_eq!((m[0]["file"].as_str(), m[0]["line"].as_u64()), (Some("src/boiler.rs"), Some(2)));
    assert_eq!(m[0]["before"], json!(["fn main() {"]));
    calls.push("symbia_fs_search");
    expect_seq += 1;
    assert_eq!(seq(&client).await, expect_seq);

    // read
    let (ok, body) = text(&client, "symbia_fs_read", json!({"path": r("src/boiler.rs"), "offset": 2, "limit": 1})).await;
    assert!(ok, "{body}");
    assert!(body.starts_with("     2\t    let pressure = 11;\n"), "{body}");
    assert!(body.contains("continue with offset 3"), "{body}");
    calls.push("symbia_fs_read");
    expect_seq += 1;
    assert_eq!(seq(&client).await, expect_seq);

    // write
    let w = call(&client, "symbia_fs_write", json!({"path": r("notes/run.md"), "content": "threshold 12 bar\n"})).await.unwrap();
    assert_eq!(w["bytes"], 17);
    assert_eq!(std::fs::read_to_string(root.join("notes/run.md")).unwrap(), "threshold 12 bar\n");
    calls.push("symbia_fs_write");
    expect_seq += 1;
    assert_eq!(seq(&client).await, expect_seq);

    // edit
    let e = call(&client, "symbia_fs_edit", json!({"path": r("notes/run.md"), "old": "12 bar", "new": "11.4 bar"})).await.unwrap();
    assert_eq!(e["line"], 1);
    assert_eq!(e["sha256_before"], w["sha256"]);
    assert_ne!(e["sha256_before"], e["sha256_after"]);
    calls.push("symbia_fs_edit");
    expect_seq += 1;
    assert_eq!(seq(&client).await, expect_seq);

    // exec
    let x = call(&client, "symbia_exec", json!({"command": "cat notes/run.md; echo warn >&2; exit 4", "cwd": r("")})).await.unwrap();
    assert_eq!(x["exit"], 4);
    assert_eq!(x["stdout"]["tail"], "threshold 11.4 bar\n");
    assert_eq!(x["stderr"]["tail"], "warn\n");
    calls.push("symbia_exec");
    expect_seq += 1;
    assert_eq!(seq(&client).await, expect_seq);

    // The full output is readable by its evidence path, though it sits outside the roots.
    let evidence = x["stdout"]["evidence"].as_str().unwrap().to_string();
    let (ok, body) = text(&client, "symbia_fs_read", json!({"path": evidence})).await;
    assert!(ok, "{body}");
    assert_eq!(body, "     1\tthreshold 11.4 bar\n");
    calls.push("symbia_fs_read");
    expect_seq += 1;

    // A refused call is recorded too.
    let (ok, body) = text(&client, "symbia_fs_read", json!({"path": home.join("keys/device.ed25519")})).await;
    assert!(!ok && body.contains("deny list"), "{body}");
    calls.push("symbia_fs_read");
    expect_seq += 1;
    assert_eq!(seq(&client).await, expect_seq);

    // seal
    let sealed = call(&client, "symbia_seal", json!({})).await.unwrap();
    assert_eq!(sealed["verified"], true);
    assert_eq!(sealed["chain_seq"], expect_seq);
    client.cancel().await.unwrap();

    let path = Path::new(sealed["path"].as_str().unwrap());
    let v = symbia::seal::verify(path).unwrap();
    assert_eq!((v.session.as_str(), v.chain_seq), (session.as_str(), expect_seq));
    let out = StdCommand::new(BIN).arg("verify").arg(path).env("SYMBIA_HOME", &home).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    // One tool_call record per call, in call order, every one on the chain.
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let rows: Vec<(String, String, String)> = c
        .prepare("SELECT r.kind, r.lane, json(r.body) FROM records r JOIN chain ch ON ch.record_id = r.id ORDER BY ch.seq")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows.len(), calls.len());
    for ((kind, lane, body), tool) in rows.iter().zip(&calls) {
        assert_eq!((kind.as_str(), lane.as_str()), ("tool_call", "apocryphal"));
        let b: Value = serde_json::from_str(body).unwrap();
        assert_eq!(b["tool"], *tool);
        assert!(b["bytes_returned"].as_u64().unwrap() > 0);
        assert!(!body.contains("threshold"), "content leaked into a record: {body}");
    }
    let exec: Value = serde_json::from_str(&rows[5].2).unwrap();
    assert_eq!(exec["exit"], 4);
    assert!(evidence.ends_with(exec["stdout_sha256"].as_str().unwrap()));
    let n: i64 = c.query_row("SELECT COUNT(*) FROM evidence", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 2);
    let missing: i64 = c.query_row("SELECT COUNT(*) FROM records WHERE host_ms IS NULL OR chars IS NULL", [], |r| r.get(0)).unwrap();
    assert_eq!(missing, 0);
}
