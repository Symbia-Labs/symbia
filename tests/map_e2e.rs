//! A MAP run end to end through the MCP tool layer of the real binary over stdio:
//! prediction, seal, result linked `results_of`, seal again; both seals verify.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use common::{Client, call, call_text};
use rmcp::ServiceExt;
use rmcp::transport::TokioChildProcess;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_symbia");

async fn spawn(home: &Path) -> Client {
    let mut cmd = tokio::process::Command::new(BIN);
    cmd.arg("mcp").env("SYMBIA_HOME", home);
    ().serve(TokioChildProcess::new(cmd).unwrap()).await.unwrap()
}

fn cli_verify(path: &Path) -> (bool, String) {
    let out = StdCommand::new(BIN).arg("verify").arg(path).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text.trim().to_string())
}

#[tokio::test]
async fn map_run_prediction_then_result() {
    let t = tempfile::tempdir().unwrap();
    let client = spawn(t.path()).await;

    let tools: Vec<String> = client.list_all_tools().await.unwrap().into_iter().map(|t| t.name.to_string()).collect();
    for name in ["symbia_status", "symbia_record", "symbia_find", "symbia_get", "symbia_seal"] {
        assert!(tools.iter().any(|t| t == name), "missing tool {name}");
    }

    let status = call(&client, "symbia_status", json!({})).await.unwrap();
    assert_eq!(status["retention"], "session");
    let session = status["session"].as_str().unwrap().to_string();
    assert!(Path::new(status["file"].as_str().unwrap()).starts_with(t.path()));

    // 1. Register the prediction before measuring.
    let pred_reply = call_text(
        &client,
        "symbia_record",
        json!({
            "key": "map.boiler.pressure",
            "kind": "prediction",
            "lane": "conditional",
            "lane_reason": "registered before measurement",
            "body": {"claim": "steady-state pressure stays below 12 bar", "threshold_bar": 12},
            "model": "claude-opus-5-5",
            "est_host_ms": 20,
            "est_chars": 120
        }),
    )
    .await;
    assert!(pred_reply.chars().count() < 300);
    let pred: Value = serde_json::from_str(&pred_reply).unwrap();
    let pred_id = pred["id"].as_str().unwrap().to_string();

    // 2. Seal with only the prediction on the chain.
    let seal1 = call(&client, "symbia_seal", json!({})).await.unwrap();
    assert_eq!(seal1["verified"], true);
    assert_eq!(seal1["chain_seq"], 1);

    // 3. Record the measured result, linked to the prediction.
    let res = call(
        &client,
        "symbia_record",
        json!({
            "key": "map.boiler.pressure.result",
            "kind": "result",
            "lane": "canonical",
            "lane_reason": "measured on the rig",
            "body": {"observed_bar": 11.4, "held": true},
            "model": "claude-opus-5-5",
            "links": [{"to_id": pred_id, "rel": "results_of"}]
        }),
    )
    .await
    .unwrap();
    let res_id = res["id"].as_str().unwrap().to_string();

    // 4. Seal again.
    let seal2 = call(&client, "symbia_seal", json!({})).await.unwrap();
    assert_eq!(seal2["verified"], true);
    assert_eq!(seal2["chain_seq"], 2);
    assert_ne!(seal1["path"], seal2["path"]);

    // The prediction sits earlier on the chain than its result.
    let p = call(&client, "symbia_get", json!({"id": pred_id})).await.unwrap();
    let r = call(&client, "symbia_get", json!({"key": "map.boiler.pressure.result"})).await.unwrap();
    assert!(p["seq"].as_i64().unwrap() < r["seq"].as_i64().unwrap());
    assert!(pred["seq"].as_i64().unwrap() < res["seq"].as_i64().unwrap());
    assert_eq!(r["links"], json!([{"to_id": pred_id, "rel": "results_of"}]));
    assert_eq!(p["linked_from"], json!([{"from_id": res_id, "rel": "results_of"}]));
    assert!(p["at_ms"].as_i64().unwrap() <= r["at_ms"].as_i64().unwrap());

    let found = call(&client, "symbia_find", json!({"query": "pressure", "kind": "prediction"})).await.unwrap();
    assert_eq!(found, json!([{"id": pred_id, "key": "map.boiler.pressure", "version": 1, "kind": "prediction", "lane": "conditional"}]));

    let status = call(&client, "symbia_status", json!({})).await.unwrap();
    assert_eq!(status["seq"], 2);
    assert_eq!(status["last_seal"]["chain_seq"], 2);

    client.cancel().await.unwrap();

    // Both seals verify, by library and by the CLI.
    let p1 = PathBuf::from(seal1["path"].as_str().unwrap());
    let p2 = PathBuf::from(seal2["path"].as_str().unwrap());
    assert_eq!(p1, t.path().join("seals").join(format!("{session}-1.sqlite")));
    assert_eq!(p2, t.path().join("seals").join(format!("{session}-2.sqlite")));
    for (path, seq) in [(&p1, 1), (&p2, 2)] {
        let v = symbia::seal::verify(path).unwrap();
        assert_eq!(v.chain_seq, seq);
        assert_eq!(v.session, session);
        let (ok, line) = cli_verify(path);
        assert!(ok, "{line}");
        assert!(line.starts_with(&format!("ok {session} seq {seq} ")), "{line}");
    }
    // The first seal holds the prediction only; the second holds both.
    let count = |p: &Path| -> i64 {
        rusqlite::Connection::open_with_flags(p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!((count(&p1), count(&p2)), (1, 2));
}

#[test]
fn cli_verify_fails_with_one_line_reason() {
    let t = tempfile::tempdir().unwrap();
    let mut store = symbia::store::Store::create(t.path()).unwrap();
    let key = symbia::keys::load_or_create(t.path()).unwrap();
    let input: symbia::record::RecordInput = serde_json::from_value(json!({
        "key": "k", "kind": "observation", "lane": "canonical", "lane_reason": "r", "body": {"v": 1}, "model": "m"
    }))
    .unwrap();
    store.write(&input, std::time::Instant::now()).unwrap();
    let sealed = symbia::seal::seal(&store, &key).unwrap();
    assert!(cli_verify(&sealed.path).0);

    let c = rusqlite::Connection::open(&sealed.path).unwrap();
    c.execute("UPDATE records SET lane = 'apocryphal'", []).unwrap();
    drop(c);
    let out = StdCommand::new(BIN).arg("verify").arg(&sealed.path).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&out.stderr), "file sha256 mismatch\n");

    let out = StdCommand::new(BIN).arg("bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
