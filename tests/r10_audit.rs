//! R10 over stdio: record, promote with confirm, the witness file, opening the ledger copy, and
//! the CLI's `--witness` check, including a rollback the witness catches.

mod common;

use common::stdio::{BIN, Mcp};
use serde_json::json;

fn verify(home: &std::path::Path, file: &str, witness: &std::path::Path) -> (bool, String, String) {
    let out = std::process::Command::new(BIN).args(["verify", file, "--witness"]).arg(witness).env("SYMBIA_HOME", home).output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[tokio::test]
async fn promote_witness_and_open_over_stdio() {
    let t = tempfile::tempdir().unwrap();
    let home = t.path().join("sym");
    let wdir = t.path().join("witness");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("config.json"), json!({"witness": wdir}).to_string()).unwrap();
    let mut m = Mcp::start(&home).await;
    let rec = json!({"key": "audit.note", "kind": "observation", "lane": "canonical", "lane_reason": "r10", "body": {"text": "boiler two serviced"}, "model": "m"});
    m.tool(1, "record", rec).await.unwrap();
    let p = m.tool(2, "promote", json!({"confirm": true})).await.unwrap();
    assert_eq!((p["promoted"].as_bool(), p["ledger_seq"].as_i64()), (Some(true), Some(1)), "{p}");
    let first_seal = p["seal"].as_str().unwrap().to_string();
    let copy = home.join("ledger").join(std::path::Path::new(&first_seal).file_name().unwrap());
    let opened = m.tool(3, "open", json!({"path": copy})).await.unwrap();
    assert_eq!((opened["verified"].as_bool(), opened["witness"].as_str()), (Some(true), Some("ok (1 entries)")), "{opened}");
    assert_eq!(opened["list"][0]["key"], "audit.note");
    m.tool(4, "record", json!({"key": "audit.later", "kind": "observation", "lane": "canonical", "lane_reason": "r10", "body": {}, "model": "m"})).await.unwrap();
    m.close().await;

    // The exit seal is the newest; it checks out against the witness.
    let mut seals: Vec<_> = std::fs::read_dir(home.join("seals")).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "sqlite") && !p.to_string_lossy().contains("ledger")).collect();
    seals.sort();
    let newest = seals.iter().max_by_key(|p| std::fs::metadata(p).unwrap().modified().unwrap()).unwrap().display().to_string();
    let (ok, out, err) = verify(&home, &newest, &wdir);
    assert!(ok, "{out}{err}");
    assert!(out.lines().any(|l| l.starts_with("witness ok (")), "{out}");
    // The first seal, offered on its own, is behind what the witness saw: a rollback.
    let (ok, out, _) = verify(&home, &first_seal, &wdir);
    assert!(ok);
    assert!(out.contains("witness behind (seen seq"), "{out}");
    // The witness file names the session, the ledger, and each seal's reason.
    let lines = std::fs::read_to_string(wdir.join("witness.jsonl")).unwrap();
    assert!(lines.contains("\"reason\":\"explicit\"") && lines.contains("\"reason\":\"ledger\"") && lines.contains("\"reason\":\"exit\""), "{lines}");
}
