//! Generates `examples/`: real seals from a short run of two agents, signed by a throwaway key.
//! Ignored in the normal suite. It writes to `target/examples-out` (or `SYMBIA_EXAMPLES_OUT`, an
//! empty or missing folder); copy that over `examples/`, then run the suite: `tests/examples.rs`
//! checks what was committed.
//!
//!     cargo test --test make_examples -- --ignored

mod common;

use std::path::{Path, PathBuf};

use common::stdio::Mcp;
use serde_json::{Value, json};

const MODEL: &str = "example-agent";

/// The server plus a running request id.
struct Agent {
    m: Mcp,
    id: i64,
}

impl Agent {
    async fn call(&mut self, thread: &str, name: &str, mut args: Value) -> Value {
        self.id += 1;
        args["thread"] = thread.into();
        self.m.tool(self.id, name, args).await.unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    async fn record(&mut self, thread: &str, key: &str, (kind, lane): (&str, &str), reason: &str, body: Value, links: Value) -> String {
        let args = json!({"key": key, "kind": kind, "lane": lane, "lane_reason": reason, "body": body, "model": MODEL, "links": links});
        self.call(thread, "record", args).await["id"].as_str().unwrap().to_string()
    }
}

fn copy_seal(from: &Path, to_dir: &Path, name: &str) -> PathBuf {
    let to = to_dir.join(format!("{name}.sqlite"));
    std::fs::copy(from, &to).unwrap();
    std::fs::copy(from.with_extension("seal.json"), to_dir.join(format!("{name}.seal.json"))).unwrap();
    to
}

fn sha_hex(p: &Path) -> String {
    hex::encode(symbia::canon::sha256(&std::fs::read(p).unwrap()))
}

#[tokio::test]
#[ignore = "writes examples to SYMBIA_EXAMPLES_OUT"]
async fn make_examples() {
    let out = match std::env::var("SYMBIA_EXAMPLES_OUT") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            // The default lives under target/, so it is ours to clear.
            let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/examples-out");
            if p.exists() {
                std::fs::remove_dir_all(&p).unwrap();
            }
            p
        }
    };
    assert!(!out.exists() || std::fs::read_dir(&out).unwrap().next().is_none(), "{} is not empty", out.display());
    let t = tempfile::tempdir().unwrap();
    let (home, work) = (t.path().join("home"), t.path().join("work"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    let work = std::fs::canonicalize(&work).unwrap();
    let witness = out.join("witness");
    std::fs::write(home.join("config.json"), json!({"roots": [&work], "witness": &witness, "resume_window_ms": 0}).to_string()).unwrap();

    let mut a = Agent { m: Mcp::start_as(&home, &[], MODEL).await, id: 0 };
    let csv = work.join("orders.csv");

    // agent-a writes a small file, predicts what it holds, measures it, and records the results.
    a.call("agent-a", "write", json!({"path": &csv, "content": "order,amount\nA-100,40\nA-101,35\nA-102,15\n"})).await;
    let p_rows = a.record("agent-a", "orders.rows", ("prediction", "canonical"), "registered before counting", json!({"claim": "orders.csv holds 3 orders"}), json!(null)).await;
    let p_total = a.record("agent-a", "orders.total", ("prediction", "canonical"), "registered before summing", json!({"claim": "the amounts sum to 100"}), json!(null)).await;
    let rows = a.call("agent-a", "exec", json!({"command": "tail -n +2 orders.csv | wc -l | tr -d ' '", "cwd": &work})).await;
    assert_eq!(rows["stdout"]["tail"], "3\n", "{rows}");
    let total = a.call("agent-a", "exec", json!({"command": "awk -F, 'NR > 1 { s += $2 } END { print s }' orders.csv", "cwd": &work})).await;
    assert_eq!(total["stdout"]["tail"], "90\n", "{total}");
    a.record("agent-a", "orders.rows.result", ("result", "canonical"), "counted by the exec call", json!({"held": true, "rows": 3}), json!([{"to_id": p_rows, "rel": "results_of"}])).await;
    a.record("agent-a", "orders.total.result", ("result", "canonical"), "summed by the exec call", json!({"held": false, "total": 90, "note": "the amounts sum to 90, not 100"}), json!([{"to_id": p_total, "rel": "results_of"}])).await;

    // agent-b reviews the same file in a thread of its own.
    a.call("agent-b", "search", json!({"path": &work, "pattern": "A-102", "literal": true})).await;
    a.record("agent-b", "review.orders", ("observation", "conditional"), "a reviewer's note, not yet checked", json!({"text": "A-102 looks low; ask whether a line is missing"}), json!(null)).await;

    // One seal of agent-a's thread alone, then a full seal of the session.
    let thread = a.call("agent-a", "seal", json!({"in_thread": "agent-a"})).await;
    let full = a.call("main", "seal", json!({})).await;
    a.m.close().await;

    let seals = out.join("seals");
    std::fs::create_dir_all(&seals).unwrap();
    let session = copy_seal(Path::new(full["path"].as_str().unwrap()), &seals, "session");
    copy_seal(Path::new(thread["path"].as_str().unwrap()), &seals, "agent-a");

    // The signer's public key, for --trust.
    let sidecar: Value = serde_json::from_slice(&std::fs::read(session.with_extension("seal.json")).unwrap()).unwrap();
    std::fs::write(out.join("example-key.pub"), format!("{}\n", sidecar["public_key"].as_str().unwrap())).unwrap();

    // The commands' saved output, named by sha256.
    let evidence = out.join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    for e in std::fs::read_dir(home.join("evidence")).unwrap().flatten() {
        std::fs::copy(e.path(), evidence.join(e.file_name())).unwrap();
    }

    // Tampered: the reviewer's note moved to the canonical lane after the seal. The file no longer
    // matches the hash the sidecar signed.
    let tampered = copy_seal(&session, &seals, "tampered");
    let c = rusqlite::Connection::open(&tampered).unwrap();
    assert_eq!(c.execute("UPDATE records SET lane = 'canonical' WHERE key = 'review.orders'", []).unwrap(), 1);
    drop(c);
    // Tampered and re-hashed: the sidecar now names the edited file's hash, so the signature fails.
    let resealed = copy_seal(&tampered, &seals, "tampered-rehashed");
    let side = resealed.with_extension("seal.json");
    let mut sc: Value = serde_json::from_slice(&std::fs::read(&side).unwrap()).unwrap();
    sc["file_sha256"] = sha_hex(&resealed).into();
    std::fs::write(&side, sc.to_string()).unwrap();
    println!("examples written to {}", out.display());
}
