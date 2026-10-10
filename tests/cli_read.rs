//! `symbia show` and `symbia get` on the committed example seals, through the real binary, with
//! an empty data folder so only `--trust` pins the example key. The expected text here is what
//! the README's walkthrough shows.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_symbia");

fn ex(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples").join(p)
}

fn key() -> String {
    std::fs::read_to_string(ex("example-key.pub")).unwrap().trim().to_string()
}

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(BIN).args(args).env("SYMBIA_HOME", home).output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).trim().to_string()
}

const COMMANDS: &str = "command                                                  exit  host_ms  chars
tail -n +2 orders.csv | wc -l | tr -d ' '                0     61       225
awk -F, 'NR > 1 { s += $2 } END { print s }' orders.csv  0     45       226
";

const PREDICTIONS: &str = "prediction    verdict  claim
orders.rows   held     orders.csv holds 3 orders
orders.total  broke    the amounts sum to 100
";

#[test]
fn show_prints_the_chain_predictions_and_commands_of_a_verified_seal() {
    let t = tempfile::tempdir().unwrap();
    let o = run(t.path(), &["show", ex("seals/session.sqlite").to_str().unwrap(), "--trust", &key()]);
    assert!(o.status.success(), "{}", err(&o));
    let want = format!(
        "ok 1791560407633-0e8022e0 seq 9 head ec1ea4fc7103

seq  thread   kind         lane         key
1    agent-a  tool_call    apocryphal   tool.write
2    agent-a  prediction   canonical    orders.rows
3    agent-a  prediction   canonical    orders.total
4    agent-a  tool_call    apocryphal   tool.exec
5    agent-a  tool_call    apocryphal   tool.exec
6    agent-a  result       canonical    orders.rows.result
7    agent-a  result       canonical    orders.total.result
8    agent-b  tool_call    apocryphal   tool.search
9    agent-b  observation  conditional  review.orders

{PREDICTIONS}
{COMMANDS}"
    );
    assert_eq!(out(&o), want);
}

#[test]
fn show_marks_what_a_thread_seal_withholds() {
    let t = tempfile::tempdir().unwrap();
    let o = run(t.path(), &["show", ex("seals/agent-a.sqlite").to_str().unwrap(), "--trust", &key()]);
    assert!(o.status.success(), "{}", err(&o));
    let text = out(&o);
    assert!(text.starts_with("ok 1791560407633-0e8022e0 seq 9 head ec1ea4fc7103 thread agent-a: 7 records, 2 withheld\n\n"), "{text}");
    assert!(text.contains("\n8                                     (withheld)\n9                                     (withheld)\n"), "{text}");
    assert!(!text.contains("review.orders"), "{text}");
    assert!(text.ends_with(&format!("{PREDICTIONS}\n{COMMANDS}")), "{text}");
}

#[test]
fn show_and_get_refuse_a_seal_that_fails() {
    let t = tempfile::tempdir().unwrap();
    let k = key();
    for (seal, reason) in [("seals/tampered.sqlite", "file sha256 mismatch"), ("seals/tampered-rehashed.sqlite", "signature invalid")] {
        let p = ex(seal);
        for args in [vec!["show", p.to_str().unwrap(), "--trust", &k], vec!["get", p.to_str().unwrap(), "review.orders", "--trust", &k]] {
            let o = run(t.path(), &args);
            assert_eq!(o.status.code(), Some(1), "{args:?}");
            assert_eq!(err(&o), reason, "{args:?}");
            assert_eq!(out(&o), "", "{args:?}");
        }
    }
    // Without --trust, the example key isn't pinned.
    let o = run(t.path(), &["show", ex("seals/session.sqlite").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(err(&o), "untrusted key 489024d5d267");
}

#[test]
fn get_prints_one_record_in_full_by_key_or_id() {
    let t = tempfile::tempdir().unwrap();
    let seal = ex("seals/session.sqlite");
    let o = run(t.path(), &["get", seal.to_str().unwrap(), "orders.total.result", "--trust", &key()]);
    assert!(o.status.success(), "{}", err(&o));
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(r["body"], serde_json::json!({"held": false, "note": "the amounts sum to 90, not 100", "total": 90}));
    assert_eq!((r["thread"].as_str(), r["seq"].as_i64()), (Some("agent-a"), Some(7)));
    assert_eq!(r["links"][0]["rel"], "results_of");

    // The same record by its id, and the prediction it answers, which links back.
    let by_id = run(t.path(), &["get", seal.to_str().unwrap(), r["id"].as_str().unwrap(), "--trust", &key()]);
    assert_eq!(by_id.stdout, o.stdout);
    let p = run(t.path(), &["get", seal.to_str().unwrap(), r["links"][0]["to_id"].as_str().unwrap(), "--trust", &key()]);
    let p: serde_json::Value = serde_json::from_slice(&p.stdout).unwrap();
    assert_eq!((p["key"].as_str(), p["linked_from"][0]["from_id"].as_str()), (Some("orders.total"), r["id"].as_str()));

    // A thread seal doesn't hold another thread's records.
    let o = run(t.path(), &["get", ex("seals/agent-a.sqlite").to_str().unwrap(), "review.orders", "--trust", &key()]);
    assert_eq!((o.status.code(), err(&o)), (Some(1), "no record review.orders in this seal".to_string()));
}

#[test]
fn show_and_get_take_their_arguments_in_any_order_and_refuse_others() {
    let t = tempfile::tempdir().unwrap();
    let seal = ex("seals/session.sqlite");
    let k = key();
    assert!(run(t.path(), &["show", "--trust", &k, seal.to_str().unwrap()]).status.success());
    assert!(run(t.path(), &["get", "--trust", &k, seal.to_str().unwrap(), "orders.rows"]).status.success());
    for args in [vec!["show"], vec!["show", "a", "b"], vec!["get", seal.to_str().unwrap()], vec!["show", seal.to_str().unwrap(), "--witness", "w"]] {
        assert_eq!(run(t.path(), &args).status.code(), Some(2), "{args:?}");
    }
    assert_eq!(run(t.path(), &["show", seal.to_str().unwrap(), "--trust", "zz"]).status.code(), Some(2));
}
