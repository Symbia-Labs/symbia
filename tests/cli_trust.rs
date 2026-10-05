//! Key pinning through the real binary: `symbia verify` trusts only pinned keys,
//! `--trust` adds one for a run, `symbia trust add|list` manage the pins.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use symbia::canon::{canonical, sha256};
use symbia::seal::{read_sidecar, sidecar_path, signed_message};

const BIN: &str = env!("CARGO_BIN_EXE_symbia");

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(BIN).args(args).env("SYMBIA_HOME", home).output().unwrap()
}

fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)).trim().to_string()
}

/// A sealed session under `home`, signed by its device key.
fn sealed(home: &Path) -> PathBuf {
    let mut store = symbia::store::Store::create(home).unwrap();
    let key = symbia::keys::load_or_create(home).unwrap();
    let input = serde_json::from_value(json!({
        "key": "k", "kind": "observation", "lane": "canonical", "lane_reason": "r", "body": {"v": 1}, "model": "m"
    }))
    .unwrap();
    store.write(&input, std::time::Instant::now()).unwrap();
    symbia::seal::seal(&store, &key).unwrap().path
}

/// Replace the sidecar's key and signature with `key`'s.
fn resign_with(path: &Path, key: &SigningKey) -> String {
    let mut sc = read_sidecar(path).unwrap();
    let sha = sha256(&std::fs::read(path).unwrap());
    let head: [u8; 32] = hex::decode(&sc.chain_head).unwrap().try_into().unwrap();
    sc.public_key = hex::encode(key.verifying_key().to_bytes());
    sc.signature = hex::encode(key.sign(&signed_message(&sha, &head)).to_bytes());
    std::fs::write(sidecar_path(path), canonical(&sc).unwrap()).unwrap();
    sc.public_key
}

#[test]
fn verify_trusts_only_pinned_keys() {
    let t = tempfile::tempdir().unwrap();
    let path = sealed(t.path());
    let p = path.to_str().unwrap();
    // The device key was pinned on first use.
    let out = run(t.path(), &["verify", p]);
    assert!(out.status.success(), "{}", text(&out));

    // Re-signed with a fresh key: untrusted by default.
    let fresh = SigningKey::from_bytes(&[42u8; 32]);
    let pk = resign_with(&path, &fresh);
    let out = run(t.path(), &["verify", p]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&out.stderr), format!("untrusted key {}\n", &pk[..12]));

    // --trust admits it for this run only, before or after the path.
    let out = run(t.path(), &["verify", p, "--trust", &pk]);
    assert!(out.status.success(), "{}", text(&out));
    let out = run(t.path(), &["verify", "--trust", &pk.to_ascii_uppercase(), p]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(run(t.path(), &["verify", p]).status.code(), Some(1));

    // A malformed --trust key is a usage error.
    assert_eq!(run(t.path(), &["verify", p, "--trust", "abc"]).status.code(), Some(2));

    // Pinning it makes it trusted without the flag.
    let out = run(t.path(), &["trust", "add", &pk, "ci runner"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(text(&out), format!("added {} ci runner", &pk[..12]));
    assert_eq!(text(&run(t.path(), &["trust", "add", &pk, "again"])), format!("already trusted {} ci runner", &pk[..12]));
    assert!(run(t.path(), &["verify", p]).status.success());

    let list = text(&run(t.path(), &["trust", "list"]));
    let lines: Vec<&str> = list.lines().collect();
    assert_eq!(lines.len(), 2, "{list}");
    assert!(lines[0].ends_with(" device"), "{list}");
    assert!(lines[1].starts_with(&pk) && lines[1].ends_with(" ci runner"), "{list}");
    assert_eq!(run(t.path(), &["trust", "add", "zz", "x"]).status.code(), Some(1));
}

#[test]
fn format1_seal_verifies_through_the_cli() {
    let t = tempfile::tempdir().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let path = t.path().join("format1.sqlite");
    std::fs::copy(fixtures.join("format1.sqlite"), &path).unwrap();
    std::fs::copy(fixtures.join("format1.seal.json"), sidecar_path(&path)).unwrap();
    let pk = read_sidecar(&path).unwrap().public_key;
    let p = path.to_str().unwrap();
    assert_eq!(text(&run(t.path(), &["verify", p])), format!("untrusted key {}", &pk[..12]));
    let out = run(t.path(), &["verify", p, "--trust", &pk]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).starts_with("ok 1791244262155-f187e6f2 seq 2 "), "{}", text(&out));
}

#[test]
fn serve_refuses_non_loopback_without_allow_remote() {
    let t = tempfile::tempdir().unwrap();
    let out = run(t.path(), &["serve", "--listen", "0.0.0.0:0"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("--allow-remote"), "{}", text(&out));
    assert_eq!(run(t.path(), &["serve", "--listen"]).status.code(), Some(2));
    assert_eq!(run(t.path(), &["serve", "--listen", "nonsense"]).status.code(), Some(1));
}
