//! The committed `examples/` still say what `examples/README.md` says they do. Regenerate them with
//! `tests/make_examples.rs` when the file format changes.

use std::path::{Path, PathBuf};

fn ex(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples").join(p)
}

fn key() -> Vec<String> {
    vec![std::fs::read_to_string(ex("example-key.pub")).unwrap().trim().to_string()]
}

#[test]
fn the_session_and_thread_seals_verify_against_the_example_key_and_witness() {
    let entries = symbia::witness::read(&symbia::witness::file_of(&ex("witness"))).unwrap();
    let full = symbia::seal::verify_trusted(&ex("seals/session.sqlite"), &key()).unwrap();
    assert_eq!((full.thread.as_deref(), full.records, full.withheld), (None, 9, 0));
    let w = symbia::witness::check(&ex("seals/session.sqlite"), &full.session, full.chain_seq, &entries).unwrap();
    assert_eq!(w.describe(), format!("ok ({} entries)", entries.len()));

    let thread = symbia::seal::verify_trusted(&ex("seals/agent-a.sqlite"), &key()).unwrap();
    assert_eq!((thread.thread.as_deref(), thread.records, thread.withheld), (Some("agent-a"), 7, 2));
    assert_eq!((thread.session, thread.chain_seq, thread.chain_head), (full.session, full.chain_seq, full.chain_head));
}

#[test]
fn the_tampered_copies_fail_where_the_readme_says() {
    assert_eq!(symbia::seal::verify_trusted(&ex("seals/tampered.sqlite"), &key()).unwrap_err(), "file sha256 mismatch");
    assert_eq!(symbia::seal::verify_trusted(&ex("seals/tampered-rehashed.sqlite"), &key()).unwrap_err(), "signature invalid");
    assert!(symbia::seal::verify_trusted(&ex("seals/session.sqlite"), &[]).unwrap_err().starts_with("untrusted key "));
}

#[test]
fn each_evidence_file_is_named_by_its_sha256() {
    let mut n = 0;
    for e in std::fs::read_dir(ex("evidence")).unwrap().flatten() {
        let bytes = std::fs::read(e.path()).unwrap();
        assert_eq!(hex::encode(symbia::canon::sha256(&bytes)), e.file_name().to_string_lossy());
        n += 1;
    }
    assert!(n >= 2);
}
