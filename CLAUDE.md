# symbia v2

One Rust binary, `symbia`, on SQLite. It records work as typed records in a signed, hash-chained ledger, seals session files, and serves its tools over MCP. The design brief is the claude.ai doc "Symbia v2 Brief". v1 is the TypeScript stack at ~/symbia-stack and is a read-only reference.

## Rules

- Work only inside ~/symbia-v2. Never write to ~/symbia-stack, ~/Library/Application Support/Claude, ~/Library/Application Support/Symbia, or any v1 bundle.
- Edit source files directly with the edit tool, one exact change at a time. No Python, sed or awk scripts that patch source.
- Tests use temporary directories, never the real data directory.
- Every behavior lands with a test. A step is done only when `cargo test` passes and `cargo clippy --all-targets -- -D warnings` is clean.
- Every timestamp is integer UTC milliseconds. No local time anywhere.
- Wherever a digest covers JSON, the JSON is canonical (RFC 8785).
- Vocabulary: retention values are `session`, `seal`, `ledger`. Lanes are `canonical`, `conditional`, `apocryphal`. Never use the words imagine or durable in v2 code or docs.
- Tool replies are terse and return references (id, version, seq, digest prefix), not whole records, except `symbia_get`.
- Commit at each green checkpoint with a short message.
- Pin exact crate versions in Cargo.toml.
