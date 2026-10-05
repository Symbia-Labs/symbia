# B1 part 1 report

## Built

One crate, `symbia` (lib + bin, edition 2024, Rust 1.91.1 Homebrew), as a single-member Cargo workspace.

| Module | What it does |
|---|---|
| `home` | `SYMBIA_HOME`, else `~/Library/Application Support/Symbia` (macOS) / `$XDG_DATA_HOME/symbia` (fallback `~/.local/share/symbia`). Creates `keys/` (0700), `sessions/`, `seals/`. |
| `keys` | ed25519 device key, raw 32-byte seed at `keys/device.ed25519`, created with `create_new` + mode 0600. |
| `record` | Kinds, lanes, rels; `record_id` = sha256 of RFC 8785 JSON of `{key, version, kind, lane, body, model, session}`; `chain_hash`. |
| `store` | `sessions/<id>.sqlite`, WAL, STRICT schema exactly as specified plus FTS5 `records_fts(id UNINDEXED, key, body)` and three indexes. Record, chain row, links and FTS row commit in one transaction; `host_ms` and `chars` are filled in the same transaction after the reply is formed. |
| `seal` | `wal_checkpoint(TRUNCATE)` → `VACUUM INTO seals/<session>-<seq>.sqlite` → `retention='seal'` in the copy → sha256 → sign `file_sha256 ‖ chain_head` → `<same>.seal.json` (canonical JSON, hex fields). `verify` checks, in order: sidecar, file sha256, signature, retention, chain walk from genesis (seq, prev_hash, hash), every record id recomputed, record `at_ms` and session, no records off the chain, sidecar seq and head. |
| `mcp` | rmcp stdio server, one process = one session: `symbia_status`, `symbia_record`, `symbia_find`, `symbia_get`, `symbia_seal`. Errors come back as tool errors (`isError`). |
| `main` | `symbia mcp`, `symbia verify <sealed.sqlite>` (exit 0 + `ok <session> seq N head <12>`, or exit 1 + one-line reason on stderr), `symbia --version`. |

**Body storage: JSONB.** Bundled SQLite is 3.53.2. Bodies are written as `jsonb(<canonical text>)` and read back with `json(body)`. A test checks `typeof(body) != 'text'` and `json_valid(body, 8)`. Seal tests use bodies with unicode, escapes, `0.1`, `1e21`, `-0.0` and 2^53+1 to show ids recompute the same after the JSONB round trip.

## Gate

| Check | Result |
|---|---|
| `cargo test` | 41 passed: 39 unit, 2 in `tests/map_e2e.rs` |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `tests/map_e2e.rs` | passes. It spawns the real binary over stdio with an rmcp client: prediction → seal → result `results_of` prediction → seal. Both seals verify (library and CLI), prediction seq < result seq, first seal holds 1 record, second holds 2. |
| `cargo build --release` | `target/release/symbia` (5.9 MB) |

Required tests map to: `record::tests::id_*`, `store::tests::versions_increment_per_key`, `seal::tests::tampered_*` / `rehashed_without_key_fails_signature` / `off_chain_record_is_detected`, `seal::tests::seal_round_trip_verifies`, `store::tests::fts_find_returns_expected_records`, `mcp::tests::record_reply_is_terse` (about 110 chars).

## Pinned crates

anyhow 1.0.104 · ed25519-dalek 3.0.0 · getrandom 0.4.3 · hex 0.4.3 · rmcp 3.5.1 (server, macros, schemars, transport-io; dev: client, transport-child-process) · rusqlite 0.40.2 (bundled) · schemars 1.2.2 · serde 1.0.229 · serde_jcs 0.2.0 · serde_json 1.0.151 · sha2 0.11.0 · tokio 1.53.2 · tempfile 3.27.0 (dev). Transitive versions are fixed by the committed `Cargo.lock`.

## Choices the spec left open

- Session id is `<at_ms>-<8 hex>`.
- Link targets must already exist in the session file, so a typo fails instead of leaving a dangling link.
- `symbia_find` rejects `limit > 50`. Default limit is 20. A query is split on whitespace and each term is quoted as an FTS5 phrase, so user text never parses as FTS syntax. With a query, results are ordered by bm25; without one, newest first.
- `symbia_get` returns `links` (outgoing) and `linked_from` (incoming), plus the record's chain `seq`.
- A record's `expires_ms` copies the file's `expires_ms` when it is written.
- The sealed copy is switched to `journal_mode=DELETE` before the retention write, so the seal is one self-contained file.
- Sealing again at an unchanged chain seq returns the existing seal. A copy without a sidecar (an interrupted seal) is deleted and redone.

## Not covered, and why

- **Live-file gaps.** In the live session file, the chain does not cover `lane_reason`, links, cost fields or `expires_ms`, because the spec's id excludes them. Once sealed, the file sha256 and signature cover every byte.
- **Key trust.** `verify` trusts whichever public key the sidecar names. It does not pin keys, so someone could rewrite a seal and re-sign it with their own key. Key trust needs its own step.
- **Search index.** `verify` does not check the FTS index. It is derived from the records.
- **Evidence.** The `evidence` table is created, but no B1 tool writes to it.
- **Out of scope per B1.md:** Streamable HTTP, session resume, the v1 importer, the decider, file and shell tools, routines, retrieval, the MQTT broker, and promotion.
