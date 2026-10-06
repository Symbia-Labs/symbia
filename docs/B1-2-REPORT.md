# B1 part 2 report

## Built

| Area | What it does |
|---|---|
| Chain format 2 | `file_meta` gains `format INTEGER NOT NULL` (new files: 2) and `mcp_session_id TEXT`. `row_digest` = sha256 of RFC 8785 JSON of `{id, key, version, kind, lane, lane_reason, body, model, session, at_ms, expires_ms, est_host_ms, est_chars, links}`, links sorted by `(to_id, rel)`, nulls as JSON null. `hash = sha256(prev_hash ‖ row_digest ‖ at_ms BE8)`. |
| `verify` | Dispatches on `format`; a missing column means 1, and format 1 uses the part 1 rule. Format 2 recomputes every row digest. Both formats now also require non-null `host_ms`/`chars` and reject links whose `from_id` is not on the chain. Unknown formats fail. |
| Key pinning (`trust`) | `keys/trusted.json` holds `[{public_key, label, added_ms}]` as canonical JSON, written to a temp file then renamed. `keys::load_or_create` pins the device key as `device`. `symbia verify` trusts only pinned keys and exits 1 with `untrusted key <12 hex>`; `--trust <hex>` (repeatable) adds a key for that run. `symbia trust add <hex> <label>` and `symbia trust list`. |
| `symbia serve` (`http`) | rmcp `StreamableHttpService` on hyper http1 at `/mcp` (other paths 404). Default `127.0.0.1:7341`. A non-loopback address exits 1 unless `--allow-remote` is given. |
| Session mapping | One `SymbiaServer` per MCP session. Its file is created the first time a message carrying `Mcp-Session-Id` arrives, either `notifications/initialized` or a tool call, because rmcp does not guarantee their order. The id is written to `file_meta.mcp_session_id`. |
| Expiry | `ExpiringSessions` wraps rmcp's `LocalSessionManager`. At the file's `expires_ms`, `has_session` closes the session and returns false, so the client gets 404. Idle keep-alive is raised from 5 min to the 24 h TTL, so a dropped client can come back. |
| `symbia_status` | Adds `mcp_session_id` (null on stdio) and `expires_ms`. Stdio (`symbia mcp`) is unchanged. |

## Gate

| Check | Result |
|---|---|
| `cargo test` | 63 passed: 56 unit, 3 `cli_trust`, 2 `map_e2e`, 2 `s1_resume` |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `tests/s1_resume.rs` | passes, 5 of 5 repeat runs. The real binary runs on a free port. The client is raw hyper over one TCP connection, so dropping the client closes the socket. Steps: initialize, record (seq 1), drop the connection, reconnect on a new socket with the same id, record (seq 2). Checks: one file; chain seq 1→2; row 2's `prev_hash` equals row 1's `hash`; `mcp_session_id` matches. The session also seals and verifies. A second client gets its own file. An unknown id or a deleted session gets 404. |
| `cargo build --release` | `target/release/symbia` (8.6 MB) |

Required tests map to: `seal::tests::tampered_write_time_fields_fail_chain_hash` (lane_reason, link rel, link to_id, expires_ms, est_host_ms, est_chars), `seal::tests::format1_seal_still_verifies`, `cli_trust::format1_seal_verifies_through_the_cli`, `cli_trust::verify_trusts_only_pinned_keys` (a fresh-key re-sign fails as untrusted and passes with `--trust`), and `s1_resume::s1_resume_continues_the_same_file_and_chain`.

**Format 1 fixture.** `tests/fixtures/format1.{sqlite,seal.json}` was produced by the part 1 code at `95f5fd4`, before any part 2 change. It has 2 records and a `results_of` link.

**Test change.** `store::tests::chain_links_each_write_to_the_last` now checks the format 2 hash. Every part 1 seal tamper test still passes with its original message. The CLI tests in `map_e2e` now set `SYMBIA_HOME`, because `verify` reads the pins from there.

## Pinned crates (new)

bytes 1.12.1 · futures 0.3.34 · http 1.5.0 · http-body-util 0.1.5 · hyper 1.11.1 (server, http1; dev: client) · hyper-util 0.1.20 (tokio, service). rmcp gains `transport-streamable-http-server`; tokio gains `net`, `signal`.

## Choices the spec left open

- **Protocol cap over HTTP.** rmcp 3.5.1 serves protocol `2026-07-28` statelessly, because SEP-2567 removed sessions from it. So over HTTP the server advertises versions up to `2025-11-25`. A request that arrives without a session has no file, and every tool returns `no session: …`. Stdio still offers every version.
- `--allow-remote` adds the bound IP to rmcp's `Host` allow-list. A wildcard bind (`0.0.0.0`) turns the check off. Clients that connect by hostname need a future flag.
- `trust add` on a key that is already pinned leaves its entry and label unchanged and prints `already trusted`.
- When verifying format 2, the chain row's `at_ms` stands in for the record's; the two are then compared. This keeps every part 1 tamper message as it was.
- `--listen 127.0.0.1:0` picks a free port. The bound URL is printed on stderr as `symbia serve: http://<addr>/mcp`.

## Server restart (out of scope; observed, not designed)

MCP sessions live only in the server's memory. After a restart, a client that sends its old `Mcp-Session-Id` gets **404**. Under the MCP spec the client must then initialize again, which opens a **new** session file and a new chain from genesis. The old file stays in `sessions/` with its chain intact. It can still be sealed later, but nothing will resume it. `s1_resume::server_restart_ends_sessions_but_keeps_their_files` checks all of this.

## Not covered, and why

- **Live-file cost fields.** `host_ms`/`chars` stay outside the live chain, as specified. Only the seal covers them.
- **Expiry granularity.** Expiry is checked when a request arrives. An idle expired session holds its SQLite handle until the 24 h keep-alive fires.
- **Concurrent `trust add`** from two processes can lose one write: there is no file lock. The rename prevents a torn file.
- **Out of scope per B1-2.md:** the v1 importer, the decider, file and shell tools, routines, retrieval, the MQTT broker, and promotion.
