# R8 report

**What changed**

- **Threads.** Every tool takes an optional `thread`. `call_tool` removes it from the arguments before dispatch and holds it, with the request's `_meta` key names, in a task-local for the call. Tool argument structs and `args_digest` are unchanged.
  - `tools/list` is now served by `SymbiaServer::tools()`, which adds `thread` to every schema.
  - An invalid name is refused before the tool runs and recorded as a `tool_call` in `main`.
  - These records carry the call's thread: `symbia_record` writes, `tool_call` records (with `client_meta_keys` when the client sent `_meta`), and a job's end record, which takes the starting call's thread.
- **File format 3.**
  - `chain` gains `thread`, `thread_sha256` and `row_digest`; `file_meta` gains `thread`; there's an index on `chain (thread)`.
  - Chain hash v3: `sha256(prev || row_digest || at_ms_be || thread_sha256)`. The row digest is unchanged.
  - Format 1 and 2 seals verify as before; a format-2 fixture made by the R7 binary is now in `tests/fixtures`.
  - Older session files are never resumed (`older file format`).
- **Reading.**
  - `symbia_find` takes `in_thread`, and hits carry `thread`.
  - `symbia_get` returns `thread`.
  - `symbia_status` adds `thread`, `threads` (newest 20 with counts) and `new_thread`.
- **Thread seals.** `symbia_seal {in_thread}` copies the session. In the copy, every other thread's row is reduced to its chain row plus row digest, and its records, links and full-text rows are deleted. Evidence rows cited only by withheld records are dropped. The full-text index is merged, and the copy is vacuumed before signing.
  - The file is `seals/<session>-<seq>.thread-<8 hex>.sqlite`.
  - The sidecar carries `thread`; full seals' sidecars are unchanged.
  - `last_seal` and seal-on-exit ignore thread seals.
- **Verify, format 3.**
  - A kept row must match its thread digest and the seal's thread.
  - A withheld row is allowed only in a thread seal, with a stored digest and a thread digest other than the seal's.
  - `Verified` gains `thread`, `records` and `withheld`. The CLI prints `thread <t>: <n> records, <w> withheld`.
- **README:** a Threads section, plus tool table updates.

**Tests:** 203 pass (190 before); clippy is clean; the release build works. The new tests cover:

- names, the v3 hash layout, and thread storage, find and summary;
- the thread seal: counts, the same head as the full seal, a secret absent from every byte (the full seal as the positive control), evidence pruning, and that sealing again reuses the copy;
- seven tamper cases on a thread seal and four on a full seal;
- the format-2 fixture;
- resume skipping older formats;
- the MCP thread plumbing, the seal tool, and a job end's thread;
- a stdio end-to-end test with `_meta`, a refusal, a thread seal and the CLI line.

`tests/map_e2e.rs` was updated for the new `thread` field on find hits.

**Left out**

- No conversation id from Claude desktop has been seen yet. `client_meta_keys` will show whether one arrives once this build is live.
- Thread seals of format 1 and 2 sessions are refused, since those files have no threads.
