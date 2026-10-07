# R6 report

## Changed

- **Lazy open.** `symbia mcp` creates no session file at startup; `SymbiaServer::new` opens the session on the first tool call that needs the store (`src/session.rs`, `SymbiaServer::slot`). A start with no tool call leaves nothing in `sessions/`.
- **Locks.** `sessions/<id>.lock` holds `{pid, started_ms}` under an exclusive `flock` for the life of the process. Taking a lock checks that the path still names the locked inode, so a holder deleting the file mid-take can't produce two holders. The lock lives inside the `Store` and is released after the connection closes; on exit `main` calls `release()` after the final seal, which deletes the file. No session opens after that.
- **Resume.** Only the session file with the newest chain `at_ms` is considered. It is resumed unless one of these applies, checked in this order: `resume off` (`resume_window_ms: 0`), `sealed` (retention not `session`), `expired`, `outside the resume window`, `in use` (lock held). When none applies, a `session.resumed` observation (lane `apocryphal`, model `symbia`) is written with `{previous_pid, previous_started_ms, gap_ms, resumes}` and the chain continues. If it can't resume, it never falls back to an older file. New config key `resume_window_ms` (default 14,400,000; negative values are refused).
- **Notice.** The first tool reply after the session opens gets `notice`. A JSON-object reply gets it as an extra field. Any other reply (plain text, errors) gets it as an extra `{"notice": ...}` text block. `symbia_status` adds `resumes` and `previous_session`.
- **Cleanup.** At startup, session files with no chain rows whose lock is free are deleted, along with their `-wal`/`-shm` files. A file that can't be read is kept.
- README updated (commands, status, `sessions/`, config keys).

## Choices the spec left open

- **`previous_pid` after a clean exit.** The spec deletes the `.lock` on exit, so after a normal SIGTERM restart the lock no longer says who held the session. Each session file now has a one-row, unchained `holder` table (`pid, started_ms`), created with `IF NOT EXISTS` so older files still work. Resume reads the stale `.lock` first (holder crashed) and the `holder` table otherwise. That table is the one schema addition. It lands in seals but plays no part in verification.
- **Session id in notices.** Notices give the full session id (22 chars), not a prefix. A 12-char prefix would be only the timestamp digits.
- **"seq continues at n"**: `n` is the seq of the `session.resumed` record.

## Tests

`cargo test`: 178 passed (was 167; two runs, no flakes). `cargo clippy --all-targets -- -D warnings`: clean.

- New: `tests/r6.rs` (6, through the binary over stdio): SIGTERM then restart resumes, with the CLI verifying the latest seal at seq 3; a second live process gets "in use"; window 1 ms and 0; no tool call leaves no file; empty leftovers removed and a file with rows kept; the notice comes on the first reply only. Also 4 unit tests in `session.rs` and 1 in `policy.rs`.
- Changed: `r3::a_result_links_to_a_prediction_from_before_the_restart` now sets `resume_window_ms: 0`. Without it the restart resumes the first session, and the link stops being cross-session, which is the thing the test checks.

## Left out

- HTTP (`symbia serve`) is unchanged, as specified.
- Startup cleanup trusts the lock. An R5 binary still running at upgrade time holds no lock, so its empty session file could be deleted under it. This only matters during the switch-over.
