# B3 report

## Built

| Area | What it does |
|---|---|
| `policy` | Roots from `$SYMBIA_HOME/config.json` (`{"roots": [...]}`, `~` expanded), default `$HOME`. Deny list: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/Library/Keychains`, `~/Library/Application Support/Claude`, `$SYMBIA_HOME/keys`. A path is resolved lexically, then the closest existing ancestor is realpath'd and the rest appended (v1's symlink defense). The lexical path must sit in a root (either spelling, so `/tmp` and `/private/tmp` both work), the realpath must sit in a realpath'd root, and neither may fall in a deny entry. Paths must be absolute. |
| `files` | `symbia_fs_read`, `_list`, `_search`, `_write`, `_edit` as specified. Search uses `grep` + `ignore` (`require_git(false)`, so `.gitignore` applies outside a repo too). Writes go to a temp file beside the target, fsync, then rename; `create_only` hard-links instead, which fails if the target exists. |
| `exec` | `symbia_exec`: `/bin/zsh -lc` with `process_group(0)`; on timeout `killpg(SIGKILL)`. stdout and stderr stream to temp files in `evidence/` while hashed, then move to `evidence/<sha256>`, with a row each in `evidence` written in the same transaction as the record. |
| Records | Each B3 call writes one `tool_call` record on `apocryphal`, key `tool.<tool>`, body as specified. `args_digest` = sha256 of the RFC 8785 JSON of the arguments. `chars` is the tool reply's length, `host_ms` covers the whole call, `est_*` are null. `Store::write_with` adds this; `Store::write` is unchanged. |
| Transports | Same router on stdio and streamable HTTP. `symbia serve` loads the policy once at start. |

## Gate

| Check | Result |
|---|---|
| `cargo test` | 92 passed: 84 unit, 1 `b3_replace`, 3 `cli_trust`, 2 `map_e2e`, 2 `s1_resume` |
| `cargo clippy --all-targets -- -D warnings` | clean |
| `tests/b3_replace.rs` | passes, 5 of 5 repeat runs. Real binary over stdio with a temp root in `config.json`: list → search (`.gitignore`d `target/` excluded) → read → write → edit → exec, then a read of the exec evidence and a refused read of `keys/`. The chain seq rises by exactly one per call; seal verifies by library and CLI; the sealed file holds one `tool_call` per call in order, no file content in any record, 2 evidence rows, no null `host_ms`/`chars`. |
| `cargo build --release` | `target/release/symbia` (11.7 MB) |

Required tests map to: `policy::tests::{dotdot_escape_is_refused, absolute_path_outside_roots_is_refused, symlink_pointing_outside_is_refused, every_deny_entry_is_refused}` (each entry, existing or not, directly, via `..` and via a symlink); `files::tests::edit_needs_exactly_one_match`; `read_numbers_lines_and_continues_past_the_line_cap`, `read_stops_at_256_kb`, `read_refuses_binary_with_size_and_sha256`; `search_respects_gitignore_context_and_cap`; `exec::tests::{exit_codes_and_output_pass_through, timeout_kills_the_group_and_returns_partial_output, full_output_lands_in_evidence_with_matching_sha256}`. The timeout test starts `sleep 60 &`, writes its pid, times out at 1.5 s, and checks with `kill(pid, 0)` that the sleep is gone.

## Pinned crates (new)

globset 0.4.20 · grep 0.4.1 (grep-regex 0.1.14, grep-searcher 0.1.17 via lock) · ignore 0.4.33 · libc 0.2.190. tokio gains `process`, `time`, `fs`.

## Choices the spec left open

- **Body additions.** A failed or refused call adds `error` (the reason). `symbia_exec` adds `stdout_sha256` and `stderr_sha256` so the record names its evidence. `path`/`cwd` hold the realpath, or the path as given when refused.
- **`model`** on `tool_call` records is the MCP client's `clientInfo.name`, else `unknown`. The server never learns the model.
- **Evidence is readable** with `symbia_fs_read` even when outside the roots: `$SYMBIA_HOME/evidence` is a read-only extra root. Exec replies give the absolute evidence path.
- **sha256 fields.** `fs_read` sets `sha256_before` (the file as read). Records hold full hex; replies use 12-char prefixes, except the binary refusal and evidence paths, which need the full digest.
- **Binary** = any NUL byte or invalid UTF-8. `fs_edit` refuses non-UTF-8 files and counts overlapping matches (`aa` in `aaa` is 2).
- **Defaults.** `fs_read` limit 2,000 (larger is clamped); `fs_list` depth 1, symlinks listed not followed, hidden files shown; `fs_search` 50 matches, hidden files skipped, lines clipped at 400 bytes; `fs_write` creates parent directories and keeps an existing file's mode.
- **Walks skip denied paths**, so listing or searching `~` never enters `~/.ssh` or `keys/`.
- **Exec pipes.** After the shell exits, it waits up to 2 s for the pipes to close, then returns what it has. A background child left running after a normal exit is not killed. A signal exit reports `"signal N"`.
- **No session, no work.** Over HTTP without a bound session, B3 tools refuse before touching anything, since the call could not be recorded.

## Not covered, and why

- **Search deadline granularity.** The 30 s deadline is checked between files and on each match or context line. One huge file with no matches can overrun it. The test uses a zero deadline.
- **`$SYMBIA_HOME/sessions` and `seals`** are not denied; `fs_write` inside a root that contains them can change a live session file. The seal still catches tampering. Not in the spec's deny list.
- **TOCTOU.** The policy check and the file operation are separate steps; a symlink swapped in between is not caught.
- **Config reload.** `config.json` is read at start; changing roots needs a restart.
- **Out of scope per B3.md:** the importer, the decider, routines, retrieval, the broker, promotion, and registering the binary with the Claude app.

## Fixes (B3-FIX.md)

This section supersedes the `sessions`/`seals` and TOCTOU bullets above.

| Fix | What changed | Tests |
|---|---|---|
| `$SYMBIA_HOME` read-only | `Policy` keeps `$SYMBIA_HOME` (both spellings). `Access::Write` on a path whose lexical path or realpath falls under it is refused: `fs_write`, `fs_edit`, and `exec`'s `cwd`. Reads still pass where a root (or the evidence read root) covers them; `keys/` stays on the deny list. | `policy::tests::symbia_home_is_read_only_even_inside_a_root`; `files::tests::symbia_home_refuses_write_and_edit_but_evidence_reads` (`sessions/`, `seals/`, `evidence/`, `config.json`: directly, via a directory symlink and via a file symlink; file unchanged; evidence reads, keys refused); `exec::tests::cwd_inside_symbia_home_is_refused` |
| `O_NOFOLLOW` | `read`, `write` and `edit` split into check, then `read_at`/`write_at`/`edit_at` on the realpath. Those open the target with `O_NOFOLLOW` (`ELOOP` → `denied: … is a symlink`), then hash, read and take the mode from that handle. | `files::tests::symlink_swapped_in_after_the_check_is_refused_at_open`: the check passes on a regular file, the file is then replaced by a link to outside the roots, and all three refuse; the outside file is unchanged |
| Re-check before rename | `atomic_write` takes the policy. The temp file is created beside the target; immediately before `rename`/`hard_link` the directory is realpath'd and checked for `Write` again. On refusal the temp file is removed. | `files::tests::rename_rechecks_the_directory_realpath` |
| `.identity/` | Added to `.gitignore`. Not read or deleted. | — |

Fixture change: two `mcp` tests used one temp dir as both root and `$SYMBIA_HOME`; their roots now sit in a second temp dir.

**Gate:** `cargo test` 97 passed (89 unit, 1 `b3_replace`, 3 `cli_trust`, 2 `map_e2e`, 2 `s1_resume`); `b3_replace` 5 of 5 repeat runs; clippy clean; `cargo build --release` 11.8 MB.

**Still uncovered:**

- **Parent components.** `O_NOFOLLOW` guards only the final component. A parent directory swapped for a symlink between check and open is followed on reads, lists and searches; nothing re-checks them.
- **Write window.** Re-check and `rename` are separate path-based calls, so a swap in between still lands. Closing it needs `openat`/`renameat` on a held directory handle.
- **Brief outside writes.** `create_dir_all` and the temp file run before the re-check. If a parent is swapped in that window, empty directories and, for a moment, the temp file (with the new content) can appear outside the roots; the temp file is then removed.
- **Exec is not confined.** Only `cwd` is checked, then used by path. The command itself runs with the user's rights and can write anywhere, `$SYMBIA_HOME` included. The seal still detects changes to sealed files.
- **Hard links.** A hard link inside a root to a file under `$SYMBIA_HOME` or `keys/` passes the realpath check. Writes and edits replace the link by rename, so the original is untouched, but reads go through it. Only `exec` can make one.
