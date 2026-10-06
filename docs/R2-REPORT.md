# R2 report

## Changed

| Area | What changed |
|---|---|
| `exec` sandbox | On macOS the command runs as `/usr/bin/sandbox-exec -p <profile> /bin/zsh -lc <command>`. The profile is built per call: `(allow default)`, one `(deny file-read* file-write* (subpath …))` per deny-list path (five `DENY_IN_HOME` entries under the policy's user home, plus `$SYMBIA_HOME/keys`, each as spelled and as its realpath when that differs), `(deny file-write* (subpath …))` on `$SYMBIA_HOME` (both spellings). Paths are SBPL-quoted (`\` and `"` escaped); a non-UTF-8 path refuses the call. sandbox-exec execs the shell in place, so process group, timeout `killpg` and output capture are unchanged. A missing `/usr/bin/sandbox-exec` refuses the call. |
| `exec_network` | New optional `config.json` key, `"allow"` (default) or `"deny"`; any other value fails config load. `"deny"` adds `(deny network-outbound)` and `(allow network-outbound (remote unix-socket))`. |
| Record | `symbia_exec`'s `tool_call` body gains `command`, `sandbox` (`"seatbelt"` / `"none"`), `network`. All three are set before any check, so refused calls carry them too. Tool description gains one sentence on the sandbox. |
| Seal on exit | `seal::seal_pending` seals only if the chain head is past the last seal; empty sessions are never sealed. `symbia mcp`: after the stdio transport closes (or SIGINT/SIGTERM), the runtime is shut down (5 s drain) and then the session is sealed. `symbia serve`: on SIGINT/SIGTERM the accept loop stops and every live HTTP session with unsealed records is sealed. Failures go to stderr; the process still exits. |

## Gate

| Check | Result |
|---|---|
| `cargo test` | 116 passed (was 101): 102 unit, 1 `b3_replace`, 3 `cli_trust`, 2 `map_e2e`, 1 `r1_tools`, 4 `r2_seal_on_exit`, 3 `s1_resume`. 5 of 5 repeat runs green. |
| `cargo clippy --all-targets -- -D warnings` | clean |
| Live check | Release binary over stdio with the real `$HOME`: `wc -c ~/.ssh/…` and `ls ~/.ssh` → `Operation not permitted`; `echo x > $SYMBIA_HOME/x` refused; `git --version` runs; the session was sealed on EOF. |

Spec tests map to: `exec::tests::sandbox::{deny_list_paths_cannot_be_read (~/.ssh/id_test and keys/, directly, via realpath and via a symlink in the root; content absent from replies and both evidence files; run once with a user home named we"ird home), symbia_home_cannot_be_written, roots_and_tools_still_work, exec_network_deny_blocks_loopback, missing_sandbox_exec_refuses}`; `exec::tests::profile_quotes_paths_and_follows_the_network_setting`; `r2_seal_on_exit::{closing_stdin_seals_a_session_with_records (one seal, `symbia verify` ok), an_empty_session_leaves_no_seal, a_session_sealed_at_its_head_is_not_sealed_again, exec_record_names_command_sandbox_and_network}`; `s1_resume::sigterm_seals_sessions_with_records`; `mcp::tests::exec_record_names_its_evidence` now checks the three fields.

## What the sandbox broke

- **Nothing in the existing suite.** `cargo --version`, `git --version`, pipes, `mkdir`/`rm` in a root, and the timeout group kill all pass under seatbelt.
- **SSH from exec.** `~/.ssh` is unreadable, including its config, `known_hosts` and any agent socket kept there, so `git push` / `ssh` over SSH keys fail inside `symbia_exec`. This is the deny list working as intended; left as is.
- **`ls ~`** prints `Operation not permitted` for `.ssh` and the other denied entries (metadata reads are denied too).

## Choices the spec left open

- **Linux with `exec_network: "deny"`** refuses the call rather than running with network on, since nothing can enforce it.
- **`symbia mcp` also seals on SIGINT/SIGTERM**, not only on EOF; clients often stop servers with SIGTERM.
- **The tool description** says the data directory is read-only rather than "off limits": reads outside `keys/` still work.
- **README** is unchanged; its privacy text ("can reach the network like any shell command") still holds for the default.

## Not covered

- `symbia serve` seals inside the runtime before the drain, so an HTTP tool call that starts writing in that instant lands after the seal and stays unsealed until the next one.
- An HTTP session that expired and was dropped before shutdown is not sealed (its store is gone from memory; the file stays on disk).
- SIGKILL or a crash still leaves the session unsealed.
- The seatbelt profile covers the deny list and `$SYMBIA_HOME` only; the command can still read and write anywhere else the user can, outside the roots included.
