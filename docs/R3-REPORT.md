# R3 report

## Changed

| Area | What changed |
|---|---|
| Seal on shutdown | `symbia mcp` seals right after stdin EOF or SIGINT/SIGTERM, then drains (5 s), then calls `seal_pending` again, which does nothing unless a draining call wrote. `symbia serve` already sealed every live session before the drain; that is unchanged. |
| Checkpoints | `seal::checkpoint` runs after each write (`symbia_record` and every `tool_call` record), once the reply is built. It seals after a `prediction` or once 50 records have been written since the last seal, whatever made that seal. A failure goes to stderr and the write still succeeds. |
| `exec_read` | New key, `"home"` (default) or `"deny_list"` (R2). In `"home"` mode the profile matches the spec: deny reads of the home; allow metadata on the home and on the folders between it and each root/allowance; allow reads of roots, `exec_read_allow` and `$SYMBIA_HOME/evidence`; then the deny list; then the `$SYMBIA_HOME` write deny; then network. Every path in both spellings. |
| `exec_read_allow` | New key, spec defaults, `~` expanded. Ancestors of allowances get metadata too, not only ancestors of roots, so `~/.config/git` resolves. |
| `DENY_IN_HOME` | 5 → 13 entries (`.config/gh`, `.netrc`, `.docker/config.json`, `.kube`, `.npmrc`, `.pypirc`, `.git-credentials`, `Library/Cookies`). Covers file tools and exec in every mode. |
| `exec_deny` / imports | New module `rules.rs`. Rules come from config and, with `exec_import_claude_rules` (default true), from `Bash(...)` entries in `~/.claude/settings.json` and in `<cwd>/.claude/settings{,.local}.json`. Here `<cwd>` is the exec call's `cwd`. Files load on every call. A bad file adds a note to the reply's `policy` list. Commands split on `&&` `\|\|` `;` `\|` newline outside quotes, leading `VAR=value` words are dropped, and any matching simple command refuses the call. The refusal names the rule and its file. Refused calls are recorded with `command` and `error`. |
| Cross-session links | `links.to_session` column. A target missing from the current session is looked up in other session files and seals, newest mtime first. The row digest includes `to_session` when it is set and leaves it out when null, so existing format-2 seals still verify and `FORMAT` stays 2. `symbia_get` shows `to_session`. `verify` lists external links and the CLI prints `external <from> <rel> <to> session <id>`. `symbia_status` gains `session_started_ms`. |
| `read_roots` | New key, default `~/.cargo/registry`, `~/.rustup/toolchains`. These folders are readable by fs_read/list/search and never writable. The deny list checks first. |
| Small fixes | `symbia_fs_write` gains `append` (create if missing; the whole file is rewritten atomically, so `sha256_before`/`after` match a write; the reply adds `size`; `append` with `create_only` is refused). The `symbia_record` description now gives the link shape and rels. Exec replies leave out zero-byte streams. |

## Gate

| Check | Result |
|---|---|
| `cargo test` | 147 passed (was 116): 129 unit, 1 b3, 3 cli_trust, 2 map_e2e, 1 r1, 4 r2, 4 r3, 3 s1 |
| `cargo clippy --all-targets -- -D warnings` | clean |

The spec tests map to: `r3::{sigterm_seals_within_one_second, fifty_records_and_a_prediction_make_checkpoint_seals, a_result_links_to_a_prediction_from_before_the_restart, exec_refuses_commands_matching_imported_claude_rules}`, `mcp::tests::{fifty_tool_calls_make_a_checkpoint_seal, a_prediction_is_sealed_at_once_and_not_again, a_failed_checkpoint_does_not_fail_the_write, …}`, `exec::tests::sandbox::{home_mode_hides_the_home_outside_roots_and_allowances, deny_list_mode_restores_r2_reads, deny_list_path_inside_a_root_is_refused_in_home_mode, real_home_toolchain_still_runs}`, `exec::tests::home_profile_orders_deny_home_then_allows_then_deny_list`, `rules::tests::*`, `seal::tests::cross_session_links_verify_as_external`, and `policy::tests::read_roots_are_readable_but_not_writable`.

## What home mode broke in normal use

I ran the debug binary over stdio with the real `$HOME`, a temp `SYMBIA_HOME`, `roots: [~/symbia-v2]` and `exec_read: "home"`:

- `CARGO_TARGET_DIR=target/r3-check cargo build`: **worked**. It was a clean build of every dependency, exit 0 in 19 s. Homebrew cargo reads `~/.cargo/registry` through the `~/.cargo` allowance.
- `git status`, `git log`: worked. The login shell's `~/.zprofile` (`brew shellenv`, PATH edits) ran without errors.
- `ls ~`: `Operation not permitted`, as designed.
- `cat ~/.config/gh/hosts.yml`: refused.
- Not exercised: SSH, Python under `~/Library/Python`, and tools that cache under `~/Library/Caches` or `~/.cache`. Those reads are refused in home mode, so expect such tools to fail until their paths go in `exec_read_allow`.

## Caveats

- **Command rules are a policy convenience, not a boundary.** `eval`, `$(...)`, `sh -c`, scripts and absolute paths (`/bin/chmod`) get around them. The sandbox is the boundary. The exec tool description says so too.
- **A root at the home cancels home mode.** With no `roots` key the root defaults to `~`, so the allow rule re-opens the whole home and only the deny list is left. The benchmark's credential paths are on the deny list now, so they stay closed in that case. Other files in the home do not.
- **`~/.zshrc` is readable by default, and on this machine it holds a plaintext API key.** Under the spec's defaults, exec can read it.
- **Rule syntax goes past the spec in one place:** a rule with `*` anywhere is a wildcard (`Bash(rm -rf *)` is the form in the real `~/.claude/settings.json`). The `:*` and exact forms behave as specified.
- **Each checkpoint is a full copy of the session file.** A long session leaves one copy per 50 records under `seals/`.
- **The process still exits about 5 s after SIGTERM.** The drain waits on rmcp's blocking stdin reader. The seal lands in milliseconds, before the drain starts.
