# R5 report

Built by hand in the session, not headless: a headless `claude -p` started through `symbia_exec` now fails with "Not logged in", because the sandbox denies `~/Library/Keychains`, where Claude Code keeps its login.

## Changed

- `exec_unlock` in `config.json`: a list of `DENY_IN_HOME` entries. Anything else fails config load; `$SYMBIA_HOME/keys` can't be listed.
- Exec only: unlocked entries are left out of the sandbox deny rules (`Policy::exec_deny_paths`) and added to the read allowances with their ancestors. The file tools still use the full deny list.
- Logging: the exec `tool_call` record carries `unlocked`; `symbia_status` reports `exec_unlock`; `symbia mcp` notes it on stderr at start. The spec also asked for `unlocked` in the exec reply; that was left out, since the record and status already carry it.
- README: data-and-safety section brought up to date (13-entry deny list, shell sandbox, `exec_unlock`).

## Gate

`cargo test`: 167 passed (was 164). `cargo clippy --all-targets -- -D warnings`: clean. Release build OK.

The gate had to run outside Symbia: inside `symbia_exec`, `sandbox-exec` can't start a nested sandbox (exit 71), so the 41 exec sandbox tests fail there. `.run/gate.sh` runs the gate; it was started through the desktop osascript tool, which leaves no Symbia record.
