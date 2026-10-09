# Changelog

## Unreleased

- `examples/`: real seals from a short run of two agents, signed by an example key, with a full seal, a thread seal, two tampered copies, the commands' evidence and the witness. The README's new "Try it on the example seals" section verifies and queries them with `symbia` and `sqlite3`. A test checks the committed files on every run.

## 0.1.0

First public release.

- A signed, hash-chained ledger of typed records on SQLite, with lanes (`canonical`, `conditional`, `apocryphal`) and retention (`session`, `seal`, `ledger`).
- Seals: a signed, verified copy of a session file; `symbia verify` checks the signature, the chain and every record; keys are pinned.
- MCP over stdio (`symbia mcp`) and streamable HTTP (`symbia serve`), 15 tools with plain names: `status`, `record`, `get`, `seal`, `find`, `report`, `open`, `promote`, `read`, `list`, `search`, `write`, `edit`, `exec`, `job`. Calls by the earlier `symbia_*` names still reach their tools and are recorded under the new names.
- Threads: every record carries the caller's thread, and a thread seal keeps one thread's records and only the digests of the rest.
- Search across every session and seal (full text, and by meaning with a local embedding model), and `report`: cost, errors and prediction outcomes by thread, tool, kind, model or day.
- Auditing: `open` verifies and reads a seal, `promote` moves a seal into the long-lived ledger, and an optional witness file outside the data folder catches a rewritten seal.
- File and shell tools that write a `tool_call` record for every call, with evidence (full command output, images as sent) kept by sha256.
- Path policy with a deny list for credential folders; on macOS, `exec` runs in the system sandbox: the home folder is unreadable outside the configured roots, network can be turned off, and Claude Code's own `Bash(...)` deny rules are applied.
- Image reads, long-running commands as jobs (`job`), seal on exit and checkpoint seals, links across sessions, and stdio sessions that resume after a server restart.
- `exec_unsandboxed`: named programs (for example `gh`, `codesign`, `cargo test`) may run outside the sandbox when a call asks, with no shell, by absolute path, and recorded with `sandbox: "none"`.
