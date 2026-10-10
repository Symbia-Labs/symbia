# Changelog

## 0.1.1

- `symbia show <seal>` and `symbia get <seal> <key or id>`: read a seal from the command line without writing SQL. Both verify the seal first, as `verify` does, and refuse one that fails. `show` prints the records in chain order, each prediction with its verdict, and the commands run; `get` prints one record in full as JSON. The README walkthrough now uses them, and the SQL queries move to an "It's just SQLite" section. ([#1](https://github.com/Symbia-Labs/symbia/issues/1))
- A seal no longer waits more than 5 seconds for its witness line. A witness folder behind a macOS privacy prompt (Documents, Desktop, iCloud Drive) used to block the seal, and with it every tool call, until someone answered the prompt. The write now finishes in the background once the folder opens, and the delay goes to stderr.
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
