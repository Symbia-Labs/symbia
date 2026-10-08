# Changelog

## 0.1.0

First public release.

- A signed, hash-chained ledger of typed records on SQLite, with lanes (`canonical`, `conditional`, `apocryphal`) and retention (`session`, `seal`, `ledger`).
- Seals: a signed, verified copy of a session file; `symbia verify` checks the signature, the chain and every record; keys are pinned.
- MCP over stdio (`symbia mcp`) and streamable HTTP (`symbia serve`), 12 tools.
- File and shell tools that write a `tool_call` record for every call, with evidence (full command output, images as sent) kept by sha256.
- Path policy with a deny list for credential folders; on macOS, `symbia_exec` runs in the system sandbox: the home folder is unreadable outside the configured roots, network can be turned off, and Claude Code's own `Bash(...)` deny rules are applied.
- Image reads, long-running commands as jobs (`symbia_job`), seal on exit and checkpoint seals, links across sessions, and stdio sessions that resume after a server restart.
