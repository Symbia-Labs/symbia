# Symbia

Symbia keeps a cryptographically signed, hash-chained record of the work AI agents do. Each record sits in a lane (`canonical`, `conditional` or `apocryphal`, from most to least trusted) that marks how far its result can be trusted. It is one Rust binary on SQLite and serves its tools over MCP, on stdio and streamable HTTP.

## Build from source

Requires Rust 1.91 or later.

```sh
cargo build --release
```

The binary is `target/release/symbia`.

| Command | What it does |
| --- | --- |
| `symbia mcp` | MCP over stdio. One process is one session. |
| `symbia serve [--listen ip:port] [--allow-remote]` | MCP over streamable HTTP at `/mcp`, default `127.0.0.1:7341`. Each MCP session gets its own session file. |
| `symbia verify <sealed.sqlite> [--trust <hex>]...` | Check a seal. Exit 0 and `ok <session> seq N head <12 hex>`, or exit 1 and the reason. |
| `symbia trust add <hex> <label>` / `symbia trust list` | Pin a public key, or list pinned keys. |
| `symbia --version` | Print the build. |

## Use with Claude

Claude Desktop, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "symbia": {
      "command": "/absolute/path/to/symbia",
      "args": ["mcp"]
    }
  }
}
```

Claude Code:

```sh
claude mcp add --scope user symbia -- /absolute/path/to/symbia mcp
```

## Tools

| Tool | What it does |
| --- | --- |
| `symbia_status` | Reports the session: build, session id, expiry, retention, file, chain seq and head, last seal, public key. |
| `symbia_record` | Writes a typed record to the ledger and returns its id, version, seq and head. |
| `symbia_find` | Finds records by full-text query, kind, lane or key prefix. |
| `symbia_get` | Returns one full record with its links, by id or by key and version. |
| `symbia_seal` | Seals the session into a signed, verified copy under `seals/`. |
| `symbia_fs_read` | Reads a text file with line numbers, up to 2,000 lines and 256 KB per call. |
| `symbia_fs_list` | Lists a folder to depth 1–5, up to 1,000 entries. |
| `symbia_fs_search` | Searches files for a regex or literal, respecting `.gitignore`. |
| `symbia_fs_write` | Writes a file atomically (temp file, then rename). |
| `symbia_fs_edit` | Replaces one exact occurrence of a string in a file, atomically. |
| `symbia_exec` | Runs a shell command with a timeout and saves its full output as evidence. |

Every call to a file or shell tool writes a `tool_call` record on the `apocryphal` lane. The record holds digests of the arguments and of any file read or written, not the file contents.

## Data and safety

**Where data lives.** `SYMBIA_HOME` if set. Otherwise `~/Library/Application Support/Symbia` on macOS, and `$XDG_DATA_HOME/symbia` (falling back to `~/.local/share/symbia`) elsewhere. It holds:

| Path | Contents |
| --- | --- |
| `keys/device.ed25519` | The device signing key (mode 0600, directory 0700). |
| `keys/trusted.json` | Pinned public keys. |
| `sessions/` | Live session files, one SQLite file per session. |
| `seals/` | Sealed copies and their signed `.seal.json` sidecars. |
| `evidence/` | Full stdout and stderr of `symbia_exec` runs, named by sha256. |
| `config.json` | Optional. `{"roots": [...]}` sets the folders the file and shell tools may use. |

**Path policy.** The file and shell tools accept only absolute paths inside the configured roots (default: your home folder). A path is resolved lexically and through its real path, so `..` and symlinks cannot leave a root. Files are opened with `O_NOFOLLOW`, and a write re-checks its folder just before the rename. These are always refused, even inside a root:

- `~/.ssh`, `~/.gnupg`, `~/.aws`
- `~/Library/Keychains`, `~/Library/Application Support/Claude`
- `$SYMBIA_HOME/keys`

**Read-only data directory.** The tools never write under `SYMBIA_HOME`: `symbia_fs_write`, `symbia_fs_edit` and a `symbia_exec` working directory there are refused. `evidence/` can be read with `symbia_fs_read`. A command run through `symbia_exec` runs with your own rights, so it is not confined to the roots.

**Key pinning.** The device key is pinned in `keys/trusted.json` when it is created. `symbia verify` accepts only seals signed by a pinned key. Add others with `symbia trust add`, or for one run with `--trust`.

**What `verify` checks**, in order:

1. The `.seal.json` sidecar is present and well formed.
2. The sidecar's public key is pinned.
3. The sealed file's sha256 matches the sidecar.
4. The signature over the file sha256 and chain head is valid.
5. The file's retention is `seal` and its format is known.
6. The chain walks from genesis: seqs are consecutive, each `prev_hash` matches the previous hash, and each hash is recomputed from its row.
7. Every record id is recomputed; every record's time and session match its chain row, and its cost fields are filled.
8. No record or link sits off the chain.
9. The sidecar's seq and head match the end of the chain.

## Privacy Policy

Symbia collects no telemetry and sends nothing over the network itself. All records, seals, keys and evidence stay in `SYMBIA_HOME` on your machine, kept until you delete them. Commands run through `symbia_exec` can reach the network like any shell command you run. No data is shared with Symbia Labs or third parties.

Contact: hello@symbia-labs.com

## License

MIT. See [LICENSE](LICENSE).
