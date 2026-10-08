# Symbia

Symbia keeps a cryptographically signed, hash-chained record of the work AI agents do. Each record sits in a lane (`canonical`, `conditional` or `apocryphal`, from most to least trusted) that marks how far its result can be trusted. It is one Rust binary on SQLite and serves its tools over MCP, on stdio and streamable HTTP.

## Install

macOS on Apple silicon, with Homebrew:

```sh
brew install symbia-labs/tap/symbia
```

Or download a binary from [Releases](https://github.com/Symbia-Labs/symbia/releases): `symbia-<version>-aarch64-apple-darwin.zip` (signed with a Developer ID and notarized by Apple) or `symbia-<version>-x86_64-unknown-linux-musl.tar.gz` (a static Linux binary). Each has a `.sha256` file beside it.

On Linux there is no shell sandbox yet: `symbia_exec` runs commands with your own rights, and `exec_network: "deny"` is refused rather than ignored.

## Build from source

Requires Rust 1.91 or later.

```sh
cargo build --release
```

The binary is `target/release/symbia`.

| Command | What it does |
| --- | --- |
| `symbia mcp` | MCP over stdio. The session opens on the first tool call: it resumes the previous session if that one is free, unexpired and written within `resume_window_ms` (default 4 h; `0` turns resume off), otherwise a new one. The first reply says which. |
| `symbia serve [--listen ip:port] [--allow-remote]` | MCP over streamable HTTP at `/mcp`, default `127.0.0.1:7341`. Each MCP session gets its own session file. |
| `symbia verify <sealed.sqlite> [--trust <hex>]...` | Check a seal. Exit 0 and `ok <session> seq N head <12 hex>`, or exit 1 and the reason. |
| `symbia trust add <hex> <label>` / `symbia trust list` | Pin a public key, or list pinned keys. |
| `symbia --version` | Print the build. |

## Use with Claude

Use the full path to the binary: `/opt/homebrew/bin/symbia` after a Homebrew install, or wherever you put a downloaded or built binary.

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
| `symbia_status` | Reports the session: build, session id, expiry, retention, file, chain seq and head, last seal, public key, running jobs, resumes, and the previous session when it was not resumed; also the caller's thread, the threads written most recently, and a fresh thread name to adopt. |
| `symbia_record` | Writes a typed record to the ledger and returns its id, version, seq and head. |
| `symbia_find` | Finds records by full-text query, kind, lane, key prefix or thread. |
| `symbia_get` | Returns one full record with its links and thread, by id or by key and version. |
| `symbia_seal` | Seals the session into a signed, verified copy under `seals/`, or with `in_thread` seals one thread. |
| `symbia_fs_read` | Reads a text file with line numbers, up to 2,000 lines and 256 KB per call. PNG, JPEG, GIF, WebP, TIFF and BMP files (detected by their bytes) come back as an image: scaled to a 1,568 px long edge unless `full: true`, never over 8,000 px or 5 MB, TIFF and BMP as PNG. The image as sent is kept as evidence. Other binary files, HEIC and audio included, are refused. |
| `symbia_fs_list` | Lists a folder to depth 1–5, up to 1,000 entries. |
| `symbia_fs_search` | Searches files for a regex or literal, respecting `.gitignore`. |
| `symbia_fs_write` | Writes a file atomically (temp file, then rename). |
| `symbia_fs_edit` | Replaces one exact occurrence of a string in a file, atomically. |
| `symbia_exec` | Runs a shell command with a timeout (up to 1 hour) and saves its full output as evidence. A command still running after `yield_ms` (default 45 s) becomes a job: the call returns its id and output so far, and the command keeps running. `tail_bytes` sizes the output tails. |
| `symbia_job` | Follows a job: `status`, `wait` (up to 50 s), `tail` or `kill` (the whole process group). Once it ends, gives the exit and evidence paths. |

That is 12 tools. Every call to a file or shell tool writes a `tool_call` record on the `apocryphal` lane. The record holds digests of the arguments and of any file read or written, not the file contents. A job's end gets its own `tool_call` record, keyed `job.<id>`, that `revises` the record of the call that started it. Jobs belong to the server process: when it shuts down, running jobs are killed, recorded as `killed: "shutdown"`, and sealed.

## Threads

Every chat in one Claude app shares one `symbia mcp` process, and so one session. A thread says which conversation or agent wrote a record. The caller names it: every tool takes an optional `thread` (1–64 characters from `A-Z a-z 0-9 . _ : -`), and a call without one goes in `main`. An agent should pick one name when it starts (`symbia_status` offers a fresh one as `new_thread`) and pass it on every call. Each record a call writes, its `tool_call` record and a job's end record included, carries that thread. The chain hash covers each row's thread, so a record can't be moved to another thread without breaking the chain.

`symbia_seal` with `in_thread` seals one thread. The copy keeps that thread's records in full. For every other record it keeps only the chain row and the record's digest. It verifies against the same chain head as a full seal at the same point, so it proves the thread's records and where they fall among everything else, without showing what the other threads wrote. `symbia verify` prints the thread and the counts of kept and withheld records.

## Data and safety

**Where data lives.** `SYMBIA_HOME` if set. Otherwise `~/Library/Application Support/Symbia` on macOS, and `$XDG_DATA_HOME/symbia` (falling back to `~/.local/share/symbia`) elsewhere. It holds:

| Path | Contents |
| --- | --- |
| `keys/device.ed25519` | The device signing key (mode 0600, directory 0700). |
| `keys/trusted.json` | Pinned public keys. |
| `sessions/` | Live session files, one SQLite file per session, and a `.lock` beside each one a `symbia mcp` process holds. |
| `seals/` | Sealed copies and their signed `.seal.json` sidecars. |
| `evidence/` | Full stdout and stderr of `symbia_exec` runs and images as sent by `symbia_fs_read`, named by sha256. |
| `config.json` | Optional. `roots` sets the folders the file and shell tools may use; `exec_read`, `exec_read_allow`, `exec_network`, `exec_deny`, `exec_unlock`, `exec_unsandboxed` and `read_roots` tune the shell sandbox and the file tools; `resume_window_ms` sets how `symbia mcp` resumes sessions. |

**Path policy.** The file and shell tools accept only absolute paths inside the configured roots (default: your home folder). A path is resolved lexically and through its real path, so `..` and symlinks cannot leave a root. Files are opened with `O_NOFOLLOW`, and a write re-checks its folder just before the rename. These are always refused, even inside a root:

- `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`
- `~/.config/gh`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json`
- `~/Library/Keychains`, `~/Library/Cookies`, `~/Library/Application Support/Claude`
- `$SYMBIA_HOME/keys`

**Read-only data directory.** The tools never write under `SYMBIA_HOME`: `symbia_fs_write`, `symbia_fs_edit` and a `symbia_exec` working directory there are refused. `evidence/` can be read with `symbia_fs_read`.

**Shell sandbox (macOS).** `symbia_exec` runs each command under the macOS sandbox. The deny list above is unreadable and unwritable, `SYMBIA_HOME` is unwritable, and by default (`"exec_read": "home"`) nothing in your home folder is readable except the roots, a few shell and toolchain files, and `evidence/`. `"exec_network": "deny"` also blocks outbound network. A command cannot start a sandbox of its own inside this one. On Linux there is no sandbox yet.

**`exec_unlock` (a stopgap).** `{"exec_unlock": [".config/gh"]}` re-opens named deny-list entries to commands run through `symbia_exec`, so a tool such as `gh` can use its own login. Only deny-list entries are accepted, and `keys/` can never be unlocked. The file tools still refuse those paths. It re-opens the entry to every command, not just one tool, so any command could read what it holds. Each exec record made while it is set carries `unlocked`, `symbia_status` shows it, and the server notes it on stderr at start.

**`exec_unsandboxed`.** Some jobs can't run in the sandbox: `gh`, `codesign` and `notarytool` need the login keychain, and a test suite that starts sandboxes of its own can't run inside one. List those programs as rules, for example `{"exec_unsandboxed": [{"program": "/opt/homebrew/bin/gh", "args": ["*"]}, {"program": "~/.cargo/bin/cargo", "args": ["test", "*"], "cwd": "~/symbia-v2"}]}`. A rule names one program by its absolute path, the arguments it takes (exact tokens, with a final `"*"` for any rest), and optionally the folder it must run in. Only a call that passes `unsandboxed: true` and matches a rule runs outside the sandbox. It runs with no shell: no pipes, redirects, variables, `~` or globs. The rule's program is started by its absolute path with a fixed `PATH`, and `exec_deny` still applies. The record carries `sandbox: "none"`, the rule and the argv; `symbia_status` lists the rules; the server names them on stderr at start. This is a short, logged list, not containment: a rule for a program that can run arbitrary code (`cargo test`, `git -c`, `gh extension`) grants exactly that.

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
