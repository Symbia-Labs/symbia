# Symbia

Symbia keeps a cryptographically signed, hash-chained record of the work AI agents do. Each record sits in a lane (`canonical`, `conditional` or `apocryphal`, from most to least trusted) that marks how far its result can be trusted. It is one Rust binary on SQLite and serves its tools over MCP, on stdio and streamable HTTP.

## Install

macOS on Apple silicon, with Homebrew:

```sh
brew install symbia-labs/tap/symbia
```

Or download a binary from [Releases](https://github.com/Symbia-Labs/symbia/releases): `symbia-<version>-aarch64-apple-darwin.zip` (signed with a Developer ID and notarized by Apple) or `symbia-<version>-x86_64-unknown-linux-musl.tar.gz` (a static Linux binary). Each has a `.sha256` file beside it.

On Linux there is no shell sandbox yet: `exec` runs commands with your own rights, and `exec_network: "deny"` is refused rather than ignored.

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
| `status` | Reports the session: build, session id, expiry, retention, file, chain seq and head, last seal, public key, running jobs, resumes, and the previous session when it was not resumed; also the caller's thread, the threads written most recently, and a fresh thread name to adopt. |
| `record` | Writes a typed record to the ledger and returns its id, version, seq and head. |
| `find` | Finds records by full-text query, kind, lane, key prefix or thread, in the open session or (`scope: "all"`) in every session and seal; `similar` searches by meaning. |
| `report` | Sums records by thread, tool, kind, model or day: tool calls, characters returned to the model, host time, errors and refusals, estimates against actuals, and predictions with their results and verdicts. |
| `get` | Returns one full record with its links and thread, by id or by key and version. |
| `seal` | Seals the session into a signed, verified copy under `seals/`, or with `in_thread` seals one thread. |
| `read` | Reads a text file with line numbers, up to 2,000 lines and 256 KB per call. PNG, JPEG, GIF, WebP, TIFF and BMP files (detected by their bytes) come back as an image: scaled to a 1,568 px long edge unless `full: true`, never over 8,000 px or 5 MB, TIFF and BMP as PNG. The image as sent is kept as evidence. Other binary files, HEIC and audio included, are refused. |
| `list` | Lists a folder to depth 1–5, up to 1,000 entries. |
| `search` | Searches files for a regex or literal, respecting `.gitignore`. |
| `write` | Writes a file atomically (temp file, then rename). |
| `edit` | Replaces one exact occurrence of a string in a file, atomically; with `replace_all: true`, every occurrence, and says how many. |
| `exec` | Runs a shell command with a timeout (up to 1 hour) and saves its full output as evidence. A command still running after `yield_ms` (default 45 s) becomes a job: the call returns its id and output so far, and the command keeps running. `tail_bytes` sizes the output tails. |
| `job` | Follows a job: `status`, `wait` (up to 50 s), `tail` or `kill` (the whole process group). Once it ends, gives the exit and evidence paths. |

`open` and `promote` are described under Auditing. That is 15 tools. Earlier builds named them `symbia_<name>` (the file tools `symbia_fs_<name>`); a client still holding those names reaches the same tools, and the calls are recorded under the new names. Every call to a file or shell tool writes a `tool_call` record on the `apocryphal` lane. The record holds digests of the arguments and of any file read or written, not the file contents. A job's end gets its own `tool_call` record, keyed `job.<id>`, that `revises` the record of the call that started it. Jobs belong to the server process: when it shuts down, running jobs are killed, recorded as `killed: "shutdown"`, and sealed.

## Threads

Every chat in one Claude app shares one `symbia mcp` process, and so one session. A thread says which conversation or agent wrote a record. The caller names it: every tool takes an optional `thread` (1–64 characters from `A-Z a-z 0-9 . _ : -`), and a call without one goes in `main`. An agent should pick one name when it starts (`status` offers a fresh one as `new_thread`) and pass it on every call. Each record a call writes, its `tool_call` record and a job's end record included, carries that thread. The chain hash covers each row's thread, so a record can't be moved to another thread without breaking the chain.

`seal` with `in_thread` seals one thread. The copy keeps that thread's records in full. For every other record it keeps only the chain row and the record's digest. It verifies against the same chain head as a full seal at the same point, so it proves the thread's records and where they fall among everything else, without showing what the other threads wrote. `symbia verify` prints the thread and the counts of kept and withheld records.

## Search

`find` searches the open session by default. With `scope: "all"` it searches every session file and full seal under the data folder, through an index kept at `index.sqlite`. The index covers each record's key and text, and for a command, the first 16 KB of its saved output. It is derived data: delete it whenever you like, and the next search rebuilds it. Each search catches it up for at most 2 seconds and says `index_behind` when there's more to read.

`similar` searches by meaning. It needs embeddings from a model on your own machine, set in `config.json` one of two ways:

- `{"embed": {"url": "http://127.0.0.1:8081/v1/embeddings", "model": "nomic-embed-text"}}` uses an OpenAI-style embeddings endpoint you run yourself. Only loopback addresses are accepted.
- `{"embed": {"server": "/opt/homebrew/bin/llama-server", "model_path": "~/models/nomic-embed-text-v1.5.Q8_0.gguf"}}` has Symbia start llama.cpp's server on first use and stop it on exit.

Records are embedded as searches need them, at most 256 per call; the reply says `unembedded` when some are still waiting. A search with both `query` and `similar` fuses the two rankings. Every find is recorded as a `tool_call`, with what it asked and the ids it returned.

## Report

`report` sums the open session, or with `scope: "all"` everything indexed, grouped by thread, tool, kind, model or UTC day. Each group gives the record and tool-call counts, the characters returned to the model, host time, errors, refusals, and how actual cost compared with the estimate where one was given. It also counts predictions: how many have a linked result, how many are still open, and the verdicts results gave. A result states its verdict as `"held": true|false`, or as a `"verdicts"` map of `"held"` and `"broke"`.

## Auditing

**Opening a seal.** `open` reads a sealed copy without changing it. It verifies the copy against your pinned keys and lists its newest records, or returns one in full. It reads seals in the data folder's `seals/` and `ledger/`, and anywhere else the file tools may read. A copy that fails verification comes back as `verified: false` with the reason, and no records.

**The witness.** A seal proves what a session held when it was signed. On its own it can't show that a later part of the session was deleted, or that an older seal is being passed off as the latest. Set `{"witness": "~/Documents/Symbia Witness"}` and every seal also appends one line to `witness.jsonl` in that folder: the session, chain position, chain head, file hash, key and signature. The folder must be outside the data folder. It's most useful somewhere that leaves the machine, such as iCloud Drive or a git repository you push. `symbia verify <file> --witness <folder>` then checks that the file's chain matches every head the witness saw. A mismatch fails. A file older than the newest witnessed seal reports `behind`. `open` runs the same check when a witness is set.

**The ledger.** `promote` copies a verified seal into `ledger/` and writes a `promotion` record into `ledger/ledger.sqlite`, a long-lived file with no expiry. The ledger is then sealed, so the ledger's own chain fixes which seals were promoted and in what order. It runs as a dry run unless `confirm` is true. Promoting the same file twice does nothing, and a newer seal of the same session supersedes the earlier promotion. Search reads `ledger/` too, so promoted records stay findable after their original seals are gone.

**Pruning.** Each seal records why it was made: `explicit`, `prediction`, `checkpoint`, `exit` or `ledger`. Once a newer full seal of a session verifies, older `checkpoint` and `exit` seals of that session are deleted, because the newer one holds every record they did. Explicit, prediction and thread seals, and seals from builds that didn't record a reason, are kept. With a witness set, the deleted seals' heads and signatures remain in the witness file. The reason isn't covered by the signature: editing it can change what gets pruned, but not what a seal proves.

## Data and safety

**Where data lives.** `SYMBIA_HOME` if set. Otherwise `~/Library/Application Support/Symbia` on macOS, and `$XDG_DATA_HOME/symbia` (falling back to `~/.local/share/symbia`) elsewhere. It holds:

| Path | Contents |
| --- | --- |
| `keys/device.ed25519` | The device signing key (mode 0600, directory 0700). |
| `keys/trusted.json` | Pinned public keys. |
| `sessions/` | Live session files, one SQLite file per session, and a `.lock` beside each one a `symbia mcp` process holds. |
| `seals/` | Sealed copies and their signed `.seal.json` sidecars. |
| `evidence/` | Full stdout and stderr of `exec` runs and images as sent by `read`, named by sha256. |
| `config.json` | Optional. `roots` sets the folders the file and shell tools may use; `exec_read`, `exec_read_allow`, `exec_network`, `exec_deny`, `exec_unlock`, `exec_unsandboxed` and `read_roots` tune the shell sandbox and the file tools; `resume_window_ms` sets how `symbia mcp` resumes sessions. |

**Path policy.** The file and shell tools accept only absolute paths inside the configured roots (default: your home folder). A path is resolved lexically and through its real path, so `..` and symlinks cannot leave a root. Files are opened with `O_NOFOLLOW`, and a write re-checks its folder just before the rename. These are always refused, even inside a root:

- `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`
- `~/.config/gh`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json`
- `~/Library/Keychains`, `~/Library/Cookies`, `~/Library/Application Support/Claude`
- `$SYMBIA_HOME/keys`

**Read-only data directory.** The tools never write under `SYMBIA_HOME`: `write`, `edit` and a `exec` working directory there are refused. `evidence/` can be read with `read`.

**Shell sandbox (macOS).** `exec` runs each command under the macOS sandbox. The deny list above is unreadable and unwritable, `SYMBIA_HOME` is unwritable, and by default (`"exec_read": "home"`) nothing in your home folder is readable except the roots, a few shell and toolchain files, and `evidence/`. `"exec_network": "deny"` also blocks outbound network. A command cannot start a sandbox of its own inside this one. On Linux there is no sandbox yet.

**`exec_unlock` (a stopgap).** `{"exec_unlock": [".config/gh"]}` re-opens named deny-list entries to commands run through `exec`, so a tool such as `gh` can use its own login. Only deny-list entries are accepted, and `keys/` can never be unlocked. The file tools still refuse those paths. It re-opens the entry to every command, not just one tool, so any command could read what it holds. Each exec record made while it is set carries `unlocked`, `status` shows it, and the server notes it on stderr at start.

**`exec_unsandboxed`.** Some jobs can't run in the sandbox: `gh`, `codesign` and `notarytool` need the login keychain, and a test suite that starts sandboxes of its own can't run inside one. List those programs as rules, for example `{"exec_unsandboxed": [{"program": "/opt/homebrew/bin/gh", "args": ["*"]}, {"program": "~/.cargo/bin/cargo", "args": ["test", "*"], "cwd": "~/symbia-v2"}]}`. A rule names one program by its absolute path, the arguments it takes (exact tokens, with a final `"*"` for any rest), and optionally the folder it must run in. Only a call that passes `unsandboxed: true` and matches a rule runs outside the sandbox. It runs with no shell: no pipes, redirects, variables, `~` or globs. The rule's program is started by its absolute path with a fixed `PATH`, and `exec_deny` still applies. The record carries `sandbox: "none"`, the rule and the argv; `status` lists the rules; the server names them on stderr at start. This is a short, logged list, not containment: a rule for a program that can run arbitrary code (`cargo test`, `git -c`, `gh extension`) grants exactly that.

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

Symbia collects no telemetry and sends nothing over the network itself. All records, seals, keys and evidence stay in `SYMBIA_HOME` on your machine, kept until you delete them. Commands run through `exec` can reach the network like any shell command you run. No data is shared with Symbia Labs or third parties.

Contact: hello@symbia-labs.com

## License

MIT. See [LICENSE](LICENSE).
