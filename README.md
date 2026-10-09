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
| `symbia verify <sealed.sqlite> [--trust <hex>]... [--witness <folder>]` | Check a seal. Exit 0 and `ok <session> seq N head <12 hex>` (for a thread seal, also the thread and its kept and withheld counts), or exit 1 and the reason. With `--witness`, also check the seal against the witness file. |
| `symbia prune-legacy [--confirm]` | Remove seals made by builds before seals recorded a reason, where a newer full seal of the same session covers them. Each is written to the witness first, so a witness must be set. A dry run unless `--confirm`. |
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

## Try it on the example seals

[`examples/`](examples/) holds real seals from a short run of two agents, signed by a throwaway example key. agent-a predicted that `orders.csv` holds 3 orders and that the amounts sum to 100, measured both with shell commands, and recorded the results: the first held and the second broke. agent-b searched the file and left a note. You can check all of it with `symbia` and `sqlite3`, without running an agent. The queries need SQLite 3.45 or later, which reads the binary JSON that record bodies are stored in.

```sh
git clone https://github.com/Symbia-Labs/symbia && cd symbia/examples
KEY=$(cat example-key.pub)
```

### Verify

```sh
symbia verify seals/session.sqlite --trust $KEY --witness witness
# ok 1791560407633-0e8022e0 seq 9 head ec1ea4fc7103
# witness ok (4 entries)

symbia verify seals/agent-a.sqlite --trust $KEY        # agent-a's thread alone
# ok 1791560407633-0e8022e0 seq 9 head ec1ea4fc7103 thread agent-a: 7 records, 2 withheld

symbia verify seals/session.sqlite                     # the example key isn't pinned
# untrusted key 489024d5d267                             (exit 1)
```

Someone moved agent-b's note from the `conditional` lane to `canonical` after the session was sealed. Both copies of the edit fail:

```sh
symbia verify seals/tampered.sqlite --trust $KEY          # file sha256 mismatch          (exit 1)
symbia verify seals/tampered-rehashed.sqlite --trust $KEY # signature invalid             (exit 1)

sqlite3 -readonly seals/tampered.sqlite "SELECT lane FROM records WHERE key = 'review.orders'"   # canonical
sqlite3 -readonly seals/session.sqlite  "SELECT lane FROM records WHERE key = 'review.orders'"   # conditional
```

The second copy rewrote the file hash in the sidecar to match the edit. The signature covers that hash, and only the holder of the private key can sign a new one. To accept seals from another machine for good, pin its key with `symbia trust add <hex> <label>` and drop `--trust`.

### Query

A seal is a SQLite file. Open it with `-readonly` or work on a copy: any write changes the file's hash, and the seal no longer verifies.

Every record in chain order, with its thread and lane:

```sh
sqlite3 -readonly -column -header seals/session.sqlite "
  SELECT c.seq, c.thread, r.kind, r.lane, r.key
  FROM chain c JOIN records r ON r.id = c.record_id ORDER BY c.seq"
```

```
seq  thread   kind         lane         key
---  -------  -----------  -----------  -------------------
1    agent-a  tool_call    apocryphal   tool.write
2    agent-a  prediction   canonical    orders.rows
3    agent-a  prediction   canonical    orders.total
4    agent-a  tool_call    apocryphal   tool.exec
5    agent-a  tool_call    apocryphal   tool.exec
6    agent-a  result       canonical    orders.rows.result
7    agent-a  result       canonical    orders.total.result
8    agent-b  tool_call    apocryphal   tool.search
9    agent-b  observation  conditional  review.orders
```

Each prediction with its result:

```sh
sqlite3 -readonly -column -header seals/session.sqlite "
  SELECT p.key AS prediction, json_extract(p.body, '$.claim') AS claim,
         CASE json_extract(r.body, '$.held') WHEN 1 THEN 'held' ELSE 'broke' END AS verdict
  FROM links l
  JOIN records p ON p.id = l.to_id
  JOIN records r ON r.id = l.from_id
  WHERE l.rel = 'results_of'"
```

```
prediction    claim                      verdict
------------  -------------------------  -------
orders.rows   orders.csv holds 3 orders  held
orders.total  the amounts sum to 100     broke
```

One record in full. Bodies are stored as binary JSON, so wrap them in `json()`:

```sh
sqlite3 -readonly seals/session.sqlite "SELECT json(body) FROM records WHERE key = 'orders.total.result'"
# {"held":false,"note":"the amounts sum to 90, not 100","total":90}
```

The commands an agent ran, with their exit status, host time and the characters returned to the model:

```sh
sqlite3 -readonly -column -header seals/session.sqlite "
  SELECT json_extract(body, '$.command') AS command, json_extract(body, '$.exit') AS exit, host_ms, chars
  FROM records WHERE kind = 'tool_call' AND json_extract(body, '$.tool') = 'exec'"
```

A command's full output, from the evidence folder. The record holds only its sha256:

```sh
sha=$(sqlite3 -readonly seals/session.sqlite "SELECT json_extract(body, '$.stdout_sha256') FROM records
      WHERE json_extract(body, '$.command') LIKE 'awk%'")
cat evidence/$sha                  # 90
shasum -a 256 evidence/$sha        # the same sha256
```

Cost by kind of record:

```sh
sqlite3 -readonly -column -header seals/session.sqlite "
  SELECT kind, COUNT(*) AS records, SUM(chars) AS chars_to_model, SUM(host_ms) AS host_ms
  FROM records GROUP BY kind"
```

Full-text search over keys and bodies (quote terms that hold punctuation):

```sh
sqlite3 -readonly -column seals/session.sqlite "
  SELECT r.key, c.thread FROM records_fts f
  JOIN records r ON r.id = f.id JOIN chain c ON c.record_id = r.id
  WHERE records_fts MATCH '\"A-102\"'"
# review.orders  agent-b
```

When a record was written, and by which model, in UTC:

```sh
sqlite3 -readonly -column -header seals/session.sqlite "
  SELECT c.thread, r.kind, r.lane, datetime(r.at_ms / 1000, 'unixepoch') AS at_utc, r.model
  FROM chain c JOIN records r ON r.id = c.record_id WHERE r.key = 'review.orders'"
```

What a thread seal withholds. Rows from other threads keep only a digest:

```sh
sqlite3 -readonly -column -header seals/agent-a.sqlite "
  SELECT c.seq, IFNULL(r.key, '(withheld)') AS key, c.thread, hex(substr(c.row_digest, 1, 6)) AS digest
  FROM chain c LEFT JOIN records r ON r.id = c.record_id ORDER BY c.seq"
```

```
seq  key                  thread   digest
---  -------------------  -------  ------------
1    tool.write           agent-a
…
7    orders.total.result  agent-a
8    (withheld)                    4DC033A5F93C
9    (withheld)                    05E373C576DA
```

The sidecar and the witness:

```sh
cat seals/session.seal.json        # session, chain_seq, chain_head, file_sha256, public_key, signature, reason
jq -c '{chain_seq, reason, head: .chain_head[0:12]}' witness/witness.jsonl
```

The same queries work on your own seals in the data folder's `seals/` (see Data and safety).

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
| `config.json` | Optional. `roots` sets the folders the file and shell tools may use; `exec_read`, `exec_read_allow`, `exec_network`, `exec_deny`, `exec_unlock`, `exec_unsandboxed` and `read_roots` tune the shell sandbox and the file tools; `resume_window_ms` sets how `symbia mcp` resumes sessions; `embed` sets up search by meaning (see Search); `witness` names the witness folder (see Auditing). |
| `index.sqlite` | The search index across sessions and seals. Derived data: safe to delete. |
| `ledger/` | Promoted seals and `ledger.sqlite`, the long-lived ledger. |

**Path policy.** The file and shell tools accept only absolute paths inside the configured roots (default: your home folder). A path is resolved lexically and through its real path, so `..` and symlinks cannot leave a root. Files are opened with `O_NOFOLLOW`, and a write re-checks its folder just before the rename. These are always refused, even inside a root:

- `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`
- `~/.config/gh`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json`
- `~/Library/Keychains`, `~/Library/Cookies`, `~/Library/Application Support/Claude`
- `$SYMBIA_HOME/keys`

**Read-only data directory.** The tools never write under `SYMBIA_HOME`: `write`, `edit` and an `exec` working directory there are refused. `evidence/` can be read with `read`.

**Shell sandbox (macOS).** `exec` runs each command under the macOS sandbox. The deny list above is unreadable and unwritable, `SYMBIA_HOME` is unwritable, and by default (`"exec_read": "home"`) nothing in your home folder is readable except the roots, a few shell and toolchain files, and `evidence/`. `"exec_network": "deny"` also blocks outbound network. A command cannot start a sandbox of its own inside this one. On Linux there is no sandbox yet.

**`exec_unlock` (a stopgap).** `{"exec_unlock": [".config/gh"]}` re-opens named deny-list entries to commands run through `exec`, so a tool such as `gh` can use its own login. Only deny-list entries are accepted, and `keys/` can never be unlocked. The file tools still refuse those paths. It re-opens the entry to every command, not just one tool, so any command could read what it holds. Each exec record made while it is set carries `unlocked`, `status` shows it, and the server notes it on stderr at start.

**`exec_unsandboxed`.** Some jobs can't run in the sandbox: `gh`, `codesign` and `notarytool` need the login keychain, and a test suite that starts sandboxes of its own can't run inside one. List those programs as rules, for example `{"exec_unsandboxed": [{"program": "/opt/homebrew/bin/gh", "args": ["*"]}, {"program": "~/.cargo/bin/cargo", "args": ["test", "*"], "cwd": "~/symbia-v2"}]}`. A rule names one program by its absolute path, the arguments it takes (exact tokens, with a final `"*"` for any rest), and optionally the folder it must run in. Only a call that passes `unsandboxed: true` and matches a rule runs outside the sandbox. It runs with no shell: no pipes, redirects, variables, `~` or globs. The rule's program is started by its absolute path with a fixed `PATH`, and `exec_deny` still applies. The record carries `sandbox: "none"`, the rule and the argv; `status` lists the rules; the server names them on stderr at start. This is a short, logged list, not containment: a rule for a program that can run arbitrary code (`cargo test`, `git -c`, `gh extension`) grants exactly that.

**Key pinning.** The device key is pinned in `keys/trusted.json` when it is created. `symbia verify` accepts only seals signed by a pinned key. Add others with `symbia trust add`, or for one run with `--trust`.

**What `verify` checks**, in order:

1. The `.seal.json` sidecar is present and well formed.
2. The sidecar's public key is pinned.
3. The sealed file's sha256 matches the sidecar.
4. The signature over the file sha256 and chain head is valid.
5. The file's retention is `seal`, its format is known, and the sidecar names the same thread as the file.
6. The chain walks from genesis: seqs are consecutive, each `prev_hash` matches the previous hash, and each hash is recomputed from its row, thread included.
7. Every record id is recomputed; every record's time and session match its chain row, and its cost fields are filled.
8. In a thread seal, every record of the sealed thread is present, no other thread's record is, and each withheld row's stored digest recomputes its chain hash.
9. No record or link sits off the chain.
10. The sidecar's seq and head match the end of the chain.
11. With `--witness`, the file's chain matches every head the witness recorded for its session; a seal older than the newest witnessed one reports `behind`.

## Privacy Policy

Symbia collects no telemetry and sends nothing over the network itself. All records, seals, keys and evidence stay in `SYMBIA_HOME` on your machine, kept until you delete them. Commands run through `exec` can reach the network like any shell command you run. No data is shared with Symbia Labs or third parties.

Contact: hello@symbia-labs.com

## License

MIT. See [LICENSE](LICENSE).
