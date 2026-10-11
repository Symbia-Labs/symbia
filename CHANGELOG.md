# Changelog

## Unreleased (0.2)

A security release. Versions now read `X.Y.YYYYMMDDHHMMSS`: the third number is the release commit's time in UTC. The second number goes up for a file format change or a breaking change, and this release has both.

### How these were found

On 10 October 2026 we reviewed 0.1.1 (commit 997c855) the way a user would meet it, with Claude as the agent: a first run from an empty data folder, five days of the ledger's own records as an agent's daily log, the CLI, search, and an attack-by-attack pass over seals, the witness and the sandbox. Every step ran through Symbia itself; the plan and the result are in that ledger (keys `review.dogfood.2026-10-10.*`). A second reviewer, who hadn't seen those notes, read a copy of the public repository at the same commit, and we checked its line references and reproduced three of its findings with tests. The review produced 26 findings. Nobody outside reported any of them, and we know of no use of them outside our own testing.

Each finding below says how we know: **ran** means reproduced on a Mac, **test** means reproduced by a test, **read** means found in the source and not exercised before the fix. Every fix lands with a test, listed by name.

We are publishing these here rather than as GitHub security advisories. Several are reachable from an agent's own tool calls under the default configuration, so please update.

### Breaking changes

- **New file format (4).** Files written by 0.2 can't be read by 0.1.x. 0.2 still verifies and reads formats 1 to 3, and keeps writing an existing ledger in its own format. A session started by 0.1.x isn't resumed by 0.2; a new session opens and the old one is sealed as before.
- **Sandboxed commands write only inside the roots, the temporary folders and `/dev`.** Before, they could write anywhere outside the deny list.
- **Protected paths** can be read but not written by the file tools or `exec`: shell startup files, `~/Library/LaunchAgents`, `~/.config/autostart`, git's global config, the witness folder, and every repository's `.git/hooks` and `.git/config`. A sandboxed `git init`, `git clone` or `git config` now fails writing `.git/config`.
- **No launchers in the sandbox:** `open`, `launchctl`, `osascript` and `osacompile` (by path), LaunchServices opens and Apple Events are refused.
- **`exec_unsandboxed` rules are refused** when their program sits where a sandboxed command can write, or changed since the server started. Command lines with newlines are refused, and so are git's `--receive-pack`, `--upload-pack`, `--exec` and `ext::`.
- **`symbia verify --witness` exits 1** for `behind` and `not witnessed`, with the reason on stderr.
- **`symbia serve --allow-remote` needs `SYMBIA_HTTP_TOKEN`** (32+ characters), sent as a bearer token on every request.
- **`find` leaves out `tool_call` records** unless `kind: "tool_call"` asks for them.
- **`report` scores only results linked `results_of` to a prediction.** Totals from 0.1.x that counted unlinked results go down.
- The search index is rebuilt once on first use, and records are embedded again.

### Findings and fixes

**1. High: writes from the sandbox could run later, outside it.** With no `roots` set, the default, the home folder is the root. The `write` tool and any sandboxed command could then edit `~/.zshrc` or drop a plist in `~/Library/LaunchAgents`, and the next login shell or login would run it unsandboxed. The profile allowed writes everywhere but the deny list and the data folder. *How:* read, and ran: a sandboxed write outside the roots succeeded. *Fix:* sandboxed writes are limited to the roots, temp folders and `/dev`; the protected paths above are refused for the file tools and in the profile, at any root; `symbia mcp` warns at start and `status` lists a warning while the only root is the home folder. *Tests:* `the_sandbox_writes_only_roots_and_temp_and_launches_nothing_outside` (live, macOS), `protected_paths_are_readable_but_never_writable`, `exec_writes_go_only_to_roots_and_temp`.

**2. High: an unsandboxed rule could be turned to run anything.** A rule names its program by path, and the sandbox could write `/opt/homebrew/bin`, so the `gh` or `cargo` a rule allows could be replaced before the next call. `git push` and `pull` run `.git/hooks`, which the sandbox could write, and `--receive-pack`, `--upload-pack` and `ext::` run other programs; none of that was documented. *How:* ran (checked the folder's permissions) and read. *Fix:* the rule's program must not be writable from the sandbox and must be the file seen at start (device, inode, size, modification time); `.git/hooks` and `.git/config` are protected; git's program-running arguments are refused; the embedding server named in `config.json` is held to the same rule. *Tests:* `a_rule_program_the_sandbox_could_write_or_that_changed_is_refused`, `git_arguments_that_run_another_program_are_refused`.

**3. High: a seal could pass as signed by a pinned key when it wasn't.** `verify` hashed the file, then reopened it by path to walk the chain, and read the sidecar a second time after the key check; that second read accepted any key. `open` and `promote` take paths an agent controls, so the file could be swapped between the check and its use. *How:* test (the second read), read (the swap itself wasn't run). *Fix:* the file and sidecar are read once; verification runs on an in-memory copy of those bytes, and `open`, `promote`, `show` and `get` read and copy from the same bytes. *Test:* `a_snapshot_keeps_the_bytes_it_verified`.

**4. High: a folder swapped for a symlink mid-call could reach refused paths.** The file tools checked a path, then opened it by path, so a parent folder replaced by a symlink in between could reach the deny list or write the data folder. *How:* read. *Fix:* after opening, the file's own path (`F_GETPATH`) is checked against the policy; writes create, rename and link through a handle on the checked folder (`openat`, `renameat`, `linkat`). *Tests:* `a_folder_swapped_for_a_symlink_mid_call_is_caught_on_the_open_file`, `symlink_swapped_in_after_the_check_is_refused_at_open`.

**5. Medium: a duplicate chain row could hide a record that wasn't on the chain.** `verify` compared counts, and `chain.record_id` wasn't unique, so someone with the live file could add a record plus a second chain row pointing at an existing one. README check 9 promised otherwise. *How:* test. *Fix:* `verify` refuses a record that appears twice on the chain; new files carry a unique index. *Test:* `a_repeated_chain_row_cannot_hide_an_off_chain_record`.

**6. Medium: the witness could be edited by the agent it watches.** Under the default root it sat inside the agent's reach. Deleting its later lines hid a rollback without any key; its line signatures were never checked; unreadable lines were skipped silently; `behind` and `not witnessed` exited 0, while SECURITY.md listed a passing rolled-back seal as in scope. *How:* ran and read. *Fix:* witness lines are version 2, each chained to the one before by sha256 and signed whole; every line is checked when the witness loads, and an unreadable or out-of-order line fails; appends hold a file lock and refuse anything but a regular file; the witness folder is protected; `behind` and `not witnessed` exit 1. Lines cut from the end can't be detected from the file alone; SECURITY.md now says so. *Tests:* `append_and_load_round_trip`, `edited_removed_reordered_or_forged_lines_fail`, `unsigned_lines_from_before_0_2_still_load`, `r10_audit`.

**7. Medium, partly fixed: processes started outside the sandbox, and DNS under `exec_network: deny`.** The profile left `open`, `launchctl` and Apple Events available, any of which can start a process outside the sandbox, and DNS lookups went out through `mDNSResponder`'s socket with the network denied. *How:* read; not confirmed before the fix. *Fix:* those launchers, LaunchServices opens and Apple Events are refused, and `mDNSResponder` is closed when the network is denied. The live test checks the refusal, with a control showing the same commands run outside the sandbox. *Not fixed:* the launchers are refused by path, so a copy in another folder gets through. macOS 26 kills such a copy itself, which is why our Mac didn't show it; CI on macOS 15 ran one. We tried matching launchers by code-signing identifier instead, but in a test that rule didn't stop even the original `launchctl`, so it isn't shipped. A program a command builds itself could also talk to `launchd` directly; that is untested. Both are listed in SECURITY.md.

**8. Medium: pruning could delete the seals that contradicted a rewrite.** Older checkpoint and exit seals were removed once a newer seal verified, without checking that the newer chain held their heads. Without a witness, a rewritten session could seal cleanly and remove the evidence against it. *How:* read. *Fix:* a seal is pruned only if the newer chain holds its head at its seq. *Test:* `pruning_keeps_a_seal_the_newer_chain_contradicts`.

**9. Medium: a newline got a denied command past `exec_deny` in unsandboxed calls.** The deny-rule splitter treats a newline as a command break; the unsandboxed splitter didn't. *How:* test. *Fix:* newlines and carriage returns are refused in unsandboxed command lines. *Test:* `split_refuses_shell_syntax_and_bad_quoting`.

**10. Medium: `exec_read: "home"` did nothing under the default root.** It hides the home folder except the roots, and the default root was the home folder. *How:* read, and ran against our own config. *Fix:* the startup and `status` warnings, sixteen more credential and private-data paths on the deny list (cloud CLIs, password stores, Mail, Messages and browser profiles among them), and the README now says plainly what the default allows.

**11. Medium: HTTP sessions weren't locked, and `--allow-remote` had no authentication.** `symbia mcp` could resume a session `symbia serve` was still writing, cleanup could delete a live HTTP session file, and a remote bind served `exec` to anyone who could reach it. *How:* read. *Fix:* served sessions hold the session lock and stdio never resumes them; `--allow-remote` requires `SYMBIA_HTTP_TOKEN`, checked in constant time on every request. *Tests:* `an_http_session_is_locked_and_never_resumed_by_stdio`, `remote_serving_needs_a_token_and_requests_must_carry_it`, `cli_trust`.

**12. Medium: sealing blocked the server's async workers.** The checkpoint seal after a prediction (a copy, two full-file hashes, a verify, and up to 5 s for the witness) ran on an async worker while holding the store's lock. *How:* read. *Fix:* store calls, and the seals they trigger, run as blocking work off the async workers; a job's end record too.

**13. Low: `report` counted verdicts that answered no prediction, and the format was hidden.** Any result with `held` counted, and the format lived only in the README, which agents don't read. *How:* ran. *Fix:* only results linked `results_of` to a prediction are scored, as `show` already did, and the `record` tool's description gives the format. *Test:* `report_scores_only_results_of_a_prediction`.

**14. Low: `find` averaged 14 s of host time, cause unknown.** *How:* ran (`report` by tool). *Fix:* each `find` record now carries `index_ms`, `embed_ms` and `search_ms`, so the next slow one says where its time went.

**15. Low: vectors were made only during searches by meaning.** 1,416 records were waiting at the time of the review, and the first such search ranked unrelated records first. *How:* ran. *Fix:* after the first search by meaning, the server embeds new records in the background, tool calls aside. *Test:* `background_embedding_drains_the_backlog_and_skips_tool_calls`.

**16. Low: `get` couldn't fetch a record `find` had found in another session.** *How:* ran. *Fix:* `get` by id looks in other session files and full seals and adds `file` to the reply. *Test:* `get_reads_a_record_from_another_session`.

**17. Low: tool calls crowded search results.** They were 89% of records, and every `exec` reused the key `tool.exec`. *How:* ran. *Fix:* `find` leaves them out unless asked. *Test:* `find_leaves_out_tool_calls_and_matches_lane_reasons`.

**18. Low: one panic disabled the session.** The store lock poisoned, every later call failed, and the exit seal never came. The path found was a byte slice on an unchecked sidecar field in `status`. *How:* read. *Fix:* a poisoned lock is taken back; `status` slices safely; the clock read can't panic. *Test:* `a_panic_under_the_store_lock_does_not_end_the_session`.

**19. Low: unbounded reads, an unbounded jobs map, and a FIFO that hung `read`.** *How:* read. *Fix:* `edit` and `append` read at most 16 MB and images 64 MB; only regular files open, without blocking; finished jobs past 200 are forgotten. *Tests:* `fifos_are_refused_and_big_files_capped`, `finished_jobs_are_forgotten_beyond_the_cap`.

**20. Low: cost fields, evidence and the HTTP binding weren't hashed.** `host_ms`, `chars`, evidence rows and `mcp_session_id` could be edited in a live file before sealing and the seal would sign the edit. *How:* read. *Fix (format 4):* the record id and row digest cover `host_ms`, `chars` and the evidence each record names; the chain starts from a digest of the session and its HTTP binding. *Test:* `format4_covers_evidence_and_salts_withheld_ids`.

**21. Low: a thread seal let a guess at a withheld record be confirmed.** A withheld row keeps its record id, which was an unsalted hash of the record. *How:* read. *Fix (format 4):* each record carries a 32-byte random salt in its id and digest. *Test:* `format4_covers_evidence_and_salts_withheld_ids`.

**22. Low: `promote` could leave the ledger pointing at the wrong file.** It skipped the copy when the destination name existed. *How:* read. *Fix:* it refuses a different file under a promoted name. *Test:* `promote_refuses_a_different_file_under_a_promoted_name`.

**25. Low: documentation.** `lane_reason` wasn't searchable; the examples' `expires_ms` had passed with no explanation; the README suggested a witness folder in Documents, which brings up a macOS privacy prompt. *Fix:* `lane_reason` is indexed and searchable; the README explains the examples' expiry, recommends a witness folder outside the roots and off Documents, Desktop and iCloud Drive, and corrects the claims findings 4, 5, 7 and 10 showed were too strong.

### Not changed

- **23. Estimates are unused** (1 of 1,693 records carried one). That is about how agents use Symbia, not a defect; `report` already compares estimates with actuals when they are given.
- **24. There is no `decision` kind.** Adding a kind is a vocabulary decision we haven't made.
- **26. The reviewing agent rarely searched before acting** (12 finds in about 1,500 calls). Findings 14, 15 and 17 make searching cheaper and more useful; the habit is outside the code.

### Also

- The README's Tools table has rows for `open` and `promote`, and `tests/docs_sync.rs` fails when a command in the usage text isn't in the README or a tool has no row in the Tools table.

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
