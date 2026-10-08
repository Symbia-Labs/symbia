# R7 report

**What changed**

- **`exec_unsandboxed` (new `src/unsandboxed.rs`).** Config rules `{program, args, cwd?}` are checked at load: the program must be an absolute (or `~`) path to an executable file, `"*"` may only come last in `args`, and `cwd` must exist. Unknown keys are refused.
- **`symbia_exec` gains `unsandboxed: true`.** The command is split without a shell, and shell operators, `$` and backticks are refused. The first word picks a rule: a bare name matches the program's file name, and a path must resolve to the same file. The rule's program then runs by its absolute path with a fixed `PATH` (rule folders, then `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`). Timeouts, jobs, tails, evidence and process-group kill work as for sandboxed exec. `exec_deny` and the imported Claude rules are checked first.
- **Logging.** The record carries `sandbox: "none"`, `network: "unrestricted"` and `unsandboxed: {rule, program, argv}`. Replies and job status carry `sandbox: "none"`, `symbia_status` lists the rules, and startup names the programs on stderr.
- **`symbia_job` action schema is inlined** (`#[schemars(inline)]`), as is `LinkInput` in `symbia_record`. No tool schema contains `$ref`.
- **Policy load tolerates permission errors on deny-list and `exec_unlock` entries.** Such a path keeps its lexical spelling, so `symbia mcp` can start inside the exec sandbox.
- **README:** an `exec_unsandboxed` paragraph under data and safety.

**Tests:** 190 pass (178 before), and `cargo clippy --all-targets -- -D warnings` is clean. The 12 new tests cover:

- splitting and its refusals;
- rule loading and its refusals;
- matching by name, path, args and cwd;
- `PATH` order;
- an end-to-end run (argv, fixed `PATH`, facts, reply, and the same command without the flag staying sandboxed);
- refusals through `start_request` (no rule, shell syntax, `exec_deny`, a cwd outside the roots);
- an unsandboxed job killed with its group;
- on macOS, an unsandboxed `cat` reading a deny-list file the sandbox refuses;
- the inlined schemas;
- config loading;
- the unreadable-`.ssh` policy load.

**Departures from the spec**

- `args` is required in each rule: an omitted list is refused rather than taken as "no arguments".
- A `"*"` anywhere but last is refused at load.
- A double-quoted backslash before any character other than `"` or `\` is kept with its backslash, as in POSIX.

**Left out**

- Per-rule environment.
- Rule-level `exec_network`: unsandboxed commands always have the network.
- Windows.
