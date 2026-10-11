# Security

Symbia signs records and runs commands for AI agents, so we treat a hole in either as a serious bug.

## Reporting

Report a vulnerability privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. If you can't use GitHub, write to hello@symbia-labs.com. Please don't open a public issue for a security problem.

Include the Symbia version (`symbia --version`), the platform, and the steps or a seal file that shows the problem. We reply to every report, and we name reporters in the release notes unless they ask us not to.

Only the latest release gets fixes.

## In scope

- A seal that passes `symbia verify` after its records, chain, sidecar or signature were changed, or one that verifies under a key that isn't pinned or passed with `--trust`.
- A thread seal that reveals a withheld record's contents, or (from format 4) lets someone confirm a guess at it.
- A witness check that passes for a rewritten or rolled-back seal, or a witness file whose lines were edited, reordered, removed from the middle or forged and still loads.
- A file or shell tool reaching a path the policy refuses: the deny list, the keys folder, outside the roots, a write into the data folder, or a write to a protected path (shell startup files, launch agents, git config and hooks, the witness).
- `open`, `promote`, `show` or `get` acting on bytes other than the ones `verify` checked.
- `symbia serve` answering a request without the token when one is set.
- A command run through `exec` escaping the macOS sandbox, or running outside it without a matching `exec_unsandboxed` rule and `unsandboxed: true`.
- A tool call that leaves no `tool_call` record.

## Working as documented

These are documented limits, not vulnerabilities:

- An `exec_unsandboxed` rule for a program that can run arbitrary code grants exactly that. The README says so.
- `exec_unlock` reopens a deny-list entry to every command while it is set.
- On Linux, `exec` has no sandbox.
- The `exec_deny` rules and Claude Code's imported `Bash(...)` rules are a convenience; `eval`, `sh -c` and scripts get around them. The sandbox is the boundary.
- A seal's `reason` isn't covered by its signature. Editing it can change what gets pruned, but not what the seal proves.
- Anyone with the private key in `keys/device.ed25519` can sign seals as that device.
- With the default roots (the whole home folder) the file tools and `exec` can write anywhere in the home folder outside the deny list and protected paths. `status` and the startup message say so. Set `roots`.
- The macOS sandbox profile starts from `(allow default)` and takes away. It refuses the launchers (`open`, `launchctl`, `osascript`, `osacompile`), LaunchServices opens and Apple Events, but a program a command builds itself could still talk to `launchd` or another system service over its socket. That path is untested.
- A witness can't show from its own contents that lines were cut off its end. Keep a copy that leaves the machine and compare against it.
- Witness lines written before 0.2 are unsigned. They still load, ahead of the first signed line.
- Seals and session files of format 3 and earlier don't cover `host_ms`, `chars`, evidence rows or the HTTP binding, and their thread seals keep unsalted record ids. They verify as before; new files are format 4.
- An `exec_unsandboxed` rule's program is checked against the file seen at server start. Replacing it with the server stopped, by someone who can write there, isn't detected.
