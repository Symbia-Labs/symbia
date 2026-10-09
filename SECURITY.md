# Security

Symbia signs records and runs commands for AI agents, so we treat a hole in either as a serious bug.

## Reporting

Report a vulnerability privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. If you can't use GitHub, write to hello@symbia-labs.com. Please don't open a public issue for a security problem.

Include the Symbia version (`symbia --version`), the platform, and the steps or a seal file that shows the problem. We reply to every report, and we name reporters in the release notes unless they ask us not to.

Only the latest release gets fixes.

## In scope

- A seal that passes `symbia verify` after its records, chain, sidecar or signature were changed, or one that verifies under a key that isn't pinned or passed with `--trust`.
- A thread seal that reveals a withheld record's contents.
- A witness check that passes for a rewritten or rolled-back seal.
- A file or shell tool reaching a path the policy refuses: the deny list, the keys folder, outside the roots, or a write into the data folder.
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
