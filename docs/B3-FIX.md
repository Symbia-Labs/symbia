# B3 fix: protect Symbia's own data, narrow the symlink race

Read CLAUDE.md and docs/B3-REPORT.md, then make these changes. Keep every existing test passing.

1. **`$SYMBIA_HOME` is read-only to the tools.** `symbia_fs_write` and `symbia_fs_edit` refuse any path that resolves under `$SYMBIA_HOME`. `symbia_exec` refuses a `cwd` under it. `fs_read`, `fs_list` and `fs_search` may still read there (evidence must stay readable), except `keys/`, which stays fully denied. Tests: writing and editing a file in `sessions/`, `seals/`, `evidence/` and `config.json` are all refused, directly and via a symlink; reading an evidence file still works.

2. **Narrow the check-then-use race.** Open the final path component with `O_NOFOLLOW` for reads, edits and writes. For writes and edits, create the temp file in the target's directory, then re-check that directory's realpath against the policy immediately before the rename. Test: a final component that is a symlink to a file outside the roots is refused at open, even though the path check alone would pass if the link were created after the check. Document what remains uncovered.

3. **Ignore `.identity/`.** Add `.identity/` to `.gitignore`. Do not delete or read the folder.

## Gate

All tests pass, clippy clean, release build.

## When done

Append a short "Fixes" section to `docs/B3-REPORT.md` and commit. Do not push.
