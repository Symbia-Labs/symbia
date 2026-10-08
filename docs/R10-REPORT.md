# R10 report

**What changed**

- **Seal reasons.** Sidecars carry `reason`: `explicit`, `prediction`, `checkpoint`, `exit` or `ledger`. It is absent on older sidecars, which still parse, and it isn't covered by the signature. `seal_for` takes the reason; `seal` is `explicit`. An explicit or prediction seal at the head of a checkpoint or exit seal upgrades that seal's reason, so it isn't pruned.
- **Pruning.** After a full seal verifies, older `checkpoint` and `exit` seals of the same session are deleted. Explicit, prediction, thread and reason-less seals stay.
- **Witness (`src/witness.rs`).**
  - Config `witness`: a folder outside the data directory, refused at load when inside it, including through a symlink.
  - Every seal (full, thread or ledger) appends a line to `witness.jsonl` with session, seq, head, file hash, key, signature, time, reason and thread.
  - `witness::check` compares a file's chain heads with every witnessed seq up to its own: a mismatch fails; a higher witnessed seq is `behind`.
  - `symbia verify --witness <folder|file>` prints `witness ok | behind | not witnessed` and exits 1 on a mismatch.
- **`symbia_open` (new).** It reads a sealed copy from `seals/`, `ledger/` or a path the policy lets the file tools read. It verifies against the pinned keys and the witness, then lists the newest records or returns one by id (`store::get_in` works on any format). A copy that fails verification returns `verified: false` and the reason.
- **`symbia_promote` (new).**
  - Without `confirm` it's a dry run that creates nothing.
  - With `confirm`: the seal is copied to `ledger/`, and a `promotion` record goes into `ledger/ledger.sqlite` (retention `ledger`, no expiry, outside `sessions/`). The record `supersedes` the session's previous promotion, and the ledger is then sealed (reason `ledger`).
  - Promoting the same file again does nothing. Ledger seals are refused.
  - The index reads `ledger/`.
- **15 tools.** README gains an Auditing section.

**Tests:** 231 pass (223 before); clippy is clean. New:

- pruning across all reasons;
- witness lines for full, thread and checkpoint seals;
- `ok`, `behind` and `not witnessed`;
- a rewritten, re-signed seal that verifies on its own but fails the witness at seq 1;
- old sidecars;
- witness config;
- `symbia_open`: a list, by id, a thread seal, a tampered file, and a refused path;
- promotion: the dry run, `confirm`, once only, supersedes, the ledger not resumed, and still searchable after the originals are deleted;
- a stdio end-to-end test with `verify --witness` and a rollback.

Updated for pruning: `fifty_tool_calls_make_a_checkpoint_seal` and `r3`'s checkpoint test.

**Predictions:**

- P1 broke: 231 tests, below the 245 predicted.
- P2 held: no new crate.
- P3 broke: on a copy of the real data, one explicit seal pruned none of the 42 existing seals, because they predate reasons. A one-time command to prune superseded reason-less seals would need Brian's call.
- P4 held, in tests.

**Left out**

- Pruning seals made before R10.
- Witness lines aren't signed separately; each carries the seal's own signature.
- No automatic commit or push of a witness kept in git.
