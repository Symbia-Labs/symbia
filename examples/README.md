# Example seals

Real seals from a short run of two agents through `symbia mcp`, signed by a throwaway example key. They let you try verification and queries before you run Symbia on your own work. The commands are in the main README under [Try it on the example seals](../README.md#try-it-on-the-example-seals).

## What happened in the run

- **agent-a** wrote `orders.csv` (three orders of 40, 35 and 15) and registered two predictions: the file holds 3 orders, and the amounts sum to 100. It counted the rows and summed the amounts with two commands, then recorded a result for each prediction. The first held. The second broke: the sum is 90.
- **agent-b** searched the file and left a note on the `conditional` lane: A-102 looks low.
- Symbia sealed agent-a's thread on its own, then the whole session.

## Files

| Path | What it is |
| --- | --- |
| `example-key.pub` | The example signer's public key, for `symbia verify --trust`. |
| `seals/session.sqlite` | The full session, 9 records. Its signed sidecar is `session.seal.json`. |
| `seals/agent-a.sqlite` | A thread seal: agent-a's 7 records in full, agent-b's 2 as digests only. It verifies against the same chain head as the full seal. |
| `seals/tampered.sqlite` | A copy of the session where agent-b's note was moved to the `canonical` lane after sealing. Fails: `file sha256 mismatch`. |
| `seals/tampered-rehashed.sqlite` | The same edit, with the sidecar's file hash rewritten to match. Fails: `signature invalid`. |
| `evidence/` | The commands' full output, each file named by its sha256. |
| `witness/witness.jsonl` | The witness lines written as each seal was made. |

Paths inside the records point at the temporary folder the run used, which no longer exists.

## Regenerating

The seals carry the file format of the build that made them. After a format change, regenerate them and commit the result:

```sh
cargo test --test make_examples -- --ignored    # writes target/examples-out
```

Copy `target/examples-out` over this folder, keep this README, and run `cargo test --test examples`, which checks the committed files against what this README and the main README say.
