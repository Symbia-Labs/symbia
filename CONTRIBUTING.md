# Contributing

Pull requests are welcome. Open an issue first for anything larger than a fix, so we can agree on the approach before you write it.

## Build and test

Rust 1.91 or later.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Both must pass; CI runs them on macOS and Linux for every pull request. On macOS the `exec` tests start the system sandbox, which can't nest, so run the suite from a normal terminal rather than from inside another sandbox.

## House rules

- Every change in behavior lands with a test that would fail without it.
- Tests use temporary directories, never a real data folder.
- Every timestamp is integer UTC milliseconds. No local time anywhere.
- Wherever a digest covers JSON, the JSON is canonical (RFC 8785).
- Retention values are `session`, `seal` and `ledger`. Lanes are `canonical`, `conditional` and `apocryphal`.
- Tool replies stay short and return references (id, version, seq, digest prefix), not whole records, except `get`.
- Crate versions are pinned exactly in `Cargo.toml`.
- A change to the file format bumps `FORMAT`, keeps older seals verifying, and regenerates `examples/` (see `examples/README.md`).

## Security problems

Report them privately, as [SECURITY.md](SECURITY.md) describes, not in a pull request or issue.

## License

By contributing, you agree that your contribution is licensed under the MIT license, the same as the rest of Symbia.
