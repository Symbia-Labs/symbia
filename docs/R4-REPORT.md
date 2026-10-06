# R4 report

## Changed

| Area | What changed |
|---|---|
| Images in `symbia_fs_read` | New module `images.rs`. Magic bytes pick PNG, JPEG, GIF, WebP, TIFF or BMP; the name is ignored. An image that fits (long edge ≤ 1,568 px, or ≤ 8,000 with `full: true`, and ≤ 5 MB) goes out unchanged. Otherwise it is scaled with Lanczos3 and re-encoded: PNG for PNG/GIF/BMP/TIFF input, JPEG q85 for JPEG/WebP. TIFF and BMP always become PNG. If the encoded image is over 5 MB it is scaled down again until it fits. The reply has two blocks: the image, then `{path, format, width, height, sent_width, sent_height, bytes, sha256}`. `bytes` and `sha256` describe the image as sent. HEIC is refused with "HEIC images are not supported". Audio and other binaries are refused as before. |
| Image record | The `tool_call` record keeps `sha256_before` (the file) and adds `image: {format, width, height, sent_width, sent_height, sent_sha256}`. The image as sent is written to `evidence/<sha256>`, and its evidence row has the image's media type. `bytes_returned` and `chars` count the base64 data. `truncated` is true when the image was scaled. |
| Jobs | `exec.rs` now starts each command as a `Job`, and a task owns the child until it ends. `symbia_exec` waits `yield_ms` (default 45,000, max 50,000). A command that ends in that time gets the same reply as before. A command still running returns `{job, running: true, pid, started_ms, stdout/stderr tails}` at once. The sandbox, rules, process group and evidence capture are unchanged. The `timeout_ms` max is now 3,600,000. `tail_bytes` is 256–65,536, default 8,192. |
| `symbia_job` | New tool with actions `status` (default), `wait` (`wait_ms` ≤ 50,000), `tail` (`bytes`) and `kill` (SIGKILL to the group; the reply says `killed: "symbia_job"`). Annotations are as specified. The 12th tool. |
| Job records | The start call writes the usual `tool_call` record with `job` and `running: true`. When the job ends by exit, timeout or kill, new module `jobs.rs` writes a `tool_call` record keyed `job.<id>`. It holds `exit`, `duration_ms`, stdout/stderr sha256, `truncated`, `killed` and the evidence rows, and links `revises` to the start record. When a `symbia_job` call sees the job has ended, it writes the end record before its own record, so the order is fixed. |
| Shutdown | `symbia mcp` handles SIGINT, SIGTERM and stdin EOF the same way: kill every running job's group, wait up to 500 ms per job, record each as `killed: "shutdown"`, then seal, then drain. `symbia serve` does the same for every live session before `seal_all`. `symbia_status` gains `jobs: [{job, pid, started_ms, command}]`, listing running jobs only. |
| README | Tools table covers images and jobs, and gives the count (12). |

## Gate

| Check | Result |
|---|---|
| `cargo test` | 164 passed (was 147): 144 unit, 1 b3, 3 cli_trust, 2 map_e2e, 1 r1, 4 r2, 4 r3, 2 r4, 3 s1 |
| `cargo clippy --all-targets -- -D warnings` | clean |

Spec tests:
- `mcp::tests::images::*`: small PNG, 4000×3000 JPEG → 1568×1176, GIF, BMP → PNG, a misnamed PNG, `full: true`, the 8,000 px cap, evidence and records, binary and HEIC refused.
- `images::tests::over_five_megabytes_is_scaled_further`.
- `mcp::tests::jobs::*`: `sleep 2; echo done` with `yield_ms: 500`, wait, timeout, kill of the whole group, `tail_bytes`, shutdown then seal, and the one-call reply.
- `r4::*` through the binary: image content on the wire; SIGTERM with a running job gives a verified seal holding the `killed: "shutdown"` record.

Two existing tests changed because the spec changed what they check:
- `exec::tests::cwd_is_checked_and_bad_timeouts_refused` now tests the 3,600,000 limit.
- `r1_tools` now expects 12 tools, including `symbia_job`'s annotations.

## Dependencies and size

| Crate | Version | Note |
|---|---|---|
| `image` | 0.25.10 (latest) | `default-features = false`, features png, jpeg, gif, webp, tiff, bmp |
| `base64` | 0.23.1 (latest) | was already in the tree through rmcp |

Release binary: 11,851,296 → 13,418,688 bytes (+1.57 MB, +13%).

## Left out / caveats

- **Jobs live in memory.** A job belongs to its server process and its session. Another session cannot see it, and nothing survives a restart. A job that runs past an HTTP session's expiry still records its end into that session's file while the server holds it.
- **An image file is read whole before decoding.** The sent image has size caps; the file read does not. `image`'s default decoder limit (512 MB of allocation) is the only guard.
- **Scaling a GIF keeps only its first frame**, as PNG. A GIF that fits goes out unchanged, with its animation.
- **Kill reports `exit: "killed"` rather than a signal number.** `killed` names who killed it: `symbia_job` or `shutdown`. A timeout still reports `exit: "timeout"`.
- **Audio is not handled**, as the spec says. Audio files are refused as binary, as before.
