# R9 report

**What changed**

- **Index (`src/index.rs`):** `$SYMBIA_HOME/index.sqlite`, derived data, rebuilt whenever it's missing.
  - It reads every session file and full seal read-only; thread seals are skipped.
  - There is one document per `(session, record)`. Seals are prefixes of their session's chain, so each source starts where its session already stands, and checkpoint copies aren't re-read.
  - Every file format is read; older files index as thread `main`.
  - Document text is the key plus the body's strings, capped at 8,000 characters. For a `tool_call`, up to 16 KB of each cited evidence stream is added when it's UTF-8.
  - Search is FTS5 with bm25. Refreshes are bounded at 2 s, and `index_behind` says when one ran out.
- **Vectors (`src/embed.rs`):**
  - `embed` takes `{url, model}` (loopback only) or `{server, model_path}`. In the second form Symbia starts `llama-server` on a free loopback port, waits for `/health` and kills it on drop.
  - Texts go 32 per request, with at most 256 pending documents embedded per search. The rest show as `unembedded`.
  - Vectors are stored as f32 blobs per model; a model change re-embeds.
  - Ranking is brute-force cosine, fused with keyword hits by reciprocal rank (k = 60).
- **`symbia_find`:** gains `scope` (`session` | `all`) and `similar`.
  - Session scope with only keyword filters keeps the old path.
  - With `scope: "all"`, hits carry `session` and `score`.
  - Every find is now recorded as a `tool_call` with a `retrieval` body: what was asked and the hit ids. Refusals are recorded too.
- **`symbia_report` (new, the 13th tool):**
  - Grouping: by thread, tool, kind, model or UTC day.
  - Per group: records, tool calls, chars, host ms, errors, refusals, and estimated-to-actual ratios.
  - Predictions: records, with results, open, and held and broke verdicts.
  - Filters: `since_ms`, `until_ms` and `in_thread`.
- **Stale schemas:** a client holding an older tool list sends unknown arguments as strings. Symbia now reads `"true"`/`"false"` and integer strings where the tool's schema wants a boolean or an integer (`coerce_args`). This came up live: the cloud session's tool list didn't refresh after the restart.
- **Other:** hyper's `client` feature moved into `[dependencies]`; no new crates. README gains Search and Report sections; there are 13 tools.

**Tests:** 223 pass (203 before); clippy is clean. Updated for finds being recorded: `map_e2e` (seq 3), `r6` (seal at seq 4), `r8_threads` (5 withheld), and `find_rejects_limit_over_50`. One full-suite run failed `r4` `sigterm_kills_a_running_job_records_it_and_seals` (the job's end record wasn't in the first verified seal). It passed 6 of 6 alone and on the next full run. That points to a timing race under load, logged as a gap and not fixed here.

**Live, on a copy of the real data folder** (8 sessions, 40 seals, 17 MB):

- The cold index of 935 records finished inside the 2 s budget.
- `scope: "all"` for "pipeline proof" returned the 7 Oct notarization record first.
- The report showed 19 prediction records: 16 with results and 3 open, with verdicts 5 held and 1 broke.
- A first query, "notarytool Accepted", returned nothing because no single record holds both words.

**Left out**

- No embedding model is installed yet, so vector search was tested only against the fake server and the Python stand-in.
- The r4 race.
