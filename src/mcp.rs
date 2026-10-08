//! MCP tool layer. Over stdio one server process is one session; over streamable HTTP
//! each MCP session (its `Mcp-Session-Id`) is one session file.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::Engine;
use ed25519_dalek::SigningKey;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::{IntoCallToolResult, ToolCallContext};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Extensions, ListToolsResult, PaginatedRequestParams, ProtocolVersion, Tool};
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::{ErrorData, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::canon::{canonical, hex_prefix, sha256};
use crate::files::{Facts, ReadOut, SEARCH_DEADLINE, SearchArgs};
use crate::http::Sessions;
use crate::jobs::Jobs;
use crate::policy::Policy;
use crate::record::{MAIN_THREAD, RecordInput, check_thread};
use crate::seal;
use crate::store::{Evidence, FIND_LIMIT_MAX, FindQuery, Store};

const PREFIX: usize = 12;
const SESSION_HEADER: &str = "mcp-session-id";
const NO_SESSION: &str = "no session: initialize an MCP session first (Mcp-Session-Id, protocol 2025-11-25 or earlier)";
pub(crate) const TOOL_LANE_REASON: &str = "tool output, not verified";
/// How long `symbia_job` kill waits for the job to end (its pipes get 2 s to drain).
const KILL_WAIT: Duration = Duration::from_millis(2_500);
/// `model` on a `tool_call` record when the client did not name itself.
pub(crate) const UNKNOWN_CLIENT: &str = "unknown";

#[derive(Clone)]
pub struct SymbiaServer {
    home: PathBuf,
    key: Arc<SigningKey>,
    /// `None` over streamable HTTP until the session id is known.
    store: Arc<Mutex<Option<Store>>>,
    /// Set over streamable HTTP: the expiry registry shared with the session manager.
    sessions: Option<Arc<Sessions>>,
    policy: Arc<Policy>,
    /// The MCP client's name from `initialize`, recorded as `model` on `tool_call` records.
    client: Arc<Mutex<Option<String>>>,
    /// Commands still running after their `symbia_exec` call returned.
    jobs: Arc<Jobs>,
    /// Set over stdio, where the session is opened on the first tool call that needs it.
    stdio: Option<Arc<Mutex<Stdio>>>,
    tool_router: ToolRouter<Self>,
}

/// The stdio process's session state.
#[derive(Debug, Default)]
struct Stdio {
    /// When this process started.
    started_ms: i64,
    /// A session was opened (or the server released); never open another.
    opened: bool,
    /// For the first tool reply after the session opened.
    notice: Option<String>,
    /// The session not resumed when a new one was opened.
    previous: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct FsReadArgs {
    /// Absolute path (a leading ~ is expanded).
    pub path: String,
    /// First line to return, 1-based; default 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Lines to return; default and cap 2,000. Replies are also capped at 256 KB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Images: skip the scaling to a 1,568 px long edge (the 8,000 px and 5 MB limits still apply).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct FsListArgs {
    /// Absolute directory path.
    pub path: String,
    /// Levels to descend, 1 to 5; default 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    /// Glob on the path relative to `path`, e.g. `**/*.rs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct FsSearchArgs {
    /// Regex (Rust syntax), or a literal string with `literal`.
    pub pattern: String,
    /// Absolute file or directory path.
    pub path: String,
    /// Glob on the file path relative to `path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub literal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignore_case: Option<bool>,
    /// Context lines before and after each match, at most 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<usize>,
    /// At most 200; default 50.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_matches: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct FsWriteArgs {
    /// Absolute path; parent directories are created.
    pub path: String,
    pub content: String,
    /// Refuse if the file already exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_only: Option<bool>,
    /// Append to the file, creating it if missing. Not with create_only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub append: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct FsEditArgs {
    /// Absolute path of a UTF-8 text file.
    pub path: String,
    /// Exact text to replace; must occur exactly once.
    pub old: String,
    pub new: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ExecArgs {
    /// Run as `/bin/zsh -lc <command>`.
    pub command: String,
    /// Absolute working directory.
    pub cwd: String,
    /// Default 120,000; at most 3,600,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Return a running job if the command has not ended by then. Default 45,000; at most 50,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yield_ms: Option<u64>,
    /// Size of the stdout and stderr tails in replies. Default 8,192; 256 to 65,536.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail_bytes: Option<usize>,
    /// Run outside the sandbox under a matching exec_unsandboxed rule: no shell, the rule's program by its absolute path, logged with sandbox "none". Refused when no rule matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsandboxed: Option<bool>,
}

/// Inlined in the schema: some clients send a `$ref`'d enum value as a bare word.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[schemars(inline)]
pub enum JobAction {
    #[default]
    Status,
    Wait,
    Tail,
    Kill,
}

impl JobAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Wait => "wait",
            Self::Tail => "tail",
            Self::Kill => "kill",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct JobArgs {
    /// Job id from symbia_exec.
    pub job: String,
    /// status (default), wait, tail or kill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<JobAction>,
    /// wait: how long to wait for the end. Default 45,000; at most 50,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    /// tail: bytes of each stream. Default the job's tail_bytes; 256 to 65,536.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<usize>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct FindArgs {
    /// Full-text terms matched against key and body; all terms must match.
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub lane: Option<String>,
    #[serde(default)]
    pub key_prefix: Option<String>,
    /// At most 50; default 20.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Only records in this thread.
    #[serde(default)]
    pub in_thread: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SealArgs {
    /// Seal only this thread: other threads' records are withheld, leaving their chain rows and digests.
    #[serde(default)]
    pub in_thread: Option<String>,
}

/// What `tools/list` says about the `thread` argument every tool takes.
pub const THREAD_DOC: &str = "Name of the conversation or agent making this call (1-64 characters from A-Z a-z 0-9 . _ : -). Pass the same value on every call; default main.";

tokio::task_local! {
    /// The tool call being handled: its thread and the key names of its `_meta`.
    static CALL: Call;
}

#[derive(Debug, Clone, Default)]
struct Call {
    thread: String,
    meta_keys: Vec<String>,
}

/// The current call's thread; `main` outside a call.
fn current_thread() -> String {
    CALL.try_with(|c| c.thread.clone()).unwrap_or_else(|_| MAIN_THREAD.to_string())
}

fn current_meta_keys() -> Vec<String> {
    CALL.try_with(|c| c.meta_keys.clone()).unwrap_or_default()
}

/// `t-` and 8 random hex digits: a thread name an agent can adopt.
fn new_thread() -> Result<String, String> {
    let mut r = [0u8; 4];
    getrandom::fill(&mut r).map_err(err)?;
    Ok(format!("t-{}", hex::encode(r)))
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct GetArgs {
    /// Record id. Give either id, or key with an optional version.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    /// Version for key; latest when omitted.
    #[serde(default)]
    pub version: Option<i64>,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl SymbiaServer {
    /// A stdio server under `home`, creating the layout and device key as needed and removing
    /// empty session files nobody holds. The session is opened (resumed or new) on the first
    /// tool call that needs it.
    pub fn new(home: &Path) -> anyhow::Result<Self> {
        crate::home::ensure(home)?;
        let key = crate::keys::load_or_create(home)?;
        let policy = Policy::from_env(home)?;
        if !policy.exec_unlock().is_empty() {
            eprintln!("symbia: exec_unlock is on; exec may use {}", policy.exec_unlock().join(", "));
        }
        if !policy.exec_unsandboxed().is_empty() {
            let programs: Vec<String> = policy.exec_unsandboxed().iter().map(|r| r.program.display().to_string()).collect();
            eprintln!("symbia: exec_unsandboxed is on; exec may run without the sandbox: {}", programs.join(", "));
        }
        crate::session::clean_empty(home);
        let stdio = Stdio { started_ms: crate::now_ms(), ..Stdio::default() };
        Ok(Self::assemble(home, Arc::new(key), None, Some(Arc::new(Mutex::new(stdio))), Arc::new(policy)))
    }

    /// A server for one streamable HTTP session. The session file is created when the
    /// first message carrying the `Mcp-Session-Id` arrives.
    pub fn for_http(home: &Path, key: Arc<SigningKey>, sessions: Arc<Sessions>, policy: Arc<Policy>) -> Self {
        Self::assemble(home, key, Some(sessions), None, policy)
    }

    fn assemble(home: &Path, key: Arc<SigningKey>, sessions: Option<Arc<Sessions>>, stdio: Option<Arc<Mutex<Stdio>>>, policy: Arc<Policy>) -> Self {
        let store = Arc::new(Mutex::new(None));
        let client: Arc<Mutex<Option<String>>> = Arc::default();
        let jobs = Arc::new(Jobs::new(store.clone(), key.clone(), client.clone()));
        Self { home: home.to_path_buf(), key, store, sessions, policy, client, jobs, stdio, tool_router: Self::tool_router() }
    }

    /// Close the stdio session on exit: drop its store, which releases and deletes its lock.
    /// No session is opened after this.
    pub fn release(&self) {
        let Ok(mut slot) = self.lock() else { return };
        if let Some(stdio) = &self.stdio
            && let Ok(mut st) = stdio.lock()
        {
            st.opened = true;
        }
        drop(slot.take());
    }

    /// The store slot, opening the stdio session first if this process has none yet.
    fn slot(&self) -> Result<MutexGuard<'_, Option<Store>>, String> {
        let mut slot = self.lock()?;
        if let (None, Some(stdio)) = (slot.as_ref(), &self.stdio) {
            let mut st = stdio.lock().map_err(|_| "state lock poisoned")?;
            if !st.opened {
                let me = crate::session::Holder::this_process(st.started_ms);
                let (store, opened) = crate::session::open(&self.home, self.policy.resume_window_ms(), me).map_err(err)?;
                st.opened = true;
                st.notice = Some(opened.notice(store.session()));
                st.previous = opened.previous_session().map(String::from);
                *slot = Some(store);
            }
        }
        Ok(slot)
    }

    /// The session notice, once: for the first tool reply after the session opened.
    fn take_notice(&self) -> Option<String> {
        self.stdio.as_ref()?.lock().ok()?.notice.take()
    }

    fn previous_session(&self) -> Option<String> {
        self.stdio.as_ref()?.lock().ok()?.previous.clone()
    }

    /// Kill running jobs and record them as killed by shutdown (on exit, before the seal).
    pub async fn shutdown_jobs(&self) {
        self.jobs.shutdown().await;
    }

    /// Replace the path policy (tests).
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    /// Seal the session if a record was written after its last seal (on exit). `None` when
    /// there is nothing to seal, including an HTTP server never bound to a session.
    pub fn seal_pending(&self) -> Result<Option<seal::Sealed>, String> {
        match self.lock()?.as_ref() {
            Some(store) => seal::seal_pending(store, &self.key).map_err(err),
            None => Ok(None),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Option<Store>>, String> {
        self.store.lock().map_err(|_| "state lock poisoned".to_string())
    }

    fn model(&self) -> String {
        self.client.lock().ok().and_then(|c| c.clone()).unwrap_or_else(|| UNKNOWN_CLIENT.into())
    }

    /// Run a blocking file tool off the async workers, then record it.
    async fn file_tool<A, F>(&self, tool: &'static str, args: A, f: F) -> Result<String, String>
    where
        A: Serialize + Send + 'static,
        F: FnOnce(&Policy, &A, &mut Facts) -> Result<String, String> + Send + 'static,
    {
        let started = Instant::now();
        let digest = self.begin(&args)?;
        let policy = self.policy.clone();
        let (facts, result) = tokio::task::spawn_blocking(move || {
            let mut facts = Facts::default();
            let r = f(&policy, &args, &mut facts);
            (facts, r)
        })
        .await
        .map_err(err)?;
        self.log(tool, &digest, started, &facts, result, &[])
    }

    /// Refuse before doing any work if there is no session to record the call in; return the args digest.
    fn begin(&self, args: &impl Serialize) -> Result<String, String> {
        if self.slot()?.is_none() {
            return Err(NO_SESSION.into());
        }
        Ok(hex::encode(sha256(canonical(args).map_err(err)?.as_bytes())))
    }

    /// Write the call's `tool_call` record, then hand back its reply (or error) unchanged.
    fn log(&self, tool: &str, digest: &str, started: Instant, facts: &Facts, result: Result<String, String>, evidence: &[Evidence]) -> Result<String, String> {
        self.log_sized(tool, digest, started, facts, result, 0, evidence).map(|(text, _)| text)
    }

    /// As [`Self::log`], where the reply also carries `extra` bytes besides the text (an
    /// image); a success comes back with the record's id.
    #[allow(clippy::too_many_arguments)]
    fn log_sized(&self, tool: &str, digest: &str, started: Instant, facts: &Facts, result: Result<String, String>, extra: usize, evidence: &[Evidence]) -> Result<(String, String), String> {
        let text = match &result {
            Ok(t) | Err(t) => t,
        };
        let mut body = serde_json::to_value(facts).map_err(err)?;
        body["tool"] = tool.into();
        body["args_digest"] = digest.into();
        body["bytes_returned"] = (text.len() + extra).into();
        if let Err(e) = &result {
            body["error"] = e.as_str().into();
        }
        let meta_keys = current_meta_keys();
        if !meta_keys.is_empty() {
            body["client_meta_keys"] = meta_keys.into();
        }
        let thread = current_thread();
        let input = RecordInput {
            key: format!("tool.{tool}"),
            kind: "tool_call".into(),
            lane: "apocryphal".into(),
            lane_reason: TOOL_LANE_REASON.into(),
            body,
            model: self.model(),
            est_host_ms: None,
            est_chars: None,
            links: None,
        };
        let id = self.with_store(|s| {
            let w = s.write_in(&thread, &input, started, Some(text.chars().count() + extra), evidence).map_err(err)?;
            self.checkpoint(s, &input.kind);
            Ok(w.id)
        })?;
        result.map(|t| (t, id))
    }

    /// The tool list as served: every tool also takes `thread`.
    pub fn tools(&self) -> Vec<Tool> {
        let mut tools = self.tool_router.list_all();
        for t in &mut tools {
            let schema = Arc::make_mut(&mut t.input_schema);
            let props = schema.entry("properties").or_insert_with(|| json!({}));
            if let Some(p) = props.as_object_mut() {
                p.insert("thread".into(), json!({"type": "string", "description": THREAD_DOC}));
            }
        }
        tools
    }

    /// Refuse a call whose `thread` is invalid, recording the refusal in `main`.
    fn refuse_call(&self, request: &CallToolRequestParams, error: String) -> Result<String, String> {
        let digest = canonical(&request.arguments).map(|c| hex::encode(sha256(c.as_bytes()))).unwrap_or_default();
        let tool = request.name.to_string();
        self.log(&tool, &digest, Instant::now(), &Facts::default(), Err(error), &[])
    }

    /// Seal if a checkpoint is due after a write. A failure goes to stderr and never fails the write.
    fn checkpoint(&self, store: &Store, kind: &str) {
        if let Err(e) = seal::checkpoint(store, &self.key, kind) {
            eprintln!("symbia: checkpoint seal of {} failed: {e:#}", store.session());
        }
    }

    fn with_store<T>(&self, f: impl FnOnce(&mut Store) -> Result<T, String>) -> Result<T, String> {
        let mut slot = self.slot()?;
        let store = slot.as_mut().ok_or(NO_SESSION)?;
        f(store)
    }

    /// Over streamable HTTP, tie this server to the request's `Mcp-Session-Id`, creating its
    /// session file on first sight. Requests without the header are left unbound.
    pub fn bind(&self, extensions: &Extensions) -> Result<(), String> {
        let Some(sessions) = &self.sessions else { return Ok(()) };
        let Some(id) = extensions
            .get::<http::request::Parts>()
            .and_then(|p| p.headers.get(SESSION_HEADER))
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(());
        };
        let mut slot = self.lock()?;
        match slot.as_ref() {
            Some(store) => {
                if store.mcp_session_id().map_err(err)?.as_deref() != Some(id) {
                    return Err("Mcp-Session-Id does not match this session".into());
                }
            }
            None => {
                let store = Store::create_for_mcp(&self.home, Some(id)).map_err(err)?;
                sessions.insert(id, store.expires_ms().map_err(err)?.unwrap_or(i64::MAX));
                sessions.track(&self.store);
                sessions.track_jobs(&self.jobs);
                *slot = Some(store);
            }
        }
        Ok(())
    }
}

#[tool_router]
impl SymbiaServer {
    #[tool(
        title = "Session status",
        annotations(title = "Session status", read_only_hint = true, open_world_hint = false),
        description = "Session status: build, session and when it started, MCP session id, expiry, retention, file, chain seq and head, last seal, public key, running jobs, resumes after server restarts, the previous session when it was not resumed, the caller's thread, the threads written most recently, and new_thread, a fresh thread name to adopt."
    )]
    pub async fn symbia_status(&self) -> Result<String, String> {
        let jobs = self.jobs.running();
        let fresh = new_thread()?;
        self.with_store(|store| {
            let (seq, head) = store.head().map_err(err)?;
            let last = seal::last_seal(store.home(), store.session())
                .map(|(_, s)| json!({"chain_seq": s.chain_seq, "file_sha256": &s.file_sha256[..PREFIX]}));
            Ok(json!({
                "build": crate::BUILD,
                "session": store.session(),
                "session_started_ms": store.started_ms(),
                "mcp_session_id": store.mcp_session_id().map_err(err)?,
                "expires_ms": store.expires_ms().map_err(err)?,
                "retention": store.retention().map_err(err)?,
                "file": store.path().display().to_string(),
                "seq": seq,
                "head": hex_prefix(&head, PREFIX),
                "last_seal": last,
                "public_key": hex_prefix(&self.key.verifying_key().to_bytes(), PREFIX),
                "jobs": jobs,
                "exec_unlock": self.policy.exec_unlock(),
                "exec_unsandboxed": self.policy.exec_unsandboxed().iter().map(|r| r.describe()).collect::<Vec<_>>(),
                "resumes": crate::session::resumes(store).map_err(err)?,
                "previous_session": self.previous_session(),
                "thread": current_thread(),
                "threads": store.threads(20).map_err(err)?,
                "new_thread": fresh,
            })
            .to_string())
        })
    }

    #[tool(
        title = "Write a record",
        annotations(title = "Write a record", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false),
        description = "Write a record to the ledger. links is a list of {\"to_id\": \"<record id>\", \"rel\": \"<rel>\"}, rel one of results_of, revises, supersedes, cites; the target may be in an earlier session. A prediction is sealed at once. Returns {id, version, seq, head}."
    )]
    pub async fn symbia_record(&self, Parameters(args): Parameters<RecordInput>) -> Result<String, String> {
        let started = Instant::now();
        self.with_store(|store| {
            let reply = store.write_in(&current_thread(), &args, started, None, &[]).map_err(err)?.reply();
            self.checkpoint(store, &args.kind);
            Ok(reply)
        })
    }

    #[tool(
        title = "Find records",
        annotations(title = "Find records", read_only_hint = true, open_world_hint = false),
        description = "Find records by full-text query, kind, lane, key prefix or thread (in_thread). Returns [{id, key, version, kind, lane, thread}]."
    )]
    pub async fn symbia_find(&self, Parameters(args): Parameters<FindArgs>) -> Result<String, String> {
        if args.limit.is_some_and(|l| l > FIND_LIMIT_MAX) {
            return Err(format!("limit must be at most {FIND_LIMIT_MAX}"));
        }
        self.with_store(|store| {
            let hits = store
                .find(&FindQuery { query: args.query, kind: args.kind, lane: args.lane, key_prefix: args.key_prefix, limit: args.limit, thread: args.in_thread })
                .map_err(err)?;
            serde_json::to_string(&hits).map_err(err)
        })
    }

    #[tool(
        title = "Get a record",
        annotations(title = "Get a record", read_only_hint = true, open_world_hint = false),
        description = "Get one full record with its links, by id or by key and optional version."
    )]
    pub async fn symbia_get(&self, Parameters(args): Parameters<GetArgs>) -> Result<String, String> {
        self.with_store(|store| {
            let id = match (args.id, args.key) {
                (Some(id), None) if args.version.is_none() => id,
                (None, Some(key)) => store.id_for_key(&key, args.version).map_err(err)?.ok_or("no such record")?,
                _ => return Err("give either id, or key with an optional version".into()),
            };
            let rec = store.get(&id).map_err(err)?.ok_or("no such record")?;
            Ok(rec.to_string())
        })
    }

    #[tool(
        title = "Seal the session",
        annotations(title = "Seal the session", read_only_hint = false, destructive_hint = false, idempotent_hint = true, open_world_hint = false),
        description = "Seal the session: signed, verified copy under seals/. Returns {path, file_sha256, chain_seq, verified}. With in_thread, seal one thread: the copy keeps that thread's records and only the chain rows and digests of the others, and verifies against the same chain head. Returns {path, file_sha256, chain_seq, thread, records, withheld, verified}."
    )]
    pub async fn symbia_seal(&self, Parameters(args): Parameters<SealArgs>) -> Result<String, String> {
        self.with_store(|store| {
            if let Some(thread) = &args.in_thread {
                let t = seal::seal_thread(store, &self.key, thread).map_err(err)?;
                return Ok(json!({
                    "path": t.sealed.path.display().to_string(),
                    "file_sha256": &t.sealed.sidecar.file_sha256[..PREFIX],
                    "chain_seq": t.sealed.sidecar.chain_seq,
                    "thread": thread,
                    "records": t.records,
                    "withheld": t.withheld,
                    "verified": t.sealed.verified,
                })
                .to_string());
            }
            let s = seal::seal(store, &self.key).map_err(err)?;
            Ok(json!({
                "path": s.path.display().to_string(),
                "file_sha256": &s.sidecar.file_sha256[..PREFIX],
                "chain_seq": s.sidecar.chain_seq,
                "verified": s.verified,
            })
            .to_string())
        })
    }

    #[tool(
        title = "Read a file",
        annotations(title = "Read a file", read_only_hint = true, open_world_hint = false),
        description = "Read a text file with 1-based line numbers. Caps: 2,000 lines and 256 KB; the reply says which limit cut it and where to continue. PNG, JPEG, GIF, WebP, TIFF and BMP files come back as an image (scaled to a 1,568 px long edge unless full; at most 8,000 px and 5 MB) plus {path, format, width, height, sent_width, sent_height, bytes, sha256} of the image sent. Other binary files (HEIC, audio) are refused with size and sha256."
    )]
    pub async fn symbia_fs_read(&self, Parameters(args): Parameters<FsReadArgs>) -> Result<CallToolResult, String> {
        const TOOL: &str = "symbia_fs_read";
        let started = Instant::now();
        let digest = self.begin(&args)?;
        let policy = self.policy.clone();
        let evidence = self.home.join("evidence");
        let (facts, result) = tokio::task::spawn_blocking(move || {
            let mut facts = Facts::default();
            let r = crate::files::read_any(&policy, &evidence, &args.path, args.offset, args.limit, args.full.unwrap_or(false), &mut facts);
            (facts, r)
        })
        .await
        .map_err(err)?;
        let text = match result {
            Ok(ReadOut::Image(img)) => {
                let data = base64::engine::general_purpose::STANDARD.encode(&img.bytes);
                let ev = Evidence { sha256: img.sha256, bytes: i64::try_from(img.bytes.len()).unwrap_or(i64::MAX), media: img.media };
                let (text, _) = self.log_sized(TOOL, &digest, started, &facts, Ok(img.text), data.len(), &[ev])?;
                return Ok(CallToolResult::success(vec![ContentBlock::image(data, img.media), ContentBlock::text(text)]));
            }
            Ok(ReadOut::Text(t)) => Ok(t),
            Err(e) => Err(e),
        };
        self.log(TOOL, &digest, started, &facts, text, &[]).map(|t| CallToolResult::success(vec![ContentBlock::text(t)]))
    }

    #[tool(
        title = "List a folder",
        annotations(title = "List a folder", read_only_hint = true, open_world_hint = false),
        description = "List a directory to depth 1-5 with type, size and mtime_ms; optional glob. Cap 1,000 entries, with a truncated flag."
    )]
    pub async fn symbia_fs_list(&self, Parameters(args): Parameters<FsListArgs>) -> Result<String, String> {
        self.file_tool("symbia_fs_list", args, |p, a, f| crate::files::list(p, &a.path, a.depth, a.glob.as_deref(), f)).await
    }

    #[tool(
        title = "Search files",
        annotations(title = "Search files", read_only_hint = true, open_world_hint = false),
        description = "Search files (ripgrep engine, respects .gitignore) for a regex or literal. Returns matches with file, line and context. Stops at max_matches or 30 s, flagged."
    )]
    pub async fn symbia_fs_search(&self, Parameters(args): Parameters<FsSearchArgs>) -> Result<String, String> {
        self.file_tool("symbia_fs_search", args, |p, a, f| {
            let s = SearchArgs {
                pattern: &a.pattern,
                path: &a.path,
                glob: a.glob.as_deref(),
                literal: a.literal.unwrap_or(false),
                ignore_case: a.ignore_case.unwrap_or(false),
                context: a.context,
                max_matches: a.max_matches,
            };
            crate::files::search(p, &s, SEARCH_DEADLINE, f)
        })
        .await
    }

    #[tool(
        title = "Write a file",
        annotations(title = "Write a file", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false),
        description = "Write a file atomically (temp file then rename), or with append add to its end (created if missing). Returns {path, bytes, sha256}; append adds size."
    )]
    pub async fn symbia_fs_write(&self, Parameters(args): Parameters<FsWriteArgs>) -> Result<String, String> {
        self.file_tool("symbia_fs_write", args, |p, a, f| match (a.create_only.unwrap_or(false), a.append.unwrap_or(false)) {
            (true, true) => {
                f.path = Some(a.path.clone());
                Err("create_only and append cannot both be set".into())
            }
            (create_only, false) => crate::files::write(p, &a.path, &a.content, create_only, f),
            (false, true) => crate::files::append(p, &a.path, &a.content, f),
        })
        .await
    }

    #[tool(
        title = "Edit a file",
        annotations(title = "Edit a file", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = false),
        description = "Replace one exact occurrence of old with new, atomically. Refuses zero or several matches. Returns {path, line, sha256_before, sha256_after}."
    )]
    pub async fn symbia_fs_edit(&self, Parameters(args): Parameters<FsEditArgs>) -> Result<String, String> {
        self.file_tool("symbia_fs_edit", args, |p, a, f| crate::files::edit(p, &a.path, &a.old, &a.new, f)).await
    }

    #[tool(
        title = "Run a command",
        annotations(title = "Run a command", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true),
        description = "Run /bin/zsh -lc <command> in cwd (off macOS: zsh, else bash, else sh), in its own process group; killed with its children at timeout_ms. Returns exit (or \"timeout\"), duration_ms and the last tail_bytes (default 8 KB) of stdout and stderr; full output is saved at the named evidence path; an empty stream is left out. If it is still running after yield_ms (default 45 s), returns {job, running: true, pid, started_ms} and the output so far at once, and the command keeps running: follow it with symbia_job. Commands run sandboxed: deny-list paths are off limits, the home folder is unreadable outside the roots and a few toolchain files (exec_read), the data directory is read-only, and network may be off. Commands matching exec_deny or Claude Code's Bash(...) deny rules are refused; that check is a policy convenience, not a boundary (eval, $(...), sh -c and scripts get around it); the sandbox is the boundary. With unsandboxed: true, a command matching an exec_unsandboxed rule runs outside the sandbox: no shell (no pipes, redirects, variables, ~ or globs), the rule's program by its absolute path, recorded with sandbox \"none\". That is a short logged list, not containment: a rule for a program that can run arbitrary code grants exactly that."
    )]
    pub async fn symbia_exec(&self, Parameters(args): Parameters<ExecArgs>) -> Result<String, String> {
        const TOOL: &str = "symbia_exec";
        let started = Instant::now();
        let digest = self.begin(&args)?;
        let mut facts = Facts::default();
        let yield_ms = args.yield_ms.unwrap_or(crate::exec::YIELD_DEFAULT_MS);
        let job = if yield_ms > crate::exec::YIELD_MAX_MS {
            facts.command = Some(args.command.clone());
            Err(format!("yield_ms must be at most {}", crate::exec::YIELD_MAX_MS))
        } else {
            let req = crate::exec::Request { command: &args.command, cwd: &args.cwd, unsandboxed: args.unsandboxed.unwrap_or(false) };
            crate::exec::start_request(&self.policy, &self.home, &req, args.timeout_ms, args.tail_bytes, &mut facts)
        };
        let job = match job {
            Ok(j) => j,
            Err(e) => return self.log(TOOL, &digest, started, &facts, Err(e), &[]),
        };
        if job.wait(Some(Duration::from_millis(yield_ms))).await {
            return match job.ran(&mut facts) {
                Ok(r) => self.log(TOOL, &digest, started, &facts, Ok(r.reply), &[r.stdout.evidence(), r.stderr.evidence()]),
                Err(e) => self.log(TOOL, &digest, started, &facts, Err(e), &[]),
            };
        }
        let id = match crate::jobs::new_id() {
            Ok(id) => id,
            Err(e) => {
                job.kill(TOOL);
                return self.log(TOOL, &digest, started, &facts, Err(e), &[]);
            }
        };
        facts.job = Some(id.clone());
        facts.running = Some(true);
        let mut reply = job.status(job.tail_bytes);
        reply["job"] = id.as_str().into();
        reply.as_object_mut().map(|o| o.remove("duration_ms"));
        match self.log_sized(TOOL, &digest, started, &facts, Ok(reply.to_string()), 0, &[]) {
            Ok((text, start_id)) => {
                self.jobs.insert(&id, job, start_id, current_thread());
                Ok(text)
            }
            Err(e) => {
                // No start record, so no job to follow.
                job.kill(TOOL);
                Err(e)
            }
        }
    }

    #[tool(
        title = "Check a job",
        annotations(title = "Check a job", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = false),
        description = "Follow a command symbia_exec left running. action: status (default), wait (up to wait_ms, default 45,000, at most 50,000), tail (bytes of each stream, 256 to 65,536) or kill (the whole process group). Returns {job, running, pid, started_ms, duration_ms, stdout, stderr}; once it has ended also exit (or \"timeout\" or \"killed\") and evidence paths."
    )]
    pub async fn symbia_job(&self, Parameters(args): Parameters<JobArgs>) -> Result<String, String> {
        const TOOL: &str = "symbia_job";
        let started = Instant::now();
        let digest = self.begin(&args)?;
        let action = args.action.unwrap_or_default();
        let mut facts = Facts { job: Some(args.job.clone()), action: Some(action.as_str()), ..Facts::default() };
        let result = self.job_action(&args, action, &mut facts).await;
        self.log(TOOL, &digest, started, &facts, result, &[])
    }
}

impl SymbiaServer {
    async fn job_action(&self, args: &JobArgs, action: JobAction, facts: &mut Facts) -> Result<String, String> {
        use crate::exec::{TAIL_MAX, TAIL_MIN, YIELD_DEFAULT_MS, YIELD_MAX_MS};
        let job = self.jobs.get(&args.job).ok_or_else(|| format!("no such job: {}", args.job))?;
        let mut n = job.tail_bytes;
        match action {
            JobAction::Status => {}
            JobAction::Wait => {
                let ms = args.wait_ms.unwrap_or(YIELD_DEFAULT_MS);
                if ms > YIELD_MAX_MS {
                    return Err(format!("wait_ms must be at most {YIELD_MAX_MS}"));
                }
                job.wait(Some(Duration::from_millis(ms))).await;
            }
            JobAction::Tail => {
                n = args.bytes.unwrap_or(n);
                if !(TAIL_MIN..=TAIL_MAX).contains(&n) {
                    return Err(format!("bytes must be {TAIL_MIN} to {TAIL_MAX}"));
                }
            }
            JobAction::Kill => {
                job.kill("symbia_job");
                job.wait(Some(KILL_WAIT)).await;
            }
        }
        // The end record goes in before this call's own record.
        self.jobs.settle(&args.job);
        facts.running = Some(job.running());
        if let Some(Ok(f)) = job.outcome() {
            facts.exit = Some(f.exit.clone());
        }
        let mut reply = job.status(n);
        reply["job"] = args.job.as_str().into();
        Ok(reply.to_string())
    }
}

/// Add `notice` to the reply's JSON object, or as a text block of its own when the reply has none.
fn add_notice(res: &mut CallToolResult, notice: String) {
    for block in &mut res.content {
        if let ContentBlock::Text(t) = block
            && let Ok(serde_json::Value::Object(mut o)) = serde_json::from_str::<serde_json::Value>(&t.text)
        {
            o.insert("notice".into(), notice.into());
            t.text = serde_json::Value::Object(o).to_string();
            return;
        }
    }
    res.content.push(ContentBlock::text(json!({"notice": notice}).to_string()));
}

#[tool_handler(router = self.tool_router, name = "symbia")]
impl ServerHandler for SymbiaServer {
    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>) -> Result<CallToolResponse, ErrorData> {
        if let Err(e) = self.bind(&context.extensions) {
            return Result::<String, String>::Err(e).into_call_tool_result();
        }
        if let Some(info) = context.peer.peer_info()
            && let Ok(mut c) = self.client.lock()
        {
            *c = Some(info.client_info.name.clone());
        }
        // `thread` belongs to the call, not the tool: take it out before the tool sees its arguments.
        let mut request = request;
        let thread = match request.arguments.as_mut().and_then(|a| a.remove("thread")) {
            None | Some(serde_json::Value::Null) => MAIN_THREAD.to_string(),
            Some(serde_json::Value::String(s)) => s,
            Some(other) => other.to_string(),
        };
        let mut meta_keys: Vec<String> = context.meta.keys().cloned().collect();
        meta_keys.sort();
        if let Err(e) = check_thread(&thread) {
            return self.refuse_call(&request, e).into_call_tool_result();
        }
        let call = Call { thread, meta_keys };
        let r = CALL.scope(call, self.tool_router.call(ToolCallContext::new(self, request, context))).await;
        match r {
            Ok(CallToolResponse::Complete(mut res)) => {
                if let Some(n) = self.take_notice() {
                    add_notice(&mut res, n);
                }
                Ok(CallToolResponse::Complete(res))
            }
            other => other,
        }
    }

    async fn list_tools(&self, _request: Option<PaginatedRequestParams>, _context: RequestContext<RoleServer>) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.tools()))
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        // A mismatch here is reported again on the next tool call.
        let _ = self.bind(&context.extensions);
    }

    /// Sessions exist only up to protocol 2025-11-25, so streamable HTTP stops there.
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        if self.sessions.is_some() {
            Cow::Borrowed(ProtocolVersion::known_up_to(&ProtocolVersion::V_2025_11_25))
        } else {
            Cow::Borrowed(ProtocolVersion::KNOWN_VERSIONS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn server() -> (tempfile::TempDir, SymbiaServer) {
        let t = tempfile::tempdir().unwrap();
        let s = SymbiaServer::new(t.path()).unwrap();
        (t, s)
    }

    /// The temp dir is the only root, the user home and `SYMBIA_HOME` at once.
    fn policy(home: &Path) -> Arc<Policy> {
        Arc::new(Policy::new(&[home.to_path_buf()], home, home).unwrap())
    }

    fn tool_calls(s: &SymbiaServer) -> Vec<Value> {
        s.with_store(|st| {
            let ids: Vec<String> = st
                .conn()
                .prepare("SELECT r.id FROM records r JOIN chain c ON c.record_id = r.id WHERE r.kind = 'tool_call' ORDER BY c.seq")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            Ok(ids.iter().map(|id| st.get(id).unwrap().unwrap()).collect())
        })
        .unwrap()
    }

    fn exec_args(command: &str, cwd: &Path) -> ExecArgs {
        ExecArgs { command: command.into(), cwd: cwd.display().to_string(), timeout_ms: None, yield_ms: None, tail_bytes: None, unsandboxed: None }
    }

    /// A server whose only root is a fresh temp dir outside its `SYMBIA_HOME`.
    fn rooted() -> (tempfile::TempDir, tempfile::TempDir, SymbiaServer) {
        let (t, s) = server();
        let w = tempfile::tempdir().unwrap();
        let s = s.with_policy(Policy::new(&[w.path().to_path_buf()], t.path(), t.path()).unwrap());
        (t, w, s)
    }

    fn all_records(s: &SymbiaServer) -> Vec<Value> {
        s.with_store(|st| {
            let ids: Vec<String> =
                st.conn().prepare("SELECT record_id FROM chain ORDER BY seq").unwrap().query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
            Ok(ids.iter().map(|id| st.get(id).unwrap().unwrap()).collect())
        })
        .unwrap()
    }

    fn job_call(s: &SymbiaServer, job: &str, action: JobAction) -> impl Future<Output = Result<String, String>> {
        s.symbia_job(Parameters(JobArgs { job: job.into(), action: Some(action), wait_ms: None, bytes: None }))
    }

    fn alive(pid: i64) -> bool {
        // SAFETY: signal 0 only checks that the process exists.
        unsafe { libc::kill(i32::try_from(pid).unwrap(), 0) == 0 }
    }

    mod images {
        use super::*;
        use ::image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
        use base64::Engine;

        fn encode(w: u32, h: u32, f: ImageFormat) -> Vec<u8> {
            let img = ImageBuffer::from_fn(w, h, |x, y| Rgb([(x % 251) as u8, (y % 241) as u8, ((x + y) % 239) as u8]));
            let mut out = std::io::Cursor::new(Vec::new());
            DynamicImage::ImageRgb8(img).write_to(&mut out, f).unwrap();
            out.into_inner()
        }

        async fn read(s: &SymbiaServer, path: &Path, full: Option<bool>) -> Result<CallToolResult, String> {
            s.symbia_fs_read(Parameters(FsReadArgs { path: path.display().to_string(), offset: None, limit: None, full })).await
        }

        /// The image block's media type and bytes, and the text block as JSON.
        fn parts(r: &CallToolResult) -> (String, Vec<u8>, Value) {
            assert_eq!(r.content.len(), 2);
            let img = r.content[0].as_image().expect("an image block first");
            let bytes = base64::engine::general_purpose::STANDARD.decode(&img.data).unwrap();
            let text: Value = serde_json::from_str(&r.content[1].as_text().expect("then text").text).unwrap();
            (img.mime_type.clone(), bytes, text)
        }

        #[tokio::test]
        async fn images_come_back_as_image_content_scaled_to_fit() {
            let (t, w, s) = rooted();
            let cases = [
                ("small.png", encode(40, 30, ImageFormat::Png), "image/png", (40, 30)),
                ("photo.jpg", encode(4000, 3000, ImageFormat::Jpeg), "image/jpeg", (1568, 1176)),
                ("anim.gif", encode(64, 48, ImageFormat::Gif), "image/gif", (64, 48)),
                ("wide.bmp", encode(2000, 1000, ImageFormat::Bmp), "image/png", (1568, 784)),
                // The name says text; the bytes say PNG.
                ("misnamed.txt", encode(10, 10, ImageFormat::Png), "image/png", (10, 10)),
            ];
            for (name, data, media, sent) in &cases {
                let f = w.path().join(name);
                std::fs::write(&f, data).unwrap();
                let r = read(&s, &f, None).await.unwrap();
                let (mime, bytes, text) = parts(&r);
                assert_eq!(mime, *media, "{name}");
                assert_eq!((text["sent_width"].as_u64().unwrap(), text["sent_height"].as_u64().unwrap()), (u64::from(sent.0), u64::from(sent.1)), "{name}");
                assert_eq!(text["bytes"], bytes.len());
                let sha = hex::encode(sha256(&bytes));
                assert_eq!(text["sha256"], sha);
                assert_eq!(text["path"], std::fs::canonicalize(&f).unwrap().display().to_string());
                // The image as sent is evidence, so a seal covers what the model saw.
                assert_eq!(std::fs::read(t.path().join("evidence").join(&sha)).unwrap(), bytes, "{name}");
                let decoded = ::image::load_from_memory(&bytes).unwrap();
                assert_eq!((decoded.width(), decoded.height()), *sent, "{name}");
                if !name.ends_with(".bmp") && !name.ends_with(".jpg") {
                    assert_eq!(&bytes, data, "{name} fits, so it goes out unchanged");
                }
            }
            let recs = tool_calls(&s);
            let jpg = &recs[1]["body"];
            assert_eq!(jpg["sha256_before"], hex::encode(sha256(&cases[1].1)));
            assert_eq!(jpg["image"]["format"], "jpeg");
            assert_eq!((jpg["image"]["width"].clone(), jpg["image"]["height"].clone()), (json!(4000), json!(3000)));
            assert_eq!((jpg["image"]["sent_width"].clone(), jpg["image"]["sent_height"].clone()), (json!(1568), json!(1176)));
            let sent_sha = jpg["image"]["sent_sha256"].as_str().unwrap();
            assert_eq!(recs[3]["body"]["image"]["format"], "bmp");
            let media: String = s
                .with_store(|st| Ok(st.conn().query_row("SELECT media FROM evidence WHERE sha256 = ?1", [hex::decode(sent_sha).unwrap()], |r| r.get(0)).unwrap()))
                .unwrap();
            assert_eq!(media, "image/jpeg");
        }

        #[tokio::test]
        async fn full_skips_the_resize() {
            let (_t, w, s) = rooted();
            let f = w.path().join("photo.jpg");
            let data = encode(4000, 3000, ImageFormat::Jpeg);
            std::fs::write(&f, &data).unwrap();
            let (mime, bytes, text) = parts(&read(&s, &f, Some(true)).await.unwrap());
            assert_eq!(mime, "image/jpeg");
            assert_eq!((text["sent_width"].clone(), text["sent_height"].clone()), (json!(4000), json!(3000)));
            assert_eq!(bytes, data);
            // Past 8,000 px on an edge, even full is scaled down.
            let f = w.path().join("tall.png");
            std::fs::write(&f, encode(100, 9000, ImageFormat::Png)).unwrap();
            let (mime, _, text) = parts(&read(&s, &f, Some(true)).await.unwrap());
            assert_eq!(mime, "image/png");
            assert_eq!((text["sent_width"].clone(), text["sent_height"].clone()), (json!(89), json!(8000)));
        }

        #[tokio::test]
        async fn other_binaries_are_still_refused() {
            let (_t, w, s) = rooted();
            let f = w.path().join("blob.bin");
            let bytes = [0u8, 1, 2, 3, 0xff, 0xfe];
            std::fs::write(&f, bytes).unwrap();
            let e = read(&s, &f, None).await.unwrap_err();
            assert_eq!(e, format!("binary file refused: 6 bytes, sha256 {}", hex::encode(sha256(&bytes))));
            let f = w.path().join("photo.heic");
            std::fs::write(&f, b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic\x00\x00").unwrap();
            let e = read(&s, &f, None).await.unwrap_err();
            assert!(e.starts_with("binary file refused") && e.contains("HEIC images are not supported"), "{e}");
            // Text is unchanged: one text block.
            std::fs::write(w.path().join("a.txt"), "hi\n").unwrap();
            let r = read(&s, &w.path().join("a.txt"), None).await.unwrap();
            assert_eq!(r.content.len(), 1);
            assert_eq!(r.content[0].as_text().unwrap().text, "     1\thi\n");
            let recs = tool_calls(&s);
            assert!(recs.iter().all(|r| r["body"].get("image").is_none()));
            // The path policy applies as for any read.
            let e = read(&s, Path::new("/etc/hosts"), None).await.unwrap_err();
            assert!(e.starts_with("denied"), "{e}");
        }
    }

    mod jobs {
        use super::*;

        async fn exec(s: &SymbiaServer, cmd: &str, cwd: &Path, yield_ms: u64, timeout_ms: Option<u64>) -> Value {
            let a = ExecArgs { yield_ms: Some(yield_ms), timeout_ms, ..exec_args(cmd, cwd) };
            serde_json::from_str(&s.symbia_exec(Parameters(a)).await.unwrap()).unwrap()
        }

        fn parse(r: Result<String, String>) -> Value {
            serde_json::from_str(&r.unwrap()).unwrap()
        }

        #[tokio::test]
        async fn a_slow_command_becomes_a_job_and_wait_returns_its_end() {
            let (_t, w, s) = rooted();
            let r = exec(&s, "echo started; sleep 2; echo done", w.path(), 500, None).await;
            let id = r["job"].as_str().unwrap().to_string();
            assert_eq!(r["running"], true);
            assert!(r["pid"].as_i64().is_some() && r["started_ms"].as_i64().unwrap() <= crate::now_ms());
            assert_eq!(r["stdout"]["tail"], "started\n");
            assert!(r.get("exit").is_none());
            let status: Value = serde_json::from_str(&s.symbia_status().await.unwrap()).unwrap();
            assert_eq!(status["jobs"][0]["job"], id.as_str());
            let st = parse(job_call(&s, &id, JobAction::Status).await);
            assert_eq!(st["running"], true);
            let done = parse(job_call(&s, &id, JobAction::Wait).await);
            assert_eq!((done["running"].clone(), done["exit"].clone()), (json!(false), json!(0)), "{done}");
            assert_eq!(done["stdout"]["tail"], "started\ndone\n");
            assert!(done["duration_ms"].as_u64().unwrap() >= 2000);
            let ev = done["stdout"]["evidence"].as_str().unwrap();
            assert_eq!(std::fs::read_to_string(ev).unwrap(), "started\ndone\n");
            let status: Value = serde_json::from_str(&s.symbia_status().await.unwrap()).unwrap();
            assert_eq!(status["jobs"], json!([]));

            // Records: the start, the end (revising the start), then the job calls.
            let recs = all_records(&s);
            let keys: Vec<&str> = recs.iter().map(|r| r["key"].as_str().unwrap()).collect();
            let end_key = format!("job.{id}");
            assert_eq!(keys, ["tool.symbia_exec", "tool.symbia_job", end_key.as_str(), "tool.symbia_job"]);
            let (start, end) = (&recs[0], &recs[2]);
            assert_eq!((start["body"]["job"].as_str(), start["body"]["running"].clone()), (Some(id.as_str()), json!(true)));
            assert!(start["body"].get("exit").is_none());
            assert_eq!(end["kind"], "tool_call");
            assert_eq!(end["body"]["exit"], 0);
            assert_eq!(end["body"]["stdout_sha256"], hex::encode(sha256(b"started\ndone\n")));
            assert!(end["body"]["duration_ms"].as_u64().unwrap() >= 2000);
            assert_eq!(end["links"], json!([{"to_id": start["id"], "rel": "revises", "to_session": null}]));
            let n: i64 = s
                .with_store(|st| Ok(st.conn().query_row("SELECT COUNT(*) FROM evidence WHERE sha256 = ?1", [sha256(b"started\ndone\n").to_vec()], |r| r.get(0)).unwrap()))
                .unwrap();
            assert_eq!(n, 1);
            let last = &recs[3]["body"];
            assert_eq!((last["action"].as_str(), last["running"].clone(), last["exit"].clone()), (Some("wait"), json!(false), json!(0)));
            assert_eq!(job_call(&s, "nope", JobAction::Status).await.unwrap_err(), "no such job: nope");
        }

        #[tokio::test]
        async fn a_short_command_answers_in_one_call() {
            let (_t, w, s) = rooted();
            let r = exec(&s, "echo hi", w.path(), 10_000, None).await;
            assert_eq!(r, json!({"exit": 0, "duration_ms": r["duration_ms"], "stdout": r["stdout"]}));
            assert_eq!(r["stdout"]["tail"], "hi\n");
            let recs = all_records(&s);
            assert_eq!(recs.len(), 1);
            assert!(recs[0]["body"].get("job").is_none());
            // The limits.
            let e = s.symbia_exec(Parameters(ExecArgs { yield_ms: Some(50_001), ..exec_args("true", w.path()) })).await.unwrap_err();
            assert_eq!(e, "yield_ms must be at most 50000");
            let e = s.symbia_exec(Parameters(ExecArgs { timeout_ms: Some(3_600_001), ..exec_args("true", w.path()) })).await.unwrap_err();
            assert!(e.starts_with("timeout_ms must be"), "{e}");
        }

        #[tokio::test]
        async fn a_job_past_its_timeout_is_killed_and_recorded() {
            let (_t, w, s) = rooted();
            let r = exec(&s, "echo up; sleep 30", w.path(), 200, Some(1_000)).await;
            let id = r["job"].as_str().unwrap().to_string();
            let pid = r["pid"].as_i64().unwrap();
            let done = parse(job_call(&s, &id, JobAction::Wait).await);
            assert_eq!(done["exit"], "timeout", "{done}");
            assert!(done.get("killed").is_none());
            assert!(!alive(pid));
            let end = all_records(&s).into_iter().find(|r| r["key"] == format!("job.{id}")).unwrap();
            assert_eq!(end["body"]["exit"], "timeout");
            assert_eq!(end["body"]["stdout_sha256"], hex::encode(sha256(b"up\n")));
        }

        #[tokio::test]
        async fn kill_ends_the_whole_group() {
            let (_t, w, s) = rooted();
            let pidfile = w.path().join("child.pid");
            let r = exec(&s, &format!("sleep 60 & echo $! > {}; wait", pidfile.display()), w.path(), 300, None).await;
            let id = r["job"].as_str().unwrap().to_string();
            let child: i64 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
            let k = parse(job_call(&s, &id, JobAction::Kill).await);
            assert_eq!((k["running"].clone(), k["exit"].clone(), k["killed"].clone()), (json!(false), json!("killed"), json!("symbia_job")), "{k}");
            let gone = (0..50).any(|_| {
                std::thread::sleep(Duration::from_millis(100));
                !alive(child)
            });
            assert!(gone, "background child {child} still running");
            let end = all_records(&s).into_iter().find(|r| r["key"] == format!("job.{id}")).unwrap();
            assert_eq!((end["body"]["exit"].clone(), end["body"]["killed"].clone()), (json!("killed"), json!("symbia_job")));
            // Killing an ended job changes nothing.
            let again = parse(job_call(&s, &id, JobAction::Kill).await);
            assert_eq!(again["killed"], "symbia_job");
            assert_eq!(all_records(&s).iter().filter(|r| r["key"] == format!("job.{id}")).count(), 1);
        }

        #[tokio::test]
        async fn tail_bytes_trims_the_tails() {
            let (_t, w, s) = rooted();
            let cmd = "for i in $(seq 1 500); do printf '%04d\\n' $i; done";
            let a = ExecArgs { tail_bytes: Some(300), ..exec_args(cmd, w.path()) };
            let r: Value = serde_json::from_str(&s.symbia_exec(Parameters(a)).await.unwrap()).unwrap();
            let tail = r["stdout"]["tail"].as_str().unwrap();
            assert_eq!((tail.len(), r["stdout"]["cut"].clone(), r["stdout"]["bytes"].clone()), (300, json!(true), json!(2500)));
            assert!(tail.ends_with("0500\n"));
            for bad in [255, 65_537] {
                let a = ExecArgs { tail_bytes: Some(bad), ..exec_args("true", w.path()) };
                assert_eq!(s.symbia_exec(Parameters(a)).await.unwrap_err(), "tail_bytes must be 256 to 65536");
            }
            // A job's tail action takes its own size.
            let r = exec(&s, &format!("{cmd}; sleep 30"), w.path(), 300, None).await;
            let id = r["job"].as_str().unwrap();
            assert_eq!(r["stdout"]["tail"].as_str().unwrap().len(), 2500, "all 2,500 bytes fit the default 8 KB tail");
            let t = parse(s.symbia_job(Parameters(JobArgs { job: id.into(), action: Some(JobAction::Tail), wait_ms: None, bytes: Some(256) })).await);
            assert_eq!(t["stdout"]["tail"].as_str().unwrap().len(), 256);
            assert_eq!(t["running"], true);
            job_call(&s, id, JobAction::Kill).await.unwrap();
        }

        #[tokio::test]
        async fn shutdown_kills_running_jobs_records_them_and_seals() {
            let (t, w, s) = rooted();
            let r = exec(&s, "sleep 60", w.path(), 200, None).await;
            let id = r["job"].as_str().unwrap().to_string();
            let pid = r["pid"].as_i64().unwrap();
            let t0 = std::time::Instant::now();
            s.shutdown_jobs().await;
            let sealed = s.seal_pending().unwrap().expect("a seal");
            assert!(t0.elapsed() < Duration::from_secs(1));
            assert!(!alive(pid));
            assert!(seal::verify(&sealed.path).is_ok());
            let c = rusqlite::Connection::open_with_flags(&sealed.path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            let body: String = c.query_row("SELECT json(body) FROM records WHERE key = ?1", [format!("job.{id}")], |r| r.get(0)).unwrap();
            let body: Value = serde_json::from_str(&body).unwrap();
            assert_eq!((body["exit"].clone(), body["killed"].clone()), (json!("killed"), json!("shutdown")), "{body}");
            assert_eq!(seal_seqs(t.path()), [2]);
        }
    }

    #[test]
    fn every_transport_lists_the_b3_tools() {
        let t = tempfile::tempdir().unwrap();
        let key = Arc::new(crate::keys::load_or_create(t.path()).unwrap());
        let http = SymbiaServer::for_http(t.path(), key, Arc::default(), policy(t.path()));
        let (_t, stdio) = server();
        for s in [http, stdio] {
            let names: Vec<String> = s.tool_router.list_all().into_iter().map(|t| t.name.to_string()).collect();
            for n in ["symbia_fs_read", "symbia_fs_list", "symbia_fs_search", "symbia_fs_write", "symbia_fs_edit", "symbia_exec", "symbia_job"] {
                assert!(names.iter().any(|x| x == n), "missing {n}");
            }
            assert_eq!(names.len(), 12);
        }
    }

    #[test]
    fn job_tool_annotations() {
        let (_t, s) = server();
        let tool = s.tool_router.list_all().into_iter().find(|t| t.name == "symbia_job").unwrap();
        let a = tool.annotations.unwrap();
        assert_eq!(a.title.as_deref(), Some("Check a job"));
        assert_eq!(
            (a.read_only_hint, a.destructive_hint, a.idempotent_hint, a.open_world_hint),
            (Some(false), Some(true), Some(false), Some(false))
        );
    }

    #[test]
    fn every_tool_takes_a_thread() {
        let (_t, s) = server();
        let tools = s.tools();
        assert_eq!(tools.len(), 12);
        for t in &tools {
            assert_eq!(t.input_schema["properties"]["thread"]["description"], THREAD_DOC, "{}", t.name);
        }
    }

    fn in_thread(thread: &str) -> Call {
        Call { thread: thread.into(), meta_keys: vec!["progressToken".into()] }
    }

    #[tokio::test]
    async fn records_and_tool_calls_land_in_the_callers_thread() {
        let (_t, w, s) = rooted();
        let r: Value = serde_json::from_str(&CALL.scope(in_thread("chat-a"), s.symbia_record(Parameters(rec("a")))).await.unwrap()).unwrap();
        let got: Value = serde_json::from_str(&s.symbia_get(Parameters(GetArgs { id: r["id"].as_str().map(String::from), ..Default::default() })).await.unwrap()).unwrap();
        assert_eq!(got["thread"], "chat-a");
        // A file tool's record carries the thread and the `_meta` key names.
        let f = w.path().join("x.txt");
        std::fs::write(&f, "x").unwrap();
        let read = FsReadArgs { path: f.display().to_string(), offset: None, limit: None, full: None };
        CALL.scope(in_thread("chat-b"), s.symbia_fs_read(Parameters(read))).await.unwrap();
        let calls = tool_calls(&s);
        let last = calls.last().unwrap();
        assert_eq!((last["thread"].as_str(), last["body"]["client_meta_keys"].clone()), (Some("chat-b"), json!(["progressToken"])));
        // Outside a call: main, and no meta keys.
        s.symbia_record(Parameters(rec("b"))).await.unwrap();
        let found: Value = serde_json::from_str(&s.symbia_find(Parameters(FindArgs { in_thread: Some("main".into()), ..Default::default() })).await.unwrap()).unwrap();
        assert_eq!((found.as_array().unwrap().len(), found[0]["key"].as_str()), (1, Some("b")));
        assert_eq!(found[0]["thread"], "main");
        let st: Value = serde_json::from_str(&CALL.scope(in_thread("chat-a"), s.symbia_status()).await.unwrap()).unwrap();
        assert_eq!(st["thread"], "chat-a");
        let threads: Vec<&str> = st["threads"].as_array().unwrap().iter().map(|t| t["thread"].as_str().unwrap()).collect();
        assert_eq!(threads, ["main", "chat-b", "chat-a"]);
        let fresh = st["new_thread"].as_str().unwrap();
        assert!(fresh.starts_with("t-") && fresh.len() == 10 && check_thread(fresh).is_ok(), "{fresh}");
        assert_ne!(fresh, serde_json::from_str::<Value>(&s.symbia_status().await.unwrap()).unwrap()["new_thread"].as_str().unwrap());
    }

    #[tokio::test]
    async fn seal_tool_seals_one_thread() {
        let (_t, s) = server();
        CALL.scope(in_thread("chat-a"), s.symbia_record(Parameters(rec("a")))).await.unwrap();
        s.symbia_record(Parameters(rec("b"))).await.unwrap();
        let r: Value = serde_json::from_str(&s.symbia_seal(Parameters(SealArgs { in_thread: Some("chat-a".into()) })).await.unwrap()).unwrap();
        assert_eq!((r["thread"].as_str(), r["records"].as_i64(), r["withheld"].as_i64(), r["verified"].as_bool()), (Some("chat-a"), Some(1), Some(1), Some(true)));
        assert!(r["path"].as_str().unwrap().contains(".thread-"));
        let e = s.symbia_seal(Parameters(SealArgs { in_thread: Some("nobody".into()) })).await.unwrap_err();
        assert!(e.contains("has no records"), "{e}");
    }

    #[tokio::test]
    async fn a_jobs_end_record_takes_its_starts_thread() {
        let (_t, w, s) = rooted();
        let a = ExecArgs { yield_ms: Some(100), ..exec_args("sleep 1; echo done", w.path()) };
        let r: Value = serde_json::from_str(&CALL.scope(in_thread("chat-j"), s.symbia_exec(Parameters(a))).await.unwrap()).unwrap();
        let id = r["job"].as_str().unwrap().to_string();
        // Waited on from outside the call: the end record still goes where the job started.
        job_call(&s, &id, JobAction::Wait).await.unwrap();
        let recs = all_records(&s);
        let end = recs.iter().find(|r| r["key"] == format!("job.{id}")).unwrap();
        let start = recs.iter().find(|r| r["key"] == "tool.symbia_exec").unwrap();
        assert_eq!((start["thread"].as_str(), end["thread"].as_str()), (Some("chat-j"), Some("chat-j")));
    }

    #[test]
    fn tool_schemas_inline_everything() {
        let (_t, s) = server();
        for tool in s.tool_router.list_all() {
            let schema = serde_json::to_string(&tool.input_schema).unwrap();
            assert!(!schema.contains("$ref"), "{}: {schema}", tool.name);
        }
        let job = s.tool_router.list_all().into_iter().find(|t| t.name == "symbia_job").unwrap();
        let action = serde_json::to_string(&job.input_schema["properties"]["action"]).unwrap();
        for v in ["status", "wait", "tail", "kill"] {
            assert!(action.contains(&format!("\"{v}\"")), "{action}");
        }
        let exec = s.tool_router.list_all().into_iter().find(|t| t.name == "symbia_exec").unwrap();
        assert!(exec.input_schema["properties"].get("unsandboxed").is_some());
    }

    #[tokio::test]
    async fn file_tools_write_one_tool_call_record_each_even_when_refused() {
        let (t, s) = server();
        // The root sits outside `SYMBIA_HOME`, which the tools may not write.
        let w = tempfile::tempdir().unwrap();
        let s = s.with_policy(Policy::new(&[w.path().join("root")], t.path(), t.path()).unwrap());
        std::fs::create_dir_all(w.path().join("root")).unwrap();
        let f = w.path().join("root/a.txt").display().to_string();
        let reply = s.symbia_fs_write(Parameters(FsWriteArgs { path: f.clone(), content: "secret body".into(), create_only: None, append: None })).await.unwrap();
        let e = s.symbia_fs_read(Parameters(FsReadArgs { path: "/etc/hosts".into(), offset: None, limit: None, full: None })).await.unwrap_err();
        assert!(e.starts_with("denied"));
        let recs = tool_calls(&s);
        assert_eq!(recs.len(), 2);
        let w = &recs[0];
        assert_eq!((w["key"].as_str(), w["lane"].as_str(), w["model"].as_str()), (Some("tool.symbia_fs_write"), Some("apocryphal"), Some(UNKNOWN_CLIENT)));
        assert_eq!(w["body"]["tool"], "symbia_fs_write");
        assert_eq!(w["body"]["bytes_returned"], reply.len());
        assert_eq!(w["body"]["truncated"], false);
        assert_eq!(w["body"]["sha256_after"], hex::encode(sha256(b"secret body")));
        assert_eq!(w["body"]["args_digest"].as_str().unwrap().len(), 64);
        assert!(w["body"].get("sha256_before").is_none());
        assert_eq!(w["chars"], reply.chars().count());
        assert!(w["host_ms"].as_i64().is_some());
        assert_eq!((w["est_host_ms"].clone(), w["est_chars"].clone()), (Value::Null, Value::Null));
        // Content is not stored in the record.
        assert!(!w.to_string().contains("secret body"));
        let r = &recs[1];
        assert_eq!(r["body"]["path"], "/etc/hosts");
        assert_eq!(r["body"]["error"], e);
    }

    #[tokio::test]
    async fn exec_record_names_its_evidence() {
        let (t, s) = server();
        let w = tempfile::tempdir().unwrap();
        let s = s.with_policy(Policy::new(&[w.path().to_path_buf()], t.path(), t.path()).unwrap());
        let reply = s.symbia_exec(Parameters(exec_args("echo hi; exit 3", w.path()))).await.unwrap();
        let v: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["exit"], 3);
        let rec = &tool_calls(&s)[0];
        let sha = hex::encode(sha256(b"hi\n"));
        assert_eq!(rec["body"]["exit"], 3);
        assert_eq!(rec["body"]["stdout_sha256"], sha);
        assert!(rec["body"]["cwd"].as_str().is_some());
        assert_eq!(rec["body"]["command"], "echo hi; exit 3");
        assert_eq!(rec["body"]["sandbox"], crate::exec::SANDBOX);
        assert_eq!(rec["body"]["network"], "allow");
        let n: i64 = s.with_store(|st| Ok(st.conn().query_row("SELECT COUNT(*) FROM evidence WHERE sha256 = ?1", [hex::decode(&sha).unwrap()], |r| r.get(0)).unwrap())).unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn file_tools_need_a_session() {
        let t = tempfile::tempdir().unwrap();
        let key = Arc::new(crate::keys::load_or_create(t.path()).unwrap());
        let s = SymbiaServer::for_http(t.path(), key, Arc::default(), policy(t.path()));
        let f = t.path().join("x").display().to_string();
        let e = s.symbia_fs_write(Parameters(FsWriteArgs { path: f, content: "x".into(), create_only: None, append: None })).await.unwrap_err();
        assert_eq!(e, NO_SESSION);
        assert!(!t.path().join("x").exists());
    }

    fn rec(key: &str) -> RecordInput {
        RecordInput {
            key: key.into(),
            kind: "claim".into(),
            lane: "apocryphal".into(),
            lane_reason: "unverified".into(),
            body: json!({"text": "a long enough body ".repeat(50)}),
            model: "claude-opus-5-5".into(),
            est_host_ms: Some(10),
            est_chars: Some(120),
            links: None,
        }
    }

    fn with_session_header(id: &str) -> Extensions {
        let (parts, ()) = http::Request::builder().header(SESSION_HEADER, id).body(()).unwrap().into_parts();
        let mut ext = Extensions::new();
        ext.insert(parts);
        ext
    }

    #[tokio::test]
    async fn record_reply_is_terse() {
        let (_t, s) = server();
        let reply = s.symbia_record(Parameters(rec("a.very.long.key.name.for.a.claim"))).await.unwrap();
        assert!(reply.chars().count() < 300, "{} chars: {reply}", reply.chars().count());
        let v: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["id"].as_str().unwrap().len(), 64);
        assert_eq!(v["version"], 1);
        assert_eq!(v["seq"], 1);
        assert_eq!(v["head"].as_str().unwrap().len(), 12);
        assert_eq!(v.as_object().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn status_reports_session_state() {
        let (t, s) = server();
        let v: Value = serde_json::from_str(&s.symbia_status().await.unwrap()).unwrap();
        assert_eq!(v["build"], crate::BUILD);
        assert_eq!(v["retention"], "session");
        assert_eq!(v["seq"], 0);
        assert_eq!(v["last_seal"], Value::Null);
        assert_eq!(v["mcp_session_id"], Value::Null);
        assert!(v["expires_ms"].as_i64().unwrap() > crate::now_ms());
        assert_eq!(v["public_key"].as_str().unwrap().len(), 12);
        assert!(v["file"].as_str().unwrap().starts_with(t.path().to_str().unwrap()));
        s.symbia_record(Parameters(rec("a"))).await.unwrap();
        s.symbia_seal(Parameters(SealArgs::default())).await.unwrap();
        let v: Value = serde_json::from_str(&s.symbia_status().await.unwrap()).unwrap();
        assert_eq!(v["seq"], 1);
        assert_eq!(v["last_seal"]["chain_seq"], 1);
    }

    #[tokio::test]
    async fn get_by_id_or_key() {
        let (_t, s) = server();
        let w1: Value = serde_json::from_str(&s.symbia_record(Parameters(rec("a"))).await.unwrap()).unwrap();
        let w2: Value = serde_json::from_str(&s.symbia_record(Parameters(rec("a"))).await.unwrap()).unwrap();
        let get = |a: GetArgs| {
            let s = s.clone();
            async move { s.symbia_get(Parameters(a)).await }
        };
        let latest: Value = serde_json::from_str(&get(GetArgs { key: Some("a".into()), ..Default::default() }).await.unwrap()).unwrap();
        assert_eq!(latest["id"], w2["id"]);
        assert_eq!(latest["lane_reason"], "unverified");
        let v1: Value =
            serde_json::from_str(&get(GetArgs { key: Some("a".into()), version: Some(1), ..Default::default() }).await.unwrap()).unwrap();
        assert_eq!(v1["id"], w1["id"]);
        let by_id: Value =
            serde_json::from_str(&get(GetArgs { id: w1["id"].as_str().map(String::from), ..Default::default() }).await.unwrap()).unwrap();
        assert_eq!(by_id["version"], 1);
        assert!(get(GetArgs::default()).await.is_err());
        assert!(get(GetArgs { id: Some("x".into()), key: Some("a".into()), ..Default::default() }).await.is_err());
        assert_eq!(get(GetArgs { id: Some("nope".into()), ..Default::default() }).await.unwrap_err(), "no such record");
    }

    #[tokio::test]
    async fn find_rejects_limit_over_50() {
        let (_t, s) = server();
        assert!(s.symbia_find(Parameters(FindArgs { limit: Some(51), ..Default::default() })).await.is_err());
        assert_eq!(s.symbia_find(Parameters(FindArgs { limit: Some(50), ..Default::default() })).await.unwrap(), "[]");
    }

    #[tokio::test]
    async fn bad_record_is_a_tool_error() {
        let (_t, s) = server();
        let e = s.symbia_record(Parameters(RecordInput { lane: "main".into(), ..rec("a") })).await.unwrap_err();
        assert!(e.contains("unknown lane"), "{e}");
    }

    #[tokio::test]
    async fn http_server_binds_one_file_to_one_session_id() {
        let t = tempfile::tempdir().unwrap();
        let key = Arc::new(crate::keys::load_or_create(t.path()).unwrap());
        let sessions = Arc::new(Sessions::default());
        let s = SymbiaServer::for_http(t.path(), key, sessions.clone(), policy(t.path()));
        // No file and no tools until the session id is known.
        assert_eq!(s.symbia_status().await.unwrap_err(), NO_SESSION);
        s.bind(&Extensions::new()).unwrap();
        assert_eq!(s.symbia_record(Parameters(rec("a"))).await.unwrap_err(), NO_SESSION);
        assert_eq!(std::fs::read_dir(t.path().join("sessions")).unwrap().count(), 0);

        s.bind(&with_session_header("sid-1")).unwrap();
        s.bind(&with_session_header("sid-1")).unwrap();
        s.symbia_record(Parameters(rec("a"))).await.unwrap();
        let v: Value = serde_json::from_str(&s.symbia_status().await.unwrap()).unwrap();
        assert_eq!(v["mcp_session_id"], "sid-1");
        assert!(!sessions.expired("sid-1", crate::now_ms()));
        assert!(sessions.expired("sid-1", v["expires_ms"].as_i64().unwrap()));
        assert_eq!(s.bind(&with_session_header("sid-2")).unwrap_err(), "Mcp-Session-Id does not match this session");
        assert_eq!(std::fs::read_dir(t.path().join("sessions")).unwrap().filter(|e| e.as_ref().unwrap().path().extension().unwrap() == "sqlite").count(), 1);
    }

    fn seal_seqs(home: &Path) -> Vec<i64> {
        let mut v: Vec<i64> = std::fs::read_dir(home.join("seals"))
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                (p.extension()? == "sqlite").then(|| seal::read_sidecar(&p).unwrap().chain_seq)
            })
            .collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn fifty_tool_calls_make_a_checkpoint_seal() {
        let (t, s) = server();
        let w = tempfile::tempdir().unwrap();
        let s = s.with_policy(Policy::new(&[w.path().to_path_buf()], t.path(), t.path()).unwrap());
        let list = || FsListArgs { path: w.path().display().to_string(), depth: None, glob: None };
        for _ in 0..49 {
            s.symbia_fs_list(Parameters(list())).await.unwrap();
        }
        assert!(seal_seqs(t.path()).is_empty());
        s.symbia_fs_list(Parameters(list())).await.unwrap();
        assert_eq!(seal_seqs(t.path()), [50]);
        let path = seal::last_seal(t.path(), &s.with_store(|st| Ok(st.session().to_string())).unwrap()).unwrap().0;
        assert!(seal::verify(&path).is_ok());
        // Refused calls are records too and count toward the next one.
        for _ in 0..50 {
            s.symbia_fs_read(Parameters(FsReadArgs { path: "/etc/hosts".into(), offset: None, limit: None, full: None })).await.unwrap_err();
        }
        assert_eq!(seal_seqs(t.path()), [50, 100]);
    }

    #[tokio::test]
    async fn a_prediction_is_sealed_at_once_and_not_again() {
        let (t, s) = server();
        s.symbia_record(Parameters(rec("a"))).await.unwrap();
        assert!(seal_seqs(t.path()).is_empty(), "a claim waits");
        let reply: Value = serde_json::from_str(&s.symbia_record(Parameters(RecordInput { kind: "prediction".into(), ..rec("p") })).await.unwrap()).unwrap();
        assert_eq!(reply.as_object().unwrap().len(), 4, "the reply is unchanged");
        assert_eq!(seal_seqs(t.path()), [2]);
        // Sealed at its head: neither an explicit seal nor the exit seal makes another.
        s.symbia_seal(Parameters(SealArgs::default())).await.unwrap();
        assert!(s.seal_pending().unwrap().is_none());
        assert_eq!(seal_seqs(t.path()), [2]);
    }

    #[tokio::test]
    async fn a_failed_checkpoint_does_not_fail_the_write() {
        let (t, s) = server();
        // A file where the seal copy would go makes `VACUUM INTO` fail.
        let session = s.with_store(|st| Ok(st.session().to_string())).unwrap();
        std::fs::create_dir_all(t.path().join("seals").join(format!("{session}-1.sqlite"))).unwrap();
        let reply = s.symbia_record(Parameters(RecordInput { kind: "prediction".into(), ..rec("p") })).await;
        assert!(reply.is_ok(), "{reply:?}");
        assert_eq!(s.with_store(|st| Ok(st.head().unwrap().0)).unwrap(), 1);
    }

    #[tokio::test]
    async fn status_names_when_the_session_started() {
        let before = crate::now_ms();
        let (_t, s) = server();
        let v: Value = serde_json::from_str(&s.symbia_status().await.unwrap()).unwrap();
        let started = v["session_started_ms"].as_i64().unwrap();
        assert!(started >= before && started <= crate::now_ms());
    }

    #[tokio::test]
    async fn fs_write_appends_and_refuses_append_with_create_only() {
        let (t, s) = server();
        let w = tempfile::tempdir().unwrap();
        let s = s.with_policy(Policy::new(&[w.path().to_path_buf()], t.path(), t.path()).unwrap());
        let f = w.path().join("log.txt").display().to_string();
        let args = |content: &str, create_only, append| FsWriteArgs { path: f.clone(), content: content.into(), create_only, append };
        s.symbia_fs_write(Parameters(args("a\n", None, Some(true)))).await.unwrap();
        s.symbia_fs_write(Parameters(args("b\n", None, Some(true)))).await.unwrap();
        assert_eq!(std::fs::read_to_string(w.path().join("log.txt")).unwrap(), "a\nb\n");
        let e = s.symbia_fs_write(Parameters(args("c\n", Some(true), Some(true)))).await.unwrap_err();
        assert_eq!(e, "create_only and append cannot both be set");
        assert_eq!(std::fs::read_to_string(w.path().join("log.txt")).unwrap(), "a\nb\n");
        let recs = tool_calls(&s);
        assert_eq!(recs[1]["body"]["sha256_before"], hex::encode(sha256(b"a\n")));
        assert_eq!(recs[1]["body"]["sha256_after"], hex::encode(sha256(b"a\nb\n")));
        assert_eq!((recs[2]["body"]["error"].as_str(), recs[2]["body"]["path"].as_str()), (Some(e.as_str()), Some(f.as_str())));
    }

    #[test]
    fn record_tool_states_the_link_shape_and_rels() {
        let (_t, s) = server();
        let tool = s.tool_router.list_all().into_iter().find(|t| t.name == "symbia_record").unwrap();
        let d = tool.description.unwrap();
        assert!(d.contains(r#"{"to_id": "<record id>", "rel": "<rel>"}"#), "{d}");
        for rel in crate::record::RELS {
            assert!(d.contains(rel), "{rel}");
        }
        let exec = s.tool_router.list_all().into_iter().find(|t| t.name == "symbia_exec").unwrap().description.unwrap();
        assert!(exec.contains("not a boundary"), "{exec}");
    }

    #[tokio::test]
    async fn refused_rel_lists_the_allowed_ones() {
        let (_t, s) = server();
        let links = Some(vec![crate::record::LinkInput { to_id: "x".into(), rel: "likes".into() }]);
        let e = s.symbia_record(Parameters(RecordInput { links, ..rec("a") })).await.unwrap_err();
        assert!(e.contains("results_of, revises, supersedes, cites"), "{e}");
    }

    #[tokio::test]
    async fn get_shows_each_links_session() {
        let t = tempfile::tempdir().unwrap();
        let a = SymbiaServer::new(t.path()).unwrap();
        let p: Value = serde_json::from_str(&a.symbia_record(Parameters(RecordInput { kind: "prediction".into(), ..rec("p") })).await.unwrap()).unwrap();
        let a_session = a.with_store(|st| Ok(st.session().to_string())).unwrap();
        let b = SymbiaServer::new(t.path()).unwrap();
        let links = Some(vec![crate::record::LinkInput { to_id: p["id"].as_str().unwrap().into(), rel: "results_of".into() }]);
        let r: Value = serde_json::from_str(&b.symbia_record(Parameters(RecordInput { kind: "result".into(), links, ..rec("r") })).await.unwrap()).unwrap();
        let got: Value = serde_json::from_str(&b.symbia_get(Parameters(GetArgs { id: r["id"].as_str().map(String::from), ..Default::default() })).await.unwrap()).unwrap();
        assert_eq!(got["links"][0]["to_session"], a_session.as_str());
    }

    #[test]
    fn http_stops_at_the_last_protocol_with_sessions() {
        let t = tempfile::tempdir().unwrap();
        let key = Arc::new(crate::keys::load_or_create(t.path()).unwrap());
        let http = SymbiaServer::for_http(t.path(), key, Arc::default(), policy(t.path()));
        let versions = http.supported_protocol_versions();
        assert_eq!(versions.last(), Some(&ProtocolVersion::V_2025_11_25));
        let (_t, stdio) = server();
        assert_eq!(stdio.supported_protocol_versions().as_ref(), ProtocolVersion::KNOWN_VERSIONS);
    }
}
