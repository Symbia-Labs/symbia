//! MCP tool layer. Over stdio one server process is one session; over streamable HTTP
//! each MCP session (its `Mcp-Session-Id`) is one session file.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use ed25519_dalek::SigningKey;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::{IntoCallToolResult, ToolCallContext};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolRequestParams, CallToolResponse, Extensions, ProtocolVersion};
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::{ErrorData, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::canon::{canonical, hex_prefix, sha256};
use crate::files::{Facts, SEARCH_DEADLINE, SearchArgs};
use crate::http::Sessions;
use crate::policy::Policy;
use crate::record::RecordInput;
use crate::seal;
use crate::store::{Evidence, FIND_LIMIT_MAX, FindQuery, Store};

const PREFIX: usize = 12;
const SESSION_HEADER: &str = "mcp-session-id";
const NO_SESSION: &str = "no session: initialize an MCP session first (Mcp-Session-Id, protocol 2025-11-25 or earlier)";
const TOOL_LANE_REASON: &str = "tool output, not verified";
/// `model` on a `tool_call` record when the client did not name itself.
const UNKNOWN_CLIENT: &str = "unknown";

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
    tool_router: ToolRouter<Self>,
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
    /// Default 120,000; at most 600,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
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
    /// Open a new session under `home`, creating the layout and device key as needed (stdio).
    pub fn new(home: &Path) -> anyhow::Result<Self> {
        crate::home::ensure(home)?;
        let key = crate::keys::load_or_create(home)?;
        let policy = Policy::from_env(home)?;
        let store = Store::create(home)?;
        Ok(Self {
            home: home.to_path_buf(),
            key: Arc::new(key),
            store: Arc::new(Mutex::new(Some(store))),
            sessions: None,
            policy: Arc::new(policy),
            client: Arc::default(),
            tool_router: Self::tool_router(),
        })
    }

    /// A server for one streamable HTTP session. The session file is created when the
    /// first message carrying the `Mcp-Session-Id` arrives.
    pub fn for_http(home: &Path, key: Arc<SigningKey>, sessions: Arc<Sessions>, policy: Arc<Policy>) -> Self {
        Self {
            home: home.to_path_buf(),
            key,
            store: Arc::new(Mutex::new(None)),
            sessions: Some(sessions),
            policy,
            client: Arc::default(),
            tool_router: Self::tool_router(),
        }
    }

    /// Replace the path policy (tests).
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = Arc::new(policy);
        self
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
        if self.lock()?.is_none() {
            return Err(NO_SESSION.into());
        }
        Ok(hex::encode(sha256(canonical(args).map_err(err)?.as_bytes())))
    }

    /// Write the call's `tool_call` record, then hand back its reply (or error) unchanged.
    fn log(&self, tool: &str, digest: &str, started: Instant, facts: &Facts, result: Result<String, String>, evidence: &[Evidence]) -> Result<String, String> {
        let text = match &result {
            Ok(t) | Err(t) => t,
        };
        let mut body = serde_json::to_value(facts).map_err(err)?;
        body["tool"] = tool.into();
        body["args_digest"] = digest.into();
        body["bytes_returned"] = text.len().into();
        if let Err(e) = &result {
            body["error"] = e.as_str().into();
        }
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
        self.with_store(|s| s.write_with(&input, started, Some(text.chars().count()), evidence).map_err(err))?;
        result
    }

    fn with_store<T>(&self, f: impl FnOnce(&mut Store) -> Result<T, String>) -> Result<T, String> {
        let mut slot = self.lock()?;
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
        description = "Session status: build, session, MCP session id, expiry, retention, file, chain seq and head, last seal, public key."
    )]
    pub async fn symbia_status(&self) -> Result<String, String> {
        self.with_store(|store| {
            let (seq, head) = store.head().map_err(err)?;
            let last = seal::last_seal(store.home(), store.session())
                .map(|(_, s)| json!({"chain_seq": s.chain_seq, "file_sha256": &s.file_sha256[..PREFIX]}));
            Ok(json!({
                "build": crate::BUILD,
                "session": store.session(),
                "mcp_session_id": store.mcp_session_id().map_err(err)?,
                "expires_ms": store.expires_ms().map_err(err)?,
                "retention": store.retention().map_err(err)?,
                "file": store.path().display().to_string(),
                "seq": seq,
                "head": hex_prefix(&head, PREFIX),
                "last_seal": last,
                "public_key": hex_prefix(&self.key.verifying_key().to_bytes(), PREFIX),
            })
            .to_string())
        })
    }

    #[tool(
        title = "Write a record",
        annotations(title = "Write a record", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false),
        description = "Write a record to the ledger. Returns {id, version, seq, head}."
    )]
    pub async fn symbia_record(&self, Parameters(args): Parameters<RecordInput>) -> Result<String, String> {
        let started = Instant::now();
        self.with_store(|store| Ok(store.write(&args, started).map_err(err)?.reply()))
    }

    #[tool(
        title = "Find records",
        annotations(title = "Find records", read_only_hint = true, open_world_hint = false),
        description = "Find records by full-text query, kind, lane or key prefix. Returns [{id, key, version, kind, lane}]."
    )]
    pub async fn symbia_find(&self, Parameters(args): Parameters<FindArgs>) -> Result<String, String> {
        if args.limit.is_some_and(|l| l > FIND_LIMIT_MAX) {
            return Err(format!("limit must be at most {FIND_LIMIT_MAX}"));
        }
        self.with_store(|store| {
            let hits = store
                .find(&FindQuery { query: args.query, kind: args.kind, lane: args.lane, key_prefix: args.key_prefix, limit: args.limit })
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
        description = "Seal the session: signed, verified copy under seals/. Returns {path, file_sha256, chain_seq, verified}."
    )]
    pub async fn symbia_seal(&self) -> Result<String, String> {
        self.with_store(|store| {
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
        description = "Read a text file with 1-based line numbers. Caps: 2,000 lines and 256 KB; the reply says which limit cut it and where to continue. Binary files are refused with size and sha256."
    )]
    pub async fn symbia_fs_read(&self, Parameters(args): Parameters<FsReadArgs>) -> Result<String, String> {
        self.file_tool("symbia_fs_read", args, |p, a, f| crate::files::read(p, &a.path, a.offset, a.limit, f)).await
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
        description = "Write a file atomically (temp file then rename). Returns {path, bytes, sha256}."
    )]
    pub async fn symbia_fs_write(&self, Parameters(args): Parameters<FsWriteArgs>) -> Result<String, String> {
        self.file_tool("symbia_fs_write", args, |p, a, f| crate::files::write(p, &a.path, &a.content, a.create_only.unwrap_or(false), f)).await
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
        description = "Run /bin/zsh -lc <command> in cwd, in its own process group; killed with its children at timeout_ms. Returns exit (or \"timeout\"), duration_ms and the last 8 KB of stdout and stderr; full output is saved at the named evidence path."
    )]
    pub async fn symbia_exec(&self, Parameters(args): Parameters<ExecArgs>) -> Result<String, String> {
        let started = Instant::now();
        let digest = self.begin(&args)?;
        let mut facts = Facts::default();
        let ran = crate::exec::exec(&self.policy, &self.home, &args.command, &args.cwd, args.timeout_ms, &mut facts).await;
        match ran {
            Ok(r) => self.log("symbia_exec", &digest, started, &facts, Ok(r.reply), &[r.stdout.evidence(), r.stderr.evidence()]),
            Err(e) => self.log("symbia_exec", &digest, started, &facts, Err(e), &[]),
        }
    }
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
        self.tool_router.call(ToolCallContext::new(self, request, context)).await
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

    #[test]
    fn every_transport_lists_the_b3_tools() {
        let t = tempfile::tempdir().unwrap();
        let key = Arc::new(crate::keys::load_or_create(t.path()).unwrap());
        let http = SymbiaServer::for_http(t.path(), key, Arc::default(), policy(t.path()));
        let (_t, stdio) = server();
        for s in [http, stdio] {
            let names: Vec<String> = s.tool_router.list_all().into_iter().map(|t| t.name.to_string()).collect();
            for n in ["symbia_fs_read", "symbia_fs_list", "symbia_fs_search", "symbia_fs_write", "symbia_fs_edit", "symbia_exec"] {
                assert!(names.iter().any(|x| x == n), "missing {n}");
            }
        }
    }

    #[tokio::test]
    async fn file_tools_write_one_tool_call_record_each_even_when_refused() {
        let (t, s) = server();
        // The root sits outside `SYMBIA_HOME`, which the tools may not write.
        let w = tempfile::tempdir().unwrap();
        let s = s.with_policy(Policy::new(&[w.path().join("root")], t.path(), t.path()).unwrap());
        std::fs::create_dir_all(w.path().join("root")).unwrap();
        let f = w.path().join("root/a.txt").display().to_string();
        let reply = s.symbia_fs_write(Parameters(FsWriteArgs { path: f.clone(), content: "secret body".into(), create_only: None })).await.unwrap();
        let e = s.symbia_fs_read(Parameters(FsReadArgs { path: "/etc/hosts".into(), offset: None, limit: None })).await.unwrap_err();
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
        let reply = s.symbia_exec(Parameters(ExecArgs { command: "echo hi; exit 3".into(), cwd: w.path().display().to_string(), timeout_ms: None })).await.unwrap();
        let v: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["exit"], 3);
        let rec = &tool_calls(&s)[0];
        let sha = hex::encode(sha256(b"hi\n"));
        assert_eq!(rec["body"]["exit"], 3);
        assert_eq!(rec["body"]["stdout_sha256"], sha);
        assert!(rec["body"]["cwd"].as_str().is_some());
        let n: i64 = s.with_store(|st| Ok(st.conn().query_row("SELECT COUNT(*) FROM evidence WHERE sha256 = ?1", [hex::decode(&sha).unwrap()], |r| r.get(0)).unwrap())).unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn file_tools_need_a_session() {
        let t = tempfile::tempdir().unwrap();
        let key = Arc::new(crate::keys::load_or_create(t.path()).unwrap());
        let s = SymbiaServer::for_http(t.path(), key, Arc::default(), policy(t.path()));
        let f = t.path().join("x").display().to_string();
        let e = s.symbia_fs_write(Parameters(FsWriteArgs { path: f, content: "x".into(), create_only: None })).await.unwrap_err();
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
        s.symbia_seal().await.unwrap();
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
