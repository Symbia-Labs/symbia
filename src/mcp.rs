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
use serde::Deserialize;
use serde_json::json;

use crate::canon::hex_prefix;
use crate::http::Sessions;
use crate::record::RecordInput;
use crate::seal;
use crate::store::{FIND_LIMIT_MAX, FindQuery, Store};

const PREFIX: usize = 12;
const SESSION_HEADER: &str = "mcp-session-id";
const NO_SESSION: &str = "no session: initialize an MCP session first (Mcp-Session-Id, protocol 2025-11-25 or earlier)";

#[derive(Clone)]
pub struct SymbiaServer {
    home: PathBuf,
    key: Arc<SigningKey>,
    /// `None` over streamable HTTP until the session id is known.
    store: Arc<Mutex<Option<Store>>>,
    /// Set over streamable HTTP: the expiry registry shared with the session manager.
    sessions: Option<Arc<Sessions>>,
    tool_router: ToolRouter<Self>,
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
        let store = Store::create(home)?;
        Ok(Self {
            home: home.to_path_buf(),
            key: Arc::new(key),
            store: Arc::new(Mutex::new(Some(store))),
            sessions: None,
            tool_router: Self::tool_router(),
        })
    }

    /// A server for one streamable HTTP session. The session file is created when the
    /// first message carrying the `Mcp-Session-Id` arrives.
    pub fn for_http(home: &Path, key: Arc<SigningKey>, sessions: Arc<Sessions>) -> Self {
        Self { home: home.to_path_buf(), key, store: Arc::new(Mutex::new(None)), sessions: Some(sessions), tool_router: Self::tool_router() }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Option<Store>>, String> {
        self.store.lock().map_err(|_| "state lock poisoned".to_string())
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
    #[tool(description = "Session status: build, session, MCP session id, expiry, retention, file, chain seq and head, last seal, public key.")]
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

    #[tool(description = "Write a record to the ledger. Returns {id, version, seq, head}.")]
    pub async fn symbia_record(&self, Parameters(args): Parameters<RecordInput>) -> Result<String, String> {
        let started = Instant::now();
        self.with_store(|store| Ok(store.write(&args, started).map_err(err)?.reply()))
    }

    #[tool(description = "Find records by full-text query, kind, lane or key prefix. Returns [{id, key, version, kind, lane}].")]
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

    #[tool(description = "Get one full record with its links, by id or by key and optional version.")]
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

    #[tool(description = "Seal the session: signed, verified copy under seals/. Returns {path, file_sha256, chain_seq, verified}.")]
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
}

#[tool_handler(router = self.tool_router, name = "symbia")]
impl ServerHandler for SymbiaServer {
    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>) -> Result<CallToolResponse, ErrorData> {
        if let Err(e) = self.bind(&context.extensions) {
            return Result::<String, String>::Err(e).into_call_tool_result();
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
        let s = SymbiaServer::for_http(t.path(), key, sessions.clone());
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
        let http = SymbiaServer::for_http(t.path(), key, Arc::default());
        let versions = http.supported_protocol_versions();
        assert_eq!(versions.last(), Some(&ProtocolVersion::V_2025_11_25));
        let (_t, stdio) = server();
        assert_eq!(stdio.supported_protocol_versions().as_ref(), ProtocolVersion::KNOWN_VERSIONS);
    }
}
