//! MCP tool layer. One server process is one session.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use ed25519_dalek::SigningKey;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use crate::canon::hex_prefix;
use crate::record::RecordInput;
use crate::seal;
use crate::store::{FIND_LIMIT_MAX, FindQuery, Store};

const PREFIX: usize = 12;

pub struct State {
    pub store: Store,
    pub key: SigningKey,
}

#[derive(Clone)]
pub struct SymbiaServer {
    state: Arc<Mutex<State>>,
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
    /// Open a new session under `home`, creating the layout and device key as needed.
    pub fn new(home: &Path) -> anyhow::Result<Self> {
        crate::home::ensure(home)?;
        let key = crate::keys::load_or_create(home)?;
        let store = Store::create(home)?;
        Ok(Self { state: Arc::new(Mutex::new(State { store, key })), tool_router: Self::tool_router() })
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, String> {
        self.state.lock().map_err(|_| "state lock poisoned".to_string())
    }
}

#[tool_router]
impl SymbiaServer {
    #[tool(description = "Session status: build, retention, file, chain seq and head, last seal, public key.")]
    pub async fn symbia_status(&self) -> Result<String, String> {
        let st = self.lock()?;
        let (seq, head) = st.store.head().map_err(err)?;
        let last = seal::last_seal(st.store.home(), st.store.session())
            .map(|(_, s)| json!({"chain_seq": s.chain_seq, "file_sha256": &s.file_sha256[..PREFIX]}));
        Ok(json!({
            "build": crate::BUILD,
            "session": st.store.session(),
            "retention": st.store.retention().map_err(err)?,
            "file": st.store.path().display().to_string(),
            "seq": seq,
            "head": hex_prefix(&head, PREFIX),
            "last_seal": last,
            "public_key": hex_prefix(&st.key.verifying_key().to_bytes(), PREFIX),
        })
        .to_string())
    }

    #[tool(description = "Write a record to the ledger. Returns {id, version, seq, head}.")]
    pub async fn symbia_record(&self, Parameters(args): Parameters<RecordInput>) -> Result<String, String> {
        let started = Instant::now();
        let mut st = self.lock()?;
        let w = st.store.write(&args, started).map_err(err)?;
        Ok(w.reply())
    }

    #[tool(description = "Find records by full-text query, kind, lane or key prefix. Returns [{id, key, version, kind, lane}].")]
    pub async fn symbia_find(&self, Parameters(args): Parameters<FindArgs>) -> Result<String, String> {
        if args.limit.is_some_and(|l| l > FIND_LIMIT_MAX) {
            return Err(format!("limit must be at most {FIND_LIMIT_MAX}"));
        }
        let st = self.lock()?;
        let hits = st
            .store
            .find(&FindQuery { query: args.query, kind: args.kind, lane: args.lane, key_prefix: args.key_prefix, limit: args.limit })
            .map_err(err)?;
        serde_json::to_string(&hits).map_err(err)
    }

    #[tool(description = "Get one full record with its links, by id or by key and optional version.")]
    pub async fn symbia_get(&self, Parameters(args): Parameters<GetArgs>) -> Result<String, String> {
        let st = self.lock()?;
        let id = match (args.id, args.key) {
            (Some(id), None) if args.version.is_none() => id,
            (None, Some(key)) => st.store.id_for_key(&key, args.version).map_err(err)?.ok_or("no such record")?,
            _ => return Err("give either id, or key with an optional version".into()),
        };
        let rec = st.store.get(&id).map_err(err)?.ok_or("no such record")?;
        Ok(rec.to_string())
    }

    #[tool(description = "Seal the session: signed, verified copy under seals/. Returns {path, file_sha256, chain_seq, verified}.")]
    pub async fn symbia_seal(&self) -> Result<String, String> {
        let st = self.lock()?;
        let s = seal::seal(&st.store, &st.key).map_err(err)?;
        Ok(json!({
            "path": s.path.display().to_string(),
            "file_sha256": &s.sidecar.file_sha256[..PREFIX],
            "chain_seq": s.sidecar.chain_seq,
            "verified": s.verified,
        })
        .to_string())
    }
}

#[tool_handler(router = self.tool_router, name = "symbia")]
impl ServerHandler for SymbiaServer {}

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
}
