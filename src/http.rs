//! `symbia serve`: the MCP tools over streamable HTTP at `/mcp`.
//!
//! rmcp's in-memory session manager keeps each MCP session alive across dropped
//! connections. A thin wrapper ends a session at its file's `expires_ms`, after which
//! its `Mcp-Session-Id` gets 404 and the client must initialize a new session.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::bail;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use futures::Stream;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::session::{ServerSseMessage, SessionId, SessionManager};
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;

use crate::mcp::SymbiaServer;
use crate::now_ms;
use crate::store::{DEFAULT_TTL_MS, Store};

pub const DEFAULT_LISTEN: &str = "127.0.0.1:7341";
pub const PATH: &str = "/mcp";

/// A session's store slot, shared with its `SymbiaServer`.
pub type Slot = Arc<Mutex<Option<Store>>>;

/// Expiry of each bound MCP session, keyed by `Mcp-Session-Id`, and the stores to seal on shutdown.
#[derive(Default)]
pub struct Sessions {
    expires: Mutex<HashMap<String, i64>>,
    stores: Mutex<Vec<Weak<Mutex<Option<Store>>>>>,
}

impl Sessions {
    /// Remember a bound session's store so shutdown can seal it while it is alive.
    pub fn track(&self, slot: &Slot) {
        let mut stores = self.stores.lock().unwrap_or_else(|e| e.into_inner());
        stores.retain(|w| w.strong_count() > 0);
        stores.push(Arc::downgrade(slot));
    }

    /// Seal every live session with records written after its last seal. Returns the failures.
    pub fn seal_all(&self, key: &SigningKey) -> Vec<String> {
        let stores: Vec<Slot> = self.stores.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(Weak::upgrade).collect();
        let mut failed = Vec::new();
        for slot in stores {
            let guard = slot.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(store) = guard.as_ref()
                && let Err(e) = crate::seal::seal_pending(store, key)
            {
                failed.push(format!("{}: {e:#}", store.session()));
            }
        }
        failed
    }

    pub fn insert(&self, id: &str, expires_ms: i64) {
        self.expires.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), expires_ms);
    }

    pub fn expired(&self, id: &str, now_ms: i64) -> bool {
        self.expires.lock().unwrap_or_else(|e| e.into_inner()).get(id).is_some_and(|e| now_ms >= *e)
    }

    pub fn remove(&self, id: &str) {
        self.expires.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
    }
}

/// rmcp's local session manager, with sessions ending at their file's expiry.
pub struct ExpiringSessions {
    inner: LocalSessionManager,
    sessions: Arc<Sessions>,
}

impl ExpiringSessions {
    pub fn new(sessions: Arc<Sessions>) -> Self {
        let mut inner = LocalSessionManager::default();
        // Idle connections must not end a session before its expiry; the expiry check does that.
        inner.session_config.keep_alive = Some(Duration::from_millis(DEFAULT_TTL_MS.unsigned_abs()));
        Self { inner, sessions }
    }
}

type Inner = LocalSessionManager;

impl SessionManager for ExpiringSessions {
    type Error = <Inner as SessionManager>::Error;
    type Transport = <Inner as SessionManager>::Transport;

    fn create_session(&self) -> impl Future<Output = Result<(SessionId, Self::Transport), Self::Error>> + Send {
        self.inner.create_session()
    }

    fn initialize_session(&self, id: &SessionId, message: ClientJsonRpcMessage) -> impl Future<Output = Result<ServerJsonRpcMessage, Self::Error>> + Send {
        self.inner.initialize_session(id, message)
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        if self.sessions.expired(id, now_ms()) {
            self.sessions.remove(id);
            // Already gone is as good as closed.
            let _ = self.inner.close_session(id).await;
            return Ok(false);
        }
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.sessions.remove(id);
        self.inner.close_session(id).await
    }

    fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> impl Future<Output = Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>> + Send {
        self.inner.create_stream(id, message)
    }

    fn accept_message(&self, id: &SessionId, message: ClientJsonRpcMessage) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.accept_message(id, message)
    }

    fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>> + Send {
        self.inner.create_standalone_stream(id)
    }

    fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> impl Future<Output = Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>> + Send {
        self.inner.resume(id, last_event_id)
    }
}

/// Refuse a non-loopback listen address unless remote access was asked for.
pub fn check_listen(addr: SocketAddr, allow_remote: bool) -> anyhow::Result<()> {
    if !addr.ip().is_loopback() && !allow_remote {
        bail!("refusing to listen on non-loopback {addr}; pass --allow-remote to allow it");
    }
    Ok(())
}

/// `Host` headers accepted: loopback names, plus the bound address when remote.
/// A wildcard bind accepts any host.
fn allowed_hosts(addr: SocketAddr) -> Vec<String> {
    let mut hosts = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
    if addr.ip().is_unspecified() {
        return Vec::new();
    }
    if !addr.ip().is_loopback() {
        hosts.push(addr.ip().to_string());
    }
    hosts
}

fn not_found() -> Response<BoxBody<Bytes, Infallible>> {
    let mut r = Response::new(Full::new(Bytes::from_static(b"Not Found")).boxed());
    *r.status_mut() = StatusCode::NOT_FOUND;
    r
}

/// Serve MCP over streamable HTTP on `listener` until `shutdown` completes, then seal every
/// live session that has unsealed records. Seal failures go to stderr.
pub async fn serve(home: PathBuf, listener: TcpListener, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    crate::home::ensure(&home)?;
    let key = Arc::new(crate::keys::load_or_create(&home)?);
    let sessions = Arc::new(Sessions::default());
    let manager = Arc::new(ExpiringSessions::new(sessions.clone()));
    let config = StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts(listener.local_addr()?));
    let policy = Arc::new(crate::policy::Policy::from_env(&home)?);
    let (k, s) = (key.clone(), sessions.clone());
    let service = StreamableHttpService::new(move || Ok(SymbiaServer::for_http(&home, k.clone(), s.clone(), policy.clone())), manager, config);
    let mut shutdown = std::pin::pin!(shutdown);
    let result = loop {
        let stream = tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, _)) => stream,
                Err(e) => break Err(e.into()),
            },
            () = &mut shutdown => break Ok(()),
        };
        let service = service.clone();
        tokio::spawn(async move {
            let handler = hyper::service::service_fn(move |req: Request<Incoming>| {
                let service = service.clone();
                async move {
                    if req.uri().path() != PATH {
                        return Ok::<_, Infallible>(not_found());
                    }
                    Ok(service.handle(req).await)
                }
            });
            // A dropped connection ends only this task; the MCP session lives on.
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), handler).await;
        });
    };
    for e in sessions.seal_all(&key) {
        eprintln!("symbia serve: seal on exit failed: {e}");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_loopback_needs_allow_remote() {
        let lo: SocketAddr = "127.0.0.1:7341".parse().unwrap();
        let lo6: SocketAddr = "[::1]:7341".parse().unwrap();
        let lan: SocketAddr = "192.168.1.20:7341".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:7341".parse().unwrap();
        assert!(check_listen(lo, false).is_ok());
        assert!(check_listen(lo6, false).is_ok());
        assert!(check_listen(lan, false).is_err());
        assert!(check_listen(any, false).is_err());
        assert!(check_listen(lan, true).is_ok());
        assert_eq!(DEFAULT_LISTEN.parse::<SocketAddr>().unwrap(), lo);
    }

    #[test]
    fn allowed_hosts_follow_the_bind_address() {
        assert_eq!(allowed_hosts("127.0.0.1:1".parse().unwrap()), ["localhost", "127.0.0.1", "::1"]);
        assert_eq!(allowed_hosts("192.168.1.20:1".parse().unwrap()), ["localhost", "127.0.0.1", "::1", "192.168.1.20"]);
        assert!(allowed_hosts("0.0.0.0:1".parse().unwrap()).is_empty());
    }

    #[tokio::test]
    async fn expired_sessions_are_closed_and_not_found() {
        let sessions = Arc::new(Sessions::default());
        let m = ExpiringSessions::new(sessions.clone());
        let (id, _transport) = m.create_session().await.unwrap();
        assert!(m.has_session(&id).await.unwrap());
        sessions.insert(&id, now_ms() + 60_000);
        assert!(m.has_session(&id).await.unwrap());
        sessions.insert(&id, now_ms() - 1);
        assert!(!m.has_session(&id).await.unwrap());
        assert!(!m.inner.has_session(&id).await.unwrap(), "the rmcp session is closed too");
        assert!(!sessions.expired(&id, i64::MAX), "and forgotten");
    }

    #[test]
    fn sessions_expire_at_their_expiry() {
        let s = Sessions::default();
        assert!(!s.expired("unknown", i64::MAX));
        s.insert("a", 100);
        assert!(!s.expired("a", 99));
        assert!(s.expired("a", 100));
        s.remove("a");
        assert!(!s.expired("a", 100));
    }
}
