//! Prediction S1: over streamable HTTP, a client that drops its connection and comes back
//! with the same `Mcp-Session-Id` continues the same session file, and the chain continues
//! from the same head.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_symbia");
const PROTOCOL: &str = "2025-11-25";

/// `symbia serve` on a free loopback port; killed on drop.
struct Server {
    child: Child,
    addr: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn start(home: &Path) -> Server {
    start_on(home, "127.0.0.1:0").await
}

async fn start_on(home: &Path, listen: &str) -> Server {
    let mut child = Command::new(BIN)
        .args(["serve", "--listen", listen])
        .env("SYMBIA_HOME", home)
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stderr.take().unwrap()).read_line(&mut line).await.unwrap();
    let addr = line.trim().strip_prefix("symbia serve: http://").and_then(|s| s.strip_suffix("/mcp")).unwrap_or_else(|| panic!("{line}"));
    Server { addr: addr.to_string(), child }
}

/// One HTTP/1.1 client over one TCP connection. Dropping it closes the connection.
struct Conn {
    addr: String,
    sender: SendRequest<Full<Bytes>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn connect(addr: &str) -> Conn {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    Conn { addr: addr.to_string(), sender, task }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    /// JSON-RPC messages from the SSE `data:` lines.
    messages: Vec<Value>,
}

impl Conn {
    async fn send(&mut self, method: Method, session: Option<&str>, body: Option<Value>) -> Reply {
        let mut req = Request::builder()
            .method(method)
            .uri("/mcp")
            .header("host", &self.addr)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json");
        if let Some(s) = session {
            req = req.header("mcp-session-id", s).header("mcp-protocol-version", PROTOCOL);
        }
        let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
        let resp = self.sender.send_request(req.body(Full::new(body)).unwrap()).await.unwrap();
        let (parts, body) = resp.into_parts();
        let text = String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap();
        let messages = text
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(|d| serde_json::from_str(d).unwrap())
            .collect();
        Reply { status: parts.status, headers: parts.headers, messages }
    }

    async fn post(&mut self, session: Option<&str>, body: Value) -> Reply {
        self.send(Method::POST, session, Some(body)).await
    }

    /// Initialize a new MCP session; returns its id.
    async fn initialize(&mut self) -> String {
        let r = self
            .post(
                None,
                json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                    "protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "s1", "version": "0"}}}),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.messages[0]["result"]["protocolVersion"], PROTOCOL);
        let sid = r.headers.get("mcp-session-id").expect("Mcp-Session-Id").to_str().unwrap().to_string();
        let ack = self.post(Some(&sid), json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
        assert_eq!(ack.status, StatusCode::ACCEPTED);
        sid
    }

    /// Call a tool and parse its text reply as JSON.
    async fn tool(&mut self, session: &str, id: i64, name: &str, args: Value) -> Value {
        let r = self.post(Some(session), json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})).await;
        assert_eq!(r.status, StatusCode::OK);
        let msg = r.messages.iter().find(|m| m["id"] == id).unwrap_or_else(|| panic!("no reply to {id}: {:?}", r.messages));
        let result = &msg["result"];
        assert_ne!(result["isError"], true, "{result}");
        serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
    }
}

fn record(key: &str) -> Value {
    json!({"key": key, "kind": "observation", "lane": "canonical", "lane_reason": "s1", "body": {"k": key}, "model": "claude-opus-5-5"})
}

fn session_files(home: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(home.join("sessions"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "sqlite"))
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn s1_resume_continues_the_same_file_and_chain() {
    let t = tempfile::tempdir().unwrap();
    let server = start(t.path()).await;

    // First connection: initialize, write one record.
    let mut a = connect(&server.addr).await;
    let sid = a.initialize().await;
    let w1 = a.tool(&sid, 1, "symbia_record", record("s1.first")).await;
    assert_eq!(w1["seq"], 1);
    let st1 = a.tool(&sid, 2, "symbia_status", json!({})).await;
    assert_eq!(st1["mcp_session_id"], sid.as_str());
    assert!(st1["expires_ms"].as_i64().unwrap() > symbia::now_ms());

    // Drop the connection; reconnect on a new one with the same session id.
    drop(a);
    let mut b = connect(&server.addr).await;
    let w2 = b.tool(&sid, 3, "symbia_record", record("s1.second")).await;
    assert_eq!(w2["seq"], 2);
    let st2 = b.tool(&sid, 4, "symbia_status", json!({})).await;
    assert_eq!(st2["session"], st1["session"]);
    assert_eq!(st2["file"], st1["file"]);
    assert_eq!(st2["head"], w2["head"]);

    // Both records are in one file, chained head to tail, bound to the MCP session id.
    let files = session_files(t.path());
    assert_eq!(files, [PathBuf::from(st1["file"].as_str().unwrap())]);
    {
        let c = rusqlite::Connection::open_with_flags(&files[0], rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let mcp: String = c.query_row("SELECT mcp_session_id FROM file_meta", [], |r| r.get(0)).unwrap();
        assert_eq!(mcp, sid);
        type Row = (i64, Vec<u8>, Vec<u8>, String);
        let rows: Vec<Row> = c
            .prepare("SELECT seq, prev_hash, hash, record_id FROM chain ORDER BY seq")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].0, rows[1].0), (1, 2));
        assert_eq!(rows[1].1, rows[0].2, "second row chains from the first row's hash");
        assert_eq!((rows[0].3.as_str(), rows[1].3.as_str()), (w1["id"].as_str().unwrap(), w2["id"].as_str().unwrap()));
    }

    // The resumed session seals and verifies like any other.
    let sealed = b.tool(&sid, 5, "symbia_seal", json!({})).await;
    assert_eq!((sealed["verified"].clone(), sealed["chain_seq"].clone()), (json!(true), json!(2)));

    // A second client gets its own session and its own file.
    let mut c = connect(&server.addr).await;
    let other = c.initialize().await;
    assert_ne!(other, sid);
    assert_eq!(c.tool(&other, 1, "symbia_record", record("other")).await["seq"], 1);
    assert_eq!(session_files(t.path()).len(), 2);

    // An unknown session id is 404; so is a session after DELETE.
    assert_eq!(b.post(Some("no-such-session"), json!({"jsonrpc": "2.0", "id": 9, "method": "tools/list"})).await.status, StatusCode::NOT_FOUND);
    assert!(b.send(Method::DELETE, Some(&sid), None).await.status.is_success());
    assert_eq!(b.post(Some(&sid), json!({"jsonrpc": "2.0", "id": 10, "method": "tools/list"})).await.status, StatusCode::NOT_FOUND);
    // Other paths are not served.
    let mut d = connect(&server.addr).await;
    let wrong = Request::builder().method(Method::GET).uri("/").header("host", &server.addr).body(Full::new(Bytes::new())).unwrap();
    assert_eq!(d.sender.send_request(wrong).await.unwrap().status(), StatusCode::NOT_FOUND);
    drop(server);
}

/// Out of scope for S1, recorded so the report describes observed behavior: sessions live in
/// the server's memory, so after a restart the old session id is 404 and the client must
/// initialize again, which opens a new file. The old file stays on disk with its chain intact.
#[tokio::test]
async fn server_restart_ends_sessions_but_keeps_their_files() {
    let t = tempfile::tempdir().unwrap();
    let mut first = start(t.path()).await;
    let addr = first.addr.clone();
    let mut a = connect(&addr).await;
    let sid = a.initialize().await;
    a.tool(&sid, 1, "symbia_record", record("before.restart")).await;
    drop(a);
    first.child.kill().await.unwrap();

    let second = start_on(t.path(), &addr).await;
    let mut b = connect(&second.addr).await;
    assert_eq!(b.post(Some(&sid), json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).await.status, StatusCode::NOT_FOUND);
    let fresh = b.initialize().await;
    assert_eq!(b.tool(&fresh, 3, "symbia_record", record("after.restart")).await["seq"], 1);

    let files = session_files(t.path());
    assert_eq!(files.len(), 2);
    let ids: Vec<Option<String>> = files
        .iter()
        .map(|f| {
            let c = rusqlite::Connection::open_with_flags(f, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            let n: i64 = c.query_row("SELECT COUNT(*) FROM chain", [], |r| r.get(0)).unwrap();
            assert_eq!(n, 1);
            c.query_row("SELECT mcp_session_id FROM file_meta", [], |r| r.get(0)).unwrap()
        })
        .collect();
    assert!(ids.contains(&Some(sid)) && ids.contains(&Some(fresh)));
}
