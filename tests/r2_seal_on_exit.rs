//! R2: the real binary seals its session when the stdio transport closes, and never seals an
//! empty session. The exec record names the command, sandbox and network setting.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const BIN: &str = env!("CARGO_BIN_EXE_symbia");

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl Mcp {
    async fn start(home: &Path) -> Self {
        let mut child = Command::new(BIN)
            .arg("mcp")
            .env("SYMBIA_HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut m = Self { child, stdin, stdout };
        m.send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "r2", "version": "0"}}}))
            .await;
        assert!(m.reply(0).await["result"]["protocolVersion"].is_string());
        m.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
        m
    }

    async fn send(&mut self, msg: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
        stdin.flush().await.unwrap();
    }

    async fn reply(&mut self, id: i64) -> Value {
        loop {
            let line = self.stdout.next_line().await.unwrap().expect("server closed stdout");
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    }

    /// Call a tool; the parsed text reply, or `Err(text)` for a tool error.
    async fn tool(&mut self, id: i64, name: &str, args: Value) -> Result<Value, String> {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})).await;
        let r = self.reply(id).await;
        let text = r["result"]["content"][0]["text"].as_str().unwrap_or_else(|| panic!("{r}")).to_string();
        if r["result"]["isError"] == true { Err(text) } else { Ok(serde_json::from_str(&text).unwrap()) }
    }

    /// Close stdin and wait for the process to exit; returns its stderr.
    async fn close(mut self) -> String {
        drop(self.stdin.take());
        let out = tokio::time::timeout(Duration::from_secs(20), self.child.wait_with_output()).await.expect("exit after EOF").unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8_lossy(&out.stderr).into_owned()
    }
}

fn seals(home: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(home.join("seals"))
        .map(|d| d.map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "sqlite")).collect())
        .unwrap_or_default();
    v.sort();
    v
}

#[tokio::test]
async fn closing_stdin_seals_a_session_with_records() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    let w = m
        .tool(1, "symbia_record", json!({"key": "r2", "kind": "observation", "lane": "canonical", "lane_reason": "r2", "body": {}, "model": "m"}))
        .await
        .unwrap();
    assert_eq!(w["seq"], 1);
    let stderr = m.close().await;
    assert!(stderr.is_empty(), "{stderr}");

    let s = seals(t.path());
    assert_eq!(s.len(), 1, "{s:?}");
    assert!(s[0].file_name().unwrap().to_str().unwrap().ends_with("-1.sqlite"));
    let out = std::process::Command::new(BIN).args(["verify", s[0].to_str().unwrap()]).env("SYMBIA_HOME", t.path()).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ok "));
}

#[tokio::test]
async fn an_empty_session_leaves_no_seal() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    // Reads write nothing.
    assert_eq!(m.tool(1, "symbia_status", json!({})).await.unwrap()["seq"], 0);
    m.close().await;
    assert!(seals(t.path()).is_empty());
}

#[tokio::test]
async fn a_session_sealed_at_its_head_is_not_sealed_again() {
    let t = tempfile::tempdir().unwrap();
    let mut m = Mcp::start(t.path()).await;
    m.tool(1, "symbia_record", json!({"key": "a", "kind": "observation", "lane": "canonical", "lane_reason": "r", "body": {}, "model": "m"}))
        .await
        .unwrap();
    m.tool(2, "symbia_seal", json!({})).await.unwrap();
    m.close().await;
    assert_eq!(seals(t.path()).len(), 1);
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn exec_record_names_command_sandbox_and_network() {
    let t = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("config.json"), json!({"roots": [root.path()], "exec_network": "deny"}).to_string()).unwrap();
    let mut m = Mcp::start(t.path()).await;
    let x = m.tool(1, "symbia_exec", json!({"command": "echo 'it ran'", "cwd": root.path()})).await.unwrap();
    assert_eq!(x["exit"], 0);
    let found = m.tool(2, "symbia_find", json!({"kind": "tool_call"})).await.unwrap();
    let id = found[0]["id"].as_str().unwrap().to_string();
    let rec = m.tool(3, "symbia_get", json!({"id": id})).await.unwrap();
    assert_eq!(rec["body"]["command"], "echo 'it ran'");
    assert_eq!(rec["body"]["sandbox"], if cfg!(target_os = "macos") { "seatbelt" } else { "none" });
    assert_eq!(rec["body"]["network"], "deny");
    m.close().await;
    // The exec call was sealed on exit, so an auditor with only the seal sees the command.
    let s = seals(t.path());
    assert_eq!(s.len(), 1);
    let c = rusqlite::Connection::open_with_flags(&s[0], rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let body: String = c.query_row("SELECT json(body) FROM records WHERE kind = 'tool_call'", [], |r| r.get(0)).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["command"], "echo 'it ran'");
}
