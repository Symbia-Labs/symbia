//! `symbia mcp` spawned over stdio, spoken to as raw JSON-RPC lines.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

pub const BIN: &str = env!("CARGO_BIN_EXE_symbia");

pub struct Mcp {
    pub child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl Mcp {
    pub async fn start(home: &Path) -> Self {
        Self::start_with(home, &[]).await
    }

    /// Start with extra environment variables, e.g. a temp `HOME`.
    pub async fn start_with(home: &Path, env: &[(&str, &Path)]) -> Self {
        Self::start_as(home, env, "stdio-test").await
    }

    /// Start as a client named `client`, which tool-call records carry as their model.
    pub async fn start_as(home: &Path, env: &[(&str, &Path)], client: &str) -> Self {
        let mut cmd = Command::new(BIN);
        cmd.arg("mcp").env("SYMBIA_HOME", home);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true).spawn().unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut m = Self { child, stdin, stdout };
        m.send(json!({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": client, "version": "0"}}}))
            .await;
        assert!(m.reply(0).await["result"]["protocolVersion"].is_string());
        m.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
        m
    }

    pub async fn send(&mut self, msg: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
        stdin.flush().await.unwrap();
    }

    pub async fn reply(&mut self, id: i64) -> Value {
        loop {
            let line = self.stdout.next_line().await.unwrap().expect("server closed stdout");
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    }

    /// Call a tool; the parsed text reply, or `Err(text)` for a tool error.
    pub async fn tool(&mut self, id: i64, name: &str, args: Value) -> Result<Value, String> {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})).await;
        let r = self.reply(id).await;
        let text = r["result"]["content"][0]["text"].as_str().unwrap_or_else(|| panic!("{r}")).to_string();
        if r["result"]["isError"] == true { Err(text) } else { Ok(serde_json::from_str(&text).unwrap()) }
    }

    /// Close stdin and wait for the process to exit; returns its stderr.
    pub async fn close(mut self) -> String {
        drop(self.stdin.take());
        let out = tokio::time::timeout(Duration::from_secs(20), self.child.wait_with_output()).await.expect("exit after EOF").unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8_lossy(&out.stderr).into_owned()
    }
}

/// The sealed copies under `home/seals`, sorted.
pub fn seals(home: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(home.join("seals"))
        .map(|d| d.map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "sqlite")).collect())
        .unwrap_or_default();
    v.sort();
    v
}
