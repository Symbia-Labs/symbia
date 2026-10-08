//! Embeddings for vector search: an OpenAI-style `/v1/embeddings` endpoint on loopback, or a
//! `llama-server` that Symbia starts itself on first use and stops when it exits.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};

/// Texts sent per request.
pub const BATCH: usize = 32;
/// Documents embedded per search call; the rest wait for later calls.
pub const PER_CALL: u32 = 256;
/// How long a started server gets to answer `GET /health`.
pub const START_WAIT: Duration = Duration::from_secs(60);
const REQUEST_WAIT: Duration = Duration::from_secs(60);
pub const NOT_CONFIGURED: &str = "vector search needs \"embed\" in config.json";

/// `embed` in config.json: `{url, model}` or `{server, model_path}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbedConfig {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub model_path: Option<String>,
}

/// Where vectors come from, checked at load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbedSpec {
    /// An endpoint on loopback: host, port, path and the model name sent with each request.
    Url { host: String, port: u16, path: String, model: String },
    /// A `llama-server` binary and the GGUF model it serves.
    Server { program: PathBuf, model_path: PathBuf },
}

fn loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "[::1]" | "localhost")
}

impl EmbedSpec {
    /// Check `c`. `expand` turns `~` and requires an absolute path.
    pub fn load(c: &EmbedConfig, expand: impl Fn(&str) -> anyhow::Result<PathBuf>) -> anyhow::Result<Self> {
        match (c, &c.url, &c.server) {
            (EmbedConfig { model: Some(model), model_path: None, .. }, Some(url), None) => {
                let uri: http::Uri = url.parse().with_context(|| format!("embed url {url:?}"))?;
                if uri.scheme_str() != Some("http") {
                    bail!("embed url must be http on loopback, got {url:?}");
                }
                let host = uri.host().unwrap_or_default().to_string();
                if !loopback(&host) {
                    bail!("embed url must be on loopback (127.0.0.1, ::1 or localhost), got {host:?}");
                }
                let path = uri.path_and_query().map_or("/".into(), |p| p.as_str().to_string());
                Ok(Self::Url { host: host.trim_matches(['[', ']']).to_string(), port: uri.port_u16().unwrap_or(80), path, model: model.clone() })
            }
            (EmbedConfig { model: None, model_path: Some(mp), .. }, None, Some(server)) => {
                let program = std::fs::canonicalize(expand(server)?).with_context(|| format!("embed server {server:?}"))?;
                let model_path = std::fs::canonicalize(expand(mp)?).with_context(|| format!("embed model_path {mp:?}"))?;
                if !crate::unsandboxed::is_executable(&program) {
                    bail!("embed server {} is not an executable file", program.display());
                }
                if !model_path.is_file() {
                    bail!("embed model_path {} is not a file", model_path.display());
                }
                Ok(Self::Server { program, model_path })
            }
            _ => bail!("embed takes either url and model, or server and model_path"),
        }
    }

    /// The model name vectors are stored under.
    pub fn model_name(&self) -> String {
        match self {
            Self::Url { model, .. } => model.clone(),
            Self::Server { model_path, .. } => model_path.file_name().map_or_else(|| model_path.display().to_string(), |n| n.to_string_lossy().into_owned()),
        }
    }

    /// The arguments Symbia starts the server with.
    pub fn server_args(model_path: &std::path::Path, port: u16) -> Vec<String> {
        [
            "--model",
            &model_path.display().to_string(),
            "--embeddings",
            "--pooling",
            "mean",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--ctx-size",
            "2048",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }
}

/// A server Symbia started: killed when dropped.
struct Started {
    _child: tokio::process::Child,
    port: u16,
}

pub struct Embedder {
    spec: EmbedSpec,
    started: tokio::sync::Mutex<Option<Started>>,
}

/// One HTTP/1.1 request to `host:port`; the status and the body.
async fn request(host: &str, port: u16, method: &str, path: &str, body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String> {
    let addr = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let stream = tokio::net::TcpStream::connect(&addr).await.map_err(|e| format!("connect {addr}: {e}"))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", addr.as_str())
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|e| e.to_string())?;
    let res = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = res.status().as_u16();
    let bytes = res.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
    Ok((status, bytes.to_vec()))
}

/// A free loopback port, by binding and releasing it.
fn free_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())
}

impl Embedder {
    pub fn new(spec: EmbedSpec) -> Self {
        Self { spec, started: tokio::sync::Mutex::new(None) }
    }

    pub fn model_name(&self) -> String {
        self.spec.model_name()
    }

    /// Host, port, path and model of the endpoint, starting the server first if needed.
    async fn endpoint(&self) -> Result<(String, u16, String, String), String> {
        match &self.spec {
            EmbedSpec::Url { host, port, path, model } => Ok((host.clone(), *port, path.clone(), model.clone())),
            EmbedSpec::Server { program, model_path } => {
                let mut g = self.started.lock().await;
                if g.is_none() {
                    *g = Some(start(program, model_path).await?);
                }
                let port = g.as_ref().map(|s| s.port).ok_or("embed server did not start")?;
                Ok(("127.0.0.1".into(), port, "/v1/embeddings".into(), self.spec.model_name()))
            }
        }
    }

    /// Vectors for `texts`, in order, sent in batches of [`BATCH`].
    pub async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        let (host, port, path, model) = self.endpoint().await?;
        let mut out = Vec::with_capacity(texts.len());
        for chunk in texts.chunks(BATCH) {
            let body = serde_json::to_vec(&json!({"model": model, "input": chunk})).map_err(|e| e.to_string())?;
            let (status, bytes) = tokio::time::timeout(REQUEST_WAIT, request(&host, port, "POST", &path, Some(body)))
                .await
                .map_err(|_| "embed request timed out".to_string())??;
            if status != 200 {
                return Err(format!("embed endpoint answered {status}: {}", String::from_utf8_lossy(&bytes[..bytes.len().min(200)])));
            }
            let v: Value = serde_json::from_slice(&bytes).map_err(|e| format!("embed reply: {e}"))?;
            let mut data: Vec<(u64, Vec<f32>)> = v["data"]
                .as_array()
                .ok_or("embed reply has no data")?
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    let idx = d["index"].as_u64().unwrap_or(i as u64);
                    let e: Vec<f32> = d["embedding"].as_array().map(|a| a.iter().filter_map(Value::as_f64).map(|x| x as f32).collect()).unwrap_or_default();
                    (idx, e)
                })
                .collect();
            data.sort_by_key(|d| d.0);
            if data.len() != chunk.len() || data.iter().any(|d| d.1.is_empty()) {
                return Err(format!("embed reply has {} vectors for {} texts", data.len(), chunk.len()));
            }
            out.extend(data.into_iter().map(|d| d.1));
        }
        Ok(out)
    }
}

/// Start `program` serving `model_path` on a free loopback port and wait for `/health`.
async fn start(program: &std::path::Path, model_path: &std::path::Path) -> Result<Started, String> {
    let port = free_port()?;
    let mut child = tokio::process::Command::new(program)
        .args(EmbedSpec::server_args(model_path, port))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("start {}: {e}", program.display()))?;
    let deadline = tokio::time::Instant::now() + START_WAIT;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("embed server exited before it was ready ({status})"));
        }
        if let Ok((200, _)) = request("127.0.0.1", port, "GET", "/health", None).await {
            return Ok(Started { _child: child, port });
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("embed server not ready after {} s", START_WAIT.as_secs()));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// A fake embeddings endpoint for tests: each text's vector counts the letters a to h in it.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub fn vector(text: &str) -> Vec<f32> {
        let mut v = vec![0f32; 8];
        for b in text.bytes() {
            if (b'a'..=b'h').contains(&b) {
                v[(b - b'a') as usize] += 1.0;
            }
        }
        v
    }

    /// Serve on a free port; returns the port and a count of requests seen.
    pub async fn serve() -> (u16, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(AtomicUsize::new(0));
        let count = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let count = count.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let count = count.clone();
                        async move {
                            count.fetch_add(1, Ordering::SeqCst);
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                            let data: Vec<Value> = v["input"]
                                .as_array()
                                .map(|a| a.iter().enumerate().rev().map(|(i, t)| json!({"index": i, "embedding": vector(t.as_str().unwrap_or(""))})).collect())
                                .unwrap_or_default();
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(json!({"data": data}).to_string()))))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
                });
            }
        });
        (port, seen)
    }

    pub fn spec(port: u16) -> EmbedSpec {
        EmbedSpec::Url { host: "127.0.0.1".into(), port, path: "/v1/embeddings".into(), model: "fake-8".into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abs(p: &str) -> anyhow::Result<PathBuf> {
        Ok(PathBuf::from(p))
    }

    fn cfg(v: Value) -> EmbedConfig {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn load_checks_the_form_and_loopback() {
        let s = EmbedSpec::load(&cfg(json!({"url": "http://127.0.0.1:8081/v1/embeddings", "model": "nomic"})), abs).unwrap();
        assert_eq!(s, EmbedSpec::Url { host: "127.0.0.1".into(), port: 8081, path: "/v1/embeddings".into(), model: "nomic".into() });
        assert_eq!(s.model_name(), "nomic");
        let v6 = EmbedSpec::load(&cfg(json!({"url": "http://[::1]:9/e", "model": "m"})), abs).unwrap();
        assert!(matches!(v6, EmbedSpec::Url { ref host, port: 9, .. } if host == "::1"));
        for bad in [
            json!({"url": "http://10.0.0.5:8081/v1/embeddings", "model": "m"}),
            json!({"url": "https://127.0.0.1/v1/embeddings", "model": "m"}),
            json!({"url": "http://example.com/v1/embeddings", "model": "m"}),
            json!({"url": "http://127.0.0.1/e"}),
            json!({"url": "http://127.0.0.1/e", "model": "m", "server": "/bin/sh"}),
            json!({"server": "/bin/sh"}),
            json!({}),
        ] {
            assert!(EmbedSpec::load(&cfg(bad.clone()), abs).is_err(), "{bad}");
        }
        assert!(serde_json::from_value::<EmbedConfig>(json!({"url": "x", "model": "m", "port": 1})).is_err());
        // Server form: both paths must exist; the model name is the file name.
        let t = tempfile::tempdir().unwrap();
        let model = t.path().join("nomic.gguf");
        std::fs::write(&model, "gguf").unwrap();
        let s = EmbedSpec::load(&cfg(json!({"server": "/bin/sh", "model_path": model})), abs).unwrap();
        assert_eq!(s.model_name(), "nomic.gguf");
        assert!(EmbedSpec::load(&cfg(json!({"server": "/bin/sh", "model_path": t.path().join("none.gguf")})), abs).is_err());
        assert!(EmbedSpec::load(&cfg(json!({"server": model, "model_path": model})), abs).unwrap_err().to_string().contains("not an executable"));
    }

    #[test]
    fn server_arguments() {
        let a = EmbedSpec::server_args(std::path::Path::new("/m/x.gguf"), 4242);
        assert_eq!(a.join(" "), "--model /m/x.gguf --embeddings --pooling mean --host 127.0.0.1 --port 4242 --ctx-size 2048");
    }

    #[tokio::test]
    async fn embeds_in_batches_and_keeps_order() {
        let (port, seen) = fake::serve().await;
        let e = Embedder::new(fake::spec(port));
        let texts: Vec<String> = (0..70).map(|i| if i % 2 == 0 { "aaa".into() } else { format!("b{i}") }).collect();
        let v = e.embed(&texts).await.unwrap();
        assert_eq!(v.len(), 70);
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 3, "70 texts in batches of 32");
        assert_eq!(v[0], fake::vector("aaa"));
        assert_eq!(v[69], fake::vector("b69"));
        assert_eq!(e.model_name(), "fake-8");
    }

    #[tokio::test]
    async fn an_unreachable_endpoint_is_an_error() {
        let port = free_port().unwrap();
        let e = Embedder::new(fake::spec(port));
        assert!(e.embed(&["x".into()]).await.unwrap_err().starts_with("connect 127.0.0.1:"));
    }

    /// Spawn mode, with a small Python stand-in for llama-server when python3 is present.
    #[tokio::test]
    async fn spawn_mode_starts_waits_and_stops_the_server() {
        let Some(python) = ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"].into_iter().find(|p| std::path::Path::new(p).exists()) else {
            eprintln!("skipped: no python3");
            return;
        };
        let t = tempfile::tempdir().unwrap();
        let args_file = t.path().join("args.txt");
        let script = t.path().join("fake-llama-server");
        std::fs::write(
            &script,
            format!(
                r#"#!{python}
import json, sys, time, http.server
open({args:?}, "w").write(" ".join(sys.argv[1:]))
port = int(sys.argv[sys.argv.index("--port") + 1])
time.sleep(0.5)
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404); self.end_headers(); self.wfile.write(b"{{}}")
    def do_POST(self):
        n = int(self.headers["content-length"]); body = json.loads(self.rfile.read(n))
        data = [{{"index": i, "embedding": [float(len(t)), 1.0]}} for i, t in enumerate(body["input"])]
        out = json.dumps({{"data": data}}).encode()
        self.send_response(200); self.send_header("content-length", str(len(out))); self.end_headers(); self.wfile.write(out)
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
"#,
                args = args_file.display().to_string()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let model = t.path().join("m.gguf");
        std::fs::write(&model, "gguf").unwrap();
        let e = Embedder::new(EmbedSpec::Server { program: script, model_path: model.clone() });
        let v = e.embed(&["abc".into(), "de".into()]).await.unwrap();
        assert_eq!(v, vec![vec![3.0, 1.0], vec![2.0, 1.0]]);
        let args = std::fs::read_to_string(&args_file).unwrap();
        assert!(args.starts_with(&format!("--model {} --embeddings --pooling mean --host 127.0.0.1 --port ", model.display())), "{args}");
        let port = e.started.lock().await.as_ref().unwrap().port;
        // A second call reuses the running server.
        e.embed(&["x".into()]).await.unwrap();
        assert_eq!(e.started.lock().await.as_ref().unwrap().port, port);
        drop(e);
        // Dropped: the server is killed and the port stops answering.
        let mut gone = false;
        for _ in 0..50 {
            if request("127.0.0.1", port, "GET", "/health", None).await.is_err() {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(gone, "server still answering after drop");
    }
}
