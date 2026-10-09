//! R4, through the real binary: an image read arrives as MCP image content, and a job still
//! running at SIGTERM is killed, recorded and sealed.

mod common;

use std::time::{Duration, Instant};

use common::stdio::{Mcp, seals};
use serde_json::{Value, json};

fn png(w: u32, h: u32) -> Vec<u8> {
    let img = image::ImageBuffer::from_fn(w, h, |x, y| image::Rgb([x as u8, y as u8, 7]));
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(img).write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

#[tokio::test]
async fn an_image_read_is_image_content_on_the_wire() {
    let t = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("config.json"), json!({"roots": [root.path()]}).to_string()).unwrap();
    std::fs::write(root.path().join("shot.png"), png(32, 16)).unwrap();
    let mut m = Mcp::start(t.path()).await;
    m.send(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read", "arguments": {"path": root.path().join("shot.png")}}}))
        .await;
    let r = m.reply(1).await;
    let content = &r["result"]["content"];
    assert_eq!((content[0]["type"].as_str(), content[0]["mimeType"].as_str()), (Some("image"), Some("image/png")), "{r}");
    assert!(content[0]["data"].as_str().is_some_and(|d| !d.is_empty()));
    assert_eq!(content[1]["type"], "text");
    let text: Value = serde_json::from_str(content[1]["text"].as_str().unwrap()).unwrap();
    assert_eq!((text["format"].as_str(), text["sent_width"].as_u64(), text["sent_height"].as_u64()), (Some("png"), Some(32), Some(16)));
    m.close().await;
}

#[tokio::test]
async fn sigterm_kills_a_running_job_records_it_and_seals() {
    let t = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::write(t.path().join("config.json"), json!({"roots": [root.path()]}).to_string()).unwrap();
    let mut m = Mcp::start(t.path()).await;
    let r = m.tool(1, "exec", json!({"command": "echo going; sleep 60", "cwd": root.path(), "yield_ms": 300})).await.unwrap();
    let job = r["job"].as_str().unwrap().to_string();
    let pid = i32::try_from(r["pid"].as_i64().unwrap()).unwrap();
    let status = m.tool(2, "status", json!({})).await.unwrap();
    assert_eq!(status["jobs"][0]["job"], job.as_str());

    let server = i32::try_from(m.child.id().unwrap()).unwrap();
    let sent = Instant::now();
    // SAFETY: signals our own child.
    assert_eq!(unsafe { libc::kill(server, libc::SIGTERM) }, 0);
    let sealed = loop {
        if let Some(s) = seals(t.path()).first().filter(|s| symbia::seal::verify(s).is_ok()) {
            break s.clone();
        }
        assert!(sent.elapsed() < Duration::from_secs(2), "no verified seal 2 s after SIGTERM");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    // SAFETY: signal 0 only checks that the process exists.
    assert!(unsafe { libc::kill(pid, 0) } != 0, "the job's shell is still running");
    let c = rusqlite::Connection::open_with_flags(&sealed, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let body: String = c.query_row("SELECT json(body) FROM records WHERE key = ?1", [format!("job.{job}")], |r| r.get(0)).unwrap();
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!((body["exit"].clone(), body["killed"].clone()), (json!("killed"), json!("shutdown")), "{body}");
    assert_eq!(body["stdout_sha256"], hex::encode(symbia::canon::sha256(b"going\n")));
    let exit = tokio::time::timeout(Duration::from_secs(20), m.child.wait()).await.unwrap().unwrap();
    assert!(exit.success(), "{exit:?}");
}
