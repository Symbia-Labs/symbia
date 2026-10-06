#![allow(dead_code)]

pub mod stdio;

use rmcp::model::CallToolRequestParams;
use rmcp::service::{RoleClient, RunningService};
use serde_json::Value;

pub type Client = RunningService<RoleClient, ()>;

/// Call a tool and parse its text reply as JSON. Tool errors become `Err(text)`.
pub async fn call(client: &Client, name: &'static str, args: Value) -> Result<Value, String> {
    let mut p = CallToolRequestParams::new(name);
    if let Value::Object(map) = args {
        p = p.with_arguments(map);
    }
    let r = client.call_tool(p).await.map_err(|e| format!("transport: {e}"))?;
    let text = r.content[0].as_text().expect("text reply").text.clone();
    if r.is_error == Some(true) {
        return Err(text);
    }
    Ok(serde_json::from_str(&text).expect("JSON reply"))
}

/// Raw text of a successful tool reply.
pub async fn call_text(client: &Client, name: &'static str, args: Value) -> String {
    let mut p = CallToolRequestParams::new(name);
    if let Value::Object(map) = args {
        p = p.with_arguments(map);
    }
    let r = client.call_tool(p).await.expect("call");
    assert_ne!(r.is_error, Some(true));
    r.content[0].as_text().expect("text reply").text.clone()
}
