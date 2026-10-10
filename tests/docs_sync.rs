//! The README names everything the binary offers: each command in its usage text, and each
//! MCP tool in the Tools table. A new command or tool without docs fails here.

use rmcp::ServiceExt;
use rmcp::transport::TokioChildProcess;

const BIN: &str = env!("CARGO_BIN_EXE_symbia");

fn readme() -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")).unwrap()
}

/// `symbia <words>` from each usage line, up to the first argument (`<…>` or `[…]`).
fn usage_commands() -> Vec<String> {
    let t = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(BIN).env("SYMBIA_HOME", t.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8(out.stderr).unwrap();
    let cmds: Vec<String> = text
        .lines()
        .filter_map(|l| {
            let l = l.trim().trim_start_matches("usage:").trim();
            let words: Vec<&str> = l.split_whitespace().take_while(|w| !w.starts_with('<') && !w.starts_with('[')).collect();
            (words.first() == Some(&"symbia") && words.len() > 1).then(|| words.join(" "))
        })
        .collect();
    assert!(cmds.len() >= 8, "usage text changed shape: {text}");
    cmds
}

#[test]
fn every_command_in_the_usage_text_is_in_the_readme() {
    let readme = readme();
    let missing: Vec<String> = usage_commands().into_iter().filter(|c| !readme.contains(&format!("`{c}"))).collect();
    assert!(missing.is_empty(), "README doesn't name: {missing:?}");
}

#[tokio::test]
async fn every_tool_has_a_row_in_the_readme_tools_table() {
    let readme = readme();
    let start = readme.find("\n## Tools\n").expect("README has a Tools section");
    let section = &readme[start + 1..];
    let section = &section[..section[1..].find("\n## ").map_or(section.len(), |i| i + 1)];

    let t = tempfile::tempdir().unwrap();
    let mut cmd = tokio::process::Command::new(BIN);
    cmd.arg("mcp").env("SYMBIA_HOME", t.path());
    let client = ().serve(TokioChildProcess::new(cmd).unwrap()).await.unwrap();
    let names: Vec<String> = client.list_all_tools().await.unwrap().into_iter().map(|t| t.name.to_string()).collect();
    client.cancel().await.unwrap();

    assert!(!names.is_empty());
    let missing: Vec<&String> = names.iter().filter(|n| !section.contains(&format!("\n| `{n}` |"))).collect();
    assert!(missing.is_empty(), "README Tools table has no row for: {missing:?}");
}
