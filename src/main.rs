use std::path::Path;
use std::process::ExitCode;

use rmcp::ServiceExt;

const USAGE: &str = "usage: symbia mcp | symbia verify <sealed.sqlite> | symbia --version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["mcp"] => match run_mcp() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("symbia mcp: {e:#}");
                ExitCode::FAILURE
            }
        },
        ["verify", path] => match symbia::seal::verify(Path::new(path)) {
            Ok(v) => {
                println!("ok {} seq {} head {}", v.session, v.chain_seq, &v.chain_head[..12]);
                ExitCode::SUCCESS
            }
            Err(reason) => {
                eprintln!("{reason}");
                ExitCode::FAILURE
            }
        },
        ["--version"] => {
            println!("{}", symbia::BUILD);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_mcp() -> anyhow::Result<()> {
    let home = symbia::home::from_env()?;
    let server = symbia::mcp::SymbiaServer::new(&home)?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let running = server.serve(rmcp::transport::stdio()).await?;
        running.waiting().await?;
        Ok(())
    })
}
