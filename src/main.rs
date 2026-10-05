use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use rmcp::ServiceExt;

const USAGE: &str = "usage: symbia mcp
       symbia serve [--listen 127.0.0.1:7341] [--allow-remote]
       symbia verify <sealed.sqlite> [--trust <hex>]...
       symbia trust add <hex> <label>
       symbia trust list
       symbia --version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["mcp"] => report("symbia mcp", run_mcp()),
        ["serve", rest @ ..] => match parse_serve(rest) {
            Some((addr, remote)) => report("symbia serve", run_serve(addr, remote)),
            None => usage(),
        },
        ["verify", rest @ ..] => match parse_verify(rest) {
            Some((path, extra)) => run_verify(Path::new(path), &extra),
            None => usage(),
        },
        ["trust", "add", key, label] => report("symbia trust", trust_add(key, label)),
        ["trust", "list"] => report("symbia trust", trust_list()),
        ["--version"] => {
            println!("{}", symbia::BUILD);
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn report(what: &str, r: anyhow::Result<()>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{what}: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// `[--listen <addr>] [--allow-remote]` in any order.
fn parse_serve(mut rest: &[&str]) -> Option<(String, bool)> {
    let mut listen = symbia::http::DEFAULT_LISTEN.to_string();
    let mut remote = false;
    loop {
        match rest {
            [] => return Some((listen, remote)),
            ["--listen", addr, tail @ ..] => {
                listen = addr.to_string();
                rest = tail;
            }
            ["--allow-remote", tail @ ..] => {
                remote = true;
                rest = tail;
            }
            _ => return None,
        }
    }
}

/// `<path>` plus any number of `--trust <hex>`, in any order.
fn parse_verify<'a>(mut rest: &[&'a str]) -> Option<(&'a str, Vec<&'a str>)> {
    let mut path = None;
    let mut extra = Vec::new();
    loop {
        match rest {
            [] => return path.map(|p| (p, extra)),
            ["--trust", key, tail @ ..] => {
                extra.push(*key);
                rest = tail;
            }
            [p, tail @ ..] if path.is_none() && !p.starts_with("--") => {
                path = Some(*p);
                rest = tail;
            }
            _ => return None,
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

fn run_serve(listen: String, remote: bool) -> anyhow::Result<()> {
    let addr: SocketAddr = listen.parse().map_err(|_| anyhow::anyhow!("--listen wants ip:port, got {listen:?}"))?;
    symbia::http::check_listen(addr, remote)?;
    let home = symbia::home::from_env()?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        eprintln!("symbia serve: http://{}{}", listener.local_addr()?, symbia::http::PATH);
        tokio::select! {
            r = symbia::http::serve(home, listener) => r,
            _ = tokio::signal::ctrl_c() => Ok(()),
        }
    })
}

/// Exit 0 with `ok ...`, 1 with a one-line reason, or 2 for a bad `--trust` key.
fn run_verify(path: &Path, extra: &[&str]) -> ExitCode {
    let mut trusted = match symbia::home::from_env().and_then(|h| symbia::trust::load(&h)) {
        Ok(list) => list.into_iter().map(|t| t.public_key).collect::<Vec<_>>(),
        Err(e) => {
            eprintln!("cannot read trusted keys: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    for k in extra {
        match symbia::trust::parse_key(k) {
            Ok(k) => trusted.push(k),
            Err(e) => {
                eprintln!("--trust: {e}");
                return ExitCode::from(2);
            }
        }
    }
    match symbia::seal::verify_trusted(path, &trusted) {
        Ok(v) => {
            println!("ok {} seq {} head {}", v.session, v.chain_seq, &v.chain_head[..12]);
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("{reason}");
            ExitCode::FAILURE
        }
    }
}

fn trust_add(key: &str, label: &str) -> anyhow::Result<()> {
    let home = symbia::home::from_env()?;
    let (t, added) = symbia::trust::add(&home, key, label)?;
    let state = if added { "added" } else { "already trusted" };
    println!("{state} {} {}", &t.public_key[..12], t.label);
    Ok(())
}

fn trust_list() -> anyhow::Result<()> {
    let home = symbia::home::from_env()?;
    for t in symbia::trust::load(&home)? {
        println!("{} {} {}", t.public_key, t.added_ms, t.label);
    }
    Ok(())
}
