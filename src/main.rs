use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use rmcp::ServiceExt;

const USAGE: &str = "usage: symbia mcp
       symbia serve [--listen 127.0.0.1:7341] [--allow-remote]
       symbia verify <sealed.sqlite> [--trust <hex>]... [--witness <folder or witness.jsonl>]
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
            Some(v) => run_verify(Path::new(v.path), &v.trust, v.witness.map(Path::new)),
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

struct VerifyArgs<'a> {
    path: &'a str,
    trust: Vec<&'a str>,
    witness: Option<&'a str>,
}

/// `<path>` plus any number of `--trust <hex>` and at most one `--witness <path>`, in any order.
fn parse_verify<'a>(mut rest: &[&'a str]) -> Option<VerifyArgs<'a>> {
    let mut path = None;
    let mut trust = Vec::new();
    let mut witness = None;
    loop {
        match rest {
            [] => return path.map(|path| VerifyArgs { path, trust, witness }),
            ["--trust", key, tail @ ..] => {
                trust.push(*key);
                rest = tail;
            }
            ["--witness", w, tail @ ..] if witness.is_none() => {
                witness = Some(*w);
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

/// How long in-flight tool calls get to finish before the exit seal.
const DRAIN: Duration = Duration::from_secs(5);

/// SIGINT or SIGTERM.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let term = async {
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = term => {}
    }
}

/// Seal on exit if anything was written since the last seal; a failure goes to stderr.
fn seal_on_exit(server: &symbia::mcp::SymbiaServer) {
    if let Err(e) = server.seal_pending() {
        eprintln!("symbia mcp: seal on exit failed: {e}");
    }
}

/// Serve over stdio until the transport closes or a signal arrives. Kill running jobs and
/// record them, then seal the session at once, since a client may kill the process soon
/// after, then drain in-flight tool calls and seal again if any of them wrote.
fn run_mcp() -> anyhow::Result<()> {
    let home = symbia::home::from_env()?;
    let server = symbia::mcp::SymbiaServer::new(&home)?;
    let handle = server.clone();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let r = rt.block_on(async {
        let running = server.serve(rmcp::transport::stdio()).await?;
        let r = tokio::select! {
            r = running.waiting() => r.map(|_| ()).map_err(anyhow::Error::from),
            () = shutdown_signal() => Ok(()),
        };
        handle.shutdown_jobs().await;
        seal_on_exit(&handle);
        r
    });
    rt.shutdown_timeout(DRAIN);
    seal_on_exit(&handle);
    handle.release();
    r
}

fn run_serve(listen: String, remote: bool) -> anyhow::Result<()> {
    let addr: SocketAddr = listen.parse().map_err(|_| anyhow::anyhow!("--listen wants ip:port, got {listen:?}"))?;
    symbia::http::check_listen(addr, remote)?;
    let home = symbia::home::from_env()?;
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let r = rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        eprintln!("symbia serve: http://{}{}", listener.local_addr()?, symbia::http::PATH);
        symbia::http::serve(home, listener, shutdown_signal()).await
    });
    rt.shutdown_timeout(DRAIN);
    r
}

/// Exit 0 with `ok ...`, 1 with a one-line reason (a witness mismatch included), or 2 for a
/// bad `--trust` key.
fn run_verify(path: &Path, extra: &[&str], witness: Option<&Path>) -> ExitCode {
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
            match &v.thread {
                Some(t) => println!("ok {} seq {} head {} thread {t}: {} records, {} withheld", v.session, v.chain_seq, &v.chain_head[..12], v.records, v.withheld),
                None => println!("ok {} seq {} head {}", v.session, v.chain_seq, &v.chain_head[..12]),
            }
            for x in &v.external {
                println!("external {} {} {} session {}", &x.from_id[..12], x.rel, &x.to_id[..x.to_id.len().min(12)], x.session);
            }
            if let Some(w) = witness {
                let entries = match symbia::witness::read(&symbia::witness::file_of(w)) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("cannot read witness {}: {e:#}", w.display());
                        return ExitCode::FAILURE;
                    }
                };
                match symbia::witness::check(path, &v.session, v.chain_seq, &entries) {
                    Ok(c) => println!("witness {}", c.describe()),
                    Err(reason) => {
                        eprintln!("{reason}");
                        return ExitCode::FAILURE;
                    }
                }
            }
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
