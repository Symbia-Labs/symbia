//! symbia: typed records in a signed, hash-chained SQLite ledger, served over MCP.

pub mod canon;
pub mod embed;
pub mod exec;
pub mod files;
pub mod home;
pub mod http;
pub mod images;
pub mod index;
pub mod jobs;
pub mod keys;
pub mod mcp;
pub mod policy;
pub mod read;
pub mod record;
pub mod rules;
pub mod seal;
pub mod session;
pub mod store;
pub mod trust;
pub mod unsandboxed;
pub mod witness;

/// Current UTC time in integer milliseconds since the Unix epoch. A clock set before 1970
/// reads as 0 rather than panicking the server.
pub fn now_ms() -> i64 {
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    i64::try_from(ms).unwrap_or(i64::MAX)
}

/// Run blocking work (SQLite, sealing, hashing) from async code. On a multi-thread runtime the
/// worker is handed over first, so other calls keep moving while this one waits on the disk or
/// on the store lock; anywhere else it just runs.
pub fn blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// Build string reported by `status`.
pub const BUILD: &str = concat!("symbia ", env!("CARGO_PKG_VERSION"));
