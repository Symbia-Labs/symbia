//! symbia: typed records in a signed, hash-chained SQLite ledger, served over MCP.

pub mod canon;
pub mod exec;
pub mod files;
pub mod home;
pub mod http;
pub mod keys;
pub mod mcp;
pub mod policy;
pub mod record;
pub mod seal;
pub mod store;
pub mod trust;

/// Current UTC time in integer milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970");
    i64::try_from(d.as_millis()).expect("time overflows i64")
}

/// Build string reported by `symbia_status`.
pub const BUILD: &str = concat!("symbia ", env!("CARGO_PKG_VERSION"));
