//! RFC 8785 canonical JSON and sha256 helpers.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// RFC 8785 (JCS) canonical JSON text of `value`.
pub fn canonical<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<String> {
    Ok(serde_jcs::to_string(value)?)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// First `n` lowercase hex chars of `bytes`.
pub fn hex_prefix(bytes: &[u8], n: usize) -> String {
    let mut s = hex::encode(bytes);
    s.truncate(n);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_keys_and_strips_whitespace() {
        let v: serde_json::Value = serde_json::from_str(r#"{ "b": 1, "a": [true, null, "x"] }"#).unwrap();
        assert_eq!(canonical(&v).unwrap(), r#"{"a":[true,null,"x"],"b":1}"#);
    }

    #[test]
    fn canonical_numbers_follow_rfc8785() {
        assert_eq!(canonical(&json!(1.0)).unwrap(), "1");
        assert_eq!(canonical(&json!(1e21)).unwrap(), "1e+21");
        assert_eq!(canonical(&json!(0.1)).unwrap(), "0.1");
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex_prefix(&sha256(b"abc"), 12), "ba7816bf8f01");
    }
}
