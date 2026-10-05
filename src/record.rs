//! Record vocabulary, record ids and chain hashes.

use anyhow::bail;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::canon::{canonical, sha256};

pub const KINDS: [&str; 8] = [
    "prediction",
    "result",
    "observation",
    "claim",
    "rejection",
    "question_set",
    "tool_call",
    "promotion",
];
pub const LANES: [&str; 3] = ["canonical", "conditional", "apocryphal"];
pub const RELS: [&str; 4] = ["results_of", "revises", "supersedes", "cites"];

/// The fields a record id covers.
pub struct IdFields<'a> {
    pub key: &'a str,
    pub version: i64,
    pub kind: &'a str,
    pub lane: &'a str,
    pub body: &'a Value,
    pub model: &'a str,
    pub session: &'a str,
}

/// Lowercase hex sha256 of the RFC 8785 JSON of `{key, version, kind, lane, body, model, session}`.
pub fn record_id(f: &IdFields) -> anyhow::Result<String> {
    let doc = json!({
        "key": f.key,
        "version": f.version,
        "kind": f.kind,
        "lane": f.lane,
        "body": f.body,
        "model": f.model,
        "session": f.session,
    });
    Ok(hex::encode(sha256(canonical(&doc)?.as_bytes())))
}

/// `sha256(prev_hash || record_id_utf8 || at_ms as 8-byte big-endian)`.
pub fn chain_hash(prev_hash: &[u8; 32], record_id: &str, at_ms: i64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + record_id.len() + 8);
    buf.extend_from_slice(prev_hash);
    buf.extend_from_slice(record_id.as_bytes());
    buf.extend_from_slice(&at_ms.to_be_bytes());
    sha256(&buf)
}

pub const GENESIS: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LinkInput {
    /// Id of the record this one links to.
    pub to_id: String,
    /// One of results_of, revises, supersedes, cites.
    pub rel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RecordInput {
    /// Stable key; versions increment per key.
    pub key: String,
    /// prediction, result, observation, claim, rejection, question_set, tool_call or promotion.
    pub kind: String,
    /// canonical, conditional or apocryphal.
    pub lane: String,
    /// Why the record sits in this lane.
    pub lane_reason: String,
    /// Record body, any JSON value.
    pub body: Value,
    /// Model that produced the record.
    pub model: String,
    /// Caller's estimate of host handling time in ms.
    #[serde(default)]
    pub est_host_ms: Option<i64>,
    /// Caller's estimate of reply length in chars.
    #[serde(default)]
    pub est_chars: Option<i64>,
    /// Links from this record to earlier records.
    #[serde(default)]
    pub links: Option<Vec<LinkInput>>,
}

impl RecordInput {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.key.trim().is_empty() {
            bail!("key is empty");
        }
        if !KINDS.contains(&self.kind.as_str()) {
            bail!("unknown kind {:?}; expected one of {}", self.kind, KINDS.join(", "));
        }
        if !LANES.contains(&self.lane.as_str()) {
            bail!("unknown lane {:?}; expected one of {}", self.lane, LANES.join(", "));
        }
        if self.lane_reason.trim().is_empty() {
            bail!("lane_reason is required");
        }
        if self.model.trim().is_empty() {
            bail!("model is empty");
        }
        for (name, v) in [("est_host_ms", self.est_host_ms), ("est_chars", self.est_chars)] {
            if v.is_some_and(|v| v < 0) {
                bail!("{name} is negative");
            }
        }
        for l in self.links.iter().flatten() {
            if !RELS.contains(&l.rel.as_str()) {
                bail!("unknown rel {:?}; expected one of {}", l.rel, RELS.join(", "));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> (String, Value) {
        ("k".to_string(), json!({"x": 1}))
    }

    fn id_of(f: &IdFields) -> String {
        record_id(f).unwrap()
    }

    #[test]
    fn id_is_deterministic_and_lowercase_hex() {
        let (key, body) = base();
        let f = IdFields { key: &key, version: 1, kind: "prediction", lane: "canonical", body: &body, model: "m", session: "s" };
        let a = id_of(&f);
        assert_eq!(a, id_of(&f));
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Key order in the body does not matter: the JSON is canonical.
        let reordered: Value = serde_json::from_str(r#"{"y":2,"x":1}"#).unwrap();
        let ordered: Value = serde_json::from_str(r#"{"x":1,"y":2}"#).unwrap();
        let g = |b| id_of(&IdFields { body: b, ..f });
        assert_eq!(g(&reordered), g(&ordered));
    }

    #[test]
    fn id_changes_with_every_covered_field() {
        let (key, body) = base();
        let f = IdFields { key: &key, version: 1, kind: "prediction", lane: "canonical", body: &body, model: "m", session: "s" };
        let a = id_of(&f);
        let other_body = json!({"x": 2});
        let variants = [
            IdFields { key: "k2", ..f },
            IdFields { version: 2, ..f },
            IdFields { kind: "result", ..f },
            IdFields { lane: "apocryphal", ..f },
            IdFields { body: &other_body, ..f },
            IdFields { model: "m2", ..f },
            IdFields { session: "s2", ..f },
        ];
        for v in &variants {
            assert_ne!(id_of(v), a);
        }
    }

    #[test]
    fn id_matches_hand_computed_digest() {
        let body = json!({"x": 1});
        let f = IdFields { key: "k", version: 1, kind: "prediction", lane: "canonical", body: &body, model: "m", session: "s" };
        let text = r#"{"body":{"x":1},"key":"k","kind":"prediction","lane":"canonical","model":"m","session":"s","version":1}"#;
        assert_eq!(id_of(&f), hex::encode(sha256(text.as_bytes())));
    }

    #[test]
    fn chain_hash_layout() {
        let mut buf = vec![0u8; 32];
        buf.extend_from_slice(b"abc");
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(chain_hash(&GENESIS, "abc", 256), sha256(&buf));
    }

    fn input() -> RecordInput {
        RecordInput {
            key: "k".into(),
            kind: "prediction".into(),
            lane: "canonical".into(),
            lane_reason: "r".into(),
            body: json!({}),
            model: "m".into(),
            est_host_ms: None,
            est_chars: None,
            links: None,
        }
    }

    #[test]
    fn validation_rejects_bad_vocabulary() {
        assert!(input().validate().is_ok());
        assert!(RecordInput { kind: "guess".into(), ..input() }.validate().is_err());
        assert!(RecordInput { lane: "main".into(), ..input() }.validate().is_err());
        assert!(RecordInput { lane_reason: " ".into(), ..input() }.validate().is_err());
        assert!(RecordInput { key: "".into(), ..input() }.validate().is_err());
        assert!(RecordInput { est_chars: Some(-1), ..input() }.validate().is_err());
        let bad_rel = vec![LinkInput { to_id: "x".into(), rel: "likes".into() }];
        assert!(RecordInput { links: Some(bad_rel), ..input() }.validate().is_err());
    }
}
