//! Commands still running when their `symbia_exec` call returned. They belong to the server
//! process: each is tracked here until it ends, when a `tool_call` record keyed `job.<id>`
//! records the outcome and `revises` the call's own record.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::exec::Job;
use crate::http::Slot;
use crate::record::{LinkInput, RecordInput};

/// At shutdown, how long a killed job's task gets to finish it before it is finished as is.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(500);

struct Entry {
    job: Arc<Job>,
    /// The `tool_call` record of the call that started it.
    start_id: String,
    recorded: AtomicBool,
}

/// The jobs of one session, and what it takes to record their ends.
pub struct Jobs {
    slot: Slot,
    key: Arc<SigningKey>,
    client: Arc<Mutex<Option<String>>>,
    map: Mutex<BTreeMap<String, Arc<Entry>>>,
}

pub fn new_id() -> Result<String, String> {
    let mut r = [0u8; 6];
    getrandom::fill(&mut r).map_err(|e| e.to_string())?;
    Ok(hex::encode(r))
}

impl Jobs {
    pub fn new(slot: Slot, key: Arc<SigningKey>, client: Arc<Mutex<Option<String>>>) -> Self {
        Self { slot, key, client, map: Mutex::default() }
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Arc<Entry>>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Track job `id`, started by the call recorded as `start_id`, and record its end when it ends.
    pub fn insert(self: &Arc<Self>, id: &str, job: Arc<Job>, start_id: String) {
        let entry = Arc::new(Entry { job, start_id, recorded: AtomicBool::new(false) });
        self.entries().insert(id.to_string(), entry.clone());
        let jobs = Arc::downgrade(self);
        let id = id.to_string();
        tokio::spawn(async move {
            entry.job.wait(None).await;
            if let Some(jobs) = jobs.upgrade() {
                jobs.record_end(&id, &entry);
            }
        });
    }

    pub fn get(&self, id: &str) -> Option<Arc<Job>> {
        self.entries().get(id).map(|e| e.job.clone())
    }

    /// Write job `id`'s end record now if it has ended and it is not written yet.
    pub fn settle(&self, id: &str) {
        let entry = self.entries().get(id).cloned();
        if let Some(e) = entry {
            self.record_end(id, &e);
        }
    }

    /// `[{job, pid, started_ms, command}]` of the jobs still running.
    pub fn running(&self) -> Vec<Value> {
        self.entries()
            .iter()
            .filter(|(_, e)| e.job.running())
            .map(|(id, e)| json!({"job": id, "pid": e.job.pid, "started_ms": e.job.started_ms, "command": e.job.command}))
            .collect()
    }

    /// Kill every running job's process group and record it as killed by `"shutdown"`.
    pub async fn shutdown(&self) {
        let live: Vec<(String, Arc<Entry>)> = self.entries().iter().filter(|(_, e)| e.job.running()).map(|(k, e)| (k.clone(), e.clone())).collect();
        for (_, e) in &live {
            e.job.kill("shutdown");
        }
        for (id, e) in &live {
            e.job.kill_and_finish("shutdown", SHUTDOWN_GRACE).await;
            self.record_end(id, e);
        }
    }

    /// The end record: exit, duration, stream digests and evidence, linked `revises` to the
    /// start record. Written once; a failure goes to stderr.
    fn record_end(&self, id: &str, e: &Entry) {
        let Some(outcome) = e.job.outcome() else { return };
        if e.recorded.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut body = json!({"tool": "symbia_exec", "job": id, "command": e.job.command, "running": false});
        let mut evidence = Vec::new();
        match &outcome {
            Ok(f) => {
                body["exit"] = f.exit.clone();
                body["duration_ms"] = f.duration_ms.into();
                body["stdout_sha256"] = hex::encode(f.stdout.sha256).into();
                body["stderr_sha256"] = hex::encode(f.stderr.sha256).into();
                body["truncated"] = (f.stdout.cut || f.stderr.cut).into();
                if let Some(k) = f.killed {
                    body["killed"] = k.into();
                }
                evidence.extend(f.evidence());
            }
            Err(err) => body["error"] = err.as_str().into(),
        }
        let input = RecordInput {
            key: format!("job.{id}"),
            kind: "tool_call".into(),
            lane: "apocryphal".into(),
            lane_reason: crate::mcp::TOOL_LANE_REASON.into(),
            body,
            model: self.client.lock().ok().and_then(|c| c.clone()).unwrap_or_else(|| crate::mcp::UNKNOWN_CLIENT.into()),
            est_host_ms: None,
            est_chars: None,
            links: Some(vec![LinkInput { to_id: e.start_id.clone(), rel: "revises".into() }]),
        };
        let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        let Some(store) = slot.as_mut() else { return };
        match store.write_with(&input, Instant::now(), None, &evidence) {
            Ok(_) => {
                if let Err(err) = crate::seal::checkpoint(store, &self.key, &input.kind) {
                    eprintln!("symbia: checkpoint seal of {} failed: {err:#}", store.session());
                }
            }
            Err(err) => eprintln!("symbia: end record of job {id} failed: {err:#}"),
        }
    }
}
