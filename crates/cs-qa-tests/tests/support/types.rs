//! Adapter-neutral types shared by `contract.rs` (real bindings) and `contract_stub.rs`.
//! Tests only ever see these types, never engineer-owned types.

use uuid::Uuid;

/// An Appendix D error as observed through the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorView {
    pub code: String,
    pub status: u16,
    pub retryable: bool,
}

/// An HTTP response rendered by the implementation's problem-details renderer.
#[derive(Debug, Clone)]
pub struct Rendered {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Rendered {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// A field error for `errors[]` (D.1).
#[derive(Debug, Clone)]
pub struct FieldError {
    pub pointer: String,
    pub code: String,
    pub detail: String,
}

/// Consistency vector component (contract §4), with the domain as its wire name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Comp {
    pub cluster: Uuid,
    pub domain: String,
    pub partition: u32,
    pub position: u64,
}

/// A request as seen by the idempotency layer (contract §5.3).
#[derive(Debug, Clone)]
pub struct IdemRequest {
    pub method: String,
    pub route_template: String,
    pub path_params: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdemResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Result of `Outbox::append` as observed by QA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    pub partition: i32,
    pub sequence: i64,
    pub event_id: Uuid,
}

/// Fault injected into the QA test saga (contract §5.4: crash injection after every step).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    /// The step's local transaction commits, then the executor process "crashes"
    /// (the executor task is aborted before it can record or continue).
    CrashAfterStep(usize),
    /// The step's local transaction commits but its acknowledgement is lost; the
    /// executor sees an unknown outcome and redelivers the same step.
    LoseAckAfterStep(usize),
    /// The step fails permanently (non-retryable) every time it runs.
    FailPermanentlyAt(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveOutcome {
    Completed,
    Compensated,
    Blocked,
    Crashed,
    Error(String),
}

/// A row of the frozen `sagas` table (contract §5.4), read with plain SQL.
#[derive(Debug, Clone)]
pub struct SagaRow {
    pub operation_id: Uuid,
    pub state: String,
    pub version: i64,
    pub pivot: String,
    pub result: Option<Vec<u8>>,
}
