//! Expected values transcribed by QA directly from the specification and the frozen M0
//! contract. Never derive these from the implementation.

/// Appendix D.2: (code, HTTP status, retryable). Exactly 19 codes.
pub const D2: &[(&str, u16, bool)] = &[
    ("invalid_request", 400, false),
    ("unauthenticated", 401, false),
    ("permission_denied", 403, false),
    ("not_found", 404, false),
    ("method_not_allowed", 405, false),
    ("conflict", 409, false),
    ("resource_trashed", 409, false),
    ("precondition_failed", 412, false),
    ("payload_too_large", 413, false),
    ("unsupported_media_type", 415, false),
    ("idempotency_mismatch", 422, false),
    ("locked", 423, false),
    ("rate_limited", 429, true),
    ("quota_exceeded", 507, false),
    ("internal", 500, true),
    ("dependency_unavailable", 503, true),
    ("unavailable", 503, true),
    ("timeout", 504, true),
    ("outcome_unknown", 504, true),
];

/// Number of codes in D.2.
pub const D2_LEN: usize = 19;

pub fn d2(code: &str) -> Option<(u16, bool)> {
    D2.iter()
        .find(|(c, _, _)| *c == code)
        .map(|(_, s, r)| (*s, *r))
}

/// Statuses an application code may map to: exactly the statuses used in D.2 (D.3).
pub fn d2_statuses() -> Vec<u16> {
    let mut v: Vec<u16> = D2.iter().map(|(_, s, _)| *s).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Problem-details fields that must always be present (D.1, contract §2).
pub const PROBLEM_REQUIRED_FIELDS: &[&str] = &[
    "type",
    "title",
    "status",
    "code",
    "detail",
    "instance",
    "request_id",
    "retryable",
];

/// Contract §3: closed context registry.
pub const SIG_CONTEXTS: &[&str] = &[
    "consistency-context/v1",
    "snapshot-handle/v1",
    "decision-ticket/v1",
    "revocation-record/v1",
    "watermark-heartbeat/v1",
    "storage-receipt/v1",
    "data-plane-token/v1",
    "state-attestation/v1",
    "test/v1",
];
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;

/// §18.1 / contract §4–§5: the eleven core domains.
pub const DOMAINS: &[&str] = &[
    "identity",
    "resources",
    "authz",
    "objects",
    "cluster",
    "operations",
    "collab",
    "events",
    "accounting",
    "plugins",
    "audit",
];

/// §2.2 / contract §6 roles. See OQ-18 for `edge`.
pub const ROLES: &[&str] = &[
    "edge", "api", "realtime", "worker", "search", "storage", "control",
];
/// Roles whose milestone is M1 or later per IMPLEMENTATION_PLAN.md; the M0 binary must refuse them.
pub const ROLES_NOT_IN_M0: &[&str] = &["realtime", "worker", "search", "storage", "control"];

/// Contract §4.
pub const MAX_VECTOR_COMPONENTS: usize = 64;

/// §6.6: S default 2 s, maximum 30 s.
pub const S_DEFAULT_SECS: f64 = 2.0;
pub const S_MAX_SECS: f64 = 30.0;

/// Contract §5.3.
pub const IDEMPOTENCY_KEY_MAX_LEN: usize = 255;
pub const IDEMPOTENCY_RETENTION_HOURS: i64 = 24;
/// App. E / contract §5.2–5.3.
pub const MAX_ROW_PAYLOAD: usize = 64 * 1024;

/// Substrings that indicate internal details leaked into a client-visible error.
/// (D.1: detail never contains data the caller may not see; contract §2.)
pub const LEAK_MARKERS: &[&str] = &[
    "panicked",
    "backtrace",
    "stack backtrace",
    "src/",
    ".rs:",
    "sqlx",
    "SQLSTATE",
    "postgres://",
    "postgresql://",
    "yugabyte@",
    "password",
    "ERROR:",
    "tokio",
    "hyper::",
    "axum::",
    "serde_json::",
    "called `Result::unwrap()`",
    "Connection refused",
    "os error",
    "127.0.0.1:",
    "localhost:",
];

pub fn leak_in(text: &str) -> Option<&'static str> {
    LEAK_MARKERS.iter().copied().find(|m| text.contains(m))
}
