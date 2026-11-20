//! STUB adapter for `--features qa-selfcheck`. Same public signatures as `contract.rs`; every
//! body that needs the implementation panics. Keep the two files' signatures identical.

use super::types::*;
use std::path::Path;
use uuid::Uuid;

fn stub<T>() -> T {
    panic!("QA stub: build with --features m0-contract after the M0 crates are merged")
}

// ---------------------------------------------------------------- binary and configuration
pub const DEPLOYMENT_DOMAIN: &str = "qa.example";
/// OQ-7: an M0 route that accepts a JSON body, if any.
pub const JSON_POST_ROUTE: Option<&str> = None;

pub fn server_args(config: &Path) -> Vec<String> {
    vec![
        "serve".into(),
        "--config".into(),
        config.display().to_string(),
    ]
}
pub fn server_prepare_args(_config: &Path) -> Vec<Vec<String>> {
    stub()
}
pub fn config_toml(
    _listen_port: u16,
    _roles: &[&str],
    _domain_url: &dyn Fn(&str) -> String,
    _state_dir: &Path,
) -> String {
    stub()
}
pub fn config_set_revocation_s(_toml: &str, _secs: f64) -> String {
    stub()
}
pub fn config_validate(_toml: &str) -> Result<(), String> {
    stub()
}
pub fn config_effective_revocation_s(_toml: &str) -> Result<f64, String> {
    stub()
}
pub fn readyz_failing_barriers(_body: &serde_json::Value) -> Vec<String> {
    stub()
}

// ---------------------------------------------------------------- error model
pub fn error_codes() -> Vec<String> {
    stub()
}
pub fn error_code_meta(_code: &str) -> Option<(u16, bool)> {
    stub()
}
pub fn app_error_code(_app_id: &str, _code: &str, _status: u16) -> Result<ErrorView, String> {
    stub()
}
pub fn render_problem(
    _code: &str,
    _instance: &str,
    _internal_cause: Option<&str>,
    _retry_after_ms: Option<u64>,
    _field_errors: &[FieldError],
) -> Rendered {
    stub()
}

// ---------------------------------------------------------------- identifiers
pub const ID_KINDS_V7: &[&str] = &[
    "tenant",
    "principal",
    "user",
    "group",
    "resource",
    "space",
    "version",
    "session",
    "seal",
    "node",
    "operation",
    "event",
    "request",
];
pub const ID_KINDS_RANDOM: &[&str] = &["chunk", "extent"];
pub fn new_id_text(_kind: &str) -> String {
    stub()
}
pub fn urn_parse_display(_s: &str) -> Result<String, String> {
    stub()
}

// ---------------------------------------------------------------- consistency vectors
#[derive(Debug, Clone)]
pub struct Cv(());
pub fn cv_new(_c: Vec<Comp>) -> Result<Cv, String> {
    stub()
}
pub fn cv_components(_v: &Cv) -> Vec<Comp> {
    stub()
}
pub fn cv_dominates(_a: &Cv, _b: &Cv) -> bool {
    stub()
}
pub fn cv_encode(_v: &Cv) -> Vec<u8> {
    stub()
}
pub fn cv_decode(_b: &[u8]) -> Result<Cv, String> {
    stub()
}
pub fn domain_wire_names() -> Vec<String> {
    stub()
}
pub fn app_domain_name(_application_id: &str) -> String {
    stub()
}

// ---------------------------------------------------------------- signing envelope
pub fn sig_contexts() -> Vec<String> {
    stub()
}
pub fn sig_context_known(_s: &str) -> bool {
    stub()
}
pub fn sig_verify(
    _envelope: &[u8],
    _expected_context: &str,
    _keys: &[(String, [u8; 32])],
) -> Result<Vec<u8>, String> {
    stub()
}
pub fn sig_verify_text(
    _text: &str,
    _expected_context: &str,
    _keys: &[(String, [u8; 32])],
) -> Result<Vec<u8>, String> {
    stub()
}
pub fn sig_sign_with_seed(
    _seed: &[u8; 32],
    _key_id: &str,
    _context: &str,
    _payload: &[u8],
) -> Result<Vec<u8>, String> {
    stub()
}
pub fn sig_encode_text(_envelope: &[u8]) -> String {
    stub()
}

// ---------------------------------------------------------------- database layer
#[derive(Debug)]
pub struct Domain(());
pub async fn domain_open(_domain: &str, _url: &str) -> Result<Domain, String> {
    stub()
}
pub async fn domain_migrate(_d: &Domain) -> Result<(), String> {
    stub()
}
pub async fn retry_probe(
    _d: &Domain,
    _sqlstate: &str,
    _fail_first: u32,
) -> (u32, Result<(), ErrorView>) {
    stub()
}

// ---------------------------------------------------------------- outbox
pub async fn outbox_append(
    _d: &Domain,
    _tenant: Uuid,
    _partition_key: Uuid,
    _event_type: &str,
    _payload: Vec<u8>,
    _commit: bool,
) -> Result<Option<Appended>, ErrorView> {
    stub()
}
pub async fn outbox_read(
    _d: &Domain,
    _tenant: Uuid,
    _partition: i32,
    _after_sequence: i64,
    _limit: usize,
) -> Result<Vec<(i64, Uuid)>, String> {
    stub()
}

// ---------------------------------------------------------------- idempotency
pub fn idem_digest(_r: &IdemRequest) -> Vec<u8> {
    stub()
}
pub async fn idem_execute(
    _d: &Domain,
    _tenant: Uuid,
    _principal: Uuid,
    _key: &str,
    _r: &IdemRequest,
    _effect_tag: &str,
    _fail_effect: bool,
) -> Result<IdemResponse, ErrorView> {
    stub()
}

// ---------------------------------------------------------------- migrations
pub fn requires_finalized_header(_release: &str) -> String {
    stub()
}
pub async fn migrate_dir(_url: &str, _domain: &str, _dir: &Path) -> Result<Vec<i32>, String> {
    stub()
}
pub async fn finalize_release(_url: &str, _domain: &str, _release: &str) -> Result<(), String> {
    stub()
}

// ---------------------------------------------------------------- sagas
pub const QA_SAGA_STEPS: usize = 4;
pub const QA_SAGA_PIVOT: usize = 2;

#[derive(Debug)]
pub struct SagaEnv(());
pub async fn saga_env(_ops_url: &str, _a_url: &str, _b_url: &str) -> Result<SagaEnv, String> {
    stub()
}
impl SagaEnv {
    pub async fn start(&self, _tenant: Uuid, _key: &str, _amount: i64) -> Result<Uuid, ErrorView> {
        stub()
    }
    pub async fn drive(&self, _op: Uuid, _fault: Fault) -> DriveOutcome {
        stub()
    }
    pub async fn reconcile(&self, _rounds: usize) -> Result<(), String> {
        stub()
    }
    pub async fn redeliver_step(&self, _op: Uuid, _step: usize) -> Result<Vec<u8>, String> {
        stub()
    }
    pub async fn step_result(&self, _op: Uuid, _step: usize) -> Option<Vec<u8>> {
        stub()
    }
    pub async fn try_transition(
        &self,
        _op: Uuid,
        _expected_version: i64,
        _to_state: &str,
    ) -> Result<(), ErrorView> {
        stub()
    }
    pub fn compensation_log(&self, _op: Uuid) -> Vec<usize> {
        stub()
    }
}
