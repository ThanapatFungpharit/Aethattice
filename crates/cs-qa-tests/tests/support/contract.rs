//! REAL adapter: the only place in the QA suite that names engineer-owned APIs.
//!
//! Written against docs/contracts/M0-foundations.md before the implementation was visible.
//! Names the contract fixes are used as-is: `cs_common::id::*`, `Urn::parse`, `ErrorCode`,
//! `cs_crypto::sig::{Context, KeyResolver}`, `ConsistencyVector`, `VectorComponent`,
//! `dominates`, `DomainId`, `DomainPool`, `DomainPool::transaction`, `DomainTx`,
//! `Outbox::append(&mut DomainTx, ..)`, `SagaDefinition`, `reconcile`, `Kms`.
//! Everything the contract leaves open (method names, argument order, module paths) is
//! marked `BIND:`. On merge, fix ONLY the `BIND:` sites here; never change test
//! expectations to match the implementation. Signatures of the `pub` items below must stay
//! identical to `contract_stub.rs`.

use super::types::*;
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

// BIND: module paths.
use cs_common::Urn;
use cs_common::consistency::{ConsistencyVector, DomainId, VectorComponent};
use cs_common::error::{ErrorCode, Problem};
use cs_common::id;
use cs_crypto::sig::{self, Context, KeyResolver};
use cs_db::{DomainPool, DomainTx, Outbox};
use cs_ops::saga::{SagaDefinition, SagaExecutor, StepContext, StepOutcome};

fn ev(e: &ErrorCode) -> ErrorView {
    ErrorView {
        code: e.as_str().to_string(),
        status: e.http_status(),
        retryable: e.retryable(),
    }
}

// ======================================================================= binary and config
pub const DEPLOYMENT_DOMAIN: &str = "qa.example";
/// OQ-7. BIND: set to an M0 route that accepts a JSON body if the Team Leader names one.
pub const JSON_POST_ROUTE: Option<&str> = None;

/// OQ-20. BIND: how `cs` receives its config file.
pub fn server_args(config: &Path) -> Vec<String> {
    vec!["--config".into(), config.display().to_string()]
}

/// Minimal valid config (contract §6). BIND: key names inside sections.
pub fn config_toml(
    listen_port: u16,
    roles: &[&str],
    domain_url: &dyn Fn(&str) -> String,
    state_dir: &Path,
) -> String {
    let roles = roles
        .iter()
        .map(|r| format!("\"{r}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut s = format!(
        "[node]\nid = \"{}\"\nroles = [{roles}]\n\n\
         [api]\nlisten = \"127.0.0.1:{listen_port}\"\ndeployment_domain = \"{DEPLOYMENT_DOMAIN}\"\n\n\
         [telemetry]\nlog_format = \"json\"\nmetrics_listen = \"127.0.0.1:{}\"\n\n\
         [kms]\nkind = \"local\"\nroot_key_path = \"{}\"\n\n[policy]\n\n[locks]\n\n",
        Uuid::now_v7(),
        super::server::free_port(),
        state_dir.join("root.key").display()
    );
    for d in super::spec::DOMAINS {
        s.push_str(&format!(
            "[domains.{d}]\nurl = \"{}\"\npool_size = 4\nconnect_timeout_ms = 2000\n\n",
            domain_url(d)
        ));
    }
    s
}

/// BIND: policy key for S (§6.6) and its unit.
pub fn config_set_revocation_s(toml: &str, secs: f64) -> String {
    toml.replacen(
        "[policy]\n",
        &format!(
            "[policy]\nrevocation_staleness_ms = {}\n",
            (secs * 1000.0) as i64
        ),
        1,
    )
}

pub fn config_validate(toml: &str) -> Result<(), String> {
    cs_common::config::Config::from_toml_str(toml)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub fn config_effective_revocation_s(toml: &str) -> Result<f64, String> {
    let c = cs_common::config::Config::from_toml_str(toml).map_err(|e| e.to_string())?;
    Ok(c.policy.revocation_staleness.as_secs_f64())
}

/// BIND: where /readyz lists failing barriers (contract §7 leaves the field open).
/// Assumed: problem `errors[]` with one entry per failing barrier, `pointer` naming it.
pub fn readyz_failing_barriers(body: &serde_json::Value) -> Vec<String> {
    body["errors"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| {
                    format!(
                        "{} {}",
                        e["pointer"].as_str().unwrap_or(""),
                        e["detail"].as_str().unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

// ======================================================================= error model
pub fn error_codes() -> Vec<String> {
    ErrorCode::ALL
        .iter()
        .map(|c| c.as_str().to_string())
        .collect()
}

pub fn error_code_meta(code: &str) -> Option<(u16, bool)> {
    code.parse::<ErrorCode>()
        .ok()
        .map(|c| (c.http_status(), c.retryable()))
}

pub fn app_error_code(app_id: &str, code: &str, status: u16) -> Result<ErrorView, String> {
    let c = ErrorCode::app(app_id, code, status).map_err(|e| e.to_string())?;
    Ok(ev(&c))
}

pub fn render_problem(
    code: &str,
    instance: &str,
    internal_cause: Option<&str>,
    retry_after_ms: Option<u64>,
    field_errors: &[FieldError],
) -> Rendered {
    let code: ErrorCode = code
        .parse()
        .unwrap_or_else(|_| panic!("unknown code {code}"));
    let mut p = Problem::new(code, DEPLOYMENT_DOMAIN).instance(instance);
    if let Some(cause) = internal_cause {
        p = p.with_internal_cause(cause);
    }
    if let Some(ms) = retry_after_ms {
        p = p.retry_after_ms(ms);
    }
    for f in field_errors {
        p = p.field_error(&f.pointer, &f.code, &f.detail);
    }
    let resp = cs_api::problem_response(p);
    Rendered {
        status: resp.status().as_u16(),
        headers: resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        body: futures::executor::block_on(cs_api::body_bytes(resp)),
    }
}

// ======================================================================= identifiers
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

pub fn new_id_text(kind: &str) -> String {
    match kind {
        "tenant" => id::TenantId::new().to_string(),
        "principal" => id::PrincipalId::new().to_string(),
        "user" => id::UserId::new().to_string(),
        "group" => id::GroupId::new().to_string(),
        "resource" => id::ResourceId::new().to_string(),
        "space" => id::SpaceId::new().to_string(),
        "version" => id::VersionId::new().to_string(),
        "session" => id::SessionId::new().to_string(),
        "seal" => id::SealId::new().to_string(),
        "node" => id::NodeId::new().to_string(),
        "operation" => id::OperationId::new().to_string(),
        "event" => id::EventId::new().to_string(),
        "request" => id::RequestId::new().to_string(),
        "chunk" => id::ChunkId::new().to_string(),
        "extent" => id::ExtentId::new().to_string(),
        other => panic!("unknown id kind {other}"),
    }
}

pub fn urn_parse_display(s: &str) -> Result<String, String> {
    Urn::parse(s)
        .map(|u| u.to_string())
        .map_err(|e| e.to_string())
}

// ======================================================================= consistency vectors
#[derive(Debug, Clone)]
pub struct Cv(ConsistencyVector);

fn domain_from(name: &str) -> DomainId {
    name.parse().unwrap_or_else(|_| panic!("domain {name}"))
}

pub fn cv_new(c: Vec<Comp>) -> Result<Cv, String> {
    let comps = c
        .into_iter()
        .map(|c| VectorComponent {
            cluster_id: c.cluster,
            domain_id: domain_from(&c.domain),
            partition: c.partition,
            position: c.position,
        })
        .collect::<Vec<_>>();
    ConsistencyVector::new(comps)
        .map(Cv)
        .map_err(|e| e.to_string())
}

pub fn cv_components(v: &Cv) -> Vec<Comp> {
    v.0.components()
        .iter()
        .map(|c| Comp {
            cluster: c.cluster_id,
            domain: c.domain_id.to_string(),
            partition: c.partition,
            position: c.position,
        })
        .collect()
}

pub fn cv_dominates(a: &Cv, b: &Cv) -> bool {
    a.0.dominates(&b.0)
}

pub fn cv_encode(v: &Cv) -> Vec<u8> {
    v.0.to_cbor()
}

pub fn cv_decode(b: &[u8]) -> Result<Cv, String> {
    ConsistencyVector::from_cbor(b)
        .map(Cv)
        .map_err(|e| e.to_string())
}

pub fn domain_wire_names() -> Vec<String> {
    DomainId::CORE.iter().map(|d| d.to_string()).collect()
}

pub fn app_domain_name(application_id: &str) -> String {
    DomainId::App(application_id.to_string()).to_string()
}

// ======================================================================= signing envelope
struct StaticResolver(Vec<(String, [u8; 32])>);

impl KeyResolver for StaticResolver {
    fn resolve(&self, key_id: &str) -> Option<sig::VerifyingKey> {
        self.0
            .iter()
            .find(|(k, _)| k == key_id)
            .and_then(|(_, pk)| sig::VerifyingKey::from_bytes(pk).ok())
    }
}

fn ctx(name: &str) -> Context {
    name.parse()
        .unwrap_or_else(|_| panic!("expected context {name} must be in the registry"))
}

pub fn sig_contexts() -> Vec<String> {
    Context::ALL
        .iter()
        .map(|c| c.as_str().to_string())
        .collect()
}

pub fn sig_context_known(s: &str) -> bool {
    s.parse::<Context>().is_ok()
}

pub fn sig_verify(
    envelope: &[u8],
    expected_context: &str,
    keys: &[(String, [u8; 32])],
) -> Result<Vec<u8>, String> {
    sig::verify(
        envelope,
        ctx(expected_context),
        &StaticResolver(keys.to_vec()),
    )
    .map_err(|e| e.to_string())
}

pub fn sig_verify_text(
    text: &str,
    expected_context: &str,
    keys: &[(String, [u8; 32])],
) -> Result<Vec<u8>, String> {
    sig::verify_text(text, ctx(expected_context), &StaticResolver(keys.to_vec()))
        .map_err(|e| e.to_string())
}

/// BIND: QA needs to sign with a known seed to compare bytes with the independent vectors
/// (Ed25519 is deterministic). A test-only constructor is acceptable.
pub fn sig_sign_with_seed(
    seed: &[u8; 32],
    key_id: &str,
    context: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let key = sig::SigningKey::from_seed(*seed);
    sig::sign(&key, key_id, ctx(context), payload).map_err(|e| e.to_string())
}

pub fn sig_encode_text(envelope: &[u8]) -> String {
    sig::encode_text(envelope)
}

// ======================================================================= database layer
#[derive(Debug)]
pub struct Domain {
    pool: DomainPool,
    name: String,
}

pub async fn domain_open(domain: &str, url: &str) -> Result<Domain, String> {
    let cfg = cs_db::DomainConfig {
        url: url.to_string(),
        pool_size: 16,
        ..Default::default()
    };
    let pool = DomainPool::connect(domain_from(domain), cfg)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Domain {
        pool,
        name: domain.to_string(),
    })
}

/// Apply the domain's embedded core migrations (creates outbox, outbox_counters,
/// idempotency_records, sagas … as frozen in contract §5).
pub async fn domain_migrate(d: &Domain) -> Result<(), String> {
    cs_db::migrate::run_embedded(&d.pool)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Runs a re-runnable closure through the 40001/40P01 retry wrapper. The closure body is QA
/// code: the first `fail_first` attempts raise `sqlstate`, later attempts succeed.
pub async fn retry_probe(
    d: &Domain,
    sqlstate: &str,
    fail_first: u32,
) -> (u32, Result<(), ErrorView>) {
    let attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let a = attempts.clone();
    let state = sqlstate.to_string();
    let res = d
        .pool
        .transaction(move |tx: &mut DomainTx| {
            let a = a.clone();
            let state = state.clone();
            Box::pin(async move {
                let n = a.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if n <= fail_first {
                    let sql = format!("DO $$ BEGIN RAISE EXCEPTION 'qa injected' USING ERRCODE = '{state}'; END $$");
                    tx.execute_raw(&sql).await?;
                }
                tx.execute_raw("SELECT 1").await?;
                Ok(())
            })
        })
        .await;
    (
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        res.map_err(|e| ev(&e.code())),
    )
}

// ======================================================================= outbox
pub async fn outbox_append(
    d: &Domain,
    tenant: Uuid,
    partition_key: Uuid,
    event_type: &str,
    payload: Vec<u8>,
    commit: bool,
) -> Result<Option<Appended>, ErrorView> {
    let event_type = event_type.to_string();
    let r = d
        .pool
        .transaction_once(
            move |tx: &mut DomainTx| {
                Box::pin(async move {
                    let rec =
                        Outbox::append(tx, tenant.into(), partition_key, &event_type, 1, &payload)
                            .await?;
                    Ok(Appended {
                        partition: rec.partition,
                        sequence: rec.sequence,
                        event_id: rec.event_id.into(),
                    })
                })
            },
            commit,
        )
        .await;
    match r {
        Ok(a) if commit => Ok(Some(a)),
        Ok(_) => Ok(None),
        Err(e) => Err(ev(&e.code())),
    }
}

/// Reads in order; must return an error on any sequence gap (contract §5.2).
pub async fn outbox_read(
    d: &Domain,
    partition: i32,
    after_sequence: i64,
    limit: usize,
) -> Result<Vec<(i64, Uuid)>, String> {
    Outbox::read(&d.pool, partition, after_sequence, limit)
        .await
        .map(|v| {
            v.into_iter()
                .map(|r| (r.sequence, r.event_id.into()))
                .collect()
        })
        .map_err(|e| e.to_string())
}

// ======================================================================= idempotency
fn idem_req(r: &IdemRequest) -> cs_db::idempotency::RequestFingerprint<'_> {
    cs_db::idempotency::RequestFingerprint {
        method: &r.method,
        route_template: &r.route_template,
        path_params: r
            .path_params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect(),
        body: &r.body,
    }
}

pub fn idem_digest(r: &IdemRequest) -> Vec<u8> {
    idem_req(r).digest().to_vec()
}

/// One idempotent single-domain write. The effect (QA code) inserts a row into the QA fixture
/// table `qa_effects` in the same DomainTx and returns 201 with a body containing a fresh
/// effect id, so a re-execution is distinguishable from a replay. `fail_effect` makes the
/// effect fail after inserting (non-retryable), which must roll everything back.
/// Tags starting with "big:" produce a > 64 KiB response body (OQ-19).
pub async fn idem_execute(
    d: &Domain,
    tenant: Uuid,
    principal: Uuid,
    key: &str,
    r: &IdemRequest,
    effect_tag: &str,
    fail_effect: bool,
) -> Result<IdemResponse, ErrorView> {
    let tag = effect_tag.to_string();
    let out = cs_db::idempotency::execute(
        &d.pool,
        tenant.into(),
        principal.into(),
        key,
        idem_req(r),
        move |tx: &mut DomainTx| {
            let tag = tag.clone();
            Box::pin(async move {
                let effect_id = Uuid::new_v4();
                tx.execute_raw_params(
                    "INSERT INTO qa_effects (tenant_id, effect_id, tag) VALUES ($1, $2, $3)",
                    &[&tenant, &effect_id, &tag],
                )
                .await?;
                if fail_effect {
                    return Err(cs_db::Error::from(ErrorCode::InvalidRequest));
                }
                let mut body = serde_json::json!({ "effect_id": effect_id, "tag": tag });
                if tag.starts_with("big:") {
                    body["pad"] = serde_json::Value::String("x".repeat(100 * 1024));
                }
                Ok(cs_db::idempotency::StoredResponse {
                    status: 201,
                    body: serde_json::to_vec(&body).unwrap_or_default(),
                })
            })
        },
    )
    .await;
    out.map(|s| IdemResponse {
        status: s.status,
        body: s.body,
    })
    .map_err(|e| ev(&e.code()))
}

// ======================================================================= migrations
/// BIND: exact header syntax of the `requires_finalized` comment (contract §5.1).
pub fn requires_finalized_header(expand_version: i32) -> String {
    format!("-- requires_finalized: {expand_version:04}\n")
}

pub async fn migrate_dir(url: &str, domain: &str, dir: &Path) -> Result<Vec<i32>, String> {
    let d = domain_open(domain, url).await?;
    cs_db::migrate::run_dir(&d.pool, dir)
        .await
        .map_err(|e| e.to_string())
}

pub async fn finalize_current_release(url: &str, domain: &str) -> Result<(), String> {
    let d = domain_open(domain, url).await?;
    cs_db::migrate::finalize_release(&d.pool)
        .await
        .map_err(|e| e.to_string())
}

// ======================================================================= sagas
pub const QA_SAGA_STEPS: usize = 4;
pub const QA_SAGA_PIVOT: usize = 2;

/// QA test saga "qa.transfer" (two test domains A and B, operations domain for the record):
///  step 0 (A): hold          INSERT qa_holds(op, held)                 compensation: held -> voided
///  step 1 (B): prepare       INSERT qa_credits(op, pending)            compensation: pending -> voided
///  step 2 (A): PIVOT commit  CAS qa_holds held -> committed
///  step 3 (B): apply         CAS qa_credits pending -> applied; qa_balance += amount
/// Every step also increments qa_step_commits(op, step) in the same local transaction, so QA
/// can count how many times a step's transaction actually committed.
#[derive(Debug)]
pub struct SagaEnv {
    ops: DomainPool,
    a: DomainPool,
    b: DomainPool,
    def: Arc<QaTransfer>,
}

#[derive(Debug, Default)]
struct QaTransfer {
    fault: Mutex<std::collections::HashMap<Uuid, Fault>>,
    comp_log: Mutex<std::collections::HashMap<Uuid, Vec<usize>>>,
    crash_gate: tokio::sync::Notify,
}

const QA_TABLES_A: &str = "
CREATE TABLE IF NOT EXISTS qa_holds (op uuid PRIMARY KEY, tenant_id uuid NOT NULL, amount bigint NOT NULL,
  state text NOT NULL CHECK (state IN ('held','committed','voided')));
CREATE TABLE IF NOT EXISTS qa_step_commits (op uuid, step int, commits int NOT NULL, PRIMARY KEY (op, step));";
const QA_TABLES_B: &str = "
CREATE TABLE IF NOT EXISTS qa_credits (op uuid PRIMARY KEY, tenant_id uuid NOT NULL, amount bigint NOT NULL,
  state text NOT NULL CHECK (state IN ('pending','applied','voided')));
CREATE TABLE IF NOT EXISTS qa_balance (tenant_id uuid PRIMARY KEY, balance bigint NOT NULL, applications bigint NOT NULL);
CREATE TABLE IF NOT EXISTS qa_step_commits (op uuid, step int, commits int NOT NULL, PRIMARY KEY (op, step));";

impl SagaDefinition for QaTransfer {
    const SAGA_TYPE: &'static str = "qa.transfer";
    const PROTOCOL_VERSION: i32 = 1;
    type Input = (Uuid, i64); // (tenant, amount)

    fn steps(&self) -> Vec<cs_ops::saga::StepSpec> {
        use cs_ops::saga::StepSpec;
        vec![
            StepSpec::new("hold", DomainId::Custom("qa_a".into())),
            StepSpec::new("prepare_credit", DomainId::Custom("qa_b".into())),
            StepSpec::pivot("commit_hold", DomainId::Custom("qa_a".into())),
            StepSpec::new("apply_credit", DomainId::Custom("qa_b".into())),
        ]
    }

    fn run_step<'a>(
        &'a self,
        cx: StepContext<'a, Self::Input>,
        tx: &'a mut DomainTx,
    ) -> cs_ops::saga::StepFuture<'a> {
        Box::pin(async move {
            let op: Uuid = cx.operation_id.into();
            let (tenant, amount) = *cx.input;
            let step = cx.step_index;
            if self
                .fault
                .lock()
                .map(|f| f.get(&op) == Some(&Fault::FailPermanentlyAt(step)))
                .unwrap_or(false)
            {
                return Ok(StepOutcome::PermanentFailure(
                    "qa injected permanent failure".into(),
                ));
            }
            let sql = match step {
                0 => "INSERT INTO qa_holds (op, tenant_id, amount, state) VALUES ($1, $2, $3, 'held')",
                1 => "INSERT INTO qa_credits (op, tenant_id, amount, state) VALUES ($1, $2, $3, 'pending')",
                2 => "UPDATE qa_holds SET state = 'committed' WHERE op = $1 AND tenant_id = $2 AND amount = $3 AND state = 'held'",
                3 => "WITH u AS (UPDATE qa_credits SET state = 'applied' WHERE op = $1 AND state = 'pending' RETURNING tenant_id, amount)
                      INSERT INTO qa_balance (tenant_id, balance, applications) SELECT $2, $3, 1 FROM u
                      ON CONFLICT (tenant_id) DO UPDATE SET balance = qa_balance.balance + EXCLUDED.balance,
                                                            applications = qa_balance.applications + 1",
                _ => unreachable!(),
            };
            let n = tx.execute_raw_params(sql, &[&op, &tenant, &amount]).await?;
            if step == 2 && n != 1 {
                return Ok(StepOutcome::PermanentFailure(
                    "pivot condition failed".into(),
                ));
            }
            tx.execute_raw_params(
                "INSERT INTO qa_step_commits (op, step, commits) VALUES ($1, $2, 1)
                 ON CONFLICT (op, step) DO UPDATE SET commits = qa_step_commits.commits + 1",
                &[&op, &(step as i32)],
            )
            .await?;
            Ok(StepOutcome::Done(format!("step{step}:{op}").into_bytes()))
        })
    }

    fn compensate<'a>(
        &'a self,
        cx: StepContext<'a, Self::Input>,
        tx: &'a mut DomainTx,
    ) -> cs_ops::saga::StepFuture<'a> {
        Box::pin(async move {
            let op: Uuid = cx.operation_id.into();
            let sql = match cx.step_index {
                0 => "UPDATE qa_holds SET state = 'voided' WHERE op = $1 AND state = 'held'",
                1 => "UPDATE qa_credits SET state = 'voided' WHERE op = $1 AND state = 'pending'",
                s => panic!("QA saga: compensation requested for post-pivot step {s}"),
            };
            tx.execute_raw_params(sql, &[&op]).await?;
            if let Ok(mut log) = self.comp_log.lock() {
                log.entry(op).or_default().push(cx.step_index);
            }
            Ok(StepOutcome::Done(Vec::new()))
        })
    }

    fn reconcile<'a>(
        &'a self,
        cx: cs_ops::saga::ReconcileContext<'a, Self::Input>,
    ) -> cs_ops::saga::ReconcileFuture<'a> {
        // Level-triggered predicate from authoritative state only: the pivot committed iff the
        // hold is 'committed' in domain A.
        Box::pin(async move {
            let op: Uuid = cx.operation_id.into();
            let state: Option<String> = cx
                .read_scalar(
                    DomainId::Custom("qa_a".into()),
                    "SELECT state FROM qa_holds WHERE op = $1",
                    &[&op],
                )
                .await?;
            Ok(match state.as_deref() {
                Some("committed") => cs_ops::saga::Authoritative::PivotCommitted,
                Some("voided") => cs_ops::saga::Authoritative::PivotAbsentFinal,
                _ => cs_ops::saga::Authoritative::PivotNotCommitted,
            })
        })
    }

    fn after_step_hook(&self, op: Uuid, step: usize) -> cs_ops::saga::HookAction {
        match self.fault.lock().ok().and_then(|f| f.get(&op).copied()) {
            Some(Fault::CrashAfterStep(s)) if s == step => cs_ops::saga::HookAction::Crash,
            Some(Fault::LoseAckAfterStep(s)) if s == step => cs_ops::saga::HookAction::LoseAck,
            _ => cs_ops::saga::HookAction::Continue,
        }
    }
}

pub async fn saga_env(ops_url: &str, a_url: &str, b_url: &str) -> Result<SagaEnv, String> {
    let ops = domain_open("operations", ops_url).await?;
    domain_migrate(&ops).await?;
    let a = DomainPool::connect(
        DomainId::Custom("qa_a".into()),
        cs_db::DomainConfig {
            url: a_url.into(),
            pool_size: 8,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let b = DomainPool::connect(
        DomainId::Custom("qa_b".into()),
        cs_db::DomainConfig {
            url: b_url.into(),
            pool_size: 8,
            ..Default::default()
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    a.execute_fixture_sql(QA_TABLES_A)
        .await
        .map_err(|e| e.to_string())?;
    b.execute_fixture_sql(QA_TABLES_B)
        .await
        .map_err(|e| e.to_string())?;
    Ok(SagaEnv {
        ops: ops.pool,
        a,
        b,
        def: Arc::new(QaTransfer::default()),
    })
}

impl SagaEnv {
    fn executor(&self) -> SagaExecutor<QaTransfer> {
        SagaExecutor::new(
            self.def.clone(),
            self.ops.clone(),
            vec![self.a.clone(), self.b.clone()],
        )
    }

    pub async fn start(&self, tenant: Uuid, key: &str, amount: i64) -> Result<Uuid, ErrorView> {
        self.executor()
            .start(tenant.into(), Uuid::nil().into(), key, (tenant, amount))
            .await
            .map(Into::into)
            .map_err(|e| ev(&e.code()))
    }

    /// Runs the executor in its own task. On `CrashAfterStep` the framework's crash hook fires
    /// and the task is aborted, which simulates a process crash.
    pub async fn drive(&self, op: Uuid, fault: Fault) -> DriveOutcome {
        if let Ok(mut f) = self.def.fault.lock() {
            f.insert(op, fault);
        }
        let exec = self.executor();
        let handle = tokio::spawn(async move { exec.drive(op.into()).await });
        let out = match handle.await {
            Ok(Ok(cs_ops::saga::Terminal::Completed)) => DriveOutcome::Completed,
            Ok(Ok(cs_ops::saga::Terminal::Compensated)) => DriveOutcome::Compensated,
            Ok(Ok(cs_ops::saga::Terminal::BlockedForOperator)) => DriveOutcome::Blocked,
            Ok(Err(e)) if e.is_injected_crash() => DriveOutcome::Crashed,
            Ok(Err(e)) => DriveOutcome::Error(e.to_string()),
            Err(join) if join.is_cancelled() || join.is_panic() => DriveOutcome::Crashed,
            Err(join) => DriveOutcome::Error(join.to_string()),
        };
        if let Ok(mut f) = self.def.fault.lock() {
            // A crash fault fires once; afterwards the "restarted process" runs normally.
            if matches!(fault, Fault::CrashAfterStep(_) | Fault::LoseAckAfterStep(_)) {
                f.remove(&op);
            }
        }
        out
    }

    pub async fn reconcile(&self, rounds: usize) -> Result<(), String> {
        for _ in 0..rounds {
            self.executor()
                .reconcile_all()
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub async fn redeliver_step(&self, op: Uuid, step: usize) -> Result<Vec<u8>, String> {
        self.executor()
            .deliver_step(op.into(), step)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn step_result(&self, op: Uuid, step: usize) -> Option<Vec<u8>> {
        self.executor()
            .recorded_step_result(op.into(), step)
            .await
            .ok()
            .flatten()
    }

    pub async fn try_transition(
        &self,
        op: Uuid,
        expected_version: i64,
        to_state: &str,
    ) -> Result<(), ErrorView> {
        let to = to_state
            .parse::<cs_ops::saga::SagaState>()
            .map_err(|_| ErrorView {
                code: "invalid_request".into(),
                status: 400,
                retryable: false,
            })?;
        cs_ops::saga::transition(&self.ops, op.into(), expected_version, to)
            .await
            .map_err(|e| ev(&e.code()))
    }

    pub fn compensation_log(&self, op: Uuid) -> Vec<usize> {
        self.def
            .comp_log
            .lock()
            .map(|l| l.get(&op).cloned().unwrap_or_default())
            .unwrap_or_default()
    }
}
