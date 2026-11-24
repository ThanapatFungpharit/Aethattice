//! REAL adapter: the only place in the QA suite that names engineer-owned APIs.
//!
//! Bound on 2026-11-20 to the merged M0 crates (contract rev 3, docs/design/M0-backend.md).
//! It translates between the QA test vocabulary (`super::types`) and the public API. It holds
//! no expectations: every assertion lives in the test files. Signatures of the `pub` items must
//! stay identical to `contract_stub.rs`.

use super::types::*;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

use cs_common::config::{Config, DomainConfig, PolicyKey, PoolConfig};
use cs_common::error::{AppErrorCode, Error as CsError, ErrorCode, FieldError as CsFieldError};
use cs_common::id::{self, OperationId, PrincipalId, RequestId, TenantId};
use cs_common::idempotency::IdempotencyKey;
use cs_common::urn::Urn;
use cs_common::vector::{ConsistencyVector, DomainId, VectorComponent};
use cs_common::{ApplicationId, Secret};
use cs_crypto::sig::{self, Context, KeyId, LocalSigner, StaticKeyResolver};
use cs_db::idempotency::{IdempotencyRecords, IdempotencyScope, RequestBody, StoredResponse};
use cs_db::migrate::{MigrationSet, Migrator, common_migrations};
use cs_db::outbox::{NewEvent, Outbox};
use cs_db::{DbError, DomainPool, DomainTx, RetryPolicy};
use cs_ops::saga::{
    CrashPoint, OpsError, ReconcileContext, ReconcileVerdict, Reconciler, SagaDefinition,
    SagaExecutor, SagaState, StartSaga, StepContext, StepDef, StepDone,
};
use futures::future::BoxFuture;

fn ev(e: CsError) -> ErrorView {
    ErrorView {
        code: e.code().to_string(),
        status: e.status(),
        retryable: e.retryable(),
    }
}
fn ev_db(e: DbError) -> ErrorView {
    ev(e.into())
}
fn ev_ops(e: OpsError) -> ErrorView {
    ev(e.into())
}

// ======================================================================= binary and config
pub const DEPLOYMENT_DOMAIN: &str = "qa.example";
/// Contract rev 2: no JSON-body routes in M0 (malformed-body test moved to M1).
pub const JSON_POST_ROUTE: Option<&str> = None;

pub fn server_args(config: &Path) -> Vec<String> {
    vec![
        "serve".into(),
        "--config".into(),
        config.display().to_string(),
    ]
}

/// Commands run (and required to succeed) before `serve`: `cs serve` requires an existing
/// local KMS root key (design doc, cs binary).
pub fn server_prepare_args(config: &Path) -> Vec<Vec<String>> {
    vec![vec![
        "init-kms".into(),
        "--config".into(),
        config.display().to_string(),
    ]]
}

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
    let node = id::NodeId::generate()
        .map(|n| n.to_string())
        .unwrap_or_default();
    let mut s = format!(
        "[node]\nid = \"{node}\"\nroles = [{roles}]\n\n\
         [api]\nlisten = \"127.0.0.1:{listen_port}\"\nadmin_listen = \"127.0.0.1:{}\"\ndeployment_domain = \"{DEPLOYMENT_DOMAIN}\"\n\n\
         [telemetry]\nlog_format = \"json\"\n\n\
         [kms]\nbackend = \"local_software\"\nroot_key_path = \"{}\"\n\n[policy]\n\n[locks]\n\n",
        super::server::free_port(),
        state_dir.join("root.key").display()
    );
    for d in super::spec::DOMAINS {
        s.push_str(&format!(
            "[domains.{d}]\nurl = \"{}\"\n\n[domains.{d}.pool]\nmax_connections = 4\nacquire_timeout_ms = 2000\n\n",
            domain_url(d)
        ));
    }
    s
}

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
    Config::from_toml_str(toml)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub fn config_effective_revocation_s(toml: &str) -> Result<f64, String> {
    let c = Config::from_toml_str(toml).map_err(|e| e.to_string())?;
    Ok(c.policy.get(PolicyKey::RevocationStalenessMs) as f64 / 1000.0)
}

/// Design doc: failing barriers are listed as `errors[].pointer = /barriers/<name>`.
pub fn readyz_failing_barriers(body: &serde_json::Value) -> Vec<String> {
    body["errors"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| e["pointer"].as_str().unwrap_or("").to_string())
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
        .map(|c| (c.status(), c.retryable()))
}

pub fn app_error_code(app_id: &str, code: &str, status: u16) -> Result<ErrorView, String> {
    let app = ApplicationId::parse(app_id).map_err(|e| e.to_string())?;
    let c = AppErrorCode::new(app, code, status).map_err(|e| e.to_string())?;
    Ok(ErrorView {
        code: c.to_string(),
        status: c.status(),
        retryable: c.retryable(),
    })
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
    let mut e = CsError::new(code);
    if let Some(cause) = internal_cause {
        e = e.with_cause(std::io::Error::other(cause.to_string()));
    }
    if let Some(ms) = retry_after_ms {
        e = e.with_retry_after_ms(ms);
    }
    for f in field_errors {
        e = e.with_field_error(CsFieldError {
            pointer: f.pointer.clone(),
            code: f.code.clone(),
            detail: f.detail.clone(),
        });
    }
    let rid = RequestId::generate().unwrap_or_else(|_| panic!("csprng"));
    let resp = cs_api::problem_response(&e, DEPLOYMENT_DOMAIN, instance, &rid);
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = futures::executor::block_on(axum::body::to_bytes(resp.into_body(), usize::MAX))
        .map(|b| b.to_vec())
        .unwrap_or_default();
    Rendered {
        status,
        headers,
        body,
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
    fn s<T: std::fmt::Display, E: std::fmt::Debug>(r: Result<T, E>) -> String {
        r.map(|v| v.to_string())
            .unwrap_or_else(|e| panic!("id generation failed: {e:?}"))
    }
    match kind {
        "tenant" => s(id::TenantId::generate()),
        "principal" => s(id::PrincipalId::generate()),
        "user" => s(id::UserId::generate()),
        "group" => s(id::GroupId::generate()),
        "resource" => s(id::ResourceId::generate()),
        "space" => s(id::SpaceId::generate()),
        "version" => s(id::VersionId::generate()),
        "session" => s(id::SessionId::generate()),
        "seal" => s(id::SealId::generate()),
        "node" => s(id::NodeId::generate()),
        "operation" => s(id::OperationId::generate()),
        "event" => s(id::EventId::generate()),
        "request" => s(id::RequestId::generate()),
        "chunk" => s(id::ChunkId::generate()),
        "extent" => s(id::ExtentId::generate()),
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
    ConsistencyVector::from_components(c.into_iter().map(|c| VectorComponent {
        cluster_id: c.cluster,
        domain_id: domain_from(&c.domain),
        partition: c.partition,
        position: c.position,
    }))
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
    cs_crypto::cbor::to_canonical(&v.0).unwrap_or_else(|e| panic!("encode vector: {e}"))
}

pub fn cv_decode(b: &[u8]) -> Result<Cv, String> {
    cs_crypto::cbor::from_canonical::<ConsistencyVector>(b, 64 * 1024)
        .map(Cv)
        .map_err(|e| e.to_string())
}

pub fn domain_wire_names() -> Vec<String> {
    DomainId::CORE.iter().map(|d| d.to_string()).collect()
}

pub fn app_domain_name(application_id: &str) -> String {
    DomainId::App(
        ApplicationId::parse(application_id).unwrap_or_else(|_| panic!("app id {application_id}")),
    )
    .to_string()
}

// ======================================================================= signing envelope
fn resolver(keys: &[(String, [u8; 32])]) -> StaticKeyResolver {
    let mut r = StaticKeyResolver::new();
    for (kid, pk) in keys {
        if let (Ok(k), Ok(vk)) = (
            kid.parse::<KeyId>(),
            cs_crypto::VerifyingKey::from_bytes(pk),
        ) {
            r.insert(k, vk, &Context::ALL);
        }
    }
    r
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
    sig::verify_bytes(
        envelope,
        ctx(expected_context),
        &resolver(keys),
        sig::DEFAULT_MAX_ENVELOPE_BYTES,
    )
    .map(|v| v.payload)
    .map_err(|e| e.to_string())
}

pub fn sig_verify_text(
    text: &str,
    expected_context: &str,
    keys: &[(String, [u8; 32])],
) -> Result<Vec<u8>, String> {
    let env = sig::from_text(text, sig::DEFAULT_MAX_ENVELOPE_BYTES).map_err(|e| e.to_string())?;
    sig_verify(&env, expected_context, keys)
}

pub fn sig_sign_with_seed(
    seed: &[u8; 32],
    key_id: &str,
    context: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let kid: KeyId = key_id.parse().map_err(|e: sig::SigError| e.to_string())?;
    let signer = LocalSigner::new(kid.clone(), cs_crypto::SigningKey::from_bytes(seed));
    sig::sign_payload_bytes(
        ctx(context),
        &kid,
        payload,
        &signer,
        sig::DEFAULT_MAX_ENVELOPE_BYTES,
    )
    .map_err(|e| e.to_string())
}

pub fn sig_encode_text(envelope: &[u8]) -> String {
    sig::to_text(envelope)
}

// ======================================================================= database layer
#[derive(Debug)]
pub struct Domain {
    pool: DomainPool,
}

fn pool_for(domain: DomainId, url: &str) -> Result<DomainPool, String> {
    let cfg = DomainConfig {
        url: Secret::new(url.to_string()),
        pool: PoolConfig {
            max_connections: 32,
            // YugabyteDB DROP DATABASE waits on a cluster-wide ProcSignalBarrier that idle
            // backends only absorb when they next run a query, so idle QA connections are
            // closed quickly; otherwise test-database drops stall (see M0 gate F-1).
            idle_timeout_ms: 1000,
            ..PoolConfig::default()
        },
    };
    DomainPool::connect_lazy(domain, &cfg, RetryPolicy::default()).map_err(|e| e.to_string())
}

fn migration_set(domain: &DomainId) -> Result<MigrationSet, String> {
    let common = common_migrations().map_err(|e| e.to_string())?;
    match domain {
        DomainId::Operations => common
            .merge(cs_ops::migrations().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string()),
        // M1: the identity domain gains its schema (M1 contract §1); mirrors `cs migrate`.
        DomainId::Identity => common
            .merge(cs_identity::migrations().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string()),
        _ => Ok(common),
    }
}

pub async fn domain_open(domain: &str, url: &str) -> Result<Domain, String> {
    Ok(Domain {
        pool: pool_for(domain_from(domain), url)?,
    })
}

/// Same migration set the `cs migrate` installer step applies to this domain.
pub async fn domain_migrate(d: &Domain) -> Result<(), String> {
    let set = migration_set(d.pool.domain())?;
    setup_migrate(&d.pool, &set).await
}

/// Fixture setup only (never used by the migration-runner tests themselves): the product
/// runner's 40001 budget (10 attempts / 5 s) can be exhausted by catalog contention from QA
/// tests running in parallel on one YugabyteDB cluster, so setup retries the whole idempotent
/// run a few times. An exhaustion seen here is reported in the gate notes, not hidden.
async fn setup_migrate(pool: &DomainPool, set: &MigrationSet) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..5u64 {
        match Migrator::run(pool, set).await {
            Ok(_) => return Ok(()),
            Err(DbError::RetryExhausted {
                attempts,
                last_sqlstate,
            }) => {
                last =
                    format!("retry budget exhausted after {attempts} attempts ({last_sqlstate})");
                eprintln!("QA setup: migration {last} (setup attempt {attempt})");
                tokio::time::sleep(Duration::from_millis(500 * (attempt + 1))).await;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Err(last)
}

pub async fn retry_probe(
    d: &Domain,
    sqlstate: &str,
    fail_first: u32,
) -> (u32, Result<(), ErrorView>) {
    let attempts = Arc::new(AtomicU32::new(0));
    let a = attempts.clone();
    let state = Arc::new(sqlstate.to_string());
    let res = d
        .pool
        .transaction(move |tx: &mut DomainTx| {
            let (a, state) = (a.clone(), state.clone());
            Box::pin(async move {
                let n = a.fetch_add(1, Ordering::SeqCst) + 1;
                if n <= fail_first {
                    let sql = format!("DO $$ BEGIN RAISE EXCEPTION 'qa injected' USING ERRCODE = '{state}'; END $$");
                    sqlx::raw_sql(sqlx::AssertSqlSafe(sql)).execute(tx.conn()).await?;
                }
                sqlx::query("SELECT 1").execute(tx.conn()).await?;
                Ok(())
            })
        })
        .await;
    (attempts.load(Ordering::SeqCst), res.map_err(ev_db))
}

// ======================================================================= outbox
#[derive(serde::Serialize)]
struct QaPayload {
    #[serde(with = "cs_crypto::cbor::bstr")]
    b: Vec<u8>,
}

/// Marker error used to roll a transaction back on purpose.
fn rollback_marker() -> DbError {
    DbError::app(CsError::new(ErrorCode::Conflict).with_detail("qa: deliberate rollback"))
}

pub async fn outbox_append(
    d: &Domain,
    tenant: Uuid,
    partition_key: Uuid,
    event_type: &str,
    payload: Vec<u8>,
    commit: bool,
) -> Result<Option<Appended>, ErrorView> {
    let tenant_id = TenantId::from_uuid(tenant).map_err(|_| ErrorView {
        code: "invalid_request".into(),
        status: 400,
        retryable: false,
    })?;
    let event_type = Arc::new(event_type.to_string());
    let payload = Arc::new(payload);
    let r = d
        .pool
        .transaction(move |tx: &mut DomainTx| {
            let (event_type, payload) = (event_type.clone(), payload.clone());
            Box::pin(async move {
                let p = QaPayload {
                    b: payload.to_vec(),
                };
                let pos = Outbox::append(
                    tx,
                    NewEvent {
                        tenant_id: Some(tenant_id),
                        event_type: &event_type,
                        event_version: 1,
                        partition_key,
                        payload: &p,
                    },
                )
                .await?;
                if !commit {
                    return Err(rollback_marker());
                }
                Ok(Appended {
                    partition: pos.partition,
                    sequence: pos.sequence,
                    event_id: pos.event_id.into_uuid(),
                })
            })
        })
        .await;
    match r {
        Ok(a) => Ok(Some(a)),
        Err(DbError::App(e)) if !commit && e.detail() == Some("qa: deliberate rollback") => {
            Ok(None)
        }
        Err(e) => Err(ev_db(e)),
    }
}

/// Contract rev 2: sequences are per (tenant, partition).
pub async fn outbox_read(
    d: &Domain,
    tenant: Uuid,
    partition: i32,
    after_sequence: i64,
    limit: usize,
) -> Result<Vec<(i64, Uuid)>, String> {
    Outbox::read(&d.pool, tenant, partition, after_sequence, limit as i64)
        .await
        .map(|v| v.into_iter().map(|r| (r.sequence, r.event_id)).collect())
        .map_err(|e| e.to_string())
}

// ======================================================================= idempotency
fn body_of(r: &IdemRequest) -> RequestBody<'_> {
    if r.body.is_empty() {
        RequestBody::Absent
    } else {
        RequestBody::Json(&r.body)
    }
}

pub fn idem_digest(r: &IdemRequest) -> Vec<u8> {
    let params: BTreeMap<String, String> = r.path_params.iter().cloned().collect();
    cs_db::idempotency::request_digest(&r.method, &r.route_template, &params, body_of(r))
        .unwrap_or_else(|e| panic!("digest: {e}"))
        .to_vec()
}

/// Parse the key exactly as the HTTP layer does (cs_api::IdempotencyKeyHeader). A value that
/// cannot even be carried in an HTTP header is reported as invalid_request.
async fn parse_key_like_http(key: &str) -> Result<IdempotencyKey, ErrorView> {
    use axum::extract::FromRequestParts;
    let invalid = ErrorView {
        code: "invalid_request".into(),
        status: 400,
        retryable: false,
    };
    let Ok(v) = http::HeaderValue::from_bytes(key.as_bytes()) else {
        return Err(invalid);
    };
    let req = http::Request::builder()
        .header("Idempotency-Key", v)
        .body(())
        .map_err(|_| invalid.clone())?;
    let (mut parts, ()) = req.into_parts();
    match cs_api::IdempotencyKeyHeader::from_request_parts(&mut parts, &()).await {
        Ok(cs_api::IdempotencyKeyHeader(Some(k))) => Ok(k),
        Ok(cs_api::IdempotencyKeyHeader(None)) => Err(invalid),
        Err(e) => Err(ev(*e.0)),
    }
}

pub async fn idem_execute(
    d: &Domain,
    tenant: Uuid,
    principal: Uuid,
    key: &str,
    r: &IdemRequest,
    effect_tag: &str,
    fail_effect: bool,
) -> Result<IdemResponse, ErrorView> {
    let key = parse_key_like_http(key).await?;
    let bad = |_| ErrorView {
        code: "invalid_request".into(),
        status: 400,
        retryable: false,
    };
    let scope = IdempotencyScope {
        tenant_id: TenantId::from_uuid(tenant).map_err(bad)?,
        principal_id: PrincipalId::from_uuid(principal).map_err(bad)?,
        key,
    };
    let digest: [u8; 32] = idem_digest(r).try_into().unwrap_or([0; 32]);
    let tag = Arc::new(effect_tag.to_string());
    let out = IdempotencyRecords::execute(&d.pool, &scope, digest, 24, move |tx: &mut DomainTx| {
        let tag = tag.clone();
        Box::pin(async move {
            let effect_id = Uuid::new_v4();
            sqlx::query("INSERT INTO qa_effects (tenant_id, effect_id, tag) VALUES ($1, $2, $3)")
                .bind(tenant)
                .bind(effect_id)
                .bind(tag.as_str())
                .execute(tx.conn())
                .await?;
            if fail_effect {
                return Err(DbError::app(CsError::new(ErrorCode::InvalidRequest)));
            }
            let mut body = serde_json::json!({ "effect_id": effect_id, "tag": tag.as_str() });
            if tag.starts_with("big:") {
                body["pad"] = serde_json::Value::String("x".repeat(100 * 1024));
            }
            Ok(StoredResponse {
                status: 201,
                body: serde_json::to_vec(&body).unwrap_or_default(),
            })
        })
    })
    .await;
    out.map(|s| IdemResponse {
        status: s.status,
        body: s.body,
    })
    .map_err(ev_db)
}

// ======================================================================= migrations
/// Contract §5.1: the header names a release that must be in the finalized-release table.
pub fn requires_finalized_header(release: &str) -> String {
    format!("-- requires_finalized: {release}\n")
}

pub async fn migrate_dir(url: &str, domain: &str, dir: &Path) -> Result<Vec<i32>, String> {
    let set = MigrationSet::from_dir(dir).map_err(|e| e.to_string())?;
    let pool = pool_for(domain_from(domain), url)?;
    let r = Migrator::run(&pool, &set)
        .await
        .map(|r| r.applied)
        .map_err(|e| e.to_string());
    pool.close().await;
    r
}

pub async fn finalize_release(url: &str, domain: &str, release: &str) -> Result<(), String> {
    let pool = pool_for(domain_from(domain), url)?;
    Migrator::bootstrap(&pool)
        .await
        .map_err(|e| e.to_string())?;
    let r = Migrator::finalize_release(&pool, release)
        .await
        .map_err(|e| e.to_string());
    pool.close().await;
    r
}

// ======================================================================= sagas
pub const QA_SAGA_STEPS: usize = 4;
pub const QA_SAGA_PIVOT: usize = 2;
const QA_SAGA_TYPE: &str = "qa.transfer";
const STEP_NAMES: [&str; 4] = ["hold", "prepare_credit", "commit_hold", "apply_credit"];

fn dom_a() -> DomainId {
    DomainId::App(ApplicationId::parse("org.qa.saga-a").unwrap_or_else(|_| panic!("app id")))
}
fn dom_b() -> DomainId {
    DomainId::App(ApplicationId::parse("org.qa.saga-b").unwrap_or_else(|_| panic!("app id")))
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

/// QA test saga "qa.transfer" (two test domains A and B):
///  step 0 (A) hold → step 1 (B) prepare credit → step 2 (A) PIVOT commit hold → step 3 (B) apply credit.
/// Every step (and compensation) writes one outbox event, as the framework requires, and
/// increments qa_step_commits in the same local transaction.
#[derive(Debug, Default)]
struct QaTransfer {
    fail_at: Mutex<HashMap<Uuid, usize>>,
    comp_log: Mutex<HashMap<Uuid, Vec<usize>>>,
}

fn input_of(ctx: &StepContext) -> i64 {
    let b: [u8; 8] = ctx.input.as_slice().try_into().unwrap_or([0; 8]);
    i64::from_be_bytes(b)
}

async fn emit(tx: &mut DomainTx, ctx: &StepContext, what: &str) -> Result<StepDone, DbError> {
    let p = QaPayload {
        b: what.as_bytes().to_vec(),
    };
    let pos = Outbox::append(
        tx,
        NewEvent {
            tenant_id: Some(ctx.tenant_id),
            event_type: "qa.saga_step",
            event_version: 1,
            partition_key: ctx.operation_id.into_uuid(),
            payload: &p,
        },
    )
    .await?;
    Ok(StepDone {
        result: format!("{what}:{}", ctx.operation_id).into_bytes(),
        outbox: vec![(&pos).into()],
    })
}

impl SagaDefinition for QaTransfer {
    fn saga_type(&self) -> &'static str {
        QA_SAGA_TYPE
    }
    fn protocol_version(&self) -> i32 {
        1
    }
    fn steps(&self) -> Vec<StepDef> {
        vec![
            StepDef {
                name: STEP_NAMES[0],
                domain: dom_a(),
            },
            StepDef {
                name: STEP_NAMES[1],
                domain: dom_b(),
            },
            StepDef {
                name: STEP_NAMES[2],
                domain: dom_a(),
            },
            StepDef {
                name: STEP_NAMES[3],
                domain: dom_b(),
            },
        ]
    }
    fn pivot(&self) -> &'static str {
        STEP_NAMES[QA_SAGA_PIVOT]
    }

    fn apply<'c>(
        &'c self,
        ctx: &'c StepContext,
        tx: &'c mut DomainTx,
    ) -> BoxFuture<'c, Result<StepDone, DbError>> {
        Box::pin(async move {
            let op = ctx.operation_id.into_uuid();
            let tenant = ctx.tenant_id.into_uuid();
            let amount = input_of(ctx);
            let step = STEP_NAMES
                .iter()
                .position(|s| *s == ctx.step)
                .unwrap_or(usize::MAX);
            if self
                .fail_at
                .lock()
                .map(|f| f.get(&op) == Some(&step))
                .unwrap_or(false)
            {
                return Err(DbError::app(
                    CsError::new(ErrorCode::InvalidRequest)
                        .with_detail("qa injected permanent failure"),
                ));
            }
            let sql = match step {
                0 => "INSERT INTO qa_holds (op, tenant_id, amount, state) VALUES ($1, $2, $3, 'held')",
                1 => "INSERT INTO qa_credits (op, tenant_id, amount, state) VALUES ($1, $2, $3, 'pending')",
                2 => "UPDATE qa_holds SET state = 'committed' WHERE op = $1 AND tenant_id = $2 AND amount = $3 AND state = 'held'",
                _ => "WITH u AS (UPDATE qa_credits SET state = 'applied' WHERE op = $1 AND state = 'pending' RETURNING tenant_id)
                      INSERT INTO qa_balance (tenant_id, balance, applications) SELECT $2, $3, 1 FROM u
                      ON CONFLICT (tenant_id) DO UPDATE SET balance = qa_balance.balance + EXCLUDED.balance,
                                                            applications = qa_balance.applications + 1",
            };
            let n = sqlx::query(sql)
                .bind(op)
                .bind(tenant)
                .bind(amount)
                .execute(tx.conn())
                .await?
                .rows_affected();
            if step == QA_SAGA_PIVOT && n != 1 {
                return Err(DbError::app(
                    CsError::new(ErrorCode::Conflict).with_detail("pivot condition failed"),
                ));
            }
            sqlx::query(
                "INSERT INTO qa_step_commits (op, step, commits) VALUES ($1, $2, 1)
                 ON CONFLICT (op, step) DO UPDATE SET commits = qa_step_commits.commits + 1",
            )
            .bind(op)
            .bind(step as i32)
            .execute(tx.conn())
            .await?;
            emit(tx, ctx, ctx.step).await
        })
    }

    fn compensate<'c>(
        &'c self,
        ctx: &'c StepContext,
        _applied: &'c StepDone,
        tx: &'c mut DomainTx,
    ) -> BoxFuture<'c, Result<StepDone, DbError>> {
        Box::pin(async move {
            let op = ctx.operation_id.into_uuid();
            let step = STEP_NAMES
                .iter()
                .position(|s| *s == ctx.step)
                .unwrap_or(usize::MAX);
            let sql = match step {
                0 => "UPDATE qa_holds SET state = 'voided' WHERE op = $1 AND state = 'held'",
                1 => "UPDATE qa_credits SET state = 'voided' WHERE op = $1 AND state = 'pending'",
                s => panic!("QA saga: compensation requested for post-pivot step {s}"),
            };
            sqlx::query(sql).bind(op).execute(tx.conn()).await?;
            if let Ok(mut log) = self.comp_log.lock() {
                log.entry(op).or_default().push(step);
            }
            emit(tx, ctx, &format!("compensate_{}", ctx.step)).await
        })
    }

    fn reconcile<'a>(
        &'a self,
        _ctx: &'a ReconcileContext<'a>,
    ) -> BoxFuture<'a, Result<ReconcileVerdict, DbError>> {
        // QA checks cross-domain consistency itself (assert_converged); this predicate only
        // reports, it never decides outcomes.
        Box::pin(async move { Ok(ReconcileVerdict::Consistent) })
    }
}

#[derive(Debug)]
pub struct SagaEnv {
    ops: DomainPool,
    a: DomainPool,
    b: DomainPool,
    def: Arc<QaTransfer>,
    tenants: Mutex<HashMap<Uuid, Uuid>>,
}

pub async fn saga_env(ops_url: &str, a_url: &str, b_url: &str) -> Result<SagaEnv, String> {
    let ops = pool_for(DomainId::Operations, ops_url)?;
    setup_migrate(&ops, &migration_set(&DomainId::Operations)?).await?;
    let a = pool_for(dom_a(), a_url)?;
    let b = pool_for(dom_b(), b_url)?;
    for (p, url, sql) in [(&a, a_url, QA_TABLES_A), (&b, b_url, QA_TABLES_B)] {
        // Participating domains get the common tables (outbox, saga_step_receipts).
        setup_migrate(p, &common_migrations().map_err(|e| e.to_string())?).await?;
        // QA fixture tables (test-only DDL, not product schema).
        super::db::fixture_sql(url, sql).await?;
    }
    Ok(SagaEnv {
        ops,
        a,
        b,
        def: Arc::new(QaTransfer::default()),
        tenants: Mutex::new(HashMap::new()),
    })
}

impl SagaEnv {
    fn executor(&self, hook: Option<cs_ops::saga::CrashHook>) -> SagaExecutor {
        let mut pools = BTreeMap::new();
        pools.insert(dom_a(), self.a.clone());
        pools.insert(dom_b(), self.b.clone());
        let mut ex = SagaExecutor::new(self.ops.clone(), pools);
        ex.register(self.def.clone())
            .unwrap_or_else(|e| panic!("register QA saga: {e}"));
        match hook {
            Some(h) => ex.with_crash_hook(h),
            None => ex,
        }
    }

    fn tenant_of(&self, op: Uuid) -> (TenantId, OperationId) {
        let t = self
            .tenants
            .lock()
            .ok()
            .and_then(|m| m.get(&op).copied())
            .unwrap_or_else(|| panic!("unknown op {op}"));
        (
            TenantId::from_uuid(t).unwrap_or_else(|_| panic!("tenant")),
            OperationId::from_uuid(op).unwrap_or_else(|_| panic!("op")),
        )
    }

    pub async fn start(&self, tenant: Uuid, key: &str, amount: i64) -> Result<Uuid, ErrorView> {
        let bad = || ErrorView {
            code: "invalid_request".into(),
            status: 400,
            retryable: false,
        };
        let body = format!("{{\"amount\":{amount}}}");
        let digest = cs_db::idempotency::request_digest(
            "POST",
            "/qa/transfer",
            &BTreeMap::new(),
            RequestBody::Json(body.as_bytes()),
        )
        .map_err(ev_db)?;
        let req = StartSaga {
            saga_type: QA_SAGA_TYPE.into(),
            tenant_id: TenantId::from_uuid(tenant).map_err(|_| bad())?,
            actor: PrincipalId::generate().map_err(|_| bad())?,
            idempotency_key: IdempotencyKey::parse(key).map_err(|_| bad())?,
            request_digest: digest,
            deadline: Duration::from_secs(600),
            input: amount.to_be_bytes().to_vec(),
        };
        let op = self
            .executor(None)
            .start(req)
            .await
            .map_err(ev_ops)?
            .into_uuid();
        if let Ok(mut m) = self.tenants.lock() {
            m.insert(op, tenant);
        }
        Ok(op)
    }

    /// `CrashAfterStep(k)`: the framework's crash hook stops the executor right after step k's
    /// local transaction commits (before the operation record is updated), as a process crash
    /// would. `LoseAckAfterStep(k)`: same, then a fresh executor immediately redelivers.
    pub async fn drive(&self, op: Uuid, fault: Fault) -> DriveOutcome {
        let (tenant, opid) = self.tenant_of(op);
        let hook_for = |k: usize| -> cs_ops::saga::CrashHook {
            let fired = Arc::new(AtomicBool::new(false));
            Arc::new(move |p: &CrashPoint| {
                matches!(p, CrashPoint::AfterStepTx { step, kind } if step == STEP_NAMES[k] && *kind == "apply")
                    && !fired.swap(true, Ordering::SeqCst)
            })
        };
        let (hook, retry_after_crash) = match fault {
            Fault::None => (None, false),
            Fault::CrashAfterStep(k) => (Some(hook_for(k)), false),
            Fault::LoseAckAfterStep(k) => (Some(hook_for(k)), true),
            Fault::FailPermanentlyAt(k) => {
                if let Ok(mut f) = self.def.fail_at.lock() {
                    f.insert(op, k);
                }
                (None, false)
            }
        };
        let map = |r: Result<SagaState, OpsError>| match r {
            Ok(SagaState::Completed) => DriveOutcome::Completed,
            Ok(SagaState::Compensated) => DriveOutcome::Compensated,
            Ok(SagaState::BlockedForOperator) => DriveOutcome::Blocked,
            Ok(s) => DriveOutcome::Error(format!("drive stopped in non-terminal state {s}")),
            Err(OpsError::Crashed(_)) => DriveOutcome::Crashed,
            Err(e) => DriveOutcome::Error(e.to_string()),
        };
        let exec = self.executor(hook);
        let first = tokio::spawn(async move { exec.drive(tenant, opid).await });
        let out = match first.await {
            Ok(r) => map(r),
            Err(j) => DriveOutcome::Error(j.to_string()),
        };
        if retry_after_crash && out == DriveOutcome::Crashed {
            return map(self.executor(None).drive(tenant, opid).await);
        }
        out
    }

    pub async fn reconcile(&self, rounds: usize) -> Result<(), String> {
        let rec = Reconciler::new(Arc::new(self.executor(None)));
        for _ in 0..rounds {
            rec.run_once().await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub async fn redeliver_step(&self, op: Uuid, step: usize) -> Result<Vec<u8>, String> {
        let (tenant, opid) = self.tenant_of(op);
        let done = self
            .executor(None)
            .redeliver_step(tenant, opid, step)
            .await
            .map_err(|e| e.to_string())?;
        cs_crypto::cbor::to_canonical(&done).map_err(|e| e.to_string())
    }

    pub async fn step_result(&self, op: Uuid, step: usize) -> Option<Vec<u8>> {
        let (tenant, opid) = self.tenant_of(op);
        let def = self.def.steps().into_iter().nth(step)?;
        let r = self
            .executor(None)
            .step_receipt(tenant, opid, &def)
            .await
            .ok()??;
        cs_crypto::cbor::to_canonical(&r).ok()
    }

    pub async fn try_transition(
        &self,
        op: Uuid,
        expected_version: i64,
        to_state: &str,
    ) -> Result<(), ErrorView> {
        let (tenant, opid) = self.tenant_of(op);
        let to = SagaState::parse(to_state).ok_or(ErrorView {
            code: "invalid_request".into(),
            status: 400,
            retryable: false,
        })?;
        self.executor(None)
            .try_transition(tenant, opid, expected_version, to)
            .await
            .map_err(ev_ops)
    }

    pub fn compensation_log(&self, op: Uuid) -> Vec<usize> {
        self.def
            .comp_log
            .lock()
            .map(|l| l.get(&op).cloned().unwrap_or_default())
            .unwrap_or_default()
    }
}
