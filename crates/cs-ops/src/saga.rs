//! Durable sagas (contract §5.4; spec §18.4, §2.6, App. C C1/C3/C9).
//!
//! # Model
//! - The operation record (`sagas`, operations domain) is created before any side effect and
//!   is advanced only by compare-and-set on `version`; [`SagaState::can_transition`] is the
//!   state machine.
//! - Every step is exactly one local transaction in its own domain plus at least one outbox
//!   event in that transaction. Step idempotency is the framework's job (contract §5.4 rev 2):
//!   the framework writes a `saga_step_receipts (tenant_id, operation_id, step, result)` row in
//!   the same local transaction as the step's effect, so a redelivered step finds its receipt
//!   and returns the stored result without re-running. Saga authors implement only the body.
//! - Authoritative proof instead of guessing: before compensating, the executor *fences* the
//!   pivot (and, during compensation, each pre-pivot step) by writing an "aborted" receipt
//!   for the step in the step's own domain. A concurrent or later execution of that
//!   step then observes the fence and cannot commit; if the step had already committed, the
//!   fence observes that instead. Timeouts, lost responses and missing events never decide an
//!   outcome.
//! - After the pivot only forward progress or `blocked_for_operator` is possible.
//! - Execution is level-triggered: [`SagaExecutor::drive`] derives the next action from the
//!   operation record and the participating domains' records, so a crash at any point is
//!   repaired by running it again (the [`Reconciler`] does this continuously).

use cs_common::error::{Error as CsError, ErrorCode};
use cs_common::id::{OperationId, PrincipalId, TenantId};
use cs_common::idempotency::IdempotencyKey;
use cs_common::vector::DomainId;
use cs_db::idempotency::RequestDigest;
use cs_db::outbox::OutboxPosition;
use cs_db::{DbError, DomainPool, DomainTx};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

/// Maximum size of the CBOR `steps` document and of results.
pub const MAX_DOC_BYTES: usize = 64 * 1024;
/// Forward retries of a post-pivot step before the saga is blocked for an operator.
pub const DEFAULT_MAX_FORWARD_ATTEMPTS: u32 = 10;

// ---------------------------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------------------------

/// Saga states (§18.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SagaState {
    Created,
    RunningPrePivot,
    PivotCommitted,
    Completing,
    Completed,
    Compensating,
    Compensated,
    BlockedForOperator,
}

impl SagaState {
    pub const ALL: [SagaState; 8] = [
        SagaState::Created,
        SagaState::RunningPrePivot,
        SagaState::PivotCommitted,
        SagaState::Completing,
        SagaState::Completed,
        SagaState::Compensating,
        SagaState::Compensated,
        SagaState::BlockedForOperator,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            SagaState::Created => "created",
            SagaState::RunningPrePivot => "running_pre_pivot",
            SagaState::PivotCommitted => "pivot_committed",
            SagaState::Completing => "completing",
            SagaState::Completed => "completed",
            SagaState::Compensating => "compensating",
            SagaState::Compensated => "compensated",
            SagaState::BlockedForOperator => "blocked_for_operator",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }

    /// No further automatic transitions (operator tooling for `blocked_for_operator` is M4).
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            SagaState::Completed | SagaState::Compensated | SagaState::BlockedForOperator
        )
    }

    pub const fn is_pre_pivot(self) -> bool {
        matches!(self, SagaState::Created | SagaState::RunningPrePivot)
    }

    /// The state machine (contract §5.4 rev 2). Self-transitions record step progress.
    /// - `compensating` is reachable only from the pre-pivot state `running_pre_pivot`;
    /// - from `pivot_committed` on, only forward transitions and `blocked_for_operator`;
    /// - `blocked_for_operator` leaves only through an audited operator action (M4), never
    ///   through this automatic state machine.
    pub fn can_transition(self, to: SagaState) -> bool {
        use SagaState::*;
        matches!(
            (self, to),
            (Created, RunningPrePivot | Compensated | BlockedForOperator)
                | (
                    RunningPrePivot,
                    RunningPrePivot | PivotCommitted | Compensating | BlockedForOperator
                )
                | (PivotCommitted, Completing | Completed | BlockedForOperator)
                | (Completing, Completing | Completed | BlockedForOperator)
                | (
                    Compensating,
                    Compensating | Compensated | BlockedForOperator
                )
        )
    }
}

impl fmt::Display for SagaState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------------------------

/// One step: exactly one local transaction in `domain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepDef {
    pub name: &'static str,
    pub domain: DomainId,
}

/// What a step (or compensation) transaction produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepDone {
    #[serde(with = "cs_crypto::cbor::bstr")]
    pub result: Vec<u8>,
    /// Outbox events written in the same transaction (at least one is required).
    pub outbox: Vec<OutboxRef>,
}

/// Outbox position recorded in the saga document (source position for §18.4 vectors).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxRef {
    pub domain: DomainId,
    pub partition: i32,
    pub sequence: i64,
    pub event_id: Uuid,
}

impl From<&OutboxPosition> for OutboxRef {
    fn from(p: &OutboxPosition) -> Self {
        Self {
            domain: p.domain.clone(),
            partition: p.partition,
            sequence: p.sequence,
            event_id: p.event_id.into_uuid(),
        }
    }
}

/// Context handed to step code.
#[derive(Debug, Clone)]
pub struct StepContext {
    pub operation_id: OperationId,
    pub tenant_id: TenantId,
    pub actor: PrincipalId,
    pub step: &'static str,
    pub input: Arc<Vec<u8>>,
}

/// Result of a definition's reconciliation predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileVerdict {
    /// Authoritative state agrees with the operation record.
    Consistent,
    /// Divergence that needs attention (exposed by the reconciler).
    Divergent(String),
}

/// Inputs to the reconciliation predicate.
#[derive(Debug)]
pub struct ReconcileContext<'a> {
    pub operation_id: OperationId,
    pub tenant_id: TenantId,
    pub state: SagaState,
    pub input: &'a [u8],
    pub pools: &'a BTreeMap<DomainId, DomainPool>,
}

/// A saga type. Steps run in order; the step named by [`SagaDefinition::pivot`] is the pivot;
/// steps before it are pre-pivot (compensable), steps after it are post-pivot (forward-only).
pub trait SagaDefinition: Send + Sync + 'static {
    fn saga_type(&self) -> &'static str;
    fn protocol_version(&self) -> i32;
    fn steps(&self) -> Vec<StepDef>;
    fn pivot(&self) -> &'static str;

    /// Apply `ctx.step` inside `tx` (its domain). Must write at least one outbox event via
    /// `cs_db::outbox::Outbox::append`. Return `Err(DbError::App(..))` for a permanent
    /// business failure; other errors are transient and retried later.
    fn apply<'c>(
        &'c self,
        ctx: &'c StepContext,
        tx: &'c mut DomainTx,
    ) -> BoxFuture<'c, Result<StepDone, DbError>>;

    /// Undo a committed pre-pivot step inside `tx`. Must write at least one outbox event.
    fn compensate<'c>(
        &'c self,
        ctx: &'c StepContext,
        applied: &'c StepDone,
        tx: &'c mut DomainTx,
    ) -> BoxFuture<'c, Result<StepDone, DbError>>;

    /// Level-triggered predicate evaluated from authoritative state only.
    fn reconcile<'a>(
        &'a self,
        ctx: &'a ReconcileContext<'a>,
    ) -> BoxFuture<'a, Result<ReconcileVerdict, DbError>>;
}

// ---------------------------------------------------------------------------------------------
// Operation record document
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Done,
    /// Fenced before it committed: never took effect.
    Skipped,
    Compensated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepState {
    pub name: String,
    pub domain: DomainId,
    pub status: StepStatus,
    pub attempts: u32,
    pub done: Option<StepDone>,
    pub compensation: Option<StepDone>,
}

/// The CBOR `steps` column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SagaDoc {
    #[serde(with = "cs_crypto::cbor::bstr")]
    pub input: Vec<u8>,
    pub steps: Vec<StepState>,
    pub failure: Option<String>,
}

impl SagaDoc {
    fn encode(&self) -> Result<Vec<u8>, OpsError> {
        let b =
            cs_crypto::cbor::to_canonical(self).map_err(|e| OpsError::Encoding(e.to_string()))?;
        if b.len() > MAX_DOC_BYTES {
            return Err(OpsError::Encoding("saga document exceeds 64 KiB".into()));
        }
        Ok(b)
    }

    fn decode(b: &[u8]) -> Result<Self, OpsError> {
        cs_crypto::cbor::from_canonical(b, MAX_DOC_BYTES)
            .map_err(|e| OpsError::Encoding(e.to_string()))
    }
}

/// A loaded operation record.
#[derive(Debug, Clone)]
pub struct SagaRecord {
    pub operation_id: OperationId,
    pub tenant_id: TenantId,
    pub saga_type: String,
    pub protocol_version: i32,
    pub actor: PrincipalId,
    pub state: SagaState,
    pub pivot: String,
    pub doc: SagaDoc,
    pub version: i64,
    pub deadline_passed: bool,
    pub result: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum OpsError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("unknown saga type {0}")]
    UnknownSagaType(String),
    #[error("no domain pool for {0}")]
    MissingPool(String),
    #[error("operation {0} not found")]
    NotFound(OperationId),
    #[error("saga record encoding: {0}")]
    Encoding(String),
    #[error("illegal saga transition {from} -> {to}")]
    IllegalTransition { from: SagaState, to: SagaState },
    #[error("operation record version {expected} is stale (current {current})")]
    VersionMismatch { expected: i64, current: i64 },
    #[error("invalid saga definition: {0}")]
    Definition(String),
    /// Test-only crash injection fired.
    #[error("injected crash at {0:?}")]
    Crashed(CrashPoint),
}

impl From<cs_crypto::rand::RandError> for OpsError {
    fn from(e: cs_crypto::rand::RandError) -> Self {
        OpsError::Db(DbError::Rand(e))
    }
}

impl From<OpsError> for CsError {
    fn from(e: OpsError) -> CsError {
        match e {
            OpsError::Db(d) => d.into(),
            OpsError::NotFound(_) => CsError::new(ErrorCode::NotFound),
            OpsError::IllegalTransition { .. } | OpsError::VersionMismatch { .. } => {
                CsError::new(ErrorCode::Conflict).with_cause(e)
            }
            other => CsError::internal(other),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Crash injection (tests)
// ---------------------------------------------------------------------------------------------

/// Points at which a test can make the executor stop as if the process died.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrashPoint {
    /// A step / compensation / fence transaction committed; the operation record is not yet updated.
    AfterStepTx { step: String, kind: &'static str },
    /// The operation record was updated.
    AfterRecordUpdate { to: SagaState },
}

/// Returns `true` to crash at the given point.
pub type CrashHook = Arc<dyn Fn(&CrashPoint) -> bool + Send + Sync>;

// ---------------------------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------------------------

/// Request to start a saga.
#[derive(Debug, Clone)]
pub struct StartSaga {
    pub saga_type: String,
    pub tenant_id: TenantId,
    pub actor: PrincipalId,
    pub idempotency_key: IdempotencyKey,
    pub request_digest: RequestDigest,
    pub deadline: Duration,
    pub input: Vec<u8>,
}

/// Drives sagas. Holds the operations-domain pool and one pool per participating domain.
pub struct SagaExecutor {
    ops: DomainPool,
    pools: BTreeMap<DomainId, DomainPool>,
    defs: BTreeMap<String, Arc<dyn SagaDefinition>>,
    crash: Option<CrashHook>,
    max_forward_attempts: u32,
}

impl fmt::Debug for SagaExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SagaExecutor")
            .field("domains", &self.pools.keys().collect::<Vec<_>>())
            .field("saga_types", &self.defs.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

enum Fence {
    /// The step never committed; it now never can.
    NotCommitted,
    Committed(StepDone),
}

#[derive(Serialize, Deserialize)]
struct StepRecordBody {
    committed: bool,
    done: Option<StepDone>,
}

/// Receipt `step` value of a compensation.
fn compensation_step(name: &str) -> String {
    format!("{name}:compensate")
}

enum Receipt {
    /// This transaction inserted the receipt row; it must fill it in before committing.
    Claimed,
    /// A committed receipt exists.
    Existing(StepRecordBody),
}

fn encode_receipt(body: &StepRecordBody) -> Result<Vec<u8>, DbError> {
    cs_crypto::cbor::to_canonical(body).map_err(|e| DbError::Invalid(e.to_string()))
}

/// Claim the receipt `(tenant, operation, step)` inside `tx`, or return the committed one.
/// A concurrent claimer blocks on the row until this transaction ends, then sees its result.
async fn claim_receipt(
    tx: &mut DomainTx,
    tenant: Uuid,
    op: Uuid,
    step: &str,
) -> Result<Receipt, DbError> {
    let claimed: Option<bool> = sqlx::query_scalar(
        "INSERT INTO saga_step_receipts (tenant_id, operation_id, step, result) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id, operation_id, step) DO NOTHING RETURNING true",
    )
    .bind(tenant)
    .bind(op)
    .bind(step)
    .bind(Vec::<u8>::new())
    .fetch_optional(tx.conn())
    .await?;
    if claimed.is_some() {
        return Ok(Receipt::Claimed);
    }
    let r: Vec<u8> = sqlx::query_scalar(
        "SELECT result FROM saga_step_receipts WHERE tenant_id = $1 AND operation_id = $2 AND step = $3",
    )
    .bind(tenant)
    .bind(op)
    .bind(step)
    .fetch_one(tx.conn())
    .await?;
    let body = cs_crypto::cbor::from_canonical(&r, MAX_DOC_BYTES)
        .map_err(|e| DbError::Invalid(format!("saga step receipt: {e}")))?;
    Ok(Receipt::Existing(body))
}

/// Fill in a claimed receipt (same transaction as the claim).
async fn write_receipt(
    tx: &mut DomainTx,
    tenant: Uuid,
    op: Uuid,
    step: &str,
    body: &StepRecordBody,
) -> Result<(), DbError> {
    let n = sqlx::query(
        "UPDATE saga_step_receipts SET result = $4 WHERE tenant_id = $1 AND operation_id = $2 AND step = $3",
    )
    .bind(tenant)
    .bind(op)
    .bind(step)
    .bind(encode_receipt(body)?)
    .execute(tx.conn())
    .await?
    .rows_affected();
    if n != 1 {
        return Err(DbError::Invalid("saga step receipt vanished".into()));
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct Row {
    operation_id: Uuid,
    tenant_id: Uuid,
    saga_type: String,
    protocol_version: i32,
    actor: Uuid,
    state: String,
    pivot: String,
    steps: Vec<u8>,
    version: i64,
    deadline_passed: bool,
    result: Option<Vec<u8>>,
}

impl SagaExecutor {
    pub fn new(ops: DomainPool, pools: BTreeMap<DomainId, DomainPool>) -> Self {
        Self {
            ops,
            pools,
            defs: BTreeMap::new(),
            crash: None,
            max_forward_attempts: DEFAULT_MAX_FORWARD_ATTEMPTS,
        }
    }

    /// Register a saga type. Validates that the pivot exists and every domain has a pool.
    pub fn register(&mut self, def: Arc<dyn SagaDefinition>) -> Result<(), OpsError> {
        let steps = def.steps();
        if steps.is_empty() || !steps.iter().any(|s| s.name == def.pivot()) {
            return Err(OpsError::Definition(format!(
                "{}: pivot must be one of the steps",
                def.saga_type()
            )));
        }
        let mut names = std::collections::BTreeSet::new();
        for s in &steps {
            let valid = !s.name.is_empty()
                && s.name.len() <= 64
                && s.name.as_bytes()[0].is_ascii_lowercase()
                && s.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            if !valid {
                return Err(OpsError::Definition(format!(
                    "invalid step name {:?}",
                    s.name
                )));
            }
            if !names.insert(s.name) {
                return Err(OpsError::Definition(format!("duplicate step {}", s.name)));
            }
            if !self.pools.contains_key(&s.domain) {
                return Err(OpsError::MissingPool(s.domain.to_string()));
            }
        }
        if def.protocol_version() < 1 {
            return Err(OpsError::Definition("protocol_version must be >= 1".into()));
        }
        self.defs.insert(def.saga_type().to_owned(), def);
        Ok(())
    }

    /// Test hook: crash (return [`OpsError::Crashed`]) when `hook` returns true.
    pub fn with_crash_hook(mut self, hook: CrashHook) -> Self {
        self.crash = Some(hook);
        self
    }

    pub fn with_max_forward_attempts(mut self, n: u32) -> Self {
        self.max_forward_attempts = n.max(1);
        self
    }

    pub fn pools(&self) -> &BTreeMap<DomainId, DomainPool> {
        &self.pools
    }

    pub fn operations_pool(&self) -> &DomainPool {
        &self.ops
    }

    fn crash_at(&self, p: CrashPoint) -> Result<(), OpsError> {
        if let Some(h) = &self.crash
            && h(&p)
        {
            return Err(OpsError::Crashed(p));
        }
        Ok(())
    }

    fn def(&self, saga_type: &str) -> Result<Arc<dyn SagaDefinition>, OpsError> {
        self.defs
            .get(saga_type)
            .cloned()
            .ok_or_else(|| OpsError::UnknownSagaType(saga_type.to_owned()))
    }

    fn pool(&self, d: &DomainId) -> Result<&DomainPool, OpsError> {
        self.pools
            .get(d)
            .ok_or_else(|| OpsError::MissingPool(d.to_string()))
    }

    /// Create the operation record (before any side effect). A duplicate request (same
    /// tenant, type and key) returns the existing operation; a different digest under the same
    /// key is `idempotency_mismatch`.
    pub async fn start(&self, req: StartSaga) -> Result<OperationId, OpsError> {
        let def = self.def(&req.saga_type)?;
        let doc = SagaDoc {
            input: req.input.clone(),
            steps: def
                .steps()
                .into_iter()
                .map(|s| StepState {
                    name: s.name.to_owned(),
                    domain: s.domain,
                    status: StepStatus::Pending,
                    attempts: 0,
                    done: None,
                    compensation: None,
                })
                .collect(),
            failure: None,
        }
        .encode()?;
        let op = OperationId::generate()?;
        let pivot = def.pivot().to_owned();
        let protocol = def.protocol_version();
        let deadline_ms = i64::try_from(req.deadline.as_millis()).unwrap_or(i64::MAX);
        let req = Arc::new(req);
        let doc = Arc::new(doc);
        let pivot = Arc::new(pivot);
        let id = self
            .ops
            .transaction(move |tx| {
                let (req, doc, pivot) = (req.clone(), doc.clone(), pivot.clone());
                Box::pin(async move {
                    let inserted: Option<Uuid> = sqlx::query_scalar(
                        "INSERT INTO sagas (operation_id, tenant_id, saga_type, protocol_version, actor, idempotency_key, \
                         request_digest, state, pivot, steps, deadline, version) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, 'created', $8, $9, now() + make_interval(secs => $10::float8 / 1000.0), 1) \
                         ON CONFLICT (tenant_id, saga_type, idempotency_key) DO NOTHING RETURNING operation_id",
                    )
                    .bind(op.as_uuid())
                    .bind(req.tenant_id.as_uuid())
                    .bind(&req.saga_type)
                    .bind(protocol)
                    .bind(req.actor.as_uuid())
                    .bind(req.idempotency_key.as_str())
                    .bind(req.request_digest.as_slice())
                    .bind(pivot.as_str())
                    .bind(doc.as_slice())
                    .bind(deadline_ms)
                    .fetch_optional(tx.conn())
                    .await?;
                    if let Some(id) = inserted {
                        return Ok(id);
                    }
                    let (id, digest): (Uuid, Vec<u8>) = sqlx::query_as(
                        "SELECT operation_id, request_digest FROM sagas \
                         WHERE tenant_id = $1 AND saga_type = $2 AND idempotency_key = $3",
                    )
                    .bind(req.tenant_id.as_uuid())
                    .bind(&req.saga_type)
                    .bind(req.idempotency_key.as_str())
                    .fetch_one(tx.conn())
                    .await?;
                    if digest.as_slice() != req.request_digest.as_slice() {
                        return Err(DbError::app(CsError::new(ErrorCode::IdempotencyMismatch)));
                    }
                    Ok(id)
                })
            })
            .await?;
        OperationId::from_uuid(id).map_err(|e| OpsError::Encoding(e.to_string()))
    }

    /// Load an operation record.
    pub async fn load(&self, tenant: TenantId, op: OperationId) -> Result<SagaRecord, OpsError> {
        let row: Option<Row> = self
            .ops
            .transaction(move |tx| Box::pin(async move {
                Ok(sqlx::query_as(
                    "SELECT operation_id, tenant_id, saga_type, protocol_version, actor, state, pivot, steps, version, \
                     (deadline <= now()) AS deadline_passed, result FROM sagas WHERE tenant_id = $1 AND operation_id = $2",
                )
                .bind(tenant.as_uuid())
                .bind(op.as_uuid())
                .fetch_optional(tx.conn())
                .await?)
            }))
            .await?;
        let r = row.ok_or(OpsError::NotFound(op))?;
        let bad = |e: cs_common::id::IdError| OpsError::Encoding(e.to_string());
        Ok(SagaRecord {
            operation_id: OperationId::from_uuid(r.operation_id).map_err(bad)?,
            tenant_id: TenantId::from_uuid(r.tenant_id).map_err(bad)?,
            saga_type: r.saga_type,
            protocol_version: r.protocol_version,
            actor: PrincipalId::from_uuid(r.actor).map_err(bad)?,
            state: SagaState::parse(&r.state)
                .ok_or_else(|| OpsError::Encoding(format!("state {}", r.state)))?,
            pivot: r.pivot,
            doc: SagaDoc::decode(&r.steps)?,
            version: r.version,
            deadline_passed: r.deadline_passed,
            result: r.result,
        })
    }

    /// Compare-and-set the operation record. Returns `false` if another executor advanced it.
    async fn cas(
        &self,
        rec: &SagaRecord,
        to: SagaState,
        doc: &SagaDoc,
        result: Option<Vec<u8>>,
    ) -> Result<bool, OpsError> {
        if !rec.state.can_transition(to) {
            return Err(OpsError::IllegalTransition {
                from: rec.state,
                to,
            });
        }
        let doc = Arc::new(doc.encode()?);
        let op = rec.operation_id;
        let tenant = rec.tenant_id;
        let expected = rec.version;
        let result = Arc::new(result);
        let n = self
            .ops
            .transaction(move |tx| {
                let (doc, result) = (doc.clone(), result.clone());
                Box::pin(async move {
                    Ok(sqlx::query(
                        "UPDATE sagas SET state = $3, steps = $4, result = COALESCE($5, result), \
                         version = version + 1, updated_at = now() \
                         WHERE operation_id = $1 AND version = $2 AND tenant_id = $6",
                    )
                    .bind(op.as_uuid())
                    .bind(expected)
                    .bind(to.as_str())
                    .bind(doc.as_slice())
                    .bind(result.as_deref())
                    .bind(tenant.as_uuid())
                    .execute(tx.conn())
                    .await?
                    .rows_affected())
                })
            })
            .await?;
        if n == 1 {
            metrics::counter!("cs_saga_transitions_total", "saga_type" => rec.saga_type.clone(), "to" => to.as_str()).increment(1);
            self.crash_at(CrashPoint::AfterRecordUpdate { to })?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn ctx(rec: &SagaRecord, step: &'static str) -> StepContext {
        StepContext {
            operation_id: rec.operation_id,
            tenant_id: rec.tenant_id,
            actor: rec.actor,
            step,
            input: Arc::new(rec.doc.input.clone()),
        }
    }

    /// Execute `step` (apply) in its domain. `Ok(None)` means the step was fenced.
    async fn run_apply(
        &self,
        def: &Arc<dyn SagaDefinition>,
        rec: &SagaRecord,
        step: &StepDef,
    ) -> Result<Option<StepDone>, OpsError> {
        let pool = self.pool(&step.domain)?;
        let (tenant, op) = (rec.tenant_id.into_uuid(), rec.operation_id.into_uuid());
        let ctx = Arc::new(Self::ctx(rec, step.name));
        let def = def.clone();
        let out = pool
            .transaction(move |tx| {
                let (def, ctx) = (def.clone(), ctx.clone());
                Box::pin(async move {
                    match claim_receipt(tx, tenant, op, ctx.step).await? {
                        Receipt::Existing(b) => Ok(b.done),
                        Receipt::Claimed => {
                            let done = def.apply(&ctx, tx).await?;
                            if done.outbox.is_empty() {
                                return Err(DbError::Invalid(format!(
                                    "step {} wrote no outbox event",
                                    ctx.step
                                )));
                            }
                            let body = StepRecordBody {
                                committed: true,
                                done: Some(done.clone()),
                            };
                            write_receipt(tx, tenant, op, ctx.step, &body).await?;
                            Ok(Some(done))
                        }
                    }
                })
            })
            .await?;
        self.crash_at(CrashPoint::AfterStepTx {
            step: step.name.to_owned(),
            kind: "apply",
        })?;
        Ok(out)
    }

    /// Fence a step in its domain: afterwards it can never commit. Reports whether it had.
    async fn fence(&self, rec: &SagaRecord, step: &StepDef) -> Result<Fence, OpsError> {
        let pool = self.pool(&step.domain)?;
        let (tenant, op) = (rec.tenant_id.into_uuid(), rec.operation_id.into_uuid());
        let name = step.name;
        let out = pool
            .transaction(move |tx| {
                Box::pin(async move {
                    match claim_receipt(tx, tenant, op, name).await? {
                        Receipt::Claimed => {
                            let body = StepRecordBody {
                                committed: false,
                                done: None,
                            };
                            write_receipt(tx, tenant, op, name, &body).await?;
                            Ok(None)
                        }
                        Receipt::Existing(b) => Ok(b.done),
                    }
                })
            })
            .await?;
        self.crash_at(CrashPoint::AfterStepTx {
            step: step.name.to_owned(),
            kind: "fence",
        })?;
        Ok(match out {
            None => Fence::NotCommitted,
            Some(d) => Fence::Committed(d),
        })
    }

    /// Fence and, if the step had committed, compensate it — in ONE transaction of its domain.
    /// Returns the compensation result, or `None` if the step never took effect.
    async fn run_compensation(
        &self,
        def: &Arc<dyn SagaDefinition>,
        rec: &SagaRecord,
        step: &StepDef,
    ) -> Result<Option<StepDone>, OpsError> {
        let pool = self.pool(&step.domain)?;
        let (tenant, op) = (rec.tenant_id.into_uuid(), rec.operation_id.into_uuid());
        let comp = Arc::new(compensation_step(step.name));
        let ctx = Arc::new(Self::ctx(rec, step.name));
        let def = def.clone();
        let out = pool
            .transaction(move |tx| {
                let (def, ctx, comp) = (def.clone(), ctx.clone(), comp.clone());
                Box::pin(async move {
                    let applied = match claim_receipt(tx, tenant, op, ctx.step).await? {
                        Receipt::Claimed => {
                            let body = StepRecordBody {
                                committed: false,
                                done: None,
                            };
                            write_receipt(tx, tenant, op, ctx.step, &body).await?;
                            return Ok(None);
                        }
                        Receipt::Existing(b) => match b.done {
                            None => return Ok(None),
                            Some(d) => d,
                        },
                    };
                    match claim_receipt(tx, tenant, op, &comp).await? {
                        Receipt::Existing(b) => Ok(b.done),
                        Receipt::Claimed => {
                            let done = def.compensate(&ctx, &applied, tx).await?;
                            if done.outbox.is_empty() {
                                return Err(DbError::Invalid(format!(
                                    "compensation of {} wrote no outbox event",
                                    ctx.step
                                )));
                            }
                            let body = StepRecordBody {
                                committed: true,
                                done: Some(done.clone()),
                            };
                            write_receipt(tx, tenant, op, &comp, &body).await?;
                            Ok(Some(done))
                        }
                    }
                })
            })
            .await?;
        self.crash_at(CrashPoint::AfterStepTx {
            step: step.name.to_owned(),
            kind: "compensate",
        })?;
        Ok(out)
    }

    /// The stored receipt of a step (apply), if any. For inspection and tests.
    pub async fn step_receipt(
        &self,
        tenant: TenantId,
        op: OperationId,
        step: &StepDef,
    ) -> Result<Option<Option<StepDone>>, OpsError> {
        let pool = self.pool(&step.domain)?;
        let name = step.name;
        let r: Option<Vec<u8>> = pool
            .transaction(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar(
                        "SELECT result FROM saga_step_receipts WHERE tenant_id = $1 AND operation_id = $2 AND step = $3",
                    )
                    .bind(tenant.as_uuid())
                    .bind(op.as_uuid())
                    .bind(name)
                    .fetch_optional(tx.conn())
                    .await?)
                })
            })
            .await?;
        r.map(|b| {
            cs_crypto::cbor::from_canonical::<StepRecordBody>(&b, MAX_DOC_BYTES)
                .map(|body| body.done)
                .map_err(|e| OpsError::Encoding(e.to_string()))
        })
        .transpose()
    }

    /// Redeliver one step (apply) as a duplicate delivery would: if its receipt exists the
    /// stored result is returned and the step body does not run. For tests and operators.
    pub async fn redeliver_step(
        &self,
        tenant: TenantId,
        op: OperationId,
        step_index: usize,
    ) -> Result<Option<StepDone>, OpsError> {
        let rec = self.load(tenant, op).await?;
        let def = self.def(&rec.saga_type)?;
        let steps = def.steps();
        let step = steps
            .get(step_index)
            .ok_or_else(|| OpsError::Definition("no such step".into()))?;
        self.run_apply(&def, &rec, step).await
    }

    /// Compare-and-set a state transition requested from outside the executor (operator
    /// tooling, tests). Enforces the transition table and the expected version.
    pub async fn try_transition(
        &self,
        tenant: TenantId,
        op: OperationId,
        expected_version: i64,
        to: SagaState,
    ) -> Result<(), OpsError> {
        let rec = self.load(tenant, op).await?;
        if rec.version != expected_version {
            return Err(OpsError::VersionMismatch {
                expected: expected_version,
                current: rec.version,
            });
        }
        if self.cas(&rec, to, &rec.doc, None).await? {
            Ok(())
        } else {
            let cur = self.load(tenant, op).await?.version;
            Err(OpsError::VersionMismatch {
                expected: expected_version,
                current: cur,
            })
        }
    }

    /// Decide pre-pivot failure: prove the pivot did not commit (fence), then compensate.
    /// If the fence finds the pivot committed, the saga moves forward instead.
    async fn abort_pre_pivot(
        &self,
        rec: &SagaRecord,
        steps: &[StepDef],
        pivot_idx: usize,
        reason: String,
    ) -> Result<bool, OpsError> {
        let mut doc = rec.doc.clone();
        match self.fence(rec, &steps[pivot_idx]).await? {
            Fence::Committed(done) => {
                doc.steps[pivot_idx].status = StepStatus::Done;
                doc.steps[pivot_idx].done = Some(done);
                self.cas(rec, SagaState::PivotCommitted, &doc, None).await
            }
            Fence::NotCommitted => {
                doc.steps[pivot_idx].status = StepStatus::Skipped;
                doc.failure = Some(reason);
                self.cas(rec, SagaState::Compensating, &doc, None).await
            }
        }
    }

    /// Advance the saga as far as possible. Returns the state reached (terminal unless a
    /// transient error stopped progress, which is returned as an error and retried later).
    pub async fn drive(&self, tenant: TenantId, op: OperationId) -> Result<SagaState, OpsError> {
        loop {
            let rec = self.load(tenant, op).await?;
            if rec.state.is_terminal() {
                return Ok(rec.state);
            }
            let def = self.def(&rec.saga_type)?;
            let steps = def.steps();
            if steps.len() != rec.doc.steps.len() {
                return Err(OpsError::Definition(
                    "step list changed for an existing operation".into(),
                ));
            }
            let pivot_idx = steps
                .iter()
                .position(|s| s.name == rec.pivot)
                .ok_or_else(|| OpsError::Definition("pivot not found".into()))?;
            let mut doc = rec.doc.clone();
            match rec.state {
                SagaState::Created => {
                    self.cas(&rec, SagaState::RunningPrePivot, &doc, None)
                        .await?;
                }
                SagaState::RunningPrePivot => {
                    if rec.deadline_passed {
                        // A deadline is not a failure; it only triggers the proof-based abort.
                        self.abort_pre_pivot(
                            &rec,
                            &steps,
                            pivot_idx,
                            "deadline passed before pivot".into(),
                        )
                        .await?;
                        continue;
                    }
                    let Some(i) =
                        (0..=pivot_idx).find(|i| doc.steps[*i].status == StepStatus::Pending)
                    else {
                        self.cas(&rec, SagaState::PivotCommitted, &doc, None)
                            .await?;
                        continue;
                    };
                    match self.run_apply(&def, &rec, &steps[i]).await {
                        Ok(Some(done)) => {
                            doc.steps[i].status = StepStatus::Done;
                            doc.steps[i].done = Some(done);
                            let to = if i == pivot_idx {
                                SagaState::PivotCommitted
                            } else {
                                SagaState::RunningPrePivot
                            };
                            self.cas(&rec, to, &doc, None).await?;
                        }
                        // Fenced by a concurrent abort. The abort fenced the pivot first, so
                        // this re-proves the outcome and follows it (the CAS loses if the
                        // other executor already advanced the record).
                        Ok(None) => {
                            self.abort_pre_pivot(
                                &rec,
                                &steps,
                                pivot_idx,
                                format!("step {} fenced", steps[i].name),
                            )
                            .await?;
                        }
                        Err(OpsError::Db(DbError::App(e))) => {
                            self.abort_pre_pivot(
                                &rec,
                                &steps,
                                pivot_idx,
                                format!("step {} failed: {}", steps[i].name, e.code()),
                            )
                            .await?;
                        }
                        Err(e) => {
                            self.note_attempt(&rec, i).await?;
                            return Err(e);
                        }
                    }
                }
                SagaState::PivotCommitted => {
                    self.cas(&rec, SagaState::Completing, &doc, None).await?;
                }
                SagaState::Completing => {
                    let Some(i) = (pivot_idx + 1..steps.len())
                        .find(|i| doc.steps[*i].status == StepStatus::Pending)
                    else {
                        let result = doc.steps[pivot_idx].done.as_ref().map(|d| d.result.clone());
                        self.cas(&rec, SagaState::Completed, &doc, result).await?;
                        continue;
                    };
                    match self.run_apply(&def, &rec, &steps[i]).await {
                        Ok(Some(done)) => {
                            doc.steps[i].status = StepStatus::Done;
                            doc.steps[i].done = Some(done);
                            self.cas(&rec, SagaState::Completing, &doc, None).await?;
                        }
                        Ok(None) => {
                            // Post-pivot steps are never fenced; this indicates corruption.
                            doc.failure =
                                Some(format!("post-pivot step {} found fenced", steps[i].name));
                            self.cas(&rec, SagaState::BlockedForOperator, &doc, None)
                                .await?;
                        }
                        Err(OpsError::Db(DbError::App(e))) => {
                            doc.failure = Some(format!(
                                "post-pivot step {} failed permanently: {}",
                                steps[i].name,
                                e.code()
                            ));
                            self.cas(&rec, SagaState::BlockedForOperator, &doc, None)
                                .await?;
                        }
                        Err(e) => {
                            if doc.steps[i].attempts + 1 >= self.max_forward_attempts {
                                doc.steps[i].attempts += 1;
                                doc.failure = Some(format!(
                                    "post-pivot step {} exhausted forward retries: {e}",
                                    steps[i].name
                                ));
                                self.cas(&rec, SagaState::BlockedForOperator, &doc, None)
                                    .await?;
                                continue;
                            }
                            self.note_attempt(&rec, i).await?;
                            return Err(e);
                        }
                    }
                }
                SagaState::Compensating => {
                    // Reverse dependency order over pre-pivot steps not yet resolved.
                    let Some(i) = (0..pivot_idx).rev().find(|i| {
                        matches!(doc.steps[*i].status, StepStatus::Pending | StepStatus::Done)
                    }) else {
                        let result = cs_crypto::cbor::to_canonical(&doc.failure)
                            .map_err(|e| OpsError::Encoding(e.to_string()))?;
                        self.cas(&rec, SagaState::Compensated, &doc, Some(result))
                            .await?;
                        continue;
                    };
                    match self.run_compensation(&def, &rec, &steps[i]).await {
                        Ok(Some(done)) => {
                            doc.steps[i].status = StepStatus::Compensated;
                            doc.steps[i].compensation = Some(done);
                        }
                        Ok(None) => doc.steps[i].status = StepStatus::Skipped,
                        Err(OpsError::Db(DbError::App(e))) => {
                            doc.failure = Some(format!(
                                "compensation of {} failed permanently: {}",
                                steps[i].name,
                                e.code()
                            ));
                            self.cas(&rec, SagaState::BlockedForOperator, &doc, None)
                                .await?;
                            continue;
                        }
                        Err(e) => {
                            self.note_attempt(&rec, i).await?;
                            return Err(e);
                        }
                    }
                    self.cas(&rec, SagaState::Compensating, &doc, None).await?;
                }
                SagaState::Completed | SagaState::Compensated | SagaState::BlockedForOperator => {
                    return Ok(rec.state);
                }
            }
        }
    }

    async fn note_attempt(&self, rec: &SagaRecord, i: usize) -> Result<(), OpsError> {
        let mut doc = rec.doc.clone();
        doc.steps[i].attempts = doc.steps[i].attempts.saturating_add(1);
        metrics::counter!("cs_saga_step_failures_total", "saga_type" => rec.saga_type.clone())
            .increment(1);
        // Losing this CAS to another executor is fine: the count is advisory.
        let _ = self.cas(rec, rec.state, &doc, None).await?;
        Ok(())
    }

    /// Evaluate the definition's reconciliation predicate for one operation.
    pub async fn verify(
        &self,
        tenant: TenantId,
        op: OperationId,
    ) -> Result<ReconcileVerdict, OpsError> {
        let rec = self.load(tenant, op).await?;
        let def = self.def(&rec.saga_type)?;
        let ctx = ReconcileContext {
            operation_id: rec.operation_id,
            tenant_id: rec.tenant_id,
            state: rec.state,
            input: &rec.doc.input,
            pools: &self.pools,
        };
        Ok(def.reconcile(&ctx).await?)
    }
}

// ---------------------------------------------------------------------------------------------
// Reconciler
// ---------------------------------------------------------------------------------------------

/// Outcome of one reconciler pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub examined: usize,
    pub terminal: usize,
    pub errors: usize,
    pub divergent: Vec<(OperationId, String)>,
}

/// Level-triggered reconciler: repeatedly drives every non-terminal saga from authoritative
/// state. Idempotent; safe to run on several nodes at once (CAS arbitrates).
#[derive(Debug, Clone)]
pub struct Reconciler {
    exec: Arc<SagaExecutor>,
    batch: i64,
}

impl Reconciler {
    pub fn new(exec: Arc<SagaExecutor>) -> Self {
        Self { exec, batch: 100 }
    }

    /// One pass over up to `batch` active sagas (oldest update first).
    pub async fn run_once(&self) -> Result<ReconcileReport, OpsError> {
        let batch = self.batch;
        let ids: Vec<(Uuid, Uuid, f64)> = self
            .exec
            .ops
            .transaction(move |tx| Box::pin(async move {
                Ok(sqlx::query_as(
                    "SELECT tenant_id, operation_id, EXTRACT(EPOCH FROM now() - created_at)::float8 FROM sagas \
                     WHERE state IN ('created', 'running_pre_pivot', 'pivot_committed', 'completing', 'compensating') \
                     ORDER BY updated_at ASC LIMIT $1",
                )
                .bind(batch)
                .fetch_all(tx.conn())
                .await?)
            }))
            .await?;
        let mut report = ReconcileReport::default();
        let mut oldest = 0f64;
        for (tenant, id, age) in ids {
            oldest = oldest.max(age);
            report.examined += 1;
            let op = OperationId::from_uuid(id).map_err(|e| OpsError::Encoding(e.to_string()))?;
            let tenant =
                TenantId::from_uuid(tenant).map_err(|e| OpsError::Encoding(e.to_string()))?;
            match self.exec.drive(tenant, op).await {
                Ok(state) if state.is_terminal() => {
                    report.terminal += 1;
                    if let ReconcileVerdict::Divergent(why) = self.exec.verify(tenant, op).await? {
                        tracing::error!(operation_id = %op, %why, "saga divergence");
                        report.divergent.push((op, why));
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    report.errors += 1;
                    tracing::warn!(operation_id = %op, error = %e, "saga step failed; will retry");
                }
            }
        }
        metrics::gauge!("cs_saga_reconciler_oldest_active_seconds").set(oldest);
        metrics::gauge!("cs_saga_reconciler_divergent").set(report.divergent.len() as f64);
        Ok(report)
    }

    /// Run until `shutdown` resolves.
    pub async fn run(self, interval: Duration, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            if let Err(e) = self.run_once().await {
                tracing::warn!(error = %e, "reconciler pass failed");
            }
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(interval) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine() {
        use SagaState::*;
        // The full rev 2 table: every allowed (from, to) pair, everything else rejected.
        let allowed: &[(SagaState, &[SagaState])] = &[
            (Created, &[RunningPrePivot, Compensated, BlockedForOperator]),
            (
                RunningPrePivot,
                &[
                    RunningPrePivot,
                    PivotCommitted,
                    Compensating,
                    BlockedForOperator,
                ],
            ),
            (PivotCommitted, &[Completing, Completed, BlockedForOperator]),
            (Completing, &[Completing, Completed, BlockedForOperator]),
            (
                Compensating,
                &[Compensating, Compensated, BlockedForOperator],
            ),
            (BlockedForOperator, &[]),
            (Completed, &[]),
            (Compensated, &[]),
        ];
        for (from, tos) in allowed {
            for to in SagaState::ALL {
                assert_eq!(from.can_transition(to), tos.contains(&to), "{from} -> {to}");
            }
        }
        // compensating only from pre-pivot states
        for s in SagaState::ALL {
            if s.can_transition(Compensating) {
                assert!(matches!(s, RunningPrePivot | Compensating), "{s}");
            }
        }
        for s in SagaState::ALL {
            assert_eq!(SagaState::parse(s.as_str()), Some(s));
        }
        assert_eq!(SagaState::parse("superseded"), None);
    }

    #[test]
    fn compensation_receipts_are_distinct() {
        assert_eq!(compensation_step("reserve"), "reserve:compensate");
        assert_ne!(compensation_step("a"), "a");
    }
}
