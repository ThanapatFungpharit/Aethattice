//! Tenant, user and group administration (contract §0, §1; spec §5.1, §5.7, §6.1, §6.4, J.4).
//!
//! In M1 these operations are reachable only from the `cs admin` CLI (contract §0 `[R4]`); the
//! HTTP admin API arrives in M2 under the relationship model. Every operation:
//! - runs as **one identity-domain transaction** (App. C rule C1) with no network call inside;
//! - writes one outbox event in that transaction (contract §0: M4 audit consumes it);
//! - maps failures to Appendix D codes.
//!
//! Group membership (§6.1, §6.4):
//! - the `group_members` row and the bump of `groups.membership_version` commit together;
//! - every membership transaction first bumps `tenants.group_epoch`, which serializes the
//!   tenant's membership writes, so the closure check below always sees every committed
//!   membership and two concurrent writes can never jointly create a cycle;
//! - cycles are rejected at write time; depth and closure-cardinality limits are checked in the
//!   same transaction and a breach returns `invalid_request` with `errors[].code =
//!   group_complexity_limit`. Nothing is written on rejection.

use crate::login::normalize_login;
use crate::token::{self, TokenHash};
use cs_common::error::{Error, ErrorCode, FieldError};
use cs_common::id::{GroupId, TenantId, UserId};
use cs_common::secret::Secret;
use cs_common::vector::DomainId;
use cs_db::outbox::{NewEvent, Outbox, OutboxPosition};
use cs_db::{DbError, DomainPool, DomainTx};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use uuid::Uuid;

/// Group nesting depth limit (edges on the longest group-in-group chain).
///
/// Provisional design constant: §6.4 requires "configured depth and cardinality limits", but
/// neither the spec, erratum C13 nor the M1 contract gives a default or safe range, so this is
/// not yet a configurable policy (reported to the Team Leader).
pub const DEFAULT_MAX_GROUP_DEPTH: u32 = 32;
/// Closure cardinality limit: distinct principals (users and groups) in a group's transitive
/// membership. Provisional design constant (see [`DEFAULT_MAX_GROUP_DEPTH`]).
pub const DEFAULT_MAX_GROUP_CLOSURE: usize = 10_000;
/// Validity of a first-administrator setup link. Provisional design constant: the contract
/// gives the link an expiry but no value (reported to the Team Leader).
pub const SETUP_LINK_LIFETIME_SECS: i64 = 24 * 3600;

/// `errors[].code` for a group depth or cardinality breach (contract §6.1).
pub const GROUP_COMPLEXITY_LIMIT: &str = "group_complexity_limit";

/// Marker recorded in outbox payloads for actions taken through the CLI.
const VIA_CLI: &str = "cs-admin";

/// Group expansion limits (§6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupLimits {
    pub max_depth: u32,
    pub max_closure: usize,
}

impl Default for GroupLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_GROUP_DEPTH,
            max_closure: DEFAULT_MAX_GROUP_CLOSURE,
        }
    }
}

/// Tenant lifecycle state (contract §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantState {
    Active,
    Suspended,
    Deleting,
}

impl TenantState {
    pub const fn as_str(self) -> &'static str {
        match self {
            TenantState::Active => "active",
            TenantState::Suspended => "suspended",
            TenantState::Deleting => "deleting",
        }
    }

    fn parse(s: &str) -> Result<Self, DbError> {
        match s {
            "active" => Ok(TenantState::Active),
            "suspended" => Ok(TenantState::Suspended),
            "deleting" => Ok(TenantState::Deleting),
            other => Err(DbError::Invalid(format!("unknown tenant state {other:?}"))),
        }
    }
}

/// User status (contract §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    Invited,
    Active,
    Disabled,
}

impl UserStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            UserStatus::Invited => "invited",
            UserStatus::Active => "active",
            UserStatus::Disabled => "disabled",
        }
    }

    fn parse(s: &str) -> Result<Self, DbError> {
        match s {
            "invited" => Ok(UserStatus::Invited),
            "active" => Ok(UserStatus::Active),
            "disabled" => Ok(UserStatus::Disabled),
            other => Err(DbError::Invalid(format!("unknown user status {other:?}"))),
        }
    }
}

/// User kind (§5.1: members of the home tenant, or invited guests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserKind {
    Member,
    Guest,
}

impl UserKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            UserKind::Member => "member",
            UserKind::Guest => "guest",
        }
    }

    fn parse(s: &str) -> Result<Self, DbError> {
        match s {
            "member" => Ok(UserKind::Member),
            "guest" => Ok(UserKind::Guest),
            other => Err(DbError::Invalid(format!("unknown user kind {other:?}"))),
        }
    }
}

/// A direct group member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Member {
    User(UserId),
    Group(GroupId),
}

impl Member {
    pub fn id(&self) -> Uuid {
        match self {
            Member::User(u) => u.into_uuid(),
            Member::Group(g) => g.into_uuid(),
        }
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Member::User(_) => "user",
            Member::Group(_) => "group",
        }
    }

    fn from_row(id: Uuid, kind: &str) -> Result<Self, DbError> {
        let bad = |e: cs_common::id::IdError| DbError::Invalid(format!("stored member id: {e}"));
        match kind {
            "user" => Ok(Member::User(UserId::from_uuid(id).map_err(bad)?)),
            "group" => Ok(Member::Group(GroupId::from_uuid(id).map_err(bad)?)),
            other => Err(DbError::Invalid(format!("unknown member kind {other:?}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRecord {
    pub tenant_id: TenantId,
    pub name: String,
    pub state: TenantState,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub login: String,
    pub status: UserStatus,
    pub kind: UserKind,
    pub display_name: Option<String>,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRecord {
    pub tenant_id: TenantId,
    pub group_id: GroupId,
    pub name: String,
    pub membership_version: i64,
}

/// A committed membership change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipChange {
    pub tenant_id: TenantId,
    pub group_id: GroupId,
    pub member: Member,
    /// `groups.membership_version` after the change.
    pub membership_version: i64,
    pub event: OutboxPosition,
}

/// A newly issued first-administrator setup link. The token is shown once and never stored.
#[derive(Debug)]
pub struct IssuedSetupLink {
    pub token: Secret<String>,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    /// Database rendering of `expires_at`.
    pub expires_at: String,
    /// Active links of the same user that this issuance revoked.
    pub revoked_previous: u64,
}

/// Input of [`IdentityAdmin::create_user`].
#[derive(Debug, Clone)]
pub struct NewUser {
    pub login: String,
    pub kind: UserKind,
    pub display_name: Option<String>,
}

// ----- outbox payloads (deterministic CBOR; no secrets) -----

#[derive(Serialize)]
struct TenantCreated<'a> {
    tenant_id: TenantId,
    state: &'a str,
    version: i64,
    via: &'a str,
}

#[derive(Serialize)]
struct UserCreated<'a> {
    tenant_id: TenantId,
    user_id: UserId,
    kind: &'a str,
    status: &'a str,
    version: i64,
    via: &'a str,
}

#[derive(Serialize)]
struct GroupCreated<'a> {
    tenant_id: TenantId,
    group_id: GroupId,
    membership_version: i64,
    via: &'a str,
}

#[derive(Serialize)]
struct MembershipChanged<'a> {
    tenant_id: TenantId,
    group_id: GroupId,
    member_id: Uuid,
    member_kind: &'a str,
    change: &'a str,
    membership_version: i64,
    via: &'a str,
}

#[derive(Serialize)]
struct SetupLinkIssued<'a> {
    tenant_id: TenantId,
    user_id: UserId,
    purpose: &'a str,
    revoked_previous: u64,
    via: &'a str,
}

// ----- error helpers -----

fn app(code: ErrorCode, detail: impl Into<String>) -> DbError {
    DbError::app(Error::new(code).with_detail(detail))
}

fn complexity(detail: impl Into<String>) -> DbError {
    let detail = detail.into();
    DbError::app(
        Error::new(ErrorCode::InvalidRequest)
            .with_detail(detail.clone())
            .with_field_error(FieldError {
                pointer: String::new(),
                code: GROUP_COMPLEXITY_LIMIT.to_owned(),
                detail,
            }),
    )
}

fn is_unique_violation(e: &DbError) -> bool {
    e.sqlstate().as_deref() == Some("23505")
}

/// Validate a display name (tenant, group or user display name): 1–200 characters, no control
/// characters, no leading or trailing whitespace.
fn valid_name(field: &str, s: &str) -> AdminResult<()> {
    let n = s.chars().count();
    if n == 0 || n > 200 || s.chars().any(char::is_control) || s.trim() != s {
        return Err(Error::new(ErrorCode::InvalidRequest)
            .with_detail(format!(
                "{field} must be 1-200 characters without control characters or surrounding whitespace"
            ))
            .with_field_error(FieldError {
                pointer: format!("/{field}"),
                code: "invalid".to_owned(),
                detail: format!("invalid {field}"),
            })
            .into());
    }
    Ok(())
}

fn ids<T>(r: Result<T, cs_common::id::IdError>) -> Result<T, DbError> {
    r.map_err(|e| DbError::Invalid(format!("stored identifier: {e}")))
}

/// Tenant must exist and be active. Takes a share lock so a concurrent state change waits.
async fn require_active_tenant(tx: &mut DomainTx, tenant: TenantId) -> Result<(), DbError> {
    let state: Option<String> =
        sqlx::query_scalar("SELECT state FROM tenants WHERE tenant_id = $1 FOR SHARE")
            .bind(tenant.as_uuid())
            .fetch_optional(tx.conn())
            .await?;
    match state.as_deref() {
        None => Err(app(ErrorCode::NotFound, "tenant not found")),
        Some("active") => Ok(()),
        Some(_) => Err(app(ErrorCode::Conflict, "tenant is not active")),
    }
}

/// Serialize the tenant's membership writes (see module docs) and check the tenant is active.
async fn lock_tenant_membership(tx: &mut DomainTx, tenant: TenantId) -> Result<(), DbError> {
    let state: Option<String> = sqlx::query_scalar(
        "UPDATE tenants SET group_epoch = group_epoch + 1 WHERE tenant_id = $1 RETURNING state",
    )
    .bind(tenant.as_uuid())
    .fetch_optional(tx.conn())
    .await?;
    match state.as_deref() {
        None => Err(app(ErrorCode::NotFound, "tenant not found")),
        Some("active") => Ok(()),
        Some(_) => Err(app(ErrorCode::Conflict, "tenant is not active")),
    }
}

async fn group_version(
    tx: &mut DomainTx,
    tenant: TenantId,
    group: GroupId,
) -> Result<Option<i64>, DbError> {
    Ok(sqlx::query_scalar(
        "SELECT membership_version FROM groups WHERE tenant_id = $1 AND group_id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(group.as_uuid())
    .fetch_optional(tx.conn())
    .await?)
}

/// Direct members of `groups`: (member_id, is_group).
async fn children(
    tx: &mut DomainTx,
    tenant: TenantId,
    groups: &[Uuid],
) -> Result<Vec<(Uuid, bool)>, DbError> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT member_id, member_kind FROM group_members WHERE tenant_id = $1 AND group_id = ANY($2)",
    )
    .bind(tenant.as_uuid())
    .bind(groups)
    .fetch_all(tx.conn())
    .await?;
    Ok(rows.into_iter().map(|(m, k)| (m, k == "group")).collect())
}

/// Groups that directly contain any of `groups` as a group member.
async fn parents(
    tx: &mut DomainTx,
    tenant: TenantId,
    groups: &[Uuid],
) -> Result<Vec<Uuid>, DbError> {
    Ok(sqlx::query_scalar(
        "SELECT group_id FROM group_members WHERE tenant_id = $1 AND member_id = ANY($2) AND member_kind = 'group'",
    )
    .bind(tenant.as_uuid())
    .bind(groups)
    .fetch_all(tx.conn())
    .await?)
}

/// Transitive members of `root` (users and groups, excluding `root` itself), level by level.
/// Returns the member set and the longest group chain below `root`. Fails with
/// `group_complexity_limit` as soon as either limit is exceeded; `stop_at` reports a cycle.
async fn expand(
    tx: &mut DomainTx,
    tenant: TenantId,
    root: Uuid,
    limits: GroupLimits,
    stop_at: Option<Uuid>,
) -> Result<(HashSet<Uuid>, u32), DbError> {
    let mut all = HashSet::new();
    let mut seen_groups = HashSet::from([root]);
    let mut level = vec![root];
    let mut depth = 0u32;
    loop {
        let rows = children(tx, tenant, &level).await?;
        let mut next = Vec::new();
        for (m, is_group) in rows {
            if stop_at == Some(m) {
                return Err(app(
                    ErrorCode::InvalidRequest,
                    "membership would create a group cycle",
                ));
            }
            all.insert(m);
            if is_group && seen_groups.insert(m) {
                next.push(m);
            }
        }
        if all.len() > limits.max_closure {
            return Err(complexity(format!(
                "group closure exceeds {} principals",
                limits.max_closure
            )));
        }
        if next.is_empty() {
            return Ok((all, depth));
        }
        depth += 1;
        if depth > limits.max_depth {
            return Err(complexity(format!(
                "group nesting exceeds depth {}",
                limits.max_depth
            )));
        }
        level = next;
    }
}

/// Every group that transitively contains `group`, and the longest chain above it.
async fn ancestors(
    tx: &mut DomainTx,
    tenant: TenantId,
    group: Uuid,
    limits: GroupLimits,
) -> Result<(HashSet<Uuid>, u32), DbError> {
    let mut all = HashSet::new();
    let mut level = vec![group];
    let mut depth = 0u32;
    loop {
        let mut p = parents(tx, tenant, &level).await?;
        p.sort_unstable();
        p.dedup();
        if p.is_empty() {
            return Ok((all, depth));
        }
        depth += 1;
        if depth > limits.max_depth {
            return Err(complexity(format!(
                "group nesting exceeds depth {}",
                limits.max_depth
            )));
        }
        all.extend(p.iter().copied());
        if all.len() > limits.max_closure {
            return Err(complexity(format!(
                "group closure exceeds {} principals",
                limits.max_closure
            )));
        }
        level = p;
    }
}

/// Closure check for adding `member` to `group` (§6.4). Runs inside the membership
/// transaction, after [`lock_tenant_membership`].
async fn check_closure(
    tx: &mut DomainTx,
    tenant: TenantId,
    group: GroupId,
    member: Member,
    limits: GroupLimits,
) -> Result<(), DbError> {
    let p = group.into_uuid();
    // Members contributed by the new edge, and the chain it hangs below `group`.
    let (added, below) = match member {
        Member::User(u) => (HashSet::from([u.into_uuid()]), 0u32),
        Member::Group(c) => {
            if c == group {
                return Err(app(
                    ErrorCode::InvalidRequest,
                    "a group cannot be a member of itself",
                ));
            }
            // A cycle exists iff `group` is already reachable from the new member group.
            let (desc, depth) = expand(tx, tenant, c.into_uuid(), limits, Some(p)).await?;
            let mut s = desc;
            s.insert(c.into_uuid());
            (s, depth + 1)
        }
    };
    let (above_set, above) = ancestors(tx, tenant, p, limits).await?;
    if above + below > limits.max_depth {
        return Err(complexity(format!(
            "group nesting would exceed depth {}",
            limits.max_depth
        )));
    }
    // Every group whose expansion grows: `group` and all its ancestors.
    let mut affected: Vec<Uuid> = above_set.into_iter().collect();
    affected.push(p);
    for a in affected {
        let (mut closure, _) = expand(tx, tenant, a, limits, None).await?;
        closure.extend(added.iter().copied());
        if closure.len() > limits.max_closure {
            return Err(complexity(format!(
                "group closure would exceed {} principals",
                limits.max_closure
            )));
        }
    }
    Ok(())
}

/// Error of [`IdentityAdmin`] operations: an Appendix D [`Error`], boxed to keep results small.
#[derive(Debug, Clone)]
pub struct AdminError(Box<Error>);

impl AdminError {
    pub fn into_inner(self) -> Error {
        *self.0
    }
}

impl std::ops::Deref for AdminError {
    type Target = Error;
    fn deref(&self) -> &Error {
        &self.0
    }
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&*self.0, f)
    }
}

impl std::error::Error for AdminError {}

impl From<Error> for AdminError {
    fn from(e: Error) -> Self {
        Self(Box::new(e))
    }
}

impl From<DbError> for AdminError {
    fn from(e: DbError) -> Self {
        Self(Box::new(e.into()))
    }
}

/// Result of [`IdentityAdmin`] operations.
pub type AdminResult<T> = Result<T, AdminError>;

/// Identity-domain administration (contract §0, §1).
#[derive(Debug, Clone)]
pub struct IdentityAdmin {
    pool: DomainPool,
    limits: GroupLimits,
}

impl IdentityAdmin {
    /// `pool` must be the identity domain's pool.
    pub fn new(pool: DomainPool) -> AdminResult<Self> {
        if pool.domain() != &DomainId::Identity {
            return Err(Error::new(ErrorCode::Internal)
                .with_detail(format!(
                    "identity administration needs the identity domain, got {}",
                    pool.domain()
                ))
                .into());
        }
        Ok(Self {
            pool,
            limits: GroupLimits::default(),
        })
    }

    /// Override the group expansion limits.
    pub fn with_group_limits(mut self, limits: GroupLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn group_limits(&self) -> GroupLimits {
        self.limits
    }

    /// Create an active tenant with the default (empty) policy document. Outbox:
    /// `identity.tenant.created`.
    pub async fn create_tenant(&self, name: &str) -> AdminResult<TenantRecord> {
        valid_name("name", name)?;
        let policy = cs_crypto::cbor::to_canonical(&BTreeMap::<String, i64>::new())
            .map_err(Error::internal)?;
        let name = name.to_owned();
        let rec = self
            .pool
            .transaction(move |tx| {
                let (name, policy) = (name.clone(), policy.clone());
                Box::pin(async move {
                    let tenant_id = TenantId::generate()?;
                    sqlx::query(
                        "INSERT INTO tenants (tenant_id, name, state, policy, version) VALUES ($1, $2, 'active', $3, 1)",
                    )
                    .bind(tenant_id.as_uuid())
                    .bind(&name)
                    .bind(&policy)
                    .execute(tx.conn())
                    .await?;
                    Outbox::append(
                        tx,
                        NewEvent {
                            tenant_id: Some(tenant_id),
                            event_type: "identity.tenant.created",
                            event_version: 1,
                            partition_key: tenant_id.into_uuid(),
                            payload: &TenantCreated {
                                tenant_id,
                                state: TenantState::Active.as_str(),
                                version: 1,
                                via: VIA_CLI,
                            },
                        },
                    )
                    .await?;
                    Ok(TenantRecord {
                        tenant_id,
                        name,
                        state: TenantState::Active,
                        version: 1,
                    })
                })
            })
            .await?;
        Ok(rec)
    }

    /// Create a user in status `invited` (credentials come from a setup link or invitation).
    /// The login is normalized and unique per tenant (`conflict` otherwise). Outbox:
    /// `identity.user.created`.
    pub async fn create_user(&self, tenant: TenantId, u: NewUser) -> AdminResult<UserRecord> {
        let login = normalize_login(&u.login).map_err(|e| {
            Error::new(ErrorCode::InvalidRequest)
                .with_detail(e.to_string())
                .with_field_error(FieldError {
                    pointer: "/login".to_owned(),
                    code: "invalid".to_owned(),
                    detail: e.to_string(),
                })
        })?;
        if let Some(d) = &u.display_name {
            valid_name("display_name", d)?;
        }
        let (kind, display_name) = (u.kind, u.display_name);
        let rec = self
            .pool
            .transaction(move |tx| {
                let (login, display_name) = (login.clone(), display_name.clone());
                Box::pin(async move {
                    require_active_tenant(tx, tenant).await?;
                    let user_id = UserId::generate()?;
                    let r = sqlx::query(
                        "INSERT INTO users (tenant_id, user_id, login, status, kind, display_name, version) \
                         VALUES ($1, $2, $3, 'invited', $4, $5, 1)",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user_id.as_uuid())
                    .bind(&login)
                    .bind(kind.as_str())
                    .bind(display_name.as_deref())
                    .execute(tx.conn())
                    .await
                    .map_err(DbError::from);
                    match r {
                        Err(e) if is_unique_violation(&e) => {
                            return Err(app(
                                ErrorCode::Conflict,
                                "a user with this login already exists in the tenant",
                            ));
                        }
                        Err(e) => return Err(e),
                        Ok(_) => {}
                    }
                    Outbox::append(
                        tx,
                        NewEvent {
                            tenant_id: Some(tenant),
                            event_type: "identity.user.created",
                            event_version: 1,
                            partition_key: user_id.into_uuid(),
                            payload: &UserCreated {
                                tenant_id: tenant,
                                user_id,
                                kind: kind.as_str(),
                                status: UserStatus::Invited.as_str(),
                                version: 1,
                                via: VIA_CLI,
                            },
                        },
                    )
                    .await?;
                    Ok(UserRecord {
                        tenant_id: tenant,
                        user_id,
                        login,
                        status: UserStatus::Invited,
                        kind,
                        display_name,
                        version: 1,
                    })
                })
            })
            .await?;
        Ok(rec)
    }

    /// Create an empty group (membership_version 1). Outbox: `identity.group.created`.
    pub async fn create_group(&self, tenant: TenantId, name: &str) -> AdminResult<GroupRecord> {
        valid_name("name", name)?;
        let name = name.to_owned();
        let rec = self
            .pool
            .transaction(move |tx| {
                let name = name.clone();
                Box::pin(async move {
                    require_active_tenant(tx, tenant).await?;
                    let group_id = GroupId::generate()?;
                    sqlx::query(
                        "INSERT INTO groups (tenant_id, group_id, name, membership_version) VALUES ($1, $2, $3, 1)",
                    )
                    .bind(tenant.as_uuid())
                    .bind(group_id.as_uuid())
                    .bind(&name)
                    .execute(tx.conn())
                    .await?;
                    Outbox::append(
                        tx,
                        NewEvent {
                            tenant_id: Some(tenant),
                            event_type: "identity.group.created",
                            event_version: 1,
                            partition_key: group_id.into_uuid(),
                            payload: &GroupCreated {
                                tenant_id: tenant,
                                group_id,
                                membership_version: 1,
                                via: VIA_CLI,
                            },
                        },
                    )
                    .await?;
                    Ok(GroupRecord {
                        tenant_id: tenant,
                        group_id,
                        name,
                        membership_version: 1,
                    })
                })
            })
            .await?;
        Ok(rec)
    }

    /// Add a direct member. With `expected_version`, the group's membership_version must match
    /// (`precondition_failed` otherwise). Cycles and limit breaches are rejected (module docs).
    /// Outbox: `identity.group.membership_changed` with the new membership_version.
    pub async fn add_member(
        &self,
        tenant: TenantId,
        group: GroupId,
        member: Member,
        expected_version: Option<i64>,
    ) -> AdminResult<MembershipChange> {
        let limits = self.limits;
        let r = self
            .pool
            .transaction(move |tx| {
                Box::pin(async move {
                    lock_tenant_membership(tx, tenant).await?;
                    let version = group_version(tx, tenant, group)
                        .await?
                        .ok_or_else(|| app(ErrorCode::NotFound, "group not found"))?;
                    if expected_version.is_some_and(|e| e != version) {
                        return Err(app(
                            ErrorCode::PreconditionFailed,
                            "group membership_version does not match",
                        ));
                    }
                    let exists: Option<i32> = match member {
                        Member::User(u) => {
                            sqlx::query_scalar(
                                "SELECT 1 FROM users WHERE tenant_id = $1 AND user_id = $2",
                            )
                            .bind(tenant.as_uuid())
                            .bind(u.as_uuid())
                            .fetch_optional(tx.conn())
                            .await?
                        }
                        Member::Group(g) => group_version(tx, tenant, g).await?.map(|_| 1),
                    };
                    if exists.is_none() {
                        return Err(app(ErrorCode::NotFound, "member not found"));
                    }
                    let already: Option<i32> = sqlx::query_scalar(
                        "SELECT 1 FROM group_members WHERE tenant_id = $1 AND group_id = $2 AND member_id = $3",
                    )
                    .bind(tenant.as_uuid())
                    .bind(group.as_uuid())
                    .bind(member.id())
                    .fetch_optional(tx.conn())
                    .await?;
                    if already.is_some() {
                        return Err(app(ErrorCode::Conflict, "already a direct member"));
                    }
                    check_closure(tx, tenant, group, member, limits).await?;
                    sqlx::query(
                        "INSERT INTO group_members (tenant_id, group_id, member_id, member_kind) VALUES ($1, $2, $3, $4)",
                    )
                    .bind(tenant.as_uuid())
                    .bind(group.as_uuid())
                    .bind(member.id())
                    .bind(member.kind())
                    .execute(tx.conn())
                    .await?;
                    finish_membership_change(tx, tenant, group, member, version, "added").await
                })
            })
            .await?;
        Ok(r)
    }

    /// Remove a direct member (`not_found` if it is not one). Same versioning and event as
    /// [`IdentityAdmin::add_member`].
    pub async fn remove_member(
        &self,
        tenant: TenantId,
        group: GroupId,
        member: Member,
        expected_version: Option<i64>,
    ) -> AdminResult<MembershipChange> {
        let r = self
            .pool
            .transaction(move |tx| {
                Box::pin(async move {
                    lock_tenant_membership(tx, tenant).await?;
                    let version = group_version(tx, tenant, group)
                        .await?
                        .ok_or_else(|| app(ErrorCode::NotFound, "group not found"))?;
                    if expected_version.is_some_and(|e| e != version) {
                        return Err(app(
                            ErrorCode::PreconditionFailed,
                            "group membership_version does not match",
                        ));
                    }
                    let n = sqlx::query(
                        "DELETE FROM group_members WHERE tenant_id = $1 AND group_id = $2 AND member_id = $3 AND member_kind = $4",
                    )
                    .bind(tenant.as_uuid())
                    .bind(group.as_uuid())
                    .bind(member.id())
                    .bind(member.kind())
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    if n == 0 {
                        return Err(app(ErrorCode::NotFound, "not a direct member"));
                    }
                    finish_membership_change(tx, tenant, group, member, version, "removed").await
                })
            })
            .await?;
        Ok(r)
    }

    /// Issue the one-time first-administrator setup link (J.4 step 4) for an `invited` member
    /// user. Earlier active links of that user are revoked in the same transaction, so at most
    /// one link per user is valid. Only SHA-256 of the token is stored. Outbox:
    /// `identity.setup_link.issued` (never carries the token or its hash).
    pub async fn issue_setup_link(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> AdminResult<IssuedSetupLink> {
        let r = self
            .pool
            .transaction(move |tx| {
                Box::pin(async move {
                    require_active_tenant(tx, tenant).await?;
                    let row: Option<(String, String)> = sqlx::query_as(
                        "SELECT status, kind FROM users WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .fetch_optional(tx.conn())
                    .await?;
                    let (status, kind) =
                        row.ok_or_else(|| app(ErrorCode::NotFound, "user not found"))?;
                    if UserKind::parse(&kind)? != UserKind::Member {
                        return Err(app(
                            ErrorCode::InvalidRequest,
                            "a guest cannot be the first administrator",
                        ));
                    }
                    if UserStatus::parse(&status)? != UserStatus::Invited {
                        return Err(app(
                            ErrorCode::Conflict,
                            "setup links are issued only for invited users",
                        ));
                    }
                    let revoked = sqlx::query(
                        "UPDATE setup_links SET state = 'revoked', version = version + 1 \
                         WHERE tenant_id = $1 AND user_id = $2 AND state = 'active'",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    let issued = token::generate(tenant)?;
                    let expires_at: String = sqlx::query_scalar(
                        "INSERT INTO setup_links (tenant_id, token_hash, user_id, purpose, state, expires_at, version) \
                         VALUES ($1, $2, $3, 'first_admin', 'active', now() + make_interval(secs => $4::float8), 1) \
                         RETURNING expires_at::text",
                    )
                    .bind(tenant.as_uuid())
                    .bind(issued.hash.as_bytes().as_slice())
                    .bind(user.as_uuid())
                    .bind(SETUP_LINK_LIFETIME_SECS as f64)
                    .fetch_one(tx.conn())
                    .await?;
                    Outbox::append(
                        tx,
                        NewEvent {
                            tenant_id: Some(tenant),
                            event_type: "identity.setup_link.issued",
                            event_version: 1,
                            partition_key: user.into_uuid(),
                            payload: &SetupLinkIssued {
                                tenant_id: tenant,
                                user_id: user,
                                purpose: "first_admin",
                                revoked_previous: revoked,
                                via: VIA_CLI,
                            },
                        },
                    )
                    .await?;
                    Ok(IssuedSetupLink {
                        token: issued.token,
                        tenant_id: tenant,
                        user_id: user,
                        expires_at,
                        revoked_previous: revoked,
                    })
                })
            })
            .await?;
        Ok(r)
    }

    // ----- reads -----

    pub async fn tenant(&self, tenant: TenantId) -> AdminResult<Option<TenantRecord>> {
        let r = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    let row: Option<(Uuid, String, String, i64)> = sqlx::query_as(
                        "SELECT tenant_id, name, state, version FROM tenants WHERE tenant_id = $1",
                    )
                    .bind(tenant.as_uuid())
                    .fetch_optional(tx.conn())
                    .await?;
                    row.map(|(id, name, state, version)| {
                        Ok(TenantRecord {
                            tenant_id: ids(TenantId::from_uuid(id))?,
                            name,
                            state: TenantState::parse(&state)?,
                            version,
                        })
                    })
                    .transpose()
                })
            })
            .await?;
        Ok(r)
    }

    pub async fn user(&self, tenant: TenantId, user: UserId) -> AdminResult<Option<UserRecord>> {
        let r = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    let row: Option<(String, String, String, Option<String>, i64)> = sqlx::query_as(
                        "SELECT login, status, kind, display_name, version FROM users WHERE tenant_id = $1 AND user_id = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .fetch_optional(tx.conn())
                    .await?;
                    row.map(|(login, status, kind, display_name, version)| {
                        Ok(UserRecord {
                            tenant_id: tenant,
                            user_id: user,
                            login,
                            status: UserStatus::parse(&status)?,
                            kind: UserKind::parse(&kind)?,
                            display_name,
                            version,
                        })
                    })
                    .transpose()
                })
            })
            .await?;
        Ok(r)
    }

    pub async fn group(
        &self,
        tenant: TenantId,
        group: GroupId,
    ) -> AdminResult<Option<GroupRecord>> {
        let r = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    let row: Option<(String, i64)> = sqlx::query_as(
                        "SELECT name, membership_version FROM groups WHERE tenant_id = $1 AND group_id = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(group.as_uuid())
                    .fetch_optional(tx.conn())
                    .await?;
                    Ok(row.map(|(name, membership_version)| GroupRecord {
                        tenant_id: tenant,
                        group_id: group,
                        name,
                        membership_version,
                    }))
                })
            })
            .await?;
        Ok(r)
    }

    /// Direct members of a group, ordered by member ID.
    pub async fn members(&self, tenant: TenantId, group: GroupId) -> AdminResult<Vec<Member>> {
        let r = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    let rows: Vec<(Uuid, String)> = sqlx::query_as(
                        "SELECT member_id, member_kind FROM group_members WHERE tenant_id = $1 AND group_id = $2 ORDER BY member_id",
                    )
                    .bind(tenant.as_uuid())
                    .bind(group.as_uuid())
                    .fetch_all(tx.conn())
                    .await?;
                    rows.into_iter()
                        .map(|(id, kind)| Member::from_row(id, &kind))
                        .collect()
                })
            })
            .await?;
        Ok(r)
    }

    /// State and user of a setup link, looked up by the presented token's hash.
    pub async fn setup_link_state(
        &self,
        tenant: TenantId,
        hash: TokenHash,
    ) -> AdminResult<Option<(String, UserId)>> {
        let r = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    let row: Option<(String, Uuid)> = sqlx::query_as(
                        "SELECT state, user_id FROM setup_links WHERE tenant_id = $1 AND token_hash = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(hash.as_bytes().as_slice())
                    .fetch_optional(tx.conn())
                    .await?;
                    row.map(|(s, u)| Ok((s, ids(UserId::from_uuid(u))?)))
                        .transpose()
                })
            })
            .await?;
        Ok(r)
    }
}

/// Bump membership_version by compare-and-set and write the membership event.
async fn finish_membership_change(
    tx: &mut DomainTx,
    tenant: TenantId,
    group: GroupId,
    member: Member,
    version: i64,
    change: &str,
) -> Result<MembershipChange, DbError> {
    let new_version: Option<i64> = sqlx::query_scalar(
        "UPDATE groups SET membership_version = membership_version + 1, updated_at = now() \
         WHERE tenant_id = $1 AND group_id = $2 AND membership_version = $3 RETURNING membership_version",
    )
    .bind(tenant.as_uuid())
    .bind(group.as_uuid())
    .bind(version)
    .fetch_optional(tx.conn())
    .await?;
    // The tenant membership lock is held, so a concurrent bump cannot happen; a mismatch here
    // means an invariant broke.
    let new_version = new_version.ok_or_else(|| {
        DbError::Invalid("group membership_version changed under the tenant lock".into())
    })?;
    let event = Outbox::append(
        tx,
        NewEvent {
            tenant_id: Some(tenant),
            event_type: "identity.group.membership_changed",
            event_version: 1,
            partition_key: group.into_uuid(),
            payload: &MembershipChanged {
                tenant_id: tenant,
                group_id: group,
                member_id: member.id(),
                member_kind: member.kind(),
                change,
                membership_version: new_version,
                via: VIA_CLI,
            },
        },
    )
    .await?;
    Ok(MembershipChange {
        tenant_id: tenant,
        group_id: group,
        member,
        membership_version: new_version,
        event,
    })
}
