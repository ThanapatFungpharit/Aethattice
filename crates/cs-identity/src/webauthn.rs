//! WebAuthn passkeys (contract §2.2, rev 10/11; spec §5.3), with kanidm `webauthn-rs` 0.6.2.
//!
//! - Relying party: rp id = deployment domain, origin `https://<deployment domain>` (the web
//!   shell and the API share one origin, rev 8). Every ceremony requires user verification.
//! - Ceremony state (`PasskeyRegistration`, `DiscoverableAuthentication`,
//!   `PasskeyAuthentication`) is kept server-side in `auth_ceremonies` (see
//!   [`crate::ceremony`]): sealed, single use, 5 min, bound to the tenant and source and, as
//!   applicable, to the user, the session and its generation, or the MFA `auth_txn`.
//! - Endpoints (L3 JSON, binary base64url without padding; rev 10):
//!   - `webauthn/register/{start,finish}`: access token (DPoP when bound) and step-up; allowed
//!     on an enrolment-only session. Discoverable credentials are preferred
//!     (`residentKey: "preferred"`), and the PRF extension is requested so its support can be
//!     recorded (`prf_supported`, for the vault work of M9). The PRF output never reaches the
//!     server. `discoverable` comes from the `credProps` client extension.
//!   - `webauthn/login/{start,finish}`: passwordless sign-in with a discoverable credential;
//!     `login/start {tenant}` does no lookup at all, so it cannot reveal whether the tenant
//!     exists. The session gets `amr = ["hwk", "user"]`.
//!   - `webauthn/assert/{start,finish}`: the MFA second factor after OPAQUE (`{auth_txn}`,
//!     result §2.4 with `amr = ["pwd", "hwk", "mfa"]` and `reregister` when due), or step-up
//!     on the current session (access token; `204`, sets `last_strong_auth_at`).
//! - Sign counters: `webauthn-rs` refuses a counter that does not grow (when either side is
//!   non-zero); the finishing transaction repeats that check against the stored counter under
//!   the credential's row lock, so two concurrent assertions cannot both pass with one counter.

use crate::admin::AdminResult as AuthResult;
use crate::auth::{
    AuthService, Authenticated, CredentialsChanged, RequestCtx, dpop_proof_required, invalid,
    parse_tenant, unauthenticated,
};
use crate::ceremony::{self, Kind};
use crate::idem::{Entry, IdemRequest, Out, Ran, Reply};
use crate::jws::AccessClaims;
use crate::recovery::RFC3339;
use crate::session::{self, NewSession};
use crate::token::{self, TokenHash};
use crate::wire::{self, CeremonyField};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cs_common::error::{Error, ErrorCode};
use cs_common::id::{SessionId, TenantId, UserId};
use cs_common::secret::Secret;
use cs_db::outbox::{NewEvent, Outbox};
use cs_db::{DbError, DomainTx};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, Url, Webauthn, WebauthnBuilder,
};

/// Passkeys per user (bounded listing and `allowCredentials`).
pub const MAX_PASSKEYS: i64 = 32;

/// The relying party for `deployment_domain`; `None` if the domain is not a valid rp id.
pub fn relying_party(deployment_domain: &str) -> Option<Arc<Webauthn>> {
    let origin = Url::parse(&format!("https://{deployment_domain}")).ok()?;
    let w = WebauthnBuilder::new(deployment_domain, &origin)
        .ok()?
        .rp_name("Cloud System")
        .timeout(std::time::Duration::from_secs(
            u64::try_from(ceremony::WEBAUTHN_TTL_SECS).unwrap_or(300),
        ))
        .build()
        .ok()?;
    Some(Arc::new(w))
}

/// User active and tenant active, under a shared lock (sign-in re-check).
pub(crate) async fn loginable_in_tx(
    tx: &mut DomainTx,
    tenant: TenantId,
    user: UserId,
) -> Result<bool, DbError> {
    let ok: Option<bool> = sqlx::query_scalar(
        "SELECT u.status = 'active' AND t.state = 'active' FROM users u \
         JOIN tenants t ON t.tenant_id = u.tenant_id \
         WHERE u.tenant_id = $1 AND u.user_id = $2 FOR SHARE OF u",
    )
    .bind(tenant.as_uuid())
    .bind(user.as_uuid())
    .fetch_optional(tx.conn())
    .await?;
    Ok(ok == Some(true))
}

/// Session still active at `generation` (and not expired), under lock.
pub(crate) async fn session_live_in_tx(
    tx: &mut DomainTx,
    tenant: TenantId,
    user: UserId,
    session: SessionId,
    generation: i64,
) -> Result<bool, DbError> {
    let ok: Option<bool> = sqlx::query_scalar(
        "SELECT true FROM sessions WHERE tenant_id = $1 AND session_id = $2 AND user_id = $3 \
           AND state = 'active' AND generation = $4 \
           AND now() < idle_expires_at AND now() < absolute_expires_at FOR UPDATE",
    )
    .bind(tenant.as_uuid())
    .bind(session.as_uuid())
    .bind(user.as_uuid())
    .bind(generation)
    .fetch_optional(tx.conn())
    .await?;
    Ok(ok == Some(true))
}

fn webauthn_failed() -> crate::admin::AdminError {
    unauthenticated()
}

fn json_bytes<T: Serialize>(v: &T) -> AuthResult<Vec<u8>> {
    Ok(serde_json::to_vec(v).map_err(Error::internal)?)
}

/// A registered passkey as listed (`GET /api/v2/me/passkeys`) or returned by
/// `register/finish` (rev 10; timestamps RFC 3339 UTC).
#[derive(Debug, Serialize)]
pub struct PasskeyItem {
    pub id: String,
    pub label: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<Option<String>>,
    pub prf: bool,
}

/// Start of a ceremony: `{<txn>, public_key}`.
#[derive(Debug)]
pub struct CeremonyStart {
    pub txn: Secret<String>,
    pub public_key: Value,
}

#[derive(Serialize, Deserialize)]
struct RegState {
    generation: i64,
    reg: PasskeyRegistration,
}

#[derive(Serialize, Deserialize)]
enum AssertMode {
    /// MFA: the `auth_txn` (SHA-256) this assertion completes.
    Mfa { auth_txn_hash: Vec<u8> },
    /// Step-up of the session at this generation.
    StepUp { generation: i64 },
}

#[derive(Serialize, Deserialize)]
struct AssertState {
    mode: AssertMode,
    ast: PasskeyAuthentication,
}

/// Result of `webauthn/assert/finish`.
#[derive(Debug)]
pub enum AssertOutcome {
    /// MFA completed: the §2.4 result.
    Authenticated(Authenticated),
    /// Step-up: `last_strong_auth_at` set (`204`).
    SteppedUp,
}

/// The passkey row of a credential, locked.
struct CredRow {
    user: Uuid,
    passkey: Passkey,
    sign_count: i64,
}

async fn cred_for_update(
    tx: &mut DomainTx,
    tenant: TenantId,
    cred_id: &[u8],
) -> Result<Option<CredRow>, DbError> {
    let r: Option<(Uuid, Option<Vec<u8>>, i64)> = sqlx::query_as(
        "SELECT user_id, passkey_state, sign_count FROM webauthn_credentials \
         WHERE tenant_id = $1 AND credential_id = $2 FOR UPDATE",
    )
    .bind(tenant.as_uuid())
    .bind(cred_id)
    .fetch_optional(tx.conn())
    .await?;
    Ok(r.and_then(|(user, state, sign_count)| {
        let passkey = serde_json::from_slice(&state?).ok()?;
        Some(CredRow {
            user,
            passkey,
            sign_count,
        })
    }))
}

/// Apply a verified assertion to the stored credential: the counter must grow when either
/// side is non-zero (re-checked under lock), then counter, state and `last_used_at` are saved.
async fn record_use(
    tx: &mut DomainTx,
    tenant: TenantId,
    cred_id: &[u8],
    mut row: CredRow,
    res: &webauthn_rs::prelude::AuthenticationResult,
) -> Result<bool, DbError> {
    let counter = i64::from(res.counter());
    if (counter > 0 || row.sign_count > 0) && counter <= row.sign_count {
        return Ok(false);
    }
    row.passkey.update_credential(res);
    let state = serde_json::to_vec(&row.passkey).map_err(|e| DbError::Invalid(e.to_string()))?;
    sqlx::query(
        "UPDATE webauthn_credentials SET sign_count = $3, passkey_state = $4, \
           last_used_at = now(), version = version + 1 \
         WHERE tenant_id = $1 AND credential_id = $2",
    )
    .bind(tenant.as_uuid())
    .bind(cred_id)
    .bind(counter)
    .bind(state)
    .execute(tx.conn())
    .await?;
    Ok(true)
}

enum Finish {
    Ok(Box<session::NewTokens>, bool),
    SteppedUp,
    Failed,
}

/// What a WebAuthn finish stores (contract rev 15/16): the sealed §2.4 envelope, an empty
/// `204` for a step-up, or the committed failure.
fn finish_entry(o: &Finish, kid: &cs_crypto::sig::KeyId) -> Result<Entry, DbError> {
    match o {
        Finish::Ok(nt, rr) => crate::idem::session_entry(nt, kid, *rr),
        Finish::SteppedUp => Ok(Entry::plain(wire::no_content(false))),
        Finish::Failed => Ok(Entry::unauthenticated()),
    }
}

impl AuthService {
    fn rp(&self) -> AuthResult<Arc<Webauthn>> {
        self.webauthn
            .clone()
            .ok_or_else(|| Error::new(ErrorCode::Internal).into())
    }

    /// The user's passkeys (bounded).
    async fn passkeys_of(&self, tenant: TenantId, user: UserId) -> AuthResult<Vec<Passkey>> {
        let rows: Vec<Option<Vec<u8>>> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar(
                        "SELECT passkey_state FROM webauthn_credentials \
                         WHERE tenant_id = $1 AND user_id = $2 ORDER BY credential_id LIMIT $3",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .bind(MAX_PASSKEYS)
                    .fetch_all(tx.conn())
                    .await?)
                })
            })
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|s| serde_json::from_slice(&s?).ok())
            .collect())
    }

    /// `webauthn/register/start {}` (access token, step-up; rev 10).
    pub async fn webauthn_register_start(
        &self,
        claims: &AccessClaims,
        source: &str,
        idem: Option<IdemRequest>,
    ) -> AuthResult<Out<CeremonyStart>> {
        let (tenant, user, session) = Self::subject(claims)?;
        let keys = self.keys().await?;
        let idem = self.bind_idem(idem, tenant, || crate::idem::user_principal(user), &keys)?;
        if let Some(r) = self.early(idem.as_ref()).await? {
            return Ok(r);
        }
        self.require_step_up(claims).await?;
        let rp = self.rp()?;
        self.sweep();
        let (login, display): (String, Option<String>) = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    Ok(sqlx::query_as(
                        "SELECT login, display_name FROM users WHERE tenant_id = $1 AND user_id = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .fetch_one(tx.conn())
                    .await?)
                })
            })
            .await?;
        let existing = self.passkeys_of(tenant, user).await?;
        if i64::try_from(existing.len()).unwrap_or(i64::MAX) >= MAX_PASSKEYS {
            return Err(invalid("", "passkey limit reached"));
        }
        let exclude = existing.iter().map(|p| p.cred_id().clone()).collect();
        let (ccr, reg) = rp
            .start_passkey_registration(
                user.into_uuid(),
                &login,
                display.as_deref().unwrap_or(&login),
                Some(exclude),
            )
            .map_err(Error::internal)?;
        let mut v = serde_json::to_value(&ccr).map_err(Error::internal)?;
        let mut pk = v
            .get_mut("publicKey")
            .map(Value::take)
            .ok_or_else(|| Error::new(ErrorCode::Internal))?;
        // Prefer discoverable credentials (passwordless sign-in) and ask for PRF support.
        if let Some(sel) = pk
            .get_mut("authenticatorSelection")
            .and_then(Value::as_object_mut)
        {
            sel.insert("residentKey".into(), Value::from("preferred"));
            sel.insert("requireResidentKey".into(), Value::from(false));
        }
        if let Some(ext) = pk.get_mut("extensions").and_then(Value::as_object_mut) {
            ext.insert("prf".into(), serde_json::json!({}));
        }
        let state = zeroize::Zeroizing::new(json_bytes(&RegState {
            generation: claims.sgen,
            reg,
        })?);
        let pk2 = pk.clone();
        let ran = ceremony::insert(
            &self.pool,
            keys,
            tenant,
            Kind::WebauthnReg,
            source,
            Some(user),
            Some(session),
            state,
            idem.clone(),
            move |txn| {
                wire::ceremony_start(
                    CeremonyField::Registration,
                    &CeremonyStart {
                        txn: txn.clone(),
                        public_key: pk2.clone(),
                    },
                )
            },
        )
        .await?;
        self.ran_plain(idem.as_ref(), ran, |txn| CeremonyStart {
            txn,
            public_key: pk,
        })
    }

    /// `webauthn/register/finish {registration_txn, credential, label}` → the new passkey.
    pub async fn webauthn_register_finish(
        &self,
        claims: &AccessClaims,
        registration_txn: &str,
        credential: &Value,
        label: &str,
        source: &str,
        idem: Option<IdemRequest>,
    ) -> AuthResult<Out<PasskeyItem>> {
        let (tenant, user, session) = Self::subject(claims)?;
        let label = label.trim().to_owned();
        if label.is_empty() || label.chars().count() > 100 {
            return Err(invalid("/label", "label must be 1-100 characters"));
        }
        let parsed = token::parse(registration_txn).map_err(|_| unauthenticated())?;
        if parsed.tenant_id != tenant {
            return Err(unauthenticated());
        }
        let cred: RegisterPublicKeyCredential = serde_json::from_value(credential.clone())
            .map_err(|_| invalid("/credential", "malformed credential"))?;
        let ext = credential.get("clientExtensionResults");
        let prf = ext
            .and_then(|e| e.pointer("/prf/enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let discoverable = ext
            .and_then(|e| e.pointer("/credProps/rk"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let transports: Vec<String> = credential
            .pointer("/response/transports")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .take(8)
                    .map(|s| s.chars().take(32).collect())
                    .collect()
            })
            .unwrap_or_default();
        let rp = self.rp()?;
        let keys = self.keys().await?;
        let idem = self.bind_idem(idem, tenant, || crate::idem::user_principal(user), &keys)?;
        if let Some(r) = self.early(idem.as_ref()).await? {
            return Ok(r);
        }
        let (hash, source, sgen) = (parsed.hash, source.to_owned(), claims.sgen);
        let ran = crate::idem::run(
            &self.pool,
            idem.clone(),
            move |tx| {
                let (keys, rp, cred, source, label, transports) = (
                    keys.clone(),
                    rp.clone(),
                    cred.clone(),
                    source.clone(),
                    label.clone(),
                    transports.clone(),
                );
                Box::pin(async move {
                    let Some(c) =
                        ceremony::take(tx, &keys, tenant, &hash, Kind::WebauthnReg).await?
                    else {
                        return Ok(None);
                    };
                    if c.source != source
                        || c.user != Some(user.into_uuid())
                        || c.session != Some(session.into_uuid())
                    {
                        return Ok(None);
                    }
                    let Ok(st) = serde_json::from_slice::<RegState>(&c.state) else {
                        return Ok(None);
                    };
                    if st.generation != sgen
                        || !session_live_in_tx(tx, tenant, user, session, sgen).await?
                    {
                        return Ok(None);
                    }
                    let Ok(passkey) = rp.finish_passkey_registration(&cred, &st.reg) else {
                        return Ok(None);
                    };
                    let cred_id = passkey.cred_id().to_vec();
                    let public_key = serde_json::to_vec(passkey.get_public_key())
                        .map_err(|e| DbError::Invalid(e.to_string()))?;
                    let state = serde_json::to_vec(&passkey)
                        .map_err(|e| DbError::Invalid(e.to_string()))?;
                    let taken: Option<bool> = sqlx::query_scalar(
                        "SELECT true FROM webauthn_credentials WHERE tenant_id = $1 AND credential_id = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(&cred_id)
                    .fetch_optional(tx.conn())
                    .await?;
                    if taken.is_some() {
                        return Err(DbError::app(
                            Error::new(ErrorCode::Conflict)
                                .with_detail("This passkey is already registered."),
                        ));
                    }
                    let q = format!(
                        "INSERT INTO webauthn_credentials (tenant_id, user_id, credential_id, \
                           public_key, sign_count, transports, discoverable, prf_supported, version, \
                           label, passkey_state) \
                         VALUES ($1, $2, $3, $4, 0, $5, $6, $7, 1, $8, $9) \
                         RETURNING to_char(created_at AT TIME ZONE 'UTC', '{RFC3339}')"
                    );
                    let created_at: String = sqlx::query_scalar(sqlx::AssertSqlSafe(q))
                        .bind(tenant.as_uuid())
                        .bind(user.as_uuid())
                        .bind(&cred_id)
                        .bind(public_key)
                        .bind(&transports)
                        .bind(discoverable)
                        .bind(prf)
                        .bind(&label)
                        .bind(state)
                        .fetch_one(tx.conn())
                        .await?;
                    Outbox::append(
                        tx,
                        NewEvent {
                            tenant_id: Some(tenant),
                            event_type: "identity.credentials.changed",
                            event_version: 1,
                            partition_key: user.into_uuid(),
                            payload: &CredentialsChanged {
                                tenant_id: tenant,
                                user_id: user,
                                method: "webauthn",
                                reason: "passkey_added",
                            },
                        },
                    )
                    .await?;
                    Ok(Some(PasskeyItem {
                        id: URL_SAFE_NO_PAD.encode(&cred_id),
                        label: Some(label),
                        created_at,
                        last_used_at: None,
                        prf,
                    }))
                })
            },
            |o: &Option<PasskeyItem>| match o {
                Some(p) => Ok(Entry::plain(Reply::json(200, p)?)),
                None => Ok(Entry::unauthenticated()),
            },
        )
        .await?;
        match self.ran_plain(idem.as_ref(), ran, |o| o)? {
            Out::Value(Some(p)) => Ok(Out::Value(p)),
            Out::Value(None) => Err(webauthn_failed()),
            Out::Reply(r) => Ok(Out::Reply(r)),
        }
    }

    /// `webauthn/login/start {tenant}` → discoverable request options (empty
    /// `allowCredentials`). No lookup: the response never depends on the tenant existing.
    pub async fn webauthn_login_start(
        &self,
        tenant: &str,
        source: &str,
        idem: Option<IdemRequest>,
    ) -> AuthResult<Out<CeremonyStart>> {
        let tenant_id = parse_tenant(tenant)?;
        self.limit("webauthn_login", source, Some(tenant), None)
            .await?;
        let rp = self.rp()?;
        let keys = self.keys().await?;
        // rev 16 P3: principal H(route ‖ tenant).
        let idem = self.bind_idem(
            idem,
            tenant_id,
            || crate::idem::start_principal(crate::idem::ROUTE_WEBAUTHN_LOGIN_START, tenant_id, ""),
            &keys,
        )?;
        if let Some(r) = self.early(idem.as_ref()).await? {
            return Ok(r);
        }
        self.sweep();
        let (rcr, st) = rp
            .start_discoverable_authentication()
            .map_err(Error::internal)?;
        let state = zeroize::Zeroizing::new(json_bytes(&st)?);
        let public_key = serde_json::to_value(&rcr.public_key).map_err(Error::internal)?;
        let pk2 = public_key.clone();
        let ran = ceremony::insert(
            &self.pool,
            keys,
            tenant_id,
            Kind::WebauthnLogin,
            source,
            None,
            None,
            state,
            idem.clone(),
            move |txn| {
                wire::ceremony_start(
                    CeremonyField::Login,
                    &CeremonyStart {
                        txn: txn.clone(),
                        public_key: pk2.clone(),
                    },
                )
            },
        )
        .await?;
        self.ran_plain(idem.as_ref(), ran, |txn| CeremonyStart { txn, public_key })
    }

    /// `webauthn/login/finish {login_txn, credential}` → §2.4 (DPoP as for OPAQUE).
    pub async fn webauthn_login_finish(
        &self,
        login_txn: &str,
        credential: &Value,
        source: &str,
        user_agent: Option<&str>,
        ctx: &RequestCtx<'_>,
        idem: Option<IdemRequest>,
    ) -> AuthResult<Out<Authenticated>> {
        let parsed = token::parse(login_txn).map_err(|_| unauthenticated())?;
        let tenant = parsed.tenant_id;
        self.limit(
            "webauthn_login",
            source,
            Some(&tenant.as_uuid().to_string()),
            None,
        )
        .await?;
        let jkt = self.proof_without_token(tenant, ctx).await?.map(|p| p.jkt);
        if self.policy.dpop_required && jkt.is_none() {
            return Err(dpop_proof_required());
        }
        let cred: PublicKeyCredential = serde_json::from_value(credential.clone())
            .map_err(|_| invalid("/credential", "malformed credential"))?;
        let rp = self.rp()?;
        let keys = self.keys().await?;
        let idem = self.bind_idem(
            idem,
            tenant,
            || crate::idem::token_principal(&parsed.hash),
            &keys,
        )?;
        if let Some(r) = self.early_replay(idem.as_ref(), |a| a).await? {
            return Ok(r);
        }
        let kid = self.signing_kid().await?;
        let kid_enc = kid.clone();
        let (hash, source, policy) = (parsed.hash, source.to_owned(), self.policy);
        let ua = user_agent.map(str::to_owned);
        let ran = crate::idem::run(
            &self.pool,
            idem.clone(),
            move |tx| {
                let (keys, rp, cred, source, ua) = (
                    keys.clone(),
                    rp.clone(),
                    cred.clone(),
                    source.clone(),
                    ua.clone(),
                );
                Box::pin(async move {
                    let Some(c) =
                        ceremony::take(tx, &keys, tenant, &hash, Kind::WebauthnLogin).await?
                    else {
                        return Ok(Finish::Failed);
                    };
                    if c.source != source {
                        return Ok(Finish::Failed);
                    }
                    let Ok(st) = serde_json::from_slice::<DiscoverableAuthentication>(&c.state)
                    else {
                        return Ok(Finish::Failed);
                    };
                    let Ok((uid, cred_id)) = rp.identify_discoverable_authentication(&cred) else {
                        return Ok(Finish::Failed);
                    };
                    let cred_id = cred_id.to_vec();
                    let Some(row) = cred_for_update(tx, tenant, &cred_id).await? else {
                        return Ok(Finish::Failed);
                    };
                    if row.user != uid {
                        return Ok(Finish::Failed);
                    }
                    let Ok(user) = UserId::from_uuid(uid) else {
                        return Ok(Finish::Failed);
                    };
                    let Ok(res) = rp.finish_discoverable_authentication_v2(&cred, st, &row.passkey)
                    else {
                        return Ok(Finish::Failed);
                    };
                    if !res.user_verified()
                        || !record_use(tx, tenant, &cred_id, row, &res).await?
                        || !loginable_in_tx(tx, tenant, user).await?
                    {
                        return Ok(Finish::Failed);
                    }
                    let nt = session::create_session(
                        tx,
                        tenant,
                        user,
                        NewSession {
                            amr: vec!["hwk", "user"],
                            jkt,
                            scope: None,
                            user_agent: ua,
                        },
                        policy,
                    )
                    .await?;
                    Ok(Finish::Ok(Box::new(nt), false))
                })
            },
            move |o| finish_entry(o, &kid_enc),
        )
        .await?;
        let out = match ran {
            Ran::Fresh(o) => o,
            Ran::Replay(r) => return self.open_replay(idem.as_ref(), r, |a| a).await,
        };
        match out {
            Finish::Ok(nt, _) => Ok(Out::Value(self.finish_tokens_with(&kid, *nt, false).await?)),
            _ => Err(self.mfa_or(login_txn, webauthn_failed()).await),
        }
    }

    /// `webauthn/assert/start {auth_txn}` (MFA after OPAQUE; the `auth_txn` is not consumed
    /// here) or `{}` with the access token (step-up of the current session).
    pub async fn webauthn_assert_start(
        &self,
        auth_txn: Option<&str>,
        claims: Option<&AccessClaims>,
        source: &str,
        idem: Option<IdemRequest>,
    ) -> AuthResult<Out<CeremonyStart>> {
        let rp = self.rp()?;
        let keys = self.keys().await?;
        self.sweep();
        // rev 16 P3: MFA keyed by the auth_txn, step-up by the user.
        let idem = match (auth_txn, claims) {
            (Some(t), None) => {
                let p = token::parse(t).map_err(|_| unauthenticated())?;
                self.bind_idem(
                    idem,
                    p.tenant_id,
                    || crate::idem::token_principal(&p.hash),
                    &keys,
                )?
            }
            (None, Some(c)) => {
                let (tenant, user, _) = Self::subject(c)?;
                self.bind_idem(idem, tenant, || crate::idem::user_principal(user), &keys)?
            }
            _ => None,
        };
        if let Some(r) = self.early(idem.as_ref()).await? {
            return Ok(r);
        }
        let (tenant, user, session, mode) = match (auth_txn, claims) {
            (Some(t), None) => {
                let p = token::parse(t).map_err(|_| unauthenticated())?;
                let (tenant, hash, k2) = (p.tenant_id, p.hash, keys.clone());
                let c = self
                    .pool
                    .read_snapshot(move |tx| {
                        let k2 = k2.clone();
                        Box::pin(
                            async move { ceremony::peek(tx, &k2, tenant, &hash, Kind::Mfa).await },
                        )
                    })
                    .await?
                    .ok_or_else(unauthenticated)?;
                if c.source != source {
                    return Err(unauthenticated());
                }
                let user = c
                    .user
                    .and_then(|u| UserId::from_uuid(u).ok())
                    .ok_or_else(unauthenticated)?;
                let mode = AssertMode::Mfa {
                    auth_txn_hash: hash.as_bytes().to_vec(),
                };
                (tenant, user, None, mode)
            }
            (None, Some(c)) => {
                let (tenant, user, session) = Self::subject(c)?;
                let mode = AssertMode::StepUp { generation: c.sgen };
                (tenant, user, Some(session), mode)
            }
            _ => {
                return Err(invalid(
                    "/auth_txn",
                    "send auth_txn without an access token (MFA), or an access token without auth_txn (step-up)",
                ));
            }
        };
        let passkeys = self.passkeys_of(tenant, user).await?;
        if passkeys.is_empty() {
            return Err(unauthenticated());
        }
        let (rcr, ast) = rp
            .start_passkey_authentication(&passkeys)
            .map_err(Error::internal)?;
        let state = zeroize::Zeroizing::new(json_bytes(&AssertState { mode, ast })?);
        let public_key = serde_json::to_value(&rcr.public_key).map_err(Error::internal)?;
        let pk2 = public_key.clone();
        let ran = ceremony::insert(
            &self.pool,
            keys,
            tenant,
            Kind::WebauthnAssert,
            source,
            Some(user),
            session,
            state,
            idem.clone(),
            move |txn| {
                wire::ceremony_start(
                    CeremonyField::Assert,
                    &CeremonyStart {
                        txn: txn.clone(),
                        public_key: pk2.clone(),
                    },
                )
            },
        )
        .await?;
        self.ran_plain(idem.as_ref(), ran, |txn| CeremonyStart { txn, public_key })
    }

    /// `webauthn/assert/finish {assert_txn, credential}`: §2.4 for MFA (DPoP as for OPAQUE),
    /// `204` for step-up (access token required, same session and generation).
    #[allow(clippy::too_many_arguments)]
    pub async fn webauthn_assert_finish(
        &self,
        assert_txn: &str,
        credential: &Value,
        claims: Option<&AccessClaims>,
        source: &str,
        user_agent: Option<&str>,
        ctx: &RequestCtx<'_>,
        idem: Option<IdemRequest>,
    ) -> AuthResult<Out<AssertOutcome>> {
        let parsed = token::parse(assert_txn).map_err(|_| unauthenticated())?;
        let tenant = parsed.tenant_id;
        let subject = claims.map(Self::subject).transpose()?;
        let sgen = claims.map(|c| c.sgen);
        if subject.is_some_and(|(t, _, _)| t != tenant) {
            return Err(unauthenticated());
        }
        // MFA completion signs in: optional (or required by policy) DPoP proof as at login.
        let jkt = if claims.is_none() {
            let j = self.proof_without_token(tenant, ctx).await?.map(|p| p.jkt);
            if self.policy.dpop_required && j.is_none() {
                return Err(dpop_proof_required());
            }
            j
        } else {
            None
        };
        let cred: PublicKeyCredential = serde_json::from_value(credential.clone())
            .map_err(|_| invalid("/credential", "malformed credential"))?;
        let rp = self.rp()?;
        let keys = self.keys().await?;
        let idem = self.bind_idem(
            idem,
            tenant,
            || crate::idem::token_principal(&parsed.hash),
            &keys,
        )?;
        if let Some(r) = self
            .early_replay(idem.as_ref(), AssertOutcome::Authenticated)
            .await?
        {
            return Ok(r);
        }
        let kid = self.signing_kid().await?;
        let kid_enc = kid.clone();
        let (hash, source, policy) = (parsed.hash, source.to_owned(), self.policy);
        let ua = user_agent.map(str::to_owned);
        let ran = crate::idem::run(
            &self.pool,
            idem.clone(),
            move |tx| {
                let (keys, rp, cred, source, ua) = (
                    keys.clone(),
                    rp.clone(),
                    cred.clone(),
                    source.clone(),
                    ua.clone(),
                );
                Box::pin(async move {
                    let Some(c) =
                        ceremony::take(tx, &keys, tenant, &hash, Kind::WebauthnAssert).await?
                    else {
                        return Ok(Finish::Failed);
                    };
                    let Some(user) = c.user.and_then(|u| UserId::from_uuid(u).ok()) else {
                        return Ok(Finish::Failed);
                    };
                    let Ok(st) = serde_json::from_slice::<AssertState>(&c.state) else {
                        return Ok(Finish::Failed);
                    };
                    if c.source != source {
                        return Ok(Finish::Failed);
                    }
                    // Mode and caller must agree: MFA without a token, step-up with the token
                    // of the same session and generation.
                    match (&st.mode, subject) {
                        (AssertMode::Mfa { .. }, None) => {}
                        (AssertMode::StepUp { generation }, Some((_, u, s)))
                            if u == user
                                && c.session == Some(s.into_uuid())
                                && Some(*generation) == sgen => {}
                        _ => return Ok(Finish::Failed),
                    }
                    let Ok(res) = rp.finish_passkey_authentication(&cred, &st.ast) else {
                        return Ok(Finish::Failed);
                    };
                    let cred_id = res.cred_id().clone();
                    let Some(row) = cred_for_update(tx, tenant, &cred_id).await? else {
                        return Ok(Finish::Failed);
                    };
                    if row.user != user.into_uuid()
                        || !res.user_verified()
                        || !record_use(tx, tenant, &cred_id, row, &res).await?
                    {
                        return Ok(Finish::Failed);
                    }
                    match st.mode {
                        AssertMode::Mfa { auth_txn_hash } => {
                            let Ok(h) = <[u8; 32]>::try_from(auth_txn_hash.as_slice()) else {
                                return Ok(Finish::Failed);
                            };
                            let mfa_hash = TokenHash::from_bytes(h);
                            let Some(m) =
                                ceremony::take(tx, &keys, tenant, &mfa_hash, Kind::Mfa).await?
                            else {
                                return Ok(Finish::Failed);
                            };
                            if m.user != Some(user.into_uuid())
                                || m.source != source
                                || !loginable_in_tx(tx, tenant, user).await?
                            {
                                return Ok(Finish::Failed);
                            }
                            let nt = session::create_session(
                                tx,
                                tenant,
                                user,
                                NewSession {
                                    amr: vec!["pwd", "hwk", "mfa"],
                                    jkt,
                                    scope: None,
                                    user_agent: ua,
                                },
                                policy,
                            )
                            .await?;
                            Ok(Finish::Ok(
                                Box::new(nt),
                                crate::mfa::mfa_state_reregister(&m.state),
                            ))
                        }
                        AssertMode::StepUp { generation } => {
                            let Some(s) = c.session.and_then(|s| SessionId::from_uuid(s).ok())
                            else {
                                return Ok(Finish::Failed);
                            };
                            if !session_live_in_tx(tx, tenant, user, s, generation).await? {
                                return Ok(Finish::Failed);
                            }
                            sqlx::query(
                                "UPDATE sessions SET last_strong_auth_at = now(), \
                                   version = version + 1, updated_at = now() \
                                 WHERE tenant_id = $1 AND session_id = $2",
                            )
                            .bind(tenant.as_uuid())
                            .bind(s.as_uuid())
                            .execute(tx.conn())
                            .await?;
                            Ok(Finish::SteppedUp)
                        }
                    }
                })
            },
            move |o| finish_entry(o, &kid_enc),
        )
        .await?;
        let out = match ran {
            Ran::Fresh(o) => o,
            Ran::Replay(r) => {
                return self
                    .open_replay(idem.as_ref(), r, AssertOutcome::Authenticated)
                    .await;
            }
        };
        match out {
            Finish::Ok(nt, reregister) => Ok(Out::Value(AssertOutcome::Authenticated(
                self.finish_tokens_with(&kid, *nt, reregister).await?,
            ))),
            Finish::SteppedUp => Ok(Out::Value(AssertOutcome::SteppedUp)),
            Finish::Failed => Err(self.mfa_or(assert_txn, webauthn_failed()).await),
        }
    }

    /// `GET /api/v2/me/passkeys` (rev 10).
    pub async fn passkeys(&self, claims: &AccessClaims) -> AuthResult<Vec<PasskeyItem>> {
        let (tenant, user, _) = Self::subject(claims)?;
        type R = (Vec<u8>, Option<String>, String, Option<String>, bool);
        let rows: Vec<R> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    let q = format!(
                        "SELECT credential_id, label, to_char(created_at AT TIME ZONE 'UTC', '{RFC3339}'), \
                           to_char(last_used_at AT TIME ZONE 'UTC', '{RFC3339}'), prf_supported \
                         FROM webauthn_credentials WHERE tenant_id = $1 AND user_id = $2 \
                         ORDER BY created_at LIMIT {MAX_PASSKEYS}"
                    );
                    Ok(sqlx::query_as(sqlx::AssertSqlSafe(q))
                        .bind(tenant.as_uuid())
                        .bind(user.as_uuid())
                        .fetch_all(tx.conn())
                        .await?)
                })
            })
            .await?;
        Ok(rows
            .into_iter()
            .map(|(id, label, created_at, last_used_at, prf)| PasskeyItem {
                id: URL_SAFE_NO_PAD.encode(id),
                label,
                created_at,
                last_used_at: Some(last_used_at),
                prf,
            })
            .collect())
    }

    /// `DELETE /api/v2/me/passkeys/{id}` (step-up). 404 unless it is the caller's passkey.
    pub async fn passkey_delete(
        &self,
        claims: &AccessClaims,
        id: &str,
        idem: Option<IdemRequest>,
    ) -> AuthResult<Out<()>> {
        let (tenant, user, _) = Self::subject(claims)?;
        let idem = match idem {
            Some(_) => {
                let keys = self.keys().await?;
                self.bind_idem(idem, tenant, || crate::idem::user_principal(user), &keys)?
            }
            None => None,
        };
        if let Some(r) = self.early(idem.as_ref()).await? {
            return Ok(r);
        }
        self.require_step_up(claims).await?;
        let not_found = || -> crate::admin::AdminError {
            Error::new(ErrorCode::NotFound)
                .with_detail("No such passkey.")
                .into()
        };
        let cred_id = URL_SAFE_NO_PAD.decode(id).map_err(|_| not_found())?;
        let ran = crate::idem::run(
            &self.pool,
            idem.clone(),
            move |tx| {
                let cred_id = cred_id.clone();
                Box::pin(async move {
                    let n = sqlx::query(
                        "DELETE FROM webauthn_credentials \
                         WHERE tenant_id = $1 AND user_id = $2 AND credential_id = $3",
                    )
                    .bind(tenant.as_uuid())
                    .bind(user.as_uuid())
                    .bind(&cred_id)
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    if n == 1 {
                        Outbox::append(
                            tx,
                            NewEvent {
                                tenant_id: Some(tenant),
                                event_type: "identity.credentials.changed",
                                event_version: 1,
                                partition_key: user.into_uuid(),
                                payload: &CredentialsChanged {
                                    tenant_id: tenant,
                                    user_id: user,
                                    method: "webauthn",
                                    reason: "passkey_removed",
                                },
                            },
                        )
                        .await?;
                    }
                    Ok(n)
                })
            },
            |n| {
                Ok(if *n == 1 {
                    Entry::plain(wire::no_content(false))
                } else {
                    Entry::Failed {
                        status: 404,
                        code: ErrorCode::NotFound,
                    }
                })
            },
        )
        .await?;
        match self.ran_plain(idem.as_ref(), ran, |n| n)? {
            Out::Value(1) => Ok(Out::Value(())),
            Out::Value(_) => Err(not_found()),
            Out::Reply(r) => Ok(Out::Reply(r)),
        }
    }
}
