//! MFA after OPAQUE (contract §2.3, rev 10/11; spec §5.3).
//!
//! - A user "has MFA" when policy `mfa_required` = 1 (deployment default, overridable by the
//!   tenant in `tenants.policy`) or the user has at least one passkey.
//! - A successful OPAQUE `login/finish` for such a user returns
//!   `200 {state: "mfa_required", auth_txn, methods}` instead of a session. `auth_txn` is an
//!   `rt1` ceremony (`auth_ceremonies`, kind `mfa`, 5 min, single use, bound to the user and
//!   the sign-in source). `methods` ⊆ `["webauthn", "recovery_code"]`.
//! - It is completed by `webauthn/assert/{start,finish}` (see [`crate::webauthn`]) or
//!   `POST /api/v2/auth/mfa/recovery-code {auth_txn, code}`; both return the §2.4 result with
//!   `reregister` when due (rev 11 addendum), never on the `mfa_required` body.
//! - Policy requires MFA but the user has no passkey and no unused recovery code: an
//!   **enrolment-only session** (`scp: "mfa_enrolment"`, see [`crate::auth::enrolment_allowed`]).
//! - `amr` (RFC 8176): password only `["pwd"]`; password + passkey `["pwd", "hwk", "mfa"]`;
//!   password + recovery code `["pwd", "otp", "mfa"]`; passwordless passkey `["hwk", "user"]`
//!   (user verification is required by every ceremony).

use crate::admin::AdminResult as AuthResult;
use crate::auth::{
    AuthService, Authenticated, RequestCtx, dpop_proof_required, mfa_required_error,
    unauthenticated,
};
use crate::ceremony::{self, Kind};
use crate::idem::{Entry, IdemRequest, Out, Ran};
use crate::recovery;
use crate::session::{self, NewSession};
use crate::token;
use cs_common::id::{TenantId, UserId};
use cs_common::secret::Secret;
use cs_db::{DbError, DomainTx};
use std::collections::BTreeMap;

/// `methods` values (rev 11).
pub const METHOD_WEBAUTHN: &str = "webauthn";
pub const METHOD_RECOVERY_CODE: &str = "recovery_code";

/// Second factors of a user at sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Factors {
    pub required_by_policy: bool,
    pub passkeys: i64,
    pub unused_codes: i64,
}

/// What `login/finish` does after a correct password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No MFA: a normal session.
    Session,
    /// `mfa_required` with these methods.
    Challenge(Vec<&'static str>),
    /// Policy requires MFA and the user has no factor: enrolment-only session.
    Enrol,
}

impl Factors {
    pub fn has_mfa(&self) -> bool {
        self.required_by_policy || self.passkeys > 0
    }

    pub fn decision(&self) -> Decision {
        if !self.has_mfa() {
            return Decision::Session;
        }
        let mut m = Vec::new();
        if self.passkeys > 0 {
            m.push(METHOD_WEBAUTHN);
        }
        if self.unused_codes > 0 {
            m.push(METHOD_RECOVERY_CODE);
        }
        if m.is_empty() {
            Decision::Enrol
        } else {
            Decision::Challenge(m)
        }
    }
}

/// The tenant's `mfa_required` override from `tenants.policy` (deterministic CBOR map of
/// text → integer); `None` when absent or not 0/1.
pub fn tenant_override(policy_cbor: &[u8]) -> Option<bool> {
    let m: BTreeMap<String, i64> = cs_crypto::cbor::from_canonical(policy_cbor, 65536).ok()?;
    match m.get("mfa_required") {
        Some(0) => Some(false),
        Some(1) => Some(true),
        _ => None,
    }
}

/// Read the user's factors inside the caller's transaction.
pub async fn factors_in_tx(
    tx: &mut DomainTx,
    tenant: TenantId,
    user: UserId,
    deployment_default: bool,
) -> Result<Factors, DbError> {
    let (policy, passkeys, codes): (Vec<u8>, i64, i64) = sqlx::query_as(
        "SELECT t.policy, \
           (SELECT count(*) FROM webauthn_credentials w WHERE w.tenant_id = $1 AND w.user_id = $2), \
           (SELECT count(*) FROM recovery_code_entries r WHERE r.tenant_id = $1 AND r.user_id = $2 \
              AND r.used_at IS NULL) \
         FROM tenants t WHERE t.tenant_id = $1",
    )
    .bind(tenant.as_uuid())
    .bind(user.as_uuid())
    .fetch_one(tx.conn())
    .await?;
    Ok(Factors {
        required_by_policy: tenant_override(&policy).unwrap_or(deployment_default),
        passkeys,
        unused_codes: codes,
    })
}

/// Sealed state of an `mfa` ceremony: `[reregister]`.
pub(crate) fn mfa_state(reregister: bool) -> Vec<u8> {
    vec![u8::from(reregister)]
}

pub(crate) fn mfa_state_reregister(state: &[u8]) -> bool {
    state.first() == Some(&1)
}

enum Outcome {
    Ok(Box<session::NewTokens>, bool),
    Failed,
}

impl AuthService {
    /// `POST /api/v2/auth/mfa/recovery-code {auth_txn, code}` (rev 10): complete an MFA
    /// sign-in with an unused recovery code, which is used up. The code is verified (Argon2id)
    /// before the transaction; the transaction re-checks it unused (CAS), consumes the
    /// `auth_txn` and creates the session. A wrong code leaves the `auth_txn` usable until it
    /// expires (rate limits apply).
    pub async fn mfa_recovery_code(
        &self,
        auth_txn: &str,
        code: &str,
        source: &str,
        user_agent: Option<&str>,
        ctx: &RequestCtx<'_>,
        idem: Option<IdemRequest>,
    ) -> AuthResult<Out<Authenticated>> {
        let parsed = token::parse(auth_txn).map_err(|_| unauthenticated())?;
        let tenant = parsed.tenant_id;
        let jkt = self.proof_without_token(tenant, ctx).await?.map(|p| p.jkt);
        if self.policy.dpop_required && jkt.is_none() {
            return Err(dpop_proof_required());
        }
        let keys = self.keys().await?;
        // rev 16 P3: keyed by the auth_txn; checked before the (consumed) txn and code.
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
        // Who is signing in (not consumed yet).
        let (hash, k2) = (parsed.hash, keys.clone());
        let c = self
            .pool
            .read_snapshot(move |tx| {
                let k2 = k2.clone();
                Box::pin(async move { ceremony::peek(tx, &k2, tenant, &hash, Kind::Mfa).await })
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
        let code_id = self
            .verify_recovery_code(tenant, Some(user), code)
            .await?
            .ok_or_else(unauthenticated)?;
        let (policy, source, ua) = (
            self.policy,
            source.to_owned(),
            user_agent.map(str::to_owned),
        );
        let ran = crate::idem::run(
            &self.pool,
            idem.clone(),
            move |tx| {
                let (keys, source, ua, code_id) =
                    (keys.clone(), source.clone(), ua.clone(), code_id.clone());
                Box::pin(async move {
                    let Some(c) = ceremony::take(tx, &keys, tenant, &hash, Kind::Mfa).await? else {
                        return Ok(Outcome::Failed);
                    };
                    if c.source != source || c.user != Some(user.into_uuid()) {
                        return Ok(Outcome::Failed);
                    }
                    if !recovery::use_code_in_tx(tx, tenant, user, &code_id).await?
                        || !crate::webauthn::loginable_in_tx(tx, tenant, user).await?
                    {
                        // Roll back: the auth_txn stays usable, the code untouched.
                        return Err(DbError::app(unauthenticated().into_inner()));
                    }
                    let nt = session::create_session(
                        tx,
                        tenant,
                        user,
                        NewSession {
                            amr: vec!["pwd", "otp", "mfa"],
                            jkt,
                            scope: None,
                            user_agent: ua,
                        },
                        policy,
                    )
                    .await?;
                    Ok(Outcome::Ok(Box::new(nt), mfa_state_reregister(&c.state)))
                })
            },
            move |o| match o {
                Outcome::Ok(nt, rr) => crate::idem::session_entry(nt, &kid_enc, *rr),
                Outcome::Failed => Ok(Entry::unauthenticated()),
            },
        )
        .await?;
        let out = match ran {
            Ran::Fresh(o) => o,
            Ran::Replay(r) => return self.open_replay(idem.as_ref(), r, |a| a).await,
        };
        match out {
            Outcome::Ok(nt, reregister) => Ok(Out::Value(
                self.finish_tokens_with(&kid, *nt, reregister).await?,
            )),
            Outcome::Failed => Err(unauthenticated()),
        }
    }

    /// rev 11: a failure on an endpoint that takes an `rt1` token answers `mfa_required` when
    /// the token is a live MFA `auth_txn` presented to the wrong endpoint.
    pub(crate) async fn mfa_or(
        &self,
        token: &str,
        e: crate::admin::AdminError,
    ) -> crate::admin::AdminError {
        if ceremony::is_live_mfa(&self.pool, token).await {
            mfa_required_error()
        } else {
            e
        }
    }
}

/// The `mfa_required` result body pieces.
#[derive(Debug)]
pub struct MfaChallenge {
    pub auth_txn: Secret<String>,
    pub methods: Vec<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(p: bool, k: i64, c: i64) -> Factors {
        Factors {
            required_by_policy: p,
            passkeys: k,
            unused_codes: c,
        }
    }

    #[test]
    fn decision_table() {
        assert_eq!(f(false, 0, 0).decision(), Decision::Session);
        assert_eq!(f(false, 0, 5).decision(), Decision::Session);
        assert_eq!(
            f(false, 1, 0).decision(),
            Decision::Challenge(vec![METHOD_WEBAUTHN])
        );
        assert_eq!(
            f(true, 1, 3).decision(),
            Decision::Challenge(vec![METHOD_WEBAUTHN, METHOD_RECOVERY_CODE])
        );
        assert_eq!(
            f(true, 0, 3).decision(),
            Decision::Challenge(vec![METHOD_RECOVERY_CODE])
        );
        assert_eq!(f(true, 0, 0).decision(), Decision::Enrol);
    }

    #[test]
    fn tenant_override_reads_policy_map() {
        let enc = |m: BTreeMap<String, i64>| cs_crypto::cbor::to_canonical(&m).unwrap();
        assert_eq!(tenant_override(&enc(BTreeMap::new())), None);
        let mut m = BTreeMap::new();
        m.insert("mfa_required".to_owned(), 1);
        assert_eq!(tenant_override(&enc(m.clone())), Some(true));
        m.insert("mfa_required".to_owned(), 0);
        assert_eq!(tenant_override(&enc(m.clone())), Some(false));
        m.insert("mfa_required".to_owned(), 7);
        assert_eq!(tenant_override(&enc(m)), None);
        assert_eq!(tenant_override(b"garbage"), None);
    }
}
