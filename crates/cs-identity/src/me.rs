//! The caller's own sessions (contract §3, rev 10).
//!
//! - `GET /api/v2/me/sessions` → `{items: [{sid, created_at, last_seen_at, amr, user_agent,
//!   current}]}`: the active, unexpired sessions of the caller, bounded, not paginated.
//! - `DELETE /api/v2/me/sessions/{sid}` → `204`. The current session: logout semantics
//!   (`[R10]`, no step-up). Another session of the caller: step-up required, then revoked
//!   (generation bump, refresh family revoked, `identity.session.revoked`). A session of
//!   another user, or none, is `not_found`, the same as a missing one.

use crate::admin::AdminResult as AuthResult;
use crate::auth::AuthService;
use crate::jws::AccessClaims;
use crate::recovery::RFC3339;
use crate::session;
use cs_common::error::{Error, ErrorCode};
use cs_common::id::SessionId;
use serde::Serialize;
use uuid::Uuid;

/// Sessions listed per user.
pub const MAX_SESSIONS: i64 = 100;

/// One listed session.
#[derive(Debug, Serialize)]
pub struct SessionItem {
    pub sid: Uuid,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub amr: Vec<String>,
    pub user_agent: Option<String>,
    pub current: bool,
}

/// Which session `DELETE /me/sessions/{sid}` revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoked {
    /// The caller's own session (the response clears the refresh cookie).
    Current,
    Other,
}

impl AuthService {
    /// `GET /api/v2/me/sessions`.
    pub async fn sessions(&self, claims: &AccessClaims) -> AuthResult<Vec<SessionItem>> {
        let (tenant, user, current) = Self::subject(claims)?;
        type R = (Uuid, String, Option<String>, Vec<String>, Option<String>);
        let rows: Vec<R> = self
            .pool
            .read_snapshot(move |tx| {
                Box::pin(async move {
                    let q = format!(
                        "SELECT session_id, to_char(created_at AT TIME ZONE 'UTC', '{RFC3339}'), \
                           to_char(last_seen_at AT TIME ZONE 'UTC', '{RFC3339}'), amr, user_agent \
                         FROM sessions WHERE tenant_id = $1 AND user_id = $2 AND state = 'active' \
                           AND now() < idle_expires_at AND now() < absolute_expires_at \
                         ORDER BY created_at DESC LIMIT {MAX_SESSIONS}"
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
            .map(
                |(sid, created_at, last_seen_at, amr, user_agent)| SessionItem {
                    current: sid == current.into_uuid(),
                    sid,
                    created_at,
                    last_seen_at,
                    amr,
                    user_agent,
                },
            )
            .collect())
    }

    /// `DELETE /api/v2/me/sessions/{sid}`.
    pub async fn session_revoke(&self, claims: &AccessClaims, sid: &str) -> AuthResult<Revoked> {
        let (tenant, user, current) = Self::subject(claims)?;
        let not_found = || -> crate::admin::AdminError {
            Error::new(ErrorCode::NotFound)
                .with_detail("No such session.")
                .into()
        };
        let target = Uuid::parse_str(sid)
            .ok()
            .and_then(|u| SessionId::from_uuid(u).ok())
            .ok_or_else(not_found)?;
        if target == current {
            self.logout(claims).await?;
            return Ok(Revoked::Current);
        }
        self.require_step_up(claims).await?;
        let ok = self
            .pool
            .transaction(move |tx| {
                Box::pin(async move {
                    let mine: Option<bool> = sqlx::query_scalar(
                        "SELECT state = 'active' FROM sessions \
                         WHERE tenant_id = $1 AND session_id = $2 AND user_id = $3 FOR UPDATE",
                    )
                    .bind(tenant.as_uuid())
                    .bind(target.as_uuid())
                    .bind(user.as_uuid())
                    .fetch_optional(tx.conn())
                    .await?;
                    if mine != Some(true) {
                        return Ok(false);
                    }
                    session::revoke_session(tx, tenant, target, "user_revoked").await
                })
            })
            .await?;
        if ok {
            Ok(Revoked::Other)
        } else {
            Err(not_found())
        }
    }
}
