//! Appendix D error model (contract §2).
//!
//! - [`ErrorCode`] is exactly table D.2.
//! - [`Code`] adds application codes `app.{application_id}.{code}`, each mapped to a D.2 status.
//! - HTTP status and `retryable` are derived from the code and cannot be set independently.
//! - [`Error`] is the platform error value. Its `detail` must be safe for the caller; the
//!   internal cause is kept separately and is never serialized.
//! - [`ProblemDocument`] is the RFC 9457 `application/problem+json` body.

use crate::app_id::ApplicationId;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error as ThisError;

/// Media type of every error response.
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// Generic detail used for internal errors (never the cause).
pub const INTERNAL_DETAIL: &str =
    "An unexpected error occurred. Quote the request_id when contacting support.";

macro_rules! codes {
    ($($variant:ident => $wire:literal, $status:literal, $retryable:literal, $title:literal;)*) => {
        /// Table D.2. Wire values are the snake_case strings.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum ErrorCode { $($variant,)* }

        impl ErrorCode {
            /// Every code of table D.2, in table order.
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$variant,)*];

            pub const fn as_str(self) -> &'static str {
                match self { $(ErrorCode::$variant => $wire,)* }
            }

            /// HTTP status from table D.2.
            pub const fn status(self) -> u16 {
                match self { $(ErrorCode::$variant => $status,)* }
            }

            /// Retryability from table D.2.
            pub const fn retryable(self) -> bool {
                match self { $(ErrorCode::$variant => $retryable,)* }
            }

            /// Short, stable, human-readable summary (English; clients localize by `code`).
            pub const fn title(self) -> &'static str {
                match self { $(ErrorCode::$variant => $title,)* }
            }
        }

        impl FromStr for ErrorCode {
            type Err = CodeParseError;
            fn from_str(s: &str) -> Result<Self, CodeParseError> {
                match s { $($wire => Ok(ErrorCode::$variant),)* _ => Err(CodeParseError) }
            }
        }
    };
}

codes! {
    InvalidRequest       => "invalid_request",        400, false, "Invalid request";
    Unauthenticated      => "unauthenticated",        401, false, "Authentication required";
    PermissionDenied     => "permission_denied",      403, false, "Permission denied";
    NotFound             => "not_found",              404, false, "Not found";
    MethodNotAllowed     => "method_not_allowed",     405, false, "Method not allowed";
    Conflict             => "conflict",               409, false, "Conflict";
    ResourceTrashed      => "resource_trashed",       409, false, "Resource is in the trash";
    PreconditionFailed   => "precondition_failed",    412, false, "Precondition failed";
    PayloadTooLarge      => "payload_too_large",      413, false, "Payload too large";
    UnsupportedMediaType => "unsupported_media_type", 415, false, "Unsupported media type";
    IdempotencyMismatch  => "idempotency_mismatch",   422, false, "Idempotency key reused with a different request";
    Locked               => "locked",                 423, false, "Locked";
    RateLimited          => "rate_limited",           429, true,  "Rate limited";
    QuotaExceeded        => "quota_exceeded",         507, false, "Quota exceeded";
    Internal             => "internal",               500, true,  "Internal error";
    DependencyUnavailable=> "dependency_unavailable", 503, true,  "Dependency unavailable";
    Unavailable          => "unavailable",            503, true,  "Service unavailable";
    Timeout              => "timeout",                504, true,  "Timeout";
    OutcomeUnknown       => "outcome_unknown",        504, true,  "Outcome unknown";
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, ThisError, Clone, PartialEq, Eq)]
#[error("unknown or invalid error code")]
pub struct CodeParseError;

/// Retryability of a D.2 HTTP status. Every status in D.2 has a single retryability
/// (409, 503 and 504 are shared by several codes with the same value), so application codes
/// inherit it from their status.
pub fn status_retryable(status: u16) -> Option<bool> {
    let mut found = None;
    for c in ErrorCode::ALL {
        if c.status() == status {
            match found {
                None => found = Some(c.retryable()),
                Some(r) if r != c.retryable() => return None,
                Some(_) => {}
            }
        }
    }
    found
}

/// An application-defined code `app.{application_id}.{code}` mapped to a D.2 status.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppErrorCode {
    application_id: ApplicationId,
    code: String,
    status: u16,
}

impl AppErrorCode {
    /// `code` matches `^[a-z][a-z0-9_]{0,63}$`; `status` must be a D.2 status.
    pub fn new(
        application_id: ApplicationId,
        code: &str,
        status: u16,
    ) -> Result<Self, CodeParseError> {
        let b = code.as_bytes();
        let valid = !b.is_empty()
            && b.len() <= 64
            && b[0].is_ascii_lowercase()
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_');
        if !valid || status_retryable(status).is_none() {
            return Err(CodeParseError);
        }
        Ok(Self {
            application_id,
            code: code.to_owned(),
            status,
        })
    }

    /// Parse `app.{application_id}.{code}`; the status comes from the application's registry.
    pub fn parse(wire: &str, status: u16) -> Result<Self, CodeParseError> {
        let rest = wire.strip_prefix("app.").ok_or(CodeParseError)?;
        let (app, code) = rest.rsplit_once('.').ok_or(CodeParseError)?;
        let app = ApplicationId::parse(app).map_err(|_| CodeParseError)?;
        Self::new(app, code, status)
    }

    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn retryable(&self) -> bool {
        status_retryable(self.status).unwrap_or(false)
    }
}

impl fmt::Display for AppErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "app.{}.{}", self.application_id, self.code)
    }
}

/// A core or application error code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Code {
    Core(ErrorCode),
    App(AppErrorCode),
}

impl Code {
    pub fn status(&self) -> u16 {
        match self {
            Code::Core(c) => c.status(),
            Code::App(a) => a.status(),
        }
    }

    pub fn retryable(&self) -> bool {
        match self {
            Code::Core(c) => c.retryable(),
            Code::App(a) => a.retryable(),
        }
    }

    pub fn title(&self) -> String {
        match self {
            Code::Core(c) => c.title().to_owned(),
            Code::App(a) => format!("Application error ({a})"),
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Code::Core(c) => fmt::Display::fmt(c, f),
            Code::App(a) => fmt::Display::fmt(a, f),
        }
    }
}

impl From<ErrorCode> for Code {
    fn from(c: ErrorCode) -> Self {
        Code::Core(c)
    }
}

/// A field-level validation error (`errors[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldError {
    /// JSON Pointer (RFC 6901) into the request body.
    pub pointer: String,
    pub code: String,
    pub detail: String,
}

/// The platform error value.
#[derive(Clone)]
pub struct Error {
    code: Code,
    detail: Option<String>,
    retry_after_ms: Option<u64>,
    errors: Vec<FieldError>,
    consistency_token: Option<String>,
    cause: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("code", &self.code.to_string())
            .field("detail", &self.detail)
            .field("retry_after_ms", &self.retry_after_ms)
            .field("errors", &self.errors)
            .field("cause", &self.cause.as_ref().map(|c| c.to_string()))
            .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if let Some(d) = &self.detail {
            write!(f, ": {d}")?;
        }
        if let Some(c) = &self.cause {
            write!(f, " (cause: {c})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|c| c.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl Error {
    pub fn new(code: impl Into<Code>) -> Self {
        Self {
            code: code.into(),
            detail: None,
            retry_after_ms: None,
            errors: Vec::new(),
            consistency_token: None,
            cause: None,
        }
    }

    /// Internal error: the cause is logged, the caller sees a generic detail.
    pub fn internal(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::new(ErrorCode::Internal).with_cause(cause)
    }

    /// Caller-visible detail. Must never contain data the caller may not see.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_retry_after_ms(mut self, ms: u64) -> Self {
        self.retry_after_ms = Some(ms);
        self
    }

    pub fn with_field_error(mut self, e: FieldError) -> Self {
        self.errors.push(e);
        self
    }

    pub fn with_consistency_token(mut self, t: impl Into<String>) -> Self {
        self.consistency_token = Some(t.into());
        self
    }

    /// Attach an internal cause (logged, never sent to the caller).
    pub fn with_cause(mut self, cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.cause = Some(Arc::new(cause));
        self
    }

    pub fn code(&self) -> &Code {
        &self.code
    }

    pub fn status(&self) -> u16 {
        self.code.status()
    }

    pub fn retryable(&self) -> bool {
        self.code.retryable()
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    pub fn retry_after_ms(&self) -> Option<u64> {
        self.retry_after_ms
    }

    pub fn field_errors(&self) -> &[FieldError] {
        &self.errors
    }

    /// The internal cause, for logging only.
    pub fn cause(&self) -> Option<&(dyn std::error::Error + Send + Sync)> {
        self.cause.as_deref()
    }

    /// `Retry-After` header value in whole seconds, rounded up.
    pub fn retry_after_header_secs(&self) -> Option<u64> {
        self.retry_after_ms.map(|ms| ms.div_ceil(1000))
    }

    /// Build the problem body.
    pub fn to_problem(
        &self,
        deployment_domain: &str,
        instance: &str,
        request_id: &crate::id::RequestId,
    ) -> ProblemDocument {
        let internal = matches!(self.code, Code::Core(ErrorCode::Internal));
        let detail = if internal {
            INTERNAL_DETAIL.to_owned()
        } else {
            self.detail.clone().unwrap_or_else(|| self.code.title())
        };
        ProblemDocument {
            r#type: format!("https://errors.{deployment_domain}/v1/{}", self.code),
            title: self.code.title(),
            status: self.code.status(),
            code: self.code.to_string(),
            detail,
            instance: instance.to_owned(),
            request_id: request_id.to_string(),
            retryable: self.code.retryable(),
            retry_after_ms: self.retry_after_ms,
            errors: if internal {
                Vec::new()
            } else {
                self.errors.clone()
            },
            consistency_token: self.consistency_token.clone(),
        }
    }
}

impl From<ErrorCode> for Error {
    fn from(c: ErrorCode) -> Self {
        Error::new(c)
    }
}

/// RFC 9457 problem details body (contract §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemDocument {
    pub r#type: String,
    pub title: String,
    pub status: u16,
    pub code: String,
    pub detail: String,
    pub instance: String,
    pub request_id: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<FieldError>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub consistency_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::RequestId;

    #[test]
    fn table_d2_exact() {
        let expected: &[(&str, u16, bool)] = &[
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
        assert_eq!(ErrorCode::ALL.len(), expected.len());
        for (c, (w, s, r)) in ErrorCode::ALL.iter().zip(expected) {
            assert_eq!(c.as_str(), *w);
            assert_eq!(c.status(), *s, "{w}");
            assert_eq!(c.retryable(), *r, "{w}");
            assert_eq!(w.parse::<ErrorCode>().unwrap(), *c);
        }
        assert!("Not_Found".parse::<ErrorCode>().is_err());
    }

    #[test]
    fn app_codes() {
        let a = AppErrorCode::parse("app.org.example.photos.album_full", 409).unwrap();
        assert_eq!(a.to_string(), "app.org.example.photos.album_full");
        assert_eq!(a.application_id().as_str(), "org.example.photos");
        assert!(!a.retryable());
        let b = AppErrorCode::parse("app.org.example.photos.busy", 503).unwrap();
        assert!(b.retryable());
        // invalid: unknown status, bad code, missing prefix
        assert!(AppErrorCode::parse("app.org.example.photos.x", 418).is_err());
        assert!(AppErrorCode::parse("app.org.example.photos.Bad", 400).is_err());
        assert!(AppErrorCode::parse("org.example.photos.x", 400).is_err());
        assert!(AppErrorCode::parse("app.photos", 400).is_err());
        let e = Error::new(Code::App(b));
        assert_eq!(e.status(), 503);
        assert!(e.retryable());
    }

    #[test]
    fn problem_document_fields() {
        let rid = RequestId::generate().unwrap();
        let e = Error::new(ErrorCode::RateLimited)
            .with_detail("slow down")
            .with_retry_after_ms(1500);
        let p = e.to_problem("example.test", "/api/v2/x", &rid);
        assert_eq!(p.r#type, "https://errors.example.test/v1/rate_limited");
        assert_eq!(p.status, 429);
        assert!(p.retryable);
        assert_eq!(p.retry_after_ms, Some(1500));
        assert_eq!(e.retry_after_header_secs(), Some(2));
        assert_eq!(p.request_id, rid.to_string());
        let j = serde_json::to_value(&p).unwrap();
        for k in [
            "type",
            "title",
            "status",
            "code",
            "detail",
            "instance",
            "request_id",
            "retryable",
            "retry_after_ms",
        ] {
            assert!(j.get(k).is_some(), "{k}");
        }
        assert!(j.get("errors").is_none());
    }

    #[test]
    fn internal_detail_is_generic() {
        let rid = RequestId::generate().unwrap();
        let e = Error::internal(std::io::Error::other("db password=hunter2"))
            .with_detail("secret table xyz");
        let p = e.to_problem("d", "/", &rid);
        assert_eq!(p.detail, INTERNAL_DETAIL);
        assert!(!serde_json::to_string(&p).unwrap().contains("hunter2"));
        assert!(e.cause().is_some());
    }

    #[test]
    fn status_retryability_is_functional() {
        for c in ErrorCode::ALL {
            assert_eq!(status_retryable(c.status()), Some(c.retryable()));
        }
        assert_eq!(status_retryable(418), None);
    }
}
