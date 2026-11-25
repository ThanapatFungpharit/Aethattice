//! Declarative node configuration (contract §6, spec J.4).
//!
//! One TOML file, parsed and validated in full before anything is applied. Unknown keys
//! are errors at every level. Validation collects every problem it finds and reports them
//! together. Error messages never echo file contents (connection URLs may hold passwords).

use crate::id::NodeId;
use crate::secret::Secret;
use crate::vector::DomainId;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("configuration syntax error: {0}")]
    Parse(String),
    #[error("invalid configuration:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

/// Server roles (spec §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    Edge,
    Api,
    Realtime,
    Worker,
    Search,
    Storage,
    Control,
}

impl Role {
    pub const ALL: [Role; 7] = [
        Role::Edge,
        Role::Api,
        Role::Realtime,
        Role::Worker,
        Role::Search,
        Role::Storage,
        Role::Control,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Edge => "edge",
            Role::Api => "api",
            Role::Realtime => "realtime",
            Role::Worker => "worker",
            Role::Search => "search",
            Role::Storage => "storage",
            Role::Control => "control",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        Role::ALL.into_iter().find(|r| r.as_str() == s).ok_or(())
    }
}

/// One policy value's contract: default and safe range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicySpec {
    pub key: &'static str,
    pub default: i64,
    pub min: i64,
    pub max: i64,
    pub unit: &'static str,
    /// Where the default comes from. Ranges marked "(design)" are not given by the spec.
    pub source: &'static str,
}

/// Every policy value known in M0.
pub const POLICY_TABLE: &[PolicySpec] = &[
    PolicySpec {
        key: "idempotency_retention_hours",
        default: 24,
        min: 24,
        max: 720,
        unit: "hours",
        source: "spec D.3 default 24 h; range (design): never below the 24 h client contract",
    },
    PolicySpec {
        key: "db_retry_max_attempts",
        default: 10,
        min: 1,
        max: 50,
        unit: "attempts",
        source: "contract §5 default 10; range (design)",
    },
    PolicySpec {
        key: "db_retry_max_elapsed_ms",
        default: 5_000,
        min: 100,
        max: 60_000,
        unit: "milliseconds",
        source: "contract §5 default 5 s; range (design)",
    },
    PolicySpec {
        key: "revocation_staleness_ms",
        default: 2_000,
        min: 1_000,
        max: 30_000,
        unit: "milliseconds",
        source: "spec §6.6 S default 2 s, max 30 s; min 1 s (design, QA OQ-6: S below the 500 ms heartbeat would make every consumer stale). Enforced from M2",
    },
    PolicySpec {
        key: "db_migration_retry_max_attempts",
        default: 30,
        min: 1,
        max: 500,
        unit: "attempts",
        source: "contract §5 rev 4 default 30; range (design)",
    },
    PolicySpec {
        key: "db_migration_retry_max_elapsed_ms",
        default: 120_000,
        min: 1_000,
        max: 3_600_000,
        unit: "milliseconds",
        source: "contract §5 rev 4 default 120 s; range (design)",
    },
    PolicySpec {
        key: "saga_reconcile_interval_ms",
        default: 1_000,
        min: 100,
        max: 60_000,
        unit: "milliseconds",
        source: "(design) §18.4 reconcilers run continuously",
    },
    PolicySpec {
        key: "group_max_depth",
        default: 32,
        min: 4,
        max: 64,
        unit: "levels",
        source: "erratum C13 / M1 contract §1 rev 4 (design; owner 2026-11-24)",
    },
    PolicySpec {
        key: "group_max_closure",
        default: 10_000,
        min: 1_000,
        max: 100_000,
        unit: "principals",
        source: "erratum C13 / M1 contract §1 rev 4 (design; owner 2026-11-24)",
    },
    PolicySpec {
        key: "setup_link_lifetime_secs",
        default: 86_400,
        min: 900,
        max: 604_800,
        unit: "seconds",
        source: "erratum C13 / M1 contract rev 4 (design; owner 2026-11-24): 24 h, 15 min–7 d",
    },
    PolicySpec {
        key: "access_token_lifetime_secs",
        default: 600,
        min: 60,
        max: 3_600,
        unit: "seconds",
        source: "spec §5.5 / erratum C13 / M1 contract §8: 600 s, 60–3600 s",
    },
    PolicySpec {
        key: "session_idle_lifetime_secs",
        default: 1_209_600,
        min: 3_600,
        max: 7_776_000,
        unit: "seconds",
        source: "spec §5.5 / erratum C13 / M1 contract §8: 14 d, 1 h–90 d",
    },
    PolicySpec {
        key: "session_absolute_lifetime_secs",
        default: 7_776_000,
        min: 86_400,
        max: 31_536_000,
        unit: "seconds",
        source: "spec §5.5 / erratum C13 / M1 contract §8: 90 d, 1–365 d",
    },
    PolicySpec {
        key: "step_up_window_secs",
        default: 300,
        min: 60,
        max: 3_600,
        unit: "seconds",
        source: "spec §5.5 / erratum C13 / M1 contract §2.3, §8: 5 min, 1–60 min",
    },
];

/// Typed handle on a policy key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKey {
    IdempotencyRetentionHours,
    DbRetryMaxAttempts,
    DbRetryMaxElapsedMs,
    SagaReconcileIntervalMs,
    RevocationStalenessMs,
    DbMigrationRetryMaxAttempts,
    DbMigrationRetryMaxElapsedMs,
    GroupMaxDepth,
    GroupMaxClosure,
    SetupLinkLifetimeSecs,
    AccessTokenLifetimeSecs,
    SessionIdleLifetimeSecs,
    SessionAbsoluteLifetimeSecs,
    StepUpWindowSecs,
}

impl PolicyKey {
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyKey::IdempotencyRetentionHours => "idempotency_retention_hours",
            PolicyKey::DbRetryMaxAttempts => "db_retry_max_attempts",
            PolicyKey::DbRetryMaxElapsedMs => "db_retry_max_elapsed_ms",
            PolicyKey::SagaReconcileIntervalMs => "saga_reconcile_interval_ms",
            PolicyKey::RevocationStalenessMs => "revocation_staleness_ms",
            PolicyKey::DbMigrationRetryMaxAttempts => "db_migration_retry_max_attempts",
            PolicyKey::DbMigrationRetryMaxElapsedMs => "db_migration_retry_max_elapsed_ms",
            PolicyKey::GroupMaxDepth => "group_max_depth",
            PolicyKey::GroupMaxClosure => "group_max_closure",
            PolicyKey::SetupLinkLifetimeSecs => "setup_link_lifetime_secs",
            PolicyKey::AccessTokenLifetimeSecs => "access_token_lifetime_secs",
            PolicyKey::SessionIdleLifetimeSecs => "session_idle_lifetime_secs",
            PolicyKey::SessionAbsoluteLifetimeSecs => "session_absolute_lifetime_secs",
            PolicyKey::StepUpWindowSecs => "step_up_window_secs",
        }
    }
}

/// Validated policy values (every key present, every value in range).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    values: BTreeMap<&'static str, i64>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            values: POLICY_TABLE.iter().map(|p| (p.key, p.default)).collect(),
        }
    }
}

impl Policy {
    pub fn get(&self, key: PolicyKey) -> i64 {
        self.values
            .get(key.as_str())
            .copied()
            .or_else(|| {
                POLICY_TABLE
                    .iter()
                    .find(|p| p.key == key.as_str())
                    .map(|p| p.default)
            })
            .unwrap_or(0)
    }

    /// Set one value, enforcing the same safe range as `check-config`.
    pub fn with_value(mut self, key: PolicyKey, value: i64) -> Result<Self, ConfigError> {
        let spec = POLICY_TABLE
            .iter()
            .find(|s| s.key == key.as_str())
            .ok_or_else(|| {
                ConfigError::Invalid(vec![format!("policy.{}: unknown", key.as_str())])
            })?;
        if value < spec.min || value > spec.max {
            return Err(ConfigError::Invalid(vec![format!(
                "policy.{}: {value} is outside the safe range {}..={} {}",
                spec.key, spec.min, spec.max, spec.unit
            )]));
        }
        self.values.insert(spec.key, value);
        Ok(self)
    }

    fn from_raw(raw: BTreeMap<String, toml::Value>, errs: &mut Vec<String>) -> Self {
        let mut p = Policy::default();
        for (k, v) in raw {
            let Some(spec) = POLICY_TABLE.iter().find(|s| s.key == k) else {
                errs.push(format!("policy.{k}: unknown policy key"));
                continue;
            };
            let Some(n) = v.as_integer() else {
                errs.push(format!("policy.{k}: must be an integer ({})", spec.unit));
                continue;
            };
            if n < spec.min || n > spec.max {
                errs.push(format!(
                    "policy.{k}: {n} is outside the safe range {}..={} {}",
                    spec.min, spec.max, spec.unit
                ));
                continue;
            }
            p.values.insert(spec.key, n);
        }
        p
    }
}

/// Connection pool settings for one domain.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    #[serde(default = "d_max_conn")]
    pub max_connections: u32,
    #[serde(default)]
    pub min_connections: u32,
    #[serde(default = "d_acquire")]
    pub acquire_timeout_ms: u64,
    #[serde(default = "d_idle")]
    pub idle_timeout_ms: u64,
    #[serde(default = "d_stmt")]
    pub statement_timeout_ms: u64,
}

fn d_max_conn() -> u32 {
    10
}
fn d_acquire() -> u64 {
    5_000
}
fn d_idle() -> u64 {
    600_000
}
fn d_stmt() -> u64 {
    30_000
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: d_max_conn(),
            min_connections: 0,
            acquire_timeout_ms: d_acquire(),
            idle_timeout_ms: d_idle(),
            statement_timeout_ms: d_stmt(),
        }
    }
}

/// Connection configuration for one domain. Domains never share a handle even when the
/// URLs point to the same cluster.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainConfig {
    /// `postgres://` URL. Treated as a secret (may contain a password).
    pub url: Secret<String>,
    #[serde(default)]
    pub pool: PoolConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum KmsBackend {
    LocalSoftware,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsConfig {
    pub backend: KmsBackend,
    /// Root key file (0600). Single-node only (J.4).
    pub root_key_path: PathBuf,
    /// Key store file; defaults to `<root_key_path>.keys`.
    #[serde(default)]
    pub keystore_path: Option<PathBuf>,
}

/// Valkey connection (M1 contract §3 `[R6]`: shared DPoP replay store). Optional: when absent,
/// replay checks use the identity `dpop_jti` table only.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValkeyConfig {
    /// `redis://` or `rediss://` (TLS) URL; may carry credentials, so it is a secret.
    pub url: Secret<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    pub listen: SocketAddr,
    pub admin_listen: SocketAddr,
    /// Used in problem `type` URIs: `https://errors.{deployment_domain}/v1/{code}`.
    pub deployment_domain: String,
    #[serde(default = "d_body")]
    pub max_body_bytes: u64,
    #[serde(default = "d_ready")]
    pub readiness_timeout_ms: u64,
}

fn d_body() -> u64 {
    1024 * 1024
}
fn d_ready() -> u64 {
    2_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Json,
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub log_format: LogFormat,
    /// `tracing_subscriber::EnvFilter` directive, e.g. `info` or `info,cs_db=debug`.
    #[serde(default = "d_level")]
    pub log_level: String,
    #[serde(default = "d_service")]
    pub service_name: String,
}

fn d_level() -> String {
    "info".to_owned()
}
fn d_service() -> String {
    "cs".to_owned()
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_format: LogFormat::Json,
            log_level: d_level(),
            service_name: d_service(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub id: String,
    pub roles: Vec<String>,
}

/// Settings tenants cannot change.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LocksConfig {
    #[serde(default)]
    pub policy: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    node: NodeConfig,
    #[serde(default)]
    domains: BTreeMap<String, DomainConfig>,
    #[serde(default)]
    kms: Option<KmsConfig>,
    #[serde(default)]
    api: Option<ApiConfig>,
    #[serde(default)]
    valkey: Option<ValkeyConfig>,
    #[serde(default)]
    telemetry: TelemetryConfig,
    #[serde(default)]
    policy: BTreeMap<String, toml::Value>,
    #[serde(default)]
    locks: LocksConfig,
}

/// A fully validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub node_id: NodeId,
    pub roles: BTreeSet<Role>,
    pub domains: BTreeMap<DomainId, DomainConfig>,
    pub kms: Option<KmsConfig>,
    pub api: Option<ApiConfig>,
    pub valkey: Option<ValkeyConfig>,
    pub telemetry: TelemetryConfig,
    pub policy: Policy,
    pub locked_policy: BTreeSet<&'static str>,
}

fn valid_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            let b = l.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        })
}

impl Config {
    /// Read and validate a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml_str(&text)
    }

    /// Parse and validate configuration text.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| {
            // Report message and location only; never echo the offending source line.
            let loc = e
                .span()
                .map(|s| {
                    let line = text[..s.start.min(text.len())].matches('\n').count() + 1;
                    format!(" (line {line})")
                })
                .unwrap_or_default();
            ConfigError::Parse(format!("{}{loc}", e.message().trim()))
        })?;
        Self::validate(raw)
    }

    fn validate(raw: RawConfig) -> Result<Self, ConfigError> {
        let mut errs = Vec::new();

        let node_id = match raw.node.id.parse::<NodeId>() {
            Ok(id) => Some(id),
            Err(e) => {
                errs.push(format!("node.id: {e}"));
                None
            }
        };
        let mut roles = BTreeSet::new();
        if raw.node.roles.is_empty() {
            errs.push("node.roles: at least one role is required".to_owned());
        }
        for r in &raw.node.roles {
            match r.parse::<Role>() {
                Ok(role) => {
                    if !roles.insert(role) {
                        errs.push(format!("node.roles: duplicate role {r:?}"));
                    }
                }
                Err(()) => errs.push(format!(
                    "node.roles: unknown role {r:?} (known: edge, api, realtime, worker, search, storage, control)"
                )),
            }
        }

        let mut domains = BTreeMap::new();
        for (name, d) in raw.domains {
            let id = match name.parse::<DomainId>() {
                Ok(DomainId::App(_)) => {
                    errs.push(format!(
                        "domains.{name}: application databases are not configured here (M5)"
                    ));
                    continue;
                }
                Ok(id) => id,
                Err(_) => {
                    errs.push(format!("domains.{name}: unknown domain"));
                    continue;
                }
            };
            let url = d.url.expose_secret();
            if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
                errs.push(format!(
                    "domains.{name}.url: must be a postgres:// or postgresql:// URL"
                ));
            }
            let p = &d.pool;
            if !(1..=1000).contains(&p.max_connections) {
                errs.push(format!(
                    "domains.{name}.pool.max_connections: must be 1..=1000"
                ));
            }
            if p.min_connections > p.max_connections {
                errs.push(format!(
                    "domains.{name}.pool.min_connections: must not exceed max_connections"
                ));
            }
            for (k, v, max) in [
                ("acquire_timeout_ms", p.acquire_timeout_ms, 300_000),
                ("idle_timeout_ms", p.idle_timeout_ms, 86_400_000),
                ("statement_timeout_ms", p.statement_timeout_ms, 3_600_000),
            ] {
                if v == 0 || v > max {
                    errs.push(format!("domains.{name}.pool.{k}: must be 1..={max}"));
                }
            }
            domains.insert(id, d);
        }

        if let Some(api) = &raw.api {
            if api.listen == api.admin_listen {
                errs.push("api.admin_listen: must differ from api.listen".to_owned());
            }
            if !valid_dns_name(&api.deployment_domain) {
                errs.push("api.deployment_domain: must be a lowercase DNS name".to_owned());
            }
            if api.max_body_bytes == 0 || api.max_body_bytes > 64 * 1024 * 1024 {
                errs.push("api.max_body_bytes: must be 1..=67108864".to_owned());
            }
            if api.readiness_timeout_ms == 0 || api.readiness_timeout_ms > 60_000 {
                errs.push("api.readiness_timeout_ms: must be 1..=60000".to_owned());
            }
        }
        if roles.contains(&Role::Api) && raw.api.is_none() {
            errs.push("api: section required when the api role is enabled".to_owned());
        }

        if let Some(k) = &raw.kms
            && k.root_key_path.as_os_str().is_empty()
        {
            errs.push("kms.root_key_path: must not be empty".to_owned());
        }

        if let Some(v) = &raw.valkey {
            let u = v.url.expose_secret();
            let rest = u
                .strip_prefix("redis://")
                .or_else(|| u.strip_prefix("rediss://"));
            if rest.is_none_or(|r| r.is_empty() || r.starts_with('/')) {
                errs.push("valkey.url: must be a redis:// or rediss:// URL with a host".to_owned());
            }
        }

        if tracing_subscriber::EnvFilter::try_new(&raw.telemetry.log_level).is_err() {
            errs.push("telemetry.log_level: invalid filter directive".to_owned());
        }
        if raw.telemetry.service_name.is_empty() {
            errs.push("telemetry.service_name: must not be empty".to_owned());
        }

        let policy = Policy::from_raw(raw.policy, &mut errs);
        let mut locked_policy = BTreeSet::new();
        for k in &raw.locks.policy {
            match POLICY_TABLE.iter().find(|s| s.key == k) {
                Some(s) => {
                    locked_policy.insert(s.key);
                }
                None => errs.push(format!("locks.policy: unknown policy key {k:?}")),
            }
        }

        match (node_id, errs.is_empty()) {
            (Some(node_id), true) => Ok(Config {
                node_id,
                roles,
                domains,
                kms: raw.kms,
                api: raw.api,
                valkey: raw.valkey,
                telemetry: raw.telemetry,
                policy,
                locked_policy,
            }),
            _ => Err(ConfigError::Invalid(errs)),
        }
    }

    /// Whether tenants are prevented from changing a policy value.
    pub fn is_locked(&self, key: PolicyKey) -> bool {
        self.locked_policy.contains(key.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id() -> String {
        NodeId::generate().unwrap().to_string()
    }

    fn good() -> String {
        format!(
            r#"
[node]
id = "{}"
roles = ["api"]

[domains.identity]
url = "postgres://yugabyte:hunter2@localhost:5433/cs_identity"

[domains.operations]
url = "postgres://yugabyte@localhost:5433/cs_operations"
pool = {{ max_connections = 4 }}

[kms]
backend = "local_software"
root_key_path = "/tmp/root.key"

[api]
listen = "127.0.0.1:8080"
admin_listen = "127.0.0.1:9090"
deployment_domain = "cs.example.test"

[telemetry]
log_format = "json"

[policy]
idempotency_retention_hours = 48

[locks]
policy = ["idempotency_retention_hours"]
"#,
            node_id()
        )
    }

    #[test]
    fn valid_config() {
        let c = Config::from_toml_str(&good()).unwrap();
        assert!(c.roles.contains(&Role::Api));
        assert_eq!(c.domains.len(), 2);
        assert_eq!(c.domains[&DomainId::Operations].pool.max_connections, 4);
        assert_eq!(c.policy.get(PolicyKey::IdempotencyRetentionHours), 48);
        assert_eq!(c.policy.get(PolicyKey::DbRetryMaxAttempts), 10);
        assert!(c.is_locked(PolicyKey::IdempotencyRetentionHours));
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    fn invalid(text: &str) -> String {
        match Config::from_toml_str(text) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("accepted invalid config:\n{text}"),
        }
    }

    #[test]
    fn unknown_keys_rejected_everywhere() {
        let g = good();
        for (anchor, extra) in [
            ("[node]\n", "colour = 1\n"),
            ("[api]\n", "lisen = \"x\"\n"),
            ("[kms]\n", "foo = 1\n"),
            ("[telemetry]\n", "x = 1\n"),
            ("[locks]\n", "y = []\n"),
        ] {
            let t = g.replacen(anchor, &format!("{anchor}{extra}"), 1);
            assert!(invalid(&t).contains("unknown field"), "{anchor}");
        }
        assert!(invalid(&format!("{g}\n[extra]\na = 1\n")).contains("unknown field"));
        assert!(
            invalid(&g.replace("pool = { max_connections = 4 }", "pool = { max_conns = 4 }"))
                .contains("unknown field")
        );
        assert!(
            invalid(&g.replace("idempotency_retention_hours = 48", "made_up = 1"))
                .contains("unknown policy key")
        );
    }

    #[test]
    fn m1_policy_ranges_enforced() {
        // erratum C13 rows added by M1 (contract §8, rev 4): bounds inclusive, outside rejected.
        for (key, lo, hi) in [
            ("group_max_depth", 4, 64),
            ("group_max_closure", 1_000, 100_000),
            ("setup_link_lifetime_secs", 900, 604_800),
            ("access_token_lifetime_secs", 60, 3_600),
            ("session_idle_lifetime_secs", 3_600, 7_776_000),
            ("session_absolute_lifetime_secs", 86_400, 31_536_000),
            ("step_up_window_secs", 60, 3_600),
        ] {
            let g = good();
            for ok in [lo, hi] {
                let doc = g.replace(
                    "idempotency_retention_hours = 48",
                    &format!("idempotency_retention_hours = 48\n{key} = {ok}"),
                );
                let c = Config::from_toml_str(&doc).unwrap();
                assert!(c.policy.values.get(key) == Some(&ok), "{key}={ok}");
            }
            for bad in [lo - 1, hi + 1] {
                let doc = g.replace(
                    "idempotency_retention_hours = 48",
                    &format!("idempotency_retention_hours = 48\n{key} = {bad}"),
                );
                assert!(
                    invalid(&doc).contains("outside the safe range"),
                    "{key}={bad}"
                );
            }
        }
        let d = Policy::default();
        assert_eq!(d.get(PolicyKey::GroupMaxDepth), 32);
        assert_eq!(d.get(PolicyKey::GroupMaxClosure), 10_000);
        assert_eq!(d.get(PolicyKey::SetupLinkLifetimeSecs), 86_400);
        assert_eq!(d.get(PolicyKey::AccessTokenLifetimeSecs), 600);
        assert_eq!(d.get(PolicyKey::StepUpWindowSecs), 300);
    }

    /// `[valkey] url` (M1 contract §3 [R6]): optional, redis:// or rediss://, credentials
    /// allowed and never printed; anything else is refused by check-config.
    #[test]
    fn valkey_section() {
        let g = good();
        assert!(Config::from_toml_str(&g).unwrap().valkey.is_none());
        for ok in [
            "redis://localhost:6379",
            "rediss://default:s3cr3t-pw@valkey.internal:6380/0",
        ] {
            let c = Config::from_toml_str(&format!("{g}\n[valkey]\nurl = \"{ok}\"\n")).unwrap();
            assert_eq!(c.valkey.as_ref().unwrap().url.expose_secret(), ok);
            assert!(!format!("{c:?}").contains("s3cr3t-pw"));
        }
        for bad in ["http://localhost:6379", "redis://", "localhost:6379", ""] {
            let e = invalid(&format!("{g}\n[valkey]\nurl = \"{bad}\"\n"));
            assert!(e.contains("valkey.url"), "{bad}: {e}");
        }
        assert!(
            invalid(&format!("{g}\n[valkey]\nurl = \"redis://h\"\nx = 1\n"))
                .contains("unknown field")
        );
    }

    #[test]
    fn policy_ranges_enforced() {
        let g = good();
        assert!(invalid(&g.replace("= 48", "= 1")).contains("outside the safe range"));
        assert!(invalid(&g.replace("= 48", "= 100000")).contains("outside the safe range"));
        assert!(invalid(&g.replace("= 48", "= \"48\"")).contains("must be an integer"));
    }

    #[test]
    fn malformed_and_semantic_errors() {
        let g = good();
        assert!(matches!(
            Config::from_toml_str("[node"),
            Err(ConfigError::Parse(_))
        ));
        assert!(
            invalid(&g.replace("roles = [\"api\"]", "roles = [\"api\", \"cook\"]"))
                .contains("unknown role")
        );
        assert!(
            invalid(&g.replace("roles = [\"api\"]", "roles = []")).contains("at least one role")
        );
        assert!(
            invalid(&g.replace("roles = [\"api\"]", "roles = [\"api\", \"api\"]"))
                .contains("duplicate role")
        );
        assert!(
            invalid(&g.replace("[domains.identity]", "[domains.idenity]"))
                .contains("unknown domain")
        );
        assert!(
            invalid(&g.replace("postgres://yugabyte@", "mysql://yugabyte@"))
                .contains("postgres://")
        );
        assert!(invalid(&g.replace("127.0.0.1:9090", "127.0.0.1:8080")).contains("must differ"));
        assert!(invalid(&g.replace("cs.example.test", "Bad_Domain")).contains("deployment_domain"));
        assert!(
            invalid(&g.replace("max_connections = 4", "max_connections = 0"))
                .contains("max_connections")
        );
        // node id must be UUIDv7
        // a fixed UUIDv4; a random 128-bit value would be a valid v7 one time in 64
        let v4 = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";
        let t = g.replacen("id = \"", &format!("id = \"{v4}\"\n#"), 1);
        assert!(invalid(&t).contains("node.id"));
        // multiple errors reported together
        let multi = g
            .replace("roles = [\"api\"]", "roles = [\"x\"]")
            .replace("[domains.identity]", "[domains.nope]");
        let m = invalid(&multi);
        assert!(
            m.contains("unknown role") && m.contains("unknown domain"),
            "{m}"
        );
    }

    #[test]
    fn parse_errors_do_not_echo_secrets() {
        // A type error on the url line must not print the url.
        let g = good().replace(
            "url = \"postgres://yugabyte:hunter2@localhost:5433/cs_identity\"",
            "url = \"postgres://yugabyte:hunter2@localhost:5433/cs_identity\"\nurl2 = 1",
        );
        let e = invalid(&g);
        assert!(!e.contains("hunter2"), "{e}");
    }
}
