//! Migration runner with expand / migrate / contract classes (contract §5.1; spec §24, App. E).
//!
//! Files: `crates/<crate>/migrations/<domain>/<NNNN>_<name>.<class>.sql`.
//!
//! Rules enforced here:
//! - Migrations are applied in version order; each is idempotent (written with
//!   `IF NOT EXISTS` / `ON CONFLICT`), so a run interrupted between executing a migration and
//!   recording it simply re-executes it (resumable).
//! - The checksum (BLAKE3 of the file bytes) of every applied migration must match the file;
//!   a mismatch is a hard error and nothing further is applied.
//! - A `contract` migration must carry a `-- requires_finalized: <release>` header, and is
//!   refused unless that release is recorded in `finalized_releases`. `expand` and `migrate`
//!   migrations must not carry the header and must not contain destructive DDL.
//! - This runner is the only place DDL is executed (runtime DDL is forbidden; see the lint test).
//!
//! Version ranges (design): `0001`–`0099` are the shared per-domain tables owned by `cs-db`
//! (outbox, idempotency records); domain crates use `0100` and above.

use crate::error::DbError;
use crate::pool::DomainPool;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::time::Instant;
use thiserror::Error;

/// Bootstrap DDL of the runner's own tables (created idempotently before anything else).
const BOOTSTRAP: &str = "\
CREATE TABLE IF NOT EXISTS schema_migrations (
  version    int         PRIMARY KEY,
  name       text        NOT NULL,
  class      text        NOT NULL CHECK (class IN ('expand', 'migrate', 'contract')),
  checksum   bytea       NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS finalized_releases (
  release      text        PRIMARY KEY,
  finalized_at timestamptz NOT NULL DEFAULT now()
);";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MigrationError {
    #[error("invalid migration file name {0:?}: expected NNNN_name.(expand|migrate|contract).sql")]
    FileName(String),
    #[error("duplicate migration version {0}")]
    DuplicateVersion(i32),
    #[error("migration {version} ({name}): {reason}")]
    Invalid {
        version: i32,
        name: String,
        reason: String,
    },
    #[error(
        "checksum mismatch for applied migration {version} ({name}): the file changed after it was applied"
    )]
    ChecksumMismatch { version: i32, name: String },
    #[error("applied migration {version} ({name}) does not match the file's name or class")]
    Mismatch { version: i32, name: String },
    #[error(
        "database has applied migration {0}, which this binary does not know and which is below its latest version"
    )]
    UnknownApplied(i32),
    #[error("contract migration {version} ({name}) requires release {release} to be finalized")]
    ContractNotFinalized {
        version: i32,
        name: String,
        release: String,
    },
    #[error("cannot read migrations: {0}")]
    Io(String),
}

/// Migration class (§24, App. E).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationClass {
    Expand,
    Migrate,
    Contract,
}

impl MigrationClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            MigrationClass::Expand => "expand",
            MigrationClass::Migrate => "migrate",
            MigrationClass::Contract => "contract",
        }
    }
}

impl fmt::Display for MigrationClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One migration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    pub version: i32,
    pub name: String,
    pub class: MigrationClass,
    pub sql: String,
    pub checksum: [u8; 32],
    pub requires_finalized: Option<String>,
}

fn valid_release(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 64
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// Destructive statements forbidden outside `contract` migrations.
const DESTRUCTIVE: &[&str] = &[
    "DROP TABLE",
    "DROP COLUMN",
    "DROP INDEX",
    "DROP CONSTRAINT",
    "DROP SCHEMA",
    "DROP VIEW",
    "DROP TYPE",
    "TRUNCATE",
    "RENAME",
    "ALTER COLUMN",
];

fn normalized_upper(sql: &str) -> String {
    let no_comments: String = sql
        .lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    // Word-normalize: identifiers like `filename` must not match `RENAME`.
    let words: String = no_comments
        .to_uppercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                ' '
            }
        })
        .collect();
    format!(
        " {} ",
        words.split_whitespace().collect::<Vec<_>>().join(" ")
    )
}

impl Migration {
    /// Parse a migration from its file name and contents.
    pub fn parse(file_name: &str, sql: &str) -> Result<Self, MigrationError> {
        let bad = || MigrationError::FileName(file_name.to_owned());
        let stem = file_name.strip_suffix(".sql").ok_or_else(bad)?;
        let (rest, class) = stem.rsplit_once('.').ok_or_else(bad)?;
        let class = match class {
            "expand" => MigrationClass::Expand,
            "migrate" => MigrationClass::Migrate,
            "contract" => MigrationClass::Contract,
            _ => return Err(bad()),
        };
        let (num, name) = rest.split_once('_').ok_or_else(bad)?;
        if num.len() != 4 || !num.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(bad());
        }
        let version: i32 = num.parse().map_err(|_| bad())?;
        if version == 0 {
            return Err(bad());
        }
        let invalid = |reason: &str| MigrationError::Invalid {
            version,
            name: name.to_owned(),
            reason: reason.to_owned(),
        };

        let mut requires_finalized = None;
        for line in sql.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let Some(comment) = t.strip_prefix("--") else {
                break; // header comments end at the first statement
            };
            if let Some(r) = comment.trim().strip_prefix("requires_finalized:") {
                let r = r.trim();
                if !valid_release(r) {
                    return Err(invalid("malformed requires_finalized header"));
                }
                if requires_finalized.replace(r.to_owned()).is_some() {
                    return Err(invalid("duplicate requires_finalized header"));
                }
            }
        }
        let upper = normalized_upper(sql);
        match class {
            MigrationClass::Contract if requires_finalized.is_none() => {
                return Err(invalid(
                    "contract migrations need a '-- requires_finalized: <release>' header",
                ));
            }
            MigrationClass::Expand | MigrationClass::Migrate => {
                if requires_finalized.is_some() {
                    return Err(invalid(
                        "requires_finalized is only valid on contract migrations",
                    ));
                }
                if let Some(d) = DESTRUCTIVE
                    .iter()
                    .find(|d| upper.contains(&format!(" {d} ")))
                {
                    return Err(invalid(&format!(
                        "{d} is destructive; only contract migrations may contain it"
                    )));
                }
            }
            MigrationClass::Contract => {}
        }
        if upper.trim().is_empty() {
            return Err(invalid("empty migration"));
        }
        Ok(Self {
            version,
            name: name.to_owned(),
            class,
            sql: sql.to_owned(),
            checksum: *blake3::hash(sql.as_bytes()).as_bytes(),
            requires_finalized,
        })
    }
}

/// An ordered set of migrations for one domain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationSet {
    migrations: BTreeMap<i32, Migration>,
}

impl MigrationSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add parsed migrations; duplicate versions are an error.
    pub fn with(
        mut self,
        items: impl IntoIterator<Item = Migration>,
    ) -> Result<Self, MigrationError> {
        for m in items {
            let v = m.version;
            if self.migrations.insert(v, m).is_some() {
                return Err(MigrationError::DuplicateVersion(v));
            }
        }
        Ok(self)
    }

    /// Parse `(file_name, contents)` pairs (typically from `include_str!`).
    pub fn from_files(files: &[(&str, &str)]) -> Result<Self, MigrationError> {
        let ms = files
            .iter()
            .map(|(n, s)| Migration::parse(n, s))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new().with(ms)
    }

    /// Load every `*.sql` file of a directory.
    pub fn from_dir(dir: &Path) -> Result<Self, MigrationError> {
        let io = |e: std::io::Error| MigrationError::Io(e.to_string());
        let mut ms = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".sql") {
                continue;
            }
            let sql = std::fs::read_to_string(entry.path()).map_err(io)?;
            ms.push(Migration::parse(&name, &sql)?);
        }
        Self::new().with(ms)
    }

    /// Union of two sets; overlapping versions are an error.
    pub fn merge(self, other: MigrationSet) -> Result<Self, MigrationError> {
        self.with(other.migrations.into_values())
    }

    /// Highest version in the set (0 when empty).
    pub fn expected_version(&self) -> i32 {
        self.migrations.keys().next_back().copied().unwrap_or(0)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Migration> {
        self.migrations.values()
    }
}

/// Result of a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub applied: Vec<i32>,
    pub already_applied: Vec<i32>,
}

/// Comparison of a domain database with a migration set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationStatus {
    pub expected_version: i32,
    pub pending: Vec<i32>,
}

impl MigrationStatus {
    pub fn is_current(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(sqlx::FromRow)]
struct AppliedRow {
    version: i32,
    name: String,
    class: String,
    checksum: Vec<u8>,
}

/// Applies migration sets to a domain.
#[derive(Debug, Clone, Copy, Default)]
pub struct Migrator;

impl Migrator {
    async fn exec_retrying(pool: &DomainPool, sql: &str) -> Result<(), DbError> {
        let policy = pool.retry_policy();
        let start = Instant::now();
        let mut attempt = 0;
        loop {
            attempt += 1;
            // Migration SQL is embedded, reviewed content (never user input).
            match sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
                .execute(pool.raw())
                .await
            {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let e = DbError::Sqlx(e);
                    if !e.is_retryable_conflict() {
                        return Err(e);
                    }
                    if attempt >= policy.max_attempts || start.elapsed() >= policy.max_elapsed {
                        return Err(DbError::RetryExhausted {
                            attempts: attempt,
                            last_sqlstate: e.sqlstate().unwrap_or_default(),
                        });
                    }
                    tokio::time::sleep(policy.backoff(attempt)?).await;
                }
            }
        }
    }

    async fn applied(pool: &DomainPool) -> Result<BTreeMap<i32, AppliedRow>, DbError> {
        let rows: Vec<AppliedRow> = sqlx::query_as(
            "SELECT version, name, class, checksum FROM schema_migrations ORDER BY version",
        )
        .fetch_all(pool.raw())
        .await?;
        Ok(rows.into_iter().map(|r| (r.version, r)).collect())
    }

    fn verify_applied(
        set: &MigrationSet,
        applied: &BTreeMap<i32, AppliedRow>,
    ) -> Result<(), MigrationError> {
        let max_known = set.expected_version();
        for (v, row) in applied {
            match set.migrations.get(v) {
                Some(m) => {
                    if row.checksum != m.checksum {
                        return Err(MigrationError::ChecksumMismatch {
                            version: *v,
                            name: m.name.clone(),
                        });
                    }
                    if row.name != m.name || row.class != m.class.as_str() {
                        return Err(MigrationError::Mismatch {
                            version: *v,
                            name: m.name.clone(),
                        });
                    }
                }
                // Newer migrations applied by a newer release are tolerated (rolling
                // upgrades); unknown versions inside our range are not.
                None if *v > max_known => {}
                None => return Err(MigrationError::UnknownApplied(*v)),
            }
        }
        Ok(())
    }

    /// Ensure the runner tables exist.
    pub async fn bootstrap(pool: &DomainPool) -> Result<(), DbError> {
        Self::exec_retrying(pool, BOOTSTRAP).await
    }

    /// Apply every pending migration of `set` in order.
    pub async fn run(pool: &DomainPool, set: &MigrationSet) -> Result<MigrationReport, DbError> {
        Self::bootstrap(pool).await?;
        let applied = Self::applied(pool).await?;
        Self::verify_applied(set, &applied)?;
        let mut report = MigrationReport::default();
        for m in set.iter() {
            if applied.contains_key(&m.version) {
                report.already_applied.push(m.version);
                continue;
            }
            if let Some(release) = &m.requires_finalized {
                let ok: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM finalized_releases WHERE release = $1)",
                )
                .bind(release)
                .fetch_one(pool.raw())
                .await?;
                if !ok {
                    return Err(MigrationError::ContractNotFinalized {
                        version: m.version,
                        name: m.name.clone(),
                        release: release.clone(),
                    }
                    .into());
                }
            }
            tracing::info!(domain = %pool.domain(), version = m.version, name = %m.name, class = %m.class, "applying migration");
            Self::exec_retrying(pool, &m.sql).await?;
            sqlx::query(
                "INSERT INTO schema_migrations (version, name, class, checksum) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (version) DO NOTHING",
            )
            .bind(m.version)
            .bind(&m.name)
            .bind(m.class.as_str())
            .bind(m.checksum.as_slice())
            .execute(pool.raw())
            .await?;
            report.applied.push(m.version);
        }
        // Re-verify: a concurrent runner may have recorded a different file.
        Self::verify_applied(set, &Self::applied(pool).await?)?;
        Ok(report)
    }

    /// Compare the database with `set` without changing anything.
    pub async fn status(pool: &DomainPool, set: &MigrationSet) -> Result<MigrationStatus, DbError> {
        let exists: bool =
            sqlx::query_scalar("SELECT to_regclass('schema_migrations') IS NOT NULL")
                .fetch_one(pool.raw())
                .await?;
        let applied = if exists {
            Self::applied(pool).await?
        } else {
            BTreeMap::new()
        };
        Self::verify_applied(set, &applied)?;
        Ok(MigrationStatus {
            expected_version: set.expected_version(),
            pending: set
                .iter()
                .filter(|m| !applied.contains_key(&m.version))
                .map(|m| m.version)
                .collect(),
        })
    }

    /// Record that `release` has been finalized (§24), enabling its contract migrations.
    pub async fn finalize_release(pool: &DomainPool, release: &str) -> Result<(), DbError> {
        if !valid_release(release) {
            return Err(DbError::Invalid(format!(
                "invalid release name {release:?}"
            )));
        }
        Self::bootstrap(pool).await?;
        sqlx::query(
            "INSERT INTO finalized_releases (release) VALUES ($1) ON CONFLICT (release) DO NOTHING",
        )
        .bind(release)
        .execute(pool.raw())
        .await?;
        Ok(())
    }
}

/// Migrations every domain receives (outbox, outbox counters, idempotency records, saga step receipts).
pub fn common_migrations() -> Result<MigrationSet, MigrationError> {
    MigrationSet::from_files(&[
        (
            "0001_outbox.expand.sql",
            include_str!("../migrations/common/0001_outbox.expand.sql"),
        ),
        (
            "0002_idempotency_records.expand.sql",
            include_str!("../migrations/common/0002_idempotency_records.expand.sql"),
        ),
        (
            "0003_saga_step_receipts.expand.sql",
            include_str!("../migrations/common/0003_saga_step_receipts.expand.sql"),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names() {
        let m = Migration::parse(
            "0003_add_x.expand.sql",
            "CREATE TABLE IF NOT EXISTS x (a int PRIMARY KEY);",
        )
        .unwrap();
        assert_eq!(
            (m.version, m.name.as_str(), m.class),
            (3, "add_x", MigrationClass::Expand)
        );
        for bad in [
            "3_x.expand.sql",
            "0003_x.sql",
            "0003_x.grow.sql",
            "0003_X.expand.sql",
            "0003-x.expand.sql",
            "0000_x.expand.sql",
            "0003_.expand.sql",
            "0003_x.expand.SQL",
        ] {
            assert!(
                matches!(
                    Migration::parse(bad, "SELECT 1;"),
                    Err(MigrationError::FileName(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn class_rules() {
        assert!(Migration::parse("0002_x.expand.sql", "DROP TABLE x;").is_err());
        assert!(
            Migration::parse("0002_x.migrate.sql", "alter table x\n  drop   column y;").is_err()
        );
        assert!(
            Migration::parse(
                "0002_x.expand.sql",
                "-- requires_finalized: 1.0.0\nSELECT 1;"
            )
            .is_err()
        );
        assert!(Migration::parse("0002_x.contract.sql", "DROP TABLE IF EXISTS x;").is_err());
        let c = Migration::parse(
            "0002_x.contract.sql",
            "-- drop old\n-- requires_finalized: 0.1.0\nDROP TABLE IF EXISTS x;",
        )
        .unwrap();
        assert_eq!(c.requires_finalized.as_deref(), Some("0.1.0"));
        assert!(
            Migration::parse(
                "0002_x.contract.sql",
                "-- requires_finalized: bad release\nSELECT 1;"
            )
            .is_err()
        );
        // a destructive keyword inside a comment does not count
        assert!(
            Migration::parse(
                "0002_x.expand.sql",
                "-- we never DROP TABLE here\nSELECT 1;"
            )
            .is_ok()
        );
        assert!(Migration::parse("0002_x.expand.sql", "-- only a comment").is_err());
        // identifiers containing a keyword are fine
        assert!(
            Migration::parse(
                "0002_x.expand.sql",
                "CREATE TABLE IF NOT EXISTS files (filename text PRIMARY KEY);"
            )
            .is_ok()
        );
    }

    #[test]
    fn checksums_and_sets() {
        let a = Migration::parse("0001_a.expand.sql", "SELECT 1;").unwrap();
        let b = Migration::parse("0001_a.expand.sql", "SELECT 2;").unwrap();
        assert_ne!(a.checksum, b.checksum);
        assert_eq!(
            MigrationSet::new().with([a.clone(), b]),
            Err(MigrationError::DuplicateVersion(1))
        );
        let common = common_migrations().unwrap();
        assert_eq!(common.expected_version(), 3);
        assert!(common.clone().merge(common).is_err());
    }
}
