//! Readiness barriers (contract §7; spec §2.6, App. C rule C14). Process health alone never
//! means ready: every configured domain must be reachable and at the expected migration
//! version. Revocation currency is added in M2.

use async_trait::async_trait;
use cs_db::DomainPool;
use cs_db::migrate::{MigrationSet, Migrator};

/// One readiness condition. `check` returns a reason on failure; the reason is logged, never
/// sent to clients.
#[async_trait]
pub trait ReadinessBarrier: Send + Sync {
    fn name(&self) -> String;
    async fn check(&self) -> Result<(), String>;
}

/// The domain database answers.
#[derive(Debug)]
pub struct DomainReachable(pub DomainPool);

#[async_trait]
impl ReadinessBarrier for DomainReachable {
    fn name(&self) -> String {
        format!("domain.{}.reachable", self.0.domain())
    }
    async fn check(&self) -> Result<(), String> {
        self.0.ping().await.map_err(|e| e.to_string())
    }
}

/// The domain database is exactly at the migration version this binary expects (no pending
/// migrations, checksums match). `cs serve` never migrates; `cs migrate` does.
#[derive(Debug)]
pub struct MigrationsCurrent {
    pub pool: DomainPool,
    pub set: MigrationSet,
}

#[async_trait]
impl ReadinessBarrier for MigrationsCurrent {
    fn name(&self) -> String {
        format!("domain.{}.migrations", self.pool.domain())
    }
    async fn check(&self) -> Result<(), String> {
        let st = Migrator::status(&self.pool, &self.set)
            .await
            .map_err(|e| e.to_string())?;
        if st.is_current() {
            Ok(())
        } else {
            Err(format!(
                "pending migrations {:?} (expected version {})",
                st.pending, st.expected_version
            ))
        }
    }
}
