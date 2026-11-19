//! `cs` — single binary hosting every server role (spec §2.2, J.2; contract §6, §7 rev 2).
//!
//! - `cs serve --config <file>`: validates the whole configuration, refuses roles that are not
//!   implemented yet, and serves the enabled roles. It never migrates; `/readyz` reports a
//!   migration version mismatch as a failing barrier.
//! - `cs migrate --config <file>`: applies the migrations of every configured domain (J.4
//!   step 3). The only path that runs DDL.
//! - `cs init-kms --config <file>`: creates the local software KMS root key (J.4 step 1,
//!   single-node only).
//! - `cs check-config --config <file>`: validates and exits.

use clap::{Parser, Subcommand};
use cs_api::{ApiState, DomainReachable, MigrationsCurrent, ReadinessBarrier};
use cs_common::config::{Config, KmsBackend, PolicyKey, Role};
use cs_common::vector::DomainId;
use cs_db::migrate::{MigrationSet, Migrator, common_migrations};
use cs_db::{DomainPool, RetryPolicy};
use cs_kms::LocalSoftwareKms;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

/// Roles implemented by this build. Every other role is refused, never run as a no-op.
const IMPLEMENTED_ROLES: &[Role] = &[Role::Api];

#[derive(Parser, Debug)]
#[command(name = "cs", about = "Cloud System workspace platform", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the roles enabled in the configuration.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Apply database migrations for every configured domain.
    Migrate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create the local software KMS root key (single-node deployments only).
    InitKms {
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate a configuration file.
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
}

/// The migration set this binary expects for a domain.
fn migration_set(domain: &DomainId) -> Result<MigrationSet, String> {
    let common = common_migrations().map_err(|e| e.to_string())?;
    match domain {
        DomainId::Operations => common
            .merge(cs_ops::migrations().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string()),
        _ => Ok(common),
    }
}

fn load(path: &Path) -> Result<Config, String> {
    Config::load(path).map_err(|e| format!("cs: {e}"))
}

fn check_roles(cfg: &Config) -> Result<(), String> {
    let refused: Vec<String> = cfg
        .roles
        .iter()
        .filter(|r| !IMPLEMENTED_ROLES.contains(r))
        .map(|r| r.to_string())
        .collect();
    if refused.is_empty() {
        return Ok(());
    }
    Err(format!(
        "cs: refusing to start: role(s) {} are not implemented in this build (implemented: {}). \
         Remove them from [node].roles; they are never started as no-ops.",
        refused.join(", "),
        IMPLEMENTED_ROLES
            .iter()
            .map(|r| r.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

fn pools(cfg: &Config) -> Result<Vec<DomainPool>, String> {
    let retry = RetryPolicy::from_policy(&cfg.policy);
    cfg.domains
        .iter()
        .map(|(d, dc)| {
            DomainPool::connect_lazy(d.clone(), dc, retry).map_err(|e| format!("cs: {e}"))
        })
        .collect()
}

fn open_kms(cfg: &Config) -> Result<Option<LocalSoftwareKms>, String> {
    let Some(k) = &cfg.kms else { return Ok(None) };
    match k.backend {
        KmsBackend::LocalSoftware => {
            if !k.root_key_path.exists() {
                return Err(format!(
                    "cs: KMS root key {} does not exist; run `cs init-kms --config <file>` first",
                    k.root_key_path.display()
                ));
            }
            LocalSoftwareKms::open(&k.root_key_path, k.keystore_path.as_deref())
                .map(Some)
                .map_err(|e| format!("cs: KMS: {e}"))
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

async fn serve(path: &Path) -> Result<(), String> {
    let cfg = load(path)?;
    check_roles(&cfg)?;
    let telemetry = cs_common::telemetry::init(&cfg.telemetry).map_err(|e| format!("cs: {e}"))?;
    let _kms = open_kms(&cfg)?;
    let api = cfg
        .api
        .clone()
        .ok_or("cs: the api role needs an [api] section")?;
    let mut barriers: Vec<Arc<dyn ReadinessBarrier>> = Vec::new();
    for pool in pools(&cfg)? {
        barriers.push(Arc::new(DomainReachable(pool.clone())));
        let set = migration_set(pool.domain())?;
        barriers.push(Arc::new(MigrationsCurrent { pool, set }));
    }
    let state = ApiState::new(
        &api.deployment_domain,
        barriers,
        Duration::from_millis(api.readiness_timeout_ms),
    );
    let max_body = usize::try_from(api.max_body_bytes).unwrap_or(usize::MAX);
    let public = tokio::net::TcpListener::bind(api.listen)
        .await
        .map_err(|e| format!("cs: cannot bind api.listen {}: {e}", api.listen))?;
    let admin = tokio::net::TcpListener::bind(api.admin_listen)
        .await
        .map_err(|e| format!("cs: cannot bind api.admin_listen {}: {e}", api.admin_listen))?;
    tracing::info!(
        node_id = %cfg.node_id,
        listen = %api.listen,
        admin_listen = %api.admin_listen,
        revocation_staleness_ms = cfg.policy.get(PolicyKey::RevocationStalenessMs),
        "cs serving roles: api"
    );
    let (tx, rx) = tokio::sync::watch::channel(false);
    let mut rx2 = rx.clone();
    let mut rx1 = rx;
    let public_task = tokio::spawn(cs_api::serve(
        public,
        cs_api::router(state.clone(), max_body),
        async move {
            let _ = rx1.wait_for(|v| *v).await;
        },
    ));
    let admin_task = tokio::spawn(cs_api::serve(
        admin,
        cs_api::admin_router(state, telemetry.metrics_handle()),
        async move {
            let _ = rx2.wait_for(|v| *v).await;
        },
    ));
    shutdown_signal().await;
    tracing::info!("shutting down");
    let _ = tx.send(true);
    for t in [public_task, admin_task] {
        match t.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("cs: server error: {e}")),
            Err(e) => return Err(format!("cs: server task failed: {e}")),
        }
    }
    Ok(())
}

async fn migrate(path: &Path) -> Result<(), String> {
    let cfg = load(path)?;
    if cfg.domains.is_empty() {
        return Err("cs: no [domains.*] configured".into());
    }
    for pool in pools(&cfg)? {
        let set = migration_set(pool.domain())?;
        let r = Migrator::run(&pool, &set)
            .await
            .map_err(|e| format!("cs: migrating domain {}: {e}", pool.domain()))?;
        println!(
            "domain {}: applied {:?}, already applied {:?}, now at version {}",
            pool.domain(),
            r.applied,
            r.already_applied,
            set.expected_version()
        );
        pool.close().await;
    }
    Ok(())
}

fn init_kms(path: &Path) -> Result<(), String> {
    let cfg = load(path)?;
    let k = cfg.kms.ok_or("cs: no [kms] section configured")?;
    match k.backend {
        KmsBackend::LocalSoftware => {
            LocalSoftwareKms::init(&k.root_key_path, k.keystore_path.as_deref())
                .map_err(|e| format!("cs: KMS: {e}"))?;
            println!(
                "created local software KMS root key {} (0600; single-node deployments only)",
                k.root_key_path.display()
            );
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cs: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let res = match cli.cmd {
        Cmd::Serve { config } => rt.block_on(serve(&config)),
        Cmd::Migrate { config } => rt.block_on(migrate(&config)),
        Cmd::InitKms { config } => init_kms(&config),
        Cmd::CheckConfig { config } => load(&config).map(|c| {
            let roles: Vec<_> = c.roles.iter().map(|r| r.as_str()).collect();
            println!("configuration valid (roles: {})", roles.join(", "));
        }),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
    }
}
