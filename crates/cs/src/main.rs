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
//! - `cs admin --config <file> <action>`: M1 tenant, user and group administration and the
//!   first-administrator setup link (M1 contract §0 `[R4]`). A standalone subcommand, not a
//!   server role: no listener, no `control` role. It connects only to the identity domain and
//!   runs each action as one identity-domain transaction that writes an outbox event.

use clap::{Parser, Subcommand};
use cs_api::{ApiState, DomainReachable, MigrationsCurrent, ReadinessBarrier};
use cs_common::config::{Config, KmsBackend, PolicyKey, Role};
use cs_common::id::{GroupId, TenantId, UserId};
use cs_common::vector::DomainId;
use cs_db::migrate::{MigrationSet, Migrator, common_migrations};
use cs_db::{DomainPool, RetryPolicy};
use cs_identity::admin::{AdminError, IdentityAdmin, Member, NewUser, UserKind};
use cs_kms::LocalSoftwareKms;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

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
    /// Identity administration (M1: CLI only; no HTTP admin API until M2).
    Admin {
        #[arg(long)]
        config: PathBuf,
        #[command(subcommand)]
        action: AdminCmd,
    },
}

#[derive(Subcommand, Debug)]
enum AdminCmd {
    /// Tenant administration.
    #[command(subcommand)]
    Tenant(TenantCmd),
    /// User administration.
    #[command(subcommand)]
    User(UserCmd),
    /// Group administration.
    #[command(subcommand)]
    Group(GroupCmd),
    /// Issue the one-time first-administrator setup link for an invited user (J.4 step 4).
    /// Prints the link token once; only its SHA-256 is stored.
    SetupLink {
        #[arg(long)]
        tenant: TenantId,
        #[arg(long)]
        user: UserId,
    },
}

#[derive(Subcommand, Debug)]
enum TenantCmd {
    /// Create an active tenant.
    Create {
        #[arg(long)]
        name: String,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum KindArg {
    Member,
    Guest,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum MemberKindArg {
    User,
    Group,
}

#[derive(Subcommand, Debug)]
enum UserCmd {
    /// Create an invited user.
    Create {
        #[arg(long)]
        tenant: TenantId,
        #[arg(long)]
        login: String,
        #[arg(long, value_enum, default_value = "member")]
        kind: KindArg,
        #[arg(long)]
        display_name: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum GroupCmd {
    /// Create an empty group.
    Create {
        #[arg(long)]
        tenant: TenantId,
        #[arg(long)]
        name: String,
    },
    /// Add a direct member (cycles and limit breaches are rejected).
    AddMember {
        #[arg(long)]
        tenant: TenantId,
        #[arg(long)]
        group: GroupId,
        #[arg(long)]
        member: Uuid,
        #[arg(long, value_enum)]
        kind: MemberKindArg,
        /// Expected current membership_version (compare-and-set).
        #[arg(long)]
        expected_version: Option<i64>,
    },
    /// Remove a direct member.
    RemoveMember {
        #[arg(long)]
        tenant: TenantId,
        #[arg(long)]
        group: GroupId,
        #[arg(long)]
        member: Uuid,
        #[arg(long, value_enum)]
        kind: MemberKindArg,
        /// Expected current membership_version (compare-and-set).
        #[arg(long)]
        expected_version: Option<i64>,
    },
}

/// The migration set this binary expects for a domain.
fn migration_set(domain: &DomainId) -> Result<MigrationSet, String> {
    let common = common_migrations().map_err(|e| e.to_string())?;
    match domain {
        DomainId::Operations => common
            .merge(cs_ops::migrations().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string()),
        DomainId::Identity => common
            .merge(cs_identity::migrations().map_err(|e| e.to_string())?)
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
    let migration_retry = RetryPolicy::migrations_from_policy(&cfg.policy);
    cfg.domains
        .iter()
        .map(|(d, dc)| {
            DomainPool::connect_lazy(d.clone(), dc, retry)
                .map(|p| p.with_migration_retry(migration_retry))
                .map_err(|e| format!("cs: {e}"))
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
    let kms = open_kms(&cfg)?;
    let api = cfg
        .api
        .clone()
        .ok_or("cs: the api role needs an [api] section")?;
    let mut barriers: Vec<Arc<dyn ReadinessBarrier>> = Vec::new();
    let mut identity_pool = None;
    for pool in pools(&cfg)? {
        if pool.domain() == &DomainId::Identity {
            identity_pool = Some(pool.clone());
        }
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
    // Identity routes (M1 contract §2, §3) need the identity domain and a KMS.
    let mut routes = cs_api::public_routes();
    match (identity_pool, kms) {
        (Some(pool), Some(kms)) => {
            let auth = cs_identity::auth::AuthService::new(
                pool,
                Arc::new(kms),
                &api.deployment_domain,
                cs_identity::session::SessionPolicy::from_policy(&cfg.policy),
            );
            // DPoP replay store (M1 contract §3 [R6]): Valkey first, dpop_jti table fallback.
            let auth = match &cfg.valkey {
                Some(v) => auth
                    .with_valkey(v.url.expose_secret())
                    .map_err(|e| format!("cs: invalid valkey.url: {e}"))?,
                None => {
                    tracing::warn!(
                        "[valkey] not configured: the DPoP replay check runs on the database (dpop_jti) only"
                    );
                    auth
                }
            };
            // Rate limits (M1 contract §5, rev 11): Valkey counters, local buckets at limit/N
            // ([cluster] node_count) when Valkey is unavailable; never unlimited.
            let limits = cs_identity::ratelimit::RateLimits::from_policy(
                &cfg.policy,
                cfg.cluster.node_count,
            );
            let limiter = cs_identity::ratelimit::RateLimiter::new(
                limits,
                cfg.valkey.as_ref().map(|v| v.url.expose_secret().as_str()),
            )
            .map_err(|e| format!("cs: invalid valkey.url: {e}"))?;
            let auth = auth.with_rate_limiter(limiter);
            routes = routes.merge(cs_identity::http::routes(Arc::new(auth)));
        }
        _ => tracing::warn!(
            "identity routes disabled: they need [domains.identity] and a [kms] section"
        ),
    }
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
        cs_api::with_middleware(routes, state.clone(), max_body),
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

/// Render an Appendix D error for the operator (code, detail, field errors; never the cause's
/// secrets: causes are driver errors, which carry no bearer material here).
fn admin_error(e: &cs_common::Error) -> String {
    let mut s = format!("cs admin: {}", e.code());
    if let Some(d) = e.detail() {
        s.push_str(&format!(": {d}"));
    }
    for f in e.field_errors() {
        s.push_str(&format!(" [{}]", f.code));
    }
    if let Some(c) = e.cause() {
        s.push_str(&format!(" (cause: {c})"));
    }
    s
}

fn member_of(member: Uuid, kind: MemberKindArg) -> Result<Member, String> {
    let bad = |e: cs_common::id::IdError| format!("cs admin: invalid --member: {e}");
    Ok(match kind {
        MemberKindArg::User => Member::User(UserId::from_uuid(member).map_err(bad)?),
        MemberKindArg::Group => Member::Group(GroupId::from_uuid(member).map_err(bad)?),
    })
}

async fn admin(path: &Path, action: AdminCmd) -> Result<(), String> {
    let cfg = load(path)?;
    let dc = cfg
        .domains
        .get(&DomainId::Identity)
        .ok_or("cs admin: no [domains.identity] configured")?;
    let pool = DomainPool::connect_lazy(
        DomainId::Identity,
        dc,
        RetryPolicy::from_policy(&cfg.policy),
    )
    .map_err(|e| format!("cs admin: {e}"))?;
    let res = admin_run(&pool, &cfg.policy, action).await;
    pool.close().await;
    res
}

async fn admin_run(
    pool: &DomainPool,
    policy: &cs_common::config::Policy,
    action: AdminCmd,
) -> Result<(), String> {
    // Refuse to write into a schema this binary does not match (J.4 step 3 runs first).
    let set = migration_set(&DomainId::Identity)?;
    let status = Migrator::status(pool, &set)
        .await
        .map_err(|e| format!("cs admin: identity domain: {e}"))?;
    if !status.is_current() {
        return Err(format!(
            "cs admin: identity domain migrations pending {:?}; run `cs migrate --config <file>` first",
            status.pending
        ));
    }
    let a = IdentityAdmin::with_policy(pool.clone(), policy).map_err(|e| admin_error(&e))?;
    let err = |e: AdminError| admin_error(&e);
    match action {
        AdminCmd::Tenant(TenantCmd::Create { name }) => {
            let t = a.create_tenant(&name).await.map_err(err)?;
            println!("tenant_id={}", t.tenant_id);
        }
        AdminCmd::User(UserCmd::Create {
            tenant,
            login,
            kind,
            display_name,
        }) => {
            let kind = match kind {
                KindArg::Member => UserKind::Member,
                KindArg::Guest => UserKind::Guest,
            };
            let u = a
                .create_user(
                    tenant,
                    NewUser {
                        login,
                        kind,
                        display_name,
                    },
                )
                .await
                .map_err(err)?;
            println!(
                "user_id={}\nlogin={}\nstatus={}",
                u.user_id,
                u.login,
                u.status.as_str()
            );
        }
        AdminCmd::Group(GroupCmd::Create { tenant, name }) => {
            let g = a.create_group(tenant, &name).await.map_err(err)?;
            println!(
                "group_id={}\nmembership_version={}",
                g.group_id, g.membership_version
            );
        }
        AdminCmd::Group(GroupCmd::AddMember {
            tenant,
            group,
            member,
            kind,
            expected_version,
        }) => {
            let c = a
                .add_member(tenant, group, member_of(member, kind)?, expected_version)
                .await
                .map_err(err)?;
            println!("membership_version={}", c.membership_version);
        }
        AdminCmd::Group(GroupCmd::RemoveMember {
            tenant,
            group,
            member,
            kind,
            expected_version,
        }) => {
            let c = a
                .remove_member(tenant, group, member_of(member, kind)?, expected_version)
                .await
                .map_err(err)?;
            println!("membership_version={}", c.membership_version);
        }
        AdminCmd::SetupLink { tenant, user } => {
            let l = a.issue_setup_link(tenant, user).await.map_err(err)?;
            // The token is a bearer secret: printed once to stdout for the operator, never
            // logged.
            println!(
                "setup_token={}\nexpires_at={}\nrevoked_previous={}",
                l.token.expose_secret(),
                l.expires_at,
                l.revoked_previous
            );
        }
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
        Cmd::Admin { config, action } => rt.block_on(admin(&config, action)),
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
