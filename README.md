# Cloud System (Aethattice)

Self-hosted modular workspace platform in Rust, implemented from
[`Cloud_System_Workspace_Platform_Specification.md`](Cloud_System_Workspace_Platform_Specification.md) (source of truth).

> **Status: pre-alpha, not production-ready.** See `docs/IMPLEMENTATION_PLAN.md` for scope and
> `docs/traceability.md` for the status of every requirement. The sealed object format is
> non-production-stable until independent cryptographic review (spec R4).

## Layout
- `crates/` — Rust workspace (`cs` single binary + core domain crates)
- `web/` — Lit + Vite + TypeScript UI SDK, shared components and web shell
- `dev/` — docker-compose for YugabyteDB and Valkey
- `docs/` — plan, spec errata, frozen contracts, traceability matrix

## Develop
```sh
docker compose -f dev/docker-compose.yml up -d
scripts/ci.sh            # fmt, clippy, unit tests, web, traceability lint
scripts/ci.sh --with-db  # plus DB integration tests
```
