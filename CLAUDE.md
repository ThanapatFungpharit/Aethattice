# Project rules for agents

- The spec (`Cloud_System_Workspace_Platform_Specification.md` + `docs/SPEC_ERRATA.md`) is the source of truth. Never silently simplify, omit or deviate. If something cannot be done as specified, stop and report it to the Team Leader.
- Contracts in `docs/contracts/` are frozen per milestone. Do not change them on your own; propose changes to the Team Leader.
- No single-node assumptions in contracts (IDs, tokens, receipts, vectors, placement, cursors, domain boundaries).
- One transaction touches exactly one domain (App. C, C1). Cross-domain work is a saga. No network calls inside DB transactions.
- Every requirement you implement or test gets its row in `docs/traceability.md` updated in the same change (status, code path, test names). Never mark anything `production-ready`.
- Never claim durability the hardware does not have (dev host = one NVMe = one failure domain).
- Rust: no `unsafe`, no `unwrap`/`expect` outside tests, errors map to Appendix D codes. Web: strict TS, no backend implementation details in components.
- Run `scripts/ci.sh` (and `--with-db` for DB work) before reporting a task done; report failures honestly with output.
- Commits end with: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
