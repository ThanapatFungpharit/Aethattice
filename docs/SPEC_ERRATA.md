# Specification Errata

Approved by the project owner on 2026-11-19. Applied to `Cloud_System_Workspace_Platform_Specification.md`, which is now v2.4.1. The original v2.4 text is in the initial commit (`8516e28`), and `git diff 8516e28 -- Cloud_System_Workspace_Platform_Specification.md` shows every change.

| ID | Issue | Resolution | Spec locations changed |
|---|---|---|---|
| C1 | Seal's final state was `superseded` in §17.4 but `retired` in F.4 | `retired` is canonical. `superseded` is only a compatibility synonym for seals. Version state `superseded` (F.2) is unrelated and unchanged. | §17.4 step 7 |
| C2 | §6.7 (signed ancestry handle, depth 256, no protected fallback) conflicted with H.5 ("64 ancestors, 1-minute tokens") | §6.7 wins. The H.5 note is replaced. No weaker token form exists for protected data at any supported depth. | §6.7, H.5 |
| C3 | "W" still appeared after W=R was made mandatory | W ≡ R is defined everywhere. | §17.3, §17.5 step 4, §25.2, H.3.1 |
| C4 | A "Warm" tier was referenced but never defined | Exactly four tiers: Hot, Standard, Cold, Archive. The Warm compression rule (Zstandard) applies to Standard. | §17.3, §17.3.2 |
| C5 | F.5 had no `installed → removing` and did not model failures, upgrades or rollbacks | Added `installed → removing`, plus explicit install, upgrade and rollback saga states. A plugin is usable only when `enabled` with a completed saga, so partially installed plugins can never be usable. The saga state names were designed by the Team Leader under this approval; they are open to owner review. | F.5 |
| C6 | F.3 did not say what happens when a session expires while finalizing | Expiry does not apply in `finalizing`. The session resolves only by pivot proof (§17.5 step 8). | F.3 |
| C7 | "UPSERT" is not PostgreSQL syntax | UPSERT = `INSERT … ON CONFLICT`. | §8.3 |
| C8 | No signature algorithm was given for several signed artifacts | Ed25519 for every signed artifact, with a separate domain-separation context per artifact type and canonical serialization. HMAC artifacts stay HMAC. | §6.4 |
| C9 | Part footers said "appendices A–L" | Normalized to A–M. | Part 2 and Part 3 footers |
| C10 | The custom crypto format had no explicit stability status | Explicitly non-production-stable until independent review. Test vectors and fuzzing are required. | §17.2 |

## Process for future errata

1. A team member finds a conflict, ambiguity or necessary deviation and reports it to the Team Leader.
2. The Team Leader proposes a resolution to the project owner. **Nothing is applied before owner approval.**
3. Once approved, the change is applied to the spec in its own commit, recorded here, and linked from the affected rows of `docs/traceability.md`.
