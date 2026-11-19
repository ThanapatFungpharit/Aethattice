# Requirement Traceability Matrix

Source: Cloud_System_Workspace_Platform_Specification.md (v2.4 + errata, docs/SPEC_ERRATA.md).

Status values: `implemented` (code exists) · `tested` (code + passing tests named in the row) · `production-ready` (tested + reviewed for production; nothing in M0–M3 qualifies) · `in-progress` · `deferred(Mn)` · `n/a(reason)`.
`scripts/trace-lint.sh` enforces that every row has a valid status.

Populated during M0 by the QA Engineer and Team Leader.

| ID | Spec ref | Requirement | Milestone | Status | Code | Tests |
|---|---|---|---|---|---|---|
| D.1-01 | App. D.1 | Client parses RFC 9457 problem+json, validates shape against D.1/D.2, drops unknown members; invalid or non-problem error bodies become a synthesized `internal`/`unavailable` problem with no raw body (frontend) | M0 | tested | web/packages/sdk/src/problem.ts, web/packages/sdk/src/client.ts | problem.test.ts: "parseProblem > rejects malformed body: *", "keeps optional D.1 members and drops unknown members"; client.test.ts: "ApiClient error model > *" |
| D.2-01 | App. D.2 | `ErrorCode` string-literal union and status/retryable table exactly as D.2 (frontend) | M0 | tested | web/packages/sdk/src/errors.ts | errors.test.ts: "ErrorCode table (D.2) > *" |
| D.2-02 | App. D.2 | `unauthenticated`: client refreshes once and retries once (hook only in M0; wired to real auth in M1) | M0 | tested | web/packages/sdk/src/client.ts (AuthHook) | client.test.ts: "ApiClient unauthenticated hook > *" |
| D.3-01 | App. D.3 | Client retries only retryable errors, exponential backoff with full jitter (200 ms initial, 30 s cap), honours retry_after_ms / Retry-After, bounded attempts (default 5) | M0 | tested | web/packages/sdk/src/retry.ts, web/packages/sdk/src/client.ts | retry.test.ts: "full-jitter exponential backoff > *", "decide > *", "parseRetryAfter > *"; client.test.ts: "ApiClient retries (D.3) > *" |
| D.3-02 | App. D.3 | Client sends Idempotency-Key on writes (crypto.randomUUID) and retries writes only with the same key; writes without a key are never retried | M0 | tested | web/packages/sdk/src/idempotency.ts, web/packages/sdk/src/client.ts | client.test.ts: "retries writes with the same Idempotency-Key", "never retries a * without an idempotency key"; i18n.test.ts: "idempotencyKey > *" |
| D.3-03 | App. D.3 | Application codes `app.<application id>.<code>` accepted by the client type, mapped to a D.2 status (frontend) | M0 | tested | web/packages/sdk/src/errors.ts, web/packages/sdk/src/problem.ts | errors.test.ts: "application codes app.<id>.<code> (D.3) > *"; problem.test.ts: "accepts application codes mapped to a D.2 status, retryable from body" |
| 14.1-01 | §14.1 | Web shell: launcher, global navigation, notifications, main region (M0 skeleton only; sign-in, search, account menu, routing to apps in later milestones) | M0 | in-progress | web/apps/shell/src/cs-shell-app.ts | shell.test.ts: "cs-shell-app > *" |
| 14.3-01 | §14.3 | TypeScript UI SDK: authenticated API clients, theme and localization (M0: ApiClient, error model, tokens, t(); realtime client, CRDT bindings, message API and intents not started) | M0 | in-progress | web/packages/sdk/src/ | sdk *.test.ts |
| 14.3-02 | §14.3 | Shared components (M0 base set: cs-button, cs-text-field, cs-dialog, cs-error-banner, cs-spinner; share dialog, pickers etc. later) | M0 | in-progress | web/packages/components/src/ | components.test.ts |
| 14.3-03 | §14.3 | Design tokens (colors, typography, spacing, radii, focus, motion) as CSS custom properties, light and dark | M0 | tested | web/packages/sdk/src/tokens.ts | tokens.test.ts: "tokensCss > *" |
| 14.6-01 | §14.6 | Core UI and shared components meet WCAG 2.2 AA (M0: token contrast checked for both themes; ARIA, keyboard and focus behavior unit-tested; no manual/assistive-technology audit yet) | M0 | in-progress | web/packages/sdk/src/tokens.ts, web/packages/components/src/ | tokens.test.ts: "* theme meets WCAG 2.2 AA > *"; components.test.ts: "cs-dialog > traps Tab and Shift+Tab", "cs-text-field > wires the error with aria-invalid, aria-describedby, aria-errormessage and a live region" |
| 14.6-02 | §14.6 | All user-facing strings localized through the SDK (M0: t() with catalogs and locale fallback, used by every component and the shell; application-shipped translations arrive with plugins) | M0 | tested | web/packages/sdk/src/i18n.ts, web/apps/shell/src/messages.ts | i18n.test.ts: "t() > *"; components.test.ts: "re-localizes when the locale changes"; shell.test.ts: "shell messages > are all registered" |
