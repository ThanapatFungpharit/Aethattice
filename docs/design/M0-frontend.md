# M0 Frontend Foundations: design

- Scope: contract `docs/contracts/M0-foundations.md` §2 (error model, client side) and §10 (frontend foundations); spec §3.5, §14, App. D.
- Code: `web/` (npm workspaces `packages/sdk`, `packages/components`, `apps/shell`; lint toolchain in `web/tools/lint`).
- Status: implemented and unit-tested. Nothing here is production-ready.

## 1. `@cs/sdk`

### 1.1 Error codes (`errors.ts`)

| Export | Meaning |
|---|---|
| `CORE_ERROR_CODES` | The 19 D.2 codes, in table order. |
| `CoreErrorCode` | String-literal union of those codes (snake_case wire values). |
| `AppErrorCode` | `` `app.${string}.${string}` `` (coarse static type). `isAppErrorCode` is the real validator. |
| `ErrorCode` | `CoreErrorCode \| AppErrorCode`. |
| `ERROR_CODE_TABLE` | Frozen `Record<CoreErrorCode, { status, retryable }>` from D.2. |
| `D2_STATUSES` | The set of statuses in D.2. Application codes must use one of them. |
| `isCoreErrorCode`, `isAppErrorCode`, `isErrorCode`, `parseAppErrorCode`, `errorCodeInfo` | Guards and helpers. |

Application code grammar (design, the spec does not define application IDs): `app.` + one or more dot-separated segments `[a-z0-9]([a-z0-9-]*[a-z0-9])?` (the application ID, so reverse-DNS IDs work) + `.` + a snake_case code `[a-z][a-z0-9_]*`. The last segment is always the code. Max 255 characters.

### 1.2 Problems (`problem.ts`)

- `Problem`: the D.1 members only (`type`, `title`, `status`, `code`, `detail?`, `instance?`, `request_id?`, `retryable`, `retry_after_ms?`, `errors?`, `consistency_token?`).
- `parseProblem(json, { httpStatus?, requestId?, retryAfterMs? })` returns `{ ok: true, problem }` or `{ ok: false, reason }`. It rejects:
  - non-objects, unknown codes, missing or wrong-typed required members (`type`, `title`, `status`, `code`, `retryable`);
  - a core code whose `status` or `retryable` disagrees with D.2 (contract §2: they "can never be set independently");
  - an application code whose status is outside D.2;
  - a body `status` that differs from the HTTP status;
  - wrong-typed optional members, negative or fractional `retry_after_ms`, malformed `errors[]`, strings longer than 4 KiB.
  - Unknown members are dropped. `request_id` falls back to `X-Request-Id`, and `retry_after_ms` falls back to `Retry-After`.
- `synthesizeProblem(code)` for `internal | unavailable | timeout`: the D.2 status and retryability, `type: "about:blank"` (the client does not know the deployment's error domain), and **no `detail`**. Raw bodies and exception text never enter a Problem.
- `codeForNonProblemStatus(status)`: 502/503/504 → `unavailable`, anything else → `internal`.
- `ApiError extends Error`: `{ problem, httpStatus, synthesized, attempts }`. Its `message` is only `code (request <id>)`.

### 1.3 `ApiClient` (`client.ts`)

```ts
new ApiClient({ baseUrl, fetch?, retryPolicy?, clock?, timeoutMs? = 30_000, auth?, idempotencyKeyFactory?, headers? })
client.get/post/put/patch/delete<T>(path, { query?, body?, headers?, signal?, timeoutMs?, idempotencyKey?, retry?, decode? })
  → Promise<ApiResponse<T>>  // { status, data, requestId, headers, attempts }
```

- `baseUrl` must be absolute, with no query or fragment. `path` must start with a single `/`. Absolute, protocol-relative and backslash paths are refused, so credentials never leave the configured origin. The client knows nothing about backend internals.
- Bodies are JSON. `Accept: application/json, application/problem+json`.
- Errors:
  - `application/problem+json` that passes `parseProblem` → that problem.
  - Anything else (invalid JSON, wrong media type, HTML proxy pages, bodies over 64 KiB) → synthesized problem.
  - Network failure → `unavailable`.
  - Per-attempt timeout → `timeout`.
  - Malformed success JSON, or a `decode` that throws → `internal`.
- Caller abort (`signal`) rejects with the signal's reason unchanged and stops retrying, including during backoff sleeps.
- `X-Request-Id` is captured on success (`requestId`) and on errors (`problem.request_id` fallback).
- Writes (POST/PUT/PATCH/DELETE): an `Idempotency-Key` is generated per call (`idempotencyKey()`) and reused for every retry of that call. Callers may pass their own key. `idempotencyKey: null` sends none, and such a write is never retried.
- `AuthHook { authorization?(); refresh(): Promise<boolean> }`. On `unauthenticated` the client calls `refresh()` once. If it returns true, it retries once outside the retry budget, and a second `unauthenticated` is surfaced. A write without an idempotency key is not refresh-retried. M0 ships no hook; M1 wires the shell token store.

### 1.4 `RetryPolicy` (`retry.ts`)

- Options: `maxAttempts` (default 5, including the first), `initialDelayMs` (200), `maxDelayMs` (30 000), `random` (injectable). `Clock { now(), sleep(ms, signal) }` is injected into `ApiClient` (`systemClock` by default).
- `backoffMs(n) = floor(random() * min(maxDelayMs, initialDelayMs * 2^n))`, which is full jitter.
- `decide({ problem, attempt, isWrite, idempotencyKey })` checks these in order:
  1. not `retryable` → stop;
  2. write without key → stop;
  3. attempts exhausted → stop;
  4. `retry_after_ms` > cap → stop (design choice, see §5);
  5. otherwise delay = `max(backoff, retry_after_ms)`.
- `parseRetryAfter` accepts delta-seconds and IMF-fixdate.

### 1.5 Idempotency (`idempotency.ts`)

`idempotencyKey()` uses `crypto.randomUUID()` and throws when it is unavailable. There is no Math.random fallback, in line with §17.2. `isValidIdempotencyKey` checks 1..255 visible ASCII characters (contract §5.3).

### 1.6 Localization (`i18n.ts`)

- `t(key, params?)` interpolates `{name}` placeholders. Lookup order is locale (`th-th`) → language (`th`) → `en` → the key itself, so a missing key is visible.
- `registerMessages(locale, catalog)` lets the shell and applications add keys. `setLocale` / `getLocale` / `onLocaleChange` notify components, which re-render through `LocaleController`.
- `EN_MESSAGES` holds the core keys, with a title and description for every D.2 code plus `error.app.*` for application codes. `problemMessageKeys(code)` picks the keys for a Problem.

### 1.7 Design tokens (`tokens.ts`)

- `tokensCss()` returns the stylesheet and `installTokens(document)` installs it once.
- Theme: `data-theme="light|dark"` on `<html>` wins, otherwise `prefers-color-scheme`. Under `prefers-reduced-motion: reduce`, the fast and normal motion durations are 0.
- All names are prefixed `--cs-`.

| Group | Tokens |
|---|---|
| Color (`--cs-color-*`, light and dark) | `bg`, `surface`, `surface-raised`, `text`, `text-muted`, `border`, `border-strong`, `primary`, `primary-hover`, `on-primary`, `danger`, `danger-hover`, `on-danger`, `danger-surface`, `danger-text`, `success-surface`, `success-text`, `focus-ring`, `backdrop` |
| Typography | `font-family`, `font-family-mono`, `font-size-sm/md/lg/xl`, `line-height-tight/normal`, `font-weight-regular/medium/bold` |
| Spacing | `space-0` … `space-7` (0 to 3rem) |
| Radii | `radius-sm/md/lg/full` |
| Focus | `focus-ring-width` (2px), `focus-ring-offset` (2px) |
| Motion | `motion-duration-fast/normal/spin`, `motion-easing-standard` |
| Sizes | `target-min` (40px), `content-max-width` |

`CONTRAST_REQUIREMENTS` lists every foreground/background pair the components render:
- 4.5:1 for text (SC 1.4.3);
- 3:1 for borders, focus indicators and the spinner arc (SC 1.4.11).

`tokens.test.ts` computes WCAG contrast for every pair in both themes. `contrastRatio` and `relativeLuminance` are exported, so install-time checks (§14.6) can reuse them.

## 2. `@cs/components`

Importing `@cs/components` registers every element. Components import only public `@cs/sdk` exports (`t`, `Problem`, `problemMessageKeys`, `onLocaleChange`). They use tokens only, re-render on locale change, and show a 2px focus ring through `:focus-visible`.

| Element | API | Keyboard and screen reader behavior |
|---|---|---|
| `cs-button` | `variant` (primary/secondary/danger/ghost), `type` (button/submit/reset), `disabled`, `busy`, `label`; default slot | Native `<button>` inside the shadow root with `delegatesFocus`, so Enter/Space work natively. `label` is the aria-label for icon-only buttons. `disabled` is native. `busy` keeps the button focusable, sets `aria-busy` and `aria-disabled`, swallows activation and shows a decorative spinner. `submit`/`reset` act on the closest form. Minimum target is 40×40 px. |
| `cs-text-field` | `label`, `description`, `error`, `value`, `name`, `type`, `required`, `disabled`, `readonly`, `autocomplete`; events `input` (composed) and `change` (re-dispatched) | `<label for>` is tied to the input. `aria-describedby` lists the description and the error. An error sets `aria-invalid="true"` and `aria-errormessage`. The error sits in a polite live region, with an icon plus text, so it is not signalled by color alone. The visible "(required)" marker is `aria-hidden`; native `required` provides `aria-required`. Form-associated through ElementInternals where available. |
| `cs-dialog` | `open`, `heading`; `show()`, `close()`, `requestClose(reason)`; default and `footer` slots; events `cs-request-close` (cancelable) and `cs-close` | `role="dialog"`, `aria-modal="true"`, `aria-labelledby` pointing at the heading. On open, focus goes to the slotted `[autofocus]`, else the first tabbable element in the body or footer, else the panel. Tab and Shift+Tab cycle through the close button, body and footer, including through slots and nested shadow roots. Focus that escapes is pulled back. Escape, the close button and a backdrop click all request closing. On close, focus returns to the element that opened the dialog. |
| `cs-error-banner` | `problem: Problem`, `dismissible`; event `cs-dismiss` (cancelable) | `role="alert"`. The title and description are localized by code (generic text for `app.*` codes); the server's `title` is never shown. `detail` and `errors[].detail` are shown only for 4xx responses, where D.1 guarantees localized, caller-visible text; for 5xx they are never shown. `request_id` appears as "Reference:" with a copy button (only where the clipboard API exists) and a polite "Reference copied" status. |
| `cs-spinner` | `label`, `size` (small/medium), `decorative` | `role="status"` with `aria-live="polite"` and a visually hidden localized label (default "Loading…"). `decorative` hides it from assistive technology (used inside a busy `cs-button`). Under `prefers-reduced-motion` it shows a static dotted ring instead of rotating. |

Helpers: `LocaleController`, `tabbableElements(root)`, `deepActiveElement()`.

## 3. Shell (`apps/shell`)

- `cs-shell-app` provides:
  - a skip link;
  - a `<header>` with the product name and `<nav aria-label="Global">` containing the launcher button, which opens a placeholder `cs-dialog`;
  - a notifications `<section>` with a polite `role="log"`;
  - a `<main>` region.
- The home route checks `GET /readyz` through `ApiClient` (3 attempts, 10 s timeout) and shows one of: a spinner, "ready", or "not ready" with `cs-error-banner`. An absent backend is reported through the error model as `unavailable`.
- `#/dev/errors` (the link is shown only in dev builds) is the developer page. It shows sample Problems (4xx with detail, validation errors, rate_limited, a 5xx whose detail must stay hidden, outcome_unknown, an app code) and buttons that drive the real `ApiClient` against a simulated misbehaving server. It also has a text field, dialog and spinner demo.
- The base URL comes from `VITE_CS_API_BASE_URL`, defaulting to the page origin. The Vite dev server proxies `/readyz`, `/healthz` and `/api` to `CS_DEV_BACKEND` (default `http://127.0.0.1:8080`, an assumption because no port is fixed yet). Proxy errors return 502 with no body, which the client maps to `unavailable`.

## 4. Tooling

- `npm run typecheck` (tsc 7 `-b`), `npm test` (vitest + happy-dom), `npm run build` (Vite), `npm run lint`.
- **Lint toolchain is a separate npm project** in `web/tools/lint` with its own lockfile. typescript-eslint 8.x requires the TypeScript ≤ 6.0 compiler API (`typescript <6.1.0`, or `@typescript/native` ≥ 7.1 beta), but the workspace builds with TypeScript 7.0.2, which has no JS API. As a workspace member, npm hoisted `ts-api-utils` next to TypeScript 7 and lint crashed. `tools/lint/run.mjs` runs `npm ci` there when needed, then runs ESLint with these configs:
  - `strictTypeChecked` and `stylisticTypeChecked`;
  - `eslint-plugin-lit` and `eslint-plugin-lit-a11y` recommended;
  - `no-console`;
  - `unbound-method` off for Lit files, because Lit binds listeners to the host.

  TypeScript 6 is used only for linting.
- `scripts/ci.sh` web step: `typecheck && lint && test && build`.

## 5. Decisions and open points

1. **Core-code problems that disagree with D.2** (status or retryable) are treated as malformed and replaced by a synthesized problem. The alternative was to normalize them to the table.
2. **`retry_after_ms` above the 30 s cap** stops retrying and surfaces the error. Waiting beyond the cap would break the cap, and retrying sooner would ignore the server.
3. **Synthesized problems** use `type: "about:blank"` and have no `detail`. `ApiError.synthesized` marks them.
4. **Non-problem error responses** map to `unavailable` for 502/503/504 and network failures, `timeout` for client-side timeouts, and `internal` for everything else, including non-problem 4xx bodies from intermediaries. `internal` is retryable per D.2, so such responses are retried (bounded; writes only with their key).
5. **Readiness success body**: contract §7 does not define one, so only the status is used.
6. **Error banner `detail`**: shown for 4xx only, as explained in §2.
7. **WCAG**: the automated checks are token contrast, ARIA wiring, keyboard trap and focus restore in happy-dom. No manual or assistive-technology audit has been done, and none in a real browser, so `14.6-01` stays `in-progress`.
8. **The dialog does not set `inert` on the background or lock scrolling.** It relies on `aria-modal`, the focus trap and the backdrop. Revisit with the shell layout in M1.
