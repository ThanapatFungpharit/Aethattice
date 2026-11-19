// Appendix D.2 error codes (contract M0 §2). The wire values are the snake_case strings below.
// Codes are part of the API contract (App. L): never remove or repurpose an entry within a major version.

/** Every core error code from spec table D.2, in table order. */
export const CORE_ERROR_CODES = [
  "invalid_request",
  "unauthenticated",
  "permission_denied",
  "not_found",
  "method_not_allowed",
  "conflict",
  "resource_trashed",
  "precondition_failed",
  "payload_too_large",
  "unsupported_media_type",
  "idempotency_mismatch",
  "locked",
  "rate_limited",
  "quota_exceeded",
  "internal",
  "dependency_unavailable",
  "unavailable",
  "timeout",
  "outcome_unknown",
] as const;

/** A core error code from table D.2. */
export type CoreErrorCode = (typeof CORE_ERROR_CODES)[number];

/**
 * An application-defined code in the namespace `app.<application id>.<code>` (D.3).
 * The template type is a coarse static check; {@link isAppErrorCode} is the authoritative validator.
 */
export type AppErrorCode = `app.${string}.${string}`;

/** Any code that may appear in a problem body. */
export type ErrorCode = CoreErrorCode | AppErrorCode;

export interface ErrorCodeInfo {
  /** HTTP status the code is always sent with. */
  readonly status: number;
  /** True when the same request may succeed later without change. */
  readonly retryable: boolean;
}

/** Table D.2: status and retryability derived from the code. They can never be set independently. */
export const ERROR_CODE_TABLE: Readonly<Record<CoreErrorCode, ErrorCodeInfo>> = Object.freeze({
  invalid_request: { status: 400, retryable: false },
  unauthenticated: { status: 401, retryable: false },
  permission_denied: { status: 403, retryable: false },
  not_found: { status: 404, retryable: false },
  method_not_allowed: { status: 405, retryable: false },
  conflict: { status: 409, retryable: false },
  resource_trashed: { status: 409, retryable: false },
  precondition_failed: { status: 412, retryable: false },
  payload_too_large: { status: 413, retryable: false },
  unsupported_media_type: { status: 415, retryable: false },
  idempotency_mismatch: { status: 422, retryable: false },
  locked: { status: 423, retryable: false },
  rate_limited: { status: 429, retryable: true },
  quota_exceeded: { status: 507, retryable: false },
  internal: { status: 500, retryable: true },
  dependency_unavailable: { status: 503, retryable: true },
  unavailable: { status: 503, retryable: true },
  timeout: { status: 504, retryable: true },
  outcome_unknown: { status: 504, retryable: true },
});

/** The HTTP statuses that appear in D.2. Application codes must map to one of them (D.3). */
export const D2_STATUSES: ReadonlySet<number> = new Set(Object.values(ERROR_CODE_TABLE).map((i) => i.status));

const CORE_SET: ReadonlySet<string> = new Set(CORE_ERROR_CODES);

// app.<application id>.<code>
// The application id is one or more dot-separated lowercase segments (so reverse-DNS ids such as
// `com.example.photos` are accepted); the final segment is the code itself, snake_case.
const APP_CODE_RE = /^app\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z][a-z0-9_]*$/;

export function isCoreErrorCode(value: unknown): value is CoreErrorCode {
  return typeof value === "string" && CORE_SET.has(value);
}

export function isAppErrorCode(value: unknown): value is AppErrorCode {
  return typeof value === "string" && value.length <= 255 && APP_CODE_RE.test(value);
}

export function isErrorCode(value: unknown): value is ErrorCode {
  return isCoreErrorCode(value) || isAppErrorCode(value);
}

/** Splits an application code into its application id and local code. */
export function parseAppErrorCode(code: AppErrorCode): { applicationId: string; code: string } | undefined {
  if (!isAppErrorCode(code)) return undefined;
  const rest = code.slice("app.".length);
  const dot = rest.lastIndexOf(".");
  return { applicationId: rest.slice(0, dot), code: rest.slice(dot + 1) };
}

/** Status and retryability for a core code (table D.2). */
export function errorCodeInfo(code: CoreErrorCode): ErrorCodeInfo {
  return ERROR_CODE_TABLE[code];
}
