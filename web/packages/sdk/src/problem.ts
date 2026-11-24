// RFC 9457 problem details as specified by App. D.1 and contract M0 §2.
import {
  D2_STATUSES,
  ERROR_CODE_TABLE,
  isAppErrorCode,
  isCoreErrorCode,
  type CoreErrorCode,
  type ErrorCode,
} from "./errors";

export const PROBLEM_CONTENT_TYPE = "application/problem+json";

/** One field error of a validation failure (D.1 `errors[]`). */
export interface FieldError {
  /** JSON pointer (RFC 6901) into the request body. */
  readonly pointer: string;
  readonly code: string;
  readonly detail?: string;
}

/** A problem-details body (D.1). Only the fields defined by D.1 are kept; unknown members are dropped. */
export interface Problem {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly code: ErrorCode;
  readonly detail?: string;
  readonly instance?: string;
  readonly request_id?: string;
  readonly retryable: boolean;
  readonly retry_after_ms?: number;
  readonly errors?: readonly FieldError[];
  readonly consistency_token?: string;
}

export type ProblemParseResult =
  | { readonly ok: true; readonly problem: Problem }
  | { readonly ok: false; readonly reason: string };

/** Context from the HTTP response used to complete or cross-check the body. */
export interface ProblemContext {
  /** HTTP status of the response; the body's `status` must equal it. */
  readonly httpStatus?: number;
  /** `X-Request-Id` header, used when the body lacks `request_id`. */
  readonly requestId?: string;
  /** Parsed `Retry-After` header in ms, used when the body lacks `retry_after_ms`. */
  readonly retryAfterMs?: number;
}

const MAX_TEXT = 4096;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function optString(obj: Record<string, unknown>, key: string): string | undefined | null {
  const v = obj[key];
  if (v === undefined) return undefined;
  if (typeof v !== "string" || v.length > MAX_TEXT) return null;
  return v;
}

/**
 * Validates an already-JSON-decoded value as a D.1 problem.
 * Rejects the body (ok: false) when any member has the wrong type, when the code is not a D.2 or
 * well-formed application code, or when `status`/`retryable` disagree with table D.2 or the HTTP status.
 */
export function parseProblem(input: unknown, ctx: ProblemContext = {}): ProblemParseResult {
  const fail = (reason: string): ProblemParseResult => ({ ok: false, reason });
  if (!isRecord(input)) return fail("body is not a JSON object");

  const { code, status, retryable, title, type } = input;
  if (typeof code !== "string") return fail("code missing");
  if (!isCoreErrorCode(code) && !isAppErrorCode(code)) return fail("unknown code");
  if (typeof type !== "string" || type.length === 0 || type.length > MAX_TEXT) return fail("type missing");
  if (typeof title !== "string" || title.length === 0 || title.length > MAX_TEXT) return fail("title missing");
  if (typeof status !== "number" || !Number.isInteger(status)) return fail("status missing");
  if (typeof retryable !== "boolean") return fail("retryable missing");

  if (isCoreErrorCode(code)) {
    const info = ERROR_CODE_TABLE[code];
    if (info.status !== status) return fail("status does not match code");
    if (info.retryable !== retryable) return fail("retryable does not match code");
  } else if (!D2_STATUSES.has(status)) {
    return fail("application code mapped to a status outside D.2");
  }
  if (ctx.httpStatus !== undefined && ctx.httpStatus !== status) return fail("status does not match HTTP status");

  const detail = optString(input, "detail");
  const instance = optString(input, "instance");
  const requestId = optString(input, "request_id");
  const consistencyToken = optString(input, "consistency_token");
  if (detail === null || instance === null || requestId === null || consistencyToken === null) {
    return fail("optional member has the wrong type");
  }

  let retryAfterMs: number | undefined;
  const rawRetryAfter = input.retry_after_ms;
  if (rawRetryAfter !== undefined) {
    if (typeof rawRetryAfter !== "number" || !Number.isSafeInteger(rawRetryAfter) || rawRetryAfter < 0) {
      return fail("retry_after_ms is not a non-negative integer");
    }
    retryAfterMs = rawRetryAfter;
  } else {
    retryAfterMs = ctx.retryAfterMs;
  }

  let errors: FieldError[] | undefined;
  const rawErrors = input.errors;
  if (rawErrors !== undefined) {
    if (!Array.isArray(rawErrors) || rawErrors.length > 1000) return fail("errors is not an array");
    errors = [];
    for (const e of rawErrors as unknown[]) {
      if (!isRecord(e)) return fail("field error is not an object");
      const pointer = e.pointer;
      const fcode = e.code;
      const fdetail = optString(e, "detail");
      if (typeof pointer !== "string" || typeof fcode !== "string" || fdetail === null) {
        return fail("field error has the wrong shape");
      }
      errors.push(fdetail === undefined ? { pointer, code: fcode } : { pointer, code: fcode, detail: fdetail });
    }
  }

  const finalRequestId = requestId ?? ctx.requestId;
  const problem: Problem = {
    type,
    title,
    status,
    code,
    retryable,
    ...(detail !== undefined && { detail }),
    ...(instance !== undefined && { instance }),
    ...(finalRequestId !== undefined && { request_id: finalRequestId }),
    ...(retryAfterMs !== undefined && { retry_after_ms: retryAfterMs }),
    ...(errors !== undefined && { errors }),
    ...(consistencyToken !== undefined && { consistency_token: consistencyToken }),
  };
  return { ok: true, problem };
}

/** Codes the client itself produces when the server did not send a usable problem. */
export type SynthesizedCode = Extract<CoreErrorCode, "internal" | "unavailable" | "timeout">;

const SYNTH_TITLES: Record<SynthesizedCode, string> = {
  internal: "Internal error",
  unavailable: "Service unavailable",
  timeout: "Request timed out",
};

/**
 * Builds a client-side problem. It never contains the raw response body or exception text:
 * `detail` is omitted so nothing internal can reach the UI.
 * `type` is `about:blank` because the client does not know the deployment's error domain.
 */
export function synthesizeProblem(
  code: SynthesizedCode,
  opts: { requestId?: string | undefined; instance?: string | undefined; retryAfterMs?: number | undefined } = {},
): Problem {
  const info = ERROR_CODE_TABLE[code];
  return {
    type: "about:blank",
    title: SYNTH_TITLES[code],
    status: info.status,
    code,
    retryable: info.retryable,
    ...(opts.instance !== undefined && { instance: opts.instance }),
    ...(opts.requestId !== undefined && { request_id: opts.requestId }),
    ...(opts.retryAfterMs !== undefined && { retry_after_ms: opts.retryAfterMs }),
  };
}

/** Code used for an error response whose body is not a valid problem (proxy pages, plain text, ...). */
export function codeForNonProblemStatus(httpStatus: number): SynthesizedCode {
  return httpStatus === 502 || httpStatus === 503 || httpStatus === 504 ? "unavailable" : "internal";
}

/** True when a Content-Type header value names application/problem+json (parameters ignored). */
export function isProblemContentType(contentType: string | null | undefined): boolean {
  if (!contentType) return false;
  return contentType.split(";")[0]?.trim().toLowerCase() === PROBLEM_CONTENT_TYPE;
}

/** Thrown by {@link ApiClient} for every failed request. Carries a validated or synthesized Problem. */
export class ApiError extends Error {
  readonly problem: Problem;
  /** HTTP status actually received, or undefined for network failures and client timeouts. */
  readonly httpStatus: number | undefined;
  /** True when the problem was built by the client rather than received from the server. */
  readonly synthesized: boolean;
  /** Number of attempts made, including the failed one. */
  readonly attempts: number;

  constructor(problem: Problem, opts: { httpStatus?: number | undefined; synthesized: boolean; attempts: number }) {
    // The message carries only the code and request id, never detail or raw bodies.
    super(`${problem.code}${problem.request_id ? ` (request ${problem.request_id})` : ""}`);
    this.name = "ApiError";
    this.problem = problem;
    this.httpStatus = opts.httpStatus;
    this.synthesized = opts.synthesized;
    this.attempts = opts.attempts;
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

/** `errors[].code` that marks an `unauthenticated` problem as a step-up request (contract M1 §2.3 [R2], §6.1). */
export const STEP_UP_REQUIRED_CODE = "step_up_required";

/** True when the problem is `unauthenticated` with an `errors[]` entry `step_up_required` (contract M1 §2.3 [R2]). */
export function isStepUpProblem(problem: Problem): boolean {
  return problem.code === "unauthenticated" && (problem.errors ?? []).some((e) => e.code === STEP_UP_REQUIRED_CODE);
}

/**
 * Thrown instead of a plain {@link ApiError} when a sensitive operation needs recent strong authentication
 * (contract M1 §2.3 [R2], M0 contract rev 5). Refreshing the access token cannot satisfy it, so the client
 * never refreshes for it; the UI runs a WebAuthn assertion or asks for the password again, then retries.
 * It is still an ApiError, so generic error handling keeps working.
 */
export class StepUpRequired extends ApiError {
  constructor(problem: Problem, opts: { httpStatus?: number | undefined; synthesized: boolean; attempts: number }) {
    super(problem, opts);
    this.name = "StepUpRequired";
  }
}

export function isStepUpRequired(e: unknown): e is StepUpRequired {
  return e instanceof StepUpRequired;
}
