// Account security over the M1 identity HTTP contract: own sessions (§3, rev 10), recovery codes (rev 10/11),
// recovery requests seen from a signed-in device (rev 10), and the account recovery flows (§4, [R5], rev 10).
import type { AuthResult } from "./auth";
import type { ApiClient } from "./client";
import { IdentityInputError, normalizeRecoveryCode, register, tenantFromGrant, type IdentityDeps } from "./identity";

export const SESSIONS_PATH = "/api/v2/me/sessions";
export const RECOVERY_CODES_PATH = "/api/v2/me/recovery-codes";
export const RECOVERY_REQUESTS_PATH = "/api/v2/me/recovery-requests";
export const RECOVERY_START_PATH = "/api/v2/auth/recovery/start";
export const RECOVERY_STATUS_PATH = "/api/v2/auth/recovery/status";

type Json = Record<string, unknown>;

function isRecord(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(r: Json, k: string): string {
  const v = r[k];
  if (typeof v !== "string" || v.length === 0) throw new TypeError(`${k} missing`);
  return v;
}

/** Rev 10 addendum: every timestamp in a body is an RFC 3339 UTC string. */
function time(r: Json, k: string): string {
  const v = str(r, k);
  if (Number.isNaN(Date.parse(v))) throw new TypeError(`${k} must be RFC 3339`);
  return v;
}

function timeOrNull(r: Json, k: string): string | null {
  return r[k] === null || r[k] === undefined ? null : time(r, k);
}

function strOrNull(r: Json, k: string): string | null {
  const v = r[k];
  if (v === null || v === undefined) return null;
  if (typeof v !== "string") throw new TypeError(`${k} must be a string or null`);
  return v;
}

function items<T>(body: unknown, f: (v: unknown) => T): T[] {
  if (!isRecord(body) || !Array.isArray(body.items)) throw new TypeError("items missing");
  return body.items.map(f);
}

function opt(signal: AbortSignal | undefined): { signal?: AbortSignal } {
  return signal !== undefined ? { signal } : {};
}

// ---- sessions ----

/** One of the user's sessions (rev 10). */
export interface SessionInfo {
  readonly sid: string;
  readonly created_at: string;
  readonly last_seen_at: string;
  readonly amr: readonly string[];
  readonly user_agent: string | null;
  readonly current: boolean;
}

export function decodeSessionInfo(v: unknown): SessionInfo {
  if (!isRecord(v)) throw new TypeError("session: not an object");
  const { amr, current } = v;
  if (!Array.isArray(amr) || !amr.every((m): m is string => typeof m === "string")) throw new TypeError("amr must be strings");
  if (typeof current !== "boolean") throw new TypeError("current must be a boolean");
  return { sid: str(v, "sid"), created_at: time(v, "created_at"), last_seen_at: time(v, "last_seen_at"), amr, user_agent: strOrNull(v, "user_agent"), current };
}

/** `GET /api/v2/me/sessions` (rev 10): bounded per user, not paginated. */
export async function listSessions(authedClient: ApiClient, signal?: AbortSignal): Promise<SessionInfo[]> {
  const r = await authedClient.get(SESSIONS_PATH, { decode: (b) => items(b, decodeSessionInfo), ...opt(signal) });
  return r.data;
}

/**
 * `DELETE /api/v2/me/sessions/{sid}` (rev 10) → 204. Revoking another session needs step-up (StepUpRequired);
 * revoking the current one acts as logout, so the caller then ends the local session.
 */
export async function revokeSession(authedClient: ApiClient, sid: string, signal?: AbortSignal): Promise<void> {
  await authedClient.delete(`${SESSIONS_PATH}/${encodeURIComponent(sid)}`, opt(signal));
}

// ---- recovery codes ----

/** Rev 11: a set has 10 codes. */
export const RECOVERY_CODE_SET_SIZE = 10;

export function decodeRecoveryCodes(body: unknown): string[] {
  if (!isRecord(body) || !Array.isArray(body.codes)) throw new TypeError("codes missing");
  const codes = body.codes.map((c) => {
    if (typeof c !== "string") throw new TypeError("code must be a string");
    return normalizeRecoveryCode(c);
  });
  if (codes.length !== RECOVERY_CODE_SET_SIZE) throw new TypeError("a recovery code set has 10 codes");
  return codes;
}

/** `POST /api/v2/me/recovery-codes` (step-up) → a new set, replacing the old one. Shown once; never stored. */
export async function generateRecoveryCodes(authedClient: ApiClient, signal?: AbortSignal): Promise<string[]> {
  const r = await authedClient.post(RECOVERY_CODES_PATH, { body: {}, decode: decodeRecoveryCodes, ...opt(signal) });
  return r.data;
}

/** `GET /api/v2/me/recovery-codes` → how many unused codes remain. */
export async function remainingRecoveryCodes(authedClient: ApiClient, signal?: AbortSignal): Promise<number> {
  const r = await authedClient.get(RECOVERY_CODES_PATH, {
    decode: (b) => {
      if (!isRecord(b) || typeof b.remaining !== "number" || !Number.isInteger(b.remaining) || b.remaining < 0) throw new TypeError("remaining");
      return b.remaining;
    },
    ...opt(signal),
  });
  return r.data;
}

// ---- recovery requests (from a signed-in device) ----

export type RecoveryMethod = "email" | "device_approval";

/** A pending or granted recovery request of the signed-in user (rev 10 addendum). */
export interface RecoveryRequestInfo {
  readonly id: string;
  readonly method: RecoveryMethod;
  readonly state: "pending" | "granted";
  readonly created_at: string;
  readonly available_at: string | null;
  readonly requester_user_agent: string | null;
}

export function decodeRecoveryRequest(v: unknown): RecoveryRequestInfo {
  if (!isRecord(v)) throw new TypeError("recovery request: not an object");
  const { method, state } = v;
  if (method !== "email" && method !== "device_approval") throw new TypeError("method");
  if (state !== "pending" && state !== "granted") throw new TypeError("state");
  return {
    id: str(v, "id"),
    method,
    state,
    created_at: time(v, "created_at"),
    available_at: timeOrNull(v, "available_at"),
    requester_user_agent: strOrNull(v, "requester_user_agent"),
  };
}

export async function listRecoveryRequests(authedClient: ApiClient, signal?: AbortSignal): Promise<RecoveryRequestInfo[]> {
  const r = await authedClient.get(RECOVERY_REQUESTS_PATH, { decode: (b) => items(b, decodeRecoveryRequest), ...opt(signal) });
  return r.data;
}

/** `POST …/{id}/approve` (step-up) → 204. Approval counts as the second factor and skips the waiting period. */
export async function approveRecoveryRequest(authedClient: ApiClient, id: string, signal?: AbortSignal): Promise<void> {
  await authedClient.post(`${RECOVERY_REQUESTS_PATH}/${encodeURIComponent(id)}/approve`, { body: {}, ...opt(signal) });
}

/** `DELETE …/{id}` → 204 (state becomes `cancelled`). Allowed from any session of the user. */
export async function cancelRecoveryRequest(authedClient: ApiClient, id: string, signal?: AbortSignal): Promise<void> {
  await authedClient.delete(`${RECOVERY_REQUESTS_PATH}/${encodeURIComponent(id)}`, opt(signal));
}

// ---- recovery flows (signed out) ----

export type RecoveryRemoteState = "pending" | "granted" | "expired" | "cancelled" | "completed";

export interface RecoveryStatus {
  readonly state: RecoveryRemoteState;
  readonly available_at?: string;
  readonly grant?: string;
  readonly grant_expires_in?: number;
  readonly recovery_txn?: string;
}

const REMOTE_STATES: readonly string[] = ["pending", "granted", "expired", "cancelled", "completed"];

export function decodeRecoveryStatus(body: unknown): RecoveryStatus {
  if (!isRecord(body) || typeof body.state !== "string" || !REMOTE_STATES.includes(body.state)) throw new TypeError("recovery state");
  const state = body.state as RecoveryRemoteState;
  const gx = body.grant_expires_in;
  if (gx !== undefined && (typeof gx !== "number" || !Number.isInteger(gx) || gx <= 0)) throw new TypeError("grant_expires_in");
  const grant = body.grant === undefined ? undefined : str(body, "grant");
  if (state === "granted" && grant === undefined) throw new TypeError("granted without grant");
  return {
    state,
    ...(body.available_at !== undefined && body.available_at !== null && { available_at: time(body, "available_at") }),
    ...(grant !== undefined && { grant }),
    ...(typeof gx === "number" && { grant_expires_in: gx }),
    ...(body.recovery_txn !== undefined && { recovery_txn: str(body, "recovery_txn") }),
  };
}

/** Phases of the recovery page. Secrets (`grant`, `token`, `recovery_txn`) stay in memory only. */
export type RecoveryPhase =
  | { readonly kind: "idle" }
  /** Email sent if the account exists (the answer is the same either way). */
  | { readonly kind: "email_sent" }
  /** Waiting for the email waiting period, or for another device to approve. */
  | { readonly kind: "waiting"; readonly method: RecoveryMethod; readonly available_at?: string }
  /** A grant is held; the user chooses the new password. */
  | { readonly kind: "granted"; readonly grant_expires_in?: number }
  | { readonly kind: "done" }
  | { readonly kind: "expired" }
  | { readonly kind: "cancelled" };

/**
 * State machine of the account recovery pages (§4, [R5], rev 10):
 * - recovery code: `start {method: "recovery_code", code}` → granted at once;
 * - email: `start {method: "email"}` → email_sent; the link opens the page with a token → `status {token, code?}` →
 *   waiting (until `available_at`) → granted;
 * - device approval: `start {method: "device_approval"}` → waiting → `status {recovery_txn}` → granted;
 * - granted → `complete(login, password)`: `register/start {grant, …}` → `register/finish` → normal sign-in → done.
 * An expired or used grant answers `unauthenticated` and the user starts over.
 */
export class RecoveryFlow {
  private readonly deps: IdentityDeps;
  private phaseValue: RecoveryPhase = { kind: "idle" };
  private grant: string | undefined;
  private token: string | undefined;
  private mfaCode: string | undefined;
  private recoveryTxn: string | undefined;
  tenant = "";
  login = "";

  constructor(deps: IdentityDeps) {
    this.deps = deps;
  }

  get phase(): RecoveryPhase {
    return this.phaseValue;
  }

  /** Recovery code: no waiting period (rev 10). Wrong, used or unknown → `unauthenticated` (indistinguishable). */
  async startWithCode(tenant: string, login: string, code: string, signal?: AbortSignal): Promise<void> {
    const c = normalizeRecoveryCode(code);
    const s = await this.start(tenant, login, { method: "recovery_code", code: c }, signal);
    this.apply(s, "email");
  }

  async startEmail(tenant: string, login: string, signal?: AbortSignal): Promise<void> {
    await this.start(tenant, login, { method: "email" }, signal);
    this.phaseValue = { kind: "email_sent" };
  }

  async startDeviceApproval(tenant: string, login: string, signal?: AbortSignal): Promise<void> {
    const s = await this.start(tenant, login, { method: "device_approval" }, signal);
    if (s.recovery_txn === undefined) throw new TypeError("recovery_txn missing");
    this.recoveryTxn = s.recovery_txn;
    this.apply(s, "device_approval");
  }

  /**
   * Opened from the emailed link. `code` is a recovery code, required for users with MFA (rev 10 (b)).
   * The token stays in memory for later polls.
   */
  async openEmailLink(token: string, code?: string, signal?: AbortSignal): Promise<void> {
    this.token = token.trim();
    if (this.token.length === 0) throw new IdentityInputError("setup_link");
    this.mfaCode = code !== undefined && code.trim().length > 0 ? normalizeRecoveryCode(code) : undefined;
    await this.poll(signal);
  }

  /** One status call for the current request; the page calls it on a timer while `waiting`. */
  async poll(signal?: AbortSignal): Promise<void> {
    let body: Json;
    let method: RecoveryMethod;
    if (this.recoveryTxn !== undefined) {
      body = { recovery_txn: this.recoveryTxn };
      method = "device_approval";
    } else if (this.token !== undefined) {
      body = { token: this.token, ...(this.mfaCode !== undefined && { code: this.mfaCode }) };
      method = "email";
    } else {
      return;
    }
    const r = await this.deps.client.post(RECOVERY_STATUS_PATH, { body, decode: decodeRecoveryStatus, ...opt(signal) });
    this.apply(r.data, method);
  }

  /**
   * Completes recovery with the grant ([R5]): registers the new password and signs in. The login is the one the
   * user enters (the grant's tenant is taken from the grant). Rejects with ApiError `unauthenticated` for a used
   * or expired grant; the flow then moves to `expired`.
   */
  async complete(login: string, newPassword: string, signal?: AbortSignal): Promise<AuthResult> {
    const grant = this.grant;
    if (grant === undefined || this.phaseValue.kind !== "granted") throw new Error("no recovery grant");
    try {
      // The grant names its tenant (§3 [R8]); needed for the link path, where the user never typed it here.
      this.tenant = tenantFromGrant(grant);
      const r = await register(this.deps, grant, login, newPassword, signal);
      this.forget();
      this.phaseValue = { kind: "done" };
      return r;
    } catch (e) {
      if (isRecord(e) && (e as { problem?: { code?: unknown } }).problem?.code === "unauthenticated") {
        this.forget();
        this.phaseValue = { kind: "expired" };
      }
      throw e;
    }
  }

  /** Back to the start; drops every secret. */
  reset(): void {
    this.forget();
    this.phaseValue = { kind: "idle" };
  }

  private forget(): void {
    this.grant = undefined;
    this.token = undefined;
    this.mfaCode = undefined;
    this.recoveryTxn = undefined;
  }

  private async start(tenant: string, login: string, extra: Json, signal?: AbortSignal): Promise<RecoveryStatus> {
    const normalized = await this.deps.engine.normalizeLogin(login).catch(() => {
      throw new IdentityInputError("login");
    });
    this.tenant = tenant;
    this.login = normalized;
    this.forget();
    const r = await this.deps.client.post(RECOVERY_START_PATH, { body: { tenant, login: normalized, ...extra }, decode: decodeRecoveryStatus, ...opt(signal) });
    return r.data;
  }

  private apply(s: RecoveryStatus, method: RecoveryMethod): void {
    switch (s.state) {
      case "granted":
        this.grant = s.grant;
        this.phaseValue = { kind: "granted", ...(s.grant_expires_in !== undefined && { grant_expires_in: s.grant_expires_in }) };
        return;
      case "pending":
        this.phaseValue = { kind: "waiting", method, ...(s.available_at !== undefined && { available_at: s.available_at }) };
        return;
      case "completed":
        this.forget();
        this.phaseValue = { kind: "done" };
        return;
      case "expired":
      case "cancelled":
        this.forget();
        this.phaseValue = { kind: s.state };
        return;
    }
  }
}
