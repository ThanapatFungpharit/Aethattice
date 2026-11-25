// Password sign-in, registration and sign-out over the M1 identity HTTP contract (rev 5 §2.1, §2.3, §2.4, §3).
// The OPAQUE cryptography runs in an {@link OpaqueEngine} (opaque-ke in WASM); this module only speaks HTTP and
// hands the resulting session to {@link AuthSession}. The password never leaves the client.
import { decodeAuthResult, type AuthResult, type AuthSession } from "./auth";
import type { ApiClient } from "./client";
import { errorCodeInfo } from "./errors";
import { ApiError, type Problem } from "./problem";
import {
  OpaqueClientError,
  base64urlDecode,
  base64urlEncode,
  decodeKsfParams,
  type KsfParams,
  type OpaqueEngine,
  type OpaqueFlow,
} from "./opaque";

export const OPAQUE_LOGIN_START_PATH = "/api/v2/auth/opaque/login/start";
export const OPAQUE_LOGIN_FINISH_PATH = "/api/v2/auth/opaque/login/finish";
export const OPAQUE_REGISTER_START_PATH = "/api/v2/auth/opaque/register/start";
export const OPAQUE_REGISTER_FINISH_PATH = "/api/v2/auth/opaque/register/finish";
export const OPAQUE_REAUTH_START_PATH = "/api/v2/auth/opaque/reauth/start";
export const OPAQUE_REAUTH_FINISH_PATH = "/api/v2/auth/opaque/reauth/finish";
export const LOGOUT_PATH = "/api/v2/auth/logout";
export const ME_PATH = "/api/v2/me";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(r: Record<string, unknown>, k: string): string {
  const v = r[k];
  if (typeof v !== "string" || v.length === 0) throw new TypeError(`${k} missing`);
  return v;
}

function bytes(r: Record<string, unknown>, k: string): Uint8Array {
  return base64urlDecode(str(r, k));
}

// ---- response decoders (contract shapes) ----

export interface LoginStartResponse {
  readonly login_txn: string;
  readonly credential_response: Uint8Array;
  readonly ksf_params: KsfParams;
}

export function decodeLoginStart(body: unknown): LoginStartResponse {
  if (!isRecord(body)) throw new TypeError("login/start: not an object");
  return { login_txn: str(body, "login_txn"), credential_response: bytes(body, "credential_response"), ksf_params: decodeKsfParams(body.ksf_params) };
}

export interface RegisterStartResponse {
  readonly registration_txn: string;
  readonly registration_response: Uint8Array;
  readonly ksf_params: KsfParams;
}

export function decodeRegisterStart(body: unknown): RegisterStartResponse {
  if (!isRecord(body)) throw new TypeError("register/start: not an object");
  return {
    registration_txn: str(body, "registration_txn"),
    registration_response: bytes(body, "registration_response"),
    ksf_params: decodeKsfParams(body.ksf_params),
  };
}

export interface ReauthStartResponse {
  readonly reauth_txn: string;
  readonly credential_response: Uint8Array;
  readonly ksf_params: KsfParams;
}

export function decodeReauthStart(body: unknown): ReauthStartResponse {
  if (!isRecord(body)) throw new TypeError("reauth/start: not an object");
  return { reauth_txn: str(body, "reauth_txn"), credential_response: bytes(body, "credential_response"), ksf_params: decodeKsfParams(body.ksf_params) };
}

/** `GET /api/v2/me` (rev 7). */
export interface Me {
  readonly user_id: string;
  readonly tenant_id: string;
  readonly login: string;
  readonly display_name: string;
  readonly state: string;
  readonly amr: readonly string[];
  /** Unix seconds. */
  readonly auth_time: number;
  readonly sid: string;
}

export function decodeMe(body: unknown): Me {
  if (!isRecord(body)) throw new TypeError("me: not an object");
  const { amr, auth_time, display_name } = body;
  if (!Array.isArray(amr) || !amr.every((m): m is string => typeof m === "string")) throw new TypeError("amr must be strings");
  if (typeof auth_time !== "number" || !Number.isInteger(auth_time) || auth_time < 0) throw new TypeError("auth_time must be unix seconds");
  if (typeof display_name !== "string") throw new TypeError("display_name missing");
  return {
    user_id: str(body, "user_id"),
    tenant_id: str(body, "tenant_id"),
    login: str(body, "login"),
    display_name,
    state: str(body, "state"),
    amr,
    auth_time,
    sid: str(body, "sid"),
  };
}

/** `{state: "mfa_required", auth_txn, methods}` (§2.3). */
export interface MfaChallenge {
  readonly state: "mfa_required";
  readonly auth_txn: string;
  readonly methods: readonly string[];
}

export function decodeLoginFinish(body: unknown): AuthResult | MfaChallenge {
  if (isRecord(body) && body.state === "mfa_required") {
    const methods = body.methods;
    if (!Array.isArray(methods) || !methods.every((m): m is string => typeof m === "string")) {
      throw new TypeError("methods must be strings");
    }
    return { state: "mfa_required", auth_txn: str(body, "auth_txn"), methods };
  }
  return decodeAuthResult(body);
}

// ---- errors ----

/**
 * Sign-in needs a second factor (§2.3). Completing it (`webauthn/assert` or a recovery code) is a later slice;
 * the UI tells the user and offers no session.
 */
export class MfaRequired extends Error {
  readonly challenge: MfaChallenge;
  constructor(challenge: MfaChallenge) {
    super("mfa_required");
    this.name = "MfaRequired";
    this.challenge = challenge;
  }
}

export function isMfaRequired(e: unknown): e is MfaRequired {
  return e instanceof MfaRequired;
}

/** Input the client rejects before any request. `field` names the form field to mark. */
export type IdentityInputField = "tenant" | "login" | "password" | "setup_link";

export class IdentityInputError extends Error {
  readonly field: IdentityInputField;
  constructor(field: IdentityInputField) {
    super(`invalid ${field}`);
    this.name = "IdentityInputError";
    this.field = field;
  }
}

export function isIdentityInputError(e: unknown): e is IdentityInputError {
  return e instanceof IdentityInputError;
}

/**
 * A failed OPAQUE finish on the client (wrong password or unknown account, RFC 9807) is reported exactly like the
 * server's answer for that case (§6: `unauthenticated`, same detail), so the UI cannot tell them apart either.
 */
function clientUnauthenticated(): ApiError {
  const info = errorCodeInfo("unauthenticated");
  const problem: Problem = { type: "about:blank", title: "Unauthenticated", status: info.status, code: "unauthenticated", retryable: info.retryable };
  return new ApiError(problem, { synthesized: true, attempts: 1 });
}

// ---- helpers ----

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Rev 5 §2.1: `tenant` is the canonical (lowercase, hyphenated) tenant UUID. */
export function isCanonicalTenantId(s: string): boolean {
  return CANONICAL_UUID.test(s);
}

function uuidFromBytes(b: Uint8Array): string {
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Tenant of an `rt1.<tenant_id base64url>.<256-bit random base64url>` grant (§3 [R8], rev 5 §2.1: the tenant comes
 * from the grant). The segment is not trusted by the server; it only selects the tenant for this client.
 */
export function tenantFromGrant(grant: string): string {
  const parts = grant.split(".");
  if (parts.length !== 3 || parts[0] !== "rt1") throw new IdentityInputError("setup_link");
  try {
    const tenant = base64urlDecode(parts[1] ?? "");
    const secret = base64urlDecode(parts[2] ?? "");
    if (tenant.length !== 16 || secret.length !== 32) throw new IdentityInputError("setup_link");
    return uuidFromBytes(tenant);
  } catch {
    throw new IdentityInputError("setup_link");
  }
}

const encoder = new TextEncoder();

/** Password bytes: UTF-8 of the string as typed. Zeroed by the caller after use. */
function passwordBytes(password: string): Uint8Array {
  if (password.length === 0) throw new IdentityInputError("password");
  return encoder.encode(password);
}

async function startFlow(engine: OpaqueEngine, kind: "login" | "registration", pw: Uint8Array, tenant: string, login: string): Promise<OpaqueFlow> {
  try {
    return await engine.start(kind, pw, tenant, login);
  } catch (e) {
    // The engine validates tenant and login before any crypto; the tenant was checked already.
    if (e instanceof OpaqueClientError) throw new IdentityInputError("login");
    throw e;
  }
}

async function finishFlow(flow: OpaqueFlow, pw: Uint8Array, response: Uint8Array, ksf: KsfParams): Promise<Uint8Array> {
  try {
    return await flow.finish(pw, response, ksf);
  } catch (e) {
    if (e instanceof OpaqueClientError) {
      // invalid_login: wrong password or unknown account. invalid_input: a response the client refuses
      // (malformed, or KSF below the minimum at registration): also not a usable authentication.
      throw clientUnauthenticated();
    }
    throw e;
  }
}

// ---- flows ----

export interface IdentityDeps {
  /**
   * Client for the auth endpoints. It needs no auth hook; {@link signOut}, {@link reauthenticate} and
   * {@link getMe} use `authedClient`. When the session is DPoP-bound (rev 8) its `dpop` prover must be the
   * session's key manager, so that `login/finish` carries a proof.
   */
  readonly client: ApiClient;
  readonly engine: OpaqueEngine;
  readonly session: AuthSession;
}

/**
 * OPAQUE sign-in (§2.1): `login/start` → Argon2id + KE3 in WASM → `login/finish`. On `authenticated` the result is
 * handed to the session (§2.4). Rejects with ApiError (`unauthenticated` for wrong password or unknown account,
 * `rate_limited`, …), {@link MfaRequired}, or {@link IdentityInputError}.
 */
export async function signIn(deps: IdentityDeps, tenant: string, login: string, password: string, signal?: AbortSignal): Promise<AuthResult> {
  if (!isCanonicalTenantId(tenant)) throw new IdentityInputError("tenant");
  const normalized = await normalizeOrThrow(deps.engine, login);
  const pw = passwordBytes(password);
  let flow: OpaqueFlow | undefined;
  try {
    flow = await startFlow(deps.engine, "login", pw, tenant, normalized);
    const start = await deps.client.post(OPAQUE_LOGIN_START_PATH, {
      body: { tenant, login: normalized, credential_request: base64urlEncode(flow.request) },
      decode: decodeLoginStart,
      ...(signal !== undefined && { signal }),
    });
    const fin = await finishFlow(flow, pw, start.data.credential_response, start.data.ksf_params);
    const keys = deps.session.dpopKeys;
    const finish = async (): Promise<AuthResult | MfaChallenge> => {
      // Rev 8: a new key pair for the new session, created before login/finish and shared by all tabs; the
      // proof on login/finish binds the session and its refresh family to it.
      await keys?.rotate();
      const r = await deps.client.post(OPAQUE_LOGIN_FINISH_PATH, {
        body: { login_txn: start.data.login_txn, credential_finalization: base64urlEncode(fin) },
        decode: decodeLoginFinish,
        ...(keys !== undefined && { dpop: true }),
        ...(signal !== undefined && { signal }),
      });
      if (r.data.state === "authenticated") deps.session.signedIn(r.data);
      return r.data;
    };
    // Under the cross-tab lock, so no other tab refreshes or signs in between the key change and the new token.
    const result = keys ? await deps.session.exclusive(finish) : await finish();
    if (result.state === "mfa_required") throw new MfaRequired(result);
    return result;
  } finally {
    flow?.abandon();
    pw.fill(0);
  }
}

/**
 * Registration from a setup link (§2.1 rev 5): `register/start {grant, login, registration_request}` →
 * `register/finish {registration_txn, registration_upload}` (204, consumes the grant) → a normal {@link signIn},
 * because only `login/finish` issues sessions.
 */
export async function register(deps: IdentityDeps, setupLinkToken: string, login: string, password: string, signal?: AbortSignal): Promise<AuthResult> {
  const grant = setupLinkToken.trim();
  const tenant = tenantFromGrant(grant);
  const normalized = await normalizeOrThrow(deps.engine, login);
  const pw = passwordBytes(password);
  let flow: OpaqueFlow | undefined;
  try {
    flow = await startFlow(deps.engine, "registration", pw, tenant, normalized);
    const start = await deps.client.post(OPAQUE_REGISTER_START_PATH, {
      body: { grant, login: normalized, registration_request: base64urlEncode(flow.request) },
      decode: decodeRegisterStart,
      ...(signal !== undefined && { signal }),
    });
    const upload = await finishFlow(flow, pw, start.data.registration_response, start.data.ksf_params);
    await deps.client.post(OPAQUE_REGISTER_FINISH_PATH, {
      body: { registration_txn: start.data.registration_txn, registration_upload: base64urlEncode(upload) },
      ...(signal !== undefined && { signal }),
    });
  } finally {
    flow?.abandon();
    pw.fill(0);
  }
  return signIn(deps, tenant, normalized, password, signal);
}

/**
 * Logout (§3 [R10]): authenticated by the access token, so `authedClient` must carry the session as its auth hook.
 * The local token is dropped on success, and also on `unauthenticated` (the session is already gone). Any other
 * failure is rethrown and the user stays signed in, because the server session would still be valid.
 */
export async function signOut(authedClient: ApiClient, session: AuthSession, signal?: AbortSignal): Promise<void> {
  try {
    await authedClient.post(LOGOUT_PATH, { ...(signal !== undefined && { signal }) });
  } catch (e) {
    if (!(e instanceof ApiError && e.problem.code === "unauthenticated")) throw e;
  }
  // Also deletes the session's DPoP key (rev 8); the next sign-in creates a new one.
  await session.signedOut();
}

/**
 * Password step-up on the existing session (rev 7): `opaque/reauth/start {credential_request}` → Argon2id + KE3 →
 * `opaque/reauth/finish {reauth_txn, credential_finalization}` → 204. Both calls carry the current access token
 * (and a DPoP proof when bound) through `authedClient`. The server sets `last_strong_auth_at` on the current
 * session; no session, token or DPoP key is created or changed here. A wrong password rejects with ApiError
 * `unauthenticated`, as for sign-in.
 */
export async function reauthenticate(
  deps: Pick<IdentityDeps, "engine">,
  authedClient: ApiClient,
  tenant: string,
  login: string,
  password: string,
  signal?: AbortSignal,
): Promise<void> {
  if (!isCanonicalTenantId(tenant)) throw new IdentityInputError("tenant");
  const normalized = await normalizeOrThrow(deps.engine, login);
  const pw = passwordBytes(password);
  let flow: OpaqueFlow | undefined;
  try {
    // The client identifier is `<tenant>/<normalized login>` of the signed-in user, as at sign-in.
    flow = await startFlow(deps.engine, "login", pw, tenant, normalized);
    const start = await authedClient.post(OPAQUE_REAUTH_START_PATH, {
      body: { credential_request: base64urlEncode(flow.request) },
      decode: decodeReauthStart,
      ...(signal !== undefined && { signal }),
    });
    const fin = await finishFlow(flow, pw, start.data.credential_response, start.data.ksf_params);
    await authedClient.post(OPAQUE_REAUTH_FINISH_PATH, {
      body: { reauth_txn: start.data.reauth_txn, credential_finalization: base64urlEncode(fin) },
      ...(signal !== undefined && { signal }),
    });
  } finally {
    flow?.abandon();
    pw.fill(0);
  }
}

/** `GET /api/v2/me` (rev 7) for the account page. */
export async function getMe(authedClient: ApiClient, signal?: AbortSignal): Promise<Me> {
  const r = await authedClient.get(ME_PATH, { decode: decodeMe, ...(signal !== undefined && { signal }) });
  return r.data;
}

async function normalizeOrThrow(engine: OpaqueEngine, login: string): Promise<string> {
  try {
    return await engine.normalizeLogin(login);
  } catch (e) {
    if (e instanceof OpaqueClientError) throw new IdentityInputError("login");
    throw e;
  }
}
