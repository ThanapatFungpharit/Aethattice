// WebAuthn passkeys over the M1 identity HTTP contract (§2.2, §2.3, rev 10 wire shapes).
// Options and credentials travel in the WebAuthn L3 JSON forms with every binary as base64url without padding.
// The browser API (navigator.credentials) is used directly; this module converts between the JSON forms and the
// ArrayBuffer forms the API takes. PRF outputs never leave the client (§2.2): only `prf.enabled` is reported.
import { decodeAuthResult, type AuthResult } from "./auth";
import type { ApiClient } from "./client";
import { afterMfa, issueSession, type IdentityDeps, type MfaRequired } from "./identity";
import { base64urlDecode, base64urlEncode } from "./opaque";

export const WEBAUTHN_REGISTER_START_PATH = "/api/v2/auth/webauthn/register/start";
export const WEBAUTHN_REGISTER_FINISH_PATH = "/api/v2/auth/webauthn/register/finish";
export const WEBAUTHN_LOGIN_START_PATH = "/api/v2/auth/webauthn/login/start";
export const WEBAUTHN_LOGIN_FINISH_PATH = "/api/v2/auth/webauthn/login/finish";
export const WEBAUTHN_ASSERT_START_PATH = "/api/v2/auth/webauthn/assert/start";
export const WEBAUTHN_ASSERT_FINISH_PATH = "/api/v2/auth/webauthn/assert/finish";
export const PASSKEYS_PATH = "/api/v2/me/passkeys";

type Json = Record<string, unknown>;

function isRecord(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(r: Json, k: string): string {
  const v = r[k];
  if (typeof v !== "string" || v.length === 0) throw new TypeError(`${k} missing`);
  return v;
}

function rfc3339(r: Json, k: string): string {
  const v = str(r, k);
  if (Number.isNaN(Date.parse(v))) throw new TypeError(`${k} must be an RFC 3339 timestamp`);
  return v;
}

function buf(b64: unknown, what: string): ArrayBuffer {
  if (typeof b64 !== "string") throw new TypeError(`${what} must be base64url`);
  const u = base64urlDecode(b64);
  const out = new ArrayBuffer(u.byteLength);
  new Uint8Array(out).set(u);
  return out;
}

function enc(b: ArrayBuffer | ArrayBufferView): string {
  return base64urlEncode(b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength));
}

// ---- errors ----

/** The user dismissed the browser prompt, it timed out, or no matching passkey was chosen (NotAllowedError). */
export class WebAuthnCancelled extends Error {
  constructor() {
    super("webauthn cancelled");
    this.name = "WebAuthnCancelled";
  }
}

/** This browser or context offers no WebAuthn, or the authenticator refused the request. */
export class WebAuthnUnavailable extends Error {
  constructor(message = "webauthn unavailable") {
    super(message);
    this.name = "WebAuthnUnavailable";
  }
}

export function isWebAuthnCancelled(e: unknown): e is WebAuthnCancelled {
  return e instanceof WebAuthnCancelled;
}

export function isWebAuthnUnavailable(e: unknown): e is WebAuthnUnavailable {
  return e instanceof WebAuthnUnavailable;
}

// ---- browser API ----

/** The subset of `navigator.credentials` used here; tests pass a fake. */
export interface CredentialsLike {
  create(options: CredentialCreationOptions): Promise<Credential | null>;
  get(options: CredentialRequestOptions): Promise<Credential | null>;
}

/** `navigator.credentials` when the page can use WebAuthn, else undefined. */
export function browserCredentials(g: typeof globalThis = globalThis): CredentialsLike | undefined {
  const nav = (g as { navigator?: { credentials?: CredentialsLike } }).navigator;
  const hasPkc = typeof (g as { PublicKeyCredential?: unknown }).PublicKeyCredential !== "undefined";
  return hasPkc && nav?.credentials ? nav.credentials : undefined;
}

async function callBrowser<T>(fn: () => Promise<T | null>): Promise<T> {
  let r: T | null;
  try {
    r = await fn();
  } catch (e) {
    const name = isRecord(e) || e instanceof Error ? (e as { name?: unknown }).name : undefined;
    if (name === "NotAllowedError" || name === "AbortError") throw new WebAuthnCancelled();
    throw new WebAuthnUnavailable(typeof name === "string" ? name : "webauthn error");
  }
  if (r === null) throw new WebAuthnCancelled();
  return r;
}

/** Decodes the binary members of `extensions` the server may send (PRF eval inputs); others pass through. */
function extensionsIn(ext: unknown): AuthenticationExtensionsClientInputs | undefined {
  if (!isRecord(ext)) return undefined;
  const out: Json = { ...ext };
  const prf = ext.prf;
  if (isRecord(prf) && isRecord(prf.eval)) {
    const ev: Json = { first: buf(prf.eval.first, "prf.eval.first") };
    if (prf.eval.second !== undefined) ev.second = buf(prf.eval.second, "prf.eval.second");
    out.prf = { ...prf, eval: ev };
  }
  return out;
}

/** Only non-secret extension results go to the server. PRF results (secret key material, §2.2) never do. */
function extensionsOut(cred: { getClientExtensionResults?: () => AuthenticationExtensionsClientOutputs }): Json {
  const r = cred.getClientExtensionResults?.() ?? {};
  const out: Json = {};
  const prf = (r as { prf?: { enabled?: unknown } }).prf;
  if (prf !== undefined) out.prf = typeof prf.enabled === "boolean" ? { enabled: prf.enabled } : {};
  const credProps = (r as { credProps?: { rk?: unknown } }).credProps;
  if (credProps !== undefined && typeof credProps.rk === "boolean") out.credProps = { rk: credProps.rk };
  return out;
}

function descriptors(v: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (v === undefined) return undefined;
  if (!Array.isArray(v)) throw new TypeError("credential descriptors must be an array");
  return v.map((d) => {
    if (!isRecord(d)) throw new TypeError("credential descriptor must be an object");
    return { ...(d as object), type: "public-key", id: buf(d.id, "descriptor id") };
  });
}

/** PublicKeyCredentialCreationOptionsJSON → the API form. */
export function creationOptionsFromJson(json: unknown): PublicKeyCredentialCreationOptions {
  if (!isRecord(json) || !isRecord(json.user) || !isRecord(json.rp)) throw new TypeError("public_key: not creation options");
  const exclude = descriptors(json.excludeCredentials);
  const extensions = extensionsIn(json.extensions);
  return {
    ...(json as object),
    challenge: buf(json.challenge, "challenge"),
    user: { ...(json.user as object), id: buf(json.user.id, "user.id") },
    ...(exclude !== undefined && { excludeCredentials: exclude }),
    ...(extensions !== undefined && { extensions }),
  } as PublicKeyCredentialCreationOptions;
}

/** PublicKeyCredentialRequestOptionsJSON → the API form. */
export function requestOptionsFromJson(json: unknown): PublicKeyCredentialRequestOptions {
  if (!isRecord(json)) throw new TypeError("public_key: not request options");
  const allow = descriptors(json.allowCredentials);
  const extensions = extensionsIn(json.extensions);
  return {
    ...(json as object),
    challenge: buf(json.challenge, "challenge"),
    ...(allow !== undefined && { allowCredentials: allow }),
    ...(extensions !== undefined && { extensions }),
  };
}

interface CredentialShape {
  readonly id: string;
  readonly rawId: ArrayBuffer;
  readonly type: string;
  readonly authenticatorAttachment?: string | null;
  readonly response: unknown;
  getClientExtensionResults?(): AuthenticationExtensionsClientOutputs;
}

/** An attestation result → RegistrationResponseJSON. */
export function registrationToJson(credential: Credential): Json {
  const c = credential as unknown as CredentialShape;
  const resp = c.response as {
    clientDataJSON: ArrayBuffer;
    attestationObject: ArrayBuffer;
    getTransports?: () => string[];
    getAuthenticatorData?: () => ArrayBuffer;
    getPublicKey?: () => ArrayBuffer | null;
    getPublicKeyAlgorithm?: () => number;
  };
  const pk = resp.getPublicKey?.();
  const authData = resp.getAuthenticatorData?.();
  const alg = resp.getPublicKeyAlgorithm?.();
  return {
    id: c.id,
    rawId: enc(c.rawId),
    type: c.type,
    ...(c.authenticatorAttachment != null && { authenticatorAttachment: c.authenticatorAttachment }),
    response: {
      clientDataJSON: enc(resp.clientDataJSON),
      attestationObject: enc(resp.attestationObject),
      transports: resp.getTransports?.() ?? [],
      ...(authData !== undefined && { authenticatorData: enc(authData) }),
      ...(pk != null && { publicKey: enc(pk) }),
      ...(alg !== undefined && { publicKeyAlgorithm: alg }),
    },
    clientExtensionResults: extensionsOut(c),
  };
}

/** An assertion result → AuthenticationResponseJSON. */
export function assertionToJson(credential: Credential): Json {
  const c = credential as unknown as CredentialShape;
  const resp = c.response as { clientDataJSON: ArrayBuffer; authenticatorData: ArrayBuffer; signature: ArrayBuffer; userHandle: ArrayBuffer | null };
  return {
    id: c.id,
    rawId: enc(c.rawId),
    type: c.type,
    ...(c.authenticatorAttachment != null && { authenticatorAttachment: c.authenticatorAttachment }),
    response: {
      clientDataJSON: enc(resp.clientDataJSON),
      authenticatorData: enc(resp.authenticatorData),
      signature: enc(resp.signature),
      userHandle: resp.userHandle === null ? null : enc(resp.userHandle),
    },
    clientExtensionResults: extensionsOut(c),
  };
}

// ---- response decoders ----

interface Txn {
  readonly txn: string;
  readonly public_key: unknown;
}

function decodeTxn(name: string) {
  return (body: unknown): Txn => {
    if (!isRecord(body) || !isRecord(body.public_key)) throw new TypeError(`${name}: not an object`);
    return { txn: str(body, name), public_key: body.public_key };
  };
}

/** A registered passkey (rev 10/11). `id` is the base64url credential ID. */
export interface Passkey {
  readonly id: string;
  readonly label: string;
  /** RFC 3339. */
  readonly created_at: string;
  /** RFC 3339, or null when never used. */
  readonly last_used_at: string | null;
  readonly prf: boolean;
}

export function decodePasskey(v: unknown): Passkey {
  if (!isRecord(v)) throw new TypeError("passkey: not an object");
  const { last_used_at, prf, label } = v;
  if (typeof prf !== "boolean") throw new TypeError("prf must be a boolean");
  if (typeof label !== "string") throw new TypeError("label missing");
  if (last_used_at !== null && (typeof last_used_at !== "string" || Number.isNaN(Date.parse(last_used_at)))) {
    throw new TypeError("last_used_at must be RFC 3339 or null");
  }
  return { id: str(v, "id"), label, created_at: rfc3339(v, "created_at"), last_used_at, prf };
}

export function decodePasskeyList(body: unknown): Passkey[] {
  if (!isRecord(body) || !Array.isArray(body.items)) throw new TypeError("passkeys: items missing");
  return body.items.map(decodePasskey);
}

// ---- flows ----

function need(creds: CredentialsLike | undefined): CredentialsLike {
  if (!creds) throw new WebAuthnUnavailable();
  return creds;
}

/** Passkey labels are 1–100 characters (rev 11). */
export const PASSKEY_LABEL_MAX = 100;

/**
 * Registers a passkey on the current session (rev 10): `webauthn/register/start {}` → `navigator.credentials.create`
 * → `webauthn/register/finish {registration_txn, credential, label}`. Needs step-up: rejects with StepUpRequired
 * from `start`, and the UI re-authenticates and calls again. Also allowed for an enrolment-only session (rev 11).
 */
export async function registerPasskey(authedClient: ApiClient, creds: CredentialsLike | undefined, label: string, signal?: AbortSignal): Promise<Passkey> {
  const c = need(creds);
  const l = label.trim();
  if (l.length === 0 || Array.from(l).length > PASSKEY_LABEL_MAX) throw new RangeError("label");
  const start = await authedClient.post(WEBAUTHN_REGISTER_START_PATH, {
    body: {},
    decode: decodeTxn("registration_txn"),
    ...(signal !== undefined && { signal }),
  });
  const publicKey = creationOptionsFromJson(start.data.public_key);
  const credential = await callBrowser(() => c.create({ publicKey, ...(signal !== undefined && { signal }) }));
  const fin = await authedClient.post(WEBAUTHN_REGISTER_FINISH_PATH, {
    body: { registration_txn: start.data.txn, credential: registrationToJson(credential), label: l },
    decode: decodePasskey,
    ...(signal !== undefined && { signal }),
  });
  return fin.data;
}

/**
 * Passwordless sign-in with a discoverable credential (rev 10): `webauthn/login/start {tenant}` →
 * `navigator.credentials.get` (empty allowCredentials) → `webauthn/login/finish {login_txn, credential}` → §2.4
 * result handed to the session, with a DPoP proof from a new session key as for OPAQUE (rev 8).
 */
export async function signInWithPasskey(deps: IdentityDeps, creds: CredentialsLike | undefined, tenant: string, signal?: AbortSignal): Promise<AuthResult> {
  const c = need(creds);
  const start = await deps.client.post(WEBAUTHN_LOGIN_START_PATH, {
    body: { tenant },
    decode: decodeTxn("login_txn"),
    ...(signal !== undefined && { signal }),
  });
  const publicKey = requestOptionsFromJson(start.data.public_key);
  const credential = await callBrowser(() => c.get({ publicKey, ...(signal !== undefined && { signal }) }));
  return issueSession(deps, WEBAUTHN_LOGIN_FINISH_PATH, { login_txn: start.data.txn, credential: assertionToJson(credential) }, decodeAuthResult, signal);
}

/**
 * Second factor after OPAQUE (§2.3, rev 10): `webauthn/assert/start {auth_txn}` → `navigator.credentials.get` →
 * `webauthn/assert/finish {assert_txn, credential}` → §2.4 result. Rev 11 addendum: a `reregister` on the result
 * runs the KSF upgrade with the retained password; the bytes are zeroed on success, failure and cancel.
 */
export async function completeMfaWithPasskey(deps: IdentityDeps, creds: CredentialsLike | undefined, mfa: MfaRequired, signal?: AbortSignal): Promise<AuthResult> {
  let result: AuthResult;
  try {
    const c = need(creds);
    const start = await deps.client.post(WEBAUTHN_ASSERT_START_PATH, {
      body: { auth_txn: mfa.challenge.auth_txn },
      decode: decodeTxn("assert_txn"),
      ...(signal !== undefined && { signal }),
    });
    const publicKey = requestOptionsFromJson(start.data.public_key);
    const credential = await callBrowser(() => c.get({ publicKey, ...(signal !== undefined && { signal }) }));
    result = await issueSession(deps, WEBAUTHN_ASSERT_FINISH_PATH, { assert_txn: start.data.txn, credential: assertionToJson(credential) }, decodeAuthResult, signal);
  } catch (e) {
    mfa.dispose();
    throw e;
  }
  return afterMfa(deps, mfa, result, signal);
}

/**
 * Step-up with a passkey on the current session (rev 10): `webauthn/assert/start {}` with the access token →
 * `navigator.credentials.get` → `webauthn/assert/finish` → 204, which sets `last_strong_auth_at`.
 */
export async function stepUpWithPasskey(authedClient: ApiClient, creds: CredentialsLike | undefined, signal?: AbortSignal): Promise<void> {
  const c = need(creds);
  const start = await authedClient.post(WEBAUTHN_ASSERT_START_PATH, {
    body: {},
    decode: decodeTxn("assert_txn"),
    ...(signal !== undefined && { signal }),
  });
  const publicKey = requestOptionsFromJson(start.data.public_key);
  const credential = await callBrowser(() => c.get({ publicKey, ...(signal !== undefined && { signal }) }));
  await authedClient.post(WEBAUTHN_ASSERT_FINISH_PATH, {
    body: { assert_txn: start.data.txn, credential: assertionToJson(credential) },
    ...(signal !== undefined && { signal }),
  });
}

/** `GET /api/v2/me/passkeys` (rev 10). */
export async function listPasskeys(authedClient: ApiClient, signal?: AbortSignal): Promise<Passkey[]> {
  const r = await authedClient.get(PASSKEYS_PATH, { decode: decodePasskeyList, ...(signal !== undefined && { signal }) });
  return r.data;
}

/** `DELETE /api/v2/me/passkeys/{id}` (rev 10, step-up). */
export async function deletePasskey(authedClient: ApiClient, id: string, signal?: AbortSignal): Promise<void> {
  await authedClient.delete(`${PASSKEYS_PATH}/${encodeURIComponent(id)}`, { ...(signal !== undefined && { signal }) });
}
