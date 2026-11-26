// Rev 9–11 flows: transparent re-registration, password change, MFA completion (with bounded password retention),
// WebAuthn with a fake navigator.credentials, sessions/passkeys/recovery codes, and the recovery state machine.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  RecoveryFlow,
  generateRecoveryCodes,
  listRecoveryRequests,
  listSessions,
  approveRecoveryRequest,
  cancelRecoveryRequest,
  remainingRecoveryCodes,
  revokeSession,
} from "./account";
import { AuthSession, MFA_ENROLMENT_SCOPE, noAuthChannel, noCrossTabLock, unverifiedClaim, type RefreshTransport } from "./auth";
import { ApiClient } from "./client";
import { errorCodeInfo, type CoreErrorCode } from "./errors";
import {
  IdentityInputError,
  MFA_PASSWORD_RETENTION_MS,
  MFA_RECOVERY_CODE_PATH,
  MfaRequired,
  OPAQUE_LOGIN_FINISH_PATH,
  OPAQUE_LOGIN_START_PATH,
  OPAQUE_REGISTER_FINISH_PATH,
  OPAQUE_REGISTER_START_PATH,
  changePassword,
  completeMfaWithRecoveryCode,
  normalizeRecoveryCode,
  signIn,
  type IdentityDeps,
  type ReregisterOutcome,
} from "./identity";
import { base64urlDecode, base64urlEncode, type KsfParams, type OpaqueEngine, type OpaqueFlowKind } from "./opaque";
import { ApiError, StepUpRequired } from "./problem";
import { RetryPolicy, type Clock } from "./retry";
import {
  PASSKEYS_PATH,
  WEBAUTHN_ASSERT_FINISH_PATH,
  WEBAUTHN_ASSERT_START_PATH,
  WEBAUTHN_LOGIN_FINISH_PATH,
  WEBAUTHN_LOGIN_START_PATH,
  WEBAUTHN_REGISTER_FINISH_PATH,
  WEBAUTHN_REGISTER_START_PATH,
  WebAuthnCancelled,
  WebAuthnUnavailable,
  completeMfaWithPasskey,
  deletePasskey,
  listPasskeys,
  registerPasskey,
  signInWithPasskey,
  stepUpWithPasskey,
  type CredentialsLike,
} from "./webauthn";

const TENANT = "0190c1d2-0000-7000-8000-000000000001";
const TENANT_BYTES = Uint8Array.from([0x01, 0x90, 0xc1, 0xd2, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]);
const GRANT = `rt1.${base64urlEncode(TENANT_BYTES)}.${base64urlEncode(new Uint8Array(32).fill(9))}`;
const KSF = { algorithm: "argon2id", m_kib: 65536, t: 3, p: 1 } as const;
const AUTH = { state: "authenticated", access_token: "at.jws", expires_in: 600, session_id: "s-1" };
const CODE = "ABCDEFGH-ABCDEFGHIJKLMNOPQRST";
const T0 = "2026-11-26T10:00:00Z";

const clock: Clock = { now: () => 1_000_000, sleep: () => Promise.resolve() };

afterEach(() => {
  vi.useRealTimers();
});

class FakeEngine implements OpaqueEngine {
  passwords: Uint8Array[] = [];
  kinds: OpaqueFlowKind[] = [];
  start(kind: OpaqueFlowKind, password: Uint8Array) {
    this.passwords.push(password);
    this.kinds.push(kind);
    return Promise.resolve({
      request: new Uint8Array(32).fill(kind === "login" ? 1 : 2),
      finish: (pw: Uint8Array, _r: Uint8Array, _k: KsfParams) => {
        this.passwords.push(pw);
        return Promise.resolve(new Uint8Array(64).fill(3));
      },
      abandon: () => undefined,
    });
  }
  normalizeLogin(login: string): Promise<string> {
    return Promise.resolve(login.toLowerCase());
  }
  allZero(): boolean {
    return this.passwords.length > 0 && this.passwords.every((p) => p.every((b) => b === 0));
  }
}

type Handler = (body: Record<string, unknown>) => Response;

const json = (v: unknown, status = 200): Response => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const noContent = (): Response => new Response(null, { status: 204 });
const problem = (status: number, code: CoreErrorCode, errors?: unknown[]): Response =>
  new Response(JSON.stringify({ type: "about:blank", title: code, status, code, retryable: errorCodeInfo(code).retryable, ...(errors && { errors }) }), {
    status,
    headers: { "Content-Type": "application/problem+json" },
  });
const stepUp = (): Response => problem(401, "unauthenticated", [{ pointer: "", code: "step_up_required", detail: "x" }]);

function setup(handlers: Record<string, Handler>, opts: { authed?: boolean } = {}) {
  const requests: { method: string; path: string; body: Record<string, unknown>; auth: string | null }[] = [];
  const fetchFn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const body = typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : {};
    const method = init?.method ?? "GET";
    requests.push({ method, path: url.pathname, body, auth: new Headers(init?.headers).get("Authorization") });
    const h = handlers[`${method} ${url.pathname}`] ?? handlers[url.pathname];
    return Promise.resolve(h ? h(body) : problem(404, "not_found"));
  });
  const transport: RefreshTransport = { refresh: () => Promise.reject(new Error("no refresh")) };
  const session = new AuthSession({ transport, lock: noCrossTabLock, channel: noAuthChannel, clock });
  const client = new ApiClient({ baseUrl: "https://cs.test", fetch: fetchFn, clock, retryPolicy: new RetryPolicy() });
  const authedClient = new ApiClient({ baseUrl: "https://cs.test", fetch: fetchFn, clock, retryPolicy: new RetryPolicy(), auth: session });
  const engine = new FakeEngine();
  const outcomes: ReregisterOutcome[] = [];
  const deps: IdentityDeps = {
    client,
    engine,
    session,
    ...(opts.authed !== false && { authedClient }),
    onReregister: (o) => outcomes.push(o),
  };
  return { requests, deps, engine, session, authedClient, outcomes };
}

const loginStart: Handler = () => json({ login_txn: "lt", credential_response: base64urlEncode(new Uint8Array(32)), ksf_params: KSF });
const registerStart: Handler = () => json({ registration_txn: "rt", registration_response: base64urlEncode(new Uint8Array(32)), ksf_params: KSF });

describe("transparent re-registration (rev 9 ksf_upgrade)", () => {
  it("runs register/start {purpose, registration_request} + register/finish with the access token, then wipes the password", async () => {
    const s = setup({
      [OPAQUE_LOGIN_START_PATH]: loginStart,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json({ ...AUTH, reregister: true }),
      [OPAQUE_REGISTER_START_PATH]: registerStart,
      [OPAQUE_REGISTER_FINISH_PATH]: noContent,
    });
    const r = await signIn(s.deps, TENANT, "Alice", "pw");
    expect(r.reregister).toBe(true);
    expect(s.requests.map((q) => q.path)).toEqual([OPAQUE_LOGIN_START_PATH, OPAQUE_LOGIN_FINISH_PATH, OPAQUE_REGISTER_START_PATH, OPAQUE_REGISTER_FINISH_PATH]);
    const [, , start, finish] = s.requests;
    expect(Object.keys(start!.body).sort()).toEqual(["purpose", "registration_request"]);
    expect(start!.body.purpose).toBe("ksf_upgrade");
    expect(start!.auth).toBe("Bearer at.jws");
    expect(finish!.body).toEqual({ registration_txn: "rt", registration_upload: base64urlEncode(new Uint8Array(64).fill(3)) });
    expect(finish!.auth).toBe("Bearer at.jws");
    expect(s.engine.kinds).toEqual(["login", "registration"]);
    expect(s.outcomes).toEqual([{ ok: true }]);
    expect(s.engine.allZero()).toBe(true);
  });

  it("does nothing when login/finish has no reregister flag", async () => {
    const s = setup({ [OPAQUE_LOGIN_START_PATH]: loginStart, [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH) });
    const r = await signIn(s.deps, TENANT, "alice", "pw");
    expect(r.reregister).toBeUndefined();
    expect(s.outcomes).toEqual([]);
    expect(s.requests).toHaveLength(2);
  });

  it.each([
    ["register/start fails (500)", { [OPAQUE_REGISTER_START_PATH]: () => problem(500, "internal") }],
    ["register/finish fails", { [OPAQUE_REGISTER_START_PATH]: registerStart, [OPAQUE_REGISTER_FINISH_PATH]: () => problem(409, "conflict") }],
    ["step-up window passed", { [OPAQUE_REGISTER_START_PATH]: stepUp }],
  ])("a failure (%s) does not break sign-in, is reported, and the password is still wiped", async (_n, extra: Record<string, Handler>) => {
    const s = setup({ [OPAQUE_LOGIN_START_PATH]: loginStart, [OPAQUE_LOGIN_FINISH_PATH]: () => json({ ...AUTH, reregister: true }), ...extra });
    const r = await signIn(s.deps, TENANT, "alice", "pw");
    expect(r.session_id).toBe("s-1");
    expect(s.session.state.authenticated).toBe(true);
    expect(s.outcomes).toHaveLength(1);
    expect(s.outcomes[0]!.ok).toBe(false);
    expect(s.engine.allZero()).toBe(true);
  });

  it("without an authenticated client the upgrade is reported failed and sign-in still succeeds", async () => {
    const s = setup({ [OPAQUE_LOGIN_START_PATH]: loginStart, [OPAQUE_LOGIN_FINISH_PATH]: () => json({ ...AUTH, reregister: true }) }, { authed: false });
    await signIn(s.deps, TENANT, "alice", "pw");
    expect(s.outcomes[0]!.ok).toBe(false);
    expect(s.session.state.authenticated).toBe(true);
  });

  it("a throwing onReregister listener does not break sign-in", async () => {
    const s = setup({ [OPAQUE_LOGIN_START_PATH]: loginStart, [OPAQUE_LOGIN_FINISH_PATH]: () => json({ ...AUTH, reregister: true }) }, { authed: false });
    const deps: IdentityDeps = { ...s.deps, onReregister: () => {
      throw new Error("boom");
    } };
    await expect(signIn(deps, TENANT, "alice", "pw")).resolves.toMatchObject({ session_id: "s-1" });
  });
});

describe("changePassword (rev 9 password_change)", () => {
  it("sends purpose password_change with the access token and zeroes the new password", async () => {
    const s = setup({ [OPAQUE_LOGIN_START_PATH]: loginStart, [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH), [OPAQUE_REGISTER_START_PATH]: registerStart, [OPAQUE_REGISTER_FINISH_PATH]: noContent });
    await signIn(s.deps, TENANT, "alice", "old");
    await changePassword(s.deps, s.authedClient, TENANT, "alice", "new");
    const start = s.requests.find((q) => q.path === OPAQUE_REGISTER_START_PATH)!;
    expect(start.body.purpose).toBe("password_change");
    expect(start.body).not.toHaveProperty("login");
    expect(start.auth).toBe("Bearer at.jws");
    expect(s.engine.allZero()).toBe(true);
  });

  it("rejects with StepUpRequired outside the step-up window (no refresh), and zeroes the password", async () => {
    const s = setup({ [OPAQUE_LOGIN_START_PATH]: loginStart, [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH), [OPAQUE_REGISTER_START_PATH]: stepUp });
    await signIn(s.deps, TENANT, "alice", "old");
    await expect(changePassword(s.deps, s.authedClient, TENANT, "alice", "new")).rejects.toBeInstanceOf(StepUpRequired);
    expect(s.engine.allZero()).toBe(true);
  });
});

describe("MFA (§2.3, rev 10/11)", () => {
  const mfaBody = () => json({ state: "mfa_required", auth_txn: "rt1.mfa", methods: ["webauthn", "recovery_code"] });

  async function mfa(extra: Record<string, Handler>) {
    const s = setup({ [OPAQUE_LOGIN_START_PATH]: loginStart, [OPAQUE_LOGIN_FINISH_PATH]: mfaBody, ...extra });
    const err: unknown = await signIn(s.deps, TENANT, "alice", "pw").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MfaRequired);
    return { s, m: err as MfaRequired };
  }

  it("mfa_required: no session, the password kept only as bytes in the challenge (the sign-in buffer is zeroed)", async () => {
    const { s, m } = await mfa({});
    expect(s.session.state.authenticated).toBe(false);
    expect(m.challenge.methods).toEqual(["webauthn", "recovery_code"]);
    expect(m.retained?.value).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(m.retained!.value)).toBe("pw");
    expect(s.engine.allZero()).toBe(true);
    m.dispose();
    expect(m.retained?.value).toBeUndefined();
  });

  it("recovery code completes sign-in; reregister on the result runs ksf_upgrade and zeroes the retained bytes", async () => {
    const { s, m } = await mfa({
      [MFA_RECOVERY_CODE_PATH]: () => json({ ...AUTH, reregister: true }),
      [OPAQUE_REGISTER_START_PATH]: registerStart,
      [OPAQUE_REGISTER_FINISH_PATH]: noContent,
    });
    const bytes = m.retained!.value!;
    const r = await completeMfaWithRecoveryCode(s.deps, m, " abcdefgh-abcdefghijklmnopqrst ");
    expect(r.session_id).toBe("s-1");
    expect(s.requests.find((q) => q.path === MFA_RECOVERY_CODE_PATH)!.body).toEqual({ auth_txn: "rt1.mfa", code: CODE });
    expect(s.requests.find((q) => q.path === OPAQUE_REGISTER_START_PATH)!.body.purpose).toBe("ksf_upgrade");
    expect(s.outcomes).toEqual([{ ok: true }]);
    expect(bytes.every((b) => b === 0)).toBe(true);
    expect(m.retained!.value).toBeUndefined();
  });

  it("a failed MFA completion zeroes the retained bytes", async () => {
    const { s, m } = await mfa({ [MFA_RECOVERY_CODE_PATH]: () => problem(401, "unauthenticated") });
    const bytes = m.retained!.value!;
    await expect(completeMfaWithRecoveryCode(s.deps, m, CODE)).rejects.toBeInstanceOf(ApiError);
    expect(bytes.every((b) => b === 0)).toBe(true);
  });

  it("a malformed recovery code is refused before any request", async () => {
    const { s, m } = await mfa({});
    const n = s.requests.length;
    await expect(completeMfaWithRecoveryCode(s.deps, m, "1234")).rejects.toBeInstanceOf(IdentityInputError);
    expect(s.requests).toHaveLength(n);
    m.dispose();
  });

  it("the retained bytes are zeroed when the auth_txn lifetime (5 min) passes", async () => {
    vi.useFakeTimers();
    const { m } = await mfa({});
    const bytes = m.retained!.value!;
    vi.advanceTimersByTime(MFA_PASSWORD_RETENTION_MS - 1);
    expect(bytes.some((b) => b !== 0)).toBe(true);
    vi.advanceTimersByTime(1);
    expect(bytes.every((b) => b === 0)).toBe(true);
    expect(MFA_PASSWORD_RETENTION_MS).toBe(300_000);
  });

  it("normalizeRecoveryCode accepts the rev 11 format only", () => {
    expect(normalizeRecoveryCode("abcd efgh-ABCDEFGHIJKLMNOPQRST")).toBe(CODE);
    for (const bad of ["", "ABCDEFGH", "ABCDEFG1-ABCDEFGHIJKLMNOPQRST", "ABCDEFGH-ABCDEFGHIJKLMNOPQRS"]) {
      expect(() => normalizeRecoveryCode(bad)).toThrow(IdentityInputError);
    }
  });
});

// ---- WebAuthn with a fake navigator.credentials ----

const ab = (...b: number[]): ArrayBuffer => Uint8Array.from(b).buffer;

class FakeCredentials implements CredentialsLike {
  created: CredentialCreationOptions[] = [];
  got: CredentialRequestOptions[] = [];
  error: Error | undefined;
  create(options: CredentialCreationOptions): Promise<Credential | null> {
    this.created.push(options);
    if (this.error) return Promise.reject(this.error);
    return Promise.resolve({
      id: "Y3JlZA",
      rawId: ab(99, 114, 101, 100),
      type: "public-key",
      authenticatorAttachment: "platform",
      response: { clientDataJSON: ab(1), attestationObject: ab(2), getTransports: () => ["internal"] },
      getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: ab(7, 7, 7) } } }),
    } as unknown as Credential);
  }
  get(options: CredentialRequestOptions): Promise<Credential | null> {
    this.got.push(options);
    if (this.error) return Promise.reject(this.error);
    return Promise.resolve({
      id: "Y3JlZA",
      rawId: ab(99, 114, 101, 100),
      type: "public-key",
      authenticatorAttachment: null,
      response: { clientDataJSON: ab(1), authenticatorData: ab(3), signature: ab(4), userHandle: ab(5) },
      getClientExtensionResults: () => ({ prf: { results: { first: ab(8, 8) } } }),
    } as unknown as Credential);
  }
}

const challenge = base64urlEncode(Uint8Array.from([9, 9, 9]));
const requestOptions = { challenge, rpId: "cs.test", allowCredentials: [], userVerification: "required" };
const passkey = { id: "Y3JlZA", label: "Laptop", created_at: T0, last_used_at: null, prf: true };

function notAllowed(): Error {
  const e = new Error("cancelled");
  e.name = "NotAllowedError";
  return e;
}

describe("WebAuthn (rev 10 wire shapes, L3 JSON, base64url)", () => {
  it("registers a passkey: decodes the creation options, encodes the attestation, never sends PRF output", async () => {
    const s = setup({
      [OPAQUE_LOGIN_START_PATH]: loginStart,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH),
      [WEBAUTHN_REGISTER_START_PATH]: () =>
        json({
          registration_txn: "wr",
          public_key: {
            challenge,
            rp: { id: "cs.test", name: "CS" },
            user: { id: base64urlEncode(Uint8Array.from([1, 2])), name: "alice", displayName: "Alice" },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            excludeCredentials: [{ type: "public-key", id: "AQI" }],
            extensions: { prf: {} },
          },
        }),
      // Contract rev 10 §2.2: register/finish → {id, label, created_at, prf}, no last_used_at (decoded as null).
      [WEBAUTHN_REGISTER_FINISH_PATH]: () => json({ id: passkey.id, label: passkey.label, created_at: passkey.created_at, prf: passkey.prf }),
    });
    await signIn(s.deps, TENANT, "alice", "pw");
    const creds = new FakeCredentials();
    const p = await registerPasskey(s.authedClient, creds, "  Laptop ");
    expect(p).toEqual(passkey);
    const pk = creds.created[0]!.publicKey!;
    expect(new Uint8Array(pk.challenge as ArrayBuffer)).toEqual(Uint8Array.from([9, 9, 9]));
    expect(new Uint8Array(pk.user.id as ArrayBuffer)).toEqual(Uint8Array.from([1, 2]));
    expect(new Uint8Array(pk.excludeCredentials![0]!.id as ArrayBuffer)).toEqual(Uint8Array.from([1, 2]));
    const start = s.requests.find((q) => q.path === WEBAUTHN_REGISTER_START_PATH)!;
    expect(start.body).toEqual({});
    expect(start.auth).toBe("Bearer at.jws");
    const fin = s.requests.find((q) => q.path === WEBAUTHN_REGISTER_FINISH_PATH)!.body;
    expect(fin).toEqual({
      registration_txn: "wr",
      label: "Laptop",
      credential: {
        id: "Y3JlZA",
        rawId: base64urlEncode(Uint8Array.from([99, 114, 101, 100])),
        type: "public-key",
        authenticatorAttachment: "platform",
        response: { clientDataJSON: "AQ", attestationObject: "Ag", transports: ["internal"] },
        clientExtensionResults: { prf: { enabled: true } },
      },
    });
    expect(JSON.stringify(fin)).not.toContain(base64urlEncode(Uint8Array.from([7, 7, 7])));
  });

  it("registration needs step-up: StepUpRequired from start, no browser prompt", async () => {
    const s = setup({ [OPAQUE_LOGIN_START_PATH]: loginStart, [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH), [WEBAUTHN_REGISTER_START_PATH]: stepUp });
    await signIn(s.deps, TENANT, "alice", "pw");
    const creds = new FakeCredentials();
    await expect(registerPasskey(s.authedClient, creds, "Key")).rejects.toBeInstanceOf(StepUpRequired);
    expect(creds.created).toHaveLength(0);
  });

  it("passwordless sign-in with a discoverable credential issues the session", async () => {
    const s = setup({
      [WEBAUTHN_LOGIN_START_PATH]: () => json({ login_txn: "wl", public_key: requestOptions }),
      [WEBAUTHN_LOGIN_FINISH_PATH]: () => json(AUTH),
    });
    const creds = new FakeCredentials();
    const r = await signInWithPasskey(s.deps, creds, TENANT);
    expect(r.session_id).toBe("s-1");
    expect(s.session.state.authenticated).toBe(true);
    expect(s.requests[0]!.body).toEqual({ tenant: TENANT });
    expect(creds.got[0]!.publicKey!.allowCredentials).toEqual([]);
    const fin = s.requests[1]!.body as { login_txn: string; credential: { response: Record<string, unknown>; clientExtensionResults: unknown } };
    expect(fin.login_txn).toBe("wl");
    expect(fin.credential.response).toEqual({ clientDataJSON: "AQ", authenticatorData: "Aw", signature: "BA", userHandle: "BQ" });
    expect(fin.credential.clientExtensionResults).toEqual({ prf: {} });
  });

  it("maps a dismissed prompt to WebAuthnCancelled and a missing API to WebAuthnUnavailable", async () => {
    const s = setup({ [WEBAUTHN_LOGIN_START_PATH]: () => json({ login_txn: "wl", public_key: requestOptions }) });
    const creds = new FakeCredentials();
    creds.error = notAllowed();
    await expect(signInWithPasskey(s.deps, creds, TENANT)).rejects.toBeInstanceOf(WebAuthnCancelled);
    await expect(signInWithPasskey(s.deps, undefined, TENANT)).rejects.toBeInstanceOf(WebAuthnUnavailable);
    expect(s.session.state.authenticated).toBe(false);
  });

  it("MFA with a passkey: assert/start {auth_txn} → assert/finish → session; reregister runs and bytes are zeroed", async () => {
    const s = setup({
      [OPAQUE_LOGIN_START_PATH]: loginStart,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json({ state: "mfa_required", auth_txn: "rt1.mfa", methods: ["webauthn"] }),
      [WEBAUTHN_ASSERT_START_PATH]: () => json({ assert_txn: "wa", public_key: requestOptions }),
      [WEBAUTHN_ASSERT_FINISH_PATH]: () => json({ ...AUTH, reregister: true }),
      [OPAQUE_REGISTER_START_PATH]: registerStart,
      [OPAQUE_REGISTER_FINISH_PATH]: noContent,
    });
    const m = (await signIn(s.deps, TENANT, "alice", "pw").catch((e: unknown) => e)) as MfaRequired;
    const bytes = m.retained!.value!;
    await completeMfaWithPasskey(s.deps, new FakeCredentials(), m);
    expect(s.requests.find((q) => q.path === WEBAUTHN_ASSERT_START_PATH)!.body).toEqual({ auth_txn: "rt1.mfa" });
    expect(s.session.state.authenticated).toBe(true);
    expect(s.outcomes).toEqual([{ ok: true }]);
    expect(bytes.every((b) => b === 0)).toBe(true);
  });

  it("a cancelled MFA passkey prompt zeroes the retained bytes", async () => {
    const s = setup({
      [OPAQUE_LOGIN_START_PATH]: loginStart,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json({ state: "mfa_required", auth_txn: "rt1.mfa", methods: ["webauthn"] }),
      [WEBAUTHN_ASSERT_START_PATH]: () => json({ assert_txn: "wa", public_key: requestOptions }),
    });
    const m = (await signIn(s.deps, TENANT, "alice", "pw").catch((e: unknown) => e)) as MfaRequired;
    const bytes = m.retained!.value!;
    const creds = new FakeCredentials();
    creds.error = notAllowed();
    await expect(completeMfaWithPasskey(s.deps, creds, m)).rejects.toBeInstanceOf(WebAuthnCancelled);
    expect(bytes.every((b) => b === 0)).toBe(true);
  });

  it("step-up with a passkey: assert/start {} with the access token → assert/finish 204", async () => {
    const s = setup({
      [OPAQUE_LOGIN_START_PATH]: loginStart,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH),
      [WEBAUTHN_ASSERT_START_PATH]: () => json({ assert_txn: "wa", public_key: requestOptions }),
      [WEBAUTHN_ASSERT_FINISH_PATH]: noContent,
    });
    await signIn(s.deps, TENANT, "alice", "pw");
    await stepUpWithPasskey(s.authedClient, new FakeCredentials());
    const start = s.requests.find((q) => q.path === WEBAUTHN_ASSERT_START_PATH)!;
    expect(start.body).toEqual({});
    expect(start.auth).toBe("Bearer at.jws");
    expect(s.requests.find((q) => q.path === WEBAUTHN_ASSERT_FINISH_PATH)!.body.assert_txn).toBe("wa");
  });

  it("lists and deletes passkeys", async () => {
    const s = setup({ [`GET ${PASSKEYS_PATH}`]: () => json({ items: [passkey] }), [`DELETE ${PASSKEYS_PATH}/Y3JlZA`]: noContent });
    expect(await listPasskeys(s.deps.client)).toEqual([passkey]);
    await deletePasskey(s.deps.client, "Y3JlZA");
    expect(s.requests.map((q) => `${q.method} ${q.path}`)).toEqual([`GET ${PASSKEYS_PATH}`, `DELETE ${PASSKEYS_PATH}/Y3JlZA`]);
  });
});

describe("sessions, recovery codes and recovery requests (rev 10)", () => {
  const sess = (sid: string, current: boolean) => ({ sid, created_at: T0, last_seen_at: T0, amr: ["pwd"], user_agent: current ? "Firefox" : null, current });

  it("lists own sessions and revokes one", async () => {
    const s = setup({ "GET /api/v2/me/sessions": () => json({ items: [sess("a", true), sess("b", false)] }), "DELETE /api/v2/me/sessions/b": noContent });
    const list = await listSessions(s.deps.client);
    expect(list.map((x) => [x.sid, x.current, x.user_agent])).toEqual([["a", true, "Firefox"], ["b", false, null]]);
    await revokeSession(s.deps.client, "b");
    expect(s.requests[1]!.method).toBe("DELETE");
  });

  it("accepts last_seen_at null for a session never refreshed (nullable on the server)", async () => {
    const s = setup({ "GET /api/v2/me/sessions": () => json({ items: [{ ...sess("a", true), last_seen_at: null }] }) });
    expect((await listSessions(s.deps.client))[0]?.last_seen_at).toBeNull();
  });

  it("refuses a session list with a non-RFC 3339 timestamp", async () => {
    const s = setup({ "GET /api/v2/me/sessions": () => json({ items: [{ ...sess("a", true), created_at: 1_700_000_000 }] }) });
    await expect(listSessions(s.deps.client)).rejects.toMatchObject({ problem: { code: "internal" } });
  });

  it("revoking another session surfaces StepUpRequired", async () => {
    const s = setup({ "DELETE /api/v2/me/sessions/b": stepUp });
    await expect(revokeSession(s.deps.client, "b")).rejects.toBeInstanceOf(StepUpRequired);
  });

  it("generates a set of 10 recovery codes and reads the remaining count", async () => {
    const codes = Array.from({ length: 10 }, (_, i) => `ABCDEFG${"ABCDEFGHIJ"[i]}-ABCDEFGHIJKLMNOPQRST`);
    const s = setup({ "POST /api/v2/me/recovery-codes": () => json({ codes }), "GET /api/v2/me/recovery-codes": () => json({ remaining: 7 }) });
    expect(await generateRecoveryCodes(s.deps.client)).toEqual(codes);
    expect(await remainingRecoveryCodes(s.deps.client)).toBe(7);
    const bad = setup({ "POST /api/v2/me/recovery-codes": () => json({ codes: codes.slice(1) }) });
    await expect(generateRecoveryCodes(bad.deps.client)).rejects.toMatchObject({ problem: { code: "internal" } });
  });

  it("lists, approves and cancels recovery requests", async () => {
    const req = { id: "r1", method: "device_approval", state: "pending", created_at: T0, available_at: null, requester_user_agent: "Safari" };
    const s = setup({
      "GET /api/v2/me/recovery-requests": () => json({ items: [req] }),
      "POST /api/v2/me/recovery-requests/r1/approve": noContent,
      "DELETE /api/v2/me/recovery-requests/r1": noContent,
    });
    expect(await listRecoveryRequests(s.deps.client)).toEqual([req]);
    await approveRecoveryRequest(s.deps.client, "r1");
    await cancelRecoveryRequest(s.deps.client, "r1");
    expect(s.requests.map((q) => `${q.method} ${q.path}`).slice(1)).toEqual(["POST /api/v2/me/recovery-requests/r1/approve", "DELETE /api/v2/me/recovery-requests/r1"]);
  });
});

describe("RecoveryFlow state machine (§4 [R5], rev 10)", () => {
  const completeHandlers: Record<string, Handler> = {
    [OPAQUE_REGISTER_START_PATH]: registerStart,
    [OPAQUE_REGISTER_FINISH_PATH]: noContent,
    [OPAQUE_LOGIN_START_PATH]: loginStart,
    [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH),
  };

  it("recovery code → granted at once → complete registers with the grant and signs in → done", async () => {
    const s = setup({ "/api/v2/auth/recovery/start": () => json({ state: "granted", grant: GRANT, grant_expires_in: 900 }), ...completeHandlers });
    const f = new RecoveryFlow(s.deps);
    expect(f.phase.kind).toBe("idle");
    await f.startWithCode(TENANT, "Alice", CODE.toLowerCase());
    expect(s.requests[0]!.body).toEqual({ tenant: TENANT, login: "alice", method: "recovery_code", code: CODE });
    expect(f.phase).toEqual({ kind: "granted", grant_expires_in: 900 });
    await f.complete("alice", "new pw");
    const reg = s.requests.find((q) => q.path === OPAQUE_REGISTER_START_PATH)!;
    expect(reg.body).toMatchObject({ grant: GRANT, login: "alice" });
    expect(f.phase.kind).toBe("done");
    expect(s.session.state.authenticated).toBe(true);
    expect(s.engine.allZero()).toBe(true);
  });

  it("a wrong code is `unauthenticated` and the flow stays idle", async () => {
    const s = setup({ "/api/v2/auth/recovery/start": () => problem(401, "unauthenticated") });
    const f = new RecoveryFlow(s.deps);
    await expect(f.startWithCode(TENANT, "alice", CODE)).rejects.toBeInstanceOf(ApiError);
    expect(f.phase.kind).toBe("idle");
  });

  it("email: start → email_sent; link (+ code for MFA) → waiting with available_at → granted", async () => {
    let granted = false;
    const s = setup({
      "/api/v2/auth/recovery/start": () => json({ state: "pending" }, 202),
      "/api/v2/auth/recovery/status": () => (granted ? json({ state: "granted", available_at: T0, grant: GRANT, grant_expires_in: 900 }) : json({ state: "pending", available_at: T0 })),
    });
    const f = new RecoveryFlow(s.deps);
    await f.startEmail(TENANT, "alice");
    expect(s.requests[0]!.body).toEqual({ tenant: TENANT, login: "alice", method: "email" });
    expect(f.phase.kind).toBe("email_sent");
    await f.openEmailLink("rt1.link", CODE);
    expect(s.requests[1]!.body).toEqual({ token: "rt1.link", code: CODE });
    expect(f.phase).toEqual({ kind: "waiting", method: "email", available_at: T0 });
    granted = true;
    await f.poll();
    expect(f.phase.kind).toBe("granted");
  });

  it("device approval: start → waiting → status {recovery_txn}; cancelled is terminal and stops polling", async () => {
    let state = "pending";
    const s = setup({
      "/api/v2/auth/recovery/start": () => json({ state: "pending", recovery_txn: "rt1.dev" }, 202),
      "/api/v2/auth/recovery/status": () => json(state === "granted" ? { state, grant: GRANT, grant_expires_in: 900 } : { state }),
    });
    const f = new RecoveryFlow(s.deps);
    await f.startDeviceApproval(TENANT, "alice");
    expect(f.phase).toEqual({ kind: "waiting", method: "device_approval" });
    await f.poll();
    expect(s.requests[1]!.body).toEqual({ recovery_txn: "rt1.dev" });
    state = "cancelled";
    await f.poll();
    expect(f.phase.kind).toBe("cancelled");
    await f.poll(); // nothing left to poll
    expect(s.requests).toHaveLength(3);
  });

  it("an expired or used grant moves to expired; the user starts over", async () => {
    const s = setup({
      "/api/v2/auth/recovery/start": () => json({ state: "granted", grant: GRANT, grant_expires_in: 900 }),
      [OPAQUE_REGISTER_START_PATH]: () => problem(401, "unauthenticated"),
    });
    const f = new RecoveryFlow(s.deps);
    await f.startWithCode(TENANT, "alice", CODE);
    await expect(f.complete("alice", "pw")).rejects.toBeInstanceOf(ApiError);
    expect(f.phase.kind).toBe("expired");
    await expect(f.complete("alice", "pw")).rejects.toThrow();
  });
});

describe("enrolment-only session scope (rev 11)", () => {
  const jwt = (payload: unknown) => `e30.${base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)))}.sig`;
  it("reads scp from the access token for display only", async () => {
    expect(unverifiedClaim(jwt({ scp: MFA_ENROLMENT_SCOPE }), "scp")).toBe("mfa_enrolment");
    expect(unverifiedClaim("garbage", "scp")).toBeUndefined();
    expect(unverifiedClaim(jwt([1]), "scp")).toBeUndefined();
    const s = setup({ [OPAQUE_LOGIN_START_PATH]: loginStart, [OPAQUE_LOGIN_FINISH_PATH]: () => json({ ...AUTH, access_token: jwt({ scp: "mfa_enrolment" }) }) });
    expect(s.session.scope).toBeUndefined();
    await signIn(s.deps, TENANT, "alice", "pw");
    expect(s.session.scope).toBe(MFA_ENROLMENT_SCOPE);
    expect(base64urlDecode(base64urlEncode(Uint8Array.from([1])))).toEqual(Uint8Array.from([1]));
  });
});
