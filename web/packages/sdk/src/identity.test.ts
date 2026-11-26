import { describe, expect, it, vi } from "vitest";
import { AuthSession, noAuthChannel, noCrossTabLock, type RefreshTransport } from "./auth";
import { ApiClient } from "./client";
import { DpopKeyManager, memoryDpopKeyStore } from "./dpop";
import {
  IdentityInputError,
  LOGOUT_PATH,
  MfaRequired,
  OPAQUE_LOGIN_FINISH_PATH,
  OPAQUE_LOGIN_START_PATH,
  OPAQUE_REGISTER_FINISH_PATH,
  OPAQUE_REGISTER_START_PATH,
  OPAQUE_REAUTH_FINISH_PATH,
  OPAQUE_REAUTH_START_PATH,
  ME_PATH,
  getMe,
  meDisplayName,
  isCanonicalTenantId,
  reauthenticate,
  register,
  signIn,
  signOut,
  tenantFromGrant,
  type IdentityDeps,
} from "./identity";
import { OpaqueClientError, base64urlDecode, base64urlEncode, type KsfParams, type OpaqueEngine, type OpaqueFlowKind } from "./opaque";
import { errorCodeInfo, type CoreErrorCode } from "./errors";
import { ApiError } from "./problem";
import { RetryPolicy, type Clock } from "./retry";

const TENANT = "0190c1d2-0000-7000-8000-000000000001";
const TENANT_BYTES = Uint8Array.from([0x01, 0x90, 0xc1, 0xd2, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]);
const GRANT = `rt1.${base64urlEncode(TENANT_BYTES)}.${base64urlEncode(new Uint8Array(32).fill(7))}`;
const KSF = { algorithm: "argon2id", m_kib: 65536, t: 3, p: 1 } as const;
const AUTH = { state: "authenticated", access_token: "at.jws", expires_in: 600, session_id: "0190c1d2-0000-7000-8000-0000000000aa" };

const instantClock: Clock = { now: () => 1_000_000, sleep: () => Promise.resolve() };

/** Fake engine: records every password buffer and call so the test can check zeroing and arguments. */
class FakeEngine implements OpaqueEngine {
  passwords: Uint8Array[] = [];
  calls: { kind: OpaqueFlowKind; tenant: string; login: string; response?: Uint8Array; ksf?: KsfParams }[] = [];
  abandoned = 0;
  finishError: OpaqueClientError | undefined;

  start(kind: OpaqueFlowKind, password: Uint8Array, tenant: string, login: string) {
    this.passwords.push(password);
    const call: (typeof this.calls)[number] = { kind, tenant, login };
    this.calls.push(call);
    return Promise.resolve({
      request: new Uint8Array(kind === "login" ? 96 : 32).fill(kind === "login" ? 1 : 2),
      finish: (pw: Uint8Array, response: Uint8Array, ksf: KsfParams) => {
        this.passwords.push(pw);
        call.response = response;
        call.ksf = ksf;
        if (this.finishError) return Promise.reject(this.finishError);
        return Promise.resolve(new Uint8Array(kind === "login" ? 64 : 192).fill(3));
      },
      abandon: () => {
        this.abandoned++;
      },
    });
  }

  normalizeLogin(login: string): Promise<string> {
    if (/\s/.test(login) || login.length === 0) return Promise.reject(new OpaqueClientError("invalid_input"));
    return Promise.resolve(login.toLowerCase());
  }
}

type Handler = (body: Record<string, unknown>, headers: Headers) => Response;

/** Fake identity endpoints with the exact contract shapes (M1 rev 5 §2.1, §2.4, §3). */
function fakeServer(handlers: Record<string, Handler>) {
  const requests: { path: string; body: Record<string, unknown>; headers: Headers }[] = [];
  const fetchFn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : {};
    requests.push({ path: url.pathname, body, headers });
    const h = handlers[url.pathname];
    if (!h) return Promise.resolve(problem(404, "not_found"));
    return Promise.resolve(h(body, headers));
  });
  return { requests, fetchFn };
}

const json = (v: unknown, status = 200): Response => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const problem = (status: number, code: string, errors?: unknown[]): Response =>
  new Response(JSON.stringify({ type: "about:blank", title: code, status, code, retryable: errorCodeInfo(code as CoreErrorCode).retryable, ...(errors && { errors }) }), {
    status,
    headers: { "Content-Type": "application/problem+json" },
  });

const loginStartOk: Handler = () => json({ login_txn: "txn-1", credential_response: base64urlEncode(new Uint8Array(320).fill(4)), ksf_params: KSF });

function deps(fetchFn: typeof fetch, engine = new FakeEngine()): IdentityDeps & { engine: FakeEngine; session: AuthSession } {
  const client = new ApiClient({ baseUrl: "https://cs.test", fetch: fetchFn, clock: instantClock, retryPolicy: new RetryPolicy() });
  const transport: RefreshTransport = { refresh: () => Promise.reject(new Error("no refresh in these tests")) };
  const session = new AuthSession({ transport, lock: noCrossTabLock, channel: noAuthChannel, clock: instantClock });
  return { client, engine, session };
}

describe("signIn (contract §2.1 login/start + login/finish)", () => {
  it("sends the contract shapes, runs the KSF with the server's params and hands the session over", async () => {
    const { requests, fetchFn } = fakeServer({
      [OPAQUE_LOGIN_START_PATH]: loginStartOk,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH),
    });
    const d = deps(fetchFn);
    const r = await signIn(d, TENANT, "Alice@Example.com", "correct horse");
    expect(r.session_id).toBe(AUTH.session_id);
    expect(requests.map((q) => q.path)).toEqual([OPAQUE_LOGIN_START_PATH, OPAQUE_LOGIN_FINISH_PATH]);
    const [start, finish] = requests;
    expect(Object.keys(start!.body).sort()).toEqual(["credential_request", "login", "tenant"]);
    expect(start!.body).toMatchObject({ tenant: TENANT, login: "alice@example.com" });
    expect(base64urlDecode(start!.body.credential_request as string)).toEqual(new Uint8Array(96).fill(1));
    expect(finish!.body).toEqual({ login_txn: "txn-1", credential_finalization: base64urlEncode(new Uint8Array(64).fill(3)) });
    expect(d.engine.calls[0]).toMatchObject({ kind: "login", tenant: TENANT, login: "alice@example.com", ksf: KSF });
    expect(d.engine.calls[0]!.response).toEqual(new Uint8Array(320).fill(4));
    expect(d.session.state).toEqual({ authenticated: true, sessionId: AUTH.session_id });
    expect(await d.session.authorization()).toBe("Bearer at.jws");
    // The password never leaves the client and its bytes are zeroed afterwards.
    for (const q of requests) expect(JSON.stringify(q.body)).not.toContain("correct horse");
    expect(d.engine.passwords.length).toBe(2);
    for (const pw of d.engine.passwords) expect(pw.every((b) => b === 0)).toBe(true);
  });

  it("reports a client-side OPAQUE failure (wrong password) as `unauthenticated` without calling login/finish", async () => {
    const { requests, fetchFn } = fakeServer({ [OPAQUE_LOGIN_START_PATH]: loginStartOk });
    const d = deps(fetchFn);
    d.engine.finishError = new OpaqueClientError("invalid_login");
    const err: unknown = await signIn(d, TENANT, "alice", "wrong").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).problem.code).toBe("unauthenticated");
    expect(requests.map((q) => q.path)).toEqual([OPAQUE_LOGIN_START_PATH]);
    expect(d.session.state.authenticated).toBe(false);
    expect(d.engine.abandoned).toBe(1);
  });

  it("passes server problems through (rate_limited, unauthenticated from login/finish)", async () => {
    const limited = fakeServer({ [OPAQUE_LOGIN_START_PATH]: () => problem(429, "rate_limited") });
    // rate_limited is retryable (D.2): the client retries with the same key before giving up.
    const e1: unknown = await signIn(deps(limited.fetchFn), TENANT, "alice", "pw").catch((e: unknown) => e);
    expect((e1 as ApiError).problem.code).toBe("rate_limited");
    const rejected = fakeServer({ [OPAQUE_LOGIN_START_PATH]: loginStartOk, [OPAQUE_LOGIN_FINISH_PATH]: () => problem(401, "unauthenticated") });
    const d = deps(rejected.fetchFn);
    const e2: unknown = await signIn(d, TENANT, "alice", "pw").catch((e: unknown) => e);
    expect((e2 as ApiError).problem.code).toBe("unauthenticated");
    expect(d.session.state.authenticated).toBe(false);
  });

  it("surfaces mfa_required (§2.3) as MfaRequired and issues no session", async () => {
    const { fetchFn } = fakeServer({
      [OPAQUE_LOGIN_START_PATH]: loginStartOk,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json({ state: "mfa_required", auth_txn: "a1", methods: ["webauthn", "recovery_code"] }),
    });
    const d = deps(fetchFn);
    const err: unknown = await signIn(d, TENANT, "alice", "pw").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MfaRequired);
    expect((err as MfaRequired).challenge).toEqual({ state: "mfa_required", auth_txn: "a1", methods: ["webauthn", "recovery_code"] });
    expect(d.session.state.authenticated).toBe(false);
  });

  it("rejects bad input before any request: non-canonical tenant, invalid login, empty password", async () => {
    const { requests, fetchFn } = fakeServer({});
    const d = deps(fetchFn);
    for (const [tenant, login, pw, field] of [
      ["acme", "alice", "pw", "tenant"],
      [TENANT.toUpperCase(), "alice", "pw", "tenant"],
      [TENANT, "al ice", "pw", "login"],
      [TENANT, "alice", "", "password"],
    ] as const) {
      const err: unknown = await signIn(d, tenant, login, pw).catch((e: unknown) => e);
      expect(err, `${tenant} ${login}`).toBeInstanceOf(IdentityInputError);
      expect((err as IdentityInputError).field).toBe(field);
    }
    expect(requests).toEqual([]);
  });

  it("treats a malformed login/start body as internal", async () => {
    const { fetchFn } = fakeServer({ [OPAQUE_LOGIN_START_PATH]: () => json({ login_txn: "t", credential_response: "a+b/", ksf_params: KSF }) });
    const err: unknown = await signIn(deps(fetchFn), TENANT, "alice", "pw").catch((e: unknown) => e);
    expect((err as ApiError).problem.code).toBe("internal");
  });
});

describe("register (rev 5 §2.1: setup link → register/start → register/finish 204 → login)", () => {
  it("presents the full rt1 grant, takes the tenant from it, then signs in normally", async () => {
    const { requests, fetchFn } = fakeServer({
      [OPAQUE_REGISTER_START_PATH]: () =>
        json({ registration_txn: "rtxn", registration_response: base64urlEncode(new Uint8Array(64).fill(5)), ksf_params: KSF }),
      [OPAQUE_REGISTER_FINISH_PATH]: () => new Response(null, { status: 204 }),
      [OPAQUE_LOGIN_START_PATH]: loginStartOk,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH),
    });
    const d = deps(fetchFn);
    await register(d, `  ${GRANT}\n`, "Alice", "a long passphrase");
    expect(requests.map((q) => q.path)).toEqual([OPAQUE_REGISTER_START_PATH, OPAQUE_REGISTER_FINISH_PATH, OPAQUE_LOGIN_START_PATH, OPAQUE_LOGIN_FINISH_PATH]);
    const [rs, rf, ls] = requests;
    expect(Object.keys(rs!.body).sort()).toEqual(["grant", "login", "registration_request"]);
    expect(rs!.body).toMatchObject({ grant: GRANT, login: "alice" });
    expect(base64urlDecode(rs!.body.registration_request as string)).toEqual(new Uint8Array(32).fill(2));
    expect(rf!.body).toEqual({ registration_txn: "rtxn", registration_upload: base64urlEncode(new Uint8Array(192).fill(3)) });
    expect(rf!.headers.get("Idempotency-Key")).toBeTruthy();
    expect(ls!.body).toMatchObject({ tenant: TENANT, login: "alice" });
    expect(d.engine.calls[0]).toMatchObject({ kind: "registration", tenant: TENANT, login: "alice", ksf: KSF });
    expect(d.session.state.authenticated).toBe(true);
    for (const pw of d.engine.passwords) expect(pw.every((b) => b === 0)).toBe(true);
  });

  it("does not sign in when register/finish fails, and maps registration_grant_required through", async () => {
    const { requests, fetchFn } = fakeServer({
      [OPAQUE_REGISTER_START_PATH]: () => problem(403, "permission_denied", [{ pointer: "/grant", code: "registration_grant_required", detail: "x" }]),
    });
    const d = deps(fetchFn);
    const err: unknown = await register(d, GRANT, "alice", "pw").catch((e: unknown) => e);
    expect((err as ApiError).problem.code).toBe("permission_denied");
    expect((err as ApiError).problem.errors?.[0]?.code).toBe("registration_grant_required");
    expect(requests.length).toBe(1);
    expect(d.session.state.authenticated).toBe(false);
  });

  it("rejects a malformed setup link before any request", async () => {
    const { requests, fetchFn } = fakeServer({});
    for (const bad of ["", "rt1.abc", `rt2.${GRANT.slice(4)}`, `rt1.${base64urlEncode(new Uint8Array(15))}.${base64urlEncode(new Uint8Array(32))}`, `rt1.${base64urlEncode(TENANT_BYTES)}.short`]) {
      const err: unknown = await register(deps(fetchFn), bad, "alice", "pw").catch((e: unknown) => e);
      expect(err, bad).toBeInstanceOf(IdentityInputError);
      expect((err as IdentityInputError).field).toBe("setup_link");
    }
    expect(requests).toEqual([]);
  });
});

describe("helpers", () => {
  it("tenantFromGrant decodes the rt1 tenant segment to the canonical UUID", () => {
    expect(tenantFromGrant(GRANT)).toBe(TENANT);
    expect(isCanonicalTenantId(TENANT)).toBe(true);
    expect(isCanonicalTenantId(TENANT.toUpperCase())).toBe(false);
  });
});

describe("signOut (§3 [R10])", () => {
  function signedInSession(fetchFn: typeof fetch) {
    const d = deps(fetchFn);
    d.session.signedIn({ state: "authenticated", access_token: "at.jws", expires_in: 600, session_id: "s1" });
    const authed = new ApiClient({ baseUrl: "https://cs.test", fetch: fetchFn, clock: instantClock, auth: d.session });
    return { d, authed };
  }

  it("posts logout with the bearer token and forgets the session", async () => {
    const { requests, fetchFn } = fakeServer({ [LOGOUT_PATH]: () => new Response(null, { status: 204 }) });
    const { d, authed } = signedInSession(fetchFn);
    await signOut(authed, d.session);
    expect(requests[0]!.path).toBe(LOGOUT_PATH);
    expect(requests[0]!.headers.get("Authorization")).toBe("Bearer at.jws");
    expect(d.session.state.authenticated).toBe(false);
  });

  it("keeps the session when logout fails for another reason than unauthenticated", async () => {
    const { fetchFn } = fakeServer({ [LOGOUT_PATH]: () => problem(500, "internal") });
    const { d, authed } = signedInSession(fetchFn);
    await expect(signOut(authed, d.session)).rejects.toBeInstanceOf(ApiError);
    expect(d.session.state.authenticated).toBe(true);
  });
});

// ---- rev 7 / rev 8 ----

function dpopDeps(fetchFn: typeof fetch) {
  const store = memoryDpopKeyStore();
  const keys = new DpopKeyManager({ store, clock: instantClock });
  const client = new ApiClient({ baseUrl: "https://cs.test", fetch: fetchFn, clock: instantClock, retryPolicy: new RetryPolicy(), dpop: keys });
  const transport: RefreshTransport = { refresh: () => Promise.reject(new Error("no refresh in these tests")) };
  const session = new AuthSession({ transport, lock: noCrossTabLock, channel: noAuthChannel, clock: instantClock, dpop: keys });
  const authed = new ApiClient({ baseUrl: "https://cs.test", fetch: fetchFn, clock: instantClock, auth: session, dpop: keys });
  return { client, engine: new FakeEngine(), session, authed, keys, store };
}

function proofPayload(h: Headers): Record<string, unknown> {
  const p = (h.get("DPoP") ?? "").split(".")[1] ?? "";
  return JSON.parse(new TextDecoder().decode(base64urlDecode(p))) as Record<string, unknown>;
}

describe("signIn with DPoP (rev 8)", () => {
  it("creates a new session key before login/finish, proves possession on login/finish only, and sends tokens as DPoP", async () => {
    const { requests, fetchFn } = fakeServer({ [OPAQUE_LOGIN_START_PATH]: loginStartOk, [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH) });
    const d = dpopDeps(fetchFn);
    const old = await d.keys.rotate();
    await signIn(d, TENANT, "alice", "pw");
    const jwk = await d.keys.publicKey();
    expect(jwk).toBeDefined();
    expect(jwk).not.toEqual(old);
    expect(requests[0]!.headers.get("DPoP")).toBeNull();
    expect(proofPayload(requests[1]!.headers)).toMatchObject({ htm: "POST", htu: `https://cs.test${OPAQUE_LOGIN_FINISH_PATH}` });
    expect(proofPayload(requests[1]!.headers)).not.toHaveProperty("ath");
    expect(await d.session.authorization()).toBe("DPoP at.jws");
  });

  it("signOut deletes the session key", async () => {
    const { fetchFn } = fakeServer({
      [OPAQUE_LOGIN_START_PATH]: loginStartOk,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH),
      [LOGOUT_PATH]: () => new Response(null, { status: 204 }),
    });
    const d = dpopDeps(fetchFn);
    await signIn(d, TENANT, "alice", "pw");
    await signOut(d.authed, d.session);
    expect(await d.store.get()).toBeUndefined();
  });
});

describe("reauthenticate (rev 7 opaque/reauth/*: step-up on the existing session)", () => {
  const reauthStartOk: Handler = () => json({ reauth_txn: "rtx", credential_response: base64urlEncode(new Uint8Array(320).fill(6)), ksf_params: KSF });

  it("runs reauth/start + reauth/finish with the access token and proofs; creates no session and keeps the key", async () => {
    const { requests, fetchFn } = fakeServer({
      [OPAQUE_LOGIN_START_PATH]: loginStartOk,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH),
      [OPAQUE_REAUTH_START_PATH]: reauthStartOk,
      [OPAQUE_REAUTH_FINISH_PATH]: () => new Response(null, { status: 204 }),
    });
    const d = dpopDeps(fetchFn);
    await signIn(d, TENANT, "alice", "pw");
    const keyBefore = await d.keys.publicKey();
    const states: unknown[] = [];
    d.session.subscribe((s) => states.push(s));
    requests.length = 0;
    await reauthenticate(d, d.authed, TENANT, "Alice", "pw");
    expect(requests.map((q) => q.path)).toEqual([OPAQUE_REAUTH_START_PATH, OPAQUE_REAUTH_FINISH_PATH]);
    expect(requests[0]!.body).toEqual({ credential_request: base64urlEncode(new Uint8Array(96).fill(1)) });
    expect(requests[1]!.body).toEqual({ reauth_txn: "rtx", credential_finalization: base64urlEncode(new Uint8Array(64).fill(3)) });
    for (const q of requests) {
      expect(q.headers.get("Authorization")).toBe("DPoP at.jws");
      expect(proofPayload(q.headers)).toHaveProperty("ath");
    }
    expect(d.engine.calls.at(-1)).toMatchObject({ kind: "login", tenant: TENANT, login: "alice", ksf: KSF });
    // No new session: no login/finish, no session change, same key.
    expect(states).toEqual([]);
    expect(d.session.state.sessionId).toBe(AUTH.session_id);
    expect(await d.keys.publicKey()).toEqual(keyBefore);
    for (const pw of d.engine.passwords) expect(pw.every((b) => b === 0)).toBe(true);
  });

  it("refuses KSF parameters outside the rev 7 bounds before Argon2id runs", async () => {
    const { requests, fetchFn } = fakeServer({
      [OPAQUE_LOGIN_START_PATH]: loginStartOk,
      [OPAQUE_LOGIN_FINISH_PATH]: () => json(AUTH),
      [OPAQUE_REAUTH_START_PATH]: () =>
        json({ reauth_txn: "rtx", credential_response: base64urlEncode(new Uint8Array(320)), ksf_params: { ...KSF, m_kib: 262145 } }),
    });
    const d = dpopDeps(fetchFn);
    await signIn(d, TENANT, "alice", "pw");
    const finishes = d.engine.calls.filter((c) => c.ksf !== undefined).length;
    await expect(reauthenticate(d, d.authed, TENANT, "alice", "pw")).rejects.toMatchObject({ problem: { code: "internal" } });
    expect(d.engine.calls.filter((c) => c.ksf !== undefined).length).toBe(finishes); // the KSF never ran
    expect(requests.map((q) => q.path)).not.toContain(OPAQUE_REAUTH_FINISH_PATH);
  });

  it("a wrong password is `unauthenticated` and reauth/finish is not called", async () => {
    const { requests, fetchFn } = fakeServer({ [OPAQUE_REAUTH_START_PATH]: reauthStartOk });
    const d = dpopDeps(fetchFn);
    d.engine.finishError = new OpaqueClientError("invalid_login");
    await expect(reauthenticate(d, d.authed, TENANT, "alice", "bad")).rejects.toMatchObject({ problem: { code: "unauthenticated" } });
    expect(requests.map((q) => q.path)).toEqual([OPAQUE_REAUTH_START_PATH]);
  });
});

describe("getMe (rev 7 GET /api/v2/me)", () => {
  const ME = { user_id: "u", tenant_id: TENANT, login: "alice", display_name: "", state: "active", amr: ["pwd"], auth_time: 1_700_000_000, sid: "s" };

  it("decodes the contract shape", async () => {
    const { fetchFn } = fakeServer({ [ME_PATH]: () => json(ME) });
    expect(await getMe(dpopDeps(fetchFn).authed)).toEqual(ME);
  });

  it("accepts display_name null (rev 14 addendum) and falls back to the login for display", async () => {
    const { fetchFn } = fakeServer({ [ME_PATH]: () => json({ ...ME, display_name: null }) });
    const me = await getMe(dpopDeps(fetchFn).authed);
    expect(me.display_name).toBeNull();
    expect(meDisplayName(me)).toBe("alice");
    expect(meDisplayName({ ...me, display_name: "" })).toBe("alice");
    expect(meDisplayName({ ...me, display_name: "Alice Example" })).toBe("Alice Example");
  });

  it("rejects malformed bodies as internal", async () => {
    for (const bad of [{ ...ME, amr: "pwd" }, { ...ME, auth_time: "x" }, { ...ME, sid: "" }, { ...ME, display_name: 1 }, { ...ME, display_name: undefined }, []]) {
      const { fetchFn } = fakeServer({ [ME_PATH]: () => json(bad) });
      await expect(getMe(dpopDeps(fetchFn).authed)).rejects.toMatchObject({ problem: { code: "internal" } });
    }
  });
});
