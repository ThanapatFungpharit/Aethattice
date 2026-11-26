// M1 identity end to end: the real @cs/sdk and opaque-wasm against `cs serve --dev` (scripts/e2e.sh).
// The tests run in order and share one account in a tenant created for this run.
import {
  ApiError,
  changePassword,
  completeMfaWithPasskey,
  generateRecoveryCodes,
  getMe,
  isMfaRequired,
  listPasskeys,
  ME_PATH,
  creationOptionsFromJson,
  registrationToJson,
  WEBAUTHN_REGISTER_FINISH_PATH,
  WEBAUTHN_REGISTER_START_PATH,
  listSessions,
  meDisplayName,
  reauthenticate,
  RecoveryFlow,
  register,
  registerPasskey,
  remainingRecoveryCodes,
  signIn,
  signInWithPasskey,
  signOut,
  type MfaRequired,
} from "@cs/sdk";
import { afterAll, describe, expect, it } from "vitest";
import { BrowserLike, E2E, REFRESH_COOKIE, ShiftedClock, tamper, type Tab } from "./harness";
import { SoftAuthenticator } from "./softauthn";

const PW1 = "correct horse battery staple 1";
const PW2 = "correct horse battery staple 2";
const PW3 = "correct horse battery staple 3";

/** Seconds before expiry inside the 60 s leeway, for a 600 s access token. */
const NEAR_EXPIRY_MS = (600 - 30) * 1000;

function code(e: unknown): string | undefined {
  return e instanceof ApiError ? e.problem.code : undefined;
}

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error("expected a rejection");
}

const browser = new BrowserLike();
const clockA = new ShiftedClock();
const tabA = browser.tab({ clock: clockA });
const tabs: Tab[] = [tabA];
let password = PW1;
/** The signed-in tab the later steps continue with. */
const session: { tab: Tab | undefined } = { tab: tabA };

afterAll(() => {
  for (const t of tabs) t.dispose();
});

describe("sign-in (WEB.M1-6: rev 5 §2.1, §2.4)", () => {
  it("registers from the setup link, then signs in with OPAQUE (Argon2id in WASM) and gets a refresh cookie", async () => {
    const result = await register(tabA.deps, E2E.setupLink, E2E.login, password);
    expect(result.state).toBe("authenticated");
    expect(tabA.session.state).toEqual({ authenticated: true, sessionId: result.session_id });
    expect(browser.refreshCookie).toBeDefined();
    expect(browser.cookies.get(REFRESH_COOKIE)?.path).toBe("/api/v2/auth/token");
    // The setup link is single use (§6: registration_grant_required → permission_denied).
    const again = new BrowserLike().tab();
    tabs.push(again);
    expect(code(await rejection(register(again.deps, E2E.setupLink, E2E.login, password)))).toBe("permission_denied");
  });

  it("calls an authenticated endpoint with a DPoP-bound token (WebCrypto ES256 proof)", async () => {
    const from = browser.log.length;
    const me = await getMe(tabA.authed);
    expect(me.tenant_id).toBe(E2E.tenant);
    expect(me.login).toBe(E2E.login);
    expect(me.sid).toBe(tabA.session.state.sessionId);
    // Created without a display name: null on the wire, the login for display (rev 14 addendum).
    expect(me.display_name).toBeNull();
    expect(meDisplayName(me)).toBe(E2E.login);
    const [call] = browser.requests(ME_PATH, from);
    expect(call).toMatchObject({ status: 200, authScheme: "DPoP", dpop: true });
    // The token is bound (cnf.jkt): presented as a bearer token, without a proof, it is refused.
    const auth = await tabA.session.authorization();
    const token = auth?.split(" ")[1] ?? "";
    // Session list: this session is current; last_seen_at is null until its first refresh (nullable).
    const sessions = await listSessions(tabA.authed);
    expect(sessions.find((x) => x.current)?.sid).toBe(me.sid);
    const bare = await browser.fetch(`${browser.origin}${ME_PATH}`, { headers: { Authorization: `Bearer ${token}` } });
    expect(bare.status).toBe(401);
  });

  it("a wrong password is reported as unauthenticated", async () => {
    const other = new BrowserLike().tab();
    tabs.push(other);
    expect(code(await rejection(signIn(other.deps, E2E.tenant, E2E.login, "not the password")))).toBe("unauthenticated");
    expect(other.session.state.authenticated).toBe(false);
  });
});

describe("refresh (D.2-2, M1 §3 [R1] [R12])", () => {
  it("refreshes proactively within the 60 s leeway and rotates the refresh cookie", async () => {
    const from = browser.log.length;
    const before = browser.refreshCookie;
    const tokenBefore = await tabA.session.authorization();
    clockA.offsetMs = NEAR_EXPIRY_MS;
    await getMe(tabA.authed);
    clockA.offsetMs = 0;
    const refreshes = browser.refreshes(from);
    expect(refreshes).toHaveLength(1);
    expect(refreshes[0]).toMatchObject({ status: 200, dpop: true, refreshCookie: before });
    expect(refreshes[0]?.idempotencyKey).toBeDefined();
    expect(browser.refreshCookie).toBeDefined();
    expect(browser.refreshCookie).not.toBe(before);
    expect(await tabA.session.authorization()).not.toBe(tokenBefore);
    // No 401 was needed: the refresh happened before the call.
    expect(browser.log.slice(from).map((r) => r.status)).toEqual([200, 200]);
  });

  it("on 401 refreshes once and retries once", async () => {
    const auth = await tabA.session.authorization();
    tabA.holdToken(tamper(auth?.split(" ")[1] ?? ""));
    const from = browser.log.length;
    const me = await getMe(tabA.authed);
    expect(me.login).toBe(E2E.login);
    expect(browser.log.slice(from).map((r) => [r.path, r.status])).toEqual([
      [ME_PATH, 401],
      ["/api/v2/auth/token/refresh", 200],
      [ME_PATH, 200],
    ]);
  });

  it("does not loop when the refresh fails too: one refresh, no second retry, signed out", async () => {
    const auth = await tabA.session.authorization();
    const saved = browser.cookies.get(REFRESH_COOKIE);
    tabA.holdToken(tamper(auth?.split(" ")[1] ?? ""));
    browser.cookies.delete(REFRESH_COOKIE);
    const from = browser.log.length;
    expect(code(await rejection(getMe(tabA.authed)))).toBe("unauthenticated");
    expect(browser.log.slice(from).map((r) => [r.path, r.status])).toEqual([
      [ME_PATH, 401],
      ["/api/v2/auth/token/refresh", 401],
    ]);
    expect(tabA.session.state.authenticated).toBe(false);
    if (saved) browser.cookies.set(REFRESH_COOKIE, saved);
    // That server session is still valid; start a clean one for the rest of the suite.
    browser.cookies.delete(REFRESH_COOKIE);
    await signIn(tabA.deps, E2E.tenant, E2E.login, password);
    expect((await getMe(tabA.authed)).login).toBe(E2E.login);
  });
});

describe("two tabs share one refresh (WEB.M1-1, M1 §3 [R1])", () => {
  for (const lock of ["web-locks", "lease"] as const) {
    it(`${lock}: concurrent near-expiry calls in two tabs cause exactly one refresh, never a reused cookie`, async () => {
      const clockB = new ShiftedClock();
      const a = lock === "web-locks" ? tabA : browser.tab({ lock, clock: clockA });
      const b = browser.tab({ lock, clock: clockB });
      tabs.push(a, b);
      // A new tab starts without a token and obtains one through the shared cookie; the other tab receives it.
      expect(await b.session.refresh()).toBe(true);
      await new Promise((r) => setTimeout(r, 20));
      const tokenB = await b.session.authorization();
      if (a !== tabA) expect(await a.session.authorization()).toBe(tokenB);

      const from = browser.log.length;
      clockA.offsetMs = NEAR_EXPIRY_MS;
      clockB.offsetMs = NEAR_EXPIRY_MS;
      const [meA, meB] = await Promise.all([getMe(a.authed), getMe(b.authed)]);
      clockA.offsetMs = 0;
      clockB.offsetMs = 0;
      expect(meA.sid).toBe(meB.sid);
      const refreshes = browser.refreshes(from);
      expect(refreshes).toHaveLength(1);
      expect(refreshes[0]?.status).toBe(200);
      expect(browser.log.slice(from).every((r) => r.status === 200)).toBe(true);
      // Both tabs hold the same new token.
      expect(await a.session.authorization()).toBe(await b.session.authorization());
      expect(await a.session.authorization()).not.toBe(tokenB);
      // A refresh cookie was never presented twice over the whole run.
      const presented = browser.refreshes().map((r) => r.refreshCookie).filter((c) => c !== undefined);
      expect(new Set(presented).size).toBe(presented.length);
    });
  }
});

describe("step-up and password change (WEB.M1-6: rev 7 reauth, rev 9 re-registration)", () => {
  it("reauthenticates the session with OPAQUE; a wrong password is unauthenticated", async () => {
    const sid = tabA.session.state.sessionId;
    expect(code(await rejection(reauthenticate(tabA.deps, tabA.authed, E2E.tenant, E2E.login, "wrong password")))).toBe("unauthenticated");
    await reauthenticate(tabA.deps, tabA.authed, E2E.tenant, E2E.login, password);
    // Same session, nothing reissued.
    expect(tabA.session.state.sessionId).toBe(sid);
    expect((await getMe(tabA.authed)).sid).toBe(sid);
  });

  it("changes the password by re-registration: this session stays, other sessions are revoked", async () => {
    const other = new BrowserLike().tab();
    tabs.push(other);
    await signIn(other.deps, E2E.tenant, E2E.login, password);
    await changePassword(tabA.deps, tabA.authed, E2E.tenant, E2E.login, PW2);
    const old = password;
    password = PW2;
    expect((await getMe(tabA.authed)).login).toBe(E2E.login);
    expect(await tabA.session.refresh()).toBe(true);
    // The other session's access token may live until its expiry; its refresh family is gone.
    expect(await other.session.refresh()).toBe(false);
    expect(other.session.state.authenticated).toBe(false);
    const fresh = new BrowserLike().tab();
    tabs.push(fresh);
    expect(code(await rejection(signIn(fresh.deps, E2E.tenant, E2E.login, old)))).toBe("unauthenticated");
    await signIn(fresh.deps, E2E.tenant, E2E.login, password);
  });
});

describe("recovery code (rev 10/11)", () => {
  let codes: string[] = [];

  it("generates a set of 10 codes on a stepped-up session", async () => {
    codes = await generateRecoveryCodes(tabA.authed);
    expect(codes).toHaveLength(10);
    expect(await remainingRecoveryCodes(tabA.authed)).toBe(10);
  });

  it("recovers the account with a code: new password, all sessions revoked, code used once", async () => {
    const rb = new BrowserLike();
    const r = rb.tab();
    tabs.push(r);
    const flow = new RecoveryFlow(r.deps);
    await flow.startWithCode(E2E.tenant, E2E.login, codes[0] ?? "");
    expect(flow.phase.kind).toBe("granted");
    await flow.complete(E2E.login, PW3);
    password = PW3;
    expect(flow.phase.kind).toBe("done");
    expect((await getMe(r.authed)).login).toBe(E2E.login);
    expect(await remainingRecoveryCodes(r.authed)).toBe(9);
    // Recovery revoked every earlier session, including tab A's refresh family.
    expect(await tabA.session.refresh()).toBe(false);
    const again = new RecoveryFlow(new BrowserLike().tab().deps);
    expect(code(await rejection(again.startWithCode(E2E.tenant, E2E.login, codes[0] ?? "")))).toBe("unauthenticated");
    session.tab = r;
  });
});

describe("passkey with a software authenticator (rev 10/11)", () => {
  const authn = new SoftAuthenticator(`https://${E2E.domain}`);

  it("registers a passkey on a stepped-up session", async () => {
    const t = session.tab;
    if (!t) throw new Error("no session");
    const from = t.browser.log.length;
    const pk = await registerPasskey(t.authed, authn, "e2e key");
    expect(pk.label).toBe("e2e key");
    expect(pk.last_used_at).toBeNull();
    // Exactly one finish, answered 2xx (no retry of a write that succeeded).
    expect(t.browser.requests(WEBAUTHN_REGISTER_FINISH_PATH, from).map((r) => r.status)).toEqual([200]);
    expect(await listPasskeys(t.authed)).toHaveLength(1);
  });

  it("signs in passwordless, and a password sign-in now needs the passkey as second factor", async () => {
    const t = session.tab;
    if (!t) throw new Error("no session");
    await signOut(t.authed, t.session);
    const p = new BrowserLike().tab();
    tabs.push(p);
    await signInWithPasskey(p.deps, authn, E2E.tenant);
    expect((await getMe(p.authed)).login).toBe(E2E.login);

    const m = new BrowserLike().tab();
    tabs.push(m);
    const mfa = await rejection(signIn(m.deps, E2E.tenant, E2E.login, password));
    expect(isMfaRequired(mfa)).toBe(true);
    await completeMfaWithPasskey(m.deps, authn, mfa as MfaRequired);
    expect((await getMe(m.authed)).login).toBe(E2E.login);
    session.tab = m;
  });
});

describe("Idempotency-Key replay of identity writes (contract rev 15)", () => {
  // A lost register/finish response retried with the same Idempotency-Key must replay the first 2xx instead of
  // answering 401 for the consumed txn. Server-side replay is the backend's rev 15 work (TL, 2026-11-26).
  it.skip("register/finish retried with the same Idempotency-Key replays the 2xx (pending backend, contract rev 15)", async () => {
    const t = session.tab;
    if (!t) throw new Error("no session");
    await reauthenticate(t.deps, t.authed, E2E.tenant, E2E.login, password);
    const start = await t.authed.post<{ registration_txn: string; public_key: unknown }>(WEBAUTHN_REGISTER_START_PATH, { body: {} });
    const credential = await new SoftAuthenticator(`https://${E2E.domain}`).create({ publicKey: creationOptionsFromJson(start.data.public_key) });
    if (!credential) throw new Error("no credential");
    const body = { registration_txn: start.data.registration_txn, credential: registrationToJson(credential), label: "replayed" };
    const first = await t.authed.post(WEBAUTHN_REGISTER_FINISH_PATH, { body, idempotencyKey: "e2e-replay-1", retry: false });
    const again = await t.authed.post(WEBAUTHN_REGISTER_FINISH_PATH, { body, idempotencyKey: "e2e-replay-1", retry: false });
    expect(again.status).toBe(first.status);
    expect(again.data).toEqual(first.data);
  });
});

describe("logout (WEB.M1-6: §3 [R10])", () => {
  it("revokes the session and its refresh family and clears the cookie", async () => {
    const t = session.tab;
    if (!t) throw new Error("no session");
    const b = t.browser;
    const cookie = b.cookies.get(REFRESH_COOKIE);
    const key = await b.keyStore.get();
    expect(cookie).toBeDefined();
    await signOut(t.authed, t.session);
    expect(t.session.state.authenticated).toBe(false);
    expect(b.refreshCookie).toBeUndefined();
    expect(code(await rejection(getMe(t.authed)))).toBe("unauthenticated");
    // Replaying the last refresh cookie with the session's own DPoP key is refused: the family is revoked.
    if (cookie && key) {
      b.cookies.set(REFRESH_COOKIE, cookie);
      await b.keyStore.put(key);
      t.keys.invalidate();
      const from = b.log.length;
      expect(await t.session.refresh()).toBe(false);
      expect(b.refreshes(from).map((r) => r.status)).toEqual([401]);
    }
  });
});
