import {
  ApiClient,
  AuthSession,
  OpaqueClientError,
  RetryPolicy,
  StepUpRequired,
  base64urlEncode,
  errorCodeInfo,
  noAuthChannel,
  noCrossTabLock,
  type Clock,
  type CoreErrorCode,
  type IdentityDeps,
  type OpaqueEngine,
  type RefreshLock,
} from "@cs/sdk";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { CsAccountPage, CsRegisterPage, CsSignInPage, CsStepUpDialog } from "./auth-pages";
import "./cs-shell-app";
import type { CsShellApp } from "./cs-shell-app";
import { routeFromHash } from "./cs-shell-app";
import { registerShellMessages } from "./messages";

const TENANT = "0190c1d2-0000-7000-8000-000000000001";
const TENANT_BYTES = Uint8Array.from([0x01, 0x90, 0xc1, 0xd2, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]);
const GRANT = `rt1.${base64urlEncode(TENANT_BYTES)}.${base64urlEncode(new Uint8Array(32).fill(7))}`;
const KSF = { algorithm: "argon2id", m_kib: 65536, t: 3, p: 1 };
const clock: Clock = { now: () => 1_000_000, sleep: () => Promise.resolve() };

const json = (v: unknown, status = 200): Response => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const problem = (status: number, code: CoreErrorCode, errors?: unknown[]): Response =>
  new Response(JSON.stringify({ type: "about:blank", title: code, status, code, retryable: errorCodeInfo(code).retryable, ...(errors && { errors }) }), {
    status,
    headers: { "Content-Type": "application/problem+json" },
  });

/** Engine that accepts password "right" only, like OPAQUE would (failure detected on the client at finish). */
const engine: OpaqueEngine = {
  start: (_kind, password) => {
    const ok = new TextDecoder().decode(password) === "right";
    return Promise.resolve({
      request: new Uint8Array(96),
      finish: () => (ok ? Promise.resolve(new Uint8Array(64)) : Promise.reject(new OpaqueClientError("invalid_login"))),
      abandon: () => undefined,
    });
  },
  normalizeLogin: (l) => (/\s/.test(l) || l === "" ? Promise.reject(new OpaqueClientError("invalid_input")) : Promise.resolve(l.toLowerCase())),
};

let sessionCounter = 0;
function server(overrides: Record<string, () => Response> = {}) {
  const paths: string[] = [];
  const routes: Record<string, () => Response> = {
    "/api/v2/auth/opaque/login/start": () => json({ login_txn: "t", credential_response: base64urlEncode(new Uint8Array(320)), ksf_params: KSF }),
    "/api/v2/auth/opaque/login/finish": () => json({ state: "authenticated", access_token: `at${++sessionCounter}`, expires_in: 600, session_id: `s${sessionCounter}` }),
    "/api/v2/auth/opaque/register/start": () => json({ registration_txn: "r", registration_response: base64urlEncode(new Uint8Array(64)), ksf_params: KSF }),
    "/api/v2/auth/opaque/register/finish": () => new Response(null, { status: 204 }),
    "/api/v2/auth/logout": () => new Response(null, { status: 204 }),
    "/api/v2/auth/opaque/reauth/start": () => json({ reauth_txn: "rt", credential_response: base64urlEncode(new Uint8Array(320)), ksf_params: KSF }),
    "/api/v2/auth/opaque/reauth/finish": () => new Response(null, { status: 204 }),
    "/api/v2/me": () =>
      json({
        user_id: "u-1",
        tenant_id: TENANT,
        login: "alice",
        display_name: "Alice Example",
        state: "active",
        amr: ["pwd"],
        auth_time: 1_700_000_000,
        sid: `s${sessionCounter}`,
      }),
    "/readyz": () => json({}),
    ...overrides,
  };
  const auths: (string | null)[] = [];
  const fetchFn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url).pathname;
    paths.push(path);
    auths.push(new Headers(init?.headers).get("Authorization"));
    const r = routes[path];
    return Promise.resolve(r ? r() : problem(404, "not_found"));
  });
  return { paths, auths, fetchFn };
}

function setup(lock: RefreshLock = noCrossTabLock, overrides: Record<string, () => Response> = {}) {
  const { paths, auths, fetchFn } = server(overrides);
  const client = new ApiClient({ baseUrl: "https://shell.test", fetch: fetchFn, clock, retryPolicy: new RetryPolicy() });
  const session = new AuthSession({ transport: { refresh: () => Promise.reject(new Error("none")) }, lock, channel: noAuthChannel, clock });
  const identity: IdentityDeps = { client, engine, session };
  const authedClient = new ApiClient({ baseUrl: "https://shell.test", fetch: fetchFn, clock, auth: session });
  return { paths, auths, identity, session, authedClient, client };
}

async function mount(s: ReturnType<typeof setup>, hash: string): Promise<CsShellApp> {
  location.hash = hash;
  const el = document.createElement("cs-shell-app");
  el.client = s.client;
  el.identity = s.identity;
  el.authedClient = s.authedClient;
  document.body.appendChild(el);
  await el.updateComplete;
  return el;
}

// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- typed query helper for tests
function q<T extends Element>(el: Element, selector: string): T {
  const found = el.shadowRoot?.querySelector<T>(selector);
  if (!found) throw new Error(`not found: ${selector}`);
  return found;
}

function fill(page: Element, values: Record<string, string>): void {
  for (const [name, v] of Object.entries(values)) q<HTMLElement & { value: string }>(page, `cs-text-field[name="${name}"]`).value = v;
}

const settle = async (...els: { updateComplete: Promise<boolean> }[]): Promise<void> => {
  await new Promise((r) => setTimeout(r, 0));
  for (const e of els) await e.updateComplete;
};

beforeAll(() => {
  registerShellMessages();
});

afterEach(() => {
  document.body.innerHTML = "";
  history.replaceState(null, "", "#");
});

describe("routes", () => {
  it("maps identity hashes", () => {
    expect(routeFromHash("#/sign-in")).toBe("sign-in");
    expect(routeFromHash("#/register")).toBe("register");
    expect(routeFromHash(`#/register/${GRANT}`)).toBe("register");
    expect(routeFromHash("#/account")).toBe("account");
    expect(routeFromHash("#/security")).toBe("security");
    expect(routeFromHash("#/recover")).toBe("recover");
    expect(routeFromHash("#/recover/rt1.x.y")).toBe("recover");
    expect(routeFromHash("#/enrol")).toBe("enrol");
  });
});

describe("sign-in page", () => {
  async function signInWith(s: ReturnType<typeof setup>, values: Record<string, string>) {
    const shell = await mount(s, "#/sign-in");
    const page = q<CsSignInPage>(shell, "cs-sign-in-page");
    await page.updateComplete;
    fill(page, values);
    await page.submit();
    await settle(shell, page);
    return { shell, page };
  }

  it("signs in, shows the account page with the normalized login, and offers sign-out", async () => {
    const s = setup();
    const { shell } = await signInWith(s, { tenant: TENANT, login: "Alice", password: "right" });
    expect(location.hash).toBe("#/account");
    const account = q<CsAccountPage>(shell, "cs-account-page");
    await account.updateComplete;
    expect(q(account, "dd.login").textContent).toBe("alice");
    expect(account.shadowRoot?.textContent).toContain("s1");
    expect(q(shell, 'a[href="#/account"]')).toBeTruthy();
  });

  it("shows one inline message for wrong credentials and clears the password", async () => {
    const s = setup();
    const { page } = await signInWith(s, { tenant: TENANT, login: "alice", password: "wrong" });
    const alert = q(page, ".failure[role=alert]");
    expect(alert.textContent).toBe("The organization ID, login or password is not correct.");
    expect(page.shadowRoot?.querySelector("cs-error-banner")).toBeNull();
    expect(q<HTMLElement & { value: string }>(page, 'cs-text-field[name="password"]').value).toBe("");
    expect(s.paths).not.toContain("/api/v2/auth/opaque/login/finish");
  });

  it("shows other problems in cs-error-banner", async () => {
    const s = setup(noCrossTabLock, { "/api/v2/auth/opaque/login/start": () => problem(503, "unavailable") });
    const { page } = await signInWith(s, { tenant: TENANT, login: "alice", password: "right" });
    const banner = q<HTMLElement & { problem?: { code: string } }>(page, "cs-error-banner");
    expect(banner.problem?.code).toBe("unavailable");
  });

  it("marks the tenant field for a non-UUID organization ID, without a request", async () => {
    const s = setup();
    const { page } = await signInWith(s, { tenant: "acme", login: "alice", password: "right" });
    const field = q<HTMLElement & { error?: string }>(page, 'cs-text-field[name="tenant"]');
    expect(field.error).toBe("Enter the organization ID exactly as you received it.");
    expect(s.paths.filter((p) => p.startsWith("/api"))).toEqual([]);
  });

  it("shows the second-factor step when login/finish answers mfa_required (no passkey API: explains, offers cancel)", async () => {
    const s = setup(noCrossTabLock, { "/api/v2/auth/opaque/login/finish": () => json({ state: "mfa_required", auth_txn: "a", methods: ["webauthn"] }) });
    const { page } = await signInWith(s, { tenant: TENANT, login: "alice", password: "right" });
    expect(q(page, "h1").textContent).toBe("Confirm with a second factor");
    expect(page.shadowRoot?.textContent).toContain("can be used in this browser");
    expect(s.session.state.authenticated).toBe(false);
  });
});

describe("registration page", () => {
  it("takes the setup link from the hash, removes it from the address bar, registers and signs in", async () => {
    const s = setup();
    const shell = await mount(s, `#/register/${GRANT}`);
    expect(location.hash).toBe("#/register");
    const page = q<CsRegisterPage>(shell, "cs-register-page");
    await page.updateComplete;
    expect(q<HTMLElement & { value: string }>(page, 'cs-text-field[name="setup_link"]').value).toBe(GRANT);
    fill(page, { login: "Alice", password: "right", confirm: "right" });
    await page.submit();
    await settle(shell);
    expect(s.paths.filter((p) => p.startsWith("/api"))).toEqual([
      "/api/v2/auth/opaque/register/start",
      "/api/v2/auth/opaque/register/finish",
      "/api/v2/auth/opaque/login/start",
      "/api/v2/auth/opaque/login/finish",
      // The account page it lands on loads GET /me (rev 7).
      "/api/v2/me",
    ]);
    expect(location.hash).toBe("#/account");
  });

  it("checks that both passwords match before any request", async () => {
    const s = setup();
    const shell = await mount(s, "#/register");
    const page = q<CsRegisterPage>(shell, "cs-register-page");
    await page.updateComplete;
    fill(page, { setup_link: GRANT, login: "alice", password: "a", confirm: "b" });
    await page.submit();
    await page.updateComplete;
    expect(q<HTMLElement & { error?: string }>(page, 'cs-text-field[name="confirm"]').error).toBe("The passwords do not match.");
    expect(s.paths.filter((p) => p.startsWith("/api"))).toEqual([]);
  });

  it("marks a malformed setup link", async () => {
    const s = setup();
    const shell = await mount(s, "#/register");
    const page = q<CsRegisterPage>(shell, "cs-register-page");
    await page.updateComplete;
    fill(page, { setup_link: "not-a-link", login: "alice", password: "a", confirm: "a" });
    await page.submit();
    await page.updateComplete;
    expect(q<HTMLElement & { error?: string }>(page, 'cs-text-field[name="setup_link"]').error).toContain("not valid");
  });
});

async function signedInShell(lock: RefreshLock = noCrossTabLock, overrides: Record<string, () => Response> = {}) {
  const s = setup(lock, overrides);
  const shell = await mount(s, "#/sign-in");
  const page = q<CsSignInPage>(shell, "cs-sign-in-page");
  await page.updateComplete;
  fill(page, { tenant: TENANT, login: "alice", password: "right" });
  await page.submit();
  await settle(shell);
  return { s, shell };
}

describe("account page", () => {
  it("shows the account from GET /api/v2/me (rev 7)", async () => {
    const { s, shell } = await signedInShell();
    const account = q<CsAccountPage>(shell, "cs-account-page");
    await account.load();
    await account.updateComplete;
    expect(s.paths).toContain("/api/v2/me");
    expect(s.auths[s.paths.indexOf("/api/v2/me")]).toMatch(/^Bearer at\d+$/);
    expect(q(account, ".display-name").textContent).toBe("Alice Example");
    expect(q(account, ".login").textContent).toBe("alice");
    expect(q(account, ".tenant").textContent).toBe(TENANT);
    expect(q(account, ".session").textContent).toBe(s.session.state.sessionId);
    expect(q(account, ".amr").textContent).toBe("pwd");
    expect(q(account, ".auth-time time").getAttribute("datetime")).toBe(new Date(1_700_000_000_000).toISOString());
  });

  it("shows the login as the name when display_name is null (rev 14 addendum)", async () => {
    const me = { user_id: "u-1", tenant_id: TENANT, login: "alice", display_name: null, state: "active", amr: ["pwd"], auth_time: 1_700_000_000, sid: "s1" };
    const { shell } = await signedInShell(noCrossTabLock, { "/api/v2/me": () => json(me) });
    const account = q<CsAccountPage>(shell, "cs-account-page");
    await account.load();
    await account.updateComplete;
    expect(q(account, ".display-name").textContent).toBe("alice");
    expect(q(account, ".login").textContent).toBe("alice");
  });

  it("shows the problem when /me fails and keeps what sign-in knew", async () => {
    const { shell } = await signedInShell(noCrossTabLock, { "/api/v2/me": () => problem(503, "unavailable") });
    const account = q<CsAccountPage>(shell, "cs-account-page");
    await account.load();
    await account.updateComplete;
    expect(q(account, ".login").textContent).toBe("alice");
    expect(q<HTMLElement & { problem?: { code: string } }>(account, "cs-error-banner").problem?.code).toBe("unavailable");
  });

  it("signs out through POST /api/v2/auth/logout and returns to sign-in", async () => {
    const { s, shell } = await signedInShell();
    const account = q<CsAccountPage>(shell, "cs-account-page");
    await account.signOut();
    await settle(shell);
    expect(s.paths).toContain("/api/v2/auth/logout");
    expect(s.session.state.authenticated).toBe(false);
    expect(location.hash).toBe("#/sign-in");
  });

  it("keeps the user signed in and shows the banner when logout fails", async () => {
    const { s, shell } = await signedInShell(noCrossTabLock, { "/api/v2/auth/logout": () => problem(500, "internal") });
    const account = q<CsAccountPage>(shell, "cs-account-page");
    await account.signOut();
    await account.updateComplete;
    expect(s.session.state.authenticated).toBe(true);
    expect(q<HTMLElement & { problem?: { code: string } }>(account, "cs-error-banner").problem?.code).toBe("internal");
  });
});

describe("single-active-tab notice (§3 [R1])", () => {
  const lease: RefreshLock = { mode: "lease", run: (fn) => fn() };
  const webLocks: RefreshLock = { mode: "web-locks", run: (fn) => fn() };

  it("is shown while signed in when refreshes fall back to the localStorage lease", async () => {
    const { shell } = await signedInShell(lease);
    expect(q(shell, ".tab-notice[role=status]").textContent).toContain("one tab");
  });

  it("is not shown with Web Locks", async () => {
    const { shell } = await signedInShell(webLocks);
    expect(shell.shadowRoot?.querySelector(".tab-notice")).toBeNull();
  });
});

describe("step-up (§2.3 [R2])", () => {
  const stepUp = (): StepUpRequired =>
    new StepUpRequired(
      { type: "about:blank", title: "u", status: 401, code: "unauthenticated", retryable: false, errors: [{ pointer: "", code: "step_up_required", detail: "d" }] },
      { httpStatus: 401, synthesized: false, attempts: 1 },
    );

  it("asks for the password, re-authenticates on the current session (reauth/*, rev 7), and retries the operation once", async () => {
    const { s, shell } = await signedInShell();
    const sessionBefore = s.session.state.sessionId;
    let calls = 0;
    const op = vi.fn(() => (++calls === 1 ? Promise.reject(stepUp()) : Promise.resolve("done")));
    const result = shell.runWithStepUp(op);
    await settle(shell);
    const dialog = q<CsStepUpDialog>(shell, "cs-step-up-dialog");
    await dialog.updateComplete;
    expect(dialog.open).toBe(true);
    fill(dialog, { password: "right" });
    await dialog.submit();
    expect(await result).toBe("done");
    expect(op).toHaveBeenCalledTimes(2);
    // No new session: login/finish ran only for the original sign-in, reauth carried the access token.
    expect(s.paths.filter((p) => p === "/api/v2/auth/opaque/login/finish").length).toBe(1);
    expect(s.paths.filter((p) => p.startsWith("/api/v2/auth/opaque/reauth/"))).toEqual([
      "/api/v2/auth/opaque/reauth/start",
      "/api/v2/auth/opaque/reauth/finish",
    ]);
    expect(s.auths[s.paths.indexOf("/api/v2/auth/opaque/reauth/start")]).toBe(`Bearer at${String(sessionCounter)}`);
    expect(s.session.state.sessionId).toBe(sessionBefore);
    expect(dialog.open).toBe(false);
  });

  it("keeps the dialog open on a wrong password and rejects with StepUpRequired when cancelled", async () => {
    const { shell } = await signedInShell();
    const result = shell.runWithStepUp(() => Promise.reject(stepUp()));
    await settle(shell);
    const dialog = q<CsStepUpDialog>(shell, "cs-step-up-dialog");
    await dialog.updateComplete;
    fill(dialog, { password: "wrong" });
    await dialog.submit();
    await dialog.updateComplete;
    expect(dialog.open).toBe(true);
    expect(q(dialog, ".failure").textContent).toContain("not correct");
    dialog.dispatchEvent(new CustomEvent("cs-step-up-cancel", { bubbles: true, composed: true }));
    await expect(result).rejects.toBeInstanceOf(StepUpRequired);
  });
});
