// Shell flows for rev 9–11: transparent re-registration notice, MFA step, passkey sign-in and step-up, security
// page (password change, sessions, passkeys, recovery codes, recovery requests), recovery pages and forced enrolment.
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
  type CredentialsLike,
  type IdentityDeps,
  type OpaqueEngine,
} from "@cs/sdk";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { CsSignInPage, CsStepUpDialog } from "./auth-pages";
import "./cs-shell-app";
import type { CsShellApp } from "./cs-shell-app";
import { registerShellMessages } from "./messages";
import type { CsEnrolmentPage, CsRecoveryPage, StepUpRunner } from "./security-pages";

const TENANT = "0190c1d2-0000-7000-8000-000000000001";
const TENANT_BYTES = Uint8Array.from([0x01, 0x90, 0xc1, 0xd2, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]);
const GRANT = `rt1.${base64urlEncode(TENANT_BYTES)}.${base64urlEncode(new Uint8Array(32).fill(5))}`;
const KSF = { algorithm: "argon2id", m_kib: 65536, t: 3, p: 1 };
const CODE = "ABCDEFGH-ABCDEFGHIJKLMNOPQRST";
const T0 = "2026-11-26T10:00:00Z";
const clock: Clock = { now: () => 1_000_000, sleep: () => Promise.resolve() };

const json = (v: unknown, status = 200): Response => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const noContent = (): Response => new Response(null, { status: 204 });
const problem = (status: number, code: CoreErrorCode, errors?: unknown[]): Response =>
  new Response(JSON.stringify({ type: "about:blank", title: code, status, code, retryable: errorCodeInfo(code).retryable, ...(errors && { errors }) }), {
    status,
    headers: { "Content-Type": "application/problem+json" },
  });
const stepUpProblem = (): Response => problem(401, "unauthenticated", [{ pointer: "", code: "step_up_required", detail: "d" }]);
const jwt = (payload: unknown): string => `e30.${base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)))}.sig`;

const engine: OpaqueEngine = {
  start: (_kind, password) => {
    const ok = new TextDecoder().decode(password) !== "wrong";
    return Promise.resolve({
      request: new Uint8Array(32),
      finish: () => (ok ? Promise.resolve(new Uint8Array(64)) : Promise.reject(new OpaqueClientError("invalid_login"))),
      abandon: () => undefined,
    });
  },
  normalizeLogin: (l) => Promise.resolve(l.toLowerCase()),
};

const auth = (extra: Record<string, unknown> = {}) => json({ state: "authenticated", access_token: "at", expires_in: 600, session_id: "s-1", ...extra });
const requestOptions = { challenge: "CQkJ", rpId: "shell.test", allowCredentials: [] };
const passkey = { id: "Y3JlZA", label: "Laptop", created_at: T0, last_used_at: null, prf: false };
const codes = Array.from({ length: 10 }, (_, i) => `ABCDEFG${"ABCDEFGHIJ"[i] ?? "A"}-ABCDEFGHIJKLMNOPQRST`);

type Route = (body: Record<string, unknown>) => Response;

function server(overrides: Record<string, Route> = {}) {
  const calls: { method: string; path: string; body: Record<string, unknown> }[] = [];
  const routes: Record<string, Route> = {
    "POST /api/v2/auth/opaque/login/start": () => json({ login_txn: "t", credential_response: base64urlEncode(new Uint8Array(32)), ksf_params: KSF }),
    "POST /api/v2/auth/opaque/login/finish": () => auth(),
    "POST /api/v2/auth/opaque/register/start": () => json({ registration_txn: "r", registration_response: base64urlEncode(new Uint8Array(32)), ksf_params: KSF }),
    "POST /api/v2/auth/opaque/register/finish": noContent,
    "POST /api/v2/auth/logout": noContent,
    "GET /api/v2/me": () => json({ user_id: "u", tenant_id: TENANT, login: "alice", display_name: "", state: "active", amr: ["hwk"], auth_time: 1, sid: "s-1" }),
    "GET /api/v2/me/sessions": () =>
      json({
        items: [
          { sid: "s-1", created_at: T0, last_seen_at: T0, amr: ["pwd"], user_agent: "Firefox", current: true },
          { sid: "s-2", created_at: T0, last_seen_at: T0, amr: ["pwd"], user_agent: "Safari", current: false },
        ],
      }),
    "DELETE /api/v2/me/sessions/s-2": noContent,
    "DELETE /api/v2/me/sessions/s-1": noContent,
    "GET /api/v2/me/passkeys": () => json({ items: [passkey] }),
    "DELETE /api/v2/me/passkeys/Y3JlZA": noContent,
    "POST /api/v2/auth/webauthn/register/start": () =>
      json({ registration_txn: "wr", public_key: { challenge: "CQkJ", rp: { id: "shell.test", name: "CS" }, user: { id: "AQ", name: "a", displayName: "A" }, pubKeyCredParams: [] } }),
    "POST /api/v2/auth/webauthn/register/finish": (b) => json({ ...passkey, id: "bmV3", label: b.label }),
    "POST /api/v2/auth/webauthn/login/start": () => json({ login_txn: "wl", public_key: requestOptions }),
    "POST /api/v2/auth/webauthn/login/finish": () => auth(),
    "POST /api/v2/auth/webauthn/assert/start": () => json({ assert_txn: "wa", public_key: requestOptions }),
    "POST /api/v2/auth/webauthn/assert/finish": () => auth(),
    "POST /api/v2/auth/mfa/recovery-code": () => auth(),
    "GET /api/v2/me/recovery-codes": () => json({ remaining: 3 }),
    "POST /api/v2/me/recovery-codes": () => json({ codes }),
    "GET /api/v2/me/recovery-requests": () =>
      json({
        items: [
          { id: "q1", method: "device_approval", state: "pending", created_at: T0, available_at: null, requester_user_agent: "Chrome on Android" },
          { id: "q2", method: "email", state: "pending", created_at: T0, available_at: T0, requester_user_agent: null },
        ],
      }),
    "POST /api/v2/me/recovery-requests/q1/approve": noContent,
    "DELETE /api/v2/me/recovery-requests/q2": noContent,
    "GET /readyz": () => json({}),
    ...overrides,
  };
  const fetchFn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url).pathname;
    const method = init?.method ?? "GET";
    const body = typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : {};
    calls.push({ method, path, body });
    const r = routes[`${method} ${path}`];
    return Promise.resolve(r ? r(body) : problem(404, "not_found"));
  });
  return { calls, fetchFn };
}

function setup(overrides: Record<string, Route> = {}) {
  const { calls, fetchFn } = server(overrides);
  const client = new ApiClient({ baseUrl: "https://shell.test", fetch: fetchFn, clock, retryPolicy: new RetryPolicy() });
  const session = new AuthSession({ transport: { refresh: () => Promise.reject(new Error("none")) }, lock: noCrossTabLock, channel: noAuthChannel, clock });
  const identity: IdentityDeps = { client, engine, session };
  const authedClient = new ApiClient({ baseUrl: "https://shell.test", fetch: fetchFn, clock, auth: session, retryPolicy: new RetryPolicy() });
  const has = (m: string, p: string) => calls.some((c) => c.method === m && c.path === p);
  const body = (m: string, p: string) => calls.find((c) => c.method === m && c.path === p)?.body;
  return { calls, identity, session, authedClient, client, has, body };
}
type Setup = ReturnType<typeof setup>;

const ab = (...b: number[]): ArrayBuffer => Uint8Array.from(b).buffer;
const fakeCredentials = (): CredentialsLike & { gets: number; creates: number; cancel: boolean } => {
  const c = {
    gets: 0,
    creates: 0,
    cancel: false,
    create() {
      c.creates++;
      return Promise.resolve({ id: "bmV3", rawId: ab(1), type: "public-key", response: { clientDataJSON: ab(1), attestationObject: ab(2) } } as unknown as Credential);
    },
    get() {
      c.gets++;
      if (c.cancel) return Promise.reject(Object.assign(new Error("x"), { name: "NotAllowedError" }));
      return Promise.resolve({
        id: "Y3JlZA",
        rawId: ab(1),
        type: "public-key",
        response: { clientDataJSON: ab(1), authenticatorData: ab(2), signature: ab(3), userHandle: null },
      } as unknown as Credential);
    },
  };
  return c;
};

async function mount(s: Setup, hash: string, credentials?: CredentialsLike): Promise<CsShellApp> {
  location.hash = hash;
  const el = document.createElement("cs-shell-app");
  el.client = s.client;
  el.identity = s.identity;
  el.authedClient = s.authedClient;
  el.credentials = credentials;
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

const flush = async (...els: { updateComplete: Promise<boolean> }[]): Promise<void> => {
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  for (const e of els) await e.updateComplete;
};

async function signIn(s: Setup, credentials?: CredentialsLike, password = "right") {
  const shell = await mount(s, "#/sign-in", credentials);
  const page = q<CsSignInPage>(shell, "cs-sign-in-page");
  await page.updateComplete;
  fill(page, { tenant: TENANT, login: "Alice", password });
  await page.submit();
  await flush(shell, page);
  return { shell, page };
}

beforeAll(() => {
  registerShellMessages();
});

afterEach(() => {
  document.body.innerHTML = "";
  history.replaceState(null, "", "#");
  vi.useRealTimers();
});

describe("transparent re-registration (rev 9)", () => {
  it("upgrades silently after sign-in: register/start {purpose: ksf_upgrade}, no notice", async () => {
    const s = setup({ "POST /api/v2/auth/opaque/login/finish": () => auth({ reregister: true }) });
    const { shell } = await signIn(s);
    expect(s.body("POST", "/api/v2/auth/opaque/register/start")).toMatchObject({ purpose: "ksf_upgrade" });
    expect(location.hash).toBe("#/account");
    expect(shell.shadowRoot?.querySelector(".notice")).toBeNull();
  });

  it("a failed upgrade keeps the user signed in and shows a dismissible, non-blocking notice", async () => {
    const s = setup({ "POST /api/v2/auth/opaque/login/finish": () => auth({ reregister: true }), "POST /api/v2/auth/opaque/register/start": () => problem(500, "internal") });
    const { shell } = await signIn(s);
    expect(location.hash).toBe("#/account");
    expect(s.session.state.authenticated).toBe(true);
    const notice = q(shell, "[role=log] .notice");
    expect(notice.textContent).toContain("will be retried the next time you sign in");
    q<HTMLElement>(shell, ".dismiss-notice").click();
    await shell.updateComplete;
    expect(shell.shadowRoot?.querySelector(".notice")).toBeNull();
  });
});

describe("MFA step and passkey sign-in (§2.3, rev 10)", () => {
  const mfa = (methods: string[]) => ({ "POST /api/v2/auth/opaque/login/finish": () => json({ state: "mfa_required", auth_txn: "rt1.m", methods }) });

  it("offers passkey and recovery code; a recovery code completes sign-in", async () => {
    const s = setup(mfa(["webauthn", "recovery_code"]));
    const { shell, page } = await signIn(s, fakeCredentials());
    expect(q(page, "h1").textContent).toBe("Confirm with a second factor");
    expect(q(page, ".mfa-passkey")).toBeTruthy();
    fill(page, { recovery_code: CODE.toLowerCase() });
    await page.mfaWithCode();
    await flush(shell, page);
    expect(s.body("POST", "/api/v2/auth/mfa/recovery-code")).toEqual({ auth_txn: "rt1.m", code: CODE });
    expect(location.hash).toBe("#/account");
  });

  it("marks a malformed recovery code without a request", async () => {
    const s = setup(mfa(["recovery_code"]));
    const { page } = await signIn(s);
    fill(page, { recovery_code: "nope" });
    await page.mfaWithCode();
    await page.updateComplete;
    expect(q<HTMLElement & { error?: string }>(page, 'cs-text-field[name="recovery_code"]').error).toContain("XXXXXXXX-");
    expect(s.has("POST", "/api/v2/auth/mfa/recovery-code")).toBe(false);
  });

  it("completes with a passkey", async () => {
    const s = setup(mfa(["webauthn"]));
    const creds = fakeCredentials();
    const { shell, page } = await signIn(s, creds);
    await page.mfaWithPasskey();
    await flush(shell, page);
    expect(s.body("POST", "/api/v2/auth/webauthn/assert/start")).toEqual({ auth_txn: "rt1.m" });
    expect(creds.gets).toBe(1);
    expect(s.session.state.authenticated).toBe(true);
  });

  it("cancel zeroes the pending password and returns to the form", async () => {
    const s = setup(mfa(["webauthn"]));
    const { page } = await signIn(s, fakeCredentials());
    const m = page.mfa;
    const bytes = m?.retained?.value;
    expect(bytes?.some((b) => b !== 0)).toBe(true);
    q<HTMLElement>(page, ".mfa-cancel").click();
    await page.updateComplete;
    expect(bytes?.every((b) => b === 0)).toBe(true);
    expect(q(page, "h1").textContent).toBe("Sign in");
  });

  it("a cancelled passkey prompt says so and requires a new sign-in", async () => {
    const s = setup(mfa(["webauthn"]));
    const creds = fakeCredentials();
    creds.cancel = true;
    const { page } = await signIn(s, creds);
    await page.mfaWithPasskey();
    await page.updateComplete;
    expect(q(page, ".failure").textContent).toContain("cancelled");
    expect(page.mfa).toBeUndefined();
  });

  it("passwordless sign-in with a passkey, login taken from /me", async () => {
    const s = setup();
    const shell = await mount(s, "#/sign-in", fakeCredentials());
    const page = q<CsSignInPage>(shell, "cs-sign-in-page");
    await page.updateComplete;
    fill(page, { tenant: TENANT });
    // The shell passes its authenticated client to the sign-in flows.
    await page.signInWithPasskey();
    await flush(shell, page);
    expect(s.body("POST", "/api/v2/auth/webauthn/login/start")).toEqual({ tenant: TENANT });
    expect(location.hash).toBe("#/account");
  });

  it("hides passkey options without the WebAuthn API", async () => {
    const s = setup();
    const shell = await mount(s, "#/sign-in");
    const page = q<CsSignInPage>(shell, "cs-sign-in-page");
    await page.updateComplete;
    expect(page.shadowRoot?.querySelector(".passkey-signin")).toBeNull();
    expect(q(page, 'a[href="#/recover"]')).toBeTruthy();
  });
});

describe("step-up with a passkey (rev 10)", () => {
  it("the dialog offers a passkey; webauthn/assert on the current session then retries the operation", async () => {
    const s = setup({ "POST /api/v2/auth/webauthn/assert/finish": noContent });
    const creds = fakeCredentials();
    const { shell } = await signIn(s, creds);
    let n = 0;
    const result = shell.runWithStepUp(() =>
      ++n === 1
        ? Promise.reject(
            new StepUpRequired(
              { type: "about:blank", title: "u", status: 401, code: "unauthenticated", retryable: false, errors: [{ pointer: "", code: "step_up_required", detail: "d" }] },
              { synthesized: false, attempts: 1 },
            ),
          )
        : Promise.resolve("ok"),
    );
    await flush(shell);
    const dialog = q<CsStepUpDialog>(shell, "cs-step-up-dialog");
    await dialog.updateComplete;
    await dialog.submitPasskey();
    expect(await result).toBe("ok");
    expect(s.body("POST", "/api/v2/auth/webauthn/assert/start")).toEqual({});
    expect(s.has("POST", "/api/v2/auth/opaque/reauth/start")).toBe(false);
  });
});

describe("security page", () => {
  async function securityPage(s: Setup, runWithStepUp?: StepUpRunner) {
    await signIn(s, fakeCredentials());
    const page = document.createElement("cs-security-page");
    page.user = { tenant: TENANT, login: "alice" };
    page.identity = s.identity;
    page.authedClient = s.authedClient;
    page.credentials = fakeCredentials();
    if (runWithStepUp) page.runWithStepUp = runWithStepUp;
    document.body.appendChild(page);
    await flush(page);
    return page;
  }

  it("lists sessions with the current one marked, and revokes another", async () => {
    const s = setup();
    const page = await securityPage(s);
    const items = page.shadowRoot!.querySelectorAll("li.session");
    expect(items).toHaveLength(2);
    expect(q(page, "li.session.current").textContent).toContain("this session");
    expect(q(page, "li.session.current cs-button.revoke").getAttribute("label")).toBe("Sign out of this session");
    await page.revoke(page.sessions![1]!);
    await page.updateComplete;
    expect(s.has("DELETE", "/api/v2/me/sessions/s-2")).toBe(true);
    expect(page.shadowRoot!.querySelectorAll("li.session")).toHaveLength(1);
    expect(page.shadowRoot!.textContent).toContain("The session was signed out.");
  });

  it("revoking the current session signs this tab out", async () => {
    const s = setup();
    const page = await securityPage(s);
    const out = vi.fn();
    page.addEventListener("cs-signed-out", out);
    await page.revoke(page.sessions![0]!);
    expect(out).toHaveBeenCalledOnce();
    expect(s.session.state.authenticated).toBe(false);
  });

  it("a revoke that needs step-up runs through the step-up runner; a cancelled step-up says nothing changed", async () => {
    const s = setup({ "DELETE /api/v2/me/sessions/s-2": stepUpProblem });
    let runs = 0;
    const runner: StepUpRunner = (op) => {
      runs++;
      return op();
    };
    const page = await securityPage(s, runner);
    await page.revoke(page.sessions![1]!);
    await page.updateComplete;
    expect(runs).toBe(1);
    expect(q(page, ".failure").textContent).toContain("did not confirm");
    expect(page.sessions).toHaveLength(2);
  });

  it("changes the password with purpose password_change and says other sessions were signed out", async () => {
    const s = setup();
    const page = await securityPage(s);
    fill(page, { new_password: "a", confirm_password: "b" });
    await page.changePassword();
    await page.updateComplete;
    expect(s.has("POST", "/api/v2/auth/opaque/register/start")).toBe(false);
    fill(page, { new_password: "new", confirm_password: "new" });
    await page.changePassword();
    await page.updateComplete;
    expect(s.body("POST", "/api/v2/auth/opaque/register/start")).toMatchObject({ purpose: "password_change" });
    expect(page.shadowRoot!.textContent).toContain("Your other sessions were signed out.");
    expect(q<HTMLElement & { value: string }>(page, 'cs-text-field[name="new_password"]').value).toBe("");
  });

  it("lists, adds and removes passkeys", async () => {
    const s = setup();
    const page = await securityPage(s);
    expect(page.shadowRoot!.querySelectorAll("li.passkey")).toHaveLength(1);
    fill(page, { passkey_label: "Phone" });
    await page.addPasskey();
    await page.updateComplete;
    expect(s.body("POST", "/api/v2/auth/webauthn/register/finish")).toMatchObject({ registration_txn: "wr", label: "Phone" });
    expect(page.shadowRoot!.querySelectorAll("li.passkey")).toHaveLength(2);
    await page.removePasskey(page.passkeys![0]!);
    await page.updateComplete;
    expect(s.has("DELETE", "/api/v2/me/passkeys/Y3JlZA")).toBe(true);
    expect(page.shadowRoot!.querySelectorAll("li.passkey")).toHaveLength(1);
  });

  it("shows new recovery codes once, with copy and download, and forgets them when done", async () => {
    const s = setup();
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const page = await securityPage(s);
    expect(q(page, ".remaining").textContent).toContain("3");
    await page.generate();
    await page.updateComplete;
    expect(page.shadowRoot!.querySelectorAll("ol.codes li")).toHaveLength(10);
    q<HTMLElement>(page, ".codes-copy").click();
    await flush(page);
    expect(writeText).toHaveBeenCalledWith(codes.join("\n"));
    expect(page.shadowRoot!.textContent).toContain("Codes copied.");
    const createObjectURL = vi.fn(() => "blob:x");
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    q<HTMLElement>(page, ".codes-download").click();
    expect(createObjectURL).toHaveBeenCalledOnce();
    q<HTMLElement>(page, ".codes-done").click();
    await page.updateComplete;
    expect(page.codes).toBeUndefined();
    expect(page.shadowRoot!.querySelector("ol.codes")).toBeNull();
  });

  it("shows recovery requests with the requester, approves device requests and cancels others", async () => {
    const s = setup();
    const page = await securityPage(s);
    expect(page.shadowRoot!.querySelectorAll("li.request")).toHaveLength(2);
    expect(page.shadowRoot!.textContent).toContain("Chrome on Android");
    expect(page.shadowRoot!.querySelectorAll("cs-button.approve")).toHaveLength(1);
    await page.approve(page.requests![0]!);
    await page.cancelRequest(page.requests![1]!);
    await page.updateComplete;
    expect(s.has("POST", "/api/v2/me/recovery-requests/q1/approve")).toBe(true);
    expect(s.has("DELETE", "/api/v2/me/recovery-requests/q2")).toBe(true);
    expect(page.shadowRoot!.querySelectorAll("li.request")).toHaveLength(1);
  });

  it("each section shows its own load failure in cs-error-banner", async () => {
    const s = setup({ "GET /api/v2/me/sessions": () => problem(503, "unavailable") });
    const page = await securityPage(s);
    const banner = q<HTMLElement & { problem?: { code: string } }>(page, "cs-error-banner");
    expect(banner.problem?.code).toBe("unavailable");
    expect(page.shadowRoot!.querySelectorAll("li.passkey")).toHaveLength(1);
  });
});

describe("recovery pages (§4 [R5], rev 10)", () => {
  async function recoveryPage(s: Setup, hash = "#/recover") {
    const shell = await mount(s, hash);
    const page = q<CsRecoveryPage>(shell, "cs-recovery-page");
    await page.updateComplete;
    return { shell, page };
  }

  it("recovery code → new password → signed in", async () => {
    const s = setup({ "POST /api/v2/auth/recovery/start": () => json({ state: "granted", grant: GRANT, grant_expires_in: 900 }) });
    const { shell, page } = await recoveryPage(s);
    fill(page, { tenant: TENANT, login: "Alice", recovery_code: CODE });
    await page.start();
    await page.updateComplete;
    expect(s.body("POST", "/api/v2/auth/recovery/start")).toEqual({ tenant: TENANT, login: "alice", method: "recovery_code", code: CODE });
    fill(page, { password: "new", confirm: "new" });
    await page.complete();
    await flush(shell, page);
    expect(s.body("POST", "/api/v2/auth/opaque/register/start")).toMatchObject({ grant: GRANT, login: "alice" });
    expect(location.hash).toBe("#/account");
  });

  it("a wrong code shows one inline message", async () => {
    const s = setup({ "POST /api/v2/auth/recovery/start": () => problem(401, "unauthenticated") });
    const { page } = await recoveryPage(s);
    fill(page, { tenant: TENANT, login: "alice", recovery_code: CODE });
    await page.start();
    await page.updateComplete;
    expect(q(page, ".failure").textContent).toContain("recovery code is not correct");
  });

  it("email link: token removed from the address bar, waiting period shown, then granted", async () => {
    let state = "pending";
    const s = setup({
      "POST /api/v2/auth/recovery/status": () => json(state === "pending" ? { state, available_at: T0 } : { state, grant: GRANT, grant_expires_in: 900 }),
    });
    const { page } = await recoveryPage(s, "#/recover/rt1.link");
    expect(location.hash).toBe("#/recover");
    expect(page.shadowRoot!.textContent).toContain("Sign in with it instead");
    await page.openLink();
    await page.updateComplete;
    expect(s.body("POST", "/api/v2/auth/recovery/status")).toEqual({ token: "rt1.link" });
    expect(q(page, ".waiting time").getAttribute("datetime")).toBe(T0);
    state = "granted";
    await page.poll();
    await page.updateComplete;
    expect(q(page, 'cs-text-field[name="password"]')).toBeTruthy();
  });

  it("device approval polls status {recovery_txn} on a timer until granted", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    let n = 0;
    const s = setup({
      "POST /api/v2/auth/recovery/start": () => json({ state: "pending", recovery_txn: "rt1.dev" }, 202),
      "POST /api/v2/auth/recovery/status": () => json(++n < 2 ? { state: "pending" } : { state: "granted", grant: GRANT, grant_expires_in: 900 }),
    });
    const { page } = await recoveryPage(s);
    page.choice = "device_approval";
    await page.updateComplete;
    fill(page, { tenant: TENANT, login: "alice" });
    await page.start();
    await page.updateComplete;
    expect(page.shadowRoot!.textContent).toContain("Approve the request on a device");
    vi.advanceTimersByTime(5_000);
    await flush(page);
    vi.advanceTimersByTime(5_000);
    await flush(page);
    expect(s.calls.filter((c) => c.path === "/api/v2/auth/recovery/status").every((c) => c.body.recovery_txn === "rt1.dev")).toBe(true);
    expect(page.flow?.phase.kind).toBe("granted");
  });

  it("an expired grant asks to start over", async () => {
    const s = setup({
      "POST /api/v2/auth/recovery/start": () => json({ state: "granted", grant: GRANT, grant_expires_in: 900 }),
      "POST /api/v2/auth/opaque/register/start": () => problem(401, "unauthenticated"),
    });
    const { page } = await recoveryPage(s);
    fill(page, { tenant: TENANT, login: "alice", recovery_code: CODE });
    await page.start();
    await page.updateComplete;
    fill(page, { password: "x", confirm: "x" });
    await page.complete();
    await page.updateComplete;
    expect(page.shadowRoot!.textContent).toContain("expired");
    expect(q(page, ".start-over")).toBeTruthy();
  });
});

describe("forced MFA enrolment (rev 11)", () => {
  it("routes an enrolment-only session to enrolment; after creating codes the user signs out and in again", async () => {
    const s = setup({ "POST /api/v2/auth/opaque/login/finish": () => auth({ access_token: jwt({ scp: "mfa_enrolment" }) }) });
    const { shell } = await signIn(s, fakeCredentials());
    expect(location.hash).toBe("#/enrol");
    const page = q<CsEnrolmentPage>(shell, "cs-enrolment-page");
    await page.updateComplete;
    expect(page.shadowRoot!.querySelector(".enrol-finish")).toBeNull();
    await page.generate();
    await page.updateComplete;
    expect(page.shadowRoot!.querySelectorAll("ol.codes li")).toHaveLength(10);
    q<HTMLElement>(page, ".codes-done").click();
    await page.updateComplete;
    await page.finish();
    await flush(shell);
    expect(s.has("POST", "/api/v2/auth/logout")).toBe(true);
    expect(location.hash).toBe("#/sign-in");
  });

  it("a passkey also completes enrolment", async () => {
    const s = setup({ "POST /api/v2/auth/opaque/login/finish": () => auth({ access_token: jwt({ scp: "mfa_enrolment" }) }) });
    const { shell } = await signIn(s, fakeCredentials());
    const page = q<CsEnrolmentPage>(shell, "cs-enrolment-page");
    await page.updateComplete;
    await page.addPasskey();
    await page.updateComplete;
    expect(page.enrolled).toBe(true);
    expect(q(page, ".enrol-finish")).toBeTruthy();
  });
});
