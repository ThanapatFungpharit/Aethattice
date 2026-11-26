// End-to-end harness: the real @cs/sdk and the real opaque-wasm against a real `cs serve --dev` (scripts/e2e.sh).
//
// What stands in for the browser, and why it does not weaken production behaviour:
// - The SDK talks to `https://<deployment domain>` exactly as in production (DPoP `htu` is checked against that
//   origin). `BrowserLike.fetch` forwards each request to the loopback listener, as the TLS-terminating proxy in
//   front of `cs serve` does, and keeps a cookie jar with browser semantics for that https origin: a `__Secure-`
//   cookie is stored only with `Secure`, sent only to its `Path` prefix, and `Max-Age=0` deletes it. The server
//   sets the production cookie unchanged.
// - Web Locks: an in-process exclusive lock manager with the `navigator.locks.request` contract (Node 22 has none).
//   BroadcastChannel: Node's own implementation. The DPoP key store: one in-memory store per "browser" (IndexedDB
//   stand-in). A real multi-tab browser run is outside this suite (see docs/traceability.md WEB.M1-1).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { initSync, loginStart, normalizeLogin, registrationStart } from "@cs/opaque-wasm";
import {
  ApiClient,
  AuthSession,
  broadcastAuthChannel,
  DpopKeyManager,
  httpRefreshTransport,
  localStorageLeaseLock,
  memoryDpopKeyStore,
  REFRESH_LOCK_NAME,
  REFRESH_PATH,
  systemClock,
  wasmOpaqueEngine,
  webLocksRefreshLock,
  type AuthChannel,
  type Clock,
  type DpopKeyStore,
  type IdentityDeps,
  type LockManagerLike,
  type OpaqueEngine,
  type RefreshLock,
  type StorageLike,
} from "@cs/sdk";

function env(name: string): string {
  const v = process.env[name];
  if (v === undefined || v.length === 0) throw new Error(`${name} is not set; run the suite through scripts/e2e.sh`);
  return v;
}

/** Values provided by scripts/e2e.sh. */
export const E2E = {
  /** Loopback listener of `cs serve --dev`. */
  get upstream(): string {
    return env("CS_E2E_UPSTREAM");
  },
  /** `[api] deployment_domain`; the SDK base URL is `https://<domain>`. */
  get domain(): string {
    return env("CS_E2E_DOMAIN");
  },
  get tenant(): string {
    return env("CS_E2E_TENANT");
  },
  /** Setup link token (rt1) of the invited first user, and that user's login. */
  get setupLink(): string {
    return env("CS_E2E_SETUP_LINK");
  },
  get login(): string {
    return env("CS_E2E_LOGIN");
  },
};

let engine: OpaqueEngine | undefined;

/** The real OPAQUE client: opaque-ke compiled to WASM (web/packages/opaque-wasm/pkg), on the calling thread. */
export function opaqueEngine(): OpaqueEngine {
  if (!engine) {
    const wasm = readFileSync(fileURLToPath(import.meta.resolve("@cs/opaque-wasm/pkg/cs_opaque_wasm_bg.wasm")));
    initSync({ module: wasm });
    engine = wasmOpaqueEngine({ loginStart, registrationStart, normalizeLogin });
  }
  return engine;
}

export interface Cookie {
  readonly value: string;
  readonly path: string;
}

export interface LoggedRequest {
  readonly method: string;
  readonly path: string;
  readonly status: number;
  /** Scheme of the Authorization header, if any. */
  readonly authScheme: string | undefined;
  readonly dpop: boolean;
  /** Refresh cookie value sent with the request, if any. */
  readonly refreshCookie: string | undefined;
  readonly idempotencyKey: string | undefined;
}

export const REFRESH_COOKIE = "__Secure-cs_rt";

/** One browser profile: a cookie jar for the deployment origin, shared by all its tabs, and a request log. */
export class BrowserLike {
  readonly origin: string;
  readonly cookies = new Map<string, Cookie>();
  readonly log: LoggedRequest[] = [];
  /** IndexedDB stand-in: one DPoP key store for every tab of this profile. */
  readonly keyStore: DpopKeyStore = memoryDpopKeyStore();
  /** `navigator.locks` stand-in, shared by every tab of this profile. */
  readonly locks: LockManagerLike = new InProcessLocks();
  /** localStorage stand-in for the lease fallback. */
  readonly storage: StorageLike = new MemoryStorage();
  private readonly channelName = `cs-auth-e2e-${globalThis.crypto.randomUUID()}`;

  constructor() {
    this.origin = `https://${E2E.domain}`;
  }

  /** `fetch` as a page on `origin` sees it, forwarded to the loopback listener. */
  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== this.origin) throw new TypeError(`e2e: request to unexpected origin ${url.origin}`);
    const headers = new Headers(init?.headers);
    const sent = this.cookieHeader(url.pathname);
    if (sent) headers.set("Cookie", sent);
    const res = await fetch(E2E.upstream + url.pathname + url.search, { ...init, headers, redirect: "manual" });
    for (const line of res.headers.getSetCookie()) this.store(line);
    const auth = headers.get("Authorization");
    this.log.push({
      method: init?.method ?? "GET",
      path: url.pathname,
      status: res.status,
      authScheme: auth?.split(" ")[0],
      dpop: headers.has("DPoP"),
      refreshCookie: sent ? /(?:^|; )__Secure-cs_rt=([^;]*)/.exec(sent)?.[1] : undefined,
      idempotencyKey: headers.get("Idempotency-Key") ?? undefined,
    });
    return res;
  };

  get refreshCookie(): string | undefined {
    return this.cookies.get(REFRESH_COOKIE)?.value;
  }

  /** Requests to `path` logged since `from`. */
  requests(path: string, from = 0): LoggedRequest[] {
    return this.log.slice(from).filter((r) => r.path === path);
  }

  refreshes(from = 0): LoggedRequest[] {
    return this.requests(REFRESH_PATH, from);
  }

  /** A new tab of this profile: its own AuthSession, DPoP manager and clients, sharing cookies, keys, lock, channel. */
  tab(opts: { lock?: "web-locks" | "lease"; clock?: Clock } = {}): Tab {
    return new Tab(this, opts.lock === "lease" ? localStorageLeaseLock(this.storage, { key: `lease-${this.channelName}` }) : webLocksRefreshLock(this.locks, REFRESH_LOCK_NAME, this.storage), opts.clock ?? systemClock, broadcastAuthChannel(new BroadcastChannel(this.channelName)));
  }

  private cookieHeader(path: string): string {
    const out: string[] = [];
    for (const [name, c] of this.cookies) {
      if (path === c.path || path.startsWith(c.path.endsWith("/") ? c.path : `${c.path}/`)) out.push(`${name}=${c.value}`);
    }
    return out.join("; ");
  }

  /** RFC 6265bis storage for an https origin, with the `__Secure-` prefix rule. */
  private store(line: string): void {
    const [pair, ...attrs] = line.split(";").map((s) => s.trim());
    const eq = pair?.indexOf("=") ?? -1;
    if (pair === undefined || eq <= 0) return;
    const name = pair.slice(0, eq);
    const value = pair.slice(eq + 1);
    let path = "/";
    let secure = false;
    let maxAge: number | undefined;
    for (const a of attrs) {
      const [k = "", v = ""] = a.split("=", 2);
      const key = k.toLowerCase();
      if (key === "path" && v.startsWith("/")) path = v;
      else if (key === "secure") secure = true;
      else if (key === "max-age") maxAge = Number(v);
    }
    if (name.startsWith("__Secure-") && !secure) return;
    if (maxAge !== undefined && maxAge <= 0) {
      this.cookies.delete(name);
      return;
    }
    this.cookies.set(name, { value, path });
  }
}

/** One tab: what the shell app wires up in a browser (apps/shell), with the browser parts from {@link BrowserLike}. */
export class Tab {
  readonly browser: BrowserLike;
  readonly keys: DpopKeyManager;
  readonly session: AuthSession;
  /** Auth endpoints (no auth hook). */
  readonly client: ApiClient;
  /** Everything else: the session is the auth hook. */
  readonly authed: ApiClient;
  readonly deps: IdentityDeps;
  readonly channel: AuthChannel;

  constructor(browser: BrowserLike, lock: RefreshLock, clock: Clock, channel: AuthChannel) {
    this.browser = browser;
    this.channel = channel;
    const base = { baseUrl: browser.origin, fetch: browser.fetch };
    this.keys = new DpopKeyManager({ store: browser.keyStore });
    this.session = new AuthSession({ transport: httpRefreshTransport({ ...base, dpop: this.keys }), lock, channel, clock, dpop: this.keys });
    this.client = new ApiClient({ ...base, dpop: this.keys });
    this.authed = new ApiClient({ ...base, dpop: this.keys, auth: this.session });
    this.deps = { client: this.client, authedClient: this.authed, session: this.session, engine: opaqueEngine() };
  }

  /** Replaces the held access token with `token` (same expiry semantics as a sign-in result). */
  holdToken(token: string, expiresIn = 600): void {
    const sid = this.session.state.sessionId ?? "unknown";
    this.session.signedIn({ state: "authenticated", access_token: token, expires_in: expiresIn, session_id: sid });
  }

  dispose(): void {
    this.session.dispose();
  }
}

/** A clock whose `now` can be moved forward, so the 60 s proactive-refresh leeway is reached without waiting. */
export class ShiftedClock implements Clock {
  offsetMs = 0;
  now(): number {
    return Date.now() + this.offsetMs;
  }
  sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return systemClock.sleep(ms, signal);
  }
}

/** FIFO exclusive locks with the `navigator.locks.request(name, {mode: "exclusive"}, cb)` semantics. */
class InProcessLocks implements LockManagerLike {
  private readonly tails = new Map<string, Promise<unknown>>();
  request<T>(name: string, _options: { mode: "exclusive" }, callback: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(name) ?? Promise.resolve();
    // As in browsers, a lock is granted in a later task, not synchronously when the previous holder releases it.
    const run = prev.then(() => new Promise<void>((r) => setTimeout(r, 0))).then(callback);
    this.tails.set(
      name,
      run.catch(() => undefined),
    );
    return run;
  }
}

class MemoryStorage implements StorageLike {
  private readonly m = new Map<string, string>();
  getItem(key: string): string | null {
    return this.m.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.m.set(key, value);
  }
  removeItem(key: string): void {
    this.m.delete(key);
  }
}

/** A token with its signature corrupted: well formed, rejected by the server's signature check. */
export function tamper(token: string): string {
  const i = token.lastIndexOf(".");
  const sig = token.slice(i + 1);
  const c = sig.startsWith("A") ? "B" : "A";
  return `${token.slice(0, i + 1)}${c}${sig.slice(1)}`;
}
