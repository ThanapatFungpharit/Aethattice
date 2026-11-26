import { describe, expect, it, vi } from "vitest";
import {
  AuthSession,
  PROACTIVE_REFRESH_LEEWAY_MS,
  REFRESH_LOCK_NAME,
  REFRESH_PATH,
  broadcastAuthChannel,
  decodeAuthResult,
  defaultAuthChannel,
  defaultRefreshLock,
  httpRefreshTransport,
  localStorageLeaseLock,
  noAuthChannel,
  noCrossTabLock,
  parseAuthChannelMessage,
  webLocksRefreshLock,
  type AuthChannel,
  type AuthChannelMessage,
  type AuthResult,
  type BroadcastChannelLike,
  type LockManagerLike,
  type RefreshLock,
  type RefreshTransport,
  type StorageLike,
} from "./auth";
import { ApiClient } from "./client";
import { ApiError, type Problem } from "./problem";
import { RetryPolicy, systemClock, type Clock } from "./retry";

// ---------- fakes ----------

const tick = (ms = 0): Promise<void> => new Promise((r) => setTimeout(r, ms));

function apiError(code: "unauthenticated" | "unavailable", status: number, retryable: boolean): ApiError {
  const problem: Problem = { type: "about:blank", title: code, status, code, retryable };
  return new ApiError(problem, { httpStatus: status, synthesized: false, attempts: 1 });
}

/**
 * The refresh endpoint as contract M1 §3 describes it: rotation on every use, the browser's cookie jar shared by
 * all tabs, reuse of a rotated token (other key or after 30 s) revokes the session, and a replay with the key
 * that rotated it within 30 s is a lost response.
 */
class FakeRefreshServer {
  jar: string | undefined = "rt-0";
  revoked = false;
  reuseDetected = 0;
  calls: { key: string; cookie: string | undefined }[] = [];
  private n = 0;
  private readonly tokens = new Map<string, { state: "active" | "rotated"; key?: string; rotatedAt?: number }>([
    ["rt-0", { state: "active" }],
  ]);
  constructor(
    private readonly clock: Clock = systemClock,
    private readonly latencyMs = 1,
  ) {}

  transport(): RefreshTransport {
    return { refresh: (key) => this.refresh(key) };
  }

  async refresh(key: string): Promise<AuthResult> {
    const cookie = this.jar; // the cookie the browser sends at request time
    this.calls.push({ key, cookie });
    await tick(this.latencyMs);
    const t = cookie === undefined ? undefined : this.tokens.get(cookie);
    if (this.revoked || cookie === undefined || t === undefined) throw apiError("unauthenticated", 401, false);
    if (t.state === "rotated") {
      const lost = t.key === key && t.rotatedAt !== undefined && this.clock.now() - t.rotatedAt <= 30_000;
      if (!lost) {
        this.reuseDetected++;
        this.revoked = true;
        throw apiError("unauthenticated", 401, false);
      }
    } else {
      t.state = "rotated";
      t.key = key;
      t.rotatedAt = this.clock.now();
    }
    this.n++;
    const next = `rt-${this.n}`;
    this.tokens.set(next, { state: "active" });
    this.jar = next; // Set-Cookie on the response
    return { state: "authenticated", access_token: `at-${this.n}`, expires_in: 600, session_id: "sess-1" };
  }
}

/** Exclusive FIFO locks shared by all "tabs" of a test, like navigator.locks within one origin. */
class FakeLockManager implements LockManagerLike {
  requests: string[] = [];
  private tail = new Map<string, Promise<unknown>>();
  request<T>(name: string, options: { mode: "exclusive" }, callback: () => Promise<T>): Promise<T> {
    expect(options.mode).toBe("exclusive");
    this.requests.push(name);
    const prev = this.tail.get(name) ?? Promise.resolve();
    const run = prev.then(callback, callback);
    this.tail.set(
      name,
      run.catch(() => undefined),
    );
    return run;
  }
}

/** BroadcastChannel hub: delivers to every other subscriber, never to the sender. */
class FakeHub {
  posted: AuthChannelMessage[] = [];
  private subs: { id: number; h: (m: AuthChannelMessage) => void }[] = [];
  private next = 0;
  channel(): AuthChannel {
    const id = this.next++;
    return {
      post: (m) => {
        this.posted.push(m);
        for (const s of this.subs) if (s.id !== id) s.h(m);
      },
      subscribe: (h) => {
        const entry = { id, h };
        this.subs.push(entry);
        return () => {
          this.subs = this.subs.filter((s) => s !== entry);
        };
      },
    };
  }
}

class MemoryStorage implements StorageLike {
  data = new Map<string, string>();
  getItem(k: string): string | null {
    return this.data.get(k) ?? null;
  }
  setItem(k: string, v: string): void {
    this.data.set(k, v);
  }
  removeItem(k: string): void {
    this.data.delete(k);
  }
}

function manualClock(start = 1_000_000): Clock & { t: number } {
  const c = {
    t: start,
    now: () => c.t,
    sleep: (ms: number, signal?: AbortSignal) => systemClock.sleep(Math.min(ms, 1), signal),
  };
  return c;
}

let keySeq = 0;
const keys = (): string => `idem-${++keySeq}`;

const result = (token: string, expiresIn = 600): AuthResult => ({
  state: "authenticated",
  access_token: token,
  expires_in: expiresIn,
  session_id: "sess-1",
});

// ---------- tests ----------

describe("decodeAuthResult (M1 §2.4)", () => {
  it("accepts the authentication result", () => {
    expect(decodeAuthResult({ state: "authenticated", access_token: "a", expires_in: 600, session_id: "s", extra: 1 })).toEqual({
      state: "authenticated",
      access_token: "a",
      expires_in: 600,
      session_id: "s",
    });
  });

  it.each([
    null,
    [],
    { state: "mfa_required", auth_txn: "x", methods: [] },
    { state: "authenticated", access_token: "", expires_in: 600, session_id: "s" },
    { state: "authenticated", access_token: "a", expires_in: 0, session_id: "s" },
    { state: "authenticated", access_token: "a", expires_in: 1.5, session_id: "s" },
    { state: "authenticated", access_token: "a", expires_in: "600", session_id: "s" },
    { state: "authenticated", access_token: "a", expires_in: 600 },
  ])("rejects %j", (v) => {
    expect(() => decodeAuthResult(v)).toThrow(TypeError);
  });
});

describe("httpRefreshTransport (M1 §3 [R1])", () => {
  interface Seen {
    url: string;
    method: string;
    headers: Headers;
    body: unknown;
  }
  function fetchSeq(...responses: (() => Response)[]): { fetch: typeof fetch; seen: Seen[] } {
    const seen: Seen[] = [];
    const fetchFn = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      seen.push({
        url: typeof input === "string" ? input : input instanceof URL ? input.href : input.url,
        method: init?.method ?? "GET",
        headers: new Headers(init?.headers),
        body: init?.body,
      });
      const r = responses[Math.min(seen.length - 1, responses.length - 1)];
      if (!r) throw new Error("no response");
      return Promise.resolve(r());
    };
    return { fetch: fetchFn, seen };
  }
  const okBody = (): Response =>
    new Response(JSON.stringify({ state: "authenticated", access_token: "at", expires_in: 600, session_id: "s" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  const prob = (code: string, status: number, retryable: boolean) => (): Response =>
    new Response(JSON.stringify({ type: "about:blank", title: code, status, code, retryable }), {
      status,
      headers: { "Content-Type": "application/problem+json" },
    });
  const noSleep: Clock = { now: () => 0, sleep: () => Promise.resolve() };

  it("POSTs to the refresh path with the Idempotency-Key and no Authorization or body", async () => {
    const { fetch, seen } = fetchSeq(okBody);
    const t = httpRefreshTransport({ baseUrl: "https://cloud.example.test", fetch, clock: noSleep });
    expect(await t.refresh("k-1")).toEqual({ state: "authenticated", access_token: "at", expires_in: 600, session_id: "s" });
    expect(seen).toHaveLength(1);
    expect(seen[0]?.url).toBe(`https://cloud.example.test${REFRESH_PATH}`);
    expect(seen[0]?.method).toBe("POST");
    expect(seen[0]?.headers.get("Idempotency-Key")).toBe("k-1");
    expect(seen[0]?.headers.get("Authorization")).toBeNull();
    expect(seen[0]?.body ?? null).toBeNull();
  });

  it("retries a lost or failed refresh only with the same key", async () => {
    const { fetch, seen } = fetchSeq(prob("unavailable", 503, true), prob("timeout", 504, true), okBody);
    const t = httpRefreshTransport({
      baseUrl: "https://cloud.example.test",
      fetch,
      clock: noSleep,
      retryPolicy: new RetryPolicy({ random: () => 0 }),
    });
    await t.refresh("k-same");
    expect(seen.map((s) => s.headers.get("Idempotency-Key"))).toEqual(["k-same", "k-same", "k-same"]);
  });

  it("does not recurse into a refresh on 401 and rejects with unauthenticated", async () => {
    const { fetch, seen } = fetchSeq(prob("unauthenticated", 401, false));
    const t = httpRefreshTransport({ baseUrl: "https://cloud.example.test", fetch, clock: noSleep });
    await expect(t.refresh("k")).rejects.toMatchObject({ problem: { code: "unauthenticated" } });
    expect(seen).toHaveLength(1);
  });

  it("treats a non-authenticated body as an internal error", async () => {
    const { fetch } = fetchSeq(
      () => new Response(JSON.stringify({ state: "mfa_required" }), { status: 200, headers: { "Content-Type": "application/json" } }),
    );
    const t = httpRefreshTransport({ baseUrl: "https://cloud.example.test", fetch, clock: noSleep, retryPolicy: RetryPolicy.none() });
    await expect(t.refresh("k")).rejects.toMatchObject({ problem: { code: "internal" } });
  });
});

describe("AuthSession, one tab", () => {
  it("keeps the token in memory and serves it as a bearer header", async () => {
    const server = new FakeRefreshServer();
    const s = new AuthSession({ transport: server.transport(), lock: noCrossTabLock, channel: noAuthChannel, idempotencyKeyFactory: keys });
    expect(await s.authorization()).toBeUndefined();
    expect(await s.refresh()).toBe(true);
    expect(await s.authorization()).toBe("Bearer at-1");
    expect(s.state).toEqual({ authenticated: true, sessionId: "sess-1" });
  });

  it("deduplicates concurrent refreshes in the tab and uses a fresh key per refresh", async () => {
    const server = new FakeRefreshServer();
    const s = new AuthSession({ transport: server.transport(), lock: noCrossTabLock, channel: noAuthChannel, idempotencyKeyFactory: keys });
    const all = await Promise.all([s.refresh(), s.refresh(), s.refresh()]);
    expect(all).toEqual([true, true, true]);
    expect(server.calls).toHaveLength(1);
    await s.refresh();
    expect(server.calls).toHaveLength(2);
    expect(new Set(server.calls.map((c) => c.key)).size).toBe(2);
    expect(server.reuseDetected).toBe(0);
  });

  it("refreshes proactively within the 60 s client leeway ([R12])", async () => {
    expect(PROACTIVE_REFRESH_LEEWAY_MS).toBe(60_000);
    const clock = manualClock();
    const server = new FakeRefreshServer(clock);
    const s = new AuthSession({ transport: server.transport(), lock: noCrossTabLock, channel: noAuthChannel, clock, idempotencyKeyFactory: keys });
    s.signedIn(result("at-signin", 600));
    clock.t += 600_000 - 60_000 - 1;
    expect(await s.authorization()).toBe("Bearer at-signin");
    expect(server.calls).toHaveLength(0);
    clock.t += 1; // exactly exp − 60 s
    expect(await s.authorization()).toBe("Bearer at-1");
    expect(server.calls).toHaveLength(1);
  });

  it("sends a near-expiry token if the proactive refresh fails, but never an expired one", async () => {
    const clock = manualClock();
    const transport: RefreshTransport = { refresh: () => Promise.reject(apiError("unavailable", 503, true)) };
    const s = new AuthSession({ transport, lock: noCrossTabLock, channel: noAuthChannel, clock, idempotencyKeyFactory: keys });
    s.signedIn(result("at-old", 600));
    clock.t += 590_000;
    expect(await s.authorization()).toBe("Bearer at-old");
    clock.t += 10_000; // server enforces exp with 0 s leeway
    expect(await s.authorization()).toBeUndefined();
  });

  it("an unauthenticated refresh signs every tab out; a transient failure keeps the token", async () => {
    const hub = new FakeHub();
    const other = new AuthSession({ transport: new FakeRefreshServer().transport(), lock: noCrossTabLock, channel: hub.channel() });
    const transient = vi.fn<RefreshTransport["refresh"]>().mockRejectedValueOnce(apiError("unavailable", 503, true));
    transient.mockRejectedValueOnce(apiError("unauthenticated", 401, false));
    const s = new AuthSession({ transport: { refresh: transient }, lock: noCrossTabLock, channel: hub.channel(), idempotencyKeyFactory: keys });
    const states: boolean[] = [];
    other.subscribe((st) => states.push(st.authenticated));
    s.signedIn(result("at-x"));
    expect(other.state.authenticated).toBe(true);
    expect(await s.refresh()).toBe(false);
    expect(s.state.authenticated).toBe(true);
    expect(await s.refresh()).toBe(false);
    expect(s.state.authenticated).toBe(false);
    expect(other.state.authenticated).toBe(false);
    expect(states).toEqual([true, false]);
  });

  it("resolves false (never throws) when the refresh cannot even start", async () => {
    const s = new AuthSession({
      transport: new FakeRefreshServer().transport(),
      lock: noCrossTabLock,
      channel: noAuthChannel,
      idempotencyKeyFactory: () => {
        throw new Error("no CSPRNG");
      },
    });
    expect(await s.refresh()).toBe(false);
  });

  it("plugs into ApiClient: 401 → refresh → retry with the new bearer", async () => {
    const server = new FakeRefreshServer();
    const s = new AuthSession({ transport: server.transport(), lock: noCrossTabLock, channel: noAuthChannel, idempotencyKeyFactory: keys });
    s.signedIn(result("at-stale"));
    const auths: (string | null)[] = [];
    const fetchFn = (_i: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const a = new Headers(init?.headers).get("Authorization");
      auths.push(a);
      if (a === "Bearer at-stale") {
        return Promise.resolve(
          new Response(JSON.stringify({ type: "about:blank", title: "u", status: 401, code: "unauthenticated", retryable: false }), {
            status: 401,
            headers: { "Content-Type": "application/problem+json" },
          }),
        );
      }
      return Promise.resolve(new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }));
    };
    const c = new ApiClient({ baseUrl: "https://cloud.example.test", fetch: fetchFn, auth: s });
    expect((await c.get("/api/v2/me")).status).toBe(200);
    expect(auths).toEqual(["Bearer at-stale", "Bearer at-1"]);
  });
});

describe("AuthSession across tabs with Web Locks + BroadcastChannel (M1 §3 [R1])", () => {
  function tabs(n: number, server: FakeRefreshServer, opts: { channel: boolean; lock: "web-locks" | "none" }) {
    const locks = new FakeLockManager();
    const hub = new FakeHub();
    const list = Array.from(
      { length: n },
      () =>
        new AuthSession({
          transport: server.transport(),
          lock: opts.lock === "web-locks" ? webLocksRefreshLock(locks) : noCrossTabLock,
          channel: opts.channel ? hub.channel() : noAuthChannel,
          idempotencyKeyFactory: keys,
        }),
    );
    return { list, locks, hub };
  }

  it("requests the cs-refresh lock exclusively", async () => {
    const server = new FakeRefreshServer();
    const { list, locks } = tabs(1, server, { channel: true, lock: "web-locks" });
    await list[0]?.refresh();
    expect(locks.requests).toEqual([REFRESH_LOCK_NAME]);
    expect(list[0]?.crossTabMode).toBe("web-locks");
  });

  it("five tabs refreshing at once: one request, everyone gets the shared token, no reuse", async () => {
    const server = new FakeRefreshServer();
    const { list, hub } = tabs(5, server, { channel: true, lock: "web-locks" });
    const res = await Promise.all(list.map((t) => t.refresh()));
    expect(res).toEqual([true, true, true, true, true]);
    expect(server.calls).toHaveLength(1);
    expect(server.reuseDetected).toBe(0);
    expect(server.revoked).toBe(false);
    for (const t of list) expect(await t.authorization()).toBe("Bearer at-1");
    expect(hub.posted).toEqual([{ type: "token", access_token: "at-1", expires_at: expect.any(Number) as number, session_id: "sess-1" }]);
  });

  it("without the channel, waiting tabs refresh one after another with the successor cookie: no reuse", async () => {
    const server = new FakeRefreshServer();
    const { list } = tabs(4, server, { channel: false, lock: "web-locks" });
    const res = await Promise.all(list.map((t) => t.refresh()));
    expect(res).toEqual([true, true, true, true]);
    expect(server.calls.map((c) => c.cookie)).toEqual(["rt-0", "rt-1", "rt-2", "rt-3"]);
    expect(new Set(server.calls.map((c) => c.key)).size).toBe(4);
    expect(server.reuseDetected).toBe(0);
    expect(server.revoked).toBe(false);
  });

  it("control: without any cross-tab lock the same race presents a rotated token and revokes the session", async () => {
    const server = new FakeRefreshServer();
    const { list } = tabs(3, server, { channel: true, lock: "none" });
    await Promise.all(list.map((t) => t.refresh()));
    expect(server.reuseDetected).toBeGreaterThan(0);
    expect(server.revoked).toBe(true);
  });

  it("a tab refreshing later (after the shared token went stale) still sends a request", async () => {
    const clock = manualClock();
    const server = new FakeRefreshServer(clock);
    const locks = new FakeLockManager();
    const hub = new FakeHub();
    const mk = (): AuthSession =>
      new AuthSession({ transport: server.transport(), lock: webLocksRefreshLock(locks), channel: hub.channel(), clock, idempotencyKeyFactory: keys });
    const [a, b] = [mk(), mk()];
    await a.refresh();
    expect(await b.authorization()).toBe("Bearer at-1");
    clock.t += 600_000;
    expect(await b.authorization()).toBe("Bearer at-2");
    expect(await a.authorization()).toBe("Bearer at-2");
    expect(server.calls).toHaveLength(2);
    expect(server.reuseDetected).toBe(0);
  });
});

describe("localStorage lease fallback (M1 §3 [R1])", () => {
  const fast = { clock: systemClock, leaseMs: 1_000, settleMs: 5, pollMs: 2 } as const;

  it("serializes holders across tabs (mutual exclusion) and releases the lease", async () => {
    const storage = new MemoryStorage();
    const locks: RefreshLock[] = Array.from({ length: 4 }, (_, i) => localStorageLeaseLock(storage, { ...fast, ownerId: `tab-${i}` }));
    let active = 0;
    let maxActive = 0;
    const order: number[] = [];
    await Promise.all(
      locks.map((l, i) =>
        l.run(async () => {
          active++;
          maxActive = Math.max(maxActive, active);
          await tick(8);
          order.push(i);
          active--;
        }),
      ),
    );
    expect(maxActive).toBe(1);
    expect(order.sort()).toEqual([0, 1, 2, 3]);
    expect(storage.getItem("cs-refresh-lease:y")).toBeNull();
    expect(locks[0]?.mode).toBe("lease");
  });

  it("four tabs refreshing at once through the lease: no reuse, and no token in storage", async () => {
    const storage = new MemoryStorage();
    const writes: string[] = [];
    const spy: StorageLike = {
      getItem: (k) => storage.getItem(k),
      setItem: (k, v) => {
        writes.push(v);
        storage.setItem(k, v);
      },
      removeItem: (k) => {
        storage.removeItem(k);
      },
    };
    const server = new FakeRefreshServer(systemClock, 5);
    const list = Array.from(
      { length: 4 },
      (_, i) =>
        new AuthSession({
          transport: server.transport(),
          lock: localStorageLeaseLock(spy, { ...fast, ownerId: `tab-${i}` }),
          channel: noAuthChannel,
          idempotencyKeyFactory: keys,
        }),
    );
    expect(list[0]?.crossTabMode).toBe("lease");
    const res = await Promise.all(list.map((t) => t.refresh()));
    expect(res).toEqual([true, true, true, true]);
    expect(server.reuseDetected).toBe(0);
    expect(server.revoked).toBe(false);
    expect(server.calls.map((c) => c.cookie)).toEqual(["rt-0", "rt-1", "rt-2", "rt-3"]);
    expect(writes.some((v) => v.includes("at-") || v.includes("rt-"))).toBe(false);
  });

  it("with a channel, tabs that waited on the lease reuse the shared token", async () => {
    const storage = new MemoryStorage();
    const hub = new FakeHub();
    const server = new FakeRefreshServer(systemClock, 5);
    const list = Array.from(
      { length: 3 },
      (_, i) =>
        new AuthSession({
          transport: server.transport(),
          lock: localStorageLeaseLock(storage, { ...fast, ownerId: `tab-${i}` }),
          channel: hub.channel(),
          idempotencyKeyFactory: keys,
        }),
    );
    await Promise.all(list.map((t) => t.refresh()));
    expect(server.calls).toHaveLength(1);
    expect(server.reuseDetected).toBe(0);
  });

  it("waits for a live lease held by another tab and takes over a lapsed one", async () => {
    const clock = manualClock();
    const storage = new MemoryStorage();
    storage.setItem("cs-refresh-lease:y", JSON.stringify({ owner: "crashed", until: clock.t - 1 }));
    const lock = localStorageLeaseLock(storage, { clock, ownerId: "me", leaseMs: 10_000, settleMs: 1, pollMs: 1 });
    expect(await lock.run(() => Promise.resolve("ran"))).toBe("ran");

    storage.setItem("cs-refresh-lease:y", JSON.stringify({ owner: "alive", until: clock.t + 5_000 }));
    let ran = false;
    const p = lock.run(() => {
      ran = true;
      return Promise.resolve();
    });
    await tick(20);
    expect(ran).toBe(false);
    clock.t += 5_001;
    await p;
    expect(ran).toBe(true);
  });

  it("treats a malformed lease record as free", async () => {
    const storage = new MemoryStorage();
    storage.setItem("cs-refresh-lease:y", "{not json");
    const lock = localStorageLeaseLock(storage, { ...fast, ownerId: "me" });
    expect(await lock.run(() => Promise.resolve(1))).toBe(1);
  });

  it("renews the lease while the holder runs", async () => {
    const clock = manualClock();
    const storage = new MemoryStorage();
    const lock = localStorageLeaseLock(storage, { clock, ownerId: "me", leaseMs: 30, settleMs: 1, pollMs: 1 });
    const untils: number[] = [];
    await lock.run(async () => {
      for (let i = 0; i < 5; i++) {
        clock.t += 10;
        await tick(3);
        const raw = storage.getItem("cs-refresh-lease:y");
        if (raw) untils.push((JSON.parse(raw) as { until: number }).until);
      }
    });
    expect(untils.at(-1)).toBeGreaterThan(1_000_000 + 30);
  });
});

/**
 * BroadcastChannel whose delivery lags the lock release, as on a slow runner: messages are delivered `delayMs`
 * after posting (macrotask), or never (`drop`), while the next lock holder runs as soon as the lock is released.
 */
class LaggingHub {
  posted: AuthChannelMessage[] = [];
  private subs: { id: number; h: (m: AuthChannelMessage) => void }[] = [];
  private next = 0;
  constructor(private readonly delayMs: number | "drop") {}
  channel(): AuthChannel {
    const id = this.next++;
    return {
      post: (m) => {
        this.posted.push(m);
        if (this.delayMs === "drop") return;
        const targets = this.subs.filter((s) => s.id !== id);
        setTimeout(() => {
          for (const s of targets) s.h(m);
        }, this.delayMs);
      },
      subscribe: (h) => {
        const entry = { id, h };
        this.subs.push(entry);
        return () => {
          this.subs = this.subs.filter((s) => s !== entry);
        };
      },
    };
  }
}

describe("broadcast delivered after the lock release (WEB.M1-1, M1 §3 [R1], CI race)", () => {
  const fast = { clock: systemClock, leaseMs: 1_000, settleMs: 5, pollMs: 2 } as const;
  const modes = {
    "web-locks": (storage: StorageLike): (() => RefreshLock) => {
      const locks = new FakeLockManager();
      return () => webLocksRefreshLock(locks, REFRESH_LOCK_NAME, storage);
    },
    lease: (storage: StorageLike): (() => RefreshLock) => {
      let n = 0;
      return () => localStorageLeaseLock(storage, { ...fast, ownerId: `tab-${n++}` });
    },
  } as const;

  for (const mode of ["web-locks", "lease"] as const) {
    function setup(delay: number | "drop", opts: { clock?: Clock; sharedTokenWaitMs?: number } = {}) {
      const storage = new MemoryStorage();
      const hub = new LaggingHub(delay);
      const server = new FakeRefreshServer(opts.clock ?? systemClock, 5);
      const lock = modes[mode](storage);
      const mk = (transport: RefreshTransport = server.transport()): AuthSession =>
        new AuthSession({
          transport,
          lock: lock(),
          channel: hub.channel(),
          idempotencyKeyFactory: keys,
          ...(opts.clock !== undefined && { clock: opts.clock }),
          ...(opts.sharedTokenWaitMs !== undefined && { sharedTokenWaitMs: opts.sharedTokenWaitMs }),
        });
      return { storage, hub, server, mk, a: mk(), b: mk() };
    }

    it(`${mode}: the waiting tab sees the generation advance and waits for the token instead of refreshing`, async () => {
      const { server, a, b, storage } = setup(30);
      const res = await Promise.all([a.refresh(), b.refresh()]);
      expect(res).toEqual([true, true]);
      expect(server.calls).toHaveLength(1);
      expect(server.reuseDetected).toBe(0);
      expect(await a.authorization()).toBe("Bearer at-1");
      expect(await b.authorization()).toBe("Bearer at-1");
      // The marker holds a generation id and an expiry only, never a token.
      for (const v of storage.data.values()) expect(v.includes("at-") || v.includes("rt-")).toBe(false);
    });

    it(`${mode}: when the announced token never arrives, the waiter refreshes exactly once after the bounded wait`, async () => {
      const { server, a, b } = setup("drop", { sharedTokenWaitMs: 50 });
      const started = Date.now();
      const res = await Promise.all([a.refresh(), b.refresh()]);
      expect(res).toEqual([true, true]);
      expect(Date.now() - started).toBeGreaterThanOrEqual(45);
      expect(server.calls.map((c) => c.cookie)).toEqual(["rt-0", "rt-1"]);
      expect(server.reuseDetected).toBe(0);
      expect(await b.authorization()).toBe("Bearer at-2");
    });

    it(`${mode}: a holder that fails (or crashes) without announcing a refresh does not make the waiter wait`, async () => {
      const { server, mk } = setup("drop", { sharedTokenWaitMs: 60_000 });
      let failOnce = true;
      const inner = server.transport();
      const flaky: RefreshTransport = {
        refresh: (key) => {
          if (failOnce) {
            failOnce = false;
            return Promise.reject(apiError("unavailable", 503, true));
          }
          return inner.refresh(key);
        },
      };
      const [a, b] = [mk(flaky), mk()];
      const res = await Promise.all([a.refresh(), b.refresh()]);
      expect(res).toEqual([false, true]);
      expect(server.calls.map((c) => c.cookie)).toEqual(["rt-0"]);
    });

    it(`${mode}: a new tab with no refresh in between refreshes at once, even if an older marker exists`, async () => {
      const { server, a, b } = setup("drop", { sharedTokenWaitMs: 60_000 });
      await a.refresh();
      expect(await b.refresh()).toBe(true);
      expect(server.calls.map((c) => c.cookie)).toEqual(["rt-0", "rt-1"]);
    });
  }
});

describe("environment selection", () => {
  it("prefers Web Locks, then the localStorage lease, then none", () => {
    const locks: LockManagerLike = { request: (_n, _o, cb) => cb() };
    expect(defaultRefreshLock({ navigator: { locks } } as unknown as typeof globalThis).mode).toBe("web-locks");
    expect(defaultRefreshLock({ navigator: {}, localStorage: new MemoryStorage() } as unknown as typeof globalThis).mode).toBe("lease");
    expect(defaultRefreshLock({} as unknown as typeof globalThis).mode).toBe("none");
  });

  it("uses BroadcastChannel when present", () => {
    const made: string[] = [];
    class BC implements BroadcastChannelLike {
      constructor(name: string) {
        made.push(name);
      }
      postMessage = vi.fn();
      addEventListener = vi.fn();
      removeEventListener = vi.fn();
    }
    expect(defaultAuthChannel({ BroadcastChannel: BC } as unknown as typeof globalThis)).not.toBe(noAuthChannel);
    expect(made).toEqual(["cs-auth"]);
    expect(defaultAuthChannel({} as unknown as typeof globalThis)).toBe(noAuthChannel);
  });

  it("broadcastAuthChannel posts messages and ignores malformed ones", () => {
    const listeners: ((ev: MessageEvent) => void)[] = [];
    const posted: unknown[] = [];
    const bc: BroadcastChannelLike = {
      postMessage: (m) => posted.push(m),
      addEventListener: (_t, l) => listeners.push(l),
      removeEventListener: (_t, l) => listeners.splice(listeners.indexOf(l), 1),
    };
    const ch = broadcastAuthChannel(bc);
    const got: AuthChannelMessage[] = [];
    const off = ch.subscribe((m) => got.push(m));
    ch.post({ type: "signed_out" });
    expect(posted).toEqual([{ type: "signed_out" }]);
    for (const data of [null, "x", { type: "token" }, { type: "token", access_token: "", expires_at: 1, session_id: "s" }, { type: "other" }]) {
      listeners[0]?.(new MessageEvent("message", { data }));
    }
    listeners[0]?.(new MessageEvent("message", { data: { type: "token", access_token: "a", expires_at: 5, session_id: "s" } }));
    expect(got).toEqual([{ type: "token", access_token: "a", expires_at: 5, session_id: "s" }]);
    off();
    expect(listeners).toHaveLength(0);
    expect(parseAuthChannelMessage({ type: "signed_out", extra: 1 })).toEqual({ type: "signed_out" });
  });
});
