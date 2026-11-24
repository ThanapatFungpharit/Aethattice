// SDK auth session (contract M1 §2.4, §3 [R1] [R12], §7).
// Keeps the access token in memory only, refreshes it through the HttpOnly refresh cookie, and serializes
// refreshes within a tab and across tabs so that a rotated refresh token is never presented twice.
// Knows only the HTTP contract (POST /api/v2/auth/token/refresh), never backend internals.
import { ApiClient, type ApiClientOptions, type AuthHook } from "./client";
import { idempotencyKey as defaultIdempotencyKey } from "./idempotency";
import { isApiError } from "./problem";
import { systemClock, type Clock } from "./retry";

/** Refresh endpoint (contract M1 §3). The refresh cookie is scoped to `/api/v2/auth/token`. */
export const REFRESH_PATH = "/api/v2/auth/token/refresh";
/** Web Locks name that serializes refreshes across tabs (contract M1 §3 [R1]). */
export const REFRESH_LOCK_NAME = "cs-refresh";
/** BroadcastChannel name on which the refreshing tab shares the new access token (contract M1 §3 [R1]). */
export const AUTH_CHANNEL_NAME = "cs-auth";
/** Client leeway for proactive refresh (contract M1 §3 [R12]): refresh when the token expires within 60 s. */
export const PROACTIVE_REFRESH_LEEWAY_MS = 60_000;

/** Authentication result (contract M1 §2.4). */
export interface AuthResult {
  readonly state: "authenticated";
  readonly access_token: string;
  /** Lifetime in seconds. */
  readonly expires_in: number;
  readonly session_id: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Validates a §2.4 authentication result. Throws TypeError (the API client maps that to `internal`). */
export function decodeAuthResult(body: unknown): AuthResult {
  if (!isRecord(body) || body.state !== "authenticated") throw new TypeError("not an authentication result");
  const { access_token, expires_in, session_id } = body;
  if (typeof access_token !== "string" || access_token.length === 0) throw new TypeError("access_token missing");
  if (typeof expires_in !== "number" || !Number.isInteger(expires_in) || expires_in <= 0) {
    throw new TypeError("expires_in must be a positive integer");
  }
  if (typeof session_id !== "string" || session_id.length === 0) throw new TypeError("session_id missing");
  return { state: "authenticated", access_token, expires_in, session_id };
}

/**
 * Performs one refresh request. Implementations must send `idempotencyKey` as the `Idempotency-Key` header
 * and must retry only with that same key (contract M1 §3 [R1]: a lost response replayed with the same key
 * within 30 s is not reuse). Rejects with an ApiError on failure.
 */
export interface RefreshTransport {
  refresh(idempotencyKey: string, signal?: AbortSignal): Promise<AuthResult>;
}

/**
 * HTTP transport for `POST /api/v2/auth/token/refresh`. The browser sends the `__Secure-cs_rt` cookie, so the
 * API must be same-origin with the page. It builds its own ApiClient without an auth hook, so a 401 from the
 * refresh endpoint can never recurse into another refresh. ApiClient retries reuse the given key (D.3).
 */
export function httpRefreshTransport(opts: Omit<ApiClientOptions, "auth" | "idempotencyKeyFactory">): RefreshTransport {
  const client = new ApiClient(opts);
  return {
    async refresh(idempotencyKey, signal) {
      const r = await client.post<AuthResult>(REFRESH_PATH, {
        idempotencyKey,
        decode: decodeAuthResult,
        ...(signal !== undefined && { signal }),
      });
      return r.data;
    },
  };
}

// ---- cross-tab serialization ----

/** Runs `fn` while holding the cross-tab refresh lock. */
export interface RefreshLock {
  readonly mode: "web-locks" | "lease" | "none";
  run<T>(fn: () => Promise<T>): Promise<T>;
}

/** The subset of the Web Locks API the SDK uses. */
export interface LockManagerLike {
  request<T>(name: string, options: { mode: "exclusive" }, callback: () => Promise<T>): Promise<T>;
}

/** Serializes refreshes across tabs with `navigator.locks.request("cs-refresh", …)` (contract M1 §3 [R1]). */
export function webLocksRefreshLock(locks: LockManagerLike, name: string = REFRESH_LOCK_NAME): RefreshLock {
  return {
    mode: "web-locks",
    run: (fn) => locks.request(name, { mode: "exclusive" }, fn),
  };
}

/** The subset of the Storage API the lease uses. */
export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface LeaseOptions {
  readonly clock?: Clock;
  /** Unique id of this tab. Default: crypto.randomUUID(). */
  readonly ownerId?: string;
  /** Storage key prefix. Default `cs-refresh-lease`. */
  readonly key?: string;
  /** Lease lifetime; a crashed holder's lease lapses after it. Renewed while held. Default 10 s. */
  readonly leaseMs?: number;
  /** Wait between the claim and its check; must exceed the longest gap between another tab's read and write. Default 50 ms. */
  readonly settleMs?: number;
  /** Poll interval while another tab holds the lease. Default 100 ms. */
  readonly pollMs?: number;
}

interface LeaseRecord {
  readonly owner: string;
  readonly until: number;
}

function readLease(storage: StorageLike, key: string): LeaseRecord | undefined {
  let raw: string | null;
  try {
    raw = storage.getItem(key);
  } catch {
    return undefined;
  }
  if (raw === null) return undefined;
  try {
    const v: unknown = JSON.parse(raw);
    if (isRecord(v) && typeof v.owner === "string" && typeof v.until === "number") return { owner: v.owner, until: v.until };
  } catch {
    // A malformed record is treated as absent.
  }
  return undefined;
}

/**
 * Fallback when Web Locks are unavailable (contract M1 §3 [R1]): a lease in localStorage.
 * localStorage has no compare-and-set, so the lease uses Lamport's fast mutual exclusion with a timing
 * assumption: announce in `<key>:x`, claim `<key>:y` if free, and when another tab announced in between,
 * wait `settleMs` and keep the lease only if `<key>:y` still names this tab. The holder renews the lease every
 * `leaseMs / 3`; a lease whose `until` has passed belongs to a crashed tab and may be taken over.
 * The lease records only a tab id and an expiry, never a token.
 * Because this is weaker than Web Locks, the UI degrades to a single active tab in this mode (§3 [R1]).
 */
export function localStorageLeaseLock(storage: StorageLike, opts: LeaseOptions = {}): RefreshLock {
  const clock = opts.clock ?? systemClock;
  const owner = opts.ownerId ?? defaultIdempotencyKey();
  const key = opts.key ?? "cs-refresh-lease";
  const xKey = `${key}:x`;
  const yKey = `${key}:y`;
  const leaseMs = opts.leaseMs ?? 10_000;
  const settleMs = opts.settleMs ?? 50;
  const pollMs = opts.pollMs ?? 100;

  const claim = (): void => {
    storage.setItem(yKey, JSON.stringify({ owner, until: clock.now() + leaseMs } satisfies LeaseRecord));
  };
  const heldByOther = (): boolean => {
    const y = readLease(storage, yKey);
    return y !== undefined && y.owner !== owner && y.until > clock.now();
  };

  const acquire = async (): Promise<void> => {
    for (;;) {
      storage.setItem(xKey, owner);
      if (heldByOther()) {
        await clock.sleep(pollMs);
        continue;
      }
      claim();
      if (storage.getItem(xKey) !== owner) {
        await clock.sleep(settleMs);
        if (readLease(storage, yKey)?.owner !== owner) {
          await clock.sleep(pollMs);
          continue;
        }
      }
      return;
    }
  };

  return {
    mode: "lease",
    async run(fn) {
      await acquire();
      const stop = new AbortController();
      const renew = async (): Promise<void> => {
        for (;;) {
          await clock.sleep(Math.max(1, Math.floor(leaseMs / 3)), stop.signal);
          if (readLease(storage, yKey)?.owner === owner) claim();
        }
      };
      renew().catch(() => undefined);
      try {
        return await fn();
      } finally {
        stop.abort();
        if (readLease(storage, yKey)?.owner === owner) storage.removeItem(yKey);
      }
    },
  };
}

/** No cross-tab serialization: only for environments with a single context (tests, workers without storage). */
export const noCrossTabLock: RefreshLock = { mode: "none", run: (fn) => fn() };

// ---- cross-tab token sharing ----

/** Messages on the auth channel. Only same-origin tabs can receive them; tokens never go to storage. */
export type AuthChannelMessage =
  | { readonly type: "token"; readonly access_token: string; readonly expires_at: number; readonly session_id: string }
  | { readonly type: "signed_out" };

export interface AuthChannel {
  post(message: AuthChannelMessage): void;
  /** Delivers messages posted by other tabs. Returns an unsubscribe function. */
  subscribe(handler: (message: AuthChannelMessage) => void): () => void;
}

/** The subset of BroadcastChannel the SDK uses. */
export interface BroadcastChannelLike {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (ev: MessageEvent) => void): void;
  removeEventListener(type: "message", listener: (ev: MessageEvent) => void): void;
}

export function parseAuthChannelMessage(v: unknown): AuthChannelMessage | undefined {
  if (!isRecord(v)) return undefined;
  if (v.type === "signed_out") return { type: "signed_out" };
  if (
    v.type === "token" &&
    typeof v.access_token === "string" &&
    v.access_token.length > 0 &&
    typeof v.expires_at === "number" &&
    Number.isFinite(v.expires_at) &&
    typeof v.session_id === "string"
  ) {
    return { type: "token", access_token: v.access_token, expires_at: v.expires_at, session_id: v.session_id };
  }
  return undefined;
}

/** Shares tokens over BroadcastChannel (contract M1 §3 [R1]). */
export function broadcastAuthChannel(channel: BroadcastChannelLike): AuthChannel {
  return {
    post: (message) => {
      channel.postMessage(message);
    },
    subscribe(handler) {
      const listener = (ev: MessageEvent): void => {
        const m = parseAuthChannelMessage(ev.data);
        if (m) handler(m);
      };
      channel.addEventListener("message", listener);
      return () => {
        channel.removeEventListener("message", listener);
      };
    },
  };
}

/**
 * Without BroadcastChannel nothing is shared: a tab that waited on the lock refreshes again with the cookie
 * the browser now holds, which is already the successor (§3 [R1]), so correctness does not depend on the channel.
 */
export const noAuthChannel: AuthChannel = { post: () => undefined, subscribe: () => () => undefined };

// ---- session ----

export interface AuthSessionOptions {
  readonly transport: RefreshTransport;
  /** Default: {@link defaultRefreshLock}. */
  readonly lock?: RefreshLock;
  /** Default: {@link defaultAuthChannel}. */
  readonly channel?: AuthChannel;
  readonly clock?: Clock;
  readonly idempotencyKeyFactory?: () => string;
  /** Default {@link PROACTIVE_REFRESH_LEEWAY_MS}. */
  readonly leewayMs?: number;
}

export interface AuthState {
  readonly authenticated: boolean;
  readonly sessionId: string | undefined;
}

/** Picks Web Locks when available, else a localStorage lease, else no cross-tab lock. */
export function defaultRefreshLock(g: typeof globalThis = globalThis): RefreshLock {
  const locks = (g as { navigator?: { locks?: LockManagerLike } }).navigator?.locks;
  if (locks && typeof locks.request === "function") return webLocksRefreshLock(locks);
  let storage: StorageLike | undefined;
  try {
    storage = (g as { localStorage?: StorageLike }).localStorage;
  } catch {
    storage = undefined;
  }
  return storage ? localStorageLeaseLock(storage) : noCrossTabLock;
}

/** BroadcastChannel when available, else no sharing. */
export function defaultAuthChannel(g: typeof globalThis = globalThis): AuthChannel {
  const BC = (g as { BroadcastChannel?: new (name: string) => BroadcastChannelLike }).BroadcastChannel;
  return BC ? broadcastAuthChannel(new BC(AUTH_CHANNEL_NAME)) : noAuthChannel;
}

/**
 * The SDK auth client (contract M1 §7). Implements {@link AuthHook} for {@link ApiClient}.
 * - The access token lives in memory only.
 * - Refreshes are deduplicated within the tab and serialized across tabs ({@link RefreshLock}).
 * - Every refresh carries a fresh Idempotency-Key, reused only for retries of that same refresh.
 * - A tab that obtains a new token shares it on the {@link AuthChannel}; a tab that was waiting for the lock
 *   and received it meanwhile skips its own request.
 * - `authorization()` refreshes proactively when the token expires within the 60 s leeway ([R12]).
 */
export class AuthSession implements AuthHook {
  private readonly transport: RefreshTransport;
  private readonly lock: RefreshLock;
  private readonly channel: AuthChannel;
  private readonly clock: Clock;
  private readonly newKey: () => string;
  private readonly leewayMs: number;
  private readonly unsubscribe: () => void;
  private readonly listeners = new Set<(state: AuthState) => void>();

  private accessToken: string | undefined;
  private expiresAt = 0;
  private sessionId: string | undefined;
  /** Bumped on every change of the token, from this tab or another. */
  private version = 0;
  private inFlight: Promise<boolean> | undefined;

  constructor(opts: AuthSessionOptions) {
    this.transport = opts.transport;
    this.lock = opts.lock ?? defaultRefreshLock();
    this.channel = opts.channel ?? defaultAuthChannel();
    this.clock = opts.clock ?? systemClock;
    this.newKey = opts.idempotencyKeyFactory ?? defaultIdempotencyKey;
    this.leewayMs = opts.leewayMs ?? PROACTIVE_REFRESH_LEEWAY_MS;
    this.unsubscribe = this.channel.subscribe((m) => {
      this.onChannelMessage(m);
    });
  }

  /** How refreshes are serialized across tabs. `lease`/`none` mean the UI must degrade to a single active tab. */
  get crossTabMode(): RefreshLock["mode"] {
    return this.lock.mode;
  }

  get state(): AuthState {
    return { authenticated: this.accessToken !== undefined, sessionId: this.sessionId };
  }

  /** Notified on every sign-in, token change and sign-out. Returns an unsubscribe function. */
  subscribe(listener: (state: AuthState) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Stores the result of a sign-in (§2.4) and shares it with the other tabs. */
  signedIn(result: AuthResult): void {
    this.adopt(result.access_token, this.clock.now() + result.expires_in * 1000, result.session_id, true);
  }

  /** Forgets the token locally and in the other tabs (e.g. after logout, §3 [R10]). */
  signedOut(): void {
    this.clear(true);
  }

  /** Stops listening to the channel. */
  dispose(): void {
    this.unsubscribe();
    this.listeners.clear();
  }

  /** True when the token is missing or expires within the leeway. */
  needsRefresh(): boolean {
    return this.accessToken === undefined || this.clock.now() >= this.expiresAt - this.leewayMs;
  }

  /** AuthHook: the bearer header, refreshing first when a held token is within the leeway of expiry. */
  async authorization(): Promise<string | undefined> {
    if (this.accessToken !== undefined && this.needsRefresh()) await this.refresh();
    if (this.accessToken === undefined || this.clock.now() >= this.expiresAt) return undefined;
    return `Bearer ${this.accessToken}`;
  }

  /**
   * AuthHook: refreshes the access token. Concurrent calls in this tab share one request; calls in different
   * tabs are serialized by the lock. Resolves true when a usable token is held afterwards.
   */
  refresh(): Promise<boolean> {
    this.inFlight ??= this.refreshSerialized()
      .catch(() => false)
      .finally(() => {
        this.inFlight = undefined;
      });
    return this.inFlight;
  }

  private async refreshSerialized(): Promise<boolean> {
    const seen = this.version;
    return this.lock.run(async () => {
      // Another tab refreshed while this one waited, and its token reached us: the cookie has rotated
      // already and the shared token is fresh, so no request is needed.
      if (this.version !== seen && this.accessToken !== undefined && !this.needsRefresh()) return true;
      const key = this.newKey();
      let result: AuthResult;
      try {
        result = await this.transport.refresh(key);
      } catch (e) {
        // `unauthenticated`: the refresh cookie is missing, expired, or its session was revoked (reuse).
        // The cookie is shared by all tabs, so they are all signed out.
        if (isApiError(e) && e.problem.code === "unauthenticated") this.clear(true);
        return false;
      }
      this.adopt(result.access_token, this.clock.now() + result.expires_in * 1000, result.session_id, true);
      return true;
    });
  }

  private onChannelMessage(m: AuthChannelMessage): void {
    if (m.type === "signed_out") this.clear(false);
    else this.adopt(m.access_token, m.expires_at, m.session_id, false);
  }

  private adopt(token: string, expiresAt: number, sessionId: string, share: boolean): void {
    this.accessToken = token;
    this.expiresAt = expiresAt;
    this.sessionId = sessionId;
    this.version++;
    // Shared before the lock is released, so waiting tabs normally receive it before they would refresh.
    if (share) this.channel.post({ type: "token", access_token: token, expires_at: expiresAt, session_id: sessionId });
    this.notify();
  }

  private clear(share: boolean): void {
    const had = this.accessToken !== undefined;
    this.accessToken = undefined;
    this.expiresAt = 0;
    this.sessionId = undefined;
    this.version++;
    if (share) this.channel.post({ type: "signed_out" });
    if (had || share) this.notify();
  }

  private notify(): void {
    const s = this.state;
    for (const l of this.listeners) l(s);
  }
}
