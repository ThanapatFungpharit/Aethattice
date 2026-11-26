// SDK auth session (contract M1 §2.4, §3 [R1] [R12], §7).
// Keeps the access token in memory only, refreshes it through the HttpOnly refresh cookie, and serializes
// refreshes within a tab and across tabs so that a rotated refresh token is never presented twice.
// Knows only the HTTP contract (POST /api/v2/auth/token/refresh), never backend internals.
import { ApiClient, type ApiClientOptions, type AuthHook } from "./client";
import type { DpopKeyManager } from "./dpop";
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
/**
 * How long a tab that waited on the refresh lock waits for the token another tab announced (refresh generation
 * marker) to arrive on the channel before it refreshes itself.
 */
export const SHARED_TOKEN_WAIT_MS = 1_000;

/** Authentication result (contract M1 §2.4). */
export interface AuthResult {
  readonly state: "authenticated";
  readonly access_token: string;
  /** Lifetime in seconds. */
  readonly expires_in: number;
  readonly session_id: string;
  /**
   * `login/finish` only (rev 9): the stored KSF parameters or server key version are not current, so the client
   * re-registers with the same password right away (`register/start {purpose: "ksf_upgrade"}`). Absent otherwise.
   */
  readonly reregister?: true;
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
  return { state: "authenticated", access_token, expires_in, session_id, ...(body.reregister === true && { reregister: true as const }) };
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
 * With `dpop`, every attempt carries a fresh proof from the session key (rev 8: a bound refresh family needs one).
 */
export function httpRefreshTransport(opts: Omit<ApiClientOptions, "auth" | "idempotencyKeyFactory">): RefreshTransport {
  const client = new ApiClient(opts);
  return {
    async refresh(idempotencyKey, signal) {
      const r = await client.post<AuthResult>(REFRESH_PATH, {
        idempotencyKey,
        decode: decodeAuthResult,
        dpop: true,
        ...(signal !== undefined && { signal }),
      });
      return r.data;
    },
  };
}

/**
 * Reads one string claim from a JWS compact token's payload WITHOUT verifying it (display and routing only).
 * Returns undefined for anything malformed.
 */
export function unverifiedClaim(token: string, claim: string): string | undefined {
  const payload = token.split(".")[1];
  if (payload === undefined || payload.length === 0) return undefined;
  try {
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const text = new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
    const v: unknown = JSON.parse(text);
    if (!isRecord(v)) return undefined;
    const c = v[claim];
    return typeof c === "string" ? c : undefined;
  } catch {
    return undefined;
  }
}

/** `scp` of an enrolment-only session (rev 11). */
export const MFA_ENROLMENT_SCOPE = "mfa_enrolment";

// ---- cross-tab serialization ----

/** Runs `fn` while holding the cross-tab refresh lock. */
export interface RefreshLock {
  readonly mode: "web-locks" | "lease" | "none";
  run<T>(fn: () => Promise<T>): Promise<T>;
  /** Refresh generation marker shared by the tabs that share this lock, when there is shared storage. */
  readonly marker?: RefreshMarker;
}

/** The last refresh announced by any tab: a random generation id and the new token's expiry. Never the token. */
export interface RefreshGeneration {
  readonly gen: string;
  readonly expiresAt: number;
}

/**
 * Non-secret record of the latest refresh, written by the lock holder after it has broadcast the new token and
 * before it releases the lock. BroadcastChannel delivery is asynchronous and not ordered with the lock: a tab that
 * gets the lock next may not have received the token yet. Seeing the generation advance since it started waiting
 * tells it a fresh token is on its way, so it waits for that instead of presenting the cookie again.
 */
export interface RefreshMarker {
  read(): RefreshGeneration | undefined;
  write(expiresAt: number): void;
}

/** The subset of the Web Locks API the SDK uses. */
export interface LockManagerLike {
  request<T>(name: string, options: { mode: "exclusive" }, callback: () => Promise<T>): Promise<T>;
}

/**
 * Serializes refreshes across tabs with `navigator.locks.request("cs-refresh", …)` (contract M1 §3 [R1]).
 * With `storage` (localStorage), the holder also records the refresh generation marker there.
 */
export function webLocksRefreshLock(locks: LockManagerLike, name: string = REFRESH_LOCK_NAME, storage?: StorageLike): RefreshLock {
  return {
    mode: "web-locks",
    run: (fn) => locks.request(name, { mode: "exclusive" }, fn),
    ...(storage !== undefined && { marker: storageRefreshMarker(storage, `${name}:gen`) }),
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

/** Refresh generation marker in localStorage: `{gen, expires_at}` only, never a token. Storage errors are ignored. */
export function storageRefreshMarker(storage: StorageLike, key: string): RefreshMarker {
  return {
    read() {
      try {
        const raw = storage.getItem(key);
        if (raw === null) return undefined;
        const v: unknown = JSON.parse(raw);
        if (isRecord(v) && typeof v.gen === "string" && typeof v.expires_at === "number") return { gen: v.gen, expiresAt: v.expires_at };
      } catch {
        // Unavailable or malformed: no marker, so the waiting tab simply refreshes.
      }
      return undefined;
    },
    write(expiresAt) {
      try {
        storage.setItem(key, JSON.stringify({ gen: defaultIdempotencyKey(), expires_at: expiresAt }));
      } catch {
        // Quota or storage unavailable: waiting tabs then refresh themselves (still serialized, no reuse).
      }
    },
  };
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
 * The lease records only a tab id and an expiry, never a token; the generation marker (`<key>:gen`) likewise.
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
    marker: storageRefreshMarker(storage, `${key}:gen`),
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
  /** Default {@link SHARED_TOKEN_WAIT_MS}. */
  readonly sharedTokenWaitMs?: number;
  /**
   * The session's DPoP key (M1 rev 8). When set, tokens are sent as `Authorization: DPoP <token>`, the key is
   * deleted when the session ends (sign-out, or a refresh refused with `unauthenticated`), and the tab re-reads the
   * shared key whenever another tab signs in or out. The same manager must be the ApiClients' `dpop` prover.
   */
  readonly dpop?: DpopKeyManager;
}

export interface AuthState {
  readonly authenticated: boolean;
  readonly sessionId: string | undefined;
}

/** Picks Web Locks when available, else a localStorage lease, else no cross-tab lock. */
export function defaultRefreshLock(g: typeof globalThis = globalThis): RefreshLock {
  const locks = (g as { navigator?: { locks?: LockManagerLike } }).navigator?.locks;
  let storage: StorageLike | undefined;
  try {
    storage = (g as { localStorage?: StorageLike }).localStorage;
  } catch {
    storage = undefined;
  }
  if (locks && typeof locks.request === "function") return webLocksRefreshLock(locks, REFRESH_LOCK_NAME, storage);
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
  private readonly sharedTokenWaitMs: number;
  private readonly dpop: DpopKeyManager | undefined;
  private readonly unsubscribe: () => void;
  private readonly listeners = new Set<(state: AuthState) => void>();

  private accessToken: string | undefined;
  private expiresAt = 0;
  private sessionId: string | undefined;
  /** Bumped on every change of the token, from this tab or another. */
  private version = 0;
  private inFlight: Promise<boolean> | undefined;
  /** Resolved on every version change. */
  private readonly versionWaiters = new Set<() => void>();

  constructor(opts: AuthSessionOptions) {
    this.transport = opts.transport;
    this.lock = opts.lock ?? defaultRefreshLock();
    this.channel = opts.channel ?? defaultAuthChannel();
    this.clock = opts.clock ?? systemClock;
    this.newKey = opts.idempotencyKeyFactory ?? defaultIdempotencyKey;
    this.leewayMs = opts.leewayMs ?? PROACTIVE_REFRESH_LEEWAY_MS;
    this.sharedTokenWaitMs = opts.sharedTokenWaitMs ?? SHARED_TOKEN_WAIT_MS;
    this.dpop = opts.dpop;
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

  /** Forgets the token locally and in the other tabs (e.g. after logout, §3 [R10]) and deletes the DPoP key. */
  async signedOut(): Promise<void> {
    this.clear(true);
    await this.discardKey();
  }

  /**
   * Runs `fn` under the cross-tab refresh lock. Sign-in uses it so that creating the session's DPoP key,
   * `login/finish` and sharing the result cannot interleave with a refresh or a sign-in in another tab.
   */
  exclusive<T>(fn: () => Promise<T>): Promise<T> {
    return this.lock.run(fn);
  }

  /**
   * The `scp` claim of the current access token (rev 11: `"mfa_enrolment"` for an enrolment-only session), read for
   * display and routing only. The token is not verified here and this value is never trusted for security.
   */
  get scope(): string | undefined {
    return this.accessToken === undefined ? undefined : unverifiedClaim(this.accessToken, "scp");
  }

  /** The DPoP key manager, when the session is DPoP-bound. */
  get dpopKeys(): DpopKeyManager | undefined {
    return this.dpop;
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
    // Rev 8: a token bound to a key (cnf.jkt) is sent with the DPoP scheme; Bearer is refused for it.
    return `${this.dpop ? "DPoP" : "Bearer"} ${this.accessToken}`;
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
    const seenGen = this.lock.marker?.read()?.gen;
    const receivedFresh = (): boolean => this.version !== seen && this.accessToken !== undefined && !this.needsRefresh();
    return this.lock.run(async () => {
      // Another tab refreshed while this one waited, and its token reached us: the cookie has rotated
      // already and the shared token is fresh, so no request is needed.
      if (receivedFresh()) return true;
      // Another tab refreshed while this one waited, but its broadcast has not arrived yet (delivery is not ordered
      // with the lock release). Wait for it, bounded; a crashed or silent holder only costs this wait, after which
      // this tab refreshes itself once with the cookie the browser now holds.
      const m = this.lock.marker?.read();
      if (m !== undefined && m.gen !== seenGen && this.clock.now() < m.expiresAt - this.leewayMs) {
        await this.waitForVersionChange(seen, this.sharedTokenWaitMs);
        if (receivedFresh()) return true;
      }
      const key = this.newKey();
      let result: AuthResult;
      try {
        result = await this.transport.refresh(key);
      } catch (e) {
        // `unauthenticated`: the refresh cookie is missing, expired, or its session was revoked (reuse).
        // The cookie is shared by all tabs, so they are all signed out.
        // Rev 8: the session has ended (revoked, reuse, or a proof from another key), so its DPoP key goes too.
        if (isApiError(e) && e.problem.code === "unauthenticated") {
          this.clear(true);
          await this.discardKey();
        }
        return false;
      }
      this.adopt(result.access_token, this.clock.now() + result.expires_in * 1000, result.session_id, true);
      return true;
    });
  }

  /** Resolves on the next token change after `seen`, or after `ms`. */
  private async waitForVersionChange(seen: number, ms: number): Promise<void> {
    if (this.version !== seen) return;
    const stop = new AbortController();
    let waiter: (() => void) | undefined;
    const changed = new Promise<void>((resolve) => {
      waiter = resolve;
      this.versionWaiters.add(resolve);
    });
    try {
      await Promise.race([changed, this.clock.sleep(ms, stop.signal).catch(() => undefined)]);
    } finally {
      stop.abort();
      if (waiter !== undefined) this.versionWaiters.delete(waiter);
    }
  }

  private bumpVersion(): void {
    this.version++;
    const waiters = [...this.versionWaiters];
    this.versionWaiters.clear();
    for (const w of waiters) w();
  }

  private onChannelMessage(m: AuthChannelMessage): void {
    // Another tab signed in (new key) or out: re-read the shared key before the next proof.
    if (m.type === "signed_out" || m.session_id !== this.sessionId) this.dpop?.invalidate();
    if (m.type === "signed_out") this.clear(false);
    else this.adopt(m.access_token, m.expires_at, m.session_id, false);
  }

  private adopt(token: string, expiresAt: number, sessionId: string, share: boolean): void {
    this.accessToken = token;
    this.expiresAt = expiresAt;
    this.sessionId = sessionId;
    this.bumpVersion();
    // Shared before the lock is released; delivery may still lag the release, so the generation marker is
    // recorded only after the broadcast was posted: a tab that sees it advance knows the token is on its way.
    if (share) {
      this.channel.post({ type: "token", access_token: token, expires_at: expiresAt, session_id: sessionId });
      this.lock.marker?.write(expiresAt);
    }
    this.notify();
  }

  private clear(share: boolean): void {
    const had = this.accessToken !== undefined;
    this.accessToken = undefined;
    this.expiresAt = 0;
    this.sessionId = undefined;
    this.bumpVersion();
    if (share) this.channel.post({ type: "signed_out" });
    if (had || share) this.notify();
  }

  private async discardKey(): Promise<void> {
    try {
      await this.dpop?.discard();
    } catch {
      // Store unavailable: the key is useless without its session, and the next sign-in replaces it.
    }
  }

  private notify(): void {
    const s = this.state;
    for (const l of this.listeners) l(s);
  }
}
