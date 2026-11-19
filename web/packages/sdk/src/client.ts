// Typed fetch wrapper (contract M0 §10). Knows only the HTTP contract (App. D, §7), never backend internals.
import { idempotencyKey as defaultIdempotencyKey, isValidIdempotencyKey } from "./idempotency";
import {
  ApiError,
  codeForNonProblemStatus,
  isProblemContentType,
  parseProblem,
  synthesizeProblem,
  type Problem,
} from "./problem";
import { RetryPolicy, parseRetryAfter, systemClock, type Clock } from "./retry";

export type HttpMethod = "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";

const WRITE_METHODS: ReadonlySet<HttpMethod> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function isWriteMethod(method: HttpMethod): boolean {
  return WRITE_METHODS.has(method);
}

/**
 * Authentication hook. M0 has no authentication; M1 wires the shell's token store in here.
 * D.2: on `unauthenticated` the client refreshes once and retries once.
 */
export interface AuthHook {
  /** Value for the Authorization header of each attempt, or undefined for none. */
  authorization?(): string | undefined | Promise<string | undefined>;
  /** Refreshes credentials. Resolves true when a retry is worthwhile. */
  refresh(): Promise<boolean>;
}

export interface ApiClientOptions {
  /** Absolute base URL, e.g. `https://cloud.example.com`. Paths are appended to it. */
  readonly baseUrl: string;
  readonly fetch?: typeof fetch;
  readonly retryPolicy?: RetryPolicy;
  readonly clock?: Clock;
  /** Per-attempt timeout. Default 30 s. */
  readonly timeoutMs?: number;
  readonly auth?: AuthHook;
  readonly idempotencyKeyFactory?: () => string;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface RequestOptions<T> {
  readonly query?: Readonly<Record<string, string | number | boolean | undefined>>;
  /** Serialized as JSON. */
  readonly body?: unknown;
  readonly headers?: Readonly<Record<string, string>>;
  readonly signal?: AbortSignal;
  /** Per-attempt timeout overriding the client default. */
  readonly timeoutMs?: number;
  /**
   * Writes only. Omitted: a fresh key is generated and reused for every retry of this call.
   * A string: that key is used. `null`: no key is sent, and the write is then never retried.
   */
  readonly idempotencyKey?: string | null;
  /** Retry policy for this call; `false` disables retries. */
  readonly retry?: RetryPolicy | false;
  /** Validates and converts the decoded success body. Throwing makes the call fail as `internal`. */
  readonly decode?: (body: unknown) => T;
}

export interface ApiResponse<T> {
  readonly status: number;
  readonly data: T;
  /** `X-Request-Id` from the response, for support and log correlation. */
  readonly requestId: string | undefined;
  readonly headers: Headers;
  readonly attempts: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_ERROR_BODY_BYTES = 64 * 1024;
const REQUEST_ID_HEADER = "X-Request-Id";
const IDEMPOTENCY_HEADER = "Idempotency-Key";

const TIMEOUT = Symbol("timeout");

type AttemptResult<T> =
  | { kind: "ok"; response: ApiResponse<T> }
  | { kind: "error"; error: ApiError };

export class ApiClient {
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly retryPolicy: RetryPolicy;
  private readonly clock: Clock;
  private readonly timeoutMs: number;
  private readonly auth: AuthHook | undefined;
  private readonly newKey: () => string;
  private readonly headers: Readonly<Record<string, string>>;

  constructor(opts: ApiClientOptions) {
    let parsed: URL;
    try {
      parsed = new URL(opts.baseUrl);
    } catch {
      throw new TypeError("ApiClient baseUrl must be an absolute URL");
    }
    if (parsed.search || parsed.hash) throw new TypeError("ApiClient baseUrl must not have a query or fragment");
    this.baseUrl = parsed.href.replace(/\/+$/, "");
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.retryPolicy = opts.retryPolicy ?? new RetryPolicy();
    this.clock = opts.clock ?? systemClock;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.auth = opts.auth;
    this.newKey = opts.idempotencyKeyFactory ?? defaultIdempotencyKey;
    this.headers = opts.headers ?? {};
  }

  get<T = unknown>(path: string, opts?: RequestOptions<T>): Promise<ApiResponse<T>> {
    return this.request("GET", path, opts);
  }
  post<T = unknown>(path: string, opts?: RequestOptions<T>): Promise<ApiResponse<T>> {
    return this.request("POST", path, opts);
  }
  put<T = unknown>(path: string, opts?: RequestOptions<T>): Promise<ApiResponse<T>> {
    return this.request("PUT", path, opts);
  }
  patch<T = unknown>(path: string, opts?: RequestOptions<T>): Promise<ApiResponse<T>> {
    return this.request("PATCH", path, opts);
  }
  delete<T = unknown>(path: string, opts?: RequestOptions<T>): Promise<ApiResponse<T>> {
    return this.request("DELETE", path, opts);
  }

  /**
   * Performs a request with retries per D.3.
   * Rejects with {@link ApiError} for every failure, except a caller abort, which rejects with the
   * signal's reason unchanged.
   */
  async request<T = unknown>(method: HttpMethod, path: string, opts: RequestOptions<T> = {}): Promise<ApiResponse<T>> {
    const url = this.buildUrl(path, opts.query);
    const write = isWriteMethod(method);
    let key: string | undefined;
    if (write && opts.idempotencyKey !== null) {
      key = opts.idempotencyKey ?? this.newKey();
      if (!isValidIdempotencyKey(key)) throw new TypeError("Idempotency-Key must be 1..255 visible ASCII characters");
    }
    const policy = opts.retry === false ? RetryPolicy.none() : (opts.retry ?? this.retryPolicy);
    const signal = opts.signal;
    let refreshed = false;
    let attempt = 0;

    for (;;) {
      signal?.throwIfAborted();
      attempt++;
      const result = await this.attempt<T>(method, url, path, opts, key, attempt);
      if (result.kind === "ok") return result.response;
      const { problem } = result.error;

      // D.2 `unauthenticated`: refresh once, retry once (outside the retry budget).
      if (problem.code === "unauthenticated" && this.auth && !refreshed && (!write || key !== undefined)) {
        refreshed = true;
        if (await this.auth.refresh()) {
          attempt--;
          continue;
        }
        throw result.error;
      }

      const decision = policy.decide({ problem, attempt, isWrite: write, idempotencyKey: key });
      if (!decision.retry) throw result.error;
      await this.clock.sleep(decision.delayMs, signal);
    }
  }

  private buildUrl(path: string, query: RequestOptions<unknown>["query"]): string {
    // Paths are origin-relative; refusing absolute or protocol-relative URLs keeps credentials on the configured origin.
    if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) {
      throw new TypeError("ApiClient path must start with a single '/'");
    }
    const url = new URL(this.baseUrl + path);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined) url.searchParams.set(k, String(v));
      }
    }
    return url.href;
  }

  private async attempt<T>(
    method: HttpMethod,
    url: string,
    path: string,
    opts: RequestOptions<T>,
    key: string | undefined,
    attempt: number,
  ): Promise<AttemptResult<T>> {
    const headers = new Headers(this.headers);
    headers.set("Accept", "application/json, application/problem+json");
    for (const [k, v] of Object.entries(opts.headers ?? {})) headers.set(k, v);
    if (key !== undefined) headers.set(IDEMPOTENCY_HEADER, key);
    const authorization = await this.auth?.authorization?.();
    if (authorization !== undefined) headers.set("Authorization", authorization);
    let body: string | undefined;
    if (opts.body !== undefined) {
      body = JSON.stringify(opts.body);
      headers.set("Content-Type", "application/json");
    }

    const controller = new AbortController();
    const outer = opts.signal;
    const onOuterAbort = (): void => {
      controller.abort(outer?.reason);
    };
    outer?.throwIfAborted();
    outer?.addEventListener("abort", onOuterAbort, { once: true });
    const timeoutMs = opts.timeoutMs ?? this.timeoutMs;
    const timer = setTimeout(() => {
      controller.abort(TIMEOUT);
    }, timeoutMs);

    const synth = (problem: Problem, httpStatus?: number): AttemptResult<T> => ({
      kind: "error",
      error: new ApiError(problem, { httpStatus, synthesized: true, attempts: attempt }),
    });

    try {
      let res: Response;
      try {
        res = await this.fetchFn(url, { method, headers, body: body ?? null, signal: controller.signal });
      } catch {
        if (outer?.aborted) throw outer.reason;
        if (controller.signal.reason === TIMEOUT) return synth(synthesizeProblem("timeout", { instance: path }));
        // Network failure. The exception text is deliberately not surfaced.
        return synth(synthesizeProblem("unavailable", { instance: path }));
      }

      const requestId = res.headers.get(REQUEST_ID_HEADER) ?? undefined;
      let text: string;
      try {
        text = await res.text();
      } catch {
        if (outer?.aborted) throw outer.reason;
        const code = controller.signal.reason === TIMEOUT ? "timeout" : "unavailable";
        return synth(synthesizeProblem(code, { requestId, instance: path }), res.status);
      }

      if (!res.ok) {
        const retryAfterMs = parseRetryAfter(res.headers.get("Retry-After"), this.clock.now());
        if (isProblemContentType(res.headers.get("Content-Type")) && text.length <= MAX_ERROR_BODY_BYTES) {
          let json: unknown;
          let jsonOk = true;
          try {
            json = JSON.parse(text);
          } catch {
            jsonOk = false;
          }
          if (jsonOk) {
            const parsed = parseProblem(json, {
              httpStatus: res.status,
              ...(requestId !== undefined && { requestId }),
              ...(retryAfterMs !== undefined && { retryAfterMs }),
            });
            if (parsed.ok) {
              return {
                kind: "error",
                error: new ApiError(parsed.problem, { httpStatus: res.status, synthesized: false, attempts: attempt }),
              };
            }
          }
        }
        const code = codeForNonProblemStatus(res.status);
        return synth(synthesizeProblem(code, { requestId, instance: path, retryAfterMs }), res.status);
      }

      let decoded: unknown = undefined;
      if (method !== "HEAD" && res.status !== 204 && res.status !== 205 && text.length > 0) {
        const ct = res.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase() ?? "";
        if (ct === "application/json" || ct.endsWith("+json")) {
          try {
            decoded = JSON.parse(text);
          } catch {
            return synth(synthesizeProblem("internal", { requestId, instance: path }), res.status);
          }
        } else {
          decoded = text;
        }
      }
      let data: T;
      try {
        data = opts.decode ? opts.decode(decoded) : (decoded as T);
      } catch {
        return synth(synthesizeProblem("internal", { requestId, instance: path }), res.status);
      }
      return { kind: "ok", response: { status: res.status, data, requestId, headers: res.headers, attempts: attempt } };
    } finally {
      clearTimeout(timer);
      outer?.removeEventListener("abort", onOuterAbort);
    }
  }
}
