// Client retry policy (App. D.3, contract M0 §2).
import type { Problem } from "./problem";

/** Time source and sleeper. Injected so tests run without real time. */
export interface Clock {
  now(): number;
  /** Resolves after `ms`; rejects with `signal.reason` if the signal aborts first. */
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
}

export const systemClock: Clock = {
  now: () => Date.now(),
  sleep: (ms, signal) =>
    new Promise<void>((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason as Error);
        return;
      }
      const onAbort = (): void => {
        clearTimeout(timer);
        reject(signal?.reason as Error);
      };
      const timer = setTimeout(() => {
        signal?.removeEventListener("abort", onAbort);
        resolve();
      }, ms);
      signal?.addEventListener("abort", onAbort, { once: true });
    }),
};

export interface RetryPolicyOptions {
  /** Total attempts including the first one. Default 5. */
  readonly maxAttempts?: number;
  /** Backoff base for the first retry. Default 200 ms (D.3). */
  readonly initialDelayMs?: number;
  /** Backoff cap. Default 30 s (D.3). */
  readonly maxDelayMs?: number;
  /** Uniform random in [0, 1). Default Math.random. */
  readonly random?: () => number;
}

export type RetryStopReason =
  | "not_retryable"
  | "attempts_exhausted"
  | "write_without_idempotency_key"
  | "retry_after_exceeds_cap";

export type RetryDecision =
  | { readonly retry: true; readonly delayMs: number }
  | { readonly retry: false; readonly reason: RetryStopReason };

export interface RetryInput {
  readonly problem: Problem;
  /** Attempts already made (1 after the first failure). */
  readonly attempt: number;
  /** True for methods with side effects (POST, PUT, PATCH, DELETE). */
  readonly isWrite: boolean;
  /** The Idempotency-Key the failed attempt carried, if any. A retry must reuse it unchanged. */
  readonly idempotencyKey?: string | undefined;
}

export const DEFAULT_MAX_ATTEMPTS = 5;
export const DEFAULT_INITIAL_DELAY_MS = 200;
export const DEFAULT_MAX_DELAY_MS = 30_000;

/**
 * D.3: retry only when `retryable` is true; exponential backoff with full jitter
 * (delay = random() * min(cap, initial * 2^n)); honour `retry_after_ms` as a minimum delay;
 * bounded attempts; writes only when they carry an Idempotency-Key.
 *
 * Design choice: a `retry_after_ms` larger than the cap stops retrying (the error is surfaced)
 * rather than either waiting beyond the cap or retrying earlier than the server asked.
 */
export class RetryPolicy {
  readonly maxAttempts: number;
  readonly initialDelayMs: number;
  readonly maxDelayMs: number;
  private readonly random: () => number;

  constructor(opts: RetryPolicyOptions = {}) {
    this.maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.initialDelayMs = opts.initialDelayMs ?? DEFAULT_INITIAL_DELAY_MS;
    this.maxDelayMs = opts.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
    this.random = opts.random ?? Math.random;
    if (!Number.isInteger(this.maxAttempts) || this.maxAttempts < 1) throw new RangeError("maxAttempts must be an integer >= 1");
    if (!(this.initialDelayMs > 0)) throw new RangeError("initialDelayMs must be > 0");
    if (!(this.maxDelayMs >= this.initialDelayMs)) throw new RangeError("maxDelayMs must be >= initialDelayMs");
  }

  /** A policy that never retries. */
  static none(): RetryPolicy {
    return new RetryPolicy({ maxAttempts: 1 });
  }

  /** Full-jitter backoff for the n-th retry (n = 0 for the first retry). */
  backoffMs(n: number): number {
    const ceiling = Math.min(this.maxDelayMs, this.initialDelayMs * 2 ** Math.min(n, 52));
    const r = this.random();
    const clamped = r < 0 ? 0 : r >= 1 ? 1 - Number.EPSILON : r;
    return Math.floor(clamped * ceiling);
  }

  decide(input: RetryInput): RetryDecision {
    if (!input.problem.retryable) return { retry: false, reason: "not_retryable" };
    if (input.isWrite && !input.idempotencyKey) return { retry: false, reason: "write_without_idempotency_key" };
    if (input.attempt >= this.maxAttempts) return { retry: false, reason: "attempts_exhausted" };
    const retryAfter = input.problem.retry_after_ms;
    if (retryAfter !== undefined && retryAfter > this.maxDelayMs) return { retry: false, reason: "retry_after_exceeds_cap" };
    const backoff = this.backoffMs(input.attempt - 1);
    return { retry: true, delayMs: Math.max(backoff, retryAfter ?? 0) };
  }
}

/**
 * Parses a Retry-After header (delta-seconds or HTTP-date) into milliseconds.
 * Returns undefined for absent or unparsable values.
 */
export function parseRetryAfter(value: string | null | undefined, nowMs: number): number | undefined {
  if (value === null || value === undefined) return undefined;
  const v = value.trim();
  if (/^\d+$/.test(v)) {
    const seconds = Number(v);
    return Number.isSafeInteger(seconds * 1000) ? seconds * 1000 : undefined;
  }
  // HTTP-date in IMF-fixdate form (RFC 9110 §5.6.7); obsolete forms are ignored.
  if (!/^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(v)) return undefined;
  const date = Date.parse(v);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - nowMs);
}
