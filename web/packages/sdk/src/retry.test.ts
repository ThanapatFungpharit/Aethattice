import { describe, expect, it } from "vitest";
import { synthesizeProblem, type Problem } from "./problem";
import { RetryPolicy, parseRetryAfter, systemClock } from "./retry";

const retryable: Problem = synthesizeProblem("unavailable");
const notRetryable: Problem = { ...synthesizeProblem("internal"), code: "not_found", status: 404, retryable: false };

describe("RetryPolicy defaults (D.3)", () => {
  it("uses 5 attempts, 200 ms initial, 30 s cap", () => {
    const p = new RetryPolicy();
    expect([p.maxAttempts, p.initialDelayMs, p.maxDelayMs]).toEqual([5, 200, 30_000]);
  });

  it("validates options", () => {
    expect(() => new RetryPolicy({ maxAttempts: 0 })).toThrow(RangeError);
    expect(() => new RetryPolicy({ maxAttempts: 1.5 })).toThrow(RangeError);
    expect(() => new RetryPolicy({ initialDelayMs: 0 })).toThrow(RangeError);
    expect(() => new RetryPolicy({ initialDelayMs: 100, maxDelayMs: 50 })).toThrow(RangeError);
  });
});

describe("full-jitter exponential backoff", () => {
  it("ceiling doubles from 200 ms and caps at 30 s (random just below 1)", () => {
    const p = new RetryPolicy({ random: () => 0.999999999 });
    const ceilings = [0, 1, 2, 3, 4, 5, 6, 7, 8, 20].map((n) => p.backoffMs(n));
    expect(ceilings).toEqual([199, 399, 799, 1599, 3199, 6399, 12799, 25599, 29999, 29999]);
  });

  it("is a uniform fraction of the ceiling", () => {
    const p = new RetryPolicy({ random: () => 0.5 });
    expect(p.backoffMs(0)).toBe(100);
    expect(p.backoffMs(3)).toBe(800);
  });

  it("can be zero (full jitter lower bound)", () => {
    expect(new RetryPolicy({ random: () => 0 }).backoffMs(4)).toBe(0);
  });

  it("clamps out-of-range random values", () => {
    expect(new RetryPolicy({ random: () => 1 }).backoffMs(0)).toBe(199);
    expect(new RetryPolicy({ random: () => -3 }).backoffMs(0)).toBe(0);
  });
});

describe("decide", () => {
  const p = new RetryPolicy({ random: () => 0.5 });

  it("retries retryable reads", () => {
    expect(p.decide({ problem: retryable, attempt: 1, isWrite: false })).toEqual({ retry: true, delayMs: 100 });
    expect(p.decide({ problem: retryable, attempt: 2, isWrite: false })).toEqual({ retry: true, delayMs: 200 });
  });

  it("never retries non-retryable codes", () => {
    expect(p.decide({ problem: notRetryable, attempt: 1, isWrite: false })).toEqual({ retry: false, reason: "not_retryable" });
  });

  it("never retries writes without an idempotency key", () => {
    expect(p.decide({ problem: retryable, attempt: 1, isWrite: true })).toEqual({
      retry: false,
      reason: "write_without_idempotency_key",
    });
    expect(p.decide({ problem: retryable, attempt: 1, isWrite: true, idempotencyKey: "" })).toEqual({
      retry: false,
      reason: "write_without_idempotency_key",
    });
  });

  it("retries writes that carry an idempotency key", () => {
    expect(p.decide({ problem: retryable, attempt: 1, isWrite: true, idempotencyKey: "k" }).retry).toBe(true);
  });

  it("stops after maxAttempts", () => {
    expect(p.decide({ problem: retryable, attempt: 4, isWrite: false }).retry).toBe(true);
    expect(p.decide({ problem: retryable, attempt: 5, isWrite: false })).toEqual({ retry: false, reason: "attempts_exhausted" });
  });

  it("honours retry_after_ms as a minimum delay", () => {
    const problem = { ...retryable, retry_after_ms: 5000 };
    expect(p.decide({ problem, attempt: 1, isWrite: false })).toEqual({ retry: true, delayMs: 5000 });
  });

  it("uses backoff when it exceeds retry_after_ms", () => {
    const problem = { ...retryable, retry_after_ms: 10 };
    expect(p.decide({ problem, attempt: 3, isWrite: false })).toEqual({ retry: true, delayMs: 400 });
  });

  it("gives up when retry_after_ms exceeds the cap", () => {
    const problem = { ...retryable, retry_after_ms: 60_000 };
    expect(p.decide({ problem, attempt: 1, isWrite: false })).toEqual({ retry: false, reason: "retry_after_exceeds_cap" });
  });

  it("RetryPolicy.none never retries", () => {
    expect(RetryPolicy.none().decide({ problem: retryable, attempt: 1, isWrite: false }).retry).toBe(false);
  });
});

describe("parseRetryAfter", () => {
  it("parses delta-seconds", () => {
    expect(parseRetryAfter("3", 0)).toBe(3000);
    expect(parseRetryAfter(" 0 ", 0)).toBe(0);
  });
  it("parses HTTP-date relative to now", () => {
    const now = Date.parse("Wed, 18 Nov 2026 10:00:00 GMT");
    expect(parseRetryAfter("Wed, 18 Nov 2026 10:00:05 GMT", now)).toBe(5000);
    expect(parseRetryAfter("Wed, 18 Nov 2026 09:00:00 GMT", now)).toBe(0);
  });
  it("ignores garbage", () => {
    expect(parseRetryAfter(null, 0)).toBeUndefined();
    expect(parseRetryAfter("soon", 0)).toBeUndefined();
    expect(parseRetryAfter("-1", 0)).toBeUndefined();
  });
});

describe("systemClock.sleep", () => {
  it("resolves after the delay", async () => {
    await expect(systemClock.sleep(1)).resolves.toBeUndefined();
  });
  it("rejects with the abort reason", async () => {
    const c = new AbortController();
    const p = systemClock.sleep(10_000, c.signal);
    c.abort(new Error("stop"));
    await expect(p).rejects.toThrow("stop");
  });
  it("rejects immediately when already aborted", async () => {
    await expect(systemClock.sleep(10, AbortSignal.abort(new Error("pre")))).rejects.toThrow("pre");
  });
});
