import { describe, expect, it, vi } from "vitest";
import { ApiClient, type AuthHook } from "./client";
import { ApiError, ResponseDecodeError, StepUpRequired, isResponseDecodeError, isStepUpRequired } from "./problem";
import { RetryPolicy, type Clock } from "./retry";

interface Call {
  url: string;
  method: string;
  headers: Headers;
  body: string | null;
}

type Responder = (call: Call, signal: AbortSignal) => Response | Promise<Response>;

function fakeFetch(...responders: Responder[]): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fn = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const call: Call = {
      url: input instanceof URL ? input.href : typeof input === "string" ? input : input.url,
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: typeof init?.body === "string" ? init.body : null,
    };
    calls.push(call);
    const r = responders[Math.min(calls.length - 1, responders.length - 1)];
    if (!r) throw new Error("no responder");
    return Promise.resolve(r(call, init?.signal ?? new AbortController().signal));
  };
  return { fetch: fn, calls };
}

function fakeClock(): Clock & { sleeps: number[] } {
  const sleeps: number[] = [];
  return {
    sleeps,
    now: () => 0,
    sleep: (ms, signal) => {
      sleeps.push(ms);
      signal?.throwIfAborted();
      return Promise.resolve();
    },
  };
}

function problem(code: string, status: number, retryable: boolean, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}): Response {
  return new Response(
    JSON.stringify({ type: `https://errors.example.test/v1/${code}`, title: code, status, code, retryable, request_id: "srv-req", ...extra }),
    { status, headers: { "Content-Type": "application/problem+json", "X-Request-Id": "srv-req", ...headers } },
  );
}

const ok = (body: unknown = { ok: true }, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json", "X-Request-Id": "req-ok", ...headers } });

function client(fetch: typeof globalThis.fetch, extra: Partial<ConstructorParameters<typeof ApiClient>[0]> = {}) {
  const clock = fakeClock();
  const c = new ApiClient({
    baseUrl: "https://cloud.example.test/",
    fetch,
    clock,
    retryPolicy: new RetryPolicy({ random: () => 0.5 }),
    idempotencyKeyFactory: () => "key-1",
    ...extra,
  });
  return { c, clock };
}

async function rejection(p: Promise<unknown>): Promise<ApiError> {
  try {
    await p;
  } catch (e) {
    if (e instanceof ApiError) return e;
    throw e;
  }
  throw new Error("expected rejection");
}

describe("ApiClient construction and URLs", () => {
  it("requires an absolute base URL", () => {
    expect(() => new ApiClient({ baseUrl: "/api" })).toThrow(TypeError);
    expect(() => new ApiClient({ baseUrl: "https://x.test/?q=1" })).toThrow(TypeError);
  });

  it("joins base and path and encodes query", async () => {
    const { fetch, calls } = fakeFetch(() => ok());
    const { c } = client(fetch, { baseUrl: "https://cloud.example.test/prefix/" });
    await c.get("/readyz", { query: { a: "b c", n: 1, skip: undefined } });
    expect(calls[0]?.url).toBe("https://cloud.example.test/prefix/readyz?a=b+c&n=1");
  });

  it.each(["readyz", "//evil.test/x", "https://evil.test/x", "/\\evil"])("refuses path %s", async (path) => {
    const { fetch } = fakeFetch(() => ok());
    await expect(client(fetch).c.get(path)).rejects.toThrow(TypeError);
  });
});

describe("ApiClient success", () => {
  it("returns data, status and X-Request-Id", async () => {
    const { fetch, calls } = fakeFetch(() => ok({ x: 1 }));
    const r = await client(fetch).c.get<{ x: number }>("/readyz");
    expect(r).toMatchObject({ status: 200, data: { x: 1 }, requestId: "req-ok", attempts: 1 });
    expect(calls[0]?.headers.get("Accept")).toContain("application/problem+json");
    expect(calls[0]?.headers.has("Idempotency-Key")).toBe(false);
  });

  it("serializes JSON bodies", async () => {
    const { fetch, calls } = fakeFetch(() => ok());
    await client(fetch).c.post("/api/v2/x", { body: { name: "a" } });
    expect(calls[0]?.body).toBe('{"name":"a"}');
    expect(calls[0]?.headers.get("Content-Type")).toBe("application/json");
  });

  it("returns undefined for 204 and text for non-JSON", async () => {
    const { fetch } = fakeFetch(
      () => new Response(null, { status: 204 }),
      () => new Response("pong", { status: 200, headers: { "Content-Type": "text/plain" } }),
    );
    const { c } = client(fetch);
    expect((await c.delete("/api/v2/x")).data).toBeUndefined();
    expect((await c.get("/healthz")).data).toBe("pong");
  });

  it("applies decode", async () => {
    const { fetch } = fakeFetch(() => ok({ n: 2 }));
    const r = await client(fetch).c.get("/x", { decode: (b) => (b as { n: number }).n * 2 });
    expect(r.data).toBe(4);
  });

  it("fails as internal when decode throws", async () => {
    const { fetch } = fakeFetch(() => ok({ n: "no" }));
    const e = await rejection(client(fetch).c.get("/x", { retry: false, decode: () => { throw new Error("bad shape"); } }));
    expect(e.problem.code).toBe("internal");
    expect(e.synthesized).toBe(true);
    expect(JSON.stringify(e.problem)).not.toContain("bad shape");
  });

  it("fails as internal on malformed success JSON", async () => {
    const { fetch } = fakeFetch(() => new Response("{nope", { status: 200, headers: { "Content-Type": "application/json" } }));
    const e = await rejection(client(fetch).c.get("/x", { retry: false }));
    expect(e.problem.code).toBe("internal");
  });

  describe("undecodable 2xx (TL ruling 2026-11-26: the request succeeded, never retried or refreshed)", () => {
    const refresh = vi.fn(() => Promise.resolve(true));
    const auth = { authorization: () => "Bearer t", refresh };

    it("a write whose 2xx body does not decode is sent exactly once and surfaces ResponseDecodeError", async () => {
      const { fetch, calls } = fakeFetch(() => ok({ n: "no" }));
      const e = await rejection(client(fetch, { auth }).c.post("/x", { body: {}, decode: () => { throw new Error("bad shape"); } }));
      expect(calls).toHaveLength(1);
      expect(refresh).not.toHaveBeenCalled();
      expect(e).toBeInstanceOf(ResponseDecodeError);
      expect(isResponseDecodeError(e)).toBe(true);
      expect(e.problem).toMatchObject({ code: "internal", retryable: false, request_id: "req-ok" });
      if (isResponseDecodeError(e)) expect(e.requestId).toBe("req-ok");
      expect(e.httpStatus).toBe(200);
      expect(e.attempts).toBe(1);
    });

    it("a read whose 2xx body is not JSON is sent exactly once and surfaces ResponseDecodeError", async () => {
      const { fetch, calls } = fakeFetch(() => new Response("{nope", { status: 200, headers: { "Content-Type": "application/json", "X-Request-Id": "r2" } }));
      const e = await rejection(client(fetch, { auth }).c.get("/x"));
      expect(calls).toHaveLength(1);
      expect(refresh).not.toHaveBeenCalled();
      expect(e).toBeInstanceOf(ResponseDecodeError);
      expect(e.problem).toMatchObject({ code: "internal", retryable: false, request_id: "r2" });
    });
  });

  it("sends Authorization from the auth hook", async () => {
    const { fetch, calls } = fakeFetch(() => ok());
    await client(fetch, { auth: { authorization: () => "Bearer t", refresh: () => Promise.resolve(false) } }).c.get("/x");
    expect(calls[0]?.headers.get("Authorization")).toBe("Bearer t");
  });
});

describe("ApiClient error model", () => {
  it("surfaces a valid problem unchanged", async () => {
    const { fetch } = fakeFetch(() => problem("not_found", 404, false, { detail: "No such item." }));
    const e = await rejection(client(fetch).c.get("/api/v2/x"));
    expect(e.synthesized).toBe(false);
    expect(e.httpStatus).toBe(404);
    expect(e.problem).toMatchObject({ code: "not_found", status: 404, detail: "No such item.", request_id: "srv-req" });
  });

  it("synthesizes internal for a malformed problem body and never leaks it", async () => {
    const { fetch } = fakeFetch(
      () =>
        new Response(JSON.stringify({ code: "nope", stack: "at db.rs:42 password=hunter2" }), {
          status: 500,
          headers: { "Content-Type": "application/problem+json", "X-Request-Id": "r1" },
        }),
    );
    const e = await rejection(client(fetch).c.get("/x", { retry: false }));
    expect(e.problem).toMatchObject({ code: "internal", status: 500, retryable: true, request_id: "r1" });
    expect(e.synthesized).toBe(true);
    expect(JSON.stringify(e.problem) + e.message).not.toMatch(/hunter2|db\.rs/);
  });

  it("synthesizes for invalid JSON in a problem+json response", async () => {
    const { fetch } = fakeFetch(() => new Response("{{{", { status: 400, headers: { "Content-Type": "application/problem+json" } }));
    const e = await rejection(client(fetch).c.get("/x", { retry: false }));
    expect(e.problem.code).toBe("internal");
    expect(e.httpStatus).toBe(400);
  });

  it("synthesizes for non-JSON error bodies (HTML proxy page) without leaking them", async () => {
    const { fetch } = fakeFetch(() => new Response("<html>nginx secret-upstream:9000</html>", { status: 502, headers: { "Content-Type": "text/html" } }));
    const e = await rejection(client(fetch).c.get("/x", { retry: false }));
    expect(e.problem.code).toBe("unavailable");
    expect(e.problem).not.toHaveProperty("detail");
    expect(JSON.stringify(e.problem) + e.message).not.toContain("secret-upstream");
  });

  it("does not accept application/json error bodies as problems", async () => {
    const { fetch } = fakeFetch(() => new Response(JSON.stringify({ code: "not_found", status: 404 }), { status: 404, headers: { "Content-Type": "application/json" } }));
    const e = await rejection(client(fetch).c.get("/x", { retry: false }));
    expect(e.problem.code).toBe("internal");
  });

  it("maps network failure to unavailable without exposing the exception", async () => {
    const fetch = vi.fn().mockRejectedValue(new TypeError("getaddrinfo ENOTFOUND db-internal.local"));
    const e = await rejection(client(fetch as unknown as typeof globalThis.fetch).c.get("/readyz", { retry: false }));
    expect(e.problem).toMatchObject({ code: "unavailable", status: 503, retryable: true, instance: "/readyz" });
    expect(e.httpStatus).toBeUndefined();
    expect(JSON.stringify(e.problem) + e.message).not.toContain("db-internal");
  });
});

describe("ApiClient abort and timeout", () => {
  const hang: Responder = (_c, signal) =>
    new Promise<Response>((_res, rej) => {
      if (signal.aborted) rej(new DOMException("aborted", "AbortError"));
      signal.addEventListener("abort", () => { rej(new DOMException("aborted", "AbortError")); });
    });

  it("maps a per-attempt timeout to the timeout problem", async () => {
    const { fetch } = fakeFetch(hang);
    const e = await rejection(client(fetch).c.get("/slow", { timeoutMs: 5, retry: false }));
    expect(e.problem).toMatchObject({ code: "timeout", status: 504, retryable: true });
  });

  it("retries after a timeout and then succeeds", async () => {
    const { fetch, calls } = fakeFetch(hang, () => ok());
    const { c, clock } = client(fetch);
    const r = await c.get("/slow", { timeoutMs: 5 });
    expect(r.attempts).toBe(2);
    expect(calls).toHaveLength(2);
    expect(clock.sleeps).toEqual([100]);
  });

  it("rejects with the caller's abort reason and does not retry", async () => {
    const { fetch, calls } = fakeFetch(hang);
    const ctl = new AbortController();
    const p = client(fetch).c.get("/slow", { signal: ctl.signal });
    const reason = new Error("user cancelled");
    await vi.waitFor(() => {
      expect(calls).toHaveLength(1);
    });
    ctl.abort(reason);
    await expect(p).rejects.toBe(reason);
    expect(calls).toHaveLength(1);
  });

  it("rejects immediately when the signal is already aborted", async () => {
    const { fetch, calls } = fakeFetch(() => ok());
    const reason = new Error("pre");
    await expect(client(fetch).c.get("/x", { signal: AbortSignal.abort(reason) })).rejects.toBe(reason);
    expect(calls).toHaveLength(0);
  });

  it("aborting during backoff stops retrying", async () => {
    const { fetch, calls } = fakeFetch(() => problem("unavailable", 503, true));
    const ctl = new AbortController();
    const reason = new Error("stop");
    const clock: Clock = {
      now: () => 0,
      sleep: (_ms, signal) => {
        ctl.abort(reason);
        signal?.throwIfAborted();
        return Promise.resolve();
      },
    };
    await expect(client(fetch, { clock }).c.get("/x", { signal: ctl.signal })).rejects.toBe(reason);
    expect(calls).toHaveLength(1);
  });
});

describe("ApiClient retries (D.3)", () => {
  it("retries retryable errors with jittered backoff until success", async () => {
    const { fetch, calls } = fakeFetch(() => problem("unavailable", 503, true), () => problem("internal", 500, true), () => ok());
    const { c, clock } = client(fetch);
    const r = await c.get("/x");
    expect(r.attempts).toBe(3);
    expect(calls).toHaveLength(3);
    expect(clock.sleeps).toEqual([100, 200]);
  });

  it("gives up after maxAttempts and reports the last problem", async () => {
    const { fetch, calls } = fakeFetch(() => problem("unavailable", 503, true));
    const { c, clock } = client(fetch);
    const e = await rejection(c.get("/x"));
    expect(calls).toHaveLength(5);
    expect(clock.sleeps).toEqual([100, 200, 400, 800]);
    expect(e.attempts).toBe(5);
    expect(e.problem.code).toBe("unavailable");
  });

  it.each([
    ["invalid_request", 400],
    ["permission_denied", 403],
    ["not_found", 404],
    ["conflict", 409],
    ["precondition_failed", 412],
    ["idempotency_mismatch", 422],
    ["quota_exceeded", 507],
  ])("never retries non-retryable %s", async (code, status) => {
    const { fetch, calls } = fakeFetch(() => problem(code, status, false));
    const e = await rejection(client(fetch).c.get("/x"));
    expect(calls).toHaveLength(1);
    expect(e.problem.code).toBe(code);
  });

  it("never retries a non-retryable application code", async () => {
    const { fetch, calls } = fakeFetch(() => problem("app.photos.album_full", 409, false));
    await rejection(client(fetch).c.get("/x"));
    expect(calls).toHaveLength(1);
  });

  it("honours retry_after_ms from the body", async () => {
    const { fetch } = fakeFetch(() => problem("rate_limited", 429, true, { retry_after_ms: 2500 }), () => ok());
    const { c, clock } = client(fetch);
    await c.get("/x");
    expect(clock.sleeps).toEqual([2500]);
  });

  it("honours the Retry-After header on a problem", async () => {
    const { fetch } = fakeFetch(() => problem("rate_limited", 429, true, {}, { "Retry-After": "3" }), () => ok());
    const { c, clock } = client(fetch);
    await c.get("/x");
    expect(clock.sleeps).toEqual([3000]);
  });

  it("honours Retry-After on a non-problem 503", async () => {
    const { fetch } = fakeFetch(() => new Response("busy", { status: 503, headers: { "Retry-After": "2" } }), () => ok());
    const { c, clock } = client(fetch);
    await c.get("/x");
    expect(clock.sleeps).toEqual([2000]);
  });

  it("stops when Retry-After exceeds the 30 s cap", async () => {
    const { fetch, calls } = fakeFetch(() => problem("unavailable", 503, true, { retry_after_ms: 120_000 }));
    const e = await rejection(client(fetch).c.get("/x"));
    expect(calls).toHaveLength(1);
    expect(e.problem.retry_after_ms).toBe(120_000);
  });

  it("retries writes with the same Idempotency-Key", async () => {
    const keys = ["first", "second"];
    const { fetch, calls } = fakeFetch(() => problem("outcome_unknown", 504, true), () => ok());
    const { c } = client(fetch, { idempotencyKeyFactory: () => keys.shift() ?? "x" });
    await c.post("/api/v2/x", { body: {} });
    expect(calls.map((x) => x.headers.get("Idempotency-Key"))).toEqual(["first", "first"]);
  });

  it("uses a caller-supplied key", async () => {
    const { fetch, calls } = fakeFetch(() => ok());
    await client(fetch).c.put("/api/v2/x", { idempotencyKey: "mine" });
    expect(calls[0]?.headers.get("Idempotency-Key")).toBe("mine");
  });

  it("rejects an invalid caller-supplied key", async () => {
    const { fetch } = fakeFetch(() => ok());
    await expect(client(fetch).c.post("/x", { idempotencyKey: "has space" })).rejects.toThrow(TypeError);
  });

  it("generates a fresh key per call by default", async () => {
    const { fetch, calls } = fakeFetch(() => ok());
    const c = new ApiClient({ baseUrl: "https://x.test", fetch });
    await c.post("/a");
    await c.post("/a");
    const [a, b] = calls.map((x) => x.headers.get("Idempotency-Key"));
    expect(a).toMatch(/^[0-9a-f-]{36}$/);
    expect(a).not.toBe(b);
  });

  it.each(["POST", "PUT", "PATCH", "DELETE"] as const)("never retries a %s without an idempotency key", async (method) => {
    const { fetch, calls } = fakeFetch(() => problem("unavailable", 503, true));
    const e = await rejection(client(fetch).c.request(method, "/api/v2/x", { idempotencyKey: null }));
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers.has("Idempotency-Key")).toBe(false);
    expect(e.problem.code).toBe("unavailable");
  });

  it("retry: false disables retries", async () => {
    const { fetch, calls } = fakeFetch(() => problem("unavailable", 503, true));
    await rejection(client(fetch).c.get("/x", { retry: false }));
    expect(calls).toHaveLength(1);
  });
});

describe("ApiClient unauthenticated hook", () => {
  const unauth = (): Response => problem("unauthenticated", 401, false);

  it("refreshes once and retries once", async () => {
    const refresh = vi.fn().mockResolvedValue(true);
    const auth: AuthHook = { refresh };
    const { fetch, calls } = fakeFetch(unauth, () => ok());
    const r = await client(fetch, { auth }).c.get("/x");
    expect(r.status).toBe(200);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(2);
  });

  it("does not refresh twice when the retry is also unauthenticated", async () => {
    const refresh = vi.fn().mockResolvedValue(true);
    const { fetch, calls } = fakeFetch(unauth);
    const e = await rejection(client(fetch, { auth: { refresh } }).c.get("/x"));
    expect(e.problem.code).toBe("unauthenticated");
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(2);
  });

  it("fails without retry when refresh fails", async () => {
    const { fetch, calls } = fakeFetch(unauth);
    await rejection(client(fetch, { auth: { refresh: () => Promise.resolve(false) } }).c.get("/x"));
    expect(calls).toHaveLength(1);
  });

  it("without a hook (M0 default) unauthenticated is surfaced", async () => {
    const { fetch, calls } = fakeFetch(unauth);
    await rejection(client(fetch).c.get("/x"));
    expect(calls).toHaveLength(1);
  });

  it("retries a write after refresh only with its idempotency key", async () => {
    const refresh = vi.fn().mockResolvedValue(true);
    const { fetch, calls } = fakeFetch(unauth, () => ok());
    await client(fetch, { auth: { refresh } }).c.post("/x");
    expect(calls.map((c) => c.headers.get("Idempotency-Key"))).toEqual(["key-1", "key-1"]);

    const second = fakeFetch(unauth, () => ok());
    await rejection(client(second.fetch, { auth: { refresh } }).c.post("/x", { idempotencyKey: null }));
    expect(second.calls).toHaveLength(1);
  });
});

describe("ApiClient step-up (M0 contract rev 5, M1 §2.3 [R2])", () => {
  const stepUp = (): Response =>
    problem("unauthenticated", 401, false, {
      errors: [{ pointer: "", code: "step_up_required", detail: "Confirm it is you" }],
    });

  it("does not refresh and surfaces StepUpRequired", async () => {
    const refresh = vi.fn().mockResolvedValue(true);
    const { fetch, calls } = fakeFetch(stepUp, () => ok());
    const e = await rejection(client(fetch, { auth: { refresh } }).c.post("/x"));
    expect(e).toBeInstanceOf(StepUpRequired);
    expect(isStepUpRequired(e)).toBe(true);
    expect(e.name).toBe("StepUpRequired");
    expect(e.problem.code).toBe("unauthenticated");
    expect(e.problem.errors?.[0]?.code).toBe("step_up_required");
    expect(refresh).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
  });

  it("finds step_up_required among other errors[] entries", async () => {
    const refresh = vi.fn().mockResolvedValue(true);
    const { fetch } = fakeFetch(() =>
      problem("unauthenticated", 401, false, {
        errors: [
          { pointer: "/x", code: "other" },
          { pointer: "", code: "step_up_required" },
        ],
      }),
    );
    const e = await rejection(client(fetch, { auth: { refresh } }).c.get("/x"));
    expect(e).toBeInstanceOf(StepUpRequired);
    expect(refresh).not.toHaveBeenCalled();
  });

  it("is surfaced without an auth hook too", async () => {
    const { fetch } = fakeFetch(stepUp);
    expect(await rejection(client(fetch).c.get("/x"))).toBeInstanceOf(StepUpRequired);
  });

  it("is surfaced when the retry after a refresh asks for step-up", async () => {
    const refresh = vi.fn().mockResolvedValue(true);
    const { fetch, calls } = fakeFetch(() => problem("unauthenticated", 401, false), stepUp);
    const e = await rejection(client(fetch, { auth: { refresh } }).c.get("/x"));
    expect(e).toBeInstanceOf(StepUpRequired);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(2);
  });

  it("other errors[] codes under unauthenticated still refresh (e.g. mfa_required is not step-up)", async () => {
    const refresh = vi.fn().mockResolvedValue(true);
    const { fetch, calls } = fakeFetch(
      () => problem("unauthenticated", 401, false, { errors: [{ pointer: "", code: "mfa_required" }] }),
      () => ok(),
    );
    const r = await client(fetch, { auth: { refresh } }).c.get("/x");
    expect(r.status).toBe(200);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(2);
  });

  it("step_up_required under a code other than unauthenticated is a plain ApiError", async () => {
    const { fetch } = fakeFetch(() =>
      problem("permission_denied", 403, false, { errors: [{ pointer: "", code: "step_up_required" }] }),
    );
    const e = await rejection(client(fetch).c.get("/x"));
    expect(e).not.toBeInstanceOf(StepUpRequired);
  });
});
