import { describe, expect, it } from "vitest";
import {
  ApiError,
  codeForNonProblemStatus,
  isProblemContentType,
  parseProblem,
  synthesizeProblem,
} from "./problem";

const valid = {
  type: "https://errors.example.test/v1/not_found",
  title: "Not found",
  status: 404,
  code: "not_found",
  detail: "No such folder.",
  instance: "/api/v2/resources/x",
  request_id: "req-1",
  retryable: false,
};

describe("parseProblem", () => {
  it("accepts a valid D.1 body", () => {
    const r = parseProblem(valid, { httpStatus: 404 });
    expect(r).toEqual({ ok: true, problem: valid });
  });

  it("keeps optional D.1 members and drops unknown members", () => {
    const r = parseProblem(
      {
        ...valid,
        code: "rate_limited",
        status: 429,
        retryable: true,
        retry_after_ms: 1500,
        consistency_token: "ct",
        errors: [{ pointer: "/name", code: "too_long", detail: "Too long" }, { pointer: "/x", code: "required" }],
        stack: "secret internals",
      },
      { httpStatus: 429 },
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.problem.retry_after_ms).toBe(1500);
    expect(r.problem.consistency_token).toBe("ct");
    expect(r.problem.errors).toEqual([
      { pointer: "/name", code: "too_long", detail: "Too long" },
      { pointer: "/x", code: "required" },
    ]);
    expect(r.problem).not.toHaveProperty("stack");
  });

  it("fills request_id and retry_after_ms from headers when the body lacks them", () => {
    const { request_id: _r, ...body } = { ...valid, code: "unavailable", status: 503, retryable: true };
    const r = parseProblem(body, { httpStatus: 503, requestId: "hdr-1", retryAfterMs: 2000 });
    expect(r.ok && r.problem.request_id).toBe("hdr-1");
    expect(r.ok && r.problem.retry_after_ms).toBe(2000);
  });

  it("prefers body request_id over header", () => {
    const r = parseProblem(valid, { requestId: "hdr" });
    expect(r.ok && r.problem.request_id).toBe("req-1");
  });

  it("accepts application codes mapped to a D.2 status, retryable from body", () => {
    const r = parseProblem({ ...valid, code: "app.photos.album_full", status: 409, retryable: true }, { httpStatus: 409 });
    expect(r.ok && r.problem.code).toBe("app.photos.album_full");
    expect(r.ok && r.problem.retryable).toBe(true);
  });

  it.each<[string, unknown]>([
    ["null", null],
    ["array", [valid]],
    ["string", "oops"],
    ["missing code", { ...valid, code: undefined }],
    ["unknown code", { ...valid, code: "teapot" }],
    ["missing title", { ...valid, title: undefined }],
    ["empty title", { ...valid, title: "" }],
    ["missing type", { ...valid, type: undefined }],
    ["string status", { ...valid, status: "404" }],
    ["non-integer status", { ...valid, status: 404.5 }],
    ["missing retryable", { ...valid, retryable: undefined }],
    ["retryable as string", { ...valid, retryable: "false" }],
    ["status disagrees with D.2", { ...valid, status: 400 }],
    ["retryable disagrees with D.2", { ...valid, retryable: true }],
    ["app code with non-D.2 status", { ...valid, code: "app.x.y", status: 418 }],
    ["detail not a string", { ...valid, detail: { stack: "x" } }],
    ["request_id not a string", { ...valid, request_id: 7 }],
    ["negative retry_after_ms", { ...valid, retry_after_ms: -1 }],
    ["fractional retry_after_ms", { ...valid, retry_after_ms: 1.5 }],
    ["errors not array", { ...valid, errors: {} }],
    ["field error without pointer", { ...valid, errors: [{ code: "x" }] }],
    ["field error not object", { ...valid, errors: ["x"] }],
    ["oversized detail", { ...valid, detail: "x".repeat(5000) }],
  ])("rejects malformed body: %s", (_name, body) => {
    expect(parseProblem(body, { httpStatus: 404 }).ok).toBe(false);
  });

  it("rejects a body whose status differs from the HTTP status", () => {
    expect(parseProblem(valid, { httpStatus: 500 }).ok).toBe(false);
  });
});

describe("synthesizeProblem", () => {
  it.each([
    ["internal", 500],
    ["unavailable", 503],
    ["timeout", 504],
  ] as const)("%s uses the D.2 status and retryability and has no detail", (code, status) => {
    const p = synthesizeProblem(code, { requestId: "r", instance: "/readyz", retryAfterMs: 10 });
    expect(p).toEqual({
      type: "about:blank",
      title: expect.any(String) as string,
      status,
      code,
      retryable: true,
      instance: "/readyz",
      request_id: "r",
      retry_after_ms: 10,
    });
    expect(p).not.toHaveProperty("detail");
  });

  it("maps non-problem statuses", () => {
    expect(codeForNonProblemStatus(502)).toBe("unavailable");
    expect(codeForNonProblemStatus(503)).toBe("unavailable");
    expect(codeForNonProblemStatus(504)).toBe("unavailable");
    expect(codeForNonProblemStatus(500)).toBe("internal");
    expect(codeForNonProblemStatus(404)).toBe("internal");
  });
});

describe("helpers", () => {
  it("detects problem+json content type", () => {
    expect(isProblemContentType("application/problem+json")).toBe(true);
    expect(isProblemContentType("Application/Problem+JSON; charset=utf-8")).toBe(true);
    expect(isProblemContentType("application/json")).toBe(false);
    expect(isProblemContentType(null)).toBe(false);
  });

  it("ApiError message has code and request id only", () => {
    const e = new ApiError({ ...synthesizeProblem("internal"), request_id: "r9" }, { synthesized: true, attempts: 1 });
    expect(e.message).toBe("internal (request r9)");
    expect(e.name).toBe("ApiError");
  });
});
