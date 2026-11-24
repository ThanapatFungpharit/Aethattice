import { describe, expect, it } from "vitest";
import {
  CORE_ERROR_CODES,
  D2_STATUSES,
  ERROR_CODE_TABLE,
  isAppErrorCode,
  isCoreErrorCode,
  isErrorCode,
  parseAppErrorCode,
} from "./errors";

// Table D.2 (spec v2.4.2, including erratum C12), transcribed independently of the implementation.
const D2: [string, number, boolean][] = [
  ["invalid_request", 400, false],
  ["unauthenticated", 401, false],
  ["permission_denied", 403, false],
  ["not_found", 404, false],
  ["method_not_allowed", 405, false],
  ["conflict", 409, false],
  ["resource_trashed", 409, false],
  ["cursor_expired", 410, false],
  ["precondition_failed", 412, false],
  ["payload_too_large", 413, false],
  ["unsupported_media_type", 415, false],
  ["idempotency_mismatch", 422, false],
  ["locked", 423, false],
  ["client_upgrade_required", 426, false],
  ["rate_limited", 429, true],
  ["quota_exceeded", 507, false],
  ["internal", 500, true],
  ["dependency_unavailable", 503, true],
  ["unavailable", 503, true],
  ["timeout", 504, true],
  ["outcome_unknown", 504, true],
];

describe("ErrorCode table (D.2)", () => {
  it("has exactly the D.2 codes in order", () => {
    expect([...CORE_ERROR_CODES]).toEqual(D2.map(([c]) => c));
  });

  it.each(D2)("%s -> %i retryable=%s", (code, status, retryable) => {
    expect(isCoreErrorCode(code)).toBe(true);
    expect(ERROR_CODE_TABLE[code as keyof typeof ERROR_CODE_TABLE]).toEqual({ status, retryable });
  });

  it("includes the erratum C12 codes, never retryable", () => {
    expect(ERROR_CODE_TABLE.cursor_expired).toEqual({ status: 410, retryable: false });
    expect(ERROR_CODE_TABLE.client_upgrade_required).toEqual({ status: 426, retryable: false });
  });

  it("is frozen", () => {
    expect(Object.isFrozen(ERROR_CODE_TABLE)).toBe(true);
  });

  it("collects the D.2 status set", () => {
    expect([...D2_STATUSES].sort()).toEqual([400, 401, 403, 404, 405, 409, 410, 412, 413, 415, 422, 423, 426, 429, 500, 503, 504, 507]);
  });

  it("rejects non-codes", () => {
    for (const v of ["NOT_FOUND", "notfound", "", "app", 404, null, undefined, {}]) {
      expect(isErrorCode(v)).toBe(false);
    }
  });
});

describe("application codes app.<id>.<code> (D.3)", () => {
  it.each(["app.photos.album_full", "app.com.example.photos.album_full", "app.my-app.x"])("accepts %s", (c) => {
    expect(isAppErrorCode(c)).toBe(true);
    expect(isErrorCode(c)).toBe(true);
    expect(isCoreErrorCode(c)).toBe(false);
  });

  it.each(["app.photos", "app..x", "app.Photos.x", "app.photos.Album", "app.photos.", "apps.photos.x", "app.-x.y", "app.photos.1x"])(
    "rejects %s",
    (c) => {
      expect(isAppErrorCode(c)).toBe(false);
    },
  );

  it("rejects over-long codes", () => {
    expect(isAppErrorCode(`app.${"a".repeat(250)}.x`)).toBe(false);
  });

  it("splits id and local code on the last dot", () => {
    expect(parseAppErrorCode("app.com.example.photos.album_full")).toEqual({
      applicationId: "com.example.photos",
      code: "album_full",
    });
    expect(parseAppErrorCode("app.Bad.x")).toBeUndefined();
  });
});
