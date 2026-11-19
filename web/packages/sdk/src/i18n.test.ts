import { afterEach, describe, expect, it, vi } from "vitest";
import { CORE_ERROR_CODES } from "./errors";
import { EN_MESSAGES, getLocale, hasMessage, onLocaleChange, problemMessageKeys, registerMessages, setLocale, t } from "./i18n";
import { idempotencyKey, isValidIdempotencyKey } from "./idempotency";

afterEach(() => {
  setLocale("en");
});

describe("t()", () => {
  it("returns English messages", () => {
    expect(t("dialog.close")).toBe("Close");
  });

  it("interpolates params and leaves unknown placeholders", () => {
    expect(t("error.request_id", { id: "abc" })).toBe("Reference: abc");
    expect(t("error.request_id")).toBe("Reference: {id}");
    registerMessages("en", { "test.multi": "{a} and {b} and {a}" });
    expect(t("test.multi", { a: 1 })).toBe("1 and {b} and 1");
  });

  it("returns the key for missing messages", () => {
    expect(t("nope.missing")).toBe("nope.missing");
    expect(hasMessage("nope.missing")).toBe(false);
  });

  it("falls back region -> language -> English and notifies listeners", () => {
    registerMessages("th", { "dialog.close": "ปิด" });
    const listener = vi.fn();
    const off = onLocaleChange(listener);
    setLocale("th-TH");
    expect(getLocale()).toBe("th-th");
    expect(listener).toHaveBeenCalledWith("th-th");
    expect(t("dialog.close")).toBe("ปิด");
    expect(t("spinner.loading")).toBe(EN_MESSAGES["spinner.loading"]);
    off();
    setLocale("en");
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("has a title and description for every D.2 code", () => {
    for (const code of CORE_ERROR_CODES) {
      const k = problemMessageKeys(code);
      expect(hasMessage(k.title), code).toBe(true);
      expect(hasMessage(k.description), code).toBe(true);
    }
  });

  it("uses generic keys for application codes", () => {
    expect(problemMessageKeys("app.photos.full")).toEqual({ title: "error.app.title", description: "error.app.description" });
  });
});

describe("idempotencyKey", () => {
  it("is a v4 UUID from crypto.randomUUID and valid as a header", () => {
    const spy = vi.spyOn(globalThis.crypto, "randomUUID");
    const k = idempotencyKey();
    expect(spy).toHaveBeenCalled();
    expect(k).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(isValidIdempotencyKey(k)).toBe(true);
    expect(idempotencyKey()).not.toBe(k);
  });

  it("fails rather than falling back when no CSPRNG exists", () => {
    vi.stubGlobal("crypto", undefined);
    try {
      expect(() => idempotencyKey()).toThrow(/randomUUID/);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("validates the header format", () => {
    expect(isValidIdempotencyKey("")).toBe(false);
    expect(isValidIdempotencyKey("a b")).toBe(false);
    expect(isValidIdempotencyKey("x".repeat(256))).toBe(false);
    expect(isValidIdempotencyKey("ü")).toBe(false);
    expect(isValidIdempotencyKey("x".repeat(255))).toBe(true);
  });
});
