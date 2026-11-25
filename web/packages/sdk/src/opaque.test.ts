/// <reference types="node" />
// Node APIs only to load the committed .wasm file in this test; the SDK itself is browser-only.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import * as wasm from "../../opaque-wasm/pkg/cs_opaque_wasm.js";
import {
  DEFAULT_KSF_PARAMS,
  KSF_MAX,
  KSF_MIN,
  OpaqueClientError,
  WASM_INVALID_LOGIN,
  base64urlDecode,
  base64urlEncode,
  decodeKsfParams,
  serveOpaqueEngine,
  wasmOpaqueEngine,
  workerOpaqueEngine,
  type MessagePortLike,
  type OpaqueWasmFlow,
  type OpaqueWasmModule,
} from "./opaque";

const TENANT = "0190c1d2-0000-7000-8000-000000000001";

describe("base64url (rev 5 §2.1: no padding)", () => {
  it("round-trips every length and matches the RFC 4648 §10 vectors", () => {
    const vectors: [string, string][] = [["", ""], ["f", "Zg"], ["fo", "Zm8"], ["foo", "Zm9v"], ["foob", "Zm9vYg"], ["fooba", "Zm9vYmE"], ["foobar", "Zm9vYmFy"]];
    for (const [plain, enc] of vectors) {
      expect(base64urlEncode(new TextEncoder().encode(plain))).toBe(enc);
      expect(new TextDecoder().decode(base64urlDecode(enc))).toBe(plain);
    }
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    const enc = base64urlEncode(all);
    expect(enc).not.toMatch(/[+/=]/);
    expect(base64urlDecode(enc)).toEqual(all);
  });

  it("rejects padding, the standard alphabet, impossible lengths and non-canonical trailing bits", () => {
    for (const bad of ["Zg==", "a+b/", "Z", "Zh"]) {
      expect(() => base64urlDecode(bad), bad).toThrow(TypeError);
    }
  });
});

describe("decodeKsfParams", () => {
  it("accepts the contract shape", () => {
    expect(decodeKsfParams({ algorithm: "argon2id", m_kib: 65536, t: 3, p: 1 })).toEqual(DEFAULT_KSF_PARAMS);
  });

  it("rejects other algorithms and non-u32 values", () => {
    for (const bad of [null, [], { algorithm: "scrypt", m_kib: 1, t: 1, p: 1 }, { algorithm: "argon2id", m_kib: 0, t: 3, p: 1 }, { algorithm: "argon2id", m_kib: 1.5, t: 3, p: 1 }, { algorithm: "argon2id", m_kib: 2 ** 32, t: 3, p: 1 }, { algorithm: "argon2id", m_kib: 65536, t: "3", p: 1 }]) {
      expect(() => decodeKsfParams(bad)).toThrow(TypeError);
    }
  });

  it("enforces exactly the rev 7 bounds 65536 ≤ m_kib ≤ 262144, 3 ≤ t ≤ 10, 1 ≤ p ≤ 4", () => {
    const base = { algorithm: "argon2id", m_kib: 65536, t: 3, p: 1 } as const;
    expect(KSF_MIN).toEqual({ m_kib: 65536, t: 3, p: 1 });
    expect(KSF_MAX).toEqual({ m_kib: 262144, t: 10, p: 4 });
    for (const ok of [base, { ...base, m_kib: 262144 }, { ...base, t: 10 }, { ...base, p: 4 }, { ...base, m_kib: 131072, t: 5, p: 2 }]) {
      expect(decodeKsfParams(ok)).toEqual(ok);
    }
    for (const bad of [{ m_kib: 65535 }, { m_kib: 262145 }, { t: 2 }, { t: 11 }, { p: 5 }, { m_kib: 0xffff_ffff }]) {
      expect(() => decodeKsfParams({ ...base, ...bad }), JSON.stringify(bad)).toThrow(TypeError);
    }
  });
});

describe("wasmOpaqueEngine with the real opaque-ke WASM build", () => {
  beforeAll(() => {
    wasm.initSync({ module: readFileSync(join(import.meta.dirname, "../../opaque-wasm/pkg/cs_opaque_wasm_bg.wasm")) });
  });

  it("produces RFC 9807 ristretto255 message sizes", async () => {
    const engine = wasmOpaqueEngine(wasm);
    const login = await engine.start("login", new TextEncoder().encode("pw"), TENANT, "Alice");
    // KE1 = blinded element (32) + client nonce (32) + client ephemeral public key (32).
    expect(login.request.length).toBe(96);
    login.abandon();
    const reg = await engine.start("registration", new TextEncoder().encode("pw"), TENANT, "Alice");
    expect(reg.request.length).toBe(32);
    reg.abandon();
    reg.abandon(); // idempotent
  });

  it("normalizes logins with the shared cs-identity-wire function", async () => {
    const engine = wasmOpaqueEngine(wasm);
    expect(await engine.normalizeLogin("Alice@Example.COM")).toBe("alice@example.com");
    expect(await engine.normalizeLogin("ＡＬＩＣＥ")).toBe("alice");
    await expect(engine.normalizeLogin("al ice")).rejects.toMatchObject({ reason: "invalid_input" });
  });

  it("refuses a non-canonical tenant or invalid login before any crypto", async () => {
    const engine = wasmOpaqueEngine(wasm);
    await expect(engine.start("login", new Uint8Array([1]), TENANT.toUpperCase(), "a")).rejects.toMatchObject({ reason: "invalid_input" });
    await expect(engine.start("login", new Uint8Array([1]), TENANT, "")).rejects.toMatchObject({ reason: "invalid_input" });
  });

  it("refuses a malformed server response and KSF parameters below the registration minimum", async () => {
    const engine = wasmOpaqueEngine(wasm);
    const login = await engine.start("login", new Uint8Array([1]), TENANT, "a");
    await expect(login.finish(new Uint8Array([1]), new Uint8Array(3), DEFAULT_KSF_PARAMS)).rejects.toMatchObject({ reason: "invalid_input" });
    const reg = await engine.start("registration", new Uint8Array([1]), TENANT, "a");
    await expect(reg.finish(new Uint8Array([1]), new Uint8Array(64), { ...DEFAULT_KSF_PARAMS, t: 2 })).rejects.toMatchObject({ reason: "invalid_input" });
  });

  it("refuses KSF parameters above the rev 7 bounds at login and registration before Argon2id runs", async () => {
    const engine = wasmOpaqueEngine(wasm);
    // 4 TiB of memory: refused at once, never attempted.
    const huge = { ...DEFAULT_KSF_PARAMS, m_kib: 0xffff_ffff };
    const login = await engine.start("login", new Uint8Array([1]), TENANT, "a");
    await expect(login.finish(new Uint8Array([1]), new Uint8Array(320), huge)).rejects.toMatchObject({ reason: "invalid_input" });
    const reg = await engine.start("registration", new Uint8Array([1]), TENANT, "a");
    await expect(reg.finish(new Uint8Array([1]), new Uint8Array(64), { ...DEFAULT_KSF_PARAMS, p: 5 })).rejects.toMatchObject({ reason: "invalid_input" });
  });
});

function fakeModule(finish: () => Uint8Array): OpaqueWasmModule & { freed: number } {
  const m = {
    freed: 0,
    loginStart: (): OpaqueWasmFlow => ({ request: new Uint8Array([1, 2]), finish, free: () => { m.freed++; } }),
    registrationStart: (): OpaqueWasmFlow => ({ request: new Uint8Array([3]), finish, free: () => { m.freed++; } }),
    normalizeLogin: (s: string) => s.toLowerCase(),
  };
  return m;
}

describe("wasmOpaqueEngine error mapping", () => {
  it("maps the module's invalid_login to OpaqueClientError('invalid_login') and finishes once", async () => {
    const mod = fakeModule(() => {
      throw new Error(WASM_INVALID_LOGIN);
    });
    const flow = await wasmOpaqueEngine(mod).start("login", new Uint8Array([1]), TENANT, "a");
    const err: unknown = await flow.finish(new Uint8Array([1]), new Uint8Array([2]), DEFAULT_KSF_PARAMS).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OpaqueClientError);
    expect((err as OpaqueClientError).reason).toBe("invalid_login");
    await expect(flow.finish(new Uint8Array([1]), new Uint8Array([2]), DEFAULT_KSF_PARAMS)).rejects.toMatchObject({ reason: "invalid_input" });
    flow.abandon();
    expect(mod.freed).toBe(0); // finish consumed the WASM object
  });
});

/** Two connected in-memory ports (Worker ⇄ main thread), delivering asynchronously like postMessage. */
function portPair(): [MessagePortLike, MessagePortLike] {
  const listeners: [((ev: { data: unknown }) => void)[], ((ev: { data: unknown }) => void)[]] = [[], []];
  const mk = (self: 0 | 1): MessagePortLike => ({
    postMessage: (data) => {
      const copy = structuredClone(data);
      queueMicrotask(() => {
        for (const l of listeners[self === 0 ? 1 : 0]) l({ data: copy });
      });
    },
    addEventListener: (_t, l) => listeners[self].push(l),
  });
  return [mk(0), mk(1)];
}

describe("workerOpaqueEngine ⇄ serveOpaqueEngine", () => {
  it("runs a flow through the worker protocol and zeroes the worker's password copies", async () => {
    const seen: Uint8Array[] = [];
    const [main, worker] = portPair();
    serveOpaqueEngine(worker, {
      start: (_k, pw) => {
        seen.push(pw);
        return Promise.resolve({
          request: new Uint8Array([9]),
          finish: (pw2) => {
            seen.push(pw2);
            return Promise.resolve(new Uint8Array([7, 7]));
          },
          abandon: () => undefined,
        });
      },
      normalizeLogin: (s) => Promise.resolve(s.toLowerCase()),
    });
    const engine = workerOpaqueEngine(main);
    const pw = new Uint8Array([5, 5]);
    const flow = await engine.start("login", pw, TENANT, "A");
    expect(flow.request).toEqual(new Uint8Array([9]));
    expect(await flow.finish(pw, new Uint8Array([1]), DEFAULT_KSF_PARAMS)).toEqual(new Uint8Array([7, 7]));
    expect(await engine.normalizeLogin("ABC")).toBe("abc");
    await new Promise((r) => setTimeout(r, 0));
    expect(seen.every((b) => b.every((x) => x === 0))).toBe(true);
    expect(pw).toEqual(new Uint8Array([5, 5])); // the caller's copy is the caller's to zero
  });

  it("carries failures as reasons only", async () => {
    const [main, worker] = portPair();
    serveOpaqueEngine(worker, {
      start: () => Promise.reject(new OpaqueClientError("invalid_login")),
      normalizeLogin: () => Promise.reject(new Error("boom")),
    });
    const engine = workerOpaqueEngine(main);
    await expect(engine.start("login", new Uint8Array([1]), TENANT, "a")).rejects.toMatchObject({ reason: "invalid_login" });
    await expect(engine.normalizeLogin("a")).rejects.toMatchObject({ reason: "invalid_input" });
  });
});
