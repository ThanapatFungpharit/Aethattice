// OPAQUE client plumbing (contract M1 rev 5 §2.1). The cryptography is not here: it is opaque-ke compiled to
// WASM (web/packages/opaque-wasm, built on cs-identity-wire, the crate the server uses). This module only
// - encodes OPAQUE messages as base64url without padding,
// - validates `ksf_params`,
// - adapts the WASM module to an async {@link OpaqueEngine}, and
// - optionally moves the engine into a Web Worker, so Argon2id (64 MiB, t=3 by default) does not block the UI.

// ---- base64url (no padding) ----

const B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64U_INDEX: ReadonlyMap<string, number> = new Map(Array.from({ length: 64 }, (_, i) => [B64U.charAt(i), i]));

/** base64url without padding (RFC 4648 §5), as used by M0 text transports and rev 5 §2.1. */
export function base64urlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    const left = bytes.length - i;
    out += B64U[(n >> 18) & 63] ?? "";
    out += B64U[(n >> 12) & 63] ?? "";
    if (left > 1) out += B64U[(n >> 6) & 63] ?? "";
    if (left > 2) out += B64U[n & 63] ?? "";
  }
  return out;
}

/** Strict decoder: rejects padding, other alphabets, impossible lengths and non-zero trailing bits. */
export function base64urlDecode(text: string): Uint8Array {
  if (text.length % 4 === 1) throw new TypeError("invalid base64url length");
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < text.length; i += 4) {
    const chunk = text.slice(i, i + 4);
    let n = 0;
    for (let j = 0; j < 4; j++) {
      const c = chunk[j];
      const v = c === undefined ? 0 : B64U_INDEX.get(c);
      if (v === undefined) throw new TypeError("invalid base64url character");
      n = (n << 6) | v;
    }
    const bytes = chunk.length - 1;
    const trailing = chunk.length === 2 ? n & 0xffff : chunk.length === 3 ? n & 0xff : 0;
    if (trailing !== 0) throw new TypeError("non-canonical base64url");
    if (bytes >= 1) out[o++] = (n >> 16) & 0xff;
    if (bytes >= 2) out[o++] = (n >> 8) & 0xff;
    if (bytes >= 3) out[o++] = n & 0xff;
  }
  return out;
}

// ---- ksf_params ----

/** `ksf_params` (rev 5 §2.1). */
export interface KsfParams {
  readonly algorithm: "argon2id";
  readonly m_kib: number;
  readonly t: number;
  readonly p: number;
}

/** Contract default and registration minimum (rev 5 §2.1, spec §5.2). */
export const DEFAULT_KSF_PARAMS: KsfParams = Object.freeze({ algorithm: "argon2id", m_kib: 65536, t: 3, p: 1 });

const U32_MAX = 0xffff_ffff;

function isU32(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= U32_MAX;
}

/** Lower bounds (rev 7 §2.1), equal to the contract default. */
export const KSF_MIN: Readonly<Pick<KsfParams, "m_kib" | "t" | "p">> = Object.freeze({ m_kib: 65536, t: 3, p: 1 });
/** Upper bounds (rev 7 §2.1): a hostile or broken server cannot make the client exhaust memory or time. */
export const KSF_MAX: Readonly<Pick<KsfParams, "m_kib" | "t" | "p">> = Object.freeze({ m_kib: 262144, t: 10, p: 4 });

function inRange(v: number, k: "m_kib" | "t" | "p"): boolean {
  return v >= KSF_MIN[k] && v <= KSF_MAX[k];
}

/**
 * Validates `ksf_params` from the server, including the rev 7 bounds `65536 ≤ m_kib ≤ 262144`, `3 ≤ t ≤ 10`,
 * `1 ≤ p ≤ 4`. Every response carrying `ksf_params` is decoded with this before Argon2id runs, so parameters
 * outside the bounds never reach the KSF. Throws TypeError (the API client maps that to `internal`).
 */
export function decodeKsfParams(v: unknown): KsfParams {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new TypeError("ksf_params must be an object");
  const r = v as Record<string, unknown>;
  if (r.algorithm !== "argon2id") throw new TypeError("unsupported ksf algorithm");
  const { m_kib, t, p } = r;
  if (!isU32(m_kib) || !isU32(t) || !isU32(p)) throw new TypeError("ksf_params values must be positive u32");
  if (!inRange(m_kib, "m_kib") || !inRange(t, "t") || !inRange(p, "p")) throw new TypeError("ksf_params outside the contract bounds");
  return { algorithm: "argon2id", m_kib, t, p };
}

// ---- engine ----

/** Why the OPAQUE client stopped. Carries no secret material. */
export type OpaqueFailure =
  /** The server could not be authenticated: wrong password, unknown account, or a tampered response (RFC 9807). */
  | "invalid_login"
  /** Inputs the client refused (malformed tenant or login, bad message, KSF parameters below the minimum). */
  | "invalid_input";

export class OpaqueClientError extends Error {
  readonly reason: OpaqueFailure;
  constructor(reason: OpaqueFailure) {
    super(`opaque: ${reason}`);
    this.name = "OpaqueClientError";
    this.reason = reason;
  }
}

export type OpaqueFlowKind = "login" | "registration";

/** One OPAQUE exchange in progress. Its client state lives in WASM memory. */
export interface OpaqueFlow {
  /** `credential_request` or `registration_request`. */
  readonly request: Uint8Array;
  /** Runs Argon2id and returns `credential_finalization` or `registration_upload`. Consumes the flow. */
  finish(password: Uint8Array, response: Uint8Array, ksf: KsfParams): Promise<Uint8Array>;
  /** Releases the state of a flow that will not be finished. Safe to call after finish. */
  abandon(): void;
}

export interface OpaqueEngine {
  /** `tenant` is the canonical tenant UUID; `login` as typed (normalized inside, rev 5 §2.1). */
  start(kind: OpaqueFlowKind, password: Uint8Array, tenant: string, login: string): Promise<OpaqueFlow>;
  /** The shared login normalization; rejects with OpaqueClientError("invalid_input") for an invalid login. */
  normalizeLogin(login: string): Promise<string>;
}

/** Structural type of the wasm-bindgen output of `@cs/opaque-wasm` (after its init). */
export interface OpaqueWasmFlow {
  readonly request: Uint8Array;
  finish(password: Uint8Array, response: Uint8Array, m_kib: number, t: number, p: number): Uint8Array;
  free(): void;
}

export interface OpaqueWasmModule {
  loginStart(password: Uint8Array, tenant: string, login: string): OpaqueWasmFlow;
  registrationStart(password: Uint8Array, tenant: string, login: string): OpaqueWasmFlow;
  normalizeLogin(raw: string): string;
}

/** Error message the WASM module uses for RFC 9807 login failures. */
export const WASM_INVALID_LOGIN = "invalid_login";

function failureOf(e: unknown): OpaqueClientError {
  if (e instanceof OpaqueClientError) return e;
  return new OpaqueClientError(e instanceof Error && e.message === WASM_INVALID_LOGIN ? "invalid_login" : "invalid_input");
}

/** Runs the WASM module on the calling thread. */
export function wasmOpaqueEngine(mod: OpaqueWasmModule): OpaqueEngine {
  return {
    start(kind, password, tenant, login) {
      let flow: OpaqueWasmFlow;
      try {
        flow = kind === "login" ? mod.loginStart(password, tenant, login) : mod.registrationStart(password, tenant, login);
      } catch (e) {
        return Promise.reject(failureOf(e));
      }
      let done = false;
      return Promise.resolve({
        request: flow.request,
        finish(pw, response, ksf) {
          if (done) return Promise.reject(new OpaqueClientError("invalid_input"));
          done = true;
          try {
            // `finish` consumes the WASM object, so it must not be freed afterwards.
            return Promise.resolve(flow.finish(pw, response, ksf.m_kib, ksf.t, ksf.p));
          } catch (e) {
            return Promise.reject(failureOf(e));
          }
        },
        abandon() {
          if (done) return;
          done = true;
          flow.free();
        },
      });
    },
    normalizeLogin(login) {
      try {
        return Promise.resolve(mod.normalizeLogin(login));
      } catch (e) {
        return Promise.reject(failureOf(e));
      }
    },
  };
}

// ---- worker transport ----

export type OpaqueWorkerRequest =
  | { readonly id: number; readonly op: "start"; readonly kind: OpaqueFlowKind; readonly password: Uint8Array; readonly tenant: string; readonly login: string }
  | { readonly id: number; readonly op: "finish"; readonly flow: number; readonly password: Uint8Array; readonly response: Uint8Array; readonly ksf: KsfParams }
  | { readonly id: number; readonly op: "abandon"; readonly flow: number }
  | { readonly id: number; readonly op: "normalize"; readonly login: string };

export type OpaqueWorkerResponse =
  | { readonly id: number; readonly ok: true; readonly flow?: number; readonly bytes?: Uint8Array; readonly text?: string }
  | { readonly id: number; readonly ok: false; readonly reason: OpaqueFailure };

/** The part of a Worker / DedicatedWorkerGlobalScope / MessagePort both sides need. */
export interface MessagePortLike {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (ev: { data: unknown }) => void): void;
}

/** Worker side: serves `engine` on `port` (call from the worker entry with `self`). */
export function serveOpaqueEngine(port: MessagePortLike, engine: OpaqueEngine): void {
  const flows = new Map<number, OpaqueFlow>();
  let next = 1;
  const reply = (m: OpaqueWorkerResponse): void => {
    port.postMessage(m);
  };
  port.addEventListener("message", (ev) => {
    const m = ev.data as OpaqueWorkerRequest;
    const fail = (e: unknown): void => {
      reply({ id: m.id, ok: false, reason: failureOf(e).reason });
    };
    switch (m.op) {
      case "start":
        engine.start(m.kind, m.password, m.tenant, m.login).then((flow) => {
          const handle = next++;
          flows.set(handle, flow);
          reply({ id: m.id, ok: true, flow: handle, bytes: flow.request });
        }, fail).finally(() => m.password.fill(0));
        break;
      case "finish": {
        const flow = flows.get(m.flow);
        flows.delete(m.flow);
        if (!flow) {
          fail(new OpaqueClientError("invalid_input"));
          break;
        }
        flow.finish(m.password, m.response, m.ksf).then((bytes) => {
          reply({ id: m.id, ok: true, bytes });
        }, fail).finally(() => m.password.fill(0));
        break;
      }
      case "abandon":
        flows.get(m.flow)?.abandon();
        flows.delete(m.flow);
        reply({ id: m.id, ok: true });
        break;
      case "normalize":
        engine.normalizeLogin(m.login).then((text) => {
          reply({ id: m.id, ok: true, text });
        }, fail);
        break;
    }
  });
}

/** Main-thread side: an {@link OpaqueEngine} whose work runs behind `port` (a Worker running serveOpaqueEngine). */
export function workerOpaqueEngine(port: MessagePortLike): OpaqueEngine {
  let nextId = 1;
  const pending = new Map<number, { resolve: (r: OpaqueWorkerResponse & { ok: true }) => void; reject: (e: unknown) => void }>();
  port.addEventListener("message", (ev) => {
    const r = ev.data as OpaqueWorkerResponse;
    const p = pending.get(r.id);
    if (!p) return;
    pending.delete(r.id);
    if (r.ok) p.resolve(r);
    else p.reject(new OpaqueClientError(r.reason));
  });
  type Req = OpaqueWorkerRequest extends infer U ? (U extends { id: number } ? Omit<U, "id"> : never) : never;
  const call = (req: Req): Promise<OpaqueWorkerResponse & { ok: true }> =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      // Structured clone copies the password; the caller zeroes its own copy.
      port.postMessage({ ...req, id });
    });
  return {
    async start(kind, password, tenant, login) {
      const r = await call({ op: "start", kind, password: password.slice(), tenant, login });
      const flow = r.flow;
      if (flow === undefined || r.bytes === undefined) throw new OpaqueClientError("invalid_input");
      let done = false;
      return {
        request: r.bytes,
        async finish(pw, response, ksf) {
          if (done) throw new OpaqueClientError("invalid_input");
          done = true;
          const f = await call({ op: "finish", flow, password: pw.slice(), response, ksf });
          if (f.bytes === undefined) throw new OpaqueClientError("invalid_input");
          return f.bytes;
        },
        abandon() {
          if (done) return;
          done = true;
          void call({ op: "abandon", flow }).catch(() => undefined);
        },
      };
    },
    async normalizeLogin(login) {
      const r = await call({ op: "normalize", login });
      if (r.text === undefined) throw new OpaqueClientError("invalid_input");
      return r.text;
    },
  };
}
