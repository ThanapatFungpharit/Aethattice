import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { AuthSession, type AuthChannel, type AuthChannelMessage, type RefreshTransport, noCrossTabLock } from "./auth";
import { ApiClient } from "./client";
import {
  DPOP_HEADER,
  DpopKeyManager,
  accessTokenHash,
  dpopAccessToken,
  jwkThumbprint,
  memoryDpopKeyStore,
  normalizeHtu,
  type DpopPublicJwk,
} from "./dpop";
import { errorCodeInfo, type CoreErrorCode } from "./errors";
import { base64urlDecode, base64urlEncode } from "./opaque";
import { ApiError } from "./problem";
import { RetryPolicy, type Clock } from "./retry";

const NOW_MS = 1_764_000_000_123;
const clock: Clock = { now: () => NOW_MS, sleep: () => Promise.resolve() };
const subtle = globalThis.crypto.subtle;
const dec = new TextDecoder();

interface DecodedProof {
  header: { typ: string; alg: string; jwk: DpopPublicJwk & Record<string, unknown> };
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Uint8Array;
}

function decodeProof(jws: string): DecodedProof {
  const [h, p, s] = jws.split(".");
  if (h === undefined || p === undefined || s === undefined) throw new Error("not a compact JWS");
  return {
    header: JSON.parse(dec.decode(base64urlDecode(h))) as DecodedProof["header"],
    payload: JSON.parse(dec.decode(base64urlDecode(p))) as Record<string, unknown>,
    signingInput: `${h}.${p}`,
    signature: base64urlDecode(s),
  };
}

/** Verifies the ES256 signature with nothing but the public JWK from the proof header, as a server would. */
async function verifyWithHeaderJwk(jws: string): Promise<boolean> {
  const d = decodeProof(jws);
  const key = await subtle.importKey("jwk", d.header.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, new Uint8Array(d.signature), new TextEncoder().encode(d.signingInput));
}

const json = (v: unknown, status = 200): Response => new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
const problem = (status: number, code: CoreErrorCode, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify({ type: "about:blank", title: code, status, code, retryable: errorCodeInfo(code).retryable }), {
    status,
    headers: { "Content-Type": "application/problem+json", ...headers },
  });

/** In-process stand-in for BroadcastChannel between "tabs". */
function channelBus(): () => AuthChannel {
  const handlers = new Set<(m: AuthChannelMessage) => void>();
  return () => {
    let own: ((m: AuthChannelMessage) => void) | undefined;
    return {
      post: (m) => {
        for (const h of handlers) if (h !== own) h(m);
      },
      subscribe: (h) => {
        own = h;
        handlers.add(h);
        return () => handlers.delete(h);
      },
    };
  };
}

function unauthenticated(): ApiError {
  const info = errorCodeInfo("unauthenticated");
  return new ApiError({ type: "about:blank", title: "u", status: info.status, code: "unauthenticated", retryable: false }, { httpStatus: 401, synthesized: false, attempts: 1 });
}

describe("DPoP proofs (RFC 9449, M1 rev 8)", () => {
  it("carries typ dpop+jwt, ES256, a public-only jwk, and htm/htu/iat/unique jti; the signature verifies with that jwk", async () => {
    let n = 0;
    const keys = new DpopKeyManager({ store: memoryDpopKeyStore(), clock, jti: () => `jti-${String(++n)}` });
    const jwk = await keys.rotate();
    const a = await keys.proof({ htm: "POST", url: "https://cloud.example.com/api/v2/auth/opaque/login/finish" });
    const b = await keys.proof({ htm: "POST", url: "https://cloud.example.com/api/v2/auth/opaque/login/finish" });
    if (a === undefined || b === undefined) throw new Error("no proof");
    const d = decodeProof(a);
    expect(d.header).toEqual({ typ: "dpop+jwt", alg: "ES256", jwk });
    expect(Object.keys(d.header.jwk).sort()).toEqual(["crv", "kty", "x", "y"]);
    expect(d.header.jwk).not.toHaveProperty("d");
    expect(d.payload).toEqual({ jti: "jti-1", htm: "POST", htu: "https://cloud.example.com/api/v2/auth/opaque/login/finish", iat: Math.floor(NOW_MS / 1000) });
    expect(d.signature.length).toBe(64); // r ‖ s, the JWS ES256 encoding
    expect(await verifyWithHeaderJwk(a)).toBe(true);
    expect(decodeProof(b).payload.jti).toBe("jti-2");
    // A tampered payload does not verify.
    const [h, , s] = a.split(".");
    const forged = `${String(h)}.${base64urlEncode(new TextEncoder().encode(JSON.stringify({ ...d.payload, htm: "GET" })))}.${String(s)}`;
    expect(await verifyWithHeaderJwk(forged)).toBe(false);
  });

  it("uses random jtis by default", async () => {
    const keys = new DpopKeyManager({ store: memoryDpopKeyStore(), clock });
    await keys.rotate();
    const jtis = new Set<unknown>();
    for (let i = 0; i < 20; i++) jtis.add(decodeProof((await keys.proof({ htm: "GET", url: "https://x.test/a" })) ?? "").payload.jti);
    expect(jtis.size).toBe(20);
  });

  it("computes ath as base64url(SHA-256(access token)) and adds it only when a token is sent", async () => {
    const token = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1In0.c2ln";
    const expected = createHash("sha256").update(token, "ascii").digest("base64url");
    expect(await accessTokenHash(token)).toBe(expected);
    const keys = new DpopKeyManager({ store: memoryDpopKeyStore(), clock });
    await keys.rotate();
    const withToken = decodeProof((await keys.proof({ htm: "GET", url: "https://x.test/api/v2/me", accessToken: token })) ?? "");
    expect(withToken.payload.ath).toBe(expected);
    const without = decodeProof((await keys.proof({ htm: "POST", url: "https://x.test/api/v2/auth/token/refresh" })) ?? "");
    expect(without.payload).not.toHaveProperty("ath");
  });

  it("normalizes htu: no query, no fragment, canonical origin", () => {
    expect(normalizeHtu("https://Cloud.Example.com:443/api/v2/files?cursor=abc&x=1#frag")).toBe("https://cloud.example.com/api/v2/files");
    expect(normalizeHtu("https://cloud.example.com/api/v2/me?")).toBe("https://cloud.example.com/api/v2/me");
    expect(normalizeHtu("http://localhost:5173/api/v2/me#x")).toBe("http://localhost:5173/api/v2/me");
  });

  it("thumbprint follows RFC 7638 (RFC 7638 §3.1 example structure, EC members)", async () => {
    const jwk: DpopPublicJwk = { kty: "EC", crv: "P-256", x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" };
    const canonical = '{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}';
    expect(await jwkThumbprint(jwk)).toBe(createHash("sha256").update(canonical).digest("base64url"));
  });

  it("generates a non-extractable private key: it cannot be exported in any format", async () => {
    const store = memoryDpopKeyStore();
    const keys = new DpopKeyManager({ store, clock });
    await keys.rotate();
    const pair = await store.get();
    if (!pair) throw new Error("no key stored");
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.algorithm).toMatchObject({ name: "ECDSA", namedCurve: "P-256" });
    for (const format of ["jwk", "pkcs8"] as const) await expect(subtle.exportKey(format, pair.privateKey)).rejects.toThrow();
  });

  it("produces no proof without a key, and none after discard", async () => {
    const store = memoryDpopKeyStore();
    const keys = new DpopKeyManager({ store, clock });
    expect(await keys.proof({ htm: "GET", url: "https://x.test/" })).toBeUndefined();
    await keys.rotate();
    await keys.discard();
    expect(await store.get()).toBeUndefined();
    expect(await keys.proof({ htm: "GET", url: "https://x.test/" })).toBeUndefined();
  });

  it("parses the DPoP authorization scheme only", () => {
    expect(dpopAccessToken("DPoP abc.def.ghi")).toBe("abc.def.ghi");
    expect(dpopAccessToken("Bearer abc")).toBeUndefined();
    expect(dpopAccessToken(undefined)).toBeUndefined();
  });
});

describe("cross-tab key sharing (rev 8: one key per session, shared by all tabs)", () => {
  it("tabs on the same store sign with the same key; a new sign-in elsewhere is picked up via the auth channel", async () => {
    const store = memoryDpopKeyStore(); // stands in for the origin's IndexedDB
    const bus = channelBus();
    const transport: RefreshTransport = { refresh: () => Promise.reject(new Error("unused")) };
    const keysA = new DpopKeyManager({ store, clock });
    const keysB = new DpopKeyManager({ store, clock });
    const tabA = new AuthSession({ transport, lock: noCrossTabLock, channel: bus(), clock, dpop: keysA });
    const tabB = new AuthSession({ transport, lock: noCrossTabLock, channel: bus(), clock, dpop: keysB });

    const jwk1 = await keysA.rotate();
    tabA.signedIn({ state: "authenticated", access_token: "at1", expires_in: 600, session_id: "s1" });
    expect(tabB.state.sessionId).toBe("s1");
    const fromB = decodeProof((await keysB.proof({ htm: "GET", url: "https://x.test/a" })) ?? "");
    expect(fromB.header.jwk).toEqual(jwk1);
    expect(await jwkThumbprint(fromB.header.jwk)).toBe(await jwkThumbprint(jwk1));

    // B cached the key; A signs in again (new session, new key): B must not keep signing with the old one.
    const jwk2 = await keysA.rotate();
    tabA.signedIn({ state: "authenticated", access_token: "at2", expires_in: 600, session_id: "s2" });
    expect(jwk2).not.toEqual(jwk1);
    expect(decodeProof((await keysB.proof({ htm: "GET", url: "https://x.test/a" })) ?? "").header.jwk).toEqual(jwk2);
    expect(await tabB.authorization()).toBe("DPoP at2");

    // Sign-out in A deletes the shared key; B has none afterwards.
    await tabA.signedOut();
    expect(await store.get()).toBeUndefined();
    expect(await keysB.proof({ htm: "GET", url: "https://x.test/a" })).toBeUndefined();
    tabA.dispose();
    tabB.dispose();
  });
});

describe("ApiClient with DPoP", () => {
  async function rig(routes: Record<string, (req: Request) => Response>) {
    const seen: Request[] = [];
    const fetchFn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const req = new Request(input, init);
      seen.push(req);
      const route = routes[new URL(req.url).pathname];
      return Promise.resolve(route ? route(req) : problem(404, "not_found"));
    });
    const store = memoryDpopKeyStore();
    const keys = new DpopKeyManager({ store, clock });
    await keys.rotate();
    return { seen, fetchFn, keys, store };
  }

  it("sends Authorization: DPoP <at> with a proof bound to the request and the token (ath)", async () => {
    const r = await rig({ "/api/v2/me": () => json({}) });
    const session = new AuthSession({ transport: { refresh: () => Promise.reject(new Error("x")) }, lock: noCrossTabLock, channel: { post: () => undefined, subscribe: () => () => undefined }, clock, dpop: r.keys });
    session.signedIn({ state: "authenticated", access_token: "tok-1", expires_in: 600, session_id: "s" });
    const client = new ApiClient({ baseUrl: "https://cloud.example.com", fetch: r.fetchFn, clock, auth: session, dpop: r.keys });
    await client.get("/api/v2/me", { query: { a: 1 } });
    const req = r.seen[0];
    if (!req) throw new Error("no request");
    expect(req.headers.get("Authorization")).toBe("DPoP tok-1");
    const proof = req.headers.get(DPOP_HEADER) ?? "";
    const d = decodeProof(proof);
    expect(d.payload).toMatchObject({ htm: "GET", htu: "https://cloud.example.com/api/v2/me", ath: await accessTokenHash("tok-1") });
    expect(await verifyWithHeaderJwk(proof)).toBe(true);
  });

  it("signs a proof without ath only when asked (login/finish, refresh), and none on other unauthenticated calls", async () => {
    const r = await rig({ "/api/v2/auth/opaque/login/start": () => json({}), "/api/v2/auth/opaque/login/finish": () => json({}) });
    const client = new ApiClient({ baseUrl: "https://cloud.example.com", fetch: r.fetchFn, clock, dpop: r.keys });
    await client.post("/api/v2/auth/opaque/login/start");
    await client.post("/api/v2/auth/opaque/login/finish", { dpop: true });
    expect(r.seen[0]?.headers.get(DPOP_HEADER)).toBeNull();
    const d = decodeProof(r.seen[1]?.headers.get(DPOP_HEADER) ?? "");
    expect(d.payload).toMatchObject({ htm: "POST", htu: "https://cloud.example.com/api/v2/auth/opaque/login/finish" });
    expect(d.payload).not.toHaveProperty("ath");
  });

  it("signs a fresh proof (new jti) for every retry attempt", async () => {
    let n = 0;
    const r = await rig({ "/api/v2/x": () => (++n < 3 ? problem(503, "unavailable") : json({})) });
    const client = new ApiClient({ baseUrl: "https://cloud.example.com", fetch: r.fetchFn, clock, dpop: r.keys, retryPolicy: new RetryPolicy() });
    await client.post("/api/v2/x", { dpop: true });
    const jtis = r.seen.map((q) => decodeProof(q.headers.get(DPOP_HEADER) ?? "").payload.jti);
    expect(jtis.length).toBe(3);
    expect(new Set(jtis).size).toBe(3);
  });

  it("retries once with the nonce on use_dpop_nonce (defensive, rev 8), and not again", async () => {
    let n = 0;
    const r = await rig({
      "/api/v2/x": () => {
        n++;
        return problem(401, "unauthenticated", { "DPoP-Nonce": `n${String(n)}`, "WWW-Authenticate": 'DPoP error="use_dpop_nonce"' });
      },
    });
    const client = new ApiClient({ baseUrl: "https://cloud.example.com", fetch: r.fetchFn, clock, dpop: r.keys });
    await expect(client.post("/api/v2/x", { dpop: true })).rejects.toMatchObject({ problem: { code: "unauthenticated" } });
    expect(r.seen.length).toBe(2);
    expect(decodeProof(r.seen[0]?.headers.get(DPOP_HEADER) ?? "").payload).not.toHaveProperty("nonce");
    expect(decodeProof(r.seen[1]?.headers.get(DPOP_HEADER) ?? "").payload.nonce).toBe("n1");
  });
});

describe("AuthSession with DPoP: key lifetime (rev 8)", () => {
  const quiet: AuthChannel = { post: () => undefined, subscribe: () => () => undefined };

  it("deletes the key when a refresh is refused with unauthenticated (session revoked, reuse, or other key)", async () => {
    const store = memoryDpopKeyStore();
    const keys = new DpopKeyManager({ store, clock });
    await keys.rotate();
    const session = new AuthSession({ transport: { refresh: () => Promise.reject(unauthenticated()) }, lock: noCrossTabLock, channel: quiet, clock, dpop: keys });
    session.signedIn({ state: "authenticated", access_token: "a", expires_in: 600, session_id: "s" });
    expect(await session.refresh()).toBe(false);
    expect(session.state.authenticated).toBe(false);
    expect(await store.get()).toBeUndefined();
  });

  it("keeps the key when a refresh fails for another reason", async () => {
    const store = memoryDpopKeyStore();
    const keys = new DpopKeyManager({ store, clock });
    await keys.rotate();
    const err = new ApiError({ type: "about:blank", title: "u", status: 503, code: "unavailable", retryable: true }, { httpStatus: 503, synthesized: false, attempts: 1 });
    const session = new AuthSession({ transport: { refresh: () => Promise.reject(err) }, lock: noCrossTabLock, channel: quiet, clock, dpop: keys });
    session.signedIn({ state: "authenticated", access_token: "a", expires_in: 600, session_id: "s" });
    expect(await session.refresh()).toBe(false);
    expect(await store.get()).toBeDefined();
  });

  it("refresh requests through httpRefreshTransport carry a proof without ath", async () => {
    const { httpRefreshTransport } = await import("./auth");
    const keys = new DpopKeyManager({ store: memoryDpopKeyStore(), clock });
    await keys.rotate();
    const seen: Request[] = [];
    const fetchFn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(new Request(input, init));
      return Promise.resolve(json({ state: "authenticated", access_token: "n", expires_in: 600, session_id: "s" }));
    });
    const t = httpRefreshTransport({ baseUrl: "https://cloud.example.com", fetch: fetchFn, clock, dpop: keys });
    await t.refresh("key-1");
    const d = decodeProof(seen[0]?.headers.get(DPOP_HEADER) ?? "");
    expect(d.payload).toMatchObject({ htm: "POST", htu: "https://cloud.example.com/api/v2/auth/token/refresh" });
    expect(d.payload).not.toHaveProperty("ath");
    expect(seen[0]?.headers.get("Authorization")).toBeNull();
  });
});
