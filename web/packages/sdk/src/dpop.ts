// DPoP client (RFC 9449; contract M1 §3, rev 8 wire details).
// - One ES256 (P-256) key pair per session, generated non-extractable by WebCrypto and kept as a CryptoKey in
//   IndexedDB, so every tab of the browser uses the same key. The private key is never exported.
// - A proof is a compact JWS with `typ: dpop+jwt`, `alg: ES256`, and a `jwk` header carrying only the public
//   members. Claims: `jti` (unique per proof), `htm`, `htu` (no query or fragment), `iat`, `ath` when an access
//   token is sent, and `nonce` only if the server ever asks for one (rev 8: never in M1).
// - The key is deleted on sign-out and on any `unauthenticated` that ends the session; the next sign-in makes a new one.
import { base64urlEncode } from "./opaque";
import { systemClock, type Clock } from "./retry";

/** `typ` header of a DPoP proof (RFC 9449 §4.2). */
export const DPOP_TYP = "dpop+jwt";
/** The web client's proof algorithm (rev 8). */
export const DPOP_ALG = "ES256";
/** Request header carrying the proof. */
export const DPOP_HEADER = "DPoP";
/** Response header carrying a server nonce (RFC 9449 §8). */
export const DPOP_NONCE_HEADER = "DPoP-Nonce";

const KEY_PARAMS: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_PARAMS: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

/** Public P-256 key in the `jwk` header: public members only (rev 8). */
export interface DpopPublicJwk {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
}

/** Persistent storage for the session key pair. Must store CryptoKey objects as such (structured clone). */
export interface DpopKeyStore {
  get(): Promise<CryptoKeyPair | undefined>;
  put(pair: CryptoKeyPair): Promise<void>;
  delete(): Promise<void>;
}

/** A store in memory; tests use one instance for several "tabs" in place of IndexedDB. */
export function memoryDpopKeyStore(): DpopKeyStore {
  let pair: CryptoKeyPair | undefined;
  return {
    get: () => Promise.resolve(pair),
    put: (p) => {
      pair = p;
      return Promise.resolve();
    },
    delete: () => {
      pair = undefined;
      return Promise.resolve();
    },
  };
}

export const DPOP_IDB_NAME = "cs-dpop";
const IDB_STORE = "keys";
const IDB_KEY = "session";

function idbRequest<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => {
      resolve(req.result);
    };
    req.onerror = () => {
      reject(req.error ?? new Error("indexeddb request failed"));
    };
  });
}

function isKeyPair(v: unknown): v is CryptoKeyPair {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Record<string, unknown>;
  return typeof CryptoKey !== "undefined" && r.privateKey instanceof CryptoKey && r.publicKey instanceof CryptoKey;
}

/**
 * The key pair in IndexedDB (database `cs-dpop`, store `keys`, entry `session`). IndexedDB stores CryptoKey objects
 * by structured clone, which keeps a non-extractable private key non-extractable: the key material never reaches
 * script. Same-origin tabs share the database, hence the key.
 */
export function indexedDbDpopKeyStore(factory: IDBFactory = globalThis.indexedDB): DpopKeyStore {
  let db: Promise<IDBDatabase> | undefined;
  const open = (): Promise<IDBDatabase> => {
    db ??= new Promise<IDBDatabase>((resolve, reject) => {
      const req = factory.open(DPOP_IDB_NAME, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(IDB_STORE)) req.result.createObjectStore(IDB_STORE);
      };
      req.onsuccess = () => {
        resolve(req.result);
      };
      req.onerror = () => {
        db = undefined;
        reject(req.error ?? new Error("indexeddb open failed"));
      };
    });
    return db;
  };
  const store = async (mode: IDBTransactionMode): Promise<IDBObjectStore> => (await open()).transaction(IDB_STORE, mode).objectStore(IDB_STORE);
  return {
    async get() {
      const v: unknown = await idbRequest((await store("readonly")).get(IDB_KEY));
      return isKeyPair(v) ? v : undefined;
    },
    async put(pair) {
      await idbRequest((await store("readwrite")).put({ privateKey: pair.privateKey, publicKey: pair.publicKey }, IDB_KEY));
    },
    async delete() {
      await idbRequest((await store("readwrite")).delete(IDB_KEY));
    },
  };
}

// ---- proof construction ----

const encoder = new TextEncoder();

function b64uJson(v: unknown): string {
  return base64urlEncode(encoder.encode(JSON.stringify(v)));
}

/** `htu` (RFC 9449 §4.2, rev 8): the absolute request URI without query and fragment. */
export function normalizeHtu(url: string): string {
  const u = new URL(url);
  u.search = "";
  u.hash = "";
  return u.href;
}

/** `ath` (RFC 9449 §4.2): base64url(SHA-256(ASCII(access token))). */
export async function accessTokenHash(accessToken: string, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<string> {
  return base64urlEncode(new Uint8Array(await subtle.digest("SHA-256", encoder.encode(accessToken))));
}

/** The public members of a P-256 public key (rev 8: no private members ever leave). */
export async function publicJwk(publicKey: CryptoKey, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<DpopPublicJwk> {
  const jwk = await subtle.exportKey("jwk", publicKey);
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new TypeError("DPoP public key must be EC P-256");
  }
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

/** JWK thumbprint (RFC 7638), the `jkt` the server binds the session to. */
export async function jwkThumbprint(jwk: DpopPublicJwk, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<string> {
  // Required members in lexicographic order, no whitespace.
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return base64urlEncode(new Uint8Array(await subtle.digest("SHA-256", encoder.encode(canonical))));
}

export interface DpopProofInput {
  readonly htm: string;
  /** Absolute request URL; query and fragment are removed. */
  readonly url: string;
  /** The access token sent with the request, for `ath`. */
  readonly accessToken?: string;
  readonly nonce?: string;
}

/** Signs proofs for {@link ApiClient}. Resolves undefined when no key is available (no session key yet). */
export interface DpopProver {
  proof(input: DpopProofInput): Promise<string | undefined>;
}

export interface DpopKeyManagerOptions {
  /** Default: {@link indexedDbDpopKeyStore}. */
  readonly store?: DpopKeyStore;
  readonly clock?: Clock;
  readonly subtle?: SubtleCrypto;
  /** `jti` generator. Default: crypto.randomUUID(). */
  readonly jti?: () => string;
}

interface LoadedKey {
  readonly pair: CryptoKeyPair;
  readonly jwk: DpopPublicJwk;
}

/**
 * Holds the session's DPoP key (rev 8 key lifetime) and signs proofs with it.
 * The key is cached in the tab; {@link invalidate} makes the next proof re-read the shared store, which
 * {@link AuthSession} does whenever another tab signs in or out.
 */
export class DpopKeyManager implements DpopProver {
  private readonly store: DpopKeyStore;
  private readonly clock: Clock;
  private readonly subtle: SubtleCrypto;
  private readonly newJti: () => string;
  private cached: Promise<LoadedKey | undefined> | undefined;

  constructor(opts: DpopKeyManagerOptions = {}) {
    this.store = opts.store ?? indexedDbDpopKeyStore();
    this.clock = opts.clock ?? systemClock;
    this.subtle = opts.subtle ?? globalThis.crypto.subtle;
    this.newJti = opts.jti ?? (() => globalThis.crypto.randomUUID());
  }

  /**
   * Creates the key pair for a new session (before `login/finish`) and stores it for all tabs, replacing any
   * previous one. The private key is generated non-extractable.
   */
  async rotate(): Promise<DpopPublicJwk> {
    const pair = await this.subtle.generateKey(KEY_PARAMS, false, ["sign", "verify"]);
    await this.store.put(pair);
    const loaded = { pair, jwk: await publicJwk(pair.publicKey, this.subtle) };
    this.cached = Promise.resolve(loaded);
    return loaded.jwk;
  }

  /** Deletes the key (sign-out, or the session ended). */
  async discard(): Promise<void> {
    this.cached = Promise.resolve(undefined);
    await this.store.delete();
  }

  /** Forgets the tab's cached key; the next proof reads the shared store. */
  invalidate(): void {
    this.cached = undefined;
  }

  /** The current public key, or undefined without a session key. */
  async publicKey(): Promise<DpopPublicJwk | undefined> {
    return (await this.load())?.jwk;
  }

  async proof(input: DpopProofInput): Promise<string | undefined> {
    const key = await this.load();
    if (!key) return undefined;
    const header = { typ: DPOP_TYP, alg: DPOP_ALG, jwk: key.jwk };
    const payload: Record<string, string | number> = {
      jti: this.newJti(),
      htm: input.htm,
      htu: normalizeHtu(input.url),
      iat: Math.floor(this.clock.now() / 1000),
    };
    if (input.accessToken !== undefined) payload.ath = await accessTokenHash(input.accessToken, this.subtle);
    if (input.nonce !== undefined) payload.nonce = input.nonce;
    const signingInput = `${b64uJson(header)}.${b64uJson(payload)}`;
    // WebCrypto ECDSA signatures are r ‖ s (IEEE P1363), which is the JWS ES256 format (RFC 7518 §3.4).
    const sig = await this.subtle.sign(SIGN_PARAMS, key.pair.privateKey, encoder.encode(signingInput));
    return `${signingInput}.${base64urlEncode(new Uint8Array(sig))}`;
  }

  private load(): Promise<LoadedKey | undefined> {
    this.cached ??= this.store.get().then(async (pair) => (pair ? { pair, jwk: await publicJwk(pair.publicKey, this.subtle) } : undefined));
    const p = this.cached;
    // A failed read is not cached, so a later proof tries again.
    p.catch(() => {
      if (this.cached === p) this.cached = undefined;
    });
    return p;
  }
}

/** Splits `DPoP <token>` / `Bearer <token>`; returns the token for `ath` when the scheme is DPoP. */
export function dpopAccessToken(authorization: string | undefined): string | undefined {
  if (authorization === undefined) return undefined;
  const m = /^DPoP (\S+)$/.exec(authorization);
  return m?.[1];
}

/** True when a response asks for a DPoP nonce (RFC 9449 §8: `WWW-Authenticate: DPoP error="use_dpop_nonce"`). */
export function isUseDpopNonce(status: number, headers: Headers): boolean {
  if (status !== 401 && status !== 400) return false;
  if (headers.get(DPOP_NONCE_HEADER) === null) return false;
  const www = headers.get("WWW-Authenticate") ?? "";
  return /error="?use_dpop_nonce"?/.test(www) || status === 400;
}
