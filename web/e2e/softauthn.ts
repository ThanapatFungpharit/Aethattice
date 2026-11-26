// A software WebAuthn authenticator for the end-to-end suite: `navigator.credentials` stand-in with an ES256
// (P-256, WebCrypto) discoverable credential, attestation "none", UP+UV set. It produces what a platform
// authenticator returns (clientDataJSON, authenticatorData, attestationObject in CBOR with a COSE_Key, DER
// signatures), so the server's webauthn-rs verification runs unchanged. Test-only: no real user presence.
import { base64urlEncode, type CredentialsLike } from "@cs/sdk";

type Cbor = number | string | Uint8Array | Map<number | string, Cbor>;

function head(major: number, n: number): number[] {
  if (n < 24) return [(major << 5) | n];
  if (n < 0x100) return [(major << 5) | 24, n];
  if (n < 0x10000) return [(major << 5) | 25, n >> 8, n & 0xff];
  return [(major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}

/** Minimal deterministic CBOR (RFC 8949) for the types an attestation object needs. */
function cbor(v: Cbor): number[] {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") {
    const b = new TextEncoder().encode(v);
    return [...head(3, b.length), ...b];
  }
  if (v instanceof Uint8Array) return [...head(2, v.length), ...v];
  const out = head(5, v.size);
  for (const [k, x] of v) out.push(...cbor(k), ...cbor(x));
  return out;
}

function bytes(b: BufferSource): Uint8Array {
  return b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}

function buffer(u: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(u.byteLength);
  new Uint8Array(out).set(u);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(b)));
}

/** IEEE P1363 r‖s → ASN.1 DER ECDSA-Sig-Value (WebAuthn ES256 signatures are DER). */
function der(sig: Uint8Array): Uint8Array {
  const int = (x: Uint8Array): number[] => {
    let i = 0;
    while (i < x.length - 1 && x[i] === 0) i++;
    const t = Array.from(x.slice(i));
    return (t[0] ?? 0) & 0x80 ? [0x02, t.length + 1, 0, ...t] : [0x02, t.length, ...t];
  };
  const body = [...int(sig.slice(0, 32)), ...int(sig.slice(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}

const UP = 0x01;
const UV = 0x04;
const AT = 0x40;

interface StoredCredential {
  readonly id: Uint8Array;
  readonly rpId: string;
  readonly userHandle: Uint8Array;
  readonly keys: CryptoKeyPair;
  counter: number;
}

export class SoftAuthenticator implements CredentialsLike {
  private readonly origin: string;
  readonly credentials: StoredCredential[] = [];

  constructor(origin: string) {
    this.origin = origin;
  }

  private clientData(type: string, challenge: BufferSource): Uint8Array {
    return new TextEncoder().encode(JSON.stringify({ type, challenge: base64urlEncode(bytes(challenge)), origin: this.origin, crossOrigin: false }));
  }

  private rpIdOf(rpId: string | undefined): string {
    return rpId ?? new URL(this.origin).hostname;
  }

  async create(options: CredentialCreationOptions): Promise<Credential | null> {
    const pk = options.publicKey;
    if (!pk) return null;
    if (!pk.pubKeyCredParams.some((p) => p.alg === -7)) throw Object.assign(new Error("ES256 not offered"), { name: "NotSupportedError" });
    const rpId = this.rpIdOf(pk.rp.id);
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
    const id = crypto.getRandomValues(new Uint8Array(16));
    const cred: StoredCredential = { id, rpId, userHandle: bytes(pk.user.id).slice(), keys, counter: 1 };
    this.credentials.push(cred);
    const cose = new Uint8Array(cbor(new Map<number, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33, 65)]])));
    const authData = concat(
      await sha256(new TextEncoder().encode(rpId)),
      new Uint8Array([UP | UV | AT, 0, 0, 0, cred.counter]),
      new Uint8Array(16),
      new Uint8Array([id.length >> 8, id.length & 0xff]),
      id,
      cose,
    );
    const attestationObject = new Uint8Array(cbor(new Map<string, Cbor>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]])));
    const clientDataJSON = this.clientData("webauthn.create", pk.challenge);
    return {
      id: base64urlEncode(id),
      rawId: buffer(id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: buffer(clientDataJSON),
        attestationObject: buffer(attestationObject),
        getTransports: () => ["internal"],
      },
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    } as unknown as Credential;
  }

  async get(options: CredentialRequestOptions): Promise<Credential | null> {
    const pk = options.publicKey;
    if (!pk) return null;
    const rpId = this.rpIdOf(pk.rpId);
    const allow = (pk.allowCredentials ?? []).map((d) => base64urlEncode(bytes(d.id)));
    const cred = this.credentials.find((c) => c.rpId === rpId && (allow.length === 0 || allow.includes(base64urlEncode(c.id))));
    if (!cred) throw Object.assign(new Error("no credential"), { name: "NotAllowedError" });
    cred.counter++;
    const n = cred.counter;
    const authData = concat(await sha256(new TextEncoder().encode(rpId)), new Uint8Array([UP | UV, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]));
    const clientDataJSON = this.clientData("webauthn.get", pk.challenge);
    const signed = concat(authData, await sha256(clientDataJSON));
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, cred.keys.privateKey, buffer(signed)));
    return {
      id: base64urlEncode(cred.id),
      rawId: buffer(cred.id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: buffer(clientDataJSON),
        authenticatorData: buffer(authData),
        signature: buffer(der(sig)),
        userHandle: buffer(cred.userHandle),
      },
      getClientExtensionResults: () => ({}),
    } as unknown as Credential;
  }
}
