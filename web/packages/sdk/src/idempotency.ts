// Idempotency-Key generation (App. D.3, contract M0 §5.3 / §10).

/**
 * A fresh Idempotency-Key from the platform CSPRNG (crypto.randomUUID).
 * Throws when no CSPRNG is available: there is deliberately no Math.random fallback.
 */
export function idempotencyKey(): string {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || typeof c.randomUUID !== "function") {
    throw new Error("crypto.randomUUID is unavailable; cannot generate an Idempotency-Key");
  }
  return c.randomUUID();
}

/** Contract M0 §5.3: 1..255 visible ASCII characters. */
export function isValidIdempotencyKey(key: string): boolean {
  return /^[\x21-\x7e]{1,255}$/.test(key);
}
