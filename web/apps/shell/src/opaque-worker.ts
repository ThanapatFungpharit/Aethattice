// Web Worker that runs the OPAQUE client (opaque-ke in WASM, contract M1 rev 5 §2.1), so Argon2id does not block
// the UI thread.
import init, * as wasm from "@cs/opaque-wasm";
import { serveOpaqueEngine, wasmOpaqueEngine, type OpaqueEngine } from "@cs/sdk";

const ready: Promise<OpaqueEngine> = init().then(() => wasmOpaqueEngine(wasm));

// Requests are queued until the module is ready.
const lazy: OpaqueEngine = {
  start: async (kind, password, tenant, login) => (await ready).start(kind, password, tenant, login),
  normalizeLogin: async (login) => (await ready).normalizeLogin(login),
};

serveOpaqueEngine(self, lazy);
