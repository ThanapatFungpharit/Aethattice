/* tslint:disable */
/* eslint-disable */

/**
 * Login in progress: holds the client state between `login/start` and `login/finish`.
 */
export class LoginClient {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Consumes the handle. Returns the `credential_finalization` bytes.
     */
    finish(password: Uint8Array | number[], response: Uint8Array | number[], m_kib: number, t: number, p: number): Uint8Array;
    /**
     * `credential_request` bytes.
     */
    readonly request: Uint8Array;
}

/**
 * Registration in progress: holds the client state between `register/start` and `register/finish`.
 */
export class RegistrationClient {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Consumes the handle. Returns the `registration_upload` bytes.
     */
    finish(password: Uint8Array | number[], response: Uint8Array | number[], m_kib: number, t: number, p: number): Uint8Array;
    /**
     * `registration_request` bytes.
     */
    readonly request: Uint8Array;
}

/**
 * Starts a login (contract §2.1 `login/start`). `tenant` is the canonical tenant UUID, `login` as typed.
 */
export function loginStart(password: Uint8Array | number[], tenant: string, login: string): LoginClient;

/**
 * The shared login normalization (contract §1, rev 5 §2.1), so the UI can validate before the round trip.
 */
export function normalizeLogin(raw: string): string;

/**
 * Starts a registration (contract §2.1 `register/start`). `tenant` is the canonical tenant UUID, `login` as
 * typed (it is normalized here, rev 5 §2.1).
 */
export function registrationStart(password: Uint8Array | number[], tenant: string, login: string): RegistrationClient;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_loginclient_free: (a: number, b: number) => void;
    readonly __wbg_registrationclient_free: (a: number, b: number) => void;
    readonly loginStart: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly loginclient_finish: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly loginclient_request: (a: number) => [number, number];
    readonly normalizeLogin: (a: number, b: number) => [number, number, number, number];
    readonly registrationStart: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly registrationclient_finish: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly registrationclient_request: (a: number) => [number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
