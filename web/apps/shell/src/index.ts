// Web shell entry (spec §14.1).
import { ApiClient, AuthSession, DpopKeyManager, browserCredentials, httpRefreshTransport, installTokens, workerOpaqueEngine } from "@cs/sdk";
import "./cs-shell-app";
import { registerShellMessages } from "./messages";

installTokens(document);
registerShellMessages();

// Base URL comes from configuration; by default the shell talks to its own origin.
const configured = import.meta.env.VITE_CS_API_BASE_URL as string | undefined;
const baseUrl = configured ?? window.location.origin;
// Identity (contract M1 §7): the access token lives only in this session object; refreshes use the cookie.
// DPoP (rev 8): one non-extractable ES256 key per session in IndexedDB, shared by all tabs; every client that
// sends login/finish, token/refresh or an access token signs a proof with it.
const dpop = new DpopKeyManager();
const client = new ApiClient({ baseUrl, dpop });
const session = new AuthSession({ transport: httpRefreshTransport({ baseUrl, dpop }), dpop });
const authedClient = new ApiClient({ baseUrl, auth: session, dpop });
const worker = new Worker(new URL("./opaque-worker.ts", import.meta.url), { type: "module" });
const engine = workerOpaqueEngine(worker);

const app = document.createElement("cs-shell-app");
app.client = client;
app.identity = { client, engine, session };
app.authedClient = authedClient;
// WebAuthn (contract §2.2): the browser API directly; passkey options are hidden where it is unavailable.
app.credentials = browserCredentials();
app.showDevLink = import.meta.env.DEV;
document.body.appendChild(app);
