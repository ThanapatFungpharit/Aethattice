// Web shell entry (spec §14.1).
import { ApiClient, AuthSession, httpRefreshTransport, installTokens, workerOpaqueEngine } from "@cs/sdk";
import "./cs-shell-app";
import { registerShellMessages } from "./messages";

installTokens(document);
registerShellMessages();

// Base URL comes from configuration; by default the shell talks to its own origin.
const configured = import.meta.env.VITE_CS_API_BASE_URL as string | undefined;
const baseUrl = configured ?? window.location.origin;
const client = new ApiClient({ baseUrl });

// Identity (contract M1 §7): the access token lives only in this session object; refreshes use the cookie.
const session = new AuthSession({ transport: httpRefreshTransport({ baseUrl }) });
const authedClient = new ApiClient({ baseUrl, auth: session });
const worker = new Worker(new URL("./opaque-worker.ts", import.meta.url), { type: "module" });
const engine = workerOpaqueEngine(worker);

const app = document.createElement("cs-shell-app");
app.client = client;
app.identity = { client, engine, session };
app.authedClient = authedClient;
app.showDevLink = import.meta.env.DEV;
document.body.appendChild(app);
