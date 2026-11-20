// Web shell entry (spec §14.1). M0 skeleton.
import { ApiClient, installTokens } from "@cs/sdk";
import "./cs-shell-app";
import { registerShellMessages } from "./messages";

installTokens(document);
registerShellMessages();

// Base URL comes from configuration; by default the shell talks to its own origin.
const configured = import.meta.env.VITE_CS_API_BASE_URL as string | undefined;
const client = new ApiClient({ baseUrl: configured ?? window.location.origin });

const app = document.createElement("cs-shell-app");
app.client = client;
app.showDevLink = import.meta.env.DEV;
document.body.appendChild(app);
