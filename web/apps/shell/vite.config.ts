import type { ServerResponse } from "node:http";
import { defineConfig } from "vite";

// Dev server only: forwards platform routes to a locally running backend. CS_DEV_BACKEND overrides the
// target (default http://127.0.0.1:8080, an assumption: the M0 contract does not fix a port). When the
// backend is down the proxy answers 502 with no body, which the client maps to `unavailable`.
const backend = process.env.CS_DEV_BACKEND ?? "http://127.0.0.1:8080";

const route = {
  target: backend,
  changeOrigin: true,
  configure: (proxy: { on(event: "error", cb: (err: Error, req: unknown, res: unknown) => void): void }) => {
    proxy.on("error", (_err, _req, res) => {
      const r = res as ServerResponse;
      if (typeof r.writeHead === "function" && !r.headersSent) {
        r.writeHead(502);
        r.end();
      }
    });
  },
};

export default defineConfig({
  server: {
    proxy: { "/readyz": route, "/healthz": route, "/api": route },
  },
});
