import { defineConfig } from "vitest/config";

// End-to-end project (scripts/e2e.sh): Node environment with its real fetch, WebCrypto and BroadcastChannel.
// One file; its tests run in order against one server and one tenant. Not part of `npm test`.
export default defineConfig({
  test: {
    root: import.meta.dirname,
    environment: "node",
    include: ["**/*.e2e.test.ts"],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
