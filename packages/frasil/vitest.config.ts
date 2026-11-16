import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

/**
 * Unit tests in Node.js, against the TypeScript sources and the built WebAssembly module
 * (`node scripts/build.mjs` first): the stores, over `fake-indexeddb` for IndexedDB, a device
 * kept in one, the reads that follow a device, and the React, Svelte and Solid bindings. The
 * binding in browsers, against the peer, is tested with Playwright (`playwright.config.ts`).
 */
export default defineConfig({
  resolve: {
    // Solid's reactive build, not the server one Node.js would pick, for the Solid binding's test.
    alias: [
      {
        find: /^solid-js$/,
        replacement: fileURLToPath(new URL("node_modules/solid-js/dist/solid.js", import.meta.url)),
      },
    ],
  },
  test: {
    include: ["test/unit/**/*.test.ts"],
    environment: "node",
  },
});
