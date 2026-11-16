import { defineConfig } from "@playwright/test";

/**
 * The binding's tests, run on the built package (`dist/`) in Chromium and WebKit:
 *
 * - `scenarios.spec.ts`: devices in pages of their own browser contexts make a space, admit one
 *   another, write Loro documents and sync them through `frasil-relay`, and reload from IndexedDB;
 * - `recovery.spec.ts`: a person who lost their only browser returns on another from the recovery
 *   sheet, through `frasil-relay`;
 * - `personal-space.spec.ts`: a browser knows its person's personal space, after a reload too;
 * - `reconnect.spec.ts`: a peer asks a browser to connect again, and its `PeerStatus` counts it;
 * - `csp.spec.ts`: the Content Security Policy experiment.
 *
 * Firefox is not listed: Playwright's build does not start on the machine this was written on.
 * `FRASIL_TEST_ENGINES=chromium` limits the browsers.
 *
 * Two servers run for the tests, both on loopback: `frasil-relay`, the workspace's peer, on a fresh
 * data directory (`test/binding/peer.mjs`, which builds it); and the test origin, which serves the
 * pages and the package and proxies the peer's routes (`test/binding/serve.mjs`), so pages reach
 * the peer at their own origin. Their ports are chosen here once, in the runner's environment,
 * which the workers inherit.
 */
const port = () => String(20_000 + Math.floor(Math.random() * 20_000));
process.env.FRASIL_TEST_PORT ??= port();
process.env.FRASIL_TEST_PEER_PORT ??= port();

const engines = (process.env.FRASIL_TEST_ENGINES ?? "chromium,webkit").split(",");
const browsers = [
  { name: "chromium", use: { browserName: "chromium" as const } },
  { name: "webkit", use: { browserName: "webkit" as const } },
].filter((project) => engines.includes(project.name));

export default defineConfig({
  testDir: "test/binding",
  timeout: 90_000,
  fullyParallel: true,
  reporter: [["list"]],
  projects: browsers,
  use: { baseURL: `http://127.0.0.1:${process.env.FRASIL_TEST_PORT}` },
  webServer: [
    {
      command: "node test/binding/peer.mjs",
      url: `http://127.0.0.1:${process.env.FRASIL_TEST_PEER_PORT}/healthz`,
      // The first run compiles the peer.
      timeout: 900_000,
      reuseExistingServer: false,
      stdout: "ignore",
      stderr: "pipe",
      gracefulShutdown: { signal: "SIGTERM", timeout: 10_000 },
    },
    {
      command: "node test/binding/serve.mjs",
      url: `http://127.0.0.1:${process.env.FRASIL_TEST_PORT}/runner.html`,
      reuseExistingServer: false,
      stdout: "ignore",
    },
  ],
});
