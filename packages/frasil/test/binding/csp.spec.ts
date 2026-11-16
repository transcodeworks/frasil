/**
 * The Content Security Policy check, with the real package: a page served under a strict policy
 * loads `dist/index.js` (or `dist/embedded/index.js`, where a case says) from a nonced module script, opens a device (randomness from
 * `crypto.getRandomValues`), creates a space, and connects to the peer over the WebSocket at its
 * own origin (the test origin proxies the peer). Each case changes one source from the policy the
 * package documents:
 *
 *     default-src 'none'; script-src 'nonce-…' 'wasm-unsafe-eval'; connect-src 'self'
 *
 * Every case records what happened, and the console errors, in `test-results/csp-<engine>.json`.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

interface Case {
  readonly name: string;
  readonly policy: string;
  readonly load: "static" | "dynamic";
  /** The entry: the default one fetches the module as a file, the embedded one carries it. */
  readonly entry?: "embedded";
  /** What must happen: everything works, the module does not load, or only the peer fails. */
  readonly expect: "works" | "no module" | "no connection";
}

const strict =
  "default-src 'none'; script-src 'nonce-{nonce}' 'wasm-unsafe-eval'; connect-src 'self'";

const cases: Case[] = [
  { name: "the documented policy", policy: strict, load: "static", expect: "works" },
  {
    name: "the documented policy, loading with import()",
    policy: strict,
    load: "dynamic",
    expect: "works",
  },
  {
    name: "without 'wasm-unsafe-eval'",
    policy: "default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'",
    load: "static",
    expect: "no module",
  },
  {
    name: "'unsafe-eval' instead of 'wasm-unsafe-eval'",
    policy: "default-src 'none'; script-src 'nonce-{nonce}' 'unsafe-eval'; connect-src 'self'",
    load: "static",
    expect: "works",
  },
  {
    name: "without connect-src, the default entry, which fetches its file",
    policy: "default-src 'none'; script-src 'nonce-{nonce}' 'wasm-unsafe-eval'",
    load: "static",
    expect: "no module",
  },
  {
    name: "without connect-src, the embedded entry",
    policy: "default-src 'none'; script-src 'nonce-{nonce}' 'wasm-unsafe-eval'",
    load: "static",
    entry: "embedded",
    expect: "no connection",
  },
  {
    name: "with Trusted Types required",
    policy: `${strict}; require-trusted-types-for 'script'; trusted-types 'none'`,
    load: "static",
    expect: "works",
  },
];

interface Observed {
  case: string;
  policy: string;
  loaded: boolean;
  device: unknown;
  peer: unknown;
  errors: string[];
}

const observed: Observed[] = [];

// One worker runs every case, so the record below holds them all.
test.describe.configure({ mode: "serial" });

// biome-ignore lint/correctness/noEmptyPattern: Playwright reads fixtures from this pattern; none are used.
test.afterAll(({}, info) => {
  mkdirSync(info.project.outputDir, { recursive: true });
  writeFileSync(
    join(info.project.outputDir, `csp-${info.project.name}.json`),
    `${JSON.stringify(observed, null, 2)}\n`,
  );
});

for (const item of cases) {
  test(`policy: ${item.name}`, async ({ page }) => {
    const errors: string[] = [];
    page.on("console", (message) => {
      if (message.type() === "error") errors.push(message.text());
    });
    page.on("pageerror", (error) => errors.push(`${error.name}: ${error.message}`));
    const params = new URLSearchParams({
      policy: item.policy,
      load: item.load,
      ...(item.entry ? { entry: item.entry } : {}),
    });
    await page.goto(`/csp?${params}`);
    if (item.expect === "no module") {
      // The module's instantiation is refused: an error, and nothing of the page's runs.
      await expect.poll(() => errors.length).toBeGreaterThan(0);
    } else {
      await page.waitForFunction(() => document.title === "done", undefined, { timeout: 30_000 });
    }
    const state = await page.evaluate(
      () => (window as unknown as { csp: Omit<Observed, "case" | "policy"> }).csp,
    );
    observed.push({
      case: item.name,
      policy: item.policy,
      ...state,
      errors: [...state.errors, ...errors],
    });

    if (item.expect === "works") {
      expect(state).toMatchObject({ loaded: true, device: 64, peer: "granted" });
    } else if (item.expect === "no connection") {
      expect(state).toMatchObject({ loaded: true, device: 64 });
      expect(String(state.peer)).toMatch(/^failed: connection/);
      expect(errors.join("\n")).toMatch(/connect|Content Security Policy|Refused/i);
    } else {
      expect(state.loaded).toBe(false);
      expect(errors.join("\n")).toMatch(
        /WebAssembly|wasm-unsafe-eval|unsafe-eval|connect|Content Security Policy/i,
      );
    }
  });
}
