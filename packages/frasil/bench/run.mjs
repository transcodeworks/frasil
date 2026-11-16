// Runs the WebAssembly benchmark on one built package, or prints the table that compares runs.
//
//   node bench/run.mjs --dist DIR --label s --runs 7 --engines node,chromium --json out.json
//   node bench/run.mjs --report a.json b.json     the table, medians in milliseconds
//
// `--dist` is a package built by `scripts/build.mjs` (`FRASIL_NPM_DIST`). Chromium needs
// `pnpm exec playwright install chromium`.
import { readFileSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

import { measure } from "./workloads.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));

/** @param {string} name @param {string} [fallback] */
function flag(name, fallback) {
  const at = process.argv.indexOf(`--${name}`);
  return at === -1 ? fallback : process.argv[at + 1];
}

/** @param {string} line */
const log = (line) => process.stderr.write(`${line}\n`);

if (process.argv.includes("--report")) {
  report(process.argv.slice(process.argv.indexOf("--report") + 1));
  process.exit(0);
}

const dist = flag("dist");
if (!dist) {
  log("bench: --dist DIR is required");
  process.exit(2);
}
const label = flag("label", "build");
const runs = Number(flag("runs", "7"));
const engines = (flag("engines", "node,chromium") ?? "").split(",").filter(Boolean);
const json = flag("json");

const wasm = readFileSync(join(dist, "wasm", "frasil_wasm_bg.wasm"));
/** @type {{ label: string, bytes: number, gzip: number, runs: number, engines: Record<string, any[]> }} */
const output = {
  label,
  bytes: wasm.length,
  gzip: gzipSync(wasm, { level: 6 }).length,
  runs,
  engines: {},
};

for (const engine of engines) {
  log(`bench ${label}: ${engine}, ${runs} runs`);
  if (engine === "node") {
    const frasil = await import(pathToFileURL(join(dist, "index.js")).href);
    output.engines.node = await measure(frasil, { runs, log });
  } else if (engine === "chromium") {
    output.engines.chromium = await inChromium(dist, runs);
  } else {
    log(`bench: unknown engine ${engine}`);
    process.exit(2);
  }
  // Each engine's results are kept as soon as they are measured.
  if (json) writeFileSync(json, `${JSON.stringify(output, null, 2)}\n`);
}

report([output]);
process.exit(0);

/**
 * Serves the package and the workloads on loopback and runs them in headless Chromium.
 *
 * @param {string} dist @param {number} runs
 */
async function inChromium(dist, runs) {
  const { chromium } = await import("@playwright/test");
  const types = {
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".html": "text/html",
    ".wasm": "application/wasm",
  };
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://localhost").pathname;
    const root = path.startsWith("/dist/") ? dist : here;
    const file = normalize(join(root, path.replace(/^\/(dist|bench)\//, "")));
    if (!file.startsWith(root)) {
      response.writeHead(404).end();
      return;
    }
    // The file is read before the answer starts, so that a missing one, such as the favicon the
    // browser asks for, is answered 404 rather than failing after a 200.
    let bytes;
    try {
      bytes = await readFile(file);
    } catch {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, {
      "content-type": types[extname(file)] ?? "application/octet-stream",
    });
    response.end(bytes);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(undefined)));
  const address = server.address();
  const origin = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    page.on("pageerror", (error) => log(`  page error: ${error.message}`));
    page.on("console", (message) => log(message.text()));
    await page.goto(`${origin}/bench/page.html`);
    await page.waitForFunction(() => /** @type {any} */ (window).__ready === true, undefined, {
      timeout: 120_000,
    });
    return await page.evaluate((runs) => /** @type {any} */ (window).__bench(runs), runs);
  } finally {
    await browser.close();
    server.close();
  }
}

/**
 * The table: one row per workload and engine, a median in milliseconds per build, and, with two
 * builds, the second's over the first's.
 *
 * @param {(string | any)[]} inputs file names of `--json` output, or the outputs themselves
 */
function report(inputs) {
  const builds = inputs.map((input) =>
    typeof input === "string" ? JSON.parse(readFileSync(input, "utf8")) : input,
  );
  console.log("");
  console.log(`median of ${builds.map((build) => `${build.runs}`).join("/")} runs, milliseconds`);
  console.log("");
  const names = builds.map((build) => `opt-level ${build.label}`);
  const header = ["workload", "engine", ...names];
  if (builds.length === 2) header.push(`${builds[1].label}/${builds[0].label}`);
  const rows = [
    [
      "module bytes (gzip -6)",
      "",
      ...builds.map(
        (build) => `${build.bytes.toLocaleString("en")} (${build.gzip.toLocaleString("en")})`,
      ),
      ...(builds.length === 2 ? [(builds[1].bytes / builds[0].bytes).toFixed(3)] : []),
    ],
  ];
  const engines = [...new Set(builds.flatMap((build) => Object.keys(build.engines)))];
  const workloads = builds[0]
    ? (builds[0].engines[engines[0] ?? "node"]?.map((row) => row.name) ?? [])
    : [];
  for (const name of workloads) {
    for (const engine of engines) {
      const medians = builds.map(
        (build) => build.engines[engine]?.find((row) => row.name === name)?.median,
      );
      rows.push([
        name,
        engine,
        ...medians.map((value) => (value === undefined ? "-" : value.toFixed(1))),
        ...(builds.length === 2 && medians[0] && medians[1]
          ? [(medians[1] / medians[0]).toFixed(3)]
          : []),
      ]);
    }
  }
  const widths = header.map((cell, column) =>
    Math.max(cell.length, ...rows.map((row) => String(row[column] ?? "").length)),
  );
  const line = (/** @type {string[]} */ row) =>
    row
      .map((cell, column) =>
        column < 2 ? cell.padEnd(widths[column]) : cell.padStart(widths[column]),
      )
      .join("  ");
  console.log(line(header));
  console.log(widths.map((width) => "-".repeat(width)).join("  "));
  for (const row of rows) console.log(line(row));
}
