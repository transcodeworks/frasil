// Measures what the package weighs, raw and compressed, and what the WebAssembly module's code is
// made of, by crate. Run after `node scripts/build.mjs`. With `--check`, it fails when a file is
// over its budget below.
//
//   node scripts/size.mjs            the package's files
//   node scripts/size.mjs --check    and fail over a budget
//   node scripts/size.mjs --crates   also the module's code size by crate
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

const packageDir = fileURLToPath(new URL("..", import.meta.url));
const root = join(packageDir, "..", "..");
const targetDir = process.env.CARGO_TARGET_DIR ?? join(root, "target");

/**
 * The budgets, in bytes, raw and gzipped at level 6: each about a tenth above the size measured
 * when it was set, so that growth is a decision, not a drift. Raise one in the same change that
 * needs it, with the reason. The module is most of the package; the base64 that inlines it is a
 * third larger, so it has no budget of its own.
 */
const budgets = {
  // 7,496,673 and 2,195,004 on 2026-10-27: the module with ext-invite-links, ext-restricted-spaces,
  // ephemeral, ext-app-requests, ext-libraries, ext-drive and space-files on. Each budget keeps the
  // ratio to its measure the 2026-10-22 budgets had (6,754,626 and 1,949,600 then). Of the growth,
  // 108,252 and 47,014 are the space-files binding; the rest came with the drive extension, file
  // references, drive batches and sharing with no peer, before any budget was raised. 7,785,163
  // and 2,291,422 on 2026-10-29: the raw budget keeps the same ratio, the gzip one still holds;
  // 62,456 raw of the growth are a space's kept peers, the `peers` record, and following a space
  // a peer answered `moved` for. 8,075,755 and 2,376,702 on 2026-11-04, each budget a tenth above:
  // a file's versions with their authors, restoring one, and links a person claims. 9,030,161
  // and 2,667,306 on 2026-11-11, each budget a tenth above: ext-deposit-tokens, with the VOPRF of
  // RFC 9497 on ristretto255 and its proof checks, and deposits kept at rest to go again.
  // 11,071,009 and 3,108,609 on 2026-11-13: checkpoints of spaces and of device lists (records,
  // votes, worlds, forgetting, skeleton cuts) and administrators' ranks. 9,878,065 and 3,061,958
  // later that day, each budget a tenth above: maps collected by insertion, which compiles no
  // sort per call site, and unstable sorts over keys that tell every element apart.
  module: { raw: 10_865_872, gzip: 3_368_154 },
  // 118,346 and 17,923 on 2026-10-27 (85,780 and 14,309 on 2026-10-22): the glue of the root API's
  // bindings with those extensions; 2,721 and 520 of the growth are the space-files bindings.
  // 132,346 and 20,036 on 2026-11-04, each budget a tenth above: the drive's versions, conflicts,
  // setBlob and restoreVersion bindings.
  // 153,260 and 22,549 on 2026-11-07, each budget a tenth above: change feeds of a space, of
  // Records and of blobs, waits for what has not arrived, a blob's status and ranges, ranges of
  // rows, and receipts.
  // 165,788 and 24,984 on 2026-11-13, each budget a tenth above: the checkpoint calls, their
  // reports and policy, and ranks.
  glue: { raw: 182_367, gzip: 27_482 },
  // 38,909 and 7,774 on 2026-10-27 (32,435 and 6,948 on 2026-10-22), without comments (the
  // declarations keep them); 576 and 95 of the growth are the space-files calls.
  // 62,830 and 12,750 on 2026-11-07, each budget a tenth above: observed stores and their sharing,
  // the React, Svelte and Solid bindings, typed tables, the index's page client and the
  // manifest's TypeScript types, besides the calls above.
  // 69,510 and 14,025 on 2026-11-12, each budget a tenth above: the default entry finds its
  // module as a file and compiles it while it downloads, and `@frasil/client/client` holds
  // `IndexClient` alone.
  layer: { raw: 76_461, gzip: 15_428 },
};

/** @type {string[]} */
const over = [];

/**
 * Every file the module at `file` imports, directly or not, by its relative `import`/`export …
 * from` specifiers, and `file` itself.
 *
 * @param {string} file
 * @param {Set<string>} [seen]
 * @returns {Set<string>}
 */
function importsOf(file, seen = new Set()) {
  if (seen.has(file)) return seen;
  seen.add(file);
  const source = readFileSync(file, "utf8");
  for (const match of source.matchAll(/(?:from|import)\s*\(?\s*["'](\.[^"']+)["']/g)) {
    importsOf(resolve(dirname(file), match[1] ?? ""), seen);
  }
  return seen;
}

/** @param {string} label @param {Buffer} bytes @param {{ raw: number, gzip: number }} budget */
function check(label, bytes, budget) {
  const { raw, gzip } = sizes(bytes);
  if (raw > budget.raw) over.push(`${label}: ${raw} bytes raw, over its budget of ${budget.raw}`);
  if (gzip > budget.gzip) {
    over.push(`${label}: ${gzip} bytes gzipped, over its budget of ${budget.gzip}`);
  }
}

/** @param {Buffer} bytes */
function sizes(bytes) {
  return {
    raw: bytes.length,
    gzip: gzipSync(bytes, { level: 6 }).length,
    gzip9: gzipSync(bytes, { level: 9 }).length,
    brotli: brotliCompressSync(bytes, {
      params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
    }).length,
  };
}

/** @param {string} label @param {Buffer} bytes */
function row(label, bytes) {
  const { raw, gzip, gzip9, brotli } = sizes(bytes);
  const cell = (/** @type {number} */ value) => value.toLocaleString("en").padStart(9);
  console.log(`${label.padEnd(44)} ${cell(raw)} ${cell(gzip)} ${cell(gzip9)} ${cell(brotli)}`);
}

const dist = join(packageDir, "dist");
const layer = readdirSync(dist)
  .filter((file) => file.endsWith(".js"))
  .map((file) => readFileSync(join(dist, file)));
console.log(
  `${"bytes".padEnd(44)} ${"raw".padStart(9)} ${"gzip -6".padStart(9)} ${"gzip -9".padStart(9)} ${"brotli".padStart(9)}`,
);
const moduleBytes = readFileSync(join(targetDir, "frasil-npm", "default", "frasil_wasm_bg.wasm"));
row("WebAssembly module (.wasm, as wasm-bindgen wrote it)", moduleBytes);
// The index entry's module (`@frasil/client/index`) has SQLite besides; only an application that
// imports that entry loads it, so it has no budget of its own.
row(
  "the index entry's module (src/wasm/…_bg.wasm)",
  readFileSync(join(packageDir, "src", "wasm", "frasil_wasm_bg.wasm")),
);
row(
  "the default entry's file (dist/wasm/…_bg.wasm)",
  readFileSync(join(dist, "wasm", "frasil_wasm_bg.wasm")),
);
row(
  "the embedded entry's base64 (dist/embedded/wasm/…_base64.js)",
  readFileSync(join(dist, "embedded", "wasm", "frasil_wasm_base64.js")),
);
const glue = readFileSync(join(dist, "wasm", "frasil_wasm.js"));
row("wasm-bindgen's glue (dist/wasm/frasil_wasm.js)", glue);
row("the TypeScript layer (dist/*.js, no comments)", Buffer.concat(layer));

if (process.argv.includes("--check")) {
  check("the WebAssembly module", moduleBytes, budgets.module);
  check("wasm-bindgen's glue", glue, budgets.glue);
  check("the TypeScript layer", Buffer.concat(layer), budgets.layer);
  // The default entry ships the module as a file, not as base64, and is the same bytes as the
  // module wasm-bindgen wrote.
  if (existsSync(join(dist, "wasm", "frasil_wasm_base64.js"))) {
    over.push("the default entry ships the module as base64 as well as a file");
  }
  if (!readFileSync(join(dist, "wasm", "frasil_wasm_bg.wasm")).equals(moduleBytes)) {
    over.push("dist/wasm/frasil_wasm_bg.wasm is not the module wasm-bindgen wrote");
  }
  // `@frasil/client/client` loads no module: nothing it imports, however deep, is the runtime,
  // the engine or the glue.
  for (const file of importsOf(join(dist, "client.js"))) {
    if (/(^|\/)(runtime|engine[^/]*|compiled)\.js$|\/wasm\//.test(file)) {
      over.push(`dist/client.js imports ${file}, which loads or holds the module`);
    }
  }
  if (over.length > 0) {
    for (const line of over) console.error(`size: ${line}`);
    process.exit(1);
  }
  console.log("\nsize: every file is within its budget");
}

if (process.argv.includes("--crates")) {
  // The same module as the package's, with wasm-bindgen keeping its name section.
  const out = mkdtempSync(join(tmpdir(), "frasil-size-"));
  const installed = join(root, "target", "wasm-tools", "bin", "wasm-bindgen");
  const bindgen = process.env.WASM_BINDGEN ?? (existsSync(installed) ? installed : "wasm-bindgen");
  execFileSync(bindgen, [
    "--target",
    "web",
    "--omit-default-module-path",
    "--out-dir",
    out,
    "--out-name",
    "named",
    join(targetDir, "wasm32-unknown-unknown", "wasm-release", "frasil_wasm.wasm"),
  ]);
  const module = readFileSync(join(out, "named_bg.wasm"));
  rmSync(out, { recursive: true, force: true });
  const byCrate = codeByCrate(module);
  const total = [...byCrate.values()].reduce((sum, size) => sum + size, 0);
  console.log(`\ncode section by crate (${total.toLocaleString("en")} bytes of function bodies):`);
  for (const [crate, size] of [...byCrate.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)) {
    console.log(
      `  ${crate.padEnd(28)} ${size.toLocaleString("en").padStart(9)}  ${((100 * size) / total).toFixed(1).padStart(5)} %`,
    );
  }
}

/**
 * The size of each function body, summed by the crate its (legacy-mangled) name starts with.
 *
 * @param {Buffer} bytes
 */
function codeByCrate(bytes) {
  let offset = 8;
  /** @returns {number} */
  const leb = () => {
    let result = 0;
    let shift = 0;
    for (;;) {
      const byte = bytes[offset++] ?? 0;
      result += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (byte < 0x80) return result;
    }
  };
  let imported = 0;
  /** @type {number[]} */
  const bodies = [];
  /** @type {Map<number, string>} */
  const names = new Map();
  while (offset < bytes.length) {
    const id = bytes[offset++];
    const size = leb();
    const end = offset + size;
    if (id === 2) {
      // Imports: count the functions, whose indices come first.
      const count = leb();
      for (let index = 0; index < count; index += 1) {
        // Module and field names: a length, then that many bytes.
        for (let name = 0; name < 2; name += 1) {
          const length = leb();
          offset += length;
        }
        const kind = bytes[offset++];
        if (kind === 0) {
          leb();
          imported += 1;
        } else if (kind === 1) {
          offset += 1;
          const flags = leb();
          leb();
          if (flags & 1) leb();
        } else if (kind === 2) {
          const flags = leb();
          leb();
          if (flags & 1) leb();
        } else if (kind === 3) {
          offset += 2;
        } else {
          leb();
        }
      }
    } else if (id === 10) {
      const count = leb();
      for (let index = 0; index < count; index += 1) {
        const length = leb();
        bodies.push(length);
        offset += length;
      }
    } else if (id === 0) {
      const nameLength = leb();
      const name = bytes.subarray(offset, offset + nameLength).toString();
      offset += nameLength;
      if (name === "name") {
        while (offset < end) {
          const kind = bytes[offset++];
          const length = leb();
          const next = offset + length;
          if (kind === 1) {
            const count = leb();
            for (let index = 0; index < count; index += 1) {
              const at = leb();
              const text = leb();
              names.set(at, bytes.subarray(offset, offset + text).toString());
              offset += text;
            }
          }
          offset = next;
        }
      }
    }
    offset = end;
  }
  /** @type {Map<string, number>} */
  const byCrate = new Map();
  bodies.forEach((size, index) => {
    const crate = crateOf(names.get(imported + index) ?? "");
    byCrate.set(crate, (byCrate.get(crate) ?? 0) + size);
  });
  return byCrate;
}

/**
 * The crate a demangled symbol belongs to: its first path segment, or for `<T as Trait>::f`
 * the crate of `T`.
 */
function crateOf(/** @type {string} */ symbol) {
  const path = symbol.replace(/^(<|&|mut |dyn |\[|\()+/, "");
  const crate = /^([A-Za-z_][A-Za-z0-9_]*)::/.exec(path)?.[1];
  if (crate) return crate;
  if (/^(__|dlmalloc|memcpy|memset|memmove|memcmp)/.test(symbol)) return "(runtime)";
  return symbol ? "(exported shims)" : "(unnamed)";
}
