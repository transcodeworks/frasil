// Builds the package from a clean state:
//
// 1. crates/frasil-wasm for wasm32-unknown-unknown, with the workspace's `wasm-release`
//    profile (size-optimised, LTO), using the toolchain's default linker;
// 2. its JavaScript glue with wasm-bindgen --target web, at exactly the version Cargo.lock pins:
//    WASM_BINDGEN, else target/wasm-tools/bin/wasm-bindgen (scripts/check-js.sh installs it), else
//    `wasm-bindgen` on the PATH; the build fails on any other version;
// 3. the module's bytes as a base64 string module, for the entries that embed it;
// 4. the TypeScript layer with tsc, into dist/: its declarations documented and its JavaScript
//    without comments;
// 5. the entries, each a copy of the TypeScript layer over the module it loads, which is what
//    differs between them (the file `engine.js`):
//    - `@frasil/client` (dist/): loads dist/wasm/frasil_wasm_bg.wasm, found with
//      `new URL(…, import.meta.url)` and compiled while it downloads;
//    - `@frasil/client/embedded` (dist/embedded/): the module inlined as base64, for an
//      application that cannot host a file;
//    - `@frasil/client/module` (dist/module/): the bare module, frasil_wasm.wasm, which
//      `load` is given compiled, for a host that imports `.wasm` as a compiled module and refuses
//      to compile from bytes;
//    - `@frasil/client/index` and `@frasil/client/index/embedded` (dist/index/ and
//      dist/index-embedded/): a second build of the module with the `index` feature (SQLite, for a
//      dedicated worker), loaded from a file and inlined. The TypeScript layer compiles against
//      that build's glue, whose declarations hold the default build's and the index's;
//    - `@frasil/client/client` (dist/client.js): `IndexClient` alone, which loads no module;
//    - `@frasil/client/media` and `@frasil/client/media/worker` (dist/media.js and
//      dist/media-worker.js): the media helper and the service worker's handler, which load no
//      module;
// 6. `@frasil/client/media-sw.js` (dist/media-sw.js): the service worker's handler as a classic
//    script to host as it is, with its listeners.
//
// Cargo builds into CARGO_TARGET_DIR when it is set, and target/ otherwise.
//
//   node scripts/build.mjs            everything
//   FRASIL_NPM_DIST=…                 write the package there instead of to dist/ (scripts/bench-wasm.sh)
//   CARGO_PROFILE_WASM_RELEASE_OPT_LEVEL=z   build the module at another opt-level (cargo reads it)
//   node scripts/build.mjs --no-cargo reuse the last wasm build (TypeScript changes only)
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const packageDir = fileURLToPath(new URL("..", import.meta.url));
const root = join(packageDir, "..", "..");
const target = "wasm32-unknown-unknown";
const profile = "wasm-release";
const targetDir = process.env.CARGO_TARGET_DIR ?? join(root, "target");
const wasm = join(targetDir, target, profile, "frasil_wasm.wasm");
const generated = join(packageDir, "src", "wasm");
const generatedDefault = join(targetDir, "frasil-npm", "default");
const savedIndex = join(targetDir, "frasil-npm", "frasil_wasm_index.wasm");
const dist = process.env.FRASIL_NPM_DIST ?? join(packageDir, "dist");
const skipCargo = process.argv.includes("--no-cargo");

/**
 * @param {string} command
 * @param {string[]} args
 * @param {import("node:child_process").ExecFileSyncOptions} [options]
 */
function run(command, args, options = {}) {
  execFileSync(command, args, { stdio: "inherit", cwd: root, ...options });
}

/**
 * The `--remap-path-prefix` flags that make the module the same wherever it is built. Source
 * paths end up in panic locations inside the module. Of several prefixes that match a path, rustc
 * uses the last one given, so the most specific come last:
 *
 * - the home directory, as `~`, so no builder's user name is published;
 * - this repository, as `frasil`;
 * - the cargo home (`CARGO_HOME`, or `~/.cargo`), as `cargo`: the registry's sources, wherever
 *   the builder keeps them;
 * - the standard library's sources that the `rust-src` component installs, back to the
 *   `/rustc/<commit>` path the prebuilt standard library already carries. rustc writes the local
 *   path for code of the standard library that it compiles into this crate when that component is
 *   installed, and the virtual path when it is not, or when a caching wrapper such as a
 *   `RUSTC_WRAPPER` runs it; mapped back, both give the same bytes.
 */
function remapFlags() {
  const rustc = (/** @type {string[]} */ args) =>
    execFileSync("rustc", args, { cwd: root, encoding: "utf8" }).toString().trim();
  const sysroot = rustc(["--print", "sysroot"]);
  const commit = /^commit-hash: (\S+)$/m.exec(rustc(["-vV"]))?.[1];
  const cargoHome = process.env.CARGO_HOME ?? join(homedir(), ".cargo");
  const flags = [
    `--remap-path-prefix=${homedir()}=~`,
    `--remap-path-prefix=${root}=frasil`,
    `--remap-path-prefix=${cargoHome}=cargo`,
  ];
  if (commit) {
    flags.push(
      `--remap-path-prefix=${join(sysroot, "lib", "rustlib", "src", "rust")}=/rustc/${commit}`,
    );
  }
  return flags;
}

/** The version of wasm-bindgen that Cargo.lock pins. */
function pinnedBindgen() {
  const lock = readFileSync(join(root, "Cargo.lock"), "utf8");
  const version = /\[\[package\]\]\nname = "wasm-bindgen"\nversion = "([^"]+)"/.exec(lock)?.[1];
  if (!version) {
    console.error("build: Cargo.lock pins no wasm-bindgen");
    process.exit(1);
  }
  return version;
}

/**
 * The wasm-bindgen CLI to run: the first of WASM_BINDGEN, target/wasm-tools/bin/wasm-bindgen and
 * `wasm-bindgen` on the PATH that exists, which must be the version Cargo.lock pins, since the glue
 * it writes must match the macro the module was built with.
 */
function wasmBindgen() {
  const pinned = pinnedBindgen();
  const installed = join(root, "target", "wasm-tools", "bin", "wasm-bindgen");
  const bindgen = process.env.WASM_BINDGEN ?? (existsSync(installed) ? installed : "wasm-bindgen");
  let version;
  try {
    version = execFileSync(bindgen, ["--version"], { encoding: "utf8" }).trim().split(/\s+/)[1];
  } catch {
    console.error(
      `build: no wasm-bindgen at ${bindgen}: run scripts/check-js.sh once, or set WASM_BINDGEN.`,
    );
    process.exit(1);
  }
  if (version !== pinned) {
    console.error(`build: ${bindgen} is wasm-bindgen ${version}; Cargo.lock pins ${pinned}.`);
    process.exit(1);
  }
  return bindgen;
}

const bindgen = wasmBindgen();

/**
 * Builds the module, with `features`, unless `--no-cargo`; then writes its glue and its bytes as
 * base64 into `out`. `keep` is where the build's module is kept, for `--no-cargo`.
 *
 * @param {string[]} features
 * @param {string} out
 * @param {string} keep
 */
function module(features, out, keep) {
  if (!skipCargo) {
    const flags = remapFlags();
    run(
      "cargo",
      [
        "build",
        "--locked",
        "--target",
        target,
        "--profile",
        profile,
        "-p",
        "frasil-wasm",
        ...(features.length > 0 ? ["--features", features.join(",")] : []),
      ],
      { env: { ...process.env, CARGO_ENCODED_RUSTFLAGS: flags.join("\x1f") } },
    );
    mkdirSync(dirname(keep), { recursive: true });
    copyFileSync(wasm, keep);
  }
  rmSync(out, { recursive: true, force: true });
  run(bindgen, [
    "--target",
    "web",
    // The glue would otherwise refer to a .wasm file next to it, which bundlers try to resolve.
    "--omit-default-module-path",
    "--remove-name-section",
    "--remove-producers-section",
    "--out-dir",
    out,
    "--out-name",
    "frasil_wasm",
    keep,
  ]);
  const bytes = readFileSync(join(out, "frasil_wasm_bg.wasm"));
  writeFileSync(
    join(out, "frasil_wasm_base64.js"),
    `// Generated by scripts/build.mjs: the WebAssembly module, base64.\nexport default ${JSON.stringify(bytes.toString("base64"))};\n`,
  );
  writeFileSync(
    join(out, "frasil_wasm_base64.d.ts"),
    "/** The WebAssembly module, base64. */\ndeclare const base64: string;\nexport default base64;\n",
  );
  return bytes;
}

// The index's build first: the TypeScript layer compiles against its glue, in src/wasm.
const indexBytes = module(["index"], generated, savedIndex);
const bytes = module([], generatedDefault, join(targetDir, "frasil-npm", "frasil_wasm.wasm"));

rmSync(dist, { recursive: true, force: true });
// The declarations carry the documentation; the JavaScript ships without comments.
const tsc = join(packageDir, "node_modules", ".bin", "tsc");
const tsconfig = join(packageDir, "tsconfig.json");
run(tsc, ["-p", tsconfig, "--outDir", dist, "--emitDeclarationOnly"]);
run(tsc, ["-p", tsconfig, "--outDir", dist, "--declaration", "false", "--removeComments"]);
/** The names of a TypeScript file's outputs. */
const outputs = (/** @type {string[]} */ names) =>
  names
    .flatMap((name) => [`${name}.js`, `${name}.d.ts`])
    .filter((file) => existsSync(join(dist, file)));
const bindings = ["react", "svelte", "solid"];
// What only one entry holds, which the others' copies of the layer leave out.
const engines = ["engine", "engine-embedded", "engine-compiled"];
const compiledEntry = ["compiled", "load"];
const indexOnly = ["indexed"];
const clientOnly = ["client"];
const mediaOnly = ["media", "media-worker"];
const everything = readdirSync(dist).filter(
  (file) => file.endsWith(".js") || file.endsWith(".d.ts"),
);

/**
 * Writes the copy of the layer in `dir` (the default entry's, in dist/ itself): the shared files,
 * `engine` from `engine` (`engine`, `engine-embedded` or `engine-compiled`), the files named by
 * `extra`, and the module's glue from `glue`, with its bytes as a file or as base64.
 *
 * @param {string} dir
 * @param {{ glue: string, engine: string, extra?: string[], bytes: "file" | "base64" | "bare" }} entry
 */
function assemble(dir, entry) {
  const own = [
    ...engines,
    ...compiledEntry,
    ...indexOnly,
    ...bindings,
    ...clientOnly,
    ...mediaOnly,
  ];
  const keep = new Set([
    ...everything.filter(
      (file) => !own.some((name) => file === `${name}.js` || file === `${name}.d.ts`),
    ),
    ...outputs(entry.extra ?? []),
  ]);
  mkdirSync(join(dir, "wasm"), { recursive: true });
  for (const file of keep) if (dir !== dist) copyFileSync(join(dist, file), join(dir, file));
  for (const ext of ["js", "d.ts"]) {
    const from = join(dist, `${entry.engine}.${ext}`);
    const to = join(dir, `engine.${ext}`);
    if (existsSync(from) && from !== to) copyFileSync(from, to);
  }
  for (const file of ["frasil_wasm.js", "frasil_wasm.d.ts"]) {
    copyFileSync(join(entry.glue, file), join(dir, "wasm", file));
  }
  if (entry.bytes === "file") {
    copyFileSync(join(entry.glue, "frasil_wasm_bg.wasm"), join(dir, "wasm", "frasil_wasm_bg.wasm"));
  } else if (entry.bytes === "bare") {
    copyFileSync(join(entry.glue, "frasil_wasm_bg.wasm"), join(dir, "frasil_wasm.wasm"));
  } else {
    for (const file of ["frasil_wasm_base64.js", "frasil_wasm_base64.d.ts"]) {
      copyFileSync(join(entry.glue, file), join(dir, "wasm", file));
    }
  }
}

// The copies first, from the layer as tsc wrote it; then dist/ itself becomes the default entry.
assemble(join(dist, "embedded"), {
  glue: generatedDefault,
  engine: "engine-embedded",
  bytes: "base64",
});
assemble(join(dist, "module"), {
  glue: generatedDefault,
  engine: "engine-compiled",
  extra: compiledEntry,
  bytes: "bare",
});
assemble(join(dist, "index"), {
  glue: generated,
  engine: "engine",
  extra: indexOnly,
  bytes: "file",
});
assemble(join(dist, "index-embedded"), {
  glue: generated,
  engine: "engine-embedded",
  extra: indexOnly,
  bytes: "base64",
});
for (const name of [...engines.slice(1), ...compiledEntry, ...indexOnly]) {
  for (const file of outputs([name])) rmSync(join(dist, file));
}
// dist/ itself: the default entry, with the bindings and the page's client, which load no module
// of their own and so are not copied.
assemble(dist, {
  glue: generatedDefault,
  engine: "engine",
  extra: [...bindings, ...clientOnly, ...mediaOnly],
  bytes: "file",
});

// The service worker's handler as a script of its own: a classic script, which every browser
// that has service workers registers, so it holds neither `import` nor `export`.
const handler = readFileSync(join(dist, "media-worker.js"), "utf8");
if (/^\s*import\s/m.test(handler)) {
  console.error("build: src/media-worker.ts must import nothing: it is hosted as one script.");
  process.exit(1);
}
writeFileSync(
  join(dist, "media-sw.js"),
  `// The service worker of @frasil/client/media: host this file where its scope covers the pages
// that play media. It answers the requests for the URLs a page's MediaServer mints, by asking
// that page, and takes control of the origin's pages at once.
(() => {
${handler.replace(/^export /gm, "")}
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  handleMedia(event);
});
self.addEventListener("message", (event) => {
  handleMedia(event);
});
})();
`,
);

console.log(`built ${dist} (${bytes.length} bytes of WebAssembly, loaded from a file)`);
console.log(`built ${join(dist, "embedded")}, with the module inlined`);
console.log(`built ${join(dist, "module")}, with the bare module`);
console.log(
  `built ${join(dist, "index")} and index-embedded (${indexBytes.length} bytes of WebAssembly, with the index)`,
);
