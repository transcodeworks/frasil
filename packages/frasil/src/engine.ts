/**
 * Internal: where the WebAssembly module comes from, for the default entry: the file
 * `wasm/frasil_wasm_bg.wasm` next to this one, found with `new URL(…, import.meta.url)`, which
 * bundlers recognise and emit as an asset. The browser compiles it while it downloads
 * (`WebAssembly.instantiateStreaming`); where the server answers with a wrong MIME type, the
 * glue falls back to instantiating the bytes. Node.js, Bun and Deno read the file from disk, since
 * `fetch` does not take file URLs in every version of them. They find it from the module's own
 * `file:` URL, held in a variable: a bundler or test runner that serves a page, such as Vite under
 * Vitest's jsdom environment, rewrites the literal `new URL(…, import.meta.url)` to its server's
 * origin, where no server may run.
 *
 * The entries `@frasil/client/embedded`, `@frasil/client/index/embedded` and
 * `@frasil/client/module` replace this file with their own (`engine-embedded.ts`,
 * `engine-compiled.ts`) when the package is built.
 *
 * @internal
 * @module
 */

/** What the glue instantiates. */
export type Source = Response | BufferSource | WebAssembly.Module;

/** The module, once it is fetched or read. It starts as soon as the package is imported. */
export const engine: Promise<Source> = locate();

async function locate(): Promise<Source> {
  const runtime = globalThis as { process?: { versions?: { node?: string } } };
  const here = import.meta.url;
  if (here.startsWith("file:") && runtime.process?.versions?.node !== undefined) {
    // A variable specifier, so that no bundler follows it into a browser build.
    const specifier = "node:fs/promises";
    const { readFile } = (await import(/* @vite-ignore */ /* webpackIgnore: true */ specifier)) as {
      readFile(url: URL): Promise<Uint8Array<ArrayBuffer>>;
    };
    return readFile(new URL("./wasm/frasil_wasm_bg.wasm", here));
  }
  return fetch(new URL("./wasm/frasil_wasm_bg.wasm", import.meta.url));
}
