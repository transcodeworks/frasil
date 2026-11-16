/**
 * The package's entries, from the built package, in Node.js: the default one reads the module
 * from the file next to it (Node.js has no `fetch` of file URLs in every version), the embedded
 * ones decode it, and every subpath of `exports` names a file that was built.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

const packageDir = fileURLToPath(new URL("../..", import.meta.url));
const dist = join(packageDir, "dist");

type Entry = typeof import("../../src/index.js");

async function makeSpace(frasil: Entry): Promise<number> {
  const device = await frasil.Device.open(
    frasil.Storage.memory(),
    crypto.getRandomValues(new Uint8Array(32)),
  );
  const space = await device.createSpace();
  const length = space.id.length;
  await device.close();
  return length;
}

it("the default entry loads the module from its file", async () => {
  expect(existsSync(join(dist, "wasm", "frasil_wasm_bg.wasm"))).toBe(true);
  expect(existsSync(join(dist, "wasm", "frasil_wasm_base64.js"))).toBe(false);
  expect(await makeSpace((await import(join(dist, "index.js"))) as Entry)).toBe(64);
});

it("the embedded entry carries the module and needs no file", async () => {
  expect(existsSync(join(dist, "embedded", "wasm", "frasil_wasm_base64.js"))).toBe(true);
  expect(existsSync(join(dist, "embedded", "wasm", "frasil_wasm_bg.wasm"))).toBe(false);
  expect(await makeSpace((await import(join(dist, "embedded", "index.js"))) as Entry)).toBe(64);
});

it("the index entries load, from a file and embedded", async () => {
  for (const dir of ["index", "index-embedded"]) {
    const entry = (await import(join(dist, dir, "indexed.js"))) as Entry & { Index: unknown };
    expect(typeof entry.Index).toBe("function");
    expect(await makeSpace(entry)).toBe(64);
  }
});

it("the client entry gives IndexClient and loads no module", async () => {
  const entry = (await import(join(dist, "client.js"))) as { IndexClient: unknown };
  expect(typeof entry.IndexClient).toBe("function");
});

it("every subpath of exports names a built file", () => {
  const manifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8")) as {
    exports: Record<string, string | Record<string, string>>;
  };
  const missing: string[] = [];
  for (const [subpath, target] of Object.entries(manifest.exports)) {
    const files = typeof target === "string" ? [target] : Object.values(target);
    for (const file of files)
      if (!existsSync(join(packageDir, file))) missing.push(`${subpath}: ${file}`);
  }
  expect(missing).toEqual([]);
});
