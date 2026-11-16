/**
 * The entry `@frasil/client/module`, from the built package: `load` instantiates the bare module
 * it is given, compiled, and returns the default entry's API; it refuses anything else.
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

const dist = fileURLToPath(new URL("../../dist/module/", import.meta.url));

it("loads the bare module it is given, and refuses anything else", async () => {
  const { load } = (await import(join(dist, "load.js"))) as typeof import("../../src/load.js");
  await expect(load({} as WebAssembly.Module)).rejects.toMatchObject({ code: "invalid_input" });
  const module = await WebAssembly.compile(await readFile(join(dist, "frasil_wasm.wasm")));
  const frasil = await load(module);
  const device = await frasil.Device.open(
    frasil.Storage.memory(),
    crypto.getRandomValues(new Uint8Array(32)),
  );
  expect((await device.createSpace()).id).toHaveLength(64);
  await device.close();
});
