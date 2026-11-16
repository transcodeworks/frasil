/**
 * The package's entries in browsers: the default one loads the module from a file next to it,
 * compiled while it streams, and falls back to instantiating the bytes where the server names the
 * wrong MIME type; `embedded` and `index/embedded` carry the module inlined; a dedicated worker
 * finds the file too.
 */
import { expect, test } from "@playwright/test";

/** What a page does with an entry: loads it, opens a device in memory, makes a space. */
async function open(page: import("@playwright/test").Page, entry: string) {
  return page.evaluate(async (entry) => {
    const frasil = await import(/* @vite-ignore */ entry);
    const device = await frasil.Device.open(
      frasil.Storage.memory(),
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const space = await device.createSpace();
    const length = space.id.length;
    await device.close();
    const requested = performance
      .getEntriesByType("resource")
      .map((entry) => entry.name)
      .filter((name) => name.endsWith(".wasm"));
    return { length, requested };
  }, entry);
}

test("the default entry fetches the module as a file", async ({ page }) => {
  await page.goto("/runner.html");
  const { length, requested } = await open(page, "/dist/index.js");
  expect(length).toBe(64);
  expect(requested.some((url) => url.endsWith("/dist/wasm/frasil_wasm_bg.wasm"))).toBe(true);
});

test("the default entry falls back to the bytes where the MIME type is wrong", async ({ page }) => {
  await page.goto("/runner.html");
  const { length, requested } = await open(page, "/wrong-mime/dist/index.js");
  expect(length).toBe(64);
  expect(requested.some((url) => url.includes("/wrong-mime/dist/wasm/"))).toBe(true);
});

test("the embedded entry needs no file", async ({ page }) => {
  await page.goto("/runner.html");
  const { length, requested } = await open(page, "/dist/embedded/index.js");
  expect(length).toBe(64);
  expect(requested.filter((url) => url.includes("/dist/embedded/"))).toEqual([]);
});

for (const entry of ["/dist/index/indexed.js", "/dist/index-embedded/indexed.js"]) {
  test(`a dedicated worker loads ${entry}`, async ({ page }) => {
    await page.goto("/runner.html");
    const answer = await page.evaluate(async (entry) => {
      const source = `
        import(${JSON.stringify(new URL(entry, location.origin).href)})
          .then(async (frasil) => {
            const device = await frasil.Device.open(
              frasil.Storage.memory(),
              crypto.getRandomValues(new Uint8Array(32)),
            );
            postMessage({ id: device.id.length, hasIndex: typeof frasil.Index });
          })
          .catch((error) => postMessage({ failed: String(error?.message ?? error) }));`;
      const url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
      const worker = new Worker(url);
      return new Promise<Record<string, unknown>>((resolve) => {
        worker.addEventListener("message", (event) => resolve(event.data));
      });
    }, entry);
    expect(answer).toEqual({ id: 64, hasIndex: "function" });
  });
}
