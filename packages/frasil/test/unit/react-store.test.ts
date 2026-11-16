// @vitest-environment jsdom
/**
 * A prebuilt store asked for during render, from the built package: the component renders a few
 * times as the rows arrive, and does not subscribe again on each render.
 */
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { expect, it } from "vitest";
import type * as F from "../../src/index.js";
import { useObserved } from "../../src/react.js";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
// Under jsdom, `import.meta.url` is no file URL: tests run from the package directory.
const dist = join(process.cwd(), "dist");

it("asks for a table's store during render without subscribing again each time", async () => {
  const frasil = (await import(pathToFileURL(join(dist, "index.js")).href)) as typeof F;
  const device = await frasil.Device.open(
    frasil.Storage.memory(),
    crypto.getRandomValues(new Uint8Array(32)),
  );
  const space = await device.createSpace();
  const records = space.createRecords();
  await records.write((tx) => tx.insert("t", "a").set("t", "a", "n", 1));
  let renders = 0;
  function Rows() {
    renders += 1;
    const rows = useObserved(records.table("t").observeRows());
    return createElement("p", null, rows.status === "ready" ? String(rows.value?.size) : "…");
  }
  const container = document.createElement("div");
  const root = createRoot(container);
  await act(async () => root.render(createElement(Rows)));
  await act(async () => new Promise((resolve) => setTimeout(resolve, 100)));
  expect(container.textContent).toBe("1");
  await act(async () => records.write((tx) => tx.insert("t", "b")));
  await act(async () => new Promise((resolve) => setTimeout(resolve, 100)));
  expect(container.textContent).toBe("2");
  const settled = renders;
  await act(async () => new Promise((resolve) => setTimeout(resolve, 200)));
  expect(renders).toBe(settled);
  expect(renders).toBeLessThan(10);
  await act(async () => root.unmount());
  await device.close();
});
