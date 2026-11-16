/**
 * The entry `@frasil/client/index` in a dedicated worker: a device and its index over the
 * origin-private file system, followed as rows are written, and queried and watched from the page
 * through `IndexClient`, which loads no module of its own.
 */
import { expect, test } from "@playwright/test";

import type * as Frasil from "../../src/index.js";
import { devicePage } from "./harness.js";

test("a worker's index follows its device, and the page queries and watches it", async ({
  browser,
  browserName,
}) => {
  // Playwright's WebKit refuses the origin-private file system itself: `getDirectory()` and then
  // `getDirectoryHandle` fail with `UnknownError` in a page of its own, with no Frasil code.
  test.skip(browserName === "webkit", "Playwright's WebKit has no origin-private file system");
  const { page, errors } = await devicePage(browser);
  const result = await page.evaluate(async () => {
    const { IndexClient } = (window as unknown as { frasil: typeof Frasil }).frasil;
    const worker = new Worker("/test/binding/index-worker.js", { type: "module" });
    const from = (key: string) =>
      new Promise<Record<string, unknown>>((resolve, reject) => {
        const listener = (event: MessageEvent) => {
          const data = event.data as Record<string, unknown>;
          if (typeof data !== "object" || data === null) return;
          if ("failed" in data) reject(new Error(String(data.failed)));
          if (key in data) {
            worker.removeEventListener("message", listener);
            resolve(data);
          }
        };
        worker.addEventListener("message", listener);
      });
    await from("ready");
    const index = new IndexClient(worker);
    const watched = index.watch<{ title: string }>("SELECT title FROM task ORDER BY title");
    const seen: string[][] = [];
    const rows = (count: number) =>
      new Promise<void>((resolve) => {
        const check = () => {
          const now = watched.get();
          if (now.status === "ready" && now.value?.length === count) resolve();
        };
        watched.subscribe(() => {
          const now = watched.get();
          if (now.status === "ready") seen.push((now.value ?? []).map((row) => row.title));
          check();
        });
        check();
      });
    await rows(0);
    worker.postMessage({ op: "write", key: "t1", title: "One" });
    await from("wrote");
    await rows(1);
    worker.postMessage({ op: "write", key: "t2", title: "Two" });
    await from("wrote");
    await rows(2);
    const counted = await index.query<{ n: number }>(
      "SELECT count(*) AS n FROM task WHERE done = ?",
      [false],
    );
    const refusedQuery = await index.query("DELETE FROM task").then(
      () => null,
      (error: { code: string }) => error.code,
    );
    worker.postMessage({ op: "refuse" });
    const refused = (await from("refused")).refused;
    worker.postMessage({ op: "facts" });
    const facts = (await from("facts")).facts as {
      manifest: string[];
      second: string[];
      errors: string[];
    };
    worker.terminate();
    return { seen, counted, refusedQuery, refused, facts };
  });
  expect(result.seen.at(-1)).toEqual(["One", "Two"]);
  expect(result.counted).toEqual([{ n: 2 }]);
  expect(result.refusedQuery).toBe("index");
  expect(result.refused).toBe("index");
  expect(result.facts.manifest).toEqual(["task"]);
  expect(result.facts.second).toEqual(["task"]);
  expect(result.facts.errors).toEqual([]);
  expect(errors).toEqual([]);
});
