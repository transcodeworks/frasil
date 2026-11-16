// @ts-nocheck: served to the worker as it is, where `/dist/index/indexed.js` is the built entry.
//
// The dedicated worker of `index.spec.ts`: it opens a device in memory and its index in the
// origin-private file system, from the entry `@frasil/client/index`, follows the device, serves the
// index to the page, and writes rows when the page asks.
import * as frasil from "/dist/index/indexed.js";

const manifest = {
  format: 1,
  tables: [
    {
      name: "task",
      source: "tasks",
      suggestions: false,
      columns: [
        { name: "title", kind: "text", nullable: false },
        { name: "done", kind: "bool", nullable: false },
      ],
    },
  ],
};

try {
  const device = await frasil.Device.open(
    frasil.Storage.memory(),
    crypto.getRandomValues(new Uint8Array(32)),
  );
  const name = `frasil-test-index-${Math.random().toString(16).slice(2)}`;
  const index = await frasil.Index.open(device, name, manifest);
  /** @type {string[]} */
  const errors = [];
  void index.follow((message) => errors.push(message));
  frasil.serveIndex(index, self);
  const space = await device.createSpaceOfKind("tasks");
  const tasks = space.createRecords();
  self.addEventListener("message", async (event) => {
    const { op, key, title } = event.data ?? {};
    try {
      if (op === "write") {
        await tasks.write((tx) =>
          tx.insert("task", key).set("task", key, "title", title).set("task", key, "done", false),
        );
        self.postMessage({ wrote: key });
      } else if (op === "refuse") {
        try {
          index.query("DELETE FROM task");
          self.postMessage({ refused: null });
        } catch (error) {
          self.postMessage({ refused: error.code });
        }
      } else if (op === "facts") {
        // A second index, under another name, in the same worker: a pool of its own.
        const second = await frasil.Index.open(device, `${name}-second`, manifest);
        self.postMessage({
          facts: {
            manifest: JSON.parse(index.manifest).tables.map((t) => t.name),
            second: JSON.parse(second.manifest).tables.map((t) => t.name),
            revision: index.revision,
            errors,
          },
        });
      }
    } catch (error) {
      self.postMessage({ failed: String(error?.message ?? error) });
    }
  });
  self.postMessage({ ready: true });
} catch (error) {
  self.postMessage({ failed: String(error?.message ?? error) });
}
