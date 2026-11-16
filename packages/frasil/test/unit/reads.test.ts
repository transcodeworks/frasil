/**
 * Reads for applications that cache, from the built package, on one device in memory: feeds that
 * say what changed, shared stores, waits, a blob's status and ranges, ranges of rows, receipts,
 * typed tables and the manifest's types.
 */
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type * as F from "../../src/index.js";

type Frasil = typeof import("../../src/index.js");
const dist = fileURLToPath(new URL("../../dist/", import.meta.url));
let frasil: Frasil;
let device: F.Device;

beforeAll(async () => {
  frasil = (await import(join(dist, "index.js"))) as Frasil;
  device = await frasil.Device.open(
    frasil.Storage.memory(),
    crypto.getRandomValues(new Uint8Array(32)),
  );
});

afterAll(async () => {
  await device.close();
});

/** Resolves with the store's first snapshot that `ready` accepts. */
function until<T>(store: F.Observable<T>, ready: (value: T) => boolean): Promise<T> {
  return new Promise((resolve) => {
    const check = () => {
      const now = store.get();
      if (now.status === "ready" && ready(now.value as T)) {
        stop();
        resolve(now.value as T);
      }
    };
    const stop = store.subscribe(check);
    check();
  });
}

/** The next item a feed gives. */
function next<T>(listen: (callback: (item: T) => void) => () => void): Promise<T> {
  return new Promise((resolve) => {
    const stop = listen((item) => {
      stop();
      resolve(item);
    });
  });
}

describe("records", () => {
  it("say which rows a write touched, and where it was made", async () => {
    const space = await device.createSpace();
    const records = space.createRecords();
    const spaceChange = next<F.SpaceChange>((cb) => space.onChange(cb));
    const change = next<F.RecordChange>((cb) => records.onChange(cb));
    await records.write((tx) => tx.insert("tasks", "b").insert("tasks", "a"));
    expect(await change).toEqual({
      kind: "rows",
      table: "tasks",
      keys: ["a", "b"],
      rawKeys: [new TextEncoder().encode("a"), new TextEncoder().encode("b")],
      origin: "local",
    });
    const seen = await spaceChange;
    expect(seen.origin).toBe("local");
    expect(seen.streams).toContain(records.id);
  });

  it("observe a table in one shared store, told only of different rows", async () => {
    const space = await device.createSpace();
    const records = space.createRecords();
    await records.write((tx) => tx.insert("tasks", "t1").set("tasks", "t1", "title", "One"));
    const tasks = records.observeRows("tasks");
    expect(records.observeRows("tasks")).toBe(tasks);
    let told = 0;
    const stop = tasks.subscribe(() => {
      told += 1;
    });
    await until(tasks, (rows) => rows.size === 1);
    const first = tasks.get();
    await records.write((tx) => tx.insert("lists", "l1"));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(tasks.get()).toBe(first);
    await records.write((tx) => tx.set("tasks", "t1", "title", "Uno"));
    const rows = await until(tasks, (rows) => rows.get("t1")?.title === "Uno");
    expect(rows.size).toBe(1);
    expect(told).toBe(2);

    const row = records.observeRow("tasks", "t1");
    await until(row, (value) => value?.title === "Uno");
    stop();
  });

  it("read by range and by prefix, write with a receipt, and read typed", async () => {
    const space = await device.createSpace();
    const records = space.createRecords();
    await records.write((tx) => {
      for (const key of ["a/1", "a/2", "a/3", "b/1"]) tx.insert("t", key).set("t", key, "n", key);
    });
    const page = await records.rowsRange("t", { limit: 2 });
    expect(page.map((entry) => entry.key)).toEqual(["a/1", "a/2"]);
    const rest = await records.rowsRange("t", { after: page[1]?.rawKey, limit: 10 });
    expect(rest.map((entry) => entry.key)).toEqual(["a/3", "b/1"]);
    expect([...(await records.rowsWithPrefix("t", "a/")).keys()]).toEqual(["a/1", "a/2", "a/3"]);

    const receipt = await records.writeWithReceipt((tx) => tx.insert("t", "c/1"));
    expect(receipt.unit).toMatch(/^[0-9a-f]{64}$/);
    expect(await receipt.isDurable()).toBe(false);
    await expect(receipt.durable(30)).rejects.toMatchObject({ code: "connection" });

    const schema: F.StandardSchemaV1<F.Row, { n: string }> = {
      "~standard": {
        version: 1,
        vendor: "test",
        validate: (value) => {
          const n = (value as { n?: unknown }).n;
          return typeof n === "string" ? { value: { n } } : { issues: [{ message: "no n" }] };
        },
      },
    };
    const typed = records.table("t", schema);
    expect((await typed.row("a/1"))?.n).toBe("a/1");
    await expect(typed.rows()).rejects.toMatchObject({ code: "invalid_input" });
    expect((await records.table("t", (row) => String(row.n ?? "")).rows()).get("c/1")).toBe("");
  });
});

describe("waits", () => {
  it("time out for what never arrives, and return what is here", async () => {
    const space = await device.createSpace();
    const missing = "07".repeat(16);
    await expect(space.documentWhenAvailable(missing, 50)).rejects.toMatchObject({
      code: "timeout",
    });
    const loading = space.observe(async (s) => (await s.records(missing)).rows("t"));
    const stop = loading.subscribe(() => {});
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(loading.get().status).toBe("loading");
    stop();
    const note = space.createDocument();
    await note.edit((doc) => doc.text("body").insert(0, "hi"));
    const found = await space.documentWhenAvailable(note.id, 1000);
    expect(await found.text("body")).toBe("hi");
    const receipt = await note.editWithReceipt((doc) => doc.text("body").insert(2, "!"));
    expect(receipt.unit).toMatch(/^[0-9a-f]{64}$/);
    const body = note.observe((doc) => doc.body);
    expect(await until(body, (text) => text === "hi!")).toBe("hi!");
  });
});

describe("blobs", () => {
  it("say what was put and removed, read by range, and give their status", async () => {
    const space = await device.createSpace();
    const blobs = space.createBlobs();
    const first = await blobs.put(new TextEncoder().encode("hello, world"), { name: "a" });
    const changes: F.BlobChange[] = [];
    const stop = await blobs.onChange((change) => changes.push(change));
    const list = blobs.observeList();
    const listed = until(list, (all) => all.length === 2);
    const second = await blobs.put(new Uint8Array([1, 2, 3]));
    expect((await listed).length).toBe(2);
    await blobs.remove(first);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(changes).toEqual([
      { kind: "added", id: second, origin: "local" },
      { kind: "removed", id: first, origin: "local" },
    ]);
    stop();
    expect(await blobs.status(second)).toEqual({ kind: "readable" });
    expect(await blobs.getRange(second, 1, 10)).toEqual(new Uint8Array([2, 3]));
    expect(await blobs.getWhenAvailable(second, 1000)).toEqual(new Uint8Array([1, 2, 3]));
    const status = blobs.observeStatus(second);
    expect(await until(status, (s) => s.kind === "readable")).toEqual({ kind: "readable" });
  });
});

describe("drives", () => {
  it("say where a change was made, observe their entries, and give receipts", async () => {
    const space = await device.createSpace();
    const drive = await frasil.Drive.create(space);
    const change = new Promise<F.DriveChange>((resolve) => {
      void drive.onChange(resolve);
    });
    const entries = drive.observe();
    expect(drive.observe()).toBe(entries);
    await new Promise((resolve) => setTimeout(resolve, 20));
    const { value: folder, receipt } = await drive.batchWithReceipt((b) =>
      b.addFolder(null, "Docs"),
    );
    expect(receipt?.unit).toMatch(/^[0-9a-f]{64}$/);
    expect(await change).toEqual({ entries: [folder], roots: [], origin: "local" });
    expect((await until(entries, (all) => all.length === 1))[0]?.name).toBe("Docs");
    const none = await drive.batchWithReceipt(() => 1);
    expect(none).toEqual({ value: 1, receipt: undefined });
  });
});

describe("manifest types", () => {
  it("are written for each table", () => {
    const manifest = {
      format: 1,
      built_in: [],
      spaces: [],
      tables: [
        {
          name: "task_item",
          source: "personal",
          suggestions: true,
          columns: [
            { name: "title", kind: "text", nullable: false },
            { name: "list", kind: "ref", nullable: true, references: "list" },
            { name: "done", kind: "bool", nullable: false },
          ],
        },
      ],
    };
    const types = frasil.manifestToTypeScript(manifest);
    expect(types).toContain("export interface TaskItemRow {");
    expect(types).toContain("  readonly list?: Uint8Array;");
    expect(types).toContain("  readonly done: number;");
    expect(types).toContain("  readonly _suggestion: string;");
    expect(types).toContain("  task_item: TaskItemRow;");
    expect(() => frasil.manifestToTypeScript({ format: 2 })).toThrow();
  });
});

describe("shared feeds and stores", () => {
  it("open one feed per Records stream for every observed row", async () => {
    const space = await device.createSpace();
    const records = space.createRecords();
    await records.write((tx) => {
      for (let i = 0; i < 50; i++) tx.insert("t", `r${i}`).set("t", `r${i}`, "n", i);
    });
    const started = { count: 0 };
    const startFeed = records.startFeed.bind(records);
    records.startFeed = (emit, fail) => {
      started.count += 1;
      return startFeed(emit, fail);
    };
    const stores = Array.from({ length: 50 }, (_, i) => records.observeRow("t", `r${i}`));
    const stops = stores.map((store) => store.subscribe(() => {}));
    await Promise.all(stores.map((store) => until(store, (row) => row !== undefined)));
    expect(started.count).toBe(1);
    await records.write((tx) => tx.set("t", "r7", "n", 700));
    expect(
      (await until(stores[7] as F.Observable<F.Row | undefined>, (row) => row?.n === 700))?.n,
    ).toBe(700);
    for (const stop of stops) stop();
  });

  it("give one store per table, validator and key, and one per document read", async () => {
    const space = await device.createSpace();
    const records = space.createRecords();
    const parse = (row: F.Row) => String(row.n ?? "");
    expect(records.table("t", parse).observeRows()).toBe(records.table("t", parse).observeRows());
    expect(records.table("t").observeRow("k")).toBe(records.table("t").observeRow("k"));
    expect(records.table("t", parse).observeRows()).not.toBe(records.table("t").observeRows());
    const note = space.createDocument();
    const read = (doc: { [container: string]: F.DocumentValue }) => doc.body;
    expect(note.observe(read)).toBe(note.observe(read));
  });
});

describe("the index client", () => {
  it("rejects queries once closed, and fails its live queries", async () => {
    const { port1 } = new MessageChannel();
    port1.start();
    const index = new frasil.IndexClient(port1);
    const pending = index.query("SELECT 1");
    const watched = index.watch("SELECT 1");
    const stop = watched.subscribe(() => {});
    index.close("the worker was terminated");
    await expect(pending).rejects.toMatchObject({ code: "closed" });
    await expect(index.query("SELECT 1")).rejects.toMatchObject({ code: "closed" });
    const again = index.watch("SELECT 2");
    const stopAgain = again.subscribe(() => {});
    expect(again.get().status).toBe("failed");
    stop();
    stopAgain();
    port1.close();
  });
});
