/**
 * The two stores, against what at-rest.md asks of a store: `get`, `scan` by prefix in bytewise
 * address order, and `commit`, which applies its deletes then its puts only if every expectation
 * holds; and the device's sealed keys beside them. IndexedDB is `fake-indexeddb`'s. Then a device
 * kept in an IndexedDB store, opened again, and one in memory using each kind of stream.
 */
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { Device } from "../../src/device.js";
import { IndexedDbStore, MemoryStore, Storage, type Store } from "../../src/stores.js";

const b = (...bytes: number[]) => new Uint8Array(bytes);

async function indexedDb(): Promise<IndexedDbStore> {
  return IndexedDbStore.open("test", new IDBFactory(), IDBKeyRange);
}

const stores: [string, () => Promise<Store>][] = [
  ["MemoryStore", async () => new MemoryStore()],
  ["IndexedDbStore", indexedDb],
];

describe.each(stores)("%s", (_, make) => {
  it("reads what a commit wrote, and nothing else", async () => {
    const store = await make();
    expect(await store.get(b(1))).toBeUndefined();
    expect(await store.commit({ expect: [], puts: [[b(1), b(10)]], deletes: [] })).toBe(true);
    expect(await store.get(b(1))).toEqual(b(10));
    expect(await store.get(b(1, 0))).toBeUndefined();
  });

  it("keeps the sealed device keys apart from the records", async () => {
    const store = await make();
    expect(await store.loadSealedKeys()).toBeUndefined();
    await store.saveSealedKeys(b(1, 2, 3));
    expect(await store.loadSealedKeys()).toEqual(b(1, 2, 3));
    expect(await store.scan(b())).toEqual([]);
  });

  it("scans a prefix in bytewise address order", async () => {
    const store = await make();
    const puts: [Uint8Array, Uint8Array][] = [
      [b(2, 0xff), b(4)],
      [b(2), b(1)],
      [b(3), b(5)],
      [b(2, 1, 0), b(3)],
      [b(1, 0xff), b(0)],
      [b(2, 1), b(2)],
    ];
    await store.commit({ expect: [], puts, deletes: [] });
    expect(await store.scan(b(2))).toEqual([
      [b(2), b(1)],
      [b(2, 1), b(2)],
      [b(2, 1, 0), b(3)],
      [b(2, 0xff), b(4)],
    ]);
    expect(await store.scan(b(0xff))).toEqual([]);
    expect((await store.scan(b())).length).toBe(6);
  });

  it("commits only when every expectation holds, deleting then putting", async () => {
    const store = await make();
    await store.commit({ expect: [], puts: [[b(1), b(1)]], deletes: [] });
    // The head moved: nothing changes.
    expect(
      await store.commit({ expect: [[b(1), b(9)]], puts: [[b(2), b(2)]], deletes: [b(1)] }),
    ).toBe(false);
    expect(await store.get(b(1))).toEqual(b(1));
    expect(await store.get(b(2))).toBeUndefined();
    // An address expected empty that holds a record.
    expect(await store.commit({ expect: [[b(1), null]], puts: [], deletes: [] })).toBe(false);
    // Both hold: a delete and a put of one address leaves it put.
    expect(
      await store.commit({
        expect: [
          [b(1), b(1)],
          [b(3), null],
        ],
        puts: [
          [b(1), b(7)],
          [b(3), b(3)],
        ],
        deletes: [b(1)],
      }),
    ).toBe(true);
    expect(await store.get(b(1))).toEqual(b(7));
    expect(await store.get(b(3))).toEqual(b(3));
  });
});

describe("a device in an IndexedDB store", () => {
  it("opens again from the keys it keeps beside its records, with what it wrote", async () => {
    const factory = new IDBFactory();
    const unlockKey = crypto.getRandomValues(new Uint8Array(32));
    const store = await IndexedDbStore.open("device", factory, IDBKeyRange);
    const device = await Device.open(Storage.of(store), unlockKey);
    expect(await store.loadSealedKeys()).toHaveLength(235);
    const space = await device.createSpace();
    const note = space.createDocument();
    await note.edit((doc) => doc.text("body").insert(0, "kept at rest"));
    const tasks = space.createRecords();
    await tasks.write((tx) => tx.insert("tasks", "t1").set("tasks", "t1", "title", "Call Ana"));
    const id = device.id;
    await device.close();
    device.free();
    store.close();

    const again = await IndexedDbStore.open("device", factory, IDBKeyRange);
    const opened = await Device.open(Storage.of(again), unlockKey);
    expect(opened.id).toBe(id);
    expect(await opened.advanced.continuity()).toBe("Current");
    const spaces = await opened.spaces();
    expect(spaces.map((s) => s.id)).toEqual([space.id]);
    const [held] = spaces;
    expect(await held?.level()).toBe("administer");
    expect(await (await held?.document(note.id))?.text("body")).toBe("kept at rest");
    expect(await (await held?.records(tasks.id))?.row("tasks", "t1")).toEqual({
      title: "Call Ana",
    });
    await expect(
      Device.open(Storage.of(again), crypto.getRandomValues(new Uint8Array(32))),
    ).rejects.toMatchObject({ name: "FrasilError", code: expect.any(String) });
    expect(() => device.events()).toThrow(expect.objectContaining({ code: "disposed" }));
    await opened.close();
  });
});

describe("a device in memory", () => {
  it("edits documents, tables and blobs, and tells its events", async () => {
    const device = await Device.open(Storage.memory(), crypto.getRandomValues(new Uint8Array(32)));
    const events = device.events();
    const space = await device.createSpace();
    expect(space.id).toMatch(/^[0-9a-f]{64}$/);
    expect(await space.members()).toEqual([
      expect.objectContaining({ id: device.id, kind: "device", level: "administer" }),
    ]);

    const note = space.createDocument();
    await note.edit((doc) => {
      doc.text("body").insert(0, "Héllo 👋").delete(0, 1).insert(0, "h");
      doc.map("meta").set("pinned", true).set("tags", ["a", 2]);
    });
    expect(await note.text("body")).toBe("héllo 👋");
    expect(await note.read()).toEqual({
      body: "héllo 👋",
      meta: { pinned: true, tags: ["a", 2] },
    });
    const changed = await events.next();
    expect(changed).toMatchObject({ kind: "changed", space: space.id });
    await expect(note.edit(() => {})).rejects.toMatchObject({ code: "adapter" });

    const table = space.createRecords();
    await table.write((tx) =>
      tx
        .insert("t", "a")
        .set("t", "a", "n", 7)
        .set("t", "a", "big", 2n ** 60n)
        .set("t", "a", "m", new Map([[1, "x"]])),
    );
    const rows = await table.rows("t");
    expect([...rows.keys()]).toEqual(["a"]);
    expect(rows.get("a")).toMatchObject({ n: 7, big: 2n ** 60n, m: new Map([[1, "x"]]) });
    // Negative integers, floats and booleans are cells of their own; NaN is refused.
    await table.write((tx) =>
      tx.set("t", "a", "neg", -1).set("t", "a", "ratio", 0.25).set("t", "a", "done", true),
    );
    expect((await table.row("t", "a")) ?? {}).toMatchObject({ neg: -1, ratio: 0.25, done: true });
    await expect(table.write((tx) => tx.set("t", "a", "n", Number.NaN))).rejects.toMatchObject({
      code: "invalid_input",
      whatToDo: expect.any(String),
    });

    const files = space.createBlobs();
    const blob = await files.put(new Uint8Array([1, 2, 3]), { name: "three.bin" });
    expect(await files.list()).toEqual([{ id: blob, name: "three.bin", size: 3 }]);
    expect(await files.get(blob)).toEqual(new Uint8Array([1, 2, 3]));

    expect((await space.streams()).map((s) => s.kind).sort()).toEqual([
      "blobs",
      "document",
      "records",
    ]);
    expect(await space.isDurable()).toBe(false);
    expect(await device.advanced.outbox(space)).toBeGreaterThan(0);
    await expect(device.space("00".repeat(32))).rejects.toMatchObject({
      code: "unknown_space",
      whatToDo: expect.stringContaining("create the space"),
    });
    await expect(space.document("zz")).rejects.toMatchObject({ code: "invalid_input" });
    events.close();
    await device.close();
  });
});
