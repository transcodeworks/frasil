/**
 * Drives (ext-drive.md) through the package, in a browser: a drive with folders, a file over a
 * Blobs stream and a document; shown names, moves, refusals, application fields, the trash and a
 * purge; the change feed; and the drive opened again after a reload, from IndexedDB. Batches of
 * changes, written all or none, and the feed's report of the application's own root containers.
 */
import { expect, test } from "@playwright/test";

import type * as Frasil from "../../src/index.js";
import { devicePage, reload, uniqueName } from "./harness.js";

/** What the page holds besides the agent: the package, and the agent's device. */
type Page = {
  frasil: typeof Frasil;
  agent: { device: Frasil.Device };
};

test("a drive's entries, changes, trash and purge, and the drive after a reload", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  const name = uniqueName("drive");
  await page.evaluate((n) => window.agent.create(n), name);
  const space = await page.evaluate(() => window.agent.createSpace());

  const result = await page.evaluate(async (spaceId) => {
    const { frasil, agent } = window as unknown as Page;
    const space = await agent.device.space(spaceId);
    const drive = await frasil.Drive.create(space);
    const changed: string[][] = [];
    const stop = await drive.onChange((change) => changed.push(change.entries));

    const scripts = await drive.addFolder(null, "Scripts");
    const again = await drive.addFolder(null, "Scripts");
    const files = space.createBlobs();
    const blob = await files.put(new TextEncoder().encode("hello"), { name: "a.txt" });
    const file = await drive.addFile(scripts, "a.txt", {
      stream: files.id,
      blob,
      size: 5,
      mediaType: "text/plain",
    });
    const sheet = space.createDocument();
    await sheet.edit((doc) => doc.map("cells").set("A1", 1));
    const listed = await drive.addDocument(null, "Budget", sheet.id, "example.spreadsheet");

    const refusals: string[] = [];
    const refused = async (body: () => Promise<unknown>) => {
      try {
        await body();
        refusals.push("written");
      } catch (error) {
        refusals.push((error as { code: string }).code);
      }
    };
    await refused(() => drive.addFolder(null, "a/b"));
    await refused(() => drive.moveTo(scripts, scripts));
    await refused(() => drive.addDocument(null, "Twice", sheet.id, "example.spreadsheet"));
    await refused(() => frasil.Drive.open(space, sheet.id));

    const before = (await drive.entries()).map((e) => e.shownName);
    await drive.rename(file, "b.txt");
    await drive.moveTo(scripts, again);
    await drive.setMeta(file, "example.color", "red");
    const root = (await drive.entries()).map((e) => e.shownName);
    const inner = await drive.entries(again);
    const fileEntry = await drive.entry(file);

    await drive.moveToTrash(again);
    const trash = (await drive.trash()).map((e) => e.id);
    const trashed = (await drive.entry(file))?.inTrash;
    await drive.restore(again);
    const released = await drive.purge(scripts);
    const after = (await drive.all()).map((e) => e.id);
    const byStream = (await drive.entryFor(sheet.id))?.id;
    await new Promise((resolve) => setTimeout(resolve, 200));
    stop();
    return {
      id: drive.id,
      ids: { scripts, again, file, listed, blob, files: files.id },
      before,
      root,
      inner: inner.map((e) => [e.id, e.shownName, e.parent]),
      fileEntry,
      refusals,
      trash,
      trashed,
      released,
      after,
      byStream,
      changed: changed.flat(),
    };
  }, space);

  const { ids } = result;
  expect(result.before).toEqual(["Scripts", "Scripts (2)", "Budget"]);
  expect(result.root).toEqual(["Scripts", "Budget"]);
  expect(result.inner).toEqual([[ids.scripts, "Scripts", ids.again]]);
  expect(result.fileEntry).toMatchObject({
    kind: "file",
    name: "b.txt",
    parent: ids.scripts,
    stream: ids.files,
    blob: ids.blob,
    size: 5,
    mediaType: "text/plain",
    inTrash: false,
    meta: { "example.color": "red" },
  });
  expect(result.refusals).toEqual([
    "invalid_input",
    "invalid_input",
    "invalid_input",
    "invalid_input",
  ]);
  expect(result.trash).toEqual([ids.again]);
  expect(result.trashed).toBe(true);
  expect(result.released).toEqual([{ stream: ids.files, blob: ids.blob }]);
  expect(result.after).toEqual([ids.again, ids.listed]);
  expect(result.byStream).toBe(ids.listed);
  expect(result.changed).toEqual(expect.arrayContaining([ids.scripts, ids.file, ids.listed]));

  // After a reload, the drive opens from the device's store as it was.
  await reload(page);
  await page.evaluate((n) => window.agent.open(n), name);
  const reopened = await page.evaluate(
    async ([spaceId, driveId]) => {
      const { frasil, agent } = window as unknown as Page;
      const drive = await frasil.Drive.open(await agent.device.space(spaceId), driveId);
      return (await drive.entries()).map((e) => [e.kind, e.shownName]);
    },
    [space, result.id] as const,
  );
  expect(reopened).toEqual([
    ["folder", "Scripts"],
    ["document", "Budget"],
  ]);
  await page.evaluate(() => window.agent.close());
  expect(errors).toEqual([]);
});

test("a drive's batches are written all or none, and its feed reports root containers", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  await page.evaluate((n) => window.agent.create(n), uniqueName("batch"));
  const space = await page.evaluate(() => window.agent.createSpace());

  const result = await page.evaluate(async (spaceId) => {
    const { frasil, agent } = window as unknown as Page;
    const space = await agent.device.space(spaceId);
    const drive = await frasil.Drive.create(space);
    const changes: Frasil.DriveChange[] = [];
    const stop = await drive.onChange((change) => changes.push(change));
    const settle = () => new Promise((resolve) => setTimeout(resolve, 200));

    // A typed folder, and a note with its attachment, each as one change.
    const folder = await drive.batch((b) => {
      const folder = b.addFolder(null, "Invoices");
      b.setMeta(folder, "example.type", "invoices");
      return folder;
    });
    const files = space.createBlobs();
    const blob = await files.put(new TextEncoder().encode("png"), { name: "scan.png" });
    const note = space.createDocument();
    await note.edit((doc) => doc.text("body").insert(0, "x"));
    const [listed, attachment] = await drive.batch((b) => {
      const listed = b.addDocument(folder, "Note", note.id, "example.note");
      const attachment = b.addFile(folder, "scan.png", { stream: files.id, blob });
      b.setMeta(attachment, "example.note", listed);
      return [listed, attachment];
    });
    await settle();
    const added = changes.at(-1)?.entries;

    // A refusal, or the callback's own error, writes nothing of the batch.
    const before = await drive.all();
    const outcomes: unknown[] = [];
    try {
      await drive.batch((b) => {
        b.rename(folder, "Renamed");
        b.setMeta(folder, "", 1);
      });
    } catch (error) {
      outcomes.push((error as { code: string }).code);
    }
    try {
      await drive.batch((b) => {
        b.purge(attachment);
        throw new Error("changed its mind");
      });
    } catch (error) {
      outcomes.push((error as Error).message);
    }
    const unchanged = JSON.stringify(await drive.all()) === JSON.stringify(before);

    // A note purged with its attachment, together; a batch kept past its callback refuses.
    const kept: { batch?: Frasil.DriveBatch } = {};
    const released = await drive.batch((b) => {
      kept.batch = b;
      return [...b.purge(listed), ...b.purge(attachment)];
    });
    try {
      kept.batch?.addFolder(null, "Late");
      outcomes.push("written");
    } catch (error) {
      outcomes.push((error as { code: string }).code);
    }
    await settle();
    const purged = changes.at(-1)?.entries;

    // A root container of the application's own.
    const document = await space.document(drive.id);
    await document.edit((doc) => doc.map("example.labels").set("red", "Urgent"));
    await settle();
    const labels = changes.at(-1);
    stop();
    return {
      ids: { folder, listed, attachment, blob, files: files.id },
      meta: (await drive.entry(folder))?.meta,
      added,
      outcomes,
      unchanged,
      released,
      purged,
      after: (await drive.all()).map((e) => e.id),
      labels,
    };
  }, space);

  const { ids } = result;
  expect(result.meta).toEqual({ "example.type": "invoices" });
  expect(result.added).toEqual([ids.listed, ids.attachment].sort());
  expect(result.outcomes).toEqual(["invalid_input", "changed its mind", "invalid_input"]);
  expect(result.unchanged).toBe(true);
  expect(result.released).toEqual([{ stream: ids.files, blob: ids.blob }]);
  expect(result.purged).toEqual([ids.listed, ids.attachment].sort());
  expect(result.after).toEqual([ids.folder]);
  expect(result.labels).toEqual({ entries: [], roots: ["example.labels"], origin: "local" });
  await page.evaluate(() => window.agent.close());
  expect(errors).toEqual([]);
});

test("a file's versions name their author, a conflict shows its heads, and an old version comes back", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  const name = uniqueName("versions");
  await page.evaluate((n) => window.agent.create(n), name);
  const { person } = await page.evaluate((n) => window.agent.makePerson(n), name);
  const space = await page.evaluate(() => window.agent.createSpace());

  const result = await page.evaluate(async (spaceId) => {
    const { frasil, agent } = window as unknown as Page;
    const space = await agent.device.space(spaceId);
    const drive = await frasil.Drive.create(space);
    const files = space.createBlobs();
    const text = (t: string) => new TextEncoder().encode(t);
    const first = await files.put(text("draft"));
    const file = await drive.addFile(null, "plan.txt", { stream: files.id, blob: first });
    const second = await files.put(text("final"));
    await drive.setBlob(file, { stream: files.id, blob: second }, [first]);
    // A save from a stale copy: a second head.
    const stale = await files.put(text("stale"));
    await drive.setBlob(file, { stream: files.id, blob: stale }, [first]);
    const conflicted = await drive.entry(file);
    const conflicts = (await drive.conflicts()).map((entry) => entry.id);
    const versions = await drive.versions(file);

    const restored = await drive.restoreVersion(file, first);
    const after = await drive.entry(file);
    const bytes = await files.get(restored);
    return {
      device: agent.device.id,
      first,
      second,
      stale,
      file,
      heads: [...(conflicted?.heads ?? [])].sort(),
      current: conflicted?.blob,
      conflicts,
      versions: versions.map((v) => ({
        blob: v.blob,
        parents: v.parents,
        device: v.author?.device,
        person: v.author?.person,
      })),
      restored,
      afterBlob: after?.blob,
      afterHeads: after?.heads,
      afterConflicts: (await drive.conflicts()).length,
      afterVersions: (await drive.versions(file)).length,
      text: bytes ? new TextDecoder().decode(bytes) : undefined,
    };
  }, space);

  expect(result.current).toBe(result.second);
  expect(result.heads).toEqual([result.second, result.stale].sort());
  expect(result.conflicts).toEqual([result.file]);
  expect(result.versions.map((v) => v.blob).sort()).toEqual(
    [result.first, result.second, result.stale].sort(),
  );
  for (const version of result.versions) {
    expect(version.device).toBe(result.device);
    expect(version.person).toBe(person);
  }
  expect(result.afterBlob).toBe(result.restored);
  expect(result.afterHeads).toEqual([result.restored]);
  expect(result.afterConflicts).toBe(0);
  expect(result.afterVersions).toBe(4);
  expect(result.text).toBe("draft");
  await page.evaluate(() => window.agent.close());
  expect(errors).toEqual([]);
});
