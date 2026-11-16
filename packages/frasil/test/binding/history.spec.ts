/**
 * History through the package, in a browser: a document's changes name the device that made
 * them, in order, with a span and a version before and after each, and a checkout at either; a
 * table's changes name the rows and columns written, and a replay says what a row held after each.
 */
import { expect, test } from "@playwright/test";

import { devicePage, uniqueName } from "./harness.js";

test("a document's and a table's history name their changes, and a checkout reads back", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  const { id: device } = await page.evaluate((n) => window.agent.create(n), uniqueName("history"));
  const space = await page.evaluate(() => window.agent.createSpace());
  const doc = await page.evaluate((s) => window.agent.createDocument(s), space);
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "hello"), [space, doc]);
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 5, 0, " world"), [space, doc]);

  const history = await page.evaluate(([s, d]) => window.agent.history(s, d), [space, doc]);
  expect(history).toHaveLength(2);
  for (const change of history) {
    expect(change.author.device).toBe(device);
    expect(change.author.persons).toEqual([]);
    expect(change.kind).toBe("edit");
    expect(change.effect).toBe("applied");
    expect(change.containers).toEqual(["cid:root-body:Text"]);
    expect(typeof change.time).toBe("number");
  }
  expect(history[0].height).toBeLessThanOrEqual(history[1].height);
  const second = history[1];
  if (!second.span || !second.before || !second.after) throw new Error("a document change");
  expect(second.span.to - second.span.from).toBe(6);
  const before = await page.evaluate(
    ([s, d, v]) => window.agent.documentAt(s, d, v),
    [space, doc, second.before],
  );
  const after = await page.evaluate(
    ([s, d, v]) => window.agent.documentAt(s, d, v),
    [space, doc, second.after],
  );
  expect(before.size).toBeGreaterThan(0);
  expect(after.size).toBeGreaterThan(before.size);
  expect(after.digest).not.toBe(before.digest);

  const records = await page.evaluate((s) => window.agent.createRecords(s), space);
  await page.evaluate(
    ([s, r]) => window.agent.writeCell(s, r, "cues", "c1", "level", 1, true),
    [space, records],
  );
  await page.evaluate(
    ([s, r]) => window.agent.writeCell(s, r, "cues", "c1", "level", 2, false),
    [space, records],
  );
  const tables = await page.evaluate(
    ([s, r]) => window.agent.recordsHistory(s, r),
    [space, records],
  );
  expect(tables).toHaveLength(2);
  expect(tables[0].rows).toHaveLength(1);
  expect(tables[0].rows?.[0].table).toBe("cues");
  expect(tables[0].rows?.[0].key).toBe("c1");
  expect(Array.from(tables[0].rows?.[0].keyBytes ?? [])).toEqual([0x63, 0x31]);
  expect(tables[0].rows?.[0].inserted).toBe(true);
  expect(tables[0].rows?.[0].columns).toEqual(["level"]);
  expect(tables[1].rows?.[0].inserted).toBe(false);
  // A table change carries its writer's claimed time, in seconds since 1970.
  expect(tables[0].time).toBeGreaterThan(1_600_000_000);
  const afterFirst = await page.evaluate(
    ([s, r, c]) => window.agent.recordsAt(s, r, c, "cues", "c1"),
    [space, records, tables[0].id],
  );
  const afterSecond = await page.evaluate(
    ([s, r, c]) => window.agent.recordsAt(s, r, c, "cues", "c1"),
    [space, records, tables[1].id],
  );
  expect(afterFirst).toEqual({ level: 1 });
  expect(afterSecond).toEqual({ level: 2 });
  expect(errors).toEqual([]);
});
