/**
 * Versions and review through the package, in a browser: a tag on a document and on a table,
 * listed and read back, then removed; a table suggestion reviewed with the cell's value now and
 * the one suggested, then accepted.
 */
import { expect, test } from "@playwright/test";

import { devicePage, uniqueName } from "./harness.js";

test("versions are tagged, listed and removed, and a suggestion is reviewed", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  const { id: device } = await page.evaluate((n) => window.agent.create(n), uniqueName("toolkit"));
  const space = await page.evaluate(() => window.agent.createSpace());
  const doc = await page.evaluate((s) => window.agent.createDocument(s), space);
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "first"), [space, doc]);
  const first = await page.evaluate(
    ([s, d]) => window.agent.tag(s, d, "first draft"),
    [space, doc],
  );
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 5, 0, " second"), [space, doc]);
  expect(first.name).toBe("first draft");
  expect(first.author).toBe(device);
  expect(first.stream).toBe(doc);
  if (!("frontier" in first.marked)) throw new Error("a document version");
  const then = await page.evaluate(
    ([s, d, v]) => window.agent.documentAt(s, d, v),
    [space, doc, first.marked.frontier],
  );
  expect(then.size).toBeGreaterThan(0);

  const records = await page.evaluate((s) => window.agent.createRecords(s), space);
  await page.evaluate(
    ([s, r]) => window.agent.writeCell(s, r, "cues", "c1", "level", 1, true),
    [space, records],
  );
  const cues = await page.evaluate(
    ([s, r]) => window.agent.recordsTag(s, r, "cues v1"),
    [space, records],
  );
  if (!("change" in cues.marked)) throw new Error("a table version");
  const versions = await page.evaluate((s) => window.agent.versions(s), space);
  expect(versions.map((v) => v.name).sort()).toEqual(["cues v1", "first draft"]);
  const stream = await page.evaluate((s) => window.agent.versionsStream(s), space);
  expect(stream).toHaveLength(32);
  await page.evaluate(([s, v]) => window.agent.untag(s, v), [space, first.id]);
  const left = await page.evaluate((s) => window.agent.versions(s), space);
  expect(left.map((v) => v.id)).toEqual([cues.id]);

  const suggestion = await page.evaluate(
    ([s, r]) => window.agent.suggestCell(s, r, "cues", "c1", "level", 2),
    [space, records],
  );
  const review = await page.evaluate(
    ([s, r, id]) => window.agent.recordsReview(s, r, id),
    [space, records, suggestion],
  );
  expect(review.id).toBe(suggestion);
  expect(review.author).toBe(device);
  expect(review.changes).toHaveLength(1);
  const change = review.changes[0];
  if (change.kind !== "cell") throw new Error("a cell change");
  expect(change.column).toBe("level");
  expect(change.key).toBe("c1");
  expect(change.from).toBe(1);
  expect(change.to).toBe(2);
  await page.evaluate(
    ([s, r, id]) => window.agent.recordsAccept(s, r, id),
    [space, records, suggestion],
  );
  const after = await page.evaluate(
    ([s, r]) => window.agent.recordsHistory(s, r),
    [space, records],
  );
  expect(after.map((c) => c.kind)).toEqual(["edit", "suggestion", "review"]);
  expect(errors).toEqual([]);
});
