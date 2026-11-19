/**
 * Devices in browsers and an always-on peer (`frasil-relay`, on loopback, through the test
 * origin's proxy): a space kept at the peer, a second browser admitted by a direct grant, Loro
 * documents written and synced through the peer both ways, devices that reload from their
 * IndexedDB store and catch up, and blobs over the peer's object routes. Each device is a page of
 * its own browser context.
 */
import { expect, test } from "@playwright/test";

import { devicePage, reload, uniqueName } from "./harness.js";

test("a device keeps a space at the peer, and its changes become durable there", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  await page.evaluate((name) => window.agent.create(name), uniqueName("alice"));
  const space = await page.evaluate(() => window.agent.createSpace());
  expect(await page.evaluate((s) => window.agent.level(s), space)).toBe("administer");
  const doc = await page.evaluate((s) => window.agent.createDocument(s), space);
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "kept"), [space, doc] as const);
  expect(await page.evaluate((s) => window.agent.outbox(s), space)).toBeGreaterThan(0);

  await page.evaluate(() => window.agent.connect());
  await page.evaluate((s) => window.agent.durable(s), space);
  const status = await page.evaluate(() => window.agent.status());
  expect(status).toMatchObject({ connected: true, closed: null, spaces: [space], refused: [] });

  // A new change goes to the peer live, and becomes durable.
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 4, 0, " live"), [space, doc] as const);
  await page.evaluate((s) => window.agent.durable(s), space);
  expect(await page.evaluate(() => window.agent.status())).toMatchObject({
    connected: true,
    refusedChanges: 0,
  });
  expect(await page.evaluate(([s, d]) => window.agent.text(s, d), [space, doc] as const)).toBe(
    "kept live",
  );
  // The device told of its own changes.
  expect(await page.evaluate(() => window.agent.told)).toContain(space);
  await page.evaluate(() => window.agent.close());
  expect(errors).toEqual([]);
});

test("a second browser, granted into the space directly, writes through the peer and catches up after a reload", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  const bob = await devicePage(browser);
  const bobName = uniqueName("bob");
  const bobKeys = await bob.page.evaluate((name) => window.agent.create(name), bobName);

  // Alice makes the space, grants Bob's device, writes, and keeps it all at the peer.
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("alice"));
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  await alice.page.evaluate(([s, id, keys]) => window.agent.grant(s, id, keys), [
    space,
    bobKeys.id,
    bobKeys.keys,
  ] as const);
  const doc = await alice.page.evaluate((s) => window.agent.createDocument(s), space);
  await alice.page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "from alice"), [
    space,
    doc,
  ] as const);
  await alice.page.evaluate(() => window.agent.connect());
  await alice.page.evaluate((s) => window.agent.durable(s), space);

  // Bob follows the space he was granted and takes its signed events from Alice, as the direct
  // grant hands them over; then he connects to the peer himself.
  expect(await bob.page.evaluate((s) => window.agent.follow(s), space)).toBe(space);
  const events = await alice.page.evaluate((s) => window.agent.signedEvents(s), space);
  const ingested = await bob.page.evaluate(([s, e]) => window.agent.ingest(s, e), [
    space,
    events,
  ] as const);
  expect(ingested.refused).toEqual([]);
  await bob.page.evaluate(() => window.agent.connect());
  await bob.page.evaluate(([s, d]) => window.agent.waitText(s, d, "from alice"), [
    space,
    doc,
  ] as const);
  expect(await bob.page.evaluate((s) => window.agent.level(s), space)).toBe("write");
  expect(await bob.page.evaluate((s) => window.agent.members(s), space)).toEqual(
    expect.arrayContaining([`${bobKeys.id}:write`]),
  );
  expect(await bob.page.evaluate(() => window.agent.told)).toContain(space);

  // Each one's new changes reach the other live, through the peer.
  await alice.page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "live: "), [
    space,
    doc,
  ] as const);
  await bob.page.evaluate(([s, d]) => window.agent.waitText(s, d, "live: from alice"), [
    space,
    doc,
  ] as const);
  await bob.page.evaluate(([s, d]) => window.agent.edit(s, d, 16, 0, " and bob"), [
    space,
    doc,
  ] as const);
  await bob.page.evaluate((s) => window.agent.durable(s), space);
  await alice.page.evaluate(([s, d]) => window.agent.waitText(s, d, "live: from alice and bob"), [
    space,
    doc,
  ] as const);

  // Bob goes away; Alice writes; Bob reloads, reads what his store kept, and catches up.
  await bob.page.evaluate(() => window.agent.close());
  await alice.page.evaluate(([s, d]) => window.agent.edit(s, d, 24, 0, " (while away)"), [
    space,
    doc,
  ] as const);
  await alice.page.evaluate((s) => window.agent.durable(s), space);
  await reload(bob.page);
  const reopened = await bob.page.evaluate((name) => window.agent.open(name), bobName);
  expect(reopened).toEqual({ id: bobKeys.id, continuity: "Current" });
  expect(await bob.page.evaluate(([s, d]) => window.agent.text(s, d), [space, doc] as const)).toBe(
    "live: from alice and bob",
  );
  await bob.page.evaluate(() => window.agent.connect());
  await bob.page.evaluate(
    ([s, d]) => window.agent.waitText(s, d, "live: from alice and bob (while away)"),
    [space, doc] as const,
  );
  expect((await bob.page.evaluate(() => window.agent.status())).refusedChanges).toBe(0);

  await alice.page.evaluate(() => window.agent.close());
  await bob.page.evaluate(() => window.agent.close());
  expect(alice.errors).toEqual([]);
  expect(bob.errors).toEqual([]);
});

test("a device reloads from its IndexedDB store and goes on writing", async ({ browser }) => {
  const { page, errors } = await devicePage(browser);
  const name = uniqueName("carol");
  const made = await page.evaluate((n) => window.agent.create(n), name);
  const space = await page.evaluate(() => window.agent.createSpace());
  const doc = await page.evaluate((s) => window.agent.createDocument(s), space);
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "before"), [space, doc] as const);
  await page.evaluate(() => window.agent.connect());
  await page.evaluate((s) => window.agent.durable(s), space);
  // A change written offline stays in the outbox, kept at rest.
  await page.evaluate(() => window.agent.disconnect());
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 6, 0, " offline"), [space, doc] as const);
  expect(await page.evaluate((s) => window.agent.outbox(s), space)).toBe(1);

  await reload(page);
  const reopened = await page.evaluate((n) => window.agent.open(n), name);
  expect(reopened).toEqual({ id: made.id, continuity: "Current" });
  expect(await page.evaluate(() => window.agent.spaces())).toEqual([space]);
  expect(await page.evaluate((s) => window.agent.documents(s), space)).toEqual([doc]);
  expect(await page.evaluate(([s, d]) => window.agent.text(s, d), [space, doc] as const)).toBe(
    "before offline",
  );
  expect(await page.evaluate((s) => window.agent.outbox(s), space)).toBe(1);

  // Connected again, the kept change and a new one become durable.
  await page.evaluate(() => window.agent.connect());
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 14, 0, ", after"), [space, doc] as const);
  await page.evaluate((s) => window.agent.durable(s), space);
  expect(await page.evaluate(([s, d]) => window.agent.text(s, d), [space, doc] as const)).toBe(
    "before offline, after",
  );
  await page.evaluate(() => window.agent.close());
  expect(errors).toEqual([]);
});

test("a blob goes to the peer over its object routes, and another browser fetches it", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  const bob = await devicePage(browser);
  const bobKeys = await bob.page.evaluate((name) => window.agent.create(name), uniqueName("bob"));
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("alice"));
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  await alice.page.evaluate(([s, id, keys]) => window.agent.grant(s, id, keys), [
    space,
    bobKeys.id,
    bobKeys.keys,
  ] as const);
  // Over one slice of the object routes (1,048,576 bytes), so it takes two requests each way.
  const blob = await alice.page.evaluate((s) => window.agent.putBlob(s, 1_500_000), space);
  // And one of three chunks put from a file, read a chunk at a time.
  const file = await alice.page.evaluate((s) => window.agent.putBlob(s, 2_600_000, true), space);
  await alice.page.evaluate(() => window.agent.connect());
  // The change that names the object waits until the peer holds the object.
  await alice.page.evaluate((s) => window.agent.durable(s), space);
  expect((await alice.page.evaluate(() => window.agent.status())).refused).toEqual([]);

  // Bob takes the space's signed events from Alice, so he knows the blob before he holds its
  // bytes; connected, he fetches them from the peer.
  const events = await alice.page.evaluate((s) => window.agent.signedEvents(s), space);
  await bob.page.evaluate((s) => window.agent.follow(s), space);
  const ingested = await bob.page.evaluate(([s, e]) => window.agent.ingest(s, e), [
    space,
    events,
  ] as const);
  expect(ingested.refused).toEqual([]);
  expect(
    await bob.page.evaluate(([s, st, b]) => window.agent.blobDigest(s, st, b), [
      space,
      blob.stream,
      blob.blob,
    ] as const),
  ).toBeNull();
  await bob.page.evaluate(() => window.agent.connect());
  for (const put of [blob, file]) {
    await bob.page.waitForFunction(
      async ([s, st, b, d]) => (await window.agent.blobDigest(s, st, b)) === d,
      [space, put.stream, put.blob, put.digest] as const,
      { timeout: 30_000, polling: 100 },
    );
  }
  expect((await bob.page.evaluate(() => window.agent.status())).refused).toEqual([]);
  await alice.page.evaluate(() => window.agent.close());
  await bob.page.evaluate(() => window.agent.close());
  expect(alice.errors).toEqual([]);
  expect(bob.errors).toEqual([]);
});

test("a guest leaves by a request that reaches its administrator's mailbox at the peer", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  const bob = await devicePage(browser);
  const bobKeys = await bob.page.evaluate((name) => window.agent.create(name), uniqueName("bob"));

  // Alice grants Bob's device as a guest of a session, writes, and keeps it all at the peer.
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("alice"));
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  const doc = await alice.page.evaluate((s) => window.agent.createDocument(s), space);
  await alice.page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "for the guest"), [
    space,
    doc,
  ] as const);
  await alice.page.evaluate(
    ([s, id, keys]) => window.agent.grantGuest(s, id, keys, "07".repeat(16)),
    [space, bobKeys.id, bobKeys.keys] as const,
  );
  await alice.page.evaluate(() => window.agent.connect());
  await alice.page.evaluate((s) => window.agent.durable(s), space);

  // Bob follows the space, connects, and writes as a guest.
  await bob.page.evaluate((s) => window.agent.follow(s), space);
  const events = await alice.page.evaluate((s) => window.agent.signedEvents(s), space);
  await bob.page.evaluate(([s, e]) => window.agent.ingest(s, e), [space, events] as const);
  await bob.page.evaluate(() => window.agent.connect());
  expect(await bob.page.evaluate((s) => window.agent.level(s), space)).toBe("write");
  const notes = await bob.page.evaluate((s) => window.agent.createDocument(s), space);
  expect(
    await bob.page.evaluate(([s, d]) => window.agent.editCode(s, d, "a guest's note"), [
      space,
      notes,
    ] as const),
  ).toBeNull();

  // He leaves: from then on his writes reject with `left`, and Alice, collecting her mailbox at
  // the peer, removes him.
  await bob.page.evaluate((s) => window.agent.leave(s), space);
  expect(
    await bob.page.evaluate(([s, d]) => window.agent.editCode(s, d, "after"), [
      space,
      notes,
    ] as const),
  ).toBe("left");
  await alice.page.evaluate(([s, id]) => window.agent.waitRemoved(s, id), [
    space,
    bobKeys.id,
  ] as const);

  await alice.page.evaluate(() => window.agent.close());
  await bob.page.evaluate(() => window.agent.close());
  expect(alice.errors).toEqual([]);
  expect(bob.errors).toEqual([]);
});

test("a device's membership calls answer through the binding", async ({ browser }) => {
  const { page, errors } = await devicePage(browser);
  const name = uniqueName("alice");
  await page.evaluate((n) => window.agent.create(n), name);
  expect(await page.evaluate((n) => window.agent.membershipCalls(n), name)).toEqual({
    delivery: true,
    canSuggest: false,
    removeSelf: "invalid_input",
    revoke: "invalid_input",
  });
  await page.evaluate(() => window.agent.close());
  expect(errors).toEqual([]);
});

test("a browser erases a space at the peer, which then refuses it", async ({ browser }) => {
  const alice = await devicePage(browser);
  const bob = await devicePage(browser);
  const bobKeys = await bob.page.evaluate((name) => window.agent.create(name), uniqueName("bob"));
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("alice"));
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  await alice.page.evaluate(([s, id, keys]) => window.agent.grant(s, id, keys), [
    space,
    bobKeys.id,
    bobKeys.keys,
  ] as const);
  const doc = await alice.page.evaluate((s) => window.agent.createDocument(s), space);
  await alice.page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "erased soon"), [
    space,
    doc,
  ] as const);
  await alice.page.evaluate(() => window.agent.connect());
  await alice.page.evaluate((s) => window.agent.durable(s), space);
  // Bob holds the space, as the direct grant hands it over, but is offline.
  await bob.page.evaluate((s) => window.agent.follow(s), space);
  const events = await alice.page.evaluate((s) => window.agent.signedEvents(s), space);
  await bob.page.evaluate(([s, e]) => window.agent.ingest(s, e), [space, events] as const);

  // Alice erases it: the peer acknowledges the erasure, and her device holds the space no more.
  expect(await alice.page.evaluate((s) => window.agent.erase(s), space)).not.toContain(space);

  // The peer executed it: Bob's present of the space is refused as erased.
  await bob.page.evaluate(() => window.agent.connect());
  expect(await bob.page.evaluate((s) => window.agent.refusedCode(s), space)).toBe("erased");
  await alice.page.evaluate(() => window.agent.close());
  await bob.page.evaluate(() => window.agent.close());
  expect(alice.errors).toEqual([]);
  expect(bob.errors).toEqual([]);
});
