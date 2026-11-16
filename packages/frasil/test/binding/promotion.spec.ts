/**
 * A reader raised to `administer` writes through the peer (`frasil-relay`, through the test
 * origin's proxy): the raise hands the reader the space's upload key, and its first write, in a
 * Records stream another browser made, reaches that browser.
 */
import { expect, test } from "@playwright/test";

import { devicePage, uniqueName } from "./harness.js";

test("a reader made administrator writes through the peer", async ({ browser }) => {
  const alice = await devicePage(browser);
  const bob = await devicePage(browser);
  const bobKeys = await bob.page.evaluate((name) => window.agent.create(name), uniqueName("bob"));

  // Alice makes the space and a Records stream, grants Bob's device `read`, and keeps them at the
  // peer.
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("alice"));
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  const records = await alice.page.evaluate((s) => window.agent.createRecords(s), space);
  await alice.page.evaluate(
    ([s, r]) => window.agent.writeCell(s, r, "tasks", "t1", "title", "plan", true),
    [space, records] as const,
  );
  await alice.page.evaluate(([s, id, k]) => window.agent.grant(s, id, k, "read"), [
    space,
    bobKeys.id,
    bobKeys.keys,
  ] as const);
  await alice.page.evaluate(() => window.agent.connect());
  await alice.page.evaluate((s) => window.agent.durable(s), space);

  // Bob takes the space's events from Alice, as a direct grant hands them over, and connects.
  const events = await alice.page.evaluate((s) => window.agent.signedEvents(s), space);
  await bob.page.evaluate((s) => window.agent.follow(s), space);
  const ingested = await bob.page.evaluate(([s, e]) => window.agent.ingest(s, e), [
    space,
    events,
  ] as const);
  expect(ingested.refused).toEqual([]);
  await bob.page.evaluate(() => window.agent.connect());
  await bob.page.evaluate(([s, r]) => window.agent.waitCell(s, r, "tasks", "t1", "title", "plan"), [
    space,
    records,
  ] as const);
  expect(await bob.page.evaluate((s) => window.agent.level(s), space)).toBe("read");

  // Alice raises Bob to `administer` and waits for the peer to hold it.
  await alice.page.evaluate(([s, id]) => window.agent.setLevel(s, id, "administer"), [
    space,
    bobKeys.id,
  ] as const);
  await alice.page.evaluate((s) => window.agent.flush(s), space);

  // Bob's first write in the space reaches the peer, and Alice.
  await bob.page.evaluate((s) => window.agent.waitLevel(s, "administer"), space);
  await bob.page.evaluate(
    ([s, r]) => window.agent.writeCell(s, r, "tasks", "t2", "title", "approve", true),
    [space, records] as const,
  );
  await bob.page.evaluate((s) => window.agent.flush(s), space);
  await alice.page.evaluate(
    ([s, r]) => window.agent.waitCell(s, r, "tasks", "t2", "title", "approve"),
    [space, records] as const,
  );
  expect(alice.errors).toEqual([]);
  expect(bob.errors).toEqual([]);
});
