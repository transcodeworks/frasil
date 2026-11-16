/**
 * A change of who administers, kept at the peer (`frasil-relay`, through the test origin's proxy)
 * before its author goes offline: the browser that grants `administer` waits with `flush()` and
 * closes at once, and the device it granted administers through the peer alone, as a third
 * browser sees.
 */
import { expect, test } from "@playwright/test";

import { devicePage, uniqueName } from "./harness.js";

test("a granted administrator administers once the browser that granted it is gone", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  const bob = await devicePage(browser);
  const carol = await devicePage(browser);
  const bobKeys = await bob.page.evaluate((name) => window.agent.create(name), uniqueName("bob"));
  const carolKeys = await carol.page.evaluate(
    (name) => window.agent.create(name),
    uniqueName("carol"),
  );

  // Alice makes the space, grants Bob's and Carol's devices `write`, and keeps it at the peer.
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("alice"));
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  for (const keys of [bobKeys, carolKeys]) {
    await alice.page.evaluate(([s, id, k]) => window.agent.grant(s, id, k), [
      space,
      keys.id,
      keys.keys,
    ] as const);
  }
  await alice.page.evaluate(() => window.agent.connect());
  await alice.page.evaluate((s) => window.agent.durable(s), space);

  // Bob and Carol take the space's events from Alice, as a direct grant hands them over, and
  // connect to the peer.
  const events = await alice.page.evaluate((s) => window.agent.signedEvents(s), space);
  for (const device of [bob, carol]) {
    await device.page.evaluate((s) => window.agent.follow(s), space);
    const ingested = await device.page.evaluate(([s, e]) => window.agent.ingest(s, e), [
      space,
      events,
    ] as const);
    expect(ingested.refused).toEqual([]);
    await device.page.evaluate(() => window.agent.connect());
  }

  // Alice grants Bob `administer`, waits for the peer to hold it, and closes at once.
  await alice.page.evaluate(([s, id]) => window.agent.setLevel(s, id, "administer"), [
    space,
    bobKeys.id,
  ] as const);
  await alice.page.evaluate((s) => window.agent.flush(s), space);
  await alice.page.evaluate(() => window.agent.close());

  // Bob administers through the peer alone: he grants Carol `administer`, and Carol sees it.
  await bob.page.evaluate((s) => window.agent.waitLevel(s, "administer"), space);
  await bob.page.evaluate(([s, id]) => window.agent.setLevel(s, id, "administer"), [
    space,
    carolKeys.id,
  ] as const);
  await bob.page.evaluate((s) => window.agent.flush(s), space);
  await carol.page.evaluate((s) => window.agent.waitLevel(s, "administer"), space);
  expect(await carol.page.evaluate((s) => window.agent.members(s), space)).toEqual(
    expect.arrayContaining([`${bobKeys.id}:administer`, `${carolKeys.id}:administer`]),
  );
  expect(alice.errors).toEqual([]);
  expect(bob.errors).toEqual([]);
  expect(carol.errors).toEqual([]);
});
