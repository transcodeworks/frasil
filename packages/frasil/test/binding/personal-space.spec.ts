/**
 * The personal space (identity.md, "The person ID and the personal space"): a browser knows its
 * person's personal space from `makePerson` on, beside the other spaces that grant the person, and
 * still knows it after a reload, from IndexedDB. No peer takes part.
 */
import { expect, test } from "@playwright/test";

import { devicePage, reload, uniqueName } from "./harness.js";

test("a browser knows its person's personal space, after a reload too", async ({ browser }) => {
  const alice = await devicePage(browser);
  const name = uniqueName("alice");
  await alice.page.evaluate((n) => window.agent.create(n), name);
  expect(await alice.page.evaluate(() => window.agent.personalSpace())).toBeNull();

  const made = await alice.page.evaluate((n) => window.agent.makePerson(n), name);
  expect(made.personalSpace).toMatch(/^[0-9a-f]{64}$/);
  expect(await alice.page.evaluate(() => window.agent.personalSpace())).toBe(made.personalSpace);

  // Spaces that grant the person alone, as the personal space does, leave it as it is.
  await alice.page.evaluate(() => window.agent.createSpace());
  await alice.page.evaluate(() => window.agent.createSpace());
  expect(await alice.page.evaluate(() => window.agent.personalSpace())).toBe(made.personalSpace);

  await alice.page.evaluate(() => window.agent.close());
  await reload(alice.page);
  await alice.page.evaluate((n) => window.agent.open(n), name);
  expect((await alice.page.evaluate(() => window.agent.spaces())).length).toBe(3);
  expect(await alice.page.evaluate(() => window.agent.personalSpace())).toBe(made.personalSpace);
  expect(alice.errors).toEqual([]);
});
