/**
 * A member of another space (admission.md, 3.16): an administrator admits a device that a space
 * it holds grants directly, with no code. A browser has no member connection, so the welcome goes
 * to the device's mailbox at the peer, where its upkeep collects it.
 */
import { expect, test } from "@playwright/test";
import { devicePage, uniqueName } from "./harness.js";

test("a direct member of one space is admitted to another with no code", async ({ browser }) => {
  const alice = await devicePage(browser);
  const bob = await devicePage(browser);
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("member-a"));
  const b = await bob.page.evaluate((name) => window.agent.create(name), uniqueName("member-b"));
  const known = await alice.page.evaluate(() => window.agent.createSpace());
  await alice.page.evaluate(() => window.agent.connect());
  await bob.page.evaluate(() => window.agent.connect());
  const text = await bob.page.evaluate(() => window.agent.joinViaPeer("Bob", 0));
  const joined = bob.page.evaluate(() => window.agent.joined());
  await alice.page.evaluate(([space, text]) => window.agent.admit(space, text, "write"), [
    known,
    text,
  ] as const);
  expect(await joined).toBe(known);

  const other = await alice.page.evaluate(() => window.agent.createSpace());
  const refused = await alice.page.evaluate(
    async ({ known, other, member }) => {
      // @ts-expect-error the harness retains the public Device
      const device = window.agent.device as import("../../src/index.js").Device;
      const space = await device.space(other);
      const administer = await space
        // @ts-expect-error administer is admitted at a rank
        .admitMember(known, member, "administer")
        .then(() => "admitted")
        .catch((error: { code?: string }) => error.code);
      await space.admitMember(known, member, "read");
      const again = await space
        .admitMemberAdministrator(known, member, 1)
        .then(() => "admitted")
        .catch((error: { code?: string }) => error.code);
      return { administer, again };
    },
    { known, other, member: b.id },
  );
  expect(refused.administer).toBe("invalid_input");
  expect(refused.again).toBe("not_allowed");
  // The space arrives once bob's upkeep collects the welcome at the peer.
  const level = await bob.page.evaluate(async (other) => {
    for (const started = Date.now(); Date.now() - started < 30_000; ) {
      const level = await window.agent.level(other).catch(() => undefined);
      if (level) return level;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return undefined;
  }, other);
  expect(level).toBe("read");
  for (const page of [alice, bob]) await page.page.evaluate(() => window.agent.close());
});
