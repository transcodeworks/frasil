/**
 * Admission through an exchange mailbox at the peer (`frasil-relay`, through the test origin's
 * proxy), between two browsers: the newcomer shows a text, the other browser enters it, both show
 * the same six digits, and the newcomer receives the space, or becomes the person's new device and
 * receives the person's spaces.
 */
import { expect, test } from "@playwright/test";

import { devicePage, reload, uniqueName } from "./harness.js";

for (const kind of ["space", "personal space"] as const) {
  test(`a browser joins a ${kind} through the peer's exchange mailbox`, async ({ browser }) => {
    const alice = await devicePage(browser);
    const bob = await devicePage(browser);
    const aliceName = uniqueName("alice");
    await alice.page.evaluate((name) => window.agent.create(name), aliceName);
    const space =
      kind === "space"
        ? await alice.page.evaluate(() => window.agent.createSpace())
        : (await alice.page.evaluate((name) => window.agent.makePerson(name), aliceName))
            .personalSpace;
    await alice.page.evaluate(() => window.agent.connect());
    await alice.page.evaluate((s) => window.agent.durable(s), space);

    await bob.page.evaluate((name) => window.agent.create(name), uniqueName("bob"));
    // The newcomer is connected to the peer already, as an application connects a device it opens.
    await bob.page.evaluate(() => window.agent.connect());
    const text = await bob.page.evaluate(() => window.agent.joinViaPeer("Bob's browser", 3000));
    expect(text.startsWith("FRASIL-ADMIT:")).toBe(true);

    const joined = bob.page.evaluate(() => window.agent.joined());
    const code = await alice.page.evaluate(([s, t]) => window.agent.admit(s, t, "write"), [
      space,
      text,
    ] as const);
    expect(await joined).toBe(space);
    expect(await bob.page.evaluate(() => window.agent.joinCode)).toBe(code);
    expect(await bob.page.evaluate((s) => window.agent.level(s), space)).toBe("write");
    expect(alice.errors).toEqual([]);
    expect(bob.errors).toEqual([]);
  });
}

test("a browser becomes a person's new device through the peer's exchange mailbox", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  const phone = await devicePage(browser);
  const aliceName = uniqueName("alice");
  await alice.page.evaluate((name) => window.agent.create(name), aliceName);
  const { person, personalSpace } = await alice.page.evaluate(
    (name) => window.agent.makePerson(name),
    aliceName,
  );
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  const doc = await alice.page.evaluate((s) => window.agent.createDocument(s), space);
  await alice.page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "from alice"), [
    space,
    doc,
  ] as const);
  await alice.page.evaluate(() => window.agent.connect());
  await alice.page.evaluate((s) => window.agent.durable(s), space);
  await alice.page.evaluate((s) => window.agent.durable(s), personalSpace);

  const phoneName = uniqueName("phone");
  await phone.page.evaluate((name) => window.agent.create(name), phoneName);
  await phone.page.evaluate(() => window.agent.connect());
  const text = await phone.page.evaluate(
    ([name, p]) => window.agent.joinPersonViaPeer(name, p, "Phone"),
    [phoneName, person] as const,
  );
  expect(text.startsWith("FRASIL-ADMIT:")).toBe(true);
  const joined = phone.page.evaluate(() => window.agent.joinedPerson());
  const code = await alice.page.evaluate((t) => window.agent.admitDevice(t), text);
  expect(await joined).toEqual([personalSpace, space].sort());
  expect(await phone.page.evaluate(() => window.agent.joinCode)).toBe(code);
  expect(await phone.page.evaluate(() => window.agent.person())).toBe(person);
  await phone.page.evaluate(([s, d]) => window.agent.waitText(s, d, "from alice"), [
    space,
    doc,
  ] as const);

  // Its keys were kept naming the person: it opens again as the person's device.
  await phone.page.evaluate(() => window.agent.close());
  await reload(phone.page);
  await phone.page.evaluate((name) => window.agent.open(name), phoneName);
  expect(await phone.page.evaluate(() => window.agent.person())).toBe(person);
  expect(alice.errors).toEqual([]);
  expect(phone.errors).toEqual([]);
});
