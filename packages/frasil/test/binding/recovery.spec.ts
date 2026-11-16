/**
 * Recovery in browsers (identity.md, "Recovery"): a person whose only browser held their personal
 * space returns on another browser from the recovery sheet, through `frasil-relay`; a sheet of
 * another key is refused there. Each device is a page of its own browser context.
 */
import { expect, test } from "@playwright/test";

import { devicePage, uniqueName } from "./harness.js";

test("a person who lost their only browser returns on another from the recovery sheet", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  const aliceName = uniqueName("alice");
  await alice.page.evaluate((name) => window.agent.create(name), aliceName);
  const made = await alice.page.evaluate((name) => window.agent.makePerson(name), aliceName);
  const space = made.personalSpace;
  const doc = await alice.page.evaluate((s) => window.agent.createDocument(s), space);
  await alice.page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "my own"), [
    space,
    doc,
  ] as const);
  await alice.page.evaluate(() => window.agent.connect());
  const sheet = await alice.page.evaluate(() => window.agent.createRecoverySheet());
  expect(sheet).toContain(made.person);
  await alice.page.evaluate((s) => window.agent.durable(s), space);
  await alice.page.evaluate(() => window.agent.registered(1));
  // The only browser is lost.
  await alice.page.evaluate(() => window.agent.close());
  await alice.page.context().close();

  // A sheet whose secret is another key's is refused at the peer.
  const stranger = await devicePage(browser);
  const strangerName = uniqueName("stranger");
  await stranger.page.evaluate((name) => window.agent.create(name), strangerName);
  await stranger.page.evaluate((name) => window.agent.makePerson(name), strangerName);
  const other = await stranger.page.evaluate(() => window.agent.createRecoverySheet());
  const secretOf = (text: string) => /Secret: (\S+)/.exec(text)?.[1] ?? "";
  const wrong = sheet.replace(secretOf(sheet), secretOf(other));
  expect(
    await stranger.page.evaluate(([name, text]) => window.agent.recoverCode(name, text), [
      uniqueName("wrong"),
      wrong,
    ] as const),
  ).toBe("credential_refused");

  // The sheet brings the person back on a new browser, which reads and writes.
  const phone = await devicePage(browser);
  await phone.page.evaluate(([name, text]) => window.agent.recover(name, text), [
    uniqueName("phone"),
    sheet,
  ] as const);
  await phone.page.evaluate(([s, d]) => window.agent.waitText(s, d, "my own"), [
    space,
    doc,
  ] as const);
  await phone.page.evaluate(([s, d]) => window.agent.edit(s, d, 6, 0, ", back"), [
    space,
    doc,
  ] as const);
  await phone.page.evaluate((s) => window.agent.durable(s), space);
  expect(
    await phone.page.evaluate(([s, d]) => window.agent.text(s, d), [space, doc] as const),
  ).toBe("my own, back");
  await phone.page.evaluate(() => window.agent.close());
  await stranger.page.evaluate(() => window.agent.close());
  expect(alice.errors).toEqual([]);
  expect(stranger.errors).toEqual([]);
  expect(phone.errors).toEqual([]);
});
