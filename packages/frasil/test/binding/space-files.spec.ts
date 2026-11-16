/**
 * Space files between browsers (ext-space-files.md): a space exported to bytes in one browser
 * and imported in another by its keys, read whole and written nowhere; a way in sealed under a
 * file key; a file whose invite admits a browser that then writes through the peer and fetches
 * the blob the file left out; and the file appended to once that claim came back.
 */
import { expect, test } from "@playwright/test";

import { devicePage, uniqueName } from "./harness.js";

const KIND = "example.notes";
const KEY = "0f".repeat(32);

test("a file carries a space to another browser, which reads it by its keys", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("alice"));
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  const doc = await alice.page.evaluate((s) => window.agent.createDocument(s), space);
  await alice.page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "hello"), [
    space,
    doc,
  ] as const);
  const put = await alice.page.evaluate((s) => window.agent.putBlob(s, 1000), space);
  const file = await alice.page.evaluate(
    (s) => window.agent.exportSpaceFile(s, "example.notes"),
    space,
  );

  // What the file says of itself, before anything is read.
  const sniffed = await alice.page.evaluate((f) => window.agent.sniffSpaceFile(f), file);
  expect(sniffed).toMatchObject({ space, kind: KIND, history: "full", objects: 1, wayIn: "clear" });

  // Bob reads the copy: the note and the blob, with no peer and no grant.
  const bob = await devicePage(browser);
  await bob.page.evaluate((name) => window.agent.create(name), uniqueName("bob"));
  const imported = await bob.page.evaluate(([f, k]) => window.agent.importSpaceFile(f, k), [
    file,
    KIND,
  ] as const);
  expect(imported).toEqual({ road: "reading", space });
  expect(await bob.page.evaluate((s) => window.agent.documents(s), space)).toEqual([doc]);
  expect(await bob.page.evaluate(([s, d]) => window.agent.text(s, d), [space, doc] as const)).toBe(
    "hello",
  );
  expect(await bob.page.evaluate((s) => window.agent.level(s), space)).toBeUndefined();
  expect(
    await bob.page.evaluate(([s, st, b]) => window.agent.blobDigest(s, st, b), [
      space,
      put.stream,
      put.blob,
    ] as const),
  ).toBe(put.digest);
  expect(
    await bob.page.evaluate(([s, d]) => window.agent.editCode(s, d, "x"), [space, doc] as const),
  ).toBe("not_allowed");

  // Another kind is refused before an event is read; so is a sealed way in without its key.
  const carol = await devicePage(browser);
  await carol.page.evaluate((name) => window.agent.create(name), uniqueName("carol"));
  expect(
    await carol.page.evaluate((f) => window.agent.importSpaceFile(f, "example.other"), file),
  ).toEqual({ code: "wrong_kind" });
  const sealed = await alice.page.evaluate(
    ([s, key]) => window.agent.exportSpaceFile(s, "example.notes", { seal: key }),
    [space, KEY] as const,
  );
  expect(await alice.page.evaluate((f) => window.agent.sniffSpaceFile(f), sealed)).toMatchObject({
    wayIn: "sealed",
  });
  expect(
    await carol.page.evaluate(([f, k]) => window.agent.importSpaceFile(f, k), [
      sealed,
      KIND,
    ] as const),
  ).toEqual({ code: "sealed" });
  expect(
    await carol.page.evaluate(([f, k, key]) => window.agent.importSpaceFile(f, k, key), [
      sealed,
      KIND,
      "ab".repeat(32),
    ] as const),
  ).toEqual({ code: "decrypt" });
  expect(
    await carol.page.evaluate(([f, k, key]) => window.agent.importSpaceFile(f, k, key), [
      sealed,
      KIND,
      KEY,
    ] as const),
  ).toEqual({ road: "reading", space });
  expect(
    await carol.page.evaluate(([s, d]) => window.agent.text(s, d), [space, doc] as const),
  ).toBe("hello");

  for (const { page, errors } of [alice, bob, carol]) {
    await page.evaluate(() => window.agent.close());
    expect(errors).toEqual([]);
  }
});

test("a file's invite admits a browser, which writes through the peer and fetches what the file left out", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  const aliceKeys = await alice.page.evaluate(
    (name) => window.agent.create(name),
    uniqueName("alice"),
  );
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  const doc = await alice.page.evaluate((s) => window.agent.createDocument(s), space);
  await alice.page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "hello"), [
    space,
    doc,
  ] as const);
  await alice.page.evaluate(() => window.agent.connect());
  const put = await alice.page.evaluate((s) => window.agent.putBlob(s, 70_000), space);
  await alice.page.evaluate((s) => window.agent.durable(s), space);

  // The file: no object, and an invite to write in place of the keys.
  const file = await alice.page.evaluate(
    (s) =>
      window.agent.exportSpaceFile(s, "example.notes", {
        objects: "none",
        wayIn: [{ level: "write", lifetime: 3600 }],
      }),
    space,
  );
  expect(await alice.page.evaluate((f) => window.agent.sniffSpaceFile(f), file)).toMatchObject({
    objects: 0,
    wayIn: "clear",
  });

  // Bob is shown the invite, consents, and writes with nobody online.
  const bob = await devicePage(browser);
  const bobKeys = await bob.page.evaluate((name) => window.agent.create(name), uniqueName("bob"));
  expect(
    await bob.page.evaluate(([f, k]) => window.agent.importSpaceFile(f, k), [file, KIND] as const),
  ).toEqual({
    road: "invited",
    inviter: aliceKeys.id,
    level: "write",
    label: null,
    space,
    accepted: space,
  });
  expect(await bob.page.evaluate((s) => window.agent.level(s), space)).toBe("write");
  expect(await bob.page.evaluate(([s, d]) => window.agent.text(s, d), [space, doc] as const)).toBe(
    "hello",
  );
  expect(
    await bob.page.evaluate(([s, st, b]) => window.agent.blobDigest(s, st, b), [
      space,
      put.stream,
      put.blob,
    ] as const),
  ).toBeNull();
  await bob.page.evaluate(([s, d]) => window.agent.edit(s, d, 5, 0, ", bob"), [
    space,
    doc,
  ] as const);

  // Through the peer: Bob's claim and edit reach Alice, and the blob reaches Bob.
  await bob.page.evaluate(() => window.agent.connect());
  await alice.page.evaluate(([s, d]) => window.agent.waitText(s, d, "hello, bob"), [
    space,
    doc,
  ] as const);
  expect(await alice.page.evaluate((s) => window.agent.members(s), space)).toEqual(
    expect.arrayContaining([`${bobKeys.id}:write`]),
  );
  await expect
    .poll(
      () =>
        bob.page.evaluate(([s, st, b]) => window.agent.blobDigest(s, st, b), [
          space,
          put.stream,
          put.blob,
        ] as const),
      { timeout: 30_000 },
    )
    .toBe(put.digest);

  // A fresh invite declined keeps nothing.
  const declined = await alice.page.evaluate(
    (s) =>
      window.agent.exportSpaceFile(s, "example.notes", {
        objects: "none",
        wayIn: [{ level: "read", lifetime: 900 }],
      }),
    space,
  );
  const dan = await devicePage(browser);
  await dan.page.evaluate((name) => window.agent.create(name), uniqueName("dan"));
  expect(
    await dan.page.evaluate(([f, k]) => window.agent.importSpaceFile(f, k, undefined, "decline"), [
      declined,
      KIND,
    ] as const),
  ).toMatchObject({ road: "invited", level: "read", declined: true });
  expect(await dan.page.evaluate(() => window.agent.spaces())).toEqual([]);

  // An invite open for the shortest lifetime, 15 minutes, accepted once the claimant's wall clock
  // passed its expiry: the refusal leaves the invitation in hand, and declining it keeps nothing.
  const brief = await alice.page.evaluate(
    (s) =>
      window.agent.exportSpaceFile(s, "example.notes", {
        objects: "none",
        wayIn: [{ level: "read", lifetime: 900 }],
      }),
    space,
  );
  const erin = await devicePage(browser);
  await erin.page.evaluate((name) => window.agent.create(name), uniqueName("erin"));
  const late = erin.page.evaluate(
    ([f, k]) => window.agent.importSpaceFile(f, k, undefined, "wait-then-accept"),
    [brief, KIND] as const,
  );
  // Shown on time; then the page's wall clock moves past the expiry, with its timers running.
  const expiresAt = await (
    await erin.page.waitForFunction(() => window.agent.waitingUntil, undefined, { timeout: 30_000 })
  ).jsonValue();
  await erin.page.clock.setFixedTime((Number(expiresAt) + 120) * 1000);
  expect(await late).toMatchObject({ road: "invited", acceptCode: "expired", declined: true });
  expect(await erin.page.evaluate(() => window.agent.spaces())).toEqual([]);

  // The file, appended to at Alice once Bob's changes came back: its invite is spent, and it
  // carries no keys, so a third browser is refused.
  await alice.page.evaluate((s) => window.agent.durable(s), space);
  const grown = await alice.page.evaluate(([s, f]) => window.agent.appendSpaceFile(s, f), [
    space,
    file,
  ] as const);
  expect(grown.startsWith(file)).toBe(true);
  const carol = await devicePage(browser);
  await carol.page.evaluate((name) => window.agent.create(name), uniqueName("carol"));
  expect(
    await carol.page.evaluate(([f, k]) => window.agent.importSpaceFile(f, k), [
      grown,
      KIND,
    ] as const),
  ).toEqual({ code: "invite_used" });

  for (const { page, errors } of [alice, bob, carol, dan, erin]) {
    await page.evaluate(() => window.agent.close());
    expect(errors).toEqual([]);
  }
});
