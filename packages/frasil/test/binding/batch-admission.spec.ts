import { expect, test } from "@playwright/test";
import { devicePage, uniqueName } from "./harness.js";

test("one authenticated browser receives administrator grants for many spaces", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  const bob = await devicePage(browser);
  const carol = await devicePage(browser);
  const a = await alice.page.evaluate((name) => window.agent.create(name), uniqueName("batch-a"));
  const b = await bob.page.evaluate((name) => window.agent.create(name), uniqueName("batch-b"));
  await carol.page.evaluate((name) => window.agent.create(name), uniqueName("batch-c"));
  const source = await alice.page.evaluate(() => window.agent.createSpace());
  await alice.page.evaluate(() => window.agent.connect());
  await bob.page.evaluate(() => window.agent.connect());
  const text = await bob.page.evaluate(() => window.agent.joinViaPeer("Bob", 0));
  const joined = bob.page.evaluate(() => window.agent.joined());
  const code = await alice.page.evaluate(
    ([space, text]) => window.agent.admit(space, text, "write"),
    [source, text] as const,
  );
  expect(await joined).toBe(source);
  expect(await bob.page.evaluate(() => window.agent.joinCode)).toBe(code);
  const denied = await carol.page.evaluate(() => window.agent.createSpace());
  const spaces = [source];
  for (let index = 0; index < 5; index += 1)
    spaces.push(await alice.page.evaluate(() => window.agent.createSpace()));
  spaces.splice(2, 0, denied);
  const reports = await alice.page.evaluate(
    async ({ source, member, spaces }) => {
      // @ts-expect-error the harness retains the public Device
      const device = window.agent.device as import("../../src/index.js").Device;
      const progress: string[] = [];
      const reports = await device.admitSpacesViaPeer(
        location.origin,
        source,
        member,
        255,
        spaces,
        (report) => progress.push(report.space),
      );
      if (progress.length !== spaces.length) throw new Error("missing progress");
      return reports.map((report) => ({
        space: report.space,
        granted: report.granted,
        error: report.error?.code,
      }));
    },
    { source, member: b.id, spaces },
  );
  expect(reports.filter((report) => !report.error)).toHaveLength(6);
  expect(reports.find((report) => report.space === denied)?.granted).toBe(false);
  const delivered = reports.filter((report) => !report.error).map((report) => report.space);
  const received = await bob.page.evaluate(
    async ({ approver, spaces }) => {
      // @ts-expect-error the harness retains the public Device
      const device = window.agent.device as import("../../src/index.js").Device;
      const reports = await device.receiveSpacesViaPeer(location.origin, approver, spaces);
      return reports.map((report) => ({ granted: report.granted, error: report.error?.code }));
    },
    { approver: a.id, spaces: delivered },
  );
  expect(received).toEqual(delivered.map(() => ({ granted: true, error: undefined })));
  for (const space of delivered)
    expect(await bob.page.evaluate((space) => window.agent.level(space), space)).toBe("administer");
  await bob.page.evaluate(([space, member]) => window.agent.setLevel(space, member, "write"), [
    source,
    a.id,
  ] as const);
  await bob.page.evaluate((space) => window.agent.flush(space), source);
  await alice.page.evaluate((space) => window.agent.waitLevel(space, "write"), source);
  for (const page of [alice, bob, carol]) await page.page.evaluate(() => window.agent.close());
});
