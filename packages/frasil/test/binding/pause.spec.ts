import { expect, test } from "@playwright/test";
import { devicePage, uniqueName } from "./harness.js";

test("a paused space stores nothing at the peer, and catches up when resumed", async ({
  browser,
}) => {
  const alice = await devicePage(browser);
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("pause"));
  await alice.page.evaluate(() => window.agent.connect());
  const steps = await alice.page.evaluate(async () => {
    // @ts-expect-error the harness keeps the public device for scenarios
    const device = window.agent.device as import("../../src/index.js").Device;
    const space = await device.createSpace();
    await space.waitDurable(30_000);
    const out: string[] = [];
    space.pauseSync();
    out.push(`paused ${space.isSyncPaused()}`);
    const records = space.createRecords();
    await records.write((tx: import("../../src/index.js").Transaction) => {
      tx.insert("rows", "while paused");
    });
    try {
      await space.waitDurable(1_500);
      out.push("stored while paused");
    } catch {
      out.push("held on the device");
    }
    out.push(`rows ${(await records.rows("rows")).size}`);
    device.resumeSync([space]);
    out.push(`paused ${space.isSyncPaused()}`);
    await space.waitDurable(30_000);
    out.push(`durable ${await space.isDurable()}`);
    return out;
  });
  expect(steps).toEqual([
    "paused true",
    "held on the device",
    "rows 1",
    "paused false",
    "durable true",
  ]);
  await alice.page.evaluate(() => window.agent.close());
  await alice.page.context().close();
});
