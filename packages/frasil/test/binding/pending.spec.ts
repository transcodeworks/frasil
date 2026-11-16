import { expect, test } from "@playwright/test";
import { devicePage, uniqueName } from "./harness.js";

test("two offline writes have two more pending authored events", async ({ browser }) => {
  const alice = await devicePage(browser);
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("pending"));
  const counts = await alice.page.evaluate(async () => {
    // @ts-expect-error the harness keeps the public device for scenarios
    const device = window.agent.device as import("../../src/index.js").Device;
    const events = device.events();
    const space = await device.createSpace();
    const before = await space.pendingAuthoredChanges();
    const records = space.createRecords();
    for (const row of ["one", "two"]) {
      await records.write((tx: import("../../src/index.js").Transaction) => {
        tx.insert("rows", row);
      });
    }
    for (;;) {
      const event = await events.next();
      if (event?.kind === "pendingChanges") {
        if (event.count !== before + 2n) throw new Error("wrong event count");
        break;
      }
    }
    events.close();
    return [String(before), String(await space.pendingAuthoredChanges())];
  });
  expect(BigInt(counts[1]) - BigInt(counts[0])).toBe(2n);
  await alice.page.evaluate(() => window.agent.close());
  await alice.page.context().close();
});
