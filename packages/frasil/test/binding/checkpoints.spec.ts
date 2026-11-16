/**
 * Checkpoints through the browser package: the device's policy, a checkpoint proposed by hand in
 * a space this device administers alone, and the device list's checkpoints of a device of no
 * person.
 */
import { expect, test } from "@playwright/test";
import { devicePage, uniqueName } from "./harness.js";

test("an administrator proposes a checkpoint and follows it", async ({ browser }) => {
  const alice = await devicePage(browser);
  await alice.page.evaluate((name) => window.agent.create(name), uniqueName("checkpoints"));
  const seen = await alice.page.evaluate(async () => {
    // @ts-expect-error the harness keeps the public device for scenarios
    const device = window.agent.device as import("../../src/index.js").Device;
    device.setCheckpointPolicy({ propose: false });
    const policy = device.checkpointPolicy();
    const space = await device.createSpace();
    const rank = await space.myRank();
    const before = await space.checkpoints();
    const checkpoint = await space.proposeCheckpoint();
    const after = await space.checkpoints();
    const late = await space.lateChanges();
    const list = await device.listCheckpoints();
    let listRefused: string | undefined;
    try {
      await device.proposeListCheckpoint();
    } catch (error) {
      listRefused = (error as import("../../src/index.js").FrasilError).code;
    }
    device.setCheckpointPolicy({});
    return {
      rank,
      policy,
      reset: device.checkpointPolicy(),
      before,
      checkpoint,
      after,
      late,
      list,
      listRefused,
    };
  });
  expect(seen.policy).toEqual({
    propose: false,
    forget: true,
    rosterEvents: 1024,
    frameBytes: 4 * 1024 * 1024,
  });
  expect(seen.reset.propose).toBe(true);
  // The space's creator holds the top rank.
  expect(seen.rank).toBe(255);
  expect(seen.before.inEffect).toBeNull();
  expect(seen.before.epoch).toBe(0);
  expect(seen.before.pending).toEqual([]);
  expect(seen.checkpoint).toMatch(/^[0-9a-f]{64}$/);
  expect(seen.after.following).toBe(seen.checkpoint);
  expect(seen.after.bad).toEqual([]);
  expect(seen.after.withheld).toEqual([]);
  expect(seen.after.rivals).toEqual([]);
  expect(seen.late).toEqual([]);
  expect(seen.list).toEqual({ inEffect: null, pending: [], forgot: false, rivals: [] });
  expect(seen.listRefused).toBe("not_allowed");
  await alice.page.evaluate(() => window.agent.close());
  await alice.page.context().close();
});
