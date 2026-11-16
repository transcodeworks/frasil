/**
 * File references (adapter-blobs.md, "References"; ext-libraries.md, "Holds") through the package,
 * in a browser: a device stores a file in one space and references it from another of the same
 * library. The reference reads as the file, names its source, and goes when it is removed; the
 * source's blob stays its own.
 *
 * The peer must keep libraries, with an open library for spaces made without a ticket:
 *
 *   FRASIL_TEST_PEER_FEATURES=ext-libraries FRASIL_EXTENSIONS=libraries FRASIL_OPEN_LIBRARY=testing:open \
 *     npx playwright test
 */
import { expect, test } from "@playwright/test";

import type * as Frasil from "../../src/index.js";
import { devicePage, uniqueName } from "./harness.js";

/** What the page holds besides the agent: the agent's device. */
type Page = {
  agent: { device: Frasil.Device };
};

const libraries = (process.env.FRASIL_TEST_PEER_FEATURES ?? "").includes("ext-libraries");

test("a file stored once, referenced from another space of its library", async ({ browser }) => {
  test.skip(!libraries, "the peer keeps no libraries: FRASIL_TEST_PEER_FEATURES=ext-libraries");
  const { page, errors } = await devicePage(browser);
  await page.evaluate((n) => window.agent.create(n), uniqueName("references"));
  const bank = await page.evaluate(() => window.agent.createSpace());
  const show = await page.evaluate(() => window.agent.createSpace());
  await page.evaluate(() => window.agent.connect());

  const result = await page.evaluate(
    async ([bankId, showId]) => {
      const { agent } = window as unknown as Page;
      const bankSpace = await agent.device.space(bankId);
      const showSpace = await agent.device.space(showId);
      const files = bankSpace.createBlobs();
      const clip = await files.put(new TextEncoder().encode("the opening clip"), {
        name: "clip.mp4",
      });
      await window.agent.durable(bankId);

      const cues = showSpace.createBlobs();
      const cue = await cues.referenceFrom(files, clip);
      await window.agent.durable(showId);
      const info = await cues.info(cue);
      const own = await files.info(clip);
      const bytes = await cues.get(cue);
      const listed = (await cues.list()).map((blob) => blob.id);

      const refusals: string[] = [];
      const refused = async (body: () => Promise<unknown>) => {
        try {
          await body();
          refusals.push("done");
        } catch (error) {
          refusals.push((error as { code: string }).code);
        }
      };
      await refused(() => cues.referenceFrom(files, "00".repeat(16)));
      await cues.remove(cue);
      await refused(() => cues.info(cue));
      return {
        cue,
        info,
        own,
        text: bytes === undefined ? null : new TextDecoder().decode(bytes),
        listed,
        refusals,
      };
    },
    [bank, show],
  );

  expect(result.info).toEqual({
    id: result.cue,
    name: "clip.mp4",
    size: 16,
    source: bank,
  });
  expect(result.own.source).toBeUndefined();
  expect(result.text).toBe("the opening clip");
  expect(result.listed).toEqual([result.cue]);
  expect(result.refusals).toEqual(["invalid_input", "invalid_input"]);
  expect(errors).toEqual([]);
});
