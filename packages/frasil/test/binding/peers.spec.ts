/**
 * A space's peers (admission.md, "The welcome"; ext-libraries.md, "The home peer"): a browser
 * keeps the home peer the issuer named for a space, and still knows it after a reload, from
 * IndexedDB; a URL that is not an origin's is refused as invalid input. No peer takes part: the
 * home peer is a loopback port nothing listens on, which the device tries and cannot reach.
 */
import { expect, test } from "@playwright/test";

import { devicePage, reload, uniqueName } from "./harness.js";

const HOME = "http://127.0.0.1:9";

test("a browser keeps a space's home peer, after a reload too", async ({ browser }) => {
  const alice = await devicePage(browser);
  const name = uniqueName("alice");
  await alice.page.evaluate((n) => window.agent.create(n), name);
  const space = await alice.page.evaluate(() => window.agent.createSpace());
  expect(await alice.page.evaluate((s) => window.agent.knownPeers(s), space)).toEqual([]);

  await alice.page.evaluate(([s, home]) => window.agent.setHomePeer(s, home), [space, HOME]);
  for (const url of ["https://home.example/path", "http://home.example", "home.example"]) {
    const refused = await alice.page.evaluate(
      ([s, u]) =>
        window.agent.setHomePeer(s, u).then(
          () => "kept",
          (error: Error & { code?: string }) => `${error.name}:${error.code}`,
        ),
      [space, url],
    );
    expect(refused, url).toBe("FrasilError:invalid_input");
  }

  await alice.page.evaluate(() => window.agent.close());
  await reload(alice.page);
  await alice.page.evaluate((n) => window.agent.open(n), name);
  expect(await alice.page.evaluate((s) => window.agent.knownPeers(s), space)).toEqual([HOME]);
  // Only the home peer it could not reach.
  expect(alice.errors.filter((error) => !/WebSocket|127\.0\.0\.1:9/.test(error))).toEqual([]);
});
