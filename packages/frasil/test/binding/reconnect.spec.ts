/**
 * A peer that asks a browser to connect again (transport.md, "The server binding", the `reconnect`
 * close): the test origin's proxy closes the page's WebSocket with `reconnect` at a frame boundary,
 * as a peer that moves the connection to another of its machines does. The device's `PeerStatus`
 * shows it reconnecting, which is no error, then connected again with one reconnect counted, and
 * the same `Peer` carries the space's next change to the peer on the new WebSocket.
 */
import { expect, test } from "@playwright/test";

import { devicePage, uniqueName } from "./harness.js";

test("a browser connects again when the peer asks it to, and its status counts it", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  // The proxy finds this page's WebSockets by this cookie.
  const tag = uniqueName("reconnect");
  await page.context().addCookies([{ name: "frasil-test-tag", value: tag, url: page.url() }]);
  await page.evaluate((name) => window.agent.create(name), uniqueName("alice"));
  const space = await page.evaluate(() => window.agent.createSpace());
  const doc = await page.evaluate((s) => window.agent.createDocument(s), space);
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 0, 0, "first"), [space, doc] as const);
  await page.evaluate(() => window.agent.connect());
  await page.evaluate((s) => window.agent.durable(s), space);
  expect(await page.evaluate(() => window.agent.status())).toMatchObject({
    connected: true,
    reconnecting: false,
    reconnects: 0,
    closed: null,
  });

  const asked = await page.request.post("/test/reconnect");
  expect(await asked.json()).toEqual({ closed: 1 });

  // Reconnecting first, then connected again: one reconnect, no close. The new WebSocket presents
  // the space just after it opens, so the wait ends once the peer keeps it again.
  const seen = await page.evaluate(async () => {
    const states: { connected: boolean; reconnecting: boolean }[] = [];
    const started = Date.now();
    for (;;) {
      const { connected, reconnecting, reconnects, closed, spaces } = window.agent.status();
      states.push({ connected, reconnecting });
      if (
        (connected && reconnects >= 1 && spaces.length > 0) ||
        closed !== null ||
        Date.now() - started > 45_000
      ) {
        return { states, final: window.agent.status() };
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  });
  expect(seen.states).toContainEqual({ connected: false, reconnecting: true });
  expect(seen.final).toMatchObject({
    connected: true,
    reconnecting: false,
    reconnects: 1,
    closed: null,
    spaces: [space],
    refused: [],
  });

  // The new WebSocket carries the next change to the peer.
  await page.evaluate(([s, d]) => window.agent.edit(s, d, 5, 0, " second"), [space, doc] as const);
  await page.evaluate((s) => window.agent.durable(s), space);
  expect(await page.evaluate(() => window.agent.status())).toMatchObject({
    connected: true,
    reconnects: 1,
  });
  await page.evaluate(() => window.agent.close());
  // Only the WebSocket the proxy closed.
  expect(errors.filter((error) => !/WebSocket/.test(error))).toEqual([]);
});
