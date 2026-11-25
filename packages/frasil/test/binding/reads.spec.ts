/**
 * Reading blobs this device does not hold, and what it keeps of them: a read's options, the
 * reader, a cancelled stream, the cache's budget, and a store with no room. Each blob is put by
 * the device itself, taken by the peer, and dropped, so that a read fetches it from the peer.
 */
import { type Browser, expect, type Page, test } from "@playwright/test";
import { devicePage, type ReadsWindow, uniqueName } from "./harness.js";

const MIB = 1024 * 1024;

/** A page with a device of `options`, connected, and its space. */
async function opened(
  browser: Browser,
  options: { blobCache?: number } = {},
): Promise<{ page: Page; errors: string[]; space: string }> {
  const { page, errors } = await devicePage(browser);
  const space = await page.evaluate(
    ([name, options]) => (window as unknown as ReadsWindow).agent.createWith(name, options),
    [uniqueName("reads"), options] as const,
  );
  return { page, errors, space };
}

test("a read's options say what the device stores of a blob it fetches", async ({ browser }) => {
  const { page, errors, space } = await opened(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers } = window as unknown as ReadsWindow;
    const data = helpers.pattern(1_300_000);
    const expected = await helpers.digest(data);
    const { blobs, blob } = await agent.absent(space, data);
    const state = async () => (await blobs.local(blob)).state;
    const digest = async (bytes: Uint8Array | undefined) =>
      bytes === undefined ? undefined : helpers.digest(bytes);
    const seen: Record<string, unknown> = { expected };
    seen.status = (await blobs.status(blob)).kind;
    seen.local = await digest(await blobs.get(blob, { local: true }));
    seen.localRange = await blobs.getRange(blob, 5, 10, { local: true });
    seen.afterLocal = await state();
    seen.uncached = await digest(await blobs.get(blob, { uncached: true }));
    seen.afterUncached = await state();
    seen.hash = await digest(data).then(
      async (plain) =>
        plain ===
        Array.from((await blobs.contentHash(blob, { uncached: true })) ?? [], (byte) =>
          byte.toString(16).padStart(2, "0"),
        ).join(""),
    );
    const pieces: Uint8Array[] = [];
    for await (const piece of blobs.getStream(blob, undefined, {
      uncached: true,
    }) as unknown as AsyncIterable<Uint8Array>) {
      pieces.push(piece);
    }
    seen.streamed = await digest(
      new Uint8Array(await new Blob(pieces as BlobPart[]).arrayBuffer()),
    );
    seen.afterStream = await state();
    const range = await blobs.getRange(blob, 1_200_000, 4, { uncached: true });
    seen.range = Array.from(range ?? []);
    seen.afterRange = await state();
    seen.cached = await digest(await blobs.get(blob));
    seen.afterCached = await state();
    seen.readable = (await blobs.status(blob)).kind;
    seen.kept = await digest(await blobs.get(blob, { keep: true }));
    seen.afterKept = await state();
    await blobs.dropLocal(blob);
    seen.afterDrop = await state();
    await blobs.keep(blob);
    seen.afterKeep = await state();
    seen.both = await blobs.get(blob, { keep: true, uncached: true }).then(
      () => "resolved",
      (error: { code: string }) => error.code,
    );
    const usage = await agent.device.blobCacheUsage();
    seen.usage = usage.kept > 1_300_000 && usage.cached === 0 && usage.budget === 256 * 1024 * 1024;
    return seen;
  }, space);
  const { expected } = seen;
  expect(seen).toEqual({
    expected,
    status: "absent",
    local: undefined,
    localRange: undefined,
    afterLocal: "absent",
    uncached: expected,
    afterUncached: "absent",
    hash: true,
    streamed: expected,
    afterStream: "absent",
    range: [1_200_000, 1_200_001, 1_200_002, 1_200_003].map((index) => (index * 31 + 7) & 0xff),
    afterRange: "absent",
    cached: expected,
    afterCached: "cached",
    readable: "readable",
    kept: expected,
    afterKept: "kept",
    afterDrop: "absent",
    afterKeep: "kept",
    both: "invalid_input",
    usage: true,
  });
  expect(errors).toEqual([]);
  await page.context().close();
});

test("a reader gives a range of a blob it has not fetched, and a read in order makes it whole", async ({
  browser,
}) => {
  const { page, errors, space } = await opened(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers } = window as unknown as ReadsWindow;
    const size = 4 * 1_048_536 + 5000;
    const data = helpers.pattern(size);
    const { blobs, blob } = await agent.absent(space, data);
    const same = (bytes: Uint8Array, offset: number) =>
      bytes.every((byte, index) => byte === data[offset + index]);
    // One chunk, and nothing ahead of it.
    const reader = await blobs.openReader(blob, { readAhead: 0 });
    const before = reader.size;
    const fetched = await reader.fetchSize();
    const known = reader.size;
    const at = 2 * 1_048_536 + 77;
    const piece = await reader.read(at, 1000);
    const partial = await blobs.local(blob);
    const jumped = reader.verified;
    // Across a chunk's end, and past the blob's.
    const across = await reader.read(1_048_536 - 10, 30);
    const tail = await reader.read(size - 4, 100);
    const beyond = await reader.read(size + 10, 100);
    await reader.close();
    const closed = await reader.read(0, 1).then(
      () => "resolved",
      (error: { code: string }) => error.code,
    );
    // Absent again, and read in order from the first byte to the last, storing nothing: every
    // check ran.
    await blobs.dropLocal(blob);
    const whole = await blobs.openReader(blob, { uncached: true });
    let read = 0;
    let right = true;
    let held = false;
    const early = whole.verified;
    for await (const part of whole.stream() as unknown as AsyncIterable<Uint8Array>) {
      right &&= same(part, read);
      read += part.length;
      // Its chunks are in its own memory, and nowhere else.
      held ||= whole.windowBytes > 0 && (await blobs.local(blob)).bytes === 0;
    }
    const verified = whole.verified;
    await whole.close();
    const stored = (await blobs.local(blob)).bytes;
    return {
      stored,
      before,
      fetched: fetched === size && known === size && reader.size === size,
      piece: piece.length === 1000 && same(piece, at),
      // The chunk its size was read by, and the chunk read: two of five.
      partial: partial.state === "cached" && partial.bytes > 0 && partial.bytes < 3 * 1_048_576,
      jumped,
      across: across.length === 30 && same(across, 1_048_536 - 10),
      tail: tail.length === 4 && same(tail, size - 4),
      beyond: beyond.length,
      closed,
      early,
      read: read === size && right,
      verified,
      afterClose: whole.verified,
      held,
    };
  }, space);
  expect(seen).toEqual({
    stored: 0,
    before: undefined,
    fetched: true,
    piece: true,
    partial: true,
    jumped: "chunks",
    across: true,
    tail: true,
    beyond: 0,
    closed: "disposed",
    early: "chunks",
    read: true,
    verified: "whole",
    afterClose: "whole",
    held: true,
  });
  expect(errors).toEqual([]);
  await page.context().close();
});

test("a cancelled stream and an aborted read leave the reader readable and the blob unused", async ({
  browser,
}) => {
  const { page, errors, space } = await opened(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers } = window as unknown as ReadsWindow;
    const size = 5 * 1_048_536;
    const data = helpers.pattern(size);
    const { blobs, blob } = await agent.absent(space, data);
    const reader = await blobs.openReader(blob, { uncached: true, readAhead: 2 });
    // Cancelled while its first read waits for a chunk from the peer.
    const first = reader.stream(3 * 1_048_536).getReader();
    const waiting = first.read();
    await first.cancel();
    const cancelledRead = (await waiting).done;
    // Cancelled after a piece was read, with the consumer gone.
    const second = reader.stream().getReader();
    const piece = (await second.read()).value;
    await second.cancel();
    // Abandoned: never read again, never cancelled.
    const abandoned = reader.stream(1_048_536).getReader();
    await abandoned.read();
    // Aborted while it waits.
    const abort = new AbortController();
    const aborting = reader.read(4 * 1_048_536, 10, { signal: abort.signal });
    abort.abort();
    const aborted = await aborting.then(
      () => "resolved",
      (error: { name: string }) => error.name,
    );
    const already = await reader.read(0, 1, { signal: abort.signal }).then(
      () => "resolved",
      (error: { name: string }) => error.name,
    );
    // The reader still reads, in the order asked.
    const [low, high] = await Promise.all([reader.read(10, 5), reader.read(size - 5, 5)]);
    const inUse = await blobs.dropLocal(blob).then(
      () => "dropped",
      (error: { code: string }) => error.code,
    );
    await reader.close();
    await reader.close();
    // Nothing uses the blob, and nothing of it is stored.
    await blobs.dropLocal(blob);
    const local = await blobs.local(blob);
    return {
      cancelledRead,
      piece: piece?.length === 262_144 && piece.every((byte, index) => byte === data[index]),
      aborted,
      already,
      low: Array.from(low),
      high: Array.from(high),
      window: reader.windowBytes,
      inUse,
      local: [local.state, local.bytes],
    };
  }, space);
  const byte = (index: number) => (index * 31 + 7) & 0xff;
  expect(seen).toEqual({
    cancelledRead: true,
    piece: true,
    aborted: "AbortError",
    already: "AbortError",
    low: [10, 11, 12, 13, 14].map(byte),
    high: [5, 4, 3, 2, 1].map((back) => byte(5 * 1_048_536 - back)),
    window: 0,
    inUse: "not_allowed",
    local: ["absent", 0],
  });
  expect(errors).toEqual([]);
  await page.context().close();
});

test("the cache stays within its budget over reads of more than the budget", async ({
  browser,
}) => {
  const budget = 3 * MIB;
  const { page, errors, space } = await opened(browser, { blobCache: budget });
  const seen = await page.evaluate(
    async ([space, budget]) => {
      const { agent, helpers } = window as unknown as ReadsWindow;
      const device = agent.device;
      const sizes = [1_200_000, 1_300_000, 1_250_000, 1_100_000, 1_350_000];
      const put = [];
      for (const size of sizes) {
        const data = helpers.pattern(size).map((byte) => byte ^ (size & 0xff));
        put.push({ ...(await agent.absent(space, data)), digest: await helpers.digest(data) });
      }
      const evicted: string[] = [];
      const stops = await Promise.all(
        put.map(({ blobs }) =>
          blobs.onChange((change) => {
            if (change.kind === "evicted") evicted.push(change.id);
          }),
        ),
      );
      const most = { cached: 0, right: true };
      const look = async () => {
        const usage = await device.blobCacheUsage();
        most.cached = Math.max(most.cached, usage.cached);
        most.right &&= usage.budget === budget;
      };
      // Twice through all of them: 12 MiB of reads through a cache of 3 MiB.
      for (let round = 0; round < 2; round += 1) {
        for (const { blobs, blob, digest } of put) {
          const data = await blobs.get(blob);
          most.right &&= data !== undefined && (await helpers.digest(data)) === digest;
          await look();
        }
      }
      // The two read last fit; the one read first went.
      const states = await Promise.all(
        put.map(async ({ blobs, blob }) => (await blobs.local(blob)).state),
      );
      // A blob larger than the whole budget passes through memory and stays absent.
      const large = helpers.pattern(4 * 1024 * 1024);
      const big = await agent.absent(space, large);
      const read = await big.blobs.get(big.blob);
      const bigRight =
        read !== undefined && (await helpers.digest(read)) === (await helpers.digest(large));
      await look();
      const bigState = (await big.blobs.local(big.blob)).state;
      await helpers.until(() => evicted.length >= 8, "the evictions to be told");
      for (const stop of stops) stop();
      const estimate = await navigator.storage.estimate();
      return {
        within: most.cached > 0 && most.cached <= budget,
        right: most.right,
        states,
        bigRight,
        bigState,
        evicted: put.map(({ blob }) => evicted.filter((id) => id === blob).length),
        usage: typeof estimate.usage,
      };
    },
    [space, budget] as const,
  );
  expect(seen).toEqual({
    within: true,
    right: true,
    states: ["absent", "absent", "absent", "cached", "cached"],
    bigRight: true,
    bigState: "absent",
    // Each went once in each round, but for the two that stayed at the end.
    evicted: [2, 2, 2, 1, 1],
    usage: expect.any(String),
  });
  expect(errors).toEqual([]);
  await page.context().close();
});

test("the budget is lowered to half of what the browser says the origin may still store", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  const budgets = await page.evaluate(async (name) => {
    const { frasil } = window as unknown as ReadsWindow;
    const estimates: ((() => Promise<StorageEstimate>) | undefined)[] = [
      async () => ({ quota: 10 * 1024 * 1024, usage: 4 * 1024 * 1024 }),
      // More used than the quota: nothing is cached.
      async () => ({ quota: 1024, usage: 4096 }),
      // No quota told, a quota of zero, an estimate that fails, and no estimate at all.
      async () => ({ usage: 5 }),
      async () => ({ quota: 0, usage: 0 }),
      async () => Promise.reject(new Error("no estimate")),
      undefined,
    ];
    const budgets: number[] = [];
    const open = async (index: number, options: { blobCache?: number; keepAllBlobs?: boolean }) => {
      const key = crypto.getRandomValues(new Uint8Array(32));
      const device = await frasil.Device.open(
        frasil.Storage.indexedDb(`${name}-${index}-${budgets.length}`),
        key,
        options,
      );
      budgets.push((await device.blobCacheUsage()).budget);
      await device.close();
    };
    for (const [index, estimate] of estimates.entries()) {
      // On the prototype: a browser may hand out another `navigator.storage` each time.
      Object.defineProperty(StorageManager.prototype, "estimate", {
        value: estimate,
        configurable: true,
      });
      await open(index, {});
    }
    Object.defineProperty(StorageManager.prototype, "estimate", {
      value: estimates[0],
      configurable: true,
    });
    // A budget below the cap stands, and a device that keeps every blob has none to cap.
    await open(9, { blobCache: 1024 * 1024 });
    await open(9, { blobCache: 64 * 1024 * 1024 });
    await open(9, { blobCache: 64 * 1024 * 1024, keepAllBlobs: true });
    // A store that is not the browser's is not measured by the browser's estimate.
    const memory = await frasil.Device.open(
      frasil.Storage.memory(),
      crypto.getRandomValues(new Uint8Array(32)),
    );
    budgets.push((await memory.blobCacheUsage()).budget);
    await memory.close();
    return budgets;
  }, uniqueName("quota"));
  const standard = 256 * MIB;
  expect(budgets).toEqual([
    3 * MIB,
    0,
    standard,
    standard,
    standard,
    standard,
    MIB,
    3 * MIB,
    64 * MIB,
    standard,
  ]);
  expect(errors).toEqual([]);
  await page.context().close();
});

test("a write the store refuses for quota makes the cache give way, then the read go through memory", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  const seen = await page.evaluate(async (name) => {
    const { agent, frasil, helpers } = window as unknown as ReadsWindow;
    // A store over IndexedDB that refuses commits of chunks as a browser past its quota does:
    // the next `refusing` of them.
    const inner = await frasil.IndexedDbStore.open(name);
    const tight = {
      refusing: 0,
      refused: 0,
      get: (address: Uint8Array) => inner.get(address),
      scan: (prefix: Uint8Array) => inner.scan(prefix),
      loadSealedKeys: () => inner.loadSealedKeys(),
      saveSealedKeys: (sealed: Uint8Array) => inner.saveSealedKeys(sealed),
      commit(commit: import("../../src/index.js").Commit) {
        if (tight.refusing > 0 && commit.puts.some(([, record]) => record.length > 500_000)) {
          tight.refusing -= 1;
          tight.refused += 1;
          throw new DOMException("the quota has been exceeded", "QuotaExceededError");
        }
        return inner.commit(commit);
      },
    };
    const space = await agent.createWith(name, {}, tight);
    const first = helpers.pattern(1_200_000);
    const second = helpers.pattern(3 * 1_048_536 + 9).map((byte) => byte ^ 0x5a);
    const one = await agent.absent(space, first);
    const two = await agent.absent(space, second);
    // One blob in the cache.
    await one.blobs.get(one.blob);
    const cachedFirst = (await one.blobs.local(one.blob)).state;
    // The store refuses once: the cached blob goes, and the chunk is written at the next attempt.
    tight.refusing = 1;
    const reader = await two.blobs.openReader(two.blob, { readAhead: 0 });
    const piece = await reader.read(0, 100);
    await reader.close();
    const afterRetry = {
      refused: tight.refused,
      piece: piece.every((byte, index) => byte === second[index]),
      first: (await one.blobs.local(one.blob)).state,
      second: (await two.blobs.local(two.blob)).state,
    };
    await two.blobs.dropLocal(two.blob);
    // The store refuses every time: the read gives the whole blob all the same, through memory.
    tight.refusing = Number.MAX_SAFE_INTEGER;
    const read = await two.blobs.get(two.blob);
    const right =
      read !== undefined && (await helpers.digest(read)) === (await helpers.digest(second));
    const through = (await two.blobs.local(two.blob)).state;
    const tried = tight.refused > 1;
    // With room again, the next read caches it.
    tight.refusing = 0;
    await two.blobs.get(two.blob);
    const cachedAgain = (await two.blobs.local(two.blob)).state;
    await agent.device.close();
    inner.close();
    return { cachedFirst, afterRetry, right, through, tried, cachedAgain };
  }, uniqueName("tight"));
  expect(seen).toEqual({
    cachedFirst: "cached",
    afterRetry: { refused: 1, piece: true, first: "absent", second: "cached" },
    right: true,
    through: "absent",
    tried: true,
    cachedAgain: "cached",
  });
  expect(errors).toEqual([]);
  await page.context().close();
});
