/**
 * The media helper: a service worker answers Range requests for a URL the page minted, with the
 * bytes of a blob this device does not hold, read through a reader; and a `<video>` element
 * plays and seeks through it; what a URL never becomes, a document; several servers in one page;
 * and the handler in a service worker of an application's own. The service worker is the
 * package's script, served at the test origin's root, unless a test says otherwise.
 */
import { type Browser, expect, type Page, test } from "@playwright/test";
import { devicePage, type ReadsWindow, uniqueName } from "./harness.js";

const CHUNK = 1_048_536;

/** A page with a device, connected, its space, and a media server in `window.served`. */
async function serving(browser: Browser): Promise<{ page: Page; errors: string[]; space: string }> {
  const { page, errors } = await devicePage(browser);
  const space = await page.evaluate(async (name) => {
    const w = window as unknown as ReadsWindow & { served: unknown };
    const space = await w.agent.createWith(name);
    w.served = await w.media.MediaServer.connect({ serviceWorker: "/media-sw.js" });
    return space;
  }, uniqueName("media"));
  return { page, errors, space };
}

type Served = ReadsWindow & { served: import("../../src/media.js").MediaServer };
type Blobs = import("../../src/index.js").Blobs;

/** What every answer of the service worker says, as `guard` reads it in a page. */
const GUARD = "nosniff | sandbox; default-src 'none' | same-origin | no-store";

test("a minted URL answers whole and Range requests with the blob's bytes", async ({ browser }) => {
  const { page, errors, space } = await serving(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers, served } = window as unknown as Served;
    const size = 4 * 1_048_536 + 321;
    const data = helpers.pattern(size);
    const { blobs, blob } = await agent.absent(space, data);
    const url = served.url(blobs, blob, { type: "audio/x-test", readAhead: 0 });
    const guard = (response: Response) =>
      [
        "x-content-type-options",
        "content-security-policy",
        "cross-origin-resource-policy",
        "cache-control",
      ]
        .map((name) => response.headers.get(name))
        .join(" | ");
    const ask = async (range?: string, method = "GET") => {
      const response = await fetch(url, { method, headers: range ? { range } : {} });
      const body = new Uint8Array(await response.arrayBuffer());
      const start = Number(
        /bytes (\d+)-/.exec(response.headers.get("content-range") ?? "")?.[1] ?? 0,
      );
      return {
        status: response.status,
        length: response.headers.get("content-length"),
        range: response.headers.get("content-range"),
        type: response.headers.get("content-type"),
        accepts: response.headers.get("accept-ranges"),
        guard: guard(response),
        bytes: body.length,
        right: body.every((byte, index) => byte === data[start + index]),
      };
    };
    const seen: Record<string, unknown> = {};
    // One chunk's worth: the device stores that chunk and no other.
    seen.first = await ask("bytes=100-199");
    const partial = await blobs.local(blob);
    seen.partial = partial.bytes > 0 && partial.bytes < 2 * 1_048_576;
    seen.across = await ask(`bytes=${1_048_536 - 5}-${1_048_536 + 4}`);
    seen.open = await ask(`bytes=${size - 50}-`);
    seen.suffix = await ask("bytes=-70");
    seen.clamped = await ask(`bytes=${size - 10}-${size + 500}`);
    seen.past = await ask(`bytes=${size}-`);
    seen.head = await ask(undefined, "HEAD");
    seen.rangedHead = await ask("bytes=0-9", "HEAD");
    seen.whole = await ask();
    seen.several = await ask("bytes=0-1,5-6");
    const plain = async (response: Response) => [response.status, guard(response)];
    seen.post = await plain(await fetch(url, { method: "POST" }));
    seen.unknown = await plain(
      await fetch(url.replace(/.$/, (last) => (last === "0" ? "1" : "0"))),
    );
    await helpers.until(() => served.openReaders === 0, "the readers to close");
    served.revoke(url);
    seen.revoked = await plain(await fetch(url));
    return { size, seen };
  }, space);
  const { size } = seen;
  const about = { type: "audio/x-test", accepts: "bytes", guard: GUARD, right: true };
  const part = (first: number, last: number) => ({
    ...about,
    status: 206,
    length: String(last - first + 1),
    range: `bytes ${first}-${last}/${size}`,
    bytes: last - first + 1,
  });
  const whole = { ...about, status: 200, length: String(size), range: null, bytes: size };
  expect(seen.seen).toEqual({
    first: part(100, 199),
    partial: true,
    across: part(CHUNK - 5, CHUNK + 4),
    open: part(size - 50, size - 1),
    suffix: part(size - 70, size - 1),
    clamped: part(size - 10, size - 1),
    past: { ...about, status: 416, length: null, range: `bytes */${size}`, bytes: 0 },
    head: { ...whole, bytes: 0 },
    rangedHead: { ...part(0, 9), bytes: 0 },
    whole,
    // More than one range is not served in parts: the whole blob is.
    several: whole,
    post: [405, GUARD],
    unknown: [404, GUARD],
    revoked: [404, GUARD],
  });
  expect(errors.filter((error) => !/40[45]|416/.test(error))).toEqual([]);
  await page.context().close();
});

test("an aborted request, and a revoked URL, close their readers", async ({ browser }) => {
  const { page, errors, space } = await serving(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers, served } = window as unknown as Served;
    const { blobs, blob } = await agent.absent(space, helpers.pattern(6 * 1_048_536));
    const url = served.url(blobs, blob, { uncached: true });
    // A seek storm: each request is given up after its first bytes.
    for (const start of [0, 3_000_000, 5_000_000, 1_500_000]) {
      const abort = new AbortController();
      const response = await fetch(url, {
        headers: { range: `bytes=${start}-` },
        signal: abort.signal,
      });
      await response.body?.getReader().read();
      abort.abort();
    }
    await helpers.until(() => served.openReaders === 0, "the aborted requests' readers", 15_000);
    // A request left open, with its consumer not reading: revoking the URL ends it.
    const held = await fetch(url);
    const reader = held.body?.getReader();
    await reader?.read();
    const open = served.openReaders;
    served.revoke(url);
    const afterRevoke = served.openReaders;
    const ended = await (async () => {
      try {
        for (;;) if ((await reader?.read())?.done !== false) return "ended";
      } catch {
        return "failed";
      }
    })();
    // Nothing uses the blob any more.
    await helpers.until(
      () =>
        blobs.dropLocal(blob).then(
          () => true,
          () => false,
        ),
      "the blob to be free",
    );
    return { open, afterRevoke, ended, state: (await blobs.local(blob)).state };
  }, space);
  expect(seen).toEqual({ open: 1, afterRevoke: 0, ended: "failed", state: "absent" });
  // A browser may log the answer that ended when its URL was revoked.
  expect(errors.filter((error) => !error.includes("the blob could not be read"))).toEqual([]);
  await page.context().close();
});

test("a video element plays and seeks a blob this device does not hold", async ({
  browser,
  browserName,
}) => {
  // The requests an element makes are covered in both browsers by the tests above. Playback
  // itself is left out for WebKit on Linux, whose page ended by itself during it once in twenty
  // runs in a container; it runs in Chromium everywhere and in WebKit on macOS.
  test.skip(
    browserName === "webkit" && process.platform === "linux",
    "WebKit's media playback is not reliable in a Linux container",
  );
  const { page, errors, space } = await serving(browser);
  // A sound of four and a half minutes, 4.1 MiB in five chunks, in a <video> element.
  const sound = await page.evaluate(async (space) => {
    const { agent, helpers, served } = window as unknown as Served;
    const { blobs, blob } = await agent.absent(space, helpers.wav(270));
    const before = (await blobs.local(blob)).state;
    const video = document.createElement("video");
    video.muted = true;
    document.body.append(video);
    const event = (name: string) =>
      new Promise<void>((resolve, reject) => {
        video.addEventListener(name, () => resolve(), { once: true });
        video.addEventListener("error", () => reject(new Error(video.error?.message)), {
          once: true,
        });
      });
    const loaded = event("loadedmetadata");
    const stop = served.serve(video, blobs, blob, { type: "audio/wav", uncached: true });
    await loaded;
    const duration = Math.round(video.duration);
    await video.play();
    await helpers.until(() => video.currentTime > 0.2, "the sound to play");
    // Far ahead, into the last chunk.
    const seeked = event("seeked");
    video.currentTime = 262;
    await seeked;
    await helpers.until(() => video.currentTime > 262.2, "the sound to play on after the seek");
    // And back.
    const back = event("seeked");
    video.currentTime = 100;
    await back;
    await helpers.until(
      () => video.currentTime > 100.2,
      "the sound to play on after the second seek",
    );
    const played = video.currentTime < 262;
    stop();
    await helpers.until(() => served.openReaders === 0, "the readers to close");
    return {
      before,
      duration,
      played,
      src: video.getAttribute("src"),
      after: (await blobs.local(blob)).state,
    };
  }, space);
  expect(sound).toEqual({
    before: "absent",
    duration: 270,
    played: true,
    src: null,
    after: "absent",
  });

  // A picture: a clip of six seconds, where the browser decodes VP8 in WebM. The clip is
  // `fixtures/clip.webm`, 75,982 bytes: a test pattern that ffmpeg draws by itself, with nothing
  // in it from anywhere else, made with
  //   ffmpeg -f lavfi -i testsrc=duration=6:size=160x120:rate=10 -c:v libvpx -b:v 120k -g 5 \
  //     -an -map_metadata -1 -fflags +bitexact -flags:v +bitexact clip.webm
  const clip = await page.evaluate(async (space) => {
    const { agent, helpers, served } = window as unknown as Served;
    const video = document.createElement("video");
    if (video.canPlayType('video/webm; codecs="vp8"') === "") return "not decoded here";
    const file = new Uint8Array(
      await (await fetch("/test/binding/fixtures/clip.webm")).arrayBuffer(),
    );
    const { blobs, blob } = await agent.absent(space, file);
    video.muted = true;
    document.body.append(video);
    const event = (name: string) =>
      new Promise<void>((resolve, reject) => {
        video.addEventListener(name, () => resolve(), { once: true });
        video.addEventListener("error", () => reject(new Error(video.error?.message)), {
          once: true,
        });
      });
    const loaded = event("loadeddata");
    const stop = served.serve(video, blobs, blob, { type: "video/webm" });
    await loaded;
    const picture = [video.videoWidth, video.videoHeight];
    await video.play();
    await helpers.until(() => video.currentTime > 0.2, "the clip to play");
    const seeked = event("seeked");
    video.currentTime = 4;
    await seeked;
    await helpers.until(() => video.currentTime > 4.2, "the clip to play on after the seek");
    stop();
    return { picture, duration: Math.round(video.duration) || 6 };
  }, space);
  if (clip !== "not decoded here") expect(clip).toEqual({ picture: [160, 120], duration: 6 });
  test.info().annotations.push({ type: "clip", description: JSON.stringify(clip) });
  expect(errors).toEqual([]);
  await page.context().close();
});

test("another page of the origin, and a navigation, read nothing through a page's URL", async ({
  browser,
}) => {
  const { page, errors, space } = await serving(browser);
  const url = await page.evaluate(async (space) => {
    const { agent, helpers, served } = window as unknown as Served;
    const { blobs, blob } = await agent.absent(space, helpers.pattern(5000));
    const url = served.url(blobs, blob);
    if ((await fetch(url)).status !== 200) throw new Error("the page's own request failed");
    return url;
  }, space);
  // A second tab of the same origin, with a media server of its own, under the same worker.
  const other = await page.context().newPage();
  await other.goto("/runner.html");
  await other.waitForFunction(() => window.ready !== undefined);
  const status = await other.evaluate(async (url) => {
    const w = window as unknown as ReadsWindow;
    await w.media.MediaServer.connect();
    return (await fetch(url)).status;
  }, url);
  expect(status).toBe(404);
  // Opened as a page of its own, the URL is nobody's.
  const opened = await other.goto(url);
  expect(opened?.status()).toBe(404);
  // The first page still reads through it.
  expect(await page.evaluate(async (url) => (await fetch(url)).status, url)).toBe(200);
  expect(errors).toEqual([]);
  await page.context().close();
});

test("a service worker the browser stopped asks the page for its port again", async ({
  browser,
  browserName,
}) => {
  test.skip(
    browserName !== "chromium",
    "only Chromium's protocol stops a service worker on demand",
  );
  const { page, errors, space } = await serving(browser);
  const url = await page.evaluate(async (space) => {
    const { agent, helpers, served } = window as unknown as Served;
    const { blobs, blob } = await agent.absent(space, helpers.pattern(3 * 1_048_536));
    const url = served.url(blobs, blob, { uncached: true });
    // A request under way when the worker stops.
    const held = await fetch(url);
    await held.body?.getReader().read();
    return url;
  }, space);
  const session = await page.context().newCDPSession(page);
  await session.send("ServiceWorker.enable");
  await session.send("ServiceWorker.stopAllWorkers");
  const seen = await page.evaluate(async (url) => {
    const { helpers, served } = window as unknown as Served;
    const response = await fetch(url, { headers: { range: "bytes=1048600-1048609" } });
    const bytes = Array.from(new Uint8Array(await response.arrayBuffer()));
    // The request the stopped worker held is over at the page.
    await helpers.until(() => served.openReaders === 0, "the readers to close");
    return { status: response.status, bytes };
  }, url);
  expect(seen).toEqual({
    status: 206,
    bytes: Array.from({ length: 10 }, (_, index) => ((1_048_600 + index) * 31 + 7) & 0xff),
  });
  expect(errors).toEqual([]);
  await page.context().close();
});

test("a blob of HTML is never a document: a frame, a window and a navigation get nothing", async ({
  browser,
}) => {
  const { page, errors, space } = await serving(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, served } = window as unknown as Served;
    const html = new TextEncoder().encode(
      `<!doctype html><title>ran</title><p id="shown">shown</p><script>
        localStorage.setItem("frasil-media-ran", "1");
        try { (window.opener || window.parent).postMessage("frasil-media-ran", "*"); } catch {}
      </script>`,
    );
    const { blobs, blob } = await agent.absent(space, html);
    const url = served.url(blobs, blob, { type: "text/html" });
    const told = { ran: false };
    window.addEventListener("message", (event) => {
      if (event.data === "frasil-media-ran") told.ran = true;
    });
    (window as unknown as { told: typeof told }).told = told;
    // A script of the page reads the bytes, told as no document's.
    const own = await fetch(url);
    const text = await own.text();
    // In a frame, an object and an embed: each is refused, and what it shows is not looked into,
    // since the answer is sandboxed away from this page.
    for (const tag of ["iframe", "object", "embed"] as const) {
      const element = document.createElement(tag);
      const settled = new Promise<void>((resolve) => {
        element.addEventListener("load", () => resolve(), { once: true });
        element.addEventListener("error", () => resolve(), { once: true });
        setTimeout(resolve, 3_000);
      });
      element.setAttribute(tag === "object" ? "data" : "src", url);
      document.body.append(element);
      await settled;
    }
    // A link and a button to click: a window of its own, and `window.open`.
    const link = document.createElement("a");
    link.id = "link";
    link.href = url;
    link.target = "_blank";
    link.textContent = "open";
    const button = document.createElement("button");
    button.id = "button";
    button.textContent = "open";
    button.addEventListener("click", () => window.open(url));
    document.body.append(link, button);
    return {
      url,
      status: own.status,
      type: own.headers.get("content-type"),
      sniff: own.headers.get("x-content-type-options"),
      policy: own.headers.get("content-security-policy"),
      read: text.includes("shown"),
    };
  }, space);
  expect({ ...seen, url: null }).toEqual({
    url: null,
    status: 200,
    type: "application/octet-stream",
    sniff: "nosniff",
    policy: "sandbox; default-src 'none'",
    read: true,
  });
  for (const selector of ["#link", "#button"]) {
    const [popup] = await Promise.all([page.waitForEvent("popup"), page.click(selector)]);
    await popup.waitForLoadState().catch(() => {});
    expect(await popup.title()).not.toBe("ran");
    expect(await popup.locator("#shown").count()).toBe(0);
    await popup.close();
  }
  // Opened as a page of its own in another tab.
  const other = await page.context().newPage();
  const opened = await other.goto(seen.url);
  expect(opened?.status()).toBe(404);
  expect(await opened?.headerValue("x-content-type-options")).toBe("nosniff");
  expect(await other.locator("#shown").count()).toBe(0);
  // No script of the blob ran anywhere.
  const ran = await page.evaluate(() => ({
    stored: localStorage.getItem("frasil-media-ran"),
    told: (window as unknown as { told: { ran: boolean } }).told.ran,
  }));
  expect(ran).toEqual({ stored: null, told: false });
  expect(errors.filter((error) => !/404/.test(error))).toEqual([]);
  await page.context().close();
});

test("a URL revoked while its request opens is answered and does not hang", async ({ browser }) => {
  const { page, errors, space } = await serving(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers, media, served } = window as unknown as Served;
    const data = helpers.pattern(3 * 1_048_536);
    const { blobs, blob } = await agent.absent(space, data);
    /** A stream whose readers open only once `release` was called, and say when one is asked for. */
    const gated = () => {
      let entered: () => void = () => {};
      let release: () => void = () => {};
      const inside = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let hold = false;
      const slow = {
        openReader: async (id: string, options: object) => {
          if (hold) {
            entered();
            await gate;
          }
          return blobs.openReader(id, options);
        },
      } as unknown as Blobs;
      return { slow, inside, release, holdNext: () => (hold = true) };
    };
    const within = <T>(work: Promise<T>): Promise<T | "hung"> =>
      Promise.race([work, new Promise<"hung">((resolve) => setTimeout(resolve, 8_000, "hung"))]);
    // Revoked while the first reader of a request opens.
    const first = gated();
    first.holdNext();
    const url = served.url(first.slow, blob, { uncached: true });
    const answering = fetch(url).then(
      (response) => response.status,
      () => "failed",
    );
    await first.inside;
    served.revoke(url);
    first.release();
    const opening = await within(answering);
    // Revoked while a request that rested opens its reader again.
    const quick = await media.MediaServer.connect({ idle: 100 });
    const second = gated();
    const resting = quick.url(second.slow, blob, { uncached: true, readAhead: 0 });
    const response = await fetch(resting);
    const body = response.body?.getReader();
    await body?.read();
    await helpers.until(() => quick.openReaders === 0, "the resting reader to close", 15_000);
    second.holdNext();
    const rest = (async () => {
      try {
        for (;;) if ((await body?.read())?.done !== false) return "ended";
      } catch {
        return "failed";
      }
    })();
    const reopening = await within(
      Promise.race([second.inside.then(() => "reopened" as const), rest]),
    );
    quick.revoke(resting);
    second.release();
    const pulling = await within(rest);
    quick.close();
    return { opening, reopening, pulling, open: served.openReaders + quick.openReaders };
  }, space);
  // A request whose whole body the browser had taken before the reader rested ends by itself.
  expect(seen.opening).toBe(404);
  expect(["reopened", "ended"]).toContain(seen.reopening);
  expect(seen.pulling).toBe(seen.reopening === "reopened" ? "failed" : "ended");
  expect(seen.open).toBe(0);
  expect(errors.filter((error) => !/404|could not be read/.test(error))).toEqual([]);
  await page.context().close();
});

test("a reader that rested is opened again, and the blob's size is fetched once for a URL", async ({
  browser,
  browserName,
}) => {
  const { page, errors, space } = await serving(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers, media } = window as unknown as Served;
    const size = 24 * 1_048_536 + 17;
    const data = helpers.pattern(size);
    const { blobs, blob } = await agent.absent(space, data);
    const quick = await media.MediaServer.connect({ idle: 150 });
    const counts = { opens: 0, sizes: 0 };
    const counted = {
      openReader: async (id: string, options: object) => {
        counts.opens += 1;
        const reader = await blobs.openReader(id, options);
        const fetchSize = reader.fetchSize.bind(reader);
        reader.fetchSize = (given) => {
          counts.sizes += 1;
          return fetchSize(given);
        };
        return reader;
      },
    } as unknown as Blobs;
    const url = quick.url(counted, blob, { uncached: true, readAhead: 0 });
    const response = await fetch(url);
    const body = response.body?.getReader();
    let total = 0;
    let right = true;
    const take = async (): Promise<boolean> => {
      const piece = await body?.read();
      if (piece?.value === undefined) return false;
      const start = total;
      right &&= piece.value.every((byte, index) => byte === data[start + index]);
      total += piece.value.length;
      return true;
    };
    await take();
    // Nothing is read from the answer: its reader closes, and the request stays open.
    await helpers.until(() => quick.openReaders === 0, "the resting reader to close", 15_000);
    const rested = { opens: counts.opens, total };
    while (await take());
    const whole = { opens: counts.opens, total, right };
    // Requests elsewhere in the blob learn its size from the first.
    for (const start of [20_000_000, 9_000_000, 0]) {
      const part = await fetch(url, { headers: { range: `bytes=${start}-${start + 9}` } });
      const bytes = new Uint8Array(await part.arrayBuffer());
      right &&= part.status === 206 && bytes.every((byte, index) => byte === data[start + index]);
    }
    const head = await fetch(url, { method: "HEAD" });
    await helpers.until(() => quick.openReaders === 0, "the readers to close");
    quick.close();
    return {
      size,
      rested,
      whole,
      right,
      sizes: counts.sizes,
      length: head.headers.get("content-length"),
    };
  }, space);
  expect(seen.rested.total).toBeLessThan(seen.size);
  // Chromium takes an answer as its consumer reads it, so the request rests and its reader is
  // opened again. WebKit takes the whole answer at once: its request never rests.
  const again = browserName === "chromium" ? 1 : 0;
  expect(seen.whole).toEqual({ opens: seen.rested.opens + again, total: seen.size, right: true });
  expect(seen.right).toBe(true);
  expect(seen.sizes).toBe(1);
  expect(seen.length).toBe(String(seen.size));
  expect(errors).toEqual([]);
  await page.context().close();
});

test("two media servers in one page each answer the URLs they minted", async ({ browser }) => {
  const { page, errors, space } = await serving(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers, media, served } = window as unknown as Served;
    const one = helpers.pattern(5000);
    const two = helpers.pattern(7000).map((byte) => byte ^ 0x5a);
    const first = await agent.absent(space, one);
    const second = await agent.absent(space, two);
    const before = served.url(first.blobs, first.blob);
    const other = await media.MediaServer.connect();
    const mine = other.url(second.blobs, second.blob);
    const read = async (url: string, data: Uint8Array) => {
      const response = await fetch(url);
      const bytes = new Uint8Array(await response.arrayBuffer());
      return response.status === 200 && bytes.length === data.length
        ? bytes.every((byte, index) => byte === data[index])
        : response.status;
    };
    const both = [await read(before, one), await read(mine, two), await read(before, one)];
    // A URL minted by the first after the second connected, and each read at once.
    const after = served.url(second.blobs, second.blob);
    const together = await Promise.all([read(after, two), read(mine, two), read(before, one)]);
    other.close();
    const closed = [await read(mine, two), await read(before, one)];
    return { both, together, closed };
  }, space);
  expect({ ...seen, closed: null }).toEqual({
    both: [true, true, true],
    together: [true, true, true],
    closed: null,
  });
  // The closed server's URL is no one's, or its request was under way as the server left.
  expect([404, 503]).toContain(seen.closed[0]);
  expect(seen.closed[1]).toBe(true);
  expect(errors.filter((error) => !/40[34]|503/.test(error))).toEqual([]);
  await page.context().close();
});

test("connecting rejects in time when no service worker takes the page's port", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  const seen = await page.evaluate(async () => {
    const { media } = window as unknown as ReadsWindow;
    const failed = (work: Promise<unknown>) =>
      work.then(
        () => ["connected", ""],
        (error: { code?: string; message: string }) => [error.code, error.message],
      );
    const started = Date.now();
    // No service worker at all, and one whose scope does not cover the page.
    const none = await failed(media.MediaServer.connect({ timeout: 400 }));
    const outside = await failed(
      media.MediaServer.connect({ serviceWorker: "/dist/media-sw.js", timeout: 400 }),
    );
    return { none, outside, quick: Date.now() - started < 10_000 };
  });
  expect(seen.none[0]).toBe("timeout");
  expect(seen.none[1]).toContain("No service worker came to control this page");
  expect(seen.outside[0]).toBe("timeout");
  expect(seen.quick).toBe(true);
  expect(errors).toEqual([]);
  await page.context().close();
});

test("the handler in an application's own service worker serves under its prefix", async ({
  browser,
}) => {
  const { page, errors } = await devicePage(browser);
  const seen = await page.evaluate(async (name) => {
    const { agent, helpers, media } = window as unknown as ReadsWindow;
    const space = await agent.createWith(name);
    await navigator.serviceWorker.register("/composed-sw.js", { type: "module", scope: "/" });
    // The prefix as the worker has it, with no slash at its end on either side.
    const served = await media.MediaServer.connect({ prefix: "/played" });
    const data = helpers.pattern(2 * 1_048_536 + 99);
    const { blobs, blob } = await agent.absent(space, data);
    const url = served.url(blobs, blob, { type: "video/mp4", uncached: true });
    const part = await fetch(url, { headers: { range: "bytes=1048500-1048599" } });
    const bytes = new Uint8Array(await part.arrayBuffer());
    // The application's own request and message, and a path that only begins as the prefix does.
    const ping = await fetch("/composed/ping");
    const answered = new Promise<unknown>((resolve) => {
      navigator.serviceWorker.addEventListener("message", (event) => {
        if (event.data === "pong") resolve(event.data);
      });
    });
    navigator.serviceWorker.controller?.postMessage("ping");
    const beside = await fetch(`/playedfoo/${url.split("/").pop()}`);
    await helpers.until(() => served.openReaders === 0, "the readers to close");
    served.close();
    return {
      path: new URL(url).pathname.replace(/[0-9a-f]{40}$/, "…"),
      status: part.status,
      type: part.headers.get("content-type"),
      sniff: part.headers.get("x-content-type-options"),
      right: bytes.length === 100 && bytes.every((byte, index) => byte === data[1_048_500 + index]),
      ping: [await ping.text(), ping.headers.get("x-composed")],
      message: await answered,
      beside: [beside.status, beside.headers.get("x-content-type-options")],
    };
  }, uniqueName("composed"));
  expect(seen).toEqual({
    path: "/played/…",
    status: 206,
    type: "video/mp4",
    sniff: "nosniff",
    right: true,
    ping: ["pong", "yes"],
    message: "pong",
    // Not the handler's: the origin's own answer.
    beside: [404, null],
  });
  expect(errors.filter((error) => !/404/.test(error))).toEqual([]);
  await page.context().close();
});

test("a media server in a dedicated worker serves through the ports its page hands it", async ({
  browser,
}) => {
  const { page, errors, space } = await serving(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers, media, served } = window as unknown as Served;
    const worker = new Worker("/test/binding/media-worker-host.js", { type: "module" });
    const stop = await media.connectMediaPort((port) =>
      worker.postMessage({ mediaPort: port }, [port]),
    );
    const minted = new Promise<string>((resolve) => {
      worker.addEventListener("message", (event) => resolve(event.data.url), { once: true });
    });
    worker.postMessage("mint");
    const url = await minted;
    const part = await fetch(url, { headers: { range: "bytes=2000000-2000099" } });
    const bytes = new Uint8Array(await part.arrayBuffer());
    const whole = await fetch(url);
    const length = (await whole.arrayBuffer()).byteLength;
    // The page's own server answers beside the worker's.
    const data = helpers.pattern(4000);
    const { blobs, blob } = await agent.absent(space, data);
    const own = await fetch(served.url(blobs, blob));
    const mine = new Uint8Array(await own.arrayBuffer());
    stop();
    worker.terminate();
    return {
      status: part.status,
      range: part.headers.get("content-range"),
      right: bytes.every((byte, index) => byte === ((2_000_000 + index) * 31 + 7) % 256),
      length,
      own: own.status === 200 && mine.every((byte, index) => byte === data[index]),
    };
  }, space);
  expect(seen).toEqual({
    status: 206,
    range: "bytes 2000000-2000099/3000000",
    right: true,
    length: 3_000_000,
    own: true,
  });
  expect(errors).toEqual([]);
  await page.context().close();
});
