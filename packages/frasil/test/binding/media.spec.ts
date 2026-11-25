/**
 * The media helper: a service worker answers Range requests for a URL the page minted, with the
 * bytes of a blob this device does not hold, read through a reader; and a `<video>` element
 * plays and seeks through it. The service worker is the package's script, served at the test
 * origin's root.
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

test("a minted URL answers whole and Range requests with the blob's bytes", async ({ browser }) => {
  const { page, errors, space } = await serving(browser);
  const seen = await page.evaluate(async (space) => {
    const { agent, helpers, served } = window as unknown as Served;
    const size = 4 * 1_048_536 + 321;
    const data = helpers.pattern(size);
    const { blobs, blob } = await agent.absent(space, data);
    const url = served.url(blobs, blob, { type: "audio/x-test", readAhead: 0 });
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
    seen.post = (await fetch(url, { method: "POST" })).status;
    seen.unknown = (await fetch(url.replace(/.$/, (last) => (last === "0" ? "1" : "0")))).status;
    await helpers.until(() => served.openReaders === 0, "the readers to close");
    served.revoke(url);
    seen.revoked = (await fetch(url)).status;
    return { size, seen };
  }, space);
  const { size } = seen;
  const about = { type: "audio/x-test", accepts: "bytes", right: true };
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
    post: 405,
    unknown: 404,
    revoked: 404,
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
