/**
 * Plays a blob in a `<video>` or `<audio>` element without downloading it: the element asks for
 * the ranges it needs, as it does of any URL, and each is read through a {@link BlobReader},
 * which fetches only the chunks that hold it.
 *
 * A media element reads from a URL. {@link MediaServer} mints one for a blob, and a service
 * worker (`@frasil/client/media-sw.js`, or {@link handleMedia} in the application's own) answers
 * the element's requests for it by asking the page for the bytes over a `MessagePort`: the client
 * cannot run in a service worker.
 *
 * ```ts
 * import { MediaServer } from "@frasil/client/media";
 *
 * const media = await MediaServer.connect({ serviceWorker: "/media-sw.js" });
 * const stop = media.serve(video, blobs, id, { type: "video/mp4" });
 * // later, when the element is done:
 * stop();
 * ```
 *
 * The service worker must control the page: its script is served from the page's directory or
 * one above it, or with a `Service-Worker-Allowed` header that names such a scope. Service
 * workers need a secure context: `https:`, or `http://localhost` while developing.
 *
 * This module loads no WebAssembly: it uses the `Blobs` it is given.
 *
 * @module
 */

import { FrasilError } from "./errors.js";
import { MEDIA_PREFIX, mediaPrefix, mediaType, SERVER_NAME_LENGTH } from "./media-worker.js";
import type { BlobReader, ReaderOptions } from "./reader.js";
import type { BlobId, Blobs } from "./streams.js";

export { handleMedia, MEDIA_PREFIX } from "./media-worker.js";

/** How a blob is served to an element: its media type, and how its readers read. */
export interface MediaOptions extends ReaderOptions {
  /**
   * The media type the element is told, such as `video/mp4`: `application/octet-stream` unless
   * given. An element may refuse a file whose type it is not told. Only `audio/…`, `video/…`,
   * `image/…` other than SVG, `application/ogg` and `application/octet-stream` are told as
   * given; any other type is told as `application/octet-stream`.
   *
   * Never take it from what another member wrote, such as a blob's `mediaType`, without
   * checking it against the types the application plays: the URL is on the page's own origin,
   * and the list above is all that stands between a member's bytes and a type the browser
   * would run there.
   */
  readonly type?: string;
}

/** How the page reaches its service worker. */
export interface MediaConnection {
  /**
   * The URL of the service worker's script, to register before connecting. Leave it out when
   * the application registers its own service worker, which calls `handleMedia`.
   */
  readonly serviceWorker?: string | URL;
  /** The scope to register it with: the script's directory unless given. */
  readonly scope?: string;
  /**
   * How long connecting may take, in milliseconds: 10,000 unless given. It rejects with
   * `timeout` when no service worker has taken the page's port by then.
   */
  readonly timeout?: number;
}

/** What a server is made with. */
export interface MediaServerOptions {
  /**
   * The path its URLs are minted under: `/frasil-media/` unless given. The service worker's
   * `handleMedia` must be given the same. It ends with a slash, and is given one if it does not.
   */
  readonly prefix?: string;
  /**
   * How long a request's reader stays open with nothing asked of it, in milliseconds: 30,000
   * unless given. The reader is opened again when the element reads on.
   */
  readonly idle?: number;
}

/** How many bytes the page reads for each piece the service worker asks for. */
const PIECE = 262_144;

/** How long a reader stays open with nothing asked of it, in milliseconds, unless given. */
const IDLE = 30_000;

/** How long connecting may take, in milliseconds, unless given. */
const CONNECT_WAIT = 10_000;

/** `bytes` random bytes in hex. */
function random(bytes: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

/** What the service worker asks. */
type Ask =
  | { t: "open"; id: number; token: string; method: string; range: string | null }
  | { t: "pull"; id: number }
  | { t: "cancel"; id: number };

/** A blob served under a URL. */
interface Served {
  readonly blobs: Blobs;
  readonly id: BlobId;
  readonly type: string;
  readonly read: ReaderOptions;
  /** The blob's size, once a request's reader has opened a chunk under its header. */
  size: number | undefined;
  /** The requests under way for it. */
  readonly requests: Set<Serving>;
}

/** One request of an element: the bytes from `position` up to `end`. */
interface Serving {
  readonly served: Served;
  readonly port: MessagePort;
  position: number;
  end: number;
  /** The reader, closed while nothing is asked of it and opened again when something is. */
  reader: BlobReader | undefined;
  readonly abort: AbortController;
  idle: ReturnType<typeof setTimeout> | undefined;
}

/**
 * The byte range a `Range` header asks of a blob of `size` bytes: `[start, end)`; `undefined`
 * for no header or one this does not read, which is answered with the whole blob; `"none"` for
 * a range the blob does not have.
 */
function rangeOf(header: string | null, size: number): [number, number] | "none" | undefined {
  const match = header === null ? null : /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (match === null) return undefined;
  const [, first = "", last = ""] = match;
  if (first === "") {
    // The last `last` bytes.
    if (last === "") return undefined;
    const length = Number(last);
    return length === 0 || size === 0 ? "none" : [Math.max(0, size - length), size];
  }
  const start = Number(first);
  if (start >= size) return "none";
  const end = last === "" ? size : Math.min(Number(last) + 1, size);
  return end <= start ? undefined : [start, end];
}

/**
 * Serves blobs to media elements under URLs it mints. It lives where the client does: in the
 * page, with {@link MediaServer.connect}, or in a worker, where the page hands it a port with
 * {@link connectMediaPort} and {@link MediaServer.attach}.
 *
 * A URL is an unguessable path of this origin. Only the service worker answers it, only for a
 * request of the page that connected this server, and only until it is revoked: another origin's
 * page is not controlled by the service worker, and another page of this origin is asked for its
 * own ports, which do not know the URL.
 *
 * A page may connect several servers: each has a port of its own at the service worker, and a
 * URL's path begins with the name of the server that minted it, which is how the worker finds
 * the port to ask.
 */
export class MediaServer {
  readonly #prefix: string;
  /** What its URLs' last segments begin with: how the service worker tells its port. */
  readonly #name = random(SERVER_NAME_LENGTH / 2);
  readonly #idleAfter: number;
  readonly #served = new Map<string, Served>();
  readonly #serving = new Map<number, Serving>();
  #port: MessagePort | undefined;
  #disconnect: (() => void) | undefined;
  #closed = false;

  constructor(options: MediaServerOptions = {}) {
    this.#prefix = mediaPrefix(options.prefix ?? MEDIA_PREFIX);
    this.#idleAfter = options.idle ?? IDLE;
  }

  /**
   * A server in a page, connected to the service worker that controls the page; with
   * `serviceWorker`, that script is registered first. Resolves once the service worker that
   * controls the page has taken the server's port.
   *
   * Rejects with `unsupported` where there are no service workers, as in a worker or outside a
   * secure context, and with `timeout` when no service worker takes the port in time
   * ({@link MediaConnection.timeout}): none controls the page, as when its script is served
   * from outside the page's directory or the page was loaded with a forced reload, or the one
   * that does is not the media worker and does not call `handleMedia`.
   */
  static async connect(options: MediaConnection & MediaServerOptions = {}): Promise<MediaServer> {
    const server = new MediaServer(options);
    try {
      server.#disconnect = await connectMediaPort((port) => server.attach(port), options);
    } catch (error) {
      server.close();
      throw error;
    }
    return server;
  }

  /**
   * Takes a port to the service worker, from {@link connectMediaPort}, in place of the one it
   * had: the requests under way on the old one are over.
   */
  attach(port: MessagePort): void {
    if (this.#closed) {
      port.close();
      return;
    }
    this.#detach();
    this.#port = port;
    port.onmessage = (event: MessageEvent<Ask>) => {
      void this.#asked(port, event.data);
    };
    // The service worker sends this port the requests for the URLs that begin with the name.
    port.postMessage({ t: "serve", server: this.#name });
  }

  /**
   * Mints a URL for a blob, to give a media element as its `src`. Nothing is read until the
   * element asks. {@link MediaServer.revoke} it when the element is done.
   */
  url(blobs: Blobs, id: BlobId, options: MediaOptions = {}): string {
    if (this.#closed) throw new FrasilError("disposed", "This MediaServer was closed.");
    const { type, ...read } = options;
    const token = this.#name + random(16);
    this.#served.set(token, {
      blobs,
      id,
      type: mediaType(type),
      read,
      size: undefined,
      requests: new Set(),
    });
    return new URL(this.#prefix + token, globalThis.location.origin).href;
  }

  /**
   * Plays a blob in an element: sets its `src` to a URL minted for the blob. Returns the function
   * that ends it, which revokes the URL and empties the element.
   */
  serve(
    element: HTMLMediaElement,
    blobs: Blobs,
    id: BlobId,
    options: MediaOptions = {},
  ): () => void {
    const url = this.url(blobs, id, options);
    element.src = url;
    return () => {
      this.revoke(url);
      if (element.src === url) {
        element.removeAttribute("src");
        element.load();
      }
    };
  }

  /** Revokes a URL: it answers no more, and the reads under way for it stop. */
  revoke(url: string): void {
    const token = new URL(url, globalThis.location.origin).pathname.slice(this.#prefix.length);
    const served = this.#served.get(token);
    if (served === undefined) return;
    this.#served.delete(token);
    for (const serving of [...served.requests]) this.#end(serving);
  }

  /** How many readers are open for the elements' requests now. */
  get openReaders(): number {
    let open = 0;
    for (const serving of this.#serving.values()) if (serving.reader !== undefined) open += 1;
    return open;
  }

  /** Revokes every URL and leaves the service worker. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#disconnect?.();
    this.#served.clear();
    this.#port?.postMessage({ t: "bye" });
    this.#detach();
  }

  /** Ends the requests of the port held, and lets go of it. */
  #detach(): void {
    for (const serving of [...this.#serving.values()]) this.#end(serving);
    this.#port?.close();
    this.#port = undefined;
  }

  /** Ends a request: its read stops and its reader closes. */
  #end(serving: Serving): void {
    for (const [id, held] of this.#serving) if (held === serving) this.#serving.delete(id);
    serving.served.requests.delete(serving);
    serving.abort.abort();
    this.#rest(serving);
  }

  /** Closes a request's reader, which a later pull opens again. */
  #rest(serving: Serving): void {
    clearTimeout(serving.idle);
    const reader = serving.reader;
    serving.reader = undefined;
    void reader?.close().catch(() => {});
  }

  async #asked(port: MessagePort, ask: Ask): Promise<void> {
    if (ask.t === "cancel") {
      const serving = this.#serving.get(ask.id);
      if (serving !== undefined) this.#end(serving);
      return;
    }
    try {
      if (ask.t === "open") await this.#open(port, ask);
      else await this.#pull(port, ask.id);
    } catch {
      const serving = this.#serving.get(ask.id);
      if (serving !== undefined) this.#end(serving);
      if (ask.t === "open") port.postMessage({ t: "head", id: ask.id, status: 503, headers: [] });
      else port.postMessage({ t: "error", id: ask.id });
    }
  }

  async #open(port: MessagePort, ask: Ask & { t: "open" }): Promise<void> {
    const head = (status: number, headers: [string, string][] = []): void =>
      port.postMessage({ t: "head", id: ask.id, status, headers });
    const served = this.#served.get(ask.token);
    if (served === undefined) {
      head(404);
      return;
    }
    const serving: Serving = {
      served,
      port,
      position: 0,
      end: 0,
      reader: undefined,
      abort: new AbortController(),
      idle: undefined,
    };
    this.#serving.set(ask.id, serving);
    served.requests.add(serving);
    // The size is the blob's, whichever request learnt it: a later one fetches no chunk for it,
    // and opens its reader when the element reads.
    let size = served.size;
    if (size === undefined) {
      const reader = await served.blobs.openReader(served.id, served.read);
      if (this.#serving.get(ask.id) !== serving) {
        // Given up while the reader opened, as when the URL was revoked: the request is
        // answered all the same, so that it ends at the service worker.
        head(404);
        await reader.close();
        return;
      }
      serving.reader = reader;
      size = await reader.fetchSize({ signal: serving.abort.signal });
      if (this.#serving.get(ask.id) !== serving) {
        head(404);
        return;
      }
      served.size = size;
    }
    const range = rangeOf(ask.range, size);
    const about: [string, string][] = [
      ["content-type", served.type],
      ["accept-ranges", "bytes"],
    ];
    if (range === "none") {
      this.#end(serving);
      head(416, [...about, ["content-range", `bytes */${size}`]]);
      return;
    }
    const [start, end] = range ?? [0, size];
    serving.position = start;
    serving.end = end;
    about.push(["content-length", String(end - start)]);
    if (range !== undefined) about.push(["content-range", `bytes ${start}-${end - 1}/${size}`]);
    if (ask.method === "HEAD") this.#end(serving);
    else this.#idle(serving);
    head(range === undefined ? 200 : 206, about);
  }

  async #pull(port: MessagePort, id: number): Promise<void> {
    const serving = this.#serving.get(id);
    if (serving === undefined) {
      port.postMessage({ t: "error", id });
      return;
    }
    clearTimeout(serving.idle);
    if (serving.position >= serving.end) {
      this.#end(serving);
      port.postMessage({ t: "end", id });
      return;
    }
    const { served, abort } = serving;
    if (serving.reader === undefined) {
      const reader = await served.blobs.openReader(served.id, served.read);
      if (this.#serving.get(id) !== serving) {
        // Given up while the reader opened: answered all the same, so that the request ends.
        port.postMessage({ t: "error", id });
        await reader.close();
        return;
      }
      serving.reader = reader;
    }
    const piece = await serving.reader.read(
      serving.position,
      Math.min(PIECE, serving.end - serving.position),
      { signal: abort.signal },
    );
    if (piece.length === 0) throw new FrasilError("missing", "the blob ended before its size");
    serving.position += piece.length;
    if (this.#serving.get(id) !== serving) {
      port.postMessage({ t: "error", id });
      return;
    }
    this.#idle(serving);
    const data = piece.buffer as ArrayBuffer;
    port.postMessage({ t: "chunk", id, data }, [data]);
  }

  /** Closes a request's reader once nothing was asked of it for a while. */
  #idle(serving: Serving): void {
    clearTimeout(serving.idle);
    serving.idle = setTimeout(() => this.#rest(serving), this.#idleAfter);
  }
}

/**
 * Connects a page to the service worker that controls it, for a {@link MediaServer} that lives
 * in a worker: `onPort` is called with a port to the service worker, once it answers and again
 * each time it asks for one, as it does after the browser stopped and started it. Hand each
 * port to the worker, which gives it to {@link MediaServer.attach}. Resolves, once the service
 * worker has taken the first port, to the function that stops it; rejects with `timeout` when
 * none takes it in time ({@link MediaConnection.timeout}).
 *
 * It may be called more than once in a page, once for each server: each call brings a port of
 * its own.
 *
 * ```ts
 * // the page
 * await connectMediaPort((port) => worker.postMessage({ mediaPort: port }, [port]));
 * // the worker
 * const media = new MediaServer();
 * self.onmessage = ({ data }) => data.mediaPort && media.attach(data.mediaPort);
 * ```
 *
 * Call it in a page: the service worker sends an element's requests to the port of the page the
 * element is in.
 */
export async function connectMediaPort(
  onPort: (port: MessagePort) => void,
  options: MediaConnection = {},
): Promise<() => void> {
  const workers = (globalThis.navigator as Navigator | undefined)?.serviceWorker;
  if (workers === undefined || typeof document === "undefined") {
    throw new FrasilError(
      "unsupported",
      "Media needs a page with service workers: a secure context, outside a worker.",
      { whatToDo: "call connectMediaPort in the page, and hand its ports to the worker" },
    );
  }
  const limit = options.timeout ?? CONNECT_WAIT;
  // The start of the service worker that has this page's port. The worker asks for a port
  // under the name of its start: once when the page says hello, and again whenever a request
  // finds it with none, as after the browser stopped and started it. One port goes to each
  // start, so a port on its way is not replaced under the requests that use it.
  let connected: unknown;
  /** The ports sent that the worker has not said it took. */
  const sent = new Set<string>();
  let taken: () => void = () => {};
  const took = new Promise<void>((resolve) => {
    taken = resolve;
  });
  const hello = (): void => workers.controller?.postMessage({ frasilMedia: "hello" });
  const asked = (event: MessageEvent): void => {
    const data = event.data as { frasilMedia?: unknown; instance?: unknown; n?: unknown } | null;
    if (data?.frasilMedia === "taken") {
      if (typeof data.n === "string" && sent.delete(data.n)) taken();
      return;
    }
    const controller = workers.controller;
    if (data?.frasilMedia !== "connect" || data.instance === connected || controller === null) {
      return;
    }
    connected = data.instance;
    const { port1, port2 } = new MessageChannel();
    const n = random(8);
    sent.add(n);
    controller.postMessage({ frasilMedia: "port", n }, [port1]);
    onPort(port2);
  };
  const stop = (): void => {
    workers.removeEventListener("message", asked);
    workers.removeEventListener("controllerchange", hello);
  };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const none = workers.controller === null;
      reject(
        new FrasilError(
          "timeout",
          none
            ? `No service worker came to control this page within ${limit} ms.`
            : `The service worker that controls this page did not take its media port within ${limit} ms.`,
          {
            whatToDo: none
              ? "serve the service worker's script from the page's directory or one above it, or with a Service-Worker-Allowed header and that scope; load the page without a forced reload; use https or localhost"
              : "register the media service worker at a scope that covers the page, or call handleMedia in the service worker that controls it, with the same prefix",
          },
        ),
      );
    }, limit);
  });
  try {
    if (options.serviceWorker !== undefined) {
      await Promise.race([
        workers.register(
          options.serviceWorker,
          options.scope === undefined ? undefined : { scope: options.scope },
        ),
        expired,
      ]);
    }
    if (workers.controller === null) {
      await Promise.race([
        new Promise<void>((resolve) => {
          workers.addEventListener("controllerchange", () => resolve(), { once: true });
        }),
        expired,
      ]);
    }
    workers.addEventListener("message", asked);
    workers.addEventListener("controllerchange", hello);
    workers.startMessages();
    hello();
    await Promise.race([took, expired]);
  } catch (error) {
    stop();
    throw error;
  } finally {
    clearTimeout(timer);
    // Not waited for by anything once the timer is cleared.
    expired.catch(() => {});
  }
  return stop;
}
