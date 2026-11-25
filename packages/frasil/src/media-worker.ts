/**
 * The service worker's side of `@frasil/client/media`: it answers the requests a media element
 * makes for a URL the page minted, by asking the page for the bytes. It holds no blob, no key and
 * no client: the client cannot run in a service worker, so each request goes over a
 * `MessagePort` to the page that runs it, or to that page's worker.
 *
 * It keeps one thing, which it can ask for again: the ports of each page, by the page's client
 * ID. A page has one port for each `MediaServer` it connected, and each server says over its port
 * which URLs are its own: a URL's path begins with the name of the server that minted it. A
 * browser may stop a service worker at any time and start it again for the next request; it then
 * asks the page that made the request for its ports. Each start of the worker has a name of its
 * own, which it asks under, so that a page sends each server's port once to each start and no
 * second one while the first is on its way. A request is only ever sent to a port of the page
 * that made it, so a page reads through a URL only what it serves itself.
 *
 * It answers requests that load a media element or that a script makes, and no other: a
 * navigation, a frame, an `<object>` or an `<embed>` gets `404`, so a URL never becomes a
 * document. Every answer says `X-Content-Type-Options: nosniff`,
 * `Content-Security-Policy: sandbox; default-src 'none'`,
 * `Cross-Origin-Resource-Policy: same-origin` and `Cache-Control: no-store`, and names a media
 * type from a short list ({@link mediaType}).
 *
 * {@link handleMedia} is the whole of it, for an application's own service worker:
 *
 * ```ts
 * import { handleMedia } from "@frasil/client/media/worker";
 *
 * self.addEventListener("fetch", (event) => {
 *   if (handleMedia(event)) return;
 *   // the application's own requests
 * });
 * self.addEventListener("message", (event) => {
 *   if (handleMedia(event)) return;
 *   // the application's own messages
 * });
 * ```
 *
 * `@frasil/client/media-sw.js` is the same as a script to host as it is.
 *
 * This module imports nothing.
 *
 * @module
 */

/** The path under which the page mints its URLs, unless both sides are given another. */
export const MEDIA_PREFIX = "/frasil-media/";

/**
 * How many characters at the start of a URL's last segment name the server that minted it.
 *
 * @internal
 */
export const SERVER_NAME_LENGTH = 8;

/** How long a request waits for its page to send a port, in milliseconds. */
const PORT_WAIT = 10_000;

/**
 * How long a request for a server this worker does not know waits for it, when the page's other
 * servers are all known: a server's first message may still be on its way.
 */
const PORT_GRACE = 1_000;

/** What every answer says, whatever the page sent. */
const GUARD: readonly (readonly [string, string])[] = [
  ["cache-control", "no-store"],
  ["cross-origin-resource-policy", "same-origin"],
  ["x-content-type-options", "nosniff"],
  ["content-security-policy", "sandbox; default-src 'none'"],
];

/** The request destinations that would make a document of the answer. */
const DOCUMENTS = new Set(["document", "iframe", "frame", "object", "embed"]);

/**
 * A prefix as both sides use it: a path that begins and ends with a slash, so that `/media`
 * takes `/media/…` and never `/mediafoo`.
 *
 * @internal
 */
export function mediaPrefix(prefix: string): string {
  const leading = prefix.startsWith("/") ? prefix : `/${prefix}`;
  return leading.endsWith("/") ? leading : `${leading}/`;
}

/**
 * The media type an answer names for `type`: `type` itself when it is `audio/…`, `video/…`,
 * `image/…` other than SVG, `application/ogg` or `application/octet-stream`, with its
 * parameters; `application/octet-stream` for anything else, so that no answer is a document, a
 * script or a style sheet.
 *
 * @internal
 */
export function mediaType(type: string | undefined): string {
  const given = (type ?? "").trim();
  const essence = (given.split(";")[0] ?? "").trim().toLowerCase();
  const allowed =
    essence === "application/ogg" ||
    essence === "application/octet-stream" ||
    (/^(audio|video|image)\/[a-z0-9][a-z0-9.+-]*$/.test(essence) && essence !== "image/svg+xml");
  // A header's value is one line of visible characters.
  return allowed && /^[\x20-\x7e]*$/.test(given) ? given : "application/octet-stream";
}

/** What a `fetch` event has that the handler uses. */
interface FetchLike {
  readonly request: Request;
  readonly clientId: string;
  respondWith(response: Promise<Response> | Response): void;
  waitUntil(work: Promise<unknown>): void;
}

/** What a `message` event has that the handler uses. */
interface MessageLike {
  readonly data: unknown;
  readonly source: { readonly id?: string; postMessage?(message: unknown): void } | null;
  readonly ports: readonly MessagePort[];
}

/** The service worker's global scope, as far as the handler uses it. */
interface Scope {
  readonly location: { readonly origin: string };
  readonly clients: {
    get(id: string): Promise<{ postMessage(message: unknown): void } | undefined>;
    matchAll(options: {
      includeUncontrolled: boolean;
      type: "all";
    }): Promise<readonly { readonly id: string }[]>;
  };
}

/**
 * What a server sends over its port: `serve` names it, `bye` says it closed, and the others
 * answer a request.
 */
type Answer =
  | { t: "serve"; server: string; id?: undefined }
  | { t: "bye"; id?: undefined }
  | { t: "head"; id: number; status: number; headers: [string, string][] }
  | { t: "chunk"; id: number; data: ArrayBuffer }
  | { t: "end"; id: number }
  | { t: "error"; id: number };

/** What answers a request. */
type Reply = Exclude<Answer, { t: "serve" } | { t: "bye" }>;

/** A request that waits for a server's port. */
interface Waiting {
  readonly server: string;
  readonly resolve: (port: MessagePort | undefined) => void;
}

/** A page's ports. */
interface Page {
  /** The port of each server that named itself. */
  readonly servers: Map<string, MessagePort>;
  /** The ports whose servers have not named themselves yet. */
  readonly unnamed: Set<MessagePort>;
  readonly waiting: Set<Waiting>;
}

const scope = globalThis as unknown as Scope;

/** This start of the worker: a page sends it each server's port once. */
const instance = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;

/** Each page, by its client ID. */
const pages = new Map<string, Page>();
/** The requests under way, each with its port and what takes the server's next answer. */
const requests = new Map<number, { port: MessagePort; take: (answer: Reply) => void }>();
let last = 0;

/**
 * Handles a service worker's `fetch` or `message` event if it is the media helper's: a request
 * for a URL under `prefix` on this origin, or a page's message that asks which start of the
 * worker this is or brings a port. Returns whether it was; a `fetch` event it took has been
 * answered with `respondWith`. A `prefix` is a path that ends with a slash: one that does not is
 * given one.
 */
export function handleMedia(event: unknown, prefix: string = MEDIA_PREFIX): boolean {
  const { request } = event as Partial<FetchLike>;
  if (request === undefined) return message(event as MessageLike);
  const under = mediaPrefix(prefix);
  const url = new URL(request.url);
  if (url.origin !== scope.location.origin || !url.pathname.startsWith(under)) return false;
  const fetch = event as FetchLike;
  // A minted URL is an element's or a script's, never a document's: whatever page asks.
  if (request.mode === "navigate" || DOCUMENTS.has(request.destination)) {
    fetch.respondWith(plain(404));
    return true;
  }
  // The worker stays for as long as the element reads the answer.
  let ended: () => void = () => {};
  fetch.waitUntil(
    new Promise<void>((resolve) => {
      ended = resolve;
    }),
  );
  fetch.respondWith(respond(request, fetch.clientId, url.pathname.slice(under.length), ended));
  return true;
}

function message(event: MessageLike): boolean {
  const data = event.data as { frasilMedia?: unknown; n?: unknown } | null;
  const tag = data?.frasilMedia;
  const client = event.source?.id;
  if (tag === "hello") {
    event.source?.postMessage?.({ frasilMedia: "connect", instance });
    return true;
  }
  const port = event.ports[0];
  if (tag !== "port" || client === undefined || port === undefined) return false;
  const page = pageOf(client);
  page.unnamed.add(port);
  port.onmessage = ({ data }: MessageEvent<Answer>) => {
    if (data.t === "serve") named(page, port, data.server);
    else if (data.t === "bye") drop(page, port);
    else {
      const request = requests.get(data.id);
      if (request?.port === port) request.take(data);
    }
  };
  // The page knows from here on that this start of the worker holds the port.
  event.source?.postMessage?.({ frasilMedia: "taken", n: data?.n });
  void prune();
  return true;
}

function pageOf(client: string): Page {
  let page = pages.get(client);
  if (page === undefined) {
    page = { servers: new Map(), unnamed: new Set(), waiting: new Set() };
    pages.set(client, page);
  }
  return page;
}

/** A server named itself over its port: the requests that wait for it go on. */
function named(page: Page, port: MessagePort, server: string): void {
  if (!page.unnamed.delete(port)) return;
  const before = page.servers.get(server);
  if (before !== undefined) drop(page, before);
  page.servers.set(server, port);
  for (const waits of [...page.waiting]) if (waits.server === server) waits.resolve(port);
}

/** Forgets a port, and fails the requests that went over it. */
function drop(page: Page, port: MessagePort): void {
  page.unnamed.delete(port);
  for (const [server, held] of [...page.servers]) if (held === port) page.servers.delete(server);
  for (const [id, request] of [...requests]) {
    if (request.port !== port) continue;
    requests.delete(id);
    request.take({ t: "error", id });
  }
  port.close();
}

/** Forgets the ports of pages that are gone. */
async function prune(): Promise<void> {
  const live = new Set(
    (await scope.clients.matchAll({ includeUncontrolled: true, type: "all" })).map(({ id }) => id),
  );
  for (const [client, page] of [...pages]) {
    if (live.has(client)) continue;
    for (const port of [...page.unnamed, ...page.servers.values()]) drop(page, port);
    pages.delete(client);
  }
}

/**
 * The port of the server `server` of the page `client`, or the status to answer with when there
 * is none. A page this start of the worker holds no port of is asked for its ports, and the
 * request waits for the server's: `503` if it does not come. Where the worker holds ports of the
 * page and not this server's, the request waits for the servers that have not named themselves,
 * and a moment when all have: `404` then, for a URL no server of the page minted.
 */
async function portOf(client: string, server: string): Promise<MessagePort | number> {
  const held = pages.get(client)?.servers.get(server);
  if (held !== undefined) return held;
  let page = pages.get(client);
  const asks = page === undefined || page.servers.size + page.unnamed.size === 0;
  if (asks) {
    const target = await scope.clients.get(client);
    // The port may have come while the page was looked up.
    const came = pages.get(client)?.servers.get(server);
    if (came !== undefined) return came;
    if (target === undefined) return 503;
    target.postMessage({ frasilMedia: "connect", instance });
  }
  page = pageOf(client);
  const unnamed = page.unnamed.size > 0;
  const waited = await new Promise<MessagePort | undefined>((resolve) => {
    const waits: Waiting = {
      server,
      resolve: (port) => {
        page.waiting.delete(waits);
        resolve(port);
      },
    };
    page.waiting.add(waits);
    setTimeout(() => waits.resolve(undefined), asks || unnamed ? PORT_WAIT : PORT_GRACE);
  });
  return waited ?? (asks || unnamed ? 503 : 404);
}

/** The headers of an answer: the page's, a media type from the list, and the guard's. */
function guarded(given: readonly (readonly [string, string])[] = []): Headers {
  const headers = new Headers();
  for (const [name, value] of given) {
    try {
      headers.set(name, name.toLowerCase() === "content-type" ? mediaType(value) : value);
    } catch {
      // Not a header: left out.
    }
  }
  for (const [name, value] of GUARD) headers.set(name, value);
  return headers;
}

/**
 * An answer with no body. It is told as plain text, so that a browser asked to open it as a page
 * shows an empty one and saves no file.
 */
function plain(status: number): Response {
  const headers = guarded();
  headers.set("content-type", "text/plain; charset=utf-8");
  return new Response(null, { status, headers });
}

async function respond(
  request: Request,
  client: string,
  token: string,
  ended: () => void,
): Promise<Response> {
  const without = (status: number): Response => {
    ended();
    return plain(status);
  };
  if (request.method !== "GET" && request.method !== "HEAD") return without(405);
  // A request with no client is no page's.
  if (client === "") return without(404);
  const port = await portOf(client, token.slice(0, SERVER_NAME_LENGTH));
  if (typeof port === "number") return without(port);
  last += 1;
  const id = last;
  const next = (ask: object): Promise<Reply> =>
    new Promise((resolve) => {
      requests.set(id, { port, take: resolve });
      port.postMessage({ ...ask, id });
    });
  /** The request is over: nothing more of it is asked of the page. */
  const over = (): boolean => {
    ended();
    return requests.delete(id);
  };
  // The element gave the request up, as it does at each seek: the page stops reading for it.
  const cancel = (): void => {
    const waits = requests.get(id);
    if (!over()) return;
    port.postMessage({ t: "cancel", id });
    waits?.take({ t: "error", id });
  };
  request.signal.addEventListener("abort", cancel);
  const head = await next({
    t: "open",
    token,
    method: request.method,
    range: request.headers.get("range"),
  });
  if (head.t !== "head") {
    over();
    return plain(503);
  }
  const init = { status: head.status, headers: guarded(head.headers) };
  if (request.method === "HEAD" || (head.status !== 200 && head.status !== 206)) {
    over();
    return new Response(null, init);
  }
  // One piece for each pull: the page reads no faster than the element takes.
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (!requests.has(id)) {
        controller.error(new DOMException("the request was aborted", "AbortError"));
        return;
      }
      const answer = await next({ t: "pull" });
      if (answer.t === "chunk") {
        controller.enqueue(new Uint8Array(answer.data));
        return;
      }
      over();
      if (answer.t === "end") controller.close();
      else controller.error(new TypeError("the blob could not be read"));
    },
    cancel,
  });
  return new Response(body, init);
}
