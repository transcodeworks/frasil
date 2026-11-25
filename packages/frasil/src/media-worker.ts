/**
 * The service worker's side of `@frasil/client/media`: it answers the requests a media element
 * makes for a URL the page minted, by asking the page for the bytes. It holds no blob, no key and
 * no client: the client cannot run in a service worker, so each request goes over a
 * `MessagePort` to the page that runs it, or to that page's worker.
 *
 * It keeps one thing, which it can ask for again: the port of each page, by the page's client
 * ID. A browser may stop a service worker at any time and start it again for the next request;
 * it then asks the page that made the request for a new port. Each start of the worker has a
 * name of its own, which it asks under, so that a page sends one port to each start and no
 * second one while the first is on its way. A request is only ever sent to the
 * port of the page that made it, so a page reads through a URL only what it serves itself.
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

/** How long a request waits for its page to send a port, in milliseconds. */
const PORT_WAIT = 10_000;

/** What a `fetch` event has that the handler uses. */
interface FetchLike {
  readonly request: Request;
  readonly clientId: string;
  respondWith(response: Promise<Response>): void;
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

/** What the page answers a request with; `bye` says its server closed. */
type Answer =
  | { t: "bye"; id?: undefined }
  | { t: "head"; id: number; status: number; headers: [string, string][] }
  | { t: "chunk"; id: number; data: ArrayBuffer }
  | { t: "end"; id: number }
  | { t: "error"; id: number };

const scope = globalThis as unknown as Scope;

/** This start of the worker: a page sends it one port. */
const instance = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;

/** Each page's port, by its client ID. */
const ports = new Map<string, MessagePort>();
/** The requests that wait for a page's port. */
const waiting = new Map<string, ((port: MessagePort | undefined) => void)[]>();
/** The requests under way, each with its port and what takes the page's next answer. */
const requests = new Map<number, { port: MessagePort; take: (answer: Answer) => void }>();
let last = 0;

/**
 * Handles a service worker's `fetch` or `message` event if it is the media helper's: a request
 * for a URL under `prefix` on this origin, or a page's message that asks which start of the
 * worker this is or brings its port. Returns whether it was; a `fetch` event it took has been answered with `respondWith`.
 */
export function handleMedia(event: unknown, prefix: string = MEDIA_PREFIX): boolean {
  const { request } = event as Partial<FetchLike>;
  if (request === undefined) return message(event as MessageLike);
  const url = new URL(request.url);
  if (url.origin !== scope.location.origin || !url.pathname.startsWith(prefix)) return false;
  const fetch = event as FetchLike;
  // The worker stays for as long as the element reads the answer.
  let ended: () => void = () => {};
  fetch.waitUntil(
    new Promise<void>((resolve) => {
      ended = resolve;
    }),
  );
  fetch.respondWith(respond(request, fetch.clientId, url.pathname.slice(prefix.length), ended));
  return true;
}

function message(event: MessageLike): boolean {
  const tag = (event.data as { frasilMedia?: unknown } | null)?.frasilMedia;
  const client = event.source?.id;
  if (tag === "hello") {
    event.source?.postMessage?.({ frasilMedia: "connect", instance });
    return true;
  }
  const port = event.ports[0];
  if (tag !== "port" || client === undefined || port === undefined) return false;
  drop(client);
  ports.set(client, port);
  port.onmessage = ({ data }: MessageEvent<Answer>) => {
    if (data.t !== "bye") requests.get(data.id)?.take(data);
    else if (ports.get(client) === port) drop(client);
  };
  for (const resolve of waiting.get(client) ?? []) resolve(port);
  waiting.delete(client);
  void prune();
  return true;
}

/** Forgets a page's port, and fails the requests that went over it. */
function drop(client: string): void {
  const port = ports.get(client);
  if (port === undefined) return;
  ports.delete(client);
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
  for (const client of [...ports.keys()]) if (!live.has(client)) drop(client);
}

/** The port of the page `client`, asked of the page when this worker holds none. */
async function portOf(client: string): Promise<MessagePort | undefined> {
  const held = ports.get(client);
  if (held !== undefined) return held;
  const page = await scope.clients.get(client);
  // The port may have come while the page was looked up.
  const came = ports.get(client);
  if (came !== undefined || page === undefined) return came;
  return new Promise((resolve) => {
    waiting.set(client, [...(waiting.get(client) ?? []), resolve]);
    page.postMessage({ frasilMedia: "connect", instance });
    setTimeout(() => resolve(undefined), PORT_WAIT);
  });
}

function plain(status: number): Response {
  return new Response(null, { status, headers: { "cache-control": "no-store" } });
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
  // A navigation has no client yet: a minted URL is an element's, not a page's.
  const port = client === "" ? undefined : await portOf(client);
  if (port === undefined) return without(client === "" ? 404 : 503);
  last += 1;
  const id = last;
  const next = (ask: object): Promise<Answer> =>
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
  const init = { status: head.status, headers: head.headers };
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
