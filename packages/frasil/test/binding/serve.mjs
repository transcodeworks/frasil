// The origin the browser tests load, on loopback: the built package (`/dist/`), the test pages'
// scripts (`/test/binding/*.js`), the page the scenarios drive (`/runner.html`), the Content
// Security Policy experiment's page (`/csp`), and a same-origin proxy to the peer for its routes
// (`/.well-known/frasil` and `/frasil/p1/`, the WebSocket included). The proxy keeps the request's
// `Host`, so the peer takes the origin a page connected to as the connection's origin, as one
// behind a reverse proxy does. `POST /test/reconnect` closes the WebSockets of the page whose
// `frasil-test-tag` cookie it carries with `reconnect`, as a peer moving them to another of its
// machines does.
//
// `/wrong-mime/dist/…` serves the same files with `.wasm` as `application/octet-stream`, as a server
// that does not know the type does, to test that the package falls back from streaming.
//
//   FRASIL_TEST_PORT=… FRASIL_TEST_PEER_PORT=… node test/binding/serve.mjs
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer, request as forward } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const packageDir = fileURLToPath(new URL("../..", import.meta.url));
const port = Number(process.env.FRASIL_TEST_PORT ?? 0);
const peerPort = Number(process.env.FRASIL_TEST_PEER_PORT ?? 8787);

/** @type {Record<string, string>} */
const types = {
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json",
  ".html": "text/html; charset=utf-8",
  ".wasm": "application/wasm",
};

/** The page the scenarios drive: it loads the package and waits for `page.evaluate`. */
const runner = `<!doctype html>
<meta charset="utf-8">
<title>frasil binding tests</title>
<script type="module" src="/test/binding/page.js"></script>`;

/**
 * A page of the policy experiment. `policy` has `{nonce}` where the nonce goes; `load` is how the
 * nonced module script loads the package: a static import, or `import()`. It loads the package,
 * opens a device in memory (randomness from `crypto.getRandomValues`), creates a space and connects
 * to the peer through this origin, and records each step in `window.csp`.
 *
 * @param {string} nonce @param {string | null} load @param {string | null} entry
 */
function cspPage(nonce, load, entry) {
  const path = entry === "embedded" ? "/dist/embedded/index.js" : "/dist/index.js";
  const body =
    load === "dynamic"
      ? `const frasil = await import("${path}");`
      : `import * as frasil from "${path}";`;
  return `<!doctype html>
<meta charset="utf-8">
<title>pending</title>
<script nonce="${nonce}">
window.csp = { loaded: false, device: null, peer: null, errors: [] };
window.addEventListener("error", (event) => { window.csp.errors.push(String(event.message)); });
window.addEventListener("unhandledrejection", (event) => { window.csp.errors.push(String(event.reason)); });
</script>
<script type="module" nonce="${nonce}">
${body}
window.csp.loaded = true;
let device;
try {
  const key = crypto.getRandomValues(new Uint8Array(32));
  device = await frasil.Device.open(frasil.Storage.memory(), key);
  await device.createSpace();
  window.csp.device = device.id.length;
} catch (error) {
  window.csp.device = "failed: " + (error.code ?? error.name) + ": " + error.message;
}
try {
  const peer = await device.connect(location.origin);
  const started = Date.now();
  while (peer.status().spaces.length === 0 && peer.status().connected && Date.now() - started < 20000) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  window.csp.peer = peer.status().spaces.length > 0 ? "granted" : "not granted: " + peer.status().closed;
  await device.close();
} catch (error) {
  window.csp.peer = "failed: " + (error.code ?? error.name) + ": " + error.message;
}
document.title = "done";
</script>`;
}

/** `reconnect`'s WebSocket close code (transport.md, "The server binding"). */
const RECONNECT = 4017;

/**
 * The proxied WebSockets by the page's `frasil-test-tag` cookie, each with a call that closes it
 * with `reconnect`, as a peer moving the connection to another of its machines does.
 *
 * @type {Map<string, Set<() => void>>}
 */
const tagged = new Map();

/** The `frasil-test-tag` cookie of a request, if it has one. */
function tagOf(/** @type {import("node:http").IncomingMessage} */ incoming) {
  for (const part of (incoming.headers.cookie ?? "").split(";")) {
    const [name, value] = part.trim().split("=");
    if (name === "frasil-test-tag" && value) return value;
  }
  return null;
}

/**
 * Pipes the peer's side of a WebSocket to the browser's, frame by frame (the peer's frames are
 * unmasked), and returns a call that, at the next frame boundary, stops the peer's bytes and sends
 * the browser a close frame with `reconnect` instead.
 *
 * @param {import("node:stream").Duplex} upstream @param {import("node:stream").Duplex} socket
 */
function relayFrames(upstream, socket) {
  /** The payload bytes left of the current frame. */
  let remaining = 0;
  /** The bytes of a frame header read so far. */
  let header = Buffer.alloc(0);
  let closing = false;
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    upstream.destroy();
    socket.write(Buffer.from([0x88, 0x02, RECONNECT >> 8, RECONNECT & 0xff]));
    // The browser answers with its own close; the socket ends after it, or at once if not.
    setTimeout(() => socket.destroy(), 1_000);
  };
  upstream.on("data", (/** @type {Buffer} */ chunk) => {
    let at = 0;
    while (at < chunk.length && !closed) {
      if (remaining > 0) {
        const take = Math.min(remaining, chunk.length - at);
        socket.write(chunk.subarray(at, at + take));
        remaining -= take;
        at += take;
        continue;
      }
      if (closing && header.length === 0) {
        close();
        return;
      }
      header = Buffer.concat([header, chunk.subarray(at, at + 1)]);
      at += 1;
      if (header.length < 2) continue;
      const short = header[1] & 0x7f;
      const masked = (header[1] & 0x80) !== 0;
      const extended = short === 126 ? 2 : short === 127 ? 8 : 0;
      const length = 2 + extended + (masked ? 4 : 0);
      if (header.length < length) continue;
      const payload =
        short === 126
          ? header.readUInt16BE(2)
          : short === 127
            ? Number(header.readBigUInt64BE(2))
            : short;
      socket.write(header);
      header = Buffer.alloc(0);
      remaining = payload;
    }
    if (closing && remaining === 0 && header.length === 0) close();
  });
  return () => {
    closing = true;
    if (remaining === 0 && header.length === 0) close();
  };
}

/** Whether a path is one of the peer's routes. */
function peerRoute(/** @type {string} */ path) {
  return path === "/.well-known/frasil" || path.startsWith("/frasil/p1/");
}

const server = createServer(async (incoming, outgoing) => {
  const url = new URL(incoming.url ?? "/", "http://localhost");
  if (peerRoute(url.pathname)) {
    const proxied = forward(
      {
        host: "127.0.0.1",
        port: peerPort,
        method: incoming.method,
        path: incoming.url,
        headers: incoming.headers,
      },
      (answer) => {
        outgoing.writeHead(answer.statusCode ?? 502, answer.headers);
        answer.pipe(outgoing);
      },
    );
    proxied.on("error", () => {
      outgoing.writeHead(502);
      outgoing.end();
    });
    incoming.pipe(proxied);
    return;
  }
  if (url.pathname === "/test/reconnect" && incoming.method === "POST") {
    const tag = tagOf(incoming);
    const sockets = tag ? (tagged.get(tag) ?? new Set()) : new Set();
    for (const close of sockets) close();
    outgoing.writeHead(200, { "content-type": types[".json"] });
    outgoing.end(JSON.stringify({ closed: sockets.size }));
    return;
  }
  if (url.pathname === "/runner.html") {
    outgoing.writeHead(200, { "content-type": types[".html"] });
    outgoing.end(runner);
    return;
  }
  if (url.pathname === "/csp") {
    const nonce = randomBytes(16).toString("base64");
    const policy = (url.searchParams.get("policy") ?? "").replaceAll("{nonce}", nonce);
    outgoing.writeHead(200, {
      "content-type": types[".html"],
      "content-security-policy": policy,
    });
    outgoing.end(cspPage(nonce, url.searchParams.get("load"), url.searchParams.get("entry")));
    return;
  }
  const wrongMime = url.pathname.startsWith("/wrong-mime/dist/");
  const path = wrongMime ? url.pathname.slice("/wrong-mime".length) : url.pathname;
  const served = path.startsWith("/dist/") || path.startsWith("/test/binding/");
  const file = normalize(join(packageDir, decodeURIComponent(path)));
  if (!served || !file.startsWith(packageDir)) {
    outgoing.writeHead(404);
    outgoing.end();
    return;
  }
  try {
    const body = await readFile(file);
    outgoing.writeHead(200, {
      "content-type":
        wrongMime && extname(file) === ".wasm"
          ? "application/octet-stream"
          : (types[extname(file)] ?? "application/octet-stream"),
      "cache-control": "no-store",
      "content-length": body.byteLength,
    });
    outgoing.end(body);
  } catch {
    outgoing.writeHead(404);
    outgoing.end();
  }
});

// The WebSocket: the upgrade request is forwarded as it came, and the two sockets are joined.
server.on("upgrade", (incoming, socket, head) => {
  const url = new URL(incoming.url ?? "/", "http://localhost");
  if (!peerRoute(url.pathname)) {
    socket.destroy();
    return;
  }
  const proxied = forward({
    host: "127.0.0.1",
    port: peerPort,
    method: incoming.method,
    path: incoming.url,
    headers: incoming.headers,
  });
  proxied.on("upgrade", (answer, upstream, upstreamHead) => {
    const lines = [`HTTP/1.1 ${answer.statusCode} ${answer.statusMessage}`];
    for (let index = 0; index < answer.rawHeaders.length; index += 2) {
      lines.push(`${answer.rawHeaders[index]}: ${answer.rawHeaders[index + 1]}`);
    }
    socket.write(`${lines.join("\r\n")}\r\n\r\n`);
    if (upstreamHead.length > 0) socket.write(upstreamHead);
    if (head.length > 0) upstream.write(head);
    let reconnecting = false;
    const reconnect = relayFrames(upstream, socket);
    const close = () => {
      reconnecting = true;
      socket.unpipe(upstream);
      reconnect();
    };
    socket.pipe(upstream);
    upstream.on("error", () => {
      if (!reconnecting) socket.destroy();
    });
    socket.on("error", () => upstream.destroy());
    upstream.on("close", () => {
      if (!reconnecting) socket.destroy();
    });
    const tag = tagOf(incoming);
    if (tag) {
      const sockets = tagged.get(tag) ?? new Set();
      sockets.add(close);
      tagged.set(tag, sockets);
    }
    socket.on("close", () => {
      upstream.destroy();
      if (tag) tagged.get(tag)?.delete(close);
    });
  });
  proxied.on("response", (answer) => {
    socket.end(`HTTP/1.1 ${answer.statusCode} ${answer.statusMessage}\r\n\r\n`);
  });
  proxied.on("error", () => socket.destroy());
  proxied.end();
});

server.listen(port, "127.0.0.1");
