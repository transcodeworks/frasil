# @frasil/client

Frasil's client for browsers. A browser becomes a **device** that shares
**spaces** of documents, tables and files with other devices, end to end
encrypted, online and offline. It keeps its records sealed in the browser's
storage and syncs through **always-on peers**, which store and relay sealed
changes and hold no key.

It is the Rust crate `frasil` compiled to WebAssembly (`crates/frasil-wasm`),
with a thin TypeScript layer of the same shape: `Device`, `Storage`, `Space`,
`LoroDocument` (the Rust crate's `Document`, renamed so that it does not
shadow the DOM's `Document`), `Records`, `Blobs`, `Peer`, `Events`, and errors
that say what to do. Protocol 1's specification is in `docs/spec/`.

## Install

```sh
npm install @frasil/client
```

With pnpm: `pnpm add @frasil/client`; with Yarn: `yarn add @frasil/client`.
[WebAssembly and the browser package](../../docs/webassembly.md) says what the
build does.

The WebAssembly module (9 MB, 2.7 MB compressed) ships as a file,
`dist/wasm/frasil_wasm_bg.wasm`, next to the code that loads it. Importing the
package starts fetching it with `new URL("./wasm/frasil_wasm_bg.wasm",
import.meta.url)`, so Vite, webpack, Rollup, esbuild and Parcel emit the file
and rewrite the address, and the browser compiles it while it downloads
(`WebAssembly.instantiateStreaming`). Where the server names the wrong MIME
type for `.wasm` (it should be `application/wasm`), the package falls back to
compiling the downloaded bytes, which waits for the whole file. Node.js, Bun
and Deno read the file from disk. A dedicated worker finds it the same way.

An application that cannot host a file imports `@frasil/client/embedded`
instead: the same API, with the module inlined as base64 (a third larger, and
compiled only after all of it has arrived). See
[Entries](#entries). The package is ESM only.

## Quick start

Two devices share a note through a peer. Both run in one snippet here; in an
application each is a browser of its own, and what crosses between them (Bob's
ID and keys, the space's ID) goes however the application carries it.

```ts
import { Device, Storage } from "@frasil/client";

// Each device seals its keys under an unlock key: 32 bytes of high entropy,
// such as a passkey's PRF output, never a password.
const alice = await Device.open(Storage.indexedDb("alice"), aliceUnlockKey);
const bob = await Device.open(Storage.indexedDb("bob"), bobUnlockKey);

// Alice creates a space, and keeps it at the peer.
const space = await alice.createSpace();
await alice.connect("https://peer.example.org");

// Alice admits Bob's device by a direct grant, and hands him the space's
// signed events, which carry his keys. Bob takes them and connects.
await alice.advanced.grantDevice(space, bob.id, bob.advanced.deviceKeys(), "write");
const bobsSpace = await bob.advanced.follow(space.id);
await bob.advanced.ingest(space.id, await alice.advanced.signedEvents(space));
await bob.connect("https://peer.example.org");

// Alice writes a note; Bob opens it once it has arrived, and edits it too.
// The edits merge.
const note = space.createDocument();
await note.edit((doc) => doc.text("body").insert(0, "Hello"));
const bobsNote = await bobsSpace.documentWhenAvailable(note.id, 30_000);
await bobsNote.edit((doc) => doc.text("body").insert(0, "Bob: "));
```

It is the Rust example `crates/frasil/examples/shared_note.rs`, with one
difference: admission by code is not available in browsers yet (see
[Admitting a device](#admitting-a-device)).

## What a device does by itself

- **Sync.** Each peer connection syncs every space the device holds, both ways
  and live. Spaces the device creates or follows later are presented too.
- **Durability.** A peer acknowledges what it keeps; until then a change is
  offered again, and kept at rest across reloads. `space.isDurable()` says
  whether every change has been acknowledged, and `space.flush()` waits until
  it has, such as before a browser that changed who administers closes.
  `space.waitDurable(withinMs)` resolves as soon as the changes are
  acknowledged, or rejects at its deadline, without waiting for an
  administration connection to finish.
- **Welcomes.** When a space grants this device's person, the granting device
  deposits a welcome in this device's mailbox at its peers; the device collects
  it there and keeps the space once the space's own roster admits it. It
  collects on a WebSocket of its own per peer, which presents none of its
  spaces, so the peer does not link the device to them.
- **Delayed deliveries.** A welcome, a leave request or a person's list that a
  peer answers `busy` or `rate_limited`, or that cannot reach the peer, is kept
  in IndexedDB and sent again with a growing wait, for up to 30 days. The
  events `"delayed"`, `"delivered"` and `"undelivered"` report it, and
  `device.waitingDeposits()` counts what waits.
- **Deposit tokens.** At a peer where the application handed the device a
  deposit grant, or where it writes a space, the device draws anonymous tokens
  ahead of need, within the hour, and pays with one for each deposit in a
  device mailbox there, on a WebSocket of its own that presents nothing. See
  `docs/deposit-tokens.md`.
- **Upkeep.** Heals and cascades run on the page's event loop while the device
  is open, so that a removed member reads nothing new. `device.close()` stops
  them.
- **Checkpoints.** An administrator's device proposes a checkpoint of a space
  once its membership history since the last one grows past a threshold, votes
  for one by writing after it, and forgets what came before one in effect; a
  device of a person does the same for the person's device list.
  `device.setCheckpointPolicy({ propose, forget, rosterEvents, frameBytes })`
  changes that; see `docs/checkpoints.md`.

## The API

| | |
|---|---|
| `Device.open(storage, unlockKey, options?)` | opens the device kept in `storage`, or creates one there |
| `device.id` | its member ID |
| `device.createSpace()`, `device.createSpaceOfKind(kind)`, `device.space(id)`, `device.spaces()` | its spaces; `space.kind()` reads the kind an application gave a space |
| `device.connect(url)`, `device.peers()` | always-on peers; `peer.status()`, which lists among the rest the spaces in which the peer served less than the device knows of (`withheld`) or lost events it acknowledged (`rolledBack`), and `peer.close()` |
| `device.events()` | `await events.next()` or `for await (const event of events)`: `"changed"`, `"removed"` (this device left the space's roster), `"moved"`, `"delayed"`, `"delivered"`, `"undelivered"`, `"depositPeerDistrusted"`, and what the device detects of its peers and members: `"withheld"` (a peer served less than the device knows of), `"rolledBack"` (a peer, or with `member` a member, lost events it acknowledged), `"badStatement"` (a member's head statement named events it could not supply), and checkpoints: `"checkpointPending"` (with `waitingFor`), `"checkpointInEffect"`, `"badCheckpoint"`, `"late"` (with the `changes` to make again), `"mixedCut"`, `"checkpointRival"`, `"checkpointWithheld"`, `"backdatedCheckpoint"`, `"listCheckpointPending"` and `"listCheckpointRival"`; and `"needsLaterVersion"` (the space uses a document of a later version than this build: the device signs nothing more there) |
| `device.deriveKey(purpose)`, `space.deriveKey(purpose)` | 32-byte keys for the application's own data at rest, one per purpose, for the device or for one space |
| `device.close()` | stops its upkeep and connections |
| `device.createRecoverySheet()`, `Device.recover(storage, unlockKey, sheet, peerUrl)` | a recovery sheet for the device's person, and a new device made from it after every other is lost; IndexedDB retains the recovered keys across reopening |
| `space.members()`, `space.level()`, `space.remove(member)` | its members |
| `space.checkpoints()`, `space.proposeCheckpoint()`, `space.lateChanges()` | the space's checkpoints: the one in effect, those waiting for votes with `waitingFor`, and the verdicts they gave (`withheld`, `rivals`, `backdated` and the rest); a checkpoint now; this device's membership changes a checkpoint made late, for the administrator to make again |
| `device.setCheckpointPolicy(policy)`, `device.checkpointPolicy()`, `device.listCheckpoints()`, `device.proposeListCheckpoint()` | what the device does about checkpoints by itself (`PROPOSE_AT_ROSTER_EVENTS`, `PROPOSE_AT_FRAME_BYTES`), and the checkpoints of its person's device list |
| `space.keepsNothingAtRest()` | whether this device keeps the space in memory only (a guest that keeps nothing at rest): cache none of it at rest either |
| `space.leave()`, `space.forget()` | leave the space and drop it from this device, or only drop it here |
| `space.streams()`, `space.isDurable()`, `space.flush()`, `space.waitDurable(withinMs)` | its streams, whether its changes are durable, and waiting until they are |
| `space.isWriteReady()`, `space.waitWriteReady(withinMs)`, `space.observeWriteReady()` | whether a device opened as restored may write there yet, and waiting until it may |
| `space.pauseSync()`, `space.resumeSync()`, `space.isSyncPaused()`, `device.pauseSync(spaces)`, `device.resumeSync(spaces)` | pause a space's sync with always-on peers, such as every space of a suspended library: no store and no fetch while paused, the space stays readable and writable, and resuming catches up |
| `space.createDocument()`, `space.document(id)` | Loro documents: `edit`, `text`, `read` |
| `space.createRecords()`, `space.records(id)` | Records tables: `write`, `rows`, `row`, and `lastChange(table, key)`, who changed a row last and when they say they did |
| `space.createBlobs()`, `space.blobs(id)` | blobs: `put`, `list`, `get`, `status` (`absent` when a read would fetch it now, `keysPending` while the key has not arrived), and `contentHash(id)`, the SHA-256 of a blob's content |
| `device.makePerson(unlockKey)`, `device.person()` | makes the device's person (first run, before `createSpace`), and its ID or `null` |
| `device.personalSpace()` | the person's personal space, or `null` for a device of no person |
| `device.joinPersonViaPeer(peerUrl, person, name, unlockKey, confirm)`, `device.admitDevice(text, name, confirm)` | a person's new device through a peer's exchange mailbox: it joins only `person`, and a device of another person that answers adds it to no list (`wrong_person`) |
| `device.joinViaPeer(peerUrl, name, confirm)`, `space.admit(code, level, name, confirm, { history? })` | admission by code through a peer's exchange mailbox: `joining.text`, `joining.joined()` |
| `space.inviteLink(level, lifetimeSeconds, { history? })`, `device.join(link, name, confirm)` | invite links |
| `space.exportSpaceFile(kind, options?)`, `space.appendSpaceFile(file)`, `device.importSpaceFile(file, kind, { key? })`, `Device.sniffSpaceFile(file)` | space files: one space as bytes, with a way in (its keys, or an invite), that another device reads, or joins by, with nobody online; an invite comes back as an `invitation` to show, then `accept()` or `decline()` |
| `space.grantPerson(person, level)`, `space.setLevel(member, level)`, `space.setSuggester(member, on)` | levels and suggesters |
| `space.admitMember(knownSpace, member, level)`, `space.admitMemberAdministrator(knownSpace, member, rank)` | admits a device that `knownSpace` grants directly, with no code, `via` none; its welcome goes to its mailbox at the peer. It rests on `knownSpace`'s roster alone, and a removal there does not reach this space |
| `space.createRestricted()`, `document.moveTo(restricted)` | restricted spaces, and documents moved into them |
| `space.erase()` | erases the whole space at its peers |
| `space.ephemeral()` | `send(bytes)`, `subscribe((from, bytes) => …)` returning its stop function |
| `space.attachLibrary(ticket)`, `device.setLibraryTicket(ticket)`, `{ libraryTicket }` at `Device.open` | library tickets |
| `device.giveDepositGrant(peerUrl, grant)`, `device.depositTokens(peerUrl)`, `device.trustDepositKeys(peerUrl)` | deposit tokens: a grant from the library's issuer, which the device draws with once and never keeps; `{held, paused, distrusted, grant}`; trusting a peer again after a `"depositPeerDistrusted"` event |
| `device.waitingDeposits()` | how many deposits in device mailboxes wait to be sent again |
| `await document.live()` | live editing with your own `LoroDoc`: `peerId`, `commit`, `suggest`, `exportSince`, `version`, `onChange(cb)` returning its stop function |
| `document.suggest(update)`, `suggestions()`, `accept(ids)`, `dismiss(ids)`; `records.suggest(write)` and the same three | suggestions |
| `blobs.get(id, { keep?, uncached?, local? })`, and the same options on `getStream`, `getRange` and `contentHash` | what becomes of a blob the read has to fetch: left in the cache (no option), kept, stored nowhere, or not fetched at all |
| `await blobs.openReader(id, { keep?, uncached?, local?, readAhead? })` | a `BlobReader` over a blob that need not be here: `read(offset, length, { signal? })`, `stream(offset?)`, `fetchSize()`, `size`, `verified`, `close()`; it fetches only the chunks it reads |
| `blobs.keep(id, onProgress?)`, `blobs.dropLocal(id)`, `blobs.local(id)` | download a blob and keep it, drop what this device stores of it, and where it stands here: `{ state: "kept" \| "cached" \| "absent", bytes, size }` |
| `device.blobCacheUsage()`, `{ blobCache, keepAllBlobs }` at `Device.open` | the cache's budget and what the cached and kept blobs take; the budget in bytes, and a device that keeps every blob |
| `MediaServer` from `@frasil/client/media` | a blob as the `src` of a `<video>` or `<audio>` element, fetched as the element asks for it |
| `blobs.putStream(name, readable, onProgress?)`, `blobs.getStream(id, onProgress?, options?)` | blobs as `ReadableStream`s: `getStream` opens a blob chunk by chunk; `putStream` reads its source as a stream but seals the blob whole in memory, so WebAssembly memory bounds what it can put |
| `blobs.putFile(name, file, onProgress?)` | a blob from a `Blob` or `File`, read twice through `slice` and sealed a chunk at a time, so a put holds a few chunks in WebAssembly memory whatever the file's size; a file that changes meanwhile rejects with `Changed` |
| `device.signRequest(subject, method, url, body)`; `verifySignedRequest(request, { audience, subject, deviceLists, nonces })` | signed application requests, verified by your server (in a Worker, from `@frasil/client/module`) |
| `device.advanced` | the direct grant, signed events, continuity, the outbox, making a person |
| `space.onChange(cb)`, `records.onChange(cb)`, `await blobs.onChange(cb)`, `await drive.onChange(cb)` | change feeds that name the streams, rows, blobs or entries that changed, and whether this device made the change (`origin`) |
| `space.observe(read)`, `records.observeRows(table)`, `records.observeRow(table, key)`, `drive.observe()`, `blobs.observeList()`, `blobs.observeStatus(id)`, `document.observe(read)`, `observe(read, changes)` | stores of observed reads: `get()` and `subscribe(listener)`, with a `status` of `"loading"`, `"ready"` or `"failed"` |
| `space.documentWhenAvailable(id, withinMs)`, `recordsWhenAvailable`, `blobsWhenAvailable`, `blobs.getWhenAvailable(id, withinMs)` | waits for what has not arrived yet |
| `blobs.status(id)`, `blobs.getRange(id, offset, length, options?)` | where a blob's bytes stand, and part of a blob |
| `records.rowsRange(table, { after, limit })`, `records.rowsWithPrefix(table, prefix)` | pages of rows, and rows by key prefix |
| `records.writeWithReceipt(write)`, `document.editWithReceipt(edit)`, `drive.batchWithReceipt(changes)` | a write with a `Receipt`: `unit`, `isDurable()`, `durable(withinMs)` |
| `records.table<T>(name, validator?)`, `manifestToTypeScript(manifest)` | typed rows, checked by a Standard Schema validator; row types from an index's manifest |
| `IndexClient` | queries and live queries of an index a worker keeps (`@frasil/client/index`); import it from `@frasil/client/client` to load no module |

Every ID is a string of lowercase hexadecimal, as the Rust crate shows them.
Every asynchronous call returns a promise; a stream made with `create…` exists
in its space from its first write.

```ts
// A document: each edit is one change.
await note.edit((doc) => {
  doc.text("body").insert(5, ", world"); // positions count UTF-16 units
  doc.map("meta").set("pinned", true);
});
await note.text("body"); // "Hello, world"

// Records: for each cell, the latest write wins.
const tasks = space.createRecords();
await tasks.write((tx) => tx.insert("tasks", "t1").set("tasks", "t1", "title", "Call Ana"));
await tasks.row("tasks", "t1"); // { title: "Call Ana" }

// Blobs: sealed as objects, which peers keep and members fetch.
const files = space.createBlobs();
const id = await files.put(bytes, { name: "photo.jpg" });
await files.get(id); // the bytes, or undefined until they have arrived
```

Each object owns memory in the WebAssembly module, which the garbage
collector frees; call `free()`, or declare it with `using`, to free it sooner.

## Reading, following and caching

Change feeds say what changed and where; observed reads turn any read into a
store that reads again after a change, takes changes that arrive together in
one read, and tells subscribers only when the result differs. Data that has
not arrived yet shows as `"loading"`, not as an error. The prebuilt stores
are shared: asking again for the same table, row, drive or blob returns the
same store while anyone subscribes, and for five seconds after.

```ts
const tasks = records.observeRows("tasks");
const stop = tasks.subscribe(() => {
  const { status, value } = tasks.get();
  if (status === "ready") render(value);
});
```

Each framework has an entry of its own, so the main entry imports none:

| Entry | Use |
|---|---|
| `@frasil/client/react` | `useObserved(store)`, through `useSyncExternalStore` |
| `@frasil/client/svelte` | `readable(store)`, the Svelte store contract; imports nothing from Svelte |
| `@frasil/client/solid` | `createObserved(store)`, an accessor under the current owner |

A device fetches a blob when it is read, and leaves it in a cache of sealed
bytes whose budget is 256 MiB unless `Device.open` is given another: `get`,
`getStream`, `getRange`, `contentHash` and `getWhenAvailable` fetch a blob
the device does not hold, and `get` resolves to `undefined` when nothing
connected could send it. The device evicts the blob read longest ago when
the budget is full, and a read fetches an evicted blob again. A read's
options say otherwise for one read: `{ keep: true }` keeps the blob,
`{ uncached: true }` stores nothing of it, and `{ local: true }` fetches
nothing ([Large blobs and media](#large-blobs-and-media)). A `BlobId` names immutable bytes, so it is a safe
permanent key for a cache of opened bytes or object URLs; `blobs.onChange`
says when a blob was removed, evicted or withdrawn. `getStream` opens a blob
chunk by chunk, and gives the chunks of one the device does not hold as they
arrive, the last once the whole blob passed its checks. `getRange` opens
only the chunks a range needs, and of a blob the device does not hold whole
fetches only those: each is checked by itself, and the checks that need the
whole blob have not run on it, so read with `get` what must not be acted on
unchecked. The guide
[Reading, following and caching synced data](../../docs/reading-and-caching.md)
covers each part, with a cache of object URLs.

## Large blobs and media

A blob is sealed in chunks of about a mebibyte, and a device can read any of
them without the others. Three things follow: a file larger than memory is
read in parts, a video plays without being downloaded, and the device
decides how much of what it reads stays on its disk.

### Reading without downloading

`blobs.openReader(id)` gives a `BlobReader`. It fetches the chunks that hold
what is read, from the peers and members connected, and nothing before it is
read or asked its size.

```ts
const reader = await blobs.openReader(id);
const size = await reader.fetchSize();
const tail = await reader.read(size - 1024, 1024); // fetches the last chunk only
for await (const piece of reader.stream(0)) {
  // 262,144 bytes at a time, read no faster than this loop takes them
}
await reader.close();
```

- `read(offset, length, { signal })` gives the bytes, fewer at the blob's
  end and none past it. Aborting the signal gives the read up, with what it
  had asked of the connections, whether or not the blob's header had come;
  the reader lives on. `fetchSize({ signal })` is given up the same way.
- `stream(offset)` is a `ReadableStream` to the blob's end. It reads one
  piece ahead of its consumer and no more, and cancelling it gives up the
  read it waits for and what that asked of the connections.
- `size` is `undefined` until a chunk has opened; `fetchSize()` fetches one.
- `verified` is `"chunks"` while each byte given comes from a chunk that
  opened under the blob's key at its own place, and `"whole"` once every
  check passed: after a read in order from the first byte to the last, or
  once the device holds the blob whole. Until then a member that holds the
  blob's key could have served other bytes; do not act on a range as if it
  were the file's.
- `close()` ends it. An open reader keeps the blob from being dropped, so
  close the ones you are done with. Calls of one reader run one after
  another; open a reader for each thing read at once.

Its options are a read's, and `readAhead`, the chunks fetched ahead of where
it reads (8 unless given). What it fetches goes into the cache; with `keep`
it is kept; with `uncached`, and for a blob larger than the whole cache, it
stays in the reader's memory, nine chunks at most at the default read-ahead.

### Playing a blob

A `<video>` or `<audio>` element reads from a URL, asking for the ranges it
needs. `MediaServer` mints a URL for a blob, and a service worker answers the
element's requests for it by asking the page, which reads each range through
a reader. The client stays in the page: it cannot run in a service worker.

```ts
import { MediaServer } from "@frasil/client/media";

const media = await MediaServer.connect({ serviceWorker: "/media-sw.js" });

const stop = media.serve(video, blobs, id, { type: "video/mp4" });
await video.play();
// when the element is done: revokes the URL, closes its readers, empties the element
stop();
```

`media.url(blobs, id, options)` gives the URL alone, and `media.revoke(url)`
ends it. The options are a reader's, and `type`, the media type the element
is told. Every request gets a reader of its own, closed when the request ends
or the element gives it up, as it does at each seek. A request left open with
nothing read from it for half a minute, as under a paused element, has its
reader closed too, and opened again when the element reads on;
`MediaServer.connect({ idle })` sets that time in milliseconds. A blob's size
is fetched once for a URL, by its first request.

**The media type.** `type` is told as given only when it is `audio/…`,
`video/…`, `image/…` other than SVG, `application/ogg` or
`application/octet-stream`; any other type is told as
`application/octet-stream`. Never pass a type that comes from untrusted
metadata, such as the `mediaType` another member wrote on a blob, without
checking it against the types your application plays. The URL is on your
page's own origin and its bytes are whatever a member of the space put
there: a type the browser renders or runs, with those bytes, would run in
your origin. The list and the headers below are there so that a mistake
does not come to that.

**Several servers.** A page may connect more than one `MediaServer`, and one
may live in the page while another lives in a worker. Each has its own port
at the service worker, and a URL begins with the name of the server that
minted it, so each answers its own URLs only.

**Hosting the service worker.** Copy `node_modules/@frasil/client/dist/media-sw.js`
(the export `@frasil/client/media-sw.js`) to where your site serves static
files. A service worker answers only pages within its scope, which is the
directory its script is served from: serve it from the site's root, or from
the directory of the pages that play media, or send the header
`Service-Worker-Allowed: /` with it and pass `scope: "/"`. Service workers
need a secure context: `https:`, or `http://localhost` while developing.

`connect` resolves once the worker that controls the page has taken the
server's port. It rejects with `timeout` after ten seconds
(`{ timeout }`, in milliseconds) when none has: no worker controls the page,
because the script is served from outside the page's directory, the page was
loaded with a forced reload, or the context is not secure; or the worker in
control is another one that does not call `handleMedia`.

`media-sw.js` calls `skipWaiting()` when it is installed and
`clients.claim()` when it is activated, so that it serves the page that
registered it without a reload. A scope has one service worker: registering
`media-sw.js` at a scope that has a worker of yours **replaces that worker at
once**, for every open page of the scope. If your origin has a service
worker, do not register this script; call the handler from yours.

**With a service worker of your own.** An origin's scope has one service
worker, so call the handler from yours instead of registering the script:

```ts
import { handleMedia } from "@frasil/client/media/worker";

self.addEventListener("fetch", (event) => {
  if (handleMedia(event)) return;
  // your own requests
});
self.addEventListener("message", (event) => {
  if (handleMedia(event)) return;
  // your own messages
});
```

Then call `MediaServer.connect()` with no `serviceWorker`. The handler takes
the requests under `/frasil-media/` on its own origin and the pages' messages
that bring their ports, and leaves every other event alone: call it first,
and return when it says `true`. It neither skips waiting nor claims clients;
your worker decides that. Both sides take another path:
`handleMedia(event, "/media/")` and `{ prefix: "/media/" }`. A prefix ends
with a slash, and is given one if it does not, so `/media` takes `/media/…`
and never `/mediafoo`.

**The client in a worker.** The service worker sends an element's requests
to the page the element is in. When the client runs in a dedicated worker,
the page passes each port on:

```ts
// the page
import { connectMediaPort } from "@frasil/client/media";
await connectMediaPort((port) => worker.postMessage({ mediaPort: port }, [port]));

// the worker
import { MediaServer } from "@frasil/client/media";
const media = new MediaServer();
self.addEventListener("message", ({ data }) => {
  if (data.mediaPort) media.attach(data.mediaPort);
});
```

**What a URL gives access to.** A URL is `/frasil-media/`, 8 hex digits that
name the server and 32 drawn at random, on the page's own origin. Nothing
on the network answers it. The service worker sends a request only to a port
of the page that made the request, and a page serves only the URLs it
minted: another tab of the origin gets `404` for it, and a page of another
origin is not controlled by the worker and reaches the network. The worker
holds no blob, key or URL: only each page's ports, which it asks the page
for again after the browser stopped and restarted it.

A URL is for a media element or a script, and never becomes a document: the
worker answers `404` to a navigation and to a request from a frame, an
`<object>` or an `<embed>`, whichever page makes it. Every answer carries
four headers:

| Header | Value | So that |
| --- | --- | --- |
| `X-Content-Type-Options` | `nosniff` | the browser does not take the bytes for another type than the one told |
| `Content-Security-Policy` | `sandbox; default-src 'none'` | an answer opened as a document all the same runs nothing and has no origin |
| `Cross-Origin-Resource-Policy` | `same-origin` | no other origin embeds it |
| `Cache-Control` | `no-store` | no cache keeps a blob's plaintext |

### The cache and the browser's quota

`Device.open(storage, unlockKey, { blobCache })` sets the cache's budget in
bytes as stored, a little more than the blobs' sizes; `0` caches nothing, and
`{ keepAllBlobs: true }` keeps every blob. `device.blobCacheUsage()` gives
`{ budget, cached, kept }`.

A browser gives an origin a quota, and refuses writes past it. Over
`Storage.indexedDb` the budget is therefore lowered, at each open, to half of
what `navigator.storage.estimate()` says the origin may still store: its
quota less its usage, plus what the cache holds already. An origin already
over its quota gets half of what its cache holds beyond the excess, and a
budget of 0, with nothing cached, when the excess is larger than the cache.
`blobCacheUsage()` shows the budget in force. Where the browser gives no
estimate, or one with no quota, the budget stands as given.

The estimate is not a promise, and kept blobs, documents and the rest of the
origin's storage share the quota. When the browser refuses a chunk a read
fetched (`QuotaExceededError`), the device drops cached blobs, the one read
longest ago first, until as many bytes went as the chunk takes, and writes it
again, once. If the browser still refuses, a blob with an open reader is read
on through memory, as an `uncached` read does, and nothing more of that blob
is stored while a reader of it is open: the read does not fail. That covers
`openReader`, a media element, and `blobs.get(id)`, which reads a blob that
is not whole here through a reader of its own and so gives the bytes and
leaves the blob absent.

What still fails under a full store:

- `blobs.keep(id)`: a kept blob is never held in memory in place of the
  store, so the download makes no progress and rejects, and the blob stays
  marked as kept, to be fetched when there is room.
- `blobs.put(data)`, and every other write: documents, rows, entries. They
  reject with a `store` error whose `cause` is the browser's exception, and
  the cache does not give way for them.
- Kept blobs are never evicted to make room, nor is a blob this device put
  that no peer holds yet.

Ask the browser not to clear the origin's storage under pressure with
`navigator.storage.persist()`.

## Entries

| Import | What it is |
|---|---|
| `@frasil/client` | the client; the module loads from a file |
| `@frasil/client/embedded` | the same, with the module inlined as base64, for an application that cannot host a file |
| `@frasil/client/index` | the client with the index, for a dedicated worker; loads its module from a file |
| `@frasil/client/index/embedded` | the same, inlined |
| `@frasil/client/client` | `IndexClient` alone, for a page: loads no module |
| `@frasil/client/module` | the bare module, which `load` is given compiled (below) |
| `@frasil/client/react`, `/svelte`, `/solid` | the framework bindings; they load no module of their own |
| `@frasil/client/media` | `MediaServer`, for a page or a worker: plays blobs in media elements; loads no module |
| `@frasil/client/media/worker` | `handleMedia`, for a service worker of your own; imports nothing |
| `@frasil/client/media-sw.js` | the media service worker as a script to host as it is |
| `@frasil/client/frasil_wasm.wasm` | the default entry's module file, for a host that serves it itself |

Use one entry for all the Frasil objects of a page or worker: two entries are
two copies of the module and their devices do not mix. The framework bindings
adapt the default entry's stores; with `embedded`, import the stores from it
and wrap them yourself.

## The index

The entry `@frasil/client/index` is the whole client from a build of the
module that also holds the index: a typed SQLite cache over the device's
spaces, encrypted at rest in the origin-private file system. Open the device
and the index in a dedicated worker; a page queries it through `IndexClient`,
which `@frasil/client/client` gives without loading any WebAssembly.

```ts
// worker.ts
import { Device, Index, serveIndex, Storage } from "@frasil/client/index";
const device = await Device.open(Storage.indexedDb("my-app"), unlockKey);
const index = await Index.open(device, "my-app", manifest);
void index.follow();
serveIndex(index, self);

// page.ts
import { IndexClient } from "@frasil/client/client";
const open = new IndexClient(worker).watch("SELECT title FROM task WHERE done = 0");
```

The manifest describes the tables, as [the index guide](../../docs/index.md)
says; `manifestToTypeScript(manifest)` writes their row types.

## Admitting a device

Nearby pairing needs a connection a browser does not have. A browser joins
through a peer instead: by code, with `device.joinViaPeer` on the newcomer and
`space.admit` on an administrator, where both persons compare a six-digit code
(`confirm` returns `true`, or a promise of `true`, when they match: return a
promise to show the code and wait for the person's click); or by an invite
link from `space.inviteLink`, which `device.join` claims.

A browser can also admit another device by a **direct grant**, under
`device.advanced`:

1. the newcomer hands over its `device.id` and `device.advanced.deviceKeys()`,
   its three public keys, which hash to its ID;
2. a device that administers the space calls
   `device.advanced.grantDevice(space, id, keys, level, history?)`, and hands
   over the space's ID and `device.advanced.signedEvents(space)`, which carry
   the newcomer's keys;
3. the newcomer calls `device.advanced.follow(spaceId)` and
   `device.advanced.ingest(spaceId, events)`, then connects to the peer that
   keeps the space, which syncs it from there.

How the newcomer's ID crosses between the devices is the application's to
secure: it is what the grant trusts. Its keys may come from anywhere, since a
grant takes only keys that hash to the ID it names, and whoever holds the keys
of the ID it grants can read the space. Show and compare devices by their ID.

## Storage

`Storage.indexedDb(name)` keeps the device in an IndexedDB database of its
own: its records, and beside them its sealed keys, which open only with the
unlock key. `Storage.memory()` keeps nothing past the page. `Storage.of(store)`
takes a `Store` of your own:

- `get`, `scan` by prefix in bytewise address order, and `commit`, which
  applies its deletes then its puts only if every expectation holds,
  atomically;
- `loadSealedKeys` and `saveSealedKeys`, for the device's sealed keys.

A store decides nothing, and nothing in it opens without the unlock key.
`IndexedDbStore` makes each commit one `readwrite` transaction, which keeps two
tabs of one device from both advancing it; `MemoryStore` is for tests. A
store with no room for a commit rejects with an error named
`QuotaExceededError`, or one whose `cause` is, as `IndexedDbStore` does past
the browser's quota: the device then makes room in its blob cache
([The cache and the browser's quota](#the-cache-and-the-browsers-quota)).

A browser has no place that no backup restores, so the device runs in restore
mode `never-restored` by default; pass `{ restoreMode: "none" }` to make every
start count as a restore.

A device that opens as restored, as every start is under `none`, writes in a
space only once it has synced that space: until then each write there rejects
with `sync_before_writing`. `space.isWriteReady()` says whether it may write
now, `space.waitWriteReady(withinMs)` resolves once it may (at once when it
already may), `space.observeWriteReady()` observes it, and the device's
events carry `{ kind: "writeReady", space }` as each space becomes writable.

## Errors

Every operation throws or rejects with a `FrasilError`:

- `code`: the specification's class in snake case (`malformed`,
  `not_a_member`, …) or the client's own failure (`store`, `not_allowed`,
  `unknown_stream`, `connection`, …); see `KnownErrorCode`;
- `class`: for a failed check of the specification, the class as the
  specification names it (`Malformed`);
- `whatToDo`: what to do about it, in a sentence you can show or log.

After an internal panic every call fails with `panicked`, and the page must
reload. Bytes from another writer that would make the document engine
panic are refused before it reads them where the package can tell
(`docs/webassembly.md`, "Documents from other writers").

## Content Security Policy

The package loads, opens a device and syncs with a peer at the page's own
origin under:

```text
default-src 'none'; script-src 'nonce-…' 'wasm-unsafe-eval'; connect-src 'self'
```

Without `'wasm-unsafe-eval'` (or `'unsafe-eval'`) the module does not load.
Without `connect-src`, the default entry cannot fetch its module file, and
the embedded entry loads but cannot reach a peer. The file's address must be
allowed by `connect-src` (the page's own origin above). It needs no
`'unsafe-inline'`, and loads under `require-trusted-types-for 'script'`.
`test/binding/csp.spec.ts` checks each of these in Chromium and WebKit. A peer
at another origin must be named in `connect-src`, and its object routes, which
take an `Authorization` header, must also answer the browser's CORS preflight.

## A host that imports `.wasm` as a module

Some hosts refuse to compile WebAssembly from bytes at run time. The entry
`@frasil/client/module` ships the bare module and takes it compiled:

```ts
import wasm from "@frasil/client/module/frasil_wasm.wasm";
import { load } from "@frasil/client/module";

const frasil = await load(wasm);
```

A Cloudflare Worker verifies requests that devices signed with
`device.signRequest` the same way: `await load(wasm)`, then
`verifySignedRequest(request, { audience, subject, deviceLists, nonces })` from
`@frasil/client/module` resolves to `{ person, device, listNeeded }`.
`audience` is the Worker's own origin, such as `https://api.example.org`, from
its configuration: it is never read from `request.url`, which the Worker builds
from the `Host` header, and a request signed for another origin is refused. It
loads the subject's and the person's records from `deviceLists` before
verifying, checks the nonce in `nonces` (atomic across workers), and stores
what changed after.

## Size

`scripts/size.mjs --check` (`pnpm size`) fails when a file is over its budget.
Measured at 0.1.0, in bytes:

| | raw | gzip | brotli | budget (raw, gzip) |
|---|---|---|---|---|
| the WebAssembly module | 11,440,228 | 3,451,228 | 2,271,929 | 11,955,637, 3,603,281 |
| the module as shipped, as a file (`dist/wasm/…_bg.wasm`) | the module's | the module's | the module's | — |
| the module inlined, base64 (`@frasil/client/embedded`) | 15,253,726 | 4,886,905 | 3,056,056 | — |
| the index entry's module, with SQLite (`@frasil/client/index`) | 12,965,333 | 4,137,241 | 2,782,040 | — |
| wasm-bindgen's glue | 191,606 | 28,300 | 22,938 | 200,624, 29,431 |
| the TypeScript layer, without comments | 92,619 | 19,406 | 16,582 | 101,881, 21,347 |
| the media service worker's script (`dist/media-sw.js`) | 5,366 | — | — | — |

The module's budget covers it with ext-invite-links, ext-restricted-spaces,
ephemeral, ext-app-requests, ext-libraries, ext-drive, space-files and
ext-deposit-tokens on.

The TypeScript layer ships without comments; its declarations keep them.

By the crate each function's name starts with, the module's code is mostly
`alloc` and `core` (generic code compiled for the client's types), Loro
(`loro_internal` and `generic_btree`, about a fifth), then `frasil`.

## Tests

```sh
node scripts/build.mjs          # the module, the glue and dist/
pnpm typecheck
pnpm test                       # the stores, a device, its reads and the framework bindings, in Node.js
pnpm test:binding               # scenarios and the policy check, Chromium and WebKit
pnpm size
```

`test:binding` builds `frasil-relay` and runs it on loopback. Each scenario's
devices are pages of their own browser contexts: a space kept at the peer, a
second browser granted into it directly, documents written and synced both
ways, devices that reload from IndexedDB and catch up, a blob that another
browser fetches over the peer's object routes, a person who returns on a
new browser from the recovery sheet, and the index in a dedicated worker,
queried from the page. `reads.spec.ts` reads blobs the device does not hold:
a read's options, a reader's ranges and `verified`, a cancelled stream, the
cache within its budget, the budget under a storage estimate, and a store
that refuses writes for quota. `media.spec.ts` asks the media service worker
for ranges of a minted URL and compares the bytes, and plays and seeks a
`<video>` element through it. Cargo builds into
`CARGO_TARGET_DIR` when it is set.

## Building from source

Build the package from a checkout of the repository, with Rust's
`wasm32-unknown-unknown` target and pnpm:

```sh
pnpm install --frozen-lockfile
pnpm --dir packages/frasil build
```

and depend on `packages/frasil` by path, or on the tarball `pnpm pack` makes
there.

## Runtimes

Browsers with WebAssembly, `crypto.getRandomValues`, IndexedDB and top-level
`await`. Tested in Chromium 153 and WebKit 26.6. The module and the memory
store also run in Node.js 20 or later.

## License

MIT.

`await space.pendingAuthoredChanges()` returns a `bigint`: locally authored
events awaiting the same acknowledgement as `flush()`, including membership,
key and storage events. An always-on peer's acknowledgement counts, or a
member's when there is no always-on peer. Device events include
`{ kind: "pendingChanges", space, count }`; rapid changes may coalesce and
the first notice establishes the observed count.

For a device already authenticated as a direct member of `knownSpace`
(use one ordinary code admission first if it has no direct grant yet):

```ts
const sent = await owner.admitSpacesViaPeer(peerUrl, knownSpace, deviceId, spaces, onProgress);
const delivered = sent.filter((report) => !report.error).map((report) => report.space);
const received = await recipient.receiveSpacesViaPeer(peerUrl, ownerId, delivered, onProgress);
```

This grants new members `Administer` with history, promotes existing members
without changing their history boundary, checks authority per space, and uses
ordinary sealed welcomes in the device mailbox instead of new code
exchanges. Select `deviceId` and `ownerId` by their previously authenticated
identities. Each report is `{ space, granted, error? }`: delivery can fail
after an atomic grant committed. Retry failed or unfinished spaces after
reconnecting, even when `granted` is true. The receiver collects from the
start on retry, checks the roster and its own keys, and accepts only the
expected spaces and approver. Missing welcomes time out after 60 seconds;
a delivered space has a separate 60-second fetch deadline. After mailbox
expiry, repeat the sender's grant. Progress callbacks observe each result;
a callback exception does not cancel the batch.

Retry a retained erasure immediately with `device.retryErasure(id)`. A late answer reports
`ErasureCheckpoint` (`erasureCheckpoint`), including the checkpoint and the
slot standing the residue checked without space keys. Standing 0, or standing
1 with an empty cut entry, sends signed welcome requests to the saved administrators and reports
`ErasureAwaitingWelcome` (`erasureAwaitingWelcome`). The residue stays while
waiting. Standing 2 reports `ErasureCannotErase` (`erasureCannotErase`): the
peer still holds the space and says the device can no longer erase it.
Administrators answer only verified requests from current members, with a
welcome and snapshot; a request never changes membership. After fetching,
the device judges the checkpoint and signs its erasure again or reports
`ErasureVoid` (`erasureVoid`) or `SlotHeld` (`slotHeld`). The application may give the space up at any time.

When another pseudonym holds this device's administrator slot, `SlotHeld`
(`slotHeld` in JavaScript) names the space and holding root or enrolment,
identifies the holder as another installation of this device, another device,
or unknown, and says whether this device's erasure waits on it. A residue
has no keys and reports unknown. It keeps asking peers, without requesting
a welcome for a slot the cut names as held. Use the other installation to
administer, or ask another administrator to disown the slot and grant a new
one. An occupied slot cannot be enrolled again.

The `peerNeedsVersion` event carries `space` and `peer` when a peer
needs a later version to follow that space’s checkpoints.
