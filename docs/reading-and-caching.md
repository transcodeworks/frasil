# Reading, following and caching synced data

A device's replica is the truth for every space it holds: a read never waits
for a server, and changes from other members arrive whenever a peer or a
member connection brings them. This guide covers what an application uses to
show that data and keep what it shows current: change feeds that say what
changed, observed reads that frameworks subscribe to, waits for data that has
not arrived yet, and blob reads that suit a cache of the application's own.

Each part exists in the Rust crate `frasil` and in the npm package
`@frasil/client`, with the same names in each language's style
(`observe_rows` and `observeRows`).

## Change feeds

The device-wide `Events` name a space and the streams that changed. The feeds
below narrow that to what an application caches. Each starts when it is asked
for, gives every change after that, and says where each change was made:
`Origin::Local` for this device's own writes, `Origin::Remote` for changes
that arrived from another member, a peer, or the person's other devices. A
Rust feed's `next()` gives `Ok(None)` once the device is gone, and fails with
`UnknownSpace` once the device no longer holds the space; an npm feed's
`onError` hears `unknown_space` then.

| Feed | Rust | npm | What each change names |
| --- | --- | --- | --- |
| One space | `space.changes()` | `space.onChange(cb)` | the streams that changed, whether the members may have changed, whether it holds space events (keys or the space's own stream), the origin |
| A Records stream | `records.changes()` | `records.onChange(cb)` | the table and the keys of the rows a write touched, the origin; or *all* |
| A blob stream | `blobs.changes().await` | `await blobs.onChange(cb)` | a blob added or removed (with the origin), arrived, or withdrawn |
| A drive | `drive.changes().await` | `await drive.onChange(cb)` | the entries and root containers that changed, the origin |

A Records change is *all* (`RecordChange::All`, `{ kind: "all" }`) when any
row may have changed: a snapshot replaced the stream's state, the space's
members changed so that a writer's changes may count or no longer count, a
key arrived that lets waiting changes read, or the feed fell far behind the
device. Read the tables again then.

A key, such as a rotation or a delivery to a new device, can arrive after
the changes it opens: the units wait, and the key makes them readable. Such
an event belongs to no stream, so the space's feed flags it as a space event
(`space_events`, `spaceEvents`), a Records feed gives *all*, and observed
reads and drive feeds read again.

A blob *arrives* when its bytes become whole on this device, so that
`get` reads them; a held blob is *withdrawn* when the file it was held in
changed or is gone, and stays fetchable from peers and members. A drive's
feed reads the drive again only after a change of its own document or of who
may write it.

```rust
let mut changes = records.changes();
while let Some(change) = changes.next().await? {
    match change {
        RecordChange::Rows { table, keys, origin } => refresh(&table, &keys, origin),
        _ => refresh_all(),
    }
}
```

## Observed reads

An observed read is a read that runs again when what it reads changes, and
tells its observers only when the result differs. It is the one primitive
behind every store an interface shows:

- `space.observe(read)` observes any read of a space; it reads again after
  each change of the space.
- `records.observe_rows(table)`, `records.observe_row(table, key)`,
  `drive.observe()`, `blobs.observe_list()`, `blobs.observe_status(id)` and
  `document.observe(read)` read again only after a change of their own
  stream (or table, or row, in npm).

Every observation carries a status beside its value:

| Status | Meaning |
| --- | --- |
| loading | the first read has not finished, or what it reads has not arrived at this device: a stream it holds no change of, or bytes it does not hold whole |
| ready | it read what the device holds now |
| failed | its last read failed otherwise, or its change feed ended with an error; the value is the last one read |

A read that fails because something has not arrived (`UnknownStream`, or
`Missing` for blob bytes) shows as loading, not as an error, and reads again
as data arrives.

Changes that arrive while a read runs are taken together: a burst of changes
costs one read more, not one per change. Results are compared structurally
(`PartialEq` in Rust; arrays, plain objects, `Map`s, `Set`s and byte arrays
by content in npm), and an equal result is not reported, so a framework does
not render again for a change that did not change what it shows.

The prebuilt stores are shared: every observer of the same table, row,
drive, blob list or blob status shares one reader. In Rust they are shared
while any clone lives. In npm, asking again returns the same store object
while anyone subscribes to it and for a grace period of five seconds after
the last subscriber leaves, so that a component that unmounts and mounts
again finds the store current.

### Rust

`Observed<T>` has `get()`, which returns the latest `Observation` (status,
value as an `Arc<T>`, error), `changed().await`, which waits for the next
different observation, and `ready().await`, which waits for a ready value.
One background task per reader follows the device; it ends when every clone
is dropped.

```rust
let mut tasks = records.observe_rows("tasks");
let rows = tasks.ready().await;
while let Some(now) = tasks.changed().await {
    if let Some(rows) = now.value {
        show(&rows);
    }
}
```

### npm

A store is `{ get(), subscribe(listener) }`: `get()` returns the latest
snapshot, the same object until something in it changes, and `subscribe`
calls `listener` each time it changes and returns the function that stops
it. The first subscriber starts the reads. `observe(read, changes)` builds a
store from any read and any change source.

The bindings adapt a store to a framework, each from an entry of its own so
that the main entry imports no framework:

```tsx
// React, through useSyncExternalStore.
import { useObserved } from "@frasil/client/react";
const tasks = useObserved(records.observeRows("tasks"));
if (tasks.status === "ready") render(tasks.value);
```

```ts
// Svelte: the store contract, which `$store` reads. Imports nothing from Svelte.
import { readable } from "@frasil/client/svelte";
const tasks = readable(records.observeRows("tasks"));
```

```ts
// Solid: an accessor that tracks the store under the current owner.
import { createObserved } from "@frasil/client/solid";
const tasks = createObserved(records.observeRows("tasks"));
```

The prebuilt stores may be asked for during render, since the same request
returns the same store: a table's rows or row (by stream, table, key and
validator), a drive, a blob list or status, and a document's read, which is
keyed on the `read` function itself, so define it outside the component. A
store from `observe` or `space.observe` is new on each call: keep it in
`useMemo` or its equivalent. In npm, every observer of a Records stream
shares one feed of it, however many rows they watch.

## Waiting for data

A newcomer to a space, or a device that partially syncs, may know a stream's
ID before it holds the stream. Rather than looping on events:

| Rust | npm |
| --- | --- |
| `space.document_when_available(id, within)` | `space.documentWhenAvailable(id, withinMs)` |
| `space.records_when_available(id, within)` | `space.recordsWhenAvailable(id, withinMs)` |
| `space.blobs_when_available(id, within)` | `space.blobsWhenAvailable(id, withinMs)` |
| `blobs.get_when_available(id, within)` | `blobs.getWhenAvailable(id, withinMs)` |

Each returns at once when the data is here, else as soon as it arrives, and
fails with `Timeout` (`timeout`) at its deadline. An observed read of the
same data shows loading meanwhile.

`blobs.status(id)` says where a blob's bytes stand: readable, fetching (with
the bytes done of the total), missing (nothing is sending them now: no peer
or member is connected, or the device fetches on demand and was not asked),
keys pending (the key the blob, or the change that adds it, is sealed under
has not reached this device yet; connecting changes nothing until a member
or a peer delivers it), or withdrawn.

A blob this device put is readable here at once; whether it has left the
device is a separate question. In Rust, `blobs.is_durable(id)` is `false`
while the change that put it waits for an always-on peer's
acknowledgement, which comes only once the peer holds the blob's bytes,
and `blobs.pending()` lists the stream's blobs still waiting. Both read the
device's store, so after a reopen they say what the device uploads once it
connects; an upload a peer holds part of goes on from there. Ask again on
`Event::PendingChanges`. In a space with no always-on peer, a member's
acknowledgement counts instead, and the member fetches the bytes after.

`device.arrivals()` gives each space and each stream the device holds for
the first time, from the moment it is asked for: `Arrival::Space` once a
space's first events arrive, then `Arrival::Stream` for each of its streams,
and later each new stream once. It serves a wait for a whole space, such as
one a grant is about to bring, or for a stream whose ID is not known in
advance.

`space.observe_durable()` is an observed read of whether the space has
nothing unsent: `false` while any change this device made waits for an
acknowledgement, `true` once every one is acknowledged. It changes as the
device writes and as acknowledgements arrive. In the npm package,
`device.events()` gives each space's count of changes awaiting
acknowledgement as `pendingChanges`.

## Blobs and an application's cache

Frasil keeps blobs sealed: a read opens them each time. An application that
shows the same file often, such as a thumbnail, keeps the opened bytes, or an
object URL of them, in a cache of its own. Frasil gives it what such a cache
needs.

- **A `BlobId` names immutable bytes.** A blob is never changed in place: a
  new version of a file is a new blob with a new ID. A `BlobId` is therefore
  a safe, permanent cache key, which needs no expiry. A drive entry's file
  names its current version by its `blob`, so the entry's `blob` is the key
  of that version: when the entry changes to a new version, its `blob`
  changes too.
- **The blob feed says when a key is done with.** `Removed` means no entry
  of the stream uses the blob any more; `Withdrawn` means this device no
  longer holds the bytes. `Arrived` means a blob that was missing can now be
  read.
- **A content hash keys media by content.** `blobs.content_hash(id)`
  (`contentHash`) is the SHA-256 of a blob's plaintext, computed on this
  device chunk by chunk and kept while it is open; equal content has an
  equal hash across blobs and spaces. It fetches nothing, and is `None`
  while the device cannot read the blob whole. The protocol carries no such
  hash, so no peer sees it.
- **Streaming and ranges keep memory flat.** `get_stream` (`getStream`)
  opens a blob chunk by chunk, about a mebibyte at a time, and writes each
  chunk as it opens, so a large file never sits whole in memory.
  `get_range(id, offset, len)` (`getRange`) returns part of a blob, opening
  only the chunks that hold it. `content_hash` reads the same way. A read
  holds a few chunks at a time, plus the range it returns, whether the
  device keeps the blob sealed, in memory, or as a file it holds. From
  Swift and Kotlin, `getToFile(id, path, listener)` writes a blob to a file
  the same way.

Every check of the object format still runs. The stored bytes are checked
against the blob's locator before any plaintext goes out; each chunk is
authenticated before it is used; and a read of the whole blob checks the
plaintext's ID before it gives the last chunk. A stream that fails part way
has written a prefix of the blob: discard it. The first range read of a blob
since the device opened reads the whole blob once, a few chunks at a time
and keeping only the range, so that every check runs on it; later range
reads open only their chunks. A range of a blob the application holds as a
file is read through the whole file each time, so that its ID is checked;
to seek in such a file, read the file itself (`materialise`).

A cache in the page, for example, keeps object URLs by `BlobId`, at most a
few hundred, and revokes the least recently used:

```ts
class BlobUrls {
  #urls = new Map<string, string>(); // BlobId → object URL, oldest first

  constructor(private blobs: Blobs, private limit = 200) {
    void blobs.onChange((change) => {
      if (change.kind === "removed" || change.kind === "withdrawn") this.drop(change.id);
    });
  }

  async url(id: BlobId, type: string): Promise<string | undefined> {
    const kept = this.#urls.get(id);
    if (kept !== undefined) {
      this.#urls.delete(id); // most recently used goes last
      this.#urls.set(id, kept);
      return kept;
    }
    const bytes = await this.blobs.get(id);
    if (bytes === undefined) return undefined; // show blobs.observeStatus(id) meanwhile
    const url = URL.createObjectURL(new Blob([bytes], { type }));
    this.#urls.set(id, url);
    for (const [old] of this.#urls) {
      if (this.#urls.size <= this.limit) break;
      this.drop(old);
    }
    return url;
  }

  drop(id: BlobId): void {
    const url = this.#urls.get(id);
    if (url !== undefined) URL.revokeObjectURL(url);
    this.#urls.delete(id);
  }
}
```

A cache on disk works the same way, keyed by `BlobId`, with the decrypted
bytes under the application's own encryption at rest
(`device.derive_key(purpose)` gives a key for it).

## Spaces that keep nothing at rest

A guest whose admitting device chose `Guest::nothing_at_rest` keeps the
space in memory only: Frasil writes none of its keys, events, objects or snapshot to the
store, and forgets the space when the session ends, when the device is
removed or leaves, and when the application closes the device. Check
`space.keeps_nothing_at_rest()` (`space.keepsNothingAtRest()` in
TypeScript) before an application caches anything of a space, and keep
such a space's content in memory only too: no cache on disk, no file, no
row in a database of its own. [The index](index.md) does the same: it
projects no row of such a space into its file.

## Pages of rows

`records.rows(table)` reads a whole table. For long tables:

- `records.rows_range(table, after, limit)` (`rowsRange(table, { after,
  limit })`) gives at most `limit` rows in key order, from the first key
  after `after`. Pass the last key read as `after` for the next page.
- `records.rows_with_prefix(table, prefix)` (`rowsWithPrefix`) gives the
  rows whose keys start with `prefix`, such as every row of one parent when
  keys are `parent/child`.

## Typed rows in TypeScript

`records.table<T>(name, parse?)` reads one table's rows as `T`: checked by a
Standard Schema validator (Zod, Valibot, ArkType and others), or by a
function, or taken as they are. Its `rows`, `row`, `observeRows` and
`observeRow` mirror those of `Records`. A row that does not validate fails
the read with `invalid_input`.

`manifestToTypeScript(manifest)` writes TypeScript declarations for an
index's tables from its manifest (see [the index](index.md)): for each table
the interface of its Records row and the interface of a query's row of it.

## Receipts for single writes

Durability is tracked per space: `space.flush()` and `space.wait_durable()`
wait for every pending change. To follow one write, write it with a receipt:

| Rust | npm |
| --- | --- |
| `records.write_with_receipt(write)` | `records.writeWithReceipt(write)` |
| `document.edit_with_receipt(edit)` | `document.editWithReceipt(edit)` |
| `drive.batch_with_receipt(changes)` | `drive.batchWithReceipt(changes)` |

A `Receipt` names the change (`unit()`), says whether a peer acknowledged it
(`is_durable()`), and waits for that with a deadline (`durable(within)`),
whatever else the space has pending. A batch that makes no operation has no
receipt.
