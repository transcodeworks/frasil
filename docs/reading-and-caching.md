# Reading, following and caching synced data

A device's replica is the truth for every space it holds: a read of a
document or a table never waits for a server, and changes from other members
arrive whenever a peer or a member connection brings them. Blobs are the one
thing a device does not hold whole by default: it knows every blob of the
streams it holds, fetches one when it is read, and keeps what it fetched in
a cache with a budget. This guide covers what an application uses to show
that data and keep what it shows current: change feeds that say what
changed, observed reads that frameworks subscribe to, waits for data that has
not arrived yet, what a device keeps of its blobs, and blob reads that suit a
cache of the application's own.

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
| A blob stream | `blobs.changes().await` | `await blobs.onChange(cb)` | a blob added or removed (with the origin), arrived, evicted, or withdrawn |
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

A blob *arrives* when its bytes become whole on this device, so that a read
gives them with no connection; it is *evicted* when the device drops them
again, to keep its cache within its budget or because the application asked,
and a read then fetches them once more; a held blob is *withdrawn* when the
file it was held in changed or is gone, and stays fetchable from peers and
members. The feed reports what differs from what it last saw, so a blob that
arrived and was evicted between two looks is reported as neither. A drive's
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
same data shows loading meanwhile. `get_when_available` is a `get` with a
deadline: it fetches a blob the device does not hold, into its cache, and
waits its whole time for one that nothing connected can send yet. While no
peer or member is connected, and while one is that does not hold the blob,
so that a fetch gets nowhere, it tries again when the space changes and
every second.

`blobs.status(id)` says where a blob's bytes stand: readable (the device
holds them whole, kept or cached), fetching (with the bytes done of the
total), absent (the device does not hold them and a peer or a member is
connected, so a read fetches them now), missing (it does not hold them and
nothing is connected that could send them), keys pending (the key the blob,
or the change that adds it, is sealed under has not reached this device yet;
connecting changes nothing until a member or a peer delivers it), or
withdrawn. The npm package and the Swift and Kotlin bindings report absent
as missing.

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

## What a device keeps of its blobs

A blob on a device is in one of three states, which `blobs.local(id)` tells
with the bytes the device stores of it:

| State | Meaning |
| --- | --- |
| kept | Stored until the application drops it. Never evicted. |
| cached | Stored within the cache's budget. Evicted, the one read longest ago first, when the budget is full. |
| absent | Nothing of it is stored. A read fetches it. |

A device opens with a budget for its cache, 256 MiB unless
`Options::blob_cache(bytes)` says otherwise. It counts the bytes as the
device stores them, a blob's sealed chunks and its header, a little more
than its size, across all the device's spaces, and it is given at each open:
it is not stored. `device.blob_cache_usage()` gives the budget and the bytes
of the cached and of the kept blobs.

**Reading.** Every read takes a `Read`, which says what becomes of a blob
the device has to fetch for it. A blob the device holds, kept or cached, is
read from the device whatever the read says.

```rust
use frasil::Read;

let bytes = blobs.get(id, &Read::new()).await?;            // fetch into the cache
let bytes = blobs.get(id, &Read::new().keep()).await?;     // fetch and keep
let bytes = blobs.get(id, &Read::new().uncached()).await?; // fetch, store nothing after
let bytes = blobs.get(id, &Read::new().local()).await?;    // fetch nothing
```

`get`, `get_stream`, `get_range` and `content_hash` take it alike. `get`
returns `None` when the blob is not here and is not fetched: the read is
`local`, or neither a peer nor a member of the space is connected, or what
is connected does not serve the blob for now. A read that must not wait on
the network is `local`. A read fails with `Timeout` when nothing arrives for
half a minute, and at once, with `ObjectMismatch` or `Malformed`, when every
connection of the space gave the blob up because the bytes it was sent
failed their checks. A peer or a member that connects while a read waits
serves it.

A read fetches the blob whole before it gives any of it, into the device's
store, so every check of the object format runs as for any stored blob. An
`uncached` read drops the blob again when it ends, and so does any read
under a budget of zero or of a blob larger than the whole budget. While such
a read runs, the device stores that blob beside its cache: the blob counts
against no budget and evicts nothing, so what a device stores beyond its
budget is only what running reads hold. `blob_cache_usage()` counts it with
the cached bytes meanwhile. When two reads of one blob run at once and one
of them is not `uncached`, the blob is left in the cache. A read that
fetches nothing, because nothing is connected or the fetch gets nowhere,
writes nothing to the store. A read that is cancelled, its future dropped
part way, ends as any read does: what it fetched to store nothing is
dropped at once.

**Keeping and dropping.** `blobs.keep(id, on_progress)` fetches a blob into
the store and keeps it, without reading it: a download in the background,
for a file the person wants with no connection. A blob that cannot be
fetched now stays marked, and the device fetches it by itself once a peer or
a member that holds it is connected. `blobs.drop_local(id)` drops what the
device stores of a blob, kept or cached, and the blob is absent. Nothing
changes for anyone else, and the stream still lists it. A reference to a
file of another space has its bytes where that space stores them: `keep`
through the reference keeps them there, and `drop_local` through it drops
them there, so the file's own blob stands as the reference does.

**What is never evicted.** Kept blobs; a blob this device put, until an
always-on peer holds its bytes; what Frasil stores for itself, such as
snapshots; and a blob that a read or a fetch is using. A blob this device
put is kept, and `blobs.local(id)` says so, until a peer of the space has
answered that it holds the bytes and has acknowledged the change that put
the blob: the blob is cached from then on, unless the application asked to
keep it. Nothing else releases it: not another member's acknowledgement,
not a reopen, not a paused space. In a space with no always-on peer no
other party is known to hold the bytes, so a blob put there is kept until
the application drops it. `drop_local` refuses, with `NotAllowed`, a blob in
use and, in a space with an always-on peer, a blob this device put that no
peer holds yet.

**An evicted blob stays away.** The device does not fetch it again by
itself: the next read does. An older version of a file that no peer keeps
any more cannot be fetched again, so keep the versions that must not be
lost.

**A full copy.** `Options::keep_all_blobs()` makes a device fetch every blob
its spaces name, because a stream names it, and keep each: for a device that
must read everything with no connection. Nothing is evicted then, and
`drop_local` is refused, since the device would fetch the blob again at
once.

**A store from an earlier version** holds blobs with no state recorded. They
are kept: opening it with a budget evicts nothing it held.

**Spaces whose blobs the application holds as files** (`held`) have no
cache: a file is the application's to keep or delete. A blob a read fetches
there becomes a file, as `materialise` with an empty hint makes one; `keep`
is that `materialise`, and `drop_local` is `release`. An `uncached` read
that would have to fetch is refused there with `Unsupported`, since it would
write a file.

The npm package and the Swift and Kotlin bindings read as `Read::new()`
does, into the cache, under the default budget.

## Blobs and an application's cache

Frasil keeps blobs sealed: a read opens them each time. An application that
shows the same file often, such as a thumbnail, keeps the opened bytes, or an
object URL of them, in a cache of its own, beside the device's cache of
sealed bytes. Frasil gives it what such a cache needs.

- **A `BlobId` names immutable bytes.** A blob is never changed in place: a
  new version of a file is a new blob with a new ID. A `BlobId` is therefore
  a safe, permanent cache key, which needs no expiry. A drive entry's file
  names its current version by its `blob`, so the entry's `blob` is the key
  of that version: when the entry changes to a new version, its `blob`
  changes too.
- **The blob feed says when a key is done with.** `Removed` means no entry
  of the stream uses the blob any more. `Evicted` and `Withdrawn` mean this
  device no longer holds the bytes, which says nothing about bytes the
  application opened and holds itself. `Arrived` means a blob can now be
  read with no connection.
- **A content hash keys media by content.** `blobs.content_hash(id, &read)`
  (`contentHash`) is the SHA-256 of a blob's plaintext, computed on this
  device chunk by chunk and kept while the device is open and holds the
  blob; equal content has an equal hash across blobs and spaces. It fetches
  a blob the device does not hold, as any read does, and is `None` when the
  device cannot read the blob whole. The protocol carries no such hash, so
  no peer sees it.
- **Streaming and ranges keep memory flat.** `get_stream` (`getStream`)
  opens a blob chunk by chunk, about a mebibyte at a time, and writes each
  chunk as it opens, so a large file never sits whole in memory.
  `get_range(id, offset, len, &read)` (`getRange`) returns part of a blob,
  opening only the chunks that hold it; the device fetches the blob whole
  first when it does not hold it. `content_hash` reads the same way. A read
  holds a few chunks at a time, plus the range it returns, whether the
  device keeps the blob sealed, in memory, or as a file it holds. From
  Swift and Kotlin, `getToFile(id, path, listener)` writes a blob to a file
  the same way.

Every check of the object format still runs. The stored bytes are checked
against the blob's locator before any plaintext goes out; each chunk is
authenticated before it is used; and a read of the whole blob checks the
plaintext's ID before it gives the last chunk. A stream that fails part way
has written a prefix of the blob: discard it. The first range read of a blob
since the device opened, or since it last fetched the blob, reads the whole
blob once, a few chunks at a time and keeping only the range, so that every
check runs on it; later range reads open only their chunks. When the device
drops a blob, what it found out about its stored bytes goes with them. A range of a blob the application holds as a
file is read through the whole file each time, so that its ID is checked;
to seek in such a file, read the file itself (`materialise`).

A cache in the page, for example, keeps object URLs by `BlobId`, at most a
few hundred, and revokes the least recently used:

```ts
class BlobUrls {
  #urls = new Map<string, string>(); // BlobId → object URL, oldest first

  constructor(private blobs: Blobs, private limit = 200) {
    // An evicted blob's opened bytes stay good: the ID names them for ever.
    void blobs.onChange((change) => {
      if (change.kind === "removed") this.drop(change.id);
    });
  }

  async url(id: BlobId, type: string): Promise<string | undefined> {
    const kept = this.#urls.get(id);
    if (kept !== undefined) {
      this.#urls.delete(id); // most recently used goes last
      this.#urls.set(id, kept);
      return kept;
    }
    const bytes = await this.blobs.get(id); // fetched when the device does not hold it
    if (bytes === undefined) return undefined; // nothing connected could send it
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
removed or leaves, and when the application closes the device. What it
fetches of the space's blobs it holds in memory, within the same budget as
the device's cache, and it keeps none: `keep`, and a read that keeps, fail
there with `NotAllowed`. Check
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
