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
every second. It waits in the same way through bytes that failed their
checks as every connected party sent them, while another party could still
send the blob: a peer the device keeps for the space that is not connected,
or any other member. It then fails at its deadline with `ObjectMismatch` or
`Malformed` and not `Timeout`. Only in a space whose one member is this
device, with every peer it keeps connected, does such a failure end the
wait at once.

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
device is a separate question, and it has two halves. In Rust,
`blobs.is_durable(id)` is `false` while the change that put the blob waits
for an acknowledgement, and `blobs.pending()` lists the stream's blobs
still waiting. Both read the device's store, so after a reopen they say
what the device offers once it connects; an upload a peer holds part of
goes on from there. Ask again on `Event::PendingChanges`.

Durable is about the change, not the bytes: an acknowledgement covers
events alone. This device uploads a blob's bytes to a peer before it sends
the peer the change, so a change a peer acknowledged to this device
normally has its bytes there. In a space with no always-on peer, or whose
peer this device has not heard since it opened, a member's acknowledgement
makes the change durable, and a member fetches a blob's bytes only when it
reads the blob. An application may conclude from a durable put that
another device knows of the blob. It may not conclude that anyone else
holds the bytes, and it must not delete its source file because a put is
durable. `blobs.local(id)` answers that: a blob this device put is kept
until an always-on peer that has acknowledged the change answers that it
holds the bytes, and cached from then on, unless the application asked to
keep it. In a space with no always-on peer the blob stays kept,
and this device's copy may be the only one.

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
failed their checks, and none is still being made. A peer or a member that
connects while a read waits serves it, and a read does not end on the
others' failure while a peer has yet to grant the space.

A read of a blob the device does not hold whole fetches the blob's chunks,
checks each as it arrives, and puts them where the read says. `get`,
`get_stream` and `content_hash` read the blob in order from its first byte,
so every check of the object format has run by the time they reach its last
chunk: `get` gives nothing before that, and `get_stream` writes each chunk
once it has passed its own checks, and the last one once the whole has.
`get_range` fetches only the chunks of its range.

By default the chunks go to the cache as they arrive. A read that fails or
is cancelled part way leaves what it fetched there, as part of a cached
blob: a later read completes it, `blobs.local(id)` counts its bytes, and
the cache evicts it whole like any other. An `uncached` read stores nothing:
the chunks pass through memory, a few at a time, and so do those of any read
under a budget of zero or of a blob too large for the whole budget. A blob
the device already holds part of is completed where it is, whatever the
read says, and when an `uncached` read and one that is not read one blob at
once, the chunks go to the cache and both read them there. A read that
fetches nothing, because nothing is connected or the fetch gets nowhere,
writes nothing to the store.

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
snapshots; and a blob that a read, an open reader or a fetch is using. A
cached blob that is being read grows as its chunks arrive: the device evicts
other blobs to make room, and when none is left to go the cache stands over
its budget, by no more than the blobs being read, until their reads end. A blob this device
put is kept, and `blobs.local(id)` says so, until a peer of the space has
acknowledged the change that put the blob and then answers that it holds
the bytes: the blob is cached from then on, unless the application asked to
keep it. The answer a peer gives when the bytes are uploaded, before the
change reaches it, does not count: a peer discards bytes that no change
names after a while, so the device asks it once more after the
acknowledgement, with one more slice of the blob over HTTP and one chunk
back over iroh. Nothing else releases the blob: not another member's or
another peer's acknowledgement, not a reopen, not a paused space. A blob
that is still kept so, as when the change reached the peer through another
device, is asked of the peer again when the device connects and from time
to time, and uploaded again if the peer lost it. A blob that was put,
removed and compacted away before a peer took it is no longer waited for:
it is cached, or kept if the application asked for that. In a space with no always-on peer no
other party is known to hold the bytes, so a blob put there is kept until
the application drops it. `drop_local` refuses, with `NotAllowed`, a blob in
use and, in a space with an always-on peer, a blob this device put that no
peer holds yet, whether or not the application asked to keep it: `keep`
on such a blob is remembered, and decides only what the blob becomes once
a peer holds it. Putting bytes the device already holds changes nothing of
that: a kept blob put again is kept once a peer holds it, and a cached one
is cached again then.

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
are kept: opening it with a budget evicts nothing it held. That includes a
blob the earlier version had fetched only part of, as a device that fetched
blobs on demand may have left one: the part is kept, and since a device
fetches the rest of a blob it keeps, such blobs are fetched whole after the
first open, outside the budget. Call `drop_local` for those the application
does not want kept; a read then fetches them into the cache.

**Spaces whose blobs the application holds as files** (`held`) have no
cache: a file is the application's to keep or delete. A blob a read fetches
there becomes a file, as `materialise` with an empty hint makes one; `keep`
is that `materialise`, and `drop_local` is `release`. An `uncached` read
that would have to fetch is refused there with `Unsupported`, since it would
write a file. A reader (`open_reader`) is the exception: over a blob held as
a file it reads the file, and over one that is not it fetches the chunks it
reads into its own memory, whatever its `Read` says, and makes no file.

The npm package and the Swift and Kotlin bindings read as `Read::new()`
does, into the cache, under the default budget. They do not yet have
`Options::blob_cache`, `Options::keep_all_blobs`, `Read`, `keep`,
`drop_local`, `local`, `blob_cache_usage` or `open_reader`.

## Reading a blob that is not all here

`blobs.open_reader(id, &read)` gives a `BlobReader`, which reads any range
of a blob and fetches only the chunks that hold it. A blob is sealed in
chunks of about a mebibyte (1,048,536 bytes of content each), and each
opens by itself, so a reader gives bytes as soon as their chunk is here and
checked, without the rest of the blob. It is what backs a media player: a
video starts within a chunk or two, and a seek fetches where it lands.

```rust
use frasil::{Read, Verified};

let mut reader = blobs.open_reader(id, &Read::new()).await?;
let size = reader.fetch_size().await?;          // from the blob's header
let mut buf = vec![0; 64 * 1024];
let n = reader.read_at(offset, &mut buf).await?; // 0 at the end
if reader.verified() == Verified::Whole { /* every check has run */ }
reader.close().await?;
```

- `read_at(offset, buf)` gives at least one byte unless `offset` is at or
  past the end, and no more than the chunk `offset` lies in holds from
  there: call it again for the rest. `read(buf)` reads at the reader's
  position, which `seek(position)` moves.
- The chunk a read needs is asked of the space's connections ahead of
  everything else, and the chunks after it behind that: eight of them
  unless `set_read_ahead(chunks)` says otherwise. A seek cancels what it
  leaves behind, and a reader that is dropped or closed cancels all of it.
- `size()` is the size the blob's header gives, which every chunk is bound
  to. It is `None` until the reader holds the header; `fetch_size()` fetches
  it, with the chunk the reader stands in.
- A read fails with `Missing` while nothing is connected that could send
  the chunk, and with `Timeout` when nothing arrives for half a minute. Such
  a read may be made again: what the reader fetched before is still there.

**Backing a player.** A player asks for byte ranges, by `Range` requests or
through a data source of its platform. Answer each from `read_at`, in a loop
until the range is filled, and give `size()` as the length. Players read
ahead by themselves, so the default read-ahead suits them; set it to 0 for a
reader that jumps about, such as one that reads an index at the end of a
file first.

**Where the chunks go** is what the reader's `Read` says, as for any read.
By default they join the cache as parts of a cached blob, and with `keep`
they are kept. With `uncached` the reader holds them itself, sealed, in a
window in memory: the chunk it stands in and its read-ahead, at most
`read_ahead + 1` chunks of 1,048,576 bytes, 9 MiB by default, beside one
opened chunk. A window takes only chunks its reader asked for, so nothing a
peer or a member sends makes it grow. Chunks behind the reader are let go,
and a seek back fetches them again. A blob too large for the whole budget
is read that way under any `Read`, as it could not be cached.

**What is checked, and when.** Before a reader gives any byte, the blob's
header has passed its checks and the byte's chunk has opened under the
blob's key, at its own place in its own blob: a chunk of another blob, or
this blob's chunk from another place, does not open. A party without the
space's keys, a peer included, cannot make a chunk that opens. Two checks
remain that need the whole blob: that its stored bytes are the ones the
stream names, and that its content is what its ID was made from. Until they
have run, a member that holds the blob's key, its writer among them, can
have served chunks that open and are not the blob's.

`reader.verified()` says which holds:

| | Meaning |
| --- | --- |
| `Verified::Chunks` | Each byte given came from a chunk that opened. The whole-blob checks have not run. |
| `Verified::Whole` | Every check has run: the bytes are the blob's. |

A reader becomes `Whole` in one of two ways. One that reads the blob in
order from its first byte to its last runs the whole-blob checks as the
bytes pass, and holds back the last chunk until they do; this works with
`uncached` too, with nothing stored. One that seeks cannot run them itself:
they run once the device holds the whole blob in its store, which happens
when the reader, or any other read, has fetched every chunk into the cache
or the blob is kept. A reader that is `uncached` and seeks therefore stays
at `Chunks`.

When a whole-blob check fails, the blob is refused: every open reader of it
fails with `ObjectMismatch` from then on, `Event::ObjectRefused` names the
blob, and the device drops what it cached of it. Content that people only
watch or listen to can be shown at `Chunks`, since the worst a member can do
is show a viewer something else than it showed another, and the reader says
so when it finds out. Content that is acted on, such as a document that is
executed, parsed as configuration, or signed off, must wait for `Whole`: read
it with `get`, or read the reader to its end in order first.

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
  opening only the chunks that hold it; when the device does not hold the
  blob whole, it fetches those chunks alone. `content_hash` reads the way
  `get_stream` does. A read
  holds a few chunks at a time, plus the range it returns, whether the
  device keeps the blob sealed, in memory, or as a file it holds. From
  Swift and Kotlin, `getToFile(id, path, listener)` writes a blob to a file
  the same way.

Every check of the object format still runs on a blob the device holds
whole. The stored bytes are checked against the blob's locator before any
plaintext goes out; each chunk is authenticated before it is used; and a
read of the whole blob checks the plaintext's ID before it gives the last
chunk. A stream that fails part way has written a prefix of the blob:
discard it. The first range read of a whole blob since the device opened,
or since it last fetched the blob, reads the whole blob once, a few chunks
at a time and keeping only the range, so that every check runs on it; later
range reads open only their chunks. A range of a blob the device holds in
part, or nothing of, is read as a reader reads it: its chunks are checked,
and the whole-blob checks have not run (see above). When the device
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
