# Native bindings

`crates/frasil-uniffi` wraps the `frasil` crate for Swift and Kotlin through
UniFFI: a device, its spaces and blob streams, the admission of a device
into a space over a nearby connection, blob reads and what the device
keeps of its blobs, and the feeds an application
follows (whether a space has nothing unsent, a blob's status, what the
device holds for the first time, and what it reports of checkpoints), each
delivered to a listener the application implements. A space's checkpoints
(`checkpoints`, `proposeCheckpoint`, `lateChanges`) and the device's
checkpoint policy and device-list checkpoints (`setCheckpointPolicy`,
`checkpointPolicy`, `listCheckpoints`, `proposeListCheckpoint`) are calls;
`checkpointReports` follows what the device reports of them. See
`docs/checkpoints.md`.

| Directory | What it is |
| --- | --- |
| `swift` | A Swift package, `Frasil`, over the library Cargo builds. |
| `kotlin` | A Kotlin library, package `frasil`, which loads the library through JNA; Gradle and a JDK 21. |

`scripts/bindings.sh` builds the library and the generator at one UniFFI
version, writes the glue, and runs each binding's tests;
`scripts/bindings.sh --check` fails when the committed glue differs from
what the generator writes. The generated files are committed, so an
application can depend on a binding without running the generator.

## Opening a device

`Device.open(path, unlockKey, options)` and `Device.openInMemory(unlockKey,
options)` take a `DeviceOptions` record, or none for the defaults:

| Field | What it sets |
| --- | --- |
| `blobCache` | The budget of the blob cache, in stored bytes; 256 MiB when left out, and 0 stores nothing once a read ends. |
| `keepAllBlobs` | The device fetches and keeps every blob its spaces name: a full copy. |
| `loopback` | The device's own endpoints bind on loopback alone, for tests and examples. |

None of it is stored: give it at each open.

## Joining a space

`space.invite(level, name, listener)` gives an `Invitation` whose `text()`
goes to the other device, which enters it in `device.join(invitation, name,
listener)`; `invitation.admitted()` waits for the newcomer. The two devices
connect to each other directly, with no always-on peer.

```swift
let invitation = try await space.invite(level: "write", name: "Ada's laptop", listener: listener)
show(invitation.text())
try await invitation.admitted()
```

```kotlin
val space = device.join(text, "Ada's phone", listener)
```

The level is `read` or `write`. A nearby admission makes no administrator:
admit the newcomer at `write`, then `space.raise(member, rank)`.

Each side's `AdmissionListener` is asked once, `confirm(code, name)`, with
the six-digit admission code and the name the other device gave, and
answers whether its person saw the same code on both screens. `false`
refuses the admission, and so does a listener that throws. The inviting
device grants as soon as its own person confirms, so its person confirms
only after seeing the code on the newcomer's screen. `confirm` is called on
a thread started for it and may wait there for the person.

**Time limit.** An admission code lives 15 minutes from the moment the
newcomer asks the inviting device. An answer that takes longer counts as
`false`. An invitation itself has no limit: it waits for a newcomer until
another invitation replaces it or the device closes.

**Abandoning an admission.** `join` and `admitted` take a `Cancellation`,
which the application cancels to end the call, and a Kotlin coroutine that
is cancelled ends its call by itself. Swift does not end a call when its
task is cancelled, so cancel the `Cancellation` from the task's
cancellation handler:

```swift
let cancellation = Cancellation()
let space = try await withTaskCancellationHandler {
    try await device.join(
        invitation: text, name: name, listener: listener, cancellation: cancellation)
} onCancel: {
    cancellation.cancel()
}
```

A cancelled `join` fails, stops where it stands, and has joined nothing. A
cancelled `admitted` fails and abandons its invitation: a newcomer that
comes, or came, is refused as if this device's person had not confirmed.
In both, a listener that is being asked is waited for no longer and its
answer counts for nothing; take the question off the screen and return
from `confirm`, since its thread is the listener's until it returns.

An invitation is waited for once. A second `admitted()` fails and says why
the invitation is spent: its admission ended, or the first call was
cancelled. Invite again.

## Reading a large blob without downloading it

A device knows every blob of the streams it holds and fetches one when it is
read. `blobs.get`, `getToFile`, `getRange` and `contentHash` take a
`ReadOptions` record, or none, which says what becomes of a blob the device
has to fetch: left in the cache (the default), kept (`keep`), or stored
nowhere once the read ends (`uncached`); `local` fetches nothing and gives
only what the device holds whole. See `docs/reading-and-caching.md`, "What a
device keeps of its blobs".

`blobs.openReader(id, read)` gives a `BlobReader`, which reads any range of
a blob and fetches only the chunks, of about a mebibyte each, that hold it.
It is what backs a media player: playback starts within a chunk or two, and
a seek fetches where it lands.

```swift
let reader = try await blobs.openReader(id: blob)
let size = try await reader.fetchSize()
let bytes = try await reader.readAt(offset: size / 2, length: 64 * 1024)
try await reader.end()
```

```kotlin
val reader = blobs.openReader(blob)
val size = reader.fetchSize()
val bytes = reader.readAt(size / 2uL, 64uL * 1024uL)
reader.end()
```

| Call | What it does |
| --- | --- |
| `fetchSize()` | The blob's size, once a chunk has opened under its header; fetches one when none has. |
| `size()` | That size, or none before the reader's first read or `fetchSize()`. |
| `readAt(offset, length)` | `length` bytes from `offset`, at most 64 MiB; fewer at the blob's end and none past it. See "What a read gives" below. |
| `readAhead()`, `setReadAhead(chunks)` | How many chunks the reader fetches ahead of where it reads: 8 unless set, at most 64. Set 0 for a reader that jumps about. |
| `verified()` | `chunks` while only each chunk's own checks have run on what the reader gave, `whole` once the checks that need the whole blob have: content that is acted on waits for `whole`. |
| `windowBytes()` | The sealed bytes an `uncached` reader holds in memory. |
| `end()` | Ends the reader: its fetches stop, the reads waiting on it fail, and it waits until the device has looked at its cache. The Rust crate calls it `close`. The generated objects' own `close` (Kotlin) only frees the handle, which stops no read. |

One call reads at a time on a reader. `size()`, `verified()` and
`windowBytes()` do not wait: while a read holds the reader they answer what
held before it.

**What a read gives.** A read holds its whole range in memory and crosses
to the application in one piece, so `length` is at most 67,108,864 bytes
(64 MiB): a longer read is refused before anything is fetched. Read a large
range in pieces. When a chunk after the range's first fails, the read gives
the bytes before it, fewer than asked, and loses none; the next read, from
where that one ended, reports the failure. So fewer bytes than asked mean
the blob's end or a failure, and only a read at or past the end gives none.
A read that is cancelled gives nothing of what it had read.

**Stopping a read.** A read stops in three ways and no other: `end()` on
its reader, its `Cancellation`, and, in Kotlin, the cancellation of the
coroutine that waits in `readAt` or `fetchSize`. Freeing the reader's
handle stops nothing: a call in flight holds the reader, which is freed
after its last call. Swift does not end a call when its task is cancelled:
without a `Cancellation` a cancelled task's read goes on to its end, and
holds the reader's turn until then. Give the read a `Cancellation` and
cancel it from the task's cancellation handler:

```swift
let cancellation = Cancellation()
let bytes = try await withTaskCancellationHandler {
    try await reader.readAt(offset: offset, length: length, cancellation: cancellation)
} onCancel: {
    cancellation.cancel()
}
```

A cancelled read fails, what it had fetched stays where the reader's
options put it, and the reader reads on.

**Backing a player.** The tests hold a sample adapter for each platform,
written to be copied into an application, not shipped in the library:
`swift/Tests/FrasilTests/BlobResourceLoader.swift` is an
`AVAssetResourceLoaderDelegate` that answers a player's content information
request from the blob's size and a content type the application supplies,
and its data requests from `readAt` in pieces of at most a chunk;
`kotlin/src/test/kotlin/BlobDataSource.kt` is a Media3 `DataSource`, written
against the part of Media3's interface it uses, since Media3 needs Android.

Both open one reader for each request of the player's, and end it with the
request. A player keeps several requests open at different places in a
file; a reader serves one call at a time and fetches ahead of where it last
read, so requests that share a reader wait for each other and each jump
between them drops what was asked for ahead. A reader costs nothing until
it is read, and what one request fetched is in the cache for the next.

AVFoundation keeps what a request is answered and does not say how much of
it it has used, so a request to the end of a resource takes the rest of the
blob as fast as the device fetches it. The Swift sample takes a
`bytesPerSecond`, and then answers no faster: set it to a few times the
resource's bit rate to bound what AVFoundation holds of a long resource.

## The cache budget, keeping and dropping

What a read fetches joins the device's blob cache, which holds at most the
budget of `DeviceOptions.blobCache` across all the device's spaces and drops
whole blobs, the one read longest ago first, to stay within it.
`device.blobCacheUsage()` gives the budget and the stored bytes of the
cached and of the kept blobs.

| Call | What it does |
| --- | --- |
| `blobs.keep(id, listener)` | Fetches a blob and keeps it, outside the budget, until it is dropped: a download in the background. |
| `blobs.dropLocal(id)` | Drops what the device stores of a blob: it is absent, and a read fetches it again. |
| `blobs.local(id)` | Whether the blob is kept, cached or absent here, the bytes the device stores of it, and its size. |
| `blobs.isDurable(id)`, `blobs.pending()` | Whether the change that put a blob still waits for an acknowledgement, and the blobs whose change does. |

`blobs.status(id)` and `observeStatus` say `absent` for a blob the device
does not hold while a peer or a member is connected that a read would fetch
it from, and `missing` while none is.

## Feeds

A feed runs until its `Subscription` is cancelled or dropped, and calls its
listener from Frasil's own threads: hand each value to the main thread or an
actor before touching the interface.
