# The Blobs adapter
Protocol 1. Vectors: [adapter-blobs.json](vectors/adapter-blobs.json).

This document specifies the adapter of type `frasil:blobs`, for large media
held as objects: attachments, recordings and images. It defines entries and
their handles, how an entry names its object by locator, references to an
object another space stores, resolution per handle, suggestions, and the
stream snapshot's state. It implements the adapter interface of
[units.md](units.md), section 3.17, and depends on
[overview.md](overview.md) for conventions, [units.md](units.md) for
objects, their locators and keys, [keys.md](keys.md) for key references,
and [adapter-records.md](adapter-records.md) for the logical clock and
stamps. A peer keeps a referenced object by
[ext-libraries.md](ext-libraries.md)'s holds.
An implementation of this adapter implements those sections of
adapter-records.md, whether or not it implements the Records adapter.

It extends [units.md](units.md) only. A core implementation without it keeps
every unit of type `frasil:blobs` and ignores its content
(`UnknownAdapter`); it neither compacts such a stream nor checks or uses its
stream snapshots. A peer keeps the objects such units list in `objects`
whatever adapter the replicas run.

## 1. Overview

- A Blobs stream is a set of **entries**. Each entry is named by a
  **handle** and names one object ([units.md](units.md), section 2.8) by
  its locator. The bytes travel and are stored as objects, fetched by chunk.
- Entries resolve per handle by the stamps of
  [adapter-records.md](adapter-records.md): a put or a remove with the
  greater stamp holds the handle.
- Every object an entry names is listed in its unit's visible `objects`, so
  a peer's view of what is referenced is complete, and compaction keeps
  current entries' objects referenced. A put that replaces an earlier
  entry's object as a version of one file says so in the unit's visible
  `supersedes`, and compaction carries that forward
  ([ext-file-versions.md](ext-file-versions.md)), so a peer can keep a
  bounded number of versions.
- A **reference** is an entry whose object another space of the same
  library stores. It carries the source space and the object's key
  ([units.md](units.md), section 2.8), sealed in this space like the rest
  of the entry, so the file is stored once and this space's readers open
  it. A reference names one object, a fixed version of the file.

## 2. Formats

### 2.1 Content

A log unit's content is a deterministic CBOR map:

| Key | Name | Value | When |
|---|---|---|---|
| 1 | `version` | 1 | always |
| 2 | `clock` | unsigned, at least 1 | always |
| 3 | `ops` | array of 1 to 1,024 ops | always |
| 4, 5, 6 | `suggestion`, `accepts`, `dismisses` | as in [adapter-records.md](adapter-records.md), section 2.2 | as there |

```text
op = [handle (bytes(16))]            a remove
   | [handle (bytes(16)), entry]     a put
```

An **entry** is a deterministic CBOR map:

| Key | Name | Value | When |
|---|---|---|---|
| 1 | `object` | bytes(64): the object's locator | always |
| 2 | `key` | bytes: the key reference of the state the object is sealed under, as its header names it | always |
| 3 | `size` | the plaintext's length, 0 to 2^40 | always |
| 4 | `media_type` | text of 1 to 255 bytes | optional |
| 5 | `name` | text of 1 to 1,022 bytes | optional |
| 6 | `source` | bytes(32): the ID of the space that stores the object | a reference only |
| 7 | `object_key` | bytes(32): the object's key ([units.md](units.md), section 2.8) | a reference only |

- An entry with keys 6 and 7 is a **reference**; an entry has both or
  neither. A reference's key 2 is the key reference the object's header
  names: a state of the source, which this space's readers need not hold.
- A handle is 16 random bytes, drawn by the writer that first puts it.
- No two ops of one unit name the same handle.
- A snapshot unit's content is empty.

### 2.2 The snapshot state

The `state` of a stream snapshot object ([units.md](units.md), section 2.9)
is a deterministic CBOR map:

| Key | Name | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `max_clock` | unsigned: the floor over the cover |
| 3 | `entries` | array of `[handle, entry or [], clock, author, event ID]`, strictly ascending by handle |
| 4 | `suggestions` | optional: as in [adapter-records.md](adapter-records.md), section 2.3 |

- A removed handle appears with `[]` in place of its entry.
- A **history-free** state is the same map without key 4 and without
  removed handles.

## 3. Procedures

### 3.1 The checks

On a unit of type `frasil:blobs`, after [units.md](units.md)'s checks, in
order:

```text
1. The content is deterministic CBOR, a map with an unsigned
   key 1, or is empty in a snapshot unit.                      else Malformed
   Key 1 is 1.                                                 else UnknownContentVersion
2. Keys among 1 to 6, keys 1 to 3 present, as section 2.1 and
   adapter-records.md's steps 2 and 3 say for keys 4 to 6.
   Each op: a 16-byte handle, at most once; an entry's keys,
   types and lengths, keys 6 and 7 both or neither; its key
   reference reads as one rotation set (keys.md, section 3.15,
   step 1).                                                    else Malformed
3. Every put's locator is in the unit's objects.               else ObjectNotListed
4. The suggest check (section 3.3) and any registered
   capability checks.                                          else CapabilityRefused
5. The unit is admitted (adapter-records.md, section 3.1).     else ClockAhead
```

### 3.2 Merge and rebuild

- The clock, the floor, admission and a writer's clock are
  [adapter-records.md](adapter-records.md)'s, section 3.1, over this
  stream's units whose content passes steps 1 and 2 of section 3.1.
- **Apply** sets each handle of the unit's ops whose stamp
  ([adapter-records.md](adapter-records.md), section 3.3) is greater than
  the handle's own, or that has none. A remove is a put of nothing: the
  handle's stamp moves, and the entry is gone until a later put. Only
  admitted units that are accepted are applied.
- **Rebuild** loads the settled snapshot and applies the accepted, admitted
  units after its cover.

### 3.3 Suggestions

As in [adapter-records.md](adapter-records.md), section 3.4: a suggestion's
ops stay in the suggestion layer; an accepting writer puts the entries it
adopts in a unit of its own, listing their objects again; and the `suggest`
check refuses anything but a suggestion from a suggester, snapshot units
included.

### 3.4 Compaction

- A compactor admits and applies as [adapter-records.md](adapter-records.md),
  section 3.5, says. **Checking a snapshot** compares its state's bytes.
- The snapshot unit lists in `objects` the locator of every current entry,
  of every put in an open suggestion, and of its snapshot object. An entry
  removed and compacted away is then no longer referenced, and a peer
  collects its object as [peers.md](peers.md) says.
- A compactor that implements
  [ext-file-versions.md](ext-file-versions.md) lists in the snapshot
  unit's `supersedes` which of those objects replaced which, as that
  document's section 3.4 says. The state's bytes do not depend on it.
- A state that does not decode as section 2.2 is `Malformed`: the replica
  reports `BadCompaction` and never uses it.

### 3.5 Fetching

A reader fetches an entry's object by chunk ([units.md](units.md), section
3.14) from any party that holds it: an always-on peer, or a member that
announced it in `ObjectHave`. For media it plays, it fetches in chunk order
from where it plays: it may fetch any chunk index first, as a seek needs.
On a stream, the header travels with the first chunk of each answer to an
`ObjectWant` ([units.md](units.md), section 3.14); on the HTTP routes,
slice 0 begins with it ([transport.md](transport.md)), and a reader that
holds no header fetches slice 0 first.
It opens the object under the state its header names, checks each chunk
before it uses it, and runs the whole-object checks, steps 0 and 7, once
it has read every chunk ([units.md](units.md), section 3.3); it reports an
entry whose `key` or `size` differs from the header's.

A reference is fetched under this space's own fetch right, from a peer that
holds the object for this space ([ext-libraries.md](ext-libraries.md),
"Fetching a held object"), or from a member that announced it. The reader
opens it with the entry's object key and the source's ID in each chunk's
associated data, and skips the object ID check that needs the source's
key ([units.md](units.md), section 3.3). A peer's **hold** on the object is
[ext-libraries.md](ext-libraries.md)'s; an **application-held** object is
[at-rest.md](at-rest.md)'s, one whose plaintext the application keeps in
place of the sealed chunks. A reader that holds only the object key may
keep a reference's plaintext that way, but cannot serve the object from
it: the chunks' nonces and the ID come from the source's `k(S)`, which the
key tells nothing of ([at-rest.md](at-rest.md), "Held objects"). It serves
the sealed bytes it stores, if any, and nothing else.

### 3.6 Re-applying a late write

Only [ext-restricted-spaces.md](ext-restricted-spaces.md) calls `reapply`.
The re-applier writes the late write's ops again in a unit of its own in the
moved document, under its own clock, listing the objects they name.

### 3.7 References

**Putting a reference.** A writer of space B that reads an entry of space A
puts a reference to it:

1. It takes the entry's locator, key reference, size, media type and name,
   and the object's key and source: `k(S)` of A's state gives the key, and
   the source is A; an entry that is itself a reference gives its own key 6
   and 7, so a reference of a reference names the space that stores the
   object.
2. It registers a hold for B ([ext-libraries.md](ext-libraries.md),
   "Registering a hold") at the peers that host B. On `other_library` the
   two spaces are billed to different libraries: the writer puts no
   reference, and copies the file instead, as a new object sealed under
   B's state. A writer with no peer connected registers the hold at its
   next connection, before it sends the unit.
3. It puts the entry, with keys 6 and 7, in a unit of B that lists the
   locator in `objects`, like any put. It uploads nothing: the peer holds
   the object for B.

**A fixed version.** A reference names one object by its locator and never
follows a later put in the source: the source's handle may take a new
blob, or be removed and compacted away, and the reference still opens the
same bytes. An application may offer the newer version; putting it is a
new reference.

**Removing.** A remove of the handle is a remove like any other. Once
compaction drops the locator and the peer collects the units that listed
it, the hold ends, and the peer collects the object if nothing else keeps
it ([ext-libraries.md](ext-libraries.md), "Keeping a held object").

### 3.8 Error classes

This document adds no class. It uses `Malformed`, `UnknownContentVersion`,
`ObjectNotListed`, `CapabilityRefused` and `BadCompaction` as
[overview.md](overview.md) and [units.md](units.md) define them, and
`ClockAhead` as [adapter-records.md](adapter-records.md) does; each refuses
or holds content only.

## 4. Security considerations

- **A complete reference view.** Because content naming an unlisted object
  is refused at every replica, a writer cannot hide a reference from peers,
  and a peer never collects an object a current entry names, except an
  old version of a file that a writer declared superseded, after the
  retention of [ext-file-versions.md](ext-file-versions.md).
- **A wrong entry.** A writer can put an entry whose size, media type or
  name is false. The object's own header and ID decide what is read; the
  entry's text fields are only shown.
- **Handles** are chosen by writers. A writer that reuses another's handle
  competes for it by stamp, as for any cell; it cannot change the other's
  object, which its locator fixes.
- Clocks, suggestions and history-free stamps carry the considerations of
  [adapter-records.md](adapter-records.md), section 4.
- **A reference hands one key.** The object key opens one object and tells
  nothing of the source's state key or other objects. A reader of B learns
  the source's ID and the state reference the object's header shows, and
  nothing else of A. A writer of B can put a reference with a false key or
  source; it opens nothing, and its reader reports it like any entry whose
  object does not open.
- **What a reader shows before the whole-object checks.** A reader uses a
  chunk once it opens (section 3.5), so what it plays or shows before it
  has read every chunk, and run steps 0 and 7, may later be refused. A
  party without the space's keys, a peer included, cannot make a chunk
  that opens under the object key. A member that holds that key, the
  object's writer among them, can serve different readers different chunks under one
  header until the final check, which binds the whole plaintext to the
  locator and the object ID. It can also seal chunks under a header of
  another size, which names the same object ID and so passes steps 1 to
  3: a reader then takes that size for the object's until step 0, which
  binds the header to the locator. A reader reports the refusal when it comes
  (`ObjectMismatch`), and an application that must not show unchecked
  bytes reads the whole object first. A reader that never reads the whole
  object never runs the final check, so no refusal comes for what it
  returned: of a range read alone, nothing later refutes a chunk that
  such a member served. The party that serves chunks learns which chunks
  a reader reads, and when: a peer learns it of every reader it serves,
  without the content.
- **References are not convergent.** An object's key derives from its
  state's key and its ID, never from the content alone, so a reference
  shows no one that two spaces hold the same file unless one references
  the other.

## 5. Test vectors

[adapter-blobs.json](vectors/adapter-blobs.json):

- `units`: three units of two writers byte for byte: two puts naming
  objects by locator, and a remove, with each unit's `objects`.
- `merge_orders`: the units applied in all six orders to one snapshot.
- `history_free`: the export of the final state.
- `snapshot_unit_objects`: the locators of the current entries, which the
  snapshot unit lists.
- `content_refusals`: four contents with their classes: an object not
  listed (`ObjectNotListed`), a handle twice, a 15-byte handle, and an entry
  without a size.
- `compaction_checks`: the `suggest` check on a snapshot unit from a full
  writer, from a suggester (`CapabilityRefused`), and from a writer granted
  `suggest` with mode `extends`.
- `references`: an object sealed in a source space, its object key, and a
  unit of another space that puts a reference to it, byte for byte, with
  its `objects`; the object read with the entry's key alone; and two
  refusals: a reference without its object key, and a 31-byte object key
  (`Malformed`).
