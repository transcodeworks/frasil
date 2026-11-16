# File versions and retention
Protocol 1. Vectors: [ext-file-versions.json](vectors/ext-file-versions.json).

This document specifies the **supersession**, a unit's visible statement
that an object it lists replaces an earlier object of its stream, and the
**retention** by which an always-on peer keeps a bounded number of a
file's old versions for a bounded time and collects the rest, without
reading content and without any device online. It extends
[units.md](units.md), which reserves visible key 8, `supersedes`, and
fixes its form; [adapter-blobs.md](adapter-blobs.md), whose puts carry
supersessions and whose snapshot units carry them forward; and
[peers.md](peers.md), whose collection it widens. It depends on
[overview.md](overview.md) for conventions, error classes and time, and
on [ext-libraries.md](ext-libraries.md) for holds.
[ext-drive.md](ext-drive.md)'s versions of a file are a writer's reason
to supersede; no drive is needed.

An implementation that does not implement it:

| What this document defines | Such an implementation |
|---|---|
| The meaning of `supersedes` | a peer stores a unit that carries it and collects nothing by it; a replica reads it for form ([units.md](units.md), section 3.1) and ignores it |
| A compactor's supersessions | a snapshot unit it writes carries none, and a replica with this document reads that as none |
| Retention | a peer keeps every referenced object until compaction drops its last listing, as [peers.md](peers.md) says |
| The cadence | a client compacts by [units.md](units.md)'s cadence alone |

Nothing in a log, roster, unit or object changes its validity by this
document, so no replica's verdict depends on it.

## 1. Overview

- A **listing** is one stored unit and one locator in its `objects`
  ([units.md](units.md), section 3.7). A unit that puts a new version of
  a file lists the new object, and in `supersedes` names the listing of
  each object it replaces: the unit that put the old version, and the old
  object. A snapshot unit names, among its own listings, which object
  replaced which.
- At a peer, a listing is **superseded** while a stored unit of its
  stream supersedes it. An object every listing of which is superseded
  is an old version; one with a listing nothing supersedes is a
  **head**, and is never collected by this document. The current
  version of a file, every side of an open conflict, and a second file
  that happens to hold the same bytes are heads.
- The peer counts versions along supersessions, from the heads down, and
  collects an old version once its depth reaches `max_file_versions`, or
  the time since it was superseded reaches `file_version_retention`,
  whichever comes first, after the superseding unit is stable at the
  peer or T has passed since the peer first saw it. A version exactly
  at either limit is collected (section 3.8, steps 5 and 6).
- Supersessions are per listing, never per object, because one object
  is one set of bytes however many files hold it: a version of one file
  that is the current version of another is a head.
- A client compacts a Blobs stream on a cadence of its own once units
  since the last snapshot carry supersessions, so that a version whose
  put was compacted before it was superseded does not wait for
  [units.md](units.md)'s cadence.
- A writer can supersede only what it could remove. The peer learns
  which objects of a stream are versions of one another, and nothing
  else it did not see before.

## 2. Formats

### 2.1 Supersessions

`supersedes` is visible key 8 of a unit's body
([units.md](units.md), section 2.3):

```text
supersession = [successor, listing, predecessor]     in a log unit
             | [successor, predecessor]              in a snapshot unit
```

- In a log unit, `[S, L, P]` says: this unit's object `S` replaces the
  object `P` as listed by the unit `L` of this stream. `L` is in the
  unit's stream past, and `P` is in `L`'s `objects`.
- In a snapshot unit, `[S, P]` says: of this unit's own listings, `S`
  replaces `P`. Both are in its `objects`.
- `S` may equal `P`: an object put again under a new handle replaces its
  own earlier listing, and the new listing is not superseded.
- A unit carries at most 4,096 supersessions, strictly ascending by
  their bytes; a peer drops a unit that breaks the form
  ([units.md](units.md), section 3.1, step 11).

### 2.2 Settings

| Setting | Scope | Default | Range | Set by |
|---|---|---|---|---|
| `max_file_versions` | the peer, or a library ([ext-libraries.md](ext-libraries.md)) | 100 | 1 to 1,024 | the operator |
| `file_version_retention` | the same | 7 days | 0 to 365 days | the operator |
| `version_compaction_interval` | a client | 24 hours | 1 hour to 7 days | the implementation |

`max_file_versions` counts the current version: with 100, a head and the
99 versions beneath it stay. `file_version_retention` counts on the
peer's timeline from its first sight of the superseding unit
([overview.md](overview.md), section 6.8). `version_compaction_interval`
is section 3.11's.

### 2.3 What a peer keeps

Per space, per stream and per superseded listing: the unit and the
locator, the units that supersede it, and `since`, the peer's reading at
which it became superseded (section 3.6). Nothing of this is served or
signed.

### 2.4 Error classes

| Class | Meaning | Sort |
|---|---|---|
| `BadSupersession` | at a replica: a supersession whose successor no put of its unit names, or, in a snapshot unit, whose successor or predecessor no current entry names; it is ignored, and the content stands | report |

`BadCompaction` is [units.md](units.md)'s: a snapshot unit whose
supersessions differ from the replica's own derivation (section 3.5).

## 3. Procedures

### 3.1 Superseding

A writer that puts an object as a new version of a file, under a new
handle of a Blobs stream ([adapter-blobs.md](adapter-blobs.md)), writes
in the unit's `supersedes` one supersession per **parent**: each
version the new one was made from whose entry it holds in the same
stream. For a parent's entry:

1. `listing` is the event ID of the unit that put the entry, as the
   stream's state stamps it ([adapter-blobs.md](adapter-blobs.md),
   section 2.2, the entry's event ID).
2. `predecessor` is the entry's locator; `successor` is the new object's.

- A parent whose entry is absent, removed or in another stream gets no
  supersession. Its object stays a head at the peer; the writer MAY
  remove its handle, which lets the peer collect the object as any
  unreferenced one once compaction drops the listing.
- A writer MUST write the supersession even when the new object is the
  parent's own, as when a person picks one side of a conflict: the
  parent's old listing is then superseded, and the new listing stands
  alone as the head. Without it the old listing would keep the object a
  head after later versions replace it. The supersession helps only
  when a later version supersedes the pick before the next compaction:
  compaction cannot carry a supersession of one entry naming an object
  that another current entry of the stream names unsuperseded (section
  3.4), and the pick's own entry is that entry until a later version
  supersedes it. After that compaction, the old handle keeps the bytes
  a head until a writer removes the handle. A writer
  that put an object's bytes again SHOULD remove the superseded handle
  once no record of it is kept ([ext-drive.md](ext-drive.md),
  "Forgetting versions").
- A writer MUST name only listings in the unit's stream past, each
  naming its predecessor. A peer cannot check this and a replica need
  not; a supersession that names no listing the peer holds has no effect
  (section 3.6).
- A resolution names every head it resolves. A plain save names the one
  version its copy came from, head or not.
- The object is uploaded before the unit, as for any put
  ([units.md](units.md), section 3.4). An object the peer stores
  already, because the same bytes were put before, needs no upload. A
  held version saved over before any peer took it goes without its
  object ([units.md](units.md), section 3.4, item 7), and a later
  version supersedes it all the same.

### 3.2 The checks at a replica

On a unit of type `frasil:blobs` whose context carries supersessions,
after [adapter-blobs.md](adapter-blobs.md)'s checks, each supersession
in order:

```text
1. In a log unit, its successor is the locator of a put of this
   unit; in a snapshot unit, its successor and predecessor are each
   the locator of a current entry of the state.                 else BadSupersession
```

A supersession that fails is reported and ignored; the content and the
unit's verdict stand. A content refusal here would undo the put itself,
and a replica without this document would still apply it.

### 3.3 The supersession set

A replica with this document keeps, per Blobs stream and as part of the
adapter's state, the **supersession set** Σ: a set of
`(listing, predecessor) → successor` triples. It is a set, so apply is
commutative and idempotent as [units.md](units.md), section 3.17,
requires.

- **Apply** adds, for each supersession `[S, L, P]` of an accepted log
  unit that passes section 3.2, `(L, P) → S`.
- **Load** of a snapshot state adds, for each supersession `[S, P]` of
  the snapshot unit that passes section 3.2 and each entry of the loaded
  state whose locator is `P`, `(that entry's event ID, P) → S`. The
  compactor wrote `[S, P]` only when every entry naming `P` was
  superseded (section 3.4), so the mapping is exact.
- **Rebuild** is load, then apply of each unit, as for the entries.
- A current entry `h` of the state, with locator `P`, is **superseded**
  when Σ holds `(h's event ID, P) → S` for some `S` that is the locator
  of a current entry other than `h`. A removed handle is never
  superseded, and an entry whose successor's handle was removed is a
  head again once that is compacted: a peer collects only what a
  referenced object replaces.
- `export_history_free` carries Σ restricted to the state's current
  entries, as it keeps their stamps; Σ travels beside the exported
  state, never in its bytes (section 3.4). A seed
  ([units.md](units.md), section 2.9) built from such an export carries
  in its own key 8 the pairs `[S, P]` that section 3.4 derives from that
  state and that Σ, in the same form and under the same limit as a
  compaction's snapshot unit: two-element supersessions, at most 4,096,
  strictly ascending. A replica that loads a seed adds them to Σ as Load
  does.
- A space snapshot's stream entry ([units.md](units.md), section 2.11)
  carries the same pairs for the history-free state it names, in its key
  7, in the same form and under the same limit; past the limit the entry
  carries none. A newcomer holds no unit of the entry's cover, so it
  adds them to Σ as Load does when it loads the entry's state.

### 3.4 Compacting

A compactor that implements this document lists in the snapshot unit's
`supersedes`, strictly ascending and without repeats, `[S, P]` for:

- each locator `P` of a current entry such that every current entry with
  locator `P` is superseded (section 3.3) and no put of an open
  suggestion names `P`; and
- each `S` that Σ gives as a successor of one of those entries and that
  is the locator of a current entry.

Both are in the unit's `objects` already, since it lists every current
entry's object ([adapter-blobs.md](adapter-blobs.md), section 3.4). A
snapshot unit with nothing to list carries no key 8. The stream
snapshot's `state` ([adapter-blobs.md](adapter-blobs.md), section 2.2)
does not change: Σ is carried by the unit's visible part, which the
unit's signature covers, and a compactor without this document produces
the same state bytes.

### 3.5 Checking a snapshot

A replica that checks a snapshot ([units.md](units.md), section 3.6)
and holds the units of the cover also derives section 3.4's list from
its own rebuild and compares it with the snapshot unit's key 8: a key 8
that is present and differs is `BadCompaction`, with everything that
entails there; a key 8 that is absent passes, and the replica loads no
supersession from it. A replica that cannot rebuild trusts the
compactor for it, as for the state.

A replica that holds the cover runs this derivation on a snapshot unit's
key 8, and its verdict governs: a key 8 that matches is loaded as section
3.3 says, and one that differs is `BadCompaction`. Section 3.2's check of
a snapshot unit, which reports `BadSupersession` and ignores the pair,
is for a replica that cannot rebuild.

### 3.6 Listings at a peer

A **listing** `(U, O)` is a stored unit `U`, neither replaced nor
released, and a locator `O` in its `objects` ([units.md](units.md),
section 3.7). A unit held as fork evidence, a second event at its author
and `seq` ([peers.md](peers.md), section 3.2), lists as any stored unit
and supersedes nothing.

A listing `(U, O)` is **superseded by** a unit `V` when `V` is a stored
unit of `U`'s stream, neither replaced, released nor fork evidence, and
either `V` is a log unit carrying `[S, U, O]`, or `V` is `U`, a snapshot
unit carrying `[S, O]`. `S` is a **successor** of `O`. A supersession
that names a listing the peer does not hold, of another stream, or whose
predecessor `U` does not list has no effect. A listing is **superseded**
while some unit supersedes it.

`since(U, O)` is the earliest first sight among the units that
supersede the listing, on the peer's timeline, kept while the listing is
superseded. For a
snapshot unit's own listing of `O`, `since` is the latest `since` of the
listings of `O` by the units of its cover, if every one of them was
superseded when the peer stored the snapshot unit; otherwise it is the
snapshot unit's first sight. So compaction neither restarts the
retention nor shortens it.

### 3.7 Heads and depth

Over the space, with every stream's listings:

- A **head** is an object with a listing that is not superseded.
- There is an edge from `S` to `P` for each superseded listing of `P`
  with successor `S`.
- `depth(O)` is the length of the shortest path from any head to `O`
  along edges, 0 for a head, and none when there is no path.

### 3.8 Retention

For an object `O` the space stores, in order:

```text
retain(O, now, max_file_versions, file_version_retention, T):
  1. O has no listing.                                        peers.md decides
  2. A live hold names O (ext-libraries.md).                  Keep
  3. Some listing of O is not superseded.                     Keep
  4. For some listing of O, no unit that supersedes it is
     stable at the peer, nor has lower(its first sight, now)
     reached T.                                               Keep
  5. depth(O) is none, or depth(O) >= max_file_versions.      Collect
  6. lower(since(O), now) >= file_version_retention, with
     since(O) the latest since over O's listings.             Collect
  7. Otherwise.                                               Keep
```

- Step 1 leaves orphans, released and covered objects to
  [peers.md](peers.md): this document collects only referenced objects.
- Step 3 is the whole guarantee: the current version of a file, every
  head of a conflict, a version put again, and a second file with the
  same bytes each have an unsuperseded listing.
- Step 4 waits as collection does ([peers.md](peers.md), section 3.19):
  replicas refuse a unit by a writer whose removal is concurrent with it,
  and the peer cannot know. T is the space's `erasure_timeout`. In a
  space whose recovery member never signs, nothing is stable at the peer
  and every retention waits T.
- Steps 5 and 6: either limit suffices, and both count the current
  version. A depth of none is an old version that no head reaches, which
  only a cycle of supersessions without a head can make; the peer
  collects it as past the count.
- Collecting deletes the object's bytes, and leaves its listings, its
  supersessions and the units as they are: the version stays in every
  drive's records, and readers show it as unavailable. The bytes leave
  usage ([peers.md](peers.md), section 3.20).
- A peer runs this at the same passes as its collection. Each peer
  decides on its own units and timeline; peers that hold the same units
  collect the same objects at different times.
- A collected object stored again, as a version restored from a copy a
  device kept, is a new upload: an orphan until a unit lists it, then
  the head of a new listing.

### 3.9 Holds, releases, erasures and forks

- **Holds.** An object a live hold names is kept (step 2). With this
  document, a hold whose holding space's every listing of the locator
  is superseded ends when `retain`, run over those listings alone and
  without step 2, would collect: a reference to an old version of a
  file goes with the version, and a reference to a current one keeps it
  ([ext-libraries.md](ext-libraries.md), section 3.8). A reference
  itself is fixed to its object; a drive that wants the newer version
  puts a new reference.
- **Releases.** A released stream's units are not listings and
  supersede nothing. What a release and a restore do to its units and
  objects is [peers.md](peers.md)'s.
- **Erasures.** An erasure names the whole space and removes every
  unit, object and supersession of it, as [peers.md](peers.md) says.
- **Forks.** Fork evidence supersedes nothing, so a forked device cannot
  start a retention; what it listed stays referenced.
- **Restores and restored devices.** A device that returns after the
  retention with a version made from a collected one puts it as any
  version: its supersession names the collected version's listing,
  which still exists, and its own listing is a head. In the drive the
  version is a second head beside the current one: a conflict whose
  base no party serves. The application resolves it by choice.

### 3.10 A superseding unit refused

A client that finds, refused by the write rule or as content, a unit
whose supersessions name objects it wants kept puts each such object
again under a new handle in a unit of its own, with no supersession: the
new listing is a head, and the peer keeps the object. The object needs
no upload if the peer stores it still. This is the counterpart of the
restore that cancels a false snapshot's collection
([peers.md](peers.md), section 3.19); a peer cannot judge the refused
unit, and step 4 gives the client until the unit is stable or T.

### 3.11 The cadence

A log unit's supersession reaches the listing it names only while that
listing is a log unit at the peer. Once a snapshot has replaced the old
version's put, the snapshot's own listing can be superseded only by the
next snapshot (section 3.4). So, besides [units.md](units.md)'s cadence,
a client that holds a Blobs stream's units whole compacts it:

```text
compact(first, now, version_compaction_interval):
  1. No unit since the stream's last snapshot carries a
     supersession.                                            Wait
  2. lower(first, now) >= version_compaction_interval.        Compact
  3. Otherwise.                                               Wait
```

`first` is the client's first sight of the earliest unit since the last
snapshot that carries a supersession, on the client's own timeline
([overview.md](overview.md), section 6.3). A Blobs snapshot is one unit
that lists the current entries' objects, so the cost is bounded by the
interval and the stream's size. An old version then waits at most the
interval beyond the retention.

## 4. Security considerations

- **What a peer learns.** For each unit of a stream: which of its
  objects replace which earlier objects, and which unit listed each.
  So: which objects are versions of one file, in what order, how often a
  file is saved, and when two devices saved concurrently and when the
  conflict was resolved. It still reads no content, name, size other
  than the object's, or number of files, and cannot tell a file from any
  other chain of objects. [overview.md](overview.md), section 4.4,
  lists this as an accepted leak.
- **A writer's power.** A writer can supersede any listing of its
  stream, and so have an object collected after the retention. It can
  remove the handle at once, which collects the object at the next
  compaction; this is the same power, bounded by the retention instead
  of by compaction. It cannot supersede a listing in a stream it cannot
  write, nor one of another space.
- **A removed writer racing.** Its supersessions wait for stability at
  the peer or T (step 4), as its snapshots do, and a client puts what it
  supersedes again (section 3.10).
- **A lying compactor** can list supersessions its cover does not
  support. Replicas that hold the cover report `BadCompaction` and
  restore, which cancels the collection of the cover, and put the
  objects again. It can also omit them, which keeps old versions longer:
  the safe direction.
- **The same bytes twice.** Supersessions name listings, not objects,
  so a version of one file that is the current version of another, or a
  version put again, is a head. A peer that collected by object would
  delete a current file. The cost is section 3.1's: a superseded entry
  whose object another current entry names unsuperseded is not carried
  by compaction, and its object stays a head until a writer removes the
  handle.
- **Peers disagree only in time.** No replica reads what a peer
  collected; a reader that finds a version at no party shows it as
  unavailable, as it would any object a release reclaimed.
- **Cycles.** A version restored from a device's copy supersedes the
  version it replaces and is itself superseded by an older supersession:
  a cycle of objects. Listings break it: the restored version's new
  listing is a head, and the depth of the others counts from it.

## 5. Test vectors

[ext-file-versions.json](vectors/ext-file-versions.json):

- `parameters`: section 2.2's settings, their defaults and ranges, the
  limit on supersessions, and the error class.
- `writer`: a Blobs stream of two writers with versions of one file, a
  second file holding the first's oldest bytes, and a third file whose
  handle a writer removed; for each put, the parents' stamps and the
  unit's `objects` and `supersedes` byte for byte: a plain save, a save
  from a stale copy, a resolution naming two heads with merged bytes,
  concurrent saves, a pick that puts one head's bytes again, and a save
  whose parent's handle was removed, which supersedes nothing.
- `replica_checks`: a log unit whose successor no put names, and a
  snapshot unit whose predecessor is not current (`BadSupersession`,
  with the content applied all the same).
- `supersession_set`: the units applied in several orders to one set,
  and which entries are superseded; the same after a successor's handle
  is removed.
- `compaction`: the snapshot unit's `objects`, `supersedes` and
  superseded entries over the `writer` stream, which carry the chain of
  the first file's versions and leave out three objects: the one the
  second file's entry holds unsuperseded, the pick's, which the pick's
  entry holds unsuperseded, and the removed handle's, which is not
  current; the state bytes, equal to
  [adapter-blobs.md](adapter-blobs.md)'s; and a second compaction over a
  cover that starts from the first: `load`'s mapping, a save from the
  pick, and the second snapshot unit's `supersedes`, which still leaves
  out the pick's bytes: the first compaction did not carry their old
  handle's supersession, so that entry holds them unsuperseded.
- `compaction_checks`: a snapshot unit whose `supersedes` matches the
  replica's derivation; one that lists a pair the cover does not support
  and one that omits a pair (`BadCompaction`); and one without key 8,
  which passes and loads nothing.
- `listings`: the peer's superseded listings given stored units: a
  supersession naming a listing it does not hold, one of another stream,
  one whose predecessor the named unit does not list, one in a released
  stream, and one in a unit held as fork evidence, each without effect;
  and `since` for a listing superseded twice.
- `after_compaction`: `since` of a snapshot unit's listing inherited
  from its cover, and set to the snapshot's first sight when a listing
  of the cover was not superseded.
- `heads_and_depth`: a chain of seven versions; two heads from one
  parent and their resolution; a version restored from a copy, which
  makes a cycle; the same bytes as a version of one file and the current
  version of another; and a cycle without a head, with a depth of none.
- `decisions`: `retain` at and around `file_version_retention`,
  `max_file_versions` and T, with a live hold, with a superseding unit
  not yet stable, and for an object with no listing.
- `holds`: a hold on an old version of a file that ends with the
  holding space's retention, and one on a current version that does not.
- `cadence`: section 3.11 at and around `version_compaction_interval`,
  and with no supersession since the last snapshot.
