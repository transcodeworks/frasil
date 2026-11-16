# The Loro adapter
Protocol 1. Vectors: [adapter-loro.json](vectors/adapter-loro.json).

This document specifies the adapter of type `frasil:loro`, for rich
documents held in a Loro document: the pinned Loro version, the framing of
Loro's bytes, peer IDs bound to writers, the checks, merge and rebuild,
suggestions, and the snapshot state. It implements the adapter interface of
[units.md](units.md), section 3.17, and depends on
[overview.md](overview.md), [crypto.md](crypto.md) for its label, and
[roster.md](roster.md) for capabilities.

It extends [units.md](units.md) only. A core implementation without it keeps
every unit of type `frasil:loro` and ignores its content
(`UnknownAdapter`); it neither compacts such a stream nor checks or uses its
stream snapshots.

## 1. Overview

- Loro names every operation by a **peer ID** and a counter, and treats one
  name as one operation. Each peer ID is bound to one writer, stream and
  **incarnation**, so no writer writes under another's name, and every
  replica refuses a writer's reuse of its own counters alike.
- A unit carries Loro's bytes for the writer's new operations; the checks
  read only their metadata. Loro's import is order-independent and
  idempotent, so a rebuild is a replay, and leaving a unit out undoes it.
- **Suggestions** are operations kept apart from the main document until a
  writer that is not a suggester accepts or dismisses them.

## 2. Formats

### 2.1 The pinned version

The adapter pins **Loro 1.17.0**: the Rust crate `loro` at version 1.17.0,
and the JavaScript package `loro-crdt` built from the same release. Its
binary encoding is what that release's `LoroDoc::export` produces and
`LoroDoc::import` reads, with the metadata `decode_import_blob_meta`
returns. Moving the pin is a change of this document; a release whose
encoding differs either way is a new content version (key 1).

### 2.2 Unit content

A log unit's content is a deterministic CBOR map:

| Key | Name | Value | Roles |
|---|---|---|---|
| 1 | `version` | 1 | all |
| 2 | `role` | 0 edit, 1 suggestion, 2 accept, 3 dismiss | all |
| 3 | `incarnation` | unsigned, at least 1 | 0 and 1 |
| 4 | `blob` | bytes: `LoroDoc::export(ExportMode::UpdatesInRange { spans })` of exactly the writer's operations this unit adds | 0 and 1 |
| 5 | `targets` | array of 1 to 64 event IDs, strictly ascending: the suggestions accepted or dismissed | 2 and 3 |

A map holds exactly the keys of its role. A snapshot unit's content is
empty.

### 2.3 Peer IDs

```text
peer(space, stream, author, s) =
    (SHA-256("frasil/loro-peer/v1" || space || stream || author || u64be(s))[0..8]
     read as a big-endian unsigned integer) mod (2^64 − 1)
```

`space` is the space ID, `stream` the stream ID, `author` the writer's
device ID ([events.md](events.md)), and `s` the unit's incarnation. The
reduction keeps the peer ID below 2^64 − 1, which Loro reserves.

### 2.4 The snapshot state

The `state` of a stream snapshot object ([units.md](units.md), section 2.9)
is a deterministic CBOR map:

| Key | Name | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `main` | bytes: `LoroDoc::export(ExportMode::Snapshot)` of the main document; when history-free, `ExportMode::ShallowSnapshot` at its current frontiers |
| 3 | `suggestions` | optional: array of `[unit ID, author, incarnation, blob]`, strictly ascending by unit ID: the open suggestions |
| 4 | `dismissed` | optional: as key 3, for the dismissed suggestions; never in a history-free state |

## 3. Procedures

### 3.1 Writing

- An **edit incarnation** begins at an edit whose incarnation is its own
  `seq`, and continues in the writer's later edits of the stream with the
  same incarnation and counters that follow on.
- A device that may have lost its own operations in the stream, such as a
  restored device that cannot fetch them, MUST begin a new incarnation, and
  MUST NOT continue one it may have lost.
- A suggestion's incarnation is its own `seq`, so each suggestion has a peer
  of its own and can be accepted alone.
- A writer sets the document's peer ID (`LoroDoc::set_peer_id`) to its
  current incarnation's peer before it commits operations.
- A writer commits before it exports, so a unit's blob ends where a
  commit ends, unless the writer divides its operations as the next point
  says.
- A writer runs step 4 on each blob before it signs the unit. When its
  operations break a limit, it writes them in more than one unit, one
  after another, each ending where one of Loro's changes ends
  (`LoroDoc::get_change`) and passing step 4; Loro stores a large commit
  as several changes of a few kilobytes, so such a unit may hold part of
  a commit. Operations that no such division passes, as a change that
  alone breaks a limit, or a suggestion, which is one unit, are not
  written, and the application learns why.
- A compactor runs the checks of section 3.5, "Loading a state", on the
  state it would write. A state they refuse is not written: the stream
  goes on growing by units, and the compactor reports it.

### 3.2 The checks

On a unit of type `frasil:loro`, after [units.md](units.md)'s checks, in
order:

```text
1. The content is deterministic CBOR, a map with an
   unsigned key 1, or is empty in a snapshot unit.       else Malformed
   Key 1 is 1.                                           else UnknownContentVersion
   The keys of its role, as section 2.2.                 else Malformed
2. The suggest check (section 3.4) and any registered
   capability checks.                                    else CapabilityRefused
3. Roles 0 and 1: incarnation <= the unit's seq; a
   suggestion's equals it.                               else LoroIncarnation
4. Roles 0 and 1: decode_import_blob_meta(blob), with the
   checksum checked, reads the blob, within the limits
   below, and its mode is updates, not a snapshot.       else LoroMalformed
5. Roles 0 and 1: the blob advances exactly one peer,
   peer(space, stream, author, incarnation).             else LoroForeignPeer
6. Roles 0 and 1: its counter span for that peer
   overlaps no span of the same peer in a Loro unit
   earlier in canonical order, handed over or handed
   back from the base snapshot's cover, and starts at
   or above the counter the base snapshot holds for it.  else LoroOverlap
7. Roles 2 and 3: every target is held, as a unit, as
   a unit of the base snapshot's cover, or in the base
   snapshot's key 3 or 4.                                else TargetNotHeld
```

- Step 4 reads the blob as the pinned release's build without debug
  assertions does. It also refuses a blob that Loro reads but that is laid
  out as no writer's export is, or that holds more than a unit can carry.
  In each change block of the blob (Loro's `EncodedBlock`):
  - nothing follows the Lamport timestamps in its change header, and no
    delta-of-delta column (dependency counters, Lamport timestamps, wall
    clock timestamps) sums past a signed 64-bit integer as it is read;
  - the columns of its tree positions table hold equally many entries, and
    so do those of its deletion starts table;
  - no deletion start has length 0;
  - each operation on a text whose value is `Null`, the end of a style,
    directly follows an operation of length 1 on the same text whose value
    is `MarkStart`, the style's start, and each such start is directly
    followed by its end; where a start ends a block, its end begins the
    next block of the same peer, whose counters continue the start's;
  - each style's start covers at least one position, and its end, its
    position plus its length, each read as Loro reads them, as unsigned
    32-bit integers, is below 2^32.

  In the blob's blocks together, the operations tables hold at most 2^20
  rows, the tree positions tables at most 2^20, and the deletion starts
  tables at most 2^20; and the tree positions decode to at most 2^24
  bytes.
- Loro's export ends a change header with its Lamport timestamps, refuses
  to write a delta-of-delta column whose sums overflow, writes
  each table's columns from one list of rows, writes no deletion of
  nothing, and writes a style over at least one position, its start
  and end as two consecutive operations of one commit, which it may store
  in two changes; a writer that divides its operations into units keeps
  only units that pass step 4 (section 3.1), so none it writes ends
  between a start and its end, and the next begins after both. 2^20
  is one row per byte of the largest unit ([units.md](units.md), section 2.1),
  and 2^24 sixteen bytes of position per byte. The pinned Loro expands each
  column of the tree positions and deletion starts tables before it pairs
  their entries, builds each tree position from the one before it, keeps a
  record of every operation it decodes, and panics on import at a style's
  end whose start it does not hold (section 4).
- Steps 4 to 6 read the blob's start and end version vectors. A peer is
  advanced when its end counter exceeds its start counter; its span is
  `[start, end)`.
- Step 6 orders units by canonical order, height then event ID, from each
  unit's context.
- Step 6 counts every earlier Loro unit whose content passes steps 1 and 3
  to 5, whatever step 2 and the write rule decide on it, but the units this
  unit re-submits: the unit its `resubmits` names ([units.md](units.md),
  "Re-submission"), and the one that unit's `resubmits` names, and so on,
  each counted out only where its content is byte for byte this unit's. A
  re-submission repeats the same operations under the same peer, which
  importing twice leaves unchanged (section 3.3), so a late or refused
  edit re-sent after a checkpoint or a re-grant is accepted whether or not
  the replica holds the original, at a replica that forgot it and at one
  that holds both alike. Text a writer wrote again under a new incarnation
  is another peer's, which this exemption does not reach, and which
  importing beside the original would apply twice; the writer therefore
  re-submits no unit of an incarnation it expressed again
  ([units.md](units.md), "Re-submission").
  Of two other units of one peer whose spans overlap, the later in
  canonical order is refused, wherever each arrived first; a replica that
  applied it rebuilds. Step 4 still reads each unit's blob on its own, so
  the screen sees every operation of each unit; a re-submission's are
  those of the unit it names, already screened.
- A unit the base snapshot's cover holds but its state excludes counts at
  step 6 only where the replica holds it and hands it back
  ([units.md](units.md), section 3.6). A replica that does not hold it MAY
  accept the content of a later overlapping unit that a replica holding it
  refuses as `LoroOverlap`.
- A gap between spans is not refused: Loro holds the later operations
  pending until the gap fills.
- A unit held at step 7 is checked again when a target arrives.

### 3.3 Merge and rebuild

- **Apply** imports an edit's blob into the main document with
  `LoroDoc::import`, puts a suggestion in the suggestion layer, and, for an
  accept, imports its targets' blobs into the main document (section 3.4).
  Importing an operation twice changes nothing.
- **Rebuild** creates an empty `LoroDoc`, imports the settled snapshot's
  `main`, restores the suggestion layer from keys 3 and 4, then applies the
  accepted units after the cover.
- An accepted operation that depends on an operation of a refused unit, such
  as text typed after a removed member's insertion, cannot be placed and
  stays pending inside Loro. The replica reports such units
  (`LoroDependsOnRefused`); their writers may write the change again.

### 3.4 Suggestions

- The **suggestion layer** holds the stream's suggestion units whose
  content is accepted ([units.md](units.md), section 3.17). Their operations
  enter the main document only through an accept. An application shows one
  on a fork of the main document (`LoroDoc::fork`) with it imported.
- A suggestion is **open** while no applied accept or dismiss names it,
  **dismissed** while only dismisses name it, and part of the main document
  once an accept names it, whatever the order in which they arrive or were
  written.
- **Accept** imports each target's blob into the main document as it is,
  under the suggester's peer. A target that is not in the layer is ignored.
- **The `suggest` check.** A writer narrowed by `suggest` writes only role
  1, and no snapshot unit, a seed included. Anything else from it is
  `CapabilityRefused`.

### 3.5 Compaction and history-free export

- **Compaction** exports the main document with its history, so that units
  concurrent with the cut still merge, and keeps open and dismissed
  suggestions, so that an accept concurrent with a compacted dismiss imports
  the suggestion at every replica.
- **History-free export** is a shallow snapshot at the current frontiers,
  with no suggestion, since suggestions depend on the history it drops.
  An export that the checks of "Loading a state" below refuse is refused
  ([units.md](units.md), section 3.17, item 5), as a compactor writes no
  such state. A
  replica that started from one and meets an accept of a suggestion it does
  not hold asks for a fresh export ([units.md](units.md), section 3.8).
- **Checking a snapshot** ([units.md](units.md), section 3.6): a replica that
  holds the cover rebuilds from the units the snapshot includes. The
  snapshot matches when both main documents have the same version vector
  (`LoroDoc::oplog_vv`) and value (`LoroDoc::get_deep_value`), and both
  layers hold the same suggestions.
- **Loading a state.** A state is at most 2^28 bytes. Its `main` is read
  as the pinned release's build without debug assertions reads it, before
  Loro reads it, and is refused when Loro would not read it, or when it is
  laid out as no export of the pinned Loro is, or breaks a limit:
  - the envelope's mode is a snapshot, and its body is exactly three
    sections, each a little-endian u32 length and that many bytes: the
    change store, the state store (or `E`, none), and the shallow root's
    state store, each empty or a key-value table (`loro-kv-store`'s
    SSTable);
  - each table is laid out as the pinned Loro writes one: its magic,
    version 0, and a block index of at most as many blocks as its bytes
    hold, ending in its checksum, whose blocks lie in order inside the
    table; each block is stored as it is or as one LZ4 frame of
    independent blocks with no checksum, content size or dictionary, and
    nothing after its end mark; each block reads as the pinned Loro reads
    it, its keys strictly ascending, non-empty, and matching the index,
    and no value empty;
  - the blocks of all three tables decompress to at most 2^28 bytes in
    all, and to at most 256 times the length of `main`;
  - the change store holds only the keys `vv`, `sv` (version vectors),
    `fr`, `sf` (frontiers), each read to its end, and 12-byte change block
    IDs; each change block is named by its first peer and first counter,
    lies past the end of the block of the same peer before it, and passes
    step 4 of section 3.2 as a blob of that one block would, its limits
    included; a style's start and end follow each other across the blocks
    of a peer as section 3.2 says, except that the first block of a peer
    may begin with a style's end whose ID is one of the shallow root's
    frontiers (`sf`);
  - in the change store together, the operations tables hold at most
    2^20 rows or one per byte of `main`, whichever is more, and so do the
    tree positions and the deletion starts tables; the tree positions
    decode to at most 2^24 bytes or sixteen per byte of `main`, whichever
    is more;
  - each state store holds only the key `fr` (frontiers) and container
    IDs; each container's state begins with its type, the key's type, its
    depth and its parent, as Loro writes them, and a text's begins its
    value with its text, in UTF-8;
  - past its value, a text's, a list's and a movable list's state, and a
    tree's, holds its peer table, as many 8-byte peer IDs as its LEB128
    count says, then its columnar tables as the pinned Loro writes them:
    a text's spans (a field count of 3, then 4 columns); a list's IDs (1
    field of 3 columns); a movable list's items, list item IDs, element
    IDs and last set IDs (4 fields of 3, 3, 2 and 2 columns); a tree's
    node IDs and nodes (4 fields: 2 columns, 5 columns, then its
    fractional indexes and one more byte string). A list's and a movable
    list's value is read to its end as Loro reads it to find the peer
    table. Each run-length column is read run by run, and is not
    expanded: a run's count is at most 10^9, and a column ends with its
    bytes. A tree's fractional indexes are tree positions, read as step 4
    of section 3.2 reads them;
  - in the state stores together, the tables' rows, each table's rows
    being the entries of its longest column, are at most 2^20 or one per
    byte of `main`, whichever is more, and so are the trees' fractional
    indexes, which decode to at most 2^24 bytes or sixteen per byte of
    `main`, whichever is more.

  The pinned Loro reads the state store lazily, a container at a time:
  its value when the container is first read, and its tables when the
  container is first changed or its state first asked for. It panics
  where it finds a container's state that does not decode. An
  implementation that can catch a panic reads every container's value and
  every container's state of the state store as it loads the state, so
  that such a panic refuses the state.
- A history-free export keeps the operation at each of its frontiers and
  drops the history before it, so a peer whose last operation was a
  style's end keeps that end alone, its start in the shallow root's state.
  The pinned Loro builds the state at those frontiers from the shallow
  root's state store and applies none of the operations at them, so it
  never applies such an end; every other end without its start is
  refused.
- 2^28 bytes is what a replica holds whole and decodes, a browser
  included. An LZ4 frame expands up to about 255 times its bytes, and the
  pinned Loro decompresses a block before it checks its length and panics
  on a block it cannot read once it has accepted the table. Each per-store
  limit is the limit of section 3.2 for one unit, or as many rows per byte
  as section 3.2 allows a unit, whichever is more; the pinned Loro splits
  changes into blocks of a few kilobytes as it stores them. Every other rule
  refuses only layouts that no export of the pinned Loro writes.
- A state that does not decode, or whose `main` the pinned Loro does not
  import, or that the checks above refuse, is `Malformed`: the replica
  reports `BadCompaction` and never uses it. A compactor writes no state
  that they refuse (section 3.1), so a state over a limit is a writer's
  error, and the restore it leads to (units.md, section 3.6) keeps the
  units of its cover.

### 3.6 Re-applying a late write

Only [ext-restricted-spaces.md](ext-restricted-spaces.md) calls `reapply`.
The re-applier imports the late write into a fork of the original document,
takes `LoroDoc::diff` of the fork against the original at the late write's
dependencies, and applies it (`apply_diff`) to the moved document under a
new incarnation that begins at the re-applier's unit, whose incarnation is
that unit's `seq`. The result is the re-applier's own edit.

### 3.7 Error classes

Each class here concerns content only; the unit's verdict stands.

| Class | Meaning | Sort |
|---|---|---|
| `LoroIncarnation` | an incarnation above the unit's `seq`, or a suggestion's other than its `seq` | report: content refused |
| `LoroMalformed` | a blob the pinned Loro does not read, or a snapshot blob | report: content refused |
| `LoroForeignPeer` | a blob that advances another peer, or more than one | report: content refused |
| `LoroOverlap` | counters that an earlier unit or the base snapshot already holds | report: content refused |
| `TargetNotHeld` | an accept or dismiss naming a target not yet held | pending: its content waits; the unit's verdict stands |
| `LoroDependsOnRefused` | an accepted unit whose operations wait on a refused unit's | report |

It also uses `Malformed`, `UnknownContentVersion`,
`CapabilityRefused` and `BadCompaction` as [overview.md](overview.md) and
[units.md](units.md) define them.

## 4. Security considerations

- **Bound peer IDs** make a Loro document safe to share with writers who may
  lie. Without them, a writer could write under another's peer ID, and each
  replica would keep whichever copy arrived first.
- **A suggester** holds the keys and the upload key, and a peer cannot tell
  its units from a full writer's. Only the `suggest` check keeps its
  operations out of the main document, at every replica. It refuses the
  suggester's snapshot units too, so a suggester cannot compact a stream
  into a state of its own; replicas that find such a snapshot unit cancel
  its collection with a restore ([units.md](units.md), section 3.6). Its
  suggestions are visible to every member.
- **Strict removal** costs content built on refused content: it stays
  pending after a rebuild, and the application shows what was left out.
- **A lied stub height** changes canonical order among units, and so which
  of two overlapping units of one writer is refused. It changes nothing
  beyond that writer's own operations.
- **Decoding a blob costs its readers.** Loro's columns are run-length
  encoded: a run of a billion entries takes a few bytes, and some
  operations take none of their own. Any writer or suggester can send a
  blob, and every replica decodes it. Step 4's limits keep what decoding
  takes within a fixed multiple of the largest unit, and its layout rules
  keep the pinned Loro's known panics on import out of reach where a panic
  cannot be caught, as in a browser. An implementation applies them before
  Loro reads the blob, since the pinned decoder reserves memory before it
  checks what it reads.
- **Decoding a snapshot state costs every replica that loads it.** Any
  writer that compacts can write one, and a state is an object that may be
  far larger than a unit. Section 3.5's limits keep a state's `main` within
  what a replica holds, keep its decompression within a fixed multiple of
  its bytes, and keep what its change store and its container states'
  tables decode to within a fixed multiple of its bytes, as for units.
  A container state's tables are read only as far as their rows, the
  runs of their columns and a tree's fractional indexes: a map's and a
  counter's state, and the rest of each table, are left to Loro, which
  checks them as it decodes and builds nothing past what the rows
  allow. Where panics unwind, reading every container's value and state
  at load turns Loro's panics on them into a refused state; where a panic
  aborts, one the screen does not foresee still aborts.

## 5. Test vectors

[adapter-loro.json](vectors/adapter-loro.json). Blobs are opaque
stand-ins, and each check takes the blob's start and end counters as input;
an implementation adds Loro round trips of its own.

- `parameters`: the pinned version, and the space and stream used.
- `peer_ids`: three peers, with the digest, its first 8 bytes as an
  integer, and the reduction.
- `contents`: one content of each role, byte for byte.
- `checks`: seventeen runs of section 3.2 with their verdicts: an edit that
  continues its incarnation; a gap; an overlap with an earlier unit and with
  the base snapshot; another writer's peer; two peers; a snapshot blob; an
  unreadable blob; an incarnation after its `seq`; a suggestion at and not
  at its own `seq`; a suggester's edit; an accept of a suggestion not held;
  an accept and a dismiss; a suggester's accept and dismiss.
- `content_refusals`: five contents refused at step 1, with their classes.
- `snapshot_state`: a state with an open suggestion, and a compacted state
  with a dismissed one.
- `compaction_checks`: the `suggest` check on a snapshot unit from a full
  writer, from a suggester (`CapabilityRefused`), and from a writer granted
  `suggest` with mode `extends`.
