# The Records adapter
Protocol 1. Vectors: [adapter-records.json](vectors/adapter-records.json).

This document specifies the adapter of type `frasil:records`, for synced
tables: changesets, the logical clock and its admission, the merge of each
cell by its stamp, row existence, suggestions, and the stream snapshot's
state, fixed byte for byte. It implements the adapter interface of
[units.md](units.md), section 3.17, and depends on
[overview.md](overview.md) for conventions and [roster.md](roster.md) for
capabilities. [adapter-blobs.md](adapter-blobs.md) uses its clock and
stamps.

It extends [units.md](units.md) only. A core implementation without it keeps
every unit of type `frasil:records` and ignores its content
(`UnknownAdapter`); it neither compacts such a stream nor checks or uses its
stream snapshots.

## 1. Overview

- A Records stream holds a small database: **tables** of **rows**, each row
  a set of **columns**. A **cell** is one column of one row of one table. A
  transaction is one **changeset**, the content of one unit.
- Each cell keeps the value of the changeset with the greatest **stamp**:
  a logical clock, then the writer, then the event ID. No wall clock is
  read.
- A changeset's clock is **admitted** only when the changesets that exist
  support it, so no writer can freeze a cell by claiming a huge clock.
- Records merges cells. It runs no constraint, aggregate or uniqueness
  check; those are the application's.

## 2. Formats

### 2.1 The data model

| What | Form |
|---|---|
| A table | text of 1 to 255 bytes |
| A row's key | bytes, 1 to 1,024 |
| A column | text of 0 to 255 bytes. The empty column is the row's **marker** |
| A value | `[]`, cleared, or `[v]`: an array of one CBOR item of the **records subset**, nesting at most 8 levels |

- The **records subset** is the deterministic subset of
  [overview.md](overview.md), section 5.3, with three more kinds of item:
  negative integers (major type 1, -1 to -2^64, shortest head); the simple
  values `false` (`0xf4`) and `true` (`0xf5`); and IEEE 754 binary64
  floats, `0xfb` then 8 bytes, never a NaN. A float always takes 8 bytes,
  whatever its value, so each value has one encoding, and `0.0` and `-0.0`
  are two values. No other simple value, no shorter float, no tag. A
  changeset and a snapshot state are decoded in the records subset; an item
  of the wider subset anywhere but inside a value fails that place's shape,
  as `Malformed`. Integers, floats and booleans are distinct: `1` and `1.0`
  are two values.
- A row exists while its marker's value is `[1]`.
- A value's item `v` is at level 0, and each item inside it is one level
  deeper than the array or map that holds it, as in
  [overview.md](overview.md), section 5.3. A changeset whose `v` nests
  deeper than 8 is `Malformed`. `v` sits at depth 4 of a changeset and at
  depth 8 of a snapshot state (section 2.3), so every state fits the
  decoders' limit of 16.

### 2.2 Changesets

A log unit's content is a deterministic CBOR map:

| Key | Name | Value | When |
|---|---|---|---|
| 1 | `version` | 1 | always |
| 2 | `clock` | unsigned, at least 1 | always |
| 3 | `ops` | array of 1 to 65,536 ops | always |
| 4 | `suggestion` | 1 | a suggestion |
| 5 | `accepts` | array of 1 to 64 event IDs, strictly ascending | optional |
| 6 | `dismisses` | array of 1 to 64 event IDs, strictly ascending | optional |
| 7 | `time` | unsigned: seconds since 1970-01-01T00:00:00Z on the writer's wall clock when it wrote | optional |

```text
op = [table (text), key (bytes), column (text), value]
```

- No two ops of one changeset name the same cell.
- `time` is the writer's claim. No replica checks it, and it never decides
  anything: the stamp alone orders writes. A writer whose wall clock is
  unknown leaves it out. Applications show it, as when another member last
  changed a row, and say that it is the writer's own.
- A marker's value is `[1]` or `[]`.
- Keys 5 and 6 never appear with key 4.
- A snapshot unit's content is empty.

### 2.3 The snapshot state

The `state` of a stream snapshot object ([units.md](units.md), section 2.9)
is a deterministic CBOR map:

| Key | Name | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `max_clock` | unsigned: the floor over the cover (section 3.1) |
| 3 | `tables` | array of `[table, rows]`, strictly ascending by table |
| 4 | `suggestions` | optional: array of `[event ID, author, changeset content]`, strictly ascending by event ID: the open suggestions |

```text
rows  = array of [key, cells], strictly ascending by key
cells = array of [column, value, clock, author, event ID] or
                 [column, value, clock, author, event ID, time], strictly ascending by column
```

- Text and bytes are ordered byte by byte, a prefix first.
- A cell appears once it has been written, cleared or not, so that a later
  write compares with its stamp.
- A cell carries `time` exactly when the changeset its stamp names carried
  one, with that changeset's key 7, so a replica that starts from a
  snapshot shows the same times as one that holds every unit.
- A row's **last change** is its cell with the greatest stamp, the marker
  included: its author and event ID name who changed the row last and in
  which changeset, and its `time`, when present, when that writer says it
  did.
- A **history-free** state is the same map without key 4. Its stamps are
  the current state's, which later changesets must compare with: a member
  admitted from now on learns which device last wrote each cell, and its
  clock, and nothing about earlier values.
- `tables` is empty when no cell has been written. `rows` and `cells` are
  never empty, and key 4 is absent when no suggestion is open, so each state
  has one encoding.
- The bytes are a function of the state, so two implementations produce one
  snapshot from one cover.
- **`load`** refuses as `Malformed` a state that breaks this section: a key
  missing or not among 1 to 4; `version` not 1; an order not strictly
  ascending; an empty `rows`, `cells` or key 4; a table, key, column or
  value that breaks section 2.1, or a marker's value other than `[1]` or
  `[]`; a stamp that is not an unsigned clock, a 32-byte author and a
  32-byte event ID; a cell of other than 5 or 6 items, or a `time` that is
  not unsigned; or a suggestion whose content is not a changeset of
  section 2.2 with key 4.

## 3. Procedures

### 3.1 The logical clock

Changesets that **count** are those of the stream's placed units whose
content passes steps 1 to 3 of section 3.2, whatever the write rule's
verdict, so that the clock never depends on verdicts.

```text
admit(counted changesets H, base max_clock b):
  A = {}; floor = b
  repeat until nothing changes:
    add to A every c in H with clock(c) <= floor + 1
    floor = max(b, the clocks of A)
  return A, floor
```

- The admitted set is a least fixed point, so it depends on the changesets
  held, never on their order. `b` is the base snapshot's `max_clock`, or 0.
- A changeset not admitted waits (`ClockAhead`), and is admitted when the
  changesets below it arrive. An honest writer's changeset always is: what
  its clock rests on is in its causal past, which a replica that places it
  holds or holds a base of.
- **A writer's clock.** A writer MUST set `clock` to its own floor plus one,
  over the changesets it holds and its base. A changeset held but not
  admitted does not count: counting one would put the writer's own
  changeset ahead too. A changeset is therefore later than every admitted
  changeset in its past.
- A writer raises the clock by at most one per changeset that exists.

### 3.2 The checks

On a unit of type `frasil:records`, after [units.md](units.md)'s checks, in
order:

```text
1. The content is deterministic CBOR, a map with an unsigned
   key 1, or is empty in a snapshot unit.                      else Malformed
   Key 1 is 1.                                                 else UnknownContentVersion
2. Keys among 1 to 7, keys 1 to 3 present, as section 2.2;
   key 7, when present, unsigned.
   Each op: a table, key, column and value of section 2.1,
   the value nesting at most 8 levels; a marker's value [1]
   or []; no cell twice.                                       else Malformed
3. Keys 5 and 6 never with key 4.                              else Malformed
4. The suggest check (section 3.4) and any registered
   capability checks.                                          else CapabilityRefused
5. The changeset is admitted (section 3.1).                    else ClockAhead
```

A changeset held at step 5 is checked again whenever another is admitted.

### 3.3 Merge and rebuild

```text
stamp = (clock, author, event ID)     compared in that order; author and ID byte by byte
```

- **Apply** sets each cell of the changeset's ops whose stamp is greater
  than the cell's own, or that has none. Only admitted changesets of
  accepted units are applied. This is commutative and idempotent.
- The event ID breaks the one remaining tie, two changesets of one writer at
  one clock, which only a writer that forked or lost its own changesets
  makes.
- **Rows.** Inserting a row writes its marker `[1]` and its columns in one
  changeset; deleting it writes its marker `[]`. Its other cells stay, so a
  later insertion shows them again unless it writes them.
- **Rebuild** loads the settled snapshot and applies the accepted, admitted
  changesets after its cover.

### 3.4 Suggestions

- A changeset with key 4 is a **suggestion**. It goes to the stream's
  **suggestion layer** by its event ID, and never to the tables. It counts
  for the clock as any changeset.
- A changeset of a writer that is not a suggester may **accept** suggestions
  (key 5) or **dismiss** them (key 6). An accept is recorded for display;
  the accepting writer writes the ops it adopts in its own changeset, under
  its own clock. A suggestion that an applied accept or dismiss names leaves
  the layer, or never enters it, whatever the order of arrival.
- A writer MUST name only suggestions in its changeset's stream past.
- **The `suggest` check.** A writer narrowed by `suggest` writes only
  changesets with key 4 and without keys 5 and 6, and no snapshot unit, a
  seed included. Anything else from it is `CapabilityRefused`.

### 3.5 Compaction

- A compactor admits over its base and the cover alone, applies the
  accepted, admitted changesets of the cover, and lists every other unit of
  the cover in `excluded` ([units.md](units.md), section 3.5). `max_clock`
  is the floor of that admission.
- **Checking a snapshot** ([units.md](units.md), section 3.6) compares its
  state's bytes with those of the replica's own rebuild.
- A state that does not decode as section 2.3 is `Malformed`: the replica
  reports `BadCompaction` and never uses it.

### 3.6 Re-applying a late write

Only [ext-restricted-spaces.md](ext-restricted-spaces.md) calls `reapply`.
The re-applier writes the late write's ops again in a changeset of its own
in the moved document, under its own clock.

- The new changeset drops keys 5 and 6: they name suggestions of the
  original stream. A late accept or dismiss is re-applied as its ops alone,
  and closes no suggestion in the moved document.
- A late suggestion is not re-applied: `reapply` returns nothing for it.

### 3.7 Error classes

| Class | Meaning | Sort |
|---|---|---|
| `ClockAhead` | a changeset whose clock the counted changesets do not yet support | pending: its content waits; the unit's verdict stands |

It also uses `Malformed`, `UnknownContentVersion`, `CapabilityRefused` and
`BadCompaction` as [overview.md](overview.md) and [units.md](units.md)
define them; each refuses content only.

## 4. Security considerations

- **A wall clock** would let any writer win every conflict by setting its
  clock ahead. The logical clock follows causality, and admission stops a
  writer from claiming a clock that no existing changeset supports.
- **A writer's own cells.** Any writer can overwrite any cell, within its
  capabilities. An application that needs "only you edit your entries"
  gives each person a space of its own, or registers a capability check.
- **A target outside the stream past.** A writer that names a suggestion it
  never saw can leave the layer differently at replicas that start from a
  snapshot and replicas that hold every unit. It changes no table.
- **`time` is untrusted.** A writer can claim any time, past or future, and
  a member that holds its keys can sign a changeset with any time. It
  orders nothing and gates nothing; an application that shows it shows the
  writer's word, never a time any replica vouches for.
- **A suggester** can neither write to the tables nor compact; see
  [adapter-loro.md](adapter-loro.md), section 4.

## 5. Test vectors

[adapter-records.json](vectors/adapter-records.json):

- `parameters`: the four writer devices and the space the vectors use.
- `changesets`: eight changesets of four writers byte for byte, with their
  event IDs: a row inserted, a tie at one clock broken by writer, a row
  deleted and inserted again, a clock ahead of the floor, a suggestion and
  its accept, and a changeset of a device whose removal is learned late.
- `admission`: the admitted set, the floor, and the changeset that waits
  (`ClockAhead`).
- `writer_clock`: the next clock a writer sets over admitted changesets
  only: 5, not the 10 that the waiting clock of 9 would give.
- `merge_orders`: the changesets applied in three orders to one snapshot,
  with the visible rows.
- `rebuilds`: the snapshot with the late-removed device's changeset applied
  and without it; a rebuild from a snapshot of the first three changesets
  that gives the same snapshot as the full set.
- `history_free`: the export of the final state.
- `suggestions`: a suggester's suggestion that passes the check, and the
  open layer when the accept is left out.
- `content_refusals`: nine contents with their classes, among them a cell
  twice, a marker of `[2]`, clock 0, accepts in a suggestion, an unknown
  version, and a suggester's plain changeset and accept.
- `compaction_checks`: the `suggest` check on a snapshot unit from a full
  writer, from a suggester (`CapabilityRefused`), and from a writer granted
  `suggest` with mode `extends`.
- `value_nesting`: a changeset whose value nests 8 levels, accepted, with
  its event ID and the snapshot state it yields alone, which nests 16 deep
  and loads; and one whose value nests 9 levels (`Malformed`).
- `change_times`: three changesets, two with `time`, one without; each
  cell's time and the changeset that wrote it, the row's last change and
  the state they yield; a time in text and a negative time
  (`Malformed`), and a state whose cell has seven items (`Malformed`).
- `value_types`: one changeset with an integer, -1, -2^63, -2^64, `false`,
  `true`, 1.5, -0.0, infinity and a list of mixed types, accepted, with its
  event ID and the snapshot state it yields; eight values outside the
  records subset (a NaN, a half and a single float, `null`, `undefined`,
  simple value 16, a head that is not the shortest, a tag) and a negative
  clock, each `Malformed`.
