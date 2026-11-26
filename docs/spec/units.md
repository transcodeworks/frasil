# Units
Protocol 1. Vectors: [units.json](vectors/units.json).

This document specifies how application data travels in a space: units,
streams, objects, compaction and the stubs it leaves, the space snapshot a
newcomer starts from, Frasil's own units, heads, acknowledgements and head
statements, the baseline sync messages, partial replicas, and the interface
an adapter implements. It depends on [overview.md](overview.md) for
conventions and time, [crypto.md](crypto.md) for primitives and schemes,
[events.md](events.md) for the envelope, placement and chains,
[roster.md](roster.md) for the write rule and stability, and
[keys.md](keys.md) for states, key references and per-state keys.
[peers.md](peers.md) says what an always-on peer stores, collects and
serves; [transport.md](transport.md) carries this document's sync
messages (section 2.14).

## 1. Overview

- A **unit** is an event of kind 4. Its writer, sequence, links, stream, key
  reference, objects and compaction declaration are visible, so a peer that
  reads nothing can store, index and serve it. The rest is sealed.
- A **stream** is a document's place in a space, 16 bytes that look random
  to a peer. The **system stream** carries Frasil's own units. An
  **object** is content-addressed, chunked bytes sealed under one state.
- **Compaction.** A snapshot unit declares exactly which units of its stream
  it replaces, one pair per writer. Each party collects replaced units from
  its own storage once the snapshot settles; a **stub** from a signed
  source stands in for a collected unit that later events name as parents.
- **Validity reads only the unit, its causal past and the keys a replica
  holds.** Stubs, compaction claims, `stream_prev` and a peer's index never
  change a verdict.
- A **full replica** holds every event of the space's log, or a stub of it.
  A **partial replica** holds the space's frame and the streams it opens
  (section 3.15).
- An **adapter** gives a stream's units meaning (section 3.17). The built-in
  ones are [adapter-loro.md](adapter-loro.md),
  [adapter-records.md](adapter-records.md) and
  [adapter-blobs.md](adapter-blobs.md).

Notation, beside [overview.md](overview.md)'s:

- `k(S)` is the content key of the state `S` that a key reference names
  ([keys.md](keys.md)). In a restricted space it is the key
  [ext-restricted-spaces.md](ext-restricted-spaces.md) defines.
- The **stream past** of a unit `u` of stream `X` is the set of units of `X`
  in the causal past of `u`. A writer's **stream frontier** in a set of
  units of one stream is its unit of greatest `seq` among them.
- To **collect** a unit or an object is to delete its bytes from one's own
  storage. It is never a request to anyone.

## 2. Formats

### 2.1 Limits

| What | Limit | On excess |
|---|---|---|
| A signed unit | 1,048,576 bytes | `TooLarge` |
| Locators a unit names | 4,096 | `Malformed` |
| Supersessions in a unit's `supersedes` | 4,096 | `Malformed` |
| Pairs in a snapshot unit's `covers` | 4,096 | `Malformed` |
| Stubs in a snapshot unit, a space snapshot's `stubs` or a log entry's stubs | 8,192 | `Malformed` |
| IDs in `excluded` | 4,096 | `Malformed` |
| An adapter type | 1 to 64 bytes, each `0x21` to `0x7e` | `Malformed` |
| Device-list events in one list copy | 1 to 16 | `Malformed` |
| Body keys in one body-keys unit | 1 to 1,024 | `Malformed` |
| An object's plaintext | 0 to 2^40 bytes | `TooLarge` |
| A chunk's plaintext | 1,048,536 bytes, fixed; a sealed chunk is 1,048,576 bytes | |
| Heads in a head statement, or in a space snapshot's `base` | 1 to 256 | `Malformed` |
| A signed head statement | 65,536 bytes | `TooLarge` |
| IDs, heads, events, pairs or ranges in one sync message | 4,096 | `Malformed` |
| A sync message | 1,052,672 bytes | `TooLarge` |
| Streams in a space, at a peer | `max_streams_per_space`: set by the operator, 1 to 1,048,576, default 65,536, and published in its discovery ([transport.md](transport.md)) | the peer refuses the stream's first unit (`stream_limit`, [peers.md](peers.md)) |

Parents and refs keep [events.md](events.md)'s limits. A writer whose
snapshot would need more pairs, stubs or exclusions than fit compacts in
smaller steps (section 3.5).

### 2.2 The envelope

A unit is an event of kind 4 in its space's log ([events.md](events.md)),
never a genesis. `log` is the space ID; its author, the **writer**, is the
signing device, named by the device ID its envelope's `ed` and `kc` give
([events.md](events.md)); `seq` is the writer's place in its chain in
that log, shared with every other event it signs there, so it is per space,
never per stream; `prev` and `parents` are its **links**; `scheme` is 0 or
2, and a writer signs units under scheme 0 until the classical sunset
([crypto.md](crypto.md)); `body` is the visible body.

### 2.3 The visible body

A deterministic CBOR map:

| Key | Name | Value | When |
|---|---|---|---|
| 1 | `version` | 1 | always |
| 2 | `stream` | bytes(16), not all zero: the stream ID | always |
| 3 | `key` | bytes: the key reference of the state the unit is sealed under ([keys.md](keys.md)) | always |
| 4 | `stream_prev` | bytes(32): the event ID of the writer's previous unit in this stream | when the writer has one |
| 5 | `objects` | array of 1 to 4,096 locators, bytes(64) each, strictly ascending | when the unit references objects |
| 6 | `compacts` | map: the compaction declaration (section 2.9) | a snapshot unit only |
| 7 | `sealed` | bytes, at least 72: the seal (section 2.4) | always |
| 8 | `supersedes` | array of 1 to 4,096 supersessions (below), strictly ascending by their bytes | when an object the unit lists replaces an earlier object of its stream ([ext-file-versions.md](ext-file-versions.md)) |

A unit with key 6 is a **snapshot unit**; every other unit is a **log
unit**. A peer reads keys 1 to 6 and 8 and never the contents of key 7.

A **supersession** says that one object the unit lists, its
**successor**, replaces an earlier object of the stream, its
**predecessor**:

```text
supersession = [successor (bytes(64)), listing (bytes(32)), predecessor (bytes(64))]
                                                      in a log unit
             | [successor (bytes(64)), predecessor (bytes(64))]
                                                      in a snapshot unit
```

- `successor` is a locator in key 5. In a snapshot unit `predecessor` is
  one too. They may be equal: a version put again under a new handle
  replaces its own earlier listing.
- `listing` is the event ID of the log unit of this stream that listed
  the predecessor and whose listing this unit supersedes. A snapshot
  unit's supersessions name its own listings.
- A core implementation reads key 8 for its form and does nothing else
  with it. [ext-file-versions.md](ext-file-versions.md) gives it meaning;
  a peer that implements that document collects by it.

### 2.4 The seal

```text
unit_key(S) = HKDF(none, k(S), "frasil/unit-key/v1")
aad         = "frasil/unit/v1" || field(log) || author || u64be(seq)
              || stream || field(key reference)
body_key    = HKDF(salt = none, ikm = unit_key(S), info = aad)
commitment  = HKDF(salt = none, ikm = body_key, info = "frasil/unit-commitment/v1")
sealed      = nonce (24 random bytes) || commitment (32)
              || XChaCha20-Poly1305(body_key, nonce, inner, aad)
```

- `S` is the state the visible key reference names, of at most 64
  rotations ([keys.md](keys.md)).
- `log` and `seq` are the envelope's, and `author` the device ID it gives
  ([events.md](events.md)); `stream` and the key reference are the visible
  body's. A sealed part therefore opens in one
  unit only, and cannot be moved under another state.
- The unit's **body key** is derived for that one unit. Handing it over
  opens that unit's sealed part and nothing else, since HKDF yields
  neither `unit_key(S)` nor another unit's body key. A member admitted
  "from now on" receives it this way for a unit it cannot otherwise open
  ([admission.md](admission.md), "Top-ups").
- The commitment binds the seal to one body key, because
  XChaCha20-Poly1305 does not commit to its key. A key that misses it
  opens nothing, so a member handed a wrong key holds the unit and never
  reads other content than every holder of `k(S)` reads.
- The seal holds no signature. The envelope's signature covers the whole
  body, `sealed` included.

### 2.5 The sealed part

`inner` is a deterministic CBOR map:

| Key | Name | Value | When |
|---|---|---|---|
| 1 | `type` | text: the adapter type (section 2.7) | always |
| 2 | `content` | bytes: the adapter's content, possibly empty | always |
| 3 | `resubmits` | bytes(32): the event ID of a refused unit of this space that this unit re-submits | a re-submission |
| 4 | `copied_from` | array `[space ID, event ID]`, bytes(32) each | a unit that re-applies a late write ([ext-restricted-spaces.md](ext-restricted-spaces.md)) |
| 5 | `excluded` | array of 1 to 4,096 event IDs, strictly ascending | a snapshot unit, when any (section 3.5) |
| 6 | `stream_opening` | array `[type (text), salt (bytes(16))]` | every unit outside the system stream |
| 17 | `padding` | bytes, every byte zero | at the writer's choice |
| 18 | `refs` | array of 1 to 64 pairs `[log ID, event ID]`, strictly ascending by their 64 bytes | when the unit names events of other logs |

- Keys 3 and 4 never appear together. A unit that carries `copied_from`
  and is refused or late is re-submitted (section 3.11) with the same
  `copied_from` and no `resubmits`: it re-applies the same late write
  again, which adapters merge idempotently, and the client matches it to
  the refused unit by that pair. Key 5 appears only in a snapshot
  unit. Key 6 appears in every unit of a document stream and in no unit of
  the system stream.
- **Refs** are the unit's refs ([events.md](events.md)), kept inside the
  seal. A unit written through a person or a granted space MAY carry, as
  refs, the heads of that log its writer held, so that a replica knows what
  to fetch to check the path.
- **Padding** hides the plaintext's length. Nothing requires it.
- A core implementation that lacks
  [ext-restricted-spaces.md](ext-restricted-spaces.md) ignores key 4.

### 2.6 Streams

- A stream exists from its first unit; nothing creates it. A stream ID is
  16 bytes, never all zero (`Malformed`), and never derived from a name.
- **A document stream's ID commits to its adapter type.** Its creator draws
  a 16-byte random salt, and every unit of the stream carries `[type,
  salt]`, its **opening**, at sealed key 6:

  ```text
  stream ID = SHA-256("frasil/stream-id/v1" || u8(len(type)) || type || salt)[0..16]
  ```
- An application maps one document to one stream by default, and MAY map
  several documents, or the whole space, to one stream to hide its
  structure, at the cost of larger fetches and compactions.
- **The system stream's ID** is 16 random bytes, not all zero, drawn by the
  founder and sealed in the genesis's roster part ([roster.md](roster.md),
  the genesis), and in every space snapshot. A device that fetches it by
  catch-up names it to that peer ([peers.md](peers.md), catch-up).

### 2.7 Adapter types

`type` names the adapter that gives the content meaning. It is sealed, so a
peer never learns which application a space belongs to.

| Type | Content | Stream | Defined in |
|---|---|---|---|
| `frasil:list` | device-list events | system | section 2.12 |
| `frasil:body-keys` | space events' body keys | system | section 2.12 |
| `frasil:recovery-entry` | a recovery entry | system | section 2.12; [identity.md](identity.md) |
| `frasil:system` | the system stream's snapshot units | system | section 2.12 |
| `frasil:move` | a move record | a document stream | [ext-restricted-spaces.md](ext-restricted-spaces.md) |
| `frasil:loro`, `frasil:records`, `frasil:blobs` | the built-in adapters' content | a document stream | the adapter documents |

- Types that begin `frasil:` are Frasil's. A third-party adapter chooses a
  type that does not, such as a reversed domain name
  (`com.example.timesheet`).
- A unit of one of the four system types outside the system stream, or of
  any other type inside it, is refused as content (`WrongStream`).
- A unit of a type this replica has no adapter for, a `frasil:` type
  included, is kept and its content ignored (`UnknownAdapter`). A core
  implementation that lacks
  [ext-restricted-spaces.md](ext-restricted-spaces.md) treats `frasil:move`
  so, and still copies its content into a stream snapshot (section 2.9).

### 2.8 Objects

```text
object_id_key(S)    = HKDF(none, k(S), "frasil/object-id-key/v1")       keys.md
object_nonce_key(S) = HKDF(none, k(S), "frasil/object-nonce-key/v1")    keys.md
object_seal_key(S)  = HKDF(none, k(S), "frasil/object-seal-key/v1")

object ID  = HMAC(object_id_key(S), plaintext)
object key = HMAC(object_seal_key(S), object ID)     32 bytes: the object's own key
digest     = SHA-256(object)                  over the stored bytes below
locator    = object ID (32) || digest (32)    64 bytes

object    = u32be(len(header)) || header || chunk_0 || ... || chunk_(n−1)
header    = deterministic CBOR map {
              1: version, 1,
              2: object ID, bytes(32),
              3: key reference of S, bytes,
              4: size, the plaintext's length, 0 to 2^40 }
c         = 1,048,536
n         = max(1, ceil(size / c))
plain_i   = plaintext[i·c .. min((i + 1)·c, size)]
aad_i     = "frasil/object-chunk/v1" || field(space ID) || object ID
            || u64be(size) || u64be(i)
nonce_i   = HMAC(object_nonce_key(S), aad_i || plain_i)[0..24]
chunk_i   = nonce_i || XChaCha20-Poly1305(object key, nonce_i, plain_i, aad_i)
```

- An object is sealed under the one state `S` its header names. Sealing is
  deterministic, so equal plaintexts under one state have one stored form
  and one locator, and writers dedupe within a state. A merge changes no ID,
  and a rotation never makes an object be uploaded again.
- A unit MAY name an object sealed under any state its writer reaches. A
  reader opens the object under the object's own state.
- Units name objects by locator. A peer stores and serves by locator and
  checks the digest of what it stores.
- An empty object has one empty chunk. A sealed chunk is exactly one frame
  of [transport.md](transport.md). The synthetic nonce lets a writer that
  resumes an upload seal any range again and get the same bytes.
- A chunk opens only at its own place in its own object, so reordering,
  swapping and truncation fail. The header is visible.
- The object key opens that object and no other, and tells nothing of
  `k(S)` or of the state's other objects. A party given it, and not
  `k(S)`, reads the object by section 3.3 (key 7 of an
  [adapter-blobs.md](adapter-blobs.md) entry carries it).

### 2.9 Snapshot units and stream snapshots

A snapshot unit's visible key 6, the **compaction declaration**:

| Key | Name | Value |
|---|---|---|
| 1 | `object` | bytes(64): the locator of the stream snapshot object, which key 5 also lists |
| 2 | `covers` | array of 0 to 4,096 pairs `[writer, unit ID]`, bytes(32) each, strictly ascending by writer |
| 3 | `stubs` | array of 0 to 8,192 stubs of five elements (section 2.10), strictly ascending by event ID |

- The **cover** of a snapshot unit `s` of stream `X` is, for each pair
  `[w, c]` of `covers`, the unit `c` and every unit of `w` in `X` with a
  smaller `seq`. A writer no pair names has nothing in the cover. Nothing
  outside `X` is ever in a cover.
- Its sealed part has the stream's type, the adapter's snapshot metadata as
  content, and the `excluded` list (section 3.5).
- A **seed** is a snapshot unit with empty `covers`: the first unit of a
  stream that starts from a copy.

The **stream snapshot object** is an object (section 2.8), sealed under the
compactor's current state, whose plaintext is a deterministic CBOR map:

| Key | Name | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `type` | text: the adapter type |
| 3 | `stream` | bytes(16) |
| 4 | `history_free` | 1 when the state carries no edit history; absent otherwise |
| 5 | `state` | bytes: the adapter's snapshot state |
| 6 | `moved` | bytes: the content of a valid `frasil:move` unit in the cover, when there is one |

The snapshot unit names the object by locator, whose ID is a MAC of this
plaintext, so the unit's signature binds the state.

### 2.10 Stubs

A **stub** stands for an event whose bytes a replica does not hold:

```text
stub = CBOR array [event ID (bytes(32)), author (bytes(32)), seq (>= 1),
                   height (>= 1), kind]
```

- `author` is the event's author, the device ID its envelope gives; `seq`
  and `kind` are its envelope fields, and `height` its height
  ([events.md](events.md)).
- `kind` is 4, or 64 to 127. A stub of any other kind is `Malformed`: space
  events, anchors and storage events decide authority, coverage and
  stability, and a replica holds them in full. Kinds 64 to 127 appear only
  in five-element stubs outside this document's containers; every container
  this document defines holds stubs of kind 4.
- A stub in a space snapshot adds a sixth element, the unit's stream (bytes(16), not all zero), so that a newcomer knows which
  stream a stubbed unit belonged to. A snapshot unit's stubs have five
  elements before any cuts; they are all of its own stream.
- A stub of an event that declares cuts ([events.md](events.md), "Cuts")
  adds them as its last element, an array of 1 to 4 event IDs, strictly
  ascending: the sixth element of a snapshot unit's stub, the seventh of a
  space snapshot's. A stub of an event that declares none has no such
  element. So a snapshot unit's stub has five or six elements, and a space
  snapshot's or a log entry's six or seven; any other count, a last element
  that is not such an array where one is optional, or one where a stream
  belongs, is `Malformed`.

### 2.11 The space snapshot

A **space snapshot** is a deterministic CBOR array `[snapshot, signature]`.
`snapshot` is the bytes of the map below, and `signature` its sender's
scheme-2 signature over `"frasil/space-snapshot/v1" || snapshot`.

| Key | Name | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `space` | bytes(32): the space ID |
| 3 | `sender` | bytes(64): the signing device's `ed \|\| kc` ([crypto.md](crypto.md), "A device's keys") |
| 4 | `base` | array of 1 to 256 event IDs, strictly ascending: the heads of the sender's view the snapshot is taken at |
| 5 | `stubs` | array of stubs of six elements, strictly ascending by event ID |
| 6 | `body_keys` | array of `[event ID, body key]`, bytes(32) each, strictly ascending by event ID |
| 7 | `lists` | array of signed device-list events, each a byte string, strictly ascending by event ID |
| 8 | `logs` | array of log entries, strictly ascending by key 1 |
| 9 | `streams` | array of stream entries, strictly ascending by key 1 |
| 10 | `proofs` | array of 1 to 256 equivocation proofs ([events.md](events.md)), each a byte string; optional |
| 11 | `system_stream` | bytes(16): the space's system stream ID |
| 12 | `checkpoint` | bytes(32): the checkpoint in effect at the base, the last of its chain ([roster.md](roster.md), "Checkpoints"); absent when none is |
| 13 | `record_key` | bytes(32): the object key of that checkpoint's record object, which opens that object alone ([roster.md](roster.md), "The record object"); present exactly with key 12 |
| 14 | `cut_chain` | array of signed events: the checkpoints key 12's cuts reach, each a byte string that decodes as an event of kind 2 ([events.md](events.md)), strictly ascending by event ID; present only with key 12, possibly empty |
| 15 | `placed` | array of 1 to 4,096 event IDs, strictly ascending: the events of key 7 whose own copy, a `frasil:list` unit, is in the past of the base, so at its place ([roster.md](roster.md), section 3.11, "A list at an event's place"); absent when there are none |

Keys 1 to 9 and 11 are present; keys 5 to 9 may be empty arrays. Key 13
is present exactly when key 12 is, and key 14 only with key 12; each ID of
key 15 is that of an event of key 7; else `Malformed`.

A **log entry** is a map: key 1, a space ID of the grant path; key 2, an
array of that space's signed events (section 3.10), in canonical order; key
3, its stubs; key 4, its body keys, as keys 5 and 6 above; key 5, optional,
its equivocation proofs, as key 10.

A **stream entry** is a map:

| Key | Name | Value |
|---|---|---|
| 1 | `stream` | bytes(16) |
| 2 | `opening` | array `[type (text), salt (bytes(16))]`: the stream's opening (section 2.6), which hashes to key 1 |
| 3 | `object` | bytes(64): the locator of a stream snapshot object with `history_free` set |
| 4 | `key` | bytes: the key reference of that object's state |
| 5 | `covers` | pairs as in section 2.9, of the stream at the base |
| 6 | `excluded` | event IDs as in section 2.5, possibly empty |
| 7 | `supersedes` | array of 1 to 4,096 supersessions of two elements (section 2.3), strictly ascending by their bytes: those of the history-free state ([ext-file-versions.md](ext-file-versions.md), section 3.3); absent when there are none |

Key 7's successors and predecessors are 64-byte locators. A core
implementation reads key 7 for its form and does nothing else with it.
The opening lets a newcomer write into the stream before any unit of it
reaches it. The space snapshot travels as an object sealed under a state
the newcomer holds, as do its stream snapshot objects.
[ext-guests.md](ext-guests.md) also hands it over a member connection.

### 2.12 Frasil's own units

Each is a unit of the system stream whose content is deterministic CBOR:

| Type | Content |
|---|---|
| `frasil:list` | an array of 1 to 16 signed device-list events, each a byte string, of one or more persons |
| `frasil:body-keys` | an array of 1 to 1,024 pairs `[event ID, body key]`, bytes(32) each, strictly ascending by event ID; an event ID may name a space event or a unit, of any log |
| `frasil:recovery-entry` | one recovery entry, the map of [identity.md](identity.md)'s "Fetch keys and recovery entries" |

A `frasil:system` unit is a snapshot unit of the system stream. Its
snapshot state is a deterministic CBOR map: key 1, every device-list event
its cover's list copies carry, strictly ascending by event ID, each once;
key 2, the body keys its cover's units carry, as `frasil:body-keys` pairs;
key 3 is reserved, and a state that carries it is `Malformed`; key 4,
optional, every recovery entry its cover's
`frasil:recovery-entry` units carry, each once, strictly ascending by its
encoding; key 5, optional, for each person whose list key 1 carries from
a list checkpoint on, the pair `[person ID, forgotten]`, strictly ascending
by person ID, where `forgotten` is an array of 1 or more list event IDs,
bytes(32) each, strictly ascending: the events of that list its writer
forgot ([identity.md](identity.md), "List checkpoints", Forgetting and
Spaces), so that a member that starts from the state tells a forgotten
parent from one it has not received. No list event and no recovery entry
is ever left out, but those a list checkpoint in effect lets the writer
forget, whose IDs key 5 then carries: a space keeps the lists of its
former members, and a device of the person registers every entry whose
list member is active ([identity.md](identity.md)).

### 2.13 Head statements

```text
statement = deterministic CBOR map {
              1: version, 1,
              2: space ID, bytes(32),
              3: device, bytes(64): its ed || kc (crypto.md),
              4: heads, array of 1 to 256 event IDs, strictly ascending,
              5: streams, optional: array of 1 to 64 pairs
                 [stream (bytes(16)), array of 1 to 4,096 pairs [writer, unit ID],
                  strictly ascending by writer],
                 strictly ascending by stream }
signed    = CBOR array [statement, signature]
signature = Ed25519, by the device's ed, over
            "frasil/head-statement/v1" || statement                    (scheme 0)
```

Key 5 states, for streams the device holds whole, each writer's stream
frontier. A device that holds more than 256 heads states 256 of them; the
statement proves what it lists. A signed statement is at most 65,536 bytes; a device includes as
many stream entries as fit.

### 2.14 Sync messages

Each message is a deterministic CBOR map of at most 1,052,672 bytes. Key 0
is its type and key 1 the space ID (bytes(32)); the other keys are the
type's. Arrays of IDs are strictly ascending. A sender splits what does not
fit over several messages.

| Type | Name | Keys | Meaning |
|---|---|---|---|
| 1 | `Heads` | 2: 0 to 4,096 heads; 3: optional vector of `[author, seq, event ID]`, strictly ascending by author, then ID; 4: optional streams, 1 to 4,096 | the sender's state; with key 4, a partial replica's: the answer narrows as `Subscribe`'s key 2 does |
| 2 | `Want` | 2: 1 to 4,096 IDs; 3: 1 to 4,096 ranges `[author, first seq, last seq]`; 4: optional kinds, 1 to 127; 5: optional streams | events asked for, by ID or by author and `seq`; at least one of keys 2 and 3. Keys 4 and 5 narrow ranges to those kinds, and units to those streams |
| 3 | `Events` | 2: 1 to 4,096 signed events | events, each after its parents |
| 4 | `Missing` | 2: optional IDs not held; 3: optional pairs `[ID, unit ID]`: a collected unit, and the snapshot unit that carries its stub | answers a `Want` the sender cannot fill |
| 5 | `Ack` | 2: 1 to 4,096 heads | an acknowledgement (section 3.13) |
| 6 | `StreamHeads` | 2: stream; 3: optional ID of the latest snapshot unit; 4: triples `[writer, unit ID, seq]`, strictly ascending by writer | a peer's index of one stream |
| 7 | `StreamWant` | 2: stream; 3: pairs `[writer, unit ID]` the sender holds, possibly empty; 4: optional, 1 to start from the latest snapshot | asks for a stream's units the sender lacks |
| 8 | `ObjectWant` | 2: locator; 3: first chunk index; 4: count, 1 to 64 | asks for chunks, each answered in its own `ObjectChunks` |
| 9 | `ObjectChunks` | 2: locator; 3: optional header bytes; 4: chunk index; 5: one sealed chunk | a chunk, as an upload or an answer |
| 10 | `ObjectHave` | 2: 1 to 4,096 locators; 3: optional, for each, the count of leading chunks held | the objects the sender holds |
| 11 | `PathWant` | 2: from; 3: to | asks for a path from one event down to another |
| 12 | `Path` | 2: from; 3: to; 4: 0 to 4,096 signed events | the first a parent of `from`, each next a parent of the one before, the last with `to` among its parents; empty when the sender knows none |
| 13 | `Subscribe` | 2: optional streams | live delivery: the whole space; or, with key 2, space events, anchors, storage events, the system stream and those streams; key 2 may name the system stream too |
| 14 | `Statement` | 2: 1 to 64 signed head statements | gossip; member connections only |
| 15 | `SnapshotWant` | 2: 1 to 4,096 streams | asks a member for history-free stream snapshots; member connections only |
| 16 | `SnapshotOffer` | 2: a space snapshot whose `streams` hold the entries asked for; its other arrays may be empty | the answer; member connections only |
| 17 | `ListEvents` | 2: 1 to 16 signed device-list events, each a byte string | a read-only person's list events handed to a writer (section 3.11); member connections only |
| 64 | `ObjectMissing` | 2: 1 to 4,096 locators | objects the sender does not hold whole, answering `ObjectWant` (section 3.14); member connections only |

Type 0 and types 18 to 63 are reserved and MUST be understood. Types from
64 are ignorable: a receiver that does not know one drops it. A receiver
that knows type 64 reads its shape as it reads any other type's.

## 3. Procedures

### 3.1 A unit, at a peer

On the envelope and the visible body, without any key, in order:

```text
 1. events.md's checks of the event alone (kind 4, scheme 0 or 2).    else that class
 2. The signed unit is at most 1,048,576 bytes.                       else TooLarge
 3. events.md's placement, counting stubbed parents (section 3.9).    else that class
 4. body: deterministic CBOR, a map with an unsigned key 1.           else Malformed
 5. Key 1 = 1.                                                        else UnsupportedVersion
 6. Keys among 1 to 8; keys 1, 2, 3 and 7 present.                    else Malformed
 7. Key 2: 16 bytes, not all zero.                                    else Malformed
 8. Key 3: a key reference, as keys.md reads one before any key, or
    a restricted one, as ext-restricted-spaces.md's steps 1 and 2
    read it.                                                          else that class
 9. Key 4: 32 bytes. Key 5: 1 to 4,096 locators of 64 bytes,
    strictly ascending. Key 7: at least 72 bytes.                     else Malformed
10. Key 6: a map of keys 1 to 3, all present; key 1 64 bytes and in
    key 5; key 2 at most 4,096 pairs of two 32-byte strings, strictly
    ascending by writer; key 3 at most 8,192 stubs of five elements
    and kind 4, strictly ascending by event ID.                       else Malformed
11. Key 8: 1 to 4,096 supersessions as section 2.3: arrays of three
    elements in a log unit and of two in a snapshot unit, of 64, 32
    and 64 bytes; each successor in key 5, and in a snapshot unit
    each predecessor too; strictly ascending by their bytes.          else Malformed
```

Steps 1 to 11 read no sealed byte. A peer cannot know whether a space is
restricted ([ext-restricted-spaces.md](ext-restricted-spaces.md)), so step
8 reads either form. A peer that collects also checks covers and stubs
against its own index (section 3.7).

### 3.2 A unit, at a member

After section 3.1, in order:

```text
12. After a checkpoint in effect, for a unit after it: the key
    reference names only the checkpoint and events after it in the
    unit's past (roster.md, "The world after a checkpoint").          else StaleSeal
    The key reference names rotations the replica holds, as keys.md
    says; a missing rotation is Pending.                              else that class
13. The replica holds k(S), or a body key handed over for the unit
    whose commitment is the seal's.                                   else Sealed
14. The body key, derived from k(S) or handed over, matches the
    seal's commitment, and the seal opens under it. Under a key
    derived from rotation keys that each matched their commitments, a
    failure is BadSeal. Under a provisional key, or a handed body
    key, it is Sealed.                                                else BadSeal / Sealed
15. inner: deterministic CBOR; keys among 1 to 6, 17 and 18; keys 1
    and 2 present; key 1 an adapter type; key 3 32 bytes; key 4 two
    32-byte strings; keys 3 and 4 not together; key 5 only in a
    snapshot unit, 1 to 4,096 IDs ascending; key 6 an adapter type
    and 16 bytes, present exactly outside the system stream; key 17
    zeros; key 18 as section 2.5, at most 64 refs.                    else Malformed / TooLarge
16. roster.md's write rule.                                           else its class
17. The unit is valid. Its content goes to its adapter (section
    3.17), which may refuse it as content without changing this
    verdict: first WrongStream (section 2.7), then the stream check
    below, then the adapter's own checks and capability checks.
```

**The stream check.** For a unit of a document stream, SHA-256 of its
opening, as section 2.6 computes it, is its visible stream
(`StreamMismatch`), and its `type` is the opening's type or `frasil:move`
(`WrongAdapter`). Each unit is checked alone, so a stream's type is fixed
when the stream is created and never depends on which unit comes first.

A unit that fails a step from 4 to 11 is dropped. One that fails step 14
with `BadSeal`, or step 15, is void, and kept as any void unit of an author
a record names ([roster.md](roster.md)). One held at step 13 or 14 still
counts as fork evidence. A partial replica runs step 16 as section 3.15
says.

### 3.3 Reading an object

In order:

```text
0. SHA-256 of the bytes is the locator's digest.                      else ObjectMismatch
1. At least 4 bytes, and the header's length fits.                    else Malformed
2. The header is deterministic CBOR, a map with an unsigned key 1.    else Malformed
   Key 1 is 1.                                                        else UnsupportedVersion
   Keys 1 to 4 only; key 2 32 bytes; key 3 a key reference, or a
   self reference (keys.md);
   key 4 at most 2^40.                                                else Malformed / TooLarge
3. The header's object ID is the locator's.                           else ObjectMismatch
4. The rest is exactly n chunks of their lengths.                     else Malformed
5. The reader holds k(S), or the object key.                         else Sealed
6. Each chunk opens under the object key. A reader verifies each
   chunk before it uses it.                                           else Decrypt
7. Once all are read, and only with k(S): HMAC(object_id_key(S),
   plaintext) is the object ID.                                       else ObjectMismatch
```

A peer runs steps 0 to 4 on an upload once it holds the header and every
chunk. It cannot tell a checkpoint's record object, whose header names the
checkpoint by its self reference ([roster.md](roster.md), "The record
object"), from any other, so it accepts either form of key 3. A member
accepts a self reference only where it reads a checkpoint's record, and
there only one equal to `0x00 || author || u64be(seq)` of that
checkpoint's envelope (else `BadCheckpoint`, the checkpoint's own fault,
since the locator binds the header); in any other object a self
reference is `Malformed`. A reader that fetches by chunk, or reads the
object as its chunks arrive without holding it whole, may run steps 1 to 7
first and step 0 on the whole last, hashing the stored bytes as they pass;
its verdict is still the first step, in the order above, that fails. So a
fault it finds at steps 1 to 7 stands only once step 0 has passed: if step
0 fails, the bytes are not the object, whatever else they hold, and the
reader holds the object as not received and fetches it again. A reader
that stops at a fault before it has run step 0 concludes nothing about the
object. Until every step it runs has passed, it acts on nothing the
plaintext says: it publishes none of it, and gives no verdict that reads
it. Giving a chunk's plaintext to the application as content it reads or
plays is neither: a reader MAY do so once steps 1 to 3 and 5 have passed
on the header and steps 4 and 6 on that chunk, with the limit that
[adapter-blobs.md](adapter-blobs.md), section 4, states for what is shown
before steps 0 and 7. Steps 1 to 3 bind the header's object ID to the
locator and nothing else of the header: its size is bound by each chunk's
associated data (section 2.8), so such a reader relies on the header's
size, as the object's length or to tell its end, only once a chunk has
opened under that header. A reader that holds only the object key skips step 7: step 0 binds
the bytes to the locator it was given, and step 6 to the key. A stream snapshot object's plaintext is then read as deterministic
CBOR, a map with key 1 (`Malformed`); key 1 is 1 (`UnsupportedVersion`);
keys 1 to 6 with their types, key 2 the snapshot unit's sealed type, and
key 3 its stream (`Malformed`).

### 3.4 What a writer does

A replica does not refuse a unit for breaking these, because no verdict may
depend on what some replicas can check only in part.

1. A device restored from a backup MUST sync before it writes
   ([events.md](events.md); [at-rest.md](at-rest.md)).
2. A writer MUST seal under the current state of its view
   ([keys.md](keys.md)), and MUST NOT write in a space whose cascade is due.
   A unit sealed under an older state is valid; readers MAY flag it
   (`StaleKey`).
3. A writer MUST cite among its parents every space event that is maximal
   among the space events of its view, besides its other heads and `prev`.
   A partial replica reads the unit's place from them.
4. A writer MUST set `stream_prev` to its own previous unit in the stream. A
   replica that finds a wrong link reports `StreamLinkBroken` and goes on.
5. A writer SHOULD batch small writes: every unit carries a signature and
   visible metadata.
6. A unit is sealed and signed once. A writer MUST NOT seal it again after a
   rotation: it stays valid under the key it names, and content the writer
   wants under a newer key is a new unit. A retry of a signed unit is the
   same event.
7. A writer MUST upload an object before the unit that names it, while it
   holds the object. A device that holds no copy of an object a unit
   names, such as a held object found not held
   ([at-rest.md](at-rest.md), "Held objects"), MUST NOT hold the unit back
   for it, nor any unit after it: the unit goes without its object. A
   device that holds the object still uploads it before it sends the unit
   to a peer. A writer offers its unacknowledged units on each connection
   (section 3.13), so one that holds the object uploads it there even when
   another device sent the unit first. Until a holder uploads it, the
   object is missing at the peer, and a reader fetches it from a member
   that announces it or not at all.

### 3.5 Compacting

Compaction is the adapter's; Frasil carries the declaration. A compactor:

1. **Chooses the cut** by the snapshot unit's parents, normally its own
   heads. `covers` is exactly the stream past of `s`: for each writer with a
   unit of the stream in the past of `s`, the pair names that writer's
   stream frontier there.
2. **Covers every unit of the stream past, valid or not.** Units the
   compactor refused, holds pending or cannot open are in the cover, so the
   cover is a function of the causal past alone. The state includes exactly
   the units of the cover the compactor applied; every other unit of the
   cover is listed in `excluded`.
3. **Lists the boundary stubs:** every unit of the cover that is a parent
   of an event in its view outside the cover, `s` included, and every stub
   of an earlier snapshot unit in the cover that is still such a parent.
   Earlier stubs that nothing outside the cover names are dropped, so stubs
   do not grow with history.
4. **Lists every object the state still references** in `objects`, its
   snapshot object included, so that compaction keeps them referenced.
5. **Compacts in smaller steps** when a stream has more writers or stubs
   than one unit holds: its parents fix an older past that holds fewer, its
   own `prev` among them, and a later snapshot covers the rest.

A snapshot unit is a unit. The write rule applies to it, and the adapter's
capability checks run on it with a context that says so (section 3.17). Any
writer whose adapter's checks let it compact MAY compact.

### 3.6 Checking, using and settling a snapshot

**Checking.** A replica that holds the stream past of `s`, as events or as
signed stubs, checks that `covers` is exactly the writers' stream frontiers
of that past, that each stub matches the event it stands for, and that the
state includes the cover less `excluded`. A replica that holds the units
checks the last by rebuilding from them and comparing what the adapter can
compare; one that cannot rebuild trusts the compactor for it. A check that
fails is reported (`BadCompaction`); the replica never uses that snapshot
and never collects what it covers. The snapshot unit stays valid. A client
that reports `BadCompaction`, or finds a snapshot unit refused by the write
rule or as content, stores a restore that names it ([peers.md](peers.md),
release and restore), which cancels its collection at every peer, and
offers again, as it offers its own unacknowledged events (section 3.13),
every unit of the cover it holds, so that the cover returns at a peer that
collected it. A snapshot unit found valid by the write rule and refused
later keeps its stubs: they counted from a judged source (section 3.9),
and events were placed on them. Each event they stand for that the
replica later holds in full replaces its stub, and the replica computes
again the heights of the events placed on it.

**Using.** A replica MAY load a snapshot's state in place of the units it
covers if the snapshot unit is valid, its content is not refused, and the
replica checked it or holds nothing it covers. Its content counts as not
refused only once the stream's adapter has accepted it: not a unit that
fails `WrongStream` or the stream check (section 3.2), nor one whose content
is ignored (`UnknownAdapter`, `UnknownContentVersion`), nor one refused by
the adapter's own or capability checks, nor one whose content waits or is
refused because its author's capabilities were not found (section 3.17). A seed covers nothing, so its
state stands in for no unit: a replica whose stream uses a snapshot with a
non-empty cover does not load a seed's state in its place. A replica that
loads a snapshot's state marks every unit of its cover as held for its
adapter, whether or not it holds the unit's bytes. Over that state it hands its
adapter every unit of the cover that the state does not include (the
snapshot unit's `excluded`) and that it holds, valid or not, as any unit:
counted, and applied if valid and not refused as content. A check that
counts units, such as [adapter-loro.md](adapter-loro.md)'s step 6 or
[adapter-records.md](adapter-records.md)'s clock, then counts over the
snapshot what it counts in a rebuild. A replica that does not hold an
excluded unit cannot hand it back, so such a check counts less there, and
the replica MAY accept the content of a later unit that a replica holding
the excluded unit refuses as content. Only content differs; verdicts are
the same at both. If it later finds refused a unit the state includes, or a
check fails, it drops the state and rebuilds (section 3.8). If it later
finds the snapshot unit itself refused, by the write rule or as content, it
no longer uses that snapshot: it drops the state and rebuilds from the
units it holds.

**Settling.** At a replica, in order:

```text
settled(s):
  1. s is stable (roster.md).                                         Settled
  2. lower(first sight of s, now) >= gap_key_timeout.                 Settled
  3. Otherwise.                                                       Unsettled
```

`gap_key_timeout` is the space's ([overview.md](overview.md), section 6.8).
Step 2 bounds a space that never reaches stability, such as one whose
recovery member never signs.

### 3.7 Collecting

**At a replica.** A replica MAY collect a unit of the cover of a settled
snapshot it checked and uses, except:

- a unit it authored that is refused ([roster.md](roster.md), keeping
  refused units);
- a unit that is part of fork evidence it holds;
- a unit that an event it holds outside the cover names as a parent, while
  it holds no signed stub for that unit;
- a unit that a space event it holds outside the cover names as a parent
  (below, "Parents of space events").

A refused unit is collected only once both its snapshot has settled and
roster.md lets the replica drop it. A replica keeps the objects its rebuild
set references, and need not keep an object it can fetch again. An
object that a peer may have collected as a superseded version
([ext-file-versions.md](ext-file-versions.md)) is not one.

**At a peer** collection is [peers.md](peers.md)'s: a peer collects a
snapshot unit's cover once that unit is stable at the peer, or after `T`,
unless a restore names it, and keeps every unit that an unreplaced event
names as a parent unless a stored snapshot unit holds a stub for it, and
every unit that a space event names as a parent. Reclaiming a released
stream keeps, as events alone, the units that an event outside the stream
names as parents ([peers.md](peers.md), release and restore). An erasure
names the whole space, and keeps nothing of it.

**Parents of space events.** Neither a replica nor a peer collects a unit
of a cover that a space event it holds names as a parent. A replica places
that event only against the unit in full or a confirmed stub (section 3.9,
"Confirming heights"), and a stub its compactor alone signed is not one;
catch-up serves the unit by ID ([peers.md](peers.md)). The unit is kept as
an event alone: it stays replaced, so it references no object and keeps no
hold live ([ext-libraries.md](ext-libraries.md)), and the snapshot's state
stands for its content. A peer keeps its own stub of each parent of such a
unit that it collects, for its own placement, so that it serves the unit.

**Objects.** An object is **referenced** while a stored unit that is
neither replaced nor released lists it in `objects`; each such unit and
locator is a **listing** of the object. A peer collects an unreferenced
object with the cover of the snapshot that dropped its last reference,
reclaims it with a release, and collects one that no unit has referenced
since it was stored after `orphan_grace` ([peers.md](peers.md)). A peer
that implements [ext-file-versions.md](ext-file-versions.md) also
collects a referenced object whose every listing is superseded, after a
retention; a replica therefore cannot count on fetching an older version
of a file again, and keeps the bytes it wants.

### 3.8 Rebuilds

A replica that applied a unit later refused undoes it, so adapters rebuild a
stream's state from an accepted set of units.

- **The rebuild set.** For each stream, a replica keeps the latest settled
  snapshot it uses, or none, and every unit of the stream after its cover:
  valid, refused, pending and unopened. With the snapshot object, that is
  all an adapter needs.
- **When.** When verdicts change, by a removal learned late, a removal
  voided at a merge, or a duel, the replica rebuilds each stream that holds a
  unit whose verdict changed, once per batch of events it processes: it
  loads the settled snapshot and applies the stream's accepted units after
  its cover, in canonical order. Streams with no such unit are not touched.
- **Unsettled snapshots** are caches, dropped on a refusal inside their
  cover.
- **A refusal inside a settled snapshot** arrives only through a backdated
  duel, or a removal that an administrator's events bring in after
  stability or the timeout. The replica rebuilds from units it still holds;
  else asks members for a snapshot built without the refused units; else
  keeps the state and reports what it could not undo (`Unremovable`).
- **A member that started from a snapshot**, on a refusal inside its
  snapshot's cover or a merge that reaches before its base, asks a member
  for a fresh history-free snapshot.

### 3.9 Placing against stubs

**Where stubs come from.** A stub counts only from a signed source the
replica has judged: the `stubs` of a snapshot unit that is placed and valid
by the write rule ([roster.md](roster.md)), under its compactor's
signature; or the `stubs` of a space snapshot's base (section 3.10), under
its sender's. A peer's or a stranger's unsigned word about an event is never a
stub, and neither is a unit's that no record lets write. After the
classical sunset, a unit's stubs count only once the unit is covered
([crypto.md](crypto.md)).

- **A pending snapshot unit's own stubs** serve only to place that unit,
  provisionally. A snapshot unit whose cover is collected waits for the
  parents its stubs stand for. Once its stubs stand for every parent that
  it and the pending events of its past lack, none of them stubbed already,
  the replica places them against those stubs, and holds every event placed
  on them out of its view until it judges the unit. If the write rule finds
  the unit valid, its stubs count from then on. If it refuses the unit, the
  replica takes its stubs back, with every event placed on them, which wait
  for their parents again. Until it judges the unit, the replica asks for
  each event those stubs stand for, as for a missing parent.
- **A carried stub** (section 3.14, step 4) counts once its carrier is
  placed and valid. A carrier that is refused, or stays pending, carries
  nothing, and the replica asks for the event again.

**Placing.** An event is placed once each parent is placed or has a stub.
A replica takes a stubbed parent's height from the stub, and so computes
heights and canonical order as a replica that holds the event would.

- A replica that holds both an event and a stub of it compares author,
  `seq`, height, kind and the cuts the stub carries with the cuts the
  event declares (none when the stub carries none). A mismatch is `BadStub`: the replica uses the event and
  reports the stub's signer. Once it places the event, it computes again
  the heights of the events it placed on the stub.
- Two stubs that disagree for one ID hold every event that has that ID as a
  parent pending, until the replica holds the event itself.
- **A stub is never evidence.** Chain checks read a stub's author and `seq`
  to place events, but only two signed events prove a fork. A stub that
  would show a skip proves nothing; the replica fetches the event or reports
  `BadStub`.
- An event with a parent that the replica neither holds nor has a stub for
  is pending. The replica asks the event's author first, which held the
  parent when it signed, then any replica. A writer whose own view is
  compacted cites only heads, which are never in a cover it collected.

**Confirming heights.** A stub's height is its signer's word until the
replica holds the event. For every parent of a space event that a replica,
full or partial, places against a stub, it either fetches the parent in
full (catch-up serves parents by ID, [peers.md](peers.md)), or holds the
same stub from two signed sources by two different writers. The stubs of
a replica's own base are the exception: they are confirmed on the space
snapshot's signature ("A base", below). Until then the
space event is pending, and the replica asks for the parent. A parent held
in full confirms its stub when its author, `seq` and kind match; one held
pending, on parents a snapshot covers, stands at the stub's height until
the replica places it. A lied height of a unit that no such space event
rests on changes only the order among units, on which no verdict depends,
and no adapter state beyond a writer's own overlapping changes
([adapter-loro.md](adapter-loro.md)).

**What is kept.** With section 3.7's exceptions, and the units a peer keeps
when it reclaims a released stream ([peers.md](peers.md), release and
restore), every parent of every stored event is a stored event or a signed
stub somewhere. A peer's own record of what it collected or reclaimed
serves only its own placement. A stub is dropped once nothing stored names
its event.

**A base.** A replica that starts from a snapshot holds a **base**: the
heads the snapshot was taken at and the stubs it came with. It treats every
event in the past of its base as decided ([events.md](events.md)), and
judges only events after it, and space events, which it holds in full.

- **Confirmed on the sender's signature.** Every stub of the base, of this
  space (key 5) and of each log of the grant path (each entry's key 3),
  counts as confirmed from the start: the space snapshot is under its
  sender's signature, and the newcomer has no second signer to ask. It
  never receives the units of the grant path's spaces, and holding a unit
  of this space from before its base would have it ask for that unit's
  parents, back past the base.
- **Where it stops.** A newcomer never asks for an event a base stub stands
  for, nor for anything in its past. A unit a base stub names that reaches
  it anyway is not placed: it stays decided, as its stub.
- **Provisional.** The base stands until something the newcomer later holds
  contradicts it: a unit a base stub names whose author, `seq`, kind or
  cuts differ from the stub's, or a stub of the same event, differing from it,
  that a carrier named in `Missing` holds (section 3.14, step 4). The newcomer
  checks each, and reports a mismatch as `BadStub` against the snapshot's
  sender. It keeps its base: it holds no past below the base from which to
  compute a height, so nothing placed on a base stub is placed again. It
  MAY ask another member for a space snapshot and start from that one
  instead.
- **What a lying sender achieves.** It can give units in the past of the
  base false heights, so shift the canonical order among the events the
  newcomer places on them, the space events included; and it can withhold.
  It cannot make the newcomer place an event it does not hold in full,
  other than a unit of the past of the base, nor forge an event, a
  signature or a verdict, nor reach any other replica. Every lie is under
  its signature, and a lie of an author, `seq` or kind is found once the
  newcomer holds the unit.

### 3.10 The space snapshot

A member admitted from now on, a member restored by a merge
([keys.md](keys.md)) and a guest start from a space snapshot.
[admission.md](admission.md) says who sends it and when.

**What it carries.**

- **The checkpoint.** With key 12, the newcomer holds the frame only from
  that checkpoint on: it fetches the checkpoint, its record and the space
  events, anchors and storage events that follow it, and never what came
  before but the genesis, the checkpoints of key 14 and the roots and
  enrolments its skeleton cut's slot entries name, which carry the
  pseudonyms' keys ([peers.md](peers.md), "Skeleton cuts"). The body keys, lists and fork evidence below are then those of
  the events that follow it, and the lists of the persons its record and
  those events name. It takes the checkpoint as its kept checkpoint once it
  is in effect in what it holds after it, and until then holds the space
  as pending ([roster.md](roster.md), section 3.15.6).
- **The base and its stubs.** `base` is the sender's heads. `stubs` holds a
  stub of every unit in the past of the base that the newcomer will not hold
  in full and that is a parent of an event it will hold: a space event, a
  storage event, an anchor, an event of the base, or an event of the
  sender's view after the base. This space's space events, storage events
  and anchors are not in the snapshot; the newcomer fetches them, by kind or
  as parents by ID.
- **Body keys:** for every space event in the past of the base that the
  sender opened and that the newcomer cannot open with the rotation keys it
  will hold ([keys.md](keys.md), body keys).
- **Device lists:** every event the sender holds of the list of every
  person a roster in the snapshot names, now or before. The newcomer cannot
  open the list copies sealed before its break, so key 15 names those of
  them whose own copy is in the past of the base: they, and the adds a
  named list checkpoint's record names, are at the place of the base and
  of every event after it; the others place nothing until a copy after
  the base carries them.
- **The grant path.** For each space this space grants, transitively: every
  space event and storage event of its log, and every anchor that is a
  parent of one, in full, with the body keys the newcomer needs and stubs of
  the units they name as parents; no unit or object of those spaces. Later
  events of those logs reach the newcomer through refs
  ([roster.md](roster.md), checks across logs).
- **Fork evidence:** one equivocation proof for every author of this
  space's log or a grant path's log whose fork the sender holds evidence of,
  at key 10 or in that log's entry, with stubs of the parents of its two
  events.
- **Documents:** a stream entry for each stream the sender chooses, by
  default every stream. A newcomer asks any member for one left out
  (`SnapshotWant`).

**Using it**, in order:

```text
1. Decode the array and the map, with the types, limits and orders above. else Malformed
   Each stream entry's opening hashes to its stream (section 2.6).        else Malformed
   Version 1.                                                             else UnsupportedVersion
2. space is the space joined.                                             else WrongSpace
3. The Ed25519 half verifies under sender's ed.                           else BadSignature
   The ML-DSA-65 half verifies once the newcomer holds keys that hash
   to sender's kc (crypto.md, "A device's keys"); until then the
   snapshot is provisional.
4. Place the device-list events and the grant path's events. Fetch this
   space's space events and storage events, from the checkpoint key 12
   names when present, placing each against the stubs and opening each
   with its body key or its own keys. The stubs of
   the base, this space's and the grant path's, are confirmed on this
   snapshot's signature (section 3.9, "A base"); confirm every other stub
   section 3.9 names. Place the proofs' events, and count them as
   evidence once both are placed and their signatures verify.
5. Judge the roster and keys over what it holds. Verdicts that rest on a
   handed body key are provisional (roster.md).
6. For each stream entry it opens, load the history-free state, then fetch
   the stream's units after the covers.
```

A peer serves the space events and storage events of step 4 under the read
credential of any state the space has had ([peers.md](peers.md),
catch-up). Anything the newcomer later holds itself, an event a stub stood
for, another signer's stub of it, or a key that derives a body key, is
checked against what the snapshot said; a mismatch is reported against the
sender (`BadStub`, `BadSeal`), and the newcomer MAY ask another member for a
snapshot (section 3.9, "A base").

### 3.11 Frasil's own units

**List copies** carry a person's list in every space that grants the
person ([identity.md](identity.md), sealed list copies). A replica checks
each event as a device-list event and places it in its person's log; an
event that fails is dropped from the copy, and the unit stays valid. Any
writer that holds a list event of a person the roster names, now or before,
and finds it missing from the system stream, forwards it in a copy.

**A read-only person's list events.** A copy needs `write`, so a device of a
person granted only `read` hands its list events to a writer device of the
space, until each appears in the system stream:

- in a `ListEvents` message on a member connection; or
- as a device-mailbox item ([transport.md](transport.md)) with content name
  `frasil/list-events`, whose body is the deterministic CBOR map `{1: space
  ID (bytes(32)), 2: array of 1 to 16 signed device-list events, each a byte
  string}`.

The writer checks each event as a list event of a person the space's roster
names, now or before, and forwards it in a `frasil:list` unit if its view
lacks it. That unit is the event's copy, which places it for the paths of
every event after it ([roster.md](roster.md), section 3.11, "A list at an
event's place"); a list event that only travelled by message gives no
path. An event that fails is dropped, and nothing else. A writer keeps
nothing it cannot check yet, such as a claimant's list that arrives before
the successor naming the claimant ([ext-invite-links.md](ext-invite-links.md)),
so the sender hands the events again, promptly at first and then less
often, until it sees each in the system stream; it MAY stop after a time
of its choosing. A device that a
recovery agent added, which holds no keys while it waits, hands its list's
events to writers the same way ([ext-recovery-agent.md](ext-recovery-agent.md)).
[ext-ephemeral.md](ext-ephemeral.md) MAY carry the same body as an
ephemeral message.

**Recovery entries.** A device of the person writes one
`frasil:recovery-entry` unit per recovery entry, in the system stream of
the personal space, as [identity.md](identity.md) says when. A replica
reads the entry by identity.md's checks; an entry that fails, or whose list
member is not active, is ignored, and the unit stays valid.

**Body keys.** A member that opens a space event or a unit that a
newcomer could not open sends the newcomer its body key in a
`frasil:body-keys` unit, sealed under the current state
([admission.md](admission.md) says who and when), or over a member
connection in the same form if it cannot upload. Each key is checked
before use: a space event's against its commitment ([keys.md](keys.md)),
a unit's against its seal's (section 2.4). A newcomer handed two different
keys for one space event holds it `Sealed`; a unit's key that misses the
commitment is ignored.

**The system stream** is compacted like any stream, by `frasil:system`
snapshot units (section 2.12).

**Re-submission.** After a re-grant, a device re-submits its refused units
([roster.md](roster.md), re-submission: those refused by a removal or a
response, and those refused as `NotAWriter` that events void, never one
that none voids): for each, in canonical order, a new
unit after its current heads, with the same type and content, whose
`resubmits` names the refused unit; a late unit counts as refused here.
It is judged as any unit, but an adapter's check that refuses content an
earlier unit already holds does not count the units it re-submits
([adapter-loro.md](adapter-loro.md), section 3.2, step 6). If the refusal
is later voided, the content arrives twice; adapters merge idempotently.

- **Text written again.** A device whose units a removal withdrew may
  write their text again under a fresh incarnation of the stream
  ([adapter-loro.md](adapter-loro.md), section 3.1), as a holder that lost
  its own operations must. It then never re-submits a refused unit of the
  incarnation it so expressed again: the new incarnation is another Loro
  peer, so importing both would apply the text twice, where a
  re-submission repeats the same operations under the same peer and
  imports once. It records each such `[stream, incarnation]` at rest in
  the same commit as the first unit it writes under the new incarnation,
  never before, so that a restart neither re-submits the old units nor,
  after a crash before that unit, loses the text ([at-rest.md](at-rest.md),
  the `state` record's key 8).

### 3.12 Release, restore and erasure at a replica

Release and restore are a writer's storage events, and erasure an
administrator's; their formats, and what a peer does, are
[peers.md](peers.md)'s. A replica judges a release or restore by the write
rule, as a unit.

- A replica keeps a released stream's units and objects for at least
  `replica_release_retention` from its first sight of the release, on the
  lower estimate, and until the release is stable, so that a writer can
  restore it from any replica after a peer has reclaimed it.
- A replica drops a space that a valid erasure names as
  [peers.md](peers.md) says. An erasure names the whole space: a writer
  deletes a document for good with a release, whose content goes once a
  peer reclaims it.
- A restore is valid at any time. After the retention it may find no bytes
  left at a given peer.
- **After a checkpoint.** A replica that forgot keeps, of the releases and
  restores of its kept checkpoint's past that are not late under an
  earlier checkpoint, the maximal ones of each stream, which are
  concurrent with each other, and counts with them the valid ones after
  the checkpoint. It orders every kept one before every event that follows
  the kept checkpoint, which holds that whole past, as a replica that kept
  everything finds them ordered; without that order it would read a kept
  release as concurrent with a later restore, or the reverse. One late
  under a checkpoint of its chain counts for nothing, though a later
  checkpoint's past holds it, as at a peer ([peers.md](peers.md), "Release
  and restore"). It thus finds a
  stream released as one that kept everything does, without the order of
  what it dropped. Releases are judged by the write rule, which a peer
  does not run, so a replica keeps the units of a stream when one of the
  kept maximal requests of it is one it judged void.

### 3.13 Heads, acknowledgements and durability

- **Heads and vectors.** A replica's state of a log is a set of events
  closed under parents, with stubs, named by its heads. Its **vector** is,
  per author, the greatest `seq` it holds and that event's ID; it holds
  exactly the first `seq` events of an unforked author's chain, because
  `prev` is a parent. Two parties that exchange heads and vectors know what
  each lacks without reading content. No `seq` starts from a clock.
- **An acknowledgement** (`Ack`) says that its sender has stored durably
  every event in the past of the named heads, or collected it under a
  stable snapshot. It is about the sender's storage alone, unsigned, and
  decides no validity, order or stability. A device keeps, per space, the
  heads each peer last acknowledged.
- **Durable.** A device counts its own event durable once an always-on peer
  of the space has acknowledged it, or, in a space with no always-on peer,
  once another member has; an application MAY require more. Until then the
  event stays in the device's outbox ([at-rest.md](at-rest.md)) and is
  offered again on every connection. Only an acknowledgement counts: heads
  or listings that show the event say nothing of its storage.
- **A restored peer** holds older events. Nothing it served was numbered by
  it, so nothing resets: the device sends what the peer lacks, and any
  member MAY upload another member's events. A device that sees a peer
  lack an event that peer acknowledged reports `RolledBack`, sends it
  again, and counts it not durable until a peer acknowledges it again; in
  a space with no always-on peer, so does a device that sees a member lack
  an event that member acknowledged.

**Head statements** let members notice a fork, a partition or a rollback
before their replicas meet, whenever a second path exists.

- A statement proves that its device held the events it lists. A receiver
  that cannot obtain a statement's heads, or their past, asks for them by
  ID, of the statement's author first, and of its peers. If the author
  answers `Missing` for them, the statement is junk (`BadStatement`),
  reported against its author.
- A peer that answers `Missing` for a statement's heads may simply not
  have received them yet: the author uploads them on its own connections.
  So the receiver does not report it at once. While it still lacks those
  heads, it asks that peer for them again once `withholding_grace` has
  passed since the peer's first `Missing` for them. Once the author has
  supplied them, which shows the statement true, the receiver reports the
  peer `Withheld` if the peer had acknowledged them (a head itself or an
  event with it in its past), or if the peer answered `Missing` for them
  again at least `withholding_grace` after its first `Missing`. Otherwise
  it reports nothing and forgets the peer's answers: a receiver that holds
  the heads sends them to the peer (section 3.14), so asking again shows
  nothing.
- A receiver checks, in order: the signature, under `device`'s `ed`
  (`BadSignature`); the space (`WrongSpace`); `device`'s `ed` is a valid
  key (`InvalidKey`), and the device ID of `device` is a member in its
  merged roster (`NotAMember`). A statement that fails is ignored.
- A statement names a device, so it never reaches a peer in the clear. It
  travels in `Statement` on member connections, when the space is admitted
  and whenever the sender's heads change, as [transport.md](transport.md)
  rate-limits it; and, with [ext-ephemeral.md](ext-ephemeral.md), as the
  ephemeral slot `frasil/heads`, holding as many stream entries as fit in 16,384
  bytes.
- A receiver keeps, per device, every statement it took that it has not
  shown to be older than another it keeps of that device: it drops a
  statement only once it holds the other's heads and each head of the one
  it drops is among them or in their past. A device's heads only grow, so
  that order is sound, but a receiver often lacks a newer statement's heads
  and a statement lists at most 256, so two statements of one device are
  not always ordered; both are kept then. A statement replayed after a
  newer one never takes its place.
- A statement is not an event and decides no validity, stability or policy.

**Detected loss.** A client keeps the heads it has seen in each space, its
own events, the heads each peer acknowledged, and, per stream it reads,
each writer's stream frontier. A peer that serves a state lacking any of
these is withholding or rolling back: the client reports `Withheld` or
`RolledBack` for that peer and repairs from other replicas. A peer's state
is what its `Heads` show: the past of its heads, once the client holds
them all, and, per author, the first `seq` events its vector names. It
lacks an event:

- that it acknowledged: `RolledBack`;
- of a state it served the client before, or a writer's units its
  `StreamHeads` leave out (section 3.14, "By stream"): `Withheld`;
- of a statement's heads it answered `Missing` for, once the statement's
  author supplied them, if it had acknowledged them or still answered
  `Missing` after `withholding_grace` (head statements, above):
  `Withheld`.

An event that reached the client by another path, and that the peer has
neither acknowledged nor served, is one the client sends it (section
3.14), not one it lacks. What a peer acknowledged is kept at rest, in the
`ack` table ([at-rest.md](at-rest.md)); the state a peer served is kept in
memory only, so a peer that serves less than a state it served is
detected within one run of the client, and a state served before a
restart is not compared.

### 3.14 Sync

[transport.md](transport.md) carries this document's sync messages
(section 2.14) between members and between a device and a peer, and says
which credential each needs. The space a message names MUST be its
frame's. A receiver refuses a message that breaks its type's shape as
`Malformed`, and type 0 or an unknown type from 18 to 63 as
`UnknownMessage`, and drops it.

**The exchange.**

1. Each side sends `Heads`. A side that holds every head the other sent
   computes exactly what the other lacks, every event it holds outside the
   past of those heads, and sends them in `Events`, in canonical order.
   When those `Heads` carry key 4, it sends of them only space events,
   anchors, storage events, the system stream's units and the units of the
   streams key 4 names.
2. A side that lacks some of the other's heads asks for them by `Want` with
   IDs, or by the vector: a range for each author whose greatest `seq` it
   holds is lower. A vector entry whose ID differs at an equal `seq` shows a
   fork; the side asks for both chains from the fork and passes the evidence
   on ([events.md](events.md)).
3. Each side places what arrives. An event that stays pending names parents
   to ask for by ID.
4. A side asked for a collected unit names, in `Missing`, a snapshot unit
   whose cover holds it and whose stubs carry it; if none exists, it still
   holds the unit (section 3.9).
5. Once it has stored what it received durably, a side sends `Ack`.

A peer verifies each event's envelope and the Ed25519 half of its signature,
places it, and runs section 3.1 on units before it stores them. A second
event at one author and `seq` is stored as fork evidence, and not
acknowledged. It judges nothing else. Live delivery uses the same messages:
a peer sends each newly stored event to every connection subscribed to it.

**By stream.** A peer indexes units by space and stream. A reader opening
one document:

1. sends `StreamWant` with what it holds of the stream, and the flag to
   start from the latest snapshot;
2. receives `StreamHeads`, then `Events`: the latest snapshot unit if it
   asked, and every unit of the stream after its cover that it lacks;
3. fetches the snapshot object;
4. checks completeness: for each writer `StreamHeads` names, it holds the
   unit named and every unit reached from it by `stream_prev`, back to that
   writer's pair in the snapshot's `covers`. A missing unit is the peer's
   gap, asked for by ID.

A peer can still withhold a writer's newest units, or a whole writer, so
the reader compares `StreamHeads` with its own units, earlier fetches and
members' head statements; a peer that serves less is `Withheld`. A unit
outside the past of the latest snapshot unit counts there whether or not
its writer is in that snapshot's `covers`.

**Objects.** A reader asks an always-on peer, or a member that announced
the object in `ObjectHave`, for chunks with `ObjectWant`, checks each as it
arrives (section 3.3), and asks another party for one that fails. The
first `ObjectChunks` of each answer to an `ObjectWant` carries the header,
whichever chunk index the `ObjectWant` starts at, so that a reader that
holds nothing of the object can check the chunks of any answer. A
**state object**, a stream snapshot object that a snapshot unit or a space
snapshot's stream entry names, can be no larger than its adapter loads: a
reader whose adapter has a largest state MAY ask for its first chunk
alone, which carries the header, and fetches no further when the header's
`size` exceeds that state and the stream snapshot's framing. Once the
first chunk opens under the object's key, which binds `size`, a snapshot
unit that names the object fails its check (`BadCompaction`, section
3.6), and a stream entry that names it is dropped, as one whose object
does not read; a reader that cannot open the chunk asks another party. A
writer
uploads the header and chunks in any order with `ObjectChunks`; the
receiver answers `ObjectHave` with how many leading chunks it holds, so an
upload resumes after any interruption. Between members, a side that admits
the other for a space announces in `ObjectHave` every object of the space it
holds whole, and later the objects that the units it sends name, so that a
newcomer that starts from a snapshot reaches objects written before its
admission; "Sources between members" below says what else it announces.
Because sealing is deterministic (section 2.8), a holder that keeps an
object's plaintext and holds `k(S)` MAY seal its chunks again from the
plaintext when it serves them, rather than store them
([at-rest.md](at-rest.md), "Held objects"); a receiver cannot tell, and
checks what it receives as section 3.3 says either way.

**Sources between members.** On a member connection, each side counts the
other as a source of an object of an attached space from an `ObjectHave`
that names it until an `ObjectMissing` that names it, or until the
connection ends. A side asks a member only for objects it counts that
member a source of.

1. **Announcing.** Once a side admits the other for a space, it announces
   in `ObjectHave` every object of the space it holds whole; afterwards,
   the objects that the units it sends name and that it holds whole; and,
   for as long as the attach lasts, each object that becomes whole at it,
   however it arrived. It gathers the objects that become whole close
   together, waiting briefly, into as few `ObjectHave`s as their limit of
   4,096 locators allows, so that a fetch of many objects announces them
   in a few messages, not one each. A side announces an object that
   becomes whole to every attach of the space, whether or not the other
   side announced it before: the other side may have dropped it since.
2. **No answer is asked.** An `ObjectHave` between members asks for
   nothing. A side that receives one asks for no object it holds whole,
   and announces nothing in return: only an object becoming whole at a
   side makes it announce, so an announcement never brings a fetch or
   another announcement back from a side that holds the object.
3. **Answering what it lacks.** A side asked by `ObjectWant` for an object
   it does not hold whole, as one it dropped or its cache evicted
   ([at-rest.md](at-rest.md), "Retention"), answers `ObjectMissing` naming
   it, on the attach's sync stream, and sends no chunk of it. A side that
   holds the object whole answers with its chunks, and with nothing for
   chunks past the object's end. A side that serves nothing yet, before it
   admits the other, answers neither.
4. **Taking an answer.** A side that receives `ObjectMissing` no longer
   counts the other as a source of the objects it names: it awaits none of
   their chunks from it, and asks the other parties that it counts as
   sources, or a peer. A request for the object that no other connection
   will still try ends then, rather than after the wait for chunks that do
   not come. An `ObjectHave`
   that names the object again, as when the other side holds it whole
   once more, makes the other a source again.
5. **Bounds.** A side keeps, for each attach, every announced object its
   replica knows: one that a unit, a snapshot or a stream snapshot it holds
   names, or of which it holds anything. Of the announced objects it does
   not know, it keeps at most 65,536, and drops the rest as if they were
   never announced. A member learns of an object from the units its
   replica receives, so honest announcements exceed the bound only when a
   newcomer is announced more objects than that before it holds the
   snapshot that names them; the member that announced them is then not a
   source of the rest until it announces them again.
6. **Earlier implementations.** A side that does not know `ObjectMissing`
   drops it (section 2.14) and awaits the chunks it asked for as before; a
   side that announces nothing when an object becomes whole is a source of
   fewer objects. Either way both sides still interoperate.

`ObjectMissing` and these rules hold between members only. A peer never
sends `ObjectMissing`, and a device never sends it to a peer.

### 3.15 Partial replicas

A partial replica holds the space's **frame**, every space event, anchor and
storage event and the system stream, and the streams it opens. Placement and
the write rule read causal order through every stream, so it judges as
follows, and never applies a unit a full replica would refuse, except where
it has not been sent fork evidence:

- **Witnessed parents.** A parent outside its frame and streams is
  witnessed once the replica has fetched it and checked its envelope,
  signature and ID; of a scheme-2 signature, it checks the Ed25519 half,
  as a peer does. An event of its frame or streams is placed once each
  parent is placed, stubbed or witnessed. It fetches a witness's own
  parents only to learn a height.
- **Proven order.** It counts an event `x` as before an event `y` only when
  a chain of parents through the events it holds, placed or witnessed,
  leads from `y` down to `x`, as a `Path` that checks does. So it judges a
  unit `u` by the write rule over the space events it holds, counting a
  space event `x` as in the past of `u` only when `x` is among `u`'s
  parents, or in the past of such a space event through space events, or a
  `Path` from `u` down to `x` checks. It counts `u` as before an event `r`
  that ends its writer's write only when a `Path` from `r` down to `u`
  checks.
- **Heights.** It knows an event's height when it holds the event's whole
  past, each event of it placed, stubbed or witnessed. A space event
  usually cites its author's last unit, so many heights rest on witnesses
  whose own parents it does not hold, and it does not know them. Computed
  from the parents it holds, a witness with none at 1, such a height is
  only a lower bound. The
  roster orders concurrent roster events by height, in seniority, the
  seniority pick and the meet ([roster.md](roster.md)). A
  partial replica therefore MUST resolve the roster only when every two
  contested roster events of its view are proven ordered or both of known
  height, counting as contested here a roster event without standing
  ([roster.md](roster.md), section 3.7) whose author some event of its view
  names at `administer`, since its standing rests on an order. Until then it MUST hold every event of its view but the genesis
  pending, and it fetches by ID each parent it does not hold of an event in
  their pasts whose height it does not know, and witnesses it, until it
  knows the heights. A stub counts there once confirmed as section 3.9
  says. Catch-up serves parents by ID ([peers.md](peers.md)), and
  `Missing` names a stub for a collected one, so the replica always learns
  the heights. It then reads every order and height the procedure reads as
  a full replica does.
- **Pending, never applied.** A unit whose verdict depends on an order the
  replica has not proven is pending. A unit concurrent with its writer's
  removal can never be proven before it, so it is never applied: a full
  replica refuses it, and a partial replica holds it pending. So the write
  rule's step 2 refuses a unit as `NotAWriter` only when no roster event
  whose order with the unit is unproven could give its writer a path, and
  a response whose order with the unit is unproven leaves it pending at
  step 5 ([roster.md](roster.md)).
- **Syncing.** Its `Heads` name, in key 4, the system stream and the
  streams it holds, so that the other side sends it its frame and those
  streams, not every stream. It asks for a stream it opens later by
  `StreamWant`, and fetches by ID what it witnesses.
- **Citing.** Its own events cite as parents the maximal space events it
  holds, its own `prev`, and units of its streams whose parents are all
  placed or witnessed. It never builds on an event whose past it could not
  place.
- **Forks.** It sees fork evidence only in its frame and streams, and a
  witness is never fork evidence. A party that holds evidence about a
  device sends both events to every replica that holds either. Until then
  a partial replica may apply a forked device's unit, and it rebuilds when
  the evidence arrives.

### 3.16 Coverage

Units are covered as [crypto.md](crypto.md) says, through `prev` and
`parents` only. An object is covered through the unit that names it, since
its ID is an HMAC of its plaintext, which holds against a quantum
adversary; a snapshot unit covers its snapshot object so. A collected unit
needs no coverage: the snapshot unit that replaced it is covered by later
anchors. Head statements and sync messages are not history and are never
covered.

### 3.17 The adapter interface

An adapter is registered under a type (section 2.7) and provides, per
stream:

1. `encode(change) → content` and `decode(content, context) → change`, or a
   content refusal.
2. `apply(state, unit) → state`, which merges one accepted unit. For any set
   of accepted units, applying them in any order, any number of times each,
   MUST give the same state. A unit whose own dependencies are not yet
   applied MAY wait inside the adapter, and applies when they arrive.
3. `compact(state) → (snapshot state, metadata)`: the stream snapshot's
   `state` and the snapshot unit's content. Frasil fixes the cover and
   `excluded` from the cut; the adapter states which units of the cover its
   state includes.
4. `load(snapshot state) → state` and `rebuild(snapshot state or nothing,
   accepted units) → state`, which is `load`, then `apply` of each unit.
5. `export_history_free(state) → snapshot state`, or a refusal: the current
   state and what later merges need to apply units written after it, and
   nothing that shows earlier states. A unit that a concurrent branch wrote
   before the export's cut cannot be applied on top of it; a member that
   meets one asks for a fresh export (section 3.8). An adapter refuses an
   export that its `load` would refuse, such as one past its limits, and
   the caller then writes no history-free state of that stream.

Optionally, an adapter provides:

- capability checks;
- `hold(state, units)`: marks units the replica holds besides those handed
  over, such as a loaded snapshot's cover, as held;
- `reapply(original state, late unit, new state, writer) → content or
  nothing`, where `writer` is the re-applier's unit's place: the moved
  document's space and stream, the re-applier's device ID and the `seq`
  its unit takes. Only [ext-restricted-spaces.md](ext-restricted-spaces.md)
  uses it;
- its own sync.

The **context** of a unit is what an adapter may read besides its content:
the space ID, the stream, the unit's event ID, author, `seq` and height
([events.md](events.md)), its `objects` and `supersedes`, whether it is a
snapshot unit, its `resubmits` and `copied_from`, and the capabilities its
author holds at its place. A height from a stub is the stub's (section 3.9). Never the time,
randomness or another stream.

- **The past of a kept checkpoint.** A unit's verdict and context are a
  function of its place, which a replica that forgets the past of its kept
  checkpoint ([roster.md](roster.md), section 3.15.6) no longer holds.
  Before it forgets, it freezes, for each unit of that past it keeps,
  its verdict (accepted; refused by the write rule with its class, among
  them a write no path admits and one held as waiting; or its content
  refused by the adapter with its class), the capabilities its author
  held at its place as the adapter reads them (the meet over its paths at
  its highest level there, [roster.md](roster.md), section 3.3, which may
  keep one name in both modes), its attribution (the members it was
  written through there, each person's list read at that place, with their
  labels there, [roster.md](roster.md), section 3.11, when the write rule
  admits it, whatever its adapter made
  of its content), and the events that void
  it, and from then on hands that unit to its adapter with the frozen
  capabilities, never with what the checkpoint's record or any later place
  gives its author ([at-rest.md](at-rest.md), the `event` record's keys 6
  to 8). Every adapter is a pure function of the content and the context
  (below), so this freezes each one's outcome whole. Of the built-in
  adapters, Loro and records read capabilities, for suggestions and
  review: whether a unit applies, is a suggestion, or is a suggester's
  direct edit refused; blobs, file versions and drive read none, and their
  outcome is the frozen verdict and the author, which the envelope
  gives. Nothing else is place-dependent: canonical order reads
  heights, which dropped parents keep ([events.md](events.md), "Placement
  and order"), and Loro's overlap rule and `resubmits` read content and
  that order alone ([adapter-loro.md](adapter-loro.md)). So a replica that
  forgot shows exactly what one that kept everything shows, whatever
  became of the author after the unit: an edit by a writer lowered to
  reader before the checkpoint stays applied, a suggester's direct
  edit stays refused though it was raised to writer later, and an edit
  shows the labels its author had at it, though relabelled or removed
  since. Both read attribution at the unit's place, never the current
  roster, so a replica that kept everything shows no other label.
- **A newcomer** never judges a unit of the checkpoint's past: the space
  snapshot it starts from has its base at heads that hold the checkpoint
  (section 3.10, key 12), so that past is in the past of its base and
  decided, and its documents come from the stream entries' states, which
  cover the stream at the base. It takes those states on the sender's
  signature, as every newcomer takes its base ("A base", what a lying
  sender achieves); it cannot check them against units it never holds,
  and MAY ask a second member for the same streams and compare their
  states by meaning, reporting a difference as `BadCompaction` against
  the sender whose state a third member, or a later snapshot unit, does
  not confirm. A member that kept the units checks any snapshot unit
  against its cover as section 3.6 says. A newcomer, a "from now on" one
  included, therefore holds no unit of that past, derives no outcome for
  one and shows no attribution of past edits beyond what a stream's state
  carries: the state, history-free, is what it is entitled to.

**Accepted** units are those valid by the
write rule whose content the adapter does not refuse.

**Determinism.** Every function that affects state or a verdict MUST be a
pure function of its inputs: no clock, randomness, network, other stream or
other space, so that one adapter version gives the same state and content
refusals on every replica and platform. States are compared by meaning; an
adapter's document MAY also fix its snapshot bytes. A replica hands
accepted units over in canonical order when it rebuilds and in arrival
order otherwise, and the state MUST NOT depend on which. Frasil keeps the
rebuild set (section 3.8); an adapter keeps nothing else a rebuild needs.

**Object references.** An adapter that refers to an object writes
`[locator, key reference]` in its content and lists the locator in the
unit's `objects`. A built-in adapter refuses content that names an object
its unit does not list (`ObjectNotListed`).

**Content refusals.** An adapter refuses content that does not decode,
breaks its format's rules, or fails a capability check. The unit stays a
valid event, in its writer's chain, counted for stability and frontiers,
and kept; only its content has no effect. A replica lists content refusals
beside verdicts. Content of a version an adapter does not know is kept and
ignored (`UnknownContentVersion`).

**Capability checks.** An adapter registers checks by capability name:

```text
check(capabilities, context, content) → accept | refuse
```

- A writer's capabilities at a unit's place are those of its strongest
  path, merged as [roster.md](roster.md) merges concurrent grants. Through
  a grant of a space, they are what that grant passes on: the narrowing
  capabilities of the device's paths that propagate in the granted space,
  never a guest grant's there ([roster.md](roster.md), 3.3 "Grants of
  spaces and effective membership"). They are read at the granted space's
  current roster as the replica holds it, and at its earlier valid places
  only once the device no longer writes there ([roster.md](roster.md),
  "Checks across logs", "Paths"). So a narrowing the granted space adds later applies to
  the writer's earlier units through that grant too: a member made a
  suggester there has its earlier direct edits refused as content from
  then on.
- A replica finds the capabilities over the write rule's paths. When it
  finds no path for a unit the write rule found valid, the content is
  never checked as an unnarrowed writer's: if a path cannot be judged
  because a list or a roster it needs is not held, the content waits
  (`Pending`) until that log arrives; otherwise it is refused
  (`CapabilityRefused`), without the adapter's checks. The write rule
  admits no unit without a path, so this happens only where the two
  computations disagree, and it fails closed. Such content is neither
  accepted nor applied, and a snapshot unit with it is never used (section
  3.6).
- A replica judges a unit's content again whenever the capabilities it
  finds for the unit's author change: when its roster, a list, or a
  granted space's roster as it holds them change. It rebuilds the stream
  as for a verdict that changed (section 3.8).
- A check runs at every replica, after the unit is decrypted and found valid
  by the write rule and before `apply`, on every unit, snapshot units and
  seeds included. It reads the capabilities, the context and the content,
  never the stream's state, which would depend on arrival order.
- Every registered check runs on every unit, whether or not its author holds
  the capability the check is registered under, in ascending order of
  capability name, byte by byte. The first that refuses refuses the unit.
- A unit it refuses is refused as content (`CapabilityRefused`). A
  capability that extends a grant extends only what an adapter accepts,
  never `write`.
- [ext-ephemeral.md](ext-ephemeral.md) runs the same interface on ephemeral
  messages, with its own context. A frame whose sender is in, but for whom
  the receiver finds no path of its current view, is refused
  (`CapabilityRefused`), never checked as an unnarrowed writer's.

**`suggest`.** A writer whose grant carries `suggest` with mode `narrows`
is a **suggester**. Every built-in adapter checks it: a suggester writes
only suggestions, in the adapter's own form, and any other content or
snapshot unit from it, a seed included, is `CapabilityRefused`. Suggestions
are kept beside the main state until a writer that is not a suggester
accepts or dismisses them. With mode `extends`, `suggest` means nothing to
the built-in adapters.

**An adapter's own sync.** Two members that can both decrypt MAY run an
adapter's own sync over a member connection ([transport.md](transport.md)).
It MAY pick units and objects the other side lacks and send them as signed
units, which Frasil judges as any others, and MAY send previews, which are
never applied to accepted state, compacted or exported, and are dropped when
the units arrive or the connection ends.

**Cadence.** A client compacts a stream when its units since the last
snapshot reach 256, or 4 MiB, while it holds the stream's units whole.
[ext-file-versions.md](ext-file-versions.md) adds a cadence for a Blobs
stream whose units since the last snapshot carry supersessions.

### 3.18 Error classes

Besides [overview.md](overview.md)'s shared classes, events.md's envelope
classes, keys.md's key-reference classes and its `StaleSeal` (a unit after
a checkpoint sealed under a state outside its world, section 3.2, step
12: final, unlike `StaleKey`), and roster.md's write-rule classes and
`BadSeal`:

| Class | Meaning | Sort |
|---|---|---|
| `ObjectMismatch` | an object's bytes or plaintext are not the ones its locator names | final, for those bytes |
| `WrongSpace` | a space snapshot or head statement of another space | final |
| `UnknownMessage` | a sync message type from 18 to 63 this side does not know | decision |
| `StreamMismatch` | a unit's opening does not hash to its stream | report: content refused |
| `WrongAdapter` | a unit of another type than its stream's opening | report: content refused |
| `WrongStream` | a system type outside the system stream, or another type inside it | report: content refused |
| `UnknownAdapter` | a type this replica has no adapter for | report: content ignored |
| `UnknownContentVersion` | a content version the adapter does not know | report: content ignored |
| `ObjectNotListed` | content names an object its unit does not list | report: content refused |
| `CapabilityRefused` | a capability check refused the content | report: content refused |
| `BadCompaction` | a snapshot unit's covers, stubs or state do not match; or, with [ext-file-versions.md](ext-file-versions.md), its supersessions differ from the replica's derivation | report |
| `BadStub` | a stub that does not match its event | report, against the stub's signer |
| `BadStatement` | a head statement whose author cannot supply its heads | report, against its author |
| `StreamLinkBroken` | a wrong `stream_prev` | report |
| `StaleKey` | a unit sealed under a state older than the current one | report |
| `Unremovable` | a refused unit inside a settled snapshot that could not be undone | report |
| `Withheld`, `RolledBack` | a peer that serves less than a client knows of, or lost what it acknowledged | report, against the peer |

Adapter documents add their own content classes. An adapter document's
`Malformed`, said of content, refuses the content only; the unit's verdict
stands.

## 4. Security considerations

- **Stream types.** A writer that backdates a unit of another type cannot
  change a stream's type: another opening for a 128-bit stream ID is a
  second preimage.
- **Objects.** Junk uploaded under a genuine object's ID has another
  digest, so it is another locator, never named, and collected after
  `orphan_grace`. A reader checks every chunk before use and the whole ID at
  the end, so content assembled from two versions of a file fails.
- **A false snapshot** is attributed to its compactor, a writer who could
  write the same content as units. Replicas that hold the cover never use
  or collect it. A member that starts from it uses it until a correct one
  arrives. A peer collects nothing until the snapshot is stable at the peer
  or `T` passes.
- **Stubs** decide heights, and heights decide canonical order. One lying
  sender cannot reorder the space events a replica judges, because each
  stub under a space event is confirmed by a second writer or the event
  itself; a newcomer's base stubs, confirmed on the snapshot's signature,
  are the exception below. It can shift only the order among units, and
  every lie is attributable. A stub counts only from a source the replica judged: a
  unit that no record lets write, or one still pending, cannot make a
  replica place an event's descendants without it, and what a pending
  unit's own stubs placed stays out of the view until the unit is judged.
- **Body keys of units.** A handed body key opens one unit, and the
  seal's commitment admits only the key every holder of `k(S)` derives, so
  a sender can withhold a unit from a newcomer but not show it other
  content. A peer sees that a body-keys unit was written, never for which
  units.
- **A space snapshot's sender** can withhold or lie. Everything it hands is
  under its scheme-2 signature and checked against what the newcomer later
  holds; a newcomer whose only sender lies applies the lie provisionally.
  Its base stubs are confirmed on that signature alone, so a false height
  there can shift the order of the space events the newcomer places on
  them, at that newcomer only, until it starts from another member's
  snapshot (section 3.9, "A base").
- **Capabilities.** A replica that finds no path for a valid unit's author
  never treats it as an unnarrowed writer: the content waits or is refused
  (section 3.17).
- **Partial replicas.** Until fork evidence reaches one, a forked device's
  unit may stand there. A height it does not know never decides its roster:
  it waits for the past instead.
- **Rebuilds** cost about one `gap_key_timeout` of writes to the affected
  streams. A refusal inside a settled snapshot cannot always be undone.
- **Withholding.** A peer that acknowledges and then loses events is
  detected by every device that remembers the acknowledgement. What no
  client knows of yet, a peer can withhold until a head statement reaches a
  client by another path.
- **Adapters.** Replicas whose adapters disagree show different documents,
  never different verdicts. A member that runs an adapter's own sync can
  show false previews until the units arrive.

## 5. Test vectors

[units.json](vectors/units.json), with fixed seeds and nonces; each case
gives every intermediate value:

- `parameters`: section 2.1's limits, the `frasil:` types and the system
  stream's types.
- `units`: nine units byte for byte, from the content key through the
  body key and its commitment to the event ID: a plain unit, one naming two objects, a list copy carrying a device-list
  genesis, a body-keys unit, a move unit with padding, a re-submission with
  refs, a unit under a merged state, a unit of a restricted space, and a
  recovery-entry unit of a personal space.
- `list_events`: a `frasil/list-events` body and its `ListEvents` message,
  and a body with an event the writer drops.
- `unit_refusals`: thirty units refused by sections 3.1 and 3.2 with
  their classes, among them stubs of kinds 2, 5 and 6, a seal of 71 bytes,
  a seal opened under another state's key, a commitment that is not the
  body key's, and document and system units with the wrong opening.
- `handed_body_keys`: the plain unit opened under its body key alone, as a
  member that does not hold its state opens it once the key is handed
  over, and held (`Sealed`) under a key that misses its commitment.
- `supersessions`: a log unit naming two objects with a supersession of
  each, and a snapshot unit carrying two, byte for byte; and seven
  refusals of key 8 at step 11: a successor not in `objects`, a
  two-element supersession in a log unit, a three-element one in a
  snapshot unit, a 31-byte listing, a snapshot's predecessor not in
  `objects`, two supersessions out of order, and 4,097 of them
  (`Malformed`).
- `stream_types`: four stream IDs with their types and salts; an honest
  unit, a backdated unit of another type with its own opening
  (`StreamMismatch`), one under the true opening (`WrongAdapter`), and a
  move unit, each judged alone. `system_stream`: the ID the vectors use.
- `objects`: objects of one chunk, of three chunks (the chunk size lowered
  to 64 bytes) and empty. `object_refusals`: nine refusals of section 3.3,
  junk under the object's ID among them.
- `compaction`: a snapshot unit over three writers in two streams, its
  cover and boundary stubs, and a newcomer whose events stay pending
  without the stubs and are placed at a full replica's heights with them.
- `stream_snapshot` and `space_snapshot`: each format and four refusals,
  and for the space snapshot a stream entry whose opening gives another
  stream;
  the space snapshot carries a device-list genesis and an equivocation
  proof, and is provisional until the newcomer holds keys that hash to the
  sender's `kc`.
- `record_objects`: a checkpoint's record object, its header the
  checkpoint's self reference, read by a member with the checkpoint's
  content key, by a newcomer with the object key alone, and by a peer
  (steps 0 to 4); refused when read as the record of a checkpoint of
  another `seq` or another author (`BadCheckpoint`), read as any other
  object, an object under a key reference read as a record, and a 40-byte
  self reference at a peer (`Malformed`).
- `stubs_with_cuts`: a snapshot unit's and a space snapshot's stubs with and
  without cuts, accepted, and seven malformed; and a held unit compared
  with stubs of it: the matching one, one without its cut, one with another
  cut and one with another height (`BadStub`).
- `snapshot_checkpoint`: a space snapshot with keys 12 to 15, accepted, and
  eight refusals of their presence, order and contents (`Malformed`), two
  of them key 15 empty and naming an event key 7 does not carry.
- `head_statements` with five refusals, one of them the device's `ed` under
  another `kc`, another device ID (`NotAMember`); `statement_outcomes`: whom a
  missing head is reported against, with a peer's acknowledgement and its
  `Missing` answers on either side of `withholding_grace`.
- `stub_confirmation`: section 3.9's rule for one signer, two that agree,
  one signer twice, two that disagree, and the event fetched in full.
- `messages`: each of the eighteen types, an ignorable type the reader
  does not know, eight refusals, and a `Path` that checks.
- `settled`: section 3.6 at and around `gap_key_timeout`.
- `partial_replica`: a partial and a full replica's verdicts on a unit
  before, after and concurrent with its writer's removal, each with what
  the partial replica has proven: the removal in the unit's past, or the
  unit before the removal.
