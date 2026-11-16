# Space files
Protocol 1. Vectors: [ext-space-files.json](vectors/ext-space-files.json).

This extension specifies a **space file**: one space, or the part of it an
exporter chose, in a file that any implementation of protocol 1 reads. The
file carries the space's events, units and objects as a peer serves them,
and a **way in**: the secrets a reader derives content keys from, invite
fragments that admit a new device with nobody online, or nothing. A reader
checks what the file holds exactly as it checks a peer's answers; the file
is an untrusted carrier. It depends on [overview.md](overview.md) for
conventions and error classes, [events.md](events.md) for placement,
[roster.md](roster.md) for the roster, [keys.md](keys.md) for states and
their derivations, [units.md](units.md) for units, objects, the space
snapshot and sync, [admission.md](admission.md) for the newcomer's
snapshot, and [ext-invite-links.md](ext-invite-links.md) for invite keys
and claims.

A core implementation that does not implement it:

| What this document defines | A core implementation |
|---|---|
| The file, its records and its way in | reads and writes none; a space reaches it by sync alone |
| Labels `frasil/space-file/key/v1` and `frasil/space-file/way-in/v1` | never uses them |

Nothing in a log, roster, unit or object refers to a space file, so no
replica's verdict depends on this extension. A file holds what the wire
holds; its checks are a replica's checks.

## 1. Overview

- A file is a **magic** line and a sequence of **records** in segments:
  the export's, then one per append. A segment holds events, objects and
  sections of the application's own, the export's also the way in and a
  space snapshot, and each segment ends with a **manifest**. The last
  manifest a reader can read whole says what the file holds.
- Events travel in wire form, signed, each after its parents. Objects
  travel as header and sealed chunks. Nothing in a file is new on the wire.
- The **way in** is the only secret in the file: rotation secrets, so that
  a copy reads for as long as it exists; invite fragments
  ([ext-invite-links.md](ext-invite-links.md)), so that a new device admits
  itself from the file alone; or nothing. It MAY be sealed under a
  32-byte **file key** the application supplies.
- A reader is one of four: a **member** already, who merges the file as
  sync by another road; a **claimant**, who signs a successor as an invite
  key the file carries; a **reader by keys**, who holds the space as a
  replica with no grant, reads everything, and writes nothing; or
  **nobody**, when the file carries no way in the reader can use.
- An invite in a file grants `read` or `write`, never `administer`.
- A **save** appends to a file; a reader ignores a truncated tail, so an
  append that did not finish loses that append and nothing before it.
- The file is generic. The application names its **kind**, which says what
  it expects to find in the space, and a reader refuses a file of another
  kind before it reads an event.

## 2. Formats

### 2.1 The file

```text
file   = magic || record*
magic  = "FRASIL-SPACE-FILE/1\n"                     20 bytes
record = u32be(len(body)) || body                     body: deterministic CBOR
```

- A record's body is at most 1,052,672 bytes, one sync message
  ([units.md](units.md), section 2.1). A longer length is `TooLarge`,
  wherever it stands in the file: a reader cannot walk past it.
- A body is a map whose key 0 is the record's type, an unsigned integer.
  Types 7 to 63 are reserved: a reader that finds one it does not know
  refuses the file as `UnsupportedVersion`. Types from 64 are the
  application's, or a later extension's, and a reader that does not know
  one skips the record.
- A magic that begins `FRASIL-SPACE-FILE/` with another version is
  `UnsupportedVersion`; any other first 20 bytes are `NotASpaceFile`.

### 2.2 Records

| Type | Name | Keys | Rule |
|---|---|---|---|
| 0 | `Manifest` | section 2.3 | ends the segment of an export or an append with the file's state then; the last one a reader reads whole wins |
| 1 | `WayIn` | 2: a way-in body, or 3: its sealed form (section 2.4); exactly one of the two | at most one; in the export's segment, before any event |
| 2 | `Event` | 2: one signed event, bytes | as `Events` carries them ([units.md](units.md), section 2.14): each after its parents, in the exporter's canonical order |
| 3 | `Snapshot` | 2: a space snapshot, bytes ([units.md](units.md), section 2.11) | at most one; present exactly when the manifest's `history` is 1, before any event; the frame's events follow it whole, and of the streams only the units outside its base |
| 4 | `ObjectHeader` | 2: locator, bytes(64); 3: the object's header, bytes | before the object's chunks |
| 5 | `ObjectChunk` | 2: locator, bytes(64); 3: chunk index, unsigned; 4: one sealed chunk, bytes | as `ObjectChunks` carries one ([units.md](units.md), section 2.14) |
| 6 | `Section` | 2: kind string; 3: name, text of 1 to 255 bytes; 4: bytes | the application's: a later section of one kind and name replaces an earlier |

Every key named is required; another key, a value of another type, or a
limit broken is `Malformed`. A **kind string** is 1 to 64 bytes of UTF-8
without a control character or white space.

### 2.3 The manifest

| Key | Name | Value |
|---|---|---|
| 1 | `space` | bytes(32): the space ID |
| 2 | `kind` | kind string: what the application expects to find in the space |
| 3 | `heads` | array of 1 to 4,096 event IDs, strictly ascending: the exporter's heads of the space at the export or the append |
| 4 | `streams` | array of 1 to 4,096 stream IDs, bytes(16), strictly ascending: the streams whose units the file holds; absent for every stream |
| 5 | `history` | 0, full history; 1, from a space snapshot |
| 6 | `objects` | array of 0 to 4,096 locators, strictly ascending: the objects the file embeds |
| 7 | `exporter` | bytes(32): the exporting device's device ID |
| 8 | `time` | unsigned: the exporter's wall clock, seconds since 1970-01-01T00:00:00Z; absent when not known |
| 9 | `revision` | unsigned: the revision the file was written under ([overview.md](overview.md), section 5.6) |

- A manifest without key 9, or of a revision other than the reader's, is
  `RevisionMismatch`, checked before any other key: the file was written
  under another revision, and its units may not open under this one.
  Every manifest of a file carries the first manifest's revision.

- The first manifest in a file ends the export's segment. Each append
  writes its records, then a manifest with `heads` and `objects` grown. A
  reader uses the last manifest it reads whole, and the records before it;
  `space`, `kind`, `streams`, `history` and `exporter` MUST be the first
  manifest's in every later one, else the file is `Malformed`.
- **The manifest is not signed.** `exporter`, `heads` and `time` are the
  writer's claims, which nothing checks: what a reader believes of the
  space is what the events prove, and `heads` only names what the frame
  check reaches for (sections 3.4 and 3.6). A file cut back to an
  earlier manifest is indistinguishable from an older copy of it.
- **Sniffing.** A reader finds a record's type without decoding its body:
  deterministic CBOR puts key 0 first, so the body begins with the map's
  head, one byte for up to 23 keys and up to nine for more, the key
  `0x00` and the type. Walking the records by their lengths
  and reading each type, the magic, the way in's record and the first
  manifest give the kind, the space ID, the history, and the way in's
  presence and whether it is sealed, without reading an event.

### 2.4 The way in

```text
way-in body = CBOR {1: 1,
                    2: [[rotation ID (32), k_R (32)], ...],        0 to 64, strictly ascending by ID
                    3: [fragment (97), ...],                         0 to 64
                    4: label (text, 1 to 255 bytes; optional)}

sealing key = HKDF(salt = none, ikm = file key, info = "frasil/space-file/key/v1")
sealed form = nonce (24) || XChaCha20-Poly1305(sealing key, nonce, way-in body,
                           aad = "frasil/space-file/way-in/v1" || space ID)
```

- Key 2 holds **rotation secrets**: a rotation's event ID and its content
  key `k_R` ([keys.md](keys.md), section 2.1), from which a reader derives
  `k(S)` for every state the file's units name (section 2.2 there). The
  way in carries no upload seed and no grant seed: a reader by keys
  uploads nothing and grants nothing.
- Key 3 holds **invite fragments**: the 97 bytes of a fragment
  ([ext-invite-links.md](ext-invite-links.md), section 2.1), not its
  base64url text. Each admits one claimant.
- Key 4 is a label the application shows, such as what the way in is for.
- Reading a body, in order: deterministic CBOR, a map with keys 1 to 4
  only, keys 1 to 3 present, the types and limits above (`Malformed`); key
  1 is 1 (`UnsupportedVersion`). A fragment inside reads as
  ext-invite-links.md reads one, and names this space (`Malformed`).
- The **file key** is 32 bytes the application supplies, as the unlock key
  of kind 2 is ([at-rest.md](at-rest.md), section 2.1): from a passphrase
  through a memory-hard derivation, a keychain item, a hardware token. The
  sealing key is derived from it, because the file key may serve
  elsewhere. The nonce is random per seal. A sealed form that does not
  open under the key tried is `Decrypt`; one shorter than 40 bytes is
  `Malformed`.

### 2.5 Order and limits

- A `WayIn` and a `Snapshot` come in the export's segment, before any
  `Event`. A second `WayIn`, or a second `Snapshot`, is `Malformed`, as is
  an `Event` before the `Snapshot` of a file whose `history` is 1, a
  `Snapshot` in a file whose `history` is 0, or a file whose `history` is 1
  and holds no `Snapshot`.
- An `Event` names the manifest's space, is at most 1,048,576 bytes, and
  keeps [events.md](events.md)'s limits; a chunk is one frame
  ([transport.md](transport.md)). An `ObjectChunk` whose locator no
  `ObjectHeader` preceded is `Malformed`.
- An `Event` before one of its parents is not refused: a reader holds it
  pending, as a replica holds a peer's event whose parent it lacks
  ([events.md](events.md)), until the parent is read. An `Event` the
  reader holds already changes nothing. Whether the file reaches its
  manifest's `heads` is the frame check's to decide (sections 3.4 and
  3.6).
- A record's limits are checked as it is read; a record that breaks one
  refuses the file, with the class, and nothing of it is kept.

### 2.6 Appending and truncation

- A **save** appends, after the last manifest, every event the device
  holds of the space's frame and the manifest's streams outside the past
  of the manifest's `heads`, each after its parents; the header and chunks
  of every object it embeds anew; and then a new manifest. It never
  rewrites what precedes.
- A reader takes the last manifest it reads whole, and the records before
  it. A tail after it, from an append that did not finish, is ignored: a
  length past the end of the file, or a record that is `Malformed`, with
  no manifest read whole after it. A `Malformed` record followed by a
  manifest that reads refuses the file as `Malformed`; so does a file with
  no manifest. A reserved type (`UnsupportedVersion`) or a length over the
  limit (`TooLarge`) refuses the file wherever it stands, a tail included:
  neither is what an unfinished write leaves.
- An exporter that finds the appended part larger than its application's
  threshold rewrites the file from a space snapshot (section 3.6).

### 2.7 Labels and error classes

Labels, from [crypto.md](crypto.md)'s registry: `frasil/space-file/key/v1`
and `frasil/space-file/way-in/v1`.

| Class | Meaning | Sort |
|---|---|---|
| `NotASpaceFile` | the file does not begin with the magic | decision |
| `WrongKind` | the manifest's kind is not one the reader accepts | decision |
| `NoWayIn` | the reader holds the space neither as a member, nor can claim a fragment, nor derive its keys | decision |
| `OtherSpace` | the file is of another space than the one an append is for | decision |

With [overview.md](overview.md)'s `Malformed`, `UnsupportedVersion`,
`RevisionMismatch`, `TooLarge`, `Decrypt` and `Sealed`; [events.md](events.md)'s `Pending`;
[keys.md](keys.md)'s `KeyMismatch`; and, for a claim,
[ext-invite-links.md](ext-invite-links.md)'s classes.

## 3. Procedures

### 3.1 Export

`export(space, options)`, where the options name the streams (every one,
or some), the history (full, or from a snapshot), the objects to embed,
the way in, the file key or none, and the sections. In order:

1. Write the magic.
2. Write the way in, if any: the rotation secrets of every rotation of
   every state the included units name, those the device holds and no
   others; the fragments of the invites the application asked for, each a
   fresh invite the device grants as [ext-invite-links.md](ext-invite-links.md),
   section 3.1, says, at the level asked for, `read` or `write`, with
   `history` 1 for a full file and 0 for a snapshot file; sealed under the
   sealing key when a file key is given.
3. With history from a snapshot: write the space snapshot the device takes
   at its heads ([admission.md](admission.md), section 3.11), as it would
   hand a newcomer, and the stream snapshot objects it names as objects.
4. Write every event of the space's frame the device holds, its space
   events, anchors, storage events and the units of the system stream
   ([units.md](units.md), section 3.11), and the units of the included
   streams, in canonical order ([events.md](events.md)), so that each
   follows its parents; with history from a snapshot, only the units
   outside the snapshot's base, since the snapshot's stubs stand for the
   rest, while the frame is written whole, as a newcomer fetches it
   ([units.md](units.md), section 3.10, step 4).
5. For each embedded object, its header, then its chunks in order. A
   device that holds the object's plaintext as the application's file
   seals the chunks again ([at-rest.md](at-rest.md), "Held objects").
6. Write the sections.
7. Write the manifest: the device's heads of the space as they were when
   step 4 began, the streams, each once and ascending whatever the caller
   gave, the history, the locators embedded, the device's device ID and
   its wall clock, if known.

A device that writes in the space between step 4 and the end exports the
heads step 7 names: an export reads the store at one version. An invite
granted for a file is a roster event of the space, which the export
includes, so the file carries its own invite entry.

### 3.2 Append

`append(space, file)`, in order:

1. Read the magic and the last manifest.                        else its class
2. The manifest's space is the space.                            else OtherSpace
3. Write what section 2.6 says, then a manifest as section 3.1's
   step 7 writes it, with the streams, history and exporter of the
   first manifest.

### 3.3 Sniff

`sniff(file)` reads the magic, walks the records by their lengths and
types to the first manifest, and reads that manifest and the `WayIn`
record's form, if one is present. It opens nothing and decodes no event.
Its classes are section 2.1's and the manifest's.

### 3.4 Import

`import(device, file, file key or none)`, in order:

```text
1. Read the magic, the first manifest and the last manifest.     else NotASpaceFile /
                                                                      UnsupportedVersion /
                                                                      RevisionMismatch / Malformed
2. The manifest's kind is one the caller accepts.                else WrongKind
3. The device holds the space, as a member or by keys; a
   claim that waits for consent holds nothing: place every
   event as a peer's Events, keep every object's parts as
   ObjectChunks, and judge the space again (units.md,
   section 3.14). The way in is ignored.                         → Member, as a member;
                                                                 → Rereading, by keys alone
4. Else read the way in, unsealing it with the file key.         else Sealed (no key) /
                                                                      Decrypt / its class
5. The first fragment that reads and passes the claim's
   checks (section 3.5, steps 1 to 4): stop with its offer.      → Invited
   On the person's consent, sign the successor.                  → Claimed
6. Rotation secrets: hold the space as a reader (section 3.6).   → Reading
7. Otherwise: no way in, or the last fragment's refusal.         → NoWayIn / its class
```

- Step 3 is sync by another road: the device checks each event as it
  checks a peer's ([units.md](units.md), section 3.1 and 3.2) and each
  object as it checks a fetched one (section 3.3), and merges. The way in
  is ignored, whatever it would grant. A device that holds the space by
  keys alone (section 3.6) merges the same way and still has no grant:
  `Rereading`, so that the application does not take it for a member.
- Step 5 tries the fragments in the way in's order. One that is refused
  at any of section 3.5's checks, `NoWrap`, `InviteUsed`, `Expired` and
  the rest, is skipped and the next tried; when none passes, step 6 runs,
  and with no rotation secrets either the import fails with the last
  refusal's class. A fragment that passes stops the import with the
  **offer**: the inviter, the level, the expiry, and the way in's label.
  The device signs nothing until the person consents; declined, it keeps
  nothing of the file. Undecided, the claim waits as a claim by link does
  ([ext-invite-links.md](ext-invite-links.md), section 3.2, step 10).
- Steps 5 and 6 take the file's events, snapshot and objects as step 3
  does, once the device holds the space. An event that fails any check is
  refused with its class, and every event after it that depends on it
  stays pending, as a replica holds a peer's events whose parents it
  cannot place ([events.md](events.md)).
- A file with a sealed way in and no file key stops at step 4 as `Sealed`:
  the caller may ask for the key and import again.

### 3.5 The claim from a file

A claimant walks [ext-invite-links.md](ext-invite-links.md), section 3.2,
with the file in place of peers:

1. The fragment names this space, and reads (step 1 there).
2. In place of the drop (steps 2 and 3): the invite entry the fragment
   names is an `Event` of the file, its delivery holds a wrap that opens
   with `K`'s X-Wing seed, for the space ID, the delivery's key names and
   recipient `K` ([keys.md](keys.md), trial decryption).    else NoWrap
3. In place of fetching (step 4): with history from a snapshot, the
   file's `Snapshot` is the snapshot for `K`, used first; the file's
   events are the space's events, the invite entry among them, since the
   frame is written whole.
4. Steps 5 to 9 as there, on what the file holds: the entry is the
   space's, grants exactly `[3, K]`, and is valid in the resolved roster;
   no successor, removal or race stands against it; its expiry holds.
   The import stops here with the offer (section 3.4, step 5). On the
   person's consent, step 10: the claimant signs the successor as `K`.
5. Step 11 runs when the device next meets a peer or a member: the
   successor waits in the outbox ([at-rest.md](at-rest.md)).

A device that can claim more than one fragment of the file claims the
first that reads and passes; the rest stay for other devices. A claimant
that signed a successor is a member from then on: its later imports of
the file take step 3 of section 3.4.

### 3.6 Reading by keys

A reader by keys holds the space as a replica with no grant:

1. For each rotation secret of the way in: the rotation's event is among
   the file's space events, and the read credential derived from `k_R`
   ([keys.md](keys.md), section 2.2) has the public key the event's
   visible key 11 names, as section 3.5 there checks a received secret;
   else `KeyMismatch`, and the import fails. It keeps each as that
   rotation's content key, and derives `k(S)` for each state the units
   name.
2. With history from a snapshot, it uses the snapshot first
   ([units.md](units.md), section 3.10): the snapshot's space is this one,
   its sender's Ed25519 half verifies, and its ML-DSA-65 half once the
   reader holds keys that hash to the sender's `kc`, from the roster or
   any other source.
3. It places the file's events and judges the roster and the keys over
   them, by the public keys the file's events carry; it opens each space
   event with the body key its secrets derive, and each unit with the
   body key its state's key derives ([units.md](units.md), section 2.4).
4. It keeps the space once the space's frame has checked through to the
   manifest's `heads`: every head is placed and valid. Otherwise it keeps
   nothing of the file: what it stored meanwhile is forgotten
   ([at-rest.md](at-rest.md), section 3.4), and the import fails with the
   first refusal's class, or `Pending` for a head the file does not reach.

A reader is not a member: `level` is none, it signs nothing in the space,
and a write there is `NotAMember`. It reads what the exporter could read
at export, and nothing written after a rotation it was not given, which
is the ordinary "from now on". A copy read by keys reads for as long as it
exists. It MAY later meet members and peers and fetch what the file left
out, such as objects not embedded; a peer serves it under the read
credential of a state it derives ([keys.md](keys.md), section 2.2).

### 3.7 Compaction

A rewrite from a space snapshot drops history as a stream snapshot does: a
reader by keys of such a file, or a claimant of it, sees nothing before
the snapshot's base, as a member admitted from now on does. The exporter
decides when, by its application's threshold; the file's semantics do not
change.

## 4. Security considerations

- **The way in is the secret, and the only one.** With rotation secrets in
  the clear, whoever holds the file reads the space as the exporter could.
  Sealed, the file key is the protection, and [at-rest.md](at-rest.md)'s
  words apply: a key kept beside the file protects nothing.
- **An invite is a capability.** A fragment in a file admits whoever opens
  it first, within its expiry, at its level. An exporter SHOULD give an
  invite in a file the shortest lifetime the use allows, and an
  administrator can revoke it ([ext-invite-links.md](ext-invite-links.md),
  section 3.6). An invite grants `read` or `write`, never `administer`, so
  a device other than the exporter's never gains full control through a
  file alone.
- **Nothing un-shares.** A file is a copy that was shared; a rotation
  afterwards protects what is written afterwards.
- **A file is evidence.** Every event in it is signed, so a file shows who
  wrote what, as a replica would. An exporter that hands a file to someone
  outside the space hands over attribution too.
- **What the file reveals without its way in** is what a peer sees: the
  space ID, stream IDs, sizes, the writers' Ed25519 keys and device IDs
  and the causal
  shape ([overview.md](overview.md), section 4.1). A sealed way in adds
  nothing to that.
- **A file is untrusted.** Every event, snapshot and object in it passes
  the checks a peer's answers pass; a file claims nothing about membership
  that a reader believes without the roster proving it. The manifest is
  the writer's word alone (section 2.3): whoever holds a file can cut it
  back to an earlier manifest, or write one naming any exporter, heads
  and time, and no reader can tell.
- **Not defended:** a file key that is a weak passphrase; a reader by keys
  that keeps a copy; a file left where the application's own copies are
  not defended.

## 5. Test vectors

[ext-space-files.json](vectors/ext-space-files.json):

- `fixtures`: the space the files carry: a founder `A` that grants a
  second device `B` `administer`, both writing units of one records
  stream, an invite by link from now on, and a third device `C` that
  claims it; every rotation's content key, the invite's fragment and the
  file key.
- `records`: each record type, from its fields to its encoding, a body at
  the limit, and an ignorable type, read as such, once with 24 keys, whose
  map head sniffing reads past; `record_refusals`: a
  body one byte over the limit (`TooLarge`), a reserved type
  (`UnsupportedVersion`), and values refused as `Malformed`.
- `way_in`: a body in the clear and its sealed form under the file key and
  a fixed nonce, with the sealing key and the associated data; refusals:
  the wrong key and another space's associated data (`Decrypt`), a short
  sealed form, a fragment of another space, version 2, 65 secrets, and
  secrets out of order.
- `files`: three full-history files of the space, with the way in by keys
  in the clear, sealed, and absent, each sniffed; the roster and the units
  a replica that holds everything reads; and the roads in: a member that
  holds the space (nothing new); a reader that holds it by keys already
  (`Rereading`); a reader by keys, with the content keys
  it derives and the roster and the units it reads, equal to the
  replica's; a sealed way in without the key (`Sealed`) and with it
  (`Reading`); no way in (`NoWayIn`); another kind (`WrongKind`); a
  rotation secret that misses its rotation's read credential
  (`KeyMismatch`); the events out of parent order, read all the same; and
  a head the file does not hold (`Pending`).
- `snapshot_file`: a history-free file with an invite's fragment: its
  snapshot, taken at the invite's base with the body keys the invite key
  cannot derive, the frame whole and the units after the base; the
  claimant's road: its wrap in the invite entry, the content key it opens,
  that the invite is open and unexpired, the offer the import stops with,
  the successor it signs on consent, and the roster afterwards; a file
  whose first fragment names an entry the file lacks, skipped for the
  second; and one whose only fragment is refused, read by its keys;
  refusals: an event before the snapshot, two snapshots, a snapshot in a
  full-history file, and history 1 without a snapshot.
- `appends`: a file after one append, whose second manifest wins; the same
  file with a truncated tail, read as the first manifest described it; a
  record that does not read before the last manifest, refused; and an
  append to another space (`OtherSpace`).
- `refusals`: `NotASpaceFile`, `UnsupportedVersion` for a magic of version
  2 and for a reserved record type, before the first manifest and after
  the last; `TooLarge` for a length over the limit; and files refused as
  `Malformed`: no manifest, and a magic alone; and `RevisionMismatch` for a
  first manifest without its revision and for one of another revision. Each says
  whether sniffing
  refuses it too, which it does when the fault lies before the first
  manifest.
- `held_object`: an object embedded from a plaintext the application holds,
  whose header and chunks equal the stored object's byte for byte.
