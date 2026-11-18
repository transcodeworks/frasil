# At rest
Protocol 1. Vectors: [at-rest.json](vectors/at-rest.json).

This document specifies what a Frasil client keeps on its device and how it
is sealed: the sealed device keys, the store of sealed records and its
tables, the rules for committing, restore detection, keys for the
application's own data, objects the application holds in place of their
sealed chunks, and what is never written. It depends on
[overview.md](overview.md) for conventions and the timeline,
[crypto.md](crypto.md) for primitives and labels, [events.md](events.md)
for logs and chains, [identity.md](identity.md) for the person ID and a
passkey's unlock key, and [units.md](units.md) for objects.

## 1. Overview

- **Everything Frasil writes on a device for its own use is sealed:** keys,
  events, objects, the outbox, acknowledgements, caches and counters, under
  one chain of keys:

  ```text
  unlock key (kind 1, a passkey's; kind 2, another source's)
    └── sealed device keys: the three seeds and the store secret s
          ├── seal_key(s), tag_key(s)         device-wide records, scope tags, the mark
          └── log key L, one per log
                └── seal_key(L), tag_key(L)   the log's records, item tags
  ```

- **An application MAY hold a space's objects itself** on a device, in
  place of their sealed chunks (section 2.8): the plaintext is the
  application's own file, and Frasil keeps the object's header and one
  `held` record, and seals the chunks again from the plaintext when it
  serves them. Units stay sealed: a unit's signature covers its sealed
  envelope, so its stored form is its only form.
- **Only the device produces a record that it opens,** and a record opens
  only at its own address, so a result the device kept, such as "this
  event's signature verified", can be trusted when read back.
- **A restored device does not fork its chain.** It detects a restore where
  the platform gives a place no backup restores, and syncs each log before
  it signs there.
- **A space is forgotten for good** by deleting one record, its log key.
- **What the application keeps is its own:** its database, rendered
  documents, an adapter's caches, indexes, exports, logs. Frasil derives
  keys for it (section 2.7) and protects nothing else of it.
- A store is read only by the device that wrote it. Data moves to another
  device by sync, never by copying a store.

## 2. Formats

### 2.1 What the application provides

| Interface | Holds | Requirement |
|---|---|---|
| A place for the sealed device keys | one 235-byte blob | durable |
| The unlock key of kind 2 | 32 bytes of high entropy | from a keychain, a secure element or a hardware token; never a password; never stored in the clear beside the sealed device keys |
| The store | addresses to records | `get(address)`; `scan(prefix)` in address order; `commit(puts, deletes)`, atomic, its deletes applied before its puts, and durable when it returns; optionally with a precondition (section 3.3) |
| The device-bound slot, if any | the 65-byte mark | `read()` and `write(bytes)`, durable, in a place no backup restores (section 3.5) |
| An object provider, if any | the plaintexts of held objects | `stat(token)`, `open(token)`, `create(space ID, object ID, size, hint)` and `forget(token)` (section 2.8) |

A put replaces whatever its address held, so an address holds one record
at most, and a record written twice is that record. A read, `get` or
`scan`, sees every commit that returned before it began. A client relies
on both: the next `seq` comes from the head it reads, and an event retried
is the same record at the same address.

The store holds only Frasil's records, and Frasil writes nothing else. A
held object's plaintext is the application's, where its provider keeps it.

### 2.2 Sealed device keys

```text
offset  length  field
0       1       version = 0x01
1       1       key kind: 0x01 or 0x02
2       32      device ID ([crypto.md](crypto.md), "A device's keys")
34      32      person ID, or 32 zero bytes for a device member
66      24      nonce, random
90      145     XChaCha20-Poly1305 ciphertext and tag                  235 bytes

aad         = "frasil/sealed-device-keys/v1" || blob[0..66]
sealing key = kind 1: the unlock key a passkey derives for the person, as it is;
                      never with a zero person ID
              kind 2: HKDF("frasil/unlock-key/v1", unlock key, "frasil/sealed-device-keys/v1")

plaintext   = 0x01 (layout version) || identity seed (32) || X-Wing seed (32)
              || ML-DSA-65 seed (32) || store secret (32)                       129 bytes
```

- A kind 1 key is the passkey's unlock key ([identity.md](identity.md)),
  derived for this purpose alone and used as it is. A kind
  2 key comes from the application and may serve elsewhere, so Frasil
  derives the sealing key from it and uses the key itself for nothing.
- A device draws all four secrets from its random source when its keys are
  made ([crypto.md](crypto.md)); the store secret is drawn even where test
  fixtures derive the other seeds. The store secret never changes while the
  device exists.
- Re-sealing, under a new passkey or kind 2 key, makes a new blob with a
  new nonce; the keys inside never change.

### 2.3 Keys, addresses and records

```text
seal_key(K)         = HKDF(none, K, "frasil/at-rest/seal-key/v1")
tag_key(K)          = HKDF(none, K, "frasil/at-rest/tag-key/v1")
app_key(K, purpose) = HKDF(none, K, "frasil/at-rest/app-key/v1" || field(purpose))

address   = scope_tag (16) || u8(table) || item_tag (16)                  33 bytes
scope_tag = 16 zero bytes                                           for a device-wide table
          = HMAC(tag_key(s), "frasil/at-rest/scope/v1" || log ID)[0..16]  for a log's table
item_tag  = HMAC(tag_key(K), "frasil/at-rest/item/v1" || u8(table) || field(item))[0..16]

record    = u8(1) || nonce (24) || XChaCha20-Poly1305(seal_key(K), nonce, plaintext, aad)
plaintext = field(item) || value
aad       = "frasil/at-rest/record/v1" || u8(1) || address
```

- `K` is the store secret `s` for a device-wide table, and the log's key
  `L` otherwise. A log key is 32 random bytes, drawn when the device first
  keeps anything of a log, a space's or a person's list, and kept in its
  `log` record. A seal key only seals and a tag key only tags.
- The **item** is what a record is about: an event ID, an object part, a
  key's name. It never appears in an address in the clear. It is inside the
  record, so a scan of a table yields each record's item.
- The scope comes first, so a log's records share a 16-byte prefix and
  deleting a log is one range. The scope tag is under `s`, so the device
  finds a log's prefix without its log key.
- The nonce is new at every seal. Because the address is associated data, a
  record moved to another address, table, log or item does not open. A
  record is 45 bytes plus its item plus its value, and at most an event's
  limit ([events.md](events.md)) plus its item and 45 bytes.

### 2.4 Tables

| Code | Table | Scope | Item | Value |
|---|---|---|---|---|
| `0x00` | `head` | device | empty | section 2.5 |
| `0x01` | `log` | device | log ID (32) | `u8(log kind) \|\| L (32)`: kind 1 a space, 2 a device list |
| `0x02` | `timeline` | device | empty | the last kept reading ([overview.md](overview.md), section 6.3) |
| `0x03` | `epoch` | The device starts its next run at an epoch it already used, or one below it (section 3.3). A receiver that accepted a higher epoch of the device refuses everything it sends in this run as `Replayed`. One that accepted the same epoch refuses its ephemeral slot values, and its ephemeral messages but those within the 64-counter window it never accepted, until the device's counter passes the highest it accepted ([ext-ephemeral.md](ext-ephemeral.md), section 3.2). Each later start uses one more, so the loss ends once the device is past the highest epoch it used. Nonces stay random, so nothing is sealed twice under one nonce. | `Replayed` at receivers; nothing at the device |
| `0x04` | `next_endpoint` | device | empty | 32 bytes: the seed of the member endpoint key this device announced as its next ([ext-next-endpoints.md](ext-next-endpoints.md)) |
| `0x05` | `deposit_keys` | device | the peer's ID (32) | `{1: seen, 2: latest, 3: 1, 4: paused}`, keys 1 and 2 present: what the device keeps of a peer's deposit keys ([ext-deposit-tokens.md](ext-deposit-tokens.md), 3.2): the issuing keys it has seen there, each `[key ID (32), first sight]`, the first sight a timeline's `T`, oldest first, the newest 1 to 64; its latest key list, 1 or 2 entries `[key ID (32), public key (32), role]` with exactly one of role 1 and no key ID twice, as `TokenKeys` key 2 carries it; `1` once the peer is `KeyInconsistent`; the reading at which the peer answered a draw `allowance_exhausted` (3.11) |
| `0x06` | `token` | device | the peer's ID (32) `\|\|` the token's nonce (32) | the token, 129 bytes, version 1, whose nonce is the item's: an unspent deposit token of that peer ([ext-deposit-tokens.md](ext-deposit-tokens.md), 3.5) |
| `0x07` | `deposit` | device | a deposit ID: 16 random bytes | `{1: peer, 2: address, 3: item, 4: first, 5: attempts, 6: next, 7: token}`, keys 1 to 6 present: a deposit in a device mailbox that the peer has not accepted yet ([transport.md](transport.md), "A sender keeps what was refused"): the origin of the peer, a text of 1 to 512 bytes; the mailbox's address (32); the item, 1 to 262,144 bytes; the reading of the first attempt; the attempts refused or unanswered so far; the timeline's `T` before which the device does not try again; and, once the device sent it with one, the token, 129 bytes, that pays for it ([ext-deposit-tokens.md](ext-deposit-tokens.md), 3.6) |
| `0x10` | `event` | log | event ID (32) | section 2.5 |
| `0x11` | `object` | log | object ID (32) `\|\| u32be(part)` | part 0: the object's header; part `i` ≥ 1: chunk `i − 1`, as received, at most 1,048,576 bytes ([units.md](units.md)) |
| `0x12` | `key` | log | `u8(key kind) \|\| name` | section 2.5 |
| `0x13` | `outbox` | log | author (32) `\|\| u64be(seq)` | the ID (32) of an event this device signed that is not yet durable ([units.md](units.md)) |
| `0x14` | `ack` | log | the peer's ID (32) | 1 to 256 event IDs, strictly ascending: the heads that peer last acknowledged |
| `0x15` | `listing` | log | the peer's ID (32) | `{1: bytes, 2: T}`: a cache of the `StreamHeads` a peer served, and when |
| `0x16` | `state` | log | empty | `{1: base heads, 2: base stubs, 3: last completed sync, 4: left, 5: personal, 6: claiming, 7: kept checkpoint, 8: expressed again, 9: erasing}`, at least one key, key 9 only alone: the log's base ([units.md](units.md)); the event ID (32) of the kept checkpoint of a log whose frame before it this device forgot ([roster.md](roster.md), section 3.15.6); the sync of [ext-guests.md](ext-guests.md)'s online-only policy; the grants a leave request this device sent named, 1 to 64 event IDs, strictly ascending ([ext-guests.md](ext-guests.md)); `1` in the person's personal space ([identity.md](identity.md)), once this device founded it or recovered into it; the invite entry, bytes(32), of a claim this device began in the log and has not signed ([ext-invite-links.md](ext-invite-links.md)); the incarnations this device expressed again, 1 or more pairs `[stream (bytes 16), incarnation (unsigned, at least 1)]`, strictly ascending by stream then incarnation, absent when there are none: each a Loro incarnation of this device's own ([adapter-loro.md](adapter-loro.md), section 2.2, key 3) whose refused units it does not re-submit, since it wrote their text again under a later one ([units.md](units.md), "Re-submission"); in the residue of this device's own erasure, the administering devices of its view at the drop, 1 to 64 pairs `[device ID (bytes 32), X-Wing key (bytes 1,216)]`, strictly ascending by device ID, to which it sends a welcome request ([peers.md](peers.md), "A device's own erasure") |
| `0x17` | `pseudonym` | log | an administrator slot's reference ([peers.md](peers.md)) | `{1: token, 2: Ed25519 seed, 3: ML-DSA-65 seed}`, bytes(32) each; 2 and 3 together; at least one key |
| `0x18` | `invite` | log | invite entry (32) | `space ID (32) \|\| invite entry (32) \|\| secret (32)`: an invite this device made ([ext-invite-links.md](ext-invite-links.md)) |
| `0x19` | `claim` | log | invite entry (32) | as `invite`: a link this device claimed |
| `0x1a` | `replay` | log | sender's device ID (32) | `u64be(epoch) \|\| u64be(counter) \|\| u64be(window)`: a sender's replay window ([ext-ephemeral.md](ext-ephemeral.md)), where `counter` is the highest counter accepted in `epoch` and bit `i` of `window`, from the least significant, is set when counter − `i` was accepted; optional |
| `0x1b` | `vouched` | log | device ID (32) | person ID (32): a list member of that person, rooted in an agent, that this device has decided `Vouched` in the space ([ext-recovery-agent.md](ext-recovery-agent.md)); deleted once the list member is no longer active |
| `0x1c` | `endpoint` | log | a member's device ID (32) | 1 to 1,024 bytes: the CBOR of the member ticket at which this device last reached that member in the space, never one only learned from another member ([transport.md](transport.md), "Reconnecting" and "Member addresses"); optional |
| `0x1d` | `held` | log | object ID (32) | `{1: token, 2: size, 3: stamp}`: the application's token for a held object's plaintext, 1 to 1,024 bytes; the plaintext's length, 0 to 2^40; the application's change stamp, 1 to 64 bytes (section 2.8) |
| `0x1e` | `peers` | log | empty | `{1: [peer hints], 2: home peer}`, at least one key: the always-on peers of the space this device knows, 1 to 8 texts of 1 to 512 bytes each, as a welcome's peer hints are ([admission.md](admission.md), "The welcome"), and the home peer of the library the space is attached to, a text of 1 to 512 bytes ([ext-libraries.md](ext-libraries.md), "The home peer"); optional |
| `0x1f` | `announced` | log | a member's device ID (32) | 32 bytes: the next member endpoint key that member announced in the space ([ext-next-endpoints.md](ext-next-endpoints.md)); kept only beside an `endpoint` record of the same member |
| `0x20` | `host` | log | 1 to 256 bytes | what a device that hosts the space as an always-on peer keeps ([peers.md](peers.md)) |
| `0x21` | `dropped` | log | event ID (32) | `{1: origin, 2: kind, 3: height}`, key 2 present exactly with origin 1, key 3 only with origin 1: an event of the log that is in the past of its kept checkpoint and that this device does not hold (section 3.4, "Forgetting before a checkpoint"): origin 1, the device held it and dropped it, with its envelope's kind and, in a space's log, when it is a parent of an event the log keeps of that past, its height, from 1 ([events.md](events.md), "Placement and order"); origin 2, a peer answered `Missing` for it when the device fetched it as a parent, at a device that started from a checkpoint ([roster.md](roster.md), section 3.15.6) |

- Every other code is `Malformed`. Device-wide tables appear only under 16
  zero bytes, and log tables only under a log's scope tag. An
  implementation that lacks the extension a table names never writes it.
- A **reading** is `{1: T, 2: run, 3: W}`, with key 3 absent when the wall
  clock was not known. A peer's ID is, for an always-on peer reached by
  its origin, the server binding's `channel` of that origin
  ([transport.md](transport.md), section 3.15), on either binding; for one
  the device dialed by an endpoint key it took from no discovery, that
  endpoint key ([transport.md](transport.md), section 3.12); and for a
  member, its device ID.
- An `invite` or `claim` record's space ID is the log's. A `pseudonym`
  record's token is kept from the grant until the enrolment is durable;
  its seeds are committed with the enrolment that names them.
- `object` parts are sealed again here so that a store shows no object ID
  and a former member's old keys open nothing in it.
- A `deposit_keys` record keeps the newest 64 issuing keys: one is seen
  at most once a day, and the rule of [ext-deposit-tokens.md](ext-deposit-tokens.md),
  3.2, reads the last two and the ones before them only to find one that
  returns. A `token` record is deleted in the commit that puts the
  `deposit` record that holds it, and that record is deleted once the peer
  has answered: a token is never in two records, and none is lost to a
  restart between sending it and the answer.
- A held object (section 2.8) has its part 0, the header, and its `held`
  record, and no other part. A device holds an object in one form only: a
  `held` record beside a part `i` ≥ 1 of the same object is `Malformed` on
  open, and the parts win.

### 2.5 The head, events and keys

**`head`**, a CBOR map:

| Key | Value |
|---|---|
| 1 | the store's ID: 16 random bytes drawn when the store is made |
| 2 | the generation, from 1 (section 3.3) |
| 3 | the **tips**: for each log and each signer of this device that has signed there, `[log ID, author, seq, event ID]` of the newest event that signer signed there, `author` its device ID; strictly ascending by `log ID \|\| author`; at most 65,536 |
| 4 | after a restore: the generation at which it was found, 1 to key 2 |
| 5 | with key 4 only: the logs synced since that restore, strictly ascending |
| 6 | the revision the store was made under ([overview.md](overview.md), section 5.6) |

A **signer of this device** is the device itself, an administrator
pseudonym it holds ([peers.md](peers.md)), or an invite key it claimed
with ([ext-invite-links.md](ext-invite-links.md)), each an author by its
device ID ([events.md](events.md)). The next event a signer signs in a log
takes the tip's `seq` plus 1 and names the tip's event as `prev`; the
device reads them from the tips and nowhere else.

**`event`**, a CBOR map:

| Key | Value |
|---|---|
| 1 | the signed event |
| 2 | its state: 1 valid; 2 void or refused; 3 pending; 4 held `Sealed`; 5 pending on `NoHybridKey`; 6 kept alone, never judged |
| 3 | flags: `0x01`, every signature half it carries has verified; `0x02`, its verdict is provisional |
| 4 | with state 2 only: the class of its verdict, 1 to 64 bytes of UTF-8 |
| 5 | its first sight, a reading; absent until the device has accepted it |
| 6 | for a unit of the past of the log's kept checkpoint that the log keeps: the capabilities its author held at its place, as the adapter reads them: the meet of the capabilities of its paths at its highest level there ([roster.md](roster.md), section 3.3), 0 to 64 pairs `[name, mode]`, strictly ascending by name then mode, a name appearing with both modes when the meet keeps both; frozen when the device forgot that past, with state 1 or 2 ([units.md](units.md), "The past of a kept checkpoint") |
| 7 | with key 6, for a unit the write rule admits at its place, whether its content applied (state 1) or was refused or held waiting (state 2): its attribution there ([roster.md](roster.md), section 3.11), 1 to 64 entries `[type, ID]`, or `[type, ID, label]` for a member with a label at that place, the member reference of each member roster.md attributes it to, from the paths the write rule's step 2 finds at its place with each person's list read as it stands there, and its label, 1 to 64 bytes of UTF-8, strictly ascending by type then ID; never beside key 8 |
| 8 | with key 6 and state 2, for a unit the write rule voids: the event IDs, 1 to 64 bytes(32), strictly ascending, of the events that void it ([roster.md](roster.md), section 3.14), when there are some, which also decide whether its author re-submits it |

- The event's ID is the item, and its `log`, or for a genesis its ID, is
  the record's log.
- States 1 and 2 are a cache: a replica recomputes verdicts when its view
  changes, but for a unit of a kept checkpoint's past, whose state and key
  6 are frozen when the device forgets that past: it hands such a unit to
  its adapter with key 6's capabilities, never recomputing them from what
  it still holds, and shows its author from key 7 alone, never from the
  roster it holds now. Flag `0x02` marks a verdict that rests on a key received whole
  or handed over ([keys.md](keys.md), [units.md](units.md)).
- **Pins** ([identity.md](identity.md)) are the `event` records of a device
  list's log. The device never deletes a verified list event but those a
  list checkpoint in effect lets it forget (section 3.4), so a pin only
  grows from the kept checkpoint on.
- State 6 marks an event a log that forgot keeps without judging it: in a
  space, the envelope of a checkpoint its kept checkpoint's cuts reach,
  kept as the signed event; in a device list, the list's first event, the
  `add` and the rooting `add` each member entry of the kept record names,
  the list checkpoints the kept one's `follows` reach, and the late list
  events ([identity.md](identity.md), "List checkpoints", Forgetting). The
  genesis of a space, the roots and enrolments its kept cut names, and the
  late space events keep their judged state.
- An event that an `outbox` record names is never collected.

**`key`**, by key kind:

| Kind | Name | Value |
|---|---|---|
| 1, rotation | rotation ID (32) | a bundle ([keys.md](keys.md)) of the rotation's secrets, verified against its commitments or drawn by this device |
| 2, state received whole | `encode_set(S)`, at least two rotations | a bundle of a merged state's secrets received by wrap; provisional; deleted once derived from verified inputs |
| 3, body key | event ID (32) of a space event or a unit | `u8(1) \|\| key (32)` when this device opened or derived it; `u8(2) \|\| key (32) \|\| unit ID (32)` when a unit handed it, which makes it provisional |
| 4, gap key | `u8(gap kind) \|\| encode_set(B)` | a bundle |
| 5, record key | event ID (32) of a checkpoint | `u8(1) \|\| key (32)` when this device derived the key of the checkpoint's record object from secrets it holds; `u8(2) \|\| key (32)` when a space snapshot handed it ([units.md](units.md), "The space snapshot"), which makes it provisional until the record object opens and matches its digest |

### 2.6 The mark

```text
mark = u8(1) || nonce (24)
       || XChaCha20-Poly1305(seal_key(s), nonce, store ID (16) || u64be(generation),
                             "frasil/at-rest/mark/v1" || u8(1) || device ID)   65 bytes
```

The mark holds nothing secret. It is sealed so that only this device makes
one that opens, and so that it names no store a reader could match.

### 2.7 Application keys

`app_key(K, purpose)` is a key for the application's own data: under `s`
for data of no log, such as settings, and under a log key for data of one
log, such as a space's index. `purpose` is the application's, such as
`com.example.index`. Frasil derives it and hands it over, and never stores
or uses it. When a log is forgotten, its application keys go with it.

### 2.8 Held objects

Object sealing is deterministic ([units.md](units.md), section 2.8): the
object ID is an HMAC over the plaintext under `object_id_key(S)`, the
object key an HMAC of the ID under `object_seal_key(S)`, and each chunk's
nonce an HMAC under `object_nonce_key(S)` over its associated data and
plaintext. A device that holds the plaintext, the space ID, the object ID
and `k(S)` therefore regenerates the header, every chunk and the locator
byte for byte. An application that keeps an object's plaintext as a file of
its own, because it reads files through paths, MAY therefore have Frasil
**hold** the object instead of storing its sealed chunks a second time.
Nothing changes on the wire, in object IDs or locators, or for a peer: the
other side of a transfer cannot tell a held object from a stored one.

**The policy.** A space's objects on a device are `sealed`, the default,
or `held`. The application sets the policy per space and per device, when
it opens the device or later, by giving the object provider below.

- The policy is never synced: it describes this device's disk, and another
  device of the same person may choose otherwise.
- It is not stored either: the `held` records say what is held. A store
  opened without a provider for a space that has `held` records treats
  them as not held until a provider is given, and deletes nothing.
- A space whose grant to this device carries `frasil.nothing-at-rest`
  ([ext-guests.md](ext-guests.md)) MUST NOT be held: the grant asked for
  nothing on disk. A client refuses to set `held` there.
- Frasil's own objects, the space snapshot and the stream snapshot objects
  it names ([units.md](units.md), sections 2.9 and 2.11), are read by
  Frasil and never by the application: a device stores them sealed under
  either policy. Every other object of the space follows the policy.

**The object provider** is the application's:

| Call | Does |
|---|---|
| `stat(token) → (size, stamp)` or none | the plaintext's size and current stamp; none when it is gone |
| `open(token) → reader` | reads the plaintext at an offset |
| `create(space ID, object ID, size, hint) → writer` | a place for a plaintext being received; `hint` is what the application passed to the call that caused the fetch, empty when Frasil started it. The writer takes the plaintext in order, then `finish() → (token, stamp)`, or `abort()`, which deletes the partial file |
| `forget(token)` | Frasil no longer needs the token; the application decides about the file |

- The **token** names the plaintext to the provider, and the **stamp** says
  whether it has changed: a path, a hash, an entry ID; a modification time
  with an inode, a content hash, a version counter. Both are opaque: Frasil
  compares stamps byte for byte and never interprets either.
- Tokens are not exclusive: two spaces may hold one file through one
  token, and a `forget` from one says nothing about the other.
- For a held object Frasil keeps the `object` part 0 record, the header,
  and one `held` record (section 2.4), and no chunk records. The header is
  kept because it is small, carries the key reference of `S` that
  re-sealing needs, and is what a peer or member asks for first. The
  `held` record is sealed under the log key like every record, so the store
  still shows no object ID and no path; the disk shows the application's
  files.

**The limit.** A device that holds only an object's key, through a
reference ([adapter-blobs.md](adapter-blobs.md), section 3.7), can open its
chunks and check the digest, but cannot derive `object_nonce_key(S)` or
`object_id_key(S)`: both come from `k(S)`, and the object key tells nothing
of it. Such a device MAY hold the plaintext, and cannot serve it. The
source's members and the peer serve it instead
([ext-libraries.md](ext-libraries.md), section 3.9). A member of both
spaces serves it under the source.

## 3. Procedures

### 3.1 Sealing and opening the device keys

```text
seal_device_keys(keys, person ID, kind, unlock key), in order:
  1. The person ID is 32 bytes; kind is 1 or 2; not kind 1 with a zero
     person ID.                                                   else Malformed
  2. header = 0x01 || u8(kind) || the device ID of the keys' public
     halves || person ID.
  3. Return header || nonce || XChaCha20-Poly1305(sealing key, nonce,
     plaintext, "frasil/sealed-device-keys/v1" || header), with a random
     nonce and section 2.2's plaintext.

open_device_keys(blob, kind, unlock key, person ID, device ID or none), in order:
  1. len(blob) >= 2.                                              else Malformed
  2. blob[0] = 0x01.                                              else UnsupportedVersion
  3. blob[1] is 1 or 2; len(blob) = 235; not kind 1 with a zero
     person ID.                                                   else Malformed
  4. blob[1] = kind.                                              else WrongKeyKind
  5. blob[34..66] = person ID.                                    else WrongPerson
  6. If a device ID is given, blob[2..34] = it.                   else WrongDevice
  7. The AEAD opens.                                              else Decrypt
  8. plaintext[0] = 0x01.                                         else UnsupportedVersion
  9. The plaintext is 129 bytes.                                  else Malformed
 10. The device ID of the three seeds' public keys, the Ed25519 key
     and the kc of the ML-DSA-65 and X-Wing keys (crypto.md), is
     blob[2..34].                                                 else Malformed
```

- Steps 1 to 4 need no key, so an application reads a blob's version, kind,
  device ID and person ID before it unlocks. Step 10 derives all three
  public keys from their seeds, which the device needs right after anyway
  to sign and to compute its `kc`. A new browser that knows no
  person ID yet reads it from the passkey's user handle
  ([identity.md](identity.md)). A client MUST name the person ID it
  expects, 32 zero bytes for a device member.
- Once opened, the keys MUST be on the person's verified device list, or
  granted as a device member, before the client uses them.

### 3.2 Opening a record

```text
open(address, record, log or none), in order:
 1. The address is 33 bytes and its table byte is in section 2.4.        else Malformed
 2. The table is device-wide exactly when no log is named, and the scope
    tag is 16 zero bytes or the named log's scope tag accordingly.       else Malformed
 3. The record has at least 1 byte, and byte 0 is 1.                     else Malformed / UnsupportedVersion
 4. The record has at least 45 bytes.                                    else Malformed
 5. The AEAD opens.                                                      else Decrypt
 6. The plaintext reads as field(item) || value; the item follows its
    table's rule; its item tag equals the address's last 16 bytes.       else Malformed
 7. The value parses exactly as its table says.                          else Malformed
```

A device does not use a record it cannot open, and does not delete it on
its own. `UnsupportedVersion` is a newer device's record. `Decrypt` and
`Malformed` are damage or tampering: the client reports them and treats the
record as missing.

### 3.3 Committing

- **Deletes, then puts.** A commit applies its deletes before its puts, so
  an address it both deletes and puts holds the put record. A delete of an
  address the store does not hold changes nothing.
- **A precondition.** A store MAY accept a precondition with a commit: for
  some addresses, the record each holds, or that it holds none. It then
  refuses a commit whose precondition fails and changes nothing, checking
  and writing in one atomic step (compare-and-swap). A client SHOULD give
  the head record it read as the precondition of a commit that advances the
  head, so that two processes of one device never advance it from the same
  state. A store that accepts no precondition MUST be used by one process at
  a time: two processes that each read the head and sign from it would sign
  two events at one `seq`, a fork that nothing at the device detects.
- **One commit, one step.** An event the device signs, its `outbox` record,
  its tip in the head, and any secret drawn for it (a rotation's secrets, a
  pseudonym's seeds, an invite's secret) go in one commit.
- **Commit before sending.** A device MUST NOT send an event before the
  commit that holds it has returned.
- **Mark before commit.** Before a commit that holds an event a signer of
  this device signed, the device MUST write the mark for `generation +
  1` to the device-bound slot, durably, then commit with the head at `generation + 1`;
  once per batch when it batches writes. Other commits leave the
  generation. In restore mode `never-restored` or `none`, no mark is written.
  The order is what makes `continuity` sound: the slot is never behind a
  head that holds a signed event. Written after the commit, a crash between
  the two would leave the slot at the generation an older backup's head
  also holds, and a restore of that backup would then look current
  although the device signed and sent events since. Written before, the
  same crash leaves the slot ahead of the head, which costs one sync
  (section 3.5).
- An `outbox` record is deleted when its event becomes durable. A lost one
  is repaired by the next exchange of heads.
- The device keeps its reading in `timeline` at least once a minute while
  it runs, and at shutdown.
- A device that starts sending ephemeral messages reads `e`, commits
  `e + 1`, then uses `e + 1`.

### 3.4 Forgetting a log, and re-keying

- **Forgetting.** When the device leaves or is removed from a space, or the
  person removes it from this device, the device deletes the log's `log`
  record in one commit, then the log's other records by their scope prefix.
  From then on no record of the log that the medium still holds can be
  opened, even with the unlock key. A store that can SHOULD then leave no
  copy of the deleted records in its file: overwrite them in place rather
  than free their pages, and empty any journal or write-ahead log that
  still holds them. A store that cannot, such as a browser's, leaves them
  to its own compaction (section 4, "Remanence").
- **Re-keying.** After a valid erasure ([peers.md](peers.md)) a device MAY
  re-key the log: draw a new `L`, seal every remaining record again under
  it, replace the `log` record, and delete the old records. What the
  erasure removed then stays unreadable on the medium, at the cost of one
  pass over the log.
- **A device's own erasure.** A device that drops a space for its own
  erasure ([peers.md](peers.md), section 3.16) keeps, in one commit with
  the drop, the log's `log` record, its `pseudonym` records, its tips, the
  `event` record of that erasure, its `peers` record, and a `state` record
  with key 9 alone, the administering devices of its view, and deletes the
  log's other records.
  The erasure's first sight (key 5) is when the bound of peers.md starts,
  and a restart reads it there; for an erasure signed again, the newest
  one's. It forgets the log (above) once each peer has answered `erased`,
  or once the application gives the space up.

- **Forgetting before a checkpoint.** A device that forgets a log's events
  before its kept checkpoint ([roster.md](roster.md), section 3.15.6; for
  a device list, [identity.md](identity.md), "List checkpoints"), in one
  commit: sets `state` key 7 to the kept checkpoint's ID; deletes the
  `event` record of every event it forgets; puts a `dropped` record of
  origin 1 for each, with its kind, and, in a space, with its height
  (key 3) exactly when it is a parent of an event the log keeps of the
  kept checkpoint's past; and marks state 6 on each event it keeps alone. The stubs of
  dropped space events are these `dropped` records, never `state` keys 1
  and 2, which hold only a stream's base of units ([units.md](units.md)): a
  space event has no stub there. A later forgetting under a newer kept
  checkpoint adds to the `dropped` records and replaces key 7, and gives
  key 3 to each record whose event a kept event still cites. It also writes
  keys 6 to 8, and freezes state 1 or 2, on each unit of that past it keeps,
  in the same commit. It keeps the `key` records of kind 1 of every
  rotation whose state seals a unit, object or name it keeps, though it
  drops the rotation event: those secrets were checked against the
  rotation's commitments when it held the event, so a kept unit sealed
  under that state opens after a restart without it. After a
  restart the device places each kept event on its dropped parents at the
  heights key 3 gives, a record without key 3 adding nothing
  ([events.md](events.md), "Placement and order"), so that it keeps the
  height it was judged at. Height alone is kept: a dropped `prev` is not
  checked against its chain again, and nothing else reads a dropped
  event.
- **Starting from a checkpoint.** A newcomer, a restored member or a
  device that lost its store, admitted from a checkpoint, commits before it
  judges anything after it: `state` key 7, the kept checkpoint's ID; a
  `key` record of kind 5 with the record object key the snapshot handed
  it; the record object's parts in `object` records; and, as peers answer
  `Missing` for parents it fetches, a `dropped` record of origin 2 for
  each, so that after a restart it places the events that cite them as
  before and never fetches them again. Its list holdings follow the lists'
  own rule below.
- **Lists after a list checkpoint.** A device that holds a person's list
  from a list checkpoint on keeps in that list's log: `state` key 7, the
  kept list checkpoint; the kept checkpoint and every list event after it,
  judged; the events kept alone, in state 6; and a `dropped` record for
  every list event it forgot, which a sealed copy names
  ([units.md](units.md), the `frasil:system` state's key 5). It keeps
  nothing else of the list.

### 3.5 Continuity

The application names its **restore mode**:

| Mode | Meaning |
|---|---|
| `device-bound` | the application gives a device-bound slot: a place no backup restores, such as a keychain item bound to the device and left out of backups. An application SHOULD use this mode wherever the platform has such a place. |
| `never-restored` | the application states that its store is never restored from a backup. It MAY state it for a browser's storage. |
| `none` | neither: every start counts as a restore |

The mark is opened in order: at least 1 byte (`Malformed`); byte 0 is 1
(`UnsupportedVersion`); exactly 65 bytes (`Malformed`); the AEAD opens
(`Decrypt`).

Before `continuity`, a head that opens without key 6, or with a revision
other than the device's, refuses the whole store as `RevisionMismatch`:
the store was made under another revision, so its events and keys
may not open under this one. The device reads no other record of it,
writes nothing to it, and signs nothing; the application starts the
device again on an empty store, and everything it shared comes back by
sync. At every open of the store:

```text
continuity(mode, head, mark), in order:
 1. The store has no head.                                               Restored
 2. mode = never-restored.                                               Current
 3. mode = none; or no mark in the device-bound slot, or it does not open. Restored
 4. The mark's store ID and generation equal the head's.                 Current
 5. Otherwise.                                                           Restored
```

- A store, its head and its mark are made when the device's keys are, and
  before it first signs; keys that open with no head mean a lost store.
- A store restored from a backup has a head older than the mark exactly
  when the device signed after the backup. A backup after which it signed
  nothing passes as current, and lacks nothing it signed.
- A crash between the mark and the commit counts as a restore and costs one
  sync. Step 5 also covers another store's mark under the same keys.

### 3.6 After a restore

When `continuity` gives `Restored`, the device:

1. **Records it:** with `g` one above the larger of the head's and the
   mark's generation (the head's alone if no mark opens), it writes the
   mark for `g` and commits the head at `g`, key 4 set to `g`, key 5 empty,
   and its tips kept.
2. **Syncs a log before it signs there.** Before any signer of this
   device signs in a log not in key 5, the device fetches from a peer or a
   member that holds the log the newest event of each of its signers
   there, places it, sets each tip to the newer of the two, and adds the
   log to key 5 ([events.md](events.md), restored devices). A log it has
   never heard of is no exception. A log the device originates after the
   restore is the one exception: when the device creates a space, writing
   its own genesis and holding the only replica, it adds that log to key 5
   in the same commit as the genesis, so it may sign there at once with
   nothing to fetch. This holds only for a genesis the device generates
   itself; a genesis learned from another party stays subject to this step.
3. **Waits, or returns as a new device,** if no reachable party holds a log.
4. **Restarts its ephemeral epoch** above any it used
   ([ext-ephemeral.md](ext-ephemeral.md)).
5. **Counts the time since the backup as time off,** by keeping the
   restored reading.

Everything a log holds comes back by sync, including wraps and body keys
for this device, and the secrets of a rotation it signed after the backup
by a delivery ([keys.md](keys.md)). A restore loses for good only what the
device held alone: its own events no party received; a pseudonym's seeds
drawn after the backup, whose administrator slot an administrator then disowns and grants
again ([peers.md](peers.md)); and a claimed link's secret, whose successor
step 2 finds as its own. A backup restore changes no verdict and is not a
member restored by a merge.

### 3.7 A memory-only log

A client MAY keep a log in memory only, as
[ext-guests.md](ext-guests.md) requires for a grant that carries
`frasil.nothing-at-rest`. Its log key and records are never committed to
the store, and the head holds no tip and no `log` record of it. After a
restart the device holds nothing of the log, so it treats the log as
restored (section 3.6, step 2) before it signs there.

### 3.8 What is never written

A passkey's PRF output and the passkey member's keys; a recovery key's
secret; a link's secret before the person consents to claim it; the
admission exchange's ephemeral seeds and transcript; member endpoint keys,
except the next one's seed ([ext-next-endpoints.md](ext-next-endpoints.md));
ephemeral messages, ephemeral slot values and receiver nonces; a deposit
grant, and a batch's nonces, blinds and inputs before it is finished
([ext-deposit-tokens.md](ext-deposit-tokens.md)); derived keys, which are
recomputed from the `key` table; verdicts, except as the `event`
table's cache; and other holders' public keys as such: no table holds
them, and a device finds them again by their hash in the records it holds
([crypto.md](crypto.md), "Keys by their hash"), so keys it learned only
from an admission exchange are gone after a restart, as the exchange is.

### 3.9 Held objects

In this section `c`, `n`, `plain_i`, `aad_i`, `nonce_i`, `chunk_i`, the
header, the digest and the locator are [units.md](units.md), section 2.8's,
for the object's own state `S`, and the device holds `k(S)` unless a step
says otherwise.

**Putting.** `put_held(space, token)`, in order:

```text
1. stat(token) gives a size and a stamp.                              else Changed
2. Pass one reads the plaintext through open(token), from offset 0
   to the size, and computes the object ID over it. The read gives
   exactly the size.                                                  else Changed
3. Pass two reads each plain_i again, seals chunk_i, and hashes the
   header and each chunk into the digest; it ends with the locator.
   Each sealed chunk is uploaded to a connected peer or member, or
   discarded. A read that gives other than plain_i's length           else Changed
4. stat(token) gives the size and the stamp of step 1.                else Changed
5. One commit: the object part 0 record with the header, and the
   held record with the token and step 1's size and stamp.
```

- Pass one comes first because the ID is in every chunk's associated data:
  no chunk can be sealed before the whole plaintext has been read. Two
  passes over the file with nothing in memory beat one pass with the whole
  file in memory.
- On `Changed` nothing is committed. A later upload reads the file again.
- Dedupe is unchanged: equal plaintexts under one state give one ID,
  whether the object is put from memory or held.
- An application that holds a file MAY put it this way under `sealed` too;
  the device then stores the chunks of pass two and no `held` record.

**Serving.** Before a device announces a held object in `ObjectHave` or
serves any chunk of it ([units.md](units.md), section 3.14), in order:

```text
1. stat(token) gives the size and the stamp of the held record.       else not held
2. For each chunk i to serve, the device reads plain_i at offset
   i·c through open(token), computes nonce_i and seals chunk_i.
   The read gives exactly plain_i's length.                           else not held
3. A serve that reads through from chunk 0 to chunk n − 1 computes
   the object ID and the digest in the same pass. The ID is the
   record's item, and the digest is that of the locator the request
   named, in ObjectWant or ObjectHave.                                 else not held
```

- A chunk depends on nothing but `aad_i` and `plain_i`, so chunks serve in
  any order, and a resumed upload gets the same bytes.
- **Not held:** the device withdraws the object from `ObjectHave`, deletes
  the `held` record, keeps the header, does not call `forget`, and
  reports the token and the object ID to the application, which MAY put
  the changed file as a new object. The object stays fetchable from peers
  and members that hold it. When none does, as when a file put while no
  peer was reachable is saved over before one is, the object is lost: the
  units that name it still go to peers without it ([units.md](units.md),
  section 3.4, item 7), and readers find it missing. A put that waits
  until a peer holds the object, before the unit is written, never loses
  it this way. The receivers' checks of [units.md](units.md), section 3.3,
  each chunk's AEAD, the digest and the ID, remain the safety net for
  whatever a stamp misses.
- A device that holds no provider for the space, or a record of a
  reference ("The limit"), announces and serves nothing of the object.

**Receiving.** A device under `held` that fetches an object it does not
hold, in order:

```text
1. Once it holds the header, create(space ID, object ID, size, hint)
   gives a writer. For a reference, the space is this space.
2. It fetches the chunks in order from 0, opens each under the
   object key (units.md, section 3.3, step 6), writes the plaintext
   through the writer, and hashes the header and each chunk, as
   sealed, into the digest. A chunk that arrives before one it
   follows waits in memory.                                           else Decrypt
3. Once every chunk is written: the digest is the locator's (step
   0), and with k(S) the object ID computed over the written
   plaintext is the header's (step 7). With the object key alone
   the digest is the only check of the whole.                         else ObjectMismatch
4. finish() gives a token and a stamp. One commit stores the object
   part 0 record with the header, and the held record.
```

- On any failure the writer is aborted, which deletes the partial file,
  and nothing is committed; the device asks another party for the object,
  as for any chunk that fails.
- A reference's `held` record is like any other, and the device never
  announces it ("The limit").

**Forgetting and collecting.** Before it deletes the `log` record (section
3.4), the device scans the log's `held` records and calls `forget(token)`
for each. When it collects an object that no unit references
([units.md](units.md), section 3.7), it deletes the `held` record and
calls `forget(token)`. The application decides about the file: a store by
content hash may still serve other spaces, and a mirrored folder may be
something the person wants to keep. Frasil deletes nothing of the
application's.

**Changing the policy** is a local pass, one object per commit:

- To `held`: for each object of the space the device holds whole, it reads
  the plaintext ([units.md](units.md), section 3.3, with `k(S)` or, for a
  reference, with the object key), writes it through `create` and
  `finish`, and in one commit puts the `held` record and deletes the chunk
  records.
- To `sealed`: for each `held` record, it seals the chunks again as
  "Serving" does, from chunk 0 to chunk `n − 1`, and in one commit puts
  the chunk records and deletes the `held` record, then calls
  `forget(token)`. An object found not held is withdrawn as "Serving"
  says, and stays fetchable.

**Rotation.** A held object stays under its original state, as a stored
one does ([units.md](units.md), section 2.8): the device keeps that state's
secrets in its `key` table, so it can seal the chunks again for as long as
it is a member. Re-keying after an erasure (section 3.4) seals
`held` records again like any record.

### 3.10 Error classes

Besides [overview.md](overview.md)'s `Malformed`, `UnsupportedVersion` and
`Decrypt`, and [units.md](units.md)'s `ObjectMismatch`:

| Class | Meaning | Sort |
|---|---|---|
| `WrongKeyKind` | sealed device keys of another kind than the caller asked for | final |
| `WrongPerson` | sealed device keys of another person than the caller expects | final |
| `WrongDevice` | sealed device keys that name another device than the caller expects | final |
| `Changed` | a held put whose plaintext is gone, or changed while it was read | decision |

`continuity` returns `Current` or `Restored`, and a serve of a held object
finds it held or not held; neither fails.

## 4. Security considerations

- **A reader of the store** without the unlock key learns the sealed device
  keys' header, how many logs and how many records of each table each log
  holds, record lengths, and when records change: that a device holds three
  invites, say, or how many events are not yet durable. It learns no log,
  event or object ID, peer, name or key.
- **Sealed under the device, not the space,** so old space keys open
  nothing in a stored copy.
- **Rollback.** The mark catches a rolled-back head. An attacker who rolls
  back both the store and the device-bound slot makes a restore look current, and the device may
  fork its chain where it signed since; only its own later events there are
  void. A deleted `event` record of the newest event cannot cause a fork,
  because the next `seq` comes from the tips. Only the head is covered by
  the mark: any other record that was once valid at its address opens when
  it is put back there, while the head stays current, and nothing at the
  device detects it. Such a record never makes another party accept
  anything it would not, and never forks the device's chain. What each of
  the device-wide counters and a log's own records does when it is put
  back alone:

  | Record put back | What follows | What detects it |
  |---|---|---|
  | `epoch` | The device starts its next run at an epoch it already used (section 3.3). Receivers that remember a higher counter in that epoch, or the forgetting of a higher epoch, refuse as `Replayed` its ephemeral slot values, and its ephemeral messages but those within the 64-counter window that they never accepted, until its counter passes theirs, as after the second restore of one backup ([ext-ephemeral.md](ext-ephemeral.md), section 3.2). Nonces stay random, so nothing is sealed twice under one nonce. | `Replayed` at receivers; nothing at the device |
  | `timeline` | The device starts from the older reading. With a wall clock known at that reading and now, the time since counts as time off and the timeline is about where it was. Without one, the timeline goes back by the time between the two readings: a rule that waits on the lower estimate waits longer by that much. The run number repeats one already used, so the upper estimate between a reading of that earlier run and now, with no wall clock on either side, is taken as within one run ([overview.md](overview.md), section 6.4) and can come out short: a rule that stops after a time stops later, by at most the time rolled back. | Nothing |
  | `state` | The log's older base: events that rest on the newer base lack their parents until sync or a snapshot brings them again. An older last completed sync: under [ext-guests.md](ext-guests.md)'s online-only policy the device stops writing sooner, until it syncs. A leave request no longer recorded: a guest writes again under its own write rule, until an administrator ends its grant. The personal space no longer marked: the device finds it again from the space's recovery entries. A claim marked again with its `claim` record present changes nothing; with it gone, the device forgets the log as a claim that never finished. | Nothing |
  | `ack` | The device remembers less of what that peer or member acknowledged: a party that then serves less than it last acknowledged, but no less than the record put back says, is not reported `RolledBack` ([units.md](units.md), section 3.13). Which events are durable comes from the `outbox` records, not from `ack`. | Nothing |

  Other rolled-back or deleted records lose data in the same way, never
  forge it.
- **Remanence.** Until a log is forgotten or re-keyed, someone who later
  obtains the unlock key and the medium's old blocks could read its deleted
  records. Forgetting deletes the `log` record, whose sealed log key opens
  the rest, so a store that keeps no copy of deleted records in its file
  (section 3.4) leaves nothing that opens. Below the file system nothing
  is in reach: flash storage remaps and keeps old blocks, and file system
  snapshots and backups keep old files. A browser's store compacts on its
  own schedule, so a forgotten log's records may stay in its files until
  then. A memory-only log (section 3.7) writes nothing to begin with.
- **The unlock key is the protection.** A kind 2 key kept in a file beside
  the store, or backed up with it, protects nothing.
- **A passkey's unlock key** opens the sealed device keys of every browser
  of that person sealed under it, and through each store secret that
  browser's whole store. It does not give the passkey member's keys.
- **An older sealing** of the same keys can be put back by whoever can
  replace the stored bytes, undoing a re-sealing under a new passkey. The
  format has no counter: a replaced passkey is revoked on the device list,
  and a browser whose passkey may be stolen is revoked too.
- **Swapped sealed keys.** The header is associated data and the client
  names the person it expects, so another person's or device's blob is
  refused before a key is tried, and a changed header fails to open.
- **Nonces** are random per seal, 24 bytes, so repeats stay negligible
  without state.
- **Not defended:** code running in the application while the device is
  unlocked; memory the operating system swaps or dumps; the application's
  own copies; a restore of both the store and the device-bound slot.
- **A held object is not defended at rest.** Its plaintext is readable from
  a stolen or imaged disk, with no unlock key. The store still shows no ID
  or path; the files show their own names. "The application's own copies"
  above already covers these files: `held` only stops the sealed second
  copy. The platform's disk encryption protects them, and a client's
  documentation SHOULD say so.
- **A removed member keeps its held copies readable.** Forgetting a log
  makes Frasil's records unopenable; the files stay until the application
  removes them, and Frasil only asks, with `forget`.
- **Remanence of a held object** is the application's: deleted plaintext
  leaves old blocks on the medium, where a re-keyed store leaves nothing
  readable.
- **Held is chosen explicitly** by the application, per space, on this
  device, and never by a peer, a member or a grant. A grant that carries
  `frasil.nothing-at-rest` is never held.
- **Nothing changes for peers or the network:** a held object's bytes,
  ID and locator are the stored object's, and no message says which form
  a device keeps.

## 5. Test vectors

[at-rest.json](vectors/at-rest.json), with fixed seeds, nonces and IDs:

- `device`: a browser's four secrets, its public keys, `kc` and device ID.
  `derivations`: seal and tag keys of the store secret and of a log key,
  two scope tags, and two application keys.
- `sealed_device_keys`: kind 1 under a passkey's unlock key, kind 2, and a
  device member with a zero person ID, each with every intermediate value.
  `sealed_device_keys_refusals`: nineteen blobs refused by section 3.1,
  among them another person's unlock key from the same passkey, a blob
  sealed directly under a kind 2 key, and a changed person ID that only the
  AEAD catches.
- `records`: one record of every table but `held`, from item and value to
  the sealed record; all five key kinds; an `event` record of a unit of a
  forgotten past with its frozen capabilities, one name in both modes,
  and its attribution with labels (keys 6 and 7), one whose content its
  adapter refused, still attributed, and one the write rule voids, with
  the events that void it (key 8); a `state` record with the
  incarnations expressed again (key 8), and one of an erasure's residue
  with its administering devices (key 9); `dropped` records
  of origin 1,
  with and without a height, and of origin 2. `record_refusals`: twenty
  records refused by section 3.2, each with the log key it is opened
  under, among them a moved record, another log's key or scope, an item
  that is not the address's, a claim naming another space, `dropped`
  records with a height beside origin 2 and of height 0, `state`
  records whose key 8 is empty or out of order, and `event` records with
  both keys 7 and 8, an attribution out of order, and an empty label,
  and a `state` record whose key 9 is not alone.
- `mark`: a mark, and four refusals, each with the mark and the device ID
  it is opened with.
- `continuity`: section 3.5's nine outcomes, from agreeing head and mark to
  each kind of restore, and the modes `none` and `never-restored`.
- `after_restore`: a head with keys 4 and 5, its mark, and in which logs the
  device may sign.
- `head_revisions`: a head of this revision, which opens, and a head
  without key 6 and one of another revision, each refused as `RevisionMismatch`.
- `passkey_to_record`: from a passkey's PRF output to an opened head record.
- `held`: sections 2.8 and 3.9. `fixtures`: units.json's space, and the
  content key and key reference of its state. `records`: a `held` record
  from item and value to the sealed record, as `records` shows one;
  `record_refusals`:
  seven values refused by section 2.4, among them a 1,025-byte token and a
  65-byte stamp. `puts`: from the plaintexts of units.json's `objects`
  (one chunk; three chunks with `c` lowered to 64; empty), held puts whose
  object ID, header, chunks and locator equal those vectors byte for byte,
  with the records each commits; and two puts refused as `Changed`, the
  file changed between the passes and gone. `reseal`: chunk 1 of the three-chunk
  object sealed alone, from `plain_1`. `serves`: the three-chunk object
  served whole and chunk 1 alone, then found not held on a changed stamp,
  a changed size and a changed byte under an unchanged stamp, which only a
  serve from chunk 0 to the end finds. `receives`: the three-chunk
  object received with `k(S)`, checked by the object ID, and with the
  object key alone, checked by the digest; a changed byte refused as
  `Decrypt` at its chunk; the bytes against a locator of another digest,
  refused as `ObjectMismatch` with the object key alone; and chunks a
  writer with `k(S)` sealed under another plaintext's ID, refused as
  `ObjectMismatch` with `k(S)` and accepted with the object key alone,
  which checks only the digest.
