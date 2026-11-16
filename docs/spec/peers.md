# Always-on peers
Protocol 1. Vectors: [peers.json](vectors/peers.json).

This document specifies what an always-on peer stores and checks without
reading a roster: the storage credentials it learns from rotations and how a
device presents them, catch-up, objects, release and restore, the collection
of what a snapshot replaces, the administrator skeleton with its twins and
its resolution, stability at the peer, erasure and credentials requests,
quotas and refusal codes. It builds on [overview.md](overview.md),
[crypto.md](crypto.md), [events.md](events.md), [keys.md](keys.md)'s
storage credentials, [roster.md](roster.md)'s resolution procedure,
[units.md](units.md)'s units and objects, and
[transport.md](transport.md)'s device-to-peer handshake.

## 1. Overview

- A peer judges no event. It checks envelopes, Ed25519 signatures, visible
  parts, sizes and rates, and decides only what it stores and serves.
- Each rotation commits to its state's read credential and upload key, and
  a peer keeps an **entry** per state. A proof under either names no device.
  Only a credentials request, a fork or the cap retires an entry, and a
  merge entry also retires with any input's entry; no writer's rotation
  does. A retired read credential still grants **catch-up**. A **recovery
  entry** lets a device that holds only a passkey or a recovery sheet catch
  up on its personal space.
- The **administrator skeleton** shows each administrator as an
  **administrator slot** under a fresh **administrator pseudonym**. Each
  roster event that changes who administers names its **twin**, which
  replicas check; the peer resolves the skeleton by the roster's rules.
- Erasures, credentials requests, reclaimed releases, collections and the
  retention of file versions ([ext-file-versions.md](ext-file-versions.md))
  wait until **stable at the peer**, or for `erasure_timeout` (T).

## 2. Formats

### 2.1 Entries

A peer keeps, per space, a table of entries:

| Field | Value |
|---|---|
| `state` | a state ([keys.md](keys.md), "Rotations and states"): one rotation, or a merged state of 2 to 64 |
| `read` | the Ed25519 public key of `read_seed(state)` |
| `upload` | the Ed25519 public key of `upload_seed(state)` |
| `status` | `live` or `retired` |
| `source` | `rotation`, `merge` or `import` |

An entry is named `[state, read]`, a CBOR array of `encode_set(state)` and
the 32-byte key. A state may have several merge entries (section 3.5).

A peer also keeps, per space, a table of **recovery entries**: a **fetch
key**, an Ed25519 public key ([identity.md](identity.md), "Fetch keys and
recovery entries"), and a status, `live` or `retired`. A recovery entry is
named by its key.

### 2.2 The credential proof

A device presents a credential in [transport.md](transport.md)'s `Present`
message. `presented` is that document's: the connection's `binding` (a hash
of the channel binding, both hellos' nonces and the purpose), the space,
the credential and its public half.

```text
proof = Ed25519-Sign(seed, "frasil/storage-proof/v1" || presented)        64 bytes
```

| `credential` | Seed | `public` |
|---|---|---|
| 1, read credential | `read_seed(state)` | the entry's `read` |
| 2, upload key | `upload_seed(state)` | the entry's `upload` |
| 3, administrator pseudonym | the pseudonym's Ed25519 seed | its device ID; the proof verifies under its Ed25519 key, the `ed` of the envelope of the root or enrolment the peer accepted for it |
| 4, fetch key | the fetch seed ([identity.md](identity.md)) | the recovery entry's key |

The proof binds the channel (so this peer and this connection), both nonces
(so no later connection), the purpose, the space and the credential. It is
scheme 0, verified once, at once ([crypto.md](crypto.md), "Which structures
carry which scheme"). A peer keeps no nonce store: a proof holds for its
connection, and only while its entry is live. A read credential's proof
then holds as a retired one's, for catch-up; an upload key's or a fetch
key's ends. A pseudonym's proof holds while the connection lasts. An
erasure of the space ends every proof of it (section 3.6).

### 2.3 The merge statement

```text
merge = CBOR map
  1  version     1
  2  space       bytes(32)
  3  state       bytes: encode_set(S), 2 to 64 rotations
  4  read        bytes(32): the public half of read_seed(S)
  5  upload      bytes(32): the public half of upload_seed(S)
  6  signatures  array of bytes(64): one per rotation of S, in the state's order

message     = "frasil/storage-merge/v1" || field(space) || field(encode_set(S))
              || read || upload
signature_i = Ed25519-Sign(upload_seed({R_i}), message)
```

### 2.4 Storage events

A **storage event** is an event of kind 6, under scheme 2. Its body is a
deterministic CBOR map that a peer reads:

| Key | Name | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `type` | 0 root, 1 change, 2 enrol, 3 disown, 4 ack, 5 erase, 6 credentials, 7 cut, 16 release, 17 restore |
| 3 and up | by type | below |

Types 0 to 7 are **skeleton events**, signed by an administrator pseudonym.
Types 16 and 17 are **writer requests**, signed by a device. Every other
type is `Malformed`, at a peer and at a replica.

An administrator slot is made by the root or by an applied change, one per
grant, and is that event's: a change whose `twin` repeats a commitment makes
administrator slots of its own, and never replaces, resets or takes over
one made before it or concurrently with it (section 3.11).

A **slot reference** names one administrator slot. It is the CBOR array
`[c, index, maker]`: `maker` the 32-byte event ID of the root or change
that made the administrator slot, `c` that event's `twin` (section 2.5),
and `index`, below 64, the administrator slot's position among that
event's grants. The founder's is `[c(genesis), 0, the root's ID]`.

A slot reference in an event **names** the administrator slot made at
`index` by `maker` when `maker` is in that event's past, is the root or an
applied change, its `twin` is `c`, and it made an administrator slot at
`index`: the root at 0 alone, a change at each of its grants. Otherwise it
names none. It never names an administrator slot that another event made,
whatever their commitments.

| Type | Keys |
|---|---|
| 0 root | 3 `twin` bytes(32); 4 `mldsa` bytes(1,952), the pseudonym's; 5 `duel_policy` unsigned, 0; 6 `founder_mldsa` bytes(1,952); 7 `founder_signature` bytes(3,373); 8 `founder_xwing` bytes(1,216) |
| 1 change | 3 `twin` bytes(32); exactly one of 4 `grants`, 1 to 64 grant maps, and 5 `lower`, a slot reference; 6 `salt` bytes(32) |
| 2 enrol | 3 `slot`, a slot reference; 4 `mldsa` bytes(1,952), the pseudonym's; 5 `slot_mldsa` bytes(1,952); 6 `authorization` bytes(3,373); 7 `binding` bytes(3,445) |
| 3 disown | 3 `slot`, a slot reference |
| 4 ack | none |
| 5 erase | 3 `space`, the unsigned 1; keys 4 and 5 are reserved |
| 6 credentials | at least one of 3 `live`, 1 to 64 entry names, strictly ascending by the bytes `encode_set(state) \|\| read`; and 4 `recovery`, a keep list of 0 to 64 fetch keys, strictly ascending |
| 7 cut | 3 `twin` bytes(32), as a change's; 4 `salt` bytes(32); 5 `record` bytes(64), the locator of the checkpoint's record object; 6 `epoch` unsigned, from 1; 7 `slots`, 0 to 512 slot entries, strictly ascending by the bytes of their slot references; 8 `standing`, 1 to 1,024 standing entries, strictly ascending by the bytes of their slot references; keys from 9 reserved (below) |
| 16 release | 3 `stream` bytes(16) |
| 17 restore | exactly one of 3 `stream` bytes(16) and 5 `snapshot` bytes(32), a snapshot unit's event ID |

A **slot entry** of a cut is the array `[slot reference, slot_ed (32),
slot_mldsa_hash (32), seniority, pseudonym, rank]`: an administrator slot in at the
cut's past, its keys as its grant map gave them (the root's slot has empty
`slot_ed` and `slot_mldsa_hash`), its seniority `[epoch, height, maker]`,
and `pseudonym` the event ID, bytes(32), of the root or enrolment that
enrolled its pseudonym, or empty bytes when none is enrolled, and `rank`
the slot's rank, 0 to 255 (section 3.12). The entry
names that event and does not carry it: the event carries the pseudonym's
ML-DSA-65 key, the peer holds it in the cut's past, and every holder keeps
it after truncation (section 3.22).

A **standing entry** of a cut is the array `[slot reference, order,
dormant, pseudonym]`, one for the administrator slot that each
administrator of the checkpoint's record holds there (its member entry's
key 13), and one for the most senior slot made for each member the
checkpoint hears ([roster.md](roster.md), section 3.15.4), which is out. A
member with no such slot has no entry:

- `order`, from 1, is the entry's place among the entries, sorted by the
  rank of each one's member, highest first, then by its seniority, most
  senior first, as the record gives them: 1 outranks every other, and the
  orders are 1 to the number of entries, with no gap for a member that has
  no entry.
- `dormant` is 0 for a member whose capabilities do not extend
  `frasil.dormant`, or a heard member; otherwise 1, or 2 when it is a
  recovery member by the predecessor's record, or `2 + k` when, without a
  predecessor, its grant in the checkpoint's past was signed by a member
  that exactly `k - 1` entries outrank, whether or not that member has an
  entry itself ([roster.md](roster.md), section 3.15.4, "excused"): it then
  excuses the slots whose order is at least `k`.
- `pseudonym` is, for a slot that is out, the event ID, bytes(32), of the
  root or enrolment of the pseudonym enrolled in it, which votes for it,
  or empty bytes when none is; empty bytes for a slot among the cut's
  `slots`, whose slot entry names it.

A peer cannot derive these, since it reads no roster; replicas check them
against the record (section 3.21), and a peer uses them only to know whose
votes a cut waits for and who may excuse whom. A slot of the cut that no
standing entry names maps to no device, waits for nothing and excuses
nobody. A standing entry is at most 115 bytes. A slot entry is at most 229 bytes, so
the body of a cut with 512 slot entries and 1,024 standing entries, the
most it carries, is at most 208,390 bytes, and the signed event at most
220,777 bytes even with 256 parents and 4 cuts and the widest values of
every field: 41,367 bytes, about 16 %, within a storage event's 262,144.
The standing entries are bounded at twice the slots because each
administrator slot has one, and each heard member's out slot one more
(section 3.21). A space with more than 512 administrator slots in, or more
than 1,024 standing entries to list, takes a cut only after it removes
some.

**Every administrator votes.** A cut takes effect only once every slot it
waits for has voted or is excused (section 3.21), and replicas wait the
same way for the record's electorate ([roster.md](roster.md), section
3.15.4). At 512 administrators that is 512 devices, each of which must
sign a skeleton event, and its device an event of the space, after the
checkpoint: one that is lost or never comes back holds the checkpoint,
and so the peer's truncation and every replica's forgetting, until a
member that outranks it, or a recovery member, removes or demotes it, or,
at replicas only, marks it dormant. A space with many administrators
pays for that size in how long its checkpoints wait.

**What 512 administrators cost.** Granting them takes at least 8 roster
updates of 64 device grants each ([roster.md](roster.md), section 2.3),
each with its twin change of 64 grants (section 2.6), and one enrolment
per device, 512 in all: 520 skeleton events, within the 4,096 contested
events one place of the skeleton holds. An enrolment is about 14 KB, so
the roots and enrolments a cut names, which every peer and every replica
that forgot keeps (section 3.22; [roster.md](roster.md), section
3.15.6), come to about 7.3 MB at 512 slots, and a round of votes, one
skeleton event of about 3.6 KB per slot, to about 1.9 MB. A peer tallies
a cut's votes as they arrive: it keeps, for each cut that can still take
effect, the set of slots that voted or are excused, and each skeleton
event costs it one lookup of its pseudonym's slot, each lowering one
comparison of two standing entries, so a vote costs the same at 512
slots as at 1 and a cut's effect is decided in time linear in its slots.
Nothing in the tally is quadratic. Per connection nothing changes: an
administration connection carries one pseudonym (section 3.9), and
`Awaiting` names events, not slots.

**Reserved cut keys.** Keys from 9 of a cut's body are reserved for a
later document, such as one that lists administrator slots in an object
rather than in the cut. Reading a cut body whose map holds a key from 9,
after `version` and `type`, is `ExtensionRequired` (held) at an
implementation that does not implement that document, and nothing more
of the body is read. At a peer such a cut is stored and kept, as section
3.11 ("No refusal for standing") keeps every skeleton event, and:

- it is no valid cut: it is never in effect, waits for no vote, excuses
  nobody, and a peer never truncates under it (section 3.22);
- no request waits for it: it is not a cut that can still take effect
  (section 3.16), since this peer can never put it in effect, so it
  holds no erasure, credentials request or reclaim;
- a later cut whose checkpoint follows it waits, as any cut whose
  predecessor's cut is not in effect does (`CutPending`), so this peer
  keeps the space whole from there on; that costs storage, as an older
  peer keeps more, and nothing else;
- the peer answers the store with `EventRefused`, code
  `extension_required`, though it keeps and serves the event, and sends
  the same on each administration connection of the space once, so that
  clients know this peer cannot follow the space's checkpoints past it.

A replica holds a checkpoint whose cut is held so exactly as one whose
record is ([roster.md](roster.md), section 3.15.2, "A record held for a
later document's key"), rivals included. So a held cut stalls no honest
party further than a rival checkpoint held for its record already can:
replicas hold what such a checkpoint holds, and a peer holds nothing.

A **grant map** is: 1 `slot_ed` bytes(32), the administrator slot's Ed25519
key; 2 `slot_mldsa_hash` bytes(32), the SHA-256 of its ML-DSA-65 key; 3
`token` bytes(1,171), the sealed slot token (section 2.5); 4 `rank`
unsigned, 0 to 255, the rank of the roster grant the change mirrors
([roster.md](roster.md), section 2.3).

Reading a body, in order: deterministic CBOR, a map with key 1 (else
`Malformed`); `version` 1 (else `UnsupportedVersion`); a known type (else
`Malformed`); exactly the keys the type allows, with their types, lengths,
orders and bounds, and stream IDs as [units.md](units.md) reads them (else
`Malformed`); every Ed25519 key valid, a change's grant maps' and a cut's
nonempty `slot_ed` alike ([crypto.md](crypto.md), "Ed25519
public keys"), and a root's `founder_xwing` valid ("X-Wing and ML-DSA-65
public keys"; else `InvalidKey`). The whole body's structure is checked
before any key, so a change whose second grant map is malformed is
`Malformed` even when its first names an invalid key. A root's
`duel_policy` is 0, since [roster.md](roster.md) reserves every other
value (else `Malformed`). A slot reference is an array of exactly three
elements, and a change carries `salt`: a slot reference of two elements,
or a change without `salt`, is `Malformed`.

An erasure names the whole space and nothing narrower (section 3.16). Keys
4 and 5 of an erase body are reserved for naming parts of a space: a body
that carries either, with or without key 3, is `Malformed` at a peer and
at a replica, so that a later protocol can give them a meaning no
protocol 1 reader mistakes for this one's.

### 2.5 Skeleton derivations

**The twin commitment.** The twin of a roster event `R` is signed before
`R` exists, so its commitment derives from what fixes `R` in advance: `R`'s
body key, which depends only on the log, `R`'s author and `seq` and the
secret it is sealed under ([keys.md](keys.md), "The space event's body"), and
`R`'s self reference, and from the twin's `salt`. Never from `R`'s event ID.

```text
twin_secret(R) = HKDF(none, body_key(R), "frasil/skeleton-twin/v1")
self_ref(R)    = 0x00 || R's author || u64be(R's seq)                     41 bytes
c(R)           = SHA-256("frasil/skeleton-twin-commitment/v1" || self_ref(R) || twin_secret(R)
                         || salt)
```

`salt` is the 32 bytes the twin carries in its key 6, which its author draws
from its random source for each twin it signs. The genesis's twin is the
root, which carries no salt: for `c(genesis)`, `salt` is empty. A body key
of an event that does not rotate is one any member can derive ahead of
time; the salt keeps `c(R)` unknown to every other party until the twin is
published, so no event in the twin's past carries it (section 4).

**The root statement**, signed by the founder's device under scheme 2:

```text
root_statement = "frasil/skeleton-root/v1" || field(space) || field(P0's device ID)
                 || field(u8(2))
```

**The slot token.** For each device granted `administer`, the granter draws
a 32-byte token from its random source:

```text
slot_ed_seed    = HKDF(none, token, "frasil/skeleton-slot/ed25519/v1")
slot_mldsa_seed = HKDF(none, token, "frasil/skeleton-slot/mldsa/v1")
info            = "frasil/skeleton-token/v1" || u16be(0x647a) || field(space) || field(c)
                  || u8(index) || the grantee's device ID (32)
sealed token    = 0x01 || u16be(0x647a) || enc || ciphertext,
                  (enc, ciphertext) = HPKE-Seal(grantee's X-Wing key, info, "", token)
                                                                 3 + 1,120 + 48 = 1,171 bytes
```

The sealed token has crypto.md's wrap layout ("The X-Wing wrap") and opens
by its "Opening a wrap", at the fixed length 1,171. The administrator
slot's keys are the Ed25519 key of `slot_ed_seed` and
`ML-DSA.KeyGen_internal(slot_mldsa_seed)`. The grantee's X-Wing key is the
one its device ID commits to ([crypto.md](crypto.md), "A device's keys"),
as its roster grant or, for a person's device, its device-list `add`
carries it.

**Enrolment.** The grantee draws a fresh pseudonym, an Ed25519 seed and an
ML-DSA-65 seed from its random source, never derived from its device keys or
from any key a peer could test. A pseudonym has no X-Wing key, so its `kc`
hashes its ML-DSA-65 key beside an empty X-Wing key, and its device ID
follows ([crypto.md](crypto.md), "A device's keys"). With `pid` the
pseudonym's device ID:

```text
enrol_statement  = "frasil/skeleton-enrol/v1" || field(space) || field(c) || u8(index)
                   || field(pid) || field(u8(2))
authorization    = the administrator slot keys' scheme-2 signature over enrol_statement

device_statement = "frasil/skeleton-device/v1" || field(space) || field(c) || u8(index)
                   || field(pid) || field(u8(2))
device_signature = the grantee device's scheme-2 signature over device_statement

bind_key = HKDF(none, twin_secret(R), "frasil/skeleton-binding/v1")
aad      = "frasil/skeleton-binding/v1" || field(space) || field(c) || u8(index) || pid
binding  = nonce (24 random bytes)
           || XChaCha20-Poly1305(bind_key, nonce, device_signature || device's device ID, aad)
                                                              24 + 3,405 + 16 = 3,445 bytes
```

- `pid` commits to both of the pseudonym's keys, so the root, the
  authorization and the device signature each bind the pseudonym's
  Ed25519 and ML-DSA-65 keys, as they would by naming both. A pseudonym's
  `kc` hashes only keys drawn for it, so it is as unlinkable to its device
  as the pseudonym's Ed25519 key.

`R` is the roster event whose twin made the administrator slot, and `c` and
`index` are those of the slot reference. None of these statements binds
`maker`, which does not exist when the token is sealed: the enrolment's
slot reference names it.

- **After a checkpoint.** When the enrolment's `cuts` name a space
  checkpoint whose skeleton cut lists the administrator slot (section
  3.21), `R` in `bind_key` is that checkpoint instead, the one with the
  smallest event ID if several are named. A replica that forgot the
  checkpoint's past holds no roster event that made a slot of its cut, and
  holds the checkpoint; reading the secret from the enrolment's own
  envelope lets every replica, whichever checkpoints are in effect at it,
  open the binding under the same key.

**Seniority** of an administrator slot:

```text
seniority(slot) = (height of the event that made it,
                   SHA-256("frasil/skeleton/seniority/v1" || space || c || u8(index)),
                   that event's ID)
```

### 2.6 Limits

| What | Limit | On excess |
|---|---|---|
| A signed storage event | 262,144 bytes ([events.md](events.md)) | `TooLarge` |
| Grants in one change | 64 | `Malformed` |
| Slot entries in one cut | 512 | `Malformed` |
| Standing entries in one cut | 1 to 1,024 | `Malformed` |
| Entries, or fetch keys, named in one credentials request | 64 each | `Malformed` |
| Live recovery entries per space | 64 | `RecoveryEntriesFull` |
| Rotations in a merge statement | 2 to 64 | `Malformed` |
| Valid changes, disowns and enrolments in one place of the skeleton | 4,096 | `Full` |
| Planted administrator slots a peer recognises: grants of changes that repeat a commitment, in a change's past and its own (section 3.11) | 256 | `PlantedSlotsFull` |
| Live entries per space, `credential_cap` | 256 by default; the operator sets 16 to 4,096 | section 3.6 |
| Live merge entries of one state, `merge_per_state` | 4 | section 3.6 |
| Pending events per space, `pending_cap` | 4,096 by default; the operator's | `rate_limited` |
| Versions of a file kept, the current one counted, `max_file_versions` | 100 by default; the operator sets 1 to 1,024 ([ext-file-versions.md](ext-file-versions.md)) | the peer collects the rest |

### 2.7 Error classes

The classes of [overview.md](overview.md), "Error classes", and:

| Class | Meaning | Sort |
|---|---|---|
| `NotAuthorized` | a store with no right, and no create, import or skeleton authority | decision |
| `UnknownCredential` | a present whose public half names no entry or pseudonym of the space | decision |
| `BadProof` | a present's proof does not verify | decision |
| `RetiredCredential` | an upload key whose entry is retired | decision |
| `UnknownState` | a merge statement over rotations the peer does not hold live, or that are not a state | decision |
| `ObjectMismatch` | an upload whose bytes do not hash to its locator's digest | decision |
| `UnknownAdministratorSlot` | a skeleton event whose slot reference names no administrator slot (section 2.4) | final |
| `DuplicateRoot` | a root after the first in canonical order; stored and ignored | final |
| `PlantedSlotsFull` | a change that repeats a commitment, whose grants would take the planted administrator slots a peer recognises in its past past 256 | final |
| `Unnamed` | at a peer: a change or a cut no stored space event names yet | pending |
| `NotAnAdministrator` | in the skeleton's resolution, or for a cut (section 3.21): the author's administrator slot is not in at the place | final |
| `AlreadyEnrolled` | an enrolment of an administrator slot that already has a valid enrolment at its place | final |
| `HigherRank` | in the skeleton's resolution: a change or disown whose author's administrator slot has a lower rank than the slot it lowers (section 3.12) | final |
| `ConcurrentEnrolment` | an enrolment concurrent with another of its administrator slot | final |
| `RemovedConcurrently` | attacked in the skeleton's resolution | final |
| `Full` | over the skeleton's 4,096 contested events in one place | final |
| `NoTwin` | at a replica: a roster event, or the genesis, whose twin or root is not held | pending |
| `BadTwin` | at a replica: a twin or root that fails section 3.13 | final |
| `BadCut` | a skeleton cut whose slots are not those of the merged skeleton of its past (section 3.21) | final |
| `CutPending` | a skeleton cut of the wrong epoch, or made before a cut its checkpoint follows took effect (section 3.21) | final |
| `Late` | with a cut in effect at the peer, a skeleton event other than a cut that is neither in its past nor follows its checkpoint; stored, with no effect (section 3.21), as [roster.md](roster.md) defines the class at replicas | final |
| `BadToken` | at the grantee: a slot token that does not open, or derives other keys | report |
| `KeyStateFull` | an entry added `retired` at the cap; the event is stored, and the peer records the class in its own log | report |
| `RecoveryEntriesFull` | a registration past a space's 64 live recovery entries | decision |
| `PeerError` | at a device: a peer's answer that contradicts what the device can check of it, such as an `ErasureLate` whose cut's envelope does not read, is not this space's or is no cut, or whose cut lists the device's slot otherwise than its standing says, or lists it with no pseudonym at standing 0 (section 3.16) | report |

The skeleton's resolution also uses `NotAMember` and `Forked` with their
overview meanings. [roster.md](roster.md) defines `TwinRequired` and
`UnexpectedTwin`. A recovery entry's registration on a connection without
the store right is [transport.md](transport.md)'s `CredentialRefused`.

### 2.8 Refusal codes

A peer refuses with a code, which travels as [transport.md](transport.md)
says:

| Code | Status | When | The application |
|---|---|---|---|
| `quota_exceeded` | 507 | the store would pass the space's quota | points to the operator's `account_url` |
| `no_library` | 507 | the peer does not host the space | creates or imports it, or uses another peer |
| `moved` | 421 | the peer handed the space over to another peer, to a device that proves it held a credential of the space (sections 3.1 and 3.7) | finds the space's new peer, and syncs there |
| `library_closed` | 507 | the operator has suspended the space's hosting | points to `account_url` |
| `stream_limit` | 507 | the space's streams would pass `max_streams_per_space` ([units.md](units.md)) | releases streams, or splits the space |
| `released` | 410 | a fetch, or a unit, of a released stream | restores first |
| `erased` | 410 | a store into an erased space, or its create or import | |
| `extension_required` | 422 | a skeleton cut whose body uses a reserved key (section 2.4), which the peer keeps and serves but gives no effect | tells the user that this peer cannot follow the space's checkpoints, and that a later version can |
| `recovery_entries_full` | 507 | a registration past 64 live recovery entries | asks an administrator for a credentials request with a keep list |
| `credential_refused` | 403 | a present this document refuses, or a fetch with no right | |
| `not_authorized` | 403 | a store with no right, or a create whose first stored event is not the genesis | |
| `conflict` | 409 | a second event at one author and `seq`, kept as evidence | |
| `object_mismatch` | 422 | an upload whose bytes do not hash to its locator's digest; the peer discards them | uploads again |
| `rate_limited` | 429 | a rate of section 3.20, or `pending_cap` | retries later |
| `too_large` | 413 | an event or object over its limit | |

[ext-libraries.md](ext-libraries.md) defines libraries, tickets, usage
reports and `account_url`, and when `no_library` and `library_closed` arise
for a library. A peer that does not implement it uses the two codes as this
table says, for its own hosting.

`moved` names no peer: a `Refused` and an `EventRefused` carry nothing but
the code ([transport.md](transport.md), section 2.4). The application finds
the new peer through its own services, such as an issuer's home peer
([ext-libraries.md](ext-libraries.md)), or through the space's peer hints
([admission.md](admission.md), "The welcome").

## 3. Procedures

### 3.1 Hosting a space

A peer **hosts** a space from a create or an import until the space's
erasure, or until it hands the space over. Which creates and imports it
accepts is the operator's policy; [ext-libraries.md](ext-libraries.md)
defines one, by tickets.

- **Create.** The first event the connection stores for a space the peer
  holds nothing of is its genesis, whose event ID is the space ID; the peer
  adds the genesis's entry, live. A genesis of a space the peer erased or
  handed over is refused `erased` at section 3.2's step 3, so only a holder
  of the genesis learns that the space was here.
- **Import.** The device stores the log, genesis first; each rotation adds
  its entry **retired**, source `import`. The importer then presents upload
  keys for the current state of its view; until the import ends, such a
  present of a retired `import` entry makes it live. The import ends at the
  importer's first store after its connection holds the store right, or
  when its connection closes: a peer cannot tell which events belong to the
  imported log. So an import makes live only credentials its importer
  holds, and never a removed writer's racing rotation. An import carries no recovery
  entries; the person's devices register them at the new peer.
- A connection imports only through [ext-libraries.md](ext-libraries.md)'s
  `LibraryAttach`. A peer that does not implement that extension treats
  every genesis stored for a space it does not host as a create.
- **Hand-over.** An operator MAY hand a space over to another peer. That
  peer takes the space as it stands: its events and objects, its entries
  and recovery entries with their statuses, its skeleton, and its readings,
  with the last reading of the timeline that keeps them. The receiving peer
  keeps them on that timeline, taking it up as a machine takes up a shard
  ([overview.md](overview.md), section 6.7): the space, alone or with its
  library, is a shard there. It is not an import: no entry retires. The peer the space leaves
  stops hosting it and keeps a **departure record**: the space ID, and the
  public halves of every entry, recovery entry and enrolled pseudonym the
  space held when it left, a pseudonym's with the Ed25519 key its root or
  enrolment carried, under which its proof verifies. It serves nothing of the space after. A present
  that checks against the record is refused `moved` (section 3.7), and so
  is each later request or event of the space on a connection granted in
  it before the hand-over; every other present or store of the space is
  refused `no_library`, as for a space never hosted, and its genesis
  `erased`. An import of the space, or its hand-over back, ends the
  record.
- **One peer on several machines.** A peer that runs on several machines
  is one peer to its devices. What one of its machines acknowledges, every
  machine of it serves, and at any moment one machine answers for each
  space, so the peer accepts each space's events in one order and never
  serves less than it acknowledged ([units.md](units.md), "Heads,
  acknowledgements and durability"). How its machines agree on which one
  answers reaches no device.

### 3.2 Storing an event

A peer checks, in order, before it stores an event:

```text
1. events.md's envelope and size checks, and crypto.md's verify, steps
   1 to 4: the Ed25519 half of a scheme-2 signature, all of scheme 0.   else that class
2. The connection may store in this space: it holds the store right
   (section 3.7); or it creates or imports the space (section 3.1); or
   it holds the erase right and the event is its pseudonym's skeleton
   event (section 3.11).                                               else NotAuthorized
3. The space is hosted here and not erased; for a create, the peer
   has neither erased it nor handed it over (section 3.1).             else no_library / erased / moved
4. Every parent is stored, or stands as a stub (units.md).             else pending, below
5. The kind's shape: a space event's visible part passes keys.md's
   structural checks; a storage event's body section 2.4; a unit
   units.md's peer checks.                                             else that class
6. Quota, streams and rates (section 3.20).                            else that code
7. Store. Record the peer's first sight, chain evidence, and usage
   (section 3.3). A rotation adds an entry (section 3.4).
```

- A peer computes each event's author, its device ID, from the envelope's
  `ed` and `kc` ([events.md](events.md)), and keys chains, conflicts,
  attribution and rates by it.
- A peer verifies the ML-DSA-65 half only of skeleton events (section
  3.11): the records that carry other authors' keys are sealed. So an
  adversary that forges Ed25519 can make a peer store events under any
  device's `ed` and `kc`, at a used `seq` too; the peer keeps such an event
  as it keeps any conflict, and every replica refuses its ML-DSA-65 half,
  so it is never evidence ([crypto.md](crypto.md), "Security
  considerations").
- **Pending.** An event whose parents the peer lacks, or a change no space
  event names (section 3.11), is held **pending**. It counts toward usage,
  is never served as stored, and is dropped after `orphan_grace` on the
  peer's timeline. A peer holds at most `pending_cap` pending events per
  space, and refuses more with `rate_limited`.
- **An identical retry.** An event the peer already stores, sent again on
  a connection that may store in the space, is acknowledged again. It
  changes nothing and counts toward no quota or rate. A device resends
  every event of its outbox until a peer acknowledges it
  ([units.md](units.md)).
- **A second event at one author and `seq`** is stored too, as fork
  evidence. The peer answers `conflict`, never acknowledges it as stored,
  and keeps and serves both, so that every replica can prove the fork.

### 3.3 Attribution

A peer keeps, per space, the bytes each author stored, by its device ID,
and the bytes stored under each entry. An object counts for the writers
whose units reference it, and until one does, for the entry it was stored
under. The operator MAY refuse an author or an entry in a space; that is an
operator control, and changes no replica's verdict. Events under minted
keys are dropped by replicas, and still count for the entry used.

### 3.4 Learning a rotation's credentials

When a peer stores a space event whose visible part rotates, it adds the
live entry `({R}, key 11, key 12)`, source `rotation`, where `R` is the
event's ID. It needs no roster: the event came on a connection that proved
a live upload entry.

- A peer cannot tell a valid rotation from a void one, so a removed
  writer's rotation stored before its removal reaches the peer adds a live
  entry too (section 4).
- A space event that does not rotate adds nothing.
- **A fork.** Once the peer holds chain evidence that an author forked at
  `seq`, every entry of a rotation by that author at or after `seq`
  retires, and its later rotations add retired entries.
- A restricted space's rotations commit to credentials of their own; to a
  peer it is a space like any other
  ([ext-restricted-spaces.md](ext-restricted-spaces.md)).

### 3.5 Merge statements

A merged state `S = {R_1, ..., R_n}` has no committed credential. A writer
that derived `S` from its inputs tells the peer the merged credentials in a
merge statement (section 2.3), and SHOULD do so when it first stores under
`S` at a peer. On a connection that proved a live upload entry, a peer
checks, in order:

```text
1. The map reads, with exactly these keys; key 1 is 1 (an unsigned
   other than 1 is UnsupportedVersion); the state is a rotation set
   of 2 to 64; one signature per rotation.                            else Malformed
2. Keys 4 and 5 are valid Ed25519 keys.                                else InvalidKey
3. Every rotation of S is a stored rotation of this space whose entry
   is live, and none is in another's past.                            else UnknownState
4. Each signature_i verifies strictly under R_i's upload key.         else BadSignature
5. Add the live entry (S, read, upload), source merge.
```

- Every input signs, so only a writer that holds every input's upload seed
  adds a merge entry, and a removed writer gains at most one entry, of
  states it already holds.
- The peer cannot check that `read` and `upload` derive from `S`: it holds
  neither `k(S)` nor `w(S)`. A junk statement only adds an entry that honest
  members' proofs fail against; they present another, or publish their own.
- A reader that holds `k(S)` whole proves a merge entry a writer published,
  or an input's entry whose key it reached by a link.

### 3.6 Retirement and the cap

An entry retires only:

1. when a credentials request is carried out (section 3.17);
2. by a fork of its rotation's author (section 3.4);
3. under the cap (below);
4. for a merge entry, when any input's entry retires.

A carried-out credentials request also revives the retired entries it
names. No writer's rotation retires anything: any writer may rotate, and a
rotation may wrap for nobody, so retirement by rotation would let one
writer leave every other member holding only retired credentials.

A peer keeps at most `credential_cap` live entries per space, and
`merge_per_state` live merge entries of one state:

- **A fifth merge entry of one state.** The peer first retires the oldest of
  that state's merge entries that no successful present has proved, or, if
  all were proved, the oldest.
- **The space's cap.** Before adding a live entry past the cap, the peer
  retires the oldest live merge entry never proved by a present; failing
  that, of the live rotation entries whose rotation is in the past of
  another stored rotation, the one it first saw longest ago, with the merge
  entries that rest on it. If neither exists, it adds the new entry `retired`
  and records `KeyStateFull` in its own log. The uploader learns it when a
  later present of that entry's read credential is granted catch-up only
  (section 3.7).
  An administrators' credentials request clears it.

Retired entries are kept, so that members can catch up.

**Connections.** When an entry or a recovery entry retires, or the space
is erased, the rights that open connections hold by a proof of it end at
once (section 2.2). What a connection keeps is what a present of each
credential it proved would be granted now (section 3.7): a retired read
credential's catch-up, nothing of an upload key or fetch key whose entry
retired, nothing at all in an erased space. A connection that proved two
entries keeps what the live one grants. The peer:

- answers a later request or event that needs an ended right as one with
  no right: `credential_refused`, or `not_authorized` for a store;
- stops honouring each transfer token whose grant's rights ended
  ([transport.md](transport.md), "The server binding");
- ends the connection's live delivery of the space, and its ephemeral
  channel, once no live entry it proved grants it the live right, and then
  closes a connection that was subscribed with `reconnect`
  ([transport.md](transport.md), 3.10), unless an import or a create holds
  it. `Subscribe` carries no request number, so no `Refused` can end it.

A device that holds a newer entry presents it, on the same connection or,
after `reconnect`, on the next; a member that missed a rotation presents
its retired read credential and catches up.

### 3.7 Presenting a credential

A peer checks a present, in order:

```text
1. credential is 1 to 4, and the connection's purpose allows it
   (transport.md).                                                    else Malformed / purpose_violation
2. The space is hosted here and not erased.                           else no_library / erased / moved
3. public is, for 1, the read key of an entry of the space; for 2, the
   upload key of one; for 3, the device ID of the root's pseudonym, of
   one whose enrolment the peer stores, late ones included, or of one
   whose enrolment is the first event this connection stores; for 4,
   the key of a recovery entry of the space.                          else UnknownCredential
4. The proof verifies strictly over this connection's presented,
   under public; for 3, under the pseudonym's Ed25519 key, the ed of
   the envelope of its root or enrolment.                             else BadProof
5. For 2: the entry is live, or it is a retired import entry and this
   connection is the import in progress (section 3.1). For 4: the
   recovery entry is live.                                            else RetiredCredential
```

Entries may share a public half, as when a rotation carries another
rotation's keys. Steps 3 to 5 take, of the entries whose key is `public`, a
live one; failing that, for 2, a retired import entry while this
connection is the import in progress; and otherwise the first the peer
added. So a retired entry never shadows a live one with the same key.

A failure at steps 3 to 5 answers `credential_refused`. A pseudonym whose
enrolment is still to come has no Ed25519 key the peer holds: the peer
grants the present after steps 1 to 3 and holds its proof, and the
connection may then store only that enrolment, by the pseudonym `public`
names, as its first event. The peer runs step 4 under that enrolment's
`ed` as part of step 2 of "Storing an event" (section 3.2): a proof that
fails, or any other first event, is `NotAuthorized`. An enrolment that
section 3.11 refuses is refused with its class, and one the peer would
hold pending is `NotAuthorized`. One the peer stores is accepted, whatever
the resolution decides of it (`ConcurrentEnrolment` or `AlreadyEnrolled`
in its place, or late, section 3.21): the resolution can change as events
arrive, and a refused enrolment would leave every event that cites it
pending at this peer for good. Until the peer accepts that enrolment,
the connection stores nothing else of the space and receives no
`Awaiting` for it. At step 2, for any space it does not
host and has not erased, the peer verifies the proof strictly under
`public`, over this connection's `presented`, whether or not it keeps a
departure record of the space (section 3.1); for credential 3, under the
Ed25519 key the record keeps for the pseudonym whose device ID `public`
is, when it keeps one. It answers `moved` only if it keeps one, the record
keeps `public` for the credential's kind, and the proof verifies; and
`no_library` otherwise. So the answer costs the
same work for a space never hosted, and `moved` tells that a space was here
only to a device that proves it held a credential of it. A success
grants:

| Credential | Entry | Rights |
|---|---|---|
| 1 | live | fetch and live delivery |
| 1 | retired | catch-up |
| 2 | live | store and release |
| 3 | | erase: the pseudonym's skeleton events and acknowledgements, on its administration connection |
| 4 | live | catch-up |

**Store** lets a connection store events of any kind in the space, its own
and those it relays; store objects; place and delete the space's invite
drops ([ext-invite-links.md](ext-invite-links.md)); present merge
statements; and learn the space's live entries. **Release** lets it store
writer requests. **Fetch** serves every stored event and object of the
space, by space and stream as [units.md](units.md) defines.

**Catch-up** serves the space's events of kinds 2 and 6 that it still
holds (section 3.22); by ID, any parent
of an event served on the connection, or a collected parent's stub answer;
and the units of the one stream the connection names as the space's system
stream, which the peer cannot otherwise recognise. Nothing else. A member
whose entry retired, one that was offline or missed a rotation, fetches
what wraps the newer keys for it, judges the roster, and then proves a live
entry.

**Recovery entries.** A device that holds only a passkey or a recovery
sheet knows its personal space ID but none of that space's keys. It derives
a fetch key and presents it as credential 4 ([identity.md](identity.md),
"Recovery"); a live recovery entry grants catch-up, whose space events hold
the wraps it needs.

- **Registering.** On a connection that holds the store right for the
  space (else `CredentialRefused`), a device registers a fetch key
  ([transport.md](transport.md) carries the request). The key passes
  `ed25519_valid` (else `InvalidKey`). A key the space already holds, live
  or retired, is accepted and changes nothing. Otherwise the peer adds it, live, unless the space already holds
  64 live recovery entries (`RecoveryEntriesFull`).
- **Retiring.** A recovery entry retires only when a credentials request
  with a keep list is carried out (section 3.17). No writer removes or
  retires one, so no writer can stop a recovery.
- An erasure of the space removes its recovery entries.

A peer MUST NOT serve a space's events to a connection that proves only
knowledge of the space ID.

### 3.8 Objects

A peer stores and serves an object by its **locator**, the object ID and
the SHA-256 of its stored bytes ([units.md](units.md)), under the store
right.

- It accepts an upload under a locator only once the bytes hash to the
  locator's digest (else `ObjectMismatch`), keeps uploads under different
  locators with one ID apart, and stores an object once per locator,
  whoever uploads it. It refuses an object whose header is malformed.
- An object is **referenced** while a stored unit that lists its locator is
  neither replaced nor released. References are counted by locator.
- **Orphans.** An object no stored unit has referenced since its upload
  completed is collected `orphan_grace` after the peer received its last
  chunk; so is an upload left incomplete. A writer uploads an object before
  the unit that names it, and the grace covers that.
- **A unit ahead of its object.** A peer stores a unit that names an
  object it does not hold as any other unit, and checks nothing of the
  object then: a writer that lost an object's only copy still sends the
  unit ([units.md](units.md), section 3.4, item 7). An upload of the object
  that completes later is referenced from then on. Until then a fetch of
  it finds nothing.
- An object whose last reference a snapshot dropped goes with that
  snapshot's collection (section 3.19); one whose references are all
  released goes with them (section 3.18).
- A peer that implements [ext-file-versions.md](ext-file-versions.md)
  also collects a referenced object whose every listing a later unit of
  its stream supersedes, once its depth reaches `max_file_versions` or
  the time since it was superseded reaches `file_version_retention`,
  whichever comes first, and the superseding unit is stable at the peer
  or T has passed since the peer first saw it. A version exactly at
  either limit is collected. A live hold keeps it, as below.
- [ext-libraries.md](ext-libraries.md)'s holds let other spaces of one
  library use an object a space stores: a live hold keeps the object past
  these rules, and the holding space's fetch right serves it.

### 3.9 Administration connections

[transport.md](transport.md) keeps administration connections apart: one
present, of one pseudonym for one space, then only that pseudonym's
skeleton events and acknowledgements, no account credential, no session
resumption. In addition:

- A device MUST NOT store a skeleton event of its own pseudonym on a
  space-traffic connection, because what a connection stores shows its
  writer's device. It MAY relay other devices' skeleton events there.
- **Between members.** Members carry skeleton events to each other as they
  carry every other event of the space, their own pseudonyms' included:
  roots, enrolments, changes, cuts and acknowledgements. This hides
  nothing the design keeps from members: every member that opens the
  roster event naming a slot opens the enrolment's binding and maps the
  pseudonym to its device (section 3.13), as it must to check twins, and a
  replica that forgot reads the same from the record. What stays hidden is
  hidden from peers. So a space with no always-on peer, or whose members
  sync only with each other for a while, keeps its skeleton, and its cuts
  take effect by section 3.21's rule over what the members hold; a peer
  that receives the skeleton later reaches the same verdicts.
- On an administration connection, a peer reports the requests and snapshot
  units that are not yet stable at the peer and that the connection's
  administrator slot has not acknowledged ([transport.md](transport.md)'s
  awaiting report). Those of a cut's past are among them while they wait,
  on the connection of the pseudonym enrolled in a slot of their stability
  set in the world after the cut (section 3.21, "Requests of the cut's
  past"); a slot made after the cut acknowledges them through the change
  that made it, so they are never reported to it. A late pseudonym's
  connection is reported nothing.

### 3.10 The skeleton

**The root.** The founder's device makes a fresh pseudonym `P0` and signs
`root_statement` (section 2.5) as `founder_signature`. `P0` signs the
root: `seq` 1, parents exactly the genesis, `twin` = `c(genesis)`, `mldsa`
its own ML-DSA-65 key, `duel_policy` the genesis's, and `founder_mldsa` and
`founder_xwing` the founder device's ML-DSA-65 and X-Wing keys, which hash
to the genesis's `kc`, so that a peer checks the founder's signature under
the founder's own key. The root's administrator slot is
`[c(genesis), 0, the root's ID]`, enrolled to `P0` from the start.

- **The genesis names no twin.** The root's parent is the genesis, so the
  genesis cannot carry the root's ID. The founder's signature binds the root
  instead, and only the founder's device can make one. The root is the
  first root in canonical order that section 3.11 accepts, at a peer and at
  replicas; later roots are stored and ignored (`DuplicateRoot`).

**A change.** A roster event changes who administers when, at its place,
one of its changes grants `administer` to a device or raises a device to it
(the twin **grants** an administrator slot for it), or removes a device at
`administer` or lowers it (the twin **lowers** that device's administrator
slot). A roster event that lowers an administrator holds no other change
([roster.md](roster.md)), so a twin lowers one administrator slot or grants
1 to 64, in the order of the roster event's changes.

The author's pseudonym signs the twin first, with a fresh `salt` and
`twin` = `c(R)` under it. The device then signs `R`, which names the
twin's event ID in visible key 15 and cites the twin among its parents. A
twin's parents are skeleton events only, and hold every skeleton event in
`R`'s past. A twin that lowers names, as `lower`, the slot reference of the
lowered device's administrator slot, its `maker` the root or the twin that
made it.

**Granting an administrator slot.** The granter draws a slot token per
device, and the change carries a grant map for each (section 2.5).

- The grantee opens `R`, finds its index among the `administer` grants,
  takes `c` and the twin's event ID from the twin that `R` names, and
  opens its token. A token that does not open, or whose
  keys miss the grant map's, is `BadToken`: the grantee's client asks for a
  re-grant. No other replica reaches this verdict.
- A token serves one administrator slot. A device granted `administer`
  again gets a new administrator slot and enrols a new pseudonym. A device
  whose enrolment turns out late under a checkpoint enrols the same slot
  again with its token, under a new pseudonym (section 3.21, "A late
  enrolment").

**Enrolment.** The pseudonym signs the enrolment as its first event (`seq`
1), with parents that hold the twin that made the administrator slot, and
with `slot`, `mldsa`, `slot_mldsa`, `authorization` and `binding` (section
2.5). `slot` names that twin as `maker`. The enrolment carries the pseudonym's ML-DSA-65 key, which hashes to
the `kc` its envelope names, so it is the record from which every verifier
takes the pseudonym's key ([crypto.md](crypto.md), "A device's keys"). An
honest client enrols at its first sync after the grant.

**A disown** lowers the administrator slot its slot reference names. Any
enrolled administrator MAY sign one. A replica deems it **justified** when, at its place, the
administrator slot was made by an applied change that is not the valid twin
of the roster event that names it (a **planted** administrator slot), is
enrolled foreignly (section 3.13), or belongs to a device that is not an
administrator in the roster.

**An acknowledgement** has no keys beyond its type. Its parents are the
heads its author's device holds and has judged. Every skeleton event
acknowledges its past.

**The cite-together rule.** A device cites a twin only once it holds the
roster event that names it, and cites a roster event that needs a twin only
with that twin: for every pair `(R', S')` of a roster event and its twin,
and every roster event `R` that needs a twin, `R'` is in `R`'s past exactly
when `S'` is. With this rule and the twin's parents, two twins are
concurrent exactly when their roster events are, so the peer's merge of the
skeleton sees the concurrency the replicas' merge of the roster sees.

### 3.11 What a peer checks before it stores a skeleton event

A peer runs these in canonical order, so that the event that makes an
administrator slot, and an author's enrolment, come before the events that
rely on them:

```text
1. The body reads (section 2.4).                                     else that class
2. A root, in order: it is the first root (a later one is stored
   and ignored, DuplicateRoot); its parents are exactly the genesis
   and its seq is 1 (Malformed); mldsa, beside an empty X-Wing key,
   hashes to its kc, and founder_mldsa and founder_xwing hash to the
   genesis's kc (NotCommitted); it verifies under its ed and mldsa,
   and founder_signature verifies under the genesis's ed and
   founder_mldsa (BadSignature).                                     else the class named
3. An enrolment, in order: its slot reference names an administrator
   slot that an applied change made (UnknownAdministratorSlot); its
   seq is 1, its author is no pseudonym the peer holds already,
   SHA-256(slot_mldsa) is that administrator slot's slot_mldsa_hash,
   and authorization verifies under its slot_ed and slot_mldsa
   (BadSignature); mldsa, beside an empty X-Wing key, hashes to its
   kc (NotCommitted); the event verifies under its ed and mldsa
   (BadSignature).                                                   else the class named
4. Any other type: when its author is the device ID of a pseudonym
   whose root or enrolment the peer holds, the event verifies under
   that pseudonym's ML-DSA-65 key.                                    else BadSignature
   Otherwise it is stored, with no effect (NotAuthorized, below).
5. A lower or a disown: its slot reference names an administrator
   slot. It lowers that one alone.                                   else UnknownAdministratorSlot
6. A change with grants that repeats a commitment: its grants, with
   those of every change in its past that repeats a commitment and
   that this section does not refuse, number at most 256.            else PlantedSlotsFull
7. A change applies only once the peer holds a space event that
   names it in visible key 15. Until then it is stored, pending.     Unnamed
```

The peer cannot open a binding. Whether an author holds its administrator
slot at an event's place is the resolution's: a peer stores events that
turn out void, so that replicas can see them.

- **No refusal for standing.** A skeleton event is refused only for what
  is wrong in it: its body, its signature under a key the peer holds, a
  slot reference that names nothing, or the limit of step 6. One whose
  author the peer holds no root or enrolment for (a pseudonym never
  enrolled, or one whose enrolment it deleted when it truncated), or whose
  author's slot is out or not in the skeleton the peer resolves, as a
  removed administrator's after a cut, is stored with no effect: it makes,
  enrols and lowers nothing, acknowledges nothing, votes for no cut, and a
  request it carries is void (`NotAuthorized`). A peer that refused it
  would leave every event that cites it, a device's vote among them,
  pending there for good, whoever signed it. Its ML-DSA-65 half is not
  verified when the peer holds no key for its author, so it is never fork
  evidence.
- A skeleton event that is late at the peer runs step 1 alone, a late
  enrolment besides the checks of section 3.21 ("Late skeleton events"
  and "What a late enrolment opens").

**A repeated commitment.** A change **repeats a commitment** when its
`twin` is the root's, or that of a change in its past that this section
does not refuse, pending ones included. The peer cannot check that a
change's `twin` is `c(R)` of the roster event that names it, so any
administrator can sign a change with a commitment already published, the
root's included, and name it from an event of its own. Such a change is
stored and applied like any other, within step 6's limit, and makes
administrator slots of its own (section 2.4):

- A slot reference names its maker, so no enrolment, lower or disown
  reaches the copy's administrator slots unless it names the copy, and
  none reaches the copied one through the copy. It changes nothing for the
  administrator slots, enrolments and requests made before it, concurrently
  with it or after it.
- A copy that reuses another change's grant map whole gives its author no
  enrolment: only the holder of the slot token can sign an authorization,
  and the grantee's enrolment names the genuine twin.
- Its administrator slots join the merged skeleton and the stability set
  beside the others. They add acknowledgements a request waits for and
  never remove one. A disown of one lowers it alone.

An honest twin never repeats a commitment: its `salt` is fresh, so no event
in its past carries `c(R)` (section 2.5), and the root is the first
skeleton event. Every administrator slot of a change that repeats a
commitment is therefore planted (section 3.13), and step 6 bounds those a
peer recognises. Step 6 reads only the change's past and the verdicts of
this section on it, so the peer and every replica reach it whatever order
the events arrive in. A copy concurrent with the change it copies repeats
nothing in its own past, so step 6 does not count it, like a planted
change under a fresh commitment named by a key event: those are bounded
only by the skeleton's place (section 2.6), and replicas disown them
(section 3.13).

### 3.12 The skeleton's resolution

A peer resolves the skeleton with [roster.md](roster.md)'s resolution
procedure, read as follows:

- **Members are administrator slots.** The root's is in from the start,
  enrolled to `P0`. An applied change's grant puts one in; a lower or a
  disown puts out the administrator slot its slot reference names
  (section 2.4). A valid enrolment binds a pseudonym to the administrator
  slot it enrols, which is in.
- **Contested events** are applied changes, disowns and enrolments.
- **Authority at the place.** A change or disown needs its author enrolled
  in an administrator slot that is in (else `NotAnAdministrator`), and an
  administrator slot it lowers in (else `NotAMember`). An enrolment needs
  its administrator slot in and not yet validly enrolled (else
  `AlreadyEnrolled`). So a slot that another pseudonym holds is never
  enrolled again while it is in: only a lowering or disown that takes it
  out, and a new grant, give its device a slot to enrol (section 3.21, "A
  slot another pseudonym holds").
- **Attacks.** `x` attacks `e` when they are concurrent, `e` is not
  self-lowering, and `x` lowers or disowns `e`'s author's administrator
  slot, or, for an enrolment `e`, the administrator slot it enrols
  (`RemovedConcurrently`).
- **Two concurrent enrolments of one administrator slot are both void**
  (`ConcurrentEnrolment`), so a granter that knows the token cannot win a
  race against the grantee.
- **Ranks.** Every administrator slot has a rank: the root's is 255, and a
  change's grant carries its own (key 4 of a grant), the rank of the roster
  grant whose twin made it, which replicas check (section 3.13). A change
  or disown whose author's slot has a lower rank than the slot it lowers is
  `HigherRank` (final), as its roster event is at replicas
  ([roster.md](roster.md), section 3.6). A slot's rank never changes: an
  administrator given another rank is lowered and granted again, each
  with its twin. A rank is a number, not an identity: a peer still learns
  nothing of who a slot's device is.
- **Mutual pairs** under `duel_policy` 0: two changes or disowns, by
  different authors, that lower each other's administrator slots. Only the
  lowering by the author whose slot outranks the other's (the higher rank,
  then the more senior) stands, as at replicas ([roster.md](roster.md),
  section 3.5.2). Neither undoes its partner's authority
  ([roster.md](roster.md), section 3.5.2): the attack of either on the
  enrolment that its partner's author signed does not count. Otherwise a
  lowering backdated before its partner's enrolment would void it, and the
  partner's lowering with it, where the roster's merge keeps both.
- **Self-lowering**, a lower or disown whose slot reference names its
  author's own administrator slot, is never attacked.
- **Rank, then seniority**, where the procedure needs it: an event's key
  is `(255 − its author's administrator slot's rank, that slot's
  seniority, its height, its ID)`; an enrolment's author's administrator
  slot is the one it enrols.
- **Forks.** A pseudonym is void from its fork point, except its
  self-lowering events. Only events whose signatures the peer verified
  count as evidence.
- At most 4,096 valid contested events in one place (else `Full`).

The **merged skeleton** is the state over every valid contested event. A
skeleton request (an ack, an erasure or a credentials request) is **valid
at the peer** when its author is enrolled in an administrator slot that is
in at its place, no valid lower or disown of that administrator slot is
concurrent with it, and its author has not forked at or before it.

**Where the peer and the roster differ.** The skeleton mirrors only the
events that change who administers, so what the peer cannot see can make
the roster decide otherwise: an attack on a grant of `administer` by a
change the skeleton does not show, a roster event void for a reason only
its sealed part shows, an odd cycle that seniority decides differently, or
a change named by a key event, which a peer cannot tell from a roster
event. A removal of a member that was not yet an administrator at its
place is one: it has no twin, though the member it removes may be an
administrator in the merged roster. Replicas run this resolution over the
same storage events and compare. An administrator disowns an administrator slot the peer keeps for
a device that is not an administrator, and demotes and re-grants an
administrator the peer has left without one.

### 3.13 What replicas check

A replica runs these for the genesis and for each roster event `R` it has
opened that changes who administers:

```text
1. The genesis: a root is held.                                      else NoTwin
   R: roster.md checks that R names a twin exactly when it changes
   who administers.                                                  else TwinRequired / UnexpectedTwin
2. The twin R names is held.                                         else NoTwin
3. A root: one that section 3.11 does not refuse, with twin
   c(genesis) and duel_policy the genesis's.
   A twin: a change that section 3.11 does not refuse, with
   twin = c(R) under its own salt.                                   else BadTwin
4. Its author's administrator slot was made for R's author's device,
   and its enrolment is not foreign.                                 else BadTwin
5. Its author has not forked at or before it.                        else BadTwin
6. Its grants number one per device R grants administer, each with
   the rank R gives that device, in R's order; or its lower names the
   administrator slot of the device R lowers.                        else BadTwin
7. R cites it; its parents are skeleton events and checkpoints; its
   cuts are R's; every skeleton event in R's past other than the twin
   is in its past.                                                   else BadTwin
8. The cite-together rule holds for R.                               else BadTwin
```

- **The device of an administrator slot** `[c, index, maker]`: for the
  root's, the genesis's author; for a change's, the device granted
  `administer` at `index`, in its order, by the roster event `R'` the
  replica opened that names `maker` in visible key 15, when `c` is
  `c(R')` under `maker`'s salt. Any other administrator slot is made for no
  device.
- **Step 6** counts the grants only: each grantee is sealed in its token,
  which only that grantee opens. An enrolment binds its administrator slot
  to the device `R` granted at its index, in `R`'s order (below). A lower
  names the administrator slot of the device `R` lowers when that slot is
  made for that device: its `maker` is the root or a twin, never a copy of
  one.
- **Enrolments.** Every member that opens `R` derives `twin_secret(R)`. A
  replica opens each enrolment's binding under the `twin_secret` of the
  roster event that names its slot reference's `maker`, or of the
  checkpoint section 2.5 names for an enrolment whose cuts name one whose
  cut lists its slot, and checks that it opens, that it names the device of that administrator slot, and that
  `device_signature` verifies under that device's keys. An enrolment that
  fails is **foreign**: replicas map its pseudonym to no device, and a
  disown of its administrator slot is justified.
- The genesis is pending until a root passes, so a space whose founder
  never makes a good root is unusable. One device signs both a roster event
  and its twin, so a bad twin holds back only that device's events.
- The twin is the event key 15 names. A change no roster event names is
  never read as a twin, so signing a change with another event's
  commitment achieves nothing.
- A change named by a key event, or by a roster event it does not pass, is
  applied by the peer; its administrator slots are planted.
- Replicas read slot references as the peer does (section 2.4). A change
  that repeats another roster event's commitment, or the root's, passes for
  no roster event, since `c(R)` binds `R`'s author and `seq`; its
  administrator slots are planted, and a disown of one is justified and
  lowers it alone, never the administrator slot it copied.

### 3.14 Stability at the peer

An event `X` the peer holds is **stable at the peer** when, for every
administrator slot of the **stability set** whose pseudonym has not forked,
an **acknowledging event** of that administrator slot has `X` in its past
or is `X`.

- **The stability set** is the administrator slots in the merged skeleton,
  and each administrator slot that a valid lowering by **another**
  pseudonym lowered, by disown or by lower alike, until that lowering is
  **settled**: stable itself, over the administrator slots that are in at
  its place, the lowered one included, or held by the peer for T from its first
  sight. A self-lowering takes its author's administrator slot out at once.
- **An administrator slot's acknowledging events** are the event that made
  it and every skeleton event signed by the pseudonym validly enrolled in
  it. An unenrolled administrator slot acknowledges only through the event
  that made it. A space recovery member whose key stays offline never
  acknowledges anything after its grant, so in its space every request
  waits for T.
- A lowering of another administrator slot waits to settle so that one
  administrator cannot lower the others out of the set and then make its
  own erasure stable alone. The cost: after a hostile administrator's
  removal, requests wait up to T unless it acknowledges its removal.
- Replicas compute the same from the same events. Their own stability
  ([roster.md](roster.md)) counts a skeleton event as an event of the
  device its binding names.

### 3.15 The administrator's duties

An acknowledgement says "I hold this", not "I agree". An administrator's
client:

- SHOULD acknowledge, at each peer of the space, the events the peer
  reports as awaiting it, once it has judged them. An administrator that
  never acknowledges delays every request to T. A request in the past of a
  checkpoint in effect in its view counts as judged: each member of that
  checkpoint's electorate judged it with the checkpoint's whole past before
  it voted, and a device that forgot that past, or started from the
  checkpoint, takes their votes for it as it takes them for the record
  ([roster.md](roster.md), section 3.15.6). It acknowledges by any
  skeleton event after the checkpoint, and never fetches a reported event
  it forgot;
- MUST, before it signs a skeleton event whose past would hold a request it
  judges void (an erasure, credentials request or disown whose author's
  device is not an administrator at its place, or which a roster event
  concurrent with it lowers), first publish a lower or disown of the
  requester's administrator slot whose parents leave the request out, so
  that the peer finds them concurrent and voids the request;
- MUST likewise lower, concurrently with the request, an administrator
  whose pending request it means to stop. This is the only veto one
  administrator has over another's erasure, and it costs the requester its
  administration;
- MUST NOT, while the administrators the skeleton resolves differ from the
  roster's in its view (section 3.12), sign an acknowledgement, a cut, or
  any other skeleton event but the twins of the roster events that repair
  the difference (a disown, or a demotion and a new grant). Every skeleton
  event after a checkpoint is a vote for its cut, so this withholds its
  votes too; a repair twin after the checkpoint is a vote as well, which
  is sound, since the demotion it carries excuses the member at replicas
  as its lowering does at the peer;
- MUST vote for a checkpoint it votes for at replicas with its pseudonym
  too, by a skeleton event that follows it, and the reverse: the peer
  counts the one where replicas count the other (section 3.21, "Votes").
  The vote is owed once the device votes for the checkpoint, and is
  signed then, whether or not a peer's awaiting report asks for it, so
  that members that sync without a peer see cuts take effect too. It is
  signed by the pseudonym that votes for the device's slot: the one the
  cut names, or the device's enrolment of the slot after the checkpoint,
  the newest of its pseudonyms;
- MUST NOT vote for a checkpoint, by any event, before each always-on
  peer of the space that it reaches has acknowledged the checkpoint's cut.
  A peer then holds the cut before it can matter, so it never carries out
  a request that the checkpoint could still make late (section 3.16). A
  device that reaches no peer votes without waiting, so that members
  syncing only with each other still checkpoint; a peer it did not reach
  can then carry out, at its timeout, an erasure that the checkpoint makes
  late. That peer answers `erased` from then on, and a client whose view
  holds the erasure late tells the application that the peer erased a
  space the checkpoint kept, naming the erasure's author, so that the
  space moves to another peer or is given up;
- signs again, after a checkpoint it follows, each erasure and credentials
  request of its own that is concurrent with that checkpoint and not yet
  carried out, naming for credentials the current state of its view, and
  tells the application that the request was signed again; the first one
  stays waiting at a peer until the cut's fate is decided (section 3.16),
  and is void if the cut takes effect.

### 3.16 Erasure

An erasure is a skeleton event of type 5. It names the whole space, and
nothing narrower (section 2.4). With `accepted` the peer's first sight of
it:

```text
erasure(valid, undecided, stable, accepted, now, T):
  0. not valid at the peer (section 3.12), or late under the
     cut in effect (section 3.21).                            Void
  1. concurrent with a cut that can still take effect.        Wait
  2. stable at the peer.                                      Execute
  3. lower(accepted, now) >= T, on the peer's timeline.       Execute
  4. otherwise.                                               Wait
```

The peer judges validity again when it executes, so a concurrent lowering
that arrived during the wait voids the erasure.

- **Undecided cuts.** A cut **can still take effect** at the peer when it
  is valid and not in effect, and its epoch is later than the cut in
  effect's (any epoch without one), or equal to that of a cut in effect
  whose checkpoint has a larger ID, which it could replace (section 3.21). A request is concurrent with it when
  it is neither in the cut's past, nor the cut, nor follows its
  checkpoint. Step 1 waits until the cut takes effect, which makes the
  request late (step 0), or can no longer take effect, and the timeout of
  step 3 runs on meanwhile. So the peer destroys nothing that a
  checkpoint replicas may still put in effect would make late.
- **A cut the peer does not hold yet** cannot make a carried-out request
  late while administrators reach the peer: an administrator votes for a
  checkpoint only once each peer it reaches has acknowledged its cut
  (section 3.15), and a peer that has carried out an erasure stores
  nothing more of the space, so a cut that reaches it after the erasure is
  never acknowledged there, gets no honest vote from a device that reaches
  it, and never takes effect at replicas either. Only votes signed while
  no peer was reachable leave this open (section 3.15). Once executed, an erasure
is final at that peer. Execution removes every event and object of the
space. The peer keeps a tombstone, the space ID and the erasure event, and
refuses every later present and store, and every create or import, of the
space (`erased`). Erased bytes leave usage when the erasure executes.

**At replicas.** An erasure is valid in a replica's view when its pseudonym
is enrolled, not foreignly, for a device that is an administrator at its
place, no valid roster event concurrent with it lowers that device, and no
checkpoint in effect makes it late. The client reports a valid erasure to
the application, and drops the space's units and objects from its own
store once the erasure is valid and stable in its view, or once it has
held it for `gap_key_timeout`, but never while it holds a valid checkpoint
concurrent with the erasure that can still take effect in its view (not in
effect, and not passed over by the chain in effect, [roster.md](roster.md),
section 3.15.4), as a peer waits (above).

- **A device's own erasure.** A device that dropped a space for its own
  erasure keeps, until each always-on peer of the space it reaches answers
  `erased` for it, the space's `log` record, its `pseudonym` records, its
  tips, the erasure's `event` record, the space's `peers` record and the
  administering devices of its view at the drop, each device ID with its
  X-Wing key ([at-rest.md](at-rest.md), section 3.4). It keeps nothing of
  the space's content and no key of it, which it dropped, so it cannot
  fetch: what it can do is present its pseudonym on an administration
  connection (section 3.7, credential 3) and store its erasure again,
  which a peer acknowledges as an identical retry (section 3.2). What the
  application keeps is its own. An erasure is a promise to the user, so
  the client never drops this residue, nor leaves the erasure undone,
  without telling the application:
  - **Asking.** The device asks each peer by presenting the pseudonym and
    storing the erasure again. A peer that carried it out answers `erased`
    at the present (section 3.7, step 2). One that holds it waiting
    acknowledges it. One that holds it late answers as below.
  - **The bound.** The bound is `erasure_timeout` at its default
    ([overview.md](overview.md), section 6.8), since the device cannot
    know each peer's, counted as `lower(first sight, now)` on the device's
    timeline from the first sight its erasure's `event` record keeps. Once
    it has passed and a peer of the space has not answered `erased`, the
    client tells the application which peers have not, and that the space
    may live on there. It keeps the residue and asks on, and deletes it
    once each peer has answered or the application gives the space up.
  - **The peer's answer to a late erasure.** A peer that stores an erasure
    late under the cut in effect (section 3.21), or is sent one again that
    it holds late, acknowledges it and sends, on that administration
    connection, `ErasureLate` ([transport.md](transport.md)): the space,
    the erasure's ID, the signed envelope of the cut in effect at the peer
    (the erasure is late under it or under a cut before it in its chain,
    late for good either way, and a peer that truncated holds it too), that
    cut's checkpoint's ID, and the **standing** of the
    pseudonym's administrator slot in that cut, which is what the device
    needs to know now: 0, the cut lists the slot enrolled to this pseudonym; 1, it
    lists the slot with another pseudonym or none; 2, it does not list the
    slot. The residue tells the two cases of standing 1 apart itself, from
    the cut's entry for its slot, which names a pseudonym's root or
    enrolment or is empty. A peer that sends it holds the space, which lives on there: it
    has not erased it, since it would then answer `erased`.
  - **What the residue checks.** Only what needs no key of the space: the
    cut's envelope decodes and verifies its Ed25519 half ([crypto.md](crypto.md)),
    and is of this space; it is a storage event of type 7 whose body
    reads (section 2.4); the cut's slots
    list the residue's slot (its `pseudonym` record's item) exactly when
    the standing is 0 or 1; and that slot's entry names a pseudonym when
    the standing is 0. A message that does not read, or names another
    space or erasure, is `Malformed`; any other mismatch is `PeerError`,
    which the client reports with the answer, and it then treats the peer
    as one that has not answered. That the erasure is outside the cut's past,
    that the cut is in effect, and that the checkpoint named is the cut's,
    are the peer's word. The message names the checkpoint by ID rather than
    carrying its envelope, so that it holds a cut of any size the storage
    event allows: a cut's signed envelope is at most 262,144 bytes, and the
    message within its cap of 266,240 whatever the checkpoint's size: the device cannot
    place either without the log. It acts on that word only in ways that
    lose nothing: it tells the application at once that its erasure is
    late at that peer, naming the checkpoint, and that the space lives on
    there; it keeps the residue; and it asks to be let back in, or says it
    cannot be.
  - **Back in.** The device cannot sign after the checkpoint from the
    residue: an event after it needs the checkpoint's record and keys, to
    tell whether its device still administers the space there, to enrol
    its slot again when the cut lists it with no pseudonym (section 3.21,
    "A late enrolment"), and to vote as section 3.15 requires. With
    standing 0, or standing 1 and an empty entry, it is, by the peer's
    word, still an administrator there whose slot it may still sign for,
    and, being a member, it asks for a welcome: it
    deposits a signed welcome request ([admission.md](admission.md),
    "Welcome requests") in the device mailbox of each administering device
    the residue names, at the peers it names. An administering device that
    holds the space and finds the requester a member at its merged roster
    answers with a welcome naming a space snapshot, as for a restored
    member ([admission.md](admission.md), sections 3.10 and 3.11). The
    device then fetches under the welcome's read credential, starts from
    the snapshot as a replica that lost its store does
    ([roster.md](roster.md), section 3.15.6), judges the checkpoint, and,
    if its device still administers the space after it, signs the erasure
    again after it, as section 3.15 says (with its pseudonym when the slot
    is enrolled to it there, else after enrolling the slot again), and
    drops the space again as above; if the slot is enrolled after the
    checkpoint to another pseudonym, it is held (below); if its device no
    longer administers, the erasure is void, and the client tells the
    application so. Until a welcome arrives the client tells the
    application that it waits for one, and the application may give the
    space up instead.
  - **Standing 1, the slot held by another pseudonym.** When the cut's
    entry names another pseudonym, or the device back in finds the slot
    enrolled after the checkpoint to another, the slot is enrolled and
    stays so while it is in: no enrolment of it is valid again (section
    3.12, `AlreadyEnrolled`), and the device holds no pseudonym that can
    sign for it, so it cannot complete its erasure. It asks for no welcome
    for this (it would have nothing to sign), tells the application
    (`SlotHeld`, naming the space, the peer and the holding pseudonym's
    root or enrolment, and that its erasure waits on it), keeps the
    residue and asks on, so that a later `erased` from any peer still
    reaches it. Section 3.21 says who can hold the slot and who must act:
    the device that holds the holding pseudonym, or another administrator.
  - **Standing 2.** By the peer's word the device no longer administers
    the space after the checkpoint, so no erasure of its own can be carried
    out there: the client tells the application that the space lives on
    at that peer and that the device can no longer erase it, and keeps the
    residue until the application gives the space up, so that a later
    `erased` from any peer still reaches it.
  - **What is left.** A checkpoint the device never receives, which
    members voted for while they reached no peer (section 3.15), keeps the
    space at those members; their clients tell their applications that a
    peer erased a space the checkpoint kept, naming the erasure's author.
    A peer that carried out the erasure answers `erased`, and never
    `ErasureLate`, whatever cut reaches it after.

**Less than a space.** No request erases one stream or one object. A writer
deletes a document for good with a release (section 3.18): the peer stops
serving it at once, and deletes its content once the release is reclaimed,
after `release_retention`, keeping only the units that events outside the
stream name, as events without content. Routine cleanup sends no erasure
either: compaction uploads a snapshot unit, and the peer collects what it
replaces (section 3.19).

### 3.17 Credentials requests

A credentials request is a skeleton event of type 6 that names the entries
that stay live (key 3), the recovery entries that stay live (key 4), or
both. It is carried out by section 3.16's rule, its steps 0 and 1
included, and then:

- without key 3, no credential entry changes;
- every named entry the peer holds becomes live, revived if retired; a named
  entry the peer lacks is skipped;
- every other entry whose state's rotations are all in the request's past
  retires. Entries of rotations concurrent with or after the request are
  untouched, so a request retires nothing its author has not seen.
  Revival comes first: a named merge entry retires again when one of its
  inputs retires here (section 3.6, rule 4). Open connections lose at once
  what they held by the entries it retires (section 3.6, "Connections").
- with a keep list (key 4), every named recovery entry the peer holds
  becomes live; a named fetch key the peer lacks is skipped; it is
  registered, not revived, by a later registration. Every other recovery
  entry the peer added before its first sight of the request retires.
  Without key 4, no recovery entry changes.

A credentials request a peer carried out before a cut concurrent with it
reached that peer stays carried out there, though the cut makes it late:
its effect is on the peer's entries alone, which no replica judges, and a
later request names the entries anew. The requester's client signs it
again after the checkpoint (section 3.15), so the entries end as the
current state of its view names them.

An administrator's client MUST send one after each roster event that
removes a member or lowers a level, and SHOULD send one whenever a peer
reports live entries outside the current state of its view. It names the
current state's entries: the single rotation's, a merge entry whose keys it
derives, or each input's. An entry is named by its read key as well as its
state, so a request revives no junk merge entry. In the personal space, an
administrator's client sends a keep list whenever the person's list revokes
a passkey member or a recovery key, naming the fetch keys of the active
ones ([identity.md](identity.md)); this retires the revoked member's entry
and any a writer registered as junk. In another space, administrators
cannot tell a person's entry from junk, so a keep list there retires every
recovery entry it does not name.

### 3.18 Release and restore

Any writer releases and restores. Both are writer requests, signed by the
writer's device and stored under the release right; they sync to every
peer and replica like any event. A release names one stream: its units, and
the objects only its units reference. A restore names the stream it brings
back or, with key 5, a snapshot unit whose collection it cancels (section
3.19).

A peer cannot judge whether the author writes. Replicas judge a writer
request by [roster.md](roster.md)'s write rule, as a unit. A client that
finds its release refused restores what it released.

A stream is **released** at a peer when some release names it and every
maximal event among the releases and restores that name it is a release: a
restore concurrent with a release wins. With a cut in effect at the peer
(section 3.21), the events counted are those in the cut's past and those
that follow its checkpoint, and every one of the past is before every one
that follows the checkpoint, which holds that whole past. A release or
restore that is late under a cut of the chain in effect counts for
nothing, then and under every later cut, though a later checkpoint's past
holds it through its author's chain; its own verdict stays `Late`, and its
author signs it again after the checkpoint. None of this needs a late
event's place among the events of the past, which a peer that truncated
no longer holds (section 3.22). While released, fetches of the
stream answer `released` and listings omit it, but for the units that an
event outside the stream names as parents, which the peer serves by ID as
any parent; new units of the stream are
refused (`released`), so a stale replica cannot bring it back silently; and
its bytes leave usage at the release's first sight. A restore counts them
again, and is refused with `quota_exceeded` if they no longer fit.

```text
release(released, undecided, stable, released_at, now, retention, T):
  1. not released.                                            Keep
  2. a release that makes it released is concurrent with a
     cut that can still take effect (section 3.16).           Keep
  3. lower(released_at, now) >= retention, and (stable at the
     peer, or lower(released_at, now) >= T).                  Reclaim
  4. otherwise.                                               Keep
```

`released_at` is the peer's first sight of the latest release that makes
the stream released; `stable` asks that each such release be stable at the
peer; `retention` is `release_retention`. Reclaiming deletes the stream's
units and the objects only they reference, and keeps a released marker:
the stream's units are refused until a restore, after which a writer may
store them again. It keeps, as an event alone, each unit of the stream
that an event outside it names as a parent, as collection keeps a parent
(section 3.19): a release removes a stream's content, not the fact that
its units existed, so a replica that catches up places what names them,
space events included ([units.md](units.md), "Confirming heights"). A kept
unit references no object, keeps no hold live, and stays out of usage; the
peer keeps its own stub of each removed unit that a remaining event names,
for its own placement, as collection does ([units.md](units.md), "Parents
of space events"). A restore is valid at any
time, but after the retention it may find no bytes at a peer.

### 3.19 Collection

A snapshot unit declares, in its visible part, the **cover** it replaces in
its stream ([units.md](units.md)). A peer computes the cover from its own
index and checks it before it collects. With `seen` the peer's first sight
of the snapshot unit:

```text
collect(cancelled, stable, seen, now, T):
  1. cancelled: a stored restore names the snapshot unit.     Keep
  2. stable at the peer, or lower(seen, now) >= T.            Collect
  3. otherwise.                                               Keep
```

- Collecting removes the units of the cover, except those an unreplaced
  event names as a parent for which no stored snapshot unit holds a stub,
  and those a space event names as a parent, which the peer keeps as
  events alone ([units.md](units.md), "Parents of space events"); and the
  objects that no stored, unreplaced and unreleased unit references. A
  unit kept so stays replaced: its objects go with the cover's.
- The cover leaves usage at the snapshot unit's first sight, and counts
  again if a restore cancels the collection. A covered unit stored again is
  collected again at the next pass.
- Collection waits for stability because replicas refuse a snapshot by a
  writer whose removal is concurrent with it.
- Any writer cancels the collection of a false snapshot with a restore
  naming it. A client does so for a snapshot it finds refused, or reports
  as a bad compaction.

### 3.20 Quotas and rates

Usage, per space, counts the bytes of stored events and objects, less what
is released, covered and not restored, erased, or collected as an old
version ([ext-file-versions.md](ext-file-versions.md)), each object once; and
the space's invite drops while they are held
([ext-invite-links.md](ext-invite-links.md)). The operator sets each
space's quota; with [ext-libraries.md](ext-libraries.md), a library's quota
covers its spaces. A store past the quota is `quota_exceeded`.

A peer limits rates on its own timeline. The operator sets them; the
defaults are:

| What | Default |
|---|---|
| Presents per connection | 64 per minute |
| Space events stored per author per space | 600 per hour |
| Storage events stored per author per space | 600 per hour |
| Merge statements per space | 64 per hour |
| Device-mailbox deposits per source address, without a deposit token ([transport.md](transport.md), "Mailboxes") | 120 per minute |

A rate applies per author and, apart, per entry: the entry whose upload
key the storing connection proved. So a writer that mints keys is still
limited by the entry it stores under. The stores of an import in
progress (section 3.1) count toward no rate: a log arrives whole, and the
quota and the import's end bound them.

### 3.21 Skeleton cuts

A space checkpoint ([roster.md](roster.md), "Checkpoints") names, as its
twin, a **cut**: a skeleton event of type 7, signed first by its author's
pseudonym with `twin` = `c(R)` of the checkpoint as a change's twin is, so
that a peer, which cannot open the checkpoint, can start the skeleton
afresh from it.

- **What a peer checks** before it applies a cut, in order:

  ```text
  1. The body reads (section 2.4).                                  else that class
  2. A stored space event names it in visible key 15, cites it,
     and has every other parent in the cut's past: its checkpoint,
     the first such in canonical order.                             else Unnamed (pending)
  3. Its epoch, below.                                              else CutPending
  4. Its author's administrator slot is in, enrolled to it, in the
     merged skeleton of its past.                                   else NotAnAdministrator
  5. It verifies under that pseudonym's ML-DSA-65 key, from the
     root or enrolment that enrolled it.                            else BadSignature
  6. Its slots are exactly the administrator slots in that merged
     skeleton, each with the keys, seniority and enrolling root or
     enrolment the peer holds for it.                               else BadCut
  7. Each standing entry names one of its slots, with an empty
     pseudonym, or a slot that is not in that merged skeleton (one a
     peer that truncated no longer holds included), with empty bytes
     or a root or enrolment of that slot the peer holds; the orders are 1 to n, the
     number of entries, each once; a dormant value from 3 is 2 + k
     with k from 1 to n + 1.                                         else BadCut
  ```

  Step 2 is the converse of the cut's own parents (below): a cut cites
  every other parent of its checkpoint, and its checkpoint cites the cut
  and nothing outside the cut's past, so the checkpoint's past is the cut
  and its past, as replicas require (roster.md, section 3.15.2, step 7). A
  space event that names a cut without citing it, or that cites something
  outside the cut's past, is no checkpoint of that cut to a peer: the cut
  stays `Unnamed` until a space event that passes step 2 names it, held
  pending as a change no space event names is (section 3.2): never served
  as stored, and dropped after `orphan_grace`. Replicas find such a
  checkpoint `BadTwin` from its own parents, without fetching the cut. A peer reads the parents of
  the naming event and the cut's past from what it holds; at a peer that
  truncated, a deleted event is in the past of the cut it kept, so in the
  past of any later cut. Every peer, and every replica reading the
  skeleton, therefore takes the same event as a cut's checkpoint, or none.
  Steps 4 to 7 read the merged skeleton of the cut's past, from the cut
  in effect there, so step 3 comes first. Step 4 reads the author's
  enrolment in that skeleton, not any root or enrolment the peer holds,
  and the signature is checked after it, under the key of that very
  enrolment: a cut by a pseudonym whose slot was removed, or never in, is
  `NotAnAdministrator`, final, whether the peer still holds that
  pseudonym's enrolment or deleted it when it truncated, so that every
  peer stores and judges it alike whatever it holds of that slot's
  history, and a cut unnamed is `Unnamed` before any key is sought.
  `NotAnAdministrator`, `BadCut`, `BadSignature` and `CutPending` are
  final, and every one of them is stored with no effect. A replica runs steps 1 to 7 too, and
  checks the cut against the checkpoint's record besides (below).
- **Following.** A pseudonym's skeleton events follow the checkpoint its
  device follows ([roster.md](roster.md), section 3.15.7), since a peer
  judges an event that follows none of the checkpoints in effect there as
  late. A twin, whose other parents are skeleton events, therefore also
  cites the checkpoints its roster event's other parents' cuts give, and
  declares the same cuts as its roster event: section 3.13, step 7. A cut
  likewise declares the same cuts as its checkpoint. Without it, a twin
  signed before its pseudonym voted would make, at replicas, an
  administrator slot the peer never applies.
- **The replica's check against the record** ([roster.md](roster.md),
  section 3.15.8, read into section 3.8's step 3): the cut declares the
  same cuts as its checkpoint, and each `slot` entry of the record's
  administrators names a slot of the cut, whose `pseudonym` names a root
  or enrolment by that entry's pseudonym, or is empty exactly when the
  entry's is; and the standing entries are exactly those the record gives
  (section 2.4): one per administrator with a `slot` entry, naming that
  slot, and one per member the record hears, naming the most senior slot
  made for it, out in the skeleton of the checkpoint's past, if there is
  one, each with the order and `dormant` the record's ranks, seniorities,
  capabilities and grants give. Else `BadTwin`. The cut's other slots, planted ones and
  those whose disown section 3.13 deems justified (such as a slot whose
  roster event a concurrent removal voided), are slots no `slot` entry
  names: a replica that forgot maps their pseudonyms to no device, as a
  foreign enrolment's, and administrators disown them as before.
- **Epochs.** Let `L` be the last cut in effect in the cut's past, if
  any. The cut's checkpoint follows `L`'s checkpoint, and every checkpoint
  its checkpoint's cuts reach is at or before `L`'s checkpoint or after it
  ([events.md](events.md), "Cuts"); no valid cut whose checkpoint is after
  `L`'s checkpoint (any, without `L`) is one its own checkpoint follows;
  and its `epoch` is one more than `L`'s, or 1 without `L`. Else it is
  `CutPending` (final), as a checkpoint made too early is. The order check
  reads envelopes alone, and the validity it asks for is only of cuts
  after `L`'s checkpoint, which a peer that truncated under `L`, or under
  an earlier cut, still holds; so such a peer and one that kept everything
  decide every cut alike, whatever events an administrator signs. Without
  the order check, a cut whose checkpoint reaches both `L`'s checkpoint
  and a valid cut's checkpoint concurrent with it would be `CutPending`
  where that cut is held whole and valid where it was truncated. A valid
  cut whose checkpoint `L`'s follows is in effect in its past, being in
  `L`'s.
- **Parents.** A cut cites every parent of its checkpoint, but itself,
  beside its pseudonym's previous event: the checkpoint's past is the
  cut's past and the cut, so that the skeleton a peer resolves for the
  cut's slots is the one the record's `slot` entries read
  ([roster.md](roster.md), section 3.15.2, step 7). A twin of a change
  cites only skeleton events and checkpoints (section 3.13, step 7); a cut
  is not held to that.
- **Votes.** A **vote** for the cut is a skeleton event that follows the
  cut's checkpoint ([events.md](events.md), "Cuts") and whose cuts reach no
  checkpoint concurrent with it, exclusive as a device's is, signed by a
  pseudonym of the slot it votes for: the pseudonym the cut's slot entry
  names; the one whose enrolment of that slot follows the checkpoint (the
  enrolment is itself a vote); or, for a slot that is out, the pseudonym
  whose root or enrolment its standing entry names. Its ML-DSA-65 half is
  one the peer verified, under the key that root or enrolment carries
  (section 3.11), whatever the resolution decides of it; so is a
  lowering's that excuses.
- **Waited and excused slots.** The cut waits for each slot of a standing
  entry whose `dormant` is 0: the slots of the checkpoint's electorate as
  its record gives it ([roster.md](roster.md), section 3.15.4). Such a slot
  `s` is **excused** by a lower or disown of `s` that the peer verified,
  whatever its verdict, that follows the checkpoint and reaches no
  checkpoint concurrent with it, signed by a pseudonym of `s` itself, or of
  a slot `t` with a standing entry among the cut's `slots` such that: `t`'s
  order is lower than `s`'s; or `t`'s `dormant` is 2 and `t`'s rank is at
  least `s`'s; or `t`'s `dormant` is `2 + k` with `k` at most `s`'s order
  and `t`'s rank at least `s`'s. An administrator with no slot has no
  entry: the peer neither waits for it nor lets it excuse, and honest
  administrators withhold their votes while the skeleton holds no slot for
  an administrator (section 3.15), so that difference is repaired, by a new
  grant, before the cut takes effect. These are the replicas' excuses, read from
  the skeleton: removed, demoted or marked dormant by a member that
  outranks it, by itself, or by a recovery member of a rank at least its
  own, since a twin lowers a slot exactly when its roster event does one of
  these (section 3.10).
- **In effect at the peer.** A valid cut is in effect at the peer when every
  slot it waits for has a vote or is excused. Validity is final, and votes
  and excuses only accumulate as events arrive, so a cut in effect over
  some events is in effect over every set that holds them: no event a peer
  receives later takes it out of effect, whatever it has done on it. Only
  the choice among cuts in effect below can move, to a concurrent one of
  the same epoch with a smaller checkpoint ID, which needs two electorates
  with no member in common ([roster.md](roster.md), section 3.15.4).
  Starting from no cut, or from the cut it kept, a peer takes, among the
  valid cuts in effect of the next epoch whose checkpoints follow the
  current one's, the one whose checkpoint has the smallest event ID, and
  repeats.
- **A lowering no roster event made.** A lowering that a key event names,
  or one whose roster event is void, excuses a slot at the peer as any
  verified lowering by an outranking slot does, while replicas, which read
  the roster event, may not excuse its member. Only an administrator that
  outranks the slot it lowers can sign one, and such an administrator can
  remove that member outright, which replicas then excuse too; so it puts
  the peer ahead of replicas only on that administrator's own signed
  event, as a dishonest signer can, and an honest one never signs it.
- **What the peer cannot see.** A peer counts a pseudonym's vote where
  replicas count its device's ([roster.md](roster.md), section 3.15.4), and
  an honest client signs both (section 3.15). With every standing entry
  checked against the record, the peer's rule therefore puts a cut in
  effect only when each member of the checkpoint's electorate voted, or
  was excused as replicas excuse it, but in two cases:
  - A replica also excuses a member shown forked by its device's events,
    which a peer does not read; there the peer is stricter, and an
    administrator that outranks the forked member, or a recovery member,
    lowers its slot. A forked member that outranks every other
    administrator, in a space without a recovery member, stops checkpoints
    at the peer, as a lost one does at replicas.
  - A dishonest administrator can vote through its pseudonym and withhold
    its device's vote, a heard member among them, which the contested
    conduct forbids to vote at all ([roster.md](roster.md), section
    3.15.7): the peer is then ahead of replicas on that administrator's
    word alone, and replicas wait for it until a member that outranks it
    excuses it, as for any vote withheld.
  - A dishonest administrator that outranks a slot can lower it by an
    event no roster event made (above).
- **Who decides that a cut is in effect.** This rule is one function of the
  skeleton events: a peer applies it to what it holds, and a client to what
  its view holds, to know when it may truncate, propose or enrol again.
  Neither is authoritative over the other; they agree once they hold the
  same skeleton events, which sync brings about. A client acts on its own
  view, and a peer that has not yet received an event a client holds
  catches up from it.
- **The skeleton after a cut.** The cut stands as the skeleton's root: its
  slots are in from the start, each enrolled to the pseudonym of the root
  or enrolment its entry names, whose ML-DSA-65 key that event gives. A
  slot reference names a slot of the cut by its reference as written
  there, or a slot an applied change after the cut made. Heights count from
  the cut at 0; seniority is `(epoch, height, hash, maker)`, the cut's slots
  keeping theirs. The 4,096 bound counts the valid changes, disowns and
  enrolments after the cut, and not the cut, as it counts no root. Stability
  (section 3.14) reads the cut's slots and the events after it; a lowering
  in the cut's past is settled.
- **Late skeleton events.** With a cut in effect at the peer, a skeleton
  event other than a cut that is neither in the cut's past, nor the cut,
  nor follows its checkpoint is **late** at the peer, as
  [roster.md](roster.md), section 3.15.1, calls one late at a replica. The
  peer stores it once it
  passes section 3.2 and its body reads (section 3.11, step 1), and a
  late enrolment the checks of "What a late enrolment opens" (below), runs
  no other step of section 3.11 on it, and acknowledges it as stored: it is
  never refused or held for being late, so that the events that cite it, a
  device's vote among them, are placed. It has no effect at the peer: it
  is in no skeleton the peer resolves after the cut, makes, enrols or
  lowers no administrator slot, acknowledges nothing and votes for no cut,
  and a late erasure or credentials request not yet carried out is void
  (`Late`). Its ML-DSA-65 half is not verified, so it is never fork
  evidence. An event stored before the cut took effect is late from then
  on in the same way. Lateness follows the cut in effect as it changes: an
  event stored late that a new cut in effect no longer makes late is
  checked then by section 3.11, and a step it fails voids it, with that
  step's class, as a stored event. A cut concurrent with the cut in effect
  keeps the checks above, which read its own past, since by the order
  above it may still take that cut's place.
- **What a late enrolment opens.** A late enrolment is stored after its
  body and section 3.2 alone, so a connection that presents its pseudonym
  provisionally could store one whose slot is invented. It is stored and
  acknowledged only if, in order: its `seq` is 1 and its author is no
  pseudonym whose root or enrolment the peer holds before it in canonical
  order (else `BadSignature`,
  as section 3.11, step 3, classes the same checks); its `mldsa` beside an
  empty X-Wing key hashes to its `kc` (else `NotCommitted`); and it
  verifies under its own `ed` and `mldsa` (else `BadSignature`). The
  classes are step 3's, so that a late and an ordinary enrolment that fail
  the same check are refused alike. The connection
  it opens may store only that pseudonym's late skeleton events, each of
  which has no effect, and is reported nothing; any other event of it is
  refused (`NotAuthorized`). A late pseudonym's honest device signs
  nothing after the checkpoint with it, and what it signed before is late,
  so this costs it nothing, and quota and rates bound what anyone stores
  this way. A device's vote that cites a late event is placed as before.
- **A late enrolment.** An enrolment concurrent with a checkpoint is not in
  its cut's past, so the cut lists its administrator slot with no
  pseudonym, or with another, when an enrolment of the same slot that is
  concurrent with it is in the cut's past (the two would void each other
  as `ConcurrentEnrolment`, but the world after the cut holds only that
  one). Once the checkpoint takes effect at a
  replica, the enrolment is late there; once the cut takes effect at the
  peer, late there too. Its pseudonym is enrolled in no slot of the world
  after the checkpoint: replicas map it to no device
  ([roster.md](roster.md), section 3.15.5), and the peer stores its
  events, late or after the cut, without effect (section 3.11, "No
  refusal for standing"). The client of the
  device that enrolled it:
  - signs with that pseudonym no event that follows the checkpoint, and
    cites none of that pseudonym's events from an event after it;
  - once it votes for the checkpoint (section 3.15), and when the cut
    lists the slot with no pseudonym and no enrolment of the slot after
    the checkpoint is valid in its view, enrols the same
    administrator slot again: a new pseudonym, its enrolment after the
    checkpoint, authorized with the same slot token, its binding sealed as
    section 2.5 says, under the `twin_secret` of the checkpoint its cuts
    name whose cut lists the slot: this checkpoint, or one after it that
    also lists it. The enrolment is the slot's vote at the peer, which the
    cut waits for. The slot is then unenrolled in the world after the
    cut, so the new enrolment is valid there at the peer and maps to the
    device at every replica. Until then the device signs no skeleton event
    after the checkpoint, and so no roster event that needs a twin. When
    the slot is held instead, it follows "A slot another pseudonym holds",
    below;
  - treats what it signed on top of the late enrolment as work concurrent
    with the checkpoint ([roster.md](roster.md), section 3.15.7): its
    roster events whose twins the late pseudonym signed are late, or
    `BadTwin` when after the checkpoint, and it re-signs, after the new
    enrolment, each removal and demotion among them that the roster still
    needs, with a twin of the new pseudonym, and lists the others for the
    administrator.

  The device's own events after the checkpoint are unaffected: one whose
  past holds the late enrolment, its twins or its roster events only
  through its `prev` votes for the checkpoint as any does. One that cites
  a late event otherwise is `MixedCut` at replicas and votes for nothing
  ([roster.md](roster.md), section 3.15.1); at the peer, a vote for a cut
  is read from its envelope alone, whatever late events its past holds.
- **A slot another pseudonym holds.** A device's administrator slot is
  held by another pseudonym when a valid enrolment of it in the world
  after the cut, in the cut's past or after the checkpoint, is not one
  the device signed. Only a holder of the slot token can sign one, so the
  other pseudonym is one of two:
  - **another installation of the same device**: a second store of the
    device's keys, such as one restored from a copy made after the grant
    and before the enrolment was durable, which still held the token, or
    one that did its own duty above and enrolled the slot again after the
    checkpoint. Its binding names the device's own ID;
  - **another holder of the token**, such as the granter, which derived
    it: a foreign enrolment, whose binding names no device or another
    one, so that the administrators the skeleton resolves differ from the
    roster's (section 3.12).

  A device that holds the space tells them apart by the holding
  enrolment's binding; a residue, which holds no key, cannot, and says
  so. Either way the slot cannot be enrolled again while it is in
  (section 3.12), so the device enrols nothing, signs no skeleton event
  for the slot, and so no roster event that needs a twin, and tells the
  application (`SlotHeld`: the space, the holding pseudonym's root or
  enrolment, the holder, "another installation of this device", "another
  device" or "unknown", and whether an erasure of its own waits on it).
  The other installation administers in its place, and the application
  asks the user to act there; a foreign holder is repaired by another
  administrator as section 3.15 says, by a disown of the slot and a new
  grant, whose slot the device then enrols. Nothing is lost meanwhile: a
  request of the device's own that waits on the slot stays reported, and
  a residue keeps asking its peers.
- **Requests of the cut's past.** An erasure or credentials request in the
  cut's past keeps the verdict and the stability of the skeleton it was
  made in, the one before the cut, read over every event the peer holds,
  those after the cut included. Every event after the cut holds the cut's
  whole past, so the votes that put the cut in effect acknowledge every
  such request for their slots, and an administrator slot of the cut also
  acknowledges by every skeleton event after the cut of the pseudonym
  enrolled in it in the world after the cut, at the cut or later. No
  acknowledgement needs the request itself, so a device that forgot it, or
  started from the checkpoint, acknowledges it as any other does. What
  such a request can still wait for once the cut is in effect is a slot of
  the cut that stays unenrolled, and a slot that a lowering not settled at
  the cut took out; each wait ends `T` after the request's first sight at
  the latest (section 3.16).
- **Entries and accounting.** Credential entries are kept across a cut: an
  entry of a rotation in the cut's past stays as it was, so a member
  offline across the cut catches up with its retired read credential.
  Deleted bytes leave usage when they are deleted.

### 3.22 Truncation

A peer cannot open a checkpoint ([roster.md](roster.md), "Checkpoints"),
but it reads which events follow one: every event's envelope declares the
checkpoints its past holds ([events.md](events.md), "Cuts"). A peer calls
`c` a **cut** when some stored event's cuts name it.

- **When.** A checkpoint `c` whose skeleton cut is in effect at the peer
  (section 3.21) may be truncated under once that has held for
  `cut_retention` on the peer's timeline, and once every erasure and every
  credentials request in `c`'s past is carried out or void at the peer
  (sections 3.16 and 3.17): truncation would take away the place a waiting
  one is judged at. A cut in effect has every enrolled slot's vote after
  `c`, so such a request is normally stable, and carried out, by then
  (section 3.21, "Requests of the cut's past"); otherwise it is carried
  out `T` after its first sight, so truncation waits at most the later of
  `cut_retention` from the cut's effect and `T` from the first sight of the
  last request in `c`'s past.
- **What is always kept.** The genesis; `c`, its cut and its record object;
  the envelopes of the checkpoints `c`'s cuts reach ([events.md](events.md),
  "Cuts"); the root or enrolment each slot entry of the cut names, which
  carries its pseudonym's key, and the root or enrolment each of its
  standing entries names, whose pseudonym votes for an out slot (section
  3.21); the root or enrolment of each pseudonym that signed an erasure
  the peer holds late, so that it still accepts that pseudonym's present
  and answers it `ErasureLate` with its slot's standing, as a peer that
  kept everything does (section 3.16); of the releases and restores in `c`'s past
  that name a stream and are not late under an earlier cut, the maximal
  ones of each stream as section 3.18 counts them, which the peer finds
  before it deletes anything, and every
  restore that names a snapshot unit (sections 3.18 and 3.19); and every
  unit. A release or restore of `c`'s past that another one there of the
  same stream follows decides nothing once `c`'s cut is in effect, since
  every event that counts beside it holds both; keeping only the maximal
  ones, which are concurrent with each other, leaves nothing whose order a
  peer that truncated would need, so it and a peer that kept everything
  find the same streams released.
- **Units are never truncated.** A unit leaves a peer only by collection
  (section 3.19), whether it is in a checkpoint's past or not: truncation
  never deletes one, so a stream's state stays served from its snapshots
  and the units they do not cover.
- **Truncating.** The peer MAY then delete every other space event, anchor
  and storage event in `c`'s past. It keeps the ID of each event it
  deletes, for its own placement only: an event whose parent it deleted is
  placed as if that parent were stored. Deleted bytes leave usage. An event
  it deleted that is sent to it again is acknowledged as an identical
  retry is (section 3.2) and not stored again: the peer held it durably,
  and it is in `c`'s past, where nothing it would store decides anything.
  It is given no verdict, `Late` included: a peer that kept everything
  holds it as it was. A `Want` for it is answered `Missing`. A peer that
  truncated counts, as part of the past of a later cut, the kept
  checkpoint's past that it deleted and what it kept of it: every later
  cut's checkpoint follows the kept one, so that past is in its past, and
  the peer judges the later cut as one that kept everything does.
- **Serving after truncation.** Catch-up serves what remains: the genesis,
  the cut, the events that follow it and the events kept above. A `Want`
  for a deleted event is answered `Missing`. An event that does not follow
  the cut and arrives later (a late event) is stored as any event, so that
  replicas can read its envelope.
- A peer that never truncates conforms. One that truncates under a cut
  that a concurrent stable checkpoint later beats loses that history; the
  members that kept it serve it ([roster.md](roster.md), section 3.15.6).

## 4. Security considerations

- **A removed writer racing ahead.** It holds the upload seeds of every
  state before its removal, and can hold a live entry of a rotation it
  stored before its removal reached the peer. It can store junk, rotations
  included, mint signing keys and fetch ciphertext it cannot open. It
  cannot retire an entry, erase or disown anything, or keep storing once a
  credentials request that names the current state is carried out, on a
  connection it kept open no more than on a new one (section 3.6). Its
  damage is quota and key state, both bounded and attributed to the entries
  it used. Under the cap, honest entries stay live until a superseded one
  is evicted, and any honest rotation that cites the flood makes the
  flood's rotations superseded.
- **Recovery entries.** A writer, removed or not, can register junk fetch
  keys up to the cap of 64 and block further registrations, until a keep
  list clears them. It cannot remove a genuine entry, and a fetch key grants
  no more than a retired read credential: catch-up.
- **Lingering credentials.** Between a removal and the next carried-out
  credentials request, the removed member fetches ciphertext and spends
  quota. Once the request is carried out, its open connections lose those
  rights with its entries (section 3.6): what bounds the window is when
  administrators end the credentials, not how long a connection lasts.
  The window is the request's stability: minutes where
  administrators are online; T after a hostile administrator's removal
  unless it acknowledges, and always T in a space with a space recovery
  member.
- **A granter that knows a slot token** can enrol a pseudonym of its own
  first. Replicas find the foreign binding and an administrator disowns
  the administrator slot; until then the peer accepts the enrolment.
- **A repeated commitment.** An administrator that signs a change with
  another administrator slot's commitment, the root's included, makes
  planted administrator slots of its own (section 3.11). Every slot
  reference names its maker, so the copy cannot reset, take over or remove
  the administrator slot it copied, and its copies only add to what a
  request waits for. A copy of a grant map, whole, gives nobody an
  enrolment: the grantee's enrolment names the genuine twin, and only the
  token's holder signs an authorization. A disown of the copy lowers the
  copy alone.
- **The limit on planted administrator slots** cannot be turned against an
  honest administrator. Section 3.11 refuses only a change that itself
  repeats a commitment carried in its past. An honest twin's commitment
  includes its fresh `salt`, which nobody knows before the twin is
  published, so no event in its past carries it: an honest twin never
  repeats a commitment and is never `PlantedSlotsFull`, however many
  planted administrator slots its past holds, and its roster event never
  `BadTwin` through it. The root is first. An honest grantee's enrolment,
  and an honest lower or disown, name their maker and are not changes, so
  the limit never reaches them. An administrator that floods copies spends
  its own budget: a further copy in the flood's future is refused, while a
  copy concurrent with all the others is not counted, and costs what any
  planted change costs, a disown that replicas find justified. The limit
  bounds what one chain of the history holds, not the union of concurrent
  ones; the place limit bounds that (section 2.6).
- **Linking pseudonyms to devices.** Beyond overview.md's accepted leak,
  a peer does not learn the pseudonyms of administrators that never change
  who administers, which device a grant makes an administrator, or which
  pseudonyms of one device belong together across spaces. A pseudonym's
  envelopes carry its own `kc`, a hash of an ML-DSA-65 key drawn for it,
  so its `kc` and device ID link nothing its Ed25519 key does not. The
  slot token names the grantee's device ID, sealed to its X-Wing key.
- **The founder's keys in a root.** The genesis's sealed founder change
  is the only other record of the founder's ML-DSA-65 and X-Wing keys, so
  the root carries both, and a peer checks them by the genesis's `kc`
  before it verifies `founder_signature`. A party that forges Ed25519 but
  not the founder's ML-DSA-65 key cannot make a peer take a root of its
  own as the space's first.
- **The projection gap.** Until administrators repair a difference between
  the skeleton and the roster, it matters only to erasures and credentials
  requests, which wait for stability or T. A gap nobody repairs within T
  lets one request through.
- **Irreversibility.** An executed erasure cannot be undone at that peer;
  replicas and other peers may still hold the data. A removed administrator
  whose lowering has not reached a peer within T can have an erasure
  executed there.
- **Several peers** decide each on its own events and timeline. A peer
  that never hears of a lowering may execute an erasure another voids. A
  peer that runs on several machines is one peer, not several: one origin,
  each shard kept by one machine at a time, on that shard's timeline
  ([overview.md](overview.md), section 6.7). A device that sees it serve
  less than any of its machines acknowledged reports `RolledBack`, as for
  any peer.
- **A departure record** shows the peer that the space was here, which it
  knew already. `moved` answers only a valid proof under a public half the
  record keeps, and the peer verifies a proof for every space it does not
  host, so a party that knows only the space ID learns nothing it would
  not learn of a space never hosted, by the answer or by its timing. Only a
  holder of the genesis learns, from `erased`, that a space was erased or
  handed over here.
- **Storage credentials are classical.** A quantum adversary that forges
  them fetches ciphertext and spends quota. It cannot store a skeleton
  event, enrol, erase or retire anything: those are scheme 2 throughout.

## 5. Test vectors

[peers.json](vectors/peers.json), with keys and signatures at full size:

- `parameters`: section 2.6's limits, the sealed slot token's and the
  binding's sizes, the storage event types, and the largest event of each
  type the limits allow, and the refusal codes with their statuses.
- `proofs`: presents of each credential, with transport.md's `binding` for a
  space-traffic and an administration connection, `presented` and the
  proof, and the peer's verdict: a read credential of a live entry (fetch)
  and of a retired one (catch-up); an upload key of a live and of a retired
  entry; a pseudonym on an administration connection, and on a
  space-traffic connection; an unknown key; proofs over another binding,
  another space and another credential; and the store right: a store under
  it, with fetch and live only, with catch-up only, a pseudonym's own
  skeleton event and another pseudonym's on an administration connection,
  and a create whose first stored event is and is not the genesis
  (`NotAuthorized`).
- `merge_statement`: the space's history and prefix; a statement over two
  rotations, accepted; then refused with a signature missing, a signature
  by the wrong upload key, a rotation the peer does not hold, and a set
  that is not a state.
- `skeleton`: one space's history, each storage event byte for byte beside
  its roster event: the genesis and its root; a grant of `administer` with
  its slot token, the grantee's enrolment and binding; a removal of an
  administrator; an acknowledgement; erasures; a credentials request; a
  release and a restore. For each twin, the body key, `twin_secret`, its
  `salt`, `c(R)` and the binding key; the token and the administrator slot's seeds and
  keys; and whether the stream is released before and after the restore.
- `twin_checks`, at a replica, each case with its history and prefix, and
  the events held where a view holds fewer: a twin that passes; one with the
  wrong grants; one by another administrator's pseudonym; one whose parent
  is not a skeleton event; a root whose founder keys do not hash to the
  genesis's `kc` (`NotCommitted` at the peer, `BadTwin` at replicas); a
  roster event that names a twin it does not cite
  (`NoTwin`, then `BadTwin`); one that names none (`TwinRequired`); a change
  with a roster event's commitment that nothing names (`Unnamed` at the
  peer, never read by replicas); a twin by a forked pseudonym; a foreign
  enrolment; a planted administrator slot named by a key event, and its
  justified disown.
- `resolution`: the merged skeleton and each event's status: a mutual
  lowering of equal ranks, the root's slot standing and the other author's
  concurrent erasure void; a mutual lowering whose one side is backdated
  before its partner's enrolment, the enrolment and the more senior
  lowering standing; a slot of rank 10 lowering one of rank 20,
  `HigherRank`; two
  concurrent enrolments of one administrator slot, both void; an
  administrator that disowns the others and then erases, stable without
  section 3.14's rule, not stable within T with it, and voided by the
  founder's concurrent lowering; the same with lowers the attacker names
  from key events of its own; the rule's cost, an erasure after a
  genuine removal that waits for the removed administrator's
  acknowledgement, or T; an administrator that repeats the root's
  commitment after it, and another administrator slot's commitment
  concurrently with it, each in a change named by a key event of its own,
  then enrols pseudonyms of its own under those changes' keys, erases and
  acknowledges: each copy makes an administrator slot of its own, the
  genuine grantee still enrols its own, the erasure waits for the
  founder's and that grantee's acknowledgements, and a disown of the copy
  of the grantee's commitment lowers the copy alone; a copy that reuses a
  grant map whole, after the grant, and the genuine grantee's enrolment
  with the copy in its past, which enrols the genuine administrator slot;
  a lower and a disown that name a maker that did not make the
  administrator slot, by another commitment, an index it has no grant at,
  and a maker outside their past (`UnknownAdministratorSlot`), and a disown
  whose slot reference has two elements (`Malformed`); and the limit:
  copies of one commitment, one after another, with 64 grants each, the
  fourth reaching 256 and the fifth refused (`PlantedSlotsFull`), a copy
  that lowers past the limit still applied, and an honest grant after it,
  valid, whose grantee enrols.
- `stability`: requests after a removal whose administrator never
  acknowledges it, which wait for T, beside an administrator slot that is
  never enrolled.
- `credentials`: the entries after each step: the genesis; a rotation; a
  removed writer's racing rotation; a merge statement; a carried-out
  credentials request, and a second after a rotation that cites the racing
  one; a lowered cap evicting a superseded entry and, when every entry is
  maximal, adding the new one retired; a fork. The `cap` cases add
  rotations to the entries directly, some without their parents, so they
  test section 3.6 alone, not through section 3.2's stores.
- `merge_cap`: an honest merge entry proved by a present and five junk
  statements for its state, the oldest unproved going first; and under a
  full space cap, a junk merge entry retired to make room for an honest one.
- `decisions`: inputs and outcomes for erasure, credentials requests,
  release and collection, at the edges of T and the retention.
- `erase_bodies`: an erase body naming the whole space, accepted; and
  bodies naming a stream, two streams, an object, a stream and an object,
  the space and a stream, the space and an object, nothing, and the space
  as 2, each `Malformed`.
- `skeleton_cuts`: one space's history with a cut (sections 3.21 and
  3.22): an administrator granted and enrolled, a release and a credentials
  request before the checkpoint, the checkpoint and its cut, both
  pseudonyms' votes, a removal and its acknowledgement after it; the
  verdicts of a peer that kept everything and of one that truncated, with
  what the truncating peer holds (the genesis, the root and enrolment the
  cut names, the release, and nothing else of the past) and that it may
  truncate; the merged administrators of each; the replica's check of the
  cut against the record's slot entries, passing, and with an entry that
  names no pseudonym where the cut's slot has one, or a slot the cut lacks
  (`BadTwin`); and the limit: a cut of 512 enrolled slot entries and
  1,024 standing entries with its size beside the bound, and bodies of
  513 slot entries and 1,025 standing entries (`Malformed`) and of an
  invalid `slot_ed` (`InvalidKey`); `held_cut`: a cut whose body uses key
  9, `ExtensionRequired` at a peer, never in effect and holding no
  request, and its checkpoint held as `ExtensionRequired`, with every
  event after it, at a replica. Besides, `unordered_cuts`, a cut
  reaching two unordered checkpoints (`CutPending`); `truncation_wait`, an
  erasure waiting for an unenrolled slot; and `late_enrolment`: an
  enrolment concurrent with a checkpoint, an acknowledgement and a device
  anchor built on it, the cut leaving the slot unenrolled, the device's
  vote whose `prev` is its late anchor, and the slot enrolled again after
  the checkpoint under the checkpoint's `twin_secret`; the peer's verdicts
  (the late events `Late`), kept and truncated, whether it may truncate
  before and after the new enrolment acknowledges the erasure of the
  past, each pseudonym's device at a replica that kept everything and at
  one that forgot, and the replicas' chain and verdicts;
  `absent_administrator`: four administrators of one rank, one of whom
  enrols and never returns, removed after the checkpoint by a senior, by a
  junior, or by nobody, with the cut's standing entries and whether the
  cut is in effect at the peer and the checkpoint at a replica (only with
  the senior's removal, both); `concurrent_request`: an erasure concurrent
  with a cut, waiting while the cut can still take effect, late once it
  does, and signed again after it, with the peer's `ErasureLate` to the
  residue that stores it again once the cut is in effect (the message,
  the cut and checkpoint it names, the slot's standing, and three
  messages the residue refuses: a standing that the cut contradicts and a
  checkpoint's envelope in place of the cut's, `PeerError`, and another
  erasure's ID, `Malformed`); `slot_held`: standing 1 told apart, for a slot the cut
  lists with another installation's pseudonym (the residue reports
  `SlotHeld` at once) and for one it lists empty and another installation
  enrolled after the checkpoint (the residue goes back in and finds it
  held), each with the message, the cut's entry, the residue's action,
  the holder and its binding, and an enrolment of the slot again,
  `AlreadyEnrolled`; and `release_order`: a restore, an
  anchor and a release before the checkpoint, the release alone kept by a
  peer that truncated, which finds the stream released as one that kept
  everything and a replica that forgot do, where keeping every request
  without the anchor between them would not; `late_then_past`: a release
  late under one checkpoint and in the next one's past, which counts for
  nothing under the next, kept or truncated; `no_slot`: an administrator
  the skeleton holds no slot for, its cut's standing entries ordered 1 and
  2 with no gap, valid at the peer and at replicas alike; `heard_vote`: a
  member the checkpoint hears, which does not vote, excused by its senior
  after the checkpoint; the cut's standing names its out slot with its
  enrolment, which a peer that truncated keeps, and the peer and a replica
  both put the checkpoint and the next one in effect, the truncated peer
  agreeing with one that kept everything; `late_enrolment_refusals`: late
  enrolments refused as a second one by a known pseudonym
  (`BadSignature`), with keys that do not give their `kc`
  (`NotCommitted`) and with a broken signature (`BadSignature`), beside a
  well-formed one (`Late`); and `detached`: a checkpoint
  that names its cut without citing it, the cut `Unnamed` at the peer and
  the checkpoint `BadTwin` at replicas; and `peerless`: three checkpoints
  in a row among members that never reach a peer, each cut in effect by
  the peer's rule over what they hold, and one checkpoint with the peer
  and two apart from it, which the peer, once it catches up, finds in
  effect, truncates under and agrees on with a peer that kept everything.
  The limit's refusals add a cut
  without standing entries and one with 129 (`Malformed`).
- `recovery_entries`: a recovery key's fetch key registered under the store
  right, and again (accepted, nothing changes); an invalid key
  (`InvalidKey`); a registration without the store right
  (`CredentialRefused`); a credentials request with a keep list alone, and
  a key registered after the peer's first sight of it, which stays live
  while the unnamed one retires; presents of a fetch key, live (catch-up),
  retired (`RetiredCredential`), on an administration connection
  (`purpose_violation`) and unknown (`UnknownCredential`); a retired key
  registered again; 64 live recovery entries and a 65th
  (`RecoveryEntriesFull`); and credentials request bodies with a keep list,
  with both keys, with an empty keep list, with neither key, out of order,
  of 65 keys, and naming an invalid key.
