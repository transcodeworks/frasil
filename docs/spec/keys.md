# Keys
Protocol 1. Vectors: [keys.json](vectors/keys.json).

This document specifies a space's keys: rotations and the states they form,
what derives from a state, how keys reach members through wraps, space
wraps, links and gap keys, the space event's body and its per-event body
key, notices of a granted space's grant key, entitlement, healing,
cascades into the spaces that grant a space, deliveries, the key reference a
unit carries, and sealed names. It depends on [overview.md](overview.md) for
conventions and timers, [crypto.md](crypto.md) for primitives, the X-Wing
wrap and labels, [events.md](events.md) for the envelope and causal order,
and [roster.md](roster.md) for the valid set, places, effective membership,
stability and the write rule.

## 1. Overview

- Each **rotation** draws fresh secrets: a content key and an upload seed,
  and, for a **grant rotation**, a grant seed. A rotation is the genesis or a
  later space event whose body rotates, roster event or key event. Its ID is
  the event ID.
- A **state** is a set of rotations. The **current state** of a view is the
  set of its maximal valid rotations, and its secrets merge those of its
  rotations, so every replica that holds the same events derives the same
  key without an orderer.
- From a state derive the keys a unit, an object and a name are sealed
  under, the **read credential** and the **upload key** a peer checks, and,
  from the grant state, the **grant key**: an X-Wing key pair to which the
  spaces that grant this one seal their keys.
- Keys reach a device in a **wrap**, one per recipient device, or a **space
  wrap**, one per granted space. Earlier keys stay reachable through
  **links**, which hang only where every possible holder is entitled to what
  they reach. Where a link is withheld, the key is a **gap key**, wrapped to
  its entitled members.
- Whenever the devices outside the roster could together derive the current
  key, any writer **heals** with a new rotation. When a space loses a device
  through a granted space or a person's list, every space that inherits the
  loss rotates: a **cascade**.
- Every key travels inside a space event signed under scheme 2, and every
  rotation commits to its secrets in the clear, so a taker checks each key
  it receives.
- A space event's sealed part is sealed under its own **body key**, derived
  from the state it names. A body key opens that one event and nothing else.

## 2. Formats

### 2.1 Rotations and states

Every rotation draws from the random source:

- `k_R`, its 32-byte content key;
- `w_R`, its 32-byte upload seed;
- for a grant rotation only, `g_R`, its 32-byte grant seed.

A **state** `S` is a set of 1 to 64 rotation IDs. `k(S)` is its content key,
`w(S)` its upload seed, and `g(G)` the grant seed of a **grant state** `G`, a
set of grant rotations.

```text
encode_set(S) = u8(n) || id_1 || ... || id_n
```

The IDs are distinct and strictly ascending as byte strings: the state's
canonical order, used wherever a state is encoded or its secrets combined.

A **key name** says which state a wrap, link or delivery is about:

- `encode_set(S)`, for a state of rotations that exist as events; or
- `self_ref = 0x00 || author || u64be(seq)`, 41 bytes, for the carrying
  event's own rotation, with its author, the device ID its envelope gives
  ([events.md](events.md)), and its `seq`. An event cannot hold its own ID,
  which is its hash.

`k_R` therefore has two names: `self_ref` inside its own event, and
`encode_set({R})` after it. Wraps and links bind the name they were made
under. Derivations from one state's secret bind no name, so both names give
the same keys.

`log`, wherever a format binds it, is `field` of the carrying event's `log`,
the space ID; inside a genesis, which has no `log`, it is `field` of the
genesis's 16-byte `nonce` (visible key 13).

### 2.2 Derivations

**Merged secrets.** For a state `S` in canonical order `R_1, ..., R_n`:

```text
k(S) = k_R                                                    if S = {R}

info = "frasil/merge-key/v1" || field(space) || encode_set(S) if n >= 2
t_i  = HMAC(key = k_Ri, message = info)                       for each i, in order
k(S) = HKDF(salt = none, ikm = t_1 || ... || t_n, info)

w(S)  likewise from the w_R, with "frasil/merge-upload/v1"
g(G)  likewise from the g_R of a grant state G, with "frasil/merge-grant/v1"
```

A state is always derived from its rotations. A device that merged A with B
and then meets C derives `k({A, B, C})`, as a device that met all three at
once does. Each input passes through HMAC under its own uniformly random
key, so one input the outsider lacks makes the merged key unpredictable.

**The grant key and its commitment.**

```text
xwing_seed(G)   = HKDF(salt = none, ikm = g(G), info = "frasil/grant-key/v1")
grant_public(G) = the X-Wing public key of xwing_seed(G)                  1,216 bytes
commitment(R)   = SHA-256("frasil/grant-commitment/v1" || u8(break)
                          || grant_public({R}))
```

Every rotation publishes a 32-byte commitment in its visible part (key 3).
A grant rotation publishes `commitment(R)`, with `break` 1 when it is a
break; any other rotation publishes 32 random bytes. A peer cannot tell the
two apart, so the commitment shows it neither whether a rotation is a grant
rotation nor whether it is a break.

**Storage credentials.** Two Ed25519 key pairs, from the seeds:

```text
read_seed(S)   = HKDF(salt = none, ikm = k(S), info = "frasil/read-credential/v1")
upload_seed(S) = HKDF(salt = none, ikm = w(S), info = "frasil/upload-key/v1")
```

Every member holds the content key and may fetch, so the read credential
needs no secret of its own. Only writers receive the upload seed. Both
change with every state. How a peer learns their public halves is
[peers.md](peers.md)'s.

**Metadata and object keys.**

```text
metadata_key(S)     = HKDF(salt = none, ikm = k(S), info = "frasil/space-metadata-key/v1")
object_id_key(S)    = HKDF(salt = none, ikm = k(S), info = "frasil/object-id-key/v1")
object_nonce_key(S) = HKDF(salt = none, ikm = k(S), info = "frasil/object-nonce-key/v1")
```

An object's ID key and nonce key derive from the state the object is sealed
under, which the object names ([units.md](units.md)). Equal files dedupe only
within one state; in exchange, a holder of old keys cannot test whether a
file it knows is stored under a later state. A unit may reference an object
sealed under any earlier state its writer reaches, and a reader opens the
object under the object's own state, so a rotation never makes anything be
uploaded again. A name is sealed under the metadata key of the state
current when it is sealed (section 2.8). Units are sealed under a key
[units.md](units.md) derives from `k(S)`.

**Key separation.**

- `k_R`, `k(S)`, `w(S)` and `g(G)` are used only as HMAC keys, as HKDF input
  keying material under labels of [crypto.md](crypto.md)'s registry, and
  inside bundles. Nothing seals or signs directly under them.
- A merge binds the space ID and the set, because it combines secrets that
  exist apart. A derivation from one state's secret binds only its label:
  that secret is fresh or a merge that already binds the space, and a
  genesis's commitments sit inside the event whose hash is the space ID.
- Wraps, links and sealed parts bind `log`. A link key binds its kind and
  both names, so it is never another link's.

### 2.3 The recipient bundle

One wrap carries every secret its recipient is entitled to for one state:

```text
bundle  = u8(flags) || slot(k(S)) || slot(w(S)) || slot(g(G))      97 bytes
flags:    0x01 content key, 0x02 upload seed, 0x04 grant seed
slot(x) = x when its flag is set, else 32 zero bytes
```

- Every member receives the content key. A member whose level writes
  receives the upload seed. A member whose grant propagates receives the
  grant seed. So a guest that writes receives content and upload, and a
  reader that propagates receives content and grant.
- Every bundle is 97 bytes, so every wrap is the same size and a peer
  cannot tell a recipient's level or whether it propagates.
- A bundle with only the grant seed carries a gap key of the grant graph.
- [ext-invite-links.md](ext-invite-links.md) says what an invite key
  receives.

### 2.4 Bundle wraps, space wraps and removal wraps

All three use [crypto.md](crypto.md)'s wrap layout: 97 bytes of plaintext
in a wrap of 1,236 bytes. None names its recipient.

```text
bundle wrap:
info = "frasil/bundle-wrap/v1" || u16be(suite) || log
       || field(key name or empty) || field(grant key name or empty)
       || recipient's device ID
sealed to the recipient device's X-Wing key

space wrap:
info = "frasil/space-wrap/v1" || u16be(suite) || log
       || field(key name or empty) || field(grant key name or empty)
       || granted space ID || grantee rotation
sealed to grant_public({grantee rotation}) of the granted space

removal wrap:
info    = "frasil/removal-wrap/v1" || u16be(suite) || log
          || field(key name) || field(grant key name or empty)
          || recipient's device ID
removal = 0x08 || body key (32) || 64 zero bytes                   97 bytes
sealed to the recipient device's X-Wing key
```

- A delivery (section 2.6) names its state `S` and grant state `G` once for
  all its wraps. A wrap carries the content key exactly when its delivery
  names a state, and `g(G)` only when the delivery names a grant state and
  the recipient propagates.
- **Which X-Wing key.** A wrapper seals to the X-Wing key that the
  recipient's device ID commits to ([crypto.md](crypto.md), section 2.4,
  "Which key"), taken from any source and checked by its hash: the
  recipient's device grant, its `add` in its person's list for a device
  reached through a person, or a key it cached. Every record of one device
  ID names the same keys, so a person's device that also holds a direct
  grant is wrapped for under the one X-Wing key both name, whichever log the
  wrapper reads.
- **The space wrap** carries every secret for every device of the granted
  space that propagates, sealed once to that space's grant key. The
  **grantee rotation** is the one grant rotation of the granted space that a
  valid notice names (section 2.6). It carries the content key, the upload
  seed when the grant is at `write`, and the grant seed, since everyone who
  opens it propagates. The grant key is a key pair so that a member of the
  granting space that is not a member of the granted space can still seal
  to it.
- **The removal wrap** carries one thing: the body key of the rotation
  that carries it (section 2.6), for a device that the rotation's roster
  changes remove. That device lacks `k_R`, so without it the device holds
  its own removal `Sealed` and never learns of it. The body key opens that
  event's sealed part and nothing else. A removal wrap sits among the
  bundle wraps of the event's own delivery, and its key names are that
  delivery's. Its info has a label of its own, so it never opens as a
  bundle wrap, and a bundle wrap never opens as a removal wrap.

### 2.5 Links and gap records

A link seals the secret of the state it reaches under a key derived from
the secret of the state it hangs under:

```text
link_key = HKDF(salt = none, ikm = secret(U),
                info = "frasil/key-link/v1" || log || u8(kind) || name(U) || name(B))
aad      = "frasil/key-link/v1" || 0x01 || log || u8(kind) || name(U) || name(B)
link     = 0x01 || u8(kind) || name(U) || name(B) || nonce (24)
           || XChaCha20-Poly1305(link_key, nonce, secret(B), aad)
```

- `kind` 1 is a content link (`k(U)` and `k(B)`), and 2 a grant link (`g(U)`
  and `g(B)` over grant states).
- `U` is the state it hangs **under**, `B` the state it **reaches**. `name(U)`
  may be a self reference; `name(B)` never is. `U` and `B` differ.
- A link between two single rotations is 140 bytes; under a self reference,
  148.

A **gap record**, `u8(kind) || encode_set(B)`, says that `B` is a gap key:
a link to it was withheld (section 3.7), or a break cut it off.

### 2.6 The space event's body

A space event's `body` is a deterministic CBOR map, the **visible part**,
which a peer reads. It holds the **sealed part**, which only members open.
Roster events and key events share this one shape, so that the kind and the
fields do not say whether membership changed.

| Key | Field | Value | When |
|---|---|---|---|
| 1 | `version` | 1 | always |
| 2 | `rotates` | 1 | the event rotates |
| 3 | `grant_commitment` | bytes(32), section 2.2 | every rotation |
| 4, 5, 6 | reserved | | never |
| 7 | `deliveries` | array of delivery maps | optional |
| 8 | `sealed` | bytes: the sealed part | always |
| 9 | `sealed_under` | a key name, not a self reference: the state whose content key seals key 8 | every event that does not rotate |
| 10 | reserved | | never |
| 11 | `read` | bytes(32): the public half of the read credential of `k_R` | every rotation |
| 12 | `upload` | bytes(32): the public half of the upload key of `w_R` | every rotation |
| 13 | `nonce` | bytes(16): random; binds the genesis in place of its log | the genesis only |
| 14 | `commitment` | bytes(32): the body key's commitment | always |
| 15 | `twin` | bytes(32): the event ID of its skeleton twin ([roster.md](roster.md)) | a roster event that changes who administers |

**A delivery** is a map: key 1, the key name of `S`; key 2, the key name of
`G`; key 3, an array of bundle wraps; key 4, an array of space wraps. It has
at least one of keys 1 and 2, and at least one of keys 3 and 4. A space
event carries at most 64 deliveries and 768 wraps in all. A rotation with
more recipients carries what fits, and its author completes the rest in key
events that deliver the same state.

**The own delivery.** A rotation delivers its own new state in a delivery
whose key name and grant key name are both `self_ref`, whether or not it is
a grant rotation, so the shape tells a peer nothing. Sealed key 1 says which
grant state its grant slots carry. A rotation that removes members also
carries its removal wraps among its own deliveries' bundle wraps (section
3.13). They count toward the limits on wraps.

**The sealed part and its body key.**

```text
aad        = "frasil/space-event/v1" || log || author || u64be(seq)
body_key   = HKDF(salt = none, ikm = secret, info = aad)
commitment = HKDF(salt = none, ikm = body_key, info = "frasil/space-event-commitment/v1")
sealed     = nonce (24) || XChaCha20-Poly1305(body_key, nonce, inner, aad)
```

- `secret` is `k_R` in an event that rotates, and `k(S)` of the state
  `sealed_under` names otherwise. The event names its state, so whether a
  replica can open it depends only on the keys it holds; trying every state
  would let two replicas with different candidates disagree on what opened.
- The body key is derived for one event: its log, its author (the device ID
  its envelope gives, [events.md](events.md)) and `seq`. Handing it over
  opens that event's sealed part and nothing else, since HKDF yields neither
  `secret` nor another event's body key.
- The commitment binds the event to one body key, because
  XChaCha20-Poly1305 does not commit to its key.
- A "from now on" newcomer opens its admitting event with the `k_R` its own
  wrap carries. Every holder of a named state opens an event sealed under
  it.
- In a restricted space, `secret` is
  [ext-restricted-spaces.md](ext-restricted-spaces.md)'s.

`inner` is a deterministic CBOR map, possibly empty:

| Key | Field | Value | When |
|---|---|---|---|
| 1 | `grant` | 1 for a grant rotation; otherwise the key name of the grant state the own delivery's grant slots carry | a rotation whose own delivery names a grant state |
| 2 | `break` | 1 | a rotation with no link back |
| 3 | `links` | array of links | optional |
| 4 | `gaps` | array of gap records | optional |
| 5 | `notices` | array of notice maps | optional |
| 16 | `roster` | bytes: the roster part ([roster.md](roster.md)) | a roster event |
| 17 | `padding` | bytes, every byte zero | optional, to hide the length |
| 18 | `refs` | 1 to 64 pairs `[log ID, event ID]`, each bytes(32), strictly ascending as the 64 bytes `log ID \|\| event ID` | when the event names events of other logs; never in a genesis |

**A rotation links back or breaks.** A rotation that is not a break carries
a content link from its own key to the previous content state of its
author's view where the gate allows (section 3.7), and otherwise a gap
record for that state. A grant rotation does the same for the grant state.
A break carries the gap records and no link back.

**A notice** tells this space's members the grant key of a space its roster
grants. It is a map: key 1, the granted space's ID; key 2, the event ID of
one grant rotation of the granted space; key 3, `grant_public` of that
rotation (1,216 bytes); key 4, 1 when that rotation is a break.

### 2.7 Key references in units

A unit names the state it is sealed under by its **key reference**,
`encode_set(S)`: the content state of its writer's view
([units.md](units.md) carries it). A unit of a restricted space carries the
restricted form of [ext-restricted-spaces.md](ext-restricted-spaces.md):
its own state in the clear, then its parent's state sealed. A core
implementation does not use a restricted space ([roster.md](roster.md)),
so it never reads that form.

### 2.8 Sealed names

A **sealed name** is a name people chose, sealed under the metadata key of
one state and bound to its space, its state and the thing it names.
Sealing, from `mk = metadata_key(S)`, the space ID, the key reference
`reference` of `S`, a kind code `c`, an ID `id` and a name:

1. `space` is 32 bytes, `c` is 1 or 2, and `id` follows its kind's rule.
   Else `Malformed`.
2. The name is 1 to 1,022 bytes of UTF-8 (`L` bytes). Else `InvalidName`.
3. `padded = u16be(L) || name || zero bytes`, of length
   `padded_len(L) = ceil((L + 2) / 64) × 64`, from 64 to 1,024.
4. `aad = "frasil/name/v1" || space || field(reference) || u8(c) || field(id)`.
5. `sealed = 0x01 || nonce (24, random) || XChaCha20-Poly1305(mk, nonce,
   padded, aad)`: `padded_len(L) + 41` bytes.

| Code | Kind | The ID | ID rule |
|---|---|---|---|
| 1 | space | the space the name is about: this space, or another whose name this space keeps | 32 bytes |
| 2 | document | the document's ID in the space: its stream ID, or the application's own | 1 to 128 bytes |

`S` is the writer's current content state when it seals. A name may hold
any Unicode character; an application may refuse some before it seals.

A sealed name travels in a **record**, which tells a reader where its key
is: `record = 0x01 || space (32) || field(reference) || sealed`.

### 2.9 Labels and limits

Labels used, from [crypto.md](crypto.md)'s registry: `frasil/merge-key/v1`,
`frasil/merge-upload/v1`, `frasil/merge-grant/v1`, `frasil/grant-key/v1`,
`frasil/grant-commitment/v1`, `frasil/read-credential/v1`,
`frasil/upload-key/v1`, `frasil/space-metadata-key/v1`,
`frasil/object-id-key/v1`, `frasil/object-nonce-key/v1`,
`frasil/key-link/v1`, `frasil/bundle-wrap/v1`, `frasil/space-wrap/v1`,
`frasil/removal-wrap/v1`, `frasil/space-event/v1`, `frasil/space-event-commitment/v1`,
`frasil/rotation-rank/v1` and `frasil/name/v1`.

| What | Limit | On excess |
|---|---|---|
| Rotations in a state or key name | 64 | `TooManyRotations` |
| Rotations in the current state before a collapse is due | 8 | a collapse (section 3.12) |
| Deliveries; wraps, bundle and space wraps together, per space event | 64; 768 | `Malformed` |
| Refs per space event | 64 | `TooLarge` ([events.md](events.md)'s limits) |
| A name; a document ID | 1 to 1,022 bytes; 1 to 128 bytes | `InvalidName`; `Malformed` |
| Breaks per space | 256 | client policy: a client refuses to admit "from now on" beyond it |
| Spaces a change cascades into | 1,024 | a client warns |

768 wraps of 1,236 bytes fit a space event's size limit
([events.md](events.md)).

## 3. Procedures

### 3.1 Reading key names, bundles, wraps and links

**A key name**, from the front of some bytes, in order:

1. At least 1 byte. Else `Malformed`.
2. If the first byte is 0: a self reference, where the structure allows
   one, of exactly 41 bytes. Else `Malformed`.
3. `n = data[0] <= 64`. Else `TooManyRotations`.
4. At least `1 + 32n` bytes, and the IDs strictly ascending. Else
   `Malformed`.

A self reference is allowed only in an event that rotates, and only equal
to `0x00 || author || u64be(seq)` of its envelope, `author` the device ID
the envelope gives.

**A bundle**, in order: exactly 97 bytes; no flag outside `0x07`; at least
one flag; the upload flag only with the content flag; every slot whose flag
is clear is zero. Else `Malformed`.

**A bundle wrap or a space wrap:** [crypto.md](crypto.md)'s `open_wrap`
with length 1,236, under the opener's X-Wing seed (for a space wrap,
`xwing_seed({grantee rotation})`) and the info for the delivery's names and
the opener (its device ID; for a space wrap, its space and that
rotation). Then the bundle reads, holds the content key exactly when the
delivery names a state, and holds a grant seed only when it names a grant
state. Else `Malformed`.

**A removal wrap:** [crypto.md](crypto.md)'s `open_wrap` with length
1,236, under the opener's X-Wing seed and the removal-wrap info for the
delivery's names and the opener's device ID. Then, in order:

1. The plaintext's first byte is `0x08` and its last 64 bytes are zero.
   Else `Malformed`.
2. `body_commitment` of the body key equals the carrying event's visible
   `commitment` (key 14). Else `KeyMismatch`, and the device drops the key.

The body key it yields is a body key handed over: provisional
([roster.md](roster.md), "Space events a replica cannot open").

**Trial decryption.** A device finds its own wrap by trying the wraps of a
delivery with its X-Wing seed and an info naming itself; a wrap meant for
another fails as `Decrypt`. A device of a granted space tries each space
wrap with the grant keys it holds for the rotations its space's valid
notices name. A device tries only a delivery whose named rotations are all
events of the log it holds, and that names a state it lacks and is entitled
to (section 3.7). A device that holds a kept checkpoint (section 3.17) also
tries, once, a delivery of an event after it that names a state it lacks
whose rotations it neither holds nor can fetch: such rotations are before
the checkpoint, and what it takes from that delivery is provisional
(section 3.5). Within a delivery it stops at the first wrap that opens.
A device that holds a rotation `Sealed`, lacking `k_R`, tries each of the
rotation's own deliveries once more for a removal wrap, with the
removal-wrap info naming itself, and stops at the first that opens.

**A link**, in order:

1. At least 1 byte. Else `Malformed`.
2. Byte 0 is `0x01`. Else `UnsupportedVersion`.
3. At least 2 bytes, and the kind is 1 or 2. Else `Malformed`.
4. `name(U)` reads (a self reference allowed), then `name(B)` (none
   allowed), as a key name. Else that class.
5. Exactly 72 bytes remain, and `name(U) ≠ name(B)`. Else `Malformed`.
6. The kind and both names are the ones the opener looks for. Else
   `Malformed`.
7. XChaCha20-Poly1305 opens. Else `Decrypt`.

**A gap record:** the kind is 1 or 2, and the rest is one rotation set.
Else `Malformed`.

### 3.2 Checking a space event's body

**The visible part,** which a peer can check too, with the event's author,
the device ID its envelope gives, and its `seq`, in order:

1. It decodes as deterministic CBOR, and is a map with an unsigned key 1.
   Else `Malformed`.
2. Key 1 is 1. Else `UnsupportedVersion`.
3. Its keys are among 1, 2, 3, 7, 8, 9, 11, 12, 13, 14 and 15. Else
   `Malformed`.
4. Keys 3, 11 and 12 are present exactly when key 2 is; key 9 exactly when
   key 2 is absent; keys 8 and 14 always. Else `Malformed`.
5. Keys 3, 11, 12, 14 and 15 are 32 bytes, and key 13 16 bytes and only with
   key 2, and never with key 15 (`Malformed`). Keys 11 and 12 are valid Ed25519 keys
   ([crypto.md](crypto.md), section 3.1; `InvalidKey`).
6. Each delivery has the shape of section 2.6; its names read as key names,
   a self reference only as section 3.1 allows; a delivery whose key name is
   the self reference names it as its grant key name too, or names no grant
   state; each wrap passes `open_wrap`'s steps 1 to 5; at most 64 deliveries
   and 768 wraps. Else `Malformed`, or that class.
7. Key 8 is at least 41 bytes, and key 9 is a key name that is no self
   reference. Else `Malformed`.

Whether keys 13 and 15 belong is [roster.md](roster.md)'s check, which knows
the envelope and the event's place.

**The sealed part,** once [roster.md](roster.md) has opened it under the
body key, in order:

1. `inner` decodes as a deterministic CBOR map with keys among 1 to 5, 16,
   17 and 18; keys 1 and 2 only in an event that rotates, key 1 present when
   the own delivery names a grant state, and 1 or a rotation set; key 2 is
   1; key 16 is bytes; key 17 is bytes of zeros. Else `Malformed`. Then key
   18 is a nonempty array (`Malformed`) of at most 64 entries (`TooLarge`),
   each a pair of two 32-byte strings, strictly ascending (`Malformed`).
2. Each link passes section 3.1's steps 1 to 5, a self reference only as
   section 3.1 allows. Each gap record reads. Else that class.
3. Each notice has the shape of section 2.6, with key 4 only in an event
   with `break` (`Malformed`), and key 3 a valid X-Wing key
   ([crypto.md](crypto.md), section 3.3; `InvalidKey`).

An event whose body fails these checks is void with that class, and is not
a rotation.

### 3.3 Checks against the event and its place

These read the event's changes, its sealed refs and notices, and the roster
`S` at its place. [roster.md](roster.md) runs them as part of the event's
authority (roster events) or of the write rule (key events). `me` is the
event's author's member.

| Flag | True when |
|---|---|
| `removes` | a change removes a member that is in `S` |
| `removes_self` | that member is `me` |
| `removes_propagating` | the event is not self-lowering, and it removes a member other than `me` that is in `S` and propagates: a person, a space, or a device grant without `session` |
| `lowers_to_read` | a change sets a member that is in `S` at `write` or `administer` to `read` |
| `lowers_self` | a change lowers `me` |
| `admits_from_now_on` | a grant has `history` 0 |
| `admits_propagating` | such a grant carries no `session` |
| `author_propagates` | `me` is in `S` with no `session` |
| `responds` | the event has sealed refs |

For a genesis, `author_propagates` is true. [ext-invite-links.md](ext-invite-links.md)
says how its grant and successor set these flags, and
[ext-restricted-spaces.md](ext-restricted-spaces.md) what a restricted space
changes. In order:

1. **`RotationRequired`.** A genesis, a `removes`, a `lowers_to_read` and an
   `admits_from_now_on` event rotates, unless it is self-lowering
   ([roster.md](roster.md)). A self-removal never rotates; a self-demotion
   to read need not, and leaves its author only the upload key until the
   next rotation.
2. **`StaleSeal`.** An event that does not rotate is sealed under its
   author's current content state: no valid rotation in its place follows
   a rotation of `sealed_under`. Otherwise a writer that has seen a removal
   could seal under a state the removed member holds. For a roster event the
   rotations counted are the genesis and the valid roster events; for a key
   event, also the key events decided valid before it.
3. **`BreakRequired`.** An `admits_from_now_on` event has `break`.
4. **`UnexpectedBreak`.** `break` appears only in an `admits_from_now_on`
   event, or in a key event that `responds` (a break cascaded from a granted
   space, section 3.10).
5. **`GrantKeyNotAllowed`.** No grant rotation by an author that does not
   propagate, and none in a restricted space.
6. **`GrantKeyRequired`.** A grant rotation in a genesis, in a
   `removes_propagating` event, in an `admits_from_now_on` event that
   `admits_propagating`, and in a key event that `responds` and rotates.
7. **`UnexpectedGrantKey`.** A roster event other than a genesis is a grant
   rotation only when step 6 requires one. A key event that does not
   respond may be one: a grant heal or a collapse.
8. **`NoticeRequired`.** A key event whose sealed refs name an event of the
   log of a space that `S` grants carries a notice for that space. A ref
   names a log by its ID, which is the space ID ([events.md](events.md)),
   so every replica decides this from the event and `S` alone.

A notice's own checks (section 3.4) are not among these: they decide
whether the notice admits a principal, never the verdict of its event.

Rotation is required where it takes a key or the upload seed away, or where
an admission needs a break. A "with history" admission, a promotion, and a
change between `administer` and `write` may rotate, but need not: the
newcomer receives the current state as a delivery.

### 3.4 Notices and space principals

A planted notice would have every later rotation seal this space's whole
bundle, grant seed included, to its author. So a notice names one grant
rotation `R` of the granted space T, never a merged state, since only a
single rotation commits to its grant key. When T's grant state holds
several rotations, the responder first publishes a collapse in T, and
notices that.

A notice's checks read T's log, which a replica MAY lack, and which can
change after the event. So they never decide the verdict of the event that
carries the notice: that event is valid or void by its other checks alone,
alike at every replica, whichever granted spaces' logs it holds. They
decide only whether the notice admits a principal at this replica.

A replica checks a notice, in order:

1. It holds T's log and `R`'s event; `R`'s visible part suffices. Else the
   notice is unresolved (`Pending`) until it holds them.
2. `R` is valid in T's log as this replica holds it. Else `NoticeVoid`.
3. `SHA-256("frasil/grant-commitment/v1" || u8(key 4) || key 3)` equals
   `R`'s key 3. Else `NoticeMismatch`. This checks the key and the break
   together.
4. `R` has in its past, or is, every valid rotation of T that a valid event
   of this space names in its sealed refs, this event's own included. Else
   `NoticeStale`.
5. The notice's author is a propagating member of T at `R`, a check across
   logs ([roster.md](roster.md)). Else `NotGranteeMember`, or unresolved
   (`Pending`) while the replica cannot tell.

A notice that passes them is **valid** at this replica. One that fails
them or is unresolved admits nothing, and nothing is sealed to it. A
replica checks a notice again whenever it learns more of T's log.

A roster event that grants a space carries a notice for the granted space's
current grant rotation. Section 3.10 says which responses carry one.

**Space principals.** The pair (T, `R`) of a valid notice is a **space
principal** of this space. Its devices are the devices of T that hold
`g_R`.

- A valid notice admits its principal at its event, "from now on" when key
  4 is set and "with history" otherwise. A principal "from now on" is
  admitted only by an event with `break`.
- A principal (T, `R`) is **in force** only if `R` has in its past, or is,
  every valid rotation of T that any valid event of this space names in its
  sealed refs. Every other principal of T is **out of force**: it receives
  nothing more, and no later notice brings it back. This follows from the
  responses alone, in whatever order they arrive.
- For each space the roster grants, a rotator seals one space wrap to each
  principal in force, normally one.
- A principal's devices count as **inside** only while this space's
  effective membership holds them: the devices still in T as this replica
  holds T's log. Every other holder of `g_R` counts as outside. A replica
  that does not hold T's log admits no principal of T and seals nothing to
  T. It counts the holders of T's grant keys as neither, and leaves the
  heal to members that hold both logs.

### 3.5 Taking a key

- **Slot by slot.** A device that opens the secrets of a single rotation,
  from any wrap or link, derives each one's public half (the read credential
  of `k_R`, the upload key of `w_R`, and the commitment of `g_R` with the
  rotation's sealed `break`) and compares it with that rotation's visible
  keys 11, 12 and 3. It keeps every slot that matches and drops the others
  (`KeyMismatch`), and keeps looking for another delivery of what it
  dropped.
- **A rotation key that does not match is not that rotation's key.** An event
  sealed under a state whose rotation keys the replica lacks, or holds only
  unmatched, is one it cannot open (`Sealed`).
- **A merged key received whole is provisional.** No rotation commits to a
  merged state's key. A device uses one it receives by wrap, marked
  provisional, until it derives the key itself from inputs that each
  matched. A space event that a provisional key fails to open is held
  `Sealed`, never `BadSeal` ([roster.md](roster.md)): the fault may be the
  wrapper's.
- **A key of a rotation the device does not hold is provisional.** A
  device that holds neither a rotation's event nor its visible part, such
  as one before its kept checkpoint (section 3.17), cannot compare what it
  receives with keys 11, 12 and 3. It keeps the slot, marked provisional,
  and compares it once it holds the visible part. Only units, objects and
  names are ever opened under such a key: every space event a replica
  judges after its kept checkpoint is sealed under a state of the
  checkpoint's world, whose rotations it holds ([roster.md](roster.md),
  section 3.15.5). A unit or object that a provisional key fails to open
  is held, never refused, and the device keeps looking for another
  delivery.

### 3.6 The current state and the inside

For a view and its valid set ([roster.md](roster.md)):

- the **content state** `S` is the set of valid rotations that no other
  valid rotation follows;
- the **grant state** `G` is the set of valid grant rotations that no other
  valid grant rotation follows. A rotation that is not a grant rotation
  leaves `G` as it was;
- the current content key is `k(S)` and the current grant seed `g(G)`.

Both are recomputed for every view. Void rotations are never in them.

The **merged roster** is the roster of the view's valid roster events, with
the space principals in force. Its effective membership gives the
**inside**:

- for the content graph, every device of every member, and the devices of
  every principal in force that are inside (section 3.4);
- for the grant graph, the same over members whose grant propagates.

A device whose chain forked counts as removed: it is never inside, receives
no wraps, and its rotations and deliveries are void from the fork point.
[ext-invite-links.md](ext-invite-links.md) says how an invite key counts.

### 3.7 Entitlement and the link gate

**Entitled.** Member `m` is **entitled** to state `K` in a view when:

1. `m` is in the roster of `K`'s place: the valid roster events and notices
   in the past of `K`'s rotations, those rotations included; or
2. `K` holds several rotations, and `m` is entitled to each; or
3. `K = {R}`, and a valid "with history" grant or notice `x` of `m` exists
   that does not precede or equal `R`, such that `R` precedes `x`, or `x` is
   in force in the merged roster. A "with history" grant reaches every key
   before it, and keys on branches concurrent with it while it is in force.

For the grant graph, only grants that propagate count.
[ext-invite-links.md](ext-invite-links.md) adds a rule for a claimant.

**Potential holders.** The grantee of every break (an admission "from now
on", or a notice "from now on") in a state's past counts as a holder of that
state, whether the break is valid or void: a void admission can become valid
at a later merge.

**The link gate.** A link to `K` may hang under `U` only when:

1. every member of the merged roster is entitled to `K`, and none of them
   waits for stability on `K` (section 3.8); and
2. for every member `m` with a break in `U`'s past, either `m` is entitled to
   `K`, or one of `m`'s breaks precedes or equals a rotation of `K`.

A link hangs only under the current state of the view it is made in, or at
a rotation under the rotation's own key, and never under a state whose heal
test fires. Where the gate refuses, the author records `K` as a gap and
wraps it for every entitled member that lacks it. For the grant graph, the
gate runs over members that propagate and breaks whose grantee propagates.

**Space principals' entitlement** is the intersection over their devices. A
state is linked or space-wrapped to (T, `R`) only if every device of T that
holds `g_R` is entitled to it through its own path. A device that T admitted
"from now on" at a break in `R`'s past is entitled here only from this
space's response to that break, and those responses count as the
principal's breaks in the gate. Devices of T entitled to more receive it by
bundle wrap.

### 3.8 Restored members

A merge that voids a removal `r` of `m` **restores** `m`. It receives the
current state at once (section 3.13), and starts from a history-free
snapshot. A state `K` is **made while `m` was out** when `m` is entitled to
it only because `r` is void, and `K`'s past lacks `r` or one of the events
that void it ([roster.md](roster.md)). Such a key is not wrapped for `m`, no
link `m` could follow reaches it, and replicas list it as waiting, until a
holder decides:

```text
gap_keys(stable, first_sight, now, gap_key_timeout):
  1. stable: the voiding of r is stable (roster.md).               Wrap
  2. lower(first_sight, now) >= gap_key_timeout.                   Wrap
  3. Otherwise.                                                    Wait
```

`first_sight` is this device's first sight of the restoring merge, and the
timeout is the space policy's. The decision is only whether this device
wraps; it never makes a key or an event valid or void. A space whose space
recovery member never signs never reaches stability, so a restored member
there waits the full timeout. If a later merge makes `r` valid again, `m` is
removed again and the heal test runs.

### 3.9 Healing

**What a set of devices derives,** from the wraps, space wraps, links, gap
records and rotation authors a view holds, for one graph:

1. A device holds every state a bundle wrap it opens carries, and every
   rotation it authored.
2. The devices of a space principal hold every state a space wrap to it
   carries.
3. Repeat until nothing changes: a link under a held state gives the state
   it reaches; a merged state named anywhere in the view is held when all
   its rotations are.

A set of devices derives the union of their holdings. Every member knows
from the roster at a delivery's place which devices it wrapped for: the
devices of its members, a person's being every device, passkey member and
recovery key that a valid `add` in the person's list names, as this replica
holds the list. A device keeps what it received whatever the lists say
later. A device that its list has
since revoked, or whose chain has since forked, still holds every state
wrapped at a delivery whose past, the delivery included, holds neither a
response to the end of its path ([roster.md](roster.md), "Checks across
logs") nor the evidence of its fork.

**The heal test** fires, for the content graph or the grant graph, when:

- **outside:** the holders outside the inside together derive the current
  state. A holder is any device a wrap was made for, any device of a space
  principal a space wrap was made for, and any rotation's author. Revoked
  and forked devices, and the devices of a principal that are no longer
  inside, count as outside; for the grant graph, so does a member whose
  grant does not propagate. [ext-invite-links.md](ext-invite-links.md)
  says when an invite key does; or
- **unreachable:** no inside device derives the current state.

Each replica computes the test from what it holds, and replicas that hold
different artifacts may disagree; the cost is an extra heal, which merges
like any rotation.

**Who heals.**

- The content key: any writer, a guest included. It waits its rank delay
  (section 3.11) with the healed state's `encode_set` as the trigger, and
  drops its heal if a rotation that follows the healed state arrives first.
- The grant key: only a writer whose grant propagates. Its heal is a grant
  rotation when the grant graph's test fires. A guest's heal never is; if
  the grant graph's test also fires, that heal waits for a writer that
  propagates.
- A healer that holds the current state links back to it; one that does not
  records a gap.

### 3.10 Cascades

**Which spaces rotate.** A **change** to space C is a roster event of C, a
device list's revocation of a device C reaches through a person, or a
cascaded rotation of C. After it, every other space X is compared before
and after, by its effective membership ([roster.md](roster.md)):

- **X loses a device:** X rotates, with a grant rotation, which cascades in
  turn.
- **A member's level in X drops to `read` through C:** X keeps its key. The
  device keeps X's upload key until X next rotates, and the write rule
  refuses its units.
- **X loses nothing:** X keeps its key.
- **C admitted a member that propagates, "from now on":** every space C
  reaches through grants, transitively, breaks. Otherwise the newcomer would
  read their history through C's new grant key.
- **C healed its grant key:** every space C reaches through grants,
  transitively, rotates.
- **A guest leaves C:** C rotates its content key only, and nothing C
  reaches rotates.
- [ext-restricted-spaces.md](ext-restricted-spaces.md) says when a
  restricted space rotates.

**The response.** X answers a change in C with a **response**, an event of X
whose sealed refs name the change, or a later event of C's log that has it
in its past, one pair per change it covers ([roster.md](roster.md)).

- When X loses a device, or C broke or healed its grant key, the response is
  a key event that rotates. It is a grant rotation, carries `break` when it
  breaks for an admission "from now on", and links back to X's previous
  state or carries the gap records of a break.
- When X loses nothing, the response only delivers: a notice for C's new
  grant rotation and a space wrap of X's current state to it.
- Every response to a change in a space X grants carries a notice for C's
  resulting grant rotation (section 3.3, step 8).
- A response that only delivers where X lost a device leaves an outside
  holder of X's current key, so the heal test of any member that holds both
  logs fires. One candidate cannot suppress a cascade.

**Who rotates.** Any **informed writer** of X: a device that reaches X at
`write`, propagates there, and holds C's new state. The **candidates** for a
change in a space C that X grants are X's writer devices that propagate and
are propagating members of C after the change; for a list's revocation,
X's writer devices that propagate and hold that list. Each waits its rank
delay with the change's event ID as the trigger, and drops its own rotation
when it sees a valid rotation of X whose sealed refs name the change and
whose notice for C is valid at the candidate. Two that rotate anyway
merge.

**Before the cascade.** Until X has rotated after a change that cost it a
device, a device that knows of the change MUST NOT write to X: no unit, not
even the `frasil:list` copy that carries a list's revocation, no key event
other than the rotation, and no ephemeral message. The copy follows the
rotation.

**Limits.** A client warns when a change would cascade into more than 1,024
spaces; a peer, which sees no grants, cannot count them. Only a writer of X
that is a propagating member of C can notice C's grant rotations. A client
warns, when it signs a grant of a space and whenever its view shows one, of
a grant with no such writer, since C's newer members would then lose access
to X's new keys.

### 3.11 The rank and the delay

Heals, collapses and cascaded rotations are each due at many devices at
once. Each candidate waits a delay set by its rank, so that usually one
rotates.

```text
rank_value(d) = u64be(first 8 bytes of SHA-256("frasil/rotation-rank/v1"
                || field(space) || field(trigger) || device ID of d))
position(d)   = d's index, from 0, among the candidates ordered by
                ascending rank_value, then ascending device ID
delay(d)      = min(position(d), rotation_rank_cap) × rotation_step
```

- The candidates are those of the device's own view: for a content heal or
  a collapse, every writer device; for a grant heal, every writer device
  that propagates; for a cascade, section 3.10's.
- The delay counts from the device's first sight of the trigger, on the
  lower estimate ([overview.md](overview.md), section 6). First sight never
  moves, so a device that returns after its delay has passed rotates at
  once if no rotation has arrived.
- A trigger that is a state, a heal's or a collapse's, is first seen when
  the device's view first calls for that rotation. No record keeps that
  sight at rest ([at-rest.md](at-rest.md)): after a restart, the device
  counts from the newest first sight among the space's events it holds,
  which is never earlier, so its wait only lengthens.
- No device waits for another: if the first candidates are offline, the
  next rotates after its own delay.
- The delay decides only when this device acts. A rotation made early, late
  or by several devices is valid by the same rules.

### 3.12 Collapsing

- When the current state holds more than 8 rotations, a collapse is due. An
  informed writer publishes a key event that rotates, with the rotations of
  `S` among its parents, after its rank delay with `encode_set(S)` as the
  trigger, unless a rotation that follows every member of `S` arrives
  first.
- No unit names a state of more than 64 rotations. A writer whose state holds
  more collapses first, with no delay, then writes.
- A collapse is an ordinary rotation that links back to `S`. It is a grant
  rotation when its author propagates and the grant state holds more than 8
  rotations, or holds several when a notice of it is needed.

### 3.13 Deliveries

A view calls for these completions. Any writer that derives what it would
deliver may publish them, in a key event that only delivers or beside a
rotation; for the grant graph, the writer MUST propagate. When the heal test
fires, the heal comes first: no link hangs under the condemned state.

1. The current state, to every inside device and space principal that lacks
   it. A member admitted "from now on" whose break merges with a rotation
   concurrent with it holds the break's key and not the other's, so it
   receives the merged state whole, and provisional (section 3.5): the
   merged key reveals no rotation's key, and every event sealed under it
   follows the break. The writers that derive the state wait their rank
   delay, with its `encode_set` as the trigger, and the first sends one key
   event that only delivers to every inside device that lacks it.
2. Every state a member is entitled to and lacks: every rotation of the view
   and every state an event of the view is sealed under, a unit's key
   reference or a space event's sealed state. Keys waiting for stability
   are held back. The writers that derive a state wait their rank delay,
   with its `encode_set` as the trigger, as for the first. A merged state
   that item 1 would deliver whole stops being current at the next
   rotation, often before that delay ends. Its place holds the member's
   admission, so the member is entitled to it (section 3.7, rule 1), and
   this item delivers it: without it, the events sealed under it stay
   `Sealed` at the member, and every event after them waits.
3. The inputs of a merge: for each rotation of a current state of several, a
   link from the current state where the gate allows, and otherwise a gap
   record and wraps.
4. Void keys: for each void rotation, and each state a unit names that
   includes one, a link from the current state where the gate allows, and
   otherwise a gap and wraps. Units sealed under them stay readable.
5. Gap keys, to every member entitled to them. A "with history" grant
   receives them all.

A "with history" newcomer receives the current state and a wrap per gap key
it is entitled to, then follows links from every state it holds, visiting
each once: linear in the space's rotations. A grant whose granter lacks some
history delivers what it holds; any other member that holds the rest
delivers it. History that only removed members held is lost.

A rotation's own delivery MUST include a wrap for the author's own device,
so that a device restored from an older backup recovers the rotation's
secrets from the log.

A rotation whose roster changes remove members SHOULD carry a removal wrap
for each device that the roster at its place reaches and the roster after
its changes does not: a removed device, and each device of a removed
person, as section 3.9 counts them. A removed space principal receives
none. Removal wraps go in the first own delivery, at any position among its
bundle wraps, as far as the limits on wraps allow. Without one, the removed
device learns of its removal only from a member that hands it the body key.

### 3.14 Who may publish what

"Validity" rules void an event at every replica. "Client policy" is what an
honest client does; a replica refuses no event for breaking it.

| Action | Who | Rule |
|---|---|---|
| Any key event | not a device rooted in a recovery agent and not confirmed ([roster.md](roster.md), `WaitingDevice`) | validity |
| A key event that rotates, not a grant rotation | any writer, a guest included, not a device waiting on a recovery agent | validity ([roster.md](roster.md)) |
| A grant rotation by key event: a grant heal, a collapse, a response that rotates | a writer whose grant propagates | validity (section 3.3, steps 5 and 6) |
| A key event whose sealed refs name a granted space's log | carries a notice for that space | validity (section 3.3, step 8) |
| A response to a change in a granted space | carries a notice for that space's resulting grant rotation | client policy |
| A notice that admits its principal | a propagating member of the granted space at a valid rotation that matches its commitment and whose principal no response has put out of force | admission, at each replica that holds the granted space's log (section 3.4); never a verdict |
| An event that does not rotate | sealed under its author's current content state | validity (section 3.3, step 2) |
| A delivery of a content state | any writer that derives it | client policy |
| A delivery of a grant state, a space wrap | a writer that propagates, derives the state, and holds a valid notice for a space wrap | client policy |
| A cascaded rotation | a candidate after its rank delay | client policy |
| How many delivery-only events an author sends | | client policy: a device MAY stop trying an author's deliveries when they flood it |
| The author's own wrap in its own delivery | the rotator | client policy |

A guest therefore makes key events, but never draws, receives or delivers a
grant seed, and never authors a valid notice.

### 3.15 Reading a unit's key reference

In order:

1. The reference reads as one rotation set. Else `Malformed` or
   `TooManyRotations`.
2. No ID names an event of this space's log that is no rotation. Else
   `NotARotation`, which is final, even when the reader also lacks another
   ID's event.
3. The reader holds every ID's event. A reader that lacks one fetches it,
   and the unit waits as if it had not arrived (`Pending`).
4. No ID of the set is in the past of another. Else `Malformed`.

A reference may name a void rotation: honest writers sealed under it in good
faith, and its keys stay reachable (section 3.13, item 4).

### 3.16 Sealed names

**Opening** a sealed name `s`, given `mk`, the space ID, the key reference,
`c` and `id`, in order:

1. As section 2.8, step 1. Else `Malformed`.
2. `s` is not empty (`Malformed`), and `s[0] = 0x01` (`UnsupportedVersion`).
3. `B = len(s) − 41` is above 0, a multiple of 64, and at most 1,024. Else
   `Malformed`.
4. `s[25..]` opens under `mk`, nonce `s[1..25]` and section 2.8's `aad`.
   Else `Decrypt`.
5. For the plaintext `p`, `L = u16be(p[0..2])` is 1 to 1,022,
   `len(p) = padded_len(L)`, `p[2 + L..]` is all zero, and `p[2..2 + L]` is
   UTF-8. Else `Malformed`. The name is `p[2..2 + L]`.

Every refusal after decryption is `Malformed`, so a caller without the key
learns only whether the tag verified.

**Reading a record**, in a space, in order:

1. Not empty (`Malformed`); byte 0 is `0x01` (`UnsupportedVersion`).
2. At least 37 bytes. Else `Malformed`.
3. The record's space is the reader's. Else `Decrypt`: another space's
   record does not open, and its reference is not read.
4. The reference's length is not 0 and fits, and the reference reads as a
   key reference of that space. Else `Malformed`, or `TooManyRotations`.
5. The reader holds the content key of the state it names. Else
   `MissingState`: the reader may reach it later.
6. The sealed name opens under that state's metadata key.

**Rotation.** A name stays sealed under its state; a rotation never seals it
again. After a break, a writer that keeps names that members admitted "from
now on" need to see MUST seal each again under the current state, with the
same kind and ID, and replace the record. After a removal, a name that does not
change need not be sealed again; one changed afterwards is sealed under the
new state.

### 3.17 Keys after a checkpoint

A checkpoint ([roster.md](roster.md), "Checkpoints") rotates, as a grant
rotation unless its author does not propagate or the space is restricted,
and is no break: section 3.3 takes it as it takes a genesis. Its author
links back to the current state of its view where the gate allows and
records gaps otherwise, as for any rotation. Its own delivery wraps the
new state for every device inside at its past (section 3.6) and, by space
wrap, for every space principal in force there whose notice its record
keeps, the principals its world will have: never for a device or an
invite key that counts as outside, such as a revoked or forked device or
an invite key whose claim was raced or made. So the checkpoint heals: no
holder outside its past's inside derives its state.

**Its world.** Once it is in effect, its world (roster.md, section 3.15.5)
is the key graph's too:

- **Rotations and artifacts.** The rotations counted are the checkpoint
  and the valid rotations after it, so the current state, the heal test,
  entitlement to states after it and the link gate read nothing before
  it. Section 3.9 derives holdings from the wraps, space wraps, links, gap
  records and rotation authors of the checkpoint and the events after it
  alone: those of late events and of events before it count for nothing,
  whether a replica kept them or not. They cannot reach a state of the
  world, whose rotations none of them has in its past, so leaving them out
  changes no heal test, and a replica that dropped them decides as one
  that kept them.
- **The inside at the root** is that of the record: its members, an
  invite key of status 0 or 3 inside and one of status 2 outside
  ([ext-invite-links.md](ext-invite-links.md)), and the principals of its
  recorded notices that pass section 3.4 at this replica, which the
  checkpoint carries as its own (roster.md, section 3.15.5). A raced or
  claimed invite key is a record entry but not inside, and the
  checkpoint's delivery never reaches it; every device that delivery
  reaches is inside, so the heal test after it fires exactly where a
  holder outside derives a state of the world.
- **Seals.** Every event after the checkpoint is sealed under a state of
  its world, else `StaleSeal` (roster.md, section 3.15.5), so every space
  event a replica judges there opens under keys checked against rotations
  it holds.

**States before the checkpoint** are reached only through links and gap
keys made under it or after it, and their keys are provisional where the
replica does not hold their rotations (section 3.5). Entitlement to them,
which only decides what an honest client delivers or links:

- a member with a "with history" grant after the checkpoint is entitled to
  every state before it (each precedes the grant); a member of the record
  is entitled to those its past entitled it to, by section 3.7 over that
  past, which only a replica that holds that past can tell, and only such
  a replica delivers them; a replica that forgot counts it as entitled to
  none;
- a space principal is entitled to no state before the checkpoint when
  the record gives its space a floor, whatever notice admits it after the
  checkpoint: some device of that space was admitted "from now on" and
  this space responded before the checkpoint, and a replica that forgot
  cannot place that response among earlier states. Without a floor, a
  "with history" notice after the checkpoint entitles it as a "with
  history" grant does;
- a break before the checkpoint precedes every rotation after it, so it
  never blocks a link after it (section 3.7, condition 2);
- a device tries a delivery that names states before the checkpoint when
  it is entitled to them (section 3.1, "Trial decryption").

**What is kept.** Keys are kept apart from events ([at-rest.md](at-rest.md)).
A replica that forgets the events before a checkpoint keeps the content
keys of the states its retained units, objects and names are sealed
under, and the grant seed of every grant rotation of its space that a
principal in force in a space that grants it names, as it holds that
space's log: that space keeps sealing space wraps to the rotation its
notice names, before this space's checkpoint, until it notices a newer
one (roster.md, section 3.15.8). It drops such a seed once no principal in
force names its rotation.

### 3.18 Error classes

Besides [overview.md](overview.md)'s classes (section 5.5):

| Class | Meaning | Sort |
|---|---|---|
| `TooManyRotations` | a state or key name of more than 64 rotations | final |
| `NotARotation` | a key reference naming an event that is no rotation | final |
| `KeyMismatch` | a received secret that misses its rotation's commitment; the slot is dropped | report |
| `RotationRequired`, `BreakRequired`, `UnexpectedBreak`, `GrantKeyNotAllowed`, `GrantKeyRequired`, `UnexpectedGrantKey`, `NoticeRequired` | section 3.3 | final |
| `StaleSeal` | an event that does not rotate, sealed under a state a valid rotation in its place follows; after a checkpoint in effect, also an event or unit sealed under a state outside the checkpoint's world (section 3.17) | final |
| `NoticeVoid`, `NoticeMismatch`, `NoticeStale`, `NotGranteeMember` | a notice that admits no principal (section 3.4) | report |
| `InvalidName` | a name to seal that is empty or longer than 1,022 bytes | final |
| `MissingState` | a record whose state the reader does not hold | held |

The classes of section 3.3 are validity failures of the carrying event.
Those of section 3.4 are a notice's own, and change no verdict.

## 4. Security considerations

- **Merge keys.** A merged key falls to whoever holds every input: one
  removed member alone, or several together. The heal test closes it from
  the heal on. Units that informed writers sealed under the merged key
  before the heal stay exposed, for one round trip among informed writers
  and a rank delay.
- **Links open forever.** A link opens for every holder of the state it
  hangs under, forever. So the gate counts every possible holder, the
  grantee of a void break and members waiting for stability included. A
  withheld link costs a wrap per entitled device, never secrecy.
- **Restored members.** A member restored by a voided removal works at once
  with the current key, and receives keys made while it was out only once
  the voiding is stable or the timeout passes, so a later merge that
  revalidates the removal does not leave it holding them. What it received
  from the restoration on it keeps; the heal test then makes the next key
  fresh.
- **Grant keys and guests.** A guest of a space holds its content key and
  never its grant key, so it opens no space wrap of a space that grants that
  space, and its leaving rotates only one content key.
- **Notices** are the one place a member hands others a key to seal to. A
  notice is checked against the granted space's own commitment, so nobody
  substitutes a key or hides a break; against the responses already made,
  so nobody brings back a principal out of force; and against its author's
  membership, so a guest or an outsider plants none. A principal sealed to
  by mistake trips the heal test. A failed notice costs only its principal,
  never its event: an author can cite a rotation of T beside a notice that
  fails, which puts T's older principals out of force and admits none, so
  T's members receive nothing new until a writer that propagates in T
  notices T's current grant rotation, which such a writer SHOULD do when
  its view shows T with no principal in force.
- **Junk key material.** A writer can wrap a key nobody else holds, or link
  to junk. Readers then cannot open units under that state, as with a
  missing key; content is signed by its writer, so junk keys never make a
  reader accept content. A misaddressed wrap makes its recipient a holder,
  which the heal test counts. A junk merged key received whole can make a
  device hold honest space events, never void them, until it derives the key.
- **The upload seed and quota.** A space wrap to a space granted at `write`
  carries the upload seed, which every propagating member of the granted
  space opens, a reader there included. Such a reader can store data at a
  peer and spend the granting space's quota, though every replica refuses
  its units. A member whose level drops to `read` through a granted space
  keeps the inheriting space's upload key until that space rotates; a direct
  demotion to `read` rotates. Both leaks are quota only.
- **Self references** bind the author and its `seq`. A device that signs two
  events at one `seq` is caught by its chain, and its events from the fork
  point are void.
- **Trial decryption is bounded.** A device tries only deliveries that name a
  state it lacks and is entitled to, and stops at the first wrap that opens:
  at most 768 X-Wing decapsulations per event. It tries an event's own
  deliveries for a removal wrap once, and only for a rotation it holds
  `Sealed`.
- **What a removal wrap reveals.** The removed device reads the sealed part
  of the event that removes it: the roster changes, the refs, the notices'
  public keys and the links. The links are sealed under `k_R`, which it
  never receives, so it learns who changed what in that event and no key.
  A peer cannot tell a removal wrap from a bundle wrap: both are 1,236
  bytes and sit in the same delivery, so a removal changes no wrap count
  the peer could compare with the previous rotation's. A writer that sends many
  delivery-only events is attributable, and a client limits how many it
  tries per author.
- **Post-quantum.** Every wrap and space wrap is X-Wing. Links, merges and
  sealed parts are symmetric. Every wrap, link and commitment is inside a
  space event signed under scheme 2, so a quantum adversary cannot hand a
  taker a key without forging ML-DSA-65 under the author's own key, the one
  its device ID commits to ([crypto.md](crypto.md), "Security
  considerations").
- **Sealed names.** The associated data binds the label, the space, the key
  reference, the kind and the ID, each fixed-length or length-prefixed, so
  a name sealed for one thing opens as no other. A sealed name reveals its
  64-byte bucket, and every holder of the state's key reads it and can seal
  any name for any thing.
- **What a peer sees** of a space event is [overview.md](overview.md)'s,
  section 4.1: whether it rotates, the state an event that does not rotate
  is sealed under (rotation IDs, which units name anyway), its commitments,
  each delivery's wrap count, its size, and key 15. Sizes hint at sealed
  facts: a break carries no link back, a grant rotation carries a grant
  link. Padding is the client's choice.

## 5. Test vectors

[keys.json](vectors/keys.json), byte for byte:

- `labels`, `parameters`: section 2.9 and the sizes of section 2.
- `rotation_sets`: encodings of one and three rotations and a self
  reference; when a collapse is due, at 1, 8, 9, 64 and 65 rotations;
  refused names with their class.
- `derivations`: three rotations' secrets in one space, and for `{A}`,
  `{A, B}` and `{A, B, C}` the content key, upload seed and grant seed with
  each merge's info, `t_i` and input; the grant key pair and its commitment
  with and without a break; the read credential, upload key, metadata and
  object keys; the body key and commitment of an event sealed under the
  state; and `{A, B}` merged in another space, which differs.
- `bundles`: every bundle shape, refused bundles (a non-zero absent slot
  among them), and who receives what, by level and propagation.
- `bundle_wraps`: five wraps (a writer and a reader that propagate, a guest
  in the same delivery with no grant seed, a self reference, a gap key) with
  their encapsulation randomness, info and ciphertext; trial decryption over
  a delivery of three; nine refusals.
- `removal_wraps`: a removal wrap of a rotation's body key with its
  encapsulation randomness, info, plaintext and ciphertext, and the body
  key's commitment; trial decryption over an own delivery of a bundle wrap
  and the removal wrap, where the removed device finds the removal wrap and
  the remaining member finds its bundle wrap; refusals: tried by another
  device, opened as a bundle wrap, a bundle wrap opened as a removal wrap, a
  wrong first byte, a tail that is not zero, and a body key that does not
  match the commitment.
- `space_wraps`: the grantee's grant key pair, wraps for a grant at `write`
  and at `read`, and five refusals.
- `links`: three links (under a self reference, from a merge to an input, a
  grant link) with info, key, associated data and nonce; nine refusals; gap
  records and three refusals.
- `space_event_bodies`: the shapes of a grant, a removal, a rotation with no
  roster change, a policy change and a delivery that do not rotate; a body
  key derived step by step for an event sealed under a named state, and for
  the genesis under its nonce; six bodies in their signed events (a removal
  of a member that propagates; a response to a removal in a granted space
  with its notice and space wrap; a cascaded break with a notice "from now
  on"; a response that loses nothing and only delivers; a guest's heal; a
  plain delivery); a self-removal that does not rotate.
- `visible_refusals`, `sealed_refusals`: twenty-four refused visible parts
  (reserved keys, missing or short commitments, a nonce outside a rotation,
  a short twin, a twin beside a nonce among them) and thirteen refused
  sealed parts (padding not zero, five malformed ref lists, a commitment to
  another key and a damaged part), with their class.
- `context_refusals`: fifteen events refused against their place, one per
  class of section 3.3 and `StaleSeal`; accepted, a delivery-only response
  with a notice and a roster event whose refs name a granted space's log
  without one.
- `notices`: whether each notice admits its principal: an honest notice;
  `NoticeMismatch` three ways; `NotGranteeMember`; `NoticeVoid`;
  `NoticeStale`; unresolved (`Pending`) twice. Each gives the grantee
  rotation's commitment and whether that rotation is valid in the grantee's
  log as held (`grantee_valid`), both null where the replica does not hold
  it.
- `checkpoint_worlds`: the key graph rooted at a checkpoint (section 3.17),
  seven histories: a heal after it; a "with history" grant after it
  entitled to states before it, a "from now on" one and a record member
  not; a raced invite key outside in the world, with no heal due when the
  checkpoint did not wrap for it and the heal test firing when it did; a
  granted space whose recorded principal is inside at the root, with a
  floor (a "with history" notice after it not entitled to earlier states)
  and without (entitled); and a late rotation whose wrap counts for
  nothing.
- `taking_keys`: four bundles checked slot by slot, with the slots kept and
  dropped; a seal mismatch under a derived and under a provisional key; four
  trial-decryption decisions; the caps on deliveries and wraps, at the cap
  and over it.
- `ranks`: five writers' rank values, positions and delays at the default
  step, at the cap and at the largest step; the candidates for a project's
  cascade after a person leaves its team, and the devices that are not
  candidates, with why.
- `rotation_delay`: section 3.11's delay at and around each bound.
- `cascades`: for seven changes (a person leaves the team; the team's guest
  leaves; a person leaves the project; a person leaves the team but is in
  the project directly; a list revokes a device; the team admits a person
  "from now on"; the team heals its grant key), each space's verdict:
  rotates and the devices it loses, keeps its key, breaks, or not reached.
- `gap_keys`: section 3.8's decision at and around each bound.
- `histories`: a cross-removal; a void rotation; a guest "from now on"; a
  void input learned late; the backdated duel; a removal outside the merged
  state; one removed member deriving the current key; concurrent heals that
  need a second heal; a stale link across a break; history across a break's
  merge; a grant valid again that misses an old merged key; a guest's heal
  whose grant heal waits for a member that propagates; a revoked device
  that still holds the keys it received; a break's merge that stops being
  current before any writer delivers it, delivered as a state the
  newcomer is entitled to; and space principals
  (a notice, a response that puts a principal out of force, a response that
  loses nothing, a re-notice of a principal out of force and an event that
  both puts it out of force and re-admits it, two refused notices nobody
  seals to, each carried by an event that stands, a cascaded break
  the team's newcomer cannot see behind, and a later notice "with history"
  that still reaches nothing before the break). Each checkpoint is one
  device's view: the events it holds, the valid set given as input, and the
  wraps, links and gaps it holds; for space principals, each granted space's
  current devices as the replica holds its log (`foreign_current`), and
  each principal's floor, this space's responses to the granted space's
  breaks before which it is entitled to nothing (`principal_floor`); and
  the devices their persons' lists have revoked (`revoked`). An
  implementation computes the merged
  roster, the current content and grant states and their secrets, each
  member's entitlement and what waits for stability, both heal tests, the
  deliveries the view calls for with the first device that can make each,
  and the stated reach queries. One checkpoint repeats a view after
  `gap_key_timeout` (`timed_out`).
- `sealed_names`: in one space, the states `A` and `A+B` with their content
  keys, key references and metadata keys; seven names (the space's own, a
  restricted space's and a granted space's kept in the space, document names of 62 and 63 bytes, one
  not ASCII, the longest), each with its nonce, padded plaintext,
  associated data, sealed bytes and record; names to open and inputs to
  seal that fail, with their class; and refused records (another space's,
  `MissingState`, an unknown version, a reference that is not a rotation
  set, 65 rotations, a reference past the record's end, 36 bytes).
