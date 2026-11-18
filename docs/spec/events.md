# Events
Protocol 1. Vectors: [events.json](vectors/events.json).

This document specifies the one envelope that every signed and synced thing
in Frasil shares: its encoding, what is signed, the event ID, the log an
event belongs to, refs to other logs, causal and canonical order, heads and
placement, per-device chains, evidence and proofs of a fork, and the limits.
It depends on [overview.md](overview.md) for conventions and error classes
and on [crypto.md](crypto.md) for signature schemes and key validation. What
an event means is its kind's document.

## 1. Overview

- An **event** is a deterministic CBOR map signed by its **author**, a
  device named by its device ID ([crypto.md](crypto.md)). The envelope
  carries the author's Ed25519 key and the commitment to its other keys,
  from which anyone computes the device ID. The **signed event** is the
  map's bytes and the signature, side by side.
- The **event ID** hashes the map without the signature. It is the causal
  link between events, and the ID of a log: a **space ID** and a **person
  ID** are the IDs of a genesis.
- A **log** is the events that share one genesis: a space's log, or a
  person's device list. Each event names its **parents** in its own log.
  Logs share no order; an event cites events of other logs only through
  **refs**, which travel sealed in its body.
- Replicas decide in **canonical order**, by height then event ID, which
  every replica computes alike from the events it holds.
- Each author's events in a log form its **chain**, numbered by `seq` and
  linked by `prev`. Two events at one `seq`, or a `prev` that skips, prove a
  **fork**. Every replica that holds the evidence voids the author's events
  from the fork point on.
- Every check of this document reads the envelope alone, which a peer
  sees, so a peer and a replica that cannot open a body still agree on
  order, chains and forks.

## 2. Formats

### 2.1 Kinds

| Kind | Name | Defined in | May start a log |
|---|---|---|---|
| 1 | device-list event | [identity.md](identity.md) | yes: a person's list |
| 2 | space event: a roster event or a key event | [roster.md](roster.md), sealed by [keys.md](keys.md) | yes: a space |
| 3 | reserved | | `Malformed` |
| 4 | unit | [units.md](units.md) | no |
| 5 | anchor | [crypto.md](crypto.md) | no |
| 6 | storage event | [peers.md](peers.md) | no |
| 7 to 63 | reserved; must be understood | | |
| 64 to 127 | ignorable; protocol 1 defines none | | no |

- The schemes each kind may carry are [crypto.md](crypto.md)'s table, "Which
  structures carry which scheme". A verifier takes them from the kind alone.
- Kinds 1 to 63 **must be understood**. A replica refuses a kind from 7 to
  63 that it does not know as `UnknownKind`. A kind that changes validity is
  numbered here.
- Kinds 64 to 127 are **ignorable**. A replica that does not know one
  verifies its envelope, places it, counts it in its author's chain, forwards
  it, and gives it no other effect. It keeps one only if a record of the log
  names its author, and drops it otherwise, so that strangers cannot
  make replicas store their events ([roster.md](roster.md), "Strangers'
  events"). A kind that only adds information may be numbered here.
- Kind 0, kind 3 and kinds from 128 are `Malformed`. Kind 3 is never
  assigned.
- A space event's body is sealed. Whether it is a roster event or a key
  event, and so which level its author needs, is known only once it is
  opened. Its envelope does not say.

### 2.2 The envelope

An event is a deterministic CBOR map ([overview.md](overview.md),
"Deterministic CBOR") with these keys:

| Key | Field | Type | Value |
|---|---|---|---|
| 0 | `version` | unsigned | `1` |
| 1 | `kind` | unsigned | section 2.1 |
| 2 | `log` | bytes(32) | the log ID; absent in a genesis |
| 3 | `ed` | bytes(32) | the author's Ed25519 identity key |
| 4 | `seq` | unsigned | the author's sequence number in this log, from 1 |
| 5 | `prev` | bytes(32) | the ID of the author's event at `seq − 1`; absent when `seq` is 1 |
| 6 | `parents` | array of bytes(32) | IDs of events of this log, strictly ascending as byte strings |
| 7 | `cuts` | array of bytes(32) | the checkpoints the event follows (section 3.11): 1 to 4 event IDs of this log, strictly ascending; absent when its past holds no checkpoint, and in a genesis |
| 8 | `body` | bytes | the kind's body |
| 9 | `scheme` | unsigned | absent for scheme 0; `2` for scheme 2 ([crypto.md](crypto.md)) |
| 10 | `kc` | bytes(32) | the author's keys commitment ([crypto.md](crypto.md), "A device's keys") |

Keys 1, 3, 4, 6, 8 and 10 are required. Any key outside 0 to 10 is
`Malformed`.

The event's **author** is the device ID of keys 3 and 10:

```text
author = SHA-256("frasil/device-id/v1" || ed || kc)
```

A peer, a replica and a verifier of a proof each compute it from the
envelope alone. Wherever a document names an event's author (its chain,
fork evidence, a self reference, a stub, a sync message, a peer's
attribution, a member reference that the author must match), it means this
32-byte device ID. Where a document needs the Ed25519 key that signs, it
names `ed`.

```text
signed event = CBOR array [event, signature]
  event:     the map's bytes, as a byte string
  signature: a byte string, 64 bytes for scheme 0, 3,373 for scheme 2
```

### 2.3 Field rules

- **A genesis** has no `log`, `seq` 1, no `prev` and no parents. Only kinds
  1 and 2 may be a genesis. Every other event has a `log` and at least one
  parent.
- **A genesis cannot name its own log**, because the log ID is the hash of
  the genesis. Whatever in a genesis binds the log binds something else in
  its place, and the genesis's signature binds that to the event: a space's
  genesis binds a 16-byte nonce in its body ([roster.md](roster.md),
  [keys.md](keys.md)); a person's first list event binds 32 zero bytes as the
  person ID of its possession proof ([identity.md](identity.md)).
- **`prev` is among the parents** whenever it is present, so an event
  follows its author's previous event causally, and a verifier checks this
  from the event alone.
- **Parents** are the heads the author holds, with `prev`. They need not be
  minimal: `prev` may also be in the past of another parent.
- **No time.** No field holds a time or a value derived from a clock, and
  `seq` counts events, not time ([overview.md](overview.md), "Time").
- **An anchor** has an empty body, and its parents are the heads its author
  holds in the log, `prev` among them ([crypto.md](crypto.md), "Anchors and
  coverage").

### 2.4 Refs

A **ref** names an event of another log: the pair `[log ID, event ID]`. An
event's refs are the events of other logs it responds to or depends on, such
as the device-list revocation a space event answers.

```text
refs = CBOR array of 1 to 64 refs, each [log (bytes 32), id (bytes 32)],
       strictly ascending as the 64 bytes log || id
```

- **Refs travel sealed in the body,** never in the envelope: a space event's
  in its sealed part ([roster.md](roster.md)), a unit's inside its seal
  ([units.md](units.md)). A device-list event carries none. In the envelope
  they would show a peer the grant graph and person IDs.
- **Refs create no order.** Two logs share no causal order, and no
  envelope check, chain, fork evidence or coverage reads a ref.
- **The author supplies what it cites.** A replica fetches each event a ref
  names that it lacks, from the referring device first. An event whose refs
  the replica cannot resolve is pending (`Pending`): never applied, never
  cited, and nothing waits for it except the events after it. A roster event
  is the exception: its validity never waits on another log, and its refs
  count only once they resolve ([roster.md](roster.md), "Checks across
  logs").

### 2.5 What is signed, and the event ID

```text
tbs      = "frasil/event/v1" || event                 the map's bytes, key 9 included
event ID = SHA-256("frasil/event-id/v1" || event)     the map's bytes, without the signature

scheme 0: signature = Ed25519-Sign(the identity seed of ed, tbs)          64 bytes
scheme 2: signature = crypto.md's scheme-2 signature over tbs          3,373 bytes
```

- **The ID leaves out the signature.** Two signed copies of one map, signed
  again or with another valid signature, are one event with one ID. A
  replica keeps the first copy whose signature it verified and treats every
  other copy as that event. So no one, the author included, can make one
  event look like two. The map holds `ed`, `kc` and the scheme, so two
  authors or two schemes never share an ID.
- **The signature covers `kc`,** which is inside `tbs`. An event signed
  under one `kc` cannot be given another, so a signature by a device's keys
  is never read as another device's, even one that shares its Ed25519
  key.
- **The scheme is inside `tbs`,** so a scheme-2 signature cut to its Ed25519
  half fails as scheme 0 too.
- **The Ed25519 half needs no other key** ([crypto.md](crypto.md),
  "Signature schemes"). A replica checks it as soon as an event arrives, so
  an event from anyone without the author's Ed25519 key costs one Ed25519
  verification, never a lookup.
- The **log ID** of an event is its `log`, or its own ID for a genesis. A
  space ID is the ID of the space's genesis space event; a person ID is the
  ID of the first event of the person's device list.

### 2.6 Equivocation proofs

```text
proof = CBOR array [type, first, second]
  type 1, duplicate: first and second are two signed events, the one with the smaller ID first
  type 2, skip:      first is a signed event e; second is the signed event e's prev names
```

### 2.7 Limits

| What | Limit |
|---|---|
| A signed event | 16,777,216 bytes, or its kind's limit below |
| A device-list event; an anchor; an event of an ignorable kind | 16,384 bytes |
| A space event; a unit | 1,048,576 bytes |
| A storage event | 262,144 bytes |
| Parents | 256; 16 for a device-list event |
| Refs in one body | 1 to 64 |
| `seq` | 1 to 2^64 − 1 |

A kind's document may set lower limits.

### 2.8 Error classes

Besides those of [overview.md](overview.md), "Error classes":

| Class | Meaning | Sort |
|---|---|---|
| `UnknownKind` | a kind from 7 to 63 this replica does not know | final, for this replica |
| `WrongLog` | an event, or one of its parents, of another log | final |
| `NotEquivocation` | a proof whose two events show no fork | decision |
| `BadCuts` | an event whose `cuts` are not the maximal checkpoints its parents give (section 3.11) | final |

## 3. Procedures

### 3.1 Decoding an event

A replica and a peer run these checks on every signed event, in order,
before anything else:

```text
decode(signed), in order:
   1. len(signed) <= 16,777,216.                                     else TooLarge
   2. signed is a deterministic CBOR array of two byte strings, with
      nothing after it.                                              else Malformed
   3. event is a deterministic CBOR map whose key 0 is unsigned.     else Malformed
   4. version = 1.                                                   else UnsupportedVersion
   5. Its keys are among 0 to 10; keys 1, 3, 4, 6, 8 and 10 are
      present.                                                       else Malformed
   6. Key 9, if present, is unsigned and not 0.                      else Malformed
   7. kind is 1 to 127, and not 3.                                   else Malformed
   8. scheme is 0 or 2.                                              else UnsupportedVersion
   9. scheme is one the kind may carry.                              else SchemeNotAllowed
  10. len(signature) = 64 for scheme 0, 3,373 for scheme 2.          else Malformed
  11. seq >= 1; ed and kc are 32 bytes each; body is bytes; log
      and prev, if present, are 32 bytes; parents is an array of
      32-byte strings, strictly ascending; cuts, if present, an
      array of 1 to 4 32-byte strings, strictly ascending.           else Malformed
  12. Section 2.3: a genesis's shape, of kind 1 or 2; parents
      outside a genesis; prev present exactly when seq > 1, and
      among the parents; an anchor's body empty; no cuts in a
      genesis.                                                       else Malformed
  13. A kind from 1 to 63 is one this replica knows.                 else UnknownKind
  14. The kind's size and parent limits (section 2.7).               else TooLarge
  15. ed passes ed25519_valid (crypto.md).                           else InvalidKey
  16. Scheme 0: the signature verifies strictly over tbs under ed.
      Scheme 2: its Ed25519 half verifies strictly over m_ed
      under ed, with no other key (crypto.md).                       else BadSignature
```

These steps include [crypto.md](crypto.md)'s `verify`, steps 1 to 4. A
missing key 10 fails step 5 and one of another length step 11, both as
`Malformed`, before any key or signature is read; no value of `kc` fails
here, since any 32 bytes may be a commitment. Whether `kc` commits to keys
the author holds is section 3.3's question.

### 3.2 Placement and order

A replica keeps, for each log it follows, the events it has **placed**.

```text
place(event, log), in order:
  1. The event's log ID is the log's ID.                             else WrongLog
  2. No parent is an event of another log.                           else WrongLog
  3. Each parent is placed in this log, or stands as an authenticated
     stub that counts for the event (units.md).                      else Pending, and fetch it
```

- A replica fetches a missing parent from the devices and peers it syncs
  with, and places the event once every parent is placed.
- A replica keeps at most 1,024 events it cannot place per author, and
  8,192 such events or 64 MiB of them in all. Past a limit it drops them
  one at a time: from the author with the most, among the authors no
  record names ([roster.md](roster.md), "Strangers' events") while any of
  them holds one, that author's greatest `seq` first. It fetches a dropped
  event again when an event it holds names it. It stores none at rest from
  an author no record names, but a space event, which may itself be the
  record that names its author.
- A **view** is a set of placed events closed under parents. Everything a
  replica decides about a log is a function of a view, and of the views it
  holds of the logs the kind's rules read across. Two replicas that hold the
  same events decide the same.
- The **past** of an event is its parents, their parents, and so on. `a` is
  **before** `b` when `a` is in the past of `b`; `a` and `b` are
  **concurrent** when they differ and neither is before the other.
- The **heads** of a view are its events that are in no other event's past.
- The **height** of a genesis is 0, and of another event one more than the
  greatest height of its parents.
- **A parent the replica dropped** under a kept checkpoint counts as
  placed ([roster.md](roster.md), section 3.15.6). A replica that held it
  and dropped it keeps its height when it is a parent of an event the
  replica keeps of the checkpoint's past, and places that event on it, so
  that the event, a unit whose height an adapter reads among them, keeps
  the height and canonical order it was judged at. Otherwise it adds
  nothing to a height: an event after the checkpoint counts heights from
  the checkpoint, a late one has no effect, and a newcomer, which counts
  as dropped a parent peers answer `Missing` for, holds of the
  checkpoint's past only units, which its base stubs place
  ([units.md](units.md), "A base"), and events whose height nothing reads.
  A dropped `prev` is not checked against its chain again: the kept event
  was checked when it was judged, and a `prev` outside a checkpoint's
  world is never checked there.
- **Canonical order** sorts a view by height, then by event ID as a byte
  string, smallest first. Height grows along every parent link, so
  canonical order extends the causal order. Every procedure that needs an
  order uses this one. A partial replica, which holds only part of a log,
  knows a height only as [units.md](units.md), section 3.15, says.

### 3.3 The ML-DSA-65 half

A scheme-2 event's ML-DSA-65 half is verified once the replica holds the
author's keys, which it recognises by their hash:

```text
verify_hybrid(event), in order:
  1. The replica holds an ML-DSA-65 key that, with an X-Wing key,
     or with none for a holder that has none, hashes to the
     event's kc (crypto.md, "A device's keys").                      else NoHybridKey
  2. The ML-DSA-65 half verifies under that key, over m_ml
     (crypto.md).                                                    else BadSignature
```

- **Any source.** The replica takes the keys from wherever it finds them:
  the event's own body (a space's genesis names its founder's keys, a
  list's first event its device's), a grant or an `add` of any log, valid
  or void, a skeleton record ([peers.md](peers.md)), another member's list,
  an admission exchange, a cache. The source vouches for nothing: keys
  that hash to `kc` are the author's, and only one ML-DSA-65 key does.
  So the verdict depends on the event alone, never on which records the
  replica holds or how it resolved them.
- **`NoHybridKey`** means only that this replica holds no keys that hash
  to the event's `kc` yet. It is pending: the event is kept, never applied
  and never cited, and verified again when such keys arrive, in a record
  of any log the replica places or from any other source. It never says
  the event is forged.
- **`BadSignature`** here is final: the author's one ML-DSA-65 key does not
  verify the half.

### 3.4 Accepted in full, and what is cited

- An event is **accepted in full** when it decoded, its signature verified
  under its scheme (both halves for scheme 2), it is placed, and its kind's
  document accepts it as an event: for a unit, its seal opened under a key
  the replica holds; for a space event, its body opened under its body key.
- A device cites as parents, and counts as heads, only events it has
  accepted in full and judged by their kind's rules, valid or kept as
  refused, with their past. It never cites an event it holds as pending,
  `NoHybridKey`, `Sealed`, `BadSeal` or `ExtensionRequired`, nor anything
  after one. So an event a replica cannot verify never becomes part of
  anyone's history.
- A device that holds more heads than an event may cite as parents first
  writes anchors over subsets of them, then cites the anchors.
- A space event the replica cannot open is held (`Sealed`). It is not
  accepted in full, and neither is anything after it. The replica judges the
  rest as one that has not yet received them, except that their signatures
  still count as evidence of a fork (section 3.5). When the body key
  arrives, its view grows as it does for any arrival.

### 3.5 Chains and evidence of a fork

The events one author signs in one log form its **chain** there: the first
has `seq` 1 and no `prev`; each later one has `seq` one more than the
previous and `prev` naming it. A device keeps one chain in each log it
writes in.

Chains, evidence and fork points are keyed by the author's device ID, never
by `ed`. Two events that carry one Ed25519 key under different `kc` are two
authors' events, in two chains, and neither is ever evidence against the
other. So an adversary that can produce Ed25519 signatures for a device's
key, but not ML-DSA-65 signatures under its ML-DSA-65 key, can sign events
in full only under a `kc` of its own: they are another author's, and frame
nobody. Events it makes under the device's own `kc` pass a peer's checks,
which read only the Ed25519 half, but their ML-DSA-65 half is
`BadSignature`, so they are never evidence (below).

Two kinds of evidence prove that an author forked its chain:

- **Duplicate:** two events of one author in one log at one `seq`, with
  different IDs. The fork point is that `seq`.
- **Skip:** an event `e` whose `prev` names an event `p` that is not its
  author's event at `seq − 1`. If `p` is the author's own, the fork point is
  `min(e.seq, p.seq + 1)`; if `p` is another author's, it is `e.seq`.

Then:

- **An event counts as evidence once its signature verifies:** scheme 0
  strictly; scheme 2, both halves; after the classical sunset, scheme 2 or a
  covered scheme 0 ([crypto.md](crypto.md), "The classical sunset").
  Whether the replica can open the event does not matter. If it did, a
  replica admitted from now on, or one that lost a key, would miss forks
  that others see, and replicas that hold the same events would disagree.
- A scheme-2 event whose author's keys the replica does not yet hold, as
  when the only record of them it has is sealed in a space event it cannot
  open, is `NoHybridKey` and not yet evidence. The keys decide the same
  verdict wherever they come from, so replicas that hold the same events
  agree on every fork once each holds the authors' keys, whatever content
  keys they hold.
- A replica's **fork point** for an author in a log is the smallest that its
  evidence shows.

### 3.6 Verifying a proof

A replica that finds evidence may pass it on as a proof (section 2.6).

```text
verify_proof(proof), in order:
  1. It is a CBOR array of an unsigned type and two byte strings,
     and the type is 1 or 2.                                         else Malformed
  2. Each event passes section 3.1, the first event then the
     second; then each scheme-2 event passes section 3.3, in the
     same order.                                                     else that class
  3. Type 1: the first ID is smaller than the second.                else Malformed
  4. Type 1: both events have the same author, log and seq.
     Type 2: first's prev is second's ID, both are of one log, and
     second is not first's author's event at first.seq − 1.          else NotEquivocation
```

A proof makes a replica fetch both events and their pasts. Until it has
placed both, the proof decides nothing; meanwhile the replica MAY stop
relying on the device, for example by wrapping nothing for it.

### 3.7 The penalty

- From its fork point on, an author's events in that log are **void**
  (`Forked`), and the author counts as removed there: it receives no wraps,
  and its events count for nothing. Its events before the fork point stand.
- A kind MAY exempt an event that only lowers its own author, so that a fork
  never undoes it: a roster event that only lowers its author
  ([roster.md](roster.md), "Self-lowering events") and a device-list event
  that revokes its author ([identity.md](identity.md), "The merge").
- A fork in one log has no effect in another. A device that forks in its
  person's list stops being vouched for by the list, which is how it leaves
  the person's spaces.

### 3.8 Restored devices sync before writing

- A device that was restored from a backup, or that may otherwise have lost
  events it signed, MUST NOT sign in a log until it has fetched its own
  latest event there from a peer that holds the log. It then continues from
  that event's `seq`.
- A log the device itself originates after the restore is the exception: a
  genesis it writes locally starts a log no other party holds and in which
  it has lost nothing, so it MAY sign there at once. This covers only a
  genesis the device generates itself, not one it learns from another party.
- If no reachable peer holds the log, it waits, or returns as a new device.
  A device that cannot tell whether its state is current MUST treat itself
  as restored.
- A peer that withholds the device's later events can still make it fork.
  Asking several peers narrows this; returning as a new device avoids it.

### 3.9 Members that start from a base

A member admitted from now on starts from a space snapshot and may hold a
log's units only from some point on ([admission.md](admission.md),
[units.md](units.md)). The units before that point stand in its base as
authenticated stubs, which placement accepts as parents (section 3.2). It
applies this document's rules to the events it holds. A merge that brings in
a branch reaching before its base sends it to a fresh snapshot.

A space's frame (its space events, anchors and storage events) is held from
its genesis on, unless a checkpoint is in effect: then a replica, a newcomer
and a peer hold it only from the checkpoint on ([roster.md](roster.md),
"Checkpoints"), and placement reads an event's parents as section 3.11
says.

### 3.10 Handing an event to its kind

For each event, a replica runs, in this order: section 3.1; section 3.2;
for a space event, opening its body ([keys.md](keys.md)) or holding it;
section 3.3, once it holds keys that hash to the event's `kc`; then it
updates its chain
evidence (section 3.5) and gives the event to its kind's checks. The kinds'
procedures that read across logs run in canonical order over the events
accepted in full ([roster.md](roster.md), "Checks across logs").

### 3.11 Cuts

A **checkpoint** is a space event, other than a genesis, whose roster part
is of type 2 ([roster.md](roster.md), "Checkpoints"). Only a replica that
opens a space event knows whether it is one. No other kind is a
checkpoint: a device-list event never carries cuts, and a device list's
own checkpoints are declared in its body ([identity.md](identity.md)). An event's `cuts` name the checkpoints it
follows, so that any party reads from an event's envelope alone which
checkpoints are in its past, without holding that past.

- **Order among checkpoints.** Checkpoint `x` is **at or before**
  checkpoint `y` when `x = y`, or `x` is among the checkpoints `y`'s cuts
  reach. The checkpoints an event's cuts **reach** are its cuts and, for
  each, the checkpoints that checkpoint's cuts reach.
- **What an event declares.** An event's `cuts` are exactly the maximal
  checkpoints, under that order, among its parents that are checkpoints
  and the cuts its parents declare; absent when there is none. An event
  whose `cuts` differ is void (`BadCuts`). The check runs after placement,
  as a verdict on a placed event, once the replica holds or has fetched
  each parent and opened each parent that is a space event; until then the
  event is pending. Fetching a parent to read its envelope and body is not
  placing it.
- **A parent held as a stub** ([units.md](units.md), "Stubs") contributes
  the cuts its stub carries; a stub of an event that declares cuts carries
  them. Until the replica holds a stub with them or the event, the check is
  pending. A holder of both a stub and its event compares the stub's cuts
  with the event's (`BadStub`, [units.md](units.md)).
- **A parent the replica dropped** after a checkpoint took effect is in
  that checkpoint's past, so all it could contribute is at or before the
  checkpoint, which the event's other parents reach: it contributes
  nothing, and the check never waits for it ([roster.md](roster.md),
  section 3.15.6).
- **Ordering needs envelopes.** To order two checkpoints a replica reads
  the cuts of the later one, and so on down. A replica therefore keeps the
  envelope of every checkpoint its kept checkpoint's cuts reach, even after
  it forgets the rest ([roster.md](roster.md), section 3.15.6), and a space
  snapshot hands a newcomer those envelopes. A check that needs the
  envelope of a checkpoint the replica neither holds nor keeps is pending
  until it fetches it. That wait always ends: a checkpoint a placed
  parent is or declares is in that parent's causal past, so the replica
  holds it, dropped it, or fetches it while placing the parent; one that
  is in none of these is in no parent's past, the parent's cuts are wrong
  (`BadCuts`), and the ID reaches nothing ([roster.md](roster.md),
  section 3.15.6).
- **Following.** An event **follows** checkpoint `c` when its cuts reach
  `c`. Whether it does is read from its envelope alone, and a peer reads it
  too. A skeleton twin cites, besides skeleton events, the checkpoints its
  roster event follows, and declares the same cuts ([peers.md](peers.md),
  "What replicas check").
- At most 4 cuts: a client that would declare more first waits for one of
  the checkpoints it follows to take effect or be voided
  ([roster.md](roster.md)). An honest event declares one, or two while
  concurrent checkpoints are proposed.

## 4. Security considerations

- **Cuts are checked, never trusted.** An event's cuts follow from its
  parents', so a replica that holds the parents finds any wrong declaration
  (`BadCuts`), whatever it holds of their past. A declaration only tells a
  replica which events it can judge without the history before a
  checkpoint; it changes no verdict a parent's own envelope does not.
- **One event, one ID.** An ID shared by two events, or two IDs for one
  event, would let a peer fake a fork or hide one. The ID hashes the whole
  map, `ed`, `kc` and the scheme included, and leaves out the signature;
  the CBOR is checked by re-encoding.
- **One author, one key set.** The author is the device ID, which commits
  to every key the author signs under, and the envelope carries what
  computes it. So a replica checks an event under keys it may take from
  anywhere, and nobody can attach a key of their own to another device by
  writing a record about it: such a record names another device ID.
- **`prev` is a parent,** so a verifier sees from the event alone that it
  follows its author's previous event. Otherwise an author could cite its
  previous event while leaving it out of the causal past, and whether that
  forked would depend on holding the whole history.
- **Nobody can be framed.** Evidence needs two events whose signatures
  verify under the author's keys, the keys its device ID commits to, and a
  second signature on one map makes no new event. Authority events need
  both halves of scheme 2, so a quantum adversary frames nobody with them
  (section 3.5). Before the classical sunset it can forge a scheme-0 unit
  under a device's own `ed` and `kc`, and a forgery at a used `seq` is
  evidence: evidence must not depend on the keys a replica holds, so the
  sunset must come first.
- **Logs share no order.** Refs name events of other logs without ordering
  them, so rules that cross logs hold pending what they cannot decide and
  never guess an order. Administer never comes from another log, so roster
  resolution reads no other log.
- **What the chain does not do.** It makes every fork provable, and it
  bounds a backdating author to what the author saw after its own last
  event. It does not bound an author that stays silent, which is why the
  backdated duel stays ([overview.md](overview.md), "Events and how they
  merge"; [rationale.md](rationale.md)).
- **Withholding.** A peer can withhold a log's events, including a restored
  device's own later events. Signed heads let a client detect withholding of
  events it knows about ([units.md](units.md)); section 3.8 keeps an honest
  restore from forking unless every peer it asks withholds.

## 5. Test vectors

[events.json](vectors/events.json), from `reference/events.py`. The example
devices' ML-DSA-65 seeds are [crypto.md](crypto.md)'s fixture derivations
from their identity seeds.

- `parameters`: the kinds, which must be understood and which are
  ignorable, the limits and the signature lengths; the identity seeds of the
  example devices.
- `encodings`: seven events of one log, byte for byte, with the map, `tbs`,
  the signature, the signed event and the ID: a genesis space event under
  scheme 2, a unit under scheme 0, another device's first event, a third
  event of the founder, a space event with two parents, an event of an
  ignorable kind, and an anchor. Each case gives the author's `kc` and
  device ID, and each scheme-2 case the author's ML-DSA-65 and X-Wing keys
  and both halves' messages. Bodies are opaque here. Signing must reproduce
  each byte for byte.
- `refusals`: thirty-five signed events, each with the class of section
  3.1 or 3.3 it must get: a trailing byte; a head not in its shortest form;
  an outer array of three; version 2; an unknown key; scheme 0 written out;
  schemes 1 and 3; signatures of the wrong length, for scheme 0 and scheme
  2; kinds 0, 3, 7 and 128; `seq` 0; a log of 31 bytes; parents out of order
  and repeated; cuts at envelope key 7 that are not event IDs; no `kc`; a `kc` of 31 bytes; no parents
  outside a genesis; a unit with no log; `seq` 2 without `prev`; `prev`
  outside the parents; a space event under scheme 0; an anchor with a body;
  an `ed` of small order; a changed body; a changed `kc`; an unreduced `S`;
  no keys held that hash to `kc` (`NoHybridKey`); each half of a scheme-2
  signature changed; and an event under this device's `ed` and `kc` whose
  ML-DSA-65 half another device's key made (`BadSignature`).
- `causal_order`: the log's IDs, heights, heads and canonical order, and
  every pair of its events as before or concurrent.
- `chains`: ten histories, each with its devices' identity seeds, its
  events, its evidence and its fork points: an honest chain; a restore that
  writes before it syncs; a restore that fetches its latest `seq` first; a
  skip forward; a `prev` at the same `seq`; a `prev` naming another
  device's event; one map signed twice by a deterministic signer; one map
  signed again with another nonce; a second unit at a used `seq` that the
  replica cannot open, which is still evidence; and two events at one
  `seq` that carry one Ed25519 key under two `kc`, which are two authors
  and no fork.
- `equivocation_proofs`: seven proofs, each with the identity seeds of its
  history's devices, and their result: a duplicate; a skip; an honest link;
  a duplicate with the larger ID first; two events at different `seq` given
  as a duplicate; a proof whose second event changed; and type 3.
