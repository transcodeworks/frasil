# Roster
Protocol 1. Vectors: [roster.json](vectors/roster.json).

This document specifies a space's membership: the roster part that a space
event carries, members, levels and capabilities, the space descriptor and
the space policy, the roster at a place, grants of spaces and effective
membership, how replicas resolve concurrent roster events, when key events
and units are valid, checks across logs, and what replicas derive from the
result. It depends on [overview.md](overview.md) for conventions, error
classes and timers, [crypto.md](crypto.md) for signatures and labels,
[events.md](events.md) for the envelope, chains and canonical order,
[identity.md](identity.md) for device lists, and [keys.md](keys.md) for the
space event's body, key states and rotations.

## 1. Overview

- A space's log holds its **space events** (kind 2). Each has a visible part
  and a sealed part ([keys.md](keys.md)). A **roster event** is a space event
  whose sealed part holds a **roster part**: the genesis, or an **update** of
  1 to 256 changes. A **key event** holds none. Only a replica that opens the
  sealed part knows which it is.
- Nobody orders the roster. Administering devices may change it while apart,
  so roster events branch. Every replica runs one resolution procedure over
  the events it holds and reaches the same valid set and the same roster, in
  whatever order the events arrived. No clock takes part.
- The **place** of an event is the set of valid roster events in its past,
  with the genesis. Every rule that asks whether a member is in, and at what
  level, asks it of the roster at the event's place (section 3.2).
- **Authority.** A roster event needs its author's device at `administer`
  at its place. A key event or a unit needs `write`, through the author's
  own device member, a person whose list holds it, or a granted space it
  reaches.
- **Concurrency.** A removal beats the removed member's concurrent actions
  and any concurrent grant of it. A demotion beats the demoted member's
  concurrent roster actions. An event that only lowers its own author is
  never voided by concurrency. When two administrators remove or demote each
  other, both events stand, and neither voids what made the other an
  administrator. Any other cycle is settled for the most senior author.
- **Removal and writes are strict:** a unit concurrent with its writer's
  removal is refused. **Removal across logs is eventual:** a unit through a
  person or a granted space stands until a writer of this space responds to
  the end in the other log.
- Three verbs have one sense each. To **demote** a member is to give it a
  lower level. To **lower** a member is to remove or demote it. To **end the
  write** of a member is to remove it or demote it to `read`.

## 2. Formats

### 2.1 Members and levels

A **member reference** is a CBOR array `[type, id]` of an unsigned type and
32 bytes:

| Type | Member | ID |
|---|---|---|
| 0 | device | its device ID ([crypto.md](crypto.md), "A device's keys") |
| 1 | person | its person ID ([identity.md](identity.md)) |
| 2 | space | its space ID |
| 3 | invite key | reserved for [ext-invite-links.md](ext-invite-links.md) (section 2.3) |

Any other type is `Malformed`. A space never names itself. A **device
member** is a member of type 0; a **guest** is a device member granted with
`session` set ([ext-guests.md](ext-guests.md)); an **administrator** is a
device member at `administer`.

| Level | Code | Gives |
|---|---|---|
| `read` | 0 | the content key of each state the member is entitled to, and the read credential |
| `write` | 1 | also the upload seed; its units and key events are accepted |
| `administer` | 2 | also: its roster events are accepted |

`administer` is granted only to a device member, never with `session`
(`AdministerNotDevice`). A roster, a device list and another space's roster
share no causal order: if `administer` could come through a person or a
space, replicas holding those logs at different heads would void different
roster events and diverge. An administrator's own devices grant
`administer` to its new devices.

A grant **propagates** unless it carries `session`. Only members whose grant
propagates hold the space's grant key, and only they reach the spaces that
grant this one (section 3.3).

### 2.2 The roster part

The roster part is a deterministic CBOR map, carried as a byte string at
inner key 16 of a space event's sealed part ([keys.md](keys.md)).

**The genesis** is the space event with no `log`. Its event ID is the space
ID, and its author's device is the **founder**. It rotates, and its roster
part is:

| Key | Field | Type | Value |
|---|---|---|---|
| 0 | `type` | unsigned | 0 |
| 1 | `founder` | map | a change (section 2.3): op grant, member `[0, author]`, level `administer`, rank 255, history 1, `via` 3, the author's Ed25519, X-Wing and ML-DSA-65 keys; no `session`, capabilities or label |
| 2 | `duel_policy` | unsigned | 0: ranks decide, and in a mutual pair of equal ranks the more senior stands (section 3.5.2) |
| 3 | `policy` | bytes | the space policy (section 2.6) |
| 4 | `descriptor` | bytes | the space descriptor (section 2.5) |
| 5 | `system_stream` | bytes(16) | the system stream's ID: 16 random bytes, not all zero, drawn by the founder ([units.md](units.md)) |

- `duel_policy` 0 is the rule of ranks of section 3.5.2; there is no rule in
  which a mutual pair both stand. Every other `duel_policy` is reserved. A replica refuses a genesis
  whose duel policy it does not know (`UnknownPolicy`), so a client never
  merges a space by rules other than its members'.
- The genesis needs no authority: it makes its author the founder.
- The genesis cannot name the space ID, which is its own hash. Its wraps,
  sealed part and body key bind its visible `nonce` in place of the log
  ([keys.md](keys.md)).
- The genesis names no twin. Its skeleton root is signed after it, and is
  found by [peers.md](peers.md)'s check of the founder's signature.
- The system stream ID is sealed: to a peer it is one more stream ID.

**An update** has key 0, `type` = 1, and key 1, `changes`: an array of 1 to
256 changes, of which at most 64 grant a device. Nothing else.

**A checkpoint** has key 0, `type` = 2; key 1, `epoch`, an unsigned of at
least 1; key 2, `digest`, bytes(32); key 3, `size`, the record's length in
bytes, at most 268,435,456 (`TooLarge`); and key 4, `locator`, bytes(64), the
locator of the object that holds the record of section 2.8 ([units.md](units.md),
"Objects"). Nothing else. The record's `epoch` is key 1.

```text
digest = SHA-256("frasil/checkpoint-record/v1" || record)
```

A checkpoint rotates, carries no refs (inner key 18) and no changes, and is
never a genesis. Its meaning is section 3.15's.

**Types from 3** are reserved for later documents. A replica that does not
implement the document that defines one holds the event as
`ExtensionRequired` and with it every event of the log outside its past
(section 3.16). Any other value of key 0 is `Malformed`.

### 2.3 Changes

A change is a deterministic CBOR map:

| Key | Field | Type | Value |
|---|---|---|---|
| 0 | `op` | unsigned | 0 grant, 1 change, 2 remove, 3 policy, 4 succeed (reserved) |
| 1 | `member` | member reference | |
| 2 | `level` | unsigned | 0 to 2 |
| 3 | `capabilities` | array | 1 to 32 pairs `[name, mode]`: a name of 1 to 64 bytes of UTF-8, and a mode, 0 extends or 1 narrows; strictly ascending by name |
| 4 | `label` | text | 1 to 64 bytes of UTF-8 |
| 5 | `history` | unsigned | 0 from now on, 1 with history |
| 6 | `via` | unsigned | 0 code, 1 link, 2 lookup, 3 none |
| 7 | `session` | bytes(16) | the session a guest belongs to |
| 8 | `replaces` | bytes(32) | the person ID a granted person replaces (section 3.13) |
| 9 | `exchange_hybrid` | bytes(1,216) | the device's X-Wing key |
| 10 | `mldsa` | bytes(1,952) | the device's ML-DSA-65 key |
| 11 | `policy` | bytes | the whole new space policy (section 2.6) |
| 12 | `ed25519` | bytes(32) | the device's Ed25519 identity key (section 2.4) |
| 13 | `expires_at` | unsigned | an instant for administering devices ([ext-guests.md](ext-guests.md)) |
| 14 | `claims` | unsigned | reserved |
| 15 | `rank` | unsigned | 0 to 255: an administrator's rank (below); the larger outranks |

Which keys each change carries ("req" required, "opt" optional; blank means
absent):

| Change | 1 | 2 | 3, 4 | 5, 6 | 7 | 8 | 9, 10, 12 | 11 | 13 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|
| grant of a device | req | req | opt | req | opt | | req | | opt, only with 7 | exactly with level `administer` |
| grant of a person | req | req | opt | req | | opt | | | | |
| grant of a space | req | req | opt | req | | | | | | |
| change | req | opt | opt | | | | | | | exactly with level `administer` |
| remove | req | | | | | | | | | |
| policy | | | | | | | | req | | |

- **A grant** admits a member. A device grant carries the keys that wraps
  are sealed to and that its signatures verify under, which its member ID
  commits to (section 2.4).
- **A change** sets the level, the capabilities or the label of a member in
  the roster, and carries at least one of keys 2, 3 and 4. History, `via`
  and `session` stay as granted.
- **A remove** ends a member.
- **Ranks.** Every administrator holds a **rank**, 0 to 255, set by the
  grant or change that makes it an administrator and carried in key 15,
  which is required there and absent beside any other level (`Malformed`);
  applications name ranks (owner, administrator, moderator) as they choose.
  The founder holds 255. A rank never changes in place: to give an
  administrator another rank, an administrator lowers it below
  `administer` and raises it again, two events (`RankInPlace`, section
  3.6). Section 3.6 lets no member act on an administrator of a higher
  rank than its own, or give a rank above its own; between equal ranks,
  the more senior stands in a duel (section 3.5.2). Readers and writers
  have no rank, and an administrator of any rank grants, changes and
  removes them.
- **A policy change** replaces the space policy. An event carries at most
  one.
- `administer` on a person, a space or a guest, by grant or change, is
  `AdministerNotDevice`: a grant alone (section 3.4.1), and a change of a
  guest at its place (section 3.6), since a change carries no `session`.
- One event names each member at most once. A key outside its row, a missing
  required key, or a value outside its type is `Malformed`.
- Capability names and labels hold no control character (Unicode category
  Cc) and are not only white space (`Malformed`). They are compared byte for
  byte.
- **Capabilities** are application-defined names that extend or narrow a
  grant; adapters register the checks, which every replica runs on what it
  decrypts ([units.md](units.md)). Names that begin `frasil.` are reserved
  for Frasil's documents; an application defines none. A replica merges
  every capability by its mode, whether or not it knows the name. A
  reserved name it does not know, from a document it does not implement,
  it keeps and merges the same way, refuses no event for and acts on in
  no other way. A client signs a reserved name only where a document it
  implements sets it, with the mode that document gives, such as
  `frasil.nothing-at-rest` in [ext-guests.md](ext-guests.md)'s guest
  preset, or where a change carries it over from the member's state at
  the client's view; it refuses any other one an application asks for.
- **A label** and **`via`** are shown, never checked. A client shows a
  member admitted by `lookup` as unverified until a code is compared
  ([admission.md](admission.md)).
- **History.** A grant "with history" entitles the member to earlier keys; a
  grant "from now on" does not, and is a **break** ([keys.md](keys.md)).
  Clients default to "with history" for a person, and to "from now on" for a
  device member and a guest.
- **`expires_at`** is never compared with a clock by a replica. Administering
  devices end the grant by a signed removal ([overview.md](overview.md),
  section 6.1). A core implementation checks its type and otherwise ignores
  it.

**Reserved for [ext-invite-links.md](ext-invite-links.md):** member type 3,
op 4 (`succeed`), change key 14, change key 13 on a grant of type 3, the
authority of a successor, and attack (d) (section 3.5). Ops from 5 are
`Malformed`. A core implementation that lacks the extension MUST NOT sign a
change that uses any of them. It holds a roster event that carries one as
`ExtensionRequired`, with every event after it, exactly as it holds an event
it cannot open (section 3.9). It never judges such an event valid or void,
so it never contradicts a replica that implements the extension.

### 2.4 A device's keys

A device grant carries the device's three public keys: key 12, its Ed25519
key; key 10, its ML-DSA-65 key; and key 9, its X-Wing key. They give the
grant's member ID:

```text
member ID = SHA-256("frasil/device-id/v1" || key 12
                    || SHA-256("frasil/device-keys-commitment/v1"
                               || field(key 10) || field(key 9)))
```

That is the device ID of the three keys ([crypto.md](crypto.md), "A
device's keys"). A grant whose keys give another ID is `NotCommitted`.

- So a grant names exactly the keys its member ID commits to. No granter
  can name a device with a key of its own: keys of its own give another
  device ID, which is another member, and every replica checks the
  device's signatures only under keys that hash to the device's own `kc`
  (section 3.4.2).
- A device's keys are the same in every grant of it, in every space and in
  its person's list, since one device ID commits to one key set. No two
  grants of one device can disagree on its keys.
- A grant carries no proof that the device holds the private keys. It needs
  none for the space's safety: a device ID whose keys no single party holds
  signs nothing and opens nothing (section 4). That the device ID is the
  device the granter means rests on how the granter learned it: an
  admission code, which commits to it, a list `add`, whose possession
  proof binds the keys to the person, or a roster it reads
  ([admission.md](admission.md); [identity.md](identity.md)).

### 2.5 The space descriptor

A deterministic CBOR map, carried as a byte string at key 4 of the genesis's
roster part. It never changes.

| Key | Field | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `kind` | 1, a restricted space; 2, a carve-out; absent for an ordinary space |
| 3 | `parent` | bytes(32): the parent's space ID, present exactly when key 2 is |
| 4 | `application` | text of 1 to 255 bytes: what kind of space the application made it, such as `"notes"`; optional |

Kinds 1 and 2 are [ext-restricted-spaces.md](ext-restricted-spaces.md)'s.
Descriptor kinds from 3, and descriptor keys from 5, are reserved for later
documents. A replica that does not implement the document that defines one,
once it has read the descriptor, checks nothing more of it, holds every
event of the space after the genesis as `ExtensionRequired`, signs nothing
in the space, and tells the application that the space needs a version it
lacks, as a core implementation does for a restricted space. At every
implementation, an edge of the grant graph to such a space never counts
(section 3.3), so a later kind never widens who reaches a space. A peer
judges no descriptor: it travels sealed, and the space is an ordinary one
to the peer.
`application` is the application's own: the protocol never reads it beyond
its shape. It travels in the genesis's sealed roster part, so members read
it and a peer does not, and like the rest of the descriptor it never
changes.
A core implementation that lacks the extension treats a carve-out as an
ordinary space. It does not use a restricted space: once it has read the
descriptor, it holds the space's other events as `ExtensionRequired`. Every
implementation applies the grant-graph rule for restricted spaces
(section 3.3).

### 2.6 The space policy

A deterministic CBOR map, carried as a byte string at key 3 of the
genesis's roster part and at key 11 of a policy change.

| Key | Field | Default | Used by |
|---|---|---|---|
| 1 | `version` | 1 | |
| 2 | `agent_waiting_period` | 259,200 | [ext-recovery-agent.md](ext-recovery-agent.md) |
| 3 | `bounded_window` | absent: off | [ext-guests.md](ext-guests.md) |
| 4 | `online_freshness` | absent: off | [ext-guests.md](ext-guests.md) |
| 5 | `gap_key_timeout` | 604,800 | refused units' content (section 3.14); a restored member's gap keys ([keys.md](keys.md)) |
| 6 | `forbid_agents` | absent | 1: the space admits no person whose list holds a recovery agent ([ext-recovery-agent.md](ext-recovery-agent.md)) |

- A value is written only when it differs from its default, so a policy has
  one encoding. Keys 3 and 4 have no default: absent means off, and any value
  in range means on with that value.
- Ranges are [overview.md](overview.md)'s, section 6.8. A core
  implementation that lacks an extension still checks, carries and merges
  that extension's fields.

Reading a descriptor or a policy, in order:

1. Deterministic CBOR, a map with an unsigned key 1. Else `Malformed`.
2. Key 1 is 1. Else `UnsupportedVersion`.
3. A descriptor: every key an unsigned integer; key 2, when present, an
   unsigned integer from 1. A key 2 from 3, or a key from 5, is a later
   document's: an implementation that lacks it reads nothing more, and
   holds the space (above). Otherwise keys 1 to 4 only; key 3 present
   exactly when key 2 is, and 32 bytes; key 4, when present, text of 1 to
   255 bytes. A policy: keys 1 to 6 only,
   each an unsigned integer that `check_policy` accepts
   ([overview.md](overview.md), section 6.7) and that is not its default;
   key 6 equal to 1. Else `Malformed`.

### 2.7 Labels and limits

Labels used, from [crypto.md](crypto.md)'s registry, which gives roster.md
`frasil/roster/seniority/v1` (section 3.2) and
`frasil/checkpoint-record/v1` (section 2.2). Section 2.4 also uses
crypto.md's own `frasil/device-keys-commitment/v1` and
`frasil/device-id/v1`, as crypto.md defines them.

| What | Limit | On excess |
|---|---|---|
| Changes per update | 256 | `Malformed` |
| Device grants per update | 64 | `Malformed` |
| Capabilities per grant or change | 32, names of 1 to 64 bytes | `Malformed` |
| A label | 1 to 64 bytes | `Malformed` |
| Valid roster events in an event's place, itself included, counted from the checkpoint in effect in its past (section 3.15) | 4,096 | `Full` |
| Undecided contested events for the agreement step | 16 | the step is skipped (section 3.7) |
| Spaces on a chain of counted grants | 8 | `GrantTooDeep` (section 3.3) |
| A space event; parents; refs | [events.md](events.md)'s limits | `TooLarge` |

- A device grant carries about 3.2 KB of keys. 64 of them leave room for a
  rotation's wraps within a space event's size limit. A client that admits
  more devices at once splits them over several events.
- The 4,096 bound counts only valid roster events, so nobody fills a place
  with events it had no authority to sign. In the world of a checkpoint it
  counts the checkpoint and the valid roster events after it (section
  3.15.4), so it bounds each epoch, not the space's life. An event held unopened is in no
  place, and key events never count.
- Neither bound counts a roster event whose author has no standing in its
  past (section 3.7): it is not contested, so it is never undecided and
  never valid. Only an author that some event in its past made an
  administrator can add to the contest.
- A device that holds more heads than an event may cite, and needs them all
  in a removal's past, first writes an anchor over the excess
  ([crypto.md](crypto.md), section 3.9), then cites the anchor.
- A space event SHOULD cite as parents every maximal space event its author
  may cite ([events.md](events.md), section 3.4), so that a partial replica
  orders space events without fetching the paths between them
  ([units.md](units.md), section 3.15).

### 2.8 The checkpoint record

The record a checkpoint carries is a deterministic CBOR map: the roster,
policy, chain tips and fork points of the checkpoint's own past, as
section 3.15.3 derives them, so that a replica that holds nothing before
the checkpoint judges what follows it as one that holds everything.

| Key | Field | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `epoch` | 1 for a checkpoint whose past has none in effect; otherwise one more than its predecessor's |
| 3 | `previous` | bytes(32): the predecessor, the checkpoint in effect in its past; present exactly when `epoch` > 1 |
| 4 | `members` | array of member entries, one per member in at the checkpoint's past, strictly ascending by the bytes of their member references |
| 5 | `policy` | bytes: the merged space policy (section 2.6) |
| 6 | `tips` | array of `[author (bytes 32), seq, event ID (bytes 32)]`, strictly ascending by author: each author's greatest `seq` there, the smaller ID on a tie |
| 7 | `forks` | array of `[author (bytes 32), seq]`, strictly ascending by author: each author's fork point there; possibly empty |
| 8 | `heard` | array of `[device ID (bytes 32), [epoch, height, grant], rank, Ed25519 key, ML-DSA-65 key, X-Wing key]`, strictly ascending by device ID: each member the checkpoint hears (section 3.15.4), with its seniority (the most senior of its seniorities at the places of the events that lowered it), as key 9 of a member entry writes it, its rank there (the highest), and the keys that give its device ID; present exactly when there are some |

`heard` reads as `members` does: deterministic CBOR, the types above
(`Malformed`), each key valid (`InvalidKey`) and giving its device ID
(`NotCommitted`).

`members` holds one entry per member in at the merged roster of that view,
and one per invite key out only by valid successors there, which no close
has removed yet ([ext-invite-links.md](ext-invite-links.md)).

A **member entry** is a map:

| Key | Field | Value | Present |
|---|---|---|---|
| 1 | `member` | the member reference, of type 0 to 3 | always |
| 2 | `level` | as section 2.3 | always, but for a claimed invite key |
| 3 | `capabilities` | as a change carries them | when the state has some |
| 4 | `label` | as section 2.3 | when the state has one |
| 5 | `history` | as section 2.3 | always, but for a claimed invite key |
| 6 | `via` | as section 2.3 | always, but for a claimed invite key |
| 7 | `session` | bytes(16) | when the state has one |
| 8 | `replaces` | bytes(32) | a person's, when its state has one |
| 9 | `seniority` | `[epoch, height, grant]` of the member's most senior grant in force (section 3.2), `grant` its event ID (bytes 32) | always, but for a claimed invite key |
| 21 | `rank` | the administrator's rank, 0 to 255 (section 2.3) | exactly at `administer` |
| 10, 11, 12 | keys | the Ed25519, ML-DSA-65 and X-Wing keys, which give the member ID (section 2.4) | exactly for a device member and an invite key |
| 13 | `slot` | `[c, index, maker, pseudonym]`: the reference of the administrator slot the skeleton holds for this device that is in, the most senior of several, and the device ID, bytes(32), of the pseudonym enrolled in it, or empty bytes when none is ([peers.md](peers.md), "Storage events") | an administrator for which the skeleton holds such a slot |
| 14 | `expires_at` | unsigned | a guest's state that has one; an invite key's, always |
| 15 | `claims` | 0 or 1, as the invite grant's | exactly for an invite key |
| 16 | `invite` | 0 open, 1 claimed, 2 raced, 3 used (below) | exactly for an invite key |
| 17 | `claimant` | the member reference its valid successor granted | exactly with `invite` 1 |
| 18 | `notices` | array of `[rotation, grant_public, break, author]`: bytes(32), bytes(1,216), 0 or 1, bytes(32), strictly ascending by their encoding (below) | a space member, when there are some |
| 19 | `floor` | 1 (below) | a space member, when it has one |
| 20 | `named` | array of event IDs of the granted space, strictly ascending (below) | a space member, when there are some |

- **A member's state** is section 3.2's at the merged roster of the view.
  `expires_at` comes with `session`: from the grant whose state gives the
  session, as section 3.2's meet takes `session`; a claimant takes its
  invite's ([ext-invite-links.md](ext-invite-links.md)).
- **An invite key's status**, from its successors in the view: 1,
  **claimed**, when a valid successor of it is there (it is then out, and
  its entry has keys 1, 10, 11, 12, 16 and 17 only); else 2, **raced**,
  when a successor of it is void as `ClaimRaced`; else 3, **used**, when
  any other successor of it is there; else 0, **open**.
- **A granted space's notices** are those for it carried by valid events of
  the view, except a notice whose carrying event another valid event of the
  view carrying a notice for that space follows; `author` is the carrying
  event's author. They decide nothing in the view: a replica that holds
  the granted space's log checks them in the checkpoint's world as
  [keys.md](keys.md), section 3.4, checks any notice.
- **A floor** is set when a valid event of the view carries a notice for
  that space with key 4: this space responded to a "from now on"
  admission in the granted space, so some device of the granted space is
  entitled here only from that response ([keys.md](keys.md), section 3.7).
- **Named** are the granted space's event IDs that the sealed refs of valid
  events of the view name. A notice admits a principal only if its
  rotation has in its past every rotation of the granted space that a
  valid event names ([keys.md](keys.md), section 3.4, step 4), and which
  of them are rotations, and in whose past, only the granted space's log
  tells, so the record keeps every name: without them a notice that was
  stale before the checkpoint would admit its principal after it. They
  cost 32 bytes per event of the granted space that this space ever
  responded to, carried from record to record.

Every field but keys 18 to 20 of a space member's entry is derived from
the view alone: roster events never wait on another log, and neither do
successors, tips or forks, so every replica that holds the view derives
them alike. Keys 18 to 20 read which key events of the view are valid,
and a key event's validity can read another log (a path through a granted
space or a person, roster.md section 3.11), so a replica that lacks that
log may derive them otherwise. Section 3.15.2 therefore compares the
record without them, and they rest on the votes: an administrator votes
only for a record whose keys 18 to 20 it derives too (section 3.15.7).

Reading a record, in order:

1. Deterministic CBOR, a map with an unsigned key 1. Else `Malformed`.
2. Key 1 is 1. Else `UnsupportedVersion`.
3. A key from 9 of the record, a key from 22 of a member entry, or a
   member reference of a type from 4 is a later document's: at an
   implementation that does not implement it, `ExtensionRequired`
   (held), and nothing more is read.
4. Keys 1 to 7, and key 8 when present, with their types, `previous`
   present exactly when `epoch` > 1; `members`, `tips` and `forks`
   strictly ascending. Each
   member entry has exactly the keys its row and member type allow, with
   their types: levels, capabilities, labels, history and `via` as
   section 2.3 reads them, an invite key's level `read` or `write` and its
   `via` 1, `administer` only for a device member without `session`;
   `pseudonym` exactly 32 or 0 bytes; each `heard` row with the types of
   its table. Else `Malformed`. Then `policy` reads as section 2.6 reads
   a policy, with that class (`Malformed`, or `UnsupportedVersion` for a
   policy of another version).
5. Each device member's, invite key's and heard member's Ed25519 and
   X-Wing keys valid ([crypto.md](crypto.md), section 3.4). Else
   `InvalidKey`.
6. Each device member's and invite key's keys give its member ID
   (section 2.4), and each heard member's its device ID. Else
   `NotCommitted`.

**Reserved record keys.** Record keys from 9, member-entry keys from 22
and member types from 4 are reserved for later documents. A replica that
holds a checkpoint as `ExtensionRequired` by step 3 holds every event after
it too, never votes for it, never starts from it (section 3.15.6), and
tells the application that the space needs a version it lacks. An
extension that changes how a space's events are judged, a roster part of
a type from 3 among them (section 3.16), MUST set a record key of its own,
from 9, in the record of every checkpoint whose past holds an event that
uses it, and an implementation of the extension derives that key as it
derives the rest of the record (section 3.15.3). A replica that lacks the
extension, a newcomer starting from such a checkpoint included, then holds
the checkpoint instead of judging what follows it by the core's rules,
which it could otherwise do: the events that used the extension are in the
checkpoint's past, which it never sees.

A record names each member's keys, so it grows by about 3.2 KB per device
member or invite key and a few dozen bytes per person, or per space and
each of its notices about 1.3 KB: the 256 MiB bound holds about 80,000
device members, or far more persons. Nothing else bounds the record
object below that: an object's plaintext may reach 2^40 bytes
([units.md](units.md)), and only a library's quota
([ext-libraries.md](ext-libraries.md)) limits what its author can upload.
A replica reads the record to compare it (section 3.15.2, step 8) and to
start from it; at the bound that is 256 MiB of plaintext, which a reader
need not hold: it can read the record as the object's chunks open
("Reading it as it streams", below), building its members in the
ascending order they are written in.

**The record object.** The record always travels as an object, in one
form whatever the space's size:

- It is sealed as [units.md](units.md)'s objects are, chunked, under the
  checkpoint's own content key `k_R`, so every member that holds the
  checkpoint's state opens it. Its header's key reference is the
  checkpoint's self reference, `0x00 || author || u64be(seq)` of the
  checkpoint's envelope ([keys.md](keys.md), "Reading key names"), since
  the checkpoint's ID does not exist when the record is sealed.
- The checkpoint binds it twice: by the locator (the object's ID, a MAC of
  the plaintext under the state's object-ID key, and the SHA-256 of its
  stored bytes), and by `digest` and `size` over the plaintext.
- Its author uploads the object to the space's peers before it signs the
  checkpoint, and its skeleton cut names the locator, so peers keep it
  ([peers.md](peers.md), "Skeleton cuts").
- **Reading it**, in order: units.md's "Reading an object" under the
  locator, with `k_R` or with the record's object key handed over (a
  newcomer's, [units.md](units.md), "The space snapshot"), where after
  its step 4, before any chunk opens, the header's key reference is the
  checkpoint's self reference (else `BadCheckpoint`); then the
  plaintext's length is `size` and its digest `digest` (else
  `BadCheckpoint`: the locator binds that very object, so no other can
  repair it); then the record reads as above (that class), and its
  `epoch` is the roster part's (else `BadCheckpoint`). The class is the
  reading's; the checkpoint whose record does not read is `BadCheckpoint`
  (section 3.15.2, step 1), but for a record held for a later document's
  key (`ExtensionRequired`), and for an object or key the replica lacks
  (`Sealed`, "Without it" below): no object held, stored bytes that are
  not the object the locator names (units.md's step 0), no key, or an
  object key handed over under which a chunk does not open (step 6),
  since the fault may be the sender's key rather than the checkpoint's.
- **Reading it as it streams.** A reader MAY read the record as the
  object's chunks open, holding neither the plaintext nor the whole
  record, and MUST then give the verdict this order gives. Each step of
  reading a record is over the whole record, each before the next, so a
  fault of an earlier step stands over one of a later step wherever each
  lies in the plaintext: a record that uses a reserved key in its first
  member entry and is not deterministic CBOR in its last is `Malformed`;
  one malformed in its first entry that uses a reserved key in its last is
  `ExtensionRequired`; an invalid key in its last entry stands over keys
  that give another member ID in its first (`InvalidKey`). Every fault of
  the object's reading (units.md, section 3.3, step 0 above all), the self
  reference, `size` and `digest` stands over the record's, though the
  record's is found first. The reader acts on nothing it read of the
  record, neither the checkpoint's verdict nor its members nor its
  `previous`, until all of them have passed and the record has read to its
  end; what it built while reading is then the record, and otherwise it
  discards it.
- **Without it.** A replica that holds a checkpoint but cannot read its
  record, because it lacks the object or a key that opens it, holds the
  checkpoint as `Sealed`, with every event after it, and judges the rest as
  one that has not received them, as for any space event it cannot open
  (section 3.9). It fetches the object by its locator from the peers and
  members it syncs with. When the object arrives, late or not, it judges
  again.
- **Validity with the object.** Section 3.15.2's comparison is between the
  record read from the object and the record it derives from the
  checkpoint's past, both as the encoding of this section.

## 3. Procedures

### 3.1 The order of verification

A replica judges a space's log in this order, each step over what the
previous ones accepted:

1. Each event's envelope and placement ([events.md](events.md)).
2. For a space event, its visible part and its body, opened or held
   (section 3.4.1, steps 2 to 10).
3. Each signature, under keys that hash to its author's `kc`, from
   wherever the replica holds them (section 3.4.2).
4. The roster events, by the resolution procedure (section 3.7), with the
   twins the skeleton gives (section 3.8).
5. Each key event, once, in canonical order, by the write rule
   (section 3.10).
6. Each unit, anchor, writer request and event of an ignorable kind, by the
   write rule and section 3.12.

Other logs are read as the replica holds them, each already resolved by its
own rules: a person's list by [identity.md](identity.md), a granted space's
roster by this document. The result is a function of the events held in
this log and the logs it reads. Replicas that hold the same events agree.
Two that hold different heads of another log may disagree until they sync,
and neither has applied anything the other would refuse once it holds the
same events, except as eventual removal allows.

### 3.2 The roster at a place

**Member state.** Given a place `V`, the state of member `m`:

1. Take the events of `V` with a change naming `m`. Keep the **maximal**
   ones, those no other of them follows.
2. If any maximal one removes `m`, `m` is **out**.
3. Otherwise `m` is **in**, with the meet of the states its maximal changes
   give. A grant gives its own fields. A change gives `m`'s state at the
   change's own place, with the fields it sets replaced; its rank is the
   one the change sets when it raises `m` to `administer`, the one `m`
   held when it keeps `m` there, and none below `administer`.

A member never named is absent. Absent and out are both "not in".

**The meet** merges concurrent states of one member to the most
restrictive:

- `level`: the lowest;
- `rank`, at `administer`: the lowest;
- capabilities: an extending one stays only if every state has it; a
  narrowing one stays if any state has it;
- `history`: "with history" only if every state has it. This decides what
  the member is entitled to from then on; it takes back no key a branch
  already delivered;
- `session`: present if any state has it, with the value of the state whose
  event is first in canonical order, and that state's `expires_at`, if
  any (a guest's grant carries it; the checkpoint record keeps it);
- `label`, `via` and `replaces`: from the state whose event is first in
  canonical order;
- the **grants in force**: the union of the grants beneath each state;
- seniority: from the most senior grant in force. A device's keys are not
  merged: every grant of it carries the ones its member ID commits to.

**Seniority** is a total order over grants, smallest first:

```text
seniority(g) = ( height(g),
                 SHA-256("frasil/roster/seniority/v1" || space ID || member ID),
                 event ID of g )
```

- The founder's grant is the genesis, at height 0, so the founder is the
  most senior. Height extends the causal order, so a grant is junior to
  every grant in its past.
- The hash covers only the space ID and the grantee's ID, which the granter
  does not choose, so a granter cannot grind which of two grants at one
  height is senior. The event ID breaks the last tie: two grants of one
  device at one height.
- A member's seniority is that of its most senior grant in force.
- **Outranks.** Administrator `x` outranks administrator `y`, each at a
  given place, when `x`'s rank is higher, or the ranks are equal and `x` is
  the more senior. The founder outranks every other member. Sections 3.5.2,
  3.6, 3.7 and 3.15 compare authors and targets so.
- A partial replica resolves the roster only on heights it knows
  ([units.md](units.md), section 3.15).

**The space policy at a place.** Take the genesis and the valid policy
changes of `V`, keep the maximal ones, and merge them field by field to the
stricter value:

| Field | Merged value |
|---|---|
| `agent_waiting_period`, `gap_key_timeout` | the longest |
| `bounded_window`, `online_freshness` | the shortest of those set; off only if off in all |
| `forbid_agents` | set if set in any |

### 3.3 Grants of spaces and effective membership

**The grant graph.** A replica builds an edge `X → Y` for each grant of
space Y in force in the roster of X, over every roster it holds. Y's
members reach X through it. Which edges **count**, in order:

1. An edge to a space whose roster this replica does not hold is
   `UnknownSpace`: it takes no part in what follows, and a path through it
   cannot be judged (section 3.11). An edge to a restricted space never
   counts (`GrantOfRestricted`): a restriction is never widened. Nor does
   an edge to a space whose descriptor is of a kind from 3 or carries a key
   from 5 (`GrantOfReserved`, section 2.5), at every implementation,
   whether or not it implements the document that defines it. An edge
   from a space to itself never counts (`GrantCycle`).
2. **Cycles.** While some counted edges lie on a cycle, the one among them
   with the highest granting space ID stops counting (`GrantCycle`). Ties
   fall to the granted space's ID, then to the grant's event ID.
3. **Depth.** The remaining edges are taken from the roots of the graph
   down: nearest a root first, by the longest chain of counted edges above
   the granting space, then by lower granting space ID. Each is kept unless
   the longest chain of kept edges ending at X, plus the longest starting at
   Y, would pass 8 spaces (`GrantTooDeep`).

An edge that does not count delivers nothing: no device reaches X through
it, and X's rotations make no space wrap for Y. These verdicts refuse no
event. A client MUST NOT sign a grant that would, in its own view, close a
cycle, pass the depth, or make a counted edge stop counting. Space IDs, not
event IDs, decide cycles, because a space ID is fixed when the space is
made and a granter cannot grind it.

**Effective membership.** The effective membership of space X is every
device that reaches X, each with a level, whether it propagates there, and
its capabilities:

- **a device grant** in X's roster: that device, at the grant's level,
  propagating unless the grant carries `session`;
- **a person grant**: every device the person's list vouches for
  ([identity.md](identity.md)), at the grant's level, propagating;
- **a counted space grant `X → Y`**: every device that reaches Y **and
  propagates there**, at the lowest of X's grant of Y, its level in Y over
  the paths that propagate there, and `write`. It propagates in X.

Along one path, a narrowing capability on any grant of the path applies,
and an extending one applies only from the path's first grant, X's own. A
device that reaches X by several paths takes the highest level over them,
and the meet of the capabilities of the paths at that level. A guest
reaches only the space that grants it.

So a device has two levels in a space, kept apart: its highest over every
path, which is its level there, and its highest over the paths that
propagate there, which is what a counted grant of that space passes on,
with the capabilities of the propagating paths at that level. A path that
does not propagate passes on nothing, neither level nor capabilities,
even when it is the device's strongest or is at the same level as a path
that propagates: a device that is a guest at `write` in Y and reaches Y at
`read` through a person reaches X through `X → Y` at `read`, with that
person grant's narrowing capabilities and none of the guest's, and one
that is a guest at `write` and reaches Y at `write` through a person
reaches X at `write` with the person grant's narrowing capabilities only.
This is everything a device holds through a grant of a space: the paths
of the write rule and the capabilities its units are checked against
read it (section 3.11, "Paths"; [units.md](units.md), 3.17 "Capability
checks"). `administer` in X comes only from a device grant at
`administer` in X's own roster.
[ext-restricted-spaces.md](ext-restricted-spaces.md) narrows a restricted
space's effective membership by its parent's.

### 3.4 Checking a space event

#### 3.4.1 The event alone

In order:

```text
 1. The envelope and placement (events.md).                      else that class
 2. The visible part passes keys.md's checks. Key 13 is present
    exactly in a genesis; key 15 is absent from a genesis.         else that class / Malformed
 3. An event that does not rotate: every rotation its
    sealed_under names is in its past.                             else Malformed
 4. The body key (keys.md): a key derived from rotation keys that
    each matched their rotation's commitments, whose commitment
    equals key 14;                                                 else BadSeal
    otherwise a provisional key whose commitment equals key 14.    else Sealed (held)
 5. The sealed part opens under it, and passes keys.md's checks
    on the sealed part.                                            else BadSeal / that class
 6. Inner key 16, if present, is a map whose key 0 is 0, 1 or
    2, 0 exactly in a genesis; a genesis has key 16; key 15 only
    on an update or a checkpoint. A key 0 from 3 is held
    (section 3.16).                                                else Malformed / ExtensionRequired (held)
    A checkpoint: its keys as section 2.2, its size at most the
    bound; it rotates and carries no inner key 18.                else Malformed / TooLarge
 7. A genesis: its roster part as section 2.2, its founder
    change as section 2.3, its keys valid and giving its member
    ID (section 2.4), which is the genesis's author;               else Malformed / that class
    duel_policy 0;                                                 else UnknownPolicy
    its policy as section 2.6, then its descriptor as
    section 2.5;                                                   else that class
    it cites nothing: no inner key 18.                             else Malformed
 8. An update: as section 2.2, its grants of a device (op 0,
    member type 0) counted before any change is read.              else Malformed
 9. Each change: as section 2.3;                                   else Malformed
    administer only for a device member without session;           else AdministerNotDevice
    a granted device's Ed25519 and X-Wing keys valid
    (crypto.md, section 3.4);                                      else InvalidKey
    its keys give its member ID (section 2.4);                     else NotCommitted
    no reserved member type, op or key, at a core
    implementation that lacks ext-invite-links.md.                 else ExtensionRequired (held)
10. At most one policy change; replaces only beside a removal
    of the person it names.                                        else Malformed
    An event that removes its own author does not rotate.          else SelfRotation
11. The signature's ML-DSA-65 half, under keys that hash to
    the event's kc (section 3.4.2).                                else NoHybridKey (pending) / BadSignature
12. The author's fork point is above seq, or the event is
    self-lowering (section 3.5).                                   else Forked
```

- Whether an update names a twin in key 15 is section 3.8's, at its
  place; a checkpoint always names its skeleton cut there (section
  3.15.8), and one without key 15 is `TwinRequired`.
- In the world of a checkpoint in effect (section 3.15.5), step 3 also
  requires that every rotation `sealed_under` names be the checkpoint or
  an event after it in the event's past, else `StaleSeal`, read from the
  visible part alone.
- Steps 1 to 3 read nothing sealed; a peer runs them too. Step 11 runs on
  every space event that passes step 3, opened or not, so that its
  signature counts as chain evidence whatever keys the replica holds.
- An event that fails a step from 2 on is void with that class, and is not
  a rotation, except where the step holds it. A class from steps 5 to 10
  other than `BadSeal` stands whatever the signature. An event held at step
  4 or 9, or refused as `BadSeal`, whose signature fails is void as
  `BadSignature`.
- A self-removal does not rotate, because the leaver would hold the new
  key. It is sealed under the state it names, and another writer heals
  ([keys.md](keys.md)).
- A replica that cannot use the genesis, through step 11, cannot use the
  space. A genesis also waits for its skeleton root ([peers.md](peers.md));
  a space whose root fails is unusable (`BadTwin`).
- A genesis also passes [keys.md](keys.md)'s checks against the event and
  its place (section 3.3), with itself as its place, before anything else
  is judged; a genesis that fails them is unusable, as one whose root
  fails.

#### 3.4.2 An author's keys

A scheme-2 event's ML-DSA-65 half verifies under the ML-DSA-65 key that,
with an X-Wing key or none, hashes to the event's `kc`
([events.md](events.md), "The ML-DSA-65 half"). A replica takes such keys
from any source and checks them by their hash ([crypto.md](crypto.md), "A
device's keys"), such as:

- for the genesis, its founder change;
- for a skeleton event, the root or enrolment its pseudonym signed, whose
  `mldsa`, with no X-Wing key, hashes to the pseudonym's `kc`
  ([peers.md](peers.md));
- a grant of the author in this log, opened, valid or void;
- an `add` of the author in a person's list, or a grant of it in another
  space, whichever log the replica holds;
- an admission exchange, or keys it cached from any of these.

The source vouches for nothing. Only one ML-DSA-65 key hashes to a `kc`, so
a key from a void event or from another member's list is the author's key
or no key, and a record can never attach a key of its own to the author: a
grant or an `add` that pairs the author's Ed25519 key with other keys names
another device ID. Whether the signature verifies therefore depends on the
event alone, never on the roster's resolution; whether the author has
standing is the resolution's. An event whose author's keys the replica does
not hold is `NoHybridKey`: pending until a record, or any other source,
brings them. Whether the skeleton vouches for a pseudonym is
[peers.md](peers.md)'s, and decides whether its event is a valid twin, not
whether its signature verifies.

### 3.5 Attacks

#### 3.5.1 Self-lowering events

An event is **self-lowering** when each of its changes names its author's
own device member and removes it or lowers only its level below
`administer`. A self-lowering event is never attacked, and survives its
author's chain penalty ([events.md](events.md)): a fork never undoes its
author's own lowering. Two concurrent self-demotions both stand, and the
meet keeps the lower level.

#### 3.5.2 What attacks what

Roster event `x`, if valid, **attacks** roster event `e` when `x` and `e`
are concurrent, `e` is not self-lowering, and:

- **(a)** `x` removes `e`'s author's member (`RemovedConcurrently`);
- **(b)** `x` demotes `e`'s author's device member below `administer`
  (`DemotedConcurrently`);
- **(c)** `x` removes a member that `e` grants or changes
  (`TargetRemovedConcurrently`); or
- **(d)** reserved for [ext-invite-links.md](ext-invite-links.md).

The relation reads only the two events and their concurrency, never the
roster, so every replica computes it alike. A re-grant after a removal MUST
follow the removal; (c) voids a concurrent one.

An attack **counts** unless a rule of this section drops it. The rules read
only the contested events (section 3.7) and their causal order, never a
status, so they too are computed alike and depend on no outcome.

`x` and `e` **lower each other** when each attacks the other through (a) or
(b) and their authors differ. Under duel policy 0:

- **Mutual pairs.** Two events that lower each other with one change each
  are a **mutual pair**. In a mutual pair, the attack of `x` on `e` counts
  exactly when `x`'s author outranks `e`'s author (section 3.2), each at
  its own event's place: the outranking author's lowering stands and the
  other's is void. Section 3.6 already voids a lowering of a higher rank,
  so a mutual pair is one of equal ranks, and the more senior stands. The
  rule reads both authors' states at their places, so it waits until both
  places are decided, as section 3.7's step 1 waits for any attack. The
  winner still attacks its partner's other concurrent events. A removed
  administrator can sign a counter-removal whose parents leave out its own
  removal, and nothing tells it from a genuine mutual removal: it wins
  exactly when it outranks its remover, and then only that remover is out.
- **A lone change is spared by an event of several.** When `e` has one
  change and `x`, which lowers `e`'s author as `e` lowers `x`'s, has more
  than one, `x`'s attack on `e` does not count.
- **Neither undoes its partner's authority.** The **support** of a roster
  event is the contested events in its past that grant or change its
  author's member, with the support of each of them. No attack of `e`
  through (a), (b) or (c) counts against an event of `x`'s support that
  `x`'s author did not sign. So a counter-removal cannot void the grant or
  the raise that made its remover an administrator, even when the remover
  was not one yet at the counter-removal's place. Its remover's own events
  stay attacked, so a remover cannot shield what it did concurrently.
- **An event that lowers an administrator names nobody else**
  (`AdminAlone`, section 3.6). Otherwise a backdated "remove my remover, and
  everyone else" would stand beside its partner. A remover that was
  not yet an administrator at the event's place is held to the same: an
  event of more than one change is never spared by its partner (the rule
  above), so it is void wherever the event that lowers its author stands,
  and removes nobody. Two such events with more than one change each wait
  on each other, a cycle that section 3.7 settles.

### 3.6 Authority at the place

Run within the resolution procedure, once the event's contested past is
decided, with `S` the roster at its place:

```text
0. No roster event in its past is pending for its twin.        else Pending
1. The author's device member is in S at administer.           else NotAnAdministrator
2. For each change, in order:
   grant:   the member is not the author's device;            else SelfGrant
            the member is not in S;                            else AlreadyMember
            its rank, if any, is at most the author's.         else HigherRank
   change, remove: the member is in S;                         else NoSuchMember
            a change of the author's own device only lowers
            its level, with no capabilities or label;          else SelfChange
            a change to administer names a member whose
            state in S has no session;                         else AdministerNotDevice
            a member at administer in S, other than the
            author's device, has a rank at most the author's,
            and a rank the change sets is at most the
            author's;                                          else HigherRank
            a change to administer of a member already at
            administer in S keeps its rank.                    else RankInPlace
   policy:  nothing more.
3. With more than one change, none lowers a device member
   that is in S at administer.                                 else AdminAlone
4. At most 4,096 valid roster events in its place, itself
   included.                                                   else Full
5. keys.md's checks against the event and its place, with the
   context it derives from the event's changes and S.          else that class
6. The twin (section 3.8).                                     else TwinRequired / UnexpectedTwin /
                                                                    NoTwin (pending) / BadTwin
```

- No administrator raises itself, adds a capability to itself, relabels
  itself or grants itself; another administrator does that.
- A change carries no `session`, so only the roster at its place says
  whether it raises a guest (step 2). A guest stays one: a change keeps
  `session` as granted, and the meet keeps it if any concurrent state has
  it, at the lowest level, so no state of a member holds both `session` and
  `administer`. A device that was a guest is raised only after a removal
  and a re-grant without `session`.
- **Ranks.** The author's rank and the member's are their states' in `S`.
  So no member removes, demotes, marks dormant, relabels or otherwise
  changes an administrator of a higher rank, and no member grants or raises
  to a rank above its own; a lower rank can never remove a higher one,
  concurrent or not, since its event is void at its own place whatever
  happens beside it. Members below `administer` have no rank, and any
  administrator manages them. An administrator may lower itself whatever
  its rank (`SelfChange` allows lowering only). An invite key, a person and
  a space never administer (`AdministerNotDevice`), so no path through
  another log carries a rank.
- Step 4 applies to self-lowering events too.
- In step 5 the rotations of a roster event's place are the genesis and the
  roster events valid there: roster resolution never waits on key events.

### 3.7 The resolution procedure

**Standing.** The author of a roster event `e` has **standing** in its
past when the genesis, or a roster event in `e`'s past whose sealed part
passes section 3.4.1 through step 10, valid or void, has a change that
names `e`'s author's device member at `administer`: a grant at that level,
or a change that sets it. A successor's standing is
[ext-invite-links.md](ext-invite-links.md)'s.

The **contested** events of a view are its roster events, other than the
genesis, that pass section 3.4.1, are not held, and whose author has
standing in their past. Such an event whose author has no standing is void
before the procedure: `Pending` if a roster event in its past is pending
for its twin (section 3.8), otherwise `NotAnAdministrator`. It is never
undecided, attacks nothing, is in no event's support (section 3.5.2), and
counts toward neither bound of section 2.7.

The procedure decides each contested event valid or void:

1. **Propagate.** Repeat until nothing changes. Take, in canonical order,
   each undecided event `e` whose contested past is all decided:
   - if `e` fails its authority (section 3.6), it is void, with that class;
   - otherwise consider the events whose attacks on `e` count
     (section 3.5.2), leaving out void ones. If one is valid, `e` is void,
     with that attack's class. If none is undecided, `e` is valid.
2. If every event is decided, stop.
3. **Agree.** If at most 16 events are undecided, consider every
   assignment of valid or void to them, the decided events as they are. An
   assignment is **allowed** when each undecided `e` is valid in it exactly
   when its authority holds at its place under the assignment and no event
   valid under the assignment attacks it with an attack that counts. If at
   least one assignment is allowed, every undecided event that has the same
   status in all of them takes it. If any event was decided so, go to
   step 1.
4. **Rank, then seniority.** Among the undecided events whose contested
   past is decided, the one with the smallest `(255 − rank of its author's
   member at its place, seniority of that member, height, event ID)` is
   valid: the outranking author first. Go to step 1.

- An author without standing is not in at `administer` at the event's
  place under any assignment: a member's level there is the meet of the
  levels its valid changes give, each at most the one a change in that
  past sets, and a change that names no level keeps the level before it.
  So section 3.6 would void the event at step 0 or step 1 whatever the
  procedure decided. Leaving it out changes another event's verdict only
  where the event alone pushed step 3's count past 16, or extended a
  support with its author's grants.
  Standing reads only the event and its past, so every replica that holds
  the event reaches the same answer, and no later event changes it.
- Step 1 is the least fixed point of the rules, so the order of evaluation
  does not change it.
- Steps 3 and 4 run only when a set of events waits on itself: a cycle of
  attacks that count. Step 3 first settles what every allowed roster agrees
  on, so that an event void either way cannot steer the pick. Above 16
  undecided events, step 4 picks directly.
- Step 4 always finds an event: the earliest undecided event has a decided
  past, so its authority holds, or step 1 would have voided it.
- An event that step 3 voids stays void: no later step decides it again,
  even if at the end its authority holds and nothing attacks it. Its class
  is the one it has under the **first** allowed assignment of that step:
  the class its authority fails with there, or else that of the attack by
  the first event, in canonical order, that is valid there and attacks it
  with an attack that counts. Of two assignments, the first is the one that
  makes void the earliest event, in canonical order, on which they differ.
- [ext-invite-links.md](ext-invite-links.md) adds a rule for successors
  around this procedure; a core implementation holds them (section 2.3).

### 3.8 The twin

A roster event **changes who administers** when, at its place, one of its
changes grants a device `administer`, raises a device to it, or removes or
demotes a device that holds it. Such an event has a **twin**: the skeleton
event that mirrors it for peers, signed by the pseudonym of its author's
administrator slot before the roster event ([peers.md](peers.md)).

The roster event names its twin's event ID in visible key 15
([keys.md](keys.md)). The twin's commitment derives from the roster event's
body key and self reference, which depend only on its log, author and `seq`,
so the twin can be built first. Section 3.6, step 6, in order:

1. Key 15 is present exactly when the event changes who administers at its
   place. Missing, `TwinRequired`; present on any other, `UnexpectedTwin`.
2. The twin it names is held. Else `NoTwin`: the event is pending.
3. The twin passes [peers.md](peers.md)'s replica checks for a twin. Else
   `BadTwin`.

- **A lookup, not a choice.** The twin is the event key 15 names. A
  skeleton change some other pseudonym signs with the same commitment is
  never this event's twin.
- **Pending.** An event held for `NoTwin`, and every event after it, is
  judged as if this replica had not received it. In the procedure it
  attacks nothing, and a roster event with it in its past is `Pending`
  (section 3.6, step 0). The replica fetches the twin by its ID.
- **Void.** One device signs both events, so a bad twin is its author's own
  fault, as a wrong seal is.
- Under an assignment of section 3.7, step 3, the check is computed at the
  event's place under that assignment.

### 3.9 Space events a replica cannot open

A space event's authority is known only once it is opened. A replica that
cannot open one cannot judge it, nor what follows it.

- **Held.** A space event this replica cannot open (`Sealed`), holds for an
  extension (`ExtensionRequired`) or refuses as `BadSeal`, and every event
  with any of them in its past (`Pending`), is not accepted in full. The
  replica resolves the roster and judges writes over the remaining events,
  which are closed under the past, exactly as a replica that never received
  the held ones, except that their signatures still count as chain
  evidence. It never cites a held event. When the key arrives, the event
  and those after it are judged, as any late event is.
- **`BadSeal` is final for replicas that hold the state.** Only a body key
  derived from rotation keys that each matched their commitments can find
  `BadSeal`. Every such holder derives the same key and compares it with the
  same commitment, so all reach `BadSeal` alike. A key that cannot be
  checked so, a merged state's key received whole or a body key handed
  over, is **provisional**: a mismatch under it holds the event `Sealed`.
  Since honest members cite no void or held event, an author that seals
  under a wrong key loses its chain from there, as a fork does.
- **Verdicts reached under a provisional key are provisional.** A replica
  marks them so, and re-judges every event it opened with a provisional key
  once it holds the state or rotation keys that derive it. A replica handed
  two different keys for one event holds it `Sealed`.
- **Body keys for newcomers.** A member admitted "from now on", or a
  restored member that rejoins from a snapshot, holds only the rotations
  from its admission on, and must still judge the genesis, the roster it is
  admitted into and the writers it will see. Its snapshot MUST carry, for
  every space event the sender has opened and the newcomer could not open
  with the rotation keys it will hold, that event's body key, under the
  sender's signature ([admission.md](admission.md), [units.md](units.md)).
  A member that later opens a space event that such a member could not open
  MUST send it that event's body key.
- **A removed device** cannot derive the body key of the rotation that
  removes it. The rotation's removal wrap hands that body key to it
  ([keys.md](keys.md), "Bundle wraps, space wraps and removal wraps"), so
  it judges its own removal provisionally, as any replica judges an event
  under a handed key, and resolves a roster without itself. It holds every
  later event sealed under the new state `Sealed`.
- **A member left out of a rotation** notices when it fails to open the
  newest state it is entitled to: a valid rotation in its view whose key it
  lacks, or a space event sealed under such a state. It asks a member that
  holds the key for a delivery ([keys.md](keys.md)).

### 3.10 The write rule

A unit or key event `u` by device `d` needs `write`. Any device that holds
`write` at the event's place may sign a key event, a guest included, so
that the first informed writer can heal without waiting for an
administrator.

After section 3.4.1's envelope and signature checks (and, for a unit, its
seal opening, as [units.md](units.md) says), in order:

```text
0. Every ref u carries names an event this replica holds.       else Pending (held)
1. d's fork point is above u.seq.                               else Forked
2. The paths through which d writes at u's place (section
   3.11): at least one.                                         else NotAWriter
                                                                     (Pending if a path cannot be judged;
                                                                      Dropped, section 3.12)
3. A key event: not every path is waiting (below).              else WaitingDevice
4. Drop each path whose write a valid roster event concurrent
   with u ends. At least one left.                              else RefusedByRemoval
5. Drop each path through a person or a space that another log
   has ended for d (section 3.11), where some response does not
   have u in its past. For a key event, only responses decided
   valid before it count. At least one left.                    else RefusedAfterResponse
6. A key event: keys.md's checks against the event and its
   place.                                                       else that class
7. u is valid.
```

- **Step 0 holds only `u`** and the events after it. Nothing else waits for
  it, and it is never a response. A replica fetches what a ref cites, from
  its author first. A stranger that cites events nobody holds freezes only
  its own chain.
- **Step 4** applies to removals and to demotions to `read`, of a person or
  a space member as of a device: a member's writes concurrent with the end
  of its write are refused, so backdating gains nothing. A unit after a
  valid re-grant is judged at its place, which holds the re-grant.
- **Step 3.** A device rooted in a recovery agent signs no key event through
  a person grant until one of the person's own devices confirms it: a key
  event chooses a key, and a device inside the roster triggers no heal. Its
  units are accepted, because a unit chooses no key. A direct device grant
  lifts the rule for that path. A path is **waiting** when it is:
  - a person grant whose list holds `d` as rooted in a recovery agent and
    not confirmed ([identity.md](identity.md)); or
  - a space Y through which `d` reaches the space only by waiting paths:
    every path by which `d` reaches Y at `write` and propagates there, at
    Y's merged roster or at the place of any of its valid roster events
    (section 3.11), is waiting in Y by this rule.

  So a granted space lifts nothing that its own roster does not: a device
  that sits in Y only through its person's grant waits in X as in Y, and a
  device grant in Y, or in X, lifts the rule. Every replica decides it from
  the lists and rosters it holds, as it decides the paths.
- **Step 6.** For keys.md's flags, `me` propagates when a path left after
  step 5 is a person, a space, or `d`'s own device member without
  `session`, and the event responds when it carries sealed refs. The
  rotations counted are the genesis, the valid roster events and the key
  events decided valid before it. So a response that rotates is a grant
  rotation (`GrantKeyRequired`), which a guest may not sign
  (`GrantKeyNotAllowed`).
- **Order.** Roster events never depend on units or key events, so this
  runs after the procedure. **Key events first, once each, in canonical
  order:** a key event counts as responses only roster events and the key
  events decided valid before it. A pass repeated until nothing changes
  does not settle: two key events that each respond to the end of the
  other's author would refuse each other, then neither, then both. Then
  units, anchors, writer requests and events of ignorable kinds, against
  every valid response.
- A key event that only delivers is valid or void by this rule like any key
  event, but is not a rotation.

### 3.11 Checks across logs

**Paths.** Device `d` writes through member `m` of the roster at a place
when `m` is in at `write` or `administer` and:

- `m` is `d`'s own device member; or
- `m` is a person whose list holds a valid `add` of `d`, as a device or a
  passkey member ([identity.md](identity.md)); or
- `m` is a space through which `d` reaches the space at `write` and
  propagates (section 3.3), over that space's merged roster or its roster
  at any earlier valid place.

Capabilities come from the strongest path ([units.md](units.md), 3.17
"Capability checks"). Along a path through a granted space Y, this
roster's grant of Y gives the path's extending capabilities and caps its
level; from inside Y come what a counted grant of Y passes on (section
3.3): the narrowing capabilities of the device's paths that propagate in
Y, at its highest level over them. A guest (`session`) grant in Y passes
on nothing through Y, neither a path nor capabilities, narrowing or
extending (section 3.3). They are read at Y's merged roster as the
replica holds it while the device reaches Y there at `write` and
propagates; once it no longer does, at each earlier valid place of Y
where it did, merged as paths are, so the narrowing of any of those
places applies. So capabilities through Y follow Y's roster as it
changes: a member that Y narrows later, made a suggester
there, has its earlier direct edits through the grant refused as content
from then on, and a member that leaves Y keeps the narrowing it had where
it wrote.

**Attribution.** A unit valid by the write rule is **attributed** to the
paths section 3.10's step 2 finds at its place, through each person's list
as it stands there ("A list at an event's place", below), less each person
whose revocation of the device is at that place too, unless that would
leave none (the unit then stands on paths that revocations have reached and
no response has ended yet), each with its label in the roster at that place
when it has one there: at most 64, the first by type then ID. Everything it reads is fixed by the unit's own past,
so it is the same at every replica and never changes while the unit stands.
That is its author as the space knew it at its place, and a client shows
it so for every unit it holds: a label changed later, a member removed
since, a person whose list changed since, and a list that adds the device
after the unit or apart from it leave it as it was, and the current roster
and lists are never read for it. A path that a later end drops (steps 4 and
5) stays in the attribution while the unit stands: attribution says who the
space knew the author as, validity whether the unit stands. A unit whose
content its adapter refuses or holds waiting is attributed the same way. A
unit the write rule voids is attributed to no member: a client shows only
the device whose signature it carries. A replica that forgot the unit's
place shows what it froze there ([units.md](units.md), "The past of a kept
checkpoint").

A path that needs a list or a roster the replica does not hold cannot be
judged; if no other path holds, the event is pending: kept and fetched
for, never applied, never counted as refused and never cited.

**Refs.** An event's refs name events of other logs, sealed in its body
(inner key 18, [keys.md](keys.md); [events.md](events.md)). A roster event's
refs never hold it: until they resolve, it is no response and gives no known
past.

**Known past.** A roster event that grants or changes a person or a space
member SHOULD carry in its refs the heads of that member's log as its author
holds them. That past is the space's **known past** of the member: a device
revoked from the person's list, or gone from the granted space, in it never
writes through the grant. A grant that carries none gives no known past.

**A list at an event's place.** List events reach a space only as the
content of `frasil:list` units of its system stream ([identity.md](identity.md),
"Sealed list copies"), so each has places in this space's log: its
**copies**. A list event is **at the place** of a space event `e` when a
copy of that event itself is `e` or in `e`'s causal past, whatever that
copy's own verdict; an `add` is also at `e`'s place when a copy of a list
checkpoint whose record names that `add` ([identity.md](identity.md),
"List checkpoints") is. A copy of any other list event places nothing
else: a later event's copy does not place the events in its past, so a
replica never needs a list's past, which it may have forgotten, to place
anything, and every replica places from the copies alone. Device `d`
writes through person `m` at `e`'s place (Paths, above) when an `add` of
`d` that is valid in the list as the replica holds and merges it is at
`e`'s place. So a list event the space learns of after
`e`, or apart from it, gives `e` no path, at every replica, and `e`'s paths
through persons are fixed by its own past:

- **Validity too.** Step 2 reads paths so, for validity as for
  attribution: a unit never becomes valid later because a list gained its
  author, and a device moved to a person, or added to a second one, after
  it wrote, writes its earlier units through the persons it wrote them
  through. A grant "with history" entitles a device to earlier keys, never
  to earlier units. A device's client publishes the copy of its `add`
  before its first event through that person, as part of that event's past
  or as that event itself ([identity.md](identity.md)); a unit signed
  without it has no path through the person, and is `NotAWriter` if it has
  no other.
- **What the list decides stays the list's.** An `add` counts only while
  the list as held keeps it valid: a later merge of the list that voids
  it voids the path, at every place, as a list checkpoint that does not
  list the device does (section 3.15.8). These are the only ways a list
  event the unit's past does not hold changes its paths, and they change
  its validity and its attribution together. A revocation is an end
  (below), which responses decide.
- **A replica that forgot.** A replica that forgot the space's events
  before its kept checkpoint keeps every `frasil:list` unit of that past
  whole (section 3.15.6), so the copies it places are those of one that
  kept everything. One that forgot a list's events before the list's kept
  checkpoint places each `add` by the ID its copy carries, or by the list
  checkpoint record that names it, and the list checkpoint's record
  decides its validity as section 3.15.8 says: what it forgot is never
  needed to place, so it places as one that kept the list whole.
- **A newcomer** holds no copy before its base. The space snapshot it
  starts from names, in its key 15 ([units.md](units.md), "The space
  snapshot"), the list events whose copies are in the past of its base, and
  those events are at the place of its base and of every event after it,
  as they are at a replica that holds the copies.

**Ends.** Another log **ends** `d`'s path by:

- a valid revocation of `d` in the person's list;
- a fork of `d` in the person's list, at the canonically later event of the
  evidence that fixes `d`'s fork point there;
- a valid event of the granted space after which `d` no longer reaches it at
  `write` and propagates;
- recursively, an end of a path `d` had into the granted space.

**Responses.** A **response** to end `X` is a valid event of this space,
signed by a device other than `d`, whose refs name `X` or an event of `X`'s
log that has `X` in its past: a valid roster event, or a key event valid
under section 3.10. From the first response on, `d`'s events through that
path stand only if they are in the past of **every** response to `X`.

- Until a response exists, `d`'s units through that path stand: removal
  across logs is eventual. A device that knows of the end writes nothing to
  the space until it has rotated ([keys.md](keys.md)).
- If `X` is voided later in its own log, its responses lose this effect.
- A grant that carries the member's heads is a response to every end in
  that past.

**Frontiers.** The **frontier** of a valid event `x` that ends a member's
write is, for each device that wrote through that member, its latest
accepted event in `x`'s past. It is derived, never written: a unit is within
the frontier exactly when it is not concurrent with `x`, which is section
3.10, step 4. For an end in another log, the past of each response is the
frontier for the devices the space loses, set by whichever informed writer
responds. Concurrent frontiers merge by intersection: a unit stands only if
it is within every frontier that applies to it.

**Newcomers.** A member admitted "from now on" cannot open list copies or
space events from before its break. Its snapshot MUST carry every event of
the list of every person a roster it carries names, now or before, that
the sender holds, naming in key 15 those at the place of the snapshot's
base, and the
events of the rosters along the space's grant path, as the sender holds
them, with the body keys of section 3.9. A list event the sender holds
with no copy in that past is carried, so that the list verifies, and not
named: it places nothing until a copy after the base carries it, as at
every member.

### 3.12 Anchors, storage events and strangers' events

#### 3.12.1 Anchors and storage events

- **An anchor** ([crypto.md](crypto.md)) is kept and chained when its author
  holds at least `read` at its place through some path. Otherwise it has no
  effect (`NotAMember`).
- **A storage event** (kind 6) is [peers.md](peers.md)'s. A writer request,
  a release or a restore, is judged by the write rule as a unit is. A
  skeleton event whose pseudonym a root or an enrolment of the log names,
  one the skeleton vouches for, is kept and chained, and counts for
  stability as section 3.14 says; whether it is a valid twin is
  [peers.md](peers.md)'s. The skeleton vouches for a root that passes
  [peers.md](peers.md)'s checks, and for an enrolment that verifies against
  an administrator slot that a held root or change made. One whose
  pseudonym no such record names, such as a stranger's self-signed
  enrolment, is `Dropped`: its signature may verify, by its own key's hash
  (section 3.4.2), but it names no slot.

#### 3.12.2 Strangers' events

- **An event of an ignorable kind** is kept and chained, with no effect,
  only if some record names its author: a grant of its device ID in this
  log, an `add` of it in a list the space reads (with a list checkpoint in
  effect, an `add` in its past only when the record lists the device,
  section 3.15.8), a grant of it in a granted space, or a skeleton record
  of its pseudonym that the skeleton vouches for (section 3.12.1).
  Otherwise it is `Dropped`.
- A unit or key event that no path admits (`NotAWriter`), from an author no
  record names, is `Dropped`. So is a unit, an anchor, a writer request or
  an event of an ignorable kind that is `NoHybridKey`, unless a list or a
  roster that could name its author is missing here; then it stays pending.
- A dropped event is not kept. A replica that later receives a record naming
  its author fetches it again. Every other refused write, and every write
  from an author a record names, is kept (section 3.14).

### 3.13 Replacing a person

A person that lost every key returns as a new person
([identity.md](identity.md)). In each space, an administrator compares the
admission code with the new person and signs one update that removes the
old person and grants the new one, with `replaces` naming the old person ID.
A client shows that the new person replaced the old, and which
administrator verified it.

- `replaces` is valid only beside a removal of the person it names, in the
  same event (`Malformed`).
- The old person's administering devices hold grants of their own, and may
  be in a thief's hands. A client that signs a `replace` MUST offer to remove
  each of them, each in an event of its own (section 3.5), and to grant
  `administer` to the new person's device.
- The new person and its devices take no seniority from the old: seniority
  is a device grant's, and a `replace` that passed it on would let a
  compromised administrator mint a founder.

### 3.14 What replicas derive

**The valid set** is the valid events of the view. **The roster at any
place**, the merged roster of the whole view included, is section 3.2 over
the valid roster events of that place. A **rotation** is the genesis or any
valid space event whose payload rotates; the **maximal valid rotations** are
those no other valid rotation follows. [keys.md](keys.md) takes all three
from here.

**The events that void an event.** Each void event names them:

- an attacked roster event: every valid event whose attack on it counts
  (section 3.5.2);
- a refused unit or key event: the event that ends its write (section
  3.10, step 4), or the response of step 5;
- a forked event: the two events of each evidence of its author's fork;
- a failed authority (`NotAnAdministrator`, `AlreadyMember`,
  `NoSuchMember`, `NotAWriter`): found the same way for the void roster
  events in its past that name its author's device or its own members,
  and, for a unit or key event, a person whose list holds its author at
  its place (section 3.11, "A list at an event's place");
- otherwise none.

**Stability.** A set of events `T` is **stable** in a view when every
administrator of the merged roster that has not forked has a valid event of
this log, of a kind below 64, whose past holds every event of `T` (or that
is one of them). A skeleton event counts as an event of the device its
pseudonym's binding names, and the root as the founder's; one by a
pseudonym enrolled foreignly, or not enrolled, counts for no device
([peers.md](peers.md)). A voiding is stable when the voided event and every
event that voids it are. Every replica computes this from what it holds.

**Duels.** For each mutual pair `(x, e)` one side of which is valid (the
outranking author's, section 3.5.2), a client exposes what that side
voided: every event not after it that is void in the view and valid in the
view without it and everything after it, its partner included. The list
covers grants, removals, rotations and units, and names both authors and
their ranks, so an application can show "Q removed P; P's concurrent
removal of Q lost, Q being the more senior". A lowering voided as
`HigherRank` is no duel: the client lists it as an attempt on a higher
rank. A member whose grant a duel voided sees only that it is out; this
list is how a client explains it.

**Re-submission.** A device whose units were refused (`RefusedByRemoval`,
`RefusedAfterResponse`, or `NotAWriter` with events that void it, above)
and that again writes through some path of the merged roster SHOULD
re-submit them. A `NotAWriter` unit has events that void it when a roster
event in its past that names its device, or a person whose list holds it
at its place,
is void by some event: the grant it wrote through was voided there. One
with none, whose author held there no grant that an event voided, was
never a writer's and is never re-submitted. A replica that forgot the
unit's place reads those events from what it froze
([at-rest.md](at-rest.md), the `event` record's key 8), so every device
re-submits the same units. It re-submits, for each refused unit of its own,
in canonical order, a new unit with the same adapter content after its
current heads, naming the unit it replaces ([units.md](units.md)), but
none of an incarnation whose text it has written again under another
([units.md](units.md), "Re-submission", text written again). A re-grant
never makes the old units valid. A client lists refused roster
events and does not re-sign them; an administrator decides.

**Keeping refused units.** A refused unit is kept: it becomes valid again
if a later merge voids the event that refused it. A replica decides how
long it keeps the content, never whether the unit is valid:

```text
refused_unit(own, stable, first_sight, now, gap_key_timeout):
  1. own: this device is the unit's author.                         Keep
  2. stable: the refusing event is stable.                          MayDrop
  3. lower(first_sight, now) >= gap_key_timeout.                    MayDrop
  4. Otherwise.                                                     Keep
```

`first_sight` is this device's first sight of the refusing event, and the
timeout is the space policy's. A space whose space recovery member never
signs never reaches stability; step 3 bounds what its replicas keep. On
`MayDrop` a replica may drop the content under compaction
([units.md](units.md)). The author keeps its own refused units until they
are accepted or re-submitted, and supplies them again.

### 3.15 Checkpoints

A **checkpoint** fixes the roster of its own past and lets every party
forget what came before it: once it is **in effect**, nothing before it can
change any verdict again, and the events that follow it are judged from its
record alone. It is a roster event with a roster part of type 2 (section
2.2) and a record (section 2.8). Its **epoch** is the record's; checkpoints
form a chain, each naming its **predecessor**, the one in effect in its
past.

#### 3.15.1 What follows a checkpoint

- An event **follows** checkpoint `c` when its cuts reach `c`
  ([events.md](events.md), "Cuts"); whether it does is read from its
  envelope.
- With `c` in effect, an event is one of: in `c`'s **past**; `c` itself;
  **after** `c`, when it follows `c`; or **late**, any other. A late event
  is void (`Late`). A late unit is refused (`Late`, with `c` as the event
  that refuses it): it is kept, and its author re-submits it (section
  3.14). A late anchor, storage event or event of an ignorable kind has no
  effect.
- **Mixed parents.** An event after `c` one of whose parents other than its
  `prev` is neither `c` nor after `c` is void (`MixedCut`). Its `prev` may
  be any event: a device whose own last event is late continues its chain.
- An event after `c` whose `seq` is at or below its author's tip in `c`'s
  record repeats a sequence number of `c`'s past: its author counts as
  forked from that `seq` in `c`'s world (section 3.15.5).

#### 3.15.2 A checkpoint's validity

A checkpoint is judged on its own past alone, so its verdict never changes:
it is never attacked, attacks nothing, takes no part in the resolution
procedure's contest, and counts as a valid roster event of every place that
holds it when valid. In order:

```text
1. Section 3.4.1, the event alone, through its step 10; then
   events.md's cuts.                                               else that class / BadCuts
   Its record reads from its object (section 2.8), and, in a space
   with a skeleton, the cut visible key 15 names, when held, uses
   no reserved key of a cut's body (peers.md, section 2.4);       else Sealed (held) / BadCheckpoint /
                                                                        ExtensionRequired (held, below)
   no checkpoint in its past is held for its record.               else Pending (held)
2. Without a predecessor (epoch 1): no checkpoint its cuts reach
   is valid.                                                       else BadCheckpoint
   With a predecessor p: p is a checkpoint its cuts reach, and
   every checkpoint its cuts reach is at or before p, or after p;  else BadCheckpoint
   no valid checkpoint its cuts reach is after p;                  else CheckpointPending
   p is valid;                                                     else BadCheckpoint
   p is in effect (section 3.15.4) in the view of p and the
   events after p in its past, and that view holds no other valid
   checkpoint.                                                     else CheckpointPending
3. Its signature (section 3.4.1, step 11), under keys taken from
   its past, as section 3.15.5 lets a replica take them in p's
   world, and from the other logs the replica holds.               else NoHybridKey (held) / BadSignature
4. Its author's fork point, in its past, is above its seq.        else Forked
5. Its author's device member is in at administer in the roster
   of its past.                                                    else NotAnAdministrator
6. keys.md's checks against the event and its place, taking it as
   a genesis takes them: it rotates, as a grant rotation unless
   the space is restricted, and is no break.                       else that class
7. Its twin: visible key 15 names a skeleton cut, which it cites
   (read from its parents, without the cut); every other parent
   of the checkpoint is in the cut's past; and the cut passes
   peers.md's checks of a cut (section 3.21, steps 1 to 7).        else TwinRequired / BadTwin
8. Its record equals, byte for byte, the record of its past
   (section 3.15.3), each space member's keys 18 to 20 left out
   of both (section 2.8). A replica may compare the two as the
   record streams, or compare a SHA-256 of each compared form;
   either gives this step's verdict.                               else BadCheckpoint
9. The cut agrees with the record (section 3.15.8).               else BadTwin
```

Its **past** here is: without a predecessor, every event in its causal
past; with predecessor `p`, `p` and the events after `p` that it reaches
through events after `p` (its past in `p`'s world, section 3.15.5). Steps 3
to 9 read the roster, forks, keys, skeleton and record of that view as
section 3.15.5 resolves it.

- **A record held for a later document's key**, or a cut held for one
  (peers.md, section 2.4, "Reserved cut keys"), which holds the
  checkpoint the same way in every respect, a rival included, holds the
  checkpoint only while the steps that read no record pass. Steps 2 to 6 run in
  order, as for any checkpoint, with the predecessor that keys 2 and 3 of
  the record's map name, or none: the predecessor and its order (step 2),
  the signature (step 3), the fork point (step 4), the authority (step 5)
  and keys.md's checks (step 6). A failure of one of them is final. A step
  that holds the checkpoint (`NoHybridKey` at step 3, or a checkpoint in
  its past held for its record) holds it there, and the later steps wait,
  as they wait for any checkpoint. One that passes all of them stays
  `ExtensionRequired`. A replica that forgot the checkpoint's past cannot
  run them, and holds it.
- **Why the twin comes before the record.** The record's `slot` entries
  (key 13) read the skeleton of the past: from the root without a
  predecessor, and from `p`'s cut with one (section 3.15.5, Skeleton). A
  cut that passes step 7 proves, by peers.md's epoch check, that `p`'s cut
  is in effect in its past and that no later cut is, so a replica that
  keeps everything and one that forgot read that skeleton alike; and since
  the checkpoint's past is the cut's past and the cut, the skeleton a peer
  read for the cut's slots is the one the record reads. Step 9 then maps
  the record's administrators to the cut's slots.
- **Step 6.** A checkpoint's author passed step 5, so it is a device
  member at `administer`, which never carries `session` (section 3.6): it
  propagates. A checkpoint is therefore always a grant rotation in a space
  that is not restricted, and never one in a restricted space
  ([keys.md](keys.md), section 3.3, step 5); a guest's checkpoint is
  `NotAnAdministrator` before keys.md is read.

- Every step reads only that past, the envelopes of the checkpoints its
  cuts reach and the verdicts of those checkpoints, so a replica that
  forgot what came before its kept checkpoint (section 3.15.6) decides it
  as one that did not. Step 2 needs no verdict before the kept
  checkpoint: a checkpoint after it that names no predecessor reaches it,
  and it is valid; one that names a predecessor before it reaches it
  after that predecessor, and it is valid, so it is `CheckpointPending`.
  Such a predecessor is one the replica keeps as an envelope alone: it
  knows it is a checkpoint, without opening it, because a correct cut
  names it (the kept checkpoint's, or that of an event after it), and an
  ID a correct cut names is a checkpoint ([events.md](events.md), "Cuts").
  The signature waits for step 2, so that a replica never needs a key
  from before its kept checkpoint to decide a checkpoint after it.
- Step 2's order check reads envelopes alone. Without it, a checkpoint
  whose cuts reach its predecessor and a checkpoint concurrent with it
  would need that concurrent checkpoint's verdict, which a replica that
  forgot under the predecessor cannot reach; peers.md's epoch check of a
  cut reads the same order for the same reason. Both hold for any events
  an administrator can sign, honest clients' fencing aside.
- `CheckpointPending` is final: it reads the checkpoint's own past and
  the verdicts of checkpoints in it, which never change. A client that
  made one too early proposes again once the checkpoint it waited for is
  in effect.

#### 3.15.3 The record of a view

The record of checkpoint `c`'s past is: `epoch` and `previous` as section
2.8 says; `members`, every member in at the merged roster of that view,
and every invite key out only by valid successors, each with its state,
its seniority and, for a device member and an invite key, its keys (any
source, by their hash), and the other fields section 2.8 lists;
`policy`, the merged policy; `forks`, every author's fork point there;
`tips`, for each author the greatest `seq` there and its event, the
smaller ID on a tie, starting from the predecessor's tips and counting
only the predecessor and the events after it when there is a
predecessor. With a predecessor, the fields section 2.8 derives from
"valid events of the view" read the predecessor's record too: a granted
space's notices, floor and names are the predecessor's, as its world
holds them (section 3.15.5), merged with those of the events after it as
if the predecessor carried them, its notices superseded by any event
after it that carries one for that space, its floor and names kept; an
invite key's status reads the
predecessor's status as one more successor where it is not 0.

#### 3.15.4 Votes and effect

- **Heard members.** A device member is **heard** by `c` when a valid
  roster event of `c`'s window (`c`'s past after its predecessor, or its
  whole past without one) removes it, demotes it below `administer` or
  extends `frasil.dormant` to it while it is at `administer` without
  `frasil.dormant` at that event's place; `c`'s record does not keep it at
  `administer` without `frasil.dormant`; and no such event that lowered it
  was signed by itself or by a member that outranks it at that event's
  place (section 3.2). Section 3.6 voids every lowering of a higher rank,
  so a heard member is one that a member of its own rank, junior to it,
  lowered. A lowering that a valid event of the window raising it back to
  `administer` follows does not count. The record lists heard members with
  their ranks (section 2.8, key 8), so every replica, one that forgot and a
  newcomer included, reads them from it; and since they are a function of
  `c`'s past, step 8 of section 3.15.2 checks them byte for byte.
- The **electorate** of checkpoint `c` is every device member at
  `administer` in its record whose capabilities do not extend
  `frasil.dormant`, and every member `c` hears, less those **excused**. A
  member is excused once the replica holds, after `c`: evidence of its own
  fork in `c`'s world; or a judged roster event whose signature verifies,
  whatever its verdict, that removes it, demotes it below `administer` or
  extends `frasil.dormant` to it, signed by a member of the record at
  `administer` that outranks it (the rank and seniority in the record, or
  those key 8 gives a heard member), `c`'s author included; signed by
  itself, a heard member's signature checked under the keys key 8 gives
  it; or signed by a **recovery member** of a rank at least the excused
  member's: a member of the record at `administer` whose capabilities
  extend `frasil.dormant` and that `c`'s predecessor's record lists so, or,
  without a predecessor, whose grant in `c`'s past the excused member
  signed, or another member that the record keeps at `administer` or
  hears and that outranks it by the record's ranks and seniorities: the record decides it, so that a peer
  reads the same from the cut's standing entries ([peers.md](peers.md),
  "Storage events"). A change that only marks a member dormant has no
  twin, so it excuses at replicas alone; to excuse a member at the peer
  too, a client removes or demotes it ([peers.md](peers.md), "Skeleton
  cuts"). Excuses only accumulate: a removal that a
  later merge voids does not put its target back in the electorate, so a
  checkpoint in effect never leaves effect as events arrive.
- **Why ranks.** A checkpoint's electorate is read from its own past, which
  is whatever its author's view held. Without ranks, one removed
  administrator, or a thief holding one administrator's device, could sign
  on its view from before its removal a removal of every other
  administrator, one per event, then a checkpoint whose electorate is
  itself alone. With ranks, its removals of a higher rank are void
  (`HigherRank`), so the record keeps those administrators and the
  checkpoint waits for their votes, which they refuse (section 3.15.7); its
  removals of an equal rank senior to it leave those heard, and nobody it
  could command (itself, a colluding device of its rank and junior to them,
  or a device it granted in its branch, junior to every member before it)
  excuses them. The rule reads only `c`'s past, its record and the events
  after `c`. Its limits are section 4's.
- A device **votes** for `c` by `c` itself if it is `c`'s author, and
  otherwise by any event of it after `c` whose signature verifies, whose
  cuts are correct, and whose cuts reach no checkpoint concurrent with `c`
  (neither at or before `c`, nor after it). Any kind below 64 counts. A vote
  is never taken back, so stability only grows as events arrive.
- `c` is **stable** when every member of its electorate votes for it. A
  vote that this replica holds (`Sealed`, `Pending`, `NoHybridKey`) does
  not count until it is judged.
- A heard member votes as any device does; its signature is checked under
  the keys key 8 of the record gives it.
- **Waiting for.** A client reports, for each valid checkpoint that is not
  in effect, the members of its electorate that have not voted, with the
  last event of each it holds, so that an application can show who a
  checkpoint waits for and an administrator that outranks one that will
  not return can remove it, or mark it dormant by a change that extends
  `frasil.dormant`; a recovery member of a rank at least its own can do
  either. Either excuses it once judged. A member that outranks every
  administrator that remains, the founder's lost device for instance, waits
  until a recovery member excuses it, or for good in a space without one.
- **In effect.** Starting from no checkpoint (or from the checkpoint a
  replica keeps, section 3.15.6), repeat: among the valid stable
  checkpoints whose predecessor is the current one and that follow it, the
  one with the smallest event ID takes effect and becomes the current one.
  The checkpoints so found are the **chain in effect** of the view.

Votes are exclusive: once one of a device's events follows `c`, every later
event of its chain does too, so it can vote for no checkpoint concurrent
with `c` without forking. So two
concurrent checkpoints both take effect only if their electorates share no
device.

**Concurrent checkpoints that are both stable.** Two such checkpoints with
the same predecessor need electorates with no device in common. The
administrator without `frasil.dormant` that outranks every other one the
predecessor's world holds is in each one's electorate: kept by its record,
or heard, since no other member outranks it, unless it lowered itself; and
only a recovery member excuses it. So two such checkpoints both take effect only
if that administrator forked and voted for both, or a recovery member
excused it from one of them. When that happens, every replica settles on
one of them by the same rule:

- Validity is final, and stability only grows, so the set of valid stable
  checkpoints with a given predecessor only grows as events arrive. The
  one with the smallest ID takes effect, at every replica that holds it
  and its votes, whatever else it holds.
- A replica's chain therefore changes, as events arrive, only to a
  checkpoint with a smaller ID than the one it replaces, and only where
  that checkpoint's electorate shares no device with the electorate of
  each checkpoint it replaces. Each such change needs another group of
  devices disjoint from every group before it, so a replica changes at most
  as many times as there are such groups, and a replica that holds every
  event never changes again: it has settled for good.
- Where a replica's chain changes, the events after the checkpoint it
  replaced, other than those after the new one, become late, with
  everything section 3.15.1 says of late events; a client re-submits,
  re-signs and lists them (section 3.15.7).
- A replica that forgot under the checkpoint that loses cannot judge the
  one that wins: section 3.15.6 says what it holds and how it settles.

#### 3.15.5 The world after a checkpoint

The **world** of checkpoint `c` is the resolution of section 3.7 to 3.14
over a log whose root is `c` and whose events are the events the replica
holds after `c`, each linked only to its parents among them (its `prev`
too, when it is after `c`):

- `c` stands as that log's genesis: each member entry of its record as a
  grant in it, with the entry's state and seniority, and the record's
  policy as the genesis policy. The space ID, descriptor and system stream
  stay the genesis's.
- **Invite keys** of the record ([ext-invite-links.md](ext-invite-links.md)):
  an open or used key, or a raced one, is in, with its entry's state; a
  claimed one is out, as if a valid successor of it were `c`, so that its
  close is valid. For a successor's step 1, `c` counts as a successor of
  every key whose status is not 0: every successor of a claimed, raced or
  used key after `c` is `InviteUsed`, as it would be over the whole past.
  A raced key counts as outside ([keys.md](keys.md)).
- **Granted spaces.** `c` carries, as its own, the notices of each space
  member's entry, each by the author the entry names, and names in its
  sealed refs the entry's `named` IDs: [keys.md](keys.md)'s checks and
  principals read them so, and a floor stays (keys.md, section 3.17).
- **Heights** count from `c` at 0: an event after `c` is one more than the
  greatest height among its parents in the world, `c` and the events after
  `c`. A parent outside the world (a late or earlier `prev`, or the
  genesis, which a replica keeps) counts for nothing. An event whose cuts
  are correct and reach `c` has a parent in the world, since they reach it
  only through one; one with none has wrong cuts (`BadCuts`) and takes
  height 1. Canonical order there reads only events after `c`. Seniority is
  `(epoch, height, hash, grant)`: a grant in the world of `c` has `c`'s
  epoch and its height there; a member of the record keeps the tuple the
  record gives, whose epoch is lower.
- An author with a fork point in the record is forked from that `seq`; an
  author with an event after `c` at or below its tip in the record is
  forked from that `seq`. Fork evidence counts between events of the world
  only; a `prev` outside the world is not checked.
- **Keys.** A replica takes an author's keys (section 3.4.2) from the
  record, the world's events, the lists and granted spaces it holds as
  section 3.15.8 reads them, the skeleton's records after the cut, its
  admission and what it cached from these, never from an event before
  `c` or a late one: a replica that forgot those and one that kept them
  check the same signatures, and an author that only an earlier grant
  named is `NoHybridKey` at both.
- **Seals.** Every event after `c` is sealed under a state of the world:
  an event or a unit whose `sealed_under` or key reference names a
  rotation that is neither `c` nor an event after `c` in its past is void
  (`StaleSeal`), read before any key is (section 3.4.1; [units.md](units.md),
  section 3.2). Such a state is one `c` follows, or one `c` does not
  reach, so no honest writer that follows `c` seals under it.
- Events with cuts that do not match are void (`BadCuts`); events with
  mixed parents are void (`MixedCut`); a later checkpoint has the verdict
  of section 3.15.2.
- The 4,096 bound counts `c` and the valid roster events after it.
- **Keys of the world** are [keys.md](keys.md)'s, section 3.17: the
  artifacts of `c` and the events after it alone.
- **Skeleton.** In a space with an administrator skeleton
  ([peers.md](peers.md)), the skeleton a replica reads in `c`'s world (for
  twins, section 3.8, for pseudonym keys, section 3.12, and for the
  `slot` entries of the record of a checkpoint whose predecessor is `c`)
  is the skeleton after `c`'s cut ([peers.md](peers.md), "The skeleton
  after a cut") over the skeleton events after `c` that it holds: `c`'s
  cut stands as its root, its slots in and enrolled to the pseudonyms of
  the roots and enrolments its entries name. A replica restarts the
  skeleton there when `c` takes effect at it, whether or not the cut is in
  effect yet at a peer. A slot of the cut maps to the device whose member
  entry in `c`'s record names it in key 13, and the pseudonym the cut
  enrols in it to that device when the entry names the same pseudonym; a
  slot no entry names, and a pseudonym of the cut that the entry does not
  name, map to no device, as a foreign enrolment's. An enrolment after `c`
  of a slot of the cut, which the cut leaves unenrolled, binds its
  pseudonym by its binding, sealed under `c`'s `twin_secret`
  ([peers.md](peers.md), sections 2.5 and 3.13), to the device the entry
  names; a late enrolment binds none, and a device whose enrolment is late
  enrols again after `c` ([peers.md](peers.md), "A late enrolment"). A
  later cut in the world is judged on its own past
  (peers.md, steps 1 to 7), but the replica's skeleton moves to it only
  with its checkpoint. Before the first checkpoint in effect the skeleton
  is the one from the root, and a cut is judged on its own past.

**Verdicts.** With a chain in effect `c1, …, ck`: events in `c1`'s past have
the verdicts of the view of that past alone; `ci` is valid; events after
`ci` that are in `c(i+1)`'s past have their verdicts in `ci`'s world over
`c(i+1)`'s past; events after `ck` have their verdicts in `ck`'s world; every
other event is late. So an event late under one checkpoint of the chain is
late for good, though a later checkpoint's past holds it, at a replica as
at a peer over its chain of cuts ([peers.md](peers.md), "Late skeleton
events" and "Release and restore"): one rule, read over each party's own
chain. Without a chain in effect, the view is resolved as
sections 3.1 to 3.14 say, each checkpoint with the verdict of section
3.15.2. The roster of the view is that of the last world.

#### 3.15.6 Forgetting, and starting from a checkpoint

- **What may be forgotten.** A replica that holds checkpoint `c` in effect,
  and judged it on its whole past, MAY drop every event in `c`'s past, and
  the bodies of late events other than space events, and keep only what
  the next item lists, with
  the content keys, body keys and units it chooses to keep under
  [units.md](units.md)'s compaction. Each unit of `c`'s past that it keeps
  keeps the verdict and the author's capabilities at its place that it
  had when the replica forgot, frozen, so that every adapter applies it as
  at a replica that kept everything ([units.md](units.md), "The past of a
  kept checkpoint"). It keeps `c` as its **kept
  checkpoint**: its verdicts are then section 3.15.5's, starting from `c`,
  and read nothing it dropped.
- **What must be kept.** The genesis (the space ID is its hash); the kept
  checkpoint, its skeleton cut and its record; the roots and enrolments
  that cut's slots name ([peers.md](peers.md), "Skeleton cuts"); the
  envelope of every checkpoint the kept one's cuts reach, so that it orders
  any cut ([events.md](events.md), "Cuts"); the envelope of every late
  event, and every late space event whole, since an event after `c` may
  have one as its `prev`, which contributes its cuts, or itself if it is
  a checkpoint; the ID of every event it dropped, so that it
  places an event that cites one, never fetches it, and tells an event in
  `c`'s past from one it has not received, and, for each dropped parent of
  an event it keeps of `c`'s past, that parent's height, so that the kept
  event keeps the height it was judged at ([events.md](events.md),
  "Placement and order"); every event after it; of the releases and
  restores of `c`'s past that are not late under an earlier checkpoint,
  the maximal ones of each stream, which it finds before it drops
  anything, ordered before every event after `c`, and every restore that names a snapshot unit
  ([units.md](units.md), "Release, restore and erasure at a replica"); the content keys of every state it
  still reads units, objects and names under, kept as the secrets of each
  of its rotations, which open what is sealed under it once the rotation
  event is dropped ([at-rest.md](at-rest.md), "Forgetting before a
  checkpoint"), and the grant seeds
  [keys.md](keys.md), section 3.17, keeps; the body keys of the space
  events it keeps; every `frasil:list` unit of `c`'s past that carries an
  event of a list the space reads, kept whole as any unit of that past it
  keeps (frozen, [units.md](units.md)), so that it places
  each list event as one that kept everything does (section 3.11, "A list
  at an event's place"); its own chain tips ([at-rest.md](at-rest.md)).
- **Dropped parents.** A parent the replica dropped is in `c`'s past, so it
  contributes to an event's cuts nothing that `c` does not reach
  ([events.md](events.md), "Cuts"): the check counts it as contributing
  nothing, and never waits for it. A parent other than `prev` that it
  dropped makes an event after `c` `MixedCut`.
- **Envelopes it fetches.** An event's cuts check orders the checkpoints
  its parents are and declare. Each is at or before `c`, and kept as an
  envelope; or in the causal past of a parent it holds and not in `c`'s
  past, so late or after `c`, and held once that parent is placed, since
  placing an event fetches its parents (a late space event is kept whole).
  The check therefore waits only while the replica places what it
  received: after a `MixedCut` event, for instance, until it holds the
  late checkpoint that the event's late parent follows. That wait is
  intended: the late parent is placed only once its own cuts are checked,
  which orders the late checkpoint it follows against `c`, so a replica
  that forgot reads `MixedCut` from the same envelopes as one that kept
  everything, and never guesses. A replica that forgot cannot hold that
  checkpoint already, since it is not in `c`'s past and the replica never
  received it; it asks for it as for any parent's past. Members that kept
  everything serve it, and so does every peer: truncation deletes only
  what lies in a cut's past, and keeps the envelopes of the checkpoints
  the cut reaches ([peers.md](peers.md), "Truncation"). An ID a placed
  parent declares that is neither held, kept nor among the IDs it
  dropped is in no parent's past: that parent's cuts are wrong
  (`BadCuts`), and the ID reaches nothing; a newcomer counts one that
  peers answer `Missing` for as dropped, below.
- **Starting from a checkpoint.** A newcomer, a restored member and a
  replica that lost its store read the checkpoint's record with the object
  key the snapshot hands them, and take as kept checkpoint the one a space
  snapshot names ([units.md](units.md), "The space snapshot"), once it is
  in effect in what they hold after it, and judge from there. They trust
  its record on the votes of its electorate, every device that
  administered there, each of which judged it on its whole past before it
  voted: a record that no honest administrator would vote for never takes
  effect. Such a replica holds no ID of what came before: a parent outside
  the world that it fetches and that a peer answers `Missing` for, since
  the peer truncated it ([peers.md](peers.md), "Truncation"), counts as a
  dropped parent; one it is served contributes the cuts its envelope
  declares, as any parent does. One whose record it holds as
  `ExtensionRequired` (section 2.8, step 3) it never starts from: it tells
  the application that the space needs a version it lacks, and judges
  nothing of the space.
- **A rival.** A replica that forgot under `c`, or started from `c`, cannot
  judge a checkpoint concurrent with `c`, since its past is gone. It calls
  one, `x`, a **rival** when: `x` names as predecessor `c`'s predecessor or
  a checkpoint that `c`'s cuts reach, or names none; `x`'s ID is smaller
  than that of `c` or of a checkpoint that `c`'s cuts reach after the one
  `x` names (any of them, when `x` names none), which are the checkpoints
  of `c`'s chain that `x` could replace; `x` passes what the replica can
  check of it without its past (section 3.15.2, step 1, and keys.md's
  checks as a genesis), or its record is `ExtensionRequired` there; and `x` is stable in what the replica holds after
  it, its votes checked under the keys its record carries and those of the
  events after it; one whose stability it cannot work out from what it
  holds (a checkpoint after it whose validity needs the forgotten past,
  say) counts as stable. While it holds a rival, it holds pending every
  event it holds: `c` and the events after it, and the late events, which
  are in the rival's past or after it. Were the rival valid, it would take
  the place of a checkpoint of `c`'s chain (section 3.15.4), and only the
  forgotten past tells. It settles once it holds the rival's past, from a
  member that kept it or a peer that has not truncated it, and judges the
  rival on it; or once it starts again from a space snapshot that names
  the rival's chain, as a newcomer does (above). Every other checkpoint
  concurrent with `c` is late at it, as at a replica that kept everything.
  A rival that is stable needs two electorates with no device in common
  (section 3.15.4): the most senior administrator forked, or a recovery
  member excused it on one side. A checkpoint whose record it holds as
  `ExtensionRequired` is a rival when its keys 2 and 3, read from the
  record's map alone, name a predecessor as above, and counts as stable,
  since its votes cannot be checked; it holds every event as above. It
  settles as any rival does, once it holds the rival's past: the steps of
  section 3.15.2 that read no record (the signature, the fork point, the
  author's authority and keys.md's checks) decide it then, a failure being
  final, so that a checkpoint by a writer or a removed administrator is
  void; one that passes them stays `ExtensionRequired`, and the replica
  signs nothing more in the space and tells the application that the
  space needs a version it lacks, as section 3.16 says. What bounds it is
  what bounds any rival: whoever can sign a checkpoint stalls only
  replicas that forgot, and only until they fetch the past, while a
  genuine administrator's use of an extension stops a replica that lacks
  it, as it must.
- What a replica forgot it never asks for again, and it answers `Missing`
  for it. A member that keeps everything, and every peer until it truncates
  ([peers.md](peers.md), "Truncation"), serves it.

#### 3.15.7 Clients

- **Following.** A device follows the latest valid checkpoint of its view
  whose chain it is on: the one in effect, or a valid one waiting for votes
  whose predecessor is in effect, the one its own events already follow
  first, else the smallest ID. It cites none of the events concurrent with
  the one it follows, so that its events are after it and none is
  `MixedCut`. It seals under the current state of that checkpoint's world.
- **Contested checkpoints.** A device never writes an event that follows a
  valid checkpoint `c` that is not in effect in its view, and so never
  votes for it, while either holds:
  - `c` hears it: `c`'s past lowered it only by members it outranks,
    whatever its own view says; or
  - its view holds a valid roster event concurrent with `c`, signed by a
    member that outranks the member it lowers, that removes, demotes below
    `administer` or extends `frasil.dormant` to `c`'s author or to another
    administrator `c`'s record keeps.
  It keeps following the checkpoint it followed, cites neither `c` nor
  anything after it, and tells the application that `c` is contested,
  naming `c`'s author and the lowering events on both sides, as it lists a
  duel (section 3.14). The contest ends when `c` takes effect in its view
  without it (its events concurrent with `c` are then late, section
  3.15.1); when the application, told of it, has the device remove itself,
  accepting its lowering; or when the lowering event it holds is void in
  its view. An administrator that is heard and still has its device should
  be asked, not overridden: its vote, or its own removal, is the only way
  a checkpoint by a junior gets past it.
- **Proposing.** An administrator's client proposes a checkpoint when the
  valid roster events since the last one in effect reach 1,024, or the
  frame events since it reach 4 MiB, no checkpoint is waiting for votes in
  its view, and the cut of the last one in effect is in effect in its view
  by peers.md's rule (every enrolled slot acknowledged it), since its own
  cut is otherwise `CutPending` and the checkpoint `BadTwin`; the most senior administrator proposes first, the others
  after their rank delay ([keys.md](keys.md), "The rank and the delay")
  with the epoch as trigger. An application MAY propose more often, and
  MAY turn proposing off.
- **Voting.** An administrator's client that judges a checkpoint valid
  votes promptly, by any event after it (an anchor if it has nothing to
  write), unless it holds a concurrent checkpoint it has voted for, and
  only once the record's space entries, keys 18 to 20, equal those it
  derives: it first fetches the granted spaces' logs and the lists that
  the key events of the checkpoint's past wait on, and one whose entries
  differ from its own it never votes for, and lists for the
  administrator. One that judges it void, or holds it (`Sealed`,
  `ExtensionRequired`), does not cite it. In a space with a skeleton, it
  votes only once each always-on peer of the space that it reaches has
  acknowledged the checkpoint's cut (at once when it reaches none), and with its pseudonym too, by a skeleton event
  after the checkpoint ([peers.md](peers.md), "The administrator's
  duties"): the peer counts the pseudonym's vote where replicas count the
  device's.
- **Work concurrent with a checkpoint.** A client whose units become late
  re-submits them (section 3.14). An administrator whose roster events
  become late re-signs, after the checkpoint, each removal and demotion
  among them that the roster still needs, and lists the others for the
  administrator to decide, as for a duel. An administrator whose skeleton
  enrolment becomes late enrols again after the checkpoint before it signs
  a twin there ([peers.md](peers.md), "A late enrolment"). A writer signs
  again after the checkpoint each release and restore of its own that
  became late, and an administrator each erasure and credentials request
  ([peers.md](peers.md), "The administrator's duties"), telling the
  application: a late release or restore counts for nothing, at a peer
  ([peers.md](peers.md), "Release and restore") as at replicas, until it
  is signed again.
- **A device offline across a checkpoint** syncs from the checkpoint on,
  finds its own concurrent events late, re-submits and continues its chain.
  A restored device takes its next `seq` from the larger of its own latest
  event and its tip in the kept checkpoint's record ([events.md](events.md),
  "Restored devices sync before writing").
- **Dormant administrators.** A space recovery member is granted
  `administer` at the top rank with the capability `frasil.dormant`
  (extends), so that checkpoints do not wait for it and it can excuse any
  member (section 3.15.4); its concurrent roster events can be made late by
  a checkpoint. Only a member of its rank marks or unmarks it (section
  3.6).

#### 3.15.8 Other logs and extensions

- **Device lists** have checkpoints of their own ([identity.md](identity.md),
  "List checkpoints"). A space reads a person's list as the replica holds
  it, at each event's place as section 3.11 says ("A list at an event's
  place"): from the list's kept checkpoint on, when it forgot the list's
  earlier events, each `add` read from the copy that carries it. A list checkpoint in effect ends at once, in every space, the
  path of every device it does not list, as if each space had responded to
  its end (section 3.11): no space needs the list event that ended it.
- **What an unlisted device loses.** With a list checkpoint in effect, an
  `add` in its past names, for this specification (section 3.12.2 and the
  write rule), only a device its record lists; an `add` after it, or a
  late one, names its device as before. A device the record does not list
  therefore has, from the moment the checkpoint is in effect at a replica,
  no path through the person for any of its events in a space, those
  signed before the checkpoint as well as those after it, and no record
  names it unless another log does. At every replica, whether it kept the
  list whole or forgot it:
  - each of its units, anchors and writer requests, and each of its key
    events whose signature the replica can check, is void: no path admits
    it (`NotAWriter`), so it is `Dropped` as a stranger's event (section
    3.12.2), and not kept;
  - each of its key events whose signature the replica cannot check, since
    the list's `add` that carried its keys is forgotten and no other source
    holds them, is `NoHybridKey`: held, never judged, and with no effect
    (section 3.4.2). A replica never judges what it cannot verify; the
    hold changes no other verdict, since no path admits the event either
    way.
  This holds for its events in the past of a space checkpoint too, at a
  replica that kept that past; one that forgot it judges them no more. A
  space thus loses the device's earlier units, which a response to a
  revocation would have kept: that is the price of not needing the list's
  earlier events, and an application warns before a list checkpoint drops
  a device that wrote recently.
- After a space checkpoint, a space's system stream need carry the lists
  of the persons its record and the events after it name, each from its
  list's latest checkpoint in effect on.
- **Granted spaces and lists across logs.** Each log has its own chain.
  A path through granted space `Y` reads `Y`'s roster as section 3.11 says,
  over what the replica holds of `Y`: from `Y`'s kept checkpoint on, when it
  forgot `Y`'s earlier events. An end in another log that a checkpoint's
  past did not answer is answered after it, as any end is; a response's
  refs to events the replica forgot count as resolved.
- **A granting space checkpoints** (this space, X, grants `Y`): X's record
  carries, in `Y`'s member entry, the notices, floor and names that decide
  `Y`'s principals, so that in X's world `Y`'s principals are those of the
  past, checked again as [keys.md](keys.md) checks any notice, and a
  device that `Y` admitted "from now on" after X responded is held to its
  floor (keys.md, section 3.17). X's checkpoint wraps for them by space
  wrap as for any principal in force.
- **A granted space checkpoints** (`Y`'s checkpoint `cY` takes effect while
  X keeps its chain): `cY` is a grant rotation of `Y`, so it is a change of
  `Y` for X ([keys.md](keys.md), "Cascades"). X loses nothing by it, so an
  informed writer of X responds by delivery: a key event whose refs name
  `cY` and that notices `(Y, cY)`, which puts X's older principals of `Y`
  out of force. Until then X keeps sealing space wraps to the rotation its
  notice names, before `cY`: a replica that forgot `Y`'s events before
  `cY` keeps the visible part of each rotation of `Y` that a principal in
  force in a space it holds names, with its verdict and each notice
  check's result, and the members of `Y` keep that rotation's grant seed
  (keys.md, section 3.17). A replica that lacks them holds the notice
  unresolved (`Pending`), as keys.md says of a log it does not hold.
- **Invites** ([ext-invite-links.md](ext-invite-links.md), "Across a
  checkpoint"): the record carries each invite key in force or claimed,
  with its keys, `expires_at`, `claims` and status, so that after the
  checkpoint a successor is judged, wrapped for, closed, revoked on
  expiry, or refused as `InviteUsed`, as over the whole past. A claim
  concurrent with a checkpoint is late; the claimant claims again after
  it, sealed under a state of the checkpoint's world.
- **Guests** ([ext-guests.md](ext-guests.md)) keep their session and
  `expires_at` in the record's member entry (keys 7 and 14), so that
  administering devices still end the session after the checkpoint.
- **Restricted spaces and carve-outs**
  ([ext-restricted-spaces.md](ext-restricted-spaces.md)): each log has its
  own checkpoints, and either may checkpoint while the other does not. A
  restricted space's checkpoint is no grant rotation. A restricted space
  reads its parent's roster as the replica holds it, from the parent's
  kept checkpoint on, as a path through a granted space reads that space's;
  a replica that forgot the parent's events before the parent's kept
  checkpoint keeps the parent's content keys of every state the
  restricted space's retained events and units name, as keys.md, section
  3.17, keeps its own. A carve-out's record lists its members as any
  space's.
- **Twins and the skeleton.** A checkpoint names a twin in visible key 15:
  its **skeleton cut**, a storage event of type 7 that its author's
  pseudonym signs before it, which carries the skeleton's administrator
  slots at that point and the record's locator ([peers.md](peers.md),
  "Skeleton cuts"). Section 3.15.2 checks it in two steps. Step 7: the
  checkpoint names and cites it, every other parent of the checkpoint is
  in the cut's past (the cut cites them all, beside its pseudonym's
  previous event), and it passes peers.md's checks of a cut (section 3.21,
  steps 1 to 7), which a replica runs as a peer does over what it holds,
  a replica that forgot as a peer that truncated under its kept
  checkpoint's cut. Step 9, its check against the record: the cut
  declares the same cuts as the checkpoint, and each `slot` entry of the
  record's administrators names a slot of the cut whose `pseudonym` names
  a root or enrolment by that entry's pseudonym, or is empty exactly when
  the entry's is. Slots of the cut that no entry names map to no device. A
  checkpoint whose cut fails either is void (`BadTwin`). A pseudonym's
  skeleton events follow the checkpoint its device follows; a twin cites,
  beside skeleton events, the checkpoints its roster event follows, and
  declares the same cuts. Once the checkpoint is in effect at a replica,
  the skeleton it reads starts at the cut (section 3.15.5, Skeleton); at a
  peer, once the cut is in effect there; the 4,096 bound counts from it.

### 3.16 Rules this replica lacks

A roster part of a type from 3 is a later document's. A replica that does
not implement that document:

- holds the event as `ExtensionRequired`, and with it every event of the
  log that is not in its past, whether after it or concurrent with it; it
  resolves the roster and judges writes over that past alone;
- signs nothing more in the log, and tells the application that the space
  needs a version it lacks;
- gives this effect only to an event whose author has standing in its past
  (section 3.7); one whose author has none is void (`NotAnAdministrator`).

A later rule that changes how concurrent events are judged therefore stops
an older replica at a point every replica agrees on, instead of letting it
judge what lies beside that point by older rules. Peers need nothing: the
event is an ordinary sealed space event to them.

### 3.17 Error classes

Besides [overview.md](overview.md)'s classes (section 5.5):

| Class | Meaning | Sort |
|---|---|---|
| `BadSeal` | the sealed part does not match or open under a body key derived from checked rotation keys | final |
| `ExtensionRequired` | a reserved member type, op or change key, a descriptor kind or key (section 2.5), a record key, member-entry key or member type of a checkpoint record (section 2.8), a key of a skeleton cut's body ([peers.md](peers.md), section 2.4), or a roster part type, that this implementation's extensions do not define | held |
| `UnknownPolicy` | a genesis duel policy other than 0 | final |
| `HigherRank` | an event that changes or removes an administrator of a higher rank than its author's, or grants or sets a rank above it (section 3.6) | final |
| `RankInPlace` | a change to `administer` of a member already there with another rank (section 3.6) | final |
| `AdministerNotDevice` | `administer` for a person, a space or a guest: alone (section 3.4.1), or for a guest at the place (section 3.6) | final |
| `SelfRotation` | a self-removal that rotates | final |
| `NotAnAdministrator`, `SelfGrant`, `AlreadyMember`, `NoSuchMember`, `SelfChange`, `AdminAlone`, `Full` | authority at the place (section 3.6) | final |
| `RemovedConcurrently`, `DemotedConcurrently`, `TargetRemovedConcurrently` | attacked by (a), (b) or (c) | final |
| `TwinRequired`, `UnexpectedTwin`, `BadTwin` | key 15 missing, present where it does not belong, or naming a twin that fails | final |
| `NoTwin` | the named twin is not held | pending |
| `NotAWriter` | no path admits the author | final |
| `WaitingDevice` | a key event by a device rooted in a recovery agent | final |
| `RefusedByRemoval`, `RefusedAfterResponse` | a write the end of its path refuses (section 3.10, steps 4 and 5) | final |
| `Dropped` | a stranger's event, or one whose signature no held record lets the replica check; not kept | decision |
| `BadCheckpoint` | a checkpoint whose predecessor or record is not that of its past, or one without a predecessor whose cuts reach a valid checkpoint (section 3.15.2) | final |
| `CheckpointPending` | a checkpoint whose predecessor a valid checkpoint its cuts reach follows, or made before its predecessor took effect; decided on its own past, so final. At a replica that forgot, a checkpoint that names a predecessor before its kept checkpoint, which it keeps as an envelope alone, is this class: its cuts reach the kept checkpoint, valid and after that predecessor (section 3.15.2) | final |
| `Late` | with a checkpoint in effect, an event neither in its past nor after it; a late unit is refused and kept | final |
| `MixedCut` | an event after a checkpoint with a parent, other than its `prev`, that is neither the checkpoint nor after it | final |

- `Sealed`, `BadSeal`, `ExtensionRequired` and `Pending` hold an event and
  every event after it; `ExtensionRequired` for a roster part of a reserved
  type also every event outside its past (section 3.16).
  [keys.md](keys.md)'s classes for checks against the event and its place
  are validity failures of the carrying event. `NotCommitted` is
  [overview.md](overview.md)'s: a grant whose keys do not give its member
  ID. `NotAMember` is an anchor whose author holds no level.
- `UnknownSpace`, `GrantOfRestricted`, `GrantOfReserved`, `GrantCycle` and `GrantTooDeep` are
  verdicts on an edge of the grant graph, not on an event: they say the edge
  delivers nothing.

## 4. Security considerations

- **A checkpoint ends the backdated duel before it.** Once a checkpoint is
  in effect, a removed administrator's counter-removal concurrent with it
  is late, and so is every concurrent event, honest or not. That is the
  price of forgetting: an offline device's work concurrent with a checkpoint
  is void and must be done again after it (units are re-submitted
  automatically; roster changes are re-signed or listed).
- **One administrator cannot impose a checkpoint on others' past.** It
  takes effect only when every non-dormant administrator of its record has
  voted, each having
  judged the record against the whole past; a false record is void
  (`BadCheckpoint`) at every replica that holds that past, and no honest
  administrator votes for it. A replica that starts from a checkpoint
  trusts that agreement; all administrators together could already rewrite
  the roster with ordinary events. An administrator that removes a junior
  one, or marks it dormant, after the checkpoint excuses it from the vote
  even if that removal is voided later: it could already end that member's
  authority by the removal, and excuses that only accumulate keep a
  checkpoint in effect once it is. Nobody excuses a member that outranks
  it, the checkpoint's author included, and a member lowered before the
  checkpoint by one it outranks is heard (section 3.15.4): a removed administrator could
  otherwise sign a checkpoint on a view before its removal, remove
  everyone else before or after it, and take effect alone, its removal
  then late.
- **The record carries what the past decided about other logs.** An
  invite key's status keeps a raced or claimed invite from being claimed
  again after the checkpoint, and keeps a raced one outside, so that no
  rotation after it wraps for a key a racer holds. A granted space's
  notices, names and floor keep its principals, and what a device it
  admitted "from now on" may read, as the past left them. Without them a
  replica that forgot would count a racer, or a granted space's devices,
  as inside, or entitle a device to history it never had.
- **What an absent administrator costs.** A checkpoint waits for every
  member of its electorate. An administrator that never returns is removed
  first, or was granted dormant. A dormant administrator's concurrent roster
  events can be made late; it gives up its backdating power before each
  checkpoint.
- **Disjoint electorates.** Two concurrent checkpoints both take effect
  only if no device is in both electorates, which takes the administrator
  that outranks all others forked, or a recovery member excusing it on one side
  (section 3.15.4). The smaller event ID wins at every
  replica that holds both, and a replica's chain moves only to a smaller ID
  (section 3.15.4); a replica that forgot under the other holds what
  follows pending until it fetches the history from a replica that kept it
  or starts again from a snapshot (section 3.15.6).
- **Ranks.** No member acts on an administrator of a higher rank, or gives
  a rank above its own, and between equal ranks the more senior wins a
  duel (sections 3.5.2 and 3.6). A thief holding an administrator's device
  can therefore remove only members of its rank or below, and of its rank
  only those junior to it, whether or not it backdates, and whether or not
  a checkpoint follows; a removal of it by a member that outranks it
  stands against any counter-removal. A thief holding a device of the top
  rank, and the most senior one at that rank, the founder's in a space
  that gives 255 to no one else, wins the space: it outranks everyone.
  Keep the top rank to few, well-guarded devices, give day-to-day
  administrators a lower rank, and grant a recovery member (below).
- **A backdated checkpoint.** A removed administrator, or a thief holding
  an administrator's device, that saw the last checkpoint in effect can
  sign, on its view from before its removal, removals of other
  administrators, one per event, then a checkpoint. Its removals of a
  higher rank are void, so its record keeps those administrators, who
  refuse to vote for it (section 3.15.7); its removals of an equal rank
  senior to it leave those heard (section 3.15.4), and nobody it commands
  can excuse them: the checkpoint never takes effect, and the attacker
  gains nothing it could not gain before checkpoints. The honest
  administrators' own checkpoint, made after a member that outranks the
  attacker removed it, does not hear it, and takes effect. A thief that
  outranks every administrator it removes takes the space, as it already
  wins every duel; the honest checkpoint that removed it by a member it
  outranks hears it and waits for a recovery member's excuse.
- **What heard members cost.** An administrator removed by a member it
  outranks, that never returns, keeps every later checkpoint waiting until
  a member that outranks it, or a recovery member of its rank or higher,
  excuses it: the founder's lost device, removed by anyone, waits for the
  recovery member, and in a space without one the space checkpoints no
  more. A device that leaves on purpose removes itself first, which leaves
  nobody heard.
- **The recovery member** ([keys.md](keys.md), "The space recovery member")
  is an administrator marked `frasil.dormant`. The founder grants it the
  top rank, so that it can excuse and remove any member; marking it dormant
  or unmarking it is a change of an administrator, which only a member of
  its rank or higher may sign (section 3.6).
- **An older replica** that lacks a rule a later roster part type brings
  stops at that event's past (section 3.16) instead of judging concurrent
  events by older rules.

- **The backdated duel.** A removed administrator can sign a counter-removal
  of its remover onto history from before its removal. If its remover
  outranks it, the counter-removal is void and its remover's later work
  stands; if the remover is of its rank and junior to it, the
  counter-removal wins, the remover is out, and the remover's roster events
  concurrent with it are void; a lower rank can remove nobody above it at
  all (section 3.5.2). The chain bounds the reach to what the attacker saw
  after its own last signed event; an administrator that stayed silent
  keeps its reach. A client therefore removes a distrusted administrator by
  a member that outranks it, and the duel list shows what each duel voided.
- **A duel with a newly raised administrator.** The graph cannot tell an
  honest administrator that removes a writer while another administrator
  raises it, and is then removed by it, from a removed administrator that
  backdates; ranks decide it as any duel. If the honest one removed the
  writer in a batch, its removal is void. A client removes a member it
  distrusts in an event of its own.
- **The space recovery member.** A space recovery member, for which every
  rotation wraps, keeps someone inside able to derive the current key and
  to excuse a lost top-rank device. A space with one administrator has no
  duels.
- **Steering cycles.** An attacker that adds backdated events can turn a
  cycle the rules decide uniquely into one that rank and seniority decide. Step 3 of
  the procedure removes the cases where an event is void either way. What
  remains needs a cycle through authority, and each event in it needs an
  administrator's signature at its place.
- **Roster events from members that do not administer.** A reader, writer,
  guest or removed member can sign roster events that open and verify. One
  whose author no event in its past made an administrator has no standing
  (section 3.7): it never enters the contest, so any number of them neither
  raise the number of undecided events past step 3's bound, nor steer a
  verdict, nor cost more than a check of the event's past each. A removed
  administrator's events keep their standing, since its grant is in their
  past, and are contested like any other administrator's.
- **History handed over by a voided re-grant.** A re-grant "with history"
  delivers the history up to it. If a later merge voids it, the member keeps
  those keys; the granter held them and could have passed them on anyway.
- **The meet** lets an administrator lower a concurrent grant by granting
  less at the same time. Any administrator can lower a member anyway; the
  meet only means concurrency never raises a grant.
- **A device's keys.** A grant names a device by the device ID its keys
  give, so no member can make replicas check a device's signatures against
  a key of its own: a grant, void or not, that names the device's Ed25519
  key with another ML-DSA-65 key names another device ID. An adversary that
  can forge Ed25519 but not ML-DSA-65, a reader, a removed member or a
  person whose list a space reads, can sign events in full only as such a
  device of its own, which holds no grant and whose events are never
  evidence against the device whose Ed25519 key it reuses
  ([events.md](events.md), "Chains and evidence of a fork").
- **A grant of keys nobody holds.** A grant carries no proof that its
  device holds the private keys, so an administrator can grant a device ID
  whose keys it took from different parties: one device's Ed25519 key, say,
  with its own ML-DSA-65 and X-Wing keys. Such a member is a device ID of
  its own. Signing as it needs both its Ed25519 seed and its ML-DSA-65
  seed, and no single party holds both, so it signs no scheme-2 event. Only
  the device that holds the Ed25519 seed can sign a unit or a scheme-0
  structure as it, and only on purpose: an envelope binds `kc`, so none of
  the device's own events counts for it, and a unit by it opens nothing the
  device was not given. Its wraps go to the X-Wing key it names,
  so to whoever holds that key, which an administrator could have granted
  under a device of its own anyway. A granter that names another device's
  X-Wing key gives that device a wrap it may open but a member it cannot
  sign as. Such a grant therefore gives nobody a power that the granter's
  own `administer` does not already give, and misleads only a client that
  shows a member by its Ed25519 key, which a client MUST NOT do: it shows
  members by device ID, label or fingerprint. A quantum adversary that is
  also an administrator could sign as a member granted with a victim's
  Ed25519 key and its own ML-DSA-65 key; that member is still not the
  victim, and the administrator could have granted any device of its own
  instead.
- **Checks across logs.** A replica holding an older head of a person's list
  may accept a unit that another, holding the revocation and a response,
  refuses. They agree once they hold the same events. `administer` never
  comes through another log, so no roster event is judged differently.
- **A wrong-sealing author and a newcomer.** An author can seal a space event
  under a key of its own and commit to it. Members that hold the state find
  `BadSeal`. A newcomer opens it only if a sender hands it the author's own
  key, and the sender's signature on the snapshot makes that attributable:
  any member that holds the state can show the derived key differs. The
  newcomer's verdict stays provisional until it holds the state.
- **Refs and strangers.** Refs are sealed, so a peer cannot read the grant
  graph from them. An unresolvable ref holds only its own event and its
  author's later ones. A stranger's units and ignorable events are dropped,
  so strangers cannot make replicas store their events.
- **Twins only delay.** A peer that withholds a twin holds back the roster
  event and what follows it, as withholding the event would. It cannot
  substitute another twin. An author that never publishes its twin stalls
  only what follows its own event.
- **What a newcomer reads.** The body keys a "from now on" newcomer receives
  show it the space's membership history before it joined, along its grant
  path too, as [overview.md](overview.md) accepts (section 4.4). A body key
  yields no content key, so it opens no unit from before its break.

## 5. Test vectors

[roster.json](vectors/roster.json). Every device's keys derive from fixed
seeds by [crypto.md](crypto.md)'s fixture derivations, and every device
grant carries the device's keys. Every space event's body is a sealed
payload of [keys.md](keys.md) whose rotations carry their commitments and
read credentials. Key events pass keys.md's checks against the event and
its place: a key event that responds and rotates is a grant rotation. Each
notice's own checks, which decide no verdict, are
[keys.json](vectors/keys.json)'s. Unless a view says otherwise, each
replica holds every rotation's content key. Histories carry no storage events and no key 15:
their views take section 3.6, step 6, as passing.
[peers.json](vectors/peers.json) tests twins.

Each history gives its events byte for byte and one or more views (sets of
events held). Each view gives the status of every event with its class, the
roster with levels, history modes, capabilities, labels, sessions and
seniority hashes, the maximal valid rotations, the events that void each
void event, derived frontiers, duels with what each side voided, and
re-submissions. A history that reads other logs gives them byte for byte,
persons' lists and granted spaces' events, with their prefixes, and each
view says which events of each list it holds.

- `history_prefixes`: each history's prefix, from which its devices' seeds
  and its rotations' content keys derive.
- `labels`, `parameters`: the label crypto.md's registry gives roster.md
  (section 2.7), and the codes of section 2.
- `encodings`: a genesis with a space policy, a grant with capabilities and a
  label, a guest's grant, a demotion to read, a policy change and a removal,
  each body and signed event byte for byte.
- `descriptors`, `policies`: sections 2.5 and 2.6, descriptors with and
  without an application kind (one of 255 bytes among them), policies read
  back with their defaults, and refused ones with their class (an empty
  application kind, one of 256 bytes and one in bytes, and a text key,
  among them); descriptors a later document defines, of kind 3 and with
  keys 5 and 7, read and held (`held`).
- `held_spaces`: a genesis with descriptor kind 3, and one with descriptor
  key 5, each with a grant and an anchor after it, held
  `ExtensionRequired` while the genesis is valid; and grant edges to a
  space of kind 3, and to an ordinary space whose descriptor carries key 5,
  that never count (`GrantOfReserved`).
- `refused_events`: a base history and the events refused alone or at their
  place, with their class: roster-part shapes, a device grant without an
  ML-DSA-65 key, a device grant whose keys do not give its member ID
  (`NotCommitted`), a change that changes nothing, unsorted capabilities, a
  session on a person, a space granting itself, `replaces` without its
  removal, two policy changes, a default written in a policy, an invalid
  X-Wing key, `administer` to a person and to a guest, a self-removal that
  rotates, each authority class, more device grants than the limit (lowered
  for the vector), a policy change and a delivery sealed under a stale state
  (`StaleSeal`), a commitment to another key and a damaged sealed part
  (`BadSeal`), a state not in the event's past, and seven refused geneses.
- `concurrent_changes`: a removal against a concurrent change of its target;
  a self-demotion against a removal of its author; two removals of one
  member; a demotion against the demoted administrator's roster event and
  heal; a removal and a demotion of each other; concurrent grants (the meet)
  and concurrent demotions of one member; a change that raises a guest to
  `administer` (`AdministerNotDevice`), a raise concurrent with the grant
  that makes its member a guest, and a former guest re-granted without a
  session and raised; `AdminAlone`; history that ends
  with its grant; concurrent policy changes; `Full` counting only valid
  events (limit lowered).
- `bound_keys`: device keys bound by their hash, with an adversary that
  signs Ed25519 for an administrator's key and holds an ML-DSA-65 key of its
  own: a reader's void grant that names the administrator's Ed25519 key with
  that ML-DSA-65 key, which names another member and lends the
  administrator no key; an event signed in full by that key set, which is
  that other member's (`NotAnAdministrator`); the same under the
  administrator's own `kc` (`BadSignature`) at a `seq` the administrator
  used, which is no fork evidence, so the administrator's later removal of
  the reader stands; a removed member's rotation that does the same, and a
  re-admission signed by that key set; and a person's own list that adds
  the administrator's Ed25519 key with that ML-DSA-65 key, whose device the
  space takes as the person's and never as the administrator.
- `cycles`: an odd cycle; an even cycle with two allowed answers; a cycle
  through authority whose agreement step voids an event that the pick
  alone would make valid, beside a reader's chain of roster events after
  it, held in views with none of them, with as many as would bring the
  undecided events to 16, and with one more, all with the same verdicts
  for the contest; an odd
  cycle among administrators granted concurrently; and one whose grant
  rests on units, with a partial replica that holds the space events
  (`partial_replica`): the events it holds and witnesses, each height with
  the lower bound it has and whether it knows it, the verdicts that the
  lower bounds taken as heights would give, its pending verdicts, the
  events it fetches in each round, and its verdicts once it knows the
  heights.
- `duels`: a backdated counter-removal by a senior and by a junior attacker,
  with re-submission after the space recovery member re-grants; a genuine
  mutual removal; a counter-removal backdated before the raise of its
  remover, alone, in a batch, against a remover raised by a chain of two
  raises, and among a thief's events that look honest; an administrator's
  removal of a remover concurrent with its raise; a removed administrator
  that raises an accomplice to raise it back; concurrent self-demotions; an
  attacker that keeps its chain and one that forks it; a fork that cannot
  erase a self-demotion.
- `forks`: a unit that reuses a sequence number; a restore that writes before
  it syncs, and one that syncs first; a unit this replica cannot open
  (`Sealed`) that still proves a fork.
- `writes`: a unit concurrent with its writer's removal; a unit after a
  re-grant; a device the remover never knew through a person grant; a
  demotion to read against units and a heal.
- `key_histories`: the roster-level outcome (valid set, maximal rotations,
  voiding events, stability) of histories that
  [keys.json](vectors/keys.json) also tests: a cross-removal, a void
  rotation, a guest "from now on" with a key event that only delivers, a
  void input learned late, a removal outside the merged state, one removed
  member deriving the key, concurrent heals, a stale link across a break,
  history across a break's merge, a grant valid again, a member restored
  then removed again, and history whose only holders are out.
- `across_logs`: a person grant, a revocation in the list and the space's
  response, resolved also before the revocation and without the list
  (`Pending`, `NoHybridKey`); a fork in a person's list answered by a
  response; a response whose ref is unresolved, then resolved; a device
  revoked before its person's grant, with and without the list's heads in
  the grant; a device that left a granted team before the grant; notices
  that decide no verdict (a grant carrying a notice its author cannot give,
  a response with its notice, one with a notice of a key the team did not
  commit to, and a key event that cites the team with no notice,
  `NoticeRequired`), alike at a replica holding the team's log as one
  member holds it, at one also holding a concurrent removal that voids the
  noticed rotation, and, but for the key events waiting on their refs
  (`Pending`), at one holding none of it, each view with the team's events
  it holds (`team_held`) and the principals it admits; two key
  events that each respond to the end of the other's author; a device rooted
  in a recovery agent (`WaitingDevice`, its unit accepted, valid after a
  confirm); one whose only path is a granted team that grants its person
  (`WaitingDevice`), valid once the team grants it directly; a granted space reached through a device grant and a person
  grant, a guest that does not propagate, and a removal in the team
  answered by a cascade, with its derived frontier, from a member of both
  spaces whose grant rotation carries a notice of the team's rotation;
  removing a granted space while a member is granted directly; a guest of
  a granted team at `write` that also reaches it at `read` through a
  person, and its mirror, with the space's effective membership
  (`effective`: each device's level and its level over the paths that
  propagate); `replace` with the old person's administering device;
  anchors and ignorable events from a member (kept) and a stranger
  (`Dropped`); a unit whose refs are unresolved; a unit refused as
  `NotAWriter` through a writer's grant, which no event voids, so that its
  author, granted later, does not re-submit it.
- `grant_graph`: two concurrent grants that close a cycle; a chain of ten
  spaces where exactly one edge stops counting; a grant of a restricted
  space; and guest grants inside a granted space, which pass on nothing
  through it, neither a path nor capabilities, even at the level of a
  path that propagates (sections 3.3 and 3.11, "Paths").
- `effective_membership`: a team of persons, an administrator device and a
  guest, and projects that grant it at `write` and at `read`: every space's
  effective membership with levels, propagation, capabilities by mode and
  depth, and every edge's verdict; and (`propagating_paths`) a team in
  which one device is a guest at `write` and reaches it at `read` through a
  person, another a guest at `read` and at `write` through a person, and a
  project that grants the team at `write`, each device with its level over
  the paths that propagate.
- `unopened_events`: a member admitted "from now on" judging the space with
  no body keys (the genesis `Sealed`), with those of its admitting grant's
  past, with every body key it cannot derive, and with one wrong key; an
  author that seals a policy change under a key of its own, `BadSeal` at
  members, applied provisionally by a newcomer handed that key, and held by
  a newcomer handed the derived key or both; a delivery under a merged
  state opened with the merged key received whole, and held under a wrong
  one. Each gives the rotation keys and body keys its views hold.
- `stability`: a removal before and after every administrator has signed
  after it.
- `refused_unit`: section 3.14's decision at and around each bound, for the
  author and for others.
- `checkpoints`: a history with a checkpoint by the founder, an
  administrator's grant concurrent with it (late once the administrator
  votes), a unit and a removal after it; the record byte for byte, its
  digest and its fields read back; the verdicts of a replica that holds
  everything and of one that holds only the checkpoint and what follows,
  which agree; a roster part of type 3 that holds itself, a concurrent
  grant and everything after both (`freeze`); thirteen records that do
  not read, each with its class, among them a record key 9, a member-entry
  key 22 and a member type 4, each `ExtensionRequired`, before a malformed
  entry beside it is read, and four with faults far apart, which a reader
  that reads as the record streams meets out of the steps' order: a key 22
  first and an integer not in its shortest form last (`Malformed`), a
  member type 4 first and a malformed tip last (`ExtensionRequired`), keys
  of another device first and an invalid key last (`InvalidKey`), and the
  first and last entries swapped (`Malformed`) (`record_refusals`); record
  objects of 256-byte chunks that read alike whole and by chunks, with the
  checkpoint's outcome: a record that uses key 22 in its first chunk
  (`ExtensionRequired`), the same with a last chunk that does not open
  (`Decrypt`), under another plaintext's object ID (`ObjectMismatch`), or
  bound by another digest (`BadCheckpoint`), each a `BadCheckpoint`, and
  stored bytes cut at a chunk boundary (`ObjectMismatch` at step 0, the
  object fetched again) (`record_object_order`); for each of those three, a
  checkpoint whose record uses it, held as `ExtensionRequired` with the
  event after it, in effect nowhere, and a newcomer that does not start
  from it (`extension_required`); a writer's checkpoint whose record uses
  key 9, concurrent with the founder's, a rival that holds everything at
  a replica that forgot under the founder's, and `NotAnAdministrator` at
  one that holds its past (`extension_rival`); two checkpoints after a
  first one in effect, whose records use key 9 and name it as predecessor,
  a writer's `NotAnAdministrator` and an administrator's held
  `ExtensionRequired` (`extension_after_predecessor`); three units of a
  checkpoint's past whose authors are lowered, raised and removed before
  it, each with its verdict and its author's capabilities at its place,
  which a replica that forgot freezes, with its attribution and the
  labels of then, one relabelled and one removed since, and no
  attribution for the voided one, which no event voids, beside the
  record's standing it must not read for them (`frozen_content`); a raced invite whose key
  the record shows raced, so that its claim after the checkpoint is
  `InviteUsed` at both replicas and its revocation valid (`raced`); and a
  granted space whose "from now on" response the record keeps as a notice,
  a floor and a name, its principal the same before and after the
  checkpoint, at both replicas (`granted`). A replica that forgot holds
  the genesis, the checkpoint, the envelopes its cuts reach, the late
  events and the events after it, and nothing else.
- `procedure_tables`: section 3.7 over events, attacks and authority given
  as tables rather than signed events: each event with its parents, in
  canonical order; each attack that counts, with its class; each authority
  rule, failing with its class unless (`needs`) or while (`bars`) another
  event is valid; the seniority order; the assignments step 3 allows, in
  order; and each event's verdict. One case: an event that step 3 voids,
  whose authority holds and which nothing attacks once the picks are made,
  stays void with its class from the first allowed assignment.
