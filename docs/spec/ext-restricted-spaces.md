# Restricted spaces and carve-outs
Protocol 1. Vectors: [ext-restricted-spaces.json](vectors/ext-restricted-spaces.json).

This extension specifies two kinds of space that a descriptor names. A
**restricted space** is a private part of a **parent** space: its members
must reach the parent, and its content key derives from the parent's. A
**carve-out** gives a guest one document of a larger space, in a new space
that grants the larger one. The extension also specifies the **move record**
that points from a document's old stream to its new one, late writes to a
moved document, and their re-application.

It extends [roster.md](roster.md) (descriptor kinds 1 and 2, effective
membership), [keys.md](keys.md) (a restricted space's secrets, sealing and
heal test), [units.md](units.md) (the restricted key reference, the
`frasil:move` type, sealed key 4 `copied_from`, stream snapshot key 6
`moved`, and the adapter's `reapply`) and [transport.md](transport.md) (a
restricted space's member key). It uses [overview.md](overview.md)'s
conventions, [crypto.md](crypto.md)'s primitives and labels, and
[admission.md](admission.md)'s newcomer's snapshot.

**A core implementation that lacks this extension:**

- holds every event of a space whose descriptor is kind 1, after it has read
  the descriptor, as `ExtensionRequired`, and never creates one. It still
  refuses every grant of a restricted space (`GrantOfRestricted`,
  [roster.md](roster.md));
- treats a carve-out (kind 2) as an ordinary space, and mirrors nothing;
- keeps a `frasil:move` unit and ignores its content (`UnknownAdapter`),
  copying it into a stream snapshot's key 6; and ignores sealed key 4.

## 1. Overview

- A restricted space F names its parent P in its genesis's descriptor. A
  device reaches F only if it also reaches P. No space grants F, and F has
  no grant key. Restrictions do not nest.
- F's rotations draw F's own secrets. F's content key is derived with F's
  secret as the HKDF salt and P's content key as the input, so a member of
  P outside F learns nothing of it, and a device removed from P loses F's
  next key with P's next key. F never rotates for P.
- F's space events, read credential, upload key and member key derive from
  F's own secrets only, so they do not move when P rotates.
- A carve-out N of P grants P, is administered by P's administrator
  devices, and admits a guest "from now on". The document moves from P to
  N; its old stream ends in a move record, and P's index points to N.

## 2. Formats

### 2.1 Descriptors

The descriptor is [roster.md](roster.md)'s: `kind` 1 with `parent` P for a
restricted space, `kind` 2 with `parent` P for a carve-out. It never
changes.

### 2.2 A restricted space's secrets and keys

Each rotation `R` of F draws a 32-byte content secret `f_R` and a 32-byte
upload seed `fw_R`, and no grant seed. `f(S_F)` and `fw(S_F)` merge them for
a state `S_F` of F exactly as [keys.md](keys.md) merges `k` and `w`, with
F's space ID. F's **content key** for `S_F` and a state `S_P` of P:

```text
k_F(S_F, S_P) = HKDF(salt = f(S_F), ikm = k_P(S_P),
                     info = "frasil/restricted-key/v1" || field(F) || field(P))
```

`S_P` is P's content state in the writer's view when it seals. In F, each
use of a state's secret becomes:

| Use ([keys.md](keys.md), [units.md](units.md), [transport.md](transport.md)) | In F |
|---|---|
| A space event's body key: `secret` | `f_R` in a rotation; `f(S_F)` of `sealed_under` otherwise |
| Read credential; upload key | from `f(S_F)`; from `fw(S_F)` |
| Bundle slots; links and gap keys | content `f(S_F)`, upload `fw(S_F)`, no grant slot; links carry `f` |
| Grant commitment (visible key 3) | 32 random bytes: F has no grant rotation |
| Member key `hk` | from `f(S_F)` |
| `k(S)` for unit, object and metadata keys | `k_F(S_F, S_P)` of the key reference |

- A rotation's own delivery has key 1, `self_ref`, and no key 2, and its
  sealed part carries no key 1. A bundle sets only flags `0x01` and `0x02`.
- A space wrap that F makes for a space F grants carries `f(S_F)` and, for
  a grant at `write`, `fw(S_F)`, and no grant slot.

### 2.3 The restricted key reference

A unit, object or sealed name of F names its state by:

```text
reference  = encode_set(S_F) || nonce (24)
             || XChaCha20-Poly1305(parent_key, nonce, encode_set(S_P), aad)
parent_key = HKDF(salt = none, ikm = f(S_F), info = "frasil/parent-reference/v1")
aad        = "frasil/parent-reference/v1" || field(F) || encode_set(S_F)
```

The nonce is random. A reference of `a` own and `b` parent rotations is
`42 + 32(a + b)` bytes, each of `a` and `b` from 1 to 64. Only a holder of
`f(S_F)` learns which state of P a unit uses.

### 2.4 The move record

A deterministic CBOR map:

| Key | Field | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `to_space` | bytes(32): the space the document moved to; required |
| 3 | `to_stream` | bytes(16): its stream there, not all zero; required |
| 4 | `name` | text, 1 to 1,022 bytes of UTF-8: a cached name; optional |

- The **move unit** is a unit of the original stream whose sealed `type` is
  `frasil:move` and whose content is the move record. Its opening (sealed
  key 6) is the stream's own, so it passes [units.md](units.md)'s stream
  check.
- The **pointer** is the same map, as the value of the document's entry in
  the original space's index document. The index's own format is the
  application's.
- A unit that re-applies a late write carries `copied_from` (sealed key 4)
  `[original space ID, the late write's event ID]`.

Labels used: `frasil/restricted-key/v1` and `frasil/parent-reference/v1`
([crypto.md](crypto.md)).

## 3. Procedures

### 3.1 The parent of a restricted space

A replica judges F's genesis only once it holds P's genesis, among the logs
it holds. Until then F's genesis, and every event of F, is `Pending`. If P's
descriptor is kind 1, F's genesis is `RestrictedParent`, final, and so is
every event of F, so F has no members. A client MUST NOT create a
restricted space or a carve-out under a restricted space, and creates a
restricted space only under a space its own device reaches.

### 3.2 Reading a restricted key reference

In place of [keys.md](keys.md)'s "Reading a unit's key reference", in
order:

```text
1. The reference starts with a rotation set S_F.            else Malformed / TooManyRotations
2. The rest is 41 + 32b bytes, with 1 <= b <= 64.           else Malformed / TooManyRotations
3. The reader holds f(S_F).                                 else Sealed (held)
4. The rest opens under parent_key, with the nonce and
   aad of section 2.3.                                      else Decrypt
5. The plaintext is a rotation set S_P of b rotations.      else Malformed
6. Every ID of S_F is a rotation of F, and every ID of
   S_P a rotation of P; a missing one is fetched, and
   the unit waits.                                          else NotARotation
7. No ID of S_F or of S_P is in the past of another of
   the same set.                                            else Malformed
```

Reading a sealed name's record of F, [keys.md](keys.md)'s step 4 reads this
form (a plain rotation set is `Malformed`), and step 5 needs both `f(S_F)`
and `k_P(S_P)` (`MissingState`). A reader that does not yet hold F's
genesis, such as a newcomer opening its snapshot, takes as P the held space
whose log holds every rotation of `S_P`; F's genesis, once held, decides.

### 3.3 Membership of a restricted space

- **Effective membership.** F's effective membership is that of F's roster
  by [roster.md](roster.md), keeping only devices that also reach P, each at
  the lower of its two levels, and propagating only if it propagates in
  both. A replica that does not hold P's roster cannot compute it, and what
  depends on it waits as roster.md's checks across logs say.
- **Authority.** Who may sign F's roster events is roster.md's, from F's
  roster alone, so resolving F's roster never waits on P's log.
- **Writes.** For roster.md's checks across logs, P is on every path into
  F: an event, in P's log or in a log P's paths depend on, after which a
  device no longer reaches P at `write` and propagates, as through a granted
  space, ends each of its paths in F, and an event of F whose refs name that
  end is a response to it.
- **Never granted.** An edge to F never counts (`GrantOfRestricted`). F may
  grant spaces, devices and persons; its grant of a space delivers nothing
  to that space's members that do not reach P.
- **Mirroring P's removals.** When a valid roster event of P removes a
  member that F's roster grants, the candidates, F's administrator devices
  that reach P, each wait their rank delay ([keys.md](keys.md), "The rank and
  the delay") with P's event as the trigger. The first removes the member
  from F, with P's event in the refs, which rotates F. A candidate drops its
  mirror when it holds a valid roster event of F whose refs name P's event.

### 3.4 Keys of a restricted space

- **When F rotates.** By keys.md's rules, applied to F's membership before
  it is narrowed by P's: a removal or demotion to `read` in F, a revocation
  in the list of a person F grants, a loss in a space F grants. F never
  rotates for a change of P, which already denies the removed device P's
  next key.
- **Checks against the event and its place.** In F, keys.md's step 5
  refuses every grant rotation (`GrantKeyNotAllowed`), so step 6 requires
  none. A response of F to a space F grants rotates without a grant key and
  still carries its notice.
- **The heal test.** F's outside holders count only if they are inside P's
  merged roster: a device outside P cannot derive `k_P` of P's current
  state, and P's own heal test covers it.
- **Collapsing.** F collapses its own state by keys.md's rule. The parent's
  state in a reference is P's to collapse.
- **Peers.** To a peer, F is a space like any other: its rotations commit to
  credentials of their own, and P's rotations never touch them
  ([peers.md](peers.md)).
- **Connections.** A device attaches F only on a connection where it has
  attached P, with F's own member key, and the roster check uses F's
  effective membership ([transport.md](transport.md)). That order binds the
  attaching device; a receiver has no refusal for it and checks F's attach
  as any other. A device never announces F on a local network.
  [ext-ephemeral.md](ext-ephemeral.md) says how F's frames name its state.
- **Names.** F's name may be kept in P as a name of kind 1 sealed under P's
  state ([keys.md](keys.md), "Sealed names"), since every member of F is a
  member of P.
- **Checkpoints.** F and P each have their own ([roster.md](roster.md),
  "Checkpoints"), and either may take effect while the other has none.
  F's checkpoint is no grant rotation. F reads P's roster as the replica
  holds it, from P's kept checkpoint on, and its record lists F's own
  members only. A replica that forgot P's events before P's kept
  checkpoint keeps P's content keys of every state that F's retained
  events, units and names name in their restricted references; after P's
  checkpoint, F's events seal under P's states of P's world, as a writer
  of P does. A carve-out checkpoints as any space.

### 3.5 Creating a carve-out

A writer of P whose grant propagates creates N for a guest and one
document, in this order:

1. **The genesis.** Its founder change grants the creator's device
   `administer`. It carries the descriptor kind 2 with `parent` P, and a
   grant rotation whose only wrap is the creator's own.
2. **The first update,** one roster event that grants:
   - P, at `write` if P's writers could write the document and at `read`
     otherwise, "with history", `via` = `none`;
   - `administer` to each other administrator device of P in the creator's
     view, "with history", `via` = `none`, with the keys and proof from P's
     grant of it;
   - the guest's device, "from now on", with `session` set, the keys and
     proof that its admission gave ([admission.md](admission.md)), and the
     `via` of that admission.

   The guest makes the event a break; it is not a grant rotation, and it
   names its twin ([roster.md](roster.md)). As [keys.md](keys.md)'s
   deliveries require, its own delivery carries the genesis's grant state
   (sealed key 1) in bundle wraps for the administrator devices, and the
   new state to the guest without a grant seed; a space wrap for P to P's
   current grant rotation, with its notice; a second delivery, of the
   genesis's state, with a space wrap for P, so that P's members can open
   the genesis; and the gap record of the genesis's state. When P's grant
   state holds several rotations, the creator first collapses it in P.
3. **A creator that does not administer P** then lowers its own grant in N
   to `write`, in a self-lowering event.

Nothing rotates in P. The creator seals the document's history-free
snapshot under N's state as the seed of a new stream of N, with a fresh
salt and the same adapter type ([units.md](units.md)); seals its objects
again under N's state; writes the document's name in N's index; writes the
pointer in P's index; and writes the move unit in the original stream
(section 3.7).

A member of P that propagates there reaches N at the lower of N's grant of
P, its level in P and `write`, with capabilities by roster.md's rule for
paths through a space. Administering N comes only from N's own grants.

### 3.6 Carve-out administration and the guest

- **Mirroring P's administrators.** When a valid roster event of P grants
  `administer` to a device, or ends a device's `administer` in P (for N's
  creator, as below), the candidates, N's administrator devices that reach P, each wait their rank
  delay with P's event as the trigger. The first grants the new device
  `administer` in N with the keys and proof of P's grant, or removes the old
  device's direct grant, with P's event in the refs. A removal from P that
  also costs N a device through its grant of P is mirrored and answered in
  one roster event, which rotates. A candidate drops its mirror when it
  holds a valid roster event of N whose refs name P's event.
- **N's creator** is mirrored as any other device N grants directly. While
  N grants it `administer`: if a valid roster event of P has ever granted
  it `administer`, an event of P that ends its `administer` there is
  mirrored as above; if none has, it steps down by itself (section 3.5,
  step 3), and only an event of P that removes it or leaves it below
  `write` is mirrored. Once it has stepped down, N grants it `write`, and an
  event of P that removes it or leaves it below `write` is mirrored. Each
  mirror removes its direct grant, so that it reaches N through P alone,
  if at all.
- **The guest is never mirrored:** P never granted it, so no event of P
  ends anything of it in N. It leaves as below.
- **The guest's snapshot.** The creator publishes the guest's space snapshot
  ([admission.md](admission.md), "The newcomer's snapshot") right after the
  first update. Its log entries along N's grant path carry P's genesis and
  every roster event, response and skeleton event of P that the creator
  holds, with their body keys, and the same for every space P grants, with
  the lists of every person those rosters name. The guest reads P's
  membership history so that it can check writers in N.
- **The guest leaves** when an administrator of N removes it. N rotates its
  content key only; nothing else rotates, since the guest never propagated.

### 3.7 Moved documents

**Reading a move record,** whether in a move unit or a pointer, in order:

```text
1. It is a deterministic CBOR map, and key 1 is an unsigned integer.    else Malformed
2. Key 1 is 1.                                                          else UnsupportedVersion
3. Keys 1 to 4 only; keys 2 and 3 present; each as section 2.4.         else Malformed
```

A move unit whose record fails is a content refusal with that class: the
unit stays valid and the stream is not moved.

- **A moved stream.** A replica shows a stream as moved once it holds an
  accepted move unit of it, or a stream snapshot whose `moved` holds a
  record that passes. A device that has the document open follows the
  pointer when it learns of the move, if it reaches `to_space`.
- **Late writes.** A unit of the original stream, a move unit aside, that
  is in the past of no accepted move unit is a **late write**. It is valid
  in its space, since a move changes no roster, and adapters show it as
  written after the move.
- **Re-applying a late write.** The late write's author, if it reaches the
  new space at `write`, re-applies it once it holds an accepted move unit.
  Re-applying is writing, in the new stream, a unit of the author's own
  whose content is the adapter's `reapply(original state, late write, new
  state, writer)`, `writer` being the place of that unit
  ([units.md](units.md), section 3.17), and whose `copied_from` names the
  late write. The author MUST NOT re-apply a late write when it holds a
  unit of the new stream whose `copied_from` names it. Any other device
  MUST NOT re-apply it, and never re-signs another device's unit, so a late
  write has one re-application at most and shows once in the new stream.
  When the author does not reach the new space at `write`, or `reapply`
  returns nothing, the late write stays in the original stream only.
- No replica refuses a unit for its `copied_from`, which names a unit of
  another space that the replica may not hold.

### 3.8 Error classes

Besides [overview.md](overview.md)'s, and those of the core documents this
extension changes:

| Class | Meaning | Sort |
|---|---|---|
| `RestrictedParent` | a restricted space whose parent is restricted | final |

## 4. Security considerations

- **A member of P outside F** holds `k_P` but not `f(S_F)`, and HKDF-Extract
  keyed by `f(S_F)` gives it nothing of `k_F`. It learns that F exists, and
  F's name if P's index keeps it.
- **A device removed from P** loses P's next key, so it opens no unit of F
  sealed under a later state of P. Until the mirror lands it keeps F's
  current read credential and upload key: it can fetch F's ciphertext and
  spend F's quota, and a re-grant to P would bring it back into F. Its units
  in F stand until F responds to its end, as across any log. A device
  removed from F but still in P holds F's old secrets, so F rotates.
- **A space F grants** gives its members that are outside P F's read
  credential and upload key through the space wrap, and nothing they can
  open.
- **What a peer learns.** F's units carry the longer reference and its own
  deliveries name no grant state, so a peer tells a restricted space from
  another space, but not which space is its parent.
- **A carve-out's guest** reads the membership history of P and of the
  spaces P grants. An application that must not show P's membership to the
  guest shares the document another way.
- **Mirrors are eventual.** A new administrator of P does not administer N
  until a mirror lands. An administrator removed from P stops reaching N
  through P at once, and keeps its direct `administer` in N until the
  mirror; so does N's creator, with its direct `administer` or `write`. With an administrator device of N online, the rank delay keeps
  this to seconds.
- **Late writes** stay in the original space, readable by its members; only
  re-application brings them to the new space, under their author's own
  signature. A late write whose author cannot write in the new space never
  reaches it.

## 5. Test vectors

[ext-restricted-spaces.json](vectors/ext-restricted-spaces.json):

- `restricted_keys`: rotations of F and P with their secrets; F's content
  key for single and merged own and parent states, with the HKDF info and
  PRK; F's read credential and upload key; the parent-reference key, nonce
  and sealed key reference.
- `reference_refusals`: a parent state opened with another own secret
  (`Decrypt`), a reference one byte short and one with no sealed parent
  state (`Malformed`).
- `restricted_space_event`: a rotation of F sealed under `f_R`, with its
  body key, commitment and payload.
- `restricted_names`: F's state under the parent state `A+B` with its
  metadata key; a document's name sealed in F; a record of F whose
  reference is a plain set (`Malformed`).
- `restricted_parent`: a restricted space whose parent's genesis is not yet
  held (`Pending`), and one whose parent is restricted (`RestrictedParent`).
- `restricted_membership`: the reference deployment's F, with a person who
  is not in P: F's effective membership, narrowed by P, with levels and
  propagation.
- `restricted_rotations`: for seven changes in the deployment, whether F
  rotates, and why.
- `carve_out`: P's grant key and grant rotation; N's three roster events
  (genesis, first update, the guest's removal) with every secret, wrap,
  notice, nonce and commitment; a member of P opening N's genesis through
  the second delivery; the guest's wrap found by trial, without a grant
  seed; each member of P's level in N; N's effective membership; the
  document's streams, move record and pointer.
- `move_records`, `move_record_refusals`: two records, and six refused.
- `late_writes`: a stream with a move unit and late writes; which units are
  late; which of them their authors re-apply; and a re-applied unit's
  `copied_from`.
