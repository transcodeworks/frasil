# Invite links
Protocol 1. Vectors: [ext-invite-links.json](vectors/ext-invite-links.json).

This extension admits someone by a link, with no administrator online. An
administrator grants an **invite key** derived from a random secret, and
whoever opens the link signs a **successor** as that key: a roster event
that hands the invite's grant to the claimant. It extends
[roster.md](roster.md), [events.md](events.md), [keys.md](keys.md),
[transport.md](transport.md), [peers.md](peers.md) and
[at-rest.md](at-rest.md) through the hooks they reserve, and uses
[admission.md](admission.md)'s newcomer snapshot and top-ups.

A core implementation that does not implement it:

| What this document defines | A core implementation |
|---|---|
| Member type 3, op 4, change key 14, change key 13 on a grant of type 3, a successor's authority, the race rule, attack (d) | never signs them; holds a roster event that carries one as `ExtensionRequired`, with every event after it ([roster.md](roster.md), section 2.3), so it cannot use a space past an invite grant |
| What an invite key receives, its flags, inside and entitlement | nothing: it holds every event that needs them |
| A checkpoint record's invite entries (member type 3, keys 14 to 17, [roster.md](roster.md), section 2.8) | never derives one, since it holds every event after an invite grant |
| Mailbox kind 4, `MailboxPut` keys 4 and 5 | refuses kind 4 as `Malformed`, and on the server binding answers 404 `not_found` ([transport.md](transport.md)) |
| Message type 28, `MailboxDelete` | closes the connection, `UnknownMessage` |
| Tables `0x18` and `0x19` | never writes them ([at-rest.md](at-rest.md)) |

## 1. Overview

- The **invite grant** gives the invite key `K`, derived from a random
  secret and named by its device ID, the grant a claimant will receive,
  and delivers a state to `K`.
  The **link** carries the secret, the grant's event ID (the **invite
  entry**) and the space ID; the **drop** keeps `K`'s wrap at peers.
- The claimant signs one **successor** as `K`. A valid one puts `K` out and
  gives the claimant the invite's grant. `K` then counts as outside, so a
  writer heals: a leaked link reads only what was written while the invite
  was open. The claimant, a member of its own, is wrapped for under its
  own keys.
- An administering device that holds a valid successor **closes** the
  invite. Concurrent successors void each other unless a close shields
  one. Expiry is enacted by a signed revocation.

## 2. Formats

### 2.1 The secret, its keys and the link

```text
seed(info)     = HKDF(salt = "frasil/invite/v1", ikm = secret, info)
Ed25519 seed   = seed("ed25519")
X-Wing seed    = seed("frasil/invite/hybrid/v1")
ML-DSA-65 seed = seed("frasil/invite/mldsa/v1")
locator        = seed("frasil/invite/locator/v1")
drop key       = seed("frasil/invite/drop/v1")

fragment = base64url, without padding, of
           u8(1) || secret (32) || invite entry (32) || space ID (32)    97 bytes
```

- The secret is 32 bytes from the inviting device's random source. An
  invite key has no X25519 key. Its three public keys give its `kc` and its
  device ID ([crypto.md](crypto.md), "A device's keys"), as a device's do;
  `K` is that device ID.
- The fragment, 130 characters, follows `#` in a link whose base the
  application chooses, so a browser never sends it to a server. Reading,
  in order: base64url characters only, and bytes that re-encode to the
  same text (`Malformed`); byte 0 present and 1 (`UnsupportedVersion`); 97
  bytes (`Malformed`).

### 2.2 The invite grant and the successor

An **invite grant** is an op-0 change whose member is `[3, K]`:

| Key | Field | Rule |
|---|---|---|
| 2 | `level` | required: `read` or `write`; `administer` is `AdministerNotDevice` |
| 3, 4 | `capabilities`, `label` | optional, as [roster.md](roster.md) |
| 5, 6 | `history`, `via` | required; `via` is 1 |
| 7 | `session` | optional: a guest invite, whose `claims` is 0 |
| 9, 10, 12 | keys | required: the invite key's X-Wing, ML-DSA-65 and Ed25519 keys, which give `K` |
| 13 | `expires_at` | required |
| 14 | `claims` | required: 0, a device claims it; 1, a person does |

Keys 8 and 11 are absent. Replicas check the keys as a device grant's
([roster.md](roster.md), section 3.4.1, step 9): valid, and giving `K`
(else `NotCommitted`). A successor's signature verifies under them, by
their hash, as any author's (roster.md, section 3.4.2). `[3, K]` appears
only in a grant, in a removal and as a successor's author; a change (op 1)
of it is `Malformed`.

A **successor** is a space event by `K` whose roster part is an update of
exactly one change, `{0: 4, 1: claimant}`, the claimant being `[1, person
ID]` or `[0, device ID]`, with keys 9, 10 and 12 exactly for a device.
It does not rotate and carries no `break`; an op-4 change beside another
change is `Malformed`. Its sealed refs SHOULD hold the claimant's list
heads ([roster.md](roster.md), "Checks across logs"). Its delivery wraps the newest
state `K` holds for the claimant's devices, and it is sealed under it.

### 2.3 The drop and its messages

```text
address   = SHA-256("frasil/mailbox/v1" || u8(4) || field(locator))
plaintext = CBOR {1: 1, 2: key name (bytes), 3: grant key name (bytes; empty if none),
                  4: K's bundle wrap in the invite entry (1,236),
                  5: [peer hints: 0 to 8 texts of 1 to 512 bytes],
                  6: snapshot (64; optional)}
drop      = nonce (24 random bytes)
            || XChaCha20-Poly1305(drop key, nonce, plaintext,
                                  aad = "frasil/invite/drop/v1" || locator)

MailboxPut, kind 4 = {0: 24, 1: request, 2: address (32), 3: drop,
                      4: space ID (32), 5: lifetime (seconds, 1 to 604,800), 6: 4}
MailboxDelete      = {0: 28, 1: request, 2: address (32), 3: space ID (32), 6: 4}
```

- The key names are those of the invite entry's delivery. Peer hints and
  `snapshot`, the locator of the snapshot for `K`, are as in a welcome
  ([admission.md](admission.md)). Opening, in order: 40 to
  65,536 bytes (`Malformed`); the AEAD opens (`Decrypt`); the map reads
  (`Malformed`); key 1 is 1 (`UnsupportedVersion`).
- `MailboxDelete` travels on the control stream; both messages are
  answered by `Accepted` or `Refused`. `MailboxGet` of kind 4 has no keys 4
  and 5, and `MailboxItems` carries the drop as its one item
  ([transport.md](transport.md)), whose item ID is 16 zero bytes. A
  `MailboxGet`, or a `GET` on the server binding, that gives `after`
  receives no item.
- On the server binding, `GET /frasil/p1/mailbox/4/{address}` serves a drop
  to anyone; a `POST` to kind 4 is 403 `credential_refused`, since a drop is
  placed and deleted only over the WebSocket. A peer without this extension
  answers 404 `not_found` for mailbox kind 4.

### 2.4 Records at rest

Two log tables of [at-rest.md](at-rest.md), item the invite entry, value
`space ID (32) || invite entry (32) || secret (32)`:

- `0x18`, `invite`: kept by the inviting device from the commit of the
  invite entry until it holds a valid removal of `[3, K]` and its drops
  are deleted or expired.
- `0x19`, `claim`: kept by the claimant from the commit of its successor
  for as long as it holds the space's log.

A claimant holds the space's log from the claim's start, before it signs:
it keeps the invite entry as the log's `state` key 6
([at-rest.md](at-rest.md)) from that start, and clears it in the commit of
its successor. A log whose `state` names a claim and holds no `claim`
record is a claim that never finished, the device having stopped before
the person decided: the device forgets the log when it next opens, as
section 3.2's step 10 would on a refusal, through the space's object
provider where it holds objects ([at-rest.md](at-rest.md), "Held
objects"). Until it signs, the device lists the space
nowhere; a claim that fetches the space from peers presents it to them
with the fetch key, as section 3.2, step 4, says, and one that holds the
space already, from a space file, presents it to none.

### 2.5 Labels and error classes

Labels, from [crypto.md](crypto.md)'s registry: `frasil/invite/v1` with the
purpose string `"ed25519"`, `frasil/invite/hybrid/v1`,
`frasil/invite/mldsa/v1`, `frasil/invite/locator/v1`,
`frasil/invite/drop/v1`; and `frasil/mailbox/v1`,
`frasil/device-keys-commitment/v1`, `frasil/device-id/v1` and
`frasil/bundle-wrap/v1` as their documents use them.

| Class | Meaning | Sort |
|---|---|---|
| `NotAnInvite` | a successor whose author is not an invite key in the roster at its place | final |
| `InviteUsed` | a grant of an invite key already named, or a successor with a successor of its key in its past; at a claimant, an invite already claimed | final; decision at a claimant |
| `ClaimMismatch` | a claimant of another type than the invite's `claims` | final |
| `ClaimRaced` | a successor that a concurrent successor of its key voids (section 3.4) | final |
| `WrongInvite`, `NoWrap`, `NotInRoster` | a fetched entry that is not the link's or grants another key; a wrap that does not open; an entry not valid | decision |
| `InviteRevoked`, `InviteRaced` | the invite key was removed, or its claims raced | decision |

A peer's checks (section 3.1) also use `CredentialRefused`, `Conflict`,
`QuotaExceeded` and `NotFound`. Their codes, `credential_refused`,
`conflict`, `quota_exceeded` and `not_found`, are [peers.md](peers.md)'s and
[transport.md](transport.md)'s.

## 3. Procedures

### 3.1 Making an invite and keeping drops

The inviting administrator's device draws the secret and derives the keys
and `K`. It signs an update that grants `[3, K]`, with
`expires_at` its wall clock plus `link_lifetime` ([overview.md](overview.md),
section 6.8). An invite "from now on" rotates with a `break`, delivering the
new state to `K` and every member device; any other invite need not rotate,
and delivers the current state to `K`. The secret, the event and the
`invite` record go in one commit. It then publishes the event, and, for an
invite "from now on", a space snapshot for `K` under the state `K`
receives, with what [admission.md](admission.md) requires of a newcomer's
snapshot, as its section 3.11 publishes one, with the drop in place of the
welcome; places the drop at one or more peers, with a lifetime of
`expires_at` less its wall clock; and shows the link.

A peer, on `MailboxPut` of kind 4, in order:

```text
1. Keys 2 and 4 are 32 bytes; key 5 is 1 to 604,800.            else Malformed
2. The drop is at most 65,536 bytes.                            else TooLarge
3. The connection holds the store right for key 4's space.      else CredentialRefused
4. No drop is held at the address.                              else Conflict
5. The space stays within its quota.                            else QuotaExceeded
```

It keeps the drop for its lifetime plus 60 seconds of its own timeline,
counts it in the space's usage meanwhile ([peers.md](peers.md)), and serves
it to anyone who names the address. It records the upload entry the drop
was placed under; `MailboxDelete` removes the drop only on a connection that
proved that entry (else `CredentialRefused`; `NotFound` if none).

### 3.2 Claiming

The claimant's device has a person, and makes one if it has none
([identity.md](identity.md)); a device that claims for itself needs none.
In order:

```text
 1. The fragment reads; derive K's keys, the locator and the drop key.  else its class
 2. Fetch the drop from a peer (the link's host, a hint, or any peer
    it knows) and open it.                                              else its class
 3. The drop's wrap opens with K's X-Wing seed, for the space ID, the
    drop's key names and recipient K, the invite key's device ID
    (keys.md).                                                          else NoWrap
 4. With that state's read credential, fetch the snapshot for K by the
    locator the drop names, if any, then the invite entry and the
    space's events.
 5. The invite entry is of the space's log, its delivery holds the
    drop's wrap, and the bundle matches its rotations' commitments
    (keys.md, "Taking a key").                                          else WrongInvite
 6. Resolve the roster, with the snapshot's body keys. The invite
    entry is valid.                                                     else NotInRoster
 7. It grants exactly one invite key, [3, K], K the derived keys'
    device ID.                                                          else WrongInvite
 8. If the log holds a successor of K that this device signed, the
    claim is made: go to step 11.
 9. No valid successor of K, no valid removal of [3, K], and no
    successor of K void as ClaimRaced.                                  else InviteUsed /
                                                                             InviteRevoked / InviteRaced
10. check_expiry(expires_at, its wall clock, 604,800, link_skew)
    (overview.md).                                                      else its class
    Show the person the space, the offer, the inviter's device and
    that this is a link. On consent, in one commit, keep the claim
    record and sign the successor as K's event at seq 1, on heads
    whose state it holds.
11. Publish the successor to members, and to peers under the upload
    key of the state it is sealed under where the claimant holds that
    state's upload seed, otherwise under the upload key of the state
    the invite delivered, whose seed K's bundle in the invite entry
    holds (section 3.5). Hand the claimant's list to the space: as list
    units if it writes, otherwise as list events to a writer
    (transport.md). Continue as a newcomer (admission.md).
```

- **Where the successor is stored.** A peer grants the store right for a
  space under any live upload entry of it ([transport.md](transport.md),
  section 3.11), so the successor need not go under the state it is
  sealed under. That state may be one the claimant holds with no upload
  seed: a merged state it received whole, such as the invite's break
  merged with a heal concurrent with it, delivered to `K` before the
  claim or to the claimant at `read`. The state the invite delivered
  always comes with its upload seed, and the peer held its entry when the
  inviter stored the invite entry.

- **From a file.** A space file ([ext-space-files.md](ext-space-files.md))
  carries a fragment and the space's events: the claimant takes `K`'s wrap
  from the invite entry's delivery in place of the drop, and the file's
  snapshot in place of a fetched one, and walks steps 5 to 11 on what the
  file holds.
- **Never sign twice.** A device signs at most one successor per invite
  key. It finds an earlier one by its `claim` record, or after a restore
  by syncing its tips before it signs ([at-rest.md](at-rest.md)).
- **A wrap left out.** If a later rotation left `K` out, the claimant signs
  on heads whose state it holds, leaving that rotation out of the
  successor's past. The successor is then concurrent with it, and valid,
  and the claimant asks for a delivery as any member left out does
  ([roster.md](roster.md), section 3.9).

### 3.3 Invites in the roster

**Member state** ([roster.md](roster.md), section 3.2):

- `K` is out at any place that holds a valid successor it signed.
- A valid successor is a grant of its claimant. It gives the invite's
  state at the successor's place: level, capabilities, label, history,
  session, and with a session `expires_at`; `via` 1; a device claimant's
  keys; and the successor's seniority.
- A successor's **author member** is `[3, K]`, for attack (a), for the
  seniority of the resolution's step 4, and as `me` in
  [keys.md](keys.md)'s flags.

**Authority** ([roster.md](roster.md), section 3.6). A grant of `[3, K]` is
also `InviteUsed` when an event of its place names `[3, K]` or `K` signed a
successor there. A removal of `[3, K]` is also allowed when `K` is out only
by valid successors: the **close**. For a successor `e` by `K`, with `S` the
roster at its place, these replace steps 1 to 3:

```text
1. No successor signed by K, valid or void, is in e's past.            else InviteUsed
2. [3, K] is in S.                                                     else NotAnInvite
3. The claimant's type is the invite's claims.                         else ClaimMismatch
4. The claimant is not in S.                                           else AlreadyMember
```

**Standing** ([roster.md](roster.md), section 3.7). A successor by `K`
has standing in its past when a roster event in its past whose sealed part
passes roster.md's section 3.4.1 through step 10, valid or void, grants
`[3, K]`. Without it, `[3, K]` is in no roster at its place, so the
successor is void before the procedure, as roster.md says, with step 1's
class if it fails step 1 and `NotAnInvite` otherwise. It still races the
other successors of `K` (section 3.4). An invite grant is never at
`administer`, so a successor gives no device standing.

A successor never changes who administers, so it names no twin. An op-4
change by any other author fails step 2.

**The chain.** Two successors of `K` that neither follows prove a fork of
`K`'s chain ([events.md](events.md)). For a successor, section 3.4's rule
replaces the penalty of [roster.md](roster.md)'s section 3.4.1, step 12,
which would void an honest claim even after its close. The penalty still
applies to any other event `K` signs.

**Attack (d)** never holds: two successors never attack each other, so
seniority never settles them.

### 3.4 Raced claims

A successor of `K` **races** every other successor of `K` concurrent with
it that passes [roster.md](roster.md)'s section 3.4.1, valid or void. A
**close** here is any valid removal of `[3, K]`.

> A racing successor is void (`ClaimRaced`) unless every successor it
> races is concurrent with a valid close of its key.

Such a shielded racer is void anyway, by attack (a). Resolution runs:

```text
forced = {}
repeat:
  resolve (roster.md, section 3.7), with each successor in forced
    failing its authority as ClaimRaced
  more = the valid successors that race a successor concurrent
         with no valid close of their key
  if more ⊆ forced: stop
  forced = forced ∪ more
```

- `forced` only grows and is bounded by the successors held, so the loop
  ends, and replicas that hold the same events agree. Forcing a successor
  void turns its close into a revocation, which must rotate; a close that
  did not rotate then falls in the next pass.
- **A closed claim stands.** Bob claims at `s1`; the inviter, holding `s1`,
  closes at `c`; Mallory signs `s2` on heads from before `s1`. `s2` is
  concurrent with `c`, so attack (a) voids it, and `c` shields `s1`.
- **A race before any close.** If a replica holds `s2` but not `c`, or `c`
  was signed after its author held `s2`, both are void. Every later
  successor is `InviteUsed`, so the invite is never claimed again.
- A raced successor is voided by the successors it races.

### 3.5 Keys

- **Receipt.** `K` is a wrap recipient while `[3, K]` is in and `K` counts
  as inside (below), under its grant's X-Wing key, with `K` as the
  recipient's device ID. Once it counts as outside it receives no wrap,
  though it stays in the roster until a removal. Its bundle holds the
  content key, the upload seed whatever its level, so that its claimant
  can store its successor and list, and the grant seed unless the invite
  carries `session`. The claimant's device MUST open wraps for `K` as its
  own, with `K`'s X-Wing seed from its `claim` record, for as long as it
  keeps that record; a wrap for `K` in a rotation whose past lacks the
  successor is a delivery to the claimant.
- **Flags** ([keys.md](keys.md), section 3.3). An invite grant sets
  `admits_from_now_on` when its history is 0, and `admits_propagating`
  when it carries no `session`. A successor sets neither; its
  `author_propagates` holds when the invite carries no `session`. A close
  removes no member in `S`, so it need not rotate; a revocation rotates.
- **Inside.** `K` in force is inside. It counts as outside after a valid
  successor, after a valid removal with no valid successor, and once a
  successor of `K` is void as `ClaimRaced`. Two successors of `K` fork its
  chain even after a close (section 3.3), and a forked key is never inside
  ([keys.md](keys.md), section 3.6). The claimant is inside as the member
  its successor grants, and is wrapped for under its own keys, or its
  person's devices'; that it also keeps `K`'s seed changes nothing.
- **The heal.** `K` holds the state the invite delivered, and every state
  wrapped for it while it counted as inside, so once it is outside the
  heal test fires ([keys.md](keys.md), section 3.9) wherever the current
  state is one `K` derives, and any writer heals, after its rank delay,
  with the healed state's `encode_set` as the trigger, as after a removal.
  A revocation rotates itself and leaves `K` out, so it needs no heal. A
  close need not rotate, and cannot be a grant rotation
  ([keys.md](keys.md), section 3.3, steps 6 and 7), while `K`'s bundle
  holds the grant seed unless the invite carries `session`: the heal is a
  key event, a grant rotation when its author propagates. A rotation whose
  author has not seen the successor still wraps for `K` (receipt, above);
  merged with the successor, `K` is outside and holds it, and the test
  fires again. A claimant that writes is a candidate too, but heals only
  once a peer or member holds its successor: until then it stores under
  the upload key section 3.2, step 11, names, which its own heal would
  leave behind.
- **Entitlement**, rule 4: the claimant of a valid successor is entitled
  to every state its invite key is entitled to; for the grant graph, only
  for an invite without `session`. An invite "from now on" is a break
  whose grantee, `K`, counts among potential holders.

### 3.6 Administering devices

Each delay is [keys.md](keys.md)'s rank delay, over the space's
administering devices in this device's view. A device drops its act if
another to the same effect arrives first.

- **The close.** The inviter's client closes as soon as it holds a valid
  successor of its invite; any other administering device, after its delay
  with the successor's ID as the trigger.
- **Expiry.** For an invite with no valid successor and no valid removal,
  after its delay with the invite entry's ID as the trigger:

  ```text
  invite_expiry(expires_at, first_sight, now), in order:
    1. Its wall clock is known and now.W >= expires_at.            Revoke
    2. lower(first_sight, now) >= 604,800.                         Revoke
    3. Otherwise.                                                  Open
  ```

  `first_sight` is this device's first sight of the invite entry, so step
  2 enforces the maximum without trusting `expires_at`.
- **A raced claim.** A device that holds a successor void as `ClaimRaced`
  tells its person that the link was claimed twice. An administering device
  that holds one revokes the invite key after its delay, with the invite
  entry's ID as the trigger, as for expiry.
- The heal that a claim calls for is not an administering device's act:
  any writer makes it (section 3.5).
- The inviter's client deletes its drops once the invite is closed or
  revoked, on a connection that proves the upload key of the state each
  drop names, since the heal after a claim may have moved its connections
  on (section 3.1). Removing the inviting administrator leaves its invites
  open; a client that removes a member offers to revoke the invites it
  made.

### 3.7 Across a checkpoint

A checkpoint ([roster.md](roster.md), "Checkpoints") fixes what its past
decided about each invite key in its record (roster.md, section 2.8): the
key's grant state, its three public keys, `expires_at`, `claims`, and its
**status**: open (0), claimed (1, with its claimant), raced (2) or used
(3). A claimed key stays in the record, out, until a close removes it; a
revoked or closed key leaves it. In the checkpoint's world:

- **Successors.** An open key's successor is judged as section 3.3 says,
  its signature under the record's keys. The checkpoint counts as a
  successor of every key whose status is not 0, so a successor of a
  claimed, raced or used key after it is `InviteUsed` (section 3.3, step
  1), as it would be over the whole past. A successor concurrent with the
  checkpoint is late; it races nothing in the world, and a successor after
  the checkpoint is judged without it.
- **Keys.** An open or used key in force is inside and is wrapped for,
  under the record's X-Wing key; a raced key counts as outside, and so
  does a claimed one, which is out. So a racer that holds the secret
  receives nothing from the checkpoint on, and the checkpoint, which
  wraps only for the inside of its past ([keys.md](keys.md), section
  3.17), already heals what a racer or a claimed key held: no heal is due
  for them after it.
- **Closes and revocations.** A close of a claimed key is valid, as the
  key is out only by its successor. A revocation of an open, raced or used
  key removes a member in the record and rotates. Expiry reads the
  record's `expires_at` (section 3.6), with `first_sight` the device's
  first sight of the invite entry, or of the checkpoint for a device that
  holds no event before it.
- **Claims in flight.** A claimant whose successor is concurrent with a
  checkpoint that takes effect finds it late, and claims again after the
  checkpoint on heads that follow it, sealed under a state of its world,
  which the checkpoint's own delivery to `K` gives it: its successor at a
  `seq` above its late one continues `K`'s chain. Its `claim` record
  (section 2.4) names the late successor as no claim made. A device never
  signs a second successor that is not after a checkpoint its first is
  late to.
- **Drops in flight.** A drop placed before a checkpoint still opens: its
  wrap names a state before the checkpoint, whose read credential still
  fetches from peers that kept its entry ([peers.md](peers.md), "Skeleton
  cuts"), and the claimant holds `K`'s seed. If the peers truncated the
  invite entry, the claimant reads the snapshot's checkpoint instead: in
  section 3.2, steps 5 to 7 read the record, which must list `[3, K]` open
  (else step 9's class), `K` the derived keys' device ID, and the checkpoint's own wrap
  for `K` replaces the entry's delivery. An inviter that holds a drop
  whose state is before a checkpoint in effect MAY place it again with
  `K`'s wrap of the checkpoint's delivery.
- **Heals in flight.** A heal concurrent with the checkpoint is late; the
  checkpoint itself rotates both the content and the grant state without
  the outside holders, so the heal is not made again.

## 4. Security considerations

- **A leaked link is a bearer credential** until it is claimed or revoked.
  A claim raced with the invitee's voids both, visibly. A claim made first
  goes unnoticed until a member compares an admission code with the
  claimant. A short-lived link sent over a trusted channel narrows this.
- **What a leaked link reads.** A holder of the link that fetched the drop
  while it was kept opens `K`'s wrap and holds the state the invite
  delivered, signing nothing; a peer that keeps the drop holds it too
  once it learns the link. It reads everything sealed under that state
  and under the states wrapped for `K` while it counted as inside: from
  the invite (or before it, for an invite "with history") until the heal
  that follows the claim, or the revocation. **The window** is what
  writers seal between the successor and the heal: units by writers that
  have not yet seen the successor, and by those that have, for about one
  round trip and a rank delay once a writer that holds the successor is
  online. The claimant's own first units fall in it. While no writer is
  online, it lasts until one is, as a removal's merge-key window does
  ([rationale.md](rationale.md), section 11).
- **Credentials after the heal.** `K`'s bundle holds the upload seed
  whatever the invite's level, and the read credential derives from the
  content key, so the holder of the link keeps the read credential and the
  upload key of every state it holds. A heal adds new entries at the
  peers and retires none ([peers.md](peers.md), "Retirement and the cap"),
  so, as a removed member does, it fetches ciphertext, of later states
  too, that it cannot open, and spends quota until a credentials request.
  Units it signs as `K` are refused, since `K` is no member once out.
- **The window before the close.** Until an administering device that holds
  an honest claim closes, a holder of the secret can race it, and the
  invitee is then admitted again. A late claim after the close changes
  nothing. Racers hold the space's keys from the invite on, until a heal.
- **Pinned.** A hostile server that holds `K`'s public keys can build a
  roster of its own that grants `K`, but that is another space and another
  event; the claimant checks the entry and space the link names.
- **The upload seed.** A claimant at `read` holds it until the next
  rotation, as a reader reached through a write grant does: it can spend
  quota, and its units are refused.
- **An unknown wall clock** makes a claim `Expired` (section 3.2, step
  10). [overview.md](overview.md)'s `check_expiry` treats an unknown wall
  clock as past, so no device claims on a time it cannot read. An
  application MUST NOT give `expires_at` to an invite meant for a device
  with no wall clock; since every invite carries it, such a device is not
  invited by link. An invite still ends by its revocation.
- **What a peer learns.** That a space has a drop, its size, and when it is
  fetched. A successor, a non-rotating space event by an author that signs
  nothing else after an invite grant, lets a peer guess a claim. The heal
  that follows, a rotation with a wrap per member device and none for
  `K`, adds only a rotation and its wrap count, which every heal shows
  ([overview.md](overview.md), section 4.4, item 1); it makes the guess
  surer and dates the claim no more closely than the successor does. An
  invite costs one heal when claimed and one rotation when revoked.

## 5. Test vectors

[ext-invite-links.json](vectors/ext-invite-links.json), with fixed seeds:

- `derivations`: a secret, every key, `kc` and `K`, the locator, the drop
  key, the drop's address and the fragment. `links`: refused fragments.
- `drops`: a drop sealed and opened; refused drops; a `MailboxPut` of kind
  4 and refused ones; a peer's drop store (a second drop `conflict`,
  deletes under another or no entry `credential_refused`, the placer's
  delete, the address free again).
- `encodings`: an invite grant and a successor, byte for byte.
  `refused_changes`: grants and successors refused by shape.
- `histories`, with each event's status and the roster: one claim; two
  concurrent claims; a claim after a claim, and after a race
  (`InviteUsed`); a claim concurrent with the revocation and after it; a
  claim and its close; a late claim after a close; a late claim before
  any close; a claimant already in; a claimant of the wrong type; op 4 by
  an administrator; a used invite granted again; a successor that rotates
  and one with two changes; re-submission through a raced claim; an invite
  "from now on" that does not rotate.
- `claims`: the claimant's walk, from fragment to roster, with and without
  the snapshot's body keys.
- `keys`: who receives what, for invite keys at `read`, at `write` and with
  `session`; a claim that hands its entitlement, after which `K` is
  outside and a writer heals, the claimant receiving the heal and `K` not;
  a raced claim after which `K` is outside and a writer heals.
- `expiry`: `invite_expiry`, the claimant's check, and the delays.
