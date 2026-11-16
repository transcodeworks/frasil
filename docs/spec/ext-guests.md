# Guests
Protocol 1. Vectors: [ext-guests.json](vectors/ext-guests.json).

This extension specifies the guest preset of a device grant, a session's
expiry and its end in one roster event, a guest's leave request, "nothing
at rest", the two write policies a space may set (the bounded window and
online-only), a session with no peer, and what a carve-out's guest reads.
It extends [roster.md](roster.md), [admission.md](admission.md),
[transport.md](transport.md), [at-rest.md](at-rest.md) and
[units.md](units.md) through their hooks, and uses
[ext-ephemeral.md](ext-ephemeral.md) and
[ext-invite-links.md](ext-invite-links.md) where they are implemented. A
guest itself, a device member granted with `session`, is core: it never
propagates and never holds a grant key ([roster.md](roster.md),
[keys.md](keys.md)).

A core implementation that does not implement it:

| What this document defines | A core implementation |
|---|---|
| `expires_at` (change key 13) on a guest's grant | checks its type and ignores it; never removes a guest by clock ([roster.md](roster.md)) |
| Offer key 13 | never puts it in an offer; as a joiner, refuses an offer that carries it as `Malformed` ([admission.md](admission.md)) |
| The capability `frasil.nothing-at-rest` | merges it by its mode as any capability, and does not act on it |
| Space policy keys 3 and 4 | checks, carries and merges them, and applies no writer's decision |
| The content name `frasil/leave-request` | drops such an item (`UnknownContent`, [transport.md](transport.md)) |
| `state` keys 3 and 4 at rest | never writes them ([at-rest.md](at-rest.md)) |

## 1. Overview

- A **guest** reaches one space and nothing else, and by default receives
  what is shared from now on.
- A **session** is the guests granted with one `session` value. Ending it
  takes one roster event and one rotation, however many guests it holds.
  A session's `expires_at` tells administering devices when to end it; no
  replica reads a clock.
- A guest cannot sign a roster event, and a leaver must not rotate, so a
  guest **leaves** by a signed request that an administering device turns
  into a removal.
- **Nothing at rest** asks the guest's client to keep the space in memory
  only. It binds honest clients only.
- A guest learns where the other members are only on local networks:
  the member addresses a member sends a guest carry local-network
  addresses alone, with no public address and no relay
  ([transport.md](transport.md), "The iroh binding", member addresses).
- A space may make every honest writer stop when it has not heard from
  another member for a while (**bounded window**), or from an always-on
  peer (**online-only**). Each writer applies the rule to itself.

## 2. Formats

### 2.1 The guest preset

A device grant ([roster.md](roster.md)) with:

| Key | Field | Value |
|---|---|---|
| 7 | `session` | 16 random bytes the application draws per session |
| 5 | `history` | 0, from now on, unless the administrator asks otherwise |
| 2 | `level` | `read` or `write` |
| 3 | `capabilities` | the application's, with `frasil.nothing-at-rest` when asked |
| 13 | `expires_at` | optional: the granter's wall clock plus `session_lifetime` ([overview.md](overview.md), section 6.8) |
| 6 | `via` | 0, code; 1, link |

The offer of an admission by code carries the same `session` and
`expires_at` (offer keys 7 and 13), and [admission.md](admission.md)'s
check that the grant matches the offer covers both. A lookup finds
persons, never guests. With [ext-invite-links.md](ext-invite-links.md), a
guest invite carries `session`; its claimant takes the invite's
`expires_at` as its session's.

### 2.2 The leave request

```text
request = CBOR {1: 1, 2: space ID (32), 3: member [type 0 or 1, ID],
                4: the member's grants in force (1 to 64 event IDs, strictly ascending),
                5: request ID (16 random bytes), 6: the signing device's device ID (32)}
signed  = CBOR {1: request (bytes),
                2: the device's scheme-2 signature over
                   "frasil/leave-request/v1" || field(request) (3,373)}
```

`member` is the leaver's own device member, or for a person that leaves,
the person. Naming grants, not a time, means a request cannot remove the
member again after a re-grant.

### 2.3 Names, labels and error classes

- The capability `frasil.nothing-at-rest` narrows. The content name
  `frasil/leave-request` names a signed leave request, as a device mailbox
  item ([transport.md](transport.md)) and as an ephemeral message
  ([ext-ephemeral.md](ext-ephemeral.md)).
- Label, from [crypto.md](crypto.md)'s registry: `frasil/leave-request/v1`.
- Space policy keys 3, `bounded_window`, and 4, `online_freshness`, are
  [roster.md](roster.md)'s, with their ranges in
  [overview.md](overview.md), section 6.8. Absent means off.

| Class | Meaning | Sort |
|---|---|---|
| `WrongSpace` | a leave request for another space | decision |
| `NotTheMember` | a leave request signed by a device that is not the member's | decision |
| `Stale` | a leave request whose grants are not the member's grants in force | decision |
| `MemberAdministers` | a leave request for a device member at `administer` | decision |
| `Left`, `SessionEnded`, `WindowElapsed`, `NotOnline` | why this device may not write now (section 3.4) | report |

## 3. Procedures

### 3.1 Admitting a guest

A guest is admitted by an admission code, on a nearby connection or
through an exchange mailbox ([admission.md](admission.md)), or by a guest
invite. An admission "from now on" is a break: it receives the new state
and a history-free snapshot, and reads the membership history but no
content from before it. For a guest whose grant carries
`frasil.nothing-at-rest`, the administering device that signs the
admission hands the space snapshot over a member connection instead of
publishing it at a peer. Concurrent grants of one device keep `session` and
`frasil.nothing-at-rest` if any grant has them, by the meet.

### 3.2 Ending a session

An application ends a session by removing every guest of that `session`
in one roster event: one removal each, up to 256 changes, the rest in
further events. It rotates once, as any removal does, and since guests do
not propagate, it rotates the content key only. Two administering devices
that end the same session concurrently both stand.

An administering device decides, for each guest grant in force that
carries `expires_at`, in order:

```text
session_expiry(expires_at, first_sight, now):
  1. Its wall clock is known and now.W >= expires_at.            Remove
  2. lower(first_sight, now) >= 2,592,000.                       Remove
  3. Otherwise.                                                  Open
```

`first_sight` is the device's first sight of the event that grants the
guest: its admission, or for a guest admitted by link its successor; for
a device that holds no event before a checkpoint in effect, and a guest
the checkpoint's record lists with its session and `expires_at`
([roster.md](roster.md), "The checkpoint record"), its first sight of the
checkpoint. Step 2 enforces the
maximum without trusting `expires_at`. A guest is **due** when one of its
grants gives `Remove`. After its rank delay
([keys.md](keys.md)) over the space's administering devices, with the
grant's event ID as the trigger, the device removes every guest that is due
in one event, unless their removals have arrived. A session without
`expires_at` ends only by hand or when its guests leave.

A guest's units and key events concurrent with or after its removal are
refused ([roster.md](roster.md), the write rule); what it wrote before
stands.

### 3.3 A leave request

Roster events need `administer`, and a self-removal never rotates, so a
member that is not an administering device leaves by request: a guest, a
device member, or a person through one of its devices. An administrator
leaves by its own self-lowering event, and a writer heals.

The leaver signs one request and sends it, as an item sealed to each
administering device's mailbox, or, with
[ext-ephemeral.md](ext-ephemeral.md), as an ephemeral message targeted at
them. A member at `read` may send either. An administering device checks,
in order:

```text
1. Both maps read, with the types, lengths and order of
   section 2.2; key 1 is 1.                                    else Malformed / UnsupportedVersion
2. It holds the signing device's keys, which hash to its
   device ID: from its device grant, the person's list, or
   any other source (crypto.md, "A device's keys").            else NoHybridKey
3. The signature verifies.                                     else BadSignature
4. The space ID is this space's.                               else WrongSpace
5. The member is in the merged roster.                         else NoSuchMember
6. The signing device is the member, or a device that
   the person's list vouches for.                              else NotTheMember
7. The named grants are exactly the member's grants in force.  else Stale
8. The member is not a device member at administer.            else MemberAdministers
9. After its rank delay over the space's administering
   devices, with SHA-256 of the signed request as the
   trigger, unless a removal of the member has arrived:
   remove the member in a roster event that rotates.
```

A refusal at any step, `NoSuchMember` included, is a decision on this
request alone, and sends nothing. Before it sends the request, the
leaver's client keeps the grants the request names as `state` key 4
([at-rest.md](at-rest.md)), so that what follows outlasts a restart. Once
it has sent the request, it seals nothing more in the space (`Left`). With
nothing at rest it deletes what it holds at once; otherwise it keeps what
it received. It discards whatever is wrapped for it afterwards.

### 3.4 The writer's decision

Before it seals anything in the space, a device decides, in order:

```text
1. It has sent a leave request for its membership: a grant of it in
   force is among the grants a sent request named.                    Left
2. A grant of it in force carries expires_at, and for the earliest,
   check_expiry(expires_at, its wall clock, 2,592,000, session_skew)
   (overview.md, section 6.6) does not pass.                          SessionEnded
3. bounded_window is set, and upper(followed, now) >= bounded_window. WindowElapsed
4. online_freshness is set, and no completed sync is recorded, or
   upper(last_sync, now) >= online_freshness.                         NotOnline
5. Otherwise.                                                         MayWrite
```

**May not write** means the device seals nothing under the space's keys: no
unit, system units included, no key event, no roster event and no ephemeral
message, since an uninformed administrator's rotation would wrap the new
key for a member it has not heard was removed. It still reads, syncs and
receives, and signs anchors, which seal nothing. The application's writes
wait unsealed, and are sealed under the then current state once it may
write; an event already signed waits in the outbox. No replica refuses an
event for this: the decision binds the writer alone.

**Followed.** Another member **follows** an event of this device when it
signs a valid event of the space, from another device that reaches the
space at that event's place, with this device's event in its past. Void,
refused and forked events do not count, so a removed or forked device keeps
no window open; an old event cannot hold a recent one in its past, so
trickled history keeps none open either. `followed` is this device's
reading when it signed the event, of those another member follows, whose
reading has the largest timeline, and at first its first sight of its own
admission. A merge that voids the following event recomputes it.

**Heartbeats.** Under a bounded window, a device keeps others able to
follow it with anchors ([crypto.md](crypto.md)), beyond those that
coverage asks for:

```text
heartbeat(last_signed, last_heartbeat, now, window, unanswered), in order:
  1. lower(last_heartbeat, now) < window / 2.                         Wait
  2. upper(last_signed, now) >= window / 2, or unanswered.             Heartbeat
  3. Otherwise.                                                        Wait
```

`unanswered` holds when the device holds another member's anchor that none
of its own events follows. Step 1 keeps heartbeats from answering each
other without end.

**A completed sync** is an exchange of heads with an always-on peer of the
space, on a device-to-peer connection that proved a live entry
([transport.md](transport.md)), after which the device holds every event
the peer's heads name, and those heads hold this device's newest event in
the space, if it has signed one. `last_sync` is the device's reading when
it completed, kept as `state` key 3 ([at-rest.md](at-rest.md)). A client
MUST NOT set `online_freshness` in a space with no always-on peer, whose
writers could then never write.

### 3.5 Nothing at rest

A client whose grant carries `frasil.nothing-at-rest` keeps the space's log
in memory only ([at-rest.md](at-rest.md), "A memory-only log"): its keys,
events, objects, snapshot and outbox. It writes none of them to Frasil's
store or the application's files. It learns this from the offer that
admits it, which carries the capabilities of its grant
([admission.md](admission.md)), before it adopts the snapshot or places
any event; a grant that the roster it then resolves gives without the
capability does not bring the log back to rest. The logs along the grant
path that its snapshot carries ([admission.md](admission.md), "The
newcomer's snapshot") are kept in memory only with it, unless the device
already keeps them at rest as a member. It deletes them when the application
closes the space, at `SessionEnded`, when it learns of its removal, and
when it sends a leave request. It keeps at rest only what belongs to no
space: its device keys, its timeline and its ephemeral epoch
([ext-ephemeral.md](ext-ephemeral.md)). Replicas run no check for the
capability.

### 3.6 A session with no peer

A guest can join with no account and no peer on either side:

1. If the content is not yet a space, the host's device signs a genesis:
   it is the founder, the policy is the default, and the content goes in
   as history-free snapshots, one stream each.
2. The guest's device, with fresh keys and no person, runs the admission
   code with the host over a nearby connection, with that connection's
   channel. The connection is direct on a shared network, or through a
   relay both devices name ([transport.md](transport.md), "The iroh
   binding"). The offer names the session and, if asked, nothing at rest.
3. The host signs the grant, a break, and sends over the same connection
   the Result, the guest's snapshot and its member endpoint. The guest
   checks the grant ([admission.md](admission.md)), and the two replicas
   sync by the member handshake, directly or through the relay.

With no peer, changes move only while both devices are connected: a relay
forwards packets and keeps nothing. Each side reconnects to the other at
the member ticket it kept ("Reconnecting" in
[transport.md](transport.md)) until the other's member endpoint key
rotates. With [ext-next-endpoints.md](ext-next-endpoints.md), each also
dials the key the other announced as its next, so they meet again unless
both have rotated twice since they last met. Otherwise each needs a fresh
invitation or another way to learn the other's endpoint.

The bounded window works here, since host and guest follow each other.
The host ends the session by section 3.2; the space stays a space.

### 3.7 A carve-out's guest

A carve-out ([ext-restricted-spaces.md](ext-restricted-spaces.md)) gives a
guest one document of a space P in a new space N that grants P. To judge a
unit a member of P writes in N, the guest resolves N's roster, P's, and
every roster along the grant path, though it is no member of P. Its
snapshot carries them, with their body keys and the device lists they
name, as [admission.md](admission.md) requires of every newcomer's
snapshot; later events reach it as [admission.md](admission.md)'s granted
rosters do. The guest so reads P's membership history, and none of P's
content.

## 4. Security considerations

- **Nothing at rest is best-effort.** A hostile guest, a modified client,
  swap, crash dumps and screenshots keep copies. Applications tell the
  person who grants it that the guest's application is asked not to keep
  a copy, and that a modified one can.
- **A guest learns no public address of a member** from member
  addresses, nor any relay, so a guest met on a venue's network cannot
  find the members it learned of there from anywhere else; it still sees
  the addresses of the connections it holds itself.
- **Expiry and leave depend on administering devices.** Until one removes
  the guest, members keep wrapping new keys for it, and only its own
  honest client stops at `expires_at` or after its request.
- **An unknown wall clock** ends a guest's writing: a guest whose grant
  carries `expires_at` gets `SessionEnded` (section 3.4, step 2).
  [overview.md](overview.md)'s `check_expiry` treats an unknown wall clock
  as past, so no device writes on a time it cannot read. An application
  MUST NOT give `expires_at` to a guest meant for a device with no wall
  clock. The end of a session is still enacted by its removal.
- **The policies bind honest writers.** They narrow how long an uninformed
  writer leaks to a removed member: from the moment its window closes,
  nothing it seals is readable by a member removed while it was unheard.
  They do nothing against a writer that ignores them, nor against a peer
  that withholds events. A wall clock set back while the device was off
  keeps a writer going longer, by the time it was set back.
- **A carve-out's guest reads its parent's membership,** at a cost that
  grows with P's roster history: up to 4,096 valid roster events, each
  device grant about 6.6 KB. A client that carves out of a space with a long
  roster says so to the inviter. An application that must not show P's
  membership shares the document another way.

## 5. Test vectors

[ext-guests.json](vectors/ext-guests.json):

- `parameters`: the capability name and the session's size.
- `sessions`: a host admits two guests of one session, one with
  `expires_at` and nothing at rest, one reading, and a third of another; a
  guest's unit and key event, valid; the end of the first session in one
  event of two removals, the third guest staying; a guest's unit
  concurrent with the end (`RefusedByRemoval`); a guest's self-removal
  (`NotAnAdministrator`); and an offer carrying key 13 at a joiner that
  implements this extension (accepted), the same without a session
  (`Malformed`), and at a core joiner (`Malformed`).
- `nothing_at_rest_meet`: two concurrent grants of one guest, one with the
  capability; the meet keeps it.
- `leave_requests`: a signed request; two administering devices'
  decisions, ranks and delays; refused requests (`NotTheMember`, `Stale`,
  `BadSignature`, `WrongSpace`, `MemberAdministers`); the removal and the
  roster after it.
- `session_expiry`: `session_expiry` at and around each bound, with and
  without a known wall clock and `expires_at`.
- `writer_decisions`: section 3.4 over readings: the window open and
  elapsed, a wall clock moved forward while off, no known wall clock after
  a restart, online-only fresh, stale and never synced, both policies, a
  guest past its expiry with a known and an unknown wall clock, a leaver.
- `followed`, `heartbeats`: which events follow a device's own, and the
  heartbeat decision.
- `off_grid`: a genesis on the host, a guest admitted by code over a
  nearby connection, the guest's unit, and the end of the session.
- `carve_out_guest`: P with a removed member; N granting P and a guest;
  what the snapshot carries; P resolved from it alone; a unit by a member
  of P, valid with P's roster and `Pending` without it.
