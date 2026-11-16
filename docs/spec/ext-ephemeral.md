# The ephemeral channel
Protocol 1. Vectors: [ext-ephemeral.json](vectors/ext-ephemeral.json).

This document specifies the **ephemeral channel**: live traffic, such as
presence, cursors and commands, carried apart from units, sealed under a
space's key, signed by the sending device, checked by capability and never
persisted. It extends [transport.md](transport.md), which reserves message
types 48 (`Ephemeral`) and 49 (`Gone`), the ephemeral stream class and the
lossy channel; [units.md](units.md), whose capability-check interface it
runs and whose head statements and list-event bodies it carries;
[keys.md](keys.md), from whose content key it derives its own; and
[at-rest.md](at-rest.md), which reserves its `epoch` and `replay` tables.
It judges senders by [roster.md](roster.md) and [identity.md](identity.md).
It depends on [overview.md](overview.md) for conventions, error classes and
time, and on [crypto.md](crypto.md) for primitives and labels.

A core implementation that does not implement it:

| What this document defines | A core implementation |
|---|---|
| Message types 48 and 49, the ephemeral stream class | drops `Ephemeral` and `Gone` and never relays them ([transport.md](transport.md), section 2.4) |
| The `live` right's relaying | a peer gives the right for live delivery only |
| Tables `0x03` and `0x1a` | never writes them ([at-rest.md](at-rest.md)) |
| The `frasil/heads`, `frasil/list-events` and `frasil/access-request` routes | sends them by their core routes: head statements on member connections; list events and access requests on member connections and device mailboxes |

## 1. Overview

- An **ephemeral message** is fire-and-forget, broadcast to a space or
  targeted at 1 to 16 devices. An **ephemeral slot** is a value its sender
  keeps current; each receiver keeps the latest value of each, and a late
  joiner receives every held ephemeral slot.
- Each frame is signed by its sender's Ed25519 key inside a seal under a
  key derived from the sender's current content state, so a receiver knows
  which device sent it and a relay does not.
- A receiver judges each frame once, against its **current view** of the
  space, not at a place: membership, freshness, replay, then an adapter's
  capability check. Each verdict is that receiver's decision about one
  frame, never a verdict on an event. No clock decides a replay.
- Frames go ahead of every sync and object frame, and a sender drops them
  rather than let them wait. No party stores their content at rest.

## 2. Formats

### 2.1 Labels and limits

This document uses the labels `frasil/ephemeral-key/v1`,
`frasil/ephemeral/v1` and `frasil/ephemeral-slot/v1` of
[crypto.md](crypto.md)'s registry.

| What | Limit |
|---|---|
| An outer frame | 24,576 bytes |
| A padded plaintext | a multiple of 256, at most 18,432 bytes |
| `data` | 16,384 bytes |
| `name` | 1 to 64 bytes of UTF-8 |
| `adapter` | an adapter type ([units.md](units.md)): 1 to 64 bytes, each `0x21` to `0x7e` |
| Targets; fresh entries | 1 to 16 each |
| Replay window per space and sender | 64 counters |
| Receiver nonces a device holds per space | its last 4 |
| Live ephemeral slots per sender per space | 32 |
| Ephemeral slots a receiver holds per sender per space, cleared ones included | 32 |
| Ephemeral slots a receiver holds per space, cleared ones included | 2,048 |
| Ephemeral slots a relay holds per connection per space | 64 |
| A sender's queue per connection | 64 frames |
| A relaying member's relay window per space and sender | 64 counters |

The largest key reference fits beside the largest plaintext under the
outer limit. `data` holds any signed record of at most 16,384 bytes, a
device-list event included; such frames travel on the ephemeral stream.

### 2.2 The ephemeral key

```text
ek(S) = HKDF(salt = none, ikm = k(S), info = "frasil/ephemeral-key/v1")         32 bytes
```

- `S` is the sender's content state of the space and `k(S)` its content key
  ([keys.md](keys.md)). `reference` below is `S`'s key reference,
  `encode_set(S)`, as a unit carries it.
- In a restricted space, `k(S)` is `k_F(S_F, S_P)` and `reference` the
  restricted key reference, with the parent's state sealed
  ([ext-restricted-spaces.md](ext-restricted-spaces.md)). A device removed
  from the parent reads none of its live traffic once the parent rotates.

### 2.3 The inner map

A deterministic CBOR map:

| Key | Field | Type | Rule |
|---|---|---|---|
| 1 | `version` | unsigned | 1 |
| 2 | `kind` | unsigned | 1 ephemeral message, 2 ephemeral slot |
| 3 | `sender` | bytes(64) | the sender's `ed \|\| kc` ([crypto.md](crypto.md), "A device's keys"); the sender is the device ID they give |
| 4 | `epoch` | unsigned | 1 to 2^64 − 1 (section 3.2) |
| 5 | `counter` | unsigned | 1 to 2^64 − 1 (section 3.2) |
| 6 | `name` | text | 1 to 64 bytes; no control character (Unicode category Cc); not only white space |
| 7 | `stream` | bytes(16) | optional; not 16 zero bytes |
| 8 | `targets` | array of bytes(32) | optional; ephemeral messages only; 1 to 16 device IDs, strictly ascending |
| 9 | `fresh` | array of `[bytes(32), bytes(16)]` | optional; only with `targets`; 1 to 16 pairs of a target and a receiver nonce, strictly ascending by target; each device a target |
| 10 | `adapter` | text | optional; an adapter type |
| 11 | `data` | bytes | 0 to 16,384 bytes |

Keys 1 to 6 and 11 are required. Any other key is `Malformed`. **Names** are
the application's, such as `com.example.cursor`, except those that begin
`frasil/` (section 2.7). A `stream` narrows an ephemeral slot or message to
one document ([units.md](units.md), streams). An `adapter` names the
adapter whose capability checks run on the frame (section 3.5).

### 2.4 The ephemeral slot handle

```text
handle = HMAC(ek(S), "frasil/ephemeral-slot/v1" || sender || field(name)
                     || field(stream, or empty))[0..16]
```

`sender` is the inner map's key 3, the sender's 64-byte `ed || kc`. The
handle is the visible key under which a relay keeps the latest value of
an ephemeral slot. An ephemeral message has no handle; where a format below
binds `handle`, it is then the empty string.

### 2.5 The signature and the seal

```text
tbs       = "frasil/ephemeral/v1" || field(space) || field(reference)
            || field(handle) || inner
signature = Ed25519-Sign(sender's identity seed, tbs)                            64 bytes

core      = CBOR array [inner (bytes), signature (bytes)]
plaintext = u16be(len(core)) || core || zero bytes
            (the fewest zero bytes that make len(plaintext) a multiple of 256)
aad       = "frasil/ephemeral/v1" || field(space) || field(reference)
            || u8(kind) || field(handle)
nonce     = 24 fresh random bytes
sealed    = nonce || XChaCha20-Poly1305(ek(S), nonce, plaintext, aad)
```

`space` is the space ID and `inner` the inner map's bytes. The signature
is scheme 0, verified once, at once ([crypto.md](crypto.md)). With the
inner kind, it binds the frame to its space, state and ephemeral slot; the
associated data binds every outer field, so a changed one does not open.

### 2.6 The outer frame

What a relay sees is a deterministic CBOR map, carried at key 2 of
[transport.md](transport.md)'s `Ephemeral` message:

| Key | Field | Type |
|---|---|---|
| 1 | `version` | unsigned, 1 |
| 2 | `kind` | unsigned: 1 ephemeral message, 2 ephemeral slot |
| 3 | `space` | bytes(32) |
| 4 | `reference` | bytes: the key reference of `S` |
| 5 | `handle` | bytes(16); present exactly for an ephemeral slot |
| 6 | `sealed` | bytes, at least 296 (24 + 256 + 16) |

### 2.7 Frasil's names

Names that begin `frasil/` are Frasil's, and an application MUST NOT send
them. Each has one kind, carries no `stream` and no `adapter`, and has the
targets and data below.

| Name | Kind | Targets | Data |
|---|---|---|---|
| `frasil/nonce` | ephemeral slot | | the sender's receiver nonce (section 3.3), 16 bytes |
| `frasil/endpoint` | ephemeral slot | | a member ticket naming the sender's current member endpoint ([transport.md](transport.md), tickets) |
| `frasil/heads` | ephemeral slot | | the sender's signed head statement of the space ([units.md](units.md)), with as many stream entries as fit in 16,384 bytes; its `space` is the frame's and its `device` is `sender` |
| `frasil/leave` | ephemeral message | none | empty |
| `frasil/access-request` | ephemeral message | required | a signed access request ([admission.md](admission.md), "Access requests") |
| `frasil/leave-request` | ephemeral message | required | a signed leave request ([ext-guests.md](ext-guests.md)) |
| `frasil/list-events` | ephemeral message | required | the body of [units.md](units.md)'s `frasil/list-events`: `{1: space ID, 2: array of 1 to 16 signed device-list events}`, whose space ID is the frame's |

The last three carry the records of the device-mailbox content names of
the same names ([transport.md](transport.md), mailboxes). A receiver that
lacks [ext-guests.md](ext-guests.md) treats `frasil/leave-request` as
unknown.

Section 3.4's step 11 checks the data of `frasil/nonce`, `frasil/leave` and
`frasil/list-events` as this table says. It does not read the data of
`frasil/endpoint`, `frasil/heads`, `frasil/access-request` or
`frasil/leave-request`. A head statement's space and device, like the rest
of such a record, are checked by its own document after the frame is
accepted, and decide what the record does, never the frame's verdict.

## 3. Procedures

### 3.1 Sending

- A sender seals under its current content state ([keys.md](keys.md)).
  When that state changes, it publishes each of its live ephemeral slots
  again under the new state, for members who hold only the new state.
- On a member connection, once both sides have sent `Admit` for an attach,
  each sends the other its own live ephemeral slots. A targeted ephemeral
  message goes only on connections whose device is a target or that relay.
- Through an always-on peer, a device sends `Ephemeral` only for a space it
  holds the `live` right for ([transport.md](transport.md), section 3.11).
  On the server binding, a client that sends bulk while live traffic flows
  opens a second device-to-peer connection that presents a read credential
  and carries only `Ephemeral` and `Gone`.
- A sender keeps at most 32 live ephemeral slots per space. Empty `data`
  clears one. `frasil/leave`, broadcast when the sender closes the space,
  clears all of them.
- **Queues.** Ephemeral frames queue apart and go first
  ([transport.md](transport.md), section 3.8), at most 64 per connection. A
  new value of an ephemeral slot replaces its unsent value; when the queue
  is full, the oldest ephemeral message is dropped, or, with no ephemeral
  message queued, the oldest ephemeral slot value; a frame not sent within
  `ephemeral_send_deadline` (2 seconds, monotonic) is dropped.

A device sends nothing on the channel of a space while it knows of a change
that cost the space a device and the space has not rotated since
([keys.md](keys.md), "Cascades"); while
[ext-guests.md](ext-guests.md)'s bounded window or online-only policy stops
it from writing; and once its own membership has ended in its view or its
chain in the space's log has forked.

### 3.2 Epoch, counter and replay

- **The epoch** is a 64-bit number per device, in
  [at-rest.md](at-rest.md)'s `epoch` table. A device that starts sending
  after its process starts reads `e`, commits `e + 1`, and uses `e + 1` in
  every space until its next start. After a restore, or with no epoch
  record, it takes instead its stored epoch (0 if none) plus 2^32 plus a
  random number below 2^32 ([at-rest.md](at-rest.md), "After a restore").
- **The counter** is per space: 1 at the start of each epoch, then one more
  for each ephemeral message and ephemeral slot value the device sends
  there. So a device's counters in one space say nothing of its traffic in
  another.
- **Ephemeral messages.** A receiver keeps, per space and sender, the
  highest epoch, the highest counter in it, and which of the 64 counters
  below that it has accepted. It accepts a higher epoch; in the same epoch,
  a higher counter, or one within 64 below that it has not accepted. Else
  `Replayed`. The window lets datagrams arrive out of order.
- **Ephemeral slots.** A receiver accepts a value only if its `(epoch,
  counter)` is greater than that of the value it holds for the same
  `(sender, name, stream)`, a cleared one included (else `Replayed`). A
  cleared value is dropped and its `(epoch, counter)` kept. A receiver
  clears each held ephemeral slot of the sender of a `frasil/leave` as if
  with the leave's `(epoch, counter)`.
- **Bounds.** A receiver holds at most 32 ephemeral slots per space and
  sender, and at most 2,048 per space, cleared ones included. To hold a
  new one past the first count, it forgets one of that sender's in the
  space; past the second, one of the sender that holds the most there (of
  those, the lowest device ID). Of a sender's, it forgets the cleared one
  with the lowest `(epoch, counter)`, or, with none cleared, the one with
  the lowest; of equal ones, the lowest `name` by its bytes, then
  `stream`, absent first.
- **The floor.** Per space and sender, a receiver keeps the highest
  `(epoch, counter)` of an ephemeral slot it has forgotten, `(0, 0)` at
  first. It accepts a value for an ephemeral slot it does not hold only if
  its `(epoch, counter)` is greater than the floor (else `Replayed`), so a
  forgotten value never returns. A sender that keeps at most 32 live
  ephemeral slots loses a held value to the first count only after a
  clear of one of them was lost.
- **Forgetting.** When a receiver accepts a frame of a sender, of either
  kind, under a higher epoch than any it accepted of that sender in the
  space, it first forgets the sender's ephemeral slots held under lower
  epochs, values and marks, and raises the sender's floor to at least
  `(that epoch, 0)`: a new run publishes its live ephemeral slots again
  (section 3.1), and a value of an older run never returns. It forgets
  each ephemeral slot of a sender that section 3.6 drops, raising the
  floor to the highest mark forgotten, and every ephemeral slot of a space
  it no longer follows.
- A receiver updates its replay state only for a frame it accepts, or as
  the bullets above and section 3.6 say. It MAY keep a sender's window in
  the `replay` table; it keeps ephemeral slot marks, floors and receiver
  nonces in memory only. A window and a floor take a few bytes per sender
  a receiver has accepted a frame from; it keeps them while it follows
  the space.

A device whose new epoch is not above one it used before loses its own
frames at receivers that remember the higher one until it passes it. Two
things cause it: a second restore from one backup, and an older `epoch`
record put back alone while the head stays current, which the device
cannot detect ([at-rest.md](at-rest.md), section 4, "Rollback").

### 3.3 Freshness across restarts

A receiver that restarts without a kept window forgets what it accepted,
and a relay could replay an old command to it. The **receiver nonce**
closes this for every ephemeral message that asks:

- A device draws a fresh 16-byte nonce whenever it starts receiving a
  space's channel, publishes it as its `frasil/nonce` ephemeral slot, and
  holds its last 4 of the current run, never at rest.
- A sender that targets devices MAY add a **fresh entry** per target: the
  target's latest nonce as the sender holds it. A receiver whose fresh
  entry is not one of its 4 nonces refuses the message as `Stale`.
- An application MAY mark names **fresh-only** at its receivers: an
  ephemeral message under such a name with no fresh entry for the receiver
  is `Stale`. A command that must never run twice, such as a cue in a live
  show, is fresh-only.

A replay of an ephemeral message that asked for no freshness, to a receiver
that restarted without a kept window, is accepted.

### 3.4 Receiving

A receiver runs these checks on each outer frame. The first that fails
drops the frame with its class, and nothing is answered.

```text
receive(outer, scope), in order:
   1. len(outer) <= 24,576.                                       else TooLarge
   2. A deterministic CBOR map with key 1 = 1 (else
      UnsupportedVersion); keys 1 to 6 only, with 1, 2, 3, 4 and
      6 present; kind 1 or 2; space of 32 bytes and equal to the
      scope's space; reference bytes; handle present exactly for
      an ephemeral slot, of 16 bytes; sealed of at least 296
      bytes.                                                      else Malformed
   3. The receiver follows the space.                             else NotFollowing
   4. The reference reads, by keys.md or, in a restricted space,
      by ext-restricted-spaces.md (else Malformed or
      TooManyRotations); the receiver holds every rotation it
      names, and k(S).                                            else Sealed
   5. sealed opens under ek(S) with section 2.5's aad.            else Decrypt
   6. The plaintext is a multiple of 256 bytes, at most 18,432;
      its length prefix is at least 1 and fits; every byte after
      the core is zero, and there are fewer than 256 of them; the
      core is a CBOR array of a byte string and a 64-byte byte
      string.                                                     else Malformed
   7. The inner map reads by section 2.3 (else Malformed;
      version other than 1, UnsupportedVersion), and its kind is
      the outer kind.                                             else Malformed
   8. An ephemeral slot: handle is section 2.4's value.           else WrongHandle
   9. sender's ed passes crypto.md's ed25519_valid (else
      InvalidKey), and the signature verifies strictly over tbs
      under it.                                                   else BadSignature
  10. sender's device ID is not this receiver's own.             else Own
  11. A name that begins "frasil/" is one of section 2.7's that
      this receiver implements (else UnknownName), with its kind,
      targets, stream, adapter and data as that table says.       else Malformed
  12. The sender is in, by section 3.6.                           else Forked, MembershipEnded,
                                                                       NotAMember or Unjudgeable
  13. No targets, or this receiver is a target.                   else NotTargeted
  14. A fresh entry for this receiver holds one of its last 4
      nonces; a fresh-only name carries one.                      else Stale
  15. Section 3.2's replay rule and floor.                        else Replayed
  16. An adapter named: the receiver has it (else
      UnknownAdapter), and its capability checks accept
      (section 3.5).                                              else CapabilityRefused
  17. Accepted: update the replay state; deliver the ephemeral
      message, or hold the ephemeral slot value.
```

- **Step 4.** A receiver that lacks a named rotation fetches it as for a
  unit, and MAY hold up to 16 frames for `ephemeral_key_wait` (5 seconds,
  monotonic) meanwhile. A merged key received whole is provisional
  ([keys.md](keys.md)); a frame that does not open under it is `Decrypt`.
- A frame from a non-member costs one AEAD open; a signature is verified
  only after the frame opens and reads. A frame refused at step 13 or later
  was valid for others.
- **A reserved name's data** is then checked by its own document: a head
  statement by [units.md](units.md), a list event by
  [identity.md](identity.md), an access request by
  [admission.md](admission.md), a leave request by
  [ext-guests.md](ext-guests.md) and a ticket by
  [transport.md](transport.md). Those checks decide what the record does,
  never the frame's verdict.

### 3.5 Capability checks

Step 16 runs [units.md](units.md)'s `check(capabilities, context,
content)`. `capabilities` are the sender's in the receiver's current view,
merged over the paths section 3.6 finds as [roster.md](roster.md) merges
them; `context` is the space ID, the kind, `name`, `stream`, `targets`, the
sender's device ID and its level in that view; `content` is `data`. The
check is deterministic, so receivers that hold the same view decide alike,
and it never sees a frame from a non-member or a replay. An ephemeral
message that names no adapter passes Frasil's checks only.

### 3.6 Membership against the current view

A frame has no place. It is judged against the receiver's **current view**:
the events of the space's log it has accepted, and the other logs it holds,
as they stand when the frame arrives.

```text
member(view, sender), in order:
  1. The receiver holds no evidence of a fork of sender's chain in the
     space's log (events.md).                                     else Forked
  2. In the merged roster of the view, sender reaches the space at any
     level by some path, where (roster.md, "Grants of spaces and
     effective membership" and "Checks across logs"):
     - a device grant counts while it is in, with session or without;
     - a person grant counts only if the person's merged list, as the
       receiver holds it, has a valid add of sender as a device or a
       passkey member, no valid revocation of it, and no fork of it;
     - a space grant counts only if sender reaches the granted space,
       and propagates there, in that space's merged roster as the
       receiver holds it;
     - a restricted space counts only if sender also reaches its parent
       in the parent's merged roster as the receiver holds it
       (ext-restricted-spaces.md, "Membership of a restricted space"),
       the parent's own paths judged by these rules; a receiver that does
       not hold the parent's log cannot judge the path.
     If a path holds, sender is in.
  3. No path holds, and a record the receiver holds named sender as
     a member of the space through any path.                     MembershipEnded
  4. No path holds, a path cannot be judged because a log it needs
     is not held, and no other path holds.                       Unjudgeable
  5. Otherwise.                                                   NotAMember
```

- **An end counts as soon as the receiver holds it.** A unit through a
  person or a granted space stands until a response, so that replicas agree
  ([roster.md](roster.md)); a frame is one receiver's decision, made once.
  A revocation in a list, or a removal from a granted space, ends the
  sender's frames at every receiver that holds it, before any cascade.
- **Read is enough.** A demotion keeps the sender in; what a reader may
  send is for capability checks. A waiting list member is in through its
  person's grants, as for its units ([identity.md](identity.md)).
- An `Unjudgeable` frame is dropped, never held; the receiver fetches the
  missing log as for a unit.
- A receiver drops every ephemeral slot of a sender whose membership ends
  in its view, or that the re-check detaches ([transport.md](transport.md),
  section 3.7), and stops relaying its frames; a frame of that sender
  refused at step 12 as `Forked`, `MembershipEnded` or `NotAMember` shows
  the end too. It forgets them as section 3.2 says. A receiver whose own membership
  ended follows the space no more.

### 3.7 Relaying

**An always-on peer** relays a space's channel among the connections that
hold the `live` right for it. A connection joins the channel with its first
`Subscribe` ([units.md](units.md)) or `Ephemeral` for the space. The peer
holds no key and checks only steps 1 and 2 of section 3.4. It:

1. draws, per connection and space, an **origin** of 8 random bytes, never
   derived from the connection's credentials;
2. forwards each frame a device sent it, with no origin, on a
   device-to-peer connection, to every other connection on the channel,
   with the sender's origin at key 3 of `Ephemeral`; it drops an
   `Ephemeral` that carries an origin, and relays to no other peer;
3. holds, per connection and handle, the latest ephemeral slot frame that
   connection sent, at most 64 per connection per space, dropping the
   oldest first, and sends all it holds, with their origins, to a
   connection that joins; it never sends an ephemeral message twice;
4. when a connection closes or loses its `live` right, drops its frames and
   sends `Gone` with its origin to the channel's other connections;
5. holds nothing at rest, holds nothing for a channel no connection is on,
   and applies its own rate limits per connection. Of what it queues for a
   connection, ephemeral frames are at most a sender's queue of section
   2.1, and when that is full it drops the ephemeral frame, never another
   message ([transport.md](transport.md), section 3.8).

A receiver drops an ephemeral slot value when the connection that delivered
it closes, or a `Gone` there names its origin.

A peer's relaying cannot loop: it forwards a frame once to each other
connection, never to the one it came on; a device never sends again a frame
it received, except as a relaying member below, which never sends to a
peer; and a frame that crossed a peer carries an origin, which a peer
drops. So a frame crosses at most one peer.

**A member** MAY relay frames between other members, such as on a local
network. It forwards a frame only if, in order:

1. steps 1 to 12 of section 3.4 pass: it opens the frame and checks its
   seal, its signature and its sender's membership, which every member
   that holds the frame's state can do;
2. its **relay window** for the space and the frame's sender accepts the
   frame's `(epoch, counter)` (else `Replayed`); it then records it.

The relay window is section 3.2's window for ephemeral messages, kept
apart from the member's replay state and over both kinds: per space and
sender, the highest epoch, the highest counter in it, and which of the 64
counters below that the member has forwarded. A sender counts every frame
it sends in a space once, so `(sender, epoch, counter)`, which the
signature binds, names one frame; another frame under the same three is
not forwarded. Steps 13 to 16 decide only the member's own verdict, by
section 3.4, which updates its replay state as for any frame: a frame
targeted at other devices, stale for the relaying member, or under an
adapter it lacks is still forwarded.

It forwards on member connections only, never on the connection the frame
came on and never to an always-on peer, and never adds an origin or sends
`Gone` ([transport.md](transport.md), section 3.1). It keeps one relay
window per sender of the space it has forwarded a frame of: a higher epoch
replaces it, and it leaves when the sender's membership ends in the
member's view (section 3.6) or the member stops relaying the space. A frame
more than 64 counters below the newest it forwarded of its sender is not
forwarded, as a datagram that late may be lost on any path.

So each relaying member forwards each frame at most once, on each of its
member connections at most once: in a ring of relaying members, a frame
stops at the first that forwarded it already.

### 3.8 The reserved routes

- **Endpoints.** A member publishes its current member ticket, with its
  home relay, as `frasil/endpoint` in each space it has open. Members read
  it through any relaying peer and dial the endpoint; the peer sees a sealed
  ephemeral slot.
- **Head statements.** Through always-on peers, a device's head statement
  travels only as its `frasil/heads` ephemeral slot, published again when
  its heads change, at most once per `gossip_interval`.
- **A reader's list events.** A device of a person granted only `read` MAY
  send its person's list events as `frasil/list-events`, targeted at 1 to
  16 writer devices whose frames it receives and whose grant writes in its
  view, when and until [transport.md](transport.md) (section 3.9) says. An
  event too large for `data` goes by a core route.
- **Access requests and leave requests** are targeted at the administering
  devices they name, never broadcast.

### 3.9 Error classes

Besides [overview.md](overview.md)'s classes, this document uses
`TooManyRotations` ([keys.md](keys.md)), `MembershipEnded`
([transport.md](transport.md)), `UnknownAdapter` and `CapabilityRefused`
([units.md](units.md)), and these. Every class here, the shared ones
included, is a decision about one frame and never a verdict on an event;
`Sealed` drops the frame after section 3.4's wait.

| Class | Meaning |
|---|---|
| `NotFollowing` | a space this receiver does not follow |
| `WrongHandle` | an ephemeral slot whose handle is not its own |
| `Own` | the receiver's own frame, echoed back |
| `UnknownName` | a `frasil/` name this receiver does not implement |
| `Unjudgeable` | membership cannot be decided without a log the receiver lacks |
| `NotTargeted` | targeted at other devices |
| `Stale` | a fresh entry this receiver does not hold, or none where its name requires one |
| `Replayed` | refused by the replay window or by a held ephemeral slot |

## 4. Security considerations

- **Signing inside the seal.** Every member holds `ek(S)`, so without the
  signature any member could seal a frame in another device's name. The
  seal hides the sender from relays.
- **What a relay sees:** the space, the kind, the key reference, which units
  show anyway, the handle, the length rounded to 256 bytes, the timing and
  the sending connection. A handle is a PRF output under the ephemeral key:
  it shows only "the same ephemeral slot again" within one state.
- **Replays.** The window refuses them within a run, and the receiver nonce
  across runs for what asks; a window kept at rest refuses the rest.
  Replaying an ephemeral slot to a late joiner is the design, and an
  application shows such a value as last known.
- **Removed members.** An informed receiver refuses a removed member's
  frames at once, and an informed sender seals under a rotation it lacks.
  An uninformed sender leaks frames to it until it hears: eventual removal
  for reads ([overview.md](overview.md), section 2.4). A removed member with
  a read credential can make a relay forward frames that informed receivers
  drop.
- **Capabilities on a view.** Receivers with different views may disagree
  on a frame, which is accepted for traffic no one judges again.
- **Authentication is classical.** A quantum adversary that forges Ed25519
  and holds a state's ephemeral key can send frames in a member's name; it
  changes no event's validity.
- **Denial of service.** A frame costs one AEAD open, then one signature.
  Receivers rate-limit per sender and relays per connection; section 2.1's
  counts bound memory. A member that sends ephemeral slots under ever new
  names costs each receiver at most 32 ephemeral slots, and a space at
  most 2,048, whatever its senders do. A flood on a peer's channel drops
  ephemeral frames, never another member's sync delivery.
- **Loops.** A relaying member forwards a frame once at most, and a peer
  relays only a device's own frames, so no ring of relays carries a frame
  without end.

## 5. Test vectors

[ext-ephemeral.json](vectors/ext-ephemeral.json). An implementation MUST
produce every encoding byte for byte, open each to its fields, and refuse
each refused frame at its step with its class.

- `parameters`: section 2.1's limits, the two timers, and section 2.7's
  names with their kinds.
- `fixtures`: six devices' seeds and keys; a space with two rotations and
  their merged state; a restricted space with its own rotation, its
  parent's state and its key reference; `ek(S)` of each state.
- `frames`: eight frames, each with its fields, the inner map, `tbs`, the
  signature, the core, the padded plaintext, the associated data, the nonce
  and the outer frame: a broadcast cursor; a targeted command with fresh
  entries; a presence ephemeral slot, and the same cleared; a
  `frasil/endpoint`; a restricted space's ephemeral message; one under an
  older state the receiver holds; and a reader's `frasil/list-events`.
- `accepted_in_order`: one receiver accepts the eight, with one replay
  state.
- `frame_refusals`: one frame for each step and class, with the receiver's
  context where it matters, among them a reference moved to another held
  state, a fresh entry for a non-target, a reserved name of the wrong kind
  or broadcast where it must be targeted, a signature by another device, a
  small-order sender, and senders whose membership ended, that no record
  names (among them a member's Ed25519 key under another `kc`), that
  forked, or reached only through a list not held.
- `replay_window`: the window over thirteen arrivals, an ephemeral slot
  over seven, and a receiver's bounds: one sender's ephemeral slots past
  32, its floor, a new epoch, and a space's past 2,048.
- `receiver_restart`: a command accepted; after a restart, its replay and a
  new command with the old run's nonce are `Stale`; a replayed cursor is
  accepted with a window in memory and `Replayed` with one kept at rest; a
  command with the new nonce is accepted.
- `epochs`: a device's epochs across starts and after a restore.
- `membership`: section 3.6 as a table of views and verdicts.
- `relay`: a relay's steps, from two connections to a late joiner, a `Gone`
  and a close; and three relaying members in a ring, each forwarding a
  frame once and refusing it the second time.
