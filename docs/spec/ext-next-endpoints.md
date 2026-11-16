# Announced next endpoints
Protocol 1. Vectors: [ext-next-endpoints.json](vectors/ext-next-endpoints.json).

This extension lets a device tell the members it is connected to which
member endpoint key it will take at its next rotation, so that members
with no always-on peer find each other again after both of them have
rotated. It extends [transport.md](transport.md), which reserves the
ignorable message type 96 it uses and whose "Reconnecting" it widens, and
[at-rest.md](at-rest.md), which reserves its `next_endpoint` and
`announced` tables. It depends on [overview.md](overview.md) for
conventions and error classes, and on [crypto.md](crypto.md) for key
validation.

A core implementation that does not implement it:

| What this document defines | A core implementation |
|---|---|
| Message type 96, `NextEndpoint` | drops it as an unknown ignorable type ([transport.md](transport.md), section 2.4) and never sends it |
| Tables `0x04` and `0x1f` | never writes them ([at-rest.md](at-rest.md)) |
| Taking an announced key at a rotation | draws every member endpoint key fresh |

## 1. Overview

- A device's member endpoint key is random and rotates at least every
  `endpoint_rotation` and whenever the device joins another network
  ([transport.md](transport.md), "The iroh binding"). A member that kept
  a ticket of it reaches it again only until it rotates.
- With this extension a device draws its **next** member endpoint key
  ahead of time and keeps its seed at rest. Once it has admitted a member
  on an attach, and been admitted, it sends that member the next key in a
  `NextEndpoint`. The member keeps it beside the ticket it keeps of the
  device.
- At its next rotation the device takes the announced key as its member
  endpoint key, and draws and announces another. A member that dials
  again after a restart dials the ticket it kept and the same ticket under
  the announced key.
- Two members therefore reach each other again unless both have rotated
  twice since they last met. The next key travels only inside member
  connections, so nobody outside the space learns it, and no party sees a
  name that outlives a rotation.

## 2. Formats

### 2.1 The message

```text
NextEndpoint = {0: 96, 1: attach, 2: next endpoint key (32)}
```

| Type | Name | Keys | Class | Cap (bytes) |
|---|---|---|---|---|
| 96 | `NextEndpoint` | 1 attach, 2 the sender's next member endpoint key | control, on member connections only | 4,096 |

`NextEndpoint` has exactly the keys listed. Its type is in transport.md's
ignorable range, so a receiver that does not implement this extension
drops it, and a sender MAY send it to any member.

### 2.2 At rest

| Code | Table | Scope | Item | Value |
|---|---|---|---|---|
| `0x04` | `next_endpoint` | device | empty | 32 bytes: the seed of the member endpoint key this device announces as its next |
| `0x1f` | `announced` | log | a member's device ID (32) | 32 bytes: the next member endpoint key that member announced in the space |

The seed is an Ed25519 seed, and the endpoint key is its public key, as
for every member endpoint key ([transport.md](transport.md), "The iroh
binding"). A `next_endpoint` record is the one member endpoint secret a
device writes ([at-rest.md](at-rest.md), "What is never written").

## 3. Procedures

### 3.1 Rotating

At each rotation of its member endpoint, in order:

```text
rotate(), in order:
  1. If the device keeps a next_endpoint record, its seed is the new
     member endpoint seed; otherwise the device draws 32 fresh random
     bytes for it.
  2. The device draws 32 fresh random bytes as its next seed, and
     replaces its next_endpoint record with them.
  3. Once the record is durable, the device binds its member endpoint
     under the seed of step 1.
```

- A device MUST NOT take a seed it took before, nor announce a key
  before its `next_endpoint` record holds that key's seed.
- A device that opens again rotates: it never takes again the member
  endpoint key of a previous run.

### 3.2 Announcing

- **Sending.** Once a side has both sent and received `Admit` for an
  attach on a member connection, it sends the other a `NextEndpoint` for
  that attach on the control stream, naming the public key of its
  `next_endpoint` seed. It sends again on each such attach whenever that
  seed changes, and at most once per attach for each seed.
- **Withdrawing.** When the membership of a device it has admitted on an
  attach ends in this device's view, as by a removal or the end of a
  guest session ([ext-guests.md](ext-guests.md)), the device replaces its
  `next_endpoint` record with 32 fresh random bytes before its next
  rotation, and announces the new key as above. A key a former member
  learned is then never taken.

### 3.3 Receiving

```text
on NextEndpoint, at the receiver, in order:
  1. read_frame; on a member connection; exactly keys 0 to 2; an
     unsigned attach; key 2 a 32-byte string.                  else Malformed
  2. Key 2 is an endpoint key crypto.md accepts.                else InvalidKey
  3. Both sides have sent Admit for the attach.                 else drop it
  4. Key 2 is not the sender's member endpoint key on this
     connection.                                               else drop it
  5. The receiver replaces its announced record of the sender
     in the attach's space with key 2.
```

- A failure at step 1 or 2 closes the connection with transport.md's
  code for the class (section 2.5). A step-3 drop is not a refusal: a
  `NextEndpoint` can cross a `Detach`.
- A receiver keeps an `announced` record only beside an `endpoint` record
  of the same member in the same space, and deletes it with that record
  ([transport.md](transport.md), "Reconnecting"). A receiver that keeps
  nothing at rest, such as a guest asked to ([ext-guests.md](ext-guests.md)),
  holds the key for the life of its run instead.

### 3.4 Reconnecting

This section widens transport.md's "Reconnecting". A device that dials a
ticket it keeps of a member, and keeps an `announced` key of that member
in the same space that differs from the ticket's endpoint key, also dials
the **announced ticket**: the kept ticket with its endpoint key replaced
by the announced key, with the same relay URLs and direct addresses, with
the member ALPN, attaching each space that keeps that ticket.

- A device dials the kept ticket first and the announced ticket second,
  and MAY dial both in each round of dialing again. It MUST NOT dial an
  announced ticket while it holds an admitted attach of the space with
  that member.
- The member handshake decides everything; the announced ticket only says
  where to dial. Once an attach that both sides admit forms at either
  ticket, "Reconnecting" keeps the ticket at which that connection reaches
  the member, and the member's next `NextEndpoint` replaces the
  `announced` record.

## 4. Security considerations

- **Who learns a next key.** Only devices admitted to an attach of a space
  the sender is in, over a member connection whose channel the member
  handshake bound. An always-on peer never carries `NextEndpoint`, so no
  peer learns that two member endpoint keys belong to one device.
- **Unlinkability.** A next key is random and independent of every
  earlier key, is published under no public name, and is first used on
  the network at the rotation that takes it. A relay or a network observer
  sees what it already sees at a rotation: an endpoint key registering
  from where the device is, and the members that dial it. A dial of an
  announced ticket tells a relay which key the dialer asks for, as any
  dial does; made before the member has taken that key, it shows the key
  early, which section 3.4 limits to members not reached.
- **Former members.** A member removed, or a guest whose session ended,
  keeps the key it was told. Section 3.2's withdrawal replaces it, so a
  former member that dials it reaches nothing. A device that learns of the
  end only after its rotation has already taken that key: the former
  member can recognise that one key until the following rotation, and the
  member handshake still refuses it, since its membership ended.
- **The seed at rest.** The `next_endpoint` record is sealed like every
  record. Whoever holds the unlocked store can bind the device's next
  member endpoint, which only lets it receive dials that the member
  handshake then judges; it gains no membership.

## 5. Test vectors

[ext-next-endpoints.json](vectors/ext-next-endpoints.json). An
implementation MUST produce every encoding byte for byte, and refuse each
refused message with its class.

- `parameters`: the type, its cap, and the two table codes.
- `rotation`: a kept next seed and a fresh one, the member endpoint key
  the rotation takes and the next key it announces, and the
  `next_endpoint` record's value before and after.
- `announcement`: a `NextEndpoint` on attach 0, its frame, the same frame
  dropped by a core receiver, and the receiver's outcomes: kept, dropped
  on an attach both sides have not admitted, and dropped when it names
  the sender's current key.
- `refused`: an extra key, a key of 31 bytes, an attach that is not
  unsigned, a small-order key (`InvalidKey`), and a `NextEndpoint` on a
  device-to-peer connection (`Malformed`).
- `reconnecting`: a kept ticket and an announced key, and the tickets
  dialed in order; the same with an announced key equal to the ticket's,
  which dials the kept ticket alone.
