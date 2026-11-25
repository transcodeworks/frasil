# Transport
Protocol 1. Vectors: [transport.json](vectors/transport.json).

This document specifies what a transport must provide to Frasil, the two
handshakes that open a connection, the framing and message set that carry
[units.md](units.md)'s sync and everything around it, mailboxes, and two
bindings: the server binding (HTTP and WebSocket) and the iroh binding
(QUIC with raw public keys), with local discovery and nearby pairing. It
depends on [overview.md](overview.md) for conventions, error classes and
timers, on [crypto.md](crypto.md) for primitives and labels, on
[roster.md](roster.md) and [identity.md](identity.md) for who a member is,
on [keys.md](keys.md) for states and their keys, and on
[peers.md](peers.md) for storage credentials.

## 1. Overview

- A **member connection** joins two devices. Each end proves that it holds
  a state of a space, without showing a non-member which space, then binds
  its device ID to the connection, then checks the other against the
  roster it holds. One connection carries any number of spaces, each
  **attached** by its own proof.
- A **device-to-peer connection** joins a device to an always-on peer. The
  device never proves who it is: it presents storage credentials, each
  proof bound to the connection.
- A **nearby connection** carries one admission exchange on a local
  network.
- The transport proves an **endpoint key**, never a device's keys. A
  device's member endpoint key rotates, so the network sees no stable name
  for it.
- Space events travel ahead of everything else, and a device checks every
  attached device again whenever its view changes, so a removal takes
  effect on a connection as soon as either end holds it.
- The ephemeral channel is [ext-ephemeral.md](ext-ephemeral.md)'s. This
  document defines only the lossy channel a transport provides for it and
  the message types it reserves.

## 2. Formats

### 2.1 What a transport provides

A **binding** maps a transport onto four requirements. Frasil needs nothing
else from it.

- **T1. An identity proved by the transport's own handshake.** On a member
  connection, each end proves an endpoint key, a 32-byte Ed25519 public
  key. On a device-to-peer connection, the peer proves its identity, as a
  WebPKI origin or an endpoint key, and the device proves nothing.
- **T2. A channel binding.** A 32-byte value, equal at both ends, unique to
  the transport session, fixed before either end sends a Frasil message,
  and different on the two sessions of anyone in the middle. Everything
  either end proves is bound to it. A binding that cannot read a value
  unique to its session, such as the server binding in a browser (section
  3.15), MAY instead fix the channel to the identity of T1, if that
  identity is one that only its holder can terminate a session as. The
  value is then the same on every connection to that identity, and only
  the fresh nonces each end adds make a binding unique to its connection;
  a party in the middle would have to terminate the session as that
  identity, which only its holder can. Such a binding carries device-to-peer
  connections only, whose `binding` holds both nonces (section 3.10).
- **T3. Reliable, ordered frames** of up to 1,056,768 bytes, on one or more
  ordered byte streams or message channels.
- **T4. A lossy channel ahead of bulk.** A way to send frames that never
  wait behind sync or object frames: unreliable datagrams, or a stream the
  transport sends ahead of all others, from which the sender drops what it
  cannot send in time.

A session above the transport sees only: `peer()`, the identity of T1;
`channel()`, the value of T2; ordered streams of the classes of section
2.3, which it opens, sends on and receives from; `send_lossy` and
`receive_lossy`, for T4; and `close(code)`, with section 2.5's codes. It
sees no URL, socket or QUIC type.

A new transport that meets T1 to T4 needs only a binding: how it meets each
requirement, its ALPN or equivalent, and how it frames. It is not a new
protocol (overview, section 5.6). A binding that cannot meet T2 between two
devices, such as a server relaying bytes it can read, MUST carry only
device-to-peer connections.

### 2.2 Labels and names

This document uses the labels and ALPNs that [crypto.md](crypto.md)'s
registry assigns to it, the credential proof's label of
[peers.md](peers.md), and the WebSocket subprotocol `frasil.p1`. The
exporter label `EXPORTER-Channel-Binding` is RFC 9266's.

Notation, beyond overview's: `k(S)` is the content key of state `S`
([keys.md](keys.md)). The **dialer** opens a connection; the **listener**
accepts it. The **initiator** of an attach sends its offer; the
**responder** answers.

### 2.3 Frames and stream classes

On a stream, a frame is

```text
frame = u32be(len(message)) || message
```

On a message channel, such as a WebSocket or a datagram, one message is one
frame, with no prefix. A **message** is a deterministic CBOR map whose key
0 is its type (section 2.4).

| Stream class | Cap (bytes) | Carries |
|---|---|---|
| control | 266,240 | handshakes, attaches, `Addresses`, presents, mailbox messages, `Merge`, `RegisterRecoveryEntry`, `Awaiting`, `EventRefused`, `Gone`, and types 21, 28, 31, 40 to 43, 96 and 97 |
| sync | 1,056,768 | `Open`, `Sync`, `AdapterSync` |
| object | 1,056,768 | `Open`, `Sync` carrying object chunks |
| ephemeral | 25,088 | `Open`, `Ephemeral` |
| nearby | 266,240 | `Pairing` |

### 2.4 Message types

| Type | Name | Keys | Cap (bytes) |
|---|---|---|---|
| 1 | `Offer` | 1 attach, 2 nonce, 3 tags, 4 revision (section 2.6) | 4,096 |
| 2 | `Answer` | 1 attach, 2 nonce, 3 index, 4 proof (section 2.6) | 4,096 |
| 3 | `Refuse` | 1 attach, 2 code | 4,096 |
| 4 | `Identify` | 1 `ed \|\| kc`, 2 signature (section 2.6) | 4,096 |
| 5 | `Admit` | 1 attach | 4,096 |
| 6 | `Detach` | 1 attach, 2 code | 4,096 |
| 7 | `Open` | 1 class: 1 sync, 2 object, 3 ephemeral; 2 scope, absent for ephemeral | 4,096 |
| 8 | `Addresses` | 1 attach, 2 entries: 0 to 64 pairs of a device ID (32) and a member ticket's CBOR (section 3.16) | 16,384 |
| 16 | `PeerHello` | section 3.10 | 16,384 |
| 17 | `Hello` | section 3.10 | 16,384 |
| 18 | `Present` | section 3.11 | 16,384 |
| 19 | `Granted` | section 3.11 | 16,384 |
| 20 | `Refused` | 1 request, 2 code (text) | 16,384 |
| 21 | reserved | `LibraryAttach`, [ext-libraries.md](ext-libraries.md)'s | 16,384 |
| 22 | `Accepted` | 1 request | 16,384 |
| 23 | `Merge` | 1 request, 2 a merge statement ([peers.md](peers.md)), as a nested map | 16,384 |
| 24 | `MailboxPut` | section 2.7 | 266,240 |
| 25 | `MailboxGet` | section 2.7 | 266,240 |
| 26 | `MailboxItems` | section 2.7 | 266,240 |
| 27 | `Awaiting` | 1 space, 2 event IDs, 0 to 7,829, strictly ascending | 266,240 |
| 28 | reserved | `MailboxDelete`, [ext-invite-links.md](ext-invite-links.md)'s | 16,384 |
| 29 | `RegisterRecoveryEntry` | 1 request, 2 space (32), 3 fetch key (32) (section 3.11) | 16,384 |
| 30 | `EventRefused` | 1 space (32), 2 event ID (32), 3 code (text) (section 3.10) | 16,384 |
| 31 | reserved | `HoldObject`, [ext-libraries.md](ext-libraries.md)'s | 16,384 |
| 32 | `Sync` | 1 scope, 2 one message of [units.md](units.md)'s baseline sync, as a byte string of at most 1,052,672 bytes | 1,056,768 |
| 34 | `AdapterSync` | 1 scope, 2 adapter ID (text), 3 bytes | 1,056,768 |
| 40 to 43 | reserved | `TokenKeysGet`, `TokenKeys`, `TokenRequest` and `TokenIssue`, [ext-deposit-tokens.md](ext-deposit-tokens.md)'s | 16,384 |
| 48 | `Ephemeral` | 1 scope, 2 an outer frame (bytes), 3 origin (8 bytes; from a peer only) | 25,088 |
| 49 | `Gone` | 1 scope, 2 origin (8 bytes) | 25,088 |
| 64 | `Pairing` | 1 one message of [admission.md](admission.md)'s exchange (bytes); 2 a member ticket, its text form (section 2.8), beside a welcome only (section 3.16) | 266,240 |
| 96 | reserved | `NextEndpoint`, [ext-next-endpoints.md](ext-next-endpoints.md)'s, on the control stream of a member connection | 4,096 |
| 97 | `ErasureLate` | 1 space (32), 2 erasure event ID (32), 3 the cut, its signed envelope (bytes), 4 the cut's checkpoint's ID (32), 5 standing: 0, 1 or 2 ([peers.md](peers.md), "A device's own erasure"); from a peer, on an administration connection | 266,240 |

- The **scope** names what a message is about: the attach number on a
  member connection, the space ID on a device-to-peer connection.
- Types 96 to 127 are ignorable: a receiver drops one it does not know. On
  any other type it does not know, a receiver MUST close the connection
  with `malformed` (`UnknownMessage`). A new type outside 96 to 127 is a new protocol.
- Types 1 to 6, 8, 16, 17 and 18 have exactly the keys listed. `Refuse`,
  `Detach`, `Granted`, `Refused` and `EventRefused` have nothing else.
- **Reserved for the ephemeral channel.** Types 48 and 49 and the ephemeral
  stream class carry [ext-ephemeral.md](ext-ephemeral.md)'s outer frames,
  whose content, limits and relaying it defines. A receiver that does not
  implement it drops `Ephemeral` and `Gone` messages and never relays them.
- `ErasureLate` is in the ignorable range so that a device that does not
  read it drops it and asks on, as it would without it. It has exactly
  the keys listed.
- Types 21, 28, 31, 40 to 43 and 96 are their extensions'. A receiver that
  does not implement the extension treats them as unknown, so it drops type
  96.

### 2.5 Codes

One table serves QUIC application close codes, WebSocket close codes (4000
plus the code), `Refuse` and `Detach`. Each name but `done` and `reconnect`
is an error class in snake case: overview's (section 5.5) or section 3.13's.

| Code | Name | Used for |
|---|---|---|
| 0 | `done` | a normal close; an attach no longer wanted |
| 1 | `malformed` | a frame or message that does not read |
| 2 | `too_large` | over a cap |
| 3 | `unsupported_version` | another protocol |
| 4 | `no_common_state` | no offered state matched |
| 5 | `bad_proof` | an answer that does not verify |
| 6 | `bad_signature` | an `Identify` that does not verify |
| 7 | `membership_ended` | the device is out of the verifier's view |
| 8 | `unknown_member` | probation ended without the device |
| 9 | `timeout` | `handshake_deadline` passed |
| 10 | `attach_limit` | an attach number of 1,024 or more |
| 11 | `busy` | the responder's budget or rate limit |
| 12 | `purpose_violation` | section 3.10 |
| 13 | `credential_refused` | a credential refused, or a message with no right |
| 14 | `invalid_key` | a key [crypto.md](crypto.md) refuses |
| 15 | `forked` | the device forked its chain in the space |
| 16 | `revision_mismatch` | the other end runs another revision (overview, section 5.6) |
| 17 | `reconnect` | a peer's close that asks the device to connect again, not an error (section 3.10) |

A **reason code** is the `code` of a `Refused` or `EventRefused` message,
or the body `{"code": "<reason>"}` of an HTTP error. The reason codes this
document raises, with their HTTP status:

| Status | Reason | When |
|---|---|---|
| 400 | `malformed` | a body, path or message that does not read |
| 400 | `revision_mismatch` | a request of another revision |
| 401 | `unauthenticated` | an account route or person mailbox without a valid bearer token |
| 403 | `credential_refused` | a transfer token or credential refused, or a request with no right |
| 403 | `purpose_violation` | section 3.10 |
| 404 | `not_found` | |
| 413 | `too_large` | over a limit of the peer's discovery, or of a format |
| 422 | `invalid_key`, `bad_signature` | key validation; a signature that does not verify |
| 426 | | a request to the connect route that is not a WebSocket upgrade |
| 429 | `rate_limited` | |
| 503 | `busy` | |

Codes that [peers.md](peers.md), [admission.md](admission.md) and the
extensions define travel the same way, with the status their document
gives, such as peers.md's `recovery_entries_full` (507). No reason code reveals another space, account or device.

### 2.6 Member handshake values

```text
hk(S)    = HKDF(none, k(S), "frasil/member-key/v1")                        32 bytes

tag(S)   = HMAC(hk(S), "frasil/member-offer/v1" || field(channel) || u8(0x01)
                       || u32be(attach) || nonce)                          32 bytes
Offer    = {0: 1, 1: attach, 2: nonce (32), 3: [tag_0, ..., tag_15], 4: revision}

core     = {0: 2, 1: attach, 2: nonce_R (32), 3: index}
th       = SHA-256("frasil/member-transcript/v1" || field(channel)
                   || field(endpoint_I) || field(endpoint_R)
                   || field(offer) || field(core))
proof    = HMAC(hk(P), "frasil/member-answer/v1" || th)
Answer   = {0: 2, 1: attach, 2: nonce_R, 3: index, 4: proof}

signed   = "frasil/member-identify/v1" || th_0 || u8(role) || ed || kc
Identify = {0: 4, 1: ed || kc (64), 2: Ed25519-Sign(identity seed, signed)}

Refuse   = {0: 3, 1: attach, 2: code}
Admit    = {0: 5, 1: attach}
Detach   = {0: 6, 1: attach, 2: code}
```

- `hk(S)` is a state's **member key**. It only authenticates; nothing is
  sealed under it. [ext-restricted-spaces.md](ext-restricted-spaces.md)
  says which secret replaces `k(S)` in a restricted space.
- `nonce` and `nonce_R` are 32 fresh random bytes per offer and per answer.
  `0x01` marks an initiator's tag. `revision` is overview's (section 5.6).
- `endpoint_I` and `endpoint_R` are the initiator's and the responder's
  endpoint keys as the transport proved them; `offer` is the offer's bytes
  as received; `P` is the **proof state** of section 3.3.
- `th_0` is attach 0's transcript. `role` is the signer's role on the
  connection: `0x01` the dialer, `0x02` the listener.
- `ed || kc` is the device's Ed25519 identity key and keys commitment
  ([crypto.md](crypto.md), "A device's keys"). The signature covers both,
  so the device it binds to the connection is the device ID they give, and
  no other key holder that shares its Ed25519 key.
- `Identify` is a scheme-0 structure, verified once, at once
  ([crypto.md](crypto.md)).

### 2.7 Mailboxes

A **mailbox** at an always-on peer holds items for a recipient that is not
connected. It is named by a kind and an address:

```text
address = SHA-256("frasil/mailbox/v1" || u8(kind) || field(name))
```

| Kind | Name | Deposits | Collects | Lifetime |
|---|---|---|---|---|
| 1, **exchange mailbox** | a request ID, 16 bytes ([admission.md](admission.md)) | anyone holding the request ID | anyone holding the request ID | `exchange_mailbox_lifetime` |
| 2, person mailbox | a person ID | anyone | a bearer of an account whose link names the person ID, at that account's server only | `mailbox_retention` |
| 3, device mailbox | a device ID | anyone | that device, by the signature of section 3.14 | `mailbox_retention` |
| 4, reserved | | | | [ext-invite-links.md](ext-invite-links.md)'s invite drop |

```text
MailboxPut   = {0: 24, 1: request, 2: address (32), 3: item (at most 262,144 bytes),
                6: kind}
MailboxGet   = {0: 25, 1: request, 2: address (32), 3: after (16; optional),
                4: ed || kc (64), 5: signature (64), 6: kind}
MailboxItems = {0: 26, 1: request, 2: [[item ID (16), item], ...]}
```

- `MailboxGet`'s keys 4 and 5 are present exactly for a device mailbox.
  `MailboxPut`'s keys 4 and 5 are reserved for kind 4, and its key 7 for a
  deposit token of kind 3 ([ext-deposit-tokens.md](ext-deposit-tokens.md)).
- A peer assigns each item a 16-byte ID, in deposit order. `after` asks for
  the items after that ID. `MailboxItems` carries at most 262,144 bytes of
  items, oldest first.
- The kind travels beside the address, and a peer keeps each mailbox under
  both. The address hashes the kind, so naming another kind names another,
  empty mailbox.
- A device mailbox holds at most 64 items and 4 MiB. A deposit past either
  evicts the oldest items first.
- Kind 2 exists only at an account's server, through the server binding
  (section 3.15). A peer that does not implement
  [ext-invite-links.md](ext-invite-links.md) refuses kind 4 as `Malformed`.

**The item seal.** An exchange mailbox carries [admission.md](admission.md)'s
messages, and a person mailbox its prompts, each in its own format. An item
in a device mailbox whose own document defines no seal uses this one. Its
layout is [crypto.md](crypto.md)'s X-Wing wrap:

```text
item      = 0x01 || u16be(0x647a) || enc (1,120) || ciphertext
(enc, ciphertext) = HPKE-Seal(recipient's X-Wing key, info, aad = "", plaintext)
info      = "frasil/mailbox-item/v1" || u16be(0x647a) || recipient's device ID (32)
plaintext = {1: content name (text, 1 to 64 bytes), 2: body (bytes)}
```

- The sender seals to the X-Wing key the recipient's device ID commits
  to, taken from any source and checked by its hash, as
  [crypto.md](crypto.md) requires of every wrap.
- An item has one recipient. What goes to several devices is sealed once
  for each.
- The **content name** says what the body is. Names that begin `frasil/`
  are Frasil's:

| Content name | Body | Defined in |
|---|---|---|
| `frasil/access-request` | a signed access request. A requester deposits one item in the device mailbox of each administering device it names; an access request is never broadcast | [admission.md](admission.md), "Access requests" |
| `frasil/welcome-request` | a signed welcome request from a member that holds no key of the space, for each administering device it names | [admission.md](admission.md), "Welcome requests" |
| `frasil/leave-request` | a signed leave request, for each administering device that will act on it | [ext-guests.md](ext-guests.md) |
| `frasil/list-events` | signed device-list events from a device that cannot publish them itself (a read-only person's, or a device a recovery agent added, [ext-recovery-agent.md](ext-recovery-agent.md)), with the space to forward them into, for a writer's device (section 3.9) | [units.md](units.md), "Frasil's own units" |

Any other name is the application's. [ext-ephemeral.md](ext-ephemeral.md)
uses the same names for the same records. A core implementation that does
not implement [ext-guests.md](ext-guests.md) drops a leave request
(`UnknownContent`).

### 2.8 Tickets

A **ticket** is an address to dial. It holds no secret and grants nothing.

```text
ticket = {1: 1, 2: kind (1 member, 2 peer, 3 nearby), 3: endpoint key (32),
          4: relay URLs (array of 1 to 4 https URLs; optional),
          5: direct addresses (array of 1 to 16: 4 bytes IPv4 or 16 bytes IPv6,
             then a 2-byte port; optional)}
text   = "frasil:" || base64url(ticket), without padding
```

A ticket is at most 1,024 bytes of CBOR. A reader refuses, as `Malformed`,
another prefix, padding, a base64url or CBOR encoding that is not canonical,
an unknown key and a relay URL that is not `https`; and, as `InvalidKey`,
an endpoint key [crypto.md](crypto.md) refuses.

### 2.9 Local-network packets

All local-network packets go to the IPv4 multicast group `239.255.77.67`
and the IPv6 group `ff02::7767`, UDP port 47767, with a TTL or hop limit of
1.

```text
member announcement, for one space at state S:
  lan_key(S) = HKDF(none, k(S), "frasil/lan-key/v1")
  core       = {1: member endpoint key (32), 2: port (1 to 65,535)}
  plaintext  = u16be(len(core)) || core || zero bytes, 96 bytes in all
  packet     = 0x01 || nonce (24) || XChaCha20-Poly1305(lan_key(S), nonce, plaintext,
                                                        aad = "frasil/lan-announce/v1")
                                                        137 bytes

nearby announcement:
  packet     = 0x02 || {1: endpoint key (32), 2: port, 3: name (text)}
```

- `nonce` is 24 fresh random bytes per packet.
- The nearby `name` is the application's display name with every control
  character (Unicode category Cc) and bidirectional control (U+061C,
  U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) removed, trimmed of
  white space, cut to 48 characters and trimmed again; `Nearby device` if
  nothing is left. A headless device in setup mode announces `setup-` and
  its setup tag in lower-case hexadecimal ([admission.md](admission.md)).

## 3. Procedures

### 3.1 Reading a frame

```text
read_frame(bytes, class, connection), in order:
  1. The 4-byte prefix is at most the class's cap.              else TooLarge
  2. The payload is one deterministic CBOR map whose key 0 is
     unsigned, and is not empty.                                else Malformed
  3. The type is known; an unknown type in 96 to 127 is
     dropped.                                                   else UnknownMessage
  4. The class carries the type.                                else Malformed
  5. The payload is within the type's cap.                      else TooLarge
  6. On a member connection: the type is not Gone, and an
     Ephemeral carries no key 3. On any other connection: the
     type is not Addresses.                                     else Malformed
```

Step 1 runs before anything is allocated. Unless this document says
otherwise, a failure closes the connection with section 2.5's code.

### 3.2 The member handshake: the offer

A member connection is the iroh binding's ALPN `frasil/p1/member`, or any
binding that meets T1 to T4 end to end between two devices. The dialer
initiates attach 0.

The initiator chooses, for one space, the states it offers, in this order:

1. its current state `S`;
2. if `S` holds several rotations, each of them alone that it holds, in
   canonical order, at most 7;
3. the states it held as current before `S`, most recent first;

at most 16 in all. It computes `tag` for each, fills the remaining places
with fresh random 32-byte values, and sends one `Offer` of exactly 16 tags.

After a `Refuse` with `no_common_state`, the initiator MAY send up to 3 more
offers for the same attach, each with a new nonce and the next 16 older
states it holds. After the fourth refusal the attach is over.

### 3.3 The member handshake: the responder's match

For each space it serves on member connections, the responder keeps a list
of **candidate states**, newest first: its current state; each rotation of
it alone, if it holds several; the states it held as current before, most
recent first; and every other single rotation it holds, by descending
height of the rotation's event, then ascending event ID. It keeps at most
256 per space.

```text
on Offer, in order:
  1. read_frame; exactly keys 0 to 4; an unsigned revision.    else Malformed
  2. The revision is the responder's.                           else Refuse RevisionMismatch
  3. The attach number is below 1,024.                          else AttachLimit
  4. The attach number has the initiator's parity; a 32-byte
     nonce; exactly 16 tags of 32 bytes.                        else Malformed
  5. This is at most the fourth offer of the attach.            else Malformed
  6. Compute tag(C) for candidates C, with the offer's channel,
     attach and nonce, at most 8,192 per offer, and look each up
     among the offer's tags. The match is the candidate whose tag
     equals the offer's tag of the smallest index; among equal
     tags, the first in the responder's order.                  else Refuse NoCommonState,
                                                                     or Busy
  7. The match fixes the space and the proof state P. Send
     Answer; for attach 0, then Identify.
```

- **An offer it cannot refuse.** A `Refuse` names the offer's attach. An
  offer that fails step 2 and whose attach is not an unsigned integer has
  none to name, so the responder MUST close the connection with
  `malformed`.
- **Order of spaces.** The responder takes spaces by most recent use,
  except that it takes first the spaces and states it announced on the
  local network (section 3.16), or published in a member ticket. A dialer
  that found it that way leads its offer with that state, so the match
  falls within the budget.
- **Busy.** A responder that ran out of budget without a match, or that
  rate-limits, answers `busy`, not `no_common_state`. The dialer retries
  with an offer that leads with the state under which it found the
  responder, or with older states.
- A non-member finds no match and answers `no_common_state`, as does a
  member far behind. The tags are HMAC outputs under keys it lacks, so it
  learns nothing.

### 3.4 The member handshake: the initiator, and Identify

```text
on Answer or Refuse, at the initiator, in order:
  1. A Refuse: its code ends this offer (section 3.2).
  2. The Answer has exactly keys 0 to 4, names its attach, and
     holds a 32-byte nonce, an index from 0 to 15 and a 32-byte
     proof.                                                     else Malformed
  3. The index names one of its real states, not a filler.      else BadProof
  4. proof = HMAC(hk(P), "frasil/member-answer/v1" || th), over
     the transcript the initiator computes, compared in constant
     time.                                                      else BadProof
  5. For attach 0: send Identify.

on Identify, at either side, in order:
  6. Exactly keys 0 to 2; a 64-byte ed || kc; a 64-byte
     signature.                                                 else Malformed
  7. ed is valid (crypto.md).                                   else InvalidKey
  8. The signature verifies strictly under ed over signed, with
     th_0, the role the sender holds on this connection, and
     ed || kc.                                                  else BadSignature
  9. Run the roster check (section 3.5) for the device ID of ed
     and kc.
```

- The responder sends its `Identify` right after its `Answer`, having
  verified the initiator's tag. The initiator sends its own after step 4.
  Neither learns the other's device before it holds the other's proof.
- `Identify` is sent once per connection. Every later attach is checked
  against the device of attach 0.
- From the transport's connection to the first `Admit` or refusal, the
  handshake runs within `handshake_deadline` (`Timeout`).

### 3.5 The roster check

For each attach, each side checks the other's device against **its own
current view** of the space:

| The device, in the verifier's view | Outcome |
|---|---|
| reaches the space at any level: through a device grant, a guest's included; a person grant whose list vouches for the device; or a granted space it reaches through | `Admit` |
| has a fork point in the space's log | `Detach`, `Forked` |
| was named and reaches the space no longer: removed, revoked from its list, or gone from a granted space | `Detach`, `MembershipEnded` |
| is named nowhere in the view, or reaches the space only through a log the verifier does not hold | probation |

- A side serves an attach only once it has admitted the other for it: no
  unit, object, ephemeral frame, head statement or member address before.
- **Probation.** The device proved a state, so it was entitled to that
  state, but the verifier's view does not name it: its grant is in an event
  the verifier lacks. During probation the verifier fetches from the device
  and judges what it receives by its own rules. Each side serves a device
  in probation only what [peers.md](peers.md) serves under catch-up: space
  events, storage events, by ID any parent of an event already served, and
  the units of the system stream, which is what a peer serves to a retired
  read credential. Two devices that each lack the other's
  grant therefore cannot deadlock. Probation ends at the first of: the
  device is in (`Admit`); it is out (`Detach` as above); `probation` is
  spent, 30 seconds or 4,096 events (`Detach`, `UnknownMember`).
- A verifier that has not received a removal admits the removed device.
  This is eventual removal for reads (overview, section 2.4). Section 3.7
  ends it as soon as either side holds the removal.
- The verifier never asks the device what it holds. The answer is in its
  own view.
- Each side sends its outcome as soon as it has one, so an `Admit` or a
  `Detach` can cross the other side's `Detach` of the same attach. A side
  drops an `Admit` or a `Detach` that names an attach it has detached. One
  that names an attach never offered is `Malformed`.

### 3.6 Further attaches

- Either side MAY attach another space on the same connection, with an
  `Offer` and an `Answer` as above. The dialer numbers its attaches 0, 2,
  4 and so on, the listener 1, 3, 5, all below 1,024 (`AttachLimit`).
- `Identify` is not repeated. Each space's roster check uses the device of
  attach 0.
- Once the other side's `Identify` has verified, a device SHOULD offer each
  other space it holds that the other device reaches in its own current
  view (section 3.5), and SHOULD do so again when it comes to hold another
  space or its view of one changes, so that two devices attach every space
  they share however they found each other. Of its own accord it offers no
  space in which the other device is out or named nowhere, and none the
  other side refused or detached on this connection: the other side offers
  that space once its own view admits it.
- A connection carries a space on one attach. An initiator does not offer a
  space an attach of the connection carries. A responder leaves out of its
  candidates (section 3.3) each space an attach of the connection carries,
  and each space it is itself offering, for the first time, under a lower
  attach number. Of two offers of one space that cross, the one with the
  lower attach number is therefore answered, and the other refused with
  `no_common_state`. An initiator refused for a space another attach now
  carries does not offer it again, and detaches the refused attach with
  `done`.
- Each attach is detached on its own. When the last one is, the connection
  closes with `done`.
- A member admitted from now on, and a guest, hold the states from their
  break on, and complete the handshake with any member that holds one of
  them. Two members that share no state cannot complete it. They reach each
  other through a third member or an always-on peer, or the one behind
  syncs first. A member far behind SHOULD dial rather than wait, since a
  responder tests 256 states per space and an initiator offers 64.
- A restricted space attaches on its own, after its parent
  ([ext-restricted-spaces.md](ext-restricted-spaces.md)).

### 3.7 Order on a connection, and the re-check

On each attach, and on each space a device-to-peer connection holds a
right for:

1. After the roster check, or after `Granted`, and before any unit, object
   or ephemeral frame, each side sends every space event the head exchange
   of [units.md](units.md) shows the other lacks. Only then do units and
   other kinds follow.
2. In live delivery, a sender sends a new space event ahead of any queued
   unit or object of that space.
3. A receiver resolves the roster and the key graph as each space event is
   accepted, before it judges the units that follow.

A removal, and the rotation after it, therefore reach a device before the
content its sender sealed under the new key.

**The re-check.** Whenever a device's view of a space changes (a roster
event, a list event of a person the roster names, an event of a granted
space's log, or fork evidence), it runs section 3.5 again for every device
attached for that space:

- a device that is now out is detached at once, with `membership_ended` or
  `forked`, before anything more is sent to it;
- a device whose path now needs a log the verifier does not hold enters
  probation;
- a device that learns that it was removed itself detaches every attach of
  that space, with `membership_ended`.

A device that loses its path into a granted space loses it in every space
that grants that space too, at each space's own re-check.

### 3.8 Priority and the lossy channel

A sender sends, in this order, whatever is ready:

1. ephemeral frames (T4);
2. control messages;
3. space events, on sync streams;
4. other events, on sync streams;
5. object chunks.

Ephemeral frames MUST NOT wait for a sync or object frame that is not yet
being written. They are never acknowledged and never retried. On a member
connection an `Ephemeral` message travels as a QUIC datagram when it fits
the path's datagram size, otherwise on the ephemeral stream: one
unidirectional stream per direction, opened with `Open {1: 3}` on first
use. A receiver takes both. On a device-to-peer connection a device sends
`Ephemeral` only for a space it holds the live right for, and only a peer
that relays sends `Gone` and adds an `origin`.

### 3.9 Sync, head statements, list events and adapter sync

[units.md](units.md)'s baseline sync messages each travel as the byte
string at key 2 of one `Sync` message:

- **On a member connection,** on the attach's sync stream, which the
  attach's initiator opens with `Open {1: 1, 2: attach}` once the answer
  has verified. Until a side has sent `Admit` for the attach, it sends on
  that stream only what probation allows. Object chunks travel after
  `Admit`, on object streams, one per transfer, opened by the sender with
  `Open {1: 2, 2: attach}`.
- **On a device-to-peer connection,** on one sync stream per space, opened
  by the device with `Open {1: 1, 2: space}` after `Granted`, and object
  streams likewise. On the server binding they travel on the WebSocket, and
  object chunks over HTTP (section 3.15).
- The space a units.md message names at its key 1 MUST be the scope's
  space (`Malformed`). `Statement`, `SnapshotWant`, `SnapshotOffer` and
  `ListEvents` travel on member connections only.

**Head statements.** A device sends [units.md](units.md)'s `Statement`, in
a `Sync` on each attach's sync stream, when the attach is admitted and
whenever its heads change, at most once per `gossip_interval` per attach.
Through always-on peers, statements travel only on the ephemeral channel
([ext-ephemeral.md](ext-ephemeral.md)).

**List events from a reader.** A device of a person granted only `read`, or
a device a recovery agent added ([ext-recovery-agent.md](ext-recovery-agent.md)),
hands its person's device-list events to a writer device of the space, as
[units.md](units.md), "Frasil's own units", specifies, by one of two
routes:

- on a member connection, after both sides have sent `Admit`, as
  units.md's `ListEvents` sync message (type 17) in a `Sync` message on the
  attach's sync stream;
- otherwise as a device-mailbox item named `frasil/list-events`, sealed to
  each writer device it sends to, whose body is units.md's.

[ext-ephemeral.md](ext-ephemeral.md) adds a third route.

**Adapter sync.** `AdapterSync` carries an adapter's own sync between two
members, on the attach's sync stream, after both sides have sent `Admit`.
Its bytes go to the adapter named, with the attach's space and the other
device's device ID. Nothing received this way is accepted as a unit:
what an adapter applies comes from units that pass the write rule
([roster.md](roster.md)). A receiver without that adapter drops the
message.

### 3.10 The device-to-peer handshake

A device-to-peer connection is the iroh binding's ALPN `frasil/p1/peer`,
or the server binding's WebSocket.

```text
PeerHello = {0: 16, 1: 1, 2: nonce_P (32), 3: services, 4: limits, 5: revision}
Hello     = {0: 17, 1: 1, 2: nonce_C (32), 3: purpose, 4: revision}
binding   = SHA-256("frasil/peer-binding/v1" || field(channel) || nonce_P || nonce_C
                    || u8(purpose))
```

- The peer sends `PeerHello` first; on the iroh binding it opens the control
  stream to send it (section 3.16). Key 1 is the protocol, 1. `services` is
  an array of: 1, relay (live delivery); 2, store; 3, mailbox; 4, account;
  5, library ([ext-libraries.md](ext-libraries.md)); 6, deposit
  ([ext-deposit-tokens.md](ext-deposit-tokens.md)). A peer that does not
  implement an extension never lists its service.
  `limits` is a map: 1, the largest frame; 2, `max_streams_per_space`
  ([units.md](units.md)); 3, the largest mailbox item; 4, the largest
  object chunk.
- The device answers with `Hello`, a fresh nonce and its **purpose**: 1,
  space traffic; 2, administration.
- `binding` is fresh per connection, and fixed to the channel and the
  purpose.

```text
at the peer, in order:
  1. Send PeerHello.
  2. Hello: read_frame; exactly keys 0 to 4.                    else Malformed
  3. Key 1 is 1.                                                else UnsupportedVersion
  4. The revision is the peer's.                                else close RevisionMismatch
  5. A 32-byte nonce; purpose 1 or 2.                           else Malformed
  6. Each Present, Merge, RegisterRecoveryEntry, mailbox message
     or reserved request: the purpose allows it (the table
     below).                                                    else close PurposeViolation
  7. Each Present: exactly keys 0 to 5 (else Malformed), then
     peers.md's checks of the credential and its proof
     (peers.md, "Presenting a credential").                     else Refused, with that step's code
  8. Every later message: its space holds the right it needs,
     within catch-up's limits where catch-up is all it holds.   else Refused CredentialRefused
```

A `Refused` names the request it answers. A `Present` that fails step 7
and whose key 1 is not an unsigned integer has none to name, so the peer
MUST close the connection with `malformed`.

An event carries no request number. The peer MUST answer each event of an
`Events` sync message that it neither acknowledges nor holds pending
([peers.md](peers.md), "Storing an event") with `EventRefused` on the
control stream, naming the event's ID and the reason code; step 8 refuses
an event this way. An event whose ID does not read has none to name, and
the peer sends nothing for it. A device counts a refused event not durable
at that peer, and acts on the code as peers.md's refusal codes say.

The device checks `PeerHello`'s keys, protocol (`UnsupportedVersion`) and
revision (close `revision_mismatch`), and nothing else: a peer is trusted
for availability only.

**Reconnecting elsewhere.** A peer MAY close a device-to-peer connection
with `reconnect`, as a QUIC application close code 17 or a WebSocket close
code 4017, such as to move load between the machines it runs on, or before
one of them stops. It is not an error, and only a peer sends it.

- A peer MUST NOT close with `reconnect` a connection on which an import
  is in progress or a create is pending ([peers.md](peers.md), "Hosting a
  space"). A peer that must stop waits for them to end, for at most
  `reconnect_drain`, and then closes such a connection as a lost one,
  with no close code.
- The device connects again to the same peer: on the server binding
  through the same origin; on the iroh binding by any endpoint key it holds
  for that peer, one its discovery lists (section 3.15) or the key of the
  ticket it dialed.
- It waits a random time, uniform from 0 to `reconnect_wait`, before its
  first attempt, and doubles the bound after each attempt that fails, to at
  most `reconnect_wait_cap`. A connection that the peer closes with
  `reconnect` before it sends any `Granted` or acknowledgement counts as an
  attempt that failed, so a peer that keeps closing at once is retried ever
  more slowly.
- On the new connection the device presents its credentials again, since a
  proof holds only for its connection, and sends again each event the peer
  has not acknowledged ([units.md](units.md)).
- A device that receives `reconnect` on a member connection treats it as
  `done`.

| Purpose | Carries | Never carries |
|---|---|---|
| 1, space traffic | read credentials, upload keys and fetch keys for any number of spaces, `Merge`, `RegisterRecoveryEntry`, mailbox messages, and types 21, 31 and 40 to 43 | an administrator pseudonym, or a skeleton event signed by the device's own pseudonym |
| 2, administration | exactly one `Present`: one administrator pseudonym for one space; then only that pseudonym's skeleton events and acknowledgements, and the peer's `Awaiting`, `EventRefused` and `ErasureLate` | a bearer token, a cookie or any other credential; `Merge`; `RegisterRecoveryEntry`; mailbox messages; types 21, 31 and 40 to 43 |

A device MUST open each administration connection fresh: a new transport
session, no TLS session resumption, no cookie, and on the iroh binding a
fresh endpoint key. It closes it when done.

### 3.11 Presenting credentials

```text
presented = field(binding) || field(space) || u8(credential) || field(public)
Present   = {0: 18, 1: request, 2: space (32), 3: credential, 4: public (bytes),
             5: proof (bytes)}
Granted   = {0: 19, 1: request, 2: rights (array), 3: transfer token (32; server
             binding only)}
```

- `credential` is 1, the read credential; 2, the upload key; 3, an
  administrator pseudonym; 4, a **fetch key**, registered for the space as
  a recovery entry ([identity.md](identity.md), "Fetch keys and recovery
  entries"). `public` is its public half. `request` numbers
  the device's requests on the connection, from 1.
- The proof is [peers.md](peers.md)'s, over `presented`. Through `binding`
  it is worthless on another connection, at another peer, for another
  purpose, and after this connection closes.
- A device MAY present credentials of several spaces on one connection;
  the peer then links those spaces. A device that wants them apart opens
  one connection per space.

| Right | Code | Given by | Allows |
|---|---|---|---|
| fetch | 1 | a read credential of a live entry | fetching the space's events and objects |
| live | 2 | the same | live delivery of the space's new events (units.md's `Subscribe`), and relaying its ephemeral frames where [ext-ephemeral.md](ext-ephemeral.md) is implemented |
| store | 3 | an upload key of a live entry | storing events and object chunks |
| release | 4 | the same | release and restore |
| erase | 5 | an administrator pseudonym, on an administration connection | storing that pseudonym's skeleton events and acknowledgements |
| catch-up | 6 | a read credential of a retired entry, or a fetch key of a recovery entry | fetching only what [peers.md](peers.md)'s catch-up allows |

A device that missed rotations holds only an older state's read
credential. It is granted catch-up, fetches the event that wraps the new
key for it, and then presents the new state's credential. A device that
holds no state of the space, recovering with only a passkey or a recovery
sheet, presents a fetch key instead, and continues the same way. A fetch
key grants nothing but catch-up.

A rotation has no entry at a peer until the peer stores it
([peers.md](peers.md), "Learning a rotation's credentials"), and storing it
needs the store right. A device whose newer rotations a peer has not
stored presents the newest state whose entry the peer holds, stores the
newer rotations under the right that grants, and then presents the newest
state's credentials.

A refusal of a read credential is not final: another member's connection
may store the entry a moment later, as when a newcomer that holds only the
state of its own admission connects before its administrator's device has
stored that rotation. While a connection holds no grant at the device's
current state of a space and awaits no answer to a present of it, the device
presents that state's credentials again `present_retry` after the refusal,
then after each further refusal, the wait doubling each time to at most 30
seconds. An event the peer acknowledges on the connection ends the wait: the
peer may then hold entries it lacked.

`Merge` travels on a connection that proved a live upload entry of its
space. `RegisterRecoveryEntry` asks the peer to add a fetch key to the
space's recovery entries; it travels on a space-traffic connection that
holds the store right for its space (`CredentialRefused` otherwise), and
the peer applies [peers.md](peers.md)'s rules for registering one. The peer sends `Awaiting` on an administration connection once the
pseudonym is granted, and again whenever the list changes; it lists the
requests and snapshots not yet stable at the peer that the connection's
administrator slot has not acknowledged ([peers.md](peers.md)). Each
request is answered by `Accepted` or by `Refused`.

### 3.12 What a peer learns of a device, and acknowledgements

- No message of sections 3.10 and 3.11 carries a device's Ed25519 key,
  `kc` or device ID. A device MUST NOT send any of them, a person ID or an
  account token on a
  space-traffic connection, except that where the operator requires an
  account, its bearer token rides on space-traffic connections, and the
  device presents, on that connection, only the spaces it is willing to
  link to the account. A bearer token never rides on an administration
  connection.
- Collecting a device mailbox shows the peer that device's Ed25519 key,
  `kc` and device ID. A device MUST collect on a connection of its own
  that presents nothing else: no credential, bearer token, deposit or
  other request that names a space or a recipient. It opens that
  connection as an administration connection is opened (section 3.10),
  and MAY keep it and collect on it again at that peer, since every
  collection there names the same device; it opens a fresh one when the
  connection ends. The peer still sees that connection's address and
  timing beside those of the device's space-traffic connections, which
  this document does not hide (section 4).
- A deposit in a device mailbox names its recipient, by the address its
  device ID gives (section 2.7). A device MUST deposit in a device mailbox
  at a peer on a connection of its own that presents nothing else, or by
  the server binding's `POST` route with no credential, never on a
  connection that presents a credential, a bearer token or a collection:
  there the peer would learn that the holder of those spaces, or that
  device, writes to the recipient. A hand-over over a member connection
  (section 3.14, "Over a member connection") reaches no peer.
- **Acknowledgements name what was stored.** A peer acknowledges an event
  by its event ID, and an object by its locator with the count of leading
  chunks it holds, never by a position alone. A device takes an
  acknowledgement only if it names exactly what the device sent. A peer
  that holds an event at the same log, author and `seq` with another ID
  never acknowledges the new one: it answers `EventRefused` with `conflict`,
  and keeps and serves both as fork evidence. An identical retry is
  acknowledged again. Delivery is never an acknowledgement of storage.
- **Whose acknowledgement.** A device keeps acknowledgements per peer,
  under the peer's origin. On the server binding it is the origin the
  connection's `channel` binds (section 3.15), which only the origin's
  holder can answer to. On the iroh binding it is the origin whose
  discovery the device dialed the endpoint key by (section 3.15),
  whichever of the peer's machines that key names. A peer reached by both
  bindings is kept once, under its origin. A peer the device dialed on the
  iroh binding by a key it took from no discovery, such as a peer ticket's,
  is kept under that endpoint key alone. [at-rest.md](at-rest.md) keeps
  these as the peer's ID.

### 3.13 Error classes

Beyond overview's shared classes, this document uses the classes that
section 2.5's codes 4, 5, 7 to 13, 15 and 16 name, in UpperCamelCase
(`NoCommonState`, `BadProof`, and so on), and these. Each is a decision
about one frame, attach, connection or request, and says nothing about any
event's validity; `Forked` here detaches a device that forked in the space.

| Class | Meaning | Code |
|---|---|---|
| `UnknownMessage` | a message type this receiver does not know | `malformed` |
| `WrongMailbox` | a collecting `ed \|\| kc` whose device ID does not hash to the address | `credential_refused` |
| `Unauthenticated` | no valid bearer token where one is needed | `unauthenticated` |
| `UnknownContent` | a mailbox item whose content name the device does not implement; dropped | |
| `NotForMe` | a member announcement that no state the listener holds opens; dropped | |

### 3.14 Mailboxes

**Depositing.** Anyone MAY deposit in an exchange, person or device
mailbox, subject to the peer's rate limits. An item is at most 262,144
bytes (`TooLarge`). A peer applies [admission.md](admission.md)'s checks to
an exchange mailbox and refuses an item whose request ID does not hash to
the address. It keeps an exchange mailbox at most `exchange_mailbox_lifetime`,
by its own timeline, and a person's or a device's at most
`mailbox_retention`.

**Claimed device mailboxes.** A device mailbox is **claimed** at a peer
from its device's first collection there that passes the checks below,
an empty mailbox's included, until `mailbox_retention` passes on the
peer's timeline with no further collection. A peer keeps an item it
received while its mailbox was not claimed at most `uncollected_retention`
from its deposit, unless the mailbox is claimed by then; once claimed,
every item it holds is kept for `mailbox_retention` from its deposit. A
peer MAY limit per source the collections that claim a mailbox.

**The peer's caps.** Besides each mailbox's own cap (section 2.7), a peer
MAY cap what all its device mailboxes hold together, in items and in
bytes; [ext-deposit-tokens.md](ext-deposit-tokens.md) keeps a second
budget beside this one. A deposit that would pass the cap first evicts
items, oldest first, from mailboxes that are not claimed, unless its own
mailbox is not claimed; if room is still lacking, the peer refuses it
`busy`, and evicts nothing for it. It never evicts an item of a claimed
mailbox to make room for another mailbox's deposit. A peer limits
anonymous deposits per source ([peers.md](peers.md), "Quotas and rates"),
and refuses more `rate_limited`.

**A sender keeps what was refused.** A device whose deposit in a device
mailbox a peer answers `busy` or `rate_limited`, or does not answer, or
cannot be reached for, keeps the item and deposits it again later: after
a random wait of up to a minute, doubled after each further refusal to at
most an hour, at that peer or another that serves the recipient, until a
peer accepts it or `mailbox_retention` has passed since the first
attempt, on the upper estimate of its timeline. A device does not know a
peer's `mailbox_retention`, so it takes its most, 30 days. It keeps the
item at rest from before the first attempt until a peer accepts it
([at-rest.md](at-rest.md), the `deposit` table), so that a restart loses
none. An item deposited twice is opened twice, and every receiving
procedure takes the second as nothing new. `too_large` and `malformed`
are final. Exchange mailboxes and invite drops are deposited within their
procedures, which wait for each answer; this rule is for device mailboxes.

**Collecting a device mailbox.** The device signs, with its Ed25519
identity key,

```text
"frasil/mailbox-collect/v1" || binding || address
```

and sends its `ed || kc` and the signature in `MailboxGet`, on a
device-to-peer connection. The peer checks, in order:

```text
  1. Keys 2, 4 and 5 are 32, 64 and 64 bytes.                    else Malformed
  2. ed is valid (crypto.md).                                    else InvalidKey
  3. address = SHA-256("frasil/mailbox/v1" || u8(3)
     || field(the device ID of ed and kc)).                      else WrongMailbox
  4. The signature verifies strictly under ed.                   else BadSignature
```

The address hashes the device ID, which hashes `kc`, so the signature over
the address binds `kc` too: a key holder that shares the device's Ed25519
key under another `kc` has another mailbox.

**Opening an item.** A device opens an item from its own mailbox in order:

```text
  1. crypto.md's open_wrap(item, X-Wing seed, info), where info names the
     device's own device ID, and the length allowed is 1,139 to
     262,144 bytes.                                              else its class
  2. The plaintext is a deterministic CBOR map of exactly keys 1
     and 2: a text of 1 to 64 bytes, and a byte string.          else Malformed
  3. The content name is one the device implements.              else UnknownContent
  4. The body passes the checks of the content name's document.  else their class
```

**Over a member connection.** A device MAY hand an item meant for the
device mailbox of the device at the other end of a member connection over
that connection instead, once the other's `Identify` has verified: a
`MailboxPut` on the control stream, with kind 3 and that device's mailbox
address. The receiver opens it as an item of its own mailbox and answers
nothing. It drops a put of another kind or address, and one that does not
open. So a welcome reaches a device that no peer serves.

A device mailbox also carries [admission.md](admission.md)'s welcomes and
Joins. Welcomes, Joins and device-mailbox items share one wrap layout and
are told apart only by their `info`, so a device tries the item seal, then
the welcome, then a Join under each reference it issued. It drops an item
none opens.

Mailboxes carry no space content. A device that was offline fetches a
space's events from any peer with its read credential, and keys travel
inside space events ([keys.md](keys.md)).

### 3.15 The server binding

The server binding is how a device, a browser included, reaches an
always-on peer that serves HTTPS. It carries device-to-peer connections
only. Every path but discovery begins `/frasil/p1/`.

**Discovery.** `GET /.well-known/frasil` returns 200 with JSON:

```json
{
  "frasil": 1,
  "revision": 1,
  "services": ["relay", "store", "mailbox", "account", "library"],
  "limits": {"max_frame_bytes": 1056768, "max_streams_per_space": 65536,
             "max_mailbox_item_bytes": 262144, "max_chunk_bytes": 1048576},
  "iroh": {"endpoint": "<64 hex>", "endpoints": ["<64 hex>", "<64 hex>"]},
  "relays": ["https://relay.example.org"],
  "account_url": "https://example.org/account"
}
```

`iroh` is present when the peer also serves the iroh binding. `endpoint` is
a stable endpoint key of the peer. A peer that runs on several machines
gives each its own endpoint key and lists every one in `endpoints`: 1 to
256 distinct keys, `endpoint` among them; a peer on one machine MAY omit
`endpoints`. A client treats every key `endpoint` and `endpoints` list as
the same peer, this origin's, and MAY dial any of them. `relays` is present
when the operator names iroh relays, whether or not the peer serves the
iroh binding: 1 to 4 `https` URLs with no credentials, query or fragment.
A peer that serves the iroh binding registers its endpoints with them. A device whose application names
no relay MAY take a peer's `relays` as the home relays of its member
endpoint (section 3.16): from the first peer it connects to whose discovery
names any, for as long as it runs. `account_url` is present when the
operator has an interface where a person sees usage and quotas. A client
treats discovery as a hint and trusts nothing in it but the endpoint keys
of `iroh`, which it trusts as the origin's own: discovery comes over HTTPS
from the peer's origin, whose WebPKI certificate covers it (section 4, "A
peer's endpoint keys").

**The connection.** `GET /frasil/p1/connect`, upgraded to a WebSocket with
subprotocol `frasil.p1`. A client closes a connection whose peer does not
echo the subprotocol.

```text
channel = SHA-256("frasil/server-channel/v1" || field(origin))
```

`origin` is the ASCII serialisation (RFC 6454) of the origin the client
connected to, such as `https://peer.example.org`. A browser cannot read
its connections' TLS exporter, so this binding fixes the channel to the
origin, as section 2.1 allows for T2: it relies on WebPKI, under which
only the origin's holder terminates the session, and the nonces of section
3.10 make each `binding` unique. The channel itself is not unique to a
session.

- Each binary WebSocket message is one message, with no prefix. A text
  message closes the connection with 1003. A close uses 4000 plus section
  2.5's code.
- The WebSocket carries what the iroh binding carries on its control, sync
  and ephemeral streams. Every message's scope names its space.
- **Priority.** The sender keeps ephemeral frames in a queue of their own,
  ahead of everything, and writes a sync frame only while its transport
  buffer (a browser's `bufferedAmount`) holds less than 64 KiB. An
  ephemeral frame may still wait behind one sync frame already written.
  [ext-ephemeral.md](ext-ephemeral.md) says when a client opens a second
  connection for ephemeral traffic alone.

**Objects over HTTP.** `Granted`, on this binding, carries a **transfer
token**: 32 random bytes the peer draws for that grant. A request carries
it as `Authorization: Frasil-Transfer <64 lowercase hex>`. It is valid
while the WebSocket that received it stays open and the grant's rights
stand ([peers.md](peers.md), 3.6, "Connections"), for that space and those
rights. Neither end logs it, and the client never stores it.

| Method and path | Right | Answers |
|---|---|---|
| `GET /frasil/p1/spaces/{space}/objects/{locator}/chunks/{index}` | fetch | 200 with the chunk; 404 if the peer lacks it |
| `PUT /frasil/p1/spaces/{space}/objects/{locator}/chunks/{index}` | store | 201 when stored durably, with `{"held": n}`, the count of leading chunks held for that locator; 200 for an identical chunk already held; 409 `conflict` for other bytes at a chunk index held; 422 `object_mismatch` when the last chunk completes an object whose SHA-256 is not the locator's digest, whose chunks the peer then discards; 507 `quota_exceeded` |

`space` is 64 lowercase hex digits; `locator` is 128, the object's 64-byte
locator ([units.md](units.md)); `index` is decimal. A peer stores and
serves by locator, never by object ID alone.

On these routes, chunk `index` is a slice of the stored object
([units.md](units.md), "Objects"): its bytes from `index · 1,048,576`,
1,048,576 of them, or the rest for the last slice, so chunk 0 begins with
the header's length and the header. A body is at most 1,048,576 bytes,
`held` counts leading slices, and a transfer resumes from it. A slice is
not one of units.md's sealed chunks, which `ObjectWant`, `ObjectChunks`
and `ObjectHave` count on a stream. A reader learns the stored length from
slice 0: `4 + len(header) + size + 40 · n`, with `size` from the header and
`n = max(1, ceil(size / 1,048,536))` ([units.md](units.md), "Objects").
On a stream, `ObjectChunks` carries a sealed chunk's index `i` at key 4
and `chunk_i` at key 5; the first `ObjectChunks` of each answer to an
`ObjectWant` carries the header as well, without its length, at key 3,
whichever chunk index the answer starts at ([units.md](units.md), section
3.14). On these routes the header is in slice 0 alone, so a reader that
holds no header fetches slice 0 first. A reader that fetches slices checks
each sealed chunk once it holds the slices that carry it.

**Mailbox routes.** `{kind}` is 1, 2 or 3, or 4 with
[ext-invite-links.md](ext-invite-links.md); a peer without that extension
answers 404 `not_found`. `{address}` is 64 lowercase hex digits. Items are `application/octet-stream`.

| Method and path | Who | Answers |
|---|---|---|
| `POST /frasil/p1/mailbox/{kind}/{address}` | anyone, rate-limited; the body is one item | 201 with `{"id": "<32 hex>"}`; 413; 429; 503 `busy` past the peer's caps; for kind 1, admission.md's refusals |
| `GET /frasil/p1/mailbox/{kind}/{address}?after={id}` | kind 1: anyone; kind 2: the account's bearer | 200 with `{"items": [{"id": ..., "item": "<hex>"}]}`, oldest first, at most 64; 401 or 403 for kind 2 without the right bearer; 403 for kind 3 |
| `DELETE /frasil/p1/mailbox/2/{address}/{id}` | the account's bearer | 204 |

A device mailbox is collected only over the WebSocket, with `MailboxGet`,
because collecting signs the connection's binding.

**Cross-origin requests.** A browser application may be served from
another origin than the peer. The peer answers every request on this
binding, discovery included, with `Access-Control-Allow-Origin: *`, and an
`OPTIONS` preflight of any of its paths with 204 and:

```text
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, PUT, POST, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Max-Age: 86400
```

It never sends `Access-Control-Allow-Credentials`: every right on this
binding travels in `Authorization` or in the WebSocket, never in a cookie,
so a page of any origin holds only the tokens it was given.

**Account routes.** At an account's server (service `account`), with
`Authorization: Bearer <token>` from the operator's sign-in. Bodies are
`application/cbor`. Each route checks every public key it takes before it
stores it (422 `invalid_key`).

| Method and path | Body or query | Answers |
|---|---|---|
| `PUT /frasil/p1/account/link` | an account link ([identity.md](identity.md)) whose subject is the bearer's | 204; 400; 403 for another subject; 422 `invalid_key` or `bad_signature` |
| `POST /frasil/p1/account/unlink` | an unlink ([identity.md](identity.md)) | 204; 400; 422 |
| `GET /frasil/p1/account/lookup?subject={subject}` | | 200 with a CBOR array of the links stored for that subject, at most 16 |
| `GET`, `PUT /frasil/p1/account/directory` | the person's sealed directory of spaces, opaque, at most 1 MiB | 200; 204 |
| `GET`, `PUT /frasil/p1/account/passkeys` | credential hints: an array of `[passkey member's device ID (32), credential ID (1 to 1,023 bytes)]`, unsigned | 200; 204 |

No route adds or revokes a list member, delivers a wrap, or decides a
check. A client passes credential hints to a passkey ceremony and checks
what the passkey derives against the person's list
([identity.md](identity.md)).

**A client's HTTP transport** MUST: use HTTPS, except to `localhost`,
`127.0.0.1` or `[::1]` during development; send each request to exactly the
URL it names and follow no redirect, returning a 3xx as it is, which the
client refuses; return every response, and fail only when none arrived;
never retry on its own; and add the bearer token where an account route
needs it, so that the Frasil client never sees it, and never on an
administration connection.

**Browsers** use the server binding for every always-on peer. A browser
MAY reach members through iroh's WebAssembly build, which connects through
a relay and runs QUIC and TLS end to end, so it has an exporter and runs
the member handshake. A browser never listens, announces, or takes part in
nearby pairing. It runs an admission exchange, as joiner or approver,
through an exchange mailbox on this binding's mailbox routes
([admission.md](admission.md), "Exchange mailboxes").

### 3.16 The iroh binding

**QUIC and TLS.** QUIC version 1 (RFC 9000) with TLS 1.3 (RFC 8446), both
ends authenticating with Ed25519 raw public keys (RFC 7250). A dialer names
the endpoint key it dials, and the connection fails unless the listener
proves it. The listener learns the dialer's endpoint key. Each end checks
the other's endpoint key with [crypto.md](crypto.md) before it stores it.

| ALPN | Connection |
|---|---|
| `frasil/p1/member` | member |
| `frasil/p1/peer` | device to always-on peer |
| `frasil/p1/nearby` | nearby |

```text
channel = TLS-Exporter("EXPORTER-Channel-Binding", context = "", 32)
```

This is RFC 9266's `tls-exporter` channel binding, over the QUIC
connection's TLS session.

| Stream | Opened by | Priority |
|---|---|---|
| control: the first bidirectional stream | the dialer; on `frasil/p1/peer`, the peer, the listener | 2 |
| sync: one bidirectional stream per attach, or per space on a device-to-peer connection | the attach's initiator, or the device | 1 |
| object: one unidirectional stream per transfer | the sender | 0 |
| ephemeral: one unidirectional stream per direction, and QUIC datagrams (RFC 9221) | each sender, on first use | 3 |

A higher priority is sent first. An end without datagram support uses the
ephemeral stream alone. Every stream after the control stream starts with
`Open`; each datagram carries one `Ephemeral` message.

The end that opens the control stream MUST write on it first, since QUIC
shows the other end a stream only once its opener writes. On
`frasil/p1/peer` the peer opens it and sends `PeerHello` on it (section
3.10), and the device accepts it.

A receiver MUST accept a second ephemeral stream from the same direction,
and reads its frames as it reads the first's. Each frame is checked alone, and
[ext-ephemeral.md](ext-ephemeral.md)'s replay rule, kept per sender, refuses
a frame sent again on either stream.

**Endpoint keys.**

| Endpoint | Key |
|---|---|
| a device's member endpoint | random; rotated at least every `endpoint_rotation` and whenever the device joins another network; never its identity key |
| a device's side of a device-to-peer connection | fresh per connection |
| a nearby endpoint | fresh per pairing session |
| an always-on peer | stable, one per machine it runs on, published in its discovery document (section 3.15) or tickets |

Members learn a member's current endpoint from its local-network
announcements, from a member ticket, or from another member of the space
("Member addresses", below).
[ext-ephemeral.md](ext-ephemeral.md) adds a way through always-on peers. A
device's member endpoint registers with home relays, as iroh does: those
its application names, or else a peer's (section 3.15). A device with
neither has no relay, and reaches members only by a direct path. A
device MUST NOT publish an endpoint key under a public name, such as iroh's
DNS or pkarr discovery.

An endpoint a device binds for one pairing or setup session MUST bind on
the networks its member endpoint binds on and register with the same
relays, so that it reaches a host that only a relay reaches.

**Member announcements.** A device that has a space open, with local
discovery switched on, sends section 2.9's member announcement for it
under its current state of that space. Every 2 seconds, with up to 0.5
seconds of random jitter, it announces at most 4 spaces, one packet each,
and takes its spaces in turn: a device with N spaces to announce announces
each of them once every ceil(N / 4) intervals. It never announces a
restricted space ([ext-restricted-spaces.md](ext-restricted-spaces.md)),
nor a space it is out of in its own view. A member connection an announcement
starts attaches every space its two devices share (section 3.6), so a
space waits for its turn only when no other space the two share has been
announced. A listener:

```text
for each packet, in order:
  1. 137 bytes, and byte 0 is 0x01.                              else Malformed
  2. For each space it has open, the lan_key of its current state
     and of up to 3 states before it opens the packet.           else NotForMe
  3. The length prefix is at least 1 and fits; every padding byte
     is zero; core has exactly keys 1 and 2, a 32-byte key and a
     port from 1 to 65,535.                                      else Malformed
```

A packet that opens gives a candidate: the source address, the port and
the endpoint key. A listener keeps at most 128 candidates, each for 10
seconds, and dials a candidate with the member ALPN. The member handshake
decides everything; an announcement only says where to dial. A listener
already connected to a candidate's endpoint key attaches the announced space
on that connection instead (section 3.6).

**Reconnecting.** Once a side has admitted the other for an attach, it MAY
keep a member ticket of the other side in the attach's space, in
[at-rest.md](at-rest.md)'s `endpoint` table: the other side's endpoint key,
and the addresses and relays the connection reaches it at. A device that
opens again dials each ticket it keeps of a member still in the space, with
the member ALPN, attaching each space that keeps that ticket, and MAY dial
again for a while one that does not answer. A ticket whose endpoint key has
rotated no longer dials; the next connection with that member replaces it.
[ext-next-endpoints.md](ext-next-endpoints.md) adds the key a member
announced as its next.
A device deletes the ticket of a member whose membership ended in its view.

**Member addresses.** The members of a space tell each other where its
other members are, so that a device that neither sends nor receives
local-network packets, or whose network blocks them, still reaches every
member that the members it reaches know of.

```text
Addresses = {0: 8, 1: attach, 2: [[device ID (32), ticket], ...]}
```

- `ticket` is the CBOR of a member ticket (section 2.8), as a byte string.
- **Sending.** Once a side has both sent and received `Admit` for an
  attach, it sends the other an `Addresses` for it on the control stream.
  The list names members of the attach's space other than the two ends:
  first each member the sender holds an admitted attach of the space
  with, at the ticket that connection reaches it at, its endpoint key and
  the addresses and relays the connection uses; then each member whose
  ticket the sender keeps in the space's `endpoint` table, at that
  ticket. It names only devices that reach the space in the sender's
  current view (section 3.5), each once, at most 64, and stops before the
  message would pass its cap. A side sends again whenever the list it
  would send changes, at most once per `gossip_interval` per attach, and
  never sends an empty list.
- **Sending to a guest.** When the other side reaches the space as a
  guest in the sender's current view, through a device grant that carries
  `session` ([roster.md](roster.md)), each ticket the sender lists keeps
  only its local-network addresses and no relay URLs, and an entry left
  with no address is left out, before the entries and the cap are
  counted. Every other member receives each ticket whole.
- A **local-network address** is an IPv4 address in `10.0.0.0/8`,
  `172.16.0.0/12` or `192.168.0.0/16` (private), `169.254.0.0/16`
  (link-local) or `127.0.0.0/8` (loopback), or an IPv6 address in
  `fc00::/7` (unique local), `fe80::/10` (link-local) or `::1/128`
  (loopback). Any other address, an IPv4-mapped IPv6 address included,
  is not one.

```text
on Addresses, at the receiver, in order:
  1. read_frame; exactly keys 0 to 2; an unsigned attach; key 2 an
     array of at most 64 entries, each an array of a 32-byte
     device ID and a byte string; no device ID twice.           else Malformed
  2. Each byte string reads as a ticket by section 2.8's checks
     that follow the base64url decoding, and is of kind member.  else Malformed,
                                                                      or InvalidKey
  3. Both sides have sent Admit for the attach.                  else drop it
  then, for each entry, in order:
  4. The device ID is neither the receiver's nor the
     sender's, and reaches the space in the receiver's current
     view (section 3.5).                                         else skip it
  5. The ticket's endpoint key is not the receiver's own member
     endpoint key.                                               else skip it
  6. The receiver holds no admitted attach of the space with
     that member.                                                else skip it
  7. It holds the ticket among its learned tickets and dials it.
```

- **Dialing.** The receiver dials with the member ALPN, attaching the
  space, or attaches the space on a connection it already holds with that
  endpoint key (section 3.6). As with local-network candidates, it holds
  at most 128 learned tickets, each for 10 seconds, and dials an endpoint
  key for a space once while it holds it. When two members learn
  of each other at once, the one whose endpoint key is greater, compared
  as bytes, SHOULD wait 1 second and dial only if no connection between
  them has formed by then. The member handshake decides everything; a
  ticket only says where to dial.
- **Keeping.** A receiver MUST NOT write a learned ticket to the
  `endpoint` table. A learned ticket is held only among the learned
  tickets, and is kept only by "Reconnecting": once a dial to it yields an
  attach that both sides admit, the device keeps the ticket at which that
  connection reaches the member. A kept ticket is so replaced only when the
  device reaches that member at another one, and a member whose endpoint
  changed is found at its new ticket by step 7's dial.
- A step-3 drop is not a refusal: an `Addresses` can cross a `Detach`.

**Nearby pairing** lets a device that holds no key of the space, a
newcomer, find a host and run [admission.md](admission.md)'s exchange.

- While the person has switched pairing on, for at most 5 minutes each
  time, the host sends section 2.9's nearby announcement on a fresh
  endpoint key, on the same groups and port. A listener keeps at most 64
  announcements, 4 per source address, each for 10 seconds.
- A newcomer that holds the host's nearby ticket from elsewhere, such as
  a text sent by message or a QR code shown on a call, dials it with no
  announcement. The ticket's relays carry the connection when no direct
  path does, so host and newcomer need not share a network. A host
  accepts a nearby connection while pairing is switched on, however it
  was dialed.
- The newcomer connects with ALPN `frasil/p1/nearby`. The connection has one
  bidirectional stream, opened by the end that writes first: in pairing the
  newcomer, the dialer, which sends the first message; in setup
  ([admission.md](admission.md), section 3.8) the device being set up, the
  listener, which sends the Hello. A device runs one pairing at a time, at
  least 3 seconds apart, each within `pairing_deadline`.
- Each message is a `Pairing` frame carrying one of admission.md's
  messages. The admission code binds this connection's exporter, so a party
  in the middle, which holds two sessions, makes the two codes differ.
- After admission, the host sends the welcome, the exchange's Result, in a
  `Pairing` frame whose key 2 is a member ticket, and the space snapshot
  as units.md's messages in `Sync` frames on object streams it opens with
  `Open {1: 2, 2: space}`. The
  newcomer then dials the ticket with the member ALPN. Nothing on the
  nearby connection admits it to anything by itself.
- When the newcomer is a person's new device (ctx `0x01`), the Result
  carries no welcome. The host then sends, for each space that reaches the
  device, a Welcome message in a `Pairing` frame whose key 2 is the member
  ticket, followed by that space's events on an object stream
  ([admission.md](admission.md), section 3.4).

## 4. Security considerations

- **Offers.** Each tag is a PRF output under a key a non-member lacks,
  bound to this channel, and every offer carries 16, real or random, so an
  offer tells a non-member nothing. Before `Identify`, nothing either side
  sends depends on what a non-member can compute, and the only refusal a
  non-member can cause is `no_common_state`, which a far-behind member also
  receives. Sixteen tags cover a member behind by 15 states in one offer
  and 63 in four.
- **What each binding stops.**

| Bound | Stops |
|---|---|
| `channel`, in every tag, the transcript, `Identify` and `binding` | replaying a message or a proof into another connection, at the same or another peer; a party in the middle passing messages between its two sessions |
| `u8(0x01)` in the tag, and distinct labels for tag and proof | passing an answer's proof off as a tag, or the reverse |
| `attach` in the tag and the answer | moving an offer or an answer to another attach |
| `nonce` and `nonce_R` | two offers of one attach sharing a tag |
| `endpoint_I` and `endpoint_R`, in order | moving messages between pairs of endpoints, or swapping roles |
| `role` in `Identify` | reflecting a side's own `Identify` back to it |
| `hk(P)` | a proof for another state or space |
| the roster check, against the verifier's view | a holder of keys whose membership ended |
| `purpose` in `binding` | moving a proof between space traffic and administration |

- **The key proof is not membership.** It shows that the other side held a
  state of the space, which it was entitled to once or was handed. Only the
  roster check, against the verifier's own view, decides admission. A
  former member that dials with an old state learns, before it is refused,
  that the member still holds that state, and the member's device;
  on a local network it opens the announcements of a device that still
  announces under that state, until the announcer's state moves past it.
  This is overview's accepted leak 7 (section 4.4).
- **Endpoint keys.** Anyone who completes the transport's handshake sees
  an endpoint key. A member endpoint key rotates and is never the device's
  Ed25519 key, so the network and relays can follow a device only until
  the next rotation.
- **Relays.** A relay sees the endpoint keys whose packets it forwards,
  their addresses and the timing, never content: the member handshake runs
  end to end through it. A peer that names relays in its discovery chooses
  who sees this for the devices that take them, so an operator names
  relays whose operator it would let see it.
- **Credentials at a peer.** A credential proof binds the channel, both
  nonces and the purpose, so a peer that keeps one cannot present it
  elsewhere, and learns only a public half it already holds. Administration
  connections carry no account and open fresh, so a peer cannot link an
  administrator pseudonym to an account by anything but address and
  timing, which this document does not hide.
- **A quantum adversary and the transport.** The text makes no
  post-quantum claim for a binding's own handshake and encryption: their
  key exchange is whatever the TLS 1.3 session negotiates, which may be
  classical. An adversary that records a connection now and breaks that
  key exchange later reads what the connection carried inside TLS: on a
  device-to-peer connection what the peer sees anyway (overview.md,
  section 4.1); on a member connection the handshake, so which devices
  attached to which spaces, and the envelopes the members exchanged. It
  reads no content, name or key: those are sealed before they reach the
  transport, under symmetric keys that X-Wing wraps carry. A binding's
  identity (T1) is checked when the session opens, so a later break of
  its signature scheme forges nothing.
- **The server binding without an exporter.** An attacker who is not the
  origin cannot terminate the TLS session under WebPKI. The origin's holder
  is the peer itself, and a proof made for it is useless at any other.
  Member handshakes never run over the server binding.
- **A peer's endpoint keys.** A client trusts discovery's iroh endpoint
  keys as far as WebPKI and no further. Whoever obtains a certificate for
  the origin can list a key of its own there, but it could already
  terminate the server binding as the peer, and a proof made on its
  connection is still worthless at any other. A key no discovery lists
  names only itself, so a ticket cannot make one peer's acknowledgements
  count as another's.
- **Reconnecting elsewhere** costs a device one handshake and its
  presents. The random wait spreads the devices a peer closes at once, so
  a machine that stops does not move all its load in one instant.
- **Local networks.** A member announcement is sealed, of fixed length and
  freshly encrypted, so two packets of one device share only their source
  address. A nearby announcement shows its display name to everyone in
  range, so an application SHOULD let the person choose a name for the
  session.
- **Member addresses.** An `Addresses` travels only on an attach that
  both ends admitted, inside the connection's TLS session, so only a
  device that proved a state of the space and that the roster admits
  learns another member's ticket. A non-member, a device in probation
  and a removed member learn none. A ticket holds no secret and grants
  nothing: the dial proves the endpoint key it names, and the member
  handshake and the roster check decide the rest. A false ticket costs
  the receiver one dial: it is held for 10 seconds and kept only once a
  dial to it is admitted, so it neither replaces a ticket the receiver
  keeps nor outlasts a restart, and the bound of 128 tickets, each for 10
  seconds, limits the dials one member can direct at an address. A member
  learns of the others only what it would see if they dialed it: endpoint
  keys, which rotate, and the addresses and relays they use. A guest
  learns only their local-network addresses, no public address and no
  relay, so once it leaves the local network it holds nothing that
  locates the members it learned of there.
- **Denial of service.** A member listener spends one TLS handshake and at
  most 8,192 HMACs on a dialer before it can refuse, and MAY rate-limit
  offers per address. Every frame's prefix is checked before allocation,
  every handshake has a deadline, and probation is bounded in time and
  events. A device mailbox can be filled by anyone, never grown. A stranger
  who fills the peer's caps delays new anonymous deposits until retention
  frees room; it pushes out nothing of a claimed mailbox, and its items in
  mailboxes nobody collects from go after `uncollected_retention`.
  [ext-deposit-tokens.md](ext-deposit-tokens.md) gives paid mail room a
  stranger cannot fill.

## 5. Test vectors

[transport.json](vectors/transport.json). Channel values come out of a TLS
handshake, so the vectors take them as inputs. An implementation MUST
produce exactly every tag, transcript, proof, signature, binding, packet,
ticket, address and item, and refuse each negative case at its step with
its class.

- `labels`, `parameters`: the labels this document uses, in hex; the limits,
  caps, codes, reason codes with their statuses, and the revision.
- `member_handshake`: one whole handshake between a dialer whose current
  state merges two rotations and a listener that has seen only one of them:
  endpoint keys, both devices' `ed || kc`, every state's member key, the
  offered states and tags, the offer, the listener's candidates, the match, the answer's
  core, transcript and proof, both `Identify` messages with what each signs,
  an `Admit`, a second attach's offer, the other space whose state the
  listener also holds, and a second connection's channel.
- `state_choice`: the offered states, what the responder holds and the match
  or refusal, for equal states, an initiator ahead, an initiator behind, a
  merged state, a member admitted from now on, and no common state.
- `member_refusals`: offers of 15 and 17 tags, with a short nonce, with an
  extra key, without a revision and of another revision; an offer replayed
  on another connection, moved to another attach or given another nonce; a
  non-member's random tags; answers bound to swapped endpoints or another
  channel, proved under another state, naming a filler, with index 16, for
  another attach, and an offer reflected as an answer; refusals for no
  common state and another revision; an `Identify` over another transcript,
  reflected, naming a key that did not sign it, with a small-order key,
  with a `kc` other than the one signed, and with a short signature.
- `roster_check`: section 3.5's outcomes, each with the device's standing
  in the verifier's view, with probation's steps where it applies:
  probation that admits, probation that ends unknown, a removal the
  verifier lacks, a removal at the re-check, and a verifier that learns of
  its own removal.
- `device_to_peer`: `binding` on both bindings for both purposes, the
  hellos, `presented` for a read credential, an upload key and a fetch key,
  with the seeds they derive from, the rights each credential's entry
  grants, a `RegisterRecoveryEntry` message, an `Awaiting` report with its
  event IDs, the purpose rules over ten connections, hellos refused for
  protocol and revision, and an object's locator with its chunk route.
- `framing`: example frames, among them an `ErasureLate` from a peer, each
  class's cap at and above its limit, and frames refused, among them an
  unknown type, a `Gone` and an `origin` on a member connection, and an
  `ErasureLate` with a standing of 3, with a key it does not list, and on a
  member connection; and an unknown type in 96 to 127, dropped.
- `local_network`: an announcement key, a packet, a listener that opens it
  with its second state, a second packet of the same device that shares
  nothing with the first, a non-member's key and an older state that cannot
  open it, and a nearby name before and after cleaning, with the nearby
  announcement's endpoint key and port.
- `tickets`: a ticket, and five refused.
- `member_addresses`: an `Addresses` with seven entries and its frame; a
  receiver's view, the tickets it keeps, the members it holds admitted
  attaches with and its own endpoint key, and each entry's outcome:
  dialed, a member whose ticket it keeps among them, and skipped as the
  receiver, as the sender, as a device out of its view, as its own
  endpoint key and as a member it holds an admitted attach with; the
  learned tickets it then holds, and the tickets it keeps, unchanged; a
  sender's list for a full member and for a guest, from five tickets: one
  whole, two narrowed to their local-network addresses and two left out;
  addresses classified as local-network or not, at and around each range's
  bounds; and
  `Addresses` refused: with a device ID twice, with 65 entries, with
  a ticket of kind peer, with an entry of three items, with an extra key,
  with a small-order endpoint key, and on a device-to-peer connection.
- `mailboxes`: an address of each of kinds 1 to 3; a device mailbox
  collection (binding, what is signed, the signature, the `MailboxGet`) and
  four refused, one of them the device's `ed` under another `kc`
  (`WrongMailbox`); a device mailbox's oldest-first eviction; sealed
  `frasil/leave-request` and `frasil/list-events` items with their info and
  plaintext; items refused: under another recipient's key, with an
  unknown suite, truncated, and with an unknown content name; the peer's
  caps, with deposits into claimed and unclaimed mailboxes, the items each
  evicts, and those refused `busy`; when a mailbox is claimed and which
  items are still kept; and a `MailboxPut` with key 7 at a peer that does
  not implement [ext-deposit-tokens.md](ext-deposit-tokens.md).
