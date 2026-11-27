# Admission
Protocol 1. Vectors: [admission.json](vectors/admission.json).

This document specifies how someone outside a space comes in, and how a new
device joins a person's device list: the admission event, the mutual
admission code and its exchange, nearby pairing, the setup code, lookups,
the welcome, the newcomer's snapshot and top-ups, and access requests. It
builds on [overview.md](overview.md), [crypto.md](crypto.md),
[identity.md](identity.md), [roster.md](roster.md), [keys.md](keys.md),
[units.md](units.md) and [transport.md](transport.md).

## 1. Overview

- **Admission is one roster event** that grants the newcomer. It rests on a
  compared **admission code**, a **lookup** through an account (shown as
  unverified), or a printed **setup code**. An `add` to a person's list is
  approved by the same code.
- **The code is mutual.** The joiner commits before the approver answers,
  then reveals. Six digits over both sides' fields authenticate each side
  to the other, and a relay gets one guess. Messages after the first are
  sealed to fresh X-Wing keys of the exchange, which runs through an
  exchange mailbox on any always-on peer, over a nearby connection, or both.
  A person's new device can be added over a direct connection alone, with
  no peer.
- **A newcomer** receives a **welcome** with a copy of its wrap, and starts
  from a space snapshot; writers top up the body keys it lacks.

## 2. Formats

### 2.1 The admission event

An admission is one roster event ([roster.md](roster.md)) whose changes
grant the newcomer: a person at `read` or `write`, with its list heads in
the refs; a device at any level, by its device ID, with the keys it
commits to; a device with `session`, a guest
([ext-guests.md](ext-guests.md)); or a space at `read` or `write`. It is
valid or void as a whole, by roster.md's rules.

Each grant's `via` ([roster.md](roster.md)) records what the admission
rests on. It is shown and never checked.

| `via` | Rests on | Signed by |
|---|---|---|
| `code` | a compared admission code (section 3.2), or a setup code (section 3.8) | the approver |
| `link` | an invite link ([ext-invite-links.md](ext-invite-links.md)) | the invite key, in its successor |
| `lookup` | an account's answer, with no code (section 3.9) | an administering device |
| `none` | no admission step: a founder, an administrator's own new device, an access request answered from a roster both read (section 3.14), a direct device member of another space (section 3.16) | an administering device |

A client offers a person "with history", and a guest and a device member
"from now on", and lets the administrator change it. An admission from now
on is a break ([keys.md](keys.md)).

**Replacing a person** ([roster.md](roster.md), "Replacing a person"). A
client MUST sign a replacement only after a compared code with the new
person, with the offer's `replaces` set and `via` = `code`; never after a
lookup or a link, which would let a stolen account or a leaked link take a
person's place. Replicas do not check this.

### 2.2 Exchange values

**J**, the **joiner**, is the device that comes in: a person's new device
(ctx `0x01`), or, for a space (ctx `0x02`), a device or one device of a
person. **I**, the **approver**, is an active list member of the person (ctx
`0x01`) or an administering device of the space (ctx `0x02`).

| Name | Bytes | Chosen by | Meaning |
|---|---|---|---|
| `ctx` | 1 | J | `0x01`: joining a person's device list; `0x02`: joining a space |
| `request` | 16 | J, random; or I, in a prompt (section 3.9) | the exchange's ID, which names its exchange mailbox |
| `expires_at` | u64 | J | J's wall clock plus `admission_code_lifetime`; 0 in the setup flow |
| `eph_J`, `eph_I` | 1,216 | each side, fresh | X-Wing public keys that the exchange's messages are sealed to |
| `nonce_J`, `nonce_I` | 32 | each side, random | the two contributions |
| `display_J`, `display_I` | 0 to 256, UTF-8 | each side | what the other side shows about it, opaque to Frasil |
| `log` | 32 | I | the space ID, or for ctx `0x01` the person ID |
| `heads` | 1 to 256 event IDs | I | the heads of that log in I's view |
| `approver` | 32 | I | I's device ID |
| `offer` | bytes | I | section 2.4; empty for ctx `0x01` |
| `channel` | 0 or 32 | both | the direct connection's channel value; empty through a mailbox |

`channel` is [transport.md](transport.md)'s channel binding of the direct
connection both sides share (the TLS exporter on the iroh binding). A man
in the middle of a direct link holds two TLS sessions, so the two sides'
values differ and so do their codes.

### 2.3 The transcript and the code

```text
heads_hash(log, heads)
           = SHA-256("frasil/admission/heads/v1" || field(log) || u16be(n)
                     || the n heads, ascending, 32 bytes each)

J_fields   = u8(ctx) || request || u64be(expires_at) || field(eph_J)
             || u8(joiner_type) || joiner || field(display_J)
  joiner_type 0, a device:  joiner = the device's device ID (crypto.md)                32 bytes
  joiner_type 1, a person:  joiner = person ID || heads_hash(person ID, list heads)    64 bytes
                            (ctx 0x02 only)

I_fields   = u8(ctx) || log || heads_hash(log, heads) || approver
             || field(eph_I) || field(offer) || field(display_I)

commitment = SHA-256("frasil/admission/commit/v1" || field(J_fields) || nonce_J)
code_hash  = SHA-256("frasil/admission/code/v1" || field(J_fields) || field(I_fields)
                     || field(channel) || nonce_J || nonce_I)
code       = u64 of code_hash[0..8], big-endian, mod 1,000,000, as six digits
```

- Every field has a fixed length or a length prefix, so each input parses
  one way. A device's three public keys, every key its `add` or grant
  will name, enter through its device ID, which commits to all three
  ([crypto.md](crypto.md), "A device's keys"). The code thereby
  authenticates the very device ID the approver then grants or adds, and
  the joiner finds it in the grant (section 3.3).
- The code hash takes `nonce_J` itself, not only the commitment: the
  commitment is public once sent, and a code computed from it and `nonce_I`
  alone could be predicted by the relay before it chose what it sends the
  joiner.
- A client shows the code as two groups of three digits, such as `052 972`,
  and the person compares all six. Nobody types it. The bias of the modulo
  is below 10^-13.

### 2.4 The offer

For ctx `0x02`, the offer is a deterministic CBOR map whose keys are the
roster's change keys ([roster.md](roster.md)):

| Key | Field | Rule |
|---|---|---|
| 2 | `level` | required; `administer` only for a device joiner without `session` |
| 3 | `capabilities` | optional; as roster.md |
| 4 | `label` | optional; 1 to 64 bytes |
| 5 | `history` | required; 0 from now on, 1 with history |
| 7 | `session` | optional, bytes(16); a device joiner only |
| 8 | `replaces` | optional, bytes(32); a person joiner only |
| 13 | `expires_at` | optional; only with `session` ([ext-guests.md](ext-guests.md)) |

Any other key, or a value outside these rules, is `Malformed`. For ctx
`0x01` the offer is empty. `via` is not in the offer: an admission by code
is `via` = `code`.

### 2.5 Messages

Every exchange message, on any path, is:

```text
message = u8(1) || u8(type) || request (16) || body
```

| Type | Name | From | Body | At most |
|---|---|---|---|---|
| 1 | Request | J | in the clear | 4,096 bytes |
| 2 | Response | I | sealed to `eph_J` | 262,144 bytes |
| 3 | Reveal | J | sealed to `eph_I` | 262,144 bytes |
| 4 | List | J, a person joiner | sealed to `eph_I` | 262,144 bytes |
| 5 | Result | I | sealed to `eph_J` | 262,144 bytes |
| 6 | Cancel | either | empty | 4,096 bytes |
| 7 | Join | a person's device (section 3.9) | sealed to the approver's X-Wing key | 262,144 bytes |
| 8 | Hello | a headless device (section 3.8) | in the clear | 262,144 bytes |
| 9 | Offer | I (section 3.8) | sealed to `eph_J` | 262,144 bytes |
| 10 | Welcome | I, ctx `0x01` on a direct connection (section 3.4) | sealed to `eph_J` | 262,144 bytes |

Reading a message, in order: at least 1 byte (else `Malformed`); byte 0 is
1 (else `UnsupportedVersion`); at least 18 bytes and a known type (else
`Malformed`); within its type's limit (else `TooLarge`); a Cancel has no
body (else `Malformed`).

### 2.6 The seal

A sealed body has [crypto.md](crypto.md)'s wrap layout ("The X-Wing wrap"):

```text
sealed body = 0x01 || u16be(0x647a) || enc (1,120) || ciphertext
(enc, ciphertext) = HPKE-Seal(recipient's X-Wing key,
                              info = "frasil/admission/seal/v1" || u16be(0x647a)
                                     || request || u8(type),
                              aad = "", plaintext)
```

It opens by crypto.md's "Opening a wrap", with step 5 requiring at least
1,139 bytes. The info binds the exchange and the message type, so no
sealed body moves to another exchange or reads as another message. The
recipient's key is bound by X-Wing itself. Each side makes a fresh X-Wing
key pair per exchange, keeps its seed in memory only, and forgets it when
the exchange ends. A Join is sealed the same way to the approver's own
X-Wing key.

### 2.7 Bodies

Each is a deterministic CBOR map with exactly the keys listed; anything else
is `Malformed`.

- **Request**, in the clear: `{1: ctx, 2: expires_at, 3: commitment (32),
  4: eph_J (1,216)}`.
- **Response**: `{1: nonce_I (32), 2: log (32), 3: heads (1 to 256 IDs,
  strictly ascending), 4: approver (32), 5: eph_I (1,216), 6: offer
  (bytes), 7: display_I (text)}`.
- **Reveal, a device**: `{1: nonce_J, 2: 0, 3: identity (32), 4: mldsa
  (1,952), 5: xwing (1,216), 6: possession (3,373; ctx 0x01 only),
  7: display_J}`. `identity` is the device's Ed25519 key. `possession`,
  for ctx `0x01`, is the device's proof over the possession statement for
  the Response's `log`, the person ID, with the Response's `approver` as
  adder ([identity.md](identity.md)), which the device signs only after the
  Response. A device joining a space signs no statement over its keys: its
  device ID, in the committed `J_fields`, is what the grant names.
- **Reveal, a person**: `{1: nonce_J, 2: 1, 7: display_J, 8: person ID (32),
  9: list heads (1 to 256 IDs, strictly ascending)}`.
- **List**, and the **Result for ctx `0x01`**: `{1: 1, 2: [signed
  device-list events]}`: every event of the person's list the sender holds,
  in a Result the new `add` included.
- **Result for ctx `0x02`**: a welcome (section 2.10).
- **Hello**: `{1: eph_J, 2: identity, 3: mldsa, 4: xwing, 5: display_J}`.
- **Offer**: `{1: log, 2: heads, 3: approver, 4: eph_I, 5: offer,
  6: display_I, 7: mac (32)}`.
- **Welcome**: a welcome (section 2.10).

### 2.8 The QR code

A joiner shows where its exchange mailbox is:

```text
text = "FRASIL-ADMIT:" || base32(CBOR {1: 1, 2: ctx, 3: request (16),
                                       4: commitment (32), 5: location (text)})
```

Base32 is RFC 4648's, upper case, without padding, so a QR code's
alphanumeric mode carries it. `location`, 1 to 512 bytes, is a peer's URL or
a nearby endpoint as [transport.md](transport.md) writes it. Reading, in
order: the prefix and base32 that re-encodes to itself (else `Malformed`);
key 1 is 1 (else `UnsupportedVersion`); the other keys and lengths (else
`Malformed`).

### 2.9 The setup code

```text
setup code = u8(1) || the device's device ID (32) || setup secret (16)                49 bytes
text       = "FRASIL-SETUP:" || base32(setup code)
setup tag  = SHA-256("frasil/admission/setup-tag/v1" || setup secret)[0..8]

J_fields   = section 2.3, with ctx 0x02, expires_at 0, joiner type 0
I_fields   = section 2.3
mac        = HMAC(setup secret, "frasil/admission/setup/v1" || field(J_fields)
                                || field(I_fields) || field(channel))
```

Base32 is as in section 2.8. Reading the text, in order: the prefix and
base32 that re-encodes to itself (else `Malformed`); byte 0 is 1 (else
`UnsupportedVersion`); 49 bytes (else `Malformed`). In setup mode the device
announces itself nearby under the name `setup-` followed by the setup tag
in lower-case hex, 22 characters.

### 2.10 The welcome

```text
welcome = CBOR {1: 1, 2: space ID (32), 3: event ID (32), 4: key name (bytes),
                5: grant key name (bytes; empty if none), 6: bundle wrap (1,236),
                7: approver (32), 8: [peer hints: 0 to 8 texts of 1 to 512 bytes],
                9: snapshot (64; optional)}

sealed welcome = 0x01 || u16be(0x647a) || enc (1,120) || ciphertext
(enc, ciphertext) = HPKE-Seal(device's X-Wing key,
                              info = "frasil/welcome/v1" || u16be(0x647a) || device ID (32),
                              aad = "", welcome)
```

`event` is the space event whose delivery holds the wrap: the admitting
event or a later delivery. The key names are that delivery's
([keys.md](keys.md)). `snapshot`, present only for an admission from now
on, is the locator of the newcomer's snapshot (section 3.11). Each **peer
hint** is the origin of an always-on peer of the space, as a URL such as
`https://peer.example`, which the newcomer reaches by the server binding
or through that origin's discovery ([transport.md](transport.md), "The
server binding"). The approver names
the peers it syncs the space with; where it knows the space's home peer
([ext-libraries.md](ext-libraries.md), "The home peer"), that peer's URL
comes first. A newcomer ignores a hint that is not such a URL. A member
MAY keep the hints it was welcomed with, in its `peers` table
([at-rest.md](at-rest.md), "Tables"), and try them when a peer answers
`moved` ([peers.md](peers.md), "Refusal codes"). A sealed
welcome opens by crypto.md's "Opening a wrap", with step 5 requiring at
least 1,139 bytes and the info naming the device's own device ID; then
the map reads (else `Malformed`). As an exchange's Result or Welcome
message, the welcome is sealed as section 2.6 says instead.

### 2.11 The lookup prompt and the Join

```text
prompt = CBOR {1: 1, 2: reference (16 random bytes), 3: approver's device ID (32),
               4: approver's X-Wing key (1,216), 5: display_I (text), 6: [peer hints]}
signed prompt = CBOR {1: prompt (bytes),
                      2: the approver device's scheme-2 signature over
                         "frasil/admission/prompt/v1" || field(prompt)}
join   = CBOR {1: reference (16), 2: person ID (32), 3: [signed device-list events],
               4: display_J (text)}
```

The Join travels as a message of type 7 whose `request` is the reference,
sealed by section 2.6 to the prompt's X-Wing key.

### 2.12 The access request

```text
request = CBOR {1: 1, 2: target space ID (32), 3: carrier space ID (32),
                4: requester member [type 0 or 1, ID], 5: requesting device's device ID (32),
                6: level asked for (0 read, 1 write), 7: note (text, 0 to 256 bytes; optional),
                8: request ID (16)}
signed  = CBOR {1: request (bytes),
                2: the device's scheme-2 signature over "frasil/access-request/v1" || field(request)}
```

A **welcome request** (section 3.14, "Welcome requests"):

```text
request = CBOR {1: 1, 2: space ID (32), 3: requesting device's device ID (32),
                4: request ID (16), 5: reason (1: its own erasure is late at a peer)}
signed  = CBOR {1: request (bytes),
                2: the device's scheme-2 signature over "frasil/welcome-request/v1" || field(request)}
```

### 2.13 Error classes

The classes of [overview.md](overview.md), "Error classes", and these, all
of sort decision:

| Class | Meaning |
|---|---|
| `Replayed` | a Request whose ID the approver has answered |
| `CommitmentMismatch` | a Reveal that does not open the Request's commitment |
| `Mismatch` | the person says the codes differ |
| `BadList`, `ListMismatch` | a person joiner's list that is not a valid list, or not the committed one |
| `WrongApprover`, `WrongSpace`, `NotFollowing`, `WrongMember`, `OfferMismatch` | a grant or `add` other than the one the code authenticated |
| `WrongPerson`, `NotInList` | a ctx `0x01` Response or Result for another person than the one expected, or a Result whose `add` is not valid |
| `MailboxInUse`, `UnknownMailbox`, `Duplicate`, `OutOfOrder`, `Cancelled`, `RateLimited`, `MailboxFull` | a peer's refusal of an exchange message |
| `SetupMismatch`, `BadMac`, `Provisioned` | the setup flow |

A peer's refusals of exchange messages travel as [transport.md](transport.md)
says, with these reason codes: `malformed` 400, `mailbox_in_use` 409,
`unknown_mailbox` 404, `expired` 410, `cancelled` 410, `duplicate` 409,
`out_of_order` 409, `rate_limited` 429, `mailbox_full` 503.

## 3. Procedures

### 3.1 The joiner

```text
start:
  1. display_J is at most 256 bytes of UTF-8.                          else Malformed
  2. Draw request and nonce_J, and a fresh X-Wing key pair eph_J.
     expires_at = the wall clock + admission_code_lifetime.
  3. Send the Request. Keep J_fields, nonce_J and the seed in memory only.

on a Response:
  4. Ignore it past expires_at, after a Response was accepted, or if it
     does not open and read, if eph_I fails crypto.md's X-Wing key
     check, or if its offer does not suit this joiner.
  5. A new device (ctx 0x01) that expects a person: log is that
     person ID.                                  else Cancel; WrongPerson
  6. Accept it. Send the Reveal. Show the code and display_I.
  7. If the person says the codes differ: send Cancel and forget the
     request. If they match, a person joiner sends its List (3.5).

on a Result: section 3.3 (ctx 0x02) or 3.4 (ctx 0x01).
```

The joiner reveals once per request, only after a Response, and only for
the first it accepts. It never reuses `request`, `nonce_J` or an ephemeral
key.

Step 5 runs before the new device signs anything over `log`. Its Reveal's
possession proof names `log` and the approver, so only that person's list
can take an `add` of it, and only from that approver; a device that refuses
at step 5 has revealed nothing: no list changes. A client that knows which person a new device is meant to join,
as when the person signed in to an account, MUST give the joiner that
person ID, so that a list member of another person who approves the
request by mistake adds the device to no list.

### 3.2 The approver

```text
on a Request:
  1. The message and its body read.                                   else that class
  2. check_expiry(expires_at, wall clock, admission_code_lifetime,
     admission_code_skew) (overview.md).                              else that class
  3. request has not been answered.                                   else Replayed
  4. ctx is what this approver is doing.                              else Malformed
  5. eph_J passes crypto.md's X-Wing key check.                       else InvalidKey
  6. Draw nonce_I and a fresh X-Wing key pair, now. Remember request
     as answered until expires_at + 60. Send the Response.

on the Reveal (one per request; after any failure the request ends):
  7. The wall clock is known and not past expires_at.                 else Expired
  8. The body opens and reads.                                        else Decrypt / Malformed
  9. Rebuild J_fields, a device's joiner the device ID of its
     revealed keys; the commitment matches.                           else CommitmentMismatch
 10. The offer suits the joiner's type.                               else Malformed
 11. A device: its three public keys pass crypto.md's checks.        else InvalidKey
 12. A device, ctx 0x01: possession verifies.                         else BadPossession
 13. Show display_J and the code; the person confirms that the
     joiner shows the same code.                                      else Cancel; Mismatch
 14. A person: wait for the List (section 3.5).
 15. Still not past expires_at: sign the grant (ctx 0x02, the offer's
     fields, via = code) or the add (ctx 0x01), and send the Result. else Expired
```

A second Reveal for a request, or a Reveal for a request that has ended, is
ignored.

After `CommitmentMismatch` or `Mismatch`, the approver SHOULD tell the
person that the exchange may have been tampered with, and MUST NOT offer
to retry it.

### 3.3 Accepting a grant

The joiner opens its wrap as the welcome says, derives the body key, opens
the admitting event, and checks, in order:

```text
1. Its author is the Response's approver.                             else WrongApprover
2. Its log is the Response's log.                                     else WrongSpace
3. Every head of the Response is in its past.                         else NotFollowing
4. It holds exactly one grant of the joiner: the person ID, or the
   device's device ID.                                                else WrongMember
5. That grant's level, capabilities, label, history, session,
   replaces and expires_at are the offer's, and via is code.          else OfferMismatch
6. A replaces grant comes with the removal of that person, and an
   offer from now on comes in a rotation that breaks.                 else OfferMismatch
7. Its own resolution of the space finds the event valid.             else the event's verdict
```

Until step 7 can run, the grant is held, never relied on. A joiner that
refuses a grant tells its person and keeps nothing of the space. So the
code pins the newcomer's view: a relay cannot hand it another space, or an
older roster.

### 3.4 A person's new device

J is the new device, and I a list member of the person; `log` is the
person ID and `heads` the list's heads at I. A J that expects a person
refuses a Response for another one before it reveals (section 3.1, step
5). After the comparison, I signs
an `add` of a device naming J's device ID and three public keys (Ed25519,
X-Wing and ML-DSA-65) with J's possession proof, and sends the Result. J
checks, in order:

```text
1. The Result reads.                                                  else Malformed
2. Exactly one event is the list's first, and its ID is the log.      else WrongPerson
3. The events place.                                                  else Malformed
4. Exactly one add names J's device ID.                               else WrongMember
5. Its author is the approver.                                        else WrongApprover
6. Every head of the Response is in its past.                         else NotFollowing
7. The merged list holds it valid.                                    else NotInList
```

An `add` that names J's device ID with other keys fails identity.md's
check alone (`NotCommitted`), so step 7 refuses it.

J then reaches the person's spaces as each person grant covers it. I
publishes the new list events into each space it writes in, as list units
([units.md](units.md)), and sends J a welcome for each.

**Over a direct connection.** Two devices that share no always-on peer,
such as two applications on one machine or two machines on a local
network, run the exchange over a nearby connection
([transport.md](transport.md)) and nothing else. I listens; J dials and
writes first; `channel` is the connection's; each message travels in a
`Pairing` frame. While its person compares the codes, each side keeps
reading, and stops at the other's Cancel: an approver that receives one
before it signs the `add` signs nothing.

After the Result, I hands J the person's spaces on the same connection.
For each space whose delivery reaches J, in turn, it sends:

1. a Welcome message, whose body is the welcome (section 2.10) naming that
   delivery and J's wrap in it, with no peer hints and no snapshot, in a
   `Pairing` frame whose key 2 is I's member ticket;
2. that space's events, as [units.md](units.md)'s messages in `Sync`
   frames on an object stream it opens with `Open {1: 2, 2: space}` and
   finishes.

I then finishes its side of the nearby stream, and deposits no welcome in
any mailbox. J ignores a Welcome before it has accepted the Result, or for
a space an earlier Welcome named, and checks each other one, in order:

```text
1. The message reads, its request is the exchange's, and its body opens
   and reads.                                                         else that class
2. Its approver is the Response's approver.                           else WrongApprover
3. J's own resolution of the space, from the events on its object
   stream, finds the delivery valid and the person's grant reaching
   J.                                                                 else the event's verdict
```

Once the nearby stream ends, J closes the connection and dials the member
ticket for the spaces it accepted. Nothing but the delivery and the roster
admits it: a Welcome only says where to look (section 3.10).

Where both devices run on one machine, the two applications MAY compare
the codes between themselves, over a local channel that authenticates
both, in place of the person's eyes, once the person has consented to the
admission (section 4).

### 3.5 A person that joins a space

A person joiner sends its List only once its person has confirmed that the
codes match, so a relay that substituted keys, or an approver the person
did not mean, never receives the list. After its own person's
confirmation, the approver checks, in order:

```text
1. The List reads.                                                    else Malformed
2. The first event's ID is the person ID, and every event passes
   identity.md's checks.                                              else BadList
3. The heads of the events received equal the committed list heads.  else ListMismatch
4. The merged list holds at least one active device or passkey
   member.                                                            else BadList
```

The approver then grants the person, with the list heads in the grant's
refs; wraps for the list's devices in the admitting event; publishes the
list as list units; and sends the Result to J and welcomes to the person's
other devices.

### 3.6 Exchange mailboxes

An exchange travels through [transport.md](transport.md)'s exchange
mailbox, named by `request`, on any always-on peer, with no account and no
credential. A Request opens it; whoever knows the request ID may put the
exchange's later messages and read them. A peer checks each put, in order;
clients rely on none of it:

```text
a Request:
  1. The message reads.                                               else that class
  2. No exchange mailbox has this request ID.                         else MailboxInUse
  3. Its body reads, and check_expiry passes on the peer's wall
     clock.                                                           else that class
  4. Its source has opened fewer than 10 exchange mailboxes in the
     last minute, and holds fewer than 128 open.                      else RateLimited
  5. The peer holds fewer than 65,536 exchange mailboxes, and under
     256 MiB in all.                                                  else MailboxFull
any other message:
  6. The message reads, and its type is 2 to 6.                       else that class / Malformed
  7. The exchange mailbox exists.                                     else UnknownMailbox
  8. The peer's wall clock is not past expires_at.                    else Expired
  9. It is not cancelled.                                             else Cancelled
 10. A Cancel marks it cancelled.
 11. It holds no message of this type.                                else Duplicate
 12. A Response follows the Request; a Reveal the Response; a List
     and a Result the Reveal.                                         else OutOfOrder
```

A peer keeps exchange mailboxes in memory only, and drops each after
`exchange_mailbox_lifetime`; a restart ends them all. A peer MAY lower any
limit. A Join, Hello, Offer or Welcome never goes to an exchange mailbox.

The approver fetches the Request from the location a QR code names
(section 2.8), and requires its commitment to equal the QR code's. An
approver can also open the exchange itself, by a prompt that names a
request ID (section 3.9); each side refuses an ID it has used.

**Without a nearby connection.** A party that cannot take part in nearby
pairing, such as a browser ([transport.md](transport.md), "The server
binding"), runs the whole exchange, as joiner or approver, through an
exchange mailbox at a peer it reaches over the server binding, with
`channel` empty:

- It deposits each message with that binding's `POST` of kind 1, and
  collects with its `GET` of kind 1, giving as `after` the last item ID it
  has collected. The peer pushes nothing, so a party polls until the
  exchange ends or `expires_at` passes, and SHOULD NOT poll more often than
  once a second. On a device-to-peer connection, `MailboxPut` and
  `MailboxGet` of kind 1 serve the same.
- Each side reads every message of the mailbox, its own included, and acts
  on each message of the other side once.
- A joiner names, as its QR code's `location`, the origin of that peer's
  server binding, such as `https://peer.example.org`. A joiner whose
  approver may be such a party names a location of this kind, never a
  nearby endpoint alone.
- For a person's new device (section 3.4), the approver deposits each
  welcome it sends J in J's device mailbox at that peer, beside any other
  route, and J collects it there.

### 3.7 Nearby pairing

The host announces itself nearby and the newcomer connects
([transport.md](transport.md)); both take `channel` from the connection.
They run the exchange in pairing frames, the newcomer as J. On a match the
host signs the admission and sends the Result, the newcomer's snapshot and
a member ticket. The newcomer checks the grant (section 3.3), closes the
connection, and dials the ticket through the member handshake. Nothing on
the nearby connection admits it to anything by itself. A person's new
device pairs the same way, with ctx `0x01`, and receives the person's
spaces after the Result (section 3.4, "Over a direct connection").

### 3.8 Setup

A device with no display is provisioned by a setup code; a device with any
display uses the admission code. At first start and after every reset, the
device makes its three key pairs, a 16-byte setup secret, a request ID and
an ephemeral X-Wing key pair, prints or shows the setup code, and announces itself nearby. The
administrator scans the code, connects, and receives the Hello on the
nearby connection.

The administrator checks, in order:

```text
1. The text reads (section 2.9).                                      else that class
2. The Hello reads, and the device ID of its keys is the scanned
   one.                                                               else SetupMismatch
3. Its keys pass crypto.md's checks.                                  else InvalidKey
4. Send the Offer. Then sign a device grant with the offer's fields
   and via = code, and send the Result.
```

The device checks, in order:

```text
1. It is not provisioned, and not bound to another Offer.             else Provisioned
2. The Offer opens and reads; its request is this device's.           else Decrypt / Malformed
3. The offer suits a device joiner.                                   else Malformed
4. mac verifies, in constant time, over this connection's channel.    else BadMac
5. Bind to this Offer: refuse every other until reset.
6. On the Result: section 3.3, with the Offer in place of the
   Response. A match provisions the device; it forgets the setup
   secret and stops announcing.
```

There is no commitment and no code: the scanned device ID authenticates
the device's keys, and the MAC the administrator and this connection.
`expires_at` is 0 because a headless device may have no clock. An Offer
whose MAC fails changes nothing, and the device MAY slow down repeated
failures. A reset makes new keys, a new secret and a new code.

### 3.9 Lookups

An administrator MAY grant a person found through an account lookup
([identity.md](identity.md)) with no code, `via` = `lookup`; applications
show the member as **unverified**. A client interface that grants a person
by an account subject MUST take the code path unless its caller asks for a
lookup grant by name. A member that later compares a code with the person
records the result on its own device only; a mismatch offers removal.

A lookup finds a person ID, not its devices. So:

1. **Prompt.** The administrator's device leaves a signed prompt in the
   person's mailbox at the account's server
   ([transport.md](transport.md)).
2. **Answer.** The person's device checks, in order: both maps read (else
   `Malformed`); key 1 is 1 (else `UnsupportedVersion`). Then:
   - **A co-member.** If a space this device holds grants both the person
     and the approver's device ID, the device takes the approver's
     Ed25519 and ML-DSA-65 keys, which with the prompt's X-Wing key give
     that device ID ([crypto.md](crypto.md), "A device's keys"; else
     `NotCommitted`), from that space's records or any other source. The
     signature verifies under them (else `BadSignature`). It shows
     "<display_I>, a member of
     <space>, asks to add you; unverified", and on consent sends a Join to
     the approver device's mailbox. A co-member already reads the person's
     list, so the Join tells it nothing new.
   - **Anyone else.** No Join. On consent, the device opens the code
     exchange instead, with the prompt's reference as the request ID, so
     its list goes out only after a matched code (section 3.5).
3. **Grant.** The approver checks the Join's list as section 3.5, steps 1,
   2 and 4, with the person ID the lookup returned; grants the person with
   `via` = `lookup` and the list's heads in the refs; wraps for the list's
   devices; publishes the list; and sends each device a sealed welcome.

When both sides run the exchange and compare the code, the grant is `via` =
`code`.

### 3.10 Welcomes

A newcomer cannot fetch before it holds a key, so the device that signs
its admission (for a person's new device, the approver, per space) sends it
a welcome: as the Result of a code or setup exchange, as a Welcome message
on a direct connection (section 3.4), and otherwise sealed to the device's
mailbox: deposited at a peer that serves the space once the peer holds the
admitting event, or over a member connection with the device
([transport.md](transport.md), "Mailboxes"), or over a nearby connection. A
grant of a person admits each device its list vouches for, so its signer
welcomes each of them but itself, and a space created for a person reaches
the person's other devices with no peer. The newcomer opens the
wrap with the welcome's key names, derives the read credential, fetches the
log, finds the event, and checks that it holds exactly this wrap. A welcome
handed over a member connection by its approver is fetched from there: the
newcomer attaches the space on that connection with the state the wrap
holds. A device takes a welcome over a member connection only from the
welcome's approver, so the device that signed the admission, or a later
delivery, is the one that hands it over; no other member carries it.
Nothing in a welcome is trusted: the event and the roster decide.
An application MAY also carry a welcome by a route of its own, such as a
message to its person; the welcome's checks are the same however it
arrives.

**A welcome that waits.** The signer keeps each welcome it means to hand
over a member connection or deposit at a peer in a list of **waiting
welcomes**, at rest in its own store, as a `welcome` record in the space's
log ([at-rest.md](at-rest.md), "Tables"). An entry holds the newcomer's
device ID, the space, the **event the entry waits on**, the sealed welcome,
the `T` of the signer's timeline at which it kept the entry
([overview.md](overview.md), "The local timeline"), and the peers the
signer has deposited the welcome at, each with the `T` of its latest
deposit there and the number of deposits it has made there. The event the
entry waits on is the event the welcome names, or, for a welcome that
answers a welcome request (section 3.14), the `frasil:body-keys` unit that
publishes its snapshot (section 3.11), which the signer writes after that
event, so that a deposit waits for the snapshot as well. The welcome is
sealed to the newcomer's X-Wing key before it is kept, so the signer's
store holds it only in the form a peer holds it: the signer cannot open it
again, and nothing in it is readable without the newcomer's keys. A signer
keeps the entry of a grant it signs in the same commit as the grant's
event, and starts each run from the entries its store holds, so a waiting
welcome survives a restart, and its hand-over and its deposits resume
with no other trigger. In a space the signer keeps in memory only
([at-rest.md](at-rest.md), "A memory-only log"), the entry and its
deposits are kept in memory only, and a restart loses them. One of these
ends an entry, and the signer then deletes its record:

- a member connection admits the newcomer's attach of the space, whether
  that attach is still live or has ended;
- the space's log, in the signer's own view, holds an event the
  newcomer's device signed, accepted in full ([events.md](events.md),
  "Accepted in full, and what is cited"), that has the event the entry
  waits on in its past: the newcomer holds that event, and with it the
  event the welcome names and the wrap in it, so it needs the welcome no
  longer. An event the device signed before the
  grant, or concurrently with it, does not have the grant in its past and
  ends nothing, so the welcome of a grant to a device the space already
  reached under another grant or level waits on. The signer checks this
  before each deposit, a further attempt of a deposit it keeps to go
  again included, and then drops the deposits of that welcome it keeps;
  it SHOULD also check it for every waiting welcome from time to time, so
  that an entry it deposits no more does not keep its place under the
  bound until its age. It need not check it before a hand-over over a
  member connection, which takes no room in a mailbox and whose attach
  ends the entry. Since each event of a device's chain names the one
  before it as `prev` ([events.md](events.md), "Chains and evidence of a
  fork"), the signer MAY look at one event of the newcomer's chain only:
  the newest event accepted in full that `prev` leads to, in at most 64
  steps, from the chain's latest event in its view, the one with the
  greatest `seq`. It MAY then judge that event once, and again only once
  it changes, or, in a log that holds a stub or a witness
  ([units.md](units.md), "Partial replicas"), where a walk of an event's
  past stops at what the log does not hold, once that log changes;
- the space's roster, in the signer's current view, no longer reaches the
  newcomer, as after its removal: the signer checks this before each
  hand-over and each deposit, a further attempt of a deposit it keeps to
  go again included, and then hands nothing over, deposits nothing, and
  drops the deposits of that welcome it keeps;
- the signer keeps at most 4,096 waiting welcomes, and a newer one passes
  the oldest, first by the `T` at which each was kept;
- `welcome_retention` ([overview.md](overview.md), "Every timer") has
  passed on the signer's timeline since it kept the entry, the most a peer
  keeps a mailbox item (`mailbox_retention`). A copy deposited late in that
  time can stay in a peer's mailbox after the entry ends, until that
  peer's retention for it passes; the newcomer's checks decide what it is
  worth, as for any welcome.

While it waits, the signer also deposits the welcome in the newcomer's
device mailbox at each peer it is connected to, once that peer holds the
event the entry waits on, and records the peer and the `T` of the deposit
in the entry, in the commit that keeps the deposit
([transport.md](transport.md), "A sender keeps what was refused"). A peer
keeps the item for a while only: `uncollected_retention`, 72 hours by
default, while the newcomer has not collected its mailbox at that peer,
and `mailbox_retention` once it has (transport.md, "Claimed device
mailboxes"). So the signer deposits the welcome at a peer again once
`welcome_redeposit` ([overview.md](overview.md), "Every timer") has
passed since its latest deposit there, at most three times: it makes at
most four deposits of a welcome at one peer, the first and three
repeats, and after the fourth it deposits that welcome at that peer no
more, while the entry lasts on until one of the conditions above ends it.
It records the new `T` and the count of deposits there with each one;
while a deposit it keeps to go again at that peer still holds the same
welcome, it waits for that one instead. The newcomer keeps one welcome
per space, so a second copy is nothing new (transport.md, "A sender
keeps what was refused"). A restart neither deposits at a recorded peer
again before `welcome_redeposit` has passed nor counts its deposits there
again. A deposit the peer refused for good (any reason but `busy` or
`rate_limited`, such as `unsupported`) counts as one of the four, and
the peer stays recorded with it. A record names at most 64 peers, and the
signer deposits a welcome at those only: once its record names 64, it
deposits that welcome at no other peer. A peer whose origin is longer
than 512 bytes, which a `deposit` record cannot name
([at-rest.md](at-rest.md), "Tables"), is deposited at never.

This leaves gaps the signer cannot close. A peer keeps the welcome for a
while only: with four deposits `welcome_redeposit` apart and the default
`uncollected_retention` of 72 hours, a newcomer that never collects its
mailbox at a peer can find the welcome there for about 9 days after the
first deposit, and after that only a member connection with the signer,
or a later first deposit at another peer, delivers it; a peer whose
operator keeps an item for less than `welcome_redeposit` (an
`uncollected_retention` or a `mailbox_retention` under 48 hours) can drop
it between deposits. A mailbox at its bound of 64 items or 4 MiB
(transport.md, "Mailboxes") evicts its oldest items, a welcome's copies
among them, and each of the at most four copies a peer receives counts
against that bound until the peer's retention for it passes. A peer the
signer is not connected to receives nothing until the two are connected
again. And a newcomer that collects the welcome from a peer and then
signs no event in the space, as a device that only reads may never do,
gives the signer no sign that it holds the space: for it, only the count
of four bounds the copies at each peer, and the entry lasts until
`welcome_retention` or the bound passes it. A signer that looks at one
event of the newcomer's chain only, as it MAY, misses in the same way an
event that `prev` does not lead to from the chain's latest: one on another
branch of a chain that forked, one of a chain the device started again
below its latest `seq`, and one more than 64 steps behind events of the
chain the signer has not accepted in full.

A space the signer forgets, or drops for its erasure, takes its waiting
welcomes with its log ([at-rest.md](at-rest.md), "Forgetting a log, and
re-keying").

A welcome that no longer waits is not made again: no member signs another
delivery to replace one. A newcomer whose welcome ended before it took the
space up, past the bound or the age, or with the signer's store, is
admitted again by an administrator, who removes it from the space and
grants it once more.

A device that forgets a space whose roster still grants it follows the
space again from a welcome it receives later: one still waiting at the
signer, which hands it over when the two next meet over a member
connection, or one still in its device mailbox at a peer, which it collects
again after a restart. Forgetting a space does not leave its roster; a
removal does.

A peer does not authenticate who deposits in a device mailbox, so a
newcomer that collects a welcome there, with no exchange that named the
approver, keeps the space only once its own resolution finds, in order:

```text
1. The event is a space event of the welcome's space, valid.          else that verdict
2. Its author is the welcome's approver, which administered the
   space at the event's place.                                        else WrongApprover
3. The event's delivery holds exactly the welcome's wrap.             else Malformed
4. The roster grants the newcomer: directly, or through a person
   whose list holds it.                                               else WrongMember
```

It forgets a space whose checks fail, or whose event has not arrived from
the peer within 60 seconds, and collects its mailbox again from its start
when it retries, so that a welcome it collected before is not lost.

### 3.11 The newcomer's snapshot

A newcomer admitted from now on, and a restored member, start from a space
snapshot, whose format is [units.md](units.md)'s and which travels under
its sender's scheme-2 signature. It carries, as the sender holds them:

- the **body keys** of every space event the sender opened that the
  newcomer cannot open with the keys it will hold: the genesis, the roster
  it joins, and its admitting event's past;
- the **device lists**: every event the sender holds of the list of every
  person a roster in the snapshot names, now or before, since a list is
  verified from its first event, naming in the snapshot's key 15 those at
  the place of its base, which the newcomer counts at the base ([roster.md](roster.md),
  section 3.11, "A list at an event's place");
- the **rosters along the grant path**: for every space this space grants,
  transitively, its space events and storage events, and the anchors among
  their parents, with their body keys, and stubs for the units they name as
  parents;
- the documents' history-free state.

The administering device that signs an admission by code, setup code,
lookup or access request publishes the snapshot right after it, sealed
under the admission's state. In order, it MUST:

1. upload the snapshot as an object ([units.md](units.md)), and the
   stream snapshot objects it names, to the peers its welcome names;
2. write a `frasil:body-keys` unit in the system stream, sealed under that
   state, that carries body keys the snapshot carries, the first 1,024 by
   event ID when it carries more, and lists every one of those objects in
   `objects`, so that peers keep them ([peers.md](peers.md), "Objects");
3. name the snapshot's locator in the newcomer's welcome.

A host of nearby pairing also hands it over the connection. The newcomer
fetches the snapshot by that locator under the read credential of the
admission's state, and MUST use it before it places the space's events. A
newcomer that finds no snapshot, or an incomplete one, asks any member,
since every member that holds the space can make one. No record keeps the
wait at rest ([at-rest.md](at-rest.md)): a newcomer that restarts before it
has used a snapshot asks any member for one, as if it had found none.

### 3.12 Top-ups

The **top-up set** of a member admitted from now on is every space event
and every unit sealed under a state from before its break that is not in
its break's past. A state is from before the break when none of its
rotations is the break or follows it. So a rotation concurrent with the
break is in the set, as is every event sealed under it.
The snapshot carries the body keys of that past, and the documents' state
in place of its units; events after the break are sealed under states the
member holds or receives ([keys.md](keys.md), "Deliveries"); so only
events concurrent with the break remain: a change written while the member
was admitted, a delivery, or a body-keys unit written before its author
saw the break. Such an event stays held (`Sealed`) at the member until it
receives the body key, and every event after it waits for it.

Any writer that opens an event of a member's top-up set whose body key that
member has not received waits its rank delay ([keys.md](keys.md)'s
cascades, over the space's writer devices, with the event's ID as the
trigger). If no body-keys unit after the break carrying that key has
arrived by then, it writes one in the space's system stream
([units.md](units.md)), sealed under the current state. A body-keys unit
concurrent with the break is itself in the top-up set, so it does not
count. Two units with the same key are harmless. A body key reveals one
event's sealed part and nothing of any state ([keys.md](keys.md), "The
space event's body"; [units.md](units.md), "The seal"). A writer that
cannot upload hands the keys over the member channel in the same form.

### 3.13 Granted rosters after the snapshot

A newcomer that is no member of a granted space cannot fetch that space's
log. After its snapshot, it fetches the granted space's later events from
the members that cite them in their refs, since every citing device
supplies what it cites ([roster.md](roster.md)). A writer that cites, in a
response, an event of a granted space whose body key some member of this
space lacks also publishes, by section 3.12's rules, the body keys of that
event and of the granted space's events it has not yet covered. Without
them, such a member holds every unit written through that grant pending.

### 3.14 Access requests

A member that cannot open a nested space asks for access in a space that it
and that space's administrators both read, usually the parent. The request
is **targeted** at administering devices, never broadcast and never written
as a unit: an item in their device mailboxes, sealed with
[transport.md](transport.md)'s item seal and the content name
`frasil/access-request`, or, with [ext-ephemeral.md](ext-ephemeral.md), an
ephemeral message targeted at them. A member at `read` MAY send one. The
requester names the administering devices it can see; a device that does
not administer the target ignores it.

An administering device of the target checks, in order: both maps read
(else `Malformed`); key 1 is 1 (else `UnsupportedVersion`); the fields have
their types and lengths, the target is not the carrier, and the level is
`read` or `write` (else `Malformed`); it holds the requesting device's
keys, which hash to its device ID, from the carrier space's records or any
other source ([crypto.md](crypto.md), "A device's keys"; else
`NoHybridKey`); the signature verifies (else `BadSignature`); the device
reaches the carrier through the named member (else it ignores the
request).

Answering is granting: the administrator grants the member in the target
space, `via` = `none`, with the person's list heads in the refs, publishes
the list if the target lacks it, and sends welcomes. Declining sends
nothing. `administer` is never asked for this way.

**Welcome requests.** A member device that holds no key of a space, as a
device that erased the space for its own erasure and was told by a peer
that the erasure is late ([peers.md](peers.md), "A device's own erasure"),
asks for a welcome: an item in the device mailbox of each administering
device it names, sealed with [transport.md](transport.md)'s item seal and
the content name `frasil/welcome-request`. An administering device of the
space checks, in order: both maps read (else `Malformed`); key 1 is 1 (else
`UnsupportedVersion`); the fields have their types and lengths and the
reason is 1 (else `Malformed`); it holds the requesting device's keys,
which hash to its device ID, from the space's records (else `NoHybridKey`);
the signature verifies (else `BadSignature`); the device is a member at
its merged roster, directly or through a person whose list holds it, at
any level (else it ignores the request). It then sends the device a
welcome (section 2.10) naming a delivery that holds a wrap for it and a
space snapshot it publishes as for a restored member (section 3.11),
sealed to the device's mailbox, once per request ID. A request grants
nothing: the device's own grant decides what it reads, and the welcome's
checks (section 3.10) are the same.

### 3.15 Invite links and guests

- [ext-invite-links.md](ext-invite-links.md) admits by an invite link,
  claimed with no administrator online, through roster.md's invite hook. A
  core implementation never signs an invite grant, treats member type 3 as
  roster.md says, and shows `via` = `link` like any other `via`.
- [ext-guests.md](ext-guests.md) gives a guest's session its expiry (offer
  key 13), keeps nothing of it at rest, and hands such a guest its snapshot
  over the member channel. A core implementation never puts key 13 in an
  offer, and a core joiner refuses an offer that carries it as `Malformed`.

### 3.16 A member of another space

An administrator of a space MAY grant a device that, in its current view,
another space it holds (the **known space**) grants directly: by that
device's ID, with the keys the known space's grant names, which the ID
commits to ([roster.md](roster.md), "A device's keys"). No code is
compared and no peer is needed. The grant is a device grant at `read` or
`write`, or at `administer` at a rank at most the granter's own, with
history, and `via` = `none`. Before it signs, the granter checks, in
order, and refuses the grant when one fails; nothing is signed or sent for
a refusal, which is the granter's own and has no class on the wire:

1. The granter administers the space.
2. The known space reaches the granter. A device the known space no longer
   reaches is no longer sent its changes, so its view of that roster is not
   kept current.
3. The known space's roster grants the device directly, not only through a
   person.
4. That grant carries no `session`: the device is not a guest there.
5. The known space reaches the device, which has not forked there
   ([roster.md](roster.md), "Grants of spaces and effective membership"): a
   grant with no effect, such as one in a restricted space whose parent
   does not reach the device, vouches for nothing.
6. The space does not reach the device yet, directly, through a person or
   through a space.
7. A restricted space's parent reaches the device
   ([ext-restricted-spaces.md](ext-restricted-spaces.md), "Membership of a
   restricted space").

Then roster.md's checks of the change apply as for any grant, the rank's
among them. Replicas check none of the seven: the grant is an ordinary
device grant, valid by roster.md's rules alone.

The grant commits at once, offline, and the granter reports it once it
commits, whatever becomes of its welcome. The welcome is sealed to the
device's X-Wing key, which every device grant carries
([roster.md](roster.md), "A device's keys"), and waits at the signer, kept
at rest in the grant's own commit, as section 3.10 says: a member
connection with the device hands it over, and the signer deposits it in
the device's mailbox at the peers it is connected to, as for a person's
grant, before and after a restart. Over a member connection, the device takes it only
from the signer: the two devices meet on a connection formed for any
space they share, such as the known space, and the granted device follows
the space and attaches it there.

What the grant proves is only that some administrator of the known space
granted that device ID there; the welcome opens for that device alone. It
proves nothing about the device's person, and the known space's later
changes do not reach the new grant: a removal from the known space leaves
the device in this one until an administrator removes it here.

## 4. Security considerations

- **One guess.** Towards the approver, the relay's last choice is the
  Request's commitment, which fixes `J_fields` and `nonce_J`; the approver
  draws `nonce_I` after it arrives. Towards the joiner, its last choice is
  the Response, which fixes `I_fields` and `nonce_I` before the joiner
  reveals `nonce_J`, which the commitment hides. Whichever side it
  completes first, the other side's code depends on a value it did not know
  when it chose. The codes match with probability 10^-6, and otherwise the
  two screens differ. The ephemeral keys are in the transcript, so a relay
  that seals to keys of its own changes both codes. This rests on both
  nonces and `request` coming from a secure random source.
- **What the code does not protect.** A person who confirms without
  comparing, or compares a code read to them over a channel the attacker
  controls. The display is committed, and a client MUST render it as text,
  never as markup.
- **Applications that compare for the person.** Two applications on one
  machine that compare the code over a local channel stand in for the
  person's eyes. The channel MUST authenticate both ends, as a check of
  the caller's code signature does, and the person MUST have consented to
  admitting that application; otherwise a local impostor confirms its own
  code.
- **An active relay** that substitutes ephemeral keys reads that one
  exchange's offer, keys, displays and list, and is then exposed by the
  codes. Expiry is committed, so a relay cannot extend it.
- **Lookups** trust the account's server at first contact: it can answer
  with a person of its choosing and relay that person's Join. The grant
  says `lookup`, applications show it unverified, and a later comparison
  detects the substitution. A prompt asks a person's device for its whole
  device list, so the device answers only a co-member, who already reads
  that list, and runs the code exchange for anyone else.
- **A setup secret is a bearer secret** until provisioning: whoever reads
  it first provisions the device, visibly, and a reset undoes it.
- **No proof of possession for a space.** A device that joins a space
  reveals its keys and signs nothing over them. The code authenticates its
  device ID, which commits to the keys, so a relay cannot swap them, and
  the grant names exactly that ID. A joiner that reveals keys it does not
  hold, such as another device's public keys, has itself compared the code:
  it gets a grant for a device ID that it cannot sign as, and whose wraps
  it cannot open, and the device that does hold them gains a grant it never
  asked for, which the approver could have made from any roster it reads.
  A person's new device still signs its possession proof, which binds its
  keys to the person and to the approver as adder; a device ID binds
  neither ([identity.md](identity.md), "The possession statement").
- **A member of another space** (section 3.16) is admitted on the trust
  of the known space's roster alone: any administrator of the known space
  could have put the device ID there. A granter that admits a known
  space's members to its own space gives that space's administrators the
  power to choose whom it admits, and a removal there does not reach the
  grant here.
- **Forks a newcomer cannot see.** A newcomer judges a granted space's
  roster from its space events alone. If an author of that space forked
  only in units the newcomer never receives, the newcomer does not void
  that author's later roster events until it holds the evidence, unless the
  snapshot carries fork evidence for that log ([units.md](units.md)).

## 5. Test vectors

[admission.json](vectors/admission.json):

- `parameters`: ctx values, joiner and message types, lifetime, skew, sizes.
- `transcript`: four exchanges with every intermediate value and message
  byte for byte: a person's new device through a mailbox, a guest nearby
  with a channel, a person joining a space, and a replacement; a code with a
  leading zero; one code with and without its channel; QR codes, three
  refused.
- `new_device`: ctx `0x01` end to end: the possession proof over the person
  ID for the approver, the `add`, the Result, and the new device's
  checks (accepted; `WrongApprover`, `WrongPerson`, `NotFollowing`,
  `WrongMember`); the same exchange over a direct connection, with its
  channel and code, a Welcome after the Result, and the new device's
  checks of it (accepted; `WrongApprover`; `Decrypt`).
- `negative`: the approver's refusals (`Expired`, a 961-second lifetime,
  `Replayed`, a wrong `ctx`, an envelope of version 2, `TooLarge`, a Cancel
  with a body, another display and other keys as `CommitmentMismatch`, a
  second Reveal, a Reveal past expiry); what the joiner ignores; seven
  refused offers.
- `exchange_mailbox`: an exchange mailbox's address; one exchange through a
  peer, step by step (stored, `MailboxInUse`, `OutOfOrder`, `Duplicate`,
  `Expired`, `UnknownMailbox`, a Join refused); eleven Requests in a minute,
  the last `RateLimited`; a 961-second lifetime.
- `setup`: the setup code, text, tag and announced name, the Hello, the
  fields, the MAC and the Offer; the outcomes (accepted, `SetupMismatch`,
  `BadMac` for a wrong MAC and another channel, bound, `Provisioned`);
  refused texts; a peer refusing a Hello.
- `welcome`: a guest's admitting event with its own wrap, the Result and a
  sealed welcome; the joiner's checks (accepted; `WrongApprover`,
  `WrongSpace`, `NotFollowing`, `OfferMismatch` twice); refused welcomes.
- `top_up`: the body keys a snapshot carries; a delivery, a rotation and a
  delivery under that rotation, each concurrent with an admission, held
  until its body key is topped up, then valid; the writers' rank for the
  first delivery's top-up. [units.json](vectors/units.json)'s
  `handed_body_keys` gives a unit's top-up.
- `lookup`: a signed prompt; the person's device's answers (a Join for a
  co-member, the code exchange for anyone else, `BadSignature`,
  `NotCommitted`); a Join.
- `access_request`: a signed request and its checks (accepted;
  `NoHybridKey`, `BadSignature`, two `Malformed`).
- `welcome_request`: a signed welcome request, with the requesting
  device's seeds, and its checks: a welcome for a member, ignored for a
  device that is no member, `NoHybridKey`, `BadSignature` for a signature
  over another request, `UnsupportedVersion`, and `Malformed` for a
  changed reason and for a reason it does not know.
