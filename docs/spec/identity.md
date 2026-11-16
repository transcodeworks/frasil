# Identity
Protocol 1. Vectors: [identity.json](vectors/identity.json).

This document specifies a device's keys, the person and its device list:
the list's events, its four kinds of list member, possession proofs, ranks,
the state of a list and how replicas merge it, and what a list vouches for.
It also specifies recovery keys and passkey members with their derivations,
how a device that holds only a passkey or a recovery sheet fetches the
person's personal space, fingerprints, pins and account links. It depends on
[overview.md](overview.md), [crypto.md](crypto.md) and
[events.md](events.md), and uses [roster.md](roster.md)'s resolution
procedure and person grants, [keys.md](keys.md)'s wraps and
[peers.md](peers.md)'s recovery entries.

## 1. Overview

- A **device** holds three key pairs: an Ed25519 **identity key**, which
  signs; an **X-Wing key**, to which keys are wrapped; and an **ML-DSA-65
  key**, which signs authority events beside the identity key. It is named
  by its **device ID**, which commits to all three ([crypto.md](crypto.md),
  "A device's keys").
- A **person** is the keys of one **device list**, a log of `add`, `revoke`
  and `confirm` events. The **person ID** is the ID of its first event. A
  list member is a device, a **passkey member**, a **recovery key** or a
  **recovery agent**, each named by its device ID. Every `add` carries the
  named keys and their **possession proof**, which binds the keys and the
  kind to the person ID and to the list member that adds it. No server adds
  or revokes a list member.
- A list branches and merges like a roster. A list member brought in by a
  passkey or an agent is **rooted** there until a device that is not rooted
  confirms it. Of two list members that revoke each other concurrently, the
  higher **rank** wins; within a rank, both are revoked. A recovery key that
  is not rooted outranks every other list member.
- The list lives in the person's **personal space**, and a sealed copy
  travels in every space that grants the person. A **fetch key** derived
  from a passkey or a recovery sheet lets a device that holds nothing else
  fetch the personal space, and so the list.
- A person who loses every device returns with the recovery key or a
  passkey, which keep the person ID; with a recovery agent
  ([ext-recovery-agent.md](ext-recovery-agent.md)); or as a new person.
- A **fingerprint** lets a person compare keys by eye, a **pin** lets a
  client detect a list rolled back, and an **account** is an optional link
  from a person ID to a subject at an identity provider that decides no
  check.

## 2. Formats

### 2.1 Device keys

A device draws an identity seed, an X-Wing seed and an ML-DSA-65 seed, each
of 32 bytes and each independently from its random source, and keeps them
sealed ([crypto.md](crypto.md), "A device's keys"; [at-rest.md](at-rest.md)).

- A device is named by its device ID ([crypto.md](crypto.md), "A device's
  keys"). Its keys never change: a device that needs new keys returns as a
  new device, with a new device ID.
- A passkey member (section 2.7) and a recovery key (section 2.6) have the
  same three key pairs, derived from a secret the person holds, and a
  device ID from them. A recovery agent has an Ed25519 key and an ML-DSA-65
  key and no X-Wing key, and its `kc` hashes an empty X-Wing key
  ([ext-recovery-agent.md](ext-recovery-agent.md)).
- A client MUST NOT offer keys derived from a passkey or a sheet as a
  device's keys, in admission or in any roster grant. Replicas cannot tell
  such keys from a device's, and a synced passkey would then administer
  spaces.

### 2.2 The person ID and the personal space

```text
person ID = the event ID of the list's first event (events.md)
```

- The first event is an `add` of a device, signed by that device. Every
  list event carries the person ID as its `log`.
- The ID names the list, not that device, and never changes, even after the
  first device is revoked. A device that signs its first event again
  restarts the same list: the ID leaves out the signature.
- The **personal space** is a space that the person's first device founds
  right after the list's first event (section 3.7). Its roster grants the
  person. A client MUST NOT grant anyone in it but the person and the
  person's own devices.
- Both IDs are the passkey's user handle (section 2.7) and are shown on the
  recovery sheet (section 2.6).

### 2.3 The device-list event

A device-list event is an event of kind 1 under scheme 2. Its author is
the signing list member's device ID, its `log` the person ID, and its body
a deterministic CBOR map:

| Key | Field | Type | Value |
|---|---|---|---|
| 0 | `version` | unsigned | `3` |
| 1 | `action` | unsigned | `0` add, `1` revoke, `2` confirm, `3` checkpoint, `4` ack (section 3.16) |
| 2 | `kind` | unsigned | `0` device, `1` recovery key, `2` passkey member, `3` recovery agent |
| 3 | `device` | bytes(32) | the device ID of the list member the event names |
| 4 | `possession` | bytes(3,373) | `add` only, required: the named keys' possession proof (section 2.5) |
| 5 | `xwing` | bytes(1,216) | `add` only: its X-Wing key; required for kinds 0 to 2, absent for an agent |
| 6 | `mldsa` | bytes(1,952) | `add` only, required: its ML-DSA-65 key |
| 7 | `identity` | bytes(32) | `add` only, required: its Ed25519 identity key |
| 8 | `follows` | array of bytes(32) | the list checkpoints the event follows: 1 to 4 event IDs, strictly ascending, as [events.md](events.md)'s cuts are, over this list's checkpoints; absent when none, and in the first event |
| 9 | `record` | bytes | `checkpoint` only, required: the list record (section 3.16) |

- An `add`'s keys 7, 6 and 5 give its key 3: the device ID of `identity`
  and of the `kc` of `mldsa` and `xwing`, `xwing` empty for an agent
  ([crypto.md](crypto.md), "A device's keys").
- A `revoke` or a `confirm` has keys 0 to 3 only, and key 8 when it follows
  a checkpoint. It names a list member by its device ID and kind.
- A `checkpoint` has keys 0, 1 and 9, and key 8 when it follows one; an
  `ack` has keys 0 and 1, and key 8. Neither names a list member.
- A device-list event carries no refs. It is at most 16,384 bytes signed,
  with at most 16 parents ([events.md](events.md), "Limits"); an `add` is
  about 10 KB.
- A verifier refuses an action or a kind it does not know as `Malformed`: it
  cannot skip the event, since later events may be signed by the list member
  it adds. A new action or kind is a new protocol.
- A list has checkpoints of its own (section 3.16); a space's checkpoints
  do not compact lists. A device-list event never carries envelope cuts
  ([events.md](events.md)): a list's checkpoints are declared in key 8.

### 2.4 Kinds of list member

| Kind | Keys from | Receives wraps | Writes | May sign |
|---|---|---|---|---|
| device | its own random seeds | yes | through the person's grants | any list event the checks allow |
| passkey member | a passkey's PRF output (section 2.7) | yes | through the person's grants | as a device, but never a `confirm`, and never a revocation of a recovery key |
| recovery key | a recovery sheet (section 2.6) | yes | nothing | as a device, but never a `confirm` |
| recovery agent | its holder's own seeds | no | nothing | only an `add` of a device, and its own `revoke` |

- A recovery key receives wraps so that a space no one else can reach
  survives a recovery by sheet.
- A **recovery agent** is a party the person names, such as a hosted
  service. This document defines its format, rank, what it may sign and the
  limit on list members rooted in it;
  [ext-recovery-agent.md](ext-recovery-agent.md) defines naming one, its
  waiting period and the relay of its entries. A core implementation that
  lacks the extension validates agent events by this document and treats a
  list member rooted in an agent as waiting until a `confirm` clears it
  (section 3.5).

### 2.5 The possession statement

The key an `add` names signs this statement under scheme 2, with its own
identity and ML-DSA-65 keys ([crypto.md](crypto.md), "Signature schemes",
with the statement as `tbs`):

```text
statement =  "frasil/device-list/possession/v3"     32 bytes
          || field(person_id)                       4 + 32
          || field(adder)                           4 + 32
          || field(u8(kind))                        4 + 1
          || field(identity)                        4 + 32
          || field(mldsa)                           4 + 1,952
          || field(xwing)                           4 + 1,216, or 4 + 0 for an agent
          || field(u8(2))                           4 + 1: the scheme

possession = the scheme-2 signature of statement by identity and mldsa   3,373 bytes
```

- `person_id` is the list's person ID, or 32 zero bytes in the list's first
  event, whose hash the person ID is. The zero value also keeps a first
  event's proof from serving a later `add`, and the reverse.
- `adder` is the device ID of the list member that signs the `add`: the
  event's author, as the list names it. In the list's first event it is the
  device's own device ID.
- `kind`, `identity`, `mldsa` and `xwing` are exactly the `add`'s body keys
  2, 7, 6 and 5. `identity` is the Ed25519 key, and the statement names
  every key the device ID commits to, so it names the device ID too.
- The statement is 3,326 bytes, or 2,110 for an agent. After the label,
  every part is length-prefixed.
- A verifier computes the statement from the list it appends to, the
  event's author and the keys the body names. It never reads one.
- **A proof is for one adder.** A list member that copies another's `add`,
  proof included, and signs it on its own chain makes an `add` whose proof
  does not verify (`BadPossession`). So no list member can add a key it was
  not given a proof for, and none can root a list member another one added
  (section 3.2). A key that two list members add, each with a proof the key
  signed for it, is added by both (section 3.4).
- **What the device ID does not bind.** The device ID commits to the keys,
  so no `add` can pair another device's Ed25519 key with keys of its own:
  that names another device ID. It does not bind the keys to a person,
  which only this proof does: without it, any list could name any device ID
  its author has seen, and that device would write through the person's
  grants and receive their wraps. A roster grant of a device carries the
  same keys and no proof ([roster.md](roster.md)), since a grant binds the
  device to a space, not to a person.

### 2.6 Recovery keys

A recovery key derives from a 32-byte secret that the device creating it
draws from its random source:

```text
prk            = HKDF-Extract("frasil/recovery/v1", secret)
identity seed  = HKDF-Expand(prk, "ed25519", 32)
X-Wing seed    = HKDF-Expand(prk, "frasil/recovery-key/hybrid/v1", 32)
ML-DSA-65 seed = HKDF-Expand(prk, "frasil/recovery-key/mldsa/v1", 32)
fetch seed     = HKDF-Expand(prk, "frasil/recovery-key/fetch/v1", 32)
```

The **recovery sheet** shows the secret in its printed form, the person ID
and the personal space ID. The IDs' layout is the application's, in hex or
in a QR code.

```text
printed = base32(secret || SHA-256(secret)[0..2])
          RFC 4648 alphabet, upper case, no padding: 55 characters,
          in groups of four joined by "-", the last group of three
```

A reader removes spaces and hyphens and maps `a`–`z` to `A`–`Z`. What
remains MUST be 55 characters of the alphabet that decode canonically to 34
bytes whose last two are the first two of SHA-256 of the first 32
(`InvalidSheet`).

### 2.7 Passkey members

A passkey member derives from the 32-byte output of a passkey's PRF
extension ([WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), "PRF
extension"), evaluated at one constant input:

```text
prf_input = SHA-256("frasil/passkey-prf-input/v2")
          = 248d03356bb53d7e0f21cb8a13079617b38d488b84c280239ac0b59478b111f9

passkey_keys(person_id, prf_output), in order:
  1. len(person_id) = 32.                                         else InvalidPersonId
  2. len(prf_output) = 32.                                        else InvalidPrfOutput
  3. prk            = HKDF-Extract("frasil/passkey-extract/v1", prf_output)
     identity seed  = HKDF-Expand(prk, "frasil/passkey-member/v1" || field("ed25519")
                                       || field(person_id), 32)
     X-Wing seed    = HKDF-Expand(prk, "frasil/passkey/hybrid/v1" || field(person_id), 32)
     ML-DSA-65 seed = HKDF-Expand(prk, "frasil/passkey/mldsa/v1" || field(person_id), 32)
     fetch seed     = HKDF-Expand(prk, "frasil/passkey/fetch/v1" || field(person_id), 32)
     unlock key     = HKDF-Expand(prk, "frasil/passkey-unlock/v1" || field("device-keys")
                                       || field(person_id), 32)
```

- The input is the same for every person, so a browser that holds nothing
  can evaluate the PRF before it knows whose passkey the platform offers.
  The person ID in every info separates persons.
- The **unlock key** seals the browser's own device keys at rest, as sealing
  key kind 1 ([at-rest.md](at-rest.md)), and nothing else.
- The **user handle** is 64 bytes, the person ID then the personal space ID:

  ```text
  user.id = person_id (32) || personal space ID (32)
  ```

  A user handle of any other length is `Malformed`. A passkey serves one
  person, because a credential has one user handle.
- A client takes the PRF output as its own type, derives every key from it
  at once, never exposes `prk`, and zeroises the output and every derived
  secret when done. No error message carries any of them.

### 2.8 Fetch keys and recovery entries

A **fetch key** is the Ed25519 key of a fetch seed. A peer serves a space's
catch-up ([peers.md](peers.md), "Presenting a credential") to a connection
that proves a fetch key registered for that space as a **recovery entry**.
A catch-up reveals no content, but its space events hold the wraps a list
member needs to open the space.

- A passkey member's and a recovery key's fetch keys derive from their
  secrets (sections 2.6 and 2.7), so a device that holds only the passkey or
  the sheet can fetch the personal space.
- A device of the person MAY also give another space that grants the
  person a recovery entry under a fetch key from a fresh random seed, kept
  in the personal space, so that a recovered device reaches that space too
  (section 3.11).

Each recovery entry is recorded in the personal space, in a unit of its
system stream of type `frasil:recovery-entry` ([units.md](units.md)), so
that every device of the person can register it at a new peer:

```text
recovery entry = CBOR map {
  0: 1                  version
  1: space ID           bytes(32)
  2: key                bytes(32): the fetch key registered at the space's peers
  3: member             bytes(32): for the personal space only, the device ID of the
                        passkey member or recovery key whose fetch seed gives key
  4: seed               bytes(32): for another space only, the random fetch seed
}
```

A reader checks, in order: it is a deterministic CBOR map (`Malformed`);
key 0 is 1 (`UnsupportedVersion`); it has keys 0 to 2 and exactly one of 3,
when key 1 is the personal space ID, or 4 otherwise, each with its length
(`Malformed`); `key` passes `ed25519_valid` (`InvalidKey`); with key 4,
`key` is the Ed25519 key of `seed` (`Malformed`). An entry whose member is not an active passkey member
or recovery key of the merged list is ignored.

### 2.9 Fingerprints

A **fingerprint** is 120 bits of a hash of a person ID and one list
member's or device's keys, written as 24 characters and a check character.

```text
digest_input = "frasil/key-fingerprint/v1" || person_id (32) || identity (32)
               || field(mldsa) || field(xwing)
digest       = SHA-256(digest_input)
value        = digest[0..15], as a big-endian 120-bit integer
d_i          = (value >> (5 · (23 − i))) & 31,        for i = 0 to 23
d_24         = check(d_0, ..., d_23)
character_i  = ALPHABET[d_i],                         for i = 0 to 24
ALPHABET     = "23456789abcdefghijkmnpqrstuvwxyz"
```

- A fingerprint is computed for **the record about to be signed**: for a
  list `add`, the list's person ID and the keys it names (`xwing` empty for
  an agent); for a roster grant of a device, 32 zero bytes and the keys it
  names.
- `identity` is the Ed25519 key. The input holds every key the device ID
  commits to, so a fingerprint stands for the device ID that the record
  names, under the person ID.
- Every key passes its check ([crypto.md](crypto.md)) first, so a list
  member has one fingerprint; a key that fails has none (`InvalidKey`). A
  person ID of another length is `InvalidPersonId`.
- `d_0` is the top five bits of digest byte 0; the 24 symbols carry exactly
  bytes 0 to 14.
- **The check symbol.** Each symbol is an element of GF(32): bits `b4 ... b0`
  are the polynomial `b4·x^4 + ... + b0`, reduced modulo `x^5 + x^2 + 1`
  (37). Addition is exclusive OR. The 25 symbols satisfy
  `d_0·x^24 + d_1·x^23 + ... + d_24 = 0`:

  ```text
  times_x(s):  t = s << 1; if t >= 32: t = t XOR 37; return t
  check(d_0, ..., d_23):
    acc = 0
    for i = 0 to 23: acc = times_x(acc) XOR d_i
    return times_x(acc)
  ```

- **Display:** five groups of five lower-case characters, joined by single
  spaces, the check character last. **QR form:** `FRASIL-FP1:` and the 25
  characters in upper case, with no separator.

```text
parse(text), in order:
  1. text has at most 128 characters, all ASCII.                  else InvalidFingerprint
  2. Strip leading and trailing space, tab, CR and LF.
  3. If the first 11 characters, compared without case, are
     "FRASIL-FP1:", remove them.
  4. No ":" remains.                                              else InvalidFingerprint
  5. Remove every space, tab, CR, LF and "-"; map A–Z to a–z.
  6. Exactly 25 characters of ALPHABET remain.                    else InvalidFingerprint
  7. d_24 = check(d_0, ..., d_23).                                else FingerprintMistyped
  8. Return the 120-bit value of d_0 to d_23.
```

No character is mapped to another. Two fingerprints are equal when their
120-bit values are equal.

### 2.10 Account links

```text
statement = "frasil/account-link/v1" || field(origin) || field(subject)
            || field(person_id) || field(nonce)
link      = CBOR map {0: 1, 1: origin (text), 2: subject (text), 3: person_id (bytes 32),
                      4: nonce (bytes 16), 5: signer (bytes 64), 6: signature (bytes 64)}
link ID   = SHA-256(statement)
unlink    = CBOR map {0: 1, 1: link ID (bytes 32), 2: signer (bytes 64), 3: signature (bytes 64)}
```

- `origin` is the identity provider's origin and `subject` its subject for
  the person: each 1 to 256 bytes of UTF-8, not only white space
  ([overview.md](overview.md), section 5.2), with no control character
  (Unicode category Cc). `nonce` is random, so a link
  signed again after an unlink is a new link.
- A link is signed under scheme 0 by an active device or passkey member of
  the person, over `statement`. An unlink is signed under scheme 0 over
  `"frasil/account-unlink/v1" || field(link ID)`.
- `signer` is the signer's `ed || kc` ([crypto.md](crypto.md), "A device's
  keys"): the Ed25519 key that signs, then the keys commitment, from which
  a checker computes the signer's device ID.
- Admission's lookups ([admission.md](admission.md)) verify links, and the
  server binding carries them ([transport.md](transport.md)).

### 2.11 Error classes

Besides those of [overview.md](overview.md), "Error classes":

| Class | Meaning | Sort |
|---|---|---|
| `BadGenesis` | a first list event that is not a device adding itself | final |
| `UntrustedSigner` | the author is not an active list member, or may not sign this; after a list checkpoint, also an author that no add of the record or the world names (section 3.16) | final |
| `AgentLimited` | an agent, or a list member rooted in one, beyond what it may do | final |
| `AlreadyListed` | an `add` naming a key already on the list, or a concurrent `add` that comes first | final |
| `NotListed` | a `revoke` or `confirm` naming no active list member of that kind | final |
| `RecoveryKeyProtected` | a rooted author revoking a recovery key other than itself | final |
| `NotPending` | a `confirm` of a list member that is not a rooted device or recovery key | final |
| `LastMember` | a revocation that leaves no active list member but agents | final |
| `Full` | more than 4,096 valid list events in an event's place, counted from the list checkpoint in effect there | final |
| `Late`, `MixedCut`, `BadCuts`, `BadCheckpoint` | as [roster.md](roster.md) and [events.md](events.md) define them, for a list checkpoint and its `follows` (section 3.16) | final |
| `CheckpointPending` | a list checkpoint made while another in its past waited for votes, or before its predecessor took effect, judged on its own past alone; the client proposes again | final |
| `RevokedConcurrently` | an event of a list member that a concurrent valid revocation names | final |
| `TargetRevokedConcurrently` | a `confirm` of a list member that a concurrent valid revocation names | final |
| `WrongPerson` | a link, list or handle for another person | final |
| `Unlinked` | a link that a valid unlink names | final |
| `InvalidPersonId`, `InvalidPrfOutput` | an input of the wrong length | decision |
| `InvalidSheet` | printed text that is not a recovery secret | decision |
| `UnstablePrf` | two PRF evaluations derived different keys | decision |
| `NotOnList` | a derived list member that is not an active list member of the merged list | decision |
| `InvalidFingerprint` | text that is not a fingerprint | decision |
| `FingerprintMistyped` | a fingerprint whose check character fails: a typing error | decision |
| `FingerprintMismatch` | keys whose fingerprint is not the one confirmed | decision |
| `RolledBack` | an offered list lacks an event the client pinned | report |
| `ForkDetected` | an offered list holds new evidence that a list member forked | report |

## 3. Procedures

### 3.1 Checking a list event alone

```text
check_alone(event), in order:
  1. events.md, "Decoding an event" and "Placement and order".     else that class
  2. The body is a deterministic CBOR map; version 3; action 0 to 4;
     for actions 0 to 2, kind 0 to 3; keys as section 2.3 for the
     action and kind, each with its length.                          else Malformed
     A checkpoint's record reads as section 3.16 says.               else Malformed /
                                                                          UnsupportedVersion
  3. The list's first event is an add of a device whose device ID
     is its author.                                                  else BadGenesis
  4. An add: identity passes ed25519_valid and, for kinds 0 to 2,
     xwing passes xwing_valid.                                       else InvalidKey
  5. An add: identity, mldsa and xwing (empty for an agent) give
     device (crypto.md, "A device's keys").                          else NotCommitted
  6. An add: possession verifies, both halves, over section 2.5's
     statement with this list's person ID (32 zero bytes in the
     first event) and the event's author as adder, under identity
     and mldsa.                                                      else BadPossession
  7. The event's signature verifies (events.md, "The ML-DSA-65
     half"), under keys that hash to its kc, wherever the replica
     found them; the first event names its own.                      else NoHybridKey / BadSignature
  8. The author's fork point in the list is above seq, or the event
     revokes its own author.                                         else Forked
```

- Step 4 runs before step 5, so a key of small order is refused before it
  is hashed or any signature by it is considered. Step 6 runs before step
  7, so an `add` changed after the named key signed, or signed by another
  author than the adder its proof names, fails as `BadPossession`.
- The keys an event's signature verifies under are those its `kc` commits
  to, so an `add` of this list or of any other, or a cache, serves alike.
  An event whose author's keys the replica does not hold is pending: the
  `add` that carries them may not have arrived.
- A space that reads a person's list may take the keys of the person's
  devices from the same `add` events, by their hash like any other
  source.

### 3.2 The state of a list at a place

The **place** of a list event is the valid list events in its past, with the
first event. At a place `V`:

- **List members.** Each device ID that an `add` of `V` names is a list
  member, with the kind of the first such `add` in canonical order, and the
  keys its device ID commits to.
  It is **revoked** when a `revoke` of `V` names it, **active** when it is
  not, and **confirmed** when a `confirm` of `V` names it.
- **Rootedness of an add.** An `add` other than the first event roots the
  list member it adds from its author's state at the `add`'s own place:
  - **in an agent**, when the author is an agent or is rooted in an agent;
  - otherwise **in a passkey**, when the added list member is a passkey
    member or the author is rooted in a passkey;
  - otherwise not.
- **Rootedness of a list member.** A list member takes the most rooted of
  its adds, an agent over a passkey over none, so rootedness fails closed.
  Then:
  - an agent is rooted in an agent;
  - a passkey member is rooted in an agent if an add rooted it there, and
    otherwise in a passkey;
  - any other list member is not rooted once it is confirmed, and otherwise
    as its adds made it.

  The agent a list member is rooted in is the author's own agent for an add
  by a list member rooted in an agent, or the author itself for an add by an
  agent, taken from the first such add in canonical order. A `confirm`
  clears only the list member it names.
- **Ranks**, 1 the highest:

  | Rank | List members |
  |---|---|
  | 1 | a recovery key that is not rooted |
  | 2 | a device that is not rooted |
  | 3 | a passkey member, and any list member rooted in a passkey |
  | 4 | an agent, and any list member rooted in an agent |

- A list member is **waiting** when it is rooted in an agent and is not an
  agent (section 3.5).

### 3.3 Checks at the event's place

With `S` the state at the event's place, in order:

```text
1. The author is an active list member of S.                         else UntrustedSigner
2. An author that is an agent signs only an add of a device, or a
   revoke of itself.                                                 else AgentLimited
3. add:     of an agent, only by a device or a recovery key that is
            not rooted;                                              else UntrustedSigner
            no list member of S, active or revoked, has its device
            ID, or its Ed25519, X-Wing or ML-DSA-65 key.             else AlreadyListed
4. confirm: the author is a device that is not rooted.               else UntrustedSigner
5. revoke, confirm: the named list member is an active list member of S of
   that kind.                                                        else NotListed
6. revoke:  a rooted author revokes a recovery key only when it
            revokes itself;                                          else RecoveryKeyProtected
            an author rooted in an agent, other than an agent,
            revokes only list members rooted in the same agent;      else AgentLimited
            some active list member of S other than the named one is
            not an agent.                                            else LastMember
7. confirm: the named list member is a device or a recovery key, and is
            rooted.                                                  else NotPending
8. At most 4,096 valid list events are in its place, itself
   included.                                                         else Full
```

- In step 6 an agent does not count toward `LastMember`, so a list never
  passes to an agent by a revocation. The agent's limit ends only with a
  `confirm`, never with time.
- Step 8 counts only valid events, so keys with no authority fill nothing.
  It applies to self-revocations too.

### 3.4 The merge

A list is resolved by [roster.md](roster.md)'s "The resolution procedure",
with the contested events, authority, attacks, mutual pairs and pick that
this section gives. The **contested** events are the list events other than
the first that pass section 3.1. An event's authority is section 3.3.

**Attacks.** A valid list event `x` attacks a list event `e` when they are
concurrent and:

- `x` revokes `e`'s author, and `e` is not a self-revocation
  (`RevokedConcurrently`): a revocation voids the revoked list member's
  concurrent actions;
- `x` revokes the list member that `e` confirms
  (`TargetRevokedConcurrently`); or
- both are adds that name one Ed25519, X-Wing or ML-DSA-65 key without
  naming the same device ID and kind, and `x` comes first in canonical
  order (`AlreadyListed`). Two adds that name one device ID and kind both
  stand and describe one list member. Each proof names its own adder
  (section 2.5), so such adds have different authors, and the named key
  signed a proof for each of them.

**Mutual pairs, by rank.** `x` and `e` are a mutual pair when both revoke,
their authors differ, and each names the other's author. Then `x`'s attack
on `e` does not count when `e`'s author ranks at least as high as `x`'s,
each rank taken at its own event's place. Within a rank both revocations
stand and both list members are revoked; across ranks the higher rank's
stands.

**The pick.** When a set of events waits only on itself, the pick takes the
smallest `(rank of its author at its place, seniority of its author, height,
event ID)`. A list member's seniority is the smallest, over its valid adds
in the place, of:

```text
( height(add), SHA-256("frasil/device-list/seniority/v1" || person ID || device ID), add's ID )
```

The hash covers only the person ID and the added device ID, which no signer
chooses; a signer can only raise an add's height.

**Self-revocations.** A `revoke` that names its own author is never attacked
and survives its author's fork ([events.md](events.md), "The penalty"), so
that no duel or fork undoes a list member's own revocation.

**The merged list** is the first event and the valid contested events. Its
state is section 3.2's over all of them. A list member that forked is not
active in it from its fork point on.

**A dead list.** Concurrent revocations can leave no active list member: a
mutual pair within a rank between the only two list members, or a cycle of
three. The list is then **dead**: no list member can sign, nothing vouches
for any key, and the person returns by social recovery (section 3.11). A
list whose person keeps a recovery key, a list member of a higher rank or
any list member outside the duel never dies this way. Restoring either list
member would hand a thief who stole an older device the list.

Two recovery keys that revoke each other are one rank, so both are revoked
and a stolen old sheet never wins; replacing a recovery key never makes
them duel (section 3.10).

### 3.5 What a list vouches for

- **Recipients.** Under a person grant ([roster.md](roster.md)), a writer
  wraps a space's keys for each active list member of the person's merged
  list that is a device, a passkey member or a recovery key, has not forked,
  and is not waiting. An agent receives nothing.
- **Writers.** A device or a passkey member that a valid `add` of the merged
  list names writes through the person's grants. Its revocation, or its
  fork, ends that path in a space once a writer of the space responds; the
  end of a fork is the canonically later event of the evidence that fixes
  its fork point ([roster.md](roster.md), "Checks across logs"). A recovery
  key and an agent never write.
- **Waiting list members.** A waiting list member is no recipient and is not
  vouched for. It writes units through the person's grants but makes no key
  event there (`WaitingDevice`, [roster.md](roster.md)). A verifier never
  refuses its events for waiting: whether its `add` is valid is the merge's
  question. In core protocol 1 a list member waits until a `confirm` clears
  it; [ext-recovery-agent.md](ext-recovery-agent.md) adds the waiting period
  after which a verifier vouches for it.
- **Passkeys.** A list member rooted in a passkey is vouched for while it is
  active.
- **Agents forbidden.** A space whose policy forbids agents
  ([roster.md](roster.md), "The space policy") wraps nothing for the devices
  of a person whose merged list holds an active agent, and a client does
  not grant such a person there.

### 3.6 Sealed list copies

- A list event is never stored or synced bare. It travels as the content of
  a `frasil:list` unit in a space's system stream ([units.md](units.md),
  "Frasil's own units"), in the personal space and in every space that
  grants or granted the person, so a peer never sees a kind-1 envelope.
- A device of the person that writes in a space publishes the list's events
  there when it learns of the person's grant, and each new one afterwards; a
  device granted only `read` hands them to a writer by [units.md](units.md)'s
  `ListEvents` message on a member connection or a `frasil/list-events`
  device-mailbox item ([transport.md](transport.md)). Any member that holds a
  newer list event of a person the space grants forwards it.
- A replica accepts list events of every person its roster names, now or
  before, checks them by sections 3.1 and 3.3 and merges them by section
  3.4, whatever path they came by. A space keeps the lists of former
  members, so that the writers it accepted stay checkable.
- A list event counts for a space event's paths only from its copies in
  that space: it is at the place of the copy and of every event after it
  ([roster.md](roster.md), section 3.11, "A list at an event's place"). One
  a replica holds by another path, or only in the past of a later event
  that was copied, is merged, and gives no path until a copy carries it
  itself, or, for an `add`, until a copy carries a list checkpoint whose
  record names it. So a device's client publishes the copy of its own
  `add` in a space, or holds one, before it signs its first event there
  through the person: the copy may be that event itself, or in its past.
- A space snapshot for a member admitted from now on carries every event of
  the list of every person the roster names, now or before
  ([admission.md](admission.md)), since that member cannot open earlier
  copies.

### 3.7 Making a person

1. A device draws its keys and signs the list's first event: an `add` of
   itself, kind device, with its possession proof over 32 zero bytes. That
   event's ID is the person ID.
2. It founds the person's personal space ([roster.md](roster.md)), whose
   roster grants the person, and publishes the first event there.
3. Only then does it add a recovery key or a passkey member (section 3.8),
   whose sheet and user handle carry both IDs.

### 3.8 Adding list members

**A device** joins through an admission code ([admission.md](admission.md)).
Its possession proof, which names the approver as adder, travels in the
exchange, and the approver checks it by section 3.1, steps 4 to 6, with
itself as author, before it signs the `add`.

**A passkey member** is added only after two evaluations of the PRF derive
the same keys: a registration that returns an output and one assertion, or
two assertions, each with user verification. A client offers no operation
that adds a passkey member from one output.

```text
add_passkey_member(person_id, output_1, output_2, signer), in order:
  1. m1 = passkey_keys(person_id, output_1); m2 = passkey_keys(person_id, output_2).
  2. m1 and m2 have the same identity, X-Wing and ML-DSA-65 keys.
     Otherwise zeroise both outputs and every derived secret.      else UnstablePrf
  3. No list member of the signer's merged list has any of m1's
     keys.                                                        else AlreadyListed
  4. m1 signs its possession proof over section 2.5's statement, with
     kind passkey member and the signer as adder.
  5. The signer, an active list member, signs the add (section 2.3) on its
     own chain in the list.
  6. Zeroise both outputs and m2.
```

Step 4 is the only use of a derived key before the merged list holds the
list member. The proof has no effect unless an active list member signs the
`add`.

**A recovery key.** A device of the person draws the secret, derives the
keys (section 2.6), has them sign their possession proof with the device as
adder, signs the `add`, shows the sheet, and then forgets the secret.

**After adding a passkey member or a recovery key**, the device that added
it, while it still holds the secret, publishes the `add` in the personal
space, delivers the personal space's current keys to the new list member
([keys.md](keys.md)), writes the list member's recovery entry (section 2.8),
and registers its fetch key at every peer that holds the personal space
([peers.md](peers.md)). A device of the person that starts using another
peer for the personal space registers there every recovery entry whose list
member is active. A revoked list member's entry ends at a peer when the
personal space's administrators leave it out of a credentials request.

**Who signs each possession proof,** and the adder it names, which the key
knows before it signs:

| Member | Signs its proof | Adder | When | Reaches the approver by |
|---|---|---|---|---|
| The first device | the device, over 32 zero bytes | itself | when it makes the person | itself |
| A device added by another list member | the new device | the approver | during admission, once the Response names the person ID and the approver | the admission exchange |
| A device added by a passkey member | the browser's device keys | the passkey member | after the assertion returns the user handle | locally |
| A device added by a recovery key | the new device | the recovery key | when the sheet is typed on it | locally |
| A device added by an agent | the new device | the agent | when the agent helps it ([ext-recovery-agent.md](ext-recovery-agent.md)) | from the device |
| A passkey member | its derived keys | the list member that enrols it | after two evaluations agree | locally |
| A recovery key | its derived keys | the device that creates it | while its creator holds the secret | locally |
| A recovery agent | the agent's keys | the naming list member | when the person names it | from the agent ([ext-recovery-agent.md](ext-recovery-agent.md)) |

A proof binds no position in the list and does not expire, but it serves
only the adder it names: that list member may add the key later, and no
other may. A key is added at most once to a list, even after it is revoked
(`AlreadyListed`), so a proof is used at most once. An adder that signs the
`add` twice either has the first in the second's past (`AlreadyListed`) or
forks its chain (`Forked`).

### 3.9 Using a passkey member

```text
use_passkey_member(user_handle, output), in order:
  1. len(user_handle) = 64.                                         else Malformed
     person_id = user_handle[0..32]; space = user_handle[32..64].
     A client that already holds the person's list checks that
     person_id is its own.                                           else WrongPerson
  2. m = passkey_keys(person_id, output).
  3. A client that does not hold the personal space fetches it with
     m (section 3.11). It verifies and merges the list, and checks
     its pin (section 3.14).
  4. The merged list's person ID is person_id, and m's keys are an
     active passkey member of it. Otherwise zeroise m.               else NotOnList
  5. m signs list events under scheme 2, or opens wraps with its
     X-Wing seed.
```

`NotOnList` covers an output that changed, a revoked list member, a handle
for another person or space, and a list a peer withheld events of.

### 3.10 Rotating a passkey and replacing a recovery key

- **Rotating a passkey** is two events: an `add` of the new list member
  (section 3.8), then a `revoke` of the old one. Each space that grants the
  person responds to the revocation by rotating, as for a revoked device.
  The old keys never return to the list (`AlreadyListed`).
- **Revocation does not cascade.** Revoking a passkey member leaves the list
  members it brought in active and rooted. An application that revokes a
  passkey member MUST show the person the members rooted in a passkey, so
  that the person can revoke them too.
- **Replacing a recovery key.** The old key signs an `add` of the new one,
  then a `revoke` of itself. A self-revocation is never attacked, so the two
  keys never duel. A device that is not rooted may also add a new recovery
  key and revoke the old. A passkey member or a rooted device may add a
  recovery key, which is then rooted, but MUST NOT revoke the old one
  (`RecoveryKeyProtected`).
- **A list revocation leaves direct grants.** A device revoked from the list
  keeps any grant a roster gave it directly, `administer` included, since
  administer never comes from a list. A client that revokes such a device
  SHOULD offer its removal from each roster that grants it, in the same
  step.

### 3.11 Recovery

A person who has lost every device has four routes:

- **The recovery key** signs a new device into the list. The device is not
  rooted, so it can confirm.
- **A passkey**, synced by its provider, derives the passkey member
  (section 3.9), which signs a new device in, rooted in a passkey.
- **A recovery agent** signs a new device in, rooted in the agent
  ([ext-recovery-agent.md](ext-recovery-agent.md)).
- **Social recovery** makes a new person. In each space an administrator
  compares an admission code with the new person and signs a `replace`
  ([roster.md](roster.md)), which also takes away the old person's
  administering devices.

An account's server can help a person find their spaces; only these routes
let them rejoin.

**Fetching the personal space with a fetch key.** A device that holds only a
passkey or a recovery sheet knows the person ID and the personal space ID,
and derives the list member `M` and its fetch key:

```text
recover(M, person ID, personal space ID), in order:
  1. Connect to a peer that holds the personal space, as the application
     names, and present M's fetch key for the space (peers.md). The peer
     serves its catch-up.                                            else the peer's refusal
  2. Place and verify what it serves (events.md). Open the deliveries
     that hold wraps for M with M's X-Wing seed (keys.md), derive the
     current state's keys and read credential, and fetch the space
     with the read credential.
  3. Open the space's list copies, then verify and merge the list
     (sections 3.1 to 3.4).
  4. M is an active list member of the merged list, of its kind, with its
     keys.                                                           else NotOnList
  5. The device draws its own keys, and M signs the device's add with
     the device's possession proof over the person ID, with M as
     adder.
  6. The device publishes the new list events in the personal space.
```

**Other spaces.** For each recovery entry of another space in the personal
space (section 2.8), the device presents the entry's fetch key at that
space's peer, opens the wraps for `M` there in the same way, and publishes
the new list events in the space. In a space with no recovery entry, the
person's new device is reached once a member of the space receives the new
list events by any path, publishes them there and sends the device a welcome
([admission.md](admission.md)).

### 3.12 Comparing fingerprints

Admitting a device rests on the admission code
([admission.md](admission.md)). A fingerprint serves a person who wants to
see the keys themselves, and any step without a commitment.

```text
the device whose keys are shown, told which record is being made:
  1. Show the fingerprint of that record's variant (section 2.9) of its
     own keys, and its QR form.

the device that will sign the record, in order:
  2. Take the keys it would sign from the message that carries them, and
     check them (crypto.md).                                         else InvalidKey
  3. Show the fingerprint of the variant of the record it will sign.
  4. Take the value the person confirms: the two screens match, the QR
     code scanned, or the fingerprint typed, parsed by section 2.9.
     On FingerprintMistyped, ask again; nothing has been compared.
  5. Recompute the fingerprint of exactly the keys it is about to sign.
  6. It equals the confirmed value. Otherwise sign nothing.          else FingerprintMismatch
  7. Sign the record naming exactly those keys.
```

- Step 5 keeps a relay from offering one set of keys while the person
  compares and another when the device signs.
- Both sides MUST use the variant of the same record. A client MUST NOT show
  a fingerprint of anything but the exact keys it would sign, and MUST NOT
  report a check failure as a mismatch or the reverse. A person compares all
  25 characters, scans, or types what the other screen shows, never a value
  read aloud.

### 3.13 Checking an account link

```text
check_link(link, list, unlinks), in order:
  1. The link is section 2.10's map, deterministic, with exactly its keys,
     version 1, and its types, lengths and texts.                     else Malformed
  2. signer's Ed25519 key passes ed25519_valid.                       else InvalidKey
  3. The signature verifies strictly over the statement, under
     signer's Ed25519 key.                                            else BadSignature
  4. person_id is the list's person ID.                               else WrongPerson
  5. signer's device ID is an active device or passkey member of the
     merged list.                                                     else UntrustedSigner
  6. No unlink held names the link ID, with a signature that verifies
     strictly by a device or passkey member that a valid add of the
     list ever named.                                                 else Unlinked
```

A link lapses when its signer is revoked; the person signs a new one from
another device. A revocation does not undo its signer's unlinks.

An account's server stores links after the provider's sign-in, answers
lookups by subject with them, and MAY keep the person's sealed directory of
spaces and a mailbox. It holds no list, so it checks only a link's shape and
signature, and it never adds or revokes a list member, appears in a roster,
or decides a check. A grant made from a lookup is shown as unverified until
a code is compared ([admission.md](admission.md)).

### 3.14 Pins

A **pin** is the set of a list's events that a client has verified and
applied. It only grows. When a peer offers a state of the list:

- if the state lacks a pinned event, the client keeps its own events and
  reports `RolledBack`: the peer withholds or rolls back;
- otherwise, if it holds new evidence of a fork, the client merges it as
  usual and reports `ForkDetected` with the evidence: a list member of the
  person equivocated, and the person can revoke it;
- otherwise the state **advances**.

### 3.15 The passkey ceremony

Frasil never sees the WebAuthn ceremony, so it cannot check these; an
application that uses passkey members MUST:

1. evaluate the PRF with user verification required, at registration and at
   every assertion;
2. request the PRF extension at registration;
3. pass `prf_input` as `prf.eval.first` and never pass `second`, and derive
   with the person ID the passkey was registered for: the first 32 bytes of
   the user handle, or the ID of the list it already holds, which MUST be
   equal;
4. register the passkey as a discoverable credential (`residentKey:
   "required"`) whose `user.id` is section 2.7's user handle, so that a new
   browser finds it with an empty `allowCredentials` and needs no hint;
5. keep the output and everything derived from it on the client, and strip
   `results` from any credential it sends to a server;
6. treat a missing output as "this passkey cannot be used", with no other
   derivation.

### 3.16 List checkpoints

A person's list is a log like a space's, with its own 4,096 bound. A **list
checkpoint** fixes the list at its past so that every holder of the list,
the person's devices and every space that reads it, may forget what came
before. It follows [roster.md](roster.md)'s "Checkpoints" rule for rule,
read for a list as follows.

**The event.** A list event with action 3. Its `record` (key 9) is a
deterministic CBOR map:

| Key | Field | Value |
|---|---|---|
| 1 | `version` | 1 |
| 2 | `epoch` | as a space checkpoint's |
| 3 | `previous` | bytes(32): the list checkpoint in effect in its past; present exactly when `epoch` > 1 |
| 4 | `members` | array, strictly ascending by device ID, one per active list member of its past: a member entry |
| 5 | `tips` | `[device, seq, event ID]` for each active member that signed in its past, strictly ascending |
| 6 | `forks` | `[device, seq]` for each author forked there, strictly ascending |
| 7 | `heard` | `[add, seniority]` for each device the checkpoint hears (below), `add` the event ID of its earliest valid `add` there and `seniority` as a member entry's, strictly ascending by `add`; present exactly when there are some |

A **member entry** is the array `[add, root, agent, confirmed, seniority,
rooting]`:

- `add`, bytes(32): the event ID of the member's earliest valid `add`
  there, in canonical order;
- `root`: the rootedness its adds gave it (section 3.2), before any
  `confirm`: 0 none, 1 passkey, 2 agent;
- `agent`: the device ID of the agent it is rooted in (section 3.2),
  present exactly when `root` is 2, otherwise empty bytes;
- `confirmed`: 1 when a valid `confirm` there names it, else 0;
- `seniority`: `[epoch, height, add]` of its most senior add (section 3.4);
- `rooting`, bytes(32): the event ID of the first valid `add` there, in
  canonical order, that rooted it in an agent; present exactly when `root`
  is 2, otherwise empty bytes. A verifier counts the waiting period of
  [ext-recovery-agent.md](ext-recovery-agent.md) from its first sight of
  that add, and the veto traces through its author.

A member's keys and kind are those of the `add` its entry names, which every
holder keeps (below).

**Reading a record,** in order: deterministic CBOR, a map with an unsigned
key 1 (`Malformed`); key 1 is 1 (`UnsupportedVersion`); exactly the keys
above with their types and orders, `previous` present exactly when `epoch`
is above 1, `heard` absent or not empty, each member entry of six elements with `agent` and `rooting` as
above (`Malformed`). Section 3.1, step 2, reads the record so; a checkpoint
whose record fails is void with that class.

**Size.** A list event is at most 16,384 bytes signed, and a checkpoint's
envelope, signature, 16 parents and 4 `follows` take about 4.2 KB of them.
A member entry with its tip takes at most about 165 bytes, and about 200
for a member rooted in an agent. A record therefore holds at least 70
active members none of which is rooted in an agent, and at least 51 when
every one is, every number at its widest. A client whose record would not
fit proposes no checkpoint.

- **Following.** Key 8 declares the list checkpoints an event follows,
  checked against its parents' as [events.md](events.md), "Cuts", checks
  envelope cuts, with this list's checkpoints for a space's (`BadCuts`). A
  parent the holder forgot (below) is in its kept checkpoint's past, so all
  it could contribute is at or before that checkpoint, which another parent
  already reaches; it contributes nothing, and the check of an event whose
  `prev` was forgotten does not wait for it.
- **Who signs.** An active device or recovery key of the checkpoint's past
  that is not rooted. A `confirm` clears a device's rootedness (section
  3.2), so a confirmed device signs one, and is waited for (below).
- **Validity,** judged on the checkpoint's past alone, in order:

  ```text
  1. Section 3.1, steps 1 to 6, its record read as above, and its
     follows.                                                        else that class / BadCuts
  2. Without a predecessor (epoch 1): no list checkpoint its follows
     reach is valid.                                                 else BadCheckpoint
     With a predecessor p: p is a list checkpoint its follows
     reach, and every one they reach is at or before p, or after p;  else BadCheckpoint
     none they reach after p is valid;                               else CheckpointPending
     p is valid;                                                     else BadCheckpoint
     p is in effect in the view of p and the events after p in its
     past, and that view holds no other valid list checkpoint.       else CheckpointPending
  3. Its signature verifies (events.md, "The ML-DSA-65 half") under
     the keys of the adds of its past: with p, those p's record names
     and the adds after p; without, every add of its past. An author
     no such add names is no list member there.                      else BadSignature /
                                                                          UntrustedSigner
  4. Its author's fork point there is above its seq.                 else Forked
  5. Its author is an active device or recovery key there that is
     not rooted.                                                     else UntrustedSigner
  6. Its record equals, byte for byte, the record of its past.       else BadCheckpoint
  ```

  Its past is, without a predecessor, its causal past, and with `p`, `p`
  and the events after `p` that it reaches through events after `p`. Every
  class is final: each reads only that past. It is never attacked and
  attacks nothing. Step 2's first rule reads only the checkpoints its
  `follows` reach, so a holder that forgot decides it from its kept
  checkpoint, which every event it holds follows and which is valid.
- **Effect.** A device **votes** by any list event of it after the
  checkpoint that is judged (not held), whose signature verifies, whose
  `follows` are correct and reach no list checkpoint concurrent with it; a
  device with nothing to sign signs an `ack`, a list event that changes
  nothing, valid when its author is active at its place. A list member
  **outranks** another at a place when its rank there is higher (section
  3.4), or the same and its seniority the smaller tuple. A device is
  **heard** by the checkpoint when a valid `revoke` of its window (its past
  after its predecessor, or its whole past) names it while it is a device
  that is not rooted, or confirmed, at that `revoke`'s place; the record
  does not list it; and no such `revoke` was signed by itself or by a
  member that outranks it there. The record lists heard devices (key 7),
  by the add that gives their keys, which every holder keeps. The
  **electorate** is every device of the record that is not rooted, a
  confirmed one included (`root` 0, or `confirmed` 1), and every device it
  hears, but those **excused**: a device with evidence of its fork in the
  checkpoint's world; a device that revokes itself after the checkpoint
  (a heard device's signature checked under its add); and a device that a
  `revoke` after the checkpoint names, signed by a device or recovery key
  of the record that may sign a checkpoint and that outranks it, when that
  `revoke` counts as its author's vote. A recovery key outranks every
  device, so the person's recovery sheet excuses any device. A heard
  device votes as any device does, its signature checked under its add.
  The checkpoint takes effect once every member of the electorate voted,
  and checkpoints chain as a space's do. Recovery keys, passkey members,
  agents and members rooted in them that no `confirm` cleared are not
  waited for.

  A `revoke` excuses its target whatever its verdict. Votes and evidence
  only accumulate, so the electorate only shrinks and effect only grows as
  events arrive: were a device excused only while it stayed revoked, a
  `revoke` that a later merge voids (its author's fork arriving, or a
  concurrent revocation of its author) would bring its target back, and a
  checkpoint a holder had forgotten under would leave effect. A device
  added after the checkpoint excuses no one; to drop a lost device that the
  record names, a device of the record that outranks it, or a recovery
  key, revokes it. A device excuses nobody it does not outrank, the
  checkpoint's author included: else a stolen device could sign a
  checkpoint on a view before its revocation, revoke every other device
  before or after it, and take effect on its own vote, its revocation then
  late. With this rule every device it revoked that outranks it is heard
  and waits, so a revoked device junior to another gains nothing, and two
  colluding junior devices neither. A stolen device that outranks every
  device it revokes, the person's first device for instance, is not
  stopped: as for a space (roster.md, section 4, "A backdated
  checkpoint"), the most senior device is worth the whole list. A person
  revokes it with a recovery key, which outranks it; the list checkpoints
  that revoked it by a junior device wait for that recovery key.

  Two concurrent list checkpoints that are both stable need electorates
  with no device in common, so the person's most senior device that is not
  rooted forked, or a recovery key excused it from one of them. As for a
  space ([roster.md](roster.md), section 3.15.4), the one with the smaller
  ID takes effect at every holder that holds both, a holder's chain moves
  only to a smaller ID, and a holder that holds every event has settled.
  The list events after the one that loses, other than those after the
  winner, become late.
- **Late and mixed.** With a list checkpoint in effect, every list event
  neither in its past nor after it is void (`Late`), and an event after it
  with a parent other than its `prev` that is neither the checkpoint nor
  after it is void (`MixedCut`). A client re-signs each of its late
  revocations after the checkpoint, and lists its late adds and confirms
  for the person to decide.
- **The world after it** is section 3.4's merge over a log whose root is the
  checkpoint and whose events are those after it, each linked only to its
  parents among them: each record member is a list member from the start,
  with its `add`'s keys and kind, its root, agent, confirmation, seniority
  and rooting add; the root's height is 0, and an event's is one more than
  the greatest height among its parents in the world (a `prev` outside it,
  late or before the checkpoint, does not count); an author's events at or
  below its tip, or after its recorded fork point, are forked there; the
  4,096 bound counts the checkpoint and the valid events after it.
- **Keys in the world.** An event after a list checkpoint is checked (section
  3.1, step 7) under the keys of the adds the record names and of the adds
  after it, and no others, so that a holder that forgot and one that did
  not use the same keys. An event whose author none of them names is
  `UntrustedSigner`, final: its author is a list member at no place of the
  world.
- **Forgetting.** With a list checkpoint in effect, a holder of the list
  may forget every list event in its past. It keeps, as events alone, which
  it never judges: the list's first event (the person ID is its hash); the
  `add` and the `rooting` add each member entry of its record names, and
  the `add` each heard device's entry names; the list checkpoints the kept
  checkpoint's `follows` reach, so that it orders
  any checkpoint an event reaches; and every late event, so that it reads
  the `follows` of a late `prev` and the checkpoints they reach. It keeps
  the kept checkpoint and every event after it, and the ID of every list
  event it forgot. It never asks for what it forgot, and judges only from
  what it keeps.
- **A rival** of the kept checkpoint is roster.md's (section 3.15.6), read
  for a list: a list checkpoint concurrent with it that names its
  predecessor or one its `follows` reach, or none, with an ID smaller than
  a checkpoint of its chain it could replace, that passes section 3.1 and
  is stable in what the holder holds after it, its votes checked under the
  keys of the adds its record names and of the adds after it. While the
  holder lacks one of those adds, or otherwise cannot work out its
  stability from what it holds, it treats the checkpoint as a rival. While
  it holds a rival, it holds pending its kept checkpoint and every list
  event it judges, and settles once a
  sealed copy of the rival's chain (which carries the adds its record
  names, below) or the rival's past lets it judge. Any other list
  checkpoint concurrent with the kept one is late, as at a holder that
  kept everything.
- **Clients.** A device follows the latest valid list checkpoint of its view
  whose chain it is on: the one in effect, or a valid one waiting for votes
  whose predecessor is the one in effect, the one its own events already
  follow first, else the smallest ID. It cites none of the events
  concurrent with it, so that its events are after it and none is
  `MixedCut`. A device never writes a list event that follows a list
  checkpoint not in effect in its view that hears it, or while its view
  holds a valid `revoke` concurrent with that checkpoint, signed by a member
  that outranks its target, that names the checkpoint's author or a device
  its record keeps; it tells the person that the checkpoint is contested,
  as roster.md, section 3.15.7, says for a space, until the checkpoint
  takes effect without it, the person has it revoke itself, or that
  `revoke` is void in its view. A device proposes a checkpoint when the valid list events
  since the last list checkpoint in effect (or since the first event) reach
  1,024, and only when no list checkpoint waits for votes in its view and
  the record fits; it MAY propose more often. It votes promptly by an `ack`
  if it has nothing else to sign.
- **Spaces.** A space reads the list as it holds it ([roster.md](roster.md),
  "Checks across logs"); with the list's checkpoint in effect, a device the
  checkpoint does not list has no path through the person, at once
  ([roster.md](roster.md), section 3.15.8). Once the checkpoint is in
  effect, an `add` in its past names a device only if the record lists
  it, at a holder that kept the whole list as at one that forgot it: a
  device it does not list loses its path for its events before the
  checkpoint as for those after it, its units are `Dropped`, and a key
  event of it whose keys the space's replica no longer holds is
  `NoHybridKey`, held and never judged (roster.md, section 3.15.8, "What
  an unlisted device loses"). A sealed list copy (section 3.6) of a list
  with a checkpoint in effect carries the list's first event, the
  checkpoint, the adds and rooting adds it names (a heard device's add
  too), the checkpoints its
  `follows` reach, the late events its holder kept, the events after the
  checkpoint, and the IDs of the list events its holder forgot: a newcomer
  that starts from the copy cannot ask a peer for a list event, since list
  events travel only inside sealed copies, so it learns from those IDs
  which parent is forgotten (it contributes nothing to `follows`, and makes
  an event after the checkpoint that cites it other than as `prev`
  `MixedCut`) rather than not yet received. The IDs cost 32 bytes per
  forgotten event. A newcomer's or
  a space's first sight of a rooting add is when it receives that add, so
  the waiting period never starts earlier for a holder that never saw the
  list before the checkpoint.
- **Pins** (section 3.14) of a list that forgot keep the checkpoint and what
  follows; a list that offers less than a pinned checkpoint and its
  successors is `RolledBack`.

## 4. Security considerations

- **A stolen device.** A thief holding an older device of the same rank can
  backdate a revocation of the person's device. Both are revoked, so the
  thief keeps nothing, and the person keeps the recovery key and any list
  member of a higher rank; a person with neither, whose only two devices
  duel, recovers socially.
- **A stolen or synced passkey.** Whoever restores a passkey holds the list
  member: it reads every space the person's grants reach and can add and
  revoke devices and passkey members. It cannot revoke a recovery key, nor
  can any list member it brings in until confirmed, and a device that is not
  rooted wins a duel against it, so the holder of the sheet or of such a
  device can always revoke it and everything it added. Nothing rooted in a
  passkey administers, as long as clients keep section 2.1's rule.
- **Rootedness fails closed.** Concurrent adds give the most rooted value,
  and a `confirm` concurrent with its author's revocation is void. Since a
  proof names its adder, only a list member the key chose can add it, so
  this takes the most rooted of the adders the key chose, never one another
  list member imposed.
- **The forged-list attack.** Members of shared spaces learn other persons'
  public keys. A list that names one fails at every verifier, because the
  proof binds the person ID its holder chose: a copied proof is over
  another person ID, and a list a peer starts has another person ID.
  Forging a proof means forging both Ed25519 and ML-DSA-65.
- **What a proof binds.** Every key the list will trust, the list member's
  kind and its adder, so no approver or server can change the kind, and no
  other list member can sign the `add` again. Pairing a device's Ed25519
  key with keys of one's own needs no proof to fail: those keys give
  another device ID, which the device never signs as, and which a proof
  must still bind to this person. Without the adder, a recovery agent, a
  device rooted in one or a passkey holder could copy the `add` of a device
  or recovery key added after it was named onto its own chain,
  concurrently, so that both stood and the list member took the most
  rooted of them: it would wait or rank lowest, lose its veto and its
  `confirm`, and be revocable by the agent's devices. The adder is named by its device ID, as the list names
  every list member. A proof does not bind the `add`'s place on the adder's
  chain, which the new key does not know when it signs and which a key
  added once needs no more than the adder; nor whether the list member will
  be rooted, which follows from the adder's state at the `add`'s place. It
  does not prove possession of the X-Wing private key, whose wraps open only
  for its holder, nor that a key belongs to one person: each list is checked
  alone.
- **Derivations.** Each secret is extracted once and each key expanded under
  its own info, so the keys are independent (RFC 5869). Distinct salts, and
  the person ID in every passkey info, give unrelated keys for each use and
  each person. An unstable PRF output is caught before a list member is
  added; a later change derives keys no list names (`NotOnList`).
- **Fingerprints.** A relay must find keys whose digest shares 120 bits
  with the genuine keys': about 2^120 trials, or 2^90 per success against
  2^30 targets at once, landing on a target it did not choose. Collisions,
  about 2^60, help only the holder of both key pairs. Six digits would fall
  in about 10^6 trials, which is why the admission code commits to keys
  first. The check character adds no security; it catches every wrong
  character and every exchange of two different characters.
- **Recovery entries.** A peer learns how many recovery entries a space has
  and when one is presented. A fetch key is unlinkable to the list member's
  keys and device ID and to other spaces, and a catch-up serves no more than a
  retired read credential. A writer, even a removed one, can add entries but
  cannot remove one, so it cannot stop a recovery ([peers.md](peers.md)).
- **An account's server** can answer a lookup with a person of its choosing;
  the grant stays unverified until a code is compared.
- **Equivocation.** A list member that signs two list histories is void from
  its fork point; its self-revocation stands. Evidence needs both halves of
  scheme 2 under the keys the list member's device ID commits to, so nobody
  is framed, even by an adversary that forges Ed25519
  ([events.md](events.md), "Chains and evidence of a fork").
- **A list cannot lend a key to another device.** A list that names
  another person's device's Ed25519 key beside an ML-DSA-65 key of its own
  names a device ID of its own: no space takes that key for the device, and
  nothing signed under it is the device's. A space reads the lists of
  persons it names, and from them takes keys only by their hash
  ([crypto.md](crypto.md), "A device's keys").

## 5. Test vectors

[identity.json](vectors/identity.json), from `reference/identity.py` with
`reference/events.py` and `reference/generate.py`. Device seeds are
[crypto.md](crypto.md)'s fixtures.

- `persons`: two persons' first events, person IDs, personal space IDs and
  their first devices' `kc` and device IDs.
- `passkey_derivations`: four PRF outputs (two passkeys of one person, one
  output under another person, all zeros), each with the user handle, the
  PRF input, the WebAuthn salt (informative), the PRK, every info, seed and
  public key, the device ID, the fetch key and the unlock key.
  `passkey_refusals`: person
  IDs of 31, 33 and 0 bytes; outputs of 31 and 33 bytes.
- `recovery_keys`: a sheet's secret, its printed form, every seed and public
  key, the device ID, the fetch key, and the unrelated keys the same bytes
  give as a PRF output.
- `recovery_entries`: an entry of the personal space and one of another
  space; refused entries with both member and seed, with neither, with a
  seed that does not give the key, and with a key of small order.
- `possession`: one `add` per case of section 3.8's table that a list holds,
  with body, signed bytes, ID, statement, proof and keys, and one statement
  field by field. `possession_refusals`: proofs for another person, over 32
  zero bytes after the first event, for another kind, for another adder,
  naming another ML-DSA-65 or X-Wing key, leaving out the X-Wing key, saying
  scheme 0, by the approver, by a stranger, an unreduced `S`, a small-order
  `R`, and a changed ML-DSA-65 bit (`BadPossession`); an Ed25519 half alone
  (`Malformed`); a key of small order (`InvalidKey`); an `add` whose keys do
  not give its key 3, and one that pairs another device's Ed25519 key with
  the adder's own ML-DSA-65 key under that device's device ID
  (`NotCommitted`).
  `forged_list`: one person's keys added to another's list with their own
  proofs; and another person's device's Ed25519 key added with an
  ML-DSA-65 key and an X-Wing key of the forger's own, which is valid in the
  forger's list and names a device ID of its own, with an event that key
  set signs, whose author is that device ID and never the other person's
  device.
- `list` and `passkey_list`: a list with every kind and action, and
  seventeen events through every rule for passkey members and recovery keys;
  each event with body, signed bytes and ID, then every event's status and
  every list member's kind, activity, rootedness and rank. `list` also
  gives section 3.5's recipients, and those under a policy that forbids
  agents: none, since the list holds an active agent.
- `list_refusals`: events on a base list, each with its class: shapes;
  unknown kind and action; an X-Wing key that fails; bad proofs; authors no
  add names; an agent beyond its limits; a rooted device naming an agent; a
  key listed twice; revokes naming no list member or the wrong kind; rooted
  authors revoking a recovery key; a recovery key, a passkey member and a
  rooted device confirming; confirms of list members that are not rooted devices
  or recovery keys; the last list member, and the last device beside an
  agent, revoking itself; a revoked signer.
- `merges`: fourteen branching lists, each with its events in canonical
  order (`log`: name, ID, author, `seq`, `prev`, parents and signed bytes),
  every event's status and reason, the list members and whether the list is
  dead: concurrent adds; one device added on both branches, with a proof
  for each adder; two adds of one
  X-Wing key; mutual revocations within a rank, of the only two devices,
  across ranks and against a recovery key; a revocation voiding a concurrent
  add and a concurrent confirm; a cycle of three settled by seniority; a
  self-revocation beside a revocation; a fork whose self-revocation stands;
  the agent's limit and a confirm lifting it.
- `replayed_adds`: lists in the same form as `merges`, in which a list
  member signs again, on its own chain, another member's `add` of a device
  or a recovery key, proof included: a recovery agent, a device rooted in
  one, and a passkey member, each concurrently and after the honest `add`.
  Each copy is `BadPossession`, and the list member keeps the rank the
  honest `add` gives it.
- `list_checkpoints`: a list in which a device names an agent that adds
  two devices, one of them confirmed, and a revocation concurrent with a
  list checkpoint; the record, the electorate (the confirmed device in it,
  the device still rooted in the agent and the agent out), every verdict
  at a holder that kept everything and at one that forgot, what the one
  that forgot holds and keeps alone, and each rooting add it keeps.
  `signatures`: a list checkpoint whose ML-DSA-65 half fails
  (`BadSignature`) and one by a device no add of its past names
  (`UntrustedSigner`). `record_refusals`: records of version 2
  (`UnsupportedVersion`), and with a member entry of five elements, an
  agent-rooted member without its rooting add or its agent, a rooting add
  or an agent
  on a member that is not rooted in an agent (`Malformed`).
- `enrolment`: two evaluations that agree, and two that do not.
- `fingerprints`: a device on a list, the same keys under another person, a
  passkey member, a device granted directly and an agent, with every
  intermediate value; five check symbols without hashing; four keys or IDs
  that have no fingerprint. `fingerprint_parsing`: eight forms of one
  fingerprint; thirteen `InvalidFingerprint` and three `FingerprintMistyped`
  texts; all 775 single-character errors; every exchange of two different
  characters; one two-character error that parses to another value.
- `account_links`: a link, its statement and ID, an unlink, and six checks:
  accepted, unlinked, a revoked signer, an agent, another person's list, a
  changed subject.
- `pins`: a later state, an earlier one, and one with a fork.
