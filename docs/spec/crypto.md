# Cryptography
Protocol 1. Vectors: [crypto.json](vectors/crypto.json).

This document fixes the primitives Frasil uses and their parameters, a
device's keys and its device ID, the checks every public key passes where
it enters, the X-Wing wrap, signature schemes 0 and 2 with anchors and
coverage, and the registry of every label.
It depends only on [overview.md](overview.md) for notation, encoding and
error classes. Every other document depends on it.

## 1. Overview

- Frasil defines no primitive of its own. It uses SHA-256, HMAC-SHA256,
  HKDF-SHA256, XChaCha20-Poly1305, Ed25519, X-Wing (ML-KEM-768 with X25519),
  HPKE with X-Wing, and ML-DSA-65; and, for
  [ext-deposit-tokens.md](ext-deposit-tokens.md) alone, RFC 9497's VOPRF
  over ristretto255.
- Every public key is checked once, where it enters (section 3.4). From then
  on it is a byte string known to be valid, with exactly one encoding, and
  keys are compared by their bytes.
- A device is named by its **device ID**, a hash of its Ed25519 key and of
  a commitment to its ML-DSA-65 and X-Wing keys. The name commits to every
  key the device signs or receives under, so a verifier takes those keys
  from any source and accepts them by their hash.
- Keys are sealed to a recipient only under X-Wing, which stays confidential
  while either ML-KEM-768 or X25519 holds.
- Every signed structure names its scheme. Scheme 0 is Ed25519. Scheme 2 is
  Ed25519 and ML-DSA-65 over the same bytes, both required, and holds while
  either holds. Every authority event and every possession proof uses
  scheme 2.
- Units use scheme 0 until the **classical sunset**, a future protocol
  revision after which a scheme-0 event counts only if a scheme-2 event
  covers it. Anchors give that coverage from protocol 1 on.
- Every hash, MAC, key derivation, AEAD and signature input is separated by
  a label from the registry of section 2.6.

## 2. Formats

### 2.1 Primitives

| Primitive | Specification | In Frasil |
|---|---|---|
| SHA-256 | FIPS 180-4 | 32 bytes out |
| HMAC-SHA256 | RFC 2104 | `HMAC(key, message)`, 32 bytes out, truncated only where a document says |
| HKDF-SHA256 | RFC 5869 | `HKDF(salt, ikm, info)`: extract, then expand to 32 bytes; a salt of `none` is 32 zero bytes. `HKDF-Extract(salt, ikm)` and `HKDF-Expand(prk, info, L)` where a document needs them apart |
| XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha-03, over RFC 8439 | 32-byte key, 24-byte nonce, 16-byte tag after the ciphertext; nonces random unless a document derives them |
| Ed25519 | RFC 8032, section 5.1 (pure Ed25519) | deterministic signing; strict verification (section 3.6) |
| X25519 | RFC 7748 | only as the classical half of X-Wing |
| ML-KEM-768 | FIPS 203 | only inside X-Wing |
| X-Wing | draft-connolly-cfrg-xwing-kem, version 06 | a KEM: 32-byte seed, 1,216-byte public key, 1,120-byte ciphertext, 32-byte shared secret |
| HPKE | RFC 9180, base mode, single shot | KEM `0x647a` (X-Wing), KDF `0x0001` (HKDF-SHA256), AEAD `0x0003` (ChaCha20-Poly1305) |
| ML-DSA-65 | FIPS 204 | pure ML-DSA, never HashML-DSA; empty context; deterministic signing (section 2.5) |
| TLS 1.3 exporter | RFC 8446, section 7.5; RFC 9266 | the channel binding of [transport.md](transport.md), under RFC 9266's label |
| VOPRF | RFC 9497, mode `modeVOPRF`, suite ristretto255-SHA512 | only deposit tokens ([ext-deposit-tokens.md](ext-deposit-tokens.md)), which protect neither confidentiality nor authority |

- **X-Wing.** The public key is the ML-KEM-768 encapsulation key (1,184
  bytes) then the X25519 public key (32); the ciphertext is the ML-KEM
  ciphertext (1,088) then the X25519 one (32). The seed is expanded by
  SHAKE256 into ML-KEM's `d` and `z` and the X25519 secret. Encapsulation
  draws 64 random bytes: ML-KEM's `m`, then the X25519 ephemeral secret.
  X-Wing's combiner is the only place the two shared secrets meet, and HPKE
  uses X-Wing's shared secret as the KEM's. `0x647a` is HPKE's code point
  for MLKEM768-X25519, which is X-Wing.
- **HPKE** is written `HPKE-Seal(pk, info, aad, plaintext) → (enc,
  ciphertext)` and `HPKE-Open(seed, enc, info, aad, ciphertext)`. `enc` is
  1,120 bytes, and the ciphertext is 16 bytes longer than the plaintext.
- **ML-DSA-65** is FIPS 204's parameter set (`q = 8380417`, `(k, l) = (6,
  5)`, `eta = 4`, `tau = 49`, `lambda = 192`, `gamma1 = 2^19`,
  `gamma2 = (q − 1)/32`, `omega = 55`). A key pair is
  `ML-DSA.KeyGen_internal(xi)` (Algorithm 6) from a 32-byte seed `xi`;
  signing is Algorithm 2 and verifying Algorithm 3. The seed is what is
  kept; the expanded secret key is derived when used.
- **Randomness** comes from the operating system's cryptographically secure
  source. An implementation without a working source MUST refuse to generate
  keys, seal or wrap. The text assumes the source never repeats an output,
  also across a restore of the machine's state: a virtual machine resumed
  from a snapshot, a process image copied or forked after it drew, or a
  device restored from an image. A source that would repeat there is not a
  working source until the platform reseeds it. A store restored from a
  backup is a different case: the machine's source is fresh, and
  [at-rest.md](at-rest.md), "After a restore", says what the device does
  about the values it drew since. A repeated draw costs what the draw is
  for: a nonce repeated under one key voids the AEAD's guarantees for the
  two messages, and a repeated secret makes two keys one.

### 2.2 Sizes

| Value | Bytes |
|---|---|
| Ed25519 seed, public key; signature | 32, 32; 64 |
| X-Wing seed; public key; `enc` | 32; 1,216; 1,120 |
| ML-DSA-65 seed; public key; expanded secret key; signature | 32; 1,952; 4,032; 3,309 |
| Scheme-2 signature | 3,373 |
| XChaCha20-Poly1305 nonce; tag | 24; 16 |

### 2.3 A device's keys

A device draws three 32-byte seeds, each independently from its random
source, and keeps them sealed ([at-rest.md](at-rest.md)): the identity seed,
of its Ed25519 **identity key**; the X-Wing seed, of its **X-Wing key**; and
the ML-DSA-65 seed, of its **ML-DSA-65 key**.

- A device MUST NOT derive one seed from another. Keys derived from a secret
  a person holds, fetch keys among them, are [identity.md](identity.md)'s
  (recovery keys and passkey members) and
  [ext-invite-links.md](ext-invite-links.md)'s (invite keys). An
  administrator pseudonym's keys are [peers.md](peers.md)'s.
- **Test fixtures** are built from an identity seed alone: X-Wing seed
  `SHA-256("frasil/device-hybrid-seed/v1" || identity seed)` and ML-DSA-65
  seed `SHA-256("frasil/device-mldsa-seed/v1" || identity seed)`. Only test
  vectors use these derivations.

**The device ID.** A device's keys give two hashes:

```text
kc        = SHA-256("frasil/device-keys-commitment/v1" || field(mldsa) || field(xwing))
device ID = SHA-256("frasil/device-id/v1" || ed (32) || kc (32))
```

- `ed` is the Ed25519 identity key, `mldsa` the ML-DSA-65 key and `xwing`
  the X-Wing key. `kc` is the **keys commitment**.
- Every holder of keys that signs events has a device ID by this rule, not
  only a device: every list member ([identity.md](identity.md)), an invite
  key ([ext-invite-links.md](ext-invite-links.md)) and an administrator
  pseudonym ([peers.md](peers.md)). A holder with no X-Wing key, a recovery
  agent or an administrator pseudonym, hashes `xwing` as the empty string:
  `field(xwing)` is `u32be(0)`.
- The **identity key** is the Ed25519 key alone. It signs, and an envelope
  carries it ([events.md](events.md)), but it never names a device: two
  key holders may share an Ed25519 key and differ in `kc`, and they are two
  devices. Every format that names a device names its device ID. A
  structure that needs the Ed25519 key carries `ed || kc`, 64 bytes, from
  which anyone computes the device ID.

**Keys by their hash.** A verifier, and a device that seals to a holder,
takes the holder's ML-DSA-65 and X-Wing keys from any source, and accepts
them exactly when they hash to the holder's `kc`. Where it knows the holder
only by its device ID, it takes the Ed25519 key with them and accepts the
three exactly when they hash to that device ID. Its sources include the
structure being verified, a record of any log, valid or void, another
member's device list, an admission exchange and a cache.
No source is trusted for anything: keys that hash to the commitment are the
holder's, wherever they came from, and keys that do not are not. A
structure that carries keys as a holder's, and whose keys do not hash to
the device ID or `kc` it names, is `NotCommitted`.

- Each key still passes its check where it enters (section 3.4), before
  it is hashed or used.
- Two key sets under one `kc`, or two `(ed, kc)` under one device ID, need
  a SHA-256 collision. So a holder has one ML-DSA-65 key and one X-Wing
  key, and a verifier has one key to try.
- A verifier that holds no keys hashing to a holder's `kc` cannot check its
  ML-DSA-65 half yet (`NoHybridKey`, pending). That says nothing against
  the holder, and the check runs again when any source brings the keys.

### 2.4 The X-Wing wrap

A **wrap** seals a plaintext to one X-Wing public key:

```text
offset  length  field
0       1       version = 0x01
1       2       u16be(suite) = 0x647a
3       1,120   enc
1,123   n + 16  ciphertext

(enc, ciphertext) = HPKE-Seal(recipient's X-Wing key, info, aad = "", plaintext)
```

| Suite | HPKE KEM | State |
|---|---|---|
| X-Wing (MLKEM768-X25519) | `0x647a` | the only suite |
| Any other, DHKEM(X25519, HKDF-SHA256) `0x0020` included | | refused, `UnsupportedVersion` |

- `info` starts with the label of the wrap's use, then `u16be(suite)`, then
  what the using document binds: the log where there is one, and the
  recipient or the exchange. A wrap therefore opens under no other suite,
  use, log or recipient.
- A wrap names no recipient; a device finds its own by trial decryption.
- A wrap carries no signature of its own. A key wrap travels only inside a
  scheme-2 event whose author is its wrapper, or as the copy an invite drop
  carries, which [ext-invite-links.md](ext-invite-links.md) checks against
  that event's delivery. Every other use authenticates
  what it carries as its document says: a mailbox item's body is signed on
  its own, an exchange message is bound by the admission code, and a slot
  token's slot is named in a scheme-2 event.

Every Frasil seal to an X-Wing key uses this layout:

| Use | Label | `info` binds, after the suite | Length |
|---|---|---|---|
| Bundle wrap ([keys.md](keys.md)) | `frasil/bundle-wrap/v1` | the log, the key names, the recipient's device ID | 1,236 |
| Space wrap ([keys.md](keys.md)) | `frasil/space-wrap/v1` | the log, the key names, the grantee space and rotation | 1,236 |
| Removal wrap ([keys.md](keys.md)) | `frasil/removal-wrap/v1` | the log, the key names, the recipient's device ID | 1,236 |
| Slot token ([peers.md](peers.md)) | `frasil/skeleton-token/v1` | the space, the slot, the grantee's device ID | 1,171 |
| Exchange message ([admission.md](admission.md)) | `frasil/admission/seal/v1` | the request and the message type | at least 1,139 |
| Welcome ([admission.md](admission.md)) | `frasil/welcome/v1` | the recipient's device ID | at least 1,139 |
| Device mailbox item ([transport.md](transport.md)) | `frasil/mailbox-item/v1` | the recipient's device ID | 1,139 to 262,144 |

- **Which key.** A wrapper seals to a device's X-Wing key only when it
  hashes, with an ML-DSA-65 key, to the device's `kc`, and `ed` with that
  `kc` to the device ID it seals for (section 2.3, "Keys by their hash").
  It may take the keys from any source, a peer's listing included, since
  the hash decides. A grant key is not a device's: a wrapper takes it from
  a notice ([keys.md](keys.md)), bound by its rotation's commitment. There
  is no fallback: a holder whose keys hold no X-Wing key receives no
  wrap.

### 2.5 Signature schemes

| Code | Scheme | Used by |
|---|---|---|
| 0 | Ed25519, verified strictly | units, and structures verified once, at once |
| 1 | reserved | refused, `UnsupportedVersion` |
| 2 | Ed25519 and ML-DSA-65, both of which MUST verify | authority events and possession proofs (section 3.8) |

Every signed structure names its scheme. A deterministic CBOR map, such as
an event, carries key 9, `scheme`: absent for scheme 0, `2` for scheme 2,
and `Malformed` when it holds 0, so each structure has one encoding. A
length-prefixed statement appends `field(u8(scheme))` for a scheme other
than 0. A fixed binary layout carries a scheme byte in its header, inside
what is signed. A verifier refuses a scheme it does not know as
`UnsupportedVersion`, and never guesses.

**Scheme 0** signs `tbs`, the bytes the structure's document defines, which
begin with the structure's own label: `signature = Ed25519-Sign(seed, tbs)`.

**Scheme 2** signs the same `tbs`, with the scheme field set to 2:

```text
m_ed      = "frasil/hybrid-signature/ed25519/v1" || ed_public (32) || tbs
m_ml      = "frasil/hybrid-signature/mldsa/v1" || ed_public (32)
            || SHA-256(mldsa_public) (32) || tbs
sig_ed    = Ed25519-Sign(ed_seed, m_ed)                        64 bytes
sig_ml    = ML-DSA.Sign(mldsa_secret, m_ml, ctx = "")         3,309 bytes
signature = sig_ed || sig_ml                                  3,373 bytes
```

- **The Ed25519 half stands on its own.** `m_ed` needs only the signer's
  Ed25519 key, so a verifier checks it before it looks anything up, and only
  the holder of an Ed25519 key can make a replica wait for the keys of a
  device that has that key.
- **The ML-DSA-65 half binds both keys,** so it cannot be moved under
  another key pair. The Ed25519 half needs no hash of the ML-DSA-65 key:
  the signer is named by its device ID, and the verifier takes the
  ML-DSA-65 key whose hash is the signer's `kc` (below).
- **Each half has its own label,** so neither half's message reads as the
  other's or as a scheme-0 message. The scheme is inside `tbs`, so a
  scheme-2 signature cut to its Ed25519 half fails as scheme 0 too.
- ML-DSA's `M'` is `0x00 || 0x00 || m_ml`: an empty context, since the label
  already separates the domain.
- A signer SHOULD sign deterministically, with ML-DSA-65's `rnd` set to 32
  zero bytes, so that one structure has one signed encoding. A signer that
  must hedge against fault attacks MAY use the hedged variant. A verifier
  accepts both; an event signed twice is still one event, because its ID
  leaves out the signature ([events.md](events.md)).

**Where a verifier takes an ML-DSA-65 key.** From any source, by its hash
(section 2.3, "Keys by their hash"): the ML-DSA-65 key that, with an X-Wing
key, or with none for a holder that has none, hashes to the signer's `kc`.
The signed structure names the signer: an event by its envelope's `ed` and
`kc` ([events.md](events.md)), any other structure by the device ID or the
`ed || kc` its document gives it. An administrator slot's keys, which sign
no event, are named instead by the slot's Ed25519 key and the SHA-256 of
its ML-DSA-65 key ([peers.md](peers.md)). The source vouches for nothing,
so a key taken from a void event, from another member's list or from a
cache is as good as one taken from the signer's own grant, and no record
can attach a key of its own to a signer. A record that MUST name an
ML-DSA-65 key and does not is `Malformed`.

### 2.6 The label registry

Every label protocol 1 uses, by the document that defines its use. A label's
bytes are its ASCII; the vectors give each in hex. No label, purpose string
or reserved string equals another or is a prefix of another.

| Label | Used as | In |
|---|---|---|
| `frasil/hybrid-signature/ed25519/v1` | first bytes of the message the Ed25519 half of a scheme-2 signature signs | crypto |
| `frasil/hybrid-signature/mldsa/v1` | first bytes of the message the ML-DSA-65 half signs | crypto |
| `frasil/device-hybrid-seed/v1` | hash prefix of a test fixture's X-Wing seed | crypto |
| `frasil/device-mldsa-seed/v1` | hash prefix of a test fixture's ML-DSA-65 seed | crypto |
| `frasil/device-keys-commitment/v1` | hash prefix of a keys commitment, `kc` | crypto |
| `frasil/device-id/v1` | hash prefix of a device ID | crypto |
| `frasil/event/v1` | first bytes of what an event signs | [events](events.md) |
| `frasil/event-id/v1` | hash prefix of an event ID | [events](events.md) |
| `frasil/device-list/possession/v3` | first bytes of the possession statement | [identity](identity.md) |
| `frasil/device-list/seniority/v1` | hash prefix that orders list members for the seniority pick | [identity](identity.md) |
| `frasil/account-link/v1` | first bytes of an account link statement | [identity](identity.md) |
| `frasil/account-unlink/v1` | first bytes of an account unlink statement | [identity](identity.md) |
| `frasil/key-fingerprint/v1` | first bytes of a fingerprint's digest input | [identity](identity.md) |
| `frasil/recovery/v1` | HKDF salt of every recovery-key derivation | [identity](identity.md) |
| `frasil/recovery-key/hybrid/v1` | HKDF info of a recovery key's X-Wing seed | [identity](identity.md) |
| `frasil/recovery-key/mldsa/v1` | HKDF info of a recovery key's ML-DSA-65 seed | [identity](identity.md) |
| `frasil/recovery-key/fetch/v1` | HKDF info of a recovery key's fetch seed | [identity](identity.md) |
| `frasil/passkey-prf-input/v2` | the bytes SHA-256 hashes into the passkey PRF input | [identity](identity.md) |
| `frasil/passkey-extract/v1` | HKDF salt of the passkey extract | [identity](identity.md) |
| `frasil/passkey-member/v1` | first bytes of the HKDF info of a passkey member's Ed25519 seed | [identity](identity.md) |
| `frasil/passkey-unlock/v1` | first bytes of the HKDF info of a passkey's unlock key | [identity](identity.md) |
| `frasil/passkey/hybrid/v1` | first bytes of the HKDF info of a passkey member's X-Wing seed | [identity](identity.md) |
| `frasil/passkey/mldsa/v1` | first bytes of the HKDF info of a passkey member's ML-DSA-65 seed | [identity](identity.md) |
| `frasil/passkey/fetch/v1` | first bytes of the HKDF info of a passkey member's fetch seed | [identity](identity.md) |
| `frasil/roster/seniority/v1` | hash prefix that orders grants by seniority | [roster](roster.md) |
| `frasil/checkpoint-record/v1` | hash prefix of a checkpoint record's digest | [roster](roster.md) |
| `frasil/merge-key/v1` | info prefix of a merged content key | [keys](keys.md) |
| `frasil/merge-upload/v1` | info prefix of a merged upload seed | [keys](keys.md) |
| `frasil/merge-grant/v1` | info prefix of a merged grant seed | [keys](keys.md) |
| `frasil/grant-key/v1` | HKDF info of a grant key's X-Wing seed | [keys](keys.md) |
| `frasil/grant-commitment/v1` | hash prefix of a grant rotation's commitment | [keys](keys.md) |
| `frasil/read-credential/v1` | HKDF info of a read credential's seed | [keys](keys.md) |
| `frasil/upload-key/v1` | HKDF info of an upload key's seed | [keys](keys.md) |
| `frasil/space-metadata-key/v1` | HKDF info of a state's metadata key | [keys](keys.md) |
| `frasil/object-id-key/v1` | HKDF info of a state's object ID key | [keys](keys.md) |
| `frasil/object-nonce-key/v1` | HKDF info of a state's object nonce key | [keys](keys.md) |
| `frasil/key-link/v1` | info prefix of a link key, and associated-data prefix of a link | [keys](keys.md) |
| `frasil/bundle-wrap/v1` | HPKE info prefix of a bundle wrap | [keys](keys.md) |
| `frasil/space-wrap/v1` | HPKE info prefix of a space wrap | [keys](keys.md) |
| `frasil/removal-wrap/v1` | HPKE info prefix of a removal wrap | [keys](keys.md) |
| `frasil/space-event/v1` | info prefix of a body key, and associated-data prefix of a space event's sealed part | [keys](keys.md) |
| `frasil/space-event-commitment/v1` | HKDF info of a body key's commitment | [keys](keys.md) |
| `frasil/rotation-rank/v1` | hash prefix of a device's rank for a trigger | [keys](keys.md) |
| `frasil/name/v1` | associated-data prefix of a sealed name | [keys](keys.md) |
| `frasil/unit/v1` | info prefix of a unit's body key, and associated-data prefix of its seal | [units](units.md) |
| `frasil/unit-key/v1` | HKDF info of a state's unit key | [units](units.md) |
| `frasil/unit-commitment/v1` | HKDF info of a unit's body key commitment | [units](units.md) |
| `frasil/object-seal-key/v1` | HKDF info of a state's object seal key | [units](units.md) |
| `frasil/object-chunk/v1` | associated-data prefix of an object's chunk | [units](units.md) |
| `frasil/stream-id/v1` | hash prefix of a stream ID | [units](units.md) |
| `frasil/head-statement/v1` | first bytes of what a head statement signs | [units](units.md) |
| `frasil/space-snapshot/v1` | first bytes of what a space snapshot signs | [units](units.md) |
| `frasil/member-key/v1` | HKDF info of a state's member key | [transport](transport.md) |
| `frasil/member-offer/v1` | prefix of an offer tag's HMAC input | [transport](transport.md) |
| `frasil/member-transcript/v1` | prefix of an attach's transcript hash | [transport](transport.md) |
| `frasil/member-answer/v1` | prefix of an answer's proof | [transport](transport.md) |
| `frasil/member-identify/v1` | prefix of what a device signs to bind itself to a connection | [transport](transport.md) |
| `frasil/peer-binding/v1` | prefix of the device-to-peer binding hash | [transport](transport.md) |
| `frasil/server-channel/v1` | prefix of the server binding's channel value | [transport](transport.md) |
| `frasil/lan-key/v1` | HKDF info of a state's local-network announcement key | [transport](transport.md) |
| `frasil/lan-announce/v1` | associated data of a member announcement | [transport](transport.md) |
| `frasil/mailbox/v1` | prefix of a mailbox address hash | [transport](transport.md) |
| `frasil/mailbox-collect/v1` | prefix of what a device signs to collect its own mailbox | [transport](transport.md) |
| `frasil/mailbox-item/v1` | HPKE info prefix of a sealed device mailbox item | [transport](transport.md) |
| `frasil/p1/member` | ALPN of a member connection | [transport](transport.md) |
| `frasil/p1/peer` | ALPN of a device-to-peer connection | [transport](transport.md) |
| `frasil/p1/nearby` | ALPN of a nearby pairing connection | [transport](transport.md) |
| `frasil/storage-proof/v1` | first bytes of a credential proof's statement | [peers](peers.md) |
| `frasil/storage-merge/v1` | first bytes of a merge statement's message | [peers](peers.md) |
| `frasil/skeleton-twin/v1` | HKDF info of a twin secret | [peers](peers.md) |
| `frasil/skeleton-twin-commitment/v1` | hash prefix of a twin commitment | [peers](peers.md) |
| `frasil/skeleton-binding/v1` | HKDF info of a binding key, and associated-data prefix of a binding | [peers](peers.md) |
| `frasil/skeleton-device/v1` | first bytes of the statement a device signs over its pseudonym | [peers](peers.md) |
| `frasil/skeleton-token/v1` | HPKE info prefix of a slot token's seal | [peers](peers.md) |
| `frasil/skeleton-slot/ed25519/v1` | HKDF info of an administrator slot's Ed25519 seed | [peers](peers.md) |
| `frasil/skeleton-slot/mldsa/v1` | HKDF info of an administrator slot's ML-DSA-65 seed | [peers](peers.md) |
| `frasil/skeleton-enrol/v1` | first bytes of the statement a slot's keys sign to enrol a pseudonym | [peers](peers.md) |
| `frasil/skeleton-root/v1` | first bytes of the statement the founder's device signs over its pseudonym | [peers](peers.md) |
| `frasil/skeleton/seniority/v1` | hash prefix of an administrator slot's seniority | [peers](peers.md) |
| `frasil/admission/commit/v1` | prefix of the joiner's commitment | [admission](admission.md) |
| `frasil/admission/code/v1` | prefix of the code hash | [admission](admission.md) |
| `frasil/admission/heads/v1` | prefix of a heads hash | [admission](admission.md) |
| `frasil/admission/seal/v1` | HPKE info prefix of an exchange message | [admission](admission.md) |
| `frasil/admission/setup/v1` | prefix of the setup MAC's input | [admission](admission.md) |
| `frasil/admission/setup-tag/v1` | prefix of the setup tag | [admission](admission.md) |
| `frasil/admission/prompt/v1` | prefix of what a lookup prompt's signature signs | [admission](admission.md) |
| `frasil/welcome/v1` | HPKE info prefix of a sealed welcome | [admission](admission.md) |
| `frasil/access-request/v1` | prefix of what an access request's signature signs | [admission](admission.md) |
| `frasil/welcome-request/v1` | prefix of what a welcome request's signature signs | [admission](admission.md) |
| `frasil/sealed-device-keys/v1` | associated-data prefix of sealed device keys, and HKDF info of a kind 2 sealing key | [at-rest](at-rest.md) |
| `frasil/unlock-key/v1` | HKDF salt of a kind 2 sealing key | [at-rest](at-rest.md) |
| `frasil/at-rest/seal-key/v1` | HKDF info of a seal key | [at-rest](at-rest.md) |
| `frasil/at-rest/tag-key/v1` | HKDF info of a tag key | [at-rest](at-rest.md) |
| `frasil/at-rest/scope/v1` | prefix of a scope tag's HMAC input | [at-rest](at-rest.md) |
| `frasil/at-rest/item/v1` | prefix of an item tag's HMAC input | [at-rest](at-rest.md) |
| `frasil/at-rest/record/v1` | associated-data prefix of a record | [at-rest](at-rest.md) |
| `frasil/at-rest/mark/v1` | associated-data prefix of the continuity mark | [at-rest](at-rest.md) |
| `frasil/at-rest/app-key/v1` | HKDF info prefix of an application key | [at-rest](at-rest.md) |
| `frasil/space-file/key/v1` | HKDF info of a space file's sealing key | [ext-space-files](ext-space-files.md) |
| `frasil/space-file/way-in/v1` | associated-data prefix of a sealed way in | [ext-space-files](ext-space-files.md) |
| `frasil/invite/v1` | HKDF salt of every invite-key derivation | [ext-invite-links](ext-invite-links.md) |
| `frasil/invite/hybrid/v1` | HKDF info of an invite key's X-Wing seed | [ext-invite-links](ext-invite-links.md) |
| `frasil/invite/mldsa/v1` | HKDF info of an invite key's ML-DSA-65 seed | [ext-invite-links](ext-invite-links.md) |
| `frasil/invite/locator/v1` | HKDF info of an invite drop's locator | [ext-invite-links](ext-invite-links.md) |
| `frasil/invite/drop/v1` | HKDF info of an invite drop's key, and its associated-data prefix | [ext-invite-links](ext-invite-links.md) |
| `frasil/leave-request/v1` | prefix of what a leave request's signature signs | [ext-guests](ext-guests.md) |
| `frasil/restricted-key/v1` | HKDF info prefix of a restricted space's content key | [ext-restricted-spaces](ext-restricted-spaces.md) |
| `frasil/parent-reference/v1` | HKDF info of the key that seals a restricted unit's parent state, and that seal's associated-data prefix | [ext-restricted-spaces](ext-restricted-spaces.md) |
| `frasil/ephemeral-key/v1` | HKDF info of the ephemeral key | [ext-ephemeral](ext-ephemeral.md) |
| `frasil/ephemeral/v1` | prefix of what a sender signs, and of the seal's associated data | [ext-ephemeral](ext-ephemeral.md) |
| `frasil/ephemeral-slot/v1` | prefix of an ephemeral slot handle's HMAC input | [ext-ephemeral](ext-ephemeral.md) |
| `frasil/library-ticket/v1` | first bytes of what a ticket's issuer signs | [ext-libraries](ext-libraries.md) |
| `frasil/object-access/v1` | HKDF info of an object's access seed | [ext-libraries](ext-libraries.md) |
| `frasil/object-hold/v1` | first bytes of what a hold's proof signs | [ext-libraries](ext-libraries.md) |
| `frasil/device-signed-request/v1` | first bytes of a device-signed request's statement | [ext-app-requests](ext-app-requests.md) |
| `frasil/deposit-key/v1` | `DeriveKeyPair` info of a peer's deposit key, and hash prefix of its key ID | [ext-deposit-tokens](ext-deposit-tokens.md) |
| `frasil/deposit-token/v1` | first bytes of a deposit token's VOPRF input | [ext-deposit-tokens](ext-deposit-tokens.md) |
| `frasil/loro-peer/v1` | hash prefix of a writer's Loro peer ID | [adapter-loro](adapter-loro.md) |

**Purpose strings.** `"ed25519"` is the whole HKDF info of a recovery key's
Ed25519 seed under the salt `frasil/recovery/v1`, and of an invite key's
under `frasil/invite/v1`. Inside the passkey infos, `"ed25519"` and
`"device-keys"` are length-prefixed fields after the label. Neither is used
as a label on its own. `"x25519"` is reserved as a purpose string.

**Reserved.** These strings MUST NOT be used as labels, and no new label may
equal or be a prefix of one: `frasil/admission/keys/v1`, `frasil/aead/v1`,
`frasil/blob-id/v1`, `frasil/blob-nonce/v1`, `frasil/blob-part/v1`
followed by one zero byte, `frasil/blob/v1/chunk`,
`frasil/blob/v1/manifest`, `frasil/comparison-code/commit/v1`,
`frasil/comparison-code/v1`, `frasil/device-keys/v1`,
`frasil/device-list/entry/v1`, `frasil/device-list/label/v1`,
`frasil/device-list/possession/v1`, `frasil/device-list/possession/v2`,
`frasil/device-list/v1`, `frasil/device-proof/v1`, `frasil/invite-pending/v1`,
`frasil/invite-wrap-signature/v1`, `frasil/invite-wrap/v1`,
`frasil/key-chain-signature/v1`, `frasil/key-chain/v1`,
`frasil/key-registration/v1`, `frasil/lan/v1`, `frasil/member/1`,
`frasil/member/v1`, `frasil/metadata-key/v1`, `frasil/nearby/1`,
`frasil/passkey-prf-input/v1`, `frasil/peer/1`, `frasil/presence/v1`,
`frasil/proposal/v2`, `frasil/scope-blob-id/v1`,
`frasil/scope-blob-nonce/v1`, `frasil/scope-key/v1`,
`frasil/scope-metadata-key/v1`, `frasil/scope-wrap/v1`,
`frasil/scoped-aead/v1`, `frasil/sealed-invite/v1`,
`frasil/sealed-pending-update/v1`, `frasil/snapshot/v1`, `frasil/update/v1`,
`frasil/vault-roster/entry/v1`, `frasil/vault-roster/label/v1`,
`frasil/vault-roster/v1`, `frasil/wrap-signature/v1` and `frasil/wrap/v1`.

**Other names Frasil keeps,** which feed no primitive: capability names
that begin `frasil.` ([roster.md](roster.md)); ephemeral names and mailbox
content names that begin `frasil/` ([ext-ephemeral.md](ext-ephemeral.md),
[transport.md](transport.md)); the WebSocket subprotocol `frasil.p1`
([transport.md](transport.md)); the QR prefixes `FRASIL-FP1:`
([identity.md](identity.md)), `FRASIL-ADMIT:` and `FRASIL-SETUP:`
([admission.md](admission.md)); and the nearby name `setup-<tag>` of a
headless device in setup mode ([admission.md](admission.md),
[transport.md](transport.md)).

## 3. Procedures

Constants, from RFC 8032 and RFC 7748: `p = 2^255 − 19`;
`d = −121665/121666 mod p` =
`37095705934669439343138083508754565189542113879843219016388785533085940283555`;
`ℓ = 2^252 + 27742317777372353535851937790883648493`, the order of the
Ed25519 base point `B` and of the X25519 base point `u = 9`; `O`, the
neutral element, `(0, 1)` on Edwards25519 and the point at infinity on
Curve25519. Field elements are little-endian, as both RFCs encode them.

### 3.1 Ed25519 public keys

```text
ed25519_valid(k), in order:
  1. len(k) = 32.                                               else InvalidKey
  2. Decode k as RFC 8032, section 5.1.3, says, exactly:
       y = k as a little-endian integer with bit 255 cleared; x0 = bit 255.
       y < p.
       u = y^2 − 1, v = d·y^2 + 1 (mod p); x = u·v^3·(u·v^7)^((p−5)/8).
       If v·x^2 = u, keep x; else if v·x^2 = −u, x = x·2^((p−1)/4);
       else fail.
       Not (x = 0 and x0 = 1).
       If x mod 2 ≠ x0: x = p − x.                              else InvalidKey
  3. Re-encoding (x, y) as RFC 8032, section 5.1.2, gives k.    else InvalidKey
  4. [8]P ≠ O: P is not of small order.                         else InvalidKey
  5. [ℓ]P = O: P is torsion-free.                               else InvalidKey
```

- Step 2 refuses `y ≥ p` and `x = 0` with the sign bit set, which some
  decoders accept. Step 3 then always holds; it is stated so that an
  implementation on a lenient decoder still refuses such keys.
- Step 4 refuses the eight points of order 1, 2, 4 and 8, `O` among them.
  Step 5 refuses every point with a torsion component.
- Every honest key is `[s]B` and passes.

### 3.2 X25519 public keys

An X25519 key appears only as the last 32 bytes of an X-Wing key, which
section 3.3 checks with this function.

```text
x25519_valid(k), in order:
  1. len(k) = 32.                                               else InvalidKey
  2. Bit 255 of k is 0.                                         else InvalidKey
  3. u = k as a little-endian integer; u < p.                   else InvalidKey
  4. u ≠ 0, and [ℓ]P = O for the point P with u-coordinate u,
     computed with RFC 7748's Montgomery ladder in projective
     coordinates: the result's Z is 0.                          else InvalidKey
```

- Steps 2 and 3 give one byte string per u-coordinate. The X25519 function
  is unchanged; such a key is refused before the function is given it,
  because Frasil compares keys by their bytes.
- Step 4 accepts exactly the points of order `ℓ`. It refuses the five
  small-order u-coordinates (0, 1, `p − 1` and the two points of order 8),
  every point on the twist, and every point with a torsion component. `u = 0`
  is refused explicitly because the ladder degenerates for it.
- Every honest key is `X25519(s, 9)` for a clamped `s`, and passes.

**At use.** An implementation that computes an X25519 shared secret outside
X-Wing MUST refuse an all-zero result:

```text
x25519_at_use(secret, public), in order:
  1. K = X25519(secret, public), exactly as RFC 7748, section 5.
  2. K is not 32 zero bytes.                                    else Decrypt
```

No protocol 1 format computes one; the rule binds any extension that does.
The X25519 half of an X-Wing ciphertext gets no such check: X-Wing's
combiner takes it with the ML-KEM-768 secret, and a sender that makes it
degenerate already knows the plaintext.

### 3.3 X-Wing and ML-DSA-65 public keys

```text
xwing_valid(k), in order:
  1. len(k) = 1,216.                                            else InvalidKey
  2. Each 12-bit coefficient of k[0..1152] is below 3,329
     (FIPS 203, section 7.2).                                   else InvalidKey
  3. x25519_valid(k[1184..1216]).                               else InvalidKey

mldsa_valid(k):
  1. len(k) = 1,952.                                            else Malformed
```

Every 1,952-byte string decodes as an ML-DSA-65 public key (FIPS 204,
Algorithm 23, has no failure case), so the length is the whole check. It
runs with the shape checks of the structure that names the key, so a wrong
length is `Malformed`, before any key is validated.

`verify` (section 3.7) takes the ML-DSA-65 key only with an X-Wing key, or
none for a holder that has none, that hash to the signer's `kc`, each
having passed its checks where it entered. A key that does not hash to the
`kc`, whatever its length, is never tried: step 5 fails with
`NoHybridKey` until keys that do are held.

### 3.4 Where keys are checked

A key is checked where it enters. A structure that names a refused key is
invalid for every verifier. A key is not checked again when it is used or
when it signs, and a key that fails is never canonicalised into one that
passes.

| Where | Keys | When |
|---|---|---|
| An event's `ed` ([events.md](events.md)) | Ed25519 | before the signature |
| A device-list `add` ([identity.md](identity.md)) | Ed25519, X-Wing; ML-DSA-65 | before its device ID and its possession proof |
| A recovery entry's fetch key ([identity.md](identity.md), [peers.md](peers.md)) | Ed25519 | when the entry is read, and before a peer registers it |
| A roster grant of a device, and a succeed that names one ([roster.md](roster.md)) | Ed25519, X-Wing; ML-DSA-65 | before the keys are hashed to the member's device ID |
| An invite key's grant ([ext-invite-links.md](ext-invite-links.md)) | as a device grant | as a device grant |
| A rotation's read credential and upload key ([keys.md](keys.md)) | Ed25519 | before the event is accepted |
| A notice's grant key ([keys.md](keys.md)) | X-Wing | when the sealed part opens, before anything is sealed to it |
| A newcomer's keys in admission ([admission.md](admission.md)) | Ed25519, X-Wing; ML-DSA-65 | on receipt, before any code or fingerprint is shown |
| Keys a verifier or a wrapper takes by their hash from any other source (section 2.3) | as their kind requires | before they are hashed |
| Admission's ephemeral keys ([admission.md](admission.md)) | X-Wing | on receipt, before anything is sealed to them |
| An account link's signer ([identity.md](identity.md)) | Ed25519 | before its signature |
| Any other structure's `ed`, beside its `kc` ([units.md](units.md), [transport.md](transport.md), the extensions) | Ed25519 | before its signature |
| Pseudonym, slot and credential keys a peer takes from events ([peers.md](peers.md)) | Ed25519; ML-DSA-65 | before the peer stores or acts on them |
| A handshake's endpoint keys and an `Identify`'s `ed` ([transport.md](transport.md)) | Ed25519 | before the key is stored or its signature checked |
| An ephemeral message's sender ([ext-ephemeral.md](ext-ephemeral.md)) | Ed25519 | before its signature |
| A key the client takes from its caller | as its kind requires | on entry |

### 3.5 Opening a wrap

```text
open_wrap(wrap, seed, info), in order:
  1. len(wrap) >= 1.                                            else Malformed
  2. wrap[0] = 0x01.                                            else UnsupportedVersion
  3. len(wrap) >= 3.                                            else Malformed
  4. u16be(wrap[1..3]) = 0x647a.                                else UnsupportedVersion
  5. len(wrap) is the length, or in the range, the using
     document fixes (section 2.4).                              else Malformed
  6. HPKE-Open(seed, wrap[3..1123], info, "", wrap[1123..]).    else Decrypt
```

A wrap meant for another recipient, log or use fails at step 6 as
`Decrypt`, like a damaged one. The using document then checks the plaintext.

### 3.6 Strict Ed25519 verification

A signature `sig` of message `M` under public key `A` is valid only if, in
order:

1. `len(sig) = 64`. `R` is `sig[0..32]`; `S` is `sig[32..64]` as a
   little-endian integer.
2. `S < ℓ`.
3. `R` decodes as section 3.1, step 2, and re-encodes to the same 32 bytes.
4. Neither `R` nor `A` is of small order.
5. With `k = SHA-512(R || A || M)` as a little-endian integer mod `ℓ`,
   `[S]B − [k]A`, encoded, equals `R`: the equation without the cofactor.

Any failure is `BadSignature`, or the class a structure's document names for
its proofs (`BadPossession`). `A` has passed section 3.1 already.

### 3.7 Verifying a signature

```text
verify(kind, scheme, ed, kc, tbs, signature, keys, sunset, covered),
in order:
  1. scheme is 0 or 2.                                          else UnsupportedVersion
  2. scheme is one the kind may carry (section 3.8).            else SchemeNotAllowed
  3. len(signature) = 64 for scheme 0, 3,373 for scheme 2.      else Malformed
  4. Scheme 0: section 3.6 over tbs.
     Scheme 2: section 3.6 over m_ed with signature[0..64].     else BadSignature
  5. Scheme 2: among keys, the verifier holds an ML-DSA-65 key
     mldsa_public that, with an X-Wing key or none, hashes to
     kc (section 2.3).                                          else NoHybridKey
  6. Scheme 2: ML-DSA.Verify(mldsa_public, m_ml,
     signature[64..3373], "").                                  else BadSignature
  7. After the sunset, scheme 0: the event is covered.          else Uncovered
```

- For an event, `tbs` is `"frasil/event/v1" || event` and the scheme is the
  map's key 9, and `ed` and `kc` are its keys 3 and 10.
  [events.md](events.md) runs steps 1 to 4 with its envelope checks, and
  steps 5 and 6 once the replica holds keys that hash to `kc`.
- Steps 1 to 4 need only the structure, so a peer can run them on all it
  stores, and a forgery by anyone without the author's Ed25519 key is
  refused before anything waits.
- Steps 5 and 7 are pending. Against a quantum adversary step 4 filters
  nothing; [roster.md](roster.md) bounds what a replica keeps pending from
  authors no record names.
- Both halves are always checked. Nothing is accepted on one half.
- A structure outside an event runs the same steps, with the scheme its
  document fixes.

### 3.8 Which structures carry which scheme

| Event kind ([events.md](events.md)) | Accepted before the sunset | Signed before | Accepted after | Signed after |
|---|---|---|---|---|
| 1, device-list event | 2 | 2 | 2 | 2 |
| 2, space event | 2 | 2 | 2 | 2 |
| 4, unit | 0 or 2 | 0 | 2, or 0 if covered | 2 |
| 5, anchor | 2 | 2 | 2 | 2 |
| 6, storage event | 2 | 2 | 2 | 2 |
| 64 to 127, ignorable | 0 or 2 | 0 | 2, or 0 if covered | 2 |

- A verifier takes the allowed schemes from the kind alone, before it opens
  any body. A kind from 7 to 63 states its schemes when it is defined; one
  that decides authority takes scheme 2 only. Until then, step 2 of section
  3.7 allows it scheme 0 or 2, and [events.md](events.md) refuses it as
  `UnknownKind` after its envelope checks.
- **Scheme 2 outside the envelope:** possession statements
  ([identity.md](identity.md)); the founder's root
  statement, a slot's authorization and the device signature in an
  enrolment ([peers.md](peers.md)); space snapshots ([units.md](units.md));
  access requests and lookup prompts ([admission.md](admission.md)); leave
  requests ([ext-guests.md](ext-guests.md)).
- **Scheme 0 outside the envelope,** each verified once, at once, so that a
  later forgery is never verified: account links; head statements; the
  admission transcript; a device's binding to a connection; credential
  proofs and merge statements; ephemeral messages, library tickets and
  device-signed requests.
- **No signature:** wraps and links. They travel only inside scheme-2 space
  events, except the copy of a key wrap an invite drop carries, which
  [ext-invite-links.md](ext-invite-links.md) checks against that event's
  delivery. Each rotation commits to its secrets ([keys.md](keys.md)).

### 3.9 Anchors and coverage

- An event `E` is **covered** for a verifier when an event it accepted under
  scheme 2 names `E` by hash, directly or through a chain of hashes. Only an
  envelope's `prev` and `parents` count; refs are sealed, and coverage MUST
  NOT depend on the keys a verifier holds. The schemes of the events between
  do not matter. Coverage vouches for an event's content, not its
  signature, because an event ID hashes the unsigned event.
- An **anchor** is an event of kind 5 under scheme 2 with an empty body.
  Its parents are the heads its author holds in that log, `prev` among them.
  It changes no state. Replicas verify it as any event and keep it in its
  author's chain; peers store and forward it as they do a unit.
- A device SHOULD write an anchor in a space when it holds scheme-0 events
  of that space that no scheme-2 event it holds covers, at most once per
  `anchor_interval` ([overview.md](overview.md), section 6.8), on the lower
  estimate from its last anchor there. If it holds more heads than one event
  may cite, it first anchors subsets of them, then writes one anchor that
  names those anchors.
- Before the sunset nothing depends on anchors. They let a space that falls
  quiet before the sunset still be verified after it.

### 3.10 The classical sunset

The sunset is a future protocol revision, made before a quantum computer can
forge Ed25519. No signed data holds a date for it, and no device decides it
by its clock. From the sunset, a client:

1. signs every structure under scheme 2;
2. accepts a scheme-0 event only if it is covered; an uncovered one is
   `Uncovered`, kept pending and accepted once a covering event arrives;
3. writes an anchor at once in every space it holds.

A replica keeps every scheme-0 event it accepted before its own sunset. A
replica that joins after it accepts earlier history only as far as scheme-2
events cover it. Whether a scheme-0 unit counts as evidence of a fork
follows the same rule ([events.md](events.md)).

## 4. Security considerations

- **Small-order, mixed-order and equivalent keys.** A small-order Ed25519
  key has signatures that verify for many messages under lenient
  verification, and cofactored and cofactorless verification disagree on a
  mixed-order key. An X25519 half with a torsion component makes an
  equivalent second encoding of an X-Wing key: `X25519(s, u(Q + T)) =
  X25519(s, u(Q))` for every clamped `s`. All are refused before any list or
  roster names them, so no rule that compares keys by bytes is fooled and no
  two verifiers disagree.
- **No combiner of Frasil's own.** X-Wing's combiner is part of its security
  proof; a hand-made `KDF(K1 || K2)` does not preserve IND-CCA security in
  general.
- **No weaker suite.** Every wrap is X-Wing, and a recipient with no X-Wing
  key receives nothing. A peer that strips or swaps an X-Wing key changes
  the keys' commitment, so they no longer hash to the holder's device ID,
  and no wrapper seals to them.
- **One name for all of a device's keys.** The device ID hashes the
  Ed25519 key and `kc`, and `kc` hashes the ML-DSA-65 and X-Wing keys, each
  length-prefixed after its own label. Finding a second key set for a
  device ID needs a second preimage of SHA-256, about 2^128 quantum work;
  two key sets under one device ID need a collision, about 2^85, which only
  helps the holder of both. So every record, grant or list that names a
  device ID names exactly one set of keys, whoever wrote it, and no
  verifier needs to trust where it found them.
- **Concatenated signatures.** A scheme-2 signature verifies only if both
  halves verify over the same `tbs`, so a forger must forge both. Nothing is
  derived from the two, so no combiner is needed.
- **Nobody can be framed.** An event ID hashes the unsigned event, so a
  second valid signature makes no new event. Showing a fork needs a second
  event that verifies under the author's keys, which are the keys its
  device ID commits to.
- **A quantum adversary at verification time** can make the Ed25519 half
  for any Ed25519 key it has seen, and nothing more. So it can:
  - sign any scheme-0 structure as any device, and so any unit before the
    classical sunset (below);
  - make a peer store events under any device's `ed` and `kc`, a peer
    checking only the Ed25519 half: a peer keeps one at a used `seq` as it
    keeps any conflict ([peers.md](peers.md)), and a replica finds its
    ML-DSA-65 half `BadSignature`, so it is never evidence and never
    applied;
  - sign scheme-2 events in full as a key set of its own that reuses a
    device's Ed25519 key beside its own ML-DSA-65 key. Their `kc` is its
    own, so their author is another device ID: it holds no grant, list
    entry or slot of the device, shares no chain with it, receives no wrap
    meant for it, and its events are never evidence against it.

  It cannot make a replica accept an authority event, a possession proof or
  fork evidence as a device's whose ML-DSA-65 key it does not hold: that
  needs ML-DSA-65 under the key whose hash is that device's `kc`, so a
  forgery of ML-DSA-65 or a second preimage of SHA-256. The same holds for
  every scheme-2 structure outside an event, each of which names its
  signer by device ID or by `ed || kc`.
- **Units before the sunset.** A quantum adversary can forge a unit's
  Ed25519 signature. The unit does not open from outside the space, but at a
  sequence number its device used it is still evidence of a fork, because
  evidence must not depend on keys held. An insider holding a content key can
  forge a unit that opens. Authority events stay safe.
- **Symmetric primitives against a quantum adversary.** Content, names,
  links, records at rest and every key derivation use 256-bit keys with
  XChaCha20-Poly1305, HMAC-SHA256 and HKDF-SHA256. Against a quantum
  adversary these are assumed to keep about 128 bits of security, the cost
  of Grover's search over a 256-bit key; nothing in the text rests on more.
- **Coverage rests on SHA-256.** An uncovered event passes for covered only
  with a second preimage of an event ID, about 2^128 quantum work. Two
  events under one ID need a collision, about 2^85 quantum work, which only
  the author could use, against its own events.
- **What this does not defend against:** a valid key held by someone who
  should not hold it; a key that leaks after it was listed; a compromised
  device, which signs both halves. A device ID shows which keys a device
  has, not that a device holds them: a record can name a device ID whose
  keys no single party holds, and such a device signs nothing and opens
  nothing ([roster.md](roster.md), "Security considerations").

## 5. Test vectors

[crypto.json](vectors/crypto.json):

- `labels`: section 2.6's labels in hex, the purpose and reserved strings,
  and that none equals or prefixes another. `sizes`, `suites`, `schemes`.
- `ed25519_keys`: valid keys; the eight small-order points; every
  non-canonical encoding with `y < 19`, with each sign bit; both encodings
  with `x = 0` and the sign bit set; three mixed-order points; a non-point;
  a 31-byte string; with each step's result.
- `x25519_keys`: valid keys; the five small-order u-coordinates; bit 255
  set; four values of `p` or more; a twist point; a mixed-order point; a
  31-byte string. `x25519_at_use`: a valid pair and two all-zero results.
  `xwing_keys`: one key accepted and four refused.
- `wycheproof`: Wycheproof's X25519 and Ed25519 files at commit
  `3fa63dd0344abb611f1fb1d77e119938603ea230`, with their SHA-256 and
  Frasil's verdict on each test; keys Wycheproof calls valid that are not of
  order `ℓ` are refused here, by design.
- `fixtures`: two devices built by section 2.3's fixture derivations, each
  with its `kc` and device ID; a recovery agent's `kc` with no X-Wing key.
- `device_ids`: the `kc` and the device ID of a device, a recovery agent and
  an administrator pseudonym, each hash's input written out, and a device's
  Ed25519 key beside another device's ML-DSA-65 and X-Wing keys, which is
  another device ID.
- `wraps`: a bundle wrap to a device, a passkey member, a recovery key and an
  invite key, with encapsulation randomness, info, `enc` and ciphertext.
  `wrap_refusals`: the X25519 suite, an unknown suite and version, a
  truncated wrap, a wrong length, another recipient, another space.
- `kind_policy`: section 3.8's table.
- `signatures`: a space genesis, a key event, an anchor and a device-list
  genesis under scheme 2, and units under schemes 0 and 2, each with `tbs`,
  the signed event and its ID, and for scheme 2 `m_ed`, `m_ml`, `M'` and
  both halves.
- `signature_refusals`: an unknown scheme; scheme 1; scheme 0 on a space
  event, a device-list event and an anchor; an Ed25519 half alone; wrong
  lengths; no ML-DSA-65 key held; an ML-DSA-65 key whose hash is not the
  event's `kc`; a stranger's forgery; a forgery that reuses a device's
  Ed25519 key under a `kc` of its own, accepted as another device ID, and
  the same forger's event under the device's own `kc` (`BadSignature`);
  each half over the other's message,
  or altered; the ML-DSA-65 half over bare `tbs`; halves of two events;
  another key or author; altered `tbs`; an unreduced `S`; a small-order
  `R`; a scheme-0 unit before and after the sunset, covered and not.
- `coverage`: units under an anchor, a unit after the last anchor, a forged
  branch no scheme-2 event names, and a unit held from before the sunset,
  each before and after the sunset.
- `mldsa65_known_answers`: a subset of Wycheproof's ML-DSA-65 signing (from a
  seed) and verification tests, at the same commit.
