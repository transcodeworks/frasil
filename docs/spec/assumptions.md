# Assumptions
Protocol 1. Informative: this document specifies nothing.

This page collects what the protocol rests on and the text does not itself
enforce: what a store, a random source, a clock, a transport, a platform and
the people who use Frasil are assumed to do. For each assumption it gives
the assumption, where the text relies on it, what breaks if it does not
hold, and what, if anything, detects the failure. Where it and a normative
document seem to differ, the normative document holds. It assumes
[overview.md](overview.md) and uses its terms. Claims of
[overview.md](overview.md)'s threat model, section 3, are cited by the
adversary's row.

Citations name a document and a section by number and title, as the other
documents cite each other. "Detected by" names a procedure of the text or
says that nothing detects the failure; a failure that only another party can
prove, such as a fork, is said to be provable and not detected.

Three kinds of reader start here:

- Someone who writes a store, a device-bound slot or an object provider
  reads sections 2, 3 and 7.
- Someone who writes a transport binding reads sections 6 and 3.
- Someone who writes a second implementation reads sections 4, 5, 10 and 11
  after the core documents, and checks that each assumption about the
  platform is met by the platform it runs on.

What the protocol does not assume is as much a part of its design. No
safety property rests on an always-on peer, on the network, on a clock, on
the order in which events arrive, or on an account's server (section 8).
Section 8 lists what liveness and availability do need.

## 1. Summary

| Area | The protocol assumes | Section |
|---|---|---|
| Storage | A returned commit is durable and atomic; a put replaces; reads see commits; records are returned as written or not at all | 2 |
| Randomness | The platform's source is unpredictable and does not repeat | 3 |
| Cryptography | The properties of nine primitives; which claims are classical | 4 |
| Time | A local timeline that ignores jumps while the device runs; no validity reads a clock | 5 |
| Transport | A proved identity, a unique channel binding, ordered frames, a lossy channel | 6 |
| Platform | An unlock key apart from the store; a slot no backup restores, where restore detection is claimed | 7 |
| Peers and network | Nothing for safety; some honest path for liveness | 8 |
| People | Codes are compared; members are shown by device ID | 9 |
| Application and adapters | Pure, order-independent adapters; names and times are claims | 10 |
| Implementations | One encoding, one order, the same limits and the same checks in the same order | 11 |

## 2. Storage

A device's store is the one place Frasil writes for its own use
([at-rest.md](at-rest.md), 1 "Overview"). The interface is
`get`, `scan` and `commit` over addresses and sealed records
([at-rest.md](at-rest.md), 2.1 "What the application provides").

### 2.1 What a store must do

| Assumption | Relied on in | If it does not hold | Detected by |
|---|---|---|---|
| **A commit that has returned is durable.** After a crash or restart the store holds every record it put and none it deleted. | [at-rest.md](at-rest.md), 2.1 "What the application provides" (`commit` is "durable when it returns"), 3.3 "Committing" ("Commit before sending"); [units.md](units.md), 3.13 "Heads, acknowledgements and durability" | A device has sent an event its store no longer holds. Its tip is older, so its next event takes the same `seq`: a fork, and the device is void from the fork point ([events.md](events.md), 3.5 "Chains and evidence of a fork", 3.7 "The penalty"; threat model, "A device that forks its chain"). A pseudonym's seeds and a claimed link's secret drawn for it are lost for good; a rotation's secrets come back by a delivery ([at-rest.md](at-rest.md), 3.6 "After a restore"; [keys.md](keys.md), 2.4 "Bundle wraps, space wraps and removal wraps"). | With a device-bound slot, a head older than the mark is `Restored`, and the device fetches its own newest event before it signs there ([at-rest.md](at-rest.md), 3.5 "Continuity", 3.6; [events.md](events.md), 3.8 "Restored devices sync before writing"). Under `never-restored` nothing detects it locally; any replica can prove the fork once it holds both events. |
| **One commit is applied whole or not at all,** with its deletes before its puts. | [at-rest.md](at-rest.md), 2.1, 3.3 ("One commit, one step": the event, its `outbox` record, its tip in the head and any secret drawn for it go in one commit) | A tip without its event is harmless, since the next `seq` comes from the tips ([at-rest.md](at-rest.md), 4 "Security considerations", "Rollback"). An event and outbox record without the advanced tip give the next event the same `seq`: a fork. An event without the seeds or the secret drawn for it leaves a pseudonym or an invite that its device cannot use. | As for a commit that was not durable. |
| **A commit that carries a precondition is one compare-and-write step,** or only one process of a device uses its store. | [at-rest.md](at-rest.md), 3.3 ("A store MAY accept a precondition"; a client SHOULD give the head it read, "so that two processes of one device never advance it from the same state"; "A store that accepts no precondition MUST be used by one process at a time") | Two processes advance the head from one state, both sign at one `seq`, and the device forks. | Nothing locally. A peer keeps both events and answers `conflict` ([peers.md](peers.md), 3.2 "Storing an event"), so every replica can prove the fork. |
| **A put replaces whatever the address held, and a record written twice is the record.** A delete of an address the store does not hold changes nothing. | [at-rest.md](at-rest.md), 2.1 ("A put replaces whatever its address held"), 3.3 ("an address it both deletes and puts holds the put record"); the `event` table's item is the event ID ([at-rest.md](at-rest.md), 2.5 "The head, events and keys"); [units.md](units.md), 3.13 (an event in the outbox "is offered again on every connection") | A store that kept two records at one address, or treated a resend of an event as a second event, would count a retry twice. A peer that treated an identical retry as a second event at one author and `seq` would answer `conflict` and never acknowledge it, and the device would count it not durable for good ([peers.md](peers.md), 3.2, "An identical retry"; [transport.md](transport.md), 3.12 "What a peer learns of a device, and acknowledgements"). | The peer's `conflict` answer, for that case. |
| **A read sees every commit that returned before it,** and a `scan(prefix)` returns every record under the prefix, in address order (bytewise). | [at-rest.md](at-rest.md), 2.1 ("A read, `get` or `scan`, sees every commit that returned before it began"); 3.4 "Forgetting a log, and re-keying" (a log is deleted "by their scope prefix"); 3.5 (the head is read at every open) | A `scan` that misses records leaves a forgotten log's records on the medium. None can be opened once the `log` record is deleted, so secrecy holds and space does not. A head read before a returned commit makes the device sign from tips it has already passed. | Nothing. |
| **A store is read and written only by the device that made it.** | [at-rest.md](at-rest.md), 1 ("Data moves to another device by sync, never by copying a store") | Two devices that hold copies of one store sign from the same tips and fork, as after a restore. | With a device-bound slot, a copied store finds no matching mark and is `Restored` ([at-rest.md](at-rest.md), 3.5, steps 3 and 5). |

### 2.2 What a store may do to records, and what is detected

A store, or whoever can read and write its medium, is not trusted
([overview.md](overview.md), section 3, "Whoever reads or replaces a
device's stored bytes"). Every record is sealed under keys that only the
unlock key reaches, with its address as associated data
([at-rest.md](at-rest.md), 2.3 "Keys, addresses and records").

| It does this | What follows | Detected by |
|---|---|---|
| Returns bytes it was not given, or changes a record | The record does not open: `Decrypt`. The client reports it and treats the record as missing ([at-rest.md](at-rest.md), 3.2 "Opening a record"). | `open`, step 5 |
| Moves a record to another address, table, log or item | It does not open, because the address is associated data; a record that opens at the wrong item fails the item-tag check, `Malformed` ([at-rest.md](at-rest.md), 2.3; 3.2, steps 5 and 6) | `open`, steps 5 and 6 |
| Forges a record | It cannot, without the seal key. "Only the device produces a record that it opens", so a result the device kept, such as a verified signature, "can be trusted when read back" ([at-rest.md](at-rest.md), 1 "Overview"). | Not applicable. With the unlock key beside the store, nothing protects this (section 7). |
| Deletes a record | Data is lost, never forged ([at-rest.md](at-rest.md), 4 "Security considerations", "Rollback"). A deleted `event` record of the newest event causes no fork. A deleted `log` record forgets the log for good ([at-rest.md](at-rest.md), 3.4). A deleted `head` is a store with no head: `Restored` ([at-rest.md](at-rest.md), 3.5, step 1). Keys, events and wraps come back by sync ([at-rest.md](at-rest.md), 3.6). | Only the `head` case; for the rest, the device finds a record missing |
| Replaces a record with an older record that was once valid at the same address | It opens. Only the head is covered by the mark. [at-rest.md](at-rest.md), 4, "Rollback", gives what an older `epoch`, `timeline`, `state` or `ack` record does: an epoch used again loses the device's own ephemeral frames at receivers until it passes theirs; an older reading without a known wall clock sets the timeline back, so waits last longer, and repeats a run number, so a stop rule can stop later by at most the time rolled back; an older `state` or `ack` loses what the newer one recorded, such as a base, a last completed sync or how much a peer acknowledged. None forges anything another party accepts. The format "has no counter" for the sealed device keys either ([at-rest.md](at-rest.md), 4, "An older sealing"). | Nothing at the device, except the head, by the mark; `Replayed` at receivers for an epoch |
| Rolls the whole store back to a backup | The head is older than the mark exactly when the device signed after the backup ([at-rest.md](at-rest.md), 3.5). The device is `Restored`, records the restore and syncs each log before it signs in it ([at-rest.md](at-rest.md), 3.6). | `continuity`, in `device-bound` mode |
| Rolls the store and the device-bound slot back together | The restore looks current. "The device may fork its chain where it signed since; only its own later events there are void" ([at-rest.md](at-rest.md), 4, "Rollback"). | Nothing locally; the fork is provable |
| Is restored from a backup after which the device signed nothing | It passes as current and "lacks nothing it signed" ([at-rest.md](at-rest.md), 3.5) | Not needed |
| Puts back an older sealing of the device keys | The older sealing opens, undoing a re-sealing under a new passkey. "The format has no counter: a replaced passkey is revoked on the device list" ([at-rest.md](at-rest.md), 4, "An older sealing"). | Nothing |
| Reads the medium without the unlock key | Sees the sealed device keys' header, how many logs, how many records of each table each log holds, record lengths and when records change. No log, event or object ID, peer, name or key ([at-rest.md](at-rest.md), 4). | Accepted leak (section 2.4) |

The restore mode is the application's statement of how much of this the
platform can detect ([at-rest.md](at-rest.md), 3.5 "Continuity"):

| Mode | The application states | A restore of the store alone | A restore of store and slot | Cost |
|---|---|---|---|---|
| `device-bound` | There is a slot no backup restores | Detected | Not detected | A sync after each restore, and after a crash between the mark and the commit |
| `never-restored` | The store is never restored from a backup | Not detected | Not detected | None. If the statement is false, a restored device signs from old tips and forks. |
| `none` | Neither | Every start is a restore | Every start is a restore | A sync of each log before it signs, at every start |

### 2.3 Order

| Order | Relied on in | If it is reversed or skipped | Detected by |
|---|---|---|---|
| **The mark for generation `g + 1` is written to the slot, durably, before the commit that holds an event a signer of the device signed, and the commit carries the head at `g + 1`.** | [at-rest.md](at-rest.md), 3.3 ("Mark before commit": "the slot is never behind a head that holds a signed event"), 3.5 | By `continuity`, step 4, a slot written after the commit can still hold the generation that an older backup's head holds, after a crash between the two writes; a restore of that backup then looks current although the device signed and sent events since. | Nothing |
| **An event is not sent before the commit that holds it has returned.** | [at-rest.md](at-rest.md), 3.3 ("Commit before sending") | The durable assumption above fails for an event that a peer already holds: the fork of 2.1. | As for a commit that was not durable |
| **A secret, and the record that uses it, go in one commit,** and a record that may be needed again is durable before the device acts on it: a `token` record is deleted in the commit that puts the `deposit` record holding it; a `vouched` record is committed before the device wraps for the member; a `next_endpoint` record is durable before the device binds the endpoint it names. | [at-rest.md](at-rest.md), 2.4 "Tables" (`token`, `deposit`); [ext-recovery-agent.md](ext-recovery-agent.md), 3.3 "The waiting period"; [ext-next-endpoints.md](ext-next-endpoints.md), 3.1 "Rotating" | A token in two records is spent twice and is refused the second time; a token in none is lost. A `Vouched` decision not kept is taken again, possibly later. A next key announced and not kept cannot be taken at the rotation, so members that were told it cannot follow the device. | Nothing; the token case ends in `TokenSpent` |
| **An ephemeral epoch `e + 1` is committed before a device uses it.** | [at-rest.md](at-rest.md), 3.3; [ext-ephemeral.md](ext-ephemeral.md), 3.2 "Epoch, counter and replay" | A restart reuses `e`, and receivers that remember the higher counter refuse the device's frames as `Replayed` until it passes them. | `Replayed` at receivers |
| **The `log` record is deleted first, in one commit, then the log's other records by their scope prefix.** | [at-rest.md](at-rest.md), 3.4 | Deleted last, a `log` record that survives a crash would leave records that still open. Deleted first, a crash leaves only records that cannot be opened. | Nothing |

### 2.4 What a store may leak

A store may show that it holds records, how many, how large and when they
changed; the count of logs; and the header of the sealed device keys, with
the device ID and person ID ([overview.md](overview.md), section 3 and 4.3
"Members and others"; [at-rest.md](at-rest.md), 4). It may not show an ID,
a peer, a name or a key. These leaks are accepted and not defended. Nothing
else is allowed to leak, and a store that logs, indexes or replicates its
contents beyond the medium it is given is outside the model.

Objects the application holds in place of their sealed chunks are not
defended at rest: their plaintext is readable from a stolen or imaged disk
with no unlock key, and removing a member's access to a log leaves the
files in place ([at-rest.md](at-rest.md), 4; 3.9 "Held objects").

## 3. Randomness

The platform's source is assumed to be unpredictable and not to repeat a
draw. The text names it as "the operating system's cryptographically secure
source", and requires that "an implementation without a working source MUST
refuse to generate keys, seal or wrap" ([crypto.md](crypto.md), 2.1
"Primitives"). It assumes the source never repeats, also across a restore of the
machine's state, such as a virtual machine resumed from a snapshot or a
process image copied after it drew: a source that would repeat there "is
not a working source until the platform reseeds it" ([crypto.md](crypto.md),
2.1). A store restored from a backup is a different case, which
[at-rest.md](at-rest.md), 3.6 "After a restore", covers. Where a document gives a draw a form that takes its
bytes, so that vectors can drive it, that form is for tests.

Where the text says what a bad draw costs, this page says so. Where it does
not, the row gives the property that is lost as the construction defines
it, and says so ("the text does not say").

| Draw | Relied on in | If it is predictable | If it repeats | Detected by |
|---|---|---|---|---|
| **A device's three seeds and its store secret,** each drawn independently | [crypto.md](crypto.md), 2.3 "A device's keys"; [at-rest.md](at-rest.md), 2.2 "Sealed device keys" | Whoever predicts a seed holds that key: signs as the device, opens its wraps, or opens its store. | Two devices with one seed hold one key set and one device ID. | Nothing. "A device ID shows which keys a device has, not that a device holds them" ([crypto.md](crypto.md), 4 "Security considerations"). |
| **A log key `L` (32 bytes), the store ID (16), a mark's nonce and every record's nonce (24)** | [at-rest.md](at-rest.md), 2.3, 2.5, 2.6 "The mark" | A predictable log key opens that log's records for whoever can read the medium. | A repeated 24-byte nonce under one seal key voids the AEAD's guarantees for those two records. "Nonces are random per seal, 24 bytes, so repeats stay negligible without state" ([at-rest.md](at-rest.md), 4). | Nothing |
| **A rotation's secrets `k_R`, `w_R` and `g_R`** | [keys.md](keys.md), 2.1 "Rotations and states", 2.2 "Derivations" | Whoever predicts `k_R` reads everything sealed under the state, and derives its read credential; whoever predicts `w_R` stores as a writer. A merged key is unpredictable only if some input is: "Each input passes through HMAC under its own uniformly random key". | Two rotations share a content key. The text does not say more. | Nothing |
| **XChaCha20-Poly1305 nonces (24 random bytes)** of space-event bodies, units, key links, sealed names, invite drops, skeleton bindings, ephemeral frames, local-network announcements and space files | [keys.md](keys.md), 2.5, 2.6, 2.8; [units.md](units.md), 2.4 "The seal"; [ext-invite-links.md](ext-invite-links.md), 2.3; [peers.md](peers.md), 2.5; [ext-ephemeral.md](ext-ephemeral.md), 2.5; [transport.md](transport.md), 2.9; [ext-space-files.md](ext-space-files.md), 2.4 "The way in" | The nonce is public in every case, so predicting it costs nothing. | A body key is derived per event from its log, author and `seq`, so a nonce repeats under that key only if one `seq` is sealed twice, which a fork or a re-sign after a restore does. Under the long-lived keys (the ephemeral key, the metadata key, the local-network key) a repeat voids the AEAD's guarantees for the two messages. The text does not say more. | Nothing |
| **X-Wing encapsulation (64 random bytes)** | [crypto.md](crypto.md), 2.1 | A predictable draw gives the wrap's shared secret to whoever predicts it: the keys inside are read. | A repeated draw gives two wraps to one key the same shared secret. The text does not say more. | Nothing |
| **The member handshake's `nonce` and `nonce_R` (32 bytes), and the 15 decoy tags of an offer** | [transport.md](transport.md), 2.6 "Member handshake values", 3.2 "The member handshake: the offer" | Decoy tags that a non-member can tell from real ones make an offer tell a non-member something ([rationale.md](rationale.md), 7.4 "Transports and storage at rest"). | "Two offers of one attach sharing a tag" ([transport.md](transport.md), 4 "Security considerations", "What each binding stops"). | Nothing |
| **A device-to-peer connection's `nonce_P` and `nonce_C`** | [transport.md](transport.md), 3.10 "The device-to-peer handshake"; [peers.md](peers.md), 2.2 "The credential proof" | A proof is bound to its connection by the channel and both nonces. On the server binding the channel is a function of the origin alone, and "the nonces of section 3.10 make each binding unique" ([transport.md](transport.md), 3.15 "The server binding"). A predictable nonce lets a later connection reuse a recorded proof. | A repeated pair makes `binding` equal on two connections: a credential proof held by anyone, a peer included, serves on the second. | Nothing. A peer "keeps no nonce store". |
| **An admission exchange's `request` (16), `nonce_J` and `nonce_I` (32) and its fresh X-Wing keys** | [admission.md](admission.md), 2.2 "Exchange values", 4 "Security considerations" ("One guess") | A relay that predicts a nonce knows a code before it chooses what to send, and the six digits no longer give it one guess in a million. "This rests on both nonces and `request` coming from a secure random source." | A repeated `request` names an exchange mailbox twice. A repeated nonce repeats a code. | The people comparing the codes (section 9), for a relay that guessed wrong |
| **An invite's secret (32 bytes)** | [ext-invite-links.md](ext-invite-links.md), 2.1 "The secret, its keys and the link" | Whoever predicts it derives the invite key `K`, the drop's locator and key, and can claim: the link is a bearer credential. | Two invites with one secret are one key and one drop. | Concurrent claims void each other visibly ([ext-invite-links.md](ext-invite-links.md), 3.4 "Raced claims"). A claim made first goes unnoticed until a code is compared. |
| **An administrator pseudonym's two seeds, and the slot token (32 bytes)** | [peers.md](peers.md), 2.5 "Skeleton derivations" | Whoever predicts the seeds signs as the administrator slot, and can ask for erasures. A pseudonym is drawn "never derived from its device keys or from any key a peer could test": one a peer can test is one it can link to a device. | Two slots with one token are one slot. | Replicas find a foreign binding, and an administrator disowns the slot ([peers.md](peers.md), 4 "Security considerations") |
| **Identifiers: a stream's salt and the system stream's ID (16), a genesis's `nonce` (16), a drive entry's ID (16), a session value (16), a library ticket's ID (16), a deposit ID (16)** | [units.md](units.md), 2.6 "Streams"; [roster.md](roster.md), 2.2 "The roster part"; [keys.md](keys.md), 2.6 "The space event's body"; [ext-drive.md](ext-drive.md), 2.1 "Values"; [ext-guests.md](ext-guests.md), 2.1 "The guest preset"; [ext-libraries.md](ext-libraries.md), 2.2 | A stream ID is "never derived from a name" ([units.md](units.md), 2.6): a predictable one can be tested against guesses by a peer. | Two documents of one type with one salt are one stream. A repeated entry ID is one entry. The text does not say more for the genesis `nonce`, which "binds the genesis in place of its log" ([keys.md](keys.md), 2.1). | Nothing |
| **A deposit token's `nonce` (32), its blind, the peer's key `seed` (32) and a proof's scalar** | [ext-deposit-tokens.md](ext-deposit-tokens.md), 2.1 "The VOPRF", 2.2 "Deposit keys", 2.4 "Tokens", 4 "Security considerations" | A blind that is predictable gives up unlinkability: "the blind is uniform and known only to the device". A predictable key seed lets anyone compute the key and forge tokens, which spends the token budget and fills mailboxes to their caps. A predictable proof scalar, or one used twice under one key, gives the key itself to whoever holds the proof: as for a predictable seed ([ext-deposit-tokens.md](ext-deposit-tokens.md), 4, "The proof's scalar is a secret"). | Two tokens with one nonce are one token: the second deposit is `TokenSpent`. | `TokenSpent` at the peer |
| **An ephemeral epoch's random part (below 2^32), a receiver's nonce (16), a connection's origin (8)** | [ext-ephemeral.md](ext-ephemeral.md), 3.2, 3.3 "Freshness across restarts", 3.7 "Relaying" | A predictable receiver nonce lets a relay build a message that passes the freshness check: a command that must never run twice runs again. | A repeated epoch after a restore drops the device's frames as `Replayed` until it passes the receivers' mark. | `Replayed`, `Stale` |
| **A device-signed request's nonce (16)** | [ext-app-requests.md](ext-app-requests.md), 2.2 "The statement", 3.5 "Replays within the window" | None for secrecy. | A stateful verifier refuses an honest request that repeats a nonce as `Replayed`. | `Replayed` |
| **A member endpoint key and its next seed (32)** | [ext-next-endpoints.md](ext-next-endpoints.md), 3.1; [transport.md](transport.md), 3.16 "The iroh binding" | Keys that can be predicted can be followed: "A next key is random and independent of every earlier key". | A device MUST NOT take a seed it took before. The text does not say more. | Nothing |
| **Jitter and random waits** (reconnection, the moment of a deposit draw) | [transport.md](transport.md), 3.10; [ext-deposit-tokens.md](ext-deposit-tokens.md), 3.12 "When to draw, and how many" | Peers' load or a draw's timing follows a pattern. This costs availability and privacy of timing, not safety. | | Nothing |

ML-DSA-65 and Ed25519 signing need no randomness: Ed25519 signs
deterministically and ML-DSA-65 SHOULD, with `rnd` set to 32 zero bytes. A
signer that hedges against fault attacks draws `rnd` from the source
([crypto.md](crypto.md), 2.5 "Signature schemes").

## 4. Cryptography

### 4.1 The property assumed of each primitive

| Primitive | Property assumed | Relied on in | If it fails |
|---|---|---|---|
| SHA-256 | Collision resistance, second-preimage resistance, and preimage resistance, used for IDs, commitments and coverage (4.3) | [crypto.md](crypto.md), 2.3, 4 "Security considerations"; [events.md](events.md), 2.5 "What is signed, and the event ID" | Section 4.3 gives each structure. |
| HMAC-SHA256 | A PRF under a secret key; a MAC | [keys.md](keys.md), 2.2 ("a uniformly random PRF key"); [transport.md](transport.md), 2.6 (offer tags are "a PRF output under a key a non-member lacks"); [units.md](units.md), 2.8 "Objects" (object IDs and chunk nonces) | A tag a non-member can compute makes an offer tell it something; a merge key stops being unpredictable; an object ID or a synthetic nonce can be predicted. |
| HKDF-SHA256 | Extract-then-expand: outputs under distinct labels or infos are independent | [identity.md](identity.md), 4 "Security considerations", "Derivations"; [at-rest.md](at-rest.md), 2.3 | Keys derived from one secret for different purposes stop being independent: a seal key and a tag key, a read credential and an upload key. |
| XChaCha20-Poly1305 | Confidentiality and integrity under a key and a 24-byte nonce that does not repeat. It does not commit to its key, and the text does not assume it does. | [crypto.md](crypto.md), 2.1; [units.md](units.md), 2.4 ("The commitment binds the seal to one body key, because XChaCha20-Poly1305 does not commit to its key"); [keys.md](keys.md), 2.6 | Without the commitment an author could make a sealed part that opens differently under different keys. A nonce that repeats is section 3. |
| Ed25519, strict verification | Unforgeability against a classical adversary; one verdict on every key and signature, because verification is strict and every key is checked where it enters | [crypto.md](crypto.md), 3.1 "Ed25519 public keys", 3.4 "Where keys are checked", 3.6 "Strict Ed25519 verification" | A lenient verifier and a strict one disagree on a small-order or mixed-order key, and "verifiers that disagree on a key diverge on every event it signs" ([rationale.md](rationale.md), 8 "Post-quantum choices"). A forger signs scheme-0 structures: section 4.2. |
| ML-DSA-65 | Unforgeability against a classical and a quantum adversary | [crypto.md](crypto.md), 2.5; [rationale.md](rationale.md), 8 | A scheme-2 signature "holds while either holds": a break of ML-DSA-65 alone leaves Ed25519, a break of both gives up every authority event. |
| X-Wing (ML-KEM-768 with X25519) in HPKE | IND-CCA security while either ML-KEM-768 or X25519 holds; no combiner of Frasil's own | [crypto.md](crypto.md), 1 "Overview", 4 | Every wrap is readable by whoever breaks both. Recorded wraps are read later. |
| ristretto255 VOPRF (RFC 9497) | One-more-gap Diffie-Hellman for unlinkability; the discrete logarithm for unforgeability | [ext-deposit-tokens.md](ext-deposit-tokens.md), 4 | A forger deposits as if it paid, up to the mailbox caps and the token budget. Unlinkability does not rest on a hardness assumption for a recorded issuance. |
| TLS 1.3's exporter (RFC 9266), and WebPKI for the server binding | On the iroh binding, a channel value unique to a session; on the server binding, a certificate only the origin's holder can obtain, with the channel fixed to the origin and the connection's nonces making each `binding` unique | [crypto.md](crypto.md), 2.1; [transport.md](transport.md), 2.1, 3.15, 3.16 | Section 6. |

### 4.2 What is classical, what is hybrid, and what a quantum adversary can do

| Claim | Holds against a quantum adversary? | Rests on | Relied on in |
|---|---|---|---|
| Confidentiality of a wrap, a space wrap and a removal wrap | Yes, while either ML-KEM-768 or X25519 holds. A quantum adversary recording now learns nothing. | X-Wing | [crypto.md](crypto.md), 1, 4; threat model, "A quantum adversary recording now" |
| Content, names, links and records at rest | Yes, at about 128 bits: 256-bit keys under Grover's search ([crypto.md](crypto.md), 4, "Symmetric primitives against a quantum adversary") | XChaCha20-Poly1305, HKDF, HMAC | [keys.md](keys.md), 4 "Security considerations", "Post-quantum"; [crypto.md](crypto.md), 4 |
| Authority events (device-list events, space events, anchors, storage events), possession proofs and fork evidence | Yes, because each needs both halves, ML-DSA-65 under the key the device ID commits to. An event signed in full under an ML-DSA-65 key of the adversary's own is another device's and never evidence against the device. | ML-DSA-65 (Ed25519 alone does not hold); SHA-256 for the device ID | [crypto.md](crypto.md), 2.5, 3.8 "Which structures carry which scheme", 4; threat model, "A quantum adversary at verification time" |
| Units, until the classical sunset | No. A forged unit at a used `seq` voids its device, and an insider holding a content key can forge a unit that opens. | Ed25519 | [crypto.md](crypto.md), 4 ("Units before the sunset"); [rationale.md](rationale.md), 8, 11 "Known limits" ("Before the sunset") |
| Scheme-0 structures verified once, at once: account links, head statements, the admission transcript, a device's binding to a connection (`Identify`), credential proofs, merge statements, ephemeral messages, library tickets and device-signed requests | No. A later forgery is never verified. | Ed25519 | [crypto.md](crypto.md), 3.8 |
| Storage credentials | No. A forger fetches ciphertext and spends quota, and decides nothing a replica reads. | Ed25519 | [rationale.md](rationale.md), 1.2 "A peer adds availability, never trust"; [peers.md](peers.md), 4 |
| Deposit tokens | No. Forged tokens deposit up to the mailbox caps and the token budget. | The discrete logarithm in ristretto255 | [ext-deposit-tokens.md](ext-deposit-tokens.md), 4 ("Classical") |
| The transport's own handshake and encryption | No claim: the key exchange is what the TLS session negotiates, which may be classical. A recording later read gives what the connection carried inside TLS: what a peer sees anyway, and on a member connection which devices attached to which spaces; no content, name or key ([transport.md](transport.md), 4, "A quantum adversary and the transport"). | TLS 1.3 with Ed25519 raw keys, or WebPKI | [transport.md](transport.md), 3.15, 3.16, 4 |
| Coverage by anchors | Yes, to a second preimage of SHA-256 (about 2^128 quantum work) | SHA-256 | [crypto.md](crypto.md), 3.9 "Anchors and coverage", 4 |

**The classical sunset.** The text assumes that the sunset, a future protocol
revision after which a scheme-0 event counts only if a scheme-2 event covers
it, comes "before a quantum computer can forge Ed25519". No signed data
holds a date for it and no device decides it by its clock
([crypto.md](crypto.md), 3.10 "The classical sunset"). If a forgery of
Ed25519 arrives first, the row for units above is what a space is left with,
and nothing in the protocol shows that it has happened. Anchors written
before the sunset are what let a space that went quiet be verified after it
([crypto.md](crypto.md), 3.9).

### 4.3 Where a hash is an identity or a commitment

| Structure | What is assumed | If it fails | Relied on in |
|---|---|---|---|
| Event ID, over the unsigned event | No two events share an ID and no event has two. A second preimage gives an uncovered event the ID of a covered one. | "An ID shared by two events, or two IDs for one event, would let a peer fake a fork or hide one." Collisions need about 2^85 quantum work and "only the author could use" them, "against its own events". | [events.md](events.md), 2.5, 4 "Security considerations"; [crypto.md](crypto.md), 4 |
| Device ID, and the keys commitment `kc` inside it | Exactly one key set per device ID. A second key set needs a second preimage, about 2^128 quantum work; two key sets need a collision, about 2^85, "which only helps the holder of both". | A record, grant or list could name a device ID for keys other than the device's. | [crypto.md](crypto.md), 2.3, 4 |
| Space ID (the genesis's event ID) and person ID (the first list event's ID) | As for an event ID | Two spaces or persons with one name | [events.md](events.md), 2.5 |
| Stream ID (16 bytes of a hash of the adapter type and a salt) | A writer cannot find another opening for a stream ID: "another opening for a 128-bit stream ID is a second preimage" | A writer backdates a unit of another type into a stream | [units.md](units.md), 2.6, 4 |
| An object's locator digest | A second preimage of the object | Junk under a genuine object's ID is "another locator, never named" only because the digest differs | [units.md](units.md), 2.8, 4 |
| A rotation's commitments, a body key's commitment, the twin commitment, a deposit key's ID | Binding | A sealed part that opens differently under different keys; a twin that is not the twin | [keys.md](keys.md), 2.6; [peers.md](peers.md), 2.5 |
| A fingerprint (120 bits) | "About 2^90 work per success against 2^30 targets" | A relay finds keys whose fingerprint matches a genuine one's | [identity.md](identity.md), 2.9 "Fingerprints", 4 |
| The admission code (six digits of a hash) | One guess, at 10^-6 | See section 3 and section 9 | [admission.md](admission.md), 2.3, 4 |

## 5. Time

### 5.1 What a device's timeline must do

| Assumption | Relied on in | If it does not hold | Detected by |
|---|---|---|---|
| **The monotonic clock never jumps and counts while the device runs,** through a suspend where the platform allows. | [overview.md](overview.md), 6.2 "Clocks", 6.3 "The local timeline" | The timeline is wrong, and every timer that counts on it is wrong with it. After a suspend in which the clock stopped, the timeline adds the wall clock's advance if the wall clock is known and nothing if it is not. | Nothing |
| **The wall clock is "known" only when the platform says it is synchronised or backed by a battery-powered clock.** | [overview.md](overview.md), 6.2 | A clock reported known that is not adds a wrong advance to the timeline across a restart. | Nothing |
| **A change to the wall clock while the device runs is not counted.** While it is off, the timeline adds the advance, never less than zero, and nothing without a known wall clock. | [overview.md](overview.md), 6.3 | See 5.3 | Nothing; threat model, "Whoever moves a device's clock" |
| **A reading is kept at least once a minute while the device runs, and at shutdown.** After a crash, the time since the last kept reading "counts once, as time off". | [overview.md](overview.md), 6.3; [at-rest.md](at-rest.md), 3.3 ("The device keeps its reading in `timeline` at least once a minute") | A reading that was not kept is not there to count: the time since the last kept reading counts once, as time off, and only if the wall clock is known. A restore from a backup brings back the reading and the first sights, and counts the time since as time off ([at-rest.md](at-rest.md), 3.6 "After a restore"). | Nothing |
| **A first sight is kept with the event and never moved,** and a timed rule counts from the deciding device's own first sight, never from a time any party states. | [overview.md](overview.md), 6.5 "First sight"; [ext-recovery-agent.md](ext-recovery-agent.md), 3.4 "The late verifier, and no witness" | A device that adopts another party's time ends a wait because that party says it should end: "one colluding member could end every verifier's wait" ([rationale.md](rationale.md), 5.2 "Recovery and verification"). | Nothing |
| **A peer keeps a timeline by the same rules, per shard when it runs on several machines, and never counts faster than the lower estimate of any machine that stored the request.** A space moved between shards keeps its own timeline. | [overview.md](overview.md), 6.7 "Policy values and a peer's clock" | An erasure, a collection or a release is reclaimed before the timeout, and a destructive act cannot be undone ([rationale.md](rationale.md), 1.4 "Destructive acts wait"). | Nothing at the peer. A device that sees it serve less than it acknowledged reports `RolledBack`. |

### 5.2 Which rules use which estimate

A rule that waits before acting uses the lower estimate, and one that stops
acting after a time uses the upper ([overview.md](overview.md), 6.4 "The two
estimates"). The timers are listed in [overview.md](overview.md), 6.8 "Every
timer".

| Estimate | Rules |
|---|---|
| Lower, on the deciding device's timeline | `gap_key_timeout` (a restored member's gap keys, the content of a refused unit, a snapshot, erased content dropped without stability), `rotation_step`, `anchor_interval`, `replica_release_retention`, `agent_waiting_period`, `version_compaction_interval`, `link_lifetime`'s and `session_lifetime`'s maximum at an administering device |
| Lower, on the peer's timeline | `erasure_timeout` (T), `release_retention`, `orphan_grace`, `file_version_retention`, `detached_grace`, `allowance_window` |
| Upper | `bounded_window`, `online_freshness`, `token_period`. Across a restart with no known wall clock the upper estimate is unbounded, so the time counts as over. |
| The monotonic clock | `handshake_deadline`, `probation`, `gossip_interval`, `present_retry`, `reconnect_wait`, `pairing_deadline`, the ephemeral deadlines |
| The device's or the peer's timeline | `endpoint_rotation`, `mailbox_retention`, `uncollected_retention` |
| The receiver's wall clock, never the timeline | The five instants of [overview.md](overview.md), 6.6 "Instants exchanged between parties" |
| The verifier's wall clock | A service verifier's waiting period for a member rooted in an agent ([ext-app-requests.md](ext-app-requests.md), 3.3 "Who signs"): a verifier keeps no timeline, so a clock moved forward after its first sight shortens the wait, while it runs or not ([ext-app-requests.md](ext-app-requests.md), 4) |

### 5.3 What a clock moved while the device is off can do

"A wrong wall clock errs the unsafe way only if it was moved while the device
was off" ([overview.md](overview.md), 6.4). By 6.3, a wall clock moved
forward while the device is off adds the jump to the timeline, and one moved
back adds nothing. The consequences follow from the estimates:

| Moved | A rule that waits (lower estimate) | A rule that stops (upper estimate) |
|---|---|---|
| Forward while off | It ends early by the jump. The device wraps gap keys, vouches for an agent's device, reclaims an erasure or a release, or collects, before the full period. These are the device's own acts; no replica refuses an event for them. | It stops sooner. |
| Back while off | It lasts as long as before. | The device writes or deposits for longer, "by the time it was set back" ([ext-guests.md](ext-guests.md), 4 "Security considerations"). |
| While running, either way | Not counted | Not counted |

The claims that rest on it are the threat model's row for a recovery agent
("waits a period at each verifier"), the stability and timeout rows of the
removed administrator, the bounded window and the online-only policy.
Nothing detects a moved clock.

### 5.4 No validity depends on a clock

"No validity check reads a clock, and no verdict rests on a time that
signed data holds" ([overview.md](overview.md), 6.1 "The principle").
Signed data does hold times: a grant's `expires_at`, the five instants of
5.5, and a writer's times in content; each row below says what decides by
them. A clock decides only a party's own next act: whether a device
signs, wraps, writes, claims or tells its person something, and what a peer
does with its own storage.

| Assumption | Relied on in | If it does not hold |
|---|---|---|
| Policy values are checked against ranges, never against a clock, and concurrent policies merge to the stricter value | [overview.md](overview.md), 6.7; [roster.md](roster.md), 2.6 "The space policy" | Replicas with different clocks would merge differently. |
| `expires_at` of an invite grant and of a guest's grant tell administering devices when to end the grant by a signed event; no replica compares them with a clock | [overview.md](overview.md), 6.1; [ext-invite-links.md](ext-invite-links.md), 1 "Overview"; [ext-guests.md](ext-guests.md), 1 "Overview" | The grant lasts until an administering device signs the end. Members keep wrapping for the guest until then. |
| A recovery agent's waiting period gates wraps, never validity | [rationale.md](rationale.md), 5.2; [ext-recovery-agent.md](ext-recovery-agent.md), 3.3 | Replicas "with different clocks would merge differently". |
| A time a writer states is a claim: a Records change's `time`, a drive's `added`, `at` and `trashed` | [adapter-records.md](adapter-records.md), 4 "Security considerations"; [ext-drive.md](ext-drive.md), 4 | A hostile clock misleads the screen and nothing else. |
| No `seq` starts from a clock | [rationale.md](rationale.md), 2.5 "Per-device chains"; [units.md](units.md), 3.13 | It would be a timestamp, and would not stop a restored device from forking. |

### 5.5 The five instants

The receiver of an exchanged instant is assumed to hold a wall clock within
the skew of the sender's. The skews are 60 seconds for an admission code
request, an invite, a guest session, a library ticket and a device-signed
request ([overview.md](overview.md), 6.6, 6.8).

| If the receiver's wall clock | Then |
|---|---|
| is not known | `Expired`: "so no device claims on a time it cannot read". An application MUST NOT give `expires_at` to an invite or a guest meant for a device with no wall clock ([ext-invite-links.md](ext-invite-links.md), 4 "Security considerations"; [ext-guests.md](ext-guests.md), 4). |
| is fast by more than the skew | Honest requests are refused, "visibly" ([ext-app-requests.md](ext-app-requests.md), 4 "Security considerations"). A peer's clock fast or slow refuses good tickets, or accepts one for at most `ticket_lifetime` and `ticket_skew` beyond its life ([ext-libraries.md](ext-libraries.md), 4 "Security considerations"). |
| is slow | A signed request's replay window is longer by the amount. |

None of these decides anything a replica reads.

## 6. The transport

### 6.1 What a binding must provide

A binding maps a transport onto four requirements, and "Frasil needs nothing
else from it" ([transport.md](transport.md), 2.1 "What a transport
provides").

| Requirement | If it does not hold | Detected by |
|---|---|---|
| **T1. An identity proved by the transport's own handshake:** on a member connection each end proves an endpoint key; on a device-to-peer connection the peer proves a WebPKI origin or an endpoint key and the device proves nothing | A device takes one party for another. Acknowledgements are kept per peer, under the origin the connection's `channel` binds, so an impostor's acknowledgement would count as the peer's and the event would be counted durable ([transport.md](transport.md), 3.12). On a member connection the endpoint key is never the device's key: `Identify` binds the device ID to the connection and the roster check decides admission. | The roster check, for members. For a peer, `RolledBack` or `Withheld` once the device sees what it was told was kept missing ([units.md](units.md), 3.13). |
| **T2. A channel binding:** 32 bytes, equal at both ends, unique to the session, fixed before either end sends a Frasil message, and different on the two sessions of anyone in the middle. "Everything either end proves is bound to it." A binding that cannot read a value unique to its session may fix the channel to an identity only its holder can terminate a session as, and then carries device-to-peer connections only, whose nonces make each `binding` unique. | See 6.2. | See 6.2 |
| **T3. Reliable, ordered frames** of up to 1,056,768 bytes | The handshakes fail or restart. Agreement does not depend on arrival order ("Replicas that hold the same events reach the same state, in whatever order they received them", [overview.md](overview.md), 1 "Goals and non-goals"), so frames lost or reordered cost sync, not a verdict. | `Malformed`, a deadline |
| **T4. A lossy channel ahead of bulk** that never waits behind sync or object frames | Ephemeral traffic is late or lost. It is never persisted ([ext-ephemeral.md](ext-ephemeral.md)). | Nothing |

A binding that cannot meet T2 between two devices, such as a server that
relays bytes it can read, MUST carry only device-to-peer connections
([transport.md](transport.md), 2.1).

### 6.2 The channel binding must be unique

What the channel is bound into, and what that stops
([transport.md](transport.md), 4 "Security considerations", "What each
binding stops"): "replaying a message or a proof into another connection, at
the same or another peer; a party in the middle passing messages between its
two sessions". The channel enters every offer tag, the transcript, `Identify`
and the peer `binding`, and the admission code of a nearby pairing
([admission.md](admission.md), 2.3 "The transcript and the code"; 3.7
"Nearby pairing").

If it is not unique, or is equal on the two sessions of a party in the
middle, the bindings above stop doing what the text says for them:

- A message or proof recorded on one connection is accepted on another. A
  credential proof is the case the text names: a peer "that keeps one cannot
  present it elsewhere", and that holds only while the channel and the two
  nonces are fresh.
- A party in the middle can pass messages between its two sessions, which
  the channel in the tags, the transcript and `Identify` is there to stop.
- The channel enters the admission code "so a relay joining two channels
  changes both codes"; with a channel equal on both, joining them changes
  neither.

Nothing detects a non-unique binding. Its uniqueness is the transport's.

On the server binding the channel is `SHA-256("frasil/server-channel/v1" ||
field(origin))`, the same for every connection to an origin. A browser cannot
read its connections' TLS exporter, so the binding "relies on WebPKI: only
the origin's holder terminates the session, and the nonces of section 3.10
make each binding unique" ([transport.md](transport.md), 3.15 "The server
binding"). There, uniqueness comes from WebPKI and from the two fresh
nonces of section 3, not from the channel. The server binding carries
device-to-peer connections only: "Member handshakes never run over the
server binding" ([transport.md](transport.md), 4). Someone who obtains a
certificate for the origin can terminate the connection as the peer, which
the text counts as already within a peer's power ([transport.md](transport.md),
4, "A peer's endpoint keys").

On the iroh binding the channel is RFC 9266's exporter over the QUIC
connection's TLS 1.3 session ([transport.md](transport.md), 3.16 "The iroh
binding"). Its uniqueness is TLS's.

## 7. The platform

| Assumption | Relied on in | If it does not hold | Detected by |
|---|---|---|---|
| **The unlock key is kept apart from the store.** A kind 2 key is 32 bytes of high entropy, from a keychain, a secure element or a hardware token; never a password; never stored in the clear beside the sealed device keys. | [at-rest.md](at-rest.md), 2.1; 4 "Security considerations" ("A kind 2 key kept in a file beside the store, or backed up with it, protects nothing"); threat model, "Whoever reads or replaces a device's stored bytes" ("An unlock key kept beside the store") | Whoever reads the store opens the sealed device keys, so holds the device's three seeds and its store secret: it signs as the device, opens its wraps, and can write records that open, including records that say an event's signatures "verified". | Nothing |
| **A passkey's PRF output is stable for the same input,** and the application keeps the ceremony the text lists: user verification at every assertion, the constant `prf_input`, a discoverable credential whose user handle is the person ID and personal space ID, the output kept on the client. | [identity.md](identity.md), 2.7 "Passkey members", 3.15 "The passkey ceremony" ("Frasil never sees the WebAuthn ceremony, so it cannot check these") | An unstable output derives keys that no list names. It is caught before a list member is added ("An unstable PRF output is caught before a list member is added"), and a later change gives `NotOnList`. The text does not say what a skipped step of the ceremony costs; the PRF output is the secret every passkey key derives from. | `NotOnList`; nothing for the ceremony |
| **A device-bound slot, where restore detection is claimed,** holds the 65-byte mark durably, in a place no backup restores, such as a keychain item bound to the device and left out of backups | [at-rest.md](at-rest.md), 2.1, 3.5; [events.md](events.md), 3.8 | A slot that a backup restores makes a restored store look current: the device may fork where it signed since. A slot that is not durable makes a crash look like a restore, which costs a sync. | Nothing locally; the fork is provable |
| **`never-restored` is stated only where it is true.** A browser's storage is the text's example. | [at-rest.md](at-rest.md), 3.5 | A restore is never detected (section 2.2). | Nothing locally |
| **Whoever controls an unlocked device is outside the model.** | [overview.md](overview.md), 1 (non-goals: "protecting a device from whoever controls it while it is unlocked"); [at-rest.md](at-rest.md), 4 ("code running in the application while the device is unlocked; memory the operating system swaps or dumps; the application's own copies") | The attacker holds the keys and the open store, reads everything the device holds, and signs as the device until it is revoked ([overview.md](overview.md), section 3, "A thief holding one of a person's devices"). | Revocation by the person's other devices |
| **The medium forgets what a delete removes, or the log is re-keyed.** | [at-rest.md](at-rest.md), 3.4, 4 ("Remanence") | Someone who later obtains the unlock key and the medium's old blocks reads deleted records. Forgetting a log removes its `log` record, which makes the rest unopenable; a re-key makes what an erasure removed unreadable. | Nothing |
| **The browser does not send a link's fragment to a server.** | [ext-invite-links.md](ext-invite-links.md), 2.1 | The invite's secret reaches a server, and anyone with it can claim. | Concurrent claims void each other; a claim made first goes unnoticed until a code is compared. |
| **The application renders text as text.** A display name, an admission code and a label are shown as text, never as markup; a nearby name has its control characters removed. | [admission.md](admission.md), 4; [transport.md](transport.md), 2.9 "Local-network packets" | Markup in a name or a code display could change what the person sees. The text does not say more. | Nothing |

## 8. Peers and the network

### 8.1 Nothing for safety

The threat model lists, for a peer or relay, "Store, drop, delay,
reorder and replay; refuse service; delete its copy; partition members", and
defends "It reads no content, names, levels, capabilities, labels, adapter
types or roster changes. Every event it forges, alters or injects is refused.
It cannot change membership" ([overview.md](overview.md), section 3). For
the network it lists "Observe, inject, drop and replay packets". Frasil asks for
neither to be honest, correct or reachable for the safety claims, and the
peer's clock "decides nothing a replica reads".

A peer is trusted for availability only ([transport.md](transport.md), 3.10;
[ext-libraries.md](ext-libraries.md), 4: "The home peer is a hint").

### 8.2 What liveness and availability need

The text states these as limits ([rationale.md](rationale.md), 11 "Known
limits": "Metadata and availability", "Members with no peer lose each other",
"A full partition"). It does not state that the network delivers, nor that
some peer is honest; each row below says what a procedure needs and what it
does without it.

| What | Needs | Without it | Relied on in |
|---|---|---|---|
| **Replicas converge** | That they come to hold the same events: "Replicas that hold the same events reach the same state" | They differ until they meet. "Partitions and forks, until replicas meet" are not defended. | [overview.md](overview.md), 1 ("The promise of agreement is conditional", and "the text claims no liveness"), 3 |
| **An event is durable** | An always-on peer of the space, or in a space with none, another member, acknowledges it after it has "stored durably" what it received | The event stays in the outbox and is offered on every connection. A peer that acknowledges and loses it is caught by "every device that remembers the acknowledgement" (`RolledBack`), and the event is counted not durable until a peer acknowledges it again. | [units.md](units.md), 3.13, 3.14 "Sync" |
| **Withholding is noticed** | A second path by which a head statement or a pinned list reaches the client | "What no client knows of yet, a peer can withhold until a head statement reaches a client by another path." | [units.md](units.md), 3.13, 4 "Security considerations"; [identity.md](identity.md), 3.14 "Pins" |
| **A restored device does not fork** | At least one reachable peer or member that holds the log and does not withhold the device's later events | The device waits, or returns as a new device. "A peer that withholds the device's later events can still make it fork. Asking several peers narrows this." | [events.md](events.md), 3.8; [at-rest.md](at-rest.md), 3.6 |
| **Stability** (gap keys for a restored member, dropping refused content, collection, erasure) | Every administrator that has not forked signs an event whose past holds the events | The act waits for the timeout (`gap_key_timeout`, T), and always in a space with a space recovery member, which never acknowledges. | [overview.md](overview.md), 2.6 "Units, replicas and peers", 6.8; [rationale.md](rationale.md), 2.9 "Stability and the space recovery member" |
| **A heal, a cascade, a top-up** | A writer that has the events online: one candidate suffices, and "an offline candidate costs only its delay" | The merged key stays exposed until a writer is online, and no writer hands a newcomer the body keys it lacks. | [rationale.md](rationale.md), 3.2 "Heals", 3.5 "Grant keys and space wraps", 6.2 "Other routes" |
| **Removal reaches an uninformed writer** | The writer hears of it | "A writer that has not heard of a removal seals for the removed member until it hears." Strict for writes, eventual for reads. | [rationale.md](rationale.md), 2.6, 11 |
| **Admission exchange, welcome, access request** | An exchange mailbox on any always-on peer, a nearby connection, or a direct connection (a person's new device needs no peer); a device mailbox for a welcome | The exchange expires after 900 seconds. A welcome that is not delivered is sent again by promoting an existing member or redelivering its keys. | [admission.md](admission.md), 1, 3.6 "Exchange mailboxes", 3.10 "Welcomes"; [rationale.md](rationale.md), 12 |
| **Members with no peer find each other** | A ticket they kept, until both have rotated their endpoint keys (twice with [ext-next-endpoints.md](ext-next-endpoints.md)) | After that one of them needs a fresh invitation, a peer, or another way to learn the other's endpoint. | [rationale.md](rationale.md), 11, 7.4 ("A relay is not a mailbox") |
| **An agent's add can be vetoed** | The person's devices hear of the add through any member, within the waiting period | A server that withholds the add and partitions the person "from every collaborator" lets a compromised agent finish its waiting unseen. "Frasil does not defend against a full partition." | [ext-recovery-agent.md](ext-recovery-agent.md), 3.5 "Relay and veto", 4 |
| **A removed member's credentials end** | An administrator's credentials request is carried out at the peer, after its stability or T | The removed member fetches ciphertext and spends quota until then. | [peers.md](peers.md), 3.17 "Credentials requests", 4 |
| **A peer on several machines is one peer** | At any moment one machine answers for each space; what any machine acknowledges, every machine serves | A device that sees it serve less than any machine acknowledged reports `RolledBack`. | [peers.md](peers.md), 3.1 "Hosting a space", 4 |
| **The online-only policy** | A completed sync with an always-on peer of the space | The writer may not write (`NotOnline`). A client MUST NOT set it in a space with no always-on peer. | [ext-guests.md](ext-guests.md), 3.4 |

An account's server is trusted for nothing a replica reads. It may answer a
lookup with a person of its choosing, and the grant is shown as unverified
(section 9).

## 9. People

| Assumption | Relied on in | If it does not hold | Detected by |
|---|---|---|---|
| **The two people compare the six digits, out of band,** with their own eyes or over a channel the attacker does not control. | [admission.md](admission.md), 4 ("What the code does not protect"); [rationale.md](rationale.md), 6.1 "A mutual code"; threat model, "A relay of an admission exchange" | A person who confirms without comparing, or compares a code read over a channel the attacker controls, admits the relay. The code's protection, one guess at 10^-6, exists only if the people compare. | Nothing |
| **An application that compares for the person authenticates both ends,** as a check of the caller's code signature does, and the person has consented to admitting that application. | [admission.md](admission.md), 4 ("Applications that compare for the person") | A local impostor confirms its own code. | Nothing |
| **Members are shown and compared by device ID, label or fingerprint, never by Ed25519 key.** A client MUST NOT show a member by its Ed25519 key. | [roster.md](roster.md), 4 "Security considerations", "A grant of keys nobody holds"; [identity.md](identity.md), 2.9, 3.12 "Comparing fingerprints" | A grant that names a victim's Ed25519 key with other keys is a member of its own device ID. A client that shows the Ed25519 key shows the victim. | Nothing |
| **A fingerprint is compared for the keys about to be signed,** and a client signs nothing else. | [identity.md](identity.md), 3.12 | A fingerprint of other keys is compared, and the wrong keys are signed. | `FingerprintMismatch` |
| **A lookup grant is only as good as the account's server until a code is compared.** It is shown as unverified. A `via` is "shown, never checked". | [admission.md](admission.md), 2.1, 3.9 "Lookups"; [roster.md](roster.md), 2.3 "Changes"; [rationale.md](rationale.md), 6.2 "Other routes" ("`via` is never checked; nothing can verify it") | The server grants a person of its choosing, and until a code is compared the substitution stands. An application that shows `code` shows what the approver wrote. | A later code comparison |
| **A leaked invite link is narrowed by its lifetime and by the channel it travels on.** | [ext-invite-links.md](ext-invite-links.md), 4 ("A leaked link is a bearer credential") | A claim made before the invitee's goes unnoticed until a member compares an admission code with the claimant; it reads what was sealed while the invite was open and until the heal. | Concurrent claims void each other, visibly; a code comparison |
| **The person keeps a recovery sheet, a space recovery member's key and a passkey where the text says.** A space recovery member's key is "kept offline". | [identity.md](identity.md), 2.6 "Recovery keys", 3.11 "Recovery"; [rationale.md](rationale.md), 2.9, 11 | A thief with the sheet outranks every other list member. "Without one, duels can leave a space with no administrator." | Nothing |
| **A person whose only two devices duel, or whose list is dead, recovers socially.** | [identity.md](identity.md), 4; [rationale.md](rationale.md), 5.1 "A person is a device list" | No protocol path returns the list. | Not applicable |
| **A person who grants a guest `frasil.nothing-at-rest` is told it asks the guest's application not to keep a copy,** and that a modified application can. | [ext-guests.md](ext-guests.md), 4 | The person believes the guest cannot keep the data. | Nothing |

## 10. The application and the adapters

### 10.1 Adapters

| Assumption | Relied on in | If it does not hold | Detected by |
|---|---|---|---|
| **`apply` gives the same state for any set of accepted units, in any order, any number of times each,** and the state does not depend on whether units were handed over in canonical order (a rebuild) or arrival order | [units.md](units.md), 3.17 "The adapter interface" | Replicas show different documents. "Replicas whose adapters disagree show different documents, never different verdicts." | Nothing in Frasil. "States are compared by meaning" by whoever compares them. |
| **Every function that affects state or a verdict is a pure function of its inputs:** no clock, randomness, network, other stream or other space. One adapter version gives the same state and content refusals on every replica and platform. | [units.md](units.md), 3.17 ("Determinism") | Replicas on different versions, platforms or inputs diverge, silently. | Nothing. A content version an adapter does not know is `UnknownContentVersion`. |
| **A capability check reads only the capabilities, the context and the content,** never the stream's state, and every registered check runs on every unit in ascending order of capability name, byte by byte. | [units.md](units.md), 3.17 ("Capability checks"); [rationale.md](rationale.md), 7.3 "Adapters" | A check that reads the state depends on arrival order, and replicas refuse different units. | Nothing |
| **A writer is untrusted,** and decoding a writer's content costs a bounded multiple of the largest unit. | [adapter-loro.md](adapter-loro.md), 4 "Security considerations" | A blob decodes to a size or a panic that the replica cannot absorb. | The limits of the adapter's decoding steps |
| **An application that needs "only you edit your entries"** gives each person a space of its own, or registers a capability check. | [adapter-records.md](adapter-records.md), 4 | Any writer overwrites any cell within its capabilities. | Nothing |
| **A time or an entry's text fields are claims.** `docKind`, `size`, `type`, a Records `time` and a blob entry's name are what a writer said. | [ext-drive.md](ext-drive.md), 4; [adapter-blobs.md](adapter-blobs.md), 4; [adapter-records.md](adapter-records.md), 4 | An application that takes them for facts shows false ones. | Nothing |

### 10.2 What the application does with names, files and a guest's data

| Assumption | Relied on in | If it does not hold | Detected by |
|---|---|---|---|
| **An application that mirrors a name to a filesystem treats it as untrusted.** The text fixes a drive name's form (1 to 255 bytes of UTF-8, no `/`, no control character), compares names byte for byte, and says a writer MAY normalise and a reader never does. It says nothing of any filesystem, and says so. | [ext-drive.md](ext-drive.md), 2.1 "Values", 4 ("Entries are claims"; "Names are a writer's, not a filesystem's"); [at-rest.md](at-rest.md), 3.9 ("Frasil deletes nothing of the application's") | The text allows `.` and `..`, names that differ only in case or normalisation, and names a filesystem reserves. A writer chooses them. What happens on the application's disk is the application's. | Nothing |
| **Held objects: the provider's plaintext is the application's file, and it does not change while it is read.** Held is chosen by the application, per space, on this device. A grant that carries `frasil.nothing-at-rest` is never held. | [at-rest.md](at-rest.md), 2.8 "Held objects", 3.9, 4 | `Changed`: nothing is committed. A held file is readable from a disk with no unlock key. | `Changed` |
| **A guest's client keeps the space in memory only** and writes none of its keys, events, objects, snapshot or outbox to Frasil's store or the application's files. | [ext-guests.md](ext-guests.md), 3.5 "Nothing at rest"; [at-rest.md](at-rest.md), 3.7 "A memory-only log" | The guest keeps what it received. Nothing at rest "binds only honest clients" ([rationale.md](rationale.md), 10 "Extensions"). No replica checks the capability. | Nothing |
| **An application gives `expires_at` only to a device with a known wall clock,** and never sets `online_freshness` in a space with no always-on peer. | [ext-invite-links.md](ext-invite-links.md), 4; [ext-guests.md](ext-guests.md), 3.4, 4 | A device that cannot read a clock cannot claim, or cannot write. | `Expired`, `NotOnline` |
| **The application names the person ID it expects when it opens sealed device keys, states its restore mode truthfully, and puts opened keys on the person's verified device list or grants them as a device member before use.** | [at-rest.md](at-rest.md), 3.1 "Sealing and opening the device keys", 3.5 | Another person's blob is opened for use; a false restore mode defeats detection (section 2.2). | `WrongPerson`, `WrongDevice`, `WrongKeyKind` |
| **Application keys are the application's to protect.** Frasil derives `app_key` and hands it over, and "never stores or uses it". | [at-rest.md](at-rest.md), 2.7 "Application keys" | What the application stores under it is its own concern. | Nothing |

## 11. Implementations

Replicas that hold the same events decide the same
([events.md](events.md), 3.2 "Placement and order"). That holds only if each
implementation does what the text fixes, in the text's way.

| Assumption | Relied on in | If it does not hold | Detected by |
|---|---|---|---|
| **A decoder accepts exactly one encoding of a structure:** it decodes, re-encodes and compares byte for byte, and refuses anything after the top-level item, nesting deeper than 16, and an unknown key. | [overview.md](overview.md), 5.3 "Deterministic CBOR" | Two encodings of one structure carry one meaning and two sets of bytes. An event ID, a signature, a commitment and a code are computed over bytes, so replicas that accept both disagree on identity or on a verdict. | `Malformed`, where the decoder holds the rule |
| **Canonical order is height, then event ID as a byte string.** Every procedure that needs an order uses it. Seniority is height, then a hash of the space ID and the grantee's ID, then the grant's event ID. | [events.md](events.md), 3.2; [roster.md](roster.md), 3.2 "The roster at a place", 3.7 "The resolution procedure" | A replica that orders events otherwise resolves a different roster, and reaches different verdicts on the same events. | Nothing; vectors catch it |
| **The limits are enforced alike by every replica,** and a bounded count is checked before anything is allocated for it. | [events.md](events.md), 2.7 "Limits"; [units.md](units.md), 2.1 "Limits"; [roster.md](roster.md), 2.7 "Labels and limits"; [keys.md](keys.md), 2.9 "Labels and limits"; [overview.md](overview.md), 5.3, 6.8 | A replica with a larger limit accepts what others refuse, and a replica with a smaller one refuses what others accept. Either way validity differs between replicas. | `TooLarge`, `Malformed`, `Full` |
| **Every public key is checked once, where it enters,** and compared by its bytes afterwards. | [crypto.md](crypto.md), 3.4 "Where keys are checked" | Verifiers disagree about a key and so about every event it signs. | `InvalidKey` |
| **Checks run in the order the text states, and the first that fails decides with the class it names.** "Every numbered step of a procedure, and every check given 'in order', is a requirement as written." | [overview.md](overview.md), 5.1, 5.2 "Notation"; [roster.md](roster.md), 3.1 "The order of verification" | One event is refused under different classes, and a class's sort (final, pending, held, decision, report) decides what is kept and what is retried. Vectors give "verdicts and error classes". | The vectors |
| **A key event is decided once, in canonical order,** and a pending event is never applied, cited or refused. | [rationale.md](rationale.md), 2.6, 2.7 "Checks across logs hold, never guess"; [roster.md](roster.md), 3.11 "Checks across logs" | Guessing an order between logs makes replicas disagree. | Nothing |
| **A hash, signature or MAC input is separated by a label, and no label equals or prefixes another.** | [overview.md](overview.md), 5.4 "Primitives and labels"; [crypto.md](crypto.md), 2.6 "The label registry" | An input of one use reads as another's. | Nothing |

## 12. What the text does not assume

For completeness, the text does not rest on:

- an orderer, a witness, or any party whose order decides membership
  ([rationale.md](rationale.md), 1.1 "Every check is a replica's");
- a peer's honesty for any verdict ([overview.md](overview.md), 1);
- a signed time, or a trusted time service ([rationale.md](rationale.md), 9
  "Time");
- an account to be the identity ([rationale.md](rationale.md), 1.5 "Accounts
  decide nothing");
- a default relay ([rationale.md](rationale.md), 7.4);
- forward secrecy within a member's history, immediate removal for reads,
  hiding traffic patterns, or stopping a hostile guest from keeping data
  ([overview.md](overview.md), 1, non-goals).
