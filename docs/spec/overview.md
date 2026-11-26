# Overview
Protocol 1. Vectors: [overview.json](vectors/overview.json).

Frasil is an end-to-end encrypted framework for collaboration without a
central authority. Devices keep their own replicas of shared data and
exchange sealed, signed events until every replica agrees: through always-on
peers, directly over a local network, or both. Frasil decides how people and
devices are trusted, how keys are managed, who may read and write, and how
changes travel. The application decides what its data means.

This document gives the goals, the system model, the one threat model, what
each party sees, the conventions every other document uses, how Frasil
treats time, the split between core and extensions, and the glossary. Its
only procedures are the timeline and the checks of section 6. Primitives,
key validation, signatures and every label are in [crypto.md](crypto.md).

## 1. Goals and non-goals

Goals:

- **No party is an authority.** An honest replica decides from the events it
  holds whether an event is valid. A peer adds availability, never trust.
- **One protocol, online and offline:** through peers, on a local network
  with nothing else, and across both.
- **Agreement without an orderer or a clock.** Replicas that hold the same
  events reach the same state, in whatever order they received them.
- **A peer learns little and corrupts nothing.** It reads no content, names,
  levels, capabilities, labels or adapter types, and nothing it forges,
  injects or reorders is accepted.
- **Identity belongs to people.** Membership rests on keys a person's
  devices hold; an account is only a way to find someone.
- **Removal protects what is written afterwards,** and **every key exchange
  and every authority signature is post-quantum hybrid.**
- **Any application, and sharing that matches intent,** at a cost that does
  not grow with the number of documents.
- **Every outcome can be explained,** and the specification is complete
  enough for an independent implementation, with vectors for every format.

Non-goals: hiding traffic patterns (sizes and timing are visible, and
padding is optional); server-side queries over content; un-sharing, or
forward secrecy within a member's history; read permissions finer than a
space; immediate removal for reads; stopping a hostile guest from keeping
data; trusted time; protecting a device from whoever controls it while it is
unlocked; a sealed export format; a guarantee that events are delivered.

The promise of agreement is conditional: replicas that come to hold the same events reach the same
state, and the text claims no liveness, that an event reaches any replica
or that replicas ever come to hold the same events. That needs a path
between them, through a peer, a member or a local network, which the
network and peers may withhold (section 3).

## 2. System model

### 2.1 Devices, persons and accounts

- A **device** runs a Frasil client and holds three key pairs, each from its
  own random seed: an Ed25519 **identity key**, which signs; an **X-Wing
  key**, to which keys are wrapped; and an **ML-DSA-65 key**, which signs
  authority events beside the identity key. It is named by its **device
  ID**, a hash of its identity key and of a commitment to the other two, so
  its name commits to every key it signs or receives under
  ([crypto.md](crypto.md)). A verifier takes those keys from anywhere and
  accepts them by their hash. A device that needs new keys returns as a new
  device, with a new device ID. Everything the client
  keeps is sealed under keys only its unlock key reaches
  ([at-rest.md](at-rest.md)).
- A **person** is the keys of one **device list**, a log of signed `add`,
  `revoke` and `confirm` events ([identity.md](identity.md)). The **person
  ID** is the event ID of the list's first event and never changes. The list
  lives in the person's **personal space**, and a sealed copy travels in
  every space that grants the person. No peer holds a list in the clear.
- A list has four kinds of **list member**: a device; a **passkey member**,
  whose keys a passkey derives; a **recovery key**, printed on a recovery
  sheet; and a **recovery agent**, which may only add a device, after a
  waiting period ([ext-recovery-agent.md](ext-recovery-agent.md)). Every
  list member is named by its device ID, and every `add` carries the named
  keys' **possession proof**, which binds the keys to the person ID and to
  the list member that adds it. Of two list members that revoke each other
  concurrently, the higher **rank** wins; within a rank, both are
  revoked.
- A new device joins when a list member signs its `add` after both screens
  show the same admission code. A device holding only a passkey or the
  recovery sheet derives a **fetch key**, registered at the personal space's
  peers as a **recovery entry**, and fetches the space with it. A person with
  no route back makes a new person, which each space's administrators
  **replace** the old one with.
- An **account** is an optional, signed link from a person ID to a subject
  at an identity provider. Its server may answer lookups, keep a sealed
  directory of spaces and keep a mailbox. It never adds or revokes a list
  member, appears in a roster, or decides a check.

### 2.2 Spaces, rosters and levels

- A **space** is the unit of sharing and encryption, with its own log,
  roster and keys. Its **space ID** is the event ID of its **genesis**, whose
  author's device is the **founder**. A space holds many documents, each a
  stream, and is tied to no peer.
- The **roster** is the space's roster events ([roster.md](roster.md)). It
  grants **members**: a device, by its device ID, a person (every device
  the person's list vouches for), a space, or an invite key, which only
  [ext-invite-links.md](ext-invite-links.md) defines. A **device member** is
  a device granted directly; its grant carries the keys its device ID
  commits to.
- **Levels** are `read` < `write` < `administer`. `read` holds the keys and
  the read credential; `write` also has its units and key events accepted
  and holds the upload key; `administer` also signs roster events, and is
  granted to devices only, in the space's own roster, because a roster, a
  list and another space's roster share no order.
- **Capabilities** are application-defined names that extend or narrow a
  grant, checked by adapters at every replica after decryption; names that
  begin `frasil.` are Frasil's. A **label** is application text, shown and
  never checked, and so is `via`, how the member was admitted.
- A grant gives history **with history**, or **from now on**: only the
  current key and a history-free snapshot, a **break** in the key graph. A
  **guest** is a device granted with `session` set
  ([ext-guests.md](ext-guests.md)).
- A **space recovery member** is a device member at `administer` whose key
  is kept offline, so that a space whose administrators are lost can be
  recovered. The **space policy**, in the genesis and changed by roster
  events, holds the space's timed values (section 6.8) and whether it admits
  persons whose list holds an agent.

### 2.3 Grants of spaces and restrictions

- A roster may grant another space at `read` or `write`. A member of the
  granted space whose grant **propagates** (has no `session`) reaches the
  granting space at the lower of the two levels, never above `write`. The
  **effective membership** of a space is every device that reaches it.
  Grants form no cycle and no chain of more than 8 spaces.
- Each space has a **grant key**, held by members that propagate. A granting
  space's rotation seals its keys once to it: a **space wrap**. When a space
  loses a device, every space that inherits the loss rotates in a
  **cascade**, made by an informed writer after a ranked delay.
- A **restricted space** is a private part of a parent, whose key derives
  from the parent's; a **carve-out** gives a guest one document of a larger
  space ([ext-restricted-spaces.md](ext-restricted-spaces.md)).

### 2.4 Events and how they merge

- Everything Frasil signs and syncs is an **event** with one envelope, in
  one **log**: a space's log or a person's list ([events.md](events.md)). The
  **event ID** hashes the unsigned event, and serves as causal link, space ID
  and person ID.
- **Kinds:** 1, device-list event; 2, **space event**, whose sealed body is
  a **roster event** (an update, or a **checkpoint**) or a **key event**; 4, **unit**; 5, **anchor**; 6,
  **storage event**; 64 to 127, ignorable, none defined. Kinds 1, 2, 5 and
  6 are **authority events**, signed under scheme 2 (Ed25519 and
  ML-DSA-65); units use scheme 0 (Ed25519) until the classical sunset.
- **Parents** give the causal order; **canonical order**, by height then
  event ID, is the one order every procedure uses. Each author's events in a
  log form its **chain**, numbered by `seq`; two events at one `seq`, or one
  that skips, prove a **fork**, and void the author from the fork point on.
- An event is **valid** or **void** once decided, **pending** while it waits
  for what the replica lacks, and **held** while the replica cannot open it.
  A unit the write rule rejects is **refused**, and kept, because a later
  merge can void the event that refused it.
- A roster event is valid only if its author holds `administer` at its
  **place**; a key event needs `write`. A removal voids the removed member's
  concurrent actions and any concurrent grant of it; a demotion voids the
  demoted member's concurrent roster actions; an event that only lowers its
  author is never voided by concurrency. In a cycle, a **mutual pair** both
  stand, and otherwise the most senior author's action stands.
- **Removal and writes are strict:** a removed member's unit concurrent with
  the removal is refused, whatever it links to. An end that comes through
  another log (a device revoked from a person's list, a member removed from a
  granted space) takes effect once a writer of the space responds to it
  ([roster.md](roster.md), "Checks across logs"). **Removal and reads are
  eventual:** a writer that has not heard of a removal seals for the removed
  member until it hears.
- **Checkpoints.** An administrator may sign a **checkpoint**, which fixes
  the roster of its past in a record. Once every administrator has voted
  for it by writing after it, it is **in effect**: every event concurrent
  with it is **late** and void, and every replica, newcomer and peer may
  forget what came before it. Each event's envelope declares the
  checkpoints it follows ([roster.md](roster.md), "Checkpoints";
  [events.md](events.md), "Cuts").
- **The backdated duel** is an accepted, visible risk until the next
  checkpoint takes effect: a removed
  administrator's counter-removal that leaves out its own removal stands
  with it, taking its remover down until a re-grant. The client shows what a
  duel voided and re-submits the remover's refused units.

### 2.5 Keys

- A space's content keys form a graph of **states**. Each **rotation** draws
  fresh secrets; the **current state** is the set of maximal valid
  rotations, and its **content key** derives from theirs ([keys.md](keys.md)).
- Keys reach a device in a **wrap**, an X-Wing seal that names no recipient:
  one per device, or a space wrap per granted space. Earlier keys stay
  reachable through **links**, which hang only where every possible holder
  is entitled to what they reach; where a link is withheld, the key is a
  **gap key**, sent by wrap to its entitled members.
- Any writer **heals**, with a rotation, when the devices outside the roster
  could together derive the current key.
- A space event's body is sealed under its own **body key**. A newcomer
  receives earlier events' body keys, so it reads the membership history but
  no content key from before its break.
- Each state derives two Ed25519 key pairs, the **read credential** and the
  **upload key**, whose public halves a peer checks.

### 2.6 Units, replicas and peers

- A **unit** carries application data, sealed under a state's keys and
  signed by its writer ([units.md](units.md)). Its writer, sequence, causal
  links, **stream**, key reference and referenced **objects** are visible,
  so a peer that reads nothing can sync. **Compaction** declares exactly
  which units of a stream a snapshot unit replaces. An **adapter** gives
  units meaning. A newcomer from now on starts from a **space snapshot**.
- A **replica** is a device that holds a log and judges its events, as a
  **full** or a **partial** replica. A set of events is **stable** when every
  administrator that has not forked has signed an event whose past holds
  them.
- An **always-on peer** relays, stores, keeps mailboxes, offers discovery
  and applies quotas, and decides no event's validity ([peers.md](peers.md)).
  It holds no roster, content key or list of readers. A device fetches with
  the read credential, stores and releases with the upload key, catches up
  with a fetch key, and asks for the space's erasure under an
  **administrator pseudonym**; a reader is never identified.
- The **administrator skeleton** shows a space's administrators under
  pseudonyms. Each roster event that changes who administers names its
  **twin**, the skeleton event that mirrors it, and replicas check the pair.
  The peer applies the roster's merge rules to the skeleton, and erases once
  a request is **stable at the peer**, or after the timeout T. A **library**
  is what an operator bills ([ext-libraries.md](ext-libraries.md)).

### 2.7 Transports, admission and the ephemeral channel

- A transport gives an identity proved by its own handshake, a channel
  binding, reliable ordered frames and a lossy channel ahead of bulk
  ([transport.md](transport.md)). In the **member handshake**, two devices
  prove they hold a key state of a space without showing a non-member which,
  then bind their device IDs and check each other's membership. In the
  **device-to-peer handshake**, a device presents a credential, never its
  identity.
- **Admission** is one roster event that grants a newcomer
  ([admission.md](admission.md)). It rests on a mutual six-digit **admission
  code** both screens show; on an invite link; or on a **lookup** through an
  account, which trusts that account's server and is shown as unverified.
- The **ephemeral channel**, an extension, carries live traffic apart from
  units, never persisted ([ext-ephemeral.md](ext-ephemeral.md)).

## 3. Threat model

This is the threat model for all of Frasil. Each document adds only what is
specific to its formats.

| Adversary | Can | Defended | Not defended |
|---|---|---|---|
| An always-on peer or relay | Store, drop, delay, reorder and replay; refuse service; delete its copy; partition members | It reads no content, names, levels, capabilities, labels, adapter types or roster changes. Every event it forges, alters or injects is refused. It cannot change membership. Withholding and rollback of events a client knows about are detected. Its clock decides nothing a replica reads. | Availability. Partitions and forks, until replicas meet. The leaks of section 4.4. |
| The network, a relay's path, a local network | Observe, inject, drop and replay packets | Transport encryption and channel binding; sealed announcements; messages bound to their channel. | Traffic analysis. That a device announces, and its address. |
| A stranger | Reach a peer or a device; sign with keys of its own; deposit in device mailboxes | It stores and fetches nothing without a credential. Its events are dropped unless a record of the log names it. It learns nothing about which spaces a device belongs to. Its deposits push out nothing of a claimed mailbox, nor, with deposit tokens (extension), any mail a token paid for. | Load: one signature check before each drop. Filling a peer's anonymous mailbox caps, which delays anonymous mail until retention frees room. |
| A holder of deposit tokens (extension) | Deposit, unlinkably, up to its library's allowance, or its space's share of it | The peer counts its tokens against the library when they are drawn, and cannot tell which library, space or grant paid for a deposit. | Filling one mailbox to its cap, which evicts that mailbox's oldest items; filling the token budget, which its library's ledger shows. |
| A reader | Hold the keys and the read credential | Its units and key events are refused. It is not in the skeleton, so it erases nothing. | What it reads, it keeps. |
| A writer, narrowed writer or guest | Write units and key events; release; compact; upload; supersede (extension) | It cannot sign as another device, attach a key to another device, change the roster, erase, or pass a capability check its grant fails. A release stays restorable during the retention, and keeps as events the units that events outside its stream name. An object it supersedes stays while any listing of it stands, and for the retention. | Junk in its own name, attributable. Spending quota. A false snapshot, until another member replaces it. Old versions of its stream's files, after the retention, which it could remove already. |
| An administrator | Sign roster and skeleton events; erase the space at its peers | It cannot grant itself, raise itself, or lower another administrator in a batch. A missing or wrong twin is found by replicas. An erasure names the whole space, waits for stability at the peer or T, and another administrator stops it by lowering its requester concurrently. | What `administer` allows. The erasure of the whole space at a peer, which cannot be undone there; what replicas hold stays theirs. |
| A removed member | Keep keys and data; write onto old heads; keep old storage credentials | Its units concurrent with or after the removal are refused. What a device seals after learning of the removal is unreadable to it. | Everything from before the removal. What uninformed writers seal. Fetching ciphertext and spending quota until administrators end its credentials, on connections it keeps open as on new ones, and, with deposit tokens (extension), drawing its space's share of them meanwhile. |
| Removed or compromised members pooling keys | Derive a merge key from branch keys | Any writer heals as soon as the outside could derive the current key. | What informed writers sealed under the merge key before the heal: one round trip. |
| A removed administrator | Backdate a counter-removal; send erasures | No member acts on a higher rank, and in a mutual removal of equal ranks the more senior stands: a removal by a member that outranks it holds. Its requests concurrent with its lowering are void at the peer. Execution waits for stability or T. | A device of the top rank, most senior there, wins its duels and the space. An erasure after T at a peer its lowering never reached. |
| A device that forks its chain, by attack or by a restore that writes first | Sign two histories | Every fork is provable, and the device is void from the fork point. Its self-lowering events stand. | Its events before the fork. |
| A thief holding one of a person's devices | Sign list events; backdate a revocation | A mutual revocation within a rank revokes both. A recovery key that is not rooted outranks every other list member. | What the device can do until it is revoked. |
| Someone holding a person's passkey | Act as the passkey member | It cannot revoke a recovery key, nor can any list member it brings in until a device not rooted confirms it. It cannot lower a list member another one added: each proof names its adder. | Reading every space the person's grants reach; adding devices. |
| A member that hands a newcomer its snapshot | Withhold, or hand wrong keys | Everything handed is under the sender's signature. A body key that misses its commitment holds the event. | A newcomer whose only sender lies applies the lie provisionally. |
| A relay of an admission exchange | Read, drop, replay and forge messages; substitute ephemeral keys | One guess at the code, 10^-6. Messages after the request are sealed. | Denial of service. An active relay reads one exchange's offer before the codes expose it. |
| An account's server | Answer a lookup with a person of its choosing | A lookup grant is shown as unverified; a later code comparison detects a substitution. It decides nothing. | Lookup grants until a code is compared. |
| A quantum adversary recording now | Break X25519 later | Every wrap is X-Wing. | |
| A quantum adversary at verification time | Forge Ed25519 for any key it has seen | Every authority event, possession proof and piece of fork evidence needs ML-DSA-65 under the key the device ID commits to, which no record, list or grant can replace. An event it signs in full under an ML-DSA-65 key of its own is another device's, with no standing, and never evidence against the device whose Ed25519 key it reuses. A peer stores its events under a device's own keys, and every replica refuses them. After the classical sunset, a scheme-0 unit counts only if covered. | Before the sunset: a forged unit at a used `seq` voids its device; an insider holding a content key can forge a unit that opens. Before the sunset, scheme-0 structures such as a connection's `Identify` or a head statement. With deposit tokens (extension), which are classical, forged tokens: deposits up to the mailbox caps and the token budget, as a stranger's. |
| Whoever reads or replaces a device's stored bytes | Read, delete, replace and roll back records; restore a backup | Every record is sealed under keys only the unlock key reaches. A moved or forged record does not open. A restore is detected where the platform gives a device-bound slot. | The counts of logs and of each table's records per log, sizes and write times (section 4.3). An unlock key kept beside the store. |
| Whoever moves a device's clock | Set the wall clock | No validity depends on time. A jump while the device runs is not counted (section 6.3). | A clock moved while the device is off. |
| The holder of a leaked invite link (extension) | Claim the invite; read with the invite key's wrap | Two concurrent claims are both void, visibly. Revoking the invite ends it. A claim or a revocation puts the invite key outside, and a writer heals. | A claim made before the invitee's, until a code is compared. What was sealed while the invite was open, and until the heal that follows. |
| A recovery agent or its server (extension) | Add a device to the person that named it | The device ranks lowest, waits a period at each verifier, and can be vetoed. Members relay the entry to the person's devices. It cannot lower a list member another one added: each proof names its adder. | A person with no device left cannot veto. |
| A guest that ignores "nothing at rest" (extension) | Keep what it received | Nothing. | Everything it received. |

## 4. What each party sees

### 4.1 An always-on peer

| Sees | Never sees |
|---|---|
| Space IDs. Each event's envelope: kind, author (its Ed25519 key and keys commitment, so its device ID), `seq`, parents, scheme and size. | Content, names, adapter types. |
| For a space event: whether it rotates, the state it is sealed under, its commitments, each delivery's wrap count, its sealed length, and which events change who administers, with their twins. | Roster changes: members, levels, capabilities, labels, history modes, `via`. Refs between logs, and which spaces grant which. |
| For a unit: its stream, key reference, referenced objects and declared compaction. So: which devices write, when, how much, and in which streams. | Device lists. Who any wrap is for. |
| For an object: its locator, state, size, and which units reference it. With [ext-file-versions.md](ext-file-versions.md): which objects of a stream replace which, and which unit listed each, so which objects are versions of one file, in what order, how often it is saved, and when two devices saved it concurrently. | A reader's device. Which file, its name, or how many files a stream holds. |
| The skeleton: pseudonyms, how many administrators, which administrator slot granted which, and when; who asked for the space's erasure and each credentials request; which writer released or restored what. | Who holds a pseudonym, except as section 4.4 says. |
| Which connections present which credentials, their addresses and timing, and which streams a connection fetches on demand. | |
| How many recovery entries a space has, and when one is presented. | Which list member a fetch key belongs to. |
| Mailboxes and invite drops: that they exist, their sizes and timing. The ephemeral channel's outer frames. | Mailbox contents. Ephemeral senders, names and data. |
| With [ext-deposit-tokens.md](ext-deposit-tokens.md): when each library draws deposit tokens, and how many; for a draw by a space's writer, that some writer of that space drew them; at a deposit, a valid token of one key period, beside the recipient's mailbox address that any deposit shows. | Which library, space, grant or draw paid for a deposit, and so who writes to which device. The device ID of a device that draws, or that deposits with a token. |

An envelope's keys commitment links nothing new. It hashes a device's other
two public keys, which never change, so it is the same on every event the
device's Ed25519 key already marks, in every space; a pseudonym's hashes
keys drawn for that pseudonym alone. It hides those keys from a peer as the
sealed records that carry them do, and a peer that learns them elsewhere
learns only what it could link by the Ed25519 key.

### 4.2 The network

A path observer sees addresses, timing and sizes. A relay also sees both
ends' current endpoint keys, which rotate and are never a device's keys, and
who talks to whom. On a local network, anyone sees that a device announces,
its address and port, and how many spaces it announces; nearby pairing shows
a display name. Nothing else crosses a transport unsealed.

### 4.3 Members and others

- **A member** reads everything sealed under keys it holds: content, names,
  and the roster at every place it holds, with members, levels,
  capabilities, labels, sessions, device keys and policies; the lists of the
  persons the space grants; and the rosters along the grant paths through
  which it checks writers. After a member handshake it knows the other
  device's device ID and endpoint.
- **A newcomer from now on** reads the membership history from before it
  joined, in its space and along its grant path, but no earlier content.
- **A former member** keeps what it held. If it dials a member with an old
  key state, it learns before it is refused that the member still holds that
  state, and the member's device ID.
- **An account's server** sees the link between a person ID and a subject,
  when lookups happen, which device looked up which person, the size of
  the person's sealed directory, and the person's mailbox traffic.
- **A reader of a device's storage,** without the unlock key, sees the
  sealed device keys' header, with their device ID and person ID; how many
  logs the store holds, and how many records of each table each log holds;
  the records' lengths; and when records change: that a device holds three
  invites, say, or how many of its events are not yet durable. It sees no
  log, event or object ID, no peer, name or key
  ([at-rest.md](at-rest.md), section 4). The plaintext of objects the
  application holds itself is its own files, readable with no unlock key
  ([at-rest.md](at-rest.md), section 2.8).

### 4.4 Accepted leaks

Each is the cost of a stated goal; [rationale.md](rationale.md) gives the
reasons.

1. **Sizes and wrap counts:** a peer tells a device grant from a removal or
   a heal by size, and follows the number of direct recipient devices.
2. **Which devices write,** with sequences and causal links, so that a peer
   that reads nothing can sync.
3. **Stream IDs and activity:** per stream, unit counts, sizes, timing,
   compaction, and which streams a device fetches on demand.
4. **Which objects units reference,** so that a peer can collect the rest.
5. **The administrator skeleton:** administrators under pseudonyms. One that
   changes who administers is linked to its device, because its roster event
   names its twin; so is the founder.
6. **Membership history to newcomers,** so that each can judge the roster it
   joins.
7. **Old states to former members,** so that members who missed rotations
   can still connect.
8. **Recovery entries:** how many a space has and when one is presented, so
   that a device holding only a passkey or a recovery sheet can recover.
9. **Which objects are versions of one another** (extension), with their
   order, so that a peer keeps a bounded number of a file's old versions
   and collects the rest with no device online.

## 5. Conventions

### 5.1 Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in these documents are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as
shown here. Every numbered step of a procedure, and every check given "in
order", is a requirement as written, whether or not it carries a keyword.

### 5.2 Notation

- `||` is concatenation; `len(x)` is the length of `x` in bytes.
- `u8(n)`, `u16be(n)`, `u32be(n)` and `u64be(n)` are `n` as an unsigned
  big-endian integer of 1, 2, 4 and 8 bytes.
- `field(x) = u32be(len(x)) || x`: Frasil's length-prefixed field.
- `x[a..b]` is bytes `a` to `b − 1` of `x`.
- A quoted string such as `"ed25519"` is its ASCII bytes, with no
  terminator. Hex is lower case, two digits per byte.
- "In order" means that the steps run as numbered and the first that fails
  decides, with the class it names (`else Malformed`).
- **White space** is the characters with the Unicode property
  `White_Space`. Text is "only white space" when it is not empty and every
  character in it is white space. Every text that this specification
  refuses for being only white space also refuses control characters
  (Unicode category Cc), so the two rules together refuse the same texts
  under any reading of white space that agrees with `White_Space` outside
  category Cc.

### 5.3 Deterministic CBOR

- Frasil's own structures use RFC 8949's core deterministic encoding
  (section 4.2.1), restricted to unsigned integers (0 to 2^64 − 1), byte
  strings, UTF-8 text strings, arrays, and maps whose keys are unsigned
  integers in ascending order, with definite lengths and shortest heads. No
  negative integers, floats, simple values or tags; applications encode
  those into their own sealed content as they choose.
  [adapter-records.md](adapter-records.md) widens it for a cell's value
  alone: its records subset adds negative integers, `false`, `true` and
  8-byte floats.
- A decoder accepts exactly one encoding: it decodes, refuses anything
  outside the subset, re-encodes and compares byte for byte. Any difference,
  or any byte after the top-level item, is `Malformed`.
- Each document names the keys each map allows and requires. An unknown key
  is `Malformed` unless the document says it is ignored. A bounded count is
  checked before anything is allocated for it.
- A decoder refuses nesting deeper than 16 as `Malformed`. The top-level
  item is at depth 0, and each item of an array, and each key and value of a
  map, is one deeper than the array or map that holds it. A document may set
  a lower limit for an item that its structures embed.

### 5.4 Primitives and labels

`HKDF(salt, ikm, info)` is HKDF-SHA256 with 32 bytes out, and a salt of
`none` is 32 zero bytes; `HMAC` is HMAC-SHA256; XChaCha20-Poly1305 takes a
24-byte nonce and appends a 16-byte tag. [crypto.md](crypto.md) fixes every
primitive, the key checks and the signature schemes. Every hash, MAC, key
derivation, AEAD and signature input is separated by a **label**, an ASCII
string such as `frasil/event/v1`; crypto.md's registry lists each label, its
use and its document, and the reserved strings. No label equals or prefixes
another, and a new label MUST keep this.

### 5.5 Error classes

Every check names the class it fails with, in UpperCamelCase. On the wire a
class is written in snake case (`malformed`), as [transport.md](transport.md)
and [peers.md](peers.md) list. A client's interface may merge classes; test
vectors give the exact class. Each class is of one sort:

- **Final:** the input is invalid for every replica that holds it.
- **Pending:** the decision waits for an event of this or another log, or a
  record that names a key. The input is kept, never applied and never cited,
  and decided again when that arrives.
- **Held:** the replica cannot open or interpret the input. It is not a
  verdict.
- **Content refused:** the unit is valid, but an adapter refuses its
  content, which has no effect ([units.md](units.md)).
- **Decision:** a receiver refuses one frame, message, request or
  connection. It says nothing about any event's validity.
- **Report:** a client tells its application something. It changes no
  verdict.

This section lists only the classes several documents share. Every other
class is defined in the document whose procedure raises it, and its sort is
given there.

| Class | Meaning | Sort |
|---|---|---|
| `TooLarge` | over a size or count limit | final |
| `Malformed` | not exactly one valid encoding, or a field rule broken | final |
| `UnsupportedVersion` | a version, suite or scheme this reader does not know | final |
| `InvalidKey` | a public key that [crypto.md](crypto.md)'s validation refuses | final |
| `BadSignature` | a signature that does not verify | final |
| `BadPossession` | a possession proof that does not verify | final |
| `NotCommitted` | public keys carried as a holder's that do not hash to the device ID or keys commitment they are named under ([crypto.md](crypto.md), "A device's keys") | final |
| `SchemeNotAllowed` | a scheme the structure may not carry | final |
| `BadSeal` | a sealed part that does not match or open under a key derived from checked secrets | final |
| `Decrypt` | an AEAD or a wrap that does not open under the key tried | final, for that key |
| `Forked` | the author forked its chain at or before this event | final; also a decision to detach a connection |
| `Full` | over 4,096 valid events of the log's own kind (roster events, or list events) in the valid past of one place, a space's counted from its checkpoint in effect there ([roster.md](roster.md), [identity.md](identity.md)) | final |
| `NoHybridKey` | the verifier holds no ML-DSA-65 key yet that, with an X-Wing key, hashes to the signer's keys commitment; it says nothing against the signer | pending |
| `Uncovered` | after the classical sunset, a scheme-0 event no scheme-2 event covers | pending |
| `Pending` | waits for an event of this or another log | pending |
| `Sealed` | no key held opens it | held |
| `ExtensionRequired` | uses a reserved hook that no extension this implementation has defines; it and everything after it are held | held |
| `NotAMember` | the signer is not a member where it is judged | final for an event; decision for a frame |
| `NotAnAdministrator` | the author does not hold `administer` at the event's place; in the skeleton, its administrator slot is not in | final |
| `Dropped` | a stranger's event, or one no held record lets the replica check; not kept | decision |
| `CapabilityRefused` | an adapter's capability check refuses a unit's content | content refused |
| `UnknownAdapter` | a unit of a type this replica has no adapter for; its content is ignored | report |
| `UnknownContentVersion` | content of a version its adapter does not know; it is ignored | report |
| `BadCompaction` | a snapshot unit whose cover, stubs or state do not match, or, with [ext-file-versions.md](ext-file-versions.md), whose supersessions differ from the replica's derivation; it is never used | report |
| `UnknownMessage` | a message type the receiver does not know | decision |
| `Replayed` | a message, request or nonce the receiver has already taken or answered | decision |
| `Expired` | an exchanged instant is past, or the receiver's wall clock is not known | decision |
| `RevisionMismatch` | the other end runs another revision (section 5.6) | decision |

### 5.6 Version policy

- This specification is **protocol 1**. Every format that carries a version
  carries 1, and every label ends in `/v1`, except where the registry or the
  format's document says otherwise: the device-list event body is version 3,
  the possession statement's label is `/v3` and the passkey PRF input's
  `/v2`,
  and connection names name the protocol, `p1`.
- A reader refuses a version, suite or scheme it does not know as
  `UnsupportedVersion`, never guesses and never rewrites; a stored record of
  an unknown version is kept.
- A change to a validity rule, a merge rule, a policy range, a
  must-understand kind, or a type that peers enforce is a new protocol, with
  new connection names. A new protocol takes the next protocol number;
  protocol 1 itself does not change incompatibly. A new binding, an
  ignorable kind or message type, a capability name or an application's
  ephemeral name is not a new protocol. Nor is an extension that gives
  meaning to a hook this specification reserves, where every
  implementation that lacks it holds, ignores or refuses what uses the
  hook as the hook says: [ext-invite-links.md](ext-invite-links.md) and
  [ext-restricted-spaces.md](ext-restricted-spaces.md) are such
  extensions. A key from 9 of a skeleton cut's body is such a hook
  ([peers.md](peers.md), section 2.4), held by peers and replicas alike,
  so that a later document can list administrator slots beyond one cut's
  512 without a new protocol.
- A **revision** number marks the protocol an implementation follows.
  Protocol 1's revision is 1, and it MUST NOT change within protocol 1.
  `Hello`, `PeerHello` and `Offer` carry it, and each end accepts only its
  own (`RevisionMismatch`). A device's store records it in its head
  ([at-rest.md](at-rest.md), section 2.5) and a space file in its manifest
  ([ext-space-files.md](ext-space-files.md), section 2.3); a reader refuses
  a store or a file that names another revision, or none, as
  `RevisionMismatch` before it opens anything in it.

## 6. Time

### 6.1 The principle

**Time decides what a device does next. It never decides whether an event is
valid.** No validity check reads a clock, and no verdict rests on a time
that signed data holds. Signed data holds times of three kinds, and none
decides validity: the `expires_at` of an invite grant and of a guest's
grant, which tell administering devices when to end the grant by a signed
event, and which no replica compares with a clock; the instants of section
6.6, each compared only by its receiver for its own next act; and times a
writer states in content, such as a Records change's `time` or a drive
entry's `added`, which are claims that decide nothing
([adapter-records.md](adapter-records.md), [ext-drive.md](ext-drive.md)). A clock decides only a
party's own next act: whether a device signs, wraps, writes, claims or tells
its person something, and what a peer does with its own storage. A client
may show when its device first saw an event, as that device's record.

### 6.2 Clocks

| Clock | Used for |
|---|---|
| The **monotonic clock**, which never jumps and keeps counting through suspend where the platform allows | Time while the device runs |
| The **wall clock**: seconds since 1970-01-01T00:00:00Z, as POSIX counts them | Time while the device was off; the instants of section 6.6 |
| Another party's clock (a `Date` header included), or any time inside an event | Nothing |

A wall clock is **known** when the platform says it is synchronised or backed
by a battery-powered clock.

### 6.3 The local timeline

Each device keeps one **timeline**, a count of seconds from 0 at its first
start whose differences are elapsed time. A **reading** is `(T, W, run)`:
the timeline, the wall clock or none, and the number of the start.

```text
The device keeps at rest its last reading (T_k, W_k); W_k is none when the
wall clock was not known.

start, and resume after a suspend in which the monotonic clock stopped:
  1. With no kept reading: base = 0.
  2. Otherwise, if the wall clock W is known now and W_k is not none:
       base = T_k + max(0, W − W_k).
     Otherwise: base = T_k.
  3. M0 = the monotonic clock. Keep (base, W).

while running:
  T = base + (monotonic clock − M0). The reading is (T, W now or none, run).
```

While the device runs, a change to the wall clock is not counted, then or
later; while it is off, the timeline adds the wall clock's advance, never
less than zero, and nothing without a known wall clock. A reading holds the
wall clock whenever it is known at that moment, even if it was not known
when the run started. A device MUST keep a reading at least once a minute
while it runs, and at shutdown; after a crash, the time since the last kept
reading counts once, as time off. A restore from a backup brings back the
reading and the first sights.

An always-on peer keeps a timeline by the same rules, for its own storage
and service, or one timeline per shard (section 6.7).

### 6.4 The two estimates

```text
lower(S, N) = N.T − S.T
upper(S, N) = max(N.T − S.T, N.W − S.W)    when S.W and N.W are both known
            = N.T − S.T                     otherwise, within one run
            = unbounded                     otherwise, across a restart
```

A rule that **waits** before acting MUST use the lower estimate, and a rule
that **stops** acting after a time MUST use the upper one. So a wrong wall
clock errs the unsafe way only if it was moved while the device was off.

### 6.5 First sight

The **first sight** of an event at a device is the device's reading when it
first accepted the event with every check passed, kept with the event and
never moved. A timed rule about an event MUST count from its first sight at
the deciding device, never from a time any party states. Devices may then
decide at different moments; each decision is that device's own act, so the
merged state does not diverge.

### 6.6 Instants exchanged between parties

Five values carry a wall-clock instant, in whole seconds, between parties.
Each is compared with the receiver's wall clock, never its timeline.

| Value | Checked by | Document |
|---|---|---|
| `expires_at` of an admission code request | the approver | [admission.md](admission.md) |
| `expires_at` of an invite grant | administering devices, the claimant | [ext-invite-links.md](ext-invite-links.md) |
| `expires_at` of a guest's grant | administering devices, the guest | [ext-guests.md](ext-guests.md) |
| `not_after` of a library ticket | the peer | [ext-libraries.md](ext-libraries.md) |
| `expires_at` of a device-signed request | the application's server | [ext-app-requests.md](ext-app-requests.md) |

```text
check_expiry(expires_at, now_wall, lifetime, skew), in order:
  1. The receiver's wall clock is known.             else Expired
  2. expires_at <= now_wall + lifetime + skew.       else Malformed
  3. now_wall <= expires_at.                         else Expired
```

Every sum here, `now_wall + lifetime + skew` included, saturates at
2^64 − 1 and never overflows.

### 6.7 Policy values and a peer's clock

A replica checks each duration a signed space policy carries, and a client
each lifetime it is about to sign, against section 6.8's range. It reads no
clock, so every replica decides alike; an event carrying a `Malformed`
policy is refused as a whole.

```text
check_policy(name, value), in order:
  1. value is an unsigned integer.                   else Malformed
  2. minimum(name) <= value <= maximum(name).        else Malformed
```

A peer keeps its own timeline and uses it only for its own storage and
service, which no replica reads. A peer run as a replicated service MUST
never count faster than the lower estimate of any machine that stored the
request.

A peer run on several machines MAY keep its timeline per **shard**: a part
of its state that one machine at a time keeps, such as one library
([ext-libraries.md](ext-libraries.md)), or a share by hash of the state that
belongs to no library or to no space, such as mailboxes. A shard's timeline
travels with the shard:

```text
The shard keeps with its state its last reading (T_k, W_k), kept at least
once a minute while a machine keeps it, and when the machine gives it up.

a machine that takes the shard up:
  1. With no kept reading: base = 0.
  2. Otherwise, if its wall clock W is known now and W_k is not none:
       base = T_k + max(0, W − W_k).
     Otherwise: base = T_k.
  3. M0 = its monotonic clock.

while it keeps the shard:
  T = base + (monotonic clock − M0).
```

This is section 6.3's rule, with the time between one machine giving the
shard up and the next taking it up counted as a device's time off. Every sight a peer records, such as a first sight, an
acceptance, a registration or a detachment, is on the timeline of the shard
that keeps it, and the peer compares two readings only on one timeline.
Where a document says the peer's timeline, it is that shard's.

A space that a move takes into another shard, such as into another library
([ext-libraries.md](ext-libraries.md), "Attaching"), keeps its own
timeline. With T_s, the space's reading at the move, and T_d, the reading
of the shard it moves into at the same move, the space's reading is
T_s + (T − T_d) for each later reading T of that shard. Every sight of the
space is on that timeline, and the peer MUST compare the space's sights
only with readings on it; its timers count on as they did, and never
faster.

### 6.8 Every timer

Durations are in seconds unless a unit is given. "Wall" is a wall-clock
instant; "lower" and "upper" are section 6.4's estimates. A space-policy
value is a policy field that every replica checks (section 6.7).

| Name | Bounds | Default | Range | Set by | Counted | In |
|---|---|---|---|---|---|---|
| `admission_code_lifetime` | an admission code request | 900 | fixed | protocol | wall, the joiner's clock | [admission.md](admission.md) |
| `admission_code_skew` | the same | 60 | fixed | protocol | wall | [admission.md](admission.md) |
| `exchange_mailbox_lifetime` | an exchange mailbox | `expires_at` + 60 | at most 1,020 after the request | the peer | the peer's timeline | [transport.md](transport.md) |
| `gap_key_timeout` | a restored member's gap keys; keeping a refused unit's content; settling a snapshot; a replica dropping erased content without stability | 7 days | 1 hour to 90 days | space policy | lower, from each holder's first sight of the restoring merge, the refusing event, the snapshot or the erasure | [keys.md](keys.md), [roster.md](roster.md), [units.md](units.md), [peers.md](peers.md) |
| `rotation_step` | the cascade delay, per rank | 2 | 1 to 10 | the implementation | lower, from first sight of the trigger | [keys.md](keys.md) |
| `rotation_rank_cap` | the highest rank the delay counts | 63 | fixed | protocol | | [keys.md](keys.md) |
| `anchor_interval` | anchors | 24 hours | 1 hour to 7 days | the implementation | lower, from the device's last anchor in the space | [crypto.md](crypto.md) |
| `replica_release_retention` | release at a replica | 30 days | at least 30 days | the application | lower, from first sight of the release | [units.md](units.md) |
| `erasure_timeout` (T) | erasure, credentials requests, reclaiming a release and collection, without stability at the peer; at the default, a device's report of its own erasure unconfirmed | 7 days | 1 hour to 90 days | the operator | lower, the peer's, from acceptance; the device's, from its erasure's first sight | [peers.md](peers.md) |
| `release_retention` | release at a peer | 30 days | 0 to 365 days | the operator | lower, the peer's, from acceptance | [peers.md](peers.md) |
| `cut_retention` | truncation at a peer after a cut is stable there | 30 days | 0 to 365 days | the operator | lower, the peer's, from the cut's stability at the peer | [peers.md](peers.md) |
| `orphan_grace` | an object no unit references | 24 hours | 1 hour to 30 days | the operator | lower, the peer's, from first sight of the object | [peers.md](peers.md) |
| `file_version_retention` | an old version of a file, superseded at every listing | 7 days | 0 to 365 days | the operator | lower, the peer's, from first sight of the earliest superseding unit | [ext-file-versions.md](ext-file-versions.md) |
| `version_compaction_interval` | compacting a Blobs stream whose units since its last snapshot carry supersessions | 24 hours | 1 hour to 7 days | the implementation | lower, from the client's first sight of the first such unit | [ext-file-versions.md](ext-file-versions.md) |
| `handshake_deadline` | a handshake, to the first `Admit` or refusal | 10 | fixed | protocol | monotonic | [transport.md](transport.md) |
| `probation` | an unknown member after a proven key state | 30, and 4,096 events | fixed | protocol | monotonic | [transport.md](transport.md) |
| `endpoint_rotation` | a device's member endpoint key | 24 hours, and at each new network | at most 24 hours | the implementation | the device's timeline | [transport.md](transport.md) |
| `gossip_interval` | head gossip and member addresses, per attach | 5 | at least 5 | the implementation | monotonic | [transport.md](transport.md) |
| `reannounce_interval` | a member connection's announcing again every object held whole, after it missed some that became whole | 30 | at least 30 | the implementation | monotonic | [units.md](units.md) |
| `withholding_grace` | a peer's `Missing` for a head statement's heads before it shows withholding | 300 | 60 to 3,600 | the implementation | monotonic, from the peer's first `Missing` for them | [units.md](units.md) |
| `present_retry` | presenting a refused read credential again | 1 | 1 to 30 | the implementation | monotonic | [transport.md](transport.md) |
| `reconnect_wait` | the random wait before the first attempt after a `reconnect` close | 5 | fixed | protocol | monotonic | [transport.md](transport.md) |
| `reconnect_wait_cap` | the bound of that wait, doubled after each failed attempt | 60 | fixed | protocol | monotonic | [transport.md](transport.md) |
| `reconnect_drain` | a stopping peer's wait for an import or a pending create before it drops the connection | 60 | 0 to 600 | the operator | monotonic | [transport.md](transport.md) |
| `pairing_deadline` | nearby pairing | 90 | fixed | protocol | monotonic | [transport.md](transport.md) |
| `mailbox_retention` | a person's or a device's mailbox | the operator's | at most 30 days | the operator | the peer's timeline | [transport.md](transport.md) |
| `uncollected_retention` | an item of a device mailbox that is not claimed | 72 hours | 1 hour to `mailbox_retention`, so at most 30 days | the operator | the peer's timeline, from the deposit | [transport.md](transport.md) |
| `link_lifetime` | an invite, ended by a revocation | 7 days | 15 minutes to 7 days | the inviter's client | wall, the inviter's clock; lower, from each administering device's first sight, for the maximum | [ext-invite-links.md](ext-invite-links.md) |
| `session_lifetime` | a guest session, ended by a removal | none | 15 minutes to 30 days | the granter's client | as `link_lifetime` | [ext-guests.md](ext-guests.md) |
| `bounded_window` | writing without hearing from another member | off | 1 hour to 90 days | space policy | upper, from the signing of this device's newest event another member has followed | [ext-guests.md](ext-guests.md) |
| `online_freshness` | writing without a recent sync with a peer of the space | off; 300 when on | 30 seconds to 1 hour | space policy | upper, from the last completed sync | [ext-guests.md](ext-guests.md) |
| `agent_waiting_period` | trusting a device an agent added | 72 hours | 72 hours to 30 days | space policy | lower, from each verifier's first sight of the `add` | [ext-recovery-agent.md](ext-recovery-agent.md) |
| `ephemeral_send_deadline` | an ephemeral frame in its sender's queue | 2 | fixed | protocol | monotonic | [ext-ephemeral.md](ext-ephemeral.md) |
| `ephemeral_key_wait` | ephemeral frames held for a rotation the receiver lacks | 5 | fixed | protocol | monotonic | [ext-ephemeral.md](ext-ephemeral.md) |
| `link_skew` | the claimant's check of an invite's `expires_at` | 60 | fixed | protocol | wall | [ext-invite-links.md](ext-invite-links.md) |
| `session_skew` | a guest's check of its session's `expires_at` | 60 | fixed | protocol | wall | [ext-guests.md](ext-guests.md) |
| `ticket_lifetime` | a library ticket | the issuer's | at most 24 hours | the issuer | wall, the peer's clock | [ext-libraries.md](ext-libraries.md) |
| `ticket_skew` | the same | 60 | fixed | protocol | wall | [ext-libraries.md](ext-libraries.md) |
| `detached_grace` | a detached space's data at a peer | 30 days | 1 to 365 days | the operator | lower, the peer's, from detachment | [ext-libraries.md](ext-libraries.md) |
| `token_period` | a deposit key's issuing, then its accepting only | 7 days | 1 to 30 days | the operator | upper, the keys' shard's, from the key's start: issuing for one period, then accepting only until two have passed | [ext-deposit-tokens.md](ext-deposit-tokens.md) |
| `allowance_window` | a library's deposit allowance | 24 hours | fixed | protocol | lower, the library's, from the window's first draw | [ext-deposit-tokens.md](ext-deposit-tokens.md) |
| `signed_request_lifetime` | a device-signed request | 60 | fixed | protocol | wall, the signer's clock | [ext-app-requests.md](ext-app-requests.md) |
| `signed_request_skew` | the same | 60 | fixed | protocol | wall | [ext-app-requests.md](ext-app-requests.md) |

Only the granter's client checks `link_lifetime` and `session_lifetime`,
when it signs; administering devices enforce the maximum from their first
sight. The operator's values apply per peer, or per library under
[ext-libraries.md](ext-libraries.md). A changed default changes its
document; a changed space-policy range is a new protocol.

## 7. Conformance

An implementation of **protocol 1 core** implements every core document. An
**extension** is optional. Each says which core documents it extends, and
what a core implementation that lacks it does with what it defines: refuse,
ignore, or hold as `ExtensionRequired`. [README.md](README.md) gives the
reading order; [rationale.md](rationale.md), informative, the reasons.

| Document | Specifies |
|---|---|
| **Core** | |
| [crypto.md](crypto.md) | Primitives, a device's keys and device ID, key validation, X-Wing wraps, signature schemes 0 and 2, anchors and coverage, the label registry |
| [events.md](events.md) | The envelope, event IDs, per-device chains, causal and canonical order, heads, placement, fork evidence, limits |
| [identity.md](identity.md) | Device keys, the person ID, the device list and its merge, recovery keys, passkey members, possession proofs, fingerprints, pins, sealed list copies, account links |
| [roster.md](roster.md) | The genesis, members and levels, capabilities, labels, history modes, changes, authority, resolution, frontiers and the write rule, checks across logs, grants of spaces, `replace`, refused units, the invite hook |
| [keys.md](keys.md) | Key states, rotations, derivations, wraps, grant keys and space wraps, notices, links and gap keys, entitlement, heals, cascades, body keys, metadata and object keys, sealed names |
| [units.md](units.md) | Streams, units, objects, compaction and stubs, heads and statements, baseline sync, acknowledgements, the space snapshot, the adapter interface |
| [transport.md](transport.md) | Transport requirements, the member and device-to-peer handshakes, framing, mailboxes, the server and iroh bindings, local discovery |
| [peers.md](peers.md) | What a peer stores and checks, storage credentials, catch-up, release and restore, collection, the skeleton and twins, stability at the peer, erasure, quotas |
| [admission.md](admission.md) | The admission event and code, lookups, the setup code, the welcome, the newcomer's snapshot and top-ups, access requests |
| [at-rest.md](at-rest.md) | What a device stores and how it is sealed, sealed device keys, restore detection, objects the application holds |
| **Extensions** | |
| [ext-invite-links.md](ext-invite-links.md) | Invite links, drops and claims; member type 3 and its successor |
| [ext-guests.md](ext-guests.md) | The guest preset, sessions, a guest's leave, nothing at rest, the bounded window and online-only |
| [ext-restricted-spaces.md](ext-restricted-spaces.md) | Restricted spaces and carve-outs |
| [ext-recovery-agent.md](ext-recovery-agent.md) | The recovery agent and its waiting period |
| [ext-ephemeral.md](ext-ephemeral.md) | The ephemeral channel |
| [ext-libraries.md](ext-libraries.md) | Libraries, tickets and usage at a peer |
| [ext-deposit-tokens.md](ext-deposit-tokens.md) | Anonymous tokens that pay for device-mailbox deposits, drawn against a library's allowance |
| [ext-app-requests.md](ext-app-requests.md) | Device-signed requests to application servers |
| [ext-drive.md](ext-drive.md) | Drives: folders, files and documents of a space in one Loro document; a file's versions, heads and conflicts |
| [ext-space-files.md](ext-space-files.md) | Space files: a space's events, units and objects in one file, with a way in: rotation secrets, invite fragments or nothing |
| [ext-file-versions.md](ext-file-versions.md) | File versions at a peer: the supersession a unit carries, and the retention by which a peer keeps a bounded number of old versions |
| [adapter-loro.md](adapter-loro.md), [adapter-records.md](adapter-records.md), [adapter-blobs.md](adapter-blobs.md) | The built-in adapters |

`overview.json` gives section 6.8's table in seconds, timelines with jumps,
restarts, suspends, an unknown wall clock and one that becomes known while
the device runs, with their estimates, `check_expiry` and `check_policy` at
and beyond each edge, and in `cbor_nesting` an array and a map nested 16
deep, accepted, and 17 deep, `Malformed` (section 5.3).

## 8. Glossary

One term per concept, in every document. Related terms share a row,
separated by semicolons in both columns. The last column names the
defining document.

| Term | Meaning | In |
|---|---|---|
| accepted | of units: valid by the write rule, with content the adapter does not refuse | units |
| account | an optional, signed link from a person ID to a subject at an identity provider | identity |
| acknowledgement | a statement of the events and objects a peer or member stored, by ID or locator | units |
| adapter; context | the code that gives a stream's units meaning; what it may read besides a unit's content | units |
| administer; administrator | the highest level; a device member at it | roster |
| administrator pseudonym | the key pair a device makes for one administrator slot, under which it acts at peers | peers |
| administrator skeleton; administrator slot | a space's administrators under pseudonyms; one grant of `administer` to one device, as the skeleton shows it | peers |
| admission code | the mutual six-digit code both screens show before an admission | admission |
| admitted | of a Records changeset's clock: supported by the changesets that exist | adapter-records |
| always-on peer, peer | a party that relays and stores events without judging them; devices that sync directly are members, not peers | peers |
| anchor | a kind-5 event under scheme 2 that covers its author's past | crypto |
| attach | one space joined to a connection by its own proof | transport |
| attack | the relation by which a valid event voids a concurrent one, such as a removal of its author | roster, identity |
| authority event | an event of kind 1, 2, 5 or 6 | crypto |
| base | the heads and stubs a replica that starts from a snapshot holds | units |
| body key | the per-event key of a space event's or a unit's sealed part | keys, units |
| break | a rotation that gives a from-now-on newcomer no link to earlier keys | keys |
| candidate; candidate state | a device that may make a cascade's rotation; a state a handshake's responder tests | keys; transport |
| canonical order | by height, then by event ID | events |
| capability; suggester | an application-defined name that extends or narrows a grant; a writer that `suggest` narrows | roster; units |
| carve-out | a space made to give a guest one document of a larger space | ext-restricted-spaces |
| cascade | the rotation of a space that inherits a loss through a grant | keys |
| chain | one author's events in one log, numbered by `seq` | events |
| checkpoint; record; epoch | a roster event that fixes the roster of its past; the roster, policy, tips and forks it carries; its number in the chain of checkpoints | roster |
| cut; follows | the checkpoints an event's envelope declares; an event whose cuts reach a checkpoint | events |
| in effect; vote; electorate | a valid checkpoint every administrator of its record voted for; a device's first event after it; those administrators, but dormant ones | roster |
| late | with a checkpoint in effect, an event neither in its past nor after it | roster |
| changeset; stamp | one Records transaction, the content of one unit; the order of a cell's values: a logical clock, then the writer, then the event ID | adapter-records |
| claimed | of a device mailbox at a peer: collected by its device there within `mailbox_retention` | transport |
| classical sunset | the future revision from which a scheme-0 event counts only if covered | crypto |
| client; application | the Frasil implementation on a device; the software that uses it | overview |
| collect | to delete a unit's or object's bytes from one's own storage | units |
| completion | a delivery a view calls for: a key, link or wrap that an entitled holder lacks | keys |
| content key | the key a state's units and objects derive from | keys |
| content refusal | an adapter's refusal of a valid unit's content, which then has no effect | units |
| contested | of a log's roster or list events: those other than the genesis that pass the event-alone checks, and for a roster event, whose author has standing in its past | roster, identity |
| cover | the units a snapshot unit replaces | units |
| covered | named by hash, through `prev` and parents, from an accepted scheme-2 event | crypto |
| delivery | in a key event, a map that names a state and carries its wraps | keys |
| deposit token; deposit grant; deposit key; allowance; space share | an anonymous, single-use token that pays for one device-mailbox deposit at the peer that issued it; a library ticket of purpose 4 that lets one device draw tokens once; the key under which a peer issues and checks them for a period; the tokens a library may draw per day; the part of it the writers of one space may draw without a grant | ext-deposit-tokens |
| kind string | an application's name for what a space, an entry or a file holds: 1 to 64 bytes without a control character or white space | ext-drive; ext-space-files |
| list delivery | a set of a person's list events given to an application's server | ext-app-requests |
| device list | a person's log of `add`, `revoke` and `confirm` events | identity |
| device; device member | a client with its own three key pairs; a device granted directly by a roster | identity; roster |
| device ID; keys commitment (`kc`) | the hash that names a device or any other holder of keys that signs events, from its Ed25519 key and `kc`; the hash of its ML-DSA-65 and X-Wing keys | crypto |
| drive; drive entry; purge | a tree of folders and named entries in one Loro document of a space; one node of it, a folder, a file or a document; to forget an entry and what is inside it for good | ext-drive |
| durable | of a device's own event: acknowledged by a peer of the space, or by another member where there is none | units |
| effective membership | every device that reaches a space, with its level | roster |
| endpoint key | the key a transport's handshake proves; it rotates and is never a device's key | transport |
| entitled; potential holder | of a member, allowed to receive a state; the grantee of any break, valid or void, in a state's past | keys |
| ephemeral message; ephemeral slot | a fire-and-forget message on the ephemeral channel, broadcast to a space or targeted at 1 to 16 devices; a latest-wins value on that channel | ext-ephemeral |
| erasure; release | an administrator's request that peers delete a whole space, carried out once stable at the peer or after T; a writer's request that peers stop serving one stream and delete its content after the retention, which a restore undoes | peers |
| event; event ID | anything signed and synced; the hash of its unsigned bytes | events |
| exchange mailbox | a mailbox at a peer that relays one admission exchange | transport |
| fetch key; recovery entry | an Ed25519 key a passkey, a recovery sheet or a random seed gives; its registration at a space's peers, which grants catch-up only | identity |
| fingerprint | 120 bits of a hash of a person ID and one member's keys, shown as 25 characters | identity |
| first sight | a device's reading when it first accepted an event | overview |
| fork; fork point; fork evidence; equivocation proof | two events of one author at one `seq`, or one that skips; the first `seq` it voids; the events that show it; that evidence passed to another replica | events |
| founder | the device whose genesis made the space | roster |
| frame | of a partial replica: every space event, anchor and storage event, and the system stream | units |
| fresh entry; fresh-only | a target's latest receiver nonce, carried in a targeted ephemeral message; of an application's name, refused without a fresh entry | ext-ephemeral |
| from now on; with history | the two history modes | roster |
| frontier | for an event that ends a member's write, the latest event of each of its devices in its past | roster |
| gap key | an earlier key sent by wrap where no link hangs | keys |
| generation; mark | the store head's commit count; its sealed copy in the device-bound slot, which reveals a restore | at-rest |
| genesis | the first event of a log, whose ID is the log's ID | events |
| grant key; grant state | a space's X-Wing key pair for space wraps, held by members that propagate; the valid grant rotations no other follows | keys |
| grant; grant graph | a change that admits a member; the edges from each space to the spaces it grants, of which a rule counts some | roster |
| guest | a device granted with `session` set | ext-guests |
| hand-over; departure record | an operator's move of a space, as it stands, to another peer; what the peer it leaves keeps to answer `moved` | peers |
| head statement | a member's signed list of its heads, to notice forks and rollbacks | units |
| heads | the events of a view in no other event's past | events |
| heal | a rotation made because the outside could derive the current key | keys |
| held | kept but not opened; not a verdict | overview |
| held object; application-held object | an object whose plaintext the application keeps through its object provider, in place of sealed chunks, on one device; distinct from a hold | at-rest |
| hold; copy | a space's registration at a peer that keeps and serves an object another space of its library stores; a library's own copy of a held object, made by a move so that a hold stays within one library | ext-libraries |
| home peer | the peer that hosts a library, which its issuer names beside a ticket | ext-libraries |
| identity key | a device's Ed25519 key, which signs; it never names a device alone | crypto |
| incarnation | a run of a Loro writer's edits in a stream, to which one peer ID is bound | adapter-loro |
| informed writer | a device that reaches a space at `write`, propagates there and holds the change's new state | keys |
| inside; outside | the devices of a space's merged roster; every other holder of a state | keys |
| issuer; ledger | the service an operator trusts to sign library tickets; a peer's usage record per library | ext-libraries |
| key event | a space event with no membership change | roster |
| key name; self reference | how a wrap, link or delivery names a state; the name of the carrying event's own rotation | keys |
| key reference | how a unit names the state it is sealed under | keys |
| known past | the heads of a person's or space's log that a grant carries in its refs | roster |
| label | a string that separates one use of a primitive from every other | crypto |
| late write | a unit of a moved document's original stream, a move unit aside, that is in the past of no accepted move unit | ext-restricted-spaces |
| level | `read`, `write` or `administer` | roster |
| library | what an operator bills and limits at a peer | ext-libraries |
| link; link gate | an earlier key sealed under a later one; the rule that lets a link hang only where every possible holder is entitled | keys |
| list member | a device ID a valid `add` names, with its keys | identity |
| listing; supersession; superseded | one stored unit and one locator in its `objects`; a unit's visible statement that an object it lists replaces an earlier object of its stream, naming the listing it replaces; of a listing, named so by a stored unit of its stream | units; ext-file-versions |
| locator | an object's ID and the SHA-256 of its stored bytes | units |
| log unit; snapshot unit; seed | a unit that is no snapshot; one that declares a cover; one with an empty cover that starts a stream from a copy | units |
| log; log key | the events that share one genesis; a device's key for that log's records at rest | events; at-rest |
| member | what a roster grants: a device, a person, a space or an invite key | roster |
| member connection; device-to-peer connection; nearby connection | one between two devices; one between a device and a peer; one that carries a single admission exchange on a local network | transport |
| merged roster | a view's valid roster events, with the space principals in force | keys |
| move record; pointer | the map that points from a document's old stream to its new one; the same map in the original space's index document | ext-restricted-spaces |
| mutual pair | two events that each lower the other's author; the outranking author's stands (rank, then seniority) | roster |
| newcomer | a member an admission grants, until it holds the current state | admission |
| notice; space principal | a key event's hand-over of a granted space's grant key; the pair a valid notice makes | keys |
| object | content-addressed, chunked bytes named by units | units |
| object provider | what the application gives to hold a space's objects: `stat`, `open`, `create` and `forget` over tokens | at-rest |
| object key; access key | the key that opens one object, derived from its state's key; the Ed25519 key derived from it that a hold proves | units; ext-libraries |
| opening | a stream's adapter type and salt, which its ID commits to | units |
| origin | 8 random bytes a peer draws per connection and space, which tell ephemeral senders apart without naming them | ext-ephemeral |
| parent | the space a restricted space is a private part of, whose content key its own derives from | ext-restricted-spaces |
| passkey member | the list member whose keys a passkey derives | identity |
| path; end | a chain of grants by which a device reaches a space; an event of another log that cuts it | roster |
| peer hint | the origin of an always-on peer of a space, carried in a welcome | admission |
| pending | waiting for what the replica lacks; never applied or cited | overview |
| person mailbox; device mailbox | a peer's mailbox for a person's prompts; one for a device's sealed items | transport |
| person; person ID | the keys of one device list; the event ID of its first event | identity |
| personal space; recovery sheet | the space that holds a person's list; the printed recovery-key secret, with the person ID and personal space ID | identity |
| pin | a client's kept list events, which reveal a list rolled back | identity |
| place | the valid roster events, or list events, in an event's past, with the genesis | roster, identity |
| possession proof | a key's scheme-2 signature over the statement that binds it to a person and an adder | identity |
| probation | a bounded time in which a verifier serves a device that proved a state its view does not name | transport |
| propagates | said of a grant without `session` | roster |
| rank | the order of list members that settles mutual revocations; the order of a cascade's candidates | identity; keys |
| read credential; upload key | the per-state Ed25519 key pairs for fetching and storing at a peer | keys |
| reading | a timeline value `(T, W, run)` | overview |
| rebuild set | per stream, the latest settled snapshot and the units after it | units |
| receiver nonce | a 16-byte value a device draws whenever it starts receiving a space's ephemeral channel, and publishes as an ephemeral slot | ext-ephemeral |
| record | a sealed name with its space and key reference; at rest, one sealed value of the store | keys; at-rest |
| recorded person; signer | the person a verifier records for an account's subject at its first accepted request; the list member whose Ed25519 key signs a device-signed request | ext-app-requests |
| recovery agent | a list member that may only add a device, after a waiting period | ext-recovery-agent |
| recovery key | the list member printed on a recovery sheet | identity |
| refs | the sealed list of other logs' events an event cites | events |
| reference | a Blobs entry that names an object another space of its library stores, with the object's key | adapter-blobs |
| refused | said of a unit the write rule rejects; it is kept | roster |
| replica, full, partial | a device that holds a log and judges its events, all of it or its frame and some streams | units |
| response | an event of one space that answers a change in another and names it in its refs | roster |
| restore mode | whether the application gives a device-bound slot | at-rest |
| restricted space | a private part of a parent space | ext-restricted-spaces |
| rooted; waiting; dead | brought in by a passkey or agent, until confirmed; rooted in an agent; of a list, with no member able to sign | identity |
| roster; roster event | a space's membership; a space event that changes it | roster |
| rotation | a space event that draws fresh key secrets | keys |
| scheme | how a structure is signed: 0, Ed25519; 2, Ed25519 and ML-DSA-65 | crypto |
| sealed device keys; store secret | a device's seeds and store secret, sealed under its unlock key; the secret its at-rest keys derive from | at-rest |
| sealed name; metadata key | a name sealed under a state's metadata key and bound to what it names; the key derived from a state's content key for names | keys |
| self-lowering | of an event: every change lowers its own author | roster |
| session | the 16-byte value shared by guests granted together | roster |
| settled | of a snapshot: stable, or held for `gap_key_timeout` | units |
| shard | a part of a peer's state that one of its machines keeps at a time, with its own timeline | overview |
| space event | an event of kind 2 | roster |
| space file; way in; file key | one space, or part of it, as a peer serves it, in a file any implementation reads; the file's secret part, rotation secrets or invite fragments or nothing, which may be sealed; the 32-byte key the application supplies to seal it | ext-space-files |
| space policy | a space's signed timed values and settings | roster |
| space recovery member | a device member at `administer` whose key is kept offline | roster |
| space snapshot | what a from-now-on newcomer starts from | units |
| space wrap | a wrap sealed to a granted space's grant key | keys |
| space; space ID | the unit of sharing and encryption; its genesis's event ID | roster |
| stable; stable at the peer | in the past of an event by every administrator that has not forked; the skeleton's form | roster; peers |
| state | a set of rotations, and the keys derived from them | keys |
| storage event | an event of kind 6: a skeleton event or a writer's request | peers |
| stream past; stream frontier | the units of a stream in a unit's causal past; a writer's newest unit among a set | units |
| stream; system stream | a document's place in a space; the one for Frasil's own units | units |
| stub | an event's ID, author, `seq`, height and kind, standing in for a collected event | units |
| suggestion; suggestion layer | content kept apart from the main state until a writer that is not a suggester accepts or dismisses it; a stream's accepted suggestion units | adapter-loro, adapter-records |
| ticket; library ticket | an address to dial, which holds no secret and grants nothing; an issuer's signature that lets one device attach one space to one library, once | transport; ext-libraries |
| timeline | a device's count of elapsed seconds; a peer's, or a shard's | overview |
| tips | the newest event per log and per signing key of this device, kept in the store's head | at-rest |
| token; stamp | how the application names a held object's plaintext to its provider, 1 to 1,024 opaque bytes; its opaque change marker, 1 to 64 bytes, compared byte for byte | at-rest |
| twin | the skeleton event that mirrors a roster event that changes who administers | peers |
| unit | an event of kind 4 that carries application data | units |
| valid; void | an event's final verdicts at a replica | events |
| version; head of a file; conflict | a blob a file entry has pointed at, recorded with the versions it was made from; a version no other names; a file with two or more heads | ext-drive |
| vector | per author, the greatest `seq` a replica holds and its event's ID | units |
| view | a set of placed events closed under parents | events |
| waiting period; veto | the time a verifier counts from its first sight of an agent's `add` before it trusts the added device; a revocation of that device by the person's own list member | ext-recovery-agent |
| witnessed | of a partial replica: a parent fetched and checked though outside its frame | units |
| wrap | a plaintext sealed to one X-Wing key | crypto |
| X-Wing key | a hybrid ML-KEM-768 and X25519 key, to which keys are wrapped | crypto |
