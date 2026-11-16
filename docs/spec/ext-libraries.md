# Libraries
Protocol 1. Vectors: [ext-libraries.json](vectors/ext-libraries.json).

This document specifies **libraries**: what an operator bills and limits at
an always-on peer, the **library ticket** by which a writer's device
attaches a space to a library, the usage a peer keeps per library, and the
**holds** by which the spaces of one library share a file stored once. It
extends [peers.md](peers.md), whose hosting policy, quotas, objects and
refusal codes it fills in, and [transport.md](transport.md), which reserves
message types 21 (`LibraryAttach`) and 31 (`HoldObject`) for it. It depends
on [overview.md](overview.md) for conventions, error classes and time, on
[units.md](units.md) for objects and their keys,
[adapter-blobs.md](adapter-blobs.md) for the reference entries a hold
serves, and on [crypto.md](crypto.md) for the labels
`frasil/library-ticket/v1`, `frasil/object-access/v1` and
`frasil/object-hold/v1`.

A core implementation that does not implement it:

| What this document defines | A core implementation |
|---|---|
| Message types 21, `LibraryAttach`, and 31, `HoldObject`, and service 5 | a device never sends them; a peer never lists the service, and closes a connection that sends type 21 or 31, as for an unknown type (`UnknownMessage`) |
| Libraries, tickets and ledgers | a peer hosts spaces by its operator's own policy ([peers.md](peers.md), "Hosting a space") |
| Holds | a peer keeps and serves an object only for its own space; a device copies a file into each space that uses it |
| `no_library` and `library_closed` | a peer uses them for its own hosting, as [peers.md](peers.md) says |
| The home peer | a device learns its peers from its application and from the space's peer hints ([admission.md](admission.md), "The welcome") |

Nothing in a log, roster or event refers to a library, so no replica's
verdict depends on this extension. A reference entry names its source
space, never a library.

## 1. Overview

- A **library** exists only at a peer. It grants nothing and refuses
  nothing but storage there, and no replica ever learns of it.
- A space is billed to at most one library at each peer that hosts it. A
  peer that implements this extension stores into a space only while the
  space is attached to an open library.
- A **library ticket** lets one device attach one space to one library,
  once. Its **issuer**, a service the operator trusts, such as the account
  server that sells the library, signs it. The issuer MAY be the peer's
  operator itself, with a key of its own and a **default library** for the
  people it hands tickets to; to the peer it is a trusted issuer like any
  other. A ticket names a library and never an account, a person, a device
  or a space. With
  [ext-deposit-tokens.md](ext-deposit-tokens.md), a ticket of purpose 4
  instead lets one device draw deposit tokens against the library, once.
- A ticket travels from the application to the peer as opaque bytes. The
  client never reads it, and no member learns the library.
- The peer learns which library each space is billed to, and not who pays.
  The issuer learns its libraries' spaces by ID and their bytes, and
  nothing in them.
- A file is stored once per library. A space that uses a file another space
  of its library stores holds a **reference** to it
  ([adapter-blobs.md](adapter-blobs.md)): the object's locator and its
  **object key** ([units.md](units.md), section 2.8), sealed in the
  referencing space like any entry. The referencing space registers a
  **hold** at the peer, proving the object's key without reading the
  source. The peer keeps the object while the source or any hold uses it,
  serves it to the holding space's readers, and counts it once in the
  library's ledger.
- A reference never crosses libraries: the peer refuses a hold whose two
  spaces are billed to different libraries (`OtherLibrary`), and a device
  copies the file into the other library's space instead. A move that
  would leave a hold between two libraries makes the peer copy the object
  into the holding space's library, so every hold stays within one.
- A library's **home peer** is where its operator hosts it. The issuer
  names it beside each ticket, and welcomes carry it to members.

## 2. Formats

### 2.1 The library ID

A library ID is 1 to 128 bytes of UTF-8, with no control character (Unicode
category Cc) and not only white space (`Malformed`). It is the operator's
or the issuer's name for a billing pool, opaque to the peer. It MUST NOT
hold an account subject, a person ID or a device key. An issuer MAY begin
it with a prefix that names a kind, such as `personal:` or `project:`,
followed by random characters, and maps IDs to accounts in its own records.

### 2.2 The library ticket

```text
ticket    = deterministic CBOR map {
              1: version, 1,
              2: library, text: a library ID,
              3: id, bytes(16): random, drawn by the issuer,
              4: purpose, unsigned: 1 create, 2 import, 3 move,
                 4 deposit tokens (ext-deposit-tokens.md),
              5: not_after, unsigned: a wall-clock instant,
              6: issuer, bytes(32): the issuer's Ed25519 public key,
              7: tokens, unsigned: 1 to 256; exactly for purpose 4 }
signed    = CBOR array [ticket (bytes), signature (bytes)]          at most 512 bytes
signature = Ed25519-Sign(issuer's seed, "frasil/library-ticket/v1" || ticket)   64 bytes
```

The signature is scheme 0, verified once, at once ([crypto.md](crypto.md)).

### 2.3 LibraryAttach

```text
LibraryAttach = {0: 21, 1: request, 2: space (32), 3: purpose, 4: signed}
```

It travels on the control stream of a space-traffic connection, never an
administration connection ([transport.md](transport.md), section 3.10),
and only to a peer whose `PeerHello` lists service 5, `library`. It has
exactly these keys. `request` numbers it among the device's requests on
the connection. The peer answers `Accepted` or `Refused` with a code.

### 2.4 Settings

| Setting | Scope | Default | Range | Set by |
|---|---|---|---|---|
| `quota` | a library | the operator's default for the ID's kind, or none | bytes, or none | the operator, or the issuer for its libraries; the last write stands |
| `erasure_timeout` (T) | a library | the peer's T ([overview.md](overview.md)) | 1 hour to 90 days | the same |
| `state` | a library | `open` | `open` or `suspended` | the same |
| `open_until` | a library | none | an instant in seconds since 1970, or none | the same |
| trusted issuers | the peer | none | at most 16 Ed25519 keys | the operator |
| `detached_grace` | the peer | 30 days | 1 to 365 days | the operator |
| `max_file_versions`, `file_version_retention` | a library, or the peer | 100; 7 days | [ext-file-versions.md](ext-file-versions.md) | the operator |
| open library | the peer | none | a library ID, or none | the operator |

A library's `quota` covers all its spaces, and its T applies to every space
billed to it ([peers.md](peers.md)), in place of the peer's. The operator's
other values apply to the whole peer.

A library's state is `suspended` while its `state` setting is `suspended`,
and also once its `open_until` is set and the peer's wall clock is at or
past it, or not known. Otherwise it is `open`. `open_until` lets whoever
pays for the library bound it in time without a further write: the issuer
moves it forward as payment continues, and the library closes on time if
no write comes.

The **open library** is the operator's own hosting. A create that no
`LibraryAttach` precedes attaches its space to the open library, with no
ticket; with none set, its genesis is `NoLibrary`. Which library is open,
and whether any is, is operator configuration.

### 2.5 What a peer keeps

Per space: its library, the ticket ID that attached it, and the peer's
reading when the attachment took effect. Per ticket ID used: its
`not_after`, until that instant and `ticket_skew` have passed. Per hold
(section 3.7), named by its holding space and the object's locator: the
source space, the access key it was registered with, the peer's reading at
its registration, and whether it points at its library's copy. Per copy
(section 3.8), named by its library and the object's locator: the source
space, and the peer's reading when the copy was made. Per library, its
**ledger**:

| Field | Value |
|---|---|
| `used_bytes` | the usage of its spaces ([peers.md](peers.md), "Quotas and rates"), and its copies (section 3.8) |
| `drops`, `drop_bytes` | its spaces' invite drops ([ext-invite-links.md](ext-invite-links.md)), counted in `used_bytes` |
| `released_bytes`, `covered_bytes`, `erasing_bytes` | released and not reclaimed; covered and not collected; of spaces whose erasure waits. Released and covered bytes do not count in `used_bytes`; a space's bytes count there until its erasure executes ([peers.md](peers.md), "Erasure") |
| `held_bytes` | the bytes of objects that only holds keep (section 3.8), its copies included, counted in `used_bytes` once each |
| `quota_bytes`, `headroom_bytes` | the quota, and the quota less `used_bytes`; none when there is no quota |
| `spaces` | per space: its ID, `used_bytes`, `released_bytes`, `covered_bytes`, `held_bytes`, `drops`, `drop_bytes`, `holds` (the holds it registered), its stream count, and the day of its last store |

### 2.6 Error classes

Besides [overview.md](overview.md)'s classes, this document uses
[peers.md](peers.md)'s class `NotAuthorized` and its refusal codes
`quota_exceeded`, `no_library`, `library_closed` and `erased`, written here
as the classes `QuotaExceeded`, `NoLibrary`, `LibraryClosed` and `Erased`
with peers.md's statuses (section 2.8), and seven of its own. All are of
sort decision:

| Class | Code | Status | Meaning |
|---|---|---|---|
| `NotAuthorized` | `not_authorized` | 403 | a move or a hold without the store right, or a create whose first stored event is not the genesis |
| `QuotaExceeded` | `quota_exceeded` | 507 | a store past the library's quota, or a move without headroom |
| `NoLibrary` | `no_library` | 507 | a store into a space attached to no library |
| `LibraryClosed` | `library_closed` | 507 | a ticket or a store for a suspended library |
| `Erased` | `erased` | 410 | the genesis of a create of a space this peer erased, deleted or handed over, or of an import of one it erased |
| `TicketRefused` | `ticket_refused` | 403 | an untrusted issuer, a signature that does not verify, or another purpose |
| `TicketExpired` | `ticket_expired` | 403 | `check_expiry` refuses the ticket |
| `TicketUsed` | `ticket_used` | 409 | a ticket ID that already attached a space, or drew deposit tokens, at this peer |
| `SpaceExists` | `space_exists` | 409 | a create or an import of a space this peer hosts |
| `HoldRefused` | `hold_refused` | 403 | a hold whose proof does not verify, or whose access key nothing vouches for |
| `UnknownObject` | `unknown_object` | 404 | a hold of an object the source does not hold whole at this peer |
| `OtherLibrary` | `other_library` | 409 | a hold whose space and source are billed to different libraries, where the space's library keeps no copy of the object |


### 2.7 Object keys and access keys

```text
object key  = HMAC(object_seal_key(S), object ID)                    units.md, section 2.8
access_seed = HKDF(none, object key, "frasil/object-access/v1")      32 bytes
access key  = the Ed25519 public key of access_seed
```

Whoever holds an object's key derives its access key: a reader of the
source from `k(S)`, a reader of a referencing space from the reference
entry. The access key is one-way: it tells nothing of the object key or of
the plaintext. Equal files under different states have unrelated object
keys and access keys.

### 2.8 HoldObject

```text
HoldObject = {0: 31, 1: request, 2: space (32), 3: source (32), 4: locator (64),
              5: access (32), 6: proof (64)}
held       = field(binding) || field(space) || field(source) || field(locator)
             || field(access)
proof      = Ed25519-Sign(access_seed, "frasil/object-hold/v1" || held)
```

- `space` is the **holding space**, whose reference entry names the
  object; `source` is the space that stores it; `locator` is the object's
  ([units.md](units.md)); `access` is its access key. `binding` is the
  connection's ([transport.md](transport.md), section 3.10).
- It travels like `LibraryAttach`: on the control stream of a space-traffic
  connection, to a peer whose `PeerHello` lists service 5. It has exactly
  these keys. The peer answers `Accepted` or `Refused` with a code.
- The proof is scheme 0, verified once, at once ([crypto.md](crypto.md)).
  Through `binding` it is worthless on another connection.

## 3. Procedures

### 3.1 Getting a ticket

The application asks its issuer for a ticket over its own account traffic
and hands the signed ticket to the client as opaque bytes. The client
passes it to the peer in `LibraryAttach`, and never reads, stores at rest
or shows it. A client MAY hold a few unused tickets ahead of need, so that
asking for one does not coincide with creating a space. The issuer returns
the library's home peer beside each ticket (section 3.10). The issuer sets
`not_after` at most `ticket_lifetime`, 24 hours, after it signs.

### 3.2 Checking a ticket

```text
check_ticket(signed, purpose), in order:
  1. len(signed) <= 512; a CBOR array of two byte strings, the
     second of 64 bytes; the first a deterministic CBOR map of
     exactly keys 1 to 6, and 7 for purpose 4; version 1; a library
     ID by section 2.1; id of 16 bytes; purpose 1, 2 or 3, or 4
     where ext-deposit-tokens.md is implemented; not_after unsigned;
     issuer of 32 bytes; tokens, where present, 1 to 256.          else Malformed
  2. issuer is one this peer trusts, and passes ed25519_valid
     (crypto.md).                                                  else TicketRefused
  3. The signature verifies strictly under issuer.                 else TicketRefused
  4. overview.md's check_expiry(not_after, the peer's wall clock,
     ticket_lifetime, ticket_skew) accepts.                        else TicketExpired
  5. id has not attached a space, or drawn deposit tokens, at
     this peer.                                                    else TicketUsed
  6. The ticket's purpose is the request's.                        else TicketRefused
  7. The library's state is open.                                  else LibraryClosed
```

A library the peer does not yet know is created at its first ticket, with
section 2.4's defaults.

### 3.3 Attaching

The peer checks a `LibraryAttach`, in order, then records section 2.5's
attachment and the ticket ID:

**Create** (purpose 1): the space is new to this peer.

1. The peer does not host the space (else `SpaceExists`).
2. `check_ticket`.
3. The peer answers `Accepted`; the ticket is now used. The first event
   the connection then stores for the space MUST be its genesis, whose
   event ID is the space ID ([peers.md](peers.md), "Hosting a space");
   anything else is `NotAuthorized`. A genesis of a space this peer
   erased, deleted or handed over is refused `Erased` there
   ([peers.md](peers.md), "Storing an event", step 3). The pending create
   lapses when the connection closes before it stores the genesis, or when
   its genesis is refused, and the ticket stays used.

**Import** (purpose 2): the space comes to this peer with its history.

1. The peer does not host the space (else `SpaceExists`).
2. `check_ticket`.
3. The device stores the log as [peers.md](peers.md)'s import says. A
   genesis of a space this peer erased is refused `Erased`, and the import
   lapses, as a create does. A space the operator deleted, or that this
   peer handed over, may be imported.

**Move** (purpose 3): the space is hosted here, in another library or in
none.

1. The connection holds the store right for the space (else
   `NotAuthorized`). Any writer may move a space's billing.
2. `check_ticket`.
3. The target library's headroom holds the space's current usage and
   every copy the move makes into the target (section 3.8) (else
   `QuotaExceeded`). A copy the move makes into the library the space
   leaves needs no headroom: the space's usage, which counted the object,
   leaves that library in the same step.
4. The space's usage leaves its library's ledger and joins the target's,
   and the peer makes section 3.8's copies, in one step.

### 3.4 Storing

A peer that implements this extension adds to [peers.md](peers.md)'s
checks before it stores an event or an object, at its step "The space is
hosted here":

```text
  1. The space is attached to a library.                           else NoLibrary
  2. The library's state is open.                                  else LibraryClosed
```

and at its quota step, the library's quota over all its spaces
(`QuotaExceeded`). Fetches, holds, releases, restores, erasures and
collection skip steps 1 and 2: they read, add no bytes, or lower usage. A restore still counts its
bytes again under the quota, and is refused `quota_exceeded` if they no
longer fit ([peers.md](peers.md), "Release and restore").

### 3.5 Detaching, suspending and deleting

- **Detaching.** Whoever pays for the library, or the operator, detaches a space
  from its library through the operator's interface: the library stops
  paying for it. The space then accepts no store (`NoLibrary`) and still
  serves fetches. Any writer attaches it again by a move. After
  `detached_grace`, on the lower estimate of the peer's timeline from the
  detachment, the operator MAY delete the space's data at this peer.
- **Suspending.** A suspended library accepts no store for any of its
  spaces and no ticket (`LibraryClosed`), whether its `state` setting
  suspends it or its `open_until` has passed (section 2.4). Its spaces
  still serve fetches. Setting it open again, or moving `open_until`
  past the peer's wall clock, reopens it at once: the spaces stay
  attached throughout.
- **Deleting** a space or a library at a peer is the operator's control
  over its own storage, which no client can prevent. It removes the space's
  events and objects at this peer and keeps the space ID, so that a
  replayed genesis cannot create an empty space under an ID members hold
  keys for: a later create of it is `Erased`. It is not an erasure
  ([peers.md](peers.md)): it needs no administrator, waits for no
  stability, and leaves replicas and other peers their copies.

### 3.6 Usage and refusals

- The issuer reads its libraries' ledgers and sets their settings through
  the operator's interface. Per-author usage ([peers.md](peers.md),
  "Attribution") never reaches the issuer: authors are devices, and the
  issuer would link them to the account.
- Discovery's `account_url` ([transport.md](transport.md), the server
  binding) is the operator's page where a person sees the ledgers of the
  libraries their account pays for.
- A client that receives `QuotaExceeded` or `LibraryClosed` reports the code
  to its application, which points its person to `account_url`. On
  `NoLibrary` the application attaches the space with a ticket, or syncs
  through another peer. On `moved` ([peers.md](peers.md), "Refusal
  codes") it finds the space's home peer (section 3.10). The client's
  interface carries codes, opaque tickets and peer URLs, and never a
  library, ledger or quota.


### 3.7 Registering a hold

A writer of the holding space registers a hold before it puts the reference
([adapter-blobs.md](adapter-blobs.md), "References"), at each peer that
hosts the space and lists service 5. The peer checks a `HoldObject`, in
order:

```text
1. Exactly keys 0 to 6; request unsigned; space and source of 32
   bytes and not equal; locator of 64; access of 32; proof of 64.  else Malformed
2. The connection holds the store right for space.                 else NotAuthorized
3. access passes ed25519_valid (crypto.md), and proof verifies
   strictly under it over held.                                    else HoldRefused
4. The connection holds the fetch right for source, or a hold of
   locator at this peer was registered with access.                else HoldRefused
5. The peer hosts source and holds the object under locator
   whole.                                                          else UnknownObject
6. space and source are attached to the same library, or space's
   library keeps a copy of locator (section 3.8).                  else OtherLibrary
```

The peer then records the hold, named by `space` and `locator`, with
`source`, `access` and its reading, and answers `Accepted`. A hold it
already holds is accepted again and changes nothing.

- Step 4 lets the first hold of an object come only from a reader of the
  source, and every later one from whoever proves an access key a hold
  carries: a reference of a reference names the same source and key.
- The proof shows the object key without revealing it. The fetch right for
  the source shows nothing of the key, so step 3 holds for every hold.

### 3.8 Keeping a held object

- A hold is **live** while the holding space stores a unit that lists its
  locator in `objects`, at this peer, other than one kept only as a parent
  of a space event ([units.md](units.md), "Parents of space events"), or,
  until one does, for
  `orphan_grace` from its registration ([peers.md](peers.md), "Objects").
  With [ext-file-versions.md](ext-file-versions.md), a hold whose every
  such listing is superseded ends when that document's retention, over
  the holding space's listings alone, would collect the object: a
  reference to an old version goes with the version.
  A unit stays stored until it is collected, reclaimed or erased, so a
  released stream's hold stays live until its release is reclaimed, and a
  restore before then keeps it.
- The peer keeps an object while a stored unit of its own space references
  it ([peers.md](peers.md), "Objects") or a live hold names it. Collection,
  a reclaimed release and `orphan_grace` remove a held object only once no
  live hold names it; the peer then collects it at its next pass.
- An erasure of its source space removes it whatever holds it
  ([peers.md](peers.md), "Erasure"), and so does the operator's deletion
  of the source (section 3.5).
- A hold ends when it is no longer live, or when its holding space is
  erased or deleted at this peer. The peer drops it.
- Usage counts a held object once, in its source space's usage, for as long
  as the peer keeps it, and never in a holding space's. A library's
  `used_bytes` therefore counts each file once however many of its spaces
  reference it. A held object no unit of its source lists counts in the
  source's `held_bytes` too.
- **Holds across a move.** A move of either space keeps its holds, and
  keeps each within one library. For each live hold whose holding space and
  source the move would bill to different libraries, the peer copies the
  object into the holding space's library, and the hold then points at the
  copy. Where that library already keeps the object under its locator,
  because one of its spaces stores it or it keeps a copy, the hold points
  at that instead, and nothing is copied.
- A **copy** is the object's stored bytes, kept once per library and
  locator. It counts once in its library's `used_bytes` and `held_bytes`,
  and in no space's usage. The peer keeps it while a live hold points at
  it, and then collects it at its next pass. An erasure of its source
  space removes the copy as it removes the object; the
  operator's deletion of the source does not, since the copy's library pays
  for it.
- Members see no difference: a reference still names its source space, and
  a hold that points at a copy is served from it (section 3.9). A detached
  source still serves its held objects.

### 3.9 Fetching a held object

A connection that holds the fetch right for a space is served the chunks of
every object a live hold of that space names, under that space's scope, as
if the space stored it: by `ObjectWant` ([units.md](units.md), "Sync") and
by the server binding's chunk route with the space's transfer token
([transport.md](transport.md), section 3.15). `ObjectHave` reports a held
object as the space's own. The bytes are the source's, whether served from
the object or from a copy: each chunk's associated data names the source
space.

- A held object whose holding units are all in released streams answers
  `released`, as one of the space's own objects does.
- The fetch right for the holding space never grants anything of the
  source but its held objects.
- A reader opens a held object with the object key its reference entry
  carries ([units.md](units.md), "Reading an object").

### 3.10 The home peer

- The issuer returns the library's home peer, as the URL of its origin,
  beside each ticket it hands the application (section 3.1). It travels at
  the application layer: the ticket's format does not change, and the peer
  never reads it. The application attaches the space there.
- A client puts the home peer first among the peer hints of each welcome it
  signs for a space of the library ([admission.md](admission.md), "The
  welcome"), so each member that joins learns it.
- An operator moves a library to another peer by handing all its spaces
  over together ([peers.md](peers.md), "Hosting a space"), with their
  attachments, holds, copies and the library's ledger, so that its holds
  stay within one peer. The issuer then names the new home peer.
- A client that a peer answers `moved` reports it to its application.
  The device tries the space's peer hints first, the home peer among them.
  Only if none hosts the space, and only for a library the person's own
  account holds, does the application ask the issuer for that library's
  home peer, by the library it attached the space to, never by space ID;
  the client then syncs there. A member whose hints all fail and whose
  account holds no such library depends on its application's own means
  to learn the new home.

## 4. Security considerations

- **A ticket is a bearer token.** Whoever holds an unused ticket can attach
  one space of its own to the ticket's library within its life. A ticket
  attaches one space, once, and lives at most a day, and whoever pays for
  the library sees the space in its ledger and detaches it. Binding a ticket to a
  space ID would make the issuer learn the ID before the space reaches the
  peer.
- **Only a writer moves a space.** A stranger who knows a space ID cannot
  move the space into a library it controls and then starve it. A writer
  can: it moves the space to its own library and later lowers the quota or
  suspends it. That is a writer's denial of service, like filling a quota
  with junk. A move needs headroom for the space's usage and the copies it
  makes into the target, whoever pays for the source library sees the
  space leave, and any writer can move it back.
- **Issuance and use correlate.** The issuer sees when an account asks for
  a ticket, and the peer when a ticket is used. An operator that runs both
  links an account to the attaching connection's time, and so to the
  space. Billing needs that link; holding tickets ahead of need blurs the
  timing. Administration connections carry no ticket and no account
  credential, so an administrator pseudonym is not linked this way.
- **Classical signatures.** A quantum adversary that forges a ticket bills
  a space to a library it does not pay for, which whoever pays for it sees
  and undoes. It
  gains nothing in any space.
- **A library is never a permission.** A suspended or detached library
  stops stores at one peer. Members keep their replicas, and another peer
  may host the space.
- **A peer's clock.** A wrong wall clock at the peer refuses good tickets,
  or accepts one for at most `ticket_lifetime` and `ticket_skew` beyond its
  life. It decides nothing a replica reads.
- **A hold needs the key.** A hold verifies under the object's access key,
  which only a party holding the object key derives, and the first hold of
  an object also needs the source's fetch right. A party that knows only a
  locator, as a former member may, can neither hold nor fetch the object,
  and a guessed access key verifies nothing.
- **What the peer learns.** It learns the access key, which reveals neither
  the object key nor the plaintext, and that two spaces of one library
  share an object. It already bills both spaces to that library, and a
  device that presents both on one connection links them anyway.
- **No convergent encryption.** An object key derives from its state's key
  and the object ID, never from the content alone, so equal files in two
  spaces have unrelated keys and locators, and a peer cannot confirm that
  someone holds a known file.
- **A held object outlives its source's entry.** Deleting a file in the
  source keeps it for every space that holds it, which is the intent.
  Erasing it, or the source, still removes it. A reader of the source who
  writes another space can hold the source's objects there and keep them
  alive; the bytes stay in the library's quota and its ledger shows them.
- **A false access key.** A reader of the source can register a hold under
  an access key that no object key gives. That hold vouches only for
  itself: honest holds carry the true key, and only a later referencer who
  does not read the source, and finds no honest hold, is refused.
- **A copy changes nothing a member sees.** It holds the source's sealed
  bytes, which only the object key opens, and the peer makes it from bytes
  it already keeps. It moves the object's cost to the library whose holds
  use it, so a writer cannot leave one library paying for another's
  files by moving a space.
- **Asking for a home peer.** A device asks the issuer only of a library
  its own account holds, and only once the space's peer hints fail. The
  issuer then learns that the account still uses that library after its
  move, and when, which it already sees from the account's tickets and
  ledger. A member of another account's library never asks, so the issuer
  never links an account to membership in a library it does not hold. What
  remains: the issuer learns when a holder's devices find their peer moved,
  and so roughly when they were last online.
- **The home peer is a hint.** The issuer's home peer and a welcome's peer
  hints say only where to dial. A peer is trusted for availability only
  ([transport.md](transport.md), section 3.10), so a false home peer costs
  a member its sync there, never a verdict.
- **Readers of a reference.** A reader of the holding space reads the
  referenced file for as long as the hold lasts, including one removed
  from the source, because the reference hands it the key. A reference
  gives nothing else of the source but its ID and the state reference the
  object's header shows.

## 5. Test vectors

[ext-libraries.json](vectors/ext-libraries.json):

- `parameters`: the limits, `ticket_lifetime`, `ticket_skew`,
  `detached_grace`, the default T, the reference instant, and an issuer's
  seed and key.
- `tickets`: a signed ticket for each purpose, byte for byte, with the
  signed message and the signature.
- `library_attach`: a `LibraryAttach` message for each purpose, as it
  travels.
- `ticket_checks`: a good ticket, and refusals with their classes: not a
  ticket, an untrusted issuer, a changed signature, past `not_after`,
  `not_after` beyond the lifetime and skew, a used ID, another purpose, a
  suspended library, a peer whose wall clock is not known, a library ID
  holding a control character, and, at a peer that does not implement
  [ext-deposit-tokens.md](ext-deposit-tokens.md), a deposit grant and key 7
  on purpose 1. Each gives the peer's setup: its wall clock,
  the ticket IDs it has used, its trusted issuers, and the state of each
  library it knows.
- `attachments`: create, import and move at a peer, with what the peer
  records, and refused for a space that exists, a move without the store
  right, and a move without headroom.
- `import`: a log imported genesis first, its entries added retired, and
  the importer's present that makes the current entry live.
- `ledgers`: two libraries' ledgers after creates, an import, a move, a
  release and a snapshot, as the issuer reads them.
- `access_keys`: an object sealed under a state, with its object key,
  access seed and access key.
- `hold_object`: a `HoldObject` as it travels, with `held` and its proof.
- `holds`: a peer's checks of `HoldObject` in order, each with the peer's
  setup: a hold under the source's fetch right; a second space's hold under
  the access key a hold carries; and refusals without the store right
  (`NotAuthorized`), with a changed proof and with an access key nothing
  vouches for (`HoldRefused`), of an object the source does not hold
  (`UnknownObject`), and of a source billed to another library
  (`OtherLibrary`).
- `held_objects`: an object whose source's units are collected, kept while
  a hold is live and collected once the holding space's last unit that
  lists it goes; an object a hold keeps that an erasure of its source
  space removes; and the
  library's ledger, which counts the object once.
