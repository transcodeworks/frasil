# Deposit tokens
Protocol 1. Vectors: [ext-deposit-tokens.json](vectors/ext-deposit-tokens.json).

This document specifies **deposit tokens**: anonymous, single-use tokens
that pay for deposits in device mailboxes at an always-on peer. A device
draws a batch of tokens from the peer by showing a **deposit grant**,
which a library's issuer signs, or the store right in a space the peer
hosts, and the peer counts the batch against that library's, or that
space's library's, **allowance**. The device later spends each token on
one deposit, on a connection that presents nothing else, and the peer
cannot link the deposit to the grant, the library or the batch. It extends
[transport.md](transport.md), whose mailboxes it fills in and which
reserves message types 40 to 43, `MailboxPut` key 7 and service 6 for it,
and [ext-libraries.md](ext-libraries.md), whose ticket carries the grant as
purpose 4 and whose libraries carry the allowance. It depends on
[overview.md](overview.md) for conventions, error classes and time, and on
[crypto.md](crypto.md) for the VOPRF of RFC 9497 and the labels
`frasil/deposit-key/v1` and `frasil/deposit-token/v1`. A peer implements
it only together with [ext-libraries.md](ext-libraries.md).

A core implementation that does not implement it:

| What this document defines | A core implementation |
|---|---|
| Message types 40, `TokenKeysGet`, 41, `TokenKeys`, 42, `TokenRequest`, and 43, `TokenIssue`, and service 6 | a device never sends them; a peer never lists the service, and closes a connection that sends any of them, as for an unknown type (`UnknownMessage`) |
| `MailboxPut` key 7, and `Authorization: Frasil-Token` on the deposit route | a device never sends them; a peer refuses key 7 as an unknown key (`Malformed`), and takes a `POST` deposit as it takes any other, without a token |
| Ticket purpose 4 and ticket key 7 | a peer that implements [ext-libraries.md](ext-libraries.md) alone refuses them in `check_ticket`, step 1 (`Malformed`) |
| The token budget, and the allowance | a peer keeps one budget for every deposit, as [transport.md](transport.md), "Mailboxes", says |
| `token_refused`, `token_expired`, `token_spent` and `allowance_exhausted` | a peer never sends them |
| `deposit_keys` in discovery | a peer never lists it; a client ignores it |

A peer whose operator turns this extension off behaves as a core peer:
every deposit is anonymous, under transport.md's caps and rates. Nothing in
a log, roster or event refers to a token, so no replica's verdict depends
on this extension.

## 1. Overview

- A device-mailbox deposit carries no credential, so that a peer never
  learns who writes to which device ([transport.md](transport.md), section
  3.12). A peer therefore cannot tell honest mail from a stranger's. This
  extension adds a second way to deposit, paid for with a **token**, that
  keeps the depositor anonymous and that a stranger cannot fill.
- **Issuance is counted.** A device asks the peer for a batch of tokens on a
  connection that shows either a **deposit grant**, a library ticket of
  purpose 4 that the library's issuer signs, naming the library and how
  many tokens it grants, or the store right in a space the peer hosts. The
  peer counts the batch against the library's **allowance**, a number of
  tokens per day of its own, apart from the library's storage quota; a
  space's writers draw at most the space's **share** of it. A grant names a
  library and never an account, a person, a device or a space
  ([ext-libraries.md](ext-libraries.md), section 1).
- **Issuance is blind.** The device sends each token's input blinded, and
  the peer evaluates it under its **deposit key** without seeing it, with a
  proof that it used the key it publishes. Only the device learns the
  finished token.
- **Spending is anonymous.** A deposit carries one token on a connection
  that presents nothing else. The peer checks the token under its key and
  that it is unspent, and learns nothing that links it to the grant, the
  library or the batch it came from.
- **A token buys one deposit** of at most 262,144 bytes, at the peer that
  issued it, while its key lives. It is bound to the peer's key and so to
  one key period, and to nothing else: not to the recipient, the size or
  the depositor.
- **Paid mail has room of its own.** The peer keeps token deposits in a
  **token budget** apart from the anonymous one. An anonymous deposit never
  evicts an item a token paid for, and a token deposit is never refused for
  the anonymous budget. So a stranger delays only anonymous mail, and the
  most one library's holders place in mailboxes is its allowance times
  262,144 bytes a day.
- **Keys rotate by period.** The peer issues under one key per
  `token_period` and accepts tokens of it for one period more, then
  forgets the key and every token spent under it. So the memory of spent
  tokens is bounded.
- **Nothing else changes.** A device with no token deposits as a core
  device does. A deposit over a member connection carries no token.
- **Only mail through Frasil.** The allowance covers device mail through a
  peer's mailboxes. An application usually has other ways to reach the
  people it invites, such as an email with a link, and MAY carry a welcome
  by such a route ([admission.md](admission.md), "Welcomes"); that needs no
  token and counts against no allowance.

## 2. Formats

### 2.1 The VOPRF

Tokens use RFC 9497's VOPRF, mode `modeVOPRF` (0x01), with the suite
ristretto255-SHA512 (RFC 9497, section 4.1): elements and scalars of 32
bytes (`Ne` = `Ns` = 32), outputs of 64 (`Nh` = 64), and the context string
`"OPRFV1-" || u8(0x01) || "-ristretto255-SHA512"`. This document uses its
functions as the RFC names them: `DeriveKeyPair`, `Blind`, `BlindEvaluate`,
`GenerateProof`, `VerifyProof`, `Finalize`, `Evaluate`,
`SerializeElement` and `DeserializeElement`. `G` is the group's generator.

- A **batch** is evaluated as `BlindEvaluate` evaluates one element, each
  element under the same key, with one proof over the whole batch:
  `GenerateProof(skS, G, pkS, blinded, evaluated)` over the lists, as RFC
  9497, section 2.2.1, defines it and as its batched test vectors show. A
  verifier checks that one proof with `VerifyProof` over the same lists,
  then finishes each element as `Finalize` does after its proof check.
- `DeserializeElement` refuses an encoding that is not canonical and the
  identity element; where it refuses, the class is `Malformed` for a
  blinded or evaluated element and `InvalidKey` for a public key.
- Every random draw has a form that takes its bytes, so that vectors drive
  it: the device's nonce and blind, the peer's key seed and the proof's
  scalar.

### 2.2 Deposit keys

```text
seed         = 32 random bytes, drawn by the peer for each key
(skS, pkS)   = DeriveKeyPair(seed, "frasil/deposit-key/v1")
public key   = SerializeElement(pkS)                                     32 bytes
key ID       = SHA-256("frasil/deposit-key/v1" || public key)            32 bytes
```

A peer has at most two **live** keys: the **issuing** key, under which it
evaluates every batch, and the key before it, which it no longer issues
under but whose tokens it still accepts (section 3.9). A peer that runs on
several machines is one peer, with one set of keys.

### 2.3 The deposit grant

A **deposit grant** is a library ticket ([ext-libraries.md](ext-libraries.md),
section 2.2) of purpose 4, with one key more:

```text
ticket = deterministic CBOR map {
           1: version, 1,
           2: library, text: a library ID,
           3: id, bytes(16): random, drawn by the issuer,
           4: purpose, 4,
           5: not_after, unsigned: a wall-clock instant,
           6: issuer, bytes(32): the issuer's Ed25519 public key,
           7: tokens, unsigned: 1 to 256 }
```

It is signed, carried and checked as every ticket is, under the label
`frasil/library-ticket/v1`, and lives at most `ticket_lifetime`. Key 7 is
present exactly for purpose 4. A grant draws one batch, once: its ID is
then used at this peer, as an attaching ticket's is.

### 2.4 Tokens

```text
nonce         = 32 random bytes, drawn by the device for each token
input         = "frasil/deposit-token/v1" || key ID || nonce             87 bytes
authenticator = Finalize's output for this element (section 2.1)          64 bytes
token         = u8(0x01) || key ID (32) || nonce (32) || authenticator (64)
                                                                         129 bytes
```

The peer checks a token by computing `Evaluate(skS, input)` and comparing
it with the authenticator in constant time. Two tokens share nothing but
their key ID.

### 2.5 Messages

```text
TokenKeysGet = {0: 40, 1: request}
TokenKeys    = {0: 41, 1: request, 2: keys}
keys         = array of 1 or 2 arrays [key ID (32), public key (32), role]
               role: 1 issuing, 2 accepting only; exactly one issuing
TokenRequest = {0: 42, 1: request, 2: grant (bytes, at most 512) or 5: space (32),
                3: key ID (32), 4: blinded (array of 1 to 256 elements of 32 bytes)}
TokenIssue   = {0: 43, 1: request, 2: evaluated (array of 1 to 256 elements
                of 32 bytes), 3: proof (64)}
MailboxPut, kind 3, with a token
             = {0: 24, 1: request, 2: address (32), 3: item, 6: 3, 7: token (129)}
```

- Each travels on the control stream of a space-traffic connection, never
  an administration connection ([transport.md](transport.md), section
  3.10), and only to or from a peer whose `PeerHello` lists service 6,
  `deposit`. Each has exactly these keys; cap 16,384 bytes, and
  `MailboxPut`'s own.
- A `TokenRequest` carries exactly one of key 2, a **grant draw**, and
  key 5, a **space draw** (section 3.3).
- `request` numbers a device's requests on the connection. A peer answers
  `TokenKeysGet` with `TokenKeys`, `TokenRequest` with `TokenIssue` or
  `Refused`, and a `MailboxPut` with a token with `Accepted` or `Refused`,
  each naming the request.
- `proof` is RFC 9497's serialized proof, two scalars.
- **The server binding.** Discovery ([transport.md](transport.md), section
  3.15) lists `"deposit"` among its services and the live keys as
  `"deposit_keys": [{"id": "<64 hex>", "key": "<64 hex>", "issuing": true},
  ...]`, one or two entries with exactly one issuing. A deposit by
  `POST /frasil/p1/mailbox/3/{address}` carries its token as
  `Authorization: Frasil-Token <258 lowercase hex>`. A browser sends it
  cross-origin under the binding's existing preflight answer, which
  already allows `Authorization` ([transport.md](transport.md), section
  3.15, "Cross-origin requests"); the peer allows nothing more for it, and
  never `Access-Control-Allow-Credentials`. Issuance runs only
  over the WebSocket. The `POST` route is a paid deposit with no
  connection to open: one request that carries nothing but the item and
  its token, as section 3.6 asks of a deposit's connection; discovery's
  keys are the peer's live keys with no connection at all. A device MAY
  deposit by either route and learn keys from either source (sections 3.2
  and 3.6); neither is required of it.

### 2.6 Settings

| Setting | Scope | Default | Range | Set by |
|---|---|---|---|---|
| `deposit_allowance` | a library | the operator's default; 64 if it sets none | 0 to 65,536 tokens per window | the operator, or the issuer for its libraries; the last write stands, as for `quota` |
| `space_share` | a library, for each of its spaces | 16 | 0 to `deposit_allowance` tokens per window | the same |
| `token_period` | the peer | 7 days | 1 to 30 days | the operator |
| token budget | the peer | the operator's | items and bytes, apart from the anonymous budget | the operator |

An **allowance window** lasts `allowance_window`, 24 hours, from the first
batch the library draws when no window of it is open (section 3.4). A
library's allowance counts every token drawn against it in its current
window, by grant draws and space draws alike. A space's **share** counts
the tokens its writers drew by space draws in that same window; grant
draws count against no share. With a share of 0, a library's spaces draw
nothing without a grant.

### 2.7 What a peer keeps

- Per live key: its seed, its key ID, its role, and the reading at which it
  began to issue, on the timeline of the keys' shard.
- Per library: its current window's start, on the library's timeline, and
  the tokens drawn in it. The library's ledger
  ([ext-libraries.md](ext-libraries.md), section 2.5) shows them as
  `tokens_drawn` and `deposit_allowance`.
- Per space that drew in the library's current window: the tokens its
  writers drew. The ledger does not show these: its per-space rows gain
  nothing, so the issuer does not learn which spaces' writers send mail.
- Per grant ID used: what [ext-libraries.md](ext-libraries.md), section
  2.5, keeps for a ticket ID.
- Per **spent token**, named by its key ID and nonce, until its key
  retires: `SHA-256(address || item)` of the deposit it paid for, and the
  item ID the peer assigned.
- Nothing that links a spent token to a grant, a library, a space, a batch
  or the connection that drew it. A peer MUST NOT log blinded or evaluated
  elements beside a grant or a space, nor a token's nonce beside the
  connection that drew it.

### 2.8 Error classes

Besides [overview.md](overview.md)'s classes, this document uses
[ext-libraries.md](ext-libraries.md)'s ticket classes, `Malformed`,
`TicketRefused`, `TicketExpired`, `TicketUsed` and `LibraryClosed`, as its
`check_ticket` raises them, and `NoLibrary`; [transport.md](transport.md)'s
`Busy`, `BadProof`, `PurposeViolation` and `CredentialRefused`; and these. Each is of sort decision but
`KeyInconsistent`, a report:

| Class | Code | Status | Meaning |
|---|---|---|---|
| `TokenRefused` | `token_refused` | 403 | a token whose authenticator does not verify |
| `TokenExpired` | `token_expired` | 403 | a token under a key that is not live at this peer, or a request under a key that is not its issuing key |
| `TokenSpent` | `token_spent` | 409 | a token another deposit already spent |
| `AllowanceExhausted` | `allowance_exhausted` | 429 | the library has drawn its whole allowance in its current window, or, for a space draw, the space its whole share |
| `KeyInconsistent` | | | at a device: a peer whose key lists contradict one another (section 3.2) |

On the server binding, a token refused at section 3.7, step 2, is answered
400 `unsupported_version`. `BadProof` and `KeyInconsistent` are a device's
own verdicts and never travel.

## 3. Procedures

### 3.1 Two ways in

A device draws tokens in one of two ways, and the tokens are the same
either way:

- A **grant draw** shows a deposit grant from the library's issuer
  (section 3.1.1). It suits a device whose account holds the library.
- A **space draw** shows the store right in a space the peer hosts, and is
  counted against the library the space is billed to, within the space's
  share (section 3.1.2). It suits any writer of the space, whoever pays for
  it, and needs no ticket. So a sender always has standing at the peer that
  serves the space it admits someone to.

#### 3.1.1 Getting a grant

The application asks the library's issuer for a deposit grant over its own
account traffic, as for any ticket ([ext-libraries.md](ext-libraries.md),
section 3.1), and hands it to the client as opaque bytes. The issuer sets
`tokens` by its own policy for the account, and `not_after` at most
`ticket_lifetime` after it signs. The client never reads, stores at rest
or shows a grant. A grant is good only at a peer that trusts its issuer,
and its tokens only at the peer that issues them: a device draws tokens at
the peer where it deposits, which for a welcome is a peer that serves the
space ([admission.md](admission.md), "Welcomes").

On a peer whose operator runs no account service, the built-in issuer of
the operator's default library signs grants in the same format.

#### 3.1.2 Drawing as a writer of a space

A device that holds the upload key of a live entry of a space the peer
hosts presents it ([transport.md](transport.md), section 3.11) and sends
`TokenRequest` with key 5, the space's ID, on that connection. It SHOULD
use a connection of its own that presents that upload key and nothing
else, and stores nothing on it: each further space it presents there tells
the peer that one device writes both, and each event it stores there names
its author's device ID in its envelope ([events.md](events.md)). The peer
counts the batch against the library the space is billed to
([ext-libraries.md](ext-libraries.md)), in the library's allowance window
and within the space's share.

- The store right is the credential, as for storing: a read credential or
  catch-up grants no draw. Writers of one state share one upload key, and
  a draw carries no Ed25519 key, `kc` or device ID, so the peer learns that
  a writer of the space drew, never which.
- The share bounds what one space's writers take from their library: a
  writer of one space cannot drain the allowance of every other space in
  it. A writer of several spaces of one library draws each one's share.
- A removed writer keeps the store right until its entry is retired
  ([peers.md](peers.md), "Lingering credentials" in its security
  considerations), and can draw its space's share in each window until
  then. The tokens it drew stay good until their key retires, at most two
  `token_period`s: being unlinkable, they cannot be revoked. Its damage is
  that share, taken from the honest writers of its space, whose mail goes
  without tokens meanwhile, and the deposits those tokens pay for.

### 3.2 Learning a peer's keys

A device learns a peer's live keys from discovery, or by `TokenKeysGet` on
a connection that presents nothing else (section 3.6); it MAY use either.
It never takes them from a connection that presents a grant or a
credential. A discovery document is an HTTP resource that a cache in front
of the peer may serve after the peer rotated its keys, and a list that
names an issuing key the device saw replaced is `KeyInconsistent`; a device
that reads discovery reads it past any cache. It checks each list, in
order:

```text
1. One or two entries, each a key ID of 32 bytes, a public key of 32
   and a role of 1 or 2; exactly one of role 1; no key ID twice. else Malformed
2. Each public key passes DeserializeElement.                    else InvalidKey
3. Each key ID is the hash of its public key (section 2.2).      else Malformed
```

A device keeps, per peer, the issuing keys it has seen, in the order it
saw them, each with its first sight on the device's timeline. A key list
whose issuing key is one the device saw replaced, or that would make three
issuing keys of one peer whose first sights lie less than 24 hours apart,
is `KeyInconsistent`: a peer changes its issuing key at
most once per `token_period`, which is at least a day. The device then
stops drawing and spending that peer's tokens, drops those it holds, and
reports the peer to its application. It keeps what it saw at rest
([at-rest.md](at-rest.md), the `deposit_keys` table), and deposits there
without tokens.

The stop holds until the application clears it, and never ends by
itself: a peer that splits its holders by key would only have to wait
out a period. An application clears it when a person, told of the
report, decides the peer is trusted again, as when its operator restored
its keys from a backup. The device then forgets the peer's key history,
as if it had never drawn there, and learns its keys anew.

### 3.3 Requesting tokens

1. The device takes the issuing key from its latest key list for the peer
   (section 3.2).
2. For each token it draws a nonce, builds `input` under that key ID, and
   computes `(blind, blinded) = Blind(input)`. It keeps the blinds and
   inputs in memory only, until the answer.
3. It sends `TokenRequest` with the key ID and the blinded elements, and
   either the grant, with at most the grant's `tokens` elements, or the
   space, on a space-traffic connection. For a grant draw it SHOULD use a
   connection of its own that presents nothing else, so that the peer
   cannot link the batch's time to the device's spaces; for a space draw,
   one that presents that space's upload key alone and stores nothing
   (section 3.1.2).

### 3.4 Issuing

The peer checks a `TokenRequest`, in order:

```text
 1. Keys 0, 1, 3 and 4, and exactly one of 2 and 5, and no other;
    request unsigned; grant a byte string of at most 512 bytes, or
    space of 32 bytes; key ID of 32 bytes; blinded an array of 1
    to 256 byte strings of 32 bytes.                             else Malformed
 2. Each blinded element passes DeserializeElement.              else Malformed
a grant draw:
 3. ext-libraries.md's check_ticket(grant, 4).                   else its class
 4. len(blinded) <= the grant's tokens.                          else TicketRefused
a space draw:
 5. The connection holds the store right for space
    (transport.md, section 3.11).                                else CredentialRefused
 6. The space is attached to a library at this peer.             else NoLibrary
 7. The library's state is open.                                 else LibraryClosed
either:
 8. key ID names the peer's issuing key.                         else TokenExpired
 9. The library has drawn fewer than deposit_allowance tokens in
    its current window.                                          else AllowanceExhausted
10. For a space draw: the space has drawn fewer than space_share
    tokens in that window.                                       else AllowanceExhausted
```

The library is the grant's for a grant draw, and the space's for a space
draw. The peer then, in one step:

- opens a window if the library has none open, or if `allowance_window`
  has passed since its current one opened, on the lower estimate of the
  library's timeline ([overview.md](overview.md), section 6.4), and so
  begins every space's share of it afresh;
- takes `m`, the number of blinded elements, or what is left of the
  allowance, and for a space draw of the share, if that is less, and
  evaluates the first `m` elements with one proof (section 2.1);
- for a grant draw, marks the grant's ID used; counts `m` tokens drawn in
  the library's window, and for a space draw in the space's share;
- answers `TokenIssue` with the `m` evaluated elements, in order, and the
  proof.

A grant refused at any step stays unused. A grant that draws fewer tokens
than it names is used all the same. Steps 9 and 10 read the window as the
first point above would open it.

A peer that cannot read its keys now, or knows they are due to rotate and
cannot rotate them, answers `busy`, before step 1 or at step 8, and never
`token_expired` for that reason: a device that is answered `busy` draws
again later. A peer with no known wall clock refuses every grant at step
3, as `check_ticket`'s `check_expiry` does (`TicketExpired`), and still
issues to space draws, under a key it began in its current run (section
3.9).

### 3.5 Finishing issuance

The device checks `TokenIssue`, in order:

```text
1. Exactly keys 0 to 3; request names its TokenRequest;
   evaluated an array of m byte strings of 32 bytes, 1 <= m <= n,
   n the number it sent; proof of 64 bytes.                      else Malformed
2. Each evaluated element passes DeserializeElement.             else Malformed
3. VerifyProof(G, pkS, the first m blinded elements, evaluated,
   proof) holds, pkS being the issuing key of section 3.3,
   step 1; a proof whose scalars do not pass DeserializeScalar
   does not hold.                                                else BadProof
```

It then finishes each token with `Finalize` and keeps it with its key ID.
A device that receives `BadProof` drops the batch, as it would a peer's
false key list, and reports the peer. It keeps its unspent tokens sealed at
rest, as it keeps its other secrets ([at-rest.md](at-rest.md), the `token`
table); a token lost is a deposit lost. A token it sends with a deposit
moves, in one commit, to the record of that deposit, and leaves the store
only once the peer has answered it, so that a deposit whose answer was
lost, by a closed connection or a restart, is repeated with the same token
(section 3.6).

### 3.6 Depositing with a token

A device that holds a token of a live key of the peer pays with it for a
deposit in a device mailbox there:

- On the WebSocket or the iroh binding, it opens a fresh connection for
  the deposit, as it opens an administration connection
  ([transport.md](transport.md), section 3.10): a new transport session,
  no TLS session resumption, no cookie, and on the iroh binding a fresh
  endpoint key; with purpose 1, and no `Present`, bearer token, grant or
  collection on it. Nothing on it then carries the depositor's Ed25519
  key, `kc` or device ID ([transport.md](transport.md), section 3.12): a
  collection would show all three. The only device a deposit names is its
  recipient, by the mailbox address its device ID gives
  ([transport.md](transport.md), section 2.7). It MAY send `TokenKeysGet`
  on it first, and MAY deposit several items on it, each with its own
  token.
- On the server binding's `POST` route, it sends one request per item,
  with the token's header and no other `Authorization`, cookie or
  credential.
- It spends tokens of the older live key first, and never one token twice,
  except to repeat a deposit whose answer it did not receive: it sends the
  same item to the same address with the same token.
- A device that holds tokens for a peer SHOULD pay with one for every
  device-mailbox deposit it makes there, so that paid deposits are not a
  smaller set than they need be.

### 3.7 Redeeming

The peer checks a `MailboxPut` of kind 3 that carries key 7, or a `POST`
of kind 3 that carries a token, in order:

```text
1. Exactly keys 0, 1, 2, 3, 6 and 7; address of 32 bytes; token
   of 129 bytes. On the server binding: the header reads as one
   token of 129 bytes in lowercase hex.                          else Malformed
2. Byte 0 of the token is 0x01.                                  else UnsupportedVersion
3. The item is at most 262,144 bytes.                            else TooLarge
4. The token's key ID names a live key of this peer.             else TokenExpired
5. The authenticator equals Evaluate(skS, input), compared in
   constant time.                                                else TokenRefused
6. The token is not spent, or it was spent by a deposit of this
   address with these item bytes.                                else TokenSpent
7. The token budget has room for the item (section 3.8).         else Busy
```

At step 6, a token spent by this very deposit is answered as its first
deposit was: `Accepted`, or 201 with the same item ID, and nothing more is
kept. Otherwise the peer keeps the item and records the token spent in one
step: a token is spent exactly when the deposit it pays for is kept, and a
refusal leaves it unspent. A token deposit counts toward no per-source
rate of anonymous deposits ([peers.md](peers.md), "Quotas and rates"). A
peer MAY limit refused tokens per source.

A peer that cannot read its keys now answers `busy` before step 4, never
`token_expired`, since a device drops a token answered so (section 3.11).

### 3.8 The token budget

A peer that implements this extension keeps two budgets over its device
mailboxes, each a number of items and of bytes: the **anonymous budget**,
which [transport.md](transport.md), "Mailboxes", caps, and the **token
budget**. A token deposit counts only in the token budget, and every other
deposit only in the anonymous one.

- **Within one mailbox,** both kinds of item share transport.md's cap of 64
  items and 4 MiB. A token deposit past it evicts the mailbox's oldest
  anonymous items first, then its oldest token items. An anonymous deposit
  past it evicts the mailbox's oldest anonymous items only; one that would
  have to evict a token item is refused `busy`.
- **Across the peer,** a token deposit that would pass the token budget
  first evicts, oldest first, token items in mailboxes that are not
  claimed ([transport.md](transport.md), "Mailboxes"), unless its own
  mailbox is not claimed; if room is still lacking, it is refused `busy`.
  The anonymous budget never takes room from the token budget, nor the
  reverse. A deposit refused `busy` evicts nothing.
- Items of both kinds are kept, expire and are collected alike, and a
  collector cannot tell them apart: `MailboxItems` carries no token.

### 3.9 Spent tokens and key rotation

- A key **issues** while the upper estimate of the time since the reading
  at which it began, on the keys' shard's timeline
  ([overview.md](overview.md), section 6.4), is less than `token_period`,
  and is **accepting only** while it is less than twice that. It then
  **retires**: the peer deletes its seed and every spent-token record
  under its key ID. Both ends are on the upper estimate, since both stop
  an act. A peer whose estimate is unbounded, after a restart with no
  known wall clock, retires both keys and begins a new one.
- When a key stops issuing, the peer begins the next at once, at that
  reading, so that one key always issues, and retires the key before it if
  that one has not yet retired, so that at most two keys live. A token
  therefore lives at least one `token_period` after it is drawn, and at
  most two.
- The spent-token records of a key are at most the tokens drawn under it,
  so the memory of spent tokens is bounded by the allowances the peer
  grants in two periods. A token of a retired key is refused
  `token_expired` and never needs a record.
- A device drops its tokens of a key that its latest key list for the peer
  does not show: that key has retired. It reads this from the key list
  alone, never from its own clock.

### 3.10 In a cluster

A peer that runs on several machines keeps one spent-token record per
token, whichever machine takes the deposit, and MUST accept each token at
most once across them all.

- The keys are one shard of the peer's state, belonging to no library and
  no space ([overview.md](overview.md), section 6.7); every machine reads
  them, and the shard that keeps them rotates them on its timeline. A
  machine that takes that shard up reads its timeline as section 6.7
  says, and where that leaves the upper estimate unbounded, both keys
  retire (section 3.9). A machine that reads the keys from that shard
  reads them again before it refuses a token or a request
  `token_expired`, so that a key begun since its last reading is not
  refused.
- A library's allowance window and count, and its spaces' shares of it,
  are kept with the library, on its timeline.
- Spent-token records are kept in shards by a hash of the nonce, like the
  mailboxes by their address, so that one shard decides each token.
- Where the token's record and the mailbox are in different shards, the
  peer records the spend first, with the deposit's hash, then keeps the
  item, and releases the spend if the item is not kept. A deposit that is
  repeated while that is undecided waits for it, or is answered `busy`.
- Each budget is split among the mailbox shards, as transport.md splits
  the anonymous one.
- A library handed over to another peer ([peers.md](peers.md), 3.1
  Hosting a space, "Hand-over") takes neither its window nor its grants
  used: its tokens are good only at the peer that issued them, and the
  peer it goes to opens a window at its first draw there.

### 3.11 A device without tokens

A device with no token of a peer's live key, at a peer that does not list
service 6, or that can draw none there, by grant or as a writer of a space
the peer hosts, deposits without a token, as a core device does: in the
anonymous budget, under the peer's caps and rates. Answered `busy` or
`rate_limited`, it keeps the item and deposits it again later ([transport.md](transport.md),
"Mailboxes"), with a token if it holds one by then. Answered `allowance_exhausted` at issuance, it draws no
tokens until the window has passed, and deposits without them meanwhile:
since it does not know when the window opened, it waits
`allowance_window` from the answer, on the lower estimate of its timeline.
Answered `token_refused` or `token_expired` on a deposit, it drops that
token, and deposits the item again with another or without one.

### 3.12 When to draw, and how many

The peer sees when a library draws tokens and how many, and for a space
draw which space's writer drew. A device keeps that from pointing at a
deposit:

- It draws ahead of need: when it holds fewer than a low mark of the
  peer's issuing key, 4 by default, it draws a batch, 16 by default, at a
  random moment in the next hour of its timeline, never in answer to one
  deposit. A device draws its first batch at a peer ahead of its first
  deposit there: at a random moment in the hour after it first holds a way
  to draw at that peer, a grant from its application or the store right in
  a space the peer hosts, whether or not it has deposited. So a new user's
  first welcome is paid for, and does not go through the anonymous budget
  a stranger can fill. The cost is that a library's allowance is drawn by
  devices that may never deposit, up to a batch each per `token_period`
  before their tokens retire. It is accepted because a first batch is
  small beside the allowance, and drawing only when needed would line up
  issuance with the first deposit, which is the link this section avoids.
- It holds at most what it spends in one `token_period`, and at most 256,
  since a token lives at least one period. Drawing only below the low mark
  keeps it under the low mark plus one batch; an application that sets a
  larger batch keeps it to what the device spends in a period.
- A device that holds a way to draw at a peer, and fewer tokens than the
  low mark there, draws once per such moment: a draw that is refused, or
  that the peer does not answer, is tried again at the next random moment
  of the hour after it, not at once.
- It draws on its own connection (section 3.3), and spends on others
  (section 3.6), never on the same one.
- Batch sizes are the application's choice, within the grant. A batch size
  links nothing at redemption, since every token of a key is alike, but an
  application SHOULD use the same defaults on every device, so that the
  pattern of draws tells the peer no more than the library does.

## 4. Security considerations

- **Unlinkability.** The peer evaluates blinded elements and sees each
  token's nonce for the first time when it is spent; the blind is uniform
  and known only to the device, so a token is unlinkable to the batch it
  came from, under the one-more-gap Diffie-Hellman assumption of RFC 9497.
  What remains to link a deposit to its depositor is outside the token:
  the transport address, the timing (section 3.12), and the key period.
  A device that wants its address hidden from the peer deposits through a
  relay or proxy that hides it; this document does not hide addresses.
- **The anonymity set** of a deposit is every holder of a token of the
  same key at the same peer. On a peer with few libraries, or few devices
  that hold tokens, it is small: a self-hosted peer for one household knows
  the household. The peer always knows the recipient's address, which
  hashes the recipient's device ID ([transport.md](transport.md), section
  2.7): a peer that has seen that device collect, or that holds events it
  wrote, whose envelopes give its device ID ([overview.md](overview.md),
  section 4.1), knows which device the mail is for. Tokens hide who sends,
  never to whom.
- **Key consistency.** A peer that gave each library or device its own
  key could tell whose token a deposit spends. The proof binds every batch
  to a key the device learned on a connection that presented nothing, and
  a peer has one issuing key per period, which a device holds it to
  (section 3.2). A peer can still show different devices different keys,
  which a device alone cannot see; it detects it only by comparing key
  lists fetched another way, such as discovery through another network.
  That partitions token holders into at most as many sets as the peer
  keeps keys apart, and every set it makes is a key it must keep and
  publish to someone.
- **The proof's scalar is a secret.** `GenerateProof` draws a scalar `r`
  and publishes `s = r − c·skS`, where `c` is a hash every device that
  receives the batch computes. Whoever can predict `r`, or sees one `r`
  used for two proofs under one key, solves for `skS` from one proof, as
  from a predictable key seed: it forges tokens of that key until the key
  is no longer live, up to the mailbox caps and the token budget. A peer
  MUST draw `r` fresh from its secure source for every proof
  ([crypto.md](crypto.md), section 2.1); its form that takes the bytes is
  for vectors.
- **The proof is not an option.** Without `VerifyProof`, a peer could
  evaluate one element of a batch under a second key and recognise that
  token when it is spent. A device that skips the proof, or takes the key
  from the issuance connection, loses unlinkability.
- **What a space draw tells the peer:** that a writer of that space, at a
  state whose upload key it holds, drew so many tokens at that moment, from
  that address; and, if the device presents other spaces on the same
  connection, that one device writes them all, or, if it stores events
  there, its device ID. Otherwise never which writer, never a
  recipient, never a deposit: the tokens are the same as a grant's, under
  the same key, and spending stays anonymous. The peer already knows the
  space's library and its writers' activity there (overview.md, section
  4.4, leaks 2 and 3); what is new is when its writers expect to send
  device mail, blurred by drawing ahead of need (section 3.12). The issuer
  learns nothing of it: the ledger shows the library's total only.
- **The space share.** Without it, any writer of any space of a library,
  whoever pays for it, could take the whole allowance in one window and
  leave the library's own holders none. With it, a space's writers take at
  most `space_share` a window, and a library with many spaces sets the
  share low or to 0, leaving its holders the grant draw. A grant draw is
  limited by its grant, and the issuer decides who receives one.
- **Tokens are only as scarce as libraries.** On a peer whose operator
  lets anyone attach a space to a library, by open hosting or by giving
  tickets for the default library to anyone, a stranger attaches a space
  and draws that space's share each window, up to the library's
  allowance. That starves the library's honest holders of tokens, though
  not of anonymous deposits, which they still make. Who receives tickets
  is the operator's choice ([ext-libraries.md](ext-libraries.md), section
  3.1), and so is this exposure: a library whose spaces strangers can
  attach SHOULD have a `space_share` of 0, or a low `deposit_allowance`,
  so that its holders draw by grant instead.
- **A removed writer** draws its space's share in each window until its
  entry is retired, and spends those tokens for up to two `token_period`s
  after (section 3.1.2). It cannot draw more than the share, and gains
  nothing in any space: a token admits nobody and opens nothing.
- **A stranger** without tokens still deposits anonymously, and can still
  fill the anonymous budget, and so delay anonymous mail until retention
  frees room, as without this extension; what it puts in mailboxes nobody
  collects from goes after `uncollected_retention`
  ([transport.md](transport.md), "Mailboxes"). It cannot take room from
  paid mail, evict an item a token paid for, or forge a token. Forged and
  replayed tokens cost the peer one evaluation each.
- **A paying user** holds tokens of its library's allowance, or of its
  space's share. It can place at most the allowance times 262,144 bytes a
  day, and those items stay at most `mailbox_retention`. It can fill one mailbox to its cap of 64 items
  and evict that mailbox's oldest items, honest paid ones included; and it
  can fill the token budget, delaying paid mail until retention frees
  room. The peer cannot tell which library did it, but each library's
  draws are in its ledger: one that draws its whole allowance day after day
  stands out, and its issuer or the operator lowers its allowance. A token
  binds no recipient, so a token cannot be refused for one mailbox alone.
- **Why a token binds no recipient.** A token bound to its recipient would
  have to be drawn when the recipient is known, so issuance would line up
  with the deposit, and a peer that saw the recipient at issuance would
  link the grant's library to it. It would add no limit: one token already
  pays for one deposit. Nor is a token bound to a size class: each class
  would need a key of its own, and every key splits the anonymity set.
- **What the issuer learns:** when an account asks for a grant and how
  many tokens it names, as for any ticket, and, through the ledger, how
  many its library drew. Nothing of any deposit: not its recipient, time,
  size or existence. An issuer that also runs the peer links an account to
  the issuance connection's time and address, and still not to a deposit.
- **What a malicious issuer can do:** grant tokens to anyone for its own
  libraries, which only spends their allowances; or grant none, which
  leaves its holders the anonymous budget. It never sees a token.
- **What a malicious peer can do:** refuse to issue, refuse tokens, drop
  mail, or partition its token holders by key as above. It learns no more
  than without this extension, and less than it would from a deposit
  charged to a space or library.
- **Double spending** is stopped by the spent-token record, which a single
  shard decides (section 3.10). Forgetting a retired key's records is safe
  because its tokens are refused as expired before step 6 is reached.
- **Classical.** The VOPRF rests on the discrete logarithm in ristretto255,
  which a quantum adversary breaks. Such an adversary could forge tokens
  from the public key, and so deposit as if it paid, up to the per-mailbox
  caps and the token budget: spam, as a stranger already can. It reads no
  mailbox, since every item is sealed under X-Wing
  ([crypto.md](crypto.md)), and gains no authority, since a token decides
  nothing a replica reads. Unlinkability does not rest on a hardness
  assumption: a recorded issuance stays unlinkable to a later deposit
  whatever the adversary computes. This matches what Frasil keeps classical
  ([crypto.md](crypto.md), "Which structures carry which scheme"): what is
  verified once, at once, and protects neither confidentiality nor
  authority. A post-quantum construction can replace this one under a new
  token version (byte 0) and service, with no change to any space.
- **A grant is a bearer token,** like every ticket. Whoever holds an unused
  one draws its tokens, once, within a day, against its library's
  allowance.

## 5. Test vectors

[ext-deposit-tokens.json](vectors/ext-deposit-tokens.json):

- `parameters`: the suite and its context string, the labels in hex, the
  limits (`tokens`, the batch, the token's length, the messages' caps),
  `token_period`, `allowance_window`, the defaults of `deposit_allowance`
  and `space_share`, and the reason codes with their statuses.
- `voprf`: RFC 9497's own ristretto255-SHA512 VOPRF vectors, single and
  batched, so that an implementation shows it runs the suite before it
  runs Frasil's use of it.
- `keys`: two seeds, the keys `DeriveKeyPair` gives, their key IDs, a
  `TokenKeys` message and a discovery `deposit_keys` member for them; and
  key lists refused: three entries, two issuing, none issuing, one key
  listed twice, a key ID that is not its key's hash, an identity element
  and an encoding that is not canonical.
- `grants`: a deposit grant byte for byte, with what is signed and the
  signature; and grants refused by `check_ticket` and by issuance: no key
  7, key 7 on purpose 1, 0 and 257 tokens, a used ID, and more blinded
  elements than the grant names.
- `issuance`: one batch of three tokens: nonces, inputs, blinds, blinded
  elements, the `TokenRequest`, the evaluated elements, the proof's random
  scalar, the proof, the `TokenIssue`, and the three tokens; a batch cut to
  the allowance left; and issuance refused: under the accepting-only key,
  an unknown key, an element that is not canonical, the identity, and a
  library past its allowance, each with the peer's setup.
- `space_draws`: a space draw under the store right, counted in the
  library's window and the space's share; a batch cut to the share left;
  a second space of the same library drawing its own share; a grant draw
  beside them that counts against no share; and refused: both keys 2 and
  5, neither, a connection with fetch and catch-up only and with a retired
  upload key (`CredentialRefused`), a space attached to no library
  (`NoLibrary`), a suspended library (`LibraryClosed`), and a space past
  its share (`AllowanceExhausted`).
- `finishing`: the device's checks of `TokenIssue`: a good one; a proof
  over other elements, under another key, and with one element evaluated
  under a second key, and a proof scalar not below the group's order
  (`BadProof`); more elements than were sent.
- `redemption`: the peer's checks of a deposit in order, each with its
  setup (live keys, spent tokens, budgets): a good token, on the WebSocket
  and on the `POST` route; the same deposit repeated (accepted, same item
  ID); the token on another item (`TokenSpent`); a changed authenticator;
  a token of a retired key; a token of version 2; an item too large; a
  full token budget. The recipients are devices, given with their device
  IDs and the mailbox addresses those give.
- `budgets`: a mailbox at its cap that a token deposit enters by evicting
  anonymous items, then token items; an anonymous deposit refused for a
  mailbox full of token items; and a full token budget that evicts token
  items of an unclaimed mailbox for a claimed one.
- `rotation`: readings of the keys' shard across three periods, with the
  issuing and accepting key at each, the records forgotten at each
  retirement, and a restart with no known wall clock.
- `key_consistency`: a device's sequence of key lists from one peer, and
  its verdict: a rotation, a replaced key that returns, and three issuing
  keys within 24 hours.
