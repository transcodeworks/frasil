# Device-signed requests
Protocol 1. Vectors: [ext-app-requests.json](vectors/ext-app-requests.json).

This document specifies **device-signed requests**: an HTTP request to an
application's server that carries, beside the account's access token, a
signature by a device or passkey member of the person's device list over a
statement that binds the request. It extends [identity.md](identity.md),
whose list checks, merge, pins and fork reports the verifier runs, and uses
[events.md](events.md)'s decoding, [crypto.md](crypto.md)'s strict Ed25519
verification and the label `frasil/device-signed-request/v1`, and
[overview.md](overview.md)'s `check_expiry` with the timers
`signed_request_lifetime` and `signed_request_skew`.

**Without this extension.** Nothing in a log, a roster, a transport or a
peer refers to a signed request. A core client never signs a request
statement, and an always-on peer never authorises by one: it authorises by
storage credentials ([peers.md](peers.md)). A core implementation ignores
everything this document defines.

## 1. Overview

- An application's server, the **verifier**, needs two things of a request:
  which account sent it, and that a device of that account's person sent it.
  The access token says who. The signature says that a device of the person
  sent this request, so a token replayed without the device serves nothing.
- This matters when the application's identity provider gives one token
  audience per sign-in and the application's server accepts the audience of
  the operator's always-on peer, to which the token also travels
  ([transport.md](transport.md), "What a peer learns of a device, and
  acknowledgements"). Whoever holds a token the peer received could
  otherwise act as the account.
- The statement binds the server, the account's subject, the person ID, the
  signer, the method, the path and query, the body, an expiry and a nonce,
  and the heads of the person's list as the signer merged it.
- No server holds a list in the clear, so the person's own devices
  **deliver** their list to the verifier, as the body of a signed request.
  A list authenticates itself, so whoever delivers it needs no trust.
- The verifier records the subject's person at the first request it accepts,
  and refuses every other person for that subject afterwards.

## 2. Formats

### 2.1 Terms and limits

- The **audience** names the verifier in the statement. The **signer** is
  the list member whose Ed25519 identity key signs, named by its device
  ID. The **heads** are the event IDs
  of the signer's merged list that no other event of it has in its past
  ([events.md](events.md)). A **list delivery** is a set of list events given to
  the verifier.
- A verifier's **state** is durable: per subject, the **recorded person**;
  per person, its **pin** of placed list events ([identity.md](identity.md),
  "Pins"), with the verifier's first sight of each.

### 2.2 The statement

```text
statement =
     "frasil/device-signed-request/v1"     31 bytes
  || 0x01                                  version byte
  || 0x00                                  scheme byte: scheme 0, Ed25519
  || field(audience)                       4 + 8 to 256 bytes
  || field(subject)                        4 + 1 to 256 bytes
  || field(person_id)                      4 + 32 bytes
  || field(signer)                         4 + 64 bytes
  || field(method)                         4 + 1 to 16 bytes
  || field(path)                           4 + 1 to 2,048 bytes
  || field(query)                          4 + 0 to 2,048 bytes
  || field(SHA-256(body))                  4 + 32 bytes
  || u64be(expires_at)                     8 bytes
  || field(nonce)                          4 + 16 bytes
  || field(heads)                          4 + 32 × (0 to 16) bytes

signature = Ed25519-Sign(signer's identity seed, statement)               64 bytes
```

Every part after the two bytes is length-prefixed or of fixed length, so two
sets of inputs never give one statement. A statement is at most 5,361 bytes.
A signer refuses to sign, and a verifier refuses, any value outside these
shapes:

- **The version byte** is `0x01`. **The scheme byte** is `0x00`: a request
  is verified once, within seconds, so it is scheme 0
  ([crypto.md](crypto.md)). Every other value of either byte is refused as
  `UnsupportedVersion`, and no other layout or scheme is tried.
- **`audience`** is the verifier's origin in canonical form: `scheme "://"
  host`, then `":" port` only when the port is not the scheme's default. The
  scheme is `https`, or `http` when the host is `localhost`, `127.0.0.1` or
  `[::1]`. The host is lower case: labels of `a` to `z`, `0` to `9` and `-`
  joined by single dots, or an IPv6 address in brackets holding only `0` to
  `9`, `a` to `f`, `:` and `.`. The port is 1 to 65,535 in decimal without a
  leading zero, and never 443 after `https` or 80 after `http`. Nothing
  else: no path, query, fragment, credentials, trailing slash or upper-case
  letter. This is what a browser's `new URL(url).origin` gives, so a signer
  derives it from the URL it calls, and a verifier configures it once.
- **`subject`** is the exact bytes of the token's subject (`sub`): 1 to 256
  bytes of UTF-8, with no control character (Unicode category Cc) and not
  only white space ([overview.md](overview.md), section 5.2). It is never
  sent; the verifier takes it from the token.
- **`person_id`** is the person ID of the signer's list, 32 bytes.
- **`signer`** is the signer's `ed || kc` ([crypto.md](crypto.md), "A
  device's keys"): its Ed25519 key, which signs, then its keys commitment.
  The signer's device ID is the hash of the two.
- **`method`** is the HTTP method, 1 to 16 upper-case ASCII letters, as the
  verifier receives it.
- **`path`** is the request target's path exactly as sent: it begins with
  `/`, holds 1 to 2,048 bytes from `0x21` to `0x7e`, and holds no `?` or
  `#`. It is never decoded, normalised or re-encoded. A client
  percent-encodes an identifier before it enters a path, and the encoded
  form is bound.
- **`query`** is the bytes after the first `?`, exactly as sent: 0 to 2,048
  bytes from `0x21` to `0x7e`, with no `#`; empty without a `?`. A target
  that ends in `?` and one without `?` give one statement.
- **`SHA-256(body)`** hashes the body exactly as sent. No body, or an empty
  one, hashes the empty string.
- **`expires_at`** is the signer's wall clock at signing plus
  `signed_request_lifetime`, 60 seconds.
- **`nonce`** is 16 fresh random bytes per request.
- **`heads`** is the concatenation of 0 to 16 event IDs, strictly
  ascending. A signer whose merged list has more than 16 heads sends none.

### 2.3 Headers

| Header | Value | At most | Required |
|---|---|---|---|
| `X-Frasil-Device` | `signer`, 128 lower-case hex digits | 128 bytes | yes |
| `X-Frasil-Person-Id` | `person_id`, 64 lower-case hex digits | 64 bytes | yes |
| `X-Frasil-Expires` | `expires_at` in decimal, 1 to 20 digits, no leading zero unless the value is `0`, at most 2^64 − 1 | 20 bytes | yes |
| `X-Frasil-Nonce` | `nonce`, 32 lower-case hex digits | 32 bytes | yes |
| `X-Frasil-List-Heads` | 1 to 16 event IDs, each 64 lower-case hex digits, strictly ascending, joined by single commas with no space; absent for none | 1,039 bytes | no |
| `X-Frasil-Signature` | the version byte, the scheme byte and the signature: 132 lower-case hex digits | 132 bytes | yes |

- The access token stays in `Authorization: Bearer`. The audience, subject,
  method, path, query and body are never repeated in a header: the
  verifier takes each from its configuration, the token or the request.
- Header names are case-insensitive; values are taken exactly, with no
  white space. A header present twice is `Malformed`. Every value has one
  spelling, so a captured set of headers has no second form that verifies.
- The response header `X-Frasil-List-Needed: 1` asks the client to deliver
  its list (section 3.4).

### 2.4 The list delivery

```text
list delivery = deterministic CBOR map {1: 1, 2: array of 1 to 4,096 signed device-list events (bytes)}
```

It is the body of a signed `PUT /frasil/p1/device-list` at the verifier's
origin, with `Content-Type: application/cbor`, signed by any device or
passkey member of the person whose ID it names. The route's body limit is
the verifier's; a client splits a larger list into several list deliveries,
each event after its parents. The verifier answers 204 once the request is
accepted.

### 2.5 Error classes and codes

Besides [overview.md](overview.md)'s classes, and
[identity.md](identity.md)'s `WrongPerson` and `ForkDetected`:

| Class | Meaning |
|---|---|
| `Unsigned` | none of the headers is present |
| `Replayed` | a nonce the verifier has seen from that signer within the window |
| `BadListDelivery` | a list delivery that does not read, or holds an event that is not a list event of the person |
| `ListNeeded` | the verifier holds no list of the person, or the heads name an event it has not placed, and its list does not hold the signer |
| `NotASigner` | the verifier's merged list does not hold the key as a signer (section 3.3) |

Every refusal is a decision about one request. The verifier answers:

| Classes | Status and code | Told to |
|---|---|---|
| no bearer, a token refused, an inactive account | 401 `unauthorized` | anyone |
| `Unsigned` | 401 `signature_required` | a holder of a valid token |
| `Malformed`, `UnsupportedVersion`, `InvalidKey`, `BadSignature`, `Replayed` | 401 `signature_invalid` | a holder of a valid token |
| `check_expiry`'s `Expired` or `Malformed` | 401 `signature_expired` | the signing key's holder |
| `WrongPerson`, `NotASigner` | 403 `device_not_listed` | the signing key's holder, with the account's token |
| `ListNeeded` | 403 `device_list_needed`, with `X-Frasil-List-Needed: 1` | the same |
| `BadListDelivery` | 400 `malformed` | the same |

One code covers every way a signature is wrong, so a caller without the key
cannot learn which field it got wrong. A verifier SHOULD log each refusal
with the account, the person, the device ID and the code.

## 3. Procedures

### 3.1 Signing

A client builds the statement from the method, the URL's path and query
and the body bytes it is about to send, with the subject it is signed in
as, its person ID, the heads of its merged list and the audience of the URL,
and sets the six headers. Its HTTP transport sends them unchanged and
follows no redirect ([transport.md](transport.md), the server binding).

A web server that forwards a browser's call to the verifier over a private
binding, such as a service binding or an in-process call, forwards the six
values unchanged. Each remote method of such a binding has a fixed,
documented method and path, so that the statement is the same bytes over
HTTP and over the binding.

### 3.2 Verifying

```text
verify_request(request, now), in order:
   1. Read the body whole, within the route's limit.             else the route's 413
   2. The token verifies (section 3.6); subject = its sub.       else 401 unauthorized
   3. The headers: if none is present, Unsigned. Otherwise each
      value present is within its "at most", then of its shape,
      in section 2.3's order; every required header is present
      and none is repeated (else Malformed). Then the
      signature's version byte is 0x01 and its scheme byte 0x00,
      each checked only at version 1's length.                   else UnsupportedVersion
   4. signer's Ed25519 key passes crypto.md's ed25519_valid;
      device = the device ID of signer.                          else InvalidKey
   5. audience, subject, method, path and query have section
      2.2's shapes.                                              else Malformed
   6. The signature verifies strictly under that key over the
      statement, with the version and scheme bytes read in
      step 3.                                                    else BadSignature
   7. check_expiry(expires_at, now, signed_request_lifetime,
      signed_request_skew) (overview.md, section 6.6).           else its class
   8. With a nonce store (section 3.5): (device, nonce) is
      unseen; record it until expires_at + signed_request_skew.  else Replayed
   9. The subject has no recorded person, or it is person_id.    else WrongPerson
  10. On the list delivery route: place the list delivery (section 3.4).   else BadListDelivery
  11. The merged list of person_id holds device as a signer
      (section 3.3).                                             else ListNeeded or NotASigner
  12. Record person_id as the subject's person if it has none.
      Run the route as subject, person_id and device. If heads
      name an event not placed, answer with X-Frasil-List-Needed: 1.
```

- Steps 2 to 8 need no state beyond the token's key set. Steps 9 to 11 run
  only for a request that a key's holder signed, so unsigned traffic
  changes and learns nothing.
- Step 4 precedes step 6, so a key of small order is refused before any
  signature by it is considered. Step 5 also checks the verifier's own
  audience: a verifier configured with an audience that is not canonical
  refuses every request rather than verify bytes no honest signer made.
- The statement's audience is the verifier's own origin, a setting of the
  verifier. It MUST NOT be read from the request, from its `Host` header,
  its request target or a forwarding header: a verifier that did would
  accept, within the lifetime, a request signed for another verifier and
  sent to it with that verifier's name. Only the path and query come from
  the request.
- Step 6 precedes step 7, so an expiry is told only to the holder of a key
  that made a valid signature. Step 9 precedes step 10, so a list delivery for
  another person than the subject's stores nothing.
- The route then holds a device ID and a person ID it can trust, and MAY
  narrow further, such as to devices only, or refuse a device ID in its own
  input that is not the signer's.

### 3.3 Who signs

A **signer** is an active device or passkey member of the verifier's merged
list of the person ([identity.md](identity.md), "What a list vouches for"),
that has not forked and is not waiting:

- A list member rooted in a passkey signs while it is active.
- A waiting list member does not sign. A verifier that implements
  [ext-recovery-agent.md](ext-recovery-agent.md) counts the waiting period
  from its own first sight of the `add`, the first in canonical order when
  the list holds several for the member, at the default
  `agent_waiting_period`, since it has no space policy. It counts by its
  wall clock, as it reads `now` in section 3.2, since a verifier keeps no
  timeline: the wait ends once `now` is at least the first sight plus the
  period. One that does not implement the extension waits for a
  `confirm`.
- A recovery key and a recovery agent never sign.
- A revoked list member, and one that forked from its fork point, never
  sign.

### 3.4 List deliveries

A list event verifies from the person's first event, whose event ID is the
person ID, and every `add` carries its key's possession proof. So the
verifier takes list events from whoever delivers them and trusts only their
signatures. **Placing** a list delivery, in order:

1. The body is section 2.4's map. Else `BadListDelivery`.
2. Each event passes [events.md](events.md)'s decoding, is of kind 1, and
   is the person's: its `log` is `person_id`, or it is a first event whose
   event ID is `person_id`. Else `BadListDelivery`, and nothing of the
   list delivery is placed.
3. A verifier that holds none of the person's events needs the first event
   in the list delivery, and places nothing without it. A first event that fails
   [identity.md](identity.md)'s check of a first event is `BadListDelivery`.
4. Each event is placed after its parents. One whose parents are missing
   waits for a later list delivery.
5. The verifier records its first sight of each event it places.

- The merged list is [identity.md](identity.md)'s merge over the placed
  events. An event the merge finds void stays placed and counts for
  nothing.
- The placed events are the verifier's pin of the person. They only grow:
  a verifier never drops a placed event, so nobody can roll back what it
  holds. A list delivery that brings new evidence of a fork is merged as usual,
  and the verifier reports `ForkDetected`.
- A verifier MAY refuse, as `BadListDelivery`, a list delivery that would bring the
  events it holds of one person past 4,096.
- **Heads.** When a request's heads name an event the verifier has not
  placed, a verifier whose list holds the signer accepts the request and
  answers with `X-Frasil-List-Needed: 1`; otherwise it refuses
  `ListNeeded`. Heads never make a request fail that the verifier's list
  accepts.

**When a client delivers.**

- After `device_list_needed`: every event of its merged list, then it
  retries the request once, signed again with a fresh nonce.
- After `X-Frasil-List-Needed: 1`: the events the verifier may lack, or
  all of them.
- Whenever it signs or first places a list event of its person, to every
  audience it has signed a request for: at once for a revocation and for
  an `add` by a recovery agent, otherwise with its next request there. A
  client keeps that set of audiences per person, on the device.

### 3.5 Replays within the window

- A request lives `signed_request_lifetime` plus `signed_request_skew`
  either way, by the verifier's wall clock.
- **A stateless verifier** keeps no nonce, and an exact replay within the
  window runs the same operation again with the same inputs. A verifier
  whose every write is idempotent, such as a completion that answers
  `not_found` once completed or an upsert of the same record, MAY be
  stateless. A replayed list delivery places nothing new.
- **A stateful verifier** keeps `(device, nonce)` until `expires_at` plus
  `signed_request_skew` and refuses a repeat as `Replayed`. A verifier with
  a write that is not idempotent MUST keep one, durably across its workers.
  Each verifier documents which it is.
- A client refused `signature_expired` reports it to its application. It
  takes no time from the answer's `Date` header ([overview.md](overview.md),
  section 6.2).

### 3.6 The token and the person

- The verifier checks the access token as its identity provider requires:
  its signature under the issuer's keys, `iss`, `sub`, `exp` and `iat`, the
  subject's shape, and that the account is active. It MAY accept the
  peer's audience: the signature, not the audience, keeps the peer out. It
  SHOULD keep an authorised-party check (`azp` or `client_id`) over every
  client whose devices call it.
- The statement's subject is the token's `sub` by construction, since the
  verifier builds the statement with it. A token and a signature from two
  accounts never combine.
- **The recorded person.** At the first request it accepts for a subject,
  the verifier records that subject's person (step 12), and afterwards
  refuses every other person for it (`WrongPerson`). Before the person's
  own first request at the verifier, a holder of the subject's token who
  signs with a person of its own takes the record; the person is then
  refused visibly, and the verifier's operator clears the record after its
  own account checks.
- A person who recovers with a recovery key, a passkey or a recovery agent
  keeps the person ID and the record. A person who returns as a new person
  ([identity.md](identity.md), "Recovery") is refused until the operator
  moves the record.
- An account link does not replace the record: an account's server stores
  links for whoever holds the subject's bearer token. A verifier MAY also
  require a valid link of the subject and person ([identity.md](identity.md),
  "Checking an account link") before it first records a person.

## 4. Security considerations

- **A replayed access token.** Without a signature by a key on the
  person's list, a request is refused before any route runs, and such a
  signature needs the device's private key. Once the subject's person is
  recorded, a list of the attacker's own serves nothing, and no key can be
  added to the person's list without a list member's signature.
- **A forged or withheld list.** Every `add` carries its key's proof for
  this person and every event a list member's signature, and the first
  event's ID is the person ID, so a forged event has no standing in the
  merge. A placed event is never dropped, so nothing rolls a list back.
- **A revoked device** signs at a verifier until one of the person's other
  devices delivers the revocation there, which each does at once. A
  verifier that cannot accept this window keeps writes behind a second
  check of its own.
- **A replayed signed request** is refused after its expiry, and within the
  window by a stateful verifier. Its bytes serve no other method, path,
  query, body, verifier, account or person.
- **A verifier's clock.** A verifier fast by `d` seconds refuses honest
  requests when `d` passes `signed_request_skew`, visibly. One slow by `d`
  lengthens the replay window by `d`. A verifier's clock moved forward by
  `d` between its first sight of an agent's `add` and a request shortens
  that waiting period by `d`, while it runs or not: unlike a member, which
  counts the wait on the lower estimate of its timeline
  ([ext-recovery-agent.md](ext-recovery-agent.md), section 3.3), a verifier
  counts it by its wall clock (section 3.3). A clock moved back lengthens
  it. The clock decides only whether the verifier serves a request.
- **What it does not bind.** Other headers, such as `Content-Type`, `Host`
  and `Accept`: the body's bytes are bound, the verifier's configured
  audience stands for `Host`, and binding headers would break signatures at
  proxies that normalise them.
  The token: binding its `sub` is what `subject` does.
- **Strict verification everywhere.** A JavaScript verifier MUST NOT use a
  platform Ed25519 that accepts an `R` of small order, such as WebCrypto's;
  it runs [crypto.md](crypto.md)'s strict verification, for instance from
  WebAssembly.
- **What it does not defend against:** a device whose key is stolen, until
  it is revoked and the revocation reaches the verifier; what the token
  alone allows at an account's server; the first record taken by a token
  holder before the person's first request; a replay within the window at a
  stateless verifier; denial of service; and a verifier that skips the
  merge, which would give a token holder a device on every person.

## 5. Test vectors

[ext-app-requests.json](vectors/ext-app-requests.json), over lists that
[identity.md](identity.md)'s reference builds:

- `parameters`: the version and scheme bytes, the lifetime and skew, the
  nonce length, the field limits, the headers and the list delivery route.
- `lists`: a person whose every event is signed: a laptop that starts the
  list, a phone, a passkey member that adds a browser, a recovery key, an
  agent that adds a device, then, concurrently, the laptop revoking the
  passkey member and the phone adding a tablet, so the full list has two
  heads. Three views a verifier may hold: before the revocation, without the
  tablet, and full. Another person. Every signing seed.
- `requests`: statements and signatures split by field, with the six header
  values, the verifier's state and its result: a `GET` with no body and two
  heads; a `PUT` with a JSON body and no heads; a path with a query to a
  loopback audience with a port, from the tablet's branch; a passkey member,
  against the list before its revocation; every field at its limit, with
  sixteen heads of which the verifier lacks fourteen (accepted, list
  needed); a device the agent added, after the waiting period; and a first
  request that is a list delivery, to a verifier that holds nothing and records
  on it. Each is verified at its signing time and at both edges of the
  window.
- `request_refusals`, each with its class: another audience, subject or
  person ID; a changed body or method; the query moved into the path with
  its `?` percent-encoded; another key's signature; an expired request and
  one 121 seconds ahead; a revoked signer, a key on no list, a recovery key,
  the agent, a device the agent added within the waiting period, and a
  device of another person once the subject's person is recorded; no list
  and no record, and a device added on a branch the verifier lacks; a
  list delivery that does not read and one holding another person's event; an
  unreduced `S`, an `R` of small order and a non-canonical `R`; a key of
  small order and a key that is no point; other version and scheme bytes;
  each header malformed, a required header absent, a repeated header, and a
  method, path, query, audience or subject outside its shape; a replayed
  nonce at a stateful verifier; and no header at all.
- `list_deliveries`: the tablet refused `ListNeeded`, its list delivery of the missing
  event, and its retry, accepted.
- `heads`: a head the verifier lacks, from a signer it holds: accepted, list
  needed.
- `lenient_verifier_would_accept`: the signatures a verifier without strict
  checks would accept.
