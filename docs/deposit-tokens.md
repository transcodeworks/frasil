# Deposit tokens and delayed deliveries

A device sends some things to another device through that device's mailbox
at a peer: a welcome when a space grants a person, a leave request to the
devices that administer a space, a person's list to a space's writers. A
deposit in a device mailbox carries no credential, so the peer never learns
who writes to which device. That also means the peer cannot tell honest mail
from a stranger's, and a stranger can fill the room it keeps for such mail.

This guide covers two things the client does about it:

- **Delayed deliveries**, in every build: a deposit the peer does not take
  now is kept and sent again.
- **Deposit tokens**, with the `ext-deposit-tokens` feature: anonymous tokens
  that pay for a deposit, kept in room of its own at the peer that a stranger
  cannot fill.

The specification is [ext-deposit-tokens.md](spec/ext-deposit-tokens.md) and
[transport.md](spec/transport.md), "A sender keeps what was refused".

## Delayed deliveries

A peer that is full answers a deposit `busy`; one that limits a sender
answers `rate_limited`. A device whose deposit is answered so, or not
answered, or whose peer cannot be reached:

- keeps the item sealed at rest, from before the first attempt, so that a
  restart or a closed tab loses nothing;
- sends it again after a random wait of up to a minute, doubled after each
  further failure to at most an hour;
- gives it up once 30 days have passed since the first attempt, the most a
  peer keeps mailbox items, or at once on a final refusal such as
  `too_large`.

Nothing is asked of the application. It learns what happens through the
device's events:

| Event | When |
|---|---|
| `Event::Delayed { peer, reason }` | an attempt failed; `reason` is the peer's code or why it was not reached |
| `Event::Delivered { peer }` | a delayed deposit was taken |
| `Event::Undelivered { peer, reason }` | a deposit was given up: `expired`, or the peer's final code |

`Device::waiting_deposits` counts what waits. A call that deposits as part of
its work reports a delay as `Error::Delayed`: for example
`Device::admit_spaces_via_peer` reports a space whose grant was made but
whose welcome waits with `granted: true` and `Err(Error::Delayed(_))`, so an
application can say "invited, delivery pending" rather than "failed".

In the browser package the events are `"delayed"`, `"delivered"` and
`"undelivered"`, the error code is `delayed`, and
`device.waitingDeposits()` counts. The native bindings give the same as a
`DepositListener` and `waiting_deposits`.

## Deposit tokens

With the `ext-deposit-tokens` feature (part of `p1-full`, and built into the
browser package and the native bindings), a device pays for each deposit in
a device mailbox with a token at a peer that offers them. The peer keeps
paid items apart: an anonymous deposit never pushes one out, and a stranger
without tokens delays only anonymous mail. Tokens are blind: the peer cannot
link the deposit it takes to the grant, library, space or batch the token
came from.

A device draws tokens in one of two ways:

- **With a grant.** The application asks its library's issuer for a deposit
  grant over its own account traffic, as for any library ticket, and hands
  the bytes to the device. The grant names the library and how many tokens
  it gives, and never an account, a person or a device.
- **As a writer of a space.** A device that may store events in a space the
  peer hosts can draw on that alone, counted against the share of tokens the
  space's library gives each of its spaces. This needs nothing from the
  application.

```rust,ignore
// The issuer's grant, as bytes, for the peer where the device deposits.
device.give_deposit_grant("https://peer.example.org", grant);

let tokens = device.deposit_tokens("https://peer.example.org").await;
println!("{} tokens, paused: {}", tokens.held, tokens.paused);
```

```ts
device.giveDepositGrant("https://peer.example.org", grant);
const { held, paused, distrusted } = await device.depositTokens("https://peer.example.org");
```

### When the device draws

The device draws ahead of need, never in answer to a deposit, so that the
time of a draw does not point at a deposit:

- When it holds fewer than 4 tokens of the peer's current key, and has a way
  to draw there, it draws a batch at a random moment within the next hour.
  A device that has just received a grant, or just started writing a space
  the peer hosts, holds none, so its first batch comes within the hour,
  before it needs one: a new user's first welcome is paid for.
- A batch is 16 tokens, or what `Options::deposit_batch` sets, up to 256.
  Give every device of an application the same batch, and ask the issuer
  for grants of at least that many tokens: a grant draws once, and a draw
  asks for exactly the batch.
- A device holds at most 256 tokens of a peer. Tokens live one to two of
  the peer's key periods, 7 days each by default; the device drops those of
  a key the peer no longer lists.

A grant is held in memory only, and used by one draw. It is never written
to the store, logged or shown, and a restart loses it: hand it over again
at each start until `deposit_tokens(peer).grant` is false, or ask for a new
one when the device runs low.

### What each connection shows

The device opens connections of its own for tokens, each a fresh WebSocket
(or a fresh iroh endpoint key), like an administration connection:

- It asks the peer's keys on a connection that presents nothing.
- It draws on another: one that presents only the grant, or only the
  space's upload key, and stores nothing.
- It deposits on another: one that carries the deposit and its token, and
  no space, key or device ID of the sender. The only device it names is the
  recipient, by its mailbox address.

Every deposit in a device mailbox goes on a connection of its own, with a
token or without one, never on the connection that carries the device's
spaces: a deposit names its recipient, and the peer would otherwise learn
that the holder of those spaces writes to that device. An application that
opens the device's connections itself (`Options::connect_with`) supplies
`Connect::bare` for this, as the browser package does; without it, the
device's deposits are undelivered (`Event::Undelivered` with
`unsupported`) and it draws no tokens.

The device learns a peer's keys by asking on a connection that presents
nothing, not from the discovery document, which a cache in front of the
peer may serve after the peer has rotated its keys.

So the peer sees, at a draw, that a library (and, for a space draw, a
writer of that space) drew so many tokens, and at a deposit, a valid token
for a recipient. It does not see who sent it. It does see the recipient,
and the network address of each connection; a device that needs its
address hidden from the peer connects through a proxy.

### What can go wrong

| What happens | What the device does | What the application sees |
|---|---|---|
| The peer answers a draw `allowance_exhausted`: the library has drawn its whole allowance for the day | draws nothing there for 24 hours, keeps the grant, and deposits without tokens meanwhile | `deposit_tokens(peer).paused` |
| A token is refused or expired | drops it, and sends the item again at once with another or without one | nothing |
| A deposit is answered `busy` | keeps the item with its token, and sends both again later | `Event::Delayed` |
| The peer's key lists contradict one another | stops drawing and spending there, drops its tokens, deposits without them | `Event::DepositPeerDistrusted { reason: "key_inconsistent" }`, `deposit_tokens(peer).distrusted` |
| A batch's proof does not hold | drops that batch | `Event::DepositPeerDistrusted { reason: "bad_proof" }` |
| The peer does not offer tokens | deposits as without the feature | nothing |

A peer that shows different devices different keys could tell their
deposits apart, so a contradiction stops the device for good, rather than
for a while. If a person decides the peer is trustworthy again, for
example because its operator says it restored its keys from a backup,
`Device::trust_deposit_keys` (`device.trustDepositKeys` in the browser)
clears the stop, and the device learns the peer's keys anew.

## What the operator sets

A peer offers tokens when its operator turns the deposit tokens extension
on, together with libraries. The settings, which the specification defines
and [self-hosting.md](self-hosting.md) shows how to set, are:

| Setting | What it is | Default |
|---|---|---|
| `deposit_allowance` | the tokens a library may draw per 24 hours | 64 |
| `space_share` | the part of it the writers of one space may draw without a grant | 16 |
| `token_period` | how long a key issues; its tokens are taken for a period more | 7 days |
| token budget | the room, in items and bytes, the peer keeps for paid mail | the operator's |

A library whose spaces strangers can attach, as on an open peer, should
have a `space_share` of 0 or a low allowance, so that its holders draw by
grant. A peer whose operator turns the extension off behaves as one without
it: devices deposit without tokens.
