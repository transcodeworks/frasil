# Recovery agent
Protocol 1. Vectors: [ext-recovery-agent.json](vectors/ext-recovery-agent.json).

A **recovery agent** is a party a person names, such as a hosted service,
an IT department or a trusted person's device, that may add a device to the
person's list. This extension specifies how a person names an agent, how
the agent's add reaches the person's spaces and devices, the **waiting
period** after which each verifier trusts a device the agent added, the
relay and the veto that let the person refuse it, and what a client tells
the person.

It extends [identity.md](identity.md), which defines the agent's list
member kind, rootedness and rank, what an agent may sign, the limit on list
members rooted in it, and **waiting**; and [roster.md](roster.md), whose
space policy carries `agent_waiting_period` and `forbid_agents`. It uses
[overview.md](overview.md)'s timeline, estimates and first sight, and
[units.md](units.md)'s and [transport.md](transport.md)'s routes for list
events.

**A core implementation that lacks this extension** validates agent events
by identity.md, and MUST NOT sign an `add` of kind 3. It holds every list
member rooted in an agent as waiting until a `confirm` clears it, so it
never wraps for such a member by the passage of time. It reads and merges
`agent_waiting_period` and does not use it. The extension adds no format,
so nothing is refused or held for it, and every verdict is the same with or
without it; implementations differ only in when they wrap.

## 1. Overview

- Naming an agent is an `add` of kind 3 by a device or a recovery key that
  is not rooted. The agent signs only adds of devices and its own revoke.
- A device the agent adds is rooted in the agent and ranks lowest. Until
  one of the person's devices confirms it, it may revoke only list members
  rooted in the same agent and signs no key event (identity.md,
  roster.md). Time never lifts these limits.
- At each verifier, such a device waits until a `confirm` clears it, or
  until the verifier has counted the space's `agent_waiting_period` from
  its own first sight of the device's add. While it waits, the verifier
  wraps nothing for it. No witness ends the wait.
- Members relay the add to the person's devices at once, and the person's
  devices raise it and offer the **veto**: an ordinary revocation, which
  outranks the agent's device.

## 2. Formats

### 2.1 The agent's list member

An agent is identity.md's list member of kind 3: an Ed25519 identity key
and an ML-DSA-65 key drawn from its own seeds, and no X-Wing key. Its `kc`
hashes its ML-DSA-65 key beside an empty X-Wing key, and its device ID
follows ([crypto.md](crypto.md), "A device's keys"). Its possession
statement is 2,110 bytes. It receives no wrap and writes nothing.

### 2.2 The waiting period

`agent_waiting_period` is key 2 of the space policy ([roster.md](roster.md),
"The space policy"): 259,200 seconds (72 hours) by default, from 259,200 to
2,592,000 (30 days), merged to the longest. A verifier that judges a
person's devices outside any space, such as an application's server
([ext-app-requests.md](ext-app-requests.md)), uses 259,200.

### 2.3 Outcomes

The waiting decision gives one of three outcomes, each a report:

| Outcome | Meaning |
|---|---|
| `Waiting` | the verifier wraps nothing for the list member yet |
| `Vouched` | the verifier treats the list member as one that is not waiting |
| `Vetoed` | the list member is no longer active in the merged list |

## 3. Procedures

### 3.1 Naming an agent

1. The naming list member, a device or a recovery key that is not rooted,
   gives the agent the person ID, the personal space ID and its own
   device ID.
2. The agent signs its possession proof over identity.md's statement with
   kind 3 and the naming list member as adder, and returns its Ed25519
   key, ML-DSA-65 key and proof.
3. The naming list member checks the keys and the proof (identity.md,
   "Checking a list event alone", steps 4 to 6), signs the `add`, and
   publishes it in the
   personal space as any list event.
4. It gives the agent the list's events up to and including that `add`.
   The agent keeps the list events it is given, and builds each add of its
   own on the heads it holds.

Before step 3, the client MUST tell the person that the agent can take over
the person's identity after the waiting period unless one of the person's
devices vetoes, and SHOULD tell the person which of their spaces forbid
agents ([identity.md](identity.md), "What a list vouches for"), since those
spaces wrap nothing more for the person's devices once the add is valid.
When the agent is hosted, the client SHOULD also tell the person not to let
the agent's operator be the only peer of every space they share
(section 4).

### 3.2 Adding a device through the agent

How an agent satisfies itself that it is helping the person is its own
policy. Frasil fixes what follows.

1. The new device, given the person ID and the agent's device ID, draws
   its keys and signs its possession proof over the person ID with the
   agent as adder. The agent checks the keys and the proof (identity.md,
   "Checking a list event alone", steps 4 to 6) and signs the device's
   `add`.
2. The new device, or the agent, hands the `add`, with the list events
   before it that the agent holds, to writer devices of the person's spaces
   by [units.md](units.md)'s route for list events from a device that
   cannot publish them: a `ListEvents` message on a member connection, or a
   `frasil/list-events` device-mailbox item ([transport.md](transport.md)).
   It MUST send them, naming the personal space, to the device mailbox of
   every active list member of the person that is a device. Which other
   spaces and writers it reaches is the application's.
3. A writer that receives them checks and forwards them as units.md says,
   and section 3.5's relay applies.
4. Once a member of a space vouches for the new device, it wraps the
   space's current state for it and sends it a welcome, as
   [identity.md](identity.md)'s recovery says for a space with no recovery
   entry.

### 3.3 The waiting period

Each verifier decides, per space and per list member `m` rooted in an agent
that is not itself an agent:

```text
agent_waiting(m, first, now, W), in order:
  1. m is not an active list member of the merged list.        Vetoed
  2. m is not rooted: a confirm has cleared it.                Vouched
  3. lower(first, now) >= W.                                   Vouched
  4. Otherwise.                                                Waiting
```

- `first` is the verifier's earliest first sight of a valid `add` that
  roots `m` in the agent ([overview.md](overview.md), "First sight"). A
  later add of `m` does not move it.
- **Across a list checkpoint.** A list checkpoint's record names, for each
  member rooted in an agent, the first `add` that rooted it there, and
  every holder of the list keeps that `add`, and every sealed list copy
  carries it ([identity.md](identity.md), "List checkpoints"). A verifier
  that already saw a rooting `add` keeps its first sight; one that sees
  the list for the first time from the checkpoint on, a newcomer or a space
  that starts from it, counts from its first sight of the named `add`,
  which is never before it receives the list. So no checkpoint shortens a
  wait.
- `W` is `agent_waiting_period` of the space's policy in the verifier's
  current view. A device's decisions for its own person use the personal
  space's policy.
- `lower` is overview.md's lower estimate, so a wall clock moved while the
  verifier runs does not shorten the wait.
- **Vouched sticks.** Once a verifier has decided `Vouched` for `m` in a
  space, it keeps that decision there while `m` is active, even if `W`
  later lengthens: wraps already sent cannot be taken back. A device keeps
  each such decision at rest, in the space's `vouched` table
  ([at-rest.md](at-rest.md), "Tables"), committed before it wraps for `m`
  on the strength of it, and decides `Vouched` for every list member a
  record names while that member is active.
- **What waiting governs.** Only whether this verifier wraps for `m`, and
  whether it counts `m` among the devices the person's list vouches for
  ([identity.md](identity.md)). A verifier never refuses an event of `m`
  for waiting: whether `m`'s add is valid is the merge's question, never
  the clock's. The limits on what `m` signs end only with a `confirm`.

### 3.4 The late verifier, and no witness

A verifier that first sees `m`'s add after other members have vouched for
it waits `W` from its own first sight. It MUST NOT end the wait early on any
statement of another party, such as a member's signed record that it saw
the add long ago: that would adopt another device's clock and honesty, it
would say nothing about whether the person's devices had a chance to veto,
and one colluding member could end every verifier's wait at once. Only a
`confirm` ends a wait early.

A late verifier delays only its own wraps. Any member past its own wait
delivers what `m` lacks, so a key event the late verifier makes while it
waits is wrapped for `m` by another member ([keys.md](keys.md),
"Deliveries").

### 3.5 Relay and veto

- **Relay.** A member device that first holds an `add` rooted in an agent,
  of a person a space grants, MUST forward it into that space's system
  stream ([identity.md](identity.md), "Sealed list copies") at once, before
  anything else it writes there. A member that cannot write hands it to a
  writer by the route of section 3.2. Every later event that member writes
  in the space then has the add in its past, so a device of the person that
  receives any of them fetches the add before it applies them.
- **Raise.** A device that accepts an `add` rooted in an agent to its own
  person's list MUST tell the person at once, whatever path brought it, and
  offer the veto.
- **Veto.** The veto is a revocation, by a list member of the person that is
  not rooted in an agent, of the device the agent added and of every list
  member added through it: each list member whose `add` that device
  signed, or a list member so added signed, when that `add` rooted it in
  the agent. A holder that forgot under a list checkpoint finds them by
  the record's rooting adds, which it keeps: each names its author. Such a
  revoker outranks the agent's device, so a duel
  between them goes to the person, and the agent's device cannot revoke it
  (`AgentLimited`). Revoking the agent too stops further adds; a revocation
  of the agent alone voids only its adds concurrent with it.
- **Quiet.** A client of a person who has named an agent SHOULD tell the
  person when none of their devices has heard from any other member of any
  of their spaces for longer than the shortest `agent_waiting_period` of
  those spaces. A quiet space looks the same, so this is a notice, not a
  block.

## 4. Security considerations

- **A compromised agent** can take over the person's identity once the
  waiting period passes at the verifiers of the person's spaces, unless a
  device of the person vetoes. Until a `confirm`, it can neither revoke the
  person's other list members nor choose a space's key.
- **The agent adds only devices that chose it.** Each possession proof
  names its adder ([identity.md](identity.md), "The possession
  statement"), so neither the agent nor a device rooted in it can sign
  again the `add` of a device or recovery key another list member added:
  the copy is `BadPossession`. Such a copy would otherwise stand beside the
  honest `add` and root the list member in the agent, so that it waited,
  lost its veto and its `confirm`, and could be revoked by the agent's
  devices.
- **An agent's server that withholds the add from the person,** while it
  shows the add to members, must keep from every one of the person's
  devices every event that any member wrote in any shared space after
  seeing the add, for the whole waiting period, and keep them off every
  local network with a member: a partition of the person from every
  collaborator. Frasil does not defend against a full partition. A person
  whose every space uses the agent's operator as its only peer can be
  partitioned this way.
- **A person with no device left** cannot veto. Only the relay to their
  spaces' members, and their own return, protect them.
- **A stolen device defeats agent recovery.** A thief holding one of the
  person's devices that is not rooted outranks the agent's device and can
  revoke it, as a veto would. The person then recovers socially
  ([identity.md](identity.md), "Recovery"). The agent route serves a person
  whose devices are lost, not one whose devices are in someone else's
  hands.
- **After recovery through an agent,** a person with no device that is not
  rooted cannot revoke their lost devices, which stay active, and signs no
  key event until an administrator grants the new device directly after
  comparing a code.
- **Divergence.** Verifiers decide at different moments, and the merged
  state never depends on when: the decision changes only who wraps.

## 5. Test vectors

[ext-recovery-agent.json](vectors/ext-recovery-agent.json):

- `parameters`: `agent_waiting_period`'s default and range.
- `waiting_decisions`: section 3.3's decision on readings: one second
  before and at 72 hours; a 7-day period at 72 hours; a `confirm` after one
  hour; a veto after 80 hours; a device seen for the first time after ten
  days, one day later; and a wall clock moved forward while the verifier
  runs, which is not counted.
- `recipients_while_waiting`: a list in which a device names an agent, the
  agent adds a device, and that device adds another; six verifiers, each
  with its first sights and its reading, and the devices each wraps for:
  at once, at 71 and at 72 hours, a late verifier, a second device seen
  later than the first, and a device that a device of the person and the
  agent both add, concurrently, with a proof the device signed for each,
  whose wait counts from the agent's `add`.
