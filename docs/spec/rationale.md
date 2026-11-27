# Rationale
Protocol 1. Informative: this document specifies nothing.

This document explains why Frasil is designed as it is. For each choice it
says what was chosen, why, and what the alternatives would have cost. Where
it and a normative document seem to differ, the normative document holds.
It assumes [overview.md](overview.md) and uses its terms. Section 11 states
plainly what Frasil does not defend.

## 1. No authority

### 1.1 Every check is a replica's

Frasil's first goal is that no party is an authority: an honest replica
decides from the events it holds whether an event is valid. Much of the
design follows from taking that seriously.

Most end-to-end encrypted group systems still have one party that orders
membership: Signal's group server checks a version on every change, MLS
leaves conflicting commits to a Delivery Service (RFC 9750, section 5.2),
and Keybase closes the race before a revocation with a server lease. Each
lets the orderer decide, delay or steer who is a member, and each needs it
reachable, so two devices on a local network could not change membership.

Frasil has no orderer. Events carry causal links, replicas decide in a
canonical order that each computes alike, and the rules are chosen so that
the result does not depend on arrival order. The costs are that some
conflicts cannot be told from attacks (section 2.3), and that removal is
eventual for reads (section 2.6). Section 11 lists both.

A witness, such as a peer's first-seen order, would settle some of those
conflicts, and Frasil has none. ERA (arXiv 2601.22963) proposes an
optional arbiter that finalises batches, and shows why information from
outside the event graph is needed to tell a genuine duel from a backdated
one. A witness whose order decides membership is an authority, and a space
that works off the network would have none.

### 1.2 A peer adds availability, never trust

An always-on peer relays, stores, keeps mailboxes and applies quotas. It
judges no event. It checks envelopes, Ed25519 signatures, visible parts,
sizes and rates, and decides only what it stores and serves.

- **Credentials, not identities.** A device fetches with a read credential
  and stores with an upload key, derived per state; a rotation commits to
  their public halves. Every member holds the read credential, so a fetch
  names no reader. It derives from the content key, which every member
  holds anyway; a secret of its own would cost a bundle slot.
- **Only administrators end credentials.** If any writer could, one writer
  could lock every member out. The cost is that a removed member keeps
  fetching ciphertext and spending quota until administrators act: bounded,
  attributed, and revealing nothing.
- **An ended read credential still grants catch-up.** A member that was
  offline through several rotations must still learn its new keys, which
  are in the space events. Catch-up serves only space and storage events,
  whose sizes and timing a peer sees anyway.
- **Storage credentials stay classical.** Forging one fetches ciphertext and
  spends quota. Nothing a peer decides on such a credential changes an
  event's validity, so a hybrid signature there would buy nothing.
- **The cap on live credentials** evicts first the entries of rotations
  that later rotations follow, so a writer's flood cannot push honest
  entries out. A merge statement needs every input's proof, so nobody can
  hand a peer an invented merge.

### 1.3 The administrator skeleton

A peer must still refuse some requests. An erasure, or a request to end
credentials, has to come from an administrator, and the peer cannot read
the roster. Frasil gives the peer the smallest structure that lets it check
this: the administrator skeleton, the space's administrators under
pseudonyms.

- **Not a shared maintenance key,** which a removed administrator keeps,
  and whose rotation needs the roster the peer cannot read.
- **Pseudonyms are fresh per space and per grant,** never derived from
  device keys, so a peer cannot link them across spaces or test a guess.
- **The granter seals a slot token** to the grantee, because the grantee
  may be absent when it is made administrator. The grantee's sealed binding
  lets replicas detect a granter that enrolled a pseudonym of its own
  first.
- **Each roster event that changes who administers names its twin by ID,**
  and the twin is signed first. A lookup by ID cannot be raced: a junk
  skeleton event with the same commitment is never the twin. The cost is
  that a peer links that administrator's pseudonym to its device.
  Administrators that never change who administers stay unlinked. The
  genesis cannot name its twin, because the twin's parent is the genesis;
  the founder's signature over the root pseudonym binds it instead.
- **A slot reference names the event that made the administrator slot,**
  as well as its commitment and index, because a peer cannot tell a twin's
  commitment from a copy. Letting a later change redefine an administrator
  slot would let one administrator take over another's; keeping the first
  in canonical order, or voiding both, could be won by choosing a copy's
  height or ID, or would remove an administrator slot after the fact. Each
  copy instead makes administrator slots of its own, and since every
  enrolment, lower and disown names its maker, removing a copy never lowers
  what it copied, and a copied grant map never blocks the real grantee.
- **A twin's commitment takes a fresh salt.** A roster event's body key can
  be derived ahead of time by any member, so without the salt an
  administrator could publish another's next commitment first and make
  that one's honest twin a repeat. With it, an honest twin never repeats a
  commitment in its past, so a peer can refuse repeats past a limit
  without ever refusing an honest twin.
- **The cite-together rule** has a device cite a twin exactly when it cites
  the twin's roster event, so the skeleton has the roster's concurrency. A
  peer then applies the roster's own merge rules to the skeleton and
  reaches the same verdicts on administrators.
- **Concurrent enrolments are both void,** so a race is visible rather
  than won.

### 1.4 Destructive acts wait

An erasure cannot be undone at a peer, and a later merge can void the
request that caused it. A verdict at a peer rests on beliefs about
concurrent events that can still change; ECAC (Jacob and Hartenstein,
CODASPY 2025) separates storing an action from executing it for this
reason. So a peer executes an erasure only once it is stable at the peer,
every administrator having acknowledged it, or after the timeout T, at
least one hour.

- **A concurrent lowering is the only veto.** An administrator that wants
  to stop another's erasure lowers that administrator, concurrently. It
  costs the requester its administration, which is the point: a veto that
  cost nothing would let any administrator block every other.
- **Lowered administrators stay in the stability set until the lowering
  settles.** Otherwise one administrator could lower the others and then
  make its own erasure stable alone. The cost: after a hostile removal,
  requests wait up to T, and in a space with an offline space recovery
  member they always wait T.
- **Routine cleanup sends no erasure,** because an erasure shows the peer
  which pseudonym asked. Compaction uploads a snapshot unit instead, and
  the peer collects what it replaces once the snapshot is stable at the
  peer, or after T.
- **Release is any writer's,** restorable during the retention, and a
  concurrent restore wins: a release is reversible, an erasure is not.
- **An erasure names the whole space.** Erasing one stream at once would
  delete units that space events of the space may name as parents, and a
  space event is placed only against its parents held in full or under
  stubs it can confirm. A replica that catches up after such an erasure
  could not place it: a stubs unit written for the erased units would
  itself wait on the space event it stands under, a peer cannot read it to
  name it as their carrier, and replicas do not judge erasures. So a peer
  never deletes part of a space at once. A document is deleted for good by
  a release: the peer stops serving it at once, any writer can restore it
  during the retention, and once the peer reclaims it the content is gone,
  while the units that events outside the stream name stay as events
  without content, so every replica still places what names them. An
  erase body reserves its keys for streams and objects, so that a later
  protocol can erase less than a space once it says how replicas place
  what named the erased units.

### 1.5 Accounts decide nothing

An account links a person ID to a subject at an identity provider. Its
server may answer lookups and keep a sealed directory and a mailbox, and
nothing more. Identity belongs to the keys of a person's devices. If the
account were the identity, every person would need one and a reachable
server, and that server could add a device to anyone.

## 2. Membership without an orderer

### 2.1 A branching roster with one resolution

Administrators may change a roster while apart, so roster events branch.
Every replica runs one resolution procedure over what it holds and reaches
the same valid set. Its first step is the least fixed point of local rules,
so the order of evaluation does not change the result, and every void event
names the events that void it, so a client can explain any outcome.

The rules read only events and their concurrency: never a clock, never
another log. That is why `administer` is granted to devices only, in the
space's own roster. A person's list and another space's roster share no
causal order with this roster; if `administer` came through them, replicas
holding those logs at different heads would void different roster events.

### 2.2 What beats what

- **A removal voids the removed member's concurrent actions,** and any
  concurrent grant of it, so a re-grant must follow the removal. Otherwise
  a removed member's acts on a branch it controls would survive the merge.
  A demotion likewise voids the demoted member's concurrent roster actions.
- **Concurrent grants of one member meet,** failing closed: the lowest
  level, an extending capability only if every grant has it, "with history"
  only if every grant gives it. Concurrency never raises a grant.
- **An event that only lowers its own author is never voided,** by
  concurrency or by its author's fork. No attack makes a member hold more
  than it asked to.
- **An event that lowers an administrator names nobody else.** Otherwise a
  backdated "remove my remover, and everyone else" would stand as half of a
  mutual pair. A remover raised after the event's place is held to the same:
  only an event of one change is spared by its partner. With this rule a
  duel takes only its pair.
- **A duel never undoes its partner's authority.** A removal beats a
  concurrent grant or raise of its target, so without this rule a removed
  administrator whose remover was still a writer at its last event would
  backdate a removal of the writer, void the raise, and with it its own
  removal. In a duel, neither side's attacks count against the grants and
  raises that made the other's author an administrator, back along the chain
  of their granters. The rule reads only events, so it depends on no
  outcome. It spares none of the remover's own events, so a remover cannot
  shield what it did concurrently, such as raising an accomplice.

### 2.3 Ranks decide duels

Every administrator carries a rank, 0 to 255, set when it becomes an
administrator; the founder holds 255. No member acts on an administrator
of a higher rank, or gives a rank above its own, and when two
administrators of one rank remove or demote each other concurrently, the
more senior one's event stands and the other's is void.

A removed administrator can sign a counter-removal whose parents leave out
its own removal, and the graph is identical to a genuine mutual removal:
no rule over the graph alone tells them apart (ERA, arXiv 2601.22963,
section 3.2). The rule must therefore pick from something both sides agree
on. A rank is set before the duel and read at each event's place, so it is
the same at every replica and no branch can change it: a removal by a
member that outranks the attacker cannot be undone by any counter-removal,
backdated or not, with or without a checkpoint. The cost is plain: whoever
holds the device of the top rank, most senior at that rank, wins every
duel, so the top rank belongs on few, well-guarded devices and day-to-day
administrators hold a lower one. "Both stand", the earlier rule, gave no
side a win but let any removed administrator take its remover with it,
and once checkpoints existed, let one removed administrator make a
checkpoint whose electorate was itself (roster.md, section 4).

The genesis carries a `duel_policy` field, 0 for this rule, with every
other value reserved. A later policy is then a space's choice, refused by
replicas that do not know it, rather than a new protocol.

### 2.4 Seniority for the other cycles

Some events wait only on each other: a cycle of attacks that count, which
no duel rule breaks. With at most 16 such events, the procedure first tries every
assignment of valid and void (at most 65,536) and settles whatever all
allowed assignments agree on, so an event that is void either way cannot
steer the choice. Above 16 the step is skipped to bound the work; every
event in such a cycle needs an administrator's signature at its place.
Then the event of the author with the highest rank, the most senior among equals, stands. Seniority is a total order over
grants: height, then a hash of the space ID and the grantee's ID, then the
grant's event ID.

- **Height, not causal order with a hash between concurrent grants,** which
  is not transitive and can cycle. Height extends the causal order, so a
  grant is junior to every grant it follows.
- **The hash covers what the granter does not choose,** so it cannot grind
  which of two concurrent grants is senior. Space IDs, not event IDs,
  decide cycles among grants of spaces for the same reason.
- **What stays grindable.** A granter can raise a grant's height, never
  lower it. A device can grind its own key before it is granted, a choice
  made before anyone trusts it, which wins only odd cycles.
- **`replace` gives no seniority,** or a compromised administrator could
  mint a founder.
- **Only authors with standing are contested.** A reader, writer, guest or
  removed member can sign roster events that open and verify. If they were
  contested, enough of them after a cycle would stay undecided with it and
  push the count past 16, so that seniority, not agreement, decided the
  cycle, and each would cost work in proportion to the others. An event
  whose author no event in its past names at `administer` is left out
  instead. The test reads the event's past alone, which never changes, so
  it is monotone: every replica that holds the event reaches it, and no
  later event takes it back. It is also sound: a level at a place comes
  only from changes in that place, so such an author is no administrator
  at its event's place under any assignment, and the event is void either
  way. A test over the whole view, an author named at `administer` by any
  event the replica holds, would be sound too, but a raise concurrent with
  the junk would bring it back into the contest. A hard cap on the events
  weighed, chosen by event ID, would bound the work but let junk with low
  IDs crowd out real events, and would make an event's verdict depend on
  how many others exist. A removed administrator keeps standing for its
  events concurrent with its removal; those are contests the rules must
  decide, and only someone once made an administrator can sign them.

### 2.5 Per-device chains

Each author's events in a log form a chain numbered by `seq`, each naming
the previous as `prev`, which is also a parent. Two events at one `seq`, or
a `prev` that skips, prove a fork, and the author is void from the fork
point. The shape is that of Keybase's signature chains, kept per device and
per log.

- **`prev` is a parent,** so a verifier sees from the event alone that it
  follows its author's previous event. Otherwise an author could cite its
  previous event while leaving it out of the causal past.
- **The chain bounds backdating** to what the author saw after its own last
  event. It does not bound an administrator that stayed silent.
- **Evidence does not depend on keys held.** An event counts as evidence
  once its signature verifies, opened or not; otherwise a newcomer would
  miss forks others see, and replicas with the same events would disagree.
- **Chains are keyed by device ID,** not by the Ed25519 key. An adversary
  that can forge Ed25519 but not the device's ML-DSA-65 key signs in full
  only under a commitment of its own, so its events form another author's
  chain and can never be evidence against the device. Keyed by the Ed25519
  key, a quantum adversary could void any device by signing a second event
  at a used `seq`.
- **Frontiers are derived,** each removed device's latest event in the
  removal's past. A frontier written by the remover could only disagree
  with the parents. `seq` is per log, not per stream, so a frontier has one
  entry per device and no gap hides between streams.
- **No `seq` starts from a clock.** That would be a timestamp, and would not
  stop a restored device from forking; fetching its own latest event before
  signing does.

### 2.6 Removal: strict for writes, eventual for reads

- **Writes are strict.** A unit concurrent with the end of its writer's
  write is refused, whatever it links to, so backdating gains nothing.
- **Reads are eventual.** A writer that has not heard of a removal seals for
  the removed member until it hears. Strict removal for reads would need
  every writer to know of every removal before writing: an orderer. The
  guests extension bounds how long an honest writer may go unheard.
- **Removal across logs is eventual too.** A revocation in a person's list,
  or a removal in a granted space, takes effect here once a writer of this
  space responds by citing it, and the response's past is the frontier.
- **Key events are decided once, in canonical order.** A pass repeated
  until nothing changes does not settle: two key events that each respond
  to the end of the other's author refuse each other, then neither, then
  both.
- **Refused units are kept,** because a later merge can void the refusing
  event. A device that regains a path re-submits them as new units, since a
  re-grant never revalidates the old ones; this is what recovers a duel's
  loss. `gap_key_timeout` bounds how long others keep their content.

### 2.7 Checks across logs hold, never guess

- **Refs are sealed,** so a peer cannot read which spaces grant which. An
  unresolved ref holds only the citing event and its author's later ones,
  so a stranger that cites events nobody holds freezes only its own chain.
- **A grant carries the member's heads,** its known past: a device revoked
  in that past never writes through the grant.
- **A pending event is never applied, cited or refused.** Guessing an order
  between logs would make replicas disagree.
- **An edge to a restricted space never counts,** since it would widen a
  restriction; nor does one that closes a cycle or passes a depth of 8.

### 2.8 Limits and proofs

- **4,096 valid roster events per place.** Only valid events count, so
  nobody fills a place with events it had no authority to sign. A
  checkpoint resets the count, so it bounds an epoch, not a space's life.
- **64 device grants per event.** A device grant with its keys is about
  3.2 KB, and 64 leave room for a rotation's wraps.
- **A device grant carries keys and no proof.** Its member ID commits to
  every key replicas will trust, so no administrator can pair a device's
  Ed25519 key with an ML-DSA-65 key of its own: that is another member. A
  proof that the device holds the keys would add nothing to the space's
  safety (section 12), and would cost 3,373 bytes and a signature per
  grant.

### 2.9 Stability and the space recovery member

A set of events is stable when every administrator that has not forked has
signed an event whose past holds it. Replicas compute this themselves, and
Frasil waits for it wherever an act cannot be taken back: gap keys for a
restored member, dropping refused content, collection and erasure.

A space recovery member, a device member at `administer`, at the top
rank, whose key is kept offline, keeps someone inside able to derive the
current key, because every rotation wraps for it, and can excuse a lost
top-rank device from a checkpoint (roster.md, section 3.15.4). It needs no
special status beyond its rank. The cost: it never acknowledges, so stability in its space always
waits for the timeout. A space with one administrator has no duels.

### 2.10 Checkpoints: forgetting without disagreeing

A roster that only grows costs every newcomer the whole history, and the
4,096 bound would end a long-lived space's membership. A checkpoint lets
every party forget, at one price: concurrent work is void.

- **Why it must change verdicts.** Without finality, any late branch, a
  removed administrator's backdated counter-removal or a fork at an old
  `seq`, can change what an old event means, so nobody may forget. A
  checkpoint in effect makes every event concurrent with it late, and
  freezes its past at the verdicts of that past alone. Both are merge
  rules: no checkpoint, no change, and a history with none resolves as
  before.
- **Why every replica agrees, whatever it forgot.** Three facts:
  1. *What follows a checkpoint is readable from envelopes.* Each event
     declares the checkpoints its past holds, and the declaration is
     checked against its parents' alone. So a replica that holds nothing
     before checkpoint `c` and one that holds everything sort every event
     they both hold the same way: in `c`'s past, `c`, after `c`, or late.
  2. *The world after `c` is one function of one input.* Events after `c`
     are judged by the resolution procedure itself, run over a log whose
     root is `c`, whose events are those after `c` linked through each
     other, and whose founder is `c`'s record. Both replicas hold exactly
     those events (each one's parents after `c` are after `c` too, or the
     event is void as mixed), and the same record. Heights, canonical
     order, seniority, attacks, the bound and fork evidence are all read
     inside that log.
  3. *The record is the past's, and the past cannot move.* A replica that
     holds the past checks the record byte for byte against the past's own
     resolution, a function of the checkpoint's past alone, and voids a
     false one. A checkpoint takes effect only once every administrator of
     its record has voted by writing after it; an honest administrator
     votes only for a record it checked. Once in effect, nothing
     concurrent with it counts, so nothing can make its past resolve
     otherwise.
  Effect itself is read from the events after `c` (the votes), which both
  replicas hold, and only grows: a later event never retracts a vote, an
  administrator excused from the vote (removed, demoted or marked dormant
  by a member senior to it or a recovery member, or by itself, or shown
  forked) stays excused whatever later merges decide,
  and votes are exclusive, so a second concurrent checkpoint can also take
  effect only with an electorate disjoint from the first's. The order of
  arrival therefore changes nothing: every verdict is a function of the
  events held. The chain in effect of a smaller view is a prefix of a
  larger one's, except where two such disjoint electorates both made
  their checkpoint stable, which takes the most senior administrator
  forked or excused by a recovery member on one side: there the smaller ID
  wins once both are held, so a chain moves only to a smaller ID, and a
  replica that holds every event has settled.
- **What the record must say.** Whatever the world after `c` reads must be
  in the record or after `c`, or a replica that forgot reads the world
  otherwise. So the record carries what the past decided that the roster
  alone does not show: an invite key's status (claimed, raced or used), so
  that a racer cannot claim again and is never wrapped for; a granted
  space's notices, names and floor, so that its principals, and what a
  device it admitted "from now on" may read, stay as the past left them;
  a guest's `expires_at`; an administrator's skeleton slot. Space entries
  read which key events are valid, which can depend on another log, so
  the checkpoint's validity leaves them out and the votes vouch for them.
  After `c`, every event is sealed under a state of the world and takes
  keys only from the world, so no verdict needs a key or a record from
  before it.
- **What is given up.** Work concurrent with a checkpoint: an offline
  device's units are refused and re-submitted; an administrator's
  concurrent roster events are void and re-signed or listed; a removed
  administrator loses the backdated duel before the cut. A replica that
  forgot cannot judge a concurrent checkpoint by a disjoint electorate;
  it holds both pending until it fetches history from a replica that kept
  it, or starts again from a snapshot.
- **What an attacker gains or loses.** A removed administrator loses its
  reach before each checkpoint. One malicious administrator can propose
  but not impose a record on the others' past: without every vote its
  checkpoint is a roster event that changes nothing. If it signs, on
  its view from before its removal, removals of every other administrator
  and a checkpoint over that branch, every administrator senior to it that
  it removed is heard by that checkpoint and waits for its own vote, which
  it refuses: a junior gains nothing. The most senior administrator's
  device is the exception: every member it removes is junior to it, and
  its branch's checkpoint takes effect ([roster.md](roster.md), section 4,
  "A backdated checkpoint"). Seniority is used because it is the one order
  every branch agrees on without a quorum: a rule that needs more than
  half of the predecessor's administrators would close the exception too,
  but stops checkpoints for good once half of them are gone. A malicious peer can withhold votes, which delays effect
  as withholding delays anything; it cannot make a replica forget, since
  forgetting follows effect in the replica's own view. A peer that
  truncates early loses only its own copy. All administrators together can
  certify any record, as they could already rewrite the roster.
- **Why not a timeout.** Time never decides validity. An administrator that
  never returns is removed, or was granted `frasil.dormant`.
- **Why a hold that freezes.** A later rule that changes how concurrent
  events are judged must stop older replicas where all agree, not merely
  hold what follows it. A roster part type from 3 does that.

## 3. Keys across branches

### 3.1 A graph of states, not epochs

Under a branching roster, two administrators may rotate concurrently, and
neither key is newer. Picking one rotation as the winner needs an orderer,
or a rule a backdating administrator can steer. Frasil keeps every valid
rotation: the current state is the set of maximal valid rotations, and its
key derives from theirs, alike at every replica.

A merge passes each input through HMAC under the input's own key before
HKDF combines them. Each input is a uniformly random PRF key, so one input
an outsider lacks makes the merged key unpredictable. A merge binds the
space ID and the set, because it combines secrets that exist apart. A state
is always derived from its rotations, so a device that merged A and B and
then meets C derives the key a device that met all three at once derives.

### 3.2 Heals

A merged key falls to whoever holds every input: one removed member that
held both branches, or several pooling theirs. So any writer heals with a
fresh rotation when the devices outside the roster could together derive
the current key, or when no device inside can. Replicas holding different
wraps may disagree; the cost is an extra heal, which merges like any
rotation. A heal needs only `write`, because waiting for an administrator
would leave the merged key exposed as long as administrators are away. A
guest heals only the content key, which is all it holds.

### 3.3 Links follow entitlement

A link seals an earlier key under a later one and opens for every holder of
the later key, forever. So a link hangs only where every possible holder is
entitled to what it reaches. Elsewhere the earlier key is a gap key,
wrapped device by device.

- **Void breaks count as holders.** A void admission "from now on" can
  become valid at a later merge. Counting it from the start costs a wrap
  per entitled device, never secrecy.
- **"From now on" is a break,** a rotation with no link back. Linking
  everything, as a simple key chain does, would let such a newcomer reach
  history through a link under a merge.
- **Void rotations stay readable,** because honest writers sealed under
  them in good faith.

### 3.4 Restored members wait

A member restored by a voided removal receives the current key at once and
starts from a history-free snapshot, so it can work. The keys made while it
was out reach it only once the voiding is stable, or after
`gap_key_timeout`, so a later merge that revalidates the removal does not
leave it holding them.

### 3.5 Grant keys and space wraps

When a space grants another, the granted space's members reach it. Wrapping
every rotation to each of those devices would make a removal cost the size
of every inheriting team. Instead each space has a grant key, held by
members that propagate, and a granting space seals its keys once to it.
Removing one device from a team of 90 devices granted into 40 projects then
costs 89 wraps for the team and one space wrap per project, where wrapping
each team device in every project would add 3,560 wraps, about 4.4 MB.

- **The grant key is an X-Wing key pair,** so a member of the granting
  space outside the granted space can still seal to it, and so rotate.
- **Commitments are hashes,** and other rotations publish 32 random bytes
  in their place, so a peer cannot tell grant rotations or breaks apart.
- **Notices are checked.** A notice is the one place a member hands others
  a key to seal to, and a planted one would have every later rotation seal
  the whole bundle to its author. So it names one rotation, whose
  commitment checks the key and the break; its author must propagate in the
  granted space; and it must cover every rotation this space has responded
  to, so nobody brings back an older principal.
- **A notice decides no verdict.** Its checks read the granted space's log,
  which a member of the granting space need not hold or be able to fetch,
  and which keeps changing. Were a failed check to void the carrying event,
  two members holding the same events would judge it differently, or one
  would wait for that log forever. So a notice that fails, or that a
  replica cannot check, only admits no principal there, and nothing is
  sealed to it. Replicas may then seal to different principals, which costs
  at most an extra heal; they never differ on a verdict. The one notice
  rule an event's validity keeps, that a key event citing a granted space
  carries a notice for it, reads only the event and the roster.
- **A principal's entitlement is the intersection over its devices,**
  since a space wrap opens for all of them.
- **Cascades.** Each candidate waits a delay set by a hash rank per
  trigger, counted from its own first sight, so usually one rotates, no
  device waits for another, and an offline candidate costs only its delay.
  Until the cascade rotates, a device that knows of the change writes
  nothing there. A response that only delivers leaves an outside holder,
  so the heal test fires: one candidate cannot suppress a cascade.
- **No grant key per level.** A reader reached through a write grant holds
  the upload seed and can spend quota, though its units are refused.
  Closing that would multiply every rotation's keys and wraps.

### 3.6 Bundles, wraps and body keys

- **Every bundle is 97 bytes,** with zeroed slots, so every wrap is 1,236
  bytes and a peer cannot tell a recipient's level or whether it
  propagates.
- **Wraps name no recipient.** A device tries only deliveries that name a
  state it lacks, and stops at the first wrap that opens: at most 768
  decapsulations per event.
- **The author wraps for itself,** so a device restored from an older
  backup recovers its rotations' secrets from the log.
- **A direct grant's X-Wing key overrides the list's.** The grant is this
  log's own record; a list may be held at different heads.
- **Wraps and links carry no signature.** They travel inside scheme-2 space
  events by the wrapper, and every rotation commits to its secrets.
- **A space event names the state its body key derives from.** Trial
  decryption over every state held would let replicas with different
  candidates disagree on what opened.
- **The body key is per event,** so a newcomer can be handed exactly the
  keys of the space events it must judge, and nothing more.
- **The body key has a commitment,** because XChaCha20-Poly1305 does not
  commit to its key: an author could otherwise make a sealed part that
  opens differently under different keys.
- **A removed device is handed its removal's body key.** A removal rotates,
  and the removed device never receives `k_R`, so without help it would
  hold the event that removes it `Sealed`, keep resolving a roster with
  itself in it, and never learn that it lost access. A removal wrap in the
  rotation's own delivery gives it that one body key. The sealed part holds
  the roster change, which the device is owed, and links it cannot follow.
  The wrap has the size and place of a bundle wrap, so a peer sees no new
  field and no change in wrap count: a visible marker of removals would
  tell the peer what the shared body shape hides. A label of its own keeps
  it apart from bundle wraps without a new bundle flag. The device judges
  its removal provisionally, which is all it needs: no later key reaches
  it to confirm the verdict, and an author that lies there misleads only
  the device it removed.
- **A provisional key holds, never voids.** A key received whole cannot be
  checked against a commitment, so a mismatch under it holds the event.
  Only a key derived from checked inputs finds `BadSeal`, alike everywhere.

### 3.7 Object keys, sealed names and collapses

- **Object IDs and nonces derive from the object's own state.** Equal files
  dedupe only within a state; in exchange, a holder of old keys cannot test
  whether a known file is stored under a later state. A unit may reference
  an object under any earlier state, so a rotation forces no re-upload.
- **Sealed names fill 64-byte buckets** and open strictly, with one failure
  class after decryption. A rotation never seals a name again, which would
  make its cost grow with the number of documents.
- **Collapse above 8, limit 64.** A unit names its state by rotation IDs,
  32 bytes each, so a writer collapses a state of more than 8 and none
  exceeds 64, which keeps references small and bounds what a reader waits
  for.

- **An application kind lives in the descriptor.** An application that
  keeps many spaces needs to tell them apart before it reads any stream,
  and every implementation must agree where that tag lives, or each
  application invents a reserved table. The descriptor is already in the
  genesis's sealed roster part: members read it, a peer does not, and it
  never changes, so the kind is fixed at creation and needs no write rule.
  The protocol reads only its shape.

## 4. What a peer sees, and why

A peer reads no content, names, levels, capabilities, labels, adapter types
or roster changes, and corrupts nothing. [overview.md](overview.md),
section 4.4, lists what it does see; here are the reasons.

1. **Sizes and wrap counts.** A device grant carries keys; a removal or a
   heal does not. Padding every event to the largest size
   would multiply storage and traffic; padding is offered, not required.
2. **Which devices write,** with sequences and causal links, so that a peer
   that reads nothing can sync and tell what another party lacks.
3. **Stream IDs and activity,** so that a peer can cap, list, release and
   serve one document. Sealed stream IDs would make opening one document
   fetch the whole space. They are random, never derived from names, and an
   application may map many documents to one stream.
4. **Which objects units reference,** so that a peer collects the rest.
5. **The administrator skeleton,** so that a peer refuses erasures from
   non-administrators without reading the roster (section 1.3).
6. **Membership history to newcomers.** A newcomer "from now on" must judge
   the roster it joins and the writers it will see. A roster summary signed
   by the sender would make the sender an authority over that view.
7. **Old states to former members,** because a member that missed
   rotations must still connect. Accepting only states after every known
   removal would refuse every member behind such a removal.
8. **Recovery entries,** so that a device holding only a passkey or a
   recovery sheet can fetch its personal space.

Other choices keep this list short. Roster events and key events share one
kind and one layout. The key reference is visible, so replicas agree on
what opened, but it names only rotation IDs a peer sees anyway. A stream ID
commits to its sealed adapter type, so a peer never learns the
application, and no writer can backdate a unit of another type into the
stream. The system stream's ID is random and sealed, since a derived one
would leak when lists change. A device presents credentials to a peer,
never its identity, and administration connections carry no account.
Endpoint keys are never identity keys and rotate daily and per network,
and local-network announcements are sealed, fixed in length and freshly
encrypted.

## 5. Identity and recovery

### 5.1 A person is a device list

A person is the keys of one device list, signed by its own list members.
No server adds or revokes one. A list merges by the roster's procedure,
with ranks where the roster has levels.

- **Possession proofs bind the person ID.** Members of shared spaces learn
  each other's keys; without the binding anyone could start a list naming
  someone else's device. A copied proof is over another person ID.
- **Possession proofs bind the adder.** A list member takes the most rooted
  of its adds, so that rootedness fails closed. Were a proof good for any
  adder, a recovery agent or a passkey holder could sign again, on its own
  chain, the `add` of a device or recovery key added after it was named,
  and root it in itself. Naming the adder lets only list members the key
  chose add it. The adder is named by its device ID, as the list names
  every member; the `add`'s place on the adder's chain is not bound, since
  the new key does not know it when it signs, and a key is added once
  anyway.
- **A list `add` keeps its proof though the device ID commits to the
  keys.** The ID binds the keys to each other, never to a person: without
  the proof, any list could name a device ID its author has seen, and that
  device would write through the person's grants and receive their
  wraps.
- **Within a rank, a mutual revocation revokes both.** Seniority would let
  a thief holding the person's older device beat the newer one. With both
  revoked, the thief keeps nothing and the person keeps what ranks higher.
- **A dead list stays dead.** Restoring either side of the last duel might
  hand the list to a thief; the person returns socially instead.
- **A recovery key that is not rooted outranks every other list member,**
  and receives wraps, so a space nobody else reaches survives a recovery by sheet. Two
  recovery keys share a rank, so a stolen old sheet never wins.
- **A passkey member is rooted** until a device that is not rooted confirms
  it. A synced passkey lives outside the person's devices, so neither it
  nor anything it brings in can revoke a recovery key, and the sheet or a
  device not rooted can always revoke it. Rootedness fails closed.

### 5.2 Recovery and verification

- **Fetch keys.** A device holding only a passkey or a recovery sheet has no
  read credential. A fetch key from the same secret, registered as a
  recovery entry, gives it catch-up, whose space events hold its wraps. It
  is unlinkable to the list member's keys and device ID, and to other
  spaces.
  Serving catch-up to anyone who knows a space ID was rejected, since space
  IDs travel widely. A writer can add entries but never remove one.
- **A recovery agent's waiting period gates wraps, never validity,** or
  replicas with different clocks would merge differently. No witness ends
  the wait: one colluding member could end every verifier's wait.
- **A device rooted in an agent signs no key event** until confirmed. A key
  event chooses a key, and a device inside the roster triggers no heal; a
  unit chooses no key, so its units are accepted.
- **Fingerprints are 120 bits,** about 2^90 work per success against 2^30
  targets. **Pins** let a client notice a list rolled back.

## 6. Admission

### 6.1 A mutual code

Admission rests on a six-digit code both screens show. The joiner commits
to its fields and a secret nonce before the approver answers, then
reveals: the commit-then-reveal of ZRTP (RFC 6189, section 4.4.1.1) and of
Matrix's SAS verification (`m.sas.v1`).

- **One guess.** Whichever side a relay completes first, the other side's
  code depends on a value the relay did not know when it chose. A match by
  chance has probability 10^-6, and every other attempt shows as a
  mismatch, so six digits are enough; ZRTP's strings are 16 or 20 bits.
- **The nonce enters the code hash,** not only the commitment, which is
  public once sent: otherwise a relay could predict the joiner's code
  before choosing what to send it.
- **The code covers every key directly,** through the joiner's device ID
  in the transcript, so no second round of MACs is needed, as Matrix needs
  one. The device ID commits to the three keys as a separate digest would,
  and is the very value the grant or `add` then names, so one value serves
  both.
- **The code is mutual.** It pins the space, its heads and the approver for
  the joiner; a one-sided code would let a relay hand the newcomer a space
  of its choice. The channel enters it too, so a relay joining two
  channels changes both codes.
- **Messages are sealed** to fresh X-Wing keys though the code needs no
  secrecy, because offers and lists are nobody else's. A person joiner
  sends its list only after the person confirms.
- **Exchange mailboxes** need no account, live in memory and are
  rate-limited per source, so any always-on peer can relay an exchange.
- **900 seconds with 60 of skew, and an advisory Cancel.** A binding Cancel
  would add a round; a joiner that cancels forgets the request and never
  accepts a grant that follows.

### 6.2 Other routes

- **Setup** of a headless device: the scanned device ID authenticates the
  device's keys, and a MAC the administrator and the connection. The first
  valid Offer binds the device until reset.
- **Lookups** are allowed, unverified and never the default: they trust the
  account's server at first contact, where a code costs a moment. A device
  answers a prompt only from a co-member, who already reads its list.
- **`replace` needs a compared code,** since it removes one person and
  grants another. `via` is never checked; nothing can verify it.
- **Top-ups wait a rank delay,** so usually one writer hands a newcomer the
  body keys it lacks. **Access requests are targeted,** never broadcast.

## 7. Sync and data

### 7.1 Units and sync

A unit's writer, `seq`, links, stream, key reference, objects and
compaction declaration are visible, and the rest is sealed: the least a
peer needs to store, index and serve units it cannot read.

- **Sync is by per-writer sequence and heads,** which any peer runs without
  content. Version vectors belong to adapters, between members. A server
  cursor would need one server, and a restore would reset every reader.
- **Acknowledgements name what was stored,** and different bytes at a used
  position are never acknowledged. They decide nothing, so they carry no
  signature. A peer that acknowledges and then loses an event is caught by
  every device that remembers the acknowledgement; a restored peer resets
  nothing, because it numbered nothing.
- **Head statements** let members notice forks and rollbacks before their
  replicas meet. They name a device, so they never reach a peer in the
  clear, and head gossip tells members nothing they could not read.
- **Validity reads only the unit, its causal past and the keys held.**
  `stream_prev`, the cited place and compaction claims never decide it, so
  full and partial replicas agree. A partial replica that cannot prove a
  unit's order holds it pending.

### 7.2 Compaction and objects

- **Compaction is non-destructive.** A snapshot unit declares, per writer,
  which units it replaces: a version vector without content. Each party
  collects from its own storage once the snapshot settles, stable or held
  for `gap_key_timeout`. A peer waits for stability or T, because replicas
  refuse a snapshot whose writer was removed concurrently.
- **Stubs come only from signed sources,** never stand for space events,
  and under a space event need two signers, so one lying sender cannot
  reorder the space events a newcomer judges.
- **A locator carries a digest,** so junk uploaded first under a genuine
  object ID is another locator, never named.
- **Chunks are fixed in size, with synthetic nonces,** so an object has one
  stored form, dedupes within its state, and uploads resume.
- **Members say what they hold as it changes.** A device drops blobs and
  its cache evicts them, so what a member announced when the connection
  started goes stale both ways. An object that becomes whole is announced
  at once, gathered with others, and a member asked for what it no longer
  holds says so in `ObjectMissing`. Silence could not say it: it reads the
  same as a slow answer or chunks past the end, and only a long wait tells
  them apart. Nor could `ObjectHave` with a count of 0, which a receiver
  reads as an announcement and would ask for again. `ObjectMissing` is of
  an ignorable type, so a receiver that does not know type 64 drops it and
  waits as it waits for any silence, and no new protocol is needed
  (overview.md, section 5.6). The withdrawal is an answer, not a
  broadcast: a member that drops ten thousand cached objects sends nothing
  until someone asks, and announces nothing either.
- **Falling behind costs one announcement per interval.** A side that
  cannot tell which objects became whole announces all it holds again, and
  does so at most once per `reannounce_interval`: a member that serves
  many small objects quickly cannot make another send its whole inventory
  over and over.
- **A flooded bound widens the sources instead of losing them.** Past the
  bound on unknown announcements, a side asks the member for any object it
  comes to know. A member gains nothing by forcing that: it could announce
  every object of the space anyway, and be asked for each. The cost is one
  `ObjectWant` per object the member lacks, answered by `ObjectMissing`;
  the side looks no further at what its replica knows on that attach, so a
  flood of announcements costs it no repeated work.

### 7.3 Adapters

- **Adapters are pure.** A capability check never reads stream state, so
  every replica reaches the same verdict; adapters that disagree show
  different documents, never different validity.
- **Records reads no wall clock,** which would let a writer win every
  conflict by setting its clock ahead. A logical clock counts only when
  existing changesets support it, so nobody freezes a cell.
- **Records runs no constraints.** Two concurrent changesets can each keep
  a constraint and together break it, and refusing one would need an
  order. Data only its writer may edit belongs in a space per person.
- **Loro peer IDs are bound** to the writer, the stream and the
  incarnation, so no writer writes under another's name, and a restored
  device starts a new incarnation rather than reuse counters.
- **Accept wins over dismiss,** whatever the order, so concurrent review
  never loses a change someone accepted.
- **A Records change carries its writer's time, untrusted.** Applications
  show when another member last changed a row. The logical clock orders
  writes and cannot say when; a peer's receipt time says when the peer
  heard, not when the writer wrote, and a peer reads no content. So the
  writer states its own wall clock, and the text calls it a claim: it
  decides nothing, so a wrong or hostile clock misleads only the screen.
  The snapshot keeps each cell's time, or a replica that starts from a
  snapshot would show none.
- **Records cells carry integers, floats and booleans natively.** Every
  application that keeps numbers or flags in a table would otherwise invent
  an encoding, and two applications sharing a table would disagree. Only a
  cell's value takes the wider subset, so every structure the protocol reads
  keeps the narrow one. Floats are always 8 bytes rather than CBOR's
  shortest form, so an implementation needs no half-precision conversion to
  find the one encoding, and NaN is refused because it has many bit
  patterns and compares unequal to itself.

### 7.4 Transports and storage at rest

- **A handshake proves a state both ends share,** not the newest key: a
  graph has none, and a member that is behind must still connect. An offer
  carries 16 tags, real or random, so it tells a non-member nothing. The
  proof is not membership; only the roster check against the verifier's
  view admits a device, and it runs again whenever that view changes.
- **One ALPN per connection kind** fixes a connection's purpose before its
  first message. **Tickets grant nothing:** a ticket that carried rights
  would be a bearer secret wherever it was pasted.
- **Nearby pairing** binds the admission code to the TLS exporter
  (RFC 9266), so a relay on the local network changes both codes.
- **Pairing travels as far as members do.** A pairing endpoint binds on
  the member endpoint's networks and relays. A pairing endpoint on
  loopback or with no relay would let two devices pair only on one
  network, while the member handshake that follows works across the
  internet; the code comparison, not the network, keeps a stranger out.
  The nearby ticket is the invitation: it names an endpoint key that
  rotates, the addresses the host listens on, and its relays, never the
  space, so whoever reads it learns where the host is for a day, and
  nothing else.
- **No default relay.** A relay sees which endpoint keys talk, when and
  how much. Which operator may see that is a choice for the application
  or the person running a peer, so the protocol names no relay: a device
  uses the relays its application names, or else those of the first peer
  it connects to, or none.
- **A relay is not a mailbox.** With no always-on peer, changes move only
  while both devices are connected. Keeping changes for a device that is
  away is an always-on peer's job, and making relays keep them would make
  every relay a peer.
- **At rest, records are sealed under the device, not the space,** so no
  IDs show and old space keys open nothing. One key per log makes
  forgetting a space one deletion.
- **A restored device does not fork.** The tips live in the store's head,
  and a mark of the head's generation lives in a device-bound slot that no
  backup restores. A restored head is older than the mark, so the device
  syncs before it signs; without such a slot, every start is a restore.
- **Secrets stay apart.** A kind 2 unlock key comes from the
  application and may serve elsewhere, so the sealing key is derived from
  it; the store secret is drawn on its own, not from the identity seed.

## 8. Post-quantum choices

- **Every wrap is X-Wing** (draft-connolly-cfrg-xwing-kem, with FIPS 203's
  ML-KEM-768) in HPKE (RFC 9180), confidential while either ML-KEM-768 or
  X25519 holds. Frasil defines no combiner of its own: X-Wing's is part of
  its security proof, and a hand-made `KDF(K1 || K2)` does not preserve
  IND-CCA security in general. There is no classical fallback.
- **Authority needs both signatures.** Scheme 2 is Ed25519 (RFC 8032) and
  ML-DSA-65 (FIPS 204) over the same bytes, both required. ML-DSA-65 alone
  would rest on one young algorithm; Ed25519 alone falls to a quantum
  adversary. Nothing is derived from the two, so no combiner is needed.
- **The Ed25519 half is checked first,** with the author's key alone, so a
  stranger's forgery is refused before a replica looks anything up. Each
  half has its own label, so neither reads as the other or as scheme 0.
- **A device's name commits to all of its keys.** Hybrid signatures defend
  only if the ML-DSA-65 key a verifier uses is the device's. Were a device
  named by its Ed25519 key, with its ML-DSA-65 key taken from records that
  the Ed25519 key signs, an adversary that forges Ed25519 could write such
  a record itself, in any body that replicas open, and then sign authority
  events in full as the device. The device ID hashes the Ed25519 key with a
  commitment to the other keys, so no record can name another key for it,
  and a verifier may take the keys from anywhere, a void event or another
  member's list included, and check them by their hash. Signature validity
  then depends on the event alone, never on the roster's resolution.
- **The envelope keeps the Ed25519 key,** beside the 32-byte commitment,
  rather than carrying only the device ID. A peer checks the Ed25519 half
  of every event it stores with no lookup, and a peer reads no record. With
  only the ID in the envelope, a peer could check nothing, and strangers
  could store conflicts at any device's `seq`. The cost is about 35 bytes
  per event.
- **A commitment, not the keys.** Carrying the ML-DSA-65 and X-Wing keys in
  every envelope would add about 3.2 KB to every event, fifty times a
  scheme-0 unit's signature. A 64-byte name, the Ed25519 key and the
  commitment side by side, would double every member reference and change
  the width of every structure that names a device. A 32-byte hash of the
  two keeps every name the size it was.
- **All three keys, the X-Wing key included.** A commitment to the
  signing keys alone would leave the X-Wing key to records, and two records
  that named two X-Wing keys for one device would again need a rule to pick
  one, and give whoever writes a record a way to steer the device's wraps.
  Committing to it too makes every key of a device a function of its name.
- **Taking the key from the record of standing** instead, the grant or
  `add` on the path that gives the author its standing, would also close
  the gap, but makes a signature's validity depend on the roster's
  resolution, which itself depends on signatures, and on which logs a
  replica holds.
- **Units stay classical until the sunset.** A forged unit does not open
  from outside the space, and units are many and small: 3,309 more bytes
  each would multiply a small edit's size. The sunset is a future protocol
  revision made before Ed25519 stops being trusted, never a date a device
  compares with its clock; NIST IR 8547 plans to disallow
  quantum-vulnerable signatures by 2035. One revision for every space, with
  no early opt-in, avoids a mixed state.
- **Anchors** cover units by hash under scheme 2, so a space that falls
  quiet before the sunset can still be verified after it. Anchoring
  authority events instead of signing them hybrid would accept a forged
  branch until an anchor excluded it.
- **What stays scheme 0 is verified once, at once:** handshakes, credential
  proofs, head statements, ephemeral frames, tickets and device-signed
  requests. A later forgery of them is never verified.
- **Keys are checked once, where they enter,** and compared by bytes.
  Lenient decoders and cofactored verification disagree on small-order and
  mixed-order Ed25519 keys, and verifiers that disagree on a key diverge on
  every event it signs.

## 9. Time

Time decides what a device does next, never whether an event is valid: no
validity check reads a clock, and no verdict rests on a time that a signed
event holds. Times that signed data does hold, a grant's `expires_at`, an
exchanged instant or a writer's time in content, decide only a party's own
next act or the screen ([overview.md](overview.md), section 6.1).

- **Signed timestamps** were rejected: the signer is the party a delay
  guards against. **A peer's clock or a trusted time service** would be an
  authority. A source such as Roughtime could later feed a device's own
  estimate without a format change.
- **First sight.** A timed rule counts from the deciding device's own first
  sight. Devices then act at different moments, but each act is its own,
  so merged state does not diverge.
- **Two estimates.** A rule that waits uses the lower estimate and a rule
  that stops the upper one, so a wrong wall clock errs the unsafe way only
  if it was moved while the device was off.
- **Policy values are checked against ranges,** never a clock, and
  concurrent policies merge to the stricter value, so concurrency never
  loosens a space.
- **Five instants cross between parties,** each compared only by its
  receiver, for its own next act.

## 10. Extensions

The core is what every replica needs to agree on validity. The core
reserves each extension's hooks, and a core implementation holds what it
cannot interpret as `ExtensionRequired`, so it never reaches a verdict
another replica would contradict.

- **Invite links.** Two concurrent claims void each other, so a leaked
  link's holder cannot silently take the invitee's place, as "first claim
  wins" would allow.
- **A claim keeps its secret.** An administrator that has not yet seen a
  successor still counts `K` as inside, so a rotation it signs then wraps
  for `K` alone. That rotation can reach the claimant at any time, and no
  member that later merges it sees the claimant as left out, so the
  claimant keeps `K`'s seed for as long as it holds the space. Keeping the
  secret exposes nothing a thief of the device's store lacks: the store
  already holds the claimant's own keys, and a claim after the close
  changes nothing.
- **A claim heals.** The claimant is not the only holder of the secret:
  whoever read the link and fetched the drop holds every state `K` holds,
  and signs nothing that would show it. So `K` counts as outside once a
  successor puts it out, and the heal test that serves removals rotates
  the space; the claimant, a member of its own, is wrapped for under its
  own keys. Any writer heals, so a claimant at `read`, a newcomer "from
  now on" and an inviter that is offline change nothing. A successor that
  rotated would need a claimant that writes and holds the grant state; a
  close that rotated would wait for an administering device, which the
  link exists to do without, and a roster event that removes no member in
  its place cannot be the grant rotation the grant graph needs. One heal
  per claimed invite shows a peer one more rotation beside a successor it
  could already guess. An invite admits once, so there is one heal per
  invite, and what a holder of the link reads is what was sealed while it
  was open, and in the heal's window.
- **Guests** are a preset of the device grant, so they need no new rule in
  the roster or key graph. A session ends many guests with one event and
  one rotation. A guest leaves by request, since it cannot sign a roster
  event and a leaver must not rotate. "Nothing at rest" binds only honest
  clients.
- **Restricted spaces.** The key is HKDF with the restricted space's secret
  as the extract salt and the parent's content key as input, so a parent's
  member outside it learns nothing, and a device removed from the parent
  loses the next key with the parent's: the restricted space never rotates
  for its parent. Its events and credentials derive from its own secrets,
  so a peer cannot link the two. No space grants it, which would widen it.
  A carve-out copies a document rather than share a key, so its cost grows
  with the document, and administration is mirrored into it, because
  `administer` never flows through a grant.
- **The ephemeral channel** carries live traffic that units would make slow
  and permanent. The signature sits inside the seal: every member holds the
  key, so without it any member could speak for another, and inside the
  seal a relay does not learn the sender. A counter window and receiver
  nonces stop replays without a clock.
- **Libraries** keep billing at a peer and out of the protocol. A ticket
  names no space, so its issuer does not learn one early; it attaches once
  and lives at most a day. Only a writer moves a space's billing, so a
  stranger cannot capture a space by its ID.
- **Deposit tokens.** A deposit charged to a space, a library or a key
  would tell the peer who writes to which device, and an anonymous deposit
  lets a stranger fill the peer. A blind token is counted when it is drawn
  and spent unlinkably, so the peer limits each library without learning
  who sends. The peer both issues and checks tokens, so a privately
  verifiable VOPRF (RFC 9497) suffices: smaller than a blind RSA signature
  (RFC 9474), proved per batch, cheap to rotate, and on the curve Frasil
  already uses. It is classical because a forged token is spam: it opens
  no mailbox and decides nothing a replica reads. A token names no
  recipient, so it is drawn ahead of need and issuance does not line up
  with the deposit. A writer of a space may draw against the space's
  library, so a sender always has standing at the peer that serves the
  space it admits someone to; the peer learns that the space's writers
  draw, never to whom they write.
- **Announced next endpoints.** A device names its next member endpoint
  key only inside member connections, so the members it already shares a
  space with can follow it across one rotation, and nobody else can link
  its keys. One key, not a schedule of them: dialing keys that are not yet
  in use would show a relay future keys in advance, and one rotation of
  each side already covers a session that pauses and resumes. Ending a
  membership replaces the key, so a former member cannot use it.
- **Device-signed requests** stop a token that also reached the operator's
  peer from serving without the device. Devices deliver their list to the
  verifier, since no server holds one in the clear. An HMAC would need a
  secret per verifier, RFC 9421 binds headers that proxies rewrite, and a
  hybrid signature buys nothing for a request verified within seconds.

## 11. Known limits

Frasil does not defend against the following. Each is the cost of a goal
above, and the document it concerns states it.

What Frasil rests on, as against what it does not defend, is on one page:
[assumptions.md](assumptions.md).

- **The backdated duel.** A removed administrator can sign a
  counter-removal of its remover onto history from before its removal. It
  cannot come back, even when its remover was raised after its last event,
  but its remover is out too, and the remover's roster events concurrent
  with the backdated one are void until a remaining administrator
  re-grants. The chain bounds its reach to what it saw after its own last
  signed event; one that stayed silent keeps its reach. An honest
  administrator that removes a writer while another raises it, and is
  removed by it, loses its seat the same way.
- **Dependence on the space recovery member.** Without one, duels can leave
  a space with no administrator.
- **Eventual removal,** for reads and across logs. A writer that has not
  heard of a removal seals for the removed member, and a device revoked in
  another log writes until a writer of the space responds.
- **The merge-key window.** What informed writers seal under a merged key
  before the heal is readable by outside holders that could derive it, for
  about one round trip and a rank delay.
- **A leaked invite link** reads what was sealed while its invite was
  open, and until the heal that follows the claim, in the same window
  (extension).
- **History only removed members held is lost.**
- **Forks caught late.** A replica accepts a forked device's events until
  it holds the evidence; a newcomer or a partial replica may wait longer.
- **Before the sunset,** a quantum adversary can forge a unit at a used
  `seq` and so void its device, and an insider holding a content key can
  forge a unit that opens.
- **Lingering credentials.** A removed member fetches ciphertext and spends
  quota until a credentials request is carried out. A connection it keeps
  open loses those rights then too, so the limit is when administrators
  end its credentials, not how long a connection lasts.
- **The projection gap.** A skeleton and roster that differ for longer than
  T let one request through, and an erasure after T executes at a peer
  that never heard of its requester's lowering.
- **Metadata and availability.** Sizes, timing and section 4's leaks; a
  peer can refuse service, partition members, and withhold what no client
  knows of yet.
- **Compromise.** A stolen device signs until revoked; a passkey's holder
  reads every space the person reaches; whoever controls an unlocked device
  reads what it holds; what a member or a hostile guest read, it keeps.
- **A full partition** of a person from every collaborator lets a
  compromised recovery agent finish its waiting period unseen.
- **Members with no peer lose each other.** Member endpoint keys rotate
  daily and at each new network, and no public name points at them. Two
  members with no always-on peer reach each other again at the tickets
  they kept until both have rotated, or, with
  [ext-next-endpoints.md](ext-next-endpoints.md), until both have rotated
  twice; after that, one of them needs a fresh invitation, or a peer, or
  another way to learn the other's endpoint.

## 12. Reusing an authenticated device for independent grants

A device ID commits to the device's Ed25519, X-Wing and ML-DSA-65 keys, and
names no space. Once an application has authenticated a device ID, through
an admission code, whose transcript commits to it, a person's list, whose
possession proof binds it to the person, or a roster it trusts, any direct
grant of that ID in a further space names the same keys, which every
replica checks by their hash. A grant needs no proof that the device holds
them: a device ID whose keys no single party holds signs nothing and opens
nothing, so granting the wrong ID gives nobody a power the granter lacks,
and what authenticates the device is how the application learned its ID.
Administrator authority remains local to each target roster; trusting a
device ID does not confer the sender's right to administer another
space.

The high-level batch API composes existing grants and device-mailbox
welcomes. It needs neither a multi-space admission transcript nor an
administrator grant to a person. Each target grant commits independently;
a failed welcome delivery can be retried by promoting an existing member or
redelivering its keys. The sender distinguishes commitment from delivery,
while the receiver checks each welcome against its resolved roster.
Applications supply the selected authenticated identities and expected space IDs.

A batch prepares all grants before waiting for durability and starts all
welcomed spaces fetching before waiting for verification. Sync connections
carry bounded groups of spaces to stay within presentation limits. A
complete, fully opened log of direct device membership, without external
references, cannot change because an unrelated log changed; omitting that
redundant resolution keeps a batch from repeating work across every pair
of independent spaces. Lists, units, guests, restricted parents, partial
bases, stubs and undecided events keep the full resolution path.

The same reasoning admits a direct device member of one space to another
with no peer at all (admission.md, "A member of another space"): the
granter reads the device ID and its keys from a roster it trusts, signs an
ordinary grant with `via` = `none`, since no code was compared for it, and
hands the welcome over the member connection the two devices already share.
The welcome comes only from its signer, as a person's grant's does, so a
member that merely carries it cannot point a device at a space of its
choosing. The signer keeps the welcome waiting at rest, in the commit that
holds the grant, because nothing else can stand in for it: a delivery's
wraps name no recipient, so not even their author can tell later which
wrap is whose, and a welcome made again would need a new delivery event in
the space for every device that never took the space up. Kept at rest, the
welcome reaches the device by whichever route comes first after any number
of restarts: the member connection, or a peer the device reaches and the
signer only reaches later. The record costs the signer the size of a
mailbox item, and nothing in it opens without the device's keys, to which
the welcome is sealed before it is kept. Its life is a peer's: after `mailbox_retention`'s
maximum no peer still holds a deposit of it, and a device that has not
taken the space up by then is admitted again. A peer keeps an item for
less in a mailbox its device has never collected (`uncollected_retention`,
72 hours by default), so the signer deposits again at each peer every
`welcome_redeposit`, 48 hours: a day under that default, which leaves room
for a deposit delayed by `busy` or `rate_limited` and its waits of up to an
hour, and for a connection to the peer that drops for a while. A second
copy is harmless to the newcomer, since a device keeps one welcome per
space, but not to its mailbox: once the newcomer has collected there, the
peer keeps each copy for `mailbox_retention`, up to 30 days, and a mailbox
holds at most 64 items, oldest evicted, so a deposit every two days for
the welcome's whole life would leave some fifteen copies at each peer and
push out what others sent. The signer cannot see the collection, which
the peer tells no depositor. So it deposits a welcome at one peer four
times at most, the first and three repeats, and keeps the count beside
the `T` in the record, so that a restart does not start it again. Four
deposits 48 hours apart keep a copy at a peer whose newcomer never
collects there for about 9 days, under the default
`uncollected_retention`; after that a member connection with the signer,
or a first deposit at another peer, still delivers it. A deposit a peer
refused for good counts too, and the peer stays in the record, and the
signer deposits at no peer past the 64 a record names, so that no peer
receives a welcome more than four times however often the signer
restarts. The trust is carried, not
shared: a later removal from the known space does not reach the grant,
which is therefore the application's to mirror.

The entry also ends when the signer sees the newcomer at work: an event
the newcomer's device signed, accepted in full, with the admitting event
in its past. Holding that event in its past means the device holds the
event, and with it the wrap the welcome carries, so the welcome has
nothing left to give it. An event without the admitting event in its past
ends nothing, so a device that the space granted before under another
grant, and that keeps writing from its old view, does not end the
welcome of its new grant. The signal costs the signer nothing it does not
already keep: a replica holds each author's chain by `seq`, and each
event names the one before it, so the latest event of the newcomer's
chain answers for all of them, and the walk back to the admitting event,
bounded below by that event's height, runs only when that latest event
changes. A peer could say more, that the newcomer collected its mailbox,
but it tells no depositor, and saying so would tell anyone who deposits
when a device comes online. A device that only reads may sign nothing in
the space; for it the count of four is the only bound on the copies at
each peer. The waiting welcomes are bounded at 4,096 per device: a
person's grant makes one per device of the person, so an administrator
who admits a few dozen people within `welcome_retention` would pass a
bound of a few hundred, and the oldest welcomes, still waiting, would go
without a word.

## References

- RFC 2104 (HMAC), RFC 5869 (HKDF), RFC 7748 (X25519), RFC 8032 (EdDSA),
  RFC 8439 and draft-irtf-cfrg-xchacha-03 (XChaCha20-Poly1305).
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), draft-connolly-cfrg-xwing-kem
  (X-Wing), RFC 9180 (HPKE), NIST IR 8547 (transition to post-quantum
  standards).
- RFC 8446 and RFC 9266 (TLS 1.3 and its channel binding), RFC 8949
  (CBOR), RFC 9421 (HTTP Message Signatures).
- RFC 9420 and RFC 9750 (MLS and its architecture). RFC 6189 (ZRTP).
  Matrix Client-Server API, "Short Authentication String (SAS)
  verification". Keybase's team and signature-chain design documents.
- K. Dougal, "ERA", arXiv 2601.22963. F. Jacob and H. Hartenstein, "ECAC",
  CODASPY 2025. p2panda-auth, access control with strong removal.
