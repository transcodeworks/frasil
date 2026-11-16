# Checkpoints: compacting a space's history, its device lists and its skeleton

A design note for checkpoints, which let every replica, newcomer and peer
forget the history before a point that every administrator agreed on. It
covers three logs that would otherwise grow for ever: a space's roster, each
person's device list, and the administrator skeleton a peer keeps. The
normative text is in the specification:

- [roster.md](../spec/roster.md), sections 2.2 "The roster part", 2.8 "The
  checkpoint record" (with "The record object"), 3.15 "Checkpoints" and
  3.16 "Rules this replica lacks";
- [events.md](../spec/events.md), section 3.11 "Cuts";
- [identity.md](../spec/identity.md), section 3.16 "List checkpoints";
- [peers.md](../spec/peers.md), sections 3.21 "Skeleton cuts" and 3.22
  "Truncation";
- [units.md](../spec/units.md), sections 2.10 "Stubs", 2.11 "The space
  snapshot" and 2.12 (the system snapshot state's key 5);
  [keys.md](../spec/keys.md), section 3.17 "Keys after a checkpoint";
  [rationale.md](../spec/rationale.md), section 2.10.

The reference code is `docs/spec/reference/checkpoints.py`,
`list_checkpoints.py` and `skeleton_cuts.py`. This note explains the design,
says what the model checks cover and what they do not, and lists what the
design gives up. For what an application sees, read the guide,
[Checkpoints](../checkpoints.md).

## 1. Why

Without checkpoints nothing is ever forgotten, and three bounds end a
long-lived space:

- A newcomer still fetches and judges every space event from the genesis
  on. Peers delete frame events only when they erase the whole space.
- Nothing is ever final: a removed administrator can sign a backdated
  counter-removal, and a fork at an old `seq` voids its author's old events.
- The roster stops after 4,095 valid roster events, a person's list after
  4,095 list events, and the skeleton after about 2,000 changes of who
  administers, each counted from the log's start.

## 2. The design in brief

### 2.1 Space checkpoints

1. **A checkpoint is a roster event** (roster part type 2) that names a
   **record**: the roster of its past (each member's state, rank,
   seniority, a device's and an invite key's keys, an administrator's slot,
   a guest's `expires_at`), each invite key's status, each granted space's
   notices, names and floor, the merged policy, each author's chain tip and
   the fork points.
2. **The record is an object**, in one form for every space: sealed and
   chunked like any object, under the checkpoint's own content key, its
   header naming the checkpoint by its self reference. The checkpoint binds
   it by locator, size (at most 256 MiB, about 80,000 device members) and
   digest. Its author uploads the object before signing; the skeleton cut
   names its locator so peers keep it; a newcomer gets its object key in the
   space snapshot.
3. **Without the object** a replica holds the checkpoint as `Sealed`, with
   every event after it, and judges the rest as if it had not received them,
   exactly as for a space event it cannot open. When the object arrives, it
   judges again. An object that opens but does not match the digest voids
   the checkpoint (`BadCheckpoint`): the locator binds that very object.
4. **It is judged on its own past alone**: its author must be an
   administrator there, its signature must verify under keys of that past,
   and its record must equal, byte for byte, the one a replica derives from
   that past, granted spaces' entries aside: those read key events'
   validity, which can read another log, so the votes vouch for them.
5. **It takes effect when every administrator of its record has voted**,
   and every member it **hears** (see 2.4), by any event after it whose cuts
   reach no concurrent checkpoint. Administrators marked `frasil.dormant`
   are not waited for, nor those excused after it. Excuses only accumulate,
   so effect never shrinks. A client reports whom a pending checkpoint waits
   for, and never votes for a checkpoint that hears it.
6. **Each event declares in its envelope the checkpoints it follows**
   (`cuts`), checked against its parents', so any party sorts an event as
   before, after or concurrent without its past.
7. **Once in effect**, concurrent events are late (void; late units are
   refused and re-submitted), and events after it are judged by the same
   resolution procedure over a log rooted at the checkpoint, the record
   standing for the founder. The 4,096 bound counts from it. Every event
   after it is sealed under a state of its world (else `StaleSeal`, read
   from the visible part) and takes its authors' keys only from the world,
   so no verdict after it needs anything from before it.
8. **A hold for later rules**: a roster part type from 3 stops a replica
   that lacks the rule at that event's past.

### 2.2 Device-list checkpoints

A person's list gets the same rules, read for a list:

- **The event** is a list event with action 3, whose body carries a small
  inline record: for each active list member the event ID of its add, its
  root, its recovery agent, whether it is confirmed, its seniority and, for
  a member rooted in a recovery agent, the add that rooted it; the active
  members' chain tips; the fork points. At the widest encodings it fits a
  list event's 16 KiB for at least 70 active members, or 51 when every one
  is rooted in a recovery agent, because a member's keys stay in its own
  add.
- **Following** is declared in the body (key 8, `follows`), checked against
  the parents' as envelope cuts are. Device-list events never carry
  envelope cuts.
- **Who signs**: an active device or recovery key that is not rooted in a
  passkey or a recovery agent, or a confirmed one; its signature is checked
  under the adds of the checkpoint's past. **Effect**: every such device of
  the record votes by any list event after it; a device with nothing to
  sign signs an `ack` (action 4). A confirmed device both signs and is
  waited for. Recovery keys, passkey members, recovery agents and
  unconfirmed devices rooted in them are not waited for. A device revoked
  in the checkpoint's past only by devices it outranks is heard (record key
  7) and waited for too. A device is excused for good by evidence of its
  fork, by its own revocation, or by a revocation after the checkpoint by a
  record device that outranks it or a recovery key.
- **Late** list events are void; clients re-sign late revocations and list
  late adds and confirms for the person.
- **Forgetting** keeps the list's first event (the person ID is its hash),
  the checkpoint, the adds and rooting adds its record names, the list
  checkpoints its `follows` reach and the late events (each as events
  alone), what follows, and the IDs of what it forgot, which sealed copies
  carry; the 4,096 bound counts from the checkpoint. In the world, only the
  record's and the world's adds supply keys. A device proposes a list
  checkpoint at 1,024 valid list events since the last.
- **Spaces** read a list as they hold it. A list checkpoint in effect ends
  at once, in every space, the path of every device it does not list, as if
  each space had responded to its revocation, for its events before the
  checkpoint as after it: an `add` before the checkpoint names only a
  device the record lists.

### 2.3 Skeleton cuts

- **A space checkpoint names a twin, its cut**: a skeleton event (storage
  type 7) its author's pseudonym signs first. The cut carries every
  administrator slot in at that point (its keys, rank, seniority and the
  event ID of the root or enrolment of its pseudonym, which every holder
  keeps), the record's locator and an epoch. A slot entry is at most 229
  bytes and a standing entry 115, so 512 enrolled slots with 1,024
  standing entries fit in at most 208,390 bytes of body and 220,777 of
  signed event, about 16 % inside a storage event's 262,144; 513 slots,
  or 1,025 standing entries, are `Malformed`. Every administrator votes
  for each checkpoint, or is excused: at 512 that is 512 devices a
  checkpoint waits for. `ErasureLate` names the checkpoint by ID, so it
  holds the envelope of any cut within its cap.
- **A peer checks** that a stored space event names the cut, that its author
  is enrolled in a slot that is in, and that its slots are exactly those of
  the merged skeleton of its past (`BadCut`). A cut of the wrong epoch, or
  made before a cut its checkpoint follows took effect, is `CutPending`.
- **In effect at the peer** once every slot of the checkpoint's electorate
  has voted, by a skeleton event of its pseudonym that follows the cut's
  checkpoint and no concurrent one, or is excused. The cut carries a
  standing entry for each administrator's slot and each heard member's,
  with its order (rank, then seniority, as the record gives them) and
  whether it is dormant or a recovery member; replicas check them against
  the record, so a peer waits for the same members as replicas and excuses
  a slot as they excuse its device: lowered after the checkpoint by itself,
  by a slot that outranks it, or by a recovery slot. Votes and excuses only
  accumulate, so a cut in effect stays in effect as events arrive; a
  lowering no roster event made can put the peer ahead of replicas only on
  its outranking signer's own event. A change that only
  marks a member dormant has no twin and excuses it at replicas alone.
  The skeleton then starts afresh from the cut: its slots are in, enrolled,
  and keep their references, rank and seniority; stability, the
  planted-slot count and the 4,096 bound count from it. Credential entries
  are kept, so a member offline across the cut still catches up.
- **Late skeleton events**, those concurrent with the cut in effect, are
  stored with no effect rather than refused, so that whatever cites them,
  a device's vote among them, is placed. An enrolment concurrent with a
  checkpoint is late once it takes effect: the device enrols the same slot
  again after the checkpoint, under a new pseudonym whose binding is sealed
  under the checkpoint's twin secret, which every replica holds, and
  re-signs what its late pseudonym twinned as other late work.
- **Requests of the cut's past** keep their place in the skeleton before
  the cut; every event after the cut holds that past, so the votes that put
  the cut in effect acknowledge them, and a slot of the cut also
  acknowledges through the pseudonym enrolled in it after the cut. A device
  that forgot acknowledges them as any other, and what still waits ends at
  the erasure timeout.
- **Truncation**: after `cut_retention` (30 days), and once every erasure
  and credentials request in the checkpoint's past is carried out or void,
  the peer may delete the rest of the checkpoint's past, but keeps the
  genesis, the envelopes of the checkpoints its cuts reach, the roots and
  enrolments the cut names, the maximal releases and restores of each
  stream (concurrent with each other, so no order among them is needed),
  every restore naming a snapshot unit, every unit (units leave a peer only
  by collection), the late events, the checkpoint, its cut and its record
  object. Every kept request is before everything after the checkpoint,
  and a release or restore late under any checkpoint of the chain counts
  for nothing, at a peer that truncated and one that did not alike. An event it deleted that arrives again is acknowledged and
  not stored.
- **Nothing irreversible while a cut is undecided.** A peer carries out no
  erasure or credentials request, and reclaims no release, concurrent with
  a valid cut that can still take effect; once the cut takes effect the
  request is late, void at the peer and at replicas alike, and its author
  signs it again after the checkpoint. Administrators vote for a checkpoint
  only once each peer has acknowledged its cut, so a cut that reaches a
  peer after it erased the space never takes effect anywhere.
- **An erasure is never left undone unreported.** The device that asked
  keeps a residue (the log key, its pseudonyms, its tips and the erasure)
  until each peer it reaches answers `erased`. Past `erasure_timeout` from
  the erasure's first sight, which the residue keeps, it tells the
  application which peers have not. A checkpoint that makes the erasure
  late, served after the drop, cannot be answered from the residue, since
  signing after it needs the checkpoint judged. The peer tells the
  residue in so many words (`ErasureLate`: the cut in effect, its
  checkpoint and the slot's standing there), which the residue can check
  only for consistency; on that word alone it reports, asks the
  administering devices it kept for a welcome, fetches the space again as
  a replica that lost its store, and erases it again, or reports that it
  can no longer erase it when the cut leaves its slot out.
- **Content of the forgotten past.** A replica that forgets freezes, for
  each unit of the past it keeps, its verdict and its author's capabilities
  at its place, and hands it to its adapter with those: every adapter is a
  function of content and context, so it shows what a replica that kept
  everything shows, whatever became of the author before the checkpoint.
  It freezes the unit's attribution too, the members it was written
  through with their labels there, since every replica shows the labels a
  unit's author had at it, never the current ones; a unit the write rule
  voids is attributed to no member, and the events that void a
  `NotAWriter` unit, frozen with it, decide whether it is re-submitted.
  A unit reads each person's list as the copies in its own past carry it,
  for validity and attribution alike, so nothing a list learns later
  changes either, but the list's own voiding of an add; a replica that
  forgets keeps the copies of the forgotten past whole. A copy places only
  the event it carries, and the adds a copied list checkpoint's record
  names, never the past of a later event, so a replica that forgot a
  list's past places as one that kept it, and a newcomer's snapshot names
  the placed events outright (key 15).
- **A held administrator slot.** A slot another pseudonym holds (another
  installation of the same device, or another holder of the slot token)
  is never enrolled again while it is in. The device signs nothing for it
  and reports `SlotHeld`; the other installation, or another
  administrator, acts. A residue tells this case from the cut alone when
  the cut names the other pseudonym, and otherwise only once back in.
  A newcomer judges no unit of that past; it reads the stream states its
  snapshot carries, on its sender's signature.
- **A cut's checkpoint** is the first space event that names it, cites it
  and has every other parent in its past, the converse of the cut citing
  every other parent of its checkpoint; one that names it otherwise names
  nothing to a peer, and replicas find it `BadTwin`.
- **A late enrolment** must be self-consistent (its keys and signature),
  and the connection it opens stores only that pseudonym's late events.
- **No refusal for standing.** A skeleton event whose author is not, or no
  longer, enrolled in a slot that is in is stored with no effect, so that
  nothing that cites it waits at a peer for good.
- **Replicas** check the cut against the record: the cut declares the
  checkpoint's cuts, and each record `slot` entry names a slot of the cut
  with the same pseudonym (or both empty). Extra slots of the cut map to no
  device. A replica that forgot maps pseudonyms to devices through those
  entries, and an enrolment after the checkpoint of a slot the cut leaves
  unenrolled through its binding, sealed under the checkpoint's twin
  secret, which the enrolment's cuts name; it restarts its skeleton at a
  checkpoint's cut when the checkpoint takes effect at it.

### 2.4 Rules that hold across the logs

**Ordering.** To order two checkpoints a replica reads the later one's
cuts. A replica keeps the envelope of every checkpoint its kept
checkpoint's cuts reach, a snapshot hands them to a newcomer, and a check
that needs one it neither holds nor keeps is pending until it fetches it. A
stub of an event that declares cuts carries them, and a stub and its event
agree on cuts (`BadStub` otherwise). A parent the replica dropped is in the
kept checkpoint's past, so it contributes nothing and the check never waits
for it; a newcomer counts as dropped a parent that peers answer `Missing`
for. A dropped parent of an event the replica keeps of the past keeps its
height, so that the kept event, a unit an adapter orders among them, keeps
the height it was judged at. A holder keeps the ID of every list event it forgot, and a
`frasil:system` snapshot state carries them, so that a member starting from
it tells a forgotten parent from one it has not received.

**Administrator ranks.** Every administrator has a rank, 0 to 255; the
founder holds 255. Nobody changes or removes an administrator of a higher
rank than its own, and nobody grants a rank above its own (`HigherRank`).
A rank never changes in place: re-ranking is a lowering then a raise.
Administrators of any rank manage readers and writers. Between two
administrators that remove each other, the one that outranks the other
stands: the higher rank, and between equals the more senior. Peers carry
ranks in the skeleton, so they settle the same duels that replicas settle
without learning who a slot is.

**Heard members and excuses.** A checkpoint hears a member that was
lowered in its past only by members it outranks, and lists it in the
record; it waits for that member's vote. An administrator is excused once
it is removed, demoted or marked dormant by a member that outranks it, by
itself, or by a recovery member of a rank at least its own, or once it is
shown forked. The recovery member is
an administrator marked `frasil.dormant`, granted by the founder at the top
rank; marking or unmarking it is a change of an administrator, so only its
rank or above may sign it. A client never votes for a checkpoint that
hears it.

**Concurrent checkpoints.** Two concurrent checkpoints can both be stable
only when their electorates share no device. The one with the smaller ID
wins. Validity is final and stability only grows, so a replica's chain
moves only to a smaller ID, and a replica that holds every event has
settled. A replica that forgot under the loser, or started from it, calls
the winner a **rival** and holds pending every event it holds, until it gets
the rival's past or starts again from a snapshot. Lists read it alike.

**What a checkpoint carries across.** The record lists each invite key in
force or claimed, with its status (open, claimed with its claimant, raced,
used); in the world the checkpoint counts as a successor of every key not
open, so a later claim is `InviteUsed` and a raced key stays outside. A
space member's entry carries the notices of the last notice events for it,
and a floor when this space answered a "from now on" admission there.
Keys before the checkpoint are provisional: every space event after it is
sealed under a state of its world, so only units, objects and names open
under older keys, and a failure holds them. Late events' artifacts count
for nothing in the world's heal test. Grant seeds before the checkpoint are
kept while a principal in force in a granting space names their rotation.

**What a dropped device loses.** A list checkpoint in effect voids the
dropped device's events in every space, before the checkpoint as after. Its
units, anchors and writer requests are `Dropped`, and its key events too
where the replica can check their signature; where it cannot, a key event
is `NoHybridKey`, held and never judged, with no effect. A replica that kept
the whole list and one that forgot it agree.

## 3. Why replicas agree

[rationale.md](../spec/rationale.md), section 2.10, gives the argument; it
holds for each of the three logs:

1. Whether an event is before, after or concurrent with checkpoint `c` is
   read from declarations checked against parents, so a holder that forgot
   and one that did not sort every event alike.
2. Events after `c` are judged by one function (the log's own merge, over a
   log rooted at `c`) on one input (`c`'s record and the events after it,
   linked to each other only); an event after `c` with another parent that
   is not after it is void, so nothing after `c` depends on what came before.
3. The record is the past's own: every holder of the past checks it, every
   voter checked it, and once it is in effect nothing concurrent counts.

Votes only accumulate, so effect only grows, and verdicts do not depend on
the order of arrival. The one exception is two concurrent checkpoints whose
electorates share no device: both can be stable, the smaller ID then wins,
and a chain held before the smaller one's votes arrived moves to it; a
replica that forgot under the other holds a rival and waits (section 2.4).
A missing record object holds a checkpoint as a key a replica lacks does,
and changes nothing once it arrives.

## 4. The model checks

Three seeded, deterministic checks build histories with the reference's own
signed and sealed events. In each, a replica that forgot is given a log
that holds only what the text lets it keep (the genesis or first event,
the kept checkpoint, the envelopes its cuts reach, late events, what the
record names, and the events after it), so it cannot read anything else.
Builders also sign as a dishonest party would: checkpoints on another's
view naming an earlier checkpoint or none, unfenced acknowledgements, a
**split** of the administrators into two groups that remove each other and
checkpoint, and an **attack** by a removed administrator (or a revoked
device) that removes every other administrator it sees on its view from
before its removal, then checkpoints. Administrators get random ranks, and
each attack is classified by its author's rank against its victims'.

The checks run as Rust tests, each over a range of seeds; a debug build
runs a few seeds by default, and a release build runs the counts below.
The reference code in `docs/spec/reference` builds the same three models,
and `generate.py` runs short versions of them among its self-tests.

- **Space checkpoints** (`FRASIL_CHECKPOINT_SEEDS=400 cargo test --release
  --all-features -p frasil-space --test checkpoint_model`, about 8
  minutes): 400 histories, 198 with invite links, 267 with a granted team
  and 267 with guests, 160 with a person member whose device list
  checkpoints, and 100 drawn for collusion. They hold 21,981 events and
  1,897 checkpoints (738 valid), 398 in effect, chains up to 6, 769
  unfenced checkpoints and 218 splits. 311 forgetting replicas are compared
  on 15,572 verdicts, 79 of them holding a rival; 921 record objects are
  withheld; 699 lowerings are checked against the rank rule. Of 382
  attacks (alone, with a colluding removed administrator, with a device it
  grants, or removing selectively), 20 take effect: where a victim voted
  for it through a dishonest step, where every victim had forked, where the
  attacker's own removal is void because it won its duel, or where it
  outranks every victim it removed. 80 seeds give 4,438 events, 399
  checkpoints, 83 in effect and 62 forgetting replicas on 3,135 verdicts
  with every feature, 4,022 events and 76 in effect with the defaults.
- **List checkpoints** (`FRASIL_LIST_MODEL_SEEDS=80`, `-p frasil-identity
  --test list_checkpoints model_check`): 80 histories, 20 drawn for
  collusion, 2,233 events, 313 checkpoints, 56 in effect, 35 forgetting
  holders compared on 765 verdicts, 17 holding a rival, 38 splits. Of 39
  attacks, 6 take effect, each by a device that no victim outranks (the
  person's first device, or one whose seniors were revoked already).
- **Skeleton cuts** (`FRASIL_SKELETON_SEEDS=40`, `-p frasil-peers --test
  skeleton_cuts`): 1,334 events, 131 cuts, 37 in effect, 35 truncating
  peers compared on 940 verdicts. Of 58 attempts on a higher rank, 51 are
  void at the peer as `HigherRank` and the other 7 for another reason first
  (`NotAnAdministrator`, `UnknownAdministratorSlot`, `NotAuthorized`).
- **The key graph** (`keys.json checkpoint_worlds`): eight histories of a
  key graph rooted at a checkpoint, among them a rotation after the
  checkpoint that also cites a late one (`MixedCut`).

The random histories cover granted spaces, guests, persons across a list
checkpoint and colluding attackers. Scenarios in the vectors cover the
cases they do not: restricted spaces across a checkpoint, a granted
space's own checkpoint, a thief of the top-rank device, a recovery member
that excuses a lost founder, disjoint electorates with and without a
recovery member, passkey members, the wait for a pending erasure at a
peer, and an enrolment concurrent with a cut, built on and enrolled again
after it (the skeleton model draws such enrolments too).

**Not covered by the model checks**: restricted spaces, a granted space's
own checkpoint, recovery and passkey members in random histories (each
has a scenario only); invite links in the skeleton and list models; the
cover rule at truncation; stubs with cuts (units.json vectors only); the
record object fetched with a handed object key; a rival settled by
fetching history or a snapshot (the models stop at holding it pending).

## 5. What the design gives up

- **Concurrent work**: anything concurrent with a checkpoint in effect, in a
  space or a list, is void (re-submitted, re-signed or listed).
- **The backdated duel before a checkpoint**, and a list's late revocations
  until re-signed.
- **Membership history for newcomers** before the checkpoint.
- **Disjoint electorates**: two groups of administrators with no device in
  common, each checkpointing concurrently; the smaller ID wins, a chain
  moves only to a smaller ID, and a holder that forgot under the other holds
  everything pending until it gets history from one that kept it or starts
  again from a snapshot.
- **A member removed by one it outranks that never returns** blocks
  checkpoints until a member that outranks it or the recovery member
  excuses it.
- **Ranks never change in place**: an administrator given another rank is
  lowered and raised again, two events with their twins.
- **Trust for newcomers** in a record every administrator voted for.
- **Withheld records**: a checkpoint whose object nobody serves is held
  where it is missing; honest administrators do not vote for a record they
  cannot read, so it never takes effect.
- **A device dropped by a list checkpoint** loses its paths in every space at
  once, not after each space responds.
- **Limits**: 512 administrators fixed by one skeleton cut (its signed
  event at most 220,777 bytes with 1,024 standing entries, 256 parents and
  4 cuts, within a storage event's 262,144), every one of whom votes for
  each checkpoint or is excused; at least 70 active members (51 all
  rooted in recovery agents) fixed by one list checkpoint; 256 MiB per
  space record, about 80,000 device members. Cut body keys from 9 are
  reserved, so that a later extension can list administrators in an
  object, held by peers and replicas that lack it as a held record is.
- **A raced or claimed invite's key** cannot be claimed again after a
  checkpoint, and a claim concurrent with one is made again after it.
- **History before a checkpoint for a granted space with a floor**: a
  principal of such a space is entitled to no state before the checkpoint,
  even by a "with history" notice after it.
- **Keys before a checkpoint are provisional** where their rotation is
  forgotten: a junk key from a member makes a unit unreadable rather than
  provably wrong.
- **A granted space's names** stay in every record, 32 bytes per response.

## 6. Known limits

- **A stolen top-rank device** (most senior at the top rank) can take the
  space, with or without checkpoints; a device of a lower rank, or of an
  equal rank and junior, gains nothing.
- **A lost top-rank device** needs an equal or a recovery member to excuse
  it; without one, checkpoints stop.
- **A backdated checkpoint** by an equal-rank junior is kept out only
  because the removed administrator's client, which the checkpoint hears,
  does not vote for it. A dishonest or careless client that votes anyway
  lets it through.
- **A device dropped by a list checkpoint** loses its earlier work too: its
  units in every space, before the list checkpoint as after, are dropped.
- **Rivals can stall**: a dishonest administrator that signs an unfenced
  checkpoint with a small ID naming an old predecessor can stall replicas
  that forgot until they fetch history.
- **Space entries rest on the votes**: a replica that never sees a granted
  space's log trusts them as it trusts the record. Until the granting space
  responds to a granted space's checkpoint, a newcomer that lacks the
  noticed rotation holds the notice unresolved.
