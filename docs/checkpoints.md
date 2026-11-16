# Checkpoints

Every change of who belongs to a space, and of what each member may do, is
an event in the space's log, and a device judges each new event against the
history before it. Without anything else, that history only grows: a
newcomer would fetch and check every membership change since the space was
made. A **checkpoint** fixes the membership at one point of the log. Its
record says who the members are and what each may do there. Once every
administrator has written something after it, it takes effect: nothing
before it changes any verdict again, and every member may forget what came
before it and start from it. A person's device list has checkpoints of its
own, which work the same way for the person's devices. See
[roster.md](spec/roster.md), "Checkpoints", and
[identity.md](spec/identity.md), "List checkpoints". For the design rationale,
read [Checkpoints: design](design/checkpoints.md).

## It happens by itself

An application does not need to call anything. By default:

- an administrator's device proposes a checkpoint once the space has 1,024
  membership changes, or 4 MiB of frame events, since the last one in
  effect. The most senior administrator proposes first; the others wait
  their turn, so that one checkpoint is proposed rather than several;
- every other administrator's device votes for it by writing anything
  after it, and writes an empty event when it has nothing else to write;
- once the checkpoint is in effect, each device forgets what came before it,
  in memory and at rest;
- a device of a person does the same for the person's device list.

A device keeps working while a checkpoint waits for votes: members read and
write as before.

### What a device keeps of the past

A device that forgets what came before a checkpoint keeps, for each unit of
that past it still holds, what it read of it: whether the unit was applied
or refused, the capabilities its author held there, who wrote it, with the
names the roster gave them then, and what voided it. Documents, tables and their history read the same before and
after forgetting, and after a restart.

A newcomer that starts from a checkpoint holds none of that past. It reads
each document and table as the state the sender signed at the checkpoint,
holds no unit from before it, and its history shows no author for those
edits: it begins at the checkpoint.

## What an application shows

A few outcomes need a person to decide or to know. The device reports each
as an event (`Device::events` in Rust, `device.events()` in the browser
package, `checkpointReports` in Swift and Kotlin), and the current
state is always one call away.

### A checkpoint waiting for administrators

A checkpoint takes effect only once each administrator has written after
it. A checkpoint's cut can list at most 512 administrator slots. A space
with more must remove some before it checkpoints. Keep administrators to
the people who will act on checkpoints. A device reads a space's checkpoint record as the record's chunks open, without holding the whole record. A device that already holds the checkpoint's past keeps only a digest of it: for a record near its 256 MiB cap (roughly 80,000 member devices), the read took about 5 seconds natively and 11 to 16 seconds in a browser on a recent laptop, in under 10 MB. A device that starts from the checkpoint keeps the record's members, about 320 MB for that record in the read alone, so a very large space still needs a device with that much memory to join it. `Event::CheckpointPending` (`"checkpointPending"`) names the
administrators it still waits for, `waiting_for`, and is reported again each
time that changes; `Space::checkpoints` (`space.checkpoints()`) lists every
pending checkpoint with the same field. Show the administrators an
application knows by name. An administrator whose device will not come
back, a lost phone for example, holds the checkpoint until a member that
outranks it, or a recovery member (below), removes it or demotes it below
administer: the checkpoint then stops waiting for it, on the devices and at
the peer alike. Marking it dormant excuses it on the devices only: the peer
still waits, and keeps the past it would otherwise delete. So to unblock a
checkpoint for good, remove or demote the lost administrator.
`Event::CheckpointInEffect` (`"checkpointInEffect"`) reports when it took
effect.

A device votes for a checkpoint once each always-on peer it reaches holds
the checkpoint, so that no peer carries out an erasure the checkpoint
could still make void. A device that reaches no peer votes at once, so
devices that sync only with each other still checkpoint.

### Requests signed again

An erasure, or a release or restore of a document, that a device made at
the same time as a checkpoint is void once the checkpoint is in effect. The
device signs it again after the checkpoint by itself, and
`Event::RequestSignedAgain` (`"requestSignedAgain"`, `RequestSignedAgain`
in Swift and Kotlin) names the late request. A peer that the device did not
reach in time may already have carried out such an erasure: it then
answers that the space is erased, though the checkpoint kept it, and
`Event::ErasedWhileLate` (`"erasedWhileLate"`) says so, naming who asked
for the erasure. Move the space to another peer, or give it up.

A device that erased a space keeps a few records of it until each peer it
reaches says the space is erased there. If a peer has not said so after
seven days, the device tells the application which peers have not, and
asks on until they do or the application gives the space up. If a peer
answers that a checkpoint made the erasure late, naming the checkpoint and
whether the device still administers the space there, the device tells the
application at once. When it still administers it, it asks the space's
administering devices for a welcome, fetches the space again, and erases
it again after the checkpoint; when it does not, it says that it can no
longer erase the space, which lives on at that peer. When its
administrator slot is held by another pseudonym, another installation of
the same device or another holder of the slot's token, no enrolment of it
can succeed: `Event::SlotHeld` says so, naming the holder when the device
can tell, and the user erases from that installation, or another
administrator erases the space or repairs the slot. That answer is the
peer's word, which the device cannot check without the space's keys, so
it only reports and asks on it. Nothing is left undone
without the application being told: `Event::ErasureUnanswered`
(`"erasureUnanswered"`) names the peers that have not answered past the
seven days, `Event::ErasureLateAtPeer` (`"erasureLateAtPeer"`) the peer that
answered with such a checkpoint, and `Event::ErasureVoid` (`"erasureVoid"`)
says the erasure is void; an erasure signed again is a
`RequestSignedAgain`. `Device::give_up_space` (`device.giveUpSpace(id)` in
the browser package, `giveUpSpace` in Swift and Kotlin) gives the space up:
the device stops asking and forgets what it kept of it.

### Membership changes to make again

A membership change made at the same time as a checkpoint, on a device that
had not seen it yet, comes too late: it is void once the checkpoint is in
effect. The device signs its own late removals and demotions again by
itself, and sends its late edits again. It does not repeat a late grant or
a raised level, because the person may no longer want it.
`Event::Late` (`"late"`) lists those changes, and `Space::late_changes`
(`space.lateChanges()`) gives the current list: each with the member it
named, what it did (`grant`, `change`, `remove` or `other`) and the level it
set. Show them to the administrator who made them, and let them make each
again with the usual calls, such as `Space::set_level` or an invitation.

### A device the device list left out

A device added to a person's device list at the same time as a list
checkpoint is left out of the list once the checkpoint takes effect, like a
late membership change, and the device does not add it again by itself:
the new device then reaches none of the person's spaces. Admit it to the
person again. A list checkpoint waits for each of the person's devices to
sign something after it; `Event::ListCheckpointPending`
(`"listCheckpointPending"`) and `Device::list_checkpoints`
(`device.listCheckpoints()`) name the devices it waits for. A device that
will not come back can be taken off the list with `Device::remove_device`
(`device.removeDevice(id)`), which stops the wait.

### A rival checkpoint while history is fetched

Two groups of administrators that cannot reach each other can each make a
checkpoint at the same time. A device that already forgot what came before
its own checkpoint needs the other one's past to decide between them. It
fetches that past by itself from a member or a peer that kept it, and every
change of the space waits until it has. `Event::CheckpointRival`
(`"checkpointRival"`, `status.rivals`) reports it; show that the space is
catching up rather than that it failed. `Event::ListCheckpointRival` is the
same for the person's device list.

### A space that needs a later version

A checkpoint's record, a space's descriptor or a roster change can use
something a later version of Frasil defines. A device whose build lacks it
holds that checkpoint and everything after it, never votes for it or builds
on it, does not start from it when a snapshot names it, and treats one that
rivals its own checkpoint as a rival it can never decide. It reads what it
judged before and signs nothing more in the space: each write there fails
with `Error::NeedsLaterVersion` (`"needs_later_version"`).
`Event::NeedsLaterVersion` (`"needsLaterVersion"`) reports it once, and
`Space::needs_later_version` gives the current answer; ask the person to
update the application.

### A checkpoint the device keeps out of

A checkpoint can drop this device as an administrator while the device's
own view says it still is one, for example when an administrator that was
removed at the same time proposed it. The device then writes nothing that
builds on it, so it never votes for it. `Event::CheckpointWithheld`
(`"checkpointWithheld"`, `status.withheld`) reports it. Tell the
administrators: another administrator should check who proposed the
checkpoint. `Event::BackdatedCheckpoint` (`"backdatedCheckpoint"`,
`status.backdated`) reports, to administrators, a checkpoint whose proposer
a removal made at the same time removes, with that removal.

### What is void

`Event::BadCheckpoint` (`"badCheckpoint"`) reports a checkpoint whose
record does not match its past: it never takes effect, and this device
never votes for it. `Event::MixedCut` (`"mixedCut"`) reports an event that
mixes history from both sides of a checkpoint; it is void. Neither needs a
person's decision, but both are worth logging.

## Ranks

Every administrator holds a rank, 0 to 255; a larger rank outranks a
smaller one, and the space's creator holds 255. Nobody changes or removes
an administrator of a higher rank, nor grants a rank above its own: such a
change is void (`HigherRank`), and the device refuses it before signing.
When two administrators remove each other at the same time, the higher
rank stands, and between equal ranks the more senior. A rank never changes
in place: `Space::set_rank` (`space.setRank()`) lowers the member, then
raises it again. Grant administrators with `Engine::grant_administrator`
or `Space::raise` (`space.raise(member, rank)`), which take the rank
explicitly; `Event::RankAttemptRefused` (`"rankAttemptRefused"`) reports a
change void as `HigherRank`.

A recovery member is an administrator at the top rank marked dormant:
checkpoints do not wait for it, and it can excuse or remove any member, a
lost top-rank device among them. Make one with `Space::make_recovery_member`
(`space.makeRecoveryMember(member)`), from a device at the top rank, and
keep its device somewhere safe, offline if you can. `Space::set_dormant`
(`space.setDormant(member, on)`) marks or unmarks an administrator, and
`Space::recovery_members` (`space.recoveryMembers()`) lists them; a member
of `Space::members` says whether it is `dormant`. To excuse a lost
administrator from a checkpoint that waits for it, the recovery member
removes it or demotes it below administer; marking it dormant excuses it on
the devices only, not at the peer (above).

Name the ranks in the application. Keep the top rank on few, well-guarded
devices and give day-to-day administrators a lower one: a stolen device at
the top rank can take the space. Set up a recovery member at the top rank:
a checkpoint waits for every administrator it hears, and without a
recovery member a lost top-rank device stops checkpoints for good. A
device that a list checkpoint drops loses its earlier work in every space
too.

## The policy

`Device::set_checkpoint_policy` (`device.setCheckpointPolicy(policy)` in the
browser package, `setCheckpointPolicy` with a `CheckpointPolicy` record in
Swift and Kotlin) changes what
the device does by itself:

| Setting | Default | What it does |
| --- | --- | --- |
| `propose` | on | Whether an administrator's device proposes checkpoints by itself, and a device proposes them for its person's device list. Off, the application proposes with `Space::propose_checkpoint` (`space.proposeCheckpoint()`) and `Device::propose_list_checkpoint`, or never. |
| `forget` | on | Whether the device forgets what came before a checkpoint once it is in effect. Off, it keeps the whole history. |
| `roster_events` (`rosterEvents`) | 1,024 (`PROPOSE_AT_ROSTER_EVENTS`) | How many membership changes, or device-list events, since the last checkpoint call for the next one. |
| `frame_bytes` (`frameBytes`) | 4 MiB (`PROPOSE_AT_FRAME_BYTES`) | How many bytes of frame events since the last checkpoint call for the next one. |

In Rust, build a policy from `CheckpointPolicy::AUTOMATIC` (the default) or
`CheckpointPolicy::MANUAL` (no proposals), with `.proposing(on)`,
`.forgetting(on)` and `.proposing_at(roster_events, frame_bytes)`. In the
browser package, fields left out take their default. A threshold of 0
counts as 1.

Votes are not part of the policy: a device that administers always votes
for the checkpoint it follows, so that the space's checkpoints can take
effect.

`Space::checkpoints` also says how far the space has grown since the last
checkpoint (`roster_events_since`, `frame_bytes_since`), which checkpoint the
device follows, and whether it forgot what came before the one in effect
(`forgot`).

## Peers

An always-on peer keeps a checkpoint's past for a while after the
checkpoint takes effect, so that a device that was away can still fetch
what it missed, then deletes it. How long is the peer's setting; see
[Self-hosting a peer](self-hosting.md#checkpoints).

A retained erasure can be retried immediately with `Device::retry_erasure`
(`device.retryErasure(id)` in the browser package). A late answer reports
`ErasureCheckpoint` (`erasureCheckpoint`), including the checkpoint and the
slot standing the residue checked without space keys. Standing 0, or standing
1 with an empty cut entry, sends signed welcome requests to the saved administrators and reports
`ErasureAwaitingWelcome` (`erasureAwaitingWelcome`). The residue stays while
waiting. Pending welcome requests are renewed daily with fresh request IDs;
`retry_erasure` renews them immediately. Standing 2 reports `ErasureCannotErase` (`erasureCannotErase`): the
peer still holds the space and says the device can no longer erase it.
Administrators answer only verified requests from current members, with a
welcome and snapshot; a request never changes membership. After fetching,
the device judges the checkpoint and signs its erasure again or reports
`ErasureVoid` (`erasureVoid`) or `SlotHeld` (`slotHeld`). The application may give the space up at any time.

A contradictory late answer reports `PeerError` (`peerError`) with the encoded,
untrusted answer. It counts as unanswered and leaves the residue intact.

A slot already enrolled to another installation after the checkpoint cannot
be enrolled a second time (`AlreadyEnrolled`). That installation must carry
out the erasure, or an administrator must replace the slot before this
installation can enrol again. The late-erasure report is not a confirmation
that any peer deleted the space.

When another pseudonym holds this device's administrator slot, `SlotHeld`
(`slotHeld` in JavaScript) names the space and holding root or enrolment,
identifies the holder as another installation of this device, another device,
or unknown, and says whether this device's erasure waits on it. A residue
has no keys and reports unknown. It keeps asking peers, without requesting
a welcome for a slot the cut names as held. Use the other installation to
administer, or ask another administrator to disown the slot and grant a new
one. An occupied slot cannot be enrolled again.

`Event::PeerNeedsVersion` (`"peerNeedsVersion"`) names a space and peer
that keeps a cut using a reserved key but cannot follow its checkpoints.
Use a later version of that peer to resume checkpoint processing.
