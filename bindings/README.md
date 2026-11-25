# Native bindings

`crates/frasil-uniffi` wraps the `frasil` crate for Swift and Kotlin through
UniFFI: a device, its spaces and blob streams, the admission of a device
into a space over a nearby connection, and the feeds an application
follows (whether a space has nothing unsent, a blob's status, what the
device holds for the first time, and what it reports of checkpoints), each
delivered to a listener the application implements. A space's checkpoints
(`checkpoints`, `proposeCheckpoint`, `lateChanges`) and the device's
checkpoint policy and device-list checkpoints (`setCheckpointPolicy`,
`checkpointPolicy`, `listCheckpoints`, `proposeListCheckpoint`) are calls;
`checkpointReports` follows what the device reports of them. See
`docs/checkpoints.md`.

| Directory | What it is |
| --- | --- |
| `swift` | A Swift package, `Frasil`, over the library Cargo builds. |
| `kotlin` | A Kotlin library, package `frasil`, which loads the library through JNA; Gradle and a JDK 21. |

`scripts/bindings.sh` builds the library and the generator at one UniFFI
version, writes the glue, and runs each binding's tests;
`scripts/bindings.sh --check` fails when the committed glue differs from
what the generator writes. The generated files are committed, so an
application can depend on a binding without running the generator.

## Opening a device

`Device.open(path, unlockKey, options)` and `Device.openInMemory(unlockKey,
options)` take a `DeviceOptions` record, or none for the defaults:

| Field | What it sets |
| --- | --- |
| `loopback` | The device's own endpoints bind on loopback alone, for tests and examples. |

None of it is stored: give it at each open.

## Joining a space

`space.invite(level, name, listener)` gives an `Invitation` whose `text()`
goes to the other device, which enters it in `device.join(invitation, name,
listener)`; `invitation.admitted()` waits for the newcomer. The two devices
connect to each other directly, with no always-on peer.

```swift
let invitation = try await space.invite(level: "write", name: "Ada's laptop", listener: listener)
show(invitation.text())
try await invitation.admitted()
```

```kotlin
val space = device.join(text, "Ada's phone", listener)
```

The level is `read` or `write`. A nearby admission makes no administrator:
admit the newcomer at `write`, then `space.raise(member, rank)`.

Each side's `AdmissionListener` is asked once, `confirm(code, name)`, with
the six-digit admission code and the name the other device gave, and
answers whether its person saw the same code on both screens. `false`
refuses the admission, and so does a listener that throws. The inviting
device grants as soon as its own person confirms, so its person confirms
only after seeing the code on the newcomer's screen. `confirm` is called on
a thread started for it and may wait there for the person.

**Time limit.** An admission code lives 15 minutes from the moment the
newcomer asks the inviting device. An answer that takes longer counts as
`false`. An invitation itself has no limit: it waits for a newcomer until
another invitation replaces it or the device closes.

**Abandoning an admission.** `join` and `admitted` take a `Cancellation`,
which the application cancels to end the call, and a Kotlin coroutine that
is cancelled ends its call by itself. Swift does not end a call when its
task is cancelled, so cancel the `Cancellation` from the task's
cancellation handler:

```swift
let cancellation = Cancellation()
let space = try await withTaskCancellationHandler {
    try await device.join(
        invitation: text, name: name, listener: listener, cancellation: cancellation)
} onCancel: {
    cancellation.cancel()
}
```

A cancelled `join` fails, stops where it stands, and has joined nothing. A
cancelled `admitted` fails and abandons its invitation: a newcomer that
comes, or came, is refused as if this device's person had not confirmed.
In both, a listener that is being asked is waited for no longer and its
answer counts for nothing; take the question off the screen and return
from `confirm`, since its thread is the listener's until it returns.

An invitation is waited for once. A second `admitted()` fails and says why
the invitation is spent: its admission ended, or the first call was
cancelled. Invite again.

## Feeds

A feed runs until its `Subscription` is cancelled or dropped, and calls its
listener from Frasil's own threads: hand each value to the main thread or an
actor before touching the interface.
