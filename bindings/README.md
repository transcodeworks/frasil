# Native bindings

`crates/frasil-uniffi` wraps the `frasil` crate for Swift and Kotlin through
UniFFI: a device, its spaces and blob streams, and the feeds an application
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
| `tauri` | `frasil-tauri`, a Rust crate for a Tauri application that holds the device: `emit_observed`, `emit_durable`, `emit_blob_status` and `emit_arrivals` emit each value as a Tauri event to the window the application names. A workspace of its own, checked by `scripts/check-tauri.sh`. |

`scripts/bindings.sh` builds the library and the generator at one UniFFI
version, writes the glue, and runs each binding's tests;
`scripts/bindings.sh --check` fails when the committed glue differs from
what the generator writes. The generated files are committed, so an
application can depend on a binding without running the generator.

A feed runs until its `Subscription` is cancelled or dropped, and calls its
listener from Frasil's own threads: hand each value to the main thread or an
actor before touching the interface.
