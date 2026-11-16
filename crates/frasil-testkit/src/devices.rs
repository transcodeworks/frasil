//! Devices for tests of applications built on the `frasil` crate.
//!
//! Each device keeps its store in memory and connects on loopback only, so
//! a test needs no peer, no network and no files. Two devices share a space
//! by nearby admission over their member connection, as two devices on one
//! network do. Every wait has a deadline and panics past it, naming what it
//! waited for, so a test fails rather than hangs.
//!
//! ```no_run
//! use frasil::Level;
//! use frasil_testkit::devices::{eventually, shared};
//!
//! # async fn example() {
//! let pair = shared(Level::Write).await;
//! let notes = pair.space.create_records().unwrap();
//! notes
//!     .write(|tx| {
//!         tx.insert("notes", b"n1").set("notes", b"n1", "text", "hi");
//!     })
//!     .await
//!     .unwrap();
//! eventually("Bob reads the note", || async {
//!     match pair.bobs_space.records(notes.id()).await {
//!         Ok(theirs) => theirs.row("notes", b"n1").await.unwrap().is_some(),
//!         Err(_) => false,
//!     }
//! })
//! .await;
//! pair.close().await;
//! # }
//! ```
//!
//! Run the tests on tokio's multi-threaded runtime, as
//! `#[tokio::test(flavor = "multi_thread")]`: devices run their upkeep and
//! connections as tasks.

use frasil::{Device, Level, Options, Space, Storage};
use std::future::Future;
use std::time::Duration;

/// How long a wait of this module lasts before it panics.
pub const DEADLINE: Duration = Duration::from_secs(60);

/// How often [`eventually`] checks again.
const POLL: Duration = Duration::from_millis(25);

/// Runs `future` to its end, or panics after [`DEADLINE`], naming `what`.
///
/// # Panics
///
/// Past the deadline.
pub async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(DEADLINE, future).await {
        Ok(out) => out,
        Err(_) => panic!("{what}: not within {DEADLINE:?}"),
    }
}

/// Waits until `check` holds, checking again every 25 ms.
///
/// # Panics
///
/// When it does not hold within [`DEADLINE`], naming `what`.
pub async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(what, async {
        while !check().await {
            tokio::time::sleep(POLL).await;
        }
    })
    .await;
}

/// A device in memory on loopback, its unlock key 32 bytes of `seed`.
/// Different seeds give different devices.
///
/// # Panics
///
/// When the device does not open.
pub async fn device(seed: u8) -> Device {
    device_with(seed, Options::new()).await
}

/// [`device`] with options of the test's own, loopback added: a clock, a
/// randomness source, extra adapters.
///
/// # Panics
///
/// When the device does not open.
pub async fn device_with(seed: u8, options: Options) -> Device {
    Device::open_with(Storage::Memory, &[seed; 32], options.loopback())
        .await
        .unwrap_or_else(|error| panic!("device {seed}: {error}"))
}

/// Admits `newcomer` into `space` at `level` by nearby admission over the
/// two devices' member connection, both screens confirming, and returns the
/// space as the newcomer holds it.
///
/// # Panics
///
/// When the admission fails or does not end within [`DEADLINE`].
pub async fn admit(space: &Space, newcomer: &Device, level: Level) -> Space {
    let invitation = space
        .invite(level, "host", |_, _| async { true })
        .await
        .unwrap_or_else(|error| panic!("invite: {error}"));
    let joined = within(
        "the newcomer joins",
        newcomer.join(invitation.text(), "newcomer", |_, _| async { true }),
    )
    .await
    .unwrap_or_else(|error| panic!("join: {error}"));
    within("the host admits", invitation.admitted())
        .await
        .unwrap_or_else(|error| panic!("admitted: {error}"));
    joined
}

/// Two devices and a space they share: Alice created it and administers
/// it; Bob was admitted at the level given.
#[derive(Debug)]
pub struct Shared {
    /// The device that created the space.
    pub alice: Device,
    /// The device admitted to it.
    pub bob: Device,
    /// The space, as Alice holds it.
    pub space: Space,
    /// The space, as Bob holds it.
    pub bobs_space: Space,
}

impl Shared {
    /// Closes both devices.
    ///
    /// # Panics
    ///
    /// When one does not close.
    pub async fn close(self) {
        self.alice.close().await.expect("Alice's device closes");
        self.bob.close().await.expect("Bob's device closes");
    }
}

/// Alice's new space, with Bob admitted at `level` and holding both
/// members: devices of seeds 1 and 2, as [`device`] makes them.
///
/// # Panics
///
/// When a step fails or does not end within [`DEADLINE`].
pub async fn shared(level: Level) -> Shared {
    let alice = device(1).await;
    let bob = device(2).await;
    let space = alice
        .create_space()
        .await
        .unwrap_or_else(|error| panic!("create the space: {error}"));
    let bobs_space = admit(&space, &bob, level).await;
    eventually("Bob holds both members", || async {
        bobs_space.members().await.is_ok_and(|m| m.len() >= 2)
    })
    .await;
    Shared {
        alice,
        bob,
        space,
        bobs_space,
    }
}
