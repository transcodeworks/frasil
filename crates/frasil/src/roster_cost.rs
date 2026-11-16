//! What roster events cost as a space's roster grows: a measurement, run
//! by hand.
//!
//! ```sh
//! cargo test --release -p frasil --lib roster_cost -- --ignored --nocapture
//! ```
//!
//! For each size N (`FRASIL_ROSTER_SIZES`, default `50,100,200,400`), an
//! administrator grants N devices at `write`, with history, one roster
//! event each; with `FRASIL_ROSTER_LEVELS=1` it then raises each to
//! `administer` and lowers it to `write` again, neither of which rotates,
//! as the WebAssembly benchmark's roster does; with
//! `FRASIL_ROSTER_ROTATIONS=R` it then removes R of them, each removal a
//! rotation wrapped to every member left. Then it times, and counts
//! the primitives run (`frasil_crypto::counts`) and the resolutions:
//!
//! - signing the roster: every event the administrator signs;
//! - one more level change at the administrator, on top of that roster;
//! - a granted device's first resolution of the whole log, from nothing;
//! - that device's refresh after one more roster event arrives;
//! - a device granted "from now on" after all that, which holds no key of
//!   the earlier rotations: its first resolution, and its refresh after
//!   one more roster event.
//!
//! The counts are process-wide, so run this test alone.

use crate::adapters::AdapterRegistry;
use crate::device::Engine;
use crate::platform::Platform;
use frasil_crypto::counts::{self, Counts};
use frasil_events::EventId;
use frasil_space::{Change, HistoryMode, Level, MemberRef, Via};
use std::time::{Duration, Instant};

async fn device(seed: u32) -> Engine {
    let mut key = [0; 32];
    key[..4].copy_from_slice(&seed.to_be_bytes());
    key[31] = 1;
    Engine::create(Platform::memory(), &key, AdapterRegistry::new())
        .await
        .expect("a device")
        .0
}

/// Time, the primitives run, and the resolutions, over one operation.
#[derive(Debug, Clone, Copy)]
struct Cost {
    time: Duration,
    counts: Counts,
    /// Views resolved whole.
    full: u64,
    /// Views resolved from an earlier resolution.
    appended: u64,
}

struct Meter {
    start: Instant,
    counts: Counts,
    resolutions: (u64, u64),
}

impl Meter {
    fn start() -> Self {
        Self {
            start: Instant::now(),
            counts: counts::now(),
            resolutions: frasil_space::space::resolution_counts(),
        }
    }

    fn stop(self) -> Cost {
        let resolutions = frasil_space::space::resolution_counts();
        Cost {
            time: self.start.elapsed(),
            counts: counts::now().since(self.counts),
            full: resolutions.0 - self.resolutions.0,
            appended: resolutions.1 - self.resolutions.1,
        }
    }
}

fn row(n: usize, events: usize, what: &str, cost: &Cost) {
    let c = cost.counts;
    println!(
        "| {n:>4} | {events:>5} | {what:<22} | {:>10.1} | {:>8} | {:>8} | {:>7} | {:>8} | {:>7} | {:>5} | {:>4} |",
        cost.time.as_secs_f64() * 1000.0,
        c.mldsa65_verify,
        c.ed25519_verify,
        c.hpke_open,
        c.aead_open,
        c.mldsa65_sign,
        cost.full,
        cost.appended,
    );
}

async fn set_level(admin: &Engine, space: EventId, member: &Engine, level: Level) {
    admin
        .sign_roster(
            space,
            vec![match level {
                Level::Administer => Change::raise(MemberRef::device(member.device_id()), 255),
                level => Change::set_level(MemberRef::device(member.device_id()), level),
            }],
        )
        .await
        .expect("a level change");
}

/// The events `to` lacks of `from`'s.
async fn lacking(to: &Engine, from: &Engine, space: EventId) -> Vec<Vec<u8>> {
    let held: std::collections::BTreeSet<Vec<u8>> = to.events(&space).await.into_iter().collect();
    from.events(&space)
        .await
        .into_iter()
        .filter(|signed| !held.contains(signed))
        .collect()
}

async fn measure(n: usize, levels: bool, rotations: usize) {
    let admin = device(1).await;
    let mut members = Vec::with_capacity(n);
    for index in 0..n {
        members.push(device(1000 + u32::try_from(index).expect("small")).await);
    }
    let space = admin.create_space().await.expect("a space");

    let meter = Meter::start();
    for member in &members {
        admin
            .grant_device(
                space,
                member.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .expect("a grant");
    }
    if levels {
        for member in &members[1..] {
            set_level(&admin, space, member, Level::Administer).await;
        }
        for member in &members[1..] {
            set_level(&admin, space, member, Level::Write).await;
        }
    }
    // Removals: each rotates, wrapped to every member left.
    for member in members.iter().rev().take(rotations) {
        admin
            .remove(space, MemberRef::device(member.device_id()))
            .await
            .expect("a removal");
    }
    let signing = meter.stop();
    let events = admin.events(&space).await.len();
    row(n, events, "sign the roster", &signing);

    // One more level change at the administrator.
    let meter = Meter::start();
    set_level(&admin, space, &members[1], Level::Administer).await;
    row(n, events, "one more set_level", &meter.stop());

    // A granted device's first resolution.
    let reader = &members[0];
    reader.follow(space).await;
    let all = admin.events(&space).await;
    let meter = Meter::start();
    reader.ingest(space, all).await.expect("an ingest");
    let first = meter.stop();
    let level = reader
        .read(&space, |r| r.level_of(&reader.device_id()))
        .await
        .expect("the space");
    assert_eq!(level, Some(Level::Write), "the reader resolves its grant");
    row(n, events + 1, "fresh reader, all", &first);

    // One more roster event, and the reader's refresh.
    set_level(&admin, space, &members[2], Level::Administer).await;
    let one = lacking(reader, &admin, space).await;
    let meter = Meter::start();
    reader.ingest(space, one).await.expect("an ingest");
    row(n, events + 2, "reader, one more event", &meter.stop());

    // A device admitted from now on, which holds no key of the rotations
    // before its grant.
    let late = device(999).await;
    admin
        .grant_device(
            space,
            late.public_keys().clone(),
            Level::Read,
            HistoryMode::FromNowOn,
            Via::Code,
        )
        .await
        .expect("a grant");
    late.follow(space).await;
    let all = admin.events(&space).await;
    let meter = Meter::start();
    late.ingest(space, all).await.expect("an ingest");
    row(n, events + 3, "late reader, all", &meter.stop());
    set_level(&admin, space, &members[3], Level::Administer).await;
    let one = lacking(&late, &admin, space).await;
    let meter = Meter::start();
    late.ingest(space, one).await.expect("an ingest");
    row(n, events + 4, "late reader, one more", &meter.stop());
}

#[tokio::test]
#[ignore = "a measurement: run by hand with --release"]
async fn roster_cost() {
    let sizes: Vec<usize> = std::env::var("FRASIL_ROSTER_SIZES")
        .unwrap_or_else(|_| "50,100,200,400".into())
        .split(',')
        .map(|n| n.trim().parse().expect("a size"))
        .collect();
    let levels = std::env::var("FRASIL_ROSTER_LEVELS").is_ok_and(|v| v == "1");
    let rotations: usize = std::env::var("FRASIL_ROSTER_ROTATIONS")
        .ok()
        .map_or(0, |r| r.parse().expect("a count"));
    println!();
    println!(
        "|    N | events | operation              |       ms   | ML-DSA v | Ed25519 v | HPKE op | AEAD op | ML-DSA s | full | app. |"
    );
    println!("| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for n in sizes {
        measure(n, levels, rotations).await;
    }
}
