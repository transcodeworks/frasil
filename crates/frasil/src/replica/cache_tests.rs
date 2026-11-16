//! What a replica keeps between refreshes gives the verdicts a refresh from
//! scratch gives: over random histories of three devices (writes in two
//! documents, grants with and without history, removals and their
//! rotations, raises to `administer` and lowers from it, each with its
//! twin, keys a device learns outside any record, events delivered late
//! and out of order, so that keys and twins arrive after what needs them; a
//! partial replica; a restricted space), every refresh is checked against a
//! resolution from scratch ([`Replica::check_from_scratch`]), which
//! verifies every signature again. At the end each device, opened again
//! from its store, reads what it read before, and a new instance of each
//! full device, given every event and the keys it learned, reads the same:
//! nothing a device remembers between refreshes (verdicts, failed wrap
//! trials) outlives what made it true.

use crate::advanced::{AdapterRegistry, Engine, MemorySlot, MemoryStore, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Via};
use frasil_store::{DeviceBoundSlot, Store};
use frasil_units::stream::Opening;
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
enum Op {
    /// A device edits a document of a space.
    Edit {
        device: usize,
        doc: usize,
        restricted: bool,
    },
    /// The founder grants a device, with history or from now on.
    Grant { device: usize, history: bool },
    /// The founder removes a device: a rotation.
    Remove { device: usize },
    /// The founder raises a device to `administer`, or lowers it to
    /// `write`: either names a twin.
    SetLevel { device: usize, administer: bool },
    /// A device learns another's keys outside any record.
    LearnKeys { device: usize, of: usize },
    /// A device ingests some of what another holds of a space, in an order
    /// of its own.
    Deliver {
        from: usize,
        to: usize,
        mask: u64,
        restricted: bool,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..3usize, 0..2usize, any::<bool>())
            .prop_map(|(device, doc, restricted)| Op::Edit { device, doc, restricted }),
        2 => (1..3usize, any::<bool>()).prop_map(|(device, history)| Op::Grant { device, history }),
        1 => (1..3usize).prop_map(|device| Op::Remove { device }),
        1 => (1..3usize, any::<bool>())
            .prop_map(|(device, administer)| Op::SetLevel { device, administer }),
        1 => (0..3usize, 0..3usize).prop_map(|(device, of)| Op::LearnKeys { device, of }),
        4 => (0..3usize, 0..3usize, any::<u64>(), any::<bool>())
            .prop_map(|(from, to, mask, restricted)| Op::Deliver { from, to, mask, restricted }),
    ]
}

struct Device {
    engine: Engine,
    store: Arc<MemoryStore>,
    slot: Arc<MemorySlot>,
    sealed: Vec<u8>,
    key: [u8; 32],
}

async fn device(key: u8) -> Device {
    let store = Arc::new(MemoryStore::new());
    let slot = Arc::new(MemorySlot::new());
    let platform = Platform::new(
        Arc::clone(&store) as Arc<dyn Store>,
        Arc::clone(&slot) as Arc<dyn DeviceBoundSlot>,
    );
    let (engine, sealed) = Engine::create(platform, &[key; 32], AdapterRegistry::with_builtins())
        .await
        .expect("a device");
    Device {
        engine,
        store,
        slot,
        sealed: sealed.to_vec(),
        key: [key; 32],
    }
}

/// Every event a device holds of a space, placed or pending.
async fn held(engine: &Engine, space: EventId) -> Vec<Vec<u8>> {
    engine
        .read(&space, |replica| {
            let Some(log) = replica.log() else {
                return Vec::new();
            };
            log.canonical()
                .into_iter()
                .filter_map(|id| log.event(id).map(frasil_events::Event::signed))
                .chain(log.pending().map(frasil_events::Event::signed))
                .collect()
        })
        .await
        .unwrap_or_default()
}

/// What a device reads of a space: each decided event's verdict, and each
/// document's text.
async fn reading(
    engine: &Engine,
    space: EventId,
    docs: &[Opening],
) -> (
    BTreeMap<EventId, (frasil_store::tables::EventState, Option<&'static str>)>,
    Vec<String>,
) {
    let verdicts = engine
        .read(&space, |replica| {
            replica
                .log()
                .map(|log| {
                    // Decided events: what is held pending, a replica
                    // need not keep at rest.
                    log.canonical()
                        .into_iter()
                        .filter(|id| replica.accepted(id))
                        .map(|id| (id, replica.event_state(&id)))
                        .collect()
                })
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default();
    let mut texts = Vec::new();
    for doc in docs {
        texts.push(
            engine
                .document(&space, &doc.stream())
                .await
                .map(|d| d.get_text("body").to_string())
                .unwrap_or_default(),
        );
    }
    (verdicts, texts)
}

async fn run(ops: Vec<Op>, partial: bool) {
    let mut devices = vec![device(1).await, device(2).await, device(3).await];
    let space = devices[0].engine.create_space().await.unwrap();
    let docs = [
        devices[0].engine.new_document().unwrap(),
        devices[0].engine.new_document().unwrap(),
    ];
    #[cfg(feature = "ext-restricted-spaces")]
    let restricted = devices[0].engine.create_restricted(space).await.ok();
    #[cfg(not(feature = "ext-restricted-spaces"))]
    let restricted: Option<EventId> = None;
    // A partial replica holds the first document only.
    #[cfg(feature = "partial-replicas")]
    if partial {
        devices[2].engine.hold_streams_only();
    }
    for other in &devices[1..] {
        other.engine.follow(space).await;
        if let Some(restricted) = restricted {
            other.engine.follow(restricted).await;
        }
    }
    if partial {
        let _ = devices[2].engine.hold_stream(space, docs[0].stream()).await;
    }
    // The keys each device learned outside any record.
    let mut learned: Vec<Vec<usize>> = vec![Vec::new(); 3];
    let space_of = |restricted_op: bool| match (restricted_op, restricted) {
        (true, Some(restricted)) => restricted,
        _ => space,
    };
    for op in ops {
        match op {
            Op::Edit {
                device,
                doc,
                restricted,
            } => {
                let _ = devices[device]
                    .engine
                    .edit_document(space_of(restricted), &docs[doc], |d| {
                        let body = d.get_text("body");
                        let _ = body.insert(body.len_unicode(), "x");
                    })
                    .await;
            }
            Op::Grant { device, history } => {
                let other = &devices[device].engine;
                let _ = devices[0]
                    .engine
                    .grant_device(
                        space,
                        other.public_keys().clone(),
                        Level::Write,
                        if history {
                            HistoryMode::WithHistory
                        } else {
                            HistoryMode::FromNowOn
                        },
                        Via::Code,
                    )
                    .await;
            }
            Op::Remove { device } => {
                let device = devices[device].engine.device_id();
                let _ = devices[0]
                    .engine
                    .remove(space, MemberRef::device(device))
                    .await;
            }
            Op::SetLevel { device, administer } => {
                let device = devices[device].engine.device_id();
                let level = if administer {
                    Level::Administer
                } else {
                    Level::Write
                };
                let _ = devices[0]
                    .engine
                    .sign_roster(
                        space,
                        vec![frasil_space::Change::set_level(
                            MemberRef::device(device),
                            level,
                        )],
                    )
                    .await;
            }
            Op::LearnKeys { device, of } => {
                let keys = devices[of].engine.public_keys().clone();
                let _ = devices[device].engine.learn_keys(keys).await;
                learned[device].push(of);
            }
            Op::Deliver {
                from,
                to,
                mask,
                restricted,
            } => {
                if from == to {
                    continue;
                }
                let space = space_of(restricted);
                let mut events = held(&devices[from].engine, space).await;
                // Some of them, newest first: parents arrive after what
                // rests on them.
                events.reverse();
                let some: Vec<Vec<u8>> = events
                    .into_iter()
                    .enumerate()
                    .filter(|(index, _)| mask & (1 << (index % 64)) != 0)
                    .map(|(_, event)| event)
                    .collect();
                let _ = devices[to].engine.ingest(space, some).await;
            }
        }
    }
    // Everything delivered everywhere, twice.
    let spaces: Vec<EventId> = [Some(space), restricted].into_iter().flatten().collect();
    for _ in 0..2 {
        for space in &spaces {
            for from in 0..3 {
                let events = held(&devices[from].engine, *space).await;
                for (to, device) in devices.iter().enumerate() {
                    if to != from {
                        let _ = device.engine.ingest(*space, events.clone()).await;
                    }
                }
            }
        }
    }
    // Opened again from its store, each device reads what it read; a
    // partial replica once it has fetched again the events it witnessed,
    // which it does not keep (units.md, "Partial replicas").
    let delivered: Vec<Vec<Vec<Vec<u8>>>> = {
        let mut out = Vec::new();
        for device in &devices {
            let mut per_space = Vec::new();
            for space in &spaces {
                per_space.push(held(&device.engine, *space).await);
            }
            out.push(per_space);
        }
        out
    };
    // A new instance of each full device, given every event any device
    // holds and the keys the device learned, reads what it reads.
    for (index, device) in devices.iter().enumerate() {
        if partial && index == 2 {
            continue;
        }
        // The same device keys over an empty store.
        let fresh = Engine::open(
            Platform::new(
                Arc::new(MemoryStore::new()) as Arc<dyn Store>,
                Arc::new(MemorySlot::new()) as Arc<dyn DeviceBoundSlot>,
            ),
            &device.sealed,
            &device.key,
            AdapterRegistry::with_builtins(),
        )
        .await
        .expect("a new instance");
        for &of in &learned[index] {
            let _ = fresh
                .learn_keys(devices[of].engine.public_keys().clone())
                .await;
        }
        let mut theirs = Vec::new();
        let mut ours = Vec::new();
        for (at, space) in spaces.iter().enumerate() {
            fresh.follow(*space).await;
            for _ in 0..2 {
                for held in &delivered {
                    let _ = fresh.ingest(*space, held[at].clone()).await;
                }
            }
            theirs.push(reading(&fresh, *space, &docs).await);
            ours.push(reading(&device.engine, *space, &docs).await);
        }
        assert_eq!(
            ours, theirs,
            "device {:?} reads otherwise than a new instance of it",
            device.key[0]
        );
    }
    for (index, device) in devices.iter_mut().enumerate() {
        #[cfg(not(feature = "partial-replicas"))]
        let _ = index;
        let mut before = Vec::new();
        for space in &spaces {
            before.push(reading(&device.engine, *space, &docs).await);
        }
        let platform = Platform::new(
            Arc::clone(&device.store) as Arc<dyn Store>,
            Arc::clone(&device.slot) as Arc<dyn DeviceBoundSlot>,
        );
        // The partial replica is one from its first resolution after open.
        #[cfg(feature = "partial-replicas")]
        let platform = if partial && device.key == [3; 32] {
            platform.holding_streams_only()
        } else {
            platform
        };
        device.engine = Engine::open(
            platform,
            &device.sealed,
            &device.key,
            AdapterRegistry::with_builtins(),
        )
        .await
        .expect("opened again");
        #[cfg(feature = "partial-replicas")]
        if partial && device.key == [3; 32] {
            device.engine.hold_streams_only();
            for (from, held) in delivered.iter().enumerate() {
                if from != index {
                    for (space, events) in spaces.iter().zip(held) {
                        let _ = device.engine.ingest(*space, events.clone()).await;
                    }
                }
            }
        }
        let mut after = Vec::new();
        for space in &spaces {
            after.push(reading(&device.engine, *space, &docs).await);
        }
        assert_eq!(
            before, after,
            "device {:?} read otherwise once opened again",
            device.key[0]
        );
    }
}

proptest! {
    // 24 cases by default; `PROPTEST_CASES` and `PROPTEST_RNG_SEED` run
    // more, from another seed. A failing case is kept in
    // `proptest-regressions/replica/cache_tests.txt` and run first after.
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|cases| cases.parse().ok())
            .unwrap_or(24),
        rng_seed: std::env::var("PROPTEST_RNG_SEED")
            .ok()
            .and_then(|seed| seed.parse().ok())
            .map_or(proptest::test_runner::RngSeed::Random, proptest::test_runner::RngSeed::Fixed),
        ..ProptestConfig::default()
    })]

    #[test]
    fn a_cached_refresh_matches_one_from_scratch(
        ops in prop::collection::vec(op(), 1..16),
        partial in any::<bool>(),
    ) {
        super::CHECK_REFRESHES.store(true, std::sync::atomic::Ordering::Relaxed);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(ops, partial));
    }
}

/// A grant whose parent a partial replica only witnessed: it is placed
/// again once the replica, opened again, fetches the witness again.
#[test]
fn a_partial_replica_places_again_what_rests_on_a_witness() {
    super::CHECK_REFRESHES.store(true, std::sync::atomic::Ordering::Relaxed);
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(
                vec![
                    Op::Edit {
                        device: 0,
                        doc: 1,
                        restricted: false,
                    },
                    Op::Grant {
                        device: 2,
                        history: true,
                    },
                ],
                true,
            ));
    }
}

/// A partial replica removed while it writes: its own edit, concurrent
/// with its removal, is held pending and never applied (units.md, 3.15
/// "Pending, never applied"). Its text leaves the document once the
/// removal arrives, and the device reads the same verdict and text once
/// opened again.
#[test]
fn a_removed_partial_device_reads_its_own_edit_the_same_once_opened_again() {
    super::CHECK_REFRESHES.store(true, std::sync::atomic::Ordering::Relaxed);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(
            vec![
                Op::Grant {
                    device: 2,
                    history: true,
                },
                Op::Deliver {
                    from: 0,
                    to: 2,
                    mask: 2_415_274_292_356_424_431,
                    restricted: false,
                },
                Op::Remove { device: 2 },
                Op::Edit {
                    device: 2,
                    doc: 0,
                    restricted: false,
                },
            ],
            true,
        ));
}

/// Edits in a row, delivered in turn: the refreshes after the first
/// resolve from the one kept, and each matches a resolution from scratch.
#[test]
fn units_placed_after_a_kept_resolution_resolve_from_it() {
    super::CHECK_REFRESHES.store(true, std::sync::atomic::Ordering::Relaxed);
    let before = super::APPENDED.load(std::sync::atomic::Ordering::Relaxed);
    let edit = |device, doc| Op::Edit {
        device,
        doc,
        restricted: false,
    };
    let deliver = |from, to| Op::Deliver {
        from,
        to,
        mask: u64::MAX,
        restricted: false,
    };
    let ops = vec![
        Op::Grant {
            device: 1,
            history: true,
        },
        deliver(0, 1),
        edit(0, 0),
        edit(0, 0),
        edit(1, 0),
        deliver(0, 1),
        deliver(1, 0),
        edit(0, 1),
        edit(1, 1),
        deliver(1, 0),
        edit(0, 0),
    ];
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(ops, false));
    assert!(super::APPENDED.load(std::sync::atomic::Ordering::Relaxed) > before);
}

/// A partial replica given an edit, newest first, before the genesis it
/// rests on: it witnesses the edit once the genesis arrives, and places
/// the grant that rests on it, as it does once opened again.
#[test]
fn a_partial_replica_witnesses_a_unit_that_came_before_the_genesis() {
    super::CHECK_REFRESHES.store(true, std::sync::atomic::Ordering::Relaxed);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(
            vec![
                Op::Edit {
                    device: 0,
                    doc: 0,
                    restricted: false,
                },
                Op::Grant {
                    device: 2,
                    history: true,
                },
                Op::Deliver {
                    from: 0,
                    to: 2,
                    mask: 254_381_535_560_967_646,
                    restricted: false,
                },
            ],
            true,
        ));
}

/// A partial replica removed, then granted again from now on: it takes
/// the removal wrap of the rotation that removed it once, whatever order
/// the events came in, and reads the same once opened again.
#[test]
fn a_partial_replica_granted_again_reads_the_same_once_opened_again() {
    super::CHECK_REFRESHES.store(true, std::sync::atomic::Ordering::Relaxed);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(
            vec![
                Op::Grant {
                    device: 2,
                    history: true,
                },
                Op::Remove { device: 2 },
                Op::Edit {
                    device: 0,
                    doc: 1,
                    restricted: false,
                },
                Op::Grant {
                    device: 2,
                    history: false,
                },
            ],
            true,
        ));
}
