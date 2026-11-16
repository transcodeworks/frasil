//! Skeleton cuts and truncation at the peer (peers.md, "Skeleton cuts" and
//! "Truncation"), over `peers.json`'s `skeleton_cuts` history: P founds the
//! space, grants A administer, releases a stream, and P0 asks for
//! credentials; P checkpoints, its pseudonym signing the cut first; both
//! administrators acknowledge after it, and P then removes A.
//!
//! The cut takes effect once both enrolled slots voted; the peer truncates
//! only once it has been in effect for `cut_retention` on its timeline,
//! here read from a [`ManualClock`]. It then deletes what the plan names,
//! serves a newcomer what it kept, answers `Missing` for what it deleted,
//! and stores a late event whose parent it deleted.

use super::*;
use crate::clock::ManualClock;
use crate::space::{Rules, Space};
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::{Envelope, kind};
use frasil_peers::body::StorageBody;
use frasil_peers::cut::RequestState;
use frasil_peers::decisions::Execution;
use frasil_peers::entries::Rights;
use frasil_store::MemoryStore;
use serde_json::Value as Json;

const CUT: &str = "P0: cut of P checkpoints";
const CHECKPOINT: &str = "P checkpoints";
/// The enrolled slots' votes after the checkpoint: the cut takes effect at
/// the later of the two in the history.
const VOTES: [&str; 2] = ["P0 acknowledges", "A1 acknowledges"];

/// The vote after which every enrolled slot has voted.
fn last_vote(history: &[(String, Vec<u8>)]) -> &'static str {
    VOTES
        .into_iter()
        .max_by_key(|vote| history.iter().position(|(name, _)| name == vote))
        .expect("two votes")
}
/// What the plan deletes: the checkpoint's past but the genesis, the cut,
/// the root and enrolment its slots name, and the release.
const DELETED: [&str; 3] = [
    "P grants A administer",
    "P0 asks for credentials",
    "P0: twin of P grants A administer",
];

fn family() -> Json {
    frasil_testkit::vectors::family::<Json>("peers.json", "skeleton_cuts")
}

/// The history's events, by name, in order.
fn history() -> Vec<(String, Vec<u8>)> {
    events_of(&family()["events"])
}

/// A vector history's events, by name, in order.
fn events_of(events: &Json) -> Vec<(String, Vec<u8>)> {
    events
        .as_array()
        .expect("an events list")
        .iter()
        .map(|row| {
            (
                row["name"].as_str().unwrap().to_owned(),
                frasil_testkit::hex::decode(row["signed"].as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

fn id_of(history: &[(String, Vec<u8>)], name: &str) -> EventId {
    let (_, signed) = history
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("{name} is in the history"));
    frasil_events::decode(signed).unwrap().id()
}

fn core(clock: &Arc<ManualClock>) -> Arc<Core> {
    core_with(
        clock,
        Settings {
            cut_retention: frasil_peers::limits::CUT_RETENTION,
            ..Settings::open_core()
        },
    )
}

fn core_with(clock: &Arc<ManualClock>, settings: Settings) -> Arc<Core> {
    let clock: Arc<dyn crate::clock::Clock> = clock.clone();
    let store: Arc<dyn frasil_store::Store> = Arc::new(MemoryStore::new());
    Arc::new(Core::open(settings, Records::new(store), clock).unwrap())
}

fn link(core: &Core) -> u64 {
    let (tx, rx) = mpsc::channel(1024);
    std::mem::forget(rx);
    core.link(tx)
}

/// A grant that may store `signed`: a skeleton event under its author's
/// pseudonym.
fn grant_for(signed: &[u8]) -> Grant {
    let event = frasil_events::decode(signed).unwrap();
    let mut grant = Grant {
        rights: Rights::STORE_AND_RELEASE.union(Rights::ERASE),
        ..Grant::default()
    };
    if event.kind() == kind::STORAGE {
        grant.pseudonym = Some(*event.author());
    }
    grant
}

async fn store(core: &Core, link: u64, space: EventId, signed: &[u8], now: Reading) -> StoreAnswer {
    let mut grant = grant_for(signed);
    core.store(link, &mut grant, space, signed, now).await
}

/// The cut the space's skeleton starts from.
fn cut_in_effect(core: &Core, space: EventId) -> Option<EventId> {
    core.read_blocking(space, |held| held.skeleton().cut())
        .expect("an open space")
}

#[tokio::test]
async fn a_cut_takes_effect_and_the_peer_truncates_after_cut_retention() {
    let history = history();
    let space = id_of(&history, "P creates the space");
    let cut = id_of(&history, CUT);
    let checkpoint = id_of(&history, CHECKPOINT);
    let clock = Arc::new(ManualClock::new(1000));
    let core = core(&clock);
    let founder = link(&core);

    // The space checkpoints; the cut takes effect once the last enrolled
    // slot voted after the checkpoint.
    let last = last_vote(&history);
    for (name, signed) in &history {
        if name == last {
            assert_eq!(cut_in_effect(&core, space), None, "{last} is not in");
        }
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
        if name == last {
            assert_eq!(cut_in_effect(&core, space), Some(cut));
        }
    }
    let deleted: Vec<EventId> = DELETED.iter().map(|name| id_of(&history, name)).collect();
    let usage = core
        .read_blocking(space, |held| {
            assert_eq!(held.skeleton().cut(), Some(cut));
            assert_eq!(held.kept(), None);
            assert_eq!(held.skeleton().administrators().len(), 1);
            held.used()
        })
        .unwrap();
    let deleted_bytes: u64 = history
        .iter()
        .filter(|(name, _)| DELETED.contains(&name.as_str()))
        .map(|(_, signed)| signed.len() as u64)
        .sum();

    // Before cut_retention has passed, nothing is truncated: the request in
    // the checkpoint's past is carried out within erasure_timeout, and the
    // peer still holds every event.
    core.sweep(clock.now()).await;
    clock.advance(frasil_peers::limits::CUT_RETENTION - 10);
    core.sweep(clock.now()).await;
    core.read_blocking(space, |held| {
        assert_eq!(held.kept(), None);
        for id in &deleted {
            assert!(held.log.contains(*id), "held until cut_retention");
        }
    })
    .unwrap();

    // Once it has, the sweep truncates under the cut.
    clock.advance(10);
    core.sweep(clock.now()).await;
    core.read_blocking(space, |held| {
        assert_eq!(held.truncated, Some((cut, checkpoint)));
        for id in &deleted {
            assert!(!held.log.contains(*id), "deleted");
            assert_eq!(held.stubs.get(id), Some(&None), "its ID kept");
        }
        // The genesis, the cut, its checkpoint, the root and enrolment the
        // cut names and the release are kept.
        for name in [
            "P creates the space",
            CUT,
            CHECKPOINT,
            "P0: root",
            "A1 enrols",
            "P releases stream x",
        ] {
            assert!(held.log.contains(id_of(&history, name)), "{name} kept");
        }
        // Usage follows the deletion.
        assert_eq!(held.used(), usage - deleted_bytes);
        // The skeleton starts from the kept cut, as before.
        let skeleton = held.skeleton();
        assert_eq!(skeleton.cut(), Some(cut));
        assert_eq!(skeleton.administrators().len(), 1);
        // A space reopened from its snapshot keeps the truncation.
        let rules = Rules {
            cap: held.entries.cap(),
            file_versions: false,
        };
        let objects = held.objects.clone().into_iter().collect();
        let reopened = Space::from_snapshot(&held.to_snapshot(), objects, rules).unwrap();
        assert_eq!(reopened.truncated, held.truncated);
        assert_eq!(reopened.stubs, held.stubs);
    })
    .unwrap();

    // A newcomer under catch-up is served what the peer kept, and `Missing`
    // for what it deleted.
    core.read_blocking(space, |held| {
        let mut grant = Grant {
            rights: Rights::CATCH_UP,
            ..Grant::default()
        };
        let reply = crate::sync::View::new(held, &mut grant).on_heads(&[], None, &[]);
        let mut answer = reply.answer.expect("events to serve");
        let mut served = BTreeSet::new();
        while let Some((_, ids)) = answer.batch(held) {
            served.extend(ids);
        }
        let mut names: Vec<&str> = history
            .iter()
            .filter(|(_, signed)| served.contains(&frasil_events::decode(signed).unwrap().id()))
            .map(|(name, _)| name.as_str())
            .collect();
        names.sort_unstable();
        let vectors = family();
        let mut expected: Vec<&str> = vectors["truncated"]["holds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        expected.sort_unstable();
        assert_eq!(names, expected);

        // The checkpoint's envelope is served by ID to whoever may fetch
        // the space's events, catch-up included: truncation never deletes
        // it.
        let reply = crate::sync::View::new(held, &mut grant).on_want(&[checkpoint], &[], &[], &[]);
        let mut answer = reply.answer.expect("an answer");
        let (_, ids) = answer.batch(held).expect("the checkpoint is served");
        assert_eq!(ids, vec![checkpoint]);
        assert!(answer.next_after().is_none(), "nothing is missing");

        let reply = crate::sync::View::new(held, &mut grant).on_want(&deleted, &[], &[], &[]);
        let mut answer = reply.answer.expect("an answer");
        assert!(answer.batch(held).is_none(), "no deleted event is served");
        let missing = answer.next_after().expect("Missing");
        for id in &deleted {
            assert!(
                missing.windows(32).any(|window| window == id.as_bytes()),
                "Missing names each deleted event"
            );
        }
    })
    .unwrap();

    // A late event, which does not follow the checkpoint and whose parent
    // the peer deleted, is placed as if that parent were stored, and kept:
    // a skeleton event runs no check but its body's, and is `Late`, with
    // no effect (peers.md, "Skeleton cuts", late skeleton events). A late
    // change no space event names is stored too, not held.
    let signer = Signer::from_seeds(&[9; 32], &[59; 32], None);
    let late_event = |seq: u64, prev: Option<EventId>, body: StorageBody| {
        Envelope {
            kind: kind::STORAGE,
            log: Some(space),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents: [id_of(&history, "P0 asks for credentials")]
                .into_iter()
                .chain(prev)
                .collect(),
            cuts: Vec::new(),
            body: body.encode(),
            scheme: Scheme::Hybrid,
        }
        .sign(&signer)
    };
    let late = late_event(1, None, StorageBody::Ack);
    let late_id = frasil_events::decode(&late).unwrap().id();
    let answer = store(&core, founder, space, &late, clock.now()).await;
    assert_eq!(answer, StoreAnswer::Acknowledge(late_id));
    let change = late_event(
        2,
        Some(late_id),
        StorageBody::Change {
            twin: [3; 32],
            salt: [4; 32],
            effect: frasil_peers::body::ChangeEffect::Lower(frasil_peers::body::SlotId::new(
                [5; 32], 0, cut,
            )),
        },
    );
    let change_id = frasil_events::decode(&change).unwrap().id();
    let answer = store(&core, founder, space, &change, clock.now()).await;
    assert_eq!(answer, StoreAnswer::Acknowledge(change_id));
    core.read_blocking(space, |held| {
        assert!(held.log.contains(late_id) && held.log.contains(change_id));
        let late_status = Some(frasil_peers::skeleton::Status::Void {
            class: frasil_peers::PeersClass::Late,
            by: None,
        });
        let skeleton = held.skeleton();
        assert_eq!(skeleton.status(late_id), late_status);
        assert_eq!(skeleton.status(change_id), late_status);
        assert!(!skeleton.view().contains(&late_id), "outside the world");
        assert!(held.servable(change_id, &held.released_streams()));
        assert_eq!(held.truncated, Some((cut, checkpoint)));
    })
    .unwrap();
}

#[tokio::test]
async fn a_peer_with_no_cut_in_effect_truncates_nothing() {
    let history = history();
    let space = id_of(&history, "P creates the space");
    let clock = Arc::new(ManualClock::new(1000));
    let core = core(&clock);
    let founder = link(&core);
    // Up to the checkpoint and the first vote: the other slot never votes.
    let last = last_vote(&history);
    for (name, signed) in &history {
        if name == last {
            break;
        }
        store(&core, founder, space, signed, clock.now()).await;
    }
    clock.advance(2 * frasil_peers::limits::CUT_RETENTION);
    core.sweep(clock.now()).await;
    core.read_blocking(space, |held| {
        assert_eq!(held.skeleton().cut(), None);
        assert_eq!(held.kept(), None);
        for name in DELETED {
            assert!(held.log.contains(id_of(&history, name)), "{name} kept");
        }
    })
    .unwrap();
}

/// `peers.json`'s `skeleton_cuts.truncation_wait`: P and A administer, A
/// enrolled; P grants B administer, and B has not enrolled. P0 asks for
/// erasure, P checkpoints, and P0 and A1 acknowledge after it. The cut's
/// standing entries name B's slot, so the cut waits for it (peers.md,
/// "Skeleton cuts", waited and excused slots): no cut is in effect, the
/// erasure waits for B's slot in the skeleton from the root, past
/// `cut_retention`, and nothing is truncated. B's pseudonym enrols after the
/// checkpoint, the enrolment B's vote: the cut takes effect, the erasure, of
/// its past, is stable before it, and is carried out.
#[tokio::test]
async fn truncation_waits_for_an_erasure_of_the_checkpoints_past() {
    let vectors = family();
    let wait = &vectors["truncation_wait"];
    let history = events_of(&wait["events"]);
    let space = id_of(&history, "P creates the space");
    let cut = id_of(&history, "P0: cut of P checkpoints");
    let erase = id_of(&history, "P0 asks for erasure");
    let clock = Arc::new(ManualClock::new(1000));
    let retention = frasil_peers::limits::CUT_RETENTION;
    let core = core_with(
        &clock,
        Settings {
            cut_retention: retention,
            erasure_timeout: 4 * retention,
            ..Settings::open_core()
        },
    );
    let founder = link(&core);
    let late = ["B1 enrols", "B1 acknowledges"];
    for (name, signed) in history
        .iter()
        .filter(|(name, _)| !late.contains(&name.as_str()))
    {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    assert_eq!(cut_in_effect(&core, space), None, "the cut waits for B");
    assert_eq!(
        wait["may_truncate"]["before B enrols"]["in_effect"],
        Json::Array(Vec::new())
    );
    assert_eq!(
        wait["may_truncate"]["before B enrols"]["may_truncate"],
        Json::Bool(false)
    );

    // Past cut_retention, the erasure still waits for B's slot, and nothing
    // is truncated.
    clock.advance(retention + 10);
    core.sweep(clock.now()).await;
    assert!(!core.tombstoned(&space), "the erasure waits");
    core.read_blocking(space, |held| {
        assert_eq!(held.truncated, None, "truncation waits");
        let skeleton = held.skeleton();
        assert!(skeleton.is_valid(erase));
        assert!(!skeleton.is_stable(erase, None));
        let awaited = held.cuts().awaiting(cut);
        assert_eq!(awaited.len(), 1, "B's slot");
    })
    .unwrap();

    // B's pseudonym enrols and acknowledges after the checkpoint: the cut
    // takes effect, and the erasure is stable before it, and carried out.
    // The peer may carry it out at the enrolment already, and then refuses
    // what follows as `erased`.
    for (name, signed) in history
        .iter()
        .filter(|(name, _)| late.contains(&name.as_str()))
    {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        let erased = core.tombstoned(&space)
            && matches!(&answer, StoreAnswer::Refused(reason) if reason == "erased");
        assert!(
            erased || !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    assert_eq!(
        wait["may_truncate"]["after B acknowledges"]["may_truncate"],
        Json::Bool(true)
    );
    core.sweep(clock.now()).await;
    assert!(core.tombstoned(&space), "the erasure is carried out");
}

/// `peers.json`'s `skeleton_cuts.late_enrolment`, at a live peer: P and A
/// administer, A enrolled; P grants B administer and P0 asks for erasure.
/// P checkpoints without B's enrolment, and P0 and A1 vote; the cut's
/// standing entries name B's slot, so it waits for B. B's enrolment,
/// concurrent with the checkpoint, arrives as the first event of B1's
/// connection, which presented B1 before the peer knew it; with no cut in
/// effect it is no late event, and B1's acknowledgement and B's device's
/// votes are stored too, none of them B's vote for the cut. The erasure, in
/// the checkpoint's past, waits for B's slot past `cut_retention`, and
/// truncation with it. B enrols the slot again after the checkpoint (B2):
/// the enrolment is B's vote, the cut takes effect, B1's enrolment is late
/// under it and B1 a late pseudonym, and the erasure, acknowledged for B's
/// slot through B2, is carried out.
#[tokio::test]
async fn a_late_enrolment_is_stored_and_the_slot_enrolled_again() {
    let vectors = family();
    let case = &vectors["late_enrolment"];
    let prefix = case["history_prefix"].as_str().unwrap();
    let history = events_of(&case["events"]);
    let signed = |name: &str| {
        history
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, signed)| signed.clone())
            .unwrap_or_else(|| panic!("{name} is in the history"))
    };
    let space = id_of(&history, "P creates the space");
    let cut = id_of(&history, "P0: cut of P checkpoints");
    let erase = id_of(&history, "P0 asks for erasure");
    const LATE_ENROLMENT: &str = "B1 enrols, concurrently with the checkpoint";
    const LATE_ACK: &str = "B1 acknowledges, on its late enrolment";
    const B_DEVICE: [&str; 2] = [
        "B anchors on its late enrolment",
        "B votes, its prev the late anchor",
    ];
    const AGAIN: &str = "B2 enrols the same slot again, after the checkpoint";
    let held_back = [LATE_ENROLMENT, LATE_ACK, B_DEVICE[0], B_DEVICE[1], AGAIN];
    let clock = Arc::new(ManualClock::new(1000));
    let retention = frasil_peers::limits::CUT_RETENTION;
    let core = core_with(
        &clock,
        Settings {
            cut_retention: retention,
            erasure_timeout: 4 * retention,
            ..Settings::open_core()
        },
    );
    let founder = link(&core);
    for (name, signed) in history
        .iter()
        .filter(|(name, _)| !held_back.contains(&name.as_str()) && !name.starts_with(AGAIN))
    {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    assert_eq!(cut_in_effect(&core, space), None, "the cut waits for B");

    // B1 presented before the peer held its enrolment: the enrolment is the
    // first event its connection stores, and is accepted.
    let enrolment = frasil_events::decode(&signed(LATE_ENROLMENT)).unwrap();
    let seed = frasil_crypto::primitives::sha256(&[
        b"frasil spec example/",
        format!("{prefix}/B1/ed25519").as_bytes(),
    ]);
    let b1 = *enrolment.author();
    let binding = [7; 32];
    let presented = frasil_peers::proof::presented(
        &binding,
        space.as_bytes(),
        frasil_peers::proof::Credential::Pseudonym.code(),
        &b1.0,
    );
    let proof = frasil_peers::proof::prove(&seed, &presented).to_vec();
    assert!(frasil_peers::proof::verify(
        &enrolment.ed().0,
        &presented,
        &proof
    ));
    let b1_link = link(&core);
    let mut grant = Grant {
        rights: Rights::ERASE,
        pseudonym: Some(b1),
        provisional: Some(Deferred { presented, proof }),
        ..Grant::default()
    };
    let answer = core
        .store(
            b1_link,
            &mut grant,
            space,
            &signed(LATE_ENROLMENT),
            clock.now(),
        )
        .await;
    assert_eq!(answer, StoreAnswer::Acknowledge(enrolment.id()));
    assert!(grant.provisional.is_none(), "the connection is accepted");
    let ack = frasil_events::decode(&signed(LATE_ACK)).unwrap().id();
    let answer = core
        .store(b1_link, &mut grant, space, &signed(LATE_ACK), clock.now())
        .await;
    assert_eq!(answer, StoreAnswer::Acknowledge(ack));
    for name in B_DEVICE {
        let answer = store(&core, founder, space, &signed(name), clock.now()).await;
        assert!(
            matches!(answer, StoreAnswer::Acknowledge(_)),
            "{name}: {answer:?}"
        );
    }
    core.read_blocking(space, |held| {
        assert_eq!(held.skeleton().cut(), None, "B's slot has not voted");
        assert_eq!(held.pseudonym_ed(&b1), Some(*enrolment.ed()));
        assert!(!held.is_late_pseudonym(&b1));
    })
    .unwrap();

    // Past cut_retention, the erasure still waits for B's slot, and
    // truncation with it.
    clock.advance(retention + 10);
    core.sweep(clock.now()).await;
    assert!(!core.tombstoned(&space), "the erasure waits");
    core.read_blocking(space, |held| {
        assert_eq!(held.truncated, None, "truncation waits");
        assert!(held.log.contains(erase));
    })
    .unwrap();
    assert_eq!(
        case["peer"]["may_truncate"]["before B enrols again"],
        Json::Bool(false)
    );

    // B enrols the slot again after the checkpoint: its vote. The cut takes
    // effect; B2 is enrolled in B's slot of the cut, B1's enrolment is late
    // and B1 a late pseudonym, asked nothing.
    let again = frasil_events::decode(&signed(AGAIN)).unwrap();
    let mut trial = core
        .read_blocking(space, |held| held.clone())
        .expect("an open space");
    let (index, op) = (
        trial.next_index,
        Op::Event {
            signed: signed(AGAIN),
            sight: clock.now(),
            entry: None,
        },
    );
    assert_eq!(
        trial.check_skeleton(&again).map(|checked| checked.enrols),
        Ok(Some(*again.author()))
    );
    trial.apply(index, &op, Some(again.clone()));
    let late_status = Some(frasil_peers::skeleton::Status::Void {
        class: frasil_peers::PeersClass::Late,
        by: None,
    });
    let skeleton = trial.skeleton();
    assert_eq!(skeleton.cut(), Some(cut));
    assert!(skeleton.is_valid(again.id()));
    let slot = skeleton.slot_of(again.author()).expect("enrolled");
    assert!(skeleton.is_cut_slot(slot));
    assert_eq!(skeleton.status(enrolment.id()), late_status);
    assert_eq!(skeleton.status(ack), late_status);
    assert_eq!(skeleton.slot_of(&b1), None, "enrolled in no slot");
    let now = trial.sights[&ack];
    assert!(
        trial.awaiting_lists(&skeleton, None, [b1], now, 4 * retention)[&b1].is_empty(),
        "a late pseudonym is asked nothing"
    );
    drop(skeleton);
    assert!(trial.is_late_pseudonym(&b1));
    let answer = store(&core, founder, space, &signed(AGAIN), clock.now()).await;
    assert_eq!(answer, StoreAnswer::Acknowledge(again.id()));
    assert_eq!(
        case["peer"]["may_truncate"]["after B enrols again"],
        Json::Bool(true)
    );
    assert!(core.tombstoned(&space), "the erasure is carried out");
}

// ---------------------------------------------------------------------------
// Requests concurrent with a cut, releases across truncation, late
// connections and truncated events sent again.

/// A storage event signed by `signer` in `space`, with explicit parents
/// and cuts.
fn signed_storage(
    signer: &Signer,
    space: EventId,
    seq: u64,
    prev: Option<EventId>,
    parents: Vec<EventId>,
    cuts: Vec<EventId>,
    body: &StorageBody,
) -> Vec<u8> {
    Envelope {
        kind: kind::STORAGE,
        log: Some(space),
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq,
        prev,
        parents: parents.into_iter().chain(prev).collect(),
        cuts,
        body: body.encode(),
        scheme: Scheme::Hybrid,
    }
    .sign(signer)
}

/// `peers.json`'s `skeleton_cuts.concurrent_request` at a live peer
/// (peers.md, "Erasure", steps 0 and 1): A1 asks for erasure apart while P
/// checkpoints without it. Past `erasure_timeout`, the peer does not carry
/// it out while the cut can still take effect; once P and A vote, the cut
/// takes effect, the erasure is late and void, and A1's erasure signed again
/// after the checkpoint is carried out.
#[tokio::test]
async fn an_erasure_waits_for_a_concurrent_cut_then_is_void() {
    let vectors = family();
    let case = &vectors["concurrent_request"];
    let history = events_of(&case["events"]);
    let space = id_of(&history, "P creates the space");
    let cut = id_of(&history, "P0: cut of P checkpoints, without the erasure");
    let erase = id_of(&history, "A1 asks for erasure, apart");
    const AGAIN: &str = "A1 asks for erasure again, after the checkpoint";
    const VOTES: [&str; 4] = ["P votes", "P0 votes", "A votes", "A1 votes"];
    let clock = Arc::new(ManualClock::new(1000));
    let timeout = 3600;
    let core = core_with(
        &clock,
        Settings {
            cut_retention: frasil_peers::limits::CUT_RETENTION,
            erasure_timeout: timeout,
            ..Settings::open_core()
        },
    );
    let founder = link(&core);
    let outcome = |core: &Core, id: EventId| {
        core.read_blocking(space, |held| held.outcomes.get(&id).copied())
            .unwrap()
    };
    for (name, signed) in history
        .iter()
        .filter(|(name, _)| !VOTES.contains(&name.as_str()) && name != AGAIN)
    {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    assert_eq!(
        case["states"]["the peer holds the erasure and the cut"]["erasure"],
        "Wait"
    );
    clock.advance(2 * timeout);
    core.sweep(clock.now()).await;
    assert!(!core.tombstoned(&space), "the erasure waits for the cut");
    assert_eq!(outcome(&core, erase), Some(Execution::Wait));
    core.read_blocking(space, |held| {
        let cuts = held.cuts();
        assert!(cuts.can_take_effect(cut));
        assert_eq!(cuts.request_state(erase), RequestState::Wait);
    })
    .unwrap();

    // The votes: the cut takes effect, the erasure is late, and void.
    for name in VOTES {
        let answer = store(
            &core,
            founder,
            space,
            &signed_of(&history, name),
            clock.now(),
        )
        .await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    assert_eq!(cut_in_effect(&core, space), Some(cut));
    core.sweep(clock.now()).await;
    assert!(
        !core.tombstoned(&space),
        "a late erasure is never carried out"
    );
    assert_eq!(outcome(&core, erase), Some(Execution::Void));
    assert_eq!(case["states"]["the cut in effect"]["erasure"], "Late");

    // Signed again after the checkpoint, it is free, and carried out past
    // its timeout.
    let answer = store(
        &core,
        founder,
        space,
        &signed_of(&history, AGAIN),
        clock.now(),
    )
    .await;
    assert!(!matches!(answer, StoreAnswer::Refused(_)), "{answer:?}");
    clock.advance(2 * timeout);
    core.sweep(clock.now()).await;
    assert!(
        core.tombstoned(&space),
        "the erasure signed again is carried out"
    );
}

fn signed_of(history: &[(String, Vec<u8>)], name: &str) -> Vec<u8> {
    history
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, signed)| signed.clone())
        .unwrap_or_else(|| panic!("{name} is in the history"))
}

/// `peers.json`'s `skeleton_cuts.release_order` at a live peer (peers.md,
/// "Truncation" and "Release and restore"): P restores stream x, anchors,
/// then releases it, and checkpoints. Truncating, the peer keeps the
/// release alone, the maximal request of the stream, notes it in its
/// journal, and still finds x released, reopened from its snapshot or
/// replayed from its journal too.
#[tokio::test]
async fn truncation_keeps_the_maximal_releases_and_restores() {
    let vectors = family();
    let case = &vectors["release_order"];
    let history = events_of(&case["events"]);
    let space = id_of(&history, "P creates the space");
    let cut = id_of(&history, "P0: cut of P checkpoints");
    let checkpoint = id_of(&history, "P checkpoints");
    let release = id_of(&history, "P releases x, after its restore");
    let restore = id_of(&history, "P restores x");
    let anchor = id_of(&history, "P anchors");
    let clock = Arc::new(ManualClock::new(1000));
    let core = core(&clock);
    let founder = link(&core);
    for (name, signed) in &history {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    assert_eq!(cut_in_effect(&core, space), Some(cut));
    let stream = core
        .read_blocking(space, |held| {
            let stream = held.writer_requests[&release].stream().unwrap();
            assert!(held.is_released(&stream), "released, kept everything");
            stream
        })
        .unwrap();
    assert_eq!(case["released"]["kept everything"], Json::Bool(true));

    clock.advance(frasil_peers::limits::CUT_RETENTION + 10);
    core.sweep(clock.now()).await;
    core.read_blocking(space, |held| {
        assert_eq!(held.truncated, Some((cut, checkpoint)));
        assert!(held.log.contains(release), "the maximal request is kept");
        assert!(!held.log.contains(restore) && !held.log.contains(anchor));
        assert_eq!(held.kept_requests, BTreeSet::from([release]));
        let mut names: Vec<&str> = history
            .iter()
            .filter(|(_, signed)| {
                held.log
                    .contains(frasil_events::decode(signed).unwrap().id())
            })
            .map(|(name, _)| name.as_str())
            .collect();
        names.sort_unstable();
        let mut expected: Vec<&str> = case["truncated_holds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        expected.sort_unstable();
        assert_eq!(names, expected);
        assert!(held.is_released(&stream), "released, truncated");
        // Reopened from its snapshot, and replayed from its journal.
        let rules = Rules {
            cap: held.entries.cap(),
            file_versions: false,
        };
        let objects: Vec<_> = held.objects.clone().into_iter().collect();
        let reopened = Space::from_snapshot(&held.to_snapshot(), objects.clone(), rules).unwrap();
        assert_eq!(reopened.kept_requests, held.kept_requests);
        assert!(reopened.is_released(&stream));
        let journal: Vec<(u64, Op)> = held
            .journal()
            .into_iter()
            .map(|(index, op, _)| (index, op))
            .collect();
        let replayed = Space::replay(journal, objects, rules).unwrap();
        assert_eq!(replayed.kept_requests, held.kept_requests);
        assert!(replayed.is_released(&stream));
    })
    .unwrap();
    assert_eq!(case["released"]["truncated"], Json::Bool(true));
}

/// peers.md, "Skeleton cuts", what a late enrolment opens, and "No refusal
/// for standing": with the vector's cut in effect, X's enrolment, which
/// does not follow the checkpoint, is late. It is the first event of X's
/// connection, which presented X provisionally and holds the store right
/// besides; the connection may then store X's late events alone, each with
/// no effect: X's event after the checkpoint and another author's late event
/// are refused (`not_authorized`). A late enrolment with a `seq` past 1 is
/// refused for itself. On another connection, X's event after the checkpoint,
/// whose author is enrolled in no slot, is stored with no effect.
#[tokio::test]
async fn a_late_enrolments_connection_stores_its_late_events_alone() {
    let history = history();
    let space = id_of(&history, "P creates the space");
    let cut = id_of(&history, CUT);
    let checkpoint = id_of(&history, CHECKPOINT);
    let past = id_of(&history, "P0 asks for credentials");
    let clock = Arc::new(ManualClock::new(1000));
    let core = core(&clock);
    let founder = link(&core);
    for (name, signed) in &history {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    assert_eq!(cut_in_effect(&core, space), Some(cut));
    let slot = core
        .read_blocking(space, |held| {
            let skeleton = held.skeleton();
            skeleton.administrators()[0]
        })
        .unwrap();
    let pseudonym = |n: u8| Signer::from_seeds(&[n; 32], &[n + 50; 32], None);
    let enrol = |signer: &Signer| StorageBody::Enrol {
        slot,
        mldsa: signer.mldsa_public().to_vec(),
        slot_mldsa: signer.mldsa_public().to_vec(),
        authorization: vec![0xaa; frasil_peers::limits::SIGNATURE_BYTES],
        binding: vec![0xbb; frasil_peers::limits::BINDING_BYTES],
    };
    let x = pseudonym(21);
    let late_enrolment = signed_storage(&x, space, 1, None, vec![past], vec![], &enrol(&x));
    let enrolment = frasil_events::decode(&late_enrolment).unwrap();
    let binding = [8; 32];
    let presented = frasil_peers::proof::presented(
        &binding,
        space.as_bytes(),
        frasil_peers::proof::Credential::Pseudonym.code(),
        &x.device_id().0,
    );
    let proof = frasil_peers::proof::prove(&[21; 32], &presented).to_vec();
    let x_link = link(&core);
    let mut grant = Grant {
        rights: Rights::STORE_AND_RELEASE.union(Rights::ERASE),
        pseudonym: Some(*x.device_id()),
        provisional: Some(Deferred { presented, proof }),
        ..Grant::default()
    };
    let answer = core
        .store(x_link, &mut grant, space, &late_enrolment, clock.now())
        .await;
    assert_eq!(answer, StoreAnswer::Acknowledge(enrolment.id()));
    assert!(grant.provisional.is_none(), "the connection is accepted");
    core.read_blocking(space, |held| {
        let skeleton = held.skeleton();
        assert_eq!(
            skeleton.status(enrolment.id()),
            Some(frasil_peers::skeleton::Status::Void {
                class: frasil_peers::PeersClass::Late,
                by: None,
            })
        );
        assert!(held.is_late_pseudonym(x.device_id()));
    })
    .unwrap();
    // X's late acknowledgement: stored, with no effect.
    let late_ack = signed_storage(
        &x,
        space,
        2,
        Some(enrolment.id()),
        vec![],
        vec![],
        &StorageBody::Ack,
    );
    let late_ack_id = frasil_events::decode(&late_ack).unwrap().id();
    let answer = core
        .store(x_link, &mut grant, space, &late_ack, clock.now())
        .await;
    assert_eq!(answer, StoreAnswer::Acknowledge(late_ack_id));
    // X's acknowledgement after the checkpoint: refused on this connection.
    let after = signed_storage(
        &x,
        space,
        3,
        Some(late_ack_id),
        vec![checkpoint],
        vec![checkpoint],
        &StorageBody::Ack,
    );
    let answer = core
        .store(x_link, &mut grant, space, &after, clock.now())
        .await;
    assert_eq!(answer, StoreAnswer::Refused("not_authorized".into()));
    // Another author's late event: refused on this connection too.
    let y = pseudonym(22);
    let other = signed_storage(&y, space, 1, None, vec![past], vec![], &StorageBody::Ack);
    let answer = core
        .store(x_link, &mut grant, space, &other, clock.now())
        .await;
    assert_eq!(answer, StoreAnswer::Refused("not_authorized".into()));
    // On another connection, it is stored: its author is no pseudonym the
    // peer holds, and it is late, with no effect.
    let other_id = frasil_events::decode(&other).unwrap().id();
    let answer = store(&core, founder, space, &other, clock.now()).await;
    assert_eq!(answer, StoreAnswer::Acknowledge(other_id));
    // A late enrolment whose `seq` is past 1 is refused for itself.
    let z = pseudonym(23);
    let first = signed_storage(&z, space, 1, None, vec![past], vec![], &StorageBody::Ack);
    let first_id = frasil_events::decode(&first).unwrap().id();
    assert_eq!(
        store(&core, founder, space, &first, clock.now()).await,
        StoreAnswer::Acknowledge(first_id)
    );
    let second = signed_storage(&z, space, 2, Some(first_id), vec![], vec![], &enrol(&z));
    assert_eq!(
        store(&core, founder, space, &second, clock.now()).await,
        StoreAnswer::Refused("bad_signature".into())
    );
    // X's event after the checkpoint, relayed by a connection with the
    // store right: its author is enrolled in no slot of the world after the
    // cut, and it is stored with no effect, never refused for that
    // (peers.md, 3.11, "No refusal for standing").
    let after_id = frasil_events::decode(&after).unwrap().id();
    let mut relaying = Grant {
        rights: Rights::STORE_AND_RELEASE,
        ..Grant::default()
    };
    let answer = core
        .store(founder, &mut relaying, space, &after, clock.now())
        .await;
    assert_eq!(answer, StoreAnswer::Acknowledge(after_id));
    core.read_blocking(space, |held| {
        let skeleton = held.skeleton();
        assert_eq!(
            skeleton.status(after_id),
            Some(frasil_peers::skeleton::Status::Void {
                class: frasil_peers::PeersClass::NotAuthorized,
                by: None,
            })
        );
        assert_eq!(skeleton.administrators().len(), 1, "P, A removed");
        assert_eq!(skeleton.slot_of(x.device_id()), None);
    })
    .unwrap();
}

/// peers.md, "Truncation": an event the peer deleted when it truncated,
/// sent to it again, is acknowledged as an identical retry and not stored
/// again, nor given a verdict; a `Want` for it is still answered
/// `Missing`.
#[tokio::test]
async fn a_truncated_event_sent_again_is_acknowledged_and_not_stored() {
    let history = history();
    let space = id_of(&history, "P creates the space");
    let cut = id_of(&history, CUT);
    let checkpoint = id_of(&history, CHECKPOINT);
    let clock = Arc::new(ManualClock::new(1000));
    let core = core(&clock);
    let founder = link(&core);
    for (_, signed) in &history {
        store(&core, founder, space, signed, clock.now()).await;
    }
    clock.advance(frasil_peers::limits::CUT_RETENTION + 10);
    core.sweep(clock.now()).await;
    let deleted = "P0 asks for credentials";
    let id = id_of(&history, deleted);
    let (usage, stubs) = core
        .read_blocking(space, |held| {
            assert_eq!(held.truncated, Some((cut, checkpoint)));
            assert!(!held.log.contains(id));
            (held.used(), held.stubs.clone())
        })
        .unwrap();
    for name in DELETED {
        let answer = store(
            &core,
            founder,
            space,
            &signed_of(&history, name),
            clock.now(),
        )
        .await;
        assert_eq!(
            answer,
            StoreAnswer::Acknowledge(id_of(&history, name)),
            "{name}"
        );
    }
    core.sweep(clock.now()).await;
    core.read_blocking(space, |held| {
        assert!(!held.log.contains(id), "not stored again");
        assert!(!held.journal_of.contains_key(&id));
        assert_eq!(held.skeleton().status(id), None, "no verdict");
        assert_eq!(held.used(), usage);
        assert_eq!(held.stubs, stubs);
        let mut grant = Grant {
            rights: Rights::CATCH_UP,
            ..Grant::default()
        };
        let reply = crate::sync::View::new(held, &mut grant).on_want(&[id], &[], &[], &[]);
        let mut answer = reply.answer.expect("an answer");
        assert!(answer.batch(held).is_none(), "not served");
        let missing = answer.next_after().expect("Missing");
        assert!(missing.windows(32).any(|window| window == id.as_bytes()));
    })
    .unwrap();
}

/// `peers.json`'s `skeleton_cuts.detached` at a live peer (peers.md,
/// "Skeleton cuts", step 3): P's device names its pseudonym's cut in a
/// checkpoint that does not cite it. No stored space event both names and
/// cites the cut, so the peer holds it pending, as a change no space event
/// names: `Unnamed`, never acknowledged or served as stored, and dropped
/// after `orphan_grace`.
#[tokio::test]
async fn a_cut_its_checkpoint_does_not_cite_is_held_unnamed_and_dropped() {
    let vectors = family();
    let case = &vectors["detached"];
    let history = events_of(&case["events"]);
    let space = id_of(&history, "P creates the space");
    let cut = id_of(
        &history,
        "P0: cut of P checkpoints, naming a cut it does not cite",
    );
    let checkpoint = id_of(&history, "P checkpoints, naming a cut it does not cite");
    let clock = Arc::new(ManualClock::new(1000));
    let core = core(&clock);
    let founder = link(&core);
    for (name, signed) in &history {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        if frasil_events::decode(signed).unwrap().id() == cut {
            assert_eq!(answer, StoreAnswer::Held(None), "{name}: held");
        } else {
            assert!(
                !matches!(answer, StoreAnswer::Refused(_)),
                "{name}: {answer:?}"
            );
        }
    }
    assert_eq!(case["cut"], "Unnamed");
    let grace = Settings::open_core().orphan_grace;
    core.read_blocking(space, |held| {
        assert!(held.log.contains(checkpoint));
        assert!(held.unnamed(cut), "held unnamed");
        let cuts = held.cuts();
        assert_eq!(cuts.checkpoint_of(cut), None);
        assert_eq!(
            cuts.validity(cut),
            frasil_peers::skeleton::Status::Void {
                class: frasil_peers::PeersClass::Unnamed,
                by: None,
            }
        );
        assert!(cuts.chain().is_empty());
        assert!(!held.servable(cut, &held.released_streams()));
        assert_eq!(held.retry(cut), Some(Stored::Retry { acknowledge: false }));
        // Neither served by ID nor to a newcomer.
        let mut grant = Grant {
            rights: Rights::CATCH_UP,
            ..Grant::default()
        };
        let reply = crate::sync::View::new(held, &mut grant).on_want(&[cut], &[], &[], &[]);
        let mut answer = reply.answer.expect("an answer");
        assert!(answer.batch(held).is_none(), "not served");
        let reply = crate::sync::View::new(held, &mut grant).on_heads(&[], None, &[]);
        let mut answer = reply.answer.expect("events to serve");
        while let Some((_, ids)) = answer.batch(held) {
            assert!(!ids.contains(&cut), "not served to a newcomer");
        }
    })
    .unwrap();
    // Before orphan_grace it stays; after it, it is dropped.
    clock.advance(grace - 1);
    core.sweep(clock.now()).await;
    core.read_blocking(space, |held| assert!(held.log.contains(cut)))
        .unwrap();
    clock.advance(1);
    core.sweep(clock.now()).await;
    core.read_blocking(space, |held| {
        assert!(!held.log.contains(cut), "dropped after orphan_grace");
        assert!(!held.journal_of.contains_key(&cut));
        assert!(held.log.contains(checkpoint));
    })
    .unwrap();
}

/// `peers.json`'s `skeleton_cuts.heard_vote` at a live peer (peers.md,
/// "Skeleton cuts" and "Truncation"): B removes A, its senior, so the
/// checkpoint P makes hears A, its standing naming A's out slot with A1's
/// enrolment. A, heard, does not vote; P removes it again after the
/// checkpoint, which excuses it, and the cut takes effect; the peer
/// truncates under it, keeping A1's enrolment. P checkpoints again and P
/// and B vote: A's slot holds nothing up, and the second cut takes effect.
#[tokio::test]
async fn a_heard_members_enrolment_is_kept_after_truncation_and_the_next_cut_takes_effect() {
    let vectors = family();
    let case = &vectors["heard_vote"];
    let history = events_of(&case["events"]);
    let space = id_of(&history, "P creates the space");
    let first = id_of(&history, "P0: cut of P checkpoints (1)");
    let checkpoint = id_of(&history, "P checkpoints (1)");
    let second = id_of(&history, "P0: cut of P checkpoints (2)");
    let a1_enrols = id_of(&history, "A1 enrols");
    let clock = Arc::new(ManualClock::new(1000));
    let core = core(&clock);
    let founder = link(&core);
    let split = history
        .iter()
        .position(|(name, _)| name == "P0: cut of P checkpoints (2)")
        .expect("the second cut");
    for (name, signed) in &history[..split] {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    assert_eq!(cut_in_effect(&core, space), Some(first));
    clock.advance(frasil_peers::limits::CUT_RETENTION + 10);
    core.sweep(clock.now()).await;
    let slot = core
        .read_blocking(space, |held| {
            assert_eq!(held.truncated, Some((first, checkpoint)));
            assert!(held.log.contains(a1_enrols), "A1's enrolment is kept");
            assert!(
                !held.log.contains(id_of(&history, "P grants A administer")),
                "the past is truncated"
            );
            let cuts = held.cuts();
            let heard: Vec<_> = cuts
                .body(first)
                .unwrap()
                .standing
                .iter()
                .filter(|x| x.pseudonym == Some(a1_enrols))
                .map(|x| x.slot)
                .collect();
            assert_eq!(heard.len(), 1, "A's out slot names A1's enrolment");
            heard[0]
        })
        .unwrap();
    for (name, signed) in &history[split..] {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    assert_eq!(cut_in_effect(&core, space), Some(second));
    core.read_blocking(space, |held| {
        let cuts = held.cuts();
        let tally = cuts.tally(second).expect("a named cut");
        assert!(held.log.contains(a1_enrols), "A1's enrolment is still kept");
        assert!(
            tally.all_votes.get(&slot).is_none_or(Vec::is_empty),
            "A, heard, casts no vote"
        );
        assert!(tally.awaiting().is_empty(), "nobody is waited for");
    })
    .unwrap();
    let chain: Vec<&str> = case["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    assert_eq!(
        chain,
        [
            "P0: cut of P checkpoints (1)",
            "P0: cut of P checkpoints (2)"
        ]
    );
}

/// `peers.json`'s `skeleton_cuts.late_then_past` at a live peer (peers.md,
/// "Release and restore"): A releases x apart while P checkpoints (C1)
/// without it; C1 takes effect and the release is late. A checkpoints
/// (C2), whose past holds the release. It counts for nothing: x is not
/// released, its state stays Late, and truncating under C2 the peer keeps
/// no request of that past, x still not released.
#[tokio::test]
async fn a_release_late_under_one_cut_counts_for_nothing_in_the_next_ones_past() {
    let vectors = family();
    let case = &vectors["late_then_past"];
    let history = events_of(&case["events"]);
    let space = id_of(&history, "P creates the space");
    let release = id_of(&history, "A releases x, apart");
    let c1 = id_of(&history, "P0: cut of C1: P checkpoints (1)");
    let c2 = id_of(&history, "A1: cut of A checkpoints (C2)");
    let checkpoint2 = id_of(&history, "A checkpoints (C2)");
    let clock = Arc::new(ManualClock::new(1000));
    let core = core(&clock);
    let founder = link(&core);
    for (name, signed) in &history {
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    let stream = core
        .read_blocking(space, |held| {
            let cuts = held.cuts();
            assert_eq!(cuts.chain(), vec![c1, c2]);
            assert_eq!(cuts.request_state(release), RequestState::Late);
            let stream = held.writer_requests[&release].stream().unwrap();
            assert!(!held.is_released(&stream), "not released, kept everything");
            stream
        })
        .unwrap();
    assert_eq!(case["released"]["kept everything"], Json::Bool(false));
    clock.advance(frasil_peers::limits::CUT_RETENTION + 10);
    core.sweep(clock.now()).await;
    core.read_blocking(space, |held| {
        assert_eq!(held.truncated, Some((c2, checkpoint2)));
        assert!(held.kept_requests.is_empty(), "no request of the past kept");
        assert!(!held.log.contains(release), "the late release is deleted");
        assert!(!held.is_released(&stream), "not released, truncated");
    })
    .unwrap();
    assert_eq!(case["released"]["truncated"], Json::Bool(false));
}

/// A retried erasure receives identical evidence after recovery and truncation.
#[tokio::test]
async fn late_erasure_answers_survive_truncation_and_recovery() {
    let vectors = family();
    let case = &vectors["concurrent_request"];
    let history = events_of(&case["events"]);
    let space = id_of(&history, "P creates the space");
    let erase = id_of(&history, "A1 asks for erasure, apart");
    let clock = Arc::new(ManualClock::new(1000));
    let backing: Arc<dyn frasil_store::Store> = Arc::new(MemoryStore::new());
    let settings = Settings::open_core();
    let core = Arc::new(
        Core::open(
            settings.clone(),
            Records::new(backing.clone()),
            clock.clone(),
        )
        .unwrap(),
    );
    let founder = link(&core);
    for (name, signed) in &history {
        if name == "A1 asks for erasure again, after the checkpoint" {
            continue;
        }
        let answer = store(&core, founder, space, signed, clock.now()).await;
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    let answer = core.erasure_late(space, erase).await.expect("late answer");
    let expected =
        frasil_testkit::hex::decode(case["erasure_late"]["message"].as_str().unwrap()).unwrap();
    assert_eq!(answer, expected);
    drop(core);
    let core = Core::open(settings, Records::new(backing), clock.clone()).unwrap();
    assert_eq!(core.erasure_late(space, erase).await.unwrap(), expected);
    clock.advance(frasil_peers::limits::CUT_RETENTION + 1);
    let writing = core.write(space).await.unwrap();
    core.sweep_space(&writing, clock.now()).await;
    drop(writing);
    assert_eq!(core.erasure_late(space, erase).await.unwrap(), expected);
    let eraser = frasil_events::decode(
        &history
            .iter()
            .find(|(_, signed)| frasil_events::decode(signed).unwrap().id() == erase)
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(
        core.read_blocking(space, |held| held.pseudonym_ed(eraser.author()))
            .unwrap(),
        Some(*eraser.ed())
    );
}

#[tokio::test]
async fn a_reserved_cut_is_kept_notified_once_per_connection_and_holds_no_erasure() {
    use frasil_transport::frame::{ConnectionKind, Extensions, StreamClass, read_message};
    use frasil_transport::messages::EventRefused;
    let case = &family()["held_cut"];
    let history = events_of(&case["events"]);
    let space = id_of(&history, "P creates the space");
    let cut = id_of(&history, case["cut"].as_str().unwrap());
    let erasure = id_of(&history, case["peer"]["erasure_event"].as_str().unwrap());
    let root = frasil_events::decode(
        &history
            .iter()
            .find(|(name, _)| name == "P0: root")
            .unwrap()
            .1,
    )
    .unwrap();
    let clock = Arc::new(ManualClock::new(1000));
    let core = core(&clock);
    let writer = link(&core);
    let mut rest = history.iter();
    for (name, signed) in rest.by_ref() {
        let answer = store(&core, writer, space, signed, clock.now()).await;
        if frasil_events::decode(signed).unwrap().id() == cut {
            assert!(matches!(
                answer,
                StoreAnswer::Held(Some("extension_required"))
            ));
            break;
        }
        assert!(
            !matches!(answer, StoreAnswer::Refused(_)),
            "{name}: {answer:?}"
        );
    }
    core.read_blocking(space, |held| {
        assert!(held.log.contains(cut));
        assert_eq!(held.cuts().request_state(erasure), RequestState::Free);
        assert!(held.cuts().chain().is_empty());
    })
    .unwrap();
    let mut receivers = Vec::new();
    for _ in 0..2 {
        let (tx, rx) = mpsc::channel(32);
        let connection = core.link(tx);
        core.admin(connection, space, *root.author());
        receivers.push(rx);
        core.read_blocking(space, |held| core.send_awaiting(held, clock.now()))
            .unwrap();
    }
    core.read_blocking(space, |held| core.send_awaiting(held, clock.now()))
        .unwrap();
    for receiver in &mut receivers {
        let mut notifications = 0;
        while let Ok(out) = receiver.try_recv() {
            let Outgoing::Control(bytes) = out else {
                continue;
            };
            let message = read_message(
                &bytes,
                StreamClass::Control,
                ConnectionKind::DeviceToPeer,
                Extensions::NONE,
            )
            .unwrap()
            .unwrap();
            if let Ok(refused) = EventRefused::read(&message) {
                assert_eq!(refused.code, "extension_required");
                assert_eq!(refused.event, cut.0);
                notifications += 1;
            }
        }
        assert_eq!(notifications, 1);
    }
    for (_, signed) in rest {
        if core.tombstoned(&space) {
            break;
        }
        let answer = store(&core, writer, space, signed, clock.now()).await;
        assert!(!matches!(answer, StoreAnswer::Refused(_)), "{answer:?}");
    }
    clock.advance(core.erasure_timeout(&space));
    core.sweep(clock.now()).await;
    assert!(
        core.tombstoned(&space),
        "the held cut does not delay erasure"
    );
}
