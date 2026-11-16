//! The replica side of the adapter interface (units.md, sections 3.6, 3.8
//! and 3.17), over the built-in adapters with real content: a snapshot's
//! cover counts as held, and every unit of the cover the state does not
//! include is handed back, so that a stream over a snapshot judges as a
//! rebuild from the units does. And units.md's reading of a unit for the
//! roster (section 3.2, steps 11 to 14).

mod common;

use common::*;
use frasil_adapter::{Adapter, Capabilities, Context, EventId, Outcome, Role, StreamUnit};
use frasil_adapter_loro::write::Writer;
use frasil_adapter_loro::{Content, Incarnation, Loro, LoroClass};
use frasil_adapter_records::{Changeset, Op, Records};
use frasil_base::ErrorClass;
use frasil_base::errors::Class;
use frasil_keys::RotationSet;
use frasil_keys::reference::{Lookup, RotationLog};
use frasil_space::{Keyring, UnitBodies, UnitBody};
use frasil_units::runtime::{Base, Stream, VerdictChange};
use frasil_units::unit::{KeyringKeys, UnitReader};
use loro::LoroDoc;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

const SPACE: [u8; 32] = [0x5a; 32];
const STREAM: [u8; 16] = [0x57; 16];

fn incarnation(author: u8, s: u64) -> Incarnation {
    Incarnation {
        space: SPACE,
        stream: STREAM,
        author: [author; 32],
        incarnation: s,
    }
}

/// A unit of `author` at `seq` and `height`, named `id`.
fn unit(id: u8, author: u8, seq: u64, height: u64, content: Vec<u8>, valid: bool) -> StreamUnit {
    StreamUnit {
        context: Context::new(
            SPACE,
            STREAM,
            [id; 32],
            [author; 32],
            seq,
            height,
            Role::Log,
        )
        .with_capabilities(Capabilities::none()),
        content,
        valid,
    }
}

fn edit(doc: &LoroDoc, author: u8, s: u64, text: &str) -> Vec<u8> {
    let mut writer = Writer::new(doc, incarnation(author, s)).unwrap();
    let length = doc.get_text("t").len_unicode();
    doc.get_text("t").insert(length, text).unwrap();
    writer.edit(doc).unwrap().unwrap().encode()
}

fn ids(units: &[&StreamUnit]) -> BTreeSet<EventId> {
    units.iter().map(|unit| unit.context.event_id).collect()
}

#[test]
fn a_refused_unit_of_the_cover_still_counts_over_the_snapshot() {
    // Alice's first edit, refused by the write rule, and a later edit of
    // hers that reuses its counters (adapter-loro.md, section 3.2, step 6).
    let first = unit(1, 1, 1, 1, edit(&LoroDoc::new(), 1, 1, "hello"), false);
    let again = unit(2, 1, 2, 3, edit(&LoroDoc::new(), 1, 1, "world"), true);
    let loro = Loro::new();

    // A full rebuild refuses the later edit.
    let mut full = Stream::new(Loro::new());
    full.receive(first.clone());
    full.receive(again.clone());
    assert_eq!(
        full.outcome(&again.context.event_id),
        Some(&Outcome::Refused(LoroClass::LoroOverlap))
    );

    // A snapshot whose cover is the first edit, which the compactor
    // refused: its state does not include it, so it is excluded.
    let compaction = loro.compact(&loro.rebuild(None, std::slice::from_ref(&first)).unwrap());
    assert!(!compaction.included.contains(&first.context.event_id));
    let base = Base {
        supersedes: Vec::new(),
        state: compaction.state,
        cover: ids(&[&first]),
        excluded: ids(&[&first]),
    };

    // The runtime hands the excluded unit back: the later edit is refused
    // over the snapshot as in the full rebuild.
    let mut over = Stream::new(Loro::new());
    over.receive(first.clone());
    over.receive(again.clone());
    over.use_snapshot(base.clone()).unwrap();
    assert_eq!(
        over.outcome(&again.context.event_id),
        Some(&Outcome::Refused(LoroClass::LoroOverlap))
    );
    assert_eq!(
        over.outcome(&first.context.event_id),
        Some(&Outcome::Counted)
    );

    // A replica that did not hand it back would apply the later edit.
    let mut state = loro.load(&base.state).unwrap();
    assert_eq!(loro.receive(&mut state, &again), Outcome::Applied);
}

#[test]
fn a_snapshots_cover_counts_as_held() {
    // Bob suggests; Alice accepts inside the cover, and dismisses after it.
    let loro = Loro::new();
    let main = LoroDoc::new();
    let first = unit(1, 1, 1, 1, edit(&main, 1, 1, "base"), true);
    let fork = main.fork();
    let mut bob = Writer::new(&fork, incarnation(2, 2)).unwrap();
    fork.get_text("t").insert(4, "?").unwrap();
    let suggestion = StreamUnit {
        content: bob.suggestion(&fork).unwrap().unwrap().encode(),
        ..unit(2, 2, 2, 2, Vec::new(), true)
    };
    let accept = unit(3, 1, 2, 3, Content::accept([[2; 32]]).encode(), true);
    let dismiss = unit(4, 1, 3, 4, Content::dismiss([[2; 32]]).encode(), true);
    let cover = [&first, &suggestion, &accept];
    let compaction = loro.compact(
        &loro
            .rebuild(None, &[first.clone(), suggestion.clone(), accept.clone()])
            .unwrap(),
    );
    assert_eq!(compaction.included, ids(&cover));
    let base = Base {
        supersedes: Vec::new(),
        state: compaction.state,
        cover: ids(&cover),
        excluded: BTreeSet::new(),
    };

    let mut over = Stream::new(Loro::new());
    over.use_snapshot(base.clone()).unwrap();
    for unit in [&first, &suggestion, &accept] {
        // Units the state includes are kept, never handed over again.
        assert_eq!(over.receive((*unit).clone()), None);
    }
    assert_eq!(over.receive(dismiss.clone()), Some(Outcome::Applied));
    assert!(loro.held(over.state()).is_empty());
    assert_eq!(over.state().doc().get_text("t").to_string(), "base?");

    // Without the cover marked as held, the dismiss would wait.
    let mut state = loro.load(&base.state).unwrap();
    assert_eq!(
        loro.receive(&mut state, &dismiss),
        Outcome::Waiting(LoroClass::TargetNotHeld)
    );
}

#[test]
fn verdict_changes_rebuild_the_stream() {
    let records = Records::new();
    let insert =
        |clock, row: &[u8]| Changeset::new(clock, vec![Op::insert_row("t", row.to_vec())]).encode();
    let a = unit(1, 1, 1, 1, insert(1, b"a"), true);
    let b = unit(2, 2, 1, 2, insert(2, b"b"), true);
    let mut stream = Stream::new(records);
    stream.receive(b.clone());
    assert_eq!(
        stream.outcome(&b.context.event_id).map(Outcome::is_applied),
        Some(false)
    );
    stream.receive(a.clone());
    assert!(stream.outcome(&b.context.event_id).unwrap().is_applied());

    // A removal learned late refuses a: rebuild once the batch is done.
    assert_eq!(
        stream.set_valid(&a.context.event_id, false),
        VerdictChange::Rebuild
    );
    assert_eq!(
        stream.set_valid(&a.context.event_id, false),
        VerdictChange::None
    );
    stream.rebuild().unwrap();
    assert_eq!(stream.outcome(&a.context.event_id), Some(&Outcome::Counted));
    // Its clock still counts, so b stays admitted.
    assert!(stream.outcome(&b.context.event_id).unwrap().is_applied());

    // Over a snapshot that includes b, refusing b is inside the snapshot.
    let compaction = Records::new().compact(stream.state());
    let mut over = Stream::new(Records::new());
    over.receive(a.clone());
    over.receive(b.clone());
    over.set_valid(&a.context.event_id, false);
    over.use_snapshot(Base {
        supersedes: Vec::new(),
        state: compaction.state,
        cover: ids(&[&a, &b]),
        excluded: ids(&[&a]),
    })
    .unwrap();
    assert_eq!(
        over.set_valid(&b.context.event_id, false),
        VerdictChange::InsideSnapshot
    );
    over.drop_snapshot();
    assert!(over.base().is_none());
    assert_eq!(over.outcome(&b.context.event_id), Some(&Outcome::Counted));
    // A state that does not load leaves the stream as it was.
    assert!(
        over.use_snapshot(Base {
            supersedes: Vec::new(),
            state: b"not a state".to_vec(),
            cover: BTreeSet::new(),
            excluded: BTreeSet::new(),
        })
        .is_err()
    );
    assert!(over.base().is_none());
}

/// A log in which every ID is a rotation, and none precedes another.
struct Rotations;

impl RotationLog for Rotations {
    fn lookup(&self, id: &frasil_events::EventId) -> Lookup {
        if id.0 == [0xee; 32] {
            Lookup::Missing
        } else {
            Lookup::Rotation
        }
    }

    fn precedes(&self, _: &frasil_events::EventId, _: &frasil_events::EventId) -> bool {
        false
    }
}

#[test]
fn the_roster_reads_units_through_the_keys_held() {
    let units = family("units");
    let plain = frasil_events::decode(&bytes(&units[0]["signed"])).unwrap();
    let resubmission = frasil_events::decode(&bytes(&units[5]["signed"])).unwrap();
    let (rotation_a, key_a) = rotation("A");
    let read = |keyring: &Keyring, event| {
        let keys = KeyringKeys {
            keyring,
            log: &Rotations,
        };
        UnitReader {
            keys: &keys,
            system: Some(system()),
        }
        .open(event)
    };

    let mut keyring = Keyring::default();
    assert_eq!(
        read(&keyring, &plain),
        UnitBody::Held(ErrorClass::Sealed.into())
    );
    keyring.rotations.insert(rotation_a, Zeroizing::new(key_a));
    assert_eq!(read(&keyring, &plain), UnitBody::Opened(Vec::new()));
    let UnitBody::Opened(refs) = read(&keyring, &resubmission) else {
        panic!("the re-submission opens");
    };
    assert_eq!(refs.len(), 1);

    // A wrong key derived from checked rotation keys: BadSeal, void.
    let mut wrong = Keyring::default();
    wrong.rotations.insert(rotation_a, Zeroizing::new([7; 32]));
    let UnitBody::Void(class) = read(&wrong, &plain) else {
        panic!("a bad seal voids the unit");
    };
    assert_eq!(class.name(), "BadSeal");
    // The same under a provisional key: held, Sealed.
    let mut provisional = Keyring::default();
    provisional
        .states
        .insert(RotationSet::single(rotation_a), Zeroizing::new([7; 32]));
    assert_eq!(
        read(&provisional, &plain),
        UnitBody::Held(ErrorClass::Sealed.into())
    );
}

#[test]
fn a_missing_rotation_holds_the_unit_pending() {
    use frasil_units::body::KeyReference;
    use frasil_units::unit::UnitKeys;
    let keyring = Keyring::default();
    let keys = KeyringKeys {
        keyring: &keyring,
        log: &Rotations,
    };
    let reference = KeyReference::Set(RotationSet::single(frasil_events::EventId([0xee; 32])));
    let class = keys.key(&space(), &reference).unwrap_err();
    assert_eq!(class.name(), "Pending");
}
