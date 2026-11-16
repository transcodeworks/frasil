//! Skeleton cuts and truncation (peers.md, "Skeleton cuts" and
//! "Truncation"): `peers.json`'s `skeleton_cuts`, the cut body's reading,
//! a replica's check against the record, truncation's plan and answers, and
//! a seeded model check that a peer that truncated under each cut in effect
//! agrees with one that kept everything.

mod builder;
mod common;

use builder::Builder;
use common::{History, family, hex, slots_json, status_text, text};
use frasil_base::ErrorClass;
use frasil_crypto::schemes::Signer;
use frasil_events::{EventId, kind};
use frasil_peers::PeersClass;
use frasil_peers::body::{
    ChangeEffect, Cut, CutSeniority, Restored, SlotEntry, SlotId, StandingEntry, StorageBody,
    StorageType,
};
use frasil_peers::cut::{
    Dormancy, Keep, PeerCuts, RecordSlot, RequestState, StandingMember, WantAnswer, always_kept,
    answer_want, check_against_record, check_standing, enrolment_of, entry_pseudonym, keep,
    may_truncate, placeable, read_cut, requests_settled, stable_past, standing_consistent,
    standing_entries,
};
use frasil_peers::limits::{CUT_RETENTION, MAX_CUT_SLOTS, MAX_RANK, MAX_STANDING};
use frasil_peers::skeleton::{Skeleton, Status};
use frasil_peers::twins::{Bound, TwinChecks};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

// ---------------------------------------------------------------------------
// peers.json, `skeleton_cuts`.

/// The verdicts of a skeleton's storage events, as the vectors write them.
fn verdicts(skeleton: &Skeleton<'_>, history: &History) -> Json {
    let map: serde_json::Map<String, Json> = skeleton
        .statuses()
        .into_iter()
        .filter(|(id, _)| {
            history
                .log
                .event(*id)
                .is_some_and(|e| e.kind() == kind::STORAGE)
        })
        .map(|(id, status)| {
            let text = match status {
                Status::Valid => "valid".to_string(),
                Status::Void { class, .. } => frasil_base::errors::Class::name(class).to_string(),
            };
            (history.name(id).to_string(), Json::from(text))
        })
        .collect();
    Json::Object(map)
}

#[test]
fn the_vector_history_kept_and_truncated() {
    let v = family("skeleton_cuts");
    let history = History::of(&v["events"]);
    let cut = history.id(text(&v["cut"]["name"]));
    let checkpoint = history.id(text(&v["cut"]["checkpoint"]));

    // The cut's body reads, and writes back byte for byte.
    let body = hex(&v["cut"]["body"]);
    let event = history.log.event(cut).expect("the cut");
    assert_eq!(event.unverified_body(), body.as_slice());
    let read = StorageBody::read(&body).expect("a cut body");
    assert_eq!(read.storage_type(), StorageType::Cut);
    assert_eq!(read.encode(), body);
    let parsed = read_cut(event).expect("a cut");
    assert_eq!(parsed.epoch, 1);

    // A peer that kept everything.
    let full = PeerCuts::new(&history.log, None);
    assert_eq!(full.checkpoint_of(cut), Some(checkpoint));
    assert_eq!(full.validity(cut), Status::Valid);
    assert_eq!(full.chain(), vec![cut]);
    assert!(full.in_effect(cut));
    assert!(full.awaiting(cut).is_empty());
    let kept = full.skeleton();
    assert_eq!(kept.cut(), Some(cut));
    assert_eq!(kept.epoch(), 1);
    assert_eq!(verdicts(&kept, &history), v["kept"]["verdicts"]);
    assert_eq!(
        slots_json(&kept.administrators(), &history),
        v["kept"]["administrators"]
    );

    // What the peer may delete when it truncates under the cut: the
    // checkpoint's past but the genesis, the cut, the root and enrolment its
    // slot entries name and the release; it is the first checkpoint, so it
    // reaches no other.
    let plan = full
        .truncation_plan(cut, |_, _| false)
        .expect("envelopes held");
    assert!(plan.whole.contains(&history.log.id()) && plan.whole.contains(&cut));
    assert!(plan.envelopes.is_empty());
    // The release, the only one of its stream, is maximal and kept.
    assert_eq!(
        plan.requests
            .iter()
            .map(|&id| history.name(id))
            .collect::<Vec<_>>(),
        ["P releases stream x"]
    );
    for entry in &parsed.slots {
        let enrolment = entry
            .pseudonym
            .expect("every slot of the vector is enrolled");
        assert!(plan.whole.contains(&enrolment));
    }
    let mut deleted: Vec<&str> = plan.delete.iter().map(|&id| history.name(id)).collect();
    deleted.sort_unstable();
    assert_eq!(
        deleted,
        [
            "P grants A administer",
            "P0 asks for credentials",
            "P0: twin of P grants A administer"
        ]
    );
    assert!(plan.deleted_bytes(&history.log) > 0);
    // Kept, deleted and what follows cover the log.
    for id in history.all() {
        let in_plan = plan.delete.contains(&id) || plan.whole.contains(&id);
        assert!(in_plan || history.log.precedes(checkpoint, id) || id == checkpoint);
    }

    // Truncation waits for nothing here: the credentials request in the
    // checkpoint's past is stable at the peer, in the skeleton before the
    // cut.
    let may = truncation_wait_settled(&full, cut);
    assert_eq!(Json::from(may), v["may_truncate"]);
    // The world after the cut holds no request of that past.
    assert!(requests_settled(&kept, checkpoint, |_| false));

    // The events a peer holds once it truncated: every event but those the
    // plan deletes.
    let held: BTreeSet<EventId> = history
        .all()
        .into_iter()
        .filter(|id| !plan.delete.contains(id))
        .collect();
    let mut names: Vec<&str> = held.iter().map(|&id| history.name(id)).collect();
    names.sort_unstable();
    let expected: Vec<&str> = v["truncated"]["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(names, expected);

    let truncated = PeerCuts::truncated(&history.log, &history.log, held, cut);
    assert_eq!(truncated.chain(), vec![cut]);
    let trimmed = truncated.skeleton();
    assert_eq!(verdicts(&trimmed, &history), v["truncated"]["verdicts"]);
    assert_eq!(
        slots_json(&trimmed.administrators(), &history),
        v["truncated"]["administrators"]
    );
}

#[test]
fn the_cut_slots_of_the_vector_are_its_past() {
    let v = family("skeleton_cuts");
    let history = History::of(&v["events"]);
    let cut = history.id(text(&v["cut"]["name"]));
    let body = read_cut(history.log.event(cut).unwrap()).unwrap();
    let full = PeerCuts::new(&history.log, None);
    let past = history.log.past(cut);
    let (epoch, slots) = full.slots_for(&past);
    assert_eq!(epoch, body.epoch);
    assert_eq!(slots, body.slots);
    // The founder's slot carries empty keys and the root; A's its grant
    // map's keys and A1's enrolment.
    assert_eq!(slots.len(), 2);
    let root = slots
        .iter()
        .find(|e| e.slot_ed.is_none())
        .expect("the root's slot");
    assert_eq!(root.seniority.epoch, 0);
    let p0_root = history.id("P0: root");
    let p0 = *history.log.event(p0_root).unwrap().author();
    assert_eq!(root.pseudonym, Some(p0_root));
    assert_eq!(entry_pseudonym(&history.log, root), Some(p0));
    // The root's slot has the top rank; A's its grant map's, the top rank
    // too.
    assert_eq!(root.rank, MAX_RANK);
    let a1 = slots.iter().find(|e| e.slot_ed.is_some()).unwrap();
    assert_eq!(a1.pseudonym, Some(history.id("A1 enrols")));
    assert_eq!(a1.rank, MAX_RANK);
}

#[test]
fn a_cut_at_the_limit_and_past_it() {
    let v = &family("skeleton_cuts")["limit"];
    let slots = v["slots"].as_u64().unwrap() as usize;
    assert_eq!(slots, MAX_CUT_SLOTS);
    // 512 enrolled entries read, and write back byte for byte.
    let body = hex(&v["body"]);
    assert_eq!(body.len() as u64, v["body_bytes"].as_u64().unwrap());
    let read = StorageBody::read(&body).expect("a cut at the limit");
    let StorageBody::Cut(cut) = &read else {
        panic!("a cut");
    };
    assert_eq!(cut.slots.len(), MAX_CUT_SLOTS);
    assert!(cut.slots.iter().all(|entry| entry.pseudonym.is_some()));
    assert_eq!(read.encode(), body);
    // The refusals cover slot and standing limits, then an invalid slot_ed.
    for refusal in v["refusals"].as_array().unwrap() {
        let class = StorageBody::read(&hex(&refusal["body"]))
            .err()
            .map(|class| frasil_base::errors::Class::name(class).to_string());
        assert_eq!(
            class.as_deref(),
            Some(text(&refusal["class"])),
            "{}",
            refusal["name"]
        );
    }
}

#[test]
fn a_cut_at_the_limit_signed() {
    let v = &family("skeleton_cuts")["limit"];
    let body = hex(&v["body"]);
    let StorageBody::Cut(cut) = StorageBody::read(&body).expect("a cut at the limit") else {
        panic!("a cut");
    };
    // Signed, with a full set of parents and four cuts, it fits a storage
    // event.
    let signed = hex(&v["signed"]);
    assert_eq!(signed.len() as u64, v["signed_bytes"].as_u64().unwrap());
    assert!(signed.len() as u64 <= v["storage_event_bound"].as_u64().unwrap());
    let event = frasil_events::decode(&signed).expect("the signed cut decodes");
    assert_eq!(event.unverified_body(), body.as_slice());
    assert_eq!(read_cut(&event), Some(cut));
}

// ---------------------------------------------------------------------------
// The body.

fn entry(index: u8, maker: u8, enrolled: Option<EventId>) -> SlotEntry {
    let keys = frasil_peers::derive::SlotKeys::from_token(&[index; 32]);
    SlotEntry {
        slot: SlotId::new([7; 32], index, EventId([maker; 32])),
        slot_ed: Some(*keys.ed_public()),
        slot_mldsa_hash: Some(keys.mldsa_hash()),
        seniority: CutSeniority {
            epoch: 0,
            height: 3,
            maker: EventId([maker; 32]),
        },
        pseudonym: enrolled,
        rank: index.wrapping_mul(37),
    }
}

fn cut_body(slots: Vec<SlotEntry>, epoch: u64) -> Cut {
    let mut standing = standing_of(&slots);
    if standing.is_empty() {
        standing.push(StandingEntry {
            slot: SlotId::new([6; 32], 0, EventId([6; 32])),
            order: 1,
            dormant: 0,
            pseudonym: None,
        });
    }
    Cut {
        twin: [1; 32],
        salt: [2; 32],
        record: [3; 64],
        epoch,
        slots,
        standing,
    }
}

/// The standing entries of a record whose administrators are the cut's
/// slots, none dormant and none heard: each slot ordered by rank, highest
/// first, then by its seniority (peers.md, "Storage events").
fn standing_of(slots: &[SlotEntry]) -> Vec<StandingEntry> {
    let members: Vec<_> = slots
        .iter()
        .map(|entry| StandingMember {
            key: (MAX_RANK - entry.rank, entry.seniority, entry.sort_bytes()),
            slot: Some(entry.slot),
            pseudonym: None,
            dormancy: Dormancy::Votes,
        })
        .collect();
    standing_entries(&members)
}

fn read(cut: &Cut) -> Result<StorageBody, PeersClass> {
    StorageBody::read(&StorageBody::Cut(cut.clone()).encode())
}

fn malformed() -> Result<StorageBody, PeersClass> {
    Err(ErrorClass::Malformed.into())
}

#[test]
fn a_cut_body_reads_and_refuses_in_order() {
    // A root's slot, keyless, and two granted slots.
    let mut root = entry(0, 9, Some(EventId([0xaa; 32])));
    root.slot_ed = None;
    root.slot_mldsa_hash = None;
    let mut slots = vec![
        root,
        entry(1, 4, None),
        entry(30, 4, Some(EventId([1; 32]))),
    ];
    slots.sort_by_cached_key(SlotEntry::sort_bytes);
    let good = cut_body(slots.clone(), 1);
    assert_eq!(read(&good), Ok(StorageBody::Cut(good.clone())));
    // No slots at all reads too.
    assert!(read(&cut_body(vec![], 3)).is_ok());

    // Epoch 0.
    assert_eq!(read(&cut_body(slots.clone(), 0)), malformed());
    // Out of order, and repeated.
    let mut reversed = slots.clone();
    reversed.reverse();
    assert_eq!(read(&cut_body(reversed, 1)), malformed());
    let mut repeated = slots.clone();
    repeated.push(slots[2].clone());
    assert_eq!(read(&cut_body(repeated, 1)), malformed());
    // A slot_ed without its hash.
    let mut half = slots.clone();
    let granted = half.iter().position(|e| e.slot_ed.is_some()).unwrap();
    half[granted].slot_mldsa_hash = None;
    half.sort_by_cached_key(SlotEntry::sort_bytes);
    assert_eq!(read(&cut_body(half, 1)), malformed());
    // 512 entries read, 513 do not.
    let many = |n: usize| {
        let mut out: Vec<SlotEntry> = (0..n)
            .map(|i| entry((i % 64) as u8, (i / 64) as u8, None))
            .collect();
        out.sort_by_cached_key(SlotEntry::sort_bytes);
        out
    };
    assert!(read(&cut_body(many(MAX_CUT_SLOTS), 1)).is_ok());
    assert_eq!(read(&cut_body(many(MAX_CUT_SLOTS + 1), 1)), malformed());
    // An Ed25519 key of small order: the structure reads, the key does not.
    let mut invalid = slots.clone();
    let at = invalid.iter().position(|e| e.slot_ed.is_some()).unwrap();
    let mut identity = [0; 32];
    identity[0] = 1;
    invalid[at].slot_ed = Some(identity);
    assert_eq!(
        read(&cut_body(invalid.clone(), 1)),
        Err(ErrorClass::InvalidKey.into())
    );
    // A structural fault after it still wins: the whole body is read first.
    invalid.push(slots[0].clone());
    assert_eq!(read(&cut_body(invalid, 1)), malformed());
    // A pseudonym names its root or enrolment by event ID: 32 bytes, or
    // empty; any other length is Malformed.
    for length in [1, 31, 33] {
        let encoded = StorageBody::Cut(good.clone()).encode();
        let frasil_base::cbor::Value::Map(mut map) = frasil_base::cbor::decode(&encoded).unwrap()
        else {
            panic!("a map");
        };
        let Some(frasil_base::cbor::Value::Array(entries)) = map.get_mut(&7) else {
            panic!("the slots");
        };
        let frasil_base::cbor::Value::Array(fields) = &mut entries[0] else {
            panic!("an entry");
        };
        fields[4] = frasil_base::cbor::Value::Bytes(vec![1; length]);
        let bytes = frasil_base::cbor::Value::Map(map).encode();
        assert_eq!(StorageBody::read(&bytes), malformed(), "{length} bytes");
    }
    // An entry is six elements, its rank last, an unsigned integer up to
    // 255: five elements, a seventh, a rank of 256 or one that is no
    // unsigned integer are Malformed.
    let altered = |change: &dyn Fn(&mut Vec<frasil_base::cbor::Value>)| {
        let encoded = StorageBody::Cut(good.clone()).encode();
        let frasil_base::cbor::Value::Map(mut map) = frasil_base::cbor::decode(&encoded).unwrap()
        else {
            panic!("a map");
        };
        let Some(frasil_base::cbor::Value::Array(entries)) = map.get_mut(&7) else {
            panic!("the slots");
        };
        let frasil_base::cbor::Value::Array(fields) = &mut entries[0] else {
            panic!("an entry");
        };
        change(fields);
        frasil_base::cbor::Value::Map(map).encode()
    };
    let five = altered(&|fields| {
        fields.pop();
    });
    assert_eq!(StorageBody::read(&five), malformed());
    let seven = altered(&|fields| fields.push(frasil_base::cbor::Value::Unsigned(0)));
    assert_eq!(StorageBody::read(&seven), malformed());
    let over = altered(&|fields| fields[5] = frasil_base::cbor::Value::Unsigned(256));
    assert_eq!(StorageBody::read(&over), malformed());
    let bytes = altered(&|fields| fields[5] = frasil_base::cbor::Value::Bytes(vec![1]));
    assert_eq!(StorageBody::read(&bytes), malformed());
    let zero = altered(&|fields| fields[5] = frasil_base::cbor::Value::Unsigned(0));
    let StorageBody::Cut(read) = StorageBody::read(&zero).expect("rank 0 reads") else {
        panic!("a cut");
    };
    assert_eq!(read.slots[0].rank, 0);

    // Key 8, the standing entries: 1 to 128, strictly ascending by their
    // slot references, each `[slot reference, order from 1, dormant,
    // pseudonym]`, the pseudonym an event ID or empty.
    let with_standing = |standing: Vec<StandingEntry>| {
        let mut cut = good.clone();
        cut.standing = standing;
        StorageBody::Cut(cut).encode()
    };
    let stand = |i: u8, order: u64, dormant: u64| StandingEntry {
        slot: SlotId::new([8; 32], i, EventId([i; 32])),
        order,
        dormant,
        pseudonym: (i % 2 == 1).then_some(EventId([i; 32])),
    };
    let mut many: Vec<StandingEntry> = (0..MAX_STANDING)
        .map(|i| stand((i % 64) as u8, i as u64 + 1, 0))
        .collect();
    many.sort_by_cached_key(StandingEntry::sort_bytes);
    many.dedup_by_key(|x| x.slot);
    assert!(StorageBody::read(&with_standing(many.clone())).is_ok());
    assert_eq!(StorageBody::read(&with_standing(Vec::new())), malformed());
    let mut reversed = vec![stand(1, 1, 0), stand(2, 2, 0)];
    reversed.sort_by_cached_key(StandingEntry::sort_bytes);
    reversed.reverse();
    assert_eq!(StorageBody::read(&with_standing(reversed)), malformed());
    assert_eq!(
        StorageBody::read(&with_standing(vec![stand(1, 0, 0)])),
        malformed()
    );
    assert!(StorageBody::read(&with_standing(vec![stand(1, 1, u64::MAX)])).is_ok());
    let without = {
        let frasil_base::cbor::Value::Map(mut map) =
            frasil_base::cbor::decode(&StorageBody::Cut(good.clone()).encode()).unwrap()
        else {
            panic!("a map");
        };
        map.remove(&8);
        frasil_base::cbor::Value::Map(map).encode()
    };
    assert_eq!(StorageBody::read(&without), malformed());
    let short = {
        let frasil_base::cbor::Value::Map(mut map) =
            frasil_base::cbor::decode(&StorageBody::Cut(good.clone()).encode()).unwrap()
        else {
            panic!("a map");
        };
        let Some(frasil_base::cbor::Value::Array(entries)) = map.get_mut(&8) else {
            panic!("the standing entries");
        };
        let frasil_base::cbor::Value::Array(fields) = &mut entries[0] else {
            panic!("an entry");
        };
        fields.pop();
        frasil_base::cbor::Value::Map(map).encode()
    };
    assert_eq!(StorageBody::read(&short), malformed());
    // Its fourth element: 32 bytes or empty; any other length, or a value
    // that is no byte string, is Malformed.
    let fourth = |value: frasil_base::cbor::Value| {
        let frasil_base::cbor::Value::Map(mut map) =
            frasil_base::cbor::decode(&with_standing(vec![stand(1, 1, 0)])).unwrap()
        else {
            panic!("a map");
        };
        let Some(frasil_base::cbor::Value::Array(entries)) = map.get_mut(&8) else {
            panic!("the standing entries");
        };
        let frasil_base::cbor::Value::Array(fields) = &mut entries[0] else {
            panic!("an entry");
        };
        fields[3] = value;
        StorageBody::read(&frasil_base::cbor::Value::Map(map).encode())
    };
    for length in [1, 31, 33] {
        assert_eq!(
            fourth(frasil_base::cbor::Value::Bytes(vec![1; length])),
            malformed()
        );
    }
    assert_eq!(fourth(frasil_base::cbor::Value::Unsigned(0)), malformed());
    let StorageBody::Cut(empty) = fourth(frasil_base::cbor::Value::Bytes(Vec::new())).unwrap()
    else {
        panic!("a cut");
    };
    assert_eq!(empty.standing[0].pseudonym, None);
    let StorageBody::Cut(named) = fourth(frasil_base::cbor::Value::Bytes(vec![5; 32])).unwrap()
    else {
        panic!("a cut");
    };
    assert_eq!(named.standing[0].pseudonym, Some(EventId([5; 32])));
}

/// peers.md, "Skeleton cuts", step 7: the standing entries are consistent
/// with each other and with the cut's slots.
#[test]
fn standing_entries_consistent_with_each_other() {
    let slots = {
        let mut slots = vec![entry(1, 4, None), entry(2, 4, None), entry(3, 4, None)];
        slots.sort_by_cached_key(SlotEntry::sort_bytes);
        slots
    };
    let none = |_: EventId, _: SlotId| false;
    let mut cut = cut_body(slots.clone(), 1);
    assert!(standing_consistent(&cut, |_| false, none));
    // An order missing, or twice.
    cut.standing[0].order = 4;
    assert!(!standing_consistent(&cut, |_| false, none));
    cut.standing[0].order = cut.standing[1].order;
    assert!(!standing_consistent(&cut, |_| false, none));
    let mut cut = cut_body(slots.clone(), 1);
    // A dormant value from 3 is 2 + k with k from 1 to n + 1.
    cut.standing[0].dormant = 2 + 1;
    assert!(standing_consistent(&cut, |_| false, none));
    cut.standing[0].dormant = 2 + 4;
    assert!(standing_consistent(&cut, |_| false, none));
    cut.standing[0].dormant = 2 + 5;
    assert!(!standing_consistent(&cut, |_| false, none));
    // A slot of the cut names no pseudonym: its slot entry does.
    let mut cut = cut_body(slots.clone(), 1);
    cut.standing[0].pseudonym = Some(EventId([5; 32]));
    assert!(!standing_consistent(&cut, |_| false, |_, _| true));
    // A slot that is not the cut's: consistent only when it is not in at
    // the peer, and with a root or enrolment of it the peer holds, or none.
    let mut cut = cut_body(slots.clone(), 1);
    let out = SlotId::new([9; 32], 0, EventId([9; 32]));
    let enrolment = EventId([10; 32]);
    cut.standing.push(StandingEntry {
        slot: out,
        order: 4,
        dormant: 0,
        pseudonym: None,
    });
    assert!(!standing_consistent(&cut, |_| false, none));
    assert!(standing_consistent(&cut, |slot| slot == out, none));
    cut.standing.last_mut().unwrap().pseudonym = Some(enrolment);
    assert!(!standing_consistent(&cut, |slot| slot == out, none));
    assert!(!standing_consistent(
        &cut,
        |slot| slot == out,
        |id, slot| id == enrolment && slot != out
    ));
    assert!(standing_consistent(
        &cut,
        |slot| slot == out,
        |id, slot| id == enrolment && slot == out
    ));
    // The orders a record gives: by rank, then seniority, over the members
    // with a slot, with no gap for one without; a dormant member granted by
    // another without a predecessor is 2 + k, k one more than the entries
    // that outrank its granter, which needs no slot of its own.
    let members = [
        StandingMember {
            key: (0u8, 2u64),
            slot: Some(slots[0].slot),
            pseudonym: None,
            dormancy: Dormancy::Votes,
        },
        StandingMember {
            key: (0, 1),
            slot: None,
            pseudonym: None,
            dormancy: Dormancy::Votes,
        },
        StandingMember {
            key: (1, 0),
            slot: Some(slots[1].slot),
            pseudonym: None,
            dormancy: Dormancy::GrantedBy(1),
        },
        StandingMember {
            key: (0, 3),
            slot: Some(slots[2].slot),
            pseudonym: None,
            dormancy: Dormancy::Recovery,
        },
        StandingMember {
            key: (2, 0),
            slot: Some(out),
            pseudonym: Some(enrolment),
            dormancy: Dormancy::Votes,
        },
        StandingMember {
            key: (1, 1),
            slot: None,
            pseudonym: None,
            dormancy: Dormancy::Votes,
        },
    ];
    let entries = standing_entries(&members);
    let by_slot = |slot: SlotId| *entries.iter().find(|x| x.slot == slot).unwrap();
    assert_eq!(entries.len(), 4);
    let facts = |slot: SlotId| {
        let x = by_slot(slot);
        (x.order, x.dormant, x.pseudonym)
    };
    assert_eq!(facts(slots[0].slot), (1, 0, None));
    assert_eq!(facts(slots[1].slot), (3, 3, None));
    assert_eq!(facts(slots[2].slot), (2, 2, None));
    assert_eq!(facts(out), (4, 0, Some(enrolment)));
    let mut cut = cut_body(slots.clone(), 1);
    cut.standing = entries;
    assert!(standing_consistent(
        &cut,
        |slot| slot == out,
        |id, slot| id == enrolment && slot == out
    ));
    // A granter that four entries outrank: k is 5, n + 1.
    let mut later = members;
    later[2].dormancy = Dormancy::GrantedBy(5);
    later[5].key = (3, 0);
    let entries = standing_entries(&later);
    assert_eq!(
        entries
            .iter()
            .find(|x| x.slot == slots[1].slot)
            .unwrap()
            .dormant,
        2 + 5
    );
    cut.standing = entries;
    assert!(standing_consistent(
        &cut,
        |slot| slot == out,
        |id, slot| id == enrolment && slot == out
    ));
}

// ---------------------------------------------------------------------------
// A replica's check against the record.

#[test]
fn a_cut_against_its_record() {
    let v = family("skeleton_cuts");
    let history = History::of(&v["events"]);
    let cut = read_cut(
        history
            .log
            .event(history.id("P0: cut of P checkpoints"))
            .unwrap(),
    )
    .unwrap();
    // peers.json's `record_check`: each case's `slot` entries, `[c, index,
    // maker, pseudonym]` with the pseudonym's device ID or empty bytes.
    for case in v["record_check"].as_array().unwrap() {
        let record: Vec<Option<RecordSlot>> = case["slots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|slot| {
                let index = u8::try_from(slot[1].as_u64().unwrap()).unwrap();
                let pseudonym = hex(&slot[3]);
                Some(RecordSlot {
                    slot: SlotId::new(
                        common::array::<32>(&slot[0]),
                        index,
                        EventId(common::array::<32>(&slot[2])),
                    ),
                    pseudonym: (!pseudonym.is_empty())
                        .then(|| frasil_crypto::device::DeviceId(pseudonym.try_into().unwrap())),
                })
            })
            .collect();
        let verdict = match check_against_record(&history.log, &cut, &record) {
            Ok(()) => "valid".to_string(),
            Err(class) => frasil_base::errors::Class::name(class).to_string(),
        };
        assert_eq!(verdict, text(&case["verdict"]), "{}", case["name"]);
    }

    let record: Vec<Option<RecordSlot>> = cut
        .slots
        .iter()
        .map(|e| {
            Some(RecordSlot {
                slot: e.slot,
                pseudonym: entry_pseudonym(&history.log, e),
            })
        })
        .collect();
    assert_eq!(check_against_record(&history.log, &cut, &record), Ok(()));
    // In another order, and with an administrator without a slot or not
    // named at all: the cut's other slots map to no device.
    let mut reversed = record.clone();
    reversed.reverse();
    assert_eq!(check_against_record(&history.log, &cut, &reversed), Ok(()));
    assert_eq!(
        check_against_record(&history.log, &cut, &record[1..]),
        Ok(())
    );
    let mut without = record.clone();
    without[0] = None;
    assert_eq!(check_against_record(&history.log, &cut, &without), Ok(()));
    // Another pseudonym, or none where the cut's slot has one.
    let bad = Err(PeersClass::BadTwin);
    let mut other = record.clone();
    other[0].as_mut().unwrap().pseudonym = None;
    assert_eq!(check_against_record(&history.log, &cut, &other), bad);
    let mut stranger = record.clone();
    stranger[0].as_mut().unwrap().pseudonym = Some(frasil_crypto::device::DeviceId([3; 32]));
    assert_eq!(check_against_record(&history.log, &cut, &stranger), bad);
}

// ---------------------------------------------------------------------------
// Truncation's answers.

#[test]
fn truncation_waits_for_the_retention() {
    let at = |t| frasil_base::time::Reading {
        timeline: t,
        wall: None,
        run: 1,
    };
    assert!(!may_truncate(
        &at(100),
        &at(100 + CUT_RETENTION - 1),
        CUT_RETENTION
    ));
    assert!(may_truncate(
        &at(100),
        &at(100 + CUT_RETENTION),
        CUT_RETENTION
    ));
    assert!(may_truncate(&at(5), &at(5), 0));
}

#[test]
fn deleted_ids_place_and_are_missing() {
    let (stored, deleted, unknown) = (EventId([1; 32]), EventId([2; 32]), EventId([3; 32]));
    let deleted_ids: BTreeSet<EventId> = [deleted].into();
    let is_stored = |id: EventId| id == stored;
    assert_eq!(
        placeable(&[stored, deleted], is_stored, &deleted_ids),
        Ok(())
    );
    assert_eq!(
        placeable(&[unknown, stored, unknown], is_stored, &deleted_ids),
        Err(vec![unknown])
    );
    assert_eq!(
        answer_want(stored, is_stored, &deleted_ids),
        WantAnswer::Serve
    );
    assert_eq!(
        answer_want(deleted, is_stored, &deleted_ids),
        WantAnswer::Missing
    );
    assert_eq!(
        answer_want(unknown, is_stored, &deleted_ids),
        WantAnswer::Missing
    );
}

// ---------------------------------------------------------------------------
// The model check (skeleton_cuts.py, `check_skeleton`), seeded.

/// splitmix64: a seeded source for the model's choices.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

const DEVICES: [&str; 3] = ["P", "A", "B"];
/// The device of the scripted late enrolment that opens most histories,
/// which takes no part in the random steps.
const LATE_DEVICE: &str = "C";
/// The share of histories, in percent, opened with that late enrolment, as
/// the reference's `LATE_EPISODES` (0.75).
const LATE_EPISODES: usize = 75;

/// The ranks the model grants: the top one, and two below it.
const RANKS: [u8; 3] = [MAX_RANK, 200, 100];

/// The streams the model's writers release and restore.
const STREAMS: [[u8; 16]; 2] = [[0x78; 16], [0x79; 16]];

/// A random skeleton with cuts, as `random_skeleton` builds one: each
/// device and its pseudonym share one view, and sync with others. Each
/// administrator grants a rank at most its own, and sometimes tries to
/// remove one of a higher rank, the founder included, which the peer voids
/// (`HigherRank`). An administrator granted and not enrolled enrols, after
/// syncing or apart on its own view, its pseudonym acknowledging and its
/// device anchoring there, while another administrator may checkpoint
/// without it: the enrolment is concurrent with that cut, and late once the
/// cut is in effect. An administrator may enrol and never return, after
/// which a senior or a junior may remove it, or nobody. A member removed by
/// one that does not outrank it is heard by the next checkpoint, its out
/// slot's standing entry naming its pseudonym's enrolment, and that
/// pseudonym keeps voting. An administrator may disown another's slot: the
/// member stays an administrator in the roster with no slot, and has no
/// standing entry, until it is granted again. A dishonest
/// administrator takes another's view and checkpoints without fencing, and
/// sometimes names its cut without citing it. Pseudonyms ask for erasure
/// and credentials, each on its own view, so that some requests are
/// concurrent with cuts; devices release and restore two streams. An honest
/// client signs, beside every skeleton event of its pseudonym, an event of
/// its device, so that the two vote alike. At the end, an administrator
/// whose enrolment is late under the cut of a checkpoint it votes for, the
/// one it follows or else the earliest pending one that waits for its slot,
/// enrols its slot again after it (peers.md, "A late enrolment"), its
/// binding sealed as peers.md, 2.5, says, and its device votes.
struct Model {
    b: Builder,
    seed: u64,
    fresh: u64,
    devices: BTreeMap<&'static str, Rc<Signer>>,
    /// Each administrator's current pseudonym and slot.
    pseudonyms: BTreeMap<&'static str, (Rc<Signer>, SlotId)>,
    /// Each administrator's rank.
    ranks: BTreeMap<&'static str, u8>,
    views: BTreeMap<&'static str, BTreeSet<EventId>>,
    cuts: Vec<EventId>,
    /// The twins of removals of an administrator of a higher rank than the
    /// remover's.
    higher: Vec<EventId>,
    snapshots: Vec<BTreeMap<&'static str, BTreeSet<EventId>>>,
    /// Administrators granted and not enrolled yet: their slot and token.
    unenrolled: BTreeMap<&'static str, (SlotId, [u8; 32])>,
    /// Each administrator's last slot and token, as granted, and who
    /// granted it.
    granted: BTreeMap<&'static str, (SlotId, [u8; 32])>,
    granted_by: BTreeMap<&'static str, &'static str>,
    /// The device each administrator slot was made for.
    slot_devices: BTreeMap<SlotId, &'static str>,
    /// The body key of each space event that names a twin: the roster
    /// events of the model, under whose twin secrets bindings are sealed.
    body_keys: BTreeMap<EventId, [u8; 32]>,
    /// Enrolments made apart from the others.
    apart: usize,
    /// Each enrolment again after a cut: the administrator, its late
    /// pseudonym, the new enrolment and the cut.
    again: Vec<(
        &'static str,
        frasil_crypto::device::DeviceId,
        EventId,
        EventId,
    )>,
    /// Administrators that enrolled and never returned.
    absent: BTreeSet<&'static str>,
    /// Ever absent, removals included.
    went_absent: usize,
    /// The checkpoints of honest administrators: fenced, citing their cuts.
    honest: BTreeSet<EventId>,
    /// Cuts of dishonest administrators, unfenced.
    rogue: usize,
    /// Checkpoints that name their cut without citing it.
    detached: usize,
    /// The pseudonyms of members a valid lowering put out, which keep
    /// voting, granted again or not: through their out slots, when a
    /// checkpoint hears them.
    former: BTreeMap<&'static str, Vec<Rc<Signer>>>,
    /// Members whose slot another administrator disowned: administrators
    /// with no slot, by the key of the slot they had, until granted again.
    slotless: BTreeMap<&'static str, (u8, Option<frasil_peers::derive::Seniority>)>,
    /// Disowns of another's slot made, votes by former pseudonyms, and
    /// checkpoints whose record has an administrator with no slot.
    disowns: usize,
    former_votes: usize,
    slotless_cuts: usize,
    /// The events before [`Model::tail`].
    pre_tail: BTreeSet<EventId>,
    /// Events a dishonest step signed: unfenced acknowledgements, and the
    /// checkpoints and cuts signed unfenced on another's view.
    dishonest: BTreeSet<EventId>,
    /// Whether the history opened with the scripted late enrolment.
    late_episode: bool,
}

impl Model {
    fn label(&mut self, what: &str) -> [u8; 32] {
        self.fresh += 1;
        builder::example(&format!("cuts/{}/{}/{what}", self.seed, self.fresh))
    }

    fn reach(&self, id: EventId) -> BTreeSet<EventId> {
        let log = &self.b.log;
        log.event(id)
            .map(|event| {
                frasil_events::cuts::reach(log, event.cuts()).expect("the log holds every envelope")
            })
            .unwrap_or_default()
    }

    /// The checkpoint `author` follows in `view`, as the reference's
    /// builder picks it: among the maximal checkpoints of the view, the
    /// smallest its own last event is or reaches, else the smallest.
    fn followed(
        &self,
        author: &frasil_crypto::device::DeviceId,
        view: &BTreeSet<EventId>,
    ) -> Option<EventId> {
        let log = &self.b.log;
        let below = |x: EventId, y: EventId| x == y || self.reach(y).contains(&x);
        let cps: Vec<EventId> = view
            .iter()
            .copied()
            .filter(|c| self.b.checkpoints.contains(c))
            .collect();
        let top: Vec<EventId> = cps
            .iter()
            .copied()
            .filter(|&c| !cps.iter().any(|&d| c != d && below(c, d)))
            .collect();
        let last = view
            .iter()
            .copied()
            .filter(|&i| log.event(i).is_some_and(|e| e.author() == author))
            .max_by_key(|&i| (log.event(i).map_or(0, |e| e.seq()), i));
        if let Some(last) = last {
            let reached = self.reach(last);
            let own = top
                .iter()
                .copied()
                .filter(|&c| c == last || reached.contains(&c))
                .min();
            if own.is_some() {
                return own;
            }
        }
        top.into_iter().min()
    }

    /// Whether `device` may follow checkpoint `c`: the checkpoints its last
    /// event reaches are none concurrent with `c`.
    fn may_follow(&self, device: &'static str, c: EventId) -> bool {
        let log = &self.b.log;
        let Some(last) = log.chain(self.devices[device].device_id()).last().copied() else {
            return true;
        };
        let mut reached = self.reach(last);
        if self.b.checkpoints.contains(&last) {
            reached.insert(last);
        }
        reached
            .iter()
            .all(|&x| frasil_events::cuts::concurrent(log, x, c) == Ok(false))
    }

    /// The parents `signer` cites on `device`'s view: its heads, fenced as
    /// an honest client fences them (the reference's `fence`): no event
    /// concurrent with the checkpoint it follows.
    fn heads(&self, device: &str, signer: &Signer) -> Vec<EventId> {
        let log = &self.b.log;
        let view = &self.views[device];
        let Some(c) = self.followed(signer.device_id(), view) else {
            return log.heads_in(view);
        };
        let before = log.past(c);
        let fenced: BTreeSet<EventId> = view
            .iter()
            .copied()
            .filter(|&x| x == c || before.contains(&x) || log.past(x).contains(&c))
            .collect();
        log.heads_in(&fenced)
    }

    /// An event of `kind` by `signer` on `device`'s view: fenced, or citing
    /// every head of the view.
    fn emit_with(
        &mut self,
        device: &'static str,
        signer: &Signer,
        kind: u8,
        body: Vec<u8>,
        fence: bool,
    ) -> Option<EventId> {
        let parents = if fence {
            self.heads(device, signer)
        } else {
            self.b.log.heads_in(&self.views[device])
        };
        let id = self.b.try_act(signer, kind, body, &parents)?;
        self.views.get_mut(device).unwrap().insert(id);
        Some(id)
    }

    fn emit(
        &mut self,
        device: &'static str,
        signer: &Signer,
        kind: u8,
        body: Vec<u8>,
    ) -> Option<EventId> {
        self.emit_with(device, signer, kind, body, true)
    }

    fn storage(&mut self, device: &'static str, body: StorageBody) -> Option<EventId> {
        let signer = Rc::clone(&self.pseudonyms[device].0);
        self.emit(device, &signer, kind::STORAGE, body.encode())
    }

    fn name(&mut self, device: &'static str, twin: EventId) -> Option<EventId> {
        let signer = Rc::clone(&self.devices[device]);
        let id = self.emit(device, &signer, kind::SPACE, Builder::naming(twin))?;
        let key = self.label("body key");
        self.body_keys.insert(id, key);
        Some(id)
    }

    /// A device's anchor on its view.
    fn anchor(&mut self, device: &'static str) -> Option<EventId> {
        let signer = Rc::clone(&self.devices[device]);
        self.emit(device, &signer, kind::ANCHOR, Vec::new())
    }

    /// `device`'s pseudonym signs `body`, and its device anchors beside it:
    /// an honest client votes with both (peers.md, 3.15, "Clients").
    /// Unfenced, as a dishonest administrator's, the pseudonym's event cites
    /// every head of its view.
    fn request(&mut self, device: &'static str, body: StorageBody, fence: bool) -> Option<()> {
        self.request_id(device, body, fence).map(|_| ())
    }

    /// [`Model::request`], giving the pseudonym's event.
    fn request_id(
        &mut self,
        device: &'static str,
        body: StorageBody,
        fence: bool,
    ) -> Option<EventId> {
        let signer = Rc::clone(&self.pseudonyms[device].0);
        let id = self.emit_with(device, &signer, kind::STORAGE, body.encode(), fence)?;
        self.anchor(device)?;
        Some(id)
    }

    /// The reference's scripted late enrolment (`LATE_EPISODES`): P grants
    /// C administer; C enrols apart and acknowledges, while P checkpoints
    /// without its enrolment and votes; C syncs, follows the checkpoint,
    /// votes, and enrols again after the cut, its new enrolment the slot's
    /// vote; P then removes C, which takes no further part.
    fn late_episode(&mut self) -> Option<()> {
        let c = LATE_DEVICE;
        let everyone: Vec<&'static str> = DEVICES.iter().copied().chain([c]).collect();
        self.grant("P", c, 100, false)?;
        let (slot, token) = self.unenrolled.remove(c)?;
        self.enrol(c, slot, &token)?;
        self.storage(c, StorageBody::Ack)?;
        self.checkpoint("P", false, false)?;
        let cut = *self.cuts.last()?;
        let checkpoint = *self.b.checkpoints.iter().find(|&&x| {
            self.b
                .log
                .event(x)
                .and_then(frasil_peers::skeleton::named_twin)
                == Some(cut)
        })?;
        self.request("P", StorageBody::Ack, true)?;
        self.sync(&everyone);
        self.anchor(c)?;
        let ack = self.enrol_again(c, cut, checkpoint)?;
        let device = Rc::clone(&self.devices[c]);
        let anchor = self.b.try_act(&device, kind::ANCHOR, Vec::new(), &[ack])?;
        self.views.get_mut(c).unwrap().insert(anchor);
        self.sync(&everyone);
        self.remove("P", c)?;
        self.sync(&everyone);
        // C takes no further part: no vote through its former pseudonyms.
        self.former.remove(c);
        self.late_episode = true;
        Some(())
    }

    /// A device releases or restores a stream: a writer request it signs.
    fn writer(&mut self, device: &'static str, body: StorageBody) -> Option<()> {
        let signer = Rc::clone(&self.devices[device]);
        self.emit(device, &signer, kind::STORAGE, body.encode())
            .map(|_| ())
    }

    /// A new pseudonym of `who` enrols `slot` on `who`'s view.
    fn enrol(&mut self, who: &'static str, slot: SlotId, token: &[u8; 32]) -> Option<EventId> {
        self.fresh += 1;
        let pseudonym = builder::pseudonym(&format!("cuts/{}/{}/pseudonym", self.seed, self.fresh));
        let keys = frasil_peers::derive::SlotKeys::from_token(token);
        let body = self.b.enrol_body(&pseudonym, slot, &keys);
        let id = self.emit(who, &pseudonym, kind::STORAGE, body.encode())?;
        self.pseudonyms.insert(who, (Rc::new(pseudonym), slot));
        Some(id)
    }

    fn sync(&mut self, names: &[&'static str]) {
        let all: BTreeSet<EventId> = names.iter().flat_map(|n| self.views[n].clone()).collect();
        for n in names {
            self.views.insert(n, all.clone());
        }
    }

    /// The administrators that act: enrolled, and not absent.
    fn active(&self) -> Vec<&'static str> {
        self.pseudonyms
            .keys()
            .copied()
            .filter(|d| !self.absent.contains(d))
            .collect()
    }

    /// The devices that sync: all but the absent ones.
    fn present(&self) -> Vec<&'static str> {
        DEVICES
            .iter()
            .copied()
            .filter(|d| !self.absent.contains(d))
            .collect()
    }

    fn grant(&mut self, by: &'static str, who: &'static str, rank: u8, enrol: bool) -> Option<()> {
        let (c, salt, token) = (self.label("c"), self.label("salt"), self.label("token"));
        let (map, _) = builder::grant_ranked(&token, rank);
        let twin = self.storage(
            by,
            StorageBody::Change {
                twin: c,
                salt,
                effect: ChangeEffect::Grants(vec![map]),
            },
        )?;
        self.name(by, twin)?;
        self.sync(&[by, who]);
        let slot = SlotId::new(c, 0, twin);
        self.ranks.insert(who, rank);
        self.slotless.remove(who);
        self.granted.insert(who, (slot, token));
        self.granted_by.insert(who, by);
        self.slot_devices.insert(slot, who);
        if enrol {
            self.enrol(who, slot, &token)?;
            self.sync(&[by, who]);
        } else {
            // Granted, not enrolled yet: the other administrators learn of
            // the grant, and a checkpoint meanwhile records its slot with no
            // pseudonym.
            let others: Vec<&'static str> = self
                .active()
                .into_iter()
                .chain([by])
                .filter(|&d| d != who)
                .collect();
            self.sync(&others);
            self.unenrolled.insert(who, (slot, token));
        }
        Some(())
    }

    /// peers.md, "A late enrolment": `who`, whose enrolment is late under
    /// `cut`, enrols its slot again after the cut's checkpoint, which it
    /// votes for, under a new pseudonym, on its view fenced at the
    /// checkpoint, so that it cites none of its late pseudonym's events. Its
    /// binding is sealed under the twin secret of the checkpoint its cuts
    /// name whose cut lists the slot. The enrolment is the slot's vote; the
    /// new pseudonym then acknowledges, and its acknowledgement is returned.
    fn enrol_again(
        &mut self,
        who: &'static str,
        cut: EventId,
        checkpoint: EventId,
    ) -> Option<EventId> {
        let (slot, token) = self.granted[who];
        let late = *self.pseudonyms[who].0.device_id();
        let fresh = builder::pseudonym(&format!("cuts/{}/{who}/again", self.seed));
        let log = &self.b.log;
        let before = log.past(checkpoint);
        let fenced: BTreeSet<EventId> = self.views[who]
            .iter()
            .copied()
            .filter(|&x| {
                x == checkpoint || before.contains(&x) || log.past(x).contains(&checkpoint)
            })
            .collect();
        let parents = log.heads_in(&fenced);
        let declared = log.cuts_for(&self.b.checkpoints, &parents).ok()?;
        assert!(
            declared
                .iter()
                .any(|&x| x == checkpoint || self.reach(x).contains(&checkpoint)),
            "seed {}: an enrolment again follows the checkpoint",
            self.seed
        );
        let listing = declared
            .iter()
            .copied()
            .filter(|&x| {
                log.event(x)
                    .and_then(frasil_peers::skeleton::named_twin)
                    .and_then(|twin| log.event(twin))
                    .and_then(read_cut)
                    .is_some_and(|c| c.slots.iter().any(|entry| entry.slot == slot))
            })
            .min();
        let sealer = match listing {
            Some(x) => x,
            None => self.naming_of(slot.maker)?,
        };
        let secret = frasil_peers::derive::twin_secret(&self.body_keys[&sealer]);
        let keys = frasil_peers::derive::SlotKeys::from_token(&token);
        let StorageBody::Enrol {
            slot: s,
            mldsa,
            slot_mldsa,
            authorization,
            ..
        } = self.b.enrol_body(&fresh, slot, &keys)
        else {
            unreachable!("an enrolment");
        };
        let nonce = self.label("binding nonce");
        let binding = frasil_peers::derive::seal_binding_with(
            &secret,
            &self.b.space,
            slot.reference,
            fresh.device_id(),
            &self.devices[who],
            nonce[..24].try_into().expect("24 bytes"),
        );
        let body = StorageBody::Enrol {
            slot: s,
            mldsa,
            slot_mldsa,
            authorization,
            binding,
        };
        let id = self
            .b
            .try_act(&fresh, kind::STORAGE, body.encode(), &parents)?;
        self.views.get_mut(who).unwrap().insert(id);
        self.pseudonyms.insert(who, (Rc::new(fresh), slot));
        let ack = self.storage(who, StorageBody::Ack)?;
        self.again.push((who, late, id, cut));
        Some(ack)
    }

    /// The space event that names `twin`, in canonical order.
    fn naming_of(&self, twin: EventId) -> Option<EventId> {
        let log = &self.b.log;
        log.canonical()
            .into_iter()
            .find(|&id| log.event(id).and_then(frasil_peers::skeleton::named_twin) == Some(twin))
    }

    fn remove(&mut self, by: &'static str, who: &'static str) -> Option<()> {
        let (c, salt) = (self.label("c"), self.label("salt"));
        let slot = self.pseudonyms[who].1;
        let twin = self.storage(
            by,
            StorageBody::Change {
                twin: c,
                salt,
                effect: ChangeEffect::Lower(slot),
            },
        )?;
        self.name(by, twin)?;
        // A removal of a higher rank is void at the peer: `who` stays.
        if self.ranks[by] < self.ranks[who] {
            self.higher.push(twin);
        } else if let Some((pseudonym, _)) = self.pseudonyms.remove(who) {
            self.ranks.remove(who);
            self.former.entry(who).or_default().push(pseudonym);
        }
        Some(())
    }

    /// `by` disowns `who`'s administrator slot (peers.md, "Storage events",
    /// a disown), its device anchoring beside it. A disown has no roster
    /// twin: `who` stays an administrator in the roster with no slot in the
    /// skeleton, so a checkpoint's record has it with no slot entry and its
    /// cut no standing entry for it. Void at the peer when `who` outranks
    /// `by`. Otherwise `by` may checkpoint at once, and then repairs the
    /// difference as an honest client does before any other skeleton event
    /// (peers.md, 3.15, "Clients"): a demotion, the twin of a lower of the
    /// disowned slot, and a new grant, which `who` enrols.
    fn disown(&mut self, by: &'static str, who: &'static str, checkpoint: bool) -> Option<()> {
        let slot = self.pseudonyms[who].1;
        let signer = Rc::clone(&self.pseudonyms[by].0);
        let id = self.emit(
            by,
            &signer,
            kind::STORAGE,
            StorageBody::Disown { slot }.encode(),
        )?;
        self.anchor(by)?;
        if self.ranks[by] < self.ranks[who] {
            self.higher.push(id);
            return Some(());
        }
        let rank = self.ranks[who];
        let key = {
            let cuts = PeerCuts::new(&self.b.log, Some(&self.views[by]));
            let skeleton = cuts.skeleton();
            (MAX_RANK - rank, skeleton.seniority(slot))
        };
        self.pseudonyms.remove(who);
        self.ranks.remove(who);
        self.slotless.insert(who, key);
        self.disowns += 1;
        if checkpoint {
            self.checkpoint(by, false, false);
        }
        let (c, salt) = (self.label("c"), self.label("salt"));
        let twin = self.storage(
            by,
            StorageBody::Change {
                twin: c,
                salt,
                effect: ChangeEffect::Lower(slot),
            },
        )?;
        self.name(by, twin)?;
        self.grant(by, who, rank, true)
    }

    /// The pairs of active administrators `(a, b)` of the same rank, `a`
    /// junior to `b` in `a`'s view, `b` not the founder.
    fn juniors(&self) -> Vec<(&'static str, &'static str)> {
        let active = self.active();
        active
            .iter()
            .flat_map(|&a| active.iter().map(move |&b| (a, b)))
            .filter(|&(a, b)| {
                a != b && b != "P" && self.ranks[a] == self.ranks[b] && {
                    let cuts = PeerCuts::new(&self.b.log, Some(&self.views[a]));
                    let skeleton = cuts.skeleton();
                    skeleton.seniority(self.pseudonyms[b].1)
                        < skeleton.seniority(self.pseudonyms[a].1)
                }
            })
            .collect()
    }

    /// A member a valid lowering put out votes with its former pseudonym,
    /// its device anchoring beside it, as an honest client does for a
    /// checkpoint that hears it.
    /// Each former pseudonym acknowledges, since a checkpoint hears the
    /// member through the most senior slot made for it, enrolled to the
    /// pseudonym it had then. They cite the heads the device fences at the
    /// checkpoint it follows, and the anchor cites them, so that all follow
    /// the same checkpoints.
    fn former_vote(&mut self, who: &'static str) -> Option<()> {
        let device = Rc::clone(&self.devices[who]);
        let parents = self.heads(who, &device);
        let mut acks = Vec::new();
        for signer in self.former[who].clone() {
            let ack =
                self.b
                    .try_act(&signer, kind::STORAGE, StorageBody::Ack.encode(), &parents)?;
            self.views.get_mut(who).unwrap().insert(ack);
            acks.push(ack);
        }
        let anchor = self.b.try_act(&device, kind::ANCHOR, Vec::new(), &acks)?;
        self.views.get_mut(who).unwrap().insert(anchor);
        self.former_votes += 1;
        Some(())
    }

    /// The standing entries of the checkpoint record over `past`, as
    /// `standing_of` gives them (peers.md, "Storage events"): one for each
    /// slot of the cut, each mapped to the device it was made for, and one
    /// for the most senior slot made for each member the checkpoint hears,
    /// out in the skeleton of `past`, naming the root or enrolment of the
    /// pseudonym enrolled in it: a device lowered in the checkpoint's window
    /// by a valid lower, the twin of a roster removal, signed neither by
    /// itself nor by a slot that outranks it, and not kept in. An
    /// administrator whose slot was disowned has none, and no entry. Orders
    /// by rank, highest first, then by seniority, 1 to the number of
    /// entries; none dormant.
    fn standing(
        &self,
        cuts: &PeerCuts<'_>,
        past: &BTreeSet<EventId>,
        slots: &[SlotEntry],
    ) -> Vec<StandingEntry> {
        let log = &self.b.log;
        let skeleton = cuts.skeleton_of(past);
        let key = |slot: SlotId| (MAX_RANK - skeleton.rank(slot), skeleton.seniority(slot));
        let mut members: Vec<StandingMember<_>> = slots
            .iter()
            .map(|entry| StandingMember {
                key: key(entry.slot),
                slot: Some(entry.slot),
                pseudonym: None,
                dormancy: Dormancy::Votes,
            })
            .collect();
        members.extend(self.slotless.values().map(|&key| StandingMember {
            key,
            slot: None,
            pseudonym: None,
            dormancy: Dormancy::Votes,
        }));
        let kept: BTreeSet<&str> = slots
            .iter()
            .filter_map(|entry| self.slot_devices.get(&entry.slot).copied())
            .collect();
        let mut heard: BTreeSet<&str> = BTreeSet::new();
        for &id in skeleton.skeleton_events() {
            let removal = matches!(skeleton.body_of(id), Some(StorageBody::Change { .. }));
            if !skeleton.is_valid(id) || !removal {
                continue;
            }
            let [target] = skeleton.lowers(id) else {
                continue;
            };
            let Some(&device) = self.slot_devices.get(target) else {
                continue;
            };
            if kept.contains(device) {
                continue;
            }
            let author = log.event(id).map(|e| *e.author());
            let by = author.and_then(|a| skeleton.slot_of(&a));
            if by == Some(*target) || by.is_some_and(|by| key(by) < key(*target)) {
                continue;
            }
            heard.insert(device);
        }
        for device in heard {
            let slot = skeleton
                .merged()
                .iter()
                .filter(|(slot, s)| !s.is_in && self.slot_devices.get(*slot) == Some(&device))
                .map(|(slot, _)| *slot)
                .min_by_key(|&slot| skeleton.seniority(slot));
            if let Some(slot) = slot {
                members.push(StandingMember {
                    key: key(slot),
                    slot: Some(slot),
                    pseudonym: enrolment_of(&skeleton, slot),
                    dormancy: Dormancy::Votes,
                });
            }
        }
        standing_entries(&members)
    }

    /// `by` checkpoints, as the reference's `make_cut` does: its pseudonym
    /// signs the cut first, citing every parent of the checkpoint beside its
    /// own previous event, with the slots of the merged skeleton of that
    /// past and the standing its record gives; the checkpoint cites the cut
    /// and names it (peers.md, "Skeleton cuts", parents). A dishonest one
    /// cites every head of its view, and a detached one does not cite its
    /// cut.
    fn checkpoint(&mut self, by: &'static str, rogue: bool, detached: bool) -> Option<()> {
        let device = Rc::clone(&self.devices[by]);
        let pseudonym = Rc::clone(&self.pseudonyms[by].0);
        let parents = if rogue {
            self.b.log.heads_in(&self.views[by])
        } else {
            self.heads(by, &device)
        };
        let prev = self.b.last.get(pseudonym.device_id()).map(|&(_, id)| id);
        let mut past = BTreeSet::new();
        for p in parents.iter().copied().chain(prev) {
            past.insert(p);
            past.extend(self.b.log.past(p));
        }
        let (epoch, slots, standing) = {
            let cuts = PeerCuts::new(&self.b.log, Some(&past));
            let (epoch, slots) = cuts.slots_for(&past);
            let standing = self.standing(&cuts, &past, &slots);
            (epoch, slots, standing)
        };
        if standing.is_empty() || standing.len() > MAX_STANDING {
            return None;
        }
        let slotless = !self.slotless.is_empty();
        let (twin, salt) = (self.label("c"), self.label("salt"));
        let mut record = [0; 64];
        record[..32].copy_from_slice(&self.label("record"));
        let body = StorageBody::Cut(Cut {
            twin,
            salt,
            record,
            epoch,
            slots,
            standing,
        });
        let cut = self
            .b
            .try_act(&pseudonym, kind::STORAGE, body.encode(), &parents)?;
        self.views.get_mut(by).unwrap().insert(cut);
        let mut cited = parents;
        if !detached {
            cited.push(cut);
        }
        let checkpoint = self
            .b
            .try_act(&device, kind::SPACE, Builder::naming(cut), &cited)?;
        self.views.get_mut(by).unwrap().insert(checkpoint);
        let key = self.label("body key");
        self.body_keys.insert(checkpoint, key);
        self.b.checkpoints.insert(checkpoint);
        self.cuts.push(cut);
        if rogue {
            self.rogue += 1;
            self.dishonest.extend([checkpoint, cut]);
        } else {
            self.honest.insert(checkpoint);
        }
        if detached {
            self.detached += 1;
        }
        if slotless {
            self.slotless_cuts += 1;
        }
        Some(())
    }

    fn random(seed: u64, steps: usize) -> Self {
        let mut rng = Rng(seed);
        let devices: BTreeMap<&'static str, Rc<Signer>> = DEVICES
            .iter()
            .chain([&LATE_DEVICE])
            .map(|&d| (d, Rc::new(builder::signer(&format!("cuts/{seed}/{d}")))))
            .collect();
        let mut b = Builder::new(&devices["P"]);
        let p0 = builder::pseudonym(&format!("cuts/{seed}/P0"));
        let c_genesis = builder::example(&format!("cuts/{seed}/c(genesis)"));
        let root = b.root(&devices["P"], &p0, c_genesis);
        let genesis = b.space;
        let root_slot = SlotId::new(c_genesis, 0, root);
        let mut model = Self {
            b,
            seed,
            fresh: 0,
            devices,
            pseudonyms: [("P", (Rc::new(p0), root_slot))].into(),
            ranks: [("P", MAX_RANK)].into(),
            views: DEVICES
                .iter()
                .chain([&LATE_DEVICE])
                .map(|&d| (d, BTreeSet::from([genesis])))
                .collect(),
            cuts: Vec::new(),
            higher: Vec::new(),
            snapshots: Vec::new(),
            unenrolled: BTreeMap::new(),
            granted: BTreeMap::new(),
            granted_by: BTreeMap::new(),
            slot_devices: [(root_slot, "P")].into(),
            body_keys: BTreeMap::new(),
            apart: 0,
            again: Vec::new(),
            absent: BTreeSet::new(),
            went_absent: 0,
            honest: BTreeSet::new(),
            rogue: 0,
            detached: 0,
            former: BTreeMap::new(),
            slotless: BTreeMap::new(),
            disowns: 0,
            former_votes: 0,
            slotless_cuts: 0,
            pre_tail: BTreeSet::new(),
            dishonest: BTreeSet::new(),
            late_episode: false,
        };
        model.views.get_mut("P").unwrap().insert(root);
        // Attempts on a higher rank, drawn apart so that the other steps
        // keep their draws: an administrator removes one that outranks it,
        // the founder included.
        let mut attempts = Rng(seed.wrapping_mul(7907).wrapping_add(31));
        // Enrolments of administrators granted and not enrolled, drawn
        // apart from the other choices too.
        let mut late = Rng(seed.wrapping_mul(7907).wrapping_add(53));
        // A dishonest administrator's choices.
        let mut adv = Rng(seed.wrapping_mul(7907).wrapping_add(1));
        // Disowns and the votes of members put out, drawn apart too, and
        // made among the random steps of every other seed: the others keep
        // the histories of the steps alone, and meet them in the tail.
        let mut extra = Rng(seed.wrapping_mul(7907).wrapping_add(71));
        let busy = seed.is_multiple_of(2);
        // Most histories open with a late enrolment, drawn apart.
        let mut episode = Rng(seed.wrapping_mul(7907).wrapping_add(83));
        if episode.below(100) < LATE_EPISODES {
            model.late_episode();
            model.snapshots.push(model.views.clone());
        }
        for _ in 0..steps {
            // A junior disowns its senior's slot, of the same rank: a
            // lowering valid at the peer that excuses nobody, since no roster
            // event made it, and that the junior repairs.
            if busy && extra.below(100) < 8 {
                let pairs = model.juniors();
                if !pairs.is_empty() {
                    let (by, who) = pairs[extra.below(pairs.len())];
                    let checkpoint = extra.below(100) < 50;
                    if model.disown(by, who, checkpoint).is_some() {
                        model.snapshots.push(model.views.clone());
                    }
                }
            }
            // A junior removes its senior of the same rank: the next
            // checkpoint hears the senior.
            if busy && extra.below(100) < 20 {
                let pairs = model.juniors();
                if !pairs.is_empty() {
                    let (by, who) = pairs[extra.below(pairs.len())];
                    model.sync(&[by, who]);
                    if model.remove(by, who).is_some() {
                        model.snapshots.push(model.views.clone());
                    }
                }
            }
            let voters: Vec<&'static str> = model
                .former
                .keys()
                .copied()
                .filter(|d| !model.absent.contains(d))
                .collect();
            if busy && !voters.is_empty() && extra.below(100) < 50 {
                // It meets everyone present first, so that it votes for
                // the checkpoints they hold.
                let who = voters[extra.below(voters.len())];
                let present = model.present();
                model.sync(&present);
                if model.former_vote(who).is_some() {
                    model.snapshots.push(model.views.clone());
                }
            }
            let active = model.active();
            let admins: Vec<&'static str> = model.pseudonyms.keys().copied().collect();
            if attempts.below(100) < 10 {
                let pairs: Vec<(&'static str, &'static str)> = active
                    .iter()
                    .flat_map(|&a| admins.iter().map(move |&b| (a, b)))
                    .filter(|&(a, b)| model.ranks[a] < model.ranks[b])
                    .collect();
                if !pairs.is_empty() {
                    let (by, who) = pairs[attempts.below(pairs.len())];
                    if model.remove(by, who).is_some() {
                        model.snapshots.push(model.views.clone());
                    }
                }
            }
            let active = model.active();
            let admins: Vec<&'static str> = model.pseudonyms.keys().copied().collect();
            let by = rng.pick(&active);
            let op = rng.below(100);
            let enrols_now = !model.unenrolled.is_empty() && late.below(100) < 30;
            let granted: Vec<&'static str> = admins
                .iter()
                .chain(model.unenrolled.keys())
                .copied()
                .collect();
            let done = if enrols_now {
                let who = *model.unenrolled.keys().next().unwrap();
                let apart = late.below(100) < 60;
                if !apart {
                    model.sync(&[who, by]);
                }
                let (slot, token) = model.unenrolled.remove(who).unwrap();
                let enrolled = model.enrol(who, slot, &token).map(|_| ());
                if enrolled.is_some() && apart {
                    // Enrolled on its own view, and built on: its pseudonym
                    // acknowledges and its device anchors before they meet
                    // anyone. Meanwhile the administrator that granted it
                    // may checkpoint without it: its cut lists the slot
                    // with no pseudonym.
                    model.apart += 1;
                    model.request(who, StorageBody::Ack, true);
                    let granter = model.granted_by[who];
                    if granter != who
                        && model.active().contains(&granter)
                        && late.below(100) < 90
                        && model.checkpoint(granter, false, false).is_some()
                        && late.below(100) < 60
                    {
                        // The others meet the checkpoint, not the
                        // enrolment, and vote.
                        let others: Vec<&'static str> =
                            model.active().into_iter().filter(|&d| d != who).collect();
                        model.sync(&others);
                        for other in others {
                            model.request(other, StorageBody::Ack, true);
                        }
                    }
                } else if enrolled.is_some() {
                    model.sync(&[by, who]);
                }
                enrolled
            } else if op < 20 && granted.len() < 3 {
                let who = *DEVICES.iter().find(|d| !granted.contains(d)).unwrap();
                let allowed: Vec<u8> = RANKS
                    .iter()
                    .copied()
                    .filter(|&r| r <= model.ranks[by])
                    .collect();
                let rank = rng.pick(&allowed);
                // Often the granter's own rank, so that a junior may remove
                // or disown its senior.
                let rank = if busy && extra.below(100) < 50 {
                    model.ranks[by]
                } else {
                    rank
                };
                let enrol = rng.below(100) < 60;
                if model.absent.contains(who) {
                    None
                } else {
                    model.grant(by, who, rank, enrol)
                }
            } else if op < 30 && admins.len() > 1 {
                // Absent administrators included: a senior or a junior may
                // remove one that never returns.
                let others: Vec<&'static str> = admins
                    .iter()
                    .copied()
                    .filter(|&a| a != by && a != "P")
                    .collect();
                if others.is_empty() {
                    None
                } else {
                    let who = rng.pick(&others);
                    model.remove(by, who)
                }
            } else if op < 50 {
                // Votes: the pseudonym acknowledges and the device anchors.
                // A dishonest one acknowledges without fencing.
                let name = rng.pick(&active);
                let rogue = adv.below(100) < 20;
                model.sync(&[name]);
                let ack = model.request_id(name, StorageBody::Ack, !rogue);
                if rogue && let Some(ack) = ack {
                    model.dishonest.insert(ack);
                }
                ack.map(|_| ())
            } else if op < 55 {
                // An administrator enrolled and synced that never returns.
                let candidates: Vec<&'static str> =
                    active.iter().copied().filter(|&d| d != "P").collect();
                if candidates.is_empty() || !model.absent.is_empty() {
                    None
                } else {
                    let who = rng.pick(&candidates);
                    let present = model.present();
                    model.sync(&present);
                    model.absent.insert(who);
                    model.went_absent += 1;
                    Some(())
                }
            } else if op < 61 {
                let name = rng.pick(&active);
                model.request(name, StorageBody::Erase, true)
            } else if op < 65 {
                let name = rng.pick(&active);
                let body = StorageBody::Credentials {
                    live: None,
                    recovery: Some(Vec::new()),
                };
                model.request(name, body, true)
            } else if op < 72 {
                // A writer releases or restores a stream (peers.md, "Release
                // and restore"): truncation keeps what decides it.
                let name = rng.pick(&model.present());
                let stream = rng.pick(&STREAMS);
                let body = if rng.below(100) < 60 {
                    StorageBody::Release { stream }
                } else {
                    StorageBody::Restore(Restored::Stream(stream))
                };
                model.writer(name, body)
            } else if op < 85 {
                let rogue = adv.below(100) < 35;
                if rogue {
                    // A dishonest administrator: it takes another member's
                    // view, then checkpoints without fencing.
                    let other = adv.pick(&model.present());
                    let theirs = model.views[other].clone();
                    model.views.get_mut(by).unwrap().extend(theirs);
                }
                let detached = rogue && adv.below(100) < 30;
                model.checkpoint(by, rogue, detached)
            } else {
                let present = model.present();
                let a = rng.pick(&present);
                let others: Vec<&'static str> =
                    present.iter().copied().filter(|&d| d != a).collect();
                if others.is_empty() {
                    None
                } else {
                    let b = rng.pick(&others);
                    model.sync(&[a, b]);
                    Some(())
                }
            };
            if done.is_some() {
                model.snapshots.push(model.views.clone());
            }
        }
        let present = model.present();
        model.sync(&present);
        // peers.md, "A late enrolment": an administrator whose enrolment is
        // late under the cut of the checkpoint it follows, a cut that lists
        // its slot with another pseudonym or none, enrols the slot again
        // after it once it votes for the checkpoint, and its device votes:
        // the cut waits for the slot, and the enrolment is its vote.
        let again: Vec<(&'static str, EventId, EventId)> = {
            let cuts = PeerCuts::new(&model.b.log, None);
            let chain = cuts.chain();
            let mut pending: Vec<EventId> = cuts
                .cuts()
                .map(|(id, _)| id)
                .filter(|id| !chain.contains(id) && cuts.validity(*id).is_valid())
                .collect();
            pending.sort_by_key(|&id| (std::cmp::Reverse(cuts.body(id).unwrap().epoch), id));
            let mut out = Vec::new();
            for who in model.active() {
                if who == "P" || !model.granted.contains_key(who) {
                    continue;
                }
                let (signer, slot) = &model.pseudonyms[who];
                let mine: Vec<EventId> = model
                    .b
                    .log
                    .chain(signer.device_id())
                    .into_iter()
                    .filter(|&id| {
                        model.b.log.event(id).is_some_and(|e| {
                            matches!(
                                StorageBody::read(e.unverified_body()),
                                Ok(StorageBody::Enrol { .. })
                            )
                        })
                    })
                    .collect();
                // Late under `cut`: its slot is a slot of the cut that names
                // no enrolment of its pseudonym, and its enrolment is held,
                // neither in the checkpoint's past nor after it.
                let late_under = |cut: EventId| {
                    let late = cuts.late_at(cut);
                    !mine.is_empty()
                        && mine.iter().all(|id| late.contains(id))
                        && cuts.body(cut).unwrap().slots.iter().any(|entry| {
                            entry.slot == *slot
                                && entry.pseudonym.is_none_or(|p| !mine.contains(&p))
                        })
                };
                // The cut of the checkpoint the device follows, as the
                // reference picks it; else the earliest pending cut that
                // waits for its slot, when the device, which holds it, may
                // follow its checkpoint: its own events reach no checkpoint
                // concurrent with it. Its vote cites the new pseudonym's.
                let followed = model.followed(model.devices[who].device_id(), &model.views[who]);
                let picked = pending
                    .iter()
                    .chain(chain.iter().rev())
                    .copied()
                    .find(|&k| followed.is_some() && cuts.checkpoint_of(k) == followed)
                    .filter(|&k| late_under(k))
                    .or_else(|| {
                        pending
                            .iter()
                            .copied()
                            .filter(|&k| late_under(k))
                            .min_by_key(|&k| (cuts.body(k).unwrap().epoch, k))
                            .filter(|&k| model.may_follow(who, cuts.checkpoint_of(k).unwrap()))
                    });
                if let Some(cut) = picked {
                    out.push((who, cut, cuts.checkpoint_of(cut).unwrap()));
                }
            }
            out
        };
        let mut enrolled_again = Vec::new();
        for (who, cut, checkpoint) in again {
            if let Some(ack) = model.enrol_again(who, cut, checkpoint) {
                enrolled_again.push((who, ack));
            }
        }
        if !enrolled_again.is_empty() {
            let present = model.present();
            model.sync(&present);
            // Each device votes for the checkpoint its new pseudonym votes
            // for, citing that pseudonym's acknowledgement.
            for (who, ack) in enrolled_again {
                let device = Rc::clone(&model.devices[who]);
                if let Some(anchor) = model.b.try_act(&device, kind::ANCHOR, Vec::new(), &[ack]) {
                    model.views.get_mut(who).unwrap().insert(anchor);
                }
            }
            model.sync(&present);
        }
        model.pre_tail = model.b.log.canonical().into_iter().collect();
        model.tail(&mut extra);
        model
    }

    /// Everyone present meets, and every active administrator votes, with
    /// its pseudonym and its device; so does every member put out, with its
    /// former pseudonym.
    fn vote_round(&mut self) {
        let present = self.present();
        self.sync(&present);
        for who in self.active() {
            self.request(who, StorageBody::Ack, true);
            self.sync(&present);
        }
        let former: Vec<&'static str> = self
            .former
            .keys()
            .copied()
            .filter(|d| present.contains(d))
            .collect();
        for who in former {
            self.former_vote(who);
            self.sync(&present);
        }
        self.snapshots.push(self.views.clone());
    }

    /// After the random steps, the cases peers.md, "Skeleton cuts", adds,
    /// over whatever history the seed made: a junior disowns its senior's
    /// slot of the same rank and checkpoints before it repairs it, so that a
    /// checkpoint's record has an administrator with no slot; a junior
    /// removes its senior of the same rank, so that the next checkpoints
    /// hear it and it votes through its out slot; and a writer releases a stream
    /// apart while another checkpoints, the release late under that cut,
    /// then in the next checkpoint's past. Each checkpoint is voted for by
    /// everyone.
    fn tail(&mut self, rng: &mut Rng) {
        let present = self.present();
        self.sync(&present);
        let pairs = self.juniors();
        if !pairs.is_empty() {
            let (by, who) = pairs[rng.below(pairs.len())];
            self.disown(by, who, true);
            self.snapshots.push(self.views.clone());
            self.sync(&present);
        }
        let pairs = self.juniors();
        if !pairs.is_empty() {
            let (by, who) = pairs[rng.below(pairs.len())];
            if self.remove(by, who).is_some() {
                self.snapshots.push(self.views.clone());
            }
        }
        self.vote_round();
        let active = self.active();
        let Some(&first) = active.get(rng.below(active.len().max(1))) else {
            return;
        };
        if self.checkpoint(first, false, false).is_some() {
            self.snapshots.push(self.views.clone());
        }
        self.vote_round();
        // A writer releases apart, while an administrator checkpoints
        // without the release.
        let present = self.present();
        let writer = present[rng.below(present.len())];
        let stream = STREAMS[rng.below(STREAMS.len())];
        self.writer(writer, StorageBody::Release { stream });
        let others: Vec<&'static str> =
            self.active().into_iter().filter(|&d| d != writer).collect();
        if let Some(&second) = others.get(rng.below(others.len().max(1))) {
            let voters: Vec<&'static str> =
                present.iter().copied().filter(|&d| d != writer).collect();
            self.sync(&voters);
            if self.checkpoint(second, false, false).is_some() {
                self.snapshots.push(self.views.clone());
            }
        }
        self.vote_round();
        // The next checkpoint's past holds the late release.
        let active = self.active();
        let third = if active.contains(&writer) {
            writer
        } else {
            let Some(&any) = active.get(rng.below(active.len().max(1))) else {
                return;
            };
            any
        };
        if self.checkpoint(third, false, false).is_some() {
            self.snapshots.push(self.views.clone());
        }
        self.vote_round();
    }

    /// The replicas' rule for checkpoint `c`, whose cut is `cut` (roster.md,
    /// 3.15.4 Votes and effect), over every event of the log, as the model's
    /// roster reads it: each member of the electorate, a device of a
    /// standing entry with `dormant` 0, votes by an event of its device that
    /// follows `c` and reaches no checkpoint concurrent with it, `c` itself
    /// for its author; or is excused by a roster event after `c`, the space
    /// event that names a lowering of its slot, signed by its own device or
    /// by the device of a slot of the cut with a lower order, whatever its
    /// verdict. Chains and validity aside.
    fn replicas_have_in_effect(&self, cuts: &PeerCuts<'_>, cut: EventId, c: EventId) -> bool {
        let log = &self.b.log;
        let body = read_cut(log.event(cut).unwrap()).unwrap();
        let author = *log.event(c).unwrap().author();
        let order_of = |device: &str| {
            body.standing
                .iter()
                .filter(|x| body.slots.iter().any(|entry| entry.slot == x.slot))
                .filter(|x| self.slot_devices.get(&x.slot) == Some(&device))
                .map(|x| x.order)
                .min()
        };
        let clean = |event: &frasil_events::Event| cuts.is_vote(event, cut);
        body.standing.iter().filter(|x| x.dormant == 0).all(|x| {
            let Some(&device) = self.slot_devices.get(&x.slot) else {
                return false;
            };
            let id = *self.devices[device].device_id();
            let voted = author == id || log.events().any(|e| *e.author() == id && clean(e));
            let excused = log.events().any(|e| {
                if e.kind() != kind::SPACE || !clean(e) {
                    return false;
                }
                let lowers = frasil_peers::skeleton::named_twin(e)
                    .and_then(|twin| log.event(twin))
                    .and_then(|twin| StorageBody::read(twin.unverified_body()).ok())
                    .and_then(|twin| twin.lowered())
                    == Some(x.slot);
                let signer = self
                    .devices
                    .iter()
                    .find(|(_, s)| s.device_id() == e.author())
                    .map(|(d, _)| *d);
                lowers
                    && signer.is_some_and(|signer| {
                        signer == device || order_of(signer).is_some_and(|o| o < x.order)
                    })
            });
            voted || excused
        })
    }
}

#[derive(Debug, Default)]
struct Totals {
    events: usize,
    cuts: usize,
    effective: usize,
    peers: usize,
    compared: usize,
    waited: usize,
    /// Cut verdicts at a peer that kept everything, by class.
    cut_verdicts: BTreeMap<String, usize>,
    /// Removals of a higher rank attempted.
    higher_rank_attempts: usize,
    /// Of those, the twins the peer judged `HigherRank`.
    higher_rank_void: usize,
    /// And those it judged otherwise, by verdict.
    higher_rank_otherwise: BTreeMap<String, usize>,
    /// Enrolments made apart from the others.
    apart_enrolments: usize,
    /// Skeleton events late at a peer that kept everything.
    late_at_peer: usize,
    /// Enrolments again after a cut.
    re_enrolments: usize,
    /// Re-enrolments whose bindings a replica that kept everything and one
    /// that forgot compared.
    bound_again: usize,
    /// Administrators that enrolled and never returned.
    absent: usize,
    /// Waited slots excused, in the cuts in effect.
    excused: usize,
    /// Cuts of dishonest administrators, and checkpoints that do not cite
    /// their cuts.
    rogue_cuts: usize,
    detached: usize,
    /// Cuts in effect at the peer whose checkpoints are honest, each
    /// checked in effect by the replicas' rule.
    replica_checked: usize,
    /// Erasures and credentials requests the peer was free to carry out
    /// at some point, and of those, the ones a later cut made late.
    requests_freed: usize,
    late_after_carry_out: usize,
    /// Requests that waited for a cut at some point.
    requests_waited: usize,
    /// Released states compared between a peer that truncated and one that
    /// kept everything, and how many were released.
    streams_compared: usize,
    released: usize,
    /// Disowns of another's slot, and checkpoints whose record has an
    /// administrator with no slot.
    disowns: usize,
    slotless_cuts: usize,
    /// Votes of members put out, standing entries naming an out slot's
    /// pseudonym, votes counted through an out slot in a cut in effect, and
    /// of those, in a cut after the one a peer truncated under.
    former_votes: usize,
    heard_entries: usize,
    heard_votes: usize,
    heard_votes_truncated: usize,
    /// Releases and restores late under a cut of the chain while a later
    /// checkpoint's past holds them.
    late_then_past: usize,
    /// Histories opened with the scripted late enrolment.
    late_episodes: usize,
    /// Cuts in effect over a view or a prefix of the history, each checked
    /// still in effect over the final set (monotonicity).
    monotone_checked: usize,
    /// Cuts in effect at the peer whose checkpoints the replicas' rule does
    /// not have in effect: every one on a dishonest signer's own event,
    /// which the safety invariant asserts.
    peer_ahead: usize,
    peer_ahead_dishonest: usize,
    /// Re-enrolments checked valid in the world after their cut at a peer
    /// that kept everything, and at one that truncated under that cut.
    bound_peer: usize,
    bound_truncated: usize,
}

/// The releases and restores among `held`.
fn writer_requests(
    log: &frasil_events::Log,
    held: &BTreeSet<EventId>,
) -> Vec<(EventId, StorageBody)> {
    held.iter()
        .filter_map(|&id| {
            let body = StorageBody::read(log.event(id)?.unverified_body()).ok()?;
            body.storage_type()
                .is_writer_request()
                .then_some((id, body))
        })
        .collect()
}

fn check_retained_tallies(log: &frasil_events::Log) {
    let cache = std::sync::Arc::new(frasil_peers::cut::CutTallies::default());
    let mut prefix = frasil_events::Log::new(log.genesis().clone()).unwrap();
    for id in log.canonical().into_iter().filter(|&id| id != log.id()) {
        prefix.place(log.event(id).unwrap().clone()).unwrap();
        let retained = PeerCuts::new(&prefix, None).with_tallies(cache.clone());
        let fresh = PeerCuts::new(&prefix, None);
        for (cut, _) in fresh.cuts() {
            assert_eq!(
                retained.tally(cut),
                fresh.tally(cut),
                "after {id:?}, cut {cut:?}"
            );
            assert_eq!(retained.in_effect(cut), fresh.in_effect(cut));
        }
        assert_eq!(retained.chain(), fresh.chain());
        assert_eq!(retained.awaiting_votes(), fresh.awaiting_votes());
    }
}

/// [`check_retained_tallies`] over another arrival order: the events in a
/// random order that keeps each after its parents, so that votes come
/// before or after the enrolments that make them verify, lowerings before
/// or after the votes they excuse, and now and then an event already placed
/// arrives again. After each arrival the retained tally of every cut equals
/// a fresh one.
fn check_retained_tallies_out_of_order(log: &frasil_events::Log, seed: u64) {
    let mut rng = Rng(seed.wrapping_mul(7907).wrapping_add(97));
    let mut pending: Vec<EventId> = log
        .canonical()
        .into_iter()
        .filter(|&id| id != log.id())
        .collect();
    let mut placed: BTreeSet<EventId> = BTreeSet::from([log.id()]);
    let cache = std::sync::Arc::new(frasil_peers::cut::CutTallies::default());
    let mut prefix = frasil_events::Log::new(log.genesis().clone()).unwrap();
    let mut arrivals = 0usize;
    while !pending.is_empty() {
        let ready: Vec<usize> = pending
            .iter()
            .enumerate()
            .filter(|(_, id)| {
                log.event(**id)
                    .unwrap()
                    .parents()
                    .iter()
                    .all(|p| placed.contains(p))
            })
            .map(|(at, _)| at)
            .collect();
        let id = pending.remove(ready[rng.below(ready.len())]);
        prefix.place(log.event(id).unwrap().clone()).unwrap();
        placed.insert(id);
        arrivals += 1;
        // An event arriving again is the same event: nothing counts twice.
        if rng.below(100) < 10 {
            let again: Vec<EventId> = placed.iter().copied().collect();
            let copy = again[rng.below(again.len())];
            prefix.place(log.event(copy).unwrap().clone()).unwrap();
        }
        let retained = PeerCuts::new(&prefix, None).with_tallies(cache.clone());
        let fresh = PeerCuts::new(&prefix, None);
        for (cut, _) in fresh.cuts() {
            assert_eq!(
                retained.tally(cut),
                fresh.tally(cut),
                "seed {seed}, arrival {arrivals}, cut {cut:?}"
            );
            assert_eq!(retained.in_effect(cut), fresh.in_effect(cut));
        }
        assert_eq!(retained.chain(), fresh.chain(), "seed {seed}");
        assert_eq!(retained.awaiting_votes(), fresh.awaiting_votes());
    }
}

fn check_skeleton(seed: u64, totals: &mut Totals) {
    let model = Model::random(seed, 22);
    let log = &model.b.log;
    check_retained_tallies(log);
    check_retained_tallies_out_of_order(log, seed);
    let full_cuts = PeerCuts::new(log, None);
    let full = full_cuts.skeleton();
    let chain = full_cuts.chain();
    totals.events += log.canonical().len();
    totals.cuts += model.cuts.len();
    totals.effective += chain.len();
    totals.apart_enrolments += model.apart;
    totals.re_enrolments += model.again.len();
    totals.absent += model.went_absent;
    totals.rogue_cuts += model.rogue;
    totals.detached += model.detached;
    totals.disowns += model.disowns;
    totals.slotless_cuts += model.slotless_cuts;
    totals.former_votes += model.former_votes;
    totals.late_episodes += usize::from(model.late_episode);
    // Every cut's standing entries are dense, and an out slot's names a root
    // or enrolment of it.
    for &cut in &model.cuts {
        let body = read_cut(log.event(cut).unwrap()).unwrap();
        let mut orders: Vec<u64> = body.standing.iter().map(|x| x.order).collect();
        orders.sort_unstable();
        assert!(
            orders.iter().copied().eq(1..=orders.len() as u64),
            "seed {seed}: standing orders with a gap"
        );
        for x in &body.standing {
            if let Some(p) = x.pseudonym {
                assert!(
                    frasil_peers::cut::enrols(log.event(p).unwrap(), x.slot),
                    "seed {seed}: a standing pseudonym that does not enrol its slot"
                );
                totals.heard_entries += 1;
            }
        }
    }
    for &cut in &model.cuts {
        *totals
            .cut_verdicts
            .entry(cut_verdict_name(full_cuts.validity(cut)))
            .or_default() += 1;
    }
    totals.late_at_peer += full
        .statuses()
        .iter()
        .filter(|(_, status)| {
            matches!(
                status,
                Status::Void {
                    class: PeersClass::Late,
                    ..
                }
            )
        })
        .count();
    // A detached cut has no checkpoint to a peer.
    for &cut in &model.cuts {
        let named = log.canonical().into_iter().any(|id| {
            log.event(id).is_some_and(|e| {
                frasil_peers::skeleton::named_twin(e) == Some(cut) && e.parents().contains(&cut)
            })
        });
        if !named {
            assert_eq!(
                full_cuts.validity(cut),
                Status::Void {
                    class: PeersClass::Unnamed,
                    by: None
                },
                "seed {seed}: a cut no checkpoint cites"
            );
        }
    }
    // The safety invariant of the cut rule (peers.md, "Skeleton cuts", what
    // the peer cannot see): a peer never has a cut in effect whose
    // checkpoint replicas do not have in effect, unless a dishonest signer's
    // own event is among what it counted. Dishonest here: an unfenced
    // acknowledgement, a checkpoint or cut signed unfenced on another's
    // view, a pseudonym's vote whose device casts no vote for the
    // checkpoint (the duty to vote with both, broken), and a lowering that
    // excuses at the peer with no valid roster event after the checkpoint.
    for &cut in &chain {
        let c = full_cuts.checkpoint_of(cut).unwrap();
        let tally = full_cuts.tally(cut).unwrap();
        totals.excused += tally
            .excuses
            .values()
            .filter(|excuses| !excuses.is_empty())
            .count();
        totals.heard_votes += heard_votes(&full_cuts, cut);
        if model.honest.contains(&c) {
            totals.replica_checked += 1;
        }
        if model.replicas_have_in_effect(&full_cuts, cut, c) {
            continue;
        }
        totals.peer_ahead += 1;
        // The device votes too, as the replicas' rule reads a vote: the
        // checkpoint's own author, or an event of its device that follows
        // the checkpoint and reaches no checkpoint concurrent with it. A
        // pseudonym's vote whose device casts none breaks the duty to vote
        // with both (peers.md, "The administrator's duties").
        let c_author = *log.event(c).unwrap().author();
        let follows = |device: &str| {
            let id = *model.devices[device].device_id();
            c_author == id
                || log
                    .events()
                    .any(|e| *e.author() == id && full_cuts.is_vote(e, cut))
        };
        let honest_vote = |slot: &SlotId, vote: &EventId| {
            !model.dishonest.contains(vote)
                && model
                    .slot_devices
                    .get(slot)
                    .is_some_and(|device| follows(device))
        };
        // A lowering's roster event: valid at the peer, named by a space
        // event that follows the checkpoint as a vote does, which replicas
        // read; else a lowering no roster event made, as only a dishonest
        // outranking administrator signs (peers.md, "Skeleton cuts").
        let honest_excuse = |low: &EventId| {
            !model.dishonest.contains(low)
                && full.status(*low) == Some(Status::Valid)
                && model
                    .naming_of(*low)
                    .and_then(|n| log.event(n))
                    .is_some_and(|n| full_cuts.is_vote(n, cut))
        };
        let honestly = !model.dishonest.contains(&cut)
            && !model.dishonest.contains(&c)
            && tally.waited.iter().all(|slot| {
                tally
                    .excuses
                    .get(slot)
                    .is_some_and(|lows| lows.iter().any(honest_excuse))
                    || tally
                        .votes
                        .get(slot)
                        .is_some_and(|votes| votes.iter().any(|v| honest_vote(slot, v)))
            });
        assert!(
            !honestly,
            "seed {seed}: a cut in effect at the peer, its checkpoint not at replicas, on honest events"
        );
        totals.peer_ahead_dishonest += 1;
    }
    // A late skeleton event is stored with no effect; an administrator
    // whose enrolment was late enrols again after the cut, validly there,
    // and a replica that kept every roster event and one that forgot all
    // but the checkpoints bind the new pseudonym to its device, the late
    // one to none. Judged over the events before the model's tail, which
    // may lower the slot again.
    for &(who, late, enrolment, cut) in &model.again {
        if !chain.contains(&cut) {
            continue;
        }
        // Valid in the world after the cut it was made after, whatever
        // followed, the slot enrolled to it there.
        let after = full_cuts.skeleton_after(cut).expect("a cut of the chain");
        assert!(
            after.is_valid(enrolment),
            "seed {seed}: a re-enrolment is void"
        );
        let fresh = *log.event(enrolment).unwrap().author();
        assert_eq!(after.slot_of(&late), None, "seed {seed}: a late pseudonym");
        totals.bound_peer += 1;
        let all_events: BTreeSet<EventId> = log.canonical().into_iter().collect();
        let world = replica_world(log, cut, &all_events);
        let body = read_cut(log.event(cut).unwrap()).unwrap();
        let cut_slots: BTreeMap<SlotId, _> = body
            .slots
            .iter()
            .filter_map(|entry| {
                let device = model.slot_devices.get(&entry.slot)?;
                Some((
                    entry.slot,
                    (
                        *model.devices[device].device_id(),
                        entry_pseudonym(log, entry),
                    ),
                ))
            })
            .collect();
        let devices: BTreeMap<_, _> = model
            .devices
            .values()
            .map(|signer| {
                (
                    *signer.device_id(),
                    frasil_crypto::device::DeviceKeys {
                        ed: *signer.identity_key(),
                        keys: signer.keys().clone(),
                    },
                )
            })
            .collect();
        let replica = |body_keys: BTreeMap<EventId, [u8; 32]>| common::Facts {
            opened: body_keys.keys().copied().collect(),
            body_keys,
            changes: BTreeMap::new(),
            ranks: BTreeMap::new(),
            devices: devices.clone(),
            administrators: Vec::new(),
            cut_slots: cut_slots.clone(),
        };
        let kept = replica(model.body_keys.clone());
        let forgot = replica(
            model
                .body_keys
                .iter()
                .filter(|(id, _)| model.b.checkpoints.contains(id))
                .map(|(id, key)| (*id, *key))
                .collect(),
        );
        for facts in [&kept, &forgot] {
            let checks = TwinChecks::new(&world, facts);
            assert_eq!(
                checks.bound(&fresh),
                Bound::Device(*model.devices[who].device_id()),
                "seed {seed}: an enrolment after the cut binds no device"
            );
            assert!(
                !matches!(checks.bound(&late), Bound::Device(_)),
                "seed {seed}: a late enrolment binds"
            );
        }
        totals.bound_again += 1;
    }
    // (iv) Every attempt on a higher rank is void at the peer, as
    // `HigherRank`, or for a reason judged before rank (a remover or a
    // target no longer an administrator there). One in the past of the cut
    // in effect is read from the skeleton with no cut.
    let plain_skeleton = Skeleton::new(log, None);
    for &twin in &model.higher {
        totals.higher_rank_attempts += 1;
        match full.status(twin).or_else(|| plain_skeleton.status(twin)) {
            Some(Status::Void {
                class: PeersClass::HigherRank,
                ..
            }) => totals.higher_rank_void += 1,
            other => {
                let text = match other {
                    None => "absent".to_string(),
                    Some(Status::Valid) => "valid".to_string(),
                    Some(Status::Void { class, .. }) => {
                        frasil_base::errors::Class::name(class).to_string()
                    }
                };
                assert_ne!(
                    text, "valid",
                    "seed {seed}: a removal of a higher rank stands"
                );
                *totals.higher_rank_otherwise.entry(text).or_default() += 1;
            }
        }
    }
    // (iii) With no cut in effect, the skeleton is the procedure's own.
    if chain.is_empty() {
        let without_cuts = |s: &Skeleton<'_>| -> Vec<(EventId, Status)> {
            s.statuses()
                .into_iter()
                .filter(|(id, _)| !model.cuts.contains(id))
                .collect()
        };
        assert_eq!(
            without_cuts(&full),
            without_cuts(&plain_skeleton),
            "seed {seed}"
        );
        assert_eq!(
            full.administrators(),
            plain_skeleton.administrators(),
            "seed {seed}"
        );
    }
    // (v) peers.md, "Erasure", step 1: a request the peer may carry out
    // (Free) at some point, with what it holds then (every event signed so
    // far), is never made late by a cut it held then. A cut it did not hold
    // yet and that makes it late is one no honest administrator votes for
    // at a peer that carried out an erasure, since that peer acknowledges
    // nothing more.
    let mut signed: BTreeSet<EventId> = BTreeSet::new();
    let mut freed: BTreeMap<EventId, BTreeSet<EventId>> = BTreeMap::new();
    let mut waited: BTreeSet<EventId> = BTreeSet::new();
    for snapshot in &model.snapshots {
        signed.extend(snapshot.values().flatten().copied());
        if !log.is_closed(&signed) {
            continue;
        }
        let cuts = PeerCuts::new(log, Some(&signed));
        let held_cuts: BTreeSet<EventId> = cuts.cuts().map(|(id, _)| id).collect();
        // Monotone at the peer over every prefix of the history.
        for &k in &held_cuts {
            if cuts.validity(k).is_valid() && cuts.tally(k).is_some_and(|t| t.in_effect()) {
                assert!(
                    full_cuts.validity(k).is_valid()
                        && full_cuts.tally(k).is_some_and(|t| t.in_effect()),
                    "seed {seed}: a cut leaves effect as events arrive"
                );
                totals.monotone_checked += 1;
            }
        }
        for &id in &signed {
            let request = log.event(id).is_some_and(|e| {
                matches!(
                    StorageBody::read(e.unverified_body()),
                    Ok(StorageBody::Erase | StorageBody::Credentials { .. })
                )
            });
            if !request || freed.contains_key(&id) {
                continue;
            }
            match cuts.request_state(id) {
                RequestState::Free => {
                    freed.insert(id, held_cuts.clone());
                }
                RequestState::Wait => {
                    waited.insert(id);
                }
                RequestState::Late => {}
            }
        }
    }
    totals.requests_freed += freed.len();
    totals.requests_waited += waited.len();
    if let Some(&last) = chain.last() {
        let c_last = full_cuts.checkpoint_of(last).unwrap();
        for (&id, cuts_then) in &freed {
            let late = !log.precedes(id, c_last) && full_cuts.follows_cut(id, last) != Ok(true);
            if late {
                let making: Vec<EventId> = chain
                    .iter()
                    .copied()
                    .filter(|&k| {
                        let ck = full_cuts.checkpoint_of(k).unwrap();
                        !log.precedes(id, ck) && full_cuts.follows_cut(id, k) != Ok(true)
                    })
                    .collect();
                assert!(
                    making.iter().all(|k| !cuts_then.contains(k)),
                    "seed {seed}: a request carried out is made late by a cut the peer held"
                );
                totals.late_after_carry_out += 1;
            }
        }
    }
    let all: BTreeSet<EventId> = log.canonical().into_iter().collect();
    let all_requests = writer_requests(log, &all);
    // A release or restore late under a cut of the chain counts for nothing
    // under that cut and every later one, though a later checkpoint's past
    // holds it: its state stays Late, and no truncation keeps it.
    let mut late_then_past: BTreeSet<EventId> = BTreeSet::new();
    for &(id, _) in &all_requests {
        if !full_cuts.late_under_chain(id, &chain) {
            continue;
        }
        assert_eq!(
            full_cuts.request_state(id),
            RequestState::Late,
            "seed {seed}: a late request"
        );
        if chain.iter().any(|&k| {
            let ck = full_cuts.checkpoint_of(k).unwrap();
            log.precedes(id, ck)
        }) {
            late_then_past.insert(id);
        }
    }
    totals.late_then_past += late_then_past.len();
    let mut seen = BTreeSet::new();
    for snapshot in &model.snapshots {
        for view in snapshot.values() {
            if view.is_empty() || !log.is_closed(view) {
                continue;
            }
            let view_cuts = PeerCuts::new(log, Some(view));
            // Monotone (peers.md, "In effect at the peer"): a cut in effect
            // over this view is in effect over every superset, the final one
            // included.
            for (k, _) in view_cuts.cuts() {
                if view_cuts.validity(k).is_valid()
                    && view_cuts.tally(k).is_some_and(|t| t.in_effect())
                {
                    assert!(
                        full_cuts.validity(k).is_valid()
                            && full_cuts.tally(k).is_some_and(|t| t.in_effect()),
                        "seed {seed}: a cut leaves effect as events arrive"
                    );
                    totals.monotone_checked += 1;
                }
            }
            let at_view = view_cuts.chain();
            // (ii) The chain at every view is a prefix of the final one: a
            // peer that holds a part of the history, or that the members
            // reach only now and then, finds the same cuts in effect.
            assert!(chain.starts_with(&at_view), "seed {seed}: a peer's cuts");
            let Some(&base) = at_view.last() else {
                continue;
            };
            if !seen.insert(base) {
                continue;
            }
            // Truncation waits for erasures and credentials requests in the
            // checkpoint's past (peers.md, "Truncation"), each judged where
            // it is judged before the cut takes effect: in the skeleton from
            // the cut before it, or the root, over everything the peer
            // holds, and carried out once stable there. The skeleton after
            // the cut holds none of them, so it would never wait.
            if !truncation_wait_settled(&full_cuts, base) {
                totals.waited += 1;
                continue;
            }
            // (i) A peer that truncated under it, keeping what the plan
            // keeps, agrees with one that kept everything.
            let plan = full_cuts
                .truncation_plan(base, |_, _| false)
                .expect("envelopes held");
            assert!(plan.whole.contains(&log.id()), "seed {seed}: the genesis");
            let held: BTreeSet<EventId> = log
                .canonical()
                .into_iter()
                .filter(|id| !plan.delete.contains(id))
                .collect();
            assert!(
                plan.requests.is_disjoint(&late_then_past),
                "seed {seed}: a truncation keeps a request late under an earlier cut"
            );
            let truncated = PeerCuts::truncated(log, log, held.clone(), base);
            // A peer that truncated under the cut a device enrolled again
            // after holds the new enrolment, valid in the world after it.
            for &(_, _, enrolment, cut) in &model.again {
                if cut == base {
                    let after = truncated.skeleton_after(base).expect("the kept cut");
                    assert!(
                        held.contains(&enrolment) && after.is_valid(enrolment),
                        "seed {seed}: a truncated peer loses an enrolment made again"
                    );
                    totals.bound_truncated += 1;
                }
            }
            let from = chain.iter().position(|&c| c == base).unwrap();
            assert_eq!(truncated.chain(), chain[from..], "seed {seed}: the chain");
            for &later in &chain[from + 1..] {
                let (kept, cut_down) = (
                    heard_votes(&full_cuts, later),
                    heard_votes(&truncated, later),
                );
                assert_eq!(kept, cut_down, "seed {seed}: votes through an out slot");
                totals.heard_votes_truncated += cut_down;
            }
            let trimmed = truncated.skeleton();
            for &id in &held {
                let event = log.event(id).unwrap();
                if event.kind() != kind::STORAGE || id == base {
                    continue;
                }
                assert_eq!(full.status(id), trimmed.status(id), "seed {seed}: {id:?}");
                let request = full
                    .body_of(id)
                    .is_some_and(|b| b.storage_type().is_request());
                if request {
                    assert_eq!(
                        full.is_stable(id, None),
                        trimmed.is_stable(id, None),
                        "seed {seed}: stability of {id:?}"
                    );
                }
            }
            assert_eq!(
                full.administrators(),
                trimmed.administrators(),
                "seed {seed}"
            );
            // (vi) What is released is decided alike by a peer that kept
            // everything and one that truncated, each from what it holds:
            // the truncated one, the maximal requests of the past, whose
            // order it no longer reads.
            let held_requests = writer_requests(log, &held);
            for stream in &STREAMS {
                let kept = full_cuts
                    .released(all_requests.iter().map(|(id, b)| (*id, b)), stream)
                    .is_some();
                let cut_down = truncated
                    .released(held_requests.iter().map(|(id, b)| (*id, b)), stream)
                    .is_some();
                assert_eq!(kept, cut_down, "seed {seed}: stream {stream:?} released");
                totals.streams_compared += 1;
                totals.released += usize::from(kept);
            }
            totals.peers += 1;
            totals.compared += held.len();
        }
    }
}

/// The votes counted for `cut`'s out slots: by the pseudonyms its standing
/// entries name.
fn heard_votes(cuts: &PeerCuts<'_>, cut: EventId) -> usize {
    let body = cuts.body(cut).unwrap();
    let tally = cuts.tally(cut).unwrap();
    body.standing
        .iter()
        .filter(|x| x.pseudonym.is_some())
        .map(|x| tally.votes.get(&x.slot).map_or(0, Vec::len))
        .sum()
}

/// A cut's verdict as the model counts it.
fn cut_verdict_name(status: Status) -> String {
    match status {
        Status::Valid => "valid".to_string(),
        Status::Void { class, .. } => frasil_base::errors::Class::name(class).to_string(),
    }
}

#[test]
fn a_peer_that_truncated_agrees_with_one_that_kept_everything() {
    // Seeds 1 to `FRASIL_SKELETON_SEEDS`, 40 by default: fewer reach every
    // case below.
    let n: u64 = std::env::var("FRASIL_SKELETON_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    let mut totals = Totals::default();
    for seed in 1..=n {
        check_skeleton(seed, &mut totals);
    }
    eprintln!("skeleton model check, seeds 1 to {n}: {totals:#?}");
    // The model reaches the cases it is for.
    assert!(totals.cuts > 0, "{totals:?}");
    assert!(totals.effective > 0, "{totals:?}");
    assert!(totals.peers > 0, "{totals:?}");
    assert!(totals.events > totals.cuts);
    assert!(totals.higher_rank_void > 0, "{totals:?}");
    assert!(totals.apart_enrolments > 0, "{totals:?}");
    assert!(totals.late_at_peer > 0, "{totals:?}");
    assert!(totals.absent > 0, "{totals:?}");
    assert!(totals.rogue_cuts > 0, "{totals:?}");
    assert!(totals.detached > 0, "{totals:?}");
    assert!(totals.replica_checked > 0, "{totals:?}");
    assert!(totals.requests_freed > 0, "{totals:?}");
    assert!(totals.streams_compared > 0, "{totals:?}");
    assert!(totals.excused > 0, "{totals:?}");
    assert!(totals.bound_again > 0, "{totals:?}");
    assert!(totals.slotless_cuts > 0, "{totals:?}");
    assert!(totals.heard_entries > 0, "{totals:?}");
    assert!(totals.heard_votes > 0, "{totals:?}");
    assert!(totals.heard_votes_truncated > 0, "{totals:?}");
    assert!(totals.disowns > 0, "{totals:?}");
    assert!(totals.late_then_past > 0, "{totals:?}");
    assert!(totals.late_episodes > 0, "{totals:?}");
    assert!(totals.monotone_checked > 0, "{totals:?}");
    assert!(totals.bound_peer > 0, "{totals:?}");
    assert!(totals.bound_truncated > 0, "{totals:?}");
}

// ---------------------------------------------------------------------------
// Cuts that fail, and what a peer keeps.

/// The founder `F`, its pseudonym `P0` and its root; `F` grants `A`, whose
/// pseudonym `A1` enrols.
fn founded() -> builder::Space {
    builder::space_with_a()
}

fn cut_from(b: &mut Builder, by: &Signer, epoch: u64, slots: Vec<SlotEntry>) -> EventId {
    let heads = b.heads();
    b.storage(
        by,
        StorageBody::Cut(Cut {
            twin: builder::example(&format!("cut twin {epoch} {}", slots.len())),
            salt: builder::example("cut salt"),
            record: [5; 64],
            epoch,
            standing: standing_of(&slots),
            slots,
        }),
        &heads,
    )
}

#[test]
fn a_cut_unnamed_bad_or_of_the_wrong_epoch() {
    let builder::Space { mut b, p0, a1, .. } = founded();
    let f = builder::signer("F");
    let void = |class| Status::Void { class, by: None };
    let all: BTreeSet<EventId> = b.log.canonical().into_iter().collect();
    let (epoch, slots) = PeerCuts::new(&b.log, None).slots_for(&all);
    assert_eq!(epoch, 1);
    assert_eq!(slots.len(), 2);

    // A cut with a slot left out: Unnamed until a checkpoint names it, then
    // BadCut.
    let bad = cut_from(&mut b, &p0, 1, slots[..1].to_vec());
    assert_eq!(
        PeerCuts::new(&b.log, None).validity(bad),
        void(PeersClass::Unnamed)
    );
    let heads = b.heads();
    b.checkpoint(&f, bad, &heads);
    assert_eq!(
        PeerCuts::new(&b.log, None).validity(bad),
        void(PeersClass::BadCut)
    );

    // A good one after it: valid, but not in effect while neither P0 nor A1
    // voted.
    let cut = cut_from(&mut b, &p0, 1, slots.clone());
    let heads = b.heads();
    let checkpoint = b.checkpoint(&f, cut, &heads);
    let cuts = PeerCuts::new(&b.log, None);
    assert_eq!(cuts.validity(cut), Status::Valid);
    assert!(!cuts.in_effect(cut));
    assert_eq!(cuts.awaiting(cut).len(), 2);
    assert!(cuts.chain().is_empty());

    // A cut of epoch 2 made before the good one took effect: CutPending.
    let early = cut_from(&mut b, &p0, 2, slots.clone());
    let heads = b.heads();
    b.checkpoint(&f, early, &heads);
    assert_eq!(
        PeerCuts::new(&b.log, None).validity(early),
        void(PeersClass::CutPending)
    );

    // Both vote: the good cut takes effect, and the skeleton starts from it.
    let heads = b.heads();
    let vote0 = b.storage(&p0, StorageBody::Ack, &heads);
    let cuts = PeerCuts::new(&b.log, None);
    assert!(cuts.is_vote(b.log.event(vote0).unwrap(), cut));
    assert_eq!(cuts.awaiting(cut).len(), 1);
    let heads = b.heads();
    b.storage(&a1, StorageBody::Ack, &heads);
    let cuts = PeerCuts::new(&b.log, None);
    assert!(cuts.in_effect(cut));
    assert_eq!(cuts.chain(), vec![cut]);
    let skeleton = cuts.skeleton();
    assert_eq!(skeleton.root(), Some(cut));
    assert_eq!(skeleton.cut(), Some(cut));
    assert_eq!(skeleton.status(vote0), Some(Status::Valid));
    assert_eq!(skeleton.status(early), Some(void(PeersClass::CutPending)));
    // The world holds only the cut and what follows its checkpoint.
    assert!(!skeleton.view().contains(&b.space));
    assert!(!skeleton.view().contains(&bad));
    assert!(skeleton.view().contains(&checkpoint));
    assert_eq!(skeleton.administrators(), cuts.skeleton().administrators());
    assert_eq!(skeleton.administrators().len(), 2);

    // What the peer keeps when it truncates under the checkpoint: the
    // genesis and the cut whole, the earlier checkpoint's envelope, if the
    // checkpoint's cuts reach it, and nothing past the checkpoint deleted.
    let plan = cuts
        .truncation_plan(cut, |_, _| false)
        .expect("envelopes held");
    assert_eq!(cuts.checkpoint_of(cut), Some(checkpoint));
    assert!(plan.whole.contains(&b.space) && plan.whole.contains(&cut));
    assert!(!plan.delete.contains(&checkpoint) && !plan.delete.contains(&vote0));
    assert!(plan.delete.contains(&bad));
    let genesis = b.log.genesis().clone();
    let always = always_kept(&b.log, cut);
    assert!(always.contains(&b.space) && always.contains(&cut));
    assert_eq!(
        keep(&genesis, &always, &BTreeSet::new(), |_, _| false),
        Keep::Whole
    );
    // The roots and enrolments the cut names are kept whole, so that the
    // world after it reads its pseudonyms' keys.
    for entry in &slots {
        let enrolment = entry.pseudonym.expect("both slots are enrolled");
        assert!(plan.whole.contains(&enrolment) && !plan.delete.contains(&enrolment));
    }
}

/// peers.md, "Skeleton cuts", step 2 takes the author's key from any root
/// or enrolment the peer holds, whatever its slot's state: a removed
/// administrator's cut verifies, is stored, and is `NotAnAdministrator` at
/// step 5.
#[test]
fn a_removed_administrators_cut_is_not_an_administrator() {
    let builder::Space {
        mut b,
        p0,
        a1,
        c_a,
        change,
        ..
    } = founded();
    let f = builder::signer("F");
    let heads = b.heads();
    let lower = b.storage(
        &p0,
        StorageBody::Change {
            twin: builder::example("c(F removes A)"),
            salt: builder::example("salt of F removes A"),
            effect: ChangeEffect::Lower(SlotId::new(c_a, 0, change)),
        },
        &heads,
    );
    b.name(&f, lower, &[lower]);
    let all: BTreeSet<EventId> = b.log.canonical().into_iter().collect();
    let (epoch, slots) = PeerCuts::new(&b.log, None).slots_for(&all);
    assert_eq!(slots.len(), 1, "A's slot is out");
    let cut = cut_from(&mut b, &a1, epoch, slots);
    let heads = b.heads();
    b.checkpoint(&f, cut, &heads);
    assert_eq!(
        PeerCuts::new(&b.log, None).validity(cut),
        Status::Void {
            class: ErrorClass::NotAnAdministrator.into(),
            by: None
        }
    );
}

/// A cut by a pseudonym enrolled in no slot of its past's skeleton is
/// `NotAnAdministrator` (peers.md, 3.21, step 4), before any key is sought;
/// the skeleton read from the root refuses the stranger's event as any
/// skeleton event of an unknown author (section 3.11).
#[test]
fn a_cut_by_a_pseudonym_the_peer_does_not_hold_is_not_an_administrator() {
    let builder::Space { mut b, p0, .. } = founded();
    let all: BTreeSet<EventId> = b.log.canonical().into_iter().collect();
    let (_, slots) = PeerCuts::new(&b.log, None).slots_for(&all);
    let stranger = builder::pseudonym("stranger");
    let heads = b.heads();
    let cut = b.storage(
        &stranger,
        StorageBody::Cut(Cut {
            twin: [9; 32],
            salt: [8; 32],
            record: [7; 64],
            epoch: 1,
            standing: standing_of(&slots),
            slots,
        }),
        &heads,
    );
    let heads = b.heads();
    b.checkpoint(&builder::signer("F"), cut, &heads);
    let cuts = PeerCuts::new(&b.log, None);
    assert_eq!(
        cuts.validity(cut),
        Status::Void {
            class: ErrorClass::NotAnAdministrator.into(),
            by: None
        }
    );
    // The skeleton read from the root refuses it at once, as the peer's
    // store check does.
    assert_eq!(
        Skeleton::new(&b.log, None).status(cut),
        Some(Status::Void {
            class: PeersClass::NotAuthorized,
            by: None
        })
    );
    let _ = p0;
}

#[test]
fn the_vector_status_text_names_the_new_classes() {
    let history = History::of(&family("skeleton_cuts")["events"]);
    assert_eq!(
        status_text(
            Status::Void {
                class: PeersClass::BadCut,
                by: None
            },
            &history
        ),
        "BadCut"
    );
    assert_eq!(
        status_text(
            Status::Void {
                class: PeersClass::CutPending,
                by: None
            },
            &history
        ),
        "CutPending"
    );
}

// ---------------------------------------------------------------------------
// peers.json, `skeleton_cuts`: unordered cuts and the truncation wait.

/// A cut's verdict as `cut_verdicts` writes it: `cut` when valid.
fn cut_verdict(cuts: &PeerCuts<'_>, cut: EventId, history: &History) -> String {
    match cuts.validity(cut) {
        Status::Valid => "cut".to_string(),
        status => status_text(status, history),
    }
}

/// Whether a peer may truncate under `cut` as far as requests go (peers.md,
/// "Truncation", when; `skeleton_cuts.py may_truncate`): every erasure and
/// credentials request of the checkpoint's past is void in the skeleton
/// before the cut, over everything the peer holds, or stable there, a slot
/// of the cut also acknowledging through its pseudonym in the cut's world
/// (peers.md, "Skeleton cuts", requests of the cut's past). With no
/// timeline, carried out means stable. Only under a cut in effect.
fn truncation_wait_settled(cuts: &PeerCuts<'_>, cut: EventId) -> bool {
    if !cuts.chain().contains(&cut) {
        return false;
    }
    let checkpoint = cuts.checkpoint_of(cut).expect("a cut in effect is named");
    let before = cuts
        .skeleton_before(cut)
        .expect("a cut in effect the peer has not truncated under");
    let after = cuts.skeleton_after(cut).expect("a cut in effect");
    requests_settled(&before, checkpoint, |id| {
        stable_past(&before, &after, id, None)
    })
}

#[test]
fn a_cut_reaching_unordered_checkpoints_is_cut_pending_kept_or_truncated() {
    // P checkpoints (B) and A checkpoints concurrently (Y); B's cut takes
    // effect; P then checkpoints without fencing (X), its cuts reaching
    // both B and Y. X's cut is CutPending at a peer that kept everything and
    // at one that truncated under B's cut (peers.md, "Skeleton cuts",
    // epochs).
    let v = &family("skeleton_cuts")["unordered_cuts"];
    let history = History::of(&v["events"]);
    let full = PeerCuts::new(&history.log, None);
    for (name, verdict) in v["cut_verdicts"].as_object().expect("verdicts") {
        let cut = history.id(name);
        assert_eq!(cut_verdict(&full, cut, &history), text(verdict), "{name}");
    }
    let b_cut = history.id("P0: cut of P checkpoints (B)");
    let b = full.checkpoint_of(b_cut).expect("B names its cut");
    assert_eq!(full.chain(), vec![b_cut]);
    let kept = full.skeleton();
    assert_eq!(verdicts(&kept, &history), v["kept"]["verdicts"]);

    // A peer that truncated under B's cut.
    assert_eq!(full.checkpoint_of(b_cut), Some(b));
    let plan = full
        .truncation_plan(b_cut, |_, _| false)
        .expect("envelopes held");
    let held: BTreeSet<EventId> = history
        .all()
        .into_iter()
        .filter(|id| !plan.delete.contains(id))
        .collect();
    let mut names: Vec<&str> = held.iter().map(|&id| history.name(id)).collect();
    names.sort_unstable();
    let expected: Vec<&str> = v["truncated"]["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(names, expected);
    let truncated = PeerCuts::truncated(&history.log, &history.log, held, b_cut);
    assert_eq!(truncated.chain(), vec![b_cut]);
    let x_cut = history.id("P0: cut of P checkpoints, unfenced (X)");
    assert_eq!(
        truncated.validity(x_cut),
        Status::Void {
            class: PeersClass::CutPending,
            by: None
        }
    );
    assert_eq!(
        verdicts(&truncated.skeleton(), &history),
        v["truncated"]["verdicts"]
    );
}

#[test]
fn the_truncation_wait_vector_and_its_empty_pseudonym() {
    // P and A administer, A enrolled; P grants B administer, and B has not
    // enrolled. P0 asks for erasure, P checkpoints, and P0 and A1
    // acknowledge after it: the cut takes effect, B's slot, with no
    // pseudonym, not voting. B then enrols and acknowledges.
    let v = &family("skeleton_cuts")["truncation_wait"];
    let history = History::of(&v["events"]);
    let checkpoint = history.id("P checkpoints");
    let cut = history.id("P0: cut of P checkpoints");
    let states = [
        ("before B enrols", history.view_without(&["B1 enrols"])),
        ("after B acknowledges", history.all()),
    ];
    for (state, view) in &states {
        let expected = &v["may_truncate"][*state];
        let cuts = PeerCuts::new(&history.log, Some(view));
        let chain: Vec<&str> = cuts.chain().iter().map(|&id| history.name(id)).collect();
        let in_effect: Vec<&str> = expected["in_effect"]
            .as_array()
            .unwrap()
            .iter()
            .map(text)
            .collect();
        assert_eq!(chain, in_effect, "{state}");
        assert_eq!(cuts.checkpoint_of(cut), Some(checkpoint), "{state}");
        // The erasure, in the checkpoint's past, is judged in the skeleton
        // before the cut, over everything the peer holds.
        let may = truncation_wait_settled(&cuts, cut);
        assert_eq!(Json::from(may), expected["may_truncate"], "{state}");
    }

    // The record's slot entries: B's names no pseudonym, as the cut's
    // entry for B's slot does; the cut passes the record check.
    let body = read_cut(history.log.event(cut).expect("the cut")).expect("a cut");
    let mut record = Vec::new();
    for (person, slot) in v["slots"].as_object().expect("slots") {
        let id = frasil_peers::body::SlotId::new(
            common::array::<32>(&slot[0]),
            u8::try_from(slot[1].as_u64().unwrap()).unwrap(),
            history.id(text(&slot[2])),
        );
        let pseudonym = hex(&slot[3]);
        let pseudonym = (!pseudonym.is_empty())
            .then(|| frasil_crypto::device::DeviceId(pseudonym.try_into().expect("32 bytes")));
        let entry = body
            .slots
            .iter()
            .find(|entry| entry.slot == id)
            .unwrap_or_else(|| panic!("{person}'s slot is in the cut"));
        assert_eq!(
            entry_pseudonym(&history.log, entry),
            pseudonym,
            "{person}'s pseudonym"
        );
        record.push(Some(RecordSlot {
            slot: id,
            pseudonym,
        }));
    }
    assert_eq!(record.len(), 3);
    assert!(record.iter().flatten().any(|slot| slot.pseudonym.is_none()));
    assert_eq!(check_against_record(&history.log, &body, &record), Ok(()));
}

#[test]
fn truncation_waits_for_an_erasure_judged_in_the_skeleton_before_the_cut() {
    // peers.md, "Truncation", when: an erasure in the checkpoint's past that
    // is neither carried out nor void holds truncation back. The peer
    // judges it in the skeleton before the cut, over everything it holds,
    // where it was judged before the cut took effect; the world after the
    // cut does not hold it. F grants B administer, dormant, and B does not
    // enrol yet, so the cut does not wait for its slot, which has no
    // pseudonym, and the erasure waits for it.
    let builder::Space { mut b, p0, a1, .. } = founded();
    let f = builder::signer("F");
    let (c_b, salt_b) = (
        builder::example("c(F grants B)"),
        builder::example("salt of F grants B"),
    );
    let (map, keys) = builder::grant_ranked(&builder::example("token of B"), 200);
    let heads = b.heads();
    let change = b.storage(
        &p0,
        StorageBody::Change {
            twin: c_b,
            salt: salt_b,
            effect: ChangeEffect::Grants(vec![map]),
        },
        &heads,
    );
    b.name(&f, change, &[change]);
    let heads = b.heads();
    let erase = b.storage(&p0, StorageBody::Erase, &heads);
    let all: BTreeSet<EventId> = b.log.canonical().into_iter().collect();
    let (epoch, slots) = PeerCuts::new(&b.log, None).slots_for(&all);
    assert_eq!(slots.len(), 3);
    assert!(slots.iter().any(|e| e.rank == 200 && e.pseudonym.is_none()));
    let dormant = slots
        .iter()
        .find(|e| e.pseudonym.is_none())
        .map(|e| e.slot)
        .unwrap();
    let mut standing = standing_of(&slots);
    for entry in &mut standing {
        if entry.slot == dormant {
            entry.dormant = 1;
        }
    }
    let heads = b.heads();
    let cut = b.storage(
        &p0,
        StorageBody::Cut(Cut {
            twin: builder::example("cut twin, B dormant"),
            salt: builder::example("cut salt"),
            record: [5; 64],
            epoch,
            slots,
            standing,
        }),
        &heads,
    );
    let heads = b.heads();
    let checkpoint = b.checkpoint(&f, cut, &heads);
    let heads = b.heads();
    b.storage(&p0, StorageBody::Ack, &heads);
    let heads = b.heads();
    b.storage(&a1, StorageBody::Ack, &heads);
    let cuts = PeerCuts::new(&b.log, None);
    assert_eq!(cuts.chain(), vec![cut]);

    // The skeleton before the cut: the erasure is valid there and waits for
    // B's slot, which acknowledged nothing.
    let before = cuts.skeleton_before(cut).expect("the cut is in effect");
    assert!(before.view().contains(&erase));
    assert!(before.is_valid(erase));
    assert!(!before.is_stable(erase, None));
    assert!(!requests_settled(&before, checkpoint, |id| before.is_stable(id, None)));
    // Carried out (or judged void) at the peer, it no longer waits.
    assert!(requests_settled(&before, checkpoint, |id| id == erase));

    // The world after the cut does not hold the erasure, so it alone would
    // never wait.
    let after = cuts.skeleton();
    assert!(!after.view().contains(&erase));
    assert!(requests_settled(&after, checkpoint, |_| false));

    // B's pseudonym enrols and acknowledges after the checkpoint: the
    // erasure is stable in the skeleton before the cut, which reads every
    // event the peer holds.
    let b1 = builder::pseudonym("B1");
    let heads = b.heads();
    b.enrol(&b1, SlotId::new(c_b, 0, change), &keys, &heads);
    let heads = b.heads();
    b.storage(&b1, StorageBody::Ack, &heads);
    let cuts = PeerCuts::new(&b.log, None);
    assert_eq!(cuts.chain(), vec![cut]);
    let before = cuts.skeleton_before(cut).expect("the cut is in effect");
    assert!(before.is_stable(erase, None));
    assert!(truncation_wait_settled(&cuts, cut));
    // A cut the peer kept when it truncated has no skeleton before it.
    let truncated =
        PeerCuts::truncated(&b.log, &b.log, b.log.canonical().into_iter().collect(), cut);
    assert!(truncated.skeleton_before(cut).is_none());
}

// ---------------------------------------------------------------------------
// peers.json, `skeleton_cuts`: a late enrolment, and the bindings after a
// cut.

/// The replica's skeleton in the world of `cut`, whose checkpoint is in
/// effect at it (roster.md, 3.15.5 The world after a checkpoint): the cut
/// and the events that follow its checkpoint, among `held`.
fn replica_world<'a>(
    log: &'a frasil_events::Log,
    cut: EventId,
    held: &BTreeSet<EventId>,
) -> Skeleton<'a> {
    let cuts = PeerCuts::new(log, Some(held));
    let members: BTreeSet<EventId> = held
        .iter()
        .copied()
        .filter(|&id| cuts.follows_cut(id, cut) == Ok(true))
        .collect();
    let body = read_cut(log.event(cut).expect("the cut")).expect("a cut");
    Skeleton::after_cut(log, cut, &body, members, BTreeMap::new())
}

/// The roster facts of a replica in the world of `cut`: the roster events
/// it opened (`roster`), and each slot of the cut mapped as the checkpoint
/// record's `slot` entries map it, to the device of the grant that made it
/// and to the pseudonym the cut enrols in it (roster.md, 3.15.5, Skeleton).
fn world_facts(
    prefix: &str,
    history: &History,
    cut: EventId,
    roster: &[(&str, frasil_peers::twins::AdministerChanges)],
    makers: &[(&str, &str)],
) -> common::Facts {
    let mut facts = common::Facts::new(prefix, history, &["P", "A", "B"], roster);
    let body = read_cut(history.log.event(cut).unwrap()).unwrap();
    for entry in &body.slots {
        let maker = history.name(entry.slot.maker);
        let device = makers
            .iter()
            .find(|(m, _)| *m == maker)
            .map(|(_, d)| common::device(prefix, d))
            .unwrap_or_else(|| panic!("a device for {maker}"));
        facts
            .cut_slots
            .insert(entry.slot, (device, entry_pseudonym(&history.log, entry)));
    }
    facts
}

#[test]
fn a_late_enrolment_kept_truncated_and_enrolled_again() {
    let v = &family("skeleton_cuts")["late_enrolment"];
    let prefix = text(&v["history_prefix"]);
    let history = History::of(&v["events"]);
    let cut = history.id("P0: cut of P checkpoints");
    let checkpoint = history.id("P checkpoints");
    let late = history.id("B1 enrols, concurrently with the checkpoint");
    let again = history.id("B2 enrols the same slot again, after the checkpoint");

    // A peer that kept everything: the late enrolment and B1's
    // acknowledgement are stored, `Late`, and B2 enrols B's slot again.
    let full = PeerCuts::new(&history.log, None);
    assert_eq!(full.chain(), vec![cut]);
    assert_eq!(full.checkpoint_of(cut), Some(checkpoint));
    let kept = full.skeleton();
    assert_eq!(verdicts(&kept, &history), v["peer"]["kept"]["verdicts"]);
    let late_events: Vec<&str> = full.late().iter().map(|&id| history.name(id)).collect();
    assert_eq!(
        late_events,
        [
            "B1 enrols, concurrently with the checkpoint",
            "B1 acknowledges, on its late enrolment"
        ]
    );
    let entry = read_cut(history.log.event(cut).unwrap())
        .unwrap()
        .slots
        .into_iter()
        .find(|entry| entry.slot.maker == history.id("P0: twin of P grants B administer"))
        .expect("B's slot is in the cut");
    assert_eq!(entry.pseudonym, None);
    let b1 = *history.log.event(late).unwrap().author();
    let b2 = *history.log.event(again).unwrap().author();
    assert_eq!(kept.slot_of(&b2), Some(entry.slot));
    assert_eq!(kept.merged()[&entry.slot].enrolled, Some(b2));
    // B1 is enrolled in no slot, and may still present its credential
    // under the `ed` of its enrolment.
    assert_eq!(kept.slot_of(&b1), None);
    assert_eq!(
        kept.pseudonym_keys(&b1).map(|keys| keys.ed),
        Some(*history.log.event(late).unwrap().ed())
    );
    assert!(kept.late_pseudonyms().any(|p| *p == b1));

    // A peer that truncated under the cut agrees.
    let plan = full
        .truncation_plan(cut, |_, _| false)
        .expect("envelopes held");
    let held: BTreeSet<EventId> = history
        .all()
        .into_iter()
        .filter(|id| !plan.delete.contains(id))
        .collect();
    let mut names: Vec<&str> = held.iter().map(|&id| history.name(id)).collect();
    names.sort_unstable();
    let expected: Vec<&str> = v["peer"]["truncated"]["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(names, expected);
    let truncated = PeerCuts::truncated(&history.log, &history.log, held, cut);
    assert_eq!(truncated.chain(), vec![cut]);
    assert_eq!(
        verdicts(&truncated.skeleton(), &history),
        v["peer"]["truncated"]["verdicts"]
    );
    assert_eq!(truncated.late(), full.late());

    // The cut waits for B's slot, which its standing entries name: it is in
    // effect once B2 enrols the slot again after the checkpoint, the
    // enrolment its vote; the erasure of the checkpoint's past waits for
    // B's slot until then.
    let states = [
        (
            "before B enrols again",
            history.view_without(&[history.name(again)]),
        ),
        ("after B enrols again", history.all()),
    ];
    for (state, view) in &states {
        let cuts = PeerCuts::new(&history.log, Some(view));
        let enrolled_again = view.contains(&again);
        let in_effect = if enrolled_again { vec![cut] } else { vec![] };
        assert_eq!(cuts.chain(), in_effect, "{state}");
        let awaiting = if enrolled_again {
            vec![]
        } else {
            vec![entry.slot]
        };
        assert_eq!(cuts.awaiting(cut), awaiting, "{state}");
        let may = truncation_wait_settled(&cuts, cut);
        assert_eq!(
            Json::from(may),
            v["peer"]["may_truncate"][*state],
            "{state}"
        );
    }

    // Replicas: in the checkpoint's world, A1 binds A through the record,
    // B2 binds B through its binding, sealed under the checkpoint's
    // twin_secret, and B1, late, binds nothing; at a replica that kept every
    // roster event, and at one that forgot all but the checkpoint.
    let world = replica_world(&history.log, cut, &history.all());
    let makers = [
        ("P0: root", "P"),
        ("P0: twin of P grants A administer", "A"),
        ("P0: twin of P grants B administer", "B"),
    ];
    let everything = [
        ("P creates the space", common::grants(prefix, &["P"])),
        ("P grants A administer", common::grants(prefix, &["A"])),
        ("P grants B administer", common::grants(prefix, &["B"])),
        ("P checkpoints", Default::default()),
    ];
    let forgot = [("P checkpoints", Default::default())];
    for (name, roster) in [("kept", &everything[..]), ("forgot", &forgot[..])] {
        let facts = world_facts(prefix, &history, cut, roster, &makers);
        let checks = TwinChecks::new(&world, &facts);
        let bindings: serde_json::Map<String, Json> = ["A1", "B1", "B2"]
            .into_iter()
            .map(|p| {
                let bound = match checks.bound(&common::pseudonym_id(prefix, p)) {
                    Bound::Device(device) => ["P", "A", "B"]
                        .into_iter()
                        .find(|d| common::device(prefix, d) == device)
                        .map_or(Json::Null, Json::from),
                    Bound::Foreign | Bound::Unbound => Json::Null,
                };
                (p.to_string(), bound)
            })
            .collect();
        assert_eq!(Json::Object(bindings), v["bindings"], "{name}");
        // B2's binding is sealed under the checkpoint's twin_secret, which
        // its own envelope names.
        let secret = checks
            .binding_secret(history.log.event(again).unwrap(), entry.slot)
            .expect("the checkpoint's secret");
        assert_eq!(
            *secret,
            *checks.commitment(checkpoint).expect("opened").0,
            "{name}"
        );
    }
    assert_eq!(
        text(&v["binding_secret"]["B2"]),
        "the checkpoint's twin_secret"
    );

    // Under the twin_secret of the roster event that granted B's slot,
    // B2's binding does not open; B1's, sealed before the checkpoint, does.
    let before = Skeleton::new(&history.log, None);
    let facts = world_facts(prefix, &history, cut, &everything, &makers);
    let checks = TwinChecks::new(&before, &facts);
    let grant_b = checks
        .commitment(history.id("P grants B administer"))
        .expect("opened")
        .0;
    let opens = |id: EventId| {
        let event = history.log.event(id).unwrap();
        let Some(StorageBody::Enrol { slot, binding, .. }) = before.body_of(id) else {
            panic!("an enrolment");
        };
        frasil_peers::derive::open_binding(
            binding,
            &grant_b,
            &history.log.id(),
            slot.reference,
            event.author(),
        )
        .is_ok()
    };
    assert!(opens(late));
    assert!(!opens(again));
    assert_eq!(
        *checks
            .binding_secret(history.log.event(late).unwrap(), entry.slot)
            .unwrap(),
        *grant_b
    );
}

#[test]
fn an_enrolment_after_the_cut_binds_under_the_checkpoints_secret() {
    // `truncation_wait`: B, granted before the checkpoint and enrolled
    // after it, seals B1's binding under the checkpoint's twin_secret, as
    // its cuts name the checkpoint and the cut lists B's slot. A replica in
    // the checkpoint's world binds B1 to B, whether it kept the roster event
    // that granted B's slot or not.
    let v = &family("skeleton_cuts")["truncation_wait"];
    let prefix = text(&v["history_prefix"]);
    let history = History::of(&v["events"]);
    let cut = history.id("P0: cut of P checkpoints");
    let world = replica_world(&history.log, cut, &history.all());
    let makers = [
        ("P0: root", "P"),
        ("P0: twin of P grants A administer", "A"),
        ("P0: twin of P grants B administer", "B"),
    ];
    let everything = [
        ("P creates the space", common::grants(prefix, &["P"])),
        ("P grants A administer", common::grants(prefix, &["A"])),
        ("P grants B administer", common::grants(prefix, &["B"])),
        ("P checkpoints", Default::default()),
    ];
    let forgot = [("P checkpoints", Default::default())];
    for roster in [&everything[..], &forgot[..]] {
        let facts = world_facts(prefix, &history, cut, roster, &makers);
        let checks = TwinChecks::new(&world, &facts);
        for (pseudonym, device) in [("P0", "P"), ("A1", "A"), ("B1", "B")] {
            assert_eq!(
                checks.bound(&common::pseudonym_id(prefix, pseudonym)),
                Bound::Device(common::device(prefix, device)),
                "{pseudonym}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// peers.json, `skeleton_cuts`: standing, concurrent requests, release order,
// detached and peerless histories.

/// The names of a set of events, sorted.
fn names_of(history: &History, ids: &BTreeSet<EventId>) -> Vec<String> {
    let mut out: Vec<String> = ids.iter().map(|&id| history.name(id).to_string()).collect();
    out.sort_unstable();
    out
}

/// A list of names as the vectors write it, sorted.
fn json_names(value: &Json) -> Vec<String> {
    let mut out: Vec<String> = value
        .as_array()
        .expect("a list of names")
        .iter()
        .map(|name| text(name).to_string())
        .collect();
    out.sort_unstable();
    out
}

#[test]
fn an_absent_administrator_removed_by_a_senior_a_junior_or_nobody() {
    // peers.md, "Skeleton cuts", waited and excused slots: P, A, B and C
    // administer at one rank, B enrols and never returns. The cut waits for
    // every standing slot with `dormant` 0; A, senior to B, excuses it by
    // removing it after the checkpoint, and C, junior to it, does not.
    let cases = &family("skeleton_cuts")["absent_administrator"];
    for (case, v) in cases.as_object().expect("cases") {
        let history = History::of(&v["events"]);
        let cut = history.id("P0: cut of P checkpoints");
        let checkpoint = history.id("P checkpoints");
        let body = read_cut(history.log.event(cut).unwrap()).unwrap();
        // The standing entries, as the vectors write them: `[c, index,
        // maker, order, dormant]`.
        let standing: Vec<Json> = body
            .standing
            .iter()
            .map(|x| {
                serde_json::json!([
                    frasil_testkit::hex::encode(x.slot.reference.commitment),
                    x.slot.reference.index,
                    history.name(x.slot.maker),
                    x.order,
                    x.dormant,
                ])
            })
            .collect();
        assert_eq!(Json::from(standing), v["standing"], "{case}");
        assert!(
            standing_consistent(&body, |_| false, |_, _| false),
            "{case}"
        );
        // Replicas check the entries against the record: these, and no
        // others.
        assert_eq!(check_standing(&body, &body.standing), Ok(()), "{case}");
        let mut other = body.standing.clone();
        other[0].order = other[1].order;
        assert_eq!(
            check_standing(&body, &other),
            Err(PeersClass::BadTwin),
            "{case}"
        );
        let full = PeerCuts::new(&history.log, None);
        assert_eq!(full.checkpoint_of(cut), Some(checkpoint), "{case}");
        assert_eq!(full.validity(cut), Status::Valid, "{case}");
        let in_effect = full.chain() == vec![cut];
        assert_eq!(
            Json::from(in_effect),
            v["cut_in_effect_at_the_peer"],
            "{case}"
        );
        // A replica holding the same events decides alike (peers.md,
        // "Skeleton cuts", what the peer cannot see).
        assert_eq!(
            v["cut_in_effect_at_the_peer"], v["checkpoint_in_effect_at_a_replica"],
            "{case}"
        );
        // B's slot: excused by the senior's removal alone; waited for
        // otherwise.
        let b = body
            .standing
            .iter()
            .find(|x| history.name(x.slot.maker) == "P0: twin of P grants B administer")
            .expect("B's standing entry");
        let tally = full.tally(cut).expect("a named cut");
        let excuses: Vec<&str> = tally.excuses[&b.slot]
            .iter()
            .map(|&id| history.name(id))
            .collect();
        match case.as_str() {
            "senior" => {
                assert_eq!(excuses, ["A1: twin of A removes B, senior to it"]);
                assert!(tally.awaiting().is_empty());
                // Votes count whatever their past holds: before the others
                // acknowledge the removal, the cut is in effect already, and
                // the peer reports nothing to anyone.
                let before = history.view_without(&[
                    "P0 acknowledges the removal",
                    "A1 acknowledges the removal",
                    "C1 acknowledges the removal",
                ]);
                let cuts = PeerCuts::new(&history.log, Some(&before));
                assert_eq!(cuts.chain(), vec![cut]);
                for name in ["P0: root", "C1 enrols", "A1 enrols"] {
                    let pseudonym = *history.log.event(history.id(name)).unwrap().author();
                    assert!(cuts.awaiting_votes_of(&pseudonym).is_empty(), "{name}");
                }
            }
            _ => {
                assert!(excuses.is_empty(), "{case}");
                assert_eq!(tally.awaiting(), vec![b.slot], "{case}");
                // The peer reports the checkpoint to nobody but B's
                // pseudonym, which never returns.
                let b1 = *history.log.event(history.id("B1 enrols")).unwrap().author();
                assert_eq!(full.awaiting_votes_of(&b1), vec![checkpoint], "{case}");
                let a1 = *history.log.event(history.id("A1 enrols")).unwrap().author();
                assert!(full.awaiting_votes_of(&a1).is_empty(), "{case}");
            }
        }
    }
}

#[test]
fn an_erasure_concurrent_with_a_cut_waits_then_is_late() {
    // peers.md, "Erasure", steps 0 and 1: A1 asks for erasure apart while P
    // checkpoints without it. While the cut can still take effect the
    // erasure waits; once it does, the erasure is late, and A1's erasure
    // signed again after the checkpoint is free.
    let v = &family("skeleton_cuts")["concurrent_request"];
    let history = History::of(&v["events"]);
    let erase = history.id("A1 asks for erasure, apart");
    let again = history.id("A1 asks for erasure again, after the checkpoint");
    let cut = history.id("P0: cut of P checkpoints, without the erasure");
    let views = [
        (
            "the peer holds the erasure and the cut",
            history.view_without(&[
                "P votes",
                "P0 votes",
                "A votes",
                "A1 votes",
                history.name(again),
            ]),
        ),
        (
            "the cut in effect",
            history.view_without(&[history.name(again)]),
        ),
        ("signed again", history.all()),
    ];
    let state = |s: RequestState| match s {
        RequestState::Late => "Late",
        RequestState::Wait => "Wait",
        RequestState::Free => "Free",
    };
    for (name, view) in &views {
        let cuts = PeerCuts::new(&history.log, Some(view));
        let mut got = serde_json::Map::new();
        got.insert(
            "erasure".into(),
            Json::from(state(cuts.request_state(erase))),
        );
        if view.contains(&again) {
            got.insert("again".into(), Json::from(state(cuts.request_state(again))));
        }
        assert_eq!(Json::Object(got), v["states"][*name], "{name}");
        // The cut can still take effect exactly while the erasure waits.
        assert_eq!(
            cuts.can_take_effect(cut),
            cuts.request_state(erase) == RequestState::Wait,
            "{name}"
        );
        // The erasure procedure waits, stable or not, past its timeout too.
        let undecided = cuts.request_state(erase) == RequestState::Wait;
        let outcome = frasil_peers::decisions::erasure(
            cuts.skeleton().is_valid(erase) || undecided,
            undecided,
            true,
            &common::reading(0),
            &common::reading(u64::MAX / 2),
            1,
        );
        let expected = match *name {
            "the peer holds the erasure and the cut" => frasil_peers::decisions::Execution::Wait,
            _ => frasil_peers::decisions::Execution::Void,
        };
        assert_eq!(outcome, expected, "{name}");
    }
    let full = PeerCuts::new(&history.log, None);
    assert_eq!(full.chain(), vec![cut]);
    assert_eq!(verdicts(&full.skeleton(), &history), v["peer_verdicts"]);
}

#[test]
fn a_truncated_peer_keeps_the_maximal_release_and_finds_it_released() {
    // peers.md, "Truncation" and "Release and restore": P restores stream
    // x, anchors, then releases it. A peer that truncated keeps the release
    // alone and finds x released, as one that kept everything and a replica
    // that forgot do; one that kept the restore beside it, without the
    // anchor between them, would not.
    let v = &family("skeleton_cuts")["release_order"];
    let history = History::of(&v["events"]);
    let cut = history.id("P0: cut of P checkpoints");
    let checkpoint = history.id("P checkpoints");
    let release = history.id("P releases x, after its restore");
    let restore = history.id("P restores x");
    let Some(StorageBody::Release { stream }) =
        Skeleton::new(&history.log, None).body_of(release).cloned()
    else {
        panic!("a release");
    };
    let requests = |held: &BTreeSet<EventId>| -> Vec<(EventId, StorageBody)> {
        held.iter()
            .filter_map(|&id| {
                let body = StorageBody::read(history.log.event(id)?.unverified_body()).ok()?;
                body.storage_type()
                    .is_writer_request()
                    .then_some((id, body))
            })
            .collect()
    };
    let released = |cuts: &PeerCuts<'_>, held: &BTreeSet<EventId>| {
        let requests = requests(held);
        cuts.released(requests.iter().map(|(id, b)| (*id, b)), &stream)
            .is_some()
    };
    let full = PeerCuts::new(&history.log, None);
    assert_eq!(full.chain(), vec![cut]);
    let all = history.all();
    // What a peer keeps of the past: the release, the maximal request.
    assert_eq!(full.kept_requests(checkpoint), BTreeSet::from([release]));
    let plan = full
        .truncation_plan(cut, |_, _| false)
        .expect("envelopes held");
    assert_eq!(plan.requests, BTreeSet::from([release]));
    assert!(plan.delete.contains(&restore));
    let held: BTreeSet<EventId> = all
        .iter()
        .copied()
        .filter(|id| !plan.delete.contains(id))
        .collect();
    assert_eq!(names_of(&history, &held), json_names(&v["truncated_holds"]));
    let truncated = PeerCuts::truncated(&history.log, &history.log, held.clone(), cut);
    // A replica that forgot holds the checkpoint and what follows it, the
    // genesis, the cut and the maximal requests of the past.
    let mut forgot: BTreeSet<EventId> = all
        .iter()
        .copied()
        .filter(|&id| id == checkpoint || history.log.precedes(checkpoint, id))
        .collect();
    forgot.extend([history.log.id(), cut]);
    forgot.extend(full.kept_requests(checkpoint));
    let replica = PeerCuts::truncated(&history.log, &history.log, forgot.clone(), cut);
    // Every request kept, the anchor between them deleted.
    let mut both = held.clone();
    both.insert(restore);
    let every = PeerCuts::truncated(&history.log, &history.log, both.clone(), cut);
    let got = serde_json::json!({
        "kept everything": released(&full, &all),
        "truncated": released(&truncated, &held),
        "a replica that forgot": released(&replica, &forgot),
        "kept every request, ordered from what it holds": released(&every, &both),
    });
    assert_eq!(got, v["released"]);
}

#[test]
fn a_checkpoint_that_does_not_cite_its_cut_names_nothing() {
    // peers.md, "Skeleton cuts", step 3: a space event that names a cut
    // without citing it is no checkpoint of it. The cut stays `Unnamed`,
    // at a peer that kept everything and at one that holds less, and a
    // replica, which reads the same, finds the checkpoint `BadTwin`.
    let v = &family("skeleton_cuts")["detached"];
    let history = History::of(&v["events"]);
    let cut = history.id("P0: cut of P checkpoints, naming a cut it does not cite");
    let checkpoint = history.id("P checkpoints, naming a cut it does not cite");
    assert_eq!(
        frasil_peers::skeleton::named_twin(history.log.event(checkpoint).unwrap()),
        Some(cut)
    );
    for view in [
        history.all(),
        history.view_without(&["P anchors", "A anchors"]),
    ] {
        let cuts = PeerCuts::new(&history.log, Some(&view));
        assert_eq!(cuts.checkpoint_of(cut), None);
        assert_eq!(cut_verdict(&cuts, cut, &history), text(&v["cut"]));
        assert!(cuts.chain().is_empty());
        assert!(cuts.tally(cut).is_none());
    }
    assert_eq!(text(&v["checkpoint"]), "BadTwin");
}

#[test]
fn checkpoints_among_members_without_a_peer() {
    // peers.md, "Between members": members that never reach a peer
    // checkpoint three times, each cut in effect by the peer's rule over
    // what they hold; and a peer that holds one checkpoint and then catches
    // up on two made apart from it finds the same chain, truncates under the
    // last cut, and agrees with one that kept everything.
    let v = &family("skeleton_cuts")["peerless"];
    let never = &v["never"];
    let history = History::of(&never["events"]);
    let chain: Vec<String> = PeerCuts::new(&history.log, None)
        .chain()
        .into_iter()
        .map(|id| history.name(id).to_string())
        .collect();
    assert_eq!(Json::from(chain), never["chain"]);

    let apart = &v["apart"];
    let history = History::of(&apart["events"]);
    let names = |ids: Vec<EventId>| -> Json {
        Json::from(
            ids.into_iter()
                .map(|id| history.name(id).to_string())
                .collect::<Vec<_>>(),
        )
    };
    let at_peer = history.view_without(&["P0: cut of apart: P checkpoints (1)"]);
    assert_eq!(
        names(PeerCuts::new(&history.log, Some(&at_peer)).chain()),
        apart["chain_at_the_peer_before"]
    );
    let full = PeerCuts::new(&history.log, None);
    let chain = full.chain();
    assert_eq!(names(chain.clone()), apart["chain_once_it_catches_up"]);
    let last = *chain.last().unwrap();
    assert!(truncation_wait_settled(&full, last));
    let plan = full
        .truncation_plan(last, |_, _| false)
        .expect("envelopes held");
    let held: BTreeSet<EventId> = history
        .all()
        .into_iter()
        .filter(|id| !plan.delete.contains(id))
        .collect();
    assert_eq!(
        names_of(&history, &held),
        json_names(&apart["truncated_holds"])
    );
    let truncated = PeerCuts::truncated(&history.log, &history.log, held.clone(), last);
    assert_eq!(truncated.chain(), vec![last]);
    let (kept, trimmed) = (full.skeleton(), truncated.skeleton());
    for &id in &held {
        if id != last && history.log.event(id).unwrap().kind() == kind::STORAGE {
            assert_eq!(kept.status(id), trimmed.status(id), "{}", history.name(id));
        }
    }
    assert_eq!(kept.administrators(), trimmed.administrators());
}

#[test]
fn a_late_enrolment_is_stored_only_with_its_own_checks() {
    // peers.md, "Skeleton cuts", what a late enrolment opens: one is stored
    // only if its `seq` is 1, its author is no pseudonym the peer holds,
    // its keys hash to its `kc` and it verifies under them. F grants B,
    // dormant; apart from the others B1 enrols B's slot, X signs an
    // acknowledgement and then an enrolment, and Y enrols with keys that are
    // not its own. P checkpoints without them; P0 and A1 vote.
    let builder::Space { mut b, p0, a1, .. } = founded();
    let f = builder::signer("F");
    let c_b = builder::example("c(F grants B), late");
    let (map, keys) = builder::grant_ranked(&builder::example("token of B, late"), 200);
    let heads = b.heads();
    let change = b.storage(
        &p0,
        StorageBody::Change {
            twin: c_b,
            salt: builder::example("salt of F grants B, late"),
            effect: ChangeEffect::Grants(vec![map]),
        },
        &heads,
    );
    b.name(&f, change, &[change]);
    let slot = SlotId::new(c_b, 0, change);
    let before = b.heads();
    // Apart: the late enrolments.
    let b1 = builder::pseudonym("B1, late");
    let late = b.enrol(&b1, slot, &keys, &before);
    let x = builder::pseudonym("X, late");
    b.storage(&x, StorageBody::Ack, &before);
    let second = b.enrol(&x, slot, &keys, &before);
    let y = builder::pseudonym("Y, late");
    let StorageBody::Enrol {
        slot: s,
        slot_mldsa,
        authorization,
        binding,
        ..
    } = b.enrol_body(&y, slot, &keys)
    else {
        panic!("an enrolment");
    };
    let not_own = b.storage(
        &y,
        StorageBody::Enrol {
            slot: s,
            mldsa: builder::pseudonym("Z, late").mldsa_public().to_vec(),
            slot_mldsa,
            authorization,
            binding,
        },
        &before,
    );
    // The checkpoint, without them.
    let all: BTreeSet<EventId> = before
        .iter()
        .flat_map(|&h| b.log.past(h).into_iter().chain([h]))
        .collect();
    let (epoch, slots) = PeerCuts::new(&b.log, Some(&all)).slots_for(&all);
    let mut standing = standing_of(&slots);
    for entry in &mut standing {
        if entry.slot == slot {
            entry.dormant = 1;
        }
    }
    let cut = b.storage(
        &p0,
        StorageBody::Cut(Cut {
            twin: builder::example("cut twin, late enrolments"),
            salt: builder::example("cut salt"),
            record: [5; 64],
            epoch,
            slots,
            standing,
        }),
        &before,
    );
    let mut cited = before.clone();
    cited.push(cut);
    let checkpoint = b.checkpoint(&f, cut, &cited);
    b.storage(&p0, StorageBody::Ack, &[checkpoint]);
    b.storage(&a1, StorageBody::Ack, &[checkpoint]);
    let cuts = PeerCuts::new(&b.log, None);
    assert_eq!(cuts.chain(), vec![cut]);
    let world = cuts.skeleton();
    assert_eq!(
        world.status(late),
        Some(Status::Void {
            class: PeersClass::Late,
            by: None
        })
    );
    assert_eq!(
        world.status(second),
        Some(Status::Void {
            class: ErrorClass::BadSignature.into(),
            by: None
        })
    );
    assert_eq!(
        world.status(not_own),
        Some(Status::Void {
            class: ErrorClass::NotCommitted.into(),
            by: None
        })
    );
    assert_eq!(
        cuts.late_refused().into_keys().collect::<BTreeSet<_>>(),
        BTreeSet::from([second, not_own])
    );
    // Only B1 may present its credential: X and Y are held as nobody's.
    let late: Vec<_> = world.late_pseudonyms().copied().collect();
    assert_eq!(late, vec![*b1.device_id()]);
    for status in [world.status(second), world.status(not_own)] {
        let Some(Status::Void { class, .. }) = status else {
            panic!("refused");
        };
        assert!(frasil_peers::skeleton::refused_by_peer(class));
    }
    assert!(world.statuses().iter().any(|(id, _)| *id == not_own));
}

#[test]
fn a_release_late_under_one_cut_counts_for_nothing_under_the_next() {
    // peers.md, "Release and restore": A releases x apart while P
    // checkpoints (C1) without it; C1 takes effect and the release is late.
    // A then checkpoints (C2), whose past holds the release through A's
    // chain. It still counts for nothing: x is not released, at a peer that
    // kept everything and at one that truncated under C2, and it stays
    // Late.
    let v = &family("skeleton_cuts")["late_then_past"];
    let history = History::of(&v["events"]);
    let release = history.id("A releases x, apart");
    let c1 = history.id("P0: cut of C1: P checkpoints (1)");
    let c2 = history.id("A1: cut of A checkpoints (C2)");
    let checkpoint2 = history.id("A checkpoints (C2)");
    let Some(StorageBody::Release { stream }) =
        Skeleton::new(&history.log, None).body_of(release).cloned()
    else {
        panic!("a release");
    };
    let full = PeerCuts::new(&history.log, None);
    assert_eq!(full.chain(), vec![c1, c2]);
    assert!(history.log.precedes(release, checkpoint2));
    assert!(full.late_under_chain(release, &full.chain()));
    assert_eq!(full.request_state(release), RequestState::Late);
    // Under C1 alone, before C2, it is late too.
    let before = history.view_without(&["A1: cut of A checkpoints (C2)"]);
    let at_c1 = PeerCuts::new(&history.log, Some(&before));
    assert_eq!(at_c1.chain(), vec![c1]);
    assert_eq!(at_c1.request_state(release), RequestState::Late);
    // No truncation under C2 keeps it, though C2's past holds it.
    assert!(full.kept_requests(checkpoint2).is_empty());
    let plan = full
        .truncation_plan(c2, |_, _| false)
        .expect("envelopes held");
    assert!(plan.delete.contains(&release));
    let all = history.all();
    let held: BTreeSet<EventId> = all
        .iter()
        .copied()
        .filter(|id| !plan.delete.contains(id))
        .collect();
    assert_eq!(names_of(&history, &held), json_names(&v["truncated_holds"]));
    let truncated = PeerCuts::truncated(&history.log, &history.log, held.clone(), c2);
    assert_eq!(truncated.chain(), vec![c2]);
    let released = |cuts: &PeerCuts<'_>, held: &BTreeSet<EventId>| {
        let requests = writer_requests(&history.log, held);
        cuts.released(requests.iter().map(|(id, b)| (*id, b)), &stream)
            .is_some()
    };
    let got = serde_json::json!({
        "kept everything": released(&full, &all),
        "truncated": released(&truncated, &held),
    });
    assert_eq!(got, v["released"]);
}

#[test]
fn an_administrator_without_a_slot_has_no_standing_entry() {
    // peers.md, "Storage events", standing entries: P, A and B administer,
    // each enrolled; P disowns B's slot, so the skeleton holds none for B,
    // an administrator in the roster. P's cut has P's and A's entries,
    // ordered 1 and 2 with no gap for B, and is valid at the peer (step 7);
    // a replica finds the checkpoint valid.
    let v = &family("skeleton_cuts")["no_slot"];
    let history = History::of(&v["events"]);
    let cut = history.id("P0: cut of P checkpoints, B without a slot");
    let body = read_cut(history.log.event(cut).unwrap()).unwrap();
    let standing: Vec<Json> = body
        .standing
        .iter()
        .map(|x| {
            serde_json::json!([
                frasil_testkit::hex::encode(x.slot.reference.commitment),
                x.slot.reference.index,
                history.name(x.slot.maker),
                x.order,
                x.dormant,
            ])
        })
        .collect();
    assert_eq!(Json::from(standing), v["standing"]);
    assert!(body.standing.iter().all(|x| x.pseudonym.is_none()));
    let full = PeerCuts::new(&history.log, None);
    assert_eq!(full.validity(cut), Status::Valid);
    assert_eq!(text(&v["cut"]), "cut");
    assert_eq!(text(&v["checkpoint"]), "checkpoint");
    // The entries a record gives with B among its members, without a slot:
    // B takes no order.
    let past = history.log.past(cut);
    let skeleton = full.skeleton_of(&past);
    let b_grant = history.id("P0: twin of P grants B administer");
    let Some(StorageBody::Change { twin: c_b, .. }) = skeleton.body_of(b_grant).cloned() else {
        panic!("B's grant");
    };
    let b_slot = SlotId::new(c_b, 0, b_grant);
    assert!(skeleton.merged().get(&b_slot).is_some_and(|s| !s.is_in));
    let key = |slot: SlotId| (MAX_RANK - skeleton.rank(slot), skeleton.seniority(slot));
    let mut members: Vec<StandingMember<_>> = body
        .slots
        .iter()
        .map(|entry| StandingMember {
            key: key(entry.slot),
            slot: Some(entry.slot),
            pseudonym: None,
            dormancy: Dormancy::Votes,
        })
        .collect();
    members.push(StandingMember {
        key: key(b_slot),
        slot: None,
        pseudonym: None,
        dormancy: Dormancy::Votes,
    });
    assert_eq!(standing_entries(&members), body.standing);
    assert_eq!(check_standing(&body, &standing_entries(&members)), Ok(()));
    // An order left for B is a gap: step 7 refuses it.
    let mut gap = body.clone();
    gap.standing.iter_mut().for_each(|x| {
        if x.order == 2 {
            x.order = 3;
        }
    });
    assert!(!standing_consistent(&gap, |_| false, |_, _| false));
}

#[test]
fn a_heard_member_excused_through_its_out_slot_kept_or_truncated() {
    // peers.md, "Skeleton cuts": B removes A, its senior, so the checkpoint
    // P makes hears A; its standing names A's out slot with A1's enrolment.
    // A, heard, does not vote: P, its senior, removes it again after the
    // checkpoint, which excuses it at the peer, and both cuts take effect. A
    // peer that truncated under the first cut keeps A1's enrolment and
    // agrees with one that kept everything.
    let v = &family("skeleton_cuts")["heard_vote"];
    let history = History::of(&v["events"]);
    let first = history.id("P0: cut of P checkpoints (1)");
    let second = history.id("P0: cut of P checkpoints (2)");
    let a1_enrols = history.id("A1 enrols");
    let a1 = *history.log.event(a1_enrols).unwrap().author();
    let full = PeerCuts::new(&history.log, None);
    let names = |ids: Vec<EventId>| -> Json {
        Json::from(
            ids.into_iter()
                .map(|id| history.name(id).to_string())
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(names(full.chain()), v["chain"]);
    let body = full.body(first).unwrap().clone();
    let heard: Vec<&StandingEntry> = body
        .standing
        .iter()
        .filter(|x| x.pseudonym.is_some())
        .collect();
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].pseudonym, Some(a1_enrols));
    assert!(body.slots.iter().all(|entry| entry.slot != heard[0].slot));
    assert!(always_kept(&history.log, first).contains(&a1_enrols));
    // A1 casts no vote; P's removal after the checkpoint excuses A's slot.
    let tally = full.tally(first).unwrap();
    assert!(tally.voters[&heard[0].slot].contains(&a1));
    assert!(
        tally
            .all_votes
            .get(&heard[0].slot)
            .is_none_or(Vec::is_empty)
    );
    let excuses: Vec<&str> = tally.excuses[&heard[0].slot]
        .iter()
        .map(|&id| history.name(id))
        .collect();
    assert_eq!(
        excuses,
        ["P0: twin of P removes A after the checkpoint, excusing it"]
    );
    assert!(tally.awaiting().is_empty());
    // Truncated under the first cut.
    let plan = full
        .truncation_plan(first, |_, _| false)
        .expect("envelopes held");
    let held: BTreeSet<EventId> = history
        .all()
        .into_iter()
        .filter(|id| !plan.delete.contains(id))
        .collect();
    assert_eq!(names_of(&history, &held), json_names(&v["truncated_holds"]));
    assert!(held.contains(&a1_enrols), "A1's enrolment is kept");
    let truncated = PeerCuts::truncated(&history.log, &history.log, held.clone(), first);
    assert_eq!(truncated.chain(), full.chain());
    assert_eq!(truncated.validity(second), Status::Valid);
    let (kept, trimmed) = (full.skeleton(), truncated.skeleton());
    for &id in &held {
        if id != first && history.log.event(id).unwrap().kind() == kind::STORAGE {
            assert_eq!(kept.status(id), trimmed.status(id), "{}", history.name(id));
        }
    }
    assert_eq!(full.tally(second), truncated.tally(second));
}

#[test]
fn late_enrolments_refused_with_the_classes_of_the_ordinary_checks() {
    // peers.md, "What a late enrolment opens": with a cut in effect, a
    // second enrolment by a pseudonym the peer holds before it is
    // BadSignature, one whose mldsa does not give its kc NotCommitted, one
    // whose ML-DSA-65 half does not verify BadSignature, and a well-formed
    // one Late, though a later event of its author is held.
    let v = &family("skeleton_cuts")["late_enrolment_refusals"];
    let history = History::of(&v["events"]);
    let cut = history.id("P0: cut of P checkpoints");
    let full = PeerCuts::new(&history.log, None);
    assert_eq!(full.chain(), vec![cut]);
    let world = full.skeleton();
    let verdicts = v["verdicts"].as_object().expect("verdicts");
    let refused = full.late_refused();
    for (name, verdict) in verdicts {
        let id = history.id(name);
        let Some(Status::Void { class, .. }) = world.status(id) else {
            panic!("{name}: void");
        };
        assert_eq!(
            frasil_base::errors::Class::name(class),
            text(verdict),
            "{name}"
        );
        assert_eq!(
            refused.get(&id).copied(),
            (text(verdict) != "Late").then_some(class),
            "{name}"
        );
    }
}

#[test]
fn a_reserved_cut_is_held_and_holds_no_erasure() {
    let v = &family("skeleton_cuts")["held_cut"];
    assert_eq!(
        StorageBody::read(&hex(&v["cut_body"])),
        Err(frasil_base::ErrorClass::ExtensionRequired.into())
    );
    let history = History::of(&v["events"]);
    let cuts = PeerCuts::new(&history.log, None);
    assert!(cuts.chain().is_empty());
    assert_eq!(
        cuts.request_state(history.id(text(&v["peer"]["erasure_event"]))),
        RequestState::Free
    );
}

/// Measures the tally alone; cut validity is exercised by the history tests.
#[test]
#[ignore = "512-vote tally measurement"]
fn tally_512_votes() {
    let founder = builder::signer("tally founder");
    let mut b = Builder::new(&founder);
    let StorageBody::Cut(mut body) =
        StorageBody::read(&hex(&family("skeleton_cuts")["limit"]["body"])).unwrap()
    else {
        panic!("cut")
    };
    let pseudonyms: Vec<_> = (0..512)
        .map(|i| builder::pseudonym(&format!("tally {i}")))
        .collect();
    let mut roots = Vec::new();
    for (index, (entry, pseudonym)) in body.slots.iter_mut().zip(&pseudonyms).enumerate() {
        let root = b.root(
            &founder,
            pseudonym,
            builder::example(&format!("root {index}")),
        );
        entry.pseudonym = Some(root);
        roots.push(root);
    }
    body.standing = standing_of(&body.slots);
    let mut joins = Vec::new();
    for parents in roots.chunks(128) {
        joins.push(b.act(&founder, kind::ANCHOR, Vec::new(), parents));
    }
    let cut = b.storage(&pseudonyms[0], StorageBody::Cut(body), &joins);
    let checkpoint = b.checkpoint(&founder, cut, &[cut]);
    let cache = std::sync::Arc::new(frasil_peers::cut::CutTallies::default());
    assert_eq!(
        PeerCuts::new(&b.log, None)
            .with_tallies(cache.clone())
            .tally(cut)
            .unwrap()
            .awaiting()
            .len(),
        512
    );
    let mut incremental = std::time::Duration::ZERO;
    for (index, pseudonym) in pseudonyms.iter().enumerate() {
        b.storage(pseudonym, StorageBody::Ack, &[checkpoint]);
        let cuts = PeerCuts::new(&b.log, None).with_tallies(cache.clone());
        let started = std::time::Instant::now();
        let tally = cuts.tally(cut).unwrap();
        incremental += started.elapsed();
        assert_eq!(tally.awaiting().len(), 511 - index);
    }
    eprintln!("512 incremental vote arrivals, including tally copies: {incremental:?}");
    let cuts = PeerCuts::new(&b.log, None);
    let started = std::time::Instant::now();
    let tally = cuts.tally(cut).unwrap();
    eprintln!("512-vote tally: {:?}", started.elapsed());
    assert_eq!(tally.waited.len(), 512);
    assert!(tally.in_effect());
}

#[test]
fn a_later_cut_cannot_restart_the_epoch_after_a_reserved_cut() {
    use frasil_base::cbor::{self, Value};
    let builder::Space { mut b, p0, .. } = founded();
    let founder = builder::signer("F");
    let all = b.log.canonical().into_iter().collect();
    let (_, slots) = PeerCuts::new(&b.log, None).slots_for(&all);
    let body = StorageBody::Cut(Cut {
        twin: builder::example("held cut twin"),
        salt: [1; 32],
        record: [2; 64],
        epoch: 1,
        standing: standing_of(&slots),
        slots: slots.clone(),
    });
    let Value::Map(mut map) = cbor::decode(&body.encode()).unwrap() else {
        panic!("map")
    };
    map.insert(9, Value::Unsigned(1));
    let parents = b.heads();
    let held = b.act(&p0, kind::STORAGE, Value::Map(map).encode(), &parents);
    let parents = b.heads();
    b.checkpoint(&founder, held, &parents);
    for epoch in [1, 2] {
        let later = cut_from(&mut b, &p0, epoch, slots.clone());
        let parents = b.heads();
        b.checkpoint(&founder, later, &parents);
        let cuts = PeerCuts::new(&b.log, None);
        assert_eq!(
            cuts.validity(held),
            Status::Void {
                class: ErrorClass::ExtensionRequired.into(),
                by: None
            }
        );
        assert_eq!(
            cuts.validity(later),
            Status::Void {
                class: PeersClass::CutPending,
                by: None
            }
        );
        assert!(cuts.chain().is_empty());
    }
}

#[test]
fn retained_tallies_match_each_vector_prefix() {
    let vectors = family("skeleton_cuts");
    for events in [
        &vectors["events"],
        &vectors["held_cut"]["events"],
        &vectors["heard_vote"]["events"],
        &vectors["concurrent_request"]["events"],
    ] {
        check_retained_tallies(&History::of(events).log);
    }
}

#[test]
fn retained_tallies_discard_an_uncommitted_preview() {
    let builder::Space { mut b, p0, a1, .. } = founded();
    let all = b.log.canonical().into_iter().collect();
    let (_, slots) = PeerCuts::new(&b.log, None).slots_for(&all);
    let cut = cut_from(&mut b, &p0, 1, slots);
    let parents = b.heads();
    let checkpoint = b.checkpoint(&builder::signer("F"), cut, &parents);
    let base = b.log.clone();
    let last = b.last.clone();
    b.storage(&p0, StorageBody::Ack, &[checkpoint]);
    let first = b.log.clone();
    b.log = base.clone();
    b.last = last;
    b.storage(&a1, StorageBody::Ack, &[checkpoint]);
    let second = b.log.clone();
    assert_eq!(first.placed_count(), second.placed_count());
    let cache = std::sync::Arc::new(frasil_peers::cut::CutTallies::default());
    // The first preview may fail to commit. A different preview of the
    // same length must not inherit its vote, and neither may the base.
    for log in [&base, &first, &second, &base, &second, &first] {
        let retained = PeerCuts::new(log, None).with_tallies(cache.clone());
        assert_eq!(retained.tally(cut), PeerCuts::new(log, None).tally(cut));
    }
}

#[test]
fn retained_tallies_learn_a_named_voter_before_its_pending_vote_places() {
    let builder::Space { mut b, p0, a1, .. } = founded();
    let enrolment = b.last[a1.device_id()].1;
    let all = b.log.canonical().into_iter().collect();
    let (_, mut slots) = PeerCuts::new(&b.log, None).slots_for(&all);
    let slot = slots
        .iter_mut()
        .find(|slot| slot.pseudonym == Some(enrolment))
        .unwrap();
    let named = slot.slot;
    slot.pseudonym = None;
    let mut standing = standing_of(&slots);
    standing
        .iter_mut()
        .find(|entry| entry.slot == named)
        .unwrap()
        .pseudonym = Some(enrolment);
    // Exercise tally independently of validity: the peer has not received
    // the enrolment the standing entry names. Its vote initially waits on
    // that enrolment as a parent, which itself predates the checkpoint.
    let founder = builder::signer("F");
    let before = b.last[founder.device_id()].1;
    let cut = b.storage(
        &p0,
        StorageBody::Cut(Cut {
            twin: [3; 32],
            salt: [4; 32],
            record: [5; 64],
            epoch: 1,
            slots,
            standing,
        }),
        &[before],
    );
    let checkpoint = b.checkpoint(&builder::signer("F"), cut, &[cut]);
    let vote = b.storage(&a1, StorageBody::Ack, &[checkpoint]);
    let mut peer = frasil_events::Log::new(b.log.genesis().clone()).unwrap();
    for id in b
        .log
        .canonical()
        .into_iter()
        .filter(|&id| id != b.log.id() && id != enrolment && id != vote)
    {
        peer.place(b.log.event(id).unwrap().clone()).unwrap();
    }
    let cache = std::sync::Arc::new(frasil_peers::cut::CutTallies::default());
    assert_eq!(
        PeerCuts::new(&peer, None)
            .with_tallies(cache.clone())
            .tally(cut)
            .unwrap()
            .awaiting()
            .len(),
        2
    );
    peer.place(b.log.event(vote).unwrap().clone()).unwrap();
    peer.place(b.log.event(enrolment).unwrap().clone()).unwrap();
    let retained = PeerCuts::new(&peer, None).with_tallies(cache);
    assert_eq!(retained.tally(cut), PeerCuts::new(&peer, None).tally(cut));
    assert_eq!(retained.tally(cut).unwrap().votes[&named], vec![vote]);
}

#[test]
fn retained_tallies_retry_votes_when_a_declared_checkpoint_arrives() {
    let builder::Space { mut b, p0, a1, .. } = founded();
    let founder = builder::signer("F");
    let all = b.log.canonical().into_iter().collect();
    let (_, slots) = PeerCuts::new(&b.log, None).slots_for(&all);
    let cut = cut_from(&mut b, &p0, 1, slots.clone());
    let parents = b.heads();
    let checkpoint = b.checkpoint(&founder, cut, &parents);
    let later_cut = cut_from(&mut b, &p0, 2, slots);
    let parents = b.heads();
    let later = b.checkpoint(&founder, later_cut, &parents);
    let original = b.storage(&a1, StorageBody::Ack, &[checkpoint]);
    let event = b.log.event(original).unwrap();
    let mut declared = vec![checkpoint, later];
    declared.sort_unstable();
    let envelope = frasil_events::Envelope {
        kind: event.kind(),
        log: Some(b.space),
        ed: *event.ed(),
        kc: *event.kc(),
        seq: event.seq(),
        prev: event.prev(),
        parents: event.parents().to_vec(),
        cuts: declared,
        body: event.unverified_body().to_vec(),
        scheme: frasil_crypto::schemes::Scheme::Hybrid,
    };
    let vote = frasil_events::decode(&envelope.sign(&a1)).unwrap();
    let id = vote.id();
    let mut peer = frasil_events::Log::new(b.log.genesis().clone()).unwrap();
    for id in b
        .log
        .canonical()
        .into_iter()
        .filter(|&id| id != b.log.id() && id != later_cut && id != later && id != original)
    {
        peer.place(b.log.event(id).unwrap().clone()).unwrap();
    }
    peer.place(vote).unwrap();
    let cache = std::sync::Arc::new(frasil_peers::cut::CutTallies::default());
    let before = PeerCuts::new(&peer, None)
        .with_tallies(cache.clone())
        .tally(cut)
        .unwrap();
    assert!(!before.votes.values().any(|ids| ids.contains(&id)));
    peer.place(b.log.event(later_cut).unwrap().clone()).unwrap();
    assert_eq!(
        PeerCuts::new(&peer, None)
            .with_tallies(cache.clone())
            .tally(cut),
        PeerCuts::new(&peer, None).tally(cut)
    );
    peer.place(b.log.event(later).unwrap().clone()).unwrap();
    let retained = PeerCuts::new(&peer, None).with_tallies(cache);
    assert_eq!(retained.tally(cut), PeerCuts::new(&peer, None).tally(cut));
    assert!(
        retained
            .tally(cut)
            .unwrap()
            .votes
            .values()
            .any(|ids| ids.contains(&id))
    );
}
