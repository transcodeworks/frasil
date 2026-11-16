//! A log's placement, copies, stubs, views, evidence and coverage
//! (events.md, "Placement and order", "Chains and evidence of a fork";
//! crypto.md, "Anchors and coverage"), beyond what the vectors show.

use frasil_base::ErrorClass;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::envelope::{self, Envelope, EventId};
use frasil_events::kind;
use frasil_events::{
    Event, EventClass, EvidenceKind, Log, Placement, SignatureState, Stub, decode,
};
use std::collections::{BTreeMap, BTreeSet};

fn signer(n: u8) -> Signer {
    Signer::from_seeds(&[n; 32], &[n.wrapping_add(50); 32], None)
}

fn genesis(founder: &Signer) -> Event {
    let envelope = Envelope {
        kind: kind::SPACE,
        log: None,
        ed: *founder.identity_key(),
        kc: *founder.kc(),
        seq: 1,
        prev: None,
        parents: vec![],
        cuts: Vec::new(),
        body: b"genesis".to_vec(),
        scheme: Scheme::Hybrid,
    };
    decode(&envelope.sign(founder)).unwrap()
}

fn event(
    signer: &Signer,
    kind: u8,
    log: EventId,
    seq: u64,
    prev: Option<EventId>,
    parents: &[EventId],
    body: &[u8],
) -> Event {
    let scheme = if kind == kind::UNIT {
        Scheme::Ed25519
    } else {
        Scheme::Hybrid
    };
    let mut parents = parents.to_vec();
    parents.extend(prev);
    let envelope = Envelope {
        kind,
        log: Some(log),
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq,
        prev,
        parents,
        cuts: Vec::new(),
        body: body.to_vec(),
        scheme,
    };
    decode(&envelope.sign(signer)).unwrap()
}

fn unit(s: &Signer, log: EventId, seq: u64, prev: Option<EventId>, parents: &[EventId]) -> Event {
    event(
        s,
        kind::UNIT,
        log,
        seq,
        prev,
        parents,
        format!("unit {seq}").as_bytes(),
    )
}

#[test]
fn a_new_log_needs_a_genesis() {
    let founder = signer(1);
    let g = genesis(&founder);
    let log = Log::new(g.clone()).unwrap();
    let u = unit(&founder, log.id(), 2, Some(g.id()), &[]);
    assert_eq!(Log::new(u).err(), Some(EventClass::WrongLog));
    assert_eq!(log.id(), g.id());
    assert_eq!(log.genesis(), &g);
    assert_eq!((log.len(), log.is_empty()), (1, false));
    assert_eq!(log.height(g.id()), Some(0));
    assert_eq!(log.heads(), vec![g.id()]);
}

/// A replica that drops a pending event no longer holds it nor waits for
/// its parents on its account; an event that waited on it names it among
/// what to fetch, and takes it when it comes again.
#[test]
fn a_dropped_pending_event_is_fetched_again() {
    let founder = signer(1);
    let writer = signer(2);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    let a = unit(&founder, log.id(), 2, Some(g.id()), &[]);
    let w = unit(&writer, log.id(), 1, None, &[a.id()]);
    let b = unit(&founder, log.id(), 3, Some(a.id()), &[w.id()]);
    log.place(w.clone()).unwrap();
    log.place(b.clone()).unwrap();
    assert_eq!(log.pending_count(), 2);
    assert_eq!(log.pending_event(w.id()), Some(&w));
    assert_eq!(log.drop_pending(w.id()), Some(w.clone()));
    assert_eq!(log.drop_pending(w.id()), None);
    assert_eq!(log.pending_event(w.id()), None);
    assert_eq!(log.pending_count(), 1);
    // b still waits for a and w, and w is fetched again.
    let mut wanted = vec![a.id(), w.id()];
    wanted.sort();
    assert_eq!(log.wanted(), wanted);
    // Dropping b too leaves nothing to wait for.
    log.drop_pending(b.id());
    assert!(log.wanted().is_empty());
    log.place(b.clone()).unwrap();
    log.place(w.clone()).unwrap();
    assert_eq!(
        log.place(a.clone()),
        Ok(Placement::Placed(vec![a.id(), w.id(), b.id()]))
    );
    assert_eq!(log.pending_count(), 0);
}

#[test]
fn pending_events_wait_for_their_parents() {
    let founder = signer(1);
    let writer = signer(2);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    let a = unit(&founder, log.id(), 2, Some(g.id()), &[]);
    let w = unit(&writer, log.id(), 1, None, &[a.id()]);
    let b = unit(&founder, log.id(), 3, Some(a.id()), &[w.id()]);
    // b waits for a and w; w waits for a.
    assert_eq!(
        log.place(b.clone()),
        Ok(Placement::Pending(
            vec![a.id(), w.id()]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        ))
    );
    assert_eq!(log.place(w.clone()), Ok(Placement::Pending(vec![a.id()])));
    assert_eq!(log.place(b.clone()), Ok(Placement::Known));
    assert_eq!(log.pending().count(), 2);
    let mut wanted = vec![a.id(), w.id()];
    wanted.sort();
    assert_eq!(log.wanted(), wanted);
    assert_eq!(
        log.place(a.clone()),
        Ok(Placement::Placed(vec![a.id(), w.id(), b.id()]))
    );
    assert_eq!(log.pending().count(), 0);
    assert!(log.wanted().is_empty());
    assert_eq!(log.heads(), vec![b.id()]);
    assert_eq!(log.height(b.id()), Some(3));
    assert!(log.precedes(g.id(), b.id()) && log.precedes(a.id(), w.id()));
    assert!(!log.precedes(b.id(), a.id()) && !log.precedes(a.id(), a.id()));
    assert_eq!(
        log.past(b.id()),
        [g.id(), a.id(), w.id()].into_iter().collect()
    );
    assert_eq!(log.chain(founder.device_id()), vec![g.id(), a.id(), b.id()]);
    assert_eq!(log.latest(founder.device_id()), Some(b.id()));
    assert_eq!(log.latest(&frasil_crypto::device::DeviceId([9; 32])), None);
    assert_eq!(log.events().count(), 4);
}

#[test]
fn events_of_another_log_are_refused() {
    let founder = signer(1);
    let mut log = Log::new(genesis(&founder)).unwrap();
    let other = Log::new(genesis(&signer(2))).unwrap();
    let stranger = unit(&founder, other.id(), 1, None, &[other.id()]);
    assert_eq!(log.place(stranger), Err(EventClass::WrongLog));
    assert_eq!(
        log.place(other.genesis().clone()),
        Err(EventClass::WrongLog)
    );
    // A parent the replica knows is another log's.
    let citing = unit(&founder, log.id(), 2, Some(log.id()), &[other.id()]);
    assert_eq!(
        log.place_checked(citing.clone(), |id| id == other.id()),
        Err(EventClass::WrongLog)
    );
    // Not known as another log's, it waits for that parent.
    assert_eq!(log.place(citing), Ok(Placement::Pending(vec![other.id()])));
}

#[test]
fn a_log_keeps_the_first_copy_whose_signature_verified() {
    let founder = signer(1);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    // A scheme-2 event, and a hedged copy of the same map: one ID.
    let fields = Envelope {
        kind: kind::SPACE,
        log: Some(log.id()),
        ed: *founder.identity_key(),
        kc: *founder.kc(),
        seq: 2,
        prev: Some(g.id()),
        parents: vec![g.id()],
        cuts: Vec::new(),
        body: b"space event".to_vec(),
        scheme: Scheme::Hybrid,
    };
    let map = fields.encode();
    let tbs = envelope::tbs(&map);
    let good = decode(&fields.sign(&founder)).unwrap();
    let hedged = decode(&envelope::assemble(
        &map,
        &founder.sign_hybrid_with_rnd(&tbs, &[7; 32]),
    ))
    .unwrap();
    assert_eq!(good.id(), hedged.id());
    assert_ne!(good.signature(), hedged.signature());
    // A copy whose ML-DSA-65 half is broken: its Ed25519 half still decodes.
    let mut broken = good.signature().to_vec();
    *broken.last_mut().unwrap() ^= 1;
    let broken = decode(&envelope::assemble(&map, &broken)).unwrap();
    let key = Some(founder.keys());

    assert_eq!(
        log.place(broken.clone()),
        Ok(Placement::Placed(vec![broken.id()]))
    );
    assert_eq!(
        log.signature_state(good.id()),
        Some(SignatureState::NoHybridKey)
    );
    assert_eq!(
        log.verify_hybrid(good.id(), None),
        Err(ErrorClass::NoHybridKey.into())
    );
    assert_eq!(
        log.verify_hybrid(good.id(), key),
        Err(ErrorClass::BadSignature.into())
    );
    assert_eq!(
        log.signature_state(good.id()),
        Some(SignatureState::BadSignature)
    );
    // Another copy replaces the refused one.
    assert_eq!(log.place(hedged.clone()), Ok(Placement::Known));
    assert_eq!(
        log.event(good.id()).unwrap().signature(),
        hedged.signature()
    );
    // Until both halves verify, the log gives the event, but not as
    // verified.
    assert!(log.verified(good.id()).is_none());
    let verified = log.verify_hybrid(good.id(), key).unwrap();
    assert!(log.is_verified(good.id()));
    assert_eq!(log.verified(good.id()), Some(&verified));
    assert_eq!(
        verified.body(),
        log.event(good.id()).unwrap().unverified_body()
    );
    // Once verified, a copy changes nothing.
    assert_eq!(log.place(good.clone()), Ok(Placement::Known));
    assert_eq!(
        log.event(good.id()).unwrap().signature(),
        hedged.signature()
    );
    assert_eq!(
        log.verify_hybrid(EventId([0; 32]), key),
        Err(ErrorClass::Pending.into())
    );
}

#[test]
fn stubs_stand_for_parents() {
    let founder = signer(1);
    let writer = signer(2);
    let mut log = Log::new(genesis(&founder)).unwrap();
    let stubbed = EventId([0x55; 32]);
    let stub = Stub {
        id: stubbed,
        author: *writer.device_id(),
        seq: 4,
        height: 9,
        kind: kind::UNIT,
        cuts: frasil_events::Cuts::NONE,
    };
    let after = unit(&writer, log.id(), 5, Some(stubbed), &[]);
    assert_eq!(
        log.place(after.clone()),
        Ok(Placement::Pending(vec![stubbed]))
    );
    assert_eq!(log.add_stub(stub), vec![after.id()]);
    assert_eq!(log.height(after.id()), Some(10));
    assert_eq!(log.stub(stubbed), Some(&stub));
    assert_eq!(
        log.heads(),
        vec![log.id(), after.id()]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
    // A stubbed prev is never evidence.
    assert!(log.evidence(|_| true).is_empty());
    // The past stops at a stub: what lies before it is not known here.
    assert!(log.precedes(stubbed, after.id()));
    assert!(!log.precedes(log.id(), after.id()));
    ancestry_agrees(&log, &[stubbed, EventId([0x66; 32])]);
    // The same stub again changes nothing; a disagreeing one disputes it.
    assert!(log.add_stub(stub).is_empty());
    assert!(log.add_stub(Stub { height: 3, ..stub }).is_empty());
    assert_eq!(log.stub(stubbed), None);
    let next = unit(&writer, log.id(), 6, Some(after.id()), &[stubbed]);
    assert_eq!(log.place(next), Ok(Placement::Pending(vec![stubbed])));
    let all: BTreeSet<EventId> = log.canonical().into_iter().collect();
    assert!(!log.is_closed(&all));
    ancestry_agrees(&log, &[stubbed]);
}

#[test]
fn an_event_that_arrives_in_full_corrects_the_heights_on_its_stub() {
    let founder = signer(1);
    let writer = signer(2);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    let first = unit(&writer, log.id(), 1, None, &[g.id()]);
    let second = unit(&writer, log.id(), 2, Some(first.id()), &[]);
    let third = unit(&writer, log.id(), 3, Some(second.id()), &[]);
    // A stub that lies about the second unit's height.
    let lie = Stub {
        id: second.id(),
        author: *writer.device_id(),
        seq: 2,
        height: 40,
        kind: kind::UNIT,
        cuts: frasil_events::Cuts::NONE,
    };
    assert!(matches!(
        log.place(third.clone()),
        Ok(Placement::Pending(_))
    ));
    assert_eq!(log.add_stub(lie), vec![third.id()]);
    assert_eq!(log.height(third.id()), Some(41));
    // The event arrives in full, its past with it: what was placed on its
    // stub takes its height from it, and it is no head.
    assert!(matches!(log.place(first.clone()), Ok(Placement::Placed(_))));
    assert!(matches!(
        log.place(second.clone()),
        Ok(Placement::Placed(_))
    ));
    assert_eq!(log.height(second.id()), Some(2));
    assert_eq!(log.height(third.id()), Some(3));
    assert_eq!(log.heads(), vec![third.id()]);
    assert_eq!(
        log.canonical(),
        vec![g.id(), first.id(), second.id(), third.id()]
    );
}

#[test]
fn a_space_event_rests_only_on_a_confirmed_stub() {
    let founder = signer(1);
    let writer = signer(2);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    let stubbed = EventId([0x66; 32]);
    let stub = Stub {
        id: stubbed,
        author: *writer.device_id(),
        seq: 1,
        height: 1,
        kind: kind::UNIT,
        cuts: frasil_events::Cuts::NONE,
    };
    let change = event(
        &founder,
        kind::SPACE,
        log.id(),
        2,
        Some(g.id()),
        &[stubbed],
        b"change",
    );
    let after = unit(&writer, log.id(), 2, Some(stubbed), &[]);
    assert!(matches!(
        log.place(change.clone()),
        Ok(Placement::Pending(_))
    ));
    assert!(matches!(
        log.place(after.clone()),
        Ok(Placement::Pending(_))
    ));
    // Unconfirmed, the stub places the unit; the space event waits, and
    // its parent is still wanted.
    assert_eq!(log.add_stub_unconfirmed(stub), vec![after.id()]);
    assert!(!log.contains(change.id()));
    assert_eq!(log.wanted(), vec![stubbed]);
    assert!(!log.is_stub_confirmed(stubbed));
    assert_eq!(log.confirm_stub(stubbed), vec![change.id()]);
    assert!(log.wanted().is_empty());
    // A stub added as confirmed places a space event at once.
    let other = EventId([0x67; 32]);
    let later = event(
        &founder,
        kind::SPACE,
        log.id(),
        3,
        Some(change.id()),
        &[other],
        b"later",
    );
    assert!(matches!(
        log.place(later.clone()),
        Ok(Placement::Pending(_))
    ));
    assert_eq!(log.add_stub(Stub { id: other, ..stub }), vec![later.id()]);
}

#[test]
fn a_pending_unit_places_on_its_own_stubs_only_provisionally() {
    let founder = signer(1);
    let writer = signer(2);
    let stranger = signer(3);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    let withheld = EventId([0x77; 32]);
    let unknown = EventId([0x78; 32]);
    let stub = |id| Stub {
        id,
        author: *writer.device_id(),
        seq: 1,
        height: 1,
        kind: kind::UNIT,
        cuts: frasil_events::Cuts::NONE,
    };
    let after = unit(&writer, log.id(), 2, Some(withheld), &[]);
    assert!(matches!(
        log.place(after.clone()),
        Ok(Placement::Pending(_))
    ));
    // A unit pending on a parent its stubs do not cover places nothing.
    let lone = unit(&stranger, log.id(), 1, None, &[unknown]);
    assert!(matches!(log.place(lone.clone()), Ok(Placement::Pending(_))));
    assert_eq!(
        log.add_provisional_stubs(lone.id(), &[stub(withheld)]),
        None
    );
    assert!(log.stub(withheld).is_none() && !log.contains(after.id()));
    // One whose stubs cover its pending past places, with what rests on
    // them, and is held apart until judged.
    let source = unit(&stranger, log.id(), 2, Some(lone.id()), &[after.id()]);
    assert!(matches!(
        log.place(source.clone()),
        Ok(Placement::Pending(_))
    ));
    let placed = log
        .add_provisional_stubs(source.id(), &[stub(withheld), stub(unknown)])
        .unwrap();
    assert!(placed.contains(&source.id()) && placed.contains(&after.id()));
    assert_eq!(log.provisional_sources(), BTreeSet::from([source.id()]));
    assert_eq!(
        log.resting_on_provisional(),
        BTreeSet::from([lone.id(), after.id(), source.id()])
    );
    // Refused, it takes them back: everything is pending as before.
    let gone: BTreeSet<EventId> = log.retract_provisional(source.id()).into_iter().collect();
    assert_eq!(gone, BTreeSet::from([lone.id(), after.id(), source.id()]));
    assert!(log.stub(withheld).is_none() && log.stub(unknown).is_none());
    assert!(!log.contains(after.id()) && !log.contains(source.id()));
    assert_eq!(log.heads(), vec![g.id()]);
    assert!(log.wanted().contains(&withheld) && log.wanted().contains(&unknown));
    assert!(log.provisional_sources().is_empty());
    // Placed again and judged valid, they stay.
    log.add_provisional_stubs(source.id(), &[stub(withheld), stub(unknown)])
        .unwrap();
    log.accept_provisional(source.id());
    assert!(log.resting_on_provisional().is_empty());
    assert!(log.contains(after.id()) && log.contains(source.id()));
    assert!(log.retract_provisional(source.id()).is_empty());
}

#[test]
fn evidence_counts_only_verified_events_of_the_view() {
    let founder = signer(1);
    let writer = signer(2);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    // Two storage events of the writer at seq 1: scheme 2, not yet verified.
    let first = event(&writer, kind::STORAGE, log.id(), 1, None, &[g.id()], b"one");
    let second = event(&writer, kind::STORAGE, log.id(), 1, None, &[g.id()], b"two");
    log.place(first.clone()).unwrap();
    log.place(second.clone()).unwrap();
    assert!(log.evidence(|_| true).is_empty());
    let key = Some(writer.keys());
    log.verify_hybrid(first.id(), key).unwrap();
    assert!(log.evidence(|_| true).is_empty());
    log.verify_hybrid(second.id(), key).unwrap();
    let evidence = log.evidence(|_| true);
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, EvidenceKind::Duplicate);
    assert_eq!(evidence[0].first, first.id().min(second.id()));
    assert_eq!(evidence[0].fork_seq, 1);
    let points = log.fork_points(|_| true);
    assert_eq!(points.fork_point(writer.device_id()), Some(1));
    assert!(points.is_void(&first) && !points.is_void(&g));
    // A view that holds one of them shows no fork.
    let view: BTreeSet<EventId> = [g.id(), first.id()].into_iter().collect();
    assert!(log.is_closed(&view));
    assert!(log.fork_points_in(&view, |_| true).is_empty());
    assert_eq!(log.heads_in(&view), vec![first.id()]);
    ancestry_agrees(&log, &[]);
    // A filter (after the sunset: covered or scheme 2) narrows what counts.
    assert!(log.evidence(|e| e.id() != second.id()).is_empty());
    // The proof verifies under the writer's key, and waits without it.
    let proof = log.proof(&evidence[0]).unwrap();
    assert_eq!(
        frasil_events::verify_proof(&proof, &()).err(),
        Some(ErrorClass::NoHybridKey.into())
    );
    let mut ring = frasil_crypto::device::KeyRing::new();
    ring.add_keys(writer.keys().clone());
    let shown = frasil_events::verify_proof(&proof, &ring).unwrap();
    assert_eq!(shown.fork_seq, 1);
    assert_eq!(shown.log, log.id());
}

#[test]
fn coverage_over_a_log() {
    let founder = signer(1);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    let u1 = unit(&founder, log.id(), 2, Some(g.id()), &[]);
    let anchor = event(&founder, kind::ANCHOR, log.id(), 3, Some(u1.id()), &[], b"");
    let u2 = unit(&founder, log.id(), 4, Some(anchor.id()), &[]);
    for e in [&u1, &anchor, &u2] {
        log.place(e.clone()).unwrap();
    }
    let none = BTreeSet::new();
    let before = log.coverage(false, &none);
    // The genesis and the anchor wait for their ML-DSA-65 halves.
    assert_eq!(before.keys().copied().collect::<Vec<_>>(), {
        let mut ids = vec![u1.id(), u2.id()];
        ids.sort_by_key(|id| log.height(*id));
        ids
    });
    assert!(before.values().all(Result::is_ok));
    // Unverified, the anchor covers nothing.
    let after = log.coverage(true, &none);
    assert_eq!(after[&u1.id()], Err(ErrorClass::Uncovered));
    let key = Some(founder.keys());
    for id in [g.id(), anchor.id()] {
        log.verify_hybrid(id, key).unwrap();
    }
    let after: BTreeMap<EventId, Result<(), ErrorClass>> = log.coverage(true, &none);
    assert_eq!(after[&g.id()], Ok(()));
    assert_eq!(after[&u1.id()], Ok(()));
    assert_eq!(after[&anchor.id()], Ok(()));
    assert_eq!(after[&u2.id()], Err(ErrorClass::Uncovered));
    let held: BTreeSet<EventId> = [u2.id()].into_iter().collect();
    assert_eq!(log.coverage(true, &held)[&u2.id()], Ok(()));
    assert_eq!(
        log.covered(),
        [g.id(), u1.id(), anchor.id()].into_iter().collect()
    );
    // An anchor with a body, or of a genesis, never decodes.
    let mut bad = Envelope {
        kind: kind::ANCHOR,
        log: Some(log.id()),
        ed: *founder.identity_key(),
        kc: *founder.kc(),
        seq: 5,
        prev: Some(u2.id()),
        parents: vec![u2.id()],
        cuts: Vec::new(),
        body: b"x".to_vec(),
        scheme: Scheme::Hybrid,
    };
    assert_eq!(
        decode(&bad.sign(&founder)).err(),
        Some(ErrorClass::Malformed.into())
    );
    bad.body.clear();
    bad.log = None;
    bad.seq = 1;
    bad.prev = None;
    bad.parents.clear();
    assert_eq!(
        decode(&bad.sign(&founder)).err(),
        Some(ErrorClass::Malformed.into())
    );
}

#[test]
fn a_device_cites_only_what_it_accepted_and_continues_its_chain() {
    let founder = signer(1);
    let writer = signer(2);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    let a = unit(&founder, log.id(), 2, Some(g.id()), &[]);
    // A space event the replica cannot verify yet, and a unit after it.
    let m = event(
        &writer,
        kind::SPACE,
        log.id(),
        1,
        None,
        &[a.id()],
        b"sealed",
    );
    let b = unit(&founder, log.id(), 3, Some(a.id()), &[m.id()]);
    let c = unit(&writer, log.id(), 2, Some(m.id()), &[]);
    for e in [&a, &m, &b, &c] {
        log.place(e.clone()).unwrap();
    }
    log.verify_hybrid(g.id(), Some(founder.keys())).unwrap();
    let view = log.citable(|e| log.is_verified(e.id()));
    assert_eq!(view, [g.id(), a.id()].into_iter().collect());
    assert_eq!(log.heads_in(&view), vec![a.id()]);
    assert_eq!(log.heads(), {
        let mut heads = vec![b.id(), c.id()];
        heads.sort();
        heads
    });
    assert_eq!(log.next_in_chain(founder.device_id()), (4, Some(b.id())));
    assert_eq!(log.next_in_chain(writer.device_id()), (3, Some(c.id())));
    assert_eq!(
        log.next_in_chain(&frasil_crypto::device::DeviceId([9; 32])),
        (1, None)
    );
}

/// events.md, 3.3 The ML-DSA-65 half: a verdict a log remembers is the one
/// the author's keys give that copy, and only matching keys reach it.
#[test]
fn a_remembered_ml_dsa_verdict_is_read_only_under_the_authors_keys() {
    let founder = signer(1);
    let other = signer(2);
    let g = genesis(&founder);
    let mut log = Log::new(g.clone()).unwrap();
    let fields = Envelope {
        kind: kind::SPACE,
        log: Some(log.id()),
        ed: *founder.identity_key(),
        kc: *founder.kc(),
        seq: 2,
        prev: Some(g.id()),
        parents: vec![g.id()],
        cuts: Vec::new(),
        body: b"space event".to_vec(),
        scheme: Scheme::Hybrid,
    };
    let map = fields.encode();
    let tbs = envelope::tbs(&map);
    let good = decode(&fields.sign(&founder)).unwrap();
    let hedged = decode(&envelope::assemble(
        &map,
        &founder.sign_hybrid_with_rnd(&tbs, &[7; 32]),
    ))
    .unwrap();
    let mut broken = good.signature().to_vec();
    *broken.last_mut().unwrap() ^= 1;
    let broken = decode(&envelope::assemble(&map, &broken)).unwrap();
    let key = Some(founder.keys());
    log.place(broken.clone()).unwrap();

    // No keys, or another holder's: pending, before and after a verdict.
    let no_key = Err(EventClass::from(ErrorClass::NoHybridKey));
    let bad = Err(EventClass::from(ErrorClass::BadSignature));
    assert_eq!(log.verify_hybrid_remembered(&broken, None), no_key);
    assert_eq!(
        log.verify_hybrid_remembered(&broken, Some(other.keys())),
        no_key
    );
    assert_eq!(log.verify_hybrid_remembered(&broken, key), bad);
    assert_eq!(log.verify_hybrid_remembered(&broken, key), bad);
    assert_eq!(log.verify_hybrid_remembered(&broken, None), no_key);
    // The log's own state is left as it was.
    assert_eq!(
        log.signature_state(good.id()),
        Some(SignatureState::NoHybridKey)
    );

    // Copies of the same event with other signatures are checked on their
    // own: one ID, three verdicts.
    assert_eq!(
        log.verify_hybrid_remembered(&good, key)
            .map(|verified| verified.into_event()),
        Ok(good.clone())
    );
    assert_eq!(
        log.verify_hybrid_remembered(&hedged, key)
            .map(|verified| verified.into_event()),
        Ok(hedged.clone())
    );
    assert_eq!(log.verify_hybrid_remembered(&broken, key), bad);
    assert_eq!(
        log.verify_hybrid_remembered(&good, Some(other.keys())),
        no_key
    );

    // A copy that replaces the refused one, and a log the replica verified
    // itself, give the same.
    assert_eq!(log.verify_hybrid(good.id(), key), bad);
    assert_eq!(log.place(hedged.clone()), Ok(Placement::Known));
    assert!(log.verify_hybrid(good.id(), key).is_ok());
    assert_eq!(log.verify_hybrid_remembered(&broken, key), bad);
    assert!(log.verify_hybrid_remembered(&hedged, None).is_ok());

    // A clone shares what was checked; a log read back from rest starts
    // with nothing remembered and checks again.
    let clone = log.clone();
    assert!(clone.verify_hybrid_remembered(&good, key).is_ok());
    let reopened = Log::decode_state(&log.encode_state()).unwrap();
    assert_eq!(reopened.verify_hybrid_remembered(&broken, None), no_key);
    assert_eq!(reopened.verify_hybrid_remembered(&broken, key), bad);
    assert!(reopened.verify_hybrid_remembered(&good, key).is_ok());
}

/// [`Log::ancestry`] answers each pair among `ids` as [`Log::precedes`]
/// does.
fn ancestry_agrees(log: &Log, extra: &[EventId]) {
    let mut ids = log.canonical();
    ids.extend_from_slice(extra);
    for &later in &ids {
        let ancestry = log.ancestry(later);
        for &earlier in &ids {
            assert_eq!(
                ancestry.includes(earlier),
                log.precedes(earlier, later),
                "{earlier:?} before {later:?}"
            );
        }
    }
}
