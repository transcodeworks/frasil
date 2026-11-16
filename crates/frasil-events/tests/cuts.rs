//! Cuts against a log's placed, witnessed and stubbed parents (events.md,
//! 3.11 Cuts; units.md, "Partial replicas").

use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::cuts::{self, Cuts, CutsCheck, NoCheckpoints};
use frasil_events::envelope::{Envelope, EventId};
use frasil_events::kind;
use frasil_events::{Event, EventClass, Log, Placement, Stub, decode};
use std::collections::BTreeSet;

fn signer(n: u8) -> Signer {
    Signer::from_seeds(&[n; 32], &[n.wrapping_add(70); 32], None)
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
    cuts: &[EventId],
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
        cuts: cuts.to_vec(),
        body: format!("event {seq}").into_bytes(),
        scheme,
    };
    decode(&envelope.sign(signer)).unwrap()
}

/// A checkpoint `c`, a unit after it, and a unit after that one:
///
/// ```text
/// g <- c (F, checkpoint) <- u1 (A, cuts [c]) <- u2 (A, cuts [c])
/// ```
struct History {
    g: Event,
    c: Event,
    u1: Event,
    u2: Event,
}

fn history() -> History {
    let (f, a) = (signer(1), signer(2));
    let g = genesis(&f);
    let log = g.id();
    let c = event(&f, kind::SPACE, log, 2, Some(g.id()), &[], &[]);
    let u1 = event(&a, kind::UNIT, log, 1, None, &[c.id()], &[c.id()]);
    let u2 = event(&a, kind::UNIT, log, 2, Some(u1.id()), &[], &[c.id()]);
    History { g, c, u1, u2 }
}

#[test]
fn a_witnessed_parent_gives_its_cuts() {
    let h = history();
    let checkpoints: BTreeSet<EventId> = [h.c.id()].into();
    let mut log = Log::new(h.g.clone()).unwrap();
    assert_eq!(
        log.place(h.u2.clone()).unwrap(),
        Placement::Pending(vec![h.u1.id()])
    );
    // Not held: the check waits for u1.
    assert_eq!(
        log.check_cuts(&checkpoints, &h.u2),
        CutsCheck::Pending(vec![h.u1.id()])
    );
    // Witnessed, u1's envelope is held: u2 reads its cuts, and needs
    // neither c nor whether c is a checkpoint.
    log.witness(h.u1.clone()).unwrap();
    assert!(log.contains(h.u2.id()));
    assert_eq!(log.check_cuts(&NoCheckpoints, &h.u2), CutsCheck::Correct);
    assert_eq!(log.check_cuts(&checkpoints, &h.u2), CutsCheck::Correct);
    assert_eq!(log.follows(h.u2.id(), h.c.id()), Ok(true));
    assert_eq!(log.follows(h.u1.id(), h.c.id()), Ok(true));
    // u1 itself names c as a parent: whether c is a checkpoint decides.
    log.witness(h.c.clone()).unwrap();
    assert_eq!(log.check_cuts(&checkpoints, &h.u1), CutsCheck::Correct);
    assert_eq!(log.check_cuts(&NoCheckpoints, &h.u1), CutsCheck::Bad);
    assert_eq!(
        log.check_cuts(&NoCheckpoints, &h.u1).verdict(),
        Err(EventClass::BadCuts)
    );
}

#[test]
fn a_stubbed_parent_gives_the_cuts_its_stub_carries() {
    let h = history();
    let checkpoints: BTreeSet<EventId> = [h.c.id()].into();
    let mut log = Log::new(h.g.clone()).unwrap();
    // c is placed; u1 stands as a stub that carries its cuts.
    log.place(h.c.clone()).unwrap();
    log.add_stub(Stub {
        id: h.u1.id(),
        author: *signer(2).device_id(),
        seq: 1,
        height: 2,
        kind: kind::UNIT,
        cuts: Cuts::of(&h.u1),
    });
    assert!(matches!(
        log.place(h.u2.clone()).unwrap(),
        Placement::Placed(_)
    ));
    // The stub answers for u1: the check no longer waits for the event.
    assert_eq!(log.check_cuts(&checkpoints, &h.u2), CutsCheck::Correct);
    assert_eq!(log.cuts_for(&checkpoints, &[h.u1.id()]), Ok(vec![h.c.id()]));
    // A stub is never a checkpoint: whether the space events are opened
    // does not matter to it.
    let unopened = |_: &Event| None;
    assert_eq!(
        cuts::expected(&log, &unopened, &[h.u1.id()]),
        Ok(vec![h.c.id()])
    );
}

#[test]
fn a_stub_that_carries_no_cuts_gives_none() {
    let h = history();
    let checkpoints: BTreeSet<EventId> = [h.c.id()].into();
    let mut log = Log::new(h.g.clone()).unwrap();
    log.place(h.c.clone()).unwrap();
    // A stub of u1 without its cuts says u1 declares none: u2's cut is
    // then one no parent gives.
    log.add_stub(Stub {
        id: h.u1.id(),
        author: *signer(2).device_id(),
        seq: 1,
        height: 2,
        kind: kind::UNIT,
        cuts: Cuts::NONE,
    });
    log.place(h.u2.clone()).unwrap();
    assert_eq!(log.check_cuts(&checkpoints, &h.u2), CutsCheck::Bad);
    // A second stub that disagrees disputes the first: the stub no longer
    // counts, and the check waits for u1 itself.
    log.add_stub(Stub {
        id: h.u1.id(),
        author: *signer(2).device_id(),
        seq: 1,
        height: 2,
        kind: kind::UNIT,
        cuts: Cuts::of(&h.u1),
    });
    assert_eq!(
        log.check_cuts(&checkpoints, &h.u2),
        CutsCheck::Pending(vec![h.u1.id()])
    );
    // The event in full answers.
    log.place(h.u1.clone()).unwrap();
    assert_eq!(log.check_cuts(&checkpoints, &h.u2), CutsCheck::Correct);
}

#[test]
fn a_stubbed_parent_whose_cut_is_not_held_waits_for_nothing_more() {
    let h = history();
    let checkpoints: BTreeSet<EventId> = [h.c.id()].into();
    // c is neither placed nor kept: one cut alone needs no ordering, so
    // the stub answers.
    let mut log = Log::new(h.g.clone()).unwrap();
    log.add_stub(Stub {
        id: h.u1.id(),
        author: *signer(2).device_id(),
        seq: 1,
        height: 2,
        kind: kind::UNIT,
        cuts: Cuts::of(&h.u1),
    });
    log.place(h.u2.clone()).unwrap();
    assert_eq!(log.check_cuts(&checkpoints, &h.u2), CutsCheck::Correct);
    // Whether u2 follows c is read from its envelope; what c follows needs
    // c's envelope.
    assert_eq!(log.follows(h.u2.id(), h.c.id()), Ok(true));
    assert_eq!(log.cuts_reach(h.u2.id()), Err(vec![h.c.id()]));
    assert!(log.keep_envelope(h.c.clone()).unwrap());
    assert_eq!(
        log.cuts_reach(h.u2.id()),
        Ok([h.c.id()].into_iter().collect())
    );
}

#[test]
fn the_cuts_a_writer_declares() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    for event in [&h.c, &h.u1, &h.u2] {
        log.place(event.clone()).unwrap();
    }
    let checkpoints: BTreeSet<EventId> = [h.c.id()].into();
    // Every event of the history declares what its parents give.
    for event in [&h.g, &h.c, &h.u1, &h.u2] {
        assert_eq!(log.check_cuts(&checkpoints, event), CutsCheck::Correct);
    }
    // A writer citing the heads declares c.
    assert_eq!(log.cuts_for(&checkpoints, &log.heads()), Ok(vec![h.c.id()]));
    // Through a closure: c not yet opened.
    let unopened = |event: &Event| (event.id() != h.c.id()).then_some(false);
    assert_eq!(
        cuts::expected(&log, &unopened, &[h.c.id()]),
        Err(vec![h.c.id()])
    );
    assert_eq!(
        cuts::expected(&log, &unopened, &[h.u2.id()]),
        Ok(vec![h.c.id()])
    );
    // c's envelope is placed: the walk below it is complete.
    assert_eq!(
        log.cuts_reach(h.u2.id()),
        Ok([h.c.id()].into_iter().collect())
    );
    assert!(cuts::may_be_checkpoint(&h.c));
    assert!(!cuts::may_be_checkpoint(&h.g));
    assert!(!cuts::may_be_checkpoint(&h.u1));
}
