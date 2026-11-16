//! A partial replica's placement by witnessed parents, `Path` checks and
//! proven order (units.md, "Partial replicas").

use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::envelope::{Envelope, EventId};
use frasil_events::kind;
use frasil_events::{Event, EventClass, Log, Placement, check_path, decode};

fn signer(n: u8) -> Signer {
    Signer::from_seeds(&[n; 32], &[n.wrapping_add(50); 32], None)
}

fn genesis(founder: &Signer, body: &[u8]) -> Event {
    let envelope = Envelope {
        kind: kind::SPACE,
        log: None,
        ed: *founder.identity_key(),
        kc: *founder.kc(),
        seq: 1,
        prev: None,
        parents: vec![],
        cuts: Vec::new(),
        body: body.to_vec(),
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
) -> Event {
    let scheme = if kind == kind::UNIT {
        Scheme::Ed25519
    } else {
        Scheme::Hybrid
    };
    let mut parents = parents.to_vec();
    parents.extend(prev);
    parents.sort();
    parents.dedup();
    let envelope = Envelope {
        kind,
        log: Some(log),
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq,
        prev,
        parents,
        cuts: Vec::new(),
        body: format!("event {seq}").into_bytes(),
        scheme,
    };
    decode(&envelope.sign(signer)).unwrap()
}

/// A space whose founder F removes after a chain of B's units in a stream
/// the partial replica does not hold:
///
/// ```text
/// g <- u1 (A, held) <- w1 (B) <- w2 (B) <- r (F, space event)
/// ```
struct History {
    g: Event,
    u1: Event,
    w1: Event,
    w2: Event,
    r: Event,
    a: Signer,
}

fn history() -> History {
    let (f, a, b) = (signer(1), signer(2), signer(3));
    let g = genesis(&f, b"genesis");
    let log = g.id();
    let u1 = event(&a, kind::UNIT, log, 1, None, &[g.id()]);
    let w1 = event(&b, kind::UNIT, log, 1, None, &[u1.id()]);
    let w2 = event(&b, kind::UNIT, log, 2, Some(w1.id()), &[]);
    let r = event(&f, kind::SPACE, log, 2, Some(g.id()), &[w2.id()]);
    History {
        g,
        u1,
        w1,
        w2,
        r,
        a,
    }
}

#[test]
fn an_event_is_placed_once_each_parent_is_placed_stubbed_or_witnessed() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    log.place(h.u1.clone()).unwrap();
    assert_eq!(
        log.place(h.r.clone()).unwrap(),
        Placement::Pending(vec![h.w2.id()])
    );
    // The replica fetches w2 and checks it; it does not fetch w2's parents.
    assert_eq!(log.witness(h.w2.clone()).unwrap(), vec![h.r.id()]);
    assert!(log.contains(h.r.id()));
    assert!(!log.contains(h.w2.id()));
    assert_eq!(log.witnessed(h.w2.id()).map(Event::id), Some(h.w2.id()));
    assert_eq!(log.wanted(), Vec::<EventId>::new());
    // A witness is in no view and no chain, and is never a head.
    assert!(!log.canonical().contains(&h.w2.id()));
    assert!(log.chain(h.w2.author()).is_empty());
    assert!(!log.heads().contains(&h.w2.id()));
    // The heights resting on a witness are lower bounds.
    assert!(log.is_height_exact(h.u1.id()));
    assert!(!log.is_height_exact(h.r.id()));
    assert!(!log.is_height_exact(h.w2.id()));
    assert_eq!(log.height(h.w2.id()), Some(1));
    assert_eq!(log.height(h.r.id()), Some(2));
    // Witnessing again, or witnessing a placed event, changes nothing.
    assert_eq!(log.witness(h.w2.clone()).unwrap(), Vec::<EventId>::new());
    assert_eq!(log.witness(h.u1.clone()).unwrap(), Vec::<EventId>::new());
    assert_eq!(log.witnessed(h.u1.id()), None);
}

#[test]
fn proven_order_follows_witnesses_and_paths() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    log.place(h.u1.clone()).unwrap();
    log.witness(h.w2.clone()).unwrap();
    log.place(h.r.clone()).unwrap();
    // r is placed through w2, whose parent w1 the replica does not hold:
    // u1 is not proven before r, nor r before u1.
    assert!(log.proves_before(h.g.id(), h.r.id()));
    assert!(log.proves_before(h.w2.id(), h.r.id()));
    assert!(!log.proves_before(h.u1.id(), h.r.id()));
    assert!(!log.proves_before(h.r.id(), h.u1.id()));
    assert!(!log.proves_before(h.r.id(), h.r.id()));
    // A path that does not check changes nothing.
    let wrong = vec![h.w1.clone(), h.w2.clone()];
    assert_eq!(log.add_path(h.r.id(), h.u1.id(), wrong).unwrap(), None);
    assert_eq!(log.add_path(h.r.id(), h.u1.id(), Vec::new()).unwrap(), None);
    // From an event the replica does not hold, nothing checks.
    let path = vec![h.w1.clone()];
    assert_eq!(log.add_path(h.r.id(), h.g.id(), path).unwrap(), None);
    assert!(log.witnessed(h.w1.id()).is_none());
    ancestry_agrees(&log, &[h.w1.id(), h.w2.id()]);
    // A `Path` from r down to u1 checks: its events are witnessed, and u1
    // is proven before r.
    let path = vec![h.w2.clone(), h.w1.clone()];
    assert_eq!(
        log.add_path(h.r.id(), h.u1.id(), path).unwrap(),
        Some(Vec::new())
    );
    assert!(log.witnessed(h.w1.id()).is_some());
    assert!(log.proves_before(h.u1.id(), h.r.id()));
    assert!(log.proves_before(h.g.id(), h.w1.id()));
    // The log's order is proven order.
    assert!(log.precedes(h.u1.id(), h.r.id()));
    assert!(log.precedes(h.g.id(), h.r.id()));
    assert!(!log.precedes(h.r.id(), h.u1.id()));
    ancestry_agrees(&log, &[h.w1.id(), h.w2.id()]);
}

#[test]
fn witnesses_and_paths_of_another_log_are_refused() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    let other = genesis(&signer(9), b"another space");
    let stray = event(&signer(9), kind::UNIT, other.id(), 1, None, &[other.id()]);
    assert_eq!(log.witness(stray.clone()), Err(EventClass::WrongLog));
    // A path naming another log's event, which links up, is refused.
    let from = event(&signer(9), kind::UNIT, h.g.id(), 1, None, &[stray.id()]);
    log.witness(from.clone()).unwrap();
    assert_eq!(
        log.add_path(from.id(), other.id(), vec![stray]),
        Err(EventClass::WrongLog)
    );
}

#[test]
fn a_partial_replica_cites_units_whose_parents_are_witnessed() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    log.place(h.u1.clone()).unwrap();
    log.witness(h.w2.clone()).unwrap();
    // A's next unit in a held stream builds on B's witnessed unit.
    let v = event(&h.a, kind::UNIT, h.g.id(), 2, Some(h.u1.id()), &[h.w2.id()]);
    assert_eq!(
        log.place(v.clone()).unwrap(),
        Placement::Placed(vec![v.id()])
    );
    let citable = log.citable(|_| true);
    assert!(citable.contains(&v.id()));
    assert!(!citable.contains(&h.w2.id()));
    assert_eq!(log.heads_in(&citable), vec![v.id()]);
    assert!(log.is_closed(&citable));
}

#[test]
fn a_witnessed_event_placed_later_leaves_the_witnesses() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    log.place(h.u1.clone()).unwrap();
    log.witness(h.w1.clone()).unwrap();
    // The replica opens B's stream: w1 is placed, and stops being a witness.
    assert_eq!(
        log.place(h.w1.clone()).unwrap(),
        Placement::Placed(vec![h.w1.id()])
    );
    assert!(log.witnessed(h.w1.id()).is_none());
    assert_eq!(log.witnesses().count(), 0);
    assert!(log.contains(h.w1.id()));
    assert!(log.is_height_exact(h.w1.id()));
}

#[test]
fn without_witnesses_proven_order_is_causal_order() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    for e in [&h.u1, &h.w1, &h.w2, &h.r] {
        log.place(e.clone()).unwrap();
    }
    let ids = log.canonical();
    for &a in &ids {
        assert!(log.is_height_exact(a));
        for &b in &ids {
            assert_eq!(log.proves_before(a, b), log.precedes(a, b), "{a:?} {b:?}");
        }
    }
}

#[test]
fn a_path_checks_link_by_link() {
    let h = history();
    let path = [h.w2.clone(), h.w1.clone()];
    assert!(check_path(&path, &h.r, h.u1.id()));
    assert!(check_path(&path[..1], &h.r, h.w1.id()));
    assert!(!check_path(&path, &h.r, h.g.id()));
    assert!(!check_path(&[], &h.r, h.w2.id()));
    assert!(!check_path(std::slice::from_ref(&h.w1), &h.r, h.u1.id()));
    assert!(!check_path(&[h.w1.clone(), h.w2.clone()], &h.r, h.u1.id()));
}

/// units.md, "Partial replicas", "Heights": a height resting on a witness
/// whose parents the replica does not all hold is a lower bound, and it
/// learns the height by fetching those parents by ID.
#[test]
fn a_partial_replica_learns_a_height_by_fetching_the_witnesses_parents() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    log.place(h.u1.clone()).unwrap();
    log.witness(h.w2.clone()).unwrap();
    log.place(h.r.clone()).unwrap();
    // g 0, u1 1, w1 2, w2 3, r 4 at a full replica.
    assert_eq!(log.height(h.r.id()), Some(2));
    assert!(!log.is_height_exact(h.r.id()));
    assert_eq!(log.heights_wanted([h.r.id()]), vec![h.w1.id()]);
    assert_eq!(log.heights_wanted([h.u1.id()]), Vec::<EventId>::new());
    // w1's parent u1 is placed: every height is known now, and revised.
    log.witness(h.w1.clone()).unwrap();
    assert!(log.is_height_exact(h.w1.id()));
    assert!(log.is_height_exact(h.w2.id()));
    assert!(log.is_height_exact(h.r.id()));
    assert_eq!(log.height(h.w1.id()), Some(2));
    assert_eq!(log.height(h.w2.id()), Some(3));
    assert_eq!(log.height(h.r.id()), Some(4));
    assert_eq!(log.heights_wanted([h.r.id()]), Vec::<EventId>::new());
    assert_eq!(log.canonical(), vec![h.g.id(), h.u1.id(), h.r.id()]);
}

/// A `Path` witnesses its events child first; the heights resting on them
/// are revised as each parent arrives, so they never fall below a held
/// parent's, and canonical order extends proven order.
#[test]
fn heights_rise_as_witnessed_parents_arrive() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    log.place(h.u1.clone()).unwrap();
    log.witness(h.w2.clone()).unwrap();
    log.place(h.r.clone()).unwrap();
    let path = vec![h.w2.clone(), h.w1.clone()];
    log.add_path(h.r.id(), h.u1.id(), path).unwrap().unwrap();
    let held = [h.g.id(), h.u1.id(), h.w1.id(), h.w2.id(), h.r.id()];
    for &a in &held {
        for &b in &held {
            if log.precedes(a, b) {
                assert!(log.height(a) < log.height(b), "{a:?} {b:?}");
            }
        }
    }
    assert_eq!(log.proven_past(h.r.id()).len(), 4);
    // A full replica's log gives the same heights.
    let mut full = Log::new(h.g.clone()).unwrap();
    for e in [&h.u1, &h.w1, &h.w2, &h.r] {
        full.place(e.clone()).unwrap();
    }
    for &id in &held {
        assert_eq!(log.height(id), full.height(id), "{id:?}");
        assert!(log.is_height_exact(id));
    }
}

/// A stub stands for a parent with a signed height: a witness on it knows
/// its height.
#[test]
fn a_stub_gives_a_witness_its_height() {
    let h = history();
    let mut log = Log::new(h.g.clone()).unwrap();
    log.place(h.u1.clone()).unwrap();
    log.witness(h.w2.clone()).unwrap();
    log.place(h.r.clone()).unwrap();
    log.add_stub(frasil_events::Stub {
        id: h.w1.id(),
        author: *h.w1.author(),
        seq: h.w1.seq(),
        height: 2,
        kind: h.w1.kind(),
        cuts: frasil_events::Cuts::NONE,
    });
    assert!(log.is_height_exact(h.r.id()));
    assert_eq!(log.height(h.r.id()), Some(4));
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
