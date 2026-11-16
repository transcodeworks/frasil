//! A newcomer's base (units.md, "A base"; "The space snapshot"): its stubs
//! stand confirmed on the sender's signature, the newcomer stops at them,
//! and what it later holds is checked against them.

use super::*;
use frasil_crypto::schemes::{Scheme, Signer};

fn signer(n: u8) -> Signer {
    Signer::from_seeds(&[n; 32], &[n.wrapping_add(50); 32], None)
}

fn signed(
    signer: &Signer,
    kind: u8,
    log: Option<EventId>,
    seq: u64,
    prev: Option<EventId>,
    body: &[u8],
) -> Event {
    let envelope = frasil_events::Envelope {
        kind,
        log,
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq,
        prev,
        parents: prev.into_iter().collect(),
        cuts: Vec::new(),
        body: body.to_vec(),
        scheme: if kind == kind::UNIT {
            Scheme::Ed25519
        } else {
            Scheme::Hybrid
        },
    };
    frasil_events::decode(&envelope.sign(signer)).unwrap()
}

/// A genesis, a unit after it, and the unit's honest stub.
fn scene() -> (Event, Event, UnitStub) {
    let founder = signer(1);
    let genesis = signed(&founder, kind::SPACE, None, 1, None, b"genesis");
    let unit = signed(
        &founder,
        kind::UNIT,
        Some(genesis.id()),
        2,
        Some(genesis.id()),
        b"unit",
    );
    let stub = UnitStub {
        id: unit.id(),
        author: *unit.author(),
        seq: 2,
        height: 2,
        kind: kind::UNIT,
        stream: Some([7; 16]),
        cuts: frasil_events::Cuts::NONE,
    };
    (genesis, unit, stub)
}

#[test]
fn a_base_stub_stands_confirmed_and_its_unit_is_not_placed() {
    let (genesis, unit, stub) = scene();
    let mut replica = Replica::new(genesis.id());
    replica.set_base(vec![unit.id()], vec![stub]);
    replica.place(vec![genesis]);
    let log = replica.log().expect("the genesis starts the log");
    assert!(log.is_stub_confirmed(unit.id()), "confirmed on the base");
    assert!(!replica.wanted().contains(&unit.id()), "never asked for");
    // The unit itself, arriving, is decided: kept as its stub, and it
    // matches.
    replica.place(vec![unit.clone()]);
    let log = replica.log().unwrap();
    assert!(!log.contains(unit.id()));
    assert!(log.is_stub_confirmed(unit.id()));
    assert!(replica.contradicted_base().is_empty());
}

#[test]
fn a_unit_that_contradicts_its_base_stub_is_reported() {
    let (genesis, unit, stub) = scene();
    let lying = UnitStub { seq: 7, ..stub };
    let mut replica = Replica::new(genesis.id());
    replica.set_base(vec![unit.id()], vec![lying]);
    replica.place(vec![genesis, unit.clone()]);
    assert!(replica.contradicted_base().contains(&unit.id()));
    // The base stands: the newcomer cannot compute a height below it.
    let log = replica.log().unwrap();
    assert!(!log.contains(unit.id()));
    assert_eq!(log.stub(unit.id()).map(|s| s.seq), Some(7));
}

#[test]
fn another_signers_stub_that_disagrees_with_a_base_stub_is_reported() {
    let (genesis, unit, stub) = scene();
    let mut replica = Replica::new(genesis.id());
    replica.set_base(vec![unit.id()], vec![stub]);
    replica.place(vec![genesis]);
    let other = UnitStub { height: 40, ..stub };
    replica.carried_stubs = vec![(DeviceId([9; 32]), other)];
    replica.add_carried_stubs();
    assert!(replica.contradicted_base().contains(&unit.id()));
    let log = replica.log().unwrap();
    assert_eq!(log.stub(unit.id()).map(|s| s.height), Some(2));
    assert!(log.is_stub_confirmed(unit.id()));
}
