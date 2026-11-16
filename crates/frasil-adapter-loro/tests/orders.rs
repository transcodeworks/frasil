//! Order independence (units.md, section 3.17, "The adapter interface",
//! `apply`; adapter-loro.md, section 3.3): a stream's units, carrying real
//! Loro bytes, handed over in any order, any number of times each, give one
//! document, one suggestion layer and one set of content refusals; and a
//! snapshot of any causal cut, with the units it excludes and the units
//! after it, rebuilds to the same document.

mod support;

use frasil_adapter::{Adapter, Capabilities, Capability, Mode, SUGGEST, StreamUnit};
use frasil_adapter_loro::{Content, Loro, LoroClass, State};
use proptest::prelude::*;
use std::sync::OnceLock;
use support::{Replica, event, unit, unit_with};

fn suggester() -> Capabilities {
    Capabilities::new([Capability::new(SUGGEST, Mode::Narrows)])
}

/// Twelve units of four writers and a suggester: edits that continue an
/// incarnation, concurrent edits, two suggestions, an accept and a dismiss,
/// a unit the write rule refuses and an edit built on it, a restored
/// device's unit that reuses counters, and an accept of a unit never held.
fn units() -> &'static [StreamUnit] {
    static UNITS: OnceLock<Vec<StreamUnit>> = OnceLock::new();
    UNITS.get_or_init(|| {
        let mut alice = Replica::new(1, 1);
        let t = alice.doc().get_text("t");
        t.insert(0, "hello").unwrap();
        alice.doc().get_map("m").insert("k", 1).unwrap();
        let a1 = unit(1, 1, 1, &alice.edit_unit());
        let mut bob = Replica::from_doc(alice.doc(), 2, 1);
        t.insert(5, " world").unwrap();
        let a2 = unit(2, 1, 2, &alice.edit_unit());
        t.insert(0, "[").unwrap();
        let a3 = unit(3, 1, 3, &alice.edit_unit());

        bob.doc().get_text("t").insert(0, "> ").unwrap();
        bob.doc().get_map("m").insert("k", 2).unwrap();
        let b1 = unit(4, 2, 1, &bob.edit_unit());

        let mut fork = Replica::from_doc(alice.doc(), 3, 4);
        fork.doc().get_text("t").insert(1, "oh, ").unwrap();
        let s1 = unit_with(5, 3, 4, &fork.suggestion_unit(), suggester(), true);
        let mut fork = Replica::from_doc(alice.doc(), 3, 5);
        fork.doc().get_map("m").insert("s", "x").unwrap();
        let s2 = unit_with(6, 3, 5, &fork.suggestion_unit(), suggester(), true);
        let accept = unit(7, 1, 4, &Content::accept([event(5)]));
        let dismiss = unit(8, 2, 2, &Content::dismiss([event(5), event(6)]));

        let mut removed = Replica::new(4, 1);
        removed.doc().get_text("r").insert(0, "removed").unwrap();
        let r = removed.edit_unit();
        let Content::Ops { blob, .. } = &r else {
            unreachable!()
        };
        let refused = unit_with(9, 4, 1, &r, Capabilities::none(), false);
        bob.import(blob).unwrap();
        bob.doc().get_text("r").insert(7, "!").unwrap();
        let built_on_refused = unit(10, 2, 3, &bob.edit_unit());

        let mut restored = Replica::new(1, 1);
        restored.doc().get_text("t").insert(0, "lost").unwrap();
        let reused = unit(11, 1, 5, &restored.edit_unit());
        let never_held = unit(12, 2, 4, &Content::accept([[0xff; 32]]));
        vec![
            a1,
            a2,
            a3,
            b1,
            s1,
            s2,
            accept,
            dismiss,
            refused,
            built_on_refused,
            reused,
            never_held,
        ]
    })
}

fn reference() -> &'static State {
    static STATE: OnceLock<State> = OnceLock::new();
    STATE.get_or_init(|| Loro::new().rebuild(None, units()).unwrap())
}

#[test]
fn the_reference_state() {
    let loro = Loro::new();
    let state = reference();
    let doc = state.doc().fork();
    assert_eq!(doc.get_text("t").to_string(), "[oh, > hello world");
    assert_eq!(state.accepted(), vec![event(5)]);
    assert_eq!(state.dismissed(), vec![event(6)]);
    assert!(state.open().is_empty());
    assert_eq!(state.refused(), vec![(event(11), LoroClass::LoroOverlap)]);
    assert_eq!(
        loro.held(state),
        vec![
            (event(10), LoroClass::LoroDependsOnRefused),
            (event(12), LoroClass::TargetNotHeld)
        ]
    );
}

/// The first `cut` units of an order, with every earlier unit of each
/// writer moved in from later, and the rest: a cover is a causal past, so
/// it holds a writer's units below each it holds.
fn causal_cut(units: &[StreamUnit], cut: usize) -> (Vec<StreamUnit>, Vec<StreamUnit>) {
    let (head, tail) = units.split_at(cut);
    let below = |unit: &StreamUnit| {
        head.iter().any(|kept| {
            kept.context.author == unit.context.author && kept.context.seq > unit.context.seq
        })
    };
    let (moved, rest): (Vec<StreamUnit>, Vec<StreamUnit>) =
        tail.iter().cloned().partition(|unit| below(unit));
    ([head.to_vec(), moved].concat(), rest)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn units_in_any_order_give_one_document(
        order in Just((0..12).collect::<Vec<usize>>()).prop_shuffle(),
        repeats in proptest::collection::vec(0..12usize, 0..6),
        cut in 0..=12usize,
    ) {
        let loro = Loro::new();
        let all = units();
        let expected = reference();
        let mut sequence: Vec<StreamUnit> = order.iter().map(|i| all[*i].clone()).collect();
        sequence.extend(repeats.iter().map(|i| all[*i].clone()));
        let state = loro.rebuild(None, &sequence).unwrap();
        prop_assert!(state.matches(expected));
        prop_assert_eq!(state.refused(), expected.refused());
        prop_assert_eq!(loro.held(&state), loro.held(expected));
        prop_assert_eq!(state.accepted(), expected.accepted());

        // A snapshot of a causal cut, then the units of the cover it does
        // not include and the units after it (units.md, section 3.6,
        // "Using").
        let in_order: Vec<StreamUnit> = order.iter().map(|i| all[*i].clone()).collect();
        let (head, tail) = causal_cut(&in_order, cut);
        let compaction = loro.compact(&loro.rebuild(None, &head).unwrap());
        let mut after: Vec<StreamUnit> = head
            .iter()
            .filter(|unit| !compaction.included.contains(&unit.context.event_id))
            .cloned()
            .collect();
        after.extend(tail);
        // The replica holds the cover's units for step 7.
        let mut rebuilt = loro.load(&compaction.state).unwrap();
        rebuilt.hold(head.iter().map(|unit| unit.context.event_id));
        for unit in &after {
            loro.receive(&mut rebuilt, unit);
        }
        prop_assert!(rebuilt.matches(expected));
    }
}
