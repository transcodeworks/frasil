//! The agreement step and the seniority pick (roster.md, 3.7 The resolution
//! procedure, steps 3 and 4), over small hand-made logs.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use frasil_base::ErrorClass;
use frasil_resolve::{AGREEMENT_LIMIT, How, Resolve, Verdict, View, resolve};

frasil_base::error_classes! {
    /// The test log's classes.
    pub enum TestClass {
        /// The attack every attack here is.
        Attacked = "attacked", Final;
        /// An event its barring event, valid in its place, bars.
        Barred = "barred", Final;
    }
}

/// A log given as tables. Event `i` has ID `i`.
#[derive(Default)]
struct Table {
    parents: Vec<Vec<u32>>,
    attacks: BTreeSet<(u32, u32)>,
    /// Authority needs this event valid (`NotAnAdministrator`).
    needs: BTreeMap<u32, u32>,
    /// Authority fails if this event is valid (`Barred`).
    bars: BTreeMap<u32, u32>,
    /// Pick keys; the ID when absent.
    keys: BTreeMap<u32, u32>,
    /// How many times authority was asked.
    calls: Cell<u64>,
}

impl Table {
    /// `n` events with no parents.
    fn roots(n: u32) -> Self {
        Self {
            parents: vec![Vec::new(); n as usize],
            ..Self::default()
        }
    }

    fn attack(mut self, x: u32, e: u32) -> Self {
        self.attacks.insert((x, e));
        self
    }

    fn ids(&self) -> Vec<u32> {
        (0..self.parents.len() as u32).collect()
    }
}

impl Resolve for Table {
    type Id = u32;
    type Class = TestClass;
    type PickKey = (u32, u32);

    fn height(&self, event: u32) -> u64 {
        self.parents[event as usize]
            .iter()
            .map(|&p| self.height(p) + 1)
            .max()
            .unwrap_or(0)
    }

    fn precedes(&self, earlier: u32, later: u32) -> bool {
        self.parents[later as usize]
            .iter()
            .any(|&p| p == earlier || self.precedes(earlier, p))
    }

    fn check(&self, _event: u32) -> Result<(), TestClass> {
        Ok(())
    }

    fn forked(&self, _event: u32) -> Option<TestClass> {
        None
    }

    fn self_lowering(&self, _event: u32) -> bool {
        false
    }

    fn authority(&self, event: u32, view: &View<'_, Self>) -> Result<(), TestClass> {
        self.calls.set(self.calls.get() + 1);
        if self.needs.get(&event).is_some_and(|&p| !view.is_valid(p)) {
            return Err(ErrorClass::NotAnAdministrator.into());
        }
        if self.bars.get(&event).is_some_and(|&p| view.is_valid(p)) {
            return Err(TestClass::Barred);
        }
        Ok(())
    }

    fn attack(&self, attacker: u32, event: u32) -> Option<TestClass> {
        self.attacks
            .contains(&(attacker, event))
            .then_some(TestClass::Attacked)
    }

    fn pick_key(&self, event: u32, _view: &View<'_, Self>) -> (u32, u32) {
        (self.keys.get(&event).copied().unwrap_or(event), event)
    }
}

const SENIORITY: Verdict<u32, TestClass> = Verdict::Valid(How::Seniority);
const RULES: Verdict<u32, TestClass> = Verdict::Valid(How::Rules);

fn by(x: u32) -> Verdict<u32, TestClass> {
    Verdict::Void {
        class: TestClass::Attacked,
        by: Some(x),
    }
}

/// A cycle of attacks among `len` concurrent events, 0 attacking 1 and so
/// on, the last attacking 0.
fn cycle(len: u32, extra: u32) -> Table {
    let mut table = Table::roots(len + extra);
    for i in 0..len {
        table = table.attack(i, (i + 1) % len);
    }
    table
}

/// After the most senior event of an odd cycle is picked, the cycle settles
/// by the rules from it.
fn assert_settled_from_zero(table: &Table, len: u32) {
    let r = resolve(table, table.ids());
    assert_eq!(r.verdict(0), Some(&SENIORITY));
    for i in 1..len {
        let want = if i % 2 == 1 { by(i - 1) } else { RULES };
        assert_eq!(r.verdict(i), Some(&want), "event {i}");
    }
}

#[test]
fn the_limit_is_sixteen() {
    assert_eq!(AGREEMENT_LIMIT, 16);
}

/// Sixteen undecided events, none of whose assignments is allowed: the
/// agreement step tries all 2^16, and then the pick decides.
#[test]
fn sixteen_undecided_try_every_assignment() {
    let table = cycle(15, 1).attack(0, 15);
    assert_settled_from_zero(&table, 15);
    assert_eq!(resolve(&table, table.ids()).verdict(15), Some(&by(0)));
    assert!(table.calls.get() >= 1 << 16, "{} calls", table.calls.get());
}

/// Seventeen undecided events: above the limit, the pick decides directly
/// and no assignment is tried.
#[test]
fn seventeen_undecided_go_straight_to_the_pick() {
    let table = cycle(17, 0);
    assert_settled_from_zero(&table, 17);
    assert!(table.calls.get() < 1_000, "{} calls", table.calls.get());
}

/// Two events that attack each other, and a third both attack: it is void
/// in each allowed assignment, so the agreement step voids it, and the event
/// it attacks is valid in each, so the step makes that one valid. The pick
/// then settles the pair. The void event keeps its reason in the first
/// allowed assignment, the one that makes 0 void: the attack by 1, though
/// the pick makes 0 valid and 1 void.
#[test]
fn what_every_allowed_assignment_agrees_on() {
    let table = Table::roots(4)
        .attack(0, 1)
        .attack(1, 0)
        .attack(0, 2)
        .attack(1, 2)
        .attack(2, 3);
    let r = resolve(&table, table.ids());
    assert_eq!(r.verdict(0), Some(&SENIORITY));
    assert_eq!(r.verdict(1), Some(&by(0)));
    assert_eq!(r.verdict(2), Some(&by(1)));
    assert_eq!(r.verdict(3), Some(&Verdict::Valid(How::Agreed)));
}

/// An event voided by agreement keeps the reason of the first allowed
/// assignment, though the final statuses give it none.
///
/// Events 0 and 1 have no parents, 2 follows 1 and 3 follows 0, 1 and 2.
/// 0 and 2 attack each other and 0 attacks 1; 2 needs 1 valid; 3 needs 1
/// valid and is barred by 2. The pick prefers 1, then 0, then 2.
///
/// The agreement step allows {0} and {1, 2}; 3 is void in both. The pick
/// then makes 1 valid and, a round later, 0, which voids 2. At the end 3's
/// authority holds and nothing attacks it. It stays void with the reason it
/// has in the first allowed assignment, {1, 2}: barred by 2 (roster.md,
/// 3.7 The resolution procedure).
#[test]
fn an_agreed_void_event_the_end_leaves_without_a_reason() {
    let mut table = Table::roots(4).attack(0, 2).attack(2, 0).attack(0, 1);
    table.parents[2] = vec![1];
    table.parents[3] = vec![0, 2];
    table.needs = BTreeMap::from([(2, 1), (3, 1)]);
    table.bars = BTreeMap::from([(3, 2)]);
    table.keys = BTreeMap::from([(1, 0), (0, 1), (2, 2), (3, 3)]);
    let r = resolve(&table, table.ids());
    assert_eq!(r.verdict(1), Some(&SENIORITY));
    assert_eq!(r.verdict(0), Some(&SENIORITY));
    assert_eq!(r.verdict(2), Some(&by(0)));
    assert_eq!(
        r.verdict(3),
        Some(&Verdict::Void {
            class: TestClass::Barred,
            by: None
        })
    );
}

/// The pick is the smallest key among the undecided events whose contested
/// past is decided, whatever order the events arrive in.
#[test]
fn the_pick_follows_the_key() {
    for first in 0..3 {
        let mut table = cycle(3, 0);
        table.keys = BTreeMap::from([(first, 0), ((first + 1) % 3, 1), ((first + 2) % 3, 2)]);
        for ids in [vec![0, 1, 2], vec![2, 1, 0], vec![1, 2, 0, 1]] {
            let r = resolve(&table, ids);
            assert_eq!(r.verdict(first), Some(&SENIORITY));
            assert_eq!(r.verdict((first + 1) % 3), Some(&by(first)));
            assert_eq!(r.verdict((first + 2) % 3), Some(&RULES));
        }
    }
}
