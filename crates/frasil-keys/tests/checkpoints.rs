//! keys.md, "Keys after a checkpoint": a heal after a checkpoint, a "with
//! history" grant after one, and a replica that forgot the past reaching
//! the same key graph as one that kept everything.
//!
//! The histories here are small models: events with parents, rotations,
//! the wraps and links each carries, and the state each event that does not
//! rotate is sealed under. What a set of devices derives and the heal test
//! follow keys.md, "Healing", over the artifacts that
//! [`counts_artifact`] counts.

use frasil_events::EventId;
use frasil_keys::RotationSet;
use frasil_keys::checkpoint::{
    KeptState, MemberAfter, Rooted, SealPlace, Side, Sides, counts_artifact, entitled_before,
    gate_breaks, plan_forgetting, provisional, seal_against_checkpoint, tries, world_state,
};
use frasil_keys::links::LinkKind;
use frasil_keys::names::KeyName;
use std::collections::{BTreeMap, BTreeSet};

type Device = &'static str;

fn id(n: u8) -> EventId {
    EventId([n; 32])
}

fn set(ids: &[EventId]) -> RotationSet {
    RotationSet::new(ids.iter().copied()).unwrap()
}

fn one(r: EventId) -> RotationSet {
    RotationSet::single(r)
}

/// One event of a model history.
#[derive(Debug, Clone, Default)]
struct Ev {
    parents: Vec<EventId>,
    author: Device,
    rotation: bool,
    is_break: bool,
    sealed_under: Option<RotationSet>,
    wraps: Vec<(Device, RotationSet)>,
    links: Vec<(RotationSet, RotationSet)>,
}

impl Ev {
    fn by(author: Device, parents: &[EventId]) -> Self {
        Self {
            author,
            parents: parents.to_vec(),
            ..Self::default()
        }
    }

    fn rotates(mut self) -> Self {
        self.rotation = true;
        self
    }

    fn breaks(mut self) -> Self {
        self.rotation = true;
        self.is_break = true;
        self
    }

    fn sealed(mut self, state: RotationSet) -> Self {
        self.sealed_under = Some(state);
        self
    }

    fn wrap(mut self, devices: &[Device], state: RotationSet) -> Self {
        for d in devices {
            self.wraps.push((d, state.clone()));
        }
        self
    }

    fn link(mut self, under: RotationSet, reaches: RotationSet) -> Self {
        self.links.push((under, reaches));
        self
    }
}

/// A model history: the events a replica holds.
#[derive(Debug, Clone, Default)]
struct Model {
    events: BTreeMap<EventId, Ev>,
}

impl Model {
    fn add(&mut self, id: EventId, ev: Ev) -> EventId {
        self.events.insert(id, ev);
        id
    }

    /// `a` is in `b`'s past, through parents the model holds.
    fn precedes(&self, a: &EventId, b: &EventId) -> bool {
        let mut stack: Vec<EventId> = self.events[b].parents.clone();
        let mut seen = BTreeSet::new();
        while let Some(x) = stack.pop() {
            if x == *a {
                return true;
            }
            if seen.insert(x)
                && let Some(ev) = self.events.get(&x)
            {
                stack.extend(ev.parents.iter().copied());
            }
        }
        false
    }

    /// The sides of the events held against checkpoint `c`; an honest
    /// event's cuts reach `c` exactly when `c` is in its past.
    fn sides(&self, c: EventId) -> Sides {
        Sides::classify(
            c,
            self.events.keys().copied(),
            |e| self.precedes(&c, e),
            |a, b| self.precedes(a, b),
        )
    }

    /// A replica that forgot: the world's events only, the checkpoint's
    /// parents gone.
    fn forget(&self, sides: &Sides) -> Self {
        let mut out = Self::default();
        for (&id, ev) in &self.events {
            if sides.side(&id).in_world() {
                let mut ev = ev.clone();
                ev.parents.retain(|p| sides.side(p).in_world());
                out.events.insert(id, ev);
            }
        }
        out
    }

    fn counted<'a>(&'a self, sides: &'a Sides) -> impl Iterator<Item = (&'a EventId, &'a Ev)> {
        self.events
            .iter()
            .filter(|(id, _)| counts_artifact(sides.side(id)))
    }

    /// What a set of devices derives from the counted artifacts (keys.md,
    /// "Healing"), with `named` the merged states named in the view.
    fn derives(
        &self,
        sides: &Sides,
        devices: &BTreeSet<Device>,
        named: &[RotationSet],
    ) -> BTreeSet<RotationSet> {
        let mut held = BTreeSet::new();
        let mut links = Vec::new();
        let mut merged: Vec<RotationSet> = named.iter().filter(|s| s.len() > 1).cloned().collect();
        for (&id, ev) in self.counted(sides) {
            if ev.rotation && devices.contains(ev.author) {
                held.insert(one(id));
            }
            for (d, state) in &ev.wraps {
                if devices.contains(d) {
                    held.insert(state.clone());
                }
                if state.len() > 1 {
                    merged.push(state.clone());
                }
            }
            links.extend(ev.links.iter().cloned());
        }
        loop {
            let before = held.len();
            for (under, reaches) in &links {
                if held.contains(under) {
                    held.insert(reaches.clone());
                }
            }
            for state in &merged {
                if state.ids().iter().all(|r| held.contains(&one(*r))) {
                    held.insert(state.clone());
                }
            }
            if held.len() == before {
                return held;
            }
        }
    }

    /// Every device a counted wrap was made for, and every counted
    /// rotation's author.
    fn holders(&self, sides: &Sides) -> BTreeSet<Device> {
        let mut out = BTreeSet::new();
        for (_, ev) in self.counted(sides) {
            if ev.rotation {
                out.insert(ev.author);
            }
            out.extend(ev.wraps.iter().map(|(d, _)| *d));
        }
        out
    }

    /// The valid rotations among the events held, `void` left out.
    fn rotations(&self, void: &[EventId]) -> Vec<EventId> {
        self.events
            .iter()
            .filter(|(id, ev)| ev.rotation && !void.contains(id))
            .map(|(id, _)| *id)
            .collect()
    }

    fn current(&self, sides: &Sides, void: &[EventId]) -> RotationSet {
        world_state(sides, self.rotations(void), |a, b| self.precedes(a, b)).unwrap()
    }

    /// keys.md's heal test over the world: the holders outside `inside`
    /// derive the current state, or no inside device does.
    fn heal_fires(&self, sides: &Sides, void: &[EventId], inside: &[Device]) -> bool {
        let current = self.current(sides, void);
        let inside: BTreeSet<Device> = inside.iter().copied().collect();
        let outside: BTreeSet<Device> = self.holders(sides).difference(&inside).copied().collect();
        let named = [current.clone()];
        self.derives(sides, &outside, &named).contains(&current)
            || !self.derives(sides, &inside, &named).contains(&current)
    }
}

/// A heal after a checkpoint: C, a member of the record, leaves by a
/// self-removal after the checkpoint, which does not rotate. C holds the
/// checkpoint's key, the current state of the world, so the heal test
/// fires; B heals, and C derives nothing of the heal.
#[test]
fn a_heal_after_a_checkpoint() {
    let mut m = Model::default();
    let g = m.add(id(1), Ev::by("A", &[]).rotates().wrap(&["A"], one(id(1))));
    let r1 = m.add(
        id(2),
        Ev::by("A", &[g])
            .rotates()
            .wrap(&["A", "B", "C"], one(id(2)))
            .link(one(id(2)), one(g)),
    );
    let c = m.add(
        id(3),
        Ev::by("A", &[r1])
            .rotates()
            .wrap(&["A", "B", "C"], one(id(3)))
            .link(one(id(3)), one(r1)),
    );
    // C leaves after the checkpoint; the event does not rotate.
    let leave = m.add(id(4), Ev::by("C", &[c]).sealed(one(c)));
    let sides = m.sides(c);
    assert_eq!(sides.side(&leave), Side::After);
    assert_eq!(m.current(&sides, &[]), one(c));
    assert!(m.heal_fires(&sides, &[], &["A", "B"]));
    // A replica that forgot the past fires too.
    let forgot = m.forget(&sides);
    let forgot_sides = sides.forgetting(|_| false);
    assert!(forgot.heal_fires(&forgot_sides, &[], &["A", "B"]));

    // B heals: a rotation after the leave, linking back to the checkpoint.
    let h = m.add(
        id(5),
        Ev::by("B", &[leave])
            .rotates()
            .wrap(&["A", "B"], one(id(5)))
            .link(one(id(5)), one(c)),
    );
    let sides = m.sides(c);
    assert_eq!(m.current(&sides, &[]), one(h));
    assert!(!m.heal_fires(&sides, &[], &["A", "B"]));
    // C still holds the checkpoint's key, never the heal's.
    let c_holds = m.derives(&sides, &BTreeSet::from(["C"]), &[]);
    assert!(c_holds.contains(&one(c)) && !c_holds.contains(&one(h)));
    let forgot = m.forget(&sides);
    assert!(!forgot.heal_fires(&sides.forgetting(|_| false), &[], &["A", "B"]));

    // The same history with no checkpoint in effect: the heal test of the
    // whole view gives the same answers, rooted at the genesis.
    let genesis = m.sides(g);
    assert_eq!(m.current(&genesis, &[]), one(h));
    assert!(!m.heal_fires(&genesis, &[], &["A", "B"]));
}

/// An invite key in the record, claimed after the checkpoint, is outside
/// once its successor is valid, and a writer heals; a claim concurrent
/// with the checkpoint is late, leaves the key inside, and the claimant
/// claims again after it.
#[cfg(feature = "ext-invite-links")]
#[test]
fn a_claim_after_a_checkpoint_calls_for_a_heal() {
    use frasil_keys::ext_invite_links::{InvitePast, Successor, record_invite_inside};

    let mut m = Model::default();
    let g = m.add(
        id(1),
        Ev::by("A", &[]).rotates().wrap(&["A", "B"], one(id(1))),
    );
    // The invite grant delivers the current state to K.
    let invite = m.add(id(2), Ev::by("A", &[g]).sealed(one(g)).wrap(&["K"], one(g)));
    let c = m.add(
        id(3),
        Ev::by("A", &[invite])
            .rotates()
            .wrap(&["A", "B", "K"], one(id(3)))
            .link(one(id(3)), one(g)),
    );
    // A claim concurrent with the checkpoint: late.
    let late = m.add(
        id(4),
        Ev::by("K", &[invite]).sealed(one(g)).wrap(&["D"], one(g)),
    );
    let sides = m.sides(c);
    assert_eq!(sides.side(&late), Side::Late);
    let late_claim = Successor {
        side: sides.side(&late),
        valid: false,
        raced: false,
    };
    let inside_k = record_invite_inside(InvitePast::Unclaimed, [late_claim], false);
    assert!(inside_k);
    assert!(!m.heal_fires(&sides, &[late], &["A", "B", "K"]));

    // The claim again, after the checkpoint.
    let claim = m.add(id(5), Ev::by("K", &[c]).sealed(one(c)).wrap(&["D"], one(c)));
    let sides = m.sides(c);
    let claim = Successor {
        side: sides.side(&claim),
        valid: true,
        raced: false,
    };
    assert!(!record_invite_inside(
        InvitePast::Unclaimed,
        [late_claim, claim],
        false
    ));
    assert!(m.heal_fires(&sides, &[late], &["A", "B", "D"]));

    // The same invite with a claim in the checkpoint's past is out of the
    // world, whatever the world holds, and so it is at a replica that
    // started from the checkpoint and cannot tell.
    assert!(!record_invite_inside(InvitePast::Claimed, [], false));
    assert!(!record_invite_inside(InvitePast::Unknown, [], false));
}

/// A "with history" grant after a checkpoint entitles its member to every
/// state before it, and to no late state; its member's device tries a
/// delivery of a state before the checkpoint it never held, and takes the
/// key as provisional.
#[test]
fn a_with_history_grant_after_a_checkpoint() {
    let mut m = Model::default();
    let g = m.add(id(1), Ev::by("A", &[]).rotates());
    let r1 = m.add(id(2), Ev::by("B", &[g]).rotates());
    let c = m.add(id(3), Ev::by("A", &[r1]).rotates());
    let late = m.add(id(4), Ev::by("C", &[r1]).rotates());
    // A grants N "with history" after the checkpoint, and delivers it the
    // states before the checkpoint that the units it keeps are sealed
    // under, as gap keys.
    let grant = m.add(
        id(5),
        Ev::by("A", &[c])
            .sealed(one(c))
            .wrap(&["N"], one(c))
            .wrap(&["N"], one(r1)),
    );
    let sides = m.sides(c);
    let with_history = MemberAfter {
        with_history_after: true,
        in_from_record: false,
        floor: false,
    };
    for state in [one(g), one(r1), set(&[g, r1])] {
        assert_eq!(
            entitled_before(&sides, &state, &"N", with_history, None),
            Some(true)
        );
        // Without the grant, or as a space principal whose notice is no
        // grant here, it is not.
        assert_eq!(
            entitled_before(&sides, &state, &"N", MemberAfter::default(), None),
            Some(false)
        );
    }
    // A late rotation does not precede the grant.
    assert_eq!(
        entitled_before(&sides, &one(late), &"N", with_history, None),
        Some(false)
    );
    assert_eq!(
        entitled_before(&sides, &set(&[r1, late]), &"N", with_history, None),
        Some(false)
    );
    // States of the world are the world's question.
    assert_eq!(
        entitled_before(&sides, &one(c), &"N", with_history, None),
        None
    );
    assert_eq!(
        entitled_before(&sides, &set(&[r1, c]), &"N", with_history, None),
        None
    );

    // N started from the checkpoint: it holds the checkpoint and what
    // follows, and knows nothing before it.
    let mut newcomer = Sides::new(c);
    newcomer.insert(grant, Side::After);
    let held = |e: &EventId| *e == c || *e == grant;
    let r1_name = KeyName::Set(one(r1));
    let entitled = |name: &KeyName| match name.as_set() {
        Some(state) => entitled_before(&newcomer, state, &"N", with_history, None) == Some(true),
        None => true,
    };
    let not_fetchable = |_: &EventId| false;
    assert!(tries(
        &newcomer,
        &grant,
        &[&r1_name],
        held,
        not_fetchable,
        |_| false,
        entitled
    ));
    // A rotation it can still fetch is waited for, and a delivery of an
    // event before the checkpoint is never tried so.
    assert!(!tries(
        &newcomer,
        &grant,
        &[&r1_name],
        held,
        |_| true,
        |_| false,
        entitled
    ));
    assert!(!tries(
        &newcomer,
        &r1,
        &[&r1_name],
        held,
        not_fetchable,
        |_| false,
        entitled
    ));
    assert!(provisional(&one(r1), held));
    assert!(!provisional(&one(c), held));
    // A replica that noted the rotation late never tries for it, and its
    // member is not entitled to it.
    let mut noted = newcomer.clone();
    noted.insert(late, Side::Late);
    let late_name = KeyName::Set(one(late));
    assert!(!tries(
        &noted,
        &grant,
        &[&late_name],
        held,
        not_fetchable,
        |_| false,
        |_| true
    ));
    assert_eq!(
        entitled_before(&noted, &one(late), &"N", with_history, None),
        Some(false)
    );
    // Nor for a state it holds already.
    assert!(!tries(
        &newcomer,
        &grant,
        &[&r1_name],
        held,
        not_fetchable,
        |_| true,
        entitled
    ));
}

/// A replica that forgot the past reaches the same key graph of the world
/// as one that kept everything: the current state, the `StaleSeal` reading,
/// the breaks the link gate counts, the heal test, and entitlement to the
/// states before the checkpoint it kept.
#[test]
fn a_replica_that_forgot_reaches_the_same_key_graph() {
    let mut m = Model::default();
    let g = m.add(id(1), Ev::by("A", &[]).rotates().wrap(&["A"], one(id(1))));
    let r1 = m.add(
        id(2),
        Ev::by("B", &[g])
            .rotates()
            .wrap(&["A", "B", "R"], one(id(2)))
            .link(one(id(2)), one(g)),
    );
    // A admits M "from now on": a break.
    let b = m.add(
        id(3),
        Ev::by("A", &[r1])
            .breaks()
            .wrap(&["A", "B", "M"], one(id(3))),
    );
    // B removes R and rotates.
    let r2 = m.add(
        id(4),
        Ev::by("B", &[b])
            .rotates()
            .wrap(&["A", "B", "M", "C"], one(id(4)))
            .link(one(id(4)), one(b)),
    );
    // A unit before the checkpoint, kept under compaction.
    let kept_unit = m.add(id(5), Ev::by("B", &[r2]).sealed(one(r2)));
    let c = m.add(
        id(6),
        Ev::by("A", &[kept_unit])
            .rotates()
            .wrap(&["A", "B", "M", "C"], one(id(6)))
            .link(one(id(6)), one(r2)),
    );
    // C rotates concurrently with the checkpoint: late, so void.
    let late = m.add(id(7), Ev::by("C", &[r2]).rotates().wrap(&["C"], one(id(7))));
    // After the checkpoint: B removes C (a rotation), A admits P "from now
    // on" (a break), concurrently.
    let a1 = m.add(
        id(8),
        Ev::by("B", &[c])
            .rotates()
            .wrap(&["A", "B", "M"], one(id(8)))
            .link(one(id(8)), one(c)),
    );
    let a2 = m.add(
        id(9),
        Ev::by("A", &[c])
            .breaks()
            .wrap(&["A", "B", "M", "P"], one(id(9))),
    );
    let unit = m.add(id(10), Ev::by("B", &[a1]).sealed(one(a1)));
    let stale_before = m.add(id(11), Ev::by("A", &[a2]).sealed(one(r2)));
    let stale_concurrent = m.add(id(12), Ev::by("B", &[a1]).sealed(one(a2)));
    let fresh = m.add(id(13), Ev::by("B", &[a1]).sealed(one(c)));
    let void = [late];

    let full = m.sides(c);
    assert_eq!(full.side(&late), Side::Late);
    assert_eq!(full.side(&r2), Side::Before);
    assert_eq!(full.side(&a2), Side::After);

    // What the replica that kept everything keeps when it forgets: the key
    // of the state its kept unit is sealed under, with who is entitled to
    // it, and the grant seed of the genesis that a granting space noticed.
    let entitled_to_r2: BTreeSet<Device> = BTreeSet::from(["A", "B", "C", "M"]);
    let plan = plan_forgetting(
        &full,
        [one(r2), one(a1), one(c)],
        [g],
        |_, _| true,
        |_, state: &RotationSet| {
            assert_eq!(*state, one(r2));
            (entitled_to_r2.clone(), BTreeSet::new())
        },
    );
    assert_eq!(plan.missing, Vec::new());
    assert_eq!(plan.grant_rotations, vec![g]);
    assert_eq!(plan.keep.len(), 1);
    let kept: &KeptState<Device> = &plan.keep[0];
    assert_eq!((kept.kind, &kept.state), (LinkKind::Content, &one(r2)));

    let noted: BTreeSet<EventId> = plan
        .keep
        .iter()
        .flat_map(|k| k.state.ids().to_vec())
        .collect();
    let forgot_sides = full.forgetting(|id| noted.contains(id));
    let forgot = m.forget(&full);
    assert_eq!(forgot_sides.world(), full.world());
    assert_eq!(forgot_sides.side(&r2), Side::Before);
    assert_eq!(forgot_sides.side(&late), Side::Unknown);

    // The current state of the world.
    let current = m.current(&full, &void);
    assert_eq!(current, set(&[a1, a2]));
    assert_eq!(forgot.current(&forgot_sides, &void), current);

    // StaleSeal: sealed under a state before the checkpoint, or under a
    // rotation of the world outside the event's past; the checkpoint's own
    // state is the world's to judge.
    for (event, expected) in [
        (stale_before, SealPlace::Stale),
        (stale_concurrent, SealPlace::Stale),
        (fresh, SealPlace::World),
        (unit, SealPlace::World),
    ] {
        let state = m.events[&event].sealed_under.clone().unwrap();
        let in_full = seal_against_checkpoint(&full, &state, |r| m.precedes(r, &event));
        let in_forgot =
            seal_against_checkpoint(&forgot_sides, &state, |r| forgot.precedes(r, &event));
        assert_eq!((in_full, in_forgot), (expected, expected));
    }

    // The breaks the link gate counts, from the breaks each replica holds.
    let breaks = |model: &Model| -> Vec<EventId> {
        model
            .events
            .iter()
            .filter(|(_, ev)| ev.is_break)
            .map(|(id, _)| *id)
            .collect()
    };
    assert_eq!(breaks(&m), vec![b, a2]);
    assert_eq!(gate_breaks(&full, breaks(&m)), vec![a2]);
    assert_eq!(gate_breaks(&forgot_sides, breaks(&forgot)), vec![a2]);

    // The heal test: C, removed after the checkpoint, holds the
    // checkpoint's key, never the world's current state; its late
    // rotation's wraps count for nothing; R, removed before it, holds
    // nothing of the world.
    let inside = ["A", "B", "M", "P"];
    assert!(!m.heal_fires(&full, &void, &inside));
    assert!(!forgot.heal_fires(&forgot_sides, &void, &inside));
    let c_full = m.derives(&full, &BTreeSet::from(["C"]), &[]);
    assert!(c_full.contains(&one(c)) && !c_full.contains(&one(late)));
    // With only P inside, the other holders count as outside and derive
    // the current state, at both replicas alike.
    assert!(m.heal_fires(&full, &void, &["P"]));
    assert!(forgot.heal_fires(&forgot_sides, &void, &["P"]));

    // Entitlement to the kept state before the checkpoint: a replica that
    // holds the past answers from its judgement there; one that forgot
    // passes none and counts every member of the record as entitled to no
    // state before the checkpoint.
    for member in ["A", "B", "M", "N"] {
        let expected = entitled_to_r2.contains(member);
        let stays = MemberAfter {
            with_history_after: false,
            in_from_record: true,
            floor: false,
        };
        assert_eq!(
            entitled_before(&full, &one(r2), &member, stays, Some(kept)),
            Some(expected),
            "{member}"
        );
        assert_eq!(
            entitled_before(&forgot_sides, &one(r2), &member, stays, None),
            Some(false),
            "{member}"
        );
    }
}
