//! Roster cases whose verdicts depend only on the procedure, run through a
//! small roster built on the engine.
//!
//! The events, their IDs, authors, sequence numbers and parents come from
//! `roster.json` (families `cycles`, `duels` and `concurrent_changes`); the
//! expected verdicts are the vectors'. This crate does not claim those
//! families: `frasil-space` does, decoding the events in full. Here the
//! changes each roster event makes are written by hand from its name, and
//! the roster is roster.md's sections 3.2, 3.5 and 3.6, steps 1 to 4 (no
//! twins, keys or capabilities).
//!
//! Seniority's hash of the space ID and member ID is stood in for by the
//! member's name. In the cases below no two grants that compete share a
//! height, so the stand-in never decides.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use frasil_base::{Class, ErrorClass};
use frasil_resolve::{How, Resolve, Verdict, View, resolve};
use frasil_testkit::{hex, vectors};
use serde_json::Value;

frasil_base::error_classes! {
    /// roster.md's classes these cases meet.
    pub enum RosterClass {
        /// (a): a concurrent event removes the author.
        RemovedConcurrently = "removed_concurrently", Final;
        /// (b): a concurrent event demotes the author below administer.
        DemotedConcurrently = "demoted_concurrently", Final;
        /// (c): a concurrent event removes a member this one grants or
        /// changes.
        TargetRemovedConcurrently = "target_removed_concurrently", Final;
        /// An administrator grants itself.
        SelfGrant = "self_grant", Final;
        /// A grant of a member already in.
        AlreadyMember = "already_member", Final;
        /// A change or removal of a member not in.
        NoSuchMember = "no_such_member", Final;
        /// A change of the author's own device other than a lowering.
        SelfChange = "self_change", Final;
        /// An event that lowers an administrator names somebody else too.
        AdminAlone = "admin_alone", Final;
    }
}

const READ: u8 = 1;
const WRITE: u8 = 2;
const ADMINISTER: u8 = 3;

/// One change of a roster event.
#[derive(Debug, Clone, Copy)]
enum Change {
    Grant(&'static str, u8),
    Remove(&'static str),
    Level(&'static str, u8),
}

impl Change {
    fn member(self) -> &'static str {
        match self {
            Change::Grant(m, _) | Change::Remove(m) | Change::Level(m, _) => m,
        }
    }
}

/// A grant's seniority: `(height of the grant, stand-in for the hash,
/// grant's ID)`.
type Seniority = (u64, String, [u8; 32]);

/// A member's state at a place (section 3.2).
#[derive(Debug, Clone, PartialEq)]
enum Member {
    Out,
    In { level: u8, seniority: Seniority },
}

struct Event {
    id: [u8; 32],
    author: String,
    seq: u64,
    unit: bool,
    parents: Vec<usize>,
    changes: Vec<Change>,
}

struct Roster {
    events: Vec<Event>,
    index: BTreeMap<[u8; 32], usize>,
    /// `anc[e]`: the events in `e`'s past.
    anc: Vec<BTreeSet<usize>>,
    height: Vec<u64>,
    /// Each forked author's fork point.
    forks: BTreeMap<String, u64>,
    /// The most valid roster events in a place, itself included.
    full: usize,
    cache: RefCell<BTreeMap<Vec<usize>, BTreeMap<&'static str, Member>>>,
}

impl Roster {
    fn at(&self, id: [u8; 32]) -> usize {
        self.index[&id]
    }

    fn genesis(&self) -> usize {
        0
    }

    /// The roster at a set of valid roster events, the genesis among them.
    fn state(&self, valid: &BTreeSet<usize>) -> BTreeMap<&'static str, Member> {
        let key: Vec<usize> = valid.iter().copied().collect();
        if let Some(hit) = self.cache.borrow().get(&key) {
            return hit.clone();
        }
        let mut by_member: BTreeMap<&'static str, Vec<(usize, Change)>> = BTreeMap::new();
        for &e in valid {
            for &c in &self.events[e].changes {
                by_member.entry(c.member()).or_default().push((e, c));
            }
        }
        let mut out = BTreeMap::new();
        for (m, items) in by_member {
            let maximal: Vec<(usize, Change)> = items
                .iter()
                .copied()
                .filter(|&(e, _)| {
                    !items
                        .iter()
                        .any(|&(o, _)| o != e && self.anc[o].contains(&e))
                })
                .collect();
            if maximal.iter().any(|(_, c)| matches!(c, Change::Remove(_))) {
                out.insert(m, Member::Out);
                continue;
            }
            // The meet: the lowest level, the most senior grant in force.
            let states: Vec<(u8, Seniority)> = maximal
                .iter()
                .filter_map(|&(e, c)| match c {
                    Change::Grant(m, level) => {
                        Some((level, (self.height[e], m.to_string(), self.events[e].id)))
                    }
                    Change::Level(m, level) => match self.state(&self.place_in(e, valid)).get(m) {
                        Some(Member::In { seniority, .. }) => Some((level, seniority.clone())),
                        _ => None,
                    },
                    Change::Remove(_) => None,
                })
                .collect();
            if let Some(level) = states.iter().map(|s| s.0).min() {
                let seniority = states.into_iter().map(|s| s.1).min().unwrap();
                out.insert(m, Member::In { level, seniority });
            }
        }
        self.cache.borrow_mut().insert(key, out.clone());
        out
    }

    /// The events of `valid` in `e`'s past, with the genesis.
    fn place_in(&self, e: usize, valid: &BTreeSet<usize>) -> BTreeSet<usize> {
        let mut place: BTreeSet<usize> = self.anc[e].intersection(valid).copied().collect();
        place.insert(self.genesis());
        place
    }

    /// The genesis and the valid contested events of the event's past.
    fn place(&self, e: usize, view: &View<'_, Self>) -> BTreeSet<usize> {
        let mut place: BTreeSet<usize> = view
            .place(self.events[e].id)
            .into_iter()
            .map(|id| self.at(id))
            .collect();
        place.insert(self.genesis());
        place
    }

    /// The seniority of an event's author's member at its place.
    fn author_seniority(&self, event: [u8; 32], view: &View<'_, Self>) -> Option<Seniority> {
        let e = self.at(event);
        match self
            .state(&self.place(e, view))
            .get(self.events[e].author.as_str())
        {
            Some(Member::In { seniority, .. }) => Some(seniority.clone()),
            _ => None,
        }
    }

    fn level(state: &BTreeMap<&'static str, Member>, m: &str) -> Option<u8> {
        match state.get(m) {
            Some(Member::In { level, .. }) => Some(*level),
            _ => None,
        }
    }

    /// Section 3.5.2: does `x` attack `e`?
    fn attacks(&self, x: usize, e: usize) -> Option<RosterClass> {
        let me = self.events[e].author.as_str();
        for c in &self.events[x].changes {
            match *c {
                Change::Remove(m) if m == me => return Some(RosterClass::RemovedConcurrently),
                Change::Level(m, level) if m == me && level < ADMINISTER => {
                    return Some(RosterClass::DemotedConcurrently);
                }
                _ => {}
            }
        }
        let removed: Vec<&str> = self.events[x]
            .changes
            .iter()
            .filter_map(|c| matches!(c, Change::Remove(_)).then_some(c.member()))
            .collect();
        self.events[e]
            .changes
            .iter()
            .any(|c| !matches!(c, Change::Remove(_)) && removed.contains(&c.member()))
            .then_some(RosterClass::TargetRemovedConcurrently)
    }

    fn lowering(class: Option<RosterClass>) -> bool {
        matches!(
            class,
            Some(RosterClass::RemovedConcurrently | RosterClass::DemotedConcurrently)
        )
    }
}

impl Resolve for Roster {
    type Id = [u8; 32];
    type Class = RosterClass;
    type PickKey = (Seniority, u64, [u8; 32]);

    fn height(&self, event: [u8; 32]) -> u64 {
        self.height[self.at(event)]
    }

    fn precedes(&self, earlier: [u8; 32], later: [u8; 32]) -> bool {
        self.anc[self.at(later)].contains(&self.at(earlier))
    }

    fn check(&self, _event: [u8; 32]) -> Result<(), RosterClass> {
        Ok(())
    }

    fn forked(&self, event: [u8; 32]) -> Option<RosterClass> {
        let e = &self.events[self.at(event)];
        self.forks
            .get(&e.author)
            .is_some_and(|&fork| e.seq >= fork)
            .then_some(ErrorClass::Forked.into())
    }

    /// Section 3.5.1: each change lowers or removes the author's own device.
    fn self_lowering(&self, event: [u8; 32]) -> bool {
        let e = &self.events[self.at(event)];
        e.changes.iter().all(|c| match *c {
            Change::Remove(m) => m == e.author,
            Change::Level(m, level) => m == e.author && level < ADMINISTER,
            Change::Grant(..) => false,
        })
    }

    /// Section 3.6, steps 1 to 4.
    fn authority(&self, event: [u8; 32], view: &View<'_, Self>) -> Result<(), RosterClass> {
        let e = self.at(event);
        let place = self.place(e, view);
        let s = self.state(&place);
        let me = self.events[e].author.as_str();
        if Self::level(&s, me) != Some(ADMINISTER) {
            return Err(ErrorClass::NotAnAdministrator.into());
        }
        let changes = &self.events[e].changes;
        for c in changes {
            let current = Self::level(&s, c.member());
            match *c {
                Change::Grant(m, _) if m == me => return Err(RosterClass::SelfGrant),
                Change::Grant(..) if current.is_some() => return Err(RosterClass::AlreadyMember),
                Change::Grant(..) => {}
                _ if current.is_none() => return Err(RosterClass::NoSuchMember),
                Change::Level(m, level) if m == me && Some(level) >= current => {
                    return Err(RosterClass::SelfChange);
                }
                _ => {}
            }
        }
        if changes.len() > 1 {
            let lowers_an_administrator = changes.iter().any(|c| {
                let current = Self::level(&s, c.member());
                current == Some(ADMINISTER)
                    && match *c {
                        Change::Remove(_) => true,
                        Change::Level(_, level) => level < ADMINISTER,
                        Change::Grant(..) => false,
                    }
            });
            if lowers_an_administrator {
                return Err(RosterClass::AdminAlone);
            }
        }
        if place.len() + 1 > self.full {
            return Err(ErrorClass::Full.into());
        }
        Ok(())
    }

    fn attack(&self, attacker: [u8; 32], event: [u8; 32]) -> Option<RosterClass> {
        self.attacks(self.at(attacker), self.at(event))
    }

    /// Two events by different authors that each attack the other through
    /// (a) or (b).
    fn mutual(&self, attacker: [u8; 32], event: [u8; 32]) -> bool {
        let (x, e) = (self.at(attacker), self.at(event));
        self.events[x].author != self.events[e].author
            && Self::lowering(self.attacks(x, e))
            && !self.self_lowering(attacker)
            && Self::lowering(self.attacks(e, x))
    }

    /// Section 3.5.2: in a mutual pair the attack counts exactly when its
    /// author outranks its partner's, each at its own event's place. Every
    /// administrator here holds the top rank, so the more senior outranks.
    fn attack_counts(
        &self,
        attacker: [u8; 32],
        event: [u8; 32],
        view: &View<'_, Self>,
    ) -> Option<bool> {
        if !self.mutual(attacker, event) {
            return Some(true);
        }
        if !(view.past_decided(attacker) && view.past_decided(event)) {
            return None;
        }
        Some(self.author_seniority(attacker, view)? < self.author_seniority(event, view)?)
    }

    fn pick_key(&self, event: [u8; 32], view: &View<'_, Self>) -> Self::PickKey {
        let e = self.at(event);
        let Some(seniority) = self.author_seniority(event, view) else {
            unreachable!("an event the pick takes has its authority");
        };
        (seniority, self.height[e], event)
    }
}

/// The changes of each roster event, by name, from what the name says. An
/// event not named here, other than the genesis, changes nobody (a heal).
fn changes(name: &str) -> Vec<Change> {
    use Change::{Grant, Level, Remove};
    let one = |c| vec![c];
    match name {
        "P grants Q administer" => one(Grant("Q", ADMINISTER)),
        "P grants Z administer" => one(Grant("Z", ADMINISTER)),
        "P grants S administer" => one(Grant("S", ADMINISTER)),
        "P grants M administer" => one(Grant("M", ADMINISTER)),
        "P grants C administer" => one(Grant("C", ADMINISTER)),
        "Q grants B administer" => one(Grant("B", ADMINISTER)),
        "P grants A administer" => one(Grant("A", ADMINISTER)),
        "P1 grants P2 administer" => one(Grant("P2", ADMINISTER)),
        "P1 grants Q administer" => one(Grant("Q", ADMINISTER)),
        "P grants M write" => one(Grant("M", WRITE)),
        "P grants H" | "Q grants H" | "Q grants H again" | "P1 grants H after its fork" => {
            one(Grant("H", WRITE))
        }
        "Q grants H (later work)" | "P grants H (later work)" => one(Grant("H", WRITE)),
        "P grants N write" => one(Grant("N", WRITE)),
        "P grants J" => one(Grant("J", WRITE)),
        "Q grants K" => one(Grant("K", WRITE)),
        "S grants Q again" => one(Grant("Q", ADMINISTER)),
        "S grants P again" => one(Grant("P", ADMINISTER)),
        "Z removes P" | "Q removes P" | "Q removes P, backdated" => one(Remove("P")),
        "Q removes Z" => one(Remove("Z")),
        "P removes Q"
        | "P removes Q, backdated"
        | "P removes Q, backdated, keeping its chain"
        | "P removes Q, backdated, forking its chain" => one(Remove("Q")),
        "P removes H" | "Q removes H" => one(Remove("H")),
        "C removes A" => one(Remove("A")),
        "B removes C" => one(Remove("C")),
        "A removes B" => one(Remove("B")),
        "P demotes itself to write" => one(Level("P", WRITE)),
        "P, restored, demotes itself to read" => one(Level("P", READ)),
        "P1 demotes itself to write" => one(Level("P1", WRITE)),
        "Q demotes itself to write" => one(Level("Q", WRITE)),
        "P demotes Q to write" => one(Level("Q", WRITE)),
        "P removes Q and M in one event" => vec![Remove("Q"), Remove("M")],
        "P removes M and N in one event" => vec![Remove("M"), Remove("N")],
        _ if name.starts_with("M's junk roster event") => one(Grant("X", WRITE)),
        "Q heals" => Vec::new(),
        _ => panic!("no changes written for {name:?}"),
    }
}

/// Builds the roster of a case, over the events a view holds.
fn roster(case: &Value, view: &Value, full: usize) -> (Roster, BTreeMap<[u8; 32], String>) {
    let mut events = Vec::new();
    let mut names = BTreeMap::new();
    let mut by_name: BTreeMap<String, usize> = BTreeMap::new();
    let holds: Option<BTreeSet<&str>> = view["holds"]
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap()).collect());
    for (i, e) in case["events"].as_array().unwrap().iter().enumerate() {
        let name = e["name"].as_str().unwrap();
        if holds.as_ref().is_some_and(|h| !h.contains(name)) {
            continue;
        }
        let id: [u8; 32] = hex::decode_array(e["id"].as_str().unwrap()).unwrap();
        let author = e["author"].as_str().unwrap().to_string();
        let changes = if i == 0 {
            vec![Change::Grant(
                Box::leak(author.clone().into_boxed_str()),
                ADMINISTER,
            )]
        } else if e["kind"] == 2 {
            changes(name)
        } else {
            Vec::new()
        };
        let parents = e["parents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| by_name[p.as_str().unwrap()])
            .collect();
        by_name.insert(name.to_string(), events.len());
        names.insert(id, name.to_string());
        events.push(Event {
            id,
            author,
            seq: e["seq"].as_u64().unwrap(),
            unit: e["kind"] != 2,
            parents,
            changes,
        });
    }
    let mut anc: Vec<BTreeSet<usize>> = Vec::new();
    let mut height = Vec::new();
    for e in &events {
        let mut past = BTreeSet::new();
        let mut h = 0;
        for &p in &e.parents {
            past.insert(p);
            past.extend(anc[p].iter().copied());
            h = h.max(height[p] + 1);
        }
        anc.push(past);
        height.push(h);
    }
    let forks = view["forked"]
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
                .collect()
        })
        .unwrap_or_default();
    let index = events.iter().enumerate().map(|(i, e)| (e.id, i)).collect();
    let roster = Roster {
        events,
        index,
        anc,
        height,
        forks,
        full,
        cache: RefCell::new(BTreeMap::new()),
    };
    (roster, names)
}

/// A verdict as the vectors write it.
fn show(verdict: &Verdict<[u8; 32], RosterClass>, names: &BTreeMap<[u8; 32], String>) -> String {
    match verdict {
        Verdict::Valid(How::Rules) => "valid".into(),
        Verdict::Valid(How::Agreed) => "valid (agreed)".into(),
        Verdict::Valid(How::Seniority) => "valid (seniority)".into(),
        Verdict::Void { class, by: None } => class.name().into(),
        Verdict::Void { class, by: Some(x) } => format!("{} by {}", class.name(), names[x]),
    }
}

/// Runs one case of `family` in every view, checking each roster event's
/// verdict, and the members the roster ends with.
fn run(family: &str, name: &str, full: usize) {
    let cases: Value = vectors::family("roster.json", family);
    let case = cases
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name:?} in {family}"));
    for (view_name, view) in case["views"].as_object().unwrap() {
        let (roster, names) = roster(case, view, full);
        let offered: Vec<[u8; 32]> = roster.events[1..]
            .iter()
            .filter(|e| !e.unit)
            .map(|e| e.id)
            .collect();
        // Arrival order does not matter: offer them backwards.
        let r = resolve(&roster, offered.iter().rev().copied());
        let expected = view["events"].as_object().unwrap();
        for &id in &offered {
            let event = &names[&id];
            assert_eq!(
                show(r.verdict(id).unwrap(), &names),
                expected[event].as_str().unwrap(),
                "{name}, view {view_name}: {event}"
            );
        }
        // The roster over the genesis and the valid events.
        let mut valid: BTreeSet<usize> = r.valid().map(|id| roster.at(id)).collect();
        valid.insert(roster.genesis());
        let state = roster.state(&valid);
        for (member, want) in view["roster"].as_object().unwrap() {
            let got = match state.get(member.as_str()) {
                Some(Member::Out) | None => "removed".to_string(),
                Some(Member::In { level, .. }) => {
                    ["", "read", "write", "administer"][*level as usize].to_string()
                }
            };
            let want = want.as_str().map_or_else(
                || want["level"].as_str().unwrap().to_string(),
                str::to_string,
            );
            assert_eq!(got, want, "{name}, view {view_name}: member {member}");
        }
    }
}

const LIMIT: usize = 4096;

// -- cycles

#[test]
fn an_odd_cycle() {
    run("cycles", "an odd cycle", LIMIT);
}

#[test]
fn an_even_cycle_with_several_answers() {
    run("cycles", "an even cycle with several answers", LIMIT);
}

#[test]
fn administrators_granted_concurrently_in_an_odd_cycle() {
    run(
        "cycles",
        "administrators granted concurrently, in an odd cycle",
        LIMIT,
    );
}

// -- duels: mutual pairs, backdating and forks

#[test]
fn a_genuine_mutual_removal() {
    run("duels", "a genuine mutual removal", LIMIT);
}

#[test]
fn the_backdated_duel_senior_attacker() {
    run("duels", "the backdated duel, senior attacker", LIMIT);
}

#[test]
fn the_backdated_duel_junior_attacker() {
    run("duels", "the backdated duel, junior attacker", LIMIT);
}

#[test]
fn concurrent_self_demotions() {
    run("duels", "concurrent self-demotions", LIMIT);
}

#[test]
fn a_backdating_attacker_that_keeps_its_chain() {
    run("duels", "a backdating attacker that keeps its chain", LIMIT);
}

#[test]
fn a_backdating_attacker_that_forks_its_chain() {
    run("duels", "a backdating attacker that forks its chain", LIMIT);
}

#[test]
fn a_fork_cannot_erase_its_authors_self_demotion() {
    run(
        "duels",
        "a fork cannot erase its author's self-demotion",
        LIMIT,
    );
}

// -- concurrent changes: self-lowering, mutual pairs, AdminAlone, Full

#[test]
fn a_self_demotion_and_a_concurrent_removal_of_its_author_both_stand() {
    run(
        "concurrent_changes",
        "a self-demotion and a concurrent removal of its author both stand",
        LIMIT,
    );
}

#[test]
fn a_demotion_beats_the_demoted_administrators_concurrent_actions() {
    run(
        "concurrent_changes",
        "a demotion beats the demoted administrator's concurrent roster actions",
        LIMIT,
    );
}

#[test]
fn a_removal_and_a_demotion_of_each_other_the_more_senior_stands() {
    run(
        "concurrent_changes",
        "a removal and a demotion of each other: the more senior stands",
        LIMIT,
    );
}

#[test]
fn an_event_that_lowers_an_administrator_names_nobody_else() {
    run(
        "concurrent_changes",
        "an event that lowers an administrator names nobody else",
        LIMIT,
    );
}

#[test]
fn junk_roster_events_do_not_fill_the_roster() {
    run(
        "concurrent_changes",
        "junk roster events do not fill the roster (limit lowered to 3 here)",
        3,
    );
}
