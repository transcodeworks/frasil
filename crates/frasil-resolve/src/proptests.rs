//! Property tests of the procedure over random logs.
//!
//! - The verdicts do not depend on the order the events arrive in, nor on
//!   the order in which step 1 takes them.
//! - They equal those of a direct transcription of the procedure (`model`),
//!   which follows roster.md section 3.7 step by step with none of the
//!   engine's bit sets or early exits.
//! - Each verdict is borne out at the end: an event void by authority fails
//!   it at its place, one void by an attack has a valid attacker whose
//!   attack counts, and one valid by the rules has neither. An event the
//!   agreement step voided is borne out instead by the first assignment
//!   that step allowed, whatever the end leaves it: there it fails its
//!   authority with its class, or else its attacker is the first valid one
//!   whose attack counts.

use std::collections::{BTreeMap, BTreeSet};

use frasil_base::ErrorClass;
use proptest::prelude::*;

use crate::engine::Engine;
use crate::{How, Resolve, Verdict, View, resolve};

frasil_base::error_classes! {
    /// The test log's own classes.
    pub(crate) enum TestClass {
        /// The first kind of attack.
        AttackOne = "attack_one", Final;
        /// The second kind of attack.
        AttackTwo = "attack_two", Final;
        /// An event its `forbids` event, valid in its place, bars.
        Barred = "barred", Final;
        /// Two concurrent events of one group.
        Clash = "clash", Final;
    }
}

/// The most events a random log holds.
const MOST: usize = 12;

/// A random log. Events are named by their index, which is a topological
/// order; their IDs are a permutation of the indices, so canonical order
/// differs from index order.
#[derive(Debug, Clone)]
pub(crate) struct RandomLog {
    ids: Vec<u32>,
    index: BTreeMap<u32, usize>,
    height: Vec<u64>,
    /// `anc[e][p]`: `p` is in `e`'s past.
    anc: Vec<Vec<bool>>,
    check_fails: Vec<bool>,
    forked: Vec<bool>,
    self_lowering: Vec<bool>,
    group: Vec<Option<u8>>,
    /// `attack[x][e]`: the class `x` attacks `e` with.
    attack: Vec<Vec<Option<TestClass>>>,
    mutual: BTreeSet<(usize, usize)>,
    /// Authority needs this event valid.
    needs: Vec<Option<usize>>,
    /// Authority fails if this event is valid.
    forbids: Vec<Option<usize>>,
    seniority: Vec<u8>,
    rank: Vec<u8>,
    /// Mutual attacks drop by rank, as a device list's do.
    by_rank: bool,
    /// The most valid contested events in a place, the event included.
    full: usize,
}

impl RandomLog {
    fn build(n: usize, by_rank: bool, words: &[[u64; 4]], seed: u64) -> Self {
        let mut anc = vec![vec![false; n]; n];
        let mut height = vec![0u64; n];
        for i in 0..n {
            for j in 0..i {
                if (words[i][0] >> (j * 3)) & 7 == 0 {
                    let inherited = anc[j].clone();
                    for (k, &before) in inherited.iter().enumerate() {
                        anc[i][k] |= before;
                    }
                    anc[i][j] = true;
                    height[i] = height[i].max(height[j] + 1);
                }
            }
        }
        let pick = |i: usize, bits: u64| {
            let past: Vec<usize> = (0..n).filter(|&p| anc[i][p]).collect();
            (!past.is_empty()).then(|| past[(bits % past.len() as u64) as usize])
        };
        let mut log = Self {
            ids: Vec::new(),
            index: BTreeMap::new(),
            height,
            anc: anc.clone(),
            check_fails: Vec::new(),
            forked: Vec::new(),
            self_lowering: Vec::new(),
            group: Vec::new(),
            attack: vec![vec![None; n]; n],
            mutual: BTreeSet::new(),
            needs: Vec::new(),
            forbids: Vec::new(),
            seniority: Vec::new(),
            rank: Vec::new(),
            by_rank,
            full: 2 + (seed % 12) as usize,
        };
        for (i, w) in words.iter().enumerate().take(n) {
            let flags = w[1];
            log.check_fails.push(flags & 31 == 0);
            log.forked.push((flags >> 5) & 15 == 0);
            log.self_lowering.push((flags >> 9) & 7 == 0);
            log.group
                .push(((flags >> 12) & 3 == 0).then_some(((flags >> 15) & 1) as u8));
            log.needs.push(if (flags >> 16) & 1 == 0 {
                pick(i, flags >> 18)
            } else {
                None
            });
            log.forbids.push(if (flags >> 26) & 3 == 0 {
                pick(i, flags >> 28)
            } else {
                None
            });
            log.seniority.push(((flags >> 40) & 7) as u8);
            log.rank.push(((flags >> 44) & 3) as u8 + 1);
            for e in 0..n {
                if e != i && (w[2] >> (e * 4)) & 3 == 0 {
                    log.attack[i][e] = Some(if (w[2] >> (e * 4 + 2)) & 1 == 0 {
                        TestClass::AttackOne
                    } else {
                        TestClass::AttackTwo
                    });
                }
                if e > i && (w[3] >> e) & 1 == 1 {
                    log.mutual.insert((i, e));
                }
            }
        }
        // IDs: the indices, shuffled by the seed.
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| (seed ^ (i as u64)).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        log.ids = vec![0; n];
        for (rank, &i) in order.iter().enumerate() {
            log.ids[i] = rank as u32;
        }
        log.index = log.ids.iter().enumerate().map(|(i, &id)| (id, i)).collect();
        log
    }

    fn n(&self) -> usize {
        self.ids.len()
    }

    fn at(&self, id: u32) -> usize {
        self.index[&id]
    }

    fn concurrent(&self, a: usize, b: usize) -> bool {
        a != b && !self.anc[a][b] && !self.anc[b][a]
    }

    /// Authority, given which events are valid and how many valid contested
    /// events the place holds.
    fn authority_with(
        &self,
        e: usize,
        valid: impl Fn(usize) -> bool,
        place: usize,
    ) -> Result<(), TestClass> {
        if self.needs[e].is_some_and(|p| !valid(p)) {
            return Err(ErrorClass::NotAnAdministrator.into());
        }
        if self.forbids[e].is_some_and(&valid) {
            return Err(TestClass::Barred);
        }
        if place + 1 > self.full {
            return Err(ErrorClass::Full.into());
        }
        Ok(())
    }

    fn is_mutual(&self, x: usize, e: usize) -> bool {
        self.mutual.contains(&(x.min(e), x.max(e)))
            && self.attack[x][e].is_some()
            && self.attack[e][x].is_some()
            && !self.self_lowering[x]
    }

    /// Whether `x`'s attack on `e` counts, with both pasts decided or not.
    fn counts_with(&self, x: usize, e: usize, decided: bool) -> Option<bool> {
        if !self.is_mutual(x, e) {
            return Some(true);
        }
        if !self.by_rank {
            return Some(false);
        }
        if !decided {
            return None;
        }
        Some(self.rank[e] > self.rank[x])
    }

    fn canonical(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.n()).collect();
        order.sort_by_key(|&i| (self.height[i], self.ids[i]));
        order
    }
}

impl Resolve for RandomLog {
    type Id = u32;
    type Class = TestClass;
    type PickKey = (u8, u64, u32);

    fn height(&self, event: u32) -> u64 {
        self.height[self.at(event)]
    }

    fn precedes(&self, earlier: u32, later: u32) -> bool {
        self.anc[self.at(later)][self.at(earlier)]
    }

    fn check(&self, event: u32) -> Result<(), TestClass> {
        if self.check_fails[self.at(event)] {
            return Err(ErrorClass::Malformed.into());
        }
        Ok(())
    }

    fn forked(&self, event: u32) -> Option<TestClass> {
        self.forked[self.at(event)].then_some(ErrorClass::Forked.into())
    }

    fn self_lowering(&self, event: u32) -> bool {
        self.self_lowering[self.at(event)]
    }

    fn check_among(&self, event: u32, screened: &[u32]) -> Result<(), TestClass> {
        let e = self.at(event);
        let Some(group) = self.group[e] else {
            return Ok(());
        };
        let clash = screened.iter().any(|&o| {
            let o = self.at(o);
            self.group[o] == Some(group) && self.concurrent(e, o)
        });
        if clash { Err(TestClass::Clash) } else { Ok(()) }
    }

    fn authority(&self, event: u32, view: &View<'_, Self>) -> Result<(), TestClass> {
        let place = view.place(event).len();
        self.authority_with(self.at(event), |p| view.is_valid(self.ids[p]), place)
    }

    fn attack(&self, attacker: u32, event: u32) -> Option<TestClass> {
        self.attack[self.at(attacker)][self.at(event)]
    }

    fn mutual(&self, attacker: u32, event: u32) -> bool {
        self.is_mutual(self.at(attacker), self.at(event))
    }

    fn attack_counts(&self, attacker: u32, event: u32, view: &View<'_, Self>) -> Option<bool> {
        let decided = view.past_decided(attacker) && view.past_decided(event);
        self.counts_with(self.at(attacker), self.at(event), decided)
    }

    fn pick_key(&self, event: u32, _view: &View<'_, Self>) -> (u8, u64, u32) {
        let e = self.at(event);
        (self.seniority[e], self.height[e], event)
    }
}

fn arb_log() -> impl Strategy<Value = RandomLog> {
    (
        1..=MOST,
        any::<bool>(),
        proptest::collection::vec(any::<[u64; 4]>(), MOST),
        any::<u64>(),
    )
        .prop_map(|(n, by_rank, words, seed)| RandomLog::build(n, by_rank, &words, seed))
}

// ---------------------------------------------------------------------------
// The model: roster.md section 3.7, transcribed step by step.

#[derive(Debug, Clone, Copy, PartialEq)]
enum M {
    Valid(How),
    Void(TestClass),
    /// Void by this attacker; its class is named at the end.
    Attacked(usize),
    Trial(bool),
}

impl M {
    fn valid(self) -> bool {
        matches!(self, M::Valid(_) | M::Trial(true))
    }
}

/// What the model decides.
struct Modelled {
    /// Every event's verdict.
    verdicts: BTreeMap<u32, Verdict<u32, TestClass>>,
    /// Each event the agreement step voided, with the events valid in the
    /// first assignment that step allowed.
    agreed_void: BTreeMap<u32, BTreeSet<usize>>,
}

fn model(log: &RandomLog) -> Modelled {
    let mut out = BTreeMap::new();
    let order = log.canonical();
    let mut screened = Vec::new();
    for &i in &order {
        if log.check_fails[i] {
            out.insert(
                log.ids[i],
                Verdict::Void {
                    class: ErrorClass::Malformed.into(),
                    by: None,
                },
            );
        } else if log.forked[i] && !log.self_lowering[i] {
            out.insert(
                log.ids[i],
                Verdict::Void {
                    class: ErrorClass::Forked.into(),
                    by: None,
                },
            );
        } else {
            screened.push(i);
        }
    }
    let mut contested = Vec::new();
    for &i in &screened {
        let clash = log.group[i].is_some()
            && screened
                .iter()
                .any(|&o| log.group[o] == log.group[i] && log.concurrent(i, o));
        if clash {
            out.insert(
                log.ids[i],
                Verdict::Void {
                    class: TestClass::Clash,
                    by: None,
                },
            );
        } else {
            contested.push(i);
        }
    }

    let past = |e: usize| -> Vec<usize> {
        contested
            .iter()
            .copied()
            .filter(|&p| log.anc[e][p])
            .collect()
    };
    let attackers = |e: usize| -> Vec<usize> {
        if log.self_lowering[e] {
            return Vec::new();
        }
        contested
            .iter()
            .copied()
            .filter(|&x| log.concurrent(x, e) && log.attack[x][e].is_some())
            .collect()
    };
    let auth = |e: usize, status: &BTreeMap<usize, M>| {
        let valid = |p: usize| status.get(&p).is_some_and(|s| s.valid());
        let place = past(e).into_iter().filter(|&p| valid(p)).count();
        log.authority_with(e, valid, place)
    };
    let counts = |x: usize, e: usize, status: &BTreeMap<usize, M>| {
        let decided = past(x)
            .into_iter()
            .chain(past(e))
            .all(|p| status.contains_key(&p));
        log.counts_with(x, e, decided)
    };
    let ready =
        |e: usize, status: &BTreeMap<usize, M>| past(e).iter().all(|p| status.contains_key(p));

    // Why an event is void under some statuses: its authority, or the first
    // valid attacker whose attack counts.
    let why = |e: usize, status: &BTreeMap<usize, M>| match auth(e, status) {
        Err(class) => Some(M::Void(class)),
        Ok(()) => attackers(e)
            .into_iter()
            .find(|&x| status[&x].valid() && counts(x, e, status) != Some(false))
            .map(M::Attacked),
    };
    let mut agreed_void: BTreeMap<u32, BTreeSet<usize>> = BTreeMap::new();
    let mut status: BTreeMap<usize, M> = BTreeMap::new();
    while status.len() < contested.len() {
        // Step 1.
        let mut progress = true;
        while progress {
            progress = false;
            for &e in &contested {
                if status.contains_key(&e) || !ready(e, &status) {
                    continue;
                }
                let verdict = match auth(e, &status) {
                    Err(class) => Some(M::Void(class)),
                    Ok(()) => {
                        let mut pending = false;
                        let mut beaten = None;
                        for x in attackers(e) {
                            if status.get(&x).is_some_and(|s| !s.valid()) {
                                continue;
                            }
                            let c = counts(x, e, &status);
                            if c == Some(false) {
                                continue;
                            }
                            if status.contains_key(&x) && c == Some(true) {
                                beaten = Some(x);
                                break;
                            }
                            pending = true;
                        }
                        match beaten {
                            Some(x) => Some(M::Attacked(x)),
                            None if pending => None,
                            None => Some(M::Valid(How::Rules)),
                        }
                    }
                };
                if let Some(v) = verdict {
                    status.insert(e, v);
                    progress = true;
                }
            }
        }
        let undecided: Vec<usize> = contested
            .iter()
            .copied()
            .filter(|e| !status.contains_key(e))
            .collect();
        if undecided.is_empty() {
            break;
        }
        // Step 3.
        if undecided.len() <= crate::AGREEMENT_LIMIT {
            let mut allowed: Vec<Vec<bool>> = Vec::new();
            for bits in 0u32..(1 << undecided.len()) {
                let mut trial = status.clone();
                // itertools.product order: the first event varies slowest.
                let k = undecided.len();
                let assignment: Vec<bool> = (0..k).map(|j| bits >> (k - 1 - j) & 1 == 1).collect();
                for (&e, &b) in undecided.iter().zip(&assignment) {
                    trial.insert(e, M::Trial(b));
                }
                let all = undecided.iter().zip(&assignment).all(|(&e, &b)| {
                    let holds = auth(e, &trial).is_ok();
                    let beaten = attackers(e)
                        .into_iter()
                        .any(|x| trial[&x].valid() && counts(x, e, &trial) != Some(false));
                    b == (holds && !beaten)
                });
                if all {
                    allowed.push(assignment);
                }
            }
            let mut agreed = false;
            if let Some(first) = allowed.first() {
                // An event agreed void stays void, with its reason under the
                // first allowed assignment.
                let mut trial = status.clone();
                for (&e, &b) in undecided.iter().zip(first) {
                    trial.insert(e, M::Trial(b));
                }
                let first_valid: BTreeSet<usize> = contested
                    .iter()
                    .copied()
                    .filter(|e| trial[e].valid())
                    .collect();
                for (j, &e) in undecided.iter().enumerate() {
                    if allowed.iter().all(|a| a[j] == first[j]) {
                        let decided = if first[j] {
                            M::Valid(How::Agreed)
                        } else {
                            agreed_void.insert(log.ids[e], first_valid.clone());
                            why(e, &trial).expect("void in an allowed assignment")
                        };
                        status.insert(e, decided);
                        agreed = true;
                    }
                }
            }
            if agreed {
                continue;
            }
        }
        // Step 4.
        let view_key = |e: usize| (log.seniority[e], log.height[e], log.ids[e]);
        let pick = undecided
            .iter()
            .copied()
            .filter(|&e| ready(e, &status))
            .min_by_key(|&e| view_key(e))
            .expect("the earliest undecided event has a decided past");
        status.insert(pick, M::Valid(How::Seniority));
    }
    for &e in &contested {
        let verdict = match status[&e] {
            M::Valid(how) => Verdict::Valid(how),
            M::Void(class) => Verdict::Void { class, by: None },
            M::Attacked(x) => Verdict::Void {
                class: log.attack[x][e].expect("an attacker attacks"),
                by: Some(log.ids[x]),
            },
            M::Trial(_) => unreachable!(),
        };
        out.insert(log.ids[e], verdict);
    }
    Modelled {
        verdicts: out,
        agreed_void,
    }
}

fn all_ids(log: &RandomLog) -> Vec<u32> {
    log.ids.clone()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// The engine decides as the step-by-step transcription does: the same
    /// verdict, the same step, the same class and the same attacker.
    #[test]
    fn matches_the_model(log in arb_log()) {
        let got: BTreeMap<u32, Verdict<u32, TestClass>> =
            resolve(&log, all_ids(&log)).iter().map(|(id, v)| (id, *v)).collect();
        prop_assert_eq!(got, model(&log).verdicts);
    }

    /// The verdicts do not depend on the order the events arrive in, nor on
    /// repeats.
    #[test]
    fn arrival_order(log in arb_log(), shuffle in any::<u64>(), repeat in any::<u16>()) {
        let base = resolve(&log, all_ids(&log));
        let mut ids = all_ids(&log);
        ids.sort_by_key(|&id| (shuffle ^ u64::from(id)).wrapping_mul(0xff51_afd7_ed55_8ccd));
        let again: Vec<u32> =
            ids.iter().copied().filter(|&id| repeat >> (id % 16) & 1 == 1).collect();
        ids.extend(again);
        prop_assert_eq!(resolve(&log, ids), base);
    }

    /// Step 1 is a least fixed point: whatever order it takes the events
    /// in, the same events are valid.
    #[test]
    fn sweep_order(log in arb_log(), shuffle in any::<u64>()) {
        let base = resolve(&log, all_ids(&log));
        let contested = base.contested().to_vec();
        let mut sweep: Vec<usize> = (0..contested.len()).collect();
        sweep.sort_by_key(|&i| (shuffle ^ i as u64).wrapping_mul(0xc4ce_b9fe_1a85_ec53));
        let swept = Engine::new(&log, contested).run(Some(&sweep));
        let valid = |r: &crate::Resolution<u32, TestClass>| r.valid().collect::<Vec<_>>();
        prop_assert_eq!(valid(&swept), base.contested().iter().copied()
            .filter(|&id| base.is_valid(id)).collect::<Vec<_>>());
    }

    /// Each verdict holds up against the final statuses, except that an
    /// event the agreement step voided holds up against the first
    /// assignment that step allowed.
    #[test]
    fn verdicts_hold(log in arb_log()) {
        let r = resolve(&log, all_ids(&log));
        let agreed_void = model(&log).agreed_void;
        let contested: BTreeSet<u32> = r.contested().iter().copied().collect();
        for &id in r.contested() {
            let e = log.at(id);
            let first = agreed_void.get(&id);
            let valid = |p: usize| match first {
                Some(first) => first.contains(&p),
                None => r.is_valid(log.ids[p]),
            };
            let place = (0..log.n())
                .filter(|&p| log.anc[e][p] && contested.contains(&log.ids[p]) && valid(p))
                .count();
            let holds = log.authority_with(e, valid, place);
            let counting = |x: usize| {
                contested.contains(&log.ids[x])
                    && log.concurrent(x, e)
                    && !log.self_lowering[e]
                    && log.attack[x][e].is_some()
                    && valid(x)
                    && log.counts_with(x, e, true) == Some(true)
            };
            let verdict = *r.verdict(id).unwrap();
            if first.is_some() {
                // Void in the first allowed assignment, and to the end.
                prop_assert!(!valid(e));
                prop_assert!(!verdict.is_valid());
            }
            match verdict {
                Verdict::Valid(How::Rules) => {
                    prop_assert!(holds.is_ok());
                    prop_assert!(!(0..log.n()).any(counting));
                }
                Verdict::Valid(How::Seniority) => prop_assert!(holds.is_ok()),
                Verdict::Valid(How::Agreed) => {}
                Verdict::Void { class, by: None } => prop_assert_eq!(holds, Err(class)),
                Verdict::Void { class, by: Some(x) } => {
                    let x = log.at(x);
                    prop_assert!(holds.is_ok());
                    prop_assert!(counting(x));
                    prop_assert_eq!(log.attack[x][e], Some(class));
                    if first.is_some() {
                        // The first, in canonical order, of the attackers
                        // that count there.
                        let rank = |p: usize| (log.height[p], log.ids[p]);
                        prop_assert!(!(0..log.n()).any(|y| counting(y) && rank(y) < rank(x)));
                    }
                }
            }
        }
    }
}
