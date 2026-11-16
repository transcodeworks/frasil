//! The resolution procedure (roster.md, 3.7 The resolution procedure).

use std::collections::BTreeMap;

use crate::bits::Bits;
use crate::{AGREEMENT_LIMIT, How, Resolution, Resolve, Standing, Verdict, View};
use frasil_base::collect::CollectMap;

/// The contested events: their IDs in canonical order, each one's position,
/// and each one's contested past.
pub(crate) struct Contest<Id> {
    pub(crate) ids: Vec<Id>,
    pub(crate) index: BTreeMap<Id, usize>,
    /// `past[e]`: the positions of the contested events in `e`'s past.
    pub(crate) past: Vec<Bits>,
}

/// Decides each event `events` names valid or void, by the log's rules
/// (roster.md, 3.7 The resolution procedure).
///
/// The order of `events` does not matter, nor do repeats: the procedure
/// sorts them in canonical order. Each event is screened
/// ([`Resolve::check`], [`Resolve::forked`], [`Resolve::check_among`]),
/// and those that pass are decided by propagation, agreement and the
/// seniority pick. The crate documentation describes each step.
///
/// # Panics
///
/// Only if the log breaks the [`Resolve`] contract, with answers that are
/// not functions of their arguments and the view.
pub fn resolve<L, I>(log: &L, events: I) -> Resolution<L::Id, L::Class>
where
    L: Resolve,
    I: IntoIterator<Item = L::Id>,
{
    let mut ids: Vec<L::Id> = events.into_iter().collect();
    ids.sort_by_key(|&id| (log.height(id), id));
    ids.dedup();

    // The screen: the event alone, then the chain penalty, which a
    // self-lowering event survives (roster.md, 3.5.1 Self-lowering events),
    // then the checks among the screened events.
    let mut screened_out: BTreeMap<L::Id, L::Class> = BTreeMap::new();
    let mut screened = Vec::with_capacity(ids.len());
    for &id in &ids {
        if let Err(class) = log.check(id) {
            screened_out.insert(id, class);
        } else if let Some(class) = log.forked(id).filter(|_| !log.self_lowering(id)) {
            screened_out.insert(id, class);
        } else {
            screened.push(id);
        }
    }
    let mut contested = Vec::with_capacity(screened.len());
    for &id in &screened {
        match log.check_among(id, &screened) {
            Err(class) => {
                screened_out.insert(id, class);
            }
            Ok(()) => contested.push(id),
        }
    }

    WEIGHED.with(|weighed| {
        let (resolutions, events) = weighed.get();
        weighed.set((
            resolutions.saturating_add(1),
            events.saturating_add(contested.len() as u64),
        ));
    });
    let decided = Engine::new(log, contested).run(None);

    let index = ids.iter().enumerate().map(|(i, &id)| (id, i)).collect_map();
    let verdicts = ids
        .iter()
        .map(|&id| {
            let verdict = match screened_out.get(&id) {
                Some(&class) => Verdict::Void { class, by: None },
                None => decided.verdicts[decided.index[&id]].1,
            };
            (id, verdict)
        })
        .collect();
    Resolution {
        verdicts,
        index,
        contested: decided.contested,
    }
}

std::thread_local! {
    /// How many times [`resolve`] ran on this thread, and how many
    /// contested events it weighed in all.
    static WEIGHED: core::cell::Cell<(u64, u64)> = const { core::cell::Cell::new((0, 0)) };
}

/// How many times [`resolve`] has run on this thread, and how many contested
/// events it has weighed in all, for tests and measurements: the procedure's
/// work grows with the second, the screen's only with the events offered.
#[doc(hidden)]
pub fn weighed() -> (u64, u64) {
    WEIGHED.with(core::cell::Cell::get)
}

/// The procedure over the contested events.
pub(crate) struct Engine<'a, L: Resolve> {
    log: &'a L,
    contest: Contest<L::Id>,
    /// `attackers[e]`: each contested event that attacks `e`, with the
    /// attack's class, in canonical order.
    attackers: Vec<Vec<(usize, L::Class)>>,
    slots: Vec<Standing<L::Id, L::Class>>,
    /// The decided events, agreed ones included.
    decided: Bits,
    /// For each event the agreement step voided, why it is void in the
    /// first allowed assignment (see [`Engine::name_agreed`]).
    agreed_reasons: BTreeMap<usize, Standing<L::Id, L::Class>>,
}

impl<'a, L: Resolve> Engine<'a, L> {
    /// Sets up the procedure over `contested`, in canonical order.
    pub(crate) fn new(log: &'a L, contested: Vec<L::Id>) -> Self {
        let n = contested.len();
        let index: BTreeMap<L::Id, usize> = contested
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i))
            .collect_map();
        // Canonical order extends the causal order, so an event's past comes
        // before it.
        let past: Vec<Bits> = (0..n)
            .map(|e| {
                let mut bits = Bits::new(n);
                for p in 0..e {
                    if log.precedes(contested[p], contested[e]) {
                        bits.insert(p);
                    }
                }
                bits
            })
            .collect();
        let concurrent =
            |a: usize, b: usize| a != b && !past[a].contains(b) && !past[b].contains(a);
        let attackers = (0..n)
            .map(|e| {
                if log.self_lowering(contested[e]) {
                    return Vec::new(); // never attacked
                }
                (0..n)
                    .filter(|&x| concurrent(x, e))
                    .filter_map(|x| log.attack(contested[x], contested[e]).map(|c| (x, c)))
                    .collect()
            })
            .collect();
        Self {
            log,
            contest: Contest {
                ids: contested,
                index,
                past,
            },
            attackers,
            slots: vec![Standing::Undecided; n],
            decided: Bits::new(n),
            agreed_reasons: BTreeMap::new(),
        }
    }

    fn view(&self) -> View<'_, L> {
        View {
            log: self.log,
            contest: &self.contest,
            slots: &self.slots,
        }
    }

    fn n(&self) -> usize {
        self.contest.ids.len()
    }

    fn ready(&self, e: usize) -> bool {
        self.contest.past[e].is_subset(&self.decided)
    }

    fn decide(&mut self, e: usize, standing: Standing<L::Id, L::Class>) {
        self.slots[e] = standing;
        self.decided.insert(e);
    }

    /// Runs the procedure to the end. `sweep` is the order in which step 1
    /// takes the events, canonical order when `None`; which events are valid
    /// does not depend on it, and tests vary it.
    pub(crate) fn run(mut self, sweep: Option<&[usize]>) -> Resolution<L::Id, L::Class> {
        let n = self.n();
        let canonical: Vec<usize> = (0..n).collect();
        let sweep = sweep.unwrap_or(&canonical);
        loop {
            self.propagate(sweep);
            let undecided: Vec<usize> = (0..n).filter(|&e| !self.decided.contains(e)).collect();
            if undecided.is_empty() {
                break;
            }
            if undecided.len() <= AGREEMENT_LIMIT && self.agree(&undecided) {
                continue;
            }
            self.pick(&undecided);
        }
        self.name_agreed();
        self.finish()
    }

    /// Step 1, propagation, until nothing changes.
    fn propagate(&mut self, sweep: &[usize]) {
        let mut progress = true;
        while progress {
            progress = false;
            for &e in sweep {
                if self.decided.contains(e) || !self.ready(e) {
                    continue;
                }
                if let Some(standing) = self.evaluate(e) {
                    self.decide(e, standing);
                    progress = true;
                }
            }
        }
    }

    /// Step 1 for one event whose contested past is decided: its verdict,
    /// or `None` while an attacker that may count is undecided.
    fn evaluate(&self, e: usize) -> Option<Standing<L::Id, L::Class>> {
        let view = self.view();
        let id = self.contest.ids[e];
        if let Err(class) = self.log.authority(id, &view) {
            return Some(Standing::Void { class, by: None });
        }
        let mut pending = false;
        for &(x, class) in &self.attackers[e] {
            let attacker = &self.slots[x];
            if attacker.is_void() {
                continue;
            }
            match self.log.attack_counts(self.contest.ids[x], id, &view) {
                Some(false) => continue,
                Some(true) if attacker.is_valid() => {
                    return Some(Standing::Void {
                        class,
                        by: Some(self.contest.ids[x]),
                    });
                }
                _ => pending = true,
            }
        }
        (!pending).then_some(Standing::Valid(How::Rules))
    }

    /// Sets each undecided event to the trial `mask` gives it: bit `j` for
    /// `undecided[j]`.
    fn try_assignment(&mut self, undecided: &[usize], mask: u32) {
        for (j, &e) in undecided.iter().enumerate() {
            self.slots[e] = Standing::Trial(mask >> j & 1 == 1);
        }
    }

    /// Step 3, agreement, over at most [`AGREEMENT_LIMIT`] undecided events.
    /// Returns whether it decided any.
    fn agree(&mut self, undecided: &[usize]) -> bool {
        let k = undecided.len();
        debug_assert!(k <= AGREEMENT_LIMIT);
        let all: u32 = (1u32 << k) - 1;
        // The first allowed assignment, and the events on which every allowed
        // assignment so far agrees with it. The trials run with the first
        // undecided event varying slowest, so "first" is the reference
        // code's: it matters only to `agreed_reasons`.
        let mut first: Option<u32> = None;
        let mut same = all;
        for count in 0..=all {
            let mask = (count.reverse_bits() >> (32 - k)) & all;
            self.try_assignment(undecided, mask);
            if undecided.iter().all(|&e| self.allowed(e)) {
                match first {
                    None => first = Some(mask),
                    Some(f) => same &= !(mask ^ f),
                }
                if same == 0 {
                    break; // no event can agree any more
                }
            }
        }
        let agreed = first.filter(|_| same != 0);
        if let Some(first) = agreed {
            // Why each event agreed void is void in the first allowed
            // assignment.
            self.try_assignment(undecided, first);
            for (j, &e) in undecided.iter().enumerate() {
                if same >> j & 1 == 1 && first >> j & 1 == 0 {
                    let reason = self
                        .reason(e)
                        .expect("an event void in an allowed assignment has a reason there");
                    self.agreed_reasons.insert(e, reason);
                }
            }
        }
        for &e in undecided {
            self.slots[e] = Standing::Undecided;
        }
        let Some(first) = agreed else {
            return false;
        };
        for (j, &e) in undecided.iter().enumerate() {
            if same >> j & 1 == 1 {
                let standing = if first >> j & 1 == 1 {
                    Standing::Valid(How::Agreed)
                } else {
                    Standing::AgreedVoid
                };
                self.decide(e, standing);
            }
        }
        true
    }

    /// Whether undecided `e` keeps the status the trial gives it: valid
    /// exactly when its authority holds and no event valid in the trial
    /// attacks it with an attack that counts.
    fn allowed(&self, e: usize) -> bool {
        let view = self.view();
        let id = self.contest.ids[e];
        let holds = self.log.authority(id, &view).is_ok();
        self.slots[e].is_valid() == (holds && self.counting_attacker(e, &view).is_none())
    }

    /// The first attacker of `e`, in canonical order, that is valid and
    /// whose attack counts or may count.
    fn counting_attacker(&self, e: usize, view: &View<'_, L>) -> Option<(usize, L::Class)> {
        let id = self.contest.ids[e];
        self.attackers[e]
            .iter()
            .find(|&&(x, _)| {
                self.slots[x].is_valid()
                    && self.log.attack_counts(self.contest.ids[x], id, view) != Some(false)
            })
            .copied()
    }

    /// Step 4, the seniority pick: the undecided event with a decided
    /// contested past and the smallest pick key is valid.
    fn pick(&mut self, undecided: &[usize]) {
        let ready: Vec<usize> = undecided
            .iter()
            .copied()
            .filter(|&e| self.ready(e))
            .collect();
        // The earliest undecided event always has a decided past, when height
        // extends the causal order.
        debug_assert!(!ready.is_empty());
        let candidates = if ready.is_empty() { undecided } else { &ready };
        let view = self.view();
        let chosen = candidates
            .iter()
            .copied()
            .min_by_key(|&e| self.log.pick_key(self.contest.ids[e], &view))
            .unwrap_or(undecided[0]);
        self.decide(chosen, Standing::Valid(How::Seniority));
    }

    /// Why `e` is void under the current statuses: its authority's class,
    /// or the first valid attacker whose attack counts. `None` if neither.
    fn reason(&self, e: usize) -> Option<Standing<L::Id, L::Class>> {
        let view = self.view();
        if let Err(class) = self.log.authority(self.contest.ids[e], &view) {
            return Some(Standing::Void { class, by: None });
        }
        self.counting_attacker(e, &view)
            .map(|(x, class)| Standing::Void {
                class,
                by: Some(self.contest.ids[x]),
            })
    }

    /// Names each event the agreement step voided: it stays void, with the
    /// reason it had in the first allowed assignment of the step that voided
    /// it (roster.md, 3.7), whatever a later seniority pick decides.
    fn name_agreed(&mut self) {
        for e in 0..self.n() {
            if self.slots[e] != Standing::AgreedVoid {
                continue;
            }
            let standing = self
                .agreed_reasons
                .get(&e)
                .copied()
                .expect("the agreement step recorded a reason");
            self.slots[e] = standing;
        }
    }

    fn finish(self) -> Resolution<L::Id, L::Class> {
        let verdicts = self
            .contest
            .ids
            .iter()
            .zip(&self.slots)
            .map(|(&id, standing)| {
                let verdict = match *standing {
                    Standing::Valid(how) => Verdict::Valid(how),
                    Standing::Void { class, by } => Verdict::Void { class, by },
                    Standing::Undecided | Standing::AgreedVoid | Standing::Trial(_) => {
                        unreachable!("every contested event is decided and named")
                    }
                };
                (id, verdict)
            })
            .collect();
        Resolution {
            verdicts,
            index: self.contest.index,
            contested: self.contest.ids,
        }
    }
}
