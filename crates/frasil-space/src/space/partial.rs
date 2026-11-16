//! A partial replica's write rule (units.md, "Partial replicas"; roster.md,
//! "The write rule").
//!
//! A partial replica judges a unit `u` by the write rule over the space
//! events it holds, counting a space event `x` as in the past of `u` only
//! when the order is proven: a chain of parents through placed and
//! witnessed events, as a `Path` that checks gives ([`Log::proves_before`]).
//! It counts `u` as before an event that ends its writer's write only when
//! such a chain leads from that event down to `u`. A unit whose verdict
//! depends on an order it has not proven is `Pending`, never applied:
//!
//! - **Step 2.** The place is the valid roster events proven in `u`'s past.
//!   With no path there, `NotAWriter` stands only when no valid roster
//!   event of unproven order names a member through which `u`'s writer
//!   might write.
//! - **Step 4.** A valid roster event that ends a path's write and is not
//!   proven after `u` makes the path's fate unproven. Concurrency is never
//!   proven, so this step never refuses: it holds `u` pending when no path
//!   is left that no such event ends.
//! - **Step 5.** A response proven in `u`'s past ends the path, as does one
//!   that is proven not to have `u` in its past; a response of unproven
//!   order holds `u` pending when no path is left that no response ends.
//!
//! Steps 0, 1, 3 and 6 read no order beyond the place. A partial replica
//! sees fork evidence only in its frame and streams, so step 1 may let a
//! forked device's unit stand until the evidence arrives.
//!
//! **Heights.** The roster orders concurrent roster events by height:
//! seniority, the seniority pick and the meet. A partial replica
//! knows a height only when it holds the event's whole past
//! ([`Log::is_height_exact`]). So it resolves the roster only when every two
//! contested roster events are proven ordered or of known heights both: then
//! every order and every height comparison the procedure reads is the one a
//! full replica reads. Until then every event of its view but the genesis
//! is `Pending`, and [`Space::heights_wanted`] names the parents to fetch.

use super::{Replica, Space, Status};
use crate::SpaceClass;
use crate::member::{Level, MemberRef, MemberType};
use frasil_base::ErrorClass;
use frasil_base::collect::CollectMap;
use frasil_events::{EventId, Log};
use std::collections::{BTreeMap, BTreeSet};

/// Where an event stands against `u` in proven order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    /// Proven in `u`'s past.
    Past,
    /// `u` is proven in its past, or it is `u`.
    After,
    /// Neither is proven.
    Unproven,
}

fn order(log: &Log, x: EventId, u: EventId) -> Order {
    if x == u || log.proves_before(u, x) {
        Order::After
    } else if log.proves_before(x, u) {
        Order::Past
    } else {
        Order::Unproven
    }
}

fn pending(by: Option<EventId>) -> Status {
    Status::Void {
        class: ErrorClass::Pending.into(),
        by,
    }
}

impl Space<'_> {
    /// units.md, "Partial replicas", "Heights": holds every event of the
    /// view but the genesis pending while two contested roster events are
    /// neither proven ordered nor of known heights both.
    pub(super) fn hold_for_heights(&mut self) {
        if self.replica != Replica::Partial {
            return;
        }
        let unordered = self.unordered();
        if unordered.is_empty() {
            return;
        }
        self.heights_wanted = self.log.heights_wanted(unordered);
        let genesis = self.log.id();
        for &id in &self.view {
            if id != genesis {
                self.statuses.insert(id, Status::void(ErrorClass::Pending));
            }
        }
        self.valid_roster = BTreeSet::from([genesis]);
        self.roster = self.roster_at(&self.valid_roster);
        let genesis_policy = self.screened.genesis().policy;
        let valid = self.valid_roster.clone();
        self.policy = self.with_places(|places| places.policy(&valid, &genesis_policy));
    }

    /// The contested roster events of a pair that is neither proven ordered
    /// nor of known heights both. A roster event void for want of standing
    /// counts as contested here when some event of the view names its
    /// author at `administer`: the order it has with that event, which
    /// decides its standing (roster.md, 3.7 "Standing"), may be unproven.
    fn unordered(&self) -> BTreeSet<EventId> {
        let log = self.log;
        let unsure: Vec<EventId> = {
            let without = self.without_standing();
            self.with_judge(|judge| {
                without
                    .into_iter()
                    .filter(|&e| !judge.standing_candidates(e).is_empty())
                    .collect()
            })
        };
        let mut contested = self.contested.clone();
        contested.extend(unsure);
        let contested = &contested;
        if contested.iter().all(|&e| log.is_height_exact(e)) {
            return BTreeSet::new();
        }
        let pasts: BTreeMap<EventId, BTreeSet<EventId>> = contested
            .iter()
            .map(|&e| (e, log.proven_past(e)))
            .collect_map();
        let mut out = BTreeSet::new();
        for (i, &a) in contested.iter().enumerate() {
            for &b in &contested[i + 1..] {
                let ordered = pasts[&b].contains(&a) || pasts[&a].contains(&b);
                let known = log.is_height_exact(a) && log.is_height_exact(b);
                if !ordered && !known {
                    out.insert(a);
                    out.insert(b);
                }
            }
        }
        out
    }

    /// The write rule, steps 1 to 7, in proven order.
    pub(super) fn partial_write_rule(&self, u: EventId) -> Status {
        debug_assert_eq!(self.replica, Replica::Partial);
        let event = self.log.event(u).expect("placed");
        let author = &event.author().0;
        let genesis = self.log.id();
        // 1.
        if self.forks.is_void(event) {
            return Status::void(ErrorClass::Forked);
        }
        // The valid roster events whose order against u is not proven.
        let unproven: Vec<EventId> = self
            .log
            .canonical_in(&self.valid_roster)
            .into_iter()
            .filter(|&x| x != genesis && order(self.log, x, u) == Order::Unproven)
            .collect();
        // 2. The place is the proven past.
        let roster = self.roster_at(&self.place_of(u));
        let (paths, unknown) = self.paths_at_event(author, &roster, Level::Write, u);
        if paths.is_empty() {
            if unknown {
                return pending(None);
            }
            if let Some(&x) = unproven.iter().find(|&&x| self.might_grant(x, author)) {
                return pending(Some(x));
            }
            return Status::void(SpaceClass::NotAWriter);
        }
        let key = self.is_key(u);
        // 3.
        if key && self.all_waiting(&paths, author) {
            return Status::void(SpaceClass::WaitingDevice);
        }
        // 4. Never proven concurrent: an end of unproven order holds u.
        let ending: Vec<(EventId, std::collections::BTreeSet<MemberRef>)> = unproven
            .iter()
            .map(|&x| (x, self.lowered(x)))
            .filter(|(_, lowered)| !lowered.is_empty())
            .collect();
        let remaining: Vec<MemberRef> = paths
            .iter()
            .copied()
            .filter(|m| !ending.iter().any(|(_, lowered)| lowered.contains(m)))
            .collect();
        if remaining.is_empty() {
            let by = ending
                .iter()
                .find(|(_, lowered)| paths.iter().any(|m| lowered.contains(m)))
                .map(|(x, _)| *x);
            return pending(by);
        }
        // 5.
        let mut ended_by = None;
        let mut unproven_by = None;
        let mut alive = Vec::new();
        for member in &remaining {
            let mut ended = None;
            let mut uncertain = None;
            for end in self.path_ends(member, author) {
                for k in self.responses(&end, author) {
                    match order(self.log, k, u) {
                        Order::After => {}
                        Order::Past => {
                            ended.get_or_insert(k);
                        }
                        Order::Unproven => {
                            uncertain.get_or_insert(k);
                        }
                    }
                }
            }
            match (ended, uncertain) {
                (Some(k), _) => {
                    ended_by.get_or_insert(k);
                }
                (None, Some(k)) => {
                    unproven_by.get_or_insert(k);
                }
                (None, None) => alive.push(*member),
            }
        }
        if alive.is_empty() {
            return match (unproven_by, ended_by) {
                (Some(k), _) => pending(Some(k)),
                (None, Some(k)) if unknown => pending(Some(k)),
                (None, Some(k)) => Status::by(SpaceClass::RefusedAfterResponse, k),
                (None, None) => unreachable!("a path was ended"),
            };
        }
        // 6.
        if key && let Err(class) = self.key_context(u, &roster, &alive) {
            return Status::void(class);
        }
        // 7.
        Status::Valid(super::Valid::Rules)
    }

    /// Whether a roster event names a member through which `device` might
    /// write: the device itself, a person whose held list makes it a
    /// writer, a space through which it propagates, or a person or a space
    /// whose log this replica does not hold. An invite member counts.
    fn might_grant(&self, x: EventId, device: &[u8; 32]) -> bool {
        self.changes(x)
            .iter()
            .filter_map(|c| c.member)
            .any(|m| match m.kind {
                MemberType::Device => m.id == *device,
                MemberType::Person => self
                    .options
                    .others
                    .list(&m.id)
                    .is_none_or(|list| list.writers().contains(device)),
                MemberType::Space => self
                    .options
                    .others
                    .space(&EventId(m.id))
                    .is_none_or(|space| space.propagating_writers().contains(device)),
                MemberType::Invite => true,
            })
    }
}
