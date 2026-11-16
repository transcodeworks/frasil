//! What replicas derive from a resolved view (roster.md, "What replicas
//! derive", and "Checks across logs", "Frontiers").
//!
//! - **The valid set**, **the roster at any place** and **the maximal valid
//!   rotations**, which keys.md takes from here.
//! - **The events that void an event** ([`Space::voiders`]).
//! - **Frontiers** ([`Space::frontier`]): derived, never written.
//! - **Stability** ([`Space::stable`]) and **keeping refused units**
//!   ([`Space::retention`]).
//! - **Duels** ([`Space::duels`], [`Space::voided_by`]) and
//!   **re-submission** ([`Space::resubmissions`]).

use crate::attacks::{self, Side};
use crate::member::{Level, MemberRef, MemberType};
use crate::space::{Retention, Space, Status, refused_unit};
use crate::{RosterClass, SpaceClass};
use frasil_base::ErrorClass;
use frasil_base::time::Reading;
use frasil_crypto::device::DeviceId;
use frasil_events::{EventId, kind};

/// The author of an event a view does not hold: no device.
const NO_AUTHOR: DeviceId = DeviceId([0; 32]);
use std::collections::{BTreeMap, BTreeSet};

impl<'a> Space<'a> {
    fn canonical(&self, ids: impl IntoIterator<Item = EventId>) -> Vec<EventId> {
        let set: BTreeSet<EventId> = ids.into_iter().collect();
        self.log().canonical_in(&set)
    }

    fn side(&self, id: EventId) -> Side<'_> {
        Side {
            author: self.log().event(id).map_or(&NO_AUTHOR, |e| e.author()),
            changes: self.opened(id).map_or(&[], |o| o.changes()),
        }
    }

    /// Whether roster event `x` attacks roster event `e` with an attack
    /// that counts (roster.md, 3.5.2 What attacks what): in a mutual pair,
    /// exactly when `x`'s author outranks `e`'s, each at its own event's
    /// place.
    fn attacks_counting(&self, x: EventId, e: EventId) -> bool {
        let log = self.log();
        let concurrent = log.concurrent(x, e);
        if attacks::attack(self.side(x), self.side(e), concurrent).is_some()
            && attacks::mutual(self.side(x), self.side(e), concurrent)
        {
            return self.outranks_at(x, e) == Some(true);
        }
        attacks::attack(self.side(x), self.side(e), concurrent).is_some_and(|class| {
            attacks::counts(
                (x, self.side(x)),
                (e, self.side(e)),
                concurrent,
                class,
                self.shields(),
            )
        })
    }

    /// The author of `event`'s state at its place: its member's (an invite
    /// key's for a successor), if it is in there.
    pub fn author_state_at(&self, event: EventId) -> Option<crate::state::MemberState> {
        let roster = self.roster_at(&self.place_of(event));
        roster.state(&self.side(event).author_member()).cloned()
    }

    /// Whether `x`'s author outranks `e`'s author, each at its own event's
    /// place (roster.md, 3.2 "Outranks"): the higher rank, then the more
    /// senior. `None` when either is not in at its place.
    pub fn outranks_at(&self, x: EventId, e: EventId) -> Option<bool> {
        let a = self.author_state_at(x)?;
        let b = self.author_state_at(e)?;
        Some(a.outranks(&b))
    }

    /// The rank of a member in the roster of this view, if it is an
    /// administrator (roster.md, 2.3 Changes, "Ranks").
    pub fn rank(&self, member: &MemberRef) -> Option<u8> {
        self.roster().state(member).and_then(|state| state.rank)
    }

    /// Whether administrator `a` outranks administrator `b` in the roster of
    /// this view: a higher rank, or the same rank and the more senior
    /// (roster.md, 3.2 "Outranks"). `None` unless both are in.
    pub fn outranks(&self, a: &MemberRef, b: &MemberRef) -> Option<bool> {
        let roster = self.roster();
        Some(roster.state(a)?.outranks(roster.state(b)?))
    }

    /// The duels' shields among the contested events, found once.
    fn shields(&self) -> &attacks::Shields {
        self.shields_cell().get_or_init(|| {
            let log = self.log();
            attacks::Shields::new(
                self.contested(),
                |a, b| log.concurrent(a, b),
                |a, b| log.precedes(a, b),
                |id| self.side(id),
            )
        })
    }

    /// The maximal valid rotations: the valid events whose body rotates,
    /// the genesis among them, that no other valid rotation follows, in
    /// canonical order.
    pub fn rotations(&self) -> Vec<EventId> {
        let rotations: Vec<EventId> = self
            .valid()
            .into_iter()
            .filter(|&id| self.opened(id).is_some_and(|o| o.visible.rotates()))
            .collect();
        rotations
            .iter()
            .copied()
            .filter(|&r| !rotations.iter().any(|&o| self.log().precedes(r, o)))
            .collect()
    }

    /// The administrators of the merged roster that have not forked, by
    /// device ID.
    pub fn administrators(&self) -> Vec<[u8; 32]> {
        self.roster()
            .administrators()
            .filter(|a| self.forks().fork_point(&DeviceId(**a)).is_none())
            .copied()
            .collect()
    }

    /// Whether a set of events is **stable** in this view: every
    /// administrator of the merged roster that has not forked has a valid
    /// event of this log, of a kind below 64, whose past holds every event
    /// of the set, or that is one of them. A skeleton event counts as an
    /// event of the device its pseudonym's binding names.
    pub fn stable(&self, targets: &[EventId]) -> bool {
        let log = self.log();
        let mine: Vec<EventId> = self
            .valid()
            .into_iter()
            .filter(|&id| {
                log.event(id)
                    .is_some_and(|e| e.kind() < kind::FIRST_IGNORABLE)
            })
            .collect();
        self.administrators().iter().all(|a| {
            mine.iter().any(|&i| {
                self.device_of(i) == Some(*a)
                    && targets.iter().all(|&t| t == i || log.precedes(t, i))
            })
        })
    }

    /// Whether a voiding is stable: the voided event and every event that
    /// voids it are.
    pub fn voiding_stable(&self, voided: EventId) -> bool {
        let mut targets = self.voiders(voided);
        targets.push(voided);
        self.stable(&targets)
    }

    /// `refused_unit` for a refused unit of this view: whether this
    /// replica keeps its content (roster.md, "Keeping refused units").
    /// `own` says whether this device is its author; `first_sight` is this
    /// device's first sight of the refusing event. `None` for an event that
    /// is not a refused write.
    pub fn retention(
        &self,
        unit: EventId,
        own: bool,
        first_sight: &Reading,
        now: &Reading,
    ) -> Option<Retention> {
        let Some(Status::Void { by: Some(by), .. }) = self.status(unit) else {
            return None;
        };
        Some(refused_unit(
            own,
            self.stable(&[*by]),
            first_sight,
            now,
            self.policy().gap_key_timeout,
        ))
    }

    /// The events that void a void event, in canonical order (roster.md,
    /// "The events that void an event"):
    ///
    /// - an attacked roster event: every valid event that attacks it,
    ///   mutual partners left out;
    /// - a refused unit or key event: the event that ends its write, or the
    ///   response;
    /// - a forked event: the two events of each evidence of its author's
    ///   fork;
    /// - with ext-invite-links.md, a raced successor: the successors it
    ///   races;
    /// - a failed authority (`NotAnAdministrator`, `AlreadyMember`,
    ///   `NoSuchMember`, `NotAMember`, `NotAWriter`): found the same way
    ///   for the void roster events in its past that name its author's
    ///   device or its own members;
    /// - otherwise none.
    pub fn voiders(&self, event: EventId) -> Vec<EventId> {
        let mut seen = BTreeSet::new();
        self.voiders_within(event, &mut seen)
    }

    fn voiders_within(&self, event: EventId, seen: &mut BTreeSet<EventId>) -> Vec<EventId> {
        let Some(&Status::Void { class, by }) = self.status(event) else {
            return Vec::new();
        };
        if !seen.insert(event) {
            return Vec::new();
        }
        let log = self.log();
        let author = *log.event(event).expect("placed").author();
        if class == RosterClass::from(ErrorClass::Forked) {
            // An event counts once its signature verified, at placement or
            // at step 11.
            let screened = self.screened();
            let evidence = log.evidence_counting_in(self.view(), |id| {
                (log.is_verified(id)
                    || screened.signature(id) == Some(crate::screen::Signature::Verified))
                    && self.accepted(id)
            });
            return self.canonical(
                evidence
                    .iter()
                    .filter(|item| item.author == author)
                    .flat_map(|item| [item.first, item.second]),
            );
        }
        // ext-invite-links.md: a raced successor is voided by the successors
        // it races.
        #[cfg(feature = "ext-invite-links")]
        if let Some(racers) = crate::ext_invite_links::racers(self, event, class) {
            return racers;
        }
        if by.is_some() && self.is_roster(event) {
            return self
                .contested()
                .iter()
                .copied()
                .filter(|&x| self.is_valid(x) && self.attacks_counting(x, event))
                .collect();
        }
        if let Some(by) = by {
            return vec![by];
        }
        let authority = [
            RosterClass::from(ErrorClass::NotAnAdministrator),
            SpaceClass::AlreadyMember.into(),
            SpaceClass::NoSuchMember.into(),
            ErrorClass::NotAMember.into(),
            SpaceClass::NotAWriter.into(),
        ];
        if !authority.contains(&class) {
            return Vec::new();
        }
        let mut who: BTreeSet<MemberRef> = BTreeSet::from([MemberRef::device(author)]);
        who.extend(self.side(event).changes.iter().filter_map(|c| c.member));
        let mut out = BTreeSet::new();
        for p in log.canonical_in(self.view()) {
            if !log.precedes(p, event) || !self.is_roster(p) || self.is_valid(p) {
                continue;
            }
            // For a unit or key event, also a person whose list holds its
            // author: a grant of it the author could have written through
            // (roster.md, 3.14, "The events that void an event").
            let roster_event = self.is_roster(event);
            let names = self.side(p).changes.iter().any(|c| {
                c.member.is_some_and(|m| {
                    who.contains(&m)
                        || (!roster_event
                            && m.kind == MemberType::Person
                            && self
                                .options()
                                .others
                                .list(&m.id)
                                .is_some_and(|list| list.writers().contains(&author.0))
                            && self.list_add_at(&m.id, &author.0, event))
                })
            });
            if names {
                out.extend(self.voiders_within(p, seen));
            }
        }
        self.canonical(out)
    }

    /// The **frontier** of a valid event that ends a member's write: for
    /// each device that wrote through a member it removes or demotes to
    /// `read`, its latest accepted event in the event's past (roster.md,
    /// "Frontiers").
    pub fn frontier(&self, x: EventId) -> BTreeMap<[u8; 32], EventId> {
        let mut devices = BTreeSet::new();
        for member in self.lowered(x) {
            match member.kind {
                MemberType::Device => {
                    devices.insert(member.id);
                }
                MemberType::Person => {
                    if let Some(list) = self.options().others.list(&member.id) {
                        devices.extend(list.writers());
                    }
                }
                MemberType::Space => {
                    if let Some(space) = self.options().others.space(&EventId(member.id)) {
                        devices.extend(space.propagating_writers());
                    }
                }
                _ => {}
            }
        }
        self.heads_of(&devices, x)
    }

    /// Every valid roster event that ends a member's write, other than the
    /// genesis, in canonical order, with its frontier.
    pub fn frontiers(&self) -> Vec<(EventId, BTreeMap<[u8; 32], EventId>)> {
        self.log()
            .canonical_in(self.valid_roster())
            .into_iter()
            .filter(|&x| x != self.log().id() && !self.lowered(x).is_empty())
            .map(|x| (x, self.frontier(x)))
            .collect()
    }

    /// For each device, its latest accepted event in an event's past: the
    /// greatest `seq`, then the greatest ID.
    pub fn heads_of(
        &self,
        devices: &BTreeSet<[u8; 32]>,
        event: EventId,
    ) -> BTreeMap<[u8; 32], EventId> {
        let log = self.log();
        let mut out = BTreeMap::new();
        for device in devices {
            let head = log
                .canonical_in(self.view())
                .into_iter()
                .filter(|&i| log.precedes(i, event) && self.accepted(i))
                .filter_map(|i| log.event(i).map(|e| (e, i)))
                .filter(|(e, _)| e.author().0 == *device)
                .map(|(e, i)| (e.seq(), i))
                .max();
            if let Some((_, id)) = head {
                out.insert(*device, id);
            }
        }
        out
    }

    /// The duels (roster.md, 3.14, "Duels"): each mutual pair of contested
    /// events one side of which is valid, the outranking author's, in
    /// canonical order.
    pub fn duels(&self) -> Vec<(EventId, EventId)> {
        let contested = self.contested();
        let mut out = Vec::new();
        for (n, &a) in contested.iter().enumerate() {
            for &b in &contested[n + 1..] {
                if (self.is_valid(a) || self.is_valid(b))
                    && attacks::mutual(self.side(a), self.side(b), self.log().concurrent(a, b))
                {
                    out.push((a, b));
                }
            }
        }
        out
    }

    /// The attempts on a higher rank (roster.md, 3.14, "Duels"): the roster
    /// events void as `HigherRank`, in canonical order. They are no duel; a
    /// client lists them apart.
    pub fn rank_attempts(&self) -> Vec<EventId> {
        let higher = RosterClass::from(SpaceClass::HigherRank);
        let ids = self
            .view()
            .iter()
            .copied()
            .filter(|&id| self.is_roster(id))
            .filter(|&id| self.status(id).and_then(Status::class) == Some(higher));
        self.canonical(ids)
    }

    /// What one side of a duel voided: every event not after `side` that is
    /// void in this view and valid in the view without `side` and
    /// everything after it, in canonical order.
    ///
    /// # Errors
    ///
    /// As [`Space::resolve`], for the view without `side`.
    pub fn voided_by(&self, side: EventId) -> Result<Vec<EventId>, RosterClass> {
        let log = self.log();
        let without: BTreeSet<EventId> = self
            .view()
            .iter()
            .copied()
            .filter(|&i| i != side && !log.precedes(side, i))
            .collect();
        let other = Space::resolve_as(log, Some(&without), self.options(), self.replica())?;
        Ok(log
            .canonical_in(&without)
            .into_iter()
            .filter(|&i| other.is_valid(i) && !self.is_valid(i))
            .collect())
    }

    /// **Re-submission** (roster.md, 3.14): each device's refused units,
    /// in canonical order, once it again writes through some path of the
    /// merged roster and has not forked: those refused by a removal or a
    /// response, and those refused as `NotAWriter`, exactly when some events
    /// void them ([`Self::voiders`]). One no event voids, whose author held
    /// there no grant an event voided, was never a writer's.
    pub fn resubmissions(&self) -> BTreeMap<[u8; 32], Vec<EventId>> {
        let log = self.log();
        let refused = [
            RosterClass::from(SpaceClass::RefusedByRemoval),
            SpaceClass::RefusedAfterResponse.into(),
            SpaceClass::NotAWriter.into(),
        ];
        let mut out: BTreeMap<[u8; 32], Vec<EventId>> = BTreeMap::new();
        for id in log.canonical_in(self.view()) {
            let event = log.event(id).expect("placed");
            let Some(class) = self.status(id).and_then(Status::class) else {
                continue;
            };
            if event.kind() != kind::UNIT {
                continue;
            }
            if !refused.contains(&class) || self.voiders(id).is_empty() {
                continue;
            }
            let author = event.author().0;
            let writes = !self
                .paths(&author, self.roster(), Level::Write)
                .0
                .is_empty();
            if writes && self.forks().fork_point(&DeviceId(author)).is_none() {
                out.entry(author).or_default().push(id);
            }
        }
        out
    }
}
