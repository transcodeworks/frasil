//! A resolved [`Space`] as the key graph's [`History`]: its view, its valid
//! set, its roster at any place, the devices of its members as the other
//! logs give them, and the granted spaces it holds.
//!
//! **Rooted at a checkpoint** (keys.md, "Keys after a checkpoint"): a space
//! resolved as a checkpoint's world ([`crate::KeyWorld`]) is read as a key
//! graph rooted at the checkpoint ([`SpaceHistory::rooted`]). The checkpoint
//! stands as the genesis; the rotations counted are it and those after it
//! ([`frasil_keys::checkpoint::counts`]), so the current state is
//! [`frasil_keys::checkpoint::world_state`]; the space's genesis, which the
//! world's log keeps as the source of its descriptor, takes no part. A
//! replica that holds everything and one that forgot read the same graph.
//! A space with no checkpoint in effect is read as it always was.

use super::graph::KeyGraph;
use super::notices::GrantedNotices;
use super::view::{EventFacts, Grant, History, Membership, NoticeFacts, Role, Rotation};
use crate::change::Op;
use crate::member::{HistoryMode, MemberRef, MemberType};
use crate::space::Space;
use frasil_base::collect::CollectMap;
use frasil_crypto::device::DeviceId;
use frasil_events::{EventId, kind};
use frasil_keys::RotationSet;
use frasil_keys::checkpoint::{
    KeptState, MemberAfter, Rooted, Side, Sides, counts, counts_artifact, entitled_before,
};
use std::collections::{BTreeMap, BTreeSet};

/// A resolved space, read by the key graph.
pub struct SpaceHistory<'s, 'a> {
    space: &'s Space<'a>,
    facts: BTreeMap<EventId, EventFacts<[u8; 32], MemberRef>>,
    /// The notices that admit their principals here, by event.
    admitted: BTreeSet<(EventId, NoticeFacts)>,
    /// Where each event stands against the checkpoint, when the space is a
    /// checkpoint's world.
    rooted: Option<Sides>,
}

impl core::fmt::Debug for SpaceHistory<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpaceHistory")
            .field("space", &self.space.log().id())
            .finish_non_exhaustive()
    }
}

impl<'s, 'a> SpaceHistory<'s, 'a> {
    /// What the key graph reads of every event of the space's view, with no
    /// unit's key reference: [`Self::with_units`] reads them.
    pub fn new(space: &'s Space<'a>) -> Self {
        Self::with_units(space, |_| None)
    }

    /// [`Self::new`], with each unit's key reference as `unit_state` reads
    /// it from the unit's visible body (units.md, "The visible
    /// body"), which this crate does not parse.
    pub fn with_units(
        space: &'s Space<'a>,
        unit_state: impl Fn(&frasil_events::Event) -> Option<frasil_keys::RotationSet>,
    ) -> Self {
        let log = space.log();
        let genesis = log.id();
        let rooted = space.world().map(|world| {
            let mut sides = Sides::new(world.root);
            for &id in space.view() {
                // The genesis stands in the checkpoint's past; every other
                // event of a world follows the checkpoint.
                sides.insert(
                    id,
                    if id == genesis {
                        Side::Before
                    } else {
                        Side::After
                    },
                );
            }
            sides
        });
        let mut facts = BTreeMap::new();
        let mut admitted = BTreeSet::new();
        let notices = GrantedNotices::new(space.options().others);
        for &id in space.view() {
            let event = log.event(id).expect("a view's events are placed");
            let role = match (event.kind(), space.opened(id)) {
                (kind::SPACE, Some(_)) if id == genesis => Role::Genesis,
                (kind::SPACE, Some(opened)) if opened.is_roster() => Role::Roster,
                (kind::SPACE, Some(_)) => Role::Key,
                (kind::UNIT, _) => Role::Unit,
                _ => Role::Other,
            };
            let mut f = EventFacts::new(event.author().0, role);
            if role == Role::Unit {
                f.key_reference = unit_state(event);
            }
            if let Some(opened) = space.opened(id) {
                f.key_reference = f
                    .key_reference
                    .or_else(|| opened.visible.sealed_under().cloned());
                if opened.visible.rotates() {
                    f.rotation = Some(Rotation {
                        grant: opened.inner.grant_rotation(),
                        is_break: opened.inner.is_break,
                    });
                }
                for change in opened.changes() {
                    let Some(member) = change.member else {
                        continue;
                    };
                    match change.op {
                        Op::Grant => f.grants.push(Grant {
                            member,
                            with_history: change.history != Some(HistoryMode::FromNowOn),
                            session: change.session.is_some(),
                        }),
                        Op::Remove => f.removes.push(member),
                        _ => {}
                    }
                }
                #[cfg(feature = "ext-invite-links")]
                {
                    f.successor =
                        crate::ext_invite_links::succession(&event.author().0, opened.changes());
                }
                for n in &opened.inner.notices {
                    let notice = NoticeFacts {
                        space: n.space,
                        rotation: n.rotation,
                        from_now_on: n.from_now_on,
                    };
                    if notices.admits(&event.author().0, n) {
                        admitted.insert((id, notice));
                    }
                    f.notices.push(notice);
                }
            }
            f.refs = space.refs_of(id).to_vec();
            // The root of a checkpoint's world carries its record's notices,
            // each by the author the record names, and names the record's
            // `named` IDs in its refs (roster.md, 3.15.5).
            if let Some(world) = space.world()
                && world.root == id
            {
                f.notices.clear();
                for (granted, recorded) in &world.notices {
                    let notice = recorded.notice(*granted);
                    let facts = NoticeFacts {
                        space: *granted,
                        rotation: recorded.rotation,
                        from_now_on: recorded.from_now_on,
                    };
                    if notices.admits(&recorded.author.0, &notice) {
                        admitted.insert((id, facts));
                    }
                    f.notices.push(facts);
                }
                f.refs = world.named.clone();
            }
            facts.insert(id, f);
        }
        Self {
            space,
            facts,
            admitted,
            rooted,
        }
    }

    /// Where the events stand against the checkpoint the key graph is
    /// rooted at, when the space is a checkpoint's world; `None` otherwise.
    pub fn rooted(&self) -> Option<&Sides> {
        self.rooted.as_ref()
    }

    /// Whether `member` is entitled to `state`, a state before the
    /// checkpoint the key graph is rooted at
    /// ([`frasil_keys::checkpoint::entitled_before`]): through a valid "with
    /// history" grant after the checkpoint, or, at a replica that holds the
    /// past, as `kept`, its judgement over that past, says. A replica that
    /// forgot the past passes none. `None` when the
    /// key graph is not rooted at a checkpoint, or `state` is no state
    /// before it.
    pub fn entitled_before(
        &self,
        valid: &BTreeSet<EventId>,
        member: &MemberRef,
        state: &RotationSet,
        kept: Option<&KeptState<MemberRef>>,
    ) -> Option<bool> {
        let rooted = self.rooted.as_ref()?;
        let root = rooted.checkpoint();
        let after = valid
            .iter()
            .filter(|&&id| id != root && rooted.side(&id) == Side::After)
            .filter_map(|id| self.facts.get(id));
        let mut with_history_after = false;
        let mut removed = false;
        for facts in after {
            with_history_after |= facts
                .grants
                .iter()
                .any(|g| g.member == *member && g.with_history && !g.session);
            removed |= facts.removes.contains(member);
        }
        let in_record = self
            .space
            .world()
            .is_some_and(|world| world.states.contains_key(member));
        let after = MemberAfter {
            with_history_after,
            in_from_record: in_record && !removed,
            floor: false,
        };
        entitled_before(rooted, state, member, after, kept)
    }

    /// The space.
    pub fn space(&self) -> &'s Space<'a> {
        self.space
    }

    /// The key graph of the space's view and its valid set.
    pub fn key_graph(&self) -> KeyGraph<'_, Self> {
        KeyGraph::new(self, self.space.valid().into_iter().collect())
    }
}

impl History for SpaceHistory<'_, '_> {
    type Device = [u8; 32];
    type Member = MemberRef;

    fn space(&self) -> EventId {
        self.space.log().id()
    }

    /// The space's genesis; in a checkpoint's world, the checkpoint.
    fn genesis(&self) -> EventId {
        self.space.root()
    }

    /// The view; in a checkpoint's world, the events whose artifacts and
    /// rotations count there, the checkpoint and those after it.
    fn events(&self) -> BTreeSet<EventId> {
        match &self.rooted {
            None => self.space.view().clone(),
            Some(rooted) => self
                .space
                .view()
                .iter()
                .copied()
                .filter(|id| counts(rooted, id) && counts_artifact(rooted.side(id)))
                .collect(),
        }
    }

    fn facts(&self, id: EventId) -> &EventFacts<[u8; 32], MemberRef> {
        &self.facts[&id]
    }

    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        // The log's order, read from the view's space pasts where the
        // resolution found them.
        self.space.precedes(earlier, later)
    }

    fn roster(&self, place: &BTreeSet<EventId>) -> BTreeMap<MemberRef, Membership> {
        let roster_events: BTreeSet<EventId> = place
            .iter()
            .copied()
            .filter(|&e| e == self.genesis() || self.space.is_roster(e))
            .collect();
        self.space
            .roster_at(&roster_events)
            .members_in()
            .map(|(m, state)| {
                (
                    *m,
                    Membership {
                        level: state.level,
                        with_history: state.history == HistoryMode::WithHistory,
                        session: state.session.is_some(),
                        grants: state.grants.iter().copied().collect(),
                    },
                )
            })
            .collect_map()
    }

    /// A person's devices are the active devices, passkey members and
    /// recovery keys of its merged list ([`HeldList::key_devices`]). A
    /// device whose chain forked counts as removed: it is never inside and
    /// receives no wraps.
    ///
    /// [`HeldList::key_devices`]: crate::HeldList::key_devices
    fn devices(&self, member: &MemberRef) -> Vec<[u8; 32]> {
        let forked = |d: &[u8; 32]| self.space.forks().fork_point(&DeviceId(*d)).is_some();
        match member.kind {
            MemberType::Device if !forked(&member.id) => vec![member.id],
            // ext-invite-links.md: an invite key receives wraps with itself
            // as the recipient device ID.
            #[cfg(feature = "ext-invite-links")]
            MemberType::Invite if !forked(&member.id) => vec![member.id],
            MemberType::Person => self
                .space
                .options()
                .others
                .list(&member.id)
                .map(|list| {
                    list.key_devices()
                        .into_iter()
                        .filter(|d| !forked(d))
                        .collect()
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn wrapped_for(&self, member: &MemberRef, delivery: EventId) -> Vec<[u8; 32]> {
        let known_forked = |d: &[u8; 32]| self.space.fork_known_at(d, delivery);
        match member.kind {
            MemberType::Device if !known_forked(&member.id) => vec![member.id],
            #[cfg(feature = "ext-invite-links")]
            MemberType::Invite if !known_forked(&member.id) => vec![member.id],
            MemberType::Person => self
                .space
                .options()
                .others
                .list(&member.id)
                .map(|list| {
                    list.writers()
                        .into_iter()
                        .chain(list.recovery_keys())
                        .filter(|d| {
                            !known_forked(d) && !self.space.end_answered_at(member, d, delivery)
                        })
                        .collect()
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    fn space_of(&self, member: &MemberRef) -> Option<EventId> {
        (member.kind == MemberType::Space).then_some(EventId(member.id))
    }

    /// identity.md, "What a list vouches for": a person's list member that
    /// waits receives nothing (until, under ext-recovery-agent.md, this
    /// replica vouches for it in the space), and where the space's policy
    /// forbids agents, no device of a person whose merged list holds an
    /// active agent receives anything.
    fn receives(&self, member: &MemberRef, device: &[u8; 32]) -> bool {
        // ext-restricted-spaces.md: a device outside a restricted space's
        // parent receives nothing of it.
        #[cfg(feature = "ext-restricted-spaces")]
        if matches!(member.kind, MemberType::Device | MemberType::Person)
            && !crate::ext_restricted_spaces::receives(self.space, device)
        {
            return false;
        }
        if member.kind != MemberType::Person {
            return true;
        }
        self.space
            .options()
            .others
            .list(&member.id)
            .is_none_or(|list| list.receives_under(device, self.space.policy()))
    }

    /// identity.md, "Kinds of list member": a person's recovery key never
    /// writes.
    fn writes(&self, member: &MemberRef, device: &[u8; 32]) -> bool {
        member.kind != MemberType::Person
            || self
                .space
                .options()
                .others
                .list(&member.id)
                .is_none_or(|list| !list.is_recovery_key(device))
    }

    fn voiders(&self, _valid: &BTreeSet<EventId>, removal: EventId) -> Vec<EventId> {
        self.space.voiders(removal)
    }

    fn stable(&self, _valid: &BTreeSet<EventId>, removal: EventId) -> bool {
        self.space.voiding_stable(removal)
    }

    fn grantee_le(&self, space: EventId, earlier: EventId, rotation: EventId) -> Option<bool> {
        let granted = self.space.options().others.space(&space)?;
        granted
            .holds(rotation)
            .then(|| earlier == rotation || granted.precedes(earlier, rotation))
    }

    fn grantee_rotation(&self, space: EventId, event: EventId) -> Option<bool> {
        let granted = self.space.options().others.space(&space)?;
        if !granted.holds(event) {
            return None;
        }
        Some(
            granted
                .rotation(event)
                .is_some_and(|r| r.valid && r.grant_commitment.is_some()),
        )
    }

    fn principal_devices(&self, space: EventId, rotation: EventId) -> Vec<[u8; 32]> {
        self.space
            .options()
            .others
            .space(&space)
            .map(|granted| granted.grant_holders(rotation).into_iter().collect())
            .unwrap_or_default()
    }

    fn grantee_current(&self, space: EventId) -> Option<BTreeSet<[u8; 32]>> {
        self.space
            .options()
            .others
            .space(&space)
            .map(|granted| granted.propagating())
    }

    fn admits(&self, event: EventId, notice: &NoticeFacts) -> bool {
        self.admitted.contains(&(event, *notice))
    }

    fn world_root(&self) -> Option<EventId> {
        self.space.world().map(|world| world.root)
    }

    fn record_floor(&self, space: EventId) -> bool {
        self.space
            .world()
            .is_some_and(|world| world.floors.contains(&space))
    }

    #[cfg(feature = "ext-invite-links")]
    fn record_raced(&self) -> Vec<MemberRef> {
        self.space
            .world()
            .map(|world| world.raced.iter().copied().collect())
            .unwrap_or_default()
    }

    #[cfg(feature = "ext-invite-links")]
    fn void_as_raced(&self, successor: EventId) -> bool {
        crate::ext_invite_links::void_as_raced(self.space, successor)
    }

    #[cfg(feature = "ext-restricted-spaces")]
    fn counts_outside(&self, device: &[u8; 32]) -> bool {
        crate::ext_restricted_spaces::counts_outside(self.space, device)
    }
}
