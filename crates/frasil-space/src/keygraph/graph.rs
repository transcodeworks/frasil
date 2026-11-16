//! The current state, the merged roster with its space principals, the
//! inside, entitlement and the link gate (keys.md, "Notices and space
//! principals", "The current state and the inside", "Entitlement and the
//! link gate", "Restored members").

use super::Kind;
use super::view::{EventFacts, History, Membership, Role};
use crate::member::Level;
use frasil_base::collect::CollectMap;
use frasil_events::EventId;
use frasil_keys::RotationSet;
use frasil_keys::derive::{Secret, SecretKind, state_secret};
use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

/// A space principal: a granted space and one of its grant rotations, the
/// pair a valid notice names (keys.md, "Notices and space principals"). Its
/// devices are the devices of the granted space that hold that rotation's
/// grant seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Principal {
    /// The granted space, T.
    pub space: EventId,
    /// The grant rotation of T, `R`.
    pub rotation: EventId,
}

/// A member of the merged roster: a member of the roster, or a space
/// principal, which stands for the space member that the roster grants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Member<M> {
    /// A member of the roster: a device or a person.
    Roster(M),
    /// A space principal.
    Principal(Principal),
}

/// A roster with its space principals: each member and its state.
pub type Roster<M> = BTreeMap<Member<M>, Membership>;

/// The key graph of one view: its events `W`, its valid set `V`, and what
/// keys.md derives from them.
pub struct KeyGraph<'h, H: History> {
    history: &'h H,
    events: BTreeSet<EventId>,
    valid: BTreeSet<EventId>,
    rosters: RefCell<RosterCache<H::Member>>,
    entitled: RefCell<BTreeMap<EntitledKey<H::Member>, bool>>,
    floors: OnceCell<BTreeMap<Principal, Vec<EventId>>>,
}

type EntitledKey<M> = (BTreeSet<EventId>, Member<M>, RotationSet, Kind);
type RosterCache<M> = BTreeMap<BTreeSet<EventId>, Rc<Roster<M>>>;

impl<H: History> core::fmt::Debug for KeyGraph<'_, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyGraph")
            .field("space", &self.history.space())
            .field("events", &self.events.len())
            .field("valid", &self.valid.len())
            .finish_non_exhaustive()
    }
}

impl<'h, H: History> KeyGraph<'h, H> {
    /// The key graph of a view whose valid set roster.md decided.
    pub fn new(history: &'h H, valid: BTreeSet<EventId>) -> Self {
        let events = history.events();
        let valid = valid.intersection(&events).copied().collect();
        Self {
            history,
            events,
            valid,
            rosters: RefCell::new(BTreeMap::new()),
            entitled: RefCell::new(BTreeMap::new()),
            floors: OnceCell::new(),
        }
    }

    /// The view.
    pub fn history(&self) -> &'h H {
        self.history
    }

    /// The events the view holds, `W`.
    pub fn events(&self) -> &BTreeSet<EventId> {
        &self.events
    }

    /// The valid set, `V`.
    pub fn valid(&self) -> &BTreeSet<EventId> {
        &self.valid
    }

    pub(crate) fn facts(&self, id: EventId) -> &'h EventFacts<H::Device, H::Member> {
        self.history.facts(id)
    }

    // -- Order

    /// `a` is `b` or in its past.
    pub fn le(&self, a: EventId, b: EventId) -> bool {
        a == b || self.history.precedes(a, b)
    }

    /// The events of the view in the past of a state's rotations, those
    /// rotations included.
    pub fn closure(&self, state: &RotationSet) -> BTreeSet<EventId> {
        self.events
            .iter()
            .copied()
            .filter(|&e| state.ids().iter().any(|&r| self.le(e, r)))
            .collect()
    }

    /// Whether an event of the view is a rotation of this graph: the
    /// genesis, or a roster event or key event that rotates; for the grant
    /// graph, a grant rotation.
    pub fn is_rotation(&self, id: EventId, kind: Kind) -> bool {
        self.facts(id)
            .rotation
            .is_some_and(|r| kind == Kind::Content || r.grant)
    }

    // -- The current state (keys.md, "The current state and the inside")

    /// The current state among a valid set: the valid rotations that no
    /// other valid rotation follows. `None` when none is valid.
    pub fn current_in(&self, valid: &BTreeSet<EventId>, kind: Kind) -> Option<RotationSet> {
        let rotations: Vec<EventId> = valid
            .iter()
            .copied()
            .filter(|&i| self.events.contains(&i) && self.is_rotation(i, kind))
            .collect();
        let maximal = rotations
            .iter()
            .copied()
            .filter(|&r| !rotations.iter().any(|&o| self.history.precedes(r, o)));
        RotationSet::new(maximal).ok()
    }

    /// The view's current content state `S`, or grant state `G`.
    pub fn current(&self, kind: Kind) -> Option<RotationSet> {
        self.current_in(&self.valid, kind)
    }

    /// The secret of the current state: `k(S)` for the content graph,
    /// `g(G)` for the grant graph, merged from its rotations' secrets in
    /// canonical order. `None` when a rotation's secret is not given.
    pub fn current_secret(
        &self,
        kind: Kind,
        secret_of: impl Fn(EventId) -> Option<[u8; 32]>,
    ) -> Option<Secret> {
        let state = self.current(kind)?;
        let inputs: Option<zeroize::Zeroizing<Vec<[u8; 32]>>> = state
            .ids()
            .iter()
            .map(|&r| secret_of(r))
            .collect::<Option<Vec<_>>>()
            .map(zeroize::Zeroizing::new);
        let secret_kind = match kind {
            Kind::Content => SecretKind::Content,
            Kind::Grant => SecretKind::Grant,
        };
        state_secret(secret_kind, &self.history.space(), &state, &inputs?).ok()
    }

    // -- The merged roster (keys.md, "Notices and space principals")

    /// The valid events that change who is in: the genesis, the roster
    /// events, and the key events that carry a notice or name events of
    /// other logs in their sealed refs (which put principals out of force).
    pub fn valid_roster(&self, valid: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        valid
            .iter()
            .copied()
            .filter(|&i| {
                let facts = self.facts(i);
                matches!(facts.role, Role::Genesis | Role::Roster)
                    || (facts.role == Role::Key
                        && (!facts.notices.is_empty() || !facts.refs.is_empty()))
            })
            .collect()
    }

    /// The roster of a set of valid events, with the space principals their
    /// notices admit at this replica ([`History::admits`]). A principal
    /// (T, `R`) is in force only if `R` has in
    /// its past, or is, every valid rotation of T that an event of the set
    /// names in its sealed refs; no later notice brings one out of force back. It
    /// stands for T's space member, at that member's level and at most
    /// `write`, and only while the roster grants T.
    pub fn roster_at(&self, place: &BTreeSet<EventId>) -> Rc<Roster<H::Member>> {
        if let Some(hit) = self.rosters.borrow().get(place) {
            return Rc::clone(hit);
        }
        let base = self.history.roster(place);
        let mut spaces: BTreeMap<EventId, Level> = BTreeMap::new();
        let mut out: Roster<H::Member> = BTreeMap::new();
        for (member, state) in base {
            match self.history.space_of(&member) {
                Some(space) => {
                    spaces.insert(space, state.level.min(Level::Write));
                }
                None => {
                    out.insert(Member::Roster(member), state);
                }
            }
        }
        let mut named: BTreeMap<EventId, BTreeSet<EventId>> = BTreeMap::new();
        for &i in place {
            for r in &self.facts(i).refs {
                named.entry(r.log).or_default().insert(r.id);
            }
        }
        for &i in place {
            for notice in &self.facts(i).notices {
                let Some(&level) = spaces.get(&notice.space) else {
                    continue;
                };
                if !self.history.admits(i, notice) {
                    continue;
                }
                let principal = Principal {
                    space: notice.space,
                    rotation: notice.rotation,
                };
                if !self.in_force(&principal, named.get(&notice.space)) {
                    continue;
                }
                let state = out
                    .entry(Member::Principal(principal))
                    .or_insert_with(|| Membership {
                        level,
                        with_history: false,
                        session: false,
                        grants: Vec::new(),
                    });
                state.with_history |= !notice.from_now_on;
                state.grants.push(i);
                state.grants.sort_unstable();
                state.grants.dedup();
            }
        }
        let out = Rc::new(out);
        self.rosters
            .borrow_mut()
            .insert(place.clone(), Rc::clone(&out));
        out
    }

    /// Whether a principal is in force given the events of its space that
    /// events name in their sealed refs: its rotation has in its past, or
    /// is, every one of them that is a valid rotation there. A named event
    /// this replica does not hold may be one, so it puts the principal out
    /// of force until the replica holds it.
    fn in_force(&self, principal: &Principal, named: Option<&BTreeSet<EventId>>) -> bool {
        let Some(named) = named.filter(|n| !n.is_empty()) else {
            return true;
        };
        named.iter().all(
            |&x| match self.history.grantee_rotation(principal.space, x) {
                None => false,
                Some(false) => true,
                Some(true) => self
                    .history
                    .grantee_le(principal.space, x, principal.rotation)
                    .unwrap_or(false),
            },
        )
    }

    /// The merged roster of a valid set; for the grant graph, only the
    /// members whose grant propagates.
    pub fn members_in(&self, valid: &BTreeSet<EventId>, kind: Kind) -> Roster<H::Member> {
        let roster = self.roster_at(&self.valid_roster(valid));
        roster
            .iter()
            .filter(|(_, state)| kind == Kind::Content || !state.session)
            .map(|(m, s)| (m.clone(), s.clone()))
            .collect_map()
    }

    /// The view's merged roster: the roster of its valid roster events,
    /// with the space principals in force (keys.md, "The current state and
    /// the inside"); for the grant graph, only members that propagate.
    pub fn members(&self, kind: Kind) -> Roster<H::Member> {
        self.members_in(&self.valid, kind)
    }

    /// The merged roster's members that receive wraps and count towards the
    /// inside: [`Self::members`].
    #[cfg(not(feature = "ext-invite-links"))]
    pub(crate) fn receiving(&self, kind: Kind) -> Roster<H::Member> {
        self.members(kind)
    }

    /// The merged roster's members that receive wraps and count towards the
    /// inside: [`Self::members`], less the invite keys a raced claim counts
    /// as outside (ext-invite-links.md, "Keys").
    #[cfg(feature = "ext-invite-links")]
    pub fn receiving(&self, kind: Kind) -> Roster<H::Member> {
        crate::ext_invite_links::receiving(self, self.members(kind))
    }

    /// The devices a delivery wraps for, of a member: its devices
    /// ([`Self::devices`]), less those this replica does not wrap for
    /// ([`History::receives`]): a person's waiting list members, and every
    /// device of a person whose list holds an active agent where the policy
    /// forbids agents.
    pub fn wrap_devices(&self, member: &Member<H::Member>) -> Vec<H::Device> {
        match member {
            Member::Roster(m) => self
                .devices(member)
                .into_iter()
                .filter(|d| self.history.receives(m, d))
                .collect(),
            Member::Principal(_) => self.devices(member),
        }
    }

    /// A member's devices; a principal's are the devices of its space that
    /// hold its rotation's grant seed.
    pub fn devices(&self, member: &Member<H::Member>) -> Vec<H::Device> {
        match member {
            Member::Roster(m) => self.history.devices(m),
            Member::Principal(p) => self.history.principal_devices(p.space, p.rotation),
        }
    }

    /// The devices a delivery at event `delivery` wrapped for, for a member
    /// of the roster at its place: the holders the heal test counts
    /// (keys.md, "Healing"). A device its person's list revoked since, or
    /// whose chain forked since, still counts unless the delivery's past
    /// shows the response to that end or the fork
    /// ([`History::wrapped_for`]). A principal's are its devices.
    pub fn wrapped_for(&self, member: &Member<H::Member>, delivery: EventId) -> Vec<H::Device> {
        match member {
            Member::Roster(m) => self.history.wrapped_for(m, delivery),
            Member::Principal(p) => self.history.principal_devices(p.space, p.rotation),
        }
    }

    /// Whether a device of a member writes through it; a principal's
    /// devices do.
    fn writes(&self, member: &Member<H::Member>, device: &H::Device) -> bool {
        match member {
            Member::Roster(m) => self.history.writes(m, device),
            Member::Principal(_) => true,
        }
    }

    /// A device's level in a roster: the highest of the members it writes
    /// through ([`History::writes`]); `None` when there is none.
    pub fn device_level(&self, device: &H::Device, roster: &Roster<H::Member>) -> Option<Level> {
        roster
            .iter()
            .filter(|(m, _)| self.devices(m).contains(device) && self.writes(m, device))
            .map(|(_, s)| s.level)
            .max()
    }

    /// Whether a device belongs only to members with `session` in a roster.
    pub fn device_session(&self, device: &H::Device, roster: &Roster<H::Member>) -> bool {
        roster
            .iter()
            .filter(|(m, _)| self.devices(m).contains(device))
            .all(|(_, s)| s.session)
    }

    /// The inside: every device of every member of the merged roster; of a
    /// principal, only those this space's effective membership holds, the
    /// devices still in its space as this replica holds that space's log.
    /// For the grant graph, over members whose grant propagates.
    pub fn inside(&self, kind: Kind) -> BTreeSet<H::Device> {
        let mut out = BTreeSet::new();
        // An invite key a valid successor put out is no member, so it
        // counts as outside (ext-invite-links.md, "Keys").
        let members = self.receiving(kind);
        for member in members.keys() {
            let devices = self.devices(member);
            match member {
                Member::Principal(p) => {
                    if let Some(current) = self.history.grantee_current(p.space) {
                        out.extend(devices.into_iter().filter(|d| current.contains(d)));
                    }
                }
                Member::Roster(_) => out.extend(devices),
            }
        }
        out
    }

    /// Whether a state may be wrapped to a member: always for a member of
    /// the roster; for a space principal, only while this replica holds its
    /// space's log, since a replica that does not seals nothing to that
    /// space (keys.md, "Notices and space principals").
    pub fn may_wrap(&self, member: &Member<H::Member>, _state: &RotationSet) -> bool {
        match member {
            Member::Principal(p) => self.history.grantee_current(p.space).is_some(),
            Member::Roster(_) => true,
        }
    }

    /// The devices counted as neither inside nor outside: those of a
    /// principal whose space's log this replica does not hold, which leaves
    /// the heal to members that hold both logs.
    pub fn neither(&self, kind: Kind) -> BTreeSet<H::Device> {
        let inside = self.inside(kind);
        let mut out = BTreeSet::new();
        for member in self.receiving(kind).keys() {
            if let Member::Principal(p) = member
                && self.history.grantee_current(p.space).is_none()
            {
                out.extend(
                    self.devices(member)
                        .into_iter()
                        .filter(|d| !inside.contains(d)),
                );
            }
        }
        out
    }

    // -- Entitlement (keys.md, "Entitlement and the link gate")

    /// A state's place among a valid set: the valid roster events and
    /// notices in the past of its rotations, those rotations included.
    pub fn place(&self, valid: &BTreeSet<EventId>, state: &RotationSet) -> BTreeSet<EventId> {
        self.valid_roster(valid)
            .into_iter()
            .filter(|&p| state.ids().iter().any(|&r| self.le(p, r)))
            .collect()
    }

    /// Whether `member` is entitled to `state` in the view:
    ///
    /// 1. it is in the roster of the state's place; or
    /// 2. the state holds several rotations, and it is entitled to each; or
    /// 3. the state is `{R}`, and a valid "with history" grant or notice `x`
    ///    of the member exists that does not precede or equal `R`, such that
    ///    `R` precedes `x`, or `x` is in force in the merged roster.
    ///
    /// For the grant graph, only grants that propagate count. A space
    /// principal's entitlement is the intersection over its devices: a
    /// device its space admitted "from now on" at a break in the principal's
    /// rotation's past is entitled here only from this space's response to
    /// that break.
    pub fn entitled(&self, member: &Member<H::Member>, state: &RotationSet, kind: Kind) -> bool {
        self.entitled_in(&self.valid.clone(), member, state, kind)
    }

    /// [`Self::entitled`] over another valid set.
    pub fn entitled_in(
        &self,
        valid: &BTreeSet<EventId>,
        member: &Member<H::Member>,
        state: &RotationSet,
        kind: Kind,
    ) -> bool {
        let key = (valid.clone(), member.clone(), state.clone(), kind);
        if let Some(&hit) = self.entitled.borrow().get(&key) {
            return hit;
        }
        // keys.md, "Keys after a checkpoint": a state with a rotation before
        // the checkpoint the view is rooted at, which it does not hold.
        if self.history.world_root().is_some()
            && state.ids().iter().any(|r| !self.events.contains(r))
        {
            let out = state.ids().iter().all(|&r| {
                if self.events.contains(&r) {
                    self.entitled_in(valid, member, &RotationSet::single(r), kind)
                } else {
                    self.entitled_before(valid, member, kind)
                }
            });
            self.entitled.borrow_mut().insert(key, out);
            return out;
        }
        let roster = self.roster_at(&self.place(valid, state));
        let mut out = roster
            .get(member)
            .is_some_and(|s| kind == Kind::Content || !s.session);
        // ext-invite-links.md, rule 4: the claimant of a valid successor is
        // entitled to every state its invite key is entitled to.
        #[cfg(feature = "ext-invite-links")]
        if !out {
            out = crate::ext_invite_links::claimant_entitled(self, valid, member, state, kind);
        }
        if !out && state.len() > 1 {
            out = state
                .ids()
                .iter()
                .all(|&r| self.entitled_in(valid, member, &RotationSet::single(r), kind));
        } else if !out {
            let r = state.ids()[0];
            let now = self.members_in(valid, kind);
            let in_force: &[EventId] = now.get(member).map_or(&[], |s| s.grants.as_slice());
            out = self.valid_roster(valid).into_iter().any(|x| {
                self.grants_with_history(x, member, kind)
                    && !self.le(x, r)
                    && (self.history.precedes(r, x) || in_force.contains(&x))
            });
        }
        if out && let Member::Principal(p) = member {
            let floors = self.floors(p);
            out = floors
                .iter()
                .all(|&f| state.ids().iter().all(|&r| self.le(f, r)));
        }
        self.entitled.borrow_mut().insert(key, out);
        out
    }

    /// keys.md, "Keys after a checkpoint": whether `member` is entitled to a
    /// rotation before the checkpoint the view is rooted at, at a replica
    /// that holds only its world. A valid "with history" grant after the
    /// checkpoint entitles its member; so does a valid "with history"
    /// notice, unless the record gives its space a floor. A member of the
    /// record alone is entitled to none here: only a replica that holds the
    /// past can tell, and only such a replica delivers them.
    fn entitled_before(
        &self,
        valid: &BTreeSet<EventId>,
        member: &Member<H::Member>,
        kind: Kind,
    ) -> bool {
        if let Member::Principal(p) = member
            && self.history.record_floor(p.space)
        {
            return false;
        }
        let root = self.history.genesis();
        self.valid_roster(valid)
            .into_iter()
            .any(|x| x != root && self.grants_with_history(x, member, kind))
    }

    /// Whether event `x` grants `member` "with history": a grant of a
    /// roster member (for the grant graph, without `session`), or a notice
    /// of a principal without key 4.
    fn grants_with_history(&self, x: EventId, member: &Member<H::Member>, kind: Kind) -> bool {
        let facts = self.facts(x);
        match member {
            Member::Roster(m) => facts
                .grants
                .iter()
                .any(|g| g.member == *m && g.with_history && !(kind == Kind::Grant && g.session)),
            Member::Principal(p) => facts.notices.iter().any(|n| {
                n.space == p.space
                    && n.rotation == p.rotation
                    && !n.from_now_on
                    && self.history.admits(x, n)
            }),
        }
    }

    /// A principal's floors: this space's valid responses to each break of
    /// its space in the past of its rotation. Its entitlement starts at
    /// them, and they count as its breaks in the gate. The breaks are the
    /// rotations of the granted space that valid notices name "from now
    /// on".
    pub fn floors(&self, principal: &Principal) -> &[EventId] {
        let all = self.floors.get_or_init(|| self.all_floors());
        all.get(principal).map_or(&[], Vec::as_slice)
    }

    fn all_floors(&self) -> BTreeMap<Principal, Vec<EventId>> {
        let mut breaks: BTreeSet<(EventId, EventId)> = BTreeSet::new();
        let mut principals: BTreeSet<Principal> = BTreeSet::new();
        // In a checkpoint's world a principal's floors before it are the
        // record's ([`History::record_floor`]): the root's notices and refs
        // make none.
        let root = self.history.world_root();
        for &i in &self.events {
            for n in &self.facts(i).notices {
                principals.insert(Principal {
                    space: n.space,
                    rotation: n.rotation,
                });
                if n.from_now_on
                    && Some(i) != root
                    && self.valid.contains(&i)
                    && self.history.admits(i, n)
                {
                    breaks.insert((n.space, n.rotation));
                }
            }
        }
        let mut out = BTreeMap::new();
        for p in principals {
            let mut floors: Vec<EventId> = Vec::new();
            for &(space, b) in &breaks {
                let in_past = self.history.grantee_le(p.space, b, p.rotation) == Some(true);
                if space != p.space || b == p.rotation || !in_past {
                    continue;
                }
                floors.extend(self.valid.iter().copied().filter(|&e| {
                    if Some(e) == root {
                        return false;
                    }
                    let facts = self.facts(e);
                    facts.is_space_event() && facts.refs.iter().any(|r| r.log == space && r.id == b)
                }));
            }
            floors.sort_unstable();
            floors.dedup();
            if !floors.is_empty() {
                out.insert(p, floors);
            }
        }
        out
    }

    // -- Restored members (keys.md, "Restored members")

    /// The removals of a member the view holds that are void: each restores
    /// it.
    pub fn void_removals(&self, member: &Member<H::Member>) -> Vec<EventId> {
        let Member::Roster(m) = member else {
            return Vec::new();
        };
        self.events
            .iter()
            .copied()
            .filter(|&r| !self.valid.contains(&r) && self.facts(r).removes.contains(m))
            .collect()
    }

    /// Whether `state` was made while `member` was out: it is entitled to it
    /// only because removal `r` is void, and the state's past lacks `r` or
    /// one of the events that void it.
    pub fn made_while_out(
        &self,
        member: &Member<H::Member>,
        state: &RotationSet,
        kind: Kind,
        r: EventId,
    ) -> bool {
        let mut with = self.valid.clone();
        with.insert(r);
        if self.entitled_in(&with, member, state, kind) {
            return false;
        }
        let past = self.closure(state);
        let mut need = vec![r];
        need.extend(self.history.voiders(&self.valid, r));
        !need.iter().all(|x| past.contains(x))
    }

    /// Whether a key waits for stability: it was made while `member` was
    /// out, and the voiding of that removal is not stable. After
    /// `gap_key_timeout` (`timed_out`) nothing waits.
    pub fn restored_pending(
        &self,
        member: &Member<H::Member>,
        state: &RotationSet,
        kind: Kind,
        timed_out: bool,
    ) -> bool {
        if timed_out {
            return false;
        }
        self.void_removals(member).into_iter().any(|r| {
            self.made_while_out(member, state, kind, r) && !self.history.stable(&self.valid, r)
        })
    }

    /// Entitled, and not waiting for stability.
    pub fn entitled_now(
        &self,
        member: &Member<H::Member>,
        state: &RotationSet,
        kind: Kind,
        timed_out: bool,
    ) -> bool {
        self.entitled(member, state, kind) && !self.restored_pending(member, state, kind, timed_out)
    }

    // -- The link gate

    /// The breaks of each member, valid or void: its "from now on" grants
    /// (for the grant graph, those that propagate) and notices, and a
    /// principal's floors. Each counts its grantee as a potential holder of
    /// every state in its future.
    pub fn breaks(&self, kind: Kind) -> BTreeMap<Member<H::Member>, Vec<EventId>> {
        let mut out: BTreeMap<Member<H::Member>, Vec<EventId>> = BTreeMap::new();
        for &i in &self.events {
            let facts = self.facts(i);
            for g in &facts.grants {
                let propagates = !(kind == Kind::Grant && g.session);
                if !g.with_history && propagates {
                    out.entry(Member::Roster(g.member.clone()))
                        .or_default()
                        .push(i);
                }
            }
            // The root of a checkpoint's world carries its record's
            // notices, whose breaks all lie before it.
            let at_root = self.history.world_root() == Some(i);
            for n in &facts.notices {
                if n.from_now_on && !at_root {
                    out.entry(Member::Principal(Principal {
                        space: n.space,
                        rotation: n.rotation,
                    }))
                    .or_default()
                    .push(i);
                }
            }
        }
        let floors = self.floors.get_or_init(|| self.all_floors());
        for (p, fs) in floors {
            out.entry(Member::Principal(*p))
                .or_default()
                .extend(fs.iter().copied().filter(|f| self.events.contains(f)));
        }
        out
    }

    /// The link gate: may a link to `k` hang under `under`?
    ///
    /// 1. every member of the merged roster is entitled to `k`, and none of
    ///    them waits for stability on it; and
    /// 2. for every member `m` with a break in `under`'s past, either `m` is
    ///    entitled to `k`, or one of `m`'s breaks precedes or equals a
    ///    rotation of `k`.
    ///
    /// For the grant graph, over members that propagate and breaks whose
    /// grantee propagates.
    pub fn gate(&self, under: &RotationSet, k: &RotationSet, kind: Kind, timed_out: bool) -> bool {
        if !self
            .members(kind)
            .keys()
            .all(|m| self.entitled_now(m, k, kind, timed_out))
        {
            return false;
        }
        let past = self.closure(under);
        for (m, breaks) in self.breaks(kind) {
            if !breaks.iter().any(|b| past.contains(b)) {
                continue;
            }
            if self.entitled(&m, k, kind)
                || breaks
                    .iter()
                    .any(|&b| k.ids().iter().any(|&r| self.le(b, r)))
            {
                continue;
            }
            return false;
        }
        true
    }
}
