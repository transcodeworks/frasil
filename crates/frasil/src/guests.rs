//! Guests at a device (ext-guests.md, feature `ext-guests`).
//!
//! - **Admitting** ("Admitting a guest"): an administering device grants a
//!   guest by the guest preset, through an admission code's offer
//!   ([`frasil_admission::ext_guests::guest_offer`]) or directly
//!   ([`Engine::grant_guest`]).
//! - **Ending a session** ("Ending a session"): [`Engine::end_session`]
//!   removes every guest of a session in one roster event per 256. Each
//!   administering device also decides `session_expiry` for every guest
//!   grant in force that carries `expires_at`, and removes the guests that
//!   are due once its rank delay has passed from its first sight of the
//!   grant ([`Engine::expire_guests`]).
//! - **Leave requests** ("A leave request"): a member that does not
//!   administer leaves by a signed request ([`Engine::leave`]), sent as an
//!   ephemeral message targeted at the administering devices where the
//!   ephemeral channel is built in; an administering device checks it
//!   ([`Engine::take_leave_request`]) and, after its rank delay with the
//!   request's hash as the trigger, removes the member.
//! - **The writer's decision** ("The writer's decision"): before it seals
//!   anything in a space, the device decides `Left`, `SessionEnded`,
//!   `WindowElapsed`, `NotOnline` or may write ([`Engine::writer_check`]).
//!   `followed` is read from the space's valid events, and `last_sync` is
//!   kept as `state` key 3 once a sync with a peer completes.
//! - **Heartbeats** ("The writer's decision", "Heartbeats"): under a
//!   bounded window, [`Engine::heartbeat`] signs an anchor when the
//!   device has signed nothing for half the window, or holds another
//!   member's anchor none of its events follows.
//! - **Nothing at rest** ("Nothing at rest"): a guest whose grant carries
//!   `frasil.nothing-at-rest` keeps the space in memory only, and forgets
//!   it at once when it leaves.

use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::replica::Replica;
use frasil_admission::ext_guests::{LeaveRequest, leave_trigger};
use frasil_base::collect::CollectMap;
use frasil_base::errors::Class;
use frasil_base::time::Reading;
use frasil_crypto::device::{DeviceId, KeySource};
use frasil_crypto::schemes::Scheme;
use frasil_events::Envelope;
use frasil_events::EventId;
use frasil_space::ext_guests::{
    GuestClass, Preset, SESSION_BYTES, earliest_expiry, followed, grant_expiries, guest_due,
    is_guest, nothing_at_rest, rank_delay,
};
use frasil_space::{Change, DeviceKeys, Level, MemberRef, MemberType, Space};
use frasil_store::tables::{LogState, Table, TableValue};
use frasil_transport::mailbox;
use frasil_units::ext_guests::{Heartbeat, WriterState, heartbeat, may_seal};
use std::collections::{BTreeMap, BTreeSet};

/// What a replica's last resolution says of guests.
#[derive(Debug, Clone, Default)]
pub(crate) struct GuestFacts {
    /// The earliest `expires_at` of this device's grants in force.
    pub my_expiry: Option<u64>,
    /// This device's earliest grant in force: its admission.
    pub admitted: Option<EventId>,
    /// `followed`, when this device has an admission it has seen and the
    /// space's policy bounds the window.
    pub followed: Option<Reading>,
    /// Whether this device's grant carries `frasil.nothing-at-rest`.
    pub nothing_at_rest: bool,
    /// Each guest in force, with the `expires_at` of each of its grants.
    pub guests: Vec<(MemberRef, BTreeMap<EventId, Option<u64>>)>,
    /// The members in the merged roster, with their grants in force.
    pub grants: BTreeMap<MemberRef, BTreeSet<EventId>>,
}

/// The guest facts of a resolved space, for this device `me`, with the
/// first sight of each event this device holds.
pub(crate) fn facts(
    space: &Space<'_>,
    me: &DeviceId,
    first_sight: &BTreeMap<EventId, Reading>,
) -> GuestFacts {
    let mine = MemberRef::device(*me);
    let state = space.roster().state(&mine);
    let admitted = state.and_then(|s| s.grants.iter().next().copied());
    // `followed` counts only under a bounded window (ext-guests.md, the
    // writer's decision, step 3), and finding it walks the view.
    let followed = admitted
        .filter(|_| space.policy().bounded_window.is_some())
        .and_then(|grant| first_sight.get(&grant).copied())
        .map(|admitted_at| {
            let log = space.log();
            let signed_at: BTreeMap<EventId, Reading> = first_sight
                .iter()
                .filter(|(id, _)| log.event(**id).is_some_and(|e| e.author() == me))
                .map(|(id, reading)| (*id, *reading))
                .collect_map();
            followed(space, &me.0, &signed_at, admitted_at)
        });
    let guests = space
        .roster()
        .members_in()
        .filter(|(_, s)| is_guest(s))
        .map(|(member, _)| (*member, grant_expiries(space, member)))
        .collect();
    let grants = space
        .roster()
        .members_in()
        .map(|(member, s)| (*member, s.grants.clone()))
        .collect_map();
    GuestFacts {
        my_expiry: earliest_expiry(space, &mine),
        admitted,
        followed,
        nothing_at_rest: state.is_some_and(nothing_at_rest),
        guests,
        grants,
    }
}

/// A leave request an administering device has checked, waiting for its
/// rank delay.
#[derive(Debug, Clone)]
pub(crate) struct PendingLeave {
    /// The leaving member.
    pub member: MemberRef,
    /// Its delay, in seconds.
    pub delay: u64,
    /// This device's first sight of the request.
    pub first: Reading,
}

/// What a device keeps of guests besides its replicas.
#[derive(Debug, Default)]
pub(crate) struct GuestState {
    /// The grants each leave request this device sent named, by space
    /// (`Left`, `state` key 4).
    pub left: BTreeMap<EventId, BTreeSet<EventId>>,
    /// The last completed sync with a peer, by space (`state` key 3).
    pub last_sync: BTreeMap<EventId, Reading>,
    /// Leave requests waiting for this device's rank delay, by space.
    pub leaves: BTreeMap<EventId, Vec<PendingLeave>>,
    /// This device's last heartbeat, by space, while it runs.
    pub heartbeats: BTreeMap<EventId, Reading>,
    /// Leave requests whose signer's keys this device did not hold yet
    /// (`NoHybridKey`, pending), by space: taken again at the next upkeep,
    /// once the keys may have arrived. At most [`PENDING_REQUESTS`].
    pub unverified: Vec<(EventId, Vec<u8>)>,
}

/// The most leave requests a device keeps while it waits for their
/// signers' keys.
const PENDING_REQUESTS: usize = 64;

impl Replica {
    /// What the last resolution says of guests.
    pub(crate) fn guest_facts(&self) -> &GuestFacts {
        &self.guests
    }
}

/// What [`Engine::leave`] signed and sealed.
#[derive(Debug, Clone)]
pub struct Leaving {
    /// The signed leave request.
    pub signed: Vec<u8>,
    /// One item for each administering device: its device mailbox's
    /// address and the request sealed to it.
    pub deposits: Vec<([u8; 32], Vec<u8>)>,
}

/// The space a signed leave request names, if its request reads.
fn leave_space(signed: &[u8]) -> Option<EventId> {
    let value = frasil_base::cbor::decode(signed).ok()?;
    let record = value.as_map().ok()?.get(&1)?.as_bytes().ok()?;
    LeaveRequest::read(record).ok().map(|r| EventId(*r.space()))
}

/// The administering devices of a replica's view.
fn administering(replica: &Replica) -> Vec<DeviceId> {
    replica
        .devices()
        .into_iter()
        .filter(|(_, level)| *level == Level::Administer)
        .map(|(device, _)| device)
        .collect()
}

/// The administering devices' IDs as bytes, for the rank order.
fn ranked(administering: &[DeviceId]) -> Vec<[u8; 32]> {
    administering.iter().map(|device| device.0).collect()
}

impl Engine {
    /// The writer's decision for this device in a space (ext-guests.md,
    /// "The writer's decision"), before it seals anything there.
    ///
    /// # Errors
    ///
    /// `Left`, `SessionEnded`, `WindowElapsed` or `NotOnline`, as
    /// [`Error::Class`].
    pub(crate) async fn writer_check(&self, state: &mut State, space: &EventId) -> Result<()> {
        let now = self.read_timeline(state).await?;
        let Some(replica) = state.replicas.get(space) else {
            return Ok(());
        };
        let facts = replica.guest_facts();
        let admitted = facts
            .admitted
            .and_then(|grant| replica.first_sight(&grant).copied())
            .unwrap_or(now);
        let mut writer = WriterState::new(replica.policy(), admitted);
        // Left: a grant of it in force is among those a sent request named.
        writer.left = state.guests.left.get(space).is_some_and(|named| {
            facts
                .grants
                .get(&MemberRef::device(self.device_id()))
                .is_some_and(|in_force| in_force.iter().any(|g| named.contains(g)))
        });
        writer.session_expires_at = facts.my_expiry;
        writer.followed = facts.followed;
        writer.last_sync = state.guests.last_sync.get(space).copied();
        may_seal(&writer, &now).map_err(Error::class)
    }

    /// Grants a guest by the preset (ext-guests.md, "The guest preset"):
    /// the device and its keys, with `session`, from now on unless the
    /// preset says otherwise.
    ///
    /// # Errors
    ///
    /// As [`Engine::sign_roster`].
    pub async fn grant_guest(
        &self,
        space: EventId,
        keys: DeviceKeys,
        preset: &Preset,
    ) -> Result<EventId> {
        self.sign_roster(space, vec![preset.grant(keys)]).await
    }

    /// Ends a session (ext-guests.md, "Ending a session"): every guest of
    /// it removed, one roster event for each 256. Returns the events.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when no guest of the session is in; as
    /// [`Engine::sign_roster`].
    pub async fn end_session(
        &self,
        space: EventId,
        session: &[u8; SESSION_BYTES],
    ) -> Result<Vec<EventId>> {
        let batches = self
            .read(&space, |replica| {
                frasil_space::ext_guests::end_session(replica.roster(), session)
            })
            .await?;
        if batches.is_empty() {
            return Err(Error::Invalid("no guest of this session is in the space"));
        }
        let mut out = Vec::new();
        for changes in batches {
            out.push(self.sign_roster(space, changes).await?);
        }
        Ok(out)
    }

    /// The session expiries and leave requests due at this device in a
    /// space it administers (ext-guests.md, "Ending a session", "A leave
    /// request"): once its rank delay has passed, every due guest and every
    /// leaving member still in is removed in one roster event.
    ///
    /// # Errors
    ///
    /// As [`Engine::sign_roster`].
    pub async fn expire_guests(&self, space: EventId) -> Result<Option<EventId>> {
        // Leave requests that waited for their signers' keys, taken again.
        let unverified: Vec<Vec<u8>> = {
            let mut state = self.lock().await;
            let (here, rest) = std::mem::take(&mut state.guests.unverified)
                .into_iter()
                .partition(|(s, _)| *s == space);
            state.guests.unverified = rest;
            here.into_iter().map(|(_, signed)| signed).collect()
        };
        for signed in unverified {
            let _ = self.take_leave_request(space, &signed).await;
        }
        let me = self.device_id();
        let due: Vec<MemberRef> = {
            let mut state = self.lock().await;
            let now = self.read_timeline(&mut state).await?;
            let Some(replica) = state.replicas.get(&space) else {
                return Ok(None);
            };
            if replica.level_of(&me) != Some(Level::Administer) {
                return Ok(None);
            }
            let admins = administering(replica);
            let step = crate::maintenance::rotation_step();
            let facts = replica.guest_facts();
            let mut due = Vec::new();
            for (member, grants) in &facts.guests {
                let sighted: Vec<(Option<u64>, Reading)> = grants
                    .iter()
                    .map(|(grant, expires)| {
                        (*expires, replica.first_sight(grant).copied().unwrap_or(now))
                    })
                    .collect();
                if !guest_due(&sighted, &now) {
                    continue;
                }
                // The trigger: the first grant that gives Remove.
                let Some((grant, first)) = grants.keys().find_map(|grant| {
                    let first = replica.first_sight(grant).copied().unwrap_or(now);
                    guest_due(&[(grants[grant], first)], &now).then_some((grant, first))
                }) else {
                    continue;
                };
                if let Some((position, _)) =
                    rank_delay(&space, &grant.0, &ranked(&admins), &me.0, step)
                    && frasil_space::keygraph::rank::due(&first, &now, position, step)
                {
                    due.push(*member);
                }
            }
            let in_roster = facts.grants.clone();
            let waiting = state.guests.leaves.entry(space).or_default();
            waiting.retain(|leave| in_roster.contains_key(&leave.member));
            for leave in waiting.iter() {
                if frasil_base::time::lower(&leave.first, &now) >= leave.delay
                    && !due.contains(&leave.member)
                {
                    due.push(leave.member);
                }
            }
            due
        };
        if due.is_empty() {
            return Ok(None);
        }
        let changes: Vec<Change> = due.into_iter().map(Change::remove).collect();
        self.sign_roster(space, changes).await.map(Some)
    }

    /// Leaves a space this device does not administer (ext-guests.md, "A
    /// leave request"): signs a leave request for its own device member,
    /// seals it to each administering device's device mailbox
    /// (transport.md, "Mailboxes") and sends it to them where the ephemeral
    /// channel is built in, and from then on seals nothing there (`Left`).
    /// A space kept in memory only is forgotten at once. Returns the signed
    /// request and the mailbox items, which the caller deposits at the
    /// space's peers.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for an administering device, which leaves by
    /// lowering itself, or a device that is no member; the writer's
    /// decision's classes; the store's.
    pub async fn leave(&self, space: EventId) -> Result<Leaving> {
        let me = self.device_id();
        let (signed, admins, deposits, forget) = {
            let mut state = self.lock().await;
            self.writer_check(&mut state, &space).await?;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let member = MemberRef::device(me);
            let level = replica
                .roster()
                .state(&member)
                .map(|s| s.level)
                .ok_or(Error::NotAllowed("this device is no member of the space"))?;
            if level == Level::Administer {
                return Err(Error::NotAllowed(
                    "an administering device leaves by lowering itself",
                ));
            }
            let grants: Vec<EventId> = replica
                .guest_facts()
                .grants
                .get(&member)
                .map(|g| g.iter().copied().collect())
                .unwrap_or_default();
            let request = LeaveRequest {
                space: space.0,
                member,
                grants,
                request: self.platform().nonce::<16>()?,
                device: me,
            };
            let signed = request.sign(self.signer());
            let admins = administering(replica);
            let named = request.grants.clone();
            // One item for each administering device, sealed to the X-Wing
            // key its device ID commits to, from its grant or any source.
            let mut deposits = Vec::new();
            for admin in &admins {
                let Some(keys) = replica
                    .roster()
                    .state(&MemberRef::device(*admin))
                    .and_then(|s| s.keys.as_deref().cloned())
                    .or_else(|| state.keys().device_keys(admin))
                    .filter(|keys| keys.device_id() == *admin)
                else {
                    continue;
                };
                let randomness = self
                    .platform()
                    .draw::<{ frasil_crypto::wrap::ENCAPSULATION_RANDOMNESS }>()?;
                let item = mailbox::seal_item_with(
                    mailbox::content::LEAVE_REQUEST,
                    &signed,
                    &keys,
                    &randomness,
                )
                .map_err(Error::class)?;
                deposits.push((mailbox::address(mailbox::Kind::Device, &admin.0), item));
            }
            let forget =
                replica.guest_facts().nothing_at_rest || state.vault.is_memory_only(&space.0);
            // Kept before the request leaves (`state` key 4), so that
            // `Left` outlasts a restart.
            self.keep_left(&mut state, space, named).await?;
            (signed, admins, deposits, forget)
        };
        #[cfg(feature = "ephemeral")]
        {
            let _ = self
                .send_targeted(
                    space,
                    frasil_ephemeral::names::LEAVE_REQUEST,
                    &admins,
                    &signed,
                )
                .await;
        }
        #[cfg(not(feature = "ephemeral"))]
        let _ = admins;
        if forget {
            self.forget_with_grant_path(&space).await?;
        }
        Ok(Leaving { signed, deposits })
    }

    /// Takes an item collected from this device's own device mailbox
    /// (transport.md, "Mailboxes", "Opening an item"): a leave request is
    /// checked as [`take_leave_request`](Engine::take_leave_request) does,
    /// for the space it names.
    ///
    /// # Errors
    ///
    /// The item's class (`UnknownContent` for a content name this device
    /// does not implement); the leave request's.
    pub async fn take_mailbox_item(&self, item: &[u8]) -> Result<()> {
        let opened = mailbox::open_item(
            item,
            &self.device_id(),
            self.xwing_seed(),
            mailbox::content::implemented,
        )
        .map_err(Error::class)?;
        if opened.content != mailbox::content::LEAVE_REQUEST {
            return Err(Error::Class("UnknownContent"));
        }
        let space = leave_space(&opened.body).ok_or(Error::Class("Malformed"))?;
        self.take_leave_request(space, &opened.body).await
    }

    /// Takes a signed leave request at an administering device
    /// (ext-guests.md, "A leave request", steps 1 to 9, over the merged
    /// roster this device holds): one that passes
    /// waits for this device's rank delay, then
    /// [`expire_guests`](Engine::expire_guests) removes its member.
    ///
    /// # Errors
    ///
    /// The class of the first step that fails; [`Error::UnknownSpace`].
    pub async fn take_leave_request(&self, space: EventId, signed: &[u8]) -> Result<()> {
        let me = self.device_id();
        let mut state = self.lock().await;
        let now = self.read_timeline(&mut state).await?;
        // 1 to 3: the maps, the signing device's keys, from any source and
        // checked by their hash, then the signature. Without the keys the
        // request is pending, and taken again at the next upkeep.
        if !state.replicas.contains_key(&space) {
            return Err(Error::UnknownSpace);
        }
        let verified = LeaveRequest::verify(signed, &state.keys());
        if let Err(class) = &verified
            && class.name() == "NoHybridKey"
        {
            let unverified = &mut state.guests.unverified;
            if unverified.len() < PENDING_REQUESTS
                && !unverified.iter().any(|(s, r)| *s == space && r == signed)
            {
                unverified.push((space, signed.to_vec()));
            }
        }
        let request = verified.map_err(Error::class)?;
        let decision = {
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let roster = replica.roster();
            // 4. The space.
            if request.space != space.0 {
                return Err(Error::class(GuestClass::WrongSpace));
            }
            // 5. The member is in the merged roster.
            let member_state = roster
                .state(&request.member)
                .ok_or(Error::class(GuestClass::NoSuchMember))?;
            // 6. The signing device is the member, or one its list vouches
            // for.
            let theirs = match request.member.kind {
                MemberType::Device => request.member.id == request.device.0,
                MemberType::Person => state
                    .lists
                    .get(&request.member.id)
                    .is_some_and(|list| list.merge().active(&request.device).is_some()),
                _ => false,
            };
            if !theirs {
                return Err(Error::class(GuestClass::NotTheMember));
            }
            // 7. The grants in force.
            let named: BTreeSet<EventId> = request.grants.iter().copied().collect();
            if named != member_state.grants {
                return Err(Error::class(GuestClass::Stale));
            }
            // 8. Not a device member at administer.
            if request.member.kind == MemberType::Device && member_state.level == Level::Administer
            {
                return Err(Error::class(GuestClass::MemberAdministers));
            }
            // 9. The rank delay, with SHA-256 of the signed request.
            rank_delay(
                &space,
                &leave_trigger(signed),
                &ranked(&administering(replica)),
                &me.0,
                crate::maintenance::rotation_step(),
            )
            .map(|(_, delay)| (request.member, delay))
        };
        if let Some((member, delay)) = decision {
            let waiting = state.guests.leaves.entry(space).or_default();
            if !waiting.iter().any(|l| l.member == member) {
                waiting.push(PendingLeave {
                    member,
                    delay,
                    first: now,
                });
            }
        }
        Ok(())
    }

    /// A heartbeat under a bounded window (ext-guests.md, "The writer's
    /// decision", "Heartbeats"): an anchor (crypto.md, "Anchors and
    /// coverage") that keeps the space's other members able to follow this
    /// device, signed when `heartbeat` says so. An anchor seals nothing, so
    /// a device that may not write still signs it. Returns the anchor.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn heartbeat(&self, space: EventId) -> Result<Option<EventId>> {
        let me = self.device_id();
        let mut state = self.lock().await;
        let now = self.read_timeline(&mut state).await?;
        if state.guests.left.contains_key(&space) || Self::check_may_sign(&state, &space).is_err() {
            return Ok(None);
        }
        let Some(replica) = state.replicas.get(&space) else {
            return Ok(None);
        };
        let Some(window) = replica.policy().bounded_window else {
            return Ok(None);
        };
        let Some(log) = replica.log() else {
            return Ok(None);
        };
        if replica.level_of(&me).is_none() {
            return Ok(None);
        }
        let latest = log.latest(&me);
        // Before it has signed anything, the window runs from its first
        // sight of its own admission.
        let last_signed = latest
            .and_then(|id| replica.first_sight(&id).copied())
            .or_else(|| {
                replica
                    .guest_facts()
                    .admitted
                    .and_then(|grant| replica.first_sight(&grant).copied())
            })
            .unwrap_or(now);
        // Another member's anchor that none of this device's events
        // follows.
        let unanswered = log.events().any(|event| {
            event.kind() == frasil_events::kind::ANCHOR
                && event.author() != &me
                && replica.accepted(&event.id())
                && latest.is_none_or(|own| !log.precedes(event.id(), own))
        });
        let decision = heartbeat(
            &last_signed,
            state.guests.heartbeats.get(&space),
            &now,
            window,
            unanswered,
        );
        if decision != Heartbeat::Heartbeat {
            return Ok(None);
        }
        let (seq, prev) = Self::next(&state, &space, &me);
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let parents = replica.parents(prev);
        let cuts = replica.cuts_for(&parents)?;
        let anchor = Envelope {
            kind: frasil_events::kind::ANCHOR,
            log: Some(space),
            ed: *self.signer().identity_key(),
            kc: *self.signer().kc(),
            seq,
            prev,
            parents,
            cuts,
            body: Vec::new(),
            scheme: Scheme::Hybrid,
        };
        let signed = anchor.sign(self.signer());
        let id = self.commit_own(&mut state, space, &signed, None).await?;
        state.guests.heartbeats.insert(space, now);
        Ok(Some(id))
    }

    /// Keeps the grants a leave request names (ext-guests.md, "A leave
    /// request"): in memory, and as `state` key 4 unless the space is kept
    /// in memory only.
    ///
    /// # Errors
    ///
    /// The store's.
    async fn keep_left(
        &self,
        state: &mut State,
        space: EventId,
        grants: Vec<EventId>,
    ) -> Result<()> {
        state
            .guests
            .left
            .entry(space)
            .or_default()
            .extend(grants.iter().copied());
        if !state.vault.has_log(&space.0) || state.vault.is_memory_only(&space.0) {
            return Ok(());
        }
        let held = Self::held_log_state(&state.vault, &space).await?;
        let mut named: Vec<[u8; 32]> = state.guests.left[&space].iter().map(|g| g.0).collect();
        named.sort_unstable();
        named.truncate(frasil_store::tables::MAX_LEFT_GRANTS);
        let value = frasil_store::ext_guests::with_left(held.as_ref(), named);
        let mut batch = crate::at_rest::Batch::default();
        state
            .vault
            .put(&mut batch, &space.0, Table::State, &[], &value)?;
        state.vault.commit(batch).await
    }

    /// The log's `state` record, as held.
    async fn held_log_state(
        vault: &crate::at_rest::Vault,
        space: &EventId,
    ) -> Result<Option<LogState>> {
        Ok(vault
            .scan(&space.0, Table::State)
            .await?
            .into_iter()
            .find_map(|(_, value)| match value {
                TableValue::State(held) => Some(held),
                _ => None,
            }))
    }

    /// Records a completed sync with an always-on peer (ext-guests.md, "A
    /// completed sync"): `last_sync`, kept as `state` key 3.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn record_sync(&self, space: &EventId) -> Result<()> {
        let mut state = self.lock().await;
        let now = self.read_timeline(&mut state).await?;
        state.guests.last_sync.insert(*space, now);
        if !state.vault.has_log(&space.0) {
            return Ok(());
        }
        let held = Self::held_log_state(&state.vault, space).await?;
        let value = frasil_store::ext_guests::with_last_sync(held.as_ref(), now);
        let mut batch = crate::at_rest::Batch::default();
        state
            .vault
            .put(&mut batch, &space.0, Table::State, &[], &value)?;
        state.vault.commit(batch).await
    }

    /// Keeps a space this device's grant asks to keep nothing of at rest
    /// in memory only, from its first resolution that says so. A space the
    /// offer that admitted this device already said so of is kept in memory
    /// only from the offer on ([`Engine::keep_in_memory`]), and stays so
    /// whatever the roster later says: never weaker than the device was
    /// first told.
    pub(crate) async fn keep_guest_in_memory(state: &mut State, space: &EventId) -> Result<()> {
        let nothing = state
            .replicas
            .get(space)
            .is_some_and(|r| r.guest_facts().nothing_at_rest);
        if nothing {
            Self::keep_space_in_memory(state, space).await?;
        }
        Ok(())
    }

    /// Keeps a space in memory only from now on, before anything of it is
    /// adopted or placed, as the offer or welcome that admits this device
    /// says its grant carries `frasil.nothing-at-rest` (ext-guests.md,
    /// "Nothing at rest"; at-rest.md, "A memory-only log").
    ///
    /// # Errors
    ///
    /// The store's.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn keep_in_memory(&self, space: &EventId) -> Result<()> {
        let mut state = self.lock().await;
        Self::keep_space_in_memory(&mut state, space).await
    }

    /// Whether this device forgets a memory-only space now (ext-guests.md,
    /// "Nothing at rest"): at `SessionEnded`, and once it learns of its
    /// removal. A space kept at rest is never forgotten here.
    pub(crate) async fn memory_only_ended(&self, space: &EventId) -> bool {
        let me = self.device_id();
        let mut state = self.lock().await;
        if !state.vault.is_memory_only(&space.0) {
            return false;
        }
        let removed = state
            .replicas
            .get(space)
            .is_some_and(|r| r.was_member() && r.level_of(&me).is_none());
        removed
            || matches!(
                self.writer_check(&mut state, space).await,
                Err(Error::Class("SessionEnded"))
            )
    }

    /// Forgets every memory-only space whose session ended or that removed
    /// this device ([`Engine::memory_only_ended`]), with the memory-only
    /// logs along its grant path. The spaces forgotten.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn forget_ended_memory_only(&self) -> Result<Vec<EventId>> {
        let mut forgotten = Vec::new();
        for space in self.spaces().await {
            if self.memory_only_ended(&space).await {
                forgotten.extend(self.forget_with_grant_path(&space).await?);
            }
        }
        Ok(forgotten)
    }

    /// Forgets a space, then the logs along its grant path that are kept in
    /// memory only and that this device is no member of: what a newcomer's
    /// snapshot of a memory-only space brought (ext-guests.md, "Nothing at
    /// rest"). The spaces forgotten.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn forget_with_grant_path(&self, space: &EventId) -> Result<Vec<EventId>> {
        let path: Vec<EventId> = {
            let state = self.lock().await;
            let mut seen = BTreeSet::new();
            let mut todo = vec![*space];
            while let Some(next) = todo.pop() {
                let Some(replica) = state.replicas.get(&next) else {
                    continue;
                };
                for (member, _) in replica.roster().members_in() {
                    if member.kind == MemberType::Space && seen.insert(EventId(member.id)) {
                        todo.push(EventId(member.id));
                    }
                }
            }
            seen.into_iter()
                .filter(|id| {
                    id != space
                        && state.vault.is_memory_only(&id.0)
                        && state.replicas.get(id).is_some_and(|r| !r.was_member())
                })
                .collect()
        };
        self.forget_space(space).await?;
        for id in &path {
            self.forget_space(id).await?;
        }
        let mut forgotten = vec![*space];
        forgotten.extend(path);
        Ok(forgotten)
    }

    /// Forgets every space kept in memory only, as when the application
    /// closes them (ext-guests.md, "Nothing at rest"); the spaces
    /// forgotten.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn forget_memory_only(&self) -> Result<Vec<EventId>> {
        let mut forgotten = Vec::new();
        for space in self.spaces().await {
            if self.lock().await.vault.is_memory_only(&space.0) {
                self.forget_space(&space).await?;
                forgotten.push(space);
            }
        }
        Ok(forgotten)
    }

    /// Keeps a space in memory only, and forgets what the store holds of
    /// it, its stored chunks read back into memory first.
    async fn keep_space_in_memory(state: &mut State, space: &EventId) -> Result<()> {
        if !state.vault.is_memory_only(&space.0) {
            // The chunks in the store come back into memory first.
            let stored = state
                .replicas
                .get(space)
                .map(crate::replica::Replica::stored_chunks)
                .unwrap_or_default();
            for (locator, indices) in stored {
                let chunks =
                    crate::objects::read_chunks(&state.vault, space, &locator, &indices).await?;
                if let (Some(chunks), Some(replica)) = (chunks, state.replicas.get_mut(space)) {
                    replica.fill_chunks(&locator, chunks);
                }
            }
            if let Some(replica) = state.replicas.get_mut(space) {
                replica.unstore_chunks();
            }
            state.vault.keep_in_memory(&space.0).await?;
        }
        Ok(())
    }
}
