//! Automatic heals and cascades (keys.md, "Healing", "Cascades", "The rank
//! and the delay").
//!
//! [`Engine::maintain`] runs a space's client policy:
//!
//! - **Responses.** For each space C that the space X grants and whose log
//!   this device holds, X owes a response when no space principal of C's
//!   current grant rotation is in force in X: after a change in C, or when
//!   a response's notice failed. X's writer devices that propagate in X and
//!   in C are the candidates, ranked with the change's event ID as the
//!   trigger. The response rotates, with a grant rotation, when X lost a
//!   device or C healed its grant key, and breaks when C admitted a member
//!   "from now on"; otherwise it only delivers. Every response names the
//!   change in its sealed refs and carries a notice for C's grant rotation.
//!   A candidate stands down only when a principal of that rotation is in
//!   force, so a response whose notice fails does not stop it.
//! - **Heals.** When the heal test fires, every candidate waits its rank
//!   delay, with the healed state's `encode_set` as the trigger, from its
//!   first sight of the test firing; a rotation that follows the healed
//!   state ends the test, and with it the heal.
//!
//! Every rotation this device makes renews its principals: a granted space
//! whose principal in force is not its current grant rotation is noticed
//! again where this device can, so a heal never seals to a principal a
//! change has put out of date.
//!
//! Until X has rotated after a change that cost it a device, this device
//! writes no unit to X.
//!
//! - **Deliveries.** An inside device that derives no current state, such
//!   as a member admitted "from now on" whose break merged with a rotation
//!   concurrent with it, receives that state in a key event that only
//!   delivers, from one writer after its rank delay (keys.md,
//!   "Deliveries").
//!
//! [`Engine::top_up`] hands members admitted "from now on" the body keys
//! of space events and units concurrent with their break (admission.md,
//! "Top-ups").

use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::replica::RotationSecrets;
use crate::writer::{self, Sealing, SpaceEventPlan, SpacePrincipal};
use frasil_base::time::{Reading, Timer};
use frasil_crypto::device::DeviceId;
use frasil_events::{EventId, Ref};
use frasil_keys::body::Notice;
use frasil_space::keygraph::rank;
use frasil_space::{Level, MemberType};
use std::collections::BTreeSet;

/// A response space X owes to a change: in a space C it grants, or a
/// person's list's revocation of a device X reached through the person.
#[derive(Debug, Clone)]
pub(crate) struct Owed {
    /// C, or the person whose list revoked.
    pub granted: EventId,
    /// C's current grant rotation, which the response notices; or the
    /// revocation.
    pub rotation: EventId,
    /// Whether the change is a list's revocation.
    pub list: bool,
    /// The devices X lost by the change.
    pub lost: Vec<[u8; 32]>,
    /// Whether the response rotates.
    pub rotates: bool,
    /// Whether it breaks: C admitted a member "from now on".
    pub breaks: bool,
    /// X's grant of C, at most `write`.
    pub level: Level,
}

/// What [`Engine::maintain`] signed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Maintained {
    /// A rotation: a heal, a cascaded rotation, or both at once.
    pub rotation: Option<EventId>,
    /// A response that only delivers, or a delivery to the devices a
    /// granted person's list added.
    pub delivery: Option<EventId>,
}

/// Devices a granted person's list added that the space has not reached:
/// their `add` is not among the space's list copies.
#[derive(Debug, Clone)]
struct ListAdditions {
    person: [u8; 32],
    level: Level,
    /// The devices, as a delivery names them.
    recipients: Vec<writer::Recipient>,
    /// Their `add`s: each the trigger of the rank delay.
    adds: Vec<EventId>,
}

/// `rotation_step`, in seconds.
pub(crate) fn rotation_step() -> u64 {
    Timer::RotationStep.spec().default.unwrap_or(5)
}

impl Engine {
    /// The responses `space` owes to changes in the spaces it grants, as
    /// this device sees them.
    pub(crate) fn owed(&self, state: &State, space: &EventId) -> Vec<Owed> {
        let Some(replica) = state.replicas.get(space) else {
            return Vec::new();
        };
        let reached: BTreeSet<[u8; 32]> = replica.devices().into_iter().map(|(d, _)| d.0).collect();
        let mut out = Vec::new();
        for (member, membership) in replica.roster().members_in() {
            if member.kind != MemberType::Space {
                continue;
            }
            let granted = EventId(member.id);
            let Some(other) = state.replicas.get(&granted) else {
                continue;
            };
            let Some(grant_state) = other.grant_current() else {
                continue;
            };
            let [rotation] = grant_state.ids() else {
                continue;
            };
            let in_force: Vec<EventId> = replica
                .principals()
                .iter()
                .filter(|(t, ..)| *t == granted)
                .map(|(_, r, ..)| *r)
                .collect();
            if in_force.contains(rotation) {
                continue;
            }
            // The devices the principals in force stood for that the space
            // no longer reaches.
            let mut lost: BTreeSet<[u8; 32]> = BTreeSet::new();
            if let Some(facts) = other.facts() {
                for r in &in_force {
                    lost.extend(
                        facts
                            .grant_holders(*r)
                            .into_iter()
                            .filter(|d| !reached.contains(d)),
                    );
                }
            }
            let breaks = breaks_at(other, rotation);
            // A grant rotation of C that is no roster event heals, collapses
            // or cascades C's grant key: the spaces C reaches rotate.
            let heals = !in_force.is_empty() && !other.is_roster(rotation);
            out.push(Owed {
                granted,
                rotation: *rotation,
                list: false,
                // A restricted space has no grant state to deliver under:
                // its responses rotate (ext-restricted-spaces.md, "Keys of a
                // restricted space").
                rotates: !lost.is_empty() || breaks || heals || !Self::draws_grant(replica),
                lost: lost.into_iter().collect(),
                breaks,
                level: membership.level.min(Level::Write),
            });
        }
        // Revocations by the lists of persons the space grants, after the
        // list state its events last named: the space reached the device.
        for (member, membership) in replica.roster().members_in() {
            if member.kind != MemberType::Person {
                continue;
            }
            let Some(list) = state.lists.get(&member.id) else {
                continue;
            };
            let log = EventId(member.id);
            let named = replica.named_in(&log);
            if named.is_empty() {
                continue;
            }
            let merged = list.merge();
            for id in list.canonical() {
                let Some(body) = list.body(id) else {
                    continue;
                };
                if body.action != frasil_identity::body::Action::Revoke || !merged.is_valid(id) {
                    continue;
                }
                let answered = named.iter().any(|n| *n == id || list.precedes(id, *n));
                if answered {
                    continue;
                }
                out.push(Owed {
                    granted: log,
                    rotation: id,
                    list: true,
                    lost: vec![body.device.0],
                    rotates: true,
                    breaks: false,
                    level: membership.level.min(Level::Write),
                });
            }
        }
        out
    }

    /// Whether a change that cost `space` a device waits for its cascaded
    /// rotation: until then this device writes nothing to the space.
    pub(crate) fn cascade_waits(&self, state: &State, space: &EventId) -> bool {
        self.owed(state, space).iter().any(|o| !o.lost.is_empty())
    }

    /// The spaces granted by `space` that owe a response, as this device
    /// sees them, each with the grant rotation the response would notice.
    pub async fn owed_responses(&self, space: &EventId) -> Vec<(EventId, EventId)> {
        let state = self.lock().await;
        self.owed(&state, space)
            .into_iter()
            .map(|o| (o.granted, o.rotation))
            .collect()
    }

    /// Runs the space's heals and cascades (module docs): signs what is due
    /// at this device now, after its rank delay, and nothing else.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::SyncBeforeWriting`]; the store's.
    pub async fn maintain(&self, space: EventId) -> Result<Maintained> {
        let mut state = self.lock().await;
        let me = self.device_id();
        let now = self.read_timeline(&mut state).await?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.level_of(&me) < Some(Level::Write)
            || Self::check_may_sign(&state, &space).is_err()
        {
            return Ok(Maintained::default());
        }
        let propagates = replica.propagates(&me);
        // Responses this device may make: it propagates in both spaces and
        // can notice the granted space's rotation.
        let owed: Vec<Owed> = self
            .owed(&state, &space)
            .into_iter()
            .filter(|o| propagates && (o.list || self.notice_of(&state, &o.granted).is_ok()))
            .collect();
        let mut due = Vec::new();
        let mut sights = Vec::new();
        for o in &owed {
            // The candidates: the space's writer devices that propagate,
            // and for a change in a granted space, propagate there too.
            let other = state.replicas.get(&o.granted);
            let candidates: Vec<[u8; 32]> = replica
                .devices()
                .into_iter()
                .filter(|(d, level)| {
                    *level >= Level::Write
                        && replica.propagates(d)
                        && (o.list || other.is_some_and(|c| c.propagates(d)))
                })
                .map(|(d, _)| d.0)
                .collect();
            let Some(position) = rank::position(&space.0, &o.rotation.0, &candidates, &me.0) else {
                continue;
            };
            // The trigger's first sight: its event record's, in the granted
            // space's log or the person's list.
            let key = (space, o.rotation.0.to_vec());
            let first = other
                .and_then(|c| c.first_sight(&o.rotation).copied())
                .or_else(|| state.list_sights.get(&o.rotation).copied())
                .or_else(|| state.heal_sights.get(&key).copied())
                .unwrap_or(now);
            sights.push((key, first));
            if rank::due(&first, &now, position, rotation_step()) {
                due.push(o.clone());
            }
        }
        for (key, first) in sights {
            state.heal_sights.entry(key).or_insert(first);
        }
        if due.iter().any(|o| o.rotates) {
            let breaks = due.iter().any(|o| o.breaks);
            let id = Box::pin(self.rotate(&mut state, space, &owed, breaks)).await?;
            drop(state);
            Box::pin(self.after_rotation(space, &owed)).await?;
            return Ok(Maintained {
                rotation: Some(id),
                delivery: None,
            });
        }
        if !due.is_empty() {
            let id = Box::pin(self.deliver_responses(&mut state, space, &due)).await?;
            return Ok(Maintained {
                rotation: None,
                delivery: Some(id),
            });
        }
        // While a change that cost the space a device waits for its
        // response, this device writes nothing else to the space: no
        // delivery to a person's new device, which the cascaded rotation
        // reaches anyway, and no heal, which is left to the cascade's
        // candidates, ranked by the change (a heal would also seal again to
        // the principal the change put out of date).
        if !owed.is_empty() || self.cascade_waits(&state, &space) {
            return Ok(Maintained::default());
        }
        // A person's new devices, which this device's copy of the list holds
        // and the space's list copies do not (identity.md, "Other spaces";
        // admission.md, "A person's new device"): after the rank delay from
        // the add's first sight, the current state goes to the devices, the
        // list to the space, and a welcome to each device.
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let found = list_additions(&state, &space, &me);
        // The candidates: the space's writer devices that propagate, other
        // than the new devices, which hold nothing to deliver.
        let new: BTreeSet<DeviceId> = found
            .iter()
            .flat_map(|added| added.recipients.iter().map(|r| r.keys.device_id()))
            .collect();
        let candidates: Vec<[u8; 32]> = replica
            .devices()
            .into_iter()
            .filter(|(d, level)| {
                *level >= Level::Write && replica.propagates(d) && !new.contains(d)
            })
            .map(|(d, _)| d.0)
            .collect();
        let mut additions = Vec::new();
        for added in found {
            let due = added.adds.iter().any(|add| {
                rank::position(&space.0, &add.0, &candidates, &me.0).is_some_and(|position| {
                    let first = state.list_sights.get(add).copied().unwrap_or(now);
                    rank::due(&first, &now, position, rotation_step())
                })
            });
            if due {
                additions.push(added);
            }
        }
        if !additions.is_empty() {
            drop(state);
            let mut delivered = None;
            for added in additions {
                // The delivery first: the list's copy in the space is what
                // marks the devices reached, so it goes in only once they
                // are. A delivery that fails leaves the add unpublished,
                // and the next maintenance tries again.
                let (delivery, wraps) =
                    Box::pin(self.deliver_with(space, added.recipients)).await?;
                // The welcomes at rest before the list's copy: a crash
                // between the delivery and them leaves the add unpublished,
                // so the next maintenance delivers and welcomes again.
                #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
                Box::pin(self.welcome_person(space, added.person, added.level, delivery, &wraps))
                    .await?;
                #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
                let _ = (wraps, added.level);
                Box::pin(self.publish_list(space, &added.person)).await?;
                delivered = Some(delivery);
            }
            return Ok(Maintained {
                rotation: None,
                delivery: delivered,
            });
        }
        // Heals, after the rank delay from the first sight of the test.
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let mut heal_due = false;
        let mut sights = Vec::new();
        for heal in replica.heals() {
            let trigger = crate::healing::trigger(&heal.state);
            // A heal's trigger is a state, which has no event record: its
            // first sight is kept while the device runs, and after a
            // restart is taken as the newest first sight among the view's
            // events, which is never earlier than the test first fired.
            let first = state
                .heal_sights
                .get(&(space, trigger.clone()))
                .copied()
                .or_else(|| replica.latest_sight().copied())
                .unwrap_or(now);
            sights.push(((space, trigger.clone()), first));
            let Some(position) = rank::position(&space.0, &trigger, &heal.candidates, &me.0) else {
                continue;
            };
            heal_due |= rank::due(&first, &now, position, rotation_step());
        }
        for (key, first) in sights {
            state.heal_sights.entry(key).or_insert(first);
        }
        // A claimant heals only once its successor is durable: until then
        // its connections present the state the invite key held, under
        // whose upload key the successor goes to peers
        // (ext-invite-links.md, "Claiming", step 11, and "Keys", the heal).
        #[cfg(feature = "ext-invite-links")]
        if heal_due && crate::invite_links::claim_unpublished(&state, &space) {
            heal_due = false;
        }
        if heal_due {
            let id = Box::pin(self.rotate(&mut state, space, &owed, false)).await?;
            drop(state);
            Box::pin(self.after_rotation(space, &owed)).await?;
            return Ok(Maintained {
                rotation: Some(id),
                delivery: None,
            });
        }
        // The current state, to inside devices that derive none, then every
        // other state inside devices are entitled to and derive none
        // (keys.md, "Deliveries", items 1 and 2): each after the rank delay
        // over the writer devices that derive none of it, with its
        // `encode_set` as the trigger, from the first sight of the lack, by
        // a device that holds it. A delivery the view holds counts as
        // reaching the devices of its place's roster, which ends the lack;
        // this device delivers the current state once, and another state
        // once to the same devices.
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let latest = replica.latest_sight().copied();
        let lacks: Vec<(crate::healing::Lacking, bool)> = replica
            .lacking()
            .map(|l| (l.clone(), true))
            .into_iter()
            .chain(
                replica
                    .entitled_lacking()
                    .iter()
                    .map(|l| (l.clone(), false)),
            )
            .filter(|(l, _)| replica.state_key(&l.state).is_some())
            .collect();
        let mut chosen = None;
        for (lacking, current) in lacks {
            let trigger = crate::healing::trigger(&lacking.state);
            let key = (space, trigger.clone());
            let first = *state
                .heal_sights
                .entry(key.clone())
                .or_insert(latest.unwrap_or(now));
            let due = rank::position(&space.0, &trigger, &lacking.candidates, &me.0)
                .is_some_and(|position| rank::due(&first, &now, position, rotation_step()));
            let mut key = key;
            if !current {
                key.1.extend(lacking.devices.iter().flatten());
            }
            if !due || state.delivered_states.contains(&key) {
                continue;
            }
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let devices: BTreeSet<[u8; 32]> = lacking.devices.iter().copied().collect();
            let recipients: Vec<_> = self
                .recipients_after(replica, &[], &state.lists, &state.replicas)
                .into_iter()
                .filter(|r| devices.contains(&r.keys.device_id().0))
                .collect();
            if !recipients.is_empty() {
                chosen = Some((key, lacking.state, current, recipients));
                break;
            }
        }
        let Some((key, delivered, current, recipients)) = chosen else {
            return Ok(Maintained::default());
        };
        state.delivered_states.insert(key);
        drop(state);
        let id = if current {
            self.deliver(space, recipients).await?
        } else {
            self.deliver_state(space, delivered, recipients).await?
        };
        Ok(Maintained {
            rotation: None,
            delivery: Some(id),
        })
    }

    /// Hands members admitted "from now on" the body keys they are owed
    /// (admission.md, "Top-ups"): for each space event or unit of a break's top-up
    /// set that this device opened and whose body key no body-keys unit
    /// after the break carries, after this device's rank delay over the
    /// space's writer devices, with the event's ID as the trigger, from its
    /// first sight of the event. The keys due go out in `frasil:body-keys`
    /// units of the system stream, sealed under the current state. Returns
    /// the units written.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; as [`Engine::publish_body_keys`].
    pub async fn top_up(&self, space: EventId) -> Result<Vec<EventId>> {
        let due: Vec<EventId> = {
            let mut state = self.lock().await;
            let me = self.device_id();
            let now = self.read_timeline(&mut state).await?;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            if replica.top_ups().is_empty()
                || replica.level_of(&me) < Some(Level::Write)
                || Self::check_may_sign(&state, &space).is_err()
            {
                return Ok(Vec::new());
            }
            let candidates: Vec<[u8; 32]> = replica
                .devices()
                .into_iter()
                .filter(|(_, level)| *level >= Level::Write)
                .map(|(d, _)| d.0)
                .collect();
            // An event with no recorded first sight, such as one this
            // device wrote, is first seen when the device first finds it
            // owed: kept while it runs, as a heal's trigger is, and after a
            // restart taken as the newest first sight among the view's
            // events.
            let latest = replica.latest_sight().copied();
            let owed: Vec<(EventId, Option<Reading>)> = replica
                .top_ups()
                .iter()
                .copied()
                .filter(|id| replica.body_key(id).is_some())
                .map(|id| (id, replica.first_sight(&id).copied()))
                .collect();
            let mut due = Vec::new();
            for (id, recorded) in owed {
                let first = match recorded {
                    Some(first) => first,
                    None => *state
                        .heal_sights
                        .entry((space, id.0.to_vec()))
                        .or_insert(latest.unwrap_or(now)),
                };
                if rank::position(&space.0, &id.0, &candidates, &me.0)
                    .is_some_and(|position| rank::due(&first, &now, position, rotation_step()))
                {
                    due.push(id);
                }
            }
            due
        };
        let mut written = Vec::new();
        for chunk in due.chunks(frasil_units::limits::MAX_BODY_KEYS) {
            written.push(self.publish_body_keys(space, chunk).await?);
        }
        Ok(written)
    }

    /// After a rotation that answers a list's revocation, the list's new
    /// state goes to the space as a `frasil:list` unit, which waited for the
    /// rotation (keys.md, "Cascades", "Before the cascade").
    pub(crate) async fn after_rotation(&self, space: EventId, owed: &[Owed]) -> Result<()> {
        let persons: BTreeSet<[u8; 32]> = owed
            .iter()
            .filter(|o| o.list)
            .map(|o| o.granted.0)
            .collect();
        for person in persons {
            self.publish_list(space, &person).await?;
        }
        Ok(())
    }

    /// [`Engine::maintain`] for every space the device holds, each once;
    /// what each signed. With `ext-invite-links`, each space's invites are
    /// maintained first.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn maintain_all(&self) -> Result<Vec<(EventId, Maintained)>> {
        let mut out = Vec::new();
        self.forget_stale_claims().await?;
        // A space kept in memory only goes at `SessionEnded`, and once this
        // device learns of its removal (ext-guests.md, "Nothing at rest").
        #[cfg(feature = "ext-guests")]
        self.forget_ended_memory_only().await?;
        // The person's device list: late revocations re-signed, its
        // pending checkpoint voted for, a checkpoint proposed when due
        // (identity.md, 3.16 List checkpoints).
        match Box::pin(self.maintain_list_checkpoint()).await {
            Ok(_) | Err(Error::NotAllowed(_) | Error::Class(_)) => {}
            Err(error) => return Err(error),
        }
        // Every list's events before its list checkpoint in effect, when the
        // policy forgets (identity.md, "List checkpoints", "Forgetting").
        if self.checkpoint_policy().forget {
            self.forget_lists_before_checkpoints().await?;
        }
        for space in self.presentable_spaces().await {
            // Invites' closes and revocations (ext-invite-links.md,
            // "Administering devices").
            #[cfg(feature = "ext-invite-links")]
            match self.maintain_invites(space).await {
                Ok(_) | Err(Error::UnknownSpace | Error::NotAllowed(_)) => {}
                Err(error) => return Err(error),
            }
            // An agent's adds relayed, and the members newly vouched for
            // delivered to (ext-recovery-agent.md).
            #[cfg(feature = "ext-recovery-agent")]
            match self.relay_agent_adds(space).await {
                Ok(()) | Err(Error::UnknownSpace | Error::NotAllowed(_)) => {}
                Err(error) => return Err(error),
            }
            match Box::pin(self.maintain(space)).await {
                Ok(done) if done != Maintained::default() => out.push((space, done)),
                Ok(_) | Err(Error::UnknownSpace | Error::NotAllowed(_)) => {}
                Err(error) => return Err(error),
            }
            // Checkpoints: votes, late work, proposals and forgetting
            // (roster.md, 3.15.7 Clients).
            match Box::pin(self.maintain_checkpoints(space)).await {
                Ok(_)
                | Err(
                    Error::UnknownSpace
                    | Error::NotAllowed(_)
                    | Error::SyncBeforeWriting
                    | Error::Class(_),
                ) => {}
                Err(error) => return Err(error),
            }
            // Body keys owed to members admitted "from now on"
            // (admission.md, "Top-ups").
            match self.top_up(space).await {
                Ok(_)
                | Err(
                    Error::UnknownSpace
                    | Error::NotAllowed(_)
                    | Error::SyncBeforeWriting
                    | Error::Class(_),
                ) => {}
                Err(error) => return Err(error),
            }
            // Snapshots settled, used and collected; restores of false
            // ones (units.md, "Checking, using and settling a snapshot").
            match self.collect(space).await {
                Ok(_) | Err(Error::UnknownSpace | Error::NotAllowed(_)) => {}
                Err(error) => return Err(error),
            }
            match self.restore_compactions(space).await {
                Ok(_)
                | Err(
                    Error::UnknownSpace
                    | Error::NotAllowed(_)
                    | Error::SyncBeforeWriting
                    | Error::Class(_),
                ) => {}
                Err(error) => return Err(error),
            }
            // Live ephemeral slots published again under a new state
            // (ext-ephemeral.md, "Sending").
            #[cfg(feature = "ephemeral")]
            let _ = self.republish_slots(space, false).await;
            // Guests due by their session's expiry or their leave
            // requests (ext-guests.md).
            #[cfg(feature = "ext-guests")]
            match self.expire_guests(space).await {
                Ok(_) | Err(Error::UnknownSpace | Error::NotAllowed(_) | Error::Class(_)) => {}
                Err(error) => return Err(error),
            }
            // Heartbeats under a bounded window (ext-guests.md).
            #[cfg(feature = "ext-guests")]
            match self.heartbeat(space).await {
                Ok(_) | Err(Error::UnknownSpace | Error::NotAllowed(_) | Error::Class(_)) => {}
                Err(error) => return Err(error),
            }
            // A restricted space's mirrors of its parent's removals, and the
            // late writes of moved documents (ext-restricted-spaces.md).
            #[cfg(feature = "ext-restricted-spaces")]
            {
                match self.mirror_parent(space).await {
                    Ok(_) | Err(Error::UnknownSpace | Error::NotAllowed(_)) => {}
                    Err(error) => return Err(error),
                }
                match self.mirror_administrators(space).await {
                    Ok(_) | Err(Error::UnknownSpace | Error::NotAllowed(_)) => {}
                    Err(error) => return Err(error),
                }
                match self.reapply_late_writes(space).await {
                    Ok(_) | Err(Error::UnknownSpace | Error::NotAllowed(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(out)
    }

    /// The renewed principals of a rotation of `space`: each principal in
    /// force, except that a granted space owing a response is noticed at
    /// its current grant rotation; with the notices and refs that takes.
    pub(crate) fn renewed_principals(
        &self,
        state: &State,
        space: &EventId,
        owed: &[Owed],
    ) -> Result<(Vec<SpacePrincipal>, Vec<Notice>, Vec<Ref>)> {
        let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
        let mut principals = Vec::new();
        let mut notices = Vec::new();
        let mut refs = Vec::new();
        let renewed: BTreeSet<EventId> = owed.iter().map(|o| o.granted).collect();
        for (t, r, public, level) in replica.principals() {
            if renewed.contains(t) {
                continue;
            }
            principals.push(SpacePrincipal {
                space: *t,
                rotation: *r,
                public: public.clone(),
                writes: *level >= Level::Write,
            });
        }
        for o in owed {
            if o.list {
                // A revocation's response names the list's heads, which
                // hold it in their past.
                if let Some(list) = state.lists.get(&o.granted.0) {
                    refs.extend(
                        list.heads()
                            .into_iter()
                            .map(|id| Ref { log: o.granted, id }),
                    );
                }
                continue;
            }
            let (notice, _) = self.notice_of(state, &o.granted)?;
            principals.push(SpacePrincipal {
                space: o.granted,
                rotation: notice.rotation,
                public: notice.public.clone(),
                writes: o.level >= Level::Write,
            });
            refs.push(Ref {
                log: o.granted,
                id: o.rotation,
            });
            notices.push(notice);
        }
        refs.sort_by_key(|a| (a.log.0, a.id.0));
        refs.dedup();
        Ok((principals, notices, refs))
    }

    /// Signs a rotation of `space` that heals both graphs and answers
    /// every response owed that this device can make: a grant rotation
    /// that links back to the state it heals, or carries the gap records
    /// of a break.
    pub(crate) async fn rotate(
        &self,
        state: &mut State,
        space: EventId,
        owed: &[Owed],
        breaks: bool,
    ) -> Result<EventId> {
        self.publish_own_lists(state, space).await?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let (principals, notices, refs) = self.renewed_principals(state, &space, owed)?;
        // A response that rotates is a grant rotation; a heal is one when
        // its author propagates (keys.md, "Checks against the event and its
        // place", steps 5 to 7; "Healing").
        let grant_rotation = replica.propagates(&self.device_id()) && Self::draws_grant(replica);
        #[cfg(feature = "ext-guests")]
        {
            self.writer_check(state, &space).await?;
        }
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let (seq, prev) = Self::next(state, &space, &self.device_id());
        let parents = replica.parents(prev);
        let cuts = replica.cuts_for(&parents)?;
        let signed = writer::space_event(
            self.platform(),
            self.signer(),
            SpaceEventPlan {
                space,
                seq,
                prev,
                parents,
                cuts,
                checkpoint: None,
                changes: None,
                sealing: Sealing::Rotate {
                    fresh: writer::Fresh::draw(self.platform())?,
                    is_break: breaks,
                    grant_rotation,
                    recipients: self.recipients_after(replica, &[], &state.lists, &state.replicas),
                    removed: Vec::new(),
                    previous: Self::held_state(replica).ok(),
                    previous_grant: Self::held_grant(replica),
                },
                refs,
                twin: None,
                notices,
                principals,
                grantless: !Self::draws_grant(replica),
            },
        )?;
        let rotation = signed.fresh.as_ref().map(|fresh| RotationSecrets {
            content: Some(fresh.content.clone()),
            upload: Some(fresh.upload.clone()),
            grant: signed.grant_rotation.then(|| fresh.grant.clone()),
        });
        self.commit_own(state, space, &signed.signed, rotation)
            .await
    }

    /// Signs a response that only delivers: a notice for each granted
    /// space's current grant rotation, and a space wrap of the current
    /// state to it, sealed under the current state.
    async fn deliver_responses(
        &self,
        state: &mut State,
        space: EventId,
        owed: &[Owed],
    ) -> Result<EventId> {
        self.publish_own_lists(state, space).await?;
        #[cfg(feature = "ext-guests")]
        self.writer_check(state, &space).await?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let held = Self::held_state(replica)?;
        let grant = Self::held_grant(replica).ok_or(Error::NotAllowed(
            "the device lacks the current grant state",
        ))?;
        let (principals, notices, refs) = self.renewed_principals(state, &space, owed)?;
        let renewed: BTreeSet<EventId> = owed.iter().map(|o| o.granted).collect();
        let principals = principals
            .into_iter()
            .filter(|p| renewed.contains(&p.space))
            .collect();
        let (seq, prev) = Self::next(state, &space, &self.device_id());
        let parents = replica.parents(prev);
        let cuts = replica.cuts_for(&parents)?;
        let signed = writer::space_event(
            self.platform(),
            self.signer(),
            SpaceEventPlan {
                space,
                seq,
                prev,
                parents,
                cuts,
                checkpoint: None,
                changes: None,
                sealing: Sealing::Under {
                    state: held,
                    grant: Some(grant),
                    recipients: Vec::new(),
                    others: Vec::new(),
                },
                refs,
                twin: None,
                notices,
                principals,
                grantless: !Self::draws_grant(replica),
            },
        )?;
        self.commit_own(state, space, &signed.signed, None).await
    }
}

/// Whether a grant rotation of a granted space is a break: its grant
/// commitment is the "from now on" one.
fn breaks_at(replica: &crate::replica::Replica, rotation: &EventId) -> bool {
    let Some(seed) = replica.secrets_of(rotation).and_then(|s| s.grant.clone()) else {
        return false;
    };
    let key = frasil_keys::derive::GrantKey::derive(&seed);
    replica
        .event(*rotation)
        .and_then(crate::replica::visible)
        .and_then(|v| v.rotation().map(|r| r.grant_commitment))
        == Some(key.commitment(true))
}

/// The devices each granted person's list added, as this device holds the
/// list, whose `add` the space's list copies lack, other than this device:
/// the space has not reached them. A device the list's copies in the space
/// already add was reached with them.
fn list_additions(state: &State, space: &EventId, me: &DeviceId) -> Vec<ListAdditions> {
    let Some(replica) = state.replicas.get(space) else {
        return Vec::new();
    };
    let held = replica.list_copies_held();
    let mut out = Vec::new();
    for (member, membership) in replica.roster().members_in() {
        if member.kind != MemberType::Person {
            continue;
        }
        let Some(list) = state.lists.get(&member.id) else {
            continue;
        };
        let merged = list.merge();
        let mut recipients = Vec::new();
        let mut adds = Vec::new();
        for recipient in crate::device::person_recipients(
            &member.id,
            membership.level,
            &state.lists,
            Some(replica),
        ) {
            let device = recipient.keys.device_id();
            if device == *me {
                continue;
            }
            let Some(add) = merged.active(&device).and_then(|m| m.adds.first().copied()) else {
                continue;
            };
            if held.contains(&add) {
                continue;
            }
            adds.push(add);
            recipients.push(recipient);
        }
        if !recipients.is_empty() {
            out.push(ListAdditions {
                person: member.id,
                level: membership.level,
                recipients,
                adds,
            });
        }
    }
    out
}
