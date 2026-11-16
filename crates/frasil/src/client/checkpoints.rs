//! Checkpoints, as a device acts on them (roster.md, 3.15.7 Clients;
//! identity.md, 3.16 List checkpoints).
//!
//! The replica judges its view with its checkpoints and follows one
//! (`crate::checkpoints`). On top of that a device:
//!
//! - **proposes** a checkpoint when it administers the space, no checkpoint
//!   waits for votes, and the roster history since the last one in effect
//!   reaches [`PROPOSE_AT_ROSTER_EVENTS`](crate::PROPOSE_AT_ROSTER_EVENTS)
//!   valid roster events or
//!   [`PROPOSE_AT_FRAME_BYTES`](crate::PROPOSE_AT_FRAME_BYTES) of frame
//!   events, the most senior
//!   administrator first and the others after their rank delay with the
//!   epoch as trigger ([`Engine::propose_checkpoint`] proposes at once). It
//!   seals the record of the checkpoint's past as its object, under the
//!   checkpoint's own content key, keeps it, signs the skeleton cut that
//!   names it with its pseudonym, then the checkpoint: a grant rotation
//!   where the device propagates, no break, delivering the new state to
//!   every member;
//! - **votes** for the checkpoint it follows while it waits for this device,
//!   by an anchor when it has nothing else to write
//!   ([`Engine::acknowledge_checkpoint`]);
//! - **re-submits** its own late units, each as a new unit after the
//!   checkpoint whose `resubmits` names it ([`Engine::resubmit_late_units`]),
//!   and **re-signs** its own late removals and demotions that the roster
//!   still needs ([`Engine::resign_late_removals`]); its other late changes
//!   are reported for the administrator to make again;
//! - **forgets** what came before the checkpoint in effect
//!   ([`Engine::forget_before_checkpoint`]), in memory and at rest, keeping
//!   what roster.md, 3.15.6, says it keeps;
//! - does the same for its person's device list: proposes a list
//!   checkpoint (action 3), acknowledges one (action 4), and re-signs its
//!   late revocations ([`Engine::maintain_list_checkpoint`]); and forgets,
//!   in every list it holds, the events before the list checkpoint in
//!   effect ([`Engine::forget_lists_before_checkpoints`]), holding the list
//!   from that checkpoint on in memory and at rest;
//! - keeps at rest what reopening a log that forgot, or that started from
//!   a checkpoint, needs: the record keys a snapshot handed over, the IDs
//!   of what it dropped and the kept checkpoint envelopes
//!   (`frasil_store::checkpoint_state`).
//!
//! [`Engine::maintain_checkpoints`] runs all of it under the device's
//! [`CheckpointPolicy`], from the device's upkeep.

use super::{ChangeId, CheckpointId, Device, MemberId, Space};
use crate::at_rest::Batch;
use crate::checkpoints::CheckpointPolicy;
use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::replica::RotationSecrets;
use crate::writer::{self, Sealing, SpaceEventPlan, SpacePrincipal};
use frasil_crypto::device::DeviceId;
use frasil_crypto::schemes::Scheme;
use frasil_events::{Envelope, EventId, kind};
use frasil_keys::SelfRef;
use frasil_peers::body::{Cut, StorageBody};
use frasil_peers::derive::{twin_commitment, twin_secret};
use frasil_space::keygraph::rank;
use frasil_space::{Change, CheckpointPart, Level, Op};
use frasil_store::tables::LogState;
use frasil_store::{Table, TableValue};
use frasil_units::unit::Draft;
use std::collections::BTreeSet;

/// A record's plaintext with record key 9 added, for a device that
/// [`crate::checkpoints::LATER_RECORD_KEY`] names.
#[cfg(test)]
fn later_key(me: &DeviceId, plaintext: Vec<u8>) -> Vec<u8> {
    let named = crate::checkpoints::LATER_RECORD_KEY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(me);
    match frasil_base::cbor::decode(&plaintext) {
        Ok(frasil_base::cbor::Value::Map(mut map)) if named => {
            map.insert(9, frasil_base::cbor::Value::Unsigned(1));
            frasil_base::cbor::Value::Map(map).encode()
        }
        _ => plaintext,
    }
}

/// What [`Engine::maintain_checkpoints`] did in one space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckpointWork {
    /// The checkpoint this device proposed.
    pub proposed: Option<EventId>,
    /// The anchor by which this device voted for the checkpoint it follows.
    pub acknowledged: Option<EventId>,
    /// The units that re-submit this device's late units.
    pub resubmitted: Vec<EventId>,
    /// The roster events that re-sign this device's late removals and
    /// demotions.
    pub resigned: Vec<EventId>,
    /// How many events the device forgot.
    pub forgotten: usize,
}

impl Engine {
    // -- Proposing (roster.md, 3.15.7, "Proposing")

    /// Proposes a checkpoint of the space now: the record of the past of the
    /// events this device would cite next, sealed as its object, the
    /// skeleton cut that names it, and the checkpoint itself.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device administers the space and
    /// holds an enrolled pseudonym in its slot, while a checkpoint waits for
    /// votes, or while the record of the past is not known (a key or another
    /// log it reads is missing); [`Error::SyncBeforeWriting`]; the store's.
    pub async fn propose_checkpoint(&self, space: EventId) -> Result<EventId> {
        // A device granted `administer` signs the cut in its own slot, so
        // it enrols first if it has not yet (peers.md, "Enrolment").
        let _ = self.enrol(&space).await;
        let mut state = self.lock().await;
        self.propose_locked(&mut state, space).await
    }

    async fn propose_locked(&self, state: &mut State, space: EventId) -> Result<EventId> {
        Self::check_may_sign(state, &space)?;
        let me = self.device_id();
        {
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            if replica.level_of(&me) != Some(Level::Administer) {
                return Err(Error::NotAllowed("a checkpoint needs administer"));
            }
            if !replica.checkpoint_facts().pending.is_empty() {
                return Err(Error::NotAllowed("a checkpoint waits for votes"));
            }
        }
        let (seq, prev) = Self::next(state, &space, &me);
        let parents = state
            .replicas
            .get(&space)
            .ok_or(Error::UnknownSpace)?
            .parents(prev);
        // The next judgement derives the record of the parents' past.
        state
            .replicas
            .get_mut(&space)
            .ok_or(Error::UnknownSpace)?
            .checkpoints
            .propose = Some(parents);
        let reading = self.read_timeline(state).await;
        let settled = match reading {
            Ok(reading) => self.settle(state, space, Vec::new(), reading).await,
            Err(error) => Err(error),
        };
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        replica.checkpoints.propose = None;
        let proposal = replica.checkpoints.facts.proposal.take();
        settled?;
        let proposal = proposal.ok_or(Error::NotAllowed(
            "the record of the checkpoint's past is not known yet",
        ))?;
        let parents = proposal.parents;
        let record = proposal.record;
        let standing = proposal.standing;
        let plaintext = record.encode();
        #[cfg(test)]
        let plaintext = later_key(&me, plaintext);
        let fresh = writer::Fresh::draw(self.platform())?;
        // The record object, sealed under the checkpoint's own content key
        // and named by its self reference (roster.md, "The record object").
        let sealed = frasil_units::record::seal_record(
            &space,
            &fresh.content,
            SelfRef::new(me, seq),
            &plaintext,
        )
        .map_err(Error::class)?;
        let locator = sealed.binding.locator;
        let stored = crate::objects::parts_of(&locator, &sealed.object.bytes)?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let log = replica.log().ok_or(Error::UnknownSpace)?;
        let mut past = BTreeSet::new();
        for parent in &parents {
            past.extend(log.past(*parent));
            past.insert(*parent);
        }
        let cuts = replica.cuts_for(&parents)?;
        let grantless = !Self::draws_grant(replica);
        // keys.md's checks take a checkpoint as a genesis: it rotates, as a
        // grant rotation where its author propagates and the space is not
        // restricted, and is no break.
        let grant_rotation = replica.propagates(&me) && !grantless;
        // Space wraps go to the principals the record keeps alone
        // (keys.md, 3.17; `checkpoint_delivery`).
        let kept_principals = frasil_space::keygraph::record_principals(&record);
        let principals: Vec<SpacePrincipal> = replica
            .principals()
            .iter()
            .filter(|(granted, rotation, _, _)| {
                kept_principals.contains(&frasil_space::keygraph::Principal {
                    space: *granted,
                    rotation: *rotation,
                })
            })
            .map(|(granted, rotation, public, level)| SpacePrincipal {
                space: *granted,
                rotation: *rotation,
                public: public.clone(),
                writes: *level >= Level::Write,
            })
            .collect();
        let sealing = Sealing::Rotate {
            fresh,
            is_break: false,
            grant_rotation,
            recipients: self.recipients_after(replica, &[], &state.lists, &state.replicas),
            removed: Vec::new(),
            previous: Self::held_state(replica).ok(),
            previous_grant: Self::held_grant(replica),
        };
        let mut plan = SpaceEventPlan {
            space,
            seq,
            prev,
            parents: parents.clone(),
            cuts,
            changes: None,
            checkpoint: Some(CheckpointPart {
                epoch: record.epoch,
                digest: sealed.binding.digest,
                size: sealed.binding.size,
                locator,
            }),
            sealing,
            refs: Vec::new(),
            twin: None,
            notices: Vec::new(),
            principals,
            grantless,
        };
        // The skeleton cut first, with the record object's parts, so that
        // the object reaches each peer before the cut that names it.
        let twin = self
            .sign_cut(state, &space, &plan, locator, &past, standing, stored)
            .await?;
        plan.twin = Some(twin);
        let mut cited = parents;
        cited.push(twin);
        plan.cuts = state
            .replicas
            .get(&space)
            .ok_or(Error::UnknownSpace)?
            .cuts_for(&cited)?;
        let signed = writer::space_event(self.platform(), self.signer(), plan)?;
        let rotation = signed.fresh.as_ref().map(|fresh| RotationSecrets {
            content: Some(fresh.content.clone()),
            upload: Some(fresh.upload.clone()),
            grant: signed.grant_rotation.then(|| fresh.grant.clone()),
        });
        self.commit_own_with(
            state,
            space,
            &signed.signed,
            rotation,
            Vec::new(),
            Vec::new(),
        )
        .await
    }

    /// Signs and commits a checkpoint's skeleton cut (peers.md, "Skeleton
    /// cuts"; roster.md, 3.15.8): by this device's enrolled pseudonym, with
    /// the slots of the merged skeleton of its past, the standing entries its
    /// record gives and the record object's locator, citing the skeleton's heads and the checkpoints the
    /// checkpoint follows, and declaring its cuts. The record object's parts
    /// are kept in the same commit.
    #[allow(clippy::too_many_arguments)]
    async fn sign_cut(
        &self,
        state: &mut State,
        space: &EventId,
        plan: &SpaceEventPlan,
        record: frasil_adapter::Locator,
        past: &BTreeSet<EventId>,
        standing: Vec<frasil_peers::body::StandingEntry>,
        stored: Vec<crate::snapshots::ObjectPart>,
    ) -> Result<EventId> {
        let me = self.device_id();
        let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
        let slot = replica
            .slot_of(&me)
            .map(|info| info.slot)
            .ok_or(Error::NotAllowed("this device holds no administrator slot"))?;
        let log = replica.log().ok_or(Error::UnknownSpace)?;
        if Self::pseudonym_late(state, space) {
            return Err(Error::NotAllowed(
                "this pseudonym cannot sign a cut in the current skeleton",
            ));
        }
        if replica.skeleton_differs() {
            return Err(Error::NotAllowed(
                "the skeleton and the roster differ: repair them before a checkpoint",
            ));
        }
        let author_prev = state
            .pseudonym(space, &slot)
            .map(|p| Self::next(state, space, p.device_id()).1)
            .unwrap_or_default();
        let heads = replica.skeleton_heads_after(author_prev);
        let mut cut_past = past.clone();
        for head in &heads {
            cut_past.extend(log.past(*head));
            cut_past.insert(*head);
        }
        let (epoch, slots) = frasil_peers::cut::PeerCuts::new(log, None).slots_for(&cut_past);
        // The cut counts its epoch from the last cut in effect in its past:
        // one whose checkpoint's predecessor's cut is not in effect there
        // yet would be `CutPending`, and the checkpoint `BadTwin`
        // (roster.md, 3.15.7, "Proposing").
        if plan
            .checkpoint
            .as_ref()
            .is_some_and(|part| part.epoch != epoch)
        {
            return Err(Error::NotAllowed(
                "the last checkpoint's cut is not in effect yet: an administrator's pseudonym has not voted for it",
            ));
        }
        let salt = *self.platform().draw::<32>()?;
        let twin = twin_commitment(&me, plan.seq, &twin_secret(&plan.body_key(&me)), &salt);
        // A cut cites every parent of its checkpoint beside the skeleton's
        // heads, so that the checkpoint's past is the cut's past and the
        // cut (peers.md, "Skeleton cuts", Parents).
        let mut parents = heads;
        parents.extend(plan.parents.iter().copied());
        parents.extend(plan.cuts.iter().copied());
        parents.sort_unstable();
        parents.dedup();
        let pseudonym = state.pseudonym(space, &slot).ok_or(Error::NotAllowed(
            "this device has not enrolled in its slot",
        ))?;
        let author = *pseudonym.device_id();
        let (seq, prev) = Self::next(state, space, &author);
        let signed = writer::storage_event(
            pseudonym,
            *space,
            seq,
            prev,
            parents,
            plan.cuts.clone(),
            &StorageBody::Cut(Cut {
                twin,
                salt,
                record,
                epoch,
                standing,
                slots,
            }),
        );
        self.commit_own_with(state, *space, &signed, None, Vec::new(), stored)
            .await
    }

    /// Whether this device proposes a checkpoint of the space by itself
    /// now: it administers it, no checkpoint waits for votes, the history
    /// since the last one in effect calls for one, and its rank delay among
    /// the administrators, with the next epoch as trigger, has passed
    /// (roster.md, 3.15.7, "Proposing"; keys.md, "The rank and the delay").
    async fn proposes_now(&self, state: &mut State, space: &EventId) -> Result<bool> {
        let me = self.device_id();
        let now = self.read_timeline(state).await?;
        let Some(replica) = state.replicas.get(space) else {
            return Ok(false);
        };
        if replica.level_of(&me) != Some(Level::Administer) {
            return Ok(false);
        }
        let facts = replica.checkpoint_facts();
        if !facts.pending.is_empty()
            || !facts.growth.calls_for_checkpoint(&self.checkpoint_policy())
        {
            return Ok(false);
        }
        let epoch = facts
            .last()
            .and_then(|last| replica.checkpoints.records.get(&last))
            .map_or(1, |record| record.epoch + 1);
        let trigger = epoch.to_be_bytes();
        let administrators: Vec<[u8; 32]> = replica
            .devices()
            .into_iter()
            .filter(|(_, level)| *level == Level::Administer)
            .map(|(device, _)| device.0)
            .collect();
        let Some(position) = rank::position(&space.0, &trigger, &administrators, &me.0) else {
            return Ok(false);
        };
        let key = (*space, [b"checkpoint".as_slice(), &trigger].concat());
        let first = *state.heal_sights.entry(key).or_insert(now);
        Ok(rank::due(
            &first,
            &now,
            position,
            crate::maintenance::rotation_step(),
        ))
    }

    // -- Voting (roster.md, 3.15.7, "Voting")

    /// Votes for the checkpoint this device follows while it waits for this
    /// device: an anchor after it, which changes nothing else. `None` when
    /// no checkpoint waits for this device. Its pseudonym votes for the
    /// checkpoint's skeleton cut besides, by an acknowledgement after the
    /// checkpoint, once it owes that vote (peers.md, "Skeleton cuts", "In
    /// effect"): whether or not the space has a peer, so that the cut takes
    /// effect from the votes replicas hold, and the next checkpoint's cut
    /// counts its epoch from it. Members carry the acknowledgement to each
    /// other; an administration connection, to a peer.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn acknowledge_checkpoint(&self, space: EventId) -> Result<Option<EventId>> {
        let mut state = self.lock().await;
        self.acknowledge_locked(&mut state, space).await
    }

    async fn acknowledge_locked(
        &self,
        state: &mut State,
        space: EventId,
    ) -> Result<Option<EventId>> {
        if Self::check_may_sign(state, &space).is_err() {
            return Ok(None);
        }
        let me = self.device_id();
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.level_of(&me) != Some(Level::Administer) {
            return Ok(None);
        }
        let facts = replica.checkpoint_facts();
        let waits = facts.following.is_some_and(|following| {
            facts.pending.iter().any(|pending| {
                pending.checkpoint == following && pending.waiting.iter().any(|w| w.device == me)
            })
        });
        let device_vote = if waits {
            let (seq, prev) = Self::next(state, &space, &me);
            let parents = replica.parents(prev);
            let cuts = replica.cuts_for(&parents)?;
            let signed = Envelope {
                kind: kind::ANCHOR,
                log: Some(space),
                ed: *self.signer().identity_key(),
                kc: *self.signer().kc(),
                seq,
                prev,
                parents,
                cuts,
                body: Vec::new(),
                scheme: Scheme::Hybrid,
            }
            .sign(self.signer());
            Some(self.commit_own(state, space, &signed, None).await?)
        } else {
            None
        };
        // The pseudonym votes too, once the device does (peers.md, "The
        // administrator's duties"): a late one by enrolling the slot again
        // after the checkpoint, which is the slot's vote; another by an
        // acknowledgement after it.
        let _ = self.enrol_locked(state, &space).await;
        if let Some(c) = Self::cut_vote_owed_for(state, &space) {
            self.acknowledge_awaited_locked(state, space, &[c]).await?;
        }
        Ok(device_vote)
    }

    // -- Late work (roster.md, 3.15.7, "Work concurrent with a checkpoint")

    /// Re-submits this device's units the checkpoint in effect made late:
    /// each as a new unit after the checkpoint, in canonical order, with the
    /// same type, content, stream opening and refs, `resubmits` naming the
    /// late unit, sealed under the current state of the checkpoint's world
    /// (units.md, 3.11, "Re-submission"). Returns the new units.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] while the device holds no current state; the
    /// store's.
    pub async fn resubmit_late_units(&self, space: EventId) -> Result<Vec<EventId>> {
        self.resubmit(space, false).await
    }

    /// Re-submits this device's units refused by a removal or after a
    /// response (`RefusedByRemoval`, `RefusedAfterResponse`) once it writes
    /// in the space again, as after a re-grant: each as a new unit with the
    /// same content, whose `resubmits` names it, in canonical order
    /// (roster.md, 3.14, "Re-submission"; units.md, 3.11). A unit
    /// re-submitted already is left out. Returns the new units.
    ///
    /// # Errors
    ///
    /// As [`Engine::resubmit_late_units`].
    pub async fn resubmit_refused_units(&self, space: EventId) -> Result<Vec<EventId>> {
        self.resubmit(space, true).await
    }

    async fn resubmit(&self, space: EventId, refused: bool) -> Result<Vec<EventId>> {
        let mut state = self.lock().await;
        if Self::check_may_sign(&state, &space).is_err() {
            return Ok(Vec::new());
        }
        let me = self.device_id();
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.level_of(&me) < Some(Level::Write) {
            return Ok(Vec::new());
        }
        #[cfg_attr(not(feature = "adapter-loro"), allow(unused_mut))]
        let mut again = if refused {
            replica.refused_units_to_resubmit(&me)
        } else {
            replica.late_units_to_resubmit(&me)
        };
        // A lent document's holder writes its lost operations again under a
        // fresh incarnation, whenever it takes the rebuild: the units of the
        // incarnation lent now, and of those it renewed away from, are not
        // re-submitted as well.
        #[cfg(feature = "adapter-loro")]
        again.retain(|late| {
            !crate::documents::expressed_again(&state, space, late.stream, &late.inner)
        });
        let mut out = Vec::new();
        for late in again {
            let (key_reference, key) = self.sealing(&state, &space)?;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let (seq, prev) = Self::next(&state, &space, &me);
            let parents = replica.parents(prev);
            let cuts = replica.cuts_for(&parents)?;
            let mut objects = late.objects.clone();
            objects.sort_unstable();
            objects.dedup();
            let draft = Draft {
                log: space,
                seq,
                prev,
                parents,
                scheme: Scheme::Ed25519,
                stream: late.stream,
                key_reference,
                stream_prev: replica.last_unit_in(&late.stream, &me),
                objects,
                compacts: None,
                supersedes: Vec::new(),
            };
            let signed = draft
                .write_with_cuts(
                    self.signer(),
                    &key,
                    &late.inner.encode(),
                    &self.platform().nonce::<24>()?,
                    &cuts,
                )
                .signed;
            out.push(self.commit_own(&mut state, space, &signed, None).await?);
        }
        Ok(out)
    }

    /// Signs again, after the checkpoint in effect, each of this device's
    /// erasures, releases and restores of a stream that it made late, and
    /// not signed again yet: the late one counts for nothing, or at a peer
    /// waits while the checkpoint's cut can still take effect (peers.md,
    /// "The administrator's duties", "Erasure", "Release and restore").
    /// The application is told ([`Event::RequestSignedAgain`](super::Event::RequestSignedAgain)).
    /// A release or restore is signed again only while the stream is not as
    /// it asked. Returns the late requests signed again.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn resign_late_requests(&self, space: EventId) -> Result<Vec<EventId>> {
        let todo = {
            let state = self.lock().await;
            // A residue's welcome and checkpoint must be judged before
            // re-entry signs anything. settle_refetched owns that request.
            if state.erasing.contains_key(&space) {
                return Ok(Vec::new());
            }
            if Self::check_may_sign(&state, &space).is_err() {
                return Ok(Vec::new());
            }
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let mut mine: BTreeSet<DeviceId> = BTreeSet::from([self.device_id()]);
            mine.extend(state.pseudonym_ids(&space));
            late_requests(replica, &mine)
        };
        let mut out = Vec::new();
        for (late, body, again) in todo {
            if again {
                continue;
            }
            let signed = match body {
                StorageBody::Erase => self
                    .sign_skeleton(space, &StorageBody::Erase)
                    .await
                    .map(drop),
                StorageBody::Release { stream } => self.release_stream(space, stream).await,
                StorageBody::Restore(frasil_peers::body::Restored::Stream(stream)) => {
                    self.restore_stream(space, stream).await
                }
                _ => continue,
            };
            match signed {
                Ok(()) => out.push(late),
                // A late pseudonym signs again once it enrolled again.
                Err(Error::NotAllowed(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(out)
    }

    /// Re-signs, after the checkpoint in effect, each removal and demotion
    /// among this device's late roster events that the roster still needs,
    /// one roster event each. Returns the new roster events.
    ///
    /// # Errors
    ///
    /// As [`Engine::sign_roster`].
    pub async fn resign_late_removals(&self, space: EventId) -> Result<Vec<EventId>> {
        let changes = {
            let state = self.lock().await;
            if Self::check_may_sign(&state, &space).is_err() {
                return Ok(Vec::new());
            }
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            late_resigns(replica, &self.device_id())
        };
        let mut out = Vec::new();
        for change in changes {
            out.push(self.sign_roster(space, vec![change]).await?);
        }
        Ok(out)
    }

    // -- Forgetting (roster.md, 3.15.6)

    /// Forgets what came before the checkpoint in effect, once this device
    /// judged it on its whole past: in memory, and at rest, where the
    /// records of the events it dropped are deleted (with the store's
    /// secure deletion where it has one) and the log's `state` names the
    /// kept checkpoint (key 7) beside the stubs of the dropped events its
    /// kept events cite. This device's own events not yet durable are never
    /// forgotten. Returns how many events it dropped.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn forget_before_checkpoint(&self, space: EventId) -> Result<usize> {
        let mut state = self.lock().await;
        let keep: BTreeSet<EventId> = state
            .outboxes
            .get(&space)
            .map(|outbox| outbox.pending().map(|(_, id)| *id).collect())
            .unwrap_or_default();
        // The judgement first freezes each unit of the past it forgets, in
        // the view that judged it.
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        if replica.request_freeze() {
            let reading = self.read_timeline(&mut state).await?;
            self.settle(&mut state, space, Vec::new(), reading).await?;
        }
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        let Some(forgotten) = replica.forget_past(&keep) else {
            return Ok(0);
        };
        let checkpoints = replica.checkpoint_state();
        let rotation_keys = replica.drop_rotation_keys(&forgotten.dropped);
        if !state.vault.is_memory_only(&space.0) {
            let mut batch = Batch::default();
            for id in &forgotten.dropped {
                state
                    .vault
                    .delete(&mut batch, &space.0, Table::Event, &id.0);
            }
            // The secrets of a dropped rotation whose states seal nothing
            // kept go; every other rotation's stay, so that what is sealed
            // under them opens after a restart.
            for rotation in &rotation_keys {
                let mut item = vec![frasil_store::tables::KeyKind::Rotation.code()];
                item.extend_from_slice(rotation);
                state.vault.delete(&mut batch, &space.0, Table::Key, &item);
            }
            // One commit: key 7, the deletions, the `dropped` records and
            // the events kept alone (at-rest.md, "Forgetting before a
            // checkpoint").
            let deleted = forgotten.dropped.iter().map(|id| id.0).collect();
            crate::device::put_checkpoint_records(
                &state.vault,
                &mut batch,
                &space.0,
                &checkpoints,
                &deleted,
            )
            .await?;
            // Each kept unit's record with what was frozen of it, in the
            // same commit (at-rest.md, keys 6 to 8).
            if let Some(replica) = state.replicas.get(&space) {
                for (id, _) in &forgotten.frozen {
                    if let Some(event) = replica.event(*id) {
                        state.vault.put(
                            &mut batch,
                            &space.0,
                            Table::Event,
                            &id.0,
                            &TableValue::Event(crate::device::event_record(replica, event, *id)),
                        )?;
                    }
                }
            }
            // The stubs of dropped events are their `dropped` records, never
            // `state` keys 1 and 2, which hold a stream's base of units.
            let kept = crate::device::log_state(&state.vault, &space.0).await?;
            state.vault.put(
                &mut batch,
                &space.0,
                Table::State,
                &[],
                &TableValue::State(LogState {
                    kept_checkpoint: Some(forgotten.checkpoint.0),
                    ..kept
                }),
            )?;
            state.vault.commit(batch).await?;
        }
        let reading = self.read_timeline(&mut state).await?;
        self.settle(&mut state, space, Vec::new(), reading).await?;
        Ok(forgotten.dropped.len())
    }

    /// Writes what the space's log keeps of its checkpoints beside key 7
    /// (`frasil_store::checkpoint_state`): a `key` record of kind 5 per
    /// record key a snapshot handed over, a `dropped` record per event the
    /// replica dropped, and an `event` record in state 6 per kept
    /// checkpoint envelope, so that the device reopens the log as it left
    /// it. Nothing for a memory-only log.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn keep_checkpoint_state(
        &self,
        state: &mut State,
        space: EventId,
    ) -> Result<()> {
        if state.vault.is_memory_only(&space.0) || !state.vault.has_log(&space.0) {
            return Ok(());
        }
        let Some(checkpoints) = state
            .replicas
            .get(&space)
            .map(crate::replica::Replica::checkpoint_state)
        else {
            return Ok(());
        };
        let mut batch = Batch::default();
        if !crate::device::put_checkpoint_records(
            &state.vault,
            &mut batch,
            &space.0,
            &checkpoints,
            &BTreeSet::new(),
        )
        .await?
        {
            return Ok(());
        }
        state.vault.commit(batch).await
    }

    // -- The upkeep

    /// Runs the device's checkpoint policy in one space: votes for the
    /// checkpoint it follows when it waits for this device, re-submits late
    /// units and re-signs late removals, proposes a checkpoint when due, and
    /// forgets what came before the checkpoint in effect.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn maintain_checkpoints(&self, space: EventId) -> Result<CheckpointWork> {
        let policy: CheckpointPolicy = self.checkpoint_policy();
        // A device whose enrolment turned late enrols its slot again first,
        // so that what follows can sign twins (peers.md, "Skeleton cuts",
        // "A late enrolment").
        let _ = self.enrol(&space).await;
        let mut work = CheckpointWork {
            acknowledged: self.acknowledge_checkpoint(space).await?,
            ..CheckpointWork::default()
        };
        work.resubmitted = match self.resubmit_late_units(space).await {
            Ok(units) => units,
            Err(Error::NotAllowed(_) | Error::Class(_)) => Vec::new(),
            Err(error) => return Err(error),
        };
        // Units refused by a removal, sent again once the device writes
        // again (roster.md, 3.14, "Re-submission").
        match self.resubmit_refused_units(space).await {
            Ok(units) => work.resubmitted.extend(units),
            Err(Error::NotAllowed(_) | Error::Class(_)) => {}
            Err(error) => return Err(error),
        }
        // Erasures, releases and restores of this device's made late, signed
        // again after the checkpoint.
        match self.resign_late_requests(space).await {
            Ok(_) | Err(Error::NotAllowed(_) | Error::Class(_)) => {}
            Err(error) => return Err(error),
        }
        work.resigned = match self.resign_late_removals(space).await {
            Ok(events) => events,
            Err(Error::NotAllowed(_) | Error::Invalid(_) | Error::Class(_)) => Vec::new(),
            Err(error) => return Err(error),
        };
        if policy.propose {
            let due = {
                let mut state = self.lock().await;
                self.proposes_now(&mut state, &space).await?
            };
            if due {
                work.proposed = match self.propose_checkpoint(space).await {
                    Ok(id) => Some(id),
                    Err(Error::NotAllowed(_) | Error::Class(_) | Error::SyncBeforeWriting) => None,
                    Err(error) => return Err(error),
                };
            }
        }
        if policy.forget {
            work.forgotten = self.forget_before_checkpoint(space).await?;
        }
        Ok(work)
    }
}

/// The removals and demotions among `me`'s late roster events that the
/// roster of the view still needs (roster.md, 3.15.7): a removal of a
/// member still in, a demotion of a member still above the level it set.
/// The requests of `mine` (the device and its pseudonyms) that the
/// checkpoint in effect made late: erasures, releases and restores of a
/// stream, each with its body and whether one of `mine` signed the same
/// again after the checkpoint (peers.md, "The administrator's duties";
/// roster.md, 3.15.7, "Work concurrent with a checkpoint").
pub(crate) fn late_requests(
    replica: &crate::replica::Replica,
    mine: &BTreeSet<DeviceId>,
) -> Vec<(EventId, StorageBody, bool)> {
    let Some(log) = replica.log() else {
        return Vec::new();
    };
    let facts = replica.checkpoint_facts();
    let Some(c) = facts.last() else {
        return Vec::new();
    };
    let request = |event: &frasil_events::Event| -> Option<StorageBody> {
        if event.kind() != kind::STORAGE || !mine.contains(event.author()) {
            return None;
        }
        match StorageBody::read(event.unverified_body()).ok()? {
            body @ (StorageBody::Erase
            | StorageBody::Release { .. }
            | StorageBody::Restore(frasil_peers::body::Restored::Stream(_))) => Some(body),
            _ => None,
        }
    };
    facts
        .late
        .iter()
        .filter_map(|&id| {
            let body = request(log.event(id)?)?;
            let again = log.events().any(|event| {
                request(event).as_ref() == Some(&body) && log.follows(event.id(), c) == Ok(true)
            });
            Some((id, body, again))
        })
        .collect()
}

pub(crate) fn late_resigns(replica: &crate::replica::Replica, me: &DeviceId) -> Vec<Change> {
    if replica.level_of(me) != Some(Level::Administer) {
        return Vec::new();
    }
    let mut out: Vec<Change> = Vec::new();
    for late in &replica.checkpoint_facts().late_roster {
        if late.author != *me {
            continue;
        }
        for change in &late.changes {
            let Some(member) = change.member else {
                continue;
            };
            if out.iter().any(|done| done.member == Some(member)) {
                continue;
            }
            let needed = match change.op {
                Op::Remove => replica.roster().is_in(&member),
                Op::Change => change.level.is_some_and(|level| {
                    replica
                        .roster()
                        .state(&member)
                        .is_some_and(|state| state.level > level)
                }),
                _ => false,
            };
            if needed {
                out.push(change.clone());
            }
        }
    }
    out
}

/// This device's late roster changes that it does not re-sign, for the
/// administrator to make again (roster.md, 3.15.7): grants, raised levels
/// and every change a re-signed removal or demotion does not cover.
pub(crate) fn late_listed(
    replica: &crate::replica::Replica,
    me: &DeviceId,
) -> Vec<(EventId, Change)> {
    let resigned = late_resigns(replica, me);
    let mut out = Vec::new();
    for late in &replica.checkpoint_facts().late_roster {
        if late.author != *me {
            continue;
        }
        for change in &late.changes {
            let covered = matches!(change.op, Op::Remove | Op::Change)
                && resigned.iter().any(|r| r.member == change.member);
            let done = match (change.op, change.member) {
                (Op::Remove, Some(member)) => !replica.roster().is_in(&member),
                _ => false,
            };
            if !covered && !done {
                out.push((late.event, change.clone()));
            }
        }
    }
    out
}

/// What [`Engine::maintain_list_checkpoint`] signed in the person's device
/// list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListCheckpointWork {
    /// The revocations re-signed after the list checkpoint in effect.
    pub resigned: Vec<EventId>,
    /// The `ack` by which this device voted.
    pub acknowledged: Option<EventId>,
    /// The list checkpoint this device proposed.
    pub proposed: Option<EventId>,
}

impl Engine {
    /// Proposes a checkpoint of this device's person's device list now
    /// (identity.md, 3.16 List checkpoints, action 3): its record is that
    /// of the past of the events this device cites next. The list event
    /// reaches every space that grants the person.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person; `CheckpointPending`
    /// while a list checkpoint waits for votes; `UntrustedSigner` for a
    /// device that may not sign one; `TooLarge` when the record does not
    /// fit a list event; the store's.
    pub async fn propose_list_checkpoint(&self) -> Result<EventId> {
        let person = self
            .person()
            .await
            .ok_or(Error::NotAllowed("the device is no person's"))?;
        let signed = {
            let state = self.lock().await;
            let list = state
                .lists
                .get(&person)
                .ok_or(Error::NotAllowed("the device holds no list of its person"))?;
            list.propose_checkpoint(self.signer())
                .map_err(|class| Error::Class(frasil_base::errors::Class::name(class)))?
        };
        let id = frasil_events::decode(&signed).map_err(Error::class)?.id();
        self.sign_list_events(&person, vec![signed]).await?;
        Ok(id)
    }

    /// Whom the person's pending list checkpoints wait for (identity.md,
    /// 3.16, "Effect"): each valid list checkpoint not in effect, with the
    /// devices of its electorate that have not voted.
    pub async fn list_waiting_for(&self) -> Vec<(EventId, Vec<DeviceId>)> {
        let Some(person) = self.person().await else {
            return Vec::new();
        };
        let state = self.lock().await;
        let Some(list) = state.lists.get(&person) else {
            return Vec::new();
        };
        list.merge()
            .pending_checkpoints()
            .map(|(id, waiting)| (id, waiting.iter().map(|(device, _)| *device).collect()))
            .collect()
    }

    /// The checkpoints of this device's person's device list
    /// ([`Device::list_checkpoints`]).
    pub async fn list_checkpoint_status(&self) -> ListCheckpointStatus {
        let Some(person) = self.person().await else {
            return ListCheckpointStatus::default();
        };
        let state = self.lock().await;
        let Some(list) = state.lists.get(&person) else {
            return ListCheckpointStatus::default();
        };
        let merged = list.merge();
        let id = |event: EventId| CheckpointId::from_bytes(event.0);
        ListCheckpointStatus {
            in_effect: merged.in_effect().map(id),
            pending: merged
                .pending_checkpoints()
                .map(|(checkpoint, waiting)| PendingListCheckpoint {
                    id: id(checkpoint),
                    waiting_for: waiting
                        .iter()
                        .map(|(device, _)| MemberId::device(*device))
                        .collect(),
                })
                .collect(),
            forgot: crate::lists::is_kept(list),
            rivals: crate::lists::rivals(list, &merged)
                .into_iter()
                .map(id)
                .collect(),
        }
    }

    /// Runs the device's checkpoint policy on its person's device list:
    /// re-signs its late revocations, votes by an `ack` for a pending list
    /// checkpoint that waits for this device when it signed nothing else,
    /// and proposes one when no list checkpoint waits, the list holds
    /// [`PROPOSE_AT_ROSTER_EVENTS`](crate::PROPOSE_AT_ROSTER_EVENTS) events
    /// since the one in effect, and the policy proposes.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn maintain_list_checkpoint(&self) -> Result<ListCheckpointWork> {
        let mut work = ListCheckpointWork::default();
        let Some(person) = self.person().await else {
            return Ok(work);
        };
        let me = self.device_id();
        let policy = self.checkpoint_policy();
        let signed = {
            let state = self.lock().await;
            let Some(list) = state.lists.get(&person) else {
                return Ok(work);
            };
            let merged = list.merge();
            let mut working = list.clone();
            let mut signed = Vec::new();
            // Late revocations, re-signed one after another on this
            // device's chain (identity.md, 3.16, "Late and mixed").
            for body in list.late_work(&merged, &me).resign {
                let event = working.sign(&body, self.signer());
                if working.insert(&event).is_err() {
                    break;
                }
                signed.push(event);
            }
            // A list checkpoint this device contests is one it never votes
            // for (identity.md, "List checkpoints", "Clients"): it signs no
            // ack for it.
            let waits = merged.pending_checkpoints().any(|(c, waiting)| {
                waiting.iter().any(|(device, _)| *device == me) && list.contest(&me, c).is_none()
            });
            if waits && signed.is_empty() {
                let event = working.ack(self.signer());
                if working.insert(&event).is_ok() {
                    signed.push(event);
                }
            } else if !waits && policy.propose && merged.pending_checkpoints().next().is_none() {
                let since = match merged.in_effect() {
                    Some(c) => list
                        .canonical()
                        .into_iter()
                        .filter(|&id| id != c && !list.precedes(id, c))
                        .count(),
                    None => list.len(),
                };
                if since as u64 >= policy.roster_events
                    && let Ok(event) = working.propose_checkpoint(self.signer())
                {
                    signed.push(event);
                }
            }
            signed
        };
        if signed.is_empty() {
            return Ok(work);
        }
        let ids: Vec<EventId> = signed
            .iter()
            .filter_map(|event| frasil_events::decode(event).ok())
            .map(|event| event.id())
            .collect();
        self.sign_list_events(&person, signed).await?;
        let state = self.lock().await;
        for id in ids {
            let action = state
                .lists
                .get(&person)
                .and_then(|list| list.body(id))
                .map(|body| body.action);
            match action {
                Some(frasil_identity::body::Action::Revoke) => work.resigned.push(id),
                Some(frasil_identity::body::Action::Ack) => work.acknowledged = Some(id),
                Some(frasil_identity::body::Action::Checkpoint) => work.proposed = Some(id),
                _ => {}
            }
        }
        Ok(work)
    }

    /// Forgets, in every person's device list this device holds, the list
    /// events before the list checkpoint in effect (identity.md, "List
    /// checkpoints", "Forgetting"): the device keeps the list's first
    /// event, the checkpoint, the adds and rooting adds its record names,
    /// the checkpoints its `follows` reach, the late events and what
    /// follows, and at rest deletes the rest, keeping their IDs in the list
    /// log's `state` record. Never while a rival list checkpoint is held,
    /// or a concurrent one with a smaller ID waits for votes. Every space
    /// is judged again, since spaces read the lists as held. Returns how
    /// many list events the device dropped.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn forget_lists_before_checkpoints(&self) -> Result<usize> {
        let mut state = self.lock().await;
        let persons: Vec<[u8; 32]> = state.lists.keys().copied().collect();
        let mut total = 0;
        let mut changed = false;
        let mut batch = Batch::default();
        for person in persons {
            let Some(list) = state.lists.get(&person) else {
                continue;
            };
            let merged = list.merge();
            let Some((kept, dropped)) = list.forget(&merged) else {
                continue;
            };
            let checkpoint = kept.checkpoint();
            let alone: Vec<(EventId, Vec<u8>)> = kept
                .alone()
                .iter()
                .map(|(id, event)| (*id, event.signed().to_vec()))
                .collect();
            state
                .lists
                .insert(person, crate::lists::PersonList::Kept(kept));
            total += dropped.len();
            changed = true;
            if !state.vault.has_log(&person) || state.vault.is_memory_only(&person) {
                continue;
            }
            for id in &dropped {
                state.vault.delete(&mut batch, &person, Table::Event, &id.0);
            }
            // A `dropped` record per list event forgotten, of the list's
            // kind (at-rest.md, "Lists after a list checkpoint").
            for id in &dropped {
                state.vault.put(
                    &mut batch,
                    &person,
                    Table::Dropped,
                    &id.0,
                    &TableValue::Dropped(frasil_store::tables::DroppedOrigin::Held {
                        kind: frasil_events::kind::DEVICE_LIST,
                        height: None,
                    }),
                )?;
            }
            // The events it keeps alone, never judged, in state 6.
            for (id, signed) in alone {
                state.vault.put(
                    &mut batch,
                    &person,
                    Table::Event,
                    &id.0,
                    &TableValue::Event(frasil_store::tables::EventRecord {
                        signed,
                        state: frasil_store::tables::EventState::KeptAlone,
                        flags: frasil_store::tables::FLAG_VERIFIED,
                        class: None,
                        first_sight: state.list_sights.get(&id).copied(),
                        frozen: None,
                    }),
                )?;
            }
            let held = crate::device::log_state(&state.vault, &person).await?;
            state.vault.put(
                &mut batch,
                &person,
                Table::State,
                &[],
                &TableValue::State(LogState {
                    kept_checkpoint: Some(checkpoint.0),
                    ..held
                }),
            )?;
        }
        if !changed {
            return Ok(0);
        }
        state.vault.commit(batch).await?;
        let reading = self.read_timeline(&mut state).await?;
        let spaces: Vec<EventId> = state.replicas.keys().copied().collect();
        for space in spaces {
            self.settle_one(&mut state, space, Vec::new(), reading)
                .await?;
        }
        Ok(total)
    }

    /// Keeps list events this device signed, and hands the person's list to
    /// every space that grants the person and that this device writes in
    /// (identity.md, "Other spaces").
    async fn sign_list_events(&self, person: &[u8; 32], signed: Vec<Vec<u8>>) -> Result<()> {
        {
            let mut state = self.lock().await;
            self.keep_lists(&mut state, signed).await?;
        }
        for space in self.spaces().await {
            let grants = self
                .read(&space, |replica| {
                    replica.roster().members_in().any(|(member, _)| {
                        member.kind == frasil_space::MemberType::Person && member.id == *person
                    }) && replica.level_of(&self.device_id()) >= Some(Level::Write)
                })
                .await
                .unwrap_or(false);
            if grants {
                let _ = self.publish_list(space, person).await;
            }
        }
        Ok(())
    }
}

// -- What an application sees

/// A valid checkpoint that waits for votes (roster.md, 3.15.4 Votes and
/// effect, "Waiting for").
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PendingCheckpoint {
    /// The checkpoint.
    pub id: CheckpointId,
    /// Its epoch: 1 for the space's first checkpoint.
    pub epoch: u64,
    /// The administrator that proposed it.
    pub proposed_by: MemberId,
    /// The administrators it waits for: each must write anything after it.
    /// One that will not return can be removed, or marked dormant, by
    /// another administrator; either excuses it.
    pub waiting_for: Vec<MemberId>,
}

/// A space's checkpoints, as this device holds them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckpointStatus {
    /// The last checkpoint in effect, if any.
    pub in_effect: Option<CheckpointId>,
    /// Its epoch; 0 with none.
    pub epoch: u64,
    /// The checkpoints waiting for votes.
    pub pending: Vec<PendingCheckpoint>,
    /// The checkpoint this device follows: the one in effect, or a pending
    /// one.
    pub following: Option<CheckpointId>,
    /// Checkpoints void as `BadCheckpoint`.
    pub bad: Vec<CheckpointId>,
    /// Events void as `Late`: made concurrently with the checkpoint in
    /// effect.
    pub late: Vec<ChangeId>,
    /// Events void as `MixedCut`.
    pub mixed: Vec<ChangeId>,
    /// Valid roster events since the last checkpoint in effect.
    pub roster_events_since: u64,
    /// Bytes of frame events since the last checkpoint in effect.
    pub frame_bytes_since: u64,
    /// Whether this device forgot what came before the checkpoint in
    /// effect.
    pub forgot: bool,
    /// Pending checkpoints whose record differs from the one this device
    /// derives from their past: it never votes for them, and reports each
    /// as [`Event::BadCheckpoint`](super::Event::BadCheckpoint).
    pub refused: Vec<CheckpointId>,
    /// Pending checkpoints whose record this device cannot check yet: it
    /// waits for the logs of other spaces or persons the record reads, and
    /// votes once it has checked it.
    pub checking: Vec<CheckpointId>,
    /// Contested checkpoints, which hear this device or whose author or
    /// kept administrator its view lowers by a concurrent event of a member
    /// that outranks them: it writes nothing that builds on them.
    pub withheld: Vec<CheckpointId>,
    /// Each contested checkpoint, with its author and the lowering events
    /// on both sides (roster.md, 3.15.7, "Contested checkpoints").
    pub contested: Vec<ContestedCheckpoint>,
    /// Checkpoints that rival the one this device kept when it forgot: until
    /// it has fetched their past, every change of the space waits.
    pub rivals: Vec<CheckpointId>,
    /// Checkpoints whose proposer a removal concurrent with them removes.
    pub backdated: Vec<BackdatedCheckpoint>,
}

/// A checkpoint this device contests, as a duel is listed (roster.md,
/// 3.15.7, "Contested checkpoints").
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContestedCheckpoint {
    /// The checkpoint.
    pub id: CheckpointId,
    /// Who proposed it.
    pub proposed_by: MemberId,
    /// The roster events of its past that lower administrators.
    pub theirs: Vec<ChangeId>,
    /// The roster events of this device's view, concurrent with it, that
    /// lower its author or an administrator its record keeps.
    pub ours: Vec<ChangeId>,
}

/// A checkpoint whose proposer was removed by a change concurrent with it
/// (roster.md, section 4, "A backdated checkpoint"): an administrator
/// should check that the checkpoint is not a removed device's attempt to
/// keep the space.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BackdatedCheckpoint {
    /// The checkpoint.
    pub checkpoint: CheckpointId,
    /// The administrator that proposed it.
    pub proposed_by: MemberId,
    /// The removal of that administrator concurrent with it.
    pub removal: ChangeId,
}

/// What a late membership change did (roster.md, 3.15.7, "Work concurrent
/// with a checkpoint").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LateChangeKind {
    /// It admitted a member.
    Grant,
    /// It changed a member's level or capabilities.
    Change,
    /// It removed a member.
    Remove,
    /// Another change.
    Other,
}

/// A membership change of this device that a checkpoint made late, and that
/// the device does not make again by itself: the administrator decides
/// whether to make it again.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LateChange {
    /// The late roster event.
    pub event: ChangeId,
    /// The member it named.
    pub member: Option<MemberId>,
    /// What it did.
    pub kind: LateChangeKind,
    /// The level it set, if any.
    pub level: Option<Level>,
}

impl LateChange {
    fn of(event: EventId, change: &Change) -> Self {
        Self {
            event: ChangeId::from_bytes(event.0),
            member: change.member.map(|member| MemberId::from_bytes(member.id)),
            kind: match change.op {
                Op::Grant => LateChangeKind::Grant,
                Op::Change => LateChangeKind::Change,
                Op::Remove => LateChangeKind::Remove,
                #[allow(unreachable_patterns)]
                _ => LateChangeKind::Other,
            },
            level: change.level,
        }
    }
}

/// A replica's checkpoints, as an application sees them.
pub(crate) fn status_of(replica: &crate::replica::Replica) -> CheckpointStatus {
    let facts = replica.checkpoint_facts();
    let id = |event: &EventId| CheckpointId::from_bytes(event.0);
    let last = facts.last();
    CheckpointStatus {
        in_effect: last.as_ref().map(id),
        epoch: last
            .and_then(|c| replica.checkpoints.records.get(&c))
            .map_or(0, |record| record.epoch),
        pending: facts
            .pending
            .iter()
            .map(|pending| PendingCheckpoint {
                id: id(&pending.checkpoint),
                epoch: pending.epoch,
                proposed_by: MemberId::device(pending.author),
                waiting_for: pending
                    .waiting
                    .iter()
                    .map(|waiting| MemberId::device(waiting.device))
                    .collect(),
            })
            .collect(),
        following: facts.following.as_ref().map(id),
        bad: facts.bad.iter().map(id).collect(),
        late: facts
            .late
            .iter()
            .map(|event| ChangeId::from_bytes(event.0))
            .collect(),
        mixed: facts
            .mixed
            .iter()
            .map(|event| ChangeId::from_bytes(event.0))
            .collect(),
        roster_events_since: facts.growth.roster_events,
        frame_bytes_since: facts.growth.frame_bytes,
        forgot: replica.kept_checkpoint().is_some(),
        refused: facts.refused().iter().map(id).collect(),
        checking: facts.unsure.iter().map(id).collect(),
        withheld: facts.withheld.iter().map(id).collect(),
        contested: facts
            .contests
            .iter()
            .filter_map(|(checkpoint, (theirs, ours))| {
                let author = *replica.log()?.event(*checkpoint)?.author();
                let change = |e: &EventId| ChangeId::from_bytes(e.0);
                Some(ContestedCheckpoint {
                    id: id(checkpoint),
                    proposed_by: MemberId::from_bytes(author.0),
                    theirs: theirs.iter().map(change).collect(),
                    ours: ours.iter().map(change).collect(),
                })
            })
            .collect(),
        rivals: facts.rivals.iter().map(id).collect(),
        backdated: facts
            .backdated
            .iter()
            .filter_map(|(checkpoint, removal)| {
                let author = *replica.log()?.event(*checkpoint)?.author();
                Some(BackdatedCheckpoint {
                    checkpoint: id(checkpoint),
                    proposed_by: MemberId::device(author),
                    removal: ChangeId::from_bytes(removal.0),
                })
            })
            .collect(),
    }
}

/// This device's late membership changes it does not make again by itself.
pub(crate) fn late_changes_of(replica: &crate::replica::Replica, me: &DeviceId) -> Vec<LateChange> {
    late_listed(replica, me)
        .iter()
        .map(|(event, change)| LateChange::of(*event, change))
        .collect()
}

impl Engine {
    /// A space's checkpoints as this device holds them
    /// ([`Space::checkpoints`]).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn checkpoint_status(&self, space: &EventId) -> Result<CheckpointStatus> {
        self.read(space, status_of).await
    }

    /// This device's late membership changes it does not make again by
    /// itself ([`Space::late_changes`]).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn late_changes(&self, space: &EventId) -> Result<Vec<LateChange>> {
        let me = self.device_id();
        self.read(space, |replica| late_changes_of(replica, &me))
            .await
    }

    /// Whether the space needs a later version of Frasil than this build
    /// ([`Space::needs_later_version`]).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn needs_later_version(&self, space: &EventId) -> Result<bool> {
        self.read(space, crate::replica::Replica::needs_later_version)
            .await
    }

    /// Takes a peer's `Missing` for events of a space this device starts
    /// from a checkpoint in: the peer truncated them, so each counts as a
    /// dropped parent (roster.md, 3.15.6, "Starting from a checkpoint").
    /// Returns the events that placed.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; the store's.
    pub async fn take_truncated(&self, space: EventId, ids: &[EventId]) -> Result<Vec<EventId>> {
        let mut state = self.lock().await;
        let placed = state
            .replicas
            .get_mut(&space)
            .ok_or(Error::UnknownSpace)?
            .drop_truncated(ids);
        self.keep_checkpoint_state(&mut state, space).await?;
        if !placed.is_empty() {
            let reading = self.read_timeline(&mut state).await?;
            self.settle(&mut state, space, placed.clone(), reading)
                .await?;
        }
        Ok(placed)
    }
}

impl Space {
    /// The space's checkpoints as this device holds them: the one in
    /// effect, those waiting for votes with whom each waits for, and the
    /// verdicts checkpoints gave (roster.md, 3.15 Checkpoints).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn checkpoints(&self) -> Result<CheckpointStatus> {
        self.read(status_of).await
    }

    /// Proposes a checkpoint of the space now, whatever the device's
    /// [`CheckpointPolicy`]: once every administrator has written anything
    /// after it, it takes effect and every member may forget what came
    /// before it.
    ///
    /// # Errors
    ///
    /// As [`Engine::propose_checkpoint`].
    pub async fn propose_checkpoint(&self) -> Result<CheckpointId> {
        let id = self
            .device
            .engine()
            .propose_checkpoint(self.id().event())
            .await?;
        Ok(CheckpointId::from_bytes(id.0))
    }

    /// This device's membership changes that a checkpoint made late and
    /// that it does not make again by itself: grants and raised levels,
    /// which the administrator decides whether to make again. Late removals
    /// and demotions the roster still needs are signed again by the
    /// device's upkeep, and late document edits re-sent.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn late_changes(&self) -> Result<Vec<LateChange>> {
        let me = self.device.engine().device_id();
        self.read(|replica| late_changes_of(replica, &me)).await
    }

    /// Whether the space needs a later version of Frasil than this build:
    /// it uses a hook a later document defines, which this build does not
    /// implement (roster.md, "The space descriptor", 2.8 The checkpoint
    /// record and 3.16). While it does, the device holds what uses it and
    /// everything after it, and signs nothing in the space: each write
    /// fails with [`Error::NeedsLaterVersion`].
    /// [`Event::NeedsLaterVersion`](crate::Event::NeedsLaterVersion) reports
    /// it as it happens.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn needs_later_version(&self) -> Result<bool> {
        self.read(crate::replica::Replica::needs_later_version)
            .await
    }
}

/// A checkpoint of this device's person's device list that waits for votes
/// (identity.md, 3.16 List checkpoints, "Effect").
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PendingListCheckpoint {
    /// The list checkpoint.
    pub id: CheckpointId,
    /// The person's devices it waits for: each must sign a list event after
    /// it. One that will not return can be removed from the list.
    pub waiting_for: Vec<MemberId>,
}

/// The checkpoints of this device's person's device list, as this device
/// holds them (identity.md, 3.16 List checkpoints).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListCheckpointStatus {
    /// The list checkpoint in effect, if any.
    pub in_effect: Option<CheckpointId>,
    /// The list checkpoints waiting for votes.
    pub pending: Vec<PendingListCheckpoint>,
    /// Whether this device forgot the list events before the checkpoint in
    /// effect.
    pub forgot: bool,
    /// List checkpoints that rival the one this device kept: until it holds
    /// their past, the list's changes wait.
    pub rivals: Vec<CheckpointId>,
}

impl Device {
    /// The checkpoints of this device's person's device list: the one in
    /// effect, those waiting for votes with whom each waits for, and
    /// whether the device forgot the list's earlier events. The default
    /// for a device of no person.
    pub async fn list_checkpoints(&self) -> ListCheckpointStatus {
        self.engine().list_checkpoint_status().await
    }

    /// Sets what the device does about checkpoints by itself: whether it
    /// proposes them when the space's history calls for one, and whether
    /// it forgets what came before one in effect.
    pub fn set_checkpoint_policy(&self, policy: CheckpointPolicy) {
        self.engine().set_checkpoint_policy(policy);
    }

    /// Proposes a checkpoint of this device's person's device list now
    /// (identity.md, 3.16 List checkpoints).
    ///
    /// # Errors
    ///
    /// As [`Engine::propose_list_checkpoint`].
    pub async fn propose_list_checkpoint(&self) -> Result<CheckpointId> {
        let id = self.engine().propose_list_checkpoint().await?;
        Ok(CheckpointId::from_bytes(id.0))
    }

    /// Whom each pending checkpoint of this device's person's device list
    /// waits for: each device of it that has not signed a list event after
    /// it. A device that will not return can be removed from the list.
    pub async fn list_checkpoints_waiting(&self) -> Vec<(CheckpointId, Vec<MemberId>)> {
        self.engine()
            .list_waiting_for()
            .await
            .into_iter()
            .map(|(id, devices)| {
                (
                    CheckpointId::from_bytes(id.0),
                    devices.into_iter().map(MemberId::device).collect(),
                )
            })
            .collect()
    }
}
