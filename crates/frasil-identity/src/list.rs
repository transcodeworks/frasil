//! A person's device list: its log of list events and the checks of each
//! event alone (identity.md, "The person ID and the personal space", "The
//! device-list event", "Checking a list event alone" and "Sealed list
//! copies").
//!
//! ```text
//! check_alone(event), in order:
//!   1. events.md, "Decoding an event" and "Placement and order".     else that class
//!   2. The body is a deterministic CBOR map; version 3; action 0 to 2;
//!      kind 0 to 3; keys as section 2.3 for the action and kind, each
//!      with its length.                                                else Malformed
//!   3. The list's first event is an add of a device whose device ID
//!      is its author.                                                  else BadGenesis
//!   4. An add: identity passes ed25519_valid and, for kinds 0 to 2,
//!      xwing passes xwing_valid.                                       else InvalidKey
//!   5. An add: identity, mldsa and xwing (empty for an agent) give
//!      device (crypto.md, "A device's keys").                          else NotCommitted
//!   6. An add: possession verifies, both halves, over section 2.5's
//!      statement with this list's person ID (32 zero bytes in the
//!      first event) and the event's author as adder, under identity
//!      and mldsa.                                                      else BadPossession
//!   7. The event's signature verifies (events.md, "The ML-DSA-65
//!      half"), under keys that hash to its kc, wherever the replica
//!      found them; the first event names its own.                      else NoHybridKey / BadSignature
//!   8. The author's fork point in the list is above seq, or the event
//!      revokes its own author.                                         else Forked
//! ```
//!
//! A [`DeviceList`] takes list events by any path and in any order, as
//! "Sealed list copies" asks of a replica: [`DeviceList::insert`] runs step
//! 1, holding an event whose parents have not arrived as pending, and steps
//! 2 to 7 on each event it places. Step 7 takes keys by their hash from the
//! list's own adds ([`DeviceList::keys`]) and from any other source the
//! caller gives ([`DeviceList::verify_with`]); an event whose author's keys
//! are not held stays `NoHybridKey` until they are. Step 8 and the checks at
//! each event's place belong to the merge ([`DeviceList::merge`]).

use crate::IdentityClass;
use crate::body::{ListBody, check_body};
use crate::checkpoint::{self, LateWork, Propose};
use crate::keys::{Kind, MemberKeys};
use crate::merge::MergedList;
use crate::possession::FIRST_EVENT_PERSON;
use frasil_base::ErrorClass;
use frasil_crypto::device::{DeviceId, KeyRing, KeySource};
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::kind::DEVICE_LIST;
use frasil_events::{
    Envelope, Event, EventClass, EventId, Evidence, ForkPoints, Log, Placement, SignatureState,
    decode,
};
use std::collections::BTreeMap;

/// Why a list refused an event before placing it: a class of events.md
/// (decoding and placement, step 1), or of identity.md (the first event's
/// own checks, or an event that is not a device-list event).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A class of events.md: decoding or placement.
    Event(EventClass),
    /// A class of identity.md.
    List(IdentityClass),
}

impl Refusal {
    /// The class's UpperCamelCase name.
    pub fn name(self) -> &'static str {
        use frasil_base::errors::Class;
        match self {
            Refusal::Event(class) => class.name(),
            Refusal::List(class) => class.name(),
        }
    }
}

impl From<EventClass> for Refusal {
    fn from(class: EventClass) -> Self {
        Refusal::Event(class)
    }
}

impl From<IdentityClass> for Refusal {
    fn from(class: IdentityClass) -> Self {
        Refusal::List(class)
    }
}

/// A person's device list: the log of its events, with each placed event's
/// body read and checked alone.
#[derive(Debug, Clone)]
pub struct DeviceList {
    log: Log,
    /// The bodies of placed events that passed steps 2 to 6.
    bodies: BTreeMap<EventId, ListBody>,
    /// Placed events that failed steps 2 to 6, with the class.
    refused: BTreeMap<EventId, IdentityClass>,
    /// The keys every `add` among `bodies` names, by their hashes.
    keys: KeyRing,
}

impl DeviceList {
    /// The list a first event starts. Its ID is the person ID.
    ///
    /// # Errors
    ///
    /// The class of events.md's decoding; `Malformed` for an event of
    /// another kind; then as [`DeviceList::from_first`].
    pub fn new(first: &[u8]) -> Result<Self, Refusal> {
        Self::from_first(decode(first)?)
    }

    /// The list a decoded first event starts: steps 2 to 7 of
    /// `check_alone`, the first event naming its own keys.
    ///
    /// # Errors
    ///
    /// `Malformed` for an event of another kind; `BadGenesis` for an event
    /// with a `log`; then `Malformed`, `BadGenesis`, `InvalidKey`,
    /// `BadPossession` and `BadSignature`, in that order.
    pub fn from_first(event: Event) -> Result<Self, Refusal> {
        if event.kind() != DEVICE_LIST {
            return Err(IdentityClass::Shared(ErrorClass::Malformed).into());
        }
        if !event.is_genesis() {
            return Err(IdentityClass::BadGenesis.into());
        }
        // Steps 2 to 6 read the body before step 7 checks the signature: the
        // first event names its own keys.
        let body = check_body(event.unverified_body(), event.author(), None)?;
        let own = body.keys().ok_or(IdentityClass::BadGenesis)?;
        let id = event.id();
        let mut log = Log::new(event)?;
        log.verify_hybrid(id, Some(&own.hybrid()))
            .map_err(|_| IdentityClass::Shared(ErrorClass::BadSignature))?;
        let mut keys = KeyRing::new();
        keys.add_device(own.device_keys());
        Ok(Self {
            log,
            bodies: BTreeMap::from([(id, body)]),
            refused: BTreeMap::new(),
            keys,
        })
    }

    /// The signed first event of a new person's list (identity.md, "Making a
    /// person", step 1): an `add` of the device itself, kind device, with its
    /// possession proof over 32 zero bytes, naming itself as adder. Its ID
    /// is the person ID.
    pub fn first_event(device: &MemberKeys) -> Vec<u8> {
        let proof = device.prove_possession(&FIRST_EVENT_PERSON, device.device_id(), Kind::Device);
        let body = ListBody::add(Kind::Device, &device.public(Kind::Device), proof);
        Envelope {
            kind: DEVICE_LIST,
            log: None,
            ed: *device.identity(),
            kc: *device.signer().kc(),
            seq: 1,
            prev: None,
            parents: Vec::new(),
            cuts: Vec::new(),
            body: body.encode(),
            scheme: Scheme::Hybrid,
        }
        .sign(device.signer())
    }

    /// The person ID: the ID of the list's first event.
    pub fn person_id(&self) -> [u8; 32] {
        self.log.id().0
    }

    /// The first event's ID, which is the person ID.
    pub fn first(&self) -> EventId {
        self.log.id()
    }

    /// The log of the list's events.
    pub fn log(&self) -> &Log {
        &self.log
    }

    /// Step 1 of `check_alone` on a signed event, then steps 2 to 7 on each
    /// event it places.
    ///
    /// # Errors
    ///
    /// As [`DeviceList::insert_event`], after events.md's decoding.
    pub fn insert(&mut self, signed: &[u8]) -> Result<Placement, Refusal> {
        self.insert_event(decode(signed)?)
    }

    /// Places a decoded event (events.md, "Placement and order"), then runs
    /// steps 2 to 7 on it and on every pending event it releases. An event
    /// that fails them stays placed, and the merge holds it void.
    ///
    /// # Errors
    ///
    /// `Malformed` for an event that is not a device-list event; `WrongLog`
    /// for an event of another person's list.
    pub fn insert_event(&mut self, event: Event) -> Result<Placement, Refusal> {
        if event.kind() != DEVICE_LIST {
            return Err(IdentityClass::Shared(ErrorClass::Malformed).into());
        }
        let placement = self.log.place(event)?;
        if let Placement::Placed(ids) = &placement {
            let person = self.person_id();
            for &id in ids {
                let event = self.log.event(id).expect("placed");
                // Steps 2 to 6 come before step 7, the signature, under keys
                // that the bodies of this list's adds may give; the merge
                // counts an event only once all seven pass (`check_alone`).
                match check_body(event.unverified_body(), event.author(), Some(&person)) {
                    Ok(body) => {
                        self.bodies.insert(id, body);
                    }
                    Err(class) => {
                        self.refused.insert(id, class);
                    }
                }
            }
            self.verify_signatures();
        }
        Ok(placement)
    }

    /// Inserts every signed event, in any order: those whose parents arrive
    /// later wait as pending. Returns the refusal of each event refused
    /// before placement, by its position.
    pub fn insert_all<'a>(
        &mut self,
        signed: impl IntoIterator<Item = &'a [u8]>,
    ) -> Vec<(usize, Refusal)> {
        signed
            .into_iter()
            .enumerate()
            .filter_map(|(i, bytes)| self.insert(bytes).err().map(|refusal| (i, refusal)))
            .collect()
    }

    /// Step 7 for every placed event still waiting for its author's keys,
    /// under the keys the list's adds name, by their hash.
    fn verify_signatures(&mut self) {
        let named: Vec<_> = self
            .bodies
            .values()
            .filter_map(ListBody::keys)
            .map(|keys| keys.device_keys())
            .collect();
        for device in named {
            self.keys.add_device(device);
        }
        self.log.verify_pending_hybrid(&self.keys);
    }

    /// Step 7 again, for every placed event still waiting for its author's
    /// keys, under the list's own keys and those `source` holds: what a
    /// replica runs when keys arrive from outside the list (crypto.md, "Keys
    /// by their hash"). Returns the events whose signature state changed.
    pub fn verify_with(&mut self, source: &(impl KeySource + ?Sized)) -> Vec<EventId> {
        self.log.verify_pending_hybrid(&(&self.keys, source))
    }

    /// The keys the list's `add`s name, indexed by their keys commitment and
    /// device ID: a source of keys by their hash for any event, of this log
    /// or another.
    pub fn keys(&self) -> &KeyRing {
        &self.keys
    }

    /// The body of a placed event that passed steps 2 to 6, whether or not
    /// its signature verified (step 7): a source of keys by their hash, as
    /// events.md, 3.3 The ML-DSA-65 half, "Any source", allows. What judges
    /// an event asks [`check_alone`](DeviceList::check_alone) first, as the
    /// merge does.
    pub fn body(&self, id: EventId) -> Option<&ListBody> {
        self.bodies.get(&id)
    }

    /// The class of a placed event that failed one of steps 2 to 7, or
    /// `None` if it passed them all. The first event always passed.
    pub fn check_alone(&self, id: EventId) -> Option<IdentityClass> {
        if let Some(&class) = self.refused.get(&id) {
            return Some(class);
        }
        match self.log.signature_state(id)? {
            SignatureState::Verified => None,
            SignatureState::NoHybridKey => Some(IdentityClass::Shared(ErrorClass::NoHybridKey)),
            SignatureState::BadSignature => Some(IdentityClass::Shared(ErrorClass::BadSignature)),
        }
    }

    /// The evidence of every fork among the placed events that passed steps
    /// 2 to 7 (events.md, "Chains and evidence of a fork").
    pub fn evidence(&self) -> Vec<Evidence> {
        self.log
            .evidence(|event| self.check_alone(event.id()).is_none())
    }

    /// Each list member's fork point, from [`DeviceList::evidence`].
    pub fn fork_points(&self) -> ForkPoints {
        ForkPoints::from_evidence(&self.evidence())
    }

    /// Every placed event's signed bytes, in canonical order: what a device
    /// publishes in a space as the list's copies, and what a space snapshot
    /// carries.
    pub fn signed_events(&self) -> Vec<Vec<u8>> {
        self.log.events().map(Event::signed).collect()
    }

    /// The signed list event `signer` makes next with `body`, on its own
    /// chain in the list: `seq` and `prev` from its latest event, and as
    /// parents the heads of what it may cite (events.md, "Accepted in full,
    /// and what is cited"), `prev` among them, at most 16. When the list
    /// holds list checkpoints, it cites none of the events concurrent with
    /// the one it follows (roster.md, 3.15.7, "Following", read for a
    /// list), and its body declares the checkpoints its parents give (body
    /// key 8, identity.md, "List checkpoints").
    ///
    /// The event is not inserted; the caller checks the body's rules first.
    pub fn sign(&self, body: &ListBody, signer: &Signer) -> Vec<u8> {
        let plan = self.plan(signer.device_id(), Propose::No);
        self.sign_on(
            body.clone().with_follows(plan.follows),
            signer,
            plan.parents,
        )
    }

    /// An `ack` signed by `signer` (identity.md, "List checkpoints",
    /// "Effect"): a list event that changes nothing, by which a device with
    /// nothing else to sign votes for the list checkpoints it follows.
    pub fn ack(&self, signer: &Signer) -> Vec<u8> {
        self.sign(&ListBody::ack(), signer)
    }

    /// A list checkpoint signed by `signer` on the events it would cite
    /// next: its record is the record of that past (identity.md, "List
    /// checkpoints"). A device proposes only when no list checkpoint waits
    /// for votes in its view, and only a record that fits. The event is not
    /// inserted.
    ///
    /// # Errors
    ///
    /// `UntrustedSigner` for a signer that is not an active device or
    /// recovery key of that past, not rooted and not forked;
    /// `CheckpointPending` while a valid list checkpoint on the chain in
    /// effect waits for votes; `TooLarge` when the record does not fit a
    /// list event (at least 70 active members fit, 51 when every one is
    /// rooted in an agent).
    pub fn propose_checkpoint(&self, signer: &Signer) -> Result<Vec<u8>, IdentityClass> {
        self.propose_with(signer, Propose::AsClient)
    }

    /// A list checkpoint signed as [`DeviceList::propose_checkpoint`] signs
    /// it, even while another waits for votes: for tests that build
    /// competing checkpoints.
    ///
    /// # Errors
    ///
    /// As [`DeviceList::propose_checkpoint`], but never
    /// `CheckpointPending`.
    #[doc(hidden)]
    pub fn propose_checkpoint_anyway(&self, signer: &Signer) -> Result<Vec<u8>, IdentityClass> {
        self.propose_with(signer, Propose::Anyway)
    }

    /// A list checkpoint signed as a dishonest device signs one: citing
    /// every head it may cite, fencing none, and naming `previous` as its
    /// predecessor (`Some(None)` for none, `None` for the latest in effect
    /// in its past), its record that predecessor's world over its past, or
    /// its whole past without one. For tests that build what a stolen or
    /// cut-off device can sign (identity.md, "List checkpoints", "A
    /// rival").
    ///
    /// # Errors
    ///
    /// `TooLarge` when the record does not fit a list event.
    #[doc(hidden)]
    pub fn propose_checkpoint_unfenced(
        &self,
        signer: &Signer,
        previous: Option<Option<EventId>>,
    ) -> Result<Vec<u8>, IdentityClass> {
        self.propose_with(signer, Propose::Unfenced { previous })
    }

    fn propose_with(&self, signer: &Signer, propose: Propose) -> Result<Vec<u8>, IdentityClass> {
        let plan = self.plan(signer.device_id(), propose);
        let record = plan.record.expect("a proposal")?;
        let body = ListBody::checkpoint(&record).with_follows(plan.follows);
        let signed = self.sign_on(body, signer, plan.parents);
        if signed.len() > frasil_events::kind::limits(DEVICE_LIST).bytes {
            return Err(IdentityClass::Shared(ErrorClass::TooLarge));
        }
        Ok(signed)
    }

    /// What `device` does with its own list events that became `Late`: the
    /// revocations to sign again, and the adds and confirms to list for the
    /// person (identity.md, "List checkpoints", "Late and mixed").
    pub fn late_work(&self, merged: &MergedList, device: &DeviceId) -> LateWork {
        checkpoint::late_work(self, merged, device)
    }

    /// Whether `device`, whose view is what this list holds, contests list
    /// checkpoint `checkpoint`, and why (identity.md, "List checkpoints",
    /// "Clients"): it never cites or votes for one, and tells the person,
    /// until the checkpoint takes effect without it, the person has it
    /// revoke itself, or the `revoke` is void in its view. A checkpoint in
    /// effect is not contested.
    pub fn contest(&self, device: &DeviceId, checkpoint: EventId) -> Option<checkpoint::Contest> {
        let ctx = checkpoint::Ctx::new(self, self.first(), None);
        if !ctx.is_checkpoint(checkpoint) || self.merge().chain().contains(&checkpoint) {
            return None;
        }
        ctx.contest(device, checkpoint)
    }

    fn plan(&self, signer: &DeviceId, propose: Propose) -> checkpoint::Plan {
        let (_, prev) = self.log.next_in_chain(signer);
        let citable = self
            .log
            .citable(|event| self.check_alone(event.id()).is_none());
        checkpoint::plan(
            self,
            self.first(),
            None,
            prev,
            citable,
            &|view| self.log.heads_in(view),
            signer,
            propose,
        )
    }

    /// Signs `body` on `signer`'s chain with these parents.
    fn sign_on(&self, body: ListBody, signer: &Signer, parents: Vec<EventId>) -> Vec<u8> {
        let (seq, prev) = self.log.next_in_chain(signer.device_id());
        Envelope {
            kind: DEVICE_LIST,
            log: Some(self.log.id()),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents,
            cuts: Vec::new(),
            body: body.encode(),
            scheme: Scheme::Hybrid,
        }
        .sign(signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: u8) -> MemberKeys {
        MemberKeys::from_seeds(&[n; 32], &[n + 1; 32], &[n + 2; 32])
    }

    #[test]
    fn a_first_event_starts_a_list() {
        let laptop = keys(1);
        let first = DeviceList::first_event(&laptop);
        let list = DeviceList::new(&first).unwrap();
        assert_eq!(list.person_id(), decode(&first).unwrap().id().0);
        assert_eq!(list.check_alone(list.first()), None);
        assert_eq!(list.signed_events(), vec![first]);
    }

    #[test]
    fn an_event_waits_for_the_add_that_names_its_author() {
        let laptop = keys(1);
        let phone = keys(10);
        let mut list = DeviceList::new(&DeviceList::first_event(&laptop)).unwrap();
        let person = list.person_id();
        let add = ListBody::add(
            Kind::Device,
            &phone.public(Kind::Device),
            phone.prove_possession(&person, laptop.device_id(), Kind::Device),
        );
        let add = list.sign(&add, laptop.signer());
        // The phone signs before its add arrives.
        let mut other = list.clone();
        other.insert(&add).unwrap();
        let revoke = other.sign(
            &ListBody::revoke(Kind::Device, *phone.device_id()),
            phone.signer(),
        );
        let revoke_id = decode(&revoke).unwrap().id();
        assert!(matches!(list.insert(&revoke), Ok(Placement::Pending(_))));
        assert!(matches!(list.insert(&add), Ok(Placement::Placed(ids)) if ids.len() == 2));
        assert_eq!(list.check_alone(revoke_id), None);
        assert_eq!(list.signed_events().len(), 3);
        // Another person's list refuses it.
        let mut stranger = DeviceList::new(&DeviceList::first_event(&keys(20))).unwrap();
        assert_eq!(stranger.insert(&add).unwrap_err().name(), "WrongLog");
    }
}
