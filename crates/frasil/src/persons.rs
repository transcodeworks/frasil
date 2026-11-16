//! Persons (identity.md): a device list, the personal space, grants of a
//! person, a person's new device, and sealed list copies.
//!
//! - **Making a person** (identity.md, "Making a person"): the device signs
//!   the list's first event, an `add` of itself, whose ID is the person ID;
//!   founds the personal space, whose roster grants the person; and
//!   publishes the first event there.
//! - **Sealed list copies** (identity.md, "Sealed list copies"): a list
//!   event is never synced bare. It travels in `frasil:list` units of the
//!   system stream of every space that grants or granted the person, and a
//!   replica places each in its person's log, wherever it came from.
//! - **A person's new device** (identity.md, "Adding list members";
//!   admission.md, "A person's new device"): a list member signs an `add`
//!   naming the device's keys with its possession proof, publishes it in
//!   each space it writes in that grants the person, and delivers each such
//!   space's current state to the device.

use crate::device::{Engine, person_recipients};
use crate::error::{Error, Result};
use crate::writer::{self, HeldGrant, HeldState, Recipient, Sealing, SpaceEventPlan};
use frasil_crypto::device::{DeviceId, KeySource};
use frasil_events::EventId;
use frasil_identity::body::ListBody;
use frasil_identity::{DeviceList, Kind, MemberKeys, PublicKeys};
use frasil_space::{Change, HistoryMode, Level, MemberRef, MemberType, Via};
use frasil_store::device_keys::{KeyKind, SEALED_DEVICE_KEYS_BYTES};

/// A person this device made.
#[derive(Debug, Clone)]
pub struct Person {
    /// The person ID.
    pub person: [u8; 32],
    /// The personal space.
    pub personal_space: EventId,
    /// The device's sealed device keys, sealed again to name the person:
    /// what the application keeps from now on, and opens with
    /// [`Engine::open_as`].
    pub sealed: [u8; SEALED_DEVICE_KEYS_BYTES],
}

/// The most list events one `frasil:list` unit carries (units.md, "Limits").
const LIST_EVENTS_PER_UNIT: usize = frasil_units::limits::MAX_LIST_EVENTS;

impl Engine {
    /// This device's keys as a list member's.
    pub(crate) fn member_keys(&self) -> MemberKeys {
        let keys = self.keys();
        MemberKeys::from_seeds(
            &keys.identity_seed_bytes(),
            self.xwing_seed(),
            &keys.mldsa_seed,
        )
    }

    /// The person this device is a device of.
    pub async fn person(&self) -> Option<[u8; 32]> {
        self.lock().await.person
    }

    /// A person's merged list as this device holds it.
    pub async fn list_events(&self, person: &[u8; 32]) -> Vec<Vec<u8>> {
        self.lock()
            .await
            .lists
            .get(person)
            .map(crate::lists::PersonList::signed_events)
            .unwrap_or_default()
    }

    /// The heads of a person's list as this device holds it.
    pub async fn list_heads(&self, person: &[u8; 32]) -> Vec<EventId> {
        self.lock()
            .await
            .lists
            .get(person)
            .map(crate::lists::PersonList::heads)
            .unwrap_or_default()
    }

    /// The devices a person's merged list vouches for, by device ID, as this
    /// device holds the list.
    pub async fn person_devices(&self, person: &[u8; 32]) -> Vec<DeviceId> {
        self.lock()
            .await
            .lists
            .get(person)
            .map(|list| list.merge().recipients())
            .unwrap_or_default()
    }

    /// Makes a person (identity.md, "Making a person"): the list's first
    /// event, the personal space granting the person, and the list's copy
    /// there. The device's keys are sealed again under `unlock_key` to name
    /// the person.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device that is already a person's; the
    /// store's.
    pub async fn make_person(&self, unlock_key: &[u8; 32]) -> Result<Person> {
        if self.person().await.is_some() {
            return Err(Error::NotAllowed("the device is already a person's"));
        }
        let first = DeviceList::first_event(&self.member_keys());
        let list = DeviceList::new(&first).map_err(|refusal| Error::Class(refusal.name()))?;
        let person = list.person_id();
        {
            let mut state = self.lock().await;
            self.keep_lists(&mut state, vec![first]).await?;
            state.person = Some(person);
        }
        let personal_space = self.create_space().await?;
        {
            let mut state = self.lock().await;
            self.keep_personal_space(&mut state, personal_space).await?;
        }
        self.grant_person(
            personal_space,
            person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::None,
        )
        .await?;
        self.publish_list(personal_space, &person).await?;
        let sealed = self.seal_again(&person, unlock_key)?;
        Ok(Person {
            person,
            personal_space,
            sealed,
        })
    }

    /// Finishes taking a person whose ID was recorded before the device's
    /// keys were sealed again to name it: only when this device, opened as
    /// a device member, holds that person's list and is active in it. The
    /// keys sealed again to name the person.
    ///
    /// # Errors
    ///
    /// `WrongPerson` for a device that is already another person's, holds
    /// no list of the person, or is not active in it.
    #[cfg(feature = "sqlite")]
    pub(crate) async fn resume_person(
        &self,
        person: [u8; 32],
        unlock_key: &[u8; 32],
    ) -> Result<[u8; SEALED_DEVICE_KEYS_BYTES]> {
        let mut state = self.lock().await;
        let active = state.person.is_none()
            && state
                .lists
                .get(&person)
                .is_some_and(|list| list.merge().active(&self.device_id()).is_some());
        if !active {
            return Err(Error::Class("WrongPerson"));
        }
        state.person = Some(person);
        drop(state);
        self.seal_again(&person, unlock_key)
    }

    pub(crate) fn seal_again(
        &self,
        person: &[u8; 32],
        unlock_key: &[u8; 32],
    ) -> Result<[u8; SEALED_DEVICE_KEYS_BYTES]> {
        let keys = self.keys();
        let device_keys = frasil_store::DeviceKeys::new(
            keys.identity_seed_bytes(),
            **self.xwing_seed(),
            *keys.mldsa_seed,
            *keys.store_secret,
        );
        frasil_store::seal_device_keys_with(
            &device_keys,
            person,
            KeyKind::UnlockKey,
            unlock_key,
            &self.platform().nonce::<24>()?,
        )
        .map_err(Error::class)
    }

    /// Grants a person (roster.md, "Changes"): its list's heads go in the
    /// event's refs, and a grant with history delivers the current state to
    /// every device its list vouches for.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] when the device holds no list of the person;
    /// as [`Engine::sign_roster`].
    pub async fn grant_person(
        &self,
        space: EventId,
        person: [u8; 32],
        level: Level,
        history: HistoryMode,
        via: Via,
    ) -> Result<EventId> {
        if !self.lock().await.lists.contains_key(&person) {
            return Err(Error::NotAllowed("the device holds no list of the person"));
        }
        let change = Change::grant(MemberRef::person(person), level, history, via);
        let (event, wraps) = self.sign_roster_with(space, vec![change]).await?;
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        if history == HistoryMode::WithHistory {
            self.welcome_person(space, person, level, event, &wraps)
                .await?;
        }
        #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
        let _ = wraps;
        Ok(event)
    }

    /// Welcomes for the devices a person grant admits, other than this
    /// one, kept until a member connection with each hands its welcome
    /// over, and deposited in each one's device mailbox at the peers this
    /// device is connected to once they hold the event (admission.md,
    /// "Welcomes"; transport.md, "Mailboxes"): a device of the person
    /// learns of the space with no peer, or through a peer alone.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn welcome_person(
        &self,
        space: EventId,
        person: [u8; 32],
        level: Level,
        event: EventId,
        wraps: &std::collections::BTreeMap<DeviceId, writer::WrapOf>,
    ) -> Result<()> {
        let recipients = {
            let state = self.lock().await;
            person_recipients(&person, level, &state.lists, state.replicas.get(&space))
        };
        let me = self.device_id();
        for recipient in recipients {
            let device = recipient.keys.device_id();
            let Some(wrap) = wraps.get(&device) else {
                continue;
            };
            if device == me {
                continue;
            }
            let welcome = frasil_admission::welcome::Welcome {
                space: space.0,
                event,
                key_name: wrap.key_name.encode(),
                grant_name: wrap
                    .grant_name
                    .as_ref()
                    .map(frasil_keys::KeyName::encode)
                    .unwrap_or_default(),
                wrap: wrap.wrap.clone(),
                approver: me,
                peers: self.welcome_hints(&space, &[]).await,
                snapshot: None,
            };
            let sealed = welcome
                .seal_with(&recipient.keys, &*self.platform().draw::<64>()?)
                .map_err(Error::class)?;
            self.links().wait(crate::links::Waiting {
                recipient: device,
                space,
                event,
                sealed,
                deposited: Vec::new(),
            });
        }
        Ok(())
    }

    /// Publishes a person's list events a space's system stream lacks, in
    /// `frasil:list` units of at most 16 events (identity.md, "Sealed list
    /// copies").
    ///
    /// # Errors
    ///
    /// As [`Engine::write_system`].
    pub async fn publish_list(&self, space: EventId, person: &[u8; 32]) -> Result<Vec<EventId>> {
        let events = self.list_events(person).await;
        let held = self
            .read(&space, |replica| replica.list_copies_held())
            .await?;
        let missing: Vec<Vec<u8>> = events
            .into_iter()
            .filter(|signed| {
                frasil_events::decode(signed).is_ok_and(|event| !held.contains(&event.id()))
            })
            .collect();
        let mut written = Vec::new();
        for chunk in missing.chunks(LIST_EVENTS_PER_UNIT) {
            let content = frasil_units::own::list_copy_content(chunk);
            written.push(
                self.write_system(space, frasil_units::types::LIST, content)
                    .await?,
            );
        }
        Ok(written)
    }

    /// Hands this device's person's list to a space it cannot write
    /// (units.md, "A read-only person's list events"; transport.md, "List
    /// events from a reader"): the device-mailbox items, each sealed to one
    /// writer device of the space, that carry the list events its system
    /// stream lacks, as `(mailbox address, item)`. A device that writes
    /// publishes them itself instead, and hands nothing over; so does one
    /// of no person.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; as [`Engine::publish_list`].
    pub async fn hand_over_list(&self, space: EventId) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        use frasil_transport::mailbox;
        let Some(person) = self.person().await else {
            return Ok(Vec::new());
        };
        let me = self.device_id();
        let writes = self
            .read(&space, |replica| {
                replica
                    .level_of(&me)
                    .is_some_and(|level| level >= Level::Write)
            })
            .await?;
        if writes {
            self.publish_list(space, &person).await?;
            return Ok(Vec::new());
        }
        let events = self.list_events(&person).await;
        let state = self.lock().await;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        // A writer takes list events only of a person the roster names, so
        // a space whose roster does not name this device's person, such as
        // one a link admitted the device alone to, is handed nothing.
        if replica.roster().state(&MemberRef::person(person)).is_none() {
            return Ok(Vec::new());
        }
        let held = replica.list_copies_held();
        let missing: Vec<Vec<u8>> = events
            .into_iter()
            .filter(|signed| {
                frasil_events::decode(signed).is_ok_and(|event| !held.contains(&event.id()))
            })
            .collect();
        if missing.is_empty() {
            return Ok(Vec::new());
        }
        // Each writer's keys, which its device ID commits to, from any
        // source: its device grant, the list of a person whose grant
        // reaches it, or the device's key ring (crypto.md, "Keys by their
        // hash").
        let writers: Vec<(DeviceId, frasil_crypto::device::DeviceKeys)> = replica
            .devices()
            .into_iter()
            .filter(|(device, level)| *device != me && *level >= Level::Write)
            .filter_map(|(device, _)| {
                let from_grant = replica
                    .roster()
                    .state(&MemberRef::device(device))
                    .and_then(|state| state.keys.as_deref())
                    .cloned();
                let from_list = || {
                    state
                        .lists
                        .values()
                        .find_map(|list| list.merge().keys(&device).map(PublicKeys::device_keys))
                };
                let from_ring = || state.keys().device_keys(&device);
                from_grant
                    .or_else(from_list)
                    .or_else(from_ring)
                    .filter(|keys| keys.device_id() == device && keys.keys.xwing().is_some())
                    .map(|keys| (device, keys))
            })
            .collect();
        let mut items = Vec::new();
        for chunk in missing.chunks(LIST_EVENTS_PER_UNIT) {
            let body = frasil_units::own::ListEventsBody {
                space,
                events: chunk.to_vec(),
            }
            .encode();
            for (writer, keys) in &writers {
                let randomness = self
                    .platform()
                    .draw::<{ frasil_crypto::wrap::ENCAPSULATION_RANDOMNESS }>()?;
                let item = mailbox::seal_item_with(
                    mailbox::content::LIST_EVENTS,
                    &body,
                    keys,
                    &randomness,
                )
                .map_err(Error::class)?;
                items.push((mailbox::address(mailbox::Kind::Device, &writer.0), item));
            }
        }
        Ok(items)
    }

    /// Takes a reader's list events at a writer device (units.md, "A
    /// read-only person's list events"): each event of a person the
    /// space's roster names, now or before, goes into the person's list,
    /// and a `frasil:list` unit forwards those the space's view lacks. An
    /// event of any other person is dropped, and nothing else.
    ///
    /// # Errors
    ///
    /// `Malformed` for a body that does not read; [`Error::UnknownSpace`];
    /// as [`Engine::publish_list`].
    pub async fn take_list_events(&self, body: &[u8]) -> Result<()> {
        let body =
            frasil_units::own::ListEventsBody::read(body).map_err(|_| Error::Class("Malformed"))?;
        let space = body.space;
        let me = self.device_id();
        let (named, writes) = self
            .read(&space, |replica| {
                let named: std::collections::BTreeSet<[u8; 32]> = replica
                    .roster()
                    .iter()
                    .filter(|(member, _)| member.kind == MemberType::Person)
                    .map(|(member, _)| member.id)
                    .collect();
                let writes = replica
                    .level_of(&me)
                    .is_some_and(|level| level >= Level::Write);
                (named, writes)
            })
            .await?;
        let mut persons = std::collections::BTreeSet::new();
        let events: Vec<Vec<u8>> = body
            .events
            .into_iter()
            .filter(|signed| {
                frasil_events::decode(signed).is_ok_and(|event| {
                    let person = event.log_id().0;
                    let kept =
                        event.kind() == frasil_events::kind::DEVICE_LIST && named.contains(&person);
                    if kept {
                        persons.insert(person);
                    }
                    kept
                })
            })
            .collect();
        if events.is_empty() {
            return Ok(());
        }
        {
            let mut state = self.lock().await;
            self.keep_lists(&mut state, events).await?;
        }
        if writes {
            for person in persons {
                self.publish_list(space, &person).await?;
            }
        }
        Ok(())
    }

    /// Takes one item of this device's own device mailbox (transport.md,
    /// "The item seal"): a reader's list events, or with ext-guests.md a
    /// leave request.
    ///
    /// # Errors
    ///
    /// The item's classes; `UnknownContent` for a content name this build
    /// does not act on; the content's own.
    pub async fn take_device_item(&self, item: &[u8]) -> Result<()> {
        use frasil_transport::mailbox;
        let opened = mailbox::open_item(
            item,
            &self.device_id(),
            self.xwing_seed(),
            mailbox::content::implemented,
        )
        .map_err(Error::class)?;
        if opened.content == mailbox::content::LIST_EVENTS {
            return self.take_list_events(&opened.body).await;
        }
        #[cfg(feature = "ext-guests")]
        if opened.content == mailbox::content::LEAVE_REQUEST {
            return self.take_mailbox_item(item).await;
        }
        Err(Error::Class("UnknownContent"))
    }

    /// Takes another person's list events, as a code exchange with a person
    /// joiner hands them over (admission.md, "A person that joins a
    /// space"): each is checked as a list event and placed in its person's
    /// list.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn receive_list(&self, events: Vec<Vec<u8>>) -> Result<()> {
        let mut state = self.lock().await;
        self.keep_lists(&mut state, events).await
    }

    /// The keys a device names when it joins a person's list (admission.md,
    /// "A person's new device"): its public keys and its possession proof
    /// over the person ID, for `adder`, the device ID of the list member
    /// that will sign its `add` (identity.md, "The possession statement").
    /// No other list member's `add` of the device carries the proof.
    pub fn list_keys(&self, person: &[u8; 32], adder: &DeviceId) -> (PublicKeys, Vec<u8>) {
        let keys = self.member_keys();
        (
            keys.public(Kind::Device),
            keys.prove_possession(person, adder, Kind::Device),
        )
    }

    /// Adds a device to this device's person (identity.md, "Adding list
    /// members"): signs the `add`, publishes it in each space this device
    /// writes in that grants the person, and delivers each such space's
    /// current state to the new device. Returns the `add`'s event ID.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device that is no person's; the list's
    /// classes; the store's.
    pub async fn add_device(&self, keys: PublicKeys, possession: Vec<u8>) -> Result<EventId> {
        Ok(self.add_device_reaching(keys, possession).await?.0)
    }

    /// [`add_device`](Self::add_device), with what reaches the new device
    /// in each space: the space, the delivery and the new device's wrap in
    /// it, as a welcome names them (admission.md, "A person's new device").
    ///
    /// # Errors
    ///
    /// As [`add_device`](Self::add_device).
    pub(crate) async fn add_device_reaching(
        &self,
        keys: PublicKeys,
        possession: Vec<u8>,
    ) -> Result<(EventId, Vec<(EventId, EventId, writer::WrapOf)>)> {
        let person = self
            .person()
            .await
            .ok_or(Error::NotAllowed("the device is no person's"))?;
        let new = keys.device_id();
        if keys.xwing.is_none() {
            return Err(Error::Class("Malformed"));
        }
        let device_keys = keys.device_keys();
        let signed = {
            let state = self.lock().await;
            let list = state
                .lists
                .get(&person)
                .ok_or(Error::NotAllowed("the device holds no list of its person"))?;
            let body = ListBody::add(Kind::Device, &keys, possession);
            list.sign(&body, self.signer())
        };
        let add = frasil_events::decode(&signed).map_err(Error::class)?.id();
        {
            let mut state = self.lock().await;
            self.keep_lists(&mut state, vec![signed]).await?;
            let valid = state
                .lists
                .get(&person)
                .is_some_and(|list| list.merge().is_valid(add));
            if !valid {
                return Err(Error::Class("NotInList"));
            }
        }
        let spaces = self.spaces().await;
        let mut reached = Vec::new();
        for space in spaces {
            let grants = self
                .read(&space, |replica| {
                    replica
                        .roster()
                        .members_in()
                        .any(|(member, _)| member.kind == MemberType::Person && member.id == person)
                        && replica.level_of(&self.device_id()) >= Some(Level::Write)
                })
                .await?;
            if !grants {
                continue;
            }
            self.publish_list(space, &person).await?;
            let level = self
                .read(&space, |replica| {
                    replica
                        .roster()
                        .level(&MemberRef::person(person))
                        .unwrap_or(Level::Read)
                })
                .await?;
            let (delivery, mut wraps) = self
                .deliver_with(
                    space,
                    vec![Recipient {
                        keys: device_keys.clone(),
                        writes: level >= Level::Write,
                        propagates: true,
                    }],
                )
                .await?;
            if let Some(wrap) = wraps.remove(&new) {
                reached.push((space, delivery, wrap));
            }
        }
        Ok((add, reached))
    }

    /// Revokes a device of this device's person by a `revoke` list event
    /// (identity.md, "The device-list event"), and hands the list's new state to every space that grants
    /// the person where this device writes, as a `frasil:list` unit. Each
    /// such space owes a cascaded rotation (keys.md, "Cascades"). Returns
    /// the revocation's event ID.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device that is no person's; the list's
    /// classes; the store's.
    pub async fn revoke_device(&self, device: DeviceId) -> Result<EventId> {
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
            list.sign(&ListBody::revoke(Kind::Device, device), self.signer())
        };
        let revoke = frasil_events::decode(&signed).map_err(Error::class)?.id();
        {
            let mut state = self.lock().await;
            self.keep_lists(&mut state, vec![signed]).await?;
            let valid = state
                .lists
                .get(&person)
                .is_some_and(|list| list.merge().is_valid(revoke));
            if !valid {
                return Err(Error::Class("NotInList"));
            }
        }
        for space in self.spaces().await {
            let grants = self
                .read(&space, |replica| {
                    replica
                        .roster()
                        .members_in()
                        .any(|(member, _)| member.kind == MemberType::Person && member.id == person)
                        && replica.level_of(&self.device_id()) >= Some(Level::Write)
                })
                .await?;
            // A space that reached the device waits for its cascaded
            // rotation; the rotation's author hands the list over after it.
            let waits = {
                let state = self.lock().await;
                self.cascade_waits(&state, &space)
            };
            if grants && !waits {
                self.publish_list(space, &person).await?;
            }
        }
        Ok(revoke)
    }

    /// Takes a person's list as its new device (admission.md, "A person's
    /// new device"): the list's events, which must hold a valid `add` of
    /// this device; the device's keys are sealed again to name the person.
    ///
    /// # Errors
    ///
    /// `WrongPerson`, `NotInList`; the store's.
    pub async fn adopt_person(
        &self,
        person: [u8; 32],
        events: Vec<Vec<u8>>,
        unlock_key: &[u8; 32],
    ) -> Result<[u8; SEALED_DEVICE_KEYS_BYTES]> {
        let mut state = self.lock().await;
        self.keep_lists(&mut state, events).await?;
        let list = state
            .lists
            .get(&person)
            .ok_or(Error::Class("WrongPerson"))?;
        if list.merge().active(&self.device_id()).is_none() {
            return Err(Error::Class("NotInList"));
        }
        state.person = Some(person);
        drop(state);
        self.seal_again(&person, unlock_key)
    }

    /// A key event that only delivers the current state, and the grant
    /// state to those that propagate, to these devices (keys.md,
    /// "Deliveries").
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device writes in the space; the
    /// store's.
    pub(crate) async fn deliver(
        &self,
        space: EventId,
        recipients: Vec<Recipient>,
    ) -> Result<EventId> {
        Ok(self.deliver_with(space, recipients).await?.0)
    }

    /// [`deliver`](Self::deliver), with each recipient's wrap.
    pub(crate) async fn deliver_with(
        &self,
        space: EventId,
        recipients: Vec<Recipient>,
    ) -> Result<(
        EventId,
        std::collections::BTreeMap<DeviceId, writer::WrapOf>,
    )> {
        self.deliver_checked(space, recipients, None, false).await
    }

    /// A key event that only delivers `delivered`, a content state other
    /// than the current one that this device holds, to these devices,
    /// sealed under the current state (keys.md, "Deliveries", item 2). The
    /// bundle carries the upload seed to recipients that write, when this
    /// device holds it, and no grant seed.
    ///
    /// # Errors
    ///
    /// As [`deliver`](Self::deliver); [`Error::NotAllowed`] when the device
    /// does not hold `delivered`.
    pub(crate) async fn deliver_state(
        &self,
        space: EventId,
        delivered: frasil_keys::RotationSet,
        recipients: Vec<Recipient>,
    ) -> Result<EventId> {
        let mut state = self.lock().await;
        self.publish_own_lists(&mut state, space).await?;
        if !state.vault.head().may_sign(&space.0) {
            return Err(Error::SyncBeforeWriting);
        }
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.level_of(&self.device_id()) < Some(Level::Write) {
            return Err(Error::NotAllowed("key events need write"));
        }
        let current = replica
            .current()
            .cloned()
            .ok_or(Error::NotAllowed("the device holds no state"))?;
        let (content, _) = replica
            .state_key(&current)
            .ok_or(Error::NotAllowed("the device lacks the current key"))?;
        let held = HeldState {
            upload: replica.state_upload(&current),
            state: current,
            content,
        };
        let (other, _) = replica
            .state_key(&delivered)
            .ok_or(Error::NotAllowed("the device lacks the state it delivers"))?;
        let other = HeldState {
            upload: replica.state_upload(&delivered),
            state: delivered,
            content: other,
        };
        let (seq, prev) = Self::next(&state, &space, &self.device_id());
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
                    grant: None,
                    recipients: Vec::new(),
                    others: vec![(other, recipients)],
                },
                refs: Vec::new(),
                twin: None,
                notices: Vec::new(),
                principals: Vec::new(),
                grantless: false,
            },
        )?;
        self.commit_signed(&mut state, space, &signed.signed).await
    }

    /// Delivers only while both author and recipient still administer,
    /// checking in the signing transaction that the recipient's grant still
    /// names these keys.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn deliver_administrator(
        &self,
        space: EventId,
        keys: &frasil_space::DeviceKeys,
    ) -> Result<(
        EventId,
        std::collections::BTreeMap<DeviceId, writer::WrapOf>,
    )> {
        self.deliver_checked(
            space,
            vec![Recipient {
                keys: keys.clone(),
                writes: true,
                propagates: true,
            }],
            Some(keys),
            false,
        )
        .await
    }

    /// Delivers to a current member without changing its grant.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn deliver_returning_member(
        &self,
        space: EventId,
        keys: &frasil_space::DeviceKeys,
    ) -> Result<(
        EventId,
        std::collections::BTreeMap<DeviceId, writer::WrapOf>,
    )> {
        let level = self
            .read(&space, |replica| replica.level_of(&keys.device_id()))
            .await?
            .ok_or(Error::NotAllowed("requester is not a member"))?;
        self.deliver_checked(
            space,
            vec![Recipient {
                keys: keys.clone(),
                writes: level >= Level::Write,
                propagates: level == Level::Administer,
            }],
            Some(keys),
            true,
        )
        .await
    }

    async fn deliver_checked(
        &self,
        space: EventId,
        recipients: Vec<Recipient>,
        expected: Option<&frasil_space::DeviceKeys>,
        returning: bool,
    ) -> Result<(
        EventId,
        std::collections::BTreeMap<DeviceId, writer::WrapOf>,
    )> {
        let mut state = self.lock().await;
        self.publish_own_lists(&mut state, space).await?;
        if !state.vault.head().may_sign(&space.0) {
            return Err(Error::SyncBeforeWriting);
        }
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.level_of(&self.device_id()) < Some(Level::Write) {
            return Err(Error::NotAllowed("key events need write"));
        }
        if let Some(keys) = expected
            && (replica.level_of(&self.device_id()) != Some(Level::Administer)
                || recipients.iter().any(|recipient| {
                    if returning {
                        let held = replica
                            .roster()
                            .state(&MemberRef::device(recipient.keys.device_id()))
                            .and_then(|member| member.keys.as_deref())
                            .cloned()
                            .or_else(|| state.keys().device_keys(&recipient.keys.device_id()));
                        return replica.level_of(&recipient.keys.device_id()).is_none()
                            || held.as_ref() != Some(keys);
                    }
                    replica
                        .roster()
                        .state(&MemberRef::device(recipient.keys.device_id()))
                        .is_none_or(|member| {
                            member.level != Level::Administer
                                || member.session.is_some()
                                || member.keys.as_deref().is_none_or(|held| held != keys)
                        })
                }))
        {
            return Err(Error::NotAllowed(
                "administrator delivery needs the same administrators and device keys",
            ));
        }
        let current = replica
            .current()
            .cloned()
            .ok_or(Error::NotAllowed("the device holds no state"))?;
        let (content, _) = replica
            .state_key(&current)
            .ok_or(Error::NotAllowed("the device lacks the current key"))?;
        let held = HeldState {
            upload: replica.state_upload(&current),
            state: current,
            content,
        };
        let grant = replica.grant_current().cloned().and_then(|state| {
            replica
                .state_grant(&state)
                .map(|grant| HeldGrant { state, grant })
        });
        let (seq, prev) = Self::next(&state, &space, &self.device_id());
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
                    grant,
                    recipients,
                    others: Vec::new(),
                },
                refs: Vec::new(),
                twin: None,
                notices: Vec::new(),
                principals: Vec::new(),
                grantless: false,
            },
        )?;
        let id = self
            .commit_signed(&mut state, space, &signed.signed)
            .await?;
        Ok((id, signed.wraps))
    }

    /// Changes a member's level (roster.md, "Changes"). A demotion to
    /// `read` rotates ([`Engine::sign_roster`]). A raise need not (keys.md,
    /// "Checks against the event and its place"): the member's devices
    /// receive the current state as a delivery, with the upload seed where
    /// they now write.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the space has no such member; as
    /// [`Engine::sign_roster`] and [`Engine::deliver`].
    pub async fn set_level(
        &self,
        space: EventId,
        member: MemberRef,
        level: Level,
    ) -> Result<EventId> {
        // Only a device administers (roster.md, 2.3 Changes): a
        // change that raises any other member to `administer` is void, and
        // signing it would leave a void event in the log.
        if level == Level::Administer && member.kind != MemberType::Device {
            return Err(Error::Class("AdministerNotDevice"));
        }
        if level == Level::Administer {
            return Err(Error::Invalid(
                "an administrator is made at a rank: Engine::raise",
            ));
        }
        self.set_level_ranked(space, member, level, None).await
    }

    /// Raises a device member to `administer` at `rank` (roster.md, 2.3
    /// Changes, "Ranks"): at most this device's own rank.
    ///
    /// # Errors
    ///
    /// `HigherRank` for a rank above this device's own; `RankInPlace` for
    /// a member at `administer` already, whose rank [`Engine::set_rank`]
    /// changes; as [`Engine::set_level`].
    pub async fn raise(&self, space: EventId, member: MemberRef, rank: u8) -> Result<EventId> {
        if member.kind != MemberType::Device {
            return Err(Error::Class("AdministerNotDevice"));
        }
        self.set_level_ranked(space, member, Level::Administer, Some(rank))
            .await
    }

    /// Makes a device member the space's recovery member (roster.md, 3.15.7,
    /// "Dormant administrators"; keys.md, "The space recovery member"): it
    /// administers at the top rank, marked `frasil.dormant`, so that
    /// checkpoints do not wait for it and it can excuse and remove any
    /// member. Only a device at the top rank makes one. A member at
    /// `administer` already is lowered to `write` first, since a rank never
    /// changes in place. Returns the change that makes it.
    ///
    /// # Errors
    ///
    /// `HigherRank` unless this device holds the top rank; `AdministerNotDevice`
    /// for a person or a space; as [`Engine::raise`].
    pub async fn make_recovery_member(&self, space: EventId, member: MemberRef) -> Result<EventId> {
        use frasil_space::change::MAX_RANK;
        if member.kind != MemberType::Device {
            return Err(Error::Class("AdministerNotDevice"));
        }
        if self.my_rank(&space).await != Some(MAX_RANK) {
            return Err(Error::Class("HigherRank"));
        }
        let level = self
            .read(&space, |replica| {
                replica.roster().state(&member).map(|s| s.level)
            })
            .await?
            .ok_or(Error::Invalid("no member of the space has this ID"))?;
        if level == Level::Administer {
            self.set_level_ranked(space, member, Level::Write, None)
                .await?;
        }
        let mut change = Change::raise(member, MAX_RANK);
        change.capabilities = Some(vec![dormant(true)]);
        self.sign_roster(space, vec![change]).await
    }

    /// Marks an administrator `frasil.dormant`, or unmarks it (roster.md,
    /// 3.15.4): a checkpoint does not wait for a dormant administrator.
    /// Only a member of its rank or higher signs it (roster.md, 3.6).
    /// Returns `None` when nothing changes.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a member that does not administer;
    /// `HigherRank` for one of a higher rank; as [`Engine::sign_roster`].
    pub async fn set_dormant(
        &self,
        space: EventId,
        member: MemberRef,
        on: bool,
    ) -> Result<Option<EventId>> {
        use frasil_space::{Capability, Op};
        let (level, held) = self
            .read(&space, |replica| {
                replica
                    .roster()
                    .state(&member)
                    .map(|state| (state.level, state.capabilities.clone()))
            })
            .await?
            .ok_or(Error::Invalid("no member of the space has this ID"))?;
        if level != Level::Administer {
            return Err(Error::Invalid("only an administrator is marked dormant"));
        }
        if held.iter().any(|c| *c == dormant(true)) == on {
            return Ok(None);
        }
        let mut kept: Vec<Capability> = held
            .into_iter()
            .filter(|c| c.name != frasil_space::checkpoint::DORMANT)
            .collect();
        // A change carries at least one capability: unmarked with no other,
        // it keeps `frasil.dormant` narrowed, which marks nothing.
        if on || kept.is_empty() {
            kept.push(dormant(on));
        }
        kept.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        kept.dedup_by(|a, b| a.name == b.name);
        let change = Change {
            capabilities: Some(kept),
            ..Change::new(Op::Change, Some(member))
        };
        self.sign_roster(space, vec![change]).await.map(Some)
    }

    /// The space's recovery members in this device's view: device members
    /// at `administer` marked `frasil.dormant`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn recovery_members(&self, space: &EventId) -> Result<Vec<DeviceId>> {
        self.read(space, |replica| {
            replica
                .roster()
                .members_in()
                .filter(|(member, state)| {
                    member.kind == MemberType::Device
                        && state.level == Level::Administer
                        && state.capabilities.contains(&dormant(true))
                })
                .map(|(member, _)| DeviceId(member.id))
                .collect()
        })
        .await
    }

    /// Changes an administrator's rank: a rank never changes in place, so
    /// this lowers the member to `write`, then raises it at `rank`, two
    /// roster events (roster.md, 2.3 Changes, "Ranks"). A member at
    /// `administer` at that rank already is left as it is. Returns the
    /// raise.
    ///
    /// # Errors
    ///
    /// `HigherRank` for a member or a rank above this device's own; as
    /// [`Engine::raise`].
    pub async fn set_rank(&self, space: EventId, member: MemberRef, rank: u8) -> Result<EventId> {
        let current = self
            .read(&space, |replica| {
                replica
                    .roster()
                    .state(&member)
                    .map(|state| (state.level, state.rank))
            })
            .await?
            .ok_or(Error::Invalid("no member of the space has this ID"))?;
        if current.0 == Level::Administer {
            if current.1 == Some(rank) {
                return Err(Error::Invalid("the member holds this rank already"));
            }
            let me = self.device_id();
            let mine = self
                .read(&space, |replica| {
                    replica
                        .roster()
                        .state(&MemberRef::device(me))
                        .and_then(|state| state.rank)
                })
                .await?;
            // Both events are checked before the first is signed.
            if rank > mine.unwrap_or(0) || current.1 > mine {
                return Err(Error::Class("HigherRank"));
            }
            self.set_level_ranked(space, member, Level::Write, None)
                .await?;
        }
        self.raise(space, member, rank).await
    }

    async fn set_level_ranked(
        &self,
        space: EventId,
        member: MemberRef,
        level: Level,
        rank: Option<u8>,
    ) -> Result<EventId> {
        let (before, guest) = self
            .read(&space, |replica| {
                replica
                    .roster()
                    .state(&member)
                    .map(|state| (state.level, state.session.is_some()))
            })
            .await?
            .ok_or(Error::Invalid("no member of the space has this ID"))?;
        // Nor a guest: a change keeps `session` as granted, and one that
        // raises a guest is void at its place (roster.md, 3.6 Authority at
        // the place).
        if level == Level::Administer && guest {
            return Err(Error::Class("AdministerNotDevice"));
        }
        let change = match rank {
            Some(rank) => Change::raise(member, rank),
            None => Change::set_level(member, level),
        };
        let id = self.sign_roster(space, vec![change]).await?;
        if before < level {
            let recipients = {
                let state = self.lock().await;
                let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
                match member.kind {
                    MemberType::Device => replica
                        .roster()
                        .state(&member)
                        .and_then(|state| {
                            state.keys.as_ref().map(|keys| Recipient {
                                keys: (**keys).clone(),
                                writes: level >= Level::Write,
                                propagates: state.propagates(),
                            })
                        })
                        .into_iter()
                        .collect(),
                    MemberType::Person => {
                        person_recipients(&member.id, level, &state.lists, Some(replica))
                    }
                    _ => Vec::new(),
                }
            };
            if !recipients.is_empty() {
                self.deliver(space, recipients).await?;
            }
        }
        Ok(id)
    }

    /// Makes a member a suggester, or no longer one (units.md, "`suggest`"):
    /// a change of its capabilities that adds `suggest` with mode narrows,
    /// or drops it. A change carries at least one capability, so a member
    /// left with none keeps `suggest` with mode extends, which the built-in
    /// adapters ignore. Returns `None` when nothing changes.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the space has no such member; as
    /// [`Engine::sign_roster`].
    pub async fn set_suggester(
        &self,
        space: EventId,
        member: MemberRef,
        suggester: bool,
    ) -> Result<Option<EventId>> {
        use frasil_adapter::SUGGEST;
        use frasil_space::{Capability, CapabilityMode, Op};
        let held = self
            .read(&space, |replica| {
                replica
                    .roster()
                    .state(&member)
                    .map(|state| state.capabilities.clone())
            })
            .await?
            .ok_or(Error::Invalid("no member of the space has this ID"))?;
        let is = held
            .iter()
            .any(|c| c.name == SUGGEST && c.mode == CapabilityMode::Narrows);
        if is == suggester {
            return Ok(None);
        }
        // One mode per name: a change's capabilities ascend strictly by
        // name.
        let mut kept: Vec<Capability> = Vec::new();
        for capability in held {
            if capability.name != SUGGEST
                && kept.last().is_none_or(|last| last.name != capability.name)
            {
                kept.push(capability);
            }
        }
        if suggester || kept.is_empty() {
            kept.push(Capability {
                name: SUGGEST.to_owned(),
                mode: if suggester {
                    CapabilityMode::Narrows
                } else {
                    CapabilityMode::Extends
                },
            });
        }
        kept.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        let change = Change {
            capabilities: Some(kept),
            ..Change::new(Op::Change, Some(member))
        };
        self.sign_roster(space, vec![change]).await.map(Some)
    }

    /// The recipients a person grant reaches now, for tests and
    /// applications that check who a grant delivers to.
    pub async fn person_recipients(&self, person: &[u8; 32], level: Level) -> Vec<DeviceId> {
        let state = self.lock().await;
        person_recipients(person, level, &state.lists, None)
            .into_iter()
            .map(|r| r.keys.device_id())
            .collect()
    }
}

/// `frasil.dormant`, extending (marked) or narrowing (unmarked).
fn dormant(on: bool) -> frasil_space::Capability {
    frasil_space::Capability {
        name: frasil_space::checkpoint::DORMANT.to_owned(),
        mode: if on {
            frasil_space::CapabilityMode::Extends
        } else {
            frasil_space::CapabilityMode::Narrows
        },
    }
}
