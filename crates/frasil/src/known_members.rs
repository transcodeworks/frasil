//! A member of another space (admission.md, 3.16): an administrator grants
//! a device that a space it holds grants directly, by the device ID and
//! keys that roster names, with no code and no peer; and the welcomes that
//! wait for a member connection, made again from the log after a restart
//! (admission.md, 3.10 Welcomes, "A welcome that waits for a member
//! connection").

use crate::device::Engine;
use crate::error::{Error, Result};
#[cfg(feature = "iroh")]
use crate::writer::Recipient;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_events::EventId;
use frasil_space::{Change, HistoryMode, Level, MemberRef, Via};

impl Engine {
    /// Grants `device`, which `known` grants directly, in `space`
    /// (admission.md, 3.16 A member of another space): at `level`, with
    /// `rank` exactly when `level` is `administer`, with history, `via` =
    /// `none`, carrying the keys `known`'s grant names. The grant commits
    /// at once; the device's welcome waits for a member connection with it
    /// and goes to the mailbox at peers as a person grant's does
    /// (admission.md, 3.10 Welcomes). Returns the admitting event, also
    /// when the welcome could not be kept: the signer makes it again when
    /// the two devices meet.
    ///
    /// # Errors
    ///
    /// In the order admission.md, 3.16 checks them, each
    /// [`Error::NotAllowed`]: this device does not administer `space`;
    /// `known` does not reach this device; `known` does not grant the
    /// device directly; the device is a guest there; `known` does not
    /// reach the device, or the device forked there; `space` reaches the
    /// device already; a restricted space's parent does not reach it. [`Error::Invalid`] for `administer`
    /// without a rank or a rank at another level; [`Error::UnknownSpace`];
    /// then as [`Engine::sign_roster`], `HigherRank` among them.
    pub async fn admit_member(
        &self,
        space: EventId,
        known: EventId,
        device: DeviceId,
        level: Level,
        rank: Option<u8>,
    ) -> Result<EventId> {
        let change = |keys: DeviceKeys| match (level, rank) {
            (Level::Administer, Some(rank)) => Ok(Change::grant_administrator(
                keys,
                rank,
                HistoryMode::WithHistory,
                Via::None,
            )),
            (Level::Administer, None) => {
                Err(Error::Invalid("an administrator is admitted at a rank"))
            }
            (_, Some(_)) => Err(Error::Invalid("only an administrator has a rank")),
            (level, None) => Ok(Change::grant_device(
                keys,
                level,
                HistoryMode::WithHistory,
                Via::None,
            )),
        };
        let me = self.device_id();
        let (keys, already) = {
            let state = self.lock().await;
            let target = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let source = state.replicas.get(&known).ok_or(Error::UnknownSpace)?;
            if target.level_of(&me) != Some(Level::Administer) {
                return Err(Error::NotAllowed("admitting needs administer"));
            }
            if source.level_of(&me).is_none() {
                return Err(Error::NotAllowed(
                    "the known space does not reach this device",
                ));
            }
            let member =
                source
                    .roster()
                    .state(&MemberRef::device(device))
                    .ok_or(Error::NotAllowed(
                        "the known space does not grant the device directly",
                    ))?;
            if member.session.is_some() {
                return Err(Error::NotAllowed(
                    "the device is a guest in the known space",
                ));
            }
            if source.level_of(&device).is_none() || source.forked(&device) {
                return Err(Error::NotAllowed(
                    "the known space's grant of the device is not in effect",
                ));
            }
            let keys = member.keys.as_deref().cloned().ok_or(Error::NotAllowed(
                "the known space does not grant the device directly",
            ))?;
            (keys, target.level_of(&device).is_some())
        };
        if already {
            return Err(Error::NotAllowed(
                "the device is a member of the space already",
            ));
        }
        if !self.reaches_parent_of(&space, &device).await {
            return Err(Error::NotAllowed(
                "the device does not reach the restricted space's parent",
            ));
        }
        let (event, wraps) = self
            .sign_roster_with(space, vec![change(keys.clone())?])
            .await?;
        // The grant has committed: a welcome that is not kept now is made
        // again when the two devices meet (admission.md, 3.10 Welcomes).
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        if let Some(wrap) = wraps.get(&device) {
            let _ = self.wait_welcome(space, &keys, event, wrap).await;
        }
        #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
        let _ = wraps;
        Ok(event)
    }

    /// Keeps a welcome for the device of `keys` naming `event`, whose
    /// delivery holds `wrap`, until a member connection with the device
    /// hands it over and the device attaches the space, and deposits it in
    /// the device's mailbox at the peers this device is connected to
    /// (admission.md, 3.10 Welcomes).
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) async fn wait_welcome(
        &self,
        space: EventId,
        keys: &DeviceKeys,
        event: EventId,
        wrap: &crate::writer::WrapOf,
    ) -> Result<()> {
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
            approver: self.device_id(),
            peers: self.welcome_hints(&space, &[]).await,
            snapshot: None,
        };
        let sealed = welcome
            .seal_with(keys, &*self.platform().draw::<64>()?)
            .map_err(Error::class)?;
        self.links().wait(crate::links::Waiting {
            recipient: keys.device_id(),
            space,
            event,
            sealed,
            deposited: Vec::new(),
        });
        Ok(())
    }

    /// Makes again the welcome of a device that refused an attach of
    /// `space` on a member connection (admission.md, 3.10 Welcomes, "A
    /// welcome that waits for a member connection"), unless a welcome of it
    /// waits, this device made one again or admitted the device's attach of
    /// the space since it opened, or it keeps a member ticket of the device
    /// for the space. In the transaction that signs it, the roster must
    /// still grant the device as [`welcome_recipient`] says; this device
    /// then signs a delivery of the current state to it and keeps a welcome
    /// naming that delivery. Whether a welcome waits for the device now.
    ///
    /// # Errors
    ///
    /// As [`Engine::deliver`]; the store's.
    #[cfg(feature = "iroh")]
    pub(crate) async fn welcome_again(&self, space: EventId, device: DeviceId) -> Result<bool> {
        if self.links().waits(&device, &space) {
            return Ok(true);
        }
        if self
            .kept_endpoints(&space)
            .await?
            .iter()
            .any(|(member, _)| *member == device)
            || !self.links().may_welcome_again(space, device)
        {
            return Ok(false);
        }
        let made = self.deliver_welcome(space, device).await;
        let Ok(Some((keys, event, wrap))) = made else {
            self.links().not_welcomed_again(&space, &device);
            return made.map(|_| false);
        };
        self.wait_welcome(space, &keys, event, &wrap).await?;
        Ok(true)
    }

    /// Signs a delivery of the current state of `space` to `device`, when
    /// in the signing transaction [`welcome_recipient`] finds it; its keys,
    /// the delivery and the device's wrap in it.
    #[cfg(feature = "iroh")]
    pub(crate) async fn deliver_welcome(
        &self,
        space: EventId,
        device: DeviceId,
    ) -> Result<Option<(DeviceKeys, EventId, crate::writer::WrapOf)>> {
        let mut state = self.lock().await;
        let Some(replica) = state.replicas.get(&space) else {
            return Ok(None);
        };
        let Some(recipient) = welcome_recipient(
            replica,
            &state.replicas,
            &state.lists,
            &self.device_id(),
            &device,
        ) else {
            return Ok(None);
        };
        let keys = recipient.keys.clone();
        self.publish_own_lists(&mut state, space).await?;
        if !state.vault.head().may_sign(&space.0) {
            return Err(Error::SyncBeforeWriting);
        }
        let (event, mut wraps) = self
            .deliver_locked(&mut state, space, vec![recipient])
            .await?;
        Ok(wraps.remove(&device).map(|wrap| (keys, event, wrap)))
    }
}

/// The recipient of a welcome that `me` makes again for `device` in the
/// space of `replica` (admission.md, 3.10 Welcomes, "A welcome that waits
/// for a member connection"), when all of these hold: `me` administers the
/// space; the space reaches the device, which has not forked there, and a
/// restricted space's parent reaches it; and the roster grants it, with
/// history, by a grant `me` signed, either directly with no `session`, or
/// through a person whose list vouches for it.
#[cfg(feature = "iroh")]
fn welcome_recipient(
    replica: &crate::replica::Replica,
    replicas: &std::collections::BTreeMap<EventId, crate::replica::Replica>,
    lists: &std::collections::BTreeMap<[u8; 32], crate::lists::PersonList>,
    me: &DeviceId,
    device: &DeviceId,
) -> Option<Recipient> {
    if replica.level_of(me) != Some(Level::Administer)
        || replica.forked(device)
        || !Engine::reaches_parent(replica, replicas, device)
    {
        return None;
    }
    let level = replica.level_of(device)?;
    let signed = |member: &frasil_space::MemberState| {
        member.history == HistoryMode::WithHistory
            && member.grants.iter().any(|grant| {
                replica
                    .event(*grant)
                    .is_some_and(|event| event.author() == me)
            })
    };
    let roster = replica.roster();
    match roster.state(&MemberRef::device(*device)) {
        Some(member) => member
            .keys
            .as_deref()
            .filter(|_| member.session.is_none() && signed(member))
            .map(|keys| Recipient {
                keys: keys.clone(),
                writes: level >= Level::Write,
                propagates: true,
            }),
        None => roster
            .members_in()
            .filter(|(member, state)| {
                member.kind == frasil_space::MemberType::Person && signed(state)
            })
            .find_map(|(person, member)| {
                crate::device::person_recipients(&person.id, member.level, lists, Some(replica))
                    .into_iter()
                    .find(|recipient| recipient.keys.device_id() == *device)
            }),
    }
}

#[cfg(all(test, feature = "iroh"))]
mod tests {
    //! The welcome a signer makes again (admission.md, 3.10 Welcomes, "A
    //! welcome that waits for a member connection"), on engines alone: who
    //! makes it, for whom, and how often in one run of the device.

    use super::*;
    use crate::advanced::{AdapterRegistry, Platform};

    async fn engine() -> Engine {
        Engine::create(
            Platform::memory(),
            &[7; 32],
            AdapterRegistry::with_builtins(),
        )
        .await
        .expect("a device")
        .0
    }

    /// The events of `space` that `author` signed, in `by`'s replica.
    async fn signed(by: &Engine, space: EventId, author: &Engine) -> usize {
        let author = author.device_id();
        by.read(&space, |replica| {
            replica.log().map_or(0, |log| {
                log.events().filter(|e| *e.author() == author).count()
            })
        })
        .await
        .unwrap()
    }

    async fn carry(from: &Engine, to: &Engine, space: EventId) {
        to.follow(space).await;
        to.ingest(space, from.events(&space).await).await.unwrap();
    }

    /// A space that grants `device` directly at `write`, from `granter`.
    async fn known(granter: &Engine, device: &Engine) -> EventId {
        let known = granter.create_space().await.unwrap();
        granter
            .grant_device(
                known,
                device.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        known
    }

    /// The signer of a grant makes its lost welcome again once in a run,
    /// however often the device refuses the space: not while the welcome
    /// waits, and not after it was made again, even once that welcome no
    /// longer waits. Another administrator never makes it.
    #[tokio::test]
    async fn only_the_signer_makes_a_welcome_again_and_once_in_a_run() {
        let granter = engine().await;
        let other = engine().await;
        let device = engine().await;
        let known = known(&granter, &device).await;
        let space = granter.create_space().await.unwrap();
        granter
            .grant_administrator(
                space,
                other.public_keys().clone(),
                1,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        granter
            .admit_member(space, known, device.device_id(), Level::Write, None)
            .await
            .unwrap();
        carry(&granter, &other, space).await;
        let id = device.device_id();
        let before = signed(&granter, space, &granter).await;

        // The welcome the grant made waits: nothing is signed.
        assert!(granter.links().waits(&id, &space));
        assert!(granter.welcome_again(space, id).await.unwrap());
        assert_eq!(signed(&granter, space, &granter).await, before);

        // It is lost, as at a restart: one delivery, and a welcome waits.
        granter.links().delivered(&id, &space);
        assert!(granter.welcome_again(space, id).await.unwrap());
        assert_eq!(signed(&granter, space, &granter).await, before + 1);
        assert!(granter.links().waits(&id, &space));
        assert!(granter.welcome_again(space, id).await.unwrap());
        assert_eq!(signed(&granter, space, &granter).await, before + 1);

        // Lost again, as when the bound on waiting welcomes passes it: no
        // more in this run.
        granter.links().delivered(&id, &space);
        for _ in 0..3 {
            assert!(!granter.welcome_again(space, id).await.unwrap());
        }
        assert_eq!(signed(&granter, space, &granter).await, before + 1);

        // Another administrator of the space, meeting the same device,
        // signs nothing.
        let theirs = signed(&other, space, &other).await;
        for _ in 0..3 {
            assert!(!other.welcome_again(space, id).await.unwrap());
        }
        assert_eq!(signed(&other, space, &other).await, theirs);
    }

    /// A device whose attach of the space a member connection admitted has
    /// taken the space up: its welcome is not made again in this run.
    #[tokio::test]
    async fn a_device_that_attached_the_space_is_not_welcomed_again() {
        let granter = engine().await;
        let device = engine().await;
        let known = known(&granter, &device).await;
        let space = granter.create_space().await.unwrap();
        granter
            .admit_member(space, known, device.device_id(), Level::Read, None)
            .await
            .unwrap();
        let id = device.device_id();
        let before = signed(&granter, space, &granter).await;
        {
            let mut links = granter.links();
            links.attach(space, Some(id));
            links.delivered(&id, &space);
            links.detach(&space, Some(id));
        }
        assert!(!granter.welcome_again(space, id).await.unwrap());
        assert_eq!(signed(&granter, space, &granter).await, before);
    }

    /// No welcome is made again for a device removed from the space, for a
    /// device granted "from now on", or by a device that does not
    /// administer the space; the signing transaction itself checks the
    /// roster, so a delivery made after a removal finds no recipient.
    #[tokio::test]
    async fn no_welcome_again_for_a_removed_or_from_now_on_device_or_by_a_reader() {
        let granter = engine().await;
        let device = engine().await;
        let later = engine().await;
        let reader = engine().await;
        let known = known(&granter, &device).await;
        let space = granter.create_space().await.unwrap();
        granter
            .admit_member(space, known, device.device_id(), Level::Write, None)
            .await
            .unwrap();
        for (member, history) in [
            (&later, HistoryMode::FromNowOn),
            (&reader, HistoryMode::WithHistory),
        ] {
            granter
                .grant_device(
                    space,
                    member.public_keys().clone(),
                    Level::Read,
                    history,
                    Via::Code,
                )
                .await
                .unwrap();
        }
        granter
            .remove(space, MemberRef::device(device.device_id()))
            .await
            .unwrap();
        let before = signed(&granter, space, &granter).await;
        for member in [&device, &later] {
            let id = member.device_id();
            granter.links().delivered(&id, &space);
            assert!(
                granter.deliver_welcome(space, id).await.unwrap().is_none(),
                "the transaction finds no recipient"
            );
            assert!(!granter.welcome_again(space, id).await.unwrap());
        }
        assert_eq!(signed(&granter, space, &granter).await, before);

        // A reader of the space signs nothing for a member granted by
        // another device.
        carry(&granter, &reader, space).await;
        let id = later.device_id();
        assert!(reader.deliver_welcome(space, id).await.unwrap().is_none());
        assert!(!reader.welcome_again(space, id).await.unwrap());
        assert_eq!(signed(&reader, space, &reader).await, 0);
    }

    /// The welcome of a person's device is made again by the signer of the
    /// person's grant, and by no other administrator.
    #[tokio::test]
    async fn a_persons_device_is_welcomed_again_by_the_persons_granter() {
        let granter = engine().await;
        let other = engine().await;
        let device = engine().await;
        let person = device.make_person(&[3; 32]).await.unwrap().person;
        let space = granter.create_space().await.unwrap();
        granter
            .grant_administrator(
                space,
                other.public_keys().clone(),
                1,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        let list = device.list_events(&person).await;
        for administrator in [&granter, &other] {
            administrator.receive_list(list.clone()).await.unwrap();
        }
        granter
            .grant_person(
                space,
                person,
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        carry(&granter, &other, space).await;
        let id = device.device_id();
        granter.links().delivered(&id, &space);
        let theirs = signed(&other, space, &other).await;
        assert!(!other.welcome_again(space, id).await.unwrap());
        assert_eq!(signed(&other, space, &other).await, theirs);
        let before = signed(&granter, space, &granter).await;
        assert!(granter.welcome_again(space, id).await.unwrap());
        assert_eq!(signed(&granter, space, &granter).await, before + 1);
    }

    /// A guest is never welcomed again: its welcome comes with its session.
    #[cfg(feature = "ext-guests")]
    #[tokio::test]
    async fn a_guest_is_not_welcomed_again() {
        let granter = engine().await;
        let guest = engine().await;
        let space = granter.create_space().await.unwrap();
        granter
            .grant_guest(
                space,
                guest.public_keys().clone(),
                &frasil_space::ext_guests::Preset::new(Level::Write, [5; 16]),
            )
            .await
            .unwrap();
        let before = signed(&granter, space, &granter).await;
        assert!(
            !granter
                .welcome_again(space, guest.device_id())
                .await
                .unwrap()
        );
        assert_eq!(signed(&granter, space, &granter).await, before);
    }
}
