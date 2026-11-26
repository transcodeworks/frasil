//! People in spaces: the device's person, grants of a person, levels and
//! suggesters (roster.md, "Changes"; identity.md).

use super::{Device, MemberId, Space, SpaceId};
use crate::error::{Error, Result};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, MemberType, Via};

/// A person's ID: the ID of its device list's first event. A space names a
/// person member by it, as [`MemberId`].
pub type PersonId = MemberId;

impl Device {
    /// The person this device is a device of; `None` for a device of no
    /// person.
    pub async fn person(&self) -> Option<PersonId> {
        self.engine().person().await.map(MemberId::from_bytes)
    }

    /// The personal space of this device's person (identity.md, "The
    /// person ID and the personal space"), once the device knows it: it
    /// made the person, recovered into it, or holds the one space that
    /// records a list member's recovery entry of itself, or else the one
    /// space that grants the person and nobody but the person's devices.
    /// `None` for a device of no person, and while the device cannot tell
    /// which space it is.
    pub async fn personal_space(&self) -> Option<SpaceId> {
        let engine = self.engine();
        engine.find_personal_space().await;
        engine.personal_space().await.map(SpaceId::of)
    }

    /// Makes this device the first device of a new person, with a
    /// personal space, and returns the person; returns the person it is
    /// already a device of, if any. Call it on an application's first run:
    /// [`Device::create_space`] then grants the person, with all its
    /// devices. `unlock_key` is the key the device was opened with: the
    /// device's keys are sealed again under it to name the person, and
    /// kept in place of the old ones, by a directory store beside it or
    /// through [`Options::keep_keys`](super::Options::keep_keys) for a
    /// store the application supplies.
    ///
    /// # Errors
    ///
    /// `BadSeal` when `unlock_key` does not open this device's keys; the
    /// store's, and what keeping the keys fails with.
    pub async fn make_person(&self, unlock_key: &[u8; 32]) -> Result<PersonId> {
        let engine = self.engine();
        if let Some(person) = engine.person().await {
            return Ok(MemberId::from_bytes(person));
        }
        self.check_unlock_key(unlock_key)?;
        let made = engine.make_person(unlock_key).await?;
        self.keep_sealed_keys(&made.person, &made.sealed).await?;
        self.present(made.personal_space);
        Ok(MemberId::from_bytes(made.person))
    }

    /// Takes another device off this device's person's device list
    /// (identity.md, "The device-list event"): a `revoke`, which reaches
    /// every space that grants the person, so the device reaches none of
    /// them any more and reads nothing written after. Each such space owes
    /// a cascaded rotation, which this device makes at once when it is
    /// first in line, and until which it writes nothing there. A list revocation
    /// leaves the grants a roster gave the device directly, so this device
    /// also removes it from each space it administers that grants it
    /// directly (identity.md, "A list revocation leaves direct grants").
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for this device itself; [`Error::NotAllowed`] for
    /// a device of no person; `NotInList` for a device not on the list, or
    /// one this device may not revoke; the store's.
    pub async fn remove_device(&self, device: MemberId) -> Result<()> {
        if device == self.id() {
            return Err(Error::Invalid("a device removes another device"));
        }
        let engine = self.engine();
        let device = DeviceId(*device.as_bytes());
        engine.revoke_device(device).await?;
        let me = engine.device_id();
        let member = MemberRef::device(device);
        // Every space the device holds, but a claim that waits for the
        // person's consent, which is presented to no peer.
        for space in engine.presentable_spaces().await {
            // The cascaded rotation, at once when this device's rank delay
            // is nothing; otherwise the upkeep makes it, or another device.
            let _ = engine.maintain(space).await;
            let direct = engine
                .read(&space, |replica| {
                    replica.roster().is_in(&member)
                        && replica.level_of(&me) == Some(Level::Administer)
                })
                .await
                .unwrap_or(false);
            if direct {
                engine.remove(space, member).await?;
            }
            self.present(space);
        }
        Ok(())
    }

    /// Fails with `BadSeal` when `unlock_key` does not open the keys a
    /// directory store keeps: keys sealed again under another key would
    /// not open at the next start.
    #[cfg_attr(not(feature = "sqlite"), allow(clippy::unused_self))]
    pub(super) fn check_unlock_key(&self, unlock_key: &[u8; 32]) -> Result<()> {
        #[cfg(feature = "sqlite")]
        if let Some(path) = &self.inner.directory {
            let sealed = std::fs::read(path.join(super::KEYS_FILE))
                .map_err(|error| Error::Store(format!("{}: {error}", path.display())))?;
            frasil_store::device_keys::open_device_keys(
                &sealed,
                frasil_store::device_keys::KeyKind::UnlockKey,
                unlock_key,
                &[0; 32],
                None,
            )
            .map_err(|_| Error::Class("BadSeal"))?;
        }
        #[cfg(not(feature = "sqlite"))]
        let _ = unlock_key;
        Ok(())
    }

    /// Keeps the device's keys, sealed again to name `person`, in place of
    /// the old ones: beside a directory store, and through
    /// [`Options::keep_keys`](super::Options::keep_keys).
    #[cfg_attr(not(feature = "sqlite"), allow(unused_variables))]
    pub(super) async fn keep_sealed_keys(&self, person: &[u8; 32], sealed: &[u8]) -> Result<()> {
        #[cfg(feature = "sqlite")]
        if let Some(path) = &self.inner.directory {
            super::keep_person(path, person, sealed)?;
        }
        if let Some(keep) = &self.inner.keep_keys {
            keep.keep(sealed).await?;
        }
        Ok(())
    }

    /// Grants this device's person, with every device on its list, `write`
    /// with history in a space this device has just created (identity.md,
    /// "Making a person"), and publishes the list there. Nothing for a
    /// device of no person.
    pub(super) async fn grant_own_person(&self, space: EventId) -> Result<()> {
        let engine = self.engine();
        let Some(person) = engine.person().await else {
            return Ok(());
        };
        engine
            .grant_person(
                space,
                person,
                Level::Write,
                HistoryMode::WithHistory,
                Via::None,
            )
            .await?;
        engine.publish_list(space, &person).await.map(drop)
    }
}

impl Space {
    /// Grants a person, with every device on its list, at `level` (`read`
    /// or `write`), with history: its devices read what the space held
    /// before. The device must hold the person's list, as an admission
    /// leaves it. The grant is made offline; each of the person's devices
    /// is sent a welcome over a member connection, and in its device
    /// mailbox at this device's peers once they hold the grant, where a
    /// device connected only through a peer collects it
    /// ([`Device::receive_welcomes_via_peer`]).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for `administer`, which only a device holds;
    /// [`Error::NotAllowed`] unless this device administers the space, or
    /// when it holds no list of the person.
    pub async fn grant_person(&self, person: PersonId, level: Level) -> Result<()> {
        if level == Level::Administer {
            return Err(Error::Invalid("a person is granted read or write"));
        }
        let engine = self.device.engine();
        let space = self.id().event();
        engine
            .grant_person(
                space,
                *person.as_bytes(),
                level,
                HistoryMode::WithHistory,
                Via::None,
            )
            .await?;
        engine.publish_list(space, person.as_bytes()).await?;
        // The person's devices' welcomes, at this device's peers once they
        // hold the grant (admission.md, 3.10 Welcomes); the upkeep deposits
        // what this does not.
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        {
            let space = self.clone();
            self.device.spawn(Box::pin(async move {
                if space
                    .wait_durable(std::time::Duration::from_secs(30))
                    .await
                    .is_ok()
                {
                    super::person_grants::deposit_welcomes(&space.device).await;
                }
            }));
        }
        Ok(())
    }

    /// Admits a device that `known_space` grants directly to this space at
    /// `level` (`read` or `write`), by its device ID `member`, with no code
    /// and no peer (admission.md, 3.16 A member of another space). The
    /// grant carries the keys that `known_space`'s roster names, which the
    /// ID commits to, is made with history, and records `via` = `none`. It
    /// commits at once, offline, and the call returns once it has, whatever
    /// becomes of the welcome. The device's welcome is sealed to its keys,
    /// kept at rest in the grant's own commit, and handed over the next
    /// member connection with it, such as the one the two devices hold for
    /// `known_space`, before or after this device restarts. It goes to the
    /// device's mailbox at this device's peers too, as
    /// [`Space::grant_person`]'s welcomes do, again every 48 hours while
    /// it waits, since a peer keeps a mailbox item only a while, unless the
    /// space no longer reaches the device. It waits at most 30 days, and
    /// among the newest
    /// 256 welcomes this device keeps; a device that has not taken the
    /// space up by then is removed and admitted again. The device follows
    /// the space as it follows a person grant's.
    ///
    /// The grant rests only on `known_space`'s roster: any administrator of
    /// that space could have put the device there, and a removal from it
    /// does not reach this grant. Select `member` from `known_space`'s
    /// [`Space::members`], never by a display name.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for `administer`, which
    /// [`Space::admit_member_administrator`] gives at a rank;
    /// [`Error::UnknownSpace`] when this device does not hold `known_space`;
    /// [`Error::NotAllowed`] unless this device administers the space, when
    /// `known_space` does not reach this device, when it does not grant the
    /// device directly (it grants no such device, or only through a
    /// person), when the device is a guest there, when its grant there has
    /// no effect or the device forked there, when this space reaches the
    /// device already, and when it is restricted and its parent does not
    /// reach the device.
    pub async fn admit_member(
        &self,
        known_space: SpaceId,
        member: MemberId,
        level: Level,
    ) -> Result<()> {
        if level == Level::Administer {
            return Err(Error::Invalid(
                "an administrator is admitted at a rank: Space::admit_member_administrator",
            ));
        }
        self.admit_member_at(known_space, member, level, None).await
    }

    /// [`Space::admit_member`], admitting the device as an administrator at
    /// `rank`, 0 to 255, at most this device's own: a larger rank outranks a
    /// smaller one (roster.md, 2.3 Changes, "Ranks").
    ///
    /// # Errors
    ///
    /// `HigherRank` for a rank above this device's own; as
    /// [`Space::admit_member`].
    pub async fn admit_member_administrator(
        &self,
        known_space: SpaceId,
        member: MemberId,
        rank: u8,
    ) -> Result<()> {
        self.admit_member_at(known_space, member, Level::Administer, Some(rank))
            .await
    }

    async fn admit_member_at(
        &self,
        known_space: SpaceId,
        member: MemberId,
        level: Level,
        rank: Option<u8>,
    ) -> Result<()> {
        self.device
            .engine()
            .admit_member(
                self.id().event(),
                known_space.event(),
                DeviceId(*member.as_bytes()),
                level,
                rank,
            )
            .await?;
        // The welcome, at this device's peers once they hold the grant
        // (admission.md, 3.10 Welcomes); the upkeep deposits what this does
        // not.
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        {
            let space = self.clone();
            self.device.spawn(Box::pin(async move {
                if space
                    .wait_durable(std::time::Duration::from_secs(30))
                    .await
                    .is_ok()
                {
                    super::person_grants::deposit_welcomes(&space.device).await;
                }
            }));
        }
        Ok(())
    }

    /// Changes a member's level. A demotion to `read` rotates the space's
    /// keys, so the member writes nothing new; a raise hands the member's
    /// devices what they need to write. The change goes to the space's
    /// peers at once; [`Space::flush`] waits until one holds it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when no member has this ID, or for `administer`,
    /// which [`Space::raise`] gives at a rank;
    /// [`Error::NotAllowed`] unless this device administers the space;
    /// `AdministerNotDevice` for `administer` on a person or a space.
    pub async fn set_level(&self, member: MemberId, level: Level) -> Result<()> {
        let member = self.member_ref(member).await?;
        self.device
            .engine()
            .set_level(self.id().event(), member, level)
            .await
            .map(drop)
    }

    /// Raises a device member to `administer` at `rank`, 0 to 255: a larger
    /// rank outranks a smaller one, and nobody changes or removes an
    /// administrator of a higher rank, nor grants a rank above its own
    /// (roster.md, 2.3 Changes, "Ranks"). The space's creator holds 255.
    ///
    /// # Errors
    ///
    /// `HigherRank` for a rank above this device's own; `RankInPlace` for
    /// a member that administers already ([`Space::set_rank`]); as
    /// [`Space::set_level`].
    pub async fn raise(&self, member: MemberId, rank: u8) -> Result<()> {
        let member = self.member_ref(member).await?;
        self.device
            .engine()
            .raise(self.id().event(), member, rank)
            .await
            .map(drop)
    }

    /// Changes an administrator's rank, or makes a device member an
    /// administrator at `rank`. A rank never changes in place, so for an
    /// administrator this signs two changes: a lowering to `write`, then a
    /// raise at `rank`.
    ///
    /// # Errors
    ///
    /// `HigherRank` for a member or a rank above this device's own; as
    /// [`Space::raise`].
    pub async fn set_rank(&self, member: MemberId, rank: u8) -> Result<()> {
        let member = self.member_ref(member).await?;
        self.device
            .engine()
            .set_rank(self.id().event(), member, rank)
            .await
            .map(drop)
    }

    /// Makes a device member the space's recovery member: an administrator
    /// at the top rank marked `frasil.dormant`, so that checkpoints do not
    /// wait for it and it can excuse and remove any member, a lost top-rank
    /// device among them. Keep its device somewhere safe. Only a device at
    /// the top rank makes one.
    ///
    /// # Errors
    ///
    /// `HigherRank` unless this device holds the top rank; as
    /// [`Space::raise`].
    pub async fn make_recovery_member(&self, member: MemberId) -> Result<()> {
        let member = self.member_ref(member).await?;
        self.device
            .engine()
            .make_recovery_member(self.id().event(), member)
            .await
            .map(drop)
    }

    /// Marks an administrator dormant, or no longer: a checkpoint does not
    /// wait for a dormant administrator. Only a member of its rank or higher
    /// marks or unmarks it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a member that does not administer;
    /// `HigherRank` for one of a higher rank; as [`Space::set_level`].
    pub async fn set_dormant(&self, member: MemberId, dormant: bool) -> Result<()> {
        let member = self.member_ref(member).await?;
        self.device
            .engine()
            .set_dormant(self.id().event(), member, dormant)
            .await
            .map(drop)
    }

    /// The space's recovery members: administrators marked dormant.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn recovery_members(&self) -> Result<Vec<MemberId>> {
        Ok(self
            .device
            .engine()
            .recovery_members(&self.id().event())
            .await?
            .into_iter()
            .map(|device| MemberId::from_bytes(device.0))
            .collect())
    }

    /// A member's rank, while it administers.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when no member has this ID.
    pub async fn rank(&self, member: MemberId) -> Result<Option<u8>> {
        let member = self.member_ref(member).await?;
        self.read(|replica| replica.roster().state(&member).and_then(|state| state.rank))
            .await
    }

    /// This device's rank, while it administers.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn my_rank(&self) -> Result<Option<u8>> {
        Ok(self.device.engine().my_rank(&self.id().event()).await)
    }

    /// Makes a writer a suggester, whose edits stay suggestions until a
    /// writer accepts them, or a full writer again.
    ///
    /// # Errors
    ///
    /// As [`Space::set_level`].
    pub async fn set_suggester(&self, member: MemberId, suggester: bool) -> Result<()> {
        let member = self.member_ref(member).await?;
        self.device
            .engine()
            .set_suggester(self.id().event(), member, suggester)
            .await
            .map(drop)
    }

    /// The member this ID names in the space's roster.
    pub(super) async fn member_ref(&self, member: MemberId) -> Result<MemberRef> {
        self.read(|replica| {
            replica
                .roster()
                .members_in()
                .map(|(member, _)| *member)
                .find(|m| m.id == *member.as_bytes() && m.kind != MemberType::Invite)
        })
        .await?
        .ok_or(Error::Invalid("no member of the space has this ID"))
    }
}
