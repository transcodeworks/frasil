//! A space, as an application sees it: its members and its streams.

use super::{Device, MemberId, SpaceId, StreamId};
use crate::error::{Error, Result};
use frasil_space::{Level, MemberRef, MemberType};
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
use frasil_store::store::MaybeSend;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
use std::future::Future;

/// A space this device holds. Clones name the same space.
#[derive(Debug, Clone)]
pub struct Space {
    pub(super) device: Device,
    id: SpaceId,
}

/// What kind of member a space names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MemberKind {
    /// A device.
    Device,
    /// A person, with every device on its device list.
    Person,
    /// Another space, with every member of it.
    Space,
}

/// A member of a space.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Member {
    /// Its ID.
    pub id: MemberId,
    /// What it is.
    pub kind: MemberKind,
    /// What it may do.
    pub level: Level,
    /// The name it was admitted with, if any: shown, never checked.
    pub name: Option<String>,
    /// Its rank, 0 to 255, while it administers: a larger rank outranks a
    /// smaller one (roster.md, 2.3 Changes, "Ranks").
    pub rank: Option<u8>,
    /// Whether it administers marked dormant, as a recovery member is: a
    /// checkpoint does not wait for it.
    pub dormant: bool,
}

/// What kind of stream a stream is: which adapter reads it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum StreamKind {
    /// A Loro document.
    Document,
    /// A Records table set.
    Records,
    /// A set of blobs.
    Blobs,
    /// Another adapter's stream, by its adapter type.
    Other(String),
}

impl StreamKind {
    pub(crate) fn of(adapter_type: &str) -> Self {
        match adapter_type {
            "frasil:loro" => Self::Document,
            "frasil:records" => Self::Records,
            "frasil:blobs" => Self::Blobs,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// A stream of a space.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamInfo {
    /// Its ID.
    pub id: StreamId,
    /// Its kind.
    pub kind: StreamKind,
}

impl Space {
    pub(super) fn new(device: Device, id: SpaceId) -> Self {
        Self { device, id }
    }

    /// The space's ID.
    pub fn id(&self) -> SpaceId {
        self.id
    }

    /// The device the space is held by.
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Whether this device keeps nothing of the space at rest: its grant,
    /// or the offer that admitted it, carries `frasil.nothing-at-rest`, so
    /// the space's keys, events, objects and snapshot stay in memory only
    /// and are forgotten when the session ends, the device is removed, it
    /// leaves, or the application closes the device (ext-guests.md,
    /// "Nothing at rest"). An application keeps no copy of such a space's
    /// content in its own files or caches either.
    pub async fn keeps_nothing_at_rest(&self) -> bool {
        self.device.engine().is_memory_only(&self.id.event()).await
    }

    /// This device's level in the space; `None` once it is no member.
    pub async fn level(&self) -> Option<Level> {
        let me = self.device.engine().device_id();
        self.read(|replica| replica.level_of(&me))
            .await
            .ok()
            .flatten()
    }

    /// A 32-byte key for the application's own data of this space on this
    /// device, as [`Device::derive_key`](super::Device::derive_key) gives,
    /// under the space's log key instead of the device's store secret
    /// (at-rest.md, "Application keys"). It goes with the space: once the
    /// device forgets the space, no call gives it again, and a space held
    /// again later gives another.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an empty purpose; [`Error::UnknownSpace`] once
    /// the device no longer keeps the space.
    pub async fn derive_key(&self, purpose: &str) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        if purpose.is_empty() {
            return Err(Error::Invalid("a key's purpose is not empty"));
        }
        self.device
            .engine()
            .app_key(Some(&self.id.event()), purpose.as_bytes())
            .await
    }

    /// The kind of space the application made it, set when it was created
    /// with [`Device::create_space_of_kind`](super::Device::create_space_of_kind);
    /// `None` for a space created without one. Every member reads it.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`] when the device no longer holds the space.
    pub async fn kind(&self) -> Result<Option<String>> {
        self.read(|replica| replica.application().map(str::to_owned))
            .await
    }

    /// Whether this device writes here only suggestions: it reaches the
    /// space at `write`, and its strongest path carries `suggest`
    /// narrowing, whether through its own grant, its person's or a granted
    /// space's (units.md, "`suggest`"). Its edits then stay suggestions
    /// until a writer accepts them. `false` for a full writer, an
    /// administrator, a reader and a device that is no member.
    pub async fn can_suggest(&self) -> bool {
        let me = self.device.engine().device_id();
        self.read(|replica| {
            replica.level_of(&me) == Some(Level::Write)
                && replica.capabilities_of(&me).is_suggester()
        })
        .await
        .unwrap_or(false)
    }

    /// The members this device is connected to for this space now, over a
    /// member connection: on the local network or through a relay
    /// (transport.md, "The iroh binding"). With no always-on peer, changes
    /// move only while the other side is among them.
    #[cfg(feature = "iroh")]
    pub fn connected_members(&self) -> Vec<MemberId> {
        self.device
            .engine()
            .links()
            .connected(&self.id().event())
            .into_iter()
            .map(MemberId::device)
            .collect()
    }

    /// The space's members as this device's view of it has them.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn members(&self) -> Result<Vec<Member>> {
        self.read(|replica| {
            replica
                .roster()
                .members_in()
                .filter_map(|(member, state)| {
                    let kind = match member.kind {
                        MemberType::Device => MemberKind::Device,
                        MemberType::Person => MemberKind::Person,
                        MemberType::Space => MemberKind::Space,
                        MemberType::Invite => return None,
                    };
                    Some(Member {
                        id: MemberId::from_bytes(member.id),
                        kind,
                        level: state.level,
                        name: state.label.clone(),
                        rank: state.rank,
                        dormant: state.level == Level::Administer
                            && state.capabilities.iter().any(|c| {
                                c.name == frasil_space::checkpoint::DORMANT
                                    && c.mode == frasil_space::CapabilityMode::Extends
                            }),
                    })
                })
                .collect()
        })
        .await
    }

    /// Removes a member. The space rotates its keys, so the member reads
    /// nothing written after; devices still connected heal and cascade by
    /// themselves.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when no member has this ID; [`Error::NotAllowed`]
    /// unless this device administers the space.
    pub async fn remove(&self, member: MemberId) -> Result<()> {
        let found: Option<MemberRef> = self
            .read(|replica| {
                replica
                    .roster()
                    .members_in()
                    .map(|(member, _)| *member)
                    .find(|m| m.id == *member.as_bytes() && m.kind != MemberType::Invite)
            })
            .await?;
        let member = found.ok_or(Error::Invalid("no member of the space has this ID"))?;
        self.device
            .engine()
            .remove(self.id.event(), member)
            .await
            .map(drop)
    }

    /// The space's streams that this device holds a change of.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn streams(&self) -> Result<Vec<StreamInfo>> {
        self.read(|replica| {
            let system = replica.system_stream();
            replica
                .streams()
                .filter(|(id, _)| Some(**id) != system)
                .map(|(id, adapter_type)| StreamInfo {
                    id: StreamId::from_bytes(*id),
                    kind: StreamKind::of(adapter_type),
                })
                .collect()
        })
        .await
    }

    /// Number of locally authored events not yet acknowledged at the same
    /// durability boundary as [`Space::flush`]. This includes roster, key
    /// and storage events as well as data units, not application operations.
    /// An always-on peer's acknowledgement counts; in a space without an
    /// always-on peer, another member's acknowledgement counts instead.
    pub async fn pending_authored_changes(&self) -> u64 {
        self.device.engine().outbox(&self.id.event()).await.len() as u64
    }

    /// Whether every change this device made in the space is durable: an
    /// always-on peer, or the members it must reach, acknowledged it.
    pub async fn is_durable(&self) -> bool {
        self.pending_authored_changes().await == 0
    }

    /// Sends every change this device made in the space that is not yet
    /// durable, and waits until it is, as [`Space::is_durable`] says: for
    /// example after [`Space::set_level`], before the device closes or goes
    /// offline. A change of who administers and its twin in the
    /// administrator skeleton go to each connected peer at once, each on
    /// its own connection (peers.md, "Administration connections").
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when the changes are not durable within 30
    /// seconds, as when no peer is connected: they stay on this device,
    /// which sends them once it reaches a peer. While waiting, it retries
    /// the administration connection once per second.
    pub async fn flush(&self) -> Result<()> {
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        {
            const DURABLE_WITHIN: std::time::Duration = std::time::Duration::from_secs(30);
            const STEP: std::time::Duration = std::time::Duration::from_millis(50);
            #[cfg(feature = "ext-libraries")]
            self.device.send_held_ticket(self.id.event());
            self.device.administer(self.id.event()).await;
            let mut waited = std::time::Duration::ZERO;
            let mut since = std::time::Duration::ZERO;
            while !self.is_durable().await && waited < DURABLE_WITHIN {
                self.device.sleep(STEP).await;
                waited += STEP;
                since += STEP;
                if since >= std::time::Duration::from_secs(1) {
                    since = std::time::Duration::ZERO;
                    self.device.administer(self.id.event()).await;
                }
            }
        }
        if self.is_durable().await {
            Ok(())
        } else {
            Err(Error::Connection(
                "no peer holds this device's changes yet; they stay on this device".into(),
            ))
        }
    }

    /// Waits until every change this device made in the space is durable,
    /// as [`Space::is_durable`] says, for at most `within`, and returns as
    /// soon as it is. Like [`Space::flush`], it drives the administration
    /// connection the space needs itself, a new space's included (peers.md,
    /// "Administration connections"); unlike `flush`, it returns at the
    /// acknowledgement without waiting for that connection to close, which
    /// then finishes on the device's tasks.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when the changes are not durable within
    /// `within`: they stay on this device, which sends them once it
    /// reaches a peer.
    pub async fn wait_durable(&self, within: std::time::Duration) -> Result<()> {
        const STEP: std::time::Duration = std::time::Duration::from_millis(25);
        if self.is_durable().await {
            return Ok(());
        }
        let waiting = async {
            let mut waited = std::time::Duration::ZERO;
            while waited < within {
                let step = STEP.min(within - waited);
                self.device.sleep(step).await;
                waited += step;
                if self.is_durable().await {
                    return true;
                }
            }
            false
        };
        // The administration connection is driven here for the whole wait,
        // its checks of durability included; what is left of it once the
        // wait ends finishes on the device's tasks.
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        let durable = {
            let device = self.device.clone();
            let space = self.id.event();
            // A new space's ticket that a closed connection handed back
            // goes again first: the peer stores nothing of a space it does
            // not host (ext-libraries.md, 3.3 Attaching).
            #[cfg(feature = "ext-libraries")]
            device.send_held_ticket(space);
            let mut administering: Option<frasil_store::BoxFuture<'static, ()>> =
                Some(Box::pin(async move { device.administer(space).await }));
            let durable = drive_beside(&mut administering, waiting).await;
            if let Some(task) = administering {
                self.device.spawn(task);
            }
            durable
        };
        #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
        let durable = waiting.await;
        if durable {
            Ok(())
        } else {
            Err(Error::Connection(
                "no peer holds this device's changes yet; they stay on this device".into(),
            ))
        }
    }

    /// Whether this device may write in the space as far as a restore
    /// goes: `true` unless the device was opened as restored and has not
    /// synced the space since. A device reopened from a store that may have
    /// been restored from a backup, or one opened in restore mode `none`,
    /// signs in a space only once it has fetched its own newest events
    /// there from a peer or a member (at-rest.md, 3.6 "After a restore";
    /// events.md, 3.8 "Restored devices sync before writing"); until then
    /// every write fails with [`Error::SyncBeforeWriting`]. The device's
    /// level is a separate question: see [`Space::level`].
    pub async fn is_write_ready(&self) -> bool {
        self.device.engine().may_sign(&self.id.event()).await
    }

    /// Waits until this device may write in the space, as
    /// [`Space::is_write_ready`] says, for at most `within`, and returns at
    /// once when it already may. The device syncs the space on its own
    /// connections, to a peer or a member, while this waits; once a sync
    /// has caught up, it returns.
    ///
    /// ```ignore
    /// let device = Device::open(storage, unlock_key).await?;
    /// let space = device.space(id).await?;
    /// space.wait_write_ready(Duration::from_secs(30)).await?;
    /// space.document(note).await?.edit(|doc| /* ... */).await?;
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::SyncBeforeWriting`] when the device has not synced the
    /// space within `within`, as when no peer or member that holds it is
    /// reachable: writes there keep failing until it has.
    pub async fn wait_write_ready(&self, within: std::time::Duration) -> Result<()> {
        const STEP: std::time::Duration = std::time::Duration::from_millis(25);
        let mut waited = std::time::Duration::ZERO;
        loop {
            if self.is_write_ready().await {
                return Ok(());
            }
            if waited >= within {
                return Err(Error::SyncBeforeWriting);
            }
            let step = STEP.min(within - waited);
            self.device.sleep(step).await;
            waited += step;
        }
    }

    /// Invites a device into the space at `level`. The invitation's
    /// [`text`](super::Invitation::text) goes to the newcomer, shown as text
    /// or a QR code, and its person enters it in [`Device::join`]. Both
    /// screens then show the same six-digit admission code: `confirm` is
    /// given the code and the newcomer's name, and its future says whether
    /// this device's person saw that code on both, so that an application
    /// can wait for the person's answer. `name` is what the newcomer's
    /// screen shows for this device.
    ///
    /// The newcomer is admitted "from now on": it reads what is written
    /// after its admission, files put before it included only once they
    /// are put again; [`Space::invite_with`] can admit it "with history"
    /// instead. A device hosts one invitation at a time; a new one
    /// replaces the last.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device administers the space;
    /// [`Error::Connection`] when its endpoint does not bind.
    #[cfg(feature = "iroh")]
    pub async fn invite<F>(
        &self,
        level: Level,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
    ) -> Result<super::Invitation>
    where
        F: Future<Output = bool> + MaybeSend + 'static,
    {
        super::invite::invite(self, level, name, confirm).await
    }

    /// [`Space::invite`], admitting the newcomer with `history`:
    /// [`HistoryMode::WithHistory`](crate::HistoryMode::WithHistory) lets
    /// it read what the space held before, its files included, which it
    /// fetches from the members it connects to.
    ///
    /// # Errors
    ///
    /// As [`Space::invite`].
    #[cfg(feature = "iroh")]
    pub async fn invite_with<F>(
        &self,
        level: Level,
        history: frasil_space::HistoryMode,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
    ) -> Result<super::Invitation>
    where
        F: Future<Output = bool> + MaybeSend + 'static,
    {
        super::invite::invite_with(
            self,
            frasil_admission::Offer::new(level, history),
            name,
            confirm,
        )
        .await
    }

    /// Makes an invite link into the space at `level` (`read` or `write`),
    /// open for `lifetime`, 15 minutes to 7 days: whoever opens the link joins
    /// with [`Device::join`](super::Device::join), with no administrator
    /// online. Treat it as a password until it is used: the first device to
    /// claim it is admitted. The link is the URL of a peer this device is
    /// connected to, `#`, and a fragment that carries the secret; an
    /// application may put the fragment after a base URL of its own.
    ///
    /// The claimant is admitted "from now on": it reads what is written
    /// after the invite, and starts from a snapshot of the space that this
    /// device leaves at its peers; [`Space::invite_link_with`] can admit it
    /// "with history" instead. Once it has claimed, this device closes the
    /// invite and deletes its drops, and a writer of the space rotates its
    /// key, so that anyone else who opened the link reads only what was
    /// written while it was open; an invite nobody claims is revoked, with
    /// a rotation, when it expires.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device administers the space and
    /// is connected to a peer, or without a wall clock; [`Error::Invalid`]
    /// for `administer` or a lifetime out of range; [`Error::Connection`]
    /// when no peer keeps the link's drop, or the snapshot.
    #[cfg(all(
        feature = "ext-invite-links",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    ))]
    pub async fn invite_link(&self, level: Level, lifetime: std::time::Duration) -> Result<String> {
        super::link::invite_link(
            self,
            level,
            frasil_space::HistoryMode::FromNowOn,
            crate::Claimant::Device,
            lifetime,
        )
        .await
    }

    /// [`Space::invite_link`], admitting the claimant with `history`:
    /// [`HistoryMode::WithHistory`](crate::HistoryMode::WithHistory) lets
    /// it read what the space held before.
    ///
    /// # Errors
    ///
    /// As [`Space::invite_link`].
    #[cfg(all(
        feature = "ext-invite-links",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    ))]
    pub async fn invite_link_with(
        &self,
        level: Level,
        lifetime: std::time::Duration,
        history: frasil_space::HistoryMode,
    ) -> Result<String> {
        super::link::invite_link(self, level, history, crate::Claimant::Device, lifetime).await
    }

    /// [`Space::invite_link_with`], for `claimant`: with
    /// [`Claimant::Person`](crate::Claimant::Person), the link admits the
    /// person of the device that opens it, with every device on the
    /// person's list, and the claimant hands the person's list to the
    /// space, so that an administering device can change the person's level
    /// or remove the person later. Only a person's device can claim it.
    ///
    /// # Errors
    ///
    /// As [`Space::invite_link`].
    #[cfg(all(
        feature = "ext-invite-links",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    ))]
    pub async fn invite_link_for(
        &self,
        claimant: crate::Claimant,
        level: Level,
        lifetime: std::time::Duration,
        history: frasil_space::HistoryMode,
    ) -> Result<String> {
        super::link::invite_link(self, level, history, claimant, lifetime).await
    }

    /// Revokes an invite link into the space that nobody has claimed yet:
    /// the space removes its invite key and rotates, so a claim of it is
    /// refused from then on (ext-invite-links.md, "Administering
    /// devices"). Once a link this device made is revoked, its drops go
    /// from the peers it is connected to. A link already claimed, closed or
    /// revoked changes nothing.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a text that is no invite link, a link into
    /// another space, or one whose invite this device's view of the space
    /// does not hold; [`Error::NotAllowed`] unless this device administers
    /// the space.
    #[cfg(all(
        feature = "ext-invite-links",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    ))]
    pub async fn revoke_invite_link(&self, link: &str) -> Result<()> {
        super::link::revoke_invite_link(self, link).await
    }

    /// Admits the device whose [`Joining::text`](super::Joining::text) a
    /// newcomer shows, at `level`, through the exchange mailbox at the peer
    /// that text names: the route of a device that cannot take part in
    /// nearby pairing, such as a browser (admission.md, "Without a nearby
    /// connection"). Both screens then show the same six-digit admission
    /// code: `confirm` is given the code and the newcomer's name, and its
    /// future says whether this device's person saw that code on both,
    /// as [`Space::invite`]'s does. `name` is what
    /// the newcomer's screen shows for this device. The newcomer is
    /// admitted "from now on": it reads what is written after its
    /// admission, and starts from a snapshot of the space that this device
    /// leaves at the peer; [`Space::admit_with`] can admit it "with
    /// history" instead.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for `administer`, which
    /// [`Space::admit_administrator`] gives at a rank;
    /// [`Error::NotAllowed`] unless this device administers the space;
    /// the code's classes; `CommitmentMismatch` when the mailbox's Request
    /// is not the one the code names; `Mismatch` when this device's person
    /// did not confirm the code; `Cancelled`, `Expired`;
    /// [`Error::Connection`] when the peer does not answer.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub async fn admit<F>(
        &self,
        code: &str,
        level: Level,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
    ) -> Result<()>
    where
        F: Future<Output = bool> + MaybeSend + 'static,
    {
        super::exchange::admit(
            self,
            code,
            frasil_admission::Offer::new(level, frasil_space::HistoryMode::FromNowOn),
            None,
            name,
            confirm,
        )
        .await
    }

    /// [`Space::admit`], admitting the newcomer with `history`:
    /// [`HistoryMode::WithHistory`](crate::HistoryMode::WithHistory) lets
    /// it read what the space held before, fetched from the peer.
    ///
    /// # Errors
    ///
    /// As [`Space::admit`].
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub async fn admit_with<F>(
        &self,
        code: &str,
        level: Level,
        history: frasil_space::HistoryMode,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
    ) -> Result<()>
    where
        F: Future<Output = bool> + MaybeSend + 'static,
    {
        super::exchange::admit(
            self,
            code,
            frasil_admission::Offer::new(level, history),
            None,
            name,
            confirm,
        )
        .await
    }

    /// [`Space::admit_with`], admitting the newcomer as an administrator at
    /// `rank`, 0 to 255, at most this device's own: a larger rank outranks a
    /// smaller one (roster.md, 2.3 Changes, "Ranks"). [`Space::admit`] and
    /// [`Space::admit_with`] refuse `administer`, which has no default rank.
    ///
    /// # Errors
    ///
    /// `HigherRank` for a rank above this device's own; as [`Space::admit`].
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub async fn admit_administrator<F>(
        &self,
        code: &str,
        rank: u8,
        history: frasil_space::HistoryMode,
        name: &str,
        confirm: impl FnOnce(String, String) -> F + MaybeSend + 'static,
    ) -> Result<()>
    where
        F: Future<Output = bool> + MaybeSend + 'static,
    {
        super::exchange::admit(
            self,
            code,
            frasil_admission::Offer::new(Level::Administer, history),
            Some(rank),
            name,
            confirm,
        )
        .await
    }

    /// Creates a restricted space under this one: a private part of it
    /// (ext-restricted-spaces.md). Only devices that also reach this space
    /// reach the restricted one, whatever its own roster grants: a member
    /// removed here loses it too. Its members join it as any space's do,
    /// by [`invite`](Space::invite) or [`admit`](Space::admit), and only a
    /// device that reaches this space can be admitted; a member of this
    /// space it does not grant reads nothing of it. Restricted spaces do
    /// not nest.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] when this device does not reach this space,
    /// or this space is itself restricted; [`Error::NoRandomness`]; the
    /// store's.
    #[cfg(feature = "ext-restricted-spaces")]
    pub async fn create_restricted(&self) -> Result<Space> {
        let id = self
            .device
            .engine()
            .create_restricted(self.id.event())
            .await?;
        self.device.present(id);
        Ok(Space::new(self.device.clone(), SpaceId::of(id)))
    }

    /// Steps down in a carve-out this device made for a guest
    /// ([`Document::carve_out`](super::Document::carve_out)), once the
    /// guest is admitted: a device that does not administer the space it
    /// carved the document from keeps `write` here, and no more
    /// (ext-restricted-spaces.md, "Creating a carve-out").
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a space that is no carve-out this device
    /// administers; as [`Space::end_session`].
    #[cfg(feature = "ext-restricted-spaces")]
    pub async fn step_down(&self) -> Result<()> {
        self.device
            .engine()
            .step_down_in_carve_out(self.id().event())
            .await
            .map(drop)
    }

    pub(super) async fn read<R>(&self, f: impl FnOnce(&crate::replica::Replica) -> R) -> Result<R> {
        self.device.engine().read(&self.id.event(), f).await
    }
}

/// Runs `main` to its end while polling `task` beside it; `task` becomes
/// `None` once it finishes.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
async fn drive_beside<T>(
    task: &mut Option<frasil_store::BoxFuture<'static, ()>>,
    main: impl std::future::Future<Output = T>,
) -> T {
    let mut main = std::pin::pin!(main);
    std::future::poll_fn(|cx| {
        if let Some(running) = task.as_mut()
            && running.as_mut().poll(cx).is_ready()
        {
            *task = None;
        }
        main.as_mut().poll(cx)
    })
    .await
}
