//! Invite links through the engine (ext-invite-links.md, feature
//! `ext-invite-links`).
//!
//! - **The inviter** ([`Engine::make_invite`]) draws the secret, grants the
//!   invite key `K` with `expires_at`, and keeps the secret, the invite
//!   entry and its `invite` record in one commit; it seals the drop that
//!   the client places at peers, and gives the link's fragment ("Making an
//!   invite and keeping drops").
//! - **The claimant** ([`Engine::begin_claim`], [`Engine::claim_status`],
//!   [`Engine::claim`]) reads the fragment, opens the drop and its wrap,
//!   presents the state the wrap names until the space's log arrives, takes
//!   `K`'s keys from the invite entry's delivery, checks the entry and the
//!   invite, and signs the successor as `K` at `seq` 1, with its `claim`
//!   record in the same commit ("Claiming").
//! - **Administering devices** ([`Engine::maintain_invites`]) close an
//!   invite once they hold a valid successor of it, and revoke one that
//!   expired or whose claims raced, each after its delay; the inviter's
//!   client closes its own at once ("Administering devices"). A claim puts
//!   `K` outside, holding the state the invite delivered, so any writer
//!   heals after its rank delay, through the device's upkeep ("Keys").
//!   [`Engine::spent_invites`] names the drops the client then deletes.
//!
//! The client asks for a link at the application's root, `Space::invite_link`,
//! and claims one through `Device::join`.

use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::replica::{InviteMe, Replica};
use crate::writer::{self, Recipient, Sealing, SpaceEventPlan};
use frasil_admission::ext_invite_links::{
    DropPlain, InviteKeys, Link, check_invite_entry, drop_address, invite_drop, link_fragment,
    open_drop, open_drop_wrap, read_fragment, seal_drop_with,
};
use frasil_base::time::{Reading, lower};
use frasil_crypto::device::DeviceId;
use frasil_events::{EventId, Log};
use frasil_keys::bundle::Bundle;
use frasil_keys::derive::Secret;
use frasil_keys::{KeyName, RotationSet};
use frasil_space::change::Op;
use frasil_space::ext_invite_links::{
    CLAIMS_DEVICE, CLAIMS_PERSON, InviteExpiry, LINK_LIFETIME_MAX, LINK_LIFETIME_MIN, act_delay,
    check_claim_expiry, invite_expiry, invite_grant, invite_member, is_successor, revoke_invite,
    successor,
};
use frasil_space::{HistoryMode, Level, MemberRef, MemberType, Space, Status};
use frasil_store::ext_invite_links::{claim_record, invite_record};
use frasil_store::{Table, TableValue};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// A drop outlives its lifetime at a peer by this many seconds of the
/// peer's timeline (ext-invite-links.md, "Making an invite and keeping
/// drops").
const DROP_GRACE: u64 = 60;

/// Who claims an invite link: the invite grant's `claims`
/// (ext-invite-links.md, 2.2 The invite grant and the successor).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Claimant {
    /// A device claims it: the device that opens the link is admitted, and
    /// it alone.
    #[default]
    Device,
    /// A person claims it: the person of the device that opens the link is
    /// admitted, with every device on its list.
    Person,
}

/// What a replica reads of one invite key of its roster.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InviteFacts {
    /// The invite entry: its first valid grant, in canonical order.
    pub entry: Option<EventId>,
    /// The entry's `expires_at`.
    pub expires_at: Option<u64>,
    /// The entry's level.
    pub level: Option<Level>,
    /// The entry's `claims`: who may claim it.
    pub claims: Option<u64>,
    /// Its valid successors, in canonical order.
    pub successors: Vec<EventId>,
    /// Whether a valid removal of `[3, K]` holds: a close or a revocation.
    pub removed: bool,
    /// Whether its claims raced: `K`'s chain forked, or a successor of it
    /// is void as `ClaimRaced`.
    pub raced: bool,
}

/// Each invite key a resolved space names, with its facts.
pub(crate) fn facts(space: &Space<'_>, log: &Log) -> BTreeMap<[u8; 32], InviteFacts> {
    let mut out: BTreeMap<[u8; 32], InviteFacts> = BTreeMap::new();
    for id in log.canonical_in(space.view()) {
        if !space.is_roster(id) {
            continue;
        }
        let Some(opened) = space.opened(id) else {
            continue;
        };
        let changes = opened.changes();
        let valid = space.status(id).is_some_and(Status::is_valid);
        if is_successor(changes) {
            let Some(event) = log.event(id) else {
                continue;
            };
            let facts = out.entry(event.author().0).or_default();
            match space.status(id) {
                Some(Status::Valid(_)) => facts.successors.push(id),
                Some(Status::Void { class, .. })
                    if frasil_base::errors::Class::name(*class) == "ClaimRaced" =>
                {
                    facts.raced = true;
                }
                _ => {}
            }
            continue;
        }
        if !valid {
            continue;
        }
        for change in changes {
            let Some(member) = change.member.filter(|m| m.kind == MemberType::Invite) else {
                continue;
            };
            let facts = out.entry(member.id).or_default();
            match change.op {
                Op::Grant if facts.entry.is_none() => {
                    facts.entry = Some(id);
                    facts.expires_at = change.expires_at;
                    facts.level = change.level;
                    facts.claims = change.claims;
                }
                Op::Remove => facts.removed = true,
                _ => {}
            }
        }
    }
    for (key, facts) in &mut out {
        facts.raced |= space.forks().fork_point(&DeviceId(*key)).is_some();
    }
    out
}

/// An invite this device made, or a claim it signed: its `invite` or
/// `claim` record (ext-invite-links.md, "Records at rest").
#[derive(Clone)]
pub(crate) struct Kept {
    /// The space.
    pub space: EventId,
    /// The secret.
    pub secret: Secret,
    /// `K`.
    pub key: [u8; 32],
    /// `K`'s X-Wing seed, whose wraps a claimant opens.
    pub xwing_seed: Secret,
}

impl Kept {
    fn new(space: EventId, secret: [u8; 32]) -> Self {
        let keys = InviteKeys::derive(&secret);
        Self {
            space,
            secret: Zeroizing::new(secret),
            key: keys.device_id().0,
            xwing_seed: keys.xwing_seed.clone(),
        }
    }
}

/// A claim this device is making, before it signs the successor.
pub(crate) struct Claiming {
    /// The invite entry.
    pub entry: EventId,
    /// The secret.
    pub secret: Secret,
    /// `K`'s keys.
    pub keys: InviteKeys,
    /// The drop, opened.
    pub plain: DropPlain,
    /// The bundle its wrap holds.
    pub bundle: Bundle,
    /// Whether the claim fetches the invite entry and the space from
    /// peers, which its connections present the space for with the fetch
    /// key ("Claiming", step 4); a claim from a space file holds them
    /// already, and is presented to no peer until it is signed.
    pub fetches: bool,
}

/// What the device keeps of invite links.
#[derive(Default)]
pub(crate) struct Invites {
    /// Invites this device made, by invite entry.
    pub made: BTreeMap<EventId, Kept>,
    /// Claims this device signed, by invite entry.
    pub claimed: BTreeMap<EventId, Kept>,
    /// Claims in progress, by space.
    pub claiming: BTreeMap<EventId, Claiming>,
    /// Where the drop of each invite made since the device opened is kept:
    /// the URLs of the peers that accepted it, none for an invite in a
    /// space file. Not kept at rest: an invite made before is deleted at
    /// every peer.
    pub drops: BTreeMap<EventId, Vec<String>>,
}

impl Invites {
    /// The invite keys whose wraps the device opens: those it claims
    /// with, and those it claimed, whose wraps keep coming from rotations
    /// signed before their authors held the successor ("Keys", receipt).
    pub fn me(&self) -> Vec<InviteMe> {
        let claiming = self.claiming.values().map(|claim| InviteMe {
            device: claim.keys.device_id(),
            xwing_seed: claim.keys.xwing_seed.clone(),
            entry: claim.entry,
        });
        let claimed = self.claimed.iter().map(|(entry, kept)| InviteMe {
            device: DeviceId(kept.key),
            xwing_seed: kept.xwing_seed.clone(),
            entry: *entry,
        });
        claiming.chain(claimed).collect()
    }

    /// Takes an `invite` or `claim` record read at rest.
    pub fn keep(&mut self, value: &TableValue) {
        match value {
            TableValue::Invite(record) => {
                self.made.insert(
                    EventId(record.invite_entry),
                    Kept::new(EventId(record.space), *record.secret.expose()),
                );
            }
            TableValue::Claim(record) => {
                self.claimed.insert(
                    EventId(record.invite_entry),
                    Kept::new(EventId(record.space), *record.secret.expose()),
                );
            }
            _ => {}
        }
    }
}

/// An invite link made: what the client places at peers and shows.
#[derive(Debug, Clone)]
pub struct MadeInvite {
    /// The space.
    pub space: EventId,
    /// The invite entry.
    pub entry: EventId,
    /// `K`.
    pub key: [u8; 32],
    /// The drop's address, mailbox kind 4.
    pub address: [u8; 32],
    /// The sealed drop.
    pub drop: Vec<u8>,
    /// The drop's lifetime at a peer, in seconds: `expires_at` less the
    /// inviter's wall clock.
    pub lifetime: u64,
    /// The link's fragment, which follows `#` in the link.
    pub fragment: String,
    /// For an invite "from now on", the unit that keeps the snapshot for
    /// `K` at peers: the client places the drop once a peer holds it.
    pub snapshot_unit: Option<EventId>,
}

/// What a claimant shows its person before it claims ("Claiming", step
/// 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimOffer {
    /// The space.
    pub space: EventId,
    /// The inviting device, by device ID: the invite entry's author.
    pub inviter: DeviceId,
    /// The level the claim gives.
    pub level: Level,
    /// The invite's `expires_at`.
    pub expires_at: u64,
}

/// Where a claim stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimStatus {
    /// The device still fetches the invite entry, or the space's events
    /// before it.
    Waiting,
    /// The checks passed: the device may sign the successor once its
    /// person consents.
    Ready(ClaimOffer),
    /// The successor is signed.
    Claimed(EventId),
}

/// An invite this device made whose key is removed: its drops are deleted
/// at the peers, then its record goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentInvite {
    /// The space.
    pub space: EventId,
    /// The invite entry.
    pub entry: EventId,
    /// The drop's address.
    pub address: [u8; 32],
    /// Whether every drop has expired at the peers, deleted or not.
    pub expired: bool,
    /// The peers that kept its drop, by URL, when the device made the
    /// invite since it opened: none for an invite in a space file.
    /// `None` for an invite made before, whose drops may be at any peer.
    pub kept_at: Option<Vec<String>>,
    /// The state the drop names, which it was placed under: a peer
    /// deletes it only on a connection that proved that state's upload
    /// key, and the heal after a claim moves the device's connections on.
    pub under: Option<RotationSet>,
}

/// The state the drop of the invite `entry` names, made from the entry
/// and the secret as the inviter made it.
fn drop_state(replica: &Replica, entry: EventId, secret: &[u8; 32]) -> Option<RotationSet> {
    let event = replica.event(entry)?;
    let plain = invite_drop(event, &InviteKeys::derive(secret), Vec::new()).ok()?;
    named_state(&plain, entry)
}

/// The state a drop's key name names: a self reference names the invite
/// entry's own rotation.
fn named_state(plain: &DropPlain, entry: EventId) -> Option<RotationSet> {
    match KeyName::read(&plain.key_name, true) {
        Ok((KeyName::Set(set), [])) => Some(set),
        Ok((KeyName::SelfRef(_), [])) => Some(RotationSet::single(entry)),
        _ => None,
    }
}

/// The state the invite `entry` delivered to `K`, with the seed of its
/// upload key, from `K`'s bundle in the entry's delivery, which holds the
/// upload seed whatever the invite's level (ext-invite-links.md, "Keys",
/// receipt).
#[cfg_attr(
    not(any(feature = "server", feature = "iroh", feature = "server-socket")),
    allow(dead_code)
)]
fn invite_upload(
    replica: &Replica,
    space: EventId,
    entry: EventId,
    secret: &[u8; 32],
) -> Option<(RotationSet, [u8; 32])> {
    let keys = InviteKeys::derive(secret);
    let plain = invite_drop(replica.event(entry)?, &keys, Vec::new()).ok()?;
    let state = named_state(&plain, entry)?;
    let bundle = open_drop_wrap(&plain, &space, &keys).ok()?;
    let seed = Zeroizing::new(*bundle.upload()?);
    Some((state, *frasil_keys::derive::upload_key(&seed).seed))
}

/// The successor `K` signed in a space, if the replica holds one.
fn successor_of(replica: &Replica, key: &[u8; 32]) -> Option<EventId> {
    let log = replica.log()?;
    log.canonical().into_iter().find(|id| {
        log.event(*id)
            .is_some_and(|event| event.author().0 == *key && replica.is_roster(id))
    })
}

impl Engine {
    /// Makes an invite link into `space` at `level` (`read` or `write`),
    /// with `history`, for a device to claim, open `lifetime` seconds: the
    /// invite grant, its `invite` record and the secret in one commit, then
    /// the drop sealed with `hints`, the peers' URLs
    /// (ext-invite-links.md, "Making an invite and keeping drops"). An
    /// invite "from now on" rotates with a break, and publishes the
    /// snapshot for `K` under the state `K` receives, which the drop names
    /// (admission.md, "The newcomer's snapshot").
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device administers the space and
    /// knows its wall clock; [`Error::Invalid`] for a lifetime under 15
    /// minutes or above 7 days (overview.md, "Every timer",
    /// `link_lifetime`), or `administer`; as [`Engine::sign_roster`].
    pub async fn make_invite(
        &self,
        space: EventId,
        level: Level,
        history: HistoryMode,
        claimant: Claimant,
        lifetime: u64,
        hints: Vec<String>,
    ) -> Result<MadeInvite> {
        if level == Level::Administer {
            return Err(Error::Invalid("an invite link grants read or write"));
        }
        if !(LINK_LIFETIME_MIN..=LINK_LIFETIME_MAX).contains(&lifetime) {
            return Err(Error::Invalid(
                "an invite link's lifetime is 15 minutes to 7 days",
            ));
        }
        let platform = self.platform();
        let wall = platform.clock.wall().ok_or(Error::NotAllowed(
            "an invite link needs the inviter's wall clock",
        ))?;
        let secret = platform.draw::<32>()?;
        let keys = InviteKeys::derive(&secret);
        let key = keys.device_id().0;
        let expires_at = wall.saturating_add(lifetime);
        let change = invite_grant(
            key,
            keys.device_keys(),
            level,
            history,
            expires_at,
            match claimant {
                Claimant::Device => CLAIMS_DEVICE,
                Claimant::Person => CLAIMS_PERSON,
            },
        );
        let record_secret = *secret;
        let (entry, _) = self
            .sign_roster_keeping(space, vec![change], move |entry, _| {
                Ok(vec![(
                    Table::Invite,
                    entry.0.to_vec(),
                    invite_record(space.0, entry.0, record_secret),
                )])
            })
            .await?;
        {
            let mut state = self.lock().await;
            state
                .invites
                .made
                .insert(entry, Kept::new(space, record_secret));
        }
        let event = self
            .read(&space, |replica| replica.event(entry).cloned())
            .await?
            .ok_or(Error::UnknownSpace)?;
        let mut hints = hints;
        hints.retain(|hint| (1..=512).contains(&hint.len()));
        hints.truncate(8);
        let mut plain = invite_drop(&event, &keys, hints).map_err(Error::class)?;
        let mut snapshot_unit = None;
        if history == HistoryMode::FromNowOn {
            let made = self.newcomer_snapshot(&space, entry).await?;
            let (locator, unit) = self.publish_newcomer_snapshot(&space, entry, &made).await?;
            plain.snapshot = Some(locator);
            snapshot_unit = Some(unit);
        }
        let nonce = platform.nonce::<24>()?;
        let drop = seal_drop_with(&secret, &plain.encode(), &nonce);
        Ok(MadeInvite {
            space,
            entry,
            key,
            address: drop_address(&secret),
            drop,
            lifetime,
            fragment: link_fragment(&secret, &entry, &space),
            snapshot_unit,
        })
    }

    /// Begins a claim ("Claiming", steps 1 to 3): reads the link's
    /// fragment, opens the drop fetched from a peer and its wrap, and
    /// follows the space, presenting the state the wrap names until the
    /// space's log arrives (step 4). Returns the space.
    ///
    /// # Errors
    ///
    /// The fragment's and the drop's classes; `NoWrap`.
    pub async fn begin_claim(&self, fragment: &str, drop: &[u8]) -> Result<EventId> {
        let link = read_fragment(fragment).map_err(Error::class)?;
        let plain = open_drop(&link.secret, drop).map_err(Error::class)?;
        self.begin_claim_with(&link, &plain, true).await
    }

    /// [`Engine::begin_claim`] with the drop's plaintext in hand: a space
    /// file carries `K`'s wrap in the invite entry's delivery instead of a
    /// drop (ext-space-files.md, "The claim from a file"). `fetches` says
    /// whether the claim fetches the space from peers, which present it
    /// with the fetch key meanwhile; a claim from a file does not, and
    /// peers hear of the space only once it is signed.
    ///
    /// # Errors
    ///
    /// `NoWrap`; the store's.
    pub async fn begin_claim_with(
        &self,
        link: &Link,
        plain: &DropPlain,
        fetches: bool,
    ) -> Result<EventId> {
        let (secret, entry, space) = (link.secret.clone(), link.entry, link.space);
        let keys = InviteKeys::derive(&secret);
        let bundle = open_drop_wrap(plain, &space, &keys).map_err(Error::class)?;
        let named = named_state(plain, entry).ok_or(Error::Class("NoWrap"))?;
        let content = *bundle.content().ok_or(Error::Class("NoWrap"))?;
        let held = bundle.clone();
        let plain = plain.clone();
        let mut state = self.lock().await;
        if state.invites.claimed.contains_key(&entry) {
            return Ok(space);
        }
        // A space the device holds already: a member needs no claim, and
        // its log is never marked as a claim's; a reader by keys may claim
        // the grant, and keeps its log either way.
        let held_before =
            state.replicas.contains_key(&space) && !state.invites.claiming.contains_key(&space);
        if held_before
            && state
                .replicas
                .get(&space)
                .is_some_and(|replica| replica.level_of(&self.device_id()).is_some())
        {
            return Err(Error::NotAllowed(
                "the device holds the space as a member already",
            ));
        }
        let replica = state
            .replicas
            .entry(space)
            .or_insert_with(|| Replica::new(space));
        replica.keep_bootstrap_state(named, Zeroizing::new(content));
        // An invite "from now on": the snapshot for K comes first
        // ("Claiming", step 4).
        if let Some(snapshot) = plain.snapshot {
            replica.await_snapshot(snapshot);
        }
        state.outboxes.entry(space).or_default();
        state.invites.claiming.insert(
            space,
            Claiming {
                entry,
                secret,
                keys,
                plain,
                bundle: held,
                fetches,
            },
        );
        // The log, with the claim in its `state` ("Records at rest"), so
        // that a device stopped before the person decides forgets it at
        // load; a log held before the claim is left as it is.
        if held_before {
            return Ok(space);
        }
        let mut batch = crate::at_rest::Batch::default();
        if !state.vault.has_log(&space.0) {
            state
                .vault
                .add_log(&mut batch, &space.0, frasil_store::tables::LogKind::Space)?;
        }
        let mut log_state = crate::device::log_state(&state.vault, &space.0).await?;
        log_state.claiming = Some(entry.0);
        state.vault.put(
            &mut batch,
            &space.0,
            Table::State,
            &[],
            &TableValue::State(log_state),
        )?;
        state.vault.commit(batch).await?;
        Ok(space)
    }

    /// The spaces where a claim waits for the person's consent or for the
    /// invite entry: begun, not signed. A device lists none of them as its
    /// spaces until the claim is signed.
    pub async fn pending_claims(&self) -> Vec<EventId> {
        self.lock().await.invites.claiming.keys().copied().collect()
    }

    /// Where a claim in `space` stands ("Claiming", steps 5 to 10).
    ///
    /// # Errors
    ///
    /// `WrongInvite`, `NotInRoster`, `InviteUsed`, `InviteRevoked`,
    /// `InviteRaced`, `Expired`; [`Error::UnknownSpace`] when no claim is
    /// made there.
    pub async fn claim_status(&self, space: &EventId) -> Result<ClaimStatus> {
        let state = self.lock().await;
        let wall = self.platform().clock.wall();
        claim_status(&state, space, wall)
    }

    /// Drops a claim this device's person declined, and the space with it.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn abandon_claim(&self, space: &EventId) -> Result<()> {
        let removed = self.lock().await.invites.claiming.remove(space).is_some();
        if removed {
            self.forget_space(space).await?;
        }
        Ok(())
    }

    /// Signs the successor as `K`, at `seq` 1 on heads whose state it
    /// holds, granting this device; its delivery wraps the newest state `K`
    /// holds for this device, and it is sealed under it. The `claim` record
    /// goes in the same commit (ext-invite-links.md, "Claiming", step 10).
    /// The successor reaches peers under the upload key of that state
    /// (step 11).
    ///
    /// # Errors
    ///
    /// As [`Engine::claim_status`]; [`Error::NotAllowed`] while the claim
    /// waits; the store's.
    pub async fn claim(&self, space: EventId) -> Result<EventId> {
        let mut state = self.lock().await;
        let wall = self.platform().clock.wall();
        match claim_status(&state, &space, wall)? {
            ClaimStatus::Claimed(id) => return Ok(id),
            ClaimStatus::Waiting => {
                return Err(Error::NotAllowed(
                    "the claim waits for the invite entry to arrive",
                ));
            }
            ClaimStatus::Ready(_) => {}
        }
        Self::check_may_sign(&state, &space)?;
        let claiming = state
            .invites
            .claiming
            .get(&space)
            .ok_or(Error::UnknownSpace)?;
        let key = claiming.keys.device_id().0;
        let entry = claiming.entry;
        let secret = *claiming.secret;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let invite = replica
            .roster()
            .state(&invite_member(key))
            .cloned()
            .ok_or(Error::Class("NotInRoster"))?;
        let me = self.device_id();
        let propagates = invite.propagates();
        let held = Self::held_state(replica)?;
        let grant = if propagates {
            Self::held_grant(replica)
        } else {
            None
        };
        let (seq, prev) = Self::next(&state, &space, &DeviceId(key));
        // The claimant is of the invite's `claims`; a person's successor
        // carries no keys, and its delivery wraps for every device on the
        // person's list ("The invite grant and the successor").
        let claims = replica.invites().get(&key).and_then(|facts| facts.claims);
        let (claimant, keys, recipients) = if claims == Some(CLAIMS_PERSON) {
            let person = state.person.ok_or(Error::NotAllowed(
                "this link admits a person, and the device is no person's",
            ))?;
            let mut recipients = crate::device::person_recipients(
                &person,
                invite.level,
                &state.lists,
                Some(replica),
            );
            for recipient in &mut recipients {
                recipient.propagates = propagates;
            }
            (MemberRef::person(person), None, recipients)
        } else {
            (
                MemberRef::device(me),
                Some(self.public_keys().clone()),
                vec![Recipient {
                    keys: self.public_keys().clone(),
                    writes: invite.level >= Level::Write,
                    propagates,
                }],
            )
        };
        let parents = replica.parents(prev);
        let cuts = replica.cuts_for(&parents)?;
        let plan = SpaceEventPlan {
            space,
            seq,
            prev,
            parents,
            cuts,
            checkpoint: None,
            refs: Vec::new(),
            changes: Some(vec![successor(claimant, keys)]),
            sealing: Sealing::Under {
                state: held,
                grant,
                recipients,
                others: Vec::new(),
            },
            twin: None,
            notices: Vec::new(),
            principals: Vec::new(),
            grantless: false,
        };
        let signed = writer::space_event(self.platform(), &claiming.keys.signer, plan)?;
        // The `claim` record, and the claim gone from the log's `state`,
        // in the successor's commit ("Records at rest").
        let mut log_state = crate::device::log_state(&state.vault, &space.0).await?;
        log_state.claiming = None;
        let extra = vec![
            (
                Table::Claim,
                entry.0.to_vec(),
                Some(claim_record(space.0, entry.0, secret)),
            ),
            (
                Table::State,
                Vec::new(),
                crate::device::log_state_value(log_state),
            ),
        ];
        let id = self
            .commit_own_keeping(&mut state, space, &signed.signed, None, extra)
            .await?;
        state.invites.claiming.remove(&space);
        state
            .invites
            .claimed
            .insert(entry, Kept::new(space, secret));
        Ok(id)
    }

    /// Whether this device publishes a successor of its own in `space` that
    /// is not durable yet: its connections then present the upload key of
    /// the state `K` held, whatever the claim's level ("Claiming", step
    /// 11; "Keys", the upload seed).
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn publishes_claim(&self, space: &EventId) -> bool {
        claim_unpublished(&*self.lock().await, space)
    }

    /// The state whose upload key this device's successor in `space` goes
    /// to peers under, with that key's seed, while the successor is not
    /// durable ("Claiming", step 11), whatever state the device holds
    /// since: the state the successor is sealed under where the device
    /// holds its upload seed, otherwise the state the invite delivered,
    /// whose seed `K`'s bundle in the invite entry holds. The successor
    /// may be sealed under a merged state the device holds whole, with no
    /// upload seed ("Where the successor is stored").
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn claim_upload(&self, space: &EventId) -> Option<(RotationSet, [u8; 32])> {
        let state = self.lock().await;
        if !claim_unpublished(&state, space) {
            return None;
        }
        let replica = state.replicas.get(space)?;
        let (entry, kept) = state
            .invites
            .claimed
            .iter()
            .find(|(_, kept)| kept.space == *space)?;
        let successor = replica.event(successor_of(replica, &kept.key)?)?;
        let sealed = crate::replica::visible(successor)?.sealed_under()?.clone();
        if let Some(seed) = replica.state_upload(&sealed) {
            return Some((sealed, *frasil_keys::derive::upload_key(&seed).seed));
        }
        invite_upload(replica, *space, *entry, &kept.secret)
    }

    /// Each space where this device signed a successor, with its first
    /// sight of it, kept at rest with the event: the claimant hands its
    /// person's list to the space from then on, until each event appears in
    /// the system stream (units.md, "A read-only person's list events";
    /// "Claiming", step 11).
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn claims_signed(&self) -> Vec<(EventId, Reading)> {
        let state = self.lock().await;
        state
            .invites
            .claimed
            .values()
            .filter_map(|kept| {
                let replica = state.replicas.get(&kept.space)?;
                let successor = successor_of(replica, &kept.key)?;
                Some((kept.space, *replica.first_sight(&successor)?))
            })
            .collect()
    }

    /// The administering devices' acts in `space` (ext-invite-links.md,
    /// "Administering devices"), each after its delay: the close of an
    /// invite whose successor this device holds, at once for an invite it
    /// made; and the revocation of an invite that expired or whose claims
    /// raced. Returns the roster event signed, if any.
    ///
    /// # Errors
    ///
    /// As [`Engine::sign_roster`].
    pub async fn maintain_invites(&self, space: EventId) -> Result<Option<EventId>> {
        let act = {
            let mut state = self.lock().await;
            let now = self.read_timeline(&mut state).await?;
            let me = self.device_id();
            let Some(replica) = state.replicas.get(&space) else {
                return Ok(None);
            };
            if replica.level_of(&me) != Some(Level::Administer)
                || Self::check_may_sign(&state, &space).is_err()
            {
                return Ok(None);
            }
            due_act(&state, replica, &space, &me, &now)
        };
        match act {
            Some(key) => Ok(Some(
                self.sign_roster(space, vec![revoke_invite(key)]).await?,
            )),
            None => Ok(None),
        }
    }

    /// The invites this device made whose key a valid removal put out: the
    /// client deletes their drops at its peers, then calls
    /// [`Engine::forget_invite`].
    pub async fn spent_invites(&self) -> Vec<SpentInvite> {
        let state = self.lock().await;
        let wall = self.platform().clock.wall();
        let mut out = Vec::new();
        for (entry, kept) in &state.invites.made {
            let Some(replica) = state.replicas.get(&kept.space) else {
                continue;
            };
            let Some(facts) = replica.invites().get(&kept.key) else {
                continue;
            };
            if !facts.removed {
                continue;
            }
            let expired = match (facts.expires_at, wall) {
                (Some(expires_at), Some(wall)) => wall >= expires_at.saturating_add(DROP_GRACE),
                _ => false,
            };
            out.push(SpentInvite {
                space: kept.space,
                entry: *entry,
                address: drop_address(&kept.secret),
                expired,
                kept_at: state.invites.drops.get(entry).cloned(),
                under: drop_state(replica, *entry, &kept.secret),
            });
        }
        out
    }

    /// Revokes the invite a link's fragment names: a removal of its invite
    /// key, which rotates (ext-invite-links.md, "Keys"). Its claims are
    /// refused from then on, and the inviter's client deletes its drops.
    /// `None` when the key is out already: closed or revoked.
    ///
    /// # Errors
    ///
    /// The fragment's classes; [`Error::Invalid`] for a link into another
    /// space, or one whose invite the space does not hold; as
    /// [`Engine::sign_roster`].
    pub async fn revoke_invite(&self, space: EventId, fragment: &str) -> Result<Option<EventId>> {
        let link = read_fragment(fragment).map_err(Error::class)?;
        if link.space != space {
            return Err(Error::Invalid("the link is into another space"));
        }
        let key = InviteKeys::derive(&link.secret).device_id().0;
        let open = self
            .read(&space, |replica| {
                replica
                    .invites()
                    .get(&key)
                    .filter(|facts| facts.entry == Some(link.entry))
                    .map(|facts| !facts.removed)
            })
            .await?
            .ok_or(Error::Invalid("the space holds no invite of this link"))?;
        if !open {
            return Ok(None);
        }
        self.sign_roster(space, vec![revoke_invite(key)])
            .await
            .map(Some)
    }

    /// The state the drop of the invite `entry`, made by this device,
    /// names: as [`SpentInvite::under`].
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn drop_state(&self, entry: &EventId) -> Option<RotationSet> {
        let state = self.lock().await;
        let kept = state.invites.made.get(entry)?;
        let replica = state.replicas.get(&kept.space)?;
        drop_state(replica, *entry, &kept.secret)
    }

    /// Records the peers that kept the drop of the invite `entry`, by URL:
    /// none for an invite in a space file. Drops are deleted only there
    /// ([`Engine::spent_invites`]), since a peer without ext-invite-links
    /// closes the connection on `MailboxDelete`.
    pub async fn drops_kept_at(&self, entry: EventId, peers: Vec<String>) {
        self.lock().await.invites.drops.insert(entry, peers);
    }

    /// The invites this device made and still keeps, spent or not: each
    /// one's space and entry, ascending by entry.
    pub async fn made_invites(&self) -> Vec<(EventId, EventId)> {
        self.lock()
            .await
            .invites
            .made
            .iter()
            .map(|(entry, kept)| (kept.space, *entry))
            .collect()
    }

    /// Where the drop of the invite `entry` is kept, when the device made
    /// it since it opened: as [`SpentInvite::kept_at`].
    pub async fn drops_of(&self, entry: &EventId) -> Option<Vec<String>> {
        self.lock().await.invites.drops.get(entry).cloned()
    }

    /// Lets go of an invite whose drops are deleted or expired: its
    /// `invite` record and its secret.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn forget_invite(&self, space: &EventId, entry: &EventId) -> Result<()> {
        let mut state = self.lock().await;
        state.invites.drops.remove(entry);
        if state.invites.made.remove(entry).is_none() {
            return Ok(());
        }
        let mut batch = crate::at_rest::Batch::default();
        state
            .vault
            .delete(&mut batch, &space.0, Table::Invite, &entry.0);
        state.vault.commit(batch).await
    }
}

/// Whether this device's successor in `space` is not durable yet.
pub(crate) fn claim_unpublished(state: &State, space: &EventId) -> bool {
    let Some(outbox) = state.outboxes.get(space) else {
        return false;
    };
    state.invites.claimed.values().any(|kept| {
        kept.space == *space
            && outbox
                .pending()
                .any(|((author, _), _)| author.0 == kept.key)
    })
}

/// Where a claim stands, in "Claiming"'s order.
fn claim_status(state: &State, space: &EventId, wall: Option<u64>) -> Result<ClaimStatus> {
    let Some(claiming) = state.invites.claiming.get(space) else {
        if let Some((_, kept)) = state
            .invites
            .claimed
            .iter()
            .find(|(_, kept)| kept.space == *space)
            && let Some(replica) = state.replicas.get(space)
            && let Some(id) = successor_of(replica, &kept.key)
        {
            return Ok(ClaimStatus::Claimed(id));
        }
        return Err(Error::UnknownSpace);
    };
    let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
    let key = claiming.keys.device_id().0;
    // 5, once the invite entry and its past are held: the space resolved
    // with the entry decided, so the rotation its delivery names is held.
    let Some(event) = replica.event(claiming.entry) else {
        return Ok(ClaimStatus::Waiting);
    };
    if replica.status(&claiming.entry).is_none() {
        return Ok(ClaimStatus::Waiting);
    }
    // 4 and 6: the roster is resolved with the snapshot's body keys. Until
    // the snapshot the drop names is used, the events before the break are
    // sealed to this device, and the entry, with them in its past, is held
    // and not judged (roster.md, "Space events a replica cannot open").
    if replica.awaited_snapshot().is_some() || is_held(replica.status(&claiming.entry)) {
        return Ok(ClaimStatus::Waiting);
    }
    check_invite_entry(event, space, &claiming.plain, &claiming.bundle, |id| {
        replica.event(*id)
    })
    .map_err(Error::class)?;
    // 6, 7 and 9.
    let facts = replica.invites().get(&key).cloned().unwrap_or_default();
    match replica.claim_check(&DeviceId(key)) {
        None => return Ok(ClaimStatus::Waiting),
        Some(Err(class)) => return Err(Error::class(*class)),
        Some(Ok(())) => {}
    }
    let expires_at = facts.expires_at.ok_or(Error::Class("WrongInvite"))?;
    // 10.
    check_claim_expiry(expires_at, wall).map_err(Error::class)?;
    // The keys K holds, for the successor's delivery.
    if Engine::held_state(replica).is_err() {
        return Ok(ClaimStatus::Waiting);
    }
    Ok(ClaimStatus::Ready(ClaimOffer {
        space: *space,
        inviter: *event.author(),
        level: facts.level.unwrap_or(Level::Read),
        expires_at,
    }))
}

/// Whether an event's status holds it for what has not arrived: a key, an
/// event of its past or a twin. An event held for an extension this device
/// lacks never resolves, and counts as judged.
fn is_held(status: Option<&Status>) -> bool {
    use frasil_base::errors::{Class, Sort};
    status.and_then(Status::class).is_some_and(|class| {
        matches!(class.sort(), Sort::Held | Sort::Pending) && class.name() != "ExtensionRequired"
    })
}

/// The invite key whose removal is due at this device now, if any.
fn due_act(
    state: &State,
    replica: &Replica,
    space: &EventId,
    me: &DeviceId,
    now: &Reading,
) -> Option<[u8; 32]> {
    let administering: Vec<[u8; 32]> = replica
        .devices()
        .into_iter()
        .filter(|(_, level)| *level == Level::Administer)
        .map(|(device, _)| device.0)
        .collect();
    let step = crate::maintenance::rotation_step();
    for (key, facts) in replica.invites() {
        let Some(entry) = facts.entry else {
            continue;
        };
        if facts.removed {
            continue;
        }
        let own = state.invites.made.contains_key(&entry);
        let (trigger, at_once) = match facts.successors.first() {
            // The close: its own invite at once, any other after the delay
            // with the successor as the trigger.
            Some(successor) if !facts.raced => (*successor, own),
            // A raced claim: revoked after the delay, as at expiry.
            _ if facts.raced => (entry, false),
            Some(_) => continue,
            None => {
                let first = replica.first_sight(&entry).copied().unwrap_or(*now);
                let expires_at = facts.expires_at?;
                if invite_expiry(expires_at, &first, now) != InviteExpiry::Revoke {
                    continue;
                }
                (entry, false)
            }
        };
        let Some(delay) = act_delay(space, &trigger, &administering, &me.0, at_once, step) else {
            continue;
        };
        let first = replica.first_sight(&trigger).copied().unwrap_or(*now);
        if lower(&first, now) >= delay {
            return Some(*key);
        }
    }
    None
}

/// Whether a removal is a close: of an invite key a valid successor put
/// out, which removes no member at its place and need not rotate
/// ("Keys", flags).
pub(crate) fn is_close(replica: &Replica, member: &MemberRef) -> bool {
    member.kind == MemberType::Invite
        && !replica.roster().is_in(member)
        && replica
            .invites()
            .get(&member.id)
            .is_some_and(|facts| !facts.successors.is_empty())
}

/// The recipient an invite key is while it counts as inside
/// ("Keys", receipt): its grant's X-Wing key, with the upload seed whatever
/// its level, and the grant seed unless the invite carries `session`.
pub(crate) fn invite_recipients(replica: &Replica, removed: &[MemberRef]) -> Vec<Recipient> {
    replica
        .roster()
        .members_in()
        .filter(|(member, _)| member.kind == MemberType::Invite && !removed.contains(member))
        .filter(|(member, _)| !replica.forked(&DeviceId(member.id)))
        .filter_map(|(_, state)| {
            let keys = state.keys.as_ref()?;
            Some(Recipient {
                keys: (**keys).clone(),
                writes: true,
                propagates: state.propagates(),
            })
        })
        .collect()
}

/// The recipient an invite grant delivers to: `K`, as
/// [`invite_recipients`] makes it.
pub(crate) fn granted_invite(change: &frasil_space::Change) -> Option<Recipient> {
    change.member.filter(|m| m.kind == MemberType::Invite)?;
    let keys = change.keys.as_ref()?;
    Some(Recipient {
        keys: (**keys).clone(),
        writes: true,
        propagates: change.session.is_none(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advanced::{AdapterRegistry, Platform};
    use frasil_space::{Change, Via};

    async fn device(key: u8) -> Engine {
        Engine::create(
            Platform::memory(),
            &[key; 32],
            AdapterRegistry::with_builtins(),
        )
        .await
        .expect("a device")
        .0
    }

    /// Alice's space, which grants her person and holds a void roster
    /// event (a person raised to `administer`, roster.md, 2.3 Changes),
    /// then an invite "from now on": the invite and its drop.
    async fn invited(alice: &Engine) -> (EventId, MadeInvite, [u8; 64]) {
        let person = alice.make_person(&[9; 32]).await.unwrap().person;
        let space = alice.create_space().await.unwrap();
        alice
            .grant_person(
                space,
                person,
                Level::Write,
                HistoryMode::WithHistory,
                Via::None,
            )
            .await
            .unwrap();
        alice.publish_list(space, &person).await.unwrap();
        let void = alice
            .sign_roster(
                space,
                vec![Change::set_level(
                    MemberRef::person(person),
                    Level::Administer,
                )],
            )
            .await
            .unwrap();
        assert!(
            alice
                .read(&space, |replica| replica
                    .status(&void)
                    .is_some_and(|s| !s.is_valid()))
                .await
                .unwrap()
        );
        let made = alice
            .make_invite(
                space,
                Level::Read,
                HistoryMode::FromNowOn,
                Claimant::Device,
                3600,
                Vec::new(),
            )
            .await
            .unwrap();
        let link = read_fragment(&made.fragment).unwrap();
        let snapshot = open_drop(&link.secret, &made.drop)
            .unwrap()
            .snapshot
            .expect("a snapshot for K");
        (space, made, snapshot)
    }

    /// A newcomer's snapshot carries the body key of a void space event
    /// from before the break, so the claimant judges it void, as its
    /// author did, and the invite entry after it valid (roster.md, "Space
    /// events a replica cannot open"; ext-invite-links.md, "Claiming",
    /// step 6). Without it, the claimant holds the void event sealed and
    /// every event after it pending, and refuses the link as
    /// `NotInRoster`.
    #[tokio::test]
    async fn a_claim_after_a_void_roster_event_is_ready() {
        let alice = device(1).await;
        let bob = device(2).await;
        let (space, made, snapshot) = invited(&alice).await;
        assert_eq!(bob.begin_claim(&made.fragment, &made.drop).await, Ok(space));
        // The snapshot first, as a claimant fetches it, then the events.
        let stored = alice.stored_object(&space, &snapshot).await.unwrap();
        bob.receive_object(space, &snapshot, &stored).await.unwrap();
        bob.ingest(space, alice.events(&space).await).await.unwrap();
        assert!(
            matches!(bob.claim_status(&space).await, Ok(ClaimStatus::Ready(_))),
            "{:?}",
            bob.claim_status(&space).await
        );
        bob.claim(space).await.unwrap();
    }

    /// Until the snapshot the drop names is used, the events before the
    /// break are sealed to the claimant and the invite entry is held: the
    /// claim waits, and is not refused ("Claiming", steps 4 and 6).
    #[tokio::test]
    async fn a_claim_waits_for_the_snapshot_its_drop_names() {
        let alice = device(1).await;
        let carol = device(3).await;
        let (space, made, _) = invited(&alice).await;
        assert_eq!(
            carol.begin_claim(&made.fragment, &made.drop).await,
            Ok(space)
        );
        carol
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
        assert_eq!(carol.claim_status(&space).await, Ok(ClaimStatus::Waiting));
    }

    /// A rotation its author signed before it held the claimant's
    /// successor wraps for `K` and not for the claimant: the claimant opens
    /// it with `K`'s wrap, and reads what follows ("Keys", receipt and
    /// entitlement).
    #[tokio::test]
    async fn a_claimant_opens_a_rotation_concurrent_with_its_successor() {
        let alice = device(1).await;
        let bob = device(2).await;
        let space = alice.create_space().await.unwrap();
        let made = alice
            .make_invite(
                space,
                Level::Write,
                HistoryMode::FromNowOn,
                Claimant::Device,
                3600,
                Vec::new(),
            )
            .await
            .unwrap();
        let link = read_fragment(&made.fragment).unwrap();
        let snapshot = open_drop(&link.secret, &made.drop)
            .unwrap()
            .snapshot
            .expect("a snapshot for K");
        bob.begin_claim(&made.fragment, &made.drop).await.unwrap();
        let stored = alice.stored_object(&space, &snapshot).await.unwrap();
        bob.receive_object(space, &snapshot, &stored).await.unwrap();
        bob.ingest(space, alice.events(&space).await).await.unwrap();
        let successor = bob.claim(space).await.unwrap();
        // Alice rotates for a second invite before Bob's successor reaches
        // her, then merges it with a roster event that does not rotate.
        let second = alice
            .make_invite(
                space,
                Level::Read,
                HistoryMode::FromNowOn,
                Claimant::Device,
                3600,
                Vec::new(),
            )
            .await
            .unwrap();
        alice.ingest(space, bob.events(&space).await).await.unwrap();
        let after = alice
            .set_suggester(space, MemberRef::device(bob.device_id()), true)
            .await
            .unwrap()
            .expect("a roster event");
        bob.ingest(space, alice.events(&space).await).await.unwrap();
        let (rotation, merged, current, level) = bob
            .read(&space, |replica| {
                (
                    replica.status(&second.entry).copied(),
                    replica.status(&after).copied(),
                    replica.current().cloned(),
                    replica.level_of(&bob.device_id()),
                )
            })
            .await
            .unwrap();
        assert!(rotation.is_some_and(|s| s.is_valid()), "{rotation:?}");
        assert!(merged.is_some_and(|s| s.is_valid()), "{merged:?}");
        let alices = alice
            .read(&space, |replica| replica.current().cloned())
            .await
            .unwrap();
        assert_eq!(current, Some(RotationSet::single(second.entry)));
        assert_eq!(current, alices);
        assert_eq!(level, Some(Level::Write));
        assert!(
            bob.read(&space, |replica| replica.status(&successor).copied())
                .await
                .unwrap()
                .is_some_and(|s| s.is_valid())
        );
    }

    /// A claimant holds its invite's break, `B`, and not a rotation `X`
    /// concurrent with it. A writer that holds both seals a unit under
    /// `{B, X}`; no rotation links back to that state, and the current
    /// state moves on before any writer delivers it whole. The claimant is
    /// entitled to it, through its invite key, since its place holds the
    /// invite (keys.md, "Entitlement and the link gate", rule 1;
    /// ext-invite-links.md, "Keys", entitlement), so a writer delivers it
    /// (keys.md, "Deliveries", item 2), and the unit opens.
    #[tokio::test]
    async fn a_claimant_receives_a_merged_state_no_longer_current() {
        let alice = device(1).await;
        let bob = device(2).await;
        let carol = device(3).await;
        let space = alice.create_space().await.unwrap();
        alice
            .grant_device(
                space,
                carol.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        carol.follow(space).await;
        carol
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
        // The invite's break, which Carol does not see yet, and her
        // rotation concurrent with it.
        let made = alice
            .make_invite(
                space,
                Level::Read,
                HistoryMode::FromNowOn,
                Claimant::Device,
                3600,
                Vec::new(),
            )
            .await
            .unwrap();
        let x = carol.heal(space).await.unwrap();
        // Carol meets the break and writes under the merged state.
        carol
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
        let merged = RotationSet::new(vec![made.entry, x]).unwrap();
        assert_eq!(
            carol
                .read(&space, |replica| replica.current().cloned())
                .await
                .unwrap(),
            Some(merged.clone())
        );
        let doc = carol.new_document().unwrap();
        let unit = carol
            .edit_document(space, &doc, |d| {
                d.get_text("body").insert(0, "under the merge").unwrap();
            })
            .await
            .unwrap();
        // Alice rotates after the break, before she meets Carol's rotation:
        // her rotation links back to the break's state alone.
        alice.heal(space).await.unwrap();
        // Bob claims on what Alice holds.
        let link = read_fragment(&made.fragment).unwrap();
        let snapshot = open_drop(&link.secret, &made.drop)
            .unwrap()
            .snapshot
            .expect("a snapshot for K");
        bob.begin_claim(&made.fragment, &made.drop).await.unwrap();
        let stored = alice.stored_object(&space, &snapshot).await.unwrap();
        bob.receive_object(space, &snapshot, &stored).await.unwrap();
        bob.ingest(space, alice.events(&space).await).await.unwrap();
        bob.claim(space).await.unwrap();
        // Everyone meets, and the writers keep up the space as a client's
        // upkeep does: the heal the claim calls for, top-ups and
        // deliveries.
        let engines = [&alice, &bob, &carol];
        let sync = || async {
            for to in engines {
                for from in engines {
                    to.ingest(space, from.events(&space).await).await.unwrap();
                }
            }
        };
        sync().await;
        for _ in 0..6 {
            for writer in [&alice, &carol] {
                writer.maintain_all().await.unwrap();
            }
            sync().await;
        }
        let (current, status) = bob
            .read(&space, |replica| {
                (replica.current().cloned(), replica.status(&unit).copied())
            })
            .await
            .unwrap();
        assert_ne!(
            current,
            Some(merged),
            "the merged state is no longer current"
        );
        assert!(status.is_some_and(|s| s.is_valid()), "{status:?}");
        let text = bob.document(&space, &doc.stream()).await.unwrap();
        assert_eq!(text.get_text("body").to_string(), "under the merge");
    }

    /// A claim made while a heal concurrent with the invite's break has
    /// merged the state: `K` holds the merge `{B, X}` whole, with no
    /// upload seed, and the successor is sealed under it. It goes to peers
    /// under the upload key of the state the invite delivered, `{B}`,
    /// whose seed `K`'s bundle holds ("Claiming", step 11, and "Where the
    /// successor is stored"); without it, no upload key presents it, and
    /// it stays in the outbox.
    #[tokio::test]
    async fn a_successor_under_a_merge_held_whole_is_stored_under_the_invites_state() {
        let alice = device(1).await;
        let bob = device(2).await;
        let carol = device(3).await;
        let space = alice.create_space().await.unwrap();
        alice
            .grant_device(
                space,
                carol.public_keys().clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        carol.follow(space).await;
        carol
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
        // The invite's break, and Carol's heal concurrent with it.
        let made = alice
            .make_invite(
                space,
                Level::Read,
                HistoryMode::FromNowOn,
                Claimant::Device,
                3600,
                Vec::new(),
            )
            .await
            .unwrap();
        let x = carol.heal(space).await.unwrap();
        let merged = RotationSet::new(vec![made.entry, x]).unwrap();
        // The writers meet, and deliver the merge whole to `K`, which holds
        // the break and not the heal (keys.md, "Deliveries", item 1).
        let writers = [&alice, &carol];
        let sync = || async {
            for to in writers {
                for from in writers {
                    to.ingest(space, from.events(&space).await).await.unwrap();
                }
            }
        };
        sync().await;
        for _ in 0..4 {
            for writer in writers {
                writer.maintain_all().await.unwrap();
            }
            sync().await;
        }
        // Bob claims on what the writers hold.
        let link = read_fragment(&made.fragment).unwrap();
        let snapshot = open_drop(&link.secret, &made.drop)
            .unwrap()
            .snapshot
            .expect("a snapshot for K");
        bob.begin_claim(&made.fragment, &made.drop).await.unwrap();
        let stored = alice.stored_object(&space, &snapshot).await.unwrap();
        bob.receive_object(space, &snapshot, &stored).await.unwrap();
        bob.ingest(space, alice.events(&space).await).await.unwrap();
        let (current, whole, upload) = bob
            .read(&space, |replica| {
                (
                    replica.current().cloned(),
                    replica.state_key(&merged).is_some(),
                    replica.state_upload(&merged).is_some(),
                )
            })
            .await
            .unwrap();
        assert_eq!(current, Some(merged.clone()), "the merge is current");
        assert!(whole, "K holds the merge whole");
        assert!(!upload, "and no upload seed of it");
        let successor = bob.claim(space).await.unwrap();
        let sealed = bob
            .read(&space, |replica| {
                replica
                    .event(successor)
                    .and_then(crate::replica::visible)
                    .and_then(|visible| visible.sealed_under().cloned())
            })
            .await
            .unwrap();
        assert_eq!(sealed, Some(merged));
        // The successor goes to peers under the break's upload key, which
        // the peer learned as the invite entry's.
        let (under, key) = bob
            .claim_upload(&space)
            .await
            .expect("an upload key for the successor");
        assert_eq!(under, RotationSet::single(made.entry));
        let break_seed = alice
            .read(&space, |replica| replica.state_upload(&under))
            .await
            .unwrap()
            .expect("the inviter's upload seed of the break");
        assert_eq!(key, *frasil_keys::derive::upload_key(&break_seed).seed);
    }

    /// A holder of a leaked link, who fetched the drop and opened `K`'s
    /// wrap but signed nothing, holds the state the invite delivered. Once
    /// a claim puts `K` out, `K` counts as outside and a writer heals, so a
    /// unit written after the claim and its close does not open under that
    /// state, while the claimant reads it ("Keys", inside; keys.md,
    /// "Healing").
    #[tokio::test]
    async fn a_leaked_link_reads_nothing_written_after_its_claim() {
        let alice = device(1).await;
        let bob = device(2).await;
        let space = alice.create_space().await.unwrap();
        let made = alice
            .make_invite(
                space,
                Level::Read,
                HistoryMode::WithHistory,
                Claimant::Device,
                3600,
                Vec::new(),
            )
            .await
            .unwrap();
        // What the link gives: K's seed and the drop.
        let link = read_fragment(&made.fragment).unwrap();
        let plain = open_drop(&link.secret, &made.drop).unwrap();
        let bundle = open_drop_wrap(&plain, &space, &InviteKeys::derive(&link.secret)).unwrap();
        let leaked = *bundle.content().expect("K's content key");

        bob.begin_claim(&made.fragment, &made.drop).await.unwrap();
        bob.ingest(space, alice.events(&space).await).await.unwrap();
        let successor = bob.claim(space).await.unwrap();
        alice.ingest(space, bob.events(&space).await).await.unwrap();
        let close = alice
            .maintain_invites(space)
            .await
            .unwrap()
            .expect("the inviter closes at once");
        // The heal: Alice is the only writer, first in rank, so no delay.
        let heal = alice.maintain(space).await.unwrap().rotation;
        assert!(heal.is_some(), "a claim puts K outside, and a writer heals");

        let doc = alice.new_document().unwrap();
        let unit = alice
            .edit_document(space, &doc, |d| {
                d.get_text("body").insert(0, "after the claim").unwrap();
            })
            .await
            .unwrap();
        let unit = alice
            .read(&space, |replica| {
                replica
                    .event(unit)
                    .and_then(|e| frasil_units::Unit::from_event(e.clone()).ok())
            })
            .await
            .unwrap()
            .expect("the unit");
        assert!(
            unit.open_with(&leaked, false, None).is_err(),
            "the leaked link's state opens a unit written after the claim"
        );

        bob.ingest(space, alice.events(&space).await).await.unwrap();
        let (statuses, level) = bob
            .read(&space, |replica| {
                (
                    [successor, close].map(|id| replica.status(&id).is_some_and(|s| s.is_valid())),
                    replica.level_of(&bob.device_id()),
                )
            })
            .await
            .unwrap();
        assert_eq!(statuses, [true, true]);
        assert_eq!(level, Some(Level::Read));
        let text = bob.document(&space, &doc.stream()).await.unwrap();
        assert_eq!(text.get_text("body").to_string(), "after the claim");
    }

    /// The engine refuses to raise a person to `administer`, a change that
    /// would be void (roster.md, 2.3 Changes).
    #[tokio::test]
    async fn a_person_is_never_raised_to_administer() {
        let alice = device(1).await;
        let person = alice.make_person(&[9; 32]).await.unwrap().person;
        let space = alice.create_space().await.unwrap();
        alice
            .grant_person(
                space,
                person,
                Level::Write,
                HistoryMode::WithHistory,
                Via::None,
            )
            .await
            .unwrap();
        assert_eq!(
            alice
                .set_level(space, MemberRef::person(person), Level::Administer)
                .await,
            Err(Error::Class("AdministerNotDevice"))
        );
    }
}
