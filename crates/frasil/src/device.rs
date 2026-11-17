//! The device: the client's root.
//!
//! A [`Engine`] owns its platform (the store, the clocks, randomness), its
//! keys, the spaces it replicates and their outboxes. It is a cheap handle:
//! clones share one device, so connections and the application can use it
//! at once. Every act that signs follows at-rest.md, "Committing": the
//! event, its `outbox` record, its tip and any secret drawn for it go in
//! one commit, behind the mark, and nothing is sent before that commit has
//! returned.
//!
//! A device here is a **device member**: its sealed device keys name no
//! person (a zero person ID, at-rest.md, "Sealed device keys"), and spaces
//! grant it directly. Persons, their device lists and grants of spaces are
//! read by the protocol crates but not yet driven by this client.

use crate::adapters::AdapterRegistry;
use crate::at_rest::{Batch, Vault};
use crate::error::{Error, Result};
use crate::outbox::{Acknowledger, Loss, LossClass, Outbox};
use crate::platform::{Platform, check_random};
use crate::replica::{Me, Replica, RotationSecrets};
use crate::sync::{Action, SyncSession};
use crate::writer::{self, HeldGrant, HeldState, Recipient, Sealing, SpaceEventPlan};
use frasil_base::collect::CollectMap;
use frasil_base::time::{Reading, Timeline};
use frasil_crypto::device::{DeviceId, DeviceKeys as PublicKeys, KeyRing, KeySource};
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_crypto::sizes::XWING_PUBLIC;
use frasil_events::{Event, EventId, kind};
use frasil_identity::DeviceList;
use frasil_keys::RotationSet;
use frasil_keys::derive::Secret;
use frasil_peers::body::{ChangeEffect, SlotId, SlotRef, StorageBody};
use frasil_peers::derive::{grant_map_with, open_token, twin_commitment, twin_secret};
use frasil_space::state::administer_changes;
use frasil_space::{Change, Level, MemberRef, MemberType, Op, Policy};
use frasil_store::device_keys::{KeyKind, SEALED_DEVICE_KEYS_BYTES};
use frasil_store::tables::{
    Bundle as StoredBundle, EventRecord, FLAG_PROVISIONAL, FLAG_VERIFIED, KeyKind as StoredKeyKind,
    KeyValue, LogKind, LogState, Pseudonym, Secret as StoredSecret,
};
use frasil_store::{Continuity, Table, TableValue, Tip};
use frasil_transport::roster::{Ended, Path, Standing};
use frasil_units::messages::SyncMessage;
use frasil_units::stream::{Opening, StreamId};
use frasil_units::unit::Draft;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard, broadcast};
use zeroize::Zeroizing;

/// The person ID a device member's sealed keys name: 32 zero bytes.
const DEVICE_MEMBER: [u8; 32] = [0; 32];

/// How often, at least, the device keeps its timeline's reading while it
/// runs (overview.md, "The local timeline").
const KEEP_READING_EVERY: u64 = 60;

/// A change the device announces to its connections and its application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// The space.
    pub space: EventId,
    /// Events newly placed, in the order placed.
    pub placed: Vec<EventId>,
    /// Held objects withdrawn as not held (at-rest.md, "Held objects").
    pub withdrawn: Vec<crate::held::Withdrawn>,
    /// Objects the application asked for, which each member connection of
    /// the space asks the other side for.
    pub wanted: Vec<frasil_adapter::Locator>,
}

/// What a unit carries beside its content.
#[derive(Debug, Clone, Default)]
pub(crate) struct UnitParts {
    /// The adapter's content.
    pub content: Vec<u8>,
    /// The locators it names (visible key 5).
    pub objects: Vec<frasil_adapter::Locator>,
    /// A snapshot unit's compaction declaration.
    pub compacts: Option<frasil_units::body::Compacts>,
    /// The supersessions it carries (visible key 8).
    pub supersedes: Vec<frasil_adapter::Supersession>,
    /// A snapshot unit's `excluded`, ascending.
    pub excluded: Vec<EventId>,
    /// The late write a unit re-applies (ext-restricted-spaces.md, sealed
    /// key 4).
    #[cfg(feature = "ext-restricted-spaces")]
    pub copied_from: Option<frasil_units::inner::CopiedFrom>,
    /// Parts of objects it names, kept in the unit's commit.
    pub stored: Vec<crate::snapshots::ObjectPart>,
    /// Further records kept in the unit's commit; one given as `None` is
    /// deleted in it.
    pub records: Vec<(Table, Vec<u8>, Option<TableValue>)>,
}

/// What [`Engine::ingest`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ingested {
    /// Events newly placed.
    pub placed: Vec<EventId>,
    /// Parents the replica waits for: what to ask for next.
    pub wanted: Vec<EventId>,
    /// Events refused before placement, with their class.
    pub refused: Vec<(usize, &'static str)>,
}

/// A device's keys, as the device makes and keeps them.
impl Keys {
    /// The identity seed's bytes.
    pub(crate) fn identity_seed_bytes(&self) -> [u8; 32] {
        *self.identity_seed
    }
}

pub(crate) struct Keys {
    /// The device's three public keys, derived from its seeds once.
    pub(crate) public: PublicKeys,
    pub(crate) mldsa_seed: Secret,
    pub(crate) store_secret: Secret,
    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    identity_seed: Secret,
    signer: Signer,
    xwing_seed: Secret,
}

/// What the device holds, behind its lock.
pub(crate) struct State {
    pub(crate) vault: Vault,
    timeline: Timeline,
    last_kept: u64,
    /// The `event` record an own event was committed with, as its verdict
    /// was foreseen: the settle after it writes the record again only if
    /// the verdict differs.
    foreseen: Option<(EventId, EventRecord)>,
    pub(crate) replicas: BTreeMap<EventId, Replica>,
    pub(crate) outboxes: BTreeMap<EventId, Outbox>,
    /// Administrator pseudonyms this device holds, by space: their signers.
    pub(crate) pseudonyms: BTreeMap<EventId, Vec<(SlotId, Signer)>>,
    /// Spaces in which an always-on peer has acknowledged events: there a
    /// member's acknowledgement no longer makes an event durable.
    peered: BTreeSet<EventId>,
    /// Persons' device lists, by person ID: every list a space this device
    /// holds carries copies of.
    pub(crate) lists: BTreeMap<[u8; 32], crate::lists::PersonList>,
    /// Logs found at load that a claim began and never finished
    /// (ext-invite-links.md, "Records at rest"): held aside, in no
    /// replica, until [`Engine::forget_stale_claims`] lets each go through
    /// the space's object provider, once one is attached.
    pub(crate) stale_claims: Vec<EventId>,
    /// Spaces this device dropped for its own erasure, of which it keeps
    /// only the `log` record, its `pseudonym` records and its tips until
    /// each always-on peer it reaches answers `erased` (peers.md, "A
    /// device's own erasure").
    pub(crate) erasing: BTreeMap<EventId, crate::erasing::Residue>,
    #[allow(dead_code)]
    pub(crate) welcomed_requests: BTreeSet<(DeviceId, [u8; 16])>,
    /// Erasures completed or given up in this run do not accept delayed welcomes.
    pub(crate) ignored_erasure_welcomes: BTreeSet<EventId>,
    /// Loro documents lent to the application, by space and stream: the
    /// incarnation each is written under, with its opening.
    #[cfg(feature = "adapter-loro")]
    pub(crate) lent: BTreeMap<(EventId, StreamId), crate::documents::LentEntry>,
    /// The incarnations, by space, stream and incarnation, whose
    /// operations a lent document's holder wrote again under a fresh one
    /// once a unit of them was withdrawn: their refused units are not
    /// re-submitted too.
    #[cfg(feature = "adapter-loro")]
    pub(crate) expressed_again: BTreeSet<(EventId, StreamId, u64)>,
    /// The person this device is a device of, if any.
    pub(crate) person: Option<[u8; 32]>,
    /// The keys the device holds outside any record: its own, and those it
    /// learned in admission exchanges (crypto.md, "Keys by their hash").
    /// Every other key it holds is in a record of a list or a space it
    /// holds, where every resolution finds it; [`State::keys`] looks in all
    /// of them. Nothing of it is written (at-rest.md, "What is never
    /// written"). Its revision grows only with a key it did not hold.
    pub(crate) ring: KeyRing,
    /// The person's personal space, once this device knows it.
    pub(crate) personal_space: Option<EventId>,
    /// The list member this device recovers with, while it recovers
    /// (identity.md, "Recovery").
    pub(crate) recovering: Option<crate::recovery::Recovering>,
    /// This device's first sight of each heal's trigger, by space, while
    /// it runs; after a restart it is derived again (`maintenance.rs`).
    pub(crate) heal_sights: BTreeMap<(EventId, Vec<u8>), Reading>,
    /// The current states this device delivered to inside devices that
    /// lacked them (keys.md, "Deliveries"), each once while it runs.
    pub(crate) delivered_states: BTreeSet<(EventId, Vec<u8>)>,
    /// The first sight of each list event, kept in its event record.
    pub(crate) list_sights: BTreeMap<EventId, Reading>,
    /// The ephemeral channel's state, from its first use.
    #[cfg(feature = "ephemeral")]
    pub(crate) ephemeral: Option<crate::ephemeral::EphemeralState>,
    /// Invites this device made and claims it makes (ext-invite-links.md).
    #[cfg(feature = "ext-invite-links")]
    pub(crate) invites: crate::invite_links::Invites,
    /// The recovery agent's waiting decisions and relays
    /// (ext-recovery-agent.md).
    #[cfg(feature = "ext-recovery-agent")]
    pub(crate) agents: crate::recovery_agent::AgentState,
    /// Leaves, completed syncs and leave requests (ext-guests.md).
    #[cfg(feature = "ext-guests")]
    pub(crate) guests: crate::guests::GuestState,
    /// The objects the application holds through its providers
    /// (at-rest.md, "Held objects").
    pub(crate) held: crate::held::HeldObjects,
}

/// Every key the device holds, by its hash: its ring, then each list's
/// `add`s, then each space's opened grants, valid or void (crypto.md, "Keys
/// by their hash"). Looked up in place; nothing is copied.
pub(crate) struct HeldKeys<'a> {
    state: &'a State,
}

impl KeySource for HeldKeys<'_> {
    fn hybrid_keys(
        &self,
        kc: &frasil_crypto::device::KeysCommitment,
    ) -> Option<frasil_crypto::device::HybridKeys> {
        self.state.ring.get(kc).cloned().or_else(|| {
            let lists = self
                .state
                .lists
                .values()
                .map(crate::lists::PersonList::keys);
            let spaces = self.state.replicas.values().map(Replica::found_keys);
            lists.chain(spaces).find_map(|ring| ring.get(kc).cloned())
        })
    }

    fn device_keys(&self, id: &DeviceId) -> Option<PublicKeys> {
        self.state.ring.device_keys(id).or_else(|| {
            let lists = self
                .state
                .lists
                .values()
                .map(crate::lists::PersonList::keys);
            let spaces = self.state.replicas.values().map(Replica::found_keys);
            lists.chain(spaces).find_map(|ring| ring.device_keys(id))
        })
    }
}

impl State {
    /// The pseudonym this device enrolled in an administrator slot of a
    /// space, if it holds it.
    pub(crate) fn pseudonym(&self, space: &EventId, slot: &SlotId) -> Option<&Signer> {
        self.pseudonyms
            .get(space)?
            .iter()
            .rfind(|(held, _)| held == slot)
            .map(|(_, signer)| signer)
    }

    /// The device IDs of the pseudonyms this device holds in a space,
    /// oldest first.
    pub(crate) fn pseudonym_ids(&self, space: &EventId) -> Vec<DeviceId> {
        self.pseudonyms
            .get(space)
            .map(|held| held.iter().map(|(_, p)| *p.device_id()).collect())
            .unwrap_or_default()
    }

    /// Every key the device holds, by its hash.
    pub(crate) fn keys(&self) -> HeldKeys<'_> {
        HeldKeys { state: self }
    }
}

/// For each space, what each always-on peer reached holds, by its key.
type PeerHoldings = BTreeMap<EventId, BTreeMap<[u8; 32], BTreeSet<EventId>>>;

struct Shared {
    platform: Platform,
    keys: Keys,
    registry: AdapterRegistry,
    /// Whether every replica is partial: it holds its frame and the streams
    /// the application opens (units.md, "Partial replicas").
    #[cfg_attr(not(feature = "partial-replicas"), allow(dead_code))]
    partial: std::sync::atomic::AtomicBool,
    /// Set once replicas held already are to be made partial, the next
    /// time the state is taken.
    #[cfg(feature = "partial-replicas")]
    partial_unapplied: std::sync::atomic::AtomicBool,
    /// Whether blobs are fetched only when the application asks for them.
    objects_on_demand: std::sync::atomic::AtomicBool,
    /// Whether this device signs roster events without checking ranks,
    /// as a client that does not would: for tests of what replicas and
    /// peers judge.
    unchecked_ranks: std::sync::atomic::AtomicBool,
    /// For each space, the always-on peers this device reaches, by their
    /// stable key, with the events each is known to hold: those it sent,
    /// listed as heads or acknowledged. A checkpoint is voted for only once
    /// each of them holds its cut (peers.md, "The administrator's duties").
    peer_holdings: std::sync::Mutex<PeerHoldings>,
    /// Spaces a peer answered `erased` for.
    erased_at_peer: std::sync::Mutex<BTreeSet<EventId>>,
    /// The application's checkpoint policy (roster.md, 3.15.7 Clients).
    checkpoint_policy: std::sync::Mutex<crate::checkpoints::CheckpointPolicy>,
    /// Names the application marks fresh-only on the ephemeral channel.
    #[cfg(feature = "ephemeral")]
    fresh_only: std::sync::Mutex<BTreeSet<String>>,
    state: Mutex<State>,
    /// Serializes restoring and deciding an erasure while upkeep runs.
    erasure_settling: Mutex<()>,
    notices: broadcast::Sender<Notice>,
    /// Detected loss, as it is reported (units.md, 3.13 "Detected loss").
    losses: broadcast::Sender<Loss>,
    /// Spaces a restored device may sign in again, as each becomes so
    /// (at-rest.md, 3.6 "After a restore", step 2).
    write_ready: broadcast::Sender<EventId>,
    /// Every loss reported while the device runs: by whom, in which space,
    /// of which class.
    lost: std::sync::Mutex<BTreeSet<(Acknowledger, EventId, LossClass)>>,
    /// Objects that became whole at this device, by space, as their last
    /// parts arrive: what a blob feed reports as arrived.
    arrivals: broadcast::Sender<(EventId, frasil_adapter::Locator)>,
    /// Held objects withdrawn since the device opened, by space and object
    /// ID, until the device holds them again (at-rest.md, "Held objects").
    withdrawn: std::sync::Mutex<BTreeSet<(EventId, [u8; 32])>>,
    /// Objects read whole since the device opened, every step of units.md,
    /// 3.3 passed, by the space that stores them.
    verified: std::sync::Mutex<BTreeSet<(EventId, frasil_adapter::Locator)>>,
    /// What the device's member connections share.
    links: std::sync::Mutex<crate::links::Links>,
    /// The object providers the application gave (at-rest.md, "Held
    /// objects"), never held across an await.
    providers: std::sync::Mutex<crate::held::Providers>,
    /// The peers that grant the device each space on an open connection
    /// now, which the welcomes it signs name (admission.md, "The welcome").
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    syncing: std::sync::Mutex<Vec<(EventId, String)>>,
}

/// A Frasil device: the client's root.
#[derive(Clone)]
pub struct Engine {
    shared: Arc<Shared>,
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("device_id", self.shared.keys.signer.device_id())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// The peers that grant the device each space on an open connection
    /// now (crate `hints`).
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) fn syncing(&self) -> &std::sync::Mutex<Vec<(EventId, String)>> {
        &self.shared.syncing
    }

    /// Makes a new device: draws its three seeds and its store secret, seals
    /// them under the application's unlock key (kind 2, a device member),
    /// and makes its store, head and mark before it first signs (at-rest.md,
    /// "Sealed device keys", "Continuity").
    ///
    /// Returns the device and its 235-byte sealed device keys, which the
    /// application keeps in a durable place.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`]; the store's.
    pub async fn create(
        platform: Platform,
        unlock_key: &[u8; 32],
        registry: AdapterRegistry,
    ) -> Result<(Self, [u8; SEALED_DEVICE_KEYS_BYTES])> {
        check_random(platform.random.as_ref())?;
        let keys = frasil_store::DeviceKeys::new(
            *platform.draw::<32>()?,
            *platform.draw::<32>()?,
            *platform.draw::<32>()?,
            *platform.draw::<32>()?,
        );
        let public = keys.public_keys();
        let sealed = frasil_store::seal_device_keys_with(
            &keys,
            &DEVICE_MEMBER,
            KeyKind::UnlockKey,
            unlock_key,
            &platform.nonce::<24>()?,
        )
        .map_err(Error::class)?;
        let vault = Vault::create(platform.clone(), &keys.store_secret, public.device_id()).await?;
        let device = Self::assemble(platform, &keys, public, vault, None, registry).await?;
        Ok((device, sealed))
    }

    /// Opens a device from its sealed device keys and the unlock key,
    /// checks continuity, and loads every space it keeps.
    ///
    /// # Errors
    ///
    /// The classes of `open_device_keys`; the store's.
    pub async fn open(
        platform: Platform,
        sealed: &[u8],
        unlock_key: &[u8; 32],
        registry: AdapterRegistry,
    ) -> Result<Self> {
        Self::open_as(platform, sealed, unlock_key, None, registry).await
    }

    /// Opens a device of a person: its sealed device keys name the person
    /// ID the application expects (at-rest.md, "Sealing and opening the
    /// device keys"); `None` for a device member.
    ///
    /// # Errors
    ///
    /// As [`Engine::open`]; `WrongPerson` for keys of another person.
    pub async fn open_as(
        platform: Platform,
        sealed: &[u8],
        unlock_key: &[u8; 32],
        person: Option<[u8; 32]>,
        registry: AdapterRegistry,
    ) -> Result<Self> {
        let keys = crate::intake::open_device_keys(
            sealed,
            KeyKind::UnlockKey,
            unlock_key,
            &person.unwrap_or(DEVICE_MEMBER),
            None,
        )
        .map_err(Error::Class)?;
        // Opening derived the public keys to check the device ID (at-rest.md,
        // "Sealing and opening the device keys", step 10); derive them once
        // more here, for the device to sign and seal with.
        let public = keys.public_keys();
        let vault = Vault::open(platform.clone(), &keys.store_secret, public.device_id()).await?;
        let kept = match vault.get_device(Table::Timeline).await? {
            Some(TableValue::Timeline(reading)) => Some(reading),
            _ => None,
        };
        let device = Self::assemble(platform, &keys, public, vault, kept, registry).await?;
        device.lock().await.person = person;
        device.load().await?;
        device.find_personal_space().await;
        Ok(device)
    }

    async fn assemble(
        platform: Platform,
        keys: &frasil_store::DeviceKeys,
        public: PublicKeys,
        vault: Vault,
        kept: Option<Reading>,
        registry: AdapterRegistry,
    ) -> Result<Self> {
        let signer = Signer::from_seeds(&keys.identity_seed, &keys.mldsa_seed, public.keys.xwing());
        let mut ring = KeyRing::new();
        ring.add_device(public.clone());
        let mono = platform.clock.monotonic();
        let wall = platform.clock.wall();
        let timeline = Timeline::start(kept, wall, mono);
        let (notices, _) = broadcast::channel(1024);
        let (arrivals, _) = broadcast::channel(1024);
        // A device whose replicas are partial from its first resolution on
        // (units.md, 3.15 Partial replicas): the load resolves each space
        // as one.
        let streams_only = cfg!(feature = "partial-replicas") && platform.streams_only;
        let device = Self {
            shared: Arc::new(Shared {
                erasure_settling: Mutex::new(()),
                keys: Keys {
                    public,
                    mldsa_seed: keys.mldsa_seed.clone(),
                    store_secret: keys.store_secret.clone(),
                    identity_seed: keys.identity_seed.clone(),
                    signer,
                    xwing_seed: keys.xwing_seed.clone(),
                },
                platform,
                registry,
                partial: std::sync::atomic::AtomicBool::new(streams_only),
                #[cfg(feature = "partial-replicas")]
                partial_unapplied: std::sync::atomic::AtomicBool::new(false),
                objects_on_demand: std::sync::atomic::AtomicBool::new(false),
                unchecked_ranks: std::sync::atomic::AtomicBool::new(false),
                peer_holdings: std::sync::Mutex::default(),
                erased_at_peer: std::sync::Mutex::default(),
                checkpoint_policy: std::sync::Mutex::default(),
                arrivals,
                withdrawn: std::sync::Mutex::new(BTreeSet::new()),
                verified: std::sync::Mutex::new(BTreeSet::new()),
                providers: std::sync::Mutex::new(crate::held::Providers::default()),
                #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
                syncing: std::sync::Mutex::new(Vec::new()),
                #[cfg(feature = "ephemeral")]
                fresh_only: std::sync::Mutex::new(BTreeSet::new()),
                state: Mutex::new(State {
                    vault,
                    timeline,
                    last_kept: mono,
                    foreseen: None,
                    replicas: BTreeMap::new(),
                    outboxes: BTreeMap::new(),
                    pseudonyms: BTreeMap::new(),
                    peered: BTreeSet::new(),
                    lists: BTreeMap::new(),
                    stale_claims: Vec::new(),
                    erasing: BTreeMap::new(),
                    welcomed_requests: BTreeSet::new(),
                    ignored_erasure_welcomes: BTreeSet::new(),
                    #[cfg(feature = "adapter-loro")]
                    lent: BTreeMap::new(),
                    #[cfg(feature = "adapter-loro")]
                    expressed_again: BTreeSet::new(),
                    person: None,
                    ring,
                    personal_space: None,
                    recovering: None,
                    heal_sights: BTreeMap::new(),
                    delivered_states: BTreeSet::new(),
                    list_sights: BTreeMap::new(),
                    #[cfg(feature = "ephemeral")]
                    ephemeral: None,
                    #[cfg(feature = "ext-invite-links")]
                    invites: crate::invite_links::Invites::default(),
                    #[cfg(feature = "ext-recovery-agent")]
                    agents: crate::recovery_agent::AgentState::default(),
                    #[cfg(feature = "ext-guests")]
                    guests: crate::guests::GuestState::default(),
                    held: crate::held::HeldObjects::default(),
                }),
                notices,
                losses: broadcast::channel(256).0,
                write_ready: broadcast::channel(256).0,
                lost: std::sync::Mutex::new(BTreeSet::new()),
                links: std::sync::Mutex::new(crate::links::Links::default()),
            }),
        };
        {
            let mut state = device.lock().await;
            let reading = state.timeline.read(mono, wall);
            state.vault.keep_reading(&reading).await?;
        }
        Ok(device)
    }

    // -- Who the device is

    /// The device ID, which names the device everywhere: the hash of its
    /// Ed25519 key and the commitment to its other keys (crypto.md, "A
    /// device's keys").
    pub fn device_id(&self) -> DeviceId {
        *self.shared.keys.signer.device_id()
    }

    /// The device's X-Wing key, to which keys are wrapped.
    pub fn xwing_public(&self) -> &[u8; XWING_PUBLIC] {
        self.shared
            .keys
            .public
            .keys
            .xwing()
            .expect("a device has an X-Wing key")
    }

    /// The device's three public keys, as a grant or a list `add` carries
    /// them; their device ID is [`device_id`](Self::device_id).
    pub fn public_keys(&self) -> &PublicKeys {
        &self.shared.keys.public
    }

    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    /// Names the application marks fresh-only (ext-ephemeral.md).
    #[cfg(feature = "ephemeral")]
    pub(crate) fn shared_fresh_only(&self) -> &std::sync::Mutex<BTreeSet<String>> {
        &self.shared.fresh_only
    }

    /// The skeleton events this device's administrator pseudonyms signed
    /// in a space, the root aside: they travel only on administration
    /// connections (peers.md, "Administration connections"). The root goes
    /// with the genesis, since a peer knows no pseudonym of the space
    /// before it, and the founder's connection has shown the genesis.
    #[cfg_attr(not(any(feature = "server", feature = "iroh")), allow(dead_code))]
    pub(crate) async fn own_skeleton(&self, space: &EventId) -> BTreeSet<EventId> {
        let state = self.lock().await;
        let Some(held) = state.pseudonyms.get(space) else {
            return BTreeSet::new();
        };
        let Some(log) = state.replicas.get(space).and_then(Replica::log) else {
            return BTreeSet::new();
        };
        held.iter()
            .flat_map(|(_, p)| log.chain(p.device_id()))
            .filter(|id| !is_root(log, *id))
            .collect()
    }

    /// What an administration connection for a space presents and stores
    /// (peers.md, "Administration connections"): the newest pseudonym's
    /// device ID, which credential 3 presents, its `Present` proof over
    /// `presented`, made with its Ed25519 seed, and the events
    /// its pseudonyms signed that no peer has acknowledged yet. `None`
    /// while the device holds no pseudonym there.
    #[cfg_attr(not(any(feature = "server", feature = "iroh")), allow(dead_code))]
    pub(crate) async fn administration(
        &self,
        space: &EventId,
        presented: impl FnOnce(&[u8; 32]) -> Vec<u8>,
    ) -> Option<([u8; 32], [u8; 64], Vec<Vec<u8>>)> {
        let state = self.lock().await;
        let held = state.pseudonyms.get(space)?;
        let erasing = state
            .erasing
            .get(space)
            .filter(|residue| !residue.refetching);
        let (_, pseudonym) = if let Some(residue) = erasing {
            let (_, signed) = residue.erasure.as_ref()?;
            let erasure = frasil_events::decode(signed).ok()?;
            held.iter()
                .find(|(_, signer)| signer.device_id() == erasure.author())?
        } else {
            held.last()?
        };
        let public = pseudonym.device_id().0;
        let message = frasil_peers::proof::proof_message(&presented(&public));
        let proof: [u8; 64] = pseudonym.sign(Scheme::Ed25519, &message).try_into().ok()?;
        // A space dropped for its own erasure presents its erasure again,
        // to learn whether the peer erased it (peers.md, 3.16).
        let pending: Vec<Vec<u8>> = if let Some(residue) = erasing {
            residue
                .erasure
                .as_ref()
                .map(|(_, signed)| vec![signed.clone()])
                .unwrap_or_default()
        } else {
            match state.replicas.get(space) {
                Some(replica) => Self::own_skeleton_pending(&state, space)
                    .into_iter()
                    .filter_map(|id| replica.event(id).map(Event::signed))
                    .collect(),
                None => Vec::new(),
            }
        };
        Some((public, proof, pending))
    }

    /// Whether the device holds skeleton events of its own pseudonyms in a
    /// space that no peer has acknowledged yet: what an administration
    /// connection would store (peers.md, "Administration connections").
    #[cfg_attr(not(any(feature = "server", feature = "iroh")), allow(dead_code))]
    pub(crate) async fn skeleton_pending(&self, space: &EventId) -> bool {
        let state = self.lock().await;
        !Self::own_skeleton_pending(&state, space).is_empty() || Self::cut_vote_owed(&state, space)
    }

    /// Whether this device's pseudonym owes the skeleton cut of a checkpoint
    /// its vote (peers.md, "Skeleton cuts", in effect at the peer): a
    /// checkpoint that waits for votes, or the last in effect, that the
    /// device builds on, and after which none of its pseudonyms has signed
    /// a skeleton event. An administration connection then takes the
    /// peer's awaiting report, which names the checkpoint, and the device's
    /// acknowledgement cites it.
    fn cut_vote_owed(state: &State, space: &EventId) -> bool {
        Self::cut_vote_owed_for(state, space).is_some()
    }

    /// The checkpoint whose skeleton cut this device's pseudonym owes its
    /// vote ([`Self::cut_vote_owed`]), if any.
    pub(crate) fn cut_vote_owed_for(state: &State, space: &EventId) -> Option<EventId> {
        let held = state.pseudonyms.get(space)?;
        let replica = state.replicas.get(space)?;
        let log = replica.log()?;
        let facts = replica.checkpoint_facts();
        let avoided = facts.avoided();
        let mine: BTreeSet<DeviceId> = held.iter().map(|(_, p)| *p.device_id()).collect();
        let newest = held.last().map(|(_, p)| p.device_id());
        facts
            .pending
            .iter()
            .map(|pending| pending.checkpoint)
            .chain(facts.last())
            .filter(|c| !avoided.contains(c) && !facts.unacknowledged.contains(c))
            // Only the pseudonym a cut's slots name enrolled votes for it: a
            // slot the cut leaves unenrolled waits for no vote, and an
            // acknowledgement by a pseudonym enrolled concurrently with the
            // checkpoint would cite an enrolment the skeleton after the cut
            // has no slot for (peers.md, "Skeleton cuts", "In effect").
            .filter(|&c| {
                log.event(c)
                    .and_then(frasil_peers::skeleton::named_twin)
                    .and_then(|cut| log.event(cut))
                    .and_then(frasil_peers::cut::read_cut)
                    .is_some_and(|cut| {
                        cut.slots.iter().any(|entry| {
                            entry
                                .pseudonym
                                .and_then(|id| log.event(id))
                                .is_some_and(|enrolment| Some(enrolment.author()) == newest)
                        })
                    })
            })
            .find(|&c| {
                !log.events().any(|event| {
                    mine.contains(event.author())
                        && event.kind() == kind::STORAGE
                        && (event.parents().contains(&c) || log.follows(event.id(), c) == Ok(true))
                })
            })
    }

    /// The record objects that this device's own skeleton cuts of a space
    /// name, of the cuts no peer has acknowledged yet: each is uploaded
    /// before its cut is stored (roster.md, "The record object"; peers.md,
    /// "Skeleton cuts").
    #[cfg_attr(not(any(feature = "server", feature = "iroh")), allow(dead_code))]
    pub(crate) async fn pending_cut_records(
        &self,
        space: &EventId,
    ) -> Vec<frasil_adapter::Locator> {
        let state = self.lock().await;
        let Some(replica) = state.replicas.get(space) else {
            return Vec::new();
        };
        Self::own_skeleton_pending(&state, space)
            .into_iter()
            .filter_map(|id| replica.event(id))
            .filter_map(|event| StorageBody::read(event.unverified_body()).ok())
            .filter_map(|body| body.cut().map(|cut| cut.record))
            .collect()
    }

    /// Whether the pseudonym this device holds for `slot` is late under
    /// checkpoint `c` (peers.md, "Skeleton cuts", "A late enrolment"): its
    /// enrolment is neither named by `c`'s cut nor after `c`. A root, which
    /// every cut names for its slot, is never late.
    fn enrolment_late(state: &State, space: &EventId, slot: &SlotId, c: EventId) -> bool {
        let Some(pseudonym) = state.pseudonym(space, slot).map(|p| *p.device_id()) else {
            return false;
        };
        let Some(replica) = state.replicas.get(space) else {
            return false;
        };
        let Some(log) = replica.log() else {
            return false;
        };
        let Some(cut) = log
            .event(c)
            .and_then(frasil_peers::skeleton::named_twin)
            .and_then(|twin| log.event(twin))
            .and_then(frasil_peers::cut::read_cut)
        else {
            return false;
        };
        let Some(enrolment) = log.chain(&pseudonym).into_iter().find(|id| {
            log.event(*id).is_some_and(|event| {
                matches!(
                    StorageBody::read(event.unverified_body()),
                    Ok(StorageBody::Enrol { .. })
                )
            })
        }) else {
            return false;
        };
        let named = cut
            .slots
            .iter()
            .any(|entry| entry.pseudonym == Some(enrolment));
        !named && log.follows(enrolment, c) != Ok(true)
    }

    /// Whether this device's newest pseudonym cannot sign in this world:
    /// it is late under the checkpoint it follows, or another pseudonym
    /// holds its slot. Only an empty slot is enrolled again (peers.md,
    /// "Skeleton cuts", "A late enrolment").
    pub(crate) fn pseudonym_late(state: &State, space: &EventId) -> bool {
        let Some(replica) = state.replicas.get(space) else {
            return false;
        };
        if state
            .pseudonyms
            .get(space)
            .and_then(|held| held.last())
            .is_some_and(|(slot, signer)| {
                replica
                    .enrolled(slot)
                    .is_some_and(|enrolled| enrolled != *signer.device_id())
            })
        {
            return true;
        }
        let facts = replica.checkpoint_facts();
        let Some(c) = facts.following.or(facts.last()) else {
            return false;
        };
        state
            .pseudonyms
            .get(space)
            .and_then(|held| held.last())
            .is_some_and(|(slot, _)| Self::enrolment_late(state, space, slot, c))
    }

    /// The skeleton events of the device's own pseudonyms in a space, the
    /// root aside, that no peer has acknowledged yet.
    fn own_skeleton_pending(state: &State, space: &EventId) -> Vec<EventId> {
        let Some(held) = state.pseudonyms.get(space) else {
            return Vec::new();
        };
        let Some(log) = state.replicas.get(space).and_then(Replica::log) else {
            return Vec::new();
        };
        // A late pseudonym's events are sent too: a peer stores a late
        // skeleton event without effect and acknowledges it, so that what
        // cites it, a vote among them, is placed (peers.md, "Skeleton
        // cuts", "Late skeleton events").
        let mine: BTreeSet<DeviceId> = held.iter().map(|(_, p)| *p.device_id()).collect();
        state
            .outboxes
            .get(space)
            .map(|outbox| {
                outbox
                    .pending()
                    .filter(|((author, _), id)| mine.contains(author) && !is_root(log, **id))
                    .map(|(_, id)| *id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Acknowledges awaited requests and snapshot units with a skeleton
    /// `ack` of this device's newest pseudonym in the space (peers.md,
    /// "Administration connections"; transport.md's awaiting report): its
    /// parents hold every awaited event the device holds. Returns the
    /// signed ack, or `None` when it holds none of them.
    ///
    /// # Errors
    ///
    /// The store's.
    #[cfg_attr(not(any(feature = "server", feature = "iroh")), allow(dead_code))]
    pub(crate) async fn acknowledge_awaited(
        &self,
        space: EventId,
        awaited: &[EventId],
    ) -> Result<Option<Vec<u8>>> {
        let mut state = self.lock().await;
        self.acknowledge_awaited_locked(&mut state, space, awaited)
            .await
    }

    /// As [`Self::acknowledge_awaited`], under the device's lock.
    pub(crate) async fn acknowledge_awaited_locked(
        &self,
        state: &mut State,
        space: EventId,
        awaited: &[EventId],
    ) -> Result<Option<Vec<u8>>> {
        let reading = self.read_timeline(state).await?;
        let Some((_, pseudonym)) = state.pseudonyms.get(&space).and_then(|p| p.last()) else {
            return Ok(None);
        };
        let author = *pseudonym.device_id();
        // A late pseudonym signs nothing after the checkpoint; nor does any,
        // an acknowledgement or a vote, while the skeleton and the roster
        // differ in this view (peers.md, 3.15).
        if Self::pseudonym_late(state, &space)
            || state
                .replicas
                .get(&space)
                .is_some_and(crate::replica::Replica::skeleton_differs)
        {
            return Ok(None);
        }
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        // Nothing is signed in a space that needs a later version.
        if replica.needs_later_version() {
            return Ok(None);
        }
        let Some(log) = replica.log() else {
            return Ok(None);
        };
        // A checkpoint the device does not build on is never cited: the
        // acknowledgement would vote for it (roster.md, 3.15.7, section 4).
        let avoided = replica.checkpoint_facts().avoided();
        let last = replica.checkpoint_facts().last();
        // A request of the past of the checkpoint in effect counts as
        // judged: any skeleton event after the checkpoint acknowledges it,
        // which never cites it, and one the device forgot it never fetches
        // (peers.md, 3.15, and "Skeleton cuts", "Requests of the cut's
        // past").
        let of_past =
            |id: &EventId| last.is_some_and(|c| !log.contains(*id) || log.precedes(*id, c));
        let held: Vec<EventId> = awaited
            .iter()
            .copied()
            .filter(|id| {
                log.contains(*id)
                    && !of_past(id)
                    && crate::checkpoints::reaches_avoided(log, &avoided, &[*id]).is_none()
            })
            .collect();
        let past = awaited.iter().any(of_past)
            && last.is_some_and(|c| {
                !log.events().any(|event| {
                    event.author() == &author
                        && (event.parents().contains(&c) || log.follows(event.id(), c) == Ok(true))
                })
            });
        if held.is_empty() && !past {
            return Ok(None);
        }
        let (seq, prev) = Self::next(state, &space, &author);
        let mut parents = replica.parents(prev);
        parents.extend(held);
        // An awaiting report can have been sent before a cut took effect.
        // Adding its requests must not reintroduce a concurrent event that
        // the checkpoint fence removed (peers.md, "The administrator's
        // duties"). An acknowledgement after the checkpoint suffices for
        // requests of its past, and a late request needs none.
        parents = crate::checkpoints::fence(
            log,
            replica.checkpoint_facts().following.or(last),
            prev,
            parents,
        );
        parents.sort_unstable();
        parents.dedup();
        parents.truncate(frasil_events::kind::MAX_PARENTS);
        let cuts = replica.cuts_for(&parents)?;
        let pseudonym = &state.pseudonyms[&space].last().expect("held").1;
        let signed = writer::storage_event(
            pseudonym,
            space,
            seq,
            prev,
            parents,
            cuts,
            &StorageBody::Ack,
        );
        let event = frasil_events::decode(&signed).map_err(Error::class)?;
        let mut batch = Batch {
            signs: true,
            ..Batch::default()
        };
        put_own(
            &state.vault,
            &mut batch,
            &space,
            &event,
            &pending_record(&event),
        )?;
        state.vault.commit(batch).await?;
        let id = event.id();
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        replica.place(vec![event.clone()]);
        state
            .outboxes
            .entry(space)
            .or_default()
            .add(*event.author(), event.seq(), id);
        self.settle(state, space, vec![id], reading).await?;
        Ok(Some(signed))
    }

    /// Signs a skeleton event of this device's newest pseudonym in the
    /// space, such as an erasure (peers.md, "Erasure"), and commits it: the
    /// device's administration connections take it to each peer.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] while the device holds no pseudonym there;
    /// [`Error::SyncBeforeWriting`]; the store's.
    pub(crate) async fn sign_skeleton(
        &self,
        space: EventId,
        body: &StorageBody,
    ) -> Result<EventId> {
        let mut state = self.lock().await;
        Self::check_may_sign(&state, &space)?;
        if Self::pseudonym_late(&state, &space) {
            return Err(Error::NotAllowed(
                "this pseudonym cannot sign in the current skeleton",
            ));
        }
        let author = *state
            .pseudonyms
            .get(&space)
            .and_then(|p| p.last())
            .ok_or(Error::NotAllowed(
                "the device holds no pseudonym in the space",
            ))?
            .1
            .device_id();
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let (seq, prev) = Self::next(&state, &space, &author);
        let parents = replica.parents(prev);
        let cuts = replica.cuts_for(&parents)?;
        let pseudonym = &state.pseudonyms[&space].last().expect("held").1;
        let signed = writer::storage_event(pseudonym, space, seq, prev, parents, cuts, body);
        self.commit_signed(&mut state, space, &signed).await
    }

    pub(crate) fn signer(&self) -> &Signer {
        &self.shared.keys.signer
    }

    /// The identity seed, which signs `Identify` (transport.md, "The
    /// member handshake: the initiator, and Identify").
    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    pub(crate) fn keys(&self) -> &Keys {
        &self.shared.keys
    }

    /// Commits, places and judges an event this device signed.
    pub(crate) async fn commit_signed(
        &self,
        state: &mut State,
        space: EventId,
        signed: &[u8],
    ) -> Result<EventId> {
        self.commit_own(state, space, signed, None).await
    }

    /// Takes list events into the device's lists, and judges every space
    /// again when one is new.
    pub(crate) async fn keep_lists(&self, state: &mut State, events: Vec<Vec<u8>>) -> Result<()> {
        if self.keep_list_events(state, events).await? {
            let reading = self.read_timeline(state).await?;
            let spaces: Vec<EventId> = state.replicas.keys().copied().collect();
            for space in spaces {
                Box::pin(self.settle_one(state, space, Vec::new(), reading)).await?;
            }
            Self::check_provisional_snapshots(state);
        }
        Ok(())
    }

    /// The identity seed, which the member handshake's endpoint key
    /// derives from.
    #[cfg(feature = "iroh")]
    pub(crate) fn identity_seed(&self) -> Secret {
        self.shared.keys.identity_seed.clone()
    }

    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    pub(crate) fn xwing_seed(&self) -> &Secret {
        &self.shared.keys.xwing_seed
    }

    /// The platform.
    pub fn platform(&self) -> &Platform {
        &self.shared.platform
    }

    /// The adapter registry.
    pub fn registry(&self) -> &AdapterRegistry {
        &self.shared.registry
    }

    /// What `continuity` found when the store was opened.
    pub async fn continuity(&self) -> Continuity {
        self.lock().await.vault.continuity()
    }

    /// Whether this device may sign in a space: always, unless it was
    /// restored and has not synced the space since (at-rest.md, "After a
    /// restore").
    pub async fn may_sign(&self, space: &EventId) -> bool {
        self.lock().await.vault.head().may_sign(&space.0)
    }

    /// What the device's member connections share.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) fn links(&self) -> std::sync::MutexGuard<'_, crate::links::Links> {
        self.shared
            .links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether a member connection serves a space: an attach of it is
    /// admitted.
    #[cfg_attr(
        not(all(
            any(feature = "server", feature = "iroh", feature = "server-socket"),
            feature = "adapter-blobs"
        )),
        allow(dead_code)
    )]
    pub(crate) fn member_attached(&self, space: &EventId) -> bool {
        self.links().attached(space)
    }

    /// Changes as they happen: events placed, by space.
    pub fn subscribe(&self) -> broadcast::Receiver<Notice> {
        self.shared.notices.subscribe()
    }

    pub(crate) fn notices(&self) -> &broadcast::Sender<Notice> {
        &self.shared.notices
    }

    /// Detected loss, from now on (units.md, 3.13 "Detected loss"): a peer
    /// that withholds or rolled back, and a member's junk head statement.
    pub fn losses(&self) -> broadcast::Receiver<Loss> {
        self.shared.losses.subscribe()
    }

    /// The spaces and classes of loss reported against a peer or a member
    /// since the device opened.
    pub fn lost_by(&self, by: &Acknowledger) -> BTreeSet<(EventId, LossClass)> {
        self.shared
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(who, _, _)| who == by)
            .map(|(_, space, class)| (*space, *class))
            .collect()
    }

    /// The spaces this device may sign in again after a restore, from now
    /// on, each once it has synced the space (at-rest.md, 3.6 "After a
    /// restore", step 2). A space it may already sign in is never sent.
    pub fn write_ready(&self) -> broadcast::Receiver<EventId> {
        self.shared.write_ready.subscribe()
    }

    /// Reports a loss: kept, and sent to every holder of [`Engine::losses`].
    pub(crate) fn report_loss(&self, loss: Loss) {
        self.shared
            .lost
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((loss.by, loss.space, loss.class));
        let _ = self.shared.losses.send(loss);
    }

    /// Objects as they become whole at this device, by space.
    #[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
    pub(crate) fn subscribe_arrivals(
        &self,
    ) -> broadcast::Receiver<(EventId, frasil_adapter::Locator)> {
        self.shared.arrivals.subscribe()
    }

    /// Tells blob feeds that an object became whole, and that it is no
    /// longer withdrawn.
    pub(crate) fn arrived(&self, space: EventId, locator: frasil_adapter::Locator) {
        let mut id = [0; 32];
        id.copy_from_slice(&locator[..32]);
        self.shared
            .withdrawn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(space, id));
        let _ = self.shared.arrivals.send((space, locator));
    }

    /// Notes that an object was read whole, every step passing.
    #[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
    pub(crate) fn mark_verified(&self, space: EventId, locator: frasil_adapter::Locator) {
        self.shared
            .verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((space, locator));
    }

    /// Whether an object was read whole since the device opened, and its
    /// stored bytes have not changed since: the replica still finds them
    /// to hash to the locator.
    #[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
    pub(crate) fn is_verified(&self, space: &EventId, locator: &frasil_adapter::Locator) -> bool {
        self.shared
            .verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&(*space, *locator))
    }

    /// Records that a held object was withdrawn.
    pub(crate) fn mark_withdrawn(&self, space: EventId, object_id: [u8; 32]) {
        self.shared
            .withdrawn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((space, object_id));
    }

    /// Whether a held object of the space was withdrawn since the device
    /// opened, and not held again.
    #[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
    pub(crate) fn is_withdrawn(&self, space: &EventId, object_id: &[u8; 32]) -> bool {
        self.shared
            .withdrawn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&(*space, *object_id))
    }

    pub(crate) fn shared_providers(&self) -> &std::sync::Mutex<crate::held::Providers> {
        &self.shared.providers
    }

    /// Whether a space is kept in memory only (at-rest.md, "A memory-only
    /// log"): its deposits are then kept in memory too.
    pub(crate) async fn is_memory_only(&self, space: &EventId) -> bool {
        self.lock().await.vault.is_memory_only(&space.0)
    }

    pub(crate) async fn lock_erasure(&self) -> MutexGuard<'_, ()> {
        self.shared.erasure_settling.lock().await
    }

    pub(crate) async fn lock(&self) -> MutexGuard<'_, State> {
        #[cfg_attr(not(feature = "partial-replicas"), allow(unused_mut))]
        let mut state = self.shared.state.lock().await;
        #[cfg(feature = "partial-replicas")]
        if self
            .shared
            .partial_unapplied
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            for replica in state.replicas.values_mut() {
                replica.make_partial();
            }
        }
        state
    }

    #[cfg_attr(not(feature = "ext-invite-links"), allow(unused_variables))]
    pub(crate) fn me(&self, state: &State) -> Me {
        Me {
            device: self.device_id(),
            xwing_seed: self.shared.keys.xwing_seed.clone(),
            #[cfg(feature = "ext-invite-links")]
            invites: state.invites.me(),
            recovering: state.recovering.as_ref().and_then(|r| r.opener()),
        }
    }

    // -- Time

    /// A reading of the device's timeline (overview.md, "The local
    /// timeline"). The device keeps one at rest at least once a minute.
    pub async fn reading(&self) -> Result<Reading> {
        let mut state = self.lock().await;
        self.read_timeline(&mut state).await
    }

    pub(crate) async fn read_timeline(&self, state: &mut State) -> Result<Reading> {
        let mono = self.shared.platform.clock.monotonic();
        let wall = self.shared.platform.clock.wall();
        let reading = state.timeline.read(mono, wall);
        if mono.saturating_sub(state.last_kept) >= KEEP_READING_EVERY {
            state.vault.keep_reading(&reading).await?;
            state.last_kept = mono;
        }
        Ok(reading)
    }

    /// [`read_timeline`](Self::read_timeline), keeping the reading at rest
    /// in `batch` when it is due, rather than in a commit of its own.
    fn read_timeline_in(
        state: &mut State,
        platform: &Platform,
        batch: &mut Batch,
    ) -> Result<Reading> {
        let mono = platform.clock.monotonic();
        let wall = platform.clock.wall();
        let reading = state.timeline.read(mono, wall);
        if mono.saturating_sub(state.last_kept) >= KEEP_READING_EVERY {
            state.vault.keep_reading_in(batch, &reading)?;
        }
        Ok(reading)
    }

    /// Keeps the timeline's reading at rest, as at shutdown.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn keep_reading(&self) -> Result<()> {
        let mut state = self.lock().await;
        let mono = self.shared.platform.clock.monotonic();
        let wall = self.shared.platform.clock.wall();
        let reading = state.timeline.read(mono, wall);
        state.vault.keep_reading(&reading).await?;
        state.last_kept = mono;
        Ok(())
    }

    // -- Loading

    async fn load(&self) -> Result<()> {
        let mut state = self.lock().await;
        let logs: Vec<([u8; 32], LogKind)> =
            state.vault.logs().map(|(id, kind)| (*id, kind)).collect();
        for (log, kind) in &logs {
            if *kind != LogKind::DeviceList {
                continue;
            }
            let mut events = Vec::new();
            for (_, value) in state.vault.scan(log, Table::Event).await? {
                if let TableValue::Event(record) = value
                    && let Ok(event) = frasil_events::decode(&record.signed)
                {
                    if let Some(reading) = record.first_sight {
                        state.list_sights.insert(event.id(), reading);
                    }
                    events.push(event);
                }
            }
            // A list this device forgot the earlier events of: its kept
            // checkpoint (key 7) and the IDs it dropped (identity.md, "List
            // checkpoints", "Forgetting").
            let kept = log_state(&state.vault, log).await?;
            let dropped: Vec<EventId> = checkpoint_records(&state.vault, log)
                .await?
                .dropped_ids()
                .map(EventId)
                .collect();
            if let Some(list) =
                crate::lists::from_events(&events, kept.kept_checkpoint.map(EventId), &dropped)
                    .or_else(|| crate::lists::from_events(&events, None, &[]))
            {
                state.lists.insert(*log, list);
            }
        }
        for (log, kind) in logs {
            if kind != LogKind::Space {
                continue;
            }
            let space = EventId(log);
            let mut replica = Replica::new(space);
            let mut events = Vec::new();
            // Decoded, each signature checked again, at once where there
            // are threads.
            let decoded = state
                .vault
                .scan_reading(
                    &log,
                    Table::Event,
                    crate::parallel::EVENT_WORK,
                    |_, value| match value {
                        // An event kept alone is never judged: it is read
                        // back with what the log keeps of its checkpoints.
                        TableValue::Event(record)
                            if record.state == frasil_store::tables::EventState::KeptAlone =>
                        {
                            Some(Err(record.signed))
                        }
                        TableValue::Event(record) => {
                            frasil_events::decode(&record.signed).ok().map(|event| {
                                // What forgetting froze of a kept unit: a
                                // unit whose content no path reached is
                                // valid by the write rule.
                                let frozen = record.frozen.as_ref().and_then(|at_rest| {
                                    crate::frozen::from_record(
                                        record.state,
                                        record.class.as_deref(),
                                        at_rest,
                                    )
                                });
                                let status = match &frozen {
                                    Some((_, status)) => Some(*status),
                                    None => recorded_status(&record),
                                };
                                Ok((record.first_sight, event, status, frozen.map(|f| f.0)))
                            })
                        }
                        _ => None,
                    },
                )
                .await?;
            // The verdicts the records keep: a log whose past before its
            // kept checkpoint this device forgot holds those of what it
            // kept of that past (roster.md, 3.15.6).
            let mut recorded = BTreeMap::new();
            let mut checkpoints = checkpoint_records(&state.vault, &log).await?;
            for decoded in decoded {
                let (first_sight, event, status, frozen) = match decoded {
                    Ok(decoded) => decoded,
                    Err(signed) => {
                        checkpoints.kept_envelopes.push(signed);
                        continue;
                    }
                };
                if let Some(reading) = first_sight {
                    replica.set_first_sight(event.id(), reading);
                }
                if let Some(status) = status {
                    recorded.insert(event.id(), status);
                }
                if let Some(frozen) = frozen {
                    if let Some(by) = frozen.voided_by.first() {
                        replica.checkpoints.recorded_by.insert(event.id(), *by);
                    }
                    replica.frozen_content.insert(event.id(), frozen);
                }
                events.push(event);
            }
            let mut recorded = Some(recorded);
            for (item, value) in state.vault.scan(&log, Table::Key).await? {
                if let TableValue::Key(KeyValue::Bundle(bundle)) = value {
                    match item.split_first() {
                        Some((&code, rest)) if code == StoredKeyKind::Rotation.code() => {
                            if let Ok(id) = <[u8; 32]>::try_from(rest) {
                                replica.keep_secrets(EventId(id), secrets_of(&bundle));
                            }
                        }
                        Some((&code, rest)) if code == StoredKeyKind::StateReceivedWhole.code() => {
                            if let (Ok(set), Some(content)) =
                                (RotationSet::decode(rest), &bundle.content)
                            {
                                replica.keep_state(set, Zeroizing::new(*content.expose()));
                            }
                        }
                        _ => {}
                    }
                }
            }
            let mut checkpoints = (!checkpoints.is_empty()).then_some(checkpoints);
            let mut claiming: Option<[u8; 32]> = None;
            for (_, value) in state.vault.scan(&log, Table::State).await? {
                // Key 6: a claim begun in this log and not signed
                // (ext-invite-links.md, "Records at rest").
                if let TableValue::State(log_state) = &value {
                    claiming = log_state.claiming;
                }
                // ext-guests.md's keys 3 and 4: the last completed sync, and
                // the grants a sent leave request named.
                #[cfg(feature = "ext-guests")]
                if let TableValue::State(log_state) = &value {
                    if let Some(at) = log_state.last_sync {
                        state.guests.last_sync.insert(EventId(log), at);
                    }
                    if let Some(grants) = &log_state.left {
                        state
                            .guests
                            .left
                            .insert(EventId(log), grants.iter().copied().map(EventId).collect());
                    }
                }
                // Key 8: the incarnations a lent document's holder expressed
                // again, whose units are not re-submitted.
                #[cfg(feature = "adapter-loro")]
                if let TableValue::State(log_state) = &value
                    && let Some(expressed) = &log_state.expressed_again
                {
                    state.expressed_again.extend(
                        expressed
                            .0
                            .iter()
                            .map(|(stream, incarnation)| (EventId(log), *stream, *incarnation)),
                    );
                }
                // Key 5: the person's personal space.
                if let TableValue::State(log_state) = &value
                    && log_state.personal
                {
                    state.personal_space = Some(EventId(log));
                }
                // The record keys, dropped IDs and kept envelopes of a log
                // that forgot its past or started from a checkpoint, in
                // records of their own.
                if let TableValue::State(log_state) = &value
                    && let Some(checkpoints) = checkpoints.take()
                {
                    replica
                        .restore_checkpoint_state(log_state.kept_checkpoint.is_some(), checkpoints);
                }
                // Key 7: the kept checkpoint of a log that forgot what came
                // before it, placed on the heights its `dropped` records
                // keep, or that started from it, from a snapshot's base below.
                if let TableValue::State(log_state) = &value
                    && let Some(checkpoint) = log_state.kept_checkpoint
                {
                    if replica.forgot_some() {
                        replica.set_forgotten(
                            EventId(checkpoint),
                            recorded.take().unwrap_or_default(),
                        );
                    } else {
                        replica.start_from_kept(EventId(checkpoint));
                    }
                }
                if let TableValue::State(log_state) = value
                    && let Some(heads) = log_state.base_heads
                {
                    let stubs = log_state
                        .base_stubs
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|bytes| {
                            frasil_base::cbor::decode(bytes)
                                .ok()
                                .and_then(|value| frasil_units::Stub::read(&value).ok())
                        })
                        .collect();
                    replica.set_base(heads.into_iter().map(EventId).collect(), stubs);
                }
            }
            // A log with no `state` record that keeps checkpoint records.
            if let Some(checkpoints) = checkpoints {
                replica.restore_checkpoint_state(false, checkpoints);
            }
            for (item, value) in state.vault.scan(&log, Table::Key).await? {
                if let TableValue::Key(KeyValue::BodyKey(body)) = value
                    && item.first() == Some(&StoredKeyKind::BodyKey.code())
                    && let Ok(id) = <[u8; 32]>::try_from(&item[1..])
                {
                    replica.keep_bodies(&[(EventId(id), *body.key.expose())]);
                }
            }
            // Objects: each header is read, and of its chunks only which
            // the store holds; the chunks are read back when an object is
            // served or opened, and its locator found then (at-rest.md,
            // "Tables").
            let sizes = state.vault.scan_sizes(&log, Table::Object).await?;
            let addresses: BTreeSet<&[u8]> = sizes.iter().map(|(a, _)| a.as_slice()).collect();
            let mut headers: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
            for (address, size) in &sizes {
                // A header is small; a chunk is read only when needed.
                if *size > OBJECT_HEADER_RECORD_BYTES {
                    continue;
                }
                if let Some((item, TableValue::Object(bytes))) =
                    state.vault.get_at(&log, address).await?
                    && item.len() == 36
                    && item[32..] == [0; 4]
                {
                    let mut id = [0; 32];
                    id.copy_from_slice(&item[..32]);
                    headers.insert(id, bytes);
                }
            }
            // Held objects: the record and the header, and no chunks. A
            // held record beside a chunk record is Malformed, and the
            // chunk records win (at-rest.md, "Tables").
            let mut held_records: BTreeMap<[u8; 32], frasil_store::tables::HeldRecord> =
                BTreeMap::new();
            for (item, value) in state.vault.scan(&log, Table::Held).await? {
                if let (TableValue::Held(record), Ok(id)) = (value, <[u8; 32]>::try_from(&item[..]))
                {
                    held_records.insert(id, record);
                }
            }
            for (id, header) in headers {
                let count = frasil_units::objects::Header::read(&header)
                    .map(|h| {
                        frasil_units::objects::chunk_count(
                            h.size,
                            frasil_units::limits::CHUNK_BYTES as u64,
                        )
                    })
                    .unwrap_or(0);
                let stored: BTreeSet<u64> = (0..count)
                    .filter(|index| {
                        let Ok(part) = crate::objects::chunk_part(*index) else {
                            return false;
                        };
                        let mut item = id.to_vec();
                        item.extend_from_slice(&part.to_be_bytes());
                        state
                            .vault
                            .address(&log, Table::Object, &item)
                            .is_some_and(|address| addresses.contains(address.as_slice()))
                    })
                    .collect();
                if stored.is_empty()
                    && let Some(record) = held_records.remove(&id)
                {
                    Self::load_held(&mut state, space, id, record, header);
                    continue;
                }
                replica.keep_stored_object(id, header, stored);
            }
            let mut outbox = Outbox::default();
            for (item, value) in state.vault.scan(&log, Table::Outbox).await? {
                if let TableValue::Outbox(id) = value
                    && item.len() == 40
                {
                    let mut author = [0; 32];
                    author.copy_from_slice(&item[..32]);
                    let seq = u64::from_be_bytes(item[32..].try_into().expect("8 bytes"));
                    outbox.add(DeviceId(author), seq, EventId(id));
                }
            }
            for (item, value) in state.vault.scan(&log, Table::Ack).await? {
                if let TableValue::Ack(heads) = value
                    && let Ok(id) = <[u8; 32]>::try_from(&item[..])
                {
                    outbox.keep_ack(
                        Acknowledger::Member(id),
                        heads.into_iter().map(EventId).collect(),
                    );
                }
            }
            let mut pseudonyms = Vec::new();
            for (item, value) in state.vault.scan(&log, Table::Pseudonym).await? {
                if let TableValue::Pseudonym(Pseudonym {
                    seeds: Some((ed, mldsa)),
                    ..
                }) = value
                    && let Some(slot) = read_slot(&item)
                {
                    // A pseudonym has no X-Wing key (peers.md).
                    pseudonyms.push((slot, Signer::from_seeds(ed.expose(), mldsa.expose(), None)));
                }
            }
            #[cfg(feature = "ext-recovery-agent")]
            for (item, value) in state.vault.scan(&log, Table::Vouched).await? {
                if let (TableValue::Vouched(person), Ok(device)) =
                    (value, <[u8; 32]>::try_from(&item[..]))
                {
                    state
                        .agents
                        .vouched
                        .entry(space)
                        .or_default()
                        .insert(DeviceId(device), person);
                }
            }
            #[cfg(feature = "ext-invite-links")]
            for table in frasil_store::ext_invite_links::TABLES {
                for (_, value) in state.vault.scan(&log, table).await? {
                    state.invites.keep(&value);
                }
            }
            // A claim that never finished: the device stopped before the
            // person decided, and no `claim` record backs the log. It is
            // forgotten, as a declined claim is.
            if let Some(entry) = claiming {
                let signed = {
                    #[cfg(feature = "ext-invite-links")]
                    {
                        state.invites.claimed.contains_key(&EventId(entry))
                    }
                    #[cfg(not(feature = "ext-invite-links"))]
                    {
                        let _ = entry;
                        false
                    }
                };
                if !signed {
                    // Set aside, with its held objects known: it is
                    // forgotten through the space's object provider, which
                    // a client attaches after the load, by
                    // `forget_stale_claims`.
                    state.stale_claims.push(space);
                    continue;
                }
            }
            // A space dropped for the device's own erasure: its `log` and
            // `pseudonym` records, and the erasure's own `event` record. It
            // takes part in nothing but presenting the erasure and learning
            // the peers' answers (at-rest.md, 3.4).
            if let Some(residue) = crate::erasing::Residue::found(&events, &pseudonyms, &replica) {
                state.pseudonyms.insert(space, pseudonyms);
                state.erasing.insert(space, residue);
                continue;
            }
            replica.place(events);
            replica.take_restored_dropped();
            // A partial replica keeps the streams it holds units of, and
            // its first resolution, below, is a partial replica's.
            #[cfg(feature = "partial-replicas")]
            if self.is_partial() {
                replica.make_partial();
            }
            state.replicas.insert(space, replica);
            state.outboxes.insert(space, outbox);
            state.pseudonyms.insert(space, pseudonyms);
        }
        // Each space reads the others it grants: twice, so a granted
        // space's facts are in place for the space that grants it.
        let spaces: Vec<EventId> = state.replicas.keys().copied().collect();
        #[cfg(feature = "ext-recovery-agent")]
        let now = self.read_timeline(&mut state).await?;
        // A third pass refreshes the spaces whose refresh needed objects the
        // store holds, once those are read back.
        for pass in 0..3 {
            // Once the first pass derived the keys, a replica that started
            // from a space snapshot takes its stream entries again, which
            // the next passes load.
            if pass == 1 {
                for space in &spaces {
                    Self::recover_snapshot(&mut state, *space).await?;
                }
            }
            let mut todo = Vec::new();
            for space in &spaces {
                if pass < 2 || Self::fill_wanted(&mut state, space).await? {
                    todo.push(*space);
                }
            }
            for space in &todo {
                let mut replica = state.replicas.remove(space).expect("loaded");
                let views: Vec<(EventId, crate::granted::GrantedView<'_>)> = state
                    .replicas
                    .iter()
                    .filter_map(|(id, r)| {
                        r.facts()
                            .map(|f| (*id, crate::granted::GrantedView::new(f, &state.lists)))
                    })
                    .collect();
                let facts: BTreeMap<EventId, &crate::granted::GrantedView<'_>> =
                    views.iter().map(|(id, view)| (*id, view)).collect_map();
                let grant_seeds: BTreeMap<EventId, BTreeMap<EventId, [u8; 32]>> = state
                    .replicas
                    .iter()
                    .map(|(id, r)| (*id, r.grant_seeds()))
                    .collect_map();
                replica.refresh(
                    &self.me(&state),
                    &self.shared.registry,
                    &crate::replica::Others {
                        lists: &state.lists,
                        spaces: &facts,
                        grant_seeds: &grant_seeds,
                        keys: &state.ring,
                        #[cfg(feature = "ext-recovery-agent")]
                        agents: Some(crate::recovery_agent::Agents {
                            now,
                            sights: &state.list_sights,
                            vouched: state.agents.vouched.get(space),
                        }),
                        #[cfg(feature = "ext-restricted-spaces")]
                        replicas: &state.replicas,
                    },
                );
                state.replicas.insert(*space, replica);
            }
        }
        for replica in state.replicas.values_mut() {
            replica.release_chunks();
        }
        // A provisional snapshot, checked with every key held now.
        Self::check_provisional_snapshots(&mut state);
        // A newcomer that restarts before it used its snapshot asks a
        // member for one (admission.md, "The newcomer's snapshot").
        let me = self.device_id();
        for replica in state.replicas.values_mut() {
            replica.notice_unused_snapshot(&me);
        }
        // Held records count as held once a provider is given.
        self.providers_changed();
        Ok(())
    }

    // -- Spaces

    /// The spaces this device keeps.
    pub async fn spaces(&self) -> Vec<EventId> {
        self.lock().await.replicas.keys().copied().collect()
    }

    /// Forgets the logs a claim began and never finished, found at load
    /// (ext-invite-links.md, "Records at rest"), as [`Engine::forget_space`]
    /// does: the space's object provider hears of each held object first,
    /// so a claim from a file that pushed the file's objects to it leaves
    /// no orphan. A client calls this once its providers are attached;
    /// [`Engine::maintain_all`] calls it too.
    ///
    /// # Errors
    ///
    /// The provider's; the store's.
    pub async fn forget_stale_claims(&self) -> Result<()> {
        let stale = std::mem::take(&mut self.lock().await.stale_claims);
        for space in stale {
            // A space held again since the load, as when the person opened
            // the same file again, is that claim's now: its log and objects
            // are no longer the stale claim's to forget.
            let held = {
                let mut state = self.lock().await;
                if state.replicas.contains_key(&space) {
                    continue;
                }
                self.take_held(&mut state, &space)
            };
            if let Some((provider, tokens)) = held {
                for token in tokens {
                    provider.forget(&token).await?;
                }
            }
            let mut state = self.lock().await;
            if !state.replicas.contains_key(&space) {
                state.vault.forget(&space.0).await?;
            }
        }
        Ok(())
    }

    /// The spaces the device presents to peers and maintains: every space
    /// it holds but one whose claim from a space file waits for the
    /// person's consent (ext-invite-links.md, "Records at rest"). A claim
    /// by link stays presented: its connections fetch the space with the
    /// fetch key the drop gives ("Claiming", step 4).
    pub async fn presentable_spaces(&self) -> Vec<EventId> {
        let state = self.lock().await;
        state
            .replicas
            .keys()
            .copied()
            .filter(|space| {
                #[cfg(feature = "ext-invite-links")]
                {
                    state
                        .invites
                        .claiming
                        .get(space)
                        .is_none_or(|claim| claim.fetches)
                }
                #[cfg(not(feature = "ext-invite-links"))]
                {
                    let _ = space;
                    true
                }
            })
            .collect()
    }

    /// Reads a space's replica.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn read<R>(&self, space: &EventId, f: impl FnOnce(&Replica) -> R) -> Result<R> {
        let state = self.lock().await;
        state.replicas.get(space).map(f).ok_or(Error::UnknownSpace)
    }

    /// Starts following a space this device was told of, such as one it
    /// was admitted to: its events are placed as they arrive, the genesis
    /// first.
    pub async fn follow(&self, space: EventId) {
        #[cfg(feature = "partial-replicas")]
        let partial = self.is_partial();
        let mut state = self.lock().await;
        #[cfg_attr(not(feature = "partial-replicas"), allow(unused_variables))]
        let replica = state
            .replicas
            .entry(space)
            .or_insert_with(|| Replica::new(space));
        #[cfg(feature = "partial-replicas")]
        if partial {
            replica.make_partial();
        }
        state.outboxes.entry(space).or_default();
    }

    // -- Partial replicas (units.md, "Partial replicas")

    /// Makes every replica partial, now and from now on: each holds its
    /// space's frame (its space events, anchors, storage events and system
    /// stream) and the streams this device opens or writes in, and
    /// witnesses any other event it fetches. A replica already loaded
    /// resolves as a partial one from its next resolution; a device opened
    /// with [`Platform::holding_streams_only`] does from its first.
    #[cfg(feature = "partial-replicas")]
    pub fn hold_streams_only(&self) {
        self.shared
            .partial
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.shared
            .partial_unapplied
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Fetches blobs only when the application asks for them, with
    /// [`Engine::fetch_object`]: a device-local choice of what to fetch,
    /// which no peer or member can see.
    pub fn fetch_objects_on_demand(&self) {
        self.shared
            .objects_on_demand
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Sets the device's checkpoint policy: whether its administrators'
    /// client proposes checkpoints by itself, and whether it forgets what
    /// came before one in effect (roster.md, 3.15.7 Clients).
    pub fn set_checkpoint_policy(&self, policy: crate::checkpoints::CheckpointPolicy) {
        *self
            .shared
            .checkpoint_policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
    }

    /// The device's checkpoint policy.
    pub fn checkpoint_policy(&self) -> crate::checkpoints::CheckpointPolicy {
        *self
            .shared
            .checkpoint_policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether this device fetches blobs only when asked.
    pub(crate) fn objects_on_demand(&self) -> bool {
        self.shared
            .objects_on_demand
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether this device's replicas are partial: never without the
    /// `partial-replicas` feature.
    pub fn is_partial(&self) -> bool {
        #[cfg(feature = "partial-replicas")]
        return self
            .shared
            .partial
            .load(std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(feature = "partial-replicas"))]
        false
    }

    /// Opens a stream at a partial replica: it places the stream's units
    /// from now on, those it witnessed among them at once, and its
    /// connections fetch the rest. Nothing changes at a full replica.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; the store's.
    #[cfg_attr(not(feature = "partial-replicas"), allow(unused_variables))]
    pub async fn hold_stream(&self, space: EventId, stream: StreamId) -> Result<()> {
        if !self.is_partial() {
            return Ok(());
        }
        #[cfg(feature = "partial-replicas")]
        self.hold_stream_now(space, stream).await?;
        Ok(())
    }

    #[cfg(feature = "partial-replicas")]
    async fn hold_stream_now(&self, space: EventId, stream: StreamId) -> Result<()> {
        let mut state = self.lock().await;
        let reading = self.read_timeline(&mut state).await?;
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        replica.make_partial();
        if replica
            .held_streams()
            .is_some_and(|held| held.contains(&stream))
        {
            return Ok(());
        }
        let placed = replica.hold_stream(stream);
        self.settle(&mut state, space, placed.clone(), reading)
            .await?;
        drop(state);
        // Connections fetch the stream, and subscribe to it.
        let _ = self.shared.notices.send(Notice {
            space,
            placed,
            withdrawn: Vec::new(),
            wanted: Vec::new(),
        });
        Ok(())
    }

    /// Takes a `Path` another party sent (units.md, "Sync messages"): one
    /// that checks witnesses its events, and the space is judged again.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; the store's.
    #[cfg(feature = "partial-replicas")]
    pub async fn add_path(
        &self,
        space: EventId,
        from: EventId,
        to: EventId,
        signed: Vec<Vec<u8>>,
    ) -> Result<Vec<EventId>> {
        let path: Vec<Event> = signed
            .iter()
            .filter_map(|bytes| crate::intake::read_event(bytes).ok())
            .collect();
        let mut state = self.lock().await;
        let reading = self.read_timeline(&mut state).await?;
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        let placed = replica.add_path(from, to, path);
        self.settle(&mut state, space, placed.clone(), reading)
            .await?;
        drop(state);
        if !placed.is_empty() {
            let _ = self.shared.notices.send(Notice {
                space,
                placed: placed.clone(),
                withdrawn: Vec::new(),
                wanted: Vec::new(),
            });
        }
        Ok(placed)
    }

    /// A key for the application's own data (at-rest.md, "Application
    /// keys"): `app_key(s, purpose)` under the store secret for `None`,
    /// `app_key(L, purpose)` under a space's log key otherwise. Frasil
    /// neither stores nor uses it.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`] for a space whose log the device does not
    /// keep.
    pub async fn app_key(
        &self,
        space: Option<&EventId>,
        purpose: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let state = self.lock().await;
        state
            .vault
            .app_key(space.map(|s| &s.0), purpose)
            .ok_or(Error::UnknownSpace)
    }

    /// Forgets a space (at-rest.md, "Forgetting a log, and re-keying"):
    /// its `log` record goes in one commit, then its other records, after
    /// which nothing of it the medium still holds opens.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn forget_space(&self, space: &EventId) -> Result<()> {
        // The provider hears of each held object before the records go
        // (at-rest.md, "Held objects", forgetting and collecting), with the
        // state unlocked.
        let held = {
            let mut state = self.lock().await;
            self.take_held(&mut state, space)
        };
        if let Some((provider, tokens)) = held {
            for token in tokens {
                provider.forget(&token).await?;
            }
        }
        let mut state = self.lock().await;
        state.vault.forget(&space.0).await?;
        state.replicas.remove(space);
        state.outboxes.remove(space);
        state.pseudonyms.remove(space);
        state.erasing.remove(space);
        // A space no longer followed: its ephemeral replay state goes
        // (ext-ephemeral.md, "Epoch, counter and replay").
        #[cfg(feature = "ephemeral")]
        if let Some(ephemeral) = state.ephemeral.as_mut() {
            ephemeral.forget_space(space);
        }
        #[cfg(feature = "ext-invite-links")]
        state.invites.claimed.retain(|_, kept| kept.space != *space);
        Ok(())
    }

    /// Whether this device may drop a space for its own erasure now: it
    /// holds an erasure of its own pseudonyms that no checkpoint made late
    /// and that every peer it reaches has acknowledged, and no checkpoint
    /// that can still take effect is concurrent with it, which could make
    /// it late (peers.md, "Erasure", "At replicas"). Until then it keeps the
    /// space, and signs a late erasure again after the checkpoint.
    pub async fn own_erasure_droppable(&self, space: &EventId) -> bool {
        let state = self.lock().await;
        let Some(replica) = state.replicas.get(space) else {
            return false;
        };
        let Some(log) = replica.log() else {
            return false;
        };
        let mine: BTreeSet<DeviceId> = state.pseudonym_ids(space).into_iter().collect();
        let outbox: BTreeSet<EventId> = state
            .outboxes
            .get(space)
            .map(|outbox| outbox.pending().map(|(_, id)| *id).collect())
            .unwrap_or_default();
        let facts = replica.checkpoint_facts();
        // Execution can win the race with the store acknowledgement. A
        // tombstone still proves durability of this device's erasure.
        let executed = self.erased_at_peer(space);
        let erasures: Vec<EventId> = log
            .frame_events()
            .filter(|event| event.kind() == kind::STORAGE && mine.contains(event.author()))
            .filter(|event| {
                matches!(
                    frasil_peers::body::StorageBody::read(event.unverified_body()),
                    Ok(frasil_peers::body::StorageBody::Erase)
                )
            })
            .map(Event::id)
            .filter(|id| {
                replica.status(id).is_some_and(|status| status.is_valid())
                    && !facts.late.contains(id)
                    && (executed || !outbox.contains(id))
            })
            .collect();
        erasures.iter().any(|&erasure| {
            facts.pending.iter().all(|pending| {
                let k = pending.checkpoint;
                log.precedes(erasure, k) || log.follows(erasure, k) == Ok(true)
            })
        })
    }

    /// Makes a space: its genesis, which grants this device `administer`
    /// as founder, and the skeleton's root under a fresh administrator
    /// pseudonym (roster.md, "The roster part"; peers.md, "The skeleton").
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`]; the store's.
    pub async fn create_space(&self) -> Result<EventId> {
        self.create_space_with(Policy::default()).await
    }

    /// Makes a space with a policy (roster.md, "The space policy").
    ///
    /// # Errors
    ///
    /// As [`create_space`](Self::create_space).
    pub async fn create_space_with(&self, policy: Policy) -> Result<EventId> {
        self.create_space_as(policy, frasil_space::Descriptor::ORDINARY)
            .await
    }

    /// Makes a space with a policy and a descriptor (roster.md, "The space
    /// descriptor"): a restricted space's names its parent, and it draws no
    /// grant seed (ext-restricted-spaces.md).
    pub(crate) async fn create_space_as(
        &self,
        policy: Policy,
        descriptor: frasil_space::Descriptor,
    ) -> Result<EventId> {
        // Keep creation temporaries out of the caller's future.
        Box::pin(self.create_space_as_inner(policy, descriptor)).await
    }

    async fn create_space_as_inner(
        &self,
        policy: Policy,
        descriptor: frasil_space::Descriptor,
    ) -> Result<EventId> {
        let platform = &self.shared.platform;
        let made = writer::new_space(
            platform,
            &self.shared.keys.signer,
            &self.shared.keys.public,
            policy,
            descriptor,
        )?;
        let space = made.genesis.id;
        let pseudonym = Signer::from_seeds(&made.pseudonym.0, &made.pseudonym.1, None);
        let mut state = self.lock().await;
        let reading = self.read_timeline(&mut state).await?;
        let mut batch = Batch {
            signs: true,
            ..Batch::default()
        };
        state.vault.add_log(&mut batch, &space.0, LogKind::Space)?;
        let genesis = frasil_events::decode(&made.genesis.signed).map_err(Error::class)?;
        let root = frasil_events::decode(&made.root).map_err(Error::class)?;
        let fresh = made.genesis.fresh.as_ref().expect("a genesis rotates");
        let secrets = RotationSecrets {
            content: Some(fresh.content.clone()),
            upload: Some(fresh.upload.clone()),
            grant: made.genesis.grant_rotation.then(|| fresh.grant.clone()),
        };
        put_rotation(&state.vault, &mut batch, &space, &space, &secrets)?;
        let slot = slot_item(SlotId::new(made.slot, 0, root.id()));
        state.vault.put(
            &mut batch,
            &space.0,
            Table::Pseudonym,
            &slot,
            &TableValue::Pseudonym(Pseudonym {
                token: None,
                seeds: Some((
                    StoredSecret::new(*made.pseudonym.0),
                    StoredSecret::new(*made.pseudonym.1),
                )),
            }),
        )?;
        for event in [&genesis, &root] {
            put_own(
                &state.vault,
                &mut batch,
                &space,
                event,
                &pending_record(event),
            )?;
        }
        state.vault.commit(batch).await?;

        let mut replica = Replica::new(space);
        replica.keep_secrets(space, secrets);
        replica.place(vec![genesis.clone(), root.clone()]);
        let mut outbox = Outbox::default();
        outbox.add(*genesis.author(), 1, genesis.id());
        outbox.add(*root.author(), 1, root.id());
        state.replicas.insert(space, replica);
        state.outboxes.insert(space, outbox);
        state.pseudonyms.insert(
            space,
            vec![(SlotId::new(made.slot, 0, root.id()), pseudonym)],
        );
        let placed = vec![genesis.id(), root.id()];
        self.settle(&mut state, space, placed.clone(), reading)
            .await?;
        drop(state);
        let _ = self.shared.notices.send(Notice {
            space,
            placed,
            withdrawn: Vec::new(),
            wanted: Vec::new(),
        });
        Ok(space)
    }

    /// Refreshes a replica and stores what changed: verdicts in `event`
    /// records, and keys taken.
    pub(crate) async fn settle(
        &self,
        state: &mut State,
        space: EventId,
        new: Vec<EventId>,
        reading: Reading,
    ) -> Result<()> {
        let lists = list_events(&state.lists);
        Box::pin(self.settle_one(state, space, new, reading)).await?;
        // Every other space reads this one's roster, if it grants it, and
        // the lists this one carried. Each is judged again only when what
        // it reads changed: the lists, what the spaces settled here offer
        // others (granted facts, keys, space events), or, for a space whose
        // view names their logs, waits on an event or is their parent or
        // child, their logs.
        let lists_changed = list_events(&state.lists) != lists;
        // Changes left by spaces settled alone count too.
        let mut sources: Vec<(EventId, bool, bool)> = state
            .replicas
            .iter_mut()
            .map(|(id, replica)| {
                let (for_others, log) = replica.take_changes();
                (*id, for_others, log)
            })
            .filter(|(_, for_others, log)| *for_others || *log)
            .collect();
        let others: Vec<EventId> = state
            .replicas
            .iter()
            .filter(|(id, replica)| {
                **id != space && (!state.lists.is_empty() || !replica.independent_of_other_logs())
            })
            .map(|(id, _)| *id)
            .collect();
        for other in others {
            let Some(replica) = state.replicas.get(&other) else {
                continue;
            };
            let due = lists_changed
                || sources.iter().any(|(source, for_others, log)| {
                    *source != other
                        && (*for_others
                            || (*log
                                && state
                                    .replicas
                                    .get(source)
                                    .is_some_and(|source| replica.may_read_log_of(source))))
                });
            if !due {
                continue;
            }
            Box::pin(self.settle_one(state, other, Vec::new(), reading)).await?;
            if let Some(replica) = state.replicas.get_mut(&other) {
                let (for_others, log) = replica.take_changes();
                sources.push((other, for_others, log));
            }
        }
        Self::check_provisional_snapshots(state);
        Ok(())
    }

    /// Checks again each provisional space snapshot's ML-DSA-65 half, with
    /// the keys the device holds now (units.md, "The space snapshot",
    /// "Using it", step 3): no resolution reads a snapshot. Keys from
    /// records reach every space's resolution through the lists and spaces
    /// the device holds, and the settle that brings them judges again the
    /// spaces that read them.
    fn check_provisional_snapshots(state: &mut State) {
        let outcomes: Vec<(EventId, Option<crate::replica::SnapshotCheck>)> = state
            .replicas
            .iter()
            .filter(|(_, replica)| replica.snapshot_provisional())
            .map(|(id, replica)| (*id, replica.read_provisional_snapshot(&state.keys())))
            .collect();
        for (id, outcome) in outcomes {
            if let Some(replica) = state.replicas.get_mut(&id) {
                replica.apply_provisional_snapshot(outcome);
            }
        }
    }

    /// Takes a holder's three keys learned outside any record the device
    /// holds, such as in an admission exchange, into its key ring, and
    /// judges again whatever waited for them (crypto.md, "Keys by their
    /// hash"): each list's events, and each space whose view holds an event
    /// whose ML-DSA-65 half waited for keys. Keys the ring holds already
    /// change nothing. Keys name no one: they are used only where they hash
    /// to the commitment or device ID a check asks for.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn learn_keys(&self, keys: PublicKeys) -> Result<()> {
        let mut state = self.lock().await;
        if !state.ring.add_device(keys) {
            return Ok(());
        }
        let reading = self.read_timeline(&mut state).await?;
        let State {
            lists,
            replicas,
            ring,
            ..
        } = &mut *state;
        let mut lists_changed = false;
        for list in lists.values_mut() {
            lists_changed |= !list.verify_with(&*ring).is_empty();
        }
        let mut due = Vec::new();
        for (id, replica) in replicas.iter_mut() {
            if lists_changed || replica.awaits_keys() {
                replica.verify_pending_hybrid(ring);
                due.push(*id);
            }
        }
        for space in due {
            self.settle(&mut state, space, Vec::new(), reading).await?;
        }
        Self::check_provisional_snapshots(&mut state);
        Ok(())
    }

    /// Refreshes one replica against the other logs the device holds, takes
    /// the list copies it carries, and stores what changed.
    pub(crate) async fn settle_one(
        &self,
        state: &mut State,
        space: EventId,
        new: Vec<EventId>,
        reading: Reading,
    ) -> Result<()> {
        let me = self.me(state);
        let holdings = self.peer_holdings_of(state, &space);
        #[cfg_attr(not(feature = "partial-replicas"), allow(unused_mut))]
        let mut replica = state.replicas.remove(&space).ok_or(Error::UnknownSpace)?;
        replica.checkpoints.peer_holdings = holdings;
        #[cfg(feature = "partial-replicas")]
        if self.is_partial() {
            replica.make_partial();
        }
        let mut refreshed;
        let mut rounds = 0;
        let mut fills = 0;
        let mut earlier = crate::replica::Refreshed::default();
        loop {
            refreshed = {
                let views: Vec<(EventId, crate::granted::GrantedView<'_>)> = state
                    .replicas
                    .iter()
                    .filter_map(|(id, r)| {
                        r.facts()
                            .map(|f| (*id, crate::granted::GrantedView::new(f, &state.lists)))
                    })
                    .collect();
                let facts: BTreeMap<EventId, &crate::granted::GrantedView<'_>> =
                    views.iter().map(|(id, view)| (*id, view)).collect_map();
                let grant_seeds: BTreeMap<EventId, BTreeMap<EventId, [u8; 32]>> = state
                    .replicas
                    .iter()
                    .map(|(id, r)| (*id, r.grant_seeds()))
                    .collect_map();
                replica.refresh(
                    &me,
                    &self.shared.registry,
                    &crate::replica::Others {
                        lists: &state.lists,
                        spaces: &facts,
                        grant_seeds: &grant_seeds,
                        keys: &state.ring,
                        #[cfg(feature = "ext-recovery-agent")]
                        agents: Some(crate::recovery_agent::Agents {
                            now: reading,
                            sights: &state.list_sights,
                            vouched: state.agents.vouched.get(&space),
                        }),
                        #[cfg(feature = "ext-restricted-spaces")]
                        replicas: &state.replicas,
                    },
                )
            };
            // Objects the refresh needed whose chunks are in the store: read
            // back, and the replica refreshed again with them.
            let wanted = replica.take_wanted_at_rest();
            if !wanted.is_empty() && fills < 2 {
                fills += 1;
                for locator in wanted {
                    // Boxed: its reader and stream stay off this future.
                    if Box::pin(crate::objects::read_stored_records(
                        &state.vault,
                        &mut replica,
                        &space,
                        &locator,
                    ))
                    .await?
                    {
                        continue;
                    }
                    let Some((_, indices)) = replica.stored_parts(&locator) else {
                        continue;
                    };
                    if let Some(chunks) =
                        crate::objects::read_chunks(&state.vault, &space, &locator, &indices)
                            .await?
                    {
                        replica.fill_chunks(&locator, chunks);
                    }
                }
                earlier.absorb(std::mem::take(&mut refreshed));
                continue;
            }
            let copies = std::mem::take(&mut refreshed.list_events);
            rounds += 1;
            if copies.is_empty() || rounds > 4 {
                break;
            }
            if !self.keep_list_events(state, copies).await? {
                break;
            }
        }
        replica.release_chunks();
        earlier.absorb(refreshed);
        let refreshed = earlier;
        state.replicas.insert(space, replica);
        // A guest asked to keep nothing at rest keeps the space in memory
        // only (ext-guests.md, "Nothing at rest").
        #[cfg(feature = "ext-guests")]
        Self::keep_guest_in_memory(state, &space).await?;
        let State {
            vault,
            replicas,
            foreseen,
            #[cfg(feature = "ext-recovery-agent")]
                agents: state_agents,
            ..
        } = state;
        let replica = replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        let mut batch = Batch::default();
        if !vault.has_log(&space.0) {
            vault.add_log(&mut batch, &space.0, LogKind::Space)?;
        }
        // The adopted snapshot's sender, once the view grants this device:
        // one that does not reach the space loses its base (units.md, "The
        // space snapshot", "Using it"). A base discarded is not kept.
        replica.check_snapshot_sender(&self.device_id());
        if replica.take_base_discarded() {
            let kept = log_state(vault, &space.0).await?;
            let without = LogState {
                base_heads: None,
                base_stubs: None,
                ..kept
            };
            if without == LogState::default() {
                vault.delete(&mut batch, &space.0, Table::State, &[]);
            } else {
                vault.put(
                    &mut batch,
                    &space.0,
                    Table::State,
                    &[],
                    &TableValue::State(without),
                )?;
            }
        }
        for id in &refreshed.taken {
            if let Some(secrets) = replica.secrets_of(id).cloned() {
                put_rotation(vault, &mut batch, &space, id, &secrets)?;
            }
        }
        // The waiting list members the space vouches for now: each new
        // decision kept before any wrap made on it, and each record of a
        // member no longer vouched for (no longer active) deleted.
        #[cfg(feature = "ext-recovery-agent")]
        {
            let decided = replica.vouched().clone();
            let kept = state_agents.vouched.entry(space).or_default();
            for (person, devices) in &decided {
                for device in devices {
                    if kept.insert(*device, *person).is_none() {
                        vault.put(
                            &mut batch,
                            &space.0,
                            Table::Vouched,
                            &device.0,
                            &TableValue::Vouched(*person),
                        )?;
                        state_agents
                            .deliveries
                            .entry(space)
                            .or_default()
                            .insert(*device);
                    }
                }
            }
            let gone: Vec<DeviceId> = kept
                .keys()
                .filter(|device| !decided.values().any(|ids| ids.contains(*device)))
                .copied()
                .collect();
            for device in gone {
                kept.remove(&device);
                vault.delete(&mut batch, &space.0, Table::Vouched, &device.0);
            }
        }
        let mut touched: BTreeSet<EventId> = refreshed.changed.into_iter().collect();
        touched.extend(new);
        for id in touched {
            if replica.accepted(&id) {
                replica.set_first_sight(id, reading);
            }
            // A stranger's event is not kept (roster.md, "Strangers'
            // events").
            if replica
                .status(&id)
                .and_then(|status| status.class())
                .is_some_and(|class| frasil_base::errors::Class::name(class) == "Dropped")
            {
                vault.delete(&mut batch, &space.0, Table::Event, &id.0);
                continue;
            }
            let Some(event) = replica.event(id) else {
                continue;
            };
            // An event the replica cannot place yet, from an author no
            // record names, is kept in memory only: strangers cannot make
            // replicas store their events (roster.md, "Strangers'
            // events"). A space event is stored, since the record that
            // names its author may be its own.
            if replica.is_pending(&id)
                && event.kind() != kind::SPACE
                && !replica.names_author(event.author())
            {
                continue;
            }
            let record = event_record(replica, event, id);
            if foreseen
                .as_ref()
                .is_some_and(|(seen, written)| *seen == id && *written == record)
            {
                continue;
            }
            vault.put(
                &mut batch,
                &space.0,
                Table::Event,
                &id.0,
                &TableValue::Event(record),
            )?;
        }
        for id in replica.take_dropped_pending() {
            vault.delete(&mut batch, &space.0, Table::Event, &id.0);
        }
        for (locator, stored) in replica.take_forgotten_objects() {
            crate::objects::delete_object_records(vault, &mut batch, &space, &locator, &stored);
        }
        vault.commit(batch).await?;
        self.keep_adopted_snapshot(state, space).await
    }

    /// Takes list events into the persons' lists the device keeps, and
    /// stores them (identity.md, "Sealed list copies"; "Pins"). Returns
    /// whether any was new.
    async fn keep_list_events(&self, state: &mut State, signed: Vec<Vec<u8>>) -> Result<bool> {
        let mut new: Vec<([u8; 32], Event)> = Vec::new();
        let mut pending = signed;
        // Each touched list as it was, for the adds an agent roots.
        #[cfg(feature = "ext-recovery-agent")]
        let mut before: BTreeMap<[u8; 32], Option<frasil_identity::MergedList>> = BTreeMap::new();
        #[cfg(feature = "ext-recovery-agent")]
        for bytes in &pending {
            if let Ok(event) = frasil_events::decode(bytes) {
                let person = event.log_id().0;
                before.entry(person).or_insert_with(|| {
                    state
                        .lists
                        .get(&person)
                        .map(crate::lists::PersonList::merge)
                });
            }
        }
        // Firsts start their lists; the rest wait for their list.
        for _ in 0..2 {
            let mut rest = Vec::new();
            for bytes in std::mem::take(&mut pending) {
                let Ok(event) = frasil_events::decode(&bytes) else {
                    continue;
                };
                if event.kind() != kind::DEVICE_LIST {
                    continue;
                }
                let person = event.log_id().0;
                match state.lists.get_mut(&person) {
                    Some(list) => {
                        if list.has_seen(event.id()) {
                            continue;
                        }
                        if list.insert_event(event.clone()).is_ok() {
                            new.push((person, event));
                        }
                    }
                    None if event.is_genesis() => {
                        if let Ok(list) = DeviceList::from_first(event.clone()) {
                            state.lists.insert(person, list.into());
                            new.push((person, event));
                        }
                    }
                    None => rest.push(bytes),
                }
            }
            pending = rest;
        }
        if new.is_empty() {
            return Ok(false);
        }
        // A sealed copy of a holder that forgot: the list is held from its
        // checkpoint on (identity.md, "List checkpoints", "Forgetting").
        let touched: BTreeSet<[u8; 32]> = new.iter().map(|(person, _)| *person).collect();
        let mut became_kept = Vec::new();
        for person in &touched {
            if let Some(list) = state.lists.remove(person) {
                let was_whole = list.whole().is_some();
                let list = list.settled();
                if was_whole && let Some(kept) = list.kept() {
                    became_kept.push((*person, kept.checkpoint()));
                }
                state.lists.insert(*person, list);
            }
        }
        #[cfg(feature = "ext-recovery-agent")]
        {
            before.retain(|person, _| new.iter().any(|(p, _)| p == person));
            let raised = Self::note_agent_adds(state, &before);
            if let (false, Some(person)) = (raised.is_empty(), state.person) {
                // Raised to the person at once, offering the veto.
                let _ = self.shared.notices.send(Notice {
                    space: EventId(person),
                    placed: raised,
                    withdrawn: Vec::new(),
                    wanted: Vec::new(),
                });
            }
        }
        let reading = self.read_timeline(state).await?;
        let mut batch = Batch::default();
        for (person, event) in &new {
            state.list_sights.entry(event.id()).or_insert(reading);
            if !state.vault.has_log(person) {
                state
                    .vault
                    .add_log(&mut batch, person, LogKind::DeviceList)?;
            }
            if let Some(index) = became_kept.iter().position(|(p, _)| p == person) {
                let (_, checkpoint) = became_kept.remove(index);
                let kept = log_state(&state.vault, person).await?;
                state.vault.put(
                    &mut batch,
                    person,
                    Table::State,
                    &[],
                    &TableValue::State(LogState {
                        kept_checkpoint: Some(checkpoint.0),
                        ..kept
                    }),
                )?;
            }
            state.vault.put(
                &mut batch,
                person,
                Table::Event,
                &event.id().0,
                &TableValue::Event(EventRecord {
                    signed: event.signed(),
                    state: frasil_store::tables::EventState::Valid,
                    flags: FLAG_VERIFIED,
                    class: None,
                    first_sight: Some(reading),
                    frozen: None,
                }),
            )?;
        }
        state.vault.commit(batch).await?;
        Ok(true)
    }

    /// Places and stores events another party sent (events.md, "Handing an
    /// event to its kind"), then judges the space again.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`] for a space the device does not follow; the
    /// store's.
    pub async fn ingest(&self, space: EventId, signed: Vec<Vec<u8>>) -> Result<Ingested> {
        // Each event is decoded, its signature checked, before the device is
        // held, and at once where there are threads.
        let decoded = crate::parallel::map(
            signed.iter().collect(),
            signed.len() * crate::parallel::EVENT_WORK,
            |bytes| crate::intake::read_event(bytes),
        );
        let mut state = self.lock().await;
        if !state.replicas.contains_key(&space) {
            return Err(Error::UnknownSpace);
        }
        let reading = self.read_timeline(&mut state).await?;
        let mut ingested = Ingested::default();
        let mut events: Vec<Event> = Vec::new();
        {
            let replica = state.replicas.get(&space).expect("checked");
            for (index, decoded) in decoded.into_iter().enumerate() {
                match decoded {
                    Ok(event) if !replica.holds(event.id()) && event.log_id() == space => {
                        events.push(event)
                    }
                    Ok(_) => {}
                    Err(class) => ingested.refused.push((index, class)),
                }
            }
        }
        if events.is_empty() {
            ingested.wanted = state.replicas[&space].wanted();
            return Ok(ingested);
        }
        let new: Vec<EventId> = events.iter().map(Event::id).collect();
        let replica = state.replicas.get_mut(&space).expect("checked");
        #[cfg(feature = "partial-replicas")]
        if self.is_partial() {
            replica.make_partial();
        }
        let (placed, wanted) = replica.place(events);
        ingested.placed = placed.clone();
        ingested.wanted = wanted;
        self.settle(&mut state, space, new, reading).await?;
        // Acknowledgements that named heads not placed until now.
        let now_held = {
            let State {
                replicas, outboxes, ..
            } = &mut *state;
            match (
                replicas.get(&space).and_then(Replica::log),
                outboxes.get_mut(&space),
            ) {
                (Some(log), Some(outbox)) => outbox.now_held(log),
                _ => Vec::new(),
            }
        };
        drop(state);
        for (by, heads) in now_held {
            self.acknowledge(space, by, &heads).await?;
        }
        // Statements' heads a peer answered `Missing` for, supplied since:
        // that peer withheld them if it had acknowledged them, or still
        // lacked them after `withholding_grace` (units.md, 3.13 "Head
        // statements"). Judged after the acknowledgements above, which
        // may name them.
        let supplied = {
            let mut state = self.lock().await;
            let State {
                replicas, outboxes, ..
            } = &mut *state;
            match (
                replicas.get(&space).and_then(Replica::log),
                outboxes.get_mut(&space),
            ) {
                (Some(log), Some(outbox)) => {
                    outbox.stated_supplied(log, crate::statements::withholding_grace())
                }
                _ => Vec::new(),
            }
        };
        for (by, events) in supplied {
            self.report_loss(Loss {
                space,
                by,
                class: LossClass::Withheld,
                events,
            });
        }
        if !placed.is_empty() {
            let _ = self.shared.notices.send(Notice {
                space,
                placed,
                withdrawn: Vec::new(),
                wanted: Vec::new(),
            });
        }
        // A device granted `administer` enrols at its first sync after the
        // grant (peers.md, "Enrolment"). A failure here is no failure of
        // the ingest: the device tries again at the next.
        let _ = self.enrol(&space).await;
        Ok(ingested)
    }

    /// Takes an acknowledgement (units.md, "Heads, acknowledgements and
    /// durability"): the outbox entries it covers are deleted once durable.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn acknowledge(
        &self,
        space: EventId,
        by: Acknowledger,
        heads: &[EventId],
    ) -> Result<()> {
        let mut state = self.lock().await;
        if matches!(by, Acknowledger::Peer(_)) {
            state.peered.insert(space);
        }
        let members_count = !state.peered.contains(&space);
        let State {
            vault,
            replicas,
            outboxes,
            ..
        } = &mut *state;
        let Some(log) = replicas.get(&space).and_then(Replica::log) else {
            return Ok(());
        };
        let outbox = outboxes.entry(space).or_default();
        let durable = outbox.acknowledge(log, by, heads, members_count);
        let mut batch = Batch::default();
        for ((author, seq), _) in &durable {
            let mut item = author.0.to_vec();
            item.extend_from_slice(&seq.to_be_bytes());
            vault.delete(&mut batch, &space.0, Table::Outbox, &item);
        }
        if let Some(acknowledged) = outbox.acknowledged(&by)
            && !acknowledged.is_empty()
            && acknowledged.len() <= 256
            && vault.has_log(&space.0)
        {
            let mut heads: Vec<[u8; 32]> = acknowledged.iter().map(|id| id.0).collect();
            heads.sort_unstable();
            heads.dedup();
            vault.put(
                &mut batch,
                &space.0,
                Table::Ack,
                &by.id(),
                &TableValue::Ack(heads),
            )?;
        }
        vault.commit(batch).await?;
        if !durable.is_empty() {
            let _ = self.shared.notices.send(Notice {
                space,
                placed: Vec::new(),
                withdrawn: Vec::new(),
                wanted: Vec::new(),
            });
        }
        Ok(())
    }

    /// Whether an acknowledgement from `by` counts in a space: always a
    /// peer's; a member's only in a space with no always-on peer (units.md,
    /// 3.13 "Durable").
    fn acknowledgement_counts(state: &State, space: &EventId, by: &Acknowledger) -> bool {
        match by {
            Acknowledger::Peer(_) => true,
            Acknowledger::Member(_) => !state.peered.contains(space),
        }
    }

    /// Takes back what `by` lost of what it acknowledged (units.md, 3.13 "A
    /// restored peer"): this device's own events among them return to the
    /// outbox, not durable, and the acknowledgement keeps the rest, at
    /// rest too. Returns the events that returned.
    async fn take_back(
        &self,
        state: &mut State,
        space: EventId,
        by: Acknowledger,
        lost: &BTreeSet<EventId>,
    ) -> Result<Vec<EventId>> {
        let mut own: BTreeSet<DeviceId> = BTreeSet::from([self.device_id()]);
        if let Some(held) = state.pseudonyms.get(&space) {
            own.extend(held.iter().map(|(_, signer)| *signer.device_id()));
        }
        let State {
            vault,
            replicas,
            outboxes,
            ..
        } = state;
        let Some(log) = replicas.get(&space).and_then(Replica::log) else {
            return Ok(Vec::new());
        };
        let outbox = outboxes.entry(space).or_default();
        let (returned, heads) =
            outbox.roll_back(log, by, lost, |event| own.contains(event.author()));
        let mut batch = Batch::default();
        if vault.has_log(&space.0) {
            for ((author, seq), id) in &returned {
                let mut item = author.0.to_vec();
                item.extend_from_slice(&seq.to_be_bytes());
                vault.put(
                    &mut batch,
                    &space.0,
                    Table::Outbox,
                    &item,
                    &TableValue::Outbox(id.0),
                )?;
            }
            if heads.is_empty() || heads.len() > 256 {
                vault.delete(&mut batch, &space.0, Table::Ack, &by.id());
            } else {
                let mut heads: Vec<[u8; 32]> = heads.iter().map(|id| id.0).collect();
                heads.sort_unstable();
                vault.put(
                    &mut batch,
                    &space.0,
                    Table::Ack,
                    &by.id(),
                    &TableValue::Ack(heads),
                )?;
            }
        }
        vault.commit(batch).await?;
        Ok(returned.into_iter().map(|(_, id)| id).collect())
    }

    /// Reports what `by` lost, and offers again this device's own events
    /// that returned to the outbox.
    async fn rolled_back(
        &self,
        session: &mut SyncSession,
        by: Acknowledger,
        lost: BTreeSet<EventId>,
        returned: Vec<EventId>,
        out: &mut Vec<SyncMessage>,
    ) {
        let space = session.space();
        if !returned.is_empty() {
            session.forget(&returned);
            let state = self.lock().await;
            if let Some(replica) = state.replicas.get(&space) {
                out.extend(sends(session.offer(replica, &returned)));
            }
            drop(state);
            // The outbox grew: what waits on durability sees it.
            let _ = self.shared.notices.send(Notice {
                space,
                placed: Vec::new(),
                withdrawn: Vec::new(),
                wanted: Vec::new(),
            });
        }
        if !lost.is_empty() {
            self.report_loss(Loss {
                space,
                by,
                class: LossClass::RolledBack,
                events: lost.into_iter().collect(),
            });
        }
    }

    /// Judges the state the other side's `Heads` show (units.md, 3.13
    /// "Detected loss"): events it acknowledged and lacks are `RolledBack`,
    /// and a peer that lacks events of a state it served before withholds
    /// (`Withheld`). Judged once the device holds every head the other sent;
    /// until then, by its vector.
    async fn judge_served(
        &self,
        session: &mut SyncSession,
        by: Acknowledger,
        out: &mut Vec<SyncMessage>,
    ) -> Result<()> {
        use crate::outbox::{judged, past_of};
        let space = session.space();
        let Some(served) = session.unjudged() else {
            return Ok(());
        };
        let mut state = self.lock().await;
        let counts = Self::acknowledgement_counts(&state, &space, &by);
        let (whole, lost, withheld) = {
            let Some(log) = state.replicas.get(&space).and_then(Replica::log) else {
                return Ok(());
            };
            let outbox = state.outboxes.get(&space);
            let whole = served.whole(log);
            let lost = match outbox {
                Some(outbox) if counts => {
                    served.lacking(log, &judged(log, outbox.acknowledged_past(log, &by)))
                }
                _ => BTreeSet::new(),
            };
            let withheld = match outbox.and_then(|o| o.served(&by)) {
                Some(before)
                    if whole
                        && matches!(by, Acknowledger::Peer(_))
                        && before.iter().all(|h| log.contains(*h)) =>
                {
                    served.lacking(log, &judged(log, past_of(log, before)))
                }
                _ => BTreeSet::new(),
            };
            (whole, lost, withheld)
        };
        let returned = if lost.is_empty() {
            Vec::new()
        } else {
            self.take_back(&mut state, space, by, &lost).await?
        };
        if whole {
            session.mark_judged();
            state
                .outboxes
                .entry(space)
                .or_default()
                .set_served(by, served.heads.clone());
        }
        drop(state);
        let withheld: Vec<EventId> = withheld.difference(&lost).copied().collect();
        self.rolled_back(session, by, lost, returned, out).await;
        if !withheld.is_empty() {
            self.report_loss(Loss {
                space,
                by,
                class: LossClass::Withheld,
                events: withheld,
            });
        }
        Ok(())
    }

    /// A `Missing` from `by` (units.md, 3.13): events it acknowledged are
    /// `RolledBack`; heads of its own head statement make the statement
    /// junk (`BadStatement`); a peer's answer for a statement's heads asked
    /// of their author is kept with its time, and once they arrive shows
    /// withholding if the peer had acknowledged them or its answers span
    /// `withholding_grace`.
    async fn on_missing(
        &self,
        session: &mut SyncSession,
        by: Acknowledger,
        ids: &[EventId],
        out: &mut Vec<SyncMessage>,
    ) -> Result<()> {
        use crate::outbox::judged;
        let space = session.space();
        let mut state = self.lock().await;
        let counts = Self::acknowledgement_counts(&state, &space, &by);
        let lost = match (
            state.replicas.get(&space).and_then(Replica::log),
            state.outboxes.get(&space),
        ) {
            (Some(log), Some(outbox)) if counts => {
                let acked = outbox.acknowledged_past(log, &by);
                judged(log, ids.iter().copied().filter(|id| acked.contains(id)))
            }
            _ => BTreeSet::new(),
        };
        let returned = if lost.is_empty() {
            Vec::new()
        } else {
            self.take_back(&mut state, space, by, &lost).await?
        };
        let mut bad = Vec::new();
        match by {
            Acknowledger::Member(remote) => {
                if let Some(replica) = state.replicas.get_mut(&space) {
                    bad = replica.drop_statements_naming(&DeviceId(remote), ids);
                }
            }
            Acknowledger::Peer(_) => {
                // A replica that starts from a checkpoint takes what the
                // peer truncated as dropped (roster.md, 3.15.6).
                let truncated = state
                    .replicas
                    .get_mut(&space)
                    .map(|replica| replica.drop_truncated(ids))
                    .unwrap_or_default();
                if !truncated.is_empty() {
                    self.keep_checkpoint_state(&mut state, space).await?;
                    let reading = self.read_timeline(&mut state).await?;
                    self.settle(&mut state, space, truncated, reading).await?;
                }
                let asked: Vec<EventId> = state
                    .replicas
                    .get(&space)
                    .map(|replica| {
                        ids.iter()
                            .copied()
                            .filter(|id| replica.stated_asked(id) && !replica.holds(*id))
                            .collect()
                    })
                    .unwrap_or_default();
                if !asked.is_empty() {
                    let now = self.read_timeline(&mut state).await?.timeline;
                    let outbox = state.outboxes.entry(space).or_default();
                    let mut first = false;
                    for id in asked {
                        first |= outbox.note_stated_missing(id, by, now);
                    }
                    if first {
                        session.note_stated_missing();
                    }
                }
            }
        }
        drop(state);
        self.rolled_back(session, by, lost, returned, out).await;
        if !bad.is_empty() {
            self.report_loss(Loss {
                space,
                by,
                class: LossClass::BadStatement,
                events: bad,
            });
        }
        Ok(())
    }

    /// The events of a space still in this device's outbox.
    pub async fn outbox(&self, space: &EventId) -> Vec<EventId> {
        let state = self.lock().await;
        state
            .outboxes
            .get(space)
            .map(|o| o.pending().map(|(_, id)| *id).collect())
            .unwrap_or_default()
    }

    /// After a restore: the device holds a space's log as another party
    /// served it, so it sets each of its signers' tips to the newer
    /// of the tip and its newest event there, and may sign there again
    /// (at-rest.md, "After a restore", step 2).
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn synced(&self, space: &EventId) -> Result<()> {
        let mut state = self.lock().await;
        let mut authors = vec![self.device_id()];
        if let Some(pseudonyms) = state.pseudonyms.get(space) {
            authors.extend(pseudonyms.iter().map(|(_, p)| *p.device_id()));
        }
        let mut batch = Batch::default();
        if let Some(log) = state.replicas.get(space).and_then(Replica::log) {
            for author in authors {
                let Some(latest) = log.latest(&author) else {
                    continue;
                };
                let seq = log.event(latest).map_or(0, Event::seq);
                let tip = state.vault.head().tip(&space.0, &author).copied();
                if tip.is_none_or(|tip| tip.seq < seq) {
                    batch.tips.push(Tip {
                        log: space.0,
                        author,
                        seq,
                        event: latest.0,
                    });
                }
            }
        }
        let ready = !state.vault.head().may_sign(&space.0);
        if ready {
            batch.synced.push(space.0);
        }
        state.vault.commit(batch).await?;
        drop(state);
        if ready {
            // Observers of the space read again, and holders of
            // `write_ready` learn that the device may sign there.
            let _ = self.shared.notices.send(Notice {
                space: *space,
                placed: Vec::new(),
                withdrawn: Vec::new(),
                wanted: Vec::new(),
            });
            let _ = self.shared.write_ready.send(*space);
        }
        Ok(())
    }

    // -- Connections

    /// Where a device stands in this device's own current view of a space
    /// (transport.md, "The roster check").
    pub async fn standing(&self, space: &EventId, device: &DeviceId) -> Standing {
        let state = self.lock().await;
        let Some(replica) = state.replicas.get(space) else {
            return Standing::NamedNowhere;
        };
        if replica.forked(device) {
            return Standing::Forked;
        }
        if replica.level_of(device).is_some() {
            return Standing::Reaches(match replica.roster().state(&MemberRef::device(*device)) {
                Some(member) if member.session.is_some() => Path::Guest,
                Some(_) => Path::DeviceGrant,
                None if replica.reaches_through_person(device) => Path::PersonGrant,
                None => Path::GrantedSpace,
            });
        }
        if replica.ended_through_list(device, &state.lists) {
            return Standing::Ended(Ended::Revoked);
        }
        match replica.roster().standing(&MemberRef::device(*device)) {
            Some(frasil_space::Standing::In(member)) => {
                Standing::Reaches(if member.session.is_some() {
                    Path::Guest
                } else {
                    Path::DeviceGrant
                })
            }
            Some(frasil_space::Standing::Out { .. }) => Standing::Ended(Ended::Removed),
            None => Standing::NamedNowhere,
        }
    }

    /// The states this device offers for a space, each with its content
    /// key (transport.md, "The member handshake: the offer"): its current
    /// state, then each of its rotations alone, then the other rotations it
    /// holds, newest first; at most 16.
    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    pub(crate) async fn offered_states(
        &self,
        space: &EventId,
    ) -> Vec<((EventId, RotationSet), Secret)> {
        let state = self.lock().await;
        state
            .replicas
            .get(space)
            .map(|replica| member_states(replica, 16))
            .unwrap_or_default()
    }

    /// The candidate states a responder tests (transport.md, "The member
    /// handshake: the responder's match"): for each space, at most 256.
    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    pub(crate) async fn candidate_states(&self) -> Vec<((EventId, RotationSet), Secret)> {
        let state = self.lock().await;
        state
            .replicas
            .values()
            .flat_map(|replica| member_states(replica, 256))
            .collect()
    }

    /// The current state's content key of up to `limit` spaces, for local
    /// announcements (transport.md, "Member announcements").
    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    pub(crate) async fn announced_states(&self, limit: usize) -> Vec<(EventId, [u8; 32])> {
        let state = self.lock().await;
        state
            .replicas
            .values()
            .filter(|replica| Self::announces(replica))
            .filter_map(|replica| {
                let current = replica.current()?;
                let (key, _) = replica.state_key(current)?;
                Some((replica.space(), *key))
            })
            .take(limit)
            .collect()
    }

    /// For each space, the keys of its current state and of up to 3 states
    /// before it, with which a listener opens announcements.
    #[cfg_attr(not(feature = "iroh"), allow(dead_code))]
    pub(crate) async fn listened_states(&self) -> Vec<(EventId, Vec<[u8; 32]>)> {
        let state = self.lock().await;
        state
            .replicas
            .values()
            .map(|replica| {
                let keys = member_states(replica, 4)
                    .into_iter()
                    .map(|(_, key)| *key)
                    .collect();
                (replica.space(), keys)
            })
            .collect()
    }

    // -- Sync

    /// The messages a sync session opens with (units.md, "Sync", step 1).
    /// A session that asks for a space snapshot notes it: only then does
    /// it take a `SnapshotOffer`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn sync_start(&self, session: &mut SyncSession) -> Result<Vec<SyncMessage>> {
        let state = self.lock().await;
        let replica = state
            .replicas
            .get(&session.space())
            .ok_or(Error::UnknownSpace)?;
        // A newcomer that never used its snapshot asks for one first
        // (admission.md, "The newcomer's snapshot"). It names the system
        // stream, or, while it cannot open the genesis, 16 bytes of the
        // space ID: a member answers with a whole snapshot, every stream.
        if replica.wants_snapshot() {
            let named = replica.system_stream().unwrap_or_else(|| {
                let mut stream = [0; 16];
                stream.copy_from_slice(&session.space().0[..16]);
                stream
            });
            session.set_snapshot_ask(crate::sync::SnapshotAsk::Asked);
            return Ok(vec![SyncMessage {
                space: session.space(),
                message: frasil_units::messages::Message::SnapshotWant {
                    streams: vec![named],
                },
            }]);
        }
        Ok(sends(session.start(replica)))
    }

    /// Takes one sync message of a session: places and stores what
    /// arrives, takes acknowledgements from `by`, and returns what to send.
    /// Once the session is caught up with the other side, a device restored
    /// from a backup may sign in the space again (at-rest.md, "After a
    /// restore", step 2).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; the store's.
    pub async fn sync_receive(
        &self,
        session: &mut SyncSession,
        by: Acknowledger,
        message: SyncMessage,
    ) -> Result<Vec<SyncMessage>> {
        let space = session.space();
        let actions = {
            let state = self.lock().await;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            // Waiting for a snapshot, the device places no event and offers
            // none (admission.md, "The newcomer's snapshot").
            if replica.wants_snapshot()
                && matches!(
                    message.message,
                    frasil_units::messages::Message::Heads { .. }
                        | frasil_units::messages::Message::Events { .. }
                )
            {
                return Ok(Vec::new());
            }
            session.receive(replica, message)
        };
        let mut out = Vec::new();
        // Whether what arrived may name objects the other side announced.
        let mut names_more = false;
        for action in actions {
            match action {
                Action::Send(message) => out.push(message),
                Action::ServeObject {
                    locator,
                    first,
                    count,
                } => {
                    if let Some(parts) = self.serve_parts(&space, &locator, first, count).await? {
                        out.extend(parts.into_iter().map(|part| chunk_message(space, part)));
                    } else if let Some(parts) =
                        self.serve_held(space, &locator, first, count).await?
                    {
                        // A held object, its chunks sealed again from the
                        // plaintext (at-rest.md, "Held objects").
                        out.extend(parts.into_iter().map(|part| chunk_message(space, part)));
                    }
                }
                Action::ObjectChunk(part) => {
                    let locator = part.locator;
                    // A chunk of an object this side asked the other for
                    // on this session, or of one the snapshot it adopted
                    // from the other names, and still missing.
                    let asked = session.is_fetching(&locator)
                        || (session.snapshot_ask() == crate::sync::SnapshotAsk::Adopted
                            && self
                                .read(&space, |replica| {
                                    replica.awaited_snapshot() == Some(&locator)
                                        || replica.pending_stream_objects().any(|l| *l == locator)
                                })
                                .await?);
                    if !asked || !self.missing_objects(&space).await.contains(&locator) {
                        continue;
                    }
                    let index = part.index;
                    let total = part
                        .header
                        .as_ref()
                        .and_then(|h| frasil_units::objects::Header::read(h).ok())
                        .map(|h| {
                            frasil_units::objects::chunk_count(
                                h.size,
                                frasil_units::limits::CHUNK_BYTES as u64,
                            )
                        });
                    match self.receive_part(space, part).await? {
                        crate::objects::Received::Refused => {
                            // Not asked of this side again; every other
                            // connection of the space asks for it.
                            session.refuse_object(locator);
                            let _ = self.shared.notices.send(Notice {
                                space,
                                placed: Vec::new(),
                                withdrawn: Vec::new(),
                                wanted: vec![locator],
                            });
                        }
                        received => {
                            let whole = received == crate::objects::Received::Whole;
                            names_more |= whole;
                            out.extend(session.next_chunks(locator, index, total, whole));
                        }
                    }
                }
                Action::ObjectsHeld(locators) => {
                    session.note_announced(&locators);
                    let missing = self.missing_objects(&space).await;
                    for locator in locators {
                        if missing.contains(&locator) {
                            out.extend(self.want_in(session, &space, locator).await);
                        }
                    }
                }
                Action::SnapshotWanted => {
                    if let Acknowledger::Member(remote) = by {
                        out.extend(Box::pin(self.snapshot_for(space, &DeviceId(remote))).await?);
                    }
                }
                Action::SnapshotOffered(signed) => {
                    // Taken only on a session that asked for it, from the
                    // member the connection identified, which signed it
                    // (units.md, "The space snapshot", "Using it"; the
                    // caller takes it only from an attach it admitted).
                    let from_asked = session.snapshot_ask() == crate::sync::SnapshotAsk::Asked;
                    let wants = self.read(&space, Replica::wants_snapshot).await?;
                    if from_asked
                        && wants
                        && offered_by(&signed, &space, by)
                        && Box::pin(self.adopt_snapshot(space, &signed, Vec::new()))
                            .await
                            .is_ok()
                    {
                        session.set_snapshot_ask(crate::sync::SnapshotAsk::Adopted);
                        names_more = true;
                        out.extend(self.sync_start(session).await?);
                    }
                }
                Action::Ingest(events) => {
                    names_more = true;
                    Box::pin(self.ingest(space, events)).await?;
                    let state = self.lock().await;
                    let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
                    out.extend(sends(session.stored(replica)));
                }
                Action::Acknowledged(heads) => self.acknowledge(space, by, &heads).await?,
                Action::Missing(ids) => self.on_missing(session, by, &ids, &mut out).await?,
                Action::Carried(pairs) => {
                    let mut state = self.lock().await;
                    let reading = self.read_timeline(&mut state).await?;
                    state
                        .replicas
                        .get_mut(&space)
                        .ok_or(Error::UnknownSpace)?
                        .take_carried(&pairs);
                    Box::pin(self.settle(&mut state, space, Vec::new(), reading)).await?;
                    let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
                    out.extend(sends(session.stored(replica)));
                }
                #[cfg(not(feature = "partial-replicas"))]
                Action::Path { .. } => {}
                #[cfg(feature = "partial-replicas")]
                Action::Path { from, to, events } => {
                    Box::pin(self.add_path(space, from, to, events)).await?;
                    let state = self.lock().await;
                    let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
                    out.extend(sends(session.stored(replica)));
                }
            }
        }
        if names_more && !session.announced().is_empty() {
            out.extend(self.want_announced(session).await);
        }
        self.judge_served(session, by, &mut out).await?;
        let caught_up = {
            let state = self.lock().await;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            session.caught_up(replica) && !state.vault.head().may_sign(&space.0)
        };
        if caught_up {
            self.synced(&space).await?;
        }
        // A completed sync with an always-on peer: this device holds every
        // event its heads name, and the peer holds this device's events
        // (ext-guests.md, "The writer's decision").
        #[cfg(feature = "ext-guests")]
        if matches!(by, Acknowledger::Peer(_)) {
            let completed = {
                let state = self.lock().await;
                let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
                session.caught_up(replica)
                    && state
                        .outboxes
                        .get(&space)
                        .is_none_or(|o| o.pending().next().is_none())
            };
            if completed {
                self.record_sync(&space).await?;
            }
        }
        // Objects the events sent name, announced to a member, which may
        // ask for them (units.md, "Sync", objects).
        if session.acknowledges() {
            let state = self.lock().await;
            if let Some(replica) = state.replicas.get(&space) {
                let announced = announced_objects(replica, &out);
                out.extend(announced);
            }
        }
        Ok(out)
    }

    /// Live delivery: the messages that carry newly placed events of a
    /// session's space the other side has not been sent.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn sync_offer(
        &self,
        session: &mut SyncSession,
        placed: &[EventId],
    ) -> Result<Vec<SyncMessage>> {
        let state = self.lock().await;
        let replica = state
            .replicas
            .get(&session.space())
            .ok_or(Error::UnknownSpace)?;
        let mut out = sends(session.offer(replica, placed));
        if session.acknowledges() {
            out.extend(announced_objects(replica, &out));
        }
        Ok(out)
    }

    /// `ObjectWant` for objects the application asked for that this device
    /// does not hold, on a session with a side that may hold them.
    pub async fn sync_want(
        &self,
        session: &mut SyncSession,
        wanted: &[frasil_adapter::Locator],
    ) -> Result<Vec<SyncMessage>> {
        let state = self.lock().await;
        let replica = state
            .replicas
            .get(&session.space())
            .ok_or(Error::UnknownSpace)?;
        Ok(wanted
            .iter()
            .filter(|locator| !replica.holds_object(locator))
            .filter_map(|locator| session.want_object(*locator))
            .collect())
    }

    /// A member's snapshot for a newcomer that asked for one (units.md,
    /// `SnapshotWant`; admission.md, "The newcomer's snapshot"): the space
    /// snapshot at this device's heads for the member's grant in force,
    /// then the chunks of the stream snapshot objects it names, which this
    /// device keeps so that it can serve them again.
    async fn snapshot_for(&self, space: EventId, member: &DeviceId) -> Result<Vec<SyncMessage>> {
        let admitting = self
            .read(&space, |replica| {
                // A snapshot this replica cannot yet attribute is not
                // passed on (units.md, "The space snapshot", "Using it").
                if replica.snapshot_unconfirmed() {
                    return None;
                }
                replica
                    .roster()
                    .state(&MemberRef::device(*member))
                    .and_then(|s| s.grants.iter().next().copied())
            })
            .await?;
        let Some(admitting) = admitting else {
            return Ok(Vec::new());
        };
        let made = self.newcomer_snapshot(&space, admitting).await?;
        let parts = made.parts();
        {
            let mut state = self.lock().await;
            Self::keep_parts_in(&mut state, space, &parts.iter().collect::<Vec<_>>()).await?;
        }
        let mut out = vec![SyncMessage {
            space,
            message: frasil_units::messages::Message::SnapshotOffer {
                snapshot: made.signed,
            },
        }];
        out.extend(parts.into_iter().map(|part| chunk_message(space, part)));
        Ok(out)
    }

    // -- Signing

    /// The next `seq` and `prev` of a signing key in a space, from the
    /// head's tips and nowhere else (at-rest.md, "The head, events and
    /// keys").
    pub(crate) fn next(
        state: &State,
        space: &EventId,
        author: &DeviceId,
    ) -> (u64, Option<EventId>) {
        match state.vault.head().tip(&space.0, author) {
            Some(tip) => (tip.seq.saturating_add(1), Some(EventId(tip.event))),
            // A memory-only log's chain is the replica's alone.
            None if state.vault.is_memory_only(&space.0) => state
                .replicas
                .get(space)
                .and_then(Replica::log)
                .and_then(|log| log.latest(author))
                .and_then(|id| {
                    let seq = state.replicas.get(space)?.log()?.event(id)?.seq();
                    Some((seq.saturating_add(1), Some(id)))
                })
                .unwrap_or((1, None)),
            None => (1, None),
        }
    }

    pub(crate) fn check_may_sign(state: &State, space: &EventId) -> Result<()> {
        if !state.vault.head().may_sign(&space.0) {
            return Err(Error::SyncBeforeWriting);
        }
        Ok(())
    }

    /// Commits an event this device signed, places it, and judges the space
    /// again. Nothing is sent before the commit returns.
    pub(crate) async fn commit_own(
        &self,
        state: &mut State,
        space: EventId,
        signed: &[u8],
        rotation: Option<RotationSecrets>,
    ) -> Result<EventId> {
        self.commit_own_keeping(state, space, signed, rotation, Vec::new())
            .await
    }

    /// [`commit_own`](Self::commit_own), with further records in the same
    /// commit, such as an invite's `invite` record; a record given as
    /// `None` is deleted in it.
    pub(crate) async fn commit_own_keeping(
        &self,
        state: &mut State,
        space: EventId,
        signed: &[u8],
        rotation: Option<RotationSecrets>,
        records: Vec<(Table, Vec<u8>, Option<TableValue>)>,
    ) -> Result<EventId> {
        self.commit_own_with(state, space, signed, rotation, records, Vec::new())
            .await
    }

    /// One commit for an own event: the event, its foreseen verdict, the
    /// rotation's secrets, further records, parts of objects it names and
    /// the timeline's reading when due; then the event is placed and the
    /// space judged again.
    pub(crate) async fn commit_own_with(
        &self,
        state: &mut State,
        space: EventId,
        signed: &[u8],
        rotation: Option<RotationSecrets>,
        records: Vec<(Table, Vec<u8>, Option<TableValue>)>,
        stored: Vec<crate::snapshots::ObjectPart>,
    ) -> Result<EventId> {
        let event = frasil_events::decode(signed).map_err(Error::class)?;
        // A space that needs a later version, this device signs nothing in
        // (roster.md, "The space descriptor", 2.8 and 3.16).
        if state
            .replicas
            .get(&space)
            .is_some_and(Replica::needs_later_version)
        {
            return Err(Error::NeedsLaterVersion);
        }
        // A device builds on no checkpoint that drops it as an
        // administrator while its own view says it is one, nor on one whose
        // record it has not agreed with (roster.md, section 4; 3.15.7).
        if let Some(replica) = state.replicas.get(&space)
            && let Some(log) = replica.log()
            && crate::checkpoints::reaches_avoided(
                log,
                &replica.checkpoint_facts().avoided(),
                event.parents(),
            )
            .is_some()
        {
            return Err(Error::NotAllowed(
                "the event would build on a checkpoint this device does not accept",
            ));
        }
        let id = event.id();
        let mut batch = Batch {
            signs: true,
            ..Batch::default()
        };
        let reading = Self::read_timeline_in(state, &self.shared.platform, &mut batch)?;
        let due = !batch.puts.is_empty();
        if let Some(secrets) = &rotation {
            put_rotation(&state.vault, &mut batch, &space, &id, secrets)?;
        }
        // An own event signed by this device's key verifies, and a member's
        // event is valid in the common case: its record is written so, and
        // written again by the settle only if the verdict differs.
        let foreseen = EventRecord {
            signed: event.signed(),
            state: frasil_store::tables::EventState::Valid,
            flags: FLAG_VERIFIED,
            class: None,
            first_sight: Some(reading),
            frozen: None,
        };
        put_own(&state.vault, &mut batch, &space, &event, &foreseen)?;
        for (table, item, value) in &records {
            match value {
                Some(value) => state.vault.put(&mut batch, &space.0, *table, item, value)?,
                None => state.vault.delete(&mut batch, &space.0, *table, item),
            }
        }
        for part in &stored {
            crate::objects::put_part(&state.vault, &mut batch, &space, part)?;
        }
        state.vault.commit(batch).await?;
        if due {
            state.last_kept = self.shared.platform.clock.monotonic();
        }
        state.foreseen = Some((id, foreseen));
        let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
        if let Some(secrets) = rotation {
            replica.keep_secrets(id, secrets);
        }
        if !stored.is_empty() {
            replica.set_chunks_at_rest(!state.vault.is_memory_only(&space.0));
            for part in &stored {
                replica.keep_part(part);
            }
            // Sealed here: their bytes hash to their locators.
            for part in &stored {
                replica.mark_checked(&part.locator);
            }
            replica.take_snapshots();
        }
        let (placed, _) = replica.place(vec![event.clone()]);
        state
            .outboxes
            .entry(space)
            .or_default()
            .add(*event.author(), event.seq(), id);
        self.settle(state, space, vec![id], reading).await?;
        let _ = self.shared.notices.send(Notice {
            space,
            placed,
            withdrawn: Vec::new(),
            wanted: Vec::new(),
        });
        Ok(id)
    }

    pub(crate) fn held_state(replica: &Replica) -> Result<HeldState> {
        let state = replica
            .current()
            .cloned()
            .ok_or(Error::NotAllowed("the device holds no state of the space"))?;
        let (content, _) = replica
            .state_key(&state)
            .ok_or(Error::NotAllowed("the device lacks the current key"))?;
        let upload = replica.state_upload(&state);
        Ok(HeldState {
            state,
            content,
            upload,
        })
    }

    /// The key reference a unit or object of the space names, and the
    /// content key it is sealed under: the current state and `k(S)`, or in
    /// a restricted space the restricted key reference and `k_F(S_F, S_P)`
    /// (ext-restricted-spaces.md, "The restricted key reference").
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] while the device
    /// holds no current state, or its key.
    pub(crate) fn sealing(&self, state: &State, space: &EventId) -> Result<(Vec<u8>, Secret)> {
        self.sealing_under(state, space, None)
    }

    /// [`sealing`](Self::sealing) under a given state of the space, such
    /// as an admission's, rather than the current one.
    pub(crate) fn sealing_under(
        &self,
        state: &State,
        space: &EventId,
        under: Option<&RotationSet>,
    ) -> Result<(Vec<u8>, Secret)> {
        let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
        #[cfg(feature = "ext-restricted-spaces")]
        if let Some(parent) = replica.restricted_parent() {
            return crate::restricted::sealing(self.platform(), state, space, &parent, under);
        }
        match under {
            Some(under) => {
                let (key, _) = replica
                    .state_key(under)
                    .ok_or(Error::NotAllowed("the device lacks the state's key"))?;
                Ok((under.encode(), key))
            }
            None => {
                let held = Self::held_state(replica)?;
                Ok((held.state.encode(), held.content))
            }
        }
    }

    /// Whether a device reaches the parent of a space, if it is restricted,
    /// in this device's view: a newcomer outside it would receive nothing
    /// of the space (ext-restricted-spaces.md, "Membership of a restricted
    /// space"). Always for another space.
    pub async fn reaches_parent_of(&self, space: &EventId, device: &DeviceId) -> bool {
        let state = self.lock().await;
        state
            .replicas
            .get(space)
            .is_none_or(|replica| Self::reaches_parent(replica, &state.replicas, device))
    }

    /// Whether a device announces a space on a local network: never a
    /// restricted one (ext-restricted-spaces.md, "Keys of a restricted
    /// space", connections).
    #[cfg_attr(not(feature = "ext-restricted-spaces"), allow(unused_variables))]
    pub(crate) fn announces(replica: &Replica) -> bool {
        #[cfg(feature = "ext-restricted-spaces")]
        return frasil_transport::ext_restricted_spaces::announces(replica.is_restricted());
        #[cfg(not(feature = "ext-restricted-spaces"))]
        true
    }

    /// Whether the space's rotations draw a grant seed: a restricted
    /// space's never do (ext-restricted-spaces.md, "A restricted space's
    /// secrets and keys").
    #[cfg_attr(not(feature = "ext-restricted-spaces"), allow(unused_variables))]
    pub(crate) fn draws_grant(replica: &Replica) -> bool {
        #[cfg(feature = "ext-restricted-spaces")]
        if replica.is_restricted() {
            return false;
        }
        true
    }

    /// Whether a device reaches a restricted space's parent; any device
    /// does for another space.
    #[cfg_attr(not(feature = "ext-restricted-spaces"), allow(unused_variables))]
    pub(crate) fn reaches_parent(
        replica: &Replica,
        others: &BTreeMap<EventId, Replica>,
        device: &DeviceId,
    ) -> bool {
        #[cfg(feature = "ext-restricted-spaces")]
        return crate::restricted::reaches_parent(replica, others, device);
        #[cfg(not(feature = "ext-restricted-spaces"))]
        true
    }

    pub(crate) fn held_grant(replica: &Replica) -> Option<HeldGrant> {
        let state = replica.grant_current()?.clone();
        let grant = replica.state_grant(&state)?;
        Some(HeldGrant { state, grant })
    }

    /// The devices a rotation's own delivery wraps for after `changes`:
    /// every device member of the merged roster that stays in, each
    /// device the changes grant, and the author (keys.md, "Deliveries").
    pub(crate) fn recipients_after(
        &self,
        replica: &Replica,
        changes: &[Change],
        lists: &BTreeMap<[u8; 32], crate::lists::PersonList>,
        others: &BTreeMap<EventId, Replica>,
    ) -> Vec<Recipient> {
        let removed: BTreeSet<MemberRef> = changes
            .iter()
            .filter(|c| c.op == Op::Remove)
            .filter_map(|c| c.member)
            .collect();
        let mut out: BTreeMap<DeviceId, Recipient> = BTreeMap::new();
        for (member, state) in replica.roster().members_in() {
            if member.kind != MemberType::Device || removed.contains(member) {
                continue;
            }
            let Some(keys) = &state.keys else {
                continue;
            };
            out.insert(
                DeviceId(member.id),
                Recipient {
                    keys: (**keys).clone(),
                    writes: state.level >= Level::Write,
                    propagates: state.propagates(),
                },
            );
        }
        for (member, state) in replica.roster().members_in() {
            if member.kind != MemberType::Person || removed.contains(member) {
                continue;
            }
            for recipient in person_recipients(&member.id, state.level, lists, Some(replica)) {
                out.insert(recipient.keys.device_id(), recipient);
            }
        }
        // Invite keys while they count as inside (ext-invite-links.md,
        // "Keys").
        #[cfg(feature = "ext-invite-links")]
        {
            let removed: Vec<MemberRef> = removed.iter().copied().collect();
            for recipient in crate::invite_links::invite_recipients(replica, &removed) {
                out.insert(recipient.keys.device_id(), recipient);
            }
        }
        // A change's new level: a demoted member keeps no upload seed.
        for change in changes.iter().filter(|c| c.op == Op::Change) {
            let (Some(member), Some(level)) = (change.member, change.level) else {
                continue;
            };
            match member.kind {
                MemberType::Device => {
                    if let Some(recipient) = out.get_mut(&DeviceId(member.id)) {
                        recipient.writes = level >= Level::Write;
                    }
                }
                MemberType::Person => {
                    for recipient in person_recipients(&member.id, level, lists, Some(replica)) {
                        out.insert(recipient.keys.device_id(), recipient);
                    }
                }
                _ => {}
            }
        }
        for change in changes {
            for recipient in granted_recipients(change, lists, Some(replica)) {
                out.insert(recipient.keys.device_id(), recipient);
            }
        }
        // A device whose chain forked counts as removed: it receives no
        // wraps (keys.md, "The current state and the inside"). A device
        // outside a restricted space's parent receives nothing of it
        // (ext-restricted-spaces.md, "Membership of a restricted space").
        out.retain(|device, _| {
            !replica.forked(device) && Self::reaches_parent(replica, others, device)
        });
        out.insert(
            self.device_id(),
            Recipient {
                keys: self.shared.keys.public.clone(),
                writes: true,
                propagates: true,
            },
        );
        out.into_values().collect()
    }

    /// Signs a roster event of these changes (roster.md, "Changes"). It
    /// rotates when keys.md requires it: a removal, a demotion to `read`,
    /// or a grant "from now on", which is a break. Otherwise it is sealed
    /// under the current state, and delivers it, with the grant state, to
    /// each device it grants "with history".
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device administers the space;
    /// [`Error::Invalid`] for a capability whose name begins `frasil.`,
    /// which is Frasil's, but one a document of Frasil's sets
    /// ([`Capability::is_set_by_frasil`](frasil_space::Capability::is_set_by_frasil))
    /// or one a change carries over from the member's own state;
    /// [`Error::SyncBeforeWriting`]; the store's.
    pub async fn sign_roster(&self, space: EventId, changes: Vec<Change>) -> Result<EventId> {
        Ok(self.sign_roster_with(space, changes).await?.0)
    }

    /// [`sign_roster`](Self::sign_roster), with each recipient's wrap.
    pub(crate) async fn sign_roster_with(
        &self,
        space: EventId,
        changes: Vec<Change>,
    ) -> Result<(EventId, BTreeMap<DeviceId, writer::WrapOf>)> {
        self.sign_roster_keeping(space, changes, |_| Vec::new())
            .await
    }

    /// [`sign_roster_with`](Self::sign_roster_with), keeping the records
    /// `keep` makes of the event's ID in its commit.
    pub(crate) async fn sign_roster_keeping(
        &self,
        space: EventId,
        changes: Vec<Change>,
        keep: impl FnOnce(EventId) -> Vec<(Table, Vec<u8>, TableValue)>,
    ) -> Result<(EventId, BTreeMap<DeviceId, writer::WrapOf>)> {
        self.sign_roster_full(space, changes, Vec::new(), keep)
            .await
    }

    /// [`sign_roster`](Self::sign_roster), naming these events of other
    /// logs in its sealed refs.
    #[cfg_attr(not(feature = "ext-restricted-spaces"), allow(dead_code))]
    pub(crate) async fn sign_roster_citing(
        &self,
        space: EventId,
        changes: Vec<Change>,
        cited: Vec<frasil_events::Ref>,
    ) -> Result<EventId> {
        Ok(self
            .sign_roster_full(space, changes, cited, |_| Vec::new())
            .await?
            .0)
    }

    async fn sign_roster_full(
        &self,
        space: EventId,
        changes: Vec<Change>,
        cited: Vec<frasil_events::Ref>,
        keep: impl FnOnce(EventId) -> Vec<(Table, Vec<u8>, TableValue)>,
    ) -> Result<(EventId, BTreeMap<DeviceId, writer::WrapOf>)> {
        // Roster signing must fit beside the caller's other work in debug builds.
        Box::pin(self.sign_roster_full_inner(space, changes, cited, keep)).await
    }

    async fn sign_roster_full_inner(
        &self,
        space: EventId,
        changes: Vec<Change>,
        cited: Vec<frasil_events::Ref>,
        keep: impl FnOnce(EventId) -> Vec<(Table, Vec<u8>, TableValue)>,
    ) -> Result<(EventId, BTreeMap<DeviceId, writer::WrapOf>)> {
        // A device granted `administer` signs a twin in its own slot, so it
        // enrols first if the sync that granted it has not yet (peers.md,
        // "Enrolment"). When that fails, signing the twin says why.
        let _ = self.enrol(&space).await;
        let mut state = self.lock().await;
        self.publish_own_lists(&mut state, space).await?;
        Self::check_may_sign(&state, &space)?;
        #[cfg(feature = "ext-guests")]
        self.writer_check(&mut state, &space).await?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.level_of(&self.device_id()) != Some(Level::Administer) && !signs_unchecked() {
            return Err(Error::NotAllowed("roster events need administer"));
        }
        reserved_capabilities(replica, &changes)?;
        if !signs_unchecked()
            && !self
                .shared
                .unchecked_ranks
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            ranks_allow(replica, &self.device_id(), &changes)?;
        }
        // A self-removal never rotates: the leaver would hold the new key
        // (roster.md, "The event alone").
        let own = MemberRef::device(self.device_id());
        let rotates = changes.iter().any(|change| {
            (change.op == Op::Remove && !closes(replica, change) && change.member != Some(own))
                || (change.op == Op::Change && change.level == Some(Level::Read))
                || (change.op == Op::Grant
                    && change.history == Some(frasil_space::HistoryMode::FromNowOn))
        });
        let is_break = changes.iter().any(|change| {
            change.op == Op::Grant && change.history == Some(frasil_space::HistoryMode::FromNowOn)
        });
        // A grant rotation only where keys.md requires one: a removal of a
        // member that propagates, or an admission "from now on" of one
        // (keys.md, "Checks against the event and its place", steps 5 to
        // 7).
        let me = MemberRef::device(self.device_id());
        let removes_propagating = changes.iter().any(|change| {
            change.op == Op::Remove
                && change.member.is_some_and(|m| {
                    m != me && replica.roster().state(&m).is_some_and(|s| s.propagates())
                })
        });
        let admits_propagating = changes.iter().any(|change| {
            change.op == Op::Grant
                && change.history == Some(frasil_space::HistoryMode::FromNowOn)
                && change.session.is_none()
        });
        let grant_rotation = replica.propagates(&self.device_id())
            && (removes_propagating || admits_propagating)
            && Self::draws_grant(replica);
        let sealing = if rotates {
            let recipients =
                self.recipients_after(replica, &changes, &state.lists, &state.replicas);
            // The devices the changes remove: reached before them and not
            // after (keys.md, "Deliveries").
            let staying: BTreeSet<DeviceId> =
                recipients.iter().map(|r| r.keys.device_id()).collect();
            let removed: Vec<Recipient> = if changes.iter().any(|c| c.op == Op::Remove) {
                self.recipients_after(replica, &[], &state.lists, &state.replicas)
                    .into_iter()
                    .filter(|r| !staying.contains(&r.keys.device_id()))
                    .collect()
            } else {
                Vec::new()
            };
            Sealing::Rotate {
                fresh: writer::Fresh::draw(&self.shared.platform)?,
                is_break,
                grant_rotation,
                recipients,
                removed,
                previous: Self::held_state(replica).ok(),
                previous_grant: Self::held_grant(replica),
            }
        } else {
            // A member raised from `read` lacks the upload seed: it
            // receives the current state as a delivery, as a newcomer does
            // (keys.md, "Checks against the event and its place").
            let newcomers: Vec<Recipient> = changes
                .iter()
                .flat_map(|change| {
                    let mut out = granted_recipients(change, &state.lists, Some(replica));
                    out.extend(raised_recipients(change, &state.lists, replica));
                    out
                })
                .filter(|r| Self::reaches_parent(replica, &state.replicas, &r.keys.device_id()))
                .collect();
            Sealing::Under {
                state: Self::held_state(replica)?,
                grant: Self::held_grant(replica),
                recipients: newcomers,
                others: Vec::new(),
            }
        };
        let administers = administer_changes(&changes, replica.roster());
        // Spaces this event grants: a notice of each one's current grant
        // rotation, its heads in the refs as its known past (roster.md,
        // "Checks across logs"), and a space wrap to the new principal
        // (keys.md, "Notices and space principals").
        let mut notices = Vec::new();
        let mut principals = Vec::new();
        let mut refs = person_refs(&changes, &state.lists);
        refs.extend(cited);
        for change in changes.iter().filter(|c| c.op == Op::Grant) {
            let Some(member) = change.member.filter(|m| m.kind == MemberType::Space) else {
                continue;
            };
            let granted = EventId(member.id);
            let (notice, heads) = self.notice_of(&state, &granted)?;
            principals.push(writer::SpacePrincipal {
                space: granted,
                rotation: notice.rotation,
                public: notice.public.clone(),
                writes: change.level >= Some(Level::Write),
            });
            notices.push(notice);
            refs.extend(
                heads
                    .into_iter()
                    .map(|id| frasil_events::Ref { log: granted, id }),
            );
        }
        refs.sort_unstable_by_key(|a| (a.log.0, a.id.0));
        refs.dedup();
        refs.truncate(64);
        if rotates {
            let removed: BTreeSet<MemberRef> = changes
                .iter()
                .filter(|c| c.op == Op::Remove)
                .filter_map(|c| c.member)
                .collect();
            principals.extend(
                replica
                    .principals()
                    .iter()
                    .filter(|(t, ..)| !removed.contains(&MemberRef::space(t.0)))
                    .map(|(t, r, public, level)| writer::SpacePrincipal {
                        space: *t,
                        rotation: *r,
                        public: public.clone(),
                        writes: *level >= Level::Write,
                    }),
            );
        }
        let (seq, prev) = Self::next(&state, &space, &self.device_id());
        // The checkpoints the roster event follows: its twin cites them and
        // declares the same cuts (roster.md, 3.15.8, twins and the skeleton).
        let cuts = replica.cuts_for(&replica.parents(prev))?;
        let mut plan = SpaceEventPlan {
            space,
            seq,
            prev,
            parents: Vec::new(),
            cuts,
            checkpoint: None,
            refs,
            changes: Some(changes),
            sealing,
            twin: None,
            notices,
            principals,
            grantless: !Self::draws_grant(replica),
        };
        if administers.changes_administration() {
            // The twin first, signed by this device's enrolled pseudonym,
            // its commitment from the roster event's body key (roster.md,
            // "The twin").
            let twin = self
                .sign_twin(&mut state, &space, &plan, &administers)
                .await?;
            plan.twin = Some(twin);
        }
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        plan.parents = replica.parents(prev);
        let mut cited = plan.parents.clone();
        cited.extend(plan.twin);
        plan.cuts = replica.cuts_for(&cited)?;
        let signed = writer::space_event(&self.shared.platform, &self.shared.keys.signer, plan)?;
        let rotation = signed.fresh.as_ref().map(|fresh| RotationSecrets {
            content: Some(fresh.content.clone()),
            upload: Some(fresh.upload.clone()),
            grant: signed.grant_rotation.then(|| fresh.grant.clone()),
        });
        let records = keep(signed.id)
            .into_iter()
            .map(|(table, item, value)| (table, item, Some(value)))
            .collect();
        let id = self
            .commit_own_keeping(&mut state, space, &signed.signed, rotation, records)
            .await?;
        Ok((id, signed.wraps))
    }

    /// A notice of a granted space's current grant rotation, and the heads
    /// of its log: this device must propagate there and hold the
    /// rotation's grant seed (keys.md, "Notices and space principals").
    pub(crate) fn notice_of(
        &self,
        state: &State,
        granted: &EventId,
    ) -> Result<(frasil_keys::body::Notice, Vec<EventId>)> {
        let replica = state.replicas.get(granted).ok_or(Error::NotAllowed(
            "the device does not hold the granted space",
        ))?;
        if !replica.propagates(&self.device_id()) {
            return Err(Error::NotAllowed(
                "the device does not propagate in the granted space",
            ));
        }
        let grant_state = replica
            .grant_current()
            .ok_or(Error::NotAllowed("the granted space has no grant state"))?;
        let [rotation] = grant_state.ids() else {
            return Err(Error::NotAllowed(
                "the granted space's grant state must collapse first",
            ));
        };
        let seed = replica
            .secrets_of(rotation)
            .and_then(|s| s.grant.clone())
            .ok_or(Error::NotAllowed("the device lacks the grant seed"))?;
        let key = frasil_keys::derive::GrantKey::derive(&seed);
        let commitment = replica
            .event(*rotation)
            .and_then(crate::replica::visible)
            .and_then(|v| v.rotation().map(|r| r.grant_commitment));
        let from_now_on = commitment == Some(key.commitment(true));
        let mut heads = replica.citable_heads();
        heads.sort_unstable();
        Ok((
            frasil_keys::body::Notice {
                space: *granted,
                rotation: *rotation,
                public: key.public.clone(),
                from_now_on,
            },
            heads,
        ))
    }

    /// Grants a space (roster.md, "Grants of spaces and effective
    /// membership"): its members that propagate reach this space at the
    /// lower of the two levels, never above `write`. The grant carries a
    /// notice of the granted space's grant key and seals it a space wrap.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device administers this space and
    /// propagates in the granted one; as [`Engine::sign_roster`].
    pub async fn grant_space(
        &self,
        space: EventId,
        granted: EventId,
        level: Level,
    ) -> Result<EventId> {
        let change = Change::grant(
            MemberRef::space(granted.0),
            level.min(Level::Write),
            frasil_space::HistoryMode::WithHistory,
            frasil_space::Via::None,
        );
        self.sign_roster(space, vec![change]).await
    }

    /// Signs and commits the twin of a roster event that changes who
    /// administers (peers.md, "The skeleton", a change): it grants a slot to
    /// each device the event grants `administer`, its token sealed to the
    /// grantee, or lowers the slot of the device it lowers.
    async fn sign_twin(
        &self,
        state: &mut State,
        space: &EventId,
        plan: &SpaceEventPlan,
        administers: &frasil_peers::twins::AdministerChanges,
    ) -> Result<EventId> {
        let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
        let me = self.device_id();
        let my_slot = replica
            .slot_of(&me)
            .map(|info| info.slot)
            .ok_or(Error::NotAllowed("this device holds no administrator slot"))?;
        if Self::pseudonym_late(state, space) {
            return Err(Error::NotAllowed(
                "this pseudonym cannot sign a twin in the current skeleton",
            ));
        }
        let pseudonym = state
            .pseudonyms
            .get(space)
            .and_then(|held| held.iter().rfind(|(slot, _)| *slot == my_slot))
            .map(|(_, signer)| signer)
            .ok_or(Error::NotAllowed(
                "this device has not enrolled in its slot",
            ))?;
        // A fresh salt for each twin keeps c(R) unknown until the twin is
        // published (peers.md, "Skeleton derivations").
        let salt = *self.shared.platform.draw::<32>()?;
        let c = twin_commitment(&me, plan.seq, &twin_secret(&plan.body_key(&me)), &salt);
        let effect = if let Some(lowered) = administers.lowers.first() {
            let slot = replica
                .slot_of(lowered)
                .map(|info| info.slot)
                .ok_or(Error::NotAllowed("the lowered administrator has no slot"))?;
            ChangeEffect::Lower(slot)
        } else {
            // Each grantee's keys, which its device ID commits to: the
            // token is sealed to the X-Wing key among them.
            let keys: BTreeMap<DeviceId, &PublicKeys> = plan
                .changes
                .iter()
                .flatten()
                .filter_map(|change| change.keys.as_deref())
                .chain(
                    replica
                        .roster()
                        .members_in()
                        .filter_map(|(_, state)| state.keys.as_deref()),
                )
                .map(|keys| (keys.device_id(), keys))
                .collect_map();
            // The rank each grant gives, as the roster event sets it
            // (roster.md, 2.3 Changes, key 15; peers.md, the grant map's
            // `rank`).
            let ranks = frasil_space::state::administer_grant_ranks(
                plan.changes.as_deref().unwrap_or_default(),
                replica.roster(),
            );
            let mut grants = Vec::new();
            for (index, device) in administers.grants.iter().enumerate() {
                let xwing = keys
                    .get(device)
                    .and_then(|keys| keys.keys.xwing())
                    .ok_or(Error::NotAllowed("a granted device names no X-Wing key"))?;
                let slot = SlotRef::new(
                    c,
                    u8::try_from(index).map_err(|_| Error::Class("Malformed"))?,
                );
                grants.push(
                    grant_map_with(
                        space,
                        slot,
                        device,
                        &xwing[..],
                        &*self.shared.platform.draw::<32>()?,
                        &*self.shared.platform.draw::<64>()?,
                        ranks
                            .get(index)
                            .copied()
                            .unwrap_or(frasil_peers::limits::MAX_RANK),
                    )
                    .map_err(Error::class)?,
                );
            }
            ChangeEffect::Grants(grants)
        };
        let author = *pseudonym.device_id();
        let (seq, prev) = Self::next(state, space, &author);
        // A twin cites, beside skeleton events, the checkpoints its roster
        // event follows, and declares the same cuts (roster.md, 3.15.8);
        // never a late event but through its `prev`.
        let mut parents = replica.skeleton_heads_after(prev);
        parents.extend(plan.cuts.iter().copied());
        parents.sort_unstable();
        parents.dedup();
        let signed = writer::storage_event(
            pseudonym,
            *space,
            seq,
            prev,
            parents,
            plan.cuts.clone(),
            &StorageBody::Change {
                twin: c,
                salt,
                effect,
            },
        );
        self.commit_own(state, *space, &signed, None).await
    }

    /// Enrols a fresh pseudonym in this device's administrator slot, if it
    /// holds one it has not enrolled in (peers.md, "Enrolment"). An honest
    /// client enrols at its first sync after the grant.
    ///
    /// # Errors
    ///
    /// `BadToken` when the slot's token does not open; the store's.
    pub async fn enrol(&self, space: &EventId) -> Result<Option<EventId>> {
        let mut state = self.lock().await;
        self.enrol_locked(&mut state, space).await
    }

    /// As [`Self::enrol`], under the device's lock.
    pub(crate) async fn enrol_locked(
        &self,
        state: &mut State,
        space: &EventId,
    ) -> Result<Option<EventId>> {
        if !state.vault.head().may_sign(&space.0) {
            return Ok(None);
        }
        let me = self.device_id();
        let Some(replica) = state.replicas.get(space) else {
            return Ok(None);
        };
        if replica.level_of(&me) != Some(Level::Administer) || replica.needs_later_version() {
            return Ok(None);
        }
        let Some(info) = replica.slot_of(&me).cloned() else {
            return Ok(None);
        };
        let held = state
            .pseudonyms
            .get(space)
            .is_some_and(|held| held.iter().any(|(slot, _)| *slot == info.slot));
        // A pseudonym whose enrolment neither the cut of the checkpoint the
        // device follows names nor follows that checkpoint is late: it is in
        // no skeleton after the cut. Once the device votes for the
        // checkpoint, it enrols the slot again after it, with the same
        // token: the new enrolment is the slot's vote for the cut (peers.md,
        // "Skeleton cuts", "A late enrolment").
        let stale = held && {
            let facts = replica.checkpoint_facts();
            let voted = |c: EventId| {
                replica.log().is_some_and(|log| {
                    log.chain(&me)
                        .iter()
                        .any(|&id| id == c || log.follows(id, c) == Ok(true))
                })
            };
            // Only under the checkpoint the device follows: a pending one
            // may never take effect, and an enrolment after it would then
            // be in no skeleton.
            facts
                .following
                .is_some_and(|c| Self::enrolment_late(state, space, &info.slot, c) && voted(c))
        };
        if replica.enrolled(&info.slot).is_some() || (!stale && held) {
            return Ok(None);
        }
        let token = if let Some(grant) = &info.grant {
            open_token(
                grant,
                space,
                info.slot.reference,
                &me,
                &self.shared.keys.xwing_seed,
            )
            .map_err(Error::class)?
        } else {
            // After truncation the cut keeps the slot's public keys, but
            // not the grant's sealed token. Its pseudonym record keeps the
            // token needed to enrol again.
            let Some(TableValue::Pseudonym(Pseudonym {
                token: Some(token), ..
            })) = state
                .vault
                .get(&space.0, Table::Pseudonym, &slot_item(info.slot))
                .await?
            else {
                return Ok(None);
            };
            zeroize::Zeroizing::new(*token.expose())
        };
        // The enrolment follows the checkpoint the device follows, and
        // cites no late event (it has no `prev`).
        let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
        let parents = replica.skeleton_heads_after(None);
        let cuts = replica.cuts_for(&parents)?;
        // Its binding is sealed under the secret of the checkpoint its cuts
        // name whose cut lists the slot, the smallest if several; else of
        // the roster event that made the slot (peers.md, 2.5, "After a
        // checkpoint").
        let listing = replica.log().and_then(|log| {
            cuts.iter()
                .copied()
                .filter(|&c| {
                    log.event(c)
                        .and_then(frasil_peers::skeleton::named_twin)
                        .and_then(|cut| log.event(cut))
                        .and_then(frasil_peers::cut::read_cut)
                        .is_some_and(|cut| cut.slots.iter().any(|entry| entry.slot == info.slot))
                })
                .min()
        });
        if info.grant.is_none() {
            let keys = frasil_peers::derive::SlotKeys::from_token(&token);
            let matches = listing
                .and_then(|checkpoint| {
                    let log = replica.log()?;
                    let cut = log
                        .event(checkpoint)
                        .and_then(frasil_peers::skeleton::named_twin)?;
                    let cut = log.event(cut).and_then(frasil_peers::cut::read_cut)?;
                    cut.slots.into_iter().find(|entry| entry.slot == info.slot)
                })
                .is_some_and(|entry| {
                    entry.slot_ed.as_ref() == Some(keys.ed_public())
                        && entry.slot_mldsa_hash == Some(keys.mldsa_hash())
                });
            if !matches {
                return Err(Error::Class("BadToken"));
            }
        }
        let sealed_by = listing.unwrap_or(info.origin);
        let body_key = replica.body_key(&sealed_by).ok_or(Error::NotAllowed(
            "the event the binding is sealed under is not opened",
        ))?;
        let ed = self.shared.platform.draw::<32>()?;
        let mldsa = self.shared.platform.draw::<32>()?;
        // A pseudonym has no X-Wing key (peers.md, "Skeleton derivations").
        let pseudonym = Signer::from_seeds(&ed, &mldsa, None);
        let signed = writer::enrolment(
            &self.shared.platform,
            &self.shared.keys.signer,
            &pseudonym,
            *space,
            info.slot,
            &token,
            &twin_secret(&body_key),
            parents,
            cuts,
        )?;
        let reading = self.read_timeline(state).await?;
        let event = frasil_events::decode(&signed).map_err(Error::class)?;
        let mut batch = Batch {
            signs: true,
            ..Batch::default()
        };
        state.vault.put(
            &mut batch,
            &space.0,
            Table::Pseudonym,
            &slot_item(info.slot),
            &TableValue::Pseudonym(Pseudonym {
                token: Some(StoredSecret::new(*token)),
                seeds: Some((StoredSecret::new(*ed), StoredSecret::new(*mldsa))),
            }),
        )?;
        put_own(
            &state.vault,
            &mut batch,
            space,
            &event,
            &pending_record(&event),
        )?;
        state.vault.commit(batch).await?;
        let id = event.id();
        let replica = state.replicas.get_mut(space).ok_or(Error::UnknownSpace)?;
        let (placed, _) = replica.place(vec![event.clone()]);
        state
            .outboxes
            .entry(*space)
            .or_default()
            .add(*event.author(), 1, id);
        // The late pseudonym stays held beside the new one, newest last, so
        // that what it signed still reaches the peers.
        state
            .pseudonyms
            .entry(*space)
            .or_default()
            .push((info.slot, pseudonym));
        self.settle(state, *space, vec![id], reading).await?;
        let _ = self.shared.notices.send(Notice {
            space: *space,
            placed,
            withdrawn: Vec::new(),
            wanted: Vec::new(),
        });
        Ok(Some(id))
    }

    /// Grants a device directly (roster.md, "Changes"): at `level`, with
    /// history or from now on, admitted as `via` says. The grant carries the
    /// device's three keys and names it by the device ID they give; the
    /// caller learned that device ID in a way it trusts, an admission code,
    /// a person's list or a roster (roster.md, "A device's keys").
    ///
    /// # Errors
    ///
    /// As [`sign_roster`](Self::sign_roster).
    pub async fn grant_device(
        &self,
        space: EventId,
        keys: PublicKeys,
        level: Level,
        history: frasil_space::HistoryMode,
        via: frasil_space::Via,
    ) -> Result<EventId> {
        self.grant_device_at(space, keys, level, None, history, via)
            .await
    }

    /// [`Engine::grant_device`] at `level`, with `rank` exactly when `level`
    /// is `administer` ([`Engine::grant_administrator`]).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for `administer` without a rank, or a rank at
    /// another level; as [`Engine::grant_administrator`].
    pub async fn grant_device_at(
        &self,
        space: EventId,
        keys: PublicKeys,
        level: Level,
        rank: Option<u8>,
        history: frasil_space::HistoryMode,
        via: frasil_space::Via,
    ) -> Result<EventId> {
        let change = match (level, rank) {
            (Level::Administer, Some(rank)) => {
                Change::grant_administrator(keys, rank, history, via)
            }
            (Level::Administer, None) => {
                return Err(Error::Invalid(
                    "an administrator is granted at a rank: Engine::grant_administrator",
                ));
            }
            (_, Some(_)) => return Err(Error::Invalid("only an administrator has a rank")),
            (level, None) => Change::grant_device(keys, level, history, via),
        };
        self.sign_roster(space, vec![change]).await
    }

    /// Grants a device `administer` at `rank`, 0 to 255, a larger rank
    /// outranking a smaller one (roster.md, 2.3 Changes, "Ranks"): at most
    /// this device's own rank. Otherwise as [`Engine::grant_device`].
    ///
    /// # Errors
    ///
    /// `HigherRank` for a rank above this device's own; as
    /// [`sign_roster`](Self::sign_roster).
    pub async fn grant_administrator(
        &self,
        space: EventId,
        keys: PublicKeys,
        rank: u8,
        history: frasil_space::HistoryMode,
        via: frasil_space::Via,
    ) -> Result<EventId> {
        let change = Change::grant_administrator(keys, rank, history, via);
        self.sign_roster(space, vec![change]).await
    }

    /// Grants a device as the space's recovery member: `administer` at the
    /// top rank, marked `frasil.dormant` (roster.md, 3.15.7, "Dormant
    /// administrators"). Only a device at the top rank grants one.
    ///
    /// # Errors
    ///
    /// `HigherRank` unless this device holds the top rank; as
    /// [`Engine::grant_administrator`].
    pub async fn grant_recovery_member(
        &self,
        space: EventId,
        keys: PublicKeys,
        history: frasil_space::HistoryMode,
        via: frasil_space::Via,
    ) -> Result<EventId> {
        let mut change =
            Change::grant_administrator(keys, frasil_space::change::MAX_RANK, history, via);
        change.capabilities = Some(vec![frasil_space::Capability {
            name: frasil_space::checkpoint::DORMANT.to_owned(),
            mode: frasil_space::CapabilityMode::Extends,
        }]);
        self.sign_roster(space, vec![change]).await
    }

    /// Notes that the always-on peer `by` holds `ids` of a space: events it
    /// sent, listed as its heads or acknowledged. A peer is counted as
    /// reached from its first such note until [`Self::peer_gone`].
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) fn peer_holds(&self, space: EventId, by: [u8; 32], ids: &[EventId]) {
        let mut holdings = self
            .shared
            .peer_holdings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        holdings
            .entry(space)
            .or_default()
            .entry(by)
            .or_default()
            .extend(ids.iter().copied());
    }

    /// The device IDs of the pseudonyms this device holds in a space.
    pub(crate) async fn pseudonym_ids(&self, space: &EventId) -> Vec<DeviceId> {
        self.lock().await.pseudonym_ids(space)
    }

    /// Notes that a peer answered `erased` for a space.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) fn note_erased_at_peer(&self, space: EventId) {
        self.shared
            .erased_at_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(space);
    }

    /// Whether a peer answered `erased` for a space.
    pub(crate) fn erased_at_peer(&self, space: &EventId) -> bool {
        self.shared
            .erased_at_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(space)
    }

    /// Notes that the always-on peer `by` is no longer reached.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(crate) fn peer_gone(&self, by: [u8; 32]) {
        let mut holdings = self
            .shared
            .peer_holdings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for peers in holdings.values_mut() {
            peers.remove(&by);
        }
    }

    /// What each always-on peer this device reaches in a space is known to
    /// hold: the events it sent, listed or acknowledged.
    fn peer_holdings_of(&self, state: &State, space: &EventId) -> Vec<BTreeSet<EventId>> {
        let holdings = self
            .shared
            .peer_holdings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(peers) = holdings.get(space) else {
            return Vec::new();
        };
        peers
            .iter()
            .map(|(by, held)| {
                let mut held = held.clone();
                if let Some(acknowledged) = state
                    .outboxes
                    .get(space)
                    .and_then(|outbox| outbox.acknowledged(&Acknowledger::Peer(*by)))
                {
                    held.extend(acknowledged.iter().copied());
                }
                held
            })
            .collect()
    }

    /// Makes this device sign roster events without checking ranks first,
    /// as a client that does not check them would, so that a test can see
    /// what other replicas and peers make of the events (`HigherRank`,
    /// `RankInPlace`). Never for an application.
    #[doc(hidden)]
    pub fn sign_without_rank_checks(&self, on: bool) {
        self.shared
            .unchecked_ranks
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// This device's rank in the space, while it administers there.
    pub async fn my_rank(&self, space: &EventId) -> Option<u8> {
        let me = MemberRef::device(self.device_id());
        self.read(space, |replica| {
            replica.roster().state(&me).and_then(|state| state.rank)
        })
        .await
        .ok()
        .flatten()
    }

    /// Removes a member (roster.md, "Changes"), with the rotation keys.md
    /// requires: the removed member receives nothing sealed after it.
    ///
    /// # Errors
    ///
    /// As [`sign_roster`](Self::sign_roster).
    pub async fn remove(&self, space: EventId, member: MemberRef) -> Result<EventId> {
        self.sign_roster(space, vec![Change::remove(member)]).await
    }

    /// Heals (keys.md, "Healing"): a key event that rotates, delivering the
    /// new state to every device of the merged roster and linking back to
    /// the state it heals.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device writes in the space;
    /// [`Error::SyncBeforeWriting`]; the store's.
    pub async fn heal(&self, space: EventId) -> Result<EventId> {
        let mut state = self.lock().await;
        Self::check_may_sign(&state, &space)?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.level_of(&self.device_id()) < Some(Level::Write) {
            return Err(Error::NotAllowed("key events need write"));
        }
        // The heal renews the principals of granted spaces that owe a
        // response, where this device can notice them.
        let propagates = replica.propagates(&self.device_id());
        let owed: Vec<crate::maintenance::Owed> = self
            .owed(&state, &space)
            .into_iter()
            .filter(|o| propagates && (o.list || self.notice_of(&state, &o.granted).is_ok()))
            .collect();
        let breaks = owed.iter().any(|o| o.breaks);
        let id = self.rotate(&mut state, space, &owed, breaks).await?;
        drop(state);
        self.after_rotation(space, &owed).await?;
        Ok(id)
    }

    /// Fresh random bytes from the platform.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`].
    #[cfg_attr(not(feature = "adapter-records"), allow(dead_code))]
    pub(crate) fn nonce<const N: usize>(&self) -> Result<[u8; N]> {
        self.shared.platform.nonce::<N>()
    }

    /// The wall clock, in seconds since 1970-01-01T00:00:00Z, when known.
    #[cfg_attr(not(feature = "adapter-records"), allow(dead_code))]
    pub(crate) fn wall_clock(&self) -> Option<u64> {
        self.shared.platform.clock.wall()
    }

    /// A new document stream's opening: its type and a fresh salt
    /// (units.md, "Streams"). The stream exists from its first unit.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`].
    pub fn new_stream(&self, adapter_type: &str) -> Result<Opening> {
        Ok(Opening::with_salt(
            adapter_type,
            self.shared.platform.nonce::<16>()?,
        ))
    }

    /// Writes a unit (units.md, "What a writer does"): sealed under the
    /// current state of this device's view, citing every maximal space
    /// event among its parents, with `stream_prev` set to its previous unit
    /// in the stream. `content` comes from `content(seq)`, given the unit's
    /// `seq`, since an adapter may bind it (adapter-loro.md's
    /// incarnations).
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device writes in the space;
    /// [`Error::SyncBeforeWriting`]; the adapter's refusal; the store's.
    pub async fn write_unit(
        &self,
        space: EventId,
        stream: &Opening,
        content: impl FnOnce(&Replica, u64) -> Result<Vec<u8>>,
    ) -> Result<EventId> {
        self.write_in(
            space,
            stream.stream(),
            Some(stream.clone()),
            &stream.type_.clone(),
            content,
        )
        .await
    }

    /// Writes a unit of the system stream, of one of Frasil's own types.
    ///
    /// # Errors
    ///
    /// As [`write_unit`](Self::write_unit).
    pub async fn write_system(
        &self,
        space: EventId,
        adapter_type: &str,
        content: Vec<u8>,
    ) -> Result<EventId> {
        let system = self
            .read(&space, Replica::system_stream)
            .await?
            .ok_or(Error::NotAllowed("the genesis is not opened"))?;
        self.write_in(space, system, None, adapter_type, |_, _| Ok(content))
            .await
    }

    async fn write_in(
        &self,
        space: EventId,
        stream: StreamId,
        opening: Option<Opening>,
        adapter_type: &str,
        content: impl FnOnce(&Replica, u64) -> Result<Vec<u8>>,
    ) -> Result<EventId> {
        let mut state = self.lock().await;
        self.write_parts(
            &mut state,
            space,
            stream,
            opening,
            adapter_type,
            |replica, seq, _| {
                Ok(UnitParts {
                    content: content(replica, seq)?,
                    ..UnitParts::default()
                })
            },
        )
        .await
    }

    /// Writes a unit of these parts (units.md, "What a writer does"): sealed
    /// under the current state, citing the replica's heads, after this
    /// writer's previous unit in the stream. `parts` is given the replica,
    /// the unit's `seq` and its parents.
    pub(crate) async fn write_parts(
        &self,
        state: &mut State,
        space: EventId,
        stream: StreamId,
        opening: Option<Opening>,
        adapter_type: &str,
        parts: impl FnOnce(&Replica, u64, &[EventId]) -> Result<UnitParts>,
    ) -> Result<EventId> {
        self.publish_own_lists(state, space).await?;
        // An agent's adds go first (ext-recovery-agent.md, "Relay and
        // veto").
        #[cfg(feature = "ext-recovery-agent")]
        self.relay_owed(state, space).await?;
        self.write_parts_now(state, space, stream, opening, adapter_type, parts)
            .await
    }

    /// Publishes the author's missing list copies before writing through a person.
    pub(crate) async fn publish_own_lists(&self, state: &mut State, space: EventId) -> Result<()> {
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let system = replica
            .system_stream()
            .ok_or(Error::NotAllowed("the genesis is not opened"))?;
        let mut lists: Vec<_> = replica
            .roster()
            .members_in()
            .filter(|(member, grant)| {
                member.kind == MemberType::Person && grant.level >= Level::Write
            })
            .filter_map(|(member, _)| state.lists.get(&member.id))
            .filter(|list| list.held().writers().contains(&self.device_id().0))
            .collect();
        if lists.is_empty() {
            return Ok(());
        }
        let (_, prev) = Self::next(state, &space, &self.device_id());
        let held = replica.lists_at_base(&replica.parents(prev));
        // A current person path admits the first copy before a former
        // person's revocation is forwarded through that path.
        lists.sort_by_cached_key(|list| list.merge().active(&self.device_id()).is_none());
        let missing: Vec<Vec<u8>> = lists
            .into_iter()
            .flat_map(|list| {
                let adds = list
                    .merge()
                    .member(&self.device_id())
                    .map(|member| member.adds.clone())
                    .unwrap_or_default();
                let holding = list.held();
                if adds.iter().any(|add| {
                    held.iter()
                        .any(|copy| add == copy || holding.precedes(*add, *copy))
                }) {
                    return Vec::new();
                }
                let mut events = list.signed_events();
                // The author's add must fit in the first copy even when
                // the list spans several units.
                events.sort_by_cached_key(|signed| {
                    frasil_events::decode(signed).map_or(2, |event| {
                        if event.is_genesis() {
                            0
                        } else if adds.contains(&event.id()) {
                            1
                        } else {
                            2
                        }
                    })
                });
                events
            })
            .filter(|signed| {
                frasil_events::decode(signed).is_ok_and(|event| !held.contains(&event.id()))
            })
            .collect();
        for chunk in missing.chunks(frasil_units::limits::MAX_LIST_EVENTS) {
            let content = frasil_units::own::list_copy_content(chunk);
            Box::pin(self.write_parts_now(
                state,
                space,
                system,
                None,
                frasil_units::types::LIST,
                |_, _, _| {
                    Ok(UnitParts {
                        content,
                        ..UnitParts::default()
                    })
                },
            ))
            .await?;
        }
        Ok(())
    }

    /// [`write_parts`](Self::write_parts), with nothing written before.
    pub(crate) async fn write_parts_now(
        &self,
        state: &mut State,
        space: EventId,
        stream: StreamId,
        opening: Option<Opening>,
        adapter_type: &str,
        parts: impl FnOnce(&Replica, u64, &[EventId]) -> Result<UnitParts>,
    ) -> Result<EventId> {
        Self::check_may_sign(state, &space)?;
        #[cfg(feature = "ext-guests")]
        self.writer_check(state, &space).await?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        if replica.level_of(&self.device_id()) < Some(Level::Write) {
            return Err(Error::NotAllowed("units need write"));
        }
        // Peers refuse a released stream's new units (peers.md, 3.18
        // Release and restore).
        if crate::release::released(replica, &stream) {
            return Err(Error::Released);
        }
        // A partial replica holds every stream it writes in.
        #[cfg(feature = "partial-replicas")]
        if replica
            .held_streams()
            .is_some_and(|held| !held.contains(&stream))
            && replica.system_stream() != Some(stream)
        {
            let replica = state.replicas.get_mut(&space).ok_or(Error::UnknownSpace)?;
            let placed = replica.hold_stream(stream);
            if !placed.is_empty() {
                let reading = self.read_timeline(state).await?;
                self.settle(state, space, placed, reading).await?;
            }
        }
        if self.cascade_waits(state, &space) {
            return Err(Error::NotAllowed("a cascaded rotation is due"));
        }
        let (key_reference, key) = self.sealing(state, &space)?;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let (seq, prev) = Self::next(state, &space, &self.device_id());
        let parents = replica.parents(prev);
        let parts = parts(replica, seq, &parents)?;
        let mut inner = frasil_units::Inner::new(adapter_type, parts.content);
        inner.excluded = parts.excluded;
        #[cfg(feature = "ext-restricted-spaces")]
        {
            inner.copied_from = parts.copied_from;
        }
        if let Some(opening) = opening {
            inner = inner.with_opening(opening);
        }
        let mut objects = parts.objects;
        objects.sort_unstable();
        objects.dedup();
        let draft = Draft {
            log: space,
            seq,
            prev,
            parents,
            scheme: Scheme::Ed25519,
            stream,
            key_reference,
            stream_prev: replica.last_unit_in(&stream, &self.device_id()),
            objects,
            compacts: parts.compacts,
            supersedes: parts.supersedes,
        };
        let cuts = replica.cuts_for(&draft.parents)?;
        let signed = draft
            .write_with_cuts(
                &self.shared.keys.signer,
                &key,
                &inner.encode(),
                &self.shared.platform.nonce::<24>()?,
                &cuts,
            )
            .signed;
        self.commit_own_with(state, space, &signed, None, parts.records, parts.stored)
            .await
    }

    /// The device's own events of a space in canonical order: for tests
    /// and for re-sending.
    pub async fn events(&self, space: &EventId) -> Vec<Vec<u8>> {
        let state = self.lock().await;
        let Some(log) = state.replicas.get(space).and_then(Replica::log) else {
            return Vec::new();
        };
        log.canonical()
            .into_iter()
            .filter_map(|id| log.event(id).map(Event::signed))
            .collect()
    }
}

/// A replica's states for the member handshake, newest first: the current
/// state, each of its rotations alone, then every other rotation held by
/// descending height.
#[cfg_attr(not(feature = "iroh"), allow(dead_code))]
fn member_states(replica: &Replica, limit: usize) -> Vec<((EventId, RotationSet), Secret)> {
    let space = replica.space();
    let mut out: Vec<((EventId, RotationSet), Secret)> = Vec::new();
    let push = |set: RotationSet, out: &mut Vec<((EventId, RotationSet), Secret)>| {
        if out.len() < limit
            && !out.iter().any(|((_, held), _)| *held == set)
            && let Some((key, _)) = replica.state_key(&set)
        {
            out.push(((space, set), key));
        }
    };
    if let Some(current) = replica.current().cloned() {
        push(current.clone(), &mut out);
        if current.len() > 1 {
            for id in current.ids() {
                push(RotationSet::single(*id), &mut out);
            }
        }
    }
    if let Some(log) = replica.log() {
        let mut rotations: Vec<(u64, EventId)> = log
            .canonical()
            .into_iter()
            .filter(|id| replica.secrets_held(id))
            .map(|id| (log.height(id).unwrap_or(0), id))
            .collect();
        rotations.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        for (_, id) in rotations {
            push(RotationSet::single(id), &mut out);
        }
    }
    out
}

/// Whether an event is a skeleton root (peers.md, "The skeleton").
#[cfg_attr(not(any(feature = "server", feature = "iroh")), allow(dead_code))]
fn is_root(log: &frasil_events::Log, id: EventId) -> bool {
    log.event(id).is_some_and(|event| {
        event.kind() == kind::STORAGE
            && matches!(
                StorageBody::read(event.unverified_body()),
                Ok(StorageBody::Root { .. })
            )
    })
}

/// A `pseudonym` record's item: the slot reference `[c, index, maker]`.
fn slot_item(slot: SlotId) -> Vec<u8> {
    slot.to_value().encode()
}

/// Reads a `pseudonym` record's item.
fn read_slot(item: &[u8]) -> Option<SlotId> {
    SlotId::read(&frasil_base::cbor::decode(item).ok()?).ok()
}

/// The messages among a session's actions.
/// An `ObjectChunks` message carrying one part of an object.
fn chunk_message(space: EventId, part: crate::snapshots::ObjectPart) -> SyncMessage {
    SyncMessage {
        space,
        message: frasil_units::messages::Message::ObjectChunks {
            locator: part.locator,
            header: part.header,
            index: part.index,
            chunk: part.chunk,
        },
    }
}

/// `ObjectHave` for the objects that the units among these messages'
/// events name and that the replica holds whole, if any.
fn announced_objects(replica: &Replica, messages: &[SyncMessage]) -> Option<SyncMessage> {
    let mut locators: BTreeSet<frasil_adapter::Locator> = BTreeSet::new();
    for message in messages {
        if let frasil_units::messages::Message::Events { events } = &message.message {
            for signed in events {
                if let Ok(event) = frasil_events::decode(signed)
                    && event.kind() == kind::UNIT
                    && let Ok(unit) = frasil_units::Unit::from_event(event)
                {
                    locators.extend(
                        unit.body
                            .objects
                            .iter()
                            .copied()
                            .filter(|l| replica.holds_object(l)),
                    );
                }
            }
        }
    }
    let space = messages.first()?.space;
    if locators.is_empty() {
        return None;
    }
    let mut locators: Vec<_> = locators.into_iter().collect();
    locators.truncate(frasil_units::limits::MAX_MESSAGE_ITEMS);
    Some(SyncMessage {
        space,
        message: frasil_units::messages::Message::ObjectHave {
            locators,
            counts: None,
        },
    })
}

fn sends(actions: Vec<Action>) -> Vec<SyncMessage> {
    actions
        .into_iter()
        .filter_map(|action| match action {
            Action::Send(message) => Some(message),
            _ => None,
        })
        .collect()
}

/// The refs of a roster event that grants persons: the heads of each
/// granted person's list, its known past (roster.md, "Checks across
/// logs").
fn person_refs(
    changes: &[Change],
    lists: &BTreeMap<[u8; 32], crate::lists::PersonList>,
) -> Vec<frasil_events::Ref> {
    let mut refs: Vec<frasil_events::Ref> = changes
        .iter()
        .filter(|c| c.op == Op::Grant)
        .filter_map(|c| c.member)
        .filter(|m| m.kind == MemberType::Person)
        .filter_map(|m| lists.get(&m.id).map(|list| (m.id, list)))
        .flat_map(|(person, list)| {
            list.heads().into_iter().map(move |id| frasil_events::Ref {
                log: EventId(person),
                id,
            })
        })
        .collect();
    refs.sort_unstable_by_key(|a| (a.log.0, a.id.0));
    refs.dedup();
    refs.truncate(64);
    refs
}

/// The recipients of a grant: the device it grants, or the devices the
/// person's merged list vouches for (identity.md, "What a list vouches
/// for").
fn granted_recipients(
    change: &Change,
    lists: &BTreeMap<[u8; 32], crate::lists::PersonList>,
    replica: Option<&Replica>,
) -> Vec<Recipient> {
    if change.op != Op::Grant {
        return Vec::new();
    }
    match change.member {
        Some(member) if member.kind == MemberType::Person => person_recipients(
            &member.id,
            change.level.unwrap_or(Level::Read),
            lists,
            replica,
        ),
        _ => granted_recipient(change).into_iter().collect(),
    }
}

/// The devices a change raises from `read` to a level that writes: each
/// lacks the upload seed of the current state, which a change that does not
/// rotate delivers to it (keys.md, "Deliveries").
fn raised_recipients(
    change: &Change,
    lists: &BTreeMap<[u8; 32], crate::lists::PersonList>,
    replica: &Replica,
) -> Vec<Recipient> {
    let (Op::Change, Some(member), Some(level)) = (change.op, change.member, change.level) else {
        return Vec::new();
    };
    let Some(before) = replica.roster().state(&member) else {
        return Vec::new();
    };
    if level < Level::Write || before.level >= Level::Write {
        return Vec::new();
    }
    match member.kind {
        MemberType::Device => before
            .keys
            .as_ref()
            .filter(|_| !replica.forked(&DeviceId(member.id)))
            .map(|keys| Recipient {
                keys: (**keys).clone(),
                writes: true,
                propagates: before.propagates(),
            })
            .into_iter()
            .collect(),
        MemberType::Person => person_recipients(&member.id, level, lists, Some(replica))
            .into_iter()
            .filter(|r| !replica.forked(&r.keys.device_id()))
            .collect(),
        _ => Vec::new(),
    }
}

/// The devices a person's merged list vouches for, as recipients at a
/// level: each active device, passkey member or recovery key, with the
/// X-Wing key its `add` names. Each receives the upload seed where the
/// person's level writes (keys.md, "The recipient bundle"), a recovery key
/// too: it signs no unit or key event, but the device it brings in writes
/// with what it holds (identity.md, "Kinds of list member").
///
/// In a space (`replica`), a space whose policy forbids agents wraps
/// nothing for a person whose merged list holds an active one, and with the
/// recovery agent each waiting list member the space vouches for is one
/// (identity.md, "What a list vouches for"; ext-recovery-agent.md, "The
/// waiting period").
#[cfg_attr(not(feature = "ext-recovery-agent"), allow(unused_variables))]
pub(crate) fn person_recipients(
    person: &[u8; 32],
    level: Level,
    lists: &BTreeMap<[u8; 32], crate::lists::PersonList>,
    replica: Option<&Replica>,
) -> Vec<Recipient> {
    let Some(list) = lists.get(person) else {
        return Vec::new();
    };
    let merged = list.merge();
    if replica.is_some_and(|r| r.policy().forbid_agents) && merged.holds_active_agent() {
        return Vec::new();
    }
    #[cfg(feature = "ext-recovery-agent")]
    let devices = {
        let none = BTreeSet::new();
        let vouched = replica
            .and_then(|r| r.vouched().get(person))
            .unwrap_or(&none);
        crate::recovery_agent::vouched_recipients(&merged, vouched)
    };
    #[cfg(not(feature = "ext-recovery-agent"))]
    let devices = merged.recipients();
    // The keys each `add` names, which its device ID commits to; a member
    // with no X-Wing key receives no wrap.
    devices
        .into_iter()
        .filter_map(|device| {
            let keys = merged.keys(&device)?;
            keys.xwing.as_ref()?;
            Some(Recipient {
                keys: keys.device_keys(),
                writes: level >= Level::Write,
                propagates: true,
            })
        })
        .collect()
}

/// A recipient for a device a change grants.
fn granted_recipient(change: &Change) -> Option<Recipient> {
    if change.op != Op::Grant {
        return None;
    }
    #[cfg(feature = "ext-invite-links")]
    if let Some(invite) = crate::invite_links::granted_invite(change) {
        return Some(invite);
    }
    let member = change.member?;
    if member.kind != MemberType::Device {
        return None;
    }
    let keys = change.keys.as_ref()?;
    Some(Recipient {
        keys: (**keys).clone(),
        writes: change.level >= Some(Level::Write),
        propagates: change.session.is_none(),
    })
}

fn secrets_of(bundle: &StoredBundle) -> RotationSecrets {
    let take = |slot: &Option<StoredSecret>| slot.as_ref().map(|s| Zeroizing::new(*s.expose()));
    RotationSecrets {
        content: take(&bundle.content),
        upload: take(&bundle.upload),
        grant: take(&bundle.grant),
    }
}

/// The log's `state` record, or an empty one when it has none.
pub(crate) async fn log_state(vault: &Vault, log: &[u8; 32]) -> Result<LogState> {
    for (_, value) in vault.scan(log, Table::State).await? {
        if let TableValue::State(state) = value {
            return Ok(state);
        }
    }
    Ok(LogState::default())
}

/// What a log keeps of its checkpoints in records of its own
/// (`frasil_store::checkpoint_state`): its record keys of kind 5 and its
/// `dropped` records. The events it keeps alone are read with its events.
///
/// # Errors
///
/// The store's.
pub(crate) async fn checkpoint_records(
    vault: &Vault,
    log: &[u8; 32],
) -> Result<frasil_store::checkpoint_state::CheckpointState> {
    let mut out = frasil_store::checkpoint_state::CheckpointState::default();
    for table in [Table::Key, Table::Dropped] {
        for (item, value) in vault.scan(log, table).await? {
            out.take(table, &item, &value);
        }
    }
    out.normalize();
    Ok(out)
}

/// Puts in `batch` the records of `checkpoints` the log does not hold yet
/// (at-rest.md, "Forgetting before a checkpoint"): a `key` record of kind 5
/// per record key, a `dropped` record per dropped event, and an `event`
/// record in state 6 per kept envelope, never in place of an `event`
/// record the log holds, unless `deleted` (deleted in the same batch) names
/// it. Returns whether it put any.
///
/// # Errors
///
/// The store's.
pub(crate) async fn put_checkpoint_records(
    vault: &Vault,
    batch: &mut Batch,
    log: &[u8; 32],
    checkpoints: &frasil_store::checkpoint_state::CheckpointState,
    deleted: &BTreeSet<[u8; 32]>,
) -> Result<bool> {
    let held = checkpoint_records(vault, log).await?;
    let mut put = false;
    for (table, item, value) in checkpoints.beyond(&held).records() {
        if table == Table::Event
            && !<[u8; 32]>::try_from(item.as_slice()).is_ok_and(|id| deleted.contains(&id))
            && vault.get(log, Table::Event, &item).await?.is_some()
        {
            continue;
        }
        vault.put(batch, log, table, &item, &value)?;
        put = true;
    }
    Ok(put)
}

/// The `state` record to put for `state`, or `None` to delete it: a record
/// with no key is not kept (at-rest.md, "Records").
#[cfg(feature = "ext-invite-links")]
pub(crate) fn log_state_value(state: LogState) -> Option<TableValue> {
    (state != LogState::default()).then_some(TableValue::State(state))
}

/// Puts a rotation's secrets as a `key` record of kind 1.
pub(crate) fn put_rotation(
    vault: &Vault,
    batch: &mut Batch,
    space: &EventId,
    rotation: &EventId,
    secrets: &RotationSecrets,
) -> Result<()> {
    let wrap = |slot: &Option<Secret>| slot.as_ref().map(|s| StoredSecret::new(**s));
    let bundle = StoredBundle {
        content: wrap(&secrets.content),
        upload: wrap(&secrets.upload),
        grant: wrap(&secrets.grant),
    };
    if bundle.content.is_none() && bundle.grant.is_none() {
        return Ok(());
    }
    let mut item = vec![StoredKeyKind::Rotation.code()];
    item.extend_from_slice(&rotation.0);
    vault.put(
        batch,
        &space.0,
        Table::Key,
        &item,
        &TableValue::Key(KeyValue::Bundle(bundle)),
    )
}

/// Puts an event a signing key of this device signed: its `event` record,
/// its `outbox` record and its tip.
fn put_own(
    vault: &Vault,
    batch: &mut Batch,
    space: &EventId,
    event: &Event,
    record: &EventRecord,
) -> Result<()> {
    let id = event.id();
    vault.put(
        batch,
        &space.0,
        Table::Event,
        &id.0,
        &TableValue::Event(record.clone()),
    )?;
    let mut item = event.author().0.to_vec();
    item.extend_from_slice(&event.seq().to_be_bytes());
    vault.put(
        batch,
        &space.0,
        Table::Outbox,
        &item,
        &TableValue::Outbox(id.0),
    )?;
    batch.tips.push(Tip {
        log: space.0,
        author: *event.author(),
        seq: event.seq(),
        event: id.0,
    });
    Ok(())
}

/// The most bytes an object's header record takes: a record any larger is
/// a chunk's, read only when the object is.
const OBJECT_HEADER_RECORD_BYTES: usize = 64 * 1024;

/// An own event's record before its verdict is reached.
/// An event's `event` record as the replica holds it: its verdict, flags
/// and first sight, and for a unit kept of a forgotten past what was frozen
/// of it (at-rest.md, keys 6 to 8; `crate::frozen`).
pub(crate) fn event_record(replica: &Replica, event: &Event, id: EventId) -> EventRecord {
    let (event_state, class) = replica.event_state(&id);
    let mut flags = 0;
    if replica.verified(&id) {
        flags |= FLAG_VERIFIED;
    }
    if replica.status(&id).is_some() && is_provisional(replica, &id) {
        flags |= FLAG_PROVISIONAL;
    }
    let (state, class, frozen) = match replica.frozen_content.get(&id) {
        Some(frozen) => {
            let (state, class, at_rest) = crate::frozen::record(frozen);
            (state, class, Some(at_rest))
        }
        None => (event_state, class.map(str::to_owned), None),
    };
    EventRecord {
        signed: event.signed(),
        state,
        flags,
        class,
        first_sight: replica.first_sight(&id).copied(),
        frozen,
    }
}

fn pending_record(event: &Event) -> EventRecord {
    EventRecord {
        signed: event.signed(),
        state: frasil_store::tables::EventState::Pending,
        flags: 0,
        class: None,
        first_sight: None,
        frozen: None,
    }
}

/// Whether a removal is an invite's close, which need not rotate
/// (ext-invite-links.md, "Keys").
#[cfg_attr(not(feature = "ext-invite-links"), allow(unused_variables))]
fn closes(replica: &Replica, change: &Change) -> bool {
    #[cfg(feature = "ext-invite-links")]
    if let Some(member) = &change.member {
        return crate::invite_links::is_close(replica, member);
    }
    false
}

/// Whether a space snapshot offered on a member connection is the
/// connection's: its `sender` is the device the connection identified
/// (units.md, "The space snapshot"; transport.md, "The member handshake:
/// the initiator, and Identify").
fn offered_by(signed: &[u8], space: &EventId, by: Acknowledger) -> bool {
    let Acknowledger::Member(remote) = by else {
        return false;
    };
    frasil_units::snapshot::SpaceSnapshot::read(signed, space, &())
        .is_ok_and(|read| read.unverified().sender.device_id().0 == remote)
}

/// Whether an event's verdict rests on a key received whole or handed
/// over.
fn is_provisional(replica: &Replica, id: &EventId) -> bool {
    let Some(event) = replica.event(*id) else {
        return false;
    };
    if event.kind() != kind::SPACE {
        return false;
    }
    let Some(visible) = crate::replica::visible(event) else {
        return false;
    };
    match visible.sealed_under() {
        Some(state) => replica
            .state_key(state)
            .is_some_and(|(_, provisional)| provisional),
        None => false,
    }
}

/// How many events the persons' lists the device keeps hold.
fn list_events(lists: &BTreeMap<[u8; 32], crate::lists::PersonList>) -> usize {
    lists.values().map(crate::lists::PersonList::len).sum()
}

/// roster.md, 2.3 Changes: capability names that begin `frasil.` are
/// Frasil's, and an application defines none. A client signs a reserved
/// capability only where a document of Frasil's sets it, as the guest
/// preset adds `frasil.nothing-at-rest`, or where a change carries it over
/// from the state the member holds now, as a change of a member's other
/// capabilities does; it refuses any other one an application asks for.
fn reserved_capabilities(replica: &Replica, changes: &[Change]) -> Result<()> {
    for change in changes {
        let held = (change.op == Op::Change)
            .then(|| change.member.and_then(|m| replica.roster().state(&m)))
            .flatten();
        for capability in change.capabilities.iter().flatten() {
            // `frasil.dormant` is Frasil's to set on an administrator
            // (roster.md, 3.15.7, "Dormant administrators").
            if capability.is_reserved()
                && !capability.is_set_by_frasil()
                && capability.name != frasil_space::checkpoint::DORMANT
                && !held.is_some_and(|state| state.capabilities.contains(capability))
            {
                return Err(Error::Invalid(
                    "a capability whose name begins frasil. is Frasil's, not the application's",
                ));
            }
        }
    }
    Ok(())
}

/// roster.md, 3.6 Authority at the place, and 2.3 Changes, "Ranks", checked
/// before signing so that the device leaves no void event in the log: an
/// administrator is made at a rank; nobody grants above its own rank, nor
/// changes or removes an administrator of a higher rank; and a rank never
/// changes in place.
fn ranks_allow(replica: &Replica, me: &DeviceId, changes: &[Change]) -> Result<()> {
    let roster = replica.roster();
    let own = MemberRef::device(*me);
    let mine = roster.state(&own).and_then(|state| state.rank).unwrap_or(0);
    for change in changes {
        let makes = change.level == Some(Level::Administer)
            && change.member.is_some_and(|m| m.kind == MemberType::Device)
            && matches!(change.op, Op::Grant | Op::Change);
        if makes && change.rank.is_none() {
            return Err(Error::Invalid("an administrator is made at a rank"));
        }
        if change.rank.is_some_and(|rank| rank > mine) {
            return Err(Error::Class("HigherRank"));
        }
        let Some(member) = change.member.filter(|m| *m != own) else {
            continue;
        };
        let Some(state) = roster.state(&member) else {
            continue;
        };
        if state.level == Level::Administer && matches!(change.op, Op::Change | Op::Remove) {
            if state.rank.unwrap_or(0) > mine {
                return Err(Error::Class("HigherRank"));
            }
            if makes && change.rank != state.rank {
                return Err(Error::Class("RankInPlace"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
std::thread_local! {
    /// Lets a test sign roster events without `administer`, as a member
    /// that holds the space's keys can by hand: what replicas must judge.
    pub(crate) static SIGN_UNCHECKED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether a test lets this thread sign roster events without
/// `administer`; never outside tests.
fn signs_unchecked() -> bool {
    #[cfg(test)]
    return SIGN_UNCHECKED.with(std::cell::Cell::get);
    #[cfg(not(test))]
    false
}

/// The verdict an `event` record keeps, as a replica that forgot holds it:
/// valid, or void with its class; `None` for a held or pending event.
fn recorded_status(record: &EventRecord) -> Option<frasil_space::Status> {
    match record.state {
        // Valid by the kind's own way: a skeleton event, an anchor or an
        // event of an ignorable kind is kept with no effect of its own; any
        // other, by the rules.
        frasil_store::tables::EventState::Valid => {
            let kept = frasil_events::decode(&record.signed).is_ok_and(|event| {
                matches!(event.kind(), kind::STORAGE | kind::ANCHOR)
                    || event.kind() >= kind::FIRST_IGNORABLE
            });
            Some(frasil_space::Status::Valid(match kept {
                true => frasil_space::Valid::Kept,
                false => frasil_space::Valid::Rules,
            }))
        }
        frasil_store::tables::EventState::Refused => {
            let class = frasil_space::RosterClass::from_name(record.class.as_deref()?)?;
            Some(frasil_space::Status::void_with(class))
        }
        _ => None,
    }
}
