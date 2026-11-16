//! The space checkpoints' model check (roster.md, "Checkpoints"), ported
//! from the reference's seeded check: random histories of grants, removals,
//! backdated counter-removals, forks, units, checkpoints with their record
//! objects, votes, events that cite against the following rule, and devices
//! offline across checkpoints, built from signed and sealed events.
//!
//! Every history is also signed as dishonest parties would, from generators
//! of their own so that the honest steps keep their draws: an administrator
//! that takes another member's view and checkpoints citing every head
//! (unfenced), naming as predecessor the last checkpoint in effect, an
//! earlier one or none; and, once per history at most, a split: the
//! administrators part into two groups that see only each other, and in
//! each one checkpoints while another removes every administrator of the
//! other group, before the checkpoint or after it, and the group votes (a
//! lone group is roster.md's backdated checkpoint, section 4). Every event
//! signed without the following rule's fence, on parents chosen against
//! it, or by an attacker, is marked dishonest. What each seed adds:
//!
//! - seeds 0 mod 4 build no checkpoint;
//! - with feature `ext-invite-links`, odd seeds grant invite keys, claim
//!   them (some on older views, racing), and close or revoke them;
//! - seeds 1 and 2 mod 3 grant a team space, a second log whose rotations
//!   commit to real grant keys (each rotation's seed kept, and the grant
//!   public key its notices carry): the founder grants it with a notice of
//!   its genesis; the team removes t1 or grants it again, or admits a
//!   device "from now on" (a break and a grant rotation), and the team's
//!   founder T0 responds here by a grant rotation whose refs name the
//!   team's event and that notices it, "from now on" for a break; t1 writes
//!   units here through the grant. The team, resolved as a `Space` as its
//!   founder holds it while the history is built and whole when it is
//!   checked, is passed through `OtherLogs::with_space` to every judge;
//! - seeds 2 mod 4, a quarter, are drawn for collusion: B and C are granted
//!   `administer` at the start at A's rank or below, early on one that
//!   outranks them or is their senior equal removes both (two fallen
//!   administrators that can collude), or B removes A, its senior equal
//!   (A is then heard), removals prefer administrators of the remover's
//!   rank, and backdated checkpoints come more often, by colluders mostly;
//! - seeds 0 and 1 mod 3 have guests (ext-guests.md): an administrator
//!   grants a device a session with an expiry, "from now on", guests write
//!   units, and administrators end sessions, so that records carry sessions
//!   and expiries across checkpoints;
//! - seeds 1 and 3 mod 5 grant a person whose device list (identity.md)
//!   adds q3, revokes q2 and checkpoints, its devices acking, while its
//!   devices write units and heal here, and the founder responds to the
//!   revocation; every judge reads the list whole;
//! - seeds with checkpoints but 1 mod 3 grant up to two recovery members
//!   (administrators with `frasil.dormant`, which no checkpoint waits for),
//!   each of a rank at most its granter's, and a recovery member removes a
//!   heard member of a rank at most its own that a checkpoint it follows
//!   waits for (roster.md, 3.15.4, "Waiting for"), which the record's
//!   ranks decide whether to count as an excuse;
//! - every seed's members release and restore two streams on their views
//!   (peers.md, 3.18), readers' and removed members' requests among them,
//!   void by the write rule;
//! - every seed's administrators change other members' standing: a writer
//!   lowered to reader, a reader raised to writer, a writer made a
//!   suggester (`suggest`, narrowing), before and after checkpoints, while
//!   those members write units.
//!
//! A backdated checkpoint (roster.md, section 4) is signed by a removed
//! administrator on its stale view, removing the administrators it sees
//! there, one per event: alone; with a colluding removed administrator; with
//! a device it grants there at its own rank; or, in collusion seeds,
//! removing only those it outranks (selective). Honest administrators answer a checkpoint that
//! waits for a member it hears: one that outranks it removes it again after
//! the checkpoint, or the heard member accepts its lowering and removes
//! itself. For each history:
//!
//! - (i) a replica that forgot under each checkpoint some view had in
//!   effect, holding only what roster.md, "Forgetting, and starting from a
//!   checkpoint", lets it keep (the genesis, the kept checkpoint, the
//!   envelopes its cuts reach, the late events and the events after it,
//!   with the IDs of what it dropped), agrees with one that kept everything
//!   on every event both hold, on the chain from its kept checkpoint, on
//!   the roster of the last world, and on the key graph rooted at it: its
//!   events, valid set, current states and space principals; or, where it
//!   holds a rival (section 3.15.6), holds every event pending;
//! - (ii) the chain in effect at every intermediate view is a prefix of the
//!   final one, except where the two part at concurrent checkpoints whose
//!   electorates share no device and the final one has the smaller ID
//!   (section 3.15.4);
//! - (iii) with no checkpoint, the verdicts are the resolution procedure's
//!   own;
//! - (iv) a successor with another successor of its key in its past is void,
//!   whatever checkpoint lies between (ext-invite-links.md);
//! - (v) every record reads back to its own bytes;
//! - a replica that lacks some record objects judges every other event as a
//!   replica that never received those checkpoints, and holds them and what
//!   follows them;
//! - (vi) a backdated checkpoint never takes effect when one of its victims
//!   outranks its author, unless a victim voted for it: by a dishonest
//!   step, or honestly, where the checkpoint was not contested for it
//!   (section 3.15.7), which is checked at each of its events after the
//!   checkpoint; or its victims were shown forked, which excuses them. Each
//!   attack is counted by mode and standing, and each in effect with why the
//!   rules let it in. Every member a checkpoint in effect hears, or that
//!   its past lowered only by members it outranks, voted for it or was
//!   excused (section 3.15.4);
//! - (vii) no valid roster event lowers an administrator of a higher rank
//!   than its author's at its place (section 3.6), in the resolution with
//!   no checkpoint and in the last world;
//! - (viii) a replica that forgot the person's list under its checkpoint in
//!   effect agrees with one that kept it on every verdict and the chain,
//!   given the forgotten adds' keys from another source; without them it
//!   holds as `NoHybridKey` only events the other drops (section 3.15.8);
//! - (ix) a replica that forgot under each checkpoint, keeping of the
//!   releases and restores of its past that are not late under an earlier
//!   checkpoint only the maximal ones of each stream, with the verdicts it
//!   gave them, finds every stream released exactly where one that kept
//!   everything does, ordering what it kept before what follows its kept
//!   checkpoint ([`Checkpointed::precedes`]) (units.md, 3.12);
//! - (x) what a replica froze of each unit of its kept checkpoint's past
//!   when that checkpoint took effect in some view (its verdict, and its
//!   author's reach and capabilities at its place) is what one that kept
//!   everything shows at the end, the author's standing in the
//!   checkpoint's record notwithstanding (units.md, "The past of a kept
//!   checkpoint"); each frozen unit whose author's frozen standing differs
//!   from the record's is counted.
//!
//! Erasures, credentials requests, cuts and their standing entries are
//! skeleton events, which these histories do not sign (twins are assumed):
//! they are checked on the fixed scenarios of peers.json's `skeleton_cuts`
//! (`tests/standing.rs`).
//!
//! Administrators carry ranks (roster.md, 2.3 Changes, "Ranks"): the
//! founder the top one, A one drawn from 100, 200 and 255 (200 and 255 in
//! collusion seeds), every later administrator one drawn at most its
//! granter's. Honest devices never cite a checkpoint contested for them,
//! nor what follows it (section 3.15.7).
//!
//! Seeds 1 to 3 run by default; `FRASIL_CHECKPOINT_SEEDS=n` runs 1 to `n`,
//! and `a-b` runs `a` to `b`.

mod common;

#[path = "support/summary.rs"]
mod summary;

use common::example;
use frasil_base::errors::Class;
use frasil_crypto::fixtures::FixtureKeys;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_crypto::sizes::XWING_PUBLIC;
use frasil_events::{Envelope, Event, EventId, Log, Ref, Stub, decode, kind};
use frasil_identity::body::ListBody;
use frasil_identity::{DeviceList, Kind as ListKind, MemberKeys};
use frasil_keys::RotationSet;
use frasil_keys::body::{GrantSlot, Inner, Notice, RotationKeys, Seal, VisiblePart};
use frasil_keys::derive::{
    GrantKey, SecretKind, body_commitment, body_key, read_credential, state_secret, upload_key,
};
use frasil_peers::body::{Restored, StorageBody};
use frasil_space::change::MAX_RANK;
use frasil_space::checkpoint_record::digest;
use frasil_space::part::{CheckpointPart, Genesis, RosterPart, Update};
use frasil_space::{
    CapabilityMode, Change, CheckpointInputs, Checkpointed, DeviceKeys, HeldList, HistoryMode,
    Kept, KeyEventChecks, Keyring, Level, Limits, MemberRef, MemberType, Op, Options, OtherLogs,
    Policy, Record, Roster, Space, Status, Twins, UnitBodies, UnitBody, Via,
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// A small deterministic generator: splitmix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next() % items.len() as u64) as usize]
    }

    /// Shuffles `items` in place (Fisher and Yates).
    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
    }
}

/// The predecessor a checkpoint names: the last checkpoint in effect in its
/// past, as an honest client names it, or one a dishonest administrator
/// chooses.
#[derive(Debug, Clone, Copy)]
enum Previous {
    /// The last checkpoint in effect in its past.
    Chain,
    /// None: its record is derived from its whole past.
    None,
    /// This checkpoint, its record derived from that checkpoint's world
    /// over its past where it can be, else the chain's record naming it.
    Named(EventId),
}

/// What a space event's sealed part carries besides its roster part, and
/// the parents it cites where they are chosen.
#[derive(Debug, Clone, Default)]
struct Sealed {
    /// Sealed key 1: a grant rotation.
    grant_rotation: bool,
    /// Sealed key 2: a break, as an admission "from now on" makes one.
    is_break: bool,
    /// Sealed key 18: the events of other logs it names.
    refs: Vec<Ref>,
    /// Sealed key 5: notices of the granted space's rotations.
    notices: Vec<Notice>,
    /// The parents it cites, where its author chooses them.
    parents: Option<BTreeSet<EventId>>,
}

/// No other log, for a granted space's own resolution: leaked once per
/// thread so that a resolved space may borrow it for as long as it lives.
fn no_others() -> &'static OtherLogs<'static> {
    thread_local! {
        static NONE: &'static OtherLogs<'static> = Box::leak(Box::new(OtherLogs::none()));
    }
    NONE.with(|none| *none)
}

/// Every unit opens, with no refs.
struct Plain;

impl UnitBodies for Plain {
    fn list_copy(&self, unit: &Event) -> Vec<Event> {
        let Some(content) = unit.unverified_body().strip_prefix(b"list:") else {
            return Vec::new();
        };
        frasil_base::cbor::decode(content)
            .ok()
            .and_then(|value| {
                value.as_array().ok().map(|items| {
                    items
                        .iter()
                        .filter_map(|item| {
                            item.as_bytes().ok().and_then(|signed| decode(signed).ok())
                        })
                        .collect()
                })
            })
            .unwrap_or_default()
    }

    fn open(&self, _: &Event) -> UnitBody {
        UnitBody::Opened(Vec::new())
    }
}

/// A space's history being built: each device holds a view, closed under
/// parents, and signs onto it.
struct History {
    prefix: String,
    log: Option<Log>,
    views: BTreeMap<String, BTreeSet<EventId>>,
    /// Each rotation's content key.
    krot: BTreeMap<EventId, [u8; 32]>,
    checkpoints: BTreeSet<EventId>,
    tampered: BTreeSet<EventId>,
    /// Each checkpoint's record, as its object's plaintext.
    records: BTreeMap<EventId, Vec<u8>>,
    /// Each successor, by the invite key that signed it.
    successors: BTreeMap<EventId, String>,
    /// The checkpoints signed without the following rule's fence.
    unfenced: usize,
    labels: u64,
    /// Each administrator's rank, by name; the founder's is the top one.
    ranks: BTreeMap<String, u8>,
    /// Whether each rotation commits to a real grant key, derived from its
    /// seed, so that a granting space's notice can name it (keys.md,
    /// "Notices and space principals"): a granted space's history.
    grant_keys: bool,
    /// With `grant_keys`, each rotation's grant seed and the grant public
    /// key a notice of it carries.
    grant_seeds: BTreeMap<EventId, [u8; 32]>,
    grant_public: BTreeMap<EventId, Box<[u8; XWING_PUBLIC]>>,
    /// The devices whose keys another history's prefix derives: a granted
    /// space's devices acting here through the grant.
    aliases: BTreeMap<String, String>,
    /// The space this one grants, with its own log and views.
    team: Option<Box<History>>,
    /// The events signed as a dishonest party signs them: without the
    /// following rule's fence, or on parents chosen against it.
    dishonest: BTreeSet<EventId>,
    /// The device list of the person this space grants, as its devices
    /// hold it, whole.
    list: Option<DeviceList>,
}

impl History {
    fn new(prefix: &str, founder: &str) -> Self {
        Self::build(prefix, founder, false)
    }

    /// A granted space's history: each of its rotations commits to a grant
    /// key.
    fn granted(prefix: &str, founder: &str) -> Self {
        Self::build(prefix, founder, true)
    }

    fn build(prefix: &str, founder: &str, grant_keys: bool) -> Self {
        let mut history = Self {
            prefix: prefix.to_owned(),
            log: None,
            views: BTreeMap::new(),
            krot: BTreeMap::new(),
            checkpoints: BTreeSet::new(),
            tampered: BTreeSet::new(),
            records: BTreeMap::new(),
            successors: BTreeMap::new(),
            unfenced: 0,
            labels: 0,
            ranks: BTreeMap::from([(founder.to_owned(), MAX_RANK)]),
            grant_keys,
            grant_seeds: BTreeMap::new(),
            grant_public: BTreeMap::new(),
            aliases: BTreeMap::new(),
            team: None,
            dishonest: BTreeSet::new(),
            list: None,
        };
        history.genesis(founder);
        history
    }

    fn log(&self) -> &Log {
        self.log.as_ref().expect("a genesis")
    }

    fn signer(&self, name: &str) -> Signer {
        let prefix = self.aliases.get(name).unwrap_or(&self.prefix);
        FixtureKeys::from_identity_seed(&example(&format!("{prefix}/{name}/ed25519"))).signer()
    }

    fn keys(&self, name: &str) -> DeviceKeys {
        let signer = self.signer(name);
        DeviceKeys {
            ed: *signer.identity_key(),
            keys: signer.keys().clone(),
        }
    }

    fn device(&self, name: &str) -> [u8; 32] {
        self.signer(name).device_id().0
    }

    fn label(&mut self, what: &str) -> String {
        self.labels += 1;
        format!("{}/{}/{what}", self.prefix, self.labels)
    }

    /// A rotation's content key and visible keys. With `grant_keys`, its
    /// grant commitment is that of the grant key its seed derives, a break's
    /// as a break's, and the seed comes too.
    fn rotation(&self, label: &str, is_break: bool) -> ([u8; 32], RotationKeys, Option<[u8; 32]>) {
        let content = example(&format!("{label}/content-key"));
        let seed = self
            .grant_keys
            .then(|| example(&format!("{label}/grant-seed")));
        let grant_commitment = match &seed {
            Some(seed) => GrantKey::derive(seed).commitment(is_break),
            None => example(&format!("{label}/grant-commitment")),
        };
        let keys = RotationKeys {
            grant_commitment,
            read: read_credential(&content).public,
            upload: upload_key(&example(&format!("{label}/upload"))).public,
        };
        (content, keys, seed)
    }

    /// Keeps a rotation's grant seed and the public key its notices carry.
    fn keep_grant_key(&mut self, id: EventId, seed: Option<[u8; 32]>) {
        if let Some(seed) = seed {
            self.grant_public.insert(id, GrantKey::derive(&seed).public);
            self.grant_seeds.insert(id, seed);
        }
    }

    /// keys.md's notice of one of this space's rotations, for the space
    /// that grants it.
    fn notice(&self, rotation: EventId, from_now_on: bool) -> Notice {
        Notice {
            space: self.log().id(),
            rotation,
            public: self.grant_public[&rotation].clone(),
            from_now_on,
        }
    }

    fn genesis(&mut self, founder: &str) {
        let signer = self.signer(founder);
        let author = *signer.device_id();
        let mut system_stream = [0u8; 16];
        system_stream.copy_from_slice(&example(&format!("{}/system-stream", self.prefix))[..16]);
        let part = RosterPart::Genesis(Box::new(Genesis::new(
            self.keys(founder),
            Policy::default(),
            system_stream,
        )));
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&example(&format!("{}/nonce", self.prefix))[..16]);
        let (content, rotation, seed) = self.rotation(&format!("{}/genesis", self.prefix), false);
        let key = body_key(&content, &nonce, &author, 1);
        let inner = Inner {
            grant: Some(GrantSlot::Rotation),
            roster: Some(part.encode()),
            ..Inner::default()
        };
        let body = VisiblePart {
            seal: Seal::Rotation(rotation),
            deliveries: Vec::new(),
            sealed: inner.seal_with(&key, &nonce, &author, 1, &[0x6e; 24]),
            nonce: Some(nonce),
            commitment: body_commitment(&key),
            twin: None,
        }
        .encode();
        let signed = Envelope {
            kind: kind::SPACE,
            log: None,
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq: 1,
            prev: None,
            parents: Vec::new(),
            cuts: Vec::new(),
            body,
            scheme: Scheme::Hybrid,
        }
        .sign(&signer);
        let event = decode(&signed).expect("the genesis decodes");
        let id = event.id();
        self.log = Some(Log::new(event).expect("a genesis"));
        self.krot.insert(id, content);
        self.keep_grant_key(id, seed);
        self.views.insert(founder.to_owned(), BTreeSet::from([id]));
    }

    fn view(&self, name: &str) -> BTreeSet<EventId> {
        self.views.get(name).cloned().unwrap_or_default()
    }

    fn reach(&self, id: EventId) -> BTreeSet<EventId> {
        let log = self.log();
        log.event(id)
            .map(|e| {
                frasil_events::cuts::reach(log, e.cuts())
                    .expect("the whole log holds every envelope")
            })
            .unwrap_or_default()
    }

    fn below(&self, x: EventId, y: EventId) -> bool {
        x == y || self.reach(y).contains(&x)
    }

    /// The checkpoint a device follows in a view: the latest valid one of
    /// the view its own events follow first, else the smallest ID.
    fn followed(
        &self,
        name: &str,
        view: &BTreeSet<EventId>,
        contested: &BTreeSet<EventId>,
    ) -> Option<EventId> {
        let cps: Vec<EventId> = view
            .iter()
            .copied()
            .filter(|c| {
                self.checkpoints.contains(c) && !self.tampered.contains(c) && !contested.contains(c)
            })
            .collect();
        let top: Vec<EventId> = cps
            .iter()
            .copied()
            .filter(|&c| !cps.iter().any(|&d| c != d && self.below(c, d)))
            .collect();
        if top.is_empty() {
            return None;
        }
        let author = self.device(name);
        let log = self.log();
        let last = view
            .iter()
            .copied()
            .filter(|&i| log.event(i).unwrap().author().0 == author)
            .max_by_key(|&i| (log.event(i).unwrap().seq(), i));
        if let Some(last) = last {
            let reached = self.reach(last);
            let own: Vec<EventId> = top
                .iter()
                .copied()
                .filter(|&c| c == last || reached.contains(&c))
                .collect();
            if let Some(&c) = own.iter().min() {
                return Some(c);
            }
        }
        top.into_iter().min()
    }

    /// The checkpoints of a view contested for device `name` (roster.md,
    /// 3.15.7, "Contested checkpoints"): one whose record hears it, or whose
    /// author or kept administrator a valid concurrent roster event of its
    /// view lowers, signed by a member that outranks the one it lowers.
    fn contested(&self, name: &str, view: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        let cps: Vec<EventId> = view
            .iter()
            .copied()
            .filter(|c| self.checkpoints.contains(c))
            .collect();
        if cps.is_empty() {
            return BTreeSet::new();
        }
        let keys = self.keyring();
        let envelopes = BTreeMap::<EventId, Event>::new();
        self.with_others(|others| {
            let judge = Checkpointed::new(
                CheckpointInputs {
                    log: self.log(),
                    options: options(&keys, others),
                    objects: &self.records,
                    envelopes: &envelopes,
                    slots: None,
                },
                None,
            );
            let device = frasil_crypto::device::DeviceId(self.device(name));
            cps.into_iter()
                .filter(|&c| judge.contest(&device, c, view).is_some())
                .collect()
        })
    }

    /// Runs `f` with the other logs this space reads: the granted team, as
    /// its founder holds its log, resolved; none without a team.
    fn with_others<R>(&self, f: impl FnOnce(&OtherLogs<'_>) -> R) -> R {
        let keys = self.team.as_ref().map(|team| team.keyring());
        let space = self.team.as_ref().zip(keys.as_ref()).map(|(team, keys)| {
            let view = team.view("T0");
            Space::resolve(team.log(), Some(&view), options(keys, no_others()))
                .expect("the team resolves")
        });
        let mut others = OtherLogs::none();
        if let Some(space) = &space {
            others = others.with_space(space);
        }
        if let Some(list) = &self.list {
            others = others.with_list(HeldList::new(list.clone()));
        }
        f(&others)
    }

    /// The events a device does not cite: a checkpoint contested for it and
    /// everything after it, which citing would vote for; and, when it
    /// follows a checkpoint, those concurrent with that checkpoint.
    fn fence(&self, name: &str, view: &BTreeSet<EventId>) -> BTreeSet<EventId> {
        let contested = self.contested(name, view);
        let log = self.log();
        let mut out: BTreeSet<EventId> = view
            .iter()
            .copied()
            .filter(|&x| contested.iter().any(|&c| x == c || log.precedes(c, x)))
            .collect();
        let Some(c) = self.followed(name, view, &contested) else {
            return out;
        };
        out.extend(
            view.iter()
                .copied()
                .filter(|&x| x != c && !log.precedes(x, c) && !log.precedes(c, x)),
        );
        out
    }

    fn parents_for(
        &self,
        name: &str,
        view: &BTreeSet<EventId>,
        prev: Option<EventId>,
        fence: bool,
    ) -> BTreeSet<EventId> {
        let blocked = if fence {
            self.fence(name, view)
        } else {
            BTreeSet::new()
        };
        let open: BTreeSet<EventId> = view.difference(&blocked).copied().collect();
        let mut parents: BTreeSet<EventId> = self.log().heads_in(&open).into_iter().collect();
        parents.extend(prev);
        parents
    }

    /// The rotations a device holds at the top of its view: the state a
    /// space event that does not rotate is sealed under.
    fn current_state(&self, name: &str) -> RotationSet {
        let view = self.view(name);
        let log = self.log();
        let rotations: Vec<EventId> = view
            .iter()
            .copied()
            .filter(|i| self.krot.contains_key(i))
            .collect();
        let top: Vec<EventId> = rotations
            .iter()
            .copied()
            .filter(|&i| !rotations.iter().any(|&j| j != i && log.precedes(i, j)))
            .collect();
        RotationSet::new(top).expect("a state")
    }

    /// Signs an event of `kind` onto a device's view: `None` when it cannot,
    /// as for a device whose view is empty, or an event the envelope rules
    /// refuse (more than four cuts).
    #[allow(clippy::too_many_arguments)]
    fn act(
        &mut self,
        name: &str,
        event_kind: u8,
        body: impl FnOnce(&mut Self, &EventId, &frasil_crypto::device::DeviceId, u64) -> Vec<u8>,
        view: Option<BTreeSet<EventId>>,
        seq_prev: Option<(u64, Option<EventId>)>,
        parents: Option<BTreeSet<EventId>>,
        fence: bool,
    ) -> Option<EventId> {
        let signer = self.signer(name);
        let author = *signer.device_id();
        let w = view.unwrap_or_else(|| self.view(name));
        if w.is_empty() {
            return None;
        }
        let log = self.log();
        let (seq, prev) = seq_prev.unwrap_or_else(|| {
            let last = w
                .iter()
                .copied()
                .filter(|&i| *log.event(i).unwrap().author() == author)
                .max_by_key(|&i| (log.event(i).unwrap().seq(), i));
            match last {
                Some(last) => (log.event(last).unwrap().seq() + 1, Some(last)),
                None => (1, None),
            }
        });
        let honest = fence && parents.is_none();
        let mut parents = parents.unwrap_or_else(|| self.parents_for(name, &w, prev, fence));
        parents.extend(prev);
        let parents: Vec<EventId> = parents.into_iter().collect();
        if parents.is_empty() {
            return None;
        }
        let cuts = frasil_events::cuts::expected(self.log(), &self.checkpoints, &parents).ok()?;
        let space = self.log().id();
        let body = body(self, &space, &author, seq);
        let scheme = if event_kind == kind::UNIT {
            Scheme::Ed25519
        } else {
            Scheme::Hybrid
        };
        let signed = Envelope {
            kind: event_kind,
            log: Some(space),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents,
            cuts,
            body,
            scheme,
        }
        .sign(&signer);
        let event = decode(&signed).ok()?;
        let id = event.id();
        let log = self.log.as_mut().expect("a genesis");
        log.place(event).expect("placed");
        let mut past = log.past(id);
        past.insert(id);
        self.views.entry(name.to_owned()).or_default().extend(past);
        if !honest {
            self.dishonest.insert(id);
        }
        Some(id)
    }

    /// A space event carrying a roster part, sealed as a rotation or under
    /// the device's current state.
    fn space_event(
        &mut self,
        name: &str,
        part: Option<Vec<u8>>,
        rotates: bool,
        grant_rotation: bool,
        view: Option<BTreeSet<EventId>>,
    ) -> Option<EventId> {
        self.space_event_fenced(name, part, rotates, grant_rotation, view, true)
    }

    /// A space event as [`Self::space_event`] signs it, citing every head
    /// of the view when `fence` is false.
    fn space_event_fenced(
        &mut self,
        name: &str,
        part: Option<Vec<u8>>,
        rotates: bool,
        grant_rotation: bool,
        view: Option<BTreeSet<EventId>>,
        fence: bool,
    ) -> Option<EventId> {
        let sealed = Sealed {
            grant_rotation,
            ..Sealed::default()
        };
        self.space_event_with(name, part, rotates, sealed, view, fence)
    }

    /// A space event with what [`Sealed`] puts in its sealed part.
    fn space_event_with(
        &mut self,
        name: &str,
        part: Option<Vec<u8>>,
        rotates: bool,
        sealed: Sealed,
        view: Option<BTreeSet<EventId>>,
        fence: bool,
    ) -> Option<EventId> {
        let Sealed {
            grant_rotation,
            is_break,
            mut refs,
            notices,
            parents,
        } = sealed;
        refs.sort_unstable();
        let label = self.label("space event");
        let (content, rotation, seed) = self.rotation(&label, rotates && is_break);
        let under = if rotates {
            None
        } else {
            let state = self.current_state(name);
            let space = self.log().id();
            let inputs: Vec<[u8; 32]> = state.ids().iter().map(|r| self.krot[r]).collect();
            let secret = state_secret(SecretKind::Content, &space, &state, &inputs).unwrap();
            Some((state.clone(), *secret))
        };
        let id = self.act(
            name,
            kind::SPACE,
            |_, space, author, seq| {
                let secret = under.as_ref().map_or(content, |(_, secret)| *secret);
                let key = body_key(&secret, &space.0, author, seq);
                let inner = Inner {
                    grant: (rotates && grant_rotation).then_some(GrantSlot::Rotation),
                    is_break: rotates && is_break,
                    notices,
                    refs,
                    roster: part,
                    ..Inner::default()
                };
                VisiblePart {
                    seal: match &under {
                        None => Seal::Rotation(rotation),
                        Some((state, _)) => Seal::Under(state.clone()),
                    },
                    deliveries: Vec::new(),
                    sealed: inner.seal_with(&key, &space.0, author, seq, &[0x6e; 24]),
                    nonce: None,
                    commitment: body_commitment(&key),
                    twin: None,
                }
                .encode()
            },
            view,
            None,
            parents,
            fence,
        )?;
        if rotates {
            self.krot.insert(id, content);
            self.keep_grant_key(id, seed);
        }
        Some(id)
    }

    fn update(
        &mut self,
        name: &str,
        change: Change,
        grant_rotation: bool,
        view: Option<BTreeSet<EventId>>,
    ) -> Option<EventId> {
        let part = RosterPart::Update(Update {
            changes: vec![change],
        })
        .encode();
        self.space_event(name, Some(part), true, grant_rotation, view)
    }

    /// `by` grants `who` at `level`. An administrator takes the rank
    /// [`Self::ranks`] names for it, else its granter's.
    fn grant(&mut self, by: &str, who: &str, level: Level) -> Option<EventId> {
        let mut change =
            Change::grant_device(self.keys(who), level, HistoryMode::WithHistory, Via::Code);
        if level == Level::Administer {
            let rank = self
                .ranks
                .get(who)
                .or_else(|| self.ranks.get(by))
                .copied()
                .unwrap_or(MAX_RANK);
            change = change.with_rank(rank);
        }
        self.update(by, change, false, None)
    }

    /// `by` grants `who` `administer` with `frasil.dormant`, extending: a
    /// recovery member (roster.md, 3.15.4), which no checkpoint waits for,
    /// of the rank [`Self::ranks`] names for it, else its granter's.
    fn grant_recovery(&mut self, by: &str, who: &str) -> Option<EventId> {
        let rank = self
            .ranks
            .get(who)
            .or_else(|| self.ranks.get(by))
            .copied()
            .unwrap_or(MAX_RANK);
        let mut change = Change::grant_device(
            self.keys(who),
            Level::Administer,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .with_rank(rank);
        change.capabilities = Some(vec![frasil_space::Capability {
            name: "frasil.dormant".into(),
            mode: CapabilityMode::Extends,
        }]);
        self.update(by, change, false, None)
    }

    fn remove(&mut self, by: &str, who: &str, view: Option<BTreeSet<EventId>>) -> Option<EventId> {
        let member = MemberRef::device(frasil_crypto::device::DeviceId(self.device(who)));
        self.update(by, Change::remove(member), true, view)
    }

    /// `by` changes `who` to `level`, and makes it a suggester (`suggest`,
    /// narrowing) when `suggest`; its capabilities stay as they are
    /// otherwise.
    fn change_standing(
        &mut self,
        by: &str,
        who: &str,
        level: Level,
        suggest: bool,
    ) -> Option<EventId> {
        let member = MemberRef::device(frasil_crypto::device::DeviceId(self.device(who)));
        let mut change = Change::set_level(member, level);
        change.capabilities = suggest.then(|| {
            vec![frasil_space::Capability {
                name: "suggest".into(),
                mode: CapabilityMode::Narrows,
            }]
        });
        self.update(by, change, false, None)
    }

    /// `by` admits `who` at `write` "from now on": a break and a grant
    /// rotation (keys.md).
    fn admit_from_now_on(&mut self, by: &str, who: &str) -> Option<EventId> {
        let change = Change::grant_device(
            self.keys(who),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        );
        let part = RosterPart::Update(Update {
            changes: vec![change],
        })
        .encode();
        let sealed = Sealed {
            grant_rotation: true,
            is_break: true,
            ..Sealed::default()
        };
        self.space_event_with(by, Some(part), true, sealed, None, true)
    }

    /// `by` grants the team space at `write`, noticing the team's genesis.
    fn grant_team(&mut self, by: &str) -> Option<EventId> {
        let team = self.team.as_ref().expect("a team");
        let notice = team.notice(team.log().id(), false);
        let change = Change::grant(
            MemberRef::space(team.log().id().0),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        );
        let part = RosterPart::Update(Update {
            changes: vec![change],
        })
        .encode();
        let sealed = Sealed {
            notices: vec![notice],
            ..Sealed::default()
        };
        self.space_event_with(by, Some(part), true, sealed, None, true)
    }

    /// `by` responds to the team's event `changed`: a key event that rotates,
    /// a grant rotation, whose refs name `changed` and that notices it, "from
    /// now on" (a break) where the team admitted a device so (roster.md,
    /// "Responses"; keys.md, "Notices and space principals").
    fn respond(&mut self, by: &str, changed: EventId, from_now_on: bool) -> Option<EventId> {
        let team = self.team.as_ref().expect("a team");
        let sealed = Sealed {
            grant_rotation: true,
            is_break: from_now_on,
            refs: vec![Ref {
                log: team.log().id(),
                id: changed,
            }],
            notices: vec![team.notice(changed, from_now_on)],
            parents: None,
        };
        self.space_event_with(by, None, true, sealed, None, true)
    }

    /// Whether `name` is in force in this space, as its founder holds the
    /// log.
    fn holds_member(&self, name: &str) -> bool {
        let keys = self.keyring();
        let view = self.view("T0");
        Space::resolve(self.log(), Some(&view), options(&keys, no_others()))
            .ok()
            .is_some_and(|space| {
                space
                    .roster()
                    .state(&MemberRef::device(frasil_crypto::device::DeviceId(
                        self.device(name),
                    )))
                    .is_some()
            })
    }

    fn unit(
        &mut self,
        name: &str,
        view: Option<BTreeSet<EventId>>,
        seq_prev: Option<(u64, Option<EventId>)>,
        parents: Option<BTreeSet<EventId>>,
        fence: bool,
    ) -> Option<EventId> {
        let label = self.label("unit");
        self.act(
            name,
            kind::UNIT,
            move |_, _, _, _| format!("unit: {label}").into_bytes(),
            view,
            seq_prev,
            parents,
            fence,
        )
    }

    fn anchor(&mut self, name: &str) -> Option<EventId> {
        self.act(
            name,
            kind::ANCHOR,
            |_, _, _, _| Vec::new(),
            None,
            None,
            None,
            true,
        )
    }

    /// A release or a restore of `stream` by `name` on its view (peers.md,
    /// 3.18): a writer's storage event, which the write rule judges.
    fn request(&mut self, name: &str, stream: [u8; 16], release: bool) -> Option<EventId> {
        let body = match release {
            true => StorageBody::Release { stream },
            false => StorageBody::Restore(Restored::Stream(stream)),
        };
        self.act(
            name,
            kind::STORAGE,
            move |_, _, _, _| body.encode(),
            None,
            None,
            None,
            true,
        )
    }

    fn sync(&mut self, names: &[&str]) {
        let union: BTreeSet<EventId> = names.iter().flat_map(|n| self.view(n)).collect();
        for name in names {
            self.views.insert((*name).to_owned(), union.clone());
        }
    }

    fn keyring(&self) -> Keyring {
        let mut keys = Keyring::default();
        for (&id, &key) in &self.krot {
            keys.rotations.insert(id, Zeroizing::new(key));
        }
        keys
    }

    /// `by` signs a checkpoint over its view: the record of its past, as a
    /// judge that holds that past derives it; `tamper` leaves an
    /// administrator out of it.
    fn checkpoint(&mut self, by: &str, tamper: bool) -> Option<EventId> {
        self.checkpoint_as(by, tamper, true, Previous::Chain)
    }

    /// `by` signs a checkpoint over its view. An honest client follows
    /// (`fence`) and names the last checkpoint in effect in its past; a
    /// dishonest administrator may cite every head of its view, concurrent
    /// checkpoints included, and name any predecessor.
    fn checkpoint_as(
        &mut self,
        by: &str,
        tamper: bool,
        fence: bool,
        previous: Previous,
    ) -> Option<EventId> {
        let w = self.view(by);
        let author = self.device(by);
        let log = self.log();
        let last = w
            .iter()
            .copied()
            .filter(|&i| log.event(i).unwrap().author().0 == author)
            .max_by_key(|&i| (log.event(i).unwrap().seq(), i));
        let parents = self.parents_for(by, &w, last, fence);
        let mut past = BTreeSet::new();
        for &p in &parents {
            past.extend(log.past(p));
            past.insert(p);
        }
        let keys = self.keyring();
        let envelopes = BTreeMap::<EventId, Event>::new();
        // The record of `past` as a judge that holds every record object
        // derives it: naming the last checkpoint in effect in `past`, none,
        // or a checkpoint the dishonest party picked (roster.md, 3.15.3).
        let record = self.with_others(|others| {
            let judge = Checkpointed::new(
                CheckpointInputs {
                    log,
                    options: options(&keys, others),
                    objects: &self.records,
                    envelopes: &envelopes,
                    slots: None,
                },
                None,
            );
            match previous {
                Previous::Chain => judge.record_for(&past),
                Previous::None => judge.record_naming(&past, None),
                Previous::Named(named) => judge.record_naming(&past, Some(named)),
            }
        })?;
        let mut record = record;
        if tamper {
            let admin = record
                .members
                .iter()
                .position(|m| m.level == Level::Administer && m.member.id != author)?;
            record.members.remove(admin);
        }
        let plaintext = record.encode();
        // (v) Every record reads back to its own bytes.
        assert_eq!(
            Record::read(&plaintext).map(|read| read.encode()),
            Ok(plaintext.clone()),
            "a record reads back to its own bytes"
        );
        let label = self.label("checkpoint");
        let mut locator = [0u8; 64];
        locator[..32].copy_from_slice(&example(&format!("{label}/locator")));
        locator[32..].copy_from_slice(&digest(&plaintext));
        let part = RosterPart::Checkpoint(CheckpointPart {
            epoch: record.epoch,
            digest: digest(&plaintext),
            size: plaintext.len() as u64,
            locator,
        })
        .encode();
        let id = self.space_event_fenced(by, Some(part), true, true, Some(w), fence)?;
        self.checkpoints.insert(id);
        if tamper {
            self.tampered.insert(id);
        }
        self.records.insert(id, plaintext);
        if !fence {
            self.unfenced += 1;
        }
        Some(id)
    }

    /// `by` signs a checkpoint over its view whose record, the record of
    /// its past otherwise, carries record key 9: a key a later document
    /// defines (roster.md, 2.8 The checkpoint record, step 3).
    fn checkpoint_with_later_key(&mut self, by: &str) -> Option<EventId> {
        let w = self.view(by);
        let log = self.log();
        let mut past = BTreeSet::new();
        for p in self.parents_for(by, &w, None, true) {
            past.extend(log.past(p));
            past.insert(p);
        }
        let keys = self.keyring();
        let envelopes = BTreeMap::<EventId, Event>::new();
        let record = self.with_others(|others| {
            Checkpointed::new(
                CheckpointInputs {
                    log,
                    options: options(&keys, others),
                    objects: &self.records,
                    envelopes: &envelopes,
                    slots: None,
                },
                None,
            )
            .record_for(&past)
        })?;
        let mut value = frasil_base::cbor::decode(&record.encode()).ok()?;
        if let frasil_base::cbor::Value::Map(map) = &mut value {
            map.insert(9, frasil_base::cbor::Value::Unsigned(1));
        }
        let plaintext = value.encode();
        let label = self.label("checkpoint");
        let mut locator = [0u8; 64];
        locator[..32].copy_from_slice(&example(&format!("{label}/locator")));
        locator[32..].copy_from_slice(&digest(&plaintext));
        let part = RosterPart::Checkpoint(CheckpointPart {
            epoch: record.epoch,
            digest: digest(&plaintext),
            size: plaintext.len() as u64,
            locator,
        })
        .encode();
        let id = self.space_event_fenced(by, Some(part), true, true, Some(w), true)?;
        self.checkpoints.insert(id);
        self.records.insert(id, plaintext);
        Some(id)
    }

    /// Whether a replica that holds the whole log judges checkpoint `c`
    /// valid: honest devices follow only such a checkpoint.
    fn judged_valid(&self, c: EventId) -> bool {
        let keys = self.keyring();
        let envelopes = BTreeMap::<EventId, Event>::new();
        self.with_others(|others| {
            Checkpointed::new(
                CheckpointInputs {
                    log: self.log(),
                    options: options(&keys, others),
                    objects: &self.records,
                    envelopes: &envelopes,
                    slots: None,
                },
                None,
            )
            .validity(c)
            .is_valid()
        })
    }

    /// A backdated checkpoint (roster.md, section 4): a removed
    /// administrator, on its stale view, removes the other administrators
    /// it sees there, one per event, then checkpoints citing its whole view
    /// (unfenced). Its mode: `alone`; `colluder`, a second removed
    /// administrator on the same view removing some of them and voting;
    /// or `sybil`, a device it grants `administer` there at its own rank,
    /// which removes some of them. With `bias`, colluders are drawn more
    /// often, and `selective`, removing only those it outranks, is drawn
    /// too. The attack, with the attacker's standing against its
    /// victims: `lower` when a victim holds a higher rank, `equal, junior`
    /// when one of its rank is more senior, `top` when it holds the top rank
    /// and outranks them all, `senior` otherwise. Every event it signs is
    /// dishonest.
    fn takeover(&mut self, rng: &mut Rng, removed: &[&str], bias: bool) -> Option<Attack> {
        let before: BTreeSet<EventId> = self.log().canonical().into_iter().collect();
        let attack = self.takeover_signed(rng, removed, bias);
        let signed: Vec<EventId> = self
            .log()
            .canonical()
            .into_iter()
            .filter(|i| !before.contains(i))
            .collect();
        self.dishonest.extend(signed);
        attack
    }

    fn takeover_signed(&mut self, rng: &mut Rng, removed: &[&str], bias: bool) -> Option<Attack> {
        let attacker = (*rng.pick(removed)).to_owned();
        let view = self.view(&attacker);
        if view.is_empty() {
            return None;
        }
        let keys = self.keyring();
        let resolve = |h: &Self, view: &BTreeSet<EventId>| {
            h.with_others(|others| {
                Space::resolve(h.log(), Some(view), options(&keys, others))
                    .ok()
                    .map(|space| space.roster().clone())
            })
        };
        let roster = resolve(self, &view)?;
        let state_of = |h: &Self, roster: &Roster, name: &str| {
            roster
                .state(&MemberRef::device(frasil_crypto::device::DeviceId(
                    h.device(name),
                )))
                .cloned()
        };
        let me = state_of(self, &roster, &attacker)?;
        if me.level != Level::Administer {
            return None;
        }
        let mine = me.authority_key();
        let mut helpers = vec![attacker.clone()];
        let modes: &[&str] = if bias && removed.len() > 1 {
            &[
                "alone",
                "colluder",
                "colluder",
                "colluder",
                "colluder",
                "sybil",
                "selective",
            ]
        } else if bias {
            &["alone", "sybil", "selective", "selective"]
        } else {
            &["alone", "colluder", "sybil"]
        };
        let mode = *rng.pick(modes);
        if mode == "colluder" && removed.len() > 1 {
            let pool: Vec<&str> = removed.iter().copied().filter(|&x| x != attacker).collect();
            let other = (*rng.pick(&pool)).to_owned();
            let mut theirs = self.view(&other);
            theirs.extend(view.iter().copied());
            let st = resolve(self, &theirs).and_then(|roster| state_of(self, &roster, &other));
            if st.is_some_and(|st| st.level == Level::Administer) {
                self.views.insert(other.clone(), theirs.clone());
                helpers.push(other);
                self.views
                    .entry(attacker.clone())
                    .or_default()
                    .extend(theirs);
            }
        } else if mode == "sybil" && !self.views.contains_key("Z") {
            // A device it grants there takes its own rank: junior to every
            // administrator before it.
            self.ranks
                .insert("Z".to_owned(), me.rank.unwrap_or(MAX_RANK));
            if self.grant(&attacker, "Z", Level::Administer).is_some() {
                self.sync(&[&attacker, "Z"]);
                helpers.push("Z".to_owned());
            }
        }
        let names: BTreeMap<[u8; 32], String> = self
            .views
            .keys()
            .map(|n| (self.device(n), n.clone()))
            .collect();
        let mut victims: Vec<String> = roster
            .members_in()
            .filter(|(m, st)| m.kind == MemberType::Device && st.level == Level::Administer)
            .filter_map(|(m, _)| names.get(&m.id).cloned())
            .filter(|n| !helpers.contains(n))
            .collect();
        if mode == "selective" {
            victims
                .retain(|v| state_of(self, &roster, v).is_some_and(|st| st.authority_key() > mine));
        }
        if victims.is_empty() {
            return None;
        }
        let helper_names: Vec<String> = helpers.clone();
        for (k, v) in victims.iter().enumerate() {
            let by = helper_names[k % helper_names.len()].clone();
            self.sync_all(&helper_names);
            self.remove(&by, v, None);
        }
        self.sync_all(&helper_names);
        let checkpoint = self.checkpoint_as(&attacker, false, false, Previous::Chain)?;
        for helper in &helper_names[1..] {
            self.sync(&[helper, &attacker]);
            self.anchor(helper);
        }
        let theirs: Vec<frasil_space::AuthorityKey> = victims
            .iter()
            .filter_map(|v| state_of(self, &roster, v))
            .map(|st| st.authority_key())
            .collect();
        let standing = if theirs.iter().any(|k| k.0 < mine.0) {
            "lower"
        } else if theirs.iter().any(|k| *k < mine) {
            "equal, junior"
        } else if me.rank == Some(MAX_RANK) {
            "top"
        } else {
            "senior"
        };
        let mode = match mode {
            "selective" => "selective",
            _ if helpers.len() > 1 => mode,
            _ => "alone",
        };
        Some(Attack {
            checkpoint,
            attackers: helpers,
            victims,
            mode,
            standing,
        })
    }

    /// A heard member's client, told that a valid checkpoint not in effect
    /// in its view hears it, has it remove itself, accepting its lowering
    /// (roster.md, 3.15.7, "Contested checkpoints"): its removal cites the
    /// checkpoint and nothing concurrent with it, so it both votes and
    /// excuses itself. `name` first takes `from`'s view. The removal, with
    /// the checkpoint.
    fn accept_lowering(&mut self, name: &str, from: &str) -> Option<(EventId, EventId)> {
        self.sync(&[name, from]);
        let view = self.view(name);
        let me = frasil_crypto::device::DeviceId(self.device(name));
        let keys = self.keyring();
        let envelopes = BTreeMap::<EventId, Event>::new();
        let c = self.with_others(|others| {
            let judge = Checkpointed::new(
                CheckpointInputs {
                    log: self.log(),
                    options: options(&keys, others),
                    objects: &self.records,
                    envelopes: &envelopes,
                    slots: None,
                },
                None,
            );
            let chain = judge.chain(&view);
            view.iter()
                .copied()
                .filter(|c| self.checkpoints.contains(c) && !chain.contains(c))
                .filter(|&c| judge.heard(c).contains_key(&me) && judge.validity(c).is_valid())
                .min()
        })?;
        let log = self.log();
        let open: BTreeSet<EventId> = view
            .iter()
            .copied()
            .filter(|&x| x == c || log.precedes(x, c) || log.precedes(c, x))
            .collect();
        let last = view
            .iter()
            .copied()
            .filter(|&i| *log.event(i).unwrap().author() == me)
            .max_by_key(|&i| (log.event(i).unwrap().seq(), i));
        if last.is_some_and(|last| !open.contains(&last)) {
            // Its own chain holds an event concurrent with the checkpoint:
            // it cannot follow it without forking.
            return None;
        }
        let parents: BTreeSet<EventId> = log.heads_in(&open).into_iter().collect();
        let member = MemberRef::device(me);
        let part = RosterPart::Update(Update {
            changes: vec![Change::remove(member)],
        })
        .encode();
        // Sealed under the state of what it cites: it removes itself, so it
        // does not rotate.
        self.views.insert(name.to_owned(), open);
        let sealed = Sealed {
            parents: Some(parents),
            ..Sealed::default()
        };
        let x = self.space_event_with(name, Some(part), false, sealed, None, true);
        self.views.entry(name.to_owned()).or_default().extend(view);
        let x = x?;
        // An honest step: the conduct rule lets it cite the checkpoint once
        // it accepts its lowering.
        self.dishonest.remove(&x);
        Some((x, c))
    }

    /// Whether a checkpoint's record hears a member.
    fn hears_someone(&self) -> bool {
        self.records
            .values()
            .any(|plain| Record::read(plain).is_ok_and(|record| !record.heard.is_empty()))
    }

    /// An honest administrator's answer to a checkpoint that waits for a
    /// member it hears (roster.md, 3.15.4, "Waiting for"): `by`, which
    /// follows a valid checkpoint of its view that is not in effect there,
    /// and outranks a heard member it waits for (by rank, or as the
    /// founder), removes that member again after it, which excuses it. The
    /// removals signed, each with the checkpoint it follows.
    fn excuse_heard(&mut self, by: &str) -> Vec<(EventId, EventId)> {
        self.excuse_heard_as(by, false)
            .into_iter()
            .map(|(x, c, _)| (x, c))
            .collect()
    }

    /// [`Self::excuse_heard`] by `by`, or, with `recovery`, by a recovery
    /// member, which removes a heard member it waits for whose rank is at
    /// most its own (roster.md, 3.15.4, "Waiting for"): its removal excuses
    /// that member when the rules count it a recovery member's. Each
    /// removal with the checkpoint and the member it removes.
    fn excuse_heard_as(&mut self, by: &str, recovery: bool) -> Vec<(EventId, EventId, [u8; 32])> {
        let view = self.view(by);
        let contested = self.contested(by, &view);
        let Some(followed) = self.followed(by, &view, &contested) else {
            return Vec::new();
        };
        let keys = self.keyring();
        let envelopes = BTreeMap::<EventId, Event>::new();
        let waiting: Vec<[u8; 32]> = self.with_others(|others| {
            let judge = Checkpointed::new(
                CheckpointInputs {
                    log: self.log(),
                    options: options(&keys, others),
                    objects: &self.records,
                    envelopes: &envelopes,
                    slots: None,
                },
                None,
            );
            if judge.chain(&view).contains(&followed) {
                return Vec::new();
            }
            judge
                .waiting_for(followed, &view)
                .into_iter()
                .filter(|w| w.heard)
                .map(|w| w.device.0)
                .collect()
        });
        let names: BTreeMap<[u8; 32], String> = self
            .views
            .keys()
            .map(|n| (self.device(n), n.clone()))
            .collect();
        let mine = self.ranks.get(by).copied().unwrap_or(0);
        let mut out = Vec::new();
        for device in waiting {
            let Some(name) = names.get(&device).cloned() else {
                continue;
            };
            let theirs = self.ranks.get(&name).copied().unwrap_or(MAX_RANK);
            let may = match recovery {
                true => mine >= theirs,
                false => by == "P" || mine > theirs,
            };
            if !may {
                continue;
            }
            if let Some(x) = self.remove(by, &name, None)
                && self.log().precedes(followed, x)
            {
                out.push((x, followed, device));
            }
        }
        out
    }

    /// The administrators split in two groups that see only each other. In
    /// each, one administrator checkpoints, and an administrator of the
    /// group removes every administrator of the other group, before the
    /// checkpoint (any of them, the author included: the record then omits
    /// them) or after it (another than its author, so that it excuses
    /// them); every administrator of the group then votes. Each checkpoint
    /// can take effect in its group's view, with an electorate disjoint from
    /// the other's: a lone group is a removed administrator's backdated
    /// checkpoint (roster.md, section 4). Whether both checkpoints were
    /// signed.
    fn split(&mut self, rng: &mut Rng, admins: &[&str]) -> bool {
        let mut admins: Vec<String> = admins.iter().map(|&a| a.to_owned()).collect();
        rng.shuffle(&mut admins);
        let k = 1 + (rng.next() % (admins.len() as u64 - 1)) as usize;
        let groups = [admins[..k].to_vec(), admins[k..].to_vec()];
        for group in &groups {
            self.sync_all(group);
        }
        let mut signed = 0;
        for (g, other) in [(&groups[0], &groups[1]), (&groups[1], &groups[0])] {
            let after = g.len() > 1 && rng.unit() < 0.5;
            let author = g[0].clone();
            let remover = if after {
                g[1].clone()
            } else {
                rng.pick(g).clone()
            };
            if !after {
                for o in other {
                    self.remove(&remover, o, None);
                }
                self.sync_all(g);
            }
            if self.checkpoint(&author, false).is_some() {
                signed += 1;
            }
            self.sync_all(g);
            if after {
                for o in other {
                    self.remove(&remover, o, None);
                }
                self.sync_all(g);
            }
            for d in g {
                if *d != author {
                    self.sync(&[d, &author]);
                    self.anchor(d);
                }
            }
            self.sync_all(g);
        }
        signed == 2
    }

    /// [`Self::sync`] over owned names, for a group of two or more.
    fn sync_all(&mut self, names: &[String]) {
        if names.len() > 1 {
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            self.sync(&names);
        }
    }
}

/// Guests (ext-guests.md, roster.md 3.15.8 "Guests"): an administrator
/// grants a device a session with an expiry, "from now on", and ends the
/// session by removing it. The grant breaks and is no grant rotation, as a
/// session member does not propagate.
impl History {
    fn grant_guest(&mut self, by: &str, who: &str, n: u64) -> Option<EventId> {
        let mut session = [0u8; 16];
        session.copy_from_slice(&example(&format!("{}/session/{who}", self.prefix))[..16]);
        let mut change = Change::grant_device(
            self.keys(who),
            Level::Write,
            HistoryMode::FromNowOn,
            Via::Code,
        );
        change.session = Some(session);
        change.expires_at = Some(1_760_604_800 + 86_400 * n);
        let part = RosterPart::Update(Update {
            changes: vec![change],
        })
        .encode();
        let sealed = Sealed {
            is_break: true,
            ..Sealed::default()
        };
        self.space_event_with(by, Some(part), true, sealed, None, true)
    }

    fn end_session(&mut self, by: &str, who: &str) -> Option<EventId> {
        let member = MemberRef::device(frasil_crypto::device::DeviceId(self.device(who)));
        self.update(by, Change::remove(member), false, None)
    }
}

/// A person this space grants, with a device list of its own (identity.md):
/// its devices q1, q2 and q3 sign the list under the list's prefix and act
/// here through the person; the list adds, revokes and checkpoints, and an
/// administrator here responds to a revocation (roster.md, "Responses").
impl History {
    fn list_keys(&self, name: &str) -> MemberKeys {
        common::space::list_device(&self.aliases[name], name)
    }

    fn person(&self) -> [u8; 32] {
        self.list.as_ref().expect("a list").person_id()
    }

    /// Places each held list event by its own copy in the space.
    fn copy_list(&mut self) {
        let items = self
            .list
            .as_ref()
            .expect("a list")
            .log()
            .canonical()
            .into_iter()
            .map(|id| {
                frasil_base::cbor::Value::from(
                    self.list
                        .as_ref()
                        .unwrap()
                        .log()
                        .event(id)
                        .unwrap()
                        .signed(),
                )
            })
            .collect();
        let mut body = b"list:".to_vec();
        body.extend(frasil_base::cbor::Value::Array(items).encode());
        let _ = self.act(
            "P",
            kind::UNIT,
            move |_, _, _, _| body,
            None,
            None,
            None,
            true,
        );
    }

    /// Signs a list event onto the whole list.
    fn list_sign(&mut self, by: &str, body: &ListBody) -> Option<EventId> {
        let keys = self.list_keys(by);
        let list = self.list.as_mut().expect("a list");
        let signed = list.sign(body, keys.signer());
        list.insert(&signed).ok()?;
        self.copy_list();
        Some(decode(&signed).ok()?.id())
    }

    fn list_add(&mut self, by: &str, who: &str) -> Option<EventId> {
        let person = self.person();
        let adder = *self.list_keys(by).device_id();
        let keys = self.list_keys(who);
        let body = ListBody::add(
            ListKind::Device,
            &keys.public(ListKind::Device),
            keys.prove_possession(&person, &adder, ListKind::Device),
        );
        self.list_sign(by, &body)
    }

    fn list_revoke(&mut self, by: &str, who: &str) -> Option<EventId> {
        let device = *self.list_keys(who).device_id();
        self.list_sign(by, &ListBody::revoke(ListKind::Device, device))
    }

    /// `by` proposes a list checkpoint, as an honest device does, and each
    /// of `voters` acks it.
    fn list_checkpoint(&mut self, by: &str, voters: &[&str]) -> Option<EventId> {
        let keys = self.list_keys(by);
        let list = self.list.as_mut().expect("a list");
        let signed = list.propose_checkpoint(keys.signer()).ok()?;
        list.insert(&signed).ok()?;
        for voter in voters {
            let keys = self.list_keys(voter);
            let list = self.list.as_mut().expect("a list");
            let ack = list.ack(keys.signer());
            let _ = list.insert(&ack);
        }
        self.copy_list();
        Some(decode(&signed).ok()?.id())
    }

    /// `by` grants the person at `write`, with history.
    fn grant_person(&mut self, by: &str) -> Option<EventId> {
        let change = Change::grant(
            MemberRef::person(self.person()),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        );
        self.update(by, change, false, None)
    }

    /// `by` responds to the list's event `ended`: a grant rotation whose
    /// refs name it.
    fn respond_to_list(&mut self, by: &str, ended: EventId) -> Option<EventId> {
        let sealed = Sealed {
            grant_rotation: true,
            refs: vec![Ref {
                log: EventId(self.person()),
                id: ended,
            }],
            ..Sealed::default()
        };
        self.space_event_with(by, None, true, sealed, None, true)
    }
}

/// Invite keys (ext-invite-links.md): an administrator grants one, a key
/// signs a successor claiming a device, and an administrator removes it (a
/// close, or a revocation).
#[cfg(feature = "ext-invite-links")]
impl History {
    fn invite(&mut self, by: &str, key: &str, history: HistoryMode) -> Option<EventId> {
        use frasil_space::ext_invite_links::{CLAIMS_DEVICE, invite_grant};
        let change = invite_grant(
            self.device(key),
            self.keys(key),
            Level::Write,
            history,
            1_760_604_800,
            CLAIMS_DEVICE,
        );
        self.update(by, change, false, None)
    }

    fn claim(&mut self, key: &str, claimant: &str) -> Option<EventId> {
        let member = MemberRef::device(frasil_crypto::device::DeviceId(self.device(claimant)));
        let change = frasil_space::ext_invite_links::successor(member, Some(self.keys(claimant)));
        let part = RosterPart::Update(Update {
            changes: vec![change],
        })
        .encode();
        let id = self.space_event(key, Some(part), false, false, None)?;
        self.successors.insert(id, key.to_owned());
        Some(id)
    }

    fn close(&mut self, by: &str, key: &str) -> Option<EventId> {
        let change = frasil_space::ext_invite_links::revoke_invite(self.device(key));
        self.update(by, change, true, None)
    }
}

/// Without the extension no history grants an invite key.
#[cfg(not(feature = "ext-invite-links"))]
impl History {
    fn invite(&mut self, _: &str, _: &str, _: HistoryMode) -> Option<EventId> {
        None
    }

    fn claim(&mut self, _: &str, _: &str) -> Option<EventId> {
        None
    }

    fn close(&mut self, _: &str, _: &str) -> Option<EventId> {
        None
    }
}

/// An invite key's claims so far: the views it held, how many it signed,
/// and the administrator that granted it.
struct Claims {
    views: Vec<BTreeSet<EventId>>,
    n: usize,
    by: String,
}

fn options<'a>(keys: &'a Keyring, others: &'a OtherLogs<'a>) -> Options<'a> {
    Options {
        keys,
        limits: Limits::PROTOCOL,
        others,
        units: &Plain,
        twins: Twins::Assumed,
        key_checks: KeyEventChecks::StaleSeal,
        notices: None,
    }
}

const DEVICES: [&str; 6] = ["P", "A", "B", "C", "W", "X"];

/// A stream ID the model's releases and restores name.
fn stream_named(name: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&example(name)[..16]);
    out
}

/// Each device's view, by name.
type Views = BTreeMap<String, BTreeSet<EventId>>;

/// A backdated checkpoint a history holds ([`History::takeover`]).
#[derive(Debug)]
struct Attack {
    checkpoint: EventId,
    /// The attacker first, then its colluder or the device it granted.
    attackers: Vec<String>,
    victims: Vec<String>,
    mode: &'static str,
    standing: &'static str,
}

impl Attack {
    /// Whether a victim outranks the attacker.
    fn junior(&self) -> bool {
        matches!(self.standing, "lower" | "equal, junior")
    }
}

/// What a seed's history holds besides the honest steps every history
/// takes.
#[derive(Debug, Clone, Copy, Default)]
struct Kinds {
    /// Checkpoints, with the dishonest parties' steps.
    checkpoints: bool,
    /// Invite keys, claims, races, closes and revocations
    /// (ext-invite-links.md).
    invites: bool,
    /// A granted team space with its own log: its changes, responses with
    /// notices ("from now on" ones included) and units its devices write
    /// here through the grant.
    granted: bool,
    /// Administrators of equal ranks, removals between them, colluders and
    /// attackers drawn more often.
    collusion: bool,
    /// Guests: devices granted a session with an expiry, which write units
    /// and whose sessions administrators end.
    guests: bool,
    /// A person granted here, whose device list adds, revokes and
    /// checkpoints while its devices write here.
    persons: bool,
    /// Recovery members: administrators granted with `frasil.dormant`,
    /// which no checkpoint waits for, and which remove heard members of a
    /// rank at most their own that a checkpoint waits for.
    recovery: bool,
}

impl Kinds {
    /// Seeds 0 mod 4 build no checkpoint; odd seeds add invite keys where
    /// the extension is on; seeds 1 and 2 mod 3 grant a team; seeds 2 mod
    /// 4, a quarter, are drawn for collusion; seeds 0 and 1 mod 3 have
    /// guests; seeds 1 and 3 mod 5 grant a person with a list; seeds with
    /// checkpoints but 1 mod 3 grant recovery members.
    fn of(seed: u64) -> Self {
        Self {
            checkpoints: !seed.is_multiple_of(4),
            invites: cfg!(feature = "ext-invite-links") && seed % 2 == 1,
            granted: !seed.is_multiple_of(3),
            collusion: seed % 4 == 2,
            guests: seed % 3 != 2,
            persons: seed % 5 == 1 || seed % 5 == 3,
            recovery: !seed.is_multiple_of(4) && seed % 3 != 1,
        }
    }
}

/// What a history built besides its honest steps.
#[derive(Debug, Default)]
struct Built {
    /// Whether its administrators split in two groups.
    split: bool,
    /// The backdated checkpoints it holds.
    attacks: Vec<Attack>,
    /// Whether it granted invite keys.
    invites: bool,
    /// The events of the team's devices here, and the grant of the team,
    /// each with what it is: `grant`, `response`, `response, from now on`
    /// or `unit`.
    team_events: Vec<(&'static str, EventId)>,
    /// Removals of an administrator of the remover's own rank.
    equal_removals: usize,
    /// Honest removals that excuse a heard member a checkpoint waits for,
    /// each with that checkpoint.
    excuses: Vec<(EventId, EventId)>,
    /// Heard members' removals of themselves, accepting their lowering,
    /// each with the checkpoint that hears them.
    accepted: Vec<(EventId, EventId)>,
    /// The events of guests and of the sessions' ends, and of the person's
    /// devices and the grant and responses for it, each with what it is.
    guest_events: Vec<(&'static str, EventId)>,
    person_events: Vec<(&'static str, EventId)>,
    /// The list's events, each with what it is.
    list_events: Vec<(&'static str, EventId)>,
    /// The recovery members granted, by name.
    recovery: Vec<&'static str>,
    /// Recovery members' removals of a heard member a checkpoint waited
    /// for, each with that checkpoint and the member removed.
    recovery_excuses: Vec<(EventId, EventId, [u8; 32])>,
    /// The releases and restores signed.
    requests: Vec<EventId>,
    /// The changes of a member's level or capabilities, each with what it
    /// is.
    changes: Vec<(&'static str, EventId)>,
}

/// A random history, and the views each device held after each step. With
/// `invites`, administrators grant invite keys, claims are signed, some
/// raced on older views, and some keys closed or revoked. With `granted`,
/// the space grants a team space whose roster changes, and the team's
/// founder responds with notices, "from now on" ones included (keys.md,
/// "Notices and space principals"), while a team device writes here
/// through the grant. With `collusion`, B and C are granted `administer`
/// at the start at A's rank or below, removals prefer administrators of the
/// remover's rank or below, and backdated checkpoints come more often, with
/// colluders and selective attackers.
fn random_history(seed: u64, kinds: Kinds) -> (History, Vec<Views>, Built) {
    let Kinds {
        checkpoints,
        invites,
        granted,
        collusion,
        guests,
        persons,
        recovery,
    } = kinds;
    let mut rng = Rng(seed);
    // A dishonest administrator, drawn apart so that the honest steps keep
    // their draws: it takes another member's view, then checkpoints citing
    // every head (no fence), naming as predecessor the last in effect, an
    // earlier checkpoint, or none.
    let mut adv = Rng(seed.wrapping_mul(7907).wrapping_add(3));
    // Two groups of administrators cut off from each other: drawn apart
    // too.
    let mut spl = Rng(seed.wrapping_mul(7907).wrapping_add(11));
    // A removed administrator's backdated checkpoint: drawn apart too.
    let mut atk = Rng(seed.wrapping_mul(7907).wrapping_add(17));
    // Administrators' ranks, drawn apart: the founder at the top, A from
    // 100, 200 and 255, every other one at most its granter's.
    let mut rk = Rng(seed.wrapping_mul(7907).wrapping_add(23));
    // The collusion seeds' choices of whom to remove: drawn apart too.
    let mut col = Rng(seed.wrapping_mul(7907).wrapping_add(29));
    // An administrator that excuses a heard member a checkpoint waits for:
    // drawn apart too.
    let mut exc = Rng(seed.wrapping_mul(7907).wrapping_add(31));
    // Guests' steps, and the person's: drawn apart too.
    let mut gst = Rng(seed.wrapping_mul(7907).wrapping_add(37));
    let mut per = Rng(seed.wrapping_mul(7907).wrapping_add(41));
    // Recovery members, and every seed's releases and restores: drawn apart
    // too.
    let mut rcv = Rng(seed.wrapping_mul(7907).wrapping_add(43));
    let mut rls = Rng(seed.wrapping_mul(7907).wrapping_add(47));
    // Changes of a member's standing: drawn apart too.
    let mut chg = Rng(seed.wrapping_mul(7907).wrapping_add(53));
    let streams = [
        stream_named(&format!("model/{seed}/stream/x")),
        stream_named(&format!("model/{seed}/stream/y")),
    ];
    let mut h = History::new(&format!("model/{seed}"), "P");
    let a_rank = if collusion {
        *rk.pick(&[200, 200, MAX_RANK])
    } else {
        *rk.pick(&[100, 200, MAX_RANK])
    };
    h.ranks.insert("A".to_owned(), a_rank);
    h.grant("P", "A", Level::Administer)
        .expect("the founder grants A");
    h.sync(&["P", "A"]);
    let mut admins: BTreeSet<&str> = BTreeSet::from(["P", "A"]);
    let mut members: BTreeSet<&str> = BTreeSet::from(["P", "A"]);
    let mut removed: BTreeSet<&str> = BTreeSet::new();
    let mut claims: BTreeMap<String, Claims> = BTreeMap::new();
    let mut built = Built::default();
    let mut snapshots = Vec::new();
    if granted {
        // The team: its founder T0 and t1, each also able to act here
        // through the grant, and devices it admits "from now on" later.
        let mut team = History::granted(&format!("model/{seed}/team"), "T0");
        team.grant("T0", "t1", Level::Write)
            .expect("the team grants t1");
        team.sync(&["T0", "t1"]);
        for name in ["T0", "t1"] {
            h.aliases.insert(name.to_owned(), team.prefix.clone());
        }
        h.team = Some(Box::new(team));
        let grant = h.grant_team("P").expect("the founder grants the team");
        built.team_events.push(("grant", grant));
        h.sync(&["P", "A", "T0", "t1"]);
    }
    if persons {
        // The person: q1 starts its list and adds q2; q3 comes later.
        let prefix = format!("model/{seed}/person");
        for name in ["q1", "q2", "q3"] {
            h.aliases.insert(name.to_owned(), prefix.clone());
        }
        let first = DeviceList::first_event(&h.list_keys("q1"));
        h.list = Some(DeviceList::new(&first).expect("a list's first event"));
        if let Some(add) = h.list_add("q1", "q2") {
            built.list_events.push(("add", add));
        }
        let grant = h.grant_person("P").expect("the founder grants the person");
        built.person_events.push(("grant", grant));
        h.sync(&["P", "A", "q1", "q2"]);
    }
    if collusion {
        // B and C, of A's rank or below it: removals between equals, which
        // leave their senior targets heard, and colluders.
        for who in ["B", "C"] {
            let rank = *rk.pick(&[a_rank, a_rank, a_rank, 100]);
            h.ranks.insert(who.to_owned(), rank);
            if h.grant("P", who, Level::Administer).is_some() {
                members.insert(who);
                admins.insert(who);
            }
        }
        let all: Vec<&str> = members.iter().copied().collect();
        h.sync(&all);
    }
    let mut admitted = 0;
    let mut guests_in: Vec<String> = Vec::new();
    let steps = 36 + if invites { 10 } else { 0 } + if granted { 10 } else { 0 };
    // The step at which a collusion seed's removals come, early.
    let scripted = 2 + (col.next() % 8) as usize;
    for step in 0..steps {
        if collusion && step == scripted {
            // Either one that outranks B and C, or is their equal and
            // senior to them, removes both, which leaves two fallen
            // administrators that can collude against it; or B, A's equal
            // and junior to it, removes A, which leaves A heard and able to
            // attack those it outranks, and the founder removes C.
            let pairs: Vec<(&str, &str)> = if col.unit() < 0.5 {
                let by = if col.unit() < 0.5 { "P" } else { "A" };
                vec![(by, "B"), (by, "C")]
            } else if h.ranks.get("B") == h.ranks.get("A") {
                vec![("B", "A"), ("P", "C")]
            } else {
                vec![("P", "B"), ("P", "C")]
            };
            for (by, who) in pairs {
                if removed.contains(by) || removed.contains(who) {
                    continue;
                }
                h.sync(&[by, "P"]);
                if h.remove(by, who, None).is_some() {
                    if h.ranks.get(who) == h.ranks.get(by) {
                        built.equal_removals += 1;
                    }
                    members.remove(who);
                    admins.remove(who);
                    removed.insert(who);
                }
            }
            snapshots.push(h.views.clone());
        }
        let op = rng.unit();
        let actors: Vec<&str> = admins.difference(&removed).copied().collect();
        if actors.is_empty() {
            break;
        }
        let fallen: Vec<&str> = removed
            .iter()
            .copied()
            .filter(|r| ["A", "B", "C"].contains(r))
            .collect();
        // In collusion seeds an attack waits, mostly, for two fallen
        // administrators, so that one can collude.
        let (odds, most) = match (collusion, fallen.len()) {
            (true, 0 | 1) => (0.05, 3),
            (true, _) => (0.3, 3),
            (false, _) => (0.08, 2),
        };
        if checkpoints
            && atk.unit() < odds
            && !fallen.is_empty()
            && built.attacks.len() < most
            && let Some(attack) = h.takeover(&mut atk, &fallen, collusion)
        {
            built.attacks.push(attack);
            snapshots.push(h.views.clone());
        }
        if checkpoints && spl.unit() < 0.05 && actors.len() >= 2 && !built.split {
            built.split = h.split(&mut spl, &actors);
            if built.split {
                snapshots.push(h.views.clone());
            }
        }
        let by = *rng.pick(&actors);
        if chg.unit() < 0.12 {
            // An administrator changes a member's standing: lowers it to
            // reader, raises it to writer, or makes it a suggester or a
            // plain writer again; the member then writes on its view.
            let pool: Vec<&str> = members
                .iter()
                .copied()
                .filter(|m| !admins.contains(m) && *m != "P")
                .collect();
            if !pool.is_empty() {
                let who = *chg.pick(&pool);
                let (what, level, suggest) = *chg.pick(&[
                    ("lower to read", Level::Read, false),
                    ("raise to write", Level::Write, false),
                    ("make a suggester", Level::Write, true),
                ]);
                h.sync(&[by, who]);
                if let Some(id) = h.change_standing(by, who, level, suggest) {
                    built.changes.push((what, id));
                }
                if chg.unit() < 0.5 {
                    h.unit(who, None, None, None, true);
                }
            }
        }
        let extra = rng.unit();
        if invites && extra < 0.10 {
            let key = format!("I{}", claims.len());
            let history = *rng.pick(&[HistoryMode::FromNowOn, HistoryMode::WithHistory]);
            if h.invite(by, &key, history).is_some() {
                h.sync(&[by, &key]);
                built.invites = true;
                claims.insert(
                    key.clone(),
                    Claims {
                        views: vec![h.view(&key)],
                        n: 0,
                        by: by.to_owned(),
                    },
                );
            }
            continue;
        }
        if invites && !claims.is_empty() && extra < 0.22 {
            let keys: Vec<String> = claims.keys().cloned().collect();
            let key = rng.pick(&keys).clone();
            let what = rng.unit();
            let n = claims[&key].n;
            if what < 0.5 || n == 0 {
                // A claim, on the key's latest view, or a racer's on an
                // older one.
                let old = what < 0.25 && n > 0;
                let saved = h.view(&key);
                if old {
                    let view = rng.pick(&claims[&key].views).clone();
                    h.views.insert(key.clone(), view);
                } else {
                    let granter = claims[&key].by.clone();
                    h.sync(&[&granter, &key]);
                }
                let claimant = format!("J{}x{n}", &key[1..]);
                h.claim(&key, &claimant);
                h.views.entry(key.clone()).or_default().extend(saved);
                let info = claims.get_mut(&key).expect("a key granted");
                info.n += 1;
                info.views.push(h.view(&key));
            } else {
                // A close, or a revocation: an administrator removes the key.
                h.sync(&[by, &key]);
                h.close(by, &key);
            }
            continue;
        }
        if granted && extra < 0.32 {
            let what = rng.unit();
            if what < 0.35 {
                // The team removes t1, or grants it again, and its founder
                // responds here.
                let team = h.team.as_mut().expect("a team");
                let changed = if team.holds_member("t1") {
                    team.remove("T0", "t1", None)
                } else {
                    team.grant("T0", "t1", Level::Write)
                };
                if let Some(changed) = changed {
                    h.sync(&["P", "T0"]);
                    if let Some(r) = h.respond("T0", changed, false) {
                        built.team_events.push(("response", r));
                    }
                }
            } else if what < 0.6 {
                // The team admits a device "from now on": a break, which
                // the response notices as one.
                let name = format!("t{}", 2 + admitted);
                let team = h.team.as_mut().expect("a team");
                if let Some(g) = team.admit_from_now_on("T0", &name) {
                    admitted += 1;
                    h.sync(&["P", "T0"]);
                    if let Some(r) = h.respond("T0", g, true) {
                        built.team_events.push(("response, from now on", r));
                    }
                }
            } else {
                h.sync(&["P", "t1"]);
                if let Some(u) = h.unit("t1", None, None, None, true) {
                    built.team_events.push(("unit", u));
                }
            }
            snapshots.push(h.views.clone());
            continue;
        }
        if op < 0.18 {
            let free: Vec<&str> = DEVICES
                .iter()
                .copied()
                .filter(|d| !members.contains(d))
                .collect();
            if free.is_empty() {
                continue;
            }
            let who = *rng.pick(&free);
            let level = *rng.pick(&[Level::Write, Level::Administer, Level::Read]);
            if level == Level::Administer {
                let mine = h.ranks.get(by).copied().unwrap_or(MAX_RANK);
                let rank = (*rk.pick(&[50, 100, 150, 200, MAX_RANK])).min(mine);
                h.ranks.insert(who.to_owned(), rank);
            }
            if h.grant(by, who, level).is_some() {
                members.insert(who);
                if level == Level::Administer {
                    admins.insert(who);
                }
            }
        } else if op < 0.28 {
            let mut candidates: Vec<&str> = members
                .iter()
                .copied()
                .filter(|&m| m != by && m != "P")
                .collect();
            if collusion && col.unit() < 0.7 {
                // An administrator of the remover's rank or below.
                let mine = h.ranks.get(by).copied().unwrap_or(MAX_RANK);
                let peers: Vec<&str> = candidates
                    .iter()
                    .copied()
                    .filter(|m| admins.contains(m) && h.ranks.get(*m).is_some_and(|&r| r <= mine))
                    .collect();
                let equals: Vec<&str> = peers
                    .iter()
                    .copied()
                    .filter(|m| h.ranks.get(*m) == Some(&mine))
                    .collect();
                if !equals.is_empty() && col.unit() < 0.6 {
                    candidates = equals;
                } else if !peers.is_empty() {
                    candidates = peers;
                }
            }
            if candidates.is_empty() {
                continue;
            }
            let who = *rng.pick(&candidates);
            if h.remove(by, who, None).is_some() {
                if admins.contains(who) && h.ranks.get(who) == h.ranks.get(by) {
                    built.equal_removals += 1;
                }
                members.remove(who);
                admins.remove(who);
                removed.insert(who);
            }
        } else if op < 0.36 && removed.iter().any(|r| ["A", "B", "C"].contains(r)) {
            // A removed administrator signs a counter-removal on its own old
            // view: the backdated duel.
            let attackers: Vec<&str> = removed
                .iter()
                .copied()
                .filter(|r| ["A", "B", "C"].contains(r))
                .collect();
            let attacker = *rng.pick(&attackers);
            let targets: Vec<&str> = ["P", "A", "B", "C"]
                .into_iter()
                .filter(|&t| t != attacker)
                .collect();
            let target = *rng.pick(&targets);
            if !h.view(attacker).is_empty() {
                let old = h.view(attacker);
                if let Some(x) = h.remove(attacker, target, Some(old)) {
                    h.dishonest.insert(x);
                }
            }
        } else if op < 0.52 {
            let all: Vec<&str> = members.iter().copied().collect();
            let who = *rng.pick(&all);
            if !h.view(who).is_empty() {
                h.unit(who, None, None, None, true);
            }
        } else if op < 0.62 && checkpoints {
            if adv.unit() < 0.35 {
                let pool: Vec<String> = h
                    .views
                    .iter()
                    .filter(|(_, v)| !v.is_empty())
                    .map(|(n, _)| n.clone())
                    .collect();
                let other = adv.pick(&pool).clone();
                let taken = h.view(&other);
                h.views.entry(by.to_owned()).or_default().extend(taken);
                let named: Vec<EventId> = h
                    .view(by)
                    .into_iter()
                    .filter(|c| h.checkpoints.contains(c))
                    .collect();
                let pick = adv.unit();
                let previous = if pick < 0.5 || named.is_empty() {
                    Previous::Chain
                } else if pick < 0.7 {
                    Previous::None
                } else {
                    Previous::Named(*adv.pick(&named))
                };
                if let Some(x) = h.checkpoint_as(by, false, false, previous)
                    && !h.judged_valid(x)
                {
                    // Honest devices follow only a checkpoint they judge
                    // valid.
                    h.tampered.insert(x);
                }
            } else {
                h.checkpoint(by, false);
            }
        } else if op < 0.70 && checkpoints {
            for name in admins.difference(&removed).copied().collect::<Vec<_>>() {
                h.sync(&[name, by]);
                h.anchor(name);
            }
        } else if op < 0.76 {
            // A fork: a device signs again at a sequence number it used.
            let all: Vec<&str> = members.iter().copied().collect();
            let who = *rng.pick(&all);
            let author = h.device(who);
            let log = h.log();
            let mut mine: Vec<(u64, EventId)> = h
                .view(who)
                .into_iter()
                .filter(|&i| log.event(i).unwrap().author().0 == author)
                .map(|i| (log.event(i).unwrap().seq(), i))
                .collect();
            mine.sort_unstable();
            if mine.len() >= 2 {
                let (seq, old) = mine[mine.len() - 2];
                let prev = log.event(old).unwrap().prev();
                let mut view = log.past(old);
                view.extend(prev);
                h.unit(who, Some(view), Some((seq, prev)), None, false);
            }
        } else if op < 0.82 && checkpoints {
            // A rogue unit that cites what a checkpoint's followers do not.
            // The reference also seals some under the genesis's state, with
            // a key reference; these units carry none, so the draw only
            // keeps the dishonest generator in step.
            let all: Vec<&str> = members.iter().copied().collect();
            let who = *rng.pick(&all);
            let w = h.view(who);
            let _stale = adv.unit() < 0.4;
            if !w.is_empty() {
                let heads: BTreeSet<EventId> = h.log().heads_in(&w).into_iter().collect();
                h.unit(who, None, None, Some(heads), false);
            }
        } else {
            let pool: Vec<String> = h
                .views
                .iter()
                .filter(|(n, v)| {
                    !v.is_empty() && (members.contains(n.as_str()) || admins.contains(n.as_str()))
                })
                .map(|(n, _)| n.clone())
                .collect();
            if pool.len() < 2 {
                continue;
            }
            let a = rng.pick(&pool).clone();
            let b = rng.pick(&pool).clone();
            if a != b {
                h.sync(&[&a, &b]);
            }
        }
        if guests && gst.unit() < 0.12 {
            guest_step(&mut h, &mut gst, by, &mut guests_in, &mut built);
        }
        if persons && per.unit() < 0.15 {
            person_step(&mut h, &mut per, &mut built);
        }
        if recovery && built.recovery.len() < 2 && rcv.unit() < 0.06 {
            // An administrator grants a recovery member, of a rank at most
            // its own.
            let free: Vec<&'static str> = DEVICES
                .iter()
                .copied()
                .filter(|d| !members.contains(d))
                .collect();
            if !free.is_empty() {
                let who = *rcv.pick(&free);
                let mine = h.ranks.get(by).copied().unwrap_or(MAX_RANK);
                let rank = (*rcv.pick(&[100, 200, MAX_RANK])).min(mine);
                h.ranks.insert(who.to_owned(), rank);
                if h.grant_recovery(by, who).is_some() {
                    members.insert(who);
                    admins.insert(who);
                    built.recovery.push(who);
                }
            }
        }
        if rls.unit() < 0.2 {
            // A member releases or restores a stream on its view: the write
            // rule judges it, so a reader's is void.
            let pool: Vec<&str> = members
                .iter()
                .copied()
                .filter(|m| !h.view(m).is_empty())
                .collect();
            if !pool.is_empty() {
                let who = *rls.pick(&pool);
                let stream = *rls.pick(&streams);
                let release = rls.unit() < 0.55;
                if let Some(id) = h.request(who, stream, release) {
                    built.requests.push(id);
                }
            }
        }
        if checkpoints && !h.checkpoints.is_empty() && exc.unit() < 0.3 {
            let names: Vec<&str> = admins.difference(&removed).copied().collect();
            if h.hears_someone() {
                for name in names {
                    built.excuses.extend(h.excuse_heard(name));
                }
                // A recovery member removes a heard member of a rank at
                // most its own that a checkpoint it follows waits for.
                for name in built.recovery.clone() {
                    if !removed.contains(name) {
                        built.recovery_excuses.extend(h.excuse_heard_as(name, true));
                    }
                }
                // Now and then a heard member accepts its lowering.
                let fallen: Vec<&str> = removed
                    .iter()
                    .copied()
                    .filter(|r| ["A", "B", "C"].contains(r))
                    .collect();
                if !fallen.is_empty() && exc.unit() < 0.3 {
                    let name = *exc.pick(&fallen);
                    built.accepted.extend(h.accept_lowering(name, "P"));
                }
            }
        }
        if checkpoints && !h.checkpoints.is_empty() && rng.unit() < 0.25 {
            let names: Vec<&str> = admins.difference(&removed).copied().collect();
            let name = if names.is_empty() {
                "P"
            } else {
                *rng.pick(&names)
            };
            let pool: Vec<String> = h
                .views
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(n, _)| n.clone())
                .collect();
            let other = rng.pick(&pool).clone();
            h.sync(&[name, &other]);
            h.anchor(name);
        }
        snapshots.push(h.views.clone());
    }
    let everyone: Vec<String> = h.views.keys().cloned().collect();
    let names: Vec<&str> = everyone.iter().map(String::as_str).collect();
    h.sync(&names);
    if let Some(team) = h.team.as_mut() {
        let everyone: Vec<String> = team.views.keys().cloned().collect();
        let names: Vec<&str> = everyone.iter().map(String::as_str).collect();
        team.sync(&names);
    }
    (h, snapshots, built)
}

/// A guests' step: an administrator grants a guest (three at most), a guest
/// writes a unit, or an administrator ends a guest's session.
fn guest_step(h: &mut History, rng: &mut Rng, by: &str, live: &mut Vec<String>, built: &mut Built) {
    let what = rng.unit();
    let granted = built
        .guest_events
        .iter()
        .filter(|(w, _)| *w == "grant")
        .count();
    if what < 0.35 && granted < 3 {
        let guest = format!("G{granted}");
        if let Some(g) = h.grant_guest(by, &guest, granted as u64) {
            built.guest_events.push(("grant", g));
            h.sync(&[by, &guest]);
            live.push(guest);
        }
    } else if what < 0.8 && !live.is_empty() {
        let guest = rng.pick(live).clone();
        h.sync(&[&guest, by]);
        if let Some(u) = h.unit(&guest, None, None, None, true) {
            built.guest_events.push(("unit", u));
        }
    } else if !live.is_empty() {
        let k = (rng.next() % live.len() as u64) as usize;
        let guest = live.remove(k);
        h.sync(&[by, &guest]);
        if let Some(e) = h.end_session(by, &guest) {
            built.guest_events.push(("end of session", e));
        }
    }
}

/// A person's step: one of its devices writes a unit or heals here (q2
/// also after its revocation), q1 adds q3, q1 revokes q2, q1 proposes a list
/// checkpoint that the others ack, or the founder responds to the
/// revocation.
fn person_step(h: &mut History, rng: &mut Rng, built: &mut Built) {
    let has = |built: &Built, what: &str| built.list_events.iter().any(|(w, _)| *w == what);
    let what = rng.unit();
    if what < 0.4 {
        let mut writers = vec!["q1", "q2"];
        if has(built, "add q3") {
            writers.push("q3");
        }
        let who = *rng.pick(&writers);
        h.sync(&[who, "P"]);
        if rng.unit() < 0.3 {
            // A key event: a writer heals, rotating.
            if let Some(k) = h.space_event(who, None, true, false, None) {
                built.person_events.push(("heal", k));
            }
        } else if let Some(u) = h.unit(who, None, None, None, true) {
            built.person_events.push(("unit", u));
        }
    } else if what < 0.5 && !has(built, "add q3") {
        if let Some(add) = h.list_add("q1", "q3") {
            built.list_events.push(("add q3", add));
            h.sync(&["q3", "P"]);
        }
    } else if what < 0.6 && !has(built, "revoke q2") {
        if let Some(revoke) = h.list_revoke("q1", "q2") {
            built.list_events.push(("revoke q2", revoke));
        }
    } else if what < 0.85 {
        let mut voters = Vec::new();
        if !has(built, "revoke q2") {
            voters.push("q2");
        }
        if has(built, "add q3") && rng.unit() < 0.8 {
            voters.push("q3");
        }
        if let Some(c) = h.list_checkpoint("q1", &voters) {
            built.list_events.push(("checkpoint", c));
        }
    } else if let Some(&(_, revoke)) = built.list_events.iter().find(|(w, _)| *w == "revoke q2")
        && !built.person_events.iter().any(|(w, _)| *w == "response")
        && let Some(r) = h.respond_to_list("P", revoke)
    {
        built.person_events.push(("response", r));
    }
}

/// The log of a replica that forgot: it holds only `held`, and keeps the
/// ID of every event in `dropped` as a stub, so that it places an event
/// citing one (roster.md, "Forgetting, and starting from a checkpoint").
fn forgetting_log(full: &Log, held: &BTreeSet<EventId>, dropped: &BTreeSet<EventId>) -> Log {
    let mut log = Log::new(full.genesis().clone()).unwrap();
    let stub = |id: EventId| {
        let forgotten = full.event(id).unwrap();
        Stub {
            id,
            author: *forgotten.author(),
            seq: forgotten.seq(),
            height: full.height(id).unwrap(),
            kind: forgotten.kind(),
            cuts: frasil_events::cuts::Cuts::of(forgotten),
        }
    };
    let mut gone: Vec<(u64, EventId)> = dropped
        .iter()
        .filter(|&&id| id != full.id() && !held.contains(&id))
        .map(|&id| (full.height(id).unwrap(), id))
        .collect();
    gone.sort_unstable();
    for &(_, id) in &gone {
        log.add_stub(stub(id));
    }
    let mut order: Vec<(u64, EventId)> = held
        .iter()
        .map(|&id| (full.height(id).unwrap(), id))
        .collect();
    order.sort_unstable();
    for &(_, id) in &order {
        let event = full.event(id).unwrap();
        for &parent in event.parents() {
            if parent == full.id() || held.contains(&parent) || log.stub(parent).is_some() {
                continue;
            }
            log.add_stub(stub(parent));
        }
        log.place(event.clone()).unwrap();
    }
    log
}

fn show(status: Option<&Status>) -> String {
    match status {
        None => "absent".into(),
        Some(Status::Valid(_)) => "valid".into(),
        Some(Status::Void { class, .. }) => class.name().to_owned(),
    }
}

/// What the model check reached, so that a run shows it covers the cases
/// it is for.
#[derive(Debug, Default)]
struct Totals {
    histories: usize,
    with_invites: usize,
    events: usize,
    checkpoints: usize,
    valid: usize,
    effective: usize,
    longest_chain: usize,
    unfenced: usize,
    splits: usize,
    /// Intermediate views whose chain the final one replaced at a disjoint
    /// electorate.
    replaced: usize,
    forgetting: usize,
    compared: usize,
    rosters_compared: usize,
    /// Forgetting replicas that held a rival, every verdict pending.
    rival_pending: usize,
    late: usize,
    withheld: usize,
    key_graphs: usize,
    invite_entries: usize,
    used_successors: usize,
    /// Histories drawn for collusion, and their removals of an
    /// administrator of the remover's own rank.
    with_collusion: usize,
    equal_removals: usize,
    /// Backdated checkpoints by mode and standing: how many, and how many
    /// took effect.
    attacks: BTreeMap<String, (usize, usize)>,
    /// Those in effect, by mode, standing and why the rules let them in.
    attacks_in_effect: BTreeMap<String, usize>,
    /// Valid checkpoints whose record hears a member, and how many took
    /// effect.
    hearing: usize,
    hearing_in_effect: usize,
    /// Honest removals after a checkpoint of a heard member it waited for,
    /// and how many of those checkpoints took effect.
    excuses: usize,
    excused_in_effect: usize,
    /// Checkpoints whose heard members accepted their lowering, and how
    /// many of them took effect.
    accepted: usize,
    accepted_in_effect: usize,
    /// Histories with guests, their events by what each is and its verdict,
    /// and records' entries for a guest (a session).
    with_guests: usize,
    guest_events: BTreeMap<String, usize>,
    guest_entries: usize,
    /// Histories with a person; its devices' events, its grant and the
    /// responses to its list, by what each is and its verdict; its list's
    /// events by what each is; its list checkpoints in effect; the events on
    /// which a replica that forgot the list, with the forgotten adds' keys
    /// from another source, was compared with one that kept it; and, by the
    /// verdict of the one that kept it, the events of unlisted devices that
    /// one without those keys holds as `NoHybridKey` (viii).
    with_persons: usize,
    person_events: BTreeMap<String, usize>,
    list_events: BTreeMap<String, usize>,
    list_in_effect: usize,
    list_forgot_compared: usize,
    list_forgot_unkeyed: BTreeMap<String, usize>,
    /// Histories with a granted team.
    with_granted: usize,
    /// The team's grant, responses and units here, by what each is and its
    /// verdict at the replica that kept everything.
    team_events: BTreeMap<String, usize>,
    /// Records' entries for the team with notices, those with a floor (a
    /// "from now on" notice answered), and those naming the team's events.
    space_entries: usize,
    space_floors: usize,
    space_named: usize,
    /// Forgetting replicas whose space principals, read from the key graph
    /// of the last world, were compared with the full replica's, and how
    /// many principals they held.
    principals_compared: usize,
    principals: usize,
    /// Members of checkpoints in effect lowered only by members they
    /// outrank, each checked to have voted or been excused.
    heard_checked: usize,
    /// Checkpoints with a predecessor whose window (the predecessor's
    /// world) the heard check resolved apart.
    windows_checked: usize,
    /// Valid lowerings of administrators checked against ranks.
    lowerings_checked: usize,
    /// Recovery members granted; their removals of a heard member a
    /// checkpoint waited for, those the checkpoint counted as excuses, and
    /// those checkpoints that took effect.
    recovery_members: usize,
    recovery_excuses: usize,
    recovery_excused: usize,
    recovery_excused_in_effect: usize,
    /// Releases and restores by verdict at the replica that kept
    /// everything; streams whose released state a replica that forgot and
    /// one that kept everything were compared on, and those released; and
    /// the requests of a checkpoint's past a replica that forgot kept.
    requests: BTreeMap<String, usize>,
    released_compared: usize,
    released: usize,
    requests_kept: usize,
    /// Changes of a member's standing, by what each is and its verdict.
    changes: BTreeMap<String, usize>,
    /// (x): units frozen when a checkpoint took effect in some view and
    /// compared with the end, and those whose author's frozen standing
    /// differs from the checkpoint's record.
    units_frozen: usize,
    frozen_standing_changed: usize,
}

/// What (x) compares of a frozen unit: its verdict; its author's level and
/// capabilities at its place, or none for a unit with no place in the view
/// that judged it, or whose author no path reached; its attribution, the
/// paths with their labels there; and the events that void it.
type FrozenKey = (
    String,
    Option<(Level, Vec<(String, u64)>)>,
    Option<Vec<(MemberRef, Option<String>)>>,
    Vec<EventId>,
);

fn frozen_key(unit: &frasil_space::FrozenUnit) -> FrozenKey {
    // Keys 7 and 8 never together: a unit is attributed or voided.
    assert!(
        unit.attribution.is_none() || unit.voided_by.is_empty(),
        "attribution beside voiding events: {unit:?}"
    );
    let reach = match &unit.reach {
        Some(frasil_space::across::AuthorReach::Reached(reach)) => Some((
            reach.level,
            unit.capabilities()
                .into_iter()
                .map(|c| (c.name, c.mode.code()))
                .collect(),
        )),
        _ => None,
    };
    (
        show(Some(&unit.status)),
        reach,
        unit.attribution.clone(),
        unit.voided_by.clone(),
    )
}

/// The present members of a roster with what two replicas compare of each:
/// level, capabilities, label, history, via, session, replaced device,
/// seniority and expiry.
fn roster_view(roster: &Roster) -> Vec<String> {
    roster
        .iter()
        .filter_map(|(member, _)| {
            let state = roster.state(member)?;
            Some(format!(
                "{member:?} {:?}",
                (
                    state.level,
                    &state.capabilities,
                    &state.label,
                    state.history,
                    state.via,
                    state.session,
                    state.replaces,
                    state.seniority,
                    state.expires_at,
                )
            ))
        })
        .collect()
}

/// The events of `all` that are `c` or follow it.
/// A lowering of a resolved window: the event, its author, its author's
/// authority key at its place, and each administrator it lowers with its
/// key there.
type WindowLowering = (
    EventId,
    [u8; 32],
    Option<frasil_space::AuthorityKey>,
    Vec<(frasil_crypto::device::DeviceId, frasil_space::AuthorityKey)>,
);

/// The valid roster events of a resolved window, its root left out, that
/// remove an administrator without `frasil.dormant`, lower it below
/// `administer` or give it `frasil.dormant` (roster.md, 3.15.4), read from
/// the space alone.
fn window_lowerings(space: &Space<'_>) -> Vec<WindowLowering> {
    fn dormant<'c>(mut caps: impl Iterator<Item = &'c frasil_space::Capability>) -> bool {
        caps.any(|c| c.name == "frasil.dormant" && c.mode == CapabilityMode::Extends)
    }
    let root = space.root();
    let mut out = Vec::new();
    for &i in space.valid_roster() {
        if i == root {
            continue;
        }
        let Some(opened) = space.opened(i) else {
            continue;
        };
        let Some(author) = space.log().event(i).map(|e| e.author().0) else {
            continue;
        };
        let roster = space.roster_at(&space.place_of(i));
        let by = space.author_state_at(i).map(|state| state.authority_key());
        let mut targets = Vec::new();
        for change in opened.changes() {
            let Some(member) = change.member.filter(|m| m.kind == MemberType::Device) else {
                continue;
            };
            let Some(target) = roster.state(&member) else {
                continue;
            };
            if target.level != Level::Administer || dormant(target.capabilities.iter()) {
                continue;
            }
            let lowers = change.op == Op::Remove
                || (change.op == Op::Change
                    && (change.level.is_some_and(|l| l < Level::Administer)
                        || dormant(change.capabilities.iter().flatten())));
            if lowers {
                targets.push((
                    frasil_crypto::device::DeviceId(member.id),
                    target.authority_key(),
                ));
            }
        }
        if !targets.is_empty() {
            out.push((i, author, by, targets));
        }
    }
    out
}

fn after(judge: &Checkpointed<'_>, all: &BTreeSet<EventId>, c: EventId) -> BTreeSet<EventId> {
    all.iter()
        .copied()
        .filter(|&i| i == c || judge.follows(i, c).unwrap_or(false))
        .collect()
}

/// Two concurrent checkpoints whose electorates, over everything that
/// follows each, share no device (roster.md, 3.15.4).
fn disjoint(judge: &Checkpointed<'_>, a: EventId, b: EventId, all: &BTreeSet<EventId>) -> bool {
    judge.concurrent(a, b).unwrap_or(false)
        && judge
            .electorate(a, &after(judge, all, a))
            .is_disjoint(&judge.electorate(b, &after(judge, all, b)))
}

/// Whether a forgetting replica's verdicts show it holds a rival (roster.md,
/// 3.15.6): while it does, every event it holds is `Pending`.
fn holds_rival(judged: &frasil_space::Judged, held: &BTreeSet<EventId>) -> bool {
    !held.is_empty()
        && held
            .iter()
            .all(|i| show(judged.statuses.get(i)) == "Pending")
}

/// Whether a replica that forgot under `base` holds a checkpoint that could
/// be a rival, read from envelopes alone: one concurrent with `base` whose ID
/// is smaller than `base`'s or than that of a checkpoint `base`'s cuts
/// reach. A replica that holds every event pending must hold one.
fn could_be_rival(
    judge: &Checkpointed<'_>,
    checkpoints: &BTreeSet<EventId>,
    held: &BTreeSet<EventId>,
    base: EventId,
) -> bool {
    let reached = judge.reach(base).unwrap_or_default();
    held.iter().any(|&x| {
        checkpoints.contains(&x)
            && x != base
            && judge.concurrent(x, base).unwrap_or(false)
            && (x < base || reached.iter().any(|&c| checkpoints.contains(&c) && x < c))
    })
}

fn check_history(seed: u64, kinds: Kinds, totals: &mut Totals) -> Vec<String> {
    let (h, snapshots, built) = random_history(seed, kinds);
    let log = h.log();
    let keys = h.keyring();
    // The granted team, resolved over its whole log, which every replica
    // here holds and passes to each judge.
    let team_keys = h.team.as_ref().map(|team| team.keyring());
    let team_space = h.team.as_ref().zip(team_keys.as_ref()).map(|(team, keys)| {
        Space::resolve(team.log(), None, options(keys, no_others())).expect("the team resolves")
    });
    let mut others = OtherLogs::none();
    if let Some(space) = &team_space {
        others = others.with_space(space);
    }
    if let Some(list) = &h.list {
        others = others.with_list(HeldList::new(list.clone()));
    }
    let none = BTreeMap::<EventId, Event>::new();
    let inputs = CheckpointInputs {
        log,
        options: options(&keys, &others),
        objects: &h.records,
        envelopes: &none,
        slots: None,
    };
    let full_judge = Checkpointed::new(inputs, None);
    let final_view: BTreeSet<EventId> = log.canonical().into_iter().collect();
    let full = full_judge.judge(&final_view);
    let summaries = summary::Summaries::new(&h.records);
    let streamed = Checkpointed::new(
        CheckpointInputs {
            objects: &summaries,
            ..inputs
        },
        None,
    );
    summary::same(&full, &streamed.judge(&final_view));
    let mut failures = Vec::new();
    totals.histories += 1;
    totals.with_invites += usize::from(built.invites);
    totals.with_granted += usize::from(kinds.granted);
    totals.with_guests += usize::from(kinds.guests);
    totals.with_persons += usize::from(kinds.persons);
    for (what, id) in &built.guest_events {
        *totals
            .guest_events
            .entry(format!("{what}: {}", show(full.statuses.get(id))))
            .or_default() += 1;
    }
    for (what, id) in &built.person_events {
        *totals
            .person_events
            .entry(format!("{what}: {}", show(full.statuses.get(id))))
            .or_default() += 1;
    }
    for (what, _) in &built.list_events {
        *totals.list_events.entry((*what).to_owned()).or_default() += 1;
    }
    totals.with_collusion += usize::from(kinds.collusion);
    totals.equal_removals += built.equal_removals;
    for &c in &h.checkpoints {
        if full_judge.validity(c).is_valid() && !full_judge.heard(c).is_empty() {
            totals.hearing += 1;
            totals.hearing_in_effect += usize::from(full.chain.contains(&c));
        }
    }
    totals.excuses += built.excuses.len();
    totals.recovery_members += built.recovery.len();
    totals.recovery_excuses += built.recovery_excuses.len();
    for &(_, c, target) in &built.recovery_excuses {
        let held_after = after(&full_judge, &final_view, c);
        let excused = full_judge.excused(c, &held_after);
        if excused.contains(&frasil_crypto::device::DeviceId(target)) {
            totals.recovery_excused += 1;
            totals.recovery_excused_in_effect += usize::from(full.chain.contains(&c));
        }
    }
    for id in &built.requests {
        *totals
            .requests
            .entry(show(full.statuses.get(id)))
            .or_default() += 1;
    }
    for (what, id) in &built.changes {
        *totals
            .changes
            .entry(format!("{what}: {}", show(full.statuses.get(id))))
            .or_default() += 1;
    }
    let accepted: BTreeSet<EventId> = built.accepted.iter().map(|&(_, c)| c).collect();
    totals.accepted += accepted.len();
    totals.accepted_in_effect += accepted.iter().filter(|c| full.chain.contains(c)).count();
    totals.excused_in_effect += built
        .excuses
        .iter()
        .filter(|(_, c)| full.chain.contains(c))
        .count();
    for (what, id) in &built.team_events {
        *totals
            .team_events
            .entry(format!("{what}: {}", show(full.statuses.get(id))))
            .or_default() += 1;
    }
    totals.splits += usize::from(built.split);
    totals.unfenced += h.unfenced;
    totals.events += final_view.len();
    totals.checkpoints += h.checkpoints.len();
    totals.valid += h
        .checkpoints
        .iter()
        .filter(|&&c| full_judge.validity(c).is_valid())
        .count();
    totals.effective += full.chain.len();
    totals.longest_chain = totals.longest_chain.max(full.chain.len());
    totals.late += full
        .statuses
        .values()
        .filter(|s| show(Some(s)) == "Late")
        .count();

    // (v) Every record reads back to its own bytes (checked as each is
    // signed), and the invite keys records carry.
    for plaintext in h.records.values() {
        if let Ok(record) = Record::read(plaintext) {
            totals.invite_entries += record
                .members
                .iter()
                .filter(|m| m.member.kind == MemberType::Invite)
                .count();
            totals.space_entries += record
                .members
                .iter()
                .filter(|m| m.member.kind == MemberType::Space && !m.notices.is_empty())
                .count();
            totals.space_floors += record
                .members
                .iter()
                .filter(|m| m.member.kind == MemberType::Space && m.floor)
                .count();
            totals.space_named += record
                .members
                .iter()
                .filter(|m| m.member.kind == MemberType::Space && !m.named.is_empty())
                .count();
            totals.guest_entries += record
                .members
                .iter()
                .filter(|m| m.session.is_some())
                .count();
        }
    }

    // (viii) A replica that forgot the person's list under its checkpoint
    // in effect agrees with one that kept it, on every verdict and the
    // chain, given the forgotten adds' keys from another source; without
    // them it holds as `NoHybridKey` only events of devices the list no
    // longer has that the other judges void: it never judges what it
    // cannot verify, and the hold changes no other verdict (roster.md,
    // 3.15.8, "What an unlisted device loses").
    if let Some(list) = &h.list {
        let merged = list.merge();
        totals.list_in_effect += merged.chain().len();
        if let Some(kept) = list.forget(&merged) {
            let unlisted: BTreeSet<[u8; 32]> = ["q1", "q2", "q3"]
                .into_iter()
                .map(|n| h.device(n))
                .filter(|d| {
                    merged
                        .active(&frasil_crypto::device::DeviceId(*d))
                        .is_none()
                })
                .collect();
            let mut ring = frasil_crypto::device::KeyRing::new();
            ring.extend(list.keys());
            for keyed in [true, false] {
                let mut forgot_list = OtherLogs::none();
                if let Some(space) = &team_space {
                    forgot_list = forgot_list.with_space(space);
                }
                forgot_list = forgot_list.with_list(HeldList::kept(kept.clone()));
                if keyed {
                    forgot_list = forgot_list.with_keys(&ring);
                }
                let judged = Checkpointed::new(
                    CheckpointInputs {
                        options: options(&keys, &forgot_list),
                        ..inputs
                    },
                    None,
                )
                .judge(&final_view);
                if judged.chain != full.chain {
                    failures.push(format!(
                        "seed {seed}: (viii) the list forgot (keyed {keyed}): another chain"
                    ));
                }
                for &i in &final_view {
                    let (got, want) = (show(judged.statuses.get(&i)), show(full.statuses.get(&i)));
                    let allowed = !keyed
                        && got == "NoHybridKey"
                        && !matches!(full.statuses.get(&i), Some(Status::Valid(_)))
                        && unlisted.contains(&log.event(i).unwrap().author().0);
                    if got != want && !allowed {
                        failures.push(format!(
                            "seed {seed}: (viii) the list forgot (keyed {keyed}): {i:?}: {got} \
                             against {want}"
                        ));
                    }
                    if allowed {
                        *totals.list_forgot_unkeyed.entry(want).or_default() += 1;
                    }
                }
                if keyed {
                    totals.list_forgot_compared += final_view.len();
                }
            }
        }
    }

    // (iii): with no checkpoint, the procedure's own verdicts.
    if h.checkpoints.is_empty() {
        let plain = Space::resolve(log, None, options(&keys, &others)).unwrap();
        for &id in &final_view {
            if plain.status(id) != full.statuses.get(&id) {
                failures.push(format!(
                    "seed {seed}: (iii) {id:?}: {} against {}",
                    show(plain.status(id)),
                    show(full.statuses.get(&id))
                ));
            }
        }
    }

    // (iv): a successor with another successor of its key in its past, not
    // late, is void, whatever checkpoint lies between.
    for &i in h.successors.keys() {
        let author = *log.event(i).unwrap().author();
        let used = h.successors.keys().any(|&x| {
            x != i
                && *log.event(x).unwrap().author() == author
                && log.precedes(x, i)
                && !["Late", "StaleSeal", "Malformed"]
                    .contains(&show(full.statuses.get(&x)).as_str())
        });
        if used {
            totals.used_successors += 1;
            if matches!(full.statuses.get(&i), Some(Status::Valid(_))) {
                failures.push(format!(
                    "seed {seed}: (iv) {i:?}: a used invite key claimed again is valid"
                ));
            }
        }
    }

    // (vi) A backdated checkpoint whose victims a member outranks never
    // takes effect, unless a victim voted for it: by a dishonest step that
    // had it sign unfenced, or honestly, where its view held no lowering
    // that contests the checkpoint for it (roster.md, 3.15.7); every member
    // a checkpoint in effect hears voted or was excused.
    for attack in &built.attacks {
        let c = attack.checkpoint;
        let won = full.chain.contains(&c);
        let name = format!("{}, {}", attack.mode, attack.standing);
        let row = totals.attacks.entry(name.clone()).or_default();
        row.0 += 1;
        row.1 += usize::from(won);
        if !won {
            continue;
        }
        let held_after = after(&full_judge, &final_view, c);
        let voted = full_judge.votes(c, &held_after);
        let excused = full_judge.excused(c, &held_after);
        let heard = full_judge.heard(c);
        let mut dishonest = 0;
        let mut honest = 0;
        for v in &attack.victims {
            let device = frasil_crypto::device::DeviceId(h.device(v));
            if !voted.contains(&device) {
                continue;
            }
            let mine: Vec<EventId> = held_after
                .iter()
                .copied()
                .filter(|&x| x != c && *log.event(x).unwrap().author() == device)
                .collect();
            if mine.iter().any(|x| h.dishonest.contains(x)) {
                dishonest += 1;
                continue;
            }
            honest += 1;
            // An honest device follows the conduct rule: c was not contested
            // for it at any event of it after c.
            for &x in &mine {
                if let Some(contest) = full_judge.contest(&device, c, &log.past(x)) {
                    failures.push(format!(
                        "seed {seed}: (vi) {c:?}: honest victim {v} voted for it by {x:?} \
                         while contested ({contest:?})"
                    ));
                }
            }
        }
        // The victims the checkpoint waits for: those its record keeps at
        // `administer` and those it hears; each voted, or was excused.
        let record = full_judge
            .record(c)
            .expect("a checkpoint in effect is read");
        let kept: BTreeSet<_> = record.administrators().collect();
        let waited: Vec<(&String, frasil_crypto::device::DeviceId)> = attack
            .victims
            .iter()
            .map(|v| (v, frasil_crypto::device::DeviceId(h.device(v))))
            .filter(|(_, d)| kept.contains(d) || heard.contains_key(d))
            .collect();
        let forked = |device: &frasil_crypto::device::DeviceId| {
            let mut seqs = BTreeSet::new();
            final_view.iter().any(|&x| {
                let e = log.event(x).unwrap();
                *e.author() == *device && !seqs.insert(e.seq())
            })
        };
        // Whether the attacker's removal stands at the end, concurrent with
        // the checkpoint: a valid lowering of it with no checkpoint in
        // effect.
        let attacker = frasil_crypto::device::DeviceId(h.device(&attack.attackers[0]));
        let lowered = full_judge.lowerings(&final_view).iter().any(|l| {
            l.targets.iter().any(|t| t.device == attacker)
                && !log.precedes(l.event, c)
                && !log.precedes(c, l.event)
        });
        let why = if dishonest > 0 {
            "a victim voted dishonestly"
        } else if honest > 0 && !lowered {
            "a victim voted honestly: the attacker's own removal is void, it won its duel"
        } else if honest > 0 {
            "a victim voted honestly, its view then holding no lowering that contests it"
        } else if waited.is_empty() {
            "no victim kept or heard"
        } else if waited.iter().all(|(_, d)| excused.contains(d) && forked(d)) {
            "its victims forked, and so were excused"
        } else if waited.iter().all(|(_, d)| excused.contains(d)) {
            "its victims were excused"
        } else {
            "unexplained"
        };
        if attack.junior() && dishonest + honest == 0 && !why.contains("forked") {
            failures.push(format!(
                "seed {seed}: (vi) {c:?}: a backdated checkpoint by an outranked attacker \
                 took effect, no victim voting ({why}): attackers {:?}, victims {:?}, \
                 waited for {:?}, excused {:?}",
                attack.attackers,
                attack.victims,
                waited.iter().map(|(v, _)| v).collect::<Vec<_>>(),
                waited
                    .iter()
                    .filter(|(_, d)| excused.contains(d))
                    .map(|(v, _)| v)
                    .collect::<Vec<_>>(),
            ));
        }
        if attack.junior() {
            eprintln!(
                "seed {seed}: {name}, by {:?} on {:?}, took effect: {why}",
                attack.attackers, attack.victims
            );
        }
        *totals
            .attacks_in_effect
            .entry(format!("{name}: {why}"))
            .or_default() += 1;
    }
    for &c in &full.chain {
        let held_after = after(&full_judge, &final_view, c);
        let ok: BTreeSet<_> = full_judge
            .votes(c, &held_after)
            .union(&full_judge.excused(c, &held_after))
            .copied()
            .collect();
        for device in full_judge.heard(c).keys() {
            totals.heard_checked += 1;
            if !ok.contains(device) {
                failures.push(format!(
                    "seed {seed}: (vi) {c:?} is in effect without its heard member {device:?}"
                ));
            }
        }
        // The heard members derived again from the checkpoint's window,
        // apart from the record code: without a predecessor, its whole
        // causal past resolved with no checkpoint in effect; with
        // predecessor `p`, `p`'s world over the events of its past that
        // follow `p` (roster.md, 3.15.4).
        let Some(record) = full_judge.record(c) else {
            continue;
        };
        let past = log.past(c);
        let world = match record.previous {
            None => None,
            Some(p) => {
                let Some(world) = full_judge.key_world(&past) else {
                    continue;
                };
                if world.checkpoint() != p {
                    continue;
                }
                Some(world)
            }
        };
        let window = match &world {
            None => Space::resolve(log, Some(&past), options(&keys, &others)),
            Some(world) => world.resolve(options(&keys, &others)),
        };
        let Ok(window) = window else {
            continue;
        };
        totals.windows_checked += usize::from(world.is_some());
        let mut lowered: BTreeMap<frasil_crypto::device::DeviceId, Vec<bool>> = BTreeMap::new();
        for (event, author, by, targets) in window_lowerings(&window) {
            for (target, key) in targets {
                let raised = window.valid_roster().iter().any(|&j| {
                    log.precedes(event, j)
                        && window.opened(j).is_some_and(|o| {
                            o.changes().iter().any(|ch| {
                                ch.member == Some(MemberRef::device(target))
                                    && ch.level == Some(Level::Administer)
                                    && matches!(ch.op, Op::Grant | Op::Change)
                            })
                        })
                });
                if raised {
                    continue;
                }
                lowered
                    .entry(target)
                    .or_default()
                    .push(author == target.0 || by.is_some_and(|by| by < key));
            }
        }
        let kept: BTreeSet<_> = record.electorate().collect();
        for (device, how) in lowered {
            if how.iter().any(|&b| b) || kept.contains(&device) {
                continue;
            }
            totals.heard_checked += 1;
            if !ok.contains(&device) {
                failures.push(format!(
                    "seed {seed}: (vi) {c:?}: a member lowered only by members it outranks \
                     neither voted nor was excused"
                ));
            }
        }
    }

    // (vii) No valid roster event lowers an administrator of a higher rank
    // than its author's at its place: with no checkpoint in effect, and in
    // the last world.
    for lowering in full_judge.lowerings(&final_view) {
        for target in &lowering.targets {
            totals.lowerings_checked += 1;
            if lowering.by.is_none_or(|by| by.0 > target.authority_key().0) {
                failures.push(format!(
                    "seed {seed}: (vii) {:?}: a lower rank lowered a higher one",
                    lowering.event
                ));
            }
        }
    }
    if let Some(world) = full_judge.key_world(&final_view)
        && let Ok(space) = world.resolve(options(&keys, &others))
    {
        let root = space.root();
        for &i in space.valid_roster() {
            if i == root {
                continue;
            }
            let Some(opened) = space.opened(i) else {
                continue;
            };
            let roster = space.roster_at(&space.place_of(i));
            let author = space.author_state_at(i);
            for change in opened.changes() {
                let Some(member) = change.member.filter(|m| m.kind == MemberType::Device) else {
                    continue;
                };
                let Some(target) = roster.state(&member) else {
                    continue;
                };
                fn dormant<'c>(
                    mut caps: impl Iterator<Item = &'c frasil_space::Capability>,
                ) -> bool {
                    caps.any(|c| c.name == "frasil.dormant" && c.mode == CapabilityMode::Extends)
                }
                let lowers = change.op == Op::Remove
                    || (change.op == Op::Change
                        && (change.level.is_some_and(|l| l < Level::Administer)
                            || dormant(change.capabilities.iter().flatten())));
                if target.level != Level::Administer
                    || dormant(target.capabilities.iter())
                    || !lowers
                {
                    continue;
                }
                totals.lowerings_checked += 1;
                let by = author.as_ref().and_then(|a| a.rank).unwrap_or(0);
                if by < target.rank.unwrap_or(0) {
                    failures.push(format!(
                        "seed {seed}: (vii) {i:?}: a lower rank lowered a higher one in the \
                         last world"
                    ));
                }
            }
        }
    }

    // A replica that lacks some record objects judges as one that never
    // received those checkpoints, and holds them with what follows them.
    if !h.checkpoints.is_empty() {
        let mut rng = Rng(seed.wrapping_mul(7919));
        let missing: BTreeSet<EventId> = h
            .checkpoints
            .iter()
            .copied()
            .filter(|_| rng.unit() < 0.5)
            .collect();
        if !missing.is_empty() {
            totals.withheld += missing.len();
            let objects: BTreeMap<EventId, Vec<u8>> = h
                .records
                .iter()
                .filter(|(c, _)| !missing.contains(c))
                .map(|(&c, p)| (c, p.clone()))
                .collect();
            let lacking = Checkpointed::new(
                CheckpointInputs {
                    objects: &objects,
                    ..inputs
                },
                None,
            );
            let removed: BTreeSet<EventId> = final_view
                .iter()
                .copied()
                .filter(|&i| missing.contains(&i) || missing.iter().any(|&m| log.precedes(m, i)))
                .collect();
            let lw = lacking.judge(&final_view);
            let kept: BTreeSet<EventId> = final_view.difference(&removed).copied().collect();
            let reference = full_judge.judge(&kept);
            let held = |status: Option<&Status>| {
                [
                    "Sealed",
                    "Pending",
                    "NoHybridKey",
                    "ExtensionRequired",
                    "BadSeal",
                ]
                .contains(&show(status).as_str())
            };
            for &i in &kept {
                let (got, want) = (lw.statuses.get(&i), reference.statuses.get(&i));
                if got != want && !held(want) && show(want) != "Dropped" && show(got) != "Forked" {
                    failures.push(format!(
                        "seed {seed}: missing objects: {i:?}: {} against {}",
                        show(got),
                        show(want)
                    ));
                }
            }
            for &i in &removed {
                let got = show(lw.statuses.get(&i));
                if !held(lw.statuses.get(&i))
                    && !["Malformed", "StaleSeal", "Dropped"].contains(&got.as_str())
                {
                    failures.push(format!(
                        "seed {seed}: missing objects: {i:?} after a missing record is {got}"
                    ));
                }
            }
        }
    }

    // (ii): along every device's views in the order reached, the chain in
    // effect is a prefix of the final one, but where the two part at
    // concurrent checkpoints whose electorates share no device and the
    // final one has the smaller ID.
    let mut bases: Vec<EventId> = Vec::new();
    // (x): what a replica that forgets under each base freezes, in the view
    // in which it first took effect, with the chain there.
    let mut frozen_at: BTreeMap<EventId, (Vec<EventId>, BTreeMap<EventId, FrozenKey>)> =
        BTreeMap::new();
    // Each view is judged once, however many devices held it after however
    // many steps.
    let mut judged_views: BTreeSet<&BTreeSet<EventId>> = BTreeSet::new();
    for snapshot in &snapshots {
        for (name, view) in snapshot {
            if view.is_empty() || !log.is_closed(view) || !judged_views.insert(view) {
                continue;
            }
            let at = full_judge.judge(view);
            if !at.chain.is_empty() && full.chain.get(..at.chain.len()) != Some(&at.chain[..]) {
                let n = at
                    .chain
                    .iter()
                    .zip(&full.chain)
                    .position(|(a, b)| a != b)
                    .unwrap_or(full.chain.len());
                let replaced = n < full.chain.len()
                    && n < at.chain.len()
                    && full.chain[n] < at.chain[n]
                    && disjoint(&full_judge, full.chain[n], at.chain[n], &final_view);
                if replaced {
                    totals.replaced += 1;
                } else {
                    failures.push(format!(
                        "seed {seed}: (ii) {name}'s chain is not a prefix, nor replaced at a \
                         disjoint electorate"
                    ));
                }
            }
            if let Some(&base) = at.chain.last()
                && !bases.contains(&base)
            {
                bases.push(base);
                let frozen = full_judge
                    .frozen_units(view, base)
                    .iter()
                    .map(|(&u, unit)| (u, frozen_key(unit)))
                    .collect();
                frozen_at.insert(base, (at.chain.clone(), frozen));
            }
        }
    }

    // (x) units.md, "The past of a kept checkpoint": what a replica froze
    // when a checkpoint took effect is what one that kept everything shows
    // for good, whatever the record says of the unit's author.
    if let Some(&last) = full.chain.last() {
        let at_end: BTreeMap<EventId, FrozenKey> = full_judge
            .frozen_units(&final_view, last)
            .iter()
            .map(|(&u, unit)| (u, frozen_key(unit)))
            .collect();
        for (base, (chain_then, frozen)) in &frozen_at {
            if full.chain.get(..chain_then.len()) != Some(&chain_then[..]) {
                continue;
            }
            let record = full_judge
                .record(*base)
                .expect("a checkpoint in effect is read");
            for (u, outcome) in frozen {
                totals.units_frozen += 1;
                if at_end.get(u) != Some(outcome) {
                    failures.push(format!(
                        "seed {seed}: (x) frozen under {base:?}: {u:?}: {outcome:?} against \
                         {:?}",
                        at_end.get(u)
                    ));
                }
                let author = *log.event(*u).unwrap().author();
                let standing = record.entry(&MemberRef::device(author)).map(|entry| {
                    (
                        entry.level,
                        entry
                            .capabilities
                            .iter()
                            .map(|c| (c.name.clone(), c.mode.code()))
                            .collect::<Vec<_>>(),
                    )
                });
                if outcome.1 != standing {
                    totals.frozen_standing_changed += 1;
                }
            }
        }
    }

    // (i): a replica that forgot under each checkpoint some view had in
    // effect, holding the genesis, the checkpoint, the envelopes its cuts
    // reach, the late events and the events after it, and the IDs of what
    // it dropped.
    let full_keys = full_judge
        .key_world(&final_view)
        .and_then(|world| key_summary(&world, options(&keys, &others)));
    let mut seen_keys = BTreeSet::new();
    // The releases and restores of the history, and the released state of
    // each stream at the replica that kept everything.
    let requests: BTreeMap<EventId, StorageBody> = final_view
        .iter()
        .filter_map(|&id| {
            let event = log.event(id)?;
            if event.kind() != kind::STORAGE {
                return None;
            }
            let body = StorageBody::read(event.unverified_body()).ok()?;
            matches!(
                body,
                StorageBody::Release { .. } | StorageBody::Restore(Restored::Stream(_))
            )
            .then_some((id, body))
        })
        .collect();
    let streams: BTreeSet<[u8; 16]> = requests
        .values()
        .filter_map(|body| match body {
            StorageBody::Release { stream } | StorageBody::Restore(Restored::Stream(stream)) => {
                Some(*stream)
            }
            _ => None,
        })
        .collect();
    let full_requests: Vec<frasil_units::release::Request<'_>> = requests
        .iter()
        .map(|(&id, body)| frasil_units::release::Request {
            id,
            body,
            placement: full_judge.placement(&final_view, id),
            valid: full.statuses.get(&id).is_some_and(Status::is_valid),
        })
        .collect();
    for base in bases {
        let following = after(&full_judge, &final_view, base);
        let base_past = log.past(base);
        let late: BTreeSet<EventId> = final_view
            .iter()
            .copied()
            .filter(|i| !base_past.contains(i) && !following.contains(i))
            .collect();
        let held: BTreeSet<EventId> = following.union(&late).copied().collect();
        // List copies are retained whole beside the checkpoint's world;
        // their former verdicts are frozen, and are not judged as late.
        let preserved: BTreeSet<EventId> = held
            .iter()
            .copied()
            .chain(
                final_view
                    .iter()
                    .copied()
                    .filter(|id| !Plain.list_copy(log.event(*id).unwrap()).is_empty()),
            )
            .collect();
        let dropped: BTreeSet<EventId> = base_past
            .intersection(&final_view)
            .copied()
            .filter(|i| !held.contains(i))
            .collect();
        let kept_envelopes: BTreeMap<EventId, Event> = full_judge
            .reach(base)
            .unwrap_or_default()
            .into_iter()
            .map(|c| (c, log.event(c).unwrap().clone()))
            .collect();
        let record = full_judge
            .record(base)
            .expect("a checkpoint in effect is read");
        let forgetting = forgetting_log(log, &preserved, &dropped);
        let mut forgot = Checkpointed::new(
            CheckpointInputs {
                log: &forgetting,
                envelopes: &kept_envelopes,
                ..inputs
            },
            Some(Kept {
                checkpoint: base,
                record: record.clone(),
            }),
        );
        let judged = forgot.judge(&held);
        let rivals = forgot.rivals(&held);
        if !rivals.is_empty() || holds_rival(&judged, &held) {
            // What it cannot judge it holds pending, and it never decides
            // otherwise; it must hold a checkpoint that could be a rival.
            totals.rival_pending += 1;
            if !holds_rival(&judged, &held) {
                failures.push(format!(
                    "seed {seed}: (i) forgot under {base:?}: holds rivals {rivals:?} and \
                     decides some event"
                ));
            }
            if rivals.is_empty() || !could_be_rival(&full_judge, &h.checkpoints, &held, base) {
                failures.push(format!(
                    "seed {seed}: (i) forgot under {base:?}: every event pending with no \
                     checkpoint that could be a rival"
                ));
            }
            continue;
        }
        let Some(index) = full.chain.iter().position(|&c| c == base) else {
            failures.push(format!(
                "seed {seed}: (i) forgot under {base:?}, overtaken, and decides without a rival"
            ));
            continue;
        };
        totals.forgetting += 1;
        totals.compared += held.len();
        for &i in &held {
            if judged.statuses.get(&i) != full.statuses.get(&i) {
                failures.push(format!(
                    "seed {seed}: (i) forgot under {base:?}: {i:?}: {} against {}",
                    show(judged.statuses.get(&i)),
                    show(full.statuses.get(&i))
                ));
            }
        }
        if judged.chain[..] != full.chain[index..] {
            failures.push(format!(
                "seed {seed}: (i) forgot under {base:?}: another chain"
            ));
        }
        totals.rosters_compared += 1;
        if roster_view(&judged.roster) != roster_view(&full.roster) {
            failures.push(format!(
                "seed {seed}: (i) forgot under {base:?}: another roster"
            ));
        }
        // (ix) And on every stream's released state (units.md, 3.12, "After a
        // checkpoint"): it kept, of the releases and restores of `base`'s
        // past that are not late under an earlier checkpoint, the maximal
        // ones of each stream, found before it dropped anything, with the
        // verdicts it gave them then; it holds the rest whole and places them
        // itself, what it kept before what follows `base` by construction.
        let kept_requests = frasil_units::release::kept_requests(
            requests
                .iter()
                .filter(|(id, _)| base_past.contains(id))
                .filter(|(id, _)| {
                    full_judge.placement(&final_view, **id) != frasil_space::Placement::Late
                })
                .map(|(&id, body)| (id, body)),
            |a, b| log.precedes(a, b),
        );
        totals.requests_kept += kept_requests.len();
        forgot.set_kept_past(kept_requests.iter().copied());
        let forgot_requests: Vec<frasil_units::release::Request<'_>> = requests
            .iter()
            .filter_map(|(&id, body)| {
                let (placement, valid) = if kept_requests.contains(&id) {
                    (
                        forgot.placement(&held, id),
                        full.statuses.get(&id).is_some_and(Status::is_valid),
                    )
                } else if held.contains(&id) {
                    (
                        forgot.placement(&held, id),
                        judged.statuses.get(&id).is_some_and(Status::is_valid),
                    )
                } else {
                    return None;
                };
                Some(frasil_units::release::Request {
                    id,
                    body,
                    placement,
                    valid,
                })
            })
            .collect();
        for stream in &streams {
            let kept_everything =
                frasil_units::release::released(&full_requests, stream, |a, b| {
                    full_judge.precedes(a, b)
                });
            let forgot_released =
                frasil_units::release::released(&forgot_requests, stream, |a, b| {
                    forgot.precedes(a, b)
                });
            totals.released_compared += 1;
            totals.released += usize::from(kept_everything);
            if kept_everything != forgot_released {
                failures.push(format!(
                    "seed {seed}: (i) forgot under {base:?}: stream {stream:?} released \
                     {forgot_released}, not {kept_everything}"
                ));
            }
        }
        // And on the key graph rooted at the checkpoint in effect: its
        // events, valid set and current states.
        if let Some(want) = &full_keys
            && !seen_keys.contains(&base)
        {
            seen_keys.insert(base);
            totals.key_graphs += 1;
            let got = forgot
                .key_world(&held)
                .and_then(|world| key_summary(&world, options(&keys, &others)));
            if got.as_ref() != Some(want) {
                failures.push(format!(
                    "seed {seed}: (i) forgot under {base:?}: another key graph"
                ));
            }
            if kinds.granted {
                totals.principals_compared += 1;
                totals.principals += want.5.len();
            }
        }
    }
    failures
}

/// What two replicas' key graphs rooted at a checkpoint must agree on: the
/// checkpoint, the world's events and valid set, the current content and
/// grant states, and the space principals of the merged roster, each as its
/// space and grant rotation (keys.md, "Notices and space principals").
type KeySummary = (
    EventId,
    BTreeSet<EventId>,
    BTreeSet<EventId>,
    Option<frasil_keys::RotationSet>,
    Option<frasil_keys::RotationSet>,
    BTreeSet<(EventId, EventId)>,
);

fn key_summary(world: &frasil_space::KeyWorld, options: Options<'_>) -> Option<KeySummary> {
    use frasil_space::keygraph::{Kind, Member, SpaceHistory};
    let space = world.resolve(options).ok()?;
    let history = SpaceHistory::new(&space);
    let graph = history.key_graph();
    let principals = graph
        .members(Kind::Content)
        .keys()
        .filter_map(|m| match m {
            Member::Principal(p) => Some((p.space, p.rotation)),
            Member::Roster(_) => None,
        })
        .collect();
    Some((
        world.checkpoint(),
        graph.events().clone(),
        graph.valid().clone(),
        graph.current(Kind::Content),
        graph.current(Kind::Grant),
        principals,
    ))
}

/// The seeds a variable names: `n` for 1 to `n`, `a-b` for `a` to `b`, so
/// that one seed runs alone; `default` for 1 to `default` without it.
fn seed_range(variable: &str, default: u64) -> (u64, u64) {
    let value = std::env::var(variable).unwrap_or_default();
    match value.split_once('-') {
        Some((a, b)) => (a.parse().expect("a seed"), b.parse().expect("a seed")),
        None => (1, value.parse().unwrap_or(default)),
    }
}

#[test]
fn replicas_that_forget_agree() {
    let (first, seeds) = seed_range("FRASIL_CHECKPOINT_SEEDS", 3);
    let mut failures = Vec::new();
    let mut totals = Totals::default();
    for seed in first..=seeds {
        failures.extend(check_history(seed, Kinds::of(seed), &mut totals));
    }
    eprintln!("checkpoint model check, seeds {first} to {seeds}: {totals:?}");
    assert!(failures.is_empty(), "{failures:#?}");
    // The model reaches the cases it is for.
    assert!(totals.effective > 0 && totals.forgetting > 0, "{totals:?}");
}

/// roster.md, 2.8 The checkpoint record, step 3, 3.15.2, "A record held for
/// a later document's key", and 3.15.6, "A rival": B signs checkpoint x,
/// whose record carries record key 9, concurrently with P's checkpoint c,
/// which P and A vote for.
///
/// - B a dormant administrator, which c does not wait for: a replica that
///   kept everything holds x as `ExtensionRequired` with the anchor after
///   it, takes c into effect and needs a later version.
/// - B a writer: a replica that kept everything judges x by the steps that
///   read no record, `NotAnAdministrator`, final, so x and B's anchor after
///   it are late, and it needs no later version.
///
/// Either way, one that forgot under c, x's past gone, holds x as
/// `ExtensionRequired`, and as a rival when x's ID is the smaller, every
/// other event then pending.
#[test]
fn a_checkpoint_of_a_later_document_is_held_and_as_a_rival_holds_everything() {
    for writer in [false, true] {
        let mut rivals_seen = 0;
        let mut others_seen = 0;
        for attempt in 0..32 {
            let mut h = History::new(&format!("checkpoints/model/later/{writer}/{attempt}"), "P");
            h.grant("P", "A", Level::Administer).unwrap();
            match writer {
                true => h.grant("P", "B", Level::Write).unwrap(),
                false => h.grant_recovery("P", "B").unwrap(),
            };
            h.sync(&["P", "A", "B"]);
            let x = h.checkpoint_with_later_key("B").unwrap();
            let after_x = h.anchor("B").unwrap();
            let c = h.checkpoint("P", false).unwrap();
            h.sync(&["P", "A"]);
            h.anchor("A").unwrap();
            h.anchor("P").unwrap();
            let log = h.log();
            let keys = h.keyring();
            let envelopes = BTreeMap::<EventId, Event>::new();
            let inputs = CheckpointInputs {
                log,
                options: options(&keys, no_others()),
                objects: &h.records,
                envelopes: &envelopes,
                slots: None,
            };
            let full = Checkpointed::new(inputs, None);
            let all: BTreeSet<EventId> = log.canonical().into_iter().collect();
            let judged = full.judge(&all);
            let extension = |status: Option<&Status>| show(status) == "ExtensionRequired";
            assert_eq!(judged.chain, vec![c], "c takes effect beside x");
            if writer {
                assert!(!full.extension_required(x));
                assert_eq!(show(Some(&full.validity(x))), "NotAnAdministrator");
                assert_eq!(show(judged.statuses.get(&x)), "Late");
                assert_eq!(show(judged.statuses.get(&after_x)), "Late");
                assert!(!judged.needs_later_rules);
            } else {
                assert!(full.extension_required(x));
                assert!(extension(judged.statuses.get(&x)));
                assert!(extension(judged.statuses.get(&after_x)));
                assert!(judged.needs_later_rules);
            }
            // A replica that forgot under c keeps c, what follows it and the
            // late events, x among them.
            let following = after(&full, &all, c);
            let past = log.past(c);
            let held: BTreeSet<EventId> = all
                .iter()
                .copied()
                .filter(|i| following.contains(i) || !past.contains(i))
                .filter(|&i| i != log.id())
                .collect();
            let dropped: BTreeSet<EventId> = past.difference(&held).copied().collect();
            let kept_envelopes: BTreeMap<EventId, Event> = full
                .reach(c)
                .unwrap_or_default()
                .into_iter()
                .map(|r| (r, log.event(r).unwrap().clone()))
                .collect();
            let forgetting = forgetting_log(log, &held, &dropped);
            let forgot = Checkpointed::new(
                CheckpointInputs {
                    log: &forgetting,
                    envelopes: &kept_envelopes,
                    ..inputs
                },
                Some(Kept {
                    checkpoint: c,
                    record: full.record(c).unwrap(),
                }),
            );
            let judged = forgot.judge(&held);
            assert!(judged.needs_later_rules);
            assert!(forgot.extension_required(x), "its past is gone");
            assert!(extension(judged.statuses.get(&x)));
            assert!(extension(judged.statuses.get(&after_x)));
            let rivals = forgot.rivals(&held);
            if x < c {
                rivals_seen += 1;
                assert_eq!(rivals, BTreeSet::from([x]), "attempt {attempt}");
                for &i in &held {
                    if i != x && i != after_x {
                        assert_eq!(
                            show(judged.statuses.get(&i)),
                            "Pending",
                            "attempt {attempt}: every other event is held"
                        );
                    }
                }
            } else {
                others_seen += 1;
                assert!(rivals.is_empty(), "attempt {attempt}");
                assert_eq!(judged.chain, vec![c]);
                assert_eq!(show(judged.statuses.get(&c)), "valid");
            }
            if rivals_seen > 0 && others_seen > 0 {
                break;
            }
        }
        assert!(
            rivals_seen > 0 && others_seen > 0,
            "writer {writer}: no history gave both orders of x and c"
        );
    }
}

/// roster.md, 3.15.4, "excused": a recovery member granted before any
/// checkpoint excuses a member when its grant was signed by that member or
/// by a member that outranks it by the ranks and seniorities of the
/// checkpoint's record, not as they stood at the grant. P grants T, then G,
/// `administer` at rank 100 (T the senior); G grants R, a recovery member
/// of rank 100; P raises G to rank 200 (lowering it first) or not; P
/// checkpoints, G votes, T
/// never returns, and R removes T after the checkpoint. With G raised, the
/// record has G outrank T, R's removal excuses T and the checkpoint takes
/// effect; without, G is T's junior there, as at the grant, and it waits.
#[test]
fn a_first_epoch_recovery_member_reads_its_granters_rank_from_the_record() {
    for raised in [true, false] {
        let mut h = History::new(&format!("checkpoints/model/recovery/{raised}"), "P");
        for name in ["T", "G", "R"] {
            h.ranks.insert(name.to_owned(), 100);
        }
        h.grant("P", "T", Level::Administer).unwrap();
        h.grant("P", "G", Level::Administer).unwrap();
        h.sync(&["P", "T", "G"]);
        let grant = h.grant_recovery("G", "R").unwrap();
        h.sync(&["P", "G"]);
        if raised {
            let g = MemberRef::device(frasil_crypto::device::DeviceId(h.device("G")));
            // A rank never changes in place: P lowers G, then raises it.
            h.update("P", Change::set_level(g, Level::Write), false, None)
                .unwrap();
            h.update("P", Change::raise(g, 200), false, None).unwrap();
        }
        h.sync(&["P", "G", "R"]);
        let c = h.checkpoint("P", false).unwrap();
        h.sync(&["P", "G", "R"]);
        h.anchor("G").unwrap();
        h.sync(&["P", "G", "R"]);
        let removal = h.remove("R", "T", None).unwrap();
        let log = h.log();
        assert!(log.precedes(c, removal) && log.precedes(grant, c));
        let keys = h.keyring();
        let envelopes = BTreeMap::<EventId, Event>::new();
        let judge = Checkpointed::new(
            CheckpointInputs {
                log,
                options: options(&keys, no_others()),
                objects: &h.records,
                envelopes: &envelopes,
                slots: None,
            },
            None,
        );
        assert!(judge.validity(c).is_valid(), "raised {raised}");
        let all: BTreeSet<EventId> = log.canonical().into_iter().collect();
        let t = frasil_crypto::device::DeviceId(h.device("T"));
        let held_after = after(&judge, &all, c);
        assert_eq!(
            judge.excused(c, &held_after).contains(&t),
            raised,
            "raised {raised}: R excuses T"
        );
        assert_eq!(
            judge.judge(&all).chain == vec![c],
            raised,
            "raised {raised}: in effect"
        );
    }
}
