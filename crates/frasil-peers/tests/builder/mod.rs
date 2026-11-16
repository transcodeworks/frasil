//! A log of storage and space events built event by event, for tests of
//! the peer's checks (peers.md, "What a peer checks before it stores a
//! skeleton event").

#![allow(dead_code)]

use frasil_base::cbor::{Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_crypto::fixtures::fixture_mldsa_seed;
use frasil_crypto::primitives::sha256;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::{Envelope, Event, EventId, Log, Placement, decode, kind};
use frasil_keys::body::visible_key;
use frasil_peers::body::{ChangeEffect, GrantMap, SlotId, StorageBody};
use frasil_peers::derive::{SlotKeys, enrol_statement, root_statement};
use std::collections::{BTreeMap, BTreeSet};

pub fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/repeated-commitment/", name.as_bytes()])
}

/// A device's signer: the fixture ML-DSA-65 and X-Wing seeds of its
/// Ed25519 seed.
pub fn signer(name: &str) -> Signer {
    let seed = example(&format!("{name}/ed25519"));
    frasil_crypto::fixtures::FixtureKeys::from_identity_seed(&seed).signer()
}

/// An administrator pseudonym's signer: no X-Wing key.
pub fn pseudonym(name: &str) -> Signer {
    let seed = example(&format!("{name}/ed25519"));
    Signer::from_seeds(&seed, &fixture_mldsa_seed(&seed), None)
}

/// A log built event by event, each author's chain kept.
pub struct Builder {
    /// The log.
    pub log: Log,
    /// The space: the genesis's ID.
    pub space: EventId,
    /// Each author's last sequence number and event.
    pub last: BTreeMap<DeviceId, (u64, EventId)>,
    /// The space events that are checkpoints, from which each event's cuts
    /// are computed (events.md, "Cuts"); none unless a test adds them.
    pub checkpoints: BTreeSet<EventId>,
}

impl Builder {
    /// The genesis, by the founder's device.
    pub fn new(founder: &Signer) -> Self {
        let envelope = Envelope {
            kind: kind::SPACE,
            log: None,
            ed: *founder.identity_key(),
            kc: *founder.kc(),
            seq: 1,
            prev: None,
            parents: vec![],
            cuts: Vec::new(),
            body: Value::Map(Map::new()).encode(),
            scheme: Scheme::Hybrid,
        };
        let genesis = decode(&envelope.sign(founder)).expect("a genesis");
        let space = genesis.id();
        let mut last = BTreeMap::new();
        last.insert(*founder.device_id(), (1, space));
        Self {
            log: Log::new(genesis).expect("a log"),
            space,
            last,
            checkpoints: BTreeSet::new(),
        }
    }

    /// An event of `kind` by `signer` with `parents` (its `prev` added).
    pub fn act(
        &mut self,
        signer: &Signer,
        kind: u8,
        body: Vec<u8>,
        parents: &[EventId],
    ) -> EventId {
        self.try_act(signer, kind, body, parents)
            .expect("an event with at most four cuts")
    }

    /// As [`Builder::act`], or none when the event would declare more cuts
    /// than an envelope carries.
    pub fn try_act(
        &mut self,
        signer: &Signer,
        kind: u8,
        body: Vec<u8>,
        parents: &[EventId],
    ) -> Option<EventId> {
        let author = *signer.device_id();
        let (seq, prev) = match self.last.get(&author) {
            Some(&(seq, prev)) => (seq + 1, Some(prev)),
            None => (1, None),
        };
        let mut parents = parents.to_vec();
        parents.extend(prev);
        let cuts = self
            .log
            .cuts_for(&self.checkpoints, &parents)
            .expect("every parent placed");
        if cuts.len() > frasil_events::MAX_CUTS {
            return None;
        }
        let envelope = Envelope {
            kind,
            log: Some(self.space),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents,
            cuts,
            body,
            scheme: Scheme::Hybrid,
        };
        let event: Event = decode(&envelope.sign(signer)).expect("an event");
        let id = event.id();
        assert!(matches!(
            self.log.place(event).expect("of the log"),
            Placement::Placed(_)
        ));
        self.last.insert(author, (seq, id));
        Some(id)
    }

    pub fn heads(&self) -> Vec<EventId> {
        let all: BTreeSet<EventId> = self.log.canonical().into_iter().collect();
        all.iter()
            .copied()
            .filter(|&a| !all.iter().any(|&b| self.log.precedes(a, b)))
            .collect()
    }

    pub fn storage(&mut self, signer: &Signer, body: StorageBody, parents: &[EventId]) -> EventId {
        self.act(signer, kind::STORAGE, body.encode(), parents)
    }

    /// A space event that names `twin` in visible key 15. The peer reads
    /// nothing else of it.
    pub fn name(&mut self, device: &Signer, twin: EventId, parents: &[EventId]) -> EventId {
        self.act(device, kind::SPACE, Self::naming(twin), parents)
    }

    /// A checkpoint that names `cut` as its twin: a space event the peer
    /// reads only for its key 15, counted as a checkpoint in the cuts of the
    /// events after it.
    pub fn checkpoint(&mut self, device: &Signer, cut: EventId, parents: &[EventId]) -> EventId {
        let id = self.name(device, cut, parents);
        self.checkpoints.insert(id);
        id
    }

    pub fn root(&mut self, founder: &Signer, pseudonym: &Signer, c: [u8; 32]) -> EventId {
        let statement = root_statement(&self.space, pseudonym.device_id());
        let body = StorageBody::Root {
            twin: c,
            mldsa: pseudonym.mldsa_public().to_vec(),
            duel_policy: 0,
            founder_mldsa: founder.mldsa_public().to_vec(),
            founder_signature: founder.sign(Scheme::Hybrid, &statement),
            founder_xwing: founder.keys().xwing().unwrap().to_vec(),
        };
        let genesis = self.space;
        self.storage(pseudonym, body, &[genesis])
    }

    pub fn enrol(
        &mut self,
        pseudonym: &Signer,
        slot: SlotId,
        keys: &SlotKeys,
        parents: &[EventId],
    ) -> EventId {
        let body = self.enrol_body(pseudonym, slot, keys);
        self.storage(pseudonym, body, parents)
    }

    /// An enrolment's body: the peer cannot open its binding, so the
    /// binding is filler of the right length.
    pub fn enrol_body(&self, pseudonym: &Signer, slot: SlotId, keys: &SlotKeys) -> StorageBody {
        let statement = enrol_statement(&self.space, slot.reference, pseudonym.device_id());
        StorageBody::Enrol {
            slot,
            mldsa: pseudonym.mldsa_public().to_vec(),
            slot_mldsa: keys.signer.mldsa_public().to_vec(),
            authorization: keys.signer.sign(Scheme::Hybrid, &statement),
            binding: vec![0xbb; 3_445],
        }
    }

    /// The body of a space event that names `twin` in visible key 15.
    pub fn naming(twin: EventId) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(visible_key::TWIN, Value::from(twin.0));
        Value::Map(map).encode()
    }
}

/// A grant map under the keys of `token`, at the top rank. The peer never
/// opens the sealed token, so its bytes are filler of the right length.
pub fn grant(token: &[u8; 32]) -> (GrantMap, SlotKeys) {
    grant_ranked(token, frasil_peers::limits::MAX_RANK)
}

/// A grant map under the keys of `token`, at `rank`.
pub fn grant_ranked(token: &[u8; 32], rank: u8) -> (GrantMap, SlotKeys) {
    let keys = SlotKeys::from_token(token);
    let map = GrantMap {
        slot_ed: *keys.ed_public(),
        slot_mldsa_hash: keys.mldsa_hash(),
        token: vec![0x01; 1_171],
        rank,
    };
    (map, keys)
}

/// The founder `F` and its pseudonym `P0`; `F` grants device `A`
/// administer through `P0`'s change, and `A`'s pseudonym `A1` enrols.
pub struct Space {
    /// The log.
    pub b: Builder,
    /// Device `A`.
    pub a: Signer,
    /// `A`'s pseudonym.
    pub a1: Signer,
    /// The founder's pseudonym.
    pub p0: Signer,
    /// The root.
    pub root: EventId,
    /// The root's commitment.
    pub c_genesis: [u8; 32],
    /// The change that grants `A` administer.
    pub change: EventId,
    /// The commitment of `A`'s administrator slot.
    pub c_a: [u8; 32],
    /// The salt of the change that grants `A` administer.
    pub salt_a: [u8; 32],
    /// `A`'s slot keys.
    pub keys: SlotKeys,
}

pub fn space_with_a() -> Space {
    let (f, p0, a, a1) = (signer("F"), pseudonym("P0"), signer("A"), pseudonym("A1"));
    let mut b = Builder::new(&f);
    let c_genesis = example("c(genesis)");
    let root = b.root(&f, &p0, c_genesis);
    let c_a = example("c(F grants A)");
    let salt_a = example("salt of F grants A");
    let (map, keys) = grant(&example("token of A"));
    let change = b.storage(
        &p0,
        StorageBody::Change {
            twin: c_a,
            salt: salt_a,
            effect: ChangeEffect::Grants(vec![map]),
        },
        &[root],
    );
    b.name(&f, change, &[change]);
    let heads = b.heads();
    b.enrol(&a1, SlotId::new(c_a, 0, change), &keys, &heads);
    Space {
        b,
        a,
        a1,
        p0,
        root,
        c_genesis,
        change,
        c_a,
        salt_a,
        keys,
    }
}
