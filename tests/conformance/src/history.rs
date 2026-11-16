//! Histories from `peers.json`, and events signed onto them.
//!
//! The vectors' histories are the reference builder's: every key is
//! `example("<prefix>/<name>/ed25519")`, every rotation's secrets are
//! `example("<prefix>/<label>/content-key")` and `.../upload-seed`, with
//! the genesis's under the label `genesis`. A scenario signs further
//! events with the same keys.

use frasil_crypto::device::{DeviceId, IdentityKey};
use frasil_crypto::fixtures::{fixture_mldsa_seed, fixture_xwing_seed};
use frasil_crypto::primitives::{ed25519_public, sha256};
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_crypto::wrap::xwing_public;
use frasil_events::{Envelope, EventId, kind};
use frasil_keys::RotationSet;
use frasil_keys::derive::{read_credential, upload_key};
use frasil_peers::body::{Restored, StorageBody};
use frasil_units::Compacts;
use frasil_units::objects::Header;
use frasil_units::unit::Draft;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

/// The vector file.
pub const PEERS: &str = "peers.json";

/// A family of `peers.json`.
pub fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(PEERS, name)
}

/// The reference's fixed inputs: SHA-256 of a description.
pub fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// The bytes of a hex string.
pub fn hex(value: &Json) -> Vec<u8> {
    frasil_testkit::hex::decode(value.as_str().expect("a hex string")).expect("hex")
}

/// A stream of the reference's main history: `example("storage/stream/<name>")`,
/// its first 16 bytes.
pub fn stream(name: &str) -> [u8; 16] {
    example(&format!("storage/stream/{name}"))[..16]
        .try_into()
        .expect("16 bytes")
}

/// An object ID of the reference's main history.
pub fn object_id(name: &str) -> [u8; 32] {
    example(&format!("storage/object/{name}"))
}

/// A history of the vectors, and the events a scenario adds to it.
#[derive(Debug, Clone)]
pub struct History {
    /// The reference builder's prefix.
    pub prefix: String,
    /// Each event's name, in order.
    pub order: Vec<String>,
    signed: BTreeMap<String, Vec<u8>>,
    ids: BTreeMap<String, EventId>,
    next: BTreeMap<String, (u64, Option<EventId>)>,
    pseudonyms: BTreeSet<String>,
}

impl History {
    /// The `events` of a family, under the builder's prefix.
    pub fn of(family_name: &str, prefix: &str) -> Self {
        Self::of_file(PEERS, family_name, prefix)
    }

    /// The `events` of a family of another vector file, under the
    /// builder's prefix.
    pub fn of_file(file: &str, family_name: &str, prefix: &str) -> Self {
        let rows = frasil_testkit::vectors::family::<Json>(file, family_name)["events"]
            .as_array()
            .expect("an events list")
            .clone();
        let mut history = Self {
            prefix: prefix.into(),
            order: Vec::new(),
            signed: BTreeMap::new(),
            ids: BTreeMap::new(),
            next: BTreeMap::new(),
            pseudonyms: BTreeSet::new(),
        };
        for row in rows {
            let name = row["name"].as_str().expect("a name").to_owned();
            let signed = hex(&row["signed"]);
            let id = frasil_events::decode(&signed).expect("an event").id();
            assert_eq!(id.0[..], hex(&row["id"])[..], "{name}");
            history.add(&name, signed);
        }
        history
    }

    /// `credentials`: P founds a space, grants W and V write, rotates,
    /// removes W while W rotates; P's pseudonym P0 asks for credentials.
    pub fn credentials() -> Self {
        Self::of("credentials", "storage/credentials")
    }

    /// `skeleton`: the main history, with administrators A and B, a
    /// release and a restore, erasures and a credentials request.
    pub fn skeleton() -> Self {
        Self::of("skeleton", "storage")
    }

    fn add(&mut self, name: &str, signed: Vec<u8>) -> EventId {
        let id = frasil_events::decode(&signed).expect("an event").id();
        self.order.push(name.into());
        self.ids.insert(name.into(), id);
        self.signed.insert(name.into(), signed);
        id
    }

    /// The space: the genesis's ID.
    pub fn space(&self) -> EventId {
        self.id(&self.order[0])
    }

    /// A named event's ID.
    pub fn id(&self, name: &str) -> EventId {
        *self
            .ids
            .get(name)
            .unwrap_or_else(|| panic!("no event {name}"))
    }

    /// An event's name.
    pub fn name(&self, id: EventId) -> Option<&str> {
        self.ids
            .iter()
            .find(|(_, held)| **held == id)
            .map(|(name, _)| name.as_str())
    }

    /// A named event's signed bytes.
    pub fn signed(&self, name: &str) -> Vec<u8> {
        self.signed
            .get(name)
            .unwrap_or_else(|| panic!("no event {name}"))
            .clone()
    }

    /// The signed bytes of named events.
    pub fn events(&self, names: &[&str]) -> Vec<Vec<u8>> {
        names.iter().map(|n| self.signed(n)).collect()
    }

    /// Every event before `name`, in order, the genesis first.
    pub fn before(&self, name: &str) -> Vec<Vec<u8>> {
        self.order
            .iter()
            .take_while(|n| *n != name)
            .map(|n| self.signed(n))
            .collect()
    }

    /// Every event up to and with `name`, in order.
    pub fn through(&self, name: &str) -> Vec<Vec<u8>> {
        let mut out = self.before(name);
        out.push(self.signed(name));
        out
    }

    /// Every event of the history, in order.
    pub fn all(&self) -> Vec<Vec<u8>> {
        self.order.iter().map(|n| self.signed(n)).collect()
    }

    /// A key's Ed25519 seed.
    pub fn seed(&self, who: &str) -> [u8; 32] {
        example(&format!("{}/{who}/ed25519", self.prefix))
    }

    /// A key's Ed25519 public key.
    pub fn key(&self, who: &str) -> [u8; 32] {
        ed25519_public(&self.seed(who))
    }

    /// A key's signer: its Ed25519 seed and the fixture ML-DSA-65 seed,
    /// with the fixture X-Wing key for a device, and none for an
    /// administrator pseudonym. A key is a pseudonym when
    /// [`Self::pseudonym`] named it, or when an event the history holds
    /// under its Ed25519 key carries the `kc` of no X-Wing key.
    pub fn signer(&self, who: &str) -> Signer {
        let seed = self.seed(who);
        let pseudonym = Signer::from_seeds(&seed, &fixture_mldsa_seed(&seed), None);
        let ed = IdentityKey(self.key(who));
        let is_pseudonym = self.pseudonyms.contains(who)
            || self.signed.values().any(|signed| {
                frasil_events::decode(signed)
                    .is_ok_and(|event| *event.ed() == ed && event.kc() == pseudonym.kc())
            });
        if is_pseudonym {
            return pseudonym;
        }
        let xwing = xwing_public(&fixture_xwing_seed(&seed));
        Signer::from_seeds(&seed, &fixture_mldsa_seed(&seed), Some(&xwing))
    }

    /// Names `who` an administrator pseudonym, with no X-Wing key, before
    /// it signs an event.
    pub fn pseudonym(&mut self, who: &str) {
        self.pseudonyms.insert(who.into());
    }

    /// A key's device ID, as [`Self::signer`] signs.
    pub fn device_id(&self, who: &str) -> DeviceId {
        *self.signer(who).device_id()
    }

    fn label(&self, rotation: &str) -> String {
        if self.ids.get(rotation) == Some(&self.space()) {
            "genesis".into()
        } else {
            rotation.into()
        }
    }

    /// A rotation's content key.
    pub fn content_key(&self, rotation: &str) -> [u8; 32] {
        example(&format!(
            "{}/{}/content-key",
            self.prefix,
            self.label(rotation)
        ))
    }

    /// The Ed25519 seed of a rotation's read credential.
    pub fn read_seed(&self, rotation: &str) -> [u8; 32] {
        *read_credential(&self.content_key(rotation)).seed
    }

    /// The Ed25519 seed of a rotation's upload key.
    pub fn upload_seed(&self, rotation: &str) -> [u8; 32] {
        let w = example(&format!(
            "{}/{}/upload-seed",
            self.prefix,
            self.label(rotation)
        ));
        *upload_key(&w).seed
    }

    /// An author's next `seq`, and its latest event, among every event the
    /// history holds.
    pub fn next_of(&self, who: &str) -> (u64, Option<EventId>) {
        if let Some(next) = self.next.get(who) {
            return *next;
        }
        let author = self.device_id(who);
        let mut best: Option<(u64, EventId)> = None;
        for signed in self.signed.values() {
            let event = frasil_events::decode(signed).expect("an event");
            if *event.author() == author
                && best.is_none_or(|(seq, id)| (event.seq(), event.id()) > (seq, id))
            {
                best = Some((event.seq(), event.id()));
            }
        }
        match best {
            Some((seq, id)) => (seq + 1, Some(id)),
            None => (1, None),
        }
    }

    /// Makes `who`'s next event take this `seq` and `prev`, once: a
    /// second event at a `seq`, as a fork.
    pub fn force_next(&mut self, who: &str, seq: u64, prev: Option<EventId>) {
        self.next.insert(who.into(), (seq, prev));
    }

    /// Signs an event of the space by `who` with these parents (its own
    /// latest event is added), and adds it to the history as `name`.
    pub fn sign(
        &mut self,
        who: &str,
        name: &str,
        event_kind: u8,
        body: Vec<u8>,
        parents: &[&str],
    ) -> Vec<u8> {
        let (seq, prev) = self.next_of(who);
        self.next.remove(who);
        let mut parents: Vec<EventId> = parents.iter().map(|p| self.id(p)).collect();
        if let Some(prev) = prev {
            parents.push(prev);
        }
        let scheme = if event_kind == kind::UNIT {
            Scheme::Ed25519
        } else {
            Scheme::Hybrid
        };
        let signer = self.signer(who);
        let envelope = Envelope {
            kind: event_kind,
            log: Some(self.space()),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents,
            cuts: Vec::new(),
            body,
            scheme,
        };
        let signed = envelope.sign(&signer);
        self.add(name, signed.clone());
        signed
    }

    /// A storage event signed onto the history.
    pub fn storage(
        &mut self,
        who: &str,
        name: &str,
        body: &StorageBody,
        parents: &[&str],
    ) -> Vec<u8> {
        self.sign(who, name, kind::STORAGE, body.encode(), parents)
    }

    /// A unit of `stream` signed onto the history, sealed under the
    /// genesis's state: the peer reads no sealed byte.
    pub fn unit(
        &mut self,
        who: &str,
        name: &str,
        stream: [u8; 16],
        objects: Vec<[u8; 64]>,
        compacts: Option<Compacts>,
        parents: &[&str],
    ) -> Vec<u8> {
        self.unit_of(who, name, stream, objects, compacts, parents, b"content")
    }

    /// [`Self::unit`] whose sealed plaintext is `content`: a unit as large
    /// as a scenario needs, within units.md's limits.
    #[allow(clippy::too_many_arguments)]
    pub fn unit_of(
        &mut self,
        who: &str,
        name: &str,
        stream: [u8; 16],
        objects: Vec<[u8; 64]>,
        compacts: Option<Compacts>,
        parents: &[&str],
        content: &[u8],
    ) -> Vec<u8> {
        let (seq, prev) = self.next_of(who);
        self.next.remove(who);
        let mut parent_ids: Vec<EventId> = parents.iter().map(|p| self.id(p)).collect();
        if let Some(prev) = prev {
            parent_ids.push(prev);
        }
        let space = self.space();
        let author = self.device_id(who);
        let stream_prev = self
            .signed
            .values()
            .filter_map(|signed| frasil_events::decode(signed).ok())
            .filter(|event| event.kind() == kind::UNIT && *event.author() == author)
            .filter(|event| {
                frasil_units::Unit::from_event(event.clone())
                    .is_ok_and(|unit| unit.body.stream == stream)
            })
            .max_by_key(|event| event.seq())
            .map(|event| event.id());
        let draft = Draft {
            log: space,
            seq,
            prev,
            parents: parent_ids,
            scheme: Scheme::Ed25519,
            stream,
            key_reference: RotationSet::single(space).encode(),
            stream_prev,
            objects,
            compacts,
            supersedes: Vec::new(),
        };
        let nonce: [u8; 24] = example(&format!("{}/{name}/nonce", self.prefix))[..24]
            .try_into()
            .expect("24 bytes");
        let written = draft.write_with(
            &self.signer(who),
            &self.content_key(&self.order[0].clone()),
            content,
            &nonce,
        );
        self.add(name, written.signed.clone());
        written.signed
    }
}

/// A space erasure's body: an erasure names the whole space.
pub fn erase_space() -> StorageBody {
    StorageBody::Erase
}

/// The bytes of an erase body that names a stream: keys 1, 2 and 4, which
/// protocol 1 reserves (peers.md, "Storage events"), so a peer refuses it
/// as `Malformed`.
pub fn erase_stream_body(stream: [u8; 16]) -> Vec<u8> {
    use frasil_base::cbor::Value;
    Value::Map(
        [
            (1u64, Value::Unsigned(1)),
            (2, Value::Unsigned(5)),
            (4, Value::Array(vec![Value::from(stream)])),
        ]
        .into(),
    )
    .encode()
}

/// A release's body.
pub fn release(stream: [u8; 16]) -> StorageBody {
    StorageBody::Release { stream }
}

/// A restore's body.
pub fn restore(stream: [u8; 16]) -> StorageBody {
    StorageBody::Restore(Restored::Stream(stream))
}

/// A stored object that the peer accepts: a header naming `id` and `size`,
/// then sealed chunks of filler bytes. The peer cannot open it and does not
/// try. Returns the stored bytes and the locator.
pub fn object(id: [u8; 32], size: u64, space: EventId) -> (Vec<u8>, [u8; 64]) {
    use frasil_units::limits::{CHUNK_BYTES, SEALED_CHUNK_BYTES};
    let header = Header {
        object_id: id,
        key_reference: RotationSet::single(space).encode(),
        size,
    }
    .encode();
    let mut stored = (header.len() as u32).to_be_bytes().to_vec();
    stored.extend_from_slice(&header);
    let chunks = frasil_units::objects::chunk_count(size, CHUNK_BYTES as u64);
    let overhead = (SEALED_CHUNK_BYTES - CHUNK_BYTES) as u64;
    let body = size + chunks * overhead;
    stored.extend((0..body).map(|i| (i % 251) as u8));
    let mut locator = [0u8; 64];
    locator[..32].copy_from_slice(&id);
    locator[32..].copy_from_slice(&sha256(&[&stored]));
    (stored, locator)
}
