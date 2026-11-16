//! Stream snapshots (units.md, section 2.9) and the space snapshot
//! (sections 2.11 and 3.10).
//!
//! The **stream snapshot object** is an object, sealed under the
//! compactor's current state, whose plaintext is a deterministic CBOR map:
//! key 1, `version`, 1; key 2, `type`, the adapter type; key 3, `stream`;
//! key 4, `history_free`, 1 when the state carries no edit history; key 5,
//! `state`, the adapter's snapshot state; key 6, `moved`, the content of a
//! valid `frasil:move` unit in the cover.
//!
//! A **space snapshot** is a deterministic CBOR array `[snapshot,
//! signature]`: `snapshot` the bytes of the map [`SpaceSnapshot`] encodes,
//! and `signature` its sender's scheme-2 signature over
//! `"frasil/space-snapshot/v1" || snapshot`. With a checkpoint in effect at
//! the base, keys 12 to 14 ([`SnapshotCheckpoint`]) name it, hand its
//! record's object key and the envelopes of the checkpoints its cuts
//! reach.

use crate::body::{
    Cover, Stub, covers_value, read_covers, read_snapshot_stubs, read_supersessions, stubs_value,
    supersession_value,
};
use crate::ids::{event_ids, ids_value};
use crate::limits::{LOCATOR_BYTES, MAX_EXCLUDED, MAX_HEADS, MAX_PROOFS};
use crate::own::{BodyKey, read_body_key_pairs};
use crate::stream::{self, Opening, StreamId};
use crate::{KeyReference, UnitClass, UnitError};
use frasil_adapter::{Locator, Supersession};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Malformed, Map, Value};
use frasil_crypto::device::{KeySource, Signatory};
use frasil_crypto::labels::SPACE_SNAPSHOT;
use frasil_crypto::schemes::{
    Scheme, Signed, Signer, ed25519_verify_strict, hybrid_ed25519_message, verify_mldsa_steps,
};
use frasil_crypto::sizes::{ED25519_SIGNATURE, SCHEME2_SIGNATURE};
use frasil_events::cuts::{may_be_checkpoint, reach};
use frasil_events::{Event, EventId};
use std::collections::BTreeMap;

/// The version of a stream snapshot's plaintext and of a space snapshot.
pub const VERSION: u64 = 1;

/// A stream snapshot object's plaintext (section 2.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSnapshot {
    /// Key 2: the adapter type.
    pub type_: String,
    /// Key 3: the stream.
    pub stream: StreamId,
    /// Key 4: whether the state carries no edit history.
    pub history_free: bool,
    /// Key 5: the adapter's snapshot state.
    pub state: Vec<u8>,
    /// Key 6: the content of a valid `frasil:move` unit in the cover.
    pub moved: Option<Vec<u8>>,
}

impl StreamSnapshot {
    /// The plaintext's deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::from([
            (1, Value::from(VERSION)),
            (2, Value::from(self.type_.as_str())),
            (3, Value::from(self.stream)),
            (5, Value::from(self.state.as_slice())),
        ]);
        if self.history_free {
            map.insert(4, Value::from(1u64));
        }
        if let Some(moved) = &self.moved {
            map.insert(6, Value::from(moved.as_slice()));
        }
        Value::Map(map).encode()
    }

    /// Reads a stream snapshot object's plaintext (section 3.3, after step
    /// 7): deterministic CBOR, a map with key 1 (`Malformed`); key 1 is 1
    /// (`UnsupportedVersion`); keys 1 to 6 with their types, key 2 the
    /// snapshot unit's sealed type, and key 3 its stream (`Malformed`).
    ///
    /// # Errors
    ///
    /// `Malformed` or `UnsupportedVersion`.
    pub fn read(data: &[u8], stream: &StreamId, type_: &str) -> Result<Self, UnitError> {
        let value = cbor::decode(data)?;
        let map = value.as_map()?;
        let version = map.get(&1).ok_or(Malformed)?.as_unsigned()?;
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        if map.keys().any(|key| !(1..=6).contains(key))
            || ![2, 3, 5].iter().all(|key| map.contains_key(key))
        {
            return Err(ErrorClass::Malformed.into());
        }
        if map[&2].as_text()? != type_ || map[&3].as_bytes()? != stream {
            return Err(ErrorClass::Malformed.into());
        }
        let state = map[&5].as_bytes()?.to_vec();
        let history_free = match map.get(&4) {
            Some(value) if value.as_unsigned()? == 1 => true,
            Some(_) => return Err(ErrorClass::Malformed.into()),
            None => false,
        };
        let moved = match map.get(&6) {
            Some(value) => Some(value.as_bytes()?.to_vec()),
            None => None,
        };
        Ok(Self {
            type_: type_.to_owned(),
            stream: *stream,
            history_free,
            state,
            moved,
        })
    }
}

/// A log entry of a space snapshot: a space of the grant path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Key 1: the space.
    pub space: EventId,
    /// Key 2: its signed space events, storage events and anchors, in
    /// canonical order.
    pub events: Vec<Vec<u8>>,
    /// Key 3: its stubs, six elements each, or seven with cuts.
    pub stubs: Vec<Stub>,
    /// Key 4: its body keys.
    pub body_keys: Vec<BodyKey>,
    /// Key 5: its equivocation proofs; empty for none.
    pub proofs: Vec<Vec<u8>>,
}

/// A stream entry of a space snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEntry {
    /// Key 1: the stream.
    pub stream: StreamId,
    /// Key 2: the stream's opening `[type, salt]`, which hashes to key 1,
    /// so that a newcomer writes into the stream before any of its units
    /// reach it.
    pub opening: Opening,
    /// Key 3: the locator of a stream snapshot object with `history_free`
    /// set.
    pub object: Locator,
    /// Key 4: the key reference of that object's state.
    pub key: Vec<u8>,
    /// Key 5: the stream's covers at the base.
    pub covers: Vec<Cover>,
    /// Key 6: the units of the cover the state does not include.
    pub excluded: Vec<EventId>,
    /// Key 7: the history-free state's supersessions, two elements each,
    /// strictly ascending; empty for none (ext-file-versions.md, 3.3 The
    /// supersession set). A core implementation reads it for its form.
    pub supersedes: Vec<Supersession>,
}

/// A space snapshot's map (section 2.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceSnapshot {
    /// Key 2: the space ID.
    pub space: EventId,
    /// Key 3: the signing device's `ed || kc` (crypto.md, "A device's
    /// keys"); the sender is the device ID they give.
    pub sender: Signatory,
    /// Key 4: 1 to 256 heads of the sender's view the snapshot is taken at.
    pub base: Vec<EventId>,
    /// Key 5: stubs of six elements, or seven with cuts.
    pub stubs: Vec<Stub>,
    /// Key 6: body keys.
    pub body_keys: Vec<BodyKey>,
    /// Key 7: signed device-list events.
    pub lists: Vec<Vec<u8>>,
    /// List events whose own copies are at the base (key 15).
    pub placed: Vec<EventId>,
    /// Key 8: the grant path's logs.
    pub logs: Vec<LogEntry>,
    /// Key 9: the stream entries.
    pub streams: Vec<StreamEntry>,
    /// Key 10: equivocation proofs; empty for none.
    pub proofs: Vec<Vec<u8>>,
    /// Key 11: the space's system stream ID.
    pub system_stream: StreamId,
    /// Keys 12 to 14: the checkpoint in effect at the base, its record's
    /// object key and its cut chain; `None` when no checkpoint is in
    /// effect there.
    pub checkpoint: Option<SnapshotCheckpoint>,
}

/// The skeleton cut a checkpoint names as its twin, in its visible key 15
/// (roster.md, 3.15.8; peers.md, "Skeleton cuts"); `None` for an event
/// whose visible part does not read or names no twin.
pub fn twin_of(checkpoint: &Event) -> Option<EventId> {
    frasil_keys::body::VisiblePart::read(
        checkpoint.unverified_body(),
        checkpoint.author(),
        checkpoint.seq(),
    )
    .ok()?
    .twin
    .map(EventId)
}

/// The roots and enrolments a skeleton cut's slot entries name, and those
/// its standing entries name for slots that are out, by event ID, strictly
/// ascending: the events that carry the keys of the pseudonyms that vote
/// for its slots, which a newcomer fetches although they lie before the
/// checkpoint (peers.md, "Skeleton cuts", "Truncation"). `None` when the
/// event is no cut.
pub fn cut_enrolments(cut: &Event) -> Option<Vec<EventId>> {
    let body = frasil_peers::cut::read_cut(cut)?;
    let named: std::collections::BTreeSet<EventId> = body
        .slots
        .iter()
        .filter_map(|entry| entry.pseudonym)
        .chain(body.standing.iter().filter_map(|entry| entry.pseudonym))
        .collect();
    Some(named.into_iter().collect())
}

/// Keys 12 to 14 of a space snapshot (section 2.11): what a newcomer starts
/// from when a checkpoint is in effect at the base. It holds the frame only
/// from that checkpoint on (section 3.10, "The checkpoint"; roster.md,
/// 3.15.6 Forgetting, and starting from a checkpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCheckpoint {
    /// Key 12: the checkpoint in effect at the base, the last of its chain.
    pub checkpoint: EventId,
    /// Key 13: the object key of that checkpoint's record object, which
    /// opens that object alone ([`record_object_key`](crate::record::record_object_key)).
    pub record_key: [u8; 32],
    /// Key 14: the signed envelopes of the checkpoints key 12's cuts
    /// reach, each a byte string, strictly ascending by event ID; possibly
    /// empty. The newcomer keeps them to order cuts (events.md, 3.11 Cuts,
    /// "Ordering needs envelopes").
    pub cut_chain: Vec<Vec<u8>>,
}

impl SnapshotCheckpoint {
    /// The cut chain's events, by ID, each checked to be an event of
    /// `space` that may be a checkpoint (a space event other than a
    /// genesis): what a newcomer keeps beside what it holds
    /// ([`frasil_events::Log::keep_envelope`], or
    /// [`frasil_events::cuts::WithKept`]).
    ///
    /// # Errors
    ///
    /// `Malformed` for an envelope that does not decode, is of another log
    /// or cannot be a checkpoint.
    pub fn kept_envelopes(&self, space: &EventId) -> Result<BTreeMap<EventId, Event>, ErrorClass> {
        let mut out = BTreeMap::new();
        for signed in &self.cut_chain {
            let event = frasil_events::decode(signed).map_err(|_| ErrorClass::Malformed)?;
            if event.log_id() != *space || !may_be_checkpoint(&event) {
                return Err(ErrorClass::Malformed);
            }
            out.insert(event.id(), event);
        }
        Ok(out)
    }

    /// Whether the cut chain is complete for the checkpoint, once the
    /// newcomer fetched it: every checkpoint its cuts reach has its
    /// envelope in the chain. Returns those it lacks, strictly ascending,
    /// which the newcomer fetches; empty when complete.
    ///
    /// # Errors
    ///
    /// `Malformed` as [`kept_envelopes`](Self::kept_envelopes), or for a
    /// `checkpoint` that is not key 12's.
    pub fn lacking(&self, space: &EventId, checkpoint: &Event) -> Result<Vec<EventId>, ErrorClass> {
        if checkpoint.id() != self.checkpoint {
            return Err(ErrorClass::Malformed);
        }
        let kept = self.kept_envelopes(space)?;
        Ok(reach(&kept, checkpoint.cuts()).err().unwrap_or_default())
    }

    /// What a newcomer fetches of the frame before the checkpoint's world
    /// (section 3.10, "The checkpoint"): never anything before the
    /// checkpoint but the genesis (the space ID is its hash), the
    /// checkpoints of key 14 and the roots and enrolments its skeleton
    /// cut's slot entries name, which carry the pseudonyms' keys (peers.md,
    /// "Skeleton cuts"). Returns, strictly ascending, those of them `held`
    /// says the newcomer lacks: the genesis; key 12's checkpoint until it
    /// is given as `checkpoint`; then the checkpoints its cuts reach that
    /// key 14 lacks ([`lacking`](Self::lacking)); and `cut_enrolments`,
    /// the event IDs the cut's slot entries name, which the skeleton
    /// layer reads from the cut's body once the newcomer holds it.
    ///
    /// # Errors
    ///
    /// As [`lacking`](Self::lacking).
    pub fn fetches(
        &self,
        space: &EventId,
        checkpoint: Option<&Event>,
        cut_enrolments: &[EventId],
        held: impl Fn(&EventId) -> bool,
    ) -> Result<Vec<EventId>, ErrorClass> {
        let mut out = std::collections::BTreeSet::new();
        out.insert(*space);
        match checkpoint {
            Some(checkpoint) => out.extend(self.lacking(space, checkpoint)?),
            None => {
                out.insert(self.checkpoint);
            }
        }
        out.extend(cut_enrolments.iter().copied());
        Ok(out.into_iter().filter(|id| !held(id)).collect())
    }

    /// [`fetches`](Self::fetches), reading what the newcomer holds so far:
    /// the genesis; key 12's checkpoint until it is given as `checkpoint`;
    /// then the checkpoints its cuts reach that key 14 lacks, and the
    /// skeleton cut its visible key 15 names ([`twin_of`]) until it is given
    /// as `cut`; then the roots and enrolments the cut's slot entries name
    /// ([`cut_enrolments`]), which carry the pseudonyms' keys (units.md,
    /// 3.10 The space snapshot, "The checkpoint"; peers.md, "Skeleton
    /// cuts"). A checkpoint that names no twin (a space with no skeleton)
    /// fetches no cut. Returns, strictly ascending, those `held` says the
    /// newcomer lacks; the newcomer fetches them and asks again until none
    /// is left.
    ///
    /// # Errors
    ///
    /// As [`lacking`](Self::lacking); `Malformed` too for a `cut` given
    /// without the checkpoint, one that is not the cut the checkpoint
    /// names, or one whose body is no cut.
    pub fn fetches_through(
        &self,
        space: &EventId,
        checkpoint: Option<&Event>,
        cut: Option<&Event>,
        held: impl Fn(&EventId) -> bool,
    ) -> Result<Vec<EventId>, ErrorClass> {
        let Some(checkpoint) = checkpoint else {
            if cut.is_some() {
                return Err(ErrorClass::Malformed);
            }
            return self.fetches(space, None, &[], held);
        };
        let twin = twin_of(checkpoint);
        let mut named = Vec::new();
        match (twin, cut) {
            (Some(twin), None) => named.push(twin),
            (Some(twin), Some(cut)) if cut.id() == twin => {
                named.extend(cut_enrolments(cut).ok_or(ErrorClass::Malformed)?);
            }
            (None, None) => {}
            _ => return Err(ErrorClass::Malformed),
        }
        self.fetches(space, Some(checkpoint), &named, held)
    }

    fn insert(&self, map: &mut Map) -> Result<(), ErrorClass> {
        let mut chain: Vec<(EventId, &Vec<u8>)> = Vec::with_capacity(self.cut_chain.len());
        for signed in &self.cut_chain {
            let id = frasil_events::decode(signed)
                .map_err(|_| ErrorClass::Malformed)?
                .id();
            chain.push((id, signed));
        }
        chain.sort_unstable_by_key(|(id, _)| *id);
        map.insert(12, Value::from(self.checkpoint.0));
        map.insert(13, Value::from(self.record_key));
        map.insert(
            14,
            Value::Array(
                chain
                    .into_iter()
                    .map(|(_, signed)| Value::from(signed.as_slice()))
                    .collect(),
            ),
        );
        Ok(())
    }

    /// Keys 12 to 14 of a snapshot's map: none, or key 12 with key 13 and,
    /// optionally, key 14, whose byte strings each decode as an event of
    /// kind 2, strictly ascending by event ID (section 2.11). Key 13 or 14
    /// without key 12, or key 12 without key 13, is `Malformed`.
    fn read(map: &Map) -> Result<Option<Self>, UnitError> {
        let Some(checkpoint) = map.get(&12) else {
            if map.contains_key(&13) || map.contains_key(&14) {
                return Err(ErrorClass::Malformed.into());
            }
            return Ok(None);
        };
        let checkpoint = EventId(checkpoint.as_byte_array()?);
        let record_key = map.get(&13).ok_or(Malformed)?.as_byte_array()?;
        let cut_chain: Vec<Vec<u8>> = match map.get(&14) {
            None => Vec::new(),
            Some(value) => value
                .as_array()?
                .iter()
                .map(|item| item.as_bytes().map(<[u8]>::to_vec))
                .collect::<Result<_, _>>()?,
        };
        // Each a signed space event (kind 2), strictly ascending by ID.
        let chain = cut_chain
            .iter()
            .map(|signed| frasil_events::decode(signed))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ErrorClass::Malformed)?;
        if chain
            .iter()
            .any(|event| event.kind() != frasil_events::kind::SPACE)
            || !chain.windows(2).all(|pair| pair[0].id() < pair[1].id())
        {
            return Err(ErrorClass::Malformed.into());
        }
        Ok(Some(Self {
            checkpoint,
            record_key,
            cut_chain,
        }))
    }
}

fn byte_strings(items: &[Vec<u8>]) -> Value {
    Value::Array(items.iter().map(|b| Value::from(b.as_slice())).collect())
}

fn pairs_value(pairs: &[BodyKey]) -> Value {
    let mut pairs = pairs.to_vec();
    pairs.sort_unstable_by_key(|(id, _)| *id);
    Value::Array(
        pairs
            .into_iter()
            .map(|(id, key)| Value::Array(vec![Value::from(id.0), Value::from(key)]))
            .collect(),
    )
}

impl LogEntry {
    fn to_value(&self) -> Value {
        let mut map = Map::from([
            (1, Value::from(self.space.0)),
            (2, byte_strings(&self.events)),
            (3, stubs_value(&self.stubs)),
            (4, pairs_value(&self.body_keys)),
        ]);
        if !self.proofs.is_empty() {
            map.insert(5, byte_strings(&self.proofs));
        }
        Value::Map(map)
    }

    fn read(value: &Value) -> Result<Self, Malformed> {
        let map = value.as_map()?;
        if map.keys().any(|key| !(1..=5).contains(key)) || !(1..=4).all(|k| map.contains_key(&k)) {
            return Err(Malformed);
        }
        let space = EventId(map[&1].as_byte_array()?);
        let events = map[&2]
            .as_array()?
            .iter()
            .map(|item| item.as_bytes().map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let stubs = read_snapshot_stubs(&map[&3])?;
        let body_keys = read_body_key_pairs(&map[&4], usize::MAX)?;
        let proofs = match map.get(&5) {
            Some(value) => read_proofs(value)?,
            None => Vec::new(),
        };
        Ok(Self {
            space,
            events,
            stubs,
            body_keys,
            proofs,
        })
    }
}

impl StreamEntry {
    fn to_value(&self) -> Value {
        let mut map = Map::from([
            (1, Value::from(self.stream)),
            (2, self.opening.to_value()),
            (3, Value::from(self.object)),
            (4, Value::from(self.key.as_slice())),
            (5, covers_value(&self.covers)),
            (6, ids_value(&self.excluded)),
        ]);
        if !self.supersedes.is_empty() {
            let mut supersedes = self.supersedes.clone();
            supersedes.sort_unstable();
            supersedes.dedup();
            map.insert(
                7,
                Value::Array(supersedes.iter().map(supersession_value).collect()),
            );
        }
        Value::Map(map)
    }

    fn read(value: &Value) -> Result<Self, UnitError> {
        let map = value.as_map()?;
        if map.keys().any(|key| !(1..=7).contains(key))
            || !(1..=6).all(|key| map.contains_key(&key))
        {
            return Err(ErrorClass::Malformed.into());
        }
        let stream_bytes = map[&1].as_bytes()?;
        let opening = Opening::read(&map[&2])?;
        if !stream::is_valid(stream_bytes) || opening.stream()[..] != *stream_bytes {
            return Err(ErrorClass::Malformed.into());
        }
        let object = map[&3].as_byte_array::<LOCATOR_BYTES>()?;
        let key = map[&4].as_bytes()?.to_vec();
        KeyReference::read(&key)?;
        let covers = read_covers(&map[&5])?;
        let excluded = event_ids(&map[&6], 0, MAX_EXCLUDED)?;
        let supersedes = match map.get(&7) {
            Some(value) => read_supersessions(value, None, true)?,
            None => Vec::new(),
        };
        Ok(Self {
            stream: stream_bytes.try_into().map_err(|_| Malformed)?,
            opening,
            object,
            key,
            covers,
            excluded,
            supersedes,
        })
    }
}

/// Key 10, and a log entry's key 5: 1 to 256 equivocation proofs, each the
/// byte string of events.md's array `[type, first, second]`, checked by
/// `verify_proof` once their events are placed.
fn read_proofs(value: &Value) -> Result<Vec<Vec<u8>>, Malformed> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > MAX_PROOFS {
        return Err(Malformed);
    }
    let mut proofs = Vec::with_capacity(items.len());
    for item in items {
        let bytes = item.as_bytes()?;
        let inner = cbor::decode(bytes)?;
        let [kind, first, second] = inner.as_array()? else {
            return Err(Malformed);
        };
        kind.as_unsigned()?;
        first.as_bytes()?;
        second.as_bytes()?;
        proofs.push(bytes.to_vec());
    }
    Ok(proofs)
}

/// What [`SpaceSnapshot::read`] found, with how far its signature is
/// verified (section 3.10, "Using it", step 3). Code that needs a snapshot
/// verified in full takes it from [`verified`](Self::verified), which a
/// provisional one never gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadSnapshot {
    /// Both halves of the sender's signature verify.
    Verified(SpaceSnapshot),
    /// The Ed25519 half verifies; the ML-DSA-65 half waits for keys that
    /// hash to the sender's `kc`, from any source. What it hands is used
    /// provisionally.
    Provisional(SpaceSnapshot),
}

impl ReadSnapshot {
    /// The snapshot, when both halves of its signature verify.
    pub fn verified(self) -> Option<SpaceSnapshot> {
        match self {
            Self::Verified(snapshot) => Some(snapshot),
            Self::Provisional(_) => None,
        }
    }

    /// Whether the ML-DSA-65 half waits for keys.
    pub fn is_provisional(&self) -> bool {
        matches!(self, Self::Provisional(_))
    }

    /// The snapshot, verified in full or not: for what section 3.10 lets a
    /// newcomer use provisionally, and for a device's own snapshot.
    pub fn unverified(&self) -> &SpaceSnapshot {
        match self {
            Self::Verified(snapshot) | Self::Provisional(snapshot) => snapshot,
        }
    }

    /// [`unverified`](Self::unverified), by value.
    pub fn into_unverified(self) -> SpaceSnapshot {
        match self {
            Self::Verified(snapshot) | Self::Provisional(snapshot) => snapshot,
        }
    }
}

impl SpaceSnapshot {
    /// The map's deterministic encoding: arrays in their orders, key 10
    /// left out when there is no proof, keys 12 to 14 when no checkpoint is
    /// in effect at the base. With a checkpoint, key 14 is written, empty
    /// when its cuts reach none.
    ///
    /// # Errors
    ///
    /// `Malformed` if a list event or an envelope of the cut chain does not
    /// decode, whose IDs order keys 7 and 14.
    pub fn encode(&self) -> Result<Vec<u8>, ErrorClass> {
        let mut lists: Vec<(EventId, &Vec<u8>)> = Vec::with_capacity(self.lists.len());
        for signed in &self.lists {
            let id = frasil_events::decode(signed)
                .map_err(|_| ErrorClass::Malformed)?
                .id();
            lists.push((id, signed));
        }
        lists.sort_unstable_by_key(|(id, _)| *id);
        // Key 15 strictly ascending, as every reader requires.
        let mut placed = self.placed.clone();
        placed.sort_unstable();
        placed.dedup();
        if placed.len() > 4096
            || placed
                .iter()
                .any(|id| !lists.iter().any(|(held, _)| held == id))
        {
            return Err(ErrorClass::Malformed);
        }
        let mut logs = self.logs.clone();
        logs.sort_unstable_by_key(|entry| entry.space);
        let mut streams = self.streams.clone();
        streams.sort_unstable_by_key(|entry| entry.stream);
        let mut map = Map::from([
            (1, Value::from(VERSION)),
            (2, Value::from(self.space.0)),
            (3, Value::from(self.sender.to_bytes())),
            (4, ids_value(&self.base)),
            (5, stubs_value(&self.stubs)),
            (6, pairs_value(&self.body_keys)),
            (
                7,
                Value::Array(
                    lists
                        .into_iter()
                        .map(|(_, signed)| Value::from(signed.as_slice()))
                        .collect(),
                ),
            ),
            (
                8,
                Value::Array(logs.iter().map(LogEntry::to_value).collect()),
            ),
            (
                9,
                Value::Array(streams.iter().map(StreamEntry::to_value).collect()),
            ),
            (11, Value::from(self.system_stream)),
        ]);
        if !self.proofs.is_empty() {
            map.insert(10, byte_strings(&self.proofs));
        }
        if !placed.is_empty() {
            map.insert(15, ids_value(&placed));
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.insert(&mut map)?;
        }
        Ok(Value::Map(map).encode())
    }

    /// The signed space snapshot, `[snapshot, signature]`, under the
    /// sender's scheme-2 signature, its ML-DSA-65 half deterministic.
    ///
    /// # Errors
    ///
    /// As [`encode`](Self::encode).
    pub fn sign(&self, signer: &Signer) -> Result<Vec<u8>, ErrorClass> {
        Ok(sign_snapshot(signer, &self.encode()?))
    }

    /// Section 3.10, "Using it", steps 1 to 3: decode the array and the map
    /// with their types, limits and orders (`Malformed`); version 1
    /// (`UnsupportedVersion`); the space is the space joined
    /// (`WrongSpace`); the Ed25519 half verifies under the sender's `ed`
    /// (`BadSignature`); the ML-DSA-65 half verifies once `keys` gives keys
    /// that hash to the sender's `kc` (crypto.md, "Keys by their hash"),
    /// and until then the snapshot is provisional.
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `WrongSpace` or `BadSignature`.
    pub fn read(
        signed: &[u8],
        space: &EventId,
        keys: &impl KeySource,
    ) -> Result<ReadSnapshot, UnitError> {
        // 1. The array and the map.
        let outer = cbor::decode(signed)?;
        let [snapshot, signature] = outer.as_array()? else {
            return Err(ErrorClass::Malformed.into());
        };
        let snapshot = snapshot.as_bytes()?;
        let signature = signature.as_bytes()?;
        if signature.len() != SCHEME2_SIGNATURE {
            return Err(ErrorClass::Malformed.into());
        }
        let decoded = Self::decode(snapshot)?;
        // 2. The space joined.
        if decoded.space != *space {
            return Err(UnitClass::WrongSpace.into());
        }
        // 3. The Ed25519 half, then the ML-DSA-65 half once keys that hash
        //    to kc are held.
        let sender = decoded.sender;
        let mut tbs = SPACE_SNAPSHOT.to_vec();
        tbs.extend_from_slice(snapshot);
        if !ed25519_verify_strict(
            &sender.ed.0,
            &hybrid_ed25519_message(&sender.ed, &tbs),
            &signature[..ED25519_SIGNATURE],
        ) {
            return Err(ErrorClass::BadSignature.into());
        }
        match keys.hybrid_keys(&sender.kc) {
            None => Ok(ReadSnapshot::Provisional(decoded)),
            Some(held) => {
                let signed = Signed {
                    scheme: 2,
                    ed: &sender.ed,
                    kc: &sender.kc,
                    tbs: &tbs,
                    signature,
                };
                verify_mldsa_steps(&signed, Some(&held)).map_err(|_| ErrorClass::BadSignature)?;
                Ok(ReadSnapshot::Verified(decoded))
            }
        }
    }

    /// Reads a space snapshot's map, without its signature: step 1 of
    /// "Using it" on the map, its types, limits and orders, and its
    /// version.
    ///
    /// # Errors
    ///
    /// `Malformed` or `UnsupportedVersion`.
    pub fn decode(snapshot: &[u8]) -> Result<Self, UnitError> {
        let value = cbor::decode(snapshot)?;
        let map = value.as_map()?;
        let version = map.get(&1).ok_or(Malformed)?.as_unsigned()?;
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        if map.keys().any(|key| !(1..=15).contains(key))
            || ![1, 2, 3, 4, 5, 6, 7, 8, 9, 11]
                .iter()
                .all(|key| map.contains_key(key))
        {
            return Err(ErrorClass::Malformed.into());
        }
        // Keys 12 to 14: the checkpoint in effect at the base, its record's
        // object key and the checkpoints its cuts reach.
        let checkpoint = SnapshotCheckpoint::read(map)?;
        let system_bytes = map[&11].as_bytes()?;
        if !stream::is_valid(system_bytes) {
            return Err(ErrorClass::Malformed.into());
        }
        let proofs = match map.get(&10) {
            Some(value) => read_proofs(value)?,
            None => Vec::new(),
        };
        let snapshot_space = EventId(map[&2].as_byte_array()?);
        let sender = Signatory::from_bytes(map[&3].as_bytes()?)?;
        let base = event_ids(&map[&4], 1, MAX_HEADS)?;
        let stubs = read_snapshot_stubs(&map[&5])?;
        let body_keys = read_body_key_pairs(&map[&6], usize::MAX)?;
        let lists: Vec<Vec<u8>> = map[&7]
            .as_array()?
            .iter()
            .map(|item| item.as_bytes().map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let list_ids = lists
            .iter()
            .map(|signed| frasil_events::decode(signed).map(|event| event.id()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ErrorClass::Malformed)?;
        if !list_ids.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ErrorClass::Malformed.into());
        }
        let placed = match map.get(&15) {
            Some(value) => event_ids(value, 1, 4096)?,
            None => Vec::new(),
        };
        if placed.iter().any(|id| !list_ids.contains(id)) {
            return Err(ErrorClass::Malformed.into());
        }
        let logs = map[&8]
            .as_array()?
            .iter()
            .map(LogEntry::read)
            .collect::<Result<Vec<_>, _>>()?;
        let streams = map[&9]
            .as_array()?
            .iter()
            .map(StreamEntry::read)
            .collect::<Result<Vec<_>, _>>()?;
        if !logs.windows(2).all(|pair| pair[0].space < pair[1].space)
            || !streams
                .windows(2)
                .all(|pair| pair[0].stream < pair[1].stream)
        {
            return Err(ErrorClass::Malformed.into());
        }
        Ok(Self {
            space: snapshot_space,
            sender,
            base,
            stubs,
            body_keys,
            lists,
            placed,
            logs,
            streams,
            proofs,
            system_stream: system_bytes.try_into().map_err(|_| Malformed)?,
            checkpoint,
        })
    }
}

/// Signs a space snapshot's map bytes: `[snapshot, signature]`, the
/// signature over `"frasil/space-snapshot/v1" || snapshot` under scheme 2.
pub fn sign_snapshot(signer: &Signer, snapshot: &[u8]) -> Vec<u8> {
    let mut tbs = SPACE_SNAPSHOT.to_vec();
    tbs.extend_from_slice(snapshot);
    let signature = signer.sign(Scheme::Hybrid, &tbs);
    Value::Array(vec![Value::from(snapshot), Value::from(signature)]).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(supersedes: Vec<Supersession>) -> StreamEntry {
        let opening = Opening::with_salt("frasil:blobs", [1; 16]);
        StreamEntry {
            stream: opening.stream(),
            opening,
            object: [2; 64],
            key: frasil_keys::RotationSet::single(EventId([3; 32])).encode(),
            covers: Vec::new(),
            excluded: Vec::new(),
            supersedes,
        }
    }

    /// Key 7 (units.md, 2.11 The space snapshot): two-element
    /// supersessions, strictly ascending, absent when there are none.
    #[test]
    fn a_stream_entry_carries_its_supersessions() {
        let pairs = vec![
            Supersession {
                successor: [5; 64],
                listing: None,
                predecessor: [4; 64],
            },
            Supersession {
                successor: [6; 64],
                listing: None,
                predecessor: [4; 64],
            },
        ];
        for supersedes in [Vec::new(), pairs] {
            let entry = entry(supersedes);
            let value = entry.to_value();
            assert_eq!(
                value.as_map().unwrap().contains_key(&7),
                !entry.supersedes.is_empty()
            );
            assert_eq!(StreamEntry::read(&value).unwrap(), entry);
        }
        // Three elements, an empty array or a repeat is Malformed.
        let bad = [
            Value::Array(vec![Value::Array(vec![
                Value::from([5u8; 64]),
                Value::from([7u8; 32]),
                Value::from([4u8; 64]),
            ])]),
            Value::Array(Vec::new()),
            Value::Array(vec![
                Value::Array(vec![Value::from([5u8; 64]), Value::from([4u8; 64])]),
                Value::Array(vec![Value::from([5u8; 64]), Value::from([4u8; 64])]),
            ]),
        ];
        for key_7 in bad {
            let Value::Map(mut map) = entry(Vec::new()).to_value() else {
                unreachable!()
            };
            map.insert(7, key_7);
            assert!(StreamEntry::read(&Value::Map(map)).is_err());
        }
        let Value::Map(mut map) = entry(Vec::new()).to_value() else {
            unreachable!()
        };
        map.insert(8, Value::from(1u64));
        assert!(StreamEntry::read(&Value::Map(map)).is_err());
    }
}
