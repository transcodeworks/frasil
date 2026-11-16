//! A log's state at rest, for a replica's own records: every placed,
//! witnessed and pending event with what placement computed for it, so that
//! a replica reopens a log without decoding or placing any event again
//! (events.md, "Placement and order").
//!
//! The encoding is deterministic CBOR, positional, version first:
//!
//! ```text
//! state   = [1, id, witnessed, [* node], [* stub], [* witness],
//!            [* [id, [* id]]], [* [event, [* id]]], ? [* event], ? [+ id],
//!            ? [+ [id, height]]]
//! node    = [event, height, exact, signature, [* child]]
//! witness = [event, height, exact]
//! stub    = [id, author, seq, height, kind, disputed, ? [+ cut]]
//! event   = [kind, log, ed, kc, seq, prev, [* parent], body, scheme, signature,
//!            ? [+ cut]]
//! ```
//!
//! `id`, `author` (a device ID), `ed`, `kc`, a child and a parent are
//! 32-byte strings, and so is a cut; `log` and
//! `prev` are 32 bytes, or empty when absent; `exact`, `witnessed` and
//! `disputed` are 0 or 1; `signature` (in a node) is 0 verified, 1
//! `NoHybridKey`, 2 `BadSignature`; `scheme` is a scheme's code. Nodes are
//! in canonical order, everything else in ID order. An event's cuts, strictly
//! ascending, are its eleventh item, present exactly when it has any. The dependents list
//! (the sixth item) and the pending list (the seventh) give each ID once.
//! A stub's cuts, strictly ascending, are its seventh item, present exactly
//! when it carries any. The ninth item holds the checkpoint envelopes the
//! log keeps ([`Log::keep_envelope`]), strictly ascending by ID; the tenth
//! the IDs of the events it dropped ([`Log::mark_dropped`]), strictly
//! ascending. The tenth is present exactly when there is one such ID; the
//! ninth when the tenth is, or when there is one kept envelope, and it is
//! empty only when the tenth is present. The eleventh holds the heights
//! kept of dropped events ([`Log::mark_dropped_at`]), strictly ascending by
//! ID, each among the tenth's IDs and from 1; it is present exactly when
//! there is one.
//!
//! An event's map is its envelope's one encoding, which is the map that
//! [`decode`](crate::decode()) read when the event arrived, so the state
//! keeps the fields and not the map, and the ID is computed again from
//! them. Nothing is verified again: the state is the replica's own, and it
//! keeps only events placement accepted. The derived indexes (canonical
//! order, heads, chains and what each missing parent holds up) are rebuilt
//! from the nodes and the pending events.

use crate::cuts::Cuts;
use crate::decode::{Event, VerifiedEvent};
use crate::envelope::{Envelope, EventId};
use crate::log::{Log, Node, SignatureState, Stub, StubEntry, Waiting, Witness};
use frasil_base::cbor::{self, Reader};
use frasil_crypto::device::{DeviceId, IdentityKey, KeysCommitment};
use frasil_crypto::schemes::Scheme;
use std::collections::{BTreeMap, BTreeSet};

/// The version this crate writes and reads.
pub const VERSION: u64 = 1;

fn flag(out: &mut Vec<u8>, value: bool) {
    cbor::unsigned(out, u64::from(value));
}

fn optional_id(out: &mut Vec<u8>, id: Option<EventId>) {
    match id {
        Some(id) => cbor::bytes(out, &id.0),
        None => cbor::bytes(out, &[]),
    }
}

fn ids<'a>(out: &mut Vec<u8>, ids: impl ExactSizeIterator<Item = &'a EventId>) {
    cbor::array_head(out, ids.len());
    for id in ids {
        cbor::bytes(out, &id.0);
    }
}

/// Writes an event's fields and signature.
fn event(out: &mut Vec<u8>, event: &Event) {
    let envelope = event.fields();
    cbor::array_head(out, if envelope.cuts.is_empty() { 10 } else { 11 });
    cbor::unsigned(out, u64::from(envelope.kind));
    optional_id(out, envelope.log);
    cbor::bytes(out, &envelope.ed.0);
    cbor::bytes(out, &envelope.kc.0);
    cbor::unsigned(out, envelope.seq);
    optional_id(out, envelope.prev);
    ids(out, envelope.parents.iter());
    cbor::bytes(out, &envelope.body);
    cbor::unsigned(out, u64::from(envelope.scheme.code()));
    cbor::bytes(out, event.signature());
    if !envelope.cuts.is_empty() {
        ids(out, envelope.cuts.iter());
    }
}

fn signature_code(state: SignatureState) -> u64 {
    match state {
        SignatureState::Verified => 0,
        SignatureState::NoHybridKey => 1,
        SignatureState::BadSignature => 2,
    }
}

fn read_flag(reader: &mut Reader<'_>) -> Option<bool> {
    match reader.unsigned().ok()? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

fn read_id(reader: &mut Reader<'_>) -> Option<EventId> {
    reader.byte_array::<32>().ok().map(EventId)
}

fn read_optional_id(reader: &mut Reader<'_>) -> Option<Option<EventId>> {
    let bytes = reader.bytes().ok()?;
    match bytes.len() {
        0 => Some(None),
        32 => Some(Some(EventId(bytes.try_into().ok()?))),
        _ => None,
    }
}

/// Reads an array of IDs, strictly ascending when `ascending`.
fn read_ids(reader: &mut Reader<'_>, ascending: bool) -> Option<Vec<EventId>> {
    let count = reader.array_len().ok()?;
    let mut out: Vec<EventId> = Vec::with_capacity(count.min(1 << 12));
    for _ in 0..count {
        let id = read_id(reader)?;
        if ascending && out.last().is_some_and(|last| *last >= id) {
            return None;
        }
        out.push(id);
    }
    Some(out)
}

fn read_event(reader: &mut Reader<'_>) -> Option<Event> {
    let items = reader.array_len().ok()?;
    if items != 10 && items != 11 {
        return None;
    }
    let kind = u8::try_from(reader.unsigned().ok()?).ok()?;
    let log = read_optional_id(reader)?;
    let ed = IdentityKey(reader.byte_array::<32>().ok()?);
    let kc = KeysCommitment(reader.byte_array::<32>().ok()?);
    let seq = reader.unsigned().ok()?;
    let prev = read_optional_id(reader)?;
    let parents = read_ids(reader, true)?;
    let body = reader.bytes().ok()?.to_vec();
    let scheme = Scheme::from_code(reader.unsigned().ok()?).ok()?;
    let signature = reader.bytes().ok()?.to_vec();
    let cuts = if items == 11 {
        let cuts = read_ids(reader, true)?;
        if cuts.is_empty() || cuts.len() > crate::cuts::MAX_CUTS || log.is_none() {
            return None;
        }
        cuts
    } else {
        Vec::new()
    };
    let envelope = Envelope {
        kind,
        log,
        ed,
        kc,
        seq,
        prev,
        parents,
        cuts,
        body,
        scheme,
    };
    Some(Event::from_parts(envelope, signature))
}

impl Log {
    /// The log's state at rest (the module's encoding). It keeps a stub as
    /// a peer adds one ([`add_stub`](Log::add_stub)): reopened, every stub
    /// is confirmed and none provisional.
    pub fn encode_state(&self) -> Vec<u8> {
        let size: usize = self
            .nodes
            .values()
            .map(|node| node.event.signed_len() + 48 * node.children.len() + 64)
            .chain(
                self.pending
                    .values()
                    .map(|waiting| waiting.event.signed_len() + 64),
            )
            .sum();
        let mut out = Vec::with_capacity(size + 128);
        let items = if !self.dropped_heights.is_empty() {
            11
        } else if !self.dropped.is_empty() {
            10
        } else if !self.kept.is_empty() {
            9
        } else {
            8
        };
        cbor::array_head(&mut out, items);
        cbor::unsigned(&mut out, VERSION);
        cbor::bytes(&mut out, &self.id.0);
        flag(&mut out, self.witnessed);
        cbor::array_head(&mut out, self.nodes.len());
        for (_, id) in &self.order {
            let node = &self.nodes[id];
            cbor::array_head(&mut out, 5);
            event(&mut out, &node.event);
            cbor::unsigned(&mut out, node.height);
            flag(&mut out, node.exact);
            cbor::unsigned(&mut out, signature_code(node.signature));
            ids(&mut out, node.children.iter());
        }
        cbor::array_head(&mut out, self.stubs.len());
        for (id, entry) in &self.stubs {
            let cuts = entry.stub.cuts;
            cbor::array_head(&mut out, if cuts.is_empty() { 6 } else { 7 });
            cbor::bytes(&mut out, &id.0);
            cbor::bytes(&mut out, &entry.stub.author.0);
            cbor::unsigned(&mut out, entry.stub.seq);
            cbor::unsigned(&mut out, entry.stub.height);
            cbor::unsigned(&mut out, u64::from(entry.stub.kind));
            flag(&mut out, entry.disputed);
            if !cuts.is_empty() {
                ids(&mut out, cuts.iter());
            }
        }
        cbor::array_head(&mut out, self.witnesses.len());
        for witness in self.witnesses.values() {
            cbor::array_head(&mut out, 3);
            event(&mut out, &witness.event);
            cbor::unsigned(&mut out, witness.height);
            flag(&mut out, witness.exact);
        }
        cbor::array_head(&mut out, self.dependents.len());
        for (id, dependents) in &self.dependents {
            cbor::array_head(&mut out, 2);
            cbor::bytes(&mut out, &id.0);
            ids(&mut out, dependents.iter());
        }
        cbor::array_head(&mut out, self.pending.len());
        for waiting in self.pending.values() {
            cbor::array_head(&mut out, 2);
            event(&mut out, &waiting.event);
            ids(&mut out, waiting.missing.iter());
        }
        if items >= 9 {
            cbor::array_head(&mut out, self.kept.len());
            for kept in self.kept.values() {
                event(&mut out, kept);
            }
        }
        if items >= 10 {
            ids(&mut out, self.dropped.iter());
        }
        if items == 11 {
            cbor::array_head(&mut out, self.dropped_heights.len());
            for (id, height) in &self.dropped_heights {
                cbor::array_head(&mut out, 2);
                cbor::bytes(&mut out, &id.0);
                cbor::unsigned(&mut out, *height);
            }
        }
        out
    }

    /// A log from its state at rest, if `bytes` are one state of this
    /// version in its one encoding, whose genesis is among its nodes and
    /// whose events are each held once.
    pub fn decode_state(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let items = reader.array_len().ok()?;
        if !(8..=11).contains(&items) || reader.unsigned().ok()? != VERSION {
            return None;
        }
        let id = read_id(&mut reader)?;
        let witnessed = read_flag(&mut reader)?;
        let mut log = Self {
            id,
            nodes: BTreeMap::new(),
            order: BTreeSet::new(),
            heads: BTreeSet::new(),
            chains: BTreeMap::new(),
            stubs: BTreeMap::new(),
            on_unplaced: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            witnessed,
            dependents: BTreeMap::new(),
            pending: BTreeMap::new(),
            waiters: BTreeMap::new(),
            placed: Vec::new(),
            frame: BTreeSet::new(),
            revision: 0,
            verdicts: crate::log::HybridVerdicts::default(),
            kept: BTreeMap::new(),
            dropped: BTreeSet::new(),
            dropped_heights: BTreeMap::new(),
        };
        let count = reader.array_len().ok()?;
        let mut last: Option<(u64, EventId)> = None;
        for _ in 0..count {
            if reader.array_len().ok()? != 5 {
                return None;
            }
            let event = read_event(&mut reader)?;
            let height = reader.unsigned().ok()?;
            let exact = read_flag(&mut reader)?;
            let signature = match reader.unsigned().ok()? {
                0 => SignatureState::Verified,
                1 => SignatureState::NoHybridKey,
                2 => SignatureState::BadSignature,
                _ => return None,
            };
            let children = read_ids(&mut reader, false)?;
            let event_id = event.id();
            if event.log_id() != id || last.is_some_and(|last| last >= (height, event_id)) {
                return None;
            }
            last = Some((height, event_id));
            log.order.insert((height, event_id));
            log.placed.push(event_id);
            if event.kind() != crate::kind::UNIT {
                log.frame.insert((height, event_id));
            }
            log.chains
                .entry(*event.author())
                .or_default()
                .insert((event.seq(), event_id));
            log.nodes.insert(
                event_id,
                Node {
                    verified: (signature == SignatureState::Verified)
                        .then(|| VerifiedEvent::from_rest(event.clone())),
                    event,
                    height,
                    exact,
                    signature,
                    children,
                },
            );
        }
        if !log
            .nodes
            .get(&id)
            .is_some_and(|node| node.event.is_genesis())
        {
            return None;
        }
        let parents: BTreeSet<EventId> = log
            .nodes
            .values()
            .flat_map(|node| node.event.parents().iter().copied())
            .collect();
        log.heads = log
            .nodes
            .keys()
            .filter(|id| !parents.contains(id))
            .copied()
            .collect();
        for (child, node) in &log.nodes {
            for parent in node.event.parents() {
                if !log.nodes.contains_key(parent) {
                    log.on_unplaced.entry(*parent).or_default().insert(*child);
                }
            }
        }
        let count = reader.array_len().ok()?;
        let mut last: Option<EventId> = None;
        for _ in 0..count {
            let stub_items = reader.array_len().ok()?;
            if stub_items != 6 && stub_items != 7 {
                return None;
            }
            let stub_id = read_id(&mut reader)?;
            if last.is_some_and(|last| last >= stub_id) {
                return None;
            }
            last = Some(stub_id);
            let mut stub = Stub {
                id: stub_id,
                author: DeviceId(reader.byte_array::<32>().ok()?),
                seq: reader.unsigned().ok()?,
                height: reader.unsigned().ok()?,
                kind: u8::try_from(reader.unsigned().ok()?).ok()?,
                cuts: Cuts::NONE,
            };
            let disputed = read_flag(&mut reader)?;
            if stub_items == 7 {
                let cuts = read_ids(&mut reader, true)?;
                if cuts.is_empty() {
                    return None;
                }
                stub.cuts = Cuts::new(&cuts)?;
            }
            log.stubs.insert(
                stub_id,
                StubEntry {
                    stub,
                    disputed,
                    confirmed: true,
                    provisional: None,
                },
            );
        }
        let count = reader.array_len().ok()?;
        let mut last: Option<EventId> = None;
        for _ in 0..count {
            if reader.array_len().ok()? != 3 {
                return None;
            }
            let event = read_event(&mut reader)?;
            let height = reader.unsigned().ok()?;
            let exact = read_flag(&mut reader)?;
            let event_id = event.id();
            if event.log_id() != id || last.is_some_and(|last| last >= event_id) {
                return None;
            }
            last = Some(event_id);
            log.witnesses.insert(
                event_id,
                Witness {
                    event,
                    height,
                    exact,
                },
            );
        }
        let count = reader.array_len().ok()?;
        let mut last: Option<EventId> = None;
        for _ in 0..count {
            if reader.array_len().ok()? != 2 {
                return None;
            }
            let parent = read_id(&mut reader)?;
            if last.is_some_and(|last| last >= parent) {
                return None;
            }
            last = Some(parent);
            let dependents = read_ids(&mut reader, true)?;
            log.dependents
                .insert(parent, dependents.into_iter().collect());
        }
        let count = reader.array_len().ok()?;
        let mut last: Option<EventId> = None;
        for _ in 0..count {
            if reader.array_len().ok()? != 2 {
                return None;
            }
            let event = read_event(&mut reader)?;
            let missing = read_ids(&mut reader, true)?;
            let event_id = event.id();
            if event.log_id() != id
                || last.is_some_and(|last| last >= event_id)
                || log.nodes.contains_key(&event_id)
                || missing.is_empty()
            {
                return None;
            }
            last = Some(event_id);
            for parent in &missing {
                log.waiters.entry(*parent).or_default().insert(event_id);
            }
            log.pending.insert(
                event_id,
                Waiting {
                    event,
                    missing: missing.into_iter().collect(),
                },
            );
        }
        if items >= 9 {
            let count = reader.array_len().ok()?;
            if count == 0 && items == 9 {
                return None;
            }
            let mut last: Option<EventId> = None;
            for _ in 0..count {
                let event = read_event(&mut reader)?;
                let event_id = event.id();
                if event.log_id() != id
                    || !crate::cuts::may_be_checkpoint(&event)
                    || last.is_some_and(|last| last >= event_id)
                {
                    return None;
                }
                last = Some(event_id);
                log.kept.insert(event_id, event);
            }
        }
        if items >= 10 {
            let dropped = read_ids(&mut reader, true)?;
            if dropped.is_empty()
                || dropped.iter().any(|id| {
                    log.nodes.contains_key(id)
                        || log.witnesses.contains_key(id)
                        || log.kept.contains_key(id)
                })
            {
                return None;
            }
            log.dropped = dropped.into_iter().collect();
        }
        if items == 11 {
            let count = reader.array_len().ok()?;
            if count == 0 {
                return None;
            }
            for _ in 0..count {
                if reader.array_len().ok()? != 2 {
                    return None;
                }
                let dropped = read_id(&mut reader)?;
                let height = reader.unsigned().ok()?;
                if height == 0
                    || !log.dropped.contains(&dropped)
                    || log
                        .dropped_heights
                        .last_key_value()
                        .is_some_and(|(last, _)| *last >= dropped)
                {
                    return None;
                }
                log.dropped_heights.insert(dropped, height);
            }
        }
        reader.finish().ok()?;
        Some(log)
    }
}

impl crate::chains::ForkPoints {
    /// The fork points at rest: `[* [author, point]]`, by author's device
    /// ID, in
    /// deterministic CBOR.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let points: Vec<(&DeviceId, u64)> = self.iter().collect();
        cbor::array_head(&mut out, points.len());
        for (author, point) in points {
            cbor::array_head(&mut out, 2);
            cbor::bytes(&mut out, &author.0);
            cbor::unsigned(&mut out, point);
        }
        out
    }

    /// Fork points from [`encode`](Self::encode)'s bytes: authors strictly
    /// ascending, each point at least 1.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let count = reader.array_len().ok()?;
        let mut points = BTreeMap::new();
        let mut last: Option<DeviceId> = None;
        for _ in 0..count {
            if reader.array_len().ok()? != 2 {
                return None;
            }
            let author = DeviceId(reader.byte_array::<32>().ok()?);
            let point = reader.unsigned().ok()?;
            if point == 0 || last.is_some_and(|last| last >= author) {
                return None;
            }
            last = Some(author);
            points.insert(author, point);
        }
        reader.finish().ok()?;
        Some(Self::from_points(points))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode;
    use frasil_crypto::schemes::Signer;

    fn signer(n: u8) -> Signer {
        Signer::from_seeds(&[n; 32], &[n.wrapping_add(100); 32], None)
    }

    fn sign(signer: &Signer, envelope: &mut Envelope) -> Event {
        envelope.ed = *signer.identity_key();
        envelope.kc = *signer.kc();
        decode(&envelope.sign(signer)).expect("a valid event")
    }

    fn genesis(signer: &Signer) -> Event {
        sign(
            signer,
            &mut Envelope {
                kind: 2,
                log: None,
                ed: IdentityKey([0; 32]),
                kc: KeysCommitment([0; 32]),
                seq: 1,
                prev: None,
                parents: Vec::new(),
                cuts: Vec::new(),
                body: vec![1, 2, 3],
                scheme: Scheme::Hybrid,
            },
        )
    }

    fn child(
        signer: &Signer,
        log: EventId,
        seq: u64,
        parents: Vec<EventId>,
        prev: Option<EventId>,
    ) -> Event {
        sign(
            signer,
            &mut Envelope {
                kind: 4,
                log: Some(log),
                ed: IdentityKey([0; 32]),
                kc: KeysCommitment([0; 32]),
                seq,
                prev,
                parents,
                cuts: Vec::new(),
                body: vec![seq as u8],
                scheme: Scheme::Ed25519,
            },
        )
    }

    #[test]
    fn a_log_reads_back_from_its_state() {
        let alice = signer(1);
        let bob = signer(2);
        let genesis = genesis(&alice);
        let id = genesis.id();
        let mut log = Log::new(genesis).unwrap();
        let a2 = child(&alice, id, 2, vec![id], Some(id));
        let b1 = child(&bob, id, 1, vec![id], None);
        let a3 = child(&alice, id, 3, vec![a2.id(), b1.id()], Some(a2.id()));
        // a3 waits for a2 and b1; a stub stands in for an absent parent.
        log.place(a3.clone()).unwrap();
        let stubbed = EventId([7; 32]);
        let b2 = child(&bob, id, 2, vec![b1.id(), stubbed], Some(b1.id()));
        log.place(b2).unwrap();
        log.place(a2).unwrap();
        log.add_stub(Stub {
            id: stubbed,
            author: DeviceId([9; 32]),
            seq: 4,
            height: 1,
            kind: 4,
            cuts: Cuts::NONE,
        });
        let pending = child(&bob, id, 9, vec![EventId([8; 32])], Some(EventId([8; 32])));
        log.place(pending).unwrap();
        log.place(b1).unwrap();
        let state = log.encode_state();
        let back = Log::decode_state(&state).expect("its own state reads");
        assert_eq!(back.encode_state(), state);
        assert_eq!(back.canonical(), log.canonical());
        assert_eq!(back.heads(), log.heads());
        assert_eq!(back.wanted(), log.wanted());
        assert_eq!(back.pending().count(), 1);
        assert_eq!(back.chain(alice.device_id()), log.chain(alice.device_id()));
        assert!(back.contains(a3.id()));
        // One byte more, or one less, is refused.
        let mut longer = state.clone();
        longer.push(0);
        assert!(Log::decode_state(&longer).is_none());
        assert!(Log::decode_state(&state[..state.len() - 1]).is_none());
        // Every byte changed, or the state cut there: no panic, and what
        // reads is the one encoding of what it returns.
        for at in 0..state.len() {
            for value in [0u8, 1, 0x18, 0x40, 0x80, 0xff, state[at] ^ 1] {
                let mut changed = state.clone();
                changed[at] = value;
                for bytes in [&changed[..], &changed[..at]] {
                    if let Some(log) = Log::decode_state(bytes) {
                        assert_eq!(log.encode_state(), bytes);
                        let _ = log.fork_points(|_| true);
                        let _ = log.heads();
                    }
                }
            }
        }
    }

    #[test]
    fn cuts_read_back() {
        let alice = signer(1);
        let genesis = genesis(&alice);
        let id = genesis.id();
        let mut log = Log::new(genesis).unwrap();
        let without = child(&alice, id, 2, vec![id], Some(id));
        log.place(without.clone()).unwrap();
        let mut envelope = without.fields().clone();
        envelope.seq = 3;
        envelope.prev = Some(without.id());
        envelope.parents = vec![without.id()];
        envelope.cuts = vec![EventId([0xcc; 32]), without.id()];
        let with = sign(&alice, &mut envelope);
        assert_eq!(with.cuts().len(), 2);
        log.place(with.clone()).unwrap();
        let state = log.encode_state();
        let back = Log::decode_state(&state).expect("its own state reads");
        assert_eq!(back.encode_state(), state);
        assert_eq!(back.event(with.id()), Some(&with));
        assert_eq!(back.event(without.id()).unwrap().cuts(), &[]);
    }

    #[test]
    fn stub_cuts_and_kept_envelopes_read_back() {
        let alice = signer(1);
        let genesis = genesis(&alice);
        let id = genesis.id();
        let mut log = Log::new(genesis).unwrap();
        // A checkpoint's envelope, kept beyond the events placed.
        let checkpoint = sign(
            &alice,
            &mut Envelope {
                kind: 2,
                log: Some(id),
                ed: IdentityKey([0; 32]),
                kc: KeysCommitment([0; 32]),
                seq: 2,
                prev: Some(id),
                parents: vec![id],
                cuts: Vec::new(),
                body: vec![2],
                scheme: Scheme::Hybrid,
            },
        );
        let state = log.encode_state();
        assert!(log.keep_envelope(checkpoint.clone()).unwrap());
        assert!(!log.keep_envelope(checkpoint.clone()).unwrap());
        // A unit is no checkpoint, and the genesis is none either.
        let unit = child(&alice, id, 2, vec![id], Some(id));
        assert!(log.keep_envelope(unit).is_err());
        // A stub that carries cuts, and one that carries none.
        let cut = Cuts::new(&[checkpoint.id()]).unwrap();
        log.add_stub(Stub {
            id: EventId([5; 32]),
            author: DeviceId([9; 32]),
            seq: 3,
            height: 2,
            kind: 4,
            cuts: cut,
        });
        log.add_stub(Stub {
            id: EventId([6; 32]),
            author: DeviceId([9; 32]),
            seq: 4,
            height: 3,
            kind: 4,
            cuts: Cuts::NONE,
        });
        let with = log.encode_state();
        assert_ne!(with, state);
        let back = Log::decode_state(&with).expect("its own state reads");
        assert_eq!(back.encode_state(), with);
        assert_eq!(back.kept_envelope_of(checkpoint.id()), Some(&checkpoint));
        assert_eq!(back.stub(EventId([5; 32])).unwrap().cuts, cut);
        assert!(back.stub(EventId([6; 32])).unwrap().cuts.is_empty());
        // Dropped again, the log writes the state without a ninth item.
        let mut dropped = back.clone();
        assert_eq!(
            dropped.drop_kept_envelope(checkpoint.id()),
            Some(checkpoint)
        );
        let without = dropped.encode_state();
        assert_eq!(without[0], 0x88);
        assert_eq!(with[0], 0x89);
        assert!(Log::decode_state(&without).is_some());
    }

    #[test]
    fn fork_points_read_back() {
        let points = crate::chains::ForkPoints::from_points(
            [(DeviceId([1; 32]), 3), (DeviceId([2; 32]), 1)].into(),
        );
        let bytes = points.encode();
        assert_eq!(crate::chains::ForkPoints::decode(&bytes), Some(points));
        assert!(crate::chains::ForkPoints::decode(&[0x81, 0x82, 0x40, 0x01]).is_none());
    }
}
