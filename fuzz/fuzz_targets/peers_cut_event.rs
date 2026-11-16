//! frasil-peers' skeleton cuts on arbitrary bytes (peers.md, "Skeleton
//! cuts" and "Truncation"): decoding a cut's body and a cut event, then
//! judging a cut in a small space.
//!
//! The space is fixed: a founder, its pseudonym's root, and nothing else;
//! as the input says, the pseudonym grants one administrator slot at a rank
//! the input picks, and the founder names the change. The input picks the
//! cut: its raw body, or one carrying the slots of the skeleton of its
//! past, with an epoch, a slot count, the slots' ranks and its other fields
//! taken from the input. The founder's pseudonym signs it, a checkpoint
//! names it, and, as the input says, the pseudonym votes after it and a
//! second cut follows. The peer judges every cut it holds on its own past,
//! finds the chain of cuts in effect and the skeleton from it, plans a
//! truncation under the last cut in effect and judges again over what it
//! would keep. Nothing panics; a cut is valid or void with a class of its
//! checks.
#![no_main]

use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_crypto::fixtures::{FixtureKeys, fixture_mldsa_seed};
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::{Envelope, EventId, Log, Placement, decode, kind};
use frasil_keys::body::visible_key;
use frasil_peers::PeersClass;
use frasil_peers::body::{ChangeEffect, Cut, GrantMap, StorageBody};
use frasil_peers::cut::{PeerCuts, read_cut};
use frasil_peers::derive::{SlotKeys, root_statement};
use frasil_peers::limits::{MAX_CUT_SLOTS, SEALED_TOKEN_BYTES};
use frasil_peers::skeleton::Status;
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

/// The fixed space: its log, the founder and the founder's pseudonym; and
/// the keys of the administrator slot a change may grant, its Ed25519 key
/// and the SHA-256 of its ML-DSA-65 key.
struct Space {
    log: Log,
    founder: Signer,
    pseudonym: Signer,
    slot: ([u8; 32], [u8; 32]),
}

static SPACE: LazyLock<Space> = LazyLock::new(|| {
    let founder = FixtureKeys::from_identity_seed(&[1; 32]).signer();
    let pseudonym = Signer::from_seeds(&[2; 32], &fixture_mldsa_seed(&[2; 32]), None);
    let genesis = Envelope {
        kind: kind::SPACE,
        log: None,
        ed: *founder.identity_key(),
        kc: *founder.kc(),
        seq: 1,
        prev: None,
        parents: Vec::new(),
        cuts: Vec::new(),
        body: Value::Map(Map::new()).encode(),
        scheme: Scheme::Hybrid,
    }
    .sign(&founder);
    let mut log = Log::new(decode(&genesis).expect("a genesis")).expect("a log");
    let space = log.id();
    let statement = root_statement(&space, pseudonym.device_id());
    let root = StorageBody::Root {
        twin: [3; 32],
        mldsa: pseudonym.mldsa_public().to_vec(),
        duel_policy: 0,
        founder_mldsa: founder.mldsa_public().to_vec(),
        founder_signature: founder.sign(Scheme::Hybrid, &statement),
        founder_xwing: founder.keys().xwing().expect("an X-Wing key").to_vec(),
    };
    let root = Envelope {
        kind: kind::STORAGE,
        log: Some(space),
        ed: *pseudonym.identity_key(),
        kc: *pseudonym.kc(),
        seq: 1,
        prev: None,
        parents: vec![space],
        cuts: Vec::new(),
        body: root.encode(),
        scheme: Scheme::Hybrid,
    }
    .sign(&pseudonym);
    let placed = log
        .place(decode(&root).expect("a root"))
        .expect("of the log");
    assert!(matches!(placed, Placement::Placed(_)));
    let keys = SlotKeys::from_token(&[4; 32]);
    Space {
        log,
        founder,
        pseudonym,
        slot: (*keys.ed_public(), keys.mldsa_hash()),
    }
});

/// A log grown event by event, each author's chain kept, each event's cuts
/// those its parents give (events.md, "Cuts").
struct Grower {
    log: Log,
    last: BTreeMap<DeviceId, (u64, EventId)>,
    checkpoints: BTreeSet<EventId>,
}

impl Grower {
    fn act(&mut self, signer: &Signer, kind: u8, body: Vec<u8>) -> Option<EventId> {
        let author = *signer.device_id();
        let (seq, prev) = match self.last.get(&author) {
            Some(&(seq, prev)) => (seq + 1, Some(prev)),
            None => (1, None),
        };
        let mut parents = self.log.heads();
        parents.extend(prev);
        parents.sort_unstable();
        parents.dedup();
        let cuts = self.log.cuts_for(&self.checkpoints, &parents).ok()?;
        if cuts.len() > frasil_events::MAX_CUTS {
            return None;
        }
        let signed = Envelope {
            kind,
            log: Some(self.log.id()),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents,
            cuts,
            body,
            scheme: Scheme::Hybrid,
        }
        .sign(signer);
        let event = decode(&signed).ok()?;
        let id = event.id();
        if !matches!(self.log.place(event), Ok(Placement::Placed(_))) {
            return None;
        }
        self.last.insert(author, (seq, id));
        Some(id)
    }

    /// A space event naming `twin` in visible key 15.
    fn name(&mut self, founder: &Signer, twin: EventId) -> Option<EventId> {
        let mut map = Map::new();
        map.insert(visible_key::TWIN, Value::from(twin.0));
        self.act(founder, kind::SPACE, Value::Map(map).encode())
    }

    /// A checkpoint naming `cut` in visible key 15.
    fn checkpoint(&mut self, founder: &Signer, cut: EventId) -> Option<EventId> {
        let id = self.name(founder, cut)?;
        self.checkpoints.insert(id);
        Some(id)
    }
}

/// The cut body the input picks: its raw bytes, or the slots of the
/// skeleton of the log's events, the input choosing the epoch, how many
/// slots it keeps and its other fields.
fn cut_body(log: &Log, data: &[u8]) -> Option<Vec<u8>> {
    let (&mode, rest) = data.split_first()?;
    if mode & 1 == 0 {
        return Some(rest.to_vec());
    }
    let mut fields = [0u8; 2 + 32 + 32 + 64];
    let n = fields.len().min(rest.len());
    fields[..n].copy_from_slice(&rest[..n]);
    let all: BTreeSet<EventId> = log.canonical().into_iter().collect();
    let (epoch, mut slots) = PeerCuts::new(log, None).slots_for(&all);
    let keep = usize::from(fields[1]) % (slots.len() + 1);
    if fields[1] & 0x80 == 0 {
        slots.truncate(keep);
    }
    // Ranks other than the skeleton's make the cut BadCut.
    if fields[1] & 0x40 != 0 {
        for (k, slot) in slots.iter_mut().enumerate() {
            slot.rank = fields[2 + k % 32];
        }
    }
    let epoch = match fields[0] % 4 {
        0 => epoch,
        k => u64::from(k) + u64::from(fields[0] >> 2),
    };
    // One standing entry per slot, ordered as the slots are, waiting for
    // each; a byte of the input makes some dormant.
    let mut standing: Vec<frasil_peers::body::StandingEntry> = slots
        .iter()
        .enumerate()
        .map(|(k, entry)| frasil_peers::body::StandingEntry {
            slot: entry.slot,
            order: k as u64 + 1,
            dormant: u64::from(fields[1] >> 5 & 1) * u64::from(fields[2 + k % 32] % 4),
            pseudonym: None,
        })
        .collect();
    if standing.is_empty() {
        standing.push(frasil_peers::body::StandingEntry {
            slot: frasil_peers::body::SlotId::new([0; 32], 0, EventId([0; 32])),
            order: 1,
            dormant: 0,
            pseudonym: None,
        });
    }
    let cut = Cut {
        twin: fields[2..34].try_into().expect("32 bytes"),
        salt: fields[34..66].try_into().expect("32 bytes"),
        record: fields[66..130].try_into().expect("64 bytes"),
        epoch,
        slots,
        standing,
    };
    Some(StorageBody::Cut(cut).encode())
}

/// Every cut a peer holds is valid or void with a class of its checks.
fn judge(cuts: &PeerCuts<'_>) {
    for (id, _) in cuts.cuts() {
        match cuts.validity(id) {
            Status::Valid => assert!(cuts.checkpoint_of(id).is_some(), "a valid cut is named"),
            Status::Void { class, .. } => assert!(
                matches!(
                    class,
                    PeersClass::NotAuthorized
                        | PeersClass::Unnamed
                        | PeersClass::CutPending
                        | PeersClass::BadCut
                        | PeersClass::Shared(
                            ErrorClass::Malformed
                                | ErrorClass::Pending
                                | ErrorClass::BadSignature
                                | ErrorClass::NotAnAdministrator
                        )
                ),
                "{class:?}"
            ),
        }
        let _ = cuts.awaiting(id);
        let _ = cuts.in_effect(id);
    }
    let chain = cuts.chain();
    assert!(chain.iter().all(|&id| cuts.validity(id).is_valid()));
    let skeleton = cuts.skeleton();
    let _ = skeleton.administrators();
    let _ = skeleton.statuses();
}

fuzz_target!(|data: &[u8]| {
    // Decoding: a cut's body reads only within its bounds, and is the one
    // encoding of what it returns.
    if let Ok(StorageBody::Cut(cut)) = StorageBody::read(data) {
        assert!(cut.slots.len() <= MAX_CUT_SLOTS);
        assert_eq!(StorageBody::Cut(cut).encode(), data);
    }
    if let Ok(event) = decode(data)
        && let Some(cut) = read_cut(&event)
    {
        assert!(cut.slots.len() <= MAX_CUT_SLOTS);
    }

    // Judging.
    let space = &*SPACE;
    let mut grower = Grower {
        log: space.log.clone(),
        last: BTreeMap::new(),
        checkpoints: BTreeSet::new(),
    };
    for id in grower.log.canonical() {
        if let Some(event) = grower.log.event(id) {
            grower.last.insert(*event.author(), (event.seq(), id));
        }
    }
    let flags = data.first().copied().unwrap_or(0);
    // An administrator slot granted at the input's rank, which the cut's
    // slots carry.
    if flags & 16 != 0 {
        let (slot_ed, slot_mldsa_hash) = space.slot;
        let change = StorageBody::Change {
            twin: [5; 32],
            salt: [6; 32],
            effect: ChangeEffect::Grants(vec![GrantMap {
                slot_ed,
                slot_mldsa_hash,
                token: vec![1; SEALED_TOKEN_BYTES],
                rank: data.get(1).copied().unwrap_or(0),
            }]),
        };
        if let Some(id) = grower.act(&space.pseudonym, kind::STORAGE, change.encode()) {
            let _ = grower.name(&space.founder, id);
        }
    }
    let mut rest = data;
    for round in 0..2 {
        if round == 1 && flags & 2 == 0 {
            break;
        }
        let Some(body) = cut_body(&grower.log, rest) else {
            break;
        };
        let Some(cut) = grower.act(&space.pseudonym, kind::STORAGE, body) else {
            break;
        };
        if flags & 4 == 0 && grower.checkpoint(&space.founder, cut).is_none() {
            break;
        }
        if flags & 8 == 0 {
            let _ = grower.act(&space.pseudonym, kind::STORAGE, StorageBody::Ack.encode());
        }
        rest = rest.get(1..).unwrap_or_default();
    }
    let log = &grower.log;
    let full = PeerCuts::new(log, None);
    judge(&full);

    // A peer that truncated under the last cut in effect judges what it
    // keeps; the kept cut stays in effect there.
    if let Some(last) = full.current()
        && let Some(checkpoint) = full.checkpoint_of(last)
        && let Ok(plan) = full.truncation_plan(last, |_, _| false)
    {
        assert!(!plan.delete.contains(&checkpoint) && !plan.delete.contains(&last));
        let held: BTreeSet<EventId> = log
            .canonical()
            .into_iter()
            .filter(|id| !plan.delete.contains(id))
            .collect();
        let truncated = PeerCuts::truncated(log, log, held, last);
        judge(&truncated);
        assert_eq!(truncated.chain().first(), Some(&last));
    }
});
