//! The peer's records at rest, over `frasil-store`'s [`Store`]: SQLite on a
//! server, memory in tests.
//!
//! A peer holds no device key, so its records are its own, in the clear:
//!
//! - **The journal** of each space: every event it stored or holds pending,
//!   with its first sight and the entry it was stored under; every merge
//!   statement it accepted; each present that changed an entry; each
//!   recovery entry registered; each request it carried out; the stubs
//!   it keeps for its own placement of what it collected, reclaimed or
//!   deleted when it truncated; and each truncation, by its cut. A
//!   space's state in memory is the journal replayed, in order, through the
//!   same procedures that wrote it.
//! - **Tombstones** of erased spaces: the space ID and the erasure event.
//! - **The object index**: each locator's pieces and state.
//! - **Device mailboxes**: their items, with each deposit's sight, whether
//!   a deposit token paid for it, and whether its mailbox was claimed when
//!   it came; and each mailbox's claim (transport.md, "Claimed device
//!   mailboxes"): its last collection and the collection its claim began
//!   with.
//! - **Invite drops** (ext-invite-links.md), by space and address: the
//!   upload entry each was placed under, its placement on the timeline, its
//!   lifetime and the drop; and by address alone, the space it was placed
//!   for, so that any node finds where it is served.
//! - **The kept reading** of the peer's timeline.
//! - **Snapshots**: each space's decoded state as of a journal index, one
//!   [`Snapshot`] kept in parts. A space opens from its snapshot, decoding
//!   no event of it, and replays the journal records after it; the two
//!   make the state the whole journal replays to.
//! - **The space index**: one record per hosted space, naming the shard
//!   that keeps its records, so that the peer knows what it hosts without
//!   reading any journal; and a **wait marker** for each space that may
//!   hold something a sweep must judge, so that a restart sweeps those
//!   spaces without opening every other.
//! - **Usage** (ext-libraries.md): a closed space's usage, which its
//!   library's ledger reads without opening it.
//! - **Exchange mailboxes**: each message an exchange mailbox holds, with
//!   its deposit's wall clock and source.
//! - **Moves** (ext-libraries.md, 3.3 Attaching): in the space index, the
//!   intent of a space's move into another shard, kept until the shard it
//!   moves to holds its records and the index names it, or until the move
//!   is abandoned.
//! - **Departures** (peers.md, 3.1 Hosting a space, "Hand-over"): in the
//!   space index, the public halves a space handed over to another peer
//!   held when it left.
//! - **Offsets**: with a space's records in its shard, once it moved in
//!   from another shard, the shard's reading and the space's at the move,
//!   so that its sights go on from where they stood (overview.md, 6.7
//!   Policy values and a peer's clock).
//!
//! Records of one space share a prefix, so a space's erasure deletes them
//! in one scan.
//!
//! Wherever a record names a device or an author, it names its device ID
//! (crypto.md, "A device's keys"), 32 bytes, and a departure record keeps a
//! pseudonym's `ed || kc`. Records written before devices were named so do
//! not open: [`Records::check_revision`] refuses them.

use frasil_base::cbor::{self, Map, Value};
use frasil_base::time::Reading;
use frasil_crypto::device::{DeviceId, Signatory};
use frasil_events::{EventId, Stub};
use frasil_store::{Store, StoreError};
use futures_util::FutureExt;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Runs a store's future. The stores the peer uses, SQLite and memory, do
/// their work when first polled.
fn ready<T>(future: frasil_store::BoxFuture<'_, Result<T, StoreError>>) -> Result<T, StoreError> {
    future
        .now_or_never()
        .unwrap_or_else(|| Err(StoreError::new("the store answered asynchronously")))
}

pub(crate) const JOURNAL: u8 = b'j';
pub(crate) const TOMBSTONE: u8 = b't';
pub(crate) const OBJECT: u8 = b'o';
pub(crate) const MAILBOX: u8 = b'm';
pub(crate) const META: u8 = b'x';
pub(crate) const SNAPSHOT: u8 = b's';
pub(crate) const HOSTED: u8 = b'h';
pub(crate) const WAITS: u8 = b'w';
/// A closed space's usage, as its library's ledger reads it.
pub(crate) const USAGE: u8 = b'u';
/// An exchange mailbox's message (transport.md, "Mailboxes").
pub(crate) const EXCHANGE: u8 = b'e';
/// ext-invite-links.md's invite drops.
pub(crate) const DROP: u8 = b'd';
/// ext-invite-links.md: where to find a drop by its address alone.
pub(crate) const DROP_AT: u8 = b'a';
/// ext-libraries.md's records: libraries, attachments, tickets used.
pub(crate) const LIBRARY: u8 = b'l';
/// A space's move into another shard, under way.
pub(crate) const MOVE: u8 = b'v';
/// A space's departure record.
pub(crate) const DEPARTURE: u8 = b'r';
/// Where a space's timeline stands against its shard's, once it moved in
/// from another shard.
pub(crate) const OFFSET: u8 = b'k';
/// The copies a page of a move carried, which the move's target keeps
/// until its last step (crate `libraries`, module `moves`).
pub(crate) const ARRIVAL: u8 = b'n';
/// A device mailbox's claim, kept in the mailbox's shard.
pub(crate) const CLAIM: u8 = b'c';
/// ext-deposit-tokens.md: a deposit key (crate `deposit`).
pub(crate) const DEPOSIT_KEY: u8 = b'q';
/// ext-deposit-tokens.md: a spent token, in the mailbox shard its nonce
/// names (crate `deposit`).
pub(crate) const SPENT: u8 = b'p';

/// The largest part of a snapshot at rest.
pub(crate) const SNAPSHOT_PART: usize = 4 << 20;

/// A library record: its table, its key, and its bytes.
pub(crate) type LibraryRow = (u8, Vec<u8>, Vec<u8>);

/// What a device mailbox item's record says besides the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MailboxItem {
    /// Its deposit's sight on the timeline.
    pub sight: u64,
    /// Whether a deposit token paid for it.
    pub paid: bool,
    /// Whether its mailbox was not claimed when it came.
    pub unclaimed: bool,
}

/// An invite drop as the peer keeps it at rest (ext-invite-links.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeptDrop {
    /// The space it was placed for.
    pub space: [u8; 32],
    /// Its mailbox address.
    pub address: [u8; 32],
    /// The upload entry whose store right placed it.
    pub entry: [u8; 32],
    /// The peer's timeline, in seconds, when it was placed.
    pub placed: u64,
    /// The lifetime it asked for, in seconds.
    pub lifetime: u64,
    /// The drop.
    pub drop: Vec<u8>,
}

/// A space's move into another shard, as the space index keeps it while
/// the move is under way: `{1: source shard, 2: target shard, 3: library,
/// 4: ticket ID?, 5: reading, 6: not_after?}`, the library the move
/// attaches the space to, the ticket that moves it, the reading the
/// attachment takes effect at, and the ticket's `not_after`, until which
/// the target keeps its ID used once the move is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MoveRecord {
    /// The shard that keeps the space's records now.
    pub source: String,
    /// The shard the space moves to.
    pub target: String,
    /// The library ID the space is attached to once it moved.
    pub library: String,
    /// The ticket that moves it.
    pub ticket: Option<Vec<u8>>,
    /// The reading of the attachment.
    pub at: Reading,
    /// The ticket's `not_after`.
    pub not_after: Option<u64>,
}

impl MoveRecord {
    /// The record's bytes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Text(self.source.clone()));
        map.insert(2, Value::Text(self.target.clone()));
        map.insert(3, Value::Text(self.library.clone()));
        if let Some(ticket) = &self.ticket {
            map.insert(4, Value::from(ticket.as_slice()));
        }
        map.insert(5, reading_value(&self.at));
        if let Some(not_after) = self.not_after {
            map.insert(6, Value::Unsigned(not_after));
        }
        Value::Map(map).encode()
    }

    /// Reads a record: exactly its keys, each of its kind.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value = cbor::decode(bytes).ok()?;
        let map = value.as_map().ok()?;
        if !map.keys().all(|key| (1..=6).contains(key)) {
            return None;
        }
        let text = |key: u64| -> Option<String> { Some(map.get(&key)?.as_text().ok()?.to_owned()) };
        Some(Self {
            source: text(1)?,
            target: text(2)?,
            library: text(3)?,
            ticket: match map.get(&4) {
                Some(value) => Some(value.as_bytes().ok()?.to_vec()),
                None => None,
            },
            at: read_reading(map.get(&5)?)?,
            not_after: match map.get(&6) {
                Some(value) => Some(value.as_unsigned().ok()?),
                None => None,
            },
        })
    }
}

/// A space's departure record (peers.md, 3.1 Hosting a space,
/// "Hand-over"): the public halves of every entry, recovery entry and
/// enrolled pseudonym the space held when it left, by credential:
/// `{1: [read keys], 2: [upload keys], 3: [pseudonyms], 4: [recovery
/// keys]}`, each list in order with no repeat. A pseudonym is kept as its
/// `ed || kc` (64 bytes), from which its device ID, credential 3's public
/// half, follows, and under whose `ed` its proof verifies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Departure {
    /// The public halves of credentials 1, 2 and 4, at 0, 1 and 3; 2 is
    /// empty, credential 3's being [`Self::pseudonyms`].
    pub keys: [BTreeSet<[u8; 32]>; 4],
    /// Each enrolled pseudonym's `ed || kc`.
    pub pseudonyms: BTreeSet<[u8; 64]>,
}

impl Departure {
    /// Whether it keeps `public` for credential `credential`: for 3, a
    /// pseudonym whose device ID is `public`.
    pub(crate) fn keeps(&self, credential: u8, public: &[u8; 32]) -> bool {
        match credential {
            3 => self.pseudonym(public).is_some(),
            1 | 2 | 4 => self.keys[usize::from(credential - 1)].contains(public),
            _ => false,
        }
    }

    /// The Ed25519 key of the pseudonym whose device ID is `device`, under
    /// which its credential 3 proof verifies.
    pub(crate) fn pseudonym(&self, device: &[u8; 32]) -> Option<[u8; 32]> {
        self.pseudonyms.iter().find_map(|signer| {
            let signer = Signatory::from_bytes(signer).ok()?;
            (signer.device_id().0 == *device).then_some(signer.ed.0)
        })
    }

    /// The record's bytes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        for (n, keys) in (1u64..).zip(&self.keys) {
            let list = if n == 3 {
                self.pseudonyms
                    .iter()
                    .map(|p| Value::from(p.as_slice()))
                    .collect()
            } else {
                keys.iter().map(|key| Value::from(*key)).collect()
            };
            map.insert(n, Value::Array(list));
        }
        Value::Map(map).encode()
    }

    /// Reads a record: each of its four lists, in order with no repeat,
    /// list 3 of 64-byte items and the others of 32-byte ones.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        fn list<const N: usize>(value: &Value) -> Option<BTreeSet<[u8; N]>> {
            let mut out = BTreeSet::new();
            let mut last: Option<[u8; N]> = None;
            for item in value.as_array().ok()? {
                let key: [u8; N] = item.as_bytes().ok()?.try_into().ok()?;
                if last.is_some_and(|last| last >= key) {
                    return None;
                }
                last = Some(key);
                out.insert(key);
            }
            Some(out)
        }
        let value = cbor::decode(bytes).ok()?;
        let map = value.as_map().ok()?;
        if map.len() != 4 {
            return None;
        }
        let mut departure = Self::default();
        for (n, keys) in (1u64..).zip(departure.keys.iter_mut()) {
            if n == 3 {
                departure.pseudonyms = list::<64>(map.get(&n)?)?;
            } else {
                *keys = list::<32>(map.get(&n)?)?;
            }
        }
        Some(departure)
    }
}

/// One record of a space's journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Op {
    /// An event stored, or held pending: its signed bytes, the peer's first
    /// sight of it, and the upload key of the entry the storing connection
    /// proved, if any.
    Event {
        signed: Vec<u8>,
        sight: Reading,
        entry: Option<[u8; 32]>,
    },
    /// A merge statement accepted (peers.md, "Merge statements").
    Merge { statement: Vec<u8> },
    /// A present that proved an entry, or made an import entry live.
    Proved {
        credential: u8,
        public: [u8; 32],
        binding: [u8; 32],
        proof: Vec<u8>,
        importing: bool,
    },
    /// A fetch key registered as a recovery entry.
    Register { key: [u8; 32] },
    /// An erasure or a credentials request carried out.
    Executed { request: EventId },
    /// A stub of a unit the peer collected or reclaimed, for its own
    /// placement (units.md, "Placing against stubs").
    Stub(Stub),
    /// A snapshot unit whose cover the peer checked and collected.
    Collected { snapshot: EventId },
    /// `since` of a snapshot unit's own listings (ext-file-versions.md, 3.6
    /// Listings at a peer), kept as its cover goes.
    Since {
        snapshot: EventId,
        since: Vec<([u8; 64], Reading)>,
    },
    /// An event an import stores, written just before the event's own
    /// record: a rotation it places adds its entry retired, source
    /// `import` (peers.md, "Hosting a space").
    Imported { event: EventId },
    /// A truncation under a skeleton cut in effect (peers.md,
    /// "Truncation"): the cut, which the skeleton starts from afterwards,
    /// and its checkpoint. Written with the stubs of the events it deleted,
    /// which the peer keeps for its own placement.
    ///
    /// With the releases and restores of the checkpoint's past it kept
    /// (peers.md, "Truncation", what is always kept), ascending: the peer
    /// counts them in that past, whose order to the checkpoint went with the
    /// events it deleted. Key 3, absent when there are none.
    Truncated {
        cut: EventId,
        checkpoint: EventId,
        requests: Vec<EventId>,
    },
}

fn reading_value(reading: &Reading) -> Value {
    let mut map = Map::new();
    map.insert(1, Value::Unsigned(reading.timeline));
    map.insert(2, Value::Unsigned(reading.run));
    if let Some(wall) = reading.wall {
        map.insert(3, Value::Unsigned(wall));
    }
    Value::Map(map)
}

fn read_reading(value: &Value) -> Option<Reading> {
    let map = value.as_map().ok()?;
    Some(Reading {
        timeline: map.get(&1)?.as_unsigned().ok()?,
        run: map.get(&2)?.as_unsigned().ok()?,
        wall: match map.get(&3) {
            Some(value) => Some(value.as_unsigned().ok()?),
            None => None,
        },
    })
}

fn field(map: &Map, key: u64) -> Option<&Value> {
    map.get(&key)
}

impl Op {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        match self {
            Self::Event {
                signed,
                sight,
                entry,
            } => {
                map.insert(0, Value::Unsigned(1));
                map.insert(1, Value::from(signed.as_slice()));
                map.insert(2, reading_value(sight));
                if let Some(entry) = entry {
                    map.insert(3, Value::from(entry.as_slice()));
                }
            }
            Self::Merge { statement } => {
                map.insert(0, Value::Unsigned(2));
                map.insert(1, Value::from(statement.as_slice()));
            }
            Self::Proved {
                credential,
                public,
                binding,
                proof,
                importing,
            } => {
                map.insert(0, Value::Unsigned(3));
                map.insert(1, Value::Unsigned((*credential).into()));
                map.insert(2, Value::from(public.as_slice()));
                map.insert(3, Value::from(binding.as_slice()));
                map.insert(4, Value::from(proof.as_slice()));
                map.insert(5, Value::Unsigned((*importing).into()));
            }
            Self::Register { key } => {
                map.insert(0, Value::Unsigned(4));
                map.insert(1, Value::from(key.as_slice()));
            }
            Self::Executed { request } => {
                map.insert(0, Value::Unsigned(5));
                map.insert(1, Value::from(request.as_bytes().as_slice()));
            }
            Self::Stub(stub) => {
                map.insert(0, Value::Unsigned(6));
                map.insert(1, Value::from(stub.id.as_bytes().as_slice()));
                map.insert(2, Value::from(stub.author.as_bytes().as_slice()));
                map.insert(3, Value::Unsigned(stub.seq));
                map.insert(4, Value::Unsigned(stub.height));
                map.insert(5, Value::Unsigned(stub.kind.into()));
                // The cuts its unit declares, when it declares any, so that
                // a child placed on the stub reads them (events.md, 3.11
                // Cuts).
                if !stub.cuts.is_empty() {
                    map.insert(
                        6,
                        Value::Array(
                            stub.cuts
                                .iter()
                                .map(|id| Value::from(id.as_bytes().as_slice()))
                                .collect(),
                        ),
                    );
                }
            }
            Self::Collected { snapshot } => {
                map.insert(0, Value::Unsigned(7));
                map.insert(1, Value::from(snapshot.as_bytes().as_slice()));
            }
            Self::Since { snapshot, since } => {
                map.insert(0, Value::Unsigned(9));
                map.insert(1, Value::from(snapshot.as_bytes().as_slice()));
                map.insert(
                    2,
                    Value::Array(
                        since
                            .iter()
                            .map(|(locator, reading)| {
                                Value::Array(vec![
                                    Value::from(locator.as_slice()),
                                    reading_value(reading),
                                ])
                            })
                            .collect(),
                    ),
                );
            }
            Self::Imported { event } => {
                map.insert(0, Value::Unsigned(8));
                map.insert(1, Value::from(event.as_bytes().as_slice()));
            }
            Self::Truncated {
                cut,
                checkpoint,
                requests,
            } => {
                map.insert(0, Value::Unsigned(10));
                map.insert(1, Value::from(cut.as_bytes().as_slice()));
                map.insert(2, Value::from(checkpoint.as_bytes().as_slice()));
                if !requests.is_empty() {
                    map.insert(
                        3,
                        Value::Array(
                            requests
                                .iter()
                                .map(|id| Value::from(id.as_bytes().as_slice()))
                                .collect(),
                        ),
                    );
                }
            }
        }
        Value::Map(map).encode()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value = cbor::decode(bytes).ok()?;
        let map = value.as_map().ok()?;
        let bytes_of = |key| field(map, key).and_then(|v| v.as_bytes().ok());
        let array_of = |key| field(map, key).and_then(|v| v.as_byte_array::<32>().ok());
        let uint = |key| field(map, key).and_then(|v| v.as_unsigned().ok());
        Some(match uint(0)? {
            1 => Self::Event {
                signed: bytes_of(1)?.to_vec(),
                sight: read_reading(field(map, 2)?)?,
                entry: match field(map, 3) {
                    Some(_) => Some(array_of(3)?),
                    None => None,
                },
            },
            2 => Self::Merge {
                statement: bytes_of(1)?.to_vec(),
            },
            3 => Self::Proved {
                credential: u8::try_from(uint(1)?).ok()?,
                public: array_of(2)?,
                binding: array_of(3)?,
                proof: bytes_of(4)?.to_vec(),
                importing: uint(5)? == 1,
            },
            4 => Self::Register { key: array_of(1)? },
            5 => Self::Executed {
                request: EventId(array_of(1)?),
            },
            6 => Self::Stub(Stub {
                id: EventId(array_of(1)?),
                author: DeviceId(array_of(2)?),
                seq: uint(3)?,
                height: uint(4)?,
                kind: u8::try_from(uint(5)?).ok()?,
                cuts: match field(map, 6) {
                    None => frasil_events::Cuts::NONE,
                    Some(value) => {
                        let ids = value
                            .as_array()
                            .ok()?
                            .iter()
                            .map(|id| id.as_byte_array::<32>().ok().map(EventId))
                            .collect::<Option<Vec<_>>>()?;
                        if ids.is_empty() {
                            return None;
                        }
                        frasil_events::Cuts::new(&ids)?
                    }
                },
            }),
            7 => Self::Collected {
                snapshot: EventId(array_of(1)?),
            },
            9 => Self::Since {
                snapshot: EventId(array_of(1)?),
                since: field(map, 2)?
                    .as_array()
                    .ok()?
                    .iter()
                    .map(|pair| {
                        let [locator, reading] = pair.as_array().ok()? else {
                            return None;
                        };
                        Some((locator.as_byte_array().ok()?, read_reading(reading)?))
                    })
                    .collect::<Option<_>>()?,
            },
            8 => Self::Imported {
                event: EventId(array_of(1)?),
            },
            10 => Self::Truncated {
                cut: EventId(array_of(1)?),
                checkpoint: EventId(array_of(2)?),
                requests: match field(map, 3) {
                    None => Vec::new(),
                    Some(value) => {
                        let ids = value
                            .as_array()
                            .ok()?
                            .iter()
                            .map(|id| id.as_byte_array::<32>().ok().map(EventId))
                            .collect::<Option<Vec<_>>>()?;
                        if ids.is_empty() || ids.windows(2).any(|w| w[0] >= w[1]) {
                            return None;
                        }
                        ids
                    }
                },
            },
            _ => return None,
        })
    }
}

/// The peer's index entry for one object, by space and locator.
///
/// On the server binding an object travels in **pieces**: its stored bytes
/// (units.md, "Objects") cut every 1,048,576 bytes. Piece 0 holds the
/// header, from which the peer learns the stored length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectRecord {
    /// The pieces held.
    pub pieces: BTreeSet<u64>,
    /// The stored object's length, once piece 0 has arrived.
    pub total: Option<u64>,
    /// Whether every piece arrived and the bytes hash to the locator's
    /// digest.
    pub complete: bool,
    /// The peer's first sight of the last piece it received.
    pub last: Reading,
    /// Whether a stored unit has referenced it since its upload completed.
    pub referenced: bool,
    /// The upload key of the entry it was stored under.
    pub entry: Option<[u8; 32]>,
}

impl ObjectRecord {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(
            1,
            Value::Array(self.pieces.iter().map(|&p| Value::Unsigned(p)).collect()),
        );
        if let Some(total) = self.total {
            map.insert(2, Value::Unsigned(total));
        }
        map.insert(3, Value::Unsigned(self.complete.into()));
        map.insert(4, reading_value(&self.last));
        map.insert(5, Value::Unsigned(self.referenced.into()));
        if let Some(entry) = self.entry {
            map.insert(6, Value::from(entry.as_slice()));
        }
        Value::Map(map).encode()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let value = cbor::decode(bytes).ok()?;
        let map = value.as_map().ok()?;
        let pieces = field(map, 1)?
            .as_array()
            .ok()?
            .iter()
            .map(|v| v.as_unsigned().ok())
            .collect::<Option<BTreeSet<u64>>>()?;
        Some(Self {
            pieces,
            total: match field(map, 2) {
                Some(v) => Some(v.as_unsigned().ok()?),
                None => None,
            },
            complete: field(map, 3)?.as_unsigned().ok()? == 1,
            last: read_reading(field(map, 4)?)?,
            referenced: field(map, 5)?.as_unsigned().ok()? == 1,
            entry: match field(map, 6) {
                Some(v) => Some(v.as_byte_array::<32>().ok()?),
                None => None,
            },
        })
    }
}

/// What the peer keeps of one held event, beside the event in the log: its
/// journal index, its first sight, and the entry it was stored under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Held {
    pub id: EventId,
    pub index: u64,
    pub sight: Reading,
    pub entry: Option<[u8; 32]>,
}

/// A unit's index entry at rest: its stream, its objects, and its
/// compaction declaration's encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeptUnit {
    pub id: EventId,
    pub stream: [u8; 16],
    pub objects: Vec<[u8; 64]>,
    pub compacts: Option<Vec<u8>>,
    pub supersedes: Vec<frasil_adapter::Supersession>,
    /// `since` of a snapshot unit's own listings.
    pub since: Vec<([u8; 64], Reading)>,
}

/// A space's decoded state at rest, as of a journal index: everything the
/// journal before `through` replays to, so that a space opens from it, and
/// the journal records from `through` on, without decoding or placing any
/// event of it again.
///
/// Its encoding is deterministic CBOR, positional, version first:
///
/// ```text
/// snapshot = [3, through, log, entries, forks, [* held], [* [index, op]],
///             [* unit], [* [id, body]], changes, named, requests,
///             executed, collected, conflicts, [* [id, n]], [* stream],
///             [* object], [* [id, carrier]], imported]
/// held     = [id, index, reading, entry]
/// unit     = [id, stream, [* locator], compacts, [* supersession],
///             [* [locator, reading]]]
/// supersession = [successor, listing, predecessor]
/// ```
///
/// `log`, `entries` and `forks` are `frasil-events`' log state,
/// `frasil-peers`' entries state and fork points; a `reading` is
/// `{1: timeline, 2: run, 3: wall?}`; `entry`, `compacts`, `carrier` and a
/// supersession's `listing` are empty bytes when absent; an `op` is a journal record that is no event's,
/// with its index below `through`; a `body` is a release or restore
/// request's storage body. `[* stream]` and `[* object]` are written empty
/// and read aside, since an erasure names the whole space (peers.md,
/// "Erasure"). Every list is ascending by its first item, and
/// the plain lists of IDs (changes, named, requests, executed, collected,
/// conflicts, imported) are strictly ascending.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    /// The first journal index the snapshot does not hold.
    pub through: u64,
    pub log: Vec<u8>,
    pub entries: Vec<u8>,
    pub forks: Vec<u8>,
    pub held: Vec<Held>,
    pub ops: Vec<(u64, Op)>,
    pub units: Vec<KeptUnit>,
    pub writer_requests: Vec<(EventId, Vec<u8>)>,
    pub changes: Vec<EventId>,
    pub named: Vec<EventId>,
    pub requests: Vec<EventId>,
    pub executed: Vec<EventId>,
    pub collected: Vec<EventId>,
    pub conflicts: Vec<EventId>,
    pub request_sights: Vec<(EventId, u64)>,
    pub stubs: Vec<(EventId, Option<EventId>)>,
    pub imported: Vec<EventId>,
}

fn write_ids(out: &mut Vec<u8>, ids: &[EventId]) {
    cbor::array_head(out, ids.len());
    for id in ids {
        cbor::bytes(out, id.as_bytes());
    }
}

fn write_reading(out: &mut Vec<u8>, reading: &Reading) {
    reading_value(reading).encode_into(out);
}

fn read_ids(reader: &mut cbor::Reader<'_>) -> Option<Vec<EventId>> {
    let count = reader.array_len().ok()?;
    let mut out: Vec<EventId> = Vec::with_capacity(count.min(1 << 12));
    for _ in 0..count {
        let id = EventId(reader.byte_array::<32>().ok()?);
        if out.last().is_some_and(|last| *last >= id) {
            return None;
        }
        out.push(id);
    }
    Some(out)
}

fn read_optional<const N: usize>(reader: &mut cbor::Reader<'_>) -> Option<Option<[u8; N]>> {
    let bytes = reader.bytes().ok()?;
    if bytes.is_empty() {
        return Some(None);
    }
    Some(Some(bytes.try_into().ok()?))
}

/// A reading, read from the front of a reader: a map of 2 or 3 keys.
fn read_reading_from(reader: &mut cbor::Reader<'_>) -> Option<Reading> {
    let count = reader.map_len().ok()?;
    if !(2..=3).contains(&count) {
        return None;
    }
    reader.key(1).ok()?;
    let timeline = reader.unsigned().ok()?;
    reader.key(2).ok()?;
    let run = reader.unsigned().ok()?;
    let wall = if count == 3 {
        reader.key(3).ok()?;
        Some(reader.unsigned().ok()?)
    } else {
        None
    };
    Some(Reading {
        timeline,
        run,
        wall,
    })
}

/// Whether a list is strictly ascending by a key.
fn ascending<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    items.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

impl Snapshot {
    /// The version this peer writes and reads.
    pub(crate) const VERSION: u64 = 3;

    pub(crate) fn encode(&self) -> Vec<u8> {
        let size = self.log.len()
            + self.entries.len()
            + 96 * self.held.len()
            + 128 * self.units.len()
            + 256;
        let mut out = Vec::with_capacity(size);
        cbor::array_head(&mut out, 20);
        cbor::unsigned(&mut out, Self::VERSION);
        cbor::unsigned(&mut out, self.through);
        cbor::bytes(&mut out, &self.log);
        cbor::bytes(&mut out, &self.entries);
        cbor::bytes(&mut out, &self.forks);
        cbor::array_head(&mut out, self.held.len());
        for held in &self.held {
            cbor::array_head(&mut out, 4);
            cbor::bytes(&mut out, held.id.as_bytes());
            cbor::unsigned(&mut out, held.index);
            write_reading(&mut out, &held.sight);
            cbor::bytes(&mut out, held.entry.as_ref().map_or(&[][..], |e| &e[..]));
        }
        cbor::array_head(&mut out, self.ops.len());
        for (index, op) in &self.ops {
            cbor::array_head(&mut out, 2);
            cbor::unsigned(&mut out, *index);
            cbor::bytes(&mut out, &op.encode());
        }
        cbor::array_head(&mut out, self.units.len());
        for unit in &self.units {
            cbor::array_head(&mut out, 6);
            cbor::bytes(&mut out, unit.id.as_bytes());
            cbor::bytes(&mut out, &unit.stream);
            cbor::array_head(&mut out, unit.objects.len());
            for locator in &unit.objects {
                cbor::bytes(&mut out, locator);
            }
            cbor::bytes(&mut out, unit.compacts.as_deref().unwrap_or(&[]));
            cbor::array_head(&mut out, unit.supersedes.len());
            for named in &unit.supersedes {
                cbor::array_head(&mut out, 3);
                cbor::bytes(&mut out, &named.successor);
                cbor::bytes(&mut out, named.listing.as_ref().map_or(&[][..], |l| &l[..]));
                cbor::bytes(&mut out, &named.predecessor);
            }
            cbor::array_head(&mut out, unit.since.len());
            for (locator, reading) in &unit.since {
                cbor::array_head(&mut out, 2);
                cbor::bytes(&mut out, locator);
                write_reading(&mut out, reading);
            }
        }
        cbor::array_head(&mut out, self.writer_requests.len());
        for (id, body) in &self.writer_requests {
            cbor::array_head(&mut out, 2);
            cbor::bytes(&mut out, id.as_bytes());
            cbor::bytes(&mut out, body);
        }
        for ids in [
            &self.changes,
            &self.named,
            &self.requests,
            &self.executed,
            &self.collected,
            &self.conflicts,
        ] {
            write_ids(&mut out, ids);
        }
        cbor::array_head(&mut out, self.request_sights.len());
        for (id, n) in &self.request_sights {
            cbor::array_head(&mut out, 2);
            cbor::bytes(&mut out, id.as_bytes());
            cbor::unsigned(&mut out, *n);
        }
        // Two empty arrays: protocol 1 erases nothing narrower than a
        // space (peers.md, "Erasure").
        cbor::array_head(&mut out, 0);
        cbor::array_head(&mut out, 0);
        cbor::array_head(&mut out, self.stubs.len());
        for (id, carrier) in &self.stubs {
            cbor::array_head(&mut out, 2);
            cbor::bytes(&mut out, id.as_bytes());
            cbor::bytes(
                &mut out,
                carrier.as_ref().map_or(&[][..], |c| &c.as_bytes()[..]),
            );
        }
        write_ids(&mut out, &self.imported);
        out
    }

    /// The version before file versions: a unit is `[id, stream, [*
    /// locator], compacts]`, read with no supersession and no `since`.
    const VERSION_2: u64 = 2;

    /// The snapshot, if `bytes` are one this peer reads, in its one
    /// encoding: this version's, or version 2's.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = cbor::Reader::new(bytes);
        if reader.array_len().ok()? != 20 {
            return None;
        }
        let version = reader.unsigned().ok()?;
        if version != Self::VERSION && version != Self::VERSION_2 {
            return None;
        }
        let unit_len = if version == Self::VERSION_2 { 4 } else { 6 };
        let through = reader.unsigned().ok()?;
        let log = reader.bytes().ok()?.to_vec();
        let entries = reader.bytes().ok()?.to_vec();
        let forks = reader.bytes().ok()?.to_vec();
        let count = reader.array_len().ok()?;
        let mut held = Vec::with_capacity(count.min(1 << 14));
        for _ in 0..count {
            if reader.array_len().ok()? != 4 {
                return None;
            }
            held.push(Held {
                id: EventId(reader.byte_array::<32>().ok()?),
                index: reader.unsigned().ok()?,
                sight: read_reading_from(&mut reader)?,
                entry: read_optional::<32>(&mut reader)?,
            });
        }
        let count = reader.array_len().ok()?;
        let mut ops = Vec::with_capacity(count.min(1 << 14));
        for _ in 0..count {
            if reader.array_len().ok()? != 2 {
                return None;
            }
            let index = reader.unsigned().ok()?;
            let op = Op::decode(reader.bytes().ok()?)?;
            if matches!(op, Op::Event { .. }) || index >= through {
                return None;
            }
            ops.push((index, op));
        }
        let count = reader.array_len().ok()?;
        let mut units = Vec::with_capacity(count.min(1 << 14));
        for _ in 0..count {
            if reader.array_len().ok()? != unit_len {
                return None;
            }
            let id = EventId(reader.byte_array::<32>().ok()?);
            let stream = reader.byte_array::<16>().ok()?;
            let objects_count = reader.array_len().ok()?;
            let mut objects = Vec::with_capacity(objects_count.min(1 << 10));
            for _ in 0..objects_count {
                objects.push(reader.byte_array::<64>().ok()?);
            }
            let compacts = reader.bytes().ok()?;
            if version == Self::VERSION_2 {
                units.push(KeptUnit {
                    id,
                    stream,
                    objects,
                    compacts: (!compacts.is_empty()).then(|| compacts.to_vec()),
                    supersedes: Vec::new(),
                    since: Vec::new(),
                });
                continue;
            }
            let count = reader.array_len().ok()?;
            let mut supersedes = Vec::with_capacity(count.min(1 << 10));
            for _ in 0..count {
                if reader.array_len().ok()? != 3 {
                    return None;
                }
                supersedes.push(frasil_adapter::Supersession {
                    successor: reader.byte_array::<64>().ok()?,
                    listing: read_optional::<32>(&mut reader)?,
                    predecessor: reader.byte_array::<64>().ok()?,
                });
            }
            let count = reader.array_len().ok()?;
            let mut since = Vec::with_capacity(count.min(1 << 10));
            for _ in 0..count {
                if reader.array_len().ok()? != 2 {
                    return None;
                }
                since.push((
                    reader.byte_array::<64>().ok()?,
                    read_reading_from(&mut reader)?,
                ));
            }
            units.push(KeptUnit {
                id,
                stream,
                objects,
                compacts: (!compacts.is_empty()).then(|| compacts.to_vec()),
                supersedes,
                since,
            });
        }
        let count = reader.array_len().ok()?;
        let mut writer_requests = Vec::with_capacity(count.min(1 << 12));
        for _ in 0..count {
            if reader.array_len().ok()? != 2 {
                return None;
            }
            writer_requests.push((
                EventId(reader.byte_array::<32>().ok()?),
                reader.bytes().ok()?.to_vec(),
            ));
        }
        let changes = read_ids(&mut reader)?;
        let named = read_ids(&mut reader)?;
        let requests = read_ids(&mut reader)?;
        let executed = read_ids(&mut reader)?;
        let collected = read_ids(&mut reader)?;
        let conflicts = read_ids(&mut reader)?;
        let count = reader.array_len().ok()?;
        let mut request_sights = Vec::with_capacity(count.min(1 << 12));
        for _ in 0..count {
            if reader.array_len().ok()? != 2 {
                return None;
            }
            request_sights.push((
                EventId(reader.byte_array::<32>().ok()?),
                reader.unsigned().ok()?,
            ));
        }
        // Two arrays of stream and object IDs, read and set aside: protocol
        // 1 erases nothing narrower than a space (peers.md, "Erasure").
        for _ in 0..reader.array_len().ok()? {
            reader.byte_array::<16>().ok()?;
        }
        for _ in 0..reader.array_len().ok()? {
            reader.byte_array::<32>().ok()?;
        }
        let count = reader.array_len().ok()?;
        let mut stubs = Vec::with_capacity(count.min(1 << 12));
        for _ in 0..count {
            if reader.array_len().ok()? != 2 {
                return None;
            }
            stubs.push((
                EventId(reader.byte_array::<32>().ok()?),
                read_optional::<32>(&mut reader)?.map(EventId),
            ));
        }
        let imported = read_ids(&mut reader)?;
        reader.finish().ok()?;
        let in_order = ascending(&held, |held| held.id)
            && ascending(&ops, |(index, _)| *index)
            && ascending(&units, |unit| unit.id)
            && ascending(&writer_requests, |(id, _)| *id)
            && ascending(&request_sights, |(id, _)| *id)
            && ascending(&stubs, |(id, _)| *id)
            && held.iter().all(|held| held.index < through);
        in_order.then_some(Self {
            through,
            log,
            entries,
            forks,
            held,
            ops,
            units,
            writer_requests,
            changes,
            named,
            requests,
            executed,
            collected,
            conflicts,
            request_sights,
            stubs,
            imported,
        })
    }
}

/// What a space's records at rest hold, to open it: its snapshot, if it
/// has one, and the journal records after it with their sizes.
#[derive(Debug, Clone, Default)]
pub(crate) struct Opened {
    /// The snapshot.
    pub snapshot: Option<Snapshot>,
    /// The snapshot's bytes and its parts.
    pub snapshot_bytes: u64,
    pub snapshot_parts: u32,
    /// The journal records from the snapshot's `through` on: each one's
    /// index, op, and size at rest.
    pub tail: Vec<(u64, Op, usize)>,
}

impl Opened {
    /// The bytes of the tail at rest.
    pub(crate) fn tail_bytes(&self) -> u64 {
        self.tail.iter().map(|(_, _, size)| *size as u64).sum()
    }
}

/// The peer's records over a [`Store`].
#[derive(Clone)]
pub(crate) struct Records {
    store: Arc<dyn Store>,
}

impl core::fmt::Debug for Records {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Records").finish_non_exhaustive()
    }
}

/// `prefix || space`.
fn of_space(prefix: u8, space: &EventId) -> Vec<u8> {
    let mut address = vec![prefix];
    address.extend_from_slice(space.as_bytes());
    address
}

impl Records {
    pub(crate) fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }

    pub(crate) fn scan(&self, prefix: &[u8]) -> Result<frasil_store::store::Records, StoreError> {
        ready(self.store.scan(prefix))
    }

    pub(crate) fn get(&self, address: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        ready(self.store.get(address))
    }

    /// Writes and deletes, in one atomic, durable commit, straight to the
    /// store: in tests. The peer commits through its writer, which keeps
    /// the order of commits.
    #[cfg(test)]
    pub(crate) fn commit(
        &self,
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        deletes: Vec<Vec<u8>>,
    ) -> Result<(), StoreError> {
        if puts.is_empty() && deletes.is_empty() {
            return Ok(());
        }
        let commit = frasil_store::Commit::new(puts, deletes);
        if ready(self.store.commit(&commit))? {
            Ok(())
        } else {
            Err(StoreError::new("a commit with no expectation was refused"))
        }
    }

    // -- The journal

    /// Whether an address is a journal record's.
    pub(crate) fn is_journal(address: &[u8]) -> bool {
        address.first() == Some(&JOURNAL)
    }

    /// The store the records are kept in.
    pub(crate) fn store(&self) -> Arc<dyn Store> {
        self.store.clone()
    }

    pub(crate) fn journal_address(space: &EventId, index: u64) -> Vec<u8> {
        let mut address = of_space(JOURNAL, space);
        address.extend_from_slice(&index.to_be_bytes());
        address
    }

    /// A space's journal, in order: each record's index and op.
    #[cfg(test)]
    pub(crate) fn journal(&self, space: &EventId) -> Result<Vec<(u64, Op)>, StoreError> {
        let mut out = Vec::new();
        for (address, record) in self.scan(&of_space(JOURNAL, space))? {
            let index = u64::from_be_bytes(
                address[33..]
                    .try_into()
                    .map_err(|_| StoreError::new("a journal address of another length"))?,
            );
            let op = Op::decode(&record)
                .ok_or_else(|| StoreError::new("a journal record that does not read"))?;
            out.push((index, op));
        }
        Ok(out)
    }

    // -- Snapshots

    /// The address of a snapshot's part.
    pub(crate) fn snapshot_address(space: &EventId, part: u32) -> Vec<u8> {
        let mut address = of_space(SNAPSHOT, space);
        address.extend_from_slice(&part.to_be_bytes());
        address
    }

    /// A snapshot's records at rest: its parts, in order.
    pub(crate) fn snapshot_puts(space: &EventId, snapshot: &Snapshot) -> Vec<(Vec<u8>, Vec<u8>)> {
        let bytes = snapshot.encode();
        bytes
            .chunks(SNAPSHOT_PART)
            .enumerate()
            .map(|(part, chunk)| {
                (
                    Self::snapshot_address(space, u32::try_from(part).unwrap_or(u32::MAX)),
                    chunk.to_vec(),
                )
            })
            .collect()
    }

    /// A space's records, to open it: its snapshot and the journal after
    /// it. A journal record before the snapshot's `through` is one a fold
    /// already holds, and is left out.
    ///
    /// # Errors
    ///
    /// If the records cannot be read, or the snapshot's parts do not make
    /// one snapshot this peer reads.
    pub(crate) fn opened(&self, space: &EventId) -> Result<Opened, StoreError> {
        let mut opened = Opened::default();
        let parts = self.scan(&of_space(SNAPSHOT, space))?;
        if !parts.is_empty() {
            let mut bytes = Vec::new();
            for (number, (address, part)) in parts.iter().enumerate() {
                let expected = Self::snapshot_address(space, u32::try_from(number).unwrap_or(0));
                if *address != expected {
                    return Err(StoreError::new("a snapshot with a part missing"));
                }
                bytes.extend_from_slice(part);
            }
            opened.snapshot_bytes = bytes.len() as u64;
            opened.snapshot_parts = u32::try_from(parts.len()).unwrap_or(u32::MAX);
            opened.snapshot = Some(
                Snapshot::decode(&bytes)
                    .ok_or_else(|| StoreError::new("a snapshot that does not read"))?,
            );
        }
        let through = opened.snapshot.as_ref().map_or(0, |s| s.through);
        for (address, record) in self.scan(&of_space(JOURNAL, space))? {
            let index = u64::from_be_bytes(
                address[33..]
                    .try_into()
                    .map_err(|_| StoreError::new("a journal address of another length"))?,
            );
            if index < through {
                continue;
            }
            let op = Op::decode(&record)
                .ok_or_else(|| StoreError::new("a journal record that does not read"))?;
            opened.tail.push((index, op, address.len() + record.len()));
        }
        Ok(opened)
    }

    // -- The space index and wait markers

    pub(crate) fn hosted_address(space: &EventId) -> Vec<u8> {
        of_space(HOSTED, space)
    }

    /// A hosted space's index record: `{1: shard}`, the shard that keeps
    /// its records.
    pub(crate) fn hosted_record(shard: &str) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Text(shard.to_owned()));
        Value::Map(map).encode()
    }

    /// The shard a hosted space's index record names.
    pub(crate) fn hosted_shard(record: &[u8]) -> Option<String> {
        let value = cbor::decode(record).ok()?;
        let shard = value.as_map().ok()?.get(&1)?.as_text().ok()?;
        Some(shard.to_owned())
    }

    /// The address of a space's move record.
    pub(crate) fn move_address(space: &EventId) -> Vec<u8> {
        of_space(MOVE, space)
    }

    /// Every move under way: the space and its record.
    pub(crate) fn moves(&self) -> Result<Vec<(EventId, MoveRecord)>, StoreError> {
        Ok(self
            .scan(&[MOVE])?
            .into_iter()
            .filter_map(|(address, record)| {
                let space: [u8; 32] = address.get(1..33)?.try_into().ok()?;
                Some((EventId(space), MoveRecord::decode(&record)?))
            })
            .collect())
    }

    /// The address of a space's offset record.
    pub(crate) fn offset_address(space: &EventId) -> Vec<u8> {
        of_space(OFFSET, space)
    }

    /// Where a move's target keeps the copies its page `page` carried.
    pub(crate) fn arrival_address(space: &EventId, page: u64) -> Vec<u8> {
        let mut address = of_space(ARRIVAL, space);
        address.extend_from_slice(&page.to_be_bytes());
        address
    }

    /// An offset record: `{1: the shard's reading, 2: the space's}`, both
    /// at the move.
    pub(crate) fn offset_record(shard: u64, space: u64) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(shard));
        map.insert(2, Value::Unsigned(space));
        Value::Map(map).encode()
    }

    /// The readings an offset record keeps: the shard's and the space's.
    pub(crate) fn read_offset(record: &[u8]) -> Option<(u64, u64)> {
        let value = cbor::decode(record).ok()?;
        let map = value.as_map().ok()?;
        if map.len() != 2 {
            return None;
        }
        Some((
            map.get(&1)?.as_unsigned().ok()?,
            map.get(&2)?.as_unsigned().ok()?,
        ))
    }

    /// The address of a space's departure record.
    pub(crate) fn departure_address(space: &EventId) -> Vec<u8> {
        of_space(DEPARTURE, space)
    }

    /// Every departure record: the space and its record.
    pub(crate) fn departures(&self) -> Result<Vec<(EventId, Departure)>, StoreError> {
        Ok(self
            .scan(&[DEPARTURE])?
            .into_iter()
            .filter_map(|(address, record)| {
                let space: [u8; 32] = address.get(1..33)?.try_into().ok()?;
                Some((EventId(space), Departure::decode(&record)?))
            })
            .collect())
    }

    /// The address of a closed space's usage record.
    pub(crate) fn usage_address(space: &EventId) -> Vec<u8> {
        of_space(USAGE, space)
    }

    /// A closed space's usage record, if it is at rest.
    pub(crate) fn usage(&self, space: &EventId) -> Result<Option<Vec<u8>>, StoreError> {
        self.get(&Self::usage_address(space))
    }

    pub(crate) fn waits_address(space: &EventId) -> Vec<u8> {
        of_space(WAITS, space)
    }

    /// A wait marker's record: an empty map.
    pub(crate) fn waits_record() -> Vec<u8> {
        Value::Map(Map::new()).encode()
    }

    fn ids_under(&self, prefix: u8) -> Result<BTreeSet<EventId>, StoreError> {
        Ok(self
            .scan(&[prefix])?
            .into_iter()
            .filter_map(|(address, _)| address.get(1..33)?.try_into().ok().map(EventId))
            .collect())
    }

    /// The spaces the index names.
    pub(crate) fn hosted_spaces(&self) -> Result<BTreeSet<EventId>, StoreError> {
        self.ids_under(HOSTED)
    }

    /// The spaces with a wait marker.
    pub(crate) fn waiting_spaces(&self) -> Result<BTreeSet<EventId>, StoreError> {
        self.ids_under(WAITS)
    }

    /// Every record of a space: its journal, its snapshot, its object
    /// index, its index record, its wait marker and a move of it under
    /// way.
    pub(crate) fn space_addresses(&self, space: &EventId) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut out: Vec<Vec<u8>> = self
            .scan(&of_space(JOURNAL, space))?
            .into_iter()
            .map(|(address, _)| address)
            .collect();
        out.push(Self::usage_address(space));
        out.push(Self::offset_address(space));
        for prefix in [OBJECT, SNAPSHOT] {
            out.extend(
                self.scan(&of_space(prefix, space))?
                    .into_iter()
                    .map(|(address, _)| address),
            );
        }
        out.push(Self::hosted_address(space));
        out.push(Self::waits_address(space));
        out.push(Self::move_address(space));
        for (address, _) in self.scan(&of_space(DROP, space))? {
            if let Some(mailbox) = address.get(33..).and_then(|a| <[u8; 32]>::try_from(a).ok()) {
                out.push(Self::drop_locator_address(&mailbox));
            }
            out.push(address);
        }
        Ok(out)
    }

    // -- Libraries (ext-libraries.md, "What a peer keeps")

    /// The address of a library record: `l`, its table, and its key.
    pub(crate) fn library_address(table: u8, key: &[u8]) -> Vec<u8> {
        let mut address = vec![LIBRARY, table];
        address.extend_from_slice(key);
        address
    }

    /// Every library record: its table, its key and the record.
    pub(crate) fn library_records(&self) -> Result<Vec<LibraryRow>, StoreError> {
        Ok(self
            .scan(&[LIBRARY])?
            .into_iter()
            .filter_map(|(address, record)| {
                let table = *address.get(1)?;
                Some((table, address[2..].to_vec(), record))
            })
            .collect())
    }

    // -- Tombstones

    pub(crate) fn tombstone_address(space: &EventId) -> Vec<u8> {
        of_space(TOMBSTONE, space)
    }

    /// Every tombstone: the space and its erasure event.
    pub(crate) fn tombstones(&self) -> Result<Vec<(EventId, Vec<u8>)>, StoreError> {
        self.scan(&[TOMBSTONE])?
            .into_iter()
            .map(|(address, record)| {
                let space: [u8; 32] = address
                    .get(1..33)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| StoreError::new("a tombstone address of another length"))?;
                Ok((EventId(space), record))
            })
            .collect()
    }

    // -- Objects

    pub(crate) fn object_address(space: &EventId, locator: &[u8; 64]) -> Vec<u8> {
        let mut address = of_space(OBJECT, space);
        address.extend_from_slice(locator);
        address
    }

    /// A space's object index.
    pub(crate) fn objects(
        &self,
        space: &EventId,
    ) -> Result<Vec<([u8; 64], ObjectRecord)>, StoreError> {
        self.scan(&of_space(OBJECT, space))?
            .into_iter()
            .map(|(address, record)| {
                let locator: [u8; 64] = address
                    .get(33..)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| StoreError::new("an object address of another length"))?;
                let record = ObjectRecord::decode(&record)
                    .ok_or_else(|| StoreError::new("an object record that does not read"))?;
                Ok((locator, record))
            })
            .collect()
    }

    // -- Device mailboxes

    pub(crate) fn mailbox_address(address: &[u8; 32], id: &[u8; 16]) -> Vec<u8> {
        let mut out = vec![MAILBOX];
        out.extend_from_slice(address);
        out.extend_from_slice(id);
        out
    }

    /// The prefix of the records of the mailboxes whose address begins with
    /// `first`: a 256th of the mailboxes, so that reading them all never
    /// holds every item in memory at once.
    pub(crate) fn mailbox_prefix(first: u8) -> [u8; 2] {
        [MAILBOX, first]
    }

    /// The mailbox items among `found`, the records scanned under a
    /// [`Self::mailbox_prefix`]: each one's mailbox's address, its ID, and
    /// what its record says besides the item, with the item's length.
    #[allow(clippy::type_complexity)]
    pub(crate) fn mailbox_items(
        found: frasil_store::store::Records,
    ) -> Result<Vec<([u8; 32], [u8; 16], MailboxItem, usize)>, StoreError> {
        let unread = || StoreError::new("a mailbox record that does not read");
        found
            .into_iter()
            .map(|(address, record)| {
                let mailbox: [u8; 32] = address
                    .get(1..33)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| StoreError::new("a mailbox address of another length"))?;
                let id: [u8; 16] = address
                    .get(33..)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| StoreError::new("a mailbox address of another length"))?;
                let (kept, item) = Self::read_mailbox_record(&record).ok_or_else(unread)?;
                Ok((mailbox, id, kept, item.len()))
            })
            .collect()
    }

    /// A mailbox item, if it is kept.
    pub(crate) fn mailbox_item(
        &self,
        address: &[u8; 32],
        id: &[u8; 16],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(record) = self.get(&Self::mailbox_address(address, id))? else {
            return Ok(None);
        };
        Self::read_mailbox_record(&record)
            .map(|(_, item)| Some(item))
            .ok_or_else(|| StoreError::new("a mailbox record that does not read"))
    }

    /// A mailbox item's record read: what it says of the item, and the
    /// item. `{1: sight, 2: item, 3: 1?, 4: 1?}`: key 3 marks an item a
    /// deposit token paid for, key 4 one that came while its mailbox was
    /// not claimed. A record kept before either key existed has neither,
    /// and reads as an anonymous item of a claimed mailbox, kept for
    /// `mailbox_retention` as it was.
    pub(crate) fn read_mailbox_record(record: &[u8]) -> Option<(MailboxItem, Vec<u8>)> {
        let value = cbor::decode(record).ok()?;
        let map = value.as_map().ok()?;
        if !map.keys().all(|key| (1..=4).contains(key)) {
            return None;
        }
        let flag = |key: u64| match map.get(&key) {
            None => Some(false),
            Some(value) => (value.as_unsigned().ok()? == 1).then_some(true),
        };
        let kept = MailboxItem {
            sight: map.get(&1)?.as_unsigned().ok()?,
            paid: flag(3)?,
            unclaimed: flag(4)?,
        };
        let item = map.get(&2)?.as_bytes().ok()?;
        Some((kept, item.to_vec()))
    }

    /// A mailbox item's record.
    pub(crate) fn mailbox_record(kept: MailboxItem, item: &[u8]) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(kept.sight));
        map.insert(2, Value::from(item));
        if kept.paid {
            map.insert(3, Value::Unsigned(1));
        }
        if kept.unclaimed {
            map.insert(4, Value::Unsigned(1));
        }
        Value::Map(map).encode()
    }

    /// A device mailbox's claim's address: `c` and the mailbox's address.
    pub(crate) fn claim_address(address: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![CLAIM];
        out.extend_from_slice(address);
        out
    }

    /// A device mailbox's claim's record: `{1: last collection, 2: the
    /// collection the claim began with}`, readings of the timeline, the
    /// second at most the first.
    pub(crate) fn claim_record(last: u64, since: u64) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(last));
        map.insert(2, Value::Unsigned(since));
        Value::Map(map).encode()
    }

    /// A claim's record read: the last collection and the claim's first.
    pub(crate) fn read_claim(record: &[u8]) -> Option<(u64, u64)> {
        let value = cbor::decode(record).ok()?;
        let map = value.as_map().ok()?;
        if map.len() != 2 {
            return None;
        }
        let last = map.get(&1)?.as_unsigned().ok()?;
        let since = map.get(&2)?.as_unsigned().ok()?;
        (since <= last && value.encode() == record).then_some((last, since))
    }

    /// The claims among `found`, the records scanned under `[CLAIM]`: each
    /// mailbox's address and its claim. One that does not read is left
    /// out: its mailbox is not claimed until its device collects again.
    pub(crate) fn claims(found: frasil_store::store::Records) -> Vec<([u8; 32], u64, u64)> {
        found
            .into_iter()
            .filter_map(|(address, record)| {
                let mailbox: [u8; 32] = address.get(1..)?.try_into().ok()?;
                let (last, since) = Self::read_claim(&record)?;
                Some((mailbox, last, since))
            })
            .collect()
    }

    // -- Exchange mailboxes

    /// An exchange message's address: `e`, its mailbox's address, and the
    /// message's kind.
    pub(crate) fn exchange_address(address: &[u8; 32], kind: u8) -> Vec<u8> {
        let mut out = vec![EXCHANGE];
        out.extend_from_slice(address);
        out.push(kind);
        out
    }

    /// An exchange message's record: `{1: wall, 2: source, 3: message}`.
    pub(crate) fn exchange_record(wall: u64, source: &str, message: &[u8]) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(wall));
        map.insert(2, Value::Text(source.to_owned()));
        map.insert(3, Value::from(message));
        Value::Map(map).encode()
    }

    /// An exchange message's record read: its deposit's wall clock, its
    /// source and the message.
    pub(crate) fn read_exchange_record(record: &[u8]) -> Option<(u64, String, Vec<u8>)> {
        let value = cbor::decode(record).ok()?;
        let map = value.as_map().ok()?;
        if map.len() != 3 {
            return None;
        }
        let wall = map.get(&1)?.as_unsigned().ok()?;
        let source = map.get(&2)?.as_text().ok()?;
        let message = map.get(&3)?.as_bytes().ok()?;
        Some((wall, source.to_owned(), message.to_vec()))
    }

    /// Every exchange message kept: its mailbox's address, its deposit's
    /// wall clock, its source and the message.
    #[allow(clippy::type_complexity)]
    pub(crate) fn exchange_messages(
        &self,
    ) -> Result<Vec<([u8; 32], u64, String, Vec<u8>)>, StoreError> {
        let unread = || StoreError::new("an exchange record that does not read");
        self.scan(&[EXCHANGE])?
            .into_iter()
            .map(|(address, record)| {
                let mailbox: [u8; 32] = address
                    .get(1..33)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(unread)?;
                let (wall, source, message) =
                    Self::read_exchange_record(&record).ok_or_else(unread)?;
                Ok((mailbox, wall, source, message))
            })
            .collect()
    }

    // -- Invite drops (ext-invite-links.md)

    /// A drop's address at rest: `d`, its space, and its mailbox address.
    pub(crate) fn drop_address(space: &[u8; 32], address: &[u8; 32]) -> Vec<u8> {
        let mut out = of_space(DROP, &EventId(*space));
        out.extend_from_slice(address);
        out
    }

    /// A drop's record: `{1: entry, 2: placed, 3: lifetime, 4: drop}`.
    pub(crate) fn drop_record(kept: &KeptDrop) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::from(kept.entry));
        map.insert(2, Value::Unsigned(kept.placed));
        map.insert(3, Value::Unsigned(kept.lifetime));
        map.insert(4, Value::from(kept.drop.as_slice()));
        Value::Map(map).encode()
    }

    /// The address of a drop's locator: `a` and its mailbox address.
    pub(crate) fn drop_locator_address(address: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![DROP_AT];
        out.extend_from_slice(address);
        out
    }

    /// A drop's locator: `{1: space}`, the space it was placed for.
    pub(crate) fn drop_locator_record(space: &[u8; 32]) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::from(*space));
        Value::Map(map).encode()
    }

    /// The space a drop's locator names.
    pub(crate) fn drop_locator_space(record: &[u8]) -> Option<[u8; 32]> {
        let value = cbor::decode(record).ok()?;
        let map = value.as_map().ok()?;
        if map.len() != 1 {
            return None;
        }
        map.get(&1)?.as_bytes().ok()?.try_into().ok()
    }

    /// Every drop kept at rest.
    pub(crate) fn drops(&self) -> Result<Vec<KeptDrop>, StoreError> {
        let unread = || StoreError::new("a drop record that does not read");
        self.scan(&[DROP])?
            .into_iter()
            .map(|(address, record)| {
                let space: [u8; 32] = address
                    .get(1..33)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(unread)?;
                let mailbox: [u8; 32] = address
                    .get(33..)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(unread)?;
                let value = cbor::decode(&record).map_err(|_| unread())?;
                let map = value.as_map().map_err(|_| unread())?;
                let entry: [u8; 32] = map
                    .get(&1)
                    .and_then(|v| v.as_bytes().ok())
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(unread)?;
                let unsigned = |key| {
                    map.get(&key)
                        .and_then(|v| v.as_unsigned().ok())
                        .ok_or_else(unread)
                };
                let drop = map
                    .get(&4)
                    .and_then(|v| v.as_bytes().ok())
                    .ok_or_else(unread)?;
                Ok(KeptDrop {
                    space,
                    address: mailbox,
                    entry,
                    placed: unsigned(2)?,
                    lifetime: unsigned(3)?,
                    drop: drop.to_vec(),
                })
            })
            .collect()
    }

    // -- The revision

    fn revision_address() -> Vec<u8> {
        let mut address = vec![META];
        address.extend_from_slice(b"revision");
        address
    }

    /// The record that says the records name each device by its device ID
    /// (crypto.md, "A device's keys").
    fn device_ids_address() -> Vec<u8> {
        let mut address = vec![META];
        address.extend_from_slice(b"device-ids");
        address
    }

    /// Checks that the records were written under this peer's
    /// revision (overview.md, "Version policy"), and records it in records
    /// that host no space yet. Records of another revision, or of none
    /// beside a hosted space, may hold units sealed as no client of this
    /// revision opens them: the peer refuses to start on them.
    ///
    /// Records of this revision written before devices were named by device
    /// ID lack the device-ID record. Their events have no `kc`, and their
    /// snapshots, mailboxes and departure records name devices by their
    /// Ed25519 keys, which this peer would read as device IDs: the peer
    /// refuses to start on them too, and such records are not converted
    /// (overview.md, 5.6 Version policy).
    pub(crate) fn check_revision(&self) -> Result<(), StoreError> {
        let revision = frasil_base::version::REVISION;
        let found = self
            .get(&Self::revision_address())?
            .map(|bytes| match cbor::decode(&bytes) {
                Ok(Value::Unsigned(found)) => Ok(found),
                _ => Err(StoreError::new("the revision record does not read")),
            })
            .transpose()?;
        let refuse = |found: &str| {
            StoreError::new(format!(
                "the records were written under {found}, and this peer runs revision {revision}: its records and objects are not readable by this revision's clients"
            ))
        };
        match found {
            Some(found) if found == revision => match self.get(&Self::device_ids_address())? {
                Some(bytes) if bytes == Self::device_ids_record() => Ok(()),
                _ => Err(StoreError::new(
                    "the records were written before devices were named by device ID, and this peer does not read them: start it from an empty store",
                )),
            },
            Some(found) => Err(refuse(&format!("revision {found}"))),
            None if !self.hosted_spaces()?.is_empty() => Err(refuse("no revision")),
            // Before the writer starts, so straight to the store.
            None => {
                let commit = frasil_store::Commit::new(
                    vec![
                        (Self::revision_address(), Value::from(revision).encode()),
                        (Self::device_ids_address(), Self::device_ids_record()),
                    ],
                    Vec::new(),
                );
                if ready(self.store.commit(&commit))? {
                    Ok(())
                } else {
                    Err(StoreError::new("the revision's commit was refused"))
                }
            }
        }
    }

    /// The device-ID record's bytes.
    fn device_ids_record() -> Vec<u8> {
        Value::Unsigned(1).encode()
    }

    // -- The timeline

    pub(crate) fn timeline_address() -> Vec<u8> {
        let mut address = vec![META];
        address.extend_from_slice(b"timeline");
        address
    }

    /// The reading the peer kept at rest.
    pub(crate) fn kept_reading(&self) -> Result<Option<Reading>, StoreError> {
        Ok(self
            .get(&Self::timeline_address())?
            .and_then(|bytes| cbor::decode(&bytes).ok())
            .and_then(|value| read_reading(&value)))
    }

    /// The record that keeps a reading at rest.
    pub(crate) fn reading_put(reading: &Reading) -> (Vec<u8>, Vec<u8>) {
        (Self::timeline_address(), reading_value(reading).encode())
    }

    /// Keeps a reading at rest.
    #[cfg(test)]
    pub(crate) fn keep_reading(&self, reading: &Reading) -> Result<(), StoreError> {
        self.commit(vec![Self::reading_put(reading)], Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_store::MemoryStore;

    fn reading(t: u64) -> Reading {
        Reading {
            timeline: t,
            wall: Some(t + 10),
            run: 2,
        }
    }

    /// An erasure deletes a move of the space under way with the rest of
    /// its records, so that no move takes an erased space anywhere.
    #[test]
    fn a_spaces_records_include_its_move() {
        let records = Records::new(Arc::new(MemoryStore::new()));
        let space = EventId([5; 32]);
        let addresses = records.space_addresses(&space).unwrap();
        assert!(addresses.contains(&Records::move_address(&space)));
        assert!(addresses.contains(&Records::offset_address(&space)));
    }

    /// A peer upgraded from a version-2 snapshot opens its spaces: units
    /// read with no supersession and no `since`.
    #[test]
    fn a_version_2_snapshot_reads() {
        let unit = KeptUnit {
            id: EventId([1; 32]),
            stream: [2; 16],
            objects: vec![[3; 64]],
            compacts: None,
            supersedes: Vec::new(),
            since: Vec::new(),
        };
        let snapshot = Snapshot {
            through: 1,
            log: vec![4],
            entries: vec![5],
            forks: Vec::new(),
            held: Vec::new(),
            ops: Vec::new(),
            units: vec![unit],
            writer_requests: Vec::new(),
            changes: Vec::new(),
            named: Vec::new(),
            requests: Vec::new(),
            executed: Vec::new(),
            collected: Vec::new(),
            conflicts: Vec::new(),
            request_sights: Vec::new(),
            stubs: Vec::new(),
            imported: Vec::new(),
        };
        let current = snapshot.encode();
        assert_eq!(current[1], 3);
        // Version 2: the version, and the unit `[id, stream, [* locator],
        // compacts]` without its two trailing arrays.
        let unit_head = [&[0x86, 0x58, 0x20][..], &[1; 32]].concat();
        let at = current
            .windows(unit_head.len())
            .position(|w| w == unit_head)
            .unwrap();
        let unit_end = at + unit_head.len() + 1 + 16 + 1 + 2 + 64 + 1;
        assert_eq!(&current[unit_end..unit_end + 2], &[0x80, 0x80]);
        let mut v2 = current[..unit_end].to_vec();
        v2[1] = 2;
        v2[at] = 0x84;
        v2.extend_from_slice(&current[unit_end + 2..]);
        assert_eq!(Snapshot::decode(&v2), Some(snapshot.clone()));
        // A unit of four elements is no version-3 unit.
        v2[1] = 3;
        assert_eq!(Snapshot::decode(&v2), None);
    }

    #[test]
    fn ops_round_trip() {
        let ops = [
            Op::Event {
                signed: vec![1, 2, 3],
                sight: reading(5),
                entry: Some([7; 32]),
            },
            Op::Event {
                signed: vec![4],
                sight: Reading {
                    timeline: 1,
                    wall: None,
                    run: 1,
                },
                entry: None,
            },
            Op::Merge {
                statement: vec![9; 40],
            },
            Op::Proved {
                credential: 2,
                public: [1; 32],
                binding: [2; 32],
                proof: vec![3; 64],
                importing: true,
            },
            Op::Register { key: [4; 32] },
            Op::Executed {
                request: EventId([5; 32]),
            },
            Op::Stub(Stub {
                id: EventId([6; 32]),
                author: DeviceId([7; 32]),
                seq: 3,
                height: 9,
                kind: 4,
                cuts: frasil_events::Cuts::NONE,
            }),
            Op::Stub(Stub {
                id: EventId([6; 32]),
                author: DeviceId([7; 32]),
                seq: 3,
                height: 9,
                kind: 4,
                cuts: frasil_events::Cuts::new(&[EventId([1; 32]), EventId([2; 32])]).unwrap(),
            }),
            Op::Collected {
                snapshot: EventId([8; 32]),
            },
            Op::Since {
                snapshot: EventId([9; 32]),
                since: vec![([3; 64], reading(4))],
            },
            Op::Truncated {
                cut: EventId([10; 32]),
                checkpoint: EventId([11; 32]),
                requests: Vec::new(),
            },
            Op::Truncated {
                cut: EventId([10; 32]),
                checkpoint: EventId([11; 32]),
                requests: vec![EventId([12; 32]), EventId([13; 32])],
            },
        ];
        for op in ops {
            assert_eq!(Op::decode(&op.encode()), Some(op));
        }
        let object = ObjectRecord {
            pieces: [0, 2].into(),
            total: Some(3_000_000),
            complete: false,
            last: reading(8),
            referenced: true,
            entry: None,
        };
        assert_eq!(ObjectRecord::decode(&object.encode()), Some(object));
    }

    #[test]
    fn journals_are_kept_per_space_in_order() {
        let records = Records::new(Arc::new(MemoryStore::new()));
        let a = EventId([1; 32]);
        let b = EventId([0xff; 32]);
        for (space, index) in [(a, 2u64), (a, 1), (b, 0)] {
            records
                .commit(
                    vec![(
                        Records::journal_address(&space, index),
                        Op::Register {
                            key: [index as u8; 32],
                        }
                        .encode(),
                    )],
                    Vec::new(),
                )
                .unwrap();
        }
        let journal = records.journal(&a).unwrap();
        assert_eq!(
            journal.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![1, 2]
        );
        records.keep_reading(&reading(3)).unwrap();
        assert_eq!(records.kept_reading().unwrap(), Some(reading(3)));
    }

    /// A departure record keeps each pseudonym's `ed || kc`, and knows it
    /// by its device ID; a record whose pseudonyms are 32-byte keys does
    /// not read.
    #[test]
    fn a_departure_keeps_pseudonyms_by_device_id() {
        let signer = Signatory {
            ed: frasil_crypto::device::IdentityKey([5; 32]),
            kc: frasil_crypto::device::KeysCommitment([6; 32]),
        };
        let device = signer.device_id().0;
        let mut departure = Departure::default();
        departure.keys[0].insert([1; 32]);
        departure.keys[3].insert([4; 32]);
        departure.pseudonyms.insert(signer.to_bytes());
        assert_eq!(
            Departure::decode(&departure.encode()),
            Some(departure.clone())
        );
        assert!(departure.keeps(3, &device));
        assert_eq!(departure.pseudonym(&device), Some([5; 32]));
        assert!(!departure.keeps(3, &[5; 32]));
        assert!(departure.keeps(1, &[1; 32]) && departure.keeps(4, &[4; 32]));
        let mut map = Map::new();
        for n in 1..=4u64 {
            map.insert(n, Value::Array(vec![Value::from([n as u8; 32])]));
        }
        assert_eq!(Departure::decode(&Value::Map(map).encode()), None);
    }

    /// Records of this revision without the device-ID record were written
    /// before devices were named by device ID: the peer does not start on
    /// them. New records get the record, and open again.
    #[test]
    fn records_from_before_device_ids_are_refused() {
        let records = Records::new(Arc::new(MemoryStore::new()));
        records.check_revision().unwrap();
        records.check_revision().unwrap();
        let old = Records::new(Arc::new(MemoryStore::new()));
        old.commit(
            vec![(
                Records::revision_address(),
                Value::from(frasil_base::version::REVISION).encode(),
            )],
            Vec::new(),
        )
        .unwrap();
        let error = old.check_revision().unwrap_err();
        assert!(error.to_string().contains("device ID"), "{error}");
    }
}
