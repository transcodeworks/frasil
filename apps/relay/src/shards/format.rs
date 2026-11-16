//! The objects of a shard in the bucket: its manifests and its log
//! batches, and the bucket's node records, each deterministic CBOR,
//! version first. This file reads no clock and does no IO.
//!
//! Under the shard's root (`<prefix><shard>/`):
//!
//! ```text
//! manifest-<epoch>-<generation>   a manifest, written once, never overwritten
//! snapshot-<epoch>-<seq>          the shard's SQLite file as of a position
//! log/<epoch>-<seq>               one batch, written once, never overwritten
//! ```
//!
//! A **position** is `(epoch, seq)`: the batch `log/<epoch>-<seq>`, or the
//! start `(0, 0)`. Positions order by epoch, then seq. An owner opens the
//! shard under an epoch above every epoch before it and writes its batches
//! from seq 1, so every position is written at most once. Its manifests
//! are numbered from 1 within its epoch, and each is a new object, so a
//! manifest whose PUT lands late never replaces a later one. The shard's
//! manifest is the one with the greatest `(epoch, generation)` whose
//! snapshot is in the bucket. Every number is written in decimal,
//! zero-padded to 20 digits, so that keys sort as their numbers do.
//!
//! ```text
//! manifest = {0: 1, 1: epoch, 2: snapshot?, 3: [* run], 4: next,
//!             5: reading?, 6: nonce}
//! snapshot = [epoch, seq, bytes]
//! run      = [epoch, first, last]
//! batch    = {0: 1, 1: [* change], 2: reading?}
//! change   = [address, record] / [address]
//! reading  = {1: timeline, 2: run, 3: wall?}
//! ```
//!
//! The manifest names the snapshot the shard opens from, by the position it
//! covers and its size; the runs of batches of earlier epochs after it, which
//! an owner adopted when it opened the shard; and `next`, the first seq of
//! its own `epoch` that the snapshot does not cover. An opener reads the
//! snapshot, the runs, then the manifest's epoch from `next` on until a
//! batch is missing. `nonce` is 16 bytes the owner drew when it opened the
//! shard: an owner that reads back a manifest of its epoch with another
//! nonce, or finds a later one, knows another writer holds the shard. A
//! batch's changes are by address, ascending, each address once: a put, or
//! a delete with no record. Its reading is the shard's timeline when it was
//! written (overview.md, 6.7 Clocks of a replicated peer).
//!
//! Under the bucket's prefix, `nodes/<node>` keeps the epoch a node last
//! started under, `{0: 1, 1: epoch}`, and `nodes/active` the node that
//! writes the bucket now, `{0: 1, 1: epoch, 2: node, 3: nonce}`.

use frasil_base::cbor::{self, Reader};
use frasil_base::time::Reading;

/// The version of the manifest and batch encodings.
pub const VERSION: u64 = 1;

/// A position in a shard's log.
pub type Position = (u64, u64);

/// The key of a batch, under the shard's root.
pub fn log_key(position: Position) -> String {
    format!("log/{:020}-{:020}", position.0, position.1)
}

/// The key of a snapshot, under the shard's root.
pub fn snapshot_key(position: Position) -> String {
    format!("snapshot-{:020}-{:020}", position.0, position.1)
}

/// The prefix of every manifest's key, under the shard's root.
pub const MANIFEST_PREFIX: &str = "manifest-";

/// The key of a manifest, under the shard's root.
pub fn manifest_key(epoch: u64, generation: u64) -> String {
    format!("{MANIFEST_PREFIX}{epoch:020}-{generation:020}")
}

/// What a key under the shard's root names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A batch, at its position.
    Log,
    /// A snapshot, at the position it covers.
    Snapshot,
    /// A manifest, at its epoch and generation.
    Manifest,
}

/// What a key under the shard's root names, and its two numbers.
pub fn parse_key(key: &str) -> Option<(Kind, Position)> {
    let (kind, rest) = if let Some(rest) = key.strip_prefix("log/") {
        (Kind::Log, rest)
    } else if let Some(rest) = key.strip_prefix("snapshot-") {
        (Kind::Snapshot, rest)
    } else {
        (Kind::Manifest, key.strip_prefix(MANIFEST_PREFIX)?)
    };
    let (epoch, seq) = rest.split_once('-')?;
    if epoch.len() != 20 || seq.len() != 20 {
        return None;
    }
    if !epoch.bytes().chain(seq.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((kind, (epoch.parse().ok()?, seq.parse().ok()?)))
}

/// The snapshot a manifest names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotRef {
    /// The position it covers: every batch up to it.
    pub position: Position,
    /// Its size, in bytes.
    pub bytes: u64,
}

/// A run of batches of one epoch, `first` to `last`, both included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    /// The epoch.
    pub epoch: u64,
    /// The first seq.
    pub first: u64,
    /// The last seq.
    pub last: u64,
}

/// A shard's manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The epoch of the owner that wrote it.
    pub epoch: u64,
    /// The snapshot to open from, if any.
    pub snapshot: Option<SnapshotRef>,
    /// The batches of earlier epochs after the snapshot, in order.
    pub runs: Vec<Run>,
    /// The first seq of `epoch` the snapshot does not cover.
    pub next: u64,
    /// The shard's last reading kept, if any.
    pub reading: Option<Reading>,
    /// What the owner drew when it opened the shard.
    pub nonce: [u8; 16],
}

fn reading_into(out: &mut Vec<u8>, reading: &Reading) {
    cbor::map_head(out, 2 + usize::from(reading.wall.is_some()));
    cbor::unsigned(out, 1);
    cbor::unsigned(out, reading.timeline);
    cbor::unsigned(out, 2);
    cbor::unsigned(out, reading.run);
    if let Some(wall) = reading.wall {
        cbor::unsigned(out, 3);
        cbor::unsigned(out, wall);
    }
}

fn read_reading(reader: &mut Reader<'_>) -> Option<Reading> {
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

/// A reading on its own, as a shard's working copy keeps it.
pub fn encode_reading(reading: &Reading) -> Vec<u8> {
    let mut out = Vec::new();
    reading_into(&mut out, reading);
    out
}

/// A reading from [`encode_reading`]'s bytes.
pub fn decode_reading(bytes: &[u8]) -> Option<Reading> {
    let mut reader = Reader::new(bytes);
    let reading = read_reading(&mut reader)?;
    reader.finish().ok()?;
    Some(reading)
}

/// A position on its own, as a shard's working copy keeps it: `[epoch,
/// seq]`.
pub fn encode_position(position: Position) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::array_head(&mut out, 2);
    cbor::unsigned(&mut out, position.0);
    cbor::unsigned(&mut out, position.1);
    out
}

/// A position from [`encode_position`]'s bytes.
pub fn decode_position(bytes: &[u8]) -> Option<Position> {
    let mut reader = Reader::new(bytes);
    if reader.array_len().ok()? != 2 {
        return None;
    }
    let position = (reader.unsigned().ok()?, reader.unsigned().ok()?);
    reader.finish().ok()?;
    Some(position)
}

/// A node's record in the bucket, `nodes/<node>`: `{0: 1, 1: epoch}`, the
/// epoch it last started under (crate `fence`).
pub fn encode_node(epoch: u64) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::map_head(&mut out, 2);
    cbor::unsigned(&mut out, 0);
    cbor::unsigned(&mut out, VERSION);
    cbor::unsigned(&mut out, 1);
    cbor::unsigned(&mut out, epoch);
    out
}

/// The epoch a node's record keeps, if `bytes` are one in its one encoding.
pub fn decode_node(bytes: &[u8]) -> Option<u64> {
    let mut reader = Reader::new(bytes);
    if reader.map_len().ok()? != 2 {
        return None;
    }
    reader.key(0).ok()?;
    if reader.unsigned().ok()? != VERSION {
        return None;
    }
    reader.key(1).ok()?;
    let epoch = reader.unsigned().ok()?;
    reader.finish().ok()?;
    Some(epoch)
}

/// The node that writes the bucket now: its epoch, its name and what it drew
/// when it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Active {
    /// The epoch it started under.
    pub epoch: u64,
    /// Its name.
    pub node: String,
    /// What it drew when it started.
    pub nonce: [u8; 16],
}

impl Active {
    /// Its encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        cbor::map_head(&mut out, 4);
        cbor::unsigned(&mut out, 0);
        cbor::unsigned(&mut out, VERSION);
        cbor::unsigned(&mut out, 1);
        cbor::unsigned(&mut out, self.epoch);
        cbor::unsigned(&mut out, 2);
        cbor::text(&mut out, &self.node);
        cbor::unsigned(&mut out, 3);
        cbor::bytes(&mut out, &self.nonce);
        out
    }

    /// The record, if `bytes` are one in its one encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        if reader.map_len().ok()? != 4 {
            return None;
        }
        reader.key(0).ok()?;
        if reader.unsigned().ok()? != VERSION {
            return None;
        }
        reader.key(1).ok()?;
        let epoch = reader.unsigned().ok()?;
        reader.key(2).ok()?;
        let node = reader.text().ok()?.to_owned();
        reader.key(3).ok()?;
        let nonce = reader.byte_array::<16>().ok()?;
        reader.finish().ok()?;
        Some(Self { epoch, node, nonce })
    }
}

impl Manifest {
    /// The manifest of a shard with nothing written, opened under `epoch`.
    pub fn empty(epoch: u64, nonce: [u8; 16]) -> Self {
        Self {
            epoch,
            snapshot: None,
            runs: Vec::new(),
            next: 1,
            reading: None,
            nonce,
        }
    }

    /// The position the snapshot covers, or the start.
    pub fn base(&self) -> Position {
        self.snapshot.map_or((0, 0), |snapshot| snapshot.position)
    }

    /// Its encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 24 * self.runs.len());
        let count = 5 + usize::from(self.snapshot.is_some()) + usize::from(self.reading.is_some());
        cbor::map_head(&mut out, count);
        cbor::unsigned(&mut out, 0);
        cbor::unsigned(&mut out, VERSION);
        cbor::unsigned(&mut out, 1);
        cbor::unsigned(&mut out, self.epoch);
        if let Some(snapshot) = &self.snapshot {
            cbor::unsigned(&mut out, 2);
            cbor::array_head(&mut out, 3);
            cbor::unsigned(&mut out, snapshot.position.0);
            cbor::unsigned(&mut out, snapshot.position.1);
            cbor::unsigned(&mut out, snapshot.bytes);
        }
        cbor::unsigned(&mut out, 3);
        cbor::array_head(&mut out, self.runs.len());
        for run in &self.runs {
            cbor::array_head(&mut out, 3);
            cbor::unsigned(&mut out, run.epoch);
            cbor::unsigned(&mut out, run.first);
            cbor::unsigned(&mut out, run.last);
        }
        cbor::unsigned(&mut out, 4);
        cbor::unsigned(&mut out, self.next);
        if let Some(reading) = &self.reading {
            cbor::unsigned(&mut out, 5);
            reading_into(&mut out, reading);
        }
        cbor::unsigned(&mut out, 6);
        cbor::bytes(&mut out, &self.nonce);
        out
    }

    /// A manifest, if `bytes` are one of this version in its one encoding
    /// whose positions ascend: the snapshot below every run, each run
    /// non-empty and below the next, every run of an epoch below the
    /// manifest's, and `next` at least 1, above the snapshot within the
    /// manifest's epoch.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let count = reader.map_len().ok()?;
        if !(5..=7).contains(&count) {
            return None;
        }
        reader.key(0).ok()?;
        if reader.unsigned().ok()? != VERSION {
            return None;
        }
        reader.key(1).ok()?;
        let epoch = reader.unsigned().ok()?;
        let mut keys = 5;
        let snapshot = if reader.optional_key(2) {
            keys += 1;
            if reader.array_len().ok()? != 3 {
                return None;
            }
            Some(SnapshotRef {
                position: (reader.unsigned().ok()?, reader.unsigned().ok()?),
                bytes: reader.unsigned().ok()?,
            })
        } else {
            None
        };
        reader.key(3).ok()?;
        let runs_count = reader.array_len().ok()?;
        let mut runs = Vec::with_capacity(runs_count.min(1 << 10));
        let mut last = snapshot.map_or((0, 0), |snapshot| snapshot.position);
        for _ in 0..runs_count {
            if reader.array_len().ok()? != 3 {
                return None;
            }
            let run = Run {
                epoch: reader.unsigned().ok()?,
                first: reader.unsigned().ok()?,
                last: reader.unsigned().ok()?,
            };
            if run.first == 0
                || run.first > run.last
                || run.epoch >= epoch
                || (run.epoch, run.first) <= last
            {
                return None;
            }
            last = (run.epoch, run.last);
            runs.push(run);
        }
        reader.key(4).ok()?;
        let next = reader.unsigned().ok()?;
        if next == 0 || (epoch, next) <= last {
            return None;
        }
        let reading = if reader.optional_key(5) {
            keys += 1;
            Some(read_reading(&mut reader)?)
        } else {
            None
        };
        reader.key(6).ok()?;
        let nonce = reader.byte_array::<16>().ok()?;
        if keys != count {
            return None;
        }
        reader.finish().ok()?;
        Some(Self {
            epoch,
            snapshot,
            runs,
            next,
            reading,
            nonce,
        })
    }
}

/// One batch: the changes of every commit a group made in the shard, the
/// last per address, and the shard's reading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Batch {
    /// Each address changed, ascending, with its record, or `None` for a
    /// delete.
    pub changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    /// The shard's reading when it was written.
    pub reading: Option<Reading>,
}

impl Batch {
    /// Its encoding.
    pub fn encode(&self) -> Vec<u8> {
        let size: usize = self
            .changes
            .iter()
            .map(|(address, record)| address.len() + record.as_ref().map_or(0, Vec::len) + 12)
            .sum();
        let mut out = Vec::with_capacity(size + 48);
        cbor::map_head(&mut out, 2 + usize::from(self.reading.is_some()));
        cbor::unsigned(&mut out, 0);
        cbor::unsigned(&mut out, VERSION);
        cbor::unsigned(&mut out, 1);
        cbor::array_head(&mut out, self.changes.len());
        for (address, record) in &self.changes {
            match record {
                Some(record) => {
                    cbor::array_head(&mut out, 2);
                    cbor::bytes(&mut out, address);
                    cbor::bytes(&mut out, record);
                }
                None => {
                    cbor::array_head(&mut out, 1);
                    cbor::bytes(&mut out, address);
                }
            }
        }
        if let Some(reading) = &self.reading {
            cbor::unsigned(&mut out, 2);
            reading_into(&mut out, reading);
        }
        out
    }

    /// A batch, if `bytes` are one of this version in its one encoding,
    /// its addresses strictly ascending.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let count = reader.map_len().ok()?;
        if !(2..=3).contains(&count) {
            return None;
        }
        reader.key(0).ok()?;
        if reader.unsigned().ok()? != VERSION {
            return None;
        }
        reader.key(1).ok()?;
        let changes_count = reader.array_len().ok()?;
        let mut changes: Vec<(Vec<u8>, Option<Vec<u8>>)> =
            Vec::with_capacity(changes_count.min(1 << 14));
        for _ in 0..changes_count {
            let record = match reader.array_len().ok()? {
                1 => false,
                2 => true,
                _ => return None,
            };
            let address = reader.bytes().ok()?.to_vec();
            if changes.last().is_some_and(|(last, _)| *last >= address) {
                return None;
            }
            let record = if record {
                Some(reader.bytes().ok()?.to_vec())
            } else {
                None
            };
            changes.push((address, record));
        }
        let reading = if count == 3 {
            reader.key(2).ok()?;
            Some(read_reading(&mut reader)?)
        } else {
            None
        };
        reader.finish().ok()?;
        Some(Self { changes, reading })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(t: u64) -> Reading {
        Reading {
            timeline: t,
            run: 2,
            wall: Some(1_700_000_000 + t),
        }
    }

    #[test]
    fn manifests_and_batches_read_back() {
        let manifest = Manifest {
            epoch: 7,
            snapshot: Some(SnapshotRef {
                position: (3, 9),
                bytes: 4096,
            }),
            runs: vec![
                Run {
                    epoch: 3,
                    first: 10,
                    last: 12,
                },
                Run {
                    epoch: 5,
                    first: 1,
                    last: 1,
                },
            ],
            next: 1,
            reading: Some(reading(40)),
            nonce: [5; 16],
        };
        assert_eq!(Manifest::decode(&manifest.encode()), Some(manifest.clone()));
        let empty = Manifest::empty(1, [0; 16]);
        assert_eq!(Manifest::decode(&empty.encode()), Some(empty));
        // A run at or before the snapshot's position does not read.
        let mut bad = manifest.clone();
        bad.runs[0].first = 9;
        assert_eq!(Manifest::decode(&bad.encode()), None);
        let mut bad = manifest;
        bad.runs[1].epoch = 7;
        assert_eq!(Manifest::decode(&bad.encode()), None);

        let batch = Batch {
            changes: vec![(vec![1], Some(vec![2, 3])), (vec![1, 0], None)],
            reading: Some(reading(5)),
        };
        assert_eq!(Batch::decode(&batch.encode()), Some(batch.clone()));
        let mut unordered = batch.clone();
        unordered.changes.swap(0, 1);
        assert_eq!(Batch::decode(&unordered.encode()), None);
        // Every byte changed, or cut there: no panic, one encoding.
        for bytes in [batch.encode(), Manifest::empty(3, [1; 16]).encode()] {
            for at in 0..bytes.len() {
                for value in [0u8, 0x18, 0x40, 0xff, bytes[at] ^ 1] {
                    let mut changed = bytes.clone();
                    changed[at] = value;
                    for cut in [&changed[..], &changed[..at]] {
                        if let Some(read) = Manifest::decode(cut) {
                            assert_eq!(read.encode(), cut);
                        }
                        if let Some(read) = Batch::decode(cut) {
                            assert_eq!(read.encode(), cut);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn keys_sort_as_positions() {
        let mut keys = [log_key((2, 1)), log_key((1, 10)), log_key((1, 9))];
        keys.sort();
        assert_eq!(
            keys.iter().map(|k| parse_key(k)).collect::<Vec<_>>(),
            vec![
                Some((Kind::Log, (1, 9))),
                Some((Kind::Log, (1, 10))),
                Some((Kind::Log, (2, 1)))
            ]
        );
        assert_eq!(
            parse_key(&snapshot_key((4, 5))),
            Some((Kind::Snapshot, (4, 5)))
        );
        assert_eq!(
            parse_key(&manifest_key(4, 6)),
            Some((Kind::Manifest, (4, 6)))
        );
        let mut manifests = [manifest_key(2, 10), manifest_key(10, 1), manifest_key(2, 9)];
        manifests.sort();
        assert_eq!(manifests.last(), Some(&manifest_key(10, 1)));
        assert_eq!(parse_key("manifest"), None);
        assert_eq!(parse_key("log/1-2"), None);
        let active = Active {
            epoch: 3,
            node: "ab".into(),
            nonce: [7; 16],
        };
        assert_eq!(Active::decode(&active.encode()), Some(active));
    }
}
