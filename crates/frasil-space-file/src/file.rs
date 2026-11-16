//! A file read whole (ext-space-files.md, "The file", "Order and limits",
//! "Appending and truncation"), sniffed, and written.
//!
//! A file is segments: the export's, then one per append, each ending with
//! its manifest. A reader takes the last manifest it reads whole and the
//! records before it; a tail after it that does not read is an unfinished
//! append, and is ignored; a record that does not read followed by a
//! manifest that does refuses the file.

use crate::SpaceFileClass;
use crate::record::{
    History, LAST_RESERVED_TYPE, MAGIC, MAGIC_PREFIX, MAX_RECORD_BYTES, Manifest, Record, Section,
    WayIn,
};
use frasil_adapter::Locator;
use frasil_base::ErrorClass;
use frasil_base::errors::Class;
use std::collections::BTreeMap;

/// Why a read stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A shared class.
    Class(ErrorClass),
    /// The file does not begin with the magic.
    NotASpaceFile,
}

impl Refusal {
    /// The class's name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Class(class) => class.name(),
            Self::NotASpaceFile => SpaceFileClass::NotASpaceFile.name(),
        }
    }
}

impl From<ErrorClass> for Refusal {
    fn from(class: ErrorClass) -> Self {
        Self::Class(class)
    }
}

/// An embedded object's parts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmbeddedObject {
    /// The header's bytes.
    pub header: Vec<u8>,
    /// The sealed chunks, by index.
    pub chunks: BTreeMap<u64, Vec<u8>>,
}

/// A file read whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// The last manifest read whole: what the file holds.
    pub manifest: Manifest,
    /// The first manifest: the export's.
    pub first: Manifest,
    /// The way in, if any.
    pub way_in: Option<WayIn>,
    /// The space snapshot, in a history-free file.
    pub snapshot: Option<Vec<u8>>,
    /// Every signed event, in the file's order.
    pub events: Vec<Vec<u8>>,
    /// The embedded objects, by locator.
    pub objects: BTreeMap<Locator, EmbeddedObject>,
    /// The sections, by kind and name, the later of two alike winning.
    pub sections: Vec<Section>,
    /// Whether a tail after the last manifest was ignored.
    pub truncated: bool,
    /// How many bytes the file as the last manifest describes it has:
    /// where an append writes.
    pub whole: usize,
}

/// Checks the magic.
///
/// # Errors
///
/// `UnsupportedVersion` for a magic of another version; `NotASpaceFile`
/// for anything else.
pub fn read_magic(data: &[u8]) -> Result<(), Refusal> {
    let Some(head) = data.get(..MAGIC.len()) else {
        return Err(Refusal::NotASpaceFile);
    };
    if head == MAGIC {
        return Ok(());
    }
    let version = &head[MAGIC_PREFIX.len()..];
    if head.starts_with(MAGIC_PREFIX)
        && version.ends_with(b"\n")
        && version[..version.len() - 1].iter().all(u8::is_ascii_digit)
        && version.len() > 1
    {
        return Err(ErrorClass::UnsupportedVersion.into());
    }
    Err(Refusal::NotASpaceFile)
}

/// Each framed record's offset and body, stopping at a length past the end
/// of the data; a length over the limit is `TooLarge`, wherever it stands
/// ("The file"), and ends the walk.
fn walk(data: &[u8]) -> impl Iterator<Item = Result<(usize, &[u8]), Refusal>> {
    let mut at = MAGIC.len();
    let mut done = false;
    core::iter::from_fn(move || {
        if done {
            return None;
        }
        let length = data.get(at..at + 4)?;
        let n = usize::try_from(u32::from_be_bytes([
            length[0], length[1], length[2], length[3],
        ]))
        .ok()?;
        if n > MAX_RECORD_BYTES {
            done = true;
            return Some(Err(ErrorClass::TooLarge.into()));
        }
        let body = data.get(at + 4..at + 4 + n)?;
        let start = at;
        at += 4 + n;
        Some(Ok((start, body)))
    })
}

/// Reads a file whole.
///
/// # Errors
///
/// The magic's; `Malformed` for a file with no manifest read whole, a
/// record that does not read before one, a manifest that differs from the
/// first in space, kind, streams, history or exporter, or an order rule
/// broken; `UnsupportedVersion` for a reserved record type and `TooLarge`
/// for a length over the limit, wherever either stands.
pub fn read(data: &[u8]) -> Result<Read, Refusal> {
    read_magic(data)?;
    let malformed = Refusal::Class(ErrorClass::Malformed);
    let mut records: Vec<(usize, Record)> = Vec::new();
    let mut manifests: Vec<usize> = Vec::new();
    let mut bad_after: Option<usize> = None;
    let mut truncated = false;
    let mut walked_to = MAGIC.len();
    for next in walk(data) {
        let (at, body) = next?;
        walked_to = at + 4 + body.len();
        match Record::read(body) {
            Ok(record) => {
                if matches!(record, Record::Manifest(_)) {
                    if bad_after.is_some() {
                        return Err(malformed);
                    }
                    manifests.push(records.len());
                }
                records.push((at, record));
            }
            Err(ErrorClass::Malformed) if !manifests.is_empty() => {
                bad_after.get_or_insert(records.len());
                truncated = true;
            }
            Err(class) => return Err(class.into()),
        }
    }
    if walked_to < data.len() {
        // A length past the end, after the records read: a tail cut short.
        truncated = true;
    }
    let Some(&last) = manifests.last() else {
        return Err(malformed);
    };
    if records.len() > last + 1 {
        truncated = true;
    }
    let whole = records[last].0 + 4 + records[last].1.body().len();
    records.truncate(last + 1);
    if let Some(bad) = bad_after {
        records.truncate(bad);
    }
    let first = match &records[manifests[0]].1 {
        Record::Manifest(manifest) => manifest.clone(),
        _ => unreachable!("indexed as a manifest"),
    };
    let manifest = match &records[last].1 {
        Record::Manifest(manifest) => manifest.clone(),
        _ => unreachable!("indexed as a manifest"),
    };
    for &index in &manifests[1..] {
        if let Record::Manifest(later) = &records[index].1
            && (later.space != first.space
                || later.kind != first.kind
                || later.streams != first.streams
                || later.history != first.history
                || later.exporter != first.exporter)
        {
            return Err(malformed);
        }
    }
    // Order: one way in and one snapshot, in the export's segment before
    // any event; chunks after their header.
    let mut way_in = None;
    let mut snapshot = None;
    let mut seen_event = false;
    let mut events = Vec::new();
    let mut objects: BTreeMap<Locator, EmbeddedObject> = BTreeMap::new();
    // A later section of the same kind and name takes the earlier's place
    // at the end of the list: the earlier one's slot empties.
    let mut sections: Vec<Option<Section>> = Vec::new();
    let mut section_at: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for (index, (_, record)) in records.iter().enumerate() {
        match record {
            Record::WayIn(found) => {
                if way_in.is_some() || seen_event || index > manifests[0] {
                    return Err(malformed);
                }
                way_in = Some(found.clone());
            }
            Record::Snapshot(signed) => {
                if snapshot.is_some()
                    || seen_event
                    || index > manifests[0]
                    || first.history != History::FromSnapshot
                {
                    return Err(malformed);
                }
                snapshot = Some(signed.clone());
            }
            Record::Event(signed) => {
                seen_event = true;
                events.push(signed.clone());
            }
            Record::ObjectHeader { locator, header } => {
                objects.entry(*locator).or_default().header = header.clone();
            }
            Record::ObjectChunk {
                locator,
                index,
                chunk,
            } => {
                let Some(object) = objects.get_mut(locator) else {
                    return Err(malformed);
                };
                object.chunks.insert(*index, chunk.clone());
            }
            Record::Section(section) => {
                let key = (section.kind.as_str(), section.name.as_str());
                if let Some(earlier) = section_at.insert(key, sections.len()) {
                    sections[earlier] = None;
                }
                sections.push(Some(section.clone()));
            }
            Record::Manifest(_) | Record::Ignored(_) => {}
        }
    }
    if (first.history == History::FromSnapshot) != snapshot.is_some() {
        return Err(malformed);
    }
    Ok(Read {
        manifest,
        first,
        way_in,
        snapshot,
        events,
        objects,
        sections: sections.into_iter().flatten().collect(),
        truncated,
        whole,
    })
}

/// What a sniff finds: the magic, the way in's record and the first
/// manifest, with no event decoded and nothing opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sniffed {
    /// The first manifest.
    pub manifest: Manifest,
    /// The way in: `None`, or whether it is sealed.
    pub way_in: Option<bool>,
}

/// Sniffs a file: walks the records by their lengths and types to the
/// first manifest.
///
/// # Errors
///
/// The magic's; `Malformed` with no manifest, or a record whose type does
/// not read; `UnsupportedVersion` for a reserved record type and
/// `TooLarge` for a length over the limit, before the first manifest.
pub fn sniff(data: &[u8]) -> Result<Sniffed, Refusal> {
    read_magic(data)?;
    let mut way_in = None;
    for next in walk(data) {
        let (_, body) = next?;
        let code = Record::type_of(body)?;
        match code {
            0 => {
                if let Record::Manifest(manifest) = Record::read(body)? {
                    return Ok(Sniffed { manifest, way_in });
                }
            }
            1 => {
                if let Record::WayIn(found) = Record::read(body)? {
                    way_in = Some(matches!(found, WayIn::Sealed(_)));
                }
            }
            code if code > LAST_RESERVED_TYPE || (2..=6).contains(&code) => {}
            _ => return Err(ErrorClass::UnsupportedVersion.into()),
        }
    }
    Err(ErrorClass::Malformed.into())
}

/// Writes a file, or a segment appended to one: records framed one after
/// the other, the manifest last.
#[derive(Debug, Clone, Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// A new file: the magic.
    pub fn new() -> Self {
        Self {
            out: MAGIC.to_vec(),
        }
    }

    /// An append to a file read whole: the bytes the last manifest
    /// describes, which the appended records follow.
    pub fn appending(data: &[u8], read: &Read) -> Self {
        Self {
            out: data[..read.whole].to_vec(),
        }
    }

    /// Writes one record.
    ///
    /// # Errors
    ///
    /// `TooLarge` for a body over the limit.
    pub fn record(&mut self, record: &Record) -> Result<&mut Self, ErrorClass> {
        self.out.extend_from_slice(&record.encode()?);
        Ok(self)
    }

    /// The bytes so far.
    pub fn bytes(&self) -> &[u8] {
        &self.out
    }

    /// The bytes written.
    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_events::EventId;

    fn manifest(heads: &[u8]) -> Manifest {
        Manifest {
            space: EventId([1; 32]),
            kind: "example.notes".into(),
            heads: heads.iter().map(|h| EventId([*h; 32])).collect(),
            streams: None,
            history: History::Full,
            objects: Vec::new(),
            exporter: frasil_crypto::device::DeviceId([4; 32]),
            time: None,
        }
    }

    #[test]
    fn the_last_manifest_wins_and_a_tail_is_ignored() {
        let mut writer = Writer::new();
        writer
            .record(&Record::Event(vec![1]))
            .unwrap()
            .record(&Record::Manifest(manifest(&[1])))
            .unwrap();
        let base = writer.finish();
        let first = read(&base).unwrap();
        assert_eq!(first.manifest.heads, vec![EventId([1; 32])]);
        assert_eq!(first.whole, base.len());
        let mut writer = Writer::appending(&base, &first);
        writer
            .record(&Record::Event(vec![2]))
            .unwrap()
            .record(&Record::Manifest(manifest(&[2])))
            .unwrap();
        let appended = writer.finish();
        let whole = read(&appended).unwrap();
        assert_eq!(whole.manifest.heads, vec![EventId([2; 32])]);
        assert_eq!(whole.events.len(), 2);
        assert!(!whole.truncated);
        let cut = read(&appended[..base.len() + 5]).unwrap();
        assert!(cut.truncated);
        assert_eq!(cut.events.len(), 1);
        assert_eq!(cut.manifest.heads, vec![EventId([1; 32])]);
        assert_eq!(
            sniff(&appended).unwrap().manifest.heads,
            vec![EventId([1; 32])]
        );
        assert_eq!(read(b"PK").unwrap_err(), Refusal::NotASpaceFile);
        assert_eq!(
            read(b"FRASIL-SPACE-FILE/2\n").unwrap_err(),
            Refusal::Class(ErrorClass::UnsupportedVersion)
        );
    }
}
