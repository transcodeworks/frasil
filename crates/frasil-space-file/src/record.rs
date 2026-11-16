//! The records of a space file (ext-space-files.md, "The file", "Records",
//! "The manifest").
//!
//! ```text
//! file   = magic || record*
//! magic  = "FRASIL-SPACE-FILE/1\n"
//! record = u32be(len(body)) || body            body: deterministic CBOR, a map with key 0 its type
//! ```

use frasil_adapter::Locator;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;

/// The magic: the file's first 20 bytes.
pub const MAGIC: &[u8; 20] = b"FRASIL-SPACE-FILE/1\n";
/// The magic's prefix, before the version.
pub const MAGIC_PREFIX: &[u8] = b"FRASIL-SPACE-FILE/";
/// A record's body is at most one sync message (units.md, "Limits").
pub const MAX_RECORD_BYTES: usize = 1_052_672;
/// An event is at most this long (units.md, "Limits").
pub const MAX_EVENT_BYTES: usize = 1_048_576;
/// The most heads, streams or locators a manifest names.
pub const MAX_ITEMS: usize = 4_096;
/// The longest kind string, in UTF-8 bytes (ext-drive.md, "Values").
pub const MAX_KIND_BYTES: usize = 64;
/// The longest section name or label, in UTF-8 bytes.
pub const MAX_TEXT_BYTES: usize = 255;
/// The shortest sealed chunk: a nonce and a tag (units.md).
pub const MIN_CHUNK_BYTES: usize = 40;
/// The last reserved record type: a reader refuses one it does not know
/// as `UnsupportedVersion`; types above are skipped.
pub const LAST_RESERVED_TYPE: u64 = 63;

const T_MANIFEST: u64 = 0;
const T_WAY_IN: u64 = 1;
const T_EVENT: u64 = 2;
const T_SNAPSHOT: u64 = 3;
const T_OBJECT_HEADER: u64 = 4;
const T_OBJECT_CHUNK: u64 = 5;
const T_SECTION: u64 = 6;

/// Whether a text is a kind string: 1 to 64 bytes of UTF-8 without a
/// control character or white space.
pub fn is_kind(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_KIND_BYTES
        && !text.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Whether a file holds full history or starts from a space snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum History {
    /// Key 5 is 0: every event of the frame and the streams.
    Full,
    /// Key 5 is 1: a space snapshot, then the events after its base.
    FromSnapshot,
}

/// The manifest: the file's state at an export or an append. Its key 9,
/// the revision, is this implementation's when written and checked
/// first when read (overview.md, "Version policy").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Key 1: the space ID.
    pub space: EventId,
    /// Key 2: the application's kind string.
    pub kind: String,
    /// Key 3: the exporter's heads of the space, 1 to 4,096, ascending.
    pub heads: Vec<EventId>,
    /// Key 4: the streams whose units the file holds; `None` for every
    /// stream.
    pub streams: Option<Vec<[u8; 16]>>,
    /// Key 5.
    pub history: History,
    /// Key 6: the objects the file embeds, ascending.
    pub objects: Vec<Locator>,
    /// Key 7: the exporting device's device ID.
    pub exporter: DeviceId,
    /// Key 8: the exporter's wall clock, if known.
    pub time: Option<u64>,
}

/// The way in, as its record carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WayIn {
    /// Key 2: the body in the clear.
    Clear(Vec<u8>),
    /// Key 3: the body's sealed form.
    Sealed(Vec<u8>),
}

/// A section of the application's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Key 2: the kind string.
    pub kind: String,
    /// Key 3: the name, 1 to 255 bytes.
    pub name: String,
    /// Key 4: the bytes.
    pub bytes: Vec<u8>,
}

/// One record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// Type 0.
    Manifest(Manifest),
    /// Type 1.
    WayIn(WayIn),
    /// Type 2: one signed event.
    Event(Vec<u8>),
    /// Type 3: a signed space snapshot.
    Snapshot(Vec<u8>),
    /// Type 4.
    ObjectHeader {
        /// The locator.
        locator: Locator,
        /// The header's bytes.
        header: Vec<u8>,
    },
    /// Type 5.
    ObjectChunk {
        /// The locator.
        locator: Locator,
        /// The chunk's index.
        index: u64,
        /// The sealed chunk.
        chunk: Vec<u8>,
    },
    /// Type 6.
    Section(Section),
    /// A type from 64, which a reader skips.
    Ignored(u64),
}

fn ascending<T: Ord>(items: &[T]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

fn ids(value: &Value, min: usize) -> Result<Vec<EventId>, ErrorClass> {
    let items = value.as_array()?;
    if items.len() < min || items.len() > MAX_ITEMS {
        return Err(ErrorClass::Malformed);
    }
    let out: Vec<EventId> = items
        .iter()
        .map(|v| v.as_byte_array::<32>().map(EventId))
        .collect::<Result<_, _>>()?;
    if !ascending(&out) {
        return Err(ErrorClass::Malformed);
    }
    Ok(out)
}

impl Manifest {
    /// The manifest's body.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(0, T_MANIFEST.into());
        map.insert(1, Value::from(self.space.0.as_slice()));
        map.insert(2, self.kind.as_str().into());
        map.insert(
            3,
            Value::from(
                self.heads
                    .iter()
                    .map(|h| Value::from(h.0.as_slice()))
                    .collect::<Vec<_>>(),
            ),
        );
        if let Some(streams) = &self.streams {
            map.insert(
                4,
                Value::from(
                    streams
                        .iter()
                        .map(|s| Value::from(s.as_slice()))
                        .collect::<Vec<_>>(),
                ),
            );
        }
        map.insert(
            5,
            match self.history {
                History::Full => 0u64,
                History::FromSnapshot => 1,
            }
            .into(),
        );
        map.insert(
            6,
            Value::from(
                self.objects
                    .iter()
                    .map(|l| Value::from(l.as_slice()))
                    .collect::<Vec<_>>(),
            ),
        );
        map.insert(7, Value::from(self.exporter.0.as_slice()));
        if let Some(time) = self.time {
            map.insert(8, time.into());
        }
        map.insert(9, frasil_base::version::REVISION.into());
        Value::Map(map).encode()
    }

    fn read(map: &Map) -> Result<Self, ErrorClass> {
        let malformed = ErrorClass::Malformed;
        // A file of another revision, or of none, is refused before
        // anything else is read of it.
        let revision = match map.get(&9) {
            Some(Value::Unsigned(revision)) => *revision,
            _ => 0,
        };
        frasil_base::version::check_revision(revision)?;
        let keys: Vec<u64> = map.keys().copied().collect();
        if !keys
            .iter()
            .all(|k| [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].contains(k))
            || ![1, 2, 3, 5, 6, 7, 9].iter().all(|k| map.contains_key(k))
        {
            return Err(malformed);
        }
        let kind = map[&2].as_text()?;
        if !is_kind(kind) {
            return Err(malformed);
        }
        let streams = match map.get(&4) {
            None => None,
            Some(value) => {
                let items = value.as_array()?;
                if items.is_empty() || items.len() > MAX_ITEMS {
                    return Err(malformed);
                }
                let out: Vec<[u8; 16]> = items
                    .iter()
                    .map(Value::as_byte_array::<16>)
                    .collect::<Result<_, _>>()?;
                if !ascending(&out) {
                    return Err(malformed);
                }
                Some(out)
            }
        };
        let history = match map[&5].as_unsigned()? {
            0 => History::Full,
            1 => History::FromSnapshot,
            _ => return Err(malformed),
        };
        let objects = {
            let items = map[&6].as_array()?;
            if items.len() > MAX_ITEMS {
                return Err(malformed);
            }
            let out: Vec<Locator> = items
                .iter()
                .map(Value::as_byte_array::<64>)
                .collect::<Result<_, _>>()?;
            if !ascending(&out) {
                return Err(malformed);
            }
            out
        };
        Ok(Self {
            space: EventId(map[&1].as_byte_array::<32>()?),
            kind: kind.to_owned(),
            heads: ids(&map[&3], 1)?,
            streams,
            history,
            objects,
            exporter: DeviceId(map[&7].as_byte_array::<32>()?),
            time: map.get(&8).map(Value::as_unsigned).transpose()?,
        })
    }
}

impl Record {
    /// The record's type.
    pub fn type_code(&self) -> u64 {
        match self {
            Self::Manifest(_) => T_MANIFEST,
            Self::WayIn(_) => T_WAY_IN,
            Self::Event(_) => T_EVENT,
            Self::Snapshot(_) => T_SNAPSHOT,
            Self::ObjectHeader { .. } => T_OBJECT_HEADER,
            Self::ObjectChunk { .. } => T_OBJECT_CHUNK,
            Self::Section(_) => T_SECTION,
            Self::Ignored(code) => *code,
        }
    }

    /// The record's body, deterministic CBOR.
    pub fn body(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(0, self.type_code().into());
        match self {
            Self::Manifest(manifest) => return manifest.encode(),
            Self::WayIn(WayIn::Clear(body)) => {
                map.insert(2, body.as_slice().into());
            }
            Self::WayIn(WayIn::Sealed(sealed)) => {
                map.insert(3, sealed.as_slice().into());
            }
            Self::Event(signed) => {
                map.insert(2, signed.as_slice().into());
            }
            Self::Snapshot(signed) => {
                map.insert(2, signed.as_slice().into());
            }
            Self::ObjectHeader { locator, header } => {
                map.insert(2, locator.as_slice().into());
                map.insert(3, header.as_slice().into());
            }
            Self::ObjectChunk {
                locator,
                index,
                chunk,
            } => {
                map.insert(2, locator.as_slice().into());
                map.insert(3, (*index).into());
                map.insert(4, chunk.as_slice().into());
            }
            Self::Section(section) => {
                map.insert(2, section.kind.as_str().into());
                map.insert(3, section.name.as_str().into());
                map.insert(4, section.bytes.as_slice().into());
            }
            Self::Ignored(_) => {}
        }
        Value::Map(map).encode()
    }

    /// The record framed: `u32be(len(body)) || body`.
    ///
    /// # Errors
    ///
    /// `TooLarge` for a body over 1,052,672 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ErrorClass> {
        let body = self.body();
        if body.len() > MAX_RECORD_BYTES {
            return Err(ErrorClass::TooLarge);
        }
        let length = u32::try_from(body.len()).map_err(|_| ErrorClass::TooLarge)?;
        let mut out = length.to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// A record's type from its body's first bytes, without decoding the
    /// rest: deterministic CBOR puts key 0 first.
    ///
    /// # Errors
    ///
    /// `Malformed` when the body does not begin with a map and key 0.
    pub fn type_of(body: &[u8]) -> Result<u64, ErrorClass> {
        // The map's head: one byte for up to 23 keys, longer for more.
        let (_, after_head) = cbor_head(body, 0, 5)?;
        // Key 0, then the type.
        if body.get(after_head) != Some(&0x00) {
            return Err(ErrorClass::Malformed);
        }
        let (code, _) = cbor_head(body, after_head + 1, 0)?;
        Ok(code)
    }

    /// Reads a record's body, exactly as its type says.
    ///
    /// # Errors
    ///
    /// `Malformed` for a body that is not a map with key 0, a key its type
    /// lacks or lacks, a value of another type, or a limit broken;
    /// `UnsupportedVersion` for a reserved type this reader does not know.
    pub fn read(body: &[u8]) -> Result<Self, ErrorClass> {
        let malformed = ErrorClass::Malformed;
        let value = cbor::decode(body)?;
        let map = value.as_map()?;
        let code = map.get(&0).ok_or(malformed)?.as_unsigned()?;
        let keys = |expected: &[u64]| -> Result<(), ErrorClass> {
            let mut present: Vec<u64> = map.keys().copied().collect();
            present.sort_unstable();
            if present == expected {
                Ok(())
            } else {
                Err(malformed)
            }
        };
        let bytes = |key: u64| -> Result<&[u8], ErrorClass> {
            Ok(map.get(&key).ok_or(malformed)?.as_bytes()?)
        };
        Ok(match code {
            T_MANIFEST => Self::Manifest(Manifest::read(map)?),
            T_WAY_IN => {
                if keys(&[0, 2]).is_ok() {
                    Self::WayIn(WayIn::Clear(bytes(2)?.to_vec()))
                } else {
                    keys(&[0, 3])?;
                    Self::WayIn(WayIn::Sealed(bytes(3)?.to_vec()))
                }
            }
            T_EVENT => {
                keys(&[0, 2])?;
                let signed = bytes(2)?;
                if signed.is_empty() || signed.len() > MAX_EVENT_BYTES {
                    return Err(malformed);
                }
                Self::Event(signed.to_vec())
            }
            T_SNAPSHOT => {
                keys(&[0, 2])?;
                Self::Snapshot(bytes(2)?.to_vec())
            }
            T_OBJECT_HEADER => {
                keys(&[0, 2, 3])?;
                Self::ObjectHeader {
                    locator: map[&2].as_byte_array::<64>()?,
                    header: bytes(3)?.to_vec(),
                }
            }
            T_OBJECT_CHUNK => {
                keys(&[0, 2, 3, 4])?;
                let chunk = bytes(4)?;
                if chunk.len() < MIN_CHUNK_BYTES || chunk.len() > MAX_EVENT_BYTES {
                    return Err(malformed);
                }
                Self::ObjectChunk {
                    locator: map[&2].as_byte_array::<64>()?,
                    index: map[&3].as_unsigned()?,
                    chunk: chunk.to_vec(),
                }
            }
            T_SECTION => {
                keys(&[0, 2, 3, 4])?;
                let kind = map[&2].as_text()?;
                let name = map[&3].as_text()?;
                if !is_kind(kind) || name.is_empty() || name.len() > MAX_TEXT_BYTES {
                    return Err(malformed);
                }
                Self::Section(Section {
                    kind: kind.to_owned(),
                    name: name.to_owned(),
                    bytes: bytes(4)?.to_vec(),
                })
            }
            code if code <= LAST_RESERVED_TYPE => return Err(ErrorClass::UnsupportedVersion),
            code => Self::Ignored(code),
        })
    }
}

/// The argument of the CBOR head at `at`, which must be of `major`, and
/// the offset after it: one byte for an argument below 24, else a length
/// marker and 1, 2, 4 or 8 bytes of argument.
fn cbor_head(body: &[u8], at: usize, major: u8) -> Result<(u64, usize), ErrorClass> {
    let malformed = ErrorClass::Malformed;
    let head = *body.get(at).ok_or(malformed)?;
    if head >> 5 != major {
        return Err(malformed);
    }
    let low = head & 0x1F;
    if low < 24 {
        return Ok((u64::from(low), at + 1));
    }
    let width = match low {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(malformed),
    };
    let bytes = body.get(at + 1..at + 1 + width).ok_or(malformed)?;
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, at + 1 + width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_reads_back_and_its_type_is_its_first_bytes() {
        let manifest = Manifest {
            space: EventId([1; 32]),
            kind: "example.notes".into(),
            heads: vec![EventId([2; 32]), EventId([3; 32])],
            streams: None,
            history: History::Full,
            objects: Vec::new(),
            exporter: DeviceId([4; 32]),
            time: Some(7),
        };
        for record in [
            Record::Manifest(manifest),
            Record::WayIn(WayIn::Sealed(vec![0; 40])),
            Record::Event(vec![9; 3]),
            Record::Snapshot(vec![8; 3]),
            Record::ObjectHeader {
                locator: [5; 64],
                header: vec![6],
            },
            Record::ObjectChunk {
                locator: [5; 64],
                index: 300,
                chunk: vec![0; 40],
            },
            Record::Section(Section {
                kind: "x".into(),
                name: "n".into(),
                bytes: vec![1],
            }),
            Record::Ignored(300),
        ] {
            let framed = record.encode().unwrap();
            let body = &framed[4..];
            assert_eq!(Record::type_of(body), Ok(record.type_code()));
            assert_eq!(Record::read(body), Ok(record));
        }
        assert_eq!(
            Record::read(&Value::Map(Map::from([(0, Value::from(7u64))])).encode()),
            Err(ErrorClass::UnsupportedVersion)
        );
    }
}
