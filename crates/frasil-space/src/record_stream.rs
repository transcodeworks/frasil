//! Incremental checkpoint records, with faults deferred in reading-step order.
use crate::{HeardMember, MemberEntry, MemberType, Policy, Record, RecordNotice, SpaceClass};
use frasil_base::{
    ErrorClass,
    cbor::{self, Malformed, Map, Value},
    cbor_stream::{PushReader, Token},
};
use frasil_crypto::sizes::{MLDSA65_PUBLIC, XWING_PUBLIC};
use frasil_crypto::{device::DeviceId, primitives::Sha256Hasher};
use frasil_events::EventId;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A receiver of opened record plaintext.
pub trait RecordSink {
    /// Supplies the next plaintext fragment.
    fn feed(&mut self, plaintext: &[u8]);
}
/// What a successful read retains.
#[derive(Clone, Copy)]
pub enum RecordMode {
    /// Retain the complete typed record.
    Build,
    /// Retain only the comparison digest and space-specific fields.
    Summary,
}
/// A space member's keys 18 through 20.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceFields {
    /// Key 18.
    pub notices: Vec<RecordNotice>,
    /// Key 19.
    pub floor: bool,
    /// Key 20.
    pub named: Vec<EventId>,
}
/// The information needed to compare a record without retaining its members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSummary {
    /// Key 2.
    pub epoch: u64,
    /// Key 3.
    pub previous: Option<EventId>,
    /// SHA-256 of the compared encoding.
    pub compared_digest: [u8; 32],
    /// Keys 18 through 20 by space ID.
    pub space_fields: BTreeMap<[u8; 32], SpaceFields>,
}
/// A completed read.
pub enum ReadRecord {
    /// A complete record.
    Built(Record),
    /// Its comparison summary.
    Summary(RecordSummary),
}
/// A deferred reading failure.
pub enum RecordFault {
    /// A reading step's class.
    Class(SpaceClass),
    /// A reserved key or member type, with the independently readable link.
    Extension(Option<(u64, Option<EventId>)>),
}

/// The longest string the record's schema allows, an ML-DSA-65 key. A
/// longer one never reads as the item it stands in, so the reader passes it
/// on in pieces instead of holding it: inside a row it makes the row
/// `Malformed`, and as the policy (key 5) it is read as it arrives.
const MAX_ITEM: usize = MLDSA65_PUBLIC;

/// The most entries a member entry's array or map holds, other than its
/// capabilities, notices (key 18) and names (key 20): a seniority, slot,
/// claimant or member reference.
const MAX_ENTRY_ARRAY: u64 = 4;

struct Frame {
    discard: bool,
    count: u64,
    remaining: u64,
    value: Value,
    key: Option<u64>,
    last: Option<u64>,
    rows: Option<u64>,
}

/// A single-pass reader. Only an entry's temporary CBOR tree is assembled.
pub struct RecordStream {
    reader: PushReader,
    mode: RecordMode,
    frames: Vec<Frame>,
    root: Option<Value>,
    malformed: bool,
    extension: bool,
    shapes: [Option<SpaceClass>; 4],
    invalid: Option<SpaceClass>,
    commitment: Option<SpaceClass>,
    members: Vec<MemberEntry>,
    heard: Vec<HeardMember>,
    tips: BTreeMap<DeviceId, (u64, EventId)>,
    forks: BTreeMap<DeviceId, u64>,
    last_member: Option<Vec<u8>>,
    last_tip: Option<DeviceId>,
    last_fork: Option<DeviceId>,
    last_heard: Option<DeviceId>,
    fields: BTreeMap<[u8; 32], SpaceFields>,
    hash: Sha256Hasher,
    /// The current row breaks its schema's counts, types or lengths: it is
    /// `Malformed`, and nothing more of it is kept.
    row_fault: bool,
    /// A root key 0, which no record has.
    stray: bool,
    /// The policy (key 5) when it is longer than [`MAX_ITEM`]: read as it
    /// arrives, then its class.
    probe: Option<PolicyProbe>,
    long_policy: Option<SpaceClass>,
}
impl RecordStream {
    /// Starts a read in the selected retention mode.
    pub fn new(mode: RecordMode) -> Self {
        Self {
            reader: PushReader::with_item_limit(cbor::MAX_DEPTH, MAX_ITEM),
            mode,
            frames: Vec::new(),
            root: None,
            malformed: false,
            extension: false,
            shapes: [None; 4],
            invalid: None,
            commitment: None,
            members: Vec::new(),
            heard: Vec::new(),
            tips: BTreeMap::new(),
            forks: BTreeMap::new(),
            last_member: None,
            last_tip: None,
            last_fork: None,
            last_heard: None,
            fields: BTreeMap::new(),
            hash: Sha256Hasher::new(),
            row_fault: false,
            stray: false,
            probe: None,
            long_policy: None,
        }
    }
    fn row(&mut self, key: u64, value: Value) {
        let index = match key {
            4 => 0,
            6 => 1,
            7 => 2,
            _ => 3,
        };
        let result = self.read_row(key, value);
        if let Err(class) = result {
            self.shapes[index].get_or_insert(class);
        }
    }
    fn read_row(&mut self, key: u64, value: Value) -> Result<(), SpaceClass> {
        match key {
            4 => {
                let (mut entry, raw) = MemberEntry::read(&value)?;
                let encoded = entry.member.to_value().encode();
                if self
                    .last_member
                    .as_ref()
                    .is_some_and(|last| *last >= encoded)
                {
                    return Err(Malformed.into());
                }
                self.last_member = Some(encoded);
                if let Some(raw) = raw {
                    if let Err(class) = raw.check_valid() {
                        self.invalid.get_or_insert(class);
                    }
                    let keys = raw.into_keys();
                    if let Err(class) = keys.check(&DeviceId(entry.member.id)) {
                        self.commitment.get_or_insert(class.into());
                    }
                    entry.keys = Some(Arc::new(keys));
                }
                let mut compared = entry.to_value();
                if let Value::Map(map) = &mut compared {
                    for key in 18..=20 {
                        map.remove(&key);
                    }
                }
                hash_value(&mut self.hash, &compared);
                if matches!(self.mode, RecordMode::Summary)
                    && entry.member.kind == MemberType::Space
                {
                    self.fields.insert(
                        entry.member.id,
                        SpaceFields {
                            notices: std::mem::take(&mut entry.notices),
                            floor: entry.floor,
                            named: std::mem::take(&mut entry.named),
                        },
                    );
                }
                if matches!(self.mode, RecordMode::Build) {
                    self.members.push(entry);
                }
            }
            6 => {
                let [author, seq, id] = value.as_array()? else {
                    return Err(Malformed.into());
                };
                let author = DeviceId(author.as_byte_array()?);
                let seq = seq.as_unsigned()?;
                let id = EventId(id.as_byte_array()?);
                if seq == 0 || self.last_tip.is_some_and(|last| last >= author) {
                    return Err(Malformed.into());
                }
                self.last_tip = Some(author);
                if matches!(self.mode, RecordMode::Build) {
                    self.tips.insert(author, (seq, id));
                }
            }
            7 => {
                let [author, seq] = value.as_array()? else {
                    return Err(Malformed.into());
                };
                let author = DeviceId(author.as_byte_array()?);
                let seq = seq.as_unsigned()?;
                if seq == 0 || self.last_fork.is_some_and(|last| last >= author) {
                    return Err(Malformed.into());
                }
                self.last_fork = Some(author);
                if matches!(self.mode, RecordMode::Build) {
                    self.forks.insert(author, seq);
                }
            }
            8 => {
                let (device, seniority, rank, raw) = HeardMember::read(&value)?;
                if self.last_heard.is_some_and(|last| last >= device) {
                    return Err(Malformed.into());
                }
                self.last_heard = Some(device);
                if let Err(class) = raw.check_valid() {
                    self.invalid.get_or_insert(class);
                }
                let keys = raw.into_keys();
                if let Err(class) = keys.check(&device) {
                    self.commitment.get_or_insert(class.into());
                }
                if matches!(self.mode, RecordMode::Build) {
                    self.heard.push(HeardMember {
                        device,
                        seniority,
                        rank,
                        keys: Arc::new(keys),
                    });
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }
    /// Whether a token inside a row breaks the row's schema, by its place:
    /// a container with more entries than the place allows, or, in the
    /// arrays a member entry may hold without bound (notices and names), an
    /// item of another type or length. Such a row is `Malformed` whatever
    /// the rest of it holds, so nothing more of it is kept, and no row holds
    /// more than a bounded tree besides those arrays' items. A reserved
    /// member type found here holds the record, as in the whole record.
    fn breaks_row(&mut self, row: u64, token: &Token<'_>) -> bool {
        let depth = self.frames.len();
        let entry_key = if row == 4 && depth >= 3 && matches!(self.frames[2].value, Value::Map(_)) {
            self.frames[2].key
        } else {
            None
        };
        let index = |frame: &Frame| frame.count - frame.remaining;
        let mut cap = 0;
        match (row, depth) {
            (_, 2) => {
                cap = match row {
                    6 => 3,
                    7 => 2,
                    8 => 6,
                    _ => u64::MAX,
                }
            }
            (4, 3) => {
                cap = match entry_key {
                    Some(3) => crate::Limits::PROTOCOL.max_capabilities as u64,
                    Some(18 | 20) => u64::MAX,
                    _ => MAX_ENTRY_ARRAY,
                }
            }
            (4, 4) => match entry_key {
                Some(1)
                    if index(&self.frames[3]) == 0
                        && matches!(self.frames[3].value, Value::Array(_)) =>
                {
                    if matches!(token, Token::Unsigned(n) if *n >= 4) {
                        self.extension = true;
                    }
                }
                Some(3) => cap = 2,
                Some(18) => return !matches!(token, Token::Array(4)),
                Some(20) => return !matches!(token, Token::Bytes(b) if b.len() == 32),
                _ => {}
            },
            (4, 5) if entry_key == Some(18) => {
                return !match index(&self.frames[4]) {
                    1 => matches!(token, Token::Bytes(b) if b.len() == XWING_PUBLIC),
                    2 => matches!(token, Token::Unsigned(_)),
                    _ => matches!(token, Token::Bytes(b) if b.len() == 32),
                };
            }
            (8, 3) => cap = 3,
            _ => {}
        }
        match token {
            Token::Array(n) => *n > cap,
            Token::Map(n) => *n > cap,
            Token::Long { .. } => true,
            _ => false,
        }
    }

    fn accept(&mut self, token: Token<'_>) -> Result<(), Malformed> {
        if let Token::Part { bytes, last } = token {
            if let Some(probe) = &mut self.probe {
                probe.feed(bytes);
                if last {
                    self.long_policy = self.probe.take().map(PolicyProbe::finish);
                }
            }
            return Ok(());
        }
        // A map's key is unsigned: anything else is not the subset's CBOR,
        // and is never assembled.
        if self
            .frames
            .last()
            .is_some_and(|f| matches!(f.value, Value::Map(_)) && f.key.is_none())
            && !matches!(token, Token::Unsigned(_))
        {
            return Err(Malformed);
        }
        let member_row =
            self.frames.get(1).is_some_and(|f| f.rows == Some(4)) && self.frames.len() >= 2;
        if !member_row {
            hash_token(&mut self.hash, &token);
        }
        let row = if self.frames.len() >= 2 {
            self.frames[1].rows
        } else {
            None
        };
        if let Some(row) = row {
            if self.frames.len() == 2 {
                self.row_fault = false;
            }
            if self.breaks_row(row, &token) {
                self.row_fault = true;
            }
        }
        let rows = if self.frames.len() == 1 {
            self.frames[0].key.filter(|k| matches!(k, 4 | 6 | 7 | 8))
        } else {
            None
        };
        // Still validate every skipped subtree's CBOR, without retaining its values.
        let discard = self.frames.last().is_some_and(|f| f.discard)
            || (row.is_some() && self.frames.len() >= 3 && self.row_fault)
            || (self.frames.len() == 3
                && row == Some(4)
                && self.frames[2].key.is_some_and(|key| key >= 22))
            || (self.frames.is_empty() && !matches!(token, Token::Map(_)))
            || (self.frames.len() == 1
                && self.frames[0].key.is_some_and(|key| match key {
                    1 | 2 => !matches!(token, Token::Unsigned(_)),
                    3 | 5 => !matches!(token, Token::Bytes(_) | Token::Long { text: false, .. }),
                    4 | 6..=8 => !matches!(token, Token::Array(_)),
                    _ => true,
                }))
            || (self.frames.len() == 2
                && self.frames[1].rows.is_some_and(|key| {
                    if key == 4 {
                        !matches!(token, Token::Map(_))
                    } else {
                        !matches!(token, Token::Array(_))
                    }
                }));
        let (value, count) = match token {
            Token::Unsigned(n) => (Value::Unsigned(n), None),
            Token::Bytes(b) => (
                Value::Bytes(if discard { Vec::new() } else { b.to_vec() }),
                None,
            ),
            Token::Text(t) => (
                Value::Text(if discard { String::new() } else { t.into() }),
                None,
            ),
            Token::Array(n) => (Value::Array(Vec::new()), Some(n)),
            Token::Map(n) => (
                Value::Map(Map::new()),
                Some(n.checked_mul(2).ok_or(Malformed)?),
            ),
            Token::Long { text, .. } => {
                if !text && !discard && self.frames.len() == 1 && self.frames[0].key == Some(5) {
                    self.probe = Some(PolicyProbe::new());
                }
                (
                    if text {
                        Value::Text(String::new())
                    } else {
                        Value::Bytes(Vec::new())
                    },
                    None,
                )
            }
            Token::Part { .. } => return Err(Malformed),
        };
        if let Some(count) = count {
            let stream_rows = if matches!(value, Value::Array(_)) {
                rows
            } else {
                None
            };
            if count > 0 {
                self.frames.push(Frame {
                    discard,
                    count,
                    remaining: count,
                    value,
                    key: None,
                    last: None,
                    rows: stream_rows,
                });
                return Ok(());
            }
            if stream_rows == Some(8) {
                self.shapes[3].get_or_insert(Malformed.into());
            }
        }
        self.complete(value)
    }
    fn complete(&mut self, mut value: Value) -> Result<(), Malformed> {
        loop {
            let Some(frame) = self.frames.last_mut() else {
                if self.root.is_some() {
                    return Err(Malformed);
                }
                self.root = Some(value);
                return Ok(());
            };
            frame.remaining -= 1;
            let depth = self.frames.len();
            let entry = depth == 3 && self.frames[1].rows == Some(4);
            let faulted = self.row_fault && depth >= 3 && self.frames[1].rows.is_some();
            let frame = self.frames.last_mut().ok_or(Malformed)?;
            if let Some(key) = frame.rows {
                if std::mem::take(&mut self.row_fault) {
                    let index = match key {
                        4 => 0,
                        6 => 1,
                        7 => 2,
                        _ => 3,
                    };
                    self.shapes[index].get_or_insert(Malformed.into());
                } else {
                    self.row(key, value);
                }
            } else {
                match &mut frame.value {
                    Value::Array(items) => {
                        if !frame.discard && !faulted {
                            items.push(value);
                        }
                    }
                    Value::Map(map) => {
                        if let Some(key) = frame.key.take() {
                            // Only keys a record or entry may hold are kept:
                            // a later document's hold the record, and a root
                            // key 0 is noted.
                            let kept = match depth {
                                1 => (1..=8).contains(&key),
                                _ if entry => key < 22,
                                _ => true,
                            };
                            if !frame.discard && !faulted && kept {
                                map.insert(key, value);
                            }
                        } else {
                            let key = value.as_unsigned()?;
                            if frame.last.is_some_and(|last| last >= key) {
                                return Err(Malformed);
                            }
                            frame.last = Some(key);
                            frame.key = Some(key);
                            if (depth == 1 && key >= 9) || (entry && key >= 22) {
                                self.extension = true;
                            }
                            if depth == 1 && key == 0 {
                                self.stray = true;
                            }
                        }
                    }
                    _ => return Err(Malformed),
                }
            }
            if self.frames.last().is_some_and(|f| f.remaining > 0) {
                return Ok(());
            }
            value = self.frames.pop().ok_or(Malformed)?.value;
        }
    }
    /// Resolves faults by reading step only after the complete plaintext arrived.
    pub fn finish(self) -> Result<ReadRecord, RecordFault> {
        let class = |c| RecordFault::Class(c);
        if self.malformed || self.reader.finish().is_err() {
            return Err(class(Malformed.into()));
        }
        let value = self.root.ok_or_else(|| class(Malformed.into()))?;
        let map = value.as_map().map_err(|e| class(e.into()))?;
        let version = map
            .get(&1)
            .ok_or_else(|| class(Malformed.into()))?
            .as_unsigned()
            .map_err(|e| class(e.into()))?;
        if version != 1 {
            return Err(class(ErrorClass::UnsupportedVersion.into()));
        }
        let link = (|| -> Result<_, Malformed> {
            let epoch = map.get(&2).ok_or(Malformed)?.as_unsigned()?;
            let previous = map
                .get(&3)
                .map(|v| v.as_byte_array().map(EventId))
                .transpose()?;
            if epoch == 0 || previous.is_some() != (epoch > 1) {
                return Err(Malformed);
            }
            Ok((epoch, previous))
        })();
        if self.extension {
            return Err(RecordFault::Extension(link.ok()));
        }
        if ![1, 2, 4, 5, 6, 7].iter().all(|k| map.contains_key(k)) || self.stray {
            return Err(class(Malformed.into()));
        }
        let (epoch, previous) = link.map_err(|e| class(e.into()))?;
        let policy_bytes = map[&5].as_bytes().map_err(|e| class(e.into()))?;
        for (i, k) in [4, 6, 7, 8].iter().enumerate() {
            if let Some(v) = map.get(k) {
                v.as_array().map_err(|e| class(e.into()))?;
            }
            if let Some(c) = self.shapes[i] {
                return Err(class(c));
            }
        }
        if let Some(c) = self.long_policy {
            return Err(class(c));
        }
        let policy = Policy::read(policy_bytes).map_err(class)?;
        if let Some(c) = self.invalid {
            return Err(class(c));
        }
        if let Some(c) = self.commitment {
            return Err(class(c));
        }
        Ok(match self.mode {
            RecordMode::Build => ReadRecord::Built(Record {
                epoch,
                previous,
                members: self.members,
                policy,
                tips: self.tips,
                forks: self.forks,
                heard: self.heard,
            }),
            RecordMode::Summary => ReadRecord::Summary(RecordSummary {
                epoch,
                previous,
                compared_digest: self.hash.finish(),
                space_fields: self.fields,
            }),
        })
    }
}
impl RecordSink for RecordStream {
    fn feed(&mut self, plaintext: &[u8]) {
        if self.malformed {
            return;
        }
        // Move the decoder out so borrowed tokens can be consumed without copying strings.
        let mut reader = std::mem::replace(
            &mut self.reader,
            PushReader::with_item_limit(cbor::MAX_DEPTH, MAX_ITEM),
        );
        reader.push(plaintext);
        loop {
            match reader.next() {
                Ok(Some(token)) => {
                    if self.accept(token).is_err() {
                        self.malformed = true;
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    self.malformed = true;
                    break;
                }
            }
        }
        self.reader = reader;
    }
}

pub(crate) fn hash_value(hash: &mut Sha256Hasher, value: &Value) {
    match value {
        Value::Unsigned(n) => hash_token(hash, &Token::Unsigned(*n)),
        Value::Bytes(b) => hash_token(hash, &Token::Bytes(b)),
        Value::Text(t) => hash_token(hash, &Token::Text(t)),
        Value::Array(a) => {
            hash_token(hash, &Token::Array(a.len() as u64));
            for v in a {
                hash_value(hash, v);
            }
        }
        Value::Map(m) => {
            hash_token(hash, &Token::Map(m.len() as u64));
            for (k, v) in m {
                hash_token(hash, &Token::Unsigned(*k));
                hash_value(hash, v);
            }
        }
        _ => unreachable!(),
    }
}
fn hash_token(hash: &mut Sha256Hasher, token: &Token<'_>) {
    let mut head = Vec::new();
    let (major, n, bytes) = match token {
        Token::Unsigned(n) => (0, *n, &[][..]),
        Token::Bytes(b) => (2, b.len() as u64, *b),
        Token::Text(t) => (3, t.len() as u64, t.as_bytes()),
        Token::Array(n) => (4, *n, &[][..]),
        Token::Map(n) => (5, *n, &[][..]),
        // A string beyond the schema's lengths: the record does not read.
        Token::Long { .. } | Token::Part { .. } => return,
    };
    cbor::head(&mut head, major, n);
    hash.update(&head);
    hash.update(bytes);
}

/// A policy longer than any policy reads, read as it arrives for the class
/// [`Policy::read`] would give it: `UnsupportedVersion` when it is the
/// subset's CBOR, a map whose key 1 is an unsigned integer other than 1,
/// and `Malformed` otherwise, since a policy of version 1 holds at most six
/// small integers.
struct PolicyProbe {
    reader: PushReader,
    /// Open containers: whether a map, entries left, the last key, and
    /// whether a key comes next.
    frames: Vec<(bool, u64, Option<u64>, bool)>,
    map: bool,
    version: Option<u64>,
    malformed: bool,
}

impl PolicyProbe {
    fn new() -> Self {
        Self {
            reader: PushReader::with_item_limit(cbor::MAX_DEPTH, MAX_ITEM),
            frames: Vec::new(),
            map: false,
            version: None,
            malformed: false,
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        if self.malformed {
            return;
        }
        self.reader.push(bytes);
        loop {
            let token = match self.reader.next() {
                Ok(Some(token)) => token,
                Ok(None) => return,
                Err(_) => {
                    self.malformed = true;
                    return;
                }
            };
            let count = match token {
                Token::Part { .. } => continue,
                Token::Array(n) => n,
                Token::Map(n) => n.saturating_mul(2),
                _ => 0,
            };
            let depth = self.frames.len();
            if depth == 0 {
                self.map = matches!(token, Token::Map(_));
            }
            if let Some((map, remaining, last, key_next)) = self.frames.last_mut() {
                *remaining -= 1;
                if *map && *key_next {
                    let Token::Unsigned(key) = token else {
                        self.malformed = true;
                        return;
                    };
                    if last.is_some_and(|last| last >= key) {
                        self.malformed = true;
                        return;
                    }
                    *last = Some(key);
                    *key_next = false;
                } else {
                    if depth == 1
                        && *map
                        && *last == Some(1)
                        && let Token::Unsigned(version) = token
                    {
                        self.version = Some(version);
                    }
                    *key_next = *map;
                }
            }
            if count > 0 {
                self.frames
                    .push((matches!(token, Token::Map(_)), count, None, true));
            }
            while self.frames.last().is_some_and(|f| f.1 == 0) {
                self.frames.pop();
            }
        }
    }

    fn finish(self) -> SpaceClass {
        let read = !self.malformed && self.reader.finish().is_ok() && self.map;
        if read && self.version.is_some_and(|version| version != 1) {
            ErrorClass::UnsupportedVersion.into()
        } else {
            Malformed.into()
        }
    }
}
