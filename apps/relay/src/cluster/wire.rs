//! The frames of the internal links between a region's nodes, and the
//! bodies this peer reads from them (crate `cluster`, module `link`).
//!
//! Every frame, once opened, is `u8 kind || u64 id || u8 tag || body`: a
//! request, its response under the same `id`, or a notice that has none.
//! Bodies are fields in order: integers big-endian, byte strings and lists
//! with a `u32` length before them, an option as a byte 0 or 1 before its
//! value. A reader takes exactly the bytes a body has, or refuses it. Raft's
//! own messages and commands travel as JSON, whose reader is serde's.
//!
//! An answer larger than a frame travels in pieces: [`PART`] notices under
//! the request's `id`, each a [`Part`], then a response tagged [`PARTS`]
//! whose body is the answer's length; the pieces, in order, are the
//! answer's body. A response tagged [`TOO_LARGE`] says the answer is larger
//! than the link carries.
//!
//! The module depends on nothing but the standard library, so that its fuzz
//! target builds it alone.

/// The most bytes a frame's plaintext may have: a piece of an object and its
/// framing, or a batch of Raft entries. A sender refuses a larger frame
/// rather than send it, and sends a larger answer in [`PART`]s.
pub const MAX_FRAME: usize = 8 << 20;

/// A request to the other node, answered by one response.
pub const REQUEST: u8 = 1;
/// The answer to a request.
pub const RESPONSE: u8 = 2;
/// A message that takes no answer.
pub const NOTICE: u8 = 3;

/// Raft's `AppendEntries`, in JSON.
pub const RAFT_APPEND: u8 = 1;
/// Raft's `Vote`, in JSON.
pub const RAFT_VOTE: u8 = 2;
/// Raft's `InstallSnapshot`, in JSON.
pub const RAFT_SNAPSHOT: u8 = 3;
/// A command for the leader to commit, in JSON.
pub const PROPOSE: u8 = 4;
/// A node asks to join, in JSON.
pub const JOIN: u8 = 5;
/// A read or a batch of a hashed shard this node does not keep:
/// [`ShardRequest`].
pub const SHARD: u8 = 6;
/// A device's message for a space, forwarded to the space's owner:
/// [`Forward`].
pub const FORWARD: u8 = 7;
/// The next part of the answer to a forwarded message, which its owner
/// serves in parts: [`ForwardNext`], answered by a [`ForwardAnswer`].
pub const FORWARD_NEXT: u8 = 22;
/// What an owner sends a gateway's connection: [`Deliver`], a notice.
pub const DELIVER: u8 = 8;
/// A gateway's connection closed, or left a space: [`Closed`], a notice.
pub const CLOSED: u8 = 9;
/// A mailbox deposit or collection, at the node that keeps the mailbox:
/// [`MailboxRequest`].
pub const MAILBOX: u8 = 10;
/// An object piece over HTTP, at the space's owner: [`Piece`].
pub const PIECE: u8 = 11;
/// A gateway's live connections that reach the owner: [`Live`], a notice.
pub const LIVE: u8 = 12;
/// How many device connections a node holds, a `u64`: a notice, every
/// lease, to every member, for balance.
pub const LOAD: u8 = 13;
/// ext-libraries.md: a library's usage, at the owner of its shard: the
/// library's ID as UTF-8, answered by a [`PieceAnswer`].
pub const USAGE: u8 = 14;
/// ext-libraries.md: a step of a library's hand-over to another peer, at
/// the owner of its shard: a [`HandoverRequest`], answered by a
/// [`PieceAnswer`].
pub const HANDOVER: u8 = 20;
/// ext-libraries.md: a library's settings read or set, at the owner of its
/// shard: a [`SettingsRequest`], answered by a [`PieceAnswer`].
pub const SETTINGS: u8 = 21;
/// ext-libraries.md: a page of a space's records moving into a shard, at
/// the owner of that shard: a [`MoveIn`], answered by a [`MoveAnswer`].
pub const MOVE_IN: u8 = 15;
/// A space's records moved into another shard: the space and the shard, a
/// [`Moved`], a notice to every member.
pub const MOVED: u8 = 16;
/// A piece of a large answer, a notice under the request's `id`: a
/// [`Part`].
pub const PART: u8 = 17;
/// The answer to a request, sent before in [`PART`]s: a response whose body
/// is the answer's length, a `u64`.
pub const PARTS: u8 = 18;
/// The answer to a request is larger than the link carries: a response with
/// an empty body.
pub const TOO_LARGE: u8 = 19;
/// A request whose tag the other end does not know: answered by an empty
/// body.
pub const UNKNOWN: u8 = 255;

/// A frame's plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// [`REQUEST`], [`RESPONSE`] or [`NOTICE`].
    pub kind: u8,
    /// The request's number; 0 for a notice.
    pub id: u64,
    /// What the body is.
    pub tag: u8,
    /// The body.
    pub body: Vec<u8>,
}

impl Frame {
    /// The frame's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.body.len());
        out.push(self.kind);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.push(self.tag);
        out.extend_from_slice(&self.body);
        out
    }

    /// Reads a frame, of a known kind and at most [`MAX_FRAME`] bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_FRAME {
            return None;
        }
        let (&kind, rest) = bytes.split_first()?;
        if !matches!(kind, REQUEST | RESPONSE | NOTICE) {
            return None;
        }
        let id = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
        let (&tag, body) = rest.get(8..)?.split_first()?;
        Some(Self {
            kind,
            id,
            tag,
            body: body.to_vec(),
        })
    }
}

/// Writes a body's fields.
#[derive(Debug, Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    /// A byte.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    /// A 16-bit integer.
    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// A 64-bit integer.
    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Bytes of a fixed length.
    pub fn fixed(&mut self, value: &[u8]) -> &mut Self {
        self.0.extend_from_slice(value);
        self
    }

    /// A byte string with its length.
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&length.to_be_bytes());
        self.0.extend_from_slice(value);
        self
    }

    /// A list's length.
    pub fn count(&mut self, count: usize) -> &mut Self {
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&count.to_be_bytes());
        self
    }

    /// A flag.
    pub fn flag(&mut self, value: bool) -> &mut Self {
        self.u8(u8::from(value))
    }

    /// The bytes written.
    pub fn done(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// Reads a body's fields, in order.
#[derive(Debug)]
pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// A reader of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    /// A byte.
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    /// A 16-bit integer.
    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    /// A 64-bit integer.
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    /// Bytes of a fixed length.
    pub fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    /// A byte string with its length.
    pub fn bytes(&mut self) -> Option<Vec<u8>> {
        let length = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        Some(self.take(length)?.to_vec())
    }

    /// A UTF-8 string with its length.
    pub fn text(&mut self) -> Option<String> {
        String::from_utf8(self.bytes()?).ok()
    }

    /// A list's length, no more than the bytes left could hold at `min`
    /// bytes an item. `min` is the fewest bytes an item of the list is
    /// written in, so that a body that reads is never refused for it.
    pub fn count(&mut self, min: usize) -> Option<usize> {
        let count = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        (count.saturating_mul(min.max(1)) <= self.0.len()).then_some(count)
    }

    /// A list's length, as [`Self::count`], and an empty vector to read
    /// its items into. The vector's room is the length, but never more
    /// items of `T` than the bytes left would fill in memory: an item is
    /// often larger in memory than its fewest bytes on the wire, and a
    /// length alone never reserves more than the body's size. The vector
    /// grows past that only as items are read.
    pub fn list<T>(&mut self, min: usize) -> Option<(usize, Vec<T>)> {
        let count = self.count(min)?;
        let room = count.min(self.0.len() / core::mem::size_of::<T>().max(1));
        Some((count, Vec::with_capacity(room)))
    }

    /// Whether the body ends here.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A flag: 0 or 1.
    pub fn flag(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// The value, if the body ends here.
    pub fn end<T>(self, value: T) -> Option<T> {
        self.0.is_empty().then_some(value)
    }
}

/// One change of a batch: an address, and its record or none.
pub type Change = (Vec<u8>, Option<Vec<u8>>);

/// What a node asks of a hashed shard that another keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardOp {
    /// One record.
    Get(Vec<u8>),
    /// The records under a prefix.
    Scan(Vec<u8>),
    /// A batch of changes, made in one step, under a key the asker draws:
    /// its run and a number. A batch sent again under its key is made once.
    Commit {
        /// The asker's run and the batch's number.
        key: (u64, u64),
        /// The changes.
        changes: Vec<Change>,
    },
    /// A batch made only if each address holds what it expects, checked
    /// and made in one step by the keeper, which serializes every such
    /// batch: under a key as `Commit` is, whose outcome a batch sent again
    /// is answered.
    CommitIf {
        /// The asker's run and the batch's number.
        key: (u64, u64),
        /// Each address and what it must hold: its record, or nothing.
        expect: Vec<Change>,
        /// The changes.
        changes: Vec<Change>,
    },
}

/// Writes changes, or expectations, as a count and each address with its
/// record or none.
fn write_changes(w: &mut Writer, changes: &[Change]) {
    w.count(changes.len());
    for (address, record) in changes {
        w.bytes(address);
        match record {
            Some(record) => w.u8(1).bytes(record),
            None => w.u8(0),
        };
    }
}

fn read_changes(r: &mut Reader<'_>) -> Option<Vec<Change>> {
    let (n, mut changes) = r.list(5)?;
    for _ in 0..n {
        let address = r.bytes()?;
        let record = if r.flag()? { Some(r.bytes()?) } else { None };
        changes.push((address, record));
    }
    Some(changes)
}

/// A request for a hashed shard, under the asker's membership epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardRequest {
    /// The asker's epoch.
    pub epoch: u64,
    /// The shard's name.
    pub shard: String,
    /// What it asks.
    pub op: ShardOp,
}

impl ShardRequest {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u64(self.epoch).bytes(self.shard.as_bytes());
        match &self.op {
            ShardOp::Get(address) => w.u8(1).bytes(address),
            ShardOp::Scan(prefix) => w.u8(2).bytes(prefix),
            ShardOp::Commit { key, changes } => {
                w.u8(3).u64(key.0).u64(key.1);
                write_changes(&mut w, changes);
                &mut w
            }
            ShardOp::CommitIf {
                key,
                expect,
                changes,
            } => {
                w.u8(4).u64(key.0).u64(key.1);
                write_changes(&mut w, expect);
                write_changes(&mut w, changes);
                &mut w
            }
        };
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let epoch = r.u64()?;
        let shard = r.text()?;
        let op = match r.u8()? {
            1 => ShardOp::Get(r.bytes()?),
            2 => ShardOp::Scan(r.bytes()?),
            3 => {
                let key = (r.u64()?, r.u64()?);
                let changes = read_changes(&mut r)?;
                ShardOp::Commit { key, changes }
            }
            4 => {
                let key = (r.u64()?, r.u64()?);
                let expect = read_changes(&mut r)?;
                let changes = read_changes(&mut r)?;
                ShardOp::CommitIf {
                    key,
                    expect,
                    changes,
                }
            }
            _ => return None,
        };
        r.end(Self { epoch, shard, op })
    }
}

/// A step of a library's hand-over, at the owner of its shard (crate
/// `libraries`, module `handover`): the step, the library's ID, the address
/// a page of the shard's records starts after, the reading a shard taken
/// in goes on from (its encoding, or empty), and records to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverRequest {
    /// The asker's epoch.
    pub epoch: u64,
    /// The step.
    pub step: u8,
    /// The library's ID.
    pub library: String,
    /// The address a page starts after, or empty.
    pub after: Vec<u8>,
    /// The reading's encoding, or empty.
    pub reading: Vec<u8>,
    /// Records to write: each address and record.
    pub rows: Vec<(Vec<u8>, Vec<u8>)>,
}

impl HandoverRequest {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u64(self.epoch)
            .u8(self.step)
            .bytes(self.library.as_bytes())
            .bytes(&self.after)
            .bytes(&self.reading)
            .count(self.rows.len());
        for (address, record) in &self.rows {
            w.bytes(address).bytes(record);
        }
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let epoch = r.u64()?;
        let step = r.u8()?;
        let library = r.text()?;
        let after = r.bytes()?;
        let reading = r.bytes()?;
        let (n, mut rows) = r.list(8)?;
        for _ in 0..n {
            rows.push((r.bytes()?, r.bytes()?));
        }
        r.end(Self {
            epoch,
            step,
            library,
            after,
            reading,
            rows,
        })
    }
}

/// A library's settings read, or set by the operator's settings route
/// (crate `libraries`): the library's ID, and the route's JSON body for a
/// change, or none for a read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsRequest {
    /// The library's ID.
    pub library: String,
    /// The change, as the route's JSON body; none for a read.
    pub change: Option<Vec<u8>>,
}

impl SettingsRequest {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(self.library.as_bytes());
        match &self.change {
            Some(change) => w.flag(true).bytes(change),
            None => w.flag(false),
        };
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let library = r.text()?;
        let change = if r.flag()? { Some(r.bytes()?) } else { None };
        r.end(Self { library, change })
    }
}

/// What the keeper of a hashed shard answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardAnswer {
    /// The record, or none.
    Found(Option<Vec<u8>>),
    /// The records under the prefix, in order.
    Records(Vec<(Vec<u8>, Vec<u8>)>),
    /// The batch is in the bucket and applied.
    Done,
    /// It failed: the batch may be in the bucket or not.
    Failed(String),
    /// Not this node's shard, at the epoch it names.
    NotMine(u64),
    /// A conditional batch was not made: an address held something else.
    Unmet,
}

impl ShardAnswer {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Self::Found(None) => w.u8(1).u8(0),
            Self::Found(Some(record)) => w.u8(1).u8(1).bytes(record),
            Self::Records(records) => {
                w.u8(2).count(records.len());
                for (address, record) in records {
                    w.bytes(address).bytes(record);
                }
                &mut w
            }
            Self::Done => w.u8(3),
            Self::Failed(text) => w.u8(4).bytes(text.as_bytes()),
            Self::NotMine(epoch) => w.u8(5).u64(*epoch),
            Self::Unmet => w.u8(6),
        };
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let answer = match r.u8()? {
            1 => Self::Found(if r.flag()? { Some(r.bytes()?) } else { None }),
            2 => {
                let (n, mut records) = r.list(8)?;
                for _ in 0..n {
                    records.push((r.bytes()?, r.bytes()?));
                }
                Self::Records(records)
            }
            3 => Self::Done,
            4 => Self::Failed(r.text()?),
            5 => Self::NotMine(r.u64()?),
            6 => Self::Unmet,
            _ => return None,
        };
        r.end(answer)
    }
}

/// A page of a space's records, from the owner of the shard that keeps
/// them to the owner of the shard the space moves into (ext-libraries.md,
/// 3.3 Attaching, Move): the move's record as the index keeps it, and on
/// the last page the space's usage and the copies the move makes into the
/// target library, which its headroom must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveIn {
    /// The asker's epoch.
    pub epoch: u64,
    /// The space.
    pub space: [u8; 32],
    /// The move's record (crate `records`, `MoveRecord`).
    pub intent: Vec<u8>,
    /// The page's number, from 0: page 0 clears what the shard holds of
    /// the space.
    pub page: u64,
    /// Whether this is the last page.
    pub last: bool,
    /// The space's `used_bytes`.
    pub usage: u64,
    /// The space's timeline reading at the move.
    pub reading: u64,
    /// The records of the page, by address.
    pub records: Vec<(Vec<u8>, Vec<u8>)>,
    /// The copies the move made: each copy record's key and bytes (crate
    /// `libraries`, table `C`), into the target library or into the library
    /// the space leaves. A move's copies may span its pages; the target
    /// keeps each page's in its shard, and records them all with its last
    /// step.
    pub copies: Vec<(Vec<u8>, Vec<u8>)>,
    /// On the last page, SHA-256 over every record of the move, in order:
    /// the target names itself only if its shard holds exactly those.
    pub digest: Vec<u8>,
}

fn write_rows(w: &mut Writer, rows: &[(Vec<u8>, Vec<u8>)]) {
    w.count(rows.len());
    for (key, value) in rows {
        w.bytes(key).bytes(value);
    }
}

fn read_rows(r: &mut Reader<'_>) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let (n, mut rows) = r.list(8)?;
    for _ in 0..n {
        rows.push((r.bytes()?, r.bytes()?));
    }
    Some(rows)
}

impl MoveIn {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u64(self.epoch)
            .fixed(&self.space)
            .bytes(&self.intent)
            .u64(self.page)
            .flag(self.last)
            .u64(self.usage)
            .u64(self.reading);
        write_rows(&mut w, &self.records);
        write_rows(&mut w, &self.copies);
        w.bytes(&self.digest);
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let read = Self {
            epoch: r.u64()?,
            space: r.fixed()?,
            intent: r.bytes()?,
            page: r.u64()?,
            last: r.flag()?,
            usage: r.u64()?,
            reading: r.u64()?,
            records: read_rows(&mut r)?,
            copies: read_rows(&mut r)?,
            digest: r.bytes()?,
        };
        r.end(read)
    }
}

/// What the owner of the shard a space moves into answers a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveAnswer {
    /// The page is in the shard; the next may follow.
    Taken,
    /// The last page is in, and the index names the target: the move is
    /// made.
    Done,
    /// The move's record is gone from the index: the move was abandoned,
    /// and the shard keeps nothing of the space.
    Abandoned,
    /// Refused, with a reason code: the move may be abandoned.
    Refused(String),
    /// Not this node's shard, at the epoch it names.
    NotMine(u64),
}

impl MoveAnswer {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Self::Taken => w.u8(1),
            Self::Done => w.u8(2),
            Self::Abandoned => w.u8(3),
            Self::Refused(code) => w.u8(4).bytes(code.as_bytes()),
            Self::NotMine(epoch) => w.u8(5).u64(*epoch),
        };
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let answer = match r.u8()? {
            1 => Self::Taken,
            2 => Self::Done,
            3 => Self::Abandoned,
            4 => Self::Refused(r.text()?),
            5 => Self::NotMine(r.u64()?),
            _ => return None,
        };
        r.end(answer)
    }
}

/// A space whose records moved into another shard, as its source's owner
/// tells every member, so that each routes the space there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    /// The space.
    pub space: [u8; 32],
    /// The shard that keeps its records now.
    pub shard: String,
}

impl Moved {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.fixed(&self.space).bytes(self.shard.as_bytes());
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let read = Self {
            space: r.fixed()?,
            shard: r.text()?,
        };
        r.end(read)
    }
}

/// What a connection sends, as the owner hands it to the gateway: a
/// control message, a space's `Sync`, an object's `Sync` messages, an
/// ephemeral frame, or an ask to close the connection with `reconnect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// A control message.
    Control(Vec<u8>),
    /// A `Sync` of a space.
    Sync([u8; 32], Vec<u8>),
    /// The `Sync` messages of one object transfer.
    Object([u8; 32], Vec<Vec<u8>>),
    /// An `Ephemeral` or `Gone`.
    Ephemeral(Vec<u8>),
    /// Close the device's connection with `reconnect` once nothing holds
    /// it: its live delivery of a space ended at the owner (peers.md, 3.6
    /// Retirement and the cap, "Connections").
    Reconnect,
}

impl Out {
    fn write(&self, w: &mut Writer) {
        match self {
            Self::Control(bytes) => w.u8(1).bytes(bytes),
            Self::Sync(space, bytes) => w.u8(2).fixed(space).bytes(bytes),
            Self::Object(space, messages) => {
                w.u8(3).fixed(space).count(messages.len());
                for message in messages {
                    w.bytes(message);
                }
                w
            }
            Self::Ephemeral(bytes) => w.u8(4).bytes(bytes),
            Self::Reconnect => w.u8(5),
        };
    }

    fn read(r: &mut Reader<'_>) -> Option<Self> {
        Some(match r.u8()? {
            1 => Self::Control(r.bytes()?),
            2 => Self::Sync(r.fixed()?, r.bytes()?),
            3 => {
                let space = r.fixed()?;
                let (n, mut messages) = r.list(4)?;
                for _ in 0..n {
                    messages.push(r.bytes()?);
                }
                Self::Object(space, messages)
            }
            4 => Self::Ephemeral(r.bytes()?),
            5 => Self::Reconnect,
            _ => return None,
        })
    }
}

/// A gateway's connection, as an owner names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkName {
    /// The gateway's node.
    pub node: u64,
    /// The gateway's run: drawn at each start, so that a gateway started
    /// again names none of its old connections.
    pub run: u64,
    /// The connection's number at the gateway.
    pub link: u64,
}

impl LinkName {
    fn write(&self, w: &mut Writer) {
        w.u64(self.node).u64(self.run).u64(self.link);
    }

    fn read(r: &mut Reader<'_>) -> Option<Self> {
        Some(Self {
            node: r.u64()?,
            run: r.u64()?,
            link: r.u64()?,
        })
    }
}

/// A device's message for a space, with what its connection's state at the
/// owner needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    /// The connection.
    pub link: LinkName,
    /// The connection's `binding`.
    pub binding: [u8; 32],
    /// Its purpose's code.
    pub purpose: u8,
    /// Whether it is on the server binding, whose grants carry transfer
    /// tokens.
    pub server: bool,
    /// The remote end, for rate limits.
    pub source: String,
    /// The transfer token a `Present` on the server binding grants, drawn
    /// by the gateway so that a present made again grants the same.
    pub token: Option<[u8; 32]>,
    /// The asker's membership epoch.
    pub epoch: u64,
    /// The space.
    pub space: [u8; 32],
    /// The shard the gateway routes the space to.
    pub shard: String,
    /// The message, as the device sent it.
    pub message: Vec<u8>,
}

impl Forward {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.link.write(&mut w);
        w.fixed(&self.binding)
            .u8(self.purpose)
            .flag(self.server)
            .bytes(self.source.as_bytes());
        match &self.token {
            Some(token) => w.u8(1).fixed(token),
            None => w.u8(0),
        };
        w.u64(self.epoch)
            .fixed(&self.space)
            .bytes(self.shard.as_bytes())
            .bytes(&self.message);
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let link = LinkName::read(&mut r)?;
        let binding = r.fixed()?;
        let purpose = r.u8()?;
        let server = r.flag()?;
        let source = r.text()?;
        let token = if r.flag()? { Some(r.fixed()?) } else { None };
        let epoch = r.u64()?;
        let space = r.fixed()?;
        let shard = r.text()?;
        let message = r.bytes()?;
        r.end(Self {
            link,
            binding,
            purpose,
            server,
            source,
            token,
            epoch,
            space,
            shard,
            message,
        })
    }
}

/// The next part of the answer to a connection's last forwarded message
/// in a space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardNext {
    /// The connection.
    pub link: LinkName,
    /// The space.
    pub space: [u8; 32],
}

impl ForwardNext {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.link.write(&mut w);
        w.fixed(&self.space);
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let link = LinkName::read(&mut r)?;
        let space = r.fixed()?;
        r.end(Self { link, space })
    }
}

/// What an owner answers a forwarded message, or a [`ForwardNext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardAnswer {
    /// The answer to send the device, or its next part; a close code, if
    /// the connection closes; whether an import or a create is under way
    /// on the connection in the space; whether the connection holds a
    /// grant in the space; whether the space is unknown to the peer; and
    /// whether more of the answer follows.
    Answered {
        /// The messages to send, in order.
        out: Vec<Out>,
        /// The close code, if the connection closes.
        close: Option<u64>,
        /// Whether the connection holds an import or a pending create in
        /// the space.
        holding: bool,
        /// Whether the connection holds a grant in the space at the owner,
        /// or an import or a create under way there: only then does its
        /// gateway keep a route for the space.
        granted: bool,
        /// A `Present` was refused `no_library` for a space the peer
        /// neither hosts nor handed over: the gateway may refuse a present
        /// for it so for a while, as the owner would.
        unknown: bool,
        /// More of the answer follows, which the gateway asks for with a
        /// [`ForwardNext`] as the device's connection takes what came.
        more: bool,
    },
    /// Not this node's space, at the epoch it names, or not open yet.
    NotMine(u64),
}

impl ForwardAnswer {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Self::Answered {
                out,
                close,
                holding,
                granted,
                unknown,
                more,
            } => {
                w.u8(1).count(out.len());
                for item in out {
                    item.write(&mut w);
                }
                match close {
                    Some(code) => w.u8(1).u64(*code),
                    None => w.u8(0),
                };
                w.flag(*holding).flag(*granted).flag(*unknown).flag(*more);
            }
            Self::NotMine(epoch) => {
                w.u8(2).u64(*epoch);
            }
        }
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let answer = match r.u8()? {
            1 => {
                // An `Out::Reconnect` is one byte.
                let (n, mut out) = r.list(1)?;
                for _ in 0..n {
                    out.push(Out::read(&mut r)?);
                }
                let close = if r.flag()? { Some(r.u64()?) } else { None };
                let holding = r.flag()?;
                // A body that ends after `holding` names none of the flags
                // after it: its gateway keeps a route for the space, and
                // remembers nothing of it. One that ends after `unknown`
                // holds the whole answer.
                let (granted, unknown) = if r.is_empty() {
                    (true, false)
                } else {
                    (r.flag()?, r.flag()?)
                };
                let more = !r.is_empty() && r.flag()?;
                Self::Answered {
                    out,
                    close,
                    holding,
                    granted,
                    unknown,
                    more,
                }
            }
            2 => Self::NotMine(r.u64()?),
            _ => return None,
        };
        r.end(answer)
    }
}

/// What an owner sends a gateway's connection on its own: a delivery, an
/// `Awaiting`, a relayed ephemeral frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deliver {
    /// The connection, at the gateway.
    pub link: LinkName,
    /// What to send.
    pub out: Out,
}

impl Deliver {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.link.write(&mut w);
        self.out.write(&mut w);
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let link = LinkName::read(&mut r)?;
        let out = Out::read(&mut r)?;
        r.end(Self { link, out })
    }
}

/// A gateway's connection closed, or stopped sending one space here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    /// The connection.
    pub link: LinkName,
    /// The space it left, or none when it closed.
    pub space: Option<[u8; 32]>,
}

impl Closed {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        self.link.write(&mut w);
        match &self.space {
            Some(space) => w.u8(1).fixed(space),
            None => w.u8(0),
        };
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let link = LinkName::read(&mut r)?;
        let space = if r.flag()? { Some(r.fixed()?) } else { None };
        r.end(Self { link, space })
    }
}

/// The connections of one run of a gateway that reach an owner, sent
/// every lease, so that the owner forgets the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Live {
    /// The gateway's run.
    pub run: u64,
    /// The connections' numbers.
    pub links: Vec<u64>,
}

impl Live {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u64(self.run).count(self.links.len());
        for link in &self.links {
            w.u64(*link);
        }
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let run = r.u64()?;
        let (n, mut links) = r.list(8)?;
        for _ in 0..n {
            links.push(r.u64()?);
        }
        r.end(Self { run, links })
    }
}

/// A mailbox request, at the node that keeps the mailbox's shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxRequest {
    /// A deposit.
    Put {
        /// The asker's epoch.
        epoch: u64,
        /// The mailbox kind's code.
        kind: u8,
        /// The mailbox's address.
        address: [u8; 32],
        /// The item.
        item: Vec<u8>,
        /// The depositor, for rate limits.
        source: String,
    },
    /// A collection.
    Get {
        /// The asker's epoch.
        epoch: u64,
        /// The mailbox kind's code.
        kind: u8,
        /// The mailbox's address.
        address: [u8; 32],
        /// The last item collected before.
        after: Option<[u8; 16]>,
        /// A device mailbox's collector: its `ed || kc` (64 bytes), its
        /// signature, and the connection's `binding`, with which the keeper
        /// makes transport.md's checks of a collection.
        collector: Option<([u8; 64], Vec<u8>, [u8; 32])>,
    },
    /// ext-deposit-tokens.md: a deposit in a device mailbox paid with a
    /// token.
    TokenPut {
        /// The asker's epoch.
        epoch: u64,
        /// The mailbox's address.
        address: [u8; 32],
        /// The item.
        item: Vec<u8>,
        /// The token, 129 bytes.
        token: Vec<u8>,
    },
}

impl MailboxRequest {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Self::Put {
                epoch,
                kind,
                address,
                item,
                source,
            } => {
                w.u8(1)
                    .u64(*epoch)
                    .u8(*kind)
                    .fixed(address)
                    .bytes(item)
                    .bytes(source.as_bytes());
            }
            Self::Get {
                epoch,
                kind,
                address,
                after,
                collector,
            } => {
                w.u8(2).u64(*epoch).u8(*kind).fixed(address);
                match after {
                    Some(after) => w.u8(1).fixed(after),
                    None => w.u8(0),
                };
                match collector {
                    Some((key, signature, binding)) => {
                        w.u8(1).fixed(key).bytes(signature).fixed(binding)
                    }
                    None => w.u8(0),
                };
            }
            Self::TokenPut {
                epoch,
                address,
                item,
                token,
            } => {
                w.u8(3).u64(*epoch).fixed(address).bytes(item).bytes(token);
            }
        }
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let request = match r.u8()? {
            3 => Self::TokenPut {
                epoch: r.u64()?,
                address: r.fixed()?,
                item: r.bytes()?,
                token: r.bytes()?,
            },
            1 => Self::Put {
                epoch: r.u64()?,
                kind: r.u8()?,
                address: r.fixed()?,
                item: r.bytes()?,
                source: r.text()?,
            },
            2 => {
                let epoch = r.u64()?;
                let kind = r.u8()?;
                let address = r.fixed()?;
                let after = if r.flag()? { Some(r.fixed()?) } else { None };
                let collector = if r.flag()? {
                    Some((r.fixed()?, r.bytes()?, r.fixed()?))
                } else {
                    None
                };
                Self::Get {
                    epoch,
                    kind,
                    address,
                    after,
                    collector,
                }
            }
            _ => return None,
        };
        r.end(request)
    }
}

/// What a mailbox's keeper answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxAnswer {
    /// The deposit's item ID.
    Put([u8; 16]),
    /// The items collected.
    Items(Vec<([u8; 16], Vec<u8>)>),
    /// Refused: a reason code and its HTTP status.
    Refused(String, u16),
    /// Not this node's mailbox, at the epoch it names.
    NotMine(u64),
}

impl MailboxAnswer {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Self::Put(id) => w.u8(1).fixed(id),
            Self::Items(items) => {
                w.u8(2).count(items.len());
                for (id, item) in items {
                    w.fixed(id).bytes(item);
                }
                &mut w
            }
            Self::Refused(code, status) => w.u8(3).bytes(code.as_bytes()).u16(*status),
            Self::NotMine(epoch) => w.u8(4).u64(*epoch),
        };
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let answer = match r.u8()? {
            1 => Self::Put(r.fixed()?),
            2 => {
                let (n, mut items) = r.list(20)?;
                for _ in 0..n {
                    items.push((r.fixed()?, r.bytes()?));
                }
                Self::Items(items)
            }
            3 => Self::Refused(r.text()?, r.u16()?),
            4 => Self::NotMine(r.u64()?),
            _ => return None,
        };
        r.end(answer)
    }
}

/// An object piece over HTTP, at the space's owner, which keeps the
/// transfer tokens its grants carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    /// A store (`PUT`), or a fetch.
    pub put: bool,
    /// The asker's epoch.
    pub epoch: u64,
    /// The space.
    pub space: [u8; 32],
    /// The object's locator.
    pub locator: [u8; 64],
    /// The piece's index.
    pub index: u64,
    /// The transfer token the request carries.
    pub token: [u8; 32],
    /// A store's bytes.
    pub body: Vec<u8>,
    /// A store's token checked alone, before its bytes are read: the owner
    /// answers whether the token grants the store right, and stores
    /// nothing.
    pub check: bool,
}

impl Piece {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.flag(self.put)
            .u64(self.epoch)
            .fixed(&self.space)
            .fixed(&self.locator)
            .u64(self.index)
            .fixed(&self.token)
            .bytes(&self.body)
            .flag(self.check);
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let piece = Self {
            put: r.flag()?,
            epoch: r.u64()?,
            space: r.fixed()?,
            locator: r.fixed()?,
            index: r.u64()?,
            token: r.fixed()?,
            body: r.bytes()?,
            // A body that ends before the flag is no check.
            check: !r.is_empty() && r.flag()?,
        };
        r.end(piece)
    }
}

/// What the owner answers an object piece: the HTTP status, whether the
/// body is JSON, and the body; or not this node's space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PieceAnswer {
    /// The HTTP answer.
    Answered {
        /// The status.
        status: u16,
        /// Whether the body is JSON, or the piece's bytes.
        json: bool,
        /// The body.
        body: Vec<u8>,
    },
    /// Not this node's space, at the epoch it names.
    NotMine(u64),
}

impl PieceAnswer {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Self::Answered { status, json, body } => w.u8(1).u16(*status).flag(*json).bytes(body),
            Self::NotMine(epoch) => w.u8(2).u64(*epoch),
        };
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let answer = match r.u8()? {
            1 => Self::Answered {
                status: r.u16()?,
                json: r.flag()?,
                body: r.bytes()?,
            },
            2 => Self::NotMine(r.u64()?),
            _ => return None,
        };
        r.end(answer)
    }
}

/// A piece of a large answer: where in the answer's body it starts, and its
/// bytes, to the end of the frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// The offset of its first byte in the answer's body.
    pub offset: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
}

impl Part {
    /// The body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u64(self.offset).fixed(&self.bytes);
        w.done()
    }

    /// Reads a body.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let offset = r.u64()?;
        Some(Self {
            offset,
            bytes: r.0.to_vec(),
        })
    }
}

/// Reads the body of a [`PARTS`] response: the answer's length.
pub fn parts_length(body: &[u8]) -> Option<u64> {
    body.try_into().ok().map(u64::from_be_bytes)
}

/// Reads a body by its frame's kind and tag, and writes it again: what the
/// fuzz target checks. Returns whether the body read.
pub fn round_trip(kind: u8, tag: u8, body: &[u8]) -> bool {
    fn again<T: PartialEq + core::fmt::Debug>(
        read: Option<T>,
        encode: impl Fn(&T) -> Vec<u8>,
        decode: impl Fn(&[u8]) -> Option<T>,
    ) -> bool {
        let Some(read) = read else {
            return false;
        };
        let bytes = encode(&read);
        assert_eq!(decode(&bytes).as_ref(), Some(&read), "a body reads back");
        true
    }
    match (kind, tag) {
        (REQUEST, SHARD) => again(
            ShardRequest::decode(body),
            ShardRequest::encode,
            ShardRequest::decode,
        ),
        (RESPONSE, SHARD) => again(
            ShardAnswer::decode(body),
            ShardAnswer::encode,
            ShardAnswer::decode,
        ),
        (REQUEST, FORWARD) => again(Forward::decode(body), Forward::encode, Forward::decode),
        (RESPONSE, FORWARD) => again(
            ForwardAnswer::decode(body),
            ForwardAnswer::encode,
            ForwardAnswer::decode,
        ),
        (REQUEST, FORWARD_NEXT) => again(
            ForwardNext::decode(body),
            ForwardNext::encode,
            ForwardNext::decode,
        ),
        (RESPONSE, FORWARD_NEXT) => again(
            ForwardAnswer::decode(body),
            ForwardAnswer::encode,
            ForwardAnswer::decode,
        ),
        (NOTICE, DELIVER) => again(Deliver::decode(body), Deliver::encode, Deliver::decode),
        (NOTICE, CLOSED) => again(Closed::decode(body), Closed::encode, Closed::decode),
        (NOTICE, LIVE) => again(Live::decode(body), Live::encode, Live::decode),
        (REQUEST, USAGE) => again(
            String::from_utf8(body.to_vec()).ok(),
            |text: &String| text.as_bytes().to_vec(),
            |bytes: &[u8]| String::from_utf8(bytes.to_vec()).ok(),
        ),
        (RESPONSE, USAGE) => again(
            PieceAnswer::decode(body),
            PieceAnswer::encode,
            PieceAnswer::decode,
        ),
        (REQUEST, MOVE_IN) => again(MoveIn::decode(body), MoveIn::encode, MoveIn::decode),
        (RESPONSE, MOVE_IN) => again(
            MoveAnswer::decode(body),
            MoveAnswer::encode,
            MoveAnswer::decode,
        ),
        (NOTICE, MOVED) => again(Moved::decode(body), Moved::encode, Moved::decode),
        (REQUEST, HANDOVER) => again(
            HandoverRequest::decode(body),
            HandoverRequest::encode,
            HandoverRequest::decode,
        ),
        (RESPONSE, HANDOVER) => again(
            PieceAnswer::decode(body),
            PieceAnswer::encode,
            PieceAnswer::decode,
        ),
        (REQUEST, SETTINGS) => again(
            SettingsRequest::decode(body),
            SettingsRequest::encode,
            SettingsRequest::decode,
        ),
        (RESPONSE, SETTINGS) => again(
            PieceAnswer::decode(body),
            PieceAnswer::encode,
            PieceAnswer::decode,
        ),
        (NOTICE, LOAD) => again(
            body.try_into().ok().map(u64::from_be_bytes),
            |n: &u64| n.to_be_bytes().to_vec(),
            |b: &[u8]| b.try_into().ok().map(u64::from_be_bytes),
        ),
        (REQUEST, MAILBOX) => again(
            MailboxRequest::decode(body),
            MailboxRequest::encode,
            MailboxRequest::decode,
        ),
        (RESPONSE, MAILBOX) => again(
            MailboxAnswer::decode(body),
            MailboxAnswer::encode,
            MailboxAnswer::decode,
        ),
        (NOTICE, PART) => again(Part::decode(body), Part::encode, Part::decode),
        (RESPONSE, PARTS) => again(
            parts_length(body),
            |n: &u64| n.to_be_bytes().to_vec(),
            parts_length,
        ),
        (RESPONSE, TOO_LARGE) => again(
            body.is_empty().then_some(()),
            |_: &()| Vec::new(),
            |b: &[u8]| b.is_empty().then_some(()),
        ),
        (REQUEST, PIECE) => again(Piece::decode(body), Piece::encode, Piece::decode),
        (RESPONSE, PIECE) => again(
            PieceAnswer::decode(body),
            PieceAnswer::encode,
            PieceAnswer::decode,
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hand_over_step_reads_back() {
        let request = HandoverRequest {
            epoch: 2,
            step: 5,
            library: "project:a".into(),
            after: vec![1],
            reading: vec![2, 3],
            rows: vec![(vec![4], vec![5]), (vec![6], vec![])],
        };
        assert!(round_trip(REQUEST, HANDOVER, &request.encode()));
        for change in [None, Some(br#"{"open_until":5}"#.to_vec())] {
            let settings = SettingsRequest {
                library: "project:a".into(),
                change,
            };
            assert!(round_trip(REQUEST, SETTINGS, &settings.encode()));
        }
        let page = MoveIn {
            epoch: 2,
            space: [3; 32],
            intent: vec![4],
            page: 1,
            last: true,
            usage: 5,
            reading: 6,
            records: vec![(vec![7], vec![8])],
            copies: vec![(vec![9], vec![])],
            digest: vec![10; 32],
        };
        assert!(round_trip(REQUEST, MOVE_IN, &page.encode()));
        for answer in [
            MoveAnswer::Taken,
            MoveAnswer::Done,
            MoveAnswer::Abandoned,
            MoveAnswer::Refused("quota_exceeded".into()),
            MoveAnswer::NotMine(3),
        ] {
            assert!(round_trip(RESPONSE, MOVE_IN, &answer.encode()));
        }
        let moved = Moved {
            space: [1; 32],
            shard: "libraries/61".into(),
        };
        assert!(round_trip(NOTICE, MOVED, &moved.encode()));
        assert_eq!(HandoverRequest::decode(&request.encode()), Some(request));
    }

    #[test]
    fn frames_and_bodies_read_back() {
        let frame = Frame {
            kind: REQUEST,
            id: 7,
            tag: SHARD,
            body: ShardRequest {
                epoch: 3,
                shard: "index/a".into(),
                op: ShardOp::Commit {
                    key: (5, 6),
                    changes: vec![(vec![1, 2], Some(vec![3])), (vec![4], None)],
                },
            }
            .encode(),
        };
        let read = Frame::decode(&frame.encode()).unwrap();
        assert_eq!(read, frame);
        assert!(round_trip(read.kind, read.tag, &read.body));
        let answer = ForwardAnswer::Answered {
            out: vec![
                Out::Control(vec![1]),
                Out::Sync([2; 32], vec![3]),
                Out::Object([4; 32], vec![vec![5], vec![]]),
                Out::Ephemeral(vec![6]),
                Out::Reconnect,
            ],
            close: Some(4),
            holding: true,
            granted: true,
            unknown: false,
            more: true,
        };
        assert_eq!(ForwardAnswer::decode(&answer.encode()), Some(answer));
        let next = ForwardNext {
            link: LinkName {
                node: 1,
                run: 2,
                link: 3,
            },
            space: [7; 32],
        };
        assert!(round_trip(REQUEST, FORWARD_NEXT, &next.encode()));
        assert_eq!(ForwardNext::decode(&next.encode()), Some(next));
        let conditional = ShardRequest {
            epoch: 4,
            shard: "index/b".into(),
            op: ShardOp::CommitIf {
                key: (1, 2),
                expect: vec![(vec![7], None), (vec![8], Some(vec![9]))],
                changes: vec![(vec![7], Some(vec![1]))],
            },
        };
        assert_eq!(
            ShardRequest::decode(&conditional.encode()),
            Some(conditional)
        );
        assert_eq!(
            ShardAnswer::decode(&ShardAnswer::Unmet.encode()),
            Some(ShardAnswer::Unmet)
        );
        let get = MailboxRequest::Get {
            epoch: 1,
            kind: 3,
            address: [9; 32],
            after: Some([1; 16]),
            collector: Some(([2; 64], vec![3; 64], [4; 32])),
        };
        assert_eq!(MailboxRequest::decode(&get.encode()), Some(get));
    }

    #[test]
    fn a_body_with_bytes_left_or_missing_is_refused() {
        let body = Closed {
            link: LinkName {
                node: 1,
                run: 2,
                link: 3,
            },
            space: None,
        }
        .encode();
        assert!(Closed::decode(&body).is_some());
        let mut longer = body.clone();
        longer.push(0);
        assert!(Closed::decode(&longer).is_none());
        assert!(Closed::decode(&body[..body.len() - 1]).is_none());
        // A count larger than the bytes left could hold.
        let mut w = Writer::default();
        w.u8(2).count(1 << 30);
        assert!(ShardAnswer::decode(&w.done()).is_none());
        assert!(Frame::decode(&[9, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_none());
    }

    /// A list's length reserves no more memory than the body's bytes left,
    /// whatever its items' size in memory, and a list of the fewest bytes
    /// an item is written in still reads.
    #[test]
    fn a_lists_length_reserves_no_more_than_the_bytes_left() {
        // A million changes of five bytes each: the fewest a change is
        // written in, 48 bytes each in memory.
        let n = 1usize << 20;
        let mut w = Writer::default();
        w.count(n);
        for _ in 0..n {
            w.bytes(&[]).u8(0);
        }
        let body = w.done();
        let mut r = Reader::new(&body);
        let (count, changes) = r.list::<Change>(5).expect("the length fits");
        assert_eq!(count, n);
        let reserved = changes.capacity() * core::mem::size_of::<Change>();
        assert!(
            reserved <= body.len(),
            "{reserved} bytes reserved for a body of {}",
            body.len()
        );
        // The same list read whole.
        let request = ShardRequest {
            epoch: 1,
            shard: "index/a".into(),
            op: ShardOp::Commit {
                key: (1, 2),
                changes: vec![(Vec::new(), None); 3],
            },
        };
        assert!(round_trip(REQUEST, SHARD, &request.encode()));
        // A length that the bytes left could not hold is refused before
        // anything is reserved.
        let mut w = Writer::default();
        w.count(n).u8(0);
        assert!(Reader::new(&w.done()).list::<Change>(5).is_none());
        // An answer that ends after `holding` reads, granted.
        let mut w = Writer::default();
        w.u8(1).count(0).u8(0).flag(false);
        assert_eq!(
            ForwardAnswer::decode(&w.done()),
            Some(ForwardAnswer::Answered {
                out: Vec::new(),
                close: None,
                holding: false,
                granted: true,
                unknown: false,
                more: false,
            })
        );
        // One that ends after `unknown` holds the whole answer.
        let mut w = Writer::default();
        w.u8(1).count(0).u8(0).flag(false).flag(true).flag(false);
        assert!(matches!(
            ForwardAnswer::decode(&w.done()),
            Some(ForwardAnswer::Answered { more: false, .. })
        ));
        // An answer of one `Reconnect` alone reads.
        let answer = ForwardAnswer::Answered {
            out: vec![Out::Reconnect],
            close: None,
            holding: false,
            granted: false,
            unknown: true,
            more: false,
        };
        assert_eq!(ForwardAnswer::decode(&answer.encode()), Some(answer));
    }

    #[test]
    fn the_pieces_of_a_large_answer_read_back() {
        let part = Part {
            offset: 4 << 20,
            bytes: vec![1, 2, 3],
        };
        assert!(round_trip(NOTICE, PART, &part.encode()));
        assert_eq!(Part::decode(&part.encode()), Some(part));
        assert!(Part::decode(&[0; 7]).is_none());
        assert!(round_trip(RESPONSE, PARTS, &(9u64 << 20).to_be_bytes()));
        assert!(!round_trip(RESPONSE, PARTS, &[0; 9]));
        assert!(round_trip(RESPONSE, TOO_LARGE, &[]));
        assert!(!round_trip(RESPONSE, TOO_LARGE, &[0]));
    }
}
