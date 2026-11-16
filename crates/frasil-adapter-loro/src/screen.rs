//! What step 4 reads of a blob before the pinned Loro decodes it
//! (adapter-loro.md, 3.2 The checks).
//!
//! `decode_import_blob_meta` and `import` decode every change block of an
//! updates blob in full: its change header and metadata, its container IDs,
//! tree positions, operations, deletion starts and values. Some inputs make
//! the pinned decoder panic, or reserve memory by a count the blob names
//! before it reads any of what is counted, or by a run length that costs
//! the blob a few bytes:
//!
//! - a change count above what the change header can hold;
//! - dependency lengths whose sum overflows, or exceeds what the
//!   dependency counters that follow can hold;
//! - a delta-of-delta column (dependency counters, Lamport timestamps, wall
//!   clock timestamps) that ends inside a value, or whose last byte counts
//!   more bits than it holds;
//! - a list or map value whose length is more than the bytes left can hold;
//! - a run in a column of the tree positions or the deletion starts, which
//!   Loro expands in full before it pairs the columns' entries;
//! - many operations that take no bytes of their own, and tree positions
//!   that repeat a long prefix.
//!
//! [`updates`] walks the envelope and each block as the pinned decoder
//! reads them. It refuses a blob on which the decoder would fail, by an
//! error or by one of the above, and a blob that breaks a limit of section
//! 3.2 ([`MAX_ROWS`], [`MAX_POSITION_BYTES`]) or is laid out as no export of
//! the pinned Loro is. Every blob it refuses is one the pinned Loro does not
//! read or one that section 3.2 refuses although Loro reads it; step 4
//! refuses both as `LoroMalformed`. What it accepts reaches Loro, which
//! reads it. It reads as Loro's release build does: where Loro's debug
//! assertions or overflow checks would stop a read that the release build
//! completes, it reads on, unless section 3.2 refuses what is read.
//!
//! It also refuses a blob of any mode other than updates without decoding
//! its body, since step 4 refuses those whatever their body.
//!
//! [`snapshot`] reads a snapshot state's `main` the same way, before Loro
//! imports it (adapter-loro.md, 3.5 Compaction and history-free export,
//! "Loading a state"): the envelope and its three sections; each key-value
//! table ([`sstable`]), its LZ4 blocks decompressed within the section's
//! limits; the change store's version vectors, frontiers and change
//! blocks, each block screened as [`updates`] screens one, with the style
//! rule carried across the blocks of a peer and the section's limits on
//! the whole store; and each container state's header, a text's value, a
//! list's and a movable list's value, and the peer table and the columnar
//! tables of a text's, a list's, a movable list's and a tree's state, each
//! run-length column read run by run, within the section's limits on the
//! rows of the state stores together. The rest of a container's state is
//! left to Loro, which checks it as it decodes the container.

use crate::sstable;

/// The envelope: the magic bytes, a 16-byte checksum, a 2-byte mode.
const MAGIC: &[u8; 4] = b"loro";
/// The envelope's length before the body.
const ENVELOPE: usize = 22;
/// The mode of an updates blob, big-endian.
const UPDATES: [u8; 2] = [0, 4];
/// The longest run the pinned columnar decoder reads; longer is an error.
const MAX_RLE_COUNT: u64 = 1_000_000_000;
/// The bias of a 21-bit delta of delta.
const MAX_DELTA_OF_DELTA: i64 = 1 << 20;
/// The longest list or map value the pinned decoder reads.
const MAX_COLLECTION_SIZE: u64 = 1 << 28;

/// The most rows that the operation tables of a blob's blocks hold
/// together, and likewise its tree position tables and its deletion start
/// tables (adapter-loro.md, 3.2 The checks): one per byte of the largest
/// unit (units.md, 2.1 Limits).
pub(crate) const MAX_ROWS: u64 = 1 << 20;
/// The most bytes that a blob's tree positions decode to, over all its
/// blocks (adapter-loro.md, 3.2 The checks): 16 times the largest unit.
pub(crate) const MAX_POSITION_BYTES: u64 = 1 << 24;

/// The container type of a list (`ContainerType::List`).
const LIST: u8 = 1;
/// The container type of a text (`ContainerType::Text`).
const TEXT: u8 = 2;
/// The container type of a tree (`ContainerType::Tree`).
const TREE: u8 = 3;
/// The container type of a movable list (`ContainerType::MovableList`).
const MOVABLE_LIST: u8 = 4;
/// The value kind of an operation (`ValueKind`) that ends a style on a
/// text.
const NULL: u8 = 0;
/// The value kind of an operation that starts a style on a text.
const MARK_START: u8 = 12;

/// A blob the pinned Loro does not read, or one section 3.2 refuses.
#[derive(Debug)]
struct Unread;

type Result<T> = core::result::Result<T, Unread>;

/// Why a varint did not parse: the bytes ended inside it (postcard's
/// `DeserializeUnexpectedEnd`), or it is not one (`DeserializeBadVarint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Varint {
    End,
    Bad,
}

impl From<sstable::Refused> for Unread {
    fn from(_: sstable::Refused) -> Self {
        Unread
    }
}

impl From<Varint> for Unread {
    fn from(_: Varint) -> Self {
        Unread
    }
}

/// Whether `blob` is an updates blob that step 4 lets the pinned Loro
/// decode: no panic and no allocation sized by an unchecked count on the
/// way through, and within the limits of section 3.2.
pub(crate) fn updates(blob: &[u8]) -> bool {
    envelope(blob).is_ok()
}

/// The mode of a snapshot, with its history or shallow (`FastSnapshot`),
/// big-endian.
const SNAPSHOT: [u8; 2] = [0, 3];
/// The state section of a snapshot that holds no state store
/// (`EMPTY_MARK`).
const NO_STATE: &[u8] = b"E";
/// The most bytes that the blocks of a snapshot's tables decompress to,
/// together (adapter-loro.md, 3.5, "Loading a state").
pub(crate) const MAX_INFLATED: usize = 1 << 28;
/// How many times the length of a snapshot its tables may decompress to.
const INFLATE_RATIO: usize = 256;

/// Whether `main`, a snapshot state's key 2, is a snapshot that the checks
/// of section 3.5, "Loading a state", let the pinned Loro decode: no panic
/// and no allocation sized by an unchecked count or length on the way
/// through its envelope, its tables and its change store, and within the
/// limits of section 3.5. The container states in its state stores are
/// read only as far as their headers and a text's value.
pub(crate) fn snapshot(main: &[u8]) -> bool {
    snapshot_body(main).is_ok()
}

fn snapshot_body(main: &[u8]) -> Result<()> {
    if main.len() < ENVELOPE || main[..4] != MAGIC[..] || main[20..22] != SNAPSHOT {
        return Err(Unread);
    }
    // `_decode_snapshot_bytes`: three sections, each a u32 length, and
    // nothing after them.
    let mut body = Reader(&main[ENVELOPE..]);
    let mut section = || -> Result<&[u8]> {
        let len = u32::from_le_bytes(body.take(4)?.try_into().map_err(|_| Unread)?);
        body.take(len as usize)
    };
    let changes = section()?;
    let state = section()?;
    let shallow_root = section()?;
    if !body.0.is_empty() {
        return Err(Unread);
    }
    let mut inflate = sstable::Inflate {
        used: 0,
        limit: MAX_INFLATED.min(main.len().saturating_mul(INFLATE_RATIO)),
    };
    change_store(changes, &mut inflate, main.len() as u64)?;
    let mut tables = Budget::new(scaled(main.len() as u64));
    if state != NO_STATE {
        state_store(state, &mut inflate, &mut tables)?;
    }
    state_store(shallow_root, &mut inflate, &mut tables)
}

/// The limits of section 3.5 on a snapshot of `main_len` bytes: those of
/// section 3.2 for one unit, or as many per byte of the snapshot as
/// section 3.2 allows per byte of a unit, whichever is more.
fn scaled(main_len: u64) -> Limits {
    Limits {
        rows: MAX_ROWS.max(main_len),
        position_bytes: MAX_POSITION_BYTES.max(main_len.saturating_mul(16)),
    }
}

/// A table's entries, key then value, in the order the table holds them.
pub(crate) type Entries = Vec<(Vec<u8>, Vec<u8>)>;

/// The entries of a snapshot's change store, state store and shallow
/// root's state store, read as [`snapshot`] reads their tables but without
/// its other checks; `None` when a table does not read. For tests and
/// fuzzing, which build snapshots from the entries of real ones.
pub(crate) fn tables(main: &[u8]) -> Option<[Entries; 3]> {
    let mut body = Reader(main.get(ENVELOPE..)?);
    let mut inflate = sstable::Inflate {
        used: 0,
        limit: MAX_INFLATED,
    };
    let mut out: [Entries; 3] = Default::default();
    for entries in &mut out {
        let len = u32::from_le_bytes(body.take(4).ok()?.try_into().ok()?);
        let bytes = body.take(len as usize).ok()?;
        if bytes == NO_STATE {
            continue;
        }
        sstable::table(bytes, &mut inflate, |key, value| {
            entries.push((key.to_vec(), value.to_vec()));
            Ok(())
        })
        .ok()?;
    }
    Some(out)
}

/// The keys of a snapshot's state store other than its frontiers: the
/// container IDs whose states it holds; none when the snapshot holds no
/// state store, and `None` when its tables do not read.
pub(crate) fn state_containers(main: &[u8]) -> Option<Vec<Vec<u8>>> {
    let [_, state, _] = tables(main)?;
    Some(
        state
            .into_iter()
            .map(|(key, _)| key)
            .filter(|key| key != b"fr")
            .collect(),
    )
}

/// The change store, `ChangeStore::import_all`: its version vectors and
/// frontiers, and its change blocks, keyed by the ID of each block's first
/// change. Each block passes step 4 as a blob of that block alone would,
/// and the blocks together stay within the limits of section 3.5, scaled
/// to `main_len`, the length of the snapshot.
fn change_store(bytes: &[u8], inflate: &mut sstable::Inflate, main_len: u64) -> Result<()> {
    let mut total = Budget::new(scaled(main_len));
    let mut previous: Option<Block> = None;
    let mut store = Store::default();
    sstable::table(bytes, inflate, |key, value| {
        change_entry(key, value, &mut previous, &mut total, &mut store)
            .map_err(|_| sstable::Refused)
    })?;
    if matches!(
        previous,
        Some(Block {
            open_style: Some(_),
            ..
        })
    ) {
        return Err(Unread);
    }
    // A peer's history that begins with a style's end begins at the
    // shallow root: that end is one of the root's frontiers, and its start
    // is in the root's state alone.
    if store.trimmed.iter().all(|&(peer, counter)| {
        store
            .shallow_frontiers
            .contains(&(peer, i64::from(counter)))
    }) {
        Ok(())
    } else {
        Err(Unread)
    }
}

/// What the change store's entries say of each other.
#[derive(Default)]
struct Store {
    /// The shallow root's frontiers, `sf`.
    shallow_frontiers: Vec<(u64, i64)>,
    /// Each block that begins with a style's end its peer's earlier blocks
    /// do not start: its peer and first counter.
    trimmed: Vec<(u64, u32)>,
}

/// One entry of the change store; `previous` is the change block read
/// before it.
fn change_entry(
    key: &[u8],
    value: &[u8],
    previous: &mut Option<Block>,
    total: &mut Budget,
    store: &mut Store,
) -> Result<()> {
    match key {
        b"sf" => {
            store.shallow_frontiers = ids(value)?;
            return Ok(());
        }
        b"vv" | b"sv" | b"fr" => return ids(value).map(drop),
        _ if key.len() == 12 => {}
        _ => return Err(Unread),
    }
    let peer = u64::from_be_bytes(key[..8].try_into().map_err(|_| Unread)?);
    let counter = i32::from_be_bytes(key[8..].try_into().map_err(|_| Unread)?);
    let mut budget = Budget::new(UNIT);
    // The first block of a peer may begin with a style's end whose start a
    // history-free export dropped, checked against the shallow root once
    // the store is read.
    let first = previous.as_ref().is_none_or(|before| before.peer != peer);
    let read = block(value, &mut budget, previous.as_ref(), first)?;
    if read.trimmed_end {
        store.trimmed.push((peer, read.counter_start));
    }
    // The key names the block's first change, as the store looks the block
    // up by it; the block lies past the one before it of the same peer.
    let overlaps = previous.as_ref().is_some_and(|before| {
        before.peer == peer && before.counter_end > u64::from(read.counter_start)
    });
    if read.peer != peer || u32::try_from(counter).ok() != Some(read.counter_start) || overlaps {
        return Err(Unread);
    }
    total.absorb(&budget)?;
    *previous = Some(read);
    Ok(())
}

/// A version vector (`VersionVector::decode`) or frontiers
/// (`Frontiers::decode`): a postcard count, then that many pairs of a peer
/// and a counter, and nothing after them. Returns the pairs, each counter
/// read as postcard reads an `i32`.
fn ids(bytes: &[u8]) -> Result<Vec<(u64, i64)>> {
    let mut ids = Reader(bytes);
    let n = ids.varint(usize::BITS)?;
    // Each pair takes at least two bytes.
    if n > ids.0.len() as u128 {
        return Err(Unread);
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let peer = ids.varint(64)? as u64;
        let counter = zigzag(ids.varint(32)?);
        out.push((peer, counter));
    }
    if ids.0.is_empty() {
        Ok(out)
    } else {
        Err(Unread)
    }
}

/// A state store, `InnerStore::decode`: its frontiers, and each container's
/// state keyed by its container ID. `tables` takes the rows of the
/// containers' tables and the trees' fractional indexes.
fn state_store(bytes: &[u8], inflate: &mut sstable::Inflate, tables: &mut Budget) -> Result<()> {
    sstable::table(bytes, inflate, |key, value| {
        let entry = if key == b"fr" {
            ids(value).map(drop)
        } else {
            container_id_key(key).and_then(|kind| container_state(kind, value, tables))
        };
        entry.map_err(|_| sstable::Refused)
    })?;
    Ok(())
}

/// A container ID as a key, `ContainerID::try_from_bytes`: its type in the
/// low seven bits of the first byte, its high bit set for a root, then a
/// root's LEB128 name length and name in UTF-8, or a creator's peer and
/// counter, 12 bytes. Returns the type.
fn container_id_key(key: &[u8]) -> Result<u8> {
    let (first, rest) = key.split_first().ok_or(Unread)?;
    if first & 0x80 == 0 {
        return if rest.len() == 12 {
            Ok(first & 0x7f)
        } else {
            Err(Unread)
        };
    }
    let mut name = Reader(rest);
    let len = usize::try_from(name.leb128()?).map_err(|_| Unread)?;
    if name.0.len() != len {
        return Err(Unread);
    }
    core::str::from_utf8(name.0).map_err(|_| Unread)?;
    Ok(first & 0x7f)
}

/// A container's state, as `ContainerWrapper::decode_header` reads its
/// header: its type, which is its key's, a LEB128 depth, and its parent, a
/// postcard `Option<ContainerID>`; then, for a text, its value, a postcard
/// string, and for a list or a movable list its value, as
/// `decode_collection` reads it. Past the value, a text's, a list's, a
/// movable list's and a tree's state hold a peer table and columnar
/// tables, whose rows `tables` takes (adapter-loro.md, 3.5, "Loading a
/// state"). What follows the tables, and a map's or a counter's state, is
/// left to Loro.
fn container_state(kind: u8, bytes: &[u8], tables: &mut Budget) -> Result<()> {
    let mut state = Reader(bytes);
    if state.byte()? != kind {
        return Err(Unread);
    }
    state.leb128()?;
    match state.byte()? {
        0 => {}
        1 => container_id(&mut state)?,
        _ => return Err(Unread),
    }
    match kind {
        // `RichtextState`: its text, its peer table, then `EncodedText`,
        // whose field count Loro reads before the spans' columns. Its keys
        // and marks follow, each of bytes of its own.
        TEXT => {
            core::str::from_utf8(state.bytes()?).map_err(|_| Unread)?;
            peer_table(&mut state)?;
            if state.varint(usize::BITS)? != 3 {
                return Err(Unread);
            }
            columns(&mut state, &[Column::Delta; 4], tables)?;
        }
        // `ListState`: its value, its peer table, then `EncodedListIds`.
        LIST => {
            collection(&mut state)?;
            peer_table(&mut state)?;
            fields(&mut state, 1)?;
            columns(&mut state, &[Column::Delta; 3], tables)?;
        }
        // `MovableListState`: its value, its peer table, then
        // `EncodedFastSnapshot`: its items, list item IDs, element IDs and
        // last set IDs.
        MOVABLE_LIST => {
            collection(&mut state)?;
            peer_table(&mut state)?;
            fields(&mut state, 4)?;
            columns(
                &mut state,
                &[Column::Delta, Column::Bool, Column::Bool],
                tables,
            )?;
            columns(&mut state, &[Column::Delta; 3], tables)?;
            columns(&mut state, &[Column::Delta; 2], tables)?;
            columns(&mut state, &[Column::Delta; 2], tables)?;
        }
        // `TreeState`, which has no value of its own: its peer table, then
        // `EncodedTree`: its node IDs, its nodes, its fractional indexes as
        // tree positions, and a byte string Loro does not read.
        TREE => {
            peer_table(&mut state)?;
            fields(&mut state, 4)?;
            columns(&mut state, &[Column::Delta; 2], tables)?;
            columns(
                &mut state,
                &[
                    Column::Delta,
                    Column::Delta,
                    Column::Delta,
                    Column::Delta,
                    Column::Plain,
                ],
                tables,
            )?;
            tree_positions(state.bytes()?, tables)?;
            state.bytes()?;
        }
        _ => {}
    }
    Ok(())
}

/// A postcard `ContainerID`: its variant, then a root's name and type, or
/// a creator's peer, counter and type.
fn container_id(state: &mut Reader) -> Result<()> {
    match state.varint(32)? {
        0 => {
            core::str::from_utf8(state.bytes()?).map_err(|_| Unread)?;
        }
        1 => {
            state.varint(64)?;
            state.varint(32)?;
        }
        _ => return Err(Unread),
    }
    state.byte()?;
    Ok(())
}

/// A peer table, `decode_peer_table`: a LEB128 count, then that many
/// 8-byte peer IDs.
fn peer_table(state: &mut Reader) -> Result<()> {
    let count = usize::try_from(state.leb128()?).map_err(|_| Unread)?;
    state.take(count.checked_mul(8).ok_or(Unread)?)?;
    Ok(())
}

/// A list's or a movable list's value, `decode_collection`: a postcard
/// length, then that many values, each a postcard `Header` variant and its
/// content; a list or map value opens a collection of its own, each of
/// whose map elements begins with its key, a string. Each element takes a
/// byte at least, so the walk ends within the bytes.
fn collection(state: &mut Reader) -> Result<()> {
    // The elements left in each collection open, and whether it is a map.
    let mut open: Vec<(u64, bool)> = vec![(state.usize_value()?, false)];
    while let Some((left, map)) = open.last_mut() {
        if *left == 0 {
            open.pop();
            continue;
        }
        *left -= 1;
        if *map {
            core::str::from_utf8(state.bytes()?).map_err(|_| Unread)?;
        }
        match state.varint(32)? {
            // Null.
            0 => {}
            // Bool.
            1 => {
                if state.byte()? > 1 {
                    return Err(Unread);
                }
            }
            // Double.
            2 => {
                state.take(8)?;
            }
            // I32, which holds an i64.
            3 => {
                state.varint(64)?;
            }
            // String.
            4 => {
                core::str::from_utf8(state.bytes()?).map_err(|_| Unread)?;
            }
            // List, Map.
            kind @ (5 | 6) => {
                let len = state.usize_value()?;
                if len > state.0.len() as u64 {
                    return Err(Unread);
                }
                open.push((len, kind == 6));
            }
            // Container.
            7 => container_id(state)?,
            // Binary.
            8 => {
                state.bytes()?;
            }
            _ => return Err(Unread),
        }
    }
    Ok(())
}

/// The fields of a columnar struct (`#[columnar(ser, de)]`): a postcard
/// sequence of exactly `n`.
fn fields(state: &mut Reader, n: u128) -> Result<()> {
    if state.varint(usize::BITS)? == n {
        Ok(())
    } else {
        Err(Unread)
    }
}

/// How a column of a columnar table is encoded.
#[derive(Debug, Clone, Copy)]
enum Column {
    /// `DeltaRle`: a run-length column of i128 deltas.
    Delta,
    /// `BoolRle`: the lengths of alternating runs of false and true.
    Bool,
    /// No strategy: a postcard sequence of its entries, each a byte at
    /// least.
    Plain,
}

/// A columnar table, a field of class `vec`: a postcard sequence of
/// exactly as many columns as `kinds` names, each a byte string. Its rows,
/// the entries of its longest column, go to `tables`. The runs are counted
/// and not expanded.
fn columns(state: &mut Reader, kinds: &[Column], tables: &mut Budget) -> Result<()> {
    if state.varint(usize::BITS)? != kinds.len() as u128 {
        return Err(Unread);
    }
    let limit = tables.limits.rows;
    let mut rows = 0u64;
    for kind in kinds {
        let column = state.bytes()?;
        let entries = match kind {
            Column::Delta => run_entries(column, limit)?,
            Column::Bool => bool_entries(column, limit)?,
            Column::Plain => {
                let mut entries = Reader(column);
                let n = entries.usize_value()?;
                if n > entries.0.len() as u64 {
                    return Err(Unread);
                }
                n
            }
        };
        rows = rows.max(entries);
    }
    spend(&mut tables.entries, rows, limit)
}

/// The entries a run-length column of i128 values names, run by run: a
/// count, an isize, then one value for a run or as many values as its
/// magnitude for a literal; at most `limit`.
fn run_entries(bytes: &[u8], limit: u64) -> Result<u64> {
    let mut column = Reader(bytes);
    let mut entries = 0u64;
    while !column.0.is_empty() {
        let count = column.isize_value()?;
        if count == 0 || count.unsigned_abs() > MAX_RLE_COUNT {
            return Err(Unread);
        }
        let values = if count < 0 { count.unsigned_abs() } else { 1 };
        // Each value takes a byte at least.
        if values > column.0.len() as u64 {
            return Err(Unread);
        }
        for _ in 0..values {
            i128_entry(&mut column)?;
        }
        spend(&mut entries, count.unsigned_abs(), limit)?;
    }
    Ok(entries)
}

/// The entries a `BoolRle` column names: the sum of its runs' lengths, each
/// a usize, at most `limit`.
fn bool_entries(bytes: &[u8], limit: u64) -> Result<u64> {
    let mut column = Reader(bytes);
    let mut entries = 0u64;
    while !column.0.is_empty() {
        let count = column.usize_value()?;
        if count > MAX_RLE_COUNT {
            return Err(Unread);
        }
        spend(&mut entries, count, limit)?;
    }
    Ok(entries)
}

/// The most rows and bytes of tree positions that a [`Budget`] allows.
#[derive(Debug, Clone, Copy)]
struct Limits {
    rows: u64,
    position_bytes: u64,
}

/// The limits of section 3.2 on one blob.
const UNIT: Limits = Limits {
    rows: MAX_ROWS,
    position_bytes: MAX_POSITION_BYTES,
};

/// What blocks take together, against limits of section 3.2 or 3.5.
#[derive(Debug)]
struct Budget {
    limits: Limits,
    operations: u64,
    positions: u64,
    position_bytes: u64,
    deletions: u64,
    /// The rows of container states' tables (adapter-loro.md, 3.5,
    /// "Loading a state").
    entries: u64,
}

impl Budget {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            operations: 0,
            positions: 0,
            position_bytes: 0,
            deletions: 0,
            entries: 0,
        }
    }

    /// Adds what `other` took to this budget's totals.
    fn absorb(&mut self, other: &Budget) -> Result<()> {
        let Limits {
            rows,
            position_bytes,
        } = self.limits;
        spend(&mut self.operations, other.operations, rows)?;
        spend(&mut self.positions, other.positions, rows)?;
        spend(&mut self.deletions, other.deletions, rows)?;
        spend(
            &mut self.position_bytes,
            other.position_bytes,
            position_bytes,
        )
    }
}

/// Adds `n` to a total that may not pass `limit`.
fn spend(total: &mut u64, n: u64, limit: u64) -> Result<()> {
    *total = total.checked_add(n).ok_or(Unread)?;
    if *total > limit {
        return Err(Unread);
    }
    Ok(())
}

/// A container named by an operation, as Loro resolves its row of the
/// block's container IDs (`as_container_id`): its type, and its root name
/// or its creator's ID.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Container {
    Root { kind: u8, name: Vec<u8> },
    Normal { kind: u8, peer: u64, counter: i64 },
}

impl Container {
    fn kind(&self) -> u8 {
        match self {
            Self::Root { kind, .. } | Self::Normal { kind, .. } => *kind,
        }
    }
}

/// What the blocks after a change block need of it.
#[derive(Debug)]
struct Block {
    /// Its peer: the first of its change header's peers.
    peer: u64,
    /// Its first counter.
    counter_start: u32,
    /// The counter after its last.
    counter_end: u64,
    /// The text of a style whose start is its last operation.
    open_style: Option<Container>,
    /// Whether its first operation is a style's end whose start no block
    /// holds, as the first block of a peer in a history-free export may
    /// begin.
    trimmed_end: bool,
}

/// The style that `previous` left open and that a block of `peer` from
/// `counter_start` ends: section 3.2 allows a style's start to end a block
/// only where the next block of the same peer, its counters continuing,
/// begins with the style's end.
fn carried(previous: Option<&Block>, peer: u64, counter_start: u32) -> Result<Option<Container>> {
    match previous {
        Some(Block {
            peer: before,
            counter_end,
            open_style: Some(open),
            ..
        }) => {
            if *before == peer && *counter_end == u64::from(counter_start) {
                Ok(Some(open.clone()))
            } else {
                Err(Unread)
            }
        }
        _ => Ok(None),
    }
}

fn envelope(blob: &[u8]) -> Result<()> {
    if blob.len() < ENVELOPE || blob[..4] != MAGIC[..] || blob[20..22] != UPDATES {
        return Err(Unread);
    }
    let mut body = Reader(&blob[ENVELOPE..]);
    let mut budget = Budget::new(UNIT);
    let mut previous: Option<Block> = None;
    while !body.0.is_empty() {
        // `decode_updates` reads each length as a u64 cast to usize.
        let len = body.leb128()? as usize;
        previous = Some(block(
            body.take(len)?,
            &mut budget,
            previous.as_ref(),
            false,
        )?);
    }
    match previous {
        Some(Block {
            open_style: Some(_),
            ..
        }) => Err(Unread),
        _ => Ok(()),
    }
}

/// One change block, a postcard `EncodedBlock`: five u32 then eight byte
/// strings. The decoder ignores bytes after them. `previous` is the block
/// read before it, whose style it may end; with `trimmed`, it may begin
/// with a style's end whose start no block holds.
fn block(
    bytes: &[u8],
    budget: &mut Budget,
    previous: Option<&Block>,
    trimmed: bool,
) -> Result<Block> {
    let mut block = Reader(bytes);
    let counter_start = block.varint(32)? as u32;
    let counter_len = block.varint(32)? as u32;
    // lamport_start, lamport_len.
    for _ in 0..2 {
        block.varint(32)?;
    }
    let n_changes = block.varint(32)?;
    let header = block.bytes()?;
    let change_meta = block.bytes()?;
    let cids = block.bytes()?;
    let keys = block.bytes()?;
    let positions = block.bytes()?;
    let ops = block.bytes()?;
    let delete_start_ids = block.bytes()?;
    let values = block.bytes()?;
    let n_changes = usize::try_from(n_changes).map_err(|_| Unread)?;
    let peers = changes_header(header, n_changes)?;
    changes_meta(change_meta, n_changes)?;
    let containers = containers(cids, &peers, &key_strings(keys)?)?;
    tree_positions(positions, budget)?;
    deletion_starts(delete_start_ids, budget)?;
    let peer = peers[0];
    let open = carried(previous, peer, counter_start)?;
    let trimmed = trimmed && open.is_none();
    let (open_style, trimmed_end) = operations(ops, values, &containers, open, trimmed, budget)?;
    Ok(Block {
        peer,
        counter_start,
        counter_end: u64::from(counter_start) + u64::from(counter_len),
        open_style,
        trimmed_end,
    })
}

/// The key strings, `decode_keys`: each a LEB128 length and that many bytes
/// of UTF-8, to the end.
fn key_strings(bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut keys = Reader(bytes);
    let mut out = Vec::new();
    while !keys.0.is_empty() {
        let len = keys.leb128()? as usize;
        let key = keys.take(len)?;
        core::str::from_utf8(key).map_err(|_| Unread)?;
        out.push(key);
    }
    Ok(out)
}

/// `decode_changes_header`: the peers, the change lengths, the
/// dependencies and the Lamport timestamps.
fn changes_header(bytes: &[u8], n_changes: usize) -> Result<Vec<u64>> {
    if n_changes == 0 {
        return Err(Unread);
    }
    let mut header = Reader(bytes);
    let peer_num = header.leb128()? as usize;
    let peers = peer_num.checked_mul(8).ok_or(Unread)?;
    if peer_num == 0 {
        return Err(Unread);
    }
    let peers: Vec<u64> = header
        .take(peers)?
        .chunks_exact(8)
        .map(|peer| u64::from_le_bytes(peer.try_into().unwrap_or_default()))
        .collect();
    // The decoder reserves room for every change's length before it reads
    // one; each of the first n - 1 is at least a byte.
    if n_changes - 1 > header.0.len() {
        return Err(Unread);
    }
    for _ in 0..n_changes - 1 {
        header.leb128()?;
    }
    let rest = bool_rle(header.0, n_changes)?;
    let mut deps_len = Vec::with_capacity(n_changes);
    let rest = any_rle(rest, n_changes, |len| deps_len.push(len))?;
    // A sum that overflows: the release build wraps it, then runs out of
    // dependencies to read.
    let other_deps = deps_len
        .iter()
        .try_fold(0usize, |sum, len| sum.checked_add(*len))
        .ok_or(Unread)?;
    // The decoder reserves room for every other dependency before it reads
    // one. Their counters follow in the bytes left, a bit at least each
    // after the first.
    if other_deps.saturating_sub(1) / 8 > rest.len() {
        return Err(Unread);
    }
    let rest = any_rle(rest, other_deps, |_| {})?;
    let rest = delta_of_delta(rest, other_deps, fits_u32)?;
    // Section 3.2: nothing follows the Lamport timestamps.
    if !delta_of_delta(rest, n_changes - 1, fits_u32)?.is_empty() {
        return Err(Unread);
    }
    Ok(peers)
}

/// The change metadata's leading column: one wall clock timestamp per
/// change.
fn changes_meta(bytes: &[u8], n_changes: usize) -> Result<()> {
    delta_of_delta(bytes, n_changes, |_| true).map(|_| ())
}

fn fits_u32(value: i64) -> bool {
    u32::try_from(value).is_ok()
}

/// A run-length column of booleans, as `BoolRleDecoder::take_n_finalize`
/// reads `n` of them: the bytes after them.
fn bool_rle(bytes: &[u8], n: usize) -> Result<&[u8]> {
    let mut column = Reader(bytes);
    let mut count = 0u64;
    for _ in 0..n {
        while count == 0 {
            count = column.usize_value()?;
            if count > MAX_RLE_COUNT {
                return Err(Unread);
            }
        }
        count -= 1;
    }
    Ok(column.0)
}

/// A run-length column of usize, as `AnyRleDecoder::take_n_finalize`
/// reads `n` of them, each handed to `value`: the bytes after them.
fn any_rle(bytes: &[u8], n: usize, mut value: impl FnMut(usize)) -> Result<&[u8]> {
    let mut column = Rle::new(bytes, Ending::Eager, usize_entry);
    for _ in 0..n {
        let last = column.next()?.ok_or(Unread)?;
        value(usize::try_from(last).map_err(|_| Unread)?);
    }
    Ok(column.column.0)
}

/// A delta-of-delta column, as `DeltaOfDeltaDecoder::take_n_finalize`
/// reads `n` values that `fits` accepts, with no sum that overflows: the
/// bytes after them.
fn delta_of_delta(bytes: &[u8], n: usize, fits: fn(i64) -> bool) -> Result<&[u8]> {
    let mut column = Reader(bytes);
    let head = match column.byte()? {
        0 => None,
        1 => Some(zigzag(column.varint(64)?)),
        _ => return Err(Unread),
    };
    let last_used_bit = column.byte()?;
    let mut bits = Bits {
        bits: column.0,
        last_used_bit,
        position: 0,
    };
    let mut head = head;
    let mut value = 0i64;
    let mut delta = 0i64;
    for _ in 0..n {
        if let Some(first) = head.take() {
            value = first;
        } else {
            // Section 3.2: no sum overflows, as Loro's export never
            // writes one that does. Loro's release build would wrap it.
            match bits.read(1)? {
                None => return Err(Unread),
                Some(0) => value = value.checked_add(delta).ok_or(Unread)?,
                Some(_) => {
                    // Past the first bit, the decoder unwraps every read.
                    let mut flag = || bits.read(1)?.ok_or(Unread);
                    let (width, bias) = if flag()? == 0 {
                        (7, 63)
                    } else if flag()? == 0 {
                        (9, 255)
                    } else if flag()? == 0 {
                        (12, 2047)
                    } else if flag()? == 0 {
                        (21, MAX_DELTA_OF_DELTA - 1)
                    } else {
                        (64, 0)
                    };
                    let raw = bits.read(width)?.ok_or(Unread)?;
                    // The decoder reads the bits as an i64, two's
                    // complement, then removes the bias.
                    let delta_of_delta = i64::from_ne_bytes(raw.to_ne_bytes()).wrapping_sub(bias);
                    delta = delta.checked_add(delta_of_delta).ok_or(Unread)?;
                    value = value.checked_add(delta).ok_or(Unread)?;
                }
            }
        }
        if !fits(value) {
            return Err(Unread);
        }
    }
    bits.rest()
}

/// The container IDs, `ContainerArena::decode`: a postcard sequence of
/// rows, each a sequence of `is_root`, `kind`, `peer_idx` and
/// `key_idx_or_counter`. Each row takes at least five bytes, so their
/// number is bounded by the bytes. Each resolves, as `as_container_id`
/// resolves it, to a root's name among `keys` or a creator among `peers`.
fn containers(bytes: &[u8], peers: &[u64], keys: &[&[u8]]) -> Result<Vec<Container>> {
    let mut cids = Reader(bytes);
    let n = cids.varint(usize::BITS)?;
    let mut out = Vec::new();
    for _ in 0..n {
        if cids.varint(usize::BITS)? < 4 {
            return Err(Unread);
        }
        let is_root = match cids.byte()? {
            0 => false,
            1 => true,
            _ => return Err(Unread),
        };
        let kind = cids.byte()?;
        let peer_idx = cids.usize_value()?;
        // An i32, zigzag.
        let key_or_counter = zigzag(cids.varint(32)?);
        out.push(if is_root {
            let key = usize::try_from(key_or_counter).map_err(|_| Unread)?;
            let name = keys.get(key).ok_or(Unread)?;
            Container::Root {
                kind,
                name: name.to_vec(),
            }
        } else {
            let peer = usize::try_from(peer_idx).map_err(|_| Unread)?;
            Container::Normal {
                kind,
                peer: *peers.get(peer).ok_or(Unread)?,
                counter: key_or_counter,
            }
        });
    }
    Ok(out)
}

/// The framing of a column table (`#[columnar(ser, de)]` around one field
/// of class `vec`): a sequence of at least one field, whose first is a
/// sequence of at least `columns` byte strings, one per column.
fn table<const N: usize>(bytes: &[u8]) -> Result<[&[u8]; N]> {
    let mut table = Reader(bytes);
    if table.varint(usize::BITS)? < 1 || table.varint(usize::BITS)? < N as u128 {
        return Err(Unread);
    }
    let mut columns = [&[][..]; N];
    for column in &mut columns {
        *column = table.bytes()?;
    }
    Ok(columns)
}

/// The tree positions, `PositionArena::decode_v2` then
/// `try_parse_to_positions`: a table of a run-length column of common
/// prefix lengths and a column of the bytes after each prefix. Loro expands
/// both columns before it pairs them, then builds each position from the
/// one before it.
fn tree_positions(bytes: &[u8], budget: &mut Budget) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let [prefixes, rests] = table::<2>(bytes)?;
    let mut prefixes = Rle::new(prefixes, Ending::Eager, usize_entry);
    let mut rests = Reader(rests);
    let rows = rests.varint(usize::BITS)?;
    let mut last: Option<u64> = None;
    for _ in 0..rows {
        let rest = rests.bytes()?.len() as u64;
        // Section 3.2: the columns hold equally many entries.
        let prefix = u64::try_from(prefixes.next()?.ok_or(Unread)?).map_err(|_| Unread)?;
        spend(&mut budget.positions, 1, budget.limits.rows)?;
        match last {
            None if prefix != 0 => return Err(Unread),
            Some(last) if prefix > last => return Err(Unread),
            _ => {}
        }
        let len = prefix.checked_add(rest).ok_or(Unread)?;
        spend(
            &mut budget.position_bytes,
            len,
            budget.limits.position_bytes,
        )?;
        last = Some(len);
    }
    if prefixes.next()?.is_some() {
        return Err(Unread);
    }
    Ok(())
}

/// The deletion starts, `EncodedDeleteStartIds`: a table of three
/// delta-run-length columns, the peer index, the counter and the signed
/// length of each deletion. Loro expands each column before it pairs them.
fn deletion_starts(bytes: &[u8], budget: &mut Budget) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let [peers, counters, lens] = table::<3>(bytes)?;
    let mut peers = DeltaRle::new(peers, Ending::Eager, fits::<usize>);
    let mut counters = DeltaRle::new(counters, Ending::Eager, fits::<i32>);
    let mut lens = DeltaRle::new(lens, Ending::Eager, fits::<isize>);
    loop {
        let row = [peers.next()?, counters.next()?, lens.next()?];
        match row {
            [None, None, None] => return Ok(()),
            // Section 3.2: the columns hold equally many entries, and no
            // deletion is of length 0.
            [Some(_), Some(_), Some(len)] if len != 0 => {
                spend(&mut budget.deletions, 1, budget.limits.rows)?;
            }
            _ => return Err(Unread),
        }
    }
}

/// The operations, `EncodedOps` read as an iterator: a table of the
/// container index, the property, the value kind and the length of each
/// operation, whose rows Loro reads one at a time, each with its value from
/// `values`, until a column ends. `open` is the text of a style that the
/// block before left open, whose end the first operation must be; with
/// `trimmed`, the first operation may be a style's end with no start.
/// Returns the text of a style that the last operation starts, and whether
/// the first was such an end.
fn operations(
    ops: &[u8],
    values: &[u8],
    containers: &[Container],
    open: Option<Container>,
    trimmed: bool,
    budget: &mut Budget,
) -> Result<(Option<Container>, bool)> {
    let [container, prop, kind, len] = table::<4>(ops)?;
    let mut container = DeltaRle::new(container, Ending::Lazy, fits::<u32>);
    let mut prop = DeltaRle::new(prop, Ending::Lazy, fits::<i32>);
    let mut kind = Rle::new(kind, Ending::Lazy, u8_entry);
    let mut len = Rle::new(len, Ending::Lazy, u32_entry);
    let mut values = Reader(values);
    // The text of a style's start whose end comes next.
    let mut open_style = open;
    let mut first = true;
    let mut trimmed_end = false;
    loop {
        // The iterator reads each column in turn and stops at the first
        // error; a row is read only when every column has an entry.
        let row = (container.next()?, prop.next()?, kind.next()?, len.next()?);
        let (Some(container), Some(prop), Some(kind), Some(len)) = row else {
            break;
        };
        spend(&mut budget.operations, 1, budget.limits.rows)?;
        let kind = u8::try_from(kind).map_err(|_| Unread)? & 0x7f;
        let style_len = value(&mut values, kind)?;
        let index = usize::try_from(container).map_err(|_| Unread)?;
        let container = containers.get(index).ok_or(Unread)?;
        let text = container.kind() == TEXT;
        // Section 3.2: a style's end directly follows its start, of length
        // 1, on the same text, and every start is followed by its end.
        let style_end = text && kind == NULL;
        let at_first = core::mem::replace(&mut first, false);
        match open_style.take() {
            Some(start) if style_end && start == *container => continue,
            Some(_) => return Err(Unread),
            None if style_end && at_first && trimmed => {
                trimmed_end = true;
                continue;
            }
            None if style_end => return Err(Unread),
            None => {}
        }
        if text && kind == MARK_START {
            // Section 3.2: the start is of length 1, and the style covers
            // at least one position and ends below 2^32. Loro reads the
            // position and the style's length as u32, and adds them.
            let start = prop as u32;
            let end = start.checked_add(style_len as u32);
            if len != 1 || style_len as u32 == 0 || end.is_none() {
                return Err(Unread);
            }
            open_style = Some(container.clone());
        }
    }
    Ok((open_style, trimmed_end))
}

/// One operation's value, `Value::decode` of `kind`, its high bit cleared:
/// the length of the style it starts, for a `MarkStart`, else 0.
fn value(values: &mut Reader, kind: u8) -> Result<u64> {
    match kind {
        // Null, True, False, DeleteOnce, DeleteSeq.
        0..=2 | 8 | 9 => {}
        // I64, DeltaInt.
        3 | 10 => values.sleb128()?,
        // F64.
        4 => {
            values.take(8)?;
        }
        // Str (Loro also checks UTF-8), Binary, and a kind of a later
        // release: a length, then the bytes.
        5 | 6 | 17..=127 => {
            let len = values.leb128()? as usize;
            values.take(len)?;
        }
        // ContainerType: a container index.
        7 => {
            values.leb128()?;
        }
        // LoroValue.
        11 => loro_value(values)?,
        // MarkStart: info, len, key index, value.
        12 => {
            values.byte()?;
            let len = values.leb128()?;
            values.leb128()?;
            loro_value(values)?;
            return Ok(len);
        }
        // TreeMove: target, whether the parent is null, position, and the
        // parent when it is not.
        13 => {
            values.leb128()?;
            let parent_is_null = values.byte()? != 0;
            values.leb128()?;
            if !parent_is_null {
                values.leb128()?;
            }
        }
        // ListMove: from, from_idx, lamport.
        14 => {
            for _ in 0..3 {
                values.leb128()?;
            }
        }
        // ListSet: peer index, lamport, value.
        15 => {
            values.leb128()?;
            values.leb128()?;
            loro_value(values)?;
        }
        // RawTreeMove: target peer and counter, position, whether the
        // parent is null, and the parent's peer and counter when it is not.
        16 => {
            for _ in 0..3 {
                values.leb128()?;
            }
            if values.byte()? == 0 {
                values.leb128()?;
                values.leb128()?;
            }
        }
        128.. => return Err(Unread),
    }
    Ok(0)
}

/// A `LoroValue` with its kind, `read_value_type_and_content`. Loro
/// reserves room for a list's or map's every element when it reads the
/// length; each element takes at least a byte, so the elements owed by
/// every list and map open must fit in the bytes left.
fn loro_value(values: &mut Reader) -> Result<()> {
    // The elements left to read of each open list or map, and whether it
    // is a map, whose elements each begin with a key index.
    let mut open: Vec<(u64, bool)> = Vec::new();
    let mut owed = 0u64;
    loop {
        match values.byte()? {
            // Null, True, False.
            0..=2 => {}
            // I64.
            3 => values.sleb128()?,
            // F64.
            4 => {
                values.take(8)?;
            }
            // Str, Binary.
            5 | 6 => {
                let len = values.leb128()? as usize;
                values.take(len)?;
            }
            // List, Map.
            kind @ (7 | 8) => {
                let len = values.leb128()?;
                if len > MAX_COLLECTION_SIZE {
                    return Err(Unread);
                }
                owed = owed.checked_add(len).ok_or(Unread)?;
                if owed > values.0.len() as u64 {
                    return Err(Unread);
                }
                open.push((len, kind == 8));
            }
            // ContainerType.
            9 => {
                values.byte()?;
            }
            _ => return Err(Unread),
        }
        // The next element of the innermost list or map not yet read in
        // full, if any.
        loop {
            match open.last_mut() {
                None => return Ok(()),
                Some((0, _)) => {
                    open.pop();
                }
                Some((left, map)) => {
                    *left -= 1;
                    owed -= 1;
                    if *map {
                        values.leb128()?;
                    }
                    break;
                }
            }
        }
    }
}

/// How a column decoder reads a run count that does not parse. Loro's
/// vector decoders end the column there; its iterators end it only where
/// the bytes end, and fail otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Eager,
    Lazy,
}

/// A run-length column (`AnyRleDecoder`, `AnyRleIter`) of values each read
/// by `read`, as an unsigned or signed integer.
struct Rle<'a> {
    column: Reader<'a>,
    ending: Ending,
    read: fn(&mut Reader<'a>) -> Result<i128>,
    count: u64,
    literal: bool,
    last: i128,
}

impl<'a> Rle<'a> {
    fn new(bytes: &'a [u8], ending: Ending, read: fn(&mut Reader<'a>) -> Result<i128>) -> Self {
        Self {
            column: Reader(bytes),
            ending,
            read,
            count: 0,
            literal: false,
            last: 0,
        }
    }

    /// The next entry, or `None` where the column ends.
    fn next(&mut self) -> Result<Option<i128>> {
        while self.count == 0 {
            let count = match self.column.isize_value() {
                Ok(count) => count,
                Err(Varint::End) => return Ok(None),
                Err(Varint::Bad) if self.ending == Ending::Eager => return Ok(None),
                Err(Varint::Bad) => return Err(Unread),
            };
            if count == 0 || count.unsigned_abs() > MAX_RLE_COUNT {
                return Err(Unread);
            }
            self.count = count.unsigned_abs();
            self.literal = count < 0;
            if !self.literal {
                self.last = (self.read)(&mut self.column)?;
            }
        }
        self.count -= 1;
        if self.literal {
            self.last = (self.read)(&mut self.column)?;
        }
        Ok(Some(self.last))
    }
}

/// A delta-run-length column (`DeltaRleDecoder`, `DeltaRleIter`): a
/// run-length column of i128 deltas, summed with saturation, each sum then
/// converted to the column's type, which `fits` checks.
struct DeltaRle<'a> {
    deltas: Rle<'a>,
    absolute: i128,
    fits: fn(i128) -> bool,
}

impl<'a> DeltaRle<'a> {
    fn new(bytes: &'a [u8], ending: Ending, fits: fn(i128) -> bool) -> Self {
        Self {
            deltas: Rle::new(bytes, ending, i128_entry),
            absolute: 0,
            fits,
        }
    }

    fn next(&mut self) -> Result<Option<i128>> {
        let Some(delta) = self.deltas.next()? else {
            return Ok(None);
        };
        self.absolute = self.absolute.saturating_add(delta);
        if !(self.fits)(self.absolute) {
            return Err(Unread);
        }
        Ok(Some(self.absolute))
    }
}

fn fits<T: TryFrom<i128>>(value: i128) -> bool {
    T::try_from(value).is_ok()
}

fn u8_entry(column: &mut Reader) -> Result<i128> {
    Ok(column.byte()?.into())
}

fn u32_entry(column: &mut Reader) -> Result<i128> {
    Ok(column.varint(32)? as i128)
}

fn usize_entry(column: &mut Reader) -> Result<i128> {
    Ok(column.usize_value()?.into())
}

fn i128_entry(column: &mut Reader) -> Result<i128> {
    let value = column.varint(128)?;
    let magnitude = (value >> 1) as i128;
    Ok(if value & 1 == 0 {
        magnitude
    } else {
        -magnitude - 1
    })
}

/// The bits of a delta-of-delta column. The decoder counts
/// `(len - 1) * 8 + last_used_bit` of them, which a `last_used_bit` above 8
/// puts past the last byte.
struct Bits<'a> {
    bits: &'a [u8],
    last_used_bit: u8,
    position: usize,
}

impl<'a> Bits<'a> {
    /// `read_bits(count)`: `None` where the decoder finds no more.
    fn read(&mut self, count: usize) -> Result<Option<u64>> {
        if self.position / 8 >= self.bits.len() {
            return Ok(None);
        }
        let total = (self.bits.len() - 1) * 8 + usize::from(self.last_used_bit);
        let remaining = total.checked_sub(self.position).ok_or(Unread)?;
        if remaining < count {
            return Ok(None);
        }
        let end = self.position + count;
        if (end - 1) / 8 >= self.bits.len() {
            // The decoder would index past the column's last byte.
            return Err(Unread);
        }
        let mut value = 0u64;
        for at in self.position..end {
            let bit = (self.bits[at / 8] >> (7 - at % 8)) & 1;
            value = (value << 1) | u64::from(bit);
        }
        self.position = end;
        Ok(Some(value))
    }

    /// `finalize`: the bytes after the last one read from.
    fn rest(&self) -> Result<&'a [u8]> {
        if self.bits.is_empty() {
            return Ok(self.bits);
        }
        self.bits.get(self.position.div_ceil(8)..).ok_or(Unread)
    }
}

fn zigzag(value: u128) -> i64 {
    let magnitude = i64::try_from(value >> 1).unwrap_or(i64::MAX);
    if value & 1 == 0 {
        magnitude
    } else {
        -magnitude - 1
    }
}

/// Bytes read from the front.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8> {
        let (first, rest) = self.0.split_first().ok_or(Unread)?;
        self.0 = rest;
        Ok(*first)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err(Unread);
        }
        let (taken, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(taken)
    }

    /// A postcard varint of an integer of `bits` bits.
    fn varint(&mut self, bits: u32) -> core::result::Result<u128, Varint> {
        let max = bits.div_ceil(7);
        let max_of_last = (1u8 << (bits % 7)) - 1;
        let mut out = 0u128;
        for i in 0..max {
            let (byte, rest) = self.0.split_first().ok_or(Varint::End)?;
            self.0 = rest;
            out |= u128::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return if i == max - 1 && *byte > max_of_last {
                    Err(Varint::Bad)
                } else {
                    Ok(out)
                };
            }
        }
        Err(Varint::Bad)
    }

    /// A postcard usize, as serde reads one: a u64 varint.
    fn usize_value(&mut self) -> Result<u64> {
        let value = self.varint(64)? as u64;
        usize::try_from(value).map_err(|_| Unread)?;
        Ok(value)
    }

    /// A postcard isize, as serde reads one: a zigzag i64 varint.
    fn isize_value(&mut self) -> core::result::Result<i64, Varint> {
        let value = zigzag(self.varint(64)?);
        isize::try_from(value).map_err(|_| Varint::Bad)?;
        Ok(value)
    }

    /// A postcard byte string: a varint length of the target's usize, then
    /// the bytes.
    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.varint(usize::BITS)?;
        self.take(usize::try_from(len).map_err(|_| Unread)?)
    }

    /// An unsigned LEB128 value, as the `leb128` crate reads one.
    fn leb128(&mut self) -> Result<u64> {
        let mut out = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.byte()?;
            if shift == 63 && byte > 1 {
                return Err(Unread);
            }
            out |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(out);
            }
            shift += 7;
        }
    }

    /// A signed LEB128 value, as the `leb128` crate reads one.
    fn sleb128(&mut self) -> Result<()> {
        let mut shift = 0;
        loop {
            let byte = self.byte()?;
            if shift == 63 && byte != 0 && byte != 0x7f {
                return Err(Unread);
            }
            if byte & 0x80 == 0 {
                return Ok(());
            }
            shift += 7;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loro::{ExportMode, IdSpan, LoroDoc};

    #[test]
    fn every_export_of_updates_passes() {
        let doc = LoroDoc::new();
        doc.set_peer_id(7).unwrap();
        doc.set_record_timestamp(true);
        let other = LoroDoc::new();
        other.set_peer_id(8).unwrap();
        for round in 0..40u32 {
            let text = doc.get_text("t");
            text.insert(0, &"x".repeat(round as usize % 5 + 1)).unwrap();
            doc.get_map("m").insert("k", i64::from(round)).unwrap();
            doc.set_next_commit_message(&format!("round {round}"));
            doc.commit();
            if round % 3 == 0 {
                other
                    .import(&doc.export(ExportMode::all_updates()).unwrap())
                    .unwrap();
                other.get_list("l").push(i64::from(round)).unwrap();
                other.commit();
                doc.import(&other.export(ExportMode::all_updates()).unwrap())
                    .unwrap();
            }
            for blob in [
                doc.export(ExportMode::all_updates()).unwrap(),
                doc.export(ExportMode::updates_in_range(vec![IdSpan::new(7, 0, 1)]))
                    .unwrap(),
                other.export(ExportMode::all_updates()).unwrap(),
            ] {
                assert!(updates(&blob), "round {round}");
            }
        }
        assert!(!updates(&doc.export(ExportMode::Snapshot).unwrap()));
    }

    #[test]
    fn delta_of_delta_reads_what_the_encoder_writes() {
        // Head 5, then deltas 1 (flag 10, 7 bits of 1 + 63), and 0 again
        // (flag 0): 5, 6, 7.
        let column = [1, 10, 2, 0b1010_0000, 0b0000_0000];
        // 10 bits used: the last byte's first two.
        assert_eq!(delta_of_delta(&column, 3, fits_u32).unwrap(), &[] as &[u8]);
        assert!(delta_of_delta(&column, 4, fits_u32).is_err());
        // A flag with nothing after it.
        assert!(delta_of_delta(&[1, 10, 1, 0x80], 2, fits_u32).is_err());
        // A last_used_bit that counts bits past the last byte.
        assert!(delta_of_delta(&[1, 10, 200, 0xff], 3, fits_u32).is_err());
    }

    #[test]
    fn a_run_is_read_as_loro_reads_it() {
        // A run of three 5s, then a literal run of 1 and 2: counts are
        // zigzag isize, values usize.
        let column = [6, 5, 3, 1, 2];
        let mut rle = Rle::new(&column, Ending::Lazy, usize_entry);
        let mut read = Vec::new();
        while let Some(value) = rle.next().unwrap() {
            read.push(value);
        }
        assert_eq!(read, [5, 5, 5, 1, 2]);
        // A count of 0 is an error; a run past the decoder's longest is
        // too.
        assert!(Rle::new(&[0], Ending::Eager, usize_entry).next().is_err());
        let mut long = Vec::new();
        let mut count = (MAX_RLE_COUNT + 1) * 2;
        while count >= 0x80 {
            long.push(count as u8 | 0x80);
            count >>= 7;
        }
        long.extend_from_slice(&[count as u8, 0]);
        assert!(Rle::new(&long, Ending::Eager, usize_entry).next().is_err());
        // A count that is not a varint ends a vector decoder's column, and
        // fails an iterator's.
        let bad = [0xff; 11];
        assert_eq!(
            Rle::new(&bad, Ending::Eager, usize_entry).next().unwrap(),
            None
        );
        assert!(Rle::new(&bad, Ending::Lazy, usize_entry).next().is_err());
    }

    #[test]
    fn a_list_value_owes_a_byte_per_element() {
        // A list of two nulls.
        assert!(loro_value(&mut Reader(&[7, 2, 0, 0])).is_ok());
        // A list of three, with two bytes left.
        assert!(loro_value(&mut Reader(&[7, 3, 0, 0])).is_err());
        // A list in a list that claims the bytes the outer one still owes.
        assert!(loro_value(&mut Reader(&[7, 3, 7, 1, 0])).is_err());
        // A map of one: key index, then the value.
        assert!(loro_value(&mut Reader(&[8, 1, 0, 3, 1])).is_ok());
    }
}
