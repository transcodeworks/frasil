//! Handing a library over to another peer (peers.md, 3.1 Hosting a space,
//! "Hand-over"; ext-libraries.md, 3.10 The home peer): the operator's
//! routes, behind the usage route's bearer token.
//!
//! 1. **Export** stops storing into the library: its spaces, attached or
//!    detached, take no store, answered `busy`, until the hand-over ends
//!    or is called off. It then streams the library's bundle (module
//!    `bundle`): the space index's records of its spaces and of the library
//!    (attachments, detachments, holds, copies, the tickets that attached
//!    its spaces, invite drops, wait markers), the shard's last reading,
//!    the records of its shard a page at a time, and the object pieces of
//!    its spaces and copies one at a time.
//! 2. **Import**, at the other peer, writes the bundle as it arrives into
//!    its own shard of the library, which goes on from the bundle's
//!    reading as a shard taken up from another machine does (overview.md,
//!    6.7 Clocks of a replicated peer), then into its index: the shard
//!    first, then the pieces, then the index, which names the spaces last.
//!    No entry retires. An import of a space that left this peer ends its
//!    departure record. A bundle that stops before its end is refused, and
//!    the pieces it put are deleted.
//! 3. **Depart**, at the exporting peer, keeps each space's departure
//!    record and forgets the library: its spaces' records, index entries,
//!    pieces and copies, and its own record. It keeps the tickets used, so
//!    that none attaches a space here again.
//! 4. **Resume** calls the hand-over off: the spaces store again.
//!
//! A library whose spaces are not all kept in its own shard, or one with a
//! move under way, is not handed over (`library_spread`, `moving`). In a
//! cluster, the owner of the library's shard freezes, pages out, takes in
//! and departs it; the node that answers the route reads and writes the
//! index and the pieces, which any node reaches.

use super::bundle::{self, Header, Item, Row};
use super::{Record, copy_home};
use crate::Shared;
use crate::records::{DROP, Departure, HOSTED, LIBRARY, OBJECT, ObjectRecord, Records, WAITS};
use crate::shards::SPACE_PREFIXES;
use crate::spaces::blocking;
use crate::state::{Core, lock};
use crate::util::log;
use frasil_base::time::Reading;
use frasil_events::EventId;
use frasil_libraries::LibraryId;
use frasil_store::StoreError;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, PoisonError};
use tokio::sync::mpsc;

/// The steps the owner of a library's shard takes (crate `cluster`, wire
/// tag `HANDOVER`).
pub(crate) mod step {
    /// Stop storing, and answer the shard's reading.
    pub const FREEZE: u8 = 1;
    /// A page of the shard's records after a given address.
    pub const RECORDS: u8 = 2;
    /// Store again.
    pub const RESUME: u8 = 3;
    /// Keep the departure records and forget the library.
    pub const DEPART: u8 = 4;
    /// Write a page of the shard's records here; the first page carries
    /// the reading the shard goes on from.
    pub const IMPORT: u8 = 5;
    /// The import is in the index: read the shared state again.
    pub const IMPORTED: u8 = 6;
}

/// The record bytes a page of the shard holds at most: well within an
/// internal link's frame.
const PAGE_BYTES: usize = 4 << 20;

/// The departures an owner remembers, so that a step re-sent after its
/// answer was lost is answered as it was. They live in memory: a restart
/// between the two answers `not_handing_over`, as for any unknown library.
const REMEMBERED_DEPARTURES: usize = 64;

/// A step's answer: its HTTP status, whether the body is JSON, and the
/// body.
pub(crate) type Answer = (u16, bool, Vec<u8>);

fn reason(status: u16, code: &str) -> Answer {
    (
        status,
        true,
        serde_json::to_vec(&serde_json::json!({ "code": code })).unwrap_or_default(),
    )
}

fn store_failed(error: &StoreError) -> Answer {
    log(format_args!("a hand-over step failed: {error}"));
    reason(503, "busy")
}

fn json(value: &serde_json::Value) -> Answer {
    (200, true, serde_json::to_vec(value).unwrap_or_default())
}

/// The space of an address `prefix || space || ...`.
fn space_of(address: &[u8]) -> Option<EventId> {
    Some(EventId(address.get(1..33)?.try_into().ok()?))
}

/// The spaces the index places in a shard, read from the index.
fn placed_in(records: &Records, shard: &str) -> Result<Vec<EventId>, StoreError> {
    Ok(records
        .scan(&[HOSTED])?
        .into_iter()
        .filter(|(_, record)| Records::hosted_shard(record).as_deref() == Some(shard))
        .filter_map(|(address, _)| space_of(&address))
        .collect())
}

/// Every record a shard keeps of its spaces, in order.
fn shard_rows(core: &Core, shard: &str) -> Result<Vec<Row>, StoreError> {
    let shards = core
        .shards
        .as_ref()
        .ok_or_else(|| StoreError::new("the records are kept in no shards"))?;
    let mut rows = Vec::new();
    for prefix in SPACE_PREFIXES {
        rows.extend(shards.scan_in(shard, &[prefix])?);
    }
    rows.sort();
    Ok(rows)
}

/// The keys of an object's pieces under `home`.
fn piece_keys(home: &[u8; 32], locator: &[u8; 64], object: &[u8]) -> Vec<String> {
    ObjectRecord::decode(object)
        .map(|record| {
            record
                .pieces
                .iter()
                .map(|&piece| crate::objects::piece_key(home, locator, piece))
                .collect()
        })
        .unwrap_or_default()
}

/// The pieces the shard's object records and the library's copies hold.
fn pieces_of(library: &LibraryId, shard: &[Row], index: &[Row]) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for (address, record) in shard {
        if address.first() != Some(&OBJECT) || address.len() != 97 {
            continue;
        }
        let (Some(space), Ok(locator)) = (space_of(address), <[u8; 64]>::try_from(&address[33..]))
        else {
            continue;
        };
        keys.extend(piece_keys(space.as_bytes(), &locator, record));
    }
    let home = copy_home(library);
    for (address, record) in index {
        if let Some(Record::Copy(locator, _, copy)) = library_row(address, record) {
            keys.extend(piece_keys(&home, &locator, &copy.object));
        }
    }
    keys.into_iter().collect()
}

/// A library record of the index, read.
fn library_row(address: &[u8], record: &[u8]) -> Option<Record> {
    if address.first() != Some(&LIBRARY) {
        return None;
    }
    Record::decode(*address.get(1)?, address.get(2..)?, record)
}

/// The index's records of a library and of the spaces it keeps in its
/// shard. Blocking.
fn index_rows(
    records: &Records,
    library: &LibraryId,
    spaces: &[EventId],
) -> Result<Vec<Row>, StoreError> {
    let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut get = |address: Vec<u8>| -> Result<(), StoreError> {
        if let Some(record) = records.get(&address)? {
            rows.insert(address, record);
        }
        Ok(())
    };
    get(Records::library_address(
        super::records::LIBRARY,
        library.as_str().as_bytes(),
    ))?;
    for space in spaces {
        get(Records::hosted_address(space))?;
        get(Records::waits_address(space))?;
        get(Records::library_address(
            super::records::ATTACHMENT,
            space.as_bytes(),
        ))?;
        get(Records::library_address(
            super::records::DETACHED,
            space.as_bytes(),
        ))?;
    }
    for space in spaces {
        for prefix in [
            [&[DROP][..], space.as_bytes()].concat(),
            Records::library_address(super::records::HOLD, space.as_bytes()),
        ] {
            rows.extend(records.scan(&prefix)?);
        }
    }
    // The tickets that attached its spaces, so that none attaches a space
    // again at the other peer.
    let tickets: Vec<Vec<u8>> = rows
        .iter()
        .filter_map(|(address, record)| match library_row(address, record) {
            Some(Record::Attachment(_, attachment)) => attachment.ticket,
            _ => None,
        })
        .map(|ticket| Records::library_address(super::records::TICKET, &ticket))
        .collect();
    for address in tickets {
        if let Some(record) = records.get(&address)? {
            rows.insert(address, record);
        }
    }
    for (address, record) in records.scan(&Records::library_address(super::records::COPY, &[]))? {
        if let Some(Record::Copy(_, of, _)) = library_row(&address, &record)
            && of == *library
        {
            rows.insert(address, record);
        }
    }
    Ok(rows.into_iter().collect())
}

/// Whether a bundle's index records are only what a hand-over of
/// `library` may hold: records of its spaces, which they place in its
/// shard, of the library itself, and the tickets that attached its spaces.
/// Its spaces.
fn check_index(index: &[Row], library: &LibraryId) -> Option<BTreeSet<EventId>> {
    let shard = crate::shards::library_shard(library.as_str());
    let spaces: BTreeSet<EventId> = index
        .iter()
        .filter(|(address, record)| {
            address.first() == Some(&HOSTED)
                && address.len() == 33
                && Records::hosted_shard(record).as_deref() == Some(shard.as_str())
        })
        .filter_map(|(address, _)| space_of(address))
        .collect();
    let of_spaces = |address: &[u8]| space_of(address).is_some_and(|space| spaces.contains(&space));
    let tickets: BTreeSet<_> = index
        .iter()
        .filter_map(|(address, record)| match library_row(address, record) {
            Some(Record::Attachment(space, attachment)) if spaces.contains(&EventId(space)) => {
                attachment.ticket
            }
            _ => None,
        })
        .collect();
    for (address, record) in index {
        let fits = match *address.first()? {
            HOSTED => spaces.contains(&space_of(address)?),
            WAITS => address.len() == 33 && of_spaces(address),
            DROP => address.len() == 65 && of_spaces(address),
            LIBRARY => match library_row(address, record)? {
                Record::Library(id, _) | Record::Copy(_, id, _) => id == *library,
                Record::Attachment(space, attachment) => {
                    spaces.contains(&EventId(space)) && attachment.library == *library
                }
                Record::Detached(space, _) | Record::Hold(space, _, _) => {
                    spaces.contains(&EventId(space))
                }
                Record::Ticket(id, _) => tickets.contains(&id),
                _ => false,
            },
            _ => false,
        };
        if !fits {
            return None;
        }
    }
    Some(spaces)
}

/// The key prefixes of the pieces a hand-over of `library` may hold: of
/// its spaces and of its copies.
fn piece_homes(spaces: &BTreeSet<EventId>, library: &LibraryId) -> Vec<String> {
    spaces
        .iter()
        .map(|space| *space.as_bytes())
        .chain([copy_home(library)])
        .map(|home| format!("{}/", crate::util::hex(&home)))
        .collect()
}

impl Core {
    /// Whether a space's library is being handed over: the space is kept
    /// in the shard of such a library, or attached to one. Stores into it
    /// are refused meanwhile (peers.md, 3.1 Hosting a space, "Hand-over").
    pub(crate) fn handing_over(&self, space: &EventId) -> bool {
        let libraries = lock(&self.libraries);
        let handing = libraries.handing();
        if handing.is_empty() {
            return false;
        }
        if libraries
            .attachment(space)
            .is_some_and(|attachment| handing.contains(&attachment.library))
        {
            return true;
        }
        let Some(shards) = &self.shards else {
            return false;
        };
        let shard = shards.space_shard_of(space.as_bytes());
        handing
            .iter()
            .any(|library| crate::shards::library_shard(library.as_str()) == shard)
    }

    /// Ends a space's departure record: it is imported, or handed back.
    pub(crate) async fn end_departure(&self, space: &EventId) {
        let had = self
            .departures
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(space)
            .is_some();
        let address = Records::departure_address(space);
        let clustered = self
            .shards
            .as_ref()
            .is_some_and(|shards| shards.clustered_now());
        if (had || clustered)
            && let Err(error) = self.writer.commit(Vec::new(), vec![address]).await
        {
            log(format_args!("a departure record was not ended: {error}"));
        }
    }

    /// Stops storing into a library's spaces, waits for every store under
    /// way, and answers the shard's reading.
    async fn freeze(&self, library: &LibraryId) -> Answer {
        lock(&self.departed).remove(library);
        let shard = crate::shards::library_shard(library.as_str());
        let (known, members) = {
            let libraries = lock(&self.libraries);
            (
                libraries.library(library).is_some(),
                libraries.members(library).copied().collect::<Vec<_>>(),
            )
        };
        if !known {
            return reason(404, "not_found");
        }
        let records = self.records.clone();
        let placed_shard = shard.clone();
        let placed = match blocking(move || placed_in(&records, &placed_shard)).await {
            Ok(placed) => placed,
            Err(error) => return store_failed(&error),
        };
        if members.iter().any(|space| !placed.contains(space)) {
            return reason(409, "library_spread");
        }
        if placed
            .iter()
            .any(|space| lock(&self.moves).contains_key(space))
        {
            return reason(409, "moving");
        }
        let frozen: BTreeSet<EventId> = placed.iter().copied().collect();
        let pending = {
            let mut libraries = lock(&self.libraries);
            let record = libraries.begin_handing(library, &frozen);
            self.submit_libraries(vec![record], Vec::new())
        };
        if let Err(error) = self.finish_libraries(pending).await {
            return store_failed(&error);
        }
        // Every writer that checked before the freeze ends first.
        for space in &placed {
            let _ = self.write(*space).await;
        }
        if let Err(error) = self.writer.barrier().await {
            return store_failed(&error);
        }
        let reading = self.shard_now(&shard, self.clock.now());
        (200, false, bundle::reading_value(&reading).encode())
    }

    /// The shard's records after `after`, a page at a time.
    async fn records_page(&self, library: &LibraryId, after: &[u8]) -> Answer {
        if !lock(&self.libraries).handing().contains(library) {
            return reason(409, "not_handing_over");
        }
        let shard = crate::shards::library_shard(library.as_str());
        if after.is_empty()
            && let Err(refused) = self.still_frozen(library, &shard).await
        {
            return refused;
        }
        let rows = match crate::spaces::blocking_here(|| shard_rows(self, &shard)) {
            Ok(rows) => rows,
            Err(error) => return store_failed(&error),
        };
        let mut page = Vec::new();
        let mut bytes = 0;
        let mut rest = rows
            .into_iter()
            .filter(|(address, _)| after.is_empty() || address.as_slice() > after)
            .peekable();
        while let Some((address, record)) = rest.next_if(|(address, record)| {
            page.is_empty() || bytes + address.len() + record.len() <= PAGE_BYTES
        }) {
            bytes += address.len() + record.len();
            page.push((address, record));
        }
        let more = rest.peek().is_some();
        (200, false, bundle::encode_page(&page, more))
    }

    /// The spaces the index places in a library's shard, which must be
    /// those the shard kept as the hand-over froze it: what the bundle
    /// carries is what the peer forgets (else `library_changed`).
    async fn still_frozen(&self, library: &LibraryId, shard: &str) -> Result<Vec<EventId>, Answer> {
        let records = self.records.clone();
        let placed_shard = shard.to_owned();
        let placed = blocking(move || placed_in(&records, &placed_shard))
            .await
            .map_err(|error| store_failed(&error))?;
        let now: BTreeSet<EventId> = placed.iter().copied().collect();
        let frozen = lock(&self.libraries).frozen(library).cloned();
        if frozen.is_some_and(|frozen| frozen == now) {
            Ok(placed)
        } else {
            Err(reason(409, "library_changed"))
        }
    }

    /// Whether a library is being handed over, by this node's memory or by
    /// the space index, whichever node froze it (peers.md, 3.1 Hosting a
    /// space, "Hand-over"): no move takes a space into or out of it
    /// meanwhile.
    pub(crate) async fn library_frozen(&self, library: &LibraryId) -> Result<bool, StoreError> {
        if lock(&self.libraries).handing().contains(library) {
            return Ok(true);
        }
        let records = self.records.clone();
        let address =
            Records::library_address(super::records::HANDING_OVER, library.as_str().as_bytes());
        blocking(move || records.get(&address))
            .await
            .map(|record| record.is_some())
    }

    /// Calls a hand-over off.
    async fn resume(&self, library: &LibraryId) -> Answer {
        let pending = {
            let mut libraries = lock(&self.libraries);
            if !libraries.handing().contains(library) {
                return reason(409, "not_handing_over");
            }
            let address = libraries.end_handing(library);
            self.submit_libraries(Vec::new(), vec![address])
        };
        match self.finish_libraries(pending).await {
            Ok(_) => json(&serde_json::json!({ "library": library.as_str() })),
            Err(error) => store_failed(&error),
        }
    }

    /// Keeps each space's departure record and forgets the library: its
    /// spaces' records, index entries and pieces, its copies and its own
    /// record (peers.md, 3.1 Hosting a space, "Hand-over").
    async fn depart(&self, library: &LibraryId) -> Result<(usize, Vec<String>), Answer> {
        if !lock(&self.libraries).handing().contains(library) {
            // A step re-sent after its answer was lost: it was made.
            return match lock(&self.departed).get(library) {
                Some(&spaces) => Ok((spaces, Vec::new())),
                None => Err(reason(409, "not_handing_over")),
            };
        }
        let shard = crate::shards::library_shard(library.as_str());
        let spaces = self.still_frozen(library, &shard).await?;
        let mut departures = Vec::new();
        for space in &spaces {
            let Some(departure) = self.read(*space, departure_of_space).await else {
                return Err(reason(503, "busy"));
            };
            departures.push((*space, departure));
        }
        let records = self.records.clone();
        let of = library.clone();
        let gathered = spaces.clone();
        let gather = move || -> Result<(Vec<Row>, Vec<Vec<u8>>), StoreError> {
            let index = index_rows(&records, &of, &gathered)?;
            // The tickets used stay, so that none attaches a space here
            // again.
            let mut deletes: Vec<Vec<u8>> = index
                .iter()
                .filter(|(address, record)| {
                    !matches!(library_row(address, record), Some(Record::Ticket(..)))
                })
                .map(|(address, _)| address.clone())
                .collect();
            for space in &gathered {
                deletes.extend(records.space_addresses(space)?);
            }
            deletes.push(Records::library_address(
                super::records::HANDING_OVER,
                of.as_str().as_bytes(),
            ));
            Ok((index, deletes))
        };
        let (index, mut deletes) = match blocking(gather).await {
            Ok(found) => found,
            Err(error) => return Err(store_failed(&error)),
        };
        let shard_records = match crate::spaces::blocking_here(|| shard_rows(self, &shard)) {
            Ok(rows) => rows,
            Err(error) => return Err(store_failed(&error)),
        };
        let pieces = pieces_of(library, &shard_records, &index);
        deletes.extend(shard_records.into_iter().map(|(address, _)| address));
        deletes.sort();
        deletes.dedup();
        let puts: Vec<(Vec<u8>, Vec<u8>)> = departures
            .iter()
            .map(|(space, departure)| (Records::departure_address(space), departure.encode()))
            .collect();
        if let Err(error) = self.writer.commit(puts, deletes).await {
            return Err(store_failed(&error));
        }
        for space in &spaces {
            if let Ok(writing) = self.write(*space).await {
                self.forget_space(&writing);
            }
        }
        {
            let mut held = self
                .departures
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            held.extend(departures);
        }
        {
            let mut departed = lock(&self.departed);
            departed.insert(library.clone(), spaces.len());
            while departed.len() > REMEMBERED_DEPARTURES {
                departed.pop_first();
            }
        }
        if let Err(error) = crate::spaces::blocking_here(|| self.reload_shared()) {
            log(format_args!("the shared state was not read again: {error}"));
        }
        Ok((spaces.len(), pieces))
    }

    /// Writes a page of a handed-over shard here; the first takes the
    /// shard's timeline up from the other peer's reading.
    async fn take_in(
        &self,
        library: &LibraryId,
        reading: Option<Reading>,
        rows: Vec<Row>,
    ) -> Answer {
        let shard = crate::shards::library_shard(library.as_str());
        let Some(shards) = self.shards.clone() else {
            return reason(409, "not_sharded");
        };
        if let Some(reading) = reading {
            lock(&self.departed).remove(library);
            // A library this peer keeps a space of is here already. What
            // its shard holds otherwise is what an import that did not end
            // left, and goes.
            // Attachments alone are such a leftover: a space is kept here
            // only once its hosted row is.
            let members: Vec<EventId> = lock(&self.libraries).members(library).copied().collect();
            let kept = self.records.clone();
            match blocking(move || {
                for space in &members {
                    if kept.get(&Records::hosted_address(space))?.is_some() {
                        return Ok(true);
                    }
                }
                Ok(false)
            })
            .await
            {
                Ok(false) => {}
                Ok(true) => return reason(409, "exists"),
                Err(error) => return store_failed(&error),
            }
            let records = self.records.clone();
            let placed_shard = shard.clone();
            match blocking(move || placed_in(&records, &placed_shard)).await {
                Ok(placed) if placed.is_empty() => {}
                Ok(_) => return reason(409, "exists"),
                Err(error) => return store_failed(&error),
            }
            let name = shard.clone();
            let taken = shards.clone();
            match blocking(move || {
                taken.clear_unplaced(&name)?;
                taken.take_up(&name, reading)
            })
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    log(format_args!("{error}"));
                    return reason(409, "exists");
                }
            }
        }
        let name = shard.clone();
        match blocking(move || shards.commit_into(&name, rows, Vec::new())).await {
            Ok(()) => (200, true, b"{}".to_vec()),
            Err(error) => store_failed(&error),
        }
    }
}

/// A space's departure record: the public halves of every entry, recovery
/// entry and enrolled pseudonym it holds (peers.md, 3.1 Hosting a space,
/// "Hand-over"). A pseudonym is kept as the `ed || kc` of its root or
/// enrolment, so that its proof verifies under that `ed` after it left.
fn departure_of_space(space: &crate::space::Space) -> Departure {
    let mut departure = Departure::default();
    for entry in space.entries.entries() {
        departure.keys[0].insert(entry.read);
        departure.keys[1].insert(entry.upload);
    }
    let skeleton = space.skeleton();
    for (pseudonym, _) in skeleton.pseudonyms() {
        if let Some(keys) = skeleton.pseudonym_keys(pseudonym) {
            departure.pseudonyms.insert(keys.signatory().to_bytes());
        }
    }
    for entry in space.entries.recovery() {
        departure.keys[3].insert(entry.key);
    }
    departure
}

/// One step at the owner of a library's shard, on this node.
pub(crate) async fn step_here(
    shared: &Arc<Shared>,
    op: u8,
    library: &LibraryId,
    after: &[u8],
    reading: Option<Reading>,
    rows: Vec<Row>,
) -> Answer {
    let core = &shared.core;
    if core.shards.is_none() {
        return reason(409, "not_sharded");
    }
    match op {
        step::FREEZE => core.freeze(library).await,
        step::RECORDS => core.records_page(library, after).await,
        step::RESUME => core.resume(library).await,
        step::DEPART => {
            let (spaces, pieces) = match core.depart(library).await {
                Ok(gone) => gone,
                Err(refused) => return refused,
            };
            for key in &pieces {
                if let Err(error) = shared.blobs.delete(key).await {
                    log(format_args!("an object piece was not deleted: {error}"));
                }
            }
            log(format_args!(
                "{}: handed over, {spaces} spaces and {} pieces gone",
                library.as_str(),
                pieces.len()
            ));
            json(&serde_json::json!({ "library": library.as_str(), "spaces": spaces }))
        }
        step::IMPORT => core.take_in(library, reading, rows).await,
        step::IMPORTED => match crate::spaces::blocking_here(|| core.reload_shared()) {
            Ok(()) => json(&serde_json::json!({ "library": library.as_str() })),
            Err(error) => store_failed(&error),
        },
        _ => reason(400, "malformed"),
    }
}

/// One step at the owner of the library's shard, here or on another node.
async fn at_owner(
    shared: &Arc<Shared>,
    op: u8,
    library: &LibraryId,
    after: &[u8],
    reading: Option<Reading>,
    rows: Vec<Row>,
) -> Answer {
    if let Some(cluster) = shared.cluster.get().cloned() {
        return cluster.handover(op, library, after, reading, rows).await;
    }
    step_here(shared, op, library, after, reading, rows).await
}

/// What the export route answers: a refusal, or the bundle's bytes as
/// they are made, an error ending them early.
pub(crate) enum Export {
    /// The library is not exported.
    Refused(Answer),
    /// The bundle, in parts.
    Bundle(mpsc::Receiver<Result<Vec<u8>, String>>),
}

/// The export route: the library frozen and its bundle streamed, or a
/// refusal. The bundle holds the shard's records a page at a time and each
/// piece alone, so that neither is held whole.
pub(crate) async fn export(shared: &Arc<Shared>, library: &LibraryId) -> Export {
    let frozen = at_owner(shared, step::FREEZE, library, &[], None, Vec::new()).await;
    if frozen.0 != 200 {
        return Export::Refused(frozen);
    }
    let Some(reading) = frasil_base::cbor::decode(&frozen.2)
        .ok()
        .and_then(|value| bundle::read_reading(&value))
    else {
        return Export::Refused(reason(503, "busy"));
    };
    // The first page before any byte goes, so that a refusal answers with
    // its status.
    let first = at_owner(shared, step::RECORDS, library, &[], None, Vec::new()).await;
    if first.0 != 200 {
        return Export::Refused(first);
    }
    let Some(first) = bundle::decode_page(&first.2) else {
        return Export::Refused(reason(503, "busy"));
    };
    let records = shared.core.records.clone();
    let of = library.clone();
    let name = crate::shards::library_shard(library.as_str());
    let index = match blocking(move || {
        let spaces = placed_in(&records, &name)?;
        index_rows(&records, &of, &spaces)
    })
    .await
    {
        Ok(index) => index,
        Err(error) => return Export::Refused(store_failed(&error)),
    };
    let (tx, rx) = mpsc::channel(2);
    let shared = shared.clone();
    let library = library.clone();
    tokio::spawn(async move {
        let mut keys: BTreeSet<String> = pieces_of(&library, &[], &index).into_iter().collect();
        let header = Header {
            library: library.as_str().to_owned(),
            reading,
            index,
        };
        if tx.send(Ok(header.encode())).await.is_err() {
            return;
        }
        let (mut rows, mut more) = first;
        loop {
            keys.extend(pieces_of(&library, &rows, &[]));
            let after = rows.last().map(|(address, _)| address.clone());
            if !rows.is_empty() && tx.send(Ok(Item::Records(rows).encode())).await.is_err() {
                return;
            }
            let Some(after) = after.filter(|_| more) else {
                break;
            };
            let page = at_owner(&shared, step::RECORDS, &library, &after, None, Vec::new()).await;
            let Some(next) = (page.0 == 200)
                .then(|| bundle::decode_page(&page.2))
                .flatten()
            else {
                let _ = tx
                    .send(Err("a page of the shard was not read".into()))
                    .await;
                return;
            };
            (rows, more) = next;
        }
        for key in keys {
            match shared.blobs.get(&key).await {
                Ok(Some(bytes)) => {
                    if tx.send(Ok(Item::Piece(key, bytes).encode())).await.is_err() {
                        return;
                    }
                }
                Ok(None) => log(format_args!("{key}: a piece held is not stored")),
                Err(error) => {
                    log(format_args!("{error}"));
                    let _ = tx.send(Err(format!("{key}: not read"))).await;
                    return;
                }
            }
        }
        let _ = tx.send(Ok(Item::End.encode())).await;
    });
    Export::Bundle(rx)
}

/// Deletes the pieces an import put, once it ended without the library.
async fn delete_pieces(shared: &Arc<Shared>, keys: &[String]) {
    for key in keys {
        if let Err(error) = shared.blobs.delete(key).await {
            log(format_args!("an object piece was not deleted: {error}"));
        }
    }
}

/// A bundle's items as its body arrives.
struct Incoming {
    body: axum::body::BodyDataStream,
    items: bundle::Items,
}

impl Incoming {
    /// The next whole item; `Err` for a body that failed, an item past its
    /// limit, or a body that ended inside an item.
    async fn next(&mut self) -> Result<Option<Vec<u8>>, ()> {
        use futures_util::StreamExt;
        loop {
            if let Some(item) = self.items.take()? {
                return Ok(Some(item));
            }
            match self.body.next().await {
                Some(Ok(bytes)) => self.items.push(&bytes),
                Some(Err(_)) => return Err(()),
                None if self.items.partial() => return Err(()),
                None => return Ok(None),
            }
        }
    }
}

/// The import route: a bundle another peer exported, written here as it
/// arrives.
pub(crate) async fn import(
    shared: &Arc<Shared>,
    library: &LibraryId,
    body: axum::body::Body,
) -> Answer {
    let mut incoming = Incoming {
        body: body.into_data_stream(),
        items: bundle::Items::default(),
    };
    let Some(header) = incoming
        .next()
        .await
        .ok()
        .flatten()
        .and_then(|bytes| Header::decode(&bytes))
    else {
        return reason(400, "malformed");
    };
    if header.library != library.as_str() {
        return reason(400, "malformed");
    }
    let Some(spaces) = check_index(&header.index, library) else {
        return reason(400, "malformed");
    };
    let core = &shared.core;
    for space in &spaces {
        if core.tombstoned(space) {
            return reason(410, "erased");
        }
    }
    let records = core.records.clone();
    let named: Vec<EventId> = spaces.iter().copied().collect();
    let hosted = blocking(move || {
        for space in &named {
            if records.get(&Records::hosted_address(space))?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    })
    .await;
    match hosted {
        Ok(false) => {}
        Ok(true) => return reason(409, "exists"),
        Err(error) => return store_failed(&error),
    }
    // A library this peer configured keeps its settings. The same record
    // is what an import that did not end left, and the import goes on.
    let bundled = header
        .index
        .iter()
        .find(|(address, record)| matches!(library_row(address, record), Some(Record::Library(..))))
        .cloned();
    if let Some((address, record)) = bundled {
        let records = core.records.clone();
        match blocking(move || Ok(records.get(&address)?.is_some_and(|held| held != record))).await
        {
            Ok(false) => {}
            Ok(true) => return reason(409, "exists"),
            Err(error) => return store_failed(&error),
        }
    }
    // The shard, a page at a time; the first takes its timeline up, and
    // refuses what is here already, before any piece is put. Then the
    // pieces. A refusal or an error after the pieces are put deletes them.
    let mut put = Vec::new();
    let taken = take_in_items(
        shared,
        library,
        &spaces,
        header.reading,
        &mut incoming,
        &mut put,
    )
    .await;
    if let Err(refused) = taken {
        delete_pieces(shared, &put).await;
        return refused;
    }
    // The index names the spaces last.
    let (names, mut rest): (Vec<Row>, Vec<Row>) = header
        .index
        .into_iter()
        .partition(|(address, _)| address.first() == Some(&HOSTED));
    // Each invite drop with its locator, by which any node finds it by
    // address (ext-invite-links.md).
    let locators: Vec<Row> = rest
        .iter()
        .filter(|(address, _)| address.first() == Some(&DROP) && address.len() == 65)
        .filter_map(|(address, _)| {
            let space: [u8; 32] = address[1..33].try_into().ok()?;
            let drop: [u8; 32] = address[33..].try_into().ok()?;
            Some((
                Records::drop_locator_address(&drop),
                Records::drop_locator_record(&space),
            ))
        })
        .collect();
    rest.extend(locators);
    if let Err(error) = core.writer.commit(rest, Vec::new()).await {
        delete_pieces(shared, &put).await;
        return store_failed(&error);
    }
    let ended: Vec<Vec<u8>> = spaces.iter().map(Records::departure_address).collect();
    if let Err(error) = core.writer.commit(names, ended).await {
        delete_pieces(shared, &put).await;
        return store_failed(&error);
    }
    core.departures
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|space, _| !spaces.contains(space));
    let done = at_owner(shared, step::IMPORTED, library, &[], None, Vec::new()).await;
    if done.0 != 200 {
        return done;
    }
    if shared.cluster.get().is_some()
        && let Err(error) = crate::spaces::blocking_here(|| core.reload_shared())
    {
        log(format_args!("the shared state was not read again: {error}"));
    }
    json(&serde_json::json!({
        "library": library.as_str(),
        "spaces": spaces.len(),
    }))
}

/// Takes in a bundle's items after its header, through its end: each page
/// of the shard's records, written at the shard's owner, then each piece,
/// put; `put` gathers the pieces' keys. A page or a piece that is not the
/// library's, out of order, or a bundle that stops before its end is
/// malformed.
async fn take_in_items(
    shared: &Arc<Shared>,
    library: &LibraryId,
    spaces: &BTreeSet<EventId>,
    reading: Reading,
    incoming: &mut Incoming,
    put: &mut Vec<String>,
) -> Result<(), Answer> {
    let malformed = || reason(400, "malformed");
    let homes = piece_homes(spaces, library);
    let mut first = Some(reading);
    let mut last_row: Option<Vec<u8>> = None;
    let mut last_key: Option<String> = None;
    loop {
        let bytes = incoming.next().await.map_err(|_| malformed())?;
        let item = bytes
            .and_then(|bytes| Item::decode(&bytes))
            .ok_or_else(malformed)?;
        let rows = match &item {
            Item::Records(rows) if last_key.is_none() => {
                for (address, _) in rows {
                    let ours = address
                        .first()
                        .is_some_and(|prefix| SPACE_PREFIXES.contains(prefix))
                        && space_of(address).is_some_and(|space| spaces.contains(&space));
                    if !ours || last_row.as_ref().is_some_and(|last| last >= address) {
                        return Err(malformed());
                    }
                    last_row = Some(address.clone());
                }
                rows.clone()
            }
            Item::Records(_) => return Err(malformed()),
            Item::Piece(..) | Item::End => Vec::new(),
        };
        // The shard's first page, or its taking up with none.
        if first.is_some() || !rows.is_empty() {
            let taken = at_owner(shared, step::IMPORT, library, &[], first.take(), rows).await;
            if taken.0 != 200 {
                return Err(taken);
            }
        }
        match item {
            Item::Records(_) => {}
            Item::Piece(key, bytes) => {
                if !homes.iter().any(|home| key.starts_with(home.as_str()))
                    || last_key.as_ref().is_some_and(|last| *last >= key)
                {
                    return Err(malformed());
                }
                last_key = Some(key.clone());
                put.push(key.clone());
                if let Err(error) = shared.blobs.put(&key, bytes).await {
                    log(format_args!("{error}"));
                    return Err(reason(503, "busy"));
                }
            }
            Item::End => {
                return match incoming.next().await {
                    Ok(None) => Ok(()),
                    _ => Err(malformed()),
                };
            }
        }
    }
}

/// The depart route: departure records kept, the library forgotten, and
/// its pieces deleted.
pub(crate) async fn depart(shared: &Arc<Shared>, library: &LibraryId) -> Answer {
    at_owner(shared, step::DEPART, library, &[], None, Vec::new()).await
}

/// The resume route: the hand-over called off.
pub(crate) async fn resume(shared: &Arc<Shared>, library: &LibraryId) -> Answer {
    at_owner(shared, step::RESUME, library, &[], None, Vec::new()).await
}
