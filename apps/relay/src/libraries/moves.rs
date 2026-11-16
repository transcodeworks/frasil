//! A ticket's move of a space into a library kept in another shard
//! (ext-libraries.md, 3.3 Attaching, Move), and the copies that keep each
//! hold within one library (3.8 Keeping a held object, "Holds across a
//! move").
//!
//! A library is one shard (crate `shards`), so a move between libraries
//! moves the space's records into the target library's shard, which may be
//! kept by another node. No node writes another's shard:
//!
//! 1. The owner of the space's shard, the **source**, checks the ticket
//!    (section 3.3, steps 1 and 2), holds the space for writing, and
//!    records the move, with the ticket's ID, in the space index: only
//!    while the index still names its shard and records no other move. From
//!    then on no store goes into the space at the source. The ticket is not
//!    yet used.
//! 2. It makes the copies the move needs, and hands the space's records,
//!    in pages, to the owner of the target shard, the **target**, which
//!    writes them into its own shard and log, one page of a space at a
//!    time. Before each page the source checks it still answers for its
//!    shard.
//!    The target keeps the copies each page carries in its shard, beside
//!    the space's records, and takes a page only once its shard holds the
//!    page before: a node that becomes the target shard's owner during the
//!    move carries it on from what the shard holds.
//! 3. With the last page the target checks that the ticket has attached
//!    nothing meanwhile, its library's headroom for the space and the
//!    copies made into it (section 3.3, step 3), and that its shard holds
//!    exactly the records the source sent, by their digest. It records the
//!    ticket used, only while the index keeps no record of it, in a commit
//!    of its own: the ticket's record is kept in another shard of the index
//!    than the move's, and one commit's expectations name one shard. Then,
//!    only while the index keeps the move's record and names the source
//!    shard, it makes the index name its shard and the target library,
//!    records the copies made into either library, and drops the move's
//!    record, in one step (step 4). Only then does the usage move show in
//!    either ledger. A move refused for its headroom leaves the ticket
//!    unused, and so does one abandoned at that step, whose ticket's
//!    record is dropped again.
//! 4. The source forgets the space's records in its shard and tells every
//!    node where the space is.
//!
//! The source abandons a move the target refuses, or cannot be reached
//! for: it drops the move's record, only while the index keeps it. So of
//! the target's last step and the source's abandoning, one is made, and
//! the index names exactly one shard. A crash at any step leaves the
//! record in the index; whichever node owns the source shard next carries
//! the move on from its first page, or abandons it ([`resume_moves`]).
//! What a shard keeps of a space the index places elsewhere, and no move
//! brings in, is collected as the shard opens (crate `shards`).

use super::{Copy, Libraries, LibraryId, Record, Request, copy_home};
use crate::Shared;
use crate::cluster::wire::{MoveAnswer, MoveIn};
use crate::objects::piece_key;
use crate::records::{ARRIVAL, MoveRecord, OFFSET, ObjectRecord, Records};
use crate::shards::{SPACE_PREFIXES, Shards};
use crate::spaces::{Writing, blocking};
use crate::state::{Core, Grant, On, Outgoing, lock, refused};
use crate::util::log;
use frasil_base::time::Reading;
use frasil_events::EventId;
use frasil_libraries::{LibraryAttach, LibraryClass, Purpose, TicketId};
use frasil_store::Commit;
use frasil_transport::messages::Accepted;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

/// Records by address.
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// What the target keeps in memory of the spaces moving into its shards:
/// one gate per space, held while a page is applied and the target names
/// itself.
#[derive(Debug, Default)]
pub(crate) struct Arrivals {
    gates: HashMap<EventId, Arc<tokio::sync::Mutex<()>>>,
}

/// Which moves this node's memory took or let go of while the index's
/// moves are read again ([`Core::reload_shared`]): the reading may predate
/// a change made here meanwhile, which must not be undone by it. A move
/// the target made, read before its last step and taken into memory after
/// it, would otherwise leave the space refusing every store at its new
/// owner, which carries on no move whose source shard it does not keep.
#[derive(Debug, Default)]
pub(crate) struct MoveChanges {
    /// A count of every change memory took.
    seq: u64,
    /// The readings under way.
    reading: usize,
    /// While a reading is under way: the count at each space's last change.
    at: BTreeMap<EventId, u64>,
}

impl Core {
    /// Memory takes a move under way. The caller holds the moves' lock.
    fn note_move(&self, space: EventId) {
        let mut changes = lock(&self.move_changes);
        changes.seq += 1;
        if changes.reading > 0 {
            let seq = changes.seq;
            changes.at.insert(space, seq);
        }
    }

    /// Memory takes a move under way of `space`.
    pub(crate) fn move_under_way(&self, space: EventId, intent: MoveRecord) {
        let mut moves = lock(&self.moves);
        moves.insert(space, intent);
        self.note_move(space);
    }

    /// Memory lets go of a move of `space`: made, abandoned, or not this
    /// node's to know.
    pub(crate) fn move_ended(&self, space: &EventId) {
        let mut moves = lock(&self.moves);
        moves.remove(space);
        self.note_move(*space);
    }

    /// A reading of the index's moves begins: the count to pass to
    /// [`Self::moves_read`], which must follow.
    pub(crate) fn moves_reading(&self) -> u64 {
        let mut changes = lock(&self.move_changes);
        changes.reading += 1;
        changes.seq
    }

    /// The index's moves, read since `since`, taken into memory, except a
    /// space whose move memory took or let go of meanwhile, which stays as
    /// that change left it. Ends the reading; `read` is `None` if it
    /// failed, and memory keeps what it has.
    pub(crate) fn moves_read(&self, since: u64, read: Option<BTreeMap<EventId, MoveRecord>>) {
        let mut moves = lock(&self.moves);
        let mut changes = lock(&self.move_changes);
        if let Some(mut read) = read {
            for (space, seq) in &changes.at {
                if *seq <= since {
                    continue;
                }
                match moves.get(space) {
                    Some(intent) => {
                        read.insert(*space, intent.clone());
                    }
                    None => {
                        read.remove(space);
                    }
                }
            }
            *moves = read;
        }
        changes.reading = changes.reading.saturating_sub(1);
        if changes.reading == 0 {
            changes.at.clear();
        }
    }
}

/// An arrival record: the move's record and the copies one page carried,
/// `{1: move record, 2: [* [key, bytes]]}`.
fn arrival(intent: &[u8], copies: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    use frasil_base::cbor::{Map, Value};
    let mut map = Map::new();
    map.insert(1, Value::from(intent));
    map.insert(
        2,
        Value::Array(
            copies
                .iter()
                .map(|(key, bytes)| {
                    Value::Array(vec![
                        Value::from(key.as_slice()),
                        Value::from(bytes.as_slice()),
                    ])
                })
                .collect(),
        ),
    );
    Value::Map(map).encode()
}

/// An arrival record, read: the move's record and the copies.
fn read_arrival(bytes: &[u8]) -> Option<(Vec<u8>, Rows)> {
    let value = frasil_base::cbor::decode(bytes).ok()?;
    let map = value.as_map().ok()?;
    if map.len() != 2 {
        return None;
    }
    let intent = map.get(&1)?.as_bytes().ok()?.to_vec();
    let mut copies = Vec::new();
    for item in map.get(&2)?.as_array().ok()? {
        let [key, bytes] = item.as_array().ok()? else {
            return None;
        };
        copies.push((
            key.as_bytes().ok()?.to_vec(),
            bytes.as_bytes().ok()?.to_vec(),
        ));
    }
    Some((intent, copies))
}

/// The arrival records a shard keeps of a space, by page.
fn arrivals(
    shards: &Shards,
    shard: &str,
    space: &EventId,
) -> Result<Rows, frasil_store::StoreError> {
    let mut start = vec![ARRIVAL];
    start.extend_from_slice(space.as_bytes());
    shards.scan_in(shard, &start)
}

/// SHA-256 over records, in order, each its address and record with their
/// lengths.
fn digest(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"frasil-relay/move/v1\0");
    for (address, record) in records {
        hash.update((address.len() as u64).to_be_bytes());
        hash.update(address);
        hash.update((record.len() as u64).to_be_bytes());
        hash.update(record);
    }
    hash.finalize().to_vec()
}

/// Whether this node still answers for a move's source shard: it keeps the
/// shard, and in a cluster its lease holds.
fn still_source(shared: &Arc<Shared>, intent: &MoveRecord) -> bool {
    let kept = shared
        .core
        .shards
        .as_ref()
        .is_some_and(|shards| shards.keeps_shard(&intent.source));
    kept && shared
        .cluster
        .get()
        .is_none_or(|cluster| cluster.answering(&intent.source))
}

/// The largest page of a space's records a move hands over at once,
/// within an internal link's frame.
const PAGE: usize = 4 << 20;

/// `LibraryAttach` with purpose move (ext-libraries.md, 3.3 Attaching): a
/// space moved into a library kept in another shard moves as this
/// module's documentation says; any other is recorded at once.
pub(crate) async fn library_move(
    shared: &Arc<Shared>,
    on: &On,
    grants: &mut BTreeMap<EventId, Grant>,
    attach: &LibraryAttach,
) -> Outgoing {
    let core = &shared.core;
    let Some(shards) = core.shards.clone() else {
        return core.library_attach(on, grants, attach).await;
    };
    let space = EventId(attach.space);
    let request = Request {
        purpose: Purpose::Move,
        space,
        signed: &attach.signed,
        wall: on.now.wall,
        hosted: core.hosts(&space),
        store_right: grants.get(&space).is_some_and(|grant| grant.rights.store),
    };
    // 1. The store right, and 2. check_ticket. The target's owner judges
    // 3., the headroom, with its library's ledger, before its last step
    // records the ticket used.
    let ticket = match lock(&core.libraries).check(&request, &|_| 0) {
        Ok(ticket) => ticket,
        Err(class) => return refused(attach.request, class.code()),
    };
    let source = shards.space_shard_of(space.as_bytes());
    let target = crate::shards::library_shard(ticket.library.as_str());
    if source == target {
        return core.library_attach(on, grants, attach).await;
    }
    let leaving = lock(&core.libraries)
        .attachment(&space)
        .map(|attachment| attachment.library.clone());
    if moving_blocked(&lock(&core.libraries), &space, &ticket.library)
        || frozen(core, &ticket.library).await
        || match &leaving {
            Some(leaving) => frozen(core, leaving).await,
            None => false,
        }
    {
        return refused(attach.request, "busy");
    }
    let Ok(writing) = core.write(space).await else {
        return refused(attach.request, "busy");
    };
    if lock(&core.moves).contains_key(&space) || !writing.hosted() {
        return refused(attach.request, "busy");
    }
    let intent = MoveRecord {
        source,
        target,
        library: ticket.library.as_str().to_owned(),
        ticket: Some(ticket.id.to_vec()),
        at: on.now,
        not_after: Some(ticket.not_after),
    };
    match record_intent(core, &space, &intent).await {
        Ok(true) => {}
        Ok(false) => return refused(attach.request, "busy"),
        Err(error) => {
            // It may be recorded: the space takes no store until the
            // sweep carries the move on or abandons it.
            log(format_args!("a move is not known to be recorded: {error}"));
            core.move_under_way(space, intent);
            resume_soon(shared, &space);
            return refused(attach.request, "busy");
        }
    }
    crate::testing::move_step(
        space.as_bytes(),
        &intent.library,
        crate::testing::MoveStep::Recorded,
    )
    .await;
    match carry(shared, &writing, &intent).await {
        Ok(()) => Outgoing::Control(
            Accepted {
                request: attach.request,
            }
            .encode(),
        ),
        Err(code) => {
            resume_soon(shared, &space);
            refused(attach.request, &code)
        }
    }
}

/// A move left under way, as one the index did not settle, carried on or
/// abandoned once the space is no longer held, without waiting for the
/// next sweep, for as long as a minute: the space takes no store
/// meanwhile.
fn resume_soon(shared: &Arc<Shared>, space: &EventId) {
    if !lock(&shared.core.moves).contains_key(space) {
        return;
    }
    let shared = shared.clone();
    let space = *space;
    tokio::spawn(async move {
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if !lock(&shared.core.moves).contains_key(&space) {
                return;
            }
            resume_moves(&shared).await;
        }
    });
}

/// Whether a library a move involves is being handed over to another peer,
/// which takes no move in or out.
fn moving_blocked(libraries: &Libraries, space: &EventId, target: &LibraryId) -> bool {
    let handing = libraries.handing();
    handing.contains(target)
        || libraries
            .attachment(space)
            .is_some_and(|attachment| handing.contains(&attachment.library))
}

/// Whether a library is being handed over to another peer, as memory or
/// the index keeps its freeze (peers.md, 3.1 Hosting a space,
/// "Hand-over"); so when the index cannot tell.
async fn frozen(core: &Core, library: &LibraryId) -> bool {
    core.library_frozen(library).await.unwrap_or(true)
}

/// Records a move in the space index, only while the index names its
/// source shard and records no other move: whether it was recorded. Its
/// ticket is recorded used only by the target's last step.
pub(super) async fn record_intent(
    core: &Core,
    space: &EventId,
    intent: &MoveRecord,
) -> Result<bool, frasil_store::StoreError> {
    let address = Records::move_address(space);
    let puts = vec![(address.clone(), intent.encode())];
    let commit = Commit::new(puts, Vec::new())
        .expecting(&address, None)
        .expecting(
            &Records::hosted_address(space),
            Some(&Records::hosted_record(&intent.source)),
        );
    let made = core.writer.submit(commit).await?;
    if made {
        core.move_under_way(*space, intent.clone());
    }
    Ok(made)
}

/// Carries a recorded move out, at the source, holding the space for
/// writing: the copies, the pages, and the source's last step; or the
/// move abandoned. `Ok` once the index names the target; else the reason
/// code to answer.
async fn carry(shared: &Arc<Shared>, writing: &Writing, intent: &MoveRecord) -> Result<(), String> {
    let core = &shared.core;
    let space = writing.id;
    let Some(shards) = core.shards.clone() else {
        return Err("busy".into());
    };
    if core.writer.barrier().await.is_err() {
        return Err("busy".into());
    }
    let Ok(library) = LibraryId::new(&intent.library) else {
        return abandoned(shared, writing, intent, "malformed", &[], Vec::new()).await;
    };
    let reading = core.space_now(&space, shared.clock.now()).timeline;
    let records = {
        let shards = shards.clone();
        let source = intent.source.clone();
        blocking(move || space_records(&shards, &source, &space)).await
    };
    let Ok(records) = records else {
        return abandoned(shared, writing, intent, "busy", &[], Vec::new()).await;
    };
    let (mut copies, pieces, leaving) = make_copies(shared, &space, &library, intent.at).await;
    // The copies into the library the space leaves go with the pages too,
    // and the target records them in its last step.
    copies.extend(leaving.iter().map(|(of, locator, copy)| {
        let (_, key, bytes) = Record::Copy(*locator, of.clone(), copy.clone()).encode();
        (key, bytes)
    }));
    let usage = core.used_bytes(&space);
    let sum = digest(&records);
    let pages = paginate(copies, records, crate::testing::move_page_bytes(PAGE));
    let count = pages.len();
    let mut outcome = Err("busy".to_owned());
    for (number, (page, copies)) in pages.into_iter().enumerate() {
        let last = number + 1 == count;
        if last {
            crate::testing::move_step(
                space.as_bytes(),
                &intent.library,
                crate::testing::MoveStep::LastPage,
            )
            .await;
        }
        // A source that no longer answers for its shard leaves the move to
        // the node that does, and abandons nothing.
        if !still_source(shared, intent) {
            return Err("busy".into());
        }
        let page = MoveIn {
            epoch: 0,
            space: *space.as_bytes(),
            intent: intent.encode(),
            page: number as u64,
            last,
            usage,
            reading,
            records: page,
            copies,
            digest: if last { sum.clone() } else { Vec::new() },
        };
        match send(shared, &intent.target, page).await {
            Some(MoveAnswer::Taken) if !last => {}
            Some(MoveAnswer::Done) if last => {
                outcome = Ok(());
                break;
            }
            Some(MoveAnswer::Refused(code)) => {
                outcome = Err(code);
                break;
            }
            _ => break,
        }
    }
    match outcome {
        Ok(()) => {
            moved_here(shared, writing, intent, &library).await;
            record_leaving(core, leaving).await;
            Ok(())
        }
        Err(code) => {
            if !still_source(shared, intent) {
                return Err("busy".into());
            }
            abandoned(shared, writing, intent, &code, &pieces, leaving).await
        }
    }
}

/// Abandons a move: its record dropped, only while the index keeps it, and
/// the pieces of the copies made for the target deleted. `Err(code)` once
/// abandoned, or if the index cannot tell; `Ok`, after the source's last
/// step, if the target made the move first.
async fn abandoned(
    shared: &Arc<Shared>,
    writing: &Writing,
    intent: &MoveRecord,
    code: &str,
    pieces: &[String],
    leaving: Vec<(LibraryId, [u8; 64], Copy)>,
) -> Result<(), String> {
    let core = &shared.core;
    match abandon(core, &writing.id, intent).await {
        Ok(true) => {
            for key in pieces {
                if let Err(error) = shared.blobs.delete(key).await {
                    log(format_args!("a copy's piece was not deleted: {error}"));
                }
            }
            Err(code.to_owned())
        }
        Ok(false) => {
            if let Ok(library) = LibraryId::new(&intent.library) {
                moved_here(shared, writing, intent, &library).await;
                record_leaving(core, leaving).await;
            }
            Ok(())
        }
        Err(error) => {
            log(format_args!("a move was not abandoned: {error}"));
            Err("busy".into())
        }
    }
}

/// Takes into this node's memory the copies a move made into the library
/// the space left, once the index names the target, and records them
/// again: the target's last step recorded them already. An abandoned move
/// records none, and its pieces go.
async fn record_leaving(core: &Core, made: Vec<(LibraryId, [u8; 64], Copy)>) {
    if made.is_empty() {
        return;
    }
    let pending = {
        let mut libraries = lock(&core.libraries);
        let puts = made
            .into_iter()
            .map(|(library, locator, copy)| libraries.add_copy(library, locator, copy))
            .collect();
        core.submit_libraries(puts, Vec::new())
    };
    if core.finish_libraries(pending).await.is_err() {
        log("a move's copies into the library it leaves were not recorded");
    }
}

/// Drops a move's record, only while the index keeps it: whether it was
/// abandoned (`false`: the target made it).
async fn abandon(
    core: &Core,
    space: &EventId,
    intent: &MoveRecord,
) -> Result<bool, frasil_store::StoreError> {
    let address = Records::move_address(space);
    let commit =
        Commit::new(Vec::new(), vec![address.clone()]).expecting(&address, Some(&intent.encode()));
    if core.writer.submit(commit).await? {
        core.move_ended(space);
        return Ok(true);
    }
    // Gone: the target made the move, or another node abandoned it.
    let shards = core.shards.clone();
    let id = *space.as_bytes();
    let placed = blocking(move || match shards {
        Some(shards) => shards.locate_fresh(&id),
        None => Ok(None),
    })
    .await?;
    core.move_ended(space);
    Ok(placed.as_deref() != Some(intent.target.as_str()))
}

/// Every record a shard keeps of a space, in order.
fn space_records(
    shards: &Shards,
    shard: &str,
    space: &EventId,
) -> Result<Rows, frasil_store::StoreError> {
    let mut out = Vec::new();
    for prefix in SPACE_PREFIXES {
        if prefix == OFFSET || prefix == ARRIVAL {
            continue;
        }
        let mut start = vec![prefix];
        start.extend_from_slice(space.as_bytes());
        out.extend(shards.scan_in(shard, &start)?);
    }
    Ok(out)
}

/// Copies, then records, in pages of at most `limit` bytes, at least one
/// page, and at least one row in each: each page's records and copies.
fn paginate(copies: Rows, records: Rows, limit: usize) -> Vec<(Rows, Rows)> {
    let mut pages: Vec<(Rows, Rows)> = vec![(Vec::new(), Vec::new())];
    let mut bytes = 0;
    let rows = copies
        .into_iter()
        .map(|row| (row, true))
        .chain(records.into_iter().map(|row| (row, false)));
    for ((key, value), copy) in rows {
        let size = key.len() + value.len() + 16;
        let empty = pages
            .last()
            .is_none_or(|(records, copies)| records.is_empty() && copies.is_empty());
        if bytes + size > limit && !empty {
            pages.push((Vec::new(), Vec::new()));
            bytes = 0;
        }
        bytes += size;
        if let Some((records, copies)) = pages.last_mut() {
            if copy {
                copies.push((key, value));
            } else {
                records.push((key, value));
            }
        }
    }
    pages
}

/// Sends a page to the owner of the target shard: here, or over the
/// cluster's link. None if no owner answers.
async fn send(shared: &Arc<Shared>, target: &str, page: MoveIn) -> Option<MoveAnswer> {
    match shared.cluster.get().cloned() {
        Some(cluster) => cluster.move_in(target, page).await,
        None => Some(move_in(shared, page).await),
    }
}

/// The source's last step, once the index names the target: memory takes
/// the attachment, the space's records leave the source's shard while
/// this node still answers for it, and every node learns where the space
/// is.
async fn moved_here(
    shared: &Arc<Shared>,
    writing: &Writing,
    intent: &MoveRecord,
    library: &LibraryId,
) {
    let core = &shared.core;
    let space = writing.id;
    core.move_ended(&space);
    {
        let mut libraries = lock(&core.libraries);
        let _ = libraries.attach(space, library, ticket_of(intent), intent.at);
        if let Some(used) = ticket_used(intent) {
            libraries.learn(used);
        }
    }
    let Some(shards) = core.shards.clone() else {
        return;
    };
    shards.set_placement(space.as_bytes(), &intent.target);
    writing.unload();
    if still_source(shared, intent) {
        let source = intent.source.clone();
        let left = blocking(move || {
            let mut gone: Vec<Vec<u8>> = space_records(&shards, &source, &space)?
                .into_iter()
                .map(|(address, _)| address)
                .collect();
            gone.push(Records::offset_address(&space));
            shards.commit_into(&source, Vec::new(), gone)
        })
        .await;
        if let Err(error) = left {
            log(format_args!(
                "a moved space's records stay in its old shard until it opens: {error}"
            ));
        }
    }
    if let Some(cluster) = shared.cluster.get().cloned() {
        cluster.moved(space, &intent.target).await;
    }
}

fn ticket_of(intent: &MoveRecord) -> Option<TicketId> {
    intent
        .ticket
        .as_deref()
        .and_then(|ticket| TicketId::try_from(ticket).ok())
}

/// The record of a move's ticket used, kept until its `not_after` and
/// `ticket_skew` pass; for a record that names no `not_after`, a lifetime
/// from the move's reading.
fn ticket_used(intent: &MoveRecord) -> Option<Record> {
    let id = ticket_of(intent)?;
    let not_after = intent.not_after.unwrap_or_else(|| {
        intent
            .at
            .wall
            .unwrap_or(0)
            .saturating_add(frasil_libraries::settings::TICKET_LIFETIME)
    });
    Some(Record::Ticket(id, not_after))
}

/// Whether the index records a ticket used.
async fn ticket_recorded(core: &Core, id: &TicketId) -> Result<bool, frasil_store::StoreError> {
    let records = core.records.clone();
    let address = Records::library_address(super::records::TICKET, id);
    Ok(blocking(move || records.get(&address)).await?.is_some())
}

/// The target's side of a page (this module's documentation, steps 2 and
/// 3).
pub(crate) async fn move_in(shared: &Arc<Shared>, page: MoveIn) -> MoveAnswer {
    let core = &shared.core;
    let Some(shards) = core.shards.clone() else {
        return MoveAnswer::Refused("busy".into());
    };
    let space = EventId(page.space);
    let Some(intent) = MoveRecord::decode(&page.intent) else {
        return MoveAnswer::Refused("malformed".into());
    };
    if !shards.keeps_shard(&intent.target) {
        return MoveAnswer::NotMine(0);
    }
    let Ok(library) = LibraryId::new(&intent.library) else {
        return MoveAnswer::Refused("malformed".into());
    };
    if lock(&core.libraries).handing().contains(&library) || frozen(core, &library).await {
        return MoveAnswer::Refused("busy".into());
    }
    // One page of a space at a time, through the target's last step.
    let gate = {
        let mut arrivals = lock(&core.arrivals);
        arrivals.gates.entry(space).or_default().clone()
    };
    let _held = gate.lock().await;
    // A page sent again once the move was made or abandoned changes
    // nothing.
    match recorded(core, &space).await {
        Ok(Some(bytes)) if bytes == page.intent => {}
        Ok(_) => return settled(&shards, &space, &intent).await,
        Err(_) => return MoveAnswer::Refused("busy".into()),
    }
    // Only the space's own records, by its prefixes, as the source reads
    // them.
    let own = |address: &[u8]| {
        address.first().is_some_and(|prefix| {
            SPACE_PREFIXES.contains(prefix) && *prefix != OFFSET && *prefix != ARRIVAL
        }) && address.get(1..33) == Some(&page.space[..])
    };
    if !page.records.iter().all(|(address, _)| own(address)) {
        return MoveAnswer::Refused("malformed".into());
    }
    // The copies the earlier pages carried, as the target shard keeps them:
    // every earlier page of this move, or the page is refused.
    let earlier = if page.page == 0 {
        Vec::new()
    } else {
        let shards = shards.clone();
        let target = intent.target.clone();
        match blocking(move || arrivals(&shards, &target, &space)).await {
            Ok(rows) => rows,
            Err(_) => return MoveAnswer::Refused("busy".into()),
        }
    };
    let mut carried: Rows = Vec::new();
    for (number, (address, record)) in earlier.iter().enumerate() {
        match read_arrival(record) {
            Some((recorded, copies))
                if recorded == page.intent
                    && *address == Records::arrival_address(&space, number as u64) =>
            {
                carried.extend(copies);
            }
            _ => return MoveAnswer::Refused("busy".into()),
        }
    }
    if earlier.len() as u64 != page.page {
        log("a move's page came before the page it follows");
        return MoveAnswer::Refused("busy".into());
    }
    carried.extend(page.copies.iter().cloned());
    // Copies into the target library, which its headroom must hold, and
    // into the library the space leaves.
    let mut copies: Vec<([u8; 64], Copy)> = Vec::new();
    let mut leaving: Vec<(LibraryId, [u8; 64], Copy)> = Vec::new();
    for (key, bytes) in &carried {
        match Record::decode(super::records::COPY, key, bytes) {
            Some(Record::Copy(locator, of, copy)) if of == library => copies.push((locator, copy)),
            Some(Record::Copy(locator, of, copy)) => leaving.push((of, locator, copy)),
            _ => return MoveAnswer::Refused("malformed".into()),
        }
    }
    let mut puts = page.records.clone();
    if page.last {
        // 2. The ticket has attached nothing since the source checked it:
        // another move it carried was made first.
        if let Some(id) = ticket_of(&intent) {
            match ticket_recorded(core, &id).await {
                Ok(false) => {}
                Ok(true) => {
                    clear(&shards, &intent.target, &space).await;
                    return MoveAnswer::Refused(LibraryClass::TicketUsed.code().into());
                }
                Err(_) => return MoveAnswer::Refused("busy".into()),
            }
        }
        // 3. The target library's headroom holds the space's usage and the
        // copies made into it (ext-libraries.md, 3.3 Attaching, Move), by
        // the settings the index keeps.
        learn_library(core, &library).await;
        core.know_library_members(&library).await;
        let room = {
            let libraries = lock(&core.libraries);
            let adds = copies
                .iter()
                .filter(|(locator, _)| libraries.copy(&library, locator).is_none())
                .fold(page.usage, |total, (_, copy)| {
                    total.saturating_add(copy.bytes)
                });
            let room = libraries.headroom(&library, &|id| {
                if *id == space { 0 } else { core.used_bytes(id) }
            });
            room.map(|room| room - i128::from(adds))
        };
        if room.is_some_and(|room| room < 0) {
            clear(&shards, &intent.target, &space).await;
            return MoveAnswer::Refused(LibraryClass::QuotaExceeded.code().into());
        }
        let shard_now = core.shard_now(&intent.target, shared.clock.now()).timeline;
        puts.push((
            Records::offset_address(&space),
            Records::offset_record(shard_now, page.reading),
        ));
    }
    let mut deletes: Vec<Vec<u8>> = if page.page == 0 {
        let shards = shards.clone();
        let target = intent.target.clone();
        match blocking(move || {
            let mut held = space_records(&shards, &target, &space)?;
            held.extend(arrivals(&shards, &target, &space)?);
            Ok(held)
        })
        .await
        {
            Ok(held) => held.into_iter().map(|(address, _)| address).collect(),
            Err(_) => return MoveAnswer::Refused("busy".into()),
        }
    } else {
        Vec::new()
    };
    if page.last {
        // The last page needs the earlier pages' copies no more.
        deletes.extend(earlier.into_iter().map(|(address, _)| address));
    } else {
        puts.push((
            Records::arrival_address(&space, page.page),
            arrival(&page.intent, &page.copies),
        ));
    }
    let written = {
        let shards = shards.clone();
        let target = intent.target.clone();
        blocking(move || shards.commit_into(&target, puts, deletes)).await
    };
    if let Err(error) = written {
        log(format_args!(
            "a moving space's records were not kept: {error}"
        ));
        return MoveAnswer::Refused("busy".into());
    }
    if !page.last {
        return MoveAnswer::Taken;
    }
    // Exactly the records the source sent: none lost to a page sent again,
    // or to another carrier of the same move.
    let held = {
        let shards = shards.clone();
        let target = intent.target.clone();
        blocking(move || space_records(&shards, &target, &space)).await
    };
    match held {
        Ok(held) if digest(&held) == page.digest => {}
        Ok(_) => {
            clear(&shards, &intent.target, &space).await;
            return MoveAnswer::Refused("busy".into());
        }
        Err(_) => return MoveAnswer::Refused("busy".into()),
    }
    crate::testing::move_step(
        space.as_bytes(),
        &intent.library,
        crate::testing::MoveStep::Naming,
    )
    .await;
    // 4. The ticket is used from here on: recorded only while no record
    // of it is kept, in a commit of its own, since it is kept in a shard of
    // the index other than the move's record.
    let reserved = match reserve_ticket(core, &intent).await {
        Ok(reserved) => reserved,
        Err(_) => return MoveAnswer::Refused("busy".into()),
    };
    if reserved == Some(false) {
        clear(&shards, &intent.target, &space).await;
        return MoveAnswer::Refused(LibraryClass::TicketUsed.code().into());
    }
    match flip(
        core,
        &space,
        &intent,
        &library,
        &page.intent,
        &copies,
        &leaving,
    )
    .await
    {
        Ok(true) => {
            adopt(core, &space, &intent, &library, page.usage, copies, leaving);
            MoveAnswer::Done
        }
        Ok(false) => {
            let answer = settled(&shards, &space, &intent).await;
            // An abandoned move leaves its ticket unused.
            if matches!(answer, MoveAnswer::Abandoned) && reserved == Some(true) {
                release_ticket(core, &intent).await;
            }
            answer
        }
        Err(error) => {
            // Its ticket stays used: the step may have been made.
            log(format_args!(
                "a move's last step is not known to be made: {error}"
            ));
            MoveAnswer::Refused("busy".into())
        }
    }
}

/// Records a move's ticket used, only while the index keeps no record of
/// it: whether it was recorded; `None` for a move that carries no ticket.
async fn reserve_ticket(
    core: &Core,
    intent: &MoveRecord,
) -> Result<Option<bool>, frasil_store::StoreError> {
    let Some(used) = ticket_used(intent) else {
        return Ok(None);
    };
    let (table, key, bytes) = used.encode();
    let address = Records::library_address(table, &key);
    let commit = Commit::new(vec![(address.clone(), bytes)], Vec::new()).expecting(&address, None);
    core.writer.submit(commit).await.map(Some)
}

/// Drops the record of a move's ticket used, for a move that was
/// abandoned after its ticket was recorded.
async fn release_ticket(core: &Core, intent: &MoveRecord) {
    let Some(used) = ticket_used(intent) else {
        return;
    };
    let (table, key, bytes) = used.encode();
    let address = Records::library_address(table, &key);
    let commit = Commit::new(Vec::new(), vec![address.clone()]).expecting(&address, Some(&bytes));
    if let Err(error) = core.writer.submit(commit).await {
        log(format_args!("a move's ticket was not released: {error}"));
    }
}

/// Takes a library's settings from the index into memory, if memory does
/// not know the library: another node may have written them.
async fn learn_library(core: &Core, library: &LibraryId) {
    if lock(&core.libraries).library(library).is_some() {
        return;
    }
    let records = core.records.clone();
    let key = library.as_str().as_bytes().to_vec();
    let address = Records::library_address(super::records::LIBRARY, &key);
    if let Ok(Some(bytes)) = blocking(move || records.get(&address)).await
        && let Some(record) = Record::decode(super::records::LIBRARY, &key, &bytes)
    {
        lock(&core.libraries).learn(record);
    }
}

/// The move's record as the index keeps it now.
async fn recorded(
    core: &Core,
    space: &EventId,
) -> Result<Option<Vec<u8>>, frasil_store::StoreError> {
    let records = core.records.clone();
    let address = Records::move_address(space);
    blocking(move || records.get(&address)).await
}

/// What the target answers once the index keeps the move's record no
/// more: made, if the index names the target; else abandoned, and what the
/// target shard keeps of the space goes.
async fn settled(shards: &Arc<Shards>, space: &EventId, intent: &MoveRecord) -> MoveAnswer {
    let id = *space.as_bytes();
    let located = {
        let shards = shards.clone();
        blocking(move || shards.locate_fresh(&id)).await
    };
    match located {
        Ok(Some(shard)) if shard == intent.target => MoveAnswer::Done,
        Ok(_) => {
            clear(shards, &intent.target, space).await;
            MoveAnswer::Abandoned
        }
        Err(_) => MoveAnswer::Refused("busy".into()),
    }
}

/// The target's last step: the index names the target shard and the
/// space's attachment to the target library, the copies made into it are
/// recorded, and the index keeps the move's record no more, in one step,
/// only while it keeps that record and names the source shard.
async fn flip(
    core: &Core,
    space: &EventId,
    intent: &MoveRecord,
    library: &LibraryId,
    recorded: &[u8],
    copies: &[([u8; 64], Copy)],
    leaving: &[(LibraryId, [u8; 64], Copy)],
) -> Result<bool, frasil_store::StoreError> {
    let address = Records::move_address(space);
    let mut rows = Vec::new();
    // A library new to the peer takes section 2.4's defaults; one the
    // index keeps keeps its settings, whatever this node's memory holds.
    let known = lock(&core.libraries).library(library).is_some() || {
        let records = core.records.clone();
        let address =
            Records::library_address(super::records::LIBRARY, library.as_str().as_bytes());
        blocking(move || records.get(&address)).await?.is_some()
    };
    if !known {
        let libraries = lock(&core.libraries);
        rows.push(Record::Library(
            library.clone(),
            libraries
                .settings()
                .new_library(library, core.settings.erasure_timeout),
        ));
    }
    rows.push(Record::Attachment(
        *space.as_bytes(),
        super::Attachment {
            library: library.clone(),
            ticket: ticket_of(intent),
            at: intent.at,
        },
    ));
    for (locator, copy) in copies {
        rows.push(Record::Copy(*locator, library.clone(), copy.clone()));
    }
    for (of, locator, copy) in leaving {
        rows.push(Record::Copy(*locator, of.clone(), copy.clone()));
    }
    let mut puts = vec![(
        Records::hosted_address(space),
        Records::hosted_record(&intent.target),
    )];
    for row in rows {
        let (table, key, bytes) = row.encode();
        puts.push((Records::library_address(table, &key), bytes));
    }
    let mut deletes = vec![address.clone()];
    for (table, key) in Libraries::cleared(space) {
        deletes.push(Records::library_address(table, &key));
    }
    let commit = Commit::new(puts, deletes)
        .expecting(&address, Some(recorded))
        .expecting(
            &Records::hosted_address(space),
            Some(&Records::hosted_record(&intent.source)),
        );
    core.writer.submit(commit).await
}

/// The target's memory takes a space that moved in.
fn adopt(
    core: &Core,
    space: &EventId,
    intent: &MoveRecord,
    library: &LibraryId,
    usage: u64,
    copies: Vec<([u8; 64], Copy)>,
    leaving: Vec<(LibraryId, [u8; 64], Copy)>,
) {
    {
        let mut libraries = lock(&core.libraries);
        let _ = libraries.attach(*space, library, ticket_of(intent), intent.at);
        if let Some(used) = ticket_used(intent) {
            libraries.learn(used);
        }
        for (locator, copy) in copies {
            let _ = libraries.add_copy(library.clone(), locator, copy);
        }
        for (of, locator, copy) in leaving {
            let _ = libraries.add_copy(of, locator, copy);
        }
    }
    core.move_ended(space);
    if let Some(shards) = &core.shards {
        shards.set_placement(space.as_bytes(), &intent.target);
    }
    let mut index = lock(&core.index);
    index.hosted.insert(*space);
    index.waiting.insert(*space);
    index.used.insert(*space, usage);
}

/// Drops what a shard keeps of a space whose move did not end there.
async fn clear(shards: &Arc<Shards>, shard: &str, space: &EventId) {
    let shards = shards.clone();
    let shard = shard.to_owned();
    let space = *space;
    let cleared = blocking(move || {
        let mut held: Vec<Vec<u8>> = space_records(&shards, &shard, &space)?
            .into_iter()
            .chain(arrivals(&shards, &shard, &space)?)
            .map(|(address, _)| address)
            .collect();
        held.push(Records::offset_address(&space));
        shards.commit_into(&shard, Vec::new(), held)
    })
    .await;
    if let Err(error) = cleared {
        log(format_args!(
            "a moving space's records stay until the shard opens: {error}"
        ));
    }
}

/// Every node: where a moved space's records are now. The node that keeps
/// that shard takes the space's attachment from the index, as the target
/// whose answer was lost would have.
pub(crate) async fn moved_elsewhere(shared: &Arc<Shared>, space: EventId, shard: String) {
    let core = &shared.core;
    let Some(shards) = core.shards.clone() else {
        return;
    };
    shards.set_placement(space.as_bytes(), &shard);
    if !shards.keeps_shard(&shard)
        || lock(&core.libraries)
            .attachment(&space)
            .is_some_and(|a| crate::shards::library_shard(a.library.as_str()) == shard)
    {
        return;
    }
    let records = core.records.clone();
    let address = Records::library_address(super::records::ATTACHMENT, space.as_bytes());
    let read = blocking(move || records.get(&address)).await;
    if let Ok(Some(bytes)) = read
        && let Some(Record::Attachment(_, attachment)) =
            Record::decode(super::records::ATTACHMENT, space.as_bytes(), &bytes)
    {
        let mut libraries = lock(&core.libraries);
        let _ = libraries.attach(space, &attachment.library, attachment.ticket, attachment.at);
        drop(libraries);
        core.move_ended(&space);
        lock(&core.index).hosted.insert(space);
    }
}

/// The moves left under way whose source shard this node keeps, each
/// carried on from its first page, or abandoned (this module's
/// documentation): after a crash, as the next owner keeps the shard.
pub(crate) async fn resume_moves(shared: &Arc<Shared>) {
    let core = &shared.core;
    let Some(shards) = core.shards.clone() else {
        return;
    };
    let under_way: Vec<(EventId, MoveRecord)> = lock(&core.moves)
        .iter()
        .filter(|(_, intent)| shards.keeps_shard(&intent.source))
        .map(|(space, intent)| (*space, intent.clone()))
        .collect();
    for (space, intent) in under_way {
        let Ok(writing) = core.write(space).await else {
            continue;
        };
        if !lock(&core.moves).contains_key(&space) {
            continue;
        }
        if !writing.hosted() {
            // Nothing of the space opens here: it cannot move.
            let _ = abandoned(shared, &writing, &intent, "busy", &[], Vec::new()).await;
            continue;
        }
        match carry(shared, &writing, &intent).await {
            Ok(()) => log("a move left under way was made"),
            Err(_) => log("a move left under way was abandoned"),
        }
    }
}

/// The copies a move makes (ext-libraries.md, 3.8 Keeping a held object,
/// "Holds across a move"): for each hold whose holding space and source
/// the move bills to two libraries, the object copied into the holding
/// space's library, unless that library keeps it already. Made at the
/// source, before the move's pages: the copies into the library the space
/// leaves are returned, to be recorded once the move is made; those into
/// the target travel with the pages, and the target records them with its
/// last step, once its headroom holds them. Returns the target's, as copy
/// records' keys and bytes, the keys of all the pieces, which an abandoned
/// move deletes, and the leaving library's copies.
async fn make_copies(
    shared: &Arc<Shared>,
    space: &EventId,
    target: &LibraryId,
    at: Reading,
) -> (Rows, Vec<String>, Vec<(LibraryId, [u8; 64], Copy)>) {
    let core = &shared.core;
    let wanted: Vec<(LibraryId, [u8; 64], EventId, Option<LibraryId>)> = {
        let libraries = lock(&core.libraries);
        let library_after = |of: &EventId| -> Option<LibraryId> {
            if of == space {
                Some(target.clone())
            } else {
                libraries.attachment(of).map(|a| a.library.clone())
            }
        };
        let mut wanted = BTreeSet::new();
        for ((holder, locator), hold) in libraries.holds() {
            let source = EventId(hold.source);
            if *holder != *space && source != *space {
                continue;
            }
            let (Some(holder_library), Some(source_library)) =
                (library_after(holder), library_after(&source))
            else {
                continue;
            };
            if holder_library == source_library
                || libraries.copy(&holder_library, locator).is_some()
            {
                continue;
            }
            // Where its bytes are now: the source, or a copy the holding
            // space's library keeps before the move.
            let before = libraries
                .hold_copy(holder, locator)
                .map(|(library, _)| library.clone());
            wanted.insert((holder_library, *locator, source, before));
        }
        wanted.into_iter().collect()
    };
    let mut made = Vec::new();
    let mut into_target = Vec::new();
    let mut pieces = Vec::new();
    for (library, locator, source, before) in wanted {
        let found = match &before {
            Some(held_in) => lock(&core.libraries)
                .copy(held_in, &locator)
                .and_then(|copy| ObjectRecord::decode(&copy.object))
                .map(|record| (copy_home(held_in), record)),
            None => core
                .read(source, |held| held.objects.get(&locator).cloned())
                .await
                .flatten()
                .filter(|record| record.complete)
                .map(|record| (*source.as_bytes(), record)),
        };
        let Some((from, record)) = found else {
            continue;
        };
        let home = copy_home(&library);
        let mut copied = true;
        for &index in &record.pieces {
            let piece = shared.blobs.get(&piece_key(&from, &locator, index)).await;
            let Ok(Some(bytes)) = piece else {
                copied = false;
                break;
            };
            if shared
                .blobs
                .put(&piece_key(&home, &locator, index), bytes)
                .await
                .is_err()
            {
                copied = false;
                break;
            }
        }
        if !copied {
            log("a held object was not copied for a move: its hold reads from its source");
            continue;
        }
        let copy = Copy {
            source: *source.as_bytes(),
            object: record.encode(),
            bytes: crate::space::object_bytes(&record),
            at,
        };
        if &library == target {
            let (_, key, bytes) = Record::Copy(locator, library.clone(), copy).encode();
            into_target.push((key, bytes));
            pieces.extend(
                record
                    .pieces
                    .iter()
                    .map(|&index| piece_key(&home, &locator, index)),
            );
        } else {
            pieces.extend(
                record
                    .pieces
                    .iter()
                    .map(|&index| piece_key(&home, &locator, index)),
            );
            made.push((library, locator, copy));
        }
    }
    (into_target, pieces, made)
}

#[cfg(test)]
mod tests {
    use super::{PAGE, digest, paginate};

    /// A move's records and copies go in pages that each fit an internal
    /// link's frame, the copies before the records, none lost.
    #[test]
    fn records_and_copies_fit_their_pages() {
        let record = |n: u8| (vec![b'j', n], vec![n; PAGE / 3]);
        let records: Vec<_> = (0..5).map(record).collect();
        let copies: Vec<_> = (0..4).map(|n| (vec![n; 70], vec![n; PAGE / 4])).collect();
        let pages = paginate(copies.clone(), records.clone(), PAGE);
        assert!(pages.len() >= 4);
        for (page_records, page_copies) in &pages {
            let bytes: usize = page_records
                .iter()
                .chain(page_copies)
                .map(|(key, value)| key.len() + value.len() + 16)
                .sum();
            assert!(bytes <= PAGE, "{bytes}");
        }
        let all_records: Vec<_> = pages.iter().flat_map(|(r, _)| r.clone()).collect();
        let all_copies: Vec<_> = pages.iter().flat_map(|(_, c)| c.clone()).collect();
        assert_eq!(all_records, records);
        assert_eq!(all_copies, copies);
        assert_eq!(
            paginate(Vec::new(), Vec::new(), PAGE).len(),
            1,
            "one page at least"
        );
    }

    /// The digest the target checks tells the records and their order
    /// apart.
    #[test]
    fn a_digest_tells_records_apart() {
        let a = vec![(vec![1], vec![2]), (vec![3], vec![4])];
        let b = vec![(vec![1], vec![2, 3]), (vec![], vec![4])];
        assert_ne!(digest(&a), digest(&b));
        assert_ne!(digest(&a), digest(&a[..1]));
        assert_eq!(digest(&a), digest(&a.clone()));
    }
}
