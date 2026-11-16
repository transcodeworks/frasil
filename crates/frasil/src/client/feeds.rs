//! Change feeds that say what changed: in one space, in a Records stream's
//! rows, and in a blob stream's blobs, each with where the change was made.
//!
//! The device-wide [`Events`](super::Events) name a space and its streams.
//! These feeds narrow that to what an application caches: a space's own
//! changes, the rows a write touched, and the blobs added, removed, become
//! readable or withdrawn. Each feed starts when it is asked for and gives
//! every change after that. A feed that falls far behind the device says so
//! rather than skipping silently: read again what it covers.

use super::{Space, StreamId};
use crate::device::Notice;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use std::collections::BTreeSet;
use tokio::sync::broadcast::{self, error::RecvError};

/// Where a change was made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Origin {
    /// This device wrote it.
    Local,
    /// It arrived from another member or a peer, or from this device's
    /// person on another device. The default.
    #[default]
    Remote,
}

impl Origin {
    /// Where the events were made: [`Origin::Local`] when this device
    /// authored every one of them.
    pub(crate) fn of(replica: &crate::replica::Replica, me: &DeviceId, ids: &[EventId]) -> Self {
        let log = replica.log();
        let local = !ids.is_empty()
            && ids.iter().all(|id| {
                log.and_then(|log| log.event(*id))
                    .is_some_and(|event| event.author() == me)
            });
        if local { Self::Local } else { Self::Remote }
    }
}

/// The next notice of one space; `Err(())` when the receiver fell behind,
/// `None` once the device is gone.
pub(crate) async fn next_notice(
    notices: &mut broadcast::Receiver<Notice>,
    space: &EventId,
) -> Option<Result<Notice, ()>> {
    loop {
        match notices.recv().await {
            Ok(notice) if notice.space == *space => return Some(Ok(notice)),
            Ok(_) => {}
            Err(RecvError::Lagged(_)) => return Some(Err(())),
            Err(RecvError::Closed) => return None,
        }
    }
}

/// A change of one space, from [`SpaceChanges::next`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpaceChange {
    /// The streams whose content changed. A feed that fell behind lists
    /// every stream the device holds of the space.
    pub streams: Vec<StreamId>,
    /// Whether its members or their levels may have changed.
    pub members: bool,
    /// Whether it holds events that are no stream's content: keys, such as
    /// a rotation or a delivery, which can make units that arrived earlier
    /// readable in any stream, or the space's own stream. Read again what
    /// the device shows of the space. A feed that fell behind sets it.
    pub space_events: bool,
    /// Where the change was made. A change that holds events of several
    /// authors, or a feed that fell behind, is [`Origin::Remote`].
    pub origin: Origin,
}

/// What placed events changed in a space, from the replica: the content
/// streams their units belong to, whether the roster changed, and whether
/// any is no content stream's unit.
pub(crate) fn classify(
    replica: &crate::replica::Replica,
    placed: &[EventId],
) -> (BTreeSet<[u8; 16]>, bool, bool) {
    let system = replica.system_stream();
    let mut streams = BTreeSet::new();
    let (mut members, mut space_events) = (false, false);
    for id in placed {
        if replica.is_roster(id) {
            members = true;
            continue;
        }
        match replica.stream_of_event(id) {
            Some(stream) if Some(stream) != system => {
                streams.insert(stream);
            }
            _ => space_events = true,
        }
    }
    (streams, members, space_events)
}

/// The changes of one space, from [`Space::changes`]: the device's
/// [`Event::Changed`](super::Event::Changed) for this space alone, with
/// where each was made.
#[derive(Debug)]
pub struct SpaceChanges {
    space: Space,
    notices: broadcast::Receiver<Notice>,
}

impl Space {
    /// This space's changes from now on, this device's own included.
    pub fn changes(&self) -> SpaceChanges {
        SpaceChanges {
            space: self.clone(),
            notices: self.device.engine().subscribe(),
        }
    }
}

impl SpaceChanges {
    /// The next change; `Ok(None)` once the device is gone.
    ///
    /// # Errors
    ///
    /// [`crate::Error::UnknownSpace`] once the device no longer holds the
    /// space, as after [`Space::forget`]: the feed ends.
    pub async fn next(&mut self) -> crate::Result<Option<SpaceChange>> {
        let space = self.space.id().event();
        let me = self.space.device.engine().device_id();
        loop {
            let Some(notice) = next_notice(&mut self.notices, &space).await else {
                return Ok(None);
            };
            let change = match notice {
                Ok(notice) if notice.placed.is_empty() => continue,
                Ok(notice) => {
                    self.space
                        .read(|replica| {
                            let (streams, members, space_events) =
                                classify(replica, &notice.placed);
                            SpaceChange {
                                streams: streams.into_iter().map(StreamId::from_bytes).collect(),
                                members,
                                space_events,
                                origin: Origin::of(replica, &me, &notice.placed),
                            }
                        })
                        .await?
                }
                Err(()) => {
                    self.space
                        .read(|replica| {
                            let system = replica.system_stream();
                            SpaceChange {
                                streams: replica
                                    .streams()
                                    .map(|(id, _)| *id)
                                    .filter(|id| Some(*id) != system)
                                    .map(StreamId::from_bytes)
                                    .collect(),
                                members: true,
                                space_events: true,
                                origin: Origin::Remote,
                            }
                        })
                        .await?
                }
            };
            return Ok(Some(change));
        }
    }
}

#[cfg(feature = "adapter-records")]
mod records {
    use super::{BTreeSet, EventId, Notice, Origin, broadcast, next_notice};
    use crate::client::Records;
    use frasil_adapter::context::Role;
    use frasil_adapter_records::Changeset;
    use frasil_units::runtime::Stream;
    use std::collections::{BTreeMap, VecDeque};

    /// A change of a Records stream, from [`RecordChanges::next`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum RecordChange {
        /// Rows of one table were written: inserted, set, cleared or
        /// deleted. Read them again with [`Records::row`].
        Rows {
            /// The table.
            table: String,
            /// The rows' keys, sorted.
            keys: Vec<Vec<u8>>,
            /// Where the write was made.
            origin: Origin,
        },
        /// Any row of any table may have changed: a snapshot replaced the
        /// stream's state, the space's members changed, so that a writer's
        /// changes may count or no longer count, or the feed fell behind.
        /// Read the tables again.
        All,
    }

    /// The changes of a Records stream, from [`Records::changes`].
    #[derive(Debug)]
    pub struct RecordChanges {
        records: Records,
        notices: broadcast::Receiver<Notice>,
        queued: VecDeque<RecordChange>,
    }

    impl Records {
        /// The rows that change from now on, this device's writes included,
        /// table by table.
        pub fn changes(&self) -> RecordChanges {
            RecordChanges {
                records: self.clone(),
                notices: self.space.device.engine().subscribe(),
                queued: VecDeque::new(),
            }
        }
    }

    impl RecordChanges {
        /// The next change; `Ok(None)` once the device is gone.
        ///
        /// # Errors
        ///
        /// [`crate::Error::UnknownSpace`] once the device no longer holds
        /// the space: the feed ends.
        pub async fn next(&mut self) -> crate::Result<Option<RecordChange>> {
            let space = self.records.space.id().event();
            loop {
                if let Some(change) = self.queued.pop_front() {
                    return Ok(Some(change));
                }
                match next_notice(&mut self.notices, &space).await {
                    None => return Ok(None),
                    Some(Ok(notice)) if notice.placed.is_empty() => {}
                    Some(Ok(notice)) => {
                        let changes = self.read(&notice.placed).await?;
                        self.queued.extend(changes);
                    }
                    Some(Err(())) => return Ok(Some(RecordChange::All)),
                }
            }
        }

        /// What the placed events changed in this stream.
        async fn read(&self, placed: &[EventId]) -> crate::Result<Vec<RecordChange>> {
            let stream = self.records.opening.stream();
            let me = self.records.space.device.engine().device_id();
            self.records
                .space
                .read(|replica| match touched(replica, &me, placed) {
                    Touched::All => vec![RecordChange::All],
                    Touched::Streams { mut rows, .. } => rows.remove(&stream).unwrap_or_default(),
                })
                .await
        }
    }

    /// What placed events changed in a space's Records streams.
    pub(crate) enum Touched {
        /// Any row may have changed: the events changed who writes, or
        /// keys, or the space's own stream, or a unit that does not read
        /// as a log change.
        All,
        /// The rows each Records stream changed, and whether streams of
        /// other kinds changed.
        Streams {
            rows: BTreeMap<[u8; 16], Vec<RecordChange>>,
            #[cfg_attr(not(feature = "index"), allow(dead_code))]
            others: bool,
        },
    }

    /// What the placed events changed in the space's Records streams,
    /// with where each change was made.
    pub(crate) fn touched(
        replica: &crate::replica::Replica,
        me: &frasil_crypto::device::DeviceId,
        placed: &[EventId],
    ) -> Touched {
        let system = replica.system_stream();
        let mut by_stream: BTreeMap<[u8; 16], BTreeSet<EventId>> = BTreeMap::new();
        for id in placed {
            if replica.is_roster(id) {
                return Touched::All;
            }
            // An event of no stream, as a key's, can make waiting units
            // read; one of the space's own stream can change its tables'
            // sources.
            match replica.stream_of_event(id) {
                Some(stream) if Some(stream) != system => {
                    by_stream.entry(stream).or_default().insert(*id);
                }
                _ => return Touched::All,
            }
        }
        let mut rows = BTreeMap::new();
        let mut others = false;
        for (stream, units) in by_stream {
            let Some(runtime) = replica.stream(&stream) else {
                // Not held here, as on a partial device.
                continue;
            };
            let Some(records) = runtime
                .as_any()
                .downcast_ref::<Stream<frasil_adapter_records::Records>>()
            else {
                others = true;
                continue;
            };
            let mut changed: BTreeMap<(Origin, String), BTreeSet<Vec<u8>>> = BTreeMap::new();
            let mut found = 0;
            // The placed units are among the newest.
            for unit in records.units().rev() {
                if found == units.len() {
                    break;
                }
                if !units.contains(&EventId(unit.context.event_id)) {
                    continue;
                }
                found += 1;
                let changeset = (unit.context.role == Role::Log)
                    .then(|| Changeset::read(&unit.content).ok())
                    .flatten();
                let Some(changeset) = changeset else {
                    return Touched::All;
                };
                let origin = if unit.context.author == me.0 {
                    Origin::Local
                } else {
                    Origin::Remote
                };
                for op in changeset.ops {
                    changed
                        .entry((origin, op.table))
                        .or_default()
                        .insert(op.key);
                }
            }
            // A unit placed but not held as a stream unit, such as one that
            // waits for its key, changes nothing yet: the event that lets it
            // read changes everything.
            rows.insert(
                stream,
                changed
                    .into_iter()
                    .map(|((origin, table), keys)| RecordChange::Rows {
                        table,
                        keys: keys.into_iter().collect(),
                        origin,
                    })
                    .collect(),
            );
        }
        Touched::Streams { rows, others }
    }
}

#[cfg(feature = "adapter-records")]
pub use records::{RecordChange, RecordChanges};
#[cfg(all(feature = "adapter-records", feature = "index"))]
pub(crate) use records::{Touched, touched};

#[cfg(feature = "adapter-blobs")]
mod blobs {
    use super::{EventId, Notice, Origin, RecvError, broadcast};
    use crate::client::{BlobId, Blobs};
    use frasil_adapter::Locator;
    use frasil_units::runtime::Stream;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    /// A change of a blob stream, from [`BlobChanges::next`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum BlobChange {
        /// A blob was put in the stream.
        Added {
            /// The blob.
            id: BlobId,
            /// Where it was put.
            origin: Origin,
        },
        /// A blob was removed from the stream, or a new version replaced
        /// it.
        Removed {
            /// The blob.
            id: BlobId,
            /// Where it was removed.
            origin: Origin,
        },
        /// A blob's bytes arrived whole: [`Blobs::get`] reads it now.
        Arrived {
            /// The blob.
            id: BlobId,
        },
        /// A held blob's file changed or is gone, so this device no longer
        /// holds its bytes (at-rest.md, "Held objects"). They stay
        /// fetchable from peers and members.
        Withdrawn {
            /// The blob.
            id: BlobId,
        },
    }

    /// What a blob feed last saw of a blob: its object, and whether the
    /// device held its bytes.
    type Known = BTreeMap<[u8; 16], (Locator, Option<EventId>, bool)>;

    /// The changes of a blob stream, from [`Blobs::changes`].
    #[derive(Debug)]
    pub struct BlobChanges {
        blobs: Blobs,
        notices: broadcast::Receiver<Notice>,
        arrivals: broadcast::Receiver<(EventId, Locator)>,
        known: Known,
        queued: VecDeque<BlobChange>,
    }

    /// The blobs the stream holds now, each with its object, the source
    /// of a reference, and whether the device holds its bytes.
    async fn current(blobs: &Blobs) -> Option<Known> {
        let stream = blobs.opening().stream();
        let engine = blobs.space().device.engine();
        let space = blobs.space().id().event();
        let mut known = blobs
            .space()
            .read(|replica| {
                let Some(state) = replica
                    .stream(&stream)
                    .and_then(|s| {
                        s.as_any()
                            .downcast_ref::<Stream<frasil_adapter_blobs::Blobs>>()
                    })
                    .map(Stream::state)
                else {
                    return Known::new();
                };
                state
                    .current()
                    .map(|(handle, entry)| {
                        let source = entry.reference.as_ref().map(|r| EventId(r.source));
                        let holds = replica.holds_object(&entry.object);
                        (*handle, (entry.object, source, holds))
                    })
                    .collect()
            })
            .await
            .ok()?;
        // A reference's bytes may be held in its source: one read per
        // source space, for every reference to it not held here.
        let mut sources: BTreeMap<EventId, Vec<Locator>> = BTreeMap::new();
        for (locator, source, holds) in known.values() {
            if let Some(source) = source.filter(|s| !*holds && *s != space) {
                sources.entry(source).or_default().push(*locator);
            }
        }
        for (source, locators) in sources {
            let held: BTreeSet<Locator> = engine
                .read(&source, |replica| {
                    locators
                        .iter()
                        .filter(|locator| replica.holds_object(locator))
                        .copied()
                        .collect()
                })
                .await
                .unwrap_or_default();
            for (locator, from, holds) in known.values_mut() {
                if *from == Some(source) && held.contains(locator) {
                    *holds = true;
                }
            }
        }
        Some(known)
    }

    impl Blobs {
        /// The blobs that change from now on: put, removed, arrived or
        /// withdrawn, this device's own puts and removals included.
        ///
        /// # Errors
        ///
        /// [`crate::Error::UnknownSpace`].
        pub async fn changes(&self) -> crate::Result<BlobChanges> {
            let engine = self.space().device.engine();
            let notices = engine.subscribe();
            let arrivals = engine.subscribe_arrivals();
            let known = current(self).await.ok_or(crate::Error::UnknownSpace)?;
            Ok(BlobChanges {
                blobs: self.clone(),
                notices,
                arrivals,
                known,
                queued: VecDeque::new(),
            })
        }
    }

    impl BlobChanges {
        /// The next change; `Ok(None)` once the device is gone.
        ///
        /// # Errors
        ///
        /// [`crate::Error::UnknownSpace`] once the device no longer holds
        /// the space: the feed ends.
        pub async fn next(&mut self) -> crate::Result<Option<BlobChange>> {
            let space = self.blobs.space().id().event();
            let stream = self.blobs.opening().stream();
            let me = self.blobs.space().device.engine().device_id();
            loop {
                if let Some(change) = self.queued.pop_front() {
                    return Ok(Some(change));
                }
                let origin = tokio::select! {
                    notice = self.notices.recv() => match notice {
                        Ok(notice) if notice.space == space => {
                            for withdrawn in &notice.withdrawn {
                                self.withdrawn(withdrawn.object_id);
                            }
                            if notice.placed.is_empty() {
                                continue;
                            }
                            // Only this stream's units, who writes, and
                            // keys change which blobs it holds.
                            let touched = self
                                .blobs
                                .space()
                                .read(|replica| {
                                    let (streams, members, space_events) =
                                        super::classify(replica, &notice.placed);
                                    (members || space_events || streams.contains(&stream))
                                        .then(|| Origin::of(replica, &me, &notice.placed))
                                })
                                .await?;
                            match touched {
                                Some(origin) => origin,
                                None => continue,
                            }
                        }
                        // A source space's blobs serve this one's
                        // references.
                        Ok(_) => continue,
                        Err(RecvError::Lagged(_)) => Origin::Remote,
                        Err(RecvError::Closed) => return Ok(None),
                    },
                    arrival = self.arrivals.recv() => match arrival {
                        Ok((from, locator))
                            if !self.known.values().any(|(l, s, holds)| {
                                *l == locator && !holds && (from == space || Some(from) == *s)
                            }) => continue,
                        Ok(_) | Err(RecvError::Lagged(_)) => Origin::Remote,
                        Err(RecvError::Closed) => return Ok(None),
                    },
                };
                self.differ(origin).await?;
            }
        }

        /// Queues a withdrawal of each blob of the object.
        fn withdrawn(&mut self, object_id: [u8; 32]) {
            for (handle, (locator, _, holds)) in &mut self.known {
                if locator[..32] == object_id && *holds {
                    *holds = false;
                    self.queued.push_back(BlobChange::Withdrawn {
                        id: BlobId::from_bytes(*handle),
                    });
                }
            }
        }

        /// Queues what differs from what the feed last saw.
        async fn differ(&mut self, origin: Origin) -> crate::Result<()> {
            let now = current(&self.blobs)
                .await
                .ok_or(crate::Error::UnknownSpace)?;
            for handle in self.known.keys().filter(|h| !now.contains_key(*h)) {
                self.queued.push_back(BlobChange::Removed {
                    id: BlobId::from_bytes(*handle),
                    origin,
                });
            }
            for (handle, (_, _, holds)) in &now {
                let id = BlobId::from_bytes(*handle);
                match self.known.get(handle) {
                    None => self.queued.push_back(BlobChange::Added { id, origin }),
                    Some((_, _, false)) if *holds => {
                        self.queued.push_back(BlobChange::Arrived { id });
                    }
                    Some(_) => {}
                }
            }
            self.known = now;
            Ok(())
        }
    }
}

#[cfg(feature = "adapter-blobs")]
pub use blobs::{BlobChange, BlobChanges};

#[cfg(all(test, feature = "adapter-records"))]
mod tests {
    use crate::device::Notice;
    use crate::{Device, Error, Storage};

    /// A feed of a space the device no longer holds ends with an error,
    /// not as the device's end.
    #[tokio::test]
    async fn a_feed_of_a_forgotten_space_ends_with_an_error() {
        let device = Device::open(Storage::Memory, &[11; 32]).await.unwrap();
        let space = device.create_space().await.unwrap();
        let records = space.create_records().unwrap();
        records
            .write(|tx| {
                tx.insert("t", b"r");
            })
            .await
            .unwrap();
        let mut changes = space.changes();
        let mut rows = records.changes();
        let placed = vec![frasil_events::EventId([9; 32])];
        space.forget().await.unwrap();
        let _ = device.engine().notices().send(Notice {
            space: space.id().event(),
            placed,
            withdrawn: Vec::new(),
            wanted: Vec::new(),
        });
        assert_eq!(changes.next().await, Err(Error::UnknownSpace));
        assert_eq!(rows.next().await, Err(Error::UnknownSpace));
    }
}
