//! Attribution and history (decision: a client toolkit): who changed what,
//! as the roster names them, and when, for every stream.
//!
//! Every change of a stream reached this device as a unit, signed by the
//! device that wrote it (events.md). The author of a [`Change`] is that
//! device, and the person whose device list vouches for it when it reaches
//! the space through a person the roster grants (identity.md, roster.md):
//! names come from the roster's labels, shown and never checked, and the
//! identities from the signatures, which no member can fake.
//!
//! A [`Change`] is one unit in canonical order (events.md, "Canonical
//! order"): for a Loro document, the operations it carried, as a span of
//! its peer, with the version before and after it, so that a read-only
//! view at either is a checkout (`LoroDoc::fork_at`); for Records, the
//! rows and columns it wrote, and a replay rebuilds the tables as they
//! stood after it. No event carries a time (overview.md, "Time"): a
//! document change's time is the one its writer's Loro recorded in the
//! change, and a Records change's the one its changeset claims
//! (adapter-records.md, section 2.2, key 7). Both are the writer's word.

use crate::client::{MemberId, SuggestionId, UnitId};
use crate::device::Engine;
use crate::error::{Error, Result};
use crate::replica::Replica;
use frasil_adapter::{Outcome, StreamUnit};
use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_units::stream::StreamId;

/// Who made a change, as the roster and the lists named them at the
/// change's place in the space's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    /// The device that signed the unit.
    pub device: MemberId,
    /// The device's name in the roster at the change's place, when the
    /// roster granted it directly: shown, never checked.
    pub device_name: Option<String>,
    /// The person whose device list vouched for the device at the
    /// change's place, when it reached the space through a person: the
    /// first of [`Author::persons`].
    pub person: Option<MemberId>,
    /// The person's name in the roster at the change's place: shown,
    /// never checked.
    pub person_name: Option<String>,
    /// Every person whose list held the device at the change's place, in
    /// roster order: more than one for a device on two persons' lists.
    pub persons: Vec<MemberId>,
}

/// What a change is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// An edit: operations, or cells written.
    Edit,
    /// A suggestion, where it stands now.
    Suggestion(Standing),
    /// An accept or a dismiss of suggestions.
    Review {
        /// The suggestions it accepts.
        accepts: Vec<SuggestionId>,
        /// The suggestions it dismisses.
        dismisses: Vec<SuggestionId>,
    },
    /// A snapshot unit: a compaction of the stream (units.md).
    Snapshot,
}

/// Where a suggestion stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// No accept or dismiss names it.
    Open,
    /// An accept names it: it is part of the state.
    Accepted,
    /// Only dismisses name it.
    Dismissed,
}

/// What became of a change at this replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Its content is in the state.
    Applied,
    /// Its content waits inside the adapter, under this class.
    Waiting(&'static str),
    /// Its content was refused, under this class, and has no effect.
    Refused(&'static str),
    /// The unit is not valid by the write rule now (its writer was removed
    /// or forked): its content has no effect.
    Withdrawn,
}

/// A span of one peer's operations in a Loro document.
#[cfg(feature = "adapter-loro")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// The peer: an incarnation of the writer (adapter-loro.md).
    pub peer: u64,
    /// The first counter.
    pub from: i32,
    /// One past the last counter.
    pub to: i32,
}

/// What a change did to a Loro document.
#[cfg(feature = "adapter-loro")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentChange {
    /// The operations it carried.
    pub span: Span,
    /// The document's version just before it: the operations it depends
    /// on. A read-only view there is [`Document::at`](crate::Document::at).
    pub before: Option<loro::Frontiers>,
    /// The version with it: the change and its causal past, without
    /// concurrent changes.
    pub after: loro::Frontiers,
    /// The containers it changed, as Loro names them, when its operations
    /// are in the document.
    pub containers: Vec<String>,
}

/// What a change did to a row of a Records table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowChange {
    /// The table.
    pub table: String,
    /// The row's key.
    pub key: Vec<u8>,
    /// The columns it wrote, cleared ones included.
    pub columns: Vec<String>,
    /// Whether it inserted the row.
    pub inserted: bool,
    /// Whether it deleted the row.
    pub deleted: bool,
}

/// What a change did, by the stream's adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Detail {
    /// A Loro document: `None` for a review or a snapshot.
    #[cfg(feature = "adapter-loro")]
    Document(Option<DocumentChange>),
    /// Records tables: the rows it wrote.
    Records(Vec<RowChange>),
}

/// One change of a stream: the unit that carried it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The unit's ID.
    pub id: UnitId,
    /// Who made it.
    pub author: Author,
    /// The unit's sequence number in its writer's chain.
    pub seq: u64,
    /// The unit's height in the space's log: changes come in canonical
    /// order, by height then ID.
    pub height: u64,
    /// When, as the writer's own clock recorded it in the change, in
    /// seconds since 1970-01-01T00:00:00Z: a document change or a Records
    /// change whose writer recorded one. The writer's claim: shown, never
    /// checked, and any writer can state any time.
    pub time: Option<u64>,
    /// What it is.
    pub kind: Kind,
    /// What became of it here.
    pub effect: Effect,
    /// What it did.
    pub detail: Detail,
}

/// The author of a unit: the device whose signature it carries, and for a
/// unit valid by the write rule its attribution at its place (roster.md,
/// 3.11, "Attribution"), with the labels of then, the same at every device.
/// A unit the write rule voids names no member.
pub(crate) fn author(replica: &Replica, unit: [u8; 32], device: DeviceId) -> Author {
    let Some(found) = replica.authorship(&EventId(unit)) else {
        return Author {
            device: MemberId::from_bytes(device.0),
            device_name: None,
            person: None,
            person_name: None,
            persons: Vec::new(),
        };
    };
    let persons = found.persons();
    let (person, person_name) = match persons.first() {
        Some((id, name)) => (Some(MemberId::from_bytes(*id)), name.clone()),
        None => (None, None),
    };
    Author {
        device: MemberId::from_bytes(device.0),
        device_name: found.device_name(&device),
        person,
        person_name,
        persons: persons
            .into_iter()
            .map(|(id, _)| MemberId::from_bytes(id))
            .collect(),
    }
}

/// What became of a unit's content.
fn effect<C: Class + Copy>(unit: &StreamUnit, outcome: Option<&Outcome<C>>) -> Effect {
    if !unit.valid {
        return Effect::Withdrawn;
    }
    match outcome {
        Some(Outcome::Applied) => Effect::Applied,
        Some(Outcome::Waiting(class)) => Effect::Waiting(class.name()),
        Some(Outcome::Refused(class)) => Effect::Refused(class.name()),
        Some(Outcome::Counted) | None => Effect::Withdrawn,
    }
}

/// A change's common part, from its unit.
fn change(
    replica: &Replica,
    unit: &StreamUnit,
    effect: Effect,
    time: Option<u64>,
    kind: Kind,
    detail: Detail,
) -> Change {
    Change {
        id: UnitId::from_bytes(unit.context.event_id),
        author: author(
            replica,
            unit.context.event_id,
            DeviceId(unit.context.author),
        ),
        seq: unit.context.seq,
        height: unit.context.height,
        time,
        kind,
        effect,
        detail,
    }
}

#[cfg(feature = "adapter-loro")]
mod loro_history {
    use super::{
        Change, Detail, DocumentChange, Kind, Replica, Span, Standing, SuggestionId, change, effect,
    };
    use frasil_adapter::context::Role;
    use frasil_adapter_loro::{BlobMeta, Content, ContentRole, Loro};
    use frasil_units::runtime::Stream;
    use loro::{Frontiers, ID, LoroDoc};

    /// A document change's detail, read from the document when its
    /// operations are there. Loro merges consecutive changes of one peer,
    /// so the change holding the unit's first operation may begin at an
    /// earlier unit: the version before the unit is then the peer's
    /// previous operation, which a merged change's operations depend on
    /// alone.
    fn document_change(doc: &LoroDoc, peer: u64, from: i32, to: i32) -> DocumentChange {
        let first = ID::new(peer, from);
        let meta = doc.get_change(first);
        let before = meta.as_ref().map(|meta| {
            if meta.id.counter < from {
                Frontiers::from(ID::new(peer, from - 1))
            } else {
                meta.deps.clone()
            }
        });
        let containers = if meta.is_some() {
            let mut containers: Vec<String> = doc
                .get_changed_containers_in(first, usize::try_from(to - from).unwrap_or(0))
                .into_iter()
                .map(|container| container.to_string())
                .collect();
            containers.sort();
            containers
        } else {
            Vec::new()
        };
        DocumentChange {
            span: Span { peer, from, to },
            before,
            after: Frontiers::from(ID::new(peer, to - 1)),
            containers,
        }
    }

    /// The time the unit's own blob carries: its first change's, as its
    /// writer's Loro recorded it. Merging in the document does not reach
    /// it. A blob the pinned Loro does not read, which any unit of the
    /// stream may carry whatever its verdict, has none.
    fn blob_time(blob: &[u8]) -> Option<u64> {
        frasil_adapter_loro::meta::import_blob_meta(blob)
            .and_then(|meta| u64::try_from(meta.start_timestamp).ok())
            .filter(|time| *time > 0)
    }

    /// The history of a Loro document's stream.
    pub(super) fn history(replica: &Replica, stream: &Stream<Loro>) -> Vec<Change> {
        let state = stream.state();
        let doc = state.doc();
        let layer = state.layer();
        stream
            .units()
            .map(|unit| {
                let id = unit.context.event_id;
                let effect = effect(unit, stream.outcome(&id));
                let (time, kind, detail) = match unit.context.role {
                    Role::Snapshot => (None, Kind::Snapshot, Detail::Document(None)),
                    Role::Log => match Content::read(&unit.content) {
                        Ok(Content::Ops { role, blob, .. }) => {
                            let kind = if role == ContentRole::Edit {
                                Kind::Edit
                            } else {
                                Kind::Suggestion(match layer.get(&id) {
                                    Some((_, frasil_adapter_loro::Standing::Accepted)) => {
                                        Standing::Accepted
                                    }
                                    Some((_, frasil_adapter_loro::Standing::Dismissed)) => {
                                        Standing::Dismissed
                                    }
                                    _ => Standing::Open,
                                })
                            };
                            let time = blob_time(&blob);
                            let written = BlobMeta::read(&blob).and_then(|meta| {
                                meta.spans.iter().next().map(|(peer, span)| {
                                    document_change(doc, *peer, span.start, span.end)
                                })
                            });
                            (time, kind, Detail::Document(written))
                        }
                        Ok(Content::Targets { role, targets }) => {
                            let ids: Vec<SuggestionId> =
                                targets.into_iter().map(SuggestionId::from_bytes).collect();
                            let kind = if role == ContentRole::Accept {
                                Kind::Review {
                                    accepts: ids,
                                    dismisses: Vec::new(),
                                }
                            } else {
                                Kind::Review {
                                    accepts: Vec::new(),
                                    dismisses: ids,
                                }
                            };
                            (None, kind, Detail::Document(None))
                        }
                        Err(_) => (None, Kind::Edit, Detail::Document(None)),
                    },
                };
                change(replica, unit, effect, time, kind, detail)
            })
            .collect()
    }
}

#[cfg(feature = "adapter-records")]
mod records_history {
    use super::{Change, Detail, Kind, Replica, RowChange, Standing, SuggestionId, change, effect};
    use crate::error::{Error, Result};
    use frasil_adapter::Outcome;
    use frasil_adapter::context::Role;
    use frasil_adapter_records::changeset::MARKER;
    use frasil_adapter_records::{Changeset, Records, State};
    use frasil_base::cbor::Value;
    use frasil_base::errors::Class;
    use frasil_units::runtime::Stream;
    use std::collections::{BTreeMap, BTreeSet};

    /// Tables of rows, by table then key: a cleared column is absent.
    pub type Tables = BTreeMap<String, BTreeMap<Vec<u8>, BTreeMap<String, Value>>>;

    /// The rows a changeset wrote.
    fn rows(changeset: &Changeset) -> Vec<RowChange> {
        let mut rows: BTreeMap<(String, Vec<u8>), RowChange> = BTreeMap::new();
        for op in &changeset.ops {
            let row = rows
                .entry((op.table.clone(), op.key.clone()))
                .or_insert_with(|| RowChange {
                    table: op.table.clone(),
                    key: op.key.clone(),
                    columns: Vec::new(),
                    inserted: false,
                    deleted: false,
                });
            if op.column == MARKER {
                if op.value.is_some() {
                    row.inserted = true;
                } else {
                    row.deleted = true;
                }
            } else {
                row.columns.push(op.column.clone());
            }
        }
        rows.into_values().collect()
    }

    /// The history of a Records stream.
    pub(super) fn history(replica: &Replica, stream: &Stream<Records>) -> Vec<Change> {
        let decoded: Vec<(&frasil_adapter::StreamUnit, Option<Changeset>)> = stream
            .units()
            .map(|unit| {
                let changeset = (unit.context.role == Role::Log)
                    .then(|| Changeset::read(&unit.content).ok())
                    .flatten();
                (unit, changeset)
            })
            .collect();
        let mut accepted: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut dismissed: BTreeSet<[u8; 32]> = BTreeSet::new();
        for (unit, changeset) in &decoded {
            if let Some(changeset) = changeset
                && unit.valid
            {
                accepted.extend(changeset.keys.accepts.iter().copied());
                dismissed.extend(changeset.keys.dismisses.iter().copied());
            }
        }
        decoded
            .into_iter()
            .map(|(unit, changeset)| {
                let id = unit.context.event_id;
                let effect = effect(unit, stream.outcome(&id));
                let time = changeset.as_ref().and_then(|changeset| changeset.time);
                let (kind, detail) = match (unit.context.role, changeset) {
                    (Role::Snapshot, _) => (Kind::Snapshot, Detail::Records(Vec::new())),
                    (Role::Log, None) => (Kind::Edit, Detail::Records(Vec::new())),
                    (Role::Log, Some(changeset)) => {
                        let kind = if changeset.keys.suggestion {
                            Kind::Suggestion(if accepted.contains(&id) {
                                Standing::Accepted
                            } else if dismissed.contains(&id) {
                                Standing::Dismissed
                            } else {
                                Standing::Open
                            })
                        } else if changeset.keys.accepts.is_empty()
                            && changeset.keys.dismisses.is_empty()
                        {
                            Kind::Edit
                        } else {
                            let ids = |targets: &[[u8; 32]]| {
                                targets
                                    .iter()
                                    .map(|target| SuggestionId::from_bytes(*target))
                                    .collect()
                            };
                            Kind::Review {
                                accepts: ids(&changeset.keys.accepts),
                                dismisses: ids(&changeset.keys.dismisses),
                            }
                        };
                        (kind, Detail::Records(rows(&changeset)))
                    }
                };
                change(replica, unit, effect, time, kind, detail)
            })
            .collect()
    }

    /// One unit of a Records stream, copied out for a replay.
    #[derive(Debug, Clone)]
    struct Step {
        id: [u8; 32],
        author: [u8; 32],
        /// The changeset of a log unit; `None` for a snapshot unit or one
        /// that does not read.
        changeset: Option<Changeset>,
        /// Whether its content counts as accepted here.
        accepted: bool,
        /// Whether the base snapshot's state already includes it.
        covered: bool,
    }

    /// A walk of a Records stream's history, one change at a time, from
    /// the base snapshot: what [`Records::replay`](crate::Records::replay)
    /// returns. Each [`Replay::step`] applies one change; the tables and
    /// rows read as they stood after it. A whole walk is linear in the
    /// stream's changes, and holds no lock.
    #[derive(Debug, Clone)]
    pub struct Replay {
        state: State,
        steps: Vec<Step>,
        next: usize,
    }

    impl Replay {
        /// Applies the next change and returns its ID; `None` at the end.
        /// A change the base snapshot compacted changes nothing here: the
        /// walk starts from the snapshot, which holds it already, with any
        /// later change it compacted too.
        pub fn step(&mut self) -> Option<crate::client::UnitId> {
            let step = self.steps.get(self.next)?;
            self.next += 1;
            if !step.covered
                && let Some(changeset) = &step.changeset
            {
                self.state.count(step.id, changeset.clock);
                if step.accepted {
                    self.state.submit(step.id, step.author, changeset);
                }
            }
            Some(crate::client::UnitId::from_bytes(step.id))
        }

        /// Walks to the change `until` and stops after it.
        ///
        /// # Errors
        ///
        /// [`Error::Invalid`] when no change of the stream has the ID.
        pub fn until(&mut self, until: crate::client::UnitId) -> Result<()> {
            while let Some(id) = self.step() {
                if id == until {
                    return Ok(());
                }
            }
            Err(Error::Invalid("no change of the stream has this ID"))
        }

        /// The tables as they stand at this point of the walk.
        pub fn tables(&self) -> Tables {
            self.state
                .rows()
                .into_iter()
                .map(|(table, rows)| {
                    let rows = rows
                        .into_iter()
                        .map(|(key, columns)| {
                            let row = columns
                                .into_iter()
                                .filter_map(|(column, value)| Some((column, value?)))
                                .collect();
                            (key, row)
                        })
                        .collect();
                    (table, rows)
                })
                .collect()
        }

        /// One row as it stands at this point of the walk, if it shows.
        pub fn row(&self, table: &str, key: &[u8]) -> Option<BTreeMap<String, Value>> {
            self.state.rows().remove(table)?.remove(key).map(|columns| {
                columns
                    .into_iter()
                    .filter_map(|(column, value)| Some((column, value?)))
                    .collect()
            })
        }
    }

    /// A replay of a Records stream: its base snapshot's state and its
    /// units in canonical order, copied out.
    pub(super) fn replay(stream: &Stream<Records>) -> Result<Replay> {
        let state = match stream.base() {
            Some(base) => State::from_bytes(&base.state)
                .map_err(|class| Error::Adapter(class.name().into()))?,
            None => State::new(),
        };
        let steps = stream
            .units()
            .map(|unit| {
                let id = unit.context.event_id;
                Step {
                    id,
                    author: unit.context.author,
                    changeset: (unit.context.role == Role::Log)
                        .then(|| Changeset::read(&unit.content).ok())
                        .flatten(),
                    accepted: unit.valid
                        && !matches!(
                            stream.outcome(&id),
                            Some(Outcome::Refused(_) | Outcome::Counted)
                        ),
                    covered: stream.base().is_some_and(|base| base.includes(&id)),
                }
            })
            .collect();
        Ok(Replay {
            state,
            steps,
            next: 0,
        })
    }
}

#[cfg(feature = "adapter-records")]
pub use records_history::{Replay, Tables};

impl Engine {
    /// The history of a stream: one [`Change`] per unit this device holds
    /// of it, in canonical order. Reading a Loro document's history
    /// commits the transaction in flight on a lent document, as an export
    /// does.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::UnknownStream`]; [`Error::Invalid`]
    /// for a stream of a kind without history.
    pub async fn stream_history(&self, space: EventId, stream: StreamId) -> Result<Vec<Change>> {
        let state = self.lock().await;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let runtime = replica.stream(&stream).ok_or(Error::UnknownStream)?;
        let any = runtime.as_any();
        #[cfg(feature = "adapter-loro")]
        if let Some(stream) =
            any.downcast_ref::<frasil_units::runtime::Stream<frasil_adapter_loro::Loro>>()
        {
            return Ok(loro_history::history(replica, stream));
        }
        #[cfg(feature = "adapter-records")]
        if let Some(stream) =
            any.downcast_ref::<frasil_units::runtime::Stream<frasil_adapter_records::Records>>()
        {
            return Ok(records_history::history(replica, stream));
        }
        let _ = any;
        Err(Error::Invalid("history is read for documents and tables"))
    }

    /// A Loro document as it stood at a version, as
    /// [`DocumentChange::before`] or [`DocumentChange::after`] name one: a
    /// copy of its own (`LoroDoc::fork_at`), which nothing it is given
    /// reaches the document.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::UnknownStream`]; [`Error::Adapter`]
    /// when the document does not reach the version.
    #[cfg(feature = "adapter-loro")]
    pub async fn document_at(
        &self,
        space: EventId,
        stream: StreamId,
        version: &loro::Frontiers,
    ) -> Result<loro::LoroDoc> {
        let state = self.lock().await;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let loro = crate::documents::loro_state(replica, &stream).ok_or(Error::UnknownStream)?;
        loro.doc()
            .fork_at(version)
            .map_err(|e| Error::Adapter(e.to_string()))
    }

    /// A walk of a Records stream's history from its base snapshot:
    /// the units are copied out under the engine's lock once, and the walk
    /// runs without it.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::UnknownStream`]; [`Error::Invalid`]
    /// for a stream of another kind; [`Error::Adapter`] when the base
    /// snapshot does not decode.
    #[cfg(feature = "adapter-records")]
    pub async fn records_replay(&self, space: EventId, stream: StreamId) -> Result<Replay> {
        let state = self.lock().await;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let runtime = replica.stream(&stream).ok_or(Error::UnknownStream)?;
        let stream = runtime
            .as_any()
            .downcast_ref::<frasil_units::runtime::Stream<frasil_adapter_records::Records>>()
            .ok_or(Error::Invalid("not a Records stream"))?;
        records_history::replay(stream)
    }

    /// A Loro document's snapshot at a version: the export a page imports
    /// into a Loro document of its own, in one pass under the lock.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::UnknownStream`]; [`Error::Adapter`]
    /// when the document does not reach the version.
    #[cfg(feature = "adapter-loro")]
    pub async fn document_snapshot_at(
        &self,
        space: EventId,
        stream: StreamId,
        version: &loro::Frontiers,
    ) -> Result<Vec<u8>> {
        let state = self.lock().await;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let loro = crate::documents::loro_state(replica, &stream).ok_or(Error::UnknownStream)?;
        loro.doc()
            .export(loro::ExportMode::snapshot_at(version))
            .map_err(|e| Error::Adapter(e.to_string()))
    }
}
