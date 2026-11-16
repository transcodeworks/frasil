//! Suggestions as a review flow (decision: a client toolkit): propose
//! ([`Document::suggest`](crate::Document::suggest),
//! [`Transaction::suggest`](crate::Transaction::suggest)), review (what
//! a suggestion changes against the base it was made on), accept or
//! dismiss, on documents and on tables.

use crate::client::{MemberId, SuggestionId};

/// One step of a text change: Loro's delta.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TextStep {
    /// Keeps this many characters.
    Retain(usize),
    /// Inserts text.
    Insert(String),
    /// Deletes this many characters.
    Delete(usize),
}

/// What a suggestion changes, one entry per container or cell.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ReviewChange {
    /// A text container, as a delta over the base.
    Text {
        /// The container, as Loro names it.
        container: String,
        /// The delta.
        delta: Vec<TextStep>,
    },
    /// A map's key set or removed.
    #[cfg(feature = "adapter-loro")]
    Map {
        /// The container, as Loro names it.
        container: String,
        /// The key.
        key: String,
        /// Its value at the base, if any.
        from: Option<loro::LoroValue>,
        /// Its value with the suggestion, if any.
        to: Option<loro::LoroValue>,
    },
    /// A list container: its items at the base, and with the suggestion.
    #[cfg(feature = "adapter-loro")]
    List {
        /// The container, as Loro names it.
        container: String,
        /// The items at the base.
        from: Vec<loro::LoroValue>,
        /// The items with the suggestion.
        to: Vec<loro::LoroValue>,
    },
    /// A container of another kind (a tree, a counter).
    #[cfg(feature = "adapter-loro")]
    Other {
        /// The container, as Loro names it.
        container: String,
    },
    /// A cell of a table.
    Cell {
        /// The table.
        table: String,
        /// The row's key.
        key: Vec<u8>,
        /// The column; the empty column is the row's marker.
        column: String,
        /// Its value now, if any.
        from: Option<frasil_base::cbor::Value>,
        /// Its value with the suggestion, if any.
        to: Option<frasil_base::cbor::Value>,
    },
}

/// A suggestion read for review: what it changes against the base.
#[derive(Debug, Clone, PartialEq)]
pub struct Review {
    /// The suggestion.
    pub id: SuggestionId,
    /// The device that suggested it.
    pub author: MemberId,
    /// The version it was made on, for a document: a read-only view there
    /// is [`Document::at`](crate::Document::at). A suggestion whose base
    /// this device does not hold reviews against the document as it is.
    #[cfg(feature = "adapter-loro")]
    pub base: Option<loro::Frontiers>,
    /// Whether this device lacks what the suggestion was made on: the
    /// operations it depends on are not here, so it stays pending inside
    /// Loro and `changes` is empty. Sync first, then review again.
    pub base_missing: bool,
    /// What it changes.
    pub changes: Vec<ReviewChange>,
}

#[cfg(feature = "adapter-loro")]
mod document {
    use super::{Review, ReviewChange, TextStep};
    use crate::client::SuggestionId;
    use crate::client::streams::Document;
    use crate::error::{Error, Result};
    use frasil_adapter_loro::BlobMeta;
    use loro::{
        Container, ContainerID, Frontiers, ID, LoroDoc, LoroValue, TextDelta, ValueOrContainer,
    };

    fn adapter(error: impl core::fmt::Display) -> Error {
        Error::Adapter(error.to_string())
    }

    /// A container's whole value.
    fn container_value(container: &Container) -> LoroValue {
        match container {
            Container::Map(map) => map.get_deep_value(),
            Container::List(list) => list.get_deep_value(),
            Container::MovableList(list) => list.get_deep_value(),
            Container::Text(text) => LoroValue::String(text.to_string().into()),
            Container::Tree(tree) => tree.get_value(),
            _ => LoroValue::Null,
        }
    }

    /// A value, with a container's value read through it.
    fn value_of(value: Option<ValueOrContainer>) -> Option<LoroValue> {
        value.map(|value| match value {
            ValueOrContainer::Value(value) => value,
            ValueOrContainer::Container(container) => container_value(&container),
        })
    }

    /// A map's value at a key in a document, if the map is there.
    fn map_value(doc: &LoroDoc, container: &ContainerID, key: &str) -> Option<LoroValue> {
        if !doc.has_container(container) {
            return None;
        }
        value_of(doc.get_map(container.clone()).get(key))
    }

    /// A list's items in a document, if the list is there.
    fn list_items(doc: &LoroDoc, container: &ContainerID) -> Vec<LoroValue> {
        if !doc.has_container(container) {
            return Vec::new();
        }
        match doc.get_list(container.clone()).get_deep_value() {
            LoroValue::List(items) => items.iter().cloned().collect(),
            _ => Vec::new(),
        }
    }

    /// The changes of `after` against `before`, by container.
    fn changes(before: &LoroDoc, after: &LoroDoc, from: &Frontiers) -> Result<Vec<ReviewChange>> {
        let to = after.oplog_frontiers();
        let batch = after.diff(from, &to).map_err(adapter)?;
        let mut out = Vec::new();
        for (container, diff) in batch.iter() {
            let name = container.to_string();
            match diff {
                loro::event::Diff::Text(text) => {
                    let delta = text
                        .iter()
                        .map(|step| match step {
                            TextDelta::Retain { retain, .. } => TextStep::Retain(*retain),
                            TextDelta::Insert { insert, .. } => TextStep::Insert(insert.clone()),
                            TextDelta::Delete { delete } => TextStep::Delete(*delete),
                        })
                        .collect();
                    out.push(ReviewChange::Text {
                        container: name,
                        delta,
                    });
                }
                loro::event::Diff::Map(map) => {
                    let mut keys: Vec<String> = map.updated.keys().map(|k| k.to_string()).collect();
                    keys.sort_unstable();
                    for key in keys {
                        out.push(ReviewChange::Map {
                            container: name.clone(),
                            from: map_value(before, container, &key),
                            to: map_value(after, container, &key),
                            key,
                        });
                    }
                }
                loro::event::Diff::List(_) => out.push(ReviewChange::List {
                    container: name,
                    from: list_items(before, container),
                    to: list_items(after, container),
                }),
                _ => out.push(ReviewChange::Other { container: name }),
            }
        }
        Ok(out)
    }

    impl Document {
        /// Reads a suggestion for review: what it changes against the
        /// version it was made on, container by container. The suggestion
        /// is applied to a copy at its base; the document is not touched.
        ///
        /// # Errors
        ///
        /// [`Error::Invalid`] when no open suggestion has the ID;
        /// [`Error::Adapter`] when Loro cannot read it; as
        /// [`Document::suggestions`].
        pub async fn review(&self, id: SuggestionId) -> Result<Review> {
            let suggestion = self
                .suggestions()
                .await?
                .into_iter()
                .find(|s| s.id == id)
                .ok_or(Error::Invalid("no open suggestion has this ID"))?;
            let doc = self.read().await?;
            let meta = BlobMeta::read(&suggestion.update)
                .ok_or(Error::Invalid("the suggestion is not a Loro update"))?;
            let deps: Vec<ID> = meta
                .deps
                .iter()
                .map(|dep| ID::new(dep.peer, dep.counter))
                .collect();
            let base = Frontiers::from(deps);
            // At the base when this device holds it; else as the document
            // is, with the operations the suggestion depends on pending.
            let (before, base) = match doc.fork_at(&base) {
                Ok(before) if !base.is_empty() => (before, Some(base)),
                _ => (doc.fork(), None),
            };
            let from = before.oplog_frontiers();
            let after = before.fork();
            let status = after.import(&suggestion.update).map_err(adapter)?;
            Ok(Review {
                id,
                author: suggestion.author,
                base,
                base_missing: status.pending.is_some(),
                changes: changes(&before, &after, &from)?,
            })
        }
    }
}

#[cfg(feature = "adapter-records")]
mod records {
    use super::{Review, ReviewChange};
    use crate::client::SuggestionId;
    use crate::client::streams::Records;
    use crate::error::{Error, Result};
    use frasil_adapter_records::Changeset;

    impl Records {
        /// Reads a suggestion for review: each cell it sets, with the
        /// cell's value now and the value it suggests.
        ///
        /// # Errors
        ///
        /// [`Error::Invalid`] when no open suggestion has the ID, or it
        /// does not read; as [`Records::suggestions`].
        pub async fn review(&self, id: SuggestionId) -> Result<Review> {
            let suggestion = self
                .suggestions()
                .await?
                .into_iter()
                .find(|s| s.id == id)
                .ok_or(Error::Invalid("no open suggestion has this ID"))?;
            let changeset = Changeset::read(&suggestion.update)
                .map_err(|_| Error::Invalid("the suggestion is not a changeset"))?;
            let stream = self.opening.stream();
            let changes = self
                .space
                .read(|replica| {
                    let state = crate::client::streams::records_state(replica, &stream);
                    changeset
                        .ops
                        .iter()
                        .map(|op| ReviewChange::Cell {
                            table: op.table.clone(),
                            key: op.key.clone(),
                            column: op.column.clone(),
                            from: state.and_then(|state| {
                                state
                                    .cell(&op.table, &op.key, &op.column)
                                    .and_then(|cell| cell.value.clone())
                            }),
                            to: op.value.clone(),
                        })
                        .collect()
                })
                .await?;
            Ok(Review {
                id,
                author: suggestion.author,
                #[cfg(feature = "adapter-loro")]
                base: None,
                base_missing: false,
                changes,
            })
        }
    }
}
