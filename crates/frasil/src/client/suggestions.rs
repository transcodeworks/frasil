//! Suggestions: changes a member proposes, which a writer accepts or
//! dismisses (adapter-loro.md, section 3.4; adapter-records.md, section
//! 3.4).
//!
//! A suggestion stays out of the document or the tables until a writer
//! accepts it. A member granted only `suggest` writes nothing else.

#![cfg_attr(
    not(any(feature = "adapter-loro", feature = "adapter-records")),
    allow(dead_code, unused_imports)
)]

use super::MemberId;
use crate::error::{Error, Result};

/// A suggestion's ID: the ID of the change that made it. It shows as
/// lowercase hexadecimal and parses from it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SuggestionId([u8; 32]);

impl SuggestionId {
    /// The ID of these bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The ID's bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Display for SuggestionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for SuggestionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SuggestionId({self})")
    }
}

impl core::str::FromStr for SuggestionId {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 64 {
            return Err(Error::Invalid("a SuggestionId is 32 bytes in hexadecimal"));
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            let digit = |c: u8| (c as char).to_digit(16);
            match (digit(pair[0]), digit(pair[1])) {
                (Some(high), Some(low)) => *slot = (high * 16 + low) as u8,
                _ => return Err(Error::Invalid("a SuggestionId is hexadecimal")),
            }
        }
        Ok(Self(out))
    }
}

/// An open suggestion: neither accepted nor dismissed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Suggestion {
    /// Its ID.
    pub id: SuggestionId,
    /// The device that suggested it.
    pub author: MemberId,
    /// What it changes. In a Loro document, a Loro update: import it into
    /// a fork of the document to show it (`LoroDoc::fork`). In Records,
    /// its changeset, as adapter-records.md, section 2.2, encodes it.
    pub update: Vec<u8>,
}

/// The targets of one accept or dismiss: 1 to 64 suggestions.
fn targets(ids: &[SuggestionId]) -> Result<Vec<[u8; 32]>> {
    let mut targets: Vec<[u8; 32]> = ids.iter().map(|id| id.0).collect();
    targets.sort_unstable();
    targets.dedup();
    if targets.is_empty() {
        return Err(Error::Invalid("name at least one suggestion"));
    }
    if targets.len() > 64 {
        return Err(Error::Invalid("name at most 64 suggestions at once"));
    }
    Ok(targets)
}

#[cfg(feature = "adapter-loro")]
mod document {
    use super::{MemberId, Result, Suggestion, SuggestionId, targets};
    use crate::client::streams::Document;
    use crate::documents::loro_state;
    use frasil_adapter_loro::{Content, Standing};

    impl Document {
        /// Suggests a change (adapter-loro.md, section 3.4): `update`,
        /// Loro's bytes for operations over the document's current state,
        /// made on a fork of it. It enters the document only once accepted.
        ///
        /// # Errors
        ///
        /// [`Error::Adapter`](crate::Error::Adapter) when Loro does not read `update`, or it
        /// changes nothing; [`Error::NotAllowed`](crate::Error::NotAllowed) unless this device writes
        /// or suggests in the space; [`Error::SyncBeforeWriting`](crate::Error::SyncBeforeWriting);
        /// [`Error::RotationDue`](crate::Error::RotationDue).
        pub async fn suggest(&self, update: &[u8]) -> Result<SuggestionId> {
            self.space
                .device
                .engine()
                .suggest_document(self.space.id().event(), &self.opening, update)
                .await
                .map(|id| SuggestionId(id.0))
        }

        /// The document's open suggestions, ascending by ID.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`](crate::Error::UnknownSpace).
        pub async fn suggestions(&self) -> Result<Vec<Suggestion>> {
            let stream = self.opening.stream();
            self.space
                .read(|replica| {
                    let Some(state) = loro_state(replica, &stream) else {
                        return Vec::new();
                    };
                    state
                        .layer()
                        .into_iter()
                        .filter(|(_, (_, standing))| *standing == Standing::Open)
                        .map(|(id, (suggestion, _))| Suggestion {
                            id: SuggestionId(id),
                            author: MemberId::from_bytes(suggestion.author),
                            update: suggestion.written.blob.clone(),
                        })
                        .collect()
                })
                .await
        }

        /// Accepts suggestions: their operations enter the document as
        /// their authors wrote them.
        ///
        /// # Errors
        ///
        /// [`Error::Invalid`](crate::Error::Invalid) for no suggestion or more than 64;
        /// [`Error::NotAllowed`](crate::Error::NotAllowed) unless this device writes in the space, a
        /// suggester's included; [`Error::SyncBeforeWriting`](crate::Error::SyncBeforeWriting);
        /// [`Error::RotationDue`](crate::Error::RotationDue).
        pub async fn accept(&self, ids: &[SuggestionId]) -> Result<()> {
            self.close(Content::accept(targets(ids)?)).await
        }

        /// Dismisses suggestions: they stay out of the document, unless
        /// another writer accepts them.
        ///
        /// # Errors
        ///
        /// As [`Document::accept`].
        pub async fn dismiss(&self, ids: &[SuggestionId]) -> Result<()> {
            self.close(Content::dismiss(targets(ids)?)).await
        }

        async fn close(&self, content: Content) -> Result<()> {
            self.space
                .device
                .engine()
                .write_document_content(self.space.id().event(), &self.opening, content)
                .await
                .map(drop)
        }
    }
}

#[cfg(feature = "adapter-records")]
mod records {
    use super::{Error, MemberId, Result, Suggestion, SuggestionId, targets};
    use crate::client::streams::{Records, Transaction};
    use frasil_adapter_records::{Changeset, Op, SuggestionKeys};
    use frasil_units::runtime::Stream;
    use std::collections::BTreeMap;

    /// The table a dismiss writes its one op in: a changeset holds at
    /// least one op (adapter-records.md, section 2.2), and a deleted row
    /// of this table never shows.
    const DISMISSED: &str = "frasil.dismissed";

    fn state<'r>(
        replica: &'r crate::replica::Replica,
        stream: &frasil_units::stream::StreamId,
    ) -> Option<&'r frasil_adapter_records::State> {
        replica
            .stream(stream)?
            .as_any()
            .downcast_ref::<Stream<frasil_adapter_records::Records>>()
            .map(Stream::state)
    }

    impl Transaction {
        /// Makes the write a suggestion (adapter-records.md, section 3.4):
        /// it stays out of the tables until a writer accepts it. A member
        /// granted only `suggest` writes nothing else.
        pub fn suggest(&mut self) -> &mut Self {
            self.suggestion = true;
            self
        }
    }

    impl Records {
        /// The open suggestions, ascending by ID.
        ///
        /// # Errors
        ///
        /// [`Error::UnknownSpace`].
        pub async fn suggestions(&self) -> Result<Vec<Suggestion>> {
            let stream = self.opening.stream();
            self.space
                .read(|replica| {
                    let Some(state) = state(replica, &stream) else {
                        return Vec::new();
                    };
                    state
                        .layer()
                        .open()
                        .iter()
                        .map(|(id, suggestion)| Suggestion {
                            id: SuggestionId(*id),
                            author: MemberId::from_bytes(suggestion.author),
                            update: suggestion.content.clone(),
                        })
                        .collect()
                })
                .await
        }

        /// Accepts open suggestions: this device writes the cells they set
        /// as its own change, that of the higher ID where two set one
        /// cell. A suggestion no longer open is passed over.
        ///
        /// # Errors
        ///
        /// [`Error::Invalid`] for no suggestion or more than 64, or when
        /// none is open; [`Error::NotAllowed`] unless this device writes in
        /// the space; [`Error::SyncBeforeWriting`]; [`Error::RotationDue`].
        pub async fn accept(&self, ids: &[SuggestionId]) -> Result<()> {
            self.close(ids, true).await
        }

        /// Dismisses open suggestions: they leave the layer, unless another
        /// writer accepts them. A suggestion no longer open is passed over.
        ///
        /// # Errors
        ///
        /// As [`Records::accept`].
        pub async fn dismiss(&self, ids: &[SuggestionId]) -> Result<()> {
            self.close(ids, false).await
        }

        async fn close(&self, ids: &[SuggestionId], accept: bool) -> Result<()> {
            let wanted = targets(ids)?;
            let stream = self.opening.stream();
            // The writer's wall clock, its claim (adapter-records.md,
            // section 2.2, key 7).
            let time = self.space().device().engine().wall_clock();
            self.space
                .device
                .engine()
                .write_unit(self.space.id().event(), &self.opening, |replica, _| {
                    let state = state(replica, &stream).ok_or(Error::UnknownStream)?;
                    let open = state.layer().open();
                    let found: Vec<[u8; 32]> = wanted
                        .iter()
                        .filter(|id| open.contains_key(*id))
                        .copied()
                        .collect();
                    let Some(first) = found.first() else {
                        return Err(Error::Invalid("none of these suggestions is open"));
                    };
                    let mut keys = SuggestionKeys::default();
                    let ops = if accept {
                        let mut cells = BTreeMap::new();
                        for id in &found {
                            let changeset = Changeset::read(&open[id].content)
                                .map_err(|class| Error::Adapter(format!("{class:?}")))?;
                            for op in changeset.ops {
                                cells.insert(
                                    (op.table.clone(), op.key.clone(), op.column.clone()),
                                    op,
                                );
                            }
                        }
                        keys.accepts = found.clone();
                        cells.into_values().collect()
                    } else {
                        keys.dismisses = found.clone();
                        vec![Op::delete_row(DISMISSED, first.to_vec())]
                    };
                    let changeset = Changeset {
                        clock: state.next_clock(),
                        ops,
                        keys,
                        time,
                    };
                    Ok(changeset.encode())
                })
                .await
                .map(drop)
        }
    }
}
