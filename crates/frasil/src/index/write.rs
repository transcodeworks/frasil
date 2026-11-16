//! Writes: an application writes rows through Records, never through the
//! cache. Source kinds come from Frasil space descriptors.

use crate::index::column::{Cell, Ref};
use crate::index::error::{Error, Result};
use crate::index::table::Table;
use crate::{Device, Records, Space, StreamKind, Transaction};

/// Creates a space of a kind: every readable space of a kind feeds the
/// tables whose source it is. Frasil records the kind at creation.
///
/// # Errors
///
/// [`Error::Schema`] for an empty kind; Frasil's.
pub async fn create_space(device: &Device, kind: &str) -> Result<Writer> {
    if kind.is_empty() {
        return Err(Error::Schema("a kind is not empty".into()));
    }
    let space = device.create_space_of_kind(kind).await?;
    let records = space.create_records()?;
    Ok(Writer {
        records,
        kind: kind.to_owned(),
    })
}

/// The tables streams of a space that name its kind, with the kind.
pub(crate) async fn kinded(space: &Space) -> Result<Vec<(Records, String)>> {
    let Some(kind) = space.kind().await? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for stream in space.streams().await? {
        if stream.kind == StreamKind::Records {
            match space.records(stream.id).await {
                Ok(records) => out.push((records, kind.clone())),
                Err(crate::Error::UnknownStream) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(out)
}

/// Writes rows of typed tables in a space's tables stream. Each call is
/// one Records change.
#[derive(Debug, Clone)]
pub struct Writer {
    records: Records,
    kind: String,
}

impl Writer {
    /// The writer of a space made by [`create_space`].
    ///
    /// # Errors
    ///
    /// [`Error::NoKind`] for a space with no kind, as until its tables
    /// stream has reached this device; Frasil's.
    pub async fn of(space: &Space) -> Result<Self> {
        if let Some((records, kind)) = kinded(space).await?.into_iter().next() {
            return Ok(Self { records, kind });
        }
        let kind = space.kind().await?.ok_or(Error::NoKind)?;
        Ok(Self {
            records: space.create_records()?,
            kind,
        })
    }

    /// The space's kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The space.
    pub fn space(&self) -> &Space {
        self.records.space()
    }

    /// The tables stream, for writes the typed calls do not make.
    pub fn records(&self) -> &Records {
        &self.records
    }

    /// Inserts a row under a new random key.
    ///
    /// # Errors
    ///
    /// As [`Writer::write`].
    pub async fn insert<T: Table>(&self, row: &T) -> Result<Ref<T>> {
        let key = Ref::random()?;
        self.put(&key, row).await?;
        Ok(key)
    }

    /// Writes every cell of a row under its key, inserting it if it is not
    /// there.
    ///
    /// # Errors
    ///
    /// As [`Writer::write`].
    pub async fn put<T: Table>(&self, key: &Ref<T>, row: &T) -> Result<()> {
        self.write(|batch| batch.put(key, row)).await
    }

    /// Writes only the cells that differ from `before`. Concurrent edits to
    /// different columns can merge without an unchanged cell overwriting them.
    ///
    /// # Errors
    ///
    /// As [`Writer::write`].
    pub async fn update<T: Table>(&self, key: &Ref<T>, before: &T, after: &T) -> Result<()> {
        self.write(|batch| batch.update(key, before, after)).await
    }

    /// Deletes a row.
    ///
    /// # Errors
    ///
    /// As [`Writer::write`].
    pub async fn delete<T: Table>(&self, key: &Ref<T>) -> Result<()> {
        self.write(|batch| batch.delete(key)).await
    }

    /// Writes what `write` puts in the batch, as one change.
    ///
    /// # Errors
    ///
    /// [`Error::Schema`] for a table that this kind of space does not
    /// feed; Frasil's: [`crate::Error::NotAllowed`] unless this device
    /// writes in the space, and the others of [`Records::write`].
    pub async fn write(&self, write: impl FnOnce(&mut Batch) -> Result<()>) -> Result<()> {
        let mut batch = Batch {
            kind: &self.kind,
            changed: false,
            transaction: Transaction::default(),
        };
        write(&mut batch)?;
        if !batch.changed {
            return Ok(());
        }
        let transaction = batch.transaction;
        self.records.write(|t| *t = transaction).await?;
        Ok(())
    }
}

/// The rows of one write.
#[derive(Debug)]
pub struct Batch<'w> {
    kind: &'w str,
    changed: bool,
    transaction: Transaction,
}

impl Batch<'_> {
    fn check<T: Table>(&self) -> Result<()> {
        if T::SCHEMA.source == self.kind {
            Ok(())
        } else {
            Err(Error::Schema(format!(
                "a {} space does not feed {}, whose source is {}",
                self.kind,
                T::SCHEMA.name,
                T::SCHEMA.source
            )))
        }
    }

    /// Inserts a row under a new random key.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`]; as [`Batch::put`].
    pub fn insert<T: Table>(&mut self, row: &T) -> Result<Ref<T>> {
        let key = Ref::random()?;
        self.put(&key, row)?;
        Ok(key)
    }

    /// Writes every cell of a row under its key, inserting it if it is not
    /// there. Frasil records the writer's change time.
    ///
    /// # Errors
    ///
    /// [`Error::Schema`] for a table that this kind of space does not
    /// feed.
    pub fn put<T: Table>(&mut self, key: &Ref<T>, row: &T) -> Result<()> {
        self.check::<T>()?;
        let table = T::SCHEMA.name;
        let key = key.key();
        self.changed = true;
        self.transaction.insert(table, key);
        for (column, cell) in row.cells() {
            match cell {
                Cell::Set(value) => {
                    self.transaction.set(table, key, column, value);
                }
                Cell::Clear => {
                    self.transaction.clear(table, key, column);
                }
                Cell::Keep => {}
            }
        }
        Ok(())
    }

    /// Updates only changed cells of an existing row, without inserting its marker.
    /// A concurrent deletion therefore stays deleted.
    ///
    /// # Errors
    ///
    /// As [`Batch::put`].
    pub fn update<T: Table>(&mut self, key: &Ref<T>, before: &T, after: &T) -> Result<()> {
        self.check::<T>()?;
        let previous = before.cells();
        let table = T::SCHEMA.name;
        let mut changed = false;
        for (column, cell) in after.cells() {
            if previous
                .iter()
                .any(|(name, value)| *name == column && *value == cell)
            {
                continue;
            }
            match cell {
                Cell::Set(value) => {
                    self.transaction.set(table, key.key(), column, value);
                    changed = true;
                }
                Cell::Clear => {
                    self.transaction.clear(table, key.key(), column);
                    changed = true;
                }
                Cell::Keep => {}
            }
        }
        if changed {
            self.changed = true;
        }
        Ok(())
    }

    /// Deletes a row.
    ///
    /// # Errors
    ///
    /// As [`Batch::put`].
    pub fn delete<T: Table>(&mut self, key: &Ref<T>) -> Result<()> {
        self.check::<T>()?;
        self.changed = true;
        self.transaction.delete(T::SCHEMA.name, key.key());
        Ok(())
    }

    /// Makes the write a suggestion: it stays out of the tables until a
    /// writer accepts it, and shows only in tables that hold suggestions.
    pub fn suggest(&mut self) -> &mut Self {
        self.transaction.suggest();
        self
    }
}
