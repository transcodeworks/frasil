//! Live queries.

use crate::index::cache::Index;
use crate::index::error::{Error, Result};
use crate::index::sql::{Row, SqlValue};
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::broadcast::{self, error::RecvError};

/// A query that runs again whenever the index changes a table it reads.
/// It needs no runtime of its own: [`Watch::next`] waits on a channel.
#[derive(Debug)]
pub struct Watch {
    index: Index,
    sql: String,
    params: Vec<SqlValue>,
    tables: BTreeSet<String>,
    changes: broadcast::Receiver<Arc<BTreeSet<String>>>,
    fresh: bool,
    /// The rows last given, under [`Watch::distinct`].
    last: Option<Option<Vec<Row>>>,
}

impl Watch {
    pub(crate) fn new(
        index: Index,
        sql: String,
        params: Vec<SqlValue>,
        tables: BTreeSet<String>,
        changes: broadcast::Receiver<Arc<BTreeSet<String>>>,
    ) -> Self {
        Self {
            index,
            sql,
            params,
            tables,
            changes,
            fresh: true,
            last: None,
        }
    }

    /// The tables the query reads.
    pub fn tables(&self) -> &BTreeSet<String> {
        &self.tables
    }

    /// This watch, giving rows only when they differ from the last it
    /// gave: a change of a table it reads that leaves its result as it was
    /// gives nothing.
    #[must_use]
    pub fn distinct(mut self) -> Self {
        self.last = Some(None);
        self
    }

    /// The query's rows: at once the first time, then once the index has
    /// changed a table it reads, and under [`Watch::distinct`] only when
    /// the rows differ from the last ones given. A watch that fell behind
    /// runs again at once.
    ///
    /// # Errors
    ///
    /// As [`Index::query`]; [`Error::Closed`] once the index is gone.
    pub async fn next(&mut self) -> Result<Vec<Row>> {
        loop {
            if !std::mem::take(&mut self.fresh) {
                loop {
                    match self.changes.recv().await {
                        Ok(changed) if changed.is_disjoint(&self.tables) => {}
                        Ok(_) | Err(RecvError::Lagged(_)) => break,
                        Err(RecvError::Closed) => return Err(Error::Closed),
                    }
                }
            }
            let rows = self.index.query(&self.sql, &self.params)?;
            match &mut self.last {
                None => return Ok(rows),
                Some(last) if last.as_ref() == Some(&rows) => {}
                Some(last) => {
                    *last = Some(rows.clone());
                    return Ok(rows);
                }
            }
        }
    }
}

/// The tables the index changes, as it changes them, from
/// [`Index::table_changes`]: for an application that reads them again its
/// own way.
#[derive(Debug)]
pub struct TableChanges {
    tables: BTreeSet<String>,
    changes: broadcast::Receiver<Arc<BTreeSet<String>>>,
}

impl TableChanges {
    pub(crate) fn new(
        tables: BTreeSet<String>,
        changes: broadcast::Receiver<Arc<BTreeSet<String>>>,
    ) -> Self {
        Self { tables, changes }
    }

    /// The tables the index changed next, `_spaces` among them when it
    /// changed which spaces feed it; every table when this receiver fell
    /// behind. `None` once the index is gone.
    pub async fn next(&mut self) -> Option<BTreeSet<String>> {
        match self.changes.recv().await {
            Ok(changed) => Some((*changed).clone()),
            Err(RecvError::Lagged(_)) => Some(self.tables.clone()),
            Err(RecvError::Closed) => None,
        }
    }
}
