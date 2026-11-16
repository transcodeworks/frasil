//! Undo (decision: a client toolkit): an undo manager that undoes only
//! this device's operations, follows Frasil across a replacement of the
//! document, keeps suggestions apart, and covers Records by writing the
//! previous value.

#[cfg(all(feature = "adapter-loro", not(target_arch = "wasm32")))]
pub use document::Undo;
#[cfg(feature = "adapter-records")]
pub use records::RecordsUndo;

#[cfg(all(feature = "adapter-loro", not(target_arch = "wasm32")))]
mod document {
    use crate::client::Lent;
    use crate::error::{Error, Result};
    use loro::{LoroDoc, UndoManager};
    use std::sync::{Arc, Mutex, PoisonError};

    /// What the manager binds: Loro's undo manager on the document of one
    /// generation, and what each new manager takes again.
    struct Bound {
        generation: Option<u64>,
        manager: UndoManager,
        /// The origin prefixes the stack leaves out.
        excluded: Vec<String>,
        /// The merge interval set, if any.
        merge_interval: Option<i64>,
    }

    impl Bound {
        /// Binds a new manager to the document of `generation`, unless the
        /// manager is bound to that one or a newer one already.
        fn bind(&mut self, doc: &LoroDoc, generation: u64) {
            if self.generation.is_some_and(|bound| bound >= generation) {
                return;
            }
            self.manager = UndoManager::new(doc);
            for prefix in &self.excluded {
                self.manager.add_exclude_origin_prefix(prefix);
            }
            if let Some(interval) = self.merge_interval {
                self.manager.set_merge_interval(interval);
            }
            self.generation = Some(generation);
        }
    }

    /// Undo for a lent document ([`Lent`]): Loro's `UndoManager` on the
    /// document, bound again whenever Frasil replaces the document
    /// ([`Lent::replaced`]) or renews the incarnation, so that the
    /// application keeps one `Undo` for the document's life.
    ///
    /// It undoes this device's operations and no one else's: Loro's manager
    /// tracks the document's own peer, which is the lent incarnation.
    /// Suggestions stay apart by construction: a suggestion is made on a
    /// fork and reaches the document only as an import once accepted, and
    /// imports are not this peer's operations. Across a replacement the
    /// stack does not carry over: Loro binds a manager to one document.
    /// The new one undoes what is written after.
    #[derive(Clone)]
    pub struct Undo {
        lent: Lent,
        bound: Arc<Mutex<Bound>>,
    }

    impl core::fmt::Debug for Undo {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Undo")
                .field("generation", &self.bound().generation)
                .finish_non_exhaustive()
        }
    }

    fn adapter(error: impl core::fmt::Display) -> Error {
        Error::Adapter(error.to_string())
    }

    impl Undo {
        /// Undo for the lent document, bound to it now and to each
        /// replacement before the application can write to it.
        pub fn new(lent: &Lent) -> Self {
            let bound = Arc::new(Mutex::new(Bound {
                generation: None,
                manager: UndoManager::new(&LoroDoc::new()),
                excluded: Vec::new(),
                merge_interval: None,
            }));
            // The hook is the one binder: run now on the document in hand
            // and on each replacement, under the lock the replacement
            // takes, so the manager is never bound to a document of
            // another generation than the one it names.
            let rebind = Arc::downgrade(&bound);
            lent.bind_replaced(move |doc, generation| {
                if let Some(bound) = rebind.upgrade() {
                    bound
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .bind(doc, generation);
                }
            });
            Self {
                lent: lent.clone(),
                bound,
            }
        }

        fn bound(&self) -> std::sync::MutexGuard<'_, Bound> {
            self.bound.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Leaves out of the stack every commit whose origin begins with
        /// `prefix`, as Loro's `UndoManager::add_exclude_origin_prefix`
        /// does, on this manager and on each one bound after a
        /// replacement. An application that applies remote or generated
        /// changes as its own commits names them with such an origin
        /// (`LoroDoc::set_next_commit_origin`).
        pub fn exclude_origin_prefix(&mut self, prefix: &str) {
            let mut bound = self.bound();
            bound.manager.add_exclude_origin_prefix(prefix);
            bound.excluded.push(prefix.to_owned());
        }

        /// The document the manager is bound to now: [`Lent::doc`].
        pub fn doc(&self) -> LoroDoc {
            self.lent.doc()
        }

        /// Undoes this device's last change. `false` when there is none.
        ///
        /// # Errors
        ///
        /// [`Error::Adapter`] when Loro refuses the step.
        pub fn undo(&self) -> Result<bool> {
            self.bound().manager.undo().map_err(adapter)
        }

        /// Redoes the last change undone. `false` when there is none.
        ///
        /// # Errors
        ///
        /// [`Error::Adapter`] when Loro refuses the step.
        pub fn redo(&self) -> Result<bool> {
            self.bound().manager.redo().map_err(adapter)
        }

        /// Whether there is a change to undo.
        pub fn can_undo(&self) -> bool {
            self.bound().manager.can_undo()
        }

        /// Whether there is a change to redo.
        pub fn can_redo(&self) -> bool {
            self.bound().manager.can_redo()
        }

        /// How many changes the stack holds to undo.
        pub fn undo_count(&self) -> usize {
            self.bound().manager.undo_count()
        }

        /// Starts a group: the changes until [`Undo::group_end`] undo as
        /// one.
        ///
        /// # Errors
        ///
        /// [`Error::Adapter`] when Loro refuses.
        pub fn group_start(&self) -> Result<()> {
            self.bound().manager.group_start().map_err(adapter)
        }

        /// Ends the group [`Undo::group_start`] began.
        pub fn group_end(&self) {
            self.bound().manager.group_end();
        }

        /// The interval, in milliseconds, within which changes merge into
        /// one step: Loro's merge interval.
        pub fn set_merge_interval(&self, milliseconds: i64) {
            let mut bound = self.bound();
            bound.manager.set_merge_interval(milliseconds);
            bound.merge_interval = Some(milliseconds);
        }

        /// Empties both stacks.
        pub fn clear(&self) {
            self.bound().manager.clear();
        }

        /// The generation of the document the manager is bound to, which
        /// rises with each replacement ([`Lent::generation`]).
        pub fn generation(&self) -> u64 {
            self.bound().generation.unwrap_or_default()
        }
    }
}

#[cfg(feature = "adapter-records")]
mod records {
    use crate::client::streams::{Records, Transaction};
    use crate::error::{Error, Result};
    use frasil_adapter_records::Op;
    use frasil_adapter_records::changeset::MARKER;
    use frasil_base::cbor::Value;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, PoisonError};

    /// What undoes one write: the ops that put each cell it set back as
    /// it was, and the ops that redo it.
    #[derive(Debug, Clone)]
    struct Step {
        undo: Vec<Op>,
        redo: Vec<Op>,
    }

    /// Undo for Records tables: each write through it records the previous
    /// value of every cell it sets, and `undo` writes those back as a
    /// change of this device. Nothing here is Loro's: a table's undo is a
    /// new write, and another member's later write to the same cell wins
    /// over it as any write does.
    #[derive(Debug, Clone)]
    pub struct RecordsUndo {
        records: Records,
        stacks: Arc<Mutex<(Vec<Step>, Vec<Step>)>>,
    }

    impl RecordsUndo {
        /// Undo for the tables.
        pub fn new(records: &Records) -> Self {
            Self {
                records: records.clone(),
                stacks: Arc::new(Mutex::new((Vec::new(), Vec::new()))),
            }
        }

        /// The tables.
        pub fn records(&self) -> &Records {
            &self.records
        }

        /// The inverse of ops over the tables as they stand now.
        async fn inverse(&self, ops: &[Op]) -> Result<Vec<Op>> {
            let stream = self.records.opening.stream();
            let cells: BTreeMap<(String, Vec<u8>, String), Option<Value>> = self
                .records
                .space
                .read(|replica| {
                    let state = crate::client::streams::records_state(replica, &stream);
                    ops.iter()
                        .map(|op| {
                            let previous = state.and_then(|state| {
                                state
                                    .cell(&op.table, &op.key, &op.column)
                                    .and_then(|cell| cell.value.clone())
                            });
                            (
                                (op.table.clone(), op.key.clone(), op.column.clone()),
                                previous,
                            )
                        })
                        .collect()
                })
                .await?;
            Ok(ops
                .iter()
                .map(|op| {
                    let previous = cells
                        .get(&(op.table.clone(), op.key.clone(), op.column.clone()))
                        .cloned()
                        .flatten();
                    match (op.column.as_str(), previous) {
                        (MARKER, Some(_)) => Op::insert_row(&op.table, op.key.clone()),
                        (MARKER, None) => Op::delete_row(&op.table, op.key.clone()),
                        (_, Some(value)) => Op::set(&op.table, op.key.clone(), &op.column, value),
                        (_, None) => Op::clear(&op.table, op.key.clone(), &op.column),
                    }
                })
                .collect())
        }

        /// Writes the cells `write` sets, as one change, and records how to
        /// undo it. A suggestion is not recorded: it is not a change of the
        /// tables.
        ///
        /// # Errors
        ///
        /// As [`Records::write`].
        pub async fn write(&self, write: impl FnOnce(&mut Transaction)) -> Result<()> {
            let mut transaction = Transaction::default();
            write(&mut transaction);
            if transaction.suggestion {
                return self.records.write_transaction(transaction).await;
            }
            let redo = transaction.ops().to_vec();
            if redo.is_empty() {
                return Err(Error::Adapter("the write sets no cell".into()));
            }
            let undo = self.inverse(&redo).await?;
            self.records.write_transaction(transaction).await?;
            let mut stacks = self.stacks.lock().unwrap_or_else(PoisonError::into_inner);
            stacks.0.push(Step { undo, redo });
            stacks.1.clear();
            Ok(())
        }

        /// Writes a step's ops and moves it to the other stack, with what
        /// the written cells held, so that the step back puts back what
        /// it found.
        async fn step(&self, undo: bool) -> Result<bool> {
            let step = {
                let mut stacks = self.stacks.lock().unwrap_or_else(PoisonError::into_inner);
                if undo { stacks.0.pop() } else { stacks.1.pop() }
            };
            let Some(step) = step else {
                return Ok(false);
            };
            let ops = if undo { step.undo } else { step.redo };
            let found = self.inverse(&ops).await?;
            let mut transaction = Transaction::default();
            transaction.extend(ops.iter().cloned());
            self.records.write_transaction(transaction).await?;
            let mut stacks = self.stacks.lock().unwrap_or_else(PoisonError::into_inner);
            if undo {
                stacks.1.push(Step {
                    undo: ops,
                    redo: found,
                });
            } else {
                stacks.0.push(Step {
                    undo: found,
                    redo: ops,
                });
            }
            Ok(true)
        }

        /// Undoes this device's last write through this manager: writes
        /// each cell it set back as it was before. `false` when there is
        /// none.
        ///
        /// # Errors
        ///
        /// As [`Records::write`].
        pub async fn undo(&self) -> Result<bool> {
            self.step(true).await
        }

        /// Redoes the last write undone. `false` when there is none.
        ///
        /// # Errors
        ///
        /// As [`Records::write`].
        pub async fn redo(&self) -> Result<bool> {
            self.step(false).await
        }

        /// Whether there is a write to undo.
        pub fn can_undo(&self) -> bool {
            !self
                .stacks
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .0
                .is_empty()
        }

        /// Whether there is a write to redo.
        pub fn can_redo(&self) -> bool {
            !self
                .stacks
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .1
                .is_empty()
        }
    }
}
