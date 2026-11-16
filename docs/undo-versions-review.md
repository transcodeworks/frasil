# Undo, versions and review

The `frasil` crate and `@frasil/client` provide an undo manager that
follows Frasil, undo for tables, named versions synced to every member,
and suggestions reviewed against their base. All of it is built on the
protocol as specified, with nothing added to it. The docs of
`frasil::Undo`, `frasil::RecordsUndo`, `frasil::Version` and
`frasil::Review` are the reference; this is the walk-through.

## Undo for a lent document

```rust
let lent = document.lend().await?;
let undo = Undo::new(&lent);          // once, for the document's life
// ... the application edits lent.doc() ...
undo.undo()?;
undo.redo()?;
```

`Undo` is Loro's `UndoManager` on the lent document, bound again by
Frasil whenever the document is replaced after a rebuild or the
incarnation is renewed. The application keeps one `Undo` and never
rebinds; `replaced()` is still there for the editor's own rebinding.
An editor that must bind something else to the new document before the
application writes to it uses the same hook `Undo` does,
`Lent::on_replaced(|doc, generation| ...)`, which runs on the new document
after the pending operations were carried over and before `replaced()`
wakes.

- It undoes this device's operations and no one else's: Loro's manager
  tracks the document's own peer, the lent incarnation.
- Suggestions stay apart by construction. A suggestion is made on a fork
  of the document and reaches it only as an import once accepted, and an
  import is not this peer's operation, so neither a suggestion of this
  device nor an accepted one of another's is ever in the stack.
- Across a replacement the stack does not carry over: Loro binds a
  manager to one document. The new one undoes what is written after.
  Replacements are rare.
- `group_start`/`group_end` and `set_merge_interval` are Loro's; the
  merge interval is set again on each new manager.
- `undo.exclude_origin_prefix("sync:")` leaves out of the stack every
  commit whose origin begins with the prefix (Loro's
  `add_exclude_origin_prefix`), on each new manager too. An application
  that writes changes it did not make, such as a calendar sync, commits
  them under such an origin (`doc.set_next_commit_origin("sync:...")`).
- Frasil binds the new manager in the replacement itself, under the lock
  that stores the new document, so an undo used meanwhile is never bound
  to the old document.

## Undo for tables

```rust
let undo = RecordsUndo::new(&records);
undo.write(|t| { t.insert("cues", b"c1").set("cues", b"c1", "level", 1u64); }).await?;
undo.undo().await?;    // writes the previous values back
undo.redo().await?;
```

A table has no operations to invert: `RecordsUndo` records, for every
cell a write through it sets, the value the cell held before, and `undo`
writes those values back as a change of this device (a cleared cell, a
row deleted or inserted again). It is a new write like any other: another
member's later write to the same cell wins over it as the latest write
does, and every step shows in the tables' history. A suggestion written
through it is not recorded, since it changes nothing until accepted.

An undo writes the value the cell held when this device wrote, with a
newer stamp: if another member wrote the same cell between this device's
write and its undo, the undo overrides that member's value too. An
application that must not do so compares the cell with the value its
write left before it undoes.

## Named versions

```rust
let version = document.tag("first draft").await?;   // a Version
let versions = space.versions().await?;             // every tag in the space
let then = document.at(&frontier).await?;           // Marked::Document(frontier)
space.untag(version.id).await?;
```

A tag marks a document at a Loro frontier (`Marked::Document`), or
tables after a change (`Marked::Records(UnitId)`, replayed with
`Records::at`). Tags live in a Records stream of Frasil's own in the
space, whose opening every member derives from the space's ID
(`Space::versions_stream`), so no registry names it; they travel as any
change does, every member reads them, and a writer removes one. The
stream shows in `space.streams()` as Records: leave it to Frasil. A tag
carries the device that tagged and the time its clock gave, shown and
never checked.

## Review

```rust
let review = document.review(suggestion_id).await?;
for change in &review.changes {
    match change {
        ReviewChange::Text { container, delta } => ..., // retain, insert, delete
        ReviewChange::Map { key, from, to, .. } => ...,
        ReviewChange::List { from, to, .. } => ...,
        ReviewChange::Cell { table, key, column, from, to } => ...,
        _ => ...,
    }
}
document.accept(&[review.id]).await?;   // or dismiss
```

The flow is propose (`Document::suggest` with an update made on a fork;
`Transaction::suggest` for tables), review, accept or dismiss. A document
review applies the suggestion to a copy at the version it was made on
(`review.base`, which `Document::at` reads) and lists what changed,
container by container; the document is not touched. When this device
does not hold the base, the review runs against the document as it is.
When it lacks what the suggestion depends on at all (an edit the
suggesting device had not yet written as a unit), the suggestion stays
pending inside Loro: `review.base_missing` is true and `changes` is
empty, and a review after syncing shows it. A
table review lists each cell the suggestion sets, with its value now and
the value suggested.

## In the browser

`@frasil/client` has the versions and the review: `space.versions()`,
`document.tag(name)`, `records.tag(name)`, `space.untag(id)`,
`document.review(id)`, `records.review(id)`, with the same shapes as
plain objects (`baseMissing` for `base_missing`). It has no `Undo`, so
no excluded origins, and no `RecordsUndo`: the browser keeps
its own Loro document and `Live`, and a Rust document cannot cross into
JavaScript, so a rebuild-aware undo would need a replacement signal `Live`
does not have; the page binds Loro's own `UndoManager` to its own document. Tables' undo by the previous value is a few lines over
`records.row` and `records.write` in the page.
