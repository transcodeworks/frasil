//! An internal building block of Frasil: applications use the `frasil`
//! crate's `Drive`, not this one.
//!
//! The drive extension (ext-drive.md): a tree of folders and named entries
//! in one Loro document, which every application of a space reads and
//! writes alike.
//!
//! - [`values`]: the forms of section 2.1.
//! - [`Tree`]: a drive as a reader reads it (section 3.2), and what it
//!   shows (section 3.3): listings under shown names, the trash, and each
//!   stream's entry.
//! - [`write`]: each change of section 3.4 with its checks, as Loro
//!   operations on a document. A caller commits them as one unit.
//!
//! No I/O: the caller holds the document and carries its bytes. Its
//! vectors are `docs/spec/vectors/ext-drive.json`.

mod error;
mod read;
pub mod values;
pub mod write;

pub use error::Error;
pub use read::{Entry, Kind, Shown, Tree, Version, numbered, shown_names};

/// The drive's kind, in its `document` map.
pub const KIND: &str = "frasil:drive";
/// The root map that names the document's kind.
pub const DOCUMENT: &str = "document";
/// The root tree of entries.
pub const ENTRIES: &str = "entries";
/// The root map of purged streams.
pub const PURGED: &str = "purged";
/// The entry kinds this document defines.
pub const FOLDER: &str = "folder";
/// A file: a blob of a Blobs stream.
pub const FILE: &str = "file";
/// A document: a stream of the space.
pub const DOCUMENT_KIND: &str = "document";
