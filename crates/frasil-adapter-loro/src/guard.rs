//! Calls into the pinned Loro on bytes that other writers wrote.
//!
//! A blob that makes the pinned Loro panic is one it does not read
//! (adapter-loro.md, 3.2 The checks, step 4), and a snapshot state that
//! does is one that does not decode (units.md, 3.17 The adapter interface,
//! `load`). Each call here runs Loro so that such a panic is refused like
//! any other unreadable input, and never reaches the replica.
//!
//! Catching a panic needs unwinding. Where panics abort, as on
//! `wasm32-unknown-unknown` or in an application built with
//! `panic = "abort"`, the screen of updates blobs ([`crate::screen`]) keeps
//! the decoder's known panics out of reach instead; a panic it does not
//! foresee still aborts there. The screen reads a snapshot state's `main`
//! as far as its tables, its change store, its container states' headers
//! and values, and the rows of their columnar tables (adapter-loro.md, 3.5,
//! "Loading a state"); a container state that does not decode makes Loro
//! panic when it is first read or changed, which
//! [`State::load`](crate::State::load) does inside a catch for every value
//! and every state of the state store.
//!
//! A panic inside `LoroDoc::import` poisons a lock of the document, and
//! dropping the document then panics again: dropped while the first panic
//! unwinds, it aborts the process. So a document is never created inside a
//! caught call that imports into it. [`import`] imports into a document its
//! caller holds, and a document Loro panicked on is [`discard`]ed, never
//! dropped.

use loro::LoroDoc;
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Runs `call`, or `None` when it panics.
///
/// Whatever `call` touched may be part-way changed after a panic.
pub(crate) fn caught<T>(call: impl FnOnce() -> T) -> Option<T> {
    catch_unwind(AssertUnwindSafe(call)).ok()
}

/// What importing a blob into a document did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Import {
    /// Loro imported it.
    Imported,
    /// Loro refused it, and the document is as it was.
    Refused,
    /// Loro panicked: the document may be part-way changed, and its locks
    /// poisoned. The caller [`discard`]s it.
    Panicked,
}

/// `LoroDoc::import(blob)`, with a panic caught.
pub(crate) fn import(doc: &LoroDoc, blob: &[u8]) -> Import {
    match caught(|| doc.import(blob)) {
        Some(Ok(_)) => Import::Imported,
        Some(Err(_)) => Import::Refused,
        None => Import::Panicked,
    }
}

/// Lets go of a document Loro panicked on without dropping it: its drop
/// would panic on a poisoned lock. Its memory is not freed.
pub(crate) fn discard(doc: LoroDoc) {
    std::mem::forget(doc);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crafted, screen};

    #[test]
    fn a_panic_inside_loro_is_caught() {
        for (name, blob) in crafted::all(7) {
            assert!(!screen::updates(&blob), "{name}");
        }
        // Unscreened, the pinned decoder panics on this blob.
        let blob = crafted::too_many_dependencies(7);
        assert!(caught(|| LoroDoc::decode_import_blob_meta(&blob, true)).is_none());
        let doc = LoroDoc::new();
        assert_eq!(import(&doc, b"stand-in for Loro's bytes"), Import::Refused);
        assert_eq!(import(&doc, &blob), Import::Panicked);
        discard(doc);
    }
}
