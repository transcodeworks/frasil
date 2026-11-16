//! What the checks read of a blob: its metadata (adapter-loro.md, section
//! 3.2, "The checks", steps 4 to 6).
//!
//! The checks read only the metadata `LoroDoc::decode_import_blob_meta`
//! returns, with the checksum checked: the blob's mode and its start and
//! end version vectors. A peer is **advanced** when its end counter exceeds
//! its start counter; its span is `[start, end)`.
//!
//! Only an updates blob that the screen of step 4 passes reaches it: one
//! the decoder reads without failing, panicking or reserving memory out of
//! proportion to the blob, within the limits of section 3.2. A panic inside
//! it is caught where panics unwind. A blob refused either way is
//! `LoroMalformed`.

use crate::peer::PeerId;
use crate::{guard, screen};
use loro::{EncodedBlobMode, ImportBlobMetadata, LoroDoc};
use std::collections::BTreeMap;

/// An operation counter of one peer (Loro's `Counter`).
pub type Counter = loro::Counter;

/// An operation's ID: its peer and counter.
pub type OpId = loro::ID;

/// The counters `[start, end)` a blob holds for one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Span {
    /// The first counter.
    pub start: Counter,
    /// One past the last counter.
    pub end: Counter,
}

impl Span {
    /// The span `[start, end)`.
    pub fn new(start: Counter, end: Counter) -> Self {
        Self { start, end }
    }

    /// Whether the span holds at least one counter.
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// Whether two spans share a counter.
    pub fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Whether the span holds this counter.
    pub fn contains(&self, counter: Counter) -> bool {
        self.start <= counter && counter < self.end
    }
}

/// A blob's mode, as the checks distinguish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlobMode {
    /// Updates: the only mode a unit's blob may have.
    Updates,
    /// A snapshot, with its history or shallow.
    Snapshot,
}

/// A blob's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMeta {
    /// The blob's mode.
    pub mode: BlobMode,
    /// The span of each peer the blob advances.
    pub spans: BTreeMap<PeerId, Span>,
    /// The operations outside the blob that its operations depend on, when
    /// known: what a replica reads to tell an operation that waits on a
    /// refused unit (adapter-loro.md, section 3.3).
    pub deps: Vec<OpId>,
}

impl BlobMeta {
    /// Metadata of an updates blob with these spans and no known
    /// dependencies.
    pub fn updates(spans: impl IntoIterator<Item = (PeerId, Span)>) -> Self {
        Self {
            mode: BlobMode::Updates,
            spans: spans.into_iter().collect(),
            deps: Vec::new(),
        }
    }

    /// Metadata of a snapshot blob.
    pub fn snapshot() -> Self {
        Self {
            mode: BlobMode::Snapshot,
            spans: BTreeMap::new(),
            deps: Vec::new(),
        }
    }

    /// `decode_import_blob_meta(blob)` with the checksum checked, or `None`
    /// when step 4 refuses the blob: the pinned Loro does not read it, or it
    /// breaks a limit of section 3.2. A blob of another mode than updates,
    /// which step 4 refuses whatever it holds, is not decoded and is `None`
    /// too.
    pub fn read(blob: &[u8]) -> Option<Self> {
        let meta = import_blob_meta(blob)?;
        let mode = match meta.mode {
            EncodedBlobMode::Updates => BlobMode::Updates,
            _ => return None,
        };
        let mut spans = BTreeMap::new();
        for (peer, end) in meta.partial_end_vv.iter() {
            let start = meta.partial_start_vv.get(peer).copied().unwrap_or(0);
            let span = Span::new(start, *end);
            if !span.is_empty() {
                spans.insert(*peer, span);
            }
        }
        let mut deps: Vec<OpId> = meta.start_frontiers.iter().collect();
        deps.sort();
        deps.dedup();
        Some(Self { mode, spans, deps })
    }

    /// Whether the blob is an updates blob, not a snapshot.
    pub fn is_updates(&self) -> bool {
        self.mode == BlobMode::Updates
    }
}

/// `LoroDoc::decode_import_blob_meta(blob)` on an updates blob, with the
/// checksum checked, or `None` when step 4 refuses it: when the blob is not
/// an updates blob, the screen refuses it, Loro returns an error, or Loro
/// panics.
pub fn import_blob_meta(blob: &[u8]) -> Option<ImportBlobMetadata> {
    if !screen::updates(blob) {
        return None;
    }
    guard::caught(|| LoroDoc::decode_import_blob_meta(blob, true).ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use loro::{ExportMode, IdSpan};

    #[test]
    fn spans_are_half_open() {
        let a = Span::new(0, 10);
        assert!(a.overlaps(&Span::new(9, 12)));
        assert!(!a.overlaps(&Span::new(10, 12)));
        assert!(a.contains(9) && !a.contains(10));
        assert!(Span::new(3, 3).is_empty());
    }

    #[test]
    fn reads_an_export_of_one_peers_range() {
        let doc = LoroDoc::new();
        doc.set_peer_id(7).unwrap();
        doc.get_text("t").insert(0, "hello").unwrap();
        doc.commit();
        doc.get_text("t").insert(5, " world").unwrap();
        doc.commit();
        let blob = doc
            .export(ExportMode::updates_in_range(vec![IdSpan::new(7, 5, 11)]))
            .unwrap();
        let meta = BlobMeta::read(&blob).unwrap();
        assert!(meta.is_updates());
        assert_eq!(meta.spans, BTreeMap::from([(7, Span::new(5, 11))]));
        assert_eq!(meta.deps, vec![OpId::new(7, 4)]);

        let snapshot = doc.export(ExportMode::Snapshot).unwrap();
        assert_eq!(BlobMeta::read(&snapshot), None);
        let mut corrupt = blob.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(BlobMeta::read(&corrupt), None);
        assert_eq!(BlobMeta::read(b"stand-in for Loro's export bytes"), None);
        assert_eq!(BlobMeta::read(&[]), None);
    }
}
