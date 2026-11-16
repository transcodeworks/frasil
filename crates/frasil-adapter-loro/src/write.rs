//! What a writer does (adapter-loro.md, section 3.1, "Writing"), and
//! re-applying a late write (section 3.6).
//!
//! - An **edit incarnation** begins at an edit whose incarnation is its own
//!   `seq`, and continues in the writer's later edits of the stream with
//!   the same incarnation and counters that follow on.
//! - A device that may have lost its own operations in the stream begins a
//!   new incarnation, and never continues one it may have lost.
//! - A suggestion's incarnation is its own `seq`, so each suggestion has a
//!   peer of its own and can be accepted alone.
//! - A writer sets the document's peer ID to its current incarnation's peer
//!   before it commits operations.
//! - A writer runs step 4 of the checks (section 3.2) on each blob before it
//!   signs the unit. Operations that break its limits are written in more
//!   than one unit, one after another, each ending where one of Loro's
//!   changes ends and passing step 4 ([`export_unit`], [`Writer::edits`]);
//!   Loro stores a large commit as several changes of a few kilobytes. A
//!   change that alone breaks them, or a suggestion that does, is not
//!   written ([`WriteError::OverLimit`]).

use crate::checks::Written;
use crate::content::Content;
use crate::guard::{self, Import};
use crate::meta::{Counter, Span};
use crate::peer::{Incarnation, PeerId};
use crate::screen;
use core::fmt;
use loro::{ExportMode, Frontiers, ID, IdSpan, LoroDoc, LoroEncodeError, LoroError};

/// Why a writer does not write its operations.
#[derive(Debug)]
pub enum WriteError {
    /// Loro did not export them.
    Encode(LoroEncodeError),
    /// The operations of `span` of `peer` break a limit of step 4 of the
    /// checks (adapter-loro.md, section 3.2) and cannot be split where one
    /// of Loro's changes ends: at most 2^20 operations, tree positions and
    /// deletion starts each, tree positions of at most 2^24 bytes in all,
    /// and a style's start and end in one unit. Every replica would refuse
    /// a unit that carries them. The application commits them in smaller
    /// steps; Loro merges consecutive commits of a peer into one change
    /// unless `LoroDoc::set_change_merge_interval` keeps them apart.
    OverLimit {
        /// The peer.
        peer: PeerId,
        /// The counters that cannot be written.
        span: Span,
    },
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(error) => write!(f, "Loro did not export the operations: {error}"),
            Self::OverLimit { peer, span } => write!(
                f,
                "the operations {}..{} of peer {peer:#x} break a limit of adapter-loro.md \
                 section 3.2, step 4 (2^20 operations, tree positions or deletion starts, \
                 2^24 bytes of tree positions, or a style split from its end) and cannot be \
                 split at a change; commit them in smaller steps",
                span.start, span.end
            ),
        }
    }
}

impl std::error::Error for WriteError {}

impl From<LoroEncodeError> for WriteError {
    fn from(error: LoroEncodeError) -> Self {
        Self::Encode(error)
    }
}

/// The operations of `peer` from counter `from` on that one unit carries
/// (adapter-loro.md, section 3.1): all of them to the document's end when
/// their blob passes step 4 of the checks, else as many as end where one
/// of Loro's changes ends and pass it, with their span. The rest is left
/// for the next unit. `None` when there are none.
///
/// # Errors
///
/// [`WriteError::OverLimit`] when the first change from `from` alone does
/// not pass step 4; [`WriteError::Encode`] when Loro does not export.
pub fn export_unit(
    doc: &LoroDoc,
    peer: PeerId,
    from: Counter,
) -> Result<Option<(Vec<u8>, Span)>, WriteError> {
    export_unit_with(doc, peer, from, screen::updates)
}

/// The blobs, with their spans, of every operation of `peer` from `from`
/// on, as [`export_unit`] divides them into units, in order.
///
/// # Errors
///
/// As [`export_unit`]: nothing is returned when any change fails.
pub fn export_units(
    doc: &LoroDoc,
    peer: PeerId,
    from: Counter,
) -> Result<Vec<(Vec<u8>, Span)>, WriteError> {
    let mut units = Vec::new();
    let mut from = from;
    while let Some((blob, span)) = export_unit(doc, peer, from)? {
        from = span.end;
        units.push((blob, span));
    }
    Ok(units)
}

/// [`export_unit`], with `passes` for step 4.
fn export_unit_with(
    doc: &LoroDoc,
    peer: PeerId,
    from: Counter,
    passes: impl Fn(&[u8]) -> bool,
) -> Result<Option<(Vec<u8>, Span)>, WriteError> {
    let Some((blob, span)) = export_since(doc, peer, from)? else {
        return Ok(None);
    };
    if passes(&blob) {
        return Ok(Some((blob, span)));
    }
    // The ends of the changes from `from` on, before the document's end.
    let mut ends = Vec::new();
    let mut at = from;
    while at < span.end {
        let end = doc
            .get_change(ID::new(peer, at))
            .map_or(span.end, |change| {
                change.id.counter.saturating_add(change.len as Counter)
            })
            .clamp(at + 1, span.end);
        if end < span.end {
            ends.push(end);
        }
        at = end;
    }
    // The longest prefix that passes, by bisection: step 4's limits are
    // totals, so a prefix that breaks one is too long. Its layout rules
    // also refuse a prefix that ends between a style's start and end, which
    // a shorter or longer prefix may pass; where bisection finds none, the
    // ends are tried in turn.
    let export = |end: Counter| {
        doc.export(ExportMode::updates_in_range(vec![IdSpan::new(
            peer, from, end,
        )]))
    };
    let (mut low, mut high) = (0, ends.len());
    let mut best = None;
    while low < high {
        let mid = low + (high - low) / 2;
        let blob = export(ends[mid])?;
        if passes(&blob) {
            best = Some((blob, Span::new(from, ends[mid])));
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if best.is_none() {
        for end in &ends {
            let blob = export(*end)?;
            if passes(&blob) {
                best = Some((blob, Span::new(from, *end)));
                break;
            }
        }
    }
    best.map(Some).ok_or(WriteError::OverLimit {
        peer,
        span: Span::new(from, ends.first().copied().unwrap_or(span.end)),
    })
}

/// Exports the operations of `peer` from counter `from` to the document's
/// end, `LoroDoc::export(ExportMode::UpdatesInRange { spans })`, with their
/// span; `None` when there are none.
pub fn export_since(
    doc: &LoroDoc,
    peer: PeerId,
    from: Counter,
) -> Result<Option<(Vec<u8>, Span)>, LoroEncodeError> {
    let end = doc.oplog_vv().get(&peer).copied().unwrap_or(0);
    if end <= from {
        return Ok(None);
    }
    let blob = doc.export(ExportMode::updates_in_range(vec![IdSpan::new(
        peer, from, end,
    )]))?;
    Ok(Some((blob, Span::new(from, end))))
}

/// A writer's incarnation over a document: it writes under the
/// incarnation's peer and exports each unit's new operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Writer {
    incarnation: Incarnation,
    next: Counter,
}

impl Writer {
    /// Begins or continues `incarnation` on `doc`: commits what is pending
    /// and sets the document's peer ID to the incarnation's peer. Its first
    /// unit takes the operations that follow those the document holds for
    /// that peer.
    pub fn new(doc: &LoroDoc, incarnation: Incarnation) -> Result<Self, LoroError> {
        doc.commit();
        let peer = incarnation.peer();
        doc.set_peer_id(peer)?;
        let next = doc.oplog_vv().get(&peer).copied().unwrap_or(0);
        Ok(Self { incarnation, next })
    }

    /// The incarnation.
    pub fn incarnation(&self) -> &Incarnation {
        &self.incarnation
    }

    /// Commits, and returns the operations written since the last unit as
    /// one edit's content, or `None` when there are none.
    ///
    /// # Errors
    ///
    /// [`WriteError::OverLimit`] when they do not pass step 4 of the checks
    /// as one unit: [`edits`](Self::edits) writes them in more than one.
    pub fn edit(&mut self, doc: &LoroDoc) -> Result<Option<Content>, WriteError> {
        Ok(self
            .take(doc)?
            .map(|blob| Content::edit(self.incarnation.incarnation, blob)))
    }

    /// Commits, and returns the operations written since the last unit as
    /// the contents of as many edits as step 4 of the checks needs, in
    /// order, each ending where one of Loro's changes ends; empty when there
    /// are none. The units continue the incarnation (section 3.1).
    ///
    /// # Errors
    ///
    /// [`WriteError::OverLimit`] when one change alone does not pass step
    /// 4; nothing is taken then.
    pub fn edits(&mut self, doc: &LoroDoc) -> Result<Vec<Content>, WriteError> {
        doc.commit();
        let units = export_units(doc, self.incarnation.peer(), self.next)?;
        if let Some((_, span)) = units.last() {
            self.next = span.end;
        }
        Ok(units
            .into_iter()
            .map(|(blob, _)| Content::edit(self.incarnation.incarnation, blob))
            .collect())
    }

    /// Commits, and returns the operations written since the last unit as
    /// a suggestion's content, or `None` when there are none. The writer's
    /// incarnation is the suggestion's own `seq`, and `doc` is a fork of the
    /// main document.
    ///
    /// # Errors
    ///
    /// [`WriteError::OverLimit`] when they do not pass step 4 of the checks
    /// as one unit: a suggestion is one unit, under a peer of its own.
    pub fn suggestion(&mut self, doc: &LoroDoc) -> Result<Option<Content>, WriteError> {
        Ok(self
            .take(doc)?
            .map(|blob| Content::suggestion(self.incarnation.incarnation, blob)))
    }

    /// The operations since the last unit, as one blob that passes step 4.
    fn take(&mut self, doc: &LoroDoc) -> Result<Option<Vec<u8>>, WriteError> {
        doc.commit();
        let peer = self.incarnation.peer();
        let Some((blob, span)) = export_since(doc, peer, self.next)? else {
            return Ok(None);
        };
        if !screen::updates(&blob) {
            return Err(WriteError::OverLimit { peer, span });
        }
        self.next = span.end;
        Ok(Some(blob))
    }
}

/// Re-applies a late write (section 3.6): imports it into a fork of the
/// original document, takes `LoroDoc::diff` of the fork against the
/// original at the late write's dependencies, and applies it
/// (`apply_diff`) to a fork of the moved document under the re-applier's
/// own peer. The result is the re-applier's own edit, or `None` when the
/// late write cannot be placed in the original or changes nothing.
pub fn reapply(
    original: &LoroDoc,
    late: &Written,
    moved: &LoroDoc,
    writer: &Incarnation,
) -> Result<Option<Content>, LoroError> {
    let fork = original.fork();
    match guard::import(&fork, &late.blob) {
        Import::Imported => {}
        Import::Refused => return Ok(None),
        Import::Panicked => {
            guard::discard(fork);
            return Ok(None);
        }
    }
    let placed = fork.oplog_vv().get(&late.peer).copied().unwrap_or(0) >= late.span.end;
    if !placed {
        return Ok(None);
    }
    let before = Frontiers::from(late.deps.clone());
    let after = Frontiers::from_id(ID::new(late.peer, late.span.end - 1));
    let diff = fork.diff(&before, &after)?;
    let target = moved.fork();
    let mut writer = Writer::new(&target, *writer)?;
    target.apply_diff(diff)?;
    writer
        .edit(&target)
        .map_err(|error| LoroError::DecodeError(error.to_string().into_boxed_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::BlobMeta;

    const PEER: PeerId = 7;

    /// A document of `PEER` with `n` changes of one character each.
    fn changes(n: usize) -> LoroDoc {
        let doc = LoroDoc::new();
        doc.set_peer_id(PEER).unwrap();
        let text = doc.get_text("t");
        for i in 0..n {
            text.insert(i, "x").unwrap();
            // Its own message keeps each commit a change of its own.
            doc.set_next_commit_message(&format!("{i}"));
            doc.commit();
        }
        doc
    }

    /// Whether `blob` passes step 4 and holds at most `most` counters.
    fn at_most(most: Counter) -> impl Fn(&[u8]) -> bool {
        move |blob: &[u8]| {
            BlobMeta::read(blob).is_some_and(|meta| {
                meta.spans
                    .values()
                    .all(|span| span.end - span.start <= most)
            })
        }
    }

    #[test]
    fn a_unit_takes_the_most_changes_that_pass_and_the_next_one_the_rest() {
        let doc = changes(10);
        let mut from = 0;
        let mut spans = Vec::new();
        while let Some((blob, span)) = export_unit_with(&doc, PEER, from, at_most(3)).unwrap() {
            assert!(at_most(3)(&blob));
            spans.push((span.start, span.end));
            from = span.end;
        }
        assert_eq!(spans, [(0, 3), (3, 6), (6, 9), (9, 10)]);
        // All of them, when they pass together.
        let (_, span) = export_unit(&doc, PEER, 0).unwrap().unwrap();
        assert_eq!(span, Span::new(0, 10));
        assert_eq!(export_unit(&doc, PEER, 10).unwrap(), None);
    }

    #[test]
    fn a_change_that_alone_breaks_a_limit_is_not_written() {
        let doc = changes(4);
        let error = export_unit_with(&doc, PEER, 1, |_| false).unwrap_err();
        assert!(matches!(
            error,
            WriteError::OverLimit { peer: PEER, span } if span == Span::new(1, 2)
        ));
    }
}
