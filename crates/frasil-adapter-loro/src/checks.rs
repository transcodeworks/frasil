//! The checks (adapter-loro.md, section 3.2, "The checks"), in order, on a
//! unit of type `frasil:loro`, after units.md's checks:
//!
//! ```text
//! 1. The content is deterministic CBOR, a map with an
//!    unsigned key 1, or is empty in a snapshot unit.       else Malformed
//!    Key 1 is 1.                                           else UnknownContentVersion
//!    The keys of its role, as section 2.2.                 else Malformed
//! 2. The suggest check (section 3.4) and any registered
//!    capability checks.                                    else CapabilityRefused
//! 3. Roles 0 and 1: incarnation <= the unit's seq; a
//!    suggestion's equals it.                               else LoroIncarnation
//! 4. Roles 0 and 1: decode_import_blob_meta(blob), with the
//!    checksum checked, reads the blob, and its mode is
//!    updates, not a snapshot.                              else LoroMalformed
//! 5. Roles 0 and 1: the blob advances exactly one peer,
//!    peer(space, stream, author, incarnation).             else LoroForeignPeer
//! 6. Roles 0 and 1: its counter span for that peer
//!    overlaps no span of the same peer in a Loro unit
//!    earlier in canonical order, but the units it
//!    re-submits with the same content, and starts at or
//!    above the counter the base snapshot holds for it.     else LoroOverlap
//! 7. Roles 2 and 3: every target is held, as a unit or in
//!    the base snapshot's key 3 or 4.                       else TargetNotHeld
//! ```
//!
//! Steps 1 to 5 read only the unit: [`check_content`], which the adapter's
//! `decode` runs. Steps 6 and 7 read the other units of the stream:
//! [`check_overlap`] and [`check_targets`], which the stream's state runs.
//! [`check`] runs all seven on inputs given explicitly, as the vectors give
//! them.

use crate::LoroClass;
use crate::content::{Content, ContentRole};
use crate::meta::{BlobMeta, Counter, OpId, Span};
use crate::peer::{PeerId, peer};
use frasil_adapter::{CapabilityChecks, Context, EventId, Role, suggest_check_snapshot};
use frasil_base::errors::ErrorClass;
use std::collections::BTreeMap;

/// The operations of an edit or a suggestion, as steps 3 to 5 found them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Written {
    /// Key 3: the incarnation.
    pub incarnation: u64,
    /// Key 4: Loro's bytes.
    pub blob: Vec<u8>,
    /// The one peer the blob advances: `peer(space, stream, author,
    /// incarnation)`.
    pub peer: PeerId,
    /// Its counter span for that peer.
    pub span: Span,
    /// The operations outside the blob its operations depend on.
    pub deps: Vec<OpId>,
}

/// A unit's decoded content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Change {
    /// Role 0: an edit of the main document.
    Edit(Written),
    /// Role 1: a suggestion.
    Suggestion(Written),
    /// Role 2: an accept of these suggestions.
    Accept(Vec<EventId>),
    /// Role 3: a dismiss of these suggestions.
    Dismiss(Vec<EventId>),
    /// A snapshot unit, whose content is empty.
    Snapshot,
}

impl Change {
    /// The content it was read from: `None` for a snapshot unit, whose
    /// content is empty.
    pub fn content(&self) -> Option<Content> {
        Some(match self {
            Self::Edit(written) => Content::edit(written.incarnation, written.blob.clone()),
            Self::Suggestion(written) => {
                Content::suggestion(written.incarnation, written.blob.clone())
            }
            Self::Accept(targets) => Content::Targets {
                role: ContentRole::Accept,
                targets: targets.clone(),
            },
            Self::Dismiss(targets) => Content::Targets {
                role: ContentRole::Dismiss,
                targets: targets.clone(),
            },
            Self::Snapshot => return None,
        })
    }

    /// The content's one encoding: empty for a snapshot unit.
    pub fn encode(&self) -> Vec<u8> {
        self.content()
            .map(|content| content.encode())
            .unwrap_or_default()
    }
}

/// Steps 1 to 5, reading a blob's metadata with `meta_of`: `None` when the
/// pinned Loro does not read the blob.
pub fn check_content(
    content: &[u8],
    context: &Context,
    checks: &CapabilityChecks,
    meta_of: impl FnOnce(&[u8]) -> Option<BlobMeta>,
) -> Result<Change, LoroClass> {
    if context.role == Role::Snapshot {
        // Step 1: a snapshot unit's content is empty.
        if !content.is_empty() {
            return Err(ErrorClass::Malformed.into());
        }
        // Step 2: a suggester writes no snapshot unit, a seed included.
        suggest_check_snapshot(context)?;
        checks.run(context, content)?;
        return Ok(Change::Snapshot);
    }
    // Step 1.
    let read = Content::read(content)?;
    // Step 2: a suggester writes only role 1 (section 3.4, "The `suggest`
    // check"), then the registered capability checks.
    if context.capabilities.is_suggester() && read.role() != ContentRole::Suggestion {
        return Err(ErrorClass::CapabilityRefused.into());
    }
    checks.run(context, content)?;
    match read {
        Content::Targets { role, targets } => Ok(match role {
            ContentRole::Accept => Change::Accept(targets),
            _ => Change::Dismiss(targets),
        }),
        Content::Ops {
            role,
            incarnation,
            blob,
        } => {
            let written = check_ops(role, incarnation, blob, context, meta_of)?;
            Ok(if role == ContentRole::Suggestion {
                Change::Suggestion(written)
            } else {
                Change::Edit(written)
            })
        }
    }
}

/// Steps 3 to 5, on an edit's or a suggestion's incarnation and blob.
pub fn check_ops(
    role: ContentRole,
    incarnation: u64,
    blob: Vec<u8>,
    context: &Context,
    meta_of: impl FnOnce(&[u8]) -> Option<BlobMeta>,
) -> Result<Written, LoroClass> {
    // Step 3.
    let suggestion = role == ContentRole::Suggestion;
    if incarnation > context.seq || (suggestion && incarnation != context.seq) {
        return Err(LoroClass::LoroIncarnation);
    }
    // Step 4.
    let meta = meta_of(&blob).ok_or(LoroClass::LoroMalformed)?;
    if !meta.is_updates() {
        return Err(LoroClass::LoroMalformed);
    }
    // Step 5.
    let own = peer(
        &context.space,
        &context.stream,
        &context.author,
        incarnation,
    );
    let span = match meta.spans.iter().collect::<Vec<_>>().as_slice() {
        [(found, span)] if **found == own && !span.is_empty() => **span,
        _ => return Err(LoroClass::LoroForeignPeer),
    };
    Ok(Written {
        incarnation,
        blob,
        peer: own,
        span,
        deps: meta.deps,
    })
}

/// What step 6 counts of a placed unit: its peer and span, when its
/// content passes steps 1 and 3 to 5, whatever step 2 and the write rule
/// decide on it (section 3.2).
pub fn counted_span(content: &[u8], context: &Context) -> Option<(PeerId, Span)> {
    if context.role == Role::Snapshot {
        return None;
    }
    match Content::read(content).ok()? {
        Content::Ops {
            role,
            incarnation,
            blob,
        } => check_ops(role, incarnation, blob, context, BlobMeta::read)
            .ok()
            .map(|written| (written.peer, written.span)),
        Content::Targets { .. } => None,
    }
}

/// Step 6: the span overlaps no span of the same peer in a Loro unit
/// earlier in canonical order, and starts at or above the counter the base
/// snapshot holds for the peer.
pub fn check_overlap(
    peer: PeerId,
    span: Span,
    earlier: impl IntoIterator<Item = (PeerId, Span)>,
    base_counters: &BTreeMap<PeerId, Counter>,
) -> Result<(), LoroClass> {
    check_overlap_resubmitted(peer, span, earlier, &[], base_counters)
}

/// Step 6 on a re-submission (units.md, 3.11 "Re-submission"): as
/// [`check_overlap`], with `resubmitted`, the earlier spans of the units
/// this unit re-submits through its `resubmits` and theirs whose content is
/// byte for byte its own, not counted. Each span of `resubmitted` counts
/// out one equal span of `earlier`.
pub fn check_overlap_resubmitted(
    peer: PeerId,
    span: Span,
    earlier: impl IntoIterator<Item = (PeerId, Span)>,
    resubmitted: &[(PeerId, Span)],
    base_counters: &BTreeMap<PeerId, Counter>,
) -> Result<(), LoroClass> {
    let mut skip = resubmitted.to_vec();
    let overlaps = earlier.into_iter().any(|(other, earlier)| {
        if let Some(at) = skip.iter().position(|x| *x == (other, earlier)) {
            // A unit it re-submits: the same operations.
            skip.swap_remove(at);
            return false;
        }
        other == peer && earlier.overlaps(&span)
    });
    let below_base = base_counters
        .get(&peer)
        .is_some_and(|counter| span.start < *counter);
    if overlaps || below_base {
        Err(LoroClass::LoroOverlap)
    } else {
        Ok(())
    }
}

/// Step 7: every target is held, as a unit or in the base snapshot's key 3
/// or 4. A unit held here waits, and is checked again when a target
/// arrives.
pub fn check_targets(
    targets: &[EventId],
    held: impl Fn(&EventId) -> bool,
) -> Result<(), LoroClass> {
    if targets.iter().all(held) {
        Ok(())
    } else {
        Err(LoroClass::TargetNotHeld)
    }
}

/// The seven checks in order, on inputs given explicitly: the blob's
/// metadata (`None` when Loro does not read it), the spans of the stream's
/// Loro units earlier in canonical order, the counters the base snapshot
/// holds, and the suggestions held as units or in the base snapshot.
pub fn check(
    content: &[u8],
    context: &Context,
    checks: &CapabilityChecks,
    meta: Option<BlobMeta>,
    earlier: &[(PeerId, Span)],
    base_counters: &BTreeMap<PeerId, Counter>,
    held: impl Fn(&EventId) -> bool,
) -> Result<Change, LoroClass> {
    check_resubmitted(
        content,
        context,
        checks,
        meta,
        earlier,
        &[],
        base_counters,
        held,
    )
}

/// [`check`] on a re-submission: `resubmitted` are the spans among
/// `earlier` of the units it re-submits with the same content, which step 6
/// does not count ([`check_overlap_resubmitted`]).
#[allow(clippy::too_many_arguments)]
pub fn check_resubmitted(
    content: &[u8],
    context: &Context,
    checks: &CapabilityChecks,
    meta: Option<BlobMeta>,
    earlier: &[(PeerId, Span)],
    resubmitted: &[(PeerId, Span)],
    base_counters: &BTreeMap<PeerId, Counter>,
    held: impl Fn(&EventId) -> bool,
) -> Result<Change, LoroClass> {
    let change = check_content(content, context, checks, |_| meta)?;
    match &change {
        Change::Edit(written) | Change::Suggestion(written) => check_overlap_resubmitted(
            written.peer,
            written.span,
            earlier.iter().copied(),
            resubmitted,
            base_counters,
        )?,
        Change::Accept(targets) | Change::Dismiss(targets) => check_targets(targets, held)?,
        Change::Snapshot => {}
    }
    Ok(change)
}
