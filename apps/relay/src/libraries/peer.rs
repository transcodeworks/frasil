//! What the operator and the issuer read and set at the peer
//! (ext-libraries.md, 3.5 Detaching, suspending and deleting, and 3.6 Usage
//! and refusals): ledgers, library settings, attachments, detaching and
//! deleting. Per-author usage never leaves through these.

use super::{Attachment, Ledger, LibraryUpdate};
use crate::state::lock;
use crate::{Peer, PeerError};
use frasil_events::EventId;
use frasil_libraries::{LibraryId, TicketId};

impl Peer {
    /// Records the operator's default library with section 2.4's
    /// defaults, if the peer trusts its operator's own issuer and does not
    /// know the library yet: at the first start, once. Returns its ID.
    /// Blocking.
    ///
    /// # Errors
    ///
    /// If the record cannot be written.
    pub fn ensure_default_library(&self) -> Result<Option<LibraryId>, PeerError> {
        let settings = &self.shared.settings;
        if !settings.extensions.libraries {
            return Ok(None);
        }
        let Some(library) = settings.libraries.default_library() else {
            return Ok(None);
        };
        let core = &self.shared.core;
        let mut libraries = lock(&core.libraries);
        if libraries.library(&library).is_none() {
            let record = libraries
                .update(&library, LibraryUpdate::default())
                .map_err(|class| PeerError(format!("the default library: {class:?}")))?;
            core.commit_libraries_blocking(&mut libraries, vec![record], Vec::new())?;
        }
        Ok(Some(library))
    }

    /// A space's attachment: its library, the ticket ID that attached it,
    /// and the peer's reading when it took effect.
    pub fn library_attachment(&self, space: &[u8; 32]) -> Option<Attachment> {
        lock(&self.shared.core.libraries)
            .attachment(&EventId(*space))
            .cloned()
    }

    /// The ticket IDs that attached a space at this peer and are still
    /// kept, in order.
    pub fn library_tickets_used(&self) -> Vec<TicketId> {
        lock(&self.shared.core.libraries)
            .tickets_used()
            .keys()
            .copied()
            .collect()
    }

    /// A library's ledger, as the issuer reads it; `None` for a library the
    /// peer does not know.
    pub fn ledger(&self, library: &LibraryId) -> Option<Ledger> {
        self.shared.core.ledger_blocking(library)
    }

    /// Every library's ledger, by library ID.
    pub fn ledgers(&self) -> Vec<Ledger> {
        let libraries: Vec<LibraryId> = lock(&self.shared.core.libraries)
            .libraries()
            .cloned()
            .collect();
        libraries
            .iter()
            .filter_map(|library| self.ledger(library))
            .collect()
    }

    /// Sets a library's quota, `erasure_timeout` or state, as the operator,
    /// or the issuer for its libraries; the last write stands. A library
    /// the peer does not yet know is created.
    ///
    /// # Errors
    ///
    /// An `erasure_timeout` outside 1 hour to 90 days, or a record that
    /// cannot be written.
    pub fn set_library(&self, library: &LibraryId, update: LibraryUpdate) -> Result<(), PeerError> {
        let core = &self.shared.core;
        let mut libraries = lock(&core.libraries);
        let record = libraries
            .update(library, update)
            .map_err(|class| PeerError(format!("the library's settings: {class:?}")))?;
        core.commit_libraries_blocking(&mut libraries, vec![record], Vec::new())?;
        Ok(())
    }

    /// Detaches a space from its library: the library stops paying for it,
    /// and the space accepts no store (`no_library`) until a writer moves
    /// it. Returns whether the space was attached.
    ///
    /// # Errors
    ///
    /// If the record cannot be written.
    pub fn detach(&self, space: &[u8; 32]) -> Result<bool, PeerError> {
        let now = self.shared.clock.now();
        let core = &self.shared.core;
        let mut libraries = lock(&core.libraries);
        let Some((record, delete)) = libraries.detach(&EventId(*space), now) else {
            return Ok(false);
        };
        core.commit_libraries_blocking(&mut libraries, vec![record], vec![delete])?;
        Ok(true)
    }

    /// The detached spaces whose `detached_grace` has passed: the operator
    /// MAY delete their data.
    pub fn detached_past_grace(&self) -> Vec<[u8; 32]> {
        let now = self.shared.clock.now();
        lock(&self.shared.core.libraries)
            .past_grace(&now)
            .iter()
            .map(|space| *space.as_bytes())
            .collect()
    }

    /// Deletes a space's events and objects at this peer, as the operator,
    /// and keeps its ID: a later create of it is `erased`, and an import
    /// is allowed. It is not an erasure: it needs no administrator, waits
    /// for no stability, and leaves replicas and other peers their copies.
    /// Returns whether the peer hosted the space.
    ///
    /// # Errors
    ///
    /// If the records cannot be written.
    pub async fn delete_space(&self, space: &[u8; 32]) -> Result<bool, PeerError> {
        let pieces = self.shared.core.delete_space(EventId(*space)).await?;
        let Some(pieces) = pieces else {
            return Ok(false);
        };
        for key in pieces {
            if let Err(error) = self.shared.blobs.delete(&key).await {
                crate::util::log(format_args!("an object piece was not deleted: {error}"));
            }
        }
        Ok(true)
    }

    /// Deletes a library at this peer: each of its spaces' data, as
    /// [`delete_space`](Self::delete_space), then the library. Returns
    /// whether the peer knew it.
    ///
    /// # Errors
    ///
    /// If the records cannot be written.
    pub async fn delete_library(&self, library: &LibraryId) -> Result<bool, PeerError> {
        let spaces: Vec<EventId> = {
            let libraries = lock(&self.shared.core.libraries);
            if libraries.library(library).is_none() {
                return Ok(false);
            }
            libraries.members(library).copied().collect()
        };
        for space in spaces {
            self.delete_space(space.as_bytes()).await?;
        }
        let core = &self.shared.core;
        let pending = {
            let mut libraries = lock(&core.libraries);
            libraries
                .forget(library)
                .map(|deletes| core.submit_libraries(Vec::new(), deletes))
        };
        if let Some(pending) = pending {
            core.finish_libraries(pending).await?;
        }
        Ok(true)
    }
}
