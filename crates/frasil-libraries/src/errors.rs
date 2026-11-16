//! The error classes ext-libraries.md uses (ext-libraries.md, 2.6 Error
//! classes).
//!
//! The document defines seven classes. It also writes peers.md's class
//! `NotAuthorized` and its refusal codes `quota_exceeded`, `no_library`,
//! `library_closed` and `erased` as classes, so [`LibraryClass`] carries
//! them too. All are of sort decision. `Malformed` is overview.md's shared
//! class.

use frasil_base::ErrorClass;
use frasil_base::errors::Class;

frasil_base::error_classes! {
    /// The classes ext-libraries.md uses, and every shared class.
    pub enum LibraryClass {
        /// An untrusted issuer, a signature that does not verify, or another
        /// purpose.
        TicketRefused = "ticket_refused", Decision;
        /// `check_expiry` refuses the ticket.
        TicketExpired = "ticket_expired", Decision;
        /// A ticket ID that already attached a space at this peer.
        TicketUsed = "ticket_used", Decision;
        /// A create or an import of a space this peer hosts.
        SpaceExists = "space_exists", Decision;
        /// A hold whose proof does not verify, or whose access key nothing
        /// vouches for.
        HoldRefused = "hold_refused", Decision;
        /// A hold of an object the source does not hold whole at this peer.
        UnknownObject = "unknown_object", Decision;
        /// A hold whose space and source are billed to different libraries.
        OtherLibrary = "other_library", Decision;
        /// peers.md's `NotAuthorized`: the connection lacks the right the
        /// request needs, such as the store right for a move.
        NotAuthorized = "not_authorized", Decision;
        /// peers.md's `quota_exceeded`: the library's quota or headroom does
        /// not hold the bytes.
        QuotaExceeded = "quota_exceeded", Decision;
        /// peers.md's `no_library`: the space is attached to no library.
        NoLibrary = "no_library", Decision;
        /// peers.md's `library_closed`: the library is suspended.
        LibraryClosed = "library_closed", Decision;
        /// peers.md's `erased`: the space was erased, or its data deleted,
        /// at this peer.
        Erased = "erased", Decision;
    }
}

impl LibraryClass {
    /// The refusal code a peer answers with: the class's wire name, such as
    /// `ticket_refused`.
    pub fn code(self) -> &'static str {
        self.wire_name()
    }

    /// The HTTP status of a refusal with this class (ext-libraries.md, 2.6
    /// Error classes, and peers.md's refusal codes), or `None` for a shared
    /// class other than `Malformed`, which this document never raises.
    pub fn status(self) -> Option<u16> {
        Some(match self {
            Self::Shared(ErrorClass::Malformed) => 400,
            Self::Shared(_) => return None,
            Self::NotAuthorized | Self::TicketRefused | Self::TicketExpired | Self::HoldRefused => {
                403
            }
            Self::UnknownObject => 404,
            Self::TicketUsed | Self::SpaceExists | Self::OtherLibrary => 409,
            Self::Erased => 410,
            Self::QuotaExceeded | Self::NoLibrary | Self::LibraryClosed => 507,
        })
    }
}
