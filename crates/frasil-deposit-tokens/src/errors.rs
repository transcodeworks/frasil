//! The error classes ext-deposit-tokens.md uses (ext-deposit-tokens.md, 2.8
//! Error classes).
//!
//! The document defines five classes. It also uses ext-libraries.md's ticket
//! classes as `check_ticket` raises them, and `NoLibrary`, and
//! transport.md's `Busy`, `BadProof`, `PurposeViolation` and
//! `CredentialRefused`, so [`TokenClass`] carries them too. Each is of sort
//! decision but `KeyInconsistent`, a report. `Malformed`, `TooLarge`,
//! `UnsupportedVersion` and `InvalidKey` are overview.md's shared classes.

use frasil_base::ErrorClass;
use frasil_base::errors::Class;
use frasil_libraries::LibraryClass;

frasil_base::error_classes! {
    /// The classes ext-deposit-tokens.md uses, and every shared class.
    pub enum TokenClass {
        /// A token whose authenticator does not verify.
        TokenRefused = "token_refused", Decision;
        /// A token under a key that is not live at this peer, or a request
        /// under a key that is not its issuing key.
        TokenExpired = "token_expired", Decision;
        /// A token another deposit already spent.
        TokenSpent = "token_spent", Decision;
        /// The library has drawn its whole allowance in its current window,
        /// or, for a space draw, the space its whole share.
        AllowanceExhausted = "allowance_exhausted", Decision;
        /// At a device: a peer whose key lists contradict one another
        /// (ext-deposit-tokens.md, 3.2 Learning a peer's keys). It never
        /// travels.
        KeyInconsistent = "key_inconsistent", Report;
        /// ext-libraries.md's: an untrusted issuer, a signature that does
        /// not verify, another purpose, or more blinded elements than the
        /// grant names.
        TicketRefused = "ticket_refused", Decision;
        /// ext-libraries.md's: `check_expiry` refuses the grant.
        TicketExpired = "ticket_expired", Decision;
        /// ext-libraries.md's: a grant ID already used at this peer.
        TicketUsed = "ticket_used", Decision;
        /// ext-libraries.md's: the space is attached to no library.
        NoLibrary = "no_library", Decision;
        /// ext-libraries.md's: the library is suspended.
        LibraryClosed = "library_closed", Decision;
        /// transport.md's: the token budget has no room.
        Busy = "busy", Decision;
        /// transport.md's: at a device, a `TokenIssue` whose proof does not
        /// hold. It never travels.
        BadProof = "bad_proof", Decision;
        /// transport.md's: a message on a connection whose purpose forbids
        /// it.
        PurposeViolation = "purpose_violation", Decision;
        /// transport.md's: a space draw without the store right.
        CredentialRefused = "credential_refused", Decision;
    }
}

impl TokenClass {
    /// The reason code a peer answers with, or `None` for a class that
    /// never travels: `KeyInconsistent`.
    pub fn code(self) -> Option<&'static str> {
        match self {
            Self::KeyInconsistent => None,
            _ => Some(self.wire_name()),
        }
    }

    /// The HTTP status of a refusal with this class on the server binding
    /// (ext-deposit-tokens.md, 2.8 Error classes, and the documents it takes
    /// classes from), or `None` for a class that is not answered over HTTP.
    pub fn status(self) -> Option<u16> {
        Some(match self {
            Self::Shared(ErrorClass::Malformed | ErrorClass::UnsupportedVersion) => 400,
            Self::Shared(ErrorClass::TooLarge) => 413,
            Self::Shared(ErrorClass::InvalidKey) => 422,
            Self::Shared(_) | Self::BadProof | Self::KeyInconsistent => return None,
            Self::TokenRefused
            | Self::TokenExpired
            | Self::TicketRefused
            | Self::TicketExpired
            | Self::PurposeViolation
            | Self::CredentialRefused => 403,
            Self::TokenSpent | Self::TicketUsed => 409,
            Self::AllowanceExhausted => 429,
            Self::Busy => 503,
            Self::NoLibrary | Self::LibraryClosed => 507,
        })
    }
}

impl From<LibraryClass> for TokenClass {
    /// `check_ticket`'s classes, as ext-deposit-tokens.md raises them at
    /// section 3.4, step 3. `check_ticket` raises no class this document
    /// does not name; the attaching classes it cannot raise become
    /// `TicketRefused`.
    fn from(class: LibraryClass) -> Self {
        match class {
            LibraryClass::Shared(shared) => Self::Shared(shared),
            LibraryClass::TicketExpired => Self::TicketExpired,
            LibraryClass::TicketUsed => Self::TicketUsed,
            LibraryClass::LibraryClosed => Self::LibraryClosed,
            LibraryClass::NoLibrary => Self::NoLibrary,
            _ => Self::TicketRefused,
        }
    }
}

pub(crate) fn malformed() -> TokenClass {
    ErrorClass::Malformed.into()
}
