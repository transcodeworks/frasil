//! A peer's checks of a ticket (ext-libraries.md, 3.2 Checking a ticket).
//!
//! ```text
//! check_ticket(signed, purpose), in order:
//!   1. len(signed) <= 512; a CBOR array of two byte strings, the
//!      second of 64 bytes; the first a deterministic CBOR map of
//!      exactly keys 1 to 6, and 7 for purpose 4; version 1; a library
//!      ID by section 2.1; id of 16 bytes; purpose 1, 2 or 3, or 4
//!      where ext-deposit-tokens.md is implemented; not_after unsigned;
//!      issuer of 32 bytes; tokens, where present, 1 to 256.          else Malformed
//!   2. issuer is one this peer trusts.                               else TicketRefused
//!   3. The signature verifies strictly under issuer.                 else TicketRefused
//!   4. overview.md's check_expiry(not_after, the peer's wall clock,
//!      ticket_lifetime, ticket_skew) accepts.                        else TicketExpired
//!   5. id has not attached a space, or drawn deposit tokens, at
//!      this peer.                                                    else TicketUsed
//!   6. The ticket's purpose is the request's.                        else TicketRefused
//!   7. The library's state is open.                                  else LibraryClosed
//! ```
//!
//! The peer's state is the peer's: [`check_ticket`] reads the ticket IDs
//! used and the libraries' states through [`PeerRecords`].

use frasil_base::ErrorClass;
use frasil_base::time::check_expiry;
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::schemes::ed25519_verify_strict;
use frasil_crypto::sizes::ED25519_PUBLIC;

use crate::errors::LibraryClass;
use crate::settings::{LibraryState, MAX_ISSUERS, TICKET_LIFETIME, TICKET_SKEW};
use crate::ticket::{LibraryId, Purpose, SignedTicket, Ticket, TicketId};

/// The issuers a peer trusts (ext-libraries.md, 2.4 Settings): at most 16
/// Ed25519 keys, set by the operator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedIssuers {
    keys: Vec<[u8; ED25519_PUBLIC]>,
}

impl TrustedIssuers {
    /// The set of these keys. A key given twice counts once.
    ///
    /// # Errors
    ///
    /// `InvalidKey` for a key `ed25519_valid` refuses (crypto.md, "Ed25519
    /// public keys"), and `TooLarge` for more than 16 keys.
    pub fn new(keys: impl IntoIterator<Item = [u8; ED25519_PUBLIC]>) -> Result<Self, ErrorClass> {
        let mut set = Self::default();
        for key in keys {
            ed25519_valid(&key)?;
            if !set.keys.contains(&key) {
                if set.keys.len() == MAX_ISSUERS {
                    return Err(ErrorClass::TooLarge);
                }
                set.keys.push(key);
            }
        }
        Ok(set)
    }

    /// Whether the peer trusts this issuer.
    pub fn trusts(&self, issuer: &[u8; ED25519_PUBLIC]) -> bool {
        self.keys.contains(issuer)
    }

    /// The trusted keys, in the order first given.
    pub fn keys(&self) -> &[[u8; ED25519_PUBLIC]] {
        &self.keys
    }

    /// The number of trusted keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the peer trusts no issuer.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// What `check_ticket` reads of what a peer keeps (ext-libraries.md, 2.5
/// What a peer keeps, and 2.4 Settings).
pub trait PeerRecords {
    /// Whether a ticket of this ID has attached a space, or drawn deposit
    /// tokens, at this peer. The peer keeps each ID used until its
    /// `not_after` and `ticket_skew` have passed; after that, step 4
    /// refuses the ticket first.
    fn ticket_used(&self, id: &TicketId) -> bool;

    /// The state of a library, or `None` for a library the peer does not
    /// yet know, which is created open at its first ticket.
    fn library_state(&self, library: &LibraryId) -> Option<LibraryState>;

    /// Whether the peer implements ext-deposit-tokens.md, so that step 1
    /// reads a deposit grant (purpose 4, key 7). Without it, and in a
    /// build without the `ext-deposit-tokens` feature, both are
    /// `Malformed`, as at a core peer.
    fn deposit_tokens(&self) -> bool {
        false
    }
}

/// `check_ticket(signed, purpose)` (ext-libraries.md, 3.2 Checking a
/// ticket), in order. `now_wall` is the peer's wall clock in seconds since
/// 1970, or `None` when it is not known.
///
/// Returns the ticket's fields. The caller then records the attachment and
/// the ticket's ID with its `not_after` (ext-libraries.md, 3.3 Attaching),
/// and creates the library with section 2.4's defaults if it did not know
/// it.
///
/// # Errors
///
/// The class of the first step that refuses: `Malformed`, `TicketRefused`,
/// `TicketExpired`, `TicketUsed` or `LibraryClosed`.
pub fn check_ticket<R: PeerRecords + ?Sized>(
    signed: &[u8],
    purpose: Purpose,
    now_wall: Option<u64>,
    issuers: &TrustedIssuers,
    records: &R,
) -> Result<Ticket, LibraryClass> {
    // 1. The form.
    let read = SignedTicket::decode_with_grants(signed, records.deposit_tokens())?;
    let ticket = read.ticket;
    // 2. A trusted issuer. The trusted keys passed ed25519_valid where the
    // operator set them; the check again costs little.
    if !issuers.trusts(&ticket.issuer) || ed25519_valid(&ticket.issuer).is_err() {
        return Err(LibraryClass::TicketRefused);
    }
    // 3. Scheme 0, verified once, at once.
    if !ed25519_verify_strict(
        &ticket.issuer,
        &crate::ticket::signed_message(&read.ticket_bytes),
        &read.signature,
    ) {
        return Err(LibraryClass::TicketRefused);
    }
    // 4. check_expiry: an unknown wall clock, a not_after beyond the
    // lifetime and skew, and a past not_after are all TicketExpired.
    if check_expiry(ticket.not_after, now_wall, TICKET_LIFETIME, TICKET_SKEW).is_err() {
        return Err(LibraryClass::TicketExpired);
    }
    // 5. An ID not yet used here.
    if records.ticket_used(&ticket.id) {
        return Err(LibraryClass::TicketUsed);
    }
    // 6. The request's purpose.
    if ticket.purpose != purpose {
        return Err(LibraryClass::TicketRefused);
    }
    // 7. An open library, or one not yet known.
    if records.library_state(&ticket.library).unwrap_or_default() != LibraryState::Open {
        return Err(LibraryClass::LibraryClosed);
    }
    Ok(ticket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_crypto::primitives::ed25519_public;

    #[test]
    fn trusted_issuers_are_bounded_and_valid() {
        let keys: Vec<_> = (1..=17u8).map(|i| ed25519_public(&[i; 32])).collect();
        assert_eq!(
            TrustedIssuers::new(keys[..16].iter().copied())
                .unwrap()
                .len(),
            16
        );
        assert_eq!(
            TrustedIssuers::new(keys.iter().copied()),
            Err(ErrorClass::TooLarge)
        );
        let twice = keys[..16].iter().chain(&keys[..1]).copied();
        assert_eq!(TrustedIssuers::new(twice).unwrap().len(), 16);
        // The identity point is of small order.
        let mut identity = [0; 32];
        identity[0] = 1;
        assert_eq!(TrustedIssuers::new([identity]), Err(ErrorClass::InvalidKey));
        assert!(TrustedIssuers::default().is_empty());
    }
}
