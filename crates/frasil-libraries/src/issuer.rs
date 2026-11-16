//! The issuer's signing (ext-libraries.md, 2.2 The library ticket, and 3.1
//! Getting a ticket).
//!
//! The issuer is a service the operator trusts, such as the account server
//! that sells the library. It draws each ticket's ID, sets `not_after` at
//! most `ticket_lifetime` after it signs, and signs with scheme 0:
//! `Ed25519-Sign(issuer's seed, "frasil/library-ticket/v1" || ticket)`.

use frasil_crypto::NoRandomness;
use frasil_crypto::primitives::{ed25519_public, ed25519_sign};
use frasil_crypto::random_bytes;
use frasil_crypto::sizes::{ED25519_PUBLIC, ED25519_SEED};
use zeroize::Zeroizing;

use crate::settings::TICKET_LIFETIME;
use crate::ticket::{LibraryId, Purpose, Ticket, TicketId, encode_signed, signed_message};

/// An issuer: its Ed25519 seed and public key.
pub struct Issuer {
    seed: Zeroizing<[u8; ED25519_SEED]>,
    public: [u8; ED25519_PUBLIC],
}

impl core::fmt::Debug for Issuer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Issuer")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Why an issuer could not issue a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    /// `not_after` is before the instant of signing, or more than
    /// `ticket_lifetime` after it (`Malformed`).
    Lifetime,
    /// The platform has no working source of randomness for the ticket's ID.
    NoRandomness,
    /// A deposit grant naming no token or more than 256, or purpose 4
    /// asked of [`Issuer::issue_with`], which names no tokens (`Malformed`).
    Tokens,
}

impl core::fmt::Display for IssueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Lifetime => "not_after is outside ticket_lifetime",
            Self::NoRandomness => "no randomness",
            Self::Tokens => "a deposit grant names 1 to 256 tokens",
        })
    }
}

impl std::error::Error for IssueError {}

impl From<NoRandomness> for IssueError {
    fn from(_: NoRandomness) -> Self {
        Self::NoRandomness
    }
}

impl Issuer {
    /// The issuer of an Ed25519 seed.
    pub fn from_seed(seed: &[u8; ED25519_SEED]) -> Self {
        Self {
            seed: Zeroizing::new(*seed),
            public: ed25519_public(seed),
        }
    }

    /// The issuer's Ed25519 public key, which peers trust and each ticket
    /// carries as key 6.
    pub fn public(&self) -> &[u8; ED25519_PUBLIC] {
        &self.public
    }

    /// Signs a ticket's fields as they are: `[ticket, signature]`. It checks
    /// nothing; [`issue_with`](Self::issue_with) checks the lifetime and
    /// sets the issuer.
    pub fn sign(&self, ticket: &Ticket) -> Vec<u8> {
        self.sign_bytes(&ticket.encode())
    }

    /// Signs a ticket's bytes as they are: `[ticket, Ed25519-Sign(seed,
    /// "frasil/library-ticket/v1" || ticket)]`.
    pub fn sign_bytes(&self, ticket: &[u8]) -> Vec<u8> {
        let signature = ed25519_sign(&self.seed, &signed_message(ticket));
        encode_signed(ticket, &signature)
    }

    /// Issues a signed ticket with the ID `id`, at the wall-clock instant
    /// `now_wall` (ext-libraries.md, 3.1 Getting a ticket). The `_with` form
    /// of [`issue`](Self::issue).
    ///
    /// # Errors
    ///
    /// [`IssueError::Lifetime`] if `not_after` is before `now_wall` or more
    /// than `ticket_lifetime` after it.
    pub fn issue_with(
        &self,
        library: &LibraryId,
        purpose: Purpose,
        now_wall: u64,
        not_after: u64,
        id: TicketId,
    ) -> Result<Vec<u8>, IssueError> {
        if not_after < now_wall || not_after > now_wall.saturating_add(TICKET_LIFETIME) {
            return Err(IssueError::Lifetime);
        }
        if !purpose.attaches() {
            return Err(IssueError::Tokens);
        }
        Ok(self.sign(&Ticket {
            library: library.clone(),
            id,
            purpose,
            not_after,
            issuer: self.public,
            tokens: None,
        }))
    }

    /// Issues a deposit grant (ext-deposit-tokens.md, 2.3 The deposit
    /// grant and 3.1.1 Getting a grant): a ticket of purpose 4 naming
    /// `tokens`, 1 to 256, with the ID given.
    ///
    /// # Errors
    ///
    /// [`IssueError::Lifetime`] as for [`issue_with`](Self::issue_with);
    /// [`IssueError::Tokens`] for a count outside 1 to 256.
    #[cfg(feature = "ext-deposit-tokens")]
    pub fn issue_grant_with(
        &self,
        library: &LibraryId,
        tokens: u64,
        now_wall: u64,
        not_after: u64,
        id: TicketId,
    ) -> Result<Vec<u8>, IssueError> {
        if not_after < now_wall || not_after > now_wall.saturating_add(TICKET_LIFETIME) {
            return Err(IssueError::Lifetime);
        }
        if !(1..=crate::ticket::MAX_GRANT_TOKENS).contains(&tokens) {
            return Err(IssueError::Tokens);
        }
        Ok(self.sign(&Ticket {
            library: library.clone(),
            id,
            purpose: Purpose::Deposit,
            not_after,
            issuer: self.public,
            tokens: Some(tokens),
        }))
    }

    /// Issues a deposit grant with a random ID.
    ///
    /// # Errors
    ///
    /// As [`issue_grant_with`](Self::issue_grant_with), and
    /// [`IssueError::NoRandomness`] when the platform has no working source.
    #[cfg(feature = "ext-deposit-tokens")]
    pub fn issue_grant(
        &self,
        library: &LibraryId,
        tokens: u64,
        now_wall: u64,
        not_after: u64,
    ) -> Result<Vec<u8>, IssueError> {
        let id = random_bytes::<{ crate::ticket::TICKET_ID_BYTES }>()?;
        self.issue_grant_with(library, tokens, now_wall, not_after, *id)
    }

    /// Issues a signed ticket with a random ID.
    ///
    /// # Errors
    ///
    /// As [`issue_with`](Self::issue_with), and
    /// [`IssueError::NoRandomness`] when the platform has no working source.
    pub fn issue(
        &self,
        library: &LibraryId,
        purpose: Purpose,
        now_wall: u64,
        not_after: u64,
    ) -> Result<Vec<u8>, IssueError> {
        let id = random_bytes::<{ crate::ticket::TICKET_ID_BYTES }>()?;
        self.issue_with(library, purpose, now_wall, not_after, *id)
    }
}
