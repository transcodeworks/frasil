//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's deposit tokens extension: anonymous, single-use tokens that pay
//! for deposits in device mailboxes at an always-on peer, drawn against a
//! library's allowance on its issuer's grant or by a writer of one of its
//! spaces.
//!
//! Specified by `docs/spec/ext-deposit-tokens.md`. Its vectors are
//! `docs/spec/vectors/ext-deposit-tokens.json`.
//!
//! - [`suite`]: RFC 9497's VOPRF, mode `modeVOPRF`, suite
//!   ristretto255-SHA512, with every random value given as bytes (2.1).
//! - [`key`]: deposit keys, key IDs and roles (2.2).
//! - [`token`]: tokens, their input and the server binding's header (2.4).
//! - [`messages`]: `TokenKeysGet`, `TokenKeys`, `TokenRequest`,
//!   `TokenIssue` and `MailboxPut` with key 7 (2.5).
//! - [`settings`]: the allowance, the share, `token_period` and the other
//!   values (2.6).
//! - [`errors`]: the classes, their codes and statuses (2.8).
//! - [`device`]: learning a peer's keys and the consistency rule, a
//!   request and finishing it (3.2, 3.3, 3.5).
//! - [`peer`]: checking a request and issuing with the allowance window and
//!   the space's share, and redeeming with the spent set (3.4, 3.7).
//! - [`budget`]: the anonymous budget and the token budget over device
//!   mailboxes (3.8).
//! - [`rotation`]: the keys' shard and its rotation (3.9).
//!
//! The deposit grant is a library ticket of purpose 4 with key 7, which
//! `frasil-libraries` reads with its `ext-deposit-tokens` feature where
//! [`PeerRecords::deposit_tokens`](frasil_libraries::PeerRecords::deposit_tokens)
//! says the peer implements this extension. Message types 40 to 43,
//! service 6 and `MailboxPut` key 7 are `frasil-transport`'s, with its
//! `ext-deposit-tokens` feature.
//!
//! The crate reads no clock and does no IO. The peer's state is the
//! peer's: the functions here read it through traits and return what to
//! record, in one step. Every random draw has a `_with` form that takes its
//! bytes: the device's nonces and blinds ([`device::Batch::new_with`]),
//! the peer's key seeds ([`key::DepositKey::from_seed`],
//! [`rotation::KeyShard::advance_with`]) and the proof's scalar
//! ([`peer::issue_with`]). Seeds, blinds, nonces and tokens are zeroized
//! when dropped, and an authenticator is compared in constant time.

#![forbid(unsafe_code)]

pub mod budget;
pub mod device;
pub mod errors;
pub mod key;
pub mod messages;
pub mod peer;
pub mod rotation;
pub mod settings;
pub mod suite;
pub mod token;

pub use device::{Batch, KeyHistory, KeyList};
pub use errors::TokenClass;
pub use key::{DepositKey, KeyId, PeerKey, Role};
pub use messages::{Draw, TokenIssue, TokenKeys, TokenKeysGet, TokenPut, TokenRequest};
pub use peer::{
    Approved, IssuanceRecords, Issued, Redemption, SpentRecord, SpentTokens, TokenDeposit,
    TokenRoom, Window, check_request, issue, issue_with, redeem,
};
pub use rotation::KeyShard;
pub use token::Token;

/// `TokenKeysGet`'s message type, which transport.md reserves for this
/// extension.
pub const TOKEN_KEYS_GET: u64 = 40;

/// `TokenKeys`'s message type.
pub const TOKEN_KEYS: u64 = 41;

/// `TokenRequest`'s message type.
pub const TOKEN_REQUEST: u64 = 42;

/// `TokenIssue`'s message type.
pub const TOKEN_ISSUE: u64 = 43;

/// Service 6, `deposit`: a peer whose `PeerHello` lists it issues and takes
/// tokens.
pub const DEPOSIT_SERVICE: u64 = 6;

/// The most blinded or evaluated elements of one batch, and the most tokens
/// a grant names.
pub const MAX_BATCH: usize = 256;

/// The most bytes of a grant in a `TokenRequest`: a signed library ticket's
/// most.
pub const MAX_GRANT_BYTES: usize = frasil_libraries::ticket::MAX_TICKET_BYTES;

/// The cap of each of the four messages, in bytes.
pub const MESSAGE_CAP: usize = 16_384;
