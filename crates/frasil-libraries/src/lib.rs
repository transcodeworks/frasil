//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's libraries extension: tickets, issuer signing and ticket checks.
//!
//! Specified by `docs/spec/ext-libraries.md`. Its vectors are
//! `docs/spec/vectors/ext-libraries.json`.
//!
//! A **library** exists only at a peer: a billing pool whose quota covers
//! the spaces attached to it. A **library ticket** lets one device attach
//! one space to one library, once. This crate holds the ticket's side:
//!
//! - [`ticket`]: the library ID, the purposes, and the signed ticket's
//!   encoding and decoding (ext-libraries.md, 2.1 and 2.2).
//! - [`attach`]: `LibraryAttach`, the message that carries a ticket to a
//!   peer (2.3).
//! - [`issuer`]: the issuer's signing (2.2, 3.1).
//! - [`link`]: a ticket handed to a person as a link, with the origin of
//!   the peer it is for.
//! - [`check`]: a peer's trusted issuers and `check_ticket`, in its order
//!   (3.2).
//! - [`settings`]: a library's and a peer's settings, their defaults and
//!   ranges, and a library's state (2.4).
//! - [`errors`]: the classes, their refusal codes and statuses (2.6).
//! - [`hold`]: an object's access key, `HoldObject` and `check_hold`, by
//!   which a space holds an object another space of its library stores
//!   (2.7, 2.8 and 3.7).
//!
//! `LibraryAttach` (message type [`LIBRARY_ATTACH`]) carries the signed
//! ticket as opaque bytes; transport.md frames it. Attaching, the
//! ledgers and the store checks (3.3 to 3.6) are the peer's: the peer keeps
//! what section 2.5 lists and answers [`check::PeerRecords`] from it, so
//! that [`check::check_ticket`] reads the peer's state without owning it.
//!
//! With the `ext-deposit-tokens` feature, a ticket of purpose 4 with key 7
//! is a **deposit grant** (ext-deposit-tokens.md, 2.3 The deposit grant),
//! which [`check_ticket`] reads where [`PeerRecords::deposit_tokens`] says
//! the peer implements that extension; anywhere else it is `Malformed`.
//!
//! The crate reads no clock and does no IO. The one random draw, a ticket's
//! ID, has a `_with` form ([`issuer::Issuer::issue_with`]).

pub mod attach;
pub mod check;
pub mod errors;
pub mod hold;
pub mod issuer;
pub mod link;
pub mod settings;
pub mod ticket;

pub use attach::LibraryAttach;
pub use check::{PeerRecords, TrustedIssuers, check_ticket};
pub use errors::LibraryClass;
pub use hold::{HoldObject, PeerHolds, access_key, check_hold};
pub use issuer::Issuer;
pub use link::TicketLink;
pub use settings::LibraryState;
pub use ticket::{LibraryId, Purpose, SignedTicket, Ticket, TicketId};

/// `LibraryAttach`'s message type, which transport.md reserves for this
/// extension (ext-libraries.md, 2.3 LibraryAttach).
pub const LIBRARY_ATTACH: u64 = 21;

/// `HoldObject`'s message type, which transport.md reserves for this
/// extension (ext-libraries.md, 2.8 HoldObject).
pub const HOLD_OBJECT: u64 = 31;

/// Service 5, `library`: a peer whose `PeerHello` lists it takes
/// `LibraryAttach` (ext-libraries.md, 2.3 LibraryAttach).
pub const LIBRARY_SERVICE: u64 = 5;
