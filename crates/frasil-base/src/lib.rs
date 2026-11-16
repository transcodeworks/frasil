//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's conventions and time.
//!
//! Specified by `docs/spec/overview.md`, section 5 (Conventions) and
//! section 6 (Time). Its vectors are `docs/spec/vectors/overview.json`.
//!
//! - [`collect`]: ordered maps built by insertion, with no sort compiled
//!   per call site.
//! - [`cbor`]: deterministic CBOR, the subset Frasil's own structures use,
//!   with one accepted encoding per value.
//! - [`notation`]: `u8`, `u16be`, `u32be`, `u64be`, `field()` and lowercase
//!   hex.
//! - [`errors`]: the error classes several documents share, their sorts, and
//!   [`error_classes!`] for a document's own classes.
//! - [`version`]: the protocol, format and revision numbers.
//! - [`time`]: the local timeline, the two estimates, `check_expiry`,
//!   `check_policy` and every timer.
//!
//! The crate reads no clock and does no IO: every time value comes in as an
//! argument.

pub mod cbor;
pub mod cbor_stream;
pub mod collect;
pub mod errors;
pub mod notation;
pub mod time;
pub mod version;

pub use errors::{Class, ErrorClass, Sort};
