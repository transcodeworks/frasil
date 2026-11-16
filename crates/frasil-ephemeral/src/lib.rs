//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's ephemeral channel: the lossy channel and its key.
//!
//! Specified by `docs/spec/ext-ephemeral.md`. Its vectors are
//! `docs/spec/vectors/ext-ephemeral.json`.
//!
//! - [`limits`]: section 2.1's labels, limits and timers.
//! - [`key`]: the ephemeral key and the ephemeral slot handle (sections 2.2
//!   and 2.4).
//! - [`inner`]: the inner map (section 2.3).
//! - [`frame`]: the signature, the seal, the padding and the outer frame
//!   (sections 2.5 and 2.6), and a sender's whole construction.
//! - [`names`]: Frasil's names (section 2.7) and their check at step 11.
//! - [`counters`]: a device's epoch and its counters per space (section
//!   3.2).
//! - [`replay`]: a receiver's replay state: the window per space and sender,
//!   and the marks of ephemeral slots (section 3.2).
//! - [`nonces`]: receiver nonces (section 3.3).
//! - [`receive`](mod@receive): the receiver's checks, in order (section
//!   3.4), against its current view.
//! - [`membership`]: membership against the current view (section 3.6).
//! - [`relay`]: an always-on peer's relaying (section 3.7).
//! - [`sending`]: a sender's live ephemeral slots and its queue per
//!   connection (section 3.1).
//!
//! The crate holds no IO, clock or randomness of its own. Every random draw
//! (the seal's nonce, the restore's epoch offset, a receiver nonce, a
//! relay's origin) has a `_with` form that takes its bytes, and the queue's
//! deadline reads a monotonic instant the caller passes in. A caller draws
//! the bytes with `frasil_crypto::random_bytes`.

pub mod counters;
pub mod frame;
pub mod inner;
pub mod key;
pub mod limits;
pub mod membership;
pub mod names;
pub mod nonces;
pub mod receive;
pub mod relay;
pub mod replay;
pub mod sending;

pub use frame::{Outer, Sealed, seal_with};
pub use inner::{Inner, Kind};
pub use membership::Membership;
pub use receive::{
    Accepted, AdapterCheck, CheckContext, Delivered, Extension, Refusal, SpaceKind, View, receive,
};

frasil_base::error_classes! {
    /// The error classes of ext-ephemeral.md (section 3.9, "Error classes"),
    /// with every shared class. Each is a decision about one frame, never a
    /// verdict on an event.
    pub enum EphemeralClass {
        /// A state or key name of more than 64 rotations (keys.md).
        TooManyRotations = "too_many_rotations", Decision;
        /// The sender's membership ended in the receiver's view
        /// (transport.md).
        MembershipEnded = "membership_ended", Decision;
        /// A space this receiver does not follow.
        NotFollowing = "not_following", Decision;
        /// An ephemeral slot whose handle is not its own.
        WrongHandle = "wrong_handle", Decision;
        /// The receiver's own frame, echoed back.
        Own = "own", Decision;
        /// A `frasil/` name this receiver does not implement.
        UnknownName = "unknown_name", Decision;
        /// Membership cannot be decided without a log the receiver lacks.
        Unjudgeable = "unjudgeable", Decision;
        /// Targeted at other devices.
        NotTargeted = "not_targeted", Decision;
        /// A fresh entry this receiver does not hold, or none where its name
        /// requires one.
        Stale = "stale", Decision;
    }
}

impl From<frasil_keys::KeyClass> for EphemeralClass {
    fn from(class: frasil_keys::KeyClass) -> Self {
        match class {
            frasil_keys::KeyClass::TooManyRotations => Self::TooManyRotations,
            frasil_keys::KeyClass::Shared(shared) => Self::Shared(shared),
            // Reading a rotation set raises nothing else.
            _ => Self::Shared(frasil_base::ErrorClass::Malformed),
        }
    }
}

pub(crate) fn malformed() -> EphemeralClass {
    EphemeralClass::Shared(frasil_base::ErrorClass::Malformed)
}
