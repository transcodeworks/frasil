//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Device-signed requests to application servers: the signer and the
//! verifier.
//!
//! Specified by `docs/spec/ext-app-requests.md`. Its vectors are
//! `docs/spec/vectors/ext-app-requests.json`.
//!
//! A device-signed request is an HTTP request to an application's server
//! that carries, beside the account's access token, a signature by a device
//! or passkey member of the person's device list over a statement that binds
//! the request. The access token says which account sent it; the signature
//! says that a device of that account's person did.
//!
//! - [`statement`]: the statement, the shapes of its fields, and
//!   [`Request`], what a request is about.
//! - [`headers`]: the six headers and how they are read.
//! - [`sign`](mod@sign): signing a request.
//! - [`delivery`]: list deliveries, placing them, and [`HeldList`], the list
//!   a verifier holds of a person and who signs in it.
//! - [`state`]: the verifier's durable state, through [`VerifierState`] and
//!   [`NonceStore`], with in-memory implementations.
//! - [`verify`](mod@verify): the verifier's checks, in order.
//! - [`errors`]: the error classes and the codes a verifier answers.
//!
//! The crate does no IO, reads no clock and draws no randomness: the
//! verifier's wall clock, the signer's clock and the nonce come in as
//! arguments, and the verifier's state through traits, so an application's
//! server, or a WebAssembly build, supplies them.

pub mod delivery;
pub mod errors;
pub mod headers;
pub mod sign;
pub mod state;
pub mod statement;
pub mod verify;

pub use delivery::{HeldList, Placed, place_delivery};
pub use errors::{AppRequestClass, Code, Refusal};
pub use headers::{Header, Received, ReceivedHeaders, SignedHeaders};
pub use sign::{heads_to_send, sign};
pub use state::{MemoryNonceStore, MemoryState, NonceStore, VerifierState};
pub use statement::Request;
pub use verify::{Verified, Verifier};

use frasil_base::time::Timer;

/// `signed_request_lifetime`: how long a signed request lives, by the
/// signer's wall clock (overview.md, "Every timer").
pub const SIGNED_REQUEST_LIFETIME: u64 = 60;
/// `signed_request_skew`: how far the verifier's wall clock may be from the
/// signer's, each way.
pub const SIGNED_REQUEST_SKEW: u64 = 60;
/// `agent_waiting_period`'s default: how long a verifier that implements
/// ext-recovery-agent.md waits, from its first sight of an agent's `add`,
/// before the list member it adds signs.
pub const AGENT_WAITING_PERIOD: u64 = 72 * 3600;

/// The timers this document uses, with the values above.
pub const TIMERS: [(Timer, u64); 3] = [
    (Timer::SignedRequestLifetime, SIGNED_REQUEST_LIFETIME),
    (Timer::SignedRequestSkew, SIGNED_REQUEST_SKEW),
    (Timer::AgentWaitingPeriod, AGENT_WAITING_PERIOD),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_timers_are_overview_md_s() {
        for (timer, value) in TIMERS {
            assert_eq!(timer.spec().default, Some(value), "{}", timer.name());
        }
        assert!(Timer::SignedRequestLifetime.spec().is_fixed());
        assert!(Timer::SignedRequestSkew.spec().is_fixed());
    }
}
