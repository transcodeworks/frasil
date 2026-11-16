//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's events: the envelope, event IDs, placement, order and chains.
//!
//! Specified by `docs/spec/events.md`, and by `docs/spec/crypto.md`,
//! section 3.9 (Anchors and coverage) and section 3.10 (The classical
//! sunset). Its vectors are `docs/spec/vectors/events.json` and
//! `crypto.json`'s `coverage`.
//!
//! - [`kind`]: the kinds, which must be understood and which are ignorable,
//!   and their limits (events.md, "Kinds", "Limits").
//! - [`envelope`]: the envelope's fields, its encoding, `tbs`, the event ID
//!   and signing (events.md, "The envelope", "What is signed, and the event
//!   ID").
//! - [`decode`](mod@decode): [`decode()`], every check of events.md,
//!   "Decoding an event", in its order, and the ML-DSA-65 half
//!   ([`Event::verify_hybrid`], "The ML-DSA-65 half"). A decoded [`Event`]
//!   has its Ed25519 signature or half checked and gives no body but
//!   through [`Event::unverified_body`]; a [`VerifiedEvent`], whose
//!   signature verified in full, gives its body and is what applies,
//!   judges or acts on an event.
//! - [`cuts`]: the checkpoints an event follows, their order and the check
//!   of an event's `cuts` against its parents (events.md, "Cuts"). The
//!   roster layer says which space events are checkpoints, through
//!   [`cuts::Checkpoints`]. Checkpoints are ordered through the envelopes a
//!   log holds and those it keeps ([`Log::keep_envelope`]); a stubbed
//!   parent gives the cuts its stub carries ([`Stub::cuts`]); and an order
//!   that needs an envelope neither held nor kept is pending.
//! - [`refs`]: refs to events of other logs, which travel sealed in bodies.
//! - [`log`]: a log's placed events, placement against parents and stubs,
//!   causal order, heights, heads and canonical order (events.md,
//!   "Placement and order"); and a partial replica's witnessed parents,
//!   `Path` checks and proven order (units.md, "Partial replicas").
//! - [`chains`]: per-author chains, evidence of a fork, fork points and the
//!   penalty (events.md, "Chains and evidence of a fork", "The penalty").
//! - [`proofs`]: equivocation proofs and their verification.
//! - [`coverage`](mod@coverage): anchors and coverage (crypto.md, "Anchors and
//!   coverage", "The classical sunset").
//! - [`state`]: a log's state at rest, and fork points, for a replica's own
//!   records: reopening a log decodes and places no event again.
//!
//! The crate reads no clock, does no IO and draws no randomness: a signer's
//! keys and every event come in as arguments, and its maps and sets are
//! ordered ones, which need no random seed.
//!
//! # Using a log from a resolution procedure
//!
//! A [`Log`] answers the causal questions a `frasil-resolve` implementation
//! asks: [`Log::height`], [`Log::precedes`] and [`Log::canonical`], with
//! [`EventId`] as the ID (it is `Copy`, and its order is the byte order
//! canonical order breaks ties with). The chain penalty comes from
//! [`Log::fork_points`] and [`ForkPoints::is_void`].

pub mod chains;
pub mod coverage;
pub mod cuts;
pub mod decode;
pub mod envelope;
pub mod kind;
pub mod log;
pub mod proofs;
pub mod refs;
pub mod state;

pub use chains::{Evidence, EvidenceKind, ForkPoints};
pub use coverage::{CoverageEvent, coverage};
pub use cuts::{Checkpoints, Cuts, CutsCheck, HeldEnvelopes, MAX_CUTS, NoCheckpoints};
pub use decode::{Event, VerifiedEvent, decode};
pub use envelope::{Envelope, EventId};
pub use log::{Ancestry, Log, Placement, SignatureState, Stub, check_path};
pub use proofs::{Equivocation, ProofType, encode_proof, verify_proof};
pub use refs::Ref;

frasil_base::error_classes! {
    /// The error classes of events.md ("Error classes"), with every shared
    /// class.
    pub enum EventClass {
        /// A kind from 7 to 63 this replica does not know. Final, for this
        /// replica.
        UnknownKind = "unknown_kind", Final;
        /// An event, or one of its parents, of another log.
        WrongLog = "wrong_log", Final;
        /// A proof whose two events show no fork.
        NotEquivocation = "not_equivocation", Decision;
        /// An event whose `cuts` are not the maximal checkpoints its parents
        /// give (events.md, 3.11 Cuts).
        BadCuts = "bad_cuts", Final;
    }
}

impl EventClass {
    /// The shared class this is, if it is one.
    pub fn shared(self) -> Option<frasil_base::ErrorClass> {
        match self {
            Self::Shared(class) => Some(class),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::{Class, ErrorClass, Sort, snake_case};

    #[test]
    fn classes_follow_the_table() {
        for &class in EventClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
        }
        assert_eq!(EventClass::UnknownKind.sort(), Sort::Final);
        assert_eq!(EventClass::WrongLog.sort(), Sort::Final);
        assert_eq!(EventClass::NotEquivocation.sort(), Sort::Decision);
        assert_eq!(EventClass::BadCuts.sort(), Sort::Final);
        assert_eq!(EventClass::BadCuts.wire_name(), "bad_cuts");
        assert_eq!(EventClass::from_name("BadCuts"), Some(EventClass::BadCuts));
        assert_eq!(
            EventClass::from_name("NoHybridKey"),
            Some(EventClass::Shared(ErrorClass::NoHybridKey))
        );
        assert_eq!(
            EventClass::from(ErrorClass::Pending).shared(),
            Some(ErrorClass::Pending)
        );
        assert_eq!(EventClass::WrongLog.shared(), None);
    }
}
