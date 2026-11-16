//! Equivocation proofs (events.md, "Equivocation proofs" and "Verifying a
//! proof").
//!
//! ```text
//! proof = CBOR array [type, first, second]
//!   type 1, duplicate: first and second are two signed events, the one with the smaller ID first
//!   type 2, skip:      first is a signed event e; second is the signed event e's prev names
//!
//! verify_proof(proof), in order:
//!   1. It is a CBOR array of an unsigned type and two byte strings,
//!      and the type is 1 or 2.                                       else Malformed
//!   2. Each event passes section 3.1 and, for scheme 2, section 3.3. else that class
//!   3. Type 1: the first ID is smaller than the second.              else Malformed
//!   4. Type 1: both events have the same author, log and seq.
//!      Type 2: first's prev is second's ID, both are of one log, and
//!      second is not first's author's event at first.seq − 1.        else NotEquivocation
//! ```
//!
//! A proof makes a replica fetch both events and their pasts. Until it has
//! placed both, the proof decides nothing.

use crate::EventClass;
use crate::decode::{VerifiedEvent, decode};
use crate::envelope::EventId;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Reader};
use frasil_crypto::device::{DeviceId, KeySource};

/// A proof's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofType {
    /// Type 1: two events of one author in one log at one `seq`.
    Duplicate,
    /// Type 2: an event, and the event its `prev` names, which is not its
    /// author's event at `seq − 1`.
    Skip,
}

impl ProofType {
    /// The type's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Duplicate => 1,
            Self::Skip => 2,
        }
    }

    /// The type of a code, if it is 1 or 2.
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Duplicate),
            2 => Some(Self::Skip),
            _ => None,
        }
    }
}

/// The proof `[type, first, second]`, as deterministic CBOR, of two signed
/// events: for a duplicate, the one with the smaller ID first; for a skip,
/// the skipping event first.
pub fn encode_proof(kind: ProofType, first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(first.len() + second.len() + 20);
    cbor::array_head(&mut out, 3);
    cbor::unsigned(&mut out, kind.code());
    cbor::bytes(&mut out, first);
    cbor::bytes(&mut out, second);
    out
}

/// What a valid proof shows: an author forked its chain in a log, from a
/// fork point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    /// The proof's type.
    pub kind: ProofType,
    /// The author that forked.
    pub author: DeviceId,
    /// The log it forked in.
    pub log: EventId,
    /// The fork point the proof shows.
    pub fork_seq: u64,
    /// The proof's first event, its signature verified in full.
    pub first: VerifiedEvent,
    /// The proof's second event, its signature verified in full.
    pub second: VerifiedEvent,
}

/// `verify_proof(proof)`, every step in order. `keys` holds keys from any
/// source, looked up by each scheme-2 event's `kc` (crypto.md, "Keys by
/// their hash").
///
/// # Errors
///
/// `Malformed`; any class of [`decode`]; `NoHybridKey` or `BadSignature`
/// from the ML-DSA-65 half; `NotEquivocation`.
pub fn verify_proof(
    proof: &[u8],
    keys: &(impl KeySource + ?Sized),
) -> Result<Equivocation, EventClass> {
    // 1. [type, first, second], the type 1 or 2.
    let mut reader = Reader::new(proof);
    if reader.array_len()? != 3 {
        return Err(ErrorClass::Malformed.into());
    }
    let code = reader.unsigned()?;
    let first = reader.bytes()?;
    let second = reader.bytes()?;
    reader.finish()?;
    let kind = ProofType::from_code(code).ok_or(ErrorClass::Malformed)?;
    // 2. Each event decodes, and a scheme-2 event's ML-DSA-65 half
    // verifies.
    let (first, second) = (decode(first)?, decode(second)?);
    let first = first.verify_hybrid_in(keys)?;
    let second = second.verify_hybrid_in(keys)?;
    let fork_seq = match kind {
        ProofType::Duplicate => {
            // 3. The smaller ID first: one pair, one proof.
            if first.id() >= second.id() {
                return Err(ErrorClass::Malformed.into());
            }
            // 4. One author, one log, one seq.
            if first.author() != second.author()
                || first.log_id() != second.log_id()
                || first.seq() != second.seq()
            {
                return Err(EventClass::NotEquivocation);
            }
            first.seq()
        }
        ProofType::Skip => {
            // 4. first's prev is second, of one log, and not first's
            // author's event at first.seq − 1.
            if first.prev() != Some(second.id()) || first.log_id() != second.log_id() {
                return Err(EventClass::NotEquivocation);
            }
            let own = second.author() == first.author();
            if own && second.seq().checked_add(1) == Some(first.seq()) {
                return Err(EventClass::NotEquivocation);
            }
            if own {
                first.seq().min(second.seq().saturating_add(1))
            } else {
                first.seq()
            }
        }
    };
    Ok(Equivocation {
        kind,
        author: *first.author(),
        log: first.log_id(),
        fork_seq,
        first,
        second,
    })
}
