//! Refs (events.md, "Refs").
//!
//! A ref names an event of another log, as the pair `[log ID, event ID]`:
//!
//! ```text
//! refs = CBOR array of 1 to 64 refs, each [log (bytes 32), id (bytes 32)],
//!        strictly ascending as the 64 bytes log || id
//! ```
//!
//! Refs travel sealed in the body, never in the envelope, so each kind's
//! document reads them from its own body with [`decode_refs`]. Refs create
//! no order: no envelope check, chain, fork evidence or coverage reads one.

use crate::envelope::EventId;
use crate::kind::MAX_REFS;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Value};

/// A ref: an event of another log. Its order is that of the 64 bytes
/// `log || id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ref {
    /// The log the event belongs to.
    pub log: EventId,
    /// The event.
    pub id: EventId,
}

impl Ref {
    /// The ref as a CBOR value, `[log, id]`.
    pub fn to_value(&self) -> Value {
        Value::Array(vec![Value::from(self.log.0), Value::from(self.id.0)])
    }
}

/// The refs as a CBOR value: strictly ascending, each once, whatever their
/// order here. The caller keeps to 1 to 64 refs.
pub fn refs_value(refs: &[Ref]) -> Value {
    let mut refs = refs.to_vec();
    refs.sort_unstable();
    refs.dedup();
    Value::Array(refs.iter().map(Ref::to_value).collect())
}

/// The refs' deterministic encoding.
pub fn encode_refs(refs: &[Ref]) -> Vec<u8> {
    refs_value(refs).encode()
}

/// Reads a body's refs from their CBOR value.
///
/// # Errors
///
/// `Malformed` for anything but an array of `[bytes(32), bytes(32)]` pairs,
/// strictly ascending, or an empty array; `TooLarge` for more than 64 refs
/// (events.md, "Limits", which roster.md and units.md keep). A kind whose
/// document names another class for too many refs maps this one.
pub fn decode_refs(value: &Value) -> Result<Vec<Ref>, ErrorClass> {
    let items = value.as_array()?;
    if items.is_empty() {
        return Err(ErrorClass::Malformed);
    }
    if items.len() > MAX_REFS {
        return Err(ErrorClass::TooLarge);
    }
    let mut refs = Vec::with_capacity(items.len());
    for item in items {
        let [log, id] = item.as_array()? else {
            return Err(ErrorClass::Malformed);
        };
        let next = Ref {
            log: EventId(log.as_byte_array::<32>()?),
            id: EventId(id.as_byte_array::<32>()?),
        };
        if refs.last().is_some_and(|last: &Ref| *last >= next) {
            return Err(ErrorClass::Malformed);
        }
        refs.push(next);
    }
    Ok(refs)
}

/// Reads refs from their deterministic encoding, as [`decode_refs`].
///
/// # Errors
///
/// As [`decode_refs`], and `Malformed` for bytes that are not one
/// deterministic CBOR value.
pub fn decode_refs_bytes(bytes: &[u8]) -> Result<Vec<Ref>, ErrorClass> {
    decode_refs(&cbor::decode(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(log: u8, id: u8) -> Ref {
        Ref {
            log: EventId([log; 32]),
            id: EventId([id; 32]),
        }
    }

    #[test]
    fn refs_round_trip_in_order() {
        let refs = [r(2, 1), r(1, 9), r(1, 2), r(1, 9)];
        let bytes = encode_refs(&refs);
        assert_eq!(
            decode_refs_bytes(&bytes),
            Ok(vec![r(1, 2), r(1, 9), r(2, 1)])
        );
    }

    #[test]
    fn refuses_bad_refs() {
        let malformed = Err(ErrorClass::Malformed);
        assert_eq!(decode_refs(&Value::Array(vec![])), malformed);
        let unordered = Value::Array(vec![r(2, 1).to_value(), r(1, 1).to_value()]);
        assert_eq!(decode_refs(&unordered), malformed);
        let twice = Value::Array(vec![r(1, 1).to_value(), r(1, 1).to_value()]);
        assert_eq!(decode_refs(&twice), malformed);
        let short = Value::Array(vec![Value::Array(vec![
            Value::from([1u8; 31]),
            Value::from([1u8; 32]),
        ])]);
        assert_eq!(decode_refs(&short), malformed);
        let triple = Value::Array(vec![Value::Array(vec![
            Value::from([1u8; 32]),
            Value::from([1u8; 32]),
            Value::from([1u8; 32]),
        ])]);
        assert_eq!(decode_refs(&triple), malformed);
        let many: Vec<Ref> = (0..65).map(|i| r(1, i)).collect();
        assert_eq!(decode_refs(&refs_value(&many)), Err(ErrorClass::TooLarge));
        assert_eq!(
            decode_refs(&refs_value(&many[..64])).map(|v| v.len()),
            Ok(64)
        );
    }
}
