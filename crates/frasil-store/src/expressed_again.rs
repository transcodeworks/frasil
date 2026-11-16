//! `state` key 8: the incarnations a lent document's holder expressed again.
//!
//! When a removal withdraws a unit a lent Loro document wrote, its holder
//! takes a fresh incarnation and writes the lost operations again under it.
//! The withdrawn unit is then not re-submitted after a re-grant, which
//! would hold the operations twice (roster.md, 3.14, "Re-submission").
//! The device keeps which incarnations those were in its log's `state`
//! record, key 8, written in the commit of the first unit under the fresh
//! incarnation, so that after reopening it still leaves their units out of
//! re-submission.
//!
//! The value is an array of `[stream (bytes 16), incarnation (uint, at
//! least 1)]` pairs, at least one, strictly ascending by stream and then
//! incarnation;
//! the key is absent when there are none. The incarnation is the one Loro
//! content names (adapter-loro.md, section 2.2, key 3), the author being
//! the device itself.

use frasil_base::ErrorClass;
use frasil_base::cbor::Value;
use std::collections::BTreeSet;

/// A stream ID's length (units.md, "Streams").
pub const STREAM_BYTES: usize = 16;

/// One stream's incarnation of this device.
pub type Expressed = ([u8; STREAM_BYTES], u64);

/// The incarnations a log's lent documents expressed again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ExpressedAgain(pub BTreeSet<Expressed>);

impl ExpressedAgain {
    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Key 8's value.
    pub fn value(&self) -> Value {
        Value::Array(
            self.0
                .iter()
                .map(|(stream, incarnation)| {
                    Value::Array(vec![stream.to_vec().into(), (*incarnation).into()])
                })
                .collect(),
        )
    }

    /// Reads key 8's value.
    ///
    /// # Errors
    ///
    /// `Malformed` unless it is a non-empty array of pairs of a 16-byte
    /// stream and an incarnation, strictly ascending.
    pub fn read(value: &Value) -> Result<Self, ErrorClass> {
        let malformed = ErrorClass::Malformed;
        let items = value.as_array().map_err(|_| malformed)?;
        if items.is_empty() {
            return Err(malformed);
        }
        let mut out = BTreeSet::new();
        let mut last: Option<Expressed> = None;
        for item in items {
            let pair = item.as_array().map_err(|_| malformed)?;
            let [stream, incarnation] = pair else {
                return Err(malformed);
            };
            let stream: [u8; STREAM_BYTES] = stream
                .as_bytes()
                .map_err(|_| malformed)?
                .try_into()
                .map_err(|_| malformed)?;
            let incarnation = incarnation.as_unsigned().map_err(|_| malformed)?;
            if incarnation == 0 {
                return Err(malformed);
            }
            let entry = (stream, incarnation);
            if last.is_some_and(|last| last >= entry) {
                return Err(malformed);
            }
            last = Some(entry);
            out.insert(entry);
        }
        Ok(Self(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_value_reads_back() {
        let set = ExpressedAgain([([1; 16], 3), ([1; 16], 7), ([2; 16], 1)].into());
        assert_eq!(ExpressedAgain::read(&set.value()), Ok(set));
    }

    #[test]
    fn empty_unordered_and_short_values_are_malformed() {
        let pair = |s: u8, i: u64| Value::Array(vec![vec![s; 16].into(), i.into()]);
        for bad in [
            Value::Array(Vec::new()),
            Value::Array(vec![pair(2, 1), pair(1, 1)]),
            Value::Array(vec![pair(1, 1), pair(1, 1)]),
            Value::Array(vec![Value::Array(vec![vec![1; 15].into(), 1u64.into()])]),
            Value::Array(vec![Value::Array(vec![vec![1; 16].into()])]),
            Value::Array(vec![pair(1, 0)]),
        ] {
            assert_eq!(ExpressedAgain::read(&bad), Err(ErrorClass::Malformed));
        }
    }
}
