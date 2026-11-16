//! Arrays of IDs as the formats write them: strictly ascending byte strings
//! of one length, within a count.

use frasil_base::cbor::{Malformed, Value};
use frasil_events::EventId;

/// Event IDs as a CBOR array, strictly ascending, each once.
pub(crate) fn ids_value(ids: &[EventId]) -> Value {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    Value::Array(ids.into_iter().map(|id| Value::from(id.0)).collect())
}

/// Reads `lo` to `hi` IDs of `N` bytes, strictly ascending.
pub(crate) fn read_ids<const N: usize>(
    value: &Value,
    lo: usize,
    hi: usize,
) -> Result<Vec<[u8; N]>, Malformed> {
    let items = value.as_array()?;
    if items.len() < lo || items.len() > hi {
        return Err(Malformed);
    }
    let ids = items
        .iter()
        .map(Value::as_byte_array::<N>)
        .collect::<Result<Vec<_>, _>>()?;
    if !ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(Malformed);
    }
    Ok(ids)
}

/// Reads `lo` to `hi` event IDs, strictly ascending.
pub(crate) fn event_ids(value: &Value, lo: usize, hi: usize) -> Result<Vec<EventId>, Malformed> {
    Ok(read_ids::<32>(value, lo, hi)?
        .into_iter()
        .map(EventId)
        .collect())
}
