//! Reading the content's and the snapshot state's fields: the small checks
//! adapter-records.md and adapter-blobs.md share. Each failure is
//! `Malformed`.

use frasil_base::cbor::{Map, Value};
use frasil_base::errors::ErrorClass;

/// Text of `min` to `max` bytes of UTF-8.
pub fn text_of(value: &Value, min: usize, max: usize) -> Result<&str, ErrorClass> {
    let text = value.as_text()?;
    if (min..=max).contains(&text.len()) {
        Ok(text)
    } else {
        Err(ErrorClass::Malformed)
    }
}

/// Bytes of `min` to `max` bytes.
pub fn bytes_of(value: &Value, min: usize, max: usize) -> Result<&[u8], ErrorClass> {
    let bytes = value.as_bytes()?;
    if (min..=max).contains(&bytes.len()) {
        Ok(bytes)
    } else {
        Err(ErrorClass::Malformed)
    }
}

/// An array of `min` to `max` items.
pub fn array_of(value: &Value, min: usize, max: usize) -> Result<&[Value], ErrorClass> {
    let items = value.as_array()?;
    if (min..=max).contains(&items.len()) {
        Ok(items)
    } else {
        Err(ErrorClass::Malformed)
    }
}

/// Items strictly ascending: text and bytes byte by byte, a prefix first,
/// which is Rust's order on `str` and `[u8]`.
pub fn strictly_ascending<T: Ord>(items: &[T]) -> Result<(), ErrorClass> {
    if items.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(ErrorClass::Malformed)
    }
}

/// A map whose keys are among `allowed` and include every key of
/// `required`.
pub fn keys(map: &Map, required: &[u64], allowed: &[u64]) -> Result<(), ErrorClass> {
    let present = required.iter().all(|key| map.contains_key(key));
    let known = map.keys().all(|key| allowed.contains(key));
    if present && known {
        Ok(())
    } else {
        Err(ErrorClass::Malformed)
    }
}

/// The first check of both adapters (adapter-records.md, section 3.2, "The
/// checks", step 1): the content is deterministic CBOR, a map with an unsigned
/// key 1, else `Malformed`; and key 1 is 1, else `UnknownContentVersion`.
pub fn versioned_map(content: &[u8], version: u64) -> Result<Map, ErrorClass> {
    versioned(frasil_base::cbor::decode(content)?, version)
}

/// [`versioned_map`] in the records subset, which a changeset's values use
/// (adapter-records.md, section 2.1).
pub fn versioned_records_map(content: &[u8], version: u64) -> Result<Map, ErrorClass> {
    versioned(frasil_base::cbor::decode_records(content)?, version)
}

fn versioned(value: Value, version: u64) -> Result<Map, ErrorClass> {
    let Value::Map(map) = value else {
        return Err(ErrorClass::Malformed);
    };
    match map.get(&1) {
        Some(Value::Unsigned(found)) if *found == version => Ok(map),
        Some(Value::Unsigned(_)) => Err(ErrorClass::UnknownContentVersion),
        _ => Err(ErrorClass::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_inclusive() {
        let text = Value::from("ab");
        assert_eq!(text_of(&text, 2, 2), Ok("ab"));
        assert!(text_of(&text, 3, 9).is_err());
        assert!(text_of(&Value::from(vec![1u8]), 0, 9).is_err());
        assert!(bytes_of(&Value::from(vec![1u8]), 1, 1).is_ok());
        assert!(bytes_of(&Value::from(Vec::<u8>::new()), 1, 1).is_err());
        assert!(array_of(&Value::Array(vec![]), 1, 2).is_err());
    }

    #[test]
    fn ascending_puts_a_prefix_first() {
        assert!(strictly_ascending(&["", "a", "ab", "b"]).is_ok());
        assert!(strictly_ascending(&["a", "a"]).is_err());
        assert!(strictly_ascending(&[&b"b"[..], b"a"]).is_err());
    }

    #[test]
    fn the_version_is_checked_after_the_map() {
        assert_eq!(
            versioned_map(&[0xa1, 0x01, 0x02], 1),
            Err(ErrorClass::UnknownContentVersion)
        );
        assert_eq!(
            versioned_map(&[0xa1, 0x01, 0x61, 0x61], 1),
            Err(ErrorClass::Malformed)
        );
        assert_eq!(
            versioned_map(&[0xa1, 0x02, 0x01], 1),
            Err(ErrorClass::Malformed)
        );
        assert_eq!(versioned_map(&[0x80], 1), Err(ErrorClass::Malformed));
        assert_eq!(versioned_map(&[], 1), Err(ErrorClass::Malformed));
        assert!(versioned_map(&[0xa1, 0x01, 0x01], 1).is_ok());
    }
}
