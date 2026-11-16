//! Streams (units.md, section 2.6, "Streams"), and the checks a member runs
//! on a valid unit before its adapter (section 3.2, step 16, and "The
//! stream check").
//!
//! - A stream exists from its first unit; nothing creates it. A stream ID
//!   is 16 bytes, never all zero, and never derived from a name.
//! - **A document stream's ID commits to its adapter type.** Its creator
//!   draws a 16-byte random salt, and every unit of the stream carries
//!   `[type, salt]`, its **opening**, at sealed key 6:
//!
//!   ```text
//!   stream ID = SHA-256("frasil/stream-id/v1" || u8(len(type)) || type || salt)[0..16]
//!   ```
//! - **The system stream's ID** is 16 random bytes, not all zero, drawn by
//!   the founder and sealed in the genesis's roster part (roster.md) and in
//!   every space snapshot.

use crate::limits::{SALT_BYTES, STREAM_BYTES};
use crate::types;
use crate::{UnitClass, UnitError};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Malformed, Value};
use frasil_crypto::labels::STREAM_ID;
use frasil_crypto::primitives::sha256;

/// A stream ID.
pub type StreamId = [u8; STREAM_BYTES];

/// Whether bytes are a stream ID: 16 bytes, not all zero.
pub fn is_valid(bytes: &[u8]) -> bool {
    bytes.len() == STREAM_BYTES && bytes.iter().any(|&byte| byte != 0)
}

/// A document stream's opening: its adapter type and its creator's salt,
/// carried at sealed key 6 by every unit of the stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Opening {
    /// The stream's adapter type.
    pub type_: String,
    /// The 16-byte salt its creator drew.
    pub salt: [u8; SALT_BYTES],
}

impl Opening {
    /// The opening of a stream of this type, from a salt the caller drew
    /// from its random source.
    pub fn with_salt(type_: impl Into<String>, salt: [u8; SALT_BYTES]) -> Self {
        Self {
            type_: type_.into(),
            salt,
        }
    }

    /// The stream ID this opening hashes to.
    pub fn stream(&self) -> StreamId {
        stream_id(&self.type_, &self.salt)
    }

    /// `[type, salt]`: sealed key 6 of a unit, and key 2 of a space
    /// snapshot's stream entry.
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::from(self.type_.as_str()),
            Value::from(self.salt),
        ])
    }

    /// Reads `[type, salt]`: an adapter type and 16 bytes.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(value: &Value) -> Result<Self, Malformed> {
        let [type_, salt] = value.as_array()? else {
            return Err(Malformed);
        };
        let type_ = type_.as_text()?;
        if !types::is_valid(type_) {
            return Err(Malformed);
        }
        Ok(Self::with_salt(type_, salt.as_byte_array::<SALT_BYTES>()?))
    }
}

/// `SHA-256("frasil/stream-id/v1" || u8(len(type)) || type || salt)[0..16]`.
/// The type is an adapter type, at most 64 bytes, so its length fits a
/// byte.
pub fn stream_id(type_: &str, salt: &[u8; SALT_BYTES]) -> StreamId {
    let length = [u8::try_from(type_.len()).unwrap_or(u8::MAX)];
    let digest = sha256(&[STREAM_ID, &length, type_.as_bytes(), salt]);
    let mut stream = [0; STREAM_BYTES];
    stream.copy_from_slice(&digest[..STREAM_BYTES]);
    stream
}

/// The stream check (section 3.2) of a unit of a document stream: SHA-256
/// of its opening is its visible stream (`StreamMismatch`), and its type is
/// the opening's type or `frasil:move` (`WrongAdapter`). Each unit is
/// checked alone, so a stream's type is fixed when the stream is created
/// and never depends on which unit comes first.
///
/// # Errors
///
/// `StreamMismatch`, then `WrongAdapter`.
pub fn check_stream(stream: &StreamId, opening: &Opening, type_: &str) -> Result<(), UnitClass> {
    if opening.stream() != *stream {
        return Err(UnitClass::StreamMismatch);
    }
    if type_ != opening.type_ && type_ != types::MOVE {
        return Err(UnitClass::WrongAdapter);
    }
    Ok(())
}

/// What section 3.2, step 16, checks of a valid unit before its adapter's
/// own checks, in order: a unit of one of the five system types outside
/// the system stream, or of any other type inside it, is refused as content
/// (`WrongStream`); then the stream check; then a type this replica has no
/// adapter for is kept and its content ignored (`UnknownAdapter`).
///
/// `opening` is the unit's sealed key 6, which step 14 requires exactly
/// outside the system stream; `has_adapter` says whether this replica has
/// an adapter for a type.
///
/// # Errors
///
/// `WrongStream`, `StreamMismatch`, `WrongAdapter` or `UnknownAdapter`, in
/// that order.
pub fn content_check(
    stream: &StreamId,
    system: &StreamId,
    type_: &str,
    opening: Option<&Opening>,
    has_adapter: impl Fn(&str) -> bool,
) -> Result<(), UnitError> {
    let in_system = stream == system;
    if types::is_system(type_) != in_system {
        return Err(UnitClass::WrongStream.into());
    }
    if !in_system {
        // Step 14 refuses a document unit with no opening as Malformed.
        let opening = opening.ok_or(ErrorClass::Malformed)?;
        check_stream(stream, opening, type_)?;
    }
    if !has_adapter(type_) {
        return Err(ErrorClass::UnknownAdapter.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM: StreamId = [9; 16];

    fn frasil(type_: &str) -> bool {
        types::FRASIL_TYPES.contains(&type_)
    }

    #[test]
    fn a_document_unit_is_checked_alone() {
        let loro = Opening::with_salt(types::LORO, [1; 16]);
        let stream = loro.stream();
        assert_eq!(
            content_check(&stream, &SYSTEM, types::LORO, Some(&loro), frasil),
            Ok(())
        );
        assert_eq!(
            content_check(&[3; 16], &SYSTEM, types::LORO, Some(&loro), frasil),
            Err(UnitClass::StreamMismatch.into())
        );
        assert_eq!(
            content_check(&stream, &SYSTEM, types::RECORDS, Some(&loro), frasil),
            Err(UnitClass::WrongAdapter.into())
        );
        assert_eq!(
            content_check(&stream, &SYSTEM, types::MOVE, Some(&loro), frasil),
            Ok(())
        );
        assert_eq!(
            content_check(&stream, &SYSTEM, types::LIST, Some(&loro), frasil),
            Err(UnitClass::WrongStream.into())
        );
        assert_eq!(
            content_check(&SYSTEM, &SYSTEM, types::LORO, None, frasil),
            Err(UnitClass::WrongStream.into())
        );
        let other = Opening::with_salt("com.example.timesheet", [2; 16]);
        assert_eq!(
            content_check(
                &other.stream(),
                &SYSTEM,
                "com.example.timesheet",
                Some(&other),
                frasil
            ),
            Err(ErrorClass::UnknownAdapter.into())
        );
        assert!(is_valid(&[0, 1].repeat(8)) && !is_valid(&[0; 16]) && !is_valid(&[1; 15]));
    }
}
