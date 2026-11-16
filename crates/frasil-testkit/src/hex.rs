//! Lowercase hex, as the vector files write byte strings.

use serde::{Deserialize, Deserializer, de::Error as _};
use serde_json::Value;

/// Why a hex string could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// The value is not a JSON string.
    NotAString,
    /// The string holds a character that is not lowercase hex, or an odd
    /// number of digits.
    Invalid(String),
    /// The string decodes to a length other than the one expected.
    Length {
        /// The length expected, in bytes.
        expected: usize,
        /// The length found, in bytes.
        found: usize,
    },
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAString => write!(f, "expected a hex string"),
            Self::Invalid(text) => write!(f, "not lowercase hex: {text:?}"),
            Self::Length { expected, found } => {
                write!(f, "expected {expected} bytes, found {found}")
            }
        }
    }
}

impl std::error::Error for HexError {}

/// Decodes lowercase hex. Upper-case digits are refused, because the vector
/// files never write them.
pub fn decode(text: &str) -> Result<Vec<u8>, HexError> {
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(HexError::Invalid(text.to_owned()));
    }
    ::hex::decode(text).map_err(|_| HexError::Invalid(text.to_owned()))
}

/// Decodes lowercase hex of exactly `N` bytes.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    let bytes = decode(text)?;
    let found = bytes.len();
    bytes
        .try_into()
        .map_err(|_| HexError::Length { expected: N, found })
}

/// Encodes bytes as lowercase hex.
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    ::hex::encode(bytes)
}

/// Decodes a JSON string value holding lowercase hex.
pub fn from_value(value: &Value) -> Result<Vec<u8>, HexError> {
    decode(value.as_str().ok_or(HexError::NotAString)?)
}

/// A serde helper for a hex field: `#[serde(deserialize_with = "frasil_testkit::hex::bytes")]`.
pub fn bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let text = String::deserialize(deserializer)?;
    decode(&text).map_err(D::Error::custom)
}

/// A serde helper for a hex field of a fixed length:
/// `#[serde(deserialize_with = "frasil_testkit::hex::array")]`.
pub fn array<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let text = String::deserialize(deserializer)?;
    decode_array(&text).map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_lowercase_hex() {
        assert_eq!(decode("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(encode([0xab, 0x01]), "ab01");
    }

    #[test]
    fn refuses_upper_case_odd_length_and_other_characters() {
        assert!(decode("00FF").is_err());
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
    }

    #[test]
    fn checks_array_length() {
        assert_eq!(decode_array::<2>("0102").unwrap(), [1, 2]);
        assert_eq!(
            decode_array::<3>("0102"),
            Err(HexError::Length {
                expected: 3,
                found: 2
            })
        );
    }

    #[test]
    fn reads_values_and_fields() {
        #[derive(serde::Deserialize)]
        struct Case {
            #[serde(deserialize_with = "bytes")]
            data: Vec<u8>,
            #[serde(deserialize_with = "array")]
            key: [u8; 2],
        }
        let case: Case = serde_json::from_str(r#"{"data":"0a0b","key":"ffee"}"#).unwrap();
        assert_eq!(case.data, vec![0x0a, 0x0b]);
        assert_eq!(case.key, [0xff, 0xee]);
        assert_eq!(from_value(&Value::from("01")).unwrap(), vec![1]);
        assert_eq!(from_value(&Value::from(1)), Err(HexError::NotAString));
    }
}
