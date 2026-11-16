//! RFC 4648's base32, upper case, without padding, as the QR code and the
//! setup code write it (admission.md, "The QR code", "The setup code").

use crate::{AdmissionClass, malformed};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The base32 text of `bytes`, upper case, without padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The bytes of a base32 text that re-encodes to itself: a nonempty text of
/// the alphabet's characters, of a length a byte string has, with zero
/// trailing bits.
///
/// # Errors
///
/// `Malformed` for anything else.
pub fn decode(text: &str) -> Result<Vec<u8>, AdmissionClass> {
    if text.is_empty() {
        return Err(malformed());
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.bytes() {
        let value = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(malformed)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if encode(&out) != text {
        return Err(malformed());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_examples() {
        for (raw, text) in [
            (&b"f"[..], "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(encode(raw), text);
            assert_eq!(decode(text).unwrap(), raw);
        }
    }

    #[test]
    fn refuses_other_texts() {
        for text in ["", "my", "MZ", "M", "MZXW6=", "MZXW6YQ1"] {
            assert!(decode(text).is_err(), "{text}");
        }
    }
}
