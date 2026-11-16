//! The notation (overview.md, "Notation"): fixed-width big-endian integers,
//! Frasil's length-prefixed field, lowercase hex, and the rule for text.

use crate::cbor::Malformed;

/// `u8(n)`: `n` as one byte.
pub fn u8(n: u8) -> [u8; 1] {
    [n]
}

/// `u16be(n)`: `n` as 2 big-endian bytes.
pub fn u16be(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

/// `u32be(n)`: `n` as 4 big-endian bytes.
pub fn u32be(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

/// `u64be(n)`: `n` as 8 big-endian bytes.
pub fn u64be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

/// `field(x) = u32be(len(x)) || x`: Frasil's length-prefixed field.
///
/// # Panics
///
/// If `x` is 2^32 bytes or longer, which no Frasil format allows.
pub fn field(x: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + x.len());
    push_field(&mut out, x);
    out
}

/// Appends `field(x)` to `out`.
///
/// # Panics
///
/// If `x` is 2^32 bytes or longer, which no Frasil format allows.
pub fn push_field(out: &mut Vec<u8>, x: &[u8]) {
    let length = u32::try_from(x.len()).expect("a field is shorter than 2^32 bytes");
    out.extend_from_slice(&u32be(length));
    out.extend_from_slice(x);
}

/// Splits one `field(x)` off the front of `input`: returns `x` and the rest.
/// `Malformed` if the input is shorter than its prefix says.
pub fn split_field(input: &[u8]) -> Result<(&[u8], &[u8]), Malformed> {
    let (prefix, rest) = input.split_first_chunk::<4>().ok_or(Malformed)?;
    let length = usize::try_from(u32::from_be_bytes(*prefix)).map_err(|_| Malformed)?;
    if rest.len() < length {
        return Err(Malformed);
    }
    Ok(rest.split_at(length))
}

/// Whether `text` is 1 to `max` bytes of UTF-8 with no control character
/// (Unicode category Cc) and not only white space (the property
/// `White_Space`): the rule of every bounded text a format holds, such as a
/// name, a label or a subject.
pub fn text_ok(text: &str, max: usize) -> bool {
    (1..=max).contains(&text.len())
        && !text.chars().any(char::is_control)
        && !text.chars().all(char::is_whitespace)
}

/// Lowercase hex, two digits per byte.
pub mod hex {
    use crate::cbor::Malformed;

    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    /// Encodes bytes as lowercase hex.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 15)]));
        }
        out
    }

    fn digit(c: u8) -> Result<u8, Malformed> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(Malformed),
        }
    }

    /// Decodes lowercase hex. An odd length, an upper-case digit or any
    /// other character is `Malformed`.
    pub fn decode(text: &str) -> Result<Vec<u8>, Malformed> {
        let (pairs, rest) = text.as_bytes().as_chunks::<2>();
        if !rest.is_empty() {
            return Err(Malformed);
        }
        pairs
            .iter()
            .map(|[high, low]| Ok((digit(*high)? << 4) | digit(*low)?))
            .collect()
    }

    /// Decodes lowercase hex of exactly `N` bytes.
    pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], Malformed> {
        decode(text)?.try_into().map_err(|_| Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_big_endian() {
        assert_eq!(u8(7), [7]);
        assert_eq!(u16be(0x0102), [1, 2]);
        assert_eq!(u32be(0x0102_0304), [1, 2, 3, 4]);
        assert_eq!(u64be(1), [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn fields_are_length_prefixed() {
        assert_eq!(field(b""), [0, 0, 0, 0]);
        assert_eq!(field(b"ed25519"), b"\x00\x00\x00\x07ed25519");
        let mut joined = field(b"ab");
        push_field(&mut joined, b"c");
        let (first, rest) = split_field(&joined).unwrap();
        assert_eq!(first, b"ab");
        let (second, rest) = split_field(rest).unwrap();
        assert_eq!((second, rest), (&b"c"[..], &b""[..]));
        assert_eq!(split_field(&[0, 0, 0]), Err(Malformed));
        assert_eq!(split_field(&[0, 0, 0, 2, 1]), Err(Malformed));
    }

    #[test]
    fn hex_is_lower_case() {
        assert_eq!(hex::encode([0x00, 0xab, 0xff]), "00abff");
        assert_eq!(hex::decode("00abff"), Ok(vec![0x00, 0xab, 0xff]));
        assert_eq!(hex::decode(""), Ok(vec![]));
        assert_eq!(hex::decode("00AB"), Err(Malformed));
        assert_eq!(hex::decode("abc"), Err(Malformed));
        assert_eq!(hex::decode("zz"), Err(Malformed));
        assert_eq!(hex::decode_array::<2>("0102"), Ok([1, 2]));
        assert_eq!(hex::decode_array::<3>("0102"), Err(Malformed));
    }
}
