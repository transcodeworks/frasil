//! Section 2.1, Values: each form as a check.

use loro::LoroValue;

/// The longest name, in bytes of UTF-8.
pub const MAX_NAME_BYTES: usize = 255;
/// The longest kind string, in bytes of UTF-8.
pub const MAX_KIND_BYTES: usize = 64;
/// The longest media type, in bytes.
pub const MAX_MEDIA_TYPE_BYTES: usize = 255;
/// The longest meta key, in bytes of UTF-8.
pub const MAX_META_KEY_BYTES: usize = 255;

/// The most parents a version record names (section 2.4).
pub const MAX_PARENTS: usize = 64;
/// The largest count: 2^53 − 1.
pub const MAX_COUNT: u64 = (1 << 53) - 1;

/// Unicode's control characters (category Cc): C0, DEL and C1.
fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

/// Unicode's `White_Space` property.
fn is_white_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn lower_hex(text: &str, digits: usize) -> bool {
    text.len() == digits && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A name: 1 to 255 bytes of UTF-8, without `/` or a control character.
pub fn is_name(text: &str) -> bool {
    (1..=MAX_NAME_BYTES).contains(&text.len()) && !text.chars().any(|c| c == '/' || is_control(c))
}

/// A kind string: 1 to 64 bytes of UTF-8, without a control character or
/// white space.
pub fn is_kind_string(text: &str) -> bool {
    (1..=MAX_KIND_BYTES).contains(&text.len())
        && !text.chars().any(|c| is_control(c) || is_white_space(c))
}

/// An entry ID: 32 lower-case hexadecimal digits.
pub fn is_entry_id(text: &str) -> bool {
    lower_hex(text, 32)
}

/// A stream ID: 32 lower-case hexadecimal digits, not all zero.
pub fn is_stream_id(text: &str) -> bool {
    lower_hex(text, 32) && text.bytes().any(|b| b != b'0')
}

/// A blob's handle: 32 lower-case hexadecimal digits.
pub fn is_handle(text: &str) -> bool {
    lower_hex(text, 32)
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b)
}

/// A media type: at most 255 bytes, `token/token`, optionally followed by
/// `;` and printable ASCII.
pub fn is_media_type(text: &str) -> bool {
    if text.len() > MAX_MEDIA_TYPE_BYTES {
        return false;
    }
    let (essence, parameters) = match text.split_once(';') {
        Some((essence, parameters)) => (essence, Some(parameters)),
        None => (text, None),
    };
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    let token = |part: &str| !part.is_empty() && part.bytes().all(is_token_byte);
    token(kind)
        && token(subtype)
        && parameters.is_none_or(|rest| rest.bytes().all(|b| (0x20..=0x7e).contains(&b)))
}

/// A meta key: 1 to 255 bytes of UTF-8, without a control character.
pub fn is_meta_key(text: &str) -> bool {
    (1..=MAX_META_KEY_BYTES).contains(&text.len()) && !text.chars().any(is_control)
}

/// A meta value: a Loro value that is not a container, at any depth.
pub fn is_meta_value(value: &LoroValue) -> bool {
    match value {
        LoroValue::Container(_) => false,
        LoroValue::List(items) => items.iter().all(is_meta_value),
        LoroValue::Map(map) => map.values().all(is_meta_value),
        _ => true,
    }
}

/// A count as a reader reads it: an `I64` in range, or a `Double` that
/// holds one.
pub fn read_count(value: &LoroValue) -> Option<u64> {
    match value {
        LoroValue::I64(n) => u64::try_from(*n).ok().filter(|n| *n <= MAX_COUNT),
        LoroValue::Double(n) if n.fract() == 0.0 && (0.0..=MAX_COUNT as f64).contains(n) => {
            Some(*n as u64)
        }
        _ => None,
    }
}
