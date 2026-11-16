//! Small helpers the modules share.

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    frasil_base::notation::hex::encode(bytes)
}

/// Exactly `N` bytes from lowercase hex.
pub(crate) fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N || text.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    frasil_base::notation::hex::decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
}

/// Logs a line to standard error. A peer logs no token, proof or content.
pub(crate) fn log(line: impl core::fmt::Display) {
    eprintln!("frasil-relay: {line}");
}
