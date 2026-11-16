//! Tokens (ext-deposit-tokens.md, 2.4 Tokens).
//!
//! ```text
//! nonce         = 32 random bytes, drawn by the device for each token
//! input         = "frasil/deposit-token/v1" || key ID || nonce             87 bytes
//! authenticator = Finalize's output for this element (section 2.1)          64 bytes
//! token         = u8(0x01) || key ID (32) || nonce (32) || authenticator (64)
//!                                                                          129 bytes
//! ```
//!
//! On the server binding a token travels as `Authorization: Frasil-Token
//! <258 lowercase hex>` (2.5 Messages, "The server binding").

use core::fmt;

use frasil_crypto::labels::DEPOSIT_TOKEN;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::{TokenClass, malformed};
use crate::key::{KEY_ID_BYTES, KeyId};
use crate::suite::OUTPUT_BYTES;

/// The bytes of a nonce.
pub const NONCE_BYTES: usize = 32;

/// The bytes of a token's VOPRF input: 87.
pub const INPUT_BYTES: usize = DEPOSIT_TOKEN.len() + KEY_ID_BYTES + NONCE_BYTES;

/// The bytes of a token: 129.
pub const TOKEN_BYTES: usize = 1 + KEY_ID_BYTES + NONCE_BYTES + OUTPUT_BYTES;

/// Byte 0 of a token: its version.
pub const TOKEN_VERSION: u8 = 0x01;

/// The `Authorization` scheme of a token, followed by one space and the
/// token in lowercase hex.
pub const HEADER_PREFIX: &str = "Frasil-Token ";

/// A token's VOPRF input: `"frasil/deposit-token/v1" || key ID || nonce`.
pub fn token_input(key_id: &KeyId, nonce: &[u8; NONCE_BYTES]) -> Zeroizing<Vec<u8>> {
    let mut input = Zeroizing::new(Vec::with_capacity(INPUT_BYTES));
    input.extend_from_slice(DEPOSIT_TOKEN);
    input.extend_from_slice(key_id);
    input.extend_from_slice(nonce);
    input
}

/// A token: one deposit's payment at the peer that issued it, while its
/// key lives. It is a bearer secret until spent, so it is zeroized when
/// dropped and its `Debug` shows only its key ID.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Token {
    bytes: [u8; TOKEN_BYTES],
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Token")
            .field("version", &self.version())
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl Token {
    /// A token of version 1 from its parts.
    pub fn new(
        key_id: &KeyId,
        nonce: &[u8; NONCE_BYTES],
        authenticator: &[u8; OUTPUT_BYTES],
    ) -> Self {
        let mut bytes = [0; TOKEN_BYTES];
        bytes[0] = TOKEN_VERSION;
        bytes[1..33].copy_from_slice(key_id);
        bytes[33..65].copy_from_slice(nonce);
        bytes[65..].copy_from_slice(authenticator);
        Self { bytes }
    }

    /// A token of 129 bytes, of any version: section 3.7, step 1.
    ///
    /// # Errors
    ///
    /// `Malformed` for any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenClass> {
        Ok(Self {
            bytes: bytes.try_into().map_err(|_| malformed())?,
        })
    }

    /// The token's bytes.
    pub fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.bytes
    }

    /// Byte 0: the version.
    pub fn version(&self) -> u8 {
        self.bytes[0]
    }

    /// The key ID.
    pub fn key_id(&self) -> KeyId {
        let mut out = [0; KEY_ID_BYTES];
        out.copy_from_slice(&self.bytes[1..33]);
        out
    }

    /// The nonce.
    pub fn nonce(&self) -> [u8; NONCE_BYTES] {
        let mut out = [0; NONCE_BYTES];
        out.copy_from_slice(&self.bytes[33..65]);
        out
    }

    /// The authenticator.
    pub fn authenticator(&self) -> &[u8] {
        &self.bytes[65..]
    }

    /// The token's VOPRF input.
    pub fn input(&self) -> Zeroizing<Vec<u8>> {
        token_input(&self.key_id(), &self.nonce())
    }

    /// The server binding's `Authorization` value: `Frasil-Token` and the
    /// token in lowercase hex.
    pub fn header(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = Zeroizing::new(String::with_capacity(HEADER_PREFIX.len() + 2 * TOKEN_BYTES));
        out.push_str(HEADER_PREFIX);
        for byte in self.bytes {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
        out
    }

    /// Reads the server binding's `Authorization` value: section 3.7, step
    /// 1, on that binding. It reads as one token of 129 bytes: exactly
    /// `Frasil-Token`, one space, and 258 lowercase hex digits.
    ///
    /// # Errors
    ///
    /// `Malformed` for anything else.
    pub fn from_header(value: &str) -> Result<Self, TokenClass> {
        let digits = value.strip_prefix(HEADER_PREFIX).ok_or_else(malformed)?;
        let digits = digits.as_bytes();
        if digits.len() != 2 * TOKEN_BYTES {
            return Err(malformed());
        }
        let mut bytes = [0; TOKEN_BYTES];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks_exact(2)) {
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self { bytes })
    }
}

fn nibble(digit: u8) -> Result<u8, TokenClass> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(malformed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_reads_back_from_its_header() {
        let token = Token::new(&[1; 32], &[2; 32], &[3; 64]);
        assert_eq!(INPUT_BYTES, 87);
        assert_eq!(TOKEN_BYTES, 129);
        let header = token.header();
        assert_eq!(header.len(), 13 + 258);
        assert_eq!(Token::from_header(&header).unwrap(), token);
        assert_eq!(token.input().len(), INPUT_BYTES);
        for bad in [
            header.to_uppercase(),
            header.replace("Frasil-Token ", "Frasil-Token  "),
            header.replace("Frasil-Token ", "frasil-token "),
            header[..header.len() - 2].to_owned(),
            format!("{}00", &*header),
            header.replacen('0', "g", 1),
        ] {
            assert_eq!(Token::from_header(&bad), Err(malformed()), "{bad}");
        }
        assert_eq!(Token::from_bytes(&[1; 128]), Err(malformed()));
    }
}
