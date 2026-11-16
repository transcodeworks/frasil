//! Recovery keys and the recovery sheet (identity.md, "Recovery keys").
//!
//! A recovery key derives from a 32-byte secret that the device creating it
//! draws from its random source:
//!
//! ```text
//! prk            = HKDF-Extract("frasil/recovery/v1", secret)
//! identity seed  = HKDF-Expand(prk, "ed25519", 32)
//! X-Wing seed    = HKDF-Expand(prk, "frasil/recovery-key/hybrid/v1", 32)
//! ML-DSA-65 seed = HKDF-Expand(prk, "frasil/recovery-key/mldsa/v1", 32)
//! fetch seed     = HKDF-Expand(prk, "frasil/recovery-key/fetch/v1", 32)
//! ```
//!
//! The sheet shows the secret in its printed form: base32 (RFC 4648, upper
//! case, no padding) of the secret and the first two bytes of its SHA-256,
//! 55 characters in groups of four joined by `-`.

use crate::IdentityClass;
use crate::keys::{FetchKey, MemberKeys};
use frasil_crypto::labels::{
    RECOVERY, RECOVERY_KEY_FETCH, RECOVERY_KEY_HYBRID, RECOVERY_KEY_MLDSA,
};
use frasil_crypto::primitives::{hkdf_expand, hkdf_extract, sha256};
use zeroize::{Zeroize, Zeroizing};

/// The HKDF info of a recovery key's identity seed.
pub const IDENTITY_INFO: &[u8] = b"ed25519";

/// The printed form's alphabet: RFC 4648's base32.
pub const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The printed form's length without separators.
pub const PRINTED_CHARACTERS: usize = 55;

/// The bytes the printed form encodes: the secret and two check bytes.
const PRINTED_BYTES: usize = 34;

/// A recovery secret: 32 bytes that a device draws, shows on the sheet and
/// then forgets.
pub struct RecoverySecret(Zeroizing<[u8; 32]>);

impl RecoverySecret {
    /// The secret of these bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    /// The secret's bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The printed form: `base32(secret || SHA-256(secret)[0..2])`, 55
    /// characters in groups of four joined by `-`, the last group of three.
    pub fn printed(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new([0u8; PRINTED_BYTES]);
        raw[..32].copy_from_slice(&self.0[..]);
        raw[32..].copy_from_slice(&sha256(&[&self.0[..]])[..2]);
        let mut symbols = Zeroizing::new([0u8; PRINTED_CHARACTERS]);
        for (index, symbol) in symbols.iter_mut().enumerate() {
            *symbol = ALPHABET[usize::from(five_bits(&raw[..], index))];
        }
        let mut out = Zeroizing::new(String::with_capacity(PRINTED_CHARACTERS + 13));
        for (index, symbol) in symbols.iter().enumerate() {
            if index > 0 && index % 4 == 0 {
                out.push('-');
            }
            out.push(char::from(*symbol));
        }
        out
    }

    /// Reads a sheet's printed text: removes spaces and hyphens and maps
    /// `a`–`z` to `A`–`Z`. What remains must be 55 characters of the
    /// alphabet that decode canonically to 34 bytes whose last two are the
    /// first two of SHA-256 of the first 32.
    ///
    /// # Errors
    ///
    /// `InvalidSheet` for any other text.
    pub fn read_sheet(text: &str) -> Result<Self, IdentityClass> {
        let mut symbols = Zeroizing::new([0u8; PRINTED_CHARACTERS]);
        let mut count = 0;
        for c in text.chars().filter(|c| *c != ' ' && *c != '-') {
            let upper = c.to_ascii_uppercase();
            let value = u8::try_from(upper)
                .ok()
                .and_then(|byte| ALPHABET.iter().position(|a| *a == byte))
                .ok_or(IdentityClass::InvalidSheet)?;
            if count == PRINTED_CHARACTERS {
                return Err(IdentityClass::InvalidSheet);
            }
            symbols[count] = u8::try_from(value).expect("an index of 32 symbols");
            count += 1;
        }
        if count != PRINTED_CHARACTERS {
            return Err(IdentityClass::InvalidSheet);
        }
        // 55 symbols carry 275 bits; the 34 bytes take 272, and the last
        // three must be zero for the decoding to be canonical.
        if symbols[PRINTED_CHARACTERS - 1] & 0b111 != 0 {
            return Err(IdentityClass::InvalidSheet);
        }
        let mut raw = Zeroizing::new([0u8; PRINTED_BYTES]);
        let mut acc: u16 = 0;
        let mut bits = 0;
        let mut at = 0;
        for symbol in symbols.iter() {
            acc = (acc << 5) | u16::from(*symbol);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                raw[at] = (acc >> bits) as u8;
                at += 1;
                acc &= (1 << bits) - 1;
            }
        }
        acc.zeroize();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&raw[..32]);
        let out = Self::from_bytes(&secret);
        secret.zeroize();
        if raw[32..] != sha256(&[&out.0[..]])[..2] {
            return Err(IdentityClass::InvalidSheet);
        }
        Ok(out)
    }
}

impl core::fmt::Debug for RecoverySecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoverySecret([redacted])")
    }
}

/// Symbol `index` of base32 over `raw`: bits `5·index` to `5·index + 4`,
/// with zero bits past the end.
fn five_bits(raw: &[u8], index: usize) -> u8 {
    let bit = index * 5;
    let byte = bit / 8;
    let high = u16::from(raw[byte]) << 8;
    let low = raw.get(byte + 1).map_or(0, |b| u16::from(*b));
    let window = high | low;
    ((window >> (11 - bit % 8)) & 31) as u8
}

/// A recovery key: the list member a recovery secret derives, with its
/// fetch key.
pub struct RecoveryKey {
    member: MemberKeys,
    fetch: FetchKey,
}

impl RecoveryKey {
    /// Derives the recovery key of a secret: one extract, then four expands.
    pub fn derive(secret: &RecoverySecret) -> Self {
        let prk = hkdf_extract(RECOVERY, &secret.0[..]);
        let expand = |info: &[u8]| {
            let mut seed = Zeroizing::new([0u8; 32]);
            hkdf_expand(&prk, info, seed.as_mut_slice()).expect("32 bytes is a valid length");
            seed
        };
        let identity = expand(IDENTITY_INFO);
        let xwing = expand(RECOVERY_KEY_HYBRID);
        let mldsa = expand(RECOVERY_KEY_MLDSA);
        let fetch = expand(RECOVERY_KEY_FETCH);
        Self {
            member: MemberKeys::from_seeds(&identity, &xwing, &mldsa),
            fetch: FetchKey::from_seed(&fetch),
        }
    }

    /// The list member's three key pairs.
    pub fn member(&self) -> &MemberKeys {
        &self.member
    }

    /// The fetch key, registered for the personal space.
    pub fn fetch(&self) -> &FetchKey {
        &self.fetch
    }
}

impl core::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryKey")
            .field("member", &self.member)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printed_round_trips() {
        for fill in [0u8, 0xff, 0x5a] {
            let secret = RecoverySecret::from_bytes(&[fill; 32]);
            let printed = secret.printed();
            assert_eq!(printed.len(), PRINTED_CHARACTERS + 13);
            let read = RecoverySecret::read_sheet(&printed).unwrap();
            assert_eq!(read.bytes(), secret.bytes());
        }
    }

    #[test]
    fn refuses_unused_bits() {
        let secret = RecoverySecret::from_bytes(&[7; 32]);
        let mut printed: Vec<u8> = secret.printed().as_bytes().to_vec();
        let last = printed.len() - 1;
        let value = ALPHABET.iter().position(|a| *a == printed[last]).unwrap();
        printed[last] = ALPHABET[value ^ 1];
        let text = String::from_utf8(printed).unwrap();
        assert_eq!(
            RecoverySecret::read_sheet(&text).unwrap_err(),
            IdentityClass::InvalidSheet
        );
        assert!(RecoverySecret::read_sheet("é").is_err());
        assert!(RecoverySecret::read_sheet(&"A".repeat(56)).is_err());
    }
}
