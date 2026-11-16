//! Fingerprints (identity.md, "Fingerprints" and "Comparing fingerprints").
//!
//! A fingerprint is 120 bits of a hash of a person ID and one list member's
//! or device's keys, written as 24 characters and a check character:
//!
//! ```text
//! digest_input = "frasil/key-fingerprint/v1" || person_id (32) || identity (32)
//!                || field(mldsa) || field(xwing)
//! digest       = SHA-256(digest_input)
//! value        = digest[0..15], as a big-endian 120-bit integer
//! d_i          = (value >> (5 · (23 − i))) & 31,        for i = 0 to 23
//! d_24         = check(d_0, ..., d_23)
//! character_i  = ALPHABET[d_i],                         for i = 0 to 24
//! ```
//!
//! The check symbol makes `d_0·x^24 + d_1·x^23 + ... + d_24 = 0` in GF(32),
//! modulo `x^5 + x^2 + 1`. Two fingerprints are equal when their 120-bit
//! values are equal.

use crate::IdentityClass;
use frasil_base::ErrorClass;
use frasil_base::notation::push_field;
use frasil_crypto::keys::{ed25519_valid, xwing_valid};
use frasil_crypto::labels::KEY_FINGERPRINT;
use frasil_crypto::primitives::sha256;
use frasil_crypto::sizes::MLDSA65_PUBLIC;

/// The 32 characters, in symbol order.
pub const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";

/// The QR form's prefix.
pub const QR_PREFIX: &str = "FRASIL-FP1:";

/// GF(32)'s modulus, `x^5 + x^2 + 1`.
pub const GF32_MODULUS: u8 = 37;

/// The longest text [`Fingerprint::parse`] reads.
pub const MAX_INPUT: usize = 128;

/// The value symbols; the check symbol follows them.
pub const VALUE_SYMBOLS: usize = 24;

/// The bits of a fingerprint's value.
pub const BITS: u32 = 120;

/// `times_x(s)`: `s · x` in GF(32).
pub const fn times_x(s: u8) -> u8 {
    let t = s << 1;
    if t >= 32 { t ^ GF32_MODULUS } else { t }
}

/// `check(d_0, ..., d_23)`: the check symbol of the 24 value symbols.
pub fn check(symbols: &[u8; VALUE_SYMBOLS]) -> u8 {
    let mut acc = 0;
    for d in symbols {
        acc = times_x(acc) ^ d;
    }
    times_x(acc)
}

/// The digest input of a fingerprint: for a list `add`, the list's person ID
/// and the keys it names, `xwing` empty for an agent; for a roster grant of a
/// device, 32 zero bytes and the keys it names.
pub fn digest_input(
    person_id: &[u8; 32],
    identity: &[u8; 32],
    mldsa: &[u8],
    xwing: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_FINGERPRINT.len() + 72 + mldsa.len() + xwing.len());
    out.extend_from_slice(KEY_FINGERPRINT);
    out.extend_from_slice(person_id);
    out.extend_from_slice(identity);
    push_field(&mut out, mldsa);
    push_field(&mut out, xwing);
    out
}

/// A fingerprint: its 120-bit value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(u128);

impl Fingerprint {
    /// The fingerprint of a person ID and keys. Every key passes its check
    /// first, so a list member has one fingerprint: `identity` passes
    /// `ed25519_valid`, `mldsa` is 1,952 bytes, and `xwing`, unless empty
    /// for an agent, passes `xwing_valid`.
    ///
    /// # Errors
    ///
    /// `InvalidPersonId` for a person ID of another length than 32 bytes,
    /// then `InvalidKey` for a key that fails its check.
    pub fn of(
        person_id: &[u8],
        identity: &[u8],
        mldsa: &[u8],
        xwing: &[u8],
    ) -> Result<Self, IdentityClass> {
        let person_id: &[u8; 32] = person_id
            .try_into()
            .map_err(|_| IdentityClass::InvalidPersonId)?;
        let invalid = IdentityClass::Shared(ErrorClass::InvalidKey);
        ed25519_valid(identity)?;
        let identity: &[u8; 32] = identity.try_into().map_err(|_| invalid)?;
        if mldsa.len() != MLDSA65_PUBLIC {
            return Err(invalid);
        }
        if !xwing.is_empty() {
            xwing_valid(xwing)?;
        }
        let digest = sha256(&[&digest_input(person_id, identity, mldsa, xwing)]);
        let mut value = [0u8; 16];
        value[1..].copy_from_slice(&digest[..15]);
        Ok(Self(u128::from_be_bytes(value)))
    }

    /// The fingerprint of a 120-bit value.
    ///
    /// # Panics
    ///
    /// If `value` has more than 120 bits.
    pub fn from_value(value: u128) -> Self {
        assert!(value < 1 << BITS, "a fingerprint's value has 120 bits");
        Self(value)
    }

    /// The 120-bit value.
    pub fn value(&self) -> u128 {
        self.0
    }

    /// The value's 15 bytes, big-endian: the digest's first 15.
    pub fn value_bytes(&self) -> [u8; 15] {
        let mut out = [0; 15];
        out.copy_from_slice(&self.0.to_be_bytes()[1..]);
        out
    }

    /// The 25 symbols: `d_0` to `d_23`, then the check symbol `d_24`.
    pub fn symbols(&self) -> [u8; 25] {
        let mut value = [0u8; VALUE_SYMBOLS];
        for (i, d) in value.iter_mut().enumerate() {
            *d = ((self.0 >> (5 * (VALUE_SYMBOLS - 1 - i))) & 31) as u8;
        }
        let mut out = [0u8; 25];
        out[..VALUE_SYMBOLS].copy_from_slice(&value);
        out[VALUE_SYMBOLS] = check(&value);
        out
    }

    /// The check symbol, `d_24`.
    pub fn check_symbol(&self) -> u8 {
        self.symbols()[VALUE_SYMBOLS]
    }

    /// The 25 characters, lower case, with no separator.
    pub fn characters(&self) -> String {
        self.symbols()
            .iter()
            .map(|d| char::from(ALPHABET[usize::from(*d)]))
            .collect()
    }

    /// The display: five groups of five lower-case characters, joined by
    /// single spaces, the check character last.
    pub fn display(&self) -> String {
        let characters = self.characters();
        let groups: Vec<&str> = (0..5).map(|g| &characters[5 * g..5 * g + 5]).collect();
        groups.join(" ")
    }

    /// The QR form: `FRASIL-FP1:` and the 25 characters in upper case, with
    /// no separator.
    pub fn qr(&self) -> String {
        format!("{QR_PREFIX}{}", self.characters().to_ascii_uppercase())
    }

    /// `parse(text)`, in order:
    /// 1. text has at most 128 characters, all ASCII;
    /// 2. strip leading and trailing space, tab, CR and LF;
    /// 3. if the first 11 characters, compared without case, are
    ///    `FRASIL-FP1:`, remove them;
    /// 4. no `:` remains;
    /// 5. remove every space, tab, CR, LF and `-`; map A–Z to a–z;
    /// 6. exactly 25 characters of the alphabet remain;
    /// 7. `d_24 = check(d_0, ..., d_23)`;
    /// 8. the 120-bit value of `d_0` to `d_23`.
    ///
    /// No character is mapped to another.
    ///
    /// # Errors
    ///
    /// `InvalidFingerprint` at steps 1, 4 and 6; `FingerprintMistyped` at
    /// step 7.
    pub fn parse(text: &str) -> Result<Self, IdentityClass> {
        let invalid = IdentityClass::InvalidFingerprint;
        if text.len() > MAX_INPUT || !text.is_ascii() {
            return Err(invalid);
        }
        let mut s = text.trim_matches([' ', '\t', '\r', '\n']);
        if s.len() >= QR_PREFIX.len() && s[..QR_PREFIX.len()].eq_ignore_ascii_case(QR_PREFIX) {
            s = &s[QR_PREFIX.len()..];
        }
        if s.contains(':') {
            return Err(invalid);
        }
        let mut symbols = [0u8; 25];
        let mut count = 0;
        for byte in s.bytes() {
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'-') {
                continue;
            }
            let lower = byte.to_ascii_lowercase();
            let d = ALPHABET.iter().position(|a| *a == lower).ok_or(invalid)?;
            if count == symbols.len() {
                return Err(invalid);
            }
            symbols[count] = d as u8;
            count += 1;
        }
        if count != symbols.len() {
            return Err(invalid);
        }
        let value: [u8; VALUE_SYMBOLS] = symbols[..VALUE_SYMBOLS].try_into().expect("24 symbols");
        if symbols[VALUE_SYMBOLS] != check(&value) {
            return Err(IdentityClass::FingerprintMistyped);
        }
        Ok(Self(
            value
                .iter()
                .fold(0u128, |acc, d| (acc << 5) | u128::from(*d)),
        ))
    }
}

/// Steps 5 and 6 of "Comparing fingerprints", for the device that will sign
/// the record: recompute the fingerprint of exactly the keys it is about to
/// sign, and compare it with the value the person confirmed. Sign nothing
/// unless this passes.
///
/// # Errors
///
/// [`Fingerprint::of`]'s classes for keys that have no fingerprint, then
/// `FingerprintMismatch`. A check failure is never reported as a mismatch,
/// nor the reverse.
pub fn confirm(
    confirmed: &Fingerprint,
    person_id: &[u8],
    identity: &[u8],
    mldsa: &[u8],
    xwing: &[u8],
) -> Result<(), IdentityClass> {
    if Fingerprint::of(person_id, identity, mldsa, xwing)? == *confirmed {
        Ok(())
    } else {
        Err(IdentityClass::FingerprintMismatch)
    }
}
