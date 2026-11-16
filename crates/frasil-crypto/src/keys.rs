//! The checks every public key passes where it enters (crypto.md, "Ed25519
//! public keys", "X25519 public keys", "X-Wing and ML-DSA-65 public keys"
//! and "Where keys are checked").
//!
//! A key is checked once, where it enters, and a structure that names a
//! refused key is invalid for every verifier. A key is not checked again
//! when it is used or when it signs, and a key that fails is never
//! canonicalised into one that passes. So one key has exactly one byte
//! string, and rules that compare keys by their bytes compare keys.
//!
//! [`ed25519_valid`], [`x25519_valid`] and [`xwing_valid`] give the class a
//! refusal is, `InvalidKey`; [`check_ed25519`] and [`check_x25519`] also
//! name the step that refused, in the document's order. [`mldsa_valid`] is a
//! shape check, `Malformed`. [`x25519_at_use`] is the rule for an X25519
//! shared secret computed outside X-Wing.

use crate::sizes::{ED25519_PUBLIC, MLDSA65_PUBLIC, XWING_PUBLIC};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use frasil_base::ErrorClass;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// `p = 2^255 − 19`, little-endian, as field elements are encoded.
pub const P: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// `ℓ = 2^252 + 27742317777372353535851937790883648493`, the order of the
/// Ed25519 base point and of the X25519 base point `u = 9`, little-endian.
pub const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `d = −121665/121666 mod p`, Edwards25519's curve constant, little-endian.
pub const D: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

/// Bytes of an ML-KEM-768 encapsulation key, the first part of an X-Wing
/// key.
pub const MLKEM768_PUBLIC: usize = 1184;

/// ML-KEM's modulus `q`.
const Q: u16 = 3329;

/// Whether the little-endian integer `value` is less than p.
fn below_p(value: &[u8; 32]) -> bool {
    for (byte, limit) in value.iter().zip(P.iter()).rev() {
        if byte != limit {
            return byte < limit;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Ed25519

/// A step of `ed25519_valid`, in order. Its name is the vectors' name for
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ed25519Step {
    /// 1. `len(k) = 32`.
    LengthOk,
    /// 2. `k` decodes as RFC 8032, section 5.1.3, says, exactly.
    Decodes,
    /// 3. Re-encoding the point gives `k`.
    Canonical,
    /// 4. `[8]P ≠ O`: the point is not of small order.
    SmallOrder,
    /// 5. `[ℓ]P = O`: the point is torsion-free.
    TorsionFree,
}

impl Ed25519Step {
    /// The step's name in the vectors, such as `small_order`.
    pub fn name(self) -> &'static str {
        match self {
            Self::LengthOk => "length_ok",
            Self::Decodes => "decodes",
            Self::Canonical => "canonical",
            Self::SmallOrder => "small_order",
            Self::TorsionFree => "torsion_free",
        }
    }
}

/// `ed25519_valid(k)`, naming the first step that refuses `k`.
///
/// # Errors
///
/// The first step that fails, in the document's order.
pub fn check_ed25519(k: &[u8]) -> Result<(), Ed25519Step> {
    let bytes: &[u8; ED25519_PUBLIC] = k.try_into().map_err(|_| Ed25519Step::LengthOk)?;
    let point = decode_ed25519(bytes).ok_or(Ed25519Step::Decodes)?;
    if point.compress().to_bytes() != *bytes {
        return Err(Ed25519Step::Canonical);
    }
    if point.is_small_order() {
        return Err(Ed25519Step::SmallOrder);
    }
    if !point.is_torsion_free() {
        return Err(Ed25519Step::TorsionFree);
    }
    Ok(())
}

/// `ed25519_valid(k)` (crypto.md, "Ed25519 public keys").
///
/// # Errors
///
/// `InvalidKey` for any key a step refuses.
pub fn ed25519_valid(k: &[u8]) -> Result<(), ErrorClass> {
    check_ed25519(k).map_err(|_| ErrorClass::InvalidKey)
}

/// Each step of `ed25519_valid` evaluated on its own, as the vectors record
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Steps {
    /// Step 1.
    pub length_ok: bool,
    /// Step 2. False for a key of another length.
    pub decodes: bool,
    /// Step 3. False when step 2 fails.
    pub canonical: bool,
    /// Whether the point is of small order (step 4 refuses it), or `None`
    /// when step 2 fails.
    pub small_order: Option<bool>,
    /// Whether the point is torsion-free (step 5 requires it), or `None`
    /// when step 2 fails.
    pub torsion_free: Option<bool>,
}

/// Every step of `ed25519_valid` on `k`, each on its own.
pub fn ed25519_steps(k: &[u8]) -> Ed25519Steps {
    let point = <&[u8; ED25519_PUBLIC]>::try_from(k)
        .ok()
        .and_then(|bytes| decode_ed25519(bytes).map(|point| (bytes, point)));
    Ed25519Steps {
        length_ok: k.len() == ED25519_PUBLIC,
        decodes: point.is_some(),
        canonical: point.is_some_and(|(bytes, point)| point.compress().to_bytes() == *bytes),
        small_order: point.map(|(_, point)| point.is_small_order()),
        torsion_free: point.map(|(_, point)| point.is_torsion_free()),
    }
}

/// RFC 8032, section 5.1.3, decoding, exactly: `y < p`, a square root that
/// exists, and not `x = 0` with the sign bit set. curve25519-dalek's
/// decompression reduces `y` modulo `p` and applies the sign bit even when
/// `x` is 0; both encodings are refused here, before and after it.
pub(crate) fn decode_ed25519(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let sign = bytes[31] >> 7;
    let mut y = *bytes;
    y[31] &= 0x7f;
    if !below_p(&y) {
        return None;
    }
    let point = CompressedEdwardsY(*bytes).decompress()?;
    // x = 0 exactly when the point is its own negation: (0, 1) and (0, −1).
    if sign == 1 && point == -point {
        return None;
    }
    Some(point)
}

// ---------------------------------------------------------------------------
// X25519

/// A step of `x25519_valid`, in order. Its name is the vectors' name for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X25519Step {
    /// 1. `len(k) = 32`.
    LengthOk,
    /// 2. Bit 255 of `k` is 0.
    TopBitClear,
    /// 3. `u < p`.
    BelowP,
    /// 4. `u ≠ 0`, and `[ℓ]P = O`: the point is of order `ℓ`.
    PrimeOrder,
}

impl X25519Step {
    /// The step's name in the vectors, such as `prime_order`.
    pub fn name(self) -> &'static str {
        match self {
            Self::LengthOk => "length_ok",
            Self::TopBitClear => "top_bit_clear",
            Self::BelowP => "below_p",
            Self::PrimeOrder => "prime_order",
        }
    }
}

/// `x25519_valid(k)`, naming the first step that refuses `k`.
///
/// # Errors
///
/// The first step that fails, in the document's order.
pub fn check_x25519(k: &[u8]) -> Result<(), X25519Step> {
    let bytes: &[u8; 32] = k.try_into().map_err(|_| X25519Step::LengthOk)?;
    if bytes[31] & 0x80 != 0 {
        return Err(X25519Step::TopBitClear);
    }
    if !below_p(bytes) {
        return Err(X25519Step::BelowP);
    }
    if !prime_order(bytes) {
        return Err(X25519Step::PrimeOrder);
    }
    Ok(())
}

/// `x25519_valid(k)` (crypto.md, "X25519 public keys").
///
/// # Errors
///
/// `InvalidKey` for any key a step refuses.
pub fn x25519_valid(k: &[u8]) -> Result<(), ErrorClass> {
    check_x25519(k).map_err(|_| ErrorClass::InvalidKey)
}

/// Each step of `x25519_valid` evaluated on its own, as the vectors record
/// them. `None` for a key of another length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519Steps {
    /// Step 2.
    pub top_bit_clear: bool,
    /// Step 3, on `k` with bit 255 cleared.
    pub below_p: bool,
    /// Step 4, for `u = k` with bit 255 cleared, modulo `p`.
    pub prime_order: bool,
}

/// Every step of `x25519_valid` on `k`, each on its own, or `None` for a key
/// of another length than 32 bytes.
pub fn x25519_steps(k: &[u8]) -> Option<X25519Steps> {
    let bytes: &[u8; 32] = k.try_into().ok()?;
    let mut u = *bytes;
    u[31] &= 0x7f;
    Some(X25519Steps {
        top_bit_clear: bytes[31] & 0x80 == 0,
        below_p: below_p(&u),
        prime_order: prime_order(&u),
    })
}

/// Step 4 for a u-coordinate with bit 255 clear: `u ≠ 0 (mod p)` and
/// `[ℓ]P = O`.
///
/// `[ℓ]P` is computed on the Edwards form of the curve: the birational map
/// from Curve25519 to Edwards25519 is an isomorphism of their groups of
/// points, so a point has order `ℓ` on one exactly when its image has order
/// `ℓ` on the other, and curve25519-dalek's torsion check computes `[ℓ]P` in
/// projective coordinates. `to_edwards` refuses the u-coordinates of the
/// twist, `u = −1` among them. curve25519-dalek's own Montgomery ladder
/// returns an affine `u`, which is 0 both for the point at infinity and for
/// `(0, 0)`, so it cannot tell them apart without the projective `Z` that
/// the document's ladder keeps; `u = 0`, for which the ladder degenerates, is
/// refused explicitly, as the document does.
fn prime_order(u: &[u8; 32]) -> bool {
    if *u == [0; 32] || *u == P {
        return false;
    }
    MontgomeryPoint(*u)
        .to_edwards(0)
        .is_some_and(|point| !point.is_small_order() && point.is_torsion_free())
}

/// `x25519_at_use(secret, public)`: the X25519 function, exactly as RFC
/// 7748, section 5, then the refusal of an all-zero result. Only an
/// extension that computes an X25519 shared secret outside X-Wing needs it;
/// no protocol 1 format does.
///
/// # Errors
///
/// `Decrypt` if the shared secret is 32 zero bytes.
pub fn x25519_at_use(
    secret: &[u8; 32],
    public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, ErrorClass> {
    let secret = x25519_dalek::StaticSecret::from(*secret);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*public));
    if bool::from(shared.as_bytes().ct_eq(&[0; 32])) {
        return Err(ErrorClass::Decrypt);
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

// ---------------------------------------------------------------------------
// X-Wing and ML-DSA-65

/// `xwing_valid(k)` (crypto.md, "X-Wing and ML-DSA-65 public keys"): 1,216
/// bytes; every 12-bit coefficient of the ML-KEM-768 encapsulation key below
/// `q` (FIPS 203, section 7.2); and its X25519 part valid.
///
/// # Errors
///
/// `InvalidKey` for any key a step refuses.
pub fn xwing_valid(k: &[u8]) -> Result<(), ErrorClass> {
    if k.len() != XWING_PUBLIC {
        return Err(ErrorClass::InvalidKey);
    }
    if !mlkem768_coefficients_valid(&k[..MLKEM768_PUBLIC]) {
        return Err(ErrorClass::InvalidKey);
    }
    x25519_valid(&k[MLKEM768_PUBLIC..])
}

/// FIPS 203, section 7.2, the encapsulation key check: every 12-bit
/// coefficient of `ek[0..1152]` is below `q`, which holds exactly when
/// `ByteEncode12(ByteDecode12(ek[0..1152])) = ek[0..1152]`. The last 32
/// bytes, the seed `ρ`, are any bytes.
fn mlkem768_coefficients_valid(key: &[u8]) -> bool {
    key[..MLKEM768_PUBLIC - 32].chunks_exact(3).all(|bytes| {
        let first = u16::from(bytes[0]) | (u16::from(bytes[1] & 0x0f) << 8);
        let second = u16::from(bytes[1] >> 4) | (u16::from(bytes[2]) << 4);
        first < Q && second < Q
    })
}

/// `mldsa_valid(k)`: 1,952 bytes. Every such string decodes as an ML-DSA-65
/// public key (FIPS 204, Algorithm 23, has no failure case), so the length is
/// the whole check. It runs with the shape checks of the structure that
/// names the key.
///
/// # Errors
///
/// `Malformed` for another length.
pub fn mldsa_valid(k: &[u8]) -> Result<(), ErrorClass> {
    if k.len() == MLDSA65_PUBLIC {
        Ok(())
    } else {
        Err(ErrorClass::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::Scalar;

    /// p + `offset`, for an offset of at most 18 (p ends in 0xed).
    fn p_plus(offset: u8) -> [u8; 32] {
        let mut value = P;
        value[0] += offset;
        value
    }

    #[test]
    fn p_is_the_first_value_refused_as_unreduced() {
        let mut below = P;
        below[0] -= 1;
        assert!(below_p(&below));
        assert!(!below_p(&P));
        assert!(!below_p(&p_plus(18)));
        assert!(below_p(&[0; 32]));
        assert_eq!(check_x25519(&P), Err(X25519Step::BelowP));
    }

    #[test]
    fn l_is_the_group_order() {
        assert!(bool::from(Scalar::from_canonical_bytes(L).is_none()));
        let mut below = L;
        below[0] -= 1;
        assert!(bool::from(Scalar::from_canonical_bytes(below).is_some()));
    }

    #[test]
    fn honest_keys_pass() {
        for byte in 0..=255u8 {
            let seed = [byte; 32];
            assert_eq!(
                check_ed25519(&crate::primitives::ed25519_public(&seed)),
                Ok(())
            );
            let exchange = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seed));
            assert_eq!(check_x25519(exchange.as_bytes()), Ok(()));
        }
    }

    #[test]
    fn every_length_but_32_is_refused() {
        for length in [0, 1, 31, 33, 64] {
            let key = vec![9; length];
            assert_eq!(check_ed25519(&key), Err(Ed25519Step::LengthOk));
            assert_eq!(check_x25519(&key), Err(X25519Step::LengthOk));
            assert_eq!(ed25519_valid(&key), Err(ErrorClass::InvalidKey));
            assert_eq!(x25519_valid(&key), Err(ErrorClass::InvalidKey));
            assert_eq!(x25519_steps(&key), None);
        }
    }

    #[test]
    fn the_encodings_a_lenient_decoder_accepts_are_refused() {
        // y = 1 is the neutral point; y = p + 1 decodes to it under dalek.
        let lenient = p_plus(1);
        assert!(CompressedEdwardsY(lenient).decompress().is_some());
        assert_eq!(check_ed25519(&lenient), Err(Ed25519Step::Decodes));
        // x = 0 with the sign bit set: the neutral point again.
        let mut signed = [0; 32];
        signed[0] = 1;
        signed[31] = 0x80;
        assert!(CompressedEdwardsY(signed).decompress().is_some());
        assert_eq!(check_ed25519(&signed), Err(Ed25519Step::Decodes));
        // Without the sign bit it decodes, and is refused for its order.
        signed[31] = 0;
        assert_eq!(check_ed25519(&signed), Err(Ed25519Step::SmallOrder));
    }

    #[test]
    fn the_mlkem_modulus_check_refuses_a_coefficient_of_q_or_more() {
        let x25519 =
            *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([9; 32])).as_bytes();
        let mut key = [0u8; XWING_PUBLIC];
        key[MLKEM768_PUBLIC..].copy_from_slice(&x25519);
        assert_eq!(xwing_valid(&key), Ok(()));
        // 3328 = q − 1 in the first coefficient: accepted.
        key[1] = 0x0d;
        assert_eq!(xwing_valid(&key), Ok(()));
        // 3329 = q: refused.
        key[0] = 0x01;
        assert_eq!(xwing_valid(&key), Err(ErrorClass::InvalidKey));
        // The second coefficient of a group: 0xfff.
        key[0] = 0;
        key[1] = 0xf0;
        key[2] = 0xff;
        assert_eq!(xwing_valid(&key), Err(ErrorClass::InvalidKey));
        // ρ is any bytes.
        let mut key = [0u8; XWING_PUBLIC];
        key[MLKEM768_PUBLIC..].copy_from_slice(&x25519);
        key[MLKEM768_PUBLIC - 32..MLKEM768_PUBLIC].fill(0xff);
        assert_eq!(xwing_valid(&key), Ok(()));
        assert_eq!(xwing_valid(&key[1..]), Err(ErrorClass::InvalidKey));
    }

    #[test]
    fn an_mldsa_key_is_checked_by_its_length() {
        assert_eq!(mldsa_valid(&[0; MLDSA65_PUBLIC]), Ok(()));
        assert_eq!(
            mldsa_valid(&[0; MLDSA65_PUBLIC - 1]),
            Err(ErrorClass::Malformed)
        );
        assert_eq!(
            mldsa_valid(&[0; MLDSA65_PUBLIC + 1]),
            Err(ErrorClass::Malformed)
        );
    }
}
