//! The symmetric primitives and Ed25519 (crypto.md, "Primitives").
//!
//! SHA-256, HMAC-SHA256, HKDF-SHA256 and XChaCha20-Poly1305, and Ed25519
//! keys and deterministic signing. X-Wing and HPKE are [`crate::wrap`]'s,
//! ML-DSA-65 is [`crate::mldsa65`]'s, and strict Ed25519 verification
//! (crypto.md, "Strict Ed25519 verification") goes with the signature
//! schemes. Nothing here draws randomness: a nonce comes in as an argument.

use crate::sizes::{XCHACHA20POLY1305_NONCE, XCHACHA20POLY1305_TAG};
use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::aead::{Aead, AeadInOut, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use frasil_base::ErrorClass;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// SHA-256 of the concatenation of `parts`: `SHA-256(a || b || ...)`.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

/// `HMAC(key, message)`: HMAC-SHA256 (RFC 2104), 32 bytes. A document that
/// truncates it says so and truncates the result.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new(key);
    mac.update(message);
    mac.finish()
}

/// SHA-256 over bytes that arrive in pieces: [`sha256`] of their
/// concatenation.
#[derive(Clone, Default)]
pub struct Sha256Hasher(Sha256);

impl core::fmt::Debug for Sha256Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sha256Hasher")
    }
}

impl Sha256Hasher {
    /// A hash of nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// The hash of everything appended.
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// HMAC-SHA256 over a message that arrives in pieces: [`hmac_sha256`] of
/// their concatenation.
#[derive(Clone)]
pub struct HmacSha256(Hmac<Sha256>);

impl core::fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HmacSha256")
    }
}

impl HmacSha256 {
    /// An HMAC under `key` of nothing yet.
    pub fn new(key: &[u8]) -> Self {
        Self(
            <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes a key of any length"),
        )
    }

    /// Appends bytes of the message.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// The HMAC of the whole message.
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into_bytes().into()
    }
}

/// `HKDF(salt, ikm, info)`: HKDF-SHA256 (RFC 5869), extract then expand to
/// 32 bytes. A salt of `None` is the document's `none`: 32 zero bytes.
pub fn hkdf(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let prk = hkdf_extract(salt.unwrap_or(&[0; 32]), ikm);
    let mut okm = Zeroizing::new([0; 32]);
    hkdf_expand(&prk, info, okm.as_mut_slice()).expect("32 bytes is a valid HKDF length");
    okm
}

/// `HKDF-Extract(salt, ikm)`: the 32-byte pseudorandom key.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    Zeroizing::new(prk.into())
}

/// `HKDF-Expand(prk, info, L)`, where `L` is `okm.len()`.
///
/// # Errors
///
/// `Malformed` if `L` is more than 8,160 bytes, the most HKDF-SHA256 gives.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) -> Result<(), ErrorClass> {
    Hkdf::<Sha256>::from_prk(prk)
        .expect("a 32-byte pseudorandom key is valid")
        .expand(info, okm)
        .map_err(|_| ErrorClass::Malformed)
}

/// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03): the ciphertext with its
/// 16-byte tag after it.
pub fn xchacha20poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; XCHACHA20POLY1305_NONCE],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 seals any plaintext Frasil allows")
}

/// [`xchacha20poly1305_seal`] in place: `buffer` holds the plaintext from
/// `start` on, which becomes the ciphertext, with the tag appended.
pub fn xchacha20poly1305_seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; XCHACHA20POLY1305_NONCE],
    aad: &[u8],
    buffer: &mut Vec<u8>,
    start: usize,
) {
    let tag = XChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(&XNonce::from(*nonce), aad, buffer[start..].as_mut().into())
        .expect("XChaCha20-Poly1305 seals any plaintext Frasil allows");
    buffer.extend_from_slice(&tag);
}

/// Opens what [`xchacha20poly1305_seal`] sealed.
///
/// # Errors
///
/// `Decrypt` if the ciphertext is shorter than its tag or does not open
/// under this key, nonce and associated data.
pub fn xchacha20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; XCHACHA20POLY1305_NONCE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ErrorClass> {
    crate::counts::aead_open();
    if ciphertext.len() < XCHACHA20POLY1305_TAG {
        return Err(ErrorClass::Decrypt);
    }
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ErrorClass::Decrypt)
}

/// [`xchacha20poly1305_open`] into `out`, which is as long as the plaintext:
/// the same check, with no buffer of its own. `out` holds the plaintext
/// once the tag verified, and zeros otherwise.
///
/// # Errors
///
/// As [`xchacha20poly1305_open`]; also `Decrypt` when `out` is not the
/// plaintext's length.
pub fn xchacha20poly1305_open_into(
    key: &[u8; 32],
    nonce: &[u8; XCHACHA20POLY1305_NONCE],
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<(), ErrorClass> {
    crate::counts::aead_open();
    let Some(length) = ciphertext.len().checked_sub(XCHACHA20POLY1305_TAG) else {
        return Err(ErrorClass::Decrypt);
    };
    if out.len() != length {
        return Err(ErrorClass::Decrypt);
    }
    let (body, tag) = ciphertext.split_at(length);
    let tag: &[u8; XCHACHA20POLY1305_TAG] = tag.try_into().map_err(|_| ErrorClass::Decrypt)?;
    let buffer = InOutBuf::new(body, out).map_err(|_| ErrorClass::Decrypt)?;
    let opened = XChaCha20Poly1305::new(key.into()).decrypt_inout_detached(
        &XNonce::from(*nonce),
        aad,
        buffer,
        &(*tag).into(),
    );
    if opened.is_err() {
        out.fill(0);
        return Err(ErrorClass::Decrypt);
    }
    Ok(())
}

/// [`xchacha20poly1305_open`] in place: `sealed` is the ciphertext with its
/// tag after it, and once the tag verifies, its first bytes are the
/// plaintext, whose length this returns. Left as it was when the tag does
/// not verify.
///
/// # Errors
///
/// As [`xchacha20poly1305_open`].
pub fn xchacha20poly1305_open_in_place(
    key: &[u8; 32],
    nonce: &[u8; XCHACHA20POLY1305_NONCE],
    aad: &[u8],
    sealed: &mut [u8],
) -> Result<usize, ErrorClass> {
    crate::counts::aead_open();
    let Some(length) = sealed.len().checked_sub(XCHACHA20POLY1305_TAG) else {
        return Err(ErrorClass::Decrypt);
    };
    let (body, tag) = sealed.split_at_mut(length);
    let tag: [u8; XCHACHA20POLY1305_TAG] = (*tag).try_into().map_err(|_| ErrorClass::Decrypt)?;
    XChaCha20Poly1305::new(key.into())
        .decrypt_inout_detached(&XNonce::from(*nonce), aad, body.into(), &tag.into())
        .map_err(|_| ErrorClass::Decrypt)?;
    Ok(length)
}

/// The Ed25519 public key of a 32-byte seed (RFC 8032, section 5.1.5).
pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// `Ed25519-Sign(seed, message)`: pure Ed25519, deterministic (RFC 8032,
/// section 5.1.6).
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        frasil_base::notation::hex::decode(text).unwrap()
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_case_1() {
        let ikm = [0x0b; 22];
        let salt = unhex("000102030405060708090a0b0c");
        let info = unhex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk.to_vec(),
            unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let mut okm = [0; 42];
        hkdf_expand(&prk, &info, &mut okm).unwrap();
        assert_eq!(
            okm.to_vec(),
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
        assert_eq!(hkdf(Some(&salt), &ikm, &info).to_vec(), okm[..32].to_vec());
        assert_eq!(
            hkdf_expand(&prk, &info, &mut [0; 8161]),
            Err(ErrorClass::Malformed)
        );
    }

    #[test]
    fn hkdf_without_a_salt_uses_32_zero_bytes() {
        assert_eq!(
            hkdf(None, b"ikm", b"info"),
            hkdf(Some(&[0; 32]), b"ikm", b"info")
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_test_case_2() {
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
            unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
    }

    #[test]
    fn xchacha20poly1305_matches_the_draft_and_refuses_a_change() {
        // draft-irtf-cfrg-xchacha-03, appendix A.3.1.
        let key: [u8; 32] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; 24] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = xchacha20poly1305_seal(&key, &nonce, &aad, plaintext);
        assert_eq!(
            sealed[plaintext.len()..].to_vec(),
            unhex("c0875924c1c7987947deafd8780acf49")
        );
        assert_eq!(
            xchacha20poly1305_open(&key, &nonce, &aad, &sealed)
                .unwrap()
                .as_slice(),
            plaintext
        );
        let mut altered = sealed.clone();
        altered[0] ^= 1;
        assert_eq!(
            xchacha20poly1305_open(&key, &nonce, &aad, &altered),
            Err(ErrorClass::Decrypt)
        );
        assert_eq!(
            xchacha20poly1305_open(&key, &nonce, b"", &sealed),
            Err(ErrorClass::Decrypt)
        );
        assert_eq!(
            xchacha20poly1305_open(&key, &nonce, &aad, &sealed[..15]),
            Err(ErrorClass::Decrypt)
        );
        let mut buffer = b"prefix".to_vec();
        buffer.extend_from_slice(plaintext);
        xchacha20poly1305_seal_in_place(&key, &nonce, &aad, &mut buffer, 6);
        assert_eq!(&buffer[..6], b"prefix");
        assert_eq!(buffer[6..], sealed[..]);
        let mut out = vec![7; plaintext.len()];
        xchacha20poly1305_open_into(&key, &nonce, &aad, &sealed, &mut out).unwrap();
        assert_eq!(out, plaintext);
        assert_eq!(
            xchacha20poly1305_open_into(&key, &nonce, &aad, &altered, &mut out),
            Err(ErrorClass::Decrypt)
        );
        assert!(out.iter().all(|&b| b == 0));
        assert_eq!(
            xchacha20poly1305_open_into(&key, &nonce, &aad, &sealed, &mut out[1..]),
            Err(ErrorClass::Decrypt)
        );
        assert_eq!(
            xchacha20poly1305_open_into(&key, &nonce, &aad, &sealed[..15], &mut []),
            Err(ErrorClass::Decrypt)
        );
        let mut in_place = sealed.clone();
        let length = xchacha20poly1305_open_in_place(&key, &nonce, &aad, &mut in_place).unwrap();
        assert_eq!(&in_place[..length], plaintext);
        let mut in_place = altered.clone();
        assert_eq!(
            xchacha20poly1305_open_in_place(&key, &nonce, &aad, &mut in_place),
            Err(ErrorClass::Decrypt)
        );
        assert_eq!(in_place, altered);
        assert_eq!(
            xchacha20poly1305_open_in_place(&key, &nonce, &aad, &mut [0; 15]),
            Err(ErrorClass::Decrypt)
        );
    }

    #[test]
    fn ed25519_matches_rfc_8032_test_1() {
        let seed: [u8; 32] =
            unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap();
        assert_eq!(
            ed25519_public(&seed).to_vec(),
            unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        assert_eq!(
            ed25519_sign(&seed, b"").to_vec(),
            unhex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
    }
}
