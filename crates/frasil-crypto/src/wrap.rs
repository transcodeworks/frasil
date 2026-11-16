//! X-Wing keys, HPKE with X-Wing, and the X-Wing wrap (crypto.md, "The
//! X-Wing wrap" and "Opening a wrap").
//!
//! A wrap seals a plaintext to one X-Wing public key:
//!
//! ```text
//! offset  length  field
//! 0       1       version = 0x01
//! 1       2       u16be(suite) = 0x647a
//! 3       1,120   enc
//! 1,123   n + 16  ciphertext
//!
//! (enc, ciphertext) = HPKE-Seal(recipient's X-Wing key, info, aad = "", plaintext)
//! ```
//!
//! HPKE runs in base mode, single shot, with KEM `0x647a` (X-Wing), KDF
//! `0x0001` (HKDF-SHA256) and AEAD `0x0003` (ChaCha20-Poly1305). X-Wing's
//! combiner is the only place the two shared secrets meet: nothing here
//! combines them. Every other suite, DHKEM(X25519, HKDF-SHA256) `0x0020`
//! included, is refused as `UnsupportedVersion`.
//!
//! `info` starts with the label of the wrap's use, then `u16be(suite)`, then
//! what the using document binds ([`wrap_info`]), so a wrap opens under no
//! other suite, use, log or recipient. A wrap names no recipient and carries
//! no signature.
//!
//! Sealing takes X-Wing's 64 bytes of encapsulation randomness from the
//! caller ([`seal_wrap_with`]), so this module draws no randomness of its
//! own: a caller draws them with [`crate::random_bytes`], which refuses when
//! the platform has no working source.

use crate::sizes::{XWING_ENC, XWING_PUBLIC, XWING_SEED};
use frasil_base::ErrorClass;
use frasil_base::notation::u16be;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use zeroize::{Zeroize, Zeroizing};

/// The wrap's version byte.
pub const WRAP_VERSION: u8 = 0x01;
/// HPKE's code point for X-Wing (MLKEM768-X25519): the only suite.
pub const SUITE_XWING: u16 = 0x647a;
/// DHKEM(X25519, HKDF-SHA256): refused, as every suite but X-Wing.
pub const SUITE_X25519: u16 = 0x0020;
/// HPKE's code point for HKDF-SHA256.
pub const KDF_HKDF_SHA256: u16 = 0x0001;
/// HPKE's code point for ChaCha20-Poly1305.
pub const AEAD_CHACHA20POLY1305: u16 = 0x0003;
/// Bytes before `enc`: the version and the suite.
pub const WRAP_HEADER: usize = 3;
/// Bytes of HPKE's ChaCha20-Poly1305 tag.
pub const HPKE_TAG: usize = 16;
/// Bytes of the shortest wrap, of an empty plaintext: 1,139.
pub const MIN_WRAP: usize = WRAP_HEADER + XWING_ENC + HPKE_TAG;
/// Bytes of X-Wing's encapsulation randomness: ML-KEM's `m`, then the X25519
/// ephemeral secret.
pub const ENCAPSULATION_RANDOMNESS: usize = 64;

/// The length, or range of lengths, a using document fixes for its wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapLength {
    /// Exactly this many bytes.
    Exactly(usize),
    /// At least this many bytes.
    AtLeast(usize),
    /// From the first to the second, both included.
    Between(usize, usize),
}

impl WrapLength {
    /// Whether a wrap of `n` bytes has this length.
    pub fn admits(self, n: usize) -> bool {
        match self {
            Self::Exactly(length) => n == length,
            Self::AtLeast(minimum) => n >= minimum,
            Self::Between(minimum, maximum) => (minimum..=maximum).contains(&n),
        }
    }
}

/// Every Frasil seal to an X-Wing key (crypto.md, "The X-Wing wrap").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WrapUse {
    /// A bundle wrap (keys.md).
    BundleWrap,
    /// A space wrap (keys.md).
    SpaceWrap,
    /// A removal wrap (keys.md).
    RemovalWrap,
    /// A slot token (peers.md).
    SlotToken,
    /// An exchange message (admission.md).
    ExchangeMessage,
    /// A welcome (admission.md).
    Welcome,
    /// A device mailbox item (transport.md).
    MailboxItem,
}

impl WrapUse {
    /// Every use, in the document's order.
    pub const ALL: [WrapUse; 7] = [
        Self::BundleWrap,
        Self::SpaceWrap,
        Self::RemovalWrap,
        Self::SlotToken,
        Self::ExchangeMessage,
        Self::Welcome,
        Self::MailboxItem,
    ];

    /// The label that starts the use's `info`.
    pub fn label(self) -> &'static [u8] {
        use crate::labels;
        match self {
            Self::BundleWrap => labels::BUNDLE_WRAP,
            Self::SpaceWrap => labels::SPACE_WRAP,
            Self::RemovalWrap => labels::REMOVAL_WRAP,
            Self::SlotToken => labels::SKELETON_TOKEN,
            Self::ExchangeMessage => labels::ADMISSION_SEAL,
            Self::Welcome => labels::WELCOME,
            Self::MailboxItem => labels::MAILBOX_ITEM,
        }
    }

    /// The length of the use's wraps.
    pub fn length(self) -> WrapLength {
        match self {
            Self::BundleWrap | Self::SpaceWrap | Self::RemovalWrap => WrapLength::Exactly(1236),
            Self::SlotToken => WrapLength::Exactly(1171),
            Self::ExchangeMessage | Self::Welcome => WrapLength::AtLeast(MIN_WRAP),
            Self::MailboxItem => WrapLength::Between(MIN_WRAP, 262_144),
        }
    }

    /// The use's `info`: its label, the suite, then `binds`, what the using
    /// document binds.
    pub fn info(self, binds: &[u8]) -> Vec<u8> {
        wrap_info(self.label(), binds)
    }
}

/// A wrap's `info`: `label || u16be(0x647a) || binds`.
pub fn wrap_info(label: &[u8], binds: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 2 + binds.len());
    info.extend_from_slice(label);
    info.extend_from_slice(&u16be(SUITE_XWING));
    info.extend_from_slice(binds);
    info
}

/// The X-Wing public key of a 32-byte seed: the ML-KEM-768 encapsulation key
/// then the X25519 public key, each derived from the seed's SHAKE256
/// expansion (draft-connolly-cfrg-xwing-kem, version 06).
pub fn xwing_public(seed: &[u8; XWING_SEED]) -> [u8; XWING_PUBLIC] {
    let private = <XWing as hpke::Kem>::PrivateKey::from_bytes(seed)
        .expect("a 32-byte X-Wing seed is a private key");
    let mut public = [0; XWING_PUBLIC];
    XWing::sk_to_pk(&private).write_exact(&mut public);
    public
}

/// `HPKE-Seal(pk, info, aad, plaintext) → (enc, ciphertext)`, with X-Wing's
/// encapsulation randomness given. The ciphertext is 16 bytes longer than the
/// plaintext.
///
/// The recipient's key is not checked again here: crypto.md checks a key
/// where it enters, before anything is sealed to it ([`crate::keys`]).
///
/// # Errors
///
/// `InvalidKey` if `recipient` is not 1,216 bytes or X-Wing refuses it.
pub fn hpke_seal_with(
    recipient: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<([u8; XWING_ENC], Vec<u8>), ErrorClass> {
    let public = <XWing as hpke::Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| ErrorClass::InvalidKey)?;
    let mut rng = EncapsulationRandomness(Some(Zeroizing::new(*encapsulation_randomness)));
    let (encapsulated, ciphertext) = hpke::single_shot_seal_with_rng::<
        ChaCha20Poly1305,
        HkdfSha256,
        XWing,
    >(&OpModeS::Base, &public, info, plaintext, aad, &mut rng)
    .map_err(|_| ErrorClass::InvalidKey)?;
    let mut enc = [0; XWING_ENC];
    encapsulated.write_exact(&mut enc);
    Ok((enc, ciphertext))
}

/// `HPKE-Open(seed, enc, info, aad, ciphertext)`.
///
/// # Errors
///
/// `Decrypt` for every failure.
pub fn hpke_open(
    seed: &[u8; XWING_SEED],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ErrorClass> {
    crate::counts::hpke_open();
    let private = <XWing as hpke::Kem>::PrivateKey::from_bytes(seed)
        .expect("a 32-byte X-Wing seed is a private key");
    let encapsulated =
        <XWing as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| ErrorClass::Decrypt)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &private,
        &encapsulated,
        info,
        ciphertext,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| ErrorClass::Decrypt)
}

/// Seals `plaintext` to `recipient`'s X-Wing key as a wrap under `info`, with
/// X-Wing's 64 bytes of encapsulation randomness given.
///
/// # Errors
///
/// `InvalidKey` if `recipient` is not 1,216 bytes or X-Wing refuses it.
pub fn seal_wrap_with(
    recipient: &[u8],
    info: &[u8],
    plaintext: &[u8],
    encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<Vec<u8>, ErrorClass> {
    let (enc, ciphertext) =
        hpke_seal_with(recipient, info, b"", plaintext, encapsulation_randomness)?;
    let mut wrap = Vec::with_capacity(WRAP_HEADER + XWING_ENC + ciphertext.len());
    wrap.push(WRAP_VERSION);
    wrap.extend_from_slice(&u16be(SUITE_XWING));
    wrap.extend_from_slice(&enc);
    wrap.extend_from_slice(&ciphertext);
    Ok(wrap)
}

/// A wrap's parts, read with no key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapParts<'a> {
    /// The X-Wing encapsulation, 1,120 bytes.
    pub enc: &'a [u8],
    /// HPKE's ciphertext, 16 bytes longer than the plaintext.
    pub ciphertext: &'a [u8],
}

/// `open_wrap`, steps 1 to 5: the layout, with no key.
///
/// # Errors
///
/// In the document's order: `Malformed` for an empty wrap;
/// `UnsupportedVersion` for another version; `Malformed` for a wrap shorter
/// than its header; `UnsupportedVersion` for another suite; `Malformed` for a
/// length other than `length` admits, or shorter than an empty plaintext's.
pub fn read_wrap(wrap: &[u8], length: WrapLength) -> Result<WrapParts<'_>, ErrorClass> {
    let (&version, rest) = wrap.split_first().ok_or(ErrorClass::Malformed)?;
    if version != WRAP_VERSION {
        return Err(ErrorClass::UnsupportedVersion);
    }
    let (suite, _) = rest.split_first_chunk::<2>().ok_or(ErrorClass::Malformed)?;
    if u16::from_be_bytes(*suite) != SUITE_XWING {
        return Err(ErrorClass::UnsupportedVersion);
    }
    if !length.admits(wrap.len()) || wrap.len() < MIN_WRAP {
        return Err(ErrorClass::Malformed);
    }
    let (enc, ciphertext) = wrap[WRAP_HEADER..].split_at(XWING_ENC);
    Ok(WrapParts { enc, ciphertext })
}

/// `open_wrap(wrap, seed, info)`, in order (crypto.md, "Opening a wrap"). A
/// wrap meant for another recipient, log or use fails at step 6 as
/// `Decrypt`, like a damaged one; the using document then checks the
/// plaintext.
///
/// # Errors
///
/// [`read_wrap`]'s, then `Decrypt` if HPKE does not open it.
pub fn open_wrap(
    wrap: &[u8],
    seed: &[u8; XWING_SEED],
    info: &[u8],
    length: WrapLength,
) -> Result<Zeroizing<Vec<u8>>, ErrorClass> {
    let parts = read_wrap(wrap, length)?;
    hpke_open(seed, parts.enc, info, b"", parts.ciphertext)
}

/// X-Wing's encapsulation randomness, given to HPKE as its random source.
/// HPKE base mode with X-Wing draws exactly once, 64 bytes, for the
/// encapsulation; this hands them out once and whole.
struct EncapsulationRandomness(Option<Zeroizing<[u8; ENCAPSULATION_RANDOMNESS]>>);

impl hpke::rand_core::TryRng for EncapsulationRandomness {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Hands out the 64 bytes once, whole. Any other request would mean the
    /// pinned HPKE draws randomness otherwise than crypto.md says; refuse
    /// rather than reuse or invent bytes.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        match self.0.take() {
            Some(mut bytes) if dest.len() == bytes.len() => {
                dest.copy_from_slice(bytes.as_slice());
                bytes.zeroize();
            }
            _ => panic!("HPKE asked for randomness other than X-Wing's one 64-byte draw"),
        }
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for EncapsulationRandomness {}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(byte: u8) -> ([u8; 32], [u8; XWING_PUBLIC]) {
        let seed = [byte; 32];
        (seed, xwing_public(&seed))
    }

    #[test]
    fn a_wrap_opens_for_its_recipient_and_info_only() {
        let (seed, public) = device(1);
        let (other_seed, _) = device(2);
        let info = WrapUse::Welcome.info(b"recipient");
        let wrap = seal_wrap_with(&public, &info, b"plaintext", &[7; 64]).unwrap();
        assert_eq!(wrap.len(), MIN_WRAP + 9);
        assert_eq!(
            wrap,
            seal_wrap_with(&public, &info, b"plaintext", &[7; 64]).unwrap()
        );
        let length = WrapUse::Welcome.length();
        assert_eq!(
            open_wrap(&wrap, &seed, &info, length).unwrap().as_slice(),
            b"plaintext"
        );
        assert_eq!(
            open_wrap(&wrap, &other_seed, &info, length),
            Err(ErrorClass::Decrypt)
        );
        let other_use = WrapUse::MailboxItem.info(b"recipient");
        assert_eq!(
            open_wrap(&wrap, &seed, &other_use, length),
            Err(ErrorClass::Decrypt)
        );
    }

    #[test]
    fn the_layout_is_checked_in_order() {
        let (_, public) = device(1);
        let wrap = seal_wrap_with(&public, b"info", b"", &[7; 64]).unwrap();
        let any = WrapLength::AtLeast(MIN_WRAP);
        assert_eq!(read_wrap(&[], any), Err(ErrorClass::Malformed));
        assert_eq!(read_wrap(&[2], any), Err(ErrorClass::UnsupportedVersion));
        assert_eq!(read_wrap(&[1, 0x64], any), Err(ErrorClass::Malformed));
        assert_eq!(
            read_wrap(&[1, 0x00, 0x20], any),
            Err(ErrorClass::UnsupportedVersion)
        );
        assert_eq!(read_wrap(&wrap[..3], any), Err(ErrorClass::Malformed));
        assert_eq!(
            read_wrap(&wrap[..MIN_WRAP - 1], WrapLength::AtLeast(0)),
            Err(ErrorClass::Malformed)
        );
        let parts = read_wrap(&wrap, WrapLength::Exactly(MIN_WRAP)).unwrap();
        assert_eq!((parts.enc.len(), parts.ciphertext.len()), (XWING_ENC, 16));
        assert_eq!(
            read_wrap(&wrap, WrapLength::Exactly(MIN_WRAP + 1)),
            Err(ErrorClass::Malformed)
        );
    }

    #[test]
    fn lengths_admit_what_they_say() {
        assert!(WrapLength::Between(3, 5).admits(3));
        assert!(WrapLength::Between(3, 5).admits(5));
        assert!(!WrapLength::Between(3, 5).admits(6));
        assert!(WrapLength::AtLeast(3).admits(300));
        assert!(!WrapLength::AtLeast(3).admits(2));
        assert!(!WrapLength::Exactly(3).admits(4));
    }

    #[test]
    fn a_key_of_another_length_is_refused_before_sealing() {
        assert_eq!(
            seal_wrap_with(&[0; XWING_PUBLIC - 1], b"info", b"", &[7; 64]),
            Err(ErrorClass::InvalidKey)
        );
    }
}
