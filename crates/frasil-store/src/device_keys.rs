//! The sealed device keys (at-rest.md, "Sealed device keys", "Sealing and
//! opening the device keys").
//!
//! ```text
//! offset  length  field
//! 0       1       version = 0x01
//! 1       1       key kind: 0x01 or 0x02
//! 2       32      device ID (crypto.md, "A device's keys")
//! 34      32      person ID, or 32 zero bytes for a device member
//! 66      24      nonce, random
//! 90      145     XChaCha20-Poly1305 ciphertext and tag              235 bytes
//! ```
//!
//! The header, the first 66 bytes, is associated data, and the plaintext is
//! `0x01 || identity seed || X-Wing seed || ML-DSA-65 seed || store secret`.
//! Opening derives all three public keys from the seeds and checks that
//! their device ID is the header's.

use crate::StoreClass;
use frasil_base::ErrorClass;
use frasil_crypto::device::{DeviceId, HybridKeys, IdentityKey};
use frasil_crypto::labels::{SEALED_DEVICE_KEYS, UNLOCK_KEY};
use frasil_crypto::mldsa65;
use frasil_crypto::primitives::{
    ed25519_public, hkdf, xchacha20poly1305_open, xchacha20poly1305_seal,
};
use frasil_crypto::schemes::Signer;
use frasil_crypto::wrap::xwing_public;
use zeroize::Zeroizing;

/// The version of the blob, its first byte.
pub const VERSION: u8 = 0x01;
/// The version of the plaintext's layout, its first byte.
pub const LAYOUT_VERSION: u8 = 0x01;
/// The header: version, key kind, device ID and person ID.
pub const HEADER_BYTES: usize = 1 + 1 + 32 + 32;
/// The plaintext: the layout version and four 32-byte secrets.
pub const PLAINTEXT_BYTES: usize = 1 + 4 * 32;
/// The whole blob.
pub const SEALED_DEVICE_KEYS_BYTES: usize = HEADER_BYTES + 24 + PLAINTEXT_BYTES + 16;
/// The person ID of a device member: 32 zero bytes.
pub const ZERO_PERSON: [u8; 32] = [0; 32];

const NONCE_AT: usize = HEADER_BYTES;
const CIPHERTEXT_AT: usize = HEADER_BYTES + 24;

/// The kind of unlock key that seals the device keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// Kind 1: the unlock key a passkey derives for the person
    /// (identity.md, "Passkey members"), used as it is.
    PasskeyUnlock,
    /// Kind 2: 32 bytes of high entropy from another source, such as a
    /// keychain, a secure element or a hardware token; never a password.
    /// The sealing key is derived from it.
    UnlockKey,
}

impl KeyKind {
    /// The kind's byte.
    pub fn code(self) -> u8 {
        match self {
            Self::PasskeyUnlock => 1,
            Self::UnlockKey => 2,
        }
    }

    /// The kind of this byte, if it is one.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::PasskeyUnlock),
            2 => Some(Self::UnlockKey),
            _ => None,
        }
    }
}

/// A device's four secrets: its three seeds (crypto.md, "A device's keys")
/// and its store secret `s`. A device draws all four from its random source
/// when its keys are made; the store secret never changes while the device
/// exists.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceKeys {
    /// The Ed25519 identity seed.
    pub identity_seed: Zeroizing<[u8; 32]>,
    /// The X-Wing seed.
    pub xwing_seed: Zeroizing<[u8; 32]>,
    /// The ML-DSA-65 seed.
    pub mldsa_seed: Zeroizing<[u8; 32]>,
    /// The store secret `s`.
    pub store_secret: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceKeys")
            .field("device_id", &self.device_id())
            .finish_non_exhaustive()
    }
}

impl DeviceKeys {
    /// The keys of these four secrets.
    pub fn new(
        identity_seed: [u8; 32],
        xwing_seed: [u8; 32],
        mldsa_seed: [u8; 32],
        store_secret: [u8; 32],
    ) -> Self {
        Self {
            identity_seed: Zeroizing::new(identity_seed),
            xwing_seed: Zeroizing::new(xwing_seed),
            mldsa_seed: Zeroizing::new(mldsa_seed),
            store_secret: Zeroizing::new(store_secret),
        }
    }

    /// The device's three public keys, derived from its seeds: the
    /// Ed25519 key, and the ML-DSA-65 and X-Wing keys its `kc` commits to
    /// (crypto.md, "A device's keys"). Deriving them costs an ML-DSA-65
    /// and an X-Wing key generation.
    pub fn public_keys(&self) -> frasil_crypto::device::DeviceKeys {
        frasil_crypto::device::DeviceKeys {
            ed: IdentityKey(ed25519_public(&self.identity_seed)),
            keys: HybridKeys::from_checked(
                mldsa65::public_from_seed(&self.mldsa_seed),
                Some(Box::new(xwing_public(&self.xwing_seed))),
            ),
        }
    }

    /// The device ID of the three public keys: never the Ed25519 key alone.
    pub fn device_id(&self) -> DeviceId {
        self.public_keys().device_id()
    }

    /// The device's signer, with its X-Wing public key.
    pub fn signer(&self) -> Signer {
        Signer::from_seeds(
            &self.identity_seed,
            &self.mldsa_seed,
            Some(&xwing_public(&self.xwing_seed)),
        )
    }

    /// The plaintext: `0x01 || identity seed || X-Wing seed || ML-DSA-65
    /// seed || store secret`, 129 bytes.
    pub fn plaintext(&self) -> Zeroizing<[u8; PLAINTEXT_BYTES]> {
        let mut out = Zeroizing::new([0u8; PLAINTEXT_BYTES]);
        out[0] = LAYOUT_VERSION;
        for (i, secret) in [
            &self.identity_seed,
            &self.xwing_seed,
            &self.mldsa_seed,
            &self.store_secret,
        ]
        .into_iter()
        .enumerate()
        {
            out[1 + 32 * i..33 + 32 * i].copy_from_slice(&secret[..]);
        }
        out
    }

    /// Reads a plaintext: open_device_keys steps 8 and 9.
    ///
    /// # Errors
    ///
    /// `Malformed` if it is empty; `UnsupportedVersion` if its layout
    /// version is not 1; `Malformed` if it is not 129 bytes.
    pub fn from_plaintext(plaintext: &[u8]) -> Result<Self, ErrorClass> {
        let Some(&layout) = plaintext.first() else {
            return Err(ErrorClass::Malformed);
        };
        if layout != LAYOUT_VERSION {
            return Err(ErrorClass::UnsupportedVersion);
        }
        if plaintext.len() != PLAINTEXT_BYTES {
            return Err(ErrorClass::Malformed);
        }
        let secret = |i: usize| {
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(&plaintext[1 + 32 * i..33 + 32 * i]);
            out
        };
        Ok(Self {
            identity_seed: secret(0),
            xwing_seed: secret(1),
            mldsa_seed: secret(2),
            store_secret: secret(3),
        })
    }
}

/// What anyone reads of a blob without a key: open_device_keys steps 1 to
/// 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The key kind.
    pub kind: KeyKind,
    /// The device ID.
    pub device_id: DeviceId,
    /// The person ID, or 32 zero bytes for a device member.
    pub person_id: [u8; 32],
}

impl Header {
    /// The 66 header bytes: `0x01 || u8(kind) || device ID || person ID`.
    pub fn to_bytes(&self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        out[0] = VERSION;
        out[1] = self.kind.code();
        out[2..34].copy_from_slice(&self.device_id.0);
        out[34..66].copy_from_slice(&self.person_id);
        out
    }

    /// The associated data: `"frasil/sealed-device-keys/v1" || header`.
    pub fn aad(&self) -> Vec<u8> {
        [SEALED_DEVICE_KEYS, &self.to_bytes()[..]].concat()
    }
}

/// The sealing key of an unlock key: kind 1, the passkey's unlock key as it
/// is; kind 2, `HKDF("frasil/unlock-key/v1", unlock key,
/// "frasil/sealed-device-keys/v1")`.
pub fn sealing_key(kind: KeyKind, unlock_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    match kind {
        KeyKind::PasskeyUnlock => Zeroizing::new(*unlock_key),
        KeyKind::UnlockKey => hkdf(Some(UNLOCK_KEY), unlock_key, SEALED_DEVICE_KEYS),
    }
}

/// open_device_keys steps 1 to 3: the blob's version, kind, length, and a
/// person ID that a kind 1 blob may not leave zero. Nothing here needs a
/// key, so an application reads the device ID and person ID before it
/// unlocks.
///
/// # Errors
///
/// `Malformed` if it is shorter than 2 bytes; `UnsupportedVersion` if its
/// version is not 1; `Malformed` if its kind is not 1 or 2, it is not 235
/// bytes, or it is kind 1 with a zero person ID.
pub fn read_header(blob: &[u8]) -> Result<Header, ErrorClass> {
    if blob.len() < 2 {
        return Err(ErrorClass::Malformed);
    }
    if blob[0] != VERSION {
        return Err(ErrorClass::UnsupportedVersion);
    }
    let kind = KeyKind::from_code(blob[1]).ok_or(ErrorClass::Malformed)?;
    if blob.len() != SEALED_DEVICE_KEYS_BYTES {
        return Err(ErrorClass::Malformed);
    }
    let device_id = DeviceId(blob[2..34].try_into().expect("32 bytes"));
    let mut person_id = [0u8; 32];
    person_id.copy_from_slice(&blob[34..66]);
    if kind == KeyKind::PasskeyUnlock && person_id == ZERO_PERSON {
        return Err(ErrorClass::Malformed);
    }
    Ok(Header {
        kind,
        device_id,
        person_id,
    })
}

/// `seal_device_keys(keys, person ID, kind, unlock key)` with its nonce
/// given: the 235-byte blob.
///
/// Re-sealing under a new passkey or kind 2 key makes a new blob with a new
/// nonce; the keys inside never change. A caller draws the nonce with
/// `frasil_crypto::random_bytes`, anew for every seal.
///
/// # Errors
///
/// `Malformed` if the person ID is not 32 bytes, or the kind is 1 and the
/// person ID is zero.
pub fn seal_device_keys_with(
    keys: &DeviceKeys,
    person_id: &[u8],
    kind: KeyKind,
    unlock_key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<[u8; SEALED_DEVICE_KEYS_BYTES], ErrorClass> {
    let person_id: [u8; 32] = person_id.try_into().map_err(|_| ErrorClass::Malformed)?;
    if kind == KeyKind::PasskeyUnlock && person_id == ZERO_PERSON {
        return Err(ErrorClass::Malformed);
    }
    let header = Header {
        kind,
        device_id: keys.device_id(),
        person_id,
    };
    let sealed = xchacha20poly1305_seal(
        &sealing_key(kind, unlock_key),
        nonce,
        &header.aad(),
        &keys.plaintext()[..],
    );
    let mut blob = [0u8; SEALED_DEVICE_KEYS_BYTES];
    blob[..HEADER_BYTES].copy_from_slice(&header.to_bytes());
    blob[NONCE_AT..CIPHERTEXT_AT].copy_from_slice(nonce);
    blob[CIPHERTEXT_AT..].copy_from_slice(&sealed);
    Ok(blob)
}

/// `open_device_keys(blob, kind, unlock key, person ID, device ID or
/// none)`, in order.
///
/// A client names the person ID it expects, 32 zero bytes for a device
/// member. Once opened, the keys must be on the person's verified device
/// list, or granted as a device member, before the client uses them.
///
/// # Errors
///
/// Steps 1 to 3 as [`read_header`]; then `WrongKeyKind`, `WrongPerson`,
/// `WrongDevice`; `Decrypt` if the AEAD does not open; then
/// [`DeviceKeys::from_plaintext`]'s classes; and `Malformed` if the device
/// ID of the three seeds' public keys is not the header's (step 10).
pub fn open_device_keys(
    blob: &[u8],
    kind: KeyKind,
    unlock_key: &[u8; 32],
    person_id: &[u8; 32],
    device_id: Option<&DeviceId>,
) -> Result<DeviceKeys, StoreClass> {
    let header = read_header(blob)?;
    if header.kind != kind {
        return Err(StoreClass::WrongKeyKind);
    }
    if &header.person_id != person_id {
        return Err(StoreClass::WrongPerson);
    }
    if device_id.is_some_and(|expected| &header.device_id != expected) {
        return Err(StoreClass::WrongDevice);
    }
    let nonce: &[u8; 24] = blob[NONCE_AT..CIPHERTEXT_AT]
        .try_into()
        .expect("the nonce is 24 bytes");
    let plaintext = xchacha20poly1305_open(
        &sealing_key(kind, unlock_key),
        nonce,
        &header.aad(),
        &blob[CIPHERTEXT_AT..],
    )?;
    let keys = DeviceKeys::from_plaintext(&plaintext)?;
    // 10. The device ID of all three public keys, derived from the seeds.
    if keys.device_id() != header.device_id {
        return Err(ErrorClass::Malformed.into());
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> DeviceKeys {
        DeviceKeys::new([1; 32], [2; 32], [3; 32], [4; 32])
    }

    #[test]
    fn sizes() {
        assert_eq!(PLAINTEXT_BYTES, 129);
        assert_eq!(SEALED_DEVICE_KEYS_BYTES, 235);
    }

    #[test]
    fn round_trip_both_kinds() {
        let person = [9; 32];
        for kind in [KeyKind::PasskeyUnlock, KeyKind::UnlockKey] {
            let blob = seal_device_keys_with(&keys(), &person, kind, &[5; 32], &[6; 24]).unwrap();
            let opened =
                open_device_keys(&blob, kind, &[5; 32], &person, Some(&keys().device_id()))
                    .unwrap();
            assert_eq!(opened, keys());
        }
    }

    #[test]
    fn seal_refuses_a_passkey_without_a_person() {
        let sealed = seal_device_keys_with(
            &keys(),
            &ZERO_PERSON,
            KeyKind::PasskeyUnlock,
            &[5; 32],
            &[6; 24],
        );
        assert_eq!(sealed, Err(ErrorClass::Malformed));
        let short =
            seal_device_keys_with(&keys(), &[1; 31], KeyKind::UnlockKey, &[5; 32], &[6; 24]);
        assert_eq!(short, Err(ErrorClass::Malformed));
    }
}
