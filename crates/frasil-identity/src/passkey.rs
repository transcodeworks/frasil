//! Passkey members (identity.md, "Passkey members").
//!
//! A passkey member derives from the 32-byte output of a passkey's PRF
//! extension, evaluated at one constant input:
//!
//! ```text
//! prf_input = SHA-256("frasil/passkey-prf-input/v2")
//!
//! passkey_keys(person_id, prf_output), in order:
//!   1. len(person_id) = 32.                                         else InvalidPersonId
//!   2. len(prf_output) = 32.                                        else InvalidPrfOutput
//!   3. prk            = HKDF-Extract("frasil/passkey-extract/v1", prf_output)
//!      identity seed  = HKDF-Expand(prk, "frasil/passkey-member/v1" || field("ed25519")
//!                                        || field(person_id), 32)
//!      X-Wing seed    = HKDF-Expand(prk, "frasil/passkey/hybrid/v1" || field(person_id), 32)
//!      ML-DSA-65 seed = HKDF-Expand(prk, "frasil/passkey/mldsa/v1" || field(person_id), 32)
//!      fetch seed     = HKDF-Expand(prk, "frasil/passkey/fetch/v1" || field(person_id), 32)
//!      unlock key     = HKDF-Expand(prk, "frasil/passkey-unlock/v1" || field("device-keys")
//!                                        || field(person_id), 32)
//! ```
//!
//! The output is taken as its own type, every key is derived from it at
//! once, `prk` is never exposed, and the output and every derived secret are
//! zeroised when dropped. No error carries any of them.

use crate::IdentityClass;
use crate::keys::{FetchKey, MemberKeys};
use frasil_base::ErrorClass;
use frasil_base::notation::push_field;
use frasil_crypto::labels::{
    PASSKEY_EXTRACT, PASSKEY_FETCH, PASSKEY_HYBRID, PASSKEY_MEMBER, PASSKEY_MLDSA,
    PASSKEY_PRF_INPUT, PASSKEY_UNLOCK,
};
use frasil_crypto::primitives::{hkdf_expand, hkdf_extract, sha256};
use zeroize::Zeroizing;

/// `prf_input = SHA-256("frasil/passkey-prf-input/v2")`, the same for every
/// person, passed as `prf.eval.first`.
pub const PRF_INPUT: [u8; 32] = [
    0x24, 0x8d, 0x03, 0x35, 0x6b, 0xb5, 0x3d, 0x7e, 0x0f, 0x21, 0xcb, 0x8a, 0x13, 0x07, 0x96, 0x17,
    0xb3, 0x8d, 0x48, 0x8b, 0x84, 0xc2, 0x80, 0x23, 0x9a, 0xc0, 0xb5, 0x94, 0x78, 0xb1, 0x11, 0xf9,
];

/// `prf_input`, computed from its label.
pub fn prf_input() -> [u8; 32] {
    sha256(&[PASSKEY_PRF_INPUT])
}

/// The HKDF infos of a person's passkey member, in the order of
/// "Passkey members": identity, X-Wing, ML-DSA-65, fetch and unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Infos {
    /// `"frasil/passkey-member/v1" || field("ed25519") || field(person_id)`.
    pub identity: Vec<u8>,
    /// `"frasil/passkey/hybrid/v1" || field(person_id)`.
    pub xwing: Vec<u8>,
    /// `"frasil/passkey/mldsa/v1" || field(person_id)`.
    pub mldsa: Vec<u8>,
    /// `"frasil/passkey/fetch/v1" || field(person_id)`.
    pub fetch: Vec<u8>,
    /// `"frasil/passkey-unlock/v1" || field("device-keys") || field(person_id)`.
    pub unlock: Vec<u8>,
}

impl Infos {
    /// The infos for a person ID: every one ends with `field(person_id)`.
    pub fn for_person(person_id: &[u8; 32]) -> Self {
        let info = |label: &[u8], middle: Option<&[u8]>| {
            let mut out = label.to_vec();
            if let Some(middle) = middle {
                push_field(&mut out, middle);
            }
            push_field(&mut out, person_id);
            out
        };
        Self {
            identity: info(PASSKEY_MEMBER, Some(b"ed25519")),
            xwing: info(PASSKEY_HYBRID, None),
            mldsa: info(PASSKEY_MLDSA, None),
            fetch: info(PASSKEY_FETCH, None),
            unlock: info(PASSKEY_UNLOCK, Some(b"device-keys")),
        }
    }
}

/// A passkey's PRF output: 32 bytes, zeroised when dropped.
pub struct PrfOutput(Zeroizing<[u8; 32]>);

impl PrfOutput {
    /// The output of these bytes.
    ///
    /// # Errors
    ///
    /// `InvalidPrfOutput` for an output of another length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, IdentityClass> {
        let array: &[u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityClass::InvalidPrfOutput)?;
        Ok(Self(Zeroizing::new(*array)))
    }
}

impl core::fmt::Debug for PrfOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrfOutput([redacted])")
    }
}

/// A passkey member: the list member, fetch key and unlock key one PRF output
/// derives for one person.
pub struct PasskeyMember {
    person_id: [u8; 32],
    member: MemberKeys,
    fetch: FetchKey,
    unlock: Zeroizing<[u8; 32]>,
}

impl PasskeyMember {
    /// `passkey_keys(person_id, prf_output)`, in order.
    ///
    /// # Errors
    ///
    /// `InvalidPersonId`, then `InvalidPrfOutput`.
    pub fn derive(person_id: &[u8], prf_output: &[u8]) -> Result<Self, IdentityClass> {
        let person_id: [u8; 32] = person_id
            .try_into()
            .map_err(|_| IdentityClass::InvalidPersonId)?;
        let output = PrfOutput::from_slice(prf_output)?;
        Ok(Self::from_output(&person_id, &output))
    }

    /// Step 3 of `passkey_keys`, on an output already taken as its type.
    pub fn from_output(person_id: &[u8; 32], output: &PrfOutput) -> Self {
        let infos = Infos::for_person(person_id);
        let prk = hkdf_extract(PASSKEY_EXTRACT, &output.0[..]);
        let expand = |info: &[u8]| {
            let mut okm = Zeroizing::new([0u8; 32]);
            hkdf_expand(&prk, info, okm.as_mut_slice()).expect("32 bytes is a valid length");
            okm
        };
        let identity = expand(&infos.identity);
        let xwing = expand(&infos.xwing);
        let mldsa = expand(&infos.mldsa);
        let fetch = expand(&infos.fetch);
        Self {
            person_id: *person_id,
            member: MemberKeys::from_seeds(&identity, &xwing, &mldsa),
            fetch: FetchKey::from_seed(&fetch),
            unlock: expand(&infos.unlock),
        }
    }

    /// Steps 1 and 2 of `add_passkey_member` (identity.md, "Adding list
    /// members"): two evaluations of the PRF derive the same identity,
    /// X-Wing and ML-DSA-65 keys. A client offers no operation that adds a
    /// passkey member from one output.
    ///
    /// # Errors
    ///
    /// `passkey_keys`'s classes, then `UnstablePrf`. Both outputs and every
    /// derived secret are zeroised whenever this fails.
    pub fn enrol(person_id: &[u8], first: &[u8], second: &[u8]) -> Result<Self, IdentityClass> {
        let one = Self::derive(person_id, first)?;
        let two = Self::derive(person_id, second)?;
        if one.member.identity() == two.member.identity()
            && one.member.xwing() == two.member.xwing()
            && one.member.mldsa() == two.member.mldsa()
        {
            Ok(one)
        } else {
            Err(IdentityClass::UnstablePrf)
        }
    }

    /// The person ID the member derives for.
    pub fn person_id(&self) -> &[u8; 32] {
        &self.person_id
    }

    /// The list member's three key pairs.
    pub fn member(&self) -> &MemberKeys {
        &self.member
    }

    /// The fetch key, registered for the personal space.
    pub fn fetch(&self) -> &FetchKey {
        &self.fetch
    }

    /// The unlock key, which seals the browser's own device keys at rest
    /// (at-rest.md, sealing key kind 1) and nothing else.
    pub fn unlock_key(&self) -> &[u8; 32] {
        &self.unlock
    }
}

impl core::fmt::Debug for PasskeyMember {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasskeyMember")
            .field("member", &self.member)
            .finish_non_exhaustive()
    }
}

/// The passkey's user handle: 64 bytes, the person ID then the personal
/// space ID (identity.md, "Passkey members").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserHandle {
    /// The person ID, the handle's first 32 bytes.
    pub person_id: [u8; 32],
    /// The personal space ID, the handle's last 32 bytes.
    pub personal_space: [u8; 32],
}

impl UserHandle {
    /// The handle's 64 bytes, `user.id`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0; 64];
        out[..32].copy_from_slice(&self.person_id);
        out[32..].copy_from_slice(&self.personal_space);
        out
    }

    /// Reads a handle.
    ///
    /// # Errors
    ///
    /// `Malformed` for a handle of any other length than 64 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, IdentityClass> {
        let bytes: &[u8; 64] = bytes
            .try_into()
            .map_err(|_| IdentityClass::Shared(ErrorClass::Malformed))?;
        let mut handle = Self {
            person_id: [0; 32],
            personal_space: [0; 32],
        };
        handle.person_id.copy_from_slice(&bytes[..32]);
        handle.personal_space.copy_from_slice(&bytes[32..]);
        Ok(handle)
    }
}

/// The WebAuthn salt a browser derives from `prf_input` (WebAuthn Level 3,
/// "PRF extension"): `SHA-256("WebAuthn PRF" || 0x00 || prf_input)`.
/// Informative: Frasil never sees it.
pub fn webauthn_salt() -> [u8; 32] {
    sha256(&[b"WebAuthn PRF\x00", &PRF_INPUT])
}
