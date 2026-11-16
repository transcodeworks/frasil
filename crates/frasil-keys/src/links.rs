//! Links and gap records (keys.md, "Links and gap records", and "Reading
//! key names, bundles, wraps and links").
//!
//! A link seals the secret of the state it reaches under a key derived from
//! the secret of the state it hangs under:
//!
//! ```text
//! link_key = HKDF(salt = none, ikm = secret(U),
//!                 info = "frasil/key-link/v1" || log || u8(kind) || name(U) || name(B))
//! aad      = "frasil/key-link/v1" || 0x01 || log || u8(kind) || name(U) || name(B)
//! link     = 0x01 || u8(kind) || name(U) || name(B) || nonce (24)
//!            || XChaCha20-Poly1305(link_key, nonce, secret(B), aad)
//! ```
//!
//! A gap record, `u8(kind) || encode_set(B)`, says that `B` is a gap key.

use crate::KeyClass;
use crate::derive::Secret;
use crate::names::{KeyName, RotationSet};
use frasil_base::ErrorClass;
use frasil_base::notation::push_field;
use frasil_crypto::labels;
use frasil_crypto::primitives::{hkdf, xchacha20poly1305_open, xchacha20poly1305_seal};
use frasil_crypto::sizes::{XCHACHA20POLY1305_NONCE, XCHACHA20POLY1305_TAG};
use zeroize::Zeroizing;

/// The link format's version byte.
pub const LINK_VERSION: u8 = 0x01;
/// The sealed secret after a link's nonce: 32 bytes and the tag.
pub const SEALED_SECRET_BYTES: usize = 32 + XCHACHA20POLY1305_TAG;

/// What a link or gap record is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LinkKind {
    /// 1: content keys, `k(U)` and `k(B)`.
    Content,
    /// 2: grant seeds, `g(U)` and `g(B)`, over grant states.
    Grant,
}

impl LinkKind {
    /// The kind's code.
    pub fn code(self) -> u8 {
        match self {
            Self::Content => 1,
            Self::Grant => 2,
        }
    }

    /// The kind of a code, if it is one.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Content),
            2 => Some(Self::Grant),
            _ => None,
        }
    }
}

fn binds(kind: LinkKind, log: &[u8], under: &KeyName, reaches: &RotationSet) -> Vec<u8> {
    let mut out = Vec::new();
    push_field(&mut out, log);
    out.push(kind.code());
    out.extend_from_slice(&under.encode());
    reaches.encode_into(&mut out);
    out
}

/// A link key's `info`: `"frasil/key-link/v1" || field(log) || u8(kind) ||
/// name(U) || name(B)`.
pub fn link_info(kind: LinkKind, log: &[u8], under: &KeyName, reaches: &RotationSet) -> Vec<u8> {
    [labels::KEY_LINK, &binds(kind, log, under, reaches)].concat()
}

/// A link's associated data: `"frasil/key-link/v1" || 0x01 || field(log) ||
/// u8(kind) || name(U) || name(B)`.
pub fn link_aad(kind: LinkKind, log: &[u8], under: &KeyName, reaches: &RotationSet) -> Vec<u8> {
    [
        labels::KEY_LINK,
        &[LINK_VERSION],
        &binds(kind, log, under, reaches),
    ]
    .concat()
}

/// A link's key, from the secret of the state it hangs under.
pub fn link_key(
    kind: LinkKind,
    log: &[u8],
    under: &KeyName,
    reaches: &RotationSet,
    under_secret: &[u8; 32],
) -> Secret {
    hkdf(None, under_secret, &link_info(kind, log, under, reaches))
}

/// A link's parts, read with no key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    /// Content or grant.
    pub kind: LinkKind,
    /// `name(U)`, the state it hangs under; may be a self reference.
    pub under: KeyName,
    /// `name(B)`, the state it reaches; never a self reference.
    pub reaches: RotationSet,
    /// The 24-byte nonce.
    pub nonce: [u8; XCHACHA20POLY1305_NONCE],
    /// The sealed secret and its tag.
    pub sealed: [u8; SEALED_SECRET_BYTES],
}

impl Link {
    /// Seals `reached_secret`, the secret of `reaches`, under a key from
    /// `under_secret`, the secret of `under`, with the nonce given.
    ///
    /// # Errors
    ///
    /// `Malformed` when `under` names `reaches`: a link joins two states.
    pub fn seal_with(
        kind: LinkKind,
        log: &[u8],
        under: KeyName,
        reaches: RotationSet,
        under_secret: &[u8; 32],
        reached_secret: &[u8; 32],
        nonce: &[u8; XCHACHA20POLY1305_NONCE],
    ) -> Result<Self, KeyClass> {
        if under.as_set() == Some(&reaches) {
            return Err(ErrorClass::Malformed.into());
        }
        let key = link_key(kind, log, &under, &reaches, under_secret);
        let aad = link_aad(kind, log, &under, &reaches);
        let sealed = xchacha20poly1305_seal(&key, nonce, &aad, reached_secret)
            .try_into()
            .map_err(|_| KeyClass::from(ErrorClass::Malformed))?;
        Ok(Self {
            kind,
            under,
            reaches,
            nonce: *nonce,
            sealed,
        })
    }

    /// The link's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![LINK_VERSION, self.kind.code()];
        out.extend_from_slice(&self.under.encode());
        self.reaches.encode_into(&mut out);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.sealed);
        out
    }

    /// Reads a link with no key, keys.md's steps 1 to 5 (section 3.1, "A
    /// link"). Whether a self reference may stand under it is the carrying
    /// event's question ([`crate::body`]).
    ///
    /// # Errors
    ///
    /// 1. `Malformed` for no byte.
    /// 2. `UnsupportedVersion` for a version other than `0x01`.
    /// 3. `Malformed` for no kind, or a kind other than 1 or 2.
    /// 4. [`KeyName::read`]'s classes for `name(U)`, a self reference
    ///    allowed, then for `name(B)`, none allowed.
    /// 5. `Malformed` unless exactly 72 bytes remain and the names differ.
    pub fn read(data: &[u8]) -> Result<Self, KeyClass> {
        let malformed = || KeyClass::from(ErrorClass::Malformed);
        let (&version, rest) = data.split_first().ok_or_else(malformed)?;
        if version != LINK_VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        let (&kind, rest) = rest.split_first().ok_or_else(malformed)?;
        let kind = LinkKind::from_code(kind).ok_or_else(malformed)?;
        let (under, rest) = KeyName::read(rest, true)?;
        let (reaches, rest) = match KeyName::read(rest, false)? {
            (KeyName::Set(set), rest) => (set, rest),
            (KeyName::SelfRef(_), _) => return Err(malformed()),
        };
        if rest.len() != XCHACHA20POLY1305_NONCE + SEALED_SECRET_BYTES
            || under.as_set() == Some(&reaches)
        {
            return Err(malformed());
        }
        let (nonce, sealed) = rest.split_at(XCHACHA20POLY1305_NONCE);
        Ok(Self {
            kind,
            under,
            reaches,
            nonce: nonce.try_into().map_err(|_| malformed())?,
            sealed: sealed.try_into().map_err(|_| malformed())?,
        })
    }

    /// Opens a link, in keys.md's order (section 3.1, "A link"): steps 1 to
    /// 5 as [`Link::read`]; 6, the kind and both names are the ones the
    /// opener looks for; 7, it opens under the key from `under_secret`.
    ///
    /// # Errors
    ///
    /// [`Link::read`]'s classes; `Malformed` at step 6; `Decrypt` at step 7.
    pub fn open(
        data: &[u8],
        kind: LinkKind,
        log: &[u8],
        under: &KeyName,
        reaches: &RotationSet,
        under_secret: &[u8; 32],
    ) -> Result<Secret, KeyClass> {
        let link = Self::read(data)?;
        if link.kind != kind || &link.under != under || &link.reaches != reaches {
            return Err(ErrorClass::Malformed.into());
        }
        link.open_read(log, under_secret)
    }

    /// Step 7 of a link already read: opens it under the key from
    /// `under_secret`, the secret of its own `under`.
    ///
    /// # Errors
    ///
    /// `Decrypt` if it does not open.
    pub fn open_read(&self, log: &[u8], under_secret: &[u8; 32]) -> Result<Secret, KeyClass> {
        let key = link_key(self.kind, log, &self.under, &self.reaches, under_secret);
        let aad = link_aad(self.kind, log, &self.under, &self.reaches);
        let secret: Zeroizing<Vec<u8>> =
            xchacha20poly1305_open(&key, &self.nonce, &aad, &self.sealed)?;
        let mut out = Zeroizing::new([0; 32]);
        if secret.len() != 32 {
            return Err(ErrorClass::Decrypt.into());
        }
        out.copy_from_slice(&secret);
        Ok(out)
    }
}

/// A gap record: `u8(kind) || encode_set(B)`, saying that `B` is a gap key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GapRecord {
    /// Content or grant.
    pub kind: LinkKind,
    /// The state that is a gap key.
    pub state: RotationSet,
}

impl GapRecord {
    /// The record's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.kind.code()];
        self.state.encode_into(&mut out);
        out
    }

    /// Reads a gap record (keys.md, section 3.1, "A gap record"): the kind
    /// is 1 or 2, and the rest is one rotation set.
    ///
    /// # Errors
    ///
    /// `Malformed`, or [`RotationSet::decode`]'s classes.
    pub fn read(data: &[u8]) -> Result<Self, KeyClass> {
        let (&kind, rest) = data
            .split_first()
            .ok_or_else(|| KeyClass::from(ErrorClass::Malformed))?;
        let kind = LinkKind::from_code(kind).ok_or(ErrorClass::Malformed)?;
        Ok(Self {
            kind,
            state: RotationSet::decode(rest)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::SelfRef;
    use frasil_crypto::device::DeviceId;
    use frasil_events::EventId;

    #[test]
    fn a_link_opens_for_what_it_names_only() {
        let under = KeyName::SelfRef(SelfRef::new(DeviceId([1; 32]), 3));
        let reaches = RotationSet::single(EventId([2; 32]));
        let link = Link::seal_with(
            LinkKind::Content,
            b"log",
            under.clone(),
            reaches.clone(),
            &[5; 32],
            &[6; 32],
            &[7; 24],
        )
        .unwrap();
        let bytes = link.encode();
        assert_eq!(bytes.len(), 148);
        assert_eq!(Link::read(&bytes), Ok(link));
        let opened = Link::open(
            &bytes,
            LinkKind::Content,
            b"log",
            &under,
            &reaches,
            &[5; 32],
        );
        assert_eq!(*opened.unwrap(), [6; 32]);
        assert_eq!(
            Link::open(
                &bytes,
                LinkKind::Content,
                b"other",
                &under,
                &reaches,
                &[5; 32]
            ),
            Err(ErrorClass::Decrypt.into())
        );
    }

    #[test]
    fn a_link_joins_two_states() {
        let set = RotationSet::single(EventId([2; 32]));
        assert!(
            Link::seal_with(
                LinkKind::Grant,
                b"log",
                KeyName::Set(set.clone()),
                set,
                &[5; 32],
                &[6; 32],
                &[7; 24],
            )
            .is_err()
        );
    }
}
