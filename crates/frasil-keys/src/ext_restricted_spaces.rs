//! A restricted space's keys (ext-restricted-spaces.md, sections 2.2, 2.3
//! and 3.2, feature `ext-restricted-spaces`).
//!
//! A restricted space F under its parent P draws its own secrets: a
//! content secret `f_R` and an upload seed `fw_R` per rotation, and no
//! grant seed. `f(S_F)` and `fw(S_F)` merge them as keys.md merges `k` and
//! `w` ([`crate::derive::state_secret`], with F's space ID). F's space
//! events, read credential, upload key and member key derive from them
//! alone. Only its content key also takes P's:
//!
//! ```text
//! k_F(S_F, S_P) = HKDF(salt = f(S_F), ikm = k_P(S_P),
//!                      info = "frasil/restricted-key/v1" || field(F) || field(P))
//!
//! reference     = encode_set(S_F) || nonce (24)
//!                 || XChaCha20-Poly1305(parent_key, nonce, encode_set(S_P), aad)
//! parent_key    = HKDF(salt = none, ikm = f(S_F), info = "frasil/parent-reference/v1")
//! aad           = "frasil/parent-reference/v1" || field(F) || encode_set(S_F)
//! ```
//!
//! A unit, object or sealed name of F names its state by the restricted
//! key reference: only a holder of `f(S_F)` learns which state of P it
//! uses. [`RestrictedReference::read`] is the one reader of its visible
//! parts, for peers and members alike.

use crate::KeyClass;
use crate::bundle::{Level, Slots, bundle_contents};
use crate::derive::Secret;
use crate::limits::MAX_ROTATIONS;
use crate::names::{KeyName, RotationSet};
use crate::reference::{Lookup, RotationLog};
use crate::sealed_names::{
    NAME_VERSION, bound_aad, open_bound, record_reference_bytes, record_space, seal_bound,
};
use frasil_base::ErrorClass;
use frasil_base::notation::push_field;
use frasil_crypto::labels;
use frasil_crypto::primitives::{
    hkdf, hkdf_extract, xchacha20poly1305_open, xchacha20poly1305_seal,
};
use frasil_crypto::sizes::{XCHACHA20POLY1305_NONCE, XCHACHA20POLY1305_TAG};
use frasil_events::EventId;

/// Bytes of a rotation ID in a rotation set.
const ID_BYTES: usize = 32;
/// The bytes of the sealed parent state beyond its rotation IDs: the
/// nonce, the set's count byte and the tag.
pub const PARENT_OVERHEAD: usize = XCHACHA20POLY1305_NONCE + 1 + XCHACHA20POLY1305_TAG;

fn malformed() -> KeyClass {
    ErrorClass::Malformed.into()
}

// ---------------------------------------------------------------------------
// The content key (section 2.2).

/// F's content key for a state of F and a state of P, with the HKDF steps
/// the vectors show.
#[derive(Clone)]
pub struct RestrictedKey {
    /// `"frasil/restricted-key/v1" || field(F) || field(P)`.
    pub info: Vec<u8>,
    /// `HKDF-Extract(salt = f(S_F), ikm = k_P(S_P))`.
    pub prk: Secret,
    /// `k_F(S_F, S_P)`.
    pub key: Secret,
}

impl core::fmt::Debug for RestrictedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RestrictedKey").finish_non_exhaustive()
    }
}

/// The content key's info: `"frasil/restricted-key/v1" || field(F) ||
/// field(P)`.
pub fn restricted_key_info(space: &EventId, parent: &EventId) -> Vec<u8> {
    let mut info = labels::RESTRICTED_KEY.to_vec();
    push_field(&mut info, space.as_bytes());
    push_field(&mut info, parent.as_bytes());
    info
}

/// `k_F(S_F, S_P) = HKDF(salt = f(S_F), ikm = k_P(S_P), info)`: what F uses
/// as `k(S)` for unit, object and metadata keys. `own_secret` is `f(S_F)`;
/// `parent_key` is `k_P(S_P)`, P's content key of the state the writer's
/// view held when it sealed.
pub fn restricted_key(
    space: &EventId,
    parent: &EventId,
    own_secret: &[u8; 32],
    parent_key: &[u8; 32],
) -> RestrictedKey {
    let info = restricted_key_info(space, parent);
    RestrictedKey {
        prk: hkdf_extract(own_secret, parent_key),
        key: hkdf(Some(own_secret), parent_key, &info),
        info,
    }
}

/// What a member of F receives of a state in a bundle (section 2.2): the
/// content secret `f(S_F)`, the upload seed `fw(S_F)` at `write`, and never
/// a grant slot, so a bundle sets only flags `0x01` and `0x02`. A space
/// wrap F makes for a space it grants carries the same.
pub fn restricted_bundle_contents(level: Level) -> Slots {
    bundle_contents(level, false)
}

// ---------------------------------------------------------------------------
// The restricted key reference (section 2.3).

/// `parent_key = HKDF(salt = none, ikm = f(S_F), info =
/// "frasil/parent-reference/v1")`.
pub fn parent_reference_key(own_secret: &[u8; 32]) -> Secret {
    hkdf(None, own_secret, labels::PARENT_REFERENCE)
}

/// `aad = "frasil/parent-reference/v1" || field(F) || encode_set(S_F)`.
pub fn parent_reference_aad(space: &EventId, own: &RotationSet) -> Vec<u8> {
    let mut aad = labels::PARENT_REFERENCE.to_vec();
    push_field(&mut aad, space.as_bytes());
    own.encode_into(&mut aad);
    aad
}

/// A restricted key reference's parts: F's own state in the clear, and
/// P's state sealed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RestrictedReference {
    /// The restricted space's own state, `S_F`.
    pub own: RotationSet,
    /// The nonce of the sealed parent state.
    pub nonce: [u8; XCHACHA20POLY1305_NONCE],
    /// `XChaCha20-Poly1305(parent_key, nonce, encode_set(S_P), aad)`, with
    /// its tag.
    pub sealed: Vec<u8>,
}

impl RestrictedReference {
    /// Seals P's state `parent` under F's own state `own`, whose content
    /// secret is `own_secret`, with the nonce given (section 2.3).
    pub fn seal_with(
        space: &EventId,
        own: &RotationSet,
        parent: &RotationSet,
        own_secret: &[u8; 32],
        nonce: &[u8; XCHACHA20POLY1305_NONCE],
    ) -> Self {
        let sealed = xchacha20poly1305_seal(
            &parent_reference_key(own_secret),
            nonce,
            &parent_reference_aad(space, own),
            &parent.encode(),
        );
        Self {
            own: own.clone(),
            nonce: *nonce,
            sealed,
        }
    }

    /// The reference's bytes: `encode_set(S_F) || nonce || sealed`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.own.encode();
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.sealed);
        out
    }

    /// The number of P's rotations the sealed state holds, `b`.
    pub fn parent_rotations(&self) -> usize {
        (self.sealed.len() + XCHACHA20POLY1305_NONCE).saturating_sub(PARENT_OVERHEAD) / ID_BYTES
    }

    /// Reads a restricted key reference before any key: "Reading a
    /// restricted key reference", steps 1 and 2. A peer cannot tell a
    /// restricted space's units from others', and reads these parts only.
    ///
    /// ```text
    /// 1. The reference starts with a rotation set S_F.   else Malformed / TooManyRotations
    /// 2. The rest is 41 + 32b bytes, with 1 <= b <= 64.  else Malformed / TooManyRotations
    /// ```
    ///
    /// # Errors
    ///
    /// `Malformed` or `TooManyRotations`.
    pub fn read(data: &[u8]) -> Result<Self, KeyClass> {
        // 1.
        let (KeyName::Set(own), rest) = KeyName::read(data, false)? else {
            return Err(malformed());
        };
        // 2.
        if rest.len() < PARENT_OVERHEAD + ID_BYTES
            || !(rest.len() - PARENT_OVERHEAD).is_multiple_of(ID_BYTES)
        {
            return Err(malformed());
        }
        if (rest.len() - PARENT_OVERHEAD) / ID_BYTES > MAX_ROTATIONS {
            return Err(KeyClass::TooManyRotations);
        }
        let (nonce, sealed) = rest
            .split_first_chunk::<XCHACHA20POLY1305_NONCE>()
            .ok_or_else(malformed)?;
        Ok(Self {
            own,
            nonce: *nonce,
            sealed: sealed.to_vec(),
        })
    }

    /// Steps 4 and 5: P's state, opened under F's own content secret
    /// `f(S_F)` (step 3 is the caller's: it holds that secret).
    ///
    /// ```text
    /// 4. The rest opens under parent_key, with the nonce and aad.  else Decrypt
    /// 5. The plaintext is a rotation set S_P of b rotations.       else Malformed
    /// ```
    ///
    /// # Errors
    ///
    /// `Decrypt`, then `Malformed`.
    pub fn open(&self, space: &EventId, own_secret: &[u8; 32]) -> Result<RotationSet, KeyClass> {
        // 4.
        let plaintext = xchacha20poly1305_open(
            &parent_reference_key(own_secret),
            &self.nonce,
            &parent_reference_aad(space, &self.own),
            &self.sealed,
        )?;
        // 5.
        let parent = RotationSet::decode(&plaintext).map_err(|_| malformed())?;
        if parent.len() != self.parent_rotations() {
            return Err(malformed());
        }
        Ok(parent)
    }
}

/// Steps 6 and 7 against F's log and P's log, as the reader holds them.
///
/// ```text
/// 6. Every ID of S_F is a rotation of F, and every ID of S_P a rotation
///    of P; a missing one is fetched, and the unit waits.         else NotARotation
/// 7. No ID of S_F or of S_P is in the past of another of the
///    same set.                                                   else Malformed
/// ```
///
/// # Errors
///
/// `NotARotation`; else `Pending` while the reader lacks a rotation's
/// event; then `Malformed`.
pub fn check_restricted_states(
    own: &RotationSet,
    parent: &RotationSet,
    own_log: &impl RotationLog,
    parent_log: &impl RotationLog,
) -> Result<(), KeyClass> {
    // 6.
    let lookups: Vec<Lookup> = own
        .ids()
        .iter()
        .map(|id| own_log.lookup(id))
        .chain(parent.ids().iter().map(|id| parent_log.lookup(id)))
        .collect();
    if lookups.contains(&Lookup::NotARotation) {
        return Err(KeyClass::NotARotation);
    }
    if lookups.contains(&Lookup::Missing) {
        return Err(ErrorClass::Pending.into());
    }
    // 7.
    fn concurrent(set: &RotationSet, log: &impl RotationLog) -> bool {
        let ids = set.ids();
        ids.iter()
            .all(|a| ids.iter().all(|b| a == b || !log.precedes(a, b)))
    }
    if !concurrent(own, own_log) || !concurrent(parent, parent_log) {
        return Err(malformed());
    }
    Ok(())
}

/// Reading a restricted key reference, every step in order (section 3.2):
/// the reference's parts, F's own content secret of `S_F` from
/// `own_secret_of`, P's state, and both states against their logs. Returns
/// `(S_F, S_P)`.
///
/// # Errors
///
/// Steps 1 and 2's `Malformed` or `TooManyRotations`; `Sealed` when the
/// reader does not hold `f(S_F)` (step 3); `Decrypt`; `Malformed`;
/// `NotARotation`, `Pending` or `Malformed` (steps 6 and 7).
pub fn read_restricted_reference(
    data: &[u8],
    space: &EventId,
    own_secret_of: impl FnOnce(&RotationSet) -> Option<Secret>,
    own_log: &impl RotationLog,
    parent_log: &impl RotationLog,
) -> Result<(RotationSet, RotationSet), KeyClass> {
    // 1, 2.
    let reference = RestrictedReference::read(data)?;
    // 3.
    let own_secret = own_secret_of(&reference.own).ok_or(ErrorClass::Sealed)?;
    // 4, 5.
    let parent = reference.open(space, &own_secret)?;
    // 6, 7.
    check_restricted_states(&reference.own, &parent, own_log, parent_log)?;
    Ok((reference.own, parent))
}

// ---------------------------------------------------------------------------
// Sealed names in a restricted space (section 3.2; keys.md, "Sealed
// names").

/// A name of F's associated data: keys.md's, bound to the restricted
/// reference's bytes.
pub fn restricted_name_aad(
    space: &EventId,
    reference: &RestrictedReference,
    kind: u8,
    id: &[u8],
) -> Vec<u8> {
    bound_aad(space, &reference.encode(), kind, id)
}

/// Seals a name of F under the metadata key of `k_F` of the state
/// `reference` names, bound to the restricted reference's bytes, with the
/// nonce given. As [`crate::sealed_names::seal_name_with`] otherwise.
///
/// # Errors
///
/// `Malformed` for a kind or ID that breaks its rule; `InvalidName`.
pub fn seal_restricted_name_with(
    metadata_key: &[u8; 32],
    space: &EventId,
    reference: &RestrictedReference,
    kind: u8,
    id: &[u8],
    name: &str,
    nonce: &[u8; XCHACHA20POLY1305_NONCE],
) -> Result<Vec<u8>, KeyClass> {
    seal_bound(
        metadata_key,
        space,
        &reference.encode(),
        kind,
        id,
        name,
        nonce,
    )
}

/// A record of F: `0x01 || space (32) || field(reference) || sealed`, its
/// reference the restricted form.
pub fn encode_restricted_record(
    space: &EventId,
    reference: &RestrictedReference,
    sealed: &[u8],
) -> Vec<u8> {
    let mut record = vec![NAME_VERSION];
    record.extend_from_slice(space.as_bytes());
    push_field(&mut record, &reference.encode());
    record.extend_from_slice(sealed);
    record
}

/// Reads a record of F and opens its name, in keys.md's order ("Reading a
/// record"), with this extension's step 4 and step 5. `content_key_of`
/// gives `k_F(S_F, S_P)` for a reference whose `f(S_F)` and `k_P(S_P)` the
/// reader holds: it opens the parent state itself.
///
/// # Errors
///
/// As [`crate::sealed_names::open_record`], except that step 4 reads the
/// restricted form, so a plain rotation set is `Malformed`, and step 5's
/// `MissingState` is for a reader that lacks `f(S_F)` or `k_P(S_P)`.
pub fn open_restricted_record(
    record: &[u8],
    space: &EventId,
    content_key_of: impl FnOnce(&RestrictedReference) -> Option<Secret>,
    kind: u8,
    id: &[u8],
) -> Result<String, KeyClass> {
    // 1, 2, 3.
    if record_space(record)? != *space {
        return Err(ErrorClass::Decrypt.into());
    }
    // 4.
    let (bytes, sealed) = record_reference_bytes(record)?;
    let reference = RestrictedReference::read(bytes)?;
    // 5.
    let content_key = content_key_of(&reference).ok_or(KeyClass::MissingState)?;
    // 6.
    open_bound(
        &crate::derive::metadata_key(&content_key),
        space,
        bytes,
        kind,
        id,
        sealed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(bytes: &[u8]) -> RotationSet {
        RotationSet::new(bytes.iter().map(|&b| EventId([b; 32]))).unwrap()
    }

    #[test]
    fn a_reference_round_trips_and_is_42_plus_32_per_rotation() {
        let space = EventId([7; 32]);
        let reference =
            RestrictedReference::seal_with(&space, &set(&[1, 2]), &set(&[3]), &[9; 32], &[5; 24]);
        let bytes = reference.encode();
        assert_eq!(bytes.len(), 42 + 32 * 3);
        let read = RestrictedReference::read(&bytes).unwrap();
        assert_eq!(read, reference);
        assert_eq!(read.parent_rotations(), 1);
        assert_eq!(read.open(&space, &[9; 32]), Ok(set(&[3])));
        assert_eq!(read.open(&space, &[8; 32]), Err(ErrorClass::Decrypt.into()));
        assert_eq!(
            RestrictedReference::read(&set(&[1]).encode()),
            Err(malformed())
        );
    }

    #[test]
    fn a_restricted_bundle_has_no_grant_slot() {
        assert_eq!(restricted_bundle_contents(Level::Write).flags(), 0x03);
        assert_eq!(restricted_bundle_contents(Level::Read).flags(), 0x01);
    }
}
