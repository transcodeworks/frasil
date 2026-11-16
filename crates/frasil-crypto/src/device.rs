//! A device's keys and its device ID (crypto.md, "A device's keys" and
//! "Keys by their hash").
//!
//! ```text
//! kc        = SHA-256("frasil/device-keys-commitment/v1" || field(mldsa) || field(xwing))
//! device ID = SHA-256("frasil/device-id/v1" || ed (32) || kc (32))
//! ```
//!
//! A holder with no X-Wing key, a recovery agent or an administrator
//! pseudonym, hashes `xwing` as the empty string.
//!
//! The three 32-byte values are distinct types, so that one is never taken
//! for another:
//!
//! - [`IdentityKey`], the Ed25519 key `ed`, which signs and which an
//!   envelope carries, but which never names a device;
//! - [`KeysCommitment`], `kc`, which names the ML-DSA-65 and X-Wing keys;
//! - [`DeviceId`], which names a device in every format.
//!
//! [`Signatory`] is `ed || kc`, the 64 bytes a structure outside an envelope
//! carries for its signer. [`HybridKeys`] are the keys `kc` commits to, and
//! [`DeviceKeys`] all three keys of a device. A verifier takes
//! [`HybridKeys`] from any source and accepts them exactly when their
//! commitment is the signer's `kc`.

use crate::ErrorClass;
use crate::keys::{mldsa_valid, xwing_valid};
use crate::labels::{DEVICE_ID, DEVICE_KEYS_COMMITMENT};
use crate::primitives::{Sha256Hasher, sha256};
use crate::sizes::{MLDSA65_PUBLIC, XWING_PUBLIC};
use core::fmt;
use std::collections::BTreeMap;

/// Writes the first eight bytes of a 32-byte value as hex, then `…`.
fn short_hex(bytes: &[u8; 32], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &bytes[..8] {
        write!(f, "{byte:02x}")?;
    }
    f.write_str("…")
}

macro_rules! name_32 {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// The 32 bytes.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                short_hex(&self.0, f)
            }
        }
    };
}

name_32! {
    /// A holder's Ed25519 identity key, `ed`: it signs, and an envelope
    /// carries it, but it never names a device. Two holders may share one
    /// and differ in `kc`; they are two devices.
    ///
    /// It has passed `ed25519_valid` where it entered.
    IdentityKey
}

name_32! {
    /// A keys commitment, `kc`: the hash of a holder's ML-DSA-65 key and its
    /// X-Wing key, or of the empty string for a holder that has none.
    KeysCommitment
}

name_32! {
    /// A device ID: the hash of a holder's Ed25519 key and its keys
    /// commitment. Every format that names a device names this.
    ///
    /// Its order is the byte order.
    DeviceId
}

/// `kc = SHA-256("frasil/device-keys-commitment/v1" || field(mldsa) ||
/// field(xwing))`, `xwing` empty for a holder with no X-Wing key. The keys
/// have passed their checks where they entered.
pub fn keys_commitment(mldsa: &[u8], xwing: Option<&[u8]>) -> KeysCommitment {
    let xwing = xwing.unwrap_or_default();
    let mut hasher = Sha256Hasher::new();
    hasher.update(DEVICE_KEYS_COMMITMENT);
    hasher.update(&field_length(mldsa));
    hasher.update(mldsa);
    hasher.update(&field_length(xwing));
    hasher.update(xwing);
    KeysCommitment(hasher.finish())
}

/// `u32be(len(x))`, the prefix of `field(x)`.
fn field_length(x: &[u8]) -> [u8; 4] {
    u32::try_from(x.len())
        .expect("a key is shorter than 2^32 bytes")
        .to_be_bytes()
}

/// `device ID = SHA-256("frasil/device-id/v1" || ed || kc)`.
pub fn device_id(ed: &IdentityKey, kc: &KeysCommitment) -> DeviceId {
    DeviceId(sha256(&[DEVICE_ID, &ed.0, &kc.0]))
}

/// `ed || kc`, 64 bytes: what a structure outside an envelope carries for
/// its signer, from which anyone computes the device ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signatory {
    /// The Ed25519 key that signs.
    pub ed: IdentityKey,
    /// The commitment to the holder's other keys.
    pub kc: KeysCommitment,
}

impl Signatory {
    /// The 64 bytes `ed || kc`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0; 64];
        out[..32].copy_from_slice(&self.ed.0);
        out[32..].copy_from_slice(&self.kc.0);
        out
    }

    /// Splits 64 bytes as `ed || kc`. The caller checks `ed` with
    /// `ed25519_valid` where it enters.
    ///
    /// # Errors
    ///
    /// `Malformed` for any length but 64.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ErrorClass> {
        let bytes: &[u8; 64] = bytes.try_into().map_err(|_| ErrorClass::Malformed)?;
        let (ed, kc) = bytes.split_at(32);
        Ok(Self {
            ed: IdentityKey(ed.try_into().expect("32 bytes")),
            kc: KeysCommitment(kc.try_into().expect("32 bytes")),
        })
    }

    /// The device ID of `ed` and `kc`.
    pub fn device_id(&self) -> DeviceId {
        device_id(&self.ed, &self.kc)
    }
}

impl fmt::Debug for Signatory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signatory")
            .field("ed", &self.ed)
            .field("kc", &self.kc)
            .finish()
    }
}

/// The keys a keys commitment commits to: an ML-DSA-65 key and an X-Wing
/// key, or none for a holder that has none. Each passed its check where it
/// entered; the commitment is computed once.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HybridKeys {
    mldsa: Box<[u8; MLDSA65_PUBLIC]>,
    xwing: Option<Box<[u8; XWING_PUBLIC]>>,
    kc: KeysCommitment,
}

impl HybridKeys {
    /// The keys of an ML-DSA-65 key and an X-Wing key, or none, each checked
    /// as it enters (crypto.md, "Where keys are checked").
    ///
    /// # Errors
    ///
    /// `Malformed` for an ML-DSA-65 key that is not 1,952 bytes;
    /// `InvalidKey` for an X-Wing key `xwing_valid` refuses.
    pub fn new(mldsa: &[u8], xwing: Option<&[u8]>) -> Result<Self, ErrorClass> {
        mldsa_valid(mldsa)?;
        if let Some(xwing) = xwing {
            xwing_valid(xwing)?;
        }
        Ok(Self::from_checked(
            Box::new(mldsa.try_into().expect("1,952 bytes")),
            xwing.map(|xwing| Box::new(xwing.try_into().expect("1,216 bytes"))),
        ))
    }

    /// The keys of keys whose lengths the types fix, the X-Wing key having
    /// passed `xwing_valid` already.
    pub fn from_checked(
        mldsa: Box<[u8; MLDSA65_PUBLIC]>,
        xwing: Option<Box<[u8; XWING_PUBLIC]>>,
    ) -> Self {
        let kc = keys_commitment(&mldsa[..], xwing.as_deref().map(|key| &key[..]));
        Self { mldsa, xwing, kc }
    }

    /// The ML-DSA-65 key.
    pub fn mldsa(&self) -> &[u8; MLDSA65_PUBLIC] {
        &self.mldsa
    }

    /// The X-Wing key, or `None` for a holder that has none.
    pub fn xwing(&self) -> Option<&[u8; XWING_PUBLIC]> {
        self.xwing.as_deref()
    }

    /// Their keys commitment, `kc`.
    pub fn commitment(&self) -> &KeysCommitment {
        &self.kc
    }

    /// Among `candidates` from any source, the keys whose commitment is
    /// `kc`, or `None` (crypto.md, "Keys by their hash"). No source is
    /// trusted: only keys that hash to `kc` are the holder's.
    pub fn find<'a>(
        kc: &KeysCommitment,
        candidates: impl IntoIterator<Item = &'a HybridKeys>,
    ) -> Option<&'a HybridKeys> {
        candidates.into_iter().find(|keys| keys.kc == *kc)
    }
}

impl fmt::Debug for HybridKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKeys")
            .field("kc", &self.kc)
            .field("xwing", &self.xwing.is_some())
            .finish_non_exhaustive()
    }
}

/// All three public keys of a holder: its Ed25519 key and the keys its `kc`
/// commits to.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DeviceKeys {
    /// The Ed25519 identity key.
    pub ed: IdentityKey,
    /// The ML-DSA-65 key and the X-Wing key, or none.
    pub keys: HybridKeys,
}

impl DeviceKeys {
    /// `ed || kc`.
    pub fn signatory(&self) -> Signatory {
        Signatory {
            ed: self.ed,
            kc: *self.keys.commitment(),
        }
    }

    /// The device ID the three keys give.
    pub fn device_id(&self) -> DeviceId {
        device_id(&self.ed, self.keys.commitment())
    }

    /// Whether the three keys hash to `id` (crypto.md, "Keys by their
    /// hash").
    ///
    /// # Errors
    ///
    /// `NotCommitted` when they do not.
    pub fn check(&self, id: &DeviceId) -> Result<(), ErrorClass> {
        if self.device_id() == *id {
            Ok(())
        } else {
            Err(ErrorClass::NotCommitted)
        }
    }
}

impl fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKeys")
            .field("device_id", &self.device_id())
            .field("ed", &self.ed)
            .field("keys", &self.keys)
            .finish()
    }
}

/// Where a replica finds keys by their hash (crypto.md, "Keys by their
/// hash"): two lookups, one by keys commitment and one by device ID.
///
/// An implementation may be fed from any source: every record it opens,
/// valid or void, the device lists it reads, granted spaces, roots and
/// enrolments, admission exchanges, a cache. No source is trusted, because
/// what it returns is used only if it hashes to the commitment or device ID
/// asked for; an implementation should still index entries by the hash it
/// computed itself, so that it never answers with keys of another hash.
///
/// A verdict of `NoHybridKey` (or of a lookup by device ID that found
/// nothing) is pending, not final: the caller runs the check again when
/// either lookup grows, which [`KeyRing::revision`] counts.
pub trait KeySource {
    /// The keys whose commitment is `kc`, if held.
    fn hybrid_keys(&self, kc: &KeysCommitment) -> Option<HybridKeys>;

    /// All three keys of the holder whose device ID is `id`, if held.
    fn device_keys(&self, id: &DeviceId) -> Option<DeviceKeys>;
}

impl<T: KeySource + ?Sized> KeySource for &T {
    fn hybrid_keys(&self, kc: &KeysCommitment) -> Option<HybridKeys> {
        (**self).hybrid_keys(kc)
    }

    fn device_keys(&self, id: &DeviceId) -> Option<DeviceKeys> {
        (**self).device_keys(id)
    }
}

/// Two sources, the first asked first.
impl<A: KeySource, B: KeySource> KeySource for (A, B) {
    fn hybrid_keys(&self, kc: &KeysCommitment) -> Option<HybridKeys> {
        self.0.hybrid_keys(kc).or_else(|| self.1.hybrid_keys(kc))
    }

    fn device_keys(&self, id: &DeviceId) -> Option<DeviceKeys> {
        self.0.device_keys(id).or_else(|| self.1.device_keys(id))
    }
}

/// No keys at all.
impl KeySource for () {
    fn hybrid_keys(&self, _: &KeysCommitment) -> Option<HybridKeys> {
        None
    }

    fn device_keys(&self, _: &DeviceId) -> Option<DeviceKeys> {
        None
    }
}

/// Keys indexed by the hashes computed from them: by keys commitment, and,
/// for holders whose Ed25519 key is known too, by device ID.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct KeyRing {
    by_kc: BTreeMap<KeysCommitment, HybridKeys>,
    by_id: BTreeMap<DeviceId, (IdentityKey, KeysCommitment)>,
    revision: u64,
}

impl KeyRing {
    /// An empty ring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds keys under the commitment they hash to. Returns whether they
    /// were new.
    pub fn add_keys(&mut self, keys: HybridKeys) -> bool {
        let kc = *keys.commitment();
        if self.by_kc.contains_key(&kc) {
            return false;
        }
        self.by_kc.insert(kc, keys);
        self.revision += 1;
        true
    }

    /// Adds a holder's three keys, under its device ID and its keys
    /// commitment. Returns whether anything was new.
    pub fn add_device(&mut self, device: DeviceKeys) -> bool {
        let id = device.device_id();
        let kc = *device.keys.commitment();
        let mut new = false;
        if let std::collections::btree_map::Entry::Vacant(entry) = self.by_id.entry(id) {
            entry.insert((device.ed, kc));
            self.revision += 1;
            new = true;
        }
        self.add_keys(device.keys) || new
    }

    /// Adds every entry of `other`. Returns whether anything was new.
    pub fn extend(&mut self, other: &KeyRing) -> bool {
        let mut new = false;
        for keys in other.by_kc.values() {
            new |= self.add_keys(keys.clone());
        }
        for (id, (ed, kc)) in &other.by_id {
            if let std::collections::btree_map::Entry::Vacant(entry) = self.by_id.entry(*id) {
                entry.insert((*ed, *kc));
                self.revision += 1;
                new = true;
            }
        }
        new
    }

    /// A count that grows whenever an entry is added: a caller that holds
    /// verdicts pending on missing keys checks them again when it has
    /// changed.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// How many key commitments are held.
    pub fn len(&self) -> usize {
        self.by_kc.len()
    }

    /// Whether no keys are held.
    pub fn is_empty(&self) -> bool {
        self.by_kc.is_empty()
    }

    /// The keys whose commitment is `kc`, borrowed.
    pub fn get(&self, kc: &KeysCommitment) -> Option<&HybridKeys> {
        self.by_kc.get(kc)
    }
}

impl KeySource for KeyRing {
    fn hybrid_keys(&self, kc: &KeysCommitment) -> Option<HybridKeys> {
        self.by_kc.get(kc).cloned()
    }

    fn device_keys(&self, id: &DeviceId) -> Option<DeviceKeys> {
        let (ed, kc) = self.by_id.get(id)?;
        Some(DeviceKeys {
            ed: *ed,
            keys: self.by_kc.get(kc)?.clone(),
        })
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRing")
            .field("commitments", &self.by_kc.len())
            .field("devices", &self.by_id.len())
            .field("revision", &self.revision)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::FixtureKeys;

    #[test]
    fn a_holder_without_x_wing_hashes_an_empty_string() {
        let mldsa = [7; MLDSA65_PUBLIC];
        let mut input = DEVICE_KEYS_COMMITMENT.to_vec();
        input.extend_from_slice(&1952u32.to_be_bytes());
        input.extend_from_slice(&mldsa);
        input.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(keys_commitment(&mldsa, None).0, sha256(&[&input]));
        assert_eq!(
            keys_commitment(&mldsa, None),
            keys_commitment(&mldsa, Some(&[]))
        );
    }

    #[test]
    fn one_ed25519_key_under_two_key_sets_is_two_devices() {
        let laptop = FixtureKeys::from_identity_seed(&[1; 32]);
        let phone = FixtureKeys::from_identity_seed(&[2; 32]);
        let own = HybridKeys::new(&laptop.mldsa_public[..], Some(&laptop.xwing[..])).unwrap();
        let other = HybridKeys::new(&phone.mldsa_public[..], Some(&phone.xwing[..])).unwrap();
        let ed = IdentityKey(laptop.identity);
        let first = DeviceKeys { ed, keys: own };
        let second = DeviceKeys { ed, keys: other };
        assert_ne!(first.device_id(), second.device_id());
        assert_eq!(
            second.check(&first.device_id()),
            Err(ErrorClass::NotCommitted)
        );
        assert_eq!(
            Signatory::from_bytes(&first.signatory().to_bytes()),
            Ok(first.signatory())
        );
        assert_eq!(Signatory::from_bytes(&[0; 63]), Err(ErrorClass::Malformed));

        let mut ring = KeyRing::new();
        assert!(ring.add_device(first.clone()));
        assert!(!ring.add_device(first.clone()));
        assert_eq!(ring.revision(), 2);
        assert_eq!(ring.device_keys(&first.device_id()), Some(first.clone()));
        assert_eq!(ring.device_keys(&second.device_id()), None);
        assert_eq!(ring.hybrid_keys(second.keys.commitment()), None);
        assert!(ring.add_keys(second.keys.clone()));
        assert_eq!(
            ring.hybrid_keys(second.keys.commitment()),
            Some(second.keys)
        );
    }
}
