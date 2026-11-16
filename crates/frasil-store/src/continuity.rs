//! The mark, continuity and the head after a restore (at-rest.md, "The
//! mark", "Committing", "Continuity", "After a restore").
//!
//! ```text
//! mark = u8(1) || nonce (24)
//!        || XChaCha20-Poly1305(seal_key(s), nonce, store ID (16) || u64be(generation),
//!                              "frasil/at-rest/mark/v1" || u8(1) || device ID)   65 bytes
//! ```
//!
//! The mark holds nothing secret. It is sealed so that only this device
//! makes one that opens, and so that it names no store a reader could match.
//!
//! **Mark before commit.** Before a commit that holds an event a signer
//! of this device signed, the device writes the mark for `generation + 1`
//! to the device-bound slot, durably, then commits with the head at
//! `generation + 1`; once per batch when it batches writes. Other commits
//! leave the generation. In restore mode `never-restored` or `none`, no mark
//! is written.

use crate::keys::StoreKeys;
use crate::tables::{Head, Restore};
use frasil_base::ErrorClass;
use frasil_crypto::device::DeviceId;
use frasil_crypto::labels::AT_REST_MARK;
use frasil_crypto::primitives::{xchacha20poly1305_open, xchacha20poly1305_seal};

/// The mark's version, its first byte.
pub const VERSION: u8 = 0x01;
/// The mark: version, nonce, the sealed store ID and generation, and tag.
pub const MARK_BYTES: usize = 1 + 24 + 16 + 8 + 16;

/// The mark's associated data: `"frasil/at-rest/mark/v1" || u8(1) ||
/// device ID`.
pub fn mark_aad(device_id: &DeviceId) -> Vec<u8> {
    [AT_REST_MARK, &[VERSION], &device_id.0[..]].concat()
}

/// The mark for a store ID and generation, with its nonce given. A caller
/// draws the nonce with `frasil_crypto::random_bytes`, anew for every mark.
pub fn seal_mark_with(
    store: &StoreKeys,
    device_id: &DeviceId,
    store_id: &[u8; 16],
    generation: u64,
    nonce: &[u8; 24],
) -> [u8; MARK_BYTES] {
    let plaintext = [&store_id[..], &generation.to_be_bytes()].concat();
    let sealed = xchacha20poly1305_seal(
        store.keys().seal_key(),
        nonce,
        &mark_aad(device_id),
        &plaintext,
    );
    let mut mark = [0u8; MARK_BYTES];
    mark[0] = VERSION;
    mark[1..25].copy_from_slice(nonce);
    mark[25..].copy_from_slice(&sealed);
    mark
}

/// Opens a mark, in order: its store ID and generation.
///
/// # Errors
///
/// `Malformed` if it is empty; `UnsupportedVersion` if its version is not
/// 1; `Malformed` if it is not 65 bytes; `Decrypt` if the AEAD does not
/// open.
pub fn open_mark(
    store: &StoreKeys,
    device_id: &DeviceId,
    mark: &[u8],
) -> Result<([u8; 16], u64), ErrorClass> {
    let Some(&version) = mark.first() else {
        return Err(ErrorClass::Malformed);
    };
    if version != VERSION {
        return Err(ErrorClass::UnsupportedVersion);
    }
    if mark.len() != MARK_BYTES {
        return Err(ErrorClass::Malformed);
    }
    let nonce: &[u8; 24] = mark[1..25].try_into().expect("24 bytes");
    let plaintext = xchacha20poly1305_open(
        store.keys().seal_key(),
        nonce,
        &mark_aad(device_id),
        &mark[25..],
    )?;
    let store_id = plaintext[..16].try_into().expect("a mark seals 24 bytes");
    let generation = u64::from_be_bytes(plaintext[16..].try_into().expect("8 bytes"));
    Ok((store_id, generation))
}

/// The application's restore mode (at-rest.md, "Continuity").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RestoreMode {
    /// `device-bound`: the application gives a device-bound slot, a place no
    /// backup restores. An application should use this mode wherever the
    /// platform has such a place.
    DeviceBound,
    /// `never-restored`: the application states that its store is never
    /// restored from a backup. It may state it for a browser's storage.
    NeverRestored,
    /// `none`: neither; every start counts as a restore.
    None,
}

impl RestoreMode {
    /// The mode's name, as at-rest.md writes it.
    pub fn name(self) -> &'static str {
        match self {
            Self::DeviceBound => "device-bound",
            Self::NeverRestored => "never-restored",
            Self::None => "none",
        }
    }

    /// The mode of this name, if it is one.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "device-bound" => Some(Self::DeviceBound),
            "never-restored" => Some(Self::NeverRestored),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// Whether the device writes a mark before a commit that holds an event
    /// it signed: only in mode `device-bound`.
    pub fn writes_mark(self) -> bool {
        self == Self::DeviceBound
    }
}

/// What `continuity` finds. It never fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Continuity {
    /// The store is the one the device last wrote.
    Current,
    /// The store was restored, or lost: the device records it and syncs each
    /// log before it signs there.
    Restored,
}

impl Continuity {
    /// The outcome's name, as at-rest.md writes it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Current => "Current",
            Self::Restored => "Restored",
        }
    }
}

/// `continuity(mode, head, mark)`, in order, at every open of the store.
/// `head` is `None` when the store has no head, or none that opens; `mark`
/// is the device-bound slot's content, `None` when it holds none.
pub fn continuity(
    store: &StoreKeys,
    device_id: &DeviceId,
    mode: RestoreMode,
    head: Option<&Head>,
    mark: Option<&[u8]>,
) -> Continuity {
    // Step 1: keys that open with no head mean a lost store.
    let Some(head) = head else {
        return Continuity::Restored;
    };
    // Step 2.
    if mode == RestoreMode::NeverRestored {
        return Continuity::Current;
    }
    // Step 3.
    if mode == RestoreMode::None {
        return Continuity::Restored;
    }
    let Some(Ok((store_id, generation))) = mark.map(|mark| open_mark(store, device_id, mark))
    else {
        return Continuity::Restored;
    };
    // Steps 4 and 5.
    if store_id == head.store_id && generation == head.generation {
        Continuity::Current
    } else {
        Continuity::Restored
    }
}

/// The head that records a restore (at-rest.md, "After a restore", step 1):
/// with `g` one above the larger of the head's and the mark's generation
/// (the head's alone if no mark opens), the head at `g`, key 4 set to `g`,
/// key 5 empty, and its tips kept. The device then writes the mark for `g`
/// and commits this head.
///
/// `mark_generation` is the generation of the device-bound slot's mark if it
/// opens, whatever store it names.
pub fn after_restore(head: &Head, mark_generation: Option<u64>) -> Head {
    let g = head
        .generation
        .max(mark_generation.unwrap_or(0))
        .saturating_add(1);
    Head {
        store_id: head.store_id,
        generation: g,
        tips: head.tips.clone(),
        restore: Some(Restore {
            found_at: g,
            synced: Vec::new(),
        }),
        revision: head.revision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_size() {
        assert_eq!(MARK_BYTES, 65);
    }

    #[test]
    fn the_head_after_a_restore() {
        let mut head = Head::new([1; 16]);
        head.generation = 2;
        let after = after_restore(&head, Some(3));
        assert_eq!(after.generation, 4);
        assert_eq!(after.restore.as_ref().map(|r| r.found_at), Some(4));
        assert!(!after.may_sign(&[5; 32]));
        assert_eq!(after_restore(&head, None).generation, 3);
        assert_eq!(after_restore(&head, Some(1)).generation, 3);
    }
}
