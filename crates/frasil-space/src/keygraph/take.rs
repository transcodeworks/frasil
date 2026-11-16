//! Taking a key (keys.md, "Taking a key"), and the trial decryption a
//! device runs over a delivery ("Reading key names, bundles, wraps and
//! links").
//!
//! - **Slot by slot.** A device that opens the secrets of a single rotation
//!   derives each one's public half and compares it with that rotation's
//!   visible keys 11, 12 and 3. It keeps every slot that matches and drops
//!   the others (`KeyMismatch`), and keeps looking for another delivery of
//!   what it dropped.
//! - **A rotation key that does not match is not that rotation's key.** An
//!   event sealed under a state whose rotation keys the replica lacks, or
//!   holds only unmatched, is one it cannot open (`Sealed`).
//! - **A merged key received whole is provisional,** until the device
//!   derives it itself from inputs that each matched. A space event that a
//!   provisional key fails to open is held `Sealed`, never `BadSeal`.

use crate::RosterClass;
use frasil_base::ErrorClass;
use frasil_events::EventId;
use frasil_keys::body::RotationKeys;
use frasil_keys::bundle::Bundle;
use frasil_keys::derive::{GrantKey, Secret, read_credential, upload_key};
use frasil_keys::{KeyName, RotationSet};
use zeroize::Zeroizing;

/// A slot of a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Slot {
    /// The content key.
    Content,
    /// The upload seed.
    Upload,
    /// The grant seed.
    Grant,
}

impl Slot {
    /// The slot's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Upload => "upload",
            Self::Grant => "grant",
        }
    }
}

/// The slots of a single rotation's bundle that its commitments confirm.
#[derive(Default)]
pub struct Taken {
    /// `k_R`, when its read credential is the rotation's key 11.
    pub content: Option<Secret>,
    /// `w_R`, when its upload key is the rotation's key 12.
    pub upload: Option<Secret>,
    /// `g_R`, when its commitment, with the rotation's `break`, is the
    /// rotation's key 3.
    pub grant: Option<Secret>,
    /// The slots dropped (`KeyMismatch`), in slot order.
    pub dropped: Vec<Slot>,
}

impl core::fmt::Debug for Taken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Taken")
            .field("kept", &self.kept())
            .field("dropped", &self.dropped)
            .finish()
    }
}

impl Taken {
    /// The slots kept, in slot order.
    pub fn kept(&self) -> Vec<Slot> {
        [
            (Slot::Content, self.content.is_some()),
            (Slot::Upload, self.upload.is_some()),
            (Slot::Grant, self.grant.is_some()),
        ]
        .into_iter()
        .filter_map(|(slot, kept)| kept.then_some(slot))
        .collect()
    }
}

/// Checks a single rotation's bundle slot by slot against the rotation's
/// visible keys and its sealed `break`.
pub fn take_slots(bundle: &Bundle, rotation: &RotationKeys, is_break: bool) -> Taken {
    let mut taken = Taken::default();
    if let Some(k) = bundle.content() {
        if read_credential(k).public == rotation.read {
            taken.content = Some(Zeroizing::new(*k));
        } else {
            taken.dropped.push(Slot::Content);
        }
    }
    if let Some(w) = bundle.upload() {
        if upload_key(w).public == rotation.upload {
            taken.upload = Some(Zeroizing::new(*w));
        } else {
            taken.dropped.push(Slot::Upload);
        }
    }
    if let Some(g) = bundle.grant() {
        if GrantKey::derive(g).commitment(is_break) == rotation.grant_commitment {
            taken.grant = Some(Zeroizing::new(*g));
        } else {
            taken.dropped.push(Slot::Grant);
        }
    }
    taken
}

/// Where a state's key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySource {
    /// Derived from rotation keys that each matched their commitments.
    Derived,
    /// A merged state's key received whole by wrap: provisional.
    Wrapped,
}

/// What a space event whose body a key fails to open is (keys.md, "Taking
/// a key"; roster.md, "Space events a replica cannot open"): `BadSeal`
/// under a derived key, which proves the author sealed under something
/// else; `Sealed` under a provisional key, whose fault may be the
/// wrapper's.
pub fn seal_mismatch(source: KeySource) -> RosterClass {
    match source {
        KeySource::Derived => ErrorClass::BadSeal.into(),
        KeySource::Wrapped => ErrorClass::Sealed.into(),
    }
}

/// Whether a device tries a delivery's wraps: every rotation its names
/// name is an event of the log it holds, and it lacks a state the delivery
/// names and is entitled to it (keys.md, "Trial decryption"). A self
/// reference names the carrying event, which the device holds.
pub fn tries(
    names: &[&KeyName],
    in_log: impl Fn(&EventId) -> bool,
    holds: impl Fn(&KeyName) -> bool,
    entitled: impl Fn(&KeyName) -> bool,
) -> bool {
    let all_in_log = names.iter().all(|name| match name.as_set() {
        Some(set) => set.ids().iter().all(&in_log),
        None => true,
    });
    all_in_log && names.iter().any(|name| !holds(name) && entitled(name))
}

/// [`tries`] in a key graph rooted at a checkpoint (keys.md, "Keys after a
/// checkpoint"; [`frasil_keys::checkpoint::tries`]): a delivery of the
/// checkpoint or an event after it (`carrier`) may also name rotations
/// before the checkpoint that the device neither holds nor can fetch
/// (`fetchable`), never a late one. With no checkpoint, [`tries`]
/// unchanged.
pub fn tries_rooted<R: frasil_keys::checkpoint::Rooted + ?Sized>(
    rooted: Option<&R>,
    carrier: &EventId,
    names: &[&KeyName],
    in_log: impl Fn(&EventId) -> bool,
    fetchable: impl Fn(&EventId) -> bool,
    holds: impl Fn(&KeyName) -> bool,
    entitled: impl Fn(&KeyName) -> bool,
) -> bool {
    match rooted {
        None => tries(names, in_log, holds, entitled),
        Some(rooted) => frasil_keys::checkpoint::tries(
            rooted, carrier, names, in_log, fetchable, holds, entitled,
        ),
    }
}

/// Where a key taken for `state` came from (keys.md, "Taking a key"): a
/// merged state received whole is provisional, and so, after a checkpoint,
/// is a state with a rotation whose event the replica does not hold
/// ([`frasil_keys::checkpoint::provisional`]); a key of rotations it holds,
/// each checked against its commitments, is derived.
pub fn key_source(state: &RotationSet, holds_event: impl Fn(&EventId) -> bool) -> KeySource {
    if frasil_keys::checkpoint::provisional(state, holds_event) {
        KeySource::Wrapped
    } else {
        KeySource::Derived
    }
}
