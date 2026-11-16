//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's key formats: rotations, derivations, bundles, wraps and links.
//!
//! Specified by `docs/spec/keys.md`, section 2 (Formats), sections 3.1 to
//! 3.3, section 3.15 (Reading a unit's key reference), section 3.16
//! (Sealed names) and section 3.17 (Keys after a checkpoint). Its vectors are the format families of
//! `docs/spec/vectors/keys.json`.
//!
//! - [`names`]: rotation sets, self references and key names (keys.md,
//!   "Rotations and states", "Reading key names, bundles, wraps and links").
//! - [`derive`](mod@derive): merged secrets, the grant key and its
//!   commitment, the storage credentials, the metadata and object keys, and
//!   a space event's body key and its commitment ("Derivations", "The space
//!   event's body").
//! - [`bundle`]: the recipient bundle and who receives what ("The recipient
//!   bundle").
//! - [`wraps`]: bundle wraps and space wraps, and trial decryption ("Bundle
//!   wraps and space wraps").
//! - [`links`]: links and gap records ("Links and gap records").
//! - [`body`]: the space event's body, its visible part and its sealed part,
//!   and the checks of "Checking a space event's body".
//! - [`context`]: the checks against the event and its place, with the
//!   roster's facts as inputs ("Checks against the event and its place").
//! - [`reference`]: a unit's key reference ("Key references in units",
//!   "Reading a unit's key reference").
//! - [`sealed_names`]: sealed names and their records ("Sealed names").
//! - [`checkpoint`]: what a checkpoint changes in the key graph ("Keys
//!   after a checkpoint"): the record object's state, the rotations a key
//!   graph rooted at a checkpoint counts, entitlement to states before it,
//!   trial decryption and taking keys across it, and what a replica keeps
//!   when it forgets the past.
//!
//! With feature `ext-invite-links`, `ext_invite_links` holds what an
//! invite key receives and whether a record's invite key counts as inside
//! after a checkpoint.
//!
//! With feature `ext-restricted-spaces`, `ext_restricted_spaces` holds
//! ext-restricted-spaces.md's formats: a restricted space's content key,
//! the restricted key reference, and sealed names under it.
//!
//! The crate reads no clock, does no IO and draws no randomness: every
//! nonce and every X-Wing encapsulation randomness comes in as an argument
//! (the `_with` forms), so the vectors can drive them. A caller draws them
//! with `frasil_crypto::random_bytes`. What needs the roster (the valid set,
//! places, entitlement, notices, the key graph) is `frasil-space`'s; this
//! crate takes the roster's facts as inputs where keys.md's checks need
//! them.
//!
//! # Where a format binds `log`
//!
//! keys.md binds `field(log)`: `field` of the carrying event's `log`, the
//! space ID, or inside a genesis, which has no `log`, `field` of the
//! genesis's 16-byte `nonce` (visible key 13). Every function here that
//! takes `log: &[u8]` takes those raw bytes, the 32-byte space ID or the
//! 16-byte nonce, and applies `field` itself.

pub mod body;
pub mod bundle;
pub mod checkpoint;
pub mod context;
pub mod derive;
#[cfg(feature = "ext-invite-links")]
pub mod ext_invite_links;
#[cfg(feature = "ext-restricted-spaces")]
pub mod ext_restricted_spaces;
pub mod links;
pub mod names;
pub mod reference;
pub mod sealed_names;
pub mod wraps;

pub use names::{KeyName, RotationSet, SelfRef};

frasil_base::error_classes! {
    /// The error classes of keys.md ("Error classes"), with every shared
    /// class.
    pub enum KeyClass {
        /// A state or key name of more than 64 rotations.
        TooManyRotations = "too_many_rotations", Final;
        /// A key reference naming an event that is no rotation.
        NotARotation = "not_a_rotation", Final;
        /// A received secret that misses its rotation's commitment; the slot
        /// is dropped.
        KeyMismatch = "key_mismatch", Report;
        /// An event that must rotate and does not (section 3.3).
        RotationRequired = "rotation_required", Final;
        /// A "from now on" admission without `break` (section 3.3).
        BreakRequired = "break_required", Final;
        /// A `break` where none may appear (section 3.3).
        UnexpectedBreak = "unexpected_break", Final;
        /// A grant rotation by an author that does not propagate, or in a
        /// restricted space (section 3.3).
        GrantKeyNotAllowed = "grant_key_not_allowed", Final;
        /// An event that must be a grant rotation and is not (section 3.3).
        GrantKeyRequired = "grant_key_required", Final;
        /// A roster event that is a grant rotation where none is required
        /// (section 3.3).
        UnexpectedGrantKey = "unexpected_grant_key", Final;
        /// A response to a granted space's change with no notice for it
        /// (section 3.3).
        NoticeRequired = "notice_required", Final;
        /// An event that does not rotate, sealed under a state a valid
        /// rotation in its place follows.
        StaleSeal = "stale_seal", Final;
        /// A notice naming a rotation void in the granted space's log
        /// (section 3.4).
        NoticeVoid = "notice_void", Final;
        /// A notice whose key or break misses the rotation's commitment
        /// (section 3.4).
        NoticeMismatch = "notice_mismatch", Final;
        /// A notice of a principal out of force (section 3.4).
        NoticeStale = "notice_stale", Final;
        /// A notice whose author is not a propagating member of the granted
        /// space (section 3.4).
        NotGranteeMember = "not_grantee_member", Final;
        /// A name to seal that is empty or longer than 1,022 bytes.
        InvalidName = "invalid_name", Final;
        /// A record whose state the reader does not hold.
        MissingState = "missing_state", Held;
    }
}

impl KeyClass {
    /// The shared class this is, if it is one.
    pub fn shared(self) -> Option<frasil_base::ErrorClass> {
        match self {
            Self::Shared(class) => Some(class),
            _ => None,
        }
    }
}

/// The limits and sizes of keys.md, "Labels and limits", and of its formats.
pub mod limits {
    /// Rotations in a state or key name; more is `TooManyRotations`.
    pub const MAX_ROTATIONS: usize = 64;
    /// Rotations in the current state before a collapse is due (section
    /// 3.12): a state of more is due one.
    pub const COLLAPSE_ABOVE: usize = 8;
    /// Deliveries in one space event; more is `Malformed`.
    pub const MAX_DELIVERIES_PER_EVENT: usize = 64;
    /// Bundle wraps and space wraps together in one space event; more is
    /// `Malformed`.
    pub const MAX_WRAPS_PER_EVENT: usize = 768;
    /// Refs in one space event: events.md's limit, whose excess is
    /// `TooLarge` (events.md, "Limits").
    pub const MAX_REFS_PER_EVENT: usize = frasil_events::kind::MAX_REFS;
    /// The longest name to seal, in bytes.
    pub const MAX_NAME_BYTES: usize = 1022;
    /// The longest document ID a sealed name binds, in bytes.
    pub const MAX_DOCUMENT_ID_BYTES: usize = 128;
    /// Breaks per space: client policy, beyond which a client refuses to
    /// admit "from now on".
    pub const MAX_BREAKS_PER_SPACE: usize = 256;
    /// Spaces a change cascades into before a client warns.
    pub const CASCADE_WARNING: usize = 1024;
    /// A self reference: `0x00 || author || u64be(seq)`.
    pub const SELF_REFERENCE_BYTES: usize = 41;
    /// A recipient bundle.
    pub const BUNDLE_BYTES: usize = 97;
    /// A grant key's public half, an X-Wing public key.
    pub const GRANT_PUBLIC_KEY_BYTES: usize = frasil_crypto::sizes::XWING_PUBLIC;
    /// A bundle wrap or a space wrap: crypto.md's wrap of a 97-byte bundle.
    pub const WRAP_BYTES: usize = frasil_crypto::wrap::WRAP_HEADER
        + frasil_crypto::sizes::XWING_ENC
        + BUNDLE_BYTES
        + frasil_crypto::wrap::HPKE_TAG;
    /// A link between two single rotations; under a self reference it is 148.
    pub const LINK_BYTES_BETWEEN_SINGLE_ROTATIONS: usize = 2 + 33 + 33 + 24 + 32 + 16;
}

/// The labels keys.md uses, from crypto.md's registry, in keys.md's order
/// ("Labels and limits").
pub const LABELS: [&[u8]; 18] = {
    use frasil_crypto::labels as l;
    [
        l::MERGE_KEY,
        l::MERGE_UPLOAD,
        l::MERGE_GRANT,
        l::GRANT_KEY,
        l::GRANT_COMMITMENT,
        l::READ_CREDENTIAL,
        l::UPLOAD_KEY,
        l::SPACE_METADATA_KEY,
        l::OBJECT_ID_KEY,
        l::OBJECT_NONCE_KEY,
        l::KEY_LINK,
        l::BUNDLE_WRAP,
        l::SPACE_WRAP,
        l::REMOVAL_WRAP,
        l::SPACE_EVENT,
        l::SPACE_EVENT_COMMITMENT,
        l::ROTATION_RANK,
        l::NAME,
    ]
};

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::{Class, ErrorClass, Sort, snake_case};

    #[test]
    fn classes_follow_the_table() {
        for &class in KeyClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
        }
        assert_eq!(KeyClass::KeyMismatch.sort(), Sort::Report);
        assert_eq!(KeyClass::MissingState.sort(), Sort::Held);
        assert_eq!(KeyClass::StaleSeal.sort(), Sort::Final);
        assert_eq!(
            KeyClass::from(ErrorClass::Malformed).shared(),
            Some(ErrorClass::Malformed)
        );
        assert_eq!(KeyClass::InvalidName.shared(), None);
    }

    #[test]
    fn sizes_add_up() {
        assert_eq!(limits::WRAP_BYTES, 1236);
        assert_eq!(limits::LINK_BYTES_BETWEEN_SINGLE_ROTATIONS, 140);
        // 768 wraps fit a space event's size limit (events.md).
        assert!(
            limits::MAX_WRAPS_PER_EVENT * limits::WRAP_BYTES
                < frasil_events::kind::limits(frasil_events::kind::SPACE).bytes
        );
    }
}
