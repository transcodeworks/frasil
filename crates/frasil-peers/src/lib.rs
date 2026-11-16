//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! The rules of Frasil's always-on peers that replicas also run: entries,
//! proofs, the skeleton and twins, and the peer's storage decisions.
//!
//! Specified by `docs/spec/peers.md`. Its vectors are
//! `docs/spec/vectors/peers.json`.
//!
//! The formats:
//! - [`proof`]: the credential proof a device presents (peers.md, "The
//!   credential proof");
//! - [`merge`](mod@merge): the merge statement ("The merge statement");
//! - [`body`]: the storage event's body and its types ("Storage events");
//! - [`derive`](mod@derive): the twin commitment, the root statement, slot
//!   tokens, enrolments, device bindings and seniority ("Skeleton
//!   derivations").
//!
//! The rules, over a log the caller holds (`frasil-events`):
//! - [`skeleton`]: what a peer checks before it stores a skeleton event, the
//!   skeleton's resolution through `frasil-resolve`, requests valid at the
//!   peer, and stability at the peer ("What a peer checks before it stores a
//!   skeleton event", "The skeleton's resolution", "Stability at the peer");
//! - [`twins`]: what replicas check of twins, roots and enrolments, with the
//!   roster's facts behind a trait ("What replicas check");
//! - [`entries`]: the peer's entries and recovery entries, merge statements,
//!   retirement and the cap, presents, registration, credentials requests and
//!   the store right ("Entries" to "Presenting a credential", "Credentials
//!   requests", "Storing an event");
//! - [`decisions`]: erasure, credentials requests, release and restore, and
//!   collection ("Erasure", "Credentials requests", "Release and restore",
//!   "Collection");
//! - [`cut`]: skeleton cuts, the twins of space checkpoints: their checks,
//!   epochs, standing, votes, excuses and effect at the peer, the skeleton
//!   restarted from the cut in effect, requests concurrent with a cut that
//!   can still take effect, released streams across truncation, a replica's
//!   checks of a cut against the checkpoint's record, and what a peer may
//!   delete once it truncates ("Skeleton cuts", "Truncation").
//!
//! - [`retention`]: listings, heads, depth and the retention of a file's old
//!   versions (ext-file-versions.md), with the feature `ext-file-versions`.
//!
//! The crate reads no clock, does no IO and draws no randomness: readings of
//! the peer's timeline, slot tokens, X-Wing encapsulation randomness and
//! binding nonces come in as arguments (the `_with` forms), so the vectors
//! can drive them. The peer service, its storage and its timers are
//! `frasil-relay`'s.

pub mod body;
pub mod cut;
pub mod decisions;
pub mod derive;
pub mod entries;
pub mod erasure;
#[cfg(feature = "ext-invite-links")]
pub mod ext_invite_links;
pub mod merge;
pub mod proof;
#[cfg(feature = "ext-file-versions")]
pub mod retention;
pub mod skeleton;
pub mod twins;

frasil_base::error_classes! {
    /// The error classes of peers.md ("Error classes"), with every shared
    /// class. The skeleton's resolution also uses the shared `NotAMember`,
    /// `NotAnAdministrator`, `Full` and `Forked`.
    pub enum PeersClass {
        /// A store with no right, and no create, import or skeleton
        /// authority.
        NotAuthorized = "not_authorized", Decision;
        /// A present whose public half names no entry or pseudonym of the
        /// space.
        UnknownCredential = "unknown_credential", Decision;
        /// A present's proof does not verify.
        BadProof = "bad_proof", Decision;
        /// An upload key whose entry is retired.
        RetiredCredential = "retired_credential", Decision;
        /// A merge statement over rotations the peer does not hold live, or
        /// that are not a state.
        UnknownState = "unknown_state", Decision;
        /// An upload whose bytes do not hash to its locator's digest.
        ObjectMismatch = "object_mismatch", Decision;
        /// A skeleton event whose slot reference names no administrator slot
        /// (peers.md, "Storage events").
        UnknownAdministratorSlot = "unknown_administrator_slot", Final;
        /// A root after the first in canonical order; stored and ignored.
        DuplicateRoot = "duplicate_root", Final;
        /// A change that repeats a commitment, whose grants would take the
        /// planted administrator slots a peer recognises in its past past
        /// 256.
        PlantedSlotsFull = "planted_slots_full", Final;
        /// At a peer: a change no stored space event names yet.
        Unnamed = "unnamed", Pending;
        /// An enrolment of an administrator slot that already has a valid
        /// enrolment at its place.
        AlreadyEnrolled = "already_enrolled", Final;
        /// An enrolment concurrent with another of its administrator slot.
        ConcurrentEnrolment = "concurrent_enrolment", Final;
        /// Attacked in the skeleton's resolution.
        RemovedConcurrently = "removed_concurrently", Final;
        /// In the skeleton's resolution: a change or disown whose author's
        /// administrator slot has a lower rank than the slot it lowers
        /// (peers.md, "The skeleton's resolution", ranks).
        HigherRank = "higher_rank", Final;
        /// At a replica: a roster event, or the genesis, whose twin or root
        /// is not held.
        NoTwin = "no_twin", Pending;
        /// At a replica: a twin or root that fails peers.md's checks.
        BadTwin = "bad_twin", Final;
        /// A skeleton cut whose slots are not those of the merged skeleton of
        /// its past (peers.md, "Skeleton cuts").
        BadCut = "bad_cut", Final;
        /// A skeleton cut of the wrong epoch, or made before a cut its
        /// checkpoint follows took effect (peers.md, "Skeleton cuts").
        CutPending = "cut_pending", Final;
        /// With a skeleton cut in effect at the peer, a skeleton event other
        /// than a cut that is neither in the cut's past nor follows its
        /// checkpoint (peers.md, "Skeleton cuts", late skeleton events):
        /// stored, with no effect, as roster.md defines the class at
        /// replicas, under the same wire name.
        Late = "late", Final;
        /// At the grantee: a slot token that does not open, or derives other
        /// keys.
        BadToken = "bad_token", Report;
        /// An entry added `retired` at the cap; the event is stored, and the
        /// peer records the class in its own log.
        KeyStateFull = "key_state_full", Report;
        /// A registration past a space's 64 live recovery entries.
        RecoveryEntriesFull = "recovery_entries_full", Decision;
        /// A peer answer contradicts the envelopes or slot standing it carries.
        PeerError = "peer_error", Report;
    }
}

impl PeersClass {
    /// The shared class this is, if it is one.
    pub fn shared(self) -> Option<frasil_base::ErrorClass> {
        match self {
            Self::Shared(class) => Some(class),
            _ => None,
        }
    }

    /// The refusal code a peer answers with for this class, if it answers
    /// one (peers.md, "Refusal codes").
    pub fn code(self) -> Option<Code> {
        use frasil_base::ErrorClass as E;
        match self {
            Self::UnknownCredential | Self::BadProof | Self::RetiredCredential => {
                Some(Code::CredentialRefused)
            }
            Self::NotAuthorized => Some(Code::NotAuthorized),
            Self::RecoveryEntriesFull => Some(Code::RecoveryEntriesFull),
            Self::ObjectMismatch => Some(Code::ObjectMismatch),
            Self::Shared(E::TooLarge) => Some(Code::TooLarge),
            _ => None,
        }
    }

    /// A shared class of another crate's errors, or `Malformed` for a class
    /// of its own.
    pub(crate) fn lift(shared: Option<frasil_base::ErrorClass>) -> Self {
        Self::Shared(shared.unwrap_or(frasil_base::ErrorClass::Malformed))
    }
}

impl From<frasil_events::EventClass> for PeersClass {
    fn from(class: frasil_events::EventClass) -> Self {
        Self::lift(class.shared())
    }
}

impl From<frasil_keys::KeyClass> for PeersClass {
    fn from(class: frasil_keys::KeyClass) -> Self {
        Self::lift(class.shared())
    }
}

/// The limits of peers.md ("Limits") and the sizes of its formats.
pub mod limits {
    /// `max_file_versions`'s default (ext-file-versions.md, 2.2 Settings).
    pub const MAX_FILE_VERSIONS: u64 = 100;
    /// `max_file_versions`'s range.
    pub const MAX_FILE_VERSIONS_RANGE: (u64, u64) = (1, 1024);

    use frasil_crypto::sizes::{
        MLDSA65_PUBLIC, SCHEME2_SIGNATURE, XCHACHA20POLY1305_NONCE, XCHACHA20POLY1305_TAG,
        XWING_ENC,
    };
    use frasil_crypto::wrap::{HPKE_TAG, WRAP_HEADER};

    /// A signed storage event, in bytes (events.md's limit for kind 6).
    pub const MAX_STORAGE_EVENT: usize = 262_144;
    /// Grants in one change.
    pub const MAX_GRANTS: usize = 64;
    /// Entries named in one credentials request.
    pub const MAX_LIVE_NAMED: usize = 64;
    /// Fetch keys in one credentials request's keep list.
    pub const MAX_KEEP: usize = 64;
    /// Live recovery entries per space.
    pub const MAX_RECOVERY_ENTRIES: usize = 64;
    /// The fewest rotations in a merge statement.
    pub const MIN_MERGE_ROTATIONS: usize = 2;
    /// The most rotations in a merge statement.
    pub const MAX_MERGE_ROTATIONS: usize = 64;
    /// The highest rank of an administrator slot: the root's (peers.md,
    /// "Storage events", a grant map's key 4).
    pub const MAX_RANK: u8 = 255;
    /// Slot entries in one skeleton cut: the administrators one cut fixes.
    pub const MAX_CUT_SLOTS: usize = 512;
    /// Standing entries in one skeleton cut, at most: the record's
    /// administrators and the members its checkpoint hears. A cut carries
    /// at least one.
    pub const MAX_STANDING: usize = 1024;
    /// The first reserved key of a cut's body: a cut that carries any key
    /// from it is held, `ExtensionRequired` (peers.md, "Storage events").
    pub const RESERVED_CUT_KEY: u64 = 9;
    /// A record object's locator, as a cut names it (units.md).
    pub const RECORD_LOCATOR_BYTES: usize = 64;
    /// `cut_retention`'s default, in seconds: 30 days (overview.md,
    /// "Parameters").
    pub const CUT_RETENTION: u64 = 30 * 24 * 3600;
    /// The most `cut_retention` an operator may set, in seconds: 365 days.
    pub const MAX_CUT_RETENTION: u64 = 365 * 24 * 3600;
    /// Valid changes, disowns and enrolments in one place of the skeleton.
    pub const MAX_SKELETON_PLACE: usize = 4096;
    /// Planted administrator slots a peer recognises: grants of changes
    /// that repeat a commitment, in a change's past and its own (peers.md,
    /// "What a peer checks before it stores a skeleton event", step 6).
    pub const MAX_PLANTED: usize = 256;
    /// Live entries per space, `credential_cap`, by default.
    pub const CREDENTIAL_CAP: usize = 256;
    /// The least `credential_cap` an operator may set.
    pub const MIN_CREDENTIAL_CAP: usize = 16;
    /// The most `credential_cap` an operator may set.
    pub const MAX_CREDENTIAL_CAP: usize = 4096;
    /// Live merge entries of one state, `merge_per_state`.
    pub const MERGE_PER_STATE: usize = 4;
    /// Pending events per space, `pending_cap`, by default.
    pub const PENDING_CAP: usize = 4096;
    /// A slot token: 32 bytes.
    pub const TOKEN_BYTES: usize = 32;
    /// A sealed slot token: crypto.md's wrap of a 32-byte token, 1,171 bytes.
    pub const SEALED_TOKEN_BYTES: usize = WRAP_HEADER + XWING_ENC + TOKEN_BYTES + HPKE_TAG;
    /// A binding's nonce.
    pub const BINDING_NONCE_BYTES: usize = XCHACHA20POLY1305_NONCE;
    /// A device binding: the nonce, then the device's scheme-2 signature and
    /// device ID sealed, 3,445 bytes.
    pub const BINDING_BYTES: usize =
        BINDING_NONCE_BYTES + SCHEME2_SIGNATURE + 32 + XCHACHA20POLY1305_TAG;
    /// An ML-DSA-65 public key.
    pub const MLDSA_BYTES: usize = MLDSA65_PUBLIC;
    /// A scheme-2 signature.
    pub const SIGNATURE_BYTES: usize = SCHEME2_SIGNATURE;
    /// A stream ID (units.md).
    pub const STREAM_BYTES: usize = 16;
}

/// A refusal code (peers.md, "Refusal codes"), which travels as
/// transport.md says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Code {
    /// The store would pass the space's quota.
    QuotaExceeded,
    /// The peer does not host the space.
    NoLibrary,
    /// The operator has suspended the space's hosting.
    LibraryClosed,
    /// The space's streams would pass `max_streams_per_space`.
    StreamLimit,
    /// A fetch, or a unit, of a released stream.
    Released,
    /// A store into an erased space, or its create or import.
    Erased,
    /// A stored cut uses a reserved body key.
    ExtensionRequired,
    /// A registration past 64 live recovery entries.
    RecoveryEntriesFull,
    /// A present peers.md refuses, or a fetch with no right.
    CredentialRefused,
    /// A store with no right, or a create whose first stored event is not
    /// the genesis.
    NotAuthorized,
    /// A second event at one author and `seq`, kept as evidence.
    Conflict,
    /// An upload whose bytes do not hash to its locator's digest.
    ObjectMismatch,
    /// A rate, or `pending_cap`.
    RateLimited,
    /// An event or object over its limit.
    TooLarge,
    /// The peer handed the space over to another peer; answered only to a
    /// device that proves it held a credential of the space.
    Moved,
}

impl Code {
    /// Every code, in the order of peers.md's table.
    pub const ALL: [Code; 15] = [
        Self::QuotaExceeded,
        Self::NoLibrary,
        Self::Moved,
        Self::LibraryClosed,
        Self::StreamLimit,
        Self::Released,
        Self::Erased,
        Self::ExtensionRequired,
        Self::RecoveryEntriesFull,
        Self::CredentialRefused,
        Self::NotAuthorized,
        Self::Conflict,
        Self::ObjectMismatch,
        Self::RateLimited,
        Self::TooLarge,
    ];

    /// The code's name on the wire.
    pub fn name(self) -> &'static str {
        match self {
            Self::QuotaExceeded => "quota_exceeded",
            Self::NoLibrary => "no_library",
            Self::LibraryClosed => "library_closed",
            Self::StreamLimit => "stream_limit",
            Self::Released => "released",
            Self::Erased => "erased",
            Self::ExtensionRequired => "extension_required",
            Self::RecoveryEntriesFull => "recovery_entries_full",
            Self::CredentialRefused => "credential_refused",
            Self::NotAuthorized => "not_authorized",
            Self::Conflict => "conflict",
            Self::ObjectMismatch => "object_mismatch",
            Self::RateLimited => "rate_limited",
            Self::TooLarge => "too_large",
            Self::Moved => "moved",
        }
    }

    /// The code of this wire name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.name() == name)
    }

    /// The status that goes with it.
    pub fn status(self) -> u16 {
        match self {
            Self::QuotaExceeded
            | Self::NoLibrary
            | Self::LibraryClosed
            | Self::StreamLimit
            | Self::RecoveryEntriesFull => 507,
            Self::Released | Self::Erased => 410,
            Self::CredentialRefused | Self::NotAuthorized => 403,
            Self::Conflict => 409,
            Self::ObjectMismatch | Self::ExtensionRequired => 422,
            Self::RateLimited => 429,
            Self::TooLarge => 413,
            Self::Moved => 421,
        }
    }
}

impl core::fmt::Display for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::{Class, ErrorClass, Sort, snake_case};

    #[test]
    fn classes_follow_the_table() {
        for &class in PeersClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
            assert_eq!(PeersClass::from_name(class.name()), Some(class));
        }
        assert_eq!(PeersClass::Unnamed.sort(), Sort::Pending);
        assert_eq!(PeersClass::NoTwin.sort(), Sort::Pending);
        assert_eq!(PeersClass::BadToken.sort(), Sort::Report);
        assert_eq!(PeersClass::KeyStateFull.sort(), Sort::Report);
        assert_eq!(PeersClass::NotAuthorized.sort(), Sort::Decision);
        assert_eq!(PeersClass::RemovedConcurrently.sort(), Sort::Final);
        assert_eq!(
            PeersClass::from(ErrorClass::Malformed).shared(),
            Some(ErrorClass::Malformed)
        );
        assert_eq!(PeersClass::BadProof.code(), Some(Code::CredentialRefused));
        // `Late` is roster.md's class, under its wire name.
        assert_eq!(PeersClass::Late.wire_name(), "late");
        assert_eq!(PeersClass::from_name("Late"), Some(PeersClass::Late));
        assert_eq!(PeersClass::Late.sort(), Sort::Final);
        assert_eq!(PeersClass::Late.code(), None);
    }

    #[test]
    fn codes_round_trip() {
        for code in Code::ALL {
            assert_eq!(Code::from_name(code.name()), Some(code));
        }
        assert_eq!(limits::SEALED_TOKEN_BYTES, 1171);
        assert_eq!(limits::BINDING_BYTES, 3445);
    }
}
