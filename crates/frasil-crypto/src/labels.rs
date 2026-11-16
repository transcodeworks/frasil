//! The label registry (crypto.md, "The label registry").
//!
//! Every label protocol 1 uses, as a constant named after the label: the
//! label without `frasil/` and its version, upper case. A label's bytes are
//! its ASCII. [`REGISTRY`] lists them in the document's order, with what each
//! is used as and the document that defines its use; [`PURPOSE_STRINGS`],
//! [`RESERVED`] and [`OTHER_NAMES`] are the registry's other lists. No label,
//! purpose string or reserved string equals another or is a prefix of
//! another ([`clashes`]).

// crypto.md

/// `frasil/hybrid-signature/ed25519/v1`: first bytes of the message the Ed25519
/// half of a scheme-2 signature signs.
pub const HYBRID_SIGNATURE_ED25519: &[u8] = b"frasil/hybrid-signature/ed25519/v1";

/// `frasil/hybrid-signature/mldsa/v1`: first bytes of the message the ML-DSA-65
/// half signs.
pub const HYBRID_SIGNATURE_MLDSA: &[u8] = b"frasil/hybrid-signature/mldsa/v1";

/// `frasil/device-hybrid-seed/v1`: hash prefix of a test fixture's X-Wing seed.
pub const DEVICE_HYBRID_SEED: &[u8] = b"frasil/device-hybrid-seed/v1";

/// `frasil/device-mldsa-seed/v1`: hash prefix of a test fixture's ML-DSA-65
/// seed.
pub const DEVICE_MLDSA_SEED: &[u8] = b"frasil/device-mldsa-seed/v1";

/// `frasil/device-keys-commitment/v1`: hash prefix of a keys commitment,
/// `kc` (crypto.md, "A device's keys").
pub const DEVICE_KEYS_COMMITMENT: &[u8] = b"frasil/device-keys-commitment/v1";

/// `frasil/device-id/v1`: hash prefix of a device ID (crypto.md, "A device's
/// keys").
pub const DEVICE_ID: &[u8] = b"frasil/device-id/v1";

// events.md

/// `frasil/event/v1`: first bytes of what an event signs.
pub const EVENT: &[u8] = b"frasil/event/v1";

/// `frasil/event-id/v1`: hash prefix of an event ID.
pub const EVENT_ID: &[u8] = b"frasil/event-id/v1";

// identity.md

/// `frasil/device-list/possession/v3`: first bytes of the possession statement.
pub const DEVICE_LIST_POSSESSION: &[u8] = b"frasil/device-list/possession/v3";

/// `frasil/device-list/seniority/v1`: hash prefix that orders list members for
/// the seniority pick.
pub const DEVICE_LIST_SENIORITY: &[u8] = b"frasil/device-list/seniority/v1";

/// `frasil/account-link/v1`: first bytes of an account link statement.
pub const ACCOUNT_LINK: &[u8] = b"frasil/account-link/v1";

/// `frasil/account-unlink/v1`: first bytes of an account unlink statement.
pub const ACCOUNT_UNLINK: &[u8] = b"frasil/account-unlink/v1";

/// `frasil/key-fingerprint/v1`: first bytes of a fingerprint's digest input.
pub const KEY_FINGERPRINT: &[u8] = b"frasil/key-fingerprint/v1";

/// `frasil/recovery/v1`: HKDF salt of every recovery-key derivation.
pub const RECOVERY: &[u8] = b"frasil/recovery/v1";

/// `frasil/recovery-key/hybrid/v1`: HKDF info of a recovery key's X-Wing seed.
pub const RECOVERY_KEY_HYBRID: &[u8] = b"frasil/recovery-key/hybrid/v1";

/// `frasil/recovery-key/mldsa/v1`: HKDF info of a recovery key's ML-DSA-65
/// seed.
pub const RECOVERY_KEY_MLDSA: &[u8] = b"frasil/recovery-key/mldsa/v1";

/// `frasil/recovery-key/fetch/v1`: HKDF info of a recovery key's fetch seed.
pub const RECOVERY_KEY_FETCH: &[u8] = b"frasil/recovery-key/fetch/v1";

/// `frasil/passkey-prf-input/v2`: the bytes SHA-256 hashes into the passkey PRF
/// input.
pub const PASSKEY_PRF_INPUT: &[u8] = b"frasil/passkey-prf-input/v2";

/// `frasil/passkey-extract/v1`: HKDF salt of the passkey extract.
pub const PASSKEY_EXTRACT: &[u8] = b"frasil/passkey-extract/v1";

/// `frasil/passkey-member/v1`: first bytes of the HKDF info of a passkey
/// member's Ed25519 seed.
pub const PASSKEY_MEMBER: &[u8] = b"frasil/passkey-member/v1";

/// `frasil/passkey-unlock/v1`: first bytes of the HKDF info of a passkey's
/// unlock key.
pub const PASSKEY_UNLOCK: &[u8] = b"frasil/passkey-unlock/v1";

/// `frasil/passkey/hybrid/v1`: first bytes of the HKDF info of a passkey
/// member's X-Wing seed.
pub const PASSKEY_HYBRID: &[u8] = b"frasil/passkey/hybrid/v1";

/// `frasil/passkey/mldsa/v1`: first bytes of the HKDF info of a passkey
/// member's ML-DSA-65 seed.
pub const PASSKEY_MLDSA: &[u8] = b"frasil/passkey/mldsa/v1";

/// `frasil/passkey/fetch/v1`: first bytes of the HKDF info of a passkey
/// member's fetch seed.
pub const PASSKEY_FETCH: &[u8] = b"frasil/passkey/fetch/v1";

// roster.md

/// `frasil/roster/seniority/v1`: hash prefix that orders grants by seniority.
pub const ROSTER_SENIORITY: &[u8] = b"frasil/roster/seniority/v1";

/// `frasil/checkpoint-record/v1`: hash prefix of a checkpoint record's
/// digest.
pub const CHECKPOINT_RECORD: &[u8] = b"frasil/checkpoint-record/v1";

// keys.md

/// `frasil/merge-key/v1`: info prefix of a merged content key.
pub const MERGE_KEY: &[u8] = b"frasil/merge-key/v1";

/// `frasil/merge-upload/v1`: info prefix of a merged upload seed.
pub const MERGE_UPLOAD: &[u8] = b"frasil/merge-upload/v1";

/// `frasil/merge-grant/v1`: info prefix of a merged grant seed.
pub const MERGE_GRANT: &[u8] = b"frasil/merge-grant/v1";

/// `frasil/grant-key/v1`: HKDF info of a grant key's X-Wing seed.
pub const GRANT_KEY: &[u8] = b"frasil/grant-key/v1";

/// `frasil/grant-commitment/v1`: hash prefix of a grant rotation's commitment.
pub const GRANT_COMMITMENT: &[u8] = b"frasil/grant-commitment/v1";

/// `frasil/read-credential/v1`: HKDF info of a read credential's seed.
pub const READ_CREDENTIAL: &[u8] = b"frasil/read-credential/v1";

/// `frasil/upload-key/v1`: HKDF info of an upload key's seed.
pub const UPLOAD_KEY: &[u8] = b"frasil/upload-key/v1";

/// `frasil/space-metadata-key/v1`: HKDF info of a state's metadata key.
pub const SPACE_METADATA_KEY: &[u8] = b"frasil/space-metadata-key/v1";

/// `frasil/object-id-key/v1`: HKDF info of a state's object ID key.
pub const OBJECT_ID_KEY: &[u8] = b"frasil/object-id-key/v1";

/// `frasil/object-nonce-key/v1`: HKDF info of a state's object nonce key.
pub const OBJECT_NONCE_KEY: &[u8] = b"frasil/object-nonce-key/v1";

/// `frasil/key-link/v1`: info prefix of a link key, and associated-data prefix
/// of a link.
pub const KEY_LINK: &[u8] = b"frasil/key-link/v1";

/// `frasil/bundle-wrap/v1`: HPKE info prefix of a bundle wrap.
pub const BUNDLE_WRAP: &[u8] = b"frasil/bundle-wrap/v1";

/// `frasil/space-wrap/v1`: HPKE info prefix of a space wrap.
pub const SPACE_WRAP: &[u8] = b"frasil/space-wrap/v1";

/// `frasil/removal-wrap/v1`: HPKE info prefix of a removal wrap.
pub const REMOVAL_WRAP: &[u8] = b"frasil/removal-wrap/v1";

/// `frasil/space-event/v1`: info prefix of a body key, and associated-data
/// prefix of a space event's sealed part.
pub const SPACE_EVENT: &[u8] = b"frasil/space-event/v1";

/// `frasil/space-event-commitment/v1`: HKDF info of a body key's commitment.
pub const SPACE_EVENT_COMMITMENT: &[u8] = b"frasil/space-event-commitment/v1";

/// `frasil/rotation-rank/v1`: hash prefix of a device's rank for a trigger.
pub const ROTATION_RANK: &[u8] = b"frasil/rotation-rank/v1";

/// `frasil/name/v1`: associated-data prefix of a sealed name.
pub const NAME: &[u8] = b"frasil/name/v1";

// units.md

/// `frasil/unit/v1`: info prefix of a unit's body key, and associated-data
/// prefix of its seal.
pub const UNIT: &[u8] = b"frasil/unit/v1";

/// `frasil/unit-key/v1`: HKDF info of a state's unit key.
pub const UNIT_KEY: &[u8] = b"frasil/unit-key/v1";

/// `frasil/unit-commitment/v1`: HKDF info of a unit's body key commitment.
pub const UNIT_COMMITMENT: &[u8] = b"frasil/unit-commitment/v1";

/// `frasil/object-seal-key/v1`: HKDF info of a state's object seal key.
pub const OBJECT_SEAL_KEY: &[u8] = b"frasil/object-seal-key/v1";

/// `frasil/object-chunk/v1`: associated-data prefix of an object's chunk.
pub const OBJECT_CHUNK: &[u8] = b"frasil/object-chunk/v1";

/// `frasil/stream-id/v1`: hash prefix of a stream ID.
pub const STREAM_ID: &[u8] = b"frasil/stream-id/v1";

/// `frasil/head-statement/v1`: first bytes of what a head statement signs.
pub const HEAD_STATEMENT: &[u8] = b"frasil/head-statement/v1";

/// `frasil/space-snapshot/v1`: first bytes of what a space snapshot signs.
pub const SPACE_SNAPSHOT: &[u8] = b"frasil/space-snapshot/v1";

// transport.md

/// `frasil/member-key/v1`: HKDF info of a state's member key.
pub const MEMBER_KEY: &[u8] = b"frasil/member-key/v1";

/// `frasil/member-offer/v1`: prefix of an offer tag's HMAC input.
pub const MEMBER_OFFER: &[u8] = b"frasil/member-offer/v1";

/// `frasil/member-transcript/v1`: prefix of an attach's transcript hash.
pub const MEMBER_TRANSCRIPT: &[u8] = b"frasil/member-transcript/v1";

/// `frasil/member-answer/v1`: prefix of an answer's proof.
pub const MEMBER_ANSWER: &[u8] = b"frasil/member-answer/v1";

/// `frasil/member-identify/v1`: prefix of what a device signs to bind itself to
/// a connection.
pub const MEMBER_IDENTIFY: &[u8] = b"frasil/member-identify/v1";

/// `frasil/peer-binding/v1`: prefix of the device-to-peer binding hash.
pub const PEER_BINDING: &[u8] = b"frasil/peer-binding/v1";

/// `frasil/server-channel/v1`: prefix of the server binding's channel value.
pub const SERVER_CHANNEL: &[u8] = b"frasil/server-channel/v1";

/// `frasil/lan-key/v1`: HKDF info of a state's local-network announcement key.
pub const LAN_KEY: &[u8] = b"frasil/lan-key/v1";

/// `frasil/lan-announce/v1`: associated data of a member announcement.
pub const LAN_ANNOUNCE: &[u8] = b"frasil/lan-announce/v1";

/// `frasil/mailbox/v1`: prefix of a mailbox address hash.
pub const MAILBOX: &[u8] = b"frasil/mailbox/v1";

/// `frasil/mailbox-collect/v1`: prefix of what a device signs to collect its
/// own mailbox.
pub const MAILBOX_COLLECT: &[u8] = b"frasil/mailbox-collect/v1";

/// `frasil/mailbox-item/v1`: HPKE info prefix of a sealed device mailbox item.
pub const MAILBOX_ITEM: &[u8] = b"frasil/mailbox-item/v1";

/// `frasil/p1/member`: ALPN of a member connection.
pub const P1_MEMBER: &[u8] = b"frasil/p1/member";

/// `frasil/p1/peer`: ALPN of a device-to-peer connection.
pub const P1_PEER: &[u8] = b"frasil/p1/peer";

/// `frasil/p1/nearby`: ALPN of a nearby pairing connection.
pub const P1_NEARBY: &[u8] = b"frasil/p1/nearby";

// peers.md

/// `frasil/storage-proof/v1`: first bytes of a credential proof's statement.
pub const STORAGE_PROOF: &[u8] = b"frasil/storage-proof/v1";

/// `frasil/storage-merge/v1`: first bytes of a merge statement's message.
pub const STORAGE_MERGE: &[u8] = b"frasil/storage-merge/v1";

/// `frasil/skeleton-twin/v1`: HKDF info of a twin secret.
pub const SKELETON_TWIN: &[u8] = b"frasil/skeleton-twin/v1";

/// `frasil/skeleton-twin-commitment/v1`: hash prefix of a twin commitment.
pub const SKELETON_TWIN_COMMITMENT: &[u8] = b"frasil/skeleton-twin-commitment/v1";

/// `frasil/skeleton-binding/v1`: HKDF info of a binding key, and associated-
/// data prefix of a binding.
pub const SKELETON_BINDING: &[u8] = b"frasil/skeleton-binding/v1";

/// `frasil/skeleton-device/v1`: first bytes of the statement a device signs
/// over its pseudonym.
pub const SKELETON_DEVICE: &[u8] = b"frasil/skeleton-device/v1";

/// `frasil/skeleton-token/v1`: HPKE info prefix of a slot token's seal.
pub const SKELETON_TOKEN: &[u8] = b"frasil/skeleton-token/v1";

/// `frasil/skeleton-slot/ed25519/v1`: HKDF info of an administrator slot's
/// Ed25519 seed.
pub const SKELETON_SLOT_ED25519: &[u8] = b"frasil/skeleton-slot/ed25519/v1";

/// `frasil/skeleton-slot/mldsa/v1`: HKDF info of an administrator slot's ML-
/// DSA-65 seed.
pub const SKELETON_SLOT_MLDSA: &[u8] = b"frasil/skeleton-slot/mldsa/v1";

/// `frasil/skeleton-enrol/v1`: first bytes of the statement a slot's keys sign
/// to enrol a pseudonym.
pub const SKELETON_ENROL: &[u8] = b"frasil/skeleton-enrol/v1";

/// `frasil/skeleton-root/v1`: first bytes of the statement the founder's device
/// signs over its pseudonym.
pub const SKELETON_ROOT: &[u8] = b"frasil/skeleton-root/v1";

/// `frasil/skeleton/seniority/v1`: hash prefix of an administrator slot's
/// seniority.
pub const SKELETON_SENIORITY: &[u8] = b"frasil/skeleton/seniority/v1";

// admission.md

/// `frasil/admission/commit/v1`: prefix of the joiner's commitment.
pub const ADMISSION_COMMIT: &[u8] = b"frasil/admission/commit/v1";

/// `frasil/admission/code/v1`: prefix of the code hash.
pub const ADMISSION_CODE: &[u8] = b"frasil/admission/code/v1";

/// `frasil/admission/heads/v1`: prefix of a heads hash.
pub const ADMISSION_HEADS: &[u8] = b"frasil/admission/heads/v1";

/// `frasil/admission/seal/v1`: HPKE info prefix of an exchange message.
pub const ADMISSION_SEAL: &[u8] = b"frasil/admission/seal/v1";

/// `frasil/admission/setup/v1`: prefix of the setup MAC's input.
pub const ADMISSION_SETUP: &[u8] = b"frasil/admission/setup/v1";

/// `frasil/admission/setup-tag/v1`: prefix of the setup tag.
pub const ADMISSION_SETUP_TAG: &[u8] = b"frasil/admission/setup-tag/v1";

/// `frasil/admission/prompt/v1`: prefix of what a lookup prompt's signature
/// signs.
pub const ADMISSION_PROMPT: &[u8] = b"frasil/admission/prompt/v1";

/// `frasil/welcome/v1`: HPKE info prefix of a sealed welcome.
pub const WELCOME: &[u8] = b"frasil/welcome/v1";

/// `frasil/access-request/v1`: prefix of what an access request's signature
/// signs.
pub const ACCESS_REQUEST: &[u8] = b"frasil/access-request/v1";

/// `frasil/welcome-request/v1`: prefix of what a welcome request's
/// signature signs.
pub const WELCOME_REQUEST: &[u8] = b"frasil/welcome-request/v1";

// at-rest.md

/// `frasil/sealed-device-keys/v1`: associated-data prefix of sealed device
/// keys, and HKDF info of a kind 2 sealing key.
pub const SEALED_DEVICE_KEYS: &[u8] = b"frasil/sealed-device-keys/v1";

/// `frasil/unlock-key/v1`: HKDF salt of a kind 2 sealing key.
pub const UNLOCK_KEY: &[u8] = b"frasil/unlock-key/v1";

/// `frasil/at-rest/seal-key/v1`: HKDF info of a seal key.
pub const AT_REST_SEAL_KEY: &[u8] = b"frasil/at-rest/seal-key/v1";

/// `frasil/at-rest/tag-key/v1`: HKDF info of a tag key.
pub const AT_REST_TAG_KEY: &[u8] = b"frasil/at-rest/tag-key/v1";

/// `frasil/at-rest/scope/v1`: prefix of a scope tag's HMAC input.
pub const AT_REST_SCOPE: &[u8] = b"frasil/at-rest/scope/v1";

/// `frasil/at-rest/item/v1`: prefix of an item tag's HMAC input.
pub const AT_REST_ITEM: &[u8] = b"frasil/at-rest/item/v1";

/// `frasil/at-rest/record/v1`: associated-data prefix of a record.
pub const AT_REST_RECORD: &[u8] = b"frasil/at-rest/record/v1";

/// `frasil/at-rest/mark/v1`: associated-data prefix of the continuity mark.
pub const AT_REST_MARK: &[u8] = b"frasil/at-rest/mark/v1";

/// `frasil/at-rest/app-key/v1`: HKDF info prefix of an application key.
pub const AT_REST_APP_KEY: &[u8] = b"frasil/at-rest/app-key/v1";

// ext-space-files.md

/// `frasil/space-file/key/v1`: HKDF info of a space file's sealing key.
pub const SPACE_FILE_KEY: &[u8] = b"frasil/space-file/key/v1";

/// `frasil/space-file/way-in/v1`: associated-data prefix of a sealed way
/// in.
pub const SPACE_FILE_WAY_IN: &[u8] = b"frasil/space-file/way-in/v1";

// ext-invite-links.md

/// `frasil/invite/v1`: HKDF salt of every invite-key derivation.
pub const INVITE: &[u8] = b"frasil/invite/v1";

/// `frasil/invite/hybrid/v1`: HKDF info of an invite key's X-Wing seed.
pub const INVITE_HYBRID: &[u8] = b"frasil/invite/hybrid/v1";

/// `frasil/invite/mldsa/v1`: HKDF info of an invite key's ML-DSA-65 seed.
pub const INVITE_MLDSA: &[u8] = b"frasil/invite/mldsa/v1";

/// `frasil/invite/locator/v1`: HKDF info of an invite drop's locator.
pub const INVITE_LOCATOR: &[u8] = b"frasil/invite/locator/v1";

/// `frasil/invite/drop/v1`: HKDF info of an invite drop's key, and its
/// associated-data prefix.
pub const INVITE_DROP: &[u8] = b"frasil/invite/drop/v1";

// ext-guests.md

/// `frasil/leave-request/v1`: prefix of what a leave request's signature signs.
pub const LEAVE_REQUEST: &[u8] = b"frasil/leave-request/v1";

// ext-restricted-spaces.md

/// `frasil/restricted-key/v1`: HKDF info prefix of a restricted space's content
/// key.
pub const RESTRICTED_KEY: &[u8] = b"frasil/restricted-key/v1";

/// `frasil/parent-reference/v1`: HKDF info of the key that seals a restricted
/// unit's parent state, and that seal's associated-data prefix.
pub const PARENT_REFERENCE: &[u8] = b"frasil/parent-reference/v1";

// ext-ephemeral.md

/// `frasil/ephemeral-key/v1`: HKDF info of the ephemeral key.
pub const EPHEMERAL_KEY: &[u8] = b"frasil/ephemeral-key/v1";

/// `frasil/ephemeral/v1`: prefix of what a sender signs, and of the seal's
/// associated data.
pub const EPHEMERAL: &[u8] = b"frasil/ephemeral/v1";

/// `frasil/ephemeral-slot/v1`: prefix of an ephemeral slot handle's HMAC input.
pub const EPHEMERAL_SLOT: &[u8] = b"frasil/ephemeral-slot/v1";

// ext-libraries.md

/// `frasil/library-ticket/v1`: first bytes of what a ticket's issuer signs.
pub const LIBRARY_TICKET: &[u8] = b"frasil/library-ticket/v1";

/// `frasil/object-access/v1`: HKDF info of an object's access seed.
pub const OBJECT_ACCESS: &[u8] = b"frasil/object-access/v1";

/// `frasil/object-hold/v1`: first bytes of what a hold's proof signs.
pub const OBJECT_HOLD: &[u8] = b"frasil/object-hold/v1";

// ext-app-requests.md

/// `frasil/device-signed-request/v1`: first bytes of a device-signed request's
/// statement.
pub const DEVICE_SIGNED_REQUEST: &[u8] = b"frasil/device-signed-request/v1";

// ext-deposit-tokens.md

/// `frasil/deposit-key/v1`: `DeriveKeyPair` info of a peer's deposit key,
/// and hash prefix of its key ID.
pub const DEPOSIT_KEY: &[u8] = b"frasil/deposit-key/v1";

/// `frasil/deposit-token/v1`: first bytes of a deposit token's VOPRF input.
pub const DEPOSIT_TOKEN: &[u8] = b"frasil/deposit-token/v1";

// adapter-loro.md

/// `frasil/loro-peer/v1`: hash prefix of a writer's Loro peer ID.
pub const LORO_PEER: &[u8] = b"frasil/loro-peer/v1";

/// One entry of the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label {
    /// The label's bytes.
    pub bytes: &'static [u8],
    /// What the label is used as.
    pub used_as: &'static str,
    /// The document that defines its use, such as `keys.md`.
    pub document: &'static str,
}

/// Every label, in the registry's order.
pub const REGISTRY: &[Label] = &[
    Label {
        bytes: HYBRID_SIGNATURE_ED25519,
        used_as: "first bytes of the message the Ed25519 half of a scheme-2 signature signs",
        document: "crypto.md",
    },
    Label {
        bytes: HYBRID_SIGNATURE_MLDSA,
        used_as: "first bytes of the message the ML-DSA-65 half signs",
        document: "crypto.md",
    },
    Label {
        bytes: DEVICE_HYBRID_SEED,
        used_as: "hash prefix of a test fixture's X-Wing seed",
        document: "crypto.md",
    },
    Label {
        bytes: DEVICE_MLDSA_SEED,
        used_as: "hash prefix of a test fixture's ML-DSA-65 seed",
        document: "crypto.md",
    },
    Label {
        bytes: DEVICE_KEYS_COMMITMENT,
        used_as: "hash prefix of a keys commitment, `kc`",
        document: "crypto.md",
    },
    Label {
        bytes: DEVICE_ID,
        used_as: "hash prefix of a device ID",
        document: "crypto.md",
    },
    Label {
        bytes: EVENT,
        used_as: "first bytes of what an event signs",
        document: "events.md",
    },
    Label {
        bytes: EVENT_ID,
        used_as: "hash prefix of an event ID",
        document: "events.md",
    },
    Label {
        bytes: DEVICE_LIST_POSSESSION,
        used_as: "first bytes of the possession statement",
        document: "identity.md",
    },
    Label {
        bytes: DEVICE_LIST_SENIORITY,
        used_as: "hash prefix that orders list members for the seniority pick",
        document: "identity.md",
    },
    Label {
        bytes: ACCOUNT_LINK,
        used_as: "first bytes of an account link statement",
        document: "identity.md",
    },
    Label {
        bytes: ACCOUNT_UNLINK,
        used_as: "first bytes of an account unlink statement",
        document: "identity.md",
    },
    Label {
        bytes: KEY_FINGERPRINT,
        used_as: "first bytes of a fingerprint's digest input",
        document: "identity.md",
    },
    Label {
        bytes: RECOVERY,
        used_as: "HKDF salt of every recovery-key derivation",
        document: "identity.md",
    },
    Label {
        bytes: RECOVERY_KEY_HYBRID,
        used_as: "HKDF info of a recovery key's X-Wing seed",
        document: "identity.md",
    },
    Label {
        bytes: RECOVERY_KEY_MLDSA,
        used_as: "HKDF info of a recovery key's ML-DSA-65 seed",
        document: "identity.md",
    },
    Label {
        bytes: RECOVERY_KEY_FETCH,
        used_as: "HKDF info of a recovery key's fetch seed",
        document: "identity.md",
    },
    Label {
        bytes: PASSKEY_PRF_INPUT,
        used_as: "the bytes SHA-256 hashes into the passkey PRF input",
        document: "identity.md",
    },
    Label {
        bytes: PASSKEY_EXTRACT,
        used_as: "HKDF salt of the passkey extract",
        document: "identity.md",
    },
    Label {
        bytes: PASSKEY_MEMBER,
        used_as: "first bytes of the HKDF info of a passkey member's Ed25519 seed",
        document: "identity.md",
    },
    Label {
        bytes: PASSKEY_UNLOCK,
        used_as: "first bytes of the HKDF info of a passkey's unlock key",
        document: "identity.md",
    },
    Label {
        bytes: PASSKEY_HYBRID,
        used_as: "first bytes of the HKDF info of a passkey member's X-Wing seed",
        document: "identity.md",
    },
    Label {
        bytes: PASSKEY_MLDSA,
        used_as: "first bytes of the HKDF info of a passkey member's ML-DSA-65 seed",
        document: "identity.md",
    },
    Label {
        bytes: PASSKEY_FETCH,
        used_as: "first bytes of the HKDF info of a passkey member's fetch seed",
        document: "identity.md",
    },
    Label {
        bytes: ROSTER_SENIORITY,
        used_as: "hash prefix that orders grants by seniority",
        document: "roster.md",
    },
    Label {
        bytes: CHECKPOINT_RECORD,
        used_as: "hash prefix of a checkpoint record's digest",
        document: "roster.md",
    },
    Label {
        bytes: MERGE_KEY,
        used_as: "info prefix of a merged content key",
        document: "keys.md",
    },
    Label {
        bytes: MERGE_UPLOAD,
        used_as: "info prefix of a merged upload seed",
        document: "keys.md",
    },
    Label {
        bytes: MERGE_GRANT,
        used_as: "info prefix of a merged grant seed",
        document: "keys.md",
    },
    Label {
        bytes: GRANT_KEY,
        used_as: "HKDF info of a grant key's X-Wing seed",
        document: "keys.md",
    },
    Label {
        bytes: GRANT_COMMITMENT,
        used_as: "hash prefix of a grant rotation's commitment",
        document: "keys.md",
    },
    Label {
        bytes: READ_CREDENTIAL,
        used_as: "HKDF info of a read credential's seed",
        document: "keys.md",
    },
    Label {
        bytes: UPLOAD_KEY,
        used_as: "HKDF info of an upload key's seed",
        document: "keys.md",
    },
    Label {
        bytes: SPACE_METADATA_KEY,
        used_as: "HKDF info of a state's metadata key",
        document: "keys.md",
    },
    Label {
        bytes: OBJECT_ID_KEY,
        used_as: "HKDF info of a state's object ID key",
        document: "keys.md",
    },
    Label {
        bytes: OBJECT_NONCE_KEY,
        used_as: "HKDF info of a state's object nonce key",
        document: "keys.md",
    },
    Label {
        bytes: KEY_LINK,
        used_as: "info prefix of a link key, and associated-data prefix of a link",
        document: "keys.md",
    },
    Label {
        bytes: BUNDLE_WRAP,
        used_as: "HPKE info prefix of a bundle wrap",
        document: "keys.md",
    },
    Label {
        bytes: SPACE_WRAP,
        used_as: "HPKE info prefix of a space wrap",
        document: "keys.md",
    },
    Label {
        bytes: REMOVAL_WRAP,
        used_as: "HPKE info prefix of a removal wrap",
        document: "keys.md",
    },
    Label {
        bytes: SPACE_EVENT,
        used_as: "info prefix of a body key, and associated-data prefix of a space event's sealed part",
        document: "keys.md",
    },
    Label {
        bytes: SPACE_EVENT_COMMITMENT,
        used_as: "HKDF info of a body key's commitment",
        document: "keys.md",
    },
    Label {
        bytes: ROTATION_RANK,
        used_as: "hash prefix of a device's rank for a trigger",
        document: "keys.md",
    },
    Label {
        bytes: NAME,
        used_as: "associated-data prefix of a sealed name",
        document: "keys.md",
    },
    Label {
        bytes: UNIT,
        used_as: "info prefix of a unit's body key, and associated-data prefix of its seal",
        document: "units.md",
    },
    Label {
        bytes: UNIT_KEY,
        used_as: "HKDF info of a state's unit key",
        document: "units.md",
    },
    Label {
        bytes: UNIT_COMMITMENT,
        used_as: "HKDF info of a unit's body key commitment",
        document: "units.md",
    },
    Label {
        bytes: OBJECT_SEAL_KEY,
        used_as: "HKDF info of a state's object seal key",
        document: "units.md",
    },
    Label {
        bytes: OBJECT_CHUNK,
        used_as: "associated-data prefix of an object's chunk",
        document: "units.md",
    },
    Label {
        bytes: STREAM_ID,
        used_as: "hash prefix of a stream ID",
        document: "units.md",
    },
    Label {
        bytes: HEAD_STATEMENT,
        used_as: "first bytes of what a head statement signs",
        document: "units.md",
    },
    Label {
        bytes: SPACE_SNAPSHOT,
        used_as: "first bytes of what a space snapshot signs",
        document: "units.md",
    },
    Label {
        bytes: MEMBER_KEY,
        used_as: "HKDF info of a state's member key",
        document: "transport.md",
    },
    Label {
        bytes: MEMBER_OFFER,
        used_as: "prefix of an offer tag's HMAC input",
        document: "transport.md",
    },
    Label {
        bytes: MEMBER_TRANSCRIPT,
        used_as: "prefix of an attach's transcript hash",
        document: "transport.md",
    },
    Label {
        bytes: MEMBER_ANSWER,
        used_as: "prefix of an answer's proof",
        document: "transport.md",
    },
    Label {
        bytes: MEMBER_IDENTIFY,
        used_as: "prefix of what a device signs to bind itself to a connection",
        document: "transport.md",
    },
    Label {
        bytes: PEER_BINDING,
        used_as: "prefix of the device-to-peer binding hash",
        document: "transport.md",
    },
    Label {
        bytes: SERVER_CHANNEL,
        used_as: "prefix of the server binding's channel value",
        document: "transport.md",
    },
    Label {
        bytes: LAN_KEY,
        used_as: "HKDF info of a state's local-network announcement key",
        document: "transport.md",
    },
    Label {
        bytes: LAN_ANNOUNCE,
        used_as: "associated data of a member announcement",
        document: "transport.md",
    },
    Label {
        bytes: MAILBOX,
        used_as: "prefix of a mailbox address hash",
        document: "transport.md",
    },
    Label {
        bytes: MAILBOX_COLLECT,
        used_as: "prefix of what a device signs to collect its own mailbox",
        document: "transport.md",
    },
    Label {
        bytes: MAILBOX_ITEM,
        used_as: "HPKE info prefix of a sealed device mailbox item",
        document: "transport.md",
    },
    Label {
        bytes: P1_MEMBER,
        used_as: "ALPN of a member connection",
        document: "transport.md",
    },
    Label {
        bytes: P1_PEER,
        used_as: "ALPN of a device-to-peer connection",
        document: "transport.md",
    },
    Label {
        bytes: P1_NEARBY,
        used_as: "ALPN of a nearby pairing connection",
        document: "transport.md",
    },
    Label {
        bytes: STORAGE_PROOF,
        used_as: "first bytes of a credential proof's statement",
        document: "peers.md",
    },
    Label {
        bytes: STORAGE_MERGE,
        used_as: "first bytes of a merge statement's message",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_TWIN,
        used_as: "HKDF info of a twin secret",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_TWIN_COMMITMENT,
        used_as: "hash prefix of a twin commitment",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_BINDING,
        used_as: "HKDF info of a binding key, and associated-data prefix of a binding",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_DEVICE,
        used_as: "first bytes of the statement a device signs over its pseudonym",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_TOKEN,
        used_as: "HPKE info prefix of a slot token's seal",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_SLOT_ED25519,
        used_as: "HKDF info of an administrator slot's Ed25519 seed",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_SLOT_MLDSA,
        used_as: "HKDF info of an administrator slot's ML-DSA-65 seed",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_ENROL,
        used_as: "first bytes of the statement a slot's keys sign to enrol a pseudonym",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_ROOT,
        used_as: "first bytes of the statement the founder's device signs over its pseudonym",
        document: "peers.md",
    },
    Label {
        bytes: SKELETON_SENIORITY,
        used_as: "hash prefix of an administrator slot's seniority",
        document: "peers.md",
    },
    Label {
        bytes: ADMISSION_COMMIT,
        used_as: "prefix of the joiner's commitment",
        document: "admission.md",
    },
    Label {
        bytes: ADMISSION_CODE,
        used_as: "prefix of the code hash",
        document: "admission.md",
    },
    Label {
        bytes: ADMISSION_HEADS,
        used_as: "prefix of a heads hash",
        document: "admission.md",
    },
    Label {
        bytes: ADMISSION_SEAL,
        used_as: "HPKE info prefix of an exchange message",
        document: "admission.md",
    },
    Label {
        bytes: ADMISSION_SETUP,
        used_as: "prefix of the setup MAC's input",
        document: "admission.md",
    },
    Label {
        bytes: ADMISSION_SETUP_TAG,
        used_as: "prefix of the setup tag",
        document: "admission.md",
    },
    Label {
        bytes: ADMISSION_PROMPT,
        used_as: "prefix of what a lookup prompt's signature signs",
        document: "admission.md",
    },
    Label {
        bytes: WELCOME,
        used_as: "HPKE info prefix of a sealed welcome",
        document: "admission.md",
    },
    Label {
        bytes: ACCESS_REQUEST,
        used_as: "prefix of what an access request's signature signs",
        document: "admission.md",
    },
    Label {
        bytes: WELCOME_REQUEST,
        used_as: "prefix of what a welcome request's signature signs",
        document: "admission.md",
    },
    Label {
        bytes: SEALED_DEVICE_KEYS,
        used_as: "associated-data prefix of sealed device keys, and HKDF info of a kind 2 sealing key",
        document: "at-rest.md",
    },
    Label {
        bytes: UNLOCK_KEY,
        used_as: "HKDF salt of a kind 2 sealing key",
        document: "at-rest.md",
    },
    Label {
        bytes: AT_REST_SEAL_KEY,
        used_as: "HKDF info of a seal key",
        document: "at-rest.md",
    },
    Label {
        bytes: AT_REST_TAG_KEY,
        used_as: "HKDF info of a tag key",
        document: "at-rest.md",
    },
    Label {
        bytes: AT_REST_SCOPE,
        used_as: "prefix of a scope tag's HMAC input",
        document: "at-rest.md",
    },
    Label {
        bytes: AT_REST_ITEM,
        used_as: "prefix of an item tag's HMAC input",
        document: "at-rest.md",
    },
    Label {
        bytes: AT_REST_RECORD,
        used_as: "associated-data prefix of a record",
        document: "at-rest.md",
    },
    Label {
        bytes: AT_REST_MARK,
        used_as: "associated-data prefix of the continuity mark",
        document: "at-rest.md",
    },
    Label {
        bytes: AT_REST_APP_KEY,
        used_as: "HKDF info prefix of an application key",
        document: "at-rest.md",
    },
    Label {
        bytes: SPACE_FILE_KEY,
        used_as: "HKDF info of a space file's sealing key",
        document: "ext-space-files.md",
    },
    Label {
        bytes: SPACE_FILE_WAY_IN,
        used_as: "associated-data prefix of a sealed way in",
        document: "ext-space-files.md",
    },
    Label {
        bytes: INVITE,
        used_as: "HKDF salt of every invite-key derivation",
        document: "ext-invite-links.md",
    },
    Label {
        bytes: INVITE_HYBRID,
        used_as: "HKDF info of an invite key's X-Wing seed",
        document: "ext-invite-links.md",
    },
    Label {
        bytes: INVITE_MLDSA,
        used_as: "HKDF info of an invite key's ML-DSA-65 seed",
        document: "ext-invite-links.md",
    },
    Label {
        bytes: INVITE_LOCATOR,
        used_as: "HKDF info of an invite drop's locator",
        document: "ext-invite-links.md",
    },
    Label {
        bytes: INVITE_DROP,
        used_as: "HKDF info of an invite drop's key, and its associated-data prefix",
        document: "ext-invite-links.md",
    },
    Label {
        bytes: LEAVE_REQUEST,
        used_as: "prefix of what a leave request's signature signs",
        document: "ext-guests.md",
    },
    Label {
        bytes: RESTRICTED_KEY,
        used_as: "HKDF info prefix of a restricted space's content key",
        document: "ext-restricted-spaces.md",
    },
    Label {
        bytes: PARENT_REFERENCE,
        used_as: "HKDF info of the key that seals a restricted unit's parent state, and that seal's associated-data prefix",
        document: "ext-restricted-spaces.md",
    },
    Label {
        bytes: EPHEMERAL_KEY,
        used_as: "HKDF info of the ephemeral key",
        document: "ext-ephemeral.md",
    },
    Label {
        bytes: EPHEMERAL,
        used_as: "prefix of what a sender signs, and of the seal's associated data",
        document: "ext-ephemeral.md",
    },
    Label {
        bytes: EPHEMERAL_SLOT,
        used_as: "prefix of an ephemeral slot handle's HMAC input",
        document: "ext-ephemeral.md",
    },
    Label {
        bytes: LIBRARY_TICKET,
        used_as: "first bytes of what a ticket's issuer signs",
        document: "ext-libraries.md",
    },
    Label {
        bytes: OBJECT_ACCESS,
        used_as: "HKDF info of an object's access seed",
        document: "ext-libraries.md",
    },
    Label {
        bytes: OBJECT_HOLD,
        used_as: "first bytes of what a hold's proof signs",
        document: "ext-libraries.md",
    },
    Label {
        bytes: DEVICE_SIGNED_REQUEST,
        used_as: "first bytes of a device-signed request's statement",
        document: "ext-app-requests.md",
    },
    Label {
        bytes: DEPOSIT_KEY,
        used_as: "`DeriveKeyPair` info of a peer's deposit key, and hash prefix of its key ID",
        document: "ext-deposit-tokens.md",
    },
    Label {
        bytes: DEPOSIT_TOKEN,
        used_as: "first bytes of a deposit token's VOPRF input",
        document: "ext-deposit-tokens.md",
    },
    Label {
        bytes: LORO_PEER,
        used_as: "hash prefix of a writer's Loro peer ID",
        document: "adapter-loro.md",
    },
];

/// A purpose string: a fixed string fed to a primitive inside a labelled
/// input, never used as a label on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurposeString {
    /// The string's bytes.
    pub bytes: &'static [u8],
    /// Where it is used.
    pub used_as: &'static str,
}

/// The purpose strings, in the registry's order.
pub const PURPOSE_STRINGS: &[PurposeString] = &[
    PurposeString {
        bytes: b"ed25519",
        used_as: "the whole HKDF info of a recovery key's Ed25519 seed under frasil/recovery/v1, and of an invite key's under frasil/invite/v1; a length-prefixed field inside the passkey infos",
    },
    PurposeString {
        bytes: b"device-keys",
        used_as: "a length-prefixed field inside the passkey unlock key's info",
    },
    PurposeString {
        bytes: b"x25519",
        used_as: "reserved as a purpose string",
    },
];

/// Strings that MUST NOT be used as labels: no new label may equal or be a
/// prefix of one.
pub const RESERVED: &[&[u8]] = &[
    b"frasil/admission/keys/v1",
    b"frasil/aead/v1",
    b"frasil/blob-id/v1",
    b"frasil/blob-nonce/v1",
    b"frasil/blob-part/v1\0",
    b"frasil/blob/v1/chunk",
    b"frasil/blob/v1/manifest",
    b"frasil/comparison-code/commit/v1",
    b"frasil/comparison-code/v1",
    b"frasil/device-keys/v1",
    b"frasil/device-list/entry/v1",
    b"frasil/device-list/label/v1",
    b"frasil/device-list/possession/v1",
    b"frasil/device-list/possession/v2",
    b"frasil/device-list/v1",
    b"frasil/device-proof/v1",
    b"frasil/invite-pending/v1",
    b"frasil/invite-wrap-signature/v1",
    b"frasil/invite-wrap/v1",
    b"frasil/key-chain-signature/v1",
    b"frasil/key-chain/v1",
    b"frasil/key-registration/v1",
    b"frasil/lan/v1",
    b"frasil/member/1",
    b"frasil/member/v1",
    b"frasil/metadata-key/v1",
    b"frasil/nearby/1",
    b"frasil/passkey-prf-input/v1",
    b"frasil/peer/1",
    b"frasil/presence/v1",
    b"frasil/proposal/v2",
    b"frasil/scope-blob-id/v1",
    b"frasil/scope-blob-nonce/v1",
    b"frasil/scope-key/v1",
    b"frasil/scope-metadata-key/v1",
    b"frasil/scope-wrap/v1",
    b"frasil/scoped-aead/v1",
    b"frasil/sealed-invite/v1",
    b"frasil/sealed-pending-update/v1",
    b"frasil/snapshot/v1",
    b"frasil/update/v1",
    b"frasil/vault-roster/entry/v1",
    b"frasil/vault-roster/label/v1",
    b"frasil/vault-roster/v1",
    b"frasil/wrap-signature/v1",
    b"frasil/wrap/v1",
];

/// Other names Frasil keeps, which feed no primitive.
pub const OTHER_NAMES: &[&str] = &[
    "capability names that begin frasil.",
    "ephemeral names and mailbox content names that begin frasil/",
    "frasil.p1",
    "FRASIL-FP1:",
    "FRASIL-ADMIT:",
    "FRASIL-SETUP:",
    "setup-<tag>",
];

/// Every label, purpose string and reserved string, in that order.
pub fn every_string() -> impl Iterator<Item = &'static [u8]> {
    REGISTRY
        .iter()
        .map(|label| label.bytes)
        .chain(PURPOSE_STRINGS.iter().map(|purpose| purpose.bytes))
        .chain(RESERVED.iter().copied())
}

/// The pairs of strings of [`every_string`] of which one equals or is a
/// prefix of the other. The registry requires there be none.
pub fn clashes() -> Vec<(&'static [u8], &'static [u8])> {
    let every: Vec<&'static [u8]> = every_string().collect();
    let mut out = Vec::new();
    for (index, first) in every.iter().enumerate() {
        for second in &every[index + 1..] {
            if first.starts_with(second) || second.starts_with(first) {
                out.push((*first, *second));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_string_equals_or_prefixes_another() {
        assert_eq!(clashes(), Vec::<(&[u8], &[u8])>::new());
    }
}
