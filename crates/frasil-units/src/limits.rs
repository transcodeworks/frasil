//! The limits of units.md, section 2.1, "Limits", and the sizes its formats
//! use. Parents and refs keep events.md's limits.

/// A signed unit, in bytes; more is `TooLarge`.
pub const MAX_UNIT_BYTES: usize = 1_048_576;
/// Locators a unit names (visible key 5); more is `Malformed`.
pub const MAX_LOCATORS: usize = 4096;
/// Supersessions in a unit's `supersedes` (units.md, section 2.1).
pub const MAX_SUPERSESSIONS: usize = 4096;
/// Pairs in a snapshot unit's `covers`; more is `Malformed`.
pub const MAX_COVERS: usize = 4096;
/// Stubs in a snapshot unit or a space snapshot's `stubs`; more is
/// `Malformed`.
pub const MAX_STUBS: usize = 8192;
/// IDs in `excluded`; more is `Malformed`.
pub const MAX_EXCLUDED: usize = 4096;
/// The fewest bytes of an adapter type.
pub const MIN_TYPE_BYTES: usize = 1;
/// The most bytes of an adapter type.
pub const MAX_TYPE_BYTES: usize = 64;
/// The lowest octet an adapter type holds.
pub const MIN_TYPE_OCTET: u8 = 0x21;
/// The highest octet an adapter type holds.
pub const MAX_TYPE_OCTET: u8 = 0x7e;
/// Device-list events in one list copy, or in one `ListEvents` message or
/// `frasil/list-events` body: at most this many, at least one.
pub const MAX_LIST_EVENTS: usize = 16;
/// Body keys in one body-keys unit: at most this many, at least one.
pub const MAX_BODY_KEYS: usize = 1024;
/// An object's plaintext, in bytes; more is `TooLarge`.
pub const MAX_OBJECT_BYTES: u64 = 1 << 40;
/// A chunk's plaintext, in bytes, fixed.
pub const CHUNK_BYTES: usize = 1_048_536;
/// A sealed chunk, in bytes: one frame of transport.md.
pub const SEALED_CHUNK_BYTES: usize = 1_048_576;
/// Heads in a head statement, or in a space snapshot's `base`: at most this
/// many, at least one.
pub const MAX_HEADS: usize = 256;
/// A signed head statement, in bytes; more is `TooLarge`.
pub const MAX_STATEMENT_BYTES: usize = 65_536;
/// Stream entries in a head statement: at most this many, at least one.
pub const MAX_STATEMENT_STREAMS: usize = 64;
/// IDs, heads, events, pairs or ranges in one sync message; more is
/// `Malformed`.
pub const MAX_MESSAGE_ITEMS: usize = 4096;
/// A sync message, in bytes; more is `TooLarge`.
pub const MAX_MESSAGE_BYTES: usize = 1_052_672;
/// Head statements in one `Statement` message: at most this many, at least
/// one.
pub const MAX_STATEMENTS_PER_MESSAGE: usize = 64;
/// Chunks one `ObjectWant` asks for: at most this many, at least one.
pub const MAX_CHUNKS_WANTED: u64 = 64;
/// Equivocation proofs in a space snapshot or a log entry: at most this
/// many, at least one.
pub const MAX_PROOFS: usize = 256;
/// Refs a unit carries, as events.md's limits say; more is `TooLarge`.
pub const MAX_REFS: usize = frasil_events::kind::MAX_REFS;

/// `max_streams_per_space`, set by a peer's operator within these bounds,
/// and published in its discovery (transport.md); a peer refuses a stream's
/// first unit past it (`stream_limit`, peers.md).
pub mod max_streams_per_space {
    /// The least an operator may set.
    pub const MIN: u64 = 1;
    /// The most an operator may set.
    pub const MAX: u64 = 1 << 20;
    /// The default.
    pub const DEFAULT: u64 = 65_536;
}

/// A stream ID's length (section 2.6, "Streams").
pub const STREAM_BYTES: usize = 16;
/// A locator's length: object ID, then digest (section 2.8).
pub const LOCATOR_BYTES: usize = frasil_adapter::LOCATOR_BYTES;
/// An XChaCha20-Poly1305 nonce's length.
pub const NONCE_BYTES: usize = 24;
/// An XChaCha20-Poly1305 tag's length.
pub const TAG_BYTES: usize = 16;
/// The shortest seal of a chunk: a nonce and a tag (section 2.8).
pub const MIN_SEAL_BYTES: usize = NONCE_BYTES + TAG_BYTES;
/// A body key's commitment in a unit's seal (section 2.4).
pub const COMMITMENT_BYTES: usize = 32;
/// The shortest seal of a unit: a nonce, a commitment and a tag (section
/// 3.1, step 9).
pub const MIN_UNIT_SEAL_BYTES: usize = NONCE_BYTES + COMMITMENT_BYTES + TAG_BYTES;
/// A salt's length in a stream's opening (section 2.6).
pub const SALT_BYTES: usize = 16;
/// Rotations of a parent state in a restricted key reference
/// (ext-restricted-spaces.md, section 2.3): at most this many, at least
/// one; more is `TooManyRotations`.
pub const MAX_ROTATIONS_PARENT: usize = 64;
