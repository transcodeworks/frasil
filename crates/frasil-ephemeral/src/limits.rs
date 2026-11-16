//! Labels, limits and timers (ext-ephemeral.md, "Labels and limits").

pub use frasil_crypto::labels::{EPHEMERAL, EPHEMERAL_KEY, EPHEMERAL_SLOT};

/// The version of the inner map and the outer frame.
pub const VERSION: u64 = 1;
/// The most bytes an outer frame holds.
pub const MAX_OUTER_BYTES: usize = 24_576;
/// A padded plaintext is a multiple of this many bytes.
pub const PAD_BLOCK: usize = 256;
/// The most bytes a padded plaintext holds.
pub const MAX_PLAINTEXT_BYTES: usize = 18_432;
/// The most bytes `data` holds.
pub const MAX_DATA_BYTES: usize = 16_384;
/// The most bytes of UTF-8 a `name` holds.
pub const MAX_NAME_BYTES: usize = 64;
/// The most bytes an `adapter` holds.
pub const MAX_ADAPTER_BYTES: usize = 64;
/// The most targets, and the most fresh entries, a frame carries.
pub const MAX_TARGETS: usize = 16;
/// The bytes of an ephemeral slot handle.
pub const HANDLE_BYTES: usize = 16;
/// The bytes of a `stream`.
pub const STREAM_BYTES: usize = 16;
/// The bytes of a receiver nonce.
pub const RECEIVER_NONCE_BYTES: usize = 16;
/// The bytes of the seal's nonce.
pub const NONCE_BYTES: usize = frasil_crypto::sizes::XCHACHA20POLY1305_NONCE;
/// The bytes of the seal's tag.
pub const TAG_BYTES: usize = frasil_crypto::sizes::XCHACHA20POLY1305_TAG;
/// The bytes of the signature.
pub const SIGNATURE_BYTES: usize = 64;
/// The fewest bytes `sealed` holds: a nonce, one block and a tag.
pub const MIN_SEALED_BYTES: usize = NONCE_BYTES + PAD_BLOCK + TAG_BYTES;
/// The replay window per space and sender, in counters.
pub const REPLAY_WINDOW: u64 = 64;
/// The receiver nonces a device holds per space: its last 4.
pub const RECEIVER_NONCES: usize = 4;
/// The live ephemeral slots a sender keeps per space.
pub const LIVE_SLOTS_PER_SENDER: usize = 32;
/// The ephemeral slots a receiver holds per sender per space, cleared ones
/// included.
pub const RECEIVER_SLOTS_PER_SENDER: usize = 32;
/// The ephemeral slots a receiver holds per space, cleared ones included.
pub const RECEIVER_SLOTS_PER_SPACE: usize = 2_048;
/// The ephemeral slots a relay holds per connection per space.
pub const RELAY_SLOTS_PER_CONNECTION: usize = 64;
/// A sender's queue per connection, in frames.
pub const SEND_QUEUE: usize = 64;
/// A relaying member's relay window per space and sender, in counters.
pub const RELAY_WINDOW: u64 = 64;
/// The bytes of a relay's origin.
pub const ORIGIN_BYTES: usize = 8;
/// The signed list events `frasil/list-events` carries: 1 to 16.
pub const MAX_LIST_EVENTS: usize = 16;
/// The step a restore adds to the stored epoch: 2^32 (section 3.2).
pub const EPOCH_RESTORE_STEP: u64 = 1 << 32;
/// `ephemeral_send_deadline`: seconds a frame may wait in its sender's
/// queue, monotonic.
pub const EPHEMERAL_SEND_DEADLINE: u64 = 2;
/// `ephemeral_key_wait`: seconds a receiver may hold frames for a rotation
/// it lacks, monotonic.
pub const EPHEMERAL_KEY_WAIT: u64 = 5;
/// The frames a receiver may hold meanwhile.
pub const KEY_WAIT_FRAMES: usize = 16;
/// The bytes of a rotation ID in a key reference.
pub const ID_BYTES: usize = 32;
/// The most rotations a state names (keys.md).
pub const MAX_ROTATIONS: usize = frasil_keys::limits::MAX_ROTATIONS;
