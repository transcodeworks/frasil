//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's identity: device keys, device lists and their merge.
//!
//! Specified by `docs/spec/identity.md`. Its vectors are
//! `docs/spec/vectors/identity.json`.
//!
//! The formats, which need no event log:
//! - [`keys`]: a list member's three key pairs, the kinds of list member and
//!   their ranks (identity.md, "Device keys", "Kinds of list member");
//! - [`body`]: the device-list event's body and the checks of it that need
//!   only the event (identity.md, "The device-list event", "Checking a list
//!   event alone", steps 2 to 5);
//! - [`possession`]: the possession statement and its proof (identity.md,
//!   "The possession statement");
//! - [`recovery`]: recovery keys and the recovery sheet (identity.md,
//!   "Recovery keys");
//! - [`passkey`]: passkey members, their derivations and the user handle
//!   (identity.md, "Passkey members");
//! - [`entries`]: fetch keys and recovery entries (identity.md, "Fetch keys
//!   and recovery entries");
//! - [`fingerprint`]: fingerprints, their parsing and their comparison
//!   (identity.md, "Fingerprints", "Comparing fingerprints");
//! - [`links`]: account links and unlinks (identity.md, "Account links",
//!   "Checking an account link").
//!
//! The list, which reads the event log (`frasil-events`) and resolves it
//! (`frasil-resolve`):
//! - [`list`]: a person's [`DeviceList`], which takes list events by any
//!   path and in any order and checks each alone (identity.md, "Checking a
//!   list event alone", "Sealed list copies");
//! - [`state`]: list members, rootedness and ranks (identity.md, "The state
//!   of a list at a place");
//! - [`merge`]: the checks at each event's place, the merge by rank, and
//!   the [`MergedList`] with what it vouches for (identity.md, "Checks at
//!   the event's place", "The merge", "What a list vouches for", "Adding
//!   list members", "Using a passkey member");
//! - [`pins`]: pins and the reports `RolledBack` and `ForkDetected`
//!   (identity.md, "Pins");
//! - [`record`] and [`checkpoint`]: list checkpoints, their record, their
//!   validity, votes and effect, late events and the world after one
//!   (identity.md, "List checkpoints");
//! - [`kept`]: a [`KeptList`], what a holder of the list keeps when it
//!   forgets the events before a list checkpoint in effect, and the list it
//!   judges from there.
//!
//! With feature `ext-recovery-agent`, `ext_recovery_agent` adds
//! ext-recovery-agent.md: the waiting period after which a verifier vouches
//! for a list member rooted in an agent, naming an agent and its adds, and
//! what a device raises, relays and vetoes.
//!
//! The crate does no IO and draws no randomness: every secret it derives
//! from comes in as an argument. A caller draws device seeds, recovery
//! secrets, fetch seeds and link nonces with `frasil_crypto::random_bytes`.

pub mod body;
pub mod checkpoint;
pub mod entries;
pub mod errors;
#[cfg(feature = "ext-recovery-agent")]
pub mod ext_recovery_agent;
pub mod fingerprint;
pub mod kept;
pub mod keys;
pub mod links;
pub mod list;
pub mod merge;
pub mod passkey;
pub mod pins;
pub mod possession;
pub mod record;
pub mod recovery;
pub mod state;

pub use checkpoint::{Checkpoints, Contest, LateWork, PROPOSAL_THRESHOLD};
pub use errors::IdentityClass;
pub use kept::KeptList;
pub use keys::{Kind, MemberKeys, PublicKeys, Rank};
pub use list::{DeviceList, Refusal};
pub use merge::{MergedList, read_user_handle};
pub use pins::{Pin, PinCheck};
pub use record::{ListRecord, RecordMember, RecordSeniority};
pub use state::{Member, Rootedness};
