//! Lower-level access to the client, for tools, tests and bindings.
//!
//! **This module is less stable than the crate root.** An application uses
//! [`Device`](crate::advanced::Engine) and the types beside it, and never needs what
//! is here. What is here is the protocol's machinery as the client runs it:
//! nothing is scheduled, nothing syncs, heals or cascades unless it is
//! called, and names follow the specification's procedures rather than what
//! an application does. Its shape changes whenever the client's internals
//! do.
//!
//! - [`Engine`]: everything a device does, one call per procedure: making
//!   spaces, signing roster events, key events and units, placing what
//!   other parties send, sync sessions, heals and cascades. A
//!   [`Device`](crate::advanced::Engine) runs one, and lends it through
//!   [`Device::engine`](crate::Device::engine).
//! - [`Platform`]: what an engine runs on: the store and the device-bound
//!   slot, the restore mode, the clocks and randomness (at-rest.md, "What
//!   the application provides"; overview.md, "Time").
//! - [`Tasks`]: where a device runs its background work, for a platform
//!   without tokio's runtime.
//! - [`KeepKeys`]: where an application that supplies its own store keeps
//!   the device's sealed keys.
//! - [`replica`]: the replica engine, which judges a space's log in
//!   roster.md's order of verification, takes the keys its deliveries and
//!   links carry (keys.md), and hands units to their adapters (units.md).
//! - [`adapters`]: the adapter registry (units.md, "The adapter
//!   interface").
//! - [`outbox`]: the outbox and acknowledgements (units.md, "Heads,
//!   acknowledgements and durability").
//! - [`sync`]: baseline sync, sans-IO (units.md, "Sync").
//! - [`Engine::fetch_chunks`]: asks the space's connections for a range of
//!   an object's chunks at a [`FetchPriority`], until its [`Fetch`] is
//!   cancelled or dropped.
//! - [`intake`]: the client's readers, through which every byte another
//!   party or the store hands the device passes first.
//! - [`maintenance`], [`persons`] and [`snapshots`]: heals and cascades,
//!   persons and their device lists, and the newcomer's snapshot.
//! - [`recovery`]: recovery keys and passkey members, their recovery
//!   entries, and recovering with a sheet or a passkey. Head
//!   statements and objects are the engine's methods alone.
//! - `peer`: device-to-peer connections over the server binding, the iroh
//!   binding, or a socket the application supplies.
//! - `node`, `member` and `pairing` (feature `iroh`): a device's iroh
//!   endpoint, its member connections and nearby pairing.
//! - `documents` (feature `adapter-loro`): Loro documents through the
//!   engine; `ephemeral` (feature `ephemeral`): the ephemeral channel.
//! - `invite_links` (feature `ext-invite-links`): invite links through the
//!   engine. With `ext-recovery-agent`, the engine names agents, keeps each
//!   space's waiting decisions, relays an agent's adds and vetoes them.
//!   With `ext-restricted-spaces`, it creates restricted spaces, mirrors
//!   their parents' removals, moves streams and re-applies late writes.
//! - Partial replicas (feature `partial-replicas`):
//!   `Engine::hold_streams_only`, then
//!   [`Engine::hold_stream`] for each stream to hold, and
//!   [`Engine::add_path`] for a `Path` another party serves.

pub use crate::adapters::{AdapterRegistry, ContentOutcome, StreamRuntime};
pub use crate::client::KeepKeys;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub use crate::client::peers::Connect;
pub use crate::device::{Engine, Ingested, Notice};
pub use crate::fetch::{Fetch, FetchPriority};
pub use crate::outbox::{Acknowledger, Outbox};
pub use crate::platform::{Clock, ManualClock, OsRandom, Platform, Random, SystemClock};
pub use crate::replica::Replica;
pub use crate::tasks::Tasks;
pub use frasil_store::{Continuity, DeviceBoundSlot, MemorySlot, MemoryStore, RestoreMode, Store};

pub mod adapters {
    //! The adapter registry (units.md, "The adapter interface").
    pub use crate::adapters::*;
}

pub mod engine {
    //! The engine: a device's keys, sealed at rest; its store, head and
    //! mark (at-rest.md); making spaces, signing roster events, key events
    //! and units, and placing what other parties send.
    pub use crate::device::*;
}

#[cfg(feature = "adapter-loro")]
pub mod documents {
    //! Loro documents (adapter-loro.md), through the engine.
    pub use crate::documents::*;
    pub use crate::text::{Comparison, Stopped, TextSplice, compare_text, replace_text};
}

#[cfg(feature = "ephemeral")]
pub mod ephemeral {
    //! The ephemeral channel (ext-ephemeral.md) over member connections.
    pub use crate::ephemeral::*;
}

#[cfg(feature = "ext-invite-links")]
pub mod invite_links {
    //! Invite links (ext-invite-links.md): the inviter's invite and drop,
    //! the claimant's walk, and the administering devices' acts, through
    //! the engine.
    pub use crate::invite_links::{ClaimOffer, ClaimStatus, MadeInvite, SpentInvite};
}

#[cfg(feature = "ext-guests")]
pub mod guests {
    //! Guests (ext-guests.md): a leave request, sealed to each
    //! administering device's mailbox.
    pub use crate::guests::Leaving;
}

/// History (decision: a client toolkit), through the engine: a stream's
/// changes, a document at a version, tables after a change.
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
pub mod history {
    pub use crate::history::*;
}

/// Held objects (at-rest.md, "Held objects"): the provider, the policy and
/// a withdrawal.
pub mod held {
    pub use crate::held::{
        HeldPut, ObjectPolicy, ObjectProvider, ObjectReader, ObjectStat, ObjectWriter, ReceiveKey,
        Receiver, Served, Withdrawn, put_with, put_with_chunked, serve_with, serve_with_chunked,
    };
}

/// Space files (ext-space-files.md): export, append and import through
/// the engine, with the road in.
#[cfg(feature = "space-files")]
pub mod space_file {
    pub use crate::space_file::{Embed, ExportOptions, Imported, Road, WayInOption};
}

pub mod public_keys {
    //! A device's three public keys as bytes, which a direct grant carries,
    //! accepted only under the device ID they hash to.
    pub use crate::public_keys::*;
}

pub mod intake {
    //! The client's readers, through which every byte another party or the
    //! store hands the device passes first.
    pub use crate::intake::*;
}

pub mod maintenance {
    //! Heals and cascades (keys.md, "Healing", "Cascades", "The rank and
    //! the delay").
    pub use crate::maintenance::*;
}

#[cfg(feature = "iroh")]
pub mod member {
    //! Member connections on the iroh binding (transport.md, "The iroh
    //! binding").
    pub use crate::member::*;
}

#[cfg(feature = "iroh")]
pub mod node {
    //! A device's member endpoint and its connections on the iroh binding.
    pub use crate::node::*;
}

pub mod outbox {
    //! The outbox and acknowledgements (units.md, "Heads,
    //! acknowledgements and durability").
    pub use crate::outbox::*;
}

#[cfg(feature = "iroh")]
pub mod pairing {
    //! Admission by code over a nearby connection (admission.md, "Nearby
    //! pairing").
    pub use crate::pairing::*;
}

#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub mod peer {
    //! Device-to-peer connections (transport.md, sections 3.10 to 3.12,
    //! 3.15 and 3.16).
    pub use crate::peer::*;
}

pub mod persons {
    //! Persons and their device lists (identity.md), through the engine.
    pub use crate::persons::*;
}

pub mod platform {
    //! What the application supplies: the store and the device-bound slot,
    //! the restore mode, the clocks and randomness.
    pub use crate::platform::*;
}

pub mod recovery {
    //! Recovery keys and passkey members, their recovery entries, and a
    //! device that returns with a sheet or a passkey (identity.md,
    //! "Recovery").
    pub use crate::recovery::*;
}

pub mod replica {
    //! The replica engine, which judges a space's log.
    pub use crate::replica::*;
}

pub mod snapshots {
    //! The newcomer's snapshot and body keys (admission.md, "The
    //! newcomer's snapshot").
    pub use crate::snapshots::*;
}

pub mod sync {
    //! Baseline sync, sans-IO (units.md, "Sync").
    pub use crate::sync::*;
}
