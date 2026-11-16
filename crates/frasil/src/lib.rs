//! Frasil for applications: devices that share spaces of documents, tables
//! and files, end to end encrypted, online and offline.
//!
//! This is the crate an application depends on. A [`Device`] keeps its
//! records in a [`Storage`], holds [`Space`]s, and connects to always-on
//! [`Peer`]s by URL. A space holds streams: a Loro [`Document`], a set of
//! [`Records`] tables, or [`Blobs`]. A device admits another device by an
//! [`Invitation`], whose person enters it, and both persons compare a
//! six-digit code. Everything the protocol needs besides runs by itself:
//! sync, durability at peers, and the heals and cascades that keep keys
//! current.
//!
//! Retained erasures are retried by upkeep and on demand with
//! [`Device::retry_erasure`]. After checking a late answer without space
//! keys, the device requests a welcome from the saved administrators before
//! fetching the space and judging the checkpoint.
//!
//! # Quick start
//!
//! Two devices share a note through a peer. Here the peer runs on loopback;
//! an application names its peer's URL.
//!
//! ```no_run
//! # #[cfg(all(feature = "server", feature = "iroh", feature = "adapter-loro"))]
//! use frasil::{Device, Level, Options, Storage};
//!
//! # #[cfg(all(feature = "server", feature = "iroh", feature = "adapter-loro"))]
//! # async fn run(peer_url: &str) -> frasil::Result<()> {
//! // Each device seals its keys under an unlock key from the platform's
//! // keychain.
//! let alice = Device::open_with(Storage::Memory, &[1; 32], Options::new().loopback()).await?;
//! let bob = Device::open_with(Storage::Memory, &[2; 32], Options::new().loopback()).await?;
//!
//! // Alice creates a space, and keeps it at the peer.
//! let space = alice.create_space().await?;
//! alice.connect(peer_url).await?;
//!
//! // Alice invites Bob's device. Bob enters the invitation's text, and
//! // both persons confirm that their screens show the same code.
//! let invitation = space
//!     .invite(Level::Write, "Alice's laptop", |code, newcomer| async move {
//!         println!("Alice: is {code} on {newcomer}'s screen?");
//!         true
//!     })
//!     .await?;
//! let bobs_space = bob
//!     .join(invitation.text(), "Bob's phone", |code, host| async move {
//!         println!("Bob: is {code} on {host}'s screen?");
//!         true
//!     })
//!     .await?;
//! invitation.admitted().await?;
//! bob.connect(peer_url).await?;
//!
//! // Alice writes a note; Bob opens it once it has arrived, and edits it
//! // too. The edits merge.
//! let note = space.create_document()?;
//! note.edit(|doc| doc.get_text("body").insert(0, "Hello")).await?;
//! let bobs_note = bobs_space
//!     .document_when_available(note.id(), std::time::Duration::from_secs(30))
//!     .await?;
//! bobs_note
//!     .edit(|doc| doc.get_text("body").insert(0, "Bob: "))
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! `examples/shared_note.rs` runs this whole against a peer on loopback;
//! its documentation says how to run `frasil-relay` beside it.
//!
//! An already authenticated direct member can receive administrator access
//! to many spaces with `Device::admit_spaces_via_peer`; the recipient uses
//! `Device::receive_spaces_via_peer`. Each space has its own authority check
//! and progress report, and failed delivery can be retried after reconnecting.
//!
//! # What a device does by itself
//!
//! - **Sync.** Each peer connection syncs every space the device holds,
//!   both ways and live; so does the member connection admission opens.
//! - **Durability.** A peer acknowledges what it keeps; until then a change
//!   is offered again. [`Space::is_durable`] says whether it has, and
//!   [`Space::pending_authored_changes`] counts the authored events still
//!   waiting, and [`Event::PendingChanges`] reports observed count changes.
//!   [`Space::flush`] waits until it has, such as before a device that
//!   changed who administers goes offline; [`Space::wait_durable`] returns
//!   as soon as it has, or at its deadline.
//! - **Welcomes.** A grant of a person sends each of its devices a
//!   welcome, over a member connection and in its device mailbox at the
//!   granting device's peers; a device collects its mailbox there and keeps
//!   a space once the space's roster admits it
//!   ([`Device::receive_welcomes_via_peer`] does so on request).
//! - **Delayed deliveries.** A welcome, a leave request or a person's list
//!   that a peer answers `busy` or `rate_limited`, or that cannot reach the
//!   peer, is kept at rest and sent again by the device, with a growing
//!   wait, for up to 30 days; `Event::Delayed`, `Event::Delivered` and
//!   `Event::Undelivered` report it, and a batch admission whose welcome
//!   waits gives [`Error::Delayed`] with its grant made.
//! - **Reconnecting.** A device keeps where it reached each member of a
//!   space, and dials those members again when it opens again, with no
//!   peer and no internet. With [`Options::local_discovery`], members on
//!   one local network also find each other, such as two members that a
//!   third admitted.
//! - **Member addresses.** Members tell each other where the space's other
//!   members are, so a device without local discovery, such as an iPad
//!   without the multicast entitlement or one on a network that blocks
//!   multicast, still reaches every member that a member it reaches knows
//!   of, and keeps where they are for when it opens again.
//! - **Upkeep.** Heals and cascades (keys.md) run in the background, after
//!   the delay the protocol gives each device, so that a removed member
//!   reads nothing new. So do top-ups (admission.md): a member admitted
//!   "from now on" receives the body keys of changes made beside its
//!   admission, such as a claim of another invite link or an edit, and
//!   reads what follows them. A member whose admission merged with a
//!   concurrent key change receives the merged key (keys.md, "Deliveries").
//!
//! # Reading, following and caching
//!
//! A replica is the truth for every space the device holds; changes from
//! others arrive whenever a connection brings them. To show that data and
//! keep it current:
//!
//! - **Change feeds** say what changed and where ([`Origin`]):
//!   [`Space::changes`] for one space, [`Records::changes`] for the rows a
//!   write touched ([`RecordChange`]), [`Blobs::changes`] for blobs added,
//!   removed, arrived or withdrawn ([`BlobChange`]), and
//!   [`Drive::changes`](crate::Drive::changes) for a drive's entries.
//! - **Observed reads** ([`Observed`]) run a read again after a change,
//!   take changes that arrive together in one read, and tell observers
//!   only when the result differs: [`Space::observe`] for any read, and
//!   prebuilt ones such as [`Records::observe_rows`], shared by every
//!   observer of the same thing. Data that has not arrived yet is
//!   [`Status::Loading`], not an error.
//! - **Waits** return data once it arrives: [`Space::document_when_available`]
//!   and its records and blobs equivalents, [`Blobs::get_when_available`];
//!   [`Blobs::status`] says where a blob's bytes stand.
//! - **Blobs for a cache.** A [`BlobId`] names immutable bytes, a new
//!   version being a new blob, so it is a safe permanent key for an
//!   application's cache of opened bytes. [`Blobs::get_stream`] opens a blob
//!   chunk by chunk, and [`Blobs::get_range`] only the chunks a range needs,
//!   every check of the object format still running.
//! - **Pages of rows**: [`Records::rows_range`], [`Records::rows_with_prefix`].
//! - **Receipts** follow one write to its acknowledgement by a peer:
//!   [`Records::write_with_receipt`], [`Receipt::durable`].
//!
//! # Recovery
//!
//! A person who loses every device returns with a recovery sheet or a
//! passkey. [`Device::create_recovery_sheet`] adds a recovery key to the
//! device's person and returns the [`RecoverySheet`] to print once;
//! [`Device::add_passkey`] adds a passkey through the application's
//! [`Passkey`]. On a new device, [`Device::recover`] or
//! [`Device::recover_with_passkey`] fetches the personal space from a peer,
//! signs the device into the person's list, and reaches each space that
//! grants the person. Recovery keeps the resealed keys through [KeepKeys],
//! including IndexedDB's automatic keeper, and reports storage failures.
//! Native hosts can supply a [DeviceBoundSlot] backed by a device-only
//! Keychain or Keystore item for continuity across store restores.
//!
//! # Writing straight after opening
//!
//! A device opened as restored, as a directory store is at every open in
//! its default restore mode, signs in a space only once it has synced that
//! space, so that it never signs from an older copy of its own chain
//! (at-rest.md, 3.6 "After a restore"). Until then a write there fails
//! with [`Error::SyncBeforeWriting`]. [`Space::is_write_ready`] says
//! whether it may write now, [`Space::wait_write_ready`] waits until it
//! may, [`Space::observe_write_ready`] observes it, and
//! [`Event::WriteReady`] reports each space as it becomes writable.
//!
//! # Held objects
//!
//! An application that keeps files of its own, and reads them through
//! paths, can hold a space's blobs itself in place of a sealed second copy
//! (at-rest.md, "Held objects"): it gives an [`ObjectProvider`] with
//! [`Options::object_provider`], or per space with
//! [`Space::hold_objects`], and puts files with [`Blobs::put_from`], gets
//! them in place with [`Blobs::materialise`], and lets go of one with
//! [`Blobs::release`]. Frasil keeps each held blob's header and a record of
//! the file's token, size and change stamp, and seals the chunks again from
//! the file when it serves them, so peers and other members see no
//! difference. A held blob whose file changed is withdrawn, which
//! [`Event::ObjectWithdrawn`] reports, and stays fetchable from the others.
//! When no other holds it, as for a file saved over before any peer took
//! it, its bytes are lost: the unit that names it still reaches peers, and
//! nothing after it waits.
//! The policy is this device's alone, never synced and never stored. With
//! [`Options::objects_on_demand`] a device fetches only the files it asks
//! for, and shows the rest as it likes.
//!
//! # Errors
//!
//! Every fallible call returns an [`Error`]. Its message says what
//! happened; [`Error::what_to_do`] says what to do about it, and the
//! alternate form, `{error:#}`, shows both.
//!
//! # Features
//!
//! - `sqlite` (default): [`Storage::Directory`], a SQLite store.
//! - `server` (default): connecting to peers by URL over WebSocket.
//! - `iroh` (default): admission by invitation and member connections.
//! - `adapter-loro`, `adapter-records`, `adapter-blobs` (default): the
//!   stream kinds. They need no binding: a device built with only these
//!   runs live and lent documents on its own tasks, natively and on wasm32.
//! - `server-socket`, `ephemeral`: for bindings and the ephemeral channel.
//! - `index`, `index-diesel`, `index-vendored-openssl`: `frasil::index`, a typed
//!   local SQLite cache over many spaces' Records tables.
//! - `ext-invite-links`, `ext-recovery-agent`: invite links and the
//!   recovery agent (`Device::name_agent`, `Space::agent_policy`,
//!   `Device::veto`).
//! - `ext-restricted-spaces`: `Space::create_restricted`, a private part of
//!   a space that only its members reach, and `Document::move_to` into it.
//!
//! - `ext-drive`: [`Drive`], folders, files and documents of a space in
//!   one Loro document, which every application reads and writes alike.
//! - `ext-guests`: guests, admitted for a session, that leave by request,
//!   and the space policies that stop an uninformed writer.
//! - `ext-next-endpoints`: each device tells the members it is connected
//!   to the member endpoint key it takes next, so members with no peer,
//!   such as a host and its guest, meet again after both rotate.
//! - `ext-deposit-tokens` (with `ext-libraries`): the device draws
//!   anonymous deposit tokens ahead of need at each peer where it holds a
//!   grant (`Device::give_deposit_grant`) or writes a space the peer
//!   hosts, keeps them sealed at rest, and pays with one for each deposit
//!   in a device mailbox there, so that a stranger filling the peer's
//!   anonymous mailbox room delays none of them (`docs/deposit-tokens.md`).
//! - `partial-replicas`: `Options::partial`, a device that holds in each
//!   space only the documents, tables and blobs it opens, beside the
//!   space's members and keys.
//!
//! # Lower levels
//!
//! [`advanced`] exposes the engine underneath, one call per procedure of
//! the specification, for tools, tests and bindings. It is less stable than
//! this root. The `frasil-*` protocol crates it is built from are internal
//! building blocks.

// On wasm32 the store's futures are not `Send` (a browser's storage
// answers through JavaScript promises), so neither is the device's shared
// state; a browser runs the client on one thread.
#![cfg_attr(target_arch = "wasm32", allow(clippy::arc_with_non_send_sync))]

mod adapters;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod admitting;
mod at_rest;
#[cfg(all(feature = "browser", target_arch = "wasm32", target_os = "unknown"))]
pub mod browser;
mod checkpoints;
mod client;
mod compaction;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod deposits;
mod device;
#[cfg(feature = "adapter-loro")]
mod documents;
#[cfg(feature = "ephemeral")]
mod ephemeral;
mod erasing;
mod error;
mod frozen;
mod granted;
#[cfg(feature = "ext-guests")]
mod guests;
mod healing;
mod held;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod hints;
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
mod history;
#[cfg(feature = "index")]
pub mod index;
mod intake;
#[cfg(feature = "ext-invite-links")]
mod invite_links;
#[cfg(test)]
mod later_version_tests;
mod links;
mod lists;
mod maintenance;
#[cfg(feature = "iroh")]
mod member;
#[cfg(feature = "ext-next-endpoints")]
mod next_endpoints;
#[cfg(feature = "iroh")]
mod node;
mod objects;
mod outbox;
#[cfg(feature = "iroh")]
mod pairing;
mod parallel;
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod peer;
mod persons;
mod platform;
mod public_keys;
mod recovery;
#[cfg(feature = "ext-recovery-agent")]
mod recovery_agent;
mod release;
mod replica;
#[cfg(test)]
mod residue_tests;
#[cfg(test)]
mod resolution_cost;
#[cfg(feature = "ext-restricted-spaces")]
mod restricted;
#[cfg(test)]
mod roster_cost;
mod skeleton;
mod snapshots;
#[cfg(feature = "space-files")]
mod space_file;
mod statements;
mod sync;
mod tasks;
#[cfg(feature = "adapter-loro")]
pub(crate) mod text;
mod top_ups;
mod writer;

pub mod advanced;

/// The drive extension's format (ext-drive.md) over a plain Loro document,
/// for an application that keeps its own copy of a drive document and syncs
/// it through [`Live`](crate::Live): read the tree, and apply each change
/// with its checks, then commit the document's new operations. [`Drive`]
/// does the same on a space's document directly.
#[cfg(feature = "ext-drive")]
pub mod drive_format {
    pub use frasil_drive::write::{self, NewEntry, NewKind, NewVersion};
    pub use frasil_drive::{
        DOCUMENT, DOCUMENT_KIND, ENTRIES, Entry, Error, FILE, FOLDER, KIND, Kind, PURGED, Shown,
        Tree, Version, numbered, shown_names, values,
    };
}

pub use checkpoints::{CheckpointPolicy, PROPOSE_AT_FRAME_BYTES, PROPOSE_AT_ROSTER_EVENTS};
#[cfg(feature = "adapter-blobs")]
pub use client::BlobInfo;
#[cfg(feature = "adapter-blobs")]
pub use client::BlobStatus;
#[cfg(all(
    feature = "ext-deposit-tokens",
    any(feature = "server", feature = "iroh", feature = "server-socket")
))]
pub use client::DepositTokens;
#[cfg(feature = "iroh")]
pub use client::DeviceInvitation;
#[cfg(feature = "adapter-loro")]
pub use client::Document;
#[cfg(feature = "ext-guests")]
pub use client::Guest;
#[cfg(feature = "iroh")]
pub use client::Invitation;
/// Durable storage for resealed device keys, configured with [Options::keep_keys].
pub use client::KeepKeys;
pub use client::PersonId;
/// Undo for a lent document (decision: a client toolkit).
#[cfg(all(feature = "adapter-loro", not(target_arch = "wasm32")))]
pub use client::Undo;
#[cfg(feature = "ext-recovery-agent")]
pub use client::{AgentKeys, AgentPolicy, NamedAgent};
pub use client::{
    Arrival, Arrivals, BlobId, Device, Event, Events, Member, MemberId, MemberKind, Observation,
    Observed, Options, Origin, Receipt, Space, SpaceChange, SpaceChanges, SpaceId, Status, Storage,
    StreamId, StreamInfo, StreamKind, UnitId, VersionId,
};
pub use client::{
    BackdatedCheckpoint, ChangeId, CheckpointId, CheckpointStatus, CheckpointWork,
    ContestedCheckpoint, LateChange, LateChangeKind, ListCheckpointStatus, ListCheckpointWork,
    PendingCheckpoint, PendingListCheckpoint,
};
#[cfg(feature = "adapter-blobs")]
pub use client::{Blob, Blobs, PutVersion};
#[cfg(feature = "adapter-blobs")]
pub use client::{BlobChange, BlobChanges};
#[cfg(feature = "adapter-loro")]
pub use client::{Changes, Live, OnLimit, SetText};
#[cfg(feature = "ext-app-requests")]
pub use client::{DeviceLists, NonceStore, RequestVerifier, SignedHeaders, VerifiedRequest};
#[cfg(feature = "ext-drive")]
pub use client::{
    Drive, DriveBatch, DriveChange, DriveChanges, DriveEntry, DriveFile, EntryId, EntryKind,
    FileVersion,
};
#[cfg(feature = "ephemeral")]
pub use client::{Ephemeral, EphemeralStream};
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
pub use client::{Joining, JoiningPerson, Peer, PeerStatus, SpaceAdmission};
/// One document: a Loro document lent to the application, edited directly
/// (decision: one document).
#[cfg(all(feature = "adapter-loro", not(target_arch = "wasm32")))]
pub use client::{LENT_PENDING_LIMIT, LENT_RETRY_LIMIT, LENT_WINDOW, Lent};
#[cfg(feature = "adapter-records")]
pub use client::{LastChange, Records, Row, RowWithMetadata, Transaction};
/// Undo for tables, and named versions (decision: a client toolkit).
#[cfg(feature = "adapter-records")]
pub use client::{Marked, RecordsUndo, Version};
pub use client::{Passkey, PasskeyAssertion, PasskeyFuture, PrfOutput, RecoverySheet};
#[cfg(feature = "adapter-records")]
pub use client::{RecordChange, RecordChanges};
/// Review (decision: a client toolkit): a suggestion read against its
/// base.
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
pub use client::{Review, ReviewChange, TextStep};
#[cfg(feature = "space-files")]
pub use client::{SpaceFile, SpaceFileFormat};
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
pub use client::{Suggestion, SuggestionId};
#[cfg(feature = "adapter-loro")]
pub use documents::{TextOutcome, TextWritten};
pub use error::{Error, Result};
pub use frasil_base::cbor::Value;
/// A device ID, which a [`NonceStore`] keys nonces by: the hash of a
/// device's Ed25519 key and the commitment to its other keys (crypto.md,
/// "A device's keys"). [`MemberId`] holds the same 32 bytes.
#[cfg(feature = "ext-app-requests")]
pub use frasil_crypto::device::DeviceId;
/// A library ticket handed to a person as a link (ext-libraries.md): the
/// origin of the peer to connect to, and the ticket's bytes for
/// `Options::library_ticket`, `Device::set_library_ticket` or
/// `Space::attach_library`, or, for a deposit grant,
/// `Device::give_deposit_grant`.
#[cfg(feature = "ext-libraries")]
pub use frasil_libraries::link::TicketLink;
pub use frasil_space::{HistoryMode, Level};
/// A boxed asynchronous adapter result; Send on native targets.
pub use frasil_store::BoxFuture;
/// A durable continuity mark excluded from backups, for [Options::device_bound].
pub use frasil_store::DeviceBoundSlot;
/// A storage or device-bound slot backend failure.
pub use frasil_store::StoreError;
pub use held::{ObjectPolicy, ObjectProvider, ObjectReader, ObjectStat, ObjectWriter};
/// History: who changed what, when, for documents and tables.
#[cfg(any(feature = "adapter-loro", feature = "adapter-records"))]
pub use history::{Author, Change, Detail, Effect, Kind, RowChange, Standing};
#[cfg(feature = "adapter-loro")]
pub use history::{DocumentChange, Span};
#[cfg(feature = "adapter-records")]
pub use history::{Replay, Tables};
/// Who claims an invite link: a device, or the person of the device that
/// opens it.
#[cfg(feature = "ext-invite-links")]
pub use invite_links::Claimant;
#[cfg(feature = "adapter-loro")]
pub use text::{LineEnding, TextStyle};
/// Space files (ext-space-files.md): what [`SpaceFile`] exports, imports
/// and reads.
#[cfg(feature = "space-files")]
pub mod space_files {
    pub use crate::client::space_file::{Export, Objects, Opened, WayIn, dynamic};
    #[cfg(feature = "ext-invite-links")]
    pub use crate::client::space_file::{Invitation, Invited};
    pub use crate::space_file::Road;
    pub use frasil_space_file::file::Sniffed;
    pub use frasil_space_file::record::{History, Manifest, Section};
}
/// The Loro library, whose documents [`Document`] edits.
#[cfg(feature = "adapter-loro")]
pub use loro;
