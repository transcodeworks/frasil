//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's transport, sans-IO: frames, message types, the handshakes,
//! mailboxes, tickets and local-network packets.
//!
//! Specified by `docs/spec/transport.md`, section 2 (Formats) and sections
//! 3.1 (Reading a frame) to 3.14 (Mailboxes), with the values of 3.15 (The
//! server binding) and 3.16 (The iroh binding) that need no socket. Its
//! vectors are `docs/spec/vectors/transport.json`.
//!
//! - [`codes`]: the codes of QUIC and WebSocket closes, `Refuse` and
//!   `Detach`; reason codes and their HTTP statuses; services and rights.
//! - [`frame`]: stream classes, message types, `read_frame` and a deframer
//!   for byte streams.
//! - [`messages`]: each message type, read and written.
//! - [`member`]: the member handshake's values and checks, one step at a
//!   time.
//! - [`session`]: the member connection as a state machine: attaches,
//!   offers, answers, `Identify`, the roster check's outcome, `Admit` and
//!   `Detach`.
//! - [`roster`]: the roster check's outcomes and probation.
//! - [`peer`]: the device-to-peer handshake as two state machines, the
//!   binding, the purpose rules, and the server binding's channel and
//!   routes.
//! - [`mailbox`]: addresses, the item seal, collecting a device mailbox,
//!   and a device mailbox's eviction.
//! - [`caps`]: the peer's caps over all its device mailboxes, claimed
//!   mailboxes, and how long their items are kept.
//! - [`ticket`]: tickets and their text form.
//! - [`addresses`]: member addresses, the `Addresses` message and what its
//!   receiver does with each entry.
//! - [`lan`]: member announcements and nearby announcements.
//!
//! The crate holds no socket, clock or randomness of its own. Channel
//! bindings come in as 32-byte values the binding computed (RFC 9266's
//! exporter on the iroh binding, the origin's hash on the server binding),
//! and every random draw has a `_with` form that takes its bytes.

pub mod addresses;
pub mod caps;
pub mod codes;
#[cfg(feature = "ext-deposit-tokens")]
pub mod ext_deposit_tokens;
#[cfg(feature = "ext-guests")]
pub mod ext_guests;
#[cfg(feature = "ext-invite-links")]
pub mod ext_invite_links;
#[cfg(feature = "ext-next-endpoints")]
pub mod ext_next_endpoints;
#[cfg(feature = "ext-restricted-spaces")]
pub mod ext_restricted_spaces;
pub mod frame;
pub mod lan;
pub mod mailbox;
pub mod member;
pub mod messages;
pub mod peer;
pub mod roster;
pub mod session;
pub mod ticket;

pub use codes::Code;
pub use frame::{ConnectionKind, Extensions, Message, MessageType, StreamClass};

frasil_base::error_classes! {
    /// The error classes of transport.md (section 3.13, "Error classes"),
    /// with every shared class. Each is a decision about one frame, attach,
    /// connection or request, and says nothing about any event's validity.
    pub enum TransportClass {
        /// No offered state matched.
        NoCommonState = "no_common_state", Decision;
        /// An answer whose proof does not verify, or whose index names no
        /// real state.
        BadProof = "bad_proof", Decision;
        /// The device is out of the verifier's view.
        MembershipEnded = "membership_ended", Decision;
        /// Probation ended without the device.
        UnknownMember = "unknown_member", Decision;
        /// `handshake_deadline` passed.
        Timeout = "timeout", Decision;
        /// An attach number of 1,024 or more.
        AttachLimit = "attach_limit", Decision;
        /// The responder's budget or rate limit.
        Busy = "busy", Decision;
        /// A message the connection's purpose does not allow.
        PurposeViolation = "purpose_violation", Decision;
        /// A credential refused, or a message with no right.
        CredentialRefused = "credential_refused", Decision;
        /// A collecting key that does not hash to the address.
        WrongMailbox = "wrong_mailbox", Decision;
        /// No valid bearer token where one is needed.
        Unauthenticated = "unauthenticated", Decision;
        /// A mailbox item whose content name the device does not implement;
        /// dropped.
        UnknownContent = "unknown_content", Decision;
        /// A member announcement that no state the listener holds opens;
        /// dropped.
        NotForMe = "not_for_me", Decision;
    }
}

impl TransportClass {
    /// The code a failure of this class closes, refuses or detaches with
    /// (section 2.5), if it has one: a shared class by its own name,
    /// `UnknownMessage` as `malformed`, `WrongMailbox` as
    /// `credential_refused`.
    pub fn code(self) -> Option<Code> {
        use frasil_base::ErrorClass as E;
        Some(match self {
            Self::Shared(E::Malformed | E::UnknownMessage) => Code::Malformed,
            Self::Shared(E::TooLarge) => Code::TooLarge,
            Self::Shared(E::UnsupportedVersion) => Code::UnsupportedVersion,
            Self::Shared(E::BadSignature) => Code::BadSignature,
            Self::Shared(E::InvalidKey) => Code::InvalidKey,
            Self::Shared(E::Forked) => Code::Forked,
            Self::Shared(E::RevisionMismatch) => Code::RevisionMismatch,
            Self::NoCommonState => Code::NoCommonState,
            Self::BadProof => Code::BadProof,
            Self::MembershipEnded => Code::MembershipEnded,
            Self::UnknownMember => Code::UnknownMember,
            Self::Timeout => Code::Timeout,
            Self::AttachLimit => Code::AttachLimit,
            Self::Busy => Code::Busy,
            Self::PurposeViolation => Code::PurposeViolation,
            Self::CredentialRefused | Self::WrongMailbox => Code::CredentialRefused,
            _ => return None,
        })
    }
}

/// A failure that closes the connection: the code the close carries and
/// the class that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed {
    /// The close code (section 2.5).
    pub code: Code,
    /// The class of the failure.
    pub class: TransportClass,
}

impl Closed {
    /// A close for a failure of `class`: its own code, or `malformed` for a
    /// class without one.
    pub fn of(class: impl Into<TransportClass>) -> Self {
        let class = class.into();
        Self {
            code: class.code().unwrap_or(Code::Malformed),
            class,
        }
    }
}

impl core::fmt::Display for Closed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "closed with {} ({})", self.code.name(), self.class)
    }
}

impl std::error::Error for Closed {}

impl From<TransportClass> for Closed {
    fn from(class: TransportClass) -> Self {
        Self::of(class)
    }
}

impl From<frasil_base::ErrorClass> for Closed {
    fn from(class: frasil_base::ErrorClass) -> Self {
        Self::of(class)
    }
}

impl From<frasil_base::cbor::Malformed> for Closed {
    fn from(_: frasil_base::cbor::Malformed) -> Self {
        Self::of(frasil_base::ErrorClass::Malformed)
    }
}

/// The labels and ALPNs this document uses (section 2.2), from crypto.md's
/// registry, and the names of its bindings.
pub mod labels {
    pub use frasil_crypto::labels::{
        LAN_ANNOUNCE, LAN_KEY, MAILBOX, MAILBOX_COLLECT, MAILBOX_ITEM, MEMBER_ANSWER,
        MEMBER_IDENTIFY, MEMBER_KEY, MEMBER_OFFER, MEMBER_TRANSCRIPT, P1_MEMBER, P1_NEARBY,
        P1_PEER, PEER_BINDING, SERVER_CHANNEL,
    };

    /// Every label and ALPN of this document, in its order.
    pub const ALL: [&[u8]; 15] = [
        MEMBER_KEY,
        MEMBER_OFFER,
        MEMBER_TRANSCRIPT,
        MEMBER_ANSWER,
        MEMBER_IDENTIFY,
        PEER_BINDING,
        SERVER_CHANNEL,
        LAN_KEY,
        LAN_ANNOUNCE,
        MAILBOX,
        MAILBOX_COLLECT,
        MAILBOX_ITEM,
        P1_MEMBER,
        P1_PEER,
        P1_NEARBY,
    ];

    /// RFC 9266's exporter label, the `tls-exporter` channel binding; not a
    /// Frasil label.
    pub const EXPORTER: &[u8] = b"EXPORTER-Channel-Binding";
    /// The exporter's length in bytes: the channel binding's.
    pub const EXPORTER_BYTES: usize = 32;
    /// The server binding's WebSocket subprotocol.
    pub const WEBSOCKET_SUBPROTOCOL: &str = "frasil.p1";
}

/// A channel binding (T2): 32 bytes, equal at both ends, unique to the
/// transport session (section 2.1).
pub type Channel = [u8; 32];

/// The handshake's deadline, `handshake_deadline`, in seconds: from the
/// transport's connection to the first `Admit` or refusal (section 3.4).
pub const HANDSHAKE_DEADLINE_SECONDS: u64 = 10;

/// A nearby pairing's deadline, `pairing_deadline`, in seconds (section
/// 3.16).
pub const PAIRING_DEADLINE_SECONDS: u64 = 90;

/// Checks that a map has exactly these keys.
pub(crate) fn exact_keys(map: &frasil_base::cbor::Map, keys: &[u64]) -> bool {
    map.len() == keys.len() && map.keys().zip(keys).all(|(a, b)| a == b)
}
