//! Frames, stream classes and message types (transport.md, sections 2.3
//! "Frames and stream classes", 2.4 "Message types" and 3.1 "Reading a
//! frame").
//!
//! ```text
//! frame = u32be(len(message)) || message
//! ```
//!
//! On a message channel, such as a WebSocket or a datagram, one message is
//! one frame, with no prefix: [`read_message`] reads it. On a stream,
//! [`read_frame`] reads one frame from the front of the bytes received, and
//! [`Deframer`] keeps the bytes of a stream between reads.

use crate::TransportClass;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};

/// The largest message units.md's baseline sync puts in one `Sync`, 1,052,672
/// bytes.
pub const UNITS_MESSAGE_BYTES: usize = 1_052_672;
/// The largest mailbox item, 262,144 bytes.
pub const MAILBOX_ITEM_BYTES: usize = 262_144;
/// The largest object chunk, 1,048,576 bytes.
pub const OBJECT_CHUNK_BYTES: usize = 1_048_576;
/// The largest frame a binding carries (T3), 1,056,768 bytes.
pub const MAX_FRAME_BYTES: usize = UNITS_MESSAGE_BYTES + 4_096;

/// A stream class (section 2.3), with its cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamClass {
    /// Handshakes, attaches, `Addresses`, presents, mailbox messages, `Merge`,
    /// `RegisterRecoveryEntry`, `Awaiting`, `EventRefused`, `Gone`, and
    /// types 21 and 28.
    Control,
    /// `Open`, `Sync`, `AdapterSync`.
    Sync,
    /// `Open`, `Sync` carrying object chunks.
    Object,
    /// `Open`, `Ephemeral`.
    Ephemeral,
    /// `Pairing`.
    Nearby,
}

impl StreamClass {
    /// Every class, in the table's order.
    pub const ALL: [StreamClass; 5] = [
        Self::Control,
        Self::Sync,
        Self::Object,
        Self::Ephemeral,
        Self::Nearby,
    ];

    /// The class's cap: the largest message its frames carry, in bytes.
    pub const fn cap(self) -> usize {
        match self {
            Self::Control | Self::Nearby => MAILBOX_ITEM_BYTES + 4_096,
            Self::Sync | Self::Object => MAX_FRAME_BYTES,
            Self::Ephemeral => 25_088,
        }
    }

    /// The class's name, as the vectors write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Sync => "sync",
            Self::Object => "object",
            Self::Ephemeral => "ephemeral",
            Self::Nearby => "nearby",
        }
    }

    /// The class of a name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The code `Open` names the class by: 1 sync, 2 object, 3 ephemeral.
    pub const fn open_code(self) -> Option<u64> {
        match self {
            Self::Sync => Some(1),
            Self::Object => Some(2),
            Self::Ephemeral => Some(3),
            Self::Control | Self::Nearby => None,
        }
    }

    /// The class `Open` names by a code.
    pub fn from_open_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Sync),
            2 => Some(Self::Object),
            3 => Some(Self::Ephemeral),
            _ => None,
        }
    }
}

/// What kind of connection a message arrives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionKind {
    /// Two devices: the iroh binding's `frasil/p1/member`. A scope is an
    /// attach number.
    Member,
    /// A device and an always-on peer: `frasil/p1/peer`, or the server
    /// binding's WebSocket. A scope is a space ID.
    DeviceToPeer,
    /// One admission exchange: `frasil/p1/nearby`. A scope is a space ID.
    Nearby,
}

impl ConnectionKind {
    /// Whether a scope on this connection is an attach number rather than a
    /// space ID.
    pub const fn scopes_by_attach(self) -> bool {
        matches!(self, Self::Member)
    }
}

/// The extensions a receiver implements that give message types of their
/// own (section 2.4). A receiver that does not implement one treats its
/// type as unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Extensions {
    /// ext-libraries.md: types 21, `LibraryAttach`, and 31, `HoldObject`.
    pub libraries: bool,
    /// ext-invite-links.md: type 28, `MailboxDelete`, and mailbox kind 4.
    pub invite_links: bool,
    /// ext-next-endpoints.md: type 96, `NextEndpoint`.
    pub next_endpoints: bool,
    /// ext-deposit-tokens.md: types 40 to 43, and `MailboxPut` key 7. It
    /// counts only in a build with the `ext-deposit-tokens` feature.
    pub deposit_tokens: bool,
}

impl Extensions {
    /// A core receiver: no extension.
    pub const NONE: Self = Self {
        libraries: false,
        invite_links: false,
        next_endpoints: false,
        deposit_tokens: false,
    };

    /// Whether the receiver reads ext-deposit-tokens.md's types and
    /// `MailboxPut` key 7: in a build with that feature, when it says so.
    pub const fn reads_deposit_tokens(self) -> bool {
        cfg!(feature = "ext-deposit-tokens") && self.deposit_tokens
    }
}

macro_rules! message_types {
    ($( $(#[$doc:meta])* $variant:ident = $code:literal, $cap:expr, [$($class:ident),*]; )*) => {
        /// A message type of section 2.4's table.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum MessageType {
            $( $(#[$doc])* $variant, )*
        }

        impl MessageType {
            /// Every type, in code order.
            pub const ALL: &'static [MessageType] = &[ $( MessageType::$variant, )* ];

            /// The type's code, key 0 of its messages.
            pub const fn code(self) -> u64 {
                match self {
                    $( Self::$variant => $code, )*
                }
            }

            /// The type's name.
            pub const fn name(self) -> &'static str {
                match self {
                    $( Self::$variant => stringify!($variant), )*
                }
            }

            /// The type's cap: its largest message, in bytes.
            pub const fn cap(self) -> usize {
                match self {
                    $( Self::$variant => $cap, )*
                }
            }

            /// The stream classes that carry the type.
            pub const fn classes(self) -> &'static [StreamClass] {
                match self {
                    $( Self::$variant => &[$(StreamClass::$class),*], )*
                }
            }

            /// The type of a code, whatever the receiver implements.
            pub const fn from_code(code: u64) -> Option<Self> {
                match code {
                    $( $code => Some(Self::$variant), )*
                    _ => None,
                }
            }
        }
    };
}

const SMALL: usize = 4_096;
const MEDIUM: usize = 16_384;
const MAILBOX_CAP: usize = MAILBOX_ITEM_BYTES + 4_096;
const EPHEMERAL_CAP: usize = 25_088;

message_types! {
    /// 1: the initiator's offer of states.
    Offer = 1, SMALL, [Control];
    /// 2: the responder's answer.
    Answer = 2, SMALL, [Control];
    /// 3: an offer refused.
    Refuse = 3, SMALL, [Control];
    /// 4: a device's `ed || kc`, its device ID bound to the connection.
    Identify = 4, SMALL, [Control];
    /// 5: an attach admitted.
    Admit = 5, SMALL, [Control];
    /// 6: an attach detached.
    Detach = 6, SMALL, [Control];
    /// 7: the first message of every stream after the control stream.
    Open = 7, SMALL, [Sync, Object, Ephemeral];
    /// 8: member tickets of the space's other members.
    Addresses = 8, MEDIUM, [Control];
    /// 16: the peer's hello.
    PeerHello = 16, MEDIUM, [Control];
    /// 17: the device's hello.
    Hello = 17, MEDIUM, [Control];
    /// 18: a credential presented.
    Present = 18, MEDIUM, [Control];
    /// 19: a present granted.
    Granted = 19, MEDIUM, [Control];
    /// 20: a request refused.
    Refused = 20, MEDIUM, [Control];
    /// 21: ext-libraries.md's `LibraryAttach`.
    LibraryAttach = 21, MEDIUM, [Control];
    /// 22: a request accepted.
    Accepted = 22, MEDIUM, [Control];
    /// 23: a merge statement.
    Merge = 23, MEDIUM, [Control];
    /// 24: a mailbox deposit.
    MailboxPut = 24, MAILBOX_CAP, [Control];
    /// 25: a mailbox collection.
    MailboxGet = 25, MAILBOX_CAP, [Control];
    /// 26: a mailbox's items.
    MailboxItems = 26, MAILBOX_CAP, [Control];
    /// 27: the requests an administrator slot has not acknowledged.
    Awaiting = 27, MAILBOX_CAP, [Control];
    /// 28: ext-invite-links.md's `MailboxDelete`.
    MailboxDelete = 28, MEDIUM, [Control];
    /// 29: a fetch key to register as a recovery entry.
    RegisterRecoveryEntry = 29, MEDIUM, [Control];
    /// 30: an event a peer neither acknowledges nor holds pending.
    EventRefused = 30, MEDIUM, [Control];
    /// 31: ext-libraries.md's `HoldObject`.
    HoldObject = 31, MEDIUM, [Control];
    /// 32: one message of units.md's baseline sync.
    Sync = 32, MAX_FRAME_BYTES, [Sync, Object];
    /// 34: an adapter's own sync.
    AdapterSync = 34, MAX_FRAME_BYTES, [Sync];
    /// 40: ext-deposit-tokens.md's `TokenKeysGet`.
    TokenKeysGet = 40, MEDIUM, [Control];
    /// 41: ext-deposit-tokens.md's `TokenKeys`.
    TokenKeys = 41, MEDIUM, [Control];
    /// 42: ext-deposit-tokens.md's `TokenRequest`.
    TokenRequest = 42, MEDIUM, [Control];
    /// 43: ext-deposit-tokens.md's `TokenIssue`.
    TokenIssue = 43, MEDIUM, [Control];
    /// 48: an outer frame of ext-ephemeral.md.
    Ephemeral = 48, EPHEMERAL_CAP, [Ephemeral];
    /// 49: an origin gone, from a relaying peer.
    Gone = 49, EPHEMERAL_CAP, [Control];
    /// 64: one message of admission.md's exchange.
    Pairing = 64, MAILBOX_CAP, [Nearby];
    /// 96: ext-next-endpoints.md's `NextEndpoint`, in the ignorable range.
    NextEndpoint = 96, SMALL, [Control];
    /// 97: a peer reports an erasure late under its cut in effect.
    ErasureLate = 97, MAILBOX_CAP, [Control];
}

impl MessageType {
    /// Whether a receiver with these extensions knows the type: types 21,
    /// 28, 31, 40 to 43 and 96 are their extensions'.
    pub const fn known_with(self, extensions: Extensions) -> bool {
        match self {
            Self::LibraryAttach | Self::HoldObject => extensions.libraries,
            Self::MailboxDelete => extensions.invite_links,
            Self::NextEndpoint => extensions.next_endpoints,
            Self::TokenKeysGet | Self::TokenKeys | Self::TokenRequest | Self::TokenIssue => {
                extensions.reads_deposit_tokens()
            }
            _ => true,
        }
    }

    /// The extension document that defines the type, if one does.
    pub const fn extension(self) -> Option<&'static str> {
        match self {
            Self::LibraryAttach | Self::HoldObject => Some("ext-libraries.md"),
            Self::MailboxDelete => Some("ext-invite-links.md"),
            Self::NextEndpoint => Some("ext-next-endpoints.md"),
            Self::TokenKeysGet | Self::TokenKeys | Self::TokenRequest | Self::TokenIssue => {
                Some("ext-deposit-tokens.md")
            }
            _ => None,
        }
    }

    /// Whether a class carries the type.
    pub fn carried_by(self, class: StreamClass) -> bool {
        self.classes().contains(&class)
    }
}

/// The ignorable types: a receiver drops one it does not know.
pub const IGNORABLE: core::ops::RangeInclusive<u64> = 96..=127;

/// One message, as read: its type, its map, and its bytes as received
/// (the transcript hashes an offer's bytes as received).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The type, key 0.
    pub kind: MessageType,
    /// The map, key 0 included.
    pub map: Map,
    /// The deterministic CBOR the message arrived as.
    pub bytes: Vec<u8>,
}

impl Message {
    /// A value of the map.
    pub fn get(&self, key: u64) -> Option<&Value> {
        self.map.get(&key)
    }
}

/// `read_frame`'s steps 2 to 6 on one message (section 3.1). `Ok(None)`
/// for an unknown type in 96 to 127, which the receiver drops.
///
/// # Errors
///
/// In the document's order: `Malformed` for a payload that is not one
/// deterministic CBOR map with an unsigned key 0, or is empty;
/// `UnknownMessage` for another unknown type; `Malformed` for a type the
/// class does not carry; `TooLarge` over the type's cap; `Malformed`, on a
/// member connection, for a `Gone` or an `Ephemeral` with key 3, and on any
/// other connection for an `Addresses`.
pub fn read_message(
    payload: &[u8],
    class: StreamClass,
    connection: ConnectionKind,
    extensions: Extensions,
) -> Result<Option<Message>, TransportClass> {
    // 2. One deterministic CBOR map, not empty, with an unsigned key 0.
    let value = cbor::decode(payload)?;
    let Value::Map(map) = value else {
        return Err(ErrorClass::Malformed.into());
    };
    let code = map.get(&0).ok_or(ErrorClass::Malformed)?.as_unsigned()?;
    // 3. The type is known; an unknown type in 96 to 127 is dropped.
    let Some(kind) = MessageType::from_code(code).filter(|kind| kind.known_with(extensions)) else {
        return if IGNORABLE.contains(&code) {
            Ok(None)
        } else {
            Err(ErrorClass::UnknownMessage.into())
        };
    };
    // 4. The class carries the type.
    if !kind.carried_by(class) {
        return Err(ErrorClass::Malformed.into());
    }
    // 5. Within the type's cap.
    if payload.len() > kind.cap() {
        return Err(ErrorClass::TooLarge.into());
    }
    // 6. On a member connection, no Gone and no Ephemeral with an origin;
    // on any other, no Addresses.
    if connection == ConnectionKind::Member
        && (kind == MessageType::Gone || (kind == MessageType::Ephemeral && map.contains_key(&3)))
    {
        return Err(ErrorClass::Malformed.into());
    }
    // An ErasureLate only on a connection to a peer.
    if kind == MessageType::ErasureLate && connection != ConnectionKind::DeviceToPeer {
        return Err(ErrorClass::Malformed.into());
    }
    if connection != ConnectionKind::Member && kind == MessageType::Addresses {
        return Err(ErrorClass::Malformed.into());
    }
    let message = Message {
        kind,
        map,
        bytes: payload.to_vec(),
    };
    // An ErasureLate is read whole here, as the reference reads it: exactly
    // keys 0 to 5, its fields' types and a standing of 0, 1 or 2.
    if kind == MessageType::ErasureLate && crate::messages::ErasureLate::read(&message).is_err() {
        return Err(ErrorClass::Malformed.into());
    }
    Ok(Some(message))
}

/// What [`read_frame`] found at the front of a stream's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read<'a> {
    /// Not a whole frame yet; read on. The prefix, if all 4 bytes are
    /// there, is within the class's cap.
    Incomplete,
    /// A message, and the bytes after its frame.
    Message(Message, &'a [u8]),
    /// An unknown type in 96 to 127, dropped, and the bytes after its
    /// frame.
    Dropped(&'a [u8]),
}

/// `read_frame(bytes, class, connection)`, in order (section 3.1), on the
/// front of a stream's bytes. The 4-byte prefix is checked against the
/// class's cap before anything is allocated.
///
/// # Errors
///
/// `TooLarge` for a prefix over the class's cap; then [`read_message`]'s.
pub fn read_frame<'a>(
    data: &'a [u8],
    class: StreamClass,
    connection: ConnectionKind,
    extensions: Extensions,
) -> Result<Read<'a>, TransportClass> {
    let Some((prefix, rest)) = data.split_first_chunk::<4>() else {
        return Ok(Read::Incomplete);
    };
    // 1. The prefix is at most the class's cap.
    let length = usize::try_from(u32::from_be_bytes(*prefix)).unwrap_or(usize::MAX);
    if length > class.cap() {
        return Err(ErrorClass::TooLarge.into());
    }
    if rest.len() < length {
        return Ok(Read::Incomplete);
    }
    let (payload, rest) = rest.split_at(length);
    Ok(
        match read_message(payload, class, connection, extensions)? {
            Some(message) => Read::Message(message, rest),
            None => Read::Dropped(rest),
        },
    )
}

/// A message's frame on a stream: `u32be(len(message)) || message`.
///
/// # Panics
///
/// If the message is 2^32 bytes or longer, which no class allows.
pub fn frame(message: &[u8]) -> Vec<u8> {
    frasil_base::notation::field(message)
}

/// The bytes of one stream, read frame by frame as they arrive.
///
/// [`push`](Deframer::push) appends received bytes; [`next_message`](Deframer::next_message)
/// returns each whole message in turn and drops ignorable ones. A failure
/// closes the connection with its class's code, so the deframer is not
/// used after one.
#[derive(Debug, Clone)]
pub struct Deframer {
    class: StreamClass,
    connection: ConnectionKind,
    extensions: Extensions,
    buffer: Vec<u8>,
}

impl Deframer {
    /// A deframer for a stream of this class on this kind of connection.
    pub fn new(class: StreamClass, connection: ConnectionKind, extensions: Extensions) -> Self {
        Self {
            class,
            connection,
            extensions,
            buffer: Vec::new(),
        }
    }

    /// The stream's class.
    pub fn class(&self) -> StreamClass {
        self.class
    }

    /// Bytes received and not yet read as a frame.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// Appends bytes received on the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next whole message, if one has arrived. Ignorable messages are
    /// dropped on the way.
    ///
    /// # Errors
    ///
    /// [`read_frame`]'s. The prefix of the frame in progress is checked as
    /// soon as its 4 bytes arrive.
    pub fn next_message(&mut self) -> Result<Option<Message>, TransportClass> {
        loop {
            let (found, used) =
                match read_frame(&self.buffer, self.class, self.connection, self.extensions)? {
                    Read::Incomplete => return Ok(None),
                    Read::Message(message, rest) => (Some(message), self.buffer.len() - rest.len()),
                    Read::Dropped(rest) => (None, self.buffer.len() - rest.len()),
                };
            self.buffer.drain(..used);
            if let Some(message) = found {
                return Ok(Some(message));
            }
        }
    }
}
