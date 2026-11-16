//! Codes (transport.md, section 2.5), services and rights (sections 3.10
//! and 3.11).
//!
//! One table of codes serves QUIC application close codes, WebSocket close
//! codes (4000 plus the code), `Refuse` and `Detach`. Each name but `done`
//! and `reconnect` is an error class in snake case.

use crate::TransportClass;
use frasil_base::ErrorClass;

macro_rules! codes {
    ($( $(#[$doc:meta])* $variant:ident = $code:literal, $name:literal; )*) => {
        /// A code of section 2.5's table.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Code {
            $( $(#[$doc])* $variant, )*
        }

        impl Code {
            /// Every code, in the table's order.
            pub const ALL: &'static [Code] = &[ $( Code::$variant, )* ];

            /// The code's number.
            pub const fn number(self) -> u64 {
                match self {
                    $( Self::$variant => $code, )*
                }
            }

            /// The code's name, in snake case.
            pub const fn name(self) -> &'static str {
                match self {
                    $( Self::$variant => $name, )*
                }
            }

            /// The code of a number.
            pub const fn from_number(number: u64) -> Option<Self> {
                match number {
                    $( $code => Some(Self::$variant), )*
                    _ => None,
                }
            }

            /// The code of a name.
            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    $( $name => Some(Self::$variant), )*
                    _ => None,
                }
            }
        }
    };
}

codes! {
    /// A normal close; an attach no longer wanted.
    Done = 0, "done";
    /// A frame or message that does not read.
    Malformed = 1, "malformed";
    /// Over a cap.
    TooLarge = 2, "too_large";
    /// Another protocol.
    UnsupportedVersion = 3, "unsupported_version";
    /// No offered state matched.
    NoCommonState = 4, "no_common_state";
    /// An answer that does not verify.
    BadProof = 5, "bad_proof";
    /// An `Identify` that does not verify.
    BadSignature = 6, "bad_signature";
    /// The device is out of the verifier's view.
    MembershipEnded = 7, "membership_ended";
    /// Probation ended without the device.
    UnknownMember = 8, "unknown_member";
    /// `handshake_deadline` passed.
    Timeout = 9, "timeout";
    /// An attach number of 1,024 or more.
    AttachLimit = 10, "attach_limit";
    /// The responder's budget or rate limit.
    Busy = 11, "busy";
    /// Section 3.10's purpose rules.
    PurposeViolation = 12, "purpose_violation";
    /// A credential refused, or a message with no right.
    CredentialRefused = 13, "credential_refused";
    /// A key crypto.md refuses.
    InvalidKey = 14, "invalid_key";
    /// The device forked its chain in the space.
    Forked = 15, "forked";
    /// The other end runs another revision.
    RevisionMismatch = 16, "revision_mismatch";
    /// A peer's close that asks the device to connect again to the same
    /// peer, after a random wait; not an error (section 3.10,
    /// "Reconnecting elsewhere").
    Reconnect = 17, "reconnect";
}

impl Code {
    /// The error class the code names; `done` and `reconnect` name none.
    pub fn class(self) -> Option<TransportClass> {
        Some(match self {
            Self::Done | Self::Reconnect => return None,
            Self::Malformed => ErrorClass::Malformed.into(),
            Self::TooLarge => ErrorClass::TooLarge.into(),
            Self::UnsupportedVersion => ErrorClass::UnsupportedVersion.into(),
            Self::NoCommonState => TransportClass::NoCommonState,
            Self::BadProof => TransportClass::BadProof,
            Self::BadSignature => ErrorClass::BadSignature.into(),
            Self::MembershipEnded => TransportClass::MembershipEnded,
            Self::UnknownMember => TransportClass::UnknownMember,
            Self::Timeout => TransportClass::Timeout,
            Self::AttachLimit => TransportClass::AttachLimit,
            Self::Busy => TransportClass::Busy,
            Self::PurposeViolation => TransportClass::PurposeViolation,
            Self::CredentialRefused => TransportClass::CredentialRefused,
            Self::InvalidKey => ErrorClass::InvalidKey.into(),
            Self::Forked => ErrorClass::Forked.into(),
            Self::RevisionMismatch => ErrorClass::RevisionMismatch.into(),
        })
    }

    /// The WebSocket close code: 4000 plus the code (section 3.15).
    pub const fn websocket(self) -> u16 {
        4000 + self.number() as u16
    }

    /// The code of a WebSocket close code, 4000 to 4017.
    pub fn from_websocket(close: u16) -> Option<Self> {
        close
            .checked_sub(4000)
            .and_then(|n| Self::from_number(n.into()))
    }
}

/// The reason codes transport.md raises, with their HTTP statuses (section
/// 2.5). A reason code is the `code` of a `Refused` message, or the body
/// `{"code": "<reason>"}` of an HTTP error.
pub const REASONS: [(&str, u16); 11] = [
    ("malformed", 400),
    ("revision_mismatch", 400),
    ("unauthenticated", 401),
    ("credential_refused", 403),
    ("purpose_violation", 403),
    ("not_found", 404),
    ("too_large", 413),
    ("invalid_key", 422),
    ("bad_signature", 422),
    ("rate_limited", 429),
    ("busy", 503),
];

/// The HTTP status of one of [`REASONS`].
pub fn reason_status(reason: &str) -> Option<u16> {
    REASONS
        .iter()
        .find(|(name, _)| *name == reason)
        .map(|&(_, status)| status)
}

/// The HTTP status of a request to the connect route that is not a
/// WebSocket upgrade.
pub const UPGRADE_REQUIRED: u16 = 426;

/// A service a peer lists in `PeerHello` (section 3.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Service {
    /// 1: live delivery.
    Relay,
    /// 2: storage.
    Store,
    /// 3: mailboxes.
    Mailbox,
    /// 4: the account service.
    Account,
    /// 5: ext-libraries.md's library; a peer that does not implement that
    /// extension never lists it.
    Library,
    /// 6: ext-deposit-tokens.md's deposit; a peer that does not implement
    /// that extension never lists it.
    Deposit,
}

impl Service {
    /// Every service, in code order.
    pub const ALL: [Service; 6] = [
        Self::Relay,
        Self::Store,
        Self::Mailbox,
        Self::Account,
        Self::Library,
        Self::Deposit,
    ];

    /// The service's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Relay => 1,
            Self::Store => 2,
            Self::Mailbox => 3,
            Self::Account => 4,
            Self::Library => 5,
            Self::Deposit => 6,
        }
    }

    /// The service's name, as the discovery document writes it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Store => "store",
            Self::Mailbox => "mailbox",
            Self::Account => "account",
            Self::Library => "library",
            Self::Deposit => "deposit",
        }
    }

    /// The service of a code.
    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.code() == code)
    }
}

/// A right a `Granted` carries (section 3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Right {
    /// 1: fetching the space's events and objects.
    Fetch,
    /// 2: live delivery of the space's new events.
    Live,
    /// 3: storing events and object chunks.
    Store,
    /// 4: release and restore.
    Release,
    /// 5: storing an administrator pseudonym's skeleton events and
    /// acknowledgements.
    Erase,
    /// 6: fetching only what peers.md's catch-up allows.
    CatchUp,
}

impl Right {
    /// Every right, in code order.
    pub const ALL: [Right; 6] = [
        Self::Fetch,
        Self::Live,
        Self::Store,
        Self::Release,
        Self::Erase,
        Self::CatchUp,
    ];

    /// The right's code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Fetch => 1,
            Self::Live => 2,
            Self::Store => 3,
            Self::Release => 4,
            Self::Erase => 5,
            Self::CatchUp => 6,
        }
    }

    /// The right's name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Live => "live",
            Self::Store => "store",
            Self::Release => "release",
            Self::Erase => "erase",
            Self::CatchUp => "catch-up",
        }
    }

    /// The right of a code.
    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.code() == code)
    }

    /// The rights peers.md granted, in code order, as `Granted` lists them.
    pub fn of(rights: frasil_peers::entries::Rights) -> Vec<Right> {
        [
            (rights.fetch, Self::Fetch),
            (rights.live, Self::Live),
            (rights.store, Self::Store),
            (rights.release, Self::Release),
            (rights.erase, Self::Erase),
            (rights.catch_up, Self::CatchUp),
        ]
        .into_iter()
        .filter_map(|(held, right)| held.then_some(right))
        .collect()
    }
}
