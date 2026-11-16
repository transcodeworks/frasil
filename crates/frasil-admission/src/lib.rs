//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's admission: the admission code and its exchange, the setup code,
//! the welcome, the newcomer's snapshot keys and top-ups, lookups and access
//! requests.
//!
//! Specified by `docs/spec/admission.md`. Its vectors are
//! `docs/spec/vectors/admission.json`.
//!
//! The formats:
//! - [`transcript`]: `heads_hash`, `J_fields`, `I_fields`,
//!   the commitment, the code hash and the six-digit code (admission.md,
//!   "Exchange values", "The transcript and the code");
//! - [`offer`]: the offer ("The offer");
//! - [`message`]: exchange messages, reading them, and the seal of their
//!   bodies ("Messages", "The seal");
//! - [`bodies`]: each message's body ("Bodies");
//! - [`qr`]: the joiner's QR code ("The QR code");
//! - [`welcome`]: the welcome and the sealed welcome ("The welcome");
//! - [`lookup`]: the lookup prompt and the Join ("The lookup prompt and the
//!   Join", "Lookups");
//! - [`access`]: the access request and its checks ("The access request",
//!   "Access requests").
//!
//! The procedures, each a value or a state machine that takes bytes in and
//! gives bytes out:
//! - [`joiner`]: the joiner ("The joiner");
//! - [`approver`]: the approver ("The approver");
//! - [`grant`]: the grant the approver signs, and the joiner's checks of it
//!   ("Accepting a grant");
//! - [`new_device`]: a person's new device, and a person that joins a space
//!   ("A person's new device", "A person that joins a space");
//! - [`setup`]: the setup code, the Hello, the Offer and a headless device
//!   ("The setup code", "Setup");
//! - [`mailbox`]: a peer's exchange mailboxes ("Exchange mailboxes");
//! - [`snapshot`]: the body keys a newcomer's snapshot carries, the top-up
//!   set and the writers' rank for a top-up ("The newcomer's snapshot",
//!   "Top-ups").
//!
//! The crate reads no clock, does no IO and draws no randomness: every wall
//! clock reading comes in as an argument, and every random draw (request
//! IDs, nonces, ephemeral X-Wing seeds, setup secrets and X-Wing's
//! encapsulation randomness) has a `_with` form that takes its bytes. A
//! caller draws them with `frasil_crypto::random_bytes`.

pub mod access;
pub mod approver;
mod base32;
pub mod bodies;
#[cfg(feature = "ext-guests")]
pub mod ext_guests;
#[cfg(feature = "ext-invite-links")]
pub mod ext_invite_links;
pub mod grant;
pub mod joiner;
pub mod lookup;
pub mod mailbox;
pub mod message;
pub mod new_device;
pub mod offer;
pub mod qr;
pub mod setup;
pub mod snapshot;
pub mod transcript;
pub mod welcome;

pub use approver::Approver;
pub use joiner::Joiner;
pub use message::{Message, MessageType};
pub use offer::Offer;
pub use transcript::Code;

use frasil_base::cbor::{KeyRules, Map, UnknownKeys, Value};
use frasil_base::errors::Class;
use frasil_events::EventId;

frasil_base::error_classes! {
    /// The error classes of admission.md ("Error classes"), with every
    /// shared class. Each is a decision.
    pub enum AdmissionClass {
        /// A Reveal that does not open the Request's commitment.
        CommitmentMismatch = "commitment_mismatch", Decision;
        /// The person says the codes differ.
        Mismatch = "mismatch", Decision;
        /// A person joiner's list that is not a valid list.
        BadList = "bad_list", Decision;
        /// A person joiner's list that is not the committed one.
        ListMismatch = "list_mismatch", Decision;
        /// A grant or `add` by another approver than the code authenticated.
        WrongApprover = "wrong_approver", Decision;
        /// A grant in another space than the code authenticated.
        WrongSpace = "wrong_space", Decision;
        /// A grant or `add` that does not follow the authenticated heads.
        NotFollowing = "not_following", Decision;
        /// A grant or `add` of another member than the code authenticated.
        WrongMember = "wrong_member", Decision;
        /// A grant other than the offer the code authenticated.
        OfferMismatch = "offer_mismatch", Decision;
        /// A ctx 0x01 Result for another person.
        WrongPerson = "wrong_person", Decision;
        /// A ctx 0x01 Result whose `add` is not valid.
        NotInList = "not_in_list", Decision;
        /// A peer's refusal: an exchange mailbox already has this request ID.
        MailboxInUse = "mailbox_in_use", Decision;
        /// A peer's refusal: no exchange mailbox has this request ID.
        UnknownMailbox = "unknown_mailbox", Decision;
        /// A peer's refusal: the exchange mailbox holds a message of this
        /// type.
        Duplicate = "duplicate", Decision;
        /// A peer's refusal: a message before the one it follows.
        OutOfOrder = "out_of_order", Decision;
        /// A peer's refusal: the exchange was cancelled.
        Cancelled = "cancelled", Decision;
        /// A peer's refusal: the source opened too many exchange mailboxes.
        RateLimited = "rate_limited", Decision;
        /// A peer's refusal: it holds too many exchange mailboxes or bytes.
        MailboxFull = "mailbox_full", Decision;
        /// A Hello whose keys are not the ones the setup code names.
        SetupMismatch = "setup_mismatch", Decision;
        /// An Offer whose MAC does not verify.
        BadMac = "bad_mac", Decision;
        /// A device already provisioned, or bound to another Offer.
        Provisioned = "provisioned", Decision;
    }
}

impl AdmissionClass {
    /// The class another document's procedure failed with, by its name:
    /// its shared class, or `Malformed` for a class of that document's
    /// own, which no admission procedure reports as itself.
    pub fn of(class: impl Class) -> Self {
        Self::from_name(class.name()).unwrap_or_else(malformed)
    }

    /// A peer's reason code and HTTP status for its refusal of an exchange
    /// message (admission.md, "Error classes"), if the class has one.
    pub fn reason(self) -> Option<(&'static str, u16)> {
        use frasil_base::ErrorClass as E;
        Some(match self {
            Self::Shared(E::Malformed) => ("malformed", 400),
            Self::MailboxInUse => ("mailbox_in_use", 409),
            Self::UnknownMailbox => ("unknown_mailbox", 404),
            Self::Shared(E::Expired) => ("expired", 410),
            Self::Cancelled => ("cancelled", 410),
            Self::Duplicate => ("duplicate", 409),
            Self::OutOfOrder => ("out_of_order", 409),
            Self::RateLimited => ("rate_limited", 429),
            Self::MailboxFull => ("mailbox_full", 503),
            _ => return None,
        })
    }
}

pub(crate) fn malformed() -> AdmissionClass {
    AdmissionClass::Shared(frasil_base::ErrorClass::Malformed)
}

/// The values of admission.md's tables.
pub mod params {
    /// The exchange's format version: byte 0 of every message, key 1 of
    /// every versioned map.
    pub const VERSION: u8 = 1;
    /// A request ID, a prompt's reference, an access request's ID.
    pub const REQUEST_BYTES: usize = 16;
    /// A nonce, `nonce_J` or `nonce_I`.
    pub const NONCE_BYTES: usize = 32;
    /// A display, `display_J` or `display_I`, at most.
    pub const MAX_DISPLAY: usize = 256;
    /// Heads in a Response, a Reveal or an Offer, at most.
    pub const MAX_HEADS: usize = 256;
    /// Peer hints in a welcome or a prompt, at most.
    pub const MAX_HINTS: usize = 8;
    /// A QR code's location and a peer hint, at most.
    pub const MAX_LOCATION: usize = 512;
    /// A setup secret.
    pub const SETUP_SECRET_BYTES: usize = 16;
    /// A setup tag.
    pub const SETUP_TAG_BYTES: usize = 8;
    /// A setup code: the version, the device ID and the setup secret.
    pub const SETUP_CODE_BYTES: usize = 1 + 32 + SETUP_SECRET_BYTES;
    /// A Request or a Cancel message, at most.
    pub const MAX_REQUEST_MESSAGE: usize = 4096;
    /// Any other message, at most.
    pub const MAX_MESSAGE: usize = 262_144;
    /// `admission_code_lifetime` (overview.md, "Every timer").
    pub const ADMISSION_CODE_LIFETIME: u64 = 900;
    /// `admission_code_skew` (overview.md, "Every timer").
    pub const ADMISSION_CODE_SKEW: u64 = 60;
    /// What `exchange_mailbox_lifetime` and the approver's memory of an
    /// answered request add to `expires_at`.
    pub const MAILBOX_GRACE: u64 = 60;
    /// Exchange mailboxes one source opens in a minute, fewer than this.
    pub const MAILBOX_NEW_PER_MINUTE: usize = 10;
    /// Exchange mailboxes one source holds open, fewer than this.
    pub const MAILBOX_OPEN_PER_SOURCE: usize = 128;
    /// Exchange mailboxes a peer holds, fewer than this.
    pub const MAILBOX_PER_PEER: usize = 65_536;
    /// Bytes a peer's exchange mailboxes hold in all, under this.
    pub const MAILBOX_BYTES_PER_PEER: usize = 256 * 1024 * 1024;
    /// A sealed body's or a sealed welcome's least length: crypto.md's
    /// wrap of an empty plaintext.
    pub const SEALED_MINIMUM: usize = frasil_crypto::wrap::MIN_WRAP;
}

/// What an exchange is for: `ctx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ctx {
    /// `0x01`: joining a person's device list.
    DeviceList,
    /// `0x02`: joining a space.
    Space,
}

impl Ctx {
    /// The byte.
    pub const fn code(self) -> u8 {
        match self {
            Self::DeviceList => 0x01,
            Self::Space => 0x02,
        }
    }

    /// The context of a byte or number.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0x01 => Some(Self::DeviceList),
            0x02 => Some(Self::Space),
            _ => None,
        }
    }
}

/// What joins: `joiner_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum JoinerType {
    /// 0: a device.
    Device,
    /// 1: a person, in ctx `0x02` only.
    Person,
}

impl JoinerType {
    /// The code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Device => 0,
            Self::Person => 1,
        }
    }

    /// The type of a code.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Device),
            1 => Some(Self::Person),
            _ => None,
        }
    }
}

/// Reads a deterministic CBOR map whose keys are among `allowed` and include
/// every one of `required`; anything else is `Malformed`.
pub(crate) fn read_map(
    data: &[u8],
    allowed: &[u64],
    required: &[u64],
) -> Result<Map, AdmissionClass> {
    let value = frasil_base::cbor::decode(data)?;
    let Value::Map(map) = value else {
        return Err(malformed());
    };
    KeyRules {
        required,
        optional: allowed,
        unknown: UnknownKeys::Malformed,
    }
    .check(&map)?;
    Ok(map)
}

/// The bytes of a map's key the caller knows is present.
pub(crate) fn bytes_at(map: &Map, key: u64) -> Result<&[u8], AdmissionClass> {
    Ok(map.get(&key).ok_or_else(malformed)?.as_bytes()?)
}

/// The bytes of a map's key, of exactly `N` bytes.
pub(crate) fn array_at<const N: usize>(map: &Map, key: u64) -> Result<[u8; N], AdmissionClass> {
    Ok(map.get(&key).ok_or_else(malformed)?.as_byte_array::<N>()?)
}

/// The boxed bytes of a map's key, of exactly `N` bytes.
pub(crate) fn boxed_at<const N: usize>(
    map: &Map,
    key: u64,
) -> Result<Box<[u8; N]>, AdmissionClass> {
    let bytes = bytes_at(map, key)?;
    let array: Box<[u8; N]> = bytes
        .to_vec()
        .into_boxed_slice()
        .try_into()
        .map_err(|_| malformed())?;
    Ok(array)
}

/// The unsigned number of a map's key.
pub(crate) fn number_at(map: &Map, key: u64) -> Result<u64, AdmissionClass> {
    Ok(map.get(&key).ok_or_else(malformed)?.as_unsigned()?)
}

/// The display at a map's key: text of at most 256 bytes.
pub(crate) fn display_at(map: &Map, key: u64) -> Result<String, AdmissionClass> {
    let text = map.get(&key).ok_or_else(malformed)?.as_text()?;
    if !display_ok(text) {
        return Err(malformed());
    }
    Ok(text.to_owned())
}

/// A display: at most 256 bytes of UTF-8.
pub(crate) fn display_ok(text: &str) -> bool {
    text.len() <= params::MAX_DISPLAY
}

/// A text of 1 to `max` bytes with no control character, and not only white
/// space: a location or a peer hint.
pub(crate) use frasil_base::notation::text_ok;

/// Heads, as a body carries them: 1 to 256 event IDs, strictly ascending.
pub(crate) fn read_heads(value: &Value) -> Result<Vec<EventId>, AdmissionClass> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > params::MAX_HEADS {
        return Err(malformed());
    }
    let heads = items
        .iter()
        .map(|item| Ok(EventId(item.as_byte_array::<32>()?)))
        .collect::<Result<Vec<_>, AdmissionClass>>()?;
    if heads.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(malformed());
    }
    Ok(heads)
}

/// Heads sorted, each once.
pub(crate) fn sorted_heads(heads: &[EventId]) -> Vec<EventId> {
    let mut sorted = heads.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted
}

/// Heads as a body writes them: sorted, each once.
pub(crate) fn heads_value(heads: &[EventId]) -> Value {
    Value::Array(
        sorted_heads(heads)
            .into_iter()
            .map(|id| Value::from(id.0))
            .collect(),
    )
}

/// Peer hints: 0 to 8 texts of 1 to 512 bytes.
pub(crate) fn read_hints(value: &Value) -> Result<Vec<String>, AdmissionClass> {
    let items = value.as_array()?;
    if items.len() > params::MAX_HINTS {
        return Err(malformed());
    }
    items
        .iter()
        .map(|item| {
            let text = item.as_text()?;
            if text_ok(text, params::MAX_LOCATION) {
                Ok(text.to_owned())
            } else {
                Err(malformed())
            }
        })
        .collect()
}

/// Peer hints as a map writes them.
pub(crate) fn hints_value(hints: &[String]) -> Value {
    Value::Array(hints.iter().map(|h| Value::from(h.as_str())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::snake_case;
    use frasil_base::time::Timer;

    #[test]
    fn wire_names_are_snake_case() {
        for class in AdmissionClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
        }
    }

    #[test]
    fn timers_are_overview_md_s() {
        assert_eq!(
            Timer::AdmissionCodeLifetime.spec().default,
            Some(params::ADMISSION_CODE_LIFETIME)
        );
        assert_eq!(
            Timer::AdmissionCodeSkew.spec().default,
            Some(params::ADMISSION_CODE_SKEW)
        );
    }

    #[test]
    fn texts() {
        assert!(text_ok("a", 1));
        assert!(!text_ok("", 4));
        assert!(!text_ok("  ", 4));
        assert!(!text_ok("a\n", 4));
        assert!(display_ok(""));
    }
}

/// Signed requests for a welcome from an existing member.
pub mod welcome_request;
