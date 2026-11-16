//! Exchange messages and the seal of their bodies (admission.md,
//! "Messages", "The seal").
//!
//! ```text
//! message     = u8(1) || u8(type) || request (16) || body
//! sealed body = 0x01 || u16be(0x647a) || enc (1,120) || ciphertext
//! (enc, ciphertext) = HPKE-Seal(recipient's X-Wing key,
//!                               info = "frasil/admission/seal/v1" || u16be(0x647a)
//!                                      || request || u8(type),
//!                               aad = "", plaintext)
//! ```

use crate::params::{MAX_MESSAGE, MAX_REQUEST_MESSAGE, REQUEST_BYTES, VERSION};
use crate::{AdmissionClass, malformed};
use frasil_base::ErrorClass;
use frasil_crypto::sizes::XWING_SEED;
use frasil_crypto::wrap::{ENCAPSULATION_RANDOMNESS, WrapUse, open_wrap, seal_wrap_with};
use zeroize::Zeroizing;

/// A message's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MessageType {
    /// 1, from J, in the clear.
    Request,
    /// 2, from I, sealed to `eph_J`.
    Response,
    /// 3, from J, sealed to `eph_I`.
    Reveal,
    /// 4, from J, a person joiner, sealed to `eph_I`.
    List,
    /// 5, from I, sealed to `eph_J`.
    Result,
    /// 6, from either, empty.
    Cancel,
    /// 7, from a person's device, sealed to the approver's X-Wing key.
    Join,
    /// 8, from a headless device, in the clear.
    Hello,
    /// 9, from I in the setup flow, sealed to `eph_J`.
    Offer,
    /// 10, from I after a ctx `0x01` Result on a direct connection, sealed
    /// to `eph_J`.
    Welcome,
}

impl MessageType {
    /// Every type, in code order.
    pub const ALL: [MessageType; 10] = [
        Self::Request,
        Self::Response,
        Self::Reveal,
        Self::List,
        Self::Result,
        Self::Cancel,
        Self::Join,
        Self::Hello,
        Self::Offer,
        Self::Welcome,
    ];

    /// The type's code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
            Self::Reveal => 3,
            Self::List => 4,
            Self::Result => 5,
            Self::Cancel => 6,
            Self::Join => 7,
            Self::Hello => 8,
            Self::Offer => 9,
            Self::Welcome => 10,
        }
    }

    /// The type of a code.
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.code() == code)
    }

    /// The type's name, as the table writes it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Request => "Request",
            Self::Response => "Response",
            Self::Reveal => "Reveal",
            Self::List => "List",
            Self::Result => "Result",
            Self::Cancel => "Cancel",
            Self::Join => "Join",
            Self::Hello => "Hello",
            Self::Offer => "Offer",
            Self::Welcome => "Welcome",
        }
    }

    /// The most bytes a message of this type has: 4,096 for a Request and a
    /// Cancel, 262,144 otherwise.
    pub const fn limit(self) -> usize {
        match self {
            Self::Request | Self::Cancel => MAX_REQUEST_MESSAGE,
            _ => MAX_MESSAGE,
        }
    }
}

/// A message, read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    /// Its type.
    pub kind: MessageType,
    /// `request`: the exchange's ID, or a Join's reference.
    pub request: [u8; REQUEST_BYTES],
    /// The body: in the clear, sealed, or empty for a Cancel.
    pub body: &'a [u8],
}

/// A message's bytes.
pub fn message(kind: MessageType, request: &[u8; REQUEST_BYTES], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + REQUEST_BYTES + body.len());
    out.push(VERSION);
    out.push(kind.code());
    out.extend_from_slice(request);
    out.extend_from_slice(body);
    out
}

/// Reads a message, in order, as a peer and both sides read one.
///
/// # Errors
///
/// `Malformed` for no byte; `UnsupportedVersion` unless byte 0 is 1;
/// `Malformed` for fewer than 18 bytes or an unknown type; `TooLarge` over
/// the type's limit; `Malformed` for a Cancel with a body.
pub fn read_message(data: &[u8]) -> Result<Message<'_>, AdmissionClass> {
    let (&version, _) = data.split_first().ok_or_else(malformed)?;
    if version != VERSION {
        return Err(ErrorClass::UnsupportedVersion.into());
    }
    if data.len() < 2 + REQUEST_BYTES {
        return Err(malformed());
    }
    let kind = MessageType::from_code(data[1]).ok_or_else(malformed)?;
    if data.len() > kind.limit() {
        return Err(ErrorClass::TooLarge.into());
    }
    let body = &data[2 + REQUEST_BYTES..];
    if kind == MessageType::Cancel && !body.is_empty() {
        return Err(malformed());
    }
    let mut request = [0; REQUEST_BYTES];
    request.copy_from_slice(&data[2..2 + REQUEST_BYTES]);
    Ok(Message {
        kind,
        request,
        body,
    })
}

/// The seal's `info`: the label, the suite, then the request and the
/// message type.
pub fn seal_info(request: &[u8; REQUEST_BYTES], kind: MessageType) -> Vec<u8> {
    let mut binds = request.to_vec();
    binds.push(kind.code());
    WrapUse::ExchangeMessage.info(&binds)
}

/// Seals a body to the recipient's X-Wing key, with X-Wing's 64 bytes of
/// encapsulation randomness given.
///
/// # Errors
///
/// `InvalidKey` for a key X-Wing refuses.
pub fn seal_body_with(
    kind: MessageType,
    request: &[u8; REQUEST_BYTES],
    recipient: &[u8],
    plaintext: &[u8],
    encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<Vec<u8>, AdmissionClass> {
    Ok(seal_wrap_with(
        recipient,
        &seal_info(request, kind),
        plaintext,
        encapsulation_randomness,
    )?)
}

/// A whole message whose body is sealed, as [`seal_body_with`].
///
/// # Errors
///
/// As [`seal_body_with`].
pub fn sealed_message_with(
    kind: MessageType,
    request: &[u8; REQUEST_BYTES],
    recipient: &[u8],
    plaintext: &[u8],
    encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<Vec<u8>, AdmissionClass> {
    let body = seal_body_with(
        kind,
        request,
        recipient,
        plaintext,
        encapsulation_randomness,
    )?;
    Ok(message(kind, request, &body))
}

/// Opens a sealed body by crypto.md's "Opening a wrap", with step 5
/// requiring at least 1,139 bytes.
///
/// # Errors
///
/// `Malformed` or `UnsupportedVersion` for its layout, then `Decrypt`.
pub fn open_body(
    kind: MessageType,
    request: &[u8; REQUEST_BYTES],
    seed: &[u8; XWING_SEED],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AdmissionClass> {
    Ok(open_wrap(
        body,
        seed,
        &seal_info(request, kind),
        WrapUse::ExchangeMessage.length(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_in_order() {
        let r = [9; 16];
        assert_eq!(read_message(&[]), Err(malformed()));
        assert_eq!(
            read_message(&[2]),
            Err(ErrorClass::UnsupportedVersion.into())
        );
        assert_eq!(read_message(&[1, 1]), Err(malformed()));
        assert_eq!(
            read_message(&message(MessageType::Cancel, &r, b"x")),
            Err(malformed())
        );
        let mut unknown = message(MessageType::Cancel, &r, b"");
        unknown[1] = 11;
        assert_eq!(read_message(&unknown), Err(malformed()));
        assert_eq!(
            read_message(&message(MessageType::Request, &r, &[0; 4096])),
            Err(ErrorClass::TooLarge.into())
        );
        let ok = message(MessageType::Cancel, &r, b"");
        assert_eq!(read_message(&ok).unwrap().kind, MessageType::Cancel);
    }
}
