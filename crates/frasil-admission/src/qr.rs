//! The QR code (admission.md, "The QR code"): where the joiner's exchange
//! mailbox is.
//!
//! ```text
//! text = "FRASIL-ADMIT:" || base32(CBOR {1: 1, 2: ctx, 3: request (16),
//!                                        4: commitment (32), 5: location (text)})
//! ```

use crate::params::{MAX_LOCATION, REQUEST_BYTES, VERSION};
use crate::{AdmissionClass, Ctx, array_at, base32, malformed, number_at, read_map, text_ok};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};

/// The QR code text's prefix.
pub const PREFIX: &str = "FRASIL-ADMIT:";

/// What a joiner's QR code shows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdmitQr {
    /// `ctx`.
    pub ctx: Ctx,
    /// The request ID, which names the exchange mailbox.
    pub request: [u8; REQUEST_BYTES],
    /// The Request's commitment, which the approver requires the fetched
    /// Request to carry.
    pub commitment: [u8; 32],
    /// A peer's URL or a nearby endpoint, 1 to 512 bytes.
    pub location: String,
}

impl AdmitQr {
    /// The QR code's text: upper case base32 without padding, which a QR
    /// code's alphanumeric mode carries.
    pub fn text(&self) -> String {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION.into()));
        map.insert(2, Value::Unsigned(self.ctx.code().into()));
        map.insert(3, Value::from(self.request));
        map.insert(4, Value::from(self.commitment));
        map.insert(5, Value::from(self.location.as_str()));
        format!("{PREFIX}{}", base32::encode(&Value::Map(map).encode()))
    }

    /// Reads a QR code's text, in order.
    ///
    /// # Errors
    ///
    /// `Malformed` without the prefix or for base32 that does not re-encode
    /// to itself; `UnsupportedVersion` unless key 1 is 1; `Malformed` for
    /// the other keys and lengths.
    pub fn read(text: &str) -> Result<Self, AdmissionClass> {
        let body = text.strip_prefix(PREFIX).ok_or_else(malformed)?;
        let raw = base32::decode(body)?;
        let map = read_map(&raw, &[1, 2, 3, 4, 5], &[1, 2, 3, 4, 5])?;
        if map[&1] != Value::Unsigned(VERSION.into()) {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        let location = map[&5].as_text()?;
        if !text_ok(location, MAX_LOCATION) {
            return Err(malformed());
        }
        Ok(Self {
            ctx: Ctx::from_code(number_at(&map, 2)?).ok_or_else(malformed)?,
            request: array_at(&map, 3)?,
            commitment: array_at(&map, 4)?,
            location: location.to_owned(),
        })
    }
}
