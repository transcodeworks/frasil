//! The six headers and how they are read (ext-app-requests.md, "Headers";
//! "Verifying", step 3).
//!
//! | Header | Value | At most | Required |
//! |---|---|---|---|
//! | `X-Frasil-Device` | `signer`, `ed \|\| kc`, 128 lower-case hex digits | 128 bytes | yes |
//! | `X-Frasil-Person-Id` | `person_id`, 64 lower-case hex digits | 64 bytes | yes |
//! | `X-Frasil-Expires` | `expires_at` in decimal | 20 bytes | yes |
//! | `X-Frasil-Nonce` | `nonce`, 32 lower-case hex digits | 32 bytes | yes |
//! | `X-Frasil-List-Heads` | 1 to 16 event IDs, ascending, comma-joined | 1,039 bytes | no |
//! | `X-Frasil-Signature` | version byte, scheme byte, signature: 132 hex digits | 132 bytes | yes |
//!
//! Header names are case-insensitive; values are taken exactly, with no
//! white space. A header present twice is `Malformed`. Every value has one
//! spelling, so a captured set of headers has no second form that verifies.

use crate::AppRequestClass;
use crate::statement::{MAX_HEADS, NONCE_BYTES, SCHEME, VERSION, decimal, heads_ok};
use frasil_base::ErrorClass;
use frasil_base::notation::hex;
use frasil_crypto::device::Signatory;
use frasil_crypto::sizes::ED25519_SIGNATURE;
use frasil_events::EventId;

/// The response header that asks the client to deliver its list.
pub const LIST_NEEDED: &str = "X-Frasil-List-Needed";
/// The value of [`LIST_NEEDED`].
pub const LIST_NEEDED_VALUE: &str = "1";

/// One of the six request headers, in the table's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Header {
    /// `X-Frasil-Device`: the signer's `ed || kc`.
    Device,
    /// `X-Frasil-Person-Id`: the person ID of the signer's list.
    PersonId,
    /// `X-Frasil-Expires`: `expires_at`, in decimal.
    Expires,
    /// `X-Frasil-Nonce`: the nonce.
    Nonce,
    /// `X-Frasil-List-Heads`: the heads; absent for none.
    ListHeads,
    /// `X-Frasil-Signature`: the version byte, the scheme byte and the
    /// signature.
    Signature,
}

impl Header {
    /// Every header, in the table's order.
    pub const ALL: [Header; 6] = [
        Header::Device,
        Header::PersonId,
        Header::Expires,
        Header::Nonce,
        Header::ListHeads,
        Header::Signature,
    ];

    /// The header's name.
    pub const fn name(self) -> &'static str {
        match self {
            Header::Device => "X-Frasil-Device",
            Header::PersonId => "X-Frasil-Person-Id",
            Header::Expires => "X-Frasil-Expires",
            Header::Nonce => "X-Frasil-Nonce",
            Header::ListHeads => "X-Frasil-List-Heads",
            Header::Signature => "X-Frasil-Signature",
        }
    }

    /// The most bytes its value has.
    pub const fn max_bytes(self) -> usize {
        match self {
            Header::Device => 128,
            Header::PersonId => 64,
            Header::Expires => 20,
            Header::Nonce => 2 * NONCE_BYTES,
            Header::ListHeads => MAX_HEADS * 64 + MAX_HEADS - 1,
            Header::Signature => 2 * (2 + ED25519_SIGNATURE),
        }
    }

    /// Whether a signed request carries it.
    pub const fn required(self) -> bool {
        !matches!(self, Header::ListHeads)
    }

    /// The header of a name, matched without regard to case.
    pub fn from_name(name: &str) -> Option<Self> {
        Header::ALL
            .into_iter()
            .find(|header| header.name().eq_ignore_ascii_case(name))
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// A header's value as received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Received<'a> {
    /// Not present.
    #[default]
    Absent,
    /// Present once, with this value.
    Once(&'a [u8]),
    /// Present more than once.
    Repeated,
}

/// The six headers of a request as received, before they are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceivedHeaders<'a> {
    values: [Received<'a>; 6],
}

impl<'a> ReceivedHeaders<'a> {
    /// None of the six headers.
    pub fn new() -> Self {
        Self::default()
    }

    /// The six headers among a request's headers, by name without regard to
    /// case. Other headers are ignored.
    pub fn from_pairs<N: AsRef<str>>(pairs: impl IntoIterator<Item = (N, &'a [u8])>) -> Self {
        let mut out = Self::new();
        for (name, value) in pairs {
            out.add(name.as_ref(), value);
        }
        out
    }

    /// Takes one header of a request. Returns whether it is one of the six;
    /// a second one of a name makes it [`Received::Repeated`].
    pub fn add(&mut self, name: &str, value: &'a [u8]) -> bool {
        let Some(header) = Header::from_name(name) else {
            return false;
        };
        let slot = &mut self.values[header.index()];
        *slot = match slot {
            Received::Absent => Received::Once(value),
            _ => Received::Repeated,
        };
        true
    }

    /// Sets what was received of one header.
    pub fn set(&mut self, header: Header, value: Received<'a>) {
        self.values[header.index()] = value;
    }

    /// What was received of one header.
    pub fn get(&self, header: Header) -> Received<'a> {
        self.values[header.index()]
    }
}

/// What the six headers carry, read and of their shapes: the values the
/// signer sets, and that the verifier reads at step 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// The signer's `ed || kc` (crypto.md, "A device's keys"): its Ed25519
    /// key, which signs, and its keys commitment. The signer's device ID is
    /// the hash of the two.
    pub signer: Signatory,
    /// The person ID of the signer's list.
    pub person_id: [u8; 32],
    /// The signer's wall clock at signing plus `signed_request_lifetime`.
    pub expires_at: u64,
    /// The nonce.
    pub nonce: [u8; NONCE_BYTES],
    /// The heads of the signer's merged list, strictly ascending; none when
    /// it has more than 16.
    pub heads: Vec<EventId>,
    /// The Ed25519 signature over the statement, which follows the version
    /// byte and the scheme byte in `X-Frasil-Signature`.
    pub signature: [u8; ED25519_SIGNATURE],
}

impl SignedHeaders {
    /// Reads the headers ("Verifying", step 3), in order:
    ///
    /// 1. If none is present, `Unsigned`.
    /// 2. In the table's order, each value present is within its "at most",
    ///    then of its shape; every required header is present and none is
    ///    repeated. Else `Malformed`.
    /// 3. The signature's version byte is `0x01`, then its scheme byte
    ///    `0x00`, each checked only at version 1's length. Else
    ///    `UnsupportedVersion`.
    ///
    /// # Errors
    ///
    /// `Unsigned`, `Malformed` or `UnsupportedVersion`.
    pub fn read(received: &ReceivedHeaders<'_>) -> Result<Self, AppRequestClass> {
        if Header::ALL
            .iter()
            .all(|&header| received.get(header) == Received::Absent)
        {
            return Err(AppRequestClass::Unsigned);
        }
        let malformed = AppRequestClass::Shared(ErrorClass::Malformed);
        let mut values: [&[u8]; 6] = [&[]; 6];
        for header in Header::ALL {
            let value = match received.get(header) {
                Received::Absent if header.required() => return Err(malformed),
                Received::Absent => continue,
                Received::Repeated => return Err(malformed),
                Received::Once(value) => value,
            };
            if value.len() > header.max_bytes() {
                return Err(malformed);
            }
            let shaped = match header {
                Header::Device | Header::PersonId | Header::Nonce | Header::Signature => {
                    lower_hex(value, header.max_bytes())
                }
                Header::Expires => decimal(value, 20).is_some_and(|n| n <= u128::from(u64::MAX)),
                Header::ListHeads => read_heads(value).is_some(),
            };
            if !shaped {
                return Err(malformed);
            }
            values[header.index()] = value;
        }
        let signature = unhex(values[Header::Signature.index()]);
        if signature[0] != VERSION || signature[1] != SCHEME {
            return Err(AppRequestClass::Shared(ErrorClass::UnsupportedVersion));
        }
        let heads = match received.get(Header::ListHeads) {
            Received::Once(value) => read_heads(value).unwrap_or_default(),
            _ => Vec::new(),
        };
        let expires = decimal(values[Header::Expires.index()], 20).unwrap_or_default();
        Ok(Self {
            signer: Signatory::from_bytes(&unhex(values[Header::Device.index()]))
                .map_err(|_| malformed)?,
            person_id: array(values[Header::PersonId.index()]),
            expires_at: u64::try_from(expires).map_err(|_| malformed)?,
            nonce: array(values[Header::Nonce.index()]),
            heads,
            signature: signature[2..].try_into().map_err(|_| malformed)?,
        })
    }

    /// One header's value as the signer sets it; `None` for
    /// `X-Frasil-List-Heads` without heads.
    pub fn value(&self, header: Header) -> Option<String> {
        Some(match header {
            Header::Device => hex::encode(self.signer.to_bytes()),
            Header::PersonId => hex::encode(self.person_id),
            Header::Expires => self.expires_at.to_string(),
            Header::Nonce => hex::encode(self.nonce),
            Header::ListHeads if self.heads.is_empty() => return None,
            Header::ListHeads => self
                .heads
                .iter()
                .map(|id| hex::encode(id.0))
                .collect::<Vec<_>>()
                .join(","),
            Header::Signature => {
                let mut bytes = vec![VERSION, SCHEME];
                bytes.extend_from_slice(&self.signature);
                hex::encode(bytes)
            }
        })
    }

    /// The headers the signer sets, by name, in the table's order.
    pub fn values(&self) -> Vec<(&'static str, String)> {
        Header::ALL
            .into_iter()
            .filter_map(|header| Some((header.name(), self.value(header)?)))
            .collect()
    }
}

/// `len` lower-case hex digits.
fn lower_hex(value: &[u8], len: usize) -> bool {
    value.len() == len && value.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The bytes of lower-case hex digits already checked.
fn unhex(value: &[u8]) -> Vec<u8> {
    let nibble = |b: u8| {
        if b.is_ascii_digit() {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    };
    value
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn array<const N: usize>(value: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&unhex(value)[..N]);
    out
}

/// `X-Frasil-List-Heads`: 1 to 16 event IDs of 64 lower-case hex digits,
/// joined by single commas, strictly ascending; `None` otherwise.
pub fn read_heads(value: &[u8]) -> Option<Vec<EventId>> {
    let parts: Vec<&[u8]> = value.split(|&b| b == b',').collect();
    if !(1..=MAX_HEADS).contains(&parts.len()) || !parts.iter().all(|p| lower_hex(p, 64)) {
        return None;
    }
    let heads: Vec<EventId> = parts.iter().map(|p| EventId(array(p))).collect();
    heads_ok(&heads).then_some(heads)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed() -> SignedHeaders {
        SignedHeaders {
            signer: Signatory::from_bytes(&[0xab; 64]).unwrap(),
            person_id: [0x01; 32],
            expires_at: 1_790_000_060,
            nonce: [0x7f; 16],
            heads: vec![EventId([1; 32]), EventId([2; 32])],
            signature: [0x55; 64],
        }
    }

    fn received(values: &[(&'static str, String)]) -> Vec<(String, Vec<u8>)> {
        values
            .iter()
            .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn values_read_back() {
        let headers = signed();
        let pairs = received(&headers.values());
        let read = ReceivedHeaders::from_pairs(pairs.iter().map(|(n, v)| (n.as_str(), &v[..])));
        assert_eq!(SignedHeaders::read(&read), Ok(headers));
        assert_eq!(
            Header::ALL.map(Header::max_bytes),
            [128, 64, 20, 32, 1039, 132]
        );
    }

    #[test]
    fn names_are_case_insensitive_and_repeats_are_malformed() {
        let headers = signed();
        let mut pairs = received(&headers.values());
        for (name, _) in &mut pairs {
            *name = name.to_ascii_lowercase();
        }
        let read = ReceivedHeaders::from_pairs(pairs.iter().map(|(n, v)| (n.as_str(), &v[..])));
        assert_eq!(SignedHeaders::read(&read), Ok(headers));
        let mut twice = read;
        assert!(twice.add("x-frasil-nonce", b"00"));
        assert!(!twice.add("content-type", b"x"));
        assert_eq!(twice.get(Header::Nonce), Received::Repeated);
        assert_eq!(
            SignedHeaders::read(&twice),
            Err(AppRequestClass::Shared(ErrorClass::Malformed))
        );
        assert_eq!(
            SignedHeaders::read(&ReceivedHeaders::new()),
            Err(AppRequestClass::Unsigned)
        );
    }

    #[test]
    fn expiries() {
        let mut headers = signed();
        headers.expires_at = u64::MAX;
        let pairs = received(&headers.values());
        let read = ReceivedHeaders::from_pairs(pairs.iter().map(|(n, v)| (n.as_str(), &v[..])));
        assert_eq!(SignedHeaders::read(&read).unwrap().expires_at, u64::MAX);
        headers.expires_at = 0;
        let pairs = received(&headers.values());
        let read = ReceivedHeaders::from_pairs(pairs.iter().map(|(n, v)| (n.as_str(), &v[..])));
        assert_eq!(SignedHeaders::read(&read).unwrap().expires_at, 0);
    }
}
