//! The transcript and the code (admission.md, "Exchange values", "The
//! transcript and the code").
//!
//! ```text
//! heads_hash(log, heads)
//!            = SHA-256("frasil/admission/heads/v1" || field(log) || u16be(n)
//!                      || the n heads, ascending, 32 bytes each)
//! J_fields   = u8(ctx) || request || u64be(expires_at) || field(eph_J)
//!              || u8(joiner_type) || joiner || field(display_J)
//!   joiner_type 0, a device:  joiner = the device's device ID (crypto.md)    32 bytes
//!   joiner_type 1, a person:  joiner = person ID || heads_hash(person ID, list heads)
//! I_fields   = u8(ctx) || log || heads_hash(log, heads) || approver
//!              || field(eph_I) || field(offer) || field(display_I)
//! commitment = SHA-256("frasil/admission/commit/v1" || field(J_fields) || nonce_J)
//! code_hash  = SHA-256("frasil/admission/code/v1" || field(J_fields) || field(I_fields)
//!                      || field(channel) || nonce_J || nonce_I)
//! code       = u64 of code_hash[0..8], big-endian, mod 1,000,000, as six digits
//! ```
//!
//! A device's three public keys enter through its device ID, which commits
//! to all three, so the code authenticates the very device ID the approver
//! then grants or adds.

use crate::params::{MAX_HEADS, NONCE_BYTES, REQUEST_BYTES};
use crate::{AdmissionClass, Ctx, JoinerType, malformed, sorted_heads};
use frasil_base::notation::{push_field, u16be, u64be};
use frasil_crypto::device::DeviceId;
use frasil_crypto::labels::{ADMISSION_CODE, ADMISSION_COMMIT, ADMISSION_HEADS};
use frasil_crypto::primitives::sha256;
use frasil_crypto::sizes::XWING_PUBLIC;
use frasil_events::EventId;

/// The hash of a log's heads as one side holds them, sorted, each once.
///
/// # Errors
///
/// `Malformed` for no heads or more than 256.
pub fn heads_hash(log: &[u8; 32], heads: &[EventId]) -> Result<[u8; 32], AdmissionClass> {
    let heads = sorted_heads(heads);
    if heads.is_empty() || heads.len() > MAX_HEADS {
        return Err(malformed());
    }
    let mut input = ADMISSION_HEADS.to_vec();
    push_field(&mut input, log);
    let count = u16::try_from(heads.len()).map_err(|_| malformed())?;
    input.extend_from_slice(&u16be(count));
    for head in &heads {
        input.extend_from_slice(&head.0);
    }
    Ok(sha256(&[&input]))
}

/// `joiner` in `J_fields`: a device's device ID, or a person ID and the
/// hash of its list heads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JoinerPart {
    /// Joiner type 0: the device's device ID, 32 bytes.
    Device(DeviceId),
    /// Joiner type 1: `person ID || heads_hash(person ID, list heads)`, 64
    /// bytes, in ctx `0x02` only.
    Person {
        /// The person ID.
        person: [u8; 32],
        /// `heads_hash(person ID, list heads)`.
        heads_hash: [u8; 32],
    },
}

impl JoinerPart {
    /// The joiner's type.
    pub fn joiner_type(&self) -> JoinerType {
        match self {
            Self::Device(_) => JoinerType::Device,
            Self::Person { .. } => JoinerType::Person,
        }
    }

    /// The part's bytes.
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Device(device) => device.0.to_vec(),
            Self::Person { person, heads_hash } => [&person[..], &heads_hash[..]].concat(),
        }
    }
}

/// What the joiner commits to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JFields {
    /// `ctx`.
    pub ctx: Ctx,
    /// `request`.
    pub request: [u8; REQUEST_BYTES],
    /// `expires_at`: 0 in the setup flow.
    pub expires_at: u64,
    /// `eph_J`.
    pub eph: Box<[u8; XWING_PUBLIC]>,
    /// `joiner_type || joiner`.
    pub joiner: JoinerPart,
    /// `display_J`, as UTF-8.
    pub display: String,
}

impl JFields {
    /// `J_fields`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + REQUEST_BYTES + 8 + 4 + XWING_PUBLIC + 65 + 4);
        out.push(self.ctx.code());
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&u64be(self.expires_at));
        push_field(&mut out, &self.eph[..]);
        out.push(self.joiner.joiner_type().code());
        out.extend_from_slice(&self.joiner.bytes());
        push_field(&mut out, self.display.as_bytes());
        out
    }
}

/// What the approver answers with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IFields {
    /// `ctx`.
    pub ctx: Ctx,
    /// `log`: the space ID, or for ctx `0x01` the person ID.
    pub log: [u8; 32],
    /// `heads_hash(log, heads)`.
    pub heads_hash: [u8; 32],
    /// `approver`: I's device ID.
    pub approver: DeviceId,
    /// `eph_I`.
    pub eph: Box<[u8; XWING_PUBLIC]>,
    /// The offer's bytes; empty for ctx `0x01`.
    pub offer: Vec<u8>,
    /// `display_I`, as UTF-8.
    pub display: String,
}

impl IFields {
    /// `I_fields`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 96 + 4 + XWING_PUBLIC + self.offer.len() + 8);
        out.push(self.ctx.code());
        out.extend_from_slice(&self.log);
        out.extend_from_slice(&self.heads_hash);
        out.extend_from_slice(&self.approver.0);
        push_field(&mut out, &self.eph[..]);
        push_field(&mut out, &self.offer);
        push_field(&mut out, self.display.as_bytes());
        out
    }
}

/// The joiner's commitment to `J_fields` and `nonce_J`.
pub fn commitment(j_fields: &[u8], nonce_j: &[u8; NONCE_BYTES]) -> [u8; 32] {
    let mut input = ADMISSION_COMMIT.to_vec();
    push_field(&mut input, j_fields);
    input.extend_from_slice(nonce_j);
    sha256(&[&input])
}

/// The code hash. `channel` is the direct connection's channel value, or
/// empty through a mailbox.
pub fn code_hash(
    j_fields: &[u8],
    i_fields: &[u8],
    channel: &[u8],
    nonce_j: &[u8; NONCE_BYTES],
    nonce_i: &[u8; NONCE_BYTES],
) -> [u8; 32] {
    let mut input = ADMISSION_CODE.to_vec();
    push_field(&mut input, j_fields);
    push_field(&mut input, i_fields);
    push_field(&mut input, channel);
    input.extend_from_slice(nonce_j);
    input.extend_from_slice(nonce_i);
    sha256(&[&input])
}

/// The six-digit code both people compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Code(u32);

impl Code {
    /// The code of a code hash: its first 8 bytes as a big-endian u64,
    /// modulo 1,000,000.
    pub fn of(code_hash: &[u8; 32]) -> Self {
        let mut first = [0; 8];
        first.copy_from_slice(&code_hash[..8]);
        Self((u64::from_be_bytes(first) % 1_000_000) as u32)
    }

    /// The code as a number below 1,000,000.
    pub fn value(self) -> u32 {
        self.0
    }

    /// The code as a client shows it: two groups of three digits, such as
    /// `052 972`.
    pub fn grouped(self) -> String {
        let digits = self.to_string();
        format!("{} {}", &digits[..3], &digits[3..])
    }
}

impl core::fmt::Display for Code {
    /// The six digits, leading zeros included.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_keeps_its_leading_zeros() {
        let mut hash = [0u8; 32];
        hash[7] = 5;
        assert_eq!(Code::of(&hash).to_string(), "000005");
        assert_eq!(Code::of(&hash).grouped(), "000 005");
    }

    #[test]
    fn heads_hash_counts_each_head_once() {
        let log = [7; 32];
        let a = EventId([1; 32]);
        let b = EventId([2; 32]);
        assert_eq!(
            heads_hash(&log, &[b, a, a]).unwrap(),
            heads_hash(&log, &[a, b]).unwrap()
        );
        assert!(heads_hash(&log, &[]).is_err());
    }
}
