//! What the admission.json tests share: the file, hex helpers, and the
//! reference's fixed inputs (`docs/spec/reference/admission.py`), each a
//! hash of a description, so no value is magic.

#![allow(dead_code)]

pub mod history;

use frasil_admission::AdmissionClass;
use frasil_admission::approver::{ApproverSide, ResponseDraw};
use frasil_admission::joiner::{JoinerKeys, JoinerStart};
use frasil_admission::{Ctx, Joiner};
use frasil_base::errors::Class;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_crypto::fixtures::fixture_mldsa_seed;
use frasil_crypto::primitives::sha256;
use frasil_crypto::schemes::Signer;
use frasil_crypto::sizes::XWING_PUBLIC;
use frasil_crypto::wrap::xwing_public;
use frasil_events::EventId;
use frasil_testkit::hex;
use serde_json::Value as Json;
use zeroize::Zeroizing;

pub const FILE: &str = "admission.json";

/// The reference's instants: the Request, the Response, the Reveal, and
/// `expires_at`.
pub const T_REQUEST: u64 = 1_760_000_100;
pub const T_RESPONSE: u64 = 1_760_000_110;
pub const T_REVEAL: u64 = 1_760_000_120;
pub const T_EXPIRES: u64 = 1_760_000_900;

pub fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

pub fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex")
}

pub fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

pub fn text(value: &Json) -> &str {
    value.as_str().expect("text")
}

pub fn h(value: impl AsRef<[u8]>) -> String {
    hex::encode(value.as_ref())
}

/// `example(name)`: SHA-256 of `"frasil spec example/" || name`.
pub fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// The first 16 bytes of an example.
pub fn example16(name: &str) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(&example(name)[..16]);
    out
}

/// 64 bytes of X-Wing encapsulation randomness, fixed for the vectors:
/// `example(label/1) || example(label/2)`.
pub fn eseed(label: &str) -> [u8; 64] {
    let mut out = [0; 64];
    out[..32].copy_from_slice(&example(&format!("{label}/1")));
    out[32..].copy_from_slice(&example(&format!("{label}/2")));
    out
}

/// The class name of a failed result, or `accepted`.
pub fn verdict<T, C: Class>(result: Result<T, C>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(class) => class.name(),
    }
}

/// A signer from an Ed25519 seed and the fixture ML-DSA-65 seed crypto.md
/// derives from it, with the X-Wing key of `xwing_seed`.
pub fn signer(seed: &[u8; 32], xwing_seed: &[u8; 32]) -> Signer {
    Signer::from_seeds(
        seed,
        &fixture_mldsa_seed(seed),
        Some(&xwing_public(xwing_seed)),
    )
}

/// A device of the vectors: its signer, X-Wing seed and key.
pub struct Device {
    pub signer: Signer,
    pub xwing_seed: [u8; 32],
    pub xwing: [u8; XWING_PUBLIC],
}

impl Device {
    pub fn new(identity_seed: [u8; 32], xwing_seed: [u8; 32]) -> Self {
        Self {
            signer: signer(&identity_seed, &xwing_seed),
            xwing_seed,
            xwing: xwing_public(&xwing_seed),
        }
    }

    /// A device of crypto.md's fixture derivations: its ML-DSA-65 and X-Wing
    /// seeds derived from its identity seed, as admission.py's
    /// `roster_device_keys` gives a device of a roster.py history.
    #[allow(dead_code)]
    pub fn fixture(identity_seed: [u8; 32]) -> Self {
        let xwing_seed = *frasil_crypto::fixtures::fixture_xwing_seed(&identity_seed);
        Self::new(identity_seed, xwing_seed)
    }

    /// admission.py's `device_keys(name)`.
    pub fn named(name: &str) -> Self {
        Self::new(
            example(&format!("admission/{name}/ed25519")),
            example(&format!("admission/{name}/xwing")),
        )
    }

    pub fn identity(&self) -> [u8; 32] {
        self.signer.identity_key().0
    }

    pub fn device_id(&self) -> DeviceId {
        *self.signer.device_id()
    }

    /// The device's three public keys.
    pub fn device_keys(&self) -> DeviceKeys {
        DeviceKeys {
            ed: *self.signer.identity_key(),
            keys: self.signer.keys().clone(),
        }
    }

    pub fn keys(&self) -> JoinerKeys<'_> {
        JoinerKeys::Device {
            signer: &self.signer,
        }
    }

    /// The vectors' `_keys_json`.
    pub fn check_json(&self, json: &Json) {
        assert_eq!(text(&json["identity"]), h(self.identity()));
        assert_eq!(text(&json["kc"]), h(self.signer.kc().0));
        assert_eq!(text(&json["device_id"]), h(self.device_id().0));
        assert_eq!(text(&json["xwing_seed"]), h(self.xwing_seed));
        assert_eq!(
            text(&json["mldsa_seed"]),
            h(*fixture_mldsa_seed(&array::<32>(&json["identity_seed"])))
        );
    }
}

/// A joiner's start from the reference's seeds under a tag.
pub fn start(ctx: Ctx, tag: &str, expires_at: u64, display: &str, channel: &[u8]) -> JoinerStart {
    JoinerStart {
        ctx,
        request: example16(&format!("{tag}/request")),
        expires_at,
        nonce: Zeroizing::new(example(&format!("{tag}/nonce-j"))),
        eph_seed: Zeroizing::new(example(&format!("{tag}/eph-j"))),
        display: display.to_owned(),
        channel: channel.to_vec(),
    }
}

/// What an approver draws, from the reference's seeds under a tag and the
/// label of the Response's encapsulation randomness.
pub fn draw(tag: &str, encapsulation: &str) -> ResponseDraw {
    ResponseDraw {
        nonce: Zeroizing::new(example(&format!("{tag}/nonce-i"))),
        eph_seed: Zeroizing::new(example(&format!("{tag}/eph-i"))),
        encapsulation: Zeroizing::new(eseed(encapsulation)),
    }
}

/// An approver's side.
pub fn side(
    approver: DeviceId,
    ctx: Ctx,
    log: [u8; 32],
    heads: Vec<EventId>,
    offer: Vec<u8>,
    display: &str,
    channel: &[u8],
) -> ApproverSide {
    ApproverSide {
        approver,
        ctx,
        log,
        heads,
        offer,
        display: display.to_owned(),
        channel: channel.to_vec(),
    }
}

/// A joiner and its Request.
pub fn joiner<'k>(start: JoinerStart, keys: JoinerKeys<'k>) -> (Joiner<'k>, Vec<u8>) {
    Joiner::start_with(start, keys).expect("the joiner starts")
}

/// The class name a result failed with, or `accepted` / `ignored`.
pub fn outcome<T>(result: Result<Option<T>, AdmissionClass>) -> &'static str {
    match result {
        Ok(Some(_)) => "accepted",
        Ok(None) => "ignored",
        Err(class) => class.name(),
    }
}

pub fn ids(value: &Json) -> Vec<EventId> {
    value
        .as_array()
        .expect("an array")
        .iter()
        .map(|v| EventId(array(v)))
        .collect()
}

/// RFC 4648 base32, upper case, no padding, for building refused texts.
pub fn base32(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = String::new();
    for b in bytes {
        bits.push_str(&format!("{b:08b}"));
    }
    while !bits.len().is_multiple_of(5) {
        bits.push('0');
    }
    bits.as_bytes()
        .chunks(5)
        .map(|c| A[usize::from_str_radix(std::str::from_utf8(c).unwrap(), 2).unwrap()] as char)
        .collect()
}
