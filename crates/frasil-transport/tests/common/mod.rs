//! What the transport.json tests share: the file, hex helpers, the
//! reference's fixed inputs (`docs/spec/reference/handshakes.py`, "Vectors:
//! fixtures"), each a hash of a description, so no value is magic, and the
//! states of the member handshake's space.

#![allow(dead_code)]

use frasil_base::Class;
use frasil_crypto::device::{DeviceId, DeviceKeys, HybridKeys, IdentityKey, Signatory};
use frasil_crypto::primitives::sha256;
use frasil_testkit::hex;
use frasil_transport::TransportClass;
use frasil_transport::frame::{ConnectionKind, Extensions, Message, StreamClass, read_message};
use serde_json::Value as Json;

pub const FILE: &str = "transport.json";

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

pub fn number(value: &Json) -> u64 {
    value.as_u64().expect("a number")
}

/// `example(name)`: SHA-256 of `"frasil spec example/" || name`.
pub fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// The class a result failed with, by its vector name.
pub fn class<T>(result: Result<T, TransportClass>) -> Option<&'static str> {
    result.err().map(Class::name)
}

/// A control-stream message, read as a member connection reads it.
pub fn control(payload: &[u8]) -> Message {
    read_message(
        payload,
        StreamClass::Control,
        ConnectionKind::Member,
        Extensions::NONE,
    )
    .expect("a control message")
    .expect("not ignorable")
}

/// A control-stream message read on a member connection, or its class.
pub fn member_read(payload: &[u8]) -> Result<Message, TransportClass> {
    read_message(
        payload,
        StreamClass::Control,
        ConnectionKind::Member,
        Extensions::NONE,
    )
    .map(|m| m.expect("not ignorable"))
}

/// A control-stream message read on a device-to-peer connection.
pub fn peer_control(payload: &[u8]) -> Result<Message, TransportClass> {
    read_message(
        payload,
        StreamClass::Control,
        ConnectionKind::DeviceToPeer,
        Extensions::NONE,
    )
    .map(|m| m.expect("not ignorable"))
}

/// The second connection's channel the refusals replay into.
pub fn channel_2() -> [u8; 32] {
    array(&family("member_handshake")["channel_2"])
}

/// The member handshake's fixtures: the channel, endpoint and identity
/// keys, and every state's content key, by label.
pub struct Handshake {
    pub json: Json,
}

impl Handshake {
    pub fn load() -> Self {
        Self {
            json: family("member_handshake"),
        }
    }

    pub fn channel(&self) -> [u8; 32] {
        array(&self.json["channel"])
    }

    pub fn endpoint(&self, side: &str) -> [u8; 32] {
        array(&self.json["endpoint_keys"][side]["public"])
    }

    pub fn identity_seed(&self, side: &str) -> [u8; 32] {
        array(&self.json["devices"][side]["seed"])
    }

    /// The side's three public keys.
    pub fn device_keys(&self, side: &str) -> DeviceKeys {
        let device = &self.json["devices"][side];
        DeviceKeys {
            ed: IdentityKey(array(&device["ed25519"])),
            keys: HybridKeys::new(&bytes(&device["mldsa"]), Some(&bytes(&device["xwing"])))
                .unwrap(),
        }
    }

    /// The side's `ed || kc`.
    pub fn signer(&self, side: &str) -> Signatory {
        let signer = self.device_keys(side).signatory();
        assert_eq!(signer.kc.0, array::<32>(&self.json["devices"][side]["kc"]));
        signer
    }

    /// The side's device ID.
    pub fn device_id(&self, side: &str) -> DeviceId {
        let id = self.device_keys(side).device_id();
        assert_eq!(id.0, array::<32>(&self.json["devices"][side]["device_id"]));
        id
    }

    /// `k(S)` of a state, by its label such as `{C,D}`.
    pub fn secret(&self, label: &str) -> [u8; 32] {
        array(&self.json["content_keys"][label])
    }

    /// The states of a list of labels, each with its secret.
    pub fn states(&self, labels: &Json) -> Vec<(String, [u8; 32])> {
        labels
            .as_array()
            .expect("labels")
            .iter()
            .map(|l| (text(l).to_owned(), self.secret(text(l))))
            .collect()
    }

    /// The responder's candidates: the other space's state first, then the
    /// space's states held, as the reference lists them.
    pub fn candidates(&self, labels: &Json) -> Vec<(String, [u8; 32])> {
        let mut out = vec![(
            "other space".to_owned(),
            array(&self.json["other_space"]["content_key"]),
        )];
        out.extend(self.states(labels));
        out
    }
}

/// The fillers of the reference's offers: the tags past the offered states.
pub fn fillers(tags: &Json, offered: usize) -> [[u8; 32]; 16] {
    let tags = tags.as_array().expect("tags");
    let mut out = [[0; 32]; 16];
    for (index, tag) in tags.iter().enumerate().skip(offered) {
        out[index] = array(tag);
    }
    out
}
