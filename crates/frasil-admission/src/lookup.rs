//! Lookups: the prompt and the Join (admission.md, "The lookup prompt and
//! the Join", "Lookups").
//!
//! ```text
//! prompt = CBOR {1: 1, 2: reference (16 random bytes), 3: approver's device ID (32),
//!                4: approver's X-Wing key (1,216), 5: display_I (text), 6: [peer hints]}
//! signed prompt = CBOR {1: prompt (bytes),
//!                       2: the approver device's scheme-2 signature over
//!                          "frasil/admission/prompt/v1" || field(prompt)}
//! join   = CBOR {1: reference (16), 2: person ID (32), 3: [signed device-list events],
//!                4: display_J (text)}
//! ```
//!
//! The Join travels as a message of type 7 whose `request` is the
//! reference, sealed to the prompt's X-Wing key. An administrator that
//! grants a person found through a lookup with no code grants it `via` =
//! `lookup`, and applications show the member as unverified.

use crate::message::{MessageType, open_body, read_message, sealed_message_with};
use crate::params::{REQUEST_BYTES, VERSION};
use crate::{
    AdmissionClass, array_at, boxed_at, bytes_at, display_at, hints_value, malformed, read_hints,
    read_map,
};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_base::notation::push_field;
use frasil_crypto::device::{DeviceId, HybridKeys, IdentityKey, device_id, keys_commitment};
use frasil_crypto::labels::ADMISSION_PROMPT;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_crypto::sizes::{MLDSA65_PUBLIC, SCHEME2_SIGNATURE, XWING_PUBLIC, XWING_SEED};
use frasil_crypto::wrap::ENCAPSULATION_RANDOMNESS;

/// A record signed under scheme 2 with a label: `CBOR {1: record, 2:
/// signature over label || field(record)}`. A prompt and an access request
/// are signed so.
pub fn sign_record(label: &[u8], record: &[u8], signer: &Signer) -> Vec<u8> {
    let mut tbs = label.to_vec();
    push_field(&mut tbs, record);
    let mut map = Map::new();
    map.insert(1, Value::from(record));
    map.insert(2, Value::from(signer.sign(Scheme::Hybrid, &tbs)));
    Value::Map(map).encode()
}

/// A signed record's two parts: `{1: record (bytes), 2: signature
/// (3,373)}`.
///
/// # Errors
///
/// `Malformed`.
pub(crate) fn read_signed(signed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AdmissionClass> {
    let map = read_map(signed, &[1, 2], &[1, 2])?;
    let record = bytes_at(&map, 1)?;
    let signature = bytes_at(&map, 2)?;
    if signature.len() != SCHEME2_SIGNATURE {
        return Err(malformed());
    }
    Ok((record.to_vec(), signature.to_vec()))
}

/// Whether a scheme-2 signature over `label || field(record)` verifies,
/// both halves, under these keys.
pub(crate) fn record_verifies(
    label: &[u8],
    record: &[u8],
    signature: &[u8],
    identity: &IdentityKey,
    keys: &HybridKeys,
) -> bool {
    let mut tbs = label.to_vec();
    push_field(&mut tbs, record);
    frasil_identity::possession::verify(identity, keys, &tbs, signature).is_ok()
}

/// What an administrator leaves in a person's mailbox after a lookup.
/// Nothing in it is secret or trusted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prompt {
    /// The reference, 16 random bytes: the request ID of the exchange that
    /// follows.
    pub reference: [u8; REQUEST_BYTES],
    /// The approver device's device ID.
    pub approver: DeviceId,
    /// The approver device's X-Wing key, which a Join is sealed to.
    pub xwing: Box<[u8; XWING_PUBLIC]>,
    /// `display_I`.
    pub display: String,
    /// Peer hints.
    pub peers: Vec<String>,
}

impl Prompt {
    /// The prompt's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION.into()));
        map.insert(2, Value::from(self.reference));
        map.insert(3, Value::from(self.approver.0));
        map.insert(4, Value::from(&self.xwing[..]));
        map.insert(5, Value::from(self.display.as_str()));
        map.insert(6, hints_value(&self.peers));
        Value::Map(map).encode()
    }

    /// The signed prompt, by the approver device.
    pub fn sign(&self, signer: &Signer) -> Vec<u8> {
        sign_record(ADMISSION_PROMPT, &self.encode(), signer)
    }

    /// Reads a prompt's map.
    ///
    /// # Errors
    ///
    /// `Malformed`; `UnsupportedVersion` unless key 1 is 1; `Malformed`.
    pub fn read(data: &[u8]) -> Result<Self, AdmissionClass> {
        let keys = [1, 2, 3, 4, 5, 6];
        let map = read_map(data, &keys, &keys)?;
        if map[&1] != Value::Unsigned(VERSION.into()) {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        Ok(Self {
            reference: array_at(&map, 2)?,
            approver: DeviceId(array_at(&map, 3)?),
            xwing: boxed_at(&map, 4)?,
            display: display_at(&map, 5)?,
            peers: read_hints(&map[&6])?,
        })
    }
}

/// What the person's device does with a prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptAnswer {
    /// A co-member: on consent, it sends a Join to the approver device's
    /// mailbox.
    Join(Prompt),
    /// Anyone else: on consent, it opens the code exchange instead, with
    /// the prompt's reference as the request ID.
    CodeExchange(Prompt),
}

/// The person's device's checks of a signed prompt, in order (admission.md,
/// "Lookups", step 2). `shared(approver)` gives the approver device's
/// Ed25519 and ML-DSA-65 keys when a space this device holds grants both
/// the person and that device ID, taken from that space's records or any
/// other source; `None` when no such space grants it. With the prompt's
/// X-Wing key they must give that device ID (crypto.md, "A device's
/// keys").
///
/// # Errors
///
/// `Malformed` until both maps read; `UnsupportedVersion`; `Malformed`;
/// then, for a co-member, `NotCommitted` and `BadSignature`.
pub fn answer_prompt(
    signed: &[u8],
    shared: impl Fn(&DeviceId) -> Option<(IdentityKey, Box<[u8; MLDSA65_PUBLIC]>)>,
) -> Result<PromptAnswer, AdmissionClass> {
    let (record, signature) = read_signed(signed)?;
    let prompt = Prompt::read(&record)?;
    let Some((ed, mldsa)) = shared(&prompt.approver) else {
        return Ok(PromptAnswer::CodeExchange(prompt));
    };
    let kc = keys_commitment(&mldsa[..], Some(&prompt.xwing[..]));
    if device_id(&ed, &kc) != prompt.approver {
        return Err(ErrorClass::NotCommitted.into());
    }
    let keys = HybridKeys::new(&mldsa[..], Some(&prompt.xwing[..]))
        .map_err(|_| AdmissionClass::from(ErrorClass::NotCommitted))?;
    if !record_verifies(ADMISSION_PROMPT, &record, &signature, &ed, &keys) {
        return Err(ErrorClass::BadSignature.into());
    }
    Ok(PromptAnswer::Join(prompt))
}

/// A co-member's answer to a prompt: its person's whole list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Join {
    /// The prompt's reference.
    pub reference: [u8; REQUEST_BYTES],
    /// The person ID.
    pub person: [u8; 32],
    /// Every event of the person's list the device holds, signed.
    pub events: Vec<Vec<u8>>,
    /// `display_J`.
    pub display: String,
}

impl Join {
    /// The Join's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::from(self.reference));
        map.insert(2, Value::from(self.person));
        map.insert(
            3,
            Value::Array(self.events.iter().map(|e| Value::from(e.clone())).collect()),
        );
        map.insert(4, Value::from(self.display.as_str()));
        Value::Map(map).encode()
    }

    /// Reads a Join's map.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(data: &[u8]) -> Result<Self, AdmissionClass> {
        let keys = [1, 2, 3, 4];
        let map = read_map(data, &keys, &keys)?;
        let events = map[&3]
            .as_array()?
            .iter()
            .map(|item| Ok(item.as_bytes()?.to_vec()))
            .collect::<Result<Vec<_>, AdmissionClass>>()?;
        Ok(Self {
            reference: array_at(&map, 1)?,
            person: array_at(&map, 2)?,
            events,
            display: display_at(&map, 4)?,
        })
    }

    /// The Join as a message of type 7, sealed to the prompt's X-Wing key,
    /// with X-Wing's 64 bytes of encapsulation randomness given.
    ///
    /// # Errors
    ///
    /// `InvalidKey` for a key X-Wing refuses.
    pub fn message_with(
        &self,
        approver_xwing: &[u8],
        encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
    ) -> Result<Vec<u8>, AdmissionClass> {
        sealed_message_with(
            MessageType::Join,
            &self.reference,
            approver_xwing,
            &self.encode(),
            encapsulation_randomness,
        )
    }

    /// Opens a Join message with the approver device's X-Wing seed. The
    /// approver then checks its list ([`crate::new_device::check_list_events`],
    /// with the person ID the lookup returned and no committed heads).
    ///
    /// # Errors
    ///
    /// The message's class; `Malformed` for another type or a reference
    /// other than the Join's; the seal's classes; the map's.
    pub fn open(message: &[u8], xwing_seed: &[u8; XWING_SEED]) -> Result<Self, AdmissionClass> {
        let read = read_message(message)?;
        if read.kind != MessageType::Join {
            return Err(malformed());
        }
        let plaintext = open_body(MessageType::Join, &read.request, xwing_seed, read.body)?;
        let join = Self::read(&plaintext)?;
        if join.reference != read.request {
            return Err(malformed());
        }
        Ok(join)
    }
}
