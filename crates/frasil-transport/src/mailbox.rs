//! Mailboxes (transport.md, sections 2.7 "Mailboxes" and 3.14
//! "Mailboxes").
//!
//! ```text
//! address      = SHA-256("frasil/mailbox/v1" || u8(kind) || field(name))
//!
//! MailboxPut   = {0: 24, 1: request, 2: address (32), 3: item (at most 262,144 bytes),
//!                 6: kind}
//! MailboxGet   = {0: 25, 1: request, 2: address (32), 3: after (16; optional),
//!                 4: ed || kc (64), 5: signature (64), 6: kind}
//! MailboxItems = {0: 26, 1: request, 2: [[item ID (16), item], ...]}
//!
//! item      = 0x01 || u16be(0x647a) || enc (1,120) || ciphertext
//! (enc, ciphertext) = HPKE-Seal(recipient's X-Wing key, info, aad = "", plaintext)
//! info      = "frasil/mailbox-item/v1" || u16be(0x647a) || recipient's device ID (32)
//! plaintext = {1: content name (text, 1 to 64 bytes), 2: body (bytes)}
//! ```

use crate::frame::{Extensions, MAILBOX_ITEM_BYTES, Message, MessageType};
use crate::messages::{self, malformed, of_type, uint};
use crate::{TransportClass, exact_keys};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Value};
use frasil_base::notation::push_field;
use frasil_crypto::device::{DeviceId, DeviceKeys, IdentityKey, KeysCommitment, Signatory};
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::labels;
use frasil_crypto::primitives::{ed25519_public, ed25519_sign, sha256};
use frasil_crypto::schemes::ed25519_verify_strict;
use frasil_crypto::wrap::{ENCAPSULATION_RANDOMNESS, WrapUse, open_wrap, seal_wrap_with};
use std::collections::VecDeque;

/// A mailbox's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// 1: an exchange mailbox, named by a 16-byte request ID
    /// (admission.md).
    Exchange,
    /// 2: a person mailbox, named by a person ID; only at an account's
    /// server.
    Person,
    /// 3: a device mailbox, named by a device ID.
    Device,
    /// 4: ext-invite-links.md's invite drop.
    Drop,
}

impl Kind {
    /// The kind's code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Exchange => 1,
            Self::Person => 2,
            Self::Device => 3,
            Self::Drop => 4,
        }
    }

    /// The kind of a code, 1 to 4.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Exchange),
            2 => Some(Self::Person),
            3 => Some(Self::Device),
            4 => Some(Self::Drop),
            _ => None,
        }
    }

    /// The kind's name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Exchange => "exchange mailbox",
            Self::Person => "person mailbox",
            Self::Device => "device mailbox",
            Self::Drop => "invite drop",
        }
    }
}

/// A mailbox's address: `SHA-256("frasil/mailbox/v1" || u8(kind) ||
/// field(name))`. The address hashes the kind, so naming another kind names
/// another, empty mailbox.
pub fn address(kind: Kind, name: &[u8]) -> [u8; 32] {
    let mut input = labels::MAILBOX.to_vec();
    input.push(kind.code());
    push_field(&mut input, name);
    sha256(&[&input])
}

/// `MailboxPut`'s key 7: a deposit token, on kind 3 only, reserved for
/// ext-deposit-tokens.md.
pub const TOKEN_KEY: u64 = 7;

/// The most items a device mailbox holds.
pub const DEVICE_MAILBOX_ITEMS: usize = 64;
/// The most bytes a device mailbox holds, 4 MiB.
pub const DEVICE_MAILBOX_BYTES: usize = 4 * 1024 * 1024;
/// The most bytes of a content name.
pub const CONTENT_NAME_BYTES: usize = 64;
/// The shortest item: a wrap of an empty plaintext, 1,139 bytes.
pub const MIN_ITEM_BYTES: usize = frasil_crypto::wrap::MIN_WRAP;
/// The most bytes of items one `MailboxItems` carries.
pub const ITEMS_BYTES: usize = MAILBOX_ITEM_BYTES;

/// Frasil's content names.
pub mod content {
    /// A signed access request (admission.md, "Access requests").
    pub const ACCESS_REQUEST: &str = "frasil/access-request";
    /// A signed leave request (ext-guests.md).
    pub const LEAVE_REQUEST: &str = "frasil/leave-request";
    /// Signed device-list events, with the space to forward them into
    /// (units.md, "Frasil's own units").
    pub const LIST_EVENTS: &str = "frasil/list-events";
    /// The content names a core implementation implements.
    pub const CORE: [&str; 3] = [ACCESS_REQUEST, LIST_EVENTS, WELCOME_REQUEST];
    /// A signed request from an existing member for a fresh welcome.
    pub const WELCOME_REQUEST: &str = "frasil/welcome-request";

    /// Whether this build implements a content name: the core's, and
    /// `frasil/leave-request` with ext-guests.md.
    pub fn implemented(name: &str) -> bool {
        CORE.contains(&name) || (cfg!(feature = "ext-guests") && name == LEAVE_REQUEST)
    }
}

/// An item's `info`: `"frasil/mailbox-item/v1" || u16be(0x647a) ||
/// recipient's device ID`.
pub fn item_info(recipient: &DeviceId) -> Vec<u8> {
    WrapUse::MailboxItem.info(&recipient.0)
}

/// An item's plaintext: `{1: content name, 2: body}`.
pub fn item_plaintext(content: &str, body: &[u8]) -> Vec<u8> {
    let mut map = cbor::Map::new();
    map.insert(1, Value::from(content));
    map.insert(2, Value::from(body));
    Value::Map(map).encode()
}

/// Seals an item for one recipient: crypto.md's X-Wing wrap to the X-Wing
/// key its device ID commits to, its `info` naming that device ID, with
/// its 64 bytes of encapsulation randomness given. The keys may come from
/// any source; they are the recipient's because they hash to its device ID.
///
/// # Errors
///
/// `Malformed` for a content name of 0 or more than 64 bytes; `TooLarge`
/// for an item over 262,144 bytes; `InvalidKey` for keys with no X-Wing
/// key, or if X-Wing refuses the key.
pub fn seal_item_with(
    content: &str,
    body: &[u8],
    recipient: &DeviceKeys,
    randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<Vec<u8>, TransportClass> {
    if content.is_empty() || content.len() > CONTENT_NAME_BYTES {
        return Err(malformed());
    }
    let xwing = recipient.keys.xwing().ok_or(ErrorClass::InvalidKey)?;
    let item = seal_wrap_with(
        xwing,
        &item_info(&recipient.device_id()),
        &item_plaintext(content, body),
        randomness,
    )?;
    if item.len() > MAILBOX_ITEM_BYTES {
        return Err(ErrorClass::TooLarge.into());
    }
    Ok(item)
}

/// An opened item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The content name.
    pub content: String,
    /// The body, which the content name's document checks.
    pub body: Vec<u8>,
}

/// Reads an item's plaintext (step 2 of opening an item).
///
/// # Errors
///
/// `Malformed` unless it is a deterministic CBOR map of exactly keys 1 and
/// 2: a text of 1 to 64 bytes, and a byte string.
pub fn read_item_plaintext(plaintext: &[u8]) -> Result<Item, TransportClass> {
    let value = cbor::decode(plaintext)?;
    let map = value.as_map()?;
    if !exact_keys(map, &[1, 2]) {
        return Err(malformed());
    }
    let content = messages::text(map, 1)?;
    if content.is_empty() || content.len() > CONTENT_NAME_BYTES {
        return Err(malformed());
    }
    Ok(Item {
        content: content.to_owned(),
        body: messages::bytes(map, 2)?.to_vec(),
    })
}

/// Opens an item from the device's own mailbox, in order (section 3.14,
/// steps 1 to 3); step 4, the body's checks, is the content name's
/// document's. `recipient` is the device's own device ID and
/// `implements` says which content names it implements.
///
/// # Errors
///
/// crypto.md's `open_wrap` classes, with lengths of 1,139 to 262,144
/// bytes; `Malformed` for a plaintext that does not read;
/// `UnknownContent` for a content name the device does not implement.
pub fn open_item(
    item: &[u8],
    recipient: &DeviceId,
    xwing_seed: &[u8; 32],
    implements: impl Fn(&str) -> bool,
) -> Result<Item, TransportClass> {
    // 1.
    let plaintext = open_wrap(
        item,
        xwing_seed,
        &item_info(recipient),
        WrapUse::MailboxItem.length(),
    )?;
    // 2.
    let opened = read_item_plaintext(&plaintext)?;
    // 3.
    if !implements(&opened.content) {
        return Err(TransportClass::UnknownContent);
    }
    Ok(opened)
}

/// `MailboxPut`: a deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxPut {
    /// The request.
    pub request: u64,
    /// The mailbox's address.
    pub address: [u8; 32],
    /// The item.
    pub item: Vec<u8>,
    /// The mailbox's kind, 1 to 3.
    pub kind: Kind,
}

impl MailboxPut {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        messages::encode(
            MessageType::MailboxPut,
            [
                (1, Value::Unsigned(self.request)),
                (2, Value::from(self.address)),
                (3, Value::from(self.item.as_slice())),
                (6, Value::Unsigned(self.kind.code().into())),
            ],
        )
    }

    /// Reads a `MailboxPut` of kind 1 to 3 at a peer: exactly keys 0 to 3
    /// and 6, a 32-byte address, an item of at most 262,144 bytes. Kind 4
    /// is ext-invite-links.md's: with that extension it is `Ok(None)`, for
    /// the extension to read; without it, `Malformed`. So is kind 3 with
    /// key 7, a deposit token, which ext-deposit-tokens.md reads in its own
    /// order (ext-deposit-tokens.md, 3.7 Redeeming).
    ///
    /// # Errors
    ///
    /// `Malformed`; `TooLarge` for an item over 262,144 bytes.
    pub fn read(message: &Message, extensions: Extensions) -> Result<Option<Self>, TransportClass> {
        of_type(message, MessageType::MailboxPut)?;
        let map = &message.map;
        let kind = Kind::from_code(uint(map, 6)?);
        if kind == Some(Kind::Drop) && extensions.invite_links {
            return Ok(None);
        }
        if kind == Some(Kind::Device)
            && map.contains_key(&TOKEN_KEY)
            && extensions.reads_deposit_tokens()
        {
            return Ok(None);
        }
        let Some(kind @ (Kind::Exchange | Kind::Person | Kind::Device)) = kind else {
            return Err(malformed());
        };
        if !exact_keys(map, &[0, 1, 2, 3, 6]) {
            return Err(malformed());
        }
        let request = uint(map, 1)?;
        let address = messages::array(map, 2)?;
        let item = messages::bytes(map, 3)?;
        if item.len() > MAILBOX_ITEM_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        Ok(Some(Self {
            request,
            address,
            item: item.to_vec(),
            kind,
        }))
    }
}

/// `MailboxGet`: a collection. Keys 4 and 5 are present exactly for a
/// device mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxGet {
    /// The request.
    pub request: u64,
    /// The mailbox's address.
    pub address: [u8; 32],
    /// Asks for the items after this ID.
    pub after: Option<[u8; 16]>,
    /// For a device mailbox: the device's `ed || kc` and the signature, by
    /// `ed`, of `"frasil/mailbox-collect/v1" || binding || address`.
    pub collector: Option<(Signatory, Vec<u8>)>,
    /// The mailbox's kind, 1 to 3.
    pub kind: Kind,
}

impl MailboxGet {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries = vec![
            (1, Value::Unsigned(self.request)),
            (2, Value::from(self.address)),
        ];
        if let Some(after) = self.after {
            entries.push((3, Value::from(after)));
        }
        if let Some((signer, signature)) = &self.collector {
            entries.push((4, Value::from(signer.to_bytes())));
            entries.push((5, Value::from(signature.as_slice())));
        }
        entries.push((6, Value::Unsigned(self.kind.code().into())));
        messages::encode(MessageType::MailboxGet, entries)
    }

    /// Reads a `MailboxGet` of kind 1 to 3, and 4 with ext-invite-links.md:
    /// keys 0 to 2 and 6, an optional 16-byte `after`, and keys 4 and 5
    /// exactly for a device mailbox. The collection's own checks are
    /// [`check_collect`]'s, whose [`CheckedCollection`] a peer requires
    /// before it serves a device mailbox.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::MailboxGet)?;
        let map = &message.map;
        let kind = match Kind::from_code(uint(map, 6)?) {
            Some(kind @ (Kind::Exchange | Kind::Person | Kind::Device)) => kind,
            // ext-invite-links.md: a drop is fetched as a mailbox of kind 4,
            // with no keys 4 and 5.
            #[cfg(feature = "ext-invite-links")]
            Some(Kind::Drop) => Kind::Drop,
            _ => return Err(malformed()),
        };
        let after = map.contains_key(&3);
        let keys: &[u64] = match (kind, after) {
            (Kind::Device, false) => &[0, 1, 2, 4, 5, 6],
            (Kind::Device, true) => &[0, 1, 2, 3, 4, 5, 6],
            (_, false) => &[0, 1, 2, 6],
            (_, true) => &[0, 1, 2, 3, 6],
        };
        if !exact_keys(map, keys) {
            return Err(malformed());
        }
        let collector = if kind == Kind::Device {
            Some((
                Signatory::from_bytes(messages::bytes(map, 4)?)?,
                messages::bytes(map, 5)?.to_vec(),
            ))
        } else {
            None
        };
        Ok(Self {
            request: uint(map, 1)?,
            address: messages::array(map, 2)?,
            after: after.then(|| messages::array(map, 3)).transpose()?,
            collector,
            kind,
        })
    }
}

/// `MailboxItems`: a mailbox's items, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxItems {
    /// The request answered.
    pub request: u64,
    /// Each item's 16-byte ID, in deposit order, and the item.
    pub items: Vec<([u8; 16], Vec<u8>)>,
}

impl MailboxItems {
    /// The message.
    pub fn encode(&self) -> Vec<u8> {
        messages::encode(
            MessageType::MailboxItems,
            [
                (1, Value::Unsigned(self.request)),
                (
                    2,
                    Value::Array(
                        self.items
                            .iter()
                            .map(|(id, item)| {
                                Value::Array(vec![Value::from(*id), Value::from(item.as_slice())])
                            })
                            .collect(),
                    ),
                ),
            ],
        )
    }

    /// Reads a `MailboxItems`: at most 262,144 bytes of items, IDs strictly
    /// ascending.
    ///
    /// # Errors
    ///
    /// `Malformed`; `TooLarge` over 262,144 bytes of items.
    pub fn read(message: &Message) -> Result<Self, TransportClass> {
        of_type(message, MessageType::MailboxItems)?;
        let map = &message.map;
        let entries = messages::field(map, 2)?.as_array()?;
        let mut items: Vec<([u8; 16], Vec<u8>)> = Vec::with_capacity(entries.len());
        let mut total = 0usize;
        for entry in entries {
            let [id, item] = entry.as_array()? else {
                return Err(malformed());
            };
            let id: [u8; 16] = id.as_byte_array()?;
            let item = item.as_bytes()?;
            if items.last().is_some_and(|(last, _)| *last >= id) {
                return Err(malformed());
            }
            total += item.len();
            if total > ITEMS_BYTES {
                return Err(ErrorClass::TooLarge.into());
            }
            items.push((id, item.to_vec()));
        }
        Ok(Self {
            request: uint(map, 1)?,
            items,
        })
    }
}

/// What a device signs, with its Ed25519 key, to collect its own mailbox:
/// `"frasil/mailbox-collect/v1" || binding || address`.
pub fn collect_input(binding: &[u8; 32], address: &[u8; 32]) -> Vec<u8> {
    [labels::MAILBOX_COLLECT, binding, address].concat()
}

/// The device's `MailboxGet` for its own mailbox on a connection of this
/// `binding`, signed with its identity seed, carrying its `ed` and its keys
/// commitment `kc`: the mailbox's address hashes the device ID of the two.
pub fn collect(
    request: u64,
    identity_seed: &[u8; 32],
    kc: &KeysCommitment,
    binding: &[u8; 32],
    after: Option<[u8; 16]>,
) -> Vec<u8> {
    let signer = Signatory {
        ed: IdentityKey(ed25519_public(identity_seed)),
        kc: *kc,
    };
    let address = address(Kind::Device, &signer.device_id().0);
    let signature = ed25519_sign(identity_seed, &collect_input(binding, &address));
    MailboxGet {
        request,
        address,
        after,
        collector: Some((signer, signature.to_vec())),
        kind: Kind::Device,
    }
    .encode()
}

/// A device mailbox's collection that passed [`check_collect`]: the only
/// way to make one, so code that serves a device mailbox's items takes it
/// and cannot serve a collection whose checks did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedCollection {
    address: [u8; 32],
    collector: DeviceId,
}

impl CheckedCollection {
    /// The mailbox's address, which the collector's device ID hashes.
    pub fn address(&self) -> &[u8; 32] {
        &self.address
    }

    /// The collecting device, whose signature over the connection's
    /// binding verified.
    pub fn collector(&self) -> DeviceId {
        self.collector
    }
}

/// Collecting a device mailbox: the peer's checks, in order (section 3.14).
/// What passes is a [`CheckedCollection`].
///
/// # Errors
///
/// `Malformed` unless the address, `ed || kc` and signature are 32, 64 and
/// 64 bytes; `InvalidKey` for an `ed` crypto.md refuses; `WrongMailbox`
/// when the device ID of `ed` and `kc` does not hash to the address;
/// `BadSignature` if the signature does not verify strictly under `ed` over
/// this connection's `binding`. The address hashes the device ID, which
/// hashes `kc`, so the signature over the address binds `kc` too.
pub fn check_collect(
    address: &[u8],
    signer: &[u8],
    signature: &[u8],
    binding: &[u8; 32],
) -> Result<CheckedCollection, TransportClass> {
    // 1.
    let (Ok(address), Ok(signer)) = (<[u8; 32]>::try_from(address), Signatory::from_bytes(signer))
    else {
        return Err(malformed());
    };
    if signature.len() != 64 {
        return Err(malformed());
    }
    // 2.
    ed25519_valid(&signer.ed.0)?;
    // 3.
    if self::address(Kind::Device, &signer.device_id().0) != address {
        return Err(TransportClass::WrongMailbox);
    }
    // 4.
    if !ed25519_verify_strict(&signer.ed.0, &collect_input(binding, &address), signature) {
        return Err(ErrorClass::BadSignature.into());
    }
    Ok(CheckedCollection {
        address,
        collector: signer.device_id(),
    })
}

/// A device mailbox at a peer: at most 64 items and 4 MiB. A deposit past
/// either evicts the oldest items first. Anyone can fill it; no one can
/// grow it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceMailbox {
    items: VecDeque<([u8; 16], Vec<u8>)>,
    bytes: usize,
}

impl DeviceMailbox {
    /// An empty mailbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// The items held, oldest first.
    pub fn items(&self) -> impl Iterator<Item = &([u8; 16], Vec<u8>)> {
        self.items.iter()
    }

    /// The bytes of items held.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Deposits an item under the ID the peer assigned, in deposit order,
    /// then evicts the oldest items past either cap. Returns the IDs
    /// evicted.
    ///
    /// # Errors
    ///
    /// `TooLarge` for an item over 262,144 bytes.
    pub fn put(&mut self, id: [u8; 16], item: Vec<u8>) -> Result<Vec<[u8; 16]>, TransportClass> {
        if item.len() > MAILBOX_ITEM_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        self.bytes += item.len();
        self.items.push_back((id, item));
        let mut evicted = Vec::new();
        while self.items.len() > DEVICE_MAILBOX_ITEMS || self.bytes > DEVICE_MAILBOX_BYTES {
            let Some((id, item)) = self.items.pop_front() else {
                break;
            };
            self.bytes -= item.len();
            evicted.push(id);
        }
        Ok(evicted)
    }

    /// The items after an ID, oldest first, at most 262,144 bytes of them.
    pub fn after(&self, after: Option<&[u8; 16]>) -> Vec<([u8; 16], Vec<u8>)> {
        let mut out = Vec::new();
        let mut total = 0;
        for (id, item) in &self.items {
            if after.is_some_and(|after| id <= after) {
                continue;
            }
            if total + item.len() > ITEMS_BYTES {
                break;
            }
            total += item.len();
            out.push((*id, item.clone()));
        }
        out
    }
}
