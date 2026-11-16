//! The store's keys and addresses (at-rest.md, "Keys, addresses and
//! records", "Application keys").
//!
//! ```text
//! seal_key(K)         = HKDF(none, K, "frasil/at-rest/seal-key/v1")
//! tag_key(K)          = HKDF(none, K, "frasil/at-rest/tag-key/v1")
//! app_key(K, purpose) = HKDF(none, K, "frasil/at-rest/app-key/v1" || field(purpose))
//!
//! address   = scope_tag (16) || u8(table) || item_tag (16)                  33 bytes
//! scope_tag = 16 zero bytes                                           for a device-wide table
//!           = HMAC(tag_key(s), "frasil/at-rest/scope/v1" || log ID)[0..16]  for a log's table
//! item_tag  = HMAC(tag_key(K), "frasil/at-rest/item/v1" || u8(table) || field(item))[0..16]
//! ```
//!
//! `K` is the store secret `s` for a device-wide table, and the log's key
//! `L` otherwise. A seal key only seals and a tag key only tags.

use crate::tables::{Scope, Table};
use frasil_base::notation::push_field;
use frasil_crypto::labels::{
    AT_REST_APP_KEY, AT_REST_ITEM, AT_REST_SCOPE, AT_REST_SEAL_KEY, AT_REST_TAG_KEY,
};
use frasil_crypto::primitives::{hkdf, hmac_sha256};
use zeroize::Zeroizing;

/// A scope tag or an item tag.
pub const TAG_BYTES: usize = 16;
/// An address: scope tag, table and item tag.
pub const ADDRESS_BYTES: usize = TAG_BYTES + 1 + TAG_BYTES;
/// The scope tag of every device-wide table.
pub const DEVICE_SCOPE: [u8; TAG_BYTES] = [0; TAG_BYTES];

/// A record's address: `scope_tag || u8(table) || item_tag`.
pub type Address = [u8; ADDRESS_BYTES];

/// `seal_key(K)`.
pub fn seal_key(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(None, key, AT_REST_SEAL_KEY)
}

/// `tag_key(K)`.
pub fn tag_key(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(None, key, AT_REST_TAG_KEY)
}

/// `app_key(K, purpose)`: a key for the application's own data, under the
/// store secret for data of no log, or under a log key for data of one log.
/// `purpose` is the application's, such as `com.example.index`. Frasil
/// derives it and hands it over, and never stores or uses it; when a log is
/// forgotten, its application keys go with it.
pub fn app_key(key: &[u8; 32], purpose: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(AT_REST_APP_KEY.len() + 4 + purpose.len());
    info.extend_from_slice(AT_REST_APP_KEY);
    push_field(&mut info, purpose);
    hkdf(None, key, &info)
}

/// `item_tag` under a tag key.
fn item_tag(tag_key: &[u8; 32], table: Table, item: &[u8]) -> [u8; TAG_BYTES] {
    let mut message = Vec::with_capacity(AT_REST_ITEM.len() + 5 + item.len());
    message.extend_from_slice(AT_REST_ITEM);
    message.push(table.code());
    push_field(&mut message, item);
    truncate(hmac_sha256(tag_key, &message))
}

fn truncate(mac: [u8; 32]) -> [u8; TAG_BYTES] {
    let mut out = [0u8; TAG_BYTES];
    out.copy_from_slice(&mac[..TAG_BYTES]);
    out
}

fn address(scope: &[u8; TAG_BYTES], table: Table, tag: &[u8; TAG_BYTES]) -> Address {
    let mut out = [0u8; ADDRESS_BYTES];
    out[..TAG_BYTES].copy_from_slice(scope);
    out[TAG_BYTES] = table.code();
    out[TAG_BYTES + 1..].copy_from_slice(tag);
    out
}

/// The seal and tag keys of one key `K`.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeKeys {
    seal: Zeroizing<[u8; 32]>,
    tag: Zeroizing<[u8; 32]>,
}

impl ScopeKeys {
    /// `seal_key(K)` and `tag_key(K)`.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            seal: seal_key(key),
            tag: tag_key(key),
        }
    }

    /// `seal_key(K)`.
    pub fn seal_key(&self) -> &[u8; 32] {
        &self.seal
    }

    /// `tag_key(K)`.
    pub fn tag_key(&self) -> &[u8; 32] {
        &self.tag
    }

    /// `item_tag` of an item of a table.
    pub fn item_tag(&self, table: Table, item: &[u8]) -> [u8; TAG_BYTES] {
        item_tag(&self.tag, table, item)
    }
}

impl core::fmt::Debug for ScopeKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ScopeKeys(..)")
    }
}

/// The keys of the store secret `s`: the device-wide tables' seal and tag
/// keys, and the tag key that makes every log's scope tag.
#[derive(Clone, PartialEq, Eq)]
pub struct StoreKeys {
    secret: Zeroizing<[u8; 32]>,
    keys: ScopeKeys,
}

impl core::fmt::Debug for StoreKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StoreKeys(..)")
    }
}

impl StoreKeys {
    /// The keys of a store secret.
    pub fn new(store_secret: &[u8; 32]) -> Self {
        Self {
            secret: Zeroizing::new(*store_secret),
            keys: ScopeKeys::new(store_secret),
        }
    }

    /// `seal_key(s)` and `tag_key(s)`.
    pub fn keys(&self) -> &ScopeKeys {
        &self.keys
    }

    /// The scope tag of a log: `HMAC(tag_key(s), "frasil/at-rest/scope/v1"
    /// || log ID)[0..16]`. It is under `s`, so the device finds a log's
    /// prefix without its log key.
    pub fn scope_tag(&self, log_id: &[u8; 32]) -> [u8; TAG_BYTES] {
        truncate(hmac_sha256(
            self.keys.tag_key(),
            &[AT_REST_SCOPE, &log_id[..]].concat(),
        ))
    }

    /// The keys of a log: its scope tag, and the seal and tag keys of its
    /// log key `L`.
    pub fn log(&self, log_id: &[u8; 32], log_key: &[u8; 32]) -> LogKeys {
        LogKeys {
            id: *log_id,
            scope_tag: self.scope_tag(log_id),
            keys: ScopeKeys::new(log_key),
            log_key: Zeroizing::new(*log_key),
        }
    }

    /// The address of an item of a device-wide table, or `None` for a log's
    /// table.
    pub fn address(&self, table: Table, item: &[u8]) -> Option<Address> {
        (table.scope() == Scope::Device)
            .then(|| address(&DEVICE_SCOPE, table, &self.keys.item_tag(table, item)))
    }

    /// `app_key(s, purpose)`, for the application's data of no log.
    pub fn app_key(&self, purpose: &[u8]) -> Zeroizing<[u8; 32]> {
        app_key(&self.secret, purpose)
    }
}

/// The keys of one log: its ID, its scope tag under `s`, and the seal and
/// tag keys of its log key `L`.
#[derive(Clone, PartialEq, Eq)]
pub struct LogKeys {
    id: [u8; 32],
    scope_tag: [u8; TAG_BYTES],
    keys: ScopeKeys,
    log_key: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for LogKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LogKeys")
            .field("id", &self.id)
            .field("scope_tag", &self.scope_tag)
            .finish_non_exhaustive()
    }
}

impl LogKeys {
    /// The log's ID.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// The log's scope tag: the 16-byte prefix every record of the log
    /// shares, so deleting the log is one range.
    pub fn scope_tag(&self) -> &[u8; TAG_BYTES] {
        &self.scope_tag
    }

    /// `seal_key(L)` and `tag_key(L)`.
    pub fn keys(&self) -> &ScopeKeys {
        &self.keys
    }

    /// `app_key(L, purpose)`, for the application's data of this log
    /// (at-rest.md, "Application keys").
    pub fn app_key(&self, purpose: &[u8]) -> Zeroizing<[u8; 32]> {
        app_key(&self.log_key, purpose)
    }

    /// The address of an item of a log's table, or `None` for a device-wide
    /// table.
    pub fn address(&self, table: Table, item: &[u8]) -> Option<Address> {
        (table.scope() == Scope::Log)
            .then(|| address(&self.scope_tag, table, &self.keys.item_tag(table, item)))
    }
}
