//! Sealing and opening a record (at-rest.md, "Keys, addresses and records",
//! "Opening a record").
//!
//! ```text
//! record    = u8(1) || nonce (24) || XChaCha20-Poly1305(seal_key(K), nonce, plaintext, aad)
//! plaintext = field(item) || value
//! aad       = "frasil/at-rest/record/v1" || u8(1) || address
//! ```
//!
//! The address is associated data, so a record moved to another address,
//! table, log or item does not open.

use crate::keys::{ADDRESS_BYTES, Address, DEVICE_SCOPE, LogKeys, ScopeKeys, StoreKeys, TAG_BYTES};
use crate::tables::{Scope, Table, TableValue, check_item, check_object_value};
use core::ops::Range;
use frasil_base::ErrorClass;
use frasil_base::notation::{push_field, split_field};
use frasil_crypto::labels::AT_REST_RECORD;
use frasil_crypto::primitives::{
    xchacha20poly1305_open, xchacha20poly1305_open_in_place, xchacha20poly1305_seal_in_place,
};

/// The record's version, its first byte.
pub const VERSION: u8 = 0x01;
/// A record's overhead: the version, the nonce and the tag.
pub const RECORD_OVERHEAD: usize = 1 + 24 + 16;
/// The shortest record: its overhead and an item's 4-byte length.
pub const MIN_RECORD: usize = RECORD_OVERHEAD + 4;

/// The associated data of a record at an address.
pub fn record_aad(address: &[u8]) -> Vec<u8> {
    [AT_REST_RECORD, &[VERSION], address].concat()
}

/// A sealed record and its address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRecord {
    /// The record's address.
    pub address: Address,
    /// The record.
    pub record: Vec<u8>,
}

/// An opened record: its table, its item, and its value as the table says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The record's table.
    pub table: Table,
    /// What the record is about: an event ID, an object part, a key's name.
    pub item: Vec<u8>,
    /// The value.
    pub value: TableValue,
}

fn scope_keys<'a>(store: &'a StoreKeys, log: Option<&'a LogKeys>) -> &'a ScopeKeys {
    log.map_or(store.keys(), LogKeys::keys)
}

/// Seals a record of a table, with its nonce given: `log` names the log of
/// a log's table, and is `None` for a device-wide table.
///
/// Only the device produces a record that it opens, so this refuses what
/// [`open_record`] would. A caller draws the nonce with
/// `frasil_crypto::random_bytes`, anew for every seal.
///
/// # Errors
///
/// `Malformed` if the table's scope is not the one named, the item does
/// not follow the table's rule, or the value does not parse exactly.
pub fn seal_record_with(
    store: &StoreKeys,
    log: Option<&LogKeys>,
    table: Table,
    item: &[u8],
    value: &[u8],
    nonce: &[u8; 24],
) -> Result<SealedRecord, ErrorClass> {
    let address = match log {
        None => store.address(table, item),
        Some(log) => log.address(table, item),
    }
    .ok_or(ErrorClass::Malformed)?;
    // Only what would open: an object's value is checked as it stands,
    // with no copy.
    if table == Table::Object {
        check_item(table, item)?;
        check_object_value(item, value)?;
    } else {
        TableValue::read(table, item, value, log.map(LogKeys::id))?;
    }
    // The record is built in one buffer and sealed where it lies.
    let mut record = Vec::with_capacity(RECORD_OVERHEAD + 4 + item.len() + value.len());
    record.push(VERSION);
    record.extend_from_slice(nonce);
    push_field(&mut record, item);
    record.extend_from_slice(value);
    xchacha20poly1305_seal_in_place(
        scope_keys(store, log).seal_key(),
        nonce,
        &record_aad(&address),
        &mut record,
        25,
    );
    Ok(SealedRecord { address, record })
}

/// `open(address, record, log or none)`, in order: `log` is the log the
/// caller reads, and is `None` for a device-wide table.
///
/// A device does not use a record it cannot open, and does not delete it
/// on its own. `UnsupportedVersion` is a newer device's record; `Decrypt`
/// and `Malformed` are damage or tampering, which the client reports while
/// treating the record as missing.
///
/// # Errors
///
/// 1. `Malformed` if the address is not 33 bytes or names no table;
/// 2. `Malformed` if the table is device-wide but a log is named, or the
///    other way round, or the scope tag is not 16 zero bytes or the log's;
/// 3. `Malformed` if the record is empty, `UnsupportedVersion` if its
///    version is not 1;
/// 4. `Malformed` if it is shorter than 45 bytes;
/// 5. `Decrypt` if the AEAD does not open;
/// 6. `Malformed` if the plaintext does not read as `field(item) ||
///    value`, the item does not follow its table's rule, or its item tag is
///    not the address's;
/// 7. `Malformed` if the value does not parse exactly.
pub fn open_record(
    store: &StoreKeys,
    log: Option<&LogKeys>,
    address: &[u8],
    record: &[u8],
) -> Result<Opened, ErrorClass> {
    let malformed = ErrorClass::Malformed;
    // Step 1.
    if address.len() != ADDRESS_BYTES {
        return Err(malformed);
    }
    let table = Table::from_code(address[TAG_BYTES]).ok_or(malformed)?;
    // Step 2.
    let scope = &address[..TAG_BYTES];
    let in_scope = match (table.scope(), log) {
        (Scope::Device, None) => scope == DEVICE_SCOPE,
        (Scope::Log, Some(log)) => scope == log.scope_tag(),
        _ => false,
    };
    if !in_scope {
        return Err(malformed);
    }
    // Step 3.
    let Some(&version) = record.first() else {
        return Err(malformed);
    };
    if version != VERSION {
        return Err(ErrorClass::UnsupportedVersion);
    }
    // Step 4.
    if record.len() < MIN_RECORD {
        return Err(malformed);
    }
    // Step 5.
    let keys = scope_keys(store, log);
    let nonce: &[u8; 24] = record[1..25].try_into().expect("24 bytes");
    let plaintext =
        xchacha20poly1305_open(keys.seal_key(), nonce, &record_aad(address), &record[25..])?;
    // Step 6.
    let (item, value) = split_field(&plaintext)?;
    check_item(table, item)?;
    if keys.item_tag(table, item)[..] != address[TAG_BYTES + 1..] {
        return Err(malformed);
    }
    // Step 7.
    let value = TableValue::read(table, item, value, log.map(LogKeys::id))?;
    Ok(Opened {
        table,
        item: item.to_vec(),
        value,
    })
}

/// An `object` record opened in place: the record's own buffer, whose
/// plaintext holds the item and the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedObject {
    bytes: Vec<u8>,
    item: Range<usize>,
    value: Range<usize>,
}

impl OpenedObject {
    /// The item: the object ID and the part's index.
    pub fn item(&self) -> &[u8] {
        &self.bytes[self.item.clone()]
    }

    /// The value: a header, or a chunk's sealed bytes.
    pub fn value(&self) -> &[u8] {
        &self.bytes[self.value.clone()]
    }
}

/// [`open_record`] for a record of the `object` table, in the record's own
/// buffer: the same steps and verdicts, with no copy of the value. An
/// object's parts are sealed already, so the plaintext needs no zeroizing.
///
/// # Errors
///
/// As [`open_record`]; `Malformed` for a record of another table.
pub fn open_object_record(
    store: &StoreKeys,
    log: &LogKeys,
    address: &[u8],
    mut record: Vec<u8>,
) -> Result<OpenedObject, ErrorClass> {
    let malformed = ErrorClass::Malformed;
    // Step 1.
    if address.len() != ADDRESS_BYTES {
        return Err(malformed);
    }
    let table = Table::from_code(address[TAG_BYTES]).ok_or(malformed)?;
    // Step 2.
    if table != Table::Object || address[..TAG_BYTES] != log.scope_tag()[..] {
        return Err(malformed);
    }
    // Step 3.
    let Some(&version) = record.first() else {
        return Err(malformed);
    };
    if version != VERSION {
        return Err(ErrorClass::UnsupportedVersion);
    }
    // Step 4.
    if record.len() < MIN_RECORD {
        return Err(malformed);
    }
    // Step 5.
    let keys = scope_keys(store, Some(log));
    let nonce: [u8; 24] = record[1..25].try_into().expect("24 bytes");
    let length = xchacha20poly1305_open_in_place(
        keys.seal_key(),
        &nonce,
        &record_aad(address),
        &mut record[25..],
    )?;
    let plaintext = &record[25..25 + length];
    // Step 6.
    let (item, value) = split_field(plaintext)?;
    check_item(table, item)?;
    if keys.item_tag(table, item)[..] != address[TAG_BYTES + 1..] {
        return Err(malformed);
    }
    // Step 7.
    check_object_value(item, value)?;
    let value_start = 25 + length - value.len();
    let item_start = value_start - item.len();
    Ok(OpenedObject {
        item: item_start..value_start,
        value: value_start..25 + length,
        bytes: record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_record_opens_in_place_as_any_record() {
        let store = StoreKeys::new(&[1; 32]);
        let log = store.log(&[2; 32], &[3; 32]);
        let chunk = |part: u32| [&[4u8; 32][..], &part.to_be_bytes()].concat();
        let sealed = seal_record_with(
            &store,
            Some(&log),
            Table::Object,
            &chunk(1),
            &[5; 64],
            &[6; 24],
        )
        .unwrap();
        let opened = open_record(&store, Some(&log), &sealed.address, &sealed.record).unwrap();
        let in_place =
            open_object_record(&store, &log, &sealed.address, sealed.record.clone()).unwrap();
        assert_eq!(opened.value, TableValue::Object(in_place.value().to_vec()));
        assert_eq!(opened.item, in_place.item());
        let mut altered = sealed.record.clone();
        altered[30] ^= 1;
        let other = store.log(&[2; 32], &[7; 32]);
        for (log, record) in [(&log, altered), (&other, sealed.record.clone())] {
            assert_eq!(
                open_object_record(&store, log, &sealed.address, record.clone()).err(),
                open_record(&store, Some(log), &sealed.address, &record).err()
            );
        }
        let outbox = seal_record_with(
            &store,
            Some(&log),
            Table::Outbox,
            &[&[4u8; 32][..], &1u64.to_be_bytes()].concat(),
            &[5; 32],
            &[6; 24],
        )
        .unwrap();
        assert_eq!(
            open_object_record(&store, &log, &outbox.address, outbox.record),
            Err(ErrorClass::Malformed)
        );
    }

    #[test]
    fn a_record_opens_only_where_it_was_sealed() {
        let store = StoreKeys::new(&[1; 32]);
        let log = store.log(&[2; 32], &[3; 32]);
        let sealed = seal_record_with(
            &store,
            Some(&log),
            Table::Outbox,
            &[&[4u8; 32][..], &1u64.to_be_bytes()].concat(),
            &[5; 32],
            &[6; 24],
        )
        .unwrap();
        let opened = open_record(&store, Some(&log), &sealed.address, &sealed.record).unwrap();
        assert_eq!(opened.value, TableValue::Outbox([5; 32]));
        assert_eq!(
            open_record(&store, None, &sealed.address, &sealed.record),
            Err(ErrorClass::Malformed)
        );
        let other = store.log(&[2; 32], &[7; 32]);
        assert_eq!(
            open_record(&store, Some(&other), &sealed.address, &sealed.record),
            Err(ErrorClass::Decrypt)
        );
    }

    #[test]
    fn sealing_refuses_what_would_not_open() {
        let store = StoreKeys::new(&[1; 32]);
        let log = store.log(&[2; 32], &[3; 32]);
        for (log, table, item, value) in [
            (Some(&log), Table::Head, &[][..], &[][..]),
            (None, Table::Outbox, &[0; 40][..], &[0; 32][..]),
            (None, Table::Epoch, &[][..], &[0; 7][..]),
        ] {
            assert_eq!(
                seal_record_with(&store, log, table, item, value, &[0; 24]),
                Err(ErrorClass::Malformed)
            );
        }
    }
}
