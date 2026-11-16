//! frasil-relay's library records at rest on arbitrary bytes
//! (ext-libraries.md, 2.5 What a peer keeps, with ext-deposit-tokens.md's
//! allowance windows and grants used): the first byte picks the
//! table, the next the key's length. The reader never panics, and a record
//! read and written again is the same table, key and bytes. The whole input
//! is also read as a closed space's usage record, which reads only in its
//! one encoding.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/libraries/records.rs"]
mod records;

use libfuzzer_sys::fuzz_target;
use records::Record;

const TABLES: [u8; 10] = [
    records::LIBRARY,
    records::ATTACHMENT,
    records::TICKET,
    records::DELETED,
    records::DETACHED,
    records::HOLD,
    records::COPY,
    records::HANDING_OVER,
    records::WINDOW,
    records::GRANT,
];

fuzz_target!(|data: &[u8]| {
    if let Some(usage) = records::UsageRecord::decode(data) {
        assert_eq!(usage.encode(), data, "a second encoding of a usage record");
    }
    let [pick, length, rest @ ..] = data else {
        return;
    };
    let table = TABLES[usize::from(*pick) % TABLES.len()];
    let length = usize::from(*length).min(rest.len());
    let (key, bytes) = rest.split_at(length);
    if let Some(record) = Record::decode(table, key, bytes) {
        assert_eq!(record.encode(), (table, key.to_vec(), bytes.to_vec()));
    }
});
