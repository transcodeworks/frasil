//! frasil-relay's records at rest on arbitrary bytes: a journal record, an
//! object index record, a space's index record, a move's record, a
//! departure record, a space's offset record, a drop's locator, a device
//! mailbox's item and claim, and an exchange message's record. No reader
//! panics, and a record read and written again reads back to the same
//! record.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/records.rs"]
mod records;

use libfuzzer_sys::fuzz_target;
use records::{Departure, MoveRecord, ObjectRecord, Op, Records};

fuzz_target!(|data: &[u8]| {
    if let Some(op) = Op::decode(data) {
        assert_eq!(Op::decode(&op.encode()), Some(op));
    }
    if let Some(intent) = MoveRecord::decode(data) {
        assert_eq!(MoveRecord::decode(&intent.encode()), Some(intent));
    }
    if let Some(departure) = Departure::decode(data) {
        assert_eq!(Departure::decode(&departure.encode()), Some(departure));
    }
    if let Some((shard, space)) = Records::read_offset(data) {
        assert_eq!(
            Records::read_offset(&Records::offset_record(shard, space)),
            Some((shard, space))
        );
    }
    if let Some(record) = ObjectRecord::decode(data) {
        assert_eq!(ObjectRecord::decode(&record.encode()), Some(record));
    }
    if let Some(shard) = Records::hosted_shard(data) {
        assert_eq!(
            Records::hosted_shard(&Records::hosted_record(&shard)),
            Some(shard)
        );
    }
    if let Some(space) = Records::drop_locator_space(data) {
        assert_eq!(
            Records::drop_locator_space(&Records::drop_locator_record(&space)),
            Some(space)
        );
    }
    if let Some((kept, item)) = Records::read_mailbox_record(data) {
        let again = Records::mailbox_record(kept, &item);
        assert_eq!(Records::read_mailbox_record(&again), Some((kept, item)));
    }
    if let Some((last, since)) = Records::read_claim(data) {
        assert_eq!(Records::claim_record(last, since), data);
    }
    if let Some((wall, source, message)) = Records::read_exchange_record(data) {
        let again = Records::exchange_record(wall, &source, &message);
        assert_eq!(
            Records::read_exchange_record(&again),
            Some((wall, source, message))
        );
    }
});
