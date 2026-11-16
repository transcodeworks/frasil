//! frasil-space's checkpoint record on arbitrary bytes (roster.md, "The
//! checkpoint record"). The reader never panics, and what it accepts it
//! writes in an encoding that reads back and writes the same bytes again.
//! The epoch and predecessor read from keys 2 and 3 alone, as for a record
//! a later document's key holds, are those of a record that reads whole.
#![no_main]

use frasil_space::checkpoint_record::{Record, read_link};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use frasil_base::ErrorClass;
    use frasil_space::{ReadRecord, RecordFault, RecordMode, RecordSink, RecordStream};
    let oracle = Record::read(data);
    let mut split_bytes = [0; 8];
    let count = data.len().min(split_bytes.len());
    split_bytes[..count].copy_from_slice(&data[..count]);
    let split = (u64::from_le_bytes(split_bytes) % (data.len() as u64 + 1)) as usize;
    for mode in [RecordMode::Build, RecordMode::Summary] {
        let mut stream = RecordStream::new(mode);
        stream.feed(&data[..split]);
        stream.feed(&data[split..]);
        match (stream.finish(), &oracle) {
            (Ok(ReadRecord::Built(record)), Ok(want)) => assert_eq!(&record, want),
            (Ok(ReadRecord::Summary(summary)), Ok(want)) => {
                assert_eq!(summary.epoch, want.epoch);
                assert_eq!(summary.previous, want.previous);
                assert_eq!(
                    summary.compared_digest,
                    frasil_crypto::primitives::sha256(&[&want.compared().encode()])
                );
                assert_eq!(summary.compared_digest, want.compared_digest());
                assert_eq!(
                    want.record_digest(),
                    frasil_space::checkpoint_record::digest(&want.encode())
                );
                assert_eq!(want.clone().with_space_fields(&summary.space_fields), *want);
            }
            (Err(RecordFault::Class(got)), Err(want)) => assert_eq!(&got, want),
            (Err(RecordFault::Extension(link)), Err(want)) => {
                assert_eq!(*want, ErrorClass::ExtensionRequired.into());
                assert_eq!(link, read_link(data));
            }
            _ => panic!("stream and whole record disagree"),
        }
    }
    let link = read_link(data);
    if let Ok(record) = Record::read(data) {
        assert_eq!(link, Some((record.epoch, record.previous)));
        let again = record.encode();
        let read = Record::read(&again).expect("its own encoding reads");
        assert_eq!(read.encode(), again);
    }
});
