//! Differential coverage for streaming record objects.
#![no_main]
use frasil_events::EventId;
use frasil_units::limits::CHUNK_BYTES;
use frasil_units::objects::{Header, plain_length};
use frasil_units::record::{
    RecordBinding, RecordKey, read_record_object_chunked, seal_record_chunked,
};
use frasil_units::{RecordObjectOutcome, RecordObjectReader};
use libfuzzer_sys::fuzz_target;

struct Collect(Vec<u8>);
impl frasil_space::record_stream::RecordSink for Collect {
    fn feed(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&mode, input)) = input.split_first() else {
        return;
    };
    let chunk = [256, 1024, CHUNK_BYTES][mode as usize % 3];
    let space = EventId([1; 32]);
    let key = [2; 32];
    let own = frasil_keys::SelfRef::new(frasil_crypto::device::DeviceId([3; 32]), 1);
    let Ok(sealed) = seal_record_chunked(&space, &key, own, input, chunk) else {
        return;
    };
    let mut binding: RecordBinding = sealed.binding;
    let mut data = sealed.object.bytes;
    // Exercise both arbitrary encodings and authenticated, structured objects.
    if mode & 4 != 0 {
        data = input.to_vec();
    }
    if mode & 32 != 0 {
        if let Some(byte) = data.last_mut() {
            *byte ^= 1;
        }
    }
    if mode & 8 != 0 {
        binding.locator[32..].copy_from_slice(&frasil_crypto::primitives::sha256(&[&data]));
    }
    if mode & 16 != 0 {
        binding.digest[0] ^= 1;
    }
    let object_key = frasil_units::record::record_object_key(&key, &binding.locator);
    let opening = match mode % 5 {
        0 => None,
        1 => Some(RecordKey::Object(&object_key)),
        2 => Some(RecordKey::Checkpoint(&[4; 32])),
        _ => Some(RecordKey::Checkpoint(&key)),
    };
    let oracle = read_record_object_chunked(&data, &space, opening, &binding, chunk);
    // The streaming interface starts after the stored framing was split.
    let Some((length, rest)) = data.split_first_chunk::<4>() else {
        return;
    };
    let n = u32::from_be_bytes(*length) as usize;
    if n > rest.len() {
        return;
    }
    let (header, mut rest) = rest.split_at(n);
    let mut reader = RecordObjectReader::new_chunked(header, &space, opening, &binding, chunk);
    let size = Header::read(header).ok().map(|h| h.size);
    let count = reader.chunk_count();
    let mut sink = Collect(Vec::new());
    let mut index = 0;
    while !rest.is_empty() {
        let length = size
            .map(|s| plain_length(s, chunk as u64, index) as usize + 40)
            .unwrap_or(rest.len())
            .min(rest.len());
        reader.feed(index, &rest[..length], &mut sink);
        rest = &rest[length..];
        index += 1;
    }
    let got = reader.finish();
    let expected = if count.is_some_and(|n| index < n)
        || frasil_crypto::primitives::sha256(&[&data]) != binding.locator[32..]
    {
        RecordObjectOutcome::NotTheObject
    } else {
        match oracle {
            Ok(plain) => {
                assert_eq!(sink.0, plain);
                RecordObjectOutcome::Opened
            }
            Err(error) => RecordObjectOutcome::Refused(error),
        }
    };
    assert_eq!(got, expected);
});
