//! frasil-relay's shard objects in the bucket on arbitrary bytes: the
//! manifest, a log batch, a node's record and the active node's, and the
//! reading and position a working copy keeps; and the bytes as a key under
//! a shard's root. No
//! reader panics, and what each accepts is the one encoding of what it
//! returns.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/shards/format.rs"]
mod format;

use format::{Active, Batch, Kind, Manifest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(manifest) = Manifest::decode(data) {
        assert_eq!(manifest.encode(), data, "a second encoding of a manifest");
        assert!(manifest.next >= 1);
        assert!(manifest.runs.iter().all(|run| run.epoch < manifest.epoch));
    }
    if let Some(batch) = Batch::decode(data) {
        assert_eq!(batch.encode(), data, "a second encoding of a batch");
    }
    if let Some(epoch) = format::decode_node(data) {
        assert_eq!(format::encode_node(epoch), data);
    }
    if let Some(active) = Active::decode(data) {
        assert_eq!(
            active.encode(),
            data,
            "a second encoding of the active node"
        );
    }
    if let Some(reading) = format::decode_reading(data) {
        assert_eq!(format::encode_reading(&reading), data);
    }
    if let Some(position) = format::decode_position(data) {
        assert_eq!(format::encode_position(position), data);
    }
    if let Ok(key) = std::str::from_utf8(data)
        && let Some((kind, position)) = format::parse_key(key)
    {
        let again = match kind {
            Kind::Log => format::log_key(position),
            Kind::Snapshot => format::snapshot_key(position),
            Kind::Manifest => format::manifest_key(position.0, position.1),
        };
        assert_eq!(again, key);
    }
});
