//! `adapter-blobs.json`: every family, as `claims.txt` lists them.

use frasil_adapter::{
    Adapter, Capabilities, Capability, Context, Locator, Mode, Outcome, Role, StreamUnit,
};
use frasil_adapter_blobs::{Blobs, Content, State};
use frasil_base::errors::Class;
use frasil_testkit::{hex, vectors};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const FILE: &str = "adapter-blobs.json";

/// The file names no space or stream: a Blobs unit's content and state
/// read neither, so any will do.
const SPACE: [u8; 32] = [0x5a; 32];
const STREAM: [u8; 16] = [0x57; 16];

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct UnitRow {
    name: String,
    #[allow(dead_code)]
    note: String,
    #[serde(deserialize_with = "hex::array")]
    id: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    author: [u8; 32],
    clock: u64,
    objects: Vec<String>,
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
}

fn locators(texts: &[String]) -> Vec<Locator> {
    texts
        .iter()
        .map(|text| hex::decode_array(text).unwrap())
        .collect()
}

fn unit_rows() -> Vec<UnitRow> {
    vectors::family(FILE, "units")
}

fn context(id: [u8; 32], author: [u8; 32], objects: Vec<Locator>, role: Role) -> Context {
    Context::new(SPACE, STREAM, id, author, 1, 1, role).with_objects(objects)
}

fn stream_unit(row: &UnitRow) -> StreamUnit {
    StreamUnit {
        context: context(row.id, row.author, locators(&row.objects), Role::Log),
        content: row.content.clone(),
        valid: true,
    }
}

fn capabilities(rows: &[(String, u64)]) -> Capabilities {
    rows.iter()
        .map(|(name, mode)| Capability::new(name.clone(), Mode::from_code(*mode).unwrap()))
        .collect()
}

/// The units applied in the vectors' order.
fn final_state() -> State {
    let units: Vec<StreamUnit> = unit_rows().iter().map(stream_unit).collect();
    Blobs::new().rebuild(None, &units).unwrap()
}

#[test]
fn units() {
    let blobs = Blobs::new();
    let rows = unit_rows();
    assert_eq!(rows.len(), 3);
    for row in &rows {
        let unit = stream_unit(row);
        let change = blobs
            .decode(&row.content, &unit.context)
            .unwrap_or_else(|class| panic!("{}: {class}", row.name));
        let Content::Change(read) = &change else {
            panic!("{}: not a change", row.name);
        };
        assert_eq!(read.clock, row.clock, "{}", row.name);
        let listed: BTreeSet<Locator> = locators(&row.objects).into_iter().collect();
        assert_eq!(read.objects(), listed, "{}", row.name);
        assert_eq!(blobs.encode(&change), row.content, "{}", row.name);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MergeOrders {
    orders: Vec<Vec<String>>,
    #[serde(deserialize_with = "hex::bytes")]
    snapshot: Vec<u8>,
}

#[test]
fn merge_orders() {
    let expected: MergeOrders = vectors::family(FILE, "merge_orders");
    assert_eq!(expected.orders.len(), 6);
    let rows: BTreeMap<String, UnitRow> = unit_rows()
        .into_iter()
        .map(|row| (row.name.clone(), row))
        .collect();
    let blobs = Blobs::new();
    for order in &expected.orders {
        let mut state = blobs.empty();
        let mut waited = false;
        for name in order {
            match blobs.receive(&mut state, &stream_unit(&rows[name])) {
                Outcome::Applied => {}
                Outcome::Waiting(class) => {
                    // A unit ahead of the floor waits, and applies once the
                    // units below it arrive.
                    assert_eq!(class.name(), "ClockAhead");
                    waited = true;
                }
                other => panic!("{order:?} {name}: {other:?}"),
            }
        }
        assert!(blobs.held(&state).is_empty(), "{order:?}");
        assert_eq!(waited, order[0] == "b3", "{order:?}");
        assert_eq!(
            hex::encode(state.to_bytes(false)),
            hex::encode(&expected.snapshot),
            "{order:?}"
        );
    }
    let loaded = blobs.load(&expected.snapshot).unwrap();
    assert_eq!(loaded.to_bytes(false), expected.snapshot);
    assert_eq!(blobs.compact(&final_state()).state, expected.snapshot);
}

#[test]
fn history_free() {
    let expected: String = vectors::family(FILE, "history_free");
    let blobs = Blobs::new();
    assert_eq!(
        hex::encode(blobs.export_history_free(&final_state()).unwrap()),
        expected
    );
    let loaded = blobs.load(&hex::decode(&expected).unwrap()).unwrap();
    assert_eq!(hex::encode(loaded.to_bytes(false)), expected);
}

#[test]
fn snapshot_unit_objects() {
    let expected: Vec<String> = vectors::family(FILE, "snapshot_unit_objects");
    let expected: BTreeSet<Locator> = locators(&expected).into_iter().collect();
    let state = final_state();
    assert_eq!(state.objects(), expected);
    let compaction = Blobs::new().compact(&state);
    assert_eq!(compaction.objects, expected);
    assert!(compaction.metadata.is_empty());
    let ids: BTreeSet<[u8; 32]> = unit_rows().iter().map(|row| row.id).collect();
    assert_eq!(compaction.included, ids);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refusal {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
    objects: Vec<String>,
    class: String,
}

#[test]
fn content_refusals() {
    let rows: Vec<Refusal> = vectors::family(FILE, "content_refusals");
    assert_eq!(rows.len(), 4);
    let any = &unit_rows()[0];
    for row in rows {
        let context = context(any.id, any.author, locators(&row.objects), Role::Log);
        let class = Blobs::new()
            .decode(&row.content, &context)
            .map(|_| ())
            .expect_err(&row.name);
        assert_eq!(class.name(), row.class, "{}", row.name);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactionCheck {
    writer: String,
    capabilities: Vec<(String, u64)>,
    adapter: String,
    snapshot_unit: String,
}

#[test]
fn compaction_checks() {
    let rows: Vec<CompactionCheck> = vectors::family(FILE, "compaction_checks");
    assert_eq!(rows.len(), 3);
    let any = &unit_rows()[0];
    let blobs = Blobs::new();
    for row in rows {
        assert_eq!(row.adapter, Blobs::TYPE);
        let context = context(any.id, any.author, Vec::new(), Role::Snapshot)
            .with_capabilities(capabilities(&row.capabilities));
        let verdict = match blobs.decode(&[], &context) {
            Ok(_) => "accepted",
            Err(class) => class.name(),
        };
        assert_eq!(verdict, row.snapshot_unit, "{}", row.writer);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceObject {
    #[serde(deserialize_with = "hex::array")]
    id: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    object_key: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    locator: Locator,
    #[serde(deserialize_with = "hex::bytes")]
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceUnit {
    #[serde(deserialize_with = "hex::array")]
    space: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    handle: [u8; 16],
    objects: Vec<String>,
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct References {
    #[serde(deserialize_with = "hex::array")]
    source_space: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    source_content_key: [u8; 32],
    #[serde(deserialize_with = "hex::bytes")]
    key_reference: Vec<u8>,
    chunk_bytes: usize,
    #[serde(deserialize_with = "hex::bytes")]
    plaintext: Vec<u8>,
    object: ReferenceObject,
    unit: ReferenceUnit,
    #[serde(deserialize_with = "hex::bytes")]
    opened: Vec<u8>,
    refusals: Vec<Refusal>,
}

#[test]
fn references() {
    use frasil_events::EventId;
    use frasil_units::objects::{ObjectKeys, read_object_with_key_chunked, seal_object_chunked};
    let v: References = vectors::family(FILE, "references");
    // The object, sealed once in its source, and its key.
    let source = EventId(v.source_space);
    let sealed = seal_object_chunked(
        &source,
        &v.source_content_key,
        &v.key_reference,
        &v.plaintext,
        v.chunk_bytes,
    )
    .unwrap();
    assert_eq!(sealed.id, v.object.id);
    assert_eq!(sealed.locator, v.object.locator);
    assert_eq!(sealed.bytes, v.object.bytes);
    let object_key = ObjectKeys::of(&v.source_content_key).object_key(&sealed.id);
    assert_eq!(*object_key, v.object.object_key);
    // The referencing space's unit: a put of a reference, listing the
    // locator.
    let blobs = Blobs::new();
    let any = &unit_rows()[0];
    let context = Context::new(v.unit.space, STREAM, any.id, any.author, 1, 1, Role::Log)
        .with_objects(locators(&v.unit.objects));
    let Content::Change(change) = blobs.decode(&v.unit.content, &context).unwrap() else {
        panic!("not a change");
    };
    assert_eq!(
        blobs.encode(&Content::Change(change.clone())),
        v.unit.content
    );
    let entry = change
        .ops
        .iter()
        .find(|op| op.handle == v.unit.handle)
        .and_then(|op| op.entry.clone())
        .expect("the reference");
    let reference = entry.reference.clone().expect("keys 6 and 7");
    assert_eq!(reference.source, v.source_space);
    assert_eq!(reference.object_key, v.object.object_key);
    assert_eq!(entry.object, v.object.locator);
    assert_eq!(entry.key, v.key_reference);
    // A reader of the referencing space opens it with the key alone.
    let opened = read_object_with_key_chunked(
        &v.object.bytes,
        &EventId(reference.source),
        &reference.object_key,
        &entry.object,
        v.chunk_bytes,
    )
    .unwrap();
    assert_eq!(opened, v.opened);
    assert_eq!(opened, v.plaintext);
    // A state that holds the reference lists its object, for compaction.
    let state = blobs.rebuild(
        None,
        &[StreamUnit {
            context,
            content: v.unit.content.clone(),
            valid: true,
        }],
    );
    assert!(state.unwrap().objects().contains(&v.object.locator));
    assert_eq!(v.refusals.len(), 2);
    for row in &v.refusals {
        let context = Context::new(v.unit.space, STREAM, any.id, any.author, 1, 1, Role::Log)
            .with_objects(locators(&row.objects));
        let class = blobs
            .decode(&row.content, &context)
            .map(|_| ())
            .expect_err(&row.name);
        assert_eq!(class.name(), row.class, "{}", row.name);
    }
}
