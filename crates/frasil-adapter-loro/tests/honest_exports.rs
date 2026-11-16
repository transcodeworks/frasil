//! Step 4's screen reads the pinned Loro's format a second time, so it
//! must never refuse a blob that the pinned Loro exports from a document
//! (adapter-loro.md, 3.2 The checks). Documents of several peers are
//! written with every kind of container and operation, in many small
//! changes and a few large ones, merged with each other's concurrent
//! edits; every unit a writer would write of them, and their whole
//! history, passes the screen, and the metadata read through it is
//! Loro's own. Every snapshot a compactor or a history-free export writes
//! of them passes the checks of section 3.5, "Loading a state", and loads
//! to Loro's own value.

use frasil_adapter_loro::snapshot::{self, SnapshotState};
use frasil_adapter_loro::write::export_since;
use frasil_adapter_loro::{State, meta};
use loro::{
    ExportMode, LoroDoc, LoroList, LoroMap, LoroText, LoroValue, TreeID, TreeParentId,
    ValueOrContainer,
};
use proptest::prelude::*;
use std::collections::BTreeMap;

/// One step a writer takes on its own document.
#[derive(Debug, Clone)]
enum Step {
    /// Inserts text at a fraction of the text's length.
    Insert(u8, String),
    /// Deletes up to `len` characters at a fraction of the text's length.
    Delete(u8, u8),
    /// Marks or unmarks a range with one of a few styles.
    Mark(u8, u8, u8, bool),
    /// Sets a key of the map to a value, or deletes it.
    MapSet(u8, Option<Value>),
    /// Inserts a value into the list, or deletes from it.
    List(u8, Option<Value>),
    /// Inserts, moves, sets or deletes in the movable list.
    Movable(u8, u8, u8),
    /// Creates, moves or deletes a tree node.
    Tree(u8, u8, u8),
    /// Adds to the counter.
    Count(i32),
    /// Nests a container in the map, and writes into it.
    Nested(u8, String),
    /// Many operations in one change: a large insert, then deletions
    /// across it.
    Large(u16),
    /// Many small changes, one character each.
    Burst(u8),
    /// Commits, with or without a message.
    Commit(bool),
    /// Imports another writer's whole history: concurrent edits merge.
    Merge(u8),
}

/// A value of a map or list.
#[derive(Debug, Clone)]
enum Value {
    Int(i64),
    Float(f64),
    Text(String),
    Bool(bool),
    Null,
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Map(Vec<(String, Value)>),
}

impl Value {
    fn loro(&self) -> LoroValue {
        match self {
            Value::Int(v) => (*v).into(),
            Value::Float(v) => (*v).into(),
            Value::Text(v) => v.as_str().into(),
            Value::Bool(v) => (*v).into(),
            Value::Null => LoroValue::Null,
            Value::Bytes(v) => v.clone().into(),
            Value::List(v) => v.iter().map(Value::loro).collect::<Vec<_>>().into(),
            Value::Map(v) => v
                .iter()
                .map(|(k, v)| (k.clone(), v.loro()))
                .collect::<std::collections::HashMap<_, _>>()
                .into(),
        }
    }
}

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<i64>().prop_map(Value::Int),
        any::<f64>().prop_map(Value::Float),
        "\\PC{0,12}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
        prop::collection::vec(any::<u8>(), 0..16).prop_map(Value::Bytes),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::List),
            prop::collection::vec(("[a-c]{1,2}", inner), 0..4).prop_map(Value::Map),
        ]
    })
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => (any::<u8>(), "\\PC{1,8}").prop_map(|(at, s)| Step::Insert(at, s)),
        2 => (any::<u8>(), 1..6u8).prop_map(|(at, len)| Step::Delete(at, len)),
        2 => (any::<u8>(), any::<u8>(), 0..3u8, any::<bool>())
            .prop_map(|(a, b, style, on)| Step::Mark(a, b, style, on)),
        2 => (0..6u8, prop::option::of(value())).prop_map(|(k, v)| Step::MapSet(k, v)),
        2 => (any::<u8>(), prop::option::of(value())).prop_map(|(at, v)| Step::List(at, v)),
        2 => (0..4u8, any::<u8>(), any::<u8>()).prop_map(|(op, a, b)| Step::Movable(op, a, b)),
        2 => (0..3u8, any::<u8>(), any::<u8>()).prop_map(|(op, a, b)| Step::Tree(op, a, b)),
        1 => (-1000..1000i32).prop_map(Step::Count),
        1 => (0..3u8, "\\PC{1,6}").prop_map(|(k, s)| Step::Nested(k, s)),
        1 => (1..2000u16).prop_map(Step::Large),
        1 => (1..120u8).prop_map(Step::Burst),
        3 => any::<bool>().prop_map(Step::Commit),
        1 => (0..3u8).prop_map(Step::Merge),
    ]
}

/// A position in `0..=len` at fraction `at` of 255.
fn at(at: u8, len: usize) -> usize {
    len * usize::from(at) / 255
}

const STYLES: [&str; 3] = ["bold", "link", "comment"];

/// Takes one step on `doc`; operations Loro refuses, such as a move of a
/// tree node under itself, are left out.
fn take(doc: &LoroDoc, step: &Step, docs: &[LoroDoc]) {
    let text: LoroText = doc.get_text("text");
    let map: LoroMap = doc.get_map("map");
    let list: LoroList = doc.get_list("list");
    let movable = doc.get_movable_list("movable");
    let tree = doc.get_tree("tree");
    match step {
        Step::Insert(pos, s) => {
            let _ = text.insert(at(*pos, text.len_unicode()), s);
        }
        Step::Delete(pos, len) => {
            let total = text.len_unicode();
            let start = at(*pos, total);
            let _ = text.delete(start, usize::from(*len).min(total - start));
        }
        Step::Mark(a, b, style, on) => {
            let total = text.len_unicode();
            let (a, b) = (at(*a, total), at(*b, total));
            let range = a.min(b)..a.max(b);
            if !range.is_empty() {
                let key = STYLES[usize::from(*style)];
                if *on {
                    let _ = text.mark(range, key, true);
                } else {
                    let _ = text.unmark(range, key);
                }
            }
        }
        Step::MapSet(key, value) => {
            let key = format!("k{key}");
            match value {
                Some(value) => {
                    let _ = map.insert(&key, value.loro());
                }
                None => {
                    let _ = map.delete(&key);
                }
            }
        }
        Step::List(pos, value) => match value {
            Some(value) => {
                let _ = list.insert(at(*pos, list.len()), value.loro());
            }
            None if !list.is_empty() => {
                let _ = list.delete(at(*pos, list.len() - 1), 1);
            }
            None => {}
        },
        Step::Movable(op, a, b) => {
            let len = movable.len();
            match op {
                0 => {
                    let _ = movable.insert(at(*a, len), i64::from(*b));
                }
                _ if len == 0 => {}
                1 => {
                    let _ = movable.mov(at(*a, len - 1), at(*b, len - 1));
                }
                2 => {
                    let _ = movable.set(at(*a, len - 1), format!("set {b}"));
                }
                _ => {
                    let _ = movable.delete(at(*a, len - 1), 1);
                }
            }
        }
        Step::Tree(op, a, b) => {
            let nodes: Vec<TreeID> = tree
                .nodes()
                .into_iter()
                .filter(|n| !tree.is_node_deleted(n).unwrap_or(true))
                .collect();
            let pick = |x: u8| nodes.get(usize::from(x) % nodes.len().max(1)).copied();
            match (op, pick(*a), pick(*b)) {
                (0, None, _) | (0, _, None) => {
                    let _ = tree.create(TreeParentId::Root);
                }
                (0, Some(parent), _) => {
                    let _ = tree.create(parent);
                }
                (1, Some(node), Some(parent)) if node != parent => {
                    let _ = tree.mov(node, parent);
                }
                (1, Some(node), _) => {
                    let _ = tree.mov(node, TreeParentId::Root);
                }
                (2, Some(node), _) => {
                    let _ = tree.delete(node);
                }
                _ => {}
            }
        }
        Step::Count(n) => {
            let _ = doc.get_counter("counter").increment(f64::from(*n));
        }
        Step::Nested(key, s) => {
            let key = format!("nested{key}");
            let child = match map.get(&key) {
                Some(ValueOrContainer::Container(loro::Container::Text(child))) => child,
                _ => match map.insert_container(&key, LoroText::new()) {
                    Ok(child) => child,
                    Err(_) => return,
                },
            };
            let _ = child.insert(0, s);
            let _ = child.mark(0..child.len_unicode(), "bold", true);
        }
        Step::Large(n) => {
            let n = usize::from(*n);
            let _ = text.insert(at(128, text.len_unicode()), &"abcdefgh".repeat(n));
            for i in 0..n / 4 {
                let total = text.len_unicode();
                if total > 2 * i + 1 {
                    let _ = text.delete(2 * i + 1, 1);
                }
            }
            for i in 0..n / 8 {
                let _ = map.insert(&format!("large{}", i % 50), i as i64);
                let _ = list.push(i as i64);
            }
        }
        Step::Burst(n) => {
            for i in 0..*n {
                let _ = text.insert(at(i, text.len_unicode()), "x");
                doc.commit();
            }
        }
        Step::Commit(message) => {
            if *message {
                doc.set_next_commit_message("a message");
            }
            doc.commit();
        }
        Step::Merge(from) => {
            let from = &docs[usize::from(*from) % docs.len()];
            doc.commit();
            if let Ok(blob) = from.export(ExportMode::all_updates()) {
                let _ = doc.import(&blob);
            }
        }
    }
}

/// The screen passes `blob`, and the metadata read through it is Loro's
/// own.
fn screened_as_loro_reads(blob: &[u8]) -> Result<(), TestCaseError> {
    let loro = LoroDoc::decode_import_blob_meta(blob, true)
        .map_err(|e| TestCaseError::fail(format!("Loro does not read its own export: {e}")))?;
    let screened = meta::import_blob_meta(blob)
        .ok_or_else(|| TestCaseError::fail(format!("the screen refused an export: {blob:02x?}")))?;
    prop_assert_eq!(format!("{screened:?}"), format!("{loro:?}"));
    Ok(())
}

/// The checks of section 3.5 pass a state of `main`, which loads to the
/// value Loro reads from `main` itself, and that to `doc`'s, but for the
/// root containers `doc` named and wrote nothing in, which no export
/// carries.
fn loads_as_loro_reads(main: Vec<u8>, doc: &LoroDoc) -> Result<(), TestCaseError> {
    let read = LoroDoc::new();
    read.import(&main)
        .map_err(|e| TestCaseError::fail(format!("Loro does not read its own export: {e}")))?;
    prop_assert_eq!(
        written(read.get_deep_value()),
        written(doc.get_deep_value())
    );
    let state = SnapshotState {
        main,
        suggestions: Vec::new(),
        dismissed: Vec::new(),
    }
    .encode();
    snapshot::check(&state)
        .map_err(|e| TestCaseError::fail(format!("the checks refused a snapshot export: {e:?}")))?;
    let loaded = State::load(&state)
        .map_err(|e| TestCaseError::fail(format!("a snapshot export does not load: {e:?}")))?;
    prop_assert_eq!(loaded.doc().get_deep_value(), read.get_deep_value());
    Ok(())
}

/// A document's value without its empty root containers.
fn written(value: loro::LoroValue) -> loro::LoroValue {
    let loro::LoroValue::Map(map) = value else {
        return value;
    };
    let empty = |value: &loro::LoroValue| match value {
        loro::LoroValue::Map(map) => map.is_empty(),
        loro::LoroValue::List(list) => list.is_empty(),
        loro::LoroValue::String(text) => text.is_empty(),
        _ => false,
    };
    loro::LoroValue::Map(
        map.iter()
            .filter(|(_, value)| !empty(value))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<std::collections::HashMap<_, _>>()
            .into(),
    )
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn the_screen_passes_every_export(
        steps in prop::collection::vec((0..3usize, step()), 1..60),
        fractional in any::<bool>(),
        timestamps in any::<bool>(),
    ) {
        let peers = [7u64, 8, u64::MAX - 1];
        let docs: Vec<LoroDoc> = peers
            .iter()
            .map(|peer| {
                let doc = LoroDoc::new();
                doc.set_peer_id(*peer).unwrap();
                doc.set_record_timestamp(timestamps);
                if fractional {
                    doc.get_tree("tree").enable_fractional_index(0);
                }
                doc
            })
            .collect();
        // Where each writer's next unit begins, as `Writer` keeps it.
        let mut next: BTreeMap<u64, i32> = BTreeMap::new();
        for (writer, step) in &steps {
            let doc = &docs[*writer];
            let peer = peers[*writer];
            take(doc, step, &docs);
            if matches!(step, Step::Commit(_) | Step::Large(_) | Step::Burst(_) | Step::Merge(_)) {
                doc.commit();
                // A unit: the writer's operations since its last one.
                let from = next.get(&peer).copied().unwrap_or(0);
                if let Some((blob, span)) = export_since(doc, peer, from).unwrap() {
                    screened_as_loro_reads(&blob)?;
                    next.insert(peer, span.end);
                }
            }
        }
        for doc in &docs {
            doc.commit();
            // Every peer's history, merged.
            screened_as_loro_reads(&doc.export(ExportMode::all_updates()).unwrap())?;
            for (peer, end) in doc.oplog_vv().iter() {
                // One peer's whole history, as a unit of a new writer
                // would carry a restored device's operations.
                let blob = export_since(doc, *peer, 0).unwrap().unwrap().0;
                screened_as_loro_reads(&blob)?;
                let _ = end;
            }
            // The snapshots: the document's own; as a compactor builds its
            // document, by import; a history-free export of that; and a
            // compaction over a history-free base.
            let built = LoroDoc::new();
            built.import(&doc.export(ExportMode::all_updates()).unwrap()).unwrap();
            let shallow = built
                .export(ExportMode::shallow_snapshot(&built.oplog_frontiers()))
                .unwrap();
            let over_shallow = LoroDoc::new();
            over_shallow.import(&shallow).unwrap();
            for main in [
                doc.export(ExportMode::Snapshot).unwrap(),
                built.export(ExportMode::Snapshot).unwrap(),
                shallow.clone(),
                over_shallow.export(ExportMode::Snapshot).unwrap(),
            ] {
                loads_as_loro_reads(main, doc)?;
            }
        }
    }
}
