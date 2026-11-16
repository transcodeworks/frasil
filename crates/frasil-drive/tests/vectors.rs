//! `ext-drive.json`: the values, shown names, reading and changes
//! (ext-drive.md, 2.1 Values, 2.4 Error classes, 3.2 Reading the tree, 3.3
//! What a reader shows and 3.4 Changes). Each tree is built as a Loro
//! document, each node created as its parent's last child, and read or
//! changed through this crate.

use frasil_drive::values::{
    MAX_COUNT, MAX_KIND_BYTES, MAX_MEDIA_TYPE_BYTES, MAX_META_KEY_BYTES, MAX_NAME_BYTES,
    MAX_PARENTS, is_entry_id, is_handle, is_kind_string, is_media_type, is_meta_key, is_name,
    is_stream_id, read_count,
};
use frasil_drive::write::{self, NewEntry, NewKind, NewVersion};
use frasil_drive::{Entry, Error, Kind, Tree, shown_names};
use frasil_testkit::vectors;
use loro::{LoroDoc, LoroMap, LoroTree, LoroValue, TreeID, TreeParentId};
use serde_json::{Map, Value, json};

const FILE: &str = "ext-drive.json";

fn scalar(value: &Value) -> LoroValue {
    match value {
        Value::Null => LoroValue::Null,
        Value::Bool(b) => LoroValue::Bool(*b),
        Value::Number(n) if n.is_i64() => LoroValue::I64(n.as_i64().unwrap()),
        Value::Number(n) if n.is_u64() => LoroValue::Double(n.as_u64().unwrap() as f64),
        Value::Number(n) => LoroValue::Double(n.as_f64().unwrap()),
        Value::String(s) => LoroValue::from(s.as_str()),
        other => panic!("not a scalar: {other}"),
    }
}

fn to_json(value: &LoroValue) -> Value {
    match value {
        LoroValue::Null => Value::Null,
        LoroValue::Bool(b) => json!(b),
        LoroValue::I64(n) => json!(n),
        LoroValue::Double(n) => json!(n),
        LoroValue::String(s) => json!(s.to_string()),
        LoroValue::Map(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), to_json(value)))
                .collect::<Map<_, _>>(),
        ),
        LoroValue::List(items) => Value::Array(items.iter().map(to_json).collect()),
        other => panic!("not in the vectors: {other:?}"),
    }
}

/// A meta value: inside `versions` an object is a map value (ext-drive.md,
/// section 5), and a list is a list value.
fn plain(value: &Value) -> LoroValue {
    match value {
        Value::Array(items) => LoroValue::from(items.iter().map(plain).collect::<Vec<_>>()),
        Value::Object(map) => LoroValue::from(
            map.iter()
                .map(|(key, value)| (key.clone(), plain(value)))
                .collect::<std::collections::HashMap<_, _>>(),
        ),
        other => scalar(other),
    }
}

/// A map's keys from a JSON object: an object is a map container, but for
/// the records inside `versions`.
fn fill(map: &LoroMap, object: &Value) {
    for (key, value) in object.as_object().unwrap() {
        if key == "versions" && value.is_object() {
            let records = map.insert_container(key, LoroMap::new()).unwrap();
            for (handle, record) in value.as_object().unwrap() {
                records.insert(handle, plain(record)).unwrap();
            }
        } else if value.is_object() {
            let child = map.insert_container(key, LoroMap::new()).unwrap();
            fill(&child, value);
        } else {
            map.insert(key, scalar(value)).unwrap();
        }
    }
}

fn add_nodes(tree: &LoroTree, parent: TreeParentId, nodes: &Value) {
    for node in nodes.as_array().unwrap() {
        let id = tree.create(parent).unwrap();
        fill(&tree.get_meta(id).unwrap(), &node["fields"]);
        add_nodes(tree, TreeParentId::Node(id), &node["children"]);
    }
}

fn build(tree: &Value) -> LoroDoc {
    let doc = LoroDoc::new();
    let entries = doc.get_tree("entries");
    entries.enable_fractional_index(0);
    fill(&doc.get_map("document"), &tree["document"]);
    fill(&doc.get_map("purged"), &tree["purged"]);
    add_nodes(&entries, TreeParentId::Root, &tree["entries"]);
    doc.commit();
    doc
}

fn export_nodes(tree: &LoroTree, ids: Vec<TreeID>) -> Value {
    Value::Array(
        ids.into_iter()
            .map(|id| {
                json!({
                    "fields": to_json(&tree.get_meta(id).unwrap().get_deep_value()),
                    "children": export_nodes(tree, tree.children(id).unwrap_or_default()),
                })
            })
            .collect(),
    )
}

fn export(doc: &LoroDoc) -> Value {
    let entries = doc.get_tree("entries");
    json!({
        "document": to_json(&doc.get_map("document").get_deep_value()),
        "entries": export_nodes(&entries, entries.roots()),
        "purged": to_json(&doc.get_map("purged").get_deep_value()),
    })
}

fn entry_json(entry: &Entry) -> Value {
    let (stream, blob, size, media_type, doc_kind) = match &entry.kind {
        Kind::File {
            stream,
            blob,
            size,
            media_type,
            ..
        } => (
            Some(stream.clone()),
            Some(blob.clone()),
            *size,
            media_type.clone(),
            None,
        ),
        Kind::Document { stream, kind } => {
            (Some(stream.clone()), None, None, None, Some(kind.clone()))
        }
        _ => (None, None, None, None, None),
    };
    let (versions, heads) = match &entry.kind {
        Kind::File {
            versions, heads, ..
        } => (
            versions
                .iter()
                .map(|(handle, v)| {
                    let record = json!({
                        "stream": v.stream,
                        "size": v.size,
                        "at": v.at,
                        "parents": v.parents,
                    });
                    (handle.clone(), record)
                })
                .collect::<Map<_, _>>(),
            heads.clone(),
        ),
        _ => (Map::new(), Vec::new()),
    };
    json!({
        "id": entry.id,
        "kind": entry.kind.name(),
        "name": entry.name,
        "parent": entry.parent,
        "order": entry.order,
        "added": entry.added,
        "at": entry.at,
        "trashed": entry.trashed,
        "stream": stream,
        "blob": blob,
        "size": size,
        "type": media_type,
        "docKind": doc_kind,
        "meta": to_json(&LoroValue::Map(
            entry.meta.clone().into_iter().collect::<std::collections::HashMap<_, _>>().into()
        )),
        "versions": versions,
        "heads": heads,
        "conflict": entry.in_conflict(),
    })
}

#[test]
fn parameters() {
    let p: Value = vectors::family(FILE, "parameters");
    assert_eq!(p["kind"], frasil_drive::KIND);
    assert_eq!(p["containers"]["document"], frasil_drive::DOCUMENT);
    assert_eq!(p["containers"]["entries"], frasil_drive::ENTRIES);
    assert_eq!(p["containers"]["purged"], frasil_drive::PURGED);
    assert_eq!(
        p["entry_kinds"],
        json!([
            frasil_drive::FOLDER,
            frasil_drive::FILE,
            frasil_drive::DOCUMENT_KIND
        ])
    );
    assert_eq!(p["max_name_bytes"], MAX_NAME_BYTES);
    assert_eq!(p["max_kind_bytes"], MAX_KIND_BYTES);
    assert_eq!(p["max_media_type_bytes"], MAX_MEDIA_TYPE_BYTES);
    assert_eq!(p["max_meta_key_bytes"], MAX_META_KEY_BYTES);
    assert_eq!(p["max_count"], MAX_COUNT);
    assert_eq!(p["max_parents"], MAX_PARENTS);
    let classes: Vec<&str> = p["classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let ours = [
        Error::NotADrive,
        Error::InvalidValue(""),
        Error::NoSuchEntry,
        Error::EntryExists,
        Error::CannotHold,
        Error::MoveIntoItself,
        Error::AlreadyListed,
        Error::AlreadyTrashed,
        Error::NotTrashed,
        Error::NotAFile,
        Error::VersionExists,
        Error::NoSuchVersion,
        Error::VersionIsHead,
        Error::VersionHasParents,
    ]
    .map(|e| e.class());
    assert_eq!(classes, ours);
}

/// A check of one form of section 2.1.
type Form = fn(&str) -> bool;

#[test]
fn values() {
    let v: Value = vectors::family(FILE, "values");
    let checks: [(&str, Form); 7] = [
        ("names", is_name),
        ("entry_ids", is_entry_id),
        ("kind_strings", is_kind_string),
        ("stream_ids", is_stream_id),
        ("handles", is_handle),
        ("media_types", is_media_type),
        ("meta_keys", is_meta_key),
    ];
    for (family, check) in checks {
        for case in v[family].as_array().unwrap() {
            let text = case[0].as_str().unwrap();
            assert_eq!(
                check(text),
                case[1].as_bool().unwrap(),
                "{family}: {text:?}"
            );
        }
    }
    for case in v["counts"].as_array().unwrap() {
        assert_eq!(
            read_count(&scalar(&case[0])),
            case[1].as_u64(),
            "count {}",
            case[0]
        );
    }
}

#[test]
fn names() {
    let cases: Vec<Value> = vectors::family(FILE, "names");
    for case in cases {
        let items: Vec<(&str, bool)> = case["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| (item[0].as_str().unwrap(), item[1].as_bool().unwrap()))
            .collect();
        let shown = shown_names(&items);
        assert_eq!(json!(shown), case["shown"], "{}", case["description"]);
    }
}

#[test]
fn reading() {
    let cases: Vec<Value> = vectors::family(FILE, "reading");
    for case in cases {
        let what = case["description"].as_str().unwrap();
        let doc = build(&case["tree"]);
        let tree = match Tree::read(&doc) {
            Ok(tree) => tree,
            Err(error) => {
                assert_eq!(case["verdict"], error.class(), "{what}");
                continue;
            }
        };
        assert_eq!(case["verdict"], "read", "{what}");
        let entries: Vec<Value> = tree.entries().iter().map(entry_json).collect();
        assert_eq!(json!(entries), case["entries"], "{what}");
        let mut listings = Map::new();
        let listing = |folder: Option<&str>| -> Value {
            json!(
                tree.listing(folder)
                    .iter()
                    .map(|shown| json!([shown.entry.id, shown.name]))
                    .collect::<Vec<_>>()
            )
        };
        listings.insert(String::new(), listing(None));
        for entry in tree.entries().iter().filter(|e| e.kind.holds()) {
            listings.insert(entry.id.clone(), listing(Some(&entry.id)));
        }
        assert_eq!(Value::Object(listings), case["listings"], "{what}");
        let trash: Vec<&str> = tree.trash().iter().map(|e| e.id.as_str()).collect();
        assert_eq!(json!(trash), case["trash"], "{what}");
        let in_trash: Vec<&str> = tree
            .entries()
            .iter()
            .filter(|e| tree.in_trash(e))
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(json!(in_trash), case["in_trash"], "{what}");
        let conflicts: Vec<&str> = tree.conflicts().iter().map(|e| e.id.as_str()).collect();
        assert_eq!(json!(conflicts), case["conflicts"], "{what}");
        for (stream, entry) in case["streams"].as_object().unwrap() {
            assert_eq!(
                tree.stream_entry(stream).map(|e| e.id.as_str()),
                entry.as_str(),
                "{what}"
            );
        }
        let streams = tree
            .entries()
            .iter()
            .filter(|e| matches!(e.kind, Kind::Document { .. }))
            .count();
        assert!(case["streams"].as_object().unwrap().len() <= streams);
    }
}

fn text(change: &Value, key: &str) -> String {
    change[key].as_str().unwrap().to_owned()
}

fn set_blob(doc: &LoroDoc, change: &Value) -> Result<(), Error> {
    let parents: Vec<String> = change["parents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|parent| parent.as_str().unwrap().to_owned())
        .collect();
    let version = NewVersion {
        stream: change["stream"].as_str().unwrap(),
        blob: change["blob"].as_str().unwrap(),
        size: change["size"].as_u64(),
        media_type: change["type"].as_str(),
        parents: &parents,
    };
    write::set_blob(doc, &text(change, "id"), &version, change["at"].as_u64())
}

/// Applies one change of the vectors; `Ok` holds the released blobs of a
/// purge.
fn apply(doc: &LoroDoc, change: &Value) -> Result<Vec<(String, String)>, Error> {
    let at = change["at"].as_u64();
    let id = text(change, "id");
    let parent = change["parent"].as_str();
    match change["op"].as_str().unwrap() {
        "add" => {
            let (stream, blob, kind) = (
                change["stream"].as_str().unwrap_or(""),
                change["blob"].as_str().unwrap_or(""),
                change["docKind"].as_str().unwrap_or(""),
            );
            let kind = match change["kind"].as_str().unwrap() {
                "folder" => NewKind::Folder,
                "file" => NewKind::File {
                    stream,
                    blob,
                    size: change["size"].as_u64(),
                    media_type: change["type"].as_str(),
                },
                "document" => NewKind::Document { stream, kind },
                // `NewKind` admits only the kinds this document defines: an
                // application's kind is refused by construction, after
                // check 1.
                _ => {
                    Tree::read(doc)?;
                    return Err(Error::InvalidValue("an application's kind"));
                }
            };
            let name = text(change, "name");
            let new = NewEntry {
                id: &id,
                parent,
                name: &name,
                kind,
            };
            write::add(doc, &new, at).map(|()| Vec::new())
        }
        "rename" => write::rename(doc, &id, &text(change, "name"), at).map(|()| Vec::new()),
        "move" => write::move_to(doc, &id, parent, at).map(|()| Vec::new()),
        "trash" => write::trash(doc, &id, at).map(|()| Vec::new()),
        "restore" => write::restore(doc, &id, at).map(|()| Vec::new()),
        "purge" => write::purge(doc, &id, at),
        "set_meta" => write::set_meta(doc, &id, &text(change, "key"), scalar(&change["value"]))
            .map(|()| Vec::new()),
        "delete_meta" => write::delete_meta(doc, &id, &text(change, "key")).map(|_| Vec::new()),
        "set_blob" => set_blob(doc, change).map(|()| Vec::new()),
        "forget_version" => {
            write::forget_version(doc, &id, &text(change, "handle")).map(|()| Vec::new())
        }
        other => panic!("unknown change {other}"),
    }
}

#[test]
fn changes() {
    let cases: Vec<Value> = vectors::family(FILE, "changes");
    for case in cases {
        let what = case["description"].as_str().unwrap();
        let doc = build(&case["before"]);
        let before = export(&doc);
        assert_eq!(before, case["before"], "{what}: the tree as built");
        match apply(&doc, &case["change"]) {
            Ok(released) => {
                assert_eq!(case["verdict"], "applied", "{what}");
                doc.commit();
                assert_eq!(export(&doc), case["after"], "{what}");
                if case["change"]["op"] == "purge" {
                    let released: Vec<Value> =
                        released.iter().map(|(s, b)| json!([s, b])).collect();
                    assert_eq!(json!(released), case["released"], "{what}");
                }
            }
            Err(error) => {
                assert_eq!(case["verdict"], error.class(), "{what}");
                doc.commit();
                assert_eq!(export(&doc), before, "{what}: nothing is written");
            }
        }
    }
}

fn heads_of(doc: &LoroDoc) -> Value {
    let tree = Tree::read(doc).unwrap();
    Value::Object(
        tree.entries()
            .iter()
            .filter_map(|entry| match &entry.kind {
                Kind::File { heads, .. } => Some((entry.id.clone(), json!(heads))),
                _ => None,
            })
            .collect(),
    )
}

/// Two writers from one document, each making one change, and merged in
/// both orders: Loro's order keeps one `blob`, and both records.
fn concurrent(case: &Value) {
    let what = case["description"].as_str().unwrap();
    let changes = case["changes"].as_array().unwrap();
    let start = build(&case["before"]);
    let bytes = start.export(loro::ExportMode::all_updates()).unwrap();
    let writers: Vec<LoroDoc> = changes
        .iter()
        .enumerate()
        .map(|(index, change)| {
            let doc = LoroDoc::new();
            doc.set_peer_id(100 + index as u64).unwrap();
            doc.import(&bytes).unwrap();
            set_blob(&doc, change).unwrap();
            doc.commit();
            doc
        })
        .collect();
    let merge = |order: [usize; 2]| {
        let merged = LoroDoc::new();
        for index in order {
            let update = writers[index].export(loro::ExportMode::all_updates());
            merged.import(&update.unwrap()).unwrap();
        }
        merged
    };
    let (one, two) = (merge([0, 1]), merge([1, 0]));
    let kept: Vec<&str> = case["merged"]
        .as_array()
        .unwrap()
        .iter()
        .map(|order| order["blob"].as_str().unwrap())
        .collect();
    let tree = Tree::read(&one).unwrap();
    let entry = tree.entry(changes[0]["id"].as_str().unwrap()).unwrap();
    let Kind::File { blob, heads, .. } = &entry.kind else {
        panic!("{what}: not a file");
    };
    assert!(kept.contains(&blob.as_str()), "{what}: one blob stays");
    assert_eq!(json!(heads), case["merged"][0]["heads"], "{what}");
    assert!(entry.in_conflict(), "{what}");
    assert_eq!(export(&one), export(&two), "{what}: every replica alike");
}

#[test]
fn versions() {
    let cases: Vec<Value> = vectors::family(FILE, "versions");
    for case in cases {
        let what = case["description"].as_str().unwrap();
        if case.get("merged").is_some() {
            concurrent(&case);
            continue;
        }
        let doc = build(&case["before"]);
        let before = export(&doc);
        assert_eq!(before, case["before"], "{what}: the tree as built");
        let outcome = case["changes"]
            .as_array()
            .unwrap()
            .iter()
            .try_for_each(|change| {
                let done = apply(&doc, change).map(drop);
                doc.commit();
                done
            });
        match outcome {
            Ok(()) => {
                assert_eq!(case["verdict"], "applied", "{what}");
                assert_eq!(export(&doc), case["after"], "{what}");
                assert_eq!(heads_of(&doc), case["heads"], "{what}");
            }
            Err(error) => {
                assert_eq!(case["verdict"], error.class(), "{what}");
                assert_eq!(export(&doc), before, "{what}: nothing is written");
            }
        }
    }
}
