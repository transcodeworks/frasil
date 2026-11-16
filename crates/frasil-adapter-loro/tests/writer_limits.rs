//! A writer runs step 4 of the checks on what it is about to sign
//! (adapter-loro.md, 3.1 Writing): operations past its limits are written in
//! more than one unit, each of which passes, or not at all.

use frasil_adapter_loro::write::{WriteError, Writer, export_since};
use frasil_adapter_loro::{BlobMeta, Content, Incarnation};
use loro::LoroDoc;

fn incarnation() -> Incarnation {
    Incarnation {
        space: [1; 32],
        stream: [2; 16],
        author: [3; 32],
        incarnation: 1,
    }
}

#[test]
fn an_update_over_a_limit_is_divided_into_units_that_each_pass() {
    let doc = LoroDoc::new();
    let mut writer = Writer::new(&doc, incarnation()).unwrap();
    let peer = incarnation().peer();
    // One commit of more operations than a unit may carry: 2^20 + 16 rows
    // in the operations tables.
    let map = doc.get_map("m");
    for i in 0..(1i64 << 20) + 16 {
        map.insert(&format!("k{}", i % 1024), i).unwrap();
    }
    doc.commit();
    let end = doc.oplog_vv().get(&peer).copied().unwrap();
    // One blob of them all: every replica refuses it.
    let (whole, _) = export_since(&doc, peer, 0).unwrap().unwrap();
    assert!(BlobMeta::read(&whole).is_none());
    // As one unit, the writer does not write them.
    let mut single = writer;
    assert!(matches!(
        single.edit(&doc),
        Err(WriteError::OverLimit { .. })
    ));
    // As edits, it divides them.
    let contents = writer.edits(&doc).unwrap();
    assert!(contents.len() >= 2, "{} units", contents.len());
    let replica = LoroDoc::new();
    let mut next = 0;
    for content in &contents {
        let Content::Ops { blob, .. } = content else {
            panic!("an edit");
        };
        let meta = BlobMeta::read(blob).expect("each unit passes step 4");
        let span = meta.spans[&peer];
        assert_eq!(span.start, next);
        next = span.end;
        replica.import(blob).unwrap();
    }
    assert_eq!(next, end);
    assert_eq!(replica.get_deep_value(), doc.get_deep_value());
    assert!(writer.edits(&doc).unwrap().is_empty());
}
