//! ext-space-files.json: the records, the way in, appends and the refusals
//! of the file itself. The files and the roads in, which need a replica,
//! are the frasil crate's.

use frasil_base::ErrorClass;
use frasil_base::errors::Class as _;
use frasil_events::EventId;
use frasil_space_file::file::{Refusal, Writer, read, sniff};
use frasil_space_file::record::{History, Record, Section, WayIn};
use frasil_space_file::way_in::{Fragment, WayInBody, open_way_in, seal_way_in_with, sealing_key};
use frasil_space_file::{MAX_RECORD_BYTES, SpaceFileClass};
use frasil_testkit::hex;
use serde_json::Value as Json;

const FILE: &str = "ext-space-files.json";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex")
}

fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

fn text(value: &Json) -> &str {
    value.as_str().expect("text")
}

fn refusal_name(refusal: &Refusal) -> &'static str {
    refusal.name()
}

#[test]
fn records() {
    let rows = family("records");
    for row in rows.as_array().unwrap() {
        let name = text(&row["name"]);
        let code = row["type"].as_u64().unwrap();
        let Some(framed) = row.get("record") else {
            // The body at the limit: rebuilt from its description.
            let section = &row["section"];
            let record = Record::Section(Section {
                kind: text(&section["kind"]).to_owned(),
                name: text(&section["name"]).to_owned(),
                bytes: vec![0; section["zero_bytes"].as_u64().unwrap() as usize],
            });
            let framed = record
                .encode()
                .unwrap_or_else(|class| panic!("{name}: {class}"));
            assert_eq!(framed.len() - 4, MAX_RECORD_BYTES, "{name}");
            assert_eq!(
                frasil_crypto::primitives::sha256(&[&framed]).to_vec(),
                bytes(&row["record_sha256"]),
                "{name}"
            );
            continue;
        };
        let framed = bytes(framed);
        let body = &framed[4..];
        assert_eq!(Record::type_of(body), Ok(code), "{name}");
        let record = Record::read(body).unwrap_or_else(|class| panic!("{name}: {class}"));
        assert_eq!(record.type_code(), code, "{name}");
        // An ignorable record's body is skipped, not kept: it has no
        // encoding of its own.
        if !matches!(record, Record::Ignored(_)) {
            assert_eq!(record.encode().unwrap(), framed, "{name}: one encoding");
        }
        let read = &row["read"];
        match &record {
            Record::Manifest(manifest) => {
                assert_eq!(manifest.space, EventId(array(&read["space"])), "{name}");
                assert_eq!(manifest.kind, text(&read["kind"]), "{name}");
                assert_eq!(
                    manifest.heads.len(),
                    read["heads"].as_array().unwrap().len(),
                    "{name}"
                );
                assert_eq!(
                    manifest.history,
                    if read["history"] == 0 {
                        History::Full
                    } else {
                        History::FromSnapshot
                    },
                    "{name}"
                );
                assert_eq!(
                    manifest.streams.is_some(),
                    !read["streams"].is_null(),
                    "{name}"
                );
                assert_eq!(manifest.time, read["time"].as_u64(), "{name}");
            }
            Record::WayIn(WayIn::Clear(clear)) => assert_eq!(*clear, bytes(&read["clear"])),
            Record::Event(signed) => assert_eq!(*signed, bytes(&read["event"])),
            Record::Snapshot(signed) => assert_eq!(*signed, bytes(&read["snapshot"])),
            Record::ObjectHeader { header, .. } => assert_eq!(*header, bytes(&read["header"])),
            Record::ObjectChunk { index, chunk, .. } => {
                assert_eq!(*index, read["index"].as_u64().unwrap());
                assert_eq!(*chunk, bytes(&read["chunk"]));
            }
            Record::Section(section) => {
                assert_eq!(section.kind, text(&read["kind"]));
                assert_eq!(section.name, text(&read["name"]));
            }
            Record::Ignored(_) => assert_eq!(read["ignored"], true),
            Record::WayIn(WayIn::Sealed(_)) => panic!("{name}: no sealed record here"),
        }
    }
}

#[test]
fn record_refusals() {
    let rows = family("record_refusals");
    for row in rows.as_array().unwrap() {
        let name = text(&row["name"]);
        let class = text(&row["class"]);
        match row.get("record") {
            None => {
                // Over the limit: refused as it is encoded.
                assert_eq!(class, "TooLarge", "{name}");
                let record = Record::Section(Section {
                    kind: "x".into(),
                    name: "big".into(),
                    bytes: vec![0; MAX_RECORD_BYTES],
                });
                assert_eq!(record.encode(), Err(ErrorClass::TooLarge), "{name}");
            }
            Some(framed) => {
                let framed = bytes(framed);
                let refused = Record::read(&framed[4..]).unwrap_err();
                assert_eq!(refused.name(), class, "{name}");
            }
        }
    }
}

#[test]
fn way_in() {
    let family = family("way_in");
    let space = EventId(array(&family["space"]));
    let file_key = array::<32>(&family["file_key"]);
    assert_eq!(
        sealing_key(&file_key).to_vec(),
        bytes(&family["sealing_key"])
    );
    assert_eq!(
        frasil_space_file::way_in::way_in_aad(&space),
        bytes(&family["aad"])
    );
    let body = bytes(&family["body"]);
    let read = WayInBody::read(&body, &space).unwrap();
    assert_eq!(read.encode(), body, "one encoding");
    let shown = &family["read"];
    assert_eq!(
        read.secrets.len(),
        shown["secrets"].as_object().unwrap().len()
    );
    assert_eq!(read.fragments.len(), 1);
    assert_eq!(read.label.as_deref(), shown["label"].as_str());
    // The fragment's text form is ext-invite-links.md's base64url.
    let fragment = &read.fragments[0];
    assert_eq!(fragment.space, space);
    let raw = fragment.encode();
    assert_eq!(Fragment::read(&raw).unwrap(), *fragment);
    let sealed = seal_way_in_with(&file_key, &array(&family["nonce"]), &body, &space);
    assert_eq!(sealed, bytes(&family["sealed"]));
    assert_eq!(
        open_way_in(&file_key, &sealed, &space).unwrap().to_vec(),
        body
    );
    let refusals = family["refusals"].as_array().unwrap();
    let wrong_key = [0xAB; 32];
    let other_space = EventId([0xCD; 32]);
    let outcomes: Vec<(&str, &'static str)> = vec![
        (
            "the wrong file key",
            open_way_in(&wrong_key, &sealed, &space).unwrap_err().name(),
        ),
        (
            "another space's associated data",
            open_way_in(&file_key, &sealed, &other_space)
                .unwrap_err()
                .name(),
        ),
        (
            "a sealed form of 39 bytes",
            open_way_in(&file_key, &sealed[..39], &space)
                .unwrap_err()
                .name(),
        ),
        (
            "a fragment of another space",
            WayInBody::read(&body, &other_space).unwrap_err().name(),
        ),
    ];
    for (name, got) in outcomes {
        let expected = refusals
            .iter()
            .find(|r| r["name"] == name)
            .unwrap_or_else(|| panic!("{name} is listed"));
        assert_eq!(got, text(&expected["class"]), "{name}");
    }
}

#[test]
fn appends() {
    let family = family("appends");
    let exported = bytes(&family["exported"]);
    let appended = bytes(&family["appended"]);
    let first = read(&exported).unwrap();
    assert!(!first.truncated);
    assert_eq!(
        first.manifest.heads.len(),
        family["first_manifest_heads"].as_array().unwrap().len()
    );
    assert_eq!(first.whole, exported.len());
    let whole = read(&appended).unwrap();
    assert!(!whole.truncated);
    assert_eq!(
        whole.events.len(),
        family["events_read"].as_u64().unwrap() as usize
    );
    assert_eq!(whole.first, first.first);
    assert_eq!(
        whole.manifest.heads.len(),
        family["last_manifest_heads"].as_array().unwrap().len()
    );
    assert!(
        appended.starts_with(&exported),
        "an append rewrites nothing"
    );
    let truncated = &family["truncated"];
    let cut = read(&bytes(&truncated["file"])).unwrap();
    assert!(cut.truncated && truncated["tail_ignored"] == true);
    assert_eq!(cut.manifest, first.manifest);
    assert_eq!(
        cut.events.len(),
        truncated["events_read"].as_u64().unwrap() as usize
    );
    // A record that does not read before the last manifest.
    let mut broken = exported.clone();
    broken.extend_from_slice(&3u32.to_be_bytes());
    broken.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    broken.extend_from_slice(&appended[exported.len()..]);
    assert_eq!(
        refusal_name(&read(&broken).unwrap_err()),
        text(&family["a record that does not read before the last manifest"])
    );
    // The writer appends after the last manifest read whole.
    let writer = Writer::appending(&exported, &first);
    assert_eq!(writer.bytes(), &exported[..]);
    assert_eq!(text(&family["an append to another space"]), "OtherSpace");
}

#[test]
fn refusals() {
    let rows = family("refusals");
    for row in rows.as_array().unwrap() {
        let name = text(&row["name"]);
        let data = bytes(&row["file"]);
        let refused = read(&data).unwrap_err();
        assert_eq!(refusal_name(&refused), text(&row["class"]), "{name}");
        // Sniffing stops at the first manifest: it refuses what lies before.
        let sniffed = sniff(&data);
        assert_eq!(
            sniffed.as_ref().err().map(refusal_name),
            (row["sniff_refuses"] == true).then_some(text(&row["class"])),
            "{name}: sniffing"
        );
    }
    assert_eq!(
        SpaceFileClass::NotASpaceFile.name(),
        Refusal::NotASpaceFile.name()
    );
}
