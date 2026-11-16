//! Held objects (at-rest.md, "Held objects"): the family `held` of
//! at-rest.json, driven through the procedures over a provider in memory.

#[path = "support/provider.rs"]
mod provider;

use frasil::Error;
use frasil::advanced::held::{ReceiveKey, Receiver, Served, put_with_chunked, serve_with_chunked};
use frasil_base::errors::Class as _;
use frasil_events::EventId;
use frasil_store::record::{open_record, record_aad, seal_record_with};
use frasil_store::tables::{HeldRecord, Table, TableValue};
use frasil_store::{LogKeys, StoreKeys};
use frasil_testkit::hex;
use frasil_units::objects::{ObjectKeys, seal_chunk};
use provider::MemoryProvider;
use serde_json::Value as Json;

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family("at-rest.json", name)
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

/// The family, and the state the vectors' objects are sealed under.
struct Held {
    family: Json,
    space: EventId,
    content_key: [u8; 32],
    key_reference: Vec<u8>,
}

impl Held {
    fn load() -> Self {
        let family = family("held");
        let fixtures = &family["fixtures"];
        Self {
            space: EventId(array(&fixtures["space"])),
            content_key: array(&fixtures["content_key"]),
            key_reference: bytes(&fixtures["key_reference"]),
            family,
        }
    }

    fn rows(&self, name: &str) -> &[Json] {
        self.family[name].as_array().expect(name)
    }
}

/// The browser's store keys and the space's log keys of at-rest.json.
fn browser() -> (StoreKeys, LogKeys) {
    let device = family("device");
    let derivations = family("derivations");
    let store = StoreKeys::new(&array(&device["keys"]["store_secret"]));
    let log = store.log(
        &array(&derivations["space"]),
        &array(&derivations["log_key(space)"]),
    );
    (store, log)
}

fn sealed_chunks(row: &Json) -> Vec<Vec<u8>> {
    row["chunks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| bytes(&c["sealed"]))
        .collect()
}

#[test]
fn records() {
    let held = Held::load();
    let (store, log) = browser();
    let mut tables = Vec::new();
    for row in held.rows("records") {
        let name = text(&row["name"]);
        let table =
            Table::from_code(u8::try_from(row["table"].as_u64().unwrap()).unwrap()).unwrap();
        tables.push(table);
        let item = bytes(&row["item"]);
        let value = bytes(&row["value"]);
        let address = log.address(table, &item).unwrap();
        assert_eq!(address.to_vec(), bytes(&row["address"]), "{name}");
        assert_eq!(record_aad(&address), bytes(&row["aad"]), "{name}");
        let sealed = seal_record_with(
            &store,
            Some(&log),
            table,
            &item,
            &value,
            &array(&row["nonce"]),
        )
        .unwrap();
        assert_eq!(sealed.record, bytes(&row["record"]), "{name}");
        let opened = open_record(&store, Some(&log), &address, &sealed.record).unwrap();
        assert_eq!(opened.item, item, "{name}");
        assert_eq!(*opened.value.encode(), value, "{name}: one encoding");
        if let TableValue::Held(record) = &opened.value {
            assert_eq!(hex::encode(&record.token), text(&row["opened"]["1"]));
            assert_eq!(record.size, row["opened"]["2"].as_u64().unwrap());
            assert_eq!(hex::encode(&record.stamp), text(&row["opened"]["3"]));
        }
    }
    assert_eq!(tables, [Table::Object, Table::Held]);
}

#[test]
fn record_refusals() {
    let held = Held::load();
    let (store, log) = browser();
    let rows = held.rows("record_refusals");
    assert_eq!(rows.len(), 7);
    for row in rows {
        let name = text(&row["name"]);
        let refused = open_record(
            &store,
            Some(&log),
            &bytes(&row["address"]),
            &bytes(&row["record"]),
        );
        assert_eq!(refused.unwrap_err().name(), text(&row["error"]), "{name}");
    }
}

#[tokio::test]
async fn puts() {
    let held = Held::load();
    let provider = MemoryProvider::new();
    for row in held.rows("puts") {
        let name = text(&row["name"]);
        let token = bytes(&row["token"]);
        provider.put(&token, &bytes(&row["plaintext"]), &bytes(&row["stamp"]));
        *provider.stats.lock().unwrap() = 0;
        let put = put_with_chunked(
            provider.as_ref(),
            &held.space,
            &held.content_key,
            &held.key_reference,
            &token,
            row["chunk_bytes"].as_u64().unwrap(),
        )
        .await
        .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            put.locator[..32],
            array::<32>(&row["pass_one"]["id"]),
            "{name}"
        );
        assert_eq!(put.header, bytes(&row["pass_two"]["header"]), "{name}");
        assert_eq!(
            put.locator.to_vec(),
            bytes(&row["pass_two"]["locator"]),
            "{name}"
        );
        let chunks: Vec<Vec<u8>> = put.parts.iter().map(|p| p.chunk.clone()).collect();
        assert_eq!(chunks, sealed_chunks(&row["pass_two"]), "{name}");
        assert!(put.parts[0].header.is_some() && put.parts[1..].iter().all(|p| p.header.is_none()));
        // The commit: the header record and the held record.
        let commit = row["commit"].as_array().unwrap();
        assert_eq!(commit[0]["table_name"], "object");
        assert_eq!(bytes(&commit[0]["value"]), put.header, "{name}");
        assert_eq!(commit[1]["table_name"], "held");
        assert_eq!(bytes(&commit[1]["item"]), put.locator[..32], "{name}");
        assert_eq!(
            bytes(&commit[1]["value"]),
            *TableValue::Held(put.record.clone()).encode(),
            "{name}"
        );
    }
}

#[tokio::test]
async fn put_refusals() {
    let held = Held::load();
    let big = &held.rows("puts")[1];
    for row in held.rows("put_refusals") {
        let name = text(&row["name"]);
        let provider = MemoryProvider::new();
        let token = bytes(&row["token"]);
        if name.contains("changed") {
            let mut changed = bytes(&big["plaintext"]);
            changed.push(b'!');
            provider.put(&token, &bytes(&big["plaintext"]), &bytes(&big["stamp"]));
            *provider.later.lock().unwrap() = Some((token.clone(), changed, vec![9; 16]));
        }
        let refused = put_with_chunked(
            provider.as_ref(),
            &held.space,
            &held.content_key,
            &held.key_reference,
            &token,
            64,
        )
        .await;
        assert_eq!(refused.unwrap_err(), Error::Class("Changed"), "{name}");
        assert_eq!(text(&row["error"]), "Changed");
    }
}

#[test]
fn reseal() {
    let held = Held::load();
    let row = &held.family["reseal"];
    let keys = ObjectKeys::of(&held.content_key);
    assert_eq!(*keys.id_key, array::<32>(&row["keys"]["id_key"]));
    assert_eq!(*keys.nonce_key, array::<32>(&row["keys"]["nonce_key"]));
    assert_eq!(*keys.seal_key, array::<32>(&row["keys"]["seal_key"]));
    let id = array::<32>(&row["id"]);
    let object_key = keys.object_key(&id);
    assert_eq!(*object_key, array::<32>(&row["object_key"]));
    let chunk = seal_chunk(
        &held.space,
        &keys,
        &object_key,
        &id,
        row["size"].as_u64().unwrap(),
        row["index"].as_u64().unwrap(),
        &bytes(&row["plain"]),
    );
    assert_eq!(chunk.aad, bytes(&row["aad"]));
    assert_eq!(chunk.nonce.to_vec(), bytes(&row["nonce"]));
    assert_eq!(chunk.sealed, bytes(&row["sealed"]));
}

#[tokio::test]
async fn serves() {
    let held = Held::load();
    let big = &held.rows("puts")[1];
    let header = bytes(&big["pass_two"]["header"]);
    let locator: [u8; 64] = bytes(&big["pass_two"]["locator"]).try_into().unwrap();
    let record = HeldRecord {
        token: bytes(&big["token"]),
        size: big["size"].as_u64().unwrap(),
        stamp: bytes(&big["stamp"]),
    };
    for row in held.rows("serves") {
        let name = text(&row["name"]);
        let provider = MemoryProvider::new();
        if let Some(file) = row["provider"].as_object() {
            provider.put(
                &record.token,
                &bytes(&file["plaintext"]),
                &bytes(&file["stamp"]),
            );
        }
        let served = serve_with_chunked(
            provider.as_ref(),
            &held.space,
            &held.content_key,
            &header,
            &record,
            Some(locator),
            row["first"].as_u64().unwrap(),
            row["count"].as_u64().unwrap(),
            64,
        )
        .await
        .unwrap_or_else(|error| panic!("{name}: {error}"));
        match served {
            Served::Held {
                locator: found,
                parts,
            } => {
                assert_eq!(text(&row["outcome"]), "held", "{name}");
                assert_eq!(found, locator, "{name}");
                let chunks: Vec<Vec<u8>> = parts.iter().map(|p| p.chunk.clone()).collect();
                assert_eq!(chunks, sealed_chunks(row), "{name}");
            }
            Served::NotHeld => assert_eq!(text(&row["outcome"]), "not held", "{name}"),
        }
    }
}

#[tokio::test]
async fn receives() {
    let held = Held::load();
    let big = &held.rows("puts")[1];
    let keys = ObjectKeys::of(&held.content_key);
    let object_key = keys.object_key(&array::<32>(&big["pass_one"]["id"]));
    for row in held.rows("receives") {
        let name = text(&row["name"]);
        let provider = MemoryProvider::new();
        let key = match text(&row["with"]) {
            "k(S)" => ReceiveKey::State(&held.content_key),
            _ => ReceiveKey::Object(&object_key),
        };
        let locator: [u8; 64] = bytes(&row["locator"]).try_into().unwrap();
        let hint = bytes(&row["hint"]);
        let mut receiver = Receiver::start_chunked(
            provider.as_ref(),
            held.space,
            held.space,
            &bytes(&row["header"]),
            key,
            &hint,
            64,
        )
        .await
        .unwrap();
        let mut outcome = Ok(());
        let chunks: Vec<Vec<u8>> = row["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect();
        for chunk in chunks {
            if let Err(error) = receiver.chunk(&chunk).await {
                outcome = Err(error);
                break;
            }
        }
        let result = match outcome {
            Ok(()) => receiver.finish(provider.as_ref(), &locator).await,
            Err(error) => {
                receiver.abort().await;
                Err(error)
            }
        };
        match result {
            Ok(record) => {
                assert_eq!(text(&row["outcome"]), "accepted", "{name}");
                assert_eq!(hex::encode(&record.token), text(&row["token"]), "{name}");
                assert_eq!(hex::encode(&record.stamp), text(&row["stamp"]), "{name}");
                let (written, _) = provider.file(&record.token).unwrap();
                assert_eq!(hex::encode(&written), text(&row["plaintext"]), "{name}");
                let commit = row["commit"].as_array().unwrap();
                assert_eq!(
                    bytes(&commit[1]["value"]),
                    *TableValue::Held(record).encode()
                );
                assert_eq!(provider.calls.lock().unwrap().finished, 1, "{name}");
            }
            Err(error) => {
                assert_eq!(text(&row["outcome"]), "refused", "{name}");
                assert_eq!(
                    error,
                    Error::Class(text(&row["error"]).to_owned().leak()),
                    "{name}"
                );
                assert_eq!(provider.calls.lock().unwrap().aborted, 1, "{name}");
                assert!(
                    provider.files.lock().unwrap().is_empty(),
                    "{name}: nothing committed"
                );
            }
        }
    }
}
