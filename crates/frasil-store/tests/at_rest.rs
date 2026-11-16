//! `at-rest.json`, every family (at-rest.md).

mod common;

use common::{
    array, bytes, example, family, flip, head_json, opened_json, optional, outcome, text, unhex,
};
use frasil_base::notation::field;
use frasil_crypto::device::DeviceId;
use frasil_crypto::primitives::ed25519_public;
use frasil_identity::passkey::PasskeyMember;
use frasil_store::continuity::{mark_aad, open_mark};
use frasil_store::device_keys::{self, Header};
use frasil_store::keys::{seal_key, tag_key};
use frasil_store::record::record_aad;
use frasil_store::tables::{Head, Table, TableValue};
use frasil_store::{
    Continuity, DeviceKeys, KeyKind, LogKeys, RestoreMode, StoreKeys, after_restore, app_key,
    continuity, open_device_keys, open_record, seal_device_keys_with, seal_mark_with,
    seal_record_with,
};
use serde_json::Value as Json;

fn device_keys(keys: &Json) -> DeviceKeys {
    DeviceKeys::new(
        array(keys, "identity_seed"),
        array(keys, "xwing_seed"),
        array(keys, "mldsa_seed"),
        array(keys, "store_secret"),
    )
}

fn kind(value: &Json) -> KeyKind {
    let code = value["key_kind"].as_u64().expect("a key kind");
    KeyKind::from_code(u8::try_from(code).unwrap()).expect("kind 1 or 2")
}

/// The browser's store keys, its space and that space's log key.
struct Browser {
    device_id: DeviceId,
    store: StoreKeys,
    space: [u8; 32],
    log_key: [u8; 32],
}

impl Browser {
    fn new() -> Self {
        let device = family("device");
        let derivations = family("derivations");
        Self {
            device_id: DeviceId(array(&device, "device_id")),
            store: StoreKeys::new(&array(&device["keys"], "store_secret")),
            space: array(&derivations, "space"),
            log_key: array(&derivations, "log_key(space)"),
        }
    }

    fn space(&self) -> LogKeys {
        self.store.log(&self.space, &self.log_key)
    }

    /// The ID of alice's list: the item of its `log` record.
    fn alice(&self) -> [u8; 32] {
        let records = family("records");
        let row = records
            .as_array()
            .unwrap()
            .iter()
            .find(|row| text(row, "name") == "alice's list's log key")
            .expect("alice's list's log record");
        array(row, "item")
    }
}

#[test]
fn device() {
    let device = family("device");
    let keys = device_keys(&device["keys"]);
    let public = keys.public_keys();
    assert_eq!(public.ed.0, array(&device, "identity"));
    assert_eq!(
        ed25519_public(&array(&device["keys"], "identity_seed")),
        public.ed.0
    );
    assert_eq!(public.keys.mldsa().to_vec(), bytes(&device, "mldsa"));
    assert_eq!(
        public.keys.xwing().map(|key| key.to_vec()),
        Some(bytes(&device, "xwing"))
    );
    assert_eq!(public.keys.commitment().0, array(&device, "kc"));
    assert_eq!(keys.device_id().0, array(&device, "device_id"));
    assert_eq!(keys.signer().device_id(), &keys.device_id());
}

#[test]
fn derivations() {
    let d = family("derivations");
    let s = array::<32>(&d, "store_secret");
    let l = array::<32>(&d, "log_key(space)");
    let browser = Browser::new();
    assert_eq!(*seal_key(&s), array(&d, "seal_key(store secret)"));
    assert_eq!(*tag_key(&s), array(&d, "tag_key(store secret)"));
    assert_eq!(*seal_key(&l), array(&d, "seal_key(log key)"));
    assert_eq!(*tag_key(&l), array(&d, "tag_key(log key)"));
    let store = StoreKeys::new(&s);
    assert_eq!(
        store.keys().seal_key(),
        &array(&d, "seal_key(store secret)")
    );
    assert_eq!(store.keys().tag_key(), &array(&d, "tag_key(store secret)"));
    let space = store.log(&array(&d, "space"), &l);
    assert_eq!(space.keys().seal_key(), &array(&d, "seal_key(log key)"));
    assert_eq!(space.keys().tag_key(), &array(&d, "tag_key(log key)"));
    assert_eq!(space.scope_tag(), &array(&d, "scope_tag(space)"));
    assert_eq!(
        store.scope_tag(&browser.alice()),
        array(&d, "scope_tag(alice's list)")
    );
    assert_eq!(
        *app_key(&l, b"com.example.index"),
        array(&d, "app_key(log key, \"com.example.index\")")
    );
    assert_eq!(
        *store.app_key(b"com.example.settings"),
        array(&d, "app_key(store secret, \"com.example.settings\")")
    );
}

#[test]
fn sealed_device_keys() {
    let cases = family("sealed_device_keys");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = text(case, "name");
        let kind = kind(case);
        let key = array::<32>(case, "key");
        let person = array::<32>(case, "person_id");
        let keys = device_keys(&case["keys"]);
        let device_id = DeviceId(array::<32>(case, "device_id"));
        assert_eq!(keys.device_id(), device_id, "{name}");
        if let Some(output) = case["prf_output"].as_str() {
            let passkey = PasskeyMember::derive(&person, &unhex(output)).unwrap();
            assert_eq!(
                passkey.unlock_key(),
                &key,
                "{name}: the passkey's unlock key"
            );
        }
        assert_eq!(
            *device_keys::sealing_key(kind, &key),
            array(case, "sealing_key"),
            "{name}"
        );
        let header = Header {
            kind,
            device_id,
            person_id: person,
        };
        assert_eq!(header.to_bytes().to_vec(), bytes(case, "header"), "{name}");
        assert_eq!(header.aad(), bytes(case, "aad"), "{name}");
        assert_eq!(
            keys.plaintext().to_vec(),
            bytes(case, "plaintext"),
            "{name}"
        );
        let sealed = seal_device_keys_with(&keys, &person, kind, &key, &array(case, "nonce"))
            .unwrap_or_else(|class| panic!("{name}: {class}"));
        assert_eq!(sealed.to_vec(), bytes(case, "sealed"), "{name}");
        assert_eq!(device_keys::read_header(&sealed), Ok(header), "{name}");
        let opened = open_device_keys(&sealed, kind, &key, &person, Some(&device_id))
            .unwrap_or_else(|class| panic!("{name}: {class}"));
        assert_eq!(opened, keys, "{name}");
        let opened = open_device_keys(&sealed, kind, &key, &person, None).unwrap();
        assert_eq!(opened, keys, "{name}");
    }
}

#[test]
fn sealed_device_keys_refusals() {
    let cases = family("sealed_device_keys_refusals");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 19);
    for case in cases {
        let name = text(case, "name");
        let blob = bytes(case, "sealed");
        // A client always names the person it expects. The one case that
        // names none shows the AEAD catching a changed person ID, so it
        // names the blob's own: step 5 passes and the AEAD decides.
        let person = optional::<32>(case, "expected_person")
            .unwrap_or_else(|| blob[34..66].try_into().unwrap());
        let device = optional::<32>(case, "expected_device").map(DeviceId);
        let result = open_device_keys(
            &blob,
            kind(case),
            &array(case, "key"),
            &person,
            device.as_ref(),
        );
        assert_eq!(outcome(result), text(case, "error"), "{name}");
    }
}

#[test]
fn records() {
    let browser = Browser::new();
    let space = browser.space();
    let rows = family("records");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 43);
    let mut tables = Vec::new();
    for row in rows {
        let name = text(row, "name");
        let code = u8::try_from(row["table"].as_u64().unwrap()).unwrap();
        let table = Table::from_code(code).unwrap_or_else(|| panic!("{name}: table {code}"));
        assert_eq!(table.name(), text(row, "table_name"), "{name}");
        tables.push(table);
        let log = optional::<32>(row, "log").map(|log| {
            assert_eq!(
                log, browser.space,
                "{name}: every log record is the space's"
            );
            &space
        });
        let item = bytes(row, "item");
        let value = bytes(row, "value");
        let address = match log {
            None => browser.store.address(table, &item),
            Some(log) => log.address(table, &item),
        }
        .unwrap_or_else(|| panic!("{name}: the table's scope"));
        assert_eq!(address.to_vec(), bytes(row, "address"), "{name}");
        assert_eq!(
            [field(&item), value.clone()].concat(),
            bytes(row, "plaintext"),
            "{name}"
        );
        assert_eq!(record_aad(&address), bytes(row, "aad"), "{name}");
        let sealed = seal_record_with(
            &browser.store,
            log,
            table,
            &item,
            &value,
            &array(row, "nonce"),
        )
        .unwrap_or_else(|class| panic!("{name}: {class}"));
        assert_eq!(sealed.address, address, "{name}");
        assert_eq!(sealed.record, bytes(row, "record"), "{name}");
        let opened = open_record(&browser.store, log, &address, &sealed.record)
            .unwrap_or_else(|class| panic!("{name}: {class}"));
        assert_eq!(opened.table, table, "{name}");
        assert_eq!(opened.item, item, "{name}");
        assert_eq!(opened_json(&opened.value), row["opened"], "{name}");
        assert_eq!(opened.value.table(), table, "{name}");
        assert_eq!(*opened.value.encode(), value, "{name}: one encoding");
    }
    // The held family shows the one table that `records` leaves out.
    let held = family("held");
    for row in held["records"].as_array().unwrap() {
        let code = u8::try_from(row["table"].as_u64().unwrap()).unwrap();
        tables.push(Table::from_code(code).unwrap());
    }
    tables.sort();
    tables.dedup();
    assert_eq!(tables, Table::ALL, "a record of every table");
}

#[test]
fn record_refusals() {
    let browser = Browser::new();
    let cases = family("record_refusals");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        let name = text(case, "name");
        // The log and the key the case opens it under; a log other than the
        // space has no key, and is refused by its scope before any key is
        // tried.
        let log = optional::<32>(case, "log").map(|log| {
            let key = optional::<32>(case, "log_key").unwrap_or([0; 32]);
            if name == "opened under another log's key" {
                assert_eq!(key, example("at-rest/other-log-key"));
            } else if log == browser.space {
                assert_eq!(key, browser.log_key, "{name}");
            }
            browser.store.log(&log, &key)
        });
        let result = open_record(
            &browser.store,
            log.as_ref(),
            &bytes(case, "address"),
            &bytes(case, "record"),
        );
        assert_eq!(outcome(result), text(case, "error"), "{name}");
    }
}

#[test]
fn mark() {
    let browser = Browser::new();
    let m = family("mark");
    let store_id = array::<16>(&m, "store_id");
    let generation = m["generation"].as_u64().unwrap();
    let device_id = DeviceId(array::<32>(&m, "device_id"));
    assert_eq!(device_id, browser.device_id);
    assert_eq!(
        [&store_id[..], &generation.to_be_bytes()].concat(),
        bytes(&m, "plaintext")
    );
    assert_eq!(mark_aad(&device_id), bytes(&m, "aad"));
    let mark = seal_mark_with(
        &browser.store,
        &device_id,
        &store_id,
        generation,
        &array(&m, "nonce"),
    );
    assert_eq!(mark.to_vec(), bytes(&m, "mark"));
    assert_eq!(
        open_mark(&browser.store, &device_id, &mark),
        Ok((store_id, generation))
    );
    let refusals = m["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 4);
    for case in refusals {
        let name = text(case, "name");
        let result = open_mark(
            &browser.store,
            &DeviceId(array::<32>(case, "device_id")),
            &bytes(case, "mark"),
        );
        assert_eq!(outcome(result), text(case, "error"), "{name}");
    }
    // The inputs are the ones the cases are named for.
    let input = |name: &str| {
        let case = refusals.iter().find(|c| text(c, "name") == name).unwrap();
        (
            DeviceId(array::<32>(case, "device_id")),
            bytes(case, "mark"),
        )
    };
    assert_eq!(
        input("an unknown version"),
        (device_id, [&[2u8][..], &mark[1..]].concat())
    );
    assert_eq!(
        input("one byte short"),
        (device_id, mark[..mark.len() - 1].to_vec())
    );
    assert_eq!(
        input("another device's"),
        (DeviceId(example("at-rest/other-device")), mark.to_vec())
    );
    assert_eq!(input("a changed byte"), (device_id, flip(&mark, 40)));
}

#[test]
fn continuity_outcomes() {
    let browser = Browser::new();
    let cases = family("continuity");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for case in cases {
        let name = text(case, "name");
        let mode = RestoreMode::from_name(text(case, "mode")).expect("a mode");
        let head = optional::<16>(case, "head_store_id").map(|store_id| Head {
            store_id,
            generation: case["head_generation"].as_u64().unwrap(),
            tips: Vec::new(),
            restore: None,
            revision: Some(frasil_base::version::REVISION),
        });
        let mark = (!case["mark"].is_null()).then(|| bytes(case, "mark"));
        let found = continuity(
            &browser.store,
            &browser.device_id,
            mode,
            head.as_ref(),
            mark.as_deref(),
        );
        assert_eq!(found.name(), text(case, "outcome"), "{name}");
    }
}

#[test]
fn head_revisions() {
    let cases = family("head_revisions");
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let head_bytes = bytes(case, "head");
        let head = Head::read(&head_bytes).unwrap();
        assert_eq!(head.encode(), head_bytes, "{}", text(case, "name"));
        let found = match head.check_revision() {
            Ok(()) => "Opens",
            Err(class) => frasil_base::errors::Class::name(class),
        };
        assert_eq!(found, text(case, "outcome"), "{}", text(case, "name"));
    }
}

#[test]
fn after_restore_head() {
    let browser = Browser::new();
    let a = family("after_restore");
    let head_bytes = bytes(&a, "head");
    let head = Head::read(&head_bytes).unwrap();
    assert_eq!(head.encode(), head_bytes);

    // The head at generation 2 with its mark at 3: g is 4. Then the device
    // syncs the space.
    let rows = family("records");
    let before = Head::read(&bytes(&rows[0], "value")).unwrap();
    assert_eq!(before.generation, 2);
    let mut after = after_restore(&before, Some(3));
    assert_eq!(after.generation, 4);
    assert!(!after.may_sign(&browser.space));
    after.add_synced(&browser.space);
    assert_eq!(after, head);
    assert_eq!(after.encode(), head_bytes);

    let mark = bytes(&a, "mark");
    let resealed = seal_mark_with(
        &browser.store,
        &browser.device_id,
        &head.store_id,
        head.generation,
        mark[1..25].try_into().unwrap(),
    );
    assert_eq!(resealed.to_vec(), mark);
    assert_eq!(
        continuity(
            &browser.store,
            &browser.device_id,
            RestoreMode::DeviceBound,
            Some(&head),
            Some(&mark),
        ),
        Continuity::Current
    );

    let may_sign = a["may_sign"].as_object().unwrap();
    assert_eq!(may_sign.len(), 2);
    for (name, expected) in may_sign {
        let log = match name.as_str() {
            "the space, synced since" => browser.space,
            "alice's list, not yet synced" => browser.alice(),
            other => panic!("an unknown log: {other}"),
        };
        assert_eq!(head.may_sign(&log), expected.as_bool().unwrap(), "{name}");
    }
}

#[test]
fn passkey_to_record() {
    let chain = family("passkey_to_record");
    let person = array::<32>(&chain, "person_id");
    let passkey = PasskeyMember::derive(&person, &bytes(&chain, "prf_output")).unwrap();
    assert_eq!(passkey.unlock_key(), &array(&chain, "unlock_key"));
    let blob = bytes(&chain, "sealed_device_keys");
    let header = device_keys::read_header(&blob).unwrap();
    assert_eq!(header.kind, KeyKind::PasskeyUnlock);
    assert_eq!(header.person_id, person);
    let keys = open_device_keys(
        &blob,
        KeyKind::PasskeyUnlock,
        passkey.unlock_key(),
        &person,
        Some(&header.device_id),
    )
    .unwrap();
    assert_eq!(*keys.store_secret, array(&chain, "store_secret"));
    let store = StoreKeys::new(&keys.store_secret);
    let opened = open_record(
        &store,
        None,
        &bytes(&chain, "head_address"),
        &bytes(&chain, "head_record"),
    )
    .unwrap();
    let TableValue::Head(head) = &opened.value else {
        panic!("the head record holds a head");
    };
    assert_eq!(head_json(head), chain["head_opened"]);
}
