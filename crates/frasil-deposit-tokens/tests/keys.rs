//! `ext-deposit-tokens.json`'s `keys` and `key_consistency`: deposit keys
//! and key IDs, `TokenKeys` and discovery's `deposit_keys`, a device's
//! checks of a key list, and its consistency rule (ext-deposit-tokens.md,
//! 2.2 Deposit keys, 2.5 Messages and 3.2 Learning a peer's keys).

mod common;

use std::collections::BTreeMap;

use common::*;
use frasil_deposit_tokens::key::key_id;
use frasil_deposit_tokens::{
    DepositKey, KeyHistory, KeyList, Role, TokenKeys, TokenKeysGet, messages::KeyEntry,
};
use frasil_testkit::hex;

#[test]
fn keys_and_their_lists() {
    let f = family("keys");
    let keys: Vec<DepositKey> = f["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let key = DepositKey::from_seed(&array(&row["seed"]));
            assert_eq!(hex::encode(*key.secret()), text(&row["secret"]));
            assert_eq!(hex::encode(key.public()), text(&row["public"]));
            assert_eq!(hex::encode(key.id()), text(&row["key_id"]));
            assert_eq!(&key_id(key.public()), key.id());
            key
        })
        .collect();
    assert_eq!(
        hex::encode(TokenKeysGet { request: 1 }.encode()),
        text(&f["token_keys_get"])
    );
    let entry = |key: &DepositKey, role| KeyEntry {
        key_id: *key.id(),
        public: *key.public(),
        role,
    };
    let message = TokenKeys {
        request: 1,
        keys: vec![
            entry(&keys[1], Role::Issuing),
            entry(&keys[0], Role::Accepting),
        ],
    };
    assert_eq!(hex::encode(message.encode()), text(&f["token_keys"]));
    let list = KeyList::decode(&message.encode(), 1).unwrap();
    assert_eq!(list.issuing().id, *keys[1].id());
    assert!(list.shows(keys[0].id()));
    // Discovery's member lists the same keys.
    let member = f["discovery"]["deposit_keys"].as_array().unwrap();
    let ids: Vec<Vec<u8>> = member.iter().map(|e| bytes(&e["id"])).collect();
    let publics: Vec<Vec<u8>> = member.iter().map(|e| bytes(&e["key"])).collect();
    let entries: Vec<(&[u8], &[u8], u64)> = member
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let role = if e["issuing"].as_bool().unwrap() {
                1
            } else {
                2
            };
            (ids[i].as_slice(), publics[i].as_slice(), role)
        })
        .collect();
    assert_eq!(KeyList::check(&entries).unwrap(), list);

    let refused = f["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 11);
    for row in refused {
        let class = KeyList::decode(&bytes(&row["token_keys"]), 1).unwrap_err();
        common::refused(row, class);
    }
}

#[test]
fn key_consistency() {
    // The keys the sequences name: those of the rotation's seeds.
    let publics: BTreeMap<String, DepositKey> = family("rotation")["seeds"]
        .as_object()
        .unwrap()
        .values()
        .map(|seed| {
            let key = DepositKey::from_seed(&array(seed));
            (hex::encode(key.id()), key)
        })
        .collect();
    let sequences = family("key_consistency");
    assert_eq!(sequences.as_array().unwrap().len(), 4);
    for sequence in sequences.as_array().unwrap() {
        let name = text(&sequence["name"]);
        let mut history = KeyHistory::new();
        for step in sequence["steps"].as_array().unwrap() {
            let listed: Vec<(Vec<u8>, Vec<u8>, u64)> = step["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| {
                    let key = &publics[text(&k["key_id"])];
                    let role = if text(&k["role"]) == "issuing" { 1 } else { 2 };
                    (key.id().to_vec(), key.public().to_vec(), role)
                })
                .collect();
            let entries: Vec<(&[u8], &[u8], u64)> = listed
                .iter()
                .map(|(id, public, role)| (id.as_slice(), public.as_slice(), *role))
                .collect();
            let list = KeyList::check(&entries).unwrap();
            let result = history.observe(&list, number(&step["reading"]));
            match result {
                Ok(()) => assert_eq!(text(&step["verdict"]), "accepted", "{name}"),
                Err(class) => common::refused(step, class),
            }
            let seen: Vec<(String, u64)> = history
                .seen()
                .iter()
                .map(|(id, at)| (hex::encode(id), *at))
                .collect();
            let expected: Vec<(String, u64)> = step["issuing_seen"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| (text(&s["key_id"]).to_owned(), number(&s["first_seen"])))
                .collect();
            assert_eq!(seen, expected, "{name}");
            let keeps: Vec<String> = history.keeps().iter().map(hex::encode).collect();
            let expected: Vec<&str> = step["keeps_tokens_of"]
                .as_array()
                .unwrap()
                .iter()
                .map(text)
                .collect();
            assert_eq!(keeps, expected, "{name}");
        }
    }
}
