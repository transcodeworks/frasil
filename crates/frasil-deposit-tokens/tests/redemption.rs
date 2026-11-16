//! `ext-deposit-tokens.json`'s `redemption` and `budgets`: a peer's checks
//! of a deposit paid with a token, in order, on the WebSocket and the
//! `POST` route, with the spent set; and the two budgets over device
//! mailboxes (ext-deposit-tokens.md, 3.7 Redeeming and 3.8 The token
//! budget).

mod common;

use std::collections::BTreeMap;

use common::*;
use frasil_crypto::device::DeviceId;
use frasil_deposit_tokens::budget::Mailboxes;
use frasil_deposit_tokens::{
    KeyId, KeyShard, Redemption, SpentRecord, SpentTokens, TokenDeposit, redeem,
};
use frasil_testkit::hex;
use frasil_transport::mailbox::{Kind, address};
use serde_json::{Value as Json, json};

#[derive(Default)]
struct Spent(BTreeMap<(KeyId, [u8; 32]), SpentRecord>);

impl SpentTokens for Spent {
    fn spent(&self, key_id: &KeyId, nonce: &[u8; 32]) -> Option<SpentRecord> {
        self.0.get(&(*key_id, *nonce)).copied()
    }
}

fn state(keys: &KeyShard, spent: &Spent, boxes: &Mailboxes) -> Json {
    let keys: Vec<Json> = keys
        .live_keys()
        .iter()
        .enumerate()
        .map(|(i, live)| {
            json!({
                "seed": hex::encode(live.key.seed()),
                "key_id": hex::encode(live.key.id()),
                "role": if i == 0 { "issuing" } else { "accepting only" },
            })
        })
        .collect();
    let spent: Vec<Json> = spent
        .0
        .iter()
        .map(|((key, nonce), record)| {
            json!({
                "key_id": hex::encode(key),
                "nonce": hex::encode(nonce),
                "deposit": hex::encode(record.deposit),
                "id": item_number(&record.item),
            })
        })
        .collect();
    json!({"keys": keys, "spent": spent, "mailboxes": describe_mailboxes(boxes)})
}

#[test]
fn redemption() {
    let f = family("redemption");
    let steps = f["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 15);
    let first = &steps[0]["before"];
    let keys = keys(&first["keys"]);
    let mut spent = Spent::default();
    let mut boxes = mailboxes(
        &f["budgets"]["anonymous"],
        &f["budgets"]["tokens"],
        &first["mailboxes"],
    );
    for step in steps {
        let name = text(&step["name"]);
        assert_eq!(state(&keys, &spent, &boxes), step["before"], "{name}");
        let deposit = match text(&step["route"]) {
            "websocket" => TokenDeposit::read_put(&map(&bytes(&step["mailbox_put"]))),
            _ => {
                let item = match step.get("item") {
                    Some(item) => bytes(item),
                    None => vec![0; number(&step["zero_item_bytes"]) as usize],
                };
                TokenDeposit::read_post(array(&step["address"]), item, text(&step["authorization"]))
            }
        };
        let result = deposit.and_then(|deposit| {
            redeem(&deposit, &keys, &spent, &boxes).map(|redemption| (deposit, redemption))
        });
        match result {
            Ok((_, Redemption::Repeat { item })) => {
                assert_eq!(text(&step["verdict"]), "accepted", "{name}");
                assert_eq!(step["repeated"], json!(true), "{name}");
                assert_eq!(item, item_id(&step["id"]), "{name}");
            }
            Ok((
                deposit,
                Redemption::Keep {
                    key_id,
                    nonce,
                    deposit: digest,
                },
            )) => {
                assert_eq!(text(&step["verdict"]), "accepted", "{name}");
                assert_eq!(step["repeated"], json!(false), "{name}");
                let kept = boxes
                    .deposit(deposit.address, deposit.item.len() as u64, true)
                    .unwrap();
                assert_eq!(kept.id, item_id(&step["id"]), "{name}");
                let evicted: Vec<[u8; 16]> = step["evicted"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(item_id)
                    .collect();
                assert_eq!(kept.evicted, evicted, "{name}");
                spent.0.insert(
                    (key_id, *nonce),
                    SpentRecord {
                        deposit: digest,
                        item: kept.id,
                    },
                );
            }
            Err(class) => refused(step, class),
        }
        assert_eq!(state(&keys, &spent, &boxes), step["after"], "{name}");
    }
}

/// The redemption's mailboxes are named by their devices' device IDs
/// (transport.md, 2.7 Mailboxes); a token binds the address, not the
/// device.
#[test]
fn the_recipients_mailboxes_are_named_by_device_id() {
    let addresses = &family("redemption")["addresses"];
    for name in ["recipient", "another recipient"] {
        let device = DeviceId(array(&addresses[name]["device_id"]));
        assert_eq!(
            address(Kind::Device, device.as_bytes()),
            array::<32>(&addresses[name]["address"]),
            "{name}"
        );
    }
}

#[test]
fn budgets() {
    let scenarios = family("budgets");
    assert_eq!(scenarios.as_array().unwrap().len(), 4);
    for scenario in scenarios.as_array().unwrap() {
        let name = text(&scenario["name"]);
        let mut boxes = mailboxes(
            &scenario["budgets"]["anonymous"],
            &scenario["budgets"]["tokens"],
            &scenario["before"],
        );
        assert_eq!(describe_mailboxes(&boxes), scenario["before"], "{name}");
        for step in scenario["deposits"].as_array().unwrap() {
            let paid = text(&step["kind"]) == "token";
            let result = boxes.deposit(array(&step["address"]), number(&step["bytes"]), paid);
            match result {
                Ok(kept) => {
                    assert_eq!(text(&step["verdict"]), "accepted", "{name}");
                    assert_eq!(kept.id, item_id(&step["id"]), "{name}");
                    let evicted: Vec<[u8; 16]> = step["evicted"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(item_id)
                        .collect();
                    assert_eq!(kept.evicted, evicted, "{name}");
                }
                Err(class) => refused(step, class),
            }
            assert_eq!(describe_mailboxes(&boxes), step["after"], "{name}");
        }
    }
}
