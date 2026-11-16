//! transport.md, sections 2.7 and 3.14: the `mailboxes` family.

mod common;

use common::*;
use frasil_crypto::primitives::ed25519_sign;
use frasil_crypto::wrap::xwing_public;
use frasil_transport::caps::{Cap, PeerMailboxes, claimed, item_kept};
use frasil_transport::frame::Extensions;
use frasil_transport::mailbox::{
    DeviceMailbox, Kind, MailboxGet, MailboxItems, MailboxPut, address, check_collect, collect,
    collect_input, content, item_info, item_plaintext, open_item, read_item_plaintext,
    seal_item_with,
};
use frasil_transport::peer::{Purpose, peer_binding};

fn implements_all(name: &str) -> bool {
    [
        content::ACCESS_REQUEST,
        content::LEAVE_REQUEST,
        content::LIST_EVENTS,
        content::WELCOME_REQUEST,
    ]
    .contains(&name)
}

fn implements_core(name: &str) -> bool {
    content::CORE.contains(&name)
}

#[test]
fn addresses() {
    let family = family("mailboxes");
    for row in family["addresses"].as_array().unwrap() {
        let kind = Kind::from_code(number(&row["kind"])).unwrap();
        assert_eq!(kind.name(), text(&row["mailbox"]));
        assert_eq!(
            address(kind, &bytes(&row["name"])),
            array::<32>(&row["address"])
        );
    }
}

#[test]
fn collection() {
    let family = family("mailboxes");
    let handshake = Handshake::load();
    let seed = handshake.identity_seed("listener");
    let signer = handshake.signer("listener");
    let me = signer.to_bytes();
    let case = &family["collection"];
    assert_eq!(me, array(&case["ed_kc"]));
    assert_eq!(
        handshake.device_id("listener").0,
        array::<32>(&case["device_id"])
    );
    let mailbox = address(Kind::Device, &signer.device_id().0);
    assert_eq!(mailbox, array(&case["address"]));
    let peer = family_of_peer();
    let binding = array::<32>(&peer["bindings"]["iroh"]["purpose_1"]);
    assert_eq!(binding, array(&case["binding"]));
    let signed = collect_input(&binding, &mailbox);
    assert_eq!(signed, bytes(&case["signed"]));
    let signature = ed25519_sign(&seed, &signed);
    assert_eq!(signature.to_vec(), bytes(&case["signature"]));
    let get = collect(1, &seed, &signer.kc, &binding, None);
    assert_eq!(get, bytes(&case["mailbox_get"]));

    // The peer reads the MailboxGet and checks the collection.
    let read = MailboxGet::read(&peer_control(&get).unwrap()).unwrap();
    assert_eq!(read.kind, Kind::Device);
    assert_eq!(read.encode(), get);
    let (key, signature) = read.collector.clone().unwrap();
    assert_eq!(key, signer);
    assert_eq!(
        check_collect(&read.address, &key.to_bytes(), &signature, &binding)
            .map(|checked| (*checked.address(), checked.collector())),
        Ok((read.address, key.device_id()))
    );

    // The refusals.
    let other_binding = peer_binding(
        &channel_2(),
        &array(&peer["nonce_peer"]),
        &array(&peer["nonce_client"]),
        Purpose::SpaceTraffic,
    );
    let dialer = handshake.device_id("dialer");
    let by_dialer = ed25519_sign(&handshake.identity_seed("dialer"), &signed);
    let rows = family["collection_refusals"].as_array().unwrap();
    // The device's Ed25519 key under another kc: another device ID, so
    // another mailbox, though the device's own key signs.
    let other_kc = bytes(&rows[3]["ed_kc"]);
    assert_eq!(other_kc[..32], me[..32]);
    assert_ne!(other_kc[32..], me[32..]);
    let results = [
        check_collect(&mailbox, &me, &signature, &other_binding),
        check_collect(&address(Kind::Device, &dialer.0), &me, &signature, &binding),
        check_collect(&mailbox, &me, &by_dialer, &binding),
        check_collect(&mailbox, &other_kc, &signature, &binding),
    ];
    assert_eq!(rows.len(), results.len());
    for (row, result) in rows.iter().zip(results) {
        assert_eq!(
            class(result),
            Some(text(&row["error"])),
            "{}",
            text(&row["description"])
        );
    }
    assert_eq!(
        class(check_collect(&mailbox[..31], &me, &signature, &binding)),
        Some("Malformed")
    );
}

fn family_of_peer() -> serde_json::Value {
    family("device_to_peer")
}

#[test]
fn eviction() {
    let family = family("mailboxes");
    let eviction = &family["eviction"];
    assert_eq!(
        number(&eviction["items"]) as usize,
        frasil_transport::mailbox::DEVICE_MAILBOX_ITEMS
    );
    assert_eq!(
        number(&eviction["bytes"]) as usize,
        frasil_transport::mailbox::DEVICE_MAILBOX_BYTES
    );
    for case in [&eviction["by_count"], &eviction["by_bytes"]] {
        let mut mailbox = DeviceMailbox::new();
        let mut evictions = Vec::new();
        for deposit in 0..number(&case["deposits"]) {
            let id = u128::from(deposit).to_be_bytes();
            let gone = mailbox
                .put(id, vec![0; number(&case["item_bytes"]) as usize])
                .unwrap();
            if !gone.is_empty() {
                let gone: Vec<u64> = gone
                    .iter()
                    .map(|g| u128::from_be_bytes(*g) as u64)
                    .collect();
                evictions.push(serde_json::json!({"deposit": deposit, "evicted": gone}));
            }
        }
        assert_eq!(serde_json::Value::from(evictions), case["evictions"]);
        assert!(mailbox.bytes() <= frasil_transport::mailbox::DEVICE_MAILBOX_BYTES);
    }
    let mut mailbox = DeviceMailbox::new();
    assert_eq!(
        class(mailbox.put([0; 16], vec![0; 262_145])),
        Some("TooLarge")
    );
}

#[test]
fn items() {
    let family = family("mailboxes");
    let recipient = &family["recipient"];
    let seed = array::<32>(&recipient["x_wing_seed"]);
    let xwing = xwing_public(&seed);
    assert_eq!(xwing.to_vec(), bytes(&recipient["x_wing_key"]));
    // The recipient is the handshake's listener, whose X-Wing key this is.
    let keys = Handshake::load().device_keys("listener");
    assert_eq!(keys.keys.xwing(), Some(&xwing));
    let me = keys.device_id();
    assert_eq!(me.0, array::<32>(&recipient["device_id"]));
    let implements: Vec<&str> = recipient["implements"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert!(implements.iter().all(|name| implements_all(name)));
    assert_eq!(implements.len(), 4);

    for row in family["items"].as_array().unwrap() {
        let content = text(&row["content"]);
        let plaintext = bytes(&row["plaintext"]);
        let read = read_item_plaintext(&plaintext).unwrap();
        assert_eq!(read.content, content);
        assert_eq!(item_plaintext(content, &read.body), plaintext);
        assert_eq!(item_info(&me), bytes(&row["info"]));
        let item = seal_item_with(content, &read.body, &keys, &array(&row["eseed"])).unwrap();
        assert_eq!(item, bytes(&row["item"]), "{content}");
        assert_eq!(item.len() as u64, number(&row["item_bytes"]));
        assert_eq!(item[3..3 + 1120], bytes(&row["enc"]));
        let opened = open_item(&item, &me, &seed, implements_all).unwrap();
        assert_eq!(opened, read);
        // A core device drops a leave request; it opens a list-events item.
        let core = open_item(&item, &me, &seed, implements_core);
        if content == content::LEAVE_REQUEST {
            assert_eq!(class(core), Some("UnknownContent"));
        } else {
            assert_eq!(core.unwrap(), read);
        }
        // It travels in a MailboxPut to the device's mailbox.
        let put = MailboxPut {
            request: 1,
            address: address(Kind::Device, &me.0),
            item: item.clone(),
            kind: Kind::Device,
        };
        let read_put = MailboxPut::read(&peer_control(&put.encode()).unwrap(), Extensions::NONE)
            .unwrap()
            .unwrap();
        assert_eq!(read_put, put);
        let items = MailboxItems {
            request: 2,
            items: vec![([0; 16], item.clone()), ([1; 16], item)],
        };
        assert_eq!(
            MailboxItems::read(&peer_control(&items.encode()).unwrap()).unwrap(),
            items
        );
    }

    for row in family["item_refusals"].as_array().unwrap() {
        assert_eq!(
            class(open_item(&bytes(&row["item"]), &me, &seed, implements_all)),
            Some(text(&row["error"])),
            "{}",
            text(&row["description"])
        );
    }
}

#[test]
fn kind_4_is_the_extension_s() {
    let put = |kind: u64| {
        let mut map = frasil_base::cbor::Map::new();
        map.insert(0, frasil_base::cbor::Value::Unsigned(24));
        map.insert(1, frasil_base::cbor::Value::Unsigned(1));
        map.insert(2, frasil_base::cbor::Value::from([0u8; 32]));
        map.insert(3, frasil_base::cbor::Value::from([0u8; 8]));
        map.insert(6, frasil_base::cbor::Value::Unsigned(kind));
        peer_control(&frasil_base::cbor::Value::Map(map).encode()).unwrap()
    };
    assert_eq!(
        class(MailboxPut::read(&put(4), Extensions::NONE)),
        Some("Malformed")
    );
    let with = Extensions {
        invite_links: true,
        ..Extensions::NONE
    };
    assert_eq!(MailboxPut::read(&put(4), with), Ok(None));
    assert!(
        MailboxPut::read(&put(1), Extensions::NONE)
            .unwrap()
            .is_some()
    );
}

fn item_id(value: &serde_json::Value) -> [u8; 16] {
    u128::from(number(value) as u32).to_be_bytes()
}

fn ids(value: &serde_json::Value) -> Vec<[u8; 16]> {
    value.as_array().unwrap().iter().map(item_id).collect()
}

/// The mailboxes as the vectors describe them: address, claim, and each
/// item's ID and size.
fn describe(peer: &PeerMailboxes) -> serde_json::Value {
    serde_json::Value::Array(
        peer.mailboxes()
            .iter()
            .map(|(address, mailbox)| {
                serde_json::json!({
                    "address": frasil_testkit::hex::encode(address),
                    "claimed": mailbox.claimed,
                    "items": mailbox
                        .items
                        .iter()
                        .map(|(id, size)| serde_json::json!([u128::from_be_bytes(*id), size]))
                        .collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn load(cap: &serde_json::Value, before: &serde_json::Value) -> PeerMailboxes {
    let cap = Cap {
        items: number(&cap["items"]),
        bytes: number(&cap["bytes"]),
    };
    let mut highest = 0;
    let mut boxes = Vec::new();
    for row in before.as_array().unwrap() {
        let items: Vec<([u8; 16], u64)> = row["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| (item_id(&item[0]), number(&item[1])))
            .collect();
        highest = highest.max(
            items
                .iter()
                .map(|i| u128::from_be_bytes(i.0))
                .max()
                .unwrap_or(0),
        );
        boxes.push((
            array::<32>(&row["address"]),
            row["claimed"].as_bool().unwrap(),
            items,
        ));
    }
    let mut peer = PeerMailboxes::new(cap, highest + 1);
    for (address, claim, items) in boxes {
        let mailbox = peer.mailbox(address);
        mailbox.claimed = claim;
        mailbox.items = items;
    }
    peer
}

fn deposit(peer: &mut PeerMailboxes, step: &serde_json::Value) {
    let address = array::<32>(&step["address"]);
    let result = peer.deposit(address, number(&step["bytes"]));
    match text(&step["verdict"]) {
        "accepted" => {
            let deposited = result.unwrap();
            assert_eq!(deposited.id, item_id(&step["id"]));
            assert_eq!(deposited.evicted, ids(&step["evicted"]));
        }
        verdict => assert_eq!(class(result), Some(verdict)),
    }
    assert_eq!(describe(peer), step["after"]);
}

#[test]
fn the_peer_s_caps() {
    let caps = &family("mailboxes")["peer_caps"];
    let mut peer = load(&caps["cap"], &caps["before"]);
    assert_eq!(describe(&peer), caps["before"]);
    for step in caps["steps"].as_array().unwrap() {
        deposit(&mut peer, step);
    }
    let by_bytes = &caps["by_bytes"];
    let mut peer = load(&by_bytes["cap"], &by_bytes["before"]);
    deposit(&mut peer, &by_bytes["step"]);
}

#[test]
fn claimed_mailboxes_and_what_they_keep() {
    let caps = &family("mailboxes")["peer_caps"];
    let retention = number(&caps["mailbox_retention"]);
    let uncollected = number(&caps["uncollected_retention"]);
    let readings = |value: &serde_json::Value| -> Vec<u64> {
        value.as_array().unwrap().iter().map(number).collect()
    };
    for row in caps["claimed"].as_array().unwrap() {
        let now = number(&row["now"]);
        let last = readings(&row["collections"])
            .into_iter()
            .filter(|&c| c <= now)
            .max();
        assert_eq!(
            claimed(last, now, retention),
            row["claimed"].as_bool().unwrap()
        );
    }
    for row in caps["kept"].as_array().unwrap() {
        let deposited = number(&row["deposited"]);
        let collections = readings(&row["collections"]);
        let before = collections
            .iter()
            .copied()
            .filter(|&c| c <= deposited)
            .max();
        let after = collections
            .iter()
            .copied()
            .filter(|&c| c >= deposited)
            .min();
        assert_eq!(
            item_kept(
                deposited,
                claimed(before, deposited, retention),
                after,
                number(&row["now"]),
                retention,
                uncollected
            ),
            row["kept"].as_bool().unwrap(),
            "{}",
            text(&row["case"])
        );
    }
}

#[test]
fn key_7_at_a_core_peer() {
    let case = &family("mailboxes")["token_put"];
    let message = peer_control(&bytes(&case["message"])).unwrap();
    assert_eq!(
        class(MailboxPut::read(&message, Extensions::NONE)),
        Some(text(&case["error"]))
    );
    // With the extension's flag, a build without its feature is still a
    // core peer; with the feature, the extension reads the token.
    let with = Extensions {
        deposit_tokens: true,
        ..Extensions::NONE
    };
    if cfg!(feature = "ext-deposit-tokens") {
        assert_eq!(MailboxPut::read(&message, with), Ok(None));
    } else {
        assert_eq!(
            class(MailboxPut::read(&message, with)),
            Some(text(&case["error"]))
        );
    }
}
