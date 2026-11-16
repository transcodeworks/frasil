//! admission.json's `setup` family (admission.md, sections 2.9 and 3.8).

mod common;

use common::*;
use frasil_admission::Offer;
use frasil_admission::bodies::{HelloBody, OfferBody, RevealedKeys};
use frasil_admission::mailbox::ExchangeMailboxes;
use frasil_admission::message::{MessageType, seal_info, sealed_message_with};
use frasil_admission::setup::{
    HeadlessDevice, SetupAnswer, SetupCode, SetupDraw, SetupState, announced_name, check_hello,
    offer_message_with, read_hello, setup_mac,
};
use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_crypto::wrap::xwing_public;
use frasil_events::EventId;
use frasil_space::{Capability, CapabilityMode, HistoryMode, Level};
use zeroize::Zeroizing;

#[test]
fn setup() {
    let s = family("setup");
    let dev = Device::named("rack-executor");
    dev.check_json(&s["device"]);
    let secret: [u8; 16] = example16("admission/setup/secret");
    assert_eq!(h(secret), text(&s["secret"]));
    let request = example16("admission/setup/request");
    assert_eq!(h(request), text(&s["request"]));
    assert_eq!(h(example("admission/setup/eph-j")), text(&s["eph_j_seed"]));
    assert_eq!(h(example("admission/setup/eph-i")), text(&s["eph_i_seed"]));
    let mut device = HeadlessDevice::new_with(
        &dev.signer,
        "Rack 3 executor",
        SetupDraw {
            secret: Zeroizing::new(secret),
            request,
            eph_seed: Zeroizing::new(example("admission/setup/eph-j")),
        },
    )
    .unwrap();

    // The code, its text, tag and announced name.
    let code = device.setup_code();
    assert_eq!(h(code.encode()), text(&s["code"]));
    assert_eq!(code.text(), text(&s["text"]));
    assert_eq!(h(code.tag()), text(&s["tag"]));
    assert_eq!(announced_name(&secret), text(&s["announced_name"]));
    assert_eq!(
        device.announced_name().as_deref(),
        Some(text(&s["announced_name"]))
    );
    let scanned = SetupCode::read(text(&s["text"])).unwrap();
    assert_eq!(scanned, code);

    // The Hello, the fields, the MAC and the Offer.
    let hello = device.hello();
    assert_eq!(h(&hello), text(&s["hello"]));
    let (hello_request, got) = read_hello(&hello).unwrap();
    assert_eq!(hello_request, request);
    assert_eq!(h(device.j_fields().encode()), text(&s["j_fields"]));
    let host = Device::named("host-desktop");
    let other = Device::named("not-the-rack");
    let offer = Offer {
        capabilities: Some(vec![Capability {
            name: "execute".into(),
            mode: CapabilityMode::Extends,
        }]),
        label: Some("Rack executor".into()),
        ..Offer::new(Level::Write, HistoryMode::FromNowOn)
    };
    let channel = example("admission/setup/exporter");
    assert_eq!(h(channel), text(&s["channel"]));
    let answer = |approver: DeviceId, display: &str| SetupAnswer {
        approver,
        log: example("admission/space/show"),
        heads: vec![EventId(example("admission/space/show/head"))],
        offer: &offer,
        display: display.to_owned(),
        eph_seed: Zeroizing::new(example("admission/setup/eph-i")),
        channel: &channel,
    };
    let (offer_message, i_fields) = offer_message_with(
        &scanned,
        &request,
        &got,
        &answer(host.device_id(), "Stage manager"),
        &eseed("admission/setup/enc-offer"),
    )
    .unwrap();
    assert_eq!(h(i_fields.encode()), text(&s["i_fields"]));
    let mac = setup_mac(
        &secret,
        &device.j_fields().encode(),
        &i_fields.encode(),
        &channel,
    );
    assert_eq!(h(mac), text(&s["mac"]));
    assert_eq!(
        h(seal_info(&request, MessageType::Offer)),
        text(&s["seal_info"])
    );
    assert_eq!(h(&offer_message), text(&s["offer_message"]));

    // An Offer whose MAC does not verify, and another administrator's.
    let mut bad_mac = mac;
    bad_mac[0] ^= 1;
    let bad = sealed_message_with(
        MessageType::Offer,
        &request,
        &got.eph[..],
        &OfferBody {
            log: example("admission/space/show"),
            heads: vec![EventId(example("admission/space/show/head"))],
            approver: host.device_id(),
            eph: Box::new(xwing_public(&example("admission/setup/eph-i"))),
            offer: offer.encode(),
            display: "Stage manager".into(),
            mac: bad_mac,
        }
        .encode(),
        &eseed("admission/setup/enc-bad"),
    )
    .unwrap();
    let (second, _) = offer_message_with(
        &scanned,
        &request,
        &got,
        &answer(other.device_id(), "Someone else"),
        &eseed("admission/setup/enc-second"),
    )
    .unwrap();

    let wrong = HelloBody {
        eph: got.eph.clone(),
        keys: RevealedKeys::of(&other.device_keys()).unwrap(),
        display: got.display.clone(),
    };
    let name = |r: Result<&OfferBody, frasil_admission::AdmissionClass>| match r {
        Ok(_) => "bound",
        Err(class) => class.name(),
    };
    let outcomes = [
        (
            "the administrator, the device's own keys",
            verdict(check_hello(&scanned, &got)),
        ),
        (
            "the administrator, another device's keys",
            verdict(check_hello(&scanned, &wrong)),
        ),
        (
            "the device, a MAC that does not verify",
            name(device.on_offer(&bad, &channel)),
        ),
        (
            "the device, an Offer on another connection",
            name(device.on_offer(&offer_message, &example("admission/setup/other-exporter"))),
        ),
        (
            "the device, the first MAC that verifies",
            name(device.on_offer(&offer_message, &channel)),
        ),
        (
            "the device, a second Offer with a valid MAC",
            name(device.on_offer(&second, &channel)),
        ),
    ];
    let want = &s["outcomes"];
    assert_eq!(want.as_object().unwrap().len(), outcomes.len());
    for (case, got) in outcomes {
        assert_eq!(got, text(&want[case]), "{case}");
    }
    assert!(matches!(device.state(), SetupState::Bound(_)));
    device.provision();
    assert_eq!(device.announced_name(), None);

    // Refused texts.
    let raw = code.encode();
    let full = code.text();
    let body = &full["FRASIL-SETUP:".len()..];
    let with = |bytes: &[u8]| format!("FRASIL-SETUP:{}", base32(bytes));
    let mut v2 = raw;
    v2[0] = 2;
    let refusals = [
        ("no prefix", body.to_owned()),
        (
            "lower case",
            format!("FRASIL-SETUP:{}", body.to_lowercase()),
        ),
        ("version 2", with(&v2)),
        ("one byte short", with(&raw[..raw.len() - 1])),
    ];
    let want = &s["text_refusals"];
    assert_eq!(want.as_object().unwrap().len(), refusals.len());
    for (case, t) in refusals {
        assert_eq!(verdict(SetupCode::read(&t)), text(&want[case]), "{case}");
    }

    // A peer refuses a Hello at an exchange mailbox.
    let mut peer: ExchangeMailboxes<&str> = ExchangeMailboxes::default();
    let refused = peer.put(&"x", &hello, 0).unwrap_err();
    let want = &s["a peer refusing a Hello"];
    assert_eq!(refused.name(), text(&want["result"]));
    let (reason, status) = refused.reason().unwrap();
    assert_eq!(reason, text(&want["reason"]));
    assert_eq!(u64::from(status), want["status"].as_u64().unwrap());
}
