//! admission.json's `new_device` family (admission.md, section 3.4: a
//! person's new device, ctx `0x01`, end to end).

mod common;

use common::*;
use frasil_admission::bodies::{ListEvents, RevealBody};
use frasil_admission::new_device::{add_body, check_list_result};
use frasil_admission::{Approver, Ctx};
use frasil_crypto::device::DeviceId;
use frasil_crypto::fixtures::FixtureKeys;
use frasil_events::{EventId, decode};
use frasil_identity::Kind;
use frasil_identity::body::{Action, ListBody};

/// The device ID of a device of crypto.md's fixture derivations.
fn fixture_device(seed: &str) -> DeviceId {
    FixtureKeys::from_identity_seed(&example(seed)).device_id()
}

#[test]
fn new_device() {
    let v = family("new_device");
    let person: [u8; 32] = array(&v["person"]);
    let heads = ids(&v["heads"]);
    let keys = &v["new_device"];
    let device = Device::new(array(&keys["identity_seed"]), array(&keys["xwing_seed"]));
    device.check_json(keys);
    let phone = fixture_device("admission/ada/phone/ed25519");
    let tablet = fixture_device("admission/ada/tablet/ed25519");

    // The exchange.
    let tag = "admission/ada";
    let (mut joiner, request) = joiner(
        start(Ctx::DeviceList, tag, T_EXPIRES, "Ada's new laptop", b""),
        device.keys(),
    );
    assert_eq!(h(&request), text(&v["request"]));
    let mut approver = Approver::new(side(
        phone,
        Ctx::DeviceList,
        person,
        heads.clone(),
        Vec::new(),
        "Ada's phone",
        b"",
    ))
    .unwrap();
    let response = approver
        .on_request_with(&request, Some(T_REQUEST), draw(tag, "admission/ada/enc-1"))
        .unwrap();
    assert_eq!(h(&response), text(&v["response"]));
    let revealed = joiner
        .on_response_with(&response, T_RESPONSE, &eseed("admission/ada/enc-2"))
        .unwrap();
    assert_eq!(h(&revealed.message), text(&v["reveal"]));

    // A new device that expects a person (admission.md, 3.1 The joiner,
    // step 5): it reveals for its person's Response, and refuses another
    // person's before it signs anything over its log.
    let expected = &v["expected_person"];
    let other: [u8; 32] = array(&expected["other_person"]);
    for (name, person) in [
        ("the expected person", person),
        ("another person than the expected one", other),
    ] {
        let (mut expecting, _) = frasil_admission::Joiner::start_with(
            start(Ctx::DeviceList, tag, T_EXPIRES, "Ada's new laptop", b""),
            device.keys(),
        )
        .unwrap();
        expecting.expect_person(person);
        let got = match expecting.accept_response_with(
            &response,
            T_RESPONSE,
            &eseed("admission/ada/enc-2"),
        ) {
            Ok(Some(again)) if again.message == revealed.message => "accepted".to_owned(),
            Ok(_) => "refused".to_owned(),
            Err(class) => {
                assert!(expecting.response().is_none());
                frasil_base::errors::Class::name(class).to_owned()
            }
        };
        assert_eq!(got, text(&expected["checks"][name]), "{name}");
    }
    assert_eq!(expected["checks"].as_object().unwrap().len(), 2);
    let approved = approver
        .on_reveal(&revealed.message, Some(T_REVEAL))
        .unwrap()
        .unwrap();
    assert_eq!(approved.code, revealed.code);
    assert_eq!(approved.code.to_string(), text(&v["code"]));

    // The possession proof the Reveal carries, its only proof.
    let RevealBody::Device {
        keys: revealed_keys,
        possession: Some(possession),
        ..
    } = &approved.reveal
    else {
        panic!("a device's Reveal with its possession proof");
    };
    assert_eq!(revealed_keys.device_id(), device.device_id());
    let statement = frasil_identity::possession::statement(
        &person,
        &phone,
        Kind::Device,
        device.signer.identity_key(),
        device.signer.mldsa_public(),
        Some(&device.xwing),
    );
    assert_eq!(h(&statement), text(&v["possession_statement"]));
    assert_eq!(h(possession), text(&v["possession"]));

    // The add the phone signs: the body add_body gives.
    let add = decode(&bytes(&v["add"])).unwrap();
    assert_eq!(add.author(), &phone);
    assert_eq!(
        add.unverified_body(),
        add_body(&approved.reveal).unwrap().encode()
    );

    // The Result.
    let plaintext = bytes(&v["result_plaintext"]);
    let events = ListEvents::read(&plaintext).unwrap();
    assert_eq!(
        ListEvents {
            events: events.events.clone()
        }
        .encode(),
        plaintext
    );
    assert!(events.events.contains(&bytes(&v["add"])));
    assert!(events.events.iter().any(|e| {
        let e = decode(e).unwrap();
        ListBody::decode(e.unverified_body())
            .is_ok_and(|b| b.action == Action::Add && b.device == tablet)
    }));
    let result = approver
        .result_with(
            &approved.request,
            &plaintext,
            Some(T_REVEAL),
            &eseed("admission/ada/enc-3"),
        )
        .unwrap();
    assert_eq!(h(&result), text(&v["result"]));
    let opened = joiner.open_result(&result).unwrap();
    assert_eq!(&opened[..], &plaintext[..]);

    // The new device's checks.
    let response = joiner.response().unwrap();
    let me = device.device_id();
    let mut more_heads = response.heads.clone();
    more_heads.push(EventId(example("admission/ada/x")));
    let without = ListEvents {
        events: events
            .events
            .iter()
            .filter(|e| **e != bytes(&v["add"]))
            .cloned()
            .collect(),
    }
    .encode();
    let accepted = check_list_result(
        &opened,
        &response.log,
        &response.approver,
        &response.heads,
        &me,
    );
    assert_eq!(accepted.as_ref().map(|(id, _)| *id).ok(), Some(add.id()));
    let cases = [
        ("the Result", verdict(accepted)),
        (
            "another approver",
            verdict(check_list_result(
                &opened,
                &response.log,
                &tablet,
                &response.heads,
                &me,
            )),
        ),
        (
            "another person",
            verdict(check_list_result(
                &opened,
                &example("admission/ada/other"),
                &response.approver,
                &response.heads,
                &me,
            )),
        ),
        (
            "a head the add does not follow",
            verdict(check_list_result(
                &opened,
                &response.log,
                &response.approver,
                &more_heads,
                &me,
            )),
        ),
        (
            "a list without the add",
            verdict(check_list_result(
                &without,
                &response.log,
                &response.approver,
                &response.heads,
                &me,
            )),
        ),
    ];
    let want = &v["checks"];
    assert_eq!(want.as_object().unwrap().len(), cases.len());
    for (name, got) in cases {
        assert_eq!(got, text(&want[name]), "{name}");
    }
}

/// `new_device.direct` (admission.md, section 3.4, "Over a direct
/// connection"): the same exchange with the connection's channel, the
/// Result, and a Welcome after it.
#[test]
fn new_device_direct() {
    use frasil_admission::MessageType;
    use frasil_admission::message::{seal_info, sealed_message_with};
    use frasil_admission::welcome::Welcome;
    use frasil_crypto::wrap::xwing_public;

    let all = family("new_device");
    let v = &all["direct"];
    let person: [u8; 32] = array(&all["person"]);
    let heads = ids(&all["heads"]);
    let keys = &all["new_device"];
    let device = Device::new(array(&keys["identity_seed"]), array(&keys["xwing_seed"]));
    let phone = fixture_device("admission/ada/phone/ed25519");
    let tag = "admission/ada/direct";
    let channel = bytes(&v["channel"]);
    assert_eq!(h(&channel), h(example(&format!("{tag}/exporter"))));

    let (mut joiner, request) = joiner(
        start(Ctx::DeviceList, tag, T_EXPIRES, "Carol", &channel),
        device.keys(),
    );
    assert_eq!(h(&request), text(&v["request"]));
    let mut approver = Approver::new(side(
        phone,
        Ctx::DeviceList,
        person,
        heads,
        Vec::new(),
        "Desktop",
        &channel,
    ))
    .unwrap();
    let response = approver
        .on_request_with(
            &request,
            Some(T_REQUEST),
            draw(tag, &format!("{tag}/enc-1")),
        )
        .unwrap();
    assert_eq!(h(&response), text(&v["response"]));
    let revealed = joiner
        .on_response_with(&response, T_RESPONSE, &eseed(&format!("{tag}/enc-2")))
        .unwrap();
    assert_eq!(h(&revealed.message), text(&v["reveal"]));
    let approved = approver
        .on_reveal(&revealed.message, Some(T_REVEAL))
        .unwrap()
        .unwrap();
    assert_eq!(approved.code, revealed.code);
    assert_eq!(approved.code.to_string(), text(&v["code"]));
    assert_ne!(text(&v["code"]), text(&all["code"]));

    let plaintext = bytes(&all["result_plaintext"]);
    let result = approver
        .result_with(
            &approved.request,
            &plaintext,
            Some(T_REVEAL),
            &eseed(&format!("{tag}/enc-3")),
        )
        .unwrap();
    assert_eq!(h(&result), text(&v["result"]));
    assert_eq!(&joiner.open_result(&result).unwrap()[..], &plaintext[..]);

    // The Welcome after the Result.
    let welcome = Welcome::read(&bytes(&v["welcome"])).unwrap();
    assert_eq!(h(welcome.encode()), text(&v["welcome"]));
    assert_eq!(welcome.approver, phone);
    assert!(welcome.peers.is_empty() && welcome.snapshot.is_none());
    assert_eq!(
        h(seal_info(&approved.request, MessageType::Welcome)),
        text(&v["welcome_seal_info"])
    );
    let message = approver
        .welcome_with(
            &approved.request,
            &welcome.encode(),
            &eseed(&format!("{tag}/enc-4")),
        )
        .unwrap();
    assert_eq!(h(&message), text(&v["welcome_message"]));

    let other = Welcome {
        approver: DeviceId(example(&format!("{tag}/another-approver"))),
        ..welcome.clone()
    };
    let to_another = approver
        .welcome_with(
            &approved.request,
            &other.encode(),
            &eseed(&format!("{tag}/enc-5")),
        )
        .unwrap();
    let mailbox_eph = xwing_public(&example("admission/ada/eph-j"));
    let sealed_elsewhere = sealed_message_with(
        MessageType::Welcome,
        &approved.request,
        &mailbox_eph[..],
        &welcome.encode(),
        &eseed(&format!("{tag}/enc-6")),
    )
    .unwrap();
    let cases = [
        ("the Result", "accepted"),
        ("the Welcome", verdict(joiner.on_welcome(&message))),
        (
            "a Welcome naming another approver",
            verdict(joiner.on_welcome(&to_another)),
        ),
        (
            "a Welcome sealed to another exchange's key",
            verdict(joiner.on_welcome(&sealed_elsewhere)),
        ),
    ];
    let want = &v["checks"];
    assert_eq!(want.as_object().unwrap().len(), cases.len());
    for (name, got) in cases {
        assert_eq!(got, text(&want[name]), "{name}");
    }
}
