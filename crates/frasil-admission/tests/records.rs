//! admission.json's `lookup`, `access_request` and `welcome_request` families (admission.md,
//! sections 2.11, 2.12, 3.9 and 3.14).

mod common;

use common::*;
use frasil_admission::access::AccessRequest;
use frasil_admission::lookup::{Join, Prompt, PromptAnswer, answer_prompt, sign_record};
use frasil_admission::message::{MessageType, seal_info};
use frasil_base::cbor::{Map, Value, decode};
use frasil_crypto::device::{DeviceId, IdentityKey, KeyRing};
use frasil_crypto::fixtures::fixture_mldsa_seed;
use frasil_crypto::labels::{ACCESS_REQUEST, ADMISSION_PROMPT};
use frasil_crypto::sizes::MLDSA65_PUBLIC;
use frasil_space::{Level, MemberRef};

/// A signed record with another record in place of the signed one.
fn with_record(signed: &[u8], record: &[u8]) -> Vec<u8> {
    let outer = decode(signed).unwrap();
    let mut map: Map = outer.as_map().unwrap().clone();
    map.insert(1, Value::from(record));
    Value::Map(map).encode()
}

/// A signed record with another signer's signature over it.
fn with_signature(signed: &[u8], other: &[u8]) -> Vec<u8> {
    let outer = decode(signed).unwrap();
    let mut map: Map = outer.as_map().unwrap().clone();
    map.insert(2, decode(other).unwrap().as_map().unwrap()[&2].clone());
    Value::Map(map).encode()
}

type Keys = (IdentityKey, Box<[u8; MLDSA65_PUBLIC]>);

#[test]
fn lookup() {
    let l = family("lookup");
    let admin = Device::named("alice-desktop");
    let other = Device::named("mallory-desktop");
    let reference = example16("admission/lookup/reference");
    let prompt = Prompt {
        reference,
        approver: admin.device_id(),
        xwing: Box::new(admin.xwing),
        display: "Alice".into(),
        peers: vec!["https://peer.example".into()],
    };
    assert_eq!(h(prompt.encode()), text(&l["prompt"]));
    let signed = prompt.sign(&admin.signer);
    assert_eq!(h(&signed), text(&l["signed_prompt"]));
    assert_eq!(
        signed,
        sign_record(ADMISSION_PROMPT, &prompt.encode(), &admin.signer)
    );

    let known = |device: &DeviceId| -> Option<Keys> {
        (*device == admin.device_id()).then(|| {
            (
                *admin.signer.identity_key(),
                Box::new(*admin.signer.mldsa_public()),
            )
        })
    };
    let forged = with_signature(&signed, &prompt.sign(&other.signer));
    let swapped = Prompt {
        xwing: Box::new(other.xwing),
        peers: Vec::new(),
        ..prompt.clone()
    }
    .sign(&admin.signer);
    let shown = |r: Result<PromptAnswer, frasil_admission::AdmissionClass>| match r {
        Ok(PromptAnswer::Join(_)) => "Join",
        Ok(PromptAnswer::CodeExchange(_)) => "code exchange",
        Err(class) => frasil_base::errors::Class::name(class),
    };
    let answers = [
        ("a co-member's device", shown(answer_prompt(&signed, known))),
        (
            "a device no shared space names",
            shown(answer_prompt(&signed, |_: &DeviceId| -> Option<Keys> {
                None
            })),
        ),
        (
            "signed by another key",
            shown(answer_prompt(&forged, known)),
        ),
        (
            "naming another X-Wing key",
            shown(answer_prompt(&swapped, known)),
        ),
    ];
    let want = &l["answers"];
    assert_eq!(want.as_object().unwrap().len(), answers.len());
    for (case, got) in answers {
        assert_eq!(got, text(&want[case]), "{case}");
    }

    // The Join.
    let join = Join {
        reference,
        person: example("admission/person/bob"),
        events: vec![b"(the person's signed list events)".to_vec()],
        display: "Bob".into(),
    };
    assert_eq!(h(join.encode()), text(&l["join_plain"]));
    assert_eq!(
        h(seal_info(&reference, MessageType::Join)),
        text(&l["seal_info"])
    );
    let message = join
        .message_with(&admin.xwing, &eseed("admission/lookup/enc"))
        .unwrap();
    assert_eq!(h(&message), text(&l["join"]));
    assert_eq!(h(admin.xwing_seed), text(&l["approver_xwing_seed"]));
    assert_eq!(Join::open(&message, &admin.xwing_seed), Ok(join));
}

#[test]
fn access_request() {
    let a = family("access_request");
    let dev = Device::named("requester-phone");
    assert_eq!(
        text(&a["device"]["identity_seed"]),
        h(example("admission/requester-phone/ed25519"))
    );
    assert_eq!(
        text(&a["device"]["mldsa_seed"]),
        h(*fixture_mldsa_seed(&example(
            "admission/requester-phone/ed25519"
        )))
    );
    let request = AccessRequest {
        target: example("admission/access/target"),
        carrier: example("admission/access/carrier"),
        member: MemberRef::person(example("admission/person/dana")),
        device: dev.device_id(),
        level: Level::Write,
        note: Some("For the budget review".into()),
        request: example16("admission/access/request"),
    };
    let record = request.encode();
    assert_eq!(h(&record), text(&a["record"]));
    let signed = request.sign(&dev.signer);
    assert_eq!(h(&signed), text(&a["signed"]));
    assert_eq!(signed, sign_record(ACCESS_REQUEST, &record, &dev.signer));

    assert_eq!(text(&a["device"]["device_id"]), h(dev.device_id().0));
    let mut ring = KeyRing::new();
    ring.add_device(dev.device_keys());
    let keys = &ring;
    let none = &KeyRing::new();
    let mut tampered = record.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let tampered = with_record(&signed, &tampered);
    let same = AccessRequest {
        target: request.carrier,
        note: None,
        request: [0; 16],
        ..request.clone()
    };
    let administer = AccessRequest {
        level: Level::Administer,
        note: None,
        request: [0; 16],
        ..request.clone()
    };
    let checks = [
        (
            "the request",
            AccessRequest::verify(&signed, keys).map(|r| r == request),
        ),
        (
            "no keys held that hash to the device ID",
            AccessRequest::verify(&signed, none).map(|_| true),
        ),
        (
            "a changed request ID",
            AccessRequest::verify(&tampered, keys).map(|_| true),
        ),
        (
            "the target is the carrier",
            AccessRequest::verify(&same.sign(&dev.signer), keys).map(|_| true),
        ),
        (
            "administer asked for",
            AccessRequest::verify(&administer.sign(&dev.signer), keys).map(|_| true),
        ),
    ];
    let want = &a["checks"];
    assert_eq!(want.as_object().unwrap().len(), checks.len());
    for (case, got) in checks {
        assert_ne!(got, Ok(false), "{case}");
        assert_eq!(verdict(got), text(&want[case]), "{case}");
    }
}

/// admission.json's `welcome_request` (admission.md, 2.12 and 3.14): the
/// record and its signed request byte for byte, and the administering
/// device's checks in order: both maps, the version, the fields and the
/// reason, keys that hash to the requester's device ID, the signature;
/// then membership decides between a welcome and nothing.
#[test]
fn welcome_request() {
    use frasil_admission::welcome_request::WelcomeRequest;
    use frasil_crypto::labels::WELCOME_REQUEST;
    let v = family("welcome_request");
    let dev = Device::named("erasing-laptop");
    assert_eq!(text(&v["device"]["device_id"]), h(dev.device_id().0));
    let identity_seed = example("admission/erasing-laptop/ed25519");
    assert_eq!(text(&v["device"]["identity_seed"]), h(identity_seed));
    assert_eq!(text(&v["device"]["xwing_seed"]), h(dev.xwing_seed));
    assert_eq!(
        text(&v["device"]["mldsa_seed"]),
        h(*fixture_mldsa_seed(&identity_seed))
    );
    let space = example("admission/welcome-request/space");
    let request = WelcomeRequest {
        space,
        device: dev.device_id(),
        request: example16("admission/welcome-request/id"),
    };
    let record = request.encode();
    assert_eq!(h(&record), text(&v["record"]));
    let signed = request.sign(&dev.signer);
    assert_eq!(h(&signed), text(&v["signed"]));
    assert_eq!(signed, sign_record(WELCOME_REQUEST, &record, &dev.signer));
    assert_eq!(WelcomeRequest::read(&signed).unwrap(), request);

    let mut keys = KeyRing::new();
    keys.add_device(dev.device_keys());
    let answer = |signed: &[u8], keys: &KeyRing, member: bool| -> &'static str {
        match WelcomeRequest::verify(signed, keys) {
            Ok(_) if member => "welcome",
            Ok(_) => "ignored",
            Err(class) => frasil_base::errors::Class::name(class),
        }
    };
    // The reason byte, the record's last, changed under the signature.
    let mut tampered = record.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let other_id = WelcomeRequest {
        request: [0; 16],
        ..request.clone()
    };
    let with_entry = |key: u64, value: Value| -> Vec<u8> {
        let mut map: Map = decode(&record).unwrap().as_map().unwrap().clone();
        map.insert(key, value);
        sign_record(WELCOME_REQUEST, &Value::Map(map).encode(), &dev.signer)
    };
    let mut other_reason = decode(&other_id.encode())
        .unwrap()
        .as_map()
        .unwrap()
        .clone();
    other_reason.insert(5, Value::Unsigned(2));
    let other_reason = sign_record(
        WELCOME_REQUEST,
        &Value::Map(other_reason).encode(),
        &dev.signer,
    );
    let checks = [
        ("the request, from a member", answer(&signed, &keys, true)),
        (
            "the request, from a device that is no member",
            answer(&signed, &keys, false),
        ),
        (
            "no keys held that hash to the device ID",
            answer(&signed, &KeyRing::new(), true),
        ),
        (
            "a changed reason",
            answer(&with_record(&signed, &tampered), &keys, true),
        ),
        (
            "signed over another request",
            answer(&with_record(&signed, &other_id.encode()), &keys, true),
        ),
        (
            "version 2",
            answer(&with_entry(1, Value::Unsigned(2)), &keys, true),
        ),
        (
            "a reason it does not know",
            answer(&other_reason, &keys, true),
        ),
    ];
    let cases = v["checks"].as_object().unwrap();
    assert_eq!(cases.len(), checks.len(), "every case");
    for (name, got) in checks {
        assert_eq!(got, text(&cases[name]), "{name}");
    }
}

#[test]
fn welcome_requests_bind_signature_and_requester() {
    use frasil_admission::welcome_request::WelcomeRequest;
    let dev = Device::named("requester-phone");
    let request = WelcomeRequest {
        space: [42; 32],
        device: dev.device_id(),
        request: [7; 16],
    };
    let signed = request.sign(&dev.signer);
    let mut keys = KeyRing::new();
    keys.add_device(dev.device_keys());
    assert_eq!(WelcomeRequest::verify(&signed, &keys).unwrap(), request);
    assert_eq!(
        outcome(WelcomeRequest::verify(&signed, &KeyRing::new()).map(Some)),
        "NoHybridKey"
    );
    let other = Device::named("approver-phone");
    let forged = request.sign(&other.signer);
    assert_eq!(
        outcome(WelcomeRequest::verify(&forged, &keys).map(Some)),
        "BadSignature"
    );
    let mut changed = request.clone();
    changed.request[0] ^= 1;
    assert_eq!(
        outcome(WelcomeRequest::verify(&with_record(&signed, &changed.encode()), &keys).map(Some)),
        "BadSignature"
    );
}
