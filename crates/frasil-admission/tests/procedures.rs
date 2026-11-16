//! Procedures admission.json does not exercise as such: a person joiner's
//! List (admission.md, section 3.5), a Join's list (section 3.9), and the
//! approver's bookkeeping (section 3.2).

mod common;

use common::*;
use frasil_admission::joiner::JoinerKeys;
use frasil_admission::lookup::Join;
use frasil_admission::new_device::{check_list, check_list_events};
use frasil_admission::{AdmissionClass, Approver, Ctx, Offer};
use frasil_base::ErrorClass;
use frasil_crypto::fixtures::fixture_mldsa_seed;
use frasil_events::{EventId, decode};
use frasil_identity::{DeviceList, MemberKeys};
use frasil_space::{HistoryMode, Level};

fn person(name: &str) -> (Vec<u8>, [u8; 32]) {
    let seed = example(&format!("procedures/{name}/ed25519"));
    let keys = MemberKeys::from_seeds(
        &seed,
        &example(&format!("procedures/{name}/xwing")),
        &fixture_mldsa_seed(&seed),
    );
    let first = DeviceList::first_event(&keys);
    let id = decode(&first).unwrap().id().0;
    (first, id)
}

#[test]
fn a_person_joins_a_space_with_its_list() {
    let (first, bob) = person("bob");
    let host = Device::named("host-desktop");
    let tag = "procedures/bob";
    let (mut joiner, request) = joiner(
        start(Ctx::Space, tag, T_EXPIRES, "Bob", b""),
        JoinerKeys::Person {
            person: bob,
            heads: vec![EventId(bob)],
        },
    );
    let mut approver = Approver::new(side(
        host.device_id(),
        Ctx::Space,
        example("procedures/space"),
        vec![EventId(example("procedures/space/head"))],
        Offer::new(Level::Write, HistoryMode::WithHistory).encode(),
        "Alice",
        b"",
    ))
    .unwrap();
    let response = approver
        .on_request_with(&request, Some(T_REQUEST), draw(tag, "procedures/enc-1"))
        .unwrap();
    let revealed = joiner
        .on_response_with(&response, T_RESPONSE, &eseed("procedures/enc-2"))
        .unwrap();
    let approved = approver
        .on_reveal(&revealed.message, Some(T_REVEAL))
        .unwrap()
        .unwrap();
    assert_eq!(approved.code, revealed.code);

    // The List, after both people confirmed.
    let list = joiner
        .list_with(vec![first.clone()], &eseed("procedures/enc-3"))
        .unwrap();
    let events = approver.open_list(&list).unwrap();
    let frasil_admission::bodies::RevealBody::Person { heads, .. } = &approved.reveal else {
        panic!("a person's Reveal");
    };
    let plaintext = events.encode();
    assert!(check_list(&plaintext, &bob, Some(heads)).is_ok());
    assert_eq!(
        check_list(&plaintext, &bob, Some(&[EventId([9; 32])])).err(),
        Some(AdmissionClass::ListMismatch)
    );
    let (_, carol) = person("carol");
    assert_eq!(
        check_list(&plaintext, &carol, Some(heads)).err(),
        Some(AdmissionClass::BadList)
    );

    // A Join carries the same list, checked with no committed heads.
    let prompt_key = Device::named("alice-desktop");
    let join = Join {
        reference: example16("procedures/reference"),
        person: bob,
        events: vec![first],
        display: "Bob".into(),
    };
    let message = join
        .message_with(&prompt_key.xwing, &eseed("procedures/enc-4"))
        .unwrap();
    let opened = Join::open(&message, &prompt_key.xwing_seed).unwrap();
    assert!(check_list_events(&opened.events, &opened.person, None).is_ok());
    assert_eq!(
        Join::open(&message, &host.xwing_seed).err(),
        Some(ErrorClass::Decrypt.into())
    );
}

#[test]
fn the_approver_remembers_answered_requests_until_their_grace_ends() {
    let guest = Device::named("guest-laptop");
    let host = Device::named("host-desktop");
    let tag = "procedures/grace";
    let (_, request) = joiner(
        start(Ctx::Space, tag, T_EXPIRES, "Guest", b""),
        guest.keys(),
    );
    let mut approver = Approver::new(side(
        host.device_id(),
        Ctx::Space,
        example("procedures/space"),
        vec![EventId(example("procedures/space/head"))],
        Offer::new(Level::Read, HistoryMode::FromNowOn).encode(),
        "Host",
        b"",
    ))
    .unwrap();
    approver
        .on_request_with(&request, Some(T_REQUEST), draw(tag, "procedures/g1"))
        .unwrap();
    let id = example16(&format!("{tag}/request"));
    assert!(approver.has_answered(&id));
    assert_eq!(
        approver
            .result_with(&id, b"", Some(T_EXPIRES + 1), &eseed("procedures/g2"))
            .err(),
        Some(ErrorClass::Expired.into())
    );
    approver.forget_expired(T_EXPIRES + 60);
    assert!(approver.has_answered(&id));
    approver.forget_expired(T_EXPIRES + 61);
    assert!(!approver.has_answered(&id));
    // A Reveal that does not open ends the request; a second is ignored.
    approver
        .on_request_with(&request, Some(T_REQUEST), draw(tag, "procedures/g3"))
        .unwrap();
    let mut body = vec![0x01, 0x64, 0x7a];
    body.resize(1200, 0);
    let garbage =
        frasil_admission::message::message(frasil_admission::MessageType::Reveal, &id, &body);
    assert_eq!(
        approver.on_reveal(&garbage, Some(T_REVEAL)).err(),
        Some(ErrorClass::Decrypt.into())
    );
    assert!(matches!(
        approver.on_reveal(&garbage, Some(T_REVEAL)),
        Ok(None)
    ));
}
