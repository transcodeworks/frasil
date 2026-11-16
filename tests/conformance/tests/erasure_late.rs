//! Keyless checks of a late-erasure answer from peers.json.
use frasil_base::ErrorClass;
use frasil_events::EventId;
use frasil_peers::{
    PeersClass,
    body::SlotId,
    erasure::{LateErasure, check_late},
};
use frasil_testkit::{hex, vectors::VectorFile};
use frasil_transport::frame::{ConnectionKind, Extensions, StreamClass, read_message};
use frasil_transport::messages::ErasureLate;
use serde_json::Value;

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn id(value: &Value) -> [u8; 32] {
    bytes(value).try_into().unwrap()
}

fn answer(value: &Value) -> ErasureLate {
    ErasureLate::read(
        &read_message(
            &bytes(value),
            StreamClass::Control,
            ConnectionKind::DeviceToPeer,
            Extensions::NONE,
        )
        .unwrap()
        .unwrap(),
    )
    .unwrap()
}

fn check(
    message: &ErasureLate,
    space: [u8; 32],
    erasure: [u8; 32],
    slot: SlotId,
) -> Result<EventId, PeersClass> {
    check_late(
        EventId(space),
        EventId(erasure),
        slot,
        LateErasure {
            space: EventId(message.space),
            erasure: EventId(message.erasure),
            cut: &message.cut,
            checkpoint: EventId(message.checkpoint),
            standing: message.standing,
        },
    )
}

#[test]
fn concurrent_erasure_answer_and_three_refusals() {
    let file = VectorFile::load("peers.json").unwrap();
    let case = &file.family("skeleton_cuts").unwrap()["concurrent_request"]["erasure_late"];
    let slot = SlotId::new(
        id(&case["slot"][0]),
        case["slot"][1].as_u64().unwrap() as u8,
        EventId(id(&case["slot"][2])),
    );
    let space = id(&case["space"]);
    let erasure = id(&case["erasure"]);
    let message = answer(&case["message"]);
    assert_eq!(message.encode(), bytes(&case["message"]));
    assert_eq!(message.standing, case["standing"].as_u64().unwrap() as u8);
    assert_eq!(
        frasil_events::decode(&message.cut).unwrap().id().0,
        id(&case["cut"])
    );
    assert_eq!(
        check(&message, space, erasure, slot),
        Ok(EventId(id(&case["checkpoint"])))
    );
    let contradictory = answer(&case["refusals"][0]["message"]);
    assert_eq!(
        check(&contradictory, space, erasure, slot),
        Err(PeersClass::PeerError)
    );
    assert_eq!(
        frasil_base::errors::Class::name(check(&contradictory, space, erasure, slot).unwrap_err()),
        case["refusals"][0]["error"].as_str().unwrap()
    );
    let mut corrupt = message.clone();
    let last = corrupt.cut.len() - 1;
    corrupt.cut[last] ^= 1;
    // A residue checks only the Ed25519 half, without the hybrid key.
    assert!(check(&corrupt, space, erasure, slot).is_ok());
    let frasil_base::cbor::Value::Array(mut signed) =
        frasil_base::cbor::decode(&message.cut).unwrap()
    else {
        panic!("signed envelope")
    };
    let mut signature = signed[1].as_bytes().unwrap().to_vec();
    signature[0] ^= 1;
    signed[1] = signature.into();
    corrupt.cut = frasil_base::cbor::Value::Array(signed).encode();
    assert_eq!(
        check(&corrupt, space, erasure, slot),
        Err(PeersClass::PeerError)
    );
    let mut swapped = message.clone();
    swapped.cut = bytes(
        &file.family("skeleton_cuts").unwrap()["concurrent_request"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| id(&row["id"]) == message.checkpoint)
            .unwrap()["signed"],
    );
    assert_eq!(
        check(&swapped, space, erasure, slot),
        Err(PeersClass::PeerError)
    );
    assert_eq!(
        frasil_base::errors::Class::name(check(&swapped, space, erasure, slot).unwrap_err()),
        case["refusals"][1]["error"].as_str().unwrap()
    );
    let mut another = message;
    another.erasure[0] ^= 1;
    assert_eq!(
        check(&another, space, erasure, slot),
        Err(ErrorClass::Malformed.into())
    );
    assert_eq!(
        frasil_base::errors::Class::name(check(&another, space, erasure, slot).unwrap_err()),
        case["refusals"][2]["error"].as_str().unwrap()
    );
}

#[test]
fn held_slots_distinguish_named_and_empty_cut_entries() {
    let file = VectorFile::load("peers.json").unwrap();
    let cases = &file.family("skeleton_cuts").unwrap()["slot_held"];
    for name in ["another", "none"] {
        let case = &cases[name];
        let rows = case["events"].as_array().unwrap();
        let events: Vec<_> = rows
            .iter()
            .map(|row| frasil_events::decode(&bytes(&row["signed"])).unwrap())
            .collect();
        let mut log = frasil_events::Log::new(events[0].clone()).unwrap();
        for event in &events[1..] {
            log.place(event.clone()).unwrap();
        }
        let named =
            |name: &str| events[rows.iter().position(|row| row["name"] == name).unwrap()].id();
        let slot = SlotId::new(
            id(&case["slot"][0]),
            case["slot"][1].as_u64().unwrap() as u8,
            EventId(id(&case["slot"][2])),
        );
        let message = answer(&case["message"]);
        assert_eq!(message.standing, 1);
        assert!(
            check(
                &message,
                id(&case["space"]),
                named(case["erasure"].as_str().unwrap()).0,
                slot
            )
            .is_ok()
        );
        let cut = frasil_events::decode(&message.cut).unwrap();
        let frasil_peers::body::StorageBody::Cut(cut) =
            frasil_peers::body::StorageBody::read(cut.unverified_body()).unwrap()
        else {
            panic!("cut")
        };
        let entry = cut.slots.iter().find(|entry| entry.slot == slot).unwrap();
        assert_eq!(entry.pseudonym.is_some(), name == "another");
        assert_eq!(
            case["residue_action"],
            if entry.pseudonym.is_some() {
                "slot held"
            } else {
                "back in"
            }
        );
        let again = named(case["enrolling_again"]["event"].as_str().unwrap());
        assert!(
            frasil_peers::body::StorageBody::read(log.event(again).unwrap().unverified_body())
                .is_ok(),
            "{name}: enrolment body"
        );
        let cuts = frasil_peers::cut::PeerCuts::new(&log, None);
        assert_eq!(
            cuts.skeleton().status(again).unwrap(),
            frasil_peers::skeleton::Status::Void {
                class: PeersClass::AlreadyEnrolled,
                by: None
            }
        );
        let mut contradictory = message;
        if entry.pseudonym.is_none() {
            contradictory.standing = 0;
            assert_eq!(
                check(
                    &contradictory,
                    id(&case["space"]),
                    named(case["erasure"].as_str().unwrap()).0,
                    slot
                ),
                Err(PeersClass::PeerError)
            );
        }
    }
}
