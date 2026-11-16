//! frasil-identity's device list on arbitrary bytes (identity.md, "Checking
//! a list event alone", "Checks at the event's place" and "The merge"): the
//! bytes as a signed list event, and as the body of a list event that a
//! list member signs in the envelope (so that the body's checks after the
//! signature are reached). Each is inserted into a small list and the list
//! merged. They never panic; a list refuses or voids an event only with the
//! classes of its procedure; and steps 2 to 5 agree with the body's own
//! checks.
#![no_main]

use frasil_base::errors::Class;
use frasil_crypto::schemes::Scheme;
use frasil_events::kind::DEVICE_LIST;
use frasil_events::{Envelope, Placement, decode};
use frasil_identity::body::{ListBody, check_body};
use frasil_identity::{DeviceList, Kind, MemberKeys, Refusal};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// A list of two devices: the laptop, which starts it, and the phone.
fn base() -> &'static (DeviceList, MemberKeys) {
    static BASE: OnceLock<(DeviceList, MemberKeys)> = OnceLock::new();
    BASE.get_or_init(|| {
        let laptop = MemberKeys::from_seeds(&[1; 32], &[2; 32], &[3; 32]);
        let phone = MemberKeys::from_seeds(&[4; 32], &[5; 32], &[6; 32]);
        let mut list = DeviceList::new(&DeviceList::first_event(&laptop)).expect("a first event");
        let person = list.person_id();
        let add = ListBody::add(
            Kind::Device,
            &phone.public(Kind::Device),
            phone.prove_possession(&person, laptop.device_id(), Kind::Device),
        );
        let signed = list.sign(&add, laptop.signer());
        list.insert(&signed).expect("the phone's add");
        (list, laptop)
    })
}

/// The classes a merge voids an event with: steps 2 to 7 of "Checking a
/// list event alone", the checks at the event's place, and the attacks.
const VOID: &[&str] = &[
    "Malformed",
    "InvalidKey",
    "NotCommitted",
    "BadPossession",
    "NoHybridKey",
    "BadSignature",
    "Forked",
    "UntrustedSigner",
    "AgentLimited",
    "AlreadyListed",
    "NotListed",
    "RecoveryKeyProtected",
    "NotPending",
    "LastMember",
    "Full",
    "RevokedConcurrently",
    "TargetRevokedConcurrently",
];

/// Inserts a signed event into the base list and merges it.
fn insert(signed: &[u8]) {
    let (base, _) = base();
    let mut list = base.clone();
    match list.insert(signed) {
        Ok(Placement::Placed(ids)) => {
            let merged = list.merge();
            for id in ids {
                let verdict = merged.verdict(id).expect("a placed event has a verdict");
                if let Some(class) = verdict.class() {
                    assert!(VOID.contains(&class.name()), "{}", class.name());
                }
                // Steps 2 to 5 are the body's own checks.
                let event = list.log().event(id).expect("placed");
                let alone = check_body(
                    event.unverified_body(),
                    event.author(),
                    Some(&list.person_id()),
                );
                assert_eq!(alone.is_ok(), list.body(id).is_some());
            }
            // The merged list never loses the first event.
            assert!(merged.is_valid(list.first()));
        }
        Ok(Placement::Pending(_) | Placement::Known) => {}
        Err(Refusal::Event(class)) => assert!(
            matches!(
                class.name(),
                "TooLarge"
                    | "Malformed"
                    | "UnsupportedVersion"
                    | "SchemeNotAllowed"
                    | "UnknownKind"
                    | "InvalidKey"
                    | "BadSignature"
                    | "WrongLog"
            ),
            "{}",
            class.name()
        ),
        Err(Refusal::List(class)) => assert_eq!(class.name(), "Malformed"),
    }
}

fuzz_target!(|data: &[u8]| {
    insert(data);
    // A first event of arbitrary bytes starts a list, or is refused.
    if let Ok(list) = DeviceList::new(data) {
        assert_eq!(decode(data).map(|e| e.id().0).ok(), Some(list.person_id()));
        assert!(list.merge().is_valid(list.first()));
    }

    // The bytes as the body of the laptop's next list event.
    let (list, laptop) = base();
    let (seq, prev) = list.log().next_in_chain(laptop.device_id());
    let signed = Envelope {
        kind: DEVICE_LIST,
        log: Some(list.log().id()),
        ed: *laptop.identity(),
        kc: *laptop.signer().kc(),
        seq,
        prev,
        parents: list.log().heads(),
        cuts: Vec::new(),
        body: data.to_vec(),
        scheme: Scheme::Hybrid,
    }
    .sign(laptop.signer());
    insert(&signed);
});
