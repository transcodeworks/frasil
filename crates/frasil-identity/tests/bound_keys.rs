//! A list `add` cannot bind an ML-DSA-65 key to another device (identity.md,
//! "The device-list event" and "Security considerations", "A list cannot
//! lend a key to another device").
//!
//! A scheme-2 signature has an Ed25519 half and an ML-DSA-65 half
//! (crypto.md, "Signature schemes"). This test models an adversary that can
//! produce the Ed25519 half for a victim's key, a quantum adversary at
//! verification time, by holding the victim device's Ed25519 seed but not
//! its ML-DSA-65 seed. The adversary is a person with a list of its own and
//! an ML-DSA-65 key `M2` of its own. frasil-space's `bound_keys` tests
//! follow the same keys into a space that names the person.

use frasil_base::ErrorClass;
use frasil_crypto::device::KeyRing;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_crypto::wrap::xwing_public;
use frasil_events::kind::DEVICE_LIST;
use frasil_events::{Envelope, decode};
use frasil_identity::body::ListBody;
use frasil_identity::{DeviceList, IdentityClass, Kind, MemberKeys};

/// The adversary's own ML-DSA-65 seed, which signs as `M2`.
const M2_SEED: [u8; 32] = [0x4d; 32];

/// A person's own list names another person's device's Ed25519 key beside
/// `M2`: the `add` names a device ID of its own, and nothing it signs is the
/// victim's.
///
/// The adversary's device `a1` starts person A's list, then adds a device
/// whose identity is the victim's Ed25519 key and whose ML-DSA-65 key is
/// `M2`, with a possession proof whose Ed25519 half is the victim's and
/// whose ML-DSA-65 half `M2`'s. That `add` is valid in A's list, but its
/// key 3 is the device ID of those keys, which is not the victim's. An
/// event signed with the victim's Ed25519 seed and `M2`:
///
/// - under that key set's own `kc` verifies in full, as that other device;
/// - under the victim's own `kc` waits for the victim's keys
///   (`NoHybridKey`), and once they are held is `BadSignature`: never the
///   victim's, and it revokes nobody.
#[test]
fn a_list_cannot_bind_its_own_ml_dsa_key_to_another_persons_device() {
    let a1 = MemberKeys::from_seeds(&[1; 32], &[2; 32], &[3; 32]);
    let victim_ed_seed = [0x56; 32];
    let victim = MemberKeys::from_seeds(&victim_ed_seed, &[0x57; 32], &[0x58; 32]);
    let bound = MemberKeys::from_seeds(&victim_ed_seed, &[0x59; 32], &M2_SEED);
    assert_eq!(bound.identity(), victim.identity());
    assert_ne!(bound.device_id(), victim.device_id(), "another device ID");

    let mut list = DeviceList::new(&DeviceList::first_event(&a1)).unwrap();
    let person = list.person_id();
    let add = ListBody::add(
        Kind::Device,
        &bound.public(Kind::Device),
        bound.prove_possession(&person, a1.device_id(), Kind::Device),
    );
    assert_eq!(add.device, *bound.device_id());
    let add = list.sign(&add, a1.signer());
    let add_id = decode(&add).unwrap().id();
    list.insert(&add).unwrap();
    assert_eq!(list.check_alone(add_id), None, "the add passes alone");

    // The same add, naming the victim's device ID beside M2, is refused:
    // the keys do not give it.
    let mut lent = ListBody::add(
        Kind::Device,
        &bound.public(Kind::Device),
        bound.prove_possession(&person, a1.device_id(), Kind::Device),
    );
    lent.device = *victim.device_id();
    let lent = list.sign(&lent, a1.signer());
    let lent_id = decode(&lent).unwrap().id();
    let mut refused = list.clone();
    refused.insert(&lent).unwrap();
    assert_eq!(
        refused.check_alone(lent_id),
        Some(IdentityClass::Shared(ErrorClass::NotCommitted))
    );

    // An event under the victim's Ed25519 key and kc, its ML-DSA-65 half
    // made with M2.
    let forger = Signer::from_seeds(&victim_ed_seed, &M2_SEED, Some(&xwing_public(&[0x59; 32])));
    let (seq, prev) = list.log().next_in_chain(victim.device_id());
    let framed = Envelope {
        kind: DEVICE_LIST,
        log: Some(list.first()),
        ed: *victim.identity(),
        kc: *victim.signer().kc(),
        seq,
        prev,
        parents: list.log().heads(),
        cuts: Vec::new(),
        body: ListBody::revoke(Kind::Device, *a1.device_id()).encode(),
        scheme: Scheme::Hybrid,
    }
    .sign(&forger);
    let framed_id = decode(&framed).unwrap().id();
    assert_eq!(decode(&framed).unwrap().author(), victim.device_id());
    let mut with_framed = list.clone();
    with_framed.insert(&framed).unwrap();
    assert_eq!(
        with_framed.check_alone(framed_id),
        Some(IdentityClass::Shared(ErrorClass::NoHybridKey)),
        "M2 is not the victim's key, whatever A's list says"
    );
    let mut victims = KeyRing::new();
    victims.add_keys(victim.signer().keys().clone());
    with_framed.verify_with(&victims);
    assert_eq!(
        with_framed.check_alone(framed_id),
        Some(IdentityClass::Shared(ErrorClass::BadSignature))
    );
    let merged = with_framed.merge();
    assert!(merged.member(victim.device_id()).is_none());
    assert!(!merged.is_valid(framed_id));
    assert!(merged.active(a1.device_id()).is_some(), "a1 stands");

    // Under the key set's own kc, the event verifies in full: as the other
    // device ID that A's list names, never as the victim.
    let revoke = list.sign(&ListBody::revoke(Kind::Device, *a1.device_id()), &forger);
    let event = decode(&revoke).unwrap();
    assert_eq!(event.author(), bound.device_id());
    assert_ne!(event.author(), victim.device_id());
    list.insert(&revoke).unwrap();
    assert_eq!(list.check_alone(event.id()), None, "it verifies in full");
    let merged = list.merge();
    assert!(merged.member(victim.device_id()).is_none());
    let member = merged.member(bound.device_id()).unwrap();
    assert_eq!(member.kind, Kind::Device);
    assert_eq!(
        merged.keys(bound.device_id()).unwrap().identity,
        *victim.identity()
    );
}
