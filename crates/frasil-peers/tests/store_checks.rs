//! An enrolment whose keys miss its `kc` (peers.md, "What a peer checks
//! before it stores a skeleton event", step 3).
//!
//! The peer refuses it `NotCommitted` only once the administrator slot, its
//! `seq` and its author have passed (`BadSignature` otherwise), and an
//! event the peer refuses gives no evidence of a fork against its author.

mod builder;

use builder::{Builder, Space, example, grant, pseudonym, signer, space_with_a};
use frasil_base::ErrorClass;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_events::EventId;
use frasil_peers::PeersClass;
use frasil_peers::body::{ChangeEffect, SlotId, StorageBody};
use frasil_peers::derive::{SlotKeys, enrol_statement};
use frasil_peers::skeleton::{Skeleton, Status, refused_at_store};

/// An enrolment by `pseudonym` whose body carries `mldsa` in place of the
/// pseudonym's own ML-DSA-65 key; its authorization is genuine.
fn enrol_with(
    b: &mut Builder,
    pseudonym: &Signer,
    slot: SlotId,
    keys: &SlotKeys,
    mldsa: &[u8],
    parents: &[EventId],
) -> EventId {
    let statement = enrol_statement(&b.space, slot.reference, pseudonym.device_id());
    let body = StorageBody::Enrol {
        slot,
        mldsa: mldsa.to_vec(),
        slot_mldsa: keys.signer.mldsa_public().to_vec(),
        authorization: keys.signer.sign(Scheme::Hybrid, &statement),
        binding: vec![0xbb; 3_445],
    };
    b.storage(pseudonym, body, parents)
}

/// `P0` grants `B` administer, and the founder names the change.
fn grant_b(b: &mut Builder, p0: &Signer) -> (EventId, SlotId, SlotKeys) {
    let c_b = example("c(F grants B)");
    let (map, keys) = grant(&example("token of B"));
    let heads = b.heads();
    let change = b.storage(
        p0,
        StorageBody::Change {
            twin: c_b,
            salt: example("salt of F grants B"),
            effect: ChangeEffect::Grants(vec![map]),
        },
        &heads,
    );
    b.name(&signer("F"), change, &[change]);
    (change, SlotId::new(c_b, 0, change), keys)
}

fn class(status: Option<Status>) -> PeersClass {
    match status {
        Some(Status::Void { class, .. }) => class,
        other => panic!("not void: {other:?}"),
    }
}

#[test]
fn not_committed_is_refused_at_store() {
    assert!(refused_at_store(ErrorClass::NotCommitted.into()));
}

/// An enrolment at `seq` 1 whose `mldsa` is another key's is
/// `NotCommitted`; a second enrolment by the same pseudonym at `seq` 1,
/// with its own keys, enrols it, and the refused one does not fork it.
#[test]
fn an_enrolment_whose_keys_miss_its_kc_is_refused_and_forks_nobody() {
    let Space { mut b, p0, .. } = space_with_a();
    let (change, slot, keys) = grant_b(&mut b, &p0);
    let b1 = pseudonym("B1");
    let other = pseudonym("another pseudonym");
    let refused = enrol_with(&mut b, &b1, slot, &keys, other.mldsa_public(), &[change]);
    // The same author again at seq 1, after the refused one.
    b.last.remove(b1.device_id());
    let heads = b.heads();
    let enrolled = b.enrol(&b1, slot, &keys, &heads);

    let skeleton = Skeleton::new(&b.log, None);
    assert_eq!(
        class(skeleton.status(refused)),
        ErrorClass::NotCommitted.into()
    );
    assert!(skeleton.is_valid(enrolled));
    assert_eq!(skeleton.forks().fork_point(b1.device_id()), None);
    assert!(skeleton.slot_of(b1.device_id()).is_some());
}

/// An enrolment at `seq` 2 whose `mldsa` is another key's: the `seq`
/// check comes before the `kc` check, so it is `BadSignature`.
#[test]
fn an_enrolment_past_seq_one_is_bad_signature_before_its_keys_are_read() {
    let Space { mut b, p0, .. } = space_with_a();
    let (_, slot, keys) = grant_b(&mut b, &p0);
    let b1 = pseudonym("B1");
    let heads = b.heads();
    let first = b.storage(&b1, StorageBody::Ack, &heads);
    let other = pseudonym("another pseudonym");
    let heads = b.heads();
    let second = enrol_with(&mut b, &b1, slot, &keys, other.mldsa_public(), &heads);

    let skeleton = Skeleton::new(&b.log, None);
    assert_eq!(class(skeleton.status(first)), PeersClass::NotAuthorized);
    assert_eq!(
        class(skeleton.status(second)),
        ErrorClass::BadSignature.into()
    );
}

/// An enrolment by a pseudonym the peer holds already, whose `mldsa` is
/// another key's, is `BadSignature`.
#[test]
fn an_enrolment_by_a_held_pseudonym_is_bad_signature_before_its_keys_are_read() {
    let Space {
        mut b,
        a1,
        c_a,
        change,
        keys,
        ..
    } = space_with_a();
    let other = pseudonym("another pseudonym");
    let heads = b.heads();
    let again = enrol_with(
        &mut b,
        &a1,
        SlotId::new(c_a, 0, change),
        &keys,
        other.mldsa_public(),
        &heads,
    );
    let skeleton = Skeleton::new(&b.log, None);
    assert!(skeleton.slot_of(a1.device_id()).is_some());
    assert_eq!(
        class(skeleton.status(again)),
        ErrorClass::BadSignature.into()
    );
}

/// A disown whose slot reference names a maker that did not make that
/// administrator slot is `UnknownAdministratorSlot` (peers.md, "What a peer
/// checks before it stores a skeleton event", step 5): another commitment,
/// an index the maker has no grant at, or the root at an index past 0.
#[test]
fn a_disown_naming_a_maker_that_did_not_make_the_slot_is_refused() {
    let Space {
        mut b,
        p0,
        root,
        c_genesis,
        change,
        c_a,
        ..
    } = space_with_a();
    let refs = [
        SlotId::new(c_genesis, 0, change),
        SlotId::new(c_a, 1, change),
        SlotId::new(c_genesis, 1, root),
        SlotId::new(c_a, 0, root),
    ];
    let mut disowns = Vec::new();
    for slot in refs {
        let heads = b.heads();
        disowns.push(b.storage(&p0, StorageBody::Disown { slot }, &heads));
    }
    let skeleton = Skeleton::new(&b.log, None);
    for id in disowns {
        assert_eq!(
            class(skeleton.status(id)),
            PeersClass::UnknownAdministratorSlot
        );
    }
    assert!(refused_at_store(PeersClass::UnknownAdministratorSlot));
    assert!(refused_at_store(PeersClass::PlantedSlotsFull));
}
