//! A change that carries a twin commitment another administrator slot was
//! made under (peers.md, "Storage events", "What a peer checks before it
//! stores a skeleton event", "The skeleton's resolution" and "Stability at
//! the peer").
//!
//! A slot reference names the event that made its administrator slot, so a
//! change that repeats a commitment makes administrator slots of its own:
//! it never replaces, resets or takes over the one it copied, an
//! enrolment, lower or disown reaches it only by naming it, and removing it
//! never lowers what it copied.

mod builder;

use builder::{Space, example, grant, pseudonym, signer, space_with_a};
use frasil_base::time::Reading;
use frasil_peers::PeersClass;
use frasil_peers::body::{ChangeEffect, SlotId, StorageBody};
use frasil_peers::decisions::{Execution, erasure};
use frasil_peers::skeleton::{Skeleton, SlotState, Status};

/// T, `erasure_timeout`: seven days.
const T: u64 = 7 * 24 * 3600;

fn reading(t: u64) -> Reading {
    Reading {
        timeline: t,
        wall: None,
        run: 1,
    }
}

fn void(class: PeersClass) -> Option<Status> {
    Some(Status::Void { class, by: None })
}

#[test]
fn a_change_with_the_roots_commitment_does_not_take_the_founders_slot() {
    let Space {
        mut b,
        a,
        a1,
        p0,
        root,
        c_genesis,
        ..
    } = space_with_a();
    // A1 stores a change with the root's commitment and one grant under
    // keys A drew, and A's device names it.
    let (map, keys) = grant(&example("A's own token"));
    let heads = b.heads();
    let copy = b.storage(
        &a1,
        StorageBody::Change {
            twin: c_genesis,
            salt: example("A's salt"),
            effect: ChangeEffect::Grants(vec![map]),
        },
        &heads,
    );
    b.name(&a, copy, &[copy]);
    // A fresh pseudonym of A's tries the founder's administrator slot under
    // the copy's keys: the founder's is enrolled from the start, and no
    // change made it.
    let root_slot = SlotId::new(c_genesis, 0, root);
    let copy_slot = SlotId::new(c_genesis, 0, copy);
    let heads = b.heads();
    let into_root = b.enrol(&pseudonym("A's other pseudonym"), root_slot, &keys, &heads);
    // A's fresh pseudonym enrols in the copy's own administrator slot.
    let fresh = pseudonym("A's fresh pseudonym");
    let heads = b.heads();
    let enrol = b.enrol(&fresh, copy_slot, &keys, &heads);
    // A1 erases the space, and the fresh pseudonym acknowledges it.
    let heads = b.heads();
    let erase = b.storage(&a1, StorageBody::Erase, &heads);
    let ack = b.storage(&fresh, StorageBody::Ack, &[erase]);

    let skeleton = Skeleton::new(&b.log, None);
    assert_eq!(skeleton.root(), Some(root));
    assert_eq!(
        skeleton.status(into_root),
        void(PeersClass::UnknownAdministratorSlot)
    );
    for id in [copy, enrol, ack, erase] {
        assert!(skeleton.is_valid(id));
    }
    assert!(skeleton.repeats(copy));
    assert_eq!(skeleton.slot_of(p0.device_id()), Some(root_slot));
    assert_eq!(skeleton.slot_of(fresh.device_id()), Some(copy_slot));
    assert_eq!(
        skeleton.merged()[&root_slot],
        SlotState {
            is_in: true,
            enrolled: Some(*p0.device_id()),
        }
    );
    let administrators = skeleton.administrators();
    assert!(administrators.contains(&root_slot) && administrators.contains(&copy_slot));
    // The erasure waits for P0.
    let stable = skeleton.is_stable(erase, None);
    assert!(!stable, "P0 has not acknowledged it");
    assert_eq!(
        erasure(true, false, stable, &reading(0), &reading(1), T),
        Execution::Wait
    );
    b.storage(&p0, StorageBody::Ack, &[ack]);
    let skeleton = Skeleton::new(&b.log, None);
    assert!(skeleton.is_stable(erase, None));
}

/// A copy of a grant, its grant map whole, after the grant: the grantee's
/// enrolment names the genuine twin and enrols its administrator slot even
/// with the copy in its past, and a disown of the copy lowers it alone.
#[test]
fn a_copy_that_reuses_the_grant_map_neither_blocks_the_grantee_nor_takes_its_slot() {
    let Space {
        mut b, a, a1, p0, ..
    } = space_with_a();
    let c_b = example("c(F grants B)");
    let salt_b = example("salt of F grants B");
    let (map, keys) = grant(&example("token of B"));
    let heads = b.heads();
    let genuine = b.storage(
        &p0,
        StorageBody::Change {
            twin: c_b,
            salt: salt_b,
            effect: ChangeEffect::Grants(vec![map.clone()]),
        },
        &heads,
    );
    b.name(&signer("F"), genuine, &[genuine]);
    let heads = b.heads();
    let copy = b.storage(
        &a1,
        StorageBody::Change {
            twin: c_b,
            salt: salt_b,
            effect: ChangeEffect::Grants(vec![map]),
        },
        &heads,
    );
    b.name(&a, copy, &[copy]);
    // B1 enrols with the copy in its past, naming the genuine twin.
    let b1 = pseudonym("B1");
    let heads = b.heads();
    let enrolled = b.enrol(&b1, SlotId::new(c_b, 0, genuine), &keys, &heads);
    let skeleton = Skeleton::new(&b.log, None);
    assert!(skeleton.log().precedes(copy, enrolled));
    assert!(skeleton.repeats(copy) && !skeleton.repeats(genuine));
    assert!(skeleton.is_valid(enrolled));
    let genuine_slot = SlotId::new(c_b, 0, genuine);
    let copy_slot = SlotId::new(c_b, 0, copy);
    assert_eq!(skeleton.slot_of(b1.device_id()), Some(genuine_slot));
    assert_eq!(skeleton.merged()[&copy_slot].enrolled, None);
    drop(skeleton);
    // P0 disowns the copy: B's administrator slot stays in, enrolled.
    let heads = b.heads();
    let disown = b.storage(&p0, StorageBody::Disown { slot: copy_slot }, &heads);
    let skeleton = Skeleton::new(&b.log, None);
    assert!(skeleton.is_valid(disown));
    assert_eq!(skeleton.lowers(disown), &[copy_slot]);
    assert_eq!(
        skeleton.merged()[&genuine_slot],
        SlotState {
            is_in: true,
            enrolled: Some(*b1.device_id()),
        }
    );
    assert!(!skeleton.merged()[&copy_slot].is_in);
}

/// A copy of A's commitment after A1 enrolled, under keys of its own: A's
/// administrator slot keeps its keys and its enrolment, and a lower that
/// names the copy leaves it in.
#[test]
fn a_later_copy_never_resets_the_slot_it_copied() {
    let Space {
        mut b,
        a,
        a1,
        p0,
        change,
        c_a,
        salt_a,
        keys,
        ..
    } = space_with_a();
    let (map, _) = grant(&example("another token"));
    let heads = b.heads();
    let copy = b.storage(
        &a1,
        StorageBody::Change {
            twin: c_a,
            salt: salt_a,
            effect: ChangeEffect::Grants(vec![map]),
        },
        &heads,
    );
    b.name(&a, copy, &[copy]);
    // A second pseudonym enrols in A's slot with A's genuine keys: the slot
    // is enrolled already.
    let heads = b.heads();
    let again = b.enrol(&pseudonym("A2"), SlotId::new(c_a, 0, change), &keys, &heads);
    // P0 lowers the copy in a change the founder names.
    let heads = b.heads();
    let lower = b.storage(
        &p0,
        StorageBody::Change {
            twin: example("c(F lowers the copy)"),
            salt: example("salt of F lowers the copy"),
            effect: ChangeEffect::Lower(SlotId::new(c_a, 0, copy)),
        },
        &heads,
    );
    b.name(&signer("F"), lower, &[lower]);
    let skeleton = Skeleton::new(&b.log, None);
    let a_slot = SlotId::new(c_a, 0, change);
    assert_eq!(skeleton.slot(a_slot).unwrap().slot_ed, Some(keys_ed(&keys)));
    assert_eq!(skeleton.slot_of(a1.device_id()), Some(a_slot));
    assert!(matches!(
        skeleton.status(again),
        Some(Status::Void {
            class: PeersClass::AlreadyEnrolled,
            ..
        })
    ));
    assert!(skeleton.is_valid(lower));
    assert_eq!(
        skeleton.merged()[&a_slot],
        SlotState {
            is_in: true,
            enrolled: Some(*a1.device_id()),
        }
    );
}

fn keys_ed(keys: &frasil_peers::derive::SlotKeys) -> [u8; 32] {
    *keys.ed_public()
}
