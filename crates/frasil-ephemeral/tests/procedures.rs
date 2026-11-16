//! The procedures the vectors do not reach (ext-ephemeral.md): the error
//! classes, sending, a sender's queue, a `frasil/leave` at a receiver, the
//! replay window's edges, receiver nonces, a relay's cap and the sender's
//! refusals.

use frasil_base::errors::{Class, Sort, snake_case};
use frasil_crypto::device::{DeviceId, IdentityKey, KeysCommitment, Signatory};
use frasil_crypto::primitives::ed25519_public;
use frasil_ephemeral::counters::Counters;
use frasil_ephemeral::frame::{encode_core, pad};
use frasil_ephemeral::limits::*;
use frasil_ephemeral::names::LEAVE;
use frasil_ephemeral::nonces::ReceiverNonces;
use frasil_ephemeral::relay::Relay;
use frasil_ephemeral::replay::{ReplayState, SlotKey, Window};
use frasil_ephemeral::sending::{LiveSlots, SendQueue};
use frasil_ephemeral::{EphemeralClass, Inner, Kind, Outer, seal_with};
use std::time::Duration;

const SPACE: [u8; 32] = [1; 32];
const SEED: [u8; 32] = [2; 32];
const KEY: [u8; 32] = [3; 32];

fn reference() -> Vec<u8> {
    let mut reference = vec![1];
    reference.extend_from_slice(&[4; 32]);
    reference
}

/// The sender's `ed || kc`, under a stand-in keys commitment.
fn signatory() -> Signatory {
    Signatory {
        ed: IdentityKey(ed25519_public(&SEED)),
        kc: KeysCommitment([6; 32]),
    }
}

fn inner(kind: Kind, name: &str, counter: u64, data: &[u8]) -> Inner {
    Inner {
        kind,
        sender: signatory(),
        epoch: 1,
        counter,
        name: name.to_owned(),
        stream: None,
        targets: None,
        fresh: None,
        adapter: None,
        data: data.to_vec(),
    }
}

fn sealed(inner: &Inner) -> (Outer, Vec<u8>) {
    let sealed = seal_with(inner, &SPACE, &reference(), &KEY, &SEED, &[9; 24]).unwrap();
    (sealed.frame, sealed.outer)
}

#[test]
fn error_classes() {
    for &class in EphemeralClass::OWN {
        assert_eq!(class.wire_name(), snake_case(class.name()));
        assert_eq!(class.sort(), Sort::Decision);
    }
    assert_eq!(
        EphemeralClass::from_name("Stale"),
        Some(EphemeralClass::Stale)
    );
    assert_eq!(
        EphemeralClass::from(frasil_keys::KeyClass::TooManyRotations),
        EphemeralClass::TooManyRotations
    );
}

#[test]
fn the_sender_refuses_what_receivers_refuse() {
    let mut bad = inner(Kind::Message, "", 1, b"");
    let seal = |i: &Inner, seed: &[u8; 32]| {
        seal_with(i, &SPACE, &reference(), &KEY, seed, &[0; 24]).map(|_| ())
    };
    assert_eq!(
        seal(&bad, &SEED),
        Err(frasil_base::ErrorClass::Malformed.into())
    );
    bad.name = "com.example.x".to_owned();
    assert_eq!(seal(&bad, &SEED), Ok(()));
    // Another device's seed.
    assert_eq!(
        seal(&bad, &[8; 32]),
        Err(frasil_base::ErrorClass::Malformed.into())
    );
    // A reserved name the table refuses: frasil/nonce as a message.
    let nonce = inner(Kind::Message, "frasil/nonce", 1, &[0; 16]);
    assert!(seal(&nonce, &SEED).is_err());
    // The largest data fits under the limits.
    let large = inner(Kind::Slot, "com.example.x", 1, &[0xff; MAX_DATA_BYTES]);
    let sealed = seal_with(&large, &SPACE, &reference(), &KEY, &SEED, &[0; 24]).unwrap();
    assert!(sealed.outer.len() <= MAX_OUTER_BYTES);
    assert!(sealed.plaintext.len() <= MAX_PLAINTEXT_BYTES);
}

#[test]
fn counters_run_out_rather_than_wrap() {
    assert!(Counters::start(u64::MAX).is_none());
    assert!(Counters::restore_with(Some(u64::MAX - EPOCH_RESTORE_STEP), 1).is_none());
    let mut counters = Counters::start(4).unwrap();
    assert_eq!(counters.epoch(), 5);
    assert_eq!(counters.next(&SPACE), Some((5, 1)));
    assert_eq!(counters.next(&[2; 32]), Some((5, 1)));
}

#[test]
fn the_window_at_its_edges() {
    let mut window = Window::new(1, 100);
    assert!(window.accepts(1, 37));
    assert!(!window.accepts(1, 36));
    assert!(!window.accepts(1, 100));
    assert!(!window.accepts(0, 1000));
    window.accept(1, 37);
    assert!(!window.accepts(1, 37));
    window.accept(1, 101);
    // 37 has left the window.
    assert!(!window.accepts(1, 37));
    assert!(window.accepts(1, 99));
    window.accept(1, u64::MAX);
    assert_eq!(window.to_record(), (1, u64::MAX, 1));
}

#[test]
fn a_leave_clears_the_senders_slots() {
    let sender = signatory().device_id();
    let key = |name: &str| SlotKey {
        space: SPACE,
        sender,
        name: name.to_owned(),
        stream: None,
    };
    let mut replay = ReplayState::new();
    replay.accept_slot(key("a"), 3, 5, b"x");
    replay.accept_slot(key("b"), 3, 9, b"y");
    replay.clear_sender(&SPACE, &sender, 3, 7);
    assert_eq!(replay.slot(&key("a")).unwrap().mark, (3, 7));
    assert_eq!(replay.slot(&key("a")).unwrap().value, None);
    assert_eq!(
        replay.slot(&key("b")).unwrap().value.as_deref(),
        Some(&b"y"[..])
    );
    assert!(!replay.slot_ok(&key("a"), 3, 6));
    replay.drop_sender(&SPACE, &sender);
    assert_eq!(replay.values().count(), 0);
    assert_eq!(LEAVE, "frasil/leave");
}

#[test]
fn receiver_nonces_keep_the_last_four() {
    let mut nonces = ReceiverNonces::new();
    for i in 0..6 {
        nonces.draw_with([i; 16]);
    }
    assert!(!nonces.holds(&[1; 16]));
    assert!((2..6).all(|i| nonces.holds(&[i; 16])));
    assert_eq!(nonces.latest(), Some(&[5; 16]));
}

#[test]
fn live_slots_are_bounded() {
    let mut live = LiveSlots::new();
    for i in 0..LIVE_SLOTS_PER_SENDER {
        live.set(&format!("n{i}"), None, b"v").unwrap();
    }
    assert!(live.set("one more", None, b"v").is_err());
    live.set("n0", None, b"w").unwrap();
    live.set("n0", None, b"").unwrap();
    live.set("one more", None, b"v").unwrap();
    assert_eq!(live.len(), LIVE_SLOTS_PER_SENDER);
    live.leave();
    assert!(live.is_empty());
}

#[test]
fn the_queue_replaces_drops_and_expires() {
    let mut queue = SendQueue::new();
    let now = Duration::from_millis(1000);
    let (slot, slot_bytes) = sealed(&inner(Kind::Slot, "com.example.p", 1, b"a"));
    let (newer, newer_bytes) = sealed(&inner(Kind::Slot, "com.example.p", 2, b"b"));
    assert!(queue.push(&slot, slot_bytes, now).is_none());
    // A new value replaces the unsent one.
    assert!(queue.push(&newer, newer_bytes.clone(), now).is_some());
    assert_eq!(queue.len(), 1);
    // Full: the oldest ephemeral message goes.
    let mut first = None;
    for counter in 0..SEND_QUEUE as u64 {
        let (message, bytes) = sealed(&inner(Kind::Message, "com.example.m", counter + 3, b""));
        first.get_or_insert(bytes.clone());
        queue.push(&message, bytes, now);
    }
    assert_eq!(queue.len(), SEND_QUEUE);
    // The slot was kept; the first message was dropped.
    let next = queue.pop(now).unwrap();
    assert_eq!(next.outer, newer_bytes);
    assert_ne!(queue.pop(now).unwrap().outer, first.unwrap());
    // Past the deadline, the rest are dropped.
    let late = now + Duration::from_secs(EPHEMERAL_SEND_DEADLINE) + Duration::from_millis(1);
    assert!(queue.pop(late).is_none());
}

#[test]
fn a_relay_holds_64_slots_per_connection() {
    let mut relay: Relay<u8> = Relay::new(SPACE);
    for counter in 0..=RELAY_SLOTS_PER_CONNECTION as u64 {
        let name = format!("com.example.s{counter}");
        let (_, bytes) = sealed(&inner(Kind::Slot, &name, counter + 1, b"v"));
        relay.frame_with(1, &bytes, [1; 8]).unwrap();
    }
    let held = relay.join_with(2, [2; 8]);
    assert_eq!(held.len(), RELAY_SLOTS_PER_CONNECTION);
    // A frame for another space is refused, and its connection does not
    // join.
    let other = seal_with(
        &inner(Kind::Message, "com.example.m", 1, b""),
        &[5; 32],
        &reference(),
        &KEY,
        &SEED,
        &[0; 24],
    )
    .unwrap();
    assert!(relay.frame_with(3, &other.outer, [3; 8]).is_err());
    assert!(relay.origin(&3).is_none());
    assert_eq!(relay.leave(&1).len(), 1);
    assert!(relay.leave(&2).is_empty());
    assert!(relay.is_empty());
}

#[test]
fn the_largest_inner_map_fits_the_padded_plaintext() {
    // Every field at its limit: a 64-byte sender, 16 targets with 16 fresh
    // entries, and 16,384 bytes of data (ext-ephemeral.md, "The inner map").
    let targets: Vec<DeviceId> = (1..=16).map(|i| DeviceId([i; 32])).collect();
    let biggest = Inner {
        kind: Kind::Message,
        sender: signatory(),
        epoch: u64::MAX,
        counter: u64::MAX,
        name: "n".repeat(MAX_NAME_BYTES),
        stream: Some([1; 16]),
        fresh: Some(targets.iter().map(|t| (*t, [0; 16])).collect()),
        targets: Some(targets),
        adapter: Some("a".repeat(MAX_ADAPTER_BYTES)),
        data: vec![0; MAX_DATA_BYTES],
    };
    let encoded = biggest.encode();
    assert_eq!(encoded.len(), 18_012);
    assert_eq!(Inner::read(&encoded), Ok(biggest));
    let padded = pad(&encode_core(&encoded, &[0; SIGNATURE_BYTES])).unwrap();
    assert!(padded.len() <= MAX_PLAINTEXT_BYTES);
}

/// A receiver whose view of one sender can change, for `receive`.
struct OneSender {
    standing: std::cell::Cell<frasil_ephemeral::Membership>,
}

impl frasil_ephemeral::View for OneSender {
    fn own(&self) -> DeviceId {
        DeviceId([8; 32])
    }

    fn follows(&self, space: &[u8; 32]) -> Option<frasil_ephemeral::SpaceKind> {
        (*space == SPACE).then_some(frasil_ephemeral::SpaceKind::Plain)
    }

    fn holds_rotation(&self, _space: &[u8; 32], _id: &frasil_keys::names::RotationId) -> bool {
        true
    }

    fn content_key(
        &self,
        _space: &[u8; 32],
        _reference: &[u8],
    ) -> Option<zeroize::Zeroizing<[u8; 32]>> {
        Some(zeroize::Zeroizing::new(KEY))
    }

    fn implements(&self, _extension: frasil_ephemeral::Extension) -> bool {
        false
    }

    fn member(&self, _space: &[u8; 32], _sender: &DeviceId) -> frasil_ephemeral::Membership {
        self.standing.get()
    }

    fn holds_nonce(&self, _space: &[u8; 32], _nonce: &[u8; RECEIVER_NONCE_BYTES]) -> bool {
        false
    }

    fn fresh_only(&self, _name: &str) -> bool {
        false
    }

    fn check_capabilities(
        &self,
        _adapter: &str,
        _context: &frasil_ephemeral::CheckContext<'_>,
        _data: &[u8],
    ) -> frasil_ephemeral::AdapterCheck {
        frasil_ephemeral::AdapterCheck::Accept
    }
}

#[test]
fn a_frame_that_shows_the_senders_membership_ended_drops_its_slots() {
    use frasil_ephemeral::Membership;
    let view = OneSender {
        standing: std::cell::Cell::new(Membership::In),
    };
    let sender = signatory().device_id();
    let mut replay = ReplayState::new();
    for counter in 1..=3 {
        let name = format!("com.example.s{counter}");
        let (_, bytes) = sealed(&inner(Kind::Slot, &name, counter, b"v"));
        frasil_ephemeral::receive(&bytes, &SPACE, &view, &mut replay).unwrap();
    }
    assert_eq!(replay.held_by(&SPACE, &sender), 3);
    // Unjudgeable keeps them: the receiver fetches the missing log.
    view.standing.set(Membership::Unjudgeable);
    let (_, next) = sealed(&inner(Kind::Message, "com.example.m", 4, b""));
    let refused = frasil_ephemeral::receive(&next, &SPACE, &view, &mut replay).unwrap_err();
    assert_eq!(
        (refused.step, refused.class),
        (12, EphemeralClass::Unjudgeable)
    );
    assert_eq!(replay.held_by(&SPACE, &sender), 3);
    // MembershipEnded forgets them, and raises the floor past them.
    view.standing.set(Membership::MembershipEnded);
    let refused = frasil_ephemeral::receive(&next, &SPACE, &view, &mut replay).unwrap_err();
    assert_eq!(
        (refused.step, refused.class),
        (12, EphemeralClass::MembershipEnded)
    );
    assert_eq!(replay.held_by(&SPACE, &sender), 0);
    assert_eq!(replay.values().count(), 0);
    assert_eq!(replay.floor(&SPACE, &sender), (1, 3));
}
