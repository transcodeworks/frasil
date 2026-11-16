//! A receiver's replay state (ext-ephemeral.md, "Epoch, counter and
//! replay").
//!
//! - **Ephemeral messages.** Per space and sender, the highest epoch, the
//!   highest counter in it, and which of the 64 counters below that have
//!   been accepted. A higher epoch is accepted; in the same epoch, a higher
//!   counter, or one within 64 below that not yet accepted. Else
//!   `Replayed`.
//! - **Ephemeral slots.** A value is accepted only if its `(epoch,
//!   counter)` is greater than that of the value held for the same
//!   `(sender, name, stream)`, a cleared one included. A cleared value is
//!   dropped and its `(epoch, counter)` kept.
//! - **Bounds.** At most 32 ephemeral slots per space and sender, and 2,048
//!   per space, cleared ones included. Past the first count the sender's
//!   own cleared slot with the lowest mark is forgotten, or with none
//!   cleared its lowest; past the second, one of the sender that holds the
//!   most in the space, the lowest device ID of those.
//! - **The floor.** Per space and sender, the highest mark forgotten: a
//!   value for an ephemeral slot not held is accepted only above it, so a
//!   forgotten value never returns.
//! - **Forgetting.** A frame accepted under a higher epoch than any before
//!   from its sender forgets the sender's slots of lower epochs and raises
//!   its floor to `(epoch, 0)`; a sender whose membership ends
//!   ([`ReplayState::drop_sender`]) and a space no longer followed
//!   ([`ReplayState::drop_space`]) are forgotten.
//!
//! The state is updated only for a frame accepted, or as those rules say.
//! A window MAY be kept in at-rest.md's `replay` table
//! ([`Window::to_record`]); ephemeral slot marks and floors stay in memory.

use crate::limits::{
    ORIGIN_BYTES, RECEIVER_SLOTS_PER_SENDER, RECEIVER_SLOTS_PER_SPACE, REPLAY_WINDOW,
};
use frasil_crypto::device::DeviceId;
use std::collections::HashMap;

/// A sender's window in one space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Window {
    /// The highest epoch accepted.
    pub epoch: u64,
    /// The highest counter accepted in it.
    pub counter: u64,
    /// Which of the counters at and below `counter` were accepted: bit `i`
    /// is `counter − i`, for `i` below 64.
    pub accepted: u64,
}

impl Window {
    /// The window after a first accepted `(epoch, counter)`.
    pub fn new(epoch: u64, counter: u64) -> Self {
        Self {
            epoch,
            counter,
            accepted: 1,
        }
    }

    /// Whether the window accepts `(epoch, counter)`.
    pub fn accepts(&self, epoch: u64, counter: u64) -> bool {
        if epoch != self.epoch {
            return epoch > self.epoch;
        }
        if counter > self.counter {
            return true;
        }
        let below = self.counter - counter;
        below < REPLAY_WINDOW && self.accepted & (1 << below) == 0
    }

    /// The window after accepting `(epoch, counter)`, which
    /// [`accepts`](Self::accepts) allowed.
    pub fn accept(&mut self, epoch: u64, counter: u64) {
        if epoch > self.epoch {
            *self = Self::new(epoch, counter);
        } else if counter > self.counter {
            let shift = counter - self.counter;
            self.accepted = if shift >= REPLAY_WINDOW {
                1
            } else {
                (self.accepted << shift) | 1
            };
            self.counter = counter;
        } else {
            self.accepted |= 1 << (self.counter - counter);
        }
    }

    /// The `replay` record's value (at-rest.md): `(epoch, counter,
    /// window)`, each `u64be`.
    pub fn to_record(&self) -> (u64, u64, u64) {
        (self.epoch, self.counter, self.accepted)
    }

    /// A window from its `replay` record's value.
    pub fn from_record(epoch: u64, counter: u64, window: u64) -> Self {
        Self {
            epoch,
            counter,
            accepted: window,
        }
    }
}

/// What identifies an ephemeral slot at a receiver: the space, the sender,
/// the name and the stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SlotKey {
    /// The space ID.
    pub space: [u8; 32],
    /// The sender's device ID.
    pub sender: DeviceId,
    /// The name.
    pub name: String,
    /// The stream, if the slot is narrowed to one.
    pub stream: Option<[u8; 16]>,
}

/// Where a held ephemeral slot value came from: the connection that
/// delivered it, numbered by the receiver, and, through an always-on peer,
/// the sender's origin there (ext-ephemeral.md, "Relaying").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Delivery {
    /// The receiver's number for the connection.
    pub connection: u64,
    /// The origin a relaying peer added, if any.
    pub origin: Option<[u8; ORIGIN_BYTES]>,
}

/// An ephemeral slot as a receiver keeps it: the mark of the last value
/// accepted, and that value unless it was cleared or dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldSlot {
    /// The `(epoch, counter)` of the last value accepted.
    pub mark: (u64, u64),
    /// The value held; `None` once cleared or dropped.
    pub value: Option<Vec<u8>>,
    /// The connection that delivered the value, once the receiver names
    /// it ([`ReplayState::set_delivery`]).
    pub delivery: Option<Delivery>,
}

/// One sender's state in one space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SenderState {
    /// Its ephemeral message window.
    window: Option<Window>,
    /// The highest epoch of a frame accepted from it, of either kind.
    epoch: u64,
    /// The highest mark of an ephemeral slot forgotten.
    floor: (u64, u64),
    /// Its ephemeral slots held, cleared ones included.
    slots: HashMap<SlotKey, HeldSlot>,
}

/// One space's state at the receiver.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SpaceState {
    senders: HashMap<DeviceId, SenderState>,
    /// The ephemeral slots held in the space, every sender's together.
    held: usize,
}

/// Of one sender's ephemeral slots, the one the bounds forget: the cleared
/// one with the lowest mark, or, with none cleared, the one with the lowest;
/// of equal marks, the lowest name by its bytes, then stream, absent first.
fn victim(slots: &HashMap<SlotKey, HeldSlot>) -> Option<SlotKey> {
    slots
        .iter()
        .min_by(|(a, held_a), (b, held_b)| {
            (
                held_a.value.is_some(),
                held_a.mark,
                a.name.as_bytes(),
                a.stream,
            )
                .cmp(&(
                    held_b.value.is_some(),
                    held_b.mark,
                    b.name.as_bytes(),
                    b.stream,
                ))
        })
        .map(|(key, _)| key.clone())
}

impl SpaceState {
    /// A frame of `sender` accepted under `epoch`: under a higher one than
    /// any before, its ephemeral slots of lower epochs are forgotten and its
    /// floor raised to at least `(epoch, 0)`.
    fn accepted_epoch(&mut self, sender: &DeviceId, epoch: u64) {
        let state = self.senders.entry(*sender).or_default();
        if epoch <= state.epoch {
            return;
        }
        state.epoch = epoch;
        let before = state.slots.len();
        state.slots.retain(|_, held| held.mark.0 >= epoch);
        self.held -= before - state.slots.len();
        state.floor = state.floor.max((epoch, 0));
    }

    /// Forgets one ephemeral slot of a sender, raising its floor.
    fn forget(&mut self, sender: &DeviceId, key: &SlotKey) {
        if let Some(state) = self.senders.get_mut(sender)
            && let Some(held) = state.slots.remove(key)
        {
            state.floor = state.floor.max(held.mark);
            self.held -= 1;
        }
    }

    /// The sender that holds the most ephemeral slots, the lowest device ID
    /// of those.
    fn holds_most(&self) -> Option<DeviceId> {
        self.senders
            .iter()
            .filter(|(_, state)| !state.slots.is_empty())
            .max_by(|(a, state_a), (b, state_b)| {
                state_a.slots.len().cmp(&state_b.slots.len()).then(b.cmp(a))
            })
            .map(|(sender, _)| *sender)
    }

    /// Makes room for one more ephemeral slot of `sender`: past its own
    /// count, one of its own is forgotten; past the space's, one of the
    /// sender that holds the most.
    fn make_room(&mut self, sender: &DeviceId) {
        if let Some(state) = self.senders.get(sender)
            && state.slots.len() >= RECEIVER_SLOTS_PER_SENDER
            && let Some(key) = victim(&state.slots)
        {
            self.forget(sender, &key);
        }
        if self.held >= RECEIVER_SLOTS_PER_SPACE
            && let Some(most) = self.holds_most()
            && let Some(key) = self.senders.get(&most).and_then(|s| victim(&s.slots))
        {
            self.forget(&most, &key);
        }
    }
}

/// One receiver's replay state, in memory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayState {
    spaces: HashMap<[u8; 32], SpaceState>,
}

impl ReplayState {
    /// An empty state: after a restart without a kept window.
    pub fn new() -> Self {
        Self::default()
    }

    fn sender(&self, space: &[u8; 32], sender: &DeviceId) -> Option<&SenderState> {
        self.spaces.get(space)?.senders.get(sender)
    }

    /// The window of a sender in a space, if any.
    pub fn window(&self, space: &[u8; 32], sender: &DeviceId) -> Option<&Window> {
        self.sender(space, sender)?.window.as_ref()
    }

    /// Every window held: the space, the sender and the window, to keep in
    /// the `replay` table.
    pub fn windows(&self) -> impl Iterator<Item = (&[u8; 32], &DeviceId, &Window)> {
        self.spaces.iter().flat_map(|(space, state)| {
            state.senders.iter().filter_map(move |(sender, held)| {
                held.window.as_ref().map(|window| (space, sender, window))
            })
        })
    }

    /// Sets a sender's window, as read from the `replay` table.
    pub fn restore_window(&mut self, space: &[u8; 32], sender: &DeviceId, window: Window) {
        self.spaces
            .entry(*space)
            .or_default()
            .senders
            .entry(*sender)
            .or_default()
            .window = Some(window);
    }

    /// Whether the window accepts an ephemeral message.
    pub fn message_ok(
        &self,
        space: &[u8; 32],
        sender: &DeviceId,
        epoch: u64,
        counter: u64,
    ) -> bool {
        self.window(space, sender)
            .is_none_or(|window| window.accepts(epoch, counter))
    }

    /// Records an accepted ephemeral message. Under a higher epoch than any
    /// before from its sender, the sender's ephemeral slots of lower epochs
    /// are forgotten.
    pub fn accept_message(
        &mut self,
        space: &[u8; 32],
        sender: &DeviceId,
        epoch: u64,
        counter: u64,
    ) {
        let state = self.spaces.entry(*space).or_default();
        state.accepted_epoch(sender, epoch);
        let held = state.senders.entry(*sender).or_default();
        match held.window.as_mut() {
            Some(window) => window.accept(epoch, counter),
            None => held.window = Some(Window::new(epoch, counter)),
        }
    }

    /// The ephemeral slot held under a key, if any.
    pub fn slot(&self, key: &SlotKey) -> Option<&HeldSlot> {
        self.sender(&key.space, &key.sender)?.slots.get(key)
    }

    /// Every ephemeral slot held with a value.
    pub fn values(&self) -> impl Iterator<Item = (&SlotKey, &[u8])> {
        self.spaces
            .values()
            .flat_map(|space| space.senders.values())
            .flat_map(|sender| sender.slots.iter())
            .filter_map(|(key, held)| Some((key, held.value.as_deref()?)))
    }

    /// The ephemeral slots held of a sender in a space, cleared ones
    /// included: at most 32.
    pub fn held_by(&self, space: &[u8; 32], sender: &DeviceId) -> usize {
        self.sender(space, sender)
            .map_or(0, |state| state.slots.len())
    }

    /// The ephemeral slots held in a space, cleared ones included: at most
    /// 2,048.
    pub fn held_in(&self, space: &[u8; 32]) -> usize {
        self.spaces.get(space).map_or(0, |state| state.held)
    }

    /// A sender's floor in a space: the highest mark of its ephemeral
    /// slots forgotten, `(0, 0)` at first.
    pub fn floor(&self, space: &[u8; 32], sender: &DeviceId) -> (u64, u64) {
        self.sender(space, sender)
            .map_or((0, 0), |state| state.floor)
    }

    /// Whether an ephemeral slot value is newer than the one held, or, for
    /// one not held, than the sender's floor.
    pub fn slot_ok(&self, key: &SlotKey, epoch: u64, counter: u64) -> bool {
        let Some(state) = self.sender(&key.space, &key.sender) else {
            return true;
        };
        match state.slots.get(key) {
            Some(held) => (epoch, counter) > held.mark,
            None => (epoch, counter) > state.floor,
        }
    }

    /// Records an accepted ephemeral slot value; empty data clears it, and
    /// its mark is kept. A slot not held yet takes room by the bounds.
    pub fn accept_slot(&mut self, key: SlotKey, epoch: u64, counter: u64, data: &[u8]) {
        let space = self.spaces.entry(key.space).or_default();
        space.accepted_epoch(&key.sender, epoch);
        let holds = space
            .senders
            .get(&key.sender)
            .is_some_and(|state| state.slots.contains_key(&key));
        if !holds {
            space.make_room(&key.sender);
            space.held += 1;
        }
        let value = (!data.is_empty()).then(|| data.to_vec());
        space.senders.entry(key.sender).or_default().slots.insert(
            key,
            HeldSlot {
                mark: (epoch, counter),
                value,
                delivery: None,
            },
        );
    }

    /// A `frasil/leave`: clears each held ephemeral slot of its sender as if
    /// with the leave's `(epoch, counter)`. A newer value stays.
    pub fn clear_sender(&mut self, space: &[u8; 32], sender: &DeviceId, epoch: u64, counter: u64) {
        let Some(state) = self
            .spaces
            .get_mut(space)
            .and_then(|state| state.senders.get_mut(sender))
        else {
            return;
        };
        for held in state.slots.values_mut() {
            if (epoch, counter) > held.mark {
                *held = HeldSlot {
                    mark: (epoch, counter),
                    value: None,
                    delivery: None,
                };
            }
        }
    }

    /// Names the connection that delivered an ephemeral slot's value, so
    /// that the value goes when that connection closes or a `Gone` there
    /// names its origin.
    pub fn set_delivery(&mut self, key: &SlotKey, delivery: Delivery) {
        if let Some(held) = self
            .spaces
            .get_mut(&key.space)
            .and_then(|state| state.senders.get_mut(&key.sender))
            .and_then(|state| state.slots.get_mut(key))
            && held.value.is_some()
        {
            held.delivery = Some(delivery);
        }
    }

    /// Drops the value of one ephemeral slot, keeping its mark: when the
    /// connection that delivered it closes, or a `Gone` there names its
    /// origin.
    pub fn drop_value(&mut self, key: &SlotKey) {
        if let Some(held) = self
            .spaces
            .get_mut(&key.space)
            .and_then(|state| state.senders.get_mut(&key.sender))
            .and_then(|state| state.slots.get_mut(key))
        {
            held.value = None;
            held.delivery = None;
        }
    }

    /// A `Gone` on a connection names an origin: the values it delivered
    /// with that origin in the space are dropped, their marks kept.
    /// Returns how many.
    pub fn drop_gone(
        &mut self,
        space: &[u8; 32],
        connection: u64,
        origin: [u8; ORIGIN_BYTES],
    ) -> usize {
        let gone = Delivery {
            connection,
            origin: Some(origin),
        };
        let Some(state) = self.spaces.get_mut(space) else {
            return 0;
        };
        drop_delivered(state, |delivery| *delivery == gone)
    }

    /// A connection closed: every value it delivered, in every space, is
    /// dropped, their marks kept. Returns how many.
    pub fn drop_connection(&mut self, connection: u64) -> usize {
        self.spaces
            .values_mut()
            .map(|state| drop_delivered(state, |delivery| delivery.connection == connection))
            .sum()
    }

    /// Forgets every ephemeral slot of a sender in a space, raising its
    /// floor to the highest mark forgotten: when its membership ends in the
    /// receiver's view, or the re-check detaches it (section 3.6).
    pub fn drop_sender(&mut self, space: &[u8; 32], sender: &DeviceId) {
        let Some(state) = self.spaces.get_mut(space) else {
            return;
        };
        let Some(held) = state.senders.get_mut(sender) else {
            return;
        };
        if let Some(top) = held.slots.values().map(|slot| slot.mark).max() {
            held.floor = held.floor.max(top);
        }
        state.held -= held.slots.len();
        held.slots.clear();
    }

    /// Forgets a space the receiver no longer follows: its windows, floors
    /// and ephemeral slots.
    pub fn drop_space(&mut self, space: &[u8; 32]) {
        self.spaces.remove(space);
    }
}

/// Drops the values whose delivery matches, keeping their marks.
fn drop_delivered(state: &mut SpaceState, matches: impl Fn(&Delivery) -> bool) -> usize {
    let mut dropped = 0;
    for held in state
        .senders
        .values_mut()
        .flat_map(|sender| sender.slots.values_mut())
    {
        if held.delivery.as_ref().is_some_and(&matches) {
            held.value = None;
            held.delivery = None;
            dropped += 1;
        }
    }
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPACE: [u8; 32] = [7; 32];

    fn sender(i: u8) -> DeviceId {
        DeviceId([i; 32])
    }

    fn key(from: u8, name: &str) -> SlotKey {
        SlotKey {
            space: SPACE,
            sender: sender(from),
            name: name.to_owned(),
            stream: None,
        }
    }

    /// Offers a slot value; accepts it if it passes. Returns whether it did.
    fn offer(state: &mut ReplayState, key: SlotKey, epoch: u64, counter: u64, data: &[u8]) -> bool {
        let ok = state.slot_ok(&key, epoch, counter);
        if ok {
            state.accept_slot(key, epoch, counter, data);
        }
        ok
    }

    #[test]
    fn a_sender_holds_at_most_32_and_a_forgotten_value_stays_out() {
        let mut state = ReplayState::new();
        for i in 0..1_000u64 {
            assert!(offer(&mut state, key(1, &format!("n{i}")), 1, i + 1, b"v"));
            assert!(state.held_by(&SPACE, &sender(1)) <= RECEIVER_SLOTS_PER_SENDER);
        }
        assert_eq!(state.held_by(&SPACE, &sender(1)), RECEIVER_SLOTS_PER_SENDER);
        assert_eq!(state.held_in(&SPACE), RECEIVER_SLOTS_PER_SENDER);
        // The newest 32 stay; the floor is the mark of the last forgotten.
        assert_eq!(state.floor(&SPACE, &sender(1)), (1, 968));
        assert!(state.slot(&key(1, "n999")).is_some());
        assert!(state.slot(&key(1, "n967")).is_none());
        // A forgotten value, replayed, is below the floor.
        assert!(!offer(&mut state, key(1, "n0"), 1, 1, b"v"));
        assert!(!offer(&mut state, key(1, "n967"), 1, 968, b"v"));
    }

    #[test]
    fn a_cleared_slot_is_forgotten_before_a_live_one() {
        let mut state = ReplayState::new();
        for i in 0..32u64 {
            assert!(offer(
                &mut state,
                key(1, &format!("n{i:02}")),
                1,
                i + 1,
                b"v"
            ));
        }
        // n10 cleared, then a 33rd name: the cleared n10 goes, not n00.
        assert!(offer(&mut state, key(1, "n10"), 1, 40, b""));
        assert!(offer(&mut state, key(1, "new"), 1, 41, b"v"));
        assert!(state.slot(&key(1, "n10")).is_none());
        assert!(state.slot(&key(1, "n00")).is_some());
        assert_eq!(state.floor(&SPACE, &sender(1)), (1, 40));
        // An older value of n10 never returns.
        assert!(!offer(&mut state, key(1, "n10"), 1, 39, b"old"));
    }

    #[test]
    fn a_space_holds_at_most_2048_and_the_largest_sender_gives_way() {
        let mut state = ReplayState::new();
        let senders = (RECEIVER_SLOTS_PER_SPACE / RECEIVER_SLOTS_PER_SENDER) as u8;
        for s in 1..=senders {
            for i in 0..RECEIVER_SLOTS_PER_SENDER as u64 {
                assert!(offer(
                    &mut state,
                    key(s, &format!("n{i:02}")),
                    1,
                    i + 1,
                    b"v"
                ));
            }
        }
        assert_eq!(state.held_in(&SPACE), RECEIVER_SLOTS_PER_SPACE);
        // Many new senders, each with a few names: the space stays bounded.
        for s in senders + 1..=senders + 100 {
            for i in 0..4u64 {
                assert!(offer(&mut state, key(s, &format!("m{i}")), 1, i + 1, b"v"));
                assert!(state.held_in(&SPACE) <= RECEIVER_SLOTS_PER_SPACE);
            }
        }
        assert_eq!(state.held_in(&SPACE), RECEIVER_SLOTS_PER_SPACE);
        // The first new sender's first value forgot sender 1's lowest.
        assert!(state.slot(&key(1, "n00")).is_none());
        assert!(!offer(&mut state, key(1, "n00"), 1, 1, b"v"));
        let total: usize = (1..=senders + 100)
            .map(|s| state.held_by(&SPACE, &sender(s)))
            .sum();
        assert_eq!(total, state.held_in(&SPACE));
    }

    #[test]
    fn a_new_epoch_forgets_the_older_runs_slots() {
        let mut state = ReplayState::new();
        assert!(offer(&mut state, key(1, "a"), 1, 5, b"x"));
        assert!(offer(&mut state, key(1, "b"), 1, 6, b"y"));
        assert!(offer(&mut state, key(2, "a"), 1, 1, b"z"));
        // An ephemeral message of sender 1's next run.
        assert!(state.message_ok(&SPACE, &sender(1), 2, 1));
        state.accept_message(&SPACE, &sender(1), 2, 1);
        assert_eq!(state.held_by(&SPACE, &sender(1)), 0);
        assert_eq!(state.held_by(&SPACE, &sender(2)), 1);
        assert_eq!(state.held_in(&SPACE), 1);
        assert_eq!(state.floor(&SPACE, &sender(1)), (2, 0));
        // An older run's value is below the floor; the new run's is not.
        assert!(!offer(&mut state, key(1, "c"), 1, 99, b"old"));
        assert!(offer(&mut state, key(1, "a"), 2, 2, b"new"));
    }

    #[test]
    fn an_ended_sender_is_forgotten_and_its_values_stay_out() {
        let mut state = ReplayState::new();
        assert!(offer(&mut state, key(1, "a"), 1, 5, b"x"));
        assert!(offer(&mut state, key(1, "b"), 1, 9, b""));
        assert!(offer(&mut state, key(2, "a"), 1, 1, b"z"));
        state.drop_sender(&SPACE, &sender(1));
        assert_eq!(state.held_by(&SPACE, &sender(1)), 0);
        assert_eq!(state.held_in(&SPACE), 1);
        assert_eq!(state.floor(&SPACE, &sender(1)), (1, 9));
        assert!(!offer(&mut state, key(1, "a"), 1, 5, b"x"));
        state.drop_space(&SPACE);
        assert_eq!(state.held_in(&SPACE), 0);
        assert_eq!(state.values().count(), 0);
    }

    #[test]
    fn a_gone_or_a_close_drops_what_that_connection_delivered() {
        let mut state = ReplayState::new();
        let origin = [9; ORIGIN_BYTES];
        for (from, connection, via) in [
            (1, 1, Some(origin)),
            (2, 1, Some([8; ORIGIN_BYTES])),
            (3, 2, None),
        ] {
            assert!(offer(&mut state, key(from, "a"), 1, 1, b"v"));
            state.set_delivery(
                &key(from, "a"),
                Delivery {
                    connection,
                    origin: via,
                },
            );
        }
        assert_eq!(state.drop_gone(&SPACE, 1, origin), 1);
        assert_eq!(state.slot(&key(1, "a")).unwrap().value, None);
        assert_eq!(state.slot(&key(1, "a")).unwrap().mark, (1, 1));
        assert!(state.slot(&key(2, "a")).unwrap().value.is_some());
        assert_eq!(state.drop_connection(2), 1);
        assert_eq!(state.slot(&key(3, "a")).unwrap().value, None);
        assert_eq!(state.values().count(), 1);
        // A dropped value is not offered again below its mark.
        assert!(!offer(&mut state, key(1, "a"), 1, 1, b"v"));
    }
}
