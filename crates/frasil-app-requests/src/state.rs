//! The verifier's state (ext-app-requests.md, "Terms and limits", "Replays
//! within the window", "The token and the person").
//!
//! A verifier's state is durable: per subject, the **recorded person**; per
//! person, its pin of placed list events, with its first sight of each
//! ([`HeldList`]). A stateful verifier also keeps `(device, nonce)` until
//! `expires_at` plus `signed_request_skew` ([`NonceStore`]).
//!
//! The verifier reaches its state only through these traits, so it does no
//! IO of its own. An application's server implements them over its own
//! storage, for instance over the records of one subject and one person
//! loaded for a request and written back after it: the person ID is in a
//! header, and the subject in the token. [`MemoryState`] and
//! [`MemoryNonceStore`] keep everything in memory.

use crate::delivery::HeldList;
use crate::statement::NONCE_BYTES;
use frasil_crypto::device::DeviceId;
use std::collections::BTreeMap;

/// What a verifier keeps of subjects and persons.
pub trait VerifierState {
    /// The person recorded for a subject, if any.
    fn recorded_person(&self, subject: &[u8]) -> Option<[u8; 32]>;

    /// Records a subject's person, at the first request the verifier accepts
    /// for it.
    fn record_person(&mut self, subject: &[u8], person_id: [u8; 32]);

    /// The list the verifier holds of a person, if any.
    fn list(&self, person_id: &[u8; 32]) -> Option<&HeldList>;

    /// The list the verifier holds of a person, to place a list delivery in.
    /// A list only grows.
    fn list_mut(&mut self, person_id: &[u8; 32]) -> Option<&mut HeldList>;

    /// Holds the first list of a person, which a list delivery started.
    fn insert_list(&mut self, list: HeldList);
}

/// A stateful verifier's nonces: `(device, nonce)` until `expires_at` plus
/// `signed_request_skew`. A verifier with a write that is not idempotent
/// MUST keep one, durably across its workers.
pub trait NonceStore {
    /// Records `(device, nonce)` until `until`, unless it is recorded
    /// already until `now` or later. Returns whether it was unseen. A store
    /// shared by several workers does this as one atomic step.
    fn check_and_record(
        &mut self,
        device: &DeviceId,
        nonce: &[u8; NONCE_BYTES],
        until: u64,
        now: u64,
    ) -> bool;
}

/// A verifier's state in memory.
#[derive(Debug, Clone, Default)]
pub struct MemoryState {
    recorded: BTreeMap<Vec<u8>, [u8; 32]>,
    lists: BTreeMap<[u8; 32], HeldList>,
}

impl MemoryState {
    /// An empty state: no recorded person and no list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears a subject's record, as the verifier's operator does after its
    /// own account checks (ext-app-requests.md, "The token and the person").
    pub fn clear_record(&mut self, subject: &[u8]) {
        self.recorded.remove(subject);
    }
}

impl VerifierState for MemoryState {
    fn recorded_person(&self, subject: &[u8]) -> Option<[u8; 32]> {
        self.recorded.get(subject).copied()
    }

    fn record_person(&mut self, subject: &[u8], person_id: [u8; 32]) {
        self.recorded.insert(subject.to_vec(), person_id);
    }

    fn list(&self, person_id: &[u8; 32]) -> Option<&HeldList> {
        self.lists.get(person_id)
    }

    fn list_mut(&mut self, person_id: &[u8; 32]) -> Option<&mut HeldList> {
        self.lists.get_mut(person_id)
    }

    fn insert_list(&mut self, list: HeldList) {
        self.lists.insert(list.person_id(), list);
    }
}

/// A stateful verifier's nonces in memory.
#[derive(Debug, Clone, Default)]
pub struct MemoryNonceStore {
    until: BTreeMap<(DeviceId, [u8; NONCE_BYTES]), u64>,
}

impl MemoryNonceStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forgets every nonce kept until before `now`.
    pub fn prune(&mut self, now: u64) {
        self.until.retain(|_, until| *until >= now);
    }

    /// How many nonces are kept.
    pub fn len(&self) -> usize {
        self.until.len()
    }

    /// Whether no nonce is kept.
    pub fn is_empty(&self) -> bool {
        self.until.is_empty()
    }
}

impl NonceStore for MemoryNonceStore {
    fn check_and_record(
        &mut self,
        device: &DeviceId,
        nonce: &[u8; NONCE_BYTES],
        until: u64,
        now: u64,
    ) -> bool {
        let key = (*device, *nonce);
        if self.until.get(&key).is_some_and(|&kept| now <= kept) {
            return false;
        }
        self.until.insert(key, until);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_kept_until_its_time() {
        let mut store = MemoryNonceStore::new();
        assert!(store.check_and_record(&DeviceId([1; 32]), &[2; 16], 120, 0));
        assert!(!store.check_and_record(&DeviceId([1; 32]), &[2; 16], 120, 120));
        assert!(store.check_and_record(&DeviceId([3; 32]), &[2; 16], 120, 1));
        store.prune(121);
        assert!(store.is_empty());
        assert!(store.check_and_record(&DeviceId([1; 32]), &[2; 16], 240, 121));
        assert_eq!(store.len(), 1);
    }
}
