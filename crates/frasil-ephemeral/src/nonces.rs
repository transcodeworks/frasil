//! Receiver nonces (ext-ephemeral.md, "Freshness across restarts").
//!
//! A device draws a fresh 16-byte nonce whenever it starts receiving a
//! space's channel, publishes it as its `frasil/nonce` ephemeral slot, and
//! holds its last 4 of the current run, never at rest.

use crate::limits::{RECEIVER_NONCE_BYTES, RECEIVER_NONCES};
use std::collections::VecDeque;

/// One space's receiver nonces of the current run: the last 4, newest
/// first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiverNonces {
    held: VecDeque<[u8; RECEIVER_NONCE_BYTES]>,
}

impl ReceiverNonces {
    /// None yet: a new run.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes a fresh nonce, 16 random bytes the caller draws, when the
    /// device starts receiving the space's channel. The oldest past 4 is
    /// forgotten. Returns the nonce, to publish as `frasil/nonce`.
    pub fn draw_with(&mut self, nonce: [u8; RECEIVER_NONCE_BYTES]) -> [u8; RECEIVER_NONCE_BYTES] {
        self.held.push_front(nonce);
        self.held.truncate(RECEIVER_NONCES);
        nonce
    }

    /// The latest nonce, which the `frasil/nonce` ephemeral slot carries.
    pub fn latest(&self) -> Option<&[u8; RECEIVER_NONCE_BYTES]> {
        self.held.front()
    }

    /// Whether `nonce` is one of the last 4.
    pub fn holds(&self, nonce: &[u8; RECEIVER_NONCE_BYTES]) -> bool {
        self.held.contains(nonce)
    }
}
