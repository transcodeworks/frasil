//! Deposits in device mailboxes (transport.md, "Mailboxes"): welcomes,
//! leave requests and a person's list, sealed to their device.
//!
//! **A sender keeps what was refused** (transport.md, "A sender keeps what
//! was refused"). A deposit is kept at rest, in the device-wide `deposit`
//! table (at-rest.md, "Tables"), from before its first attempt until a
//! peer accepts it. One answered `busy` or `rate_limited`, or not
//! answered, or whose peer cannot be reached, is attempted again after a
//! random wait of up to a minute, doubled after each further failure to at
//! most an hour, until 30 days have passed since the first attempt on the
//! upper estimate of the device's timeline: the most a peer's
//! `mailbox_retention` can be, which the device does not know. Any other
//! refusal is final. The device's upkeep attempts what is due, so a
//! restart loses none. [`Event::Delayed`], [`Event::Delivered`] and
//! [`Event::Undelivered`] tell the application.
//!
//! **Paying with a token** (ext-deposit-tokens.md, 3.6), with the
//! `ext-deposit-tokens` feature: a device that holds a token of the peer
//! pays with it for every deposit there, on a connection of its own that
//! presents nothing. The token moves in one commit from the `token` table
//! to the deposit's record, and leaves the store only once the peer has
//! answered, so a deposit whose answer was lost is repeated with the same
//! item, address and token. `token_refused`, `token_expired` and
//! `token_spent` drop the token, and the item goes again at once, with
//! another or without one.
//!
//! **On a connection of its own.** Every deposit, with a token or without,
//! goes on a connection of the device's own that presents nothing else
//! ([`Bare`](crate::peer::Bare)), never on the connection that presents
//! the device's spaces: a deposit names its recipient, and the peer would
//! otherwise learn that a writer of those spaces writes to that device
//! (transport.md, 3.12 What a peer learns of a device).

use super::Device;
use super::events::Event;
use crate::error::{Error, Result};
use frasil_store::{DepositRecord, Table, TableValue};
use std::sync::PoisonError;

/// The longest a device keeps a deposit, in seconds: the most a peer's
/// `mailbox_retention` can be, 30 days.
pub(crate) const KEEP_FOR: u64 = 30 * 24 * 3_600;

/// The first bound of the random wait before a deposit goes again, in
/// seconds.
const FIRST_WAIT: u64 = 60;

/// The last bound: an hour.
const WAIT_CAP: u64 = 3_600;

/// The bound of the wait after `attempts` attempts that failed: a minute,
/// doubled after each further one, to at most an hour.
pub(crate) fn retry_bound(attempts: u64) -> u64 {
    let doublings = u32::try_from(attempts.saturating_sub(1).min(16)).unwrap_or(16);
    FIRST_WAIT.saturating_mul(1 << doublings).min(WAIT_CAP)
}

/// A wait uniform from 0 to `bound` seconds, from 8 random bytes.
pub(crate) fn wait_with(bound: u64, random: [u8; 8]) -> u64 {
    u64::from_be_bytes(random) % bound.saturating_add(1)
}

/// How a deposit went, at its first attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// The peer accepted it.
    Delivered,
    /// It is kept and goes again later: the peer's reason, or why it was
    /// not reached.
    Delayed(String),
    /// The peer refused it for good: its reason code.
    Refused(String),
}

impl Delivery {
    /// As a result: [`Error::Delayed`] for a deposit kept to go again.
    pub(crate) fn into_result(self) -> Result<()> {
        match self {
            Self::Delivered => Ok(()),
            Self::Delayed(why) => Err(Error::Delayed(why)),
            Self::Refused(code) => Err(Error::Connection(format!("refused: {code}"))),
        }
    }
}

/// What one attempt's answer was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Answer {
    /// `Accepted`.
    Accepted,
    /// `Refused`, with its reason code.
    Refused(String),
    /// No answer: why.
    Unanswered(String),
}

/// The reason a deposit is undelivered when the application's connector
/// opens no connection of the device's own.
const UNSUPPORTED: &str = "unsupported";

/// Whether a reason code leaves the item to go again later.
fn goes_again(code: &str) -> bool {
    matches!(code, "busy" | "rate_limited")
}

/// Whether a refusal is of the token alone: the item goes again at once
/// without it (ext-deposit-tokens.md, 3.11 A device without tokens).
#[cfg(feature = "ext-deposit-tokens")]
fn refuses_token(code: &str) -> bool {
    matches!(code, "token_refused" | "token_expired" | "token_spent")
}

impl Device {
    /// Deposits `item` in the device mailbox at `address` at the peer at
    /// `url`, and keeps it to go again until the peer takes it.
    /// `keep_at_rest` is false for an item of a space kept in memory only
    /// (at-rest.md, "A memory-only log"): it is then kept in memory, and a
    /// restart loses it.
    pub(crate) async fn deposit(
        &self,
        url: &str,
        address: [u8; 32],
        item: Vec<u8>,
        keep_at_rest: bool,
    ) -> Delivery {
        let engine = self.engine();
        let (first, id) = match (engine.reading().await, engine.platform().nonce::<16>()) {
            (Ok(first), Ok(id)) => (first, id),
            (Err(error), _) | (_, Err(error)) => return Delivery::Delayed(error.to_string()),
        };
        let record = DepositRecord {
            peer: url.trim_end_matches('/').to_owned(),
            address,
            item,
            first,
            attempts: 0,
            next: first.timeline,
            token: None,
        };
        if let Err(error) = self.keep_deposit(&id, &record, keep_at_rest).await {
            return Delivery::Delayed(error.to_string());
        }
        if !self.claim_deposit(id) {
            return Delivery::Delayed("already being deposited".into());
        }
        let delivery = self.attempt_deposit(id, record, keep_at_rest).await;
        self.release_deposit(id);
        delivery
    }

    /// Takes a deposit for one attempt; false when one is under way.
    fn claim_deposit(&self, id: [u8; 16]) -> bool {
        self.inner
            .depositing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id)
    }

    fn release_deposit(&self, id: [u8; 16]) {
        self.inner
            .depositing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }

    /// Keeps a deposit: at rest, or in memory for one of a space kept in
    /// memory only.
    pub(crate) async fn keep_deposit(
        &self,
        id: &[u8; 16],
        record: &DepositRecord,
        keep_at_rest: bool,
    ) -> Result<()> {
        if keep_at_rest {
            self.engine()
                .commit_device(
                    vec![(
                        Table::Deposit,
                        id.to_vec(),
                        TableValue::Deposit(record.clone()),
                    )],
                    Vec::new(),
                )
                .await
        } else {
            self.inner
                .unkept
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(*id, record.clone());
            Ok(())
        }
    }

    /// Forgets a deposit, wherever it is kept.
    async fn forget_deposit(&self, id: &[u8; 16]) {
        self.inner
            .unkept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        let _ = self
            .engine()
            .commit_device(Vec::new(), vec![(Table::Deposit, id.to_vec())])
            .await;
    }

    /// Every deposit kept, at rest and in memory, with whether it is at
    /// rest.
    pub(crate) async fn kept_deposits(&self) -> Vec<([u8; 16], DepositRecord, bool)> {
        let mut kept: Vec<_> = self
            .engine()
            .device_records(Table::Deposit)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(item, value)| match value {
                TableValue::Deposit(record) => Some((item.try_into().ok()?, record, true)),
                _ => None,
            })
            .collect();
        kept.extend(
            self.inner
                .unkept
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|(id, record)| (*id, record.clone(), false)),
        );
        kept
    }

    /// One attempt of a deposit, and what follows from its answer.
    #[cfg_attr(
        not(feature = "ext-deposit-tokens"),
        allow(unused_mut, clippy::never_loop)
    )]
    async fn attempt_deposit(
        &self,
        id: [u8; 16],
        mut record: DepositRecord,
        keep_at_rest: bool,
    ) -> Delivery {
        // A token refused alone sends the item again at once: at most
        // twice with a token, then without one.
        for _ in 0..3 {
            #[cfg(feature = "ext-deposit-tokens")]
            if record.token.is_none() {
                record.token = super::tokens::take(self, &id, &record, keep_at_rest).await;
            }
            let answer = match &record.token {
                #[cfg(feature = "ext-deposit-tokens")]
                Some(token) => super::tokens::spend(self, &record, token).await,
                _ => self.deposit_anonymously(&record).await,
            };
            match answer {
                Answer::Accepted => {
                    self.forget_deposit(&id).await;
                    if record.attempts > 0 {
                        self.report(Event::Delivered {
                            peer: record.peer.clone(),
                        });
                    }
                    return Delivery::Delivered;
                }
                Answer::Refused(code) if goes_again(&code) => {
                    return self.delay(id, record, code, keep_at_rest).await;
                }
                #[cfg(feature = "ext-deposit-tokens")]
                Answer::Refused(code) if record.token.is_some() && refuses_token(&code) => {
                    record.token = None;
                    let _ = self.keep_deposit(&id, &record, keep_at_rest).await;
                }
                Answer::Refused(code) => {
                    // A refusal leaves a token unspent (ext-deposit-tokens.md,
                    // 3.7 Redeeming): it goes back to the store.
                    #[cfg(feature = "ext-deposit-tokens")]
                    if let Some(token) = record.token.take() {
                        super::tokens::give_back(self, &record.peer, token).await;
                    }
                    self.forget_deposit(&id).await;
                    self.report(Event::Undelivered {
                        peer: record.peer.clone(),
                        reason: code.clone(),
                    });
                    return Delivery::Refused(code);
                }
                Answer::Unanswered(why) => {
                    return self.delay(id, record, why, keep_at_rest).await;
                }
            }
        }
        self.delay(id, record, "token_refused".into(), keep_at_rest)
            .await
    }

    /// Keeps a deposit that failed to go again later, or gives it up once
    /// it has been kept [`KEEP_FOR`].
    async fn delay(
        &self,
        id: [u8; 16],
        mut record: DepositRecord,
        why: String,
        keep_at_rest: bool,
    ) -> Delivery {
        let engine = self.engine();
        let (now, random) = match (engine.reading().await, engine.platform().nonce::<8>()) {
            (Ok(now), Ok(random)) => (now, random),
            _ => return Delivery::Delayed(why),
        };
        if frasil_base::time::upper(&record.first, &now).at_least(KEEP_FOR) {
            self.forget_deposit(&id).await;
            self.report(Event::Undelivered {
                peer: record.peer,
                reason: "expired".into(),
            });
            return Delivery::Refused("expired".into());
        }
        record.attempts = record.attempts.saturating_add(1);
        record.next = now
            .timeline
            .saturating_add(wait_with(retry_bound(record.attempts), random));
        let _ = self.keep_deposit(&id, &record, keep_at_rest).await;
        self.report(Event::Delayed {
            peer: record.peer,
            reason: why.clone(),
        });
        Delivery::Delayed(why)
    }

    /// A deposit with no token, on a connection of the device's own that
    /// presents nothing (transport.md, 3.12 What a peer learns of a
    /// device): never on the connection that presents the device's spaces,
    /// since a deposit names its recipient. A connector that opens no such
    /// connection ([`Connect::bare`](super::Connect::bare)) leaves the item
    /// undelivered, `unsupported`, rather than show it beside the device's
    /// spaces.
    async fn deposit_anonymously(&self, record: &DepositRecord) -> Answer {
        let mut bare = match self.bare(&record.peer).await {
            Ok(bare) => bare,
            Err(Error::Unsupported(_)) => return Answer::Refused(UNSUPPORTED.into()),
            Err(error) => return Answer::Unanswered(error.to_string()),
        };
        let request = bare.next_request();
        let message = frasil_transport::mailbox::MailboxPut {
            request,
            address: record.address,
            item: record.item.clone(),
            kind: frasil_transport::mailbox::Kind::Device,
        }
        .encode();
        answer_of(bare.put(&message, request).await)
    }

    /// A connection of the device's own to the peer at `url` that presents
    /// nothing.
    pub(crate) async fn bare(&self, url: &str) -> Result<crate::peer::Bare> {
        super::peers::bare(self.engine(), self.inner.connect.as_ref(), url).await
    }
}

impl Device {
    /// Deposits `item` in the device mailbox of `recipient` at the peer at
    /// `url` as the device deposits welcomes: kept, and sent again until
    /// the peer takes it, with a token where the device holds one. For
    /// tests of that path; the items a device sends are sealed by the
    /// procedures that make them.
    ///
    /// # Errors
    ///
    /// [`Error::Delayed`] for an item kept to go again;
    /// [`Error::Connection`] for one the peer refused for good.
    #[doc(hidden)]
    pub async fn deposit_item(
        &self,
        url: &str,
        recipient: super::MemberId,
        item: Vec<u8>,
    ) -> Result<()> {
        let address = frasil_transport::mailbox::address(
            frasil_transport::mailbox::Kind::Device,
            recipient.as_bytes(),
        );
        self.deposit(url, address, item, true).await.into_result()
    }

    /// Runs what the device's upkeep runs for deposits at once: the kept
    /// deposits that are due, and, with deposit tokens, the draws that are
    /// due. For tests that move the device's clock.
    #[doc(hidden)]
    pub async fn deposit_upkeep(&self) {
        retry(self).await;
        #[cfg(feature = "ext-deposit-tokens")]
        super::tokens::upkeep(self).await;
    }

    /// How many deposits the device keeps to send again.
    pub async fn waiting_deposits(&self) -> usize {
        self.kept_deposits().await.len()
    }
}

/// An answer on a [`Bare`](crate::peer::Bare) connection.
pub(crate) fn answer_of(answer: Result<std::result::Result<(), String>>) -> Answer {
    match answer {
        Ok(Ok(())) => Answer::Accepted,
        Ok(Err(code)) => Answer::Refused(code),
        Err(error) => Answer::Unanswered(error.to_string()),
    }
}

/// Attempts each kept deposit whose wait has passed: the device's upkeep
/// runs it.
pub(super) async fn retry(device: &Device) {
    let Ok(now) = device.engine().reading().await else {
        return;
    };
    for (id, record, at_rest) in device.kept_deposits().await {
        if record.next > now.timeline || !device.claim_deposit(id) {
            continue;
        }
        let _ = device.attempt_deposit(id, record, at_rest).await;
        device.release_deposit(id);
    }
}

#[cfg(test)]
mod tests {
    use super::{retry_bound, wait_with};

    /// transport.md, "A sender keeps what was refused": a random wait of
    /// up to a minute, doubled after each further refusal to at most an
    /// hour.
    #[test]
    fn the_waits_double_to_an_hour() {
        let bounds: Vec<u64> = (1..=9).map(retry_bound).collect();
        assert_eq!(bounds, [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
        assert_eq!(retry_bound(u64::MAX), 3600);
        assert_eq!(wait_with(60, [0; 8]), 0);
        assert_eq!(wait_with(60, 60_u64.to_be_bytes()), 60);
        assert_eq!(wait_with(60, 61_u64.to_be_bytes()), 0);
        assert!(wait_with(3600, [0xff; 8]) <= 3600);
    }
}
