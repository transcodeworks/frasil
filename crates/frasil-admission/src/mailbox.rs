//! A peer's exchange mailboxes (admission.md, "Exchange mailboxes").
//!
//! An exchange travels through transport.md's exchange mailbox, named by
//! `request`, on any always-on peer, with no account and no credential. A
//! Request opens it; whoever knows the request ID may put the exchange's
//! later messages and read them. A peer checks each put, in order; clients
//! rely on none of it:
//!
//! ```text
//! a Request:
//!   1. The message reads.                                               else that class
//!   2. No exchange mailbox has this request ID.                         else MailboxInUse
//!   3. Its body reads, and check_expiry passes on the peer's wall
//!      clock.                                                           else that class
//!   4. Its source has opened fewer than 10 exchange mailboxes in the
//!      last minute, and holds fewer than 128 open.                      else RateLimited
//!   5. The peer holds fewer than 65,536 exchange mailboxes, and under
//!      256 MiB in all.                                                  else MailboxFull
//! any other message:
//!   6. The message reads, and its type is 2 to 6.                       else that class / Malformed
//!   7. The exchange mailbox exists.                                     else UnknownMailbox
//!   8. The peer's wall clock is not past expires_at.                    else Expired
//!   9. It is not cancelled.                                             else Cancelled
//!  10. A Cancel marks it cancelled.
//!  11. It holds no message of this type.                                else Duplicate
//!  12. A Response follows the Request; a Reveal the Response; a List
//!      and a Result the Reveal.                                         else OutOfOrder
//! ```
//!
//! A peer keeps exchange mailboxes in memory only, and drops each after
//! `exchange_mailbox_lifetime` (`expires_at + 60`); a restart ends them
//! all. A Join, Hello or Offer never goes to an exchange mailbox.

use crate::bodies::RequestBody;
use crate::message::{MessageType, read_message};
use crate::params::{
    ADMISSION_CODE_LIFETIME, ADMISSION_CODE_SKEW, MAILBOX_BYTES_PER_PEER, MAILBOX_GRACE,
    MAILBOX_NEW_PER_MINUTE, MAILBOX_OPEN_PER_SOURCE, MAILBOX_PER_PEER, REQUEST_BYTES,
};
use crate::{AdmissionClass, malformed};
use frasil_base::ErrorClass;
use frasil_base::time::check_expiry;
use frasil_transport::mailbox::{Kind, address};
use std::collections::BTreeMap;

/// An exchange mailbox's address (transport.md, "Mailboxes"): kind 1, named
/// by the request ID.
pub fn exchange_address(request: &[u8; REQUEST_BYTES]) -> [u8; 32] {
    address(Kind::Exchange, request)
}

/// A peer's limits on exchange mailboxes. A peer MAY lower any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxLimits {
    /// Exchange mailboxes one source opens in a minute, fewer than this.
    pub new_per_source_per_minute: usize,
    /// Exchange mailboxes one source holds open, fewer than this.
    pub open_per_source: usize,
    /// Exchange mailboxes the peer holds, fewer than this.
    pub per_peer: usize,
    /// Bytes the peer's exchange mailboxes hold in all, under this.
    pub bytes_per_peer: usize,
}

impl MailboxLimits {
    /// admission.md's limits.
    pub const PROTOCOL: Self = Self {
        new_per_source_per_minute: MAILBOX_NEW_PER_MINUTE,
        open_per_source: MAILBOX_OPEN_PER_SOURCE,
        per_peer: MAILBOX_PER_PEER,
        bytes_per_peer: MAILBOX_BYTES_PER_PEER,
    };
}

#[derive(Debug, Clone)]
struct Mailbox<S> {
    /// Who opened it; none for a put with no source.
    source: Option<S>,
    expires_at: u64,
    drop_at: u64,
    messages: BTreeMap<MessageType, Vec<u8>>,
    cancelled: bool,
}

/// A peer's exchange mailboxes, by request ID, in memory only. `S` names a
/// source, such as a connection's remote address. A put with no source,
/// from a connection the peer cannot name one for, is bound by step 5's
/// limits alone.
#[derive(Debug, Clone)]
pub struct ExchangeMailboxes<S> {
    limits: MailboxLimits,
    mailboxes: BTreeMap<[u8; REQUEST_BYTES], Mailbox<S>>,
    opened: BTreeMap<S, Vec<u64>>,
    bytes: usize,
}

impl<S: Ord + Clone> Default for ExchangeMailboxes<S> {
    fn default() -> Self {
        Self::new(MailboxLimits::PROTOCOL)
    }
}

impl<S: Ord + Clone> ExchangeMailboxes<S> {
    /// No exchange mailbox, under these limits.
    pub fn new(limits: MailboxLimits) -> Self {
        Self {
            limits,
            mailboxes: BTreeMap::new(),
            opened: BTreeMap::new(),
            bytes: 0,
        }
    }

    /// Drops each exchange mailbox whose lifetime has passed at the wall
    /// clock `now`, and forgets the opens of each source that opened none
    /// in the last minute, which step 4 no longer counts.
    pub fn sweep(&mut self, now: u64) {
        self.opened.retain(|_, times| {
            times.retain(|&t| now.saturating_sub(t) < 60);
            !times.is_empty()
        });
        let gone: Vec<[u8; REQUEST_BYTES]> = self
            .mailboxes
            .iter()
            .filter(|(_, mailbox)| now > mailbox.drop_at)
            .map(|(request, _)| *request)
            .collect();
        for request in gone {
            if let Some(mailbox) = self.mailboxes.remove(&request) {
                self.bytes -= mailbox.messages.values().map(Vec::len).sum::<usize>();
            }
        }
    }

    /// Steps 1 to 12, in order, for a message `source` puts at the peer's
    /// wall clock `now`, after dropping the mailboxes whose lifetime has
    /// passed.
    ///
    /// # Errors
    ///
    /// The steps' classes; [`AdmissionClass::reason`] gives each one's
    /// reason code and HTTP status.
    pub fn put(&mut self, source: &S, message: &[u8], now: u64) -> Result<(), AdmissionClass> {
        self.put_from(Some(source), message, now)
    }

    /// [`Self::put`] for a message with no source: step 4 counts nothing
    /// for it, and step 5's limits on all exchange mailboxes together bound
    /// it.
    ///
    /// # Errors
    ///
    /// As [`Self::put`].
    pub fn put_unsourced(&mut self, message: &[u8], now: u64) -> Result<(), AdmissionClass> {
        self.put_from(None, message, now)
    }

    fn put_from(
        &mut self,
        source: Option<&S>,
        message: &[u8],
        now: u64,
    ) -> Result<(), AdmissionClass> {
        self.sweep(now);
        let read = read_message(message)?;
        if read.kind == MessageType::Request {
            return self.open(source, read.request, read.body, message, now);
        }
        if !matches!(
            read.kind,
            MessageType::Response
                | MessageType::Reveal
                | MessageType::List
                | MessageType::Result
                | MessageType::Cancel
        ) {
            return Err(malformed());
        }
        let total = self.bytes;
        let limit = self.limits.bytes_per_peer;
        let mailbox = self
            .mailboxes
            .get_mut(&read.request)
            .ok_or(AdmissionClass::UnknownMailbox)?;
        if now > mailbox.expires_at {
            return Err(ErrorClass::Expired.into());
        }
        if mailbox.cancelled {
            return Err(AdmissionClass::Cancelled);
        }
        if read.kind == MessageType::Cancel {
            // Kept, so that each side reads it ("Without a nearby
            // connection": each side reads every message of the mailbox).
            mailbox.cancelled = true;
            mailbox.messages.insert(read.kind, message.to_vec());
            self.bytes += message.len();
            return Ok(());
        }
        if mailbox.messages.contains_key(&read.kind) {
            return Err(AdmissionClass::Duplicate);
        }
        let follows = match read.kind {
            MessageType::Response => MessageType::Request,
            MessageType::Reveal => MessageType::Response,
            _ => MessageType::Reveal,
        };
        if !mailbox.messages.contains_key(&follows) {
            return Err(AdmissionClass::OutOfOrder);
        }
        if total + message.len() > limit {
            return Err(AdmissionClass::MailboxFull);
        }
        mailbox.messages.insert(read.kind, message.to_vec());
        self.bytes += message.len();
        Ok(())
    }

    fn open(
        &mut self,
        source: Option<&S>,
        request: [u8; REQUEST_BYTES],
        body: &[u8],
        message: &[u8],
        now: u64,
    ) -> Result<(), AdmissionClass> {
        // 2.
        if self.mailboxes.contains_key(&request) {
            return Err(AdmissionClass::MailboxInUse);
        }
        // 3.
        let body = RequestBody::read(body)?;
        check_expiry(
            body.expires_at,
            Some(now),
            ADMISSION_CODE_LIFETIME,
            ADMISSION_CODE_SKEW,
        )?;
        // 4.
        let recent: Vec<u64> = source
            .and_then(|source| self.opened.get(source))
            .map(|times| {
                times
                    .iter()
                    .copied()
                    .filter(|&t| now.saturating_sub(t) < 60)
                    .collect()
            })
            .unwrap_or_default();
        let mine = source.map_or(0, |source| {
            self.mailboxes
                .values()
                .filter(|m| m.source.as_ref() == Some(source))
                .count()
        });
        if source.is_some()
            && (recent.len() >= self.limits.new_per_source_per_minute
                || mine >= self.limits.open_per_source)
        {
            return Err(AdmissionClass::RateLimited);
        }
        // 5.
        if self.mailboxes.len() >= self.limits.per_peer
            || self.bytes + message.len() > self.limits.bytes_per_peer
        {
            return Err(AdmissionClass::MailboxFull);
        }
        if let Some(source) = source {
            let mut times = recent;
            times.push(now);
            self.opened.insert(source.clone(), times);
        }
        self.mailboxes.insert(
            request,
            Mailbox {
                source: source.cloned(),
                expires_at: body.expires_at,
                drop_at: body.expires_at.saturating_add(MAILBOX_GRACE),
                messages: BTreeMap::from([(MessageType::Request, message.to_vec())]),
                cancelled: false,
            },
        );
        self.bytes += message.len();
        Ok(())
    }

    /// The messages an exchange mailbox holds, in type order, a Cancel
    /// included, and whether it is cancelled; `None` when no exchange
    /// mailbox has this request ID.
    pub fn read(&self, request: &[u8; REQUEST_BYTES]) -> Option<(Vec<&[u8]>, bool)> {
        self.mailboxes.get(request).map(|mailbox| {
            (
                mailbox.messages.values().map(Vec::as_slice).collect(),
                mailbox.cancelled,
            )
        })
    }

    /// How many sources step 4 counts recent opens for: each source that
    /// opened an exchange mailbox in the last minute, until a sweep.
    pub fn sources_counted(&self) -> usize {
        self.opened.len()
    }

    /// How many exchange mailboxes the peer holds.
    pub fn len(&self) -> usize {
        self.mailboxes.len()
    }

    /// Whether the peer holds no exchange mailbox.
    pub fn is_empty(&self) -> bool {
        self.mailboxes.is_empty()
    }
}
