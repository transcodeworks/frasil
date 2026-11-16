//! The device's collecting connections: where it collects its own device
//! mailbox (transport.md, "Collecting a device mailbox").
//!
//! A collection shows the peer the device's Ed25519 key, `kc` and device
//! ID, so it never rides the connection that presents the device's
//! spaces: the peer would link the device, a reader's included, to those
//! spaces (transport.md, 3.12 What a peer learns of a device; overview.md,
//! 4.1). It goes on a connection of the device's own that presents
//! nothing ([`Bare`]), opened as an administration connection is: a fresh
//! transport, no TLS session resumed, no cookie.
//!
//! One such connection per peer, by URL, carries every collection there:
//! the upkeep's, a new device's and a batch admission's. It is opened when
//! a collection first needs it, kept between collections, opened again
//! when it ends (at once the first time, then after a random wait that
//! doubles from `reconnect_wait` to `reconnect_wait_cap` while opening
//! fails), and closed with the device, or once the device holds no open
//! connection to that peer. It carries collections alone: no `Present`, no
//! deposit, which names its recipient and goes on a connection of its own
//! ([`Device::deposit`]), and no draw of deposit tokens. A peer still sees
//! its source address and timing beside the space connection's, which
//! transport.md does not hide (section 4, "Credentials at a peer").

use super::Device;
use crate::error::{Error, Result};
use crate::peer::{Bare, MailboxAnswer};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

/// The first bound of the random wait before a collecting connection that
/// failed to open is opened again, in seconds: `reconnect_wait`.
fn first_wait() -> u64 {
    frasil_base::time::Timer::ReconnectWait
        .spec()
        .default
        .unwrap_or(5)
}

/// The last bound: `reconnect_wait_cap`.
fn wait_cap() -> u64 {
    frasil_base::time::Timer::ReconnectWaitCap
        .spec()
        .default
        .unwrap_or(60)
}

/// The bound of the wait after `failures` openings in a row that failed:
/// `reconnect_wait`, doubled after each further one, to at most
/// `reconnect_wait_cap`.
pub(crate) fn open_bound(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    first_wait().saturating_mul(1 << doublings).min(wait_cap())
}

/// One peer's collecting connection.
#[derive(Default)]
struct Collecting {
    /// The connection, while it runs.
    bare: Option<Bare>,
    /// How many openings in a row failed.
    failures: u32,
    /// The device's timeline reading, in seconds, before which no opening
    /// is attempted after one failed.
    not_before: u64,
    /// How many connections were opened, for [`Device::collecting_opened`].
    opened: u64,
}

/// Every peer's collecting connection, by the peer's URL.
#[derive(Default)]
pub(super) struct Collectors {
    by_peer: Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<Collecting>>>>,
}

impl Collectors {
    /// The peer's collecting connection, made when first named.
    fn of(&self, url: &str) -> Arc<tokio::sync::Mutex<Collecting>> {
        self.by_peer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key(url))
            .or_default()
            .clone()
    }

    /// Closes the collecting connections of every peer not in `keep`, by
    /// URL. One busy collecting closes once its collection ends.
    pub(super) fn keep_only(&self, keep: &[String]) {
        let keep: Vec<String> = keep.iter().map(|url| key(url)).collect();
        self.by_peer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|url, _| keep.contains(url));
    }

    /// Closes every collecting connection, with the device.
    pub(super) fn close_all(&self) {
        let all = std::mem::take(&mut *self.by_peer.lock().unwrap_or_else(PoisonError::into_inner));
        for collecting in all.into_values() {
            if let Ok(mut collecting) = collecting.try_lock() {
                collecting.bare = None;
            }
        }
    }
}

/// A peer's URL as the collecting connections are kept by.
fn key(url: &str) -> String {
    url.trim_end_matches('/').to_owned()
}

impl Device {
    /// Collects this device's own device mailbox at the peer at `url`
    /// after the item `after`, on the peer's collecting connection: the
    /// items, or the peer's reason code.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] once the device is closed;
    /// [`Error::Connection`] when no collecting connection opens, or
    /// while one waits to open again after a failure; as [`Bare::ask`].
    pub(crate) async fn collect_own(
        &self,
        url: &str,
        after: Option<[u8; 16]>,
    ) -> Result<Vec<([u8; 16], Vec<u8>)>> {
        match self.collect_own_answer(url, after).await? {
            Ok(items) => Ok(items),
            Err(code) => Err(Error::Connection(code)),
        }
    }

    async fn collect_own_answer(
        &self,
        url: &str,
        after: Option<[u8; 16]>,
    ) -> Result<MailboxAnswer> {
        let slot = self.inner.collecting.of(url);
        let mut collecting = slot.lock().await;
        // A connection that ended is dropped: the next one is fresh.
        if collecting.bare.as_ref().is_some_and(|bare| !bare.is_open()) {
            collecting.bare = None;
        }
        let reused = collecting.bare.is_some();
        for _ in 0..2 {
            if collecting.bare.is_none() {
                self.open_collecting(url, &mut collecting).await?;
            }
            let Some(bare) = collecting.bare.as_mut() else {
                return Err(Error::Connection("no collecting connection".into()));
            };
            match bare.collect_own(self.engine(), after).await {
                Ok(answer) => return Ok(answer),
                // A kept connection that the peer closed meanwhile, or that
                // was lost: once more, on a fresh one.
                Err(_) if reused => collecting.bare = None,
                Err(error) => {
                    collecting.bare = None;
                    return Err(error);
                }
            }
        }
        Err(Error::Connection("the collecting connection ended".into()))
    }

    /// Opens the peer's collecting connection, unless a failed opening's
    /// wait has not passed.
    async fn open_collecting(&self, url: &str, collecting: &mut Collecting) -> Result<()> {
        if self.is_closed() {
            return Err(Error::NotAllowed("the device is closed"));
        }
        let now = self.engine().reading().await?.timeline;
        if now < collecting.not_before {
            return Err(Error::Connection(
                "the collecting connection waits to open again".into(),
            ));
        }
        match self.bare(url).await {
            Ok(bare) => {
                collecting.bare = Some(bare);
                collecting.failures = 0;
                collecting.not_before = 0;
                collecting.opened += 1;
                Ok(())
            }
            Err(error) => {
                collecting.failures = collecting.failures.saturating_add(1);
                let random = self.engine().platform().nonce::<8>()?;
                let wait = super::deposits::wait_with(open_bound(collecting.failures), random);
                collecting.not_before = now.saturating_add(wait);
                Err(error)
            }
        }
    }

    /// How many collecting connections the device has opened to the peer
    /// at `url`, for tests that a collecting connection is kept and opened
    /// again.
    #[doc(hidden)]
    pub async fn collecting_opened(&self, url: &str) -> u64 {
        self.inner.collecting.of(url).lock().await.opened
    }

    /// Runs what the device's upkeep runs for its own device mailbox at
    /// once: a collection at each connected peer. For tests.
    #[doc(hidden)]
    pub async fn mailbox_upkeep(&self) {
        super::collect_mailboxes(self).await;
    }
}

#[cfg(test)]
mod tests {
    use super::open_bound;

    /// The wait before a collecting connection opens again: from
    /// `reconnect_wait`, doubled after each failure, to
    /// `reconnect_wait_cap` (transport.md, "Reconnecting elsewhere").
    #[test]
    fn the_wait_to_open_again_doubles_to_its_cap() {
        let bounds: Vec<u64> = (1..=6).map(open_bound).collect();
        assert_eq!(bounds, [5, 10, 20, 40, 60, 60]);
        assert_eq!(open_bound(u32::MAX), 60);
    }
}
