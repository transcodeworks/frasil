//! Head statements (units.md, "Head statements"; transport.md, "Sync, head
//! statements, list events and adapter sync").
//!
//! A device states, under its Ed25519 key, with the `ed || kc` whose device
//! ID names it, the heads it holds of a space
//! and, for each stream it holds whole, each writer's stream frontier. It
//! sends its statement on each admitted attach when the attach is admitted
//! and whenever its heads change, at most once per `gossip_interval`. A
//! receiver keeps each valid statement of a member device that it has not
//! shown older than another it keeps, which shows what that device holds.
//! It asks the statement's author for heads it lacks, then its peers. A
//! peer that answered `Missing` for heads the author then supplies was
//! withholding (`Withheld`) if it had acknowledged them, or if it still
//! answered `Missing` when asked again after `withholding_grace`; a peer
//! that merely had not received them yet is not reported. An author that
//! answers `Missing` for its own heads made a junk statement
//! (`BadStatement`).

use crate::device::Engine;
use crate::error::{Error, Result};
use frasil_events::EventId;
use frasil_units::statement::HeadStatement;

/// The most heads a statement lists.
const MAX_HEADS: usize = 256;
/// The most streams a statement lists.
const MAX_STREAMS: usize = 64;

/// `gossip_interval`.
#[cfg(feature = "iroh")]
pub(crate) fn gossip_interval() -> std::time::Duration {
    std::time::Duration::from_secs(
        frasil_base::time::Timer::GossipInterval
            .spec()
            .default
            .unwrap_or(30),
    )
}

/// `withholding_grace`, in seconds: how long after a peer's first
/// `Missing` for a statement's heads the device asks it again, and how
/// long its `Missing` answers must span before they show withholding
/// (units.md, 3.13 "Head statements").
pub(crate) fn withholding_grace() -> u64 {
    frasil_base::time::Timer::WithholdingGrace
        .spec()
        .default
        .unwrap_or(300)
}

impl Engine {
    /// Asks a peer again for the head statements' heads it answered
    /// `Missing` for at least `withholding_grace` ago, of those the device
    /// still lacks (units.md, 3.13 "Head statements"): `Want` messages.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`], or the store's.
    pub async fn sync_restated(
        &self,
        session: &mut crate::sync::SyncSession,
        by: crate::outbox::Acknowledger,
    ) -> Result<Vec<frasil_units::messages::SyncMessage>> {
        let space = session.space();
        let mut state = self.lock().await;
        let now = self.read_timeline(&mut state).await?.timeline;
        let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
        let due: Vec<EventId> = state
            .outboxes
            .get(&space)
            .map(|outbox| outbox.stated_due(&by, now, withholding_grace()))
            .unwrap_or_default()
            .into_iter()
            .filter(|head| !replica.holds(*head))
            .collect();
        Ok(session
            .ask_stated_again(due)
            .into_iter()
            .filter_map(|action| match action {
                crate::sync::Action::Send(message) => Some(message),
                _ => None,
            })
            .collect())
    }

    /// This device's signed head statement of a space, with its heads.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn head_statement(&self, space: &EventId) -> Result<(Vec<u8>, Vec<EventId>)> {
        let seed = self.keys().identity_seed_bytes();
        let device = self.signer().signatory();
        self.read(space, |replica| {
            let log = replica.log()?;
            let mut heads = log.heads();
            heads.sort_unstable();
            heads.truncate(MAX_HEADS);
            if heads.is_empty() {
                return None;
            }
            let streams = replica
                .streams()
                .map(|(stream, _)| *stream)
                .filter(|stream| {
                    replica
                        .stream(stream)
                        .is_some_and(|r| r.base_cover().is_empty())
                })
                .take(MAX_STREAMS)
                .filter_map(|stream| {
                    let covers = frasil_units::compaction::covers(
                        log,
                        |id| crate::compaction::stream_of(log, id),
                        &heads,
                        &stream,
                    );
                    (!covers.is_empty()).then_some((stream, covers))
                })
                .collect();
            let statement = HeadStatement {
                space: *space,
                device,
                heads: heads.clone(),
                streams,
            };
            Some((statement.sign(&seed), heads))
        })
        .await?
        .ok_or(Error::NotAllowed("the device holds nothing of the space"))
    }

    /// Takes signed head statements another member sent: each one that
    /// reads, verifies and names a member device of the merged roster is
    /// kept, unless one kept of that device is shown no older (units.md,
    /// 3.13 "Head statements"). Returns how many were kept.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn take_statements(&self, space: &EventId, signed: &[Vec<u8>]) -> Result<usize> {
        let mut state = self.lock().await;
        let replica = state.replicas.get_mut(space).ok_or(Error::UnknownSpace)?;
        let mut kept = 0;
        for bytes in signed {
            let read =
                HeadStatement::read(bytes, space, |device| replica.level_of(device).is_some());
            if let Ok(statement) = read
                && replica.keep_statement(statement)
            {
                kept += 1;
            }
        }
        Ok(kept)
    }

    /// Asks a statement's author, on its session, for the heads of its
    /// kept statements this device lacks (units.md, 3.13 "Head
    /// statements"): `Want` messages, each head once per session. Peers
    /// are asked for them after.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn sync_stated(
        &self,
        session: &mut crate::sync::SyncSession,
        author: &frasil_crypto::device::DeviceId,
    ) -> Result<Vec<frasil_units::messages::SyncMessage>> {
        let mut state = self.lock().await;
        let replica = state
            .replicas
            .get_mut(&session.space())
            .ok_or(Error::UnknownSpace)?;
        let lacking = replica.stated_lacking_of(author);
        replica.note_stated_asked(&lacking);
        Ok(session
            .ask_stated(lacking)
            .into_iter()
            .filter_map(|action| match action {
                crate::sync::Action::Send(message) => Some(message),
                _ => None,
            })
            .collect())
    }
}
