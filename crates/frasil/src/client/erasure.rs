//! Erasing a space at its peers (peers.md, "Erasure"), and from this
//! device.

use super::{Event, Space, SpaceId};
use crate::erasing::{ErasureProgress, Refetched};
use crate::error::{Error, Result};
use frasil_space::Level;

impl Space {
    /// Erases the whole space at its peers, then drops it from this
    /// device. The erasure is a skeleton event of this device's pseudonym,
    /// which each peer executes once it is stable there, or after its
    /// erasure timeout. A peer then removes every event and object of the
    /// space, and refuses to keep it again. This device then forgets the
    /// space: its log, streams and keys at rest go, and it no longer holds
    /// it. What the devices of other members keep is their own.
    ///
    /// An erasure names the whole space and nothing narrower (peers.md,
    /// "Erasure"). A document is deleted for good with a release
    /// ([`Space::release_stream`]), whose content the peers delete once
    /// they reclaim it, after their release retention.
    ///
    /// A device with peers hands the erasure to each one connected first,
    /// over an administration connection, natively or through its
    /// connector in a browser, and keeps the space until one has
    /// acknowledged it, or refused the device's pseudonym `erased`
    /// because it already executed an erasure of the space. While a
    /// checkpoint that could make the erasure late can still take effect,
    /// the device keeps the space, signs the erasure again after the
    /// checkpoint if it does, and drops the space in its upkeep once that
    /// erasure is acknowledged.
    ///
    /// Dropping the space removes its content from this device at once.
    /// The device keeps its erasure residue, including its pseudonyms,
    /// peer addresses and administering devices, until every peer answers
    /// `erased` or the application gives the space up. After the erasure
    /// timeout, seven days by default, it reports unanswered peers and
    /// keeps asking.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] unless this device administers the space and
    /// holds a pseudonym there; [`Error::Connection`] when no connected
    /// peer acknowledged the erasure within 30 seconds, and the space stays
    /// on this device; the store's.
    pub async fn erase(&self) -> Result<()> {
        if self.level().await != Some(Level::Administer) {
            return Err(Error::NotAllowed("erasing a space needs administer"));
        }
        let engine = self.device.engine();
        let space = self.id().event();
        let erasure = engine.request_erasure(space).await?;
        // A peer that answers `erased` carried an erasure of the space out:
        // nothing can make it late any more.
        #[allow(unused_mut)]
        let mut executed = false;
        // At once on an administration connection to each connected peer,
        // natively or through the application's connector; the space goes
        // from this device once one acknowledged it.
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        {
            // The device's own administration connection for the space may
            // store the erasure beside this one: the peer then acknowledges
            // it there, and may execute it before this connection presents,
            // which it then refuses `erased`. A peer holding the space's
            // tombstone erased it, so that refusal is as good as the
            // acknowledgement; else the device waits for one, asking again,
            // for as long as a flush waits.
            const ACKNOWLEDGED_WITHIN: std::time::Duration = std::time::Duration::from_secs(30);
            const STEP: std::time::Duration = std::time::Duration::from_millis(50);
            const AGAIN: std::time::Duration = std::time::Duration::from_secs(1);
            let peers = self.device.peers_of(&space);
            if !peers.is_empty() {
                let mut waited = std::time::Duration::ZERO;
                let mut since = AGAIN;
                'acknowledged: while engine.outbox(&space).await.contains(&erasure) {
                    if waited >= ACKNOWLEDGED_WITHIN {
                        return Err(Error::Connection(
                            "no connected peer acknowledged the erasure; the space stays on this device"
                                .into(),
                        ));
                    }
                    if since >= AGAIN {
                        since = std::time::Duration::ZERO;
                        for peer in &peers {
                            if peer.status().connected {
                                let administered = super::peers::administer(
                                    engine,
                                    self.device.inner.connect.as_ref(),
                                    peer.url(),
                                    space,
                                )
                                .await;
                                if matches!(
                                    &administered,
                                    Err(crate::Error::Class("extension_required"))
                                ) {
                                    self.device.report(Event::PeerNeedsVersion {
                                        space: SpaceId::of(space),
                                        peer: peer.url().to_owned(),
                                    });
                                }
                                if let Err(error) = administered
                                    && crate::peer::refused_as_erased(&error)
                                {
                                    executed = true;
                                    break 'acknowledged;
                                }
                            }
                        }
                        continue;
                    }
                    self.device.sleep(STEP).await;
                    waited += STEP;
                    since += STEP;
                }
            }
        }
        #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
        let _ = erasure;
        // Its content goes now, unless a checkpoint that can still take
        // effect is concurrent with the erasure: the device then keeps the
        // space, signs the erasure again if the checkpoint makes it late,
        // and drops it in its upkeep. The pseudonym stays until each peer
        // answers `erased` (peers.md, "A device's own erasure").
        if executed || engine.own_erasure_droppable(&space).await {
            engine.drop_for_erasure(&space).await?;
            self.device.finish_erasure(space).await?;
        }
        Ok(())
    }
}

impl super::Device {
    /// Presents, at each of the space's peers, the erasure of a space this
    /// device dropped for its own erasure, and forgets the space once each
    /// answered `erased` (peers.md, 3.16, "A device's own erasure"). Past
    /// the bound, `erasure_timeout` at its default on the device's timeline
    /// from the erasure's first sight, it tells the application which peers
    /// have not answered ([`Event::ErasureUnanswered`]), and keeps asking
    /// until each has, or the application gives the space up
    /// ([`Device::give_up_space`](super::Device::give_up_space)). Nothing for
    /// a space not dropped so.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn finish_erasure(&self, space: frasil_events::EventId) -> Result<()> {
        self.finish_erasure_with(space, false).await
    }

    async fn finish_erasure_with(
        &self,
        space: frasil_events::EventId,
        request_welcome: bool,
    ) -> Result<()> {
        #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
        let _ = request_welcome;
        let engine = self.engine();
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        {
            let known: Vec<String> = self
                .peers()
                .iter()
                .map(|peer| peer.url().to_owned())
                .collect();
            engine.keep_peer_hints(&space, &known).await?;
        }
        let saved = engine.erasure_peers(&space).await?;
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        {
            for url in &saved {
                if !self
                    .peers()
                    .iter()
                    .any(|peer| crate::hints::same_peer(peer.url(), url) && peer.status().connected)
                {
                    let _ = self.connect(url).await;
                }
            }
        }
        #[allow(unused_mut)]
        let mut answered: Vec<String> = Vec::new();
        #[allow(unused_mut)]
        let mut reached = saved;
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        for peer in self.peers_of(&space) {
            if !reached
                .iter()
                .any(|url| crate::hints::same_peer(url, peer.url()))
            {
                reached.push(peer.url().to_owned());
            }
            // Welcome requests can outlive the welcome they trigger. Keep
            // the exchange and its answer together, but let the restored
            // device send its new erasure while those deposits finish.
            let (administered, peer_error, late) = {
                let _one = self.inner.administering.lock().await;
                let administered = super::peers::administer(
                    engine,
                    self.inner.connect.as_ref(),
                    peer.url(),
                    space,
                )
                .await;
                (
                    administered,
                    engine.take_erasure_peer_error(&space).await,
                    engine.take_erasure_late(&space).await,
                )
            };
            if matches!(
                &administered,
                Err(crate::Error::Class("extension_required"))
            ) {
                self.report(Event::PeerNeedsVersion {
                    space: SpaceId::of(space),
                    peer: peer.url().to_owned(),
                });
            }
            if let Err(error) = administered
                && crate::peer::refused_as_erased(&error)
            {
                answered.push(peer.url().to_owned());
            }
            if let Some(answer) = peer_error {
                self.report(Event::PeerError {
                    space: SpaceId::of(space),
                    peer: peer.url().to_owned(),
                    answer,
                });
            }
            if let Some(answer) = late {
                let checkpoint = frasil_events::EventId(answer.checkpoint);
                if engine.erasure_late_at(&space, peer.url()).await {
                    self.report(Event::ErasureLateAtPeer {
                        space: SpaceId::of(space),
                        peer: peer.url().to_owned(),
                    });
                }
                self.report(Event::ErasureCheckpoint {
                    space: SpaceId::of(space),
                    peer: peer.url().to_owned(),
                    checkpoint: super::CheckpointId::from_bytes(checkpoint.0),
                    standing: answer.standing,
                });
                if answer.standing < 2
                    && let Some((holding, same_device)) = engine.held_slot(&space).await
                {
                    self.report(Event::SlotHeld {
                        space: SpaceId::of(space),
                        holding: super::ChangeId::from_bytes(holding.0),
                        holder: if same_device {
                            "another installation of this device"
                        } else {
                            "another device"
                        }
                        .into(),
                        erasure_waiting: true,
                        peer: Some(peer.url().to_owned()),
                    });
                } else if answer.standing == 1
                    && let Some(holding) = engine.residue_slot_held(&space, &answer.cut).await
                {
                    self.report(Event::SlotHeld {
                        space: SpaceId::of(space),
                        holding: super::ChangeId::from_bytes(holding.0),
                        holder: "unknown".into(),
                        erasure_waiting: true,
                        peer: Some(peer.url().to_owned()),
                    });
                } else if answer.standing < 2 {
                    if request_welcome || engine.erasure_welcome_due(&space).await? {
                        self.erasure_late_at(SpaceId::of(space), peer.url()).await?;
                    } else {
                        self.report(Event::ErasureAwaitingWelcome {
                            space: SpaceId::of(space),
                        });
                    }
                } else {
                    self.report(Event::ErasureCannotErase {
                        space: SpaceId::of(space),
                        peer: peer.url().to_owned(),
                    });
                }
            }
        }
        // Every answer first, then where the residue stands.
        for peer in &answered {
            engine
                .erasure_answered(&space, Some(peer), &reached)
                .await?;
        }
        let progress = engine.erasure_answered(&space, None, &reached).await?;
        if let ErasureProgress::Waiting {
            unanswered: Some(peers),
        } = progress
        {
            self.report(Event::ErasureUnanswered {
                space: SpaceId::of(space),
                peers,
            });
        }
        Ok(())
    }

    /// [`Self::finish_erasure`] for every space dropped for its own erasure,
    /// and what becomes of an erasure a checkpoint made late, once the space
    /// is fetched again.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn finish_erasures(&self) {
        // An erasure the device kept its space for while a concurrent
        // checkpoint could still make it late, once it can no longer.
        for space in self.engine().presentable_spaces().await {
            if self.engine().own_erasure_droppable(&space).await
                && self.engine().drop_for_erasure(&space).await.is_err()
            {
                continue;
            }
            self.settle_refetched(space).await;
        }
        for space in self.engine().erasing().await {
            let _ = self.finish_erasure(space).await;
        }
    }

    /// Once a space fetched again after a checkpoint made this device's
    /// erasure late holds that checkpoint: the erasure signed again after
    /// it and handed to the peers, or a void erasure or held slot reported.
    pub(crate) async fn settle_refetched(&self, space: frasil_events::EventId) {
        let original = self
            .engine()
            .lock()
            .await
            .erasing
            .get(&space)
            .and_then(|residue| residue.erasure.as_ref().map(|(id, _)| *id));
        match self.engine().settle_refetched(&space).await {
            Ok(Some(Refetched::SignedAgain(erasure))) => {
                self.report(Event::RequestSignedAgain {
                    space: SpaceId::of(space),
                    request: super::ChangeId::from_bytes(original.unwrap_or(erasure).0),
                });
                // Re-entry can run inside the upkeep that received the
                // welcome. Hand the new request over here, before that
                // upkeep returns to its next administration pass.
                #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
                Box::pin(self.administer(space)).await;
            }
            Ok(Some(Refetched::SlotHeld {
                holding,
                same_device,
            })) => {
                self.report(Event::SlotHeld {
                    space: SpaceId::of(space),
                    holding: super::ChangeId::from_bytes(holding.0),
                    holder: if same_device {
                        "another installation of this device"
                    } else {
                        "another device"
                    }
                    .into(),
                    erasure_waiting: true,
                    peer: None,
                });
            }
            Ok(Some(Refetched::Void)) => {
                self.report(Event::ErasureVoid {
                    space: SpaceId::of(space),
                });
            }
            Ok(None) | Err(_) => {}
        }
    }

    /// Asks the connected peers again about a retained erasure now.
    ///
    /// # Errors
    /// `UnknownSpace` unless this device retains an erasure residue; the store's.
    pub async fn retry_erasure(&self, space: SpaceId) -> Result<()> {
        if !self.engine().erasing().await.contains(&space.event()) {
            return Err(Error::UnknownSpace);
        }
        self.finish_erasure_with(space.event(), true).await
    }

    /// Gives up a space this device dropped for its own erasure (peers.md,
    /// 3.16, "A device's own erasure"): it no longer waits for each peer to
    /// answer `erased`, nor fetches the space again after a checkpoint that
    /// made the erasure late, and forgets what it kept of the space. The
    /// space may live on at the peers that did not answer.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`](crate::Error::UnknownSpace) for a space this
    /// device did not drop for its own erasure; the store's.
    pub async fn give_up_space(&self, space: SpaceId) -> Result<()> {
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        let _one = self.inner.receiving.lock().await;
        self.engine().give_up_erasure(&space.event()).await
    }

    /// Tells the device that the peer at `peer` served, instead of
    /// `erased`, a checkpoint that makes its erasure of a space it dropped
    /// late (peers.md, 3.16, "A device's own erasure"). The application is
    /// told at once ([`Event::ErasureLateAtPeer`]), and the device fetches
    /// the space again as a replica that lost its store does, from a
    /// member's space snapshot ([`Engine::adopt_snapshot`]); once it holds
    /// the checkpoint, it signs the erasure again after it if it still
    /// administers the space with a usable slot, reports a held slot
    /// ([`Event::SlotHeld`]), or reports the erasure void
    /// ([`Event::ErasureVoid`]). The application may give the space up
    /// instead ([`Self::give_up_space`]).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`](crate::Error::UnknownSpace) for a space this
    /// device did not drop for its own erasure.
    ///
    /// [`Engine::adopt_snapshot`]: crate::advanced::Engine::adopt_snapshot
    pub async fn erasure_late_at(&self, space: SpaceId, peer: &str) -> Result<()> {
        let engine = self.engine();
        let id = space.event();
        if engine.erasure_late_at(&id, peer).await {
            self.report(Event::ErasureLateAtPeer {
                space,
                peer: peer.to_owned(),
            });
        }
        let requests = engine.erasure_welcome_requests(&id).await?;
        #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
        for target in self.peers_of(&id) {
            for (address, sealed) in &requests {
                let _ = self
                    .deposit(target.url(), *address, sealed.clone(), true)
                    .await;
            }
        }
        let _ = requests;
        self.report(Event::ErasureAwaitingWelcome { space });
        Ok(())
    }
}
