//! A device's arrivals: each space and each stream it holds for the first
//! time, from the moment they were asked for. They serve a wait for a whole
//! space, such as one a grant is about to bring, and for a stream whose ID
//! is not known in advance.

use super::{Device, SpaceId, StreamId};
use crate::device::{Engine, Notice};
use frasil_events::EventId;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use tokio::sync::broadcast::{self, error::RecvError};

/// Something a device holds for the first time, from [`Arrivals::next`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Arrival {
    /// A space: the device holds its first events. Its streams follow,
    /// each as an [`Arrival::Stream`].
    Space(SpaceId),
    /// A stream of a space: the device holds its first change.
    Stream {
        /// The space.
        space: SpaceId,
        /// The stream.
        stream: StreamId,
    },
}

/// A device's arrivals, from the moment they were asked for: each space and
/// stream it did not hold then, once. A holder that falls behind loses
/// nothing: it compares what the device holds again.
#[derive(Debug)]
pub struct Arrivals {
    engine: Engine,
    notices: broadcast::Receiver<Notice>,
    /// What the device held, by space: the streams.
    held: BTreeMap<EventId, BTreeSet<[u8; 16]>>,
    queued: VecDeque<Arrival>,
}

impl Device {
    /// The device's arrivals from now on: each space and each stream it
    /// holds for the first time.
    pub async fn arrivals(&self) -> Arrivals {
        let engine = self.engine().clone();
        let notices = engine.subscribe();
        let mut held = BTreeMap::new();
        for space in engine.spaces().await {
            held.insert(space, streams(&engine, &space).await);
        }
        Arrivals {
            engine,
            notices,
            held,
            queued: VecDeque::new(),
        }
    }
}

/// The streams the device holds of a space.
async fn streams(engine: &Engine, space: &EventId) -> BTreeSet<[u8; 16]> {
    engine
        .read(space, |replica| {
            replica
                .streams()
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>()
        })
        .await
        .unwrap_or_default()
}

impl Arrivals {
    /// The next arrival; `None` once the device is gone.
    pub async fn next(&mut self) -> Option<Arrival> {
        loop {
            if let Some(arrival) = self.queued.pop_front() {
                return Some(arrival);
            }
            match self.notices.recv().await {
                Ok(notice) => self.compare(notice.space).await,
                Err(RecvError::Lagged(_)) => {
                    for space in self.engine.spaces().await {
                        self.compare(space).await;
                    }
                }
                Err(RecvError::Closed) => return None,
            }
        }
    }

    /// Queues what the device holds of a space that it did not before.
    async fn compare(&mut self, space: EventId) {
        if !self.engine.spaces().await.contains(&space) {
            return;
        }
        let now = streams(&self.engine, &space).await;
        let before = match self.held.get(&space) {
            Some(before) => before,
            None => {
                self.queued.push_back(Arrival::Space(SpaceId::of(space)));
                &BTreeSet::new()
            }
        };
        for stream in now.difference(before) {
            self.queued.push_back(Arrival::Stream {
                space: SpaceId::of(space),
                stream: StreamId::from_bytes(*stream),
            });
        }
        self.held.insert(space, now);
    }
}
