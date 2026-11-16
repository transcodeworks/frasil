//! A space a peer handed over to another peer (peers.md, "Hosting a space"
//! and "Refusal codes"): the device looks for it among the peers it knows
//! for the space, the home peer first and then the peer hints
//! (ext-libraries.md, "The home peer"; admission.md, "The welcome"), and
//! syncs where one hosts it. Only when every one of them answered, and none
//! hosts it, is the move the application's to resolve:
//! [`Event::Moved`](super::Event::Moved).
//!
//! A hint comes from another member's welcome, or from a peer that granted
//! the space once, and `moved` from any peer, so a peer the device reaches
//! only by a hint learns of that one space alone: the device opens a
//! connection of its own to it that presents only that space, as for
//! spaces kept apart (transport.md, 3.11 Presenting credentials), takes
//! nothing from its discovery document, and closes it when it does not
//! grant the space in time.
//!
//! Every peer that grants the device a space becomes one of the space's
//! hints. A peer that answers `moved` goes last among them: the space may
//! come back to it.

use super::{Device, Peer, Space, SpaceId};
use crate::error::Result;
use crate::hints::same_peer;
use frasil_events::EventId;
use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// How long the device waits for a peer it tries to grant or refuse the
/// space, its connection included.
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// How often it looks at that peer's answer.
const LOOK_EVERY: Duration = Duration::from_millis(100);
/// The waits before each further round over the space's peers, while one
/// refuses it for another reason than `moved` or cannot be reached: a
/// peer the space is being handed over to may host it seconds later.
const ROUNDS: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

/// The wait before the device looks for a space again whose peers it could
/// not all reach, doubled after each look that reaches them no better, to
/// at most [`RETRY_CAP`].
const RETRY_FIRST: Duration = Duration::from_secs(5);
/// The longest such wait.
const RETRY_CAP: Duration = Duration::from_secs(120);

/// The refusal code of a space handed over (peers.md, "Refusal codes").
fn moved_code() -> &'static str {
    frasil_peers::Code::Moved.name()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a device does about spaces handed over, while it is open.
#[derive(Debug, Default)]
pub(super) struct Moves {
    /// Spaces it is looking for now.
    following: Mutex<BTreeSet<EventId>>,
    /// Each space's `moved` answers it acted on, by peer URL, until that
    /// peer grants the space again.
    answered: Mutex<Vec<(EventId, String)>>,
    /// The peers it keeps as each space's hints since it opened, so that
    /// each is written once.
    kept: Mutex<Vec<(EventId, String)>>,
    /// The connections it opened to follow one space, each presenting that
    /// space alone.
    scoped: Mutex<Vec<(EventId, Peer)>>,
}

impl Moves {
    /// The open connections opened for `space` alone.
    pub(super) fn scoped_to(&self, space: &EventId) -> Vec<Peer> {
        lock(&self.scoped)
            .iter()
            .filter(|(of, peer)| of == space && peer.status().closed.is_none())
            .map(|(_, peer)| peer.clone())
            .collect()
    }

    /// Every connection opened for one space alone.
    pub(super) fn all_scoped(&self) -> Vec<Peer> {
        lock(&self.scoped)
            .iter()
            .map(|(_, peer)| peer.clone())
            .collect()
    }
}

/// Looks after spaces handed over every [`upkeep_every`](super::upkeep_every)
/// while the device is open, apart from the upkeep, which waits on its
/// peers' answers.
pub(super) fn start(inner: &std::sync::Arc<super::Inner>) {
    let weak = std::sync::Arc::downgrade(inner);
    inner.tasks.spawn(Box::pin(async move {
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let device = Device { inner };
            if device.is_closed() {
                return;
            }
            device.look_after_moves().await;
            let sleep = device.sleep(super::upkeep_every());
            drop(device);
            sleep.await;
        }
    }));
}

impl Space {
    /// Keeps the home peer of the space's library, as the URL of its
    /// origin, such as `https://peer.example`: what the library's issuer
    /// returns beside the ticket (ext-libraries.md, "The home peer"), and
    /// after a move the new home it names. The device names it first in
    /// each welcome it signs for the space, and tries it first when a peer
    /// answers that it handed the space over; when no open connection
    /// syncs the space, it syncs there now. It survives a restart.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`](crate::Error::Invalid) for a URL that is not an
    /// origin's: `https`, with no path, query or credentials (plain `http`
    /// only on loopback); the store's.
    #[cfg(feature = "ext-libraries")]
    pub async fn set_home_peer(&self, url: &str) -> Result<()> {
        if !crate::hints::is_peer_url(url) {
            return Err(crate::error::Error::Invalid(
                "not the URL of a peer's origin",
            ));
        }
        let space = self.id().event();
        self.device.engine().keep_home_peer(&space, url).await?;
        lock(&self.device.inner.reported).remove(&space);
        if !self.device.synced_anywhere(&space) {
            self.device.follow(space);
        }
        Ok(())
    }

    /// The always-on peers the device knows for the space, as origins'
    /// URLs, in the order it tries them: the home peer first, then the
    /// peer hints its welcome named and the peers that granted it the
    /// space, at most 8 (admission.md, "The welcome"); a peer that
    /// answered that it handed the space over comes last.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn known_peers(&self) -> Result<Vec<String>> {
        let kept = self.device.engine().kept_peers(&self.id().event()).await?;
        Ok(kept.ordered())
    }
}

/// How looking for a space ended.
enum Looked {
    /// A connection syncs it, or the device closed.
    Found,
    /// Every peer it knows answered, and none hosts it.
    Report,
    /// A peer could not be reached, or refused it for another reason than
    /// `moved`: looked for again later.
    Unsettled,
}

/// What a peer the device tries answered for the space.
enum Answer {
    /// It grants the space.
    Granted,
    /// It refused the space, with this code.
    Refused(String),
    /// It did not answer in time, or could not be reached.
    Unreachable,
}

impl Device {
    /// Keeps each peer that grants a space as one of its hints, notes the
    /// peers that grant each space now for the welcomes the device signs,
    /// and follows each space a peer has just answered `moved` for that no
    /// open connection syncs.
    pub(super) async fn look_after_moves(&self) {
        let code = moved_code();
        lock(&self.inner.moves.scoped).retain(|(_, peer)| peer.status().closed.is_none());
        let connections: Vec<Peer> = self
            .peers()
            .into_iter()
            .chain(self.inner.moves.all_scoped())
            .collect();
        let mut granting = Vec::new();
        let mut moved = BTreeSet::new();
        for peer in &connections {
            let status = peer.status();
            if status.connected {
                for space in &status.spaces {
                    granting.push((space.event(), peer.url().to_owned()));
                }
            }
            for (space, refused) in &status.refused {
                if refused == code && self.answered(space.event(), peer.url()) {
                    let _ = self.engine().demote_peer(&space.event(), peer.url()).await;
                    moved.insert(space.event());
                }
            }
        }
        self.engine().set_syncing(granting.clone());
        for (space, url) in granting {
            lock(&self.inner.reported).remove(&space);
            lock(&self.inner.moves.answered)
                .retain(|(of, by)| *of != space || !same_peer(by, &url));
            self.keep_hint(space, &url).await;
        }
        for space in moved {
            if !self.synced_anywhere(&space) {
                self.follow(space);
            }
        }
    }

    /// Notes a `moved` answer of the peer at `url` for `space`: whether it
    /// is a new one.
    fn answered(&self, space: EventId, url: &str) -> bool {
        let mut answered = lock(&self.inner.moves.answered);
        if answered
            .iter()
            .any(|(of, by)| *of == space && same_peer(by, url))
        {
            return false;
        }
        answered.push((space, url.to_owned()));
        true
    }

    /// Keeps `url` as a hint of `space`, once while the device is open.
    async fn keep_hint(&self, space: EventId, url: &str) {
        let fresh = {
            let mut kept = lock(&self.inner.moves.kept);
            let fresh = !kept
                .iter()
                .any(|(of, by)| *of == space && same_peer(by, url));
            if fresh {
                kept.push((space, url.to_owned()));
            }
            fresh
        };
        if fresh {
            let _ = self
                .engine()
                .keep_peer_hints(&space, &[url.to_owned()])
                .await;
        }
    }

    /// Whether an open connection syncs the space.
    fn synced_anywhere(&self, space: &EventId) -> bool {
        let id = SpaceId::of(*space);
        self.peers_of(space).iter().any(|peer| {
            let status = peer.status();
            status.connected && status.spaces.contains(&id)
        })
    }

    /// Looks for a space handed over in the background, unless the device
    /// is already looking or reported it.
    fn follow(&self, space: EventId) {
        let moves = &self.inner.moves;
        if lock(&self.inner.reported).contains(&space) || !lock(&moves.following).insert(space) {
            return;
        }
        let weak = std::sync::Arc::downgrade(&self.inner);
        self.spawn(Box::pin(async move {
            // A space whose peers could not all be reached is looked for
            // again, ever more slowly: no other `moved` may come to start
            // it. The wait holds the device only weakly, so that one
            // dropped meanwhile ends it.
            let mut retry = RETRY_FIRST;
            loop {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                let device = Device { inner };
                let report = match device.find_moved(space).await {
                    Looked::Found => false,
                    Looked::Report => true,
                    Looked::Unsettled if !device.is_closed() => {
                        let sleep = device.sleep(retry);
                        drop(device);
                        sleep.await;
                        retry = (retry * 2).min(RETRY_CAP);
                        continue;
                    }
                    Looked::Unsettled => false,
                };
                lock(&device.inner.moves.following).remove(&space);
                if report && !device.is_closed() && lock(&device.inner.reported).insert(space) {
                    let _ = device.inner.moved.send(space);
                }
                return;
            }
        }));
    }

    /// Tries the space's peers in turn, the home peer first, until one
    /// syncs it, in rounds while one refuses it for another reason than
    /// `moved` or cannot be reached. A peer that answered `moved`, on an
    /// open connection or in an earlier round, is not asked again.
    async fn find_moved(&self, space: EventId) -> Looked {
        let mut waits = ROUNDS.iter();
        let mut moved_at = self.answered_moved(space);
        loop {
            if self.is_closed() || self.synced_anywhere(&space) {
                return Looked::Found;
            }
            let Ok(kept) = self.engine().kept_peers(&space).await else {
                return Looked::Found;
            };
            let mut settled = true;
            for url in kept.ordered() {
                if self.is_closed() || self.synced_anywhere(&space) {
                    return Looked::Found;
                }
                if moved_at.iter().any(|by| same_peer(by, &url)) {
                    continue;
                }
                match self.try_peer(space, &url).await {
                    Answer::Granted => {
                        self.keep_hint(space, &url).await;
                        return Looked::Found;
                    }
                    Answer::Refused(code) if code == moved_code() => {
                        self.answered(space, &url);
                        let _ = self.engine().demote_peer(&space, &url).await;
                        moved_at.push(url);
                    }
                    Answer::Refused(_) | Answer::Unreachable => settled = false,
                }
            }
            match waits.next() {
                _ if settled => return Looked::Report,
                Some(wait) => self.sleep(*wait).await,
                None => return Looked::Unsettled,
            }
        }
    }

    /// The peers whose open connection refused the space `moved`.
    fn answered_moved(&self, space: EventId) -> Vec<String> {
        let (id, code) = (SpaceId::of(space), moved_code());
        self.peers()
            .into_iter()
            .chain(self.inner.moves.scoped_to(&space))
            .filter(|peer| {
                let status = peer.status();
                status.closed.is_none()
                    && status
                        .refused
                        .iter()
                        .any(|(of, refused)| *of == id && refused == code)
            })
            .map(|peer| peer.url().to_owned())
            .collect()
    }

    /// Presents the space to the peer at `url`: on an open connection the
    /// application made to it that has not refused the space, else on a
    /// connection of the device's own that presents that space alone,
    /// kept while it grants the space and closed otherwise.
    async fn try_peer(&self, space: EventId, url: &str) -> Answer {
        let id = SpaceId::of(space);
        let open = self.peers().into_iter().find(|peer| {
            let status = peer.status();
            same_peer(peer.url(), url)
                && status.closed.is_none()
                && !status.refused.iter().any(|(s, _)| *s == id)
        });
        if let Some(peer) = open {
            peer.present(space);
            return self.answer_of(&peer, id).await;
        }
        let Some(peer) = self.open_scoped(space, url).await else {
            return Answer::Unreachable;
        };
        let answer = self.answer_of(&peer, id).await;
        if matches!(answer, Answer::Granted) {
            lock(&self.inner.moves.scoped).push((space, peer));
        } else {
            peer.close();
        }
        answer
    }

    /// A connection to `url` that presents `space` alone, only to find out
    /// whether the peer hosts it, within [`ANSWER_WAIT`]. The connection runs to its end on a task of its
    /// own, so that one that opens too late is closed rather than left
    /// running.
    async fn open_scoped(&self, space: EventId, url: &str) -> Option<Peer> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (device, url) = (self.clone(), url.to_owned());
        self.spawn(Box::pin(async move {
            if let Ok(peer) = device.open_connection(&url, Vec::new()).await {
                peer.seek(space);
                if let Err(peer) = tx.send(peer) {
                    peer.close();
                }
            }
        }));
        let wait = self.sleep(ANSWER_WAIT);
        tokio::select! {
            opened = rx => opened.ok(),
            () = wait => None,
        }
    }

    /// What a connection answers the space within [`ANSWER_WAIT`]: a
    /// connection that is connecting again has not answered.
    async fn answer_of(&self, peer: &Peer, id: SpaceId) -> Answer {
        let mut waited = Duration::ZERO;
        loop {
            let status = peer.status();
            if status.connected && status.spaces.contains(&id) {
                return Answer::Granted;
            }
            if let Some((_, code)) = status.refused.iter().find(|(s, _)| *s == id) {
                return Answer::Refused(code.clone());
            }
            if status.closed.is_some() || waited >= ANSWER_WAIT {
                return Answer::Unreachable;
            }
            self.sleep(LOOK_EVERY).await;
            waited += LOOK_EVERY;
        }
    }
}
