//! Connections to always-on peers, by URL.

use super::SpaceId;
use crate::device::Engine;
use crate::error::Result;
use crate::peer::PeerHandle;
use frasil_events::EventId;
use frasil_store::BoxFuture;
use frasil_store::store::{MaybeSend, MaybeSync};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

/// Opens a device's connection to a peer by URL, for a platform where this
/// crate opens no socket of its own: a browser's, through `frasil-wasm`.
pub trait Connect: MaybeSend + MaybeSync {
    /// Connects `engine` to the peer at `url`, presenting `spaces`, and
    /// returns once the handshake has completed.
    fn connect(
        &self,
        engine: Engine,
        url: String,
        spaces: Vec<EventId>,
    ) -> BoxFuture<'static, Result<PeerHandle>>;

    /// Stores `engine`'s own skeleton events of `space` at the peer at
    /// `url` over a fresh administration connection (peers.md,
    /// "Administration connections"), such as
    /// [`administer_socket`](crate::advanced::peer::socket::administer_socket)
    /// over a socket of its own, and closes it once the peer has
    /// acknowledged them. A connector that reads the wire itself passes a
    /// late answer to [`Engine::receive_erasure_late`]. Returns whether
    /// anything was stored. Without it,
    /// the device's skeleton events, an erasure among them, never reach its
    /// peers.
    fn administer(
        &self,
        engine: Engine,
        url: String,
        space: EventId,
    ) -> BoxFuture<'static, Result<bool>> {
        let _ = (engine, url, space);
        Box::pin(async {
            Err(crate::error::Error::Unsupported(
                "this connector opens no administration connection",
            ))
        })
    }

    /// Opens a connection of its own to the peer at `url` that presents
    /// nothing, as an administration connection is opened (a fresh
    /// transport, no cookie, no session resumed), such as
    /// [`bare_socket`](crate::advanced::peer::socket::bare_socket) over a
    /// socket of its own. The device deposits in device mailboxes on it,
    /// asks for and spends deposit tokens (ext-deposit-tokens.md, 3.2 and
    /// 3.6), and keeps one per peer to collect its own device mailbox.
    /// Without it, the device draws no tokens, its deposits in device
    /// mailboxes are undelivered (`unsupported`), and it collects no
    /// welcome or list events from its mailbox: a deposit names its
    /// recipient and a collection names the device, so neither rides the
    /// connection that presents the device's spaces (transport.md, 3.12
    /// What a peer learns of a device).
    fn bare(&self, engine: Engine, url: String) -> BoxFuture<'static, Result<crate::peer::Bare>> {
        let _ = (engine, url);
        Box::pin(async {
            Err(crate::error::Error::Unsupported(
                "this connector opens no connection of the device's own",
            ))
        })
    }
}

/// A connection of the device's own to the peer at `url` that presents
/// nothing: through the application's connector when it has one, else
/// over the server binding where this build has it.
#[cfg_attr(not(feature = "server"), allow(unused_variables))]
pub(super) async fn bare(
    engine: &Engine,
    connect: Option<&Arc<dyn Connect>>,
    url: &str,
) -> Result<crate::peer::Bare> {
    if let Some(connect) = connect {
        return connect.bare(engine.clone(), url.to_owned()).await;
    }
    #[cfg(feature = "server")]
    {
        crate::peer::bare_server(engine, url).await
    }
    #[cfg(not(feature = "server"))]
    {
        Err(crate::error::Error::Unsupported(
            "a connection of the device's own needs the `server` feature, or Options::connect_with",
        ))
    }
}

/// Stores the device's own skeleton events of `space` at the peer at
/// `url` over a fresh administration connection: through the
/// application's connector when it has one, else over the server binding
/// where this build has it.
#[cfg_attr(not(feature = "server"), allow(unused_variables))]
pub(super) async fn administer(
    engine: &Engine,
    connect: Option<&Arc<dyn Connect>>,
    url: &str,
    space: EventId,
) -> Result<bool> {
    if let Some(connect) = connect {
        return connect
            .administer(engine.clone(), url.to_owned(), space)
            .await;
    }
    #[cfg(feature = "server")]
    {
        crate::peer::administer_server(engine, url, space).await
    }
    #[cfg(not(feature = "server"))]
    {
        Err(crate::error::Error::Unsupported(
            "an administration connection needs the `server` feature, or Options::connect_with",
        ))
    }
}

/// How long the device waits for a peer to take a cut's record object.
const RECORD_UPLOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

impl super::Device {
    /// Uploads to `peer` the record objects of this device's own skeleton
    /// cuts of `space` that no peer has acknowledged, and waits, for at
    /// most [`RECORD_UPLOAD_WAIT`], until the peer holds each. Returns
    /// whether it holds them all.
    async fn upload_cut_records(&self, peer: &Peer, space: EventId) -> bool {
        use tokio::sync::oneshot::error::TryRecvError;
        const POLL: std::time::Duration = std::time::Duration::from_millis(50);
        let mut answers: Vec<_> = self
            .engine()
            .pending_cut_records(&space)
            .await
            .into_iter()
            .map(|locator| peer.handle().upload(space, locator))
            .collect();
        let mut waited = std::time::Duration::ZERO;
        loop {
            let mut open = Vec::new();
            for mut answer in answers {
                match answer.try_recv() {
                    Ok(true) => {}
                    Ok(false) | Err(TryRecvError::Closed) => return false,
                    Err(TryRecvError::Empty) => open.push(answer),
                }
            }
            if open.is_empty() {
                return true;
            }
            if waited >= RECORD_UPLOAD_WAIT {
                return false;
            }
            answers = open;
            self.sleep(POLL).await;
            waited += POLL;
        }
    }

    /// Stores this device's own skeleton events of `space` at each
    /// connected peer that may carry the space, over administration
    /// connections of their own (peers.md, "Administration connections"),
    /// then offers the space's unacknowledged events again on that peer's
    /// connection: a roster event that changes who administers cites its
    /// twin, so the peer acknowledges it only once it holds the twin
    /// (peers.md, "The skeleton").
    pub(super) async fn administer(&self, space: EventId) {
        let _one = self.inner.administering.lock().await;
        let engine = self.engine();
        for peer in self.peers_of(&space) {
            if !peer.status().connected || !engine.skeleton_pending(&space).await {
                continue;
            }
            // The record object a pending skeleton cut names reaches the
            // peer before the cut, on the space's own connection, which
            // holds the store right (roster.md, "The record object"); until
            // the peer holds it, the cut waits for the next attempt.
            if !self.upload_cut_records(&peer, space).await {
                continue;
            }
            match administer(engine, self.inner.connect.as_ref(), peer.url(), space).await {
                Ok(true) => peer.handle().reoffer(space),
                Err(crate::Error::Class("extension_required")) => {
                    self.report(super::Event::PeerNeedsVersion {
                        space: SpaceId::of(space),
                        peer: peer.url().to_owned(),
                    })
                }
                Err(error) if crate::peer::refused_as_erased(&error) => {
                    engine.note_erased_at_peer(space);
                }
                _ => {}
            }
        }
    }
}

/// Connects over the server binding's WebSocket, where this build has it.
#[cfg_attr(not(feature = "server"), allow(unused_variables))]
pub(super) async fn connect_default(
    engine: &Engine,
    url: &str,
    spaces: Vec<EventId>,
) -> Result<PeerHandle> {
    #[cfg(feature = "server")]
    {
        crate::peer::connect_server(engine, url, spaces).await
    }
    #[cfg(not(feature = "server"))]
    {
        Err(crate::error::Error::Unsupported(
            "connecting by URL needs the `server` feature, or Options::connect_with",
        ))
    }
}

/// The iroh relays the peer at `url`, an origin, names in its discovery
/// document (transport.md, "The server binding"): 1 to 4 `https` URLs, or
/// plain `http` on loopback for tests. None when the document does not
/// arrive or names none that pass. Discovery is a hint; a relay carries the
/// member handshake end to end, so a wrong one costs only reachability.
#[cfg(all(feature = "iroh", feature = "server"))]
pub(super) async fn discovery_relays(url: &str) -> Option<Vec<String>> {
    let url = format!(
        "{}{}",
        url.trim_end_matches('/'),
        frasil_transport::peer::DISCOVERY_PATH
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = response.bytes().await.ok()?;
    let document: serde_json::Value = serde_json::from_slice(&body).ok()?;
    let relays: Vec<String> = document
        .get("relays")?
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .filter(|relay| is_relay(relay))
        .take(frasil_iroh::endpoint::TICKET_RELAYS)
        .map(str::to_owned)
        .collect();
    (!relays.is_empty()).then_some(relays)
}

/// An `https` URL with no credentials, query or fragment, or one over
/// plain `http` on loopback.
#[cfg(all(feature = "iroh", feature = "server"))]
fn is_relay(url: &str) -> bool {
    let rest = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or_default();
        if !matches!(host, "127.0.0.1" | "localhost") && !rest.starts_with("[::1]") {
            return false;
        }
        rest
    } else {
        return false;
    };
    !rest.is_empty() && !rest.contains(['?', '#', '@']) && url.len() <= 2048
}

struct Link {
    url: String,
    handle: PeerHandle,
    presented: Mutex<BTreeSet<EventId>>,
    /// The last item collected from this device's own device mailbox.
    collected: Mutex<Option<[u8; 16]>>,
    versions_reported: Mutex<BTreeSet<EventId>>,
}

/// A connection to an always-on peer. Clones share it.
#[derive(Clone)]
pub struct Peer {
    link: Arc<Link>,
}

impl core::fmt::Debug for Peer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Peer")
            .field("url", &self.link.url)
            .finish_non_exhaustive()
    }
}

/// What a peer connection has done, for an application to show.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerStatus {
    /// Whether the connection runs.
    pub connected: bool,
    /// Whether it is connecting again because the peer asked it to, such
    /// as to move it to another of its machines (transport.md,
    /// "Reconnecting elsewhere"). That is no error: the connection goes on
    /// once connected.
    pub reconnecting: bool,
    /// How many times it has connected again so.
    pub reconnects: u64,
    /// Why it ended, once it has.
    pub closed: Option<String>,
    /// Whether it ended because the peer runs another protocol
    /// revision ([`crate::Error::OtherRevision`]).
    pub other_revision: bool,
    /// The spaces the peer keeps and syncs on this connection.
    pub spaces: Vec<SpaceId>,
    /// Spaces the peer refused, with its reason code. A space refused
    /// `moved` was handed over to another peer, and is no longer presented
    /// on this connection (peers.md, "Refusal codes").
    pub refused: Vec<(SpaceId, String)>,
    /// How many of this device's changes the peer refused to keep. They
    /// stay unacknowledged, and are offered again.
    pub refused_changes: usize,
    /// How many fetch keys the peer registered as recovery entries on this
    /// connection: a recovery sheet or a passkey reaches the spaces they
    /// serve through this peer.
    pub recovery_entries: usize,
    /// Spaces in which the peer served less than this device knows of
    /// (`Withheld`, units.md, 3.13 "Detected loss"), since the device
    /// opened. The device fetches what it lacks from other replicas.
    pub withheld: Vec<SpaceId>,
    /// Spaces in which the peer no longer held events it acknowledged
    /// (`RolledBack`), since the device opened. This device's own events
    /// among them count as not durable again, and are offered again.
    pub rolled_back: Vec<SpaceId>,
}

impl Peer {
    pub(super) fn new(url: &str, handle: PeerHandle, presented: Vec<EventId>) -> Self {
        Self {
            link: Arc::new(Link {
                url: url.to_owned(),
                handle,
                presented: Mutex::new(presented.into_iter().collect()),
                collected: Mutex::new(None),
                versions_reported: Mutex::new(BTreeSet::new()),
            }),
        }
    }

    pub(super) fn report_versions(&self, device: &super::Device) {
        let status = self.link.handle.status();
        let mut reported = self
            .link
            .versions_reported
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for (space, _, code) in status.refused_events {
            if code == "extension_required" && reported.insert(space) {
                device.report(super::Event::PeerNeedsVersion {
                    space: SpaceId::of(space),
                    peer: self.url().to_owned(),
                });
            }
        }
    }

    /// The URL the device connected to.
    pub fn url(&self) -> &str {
        &self.link.url
    }

    /// What the connection has done so far.
    pub fn status(&self) -> PeerStatus {
        let raw = self.link.handle.status();
        PeerStatus {
            connected: raw.closed.is_none() && !raw.reconnecting,
            reconnecting: raw.reconnecting,
            reconnects: raw.reconnects,
            other_revision: raw
                .closed
                .as_deref()
                .is_some_and(crate::peer::is_other_revision),
            closed: raw.closed,
            spaces: raw.granted.keys().map(|id| SpaceId::of(*id)).collect(),
            refused: raw
                .refused
                .into_iter()
                .map(|(id, code)| (SpaceId::of(id), code))
                .collect(),
            refused_changes: raw.refused_events.len(),
            recovery_entries: raw.registered.len(),
            withheld: raw
                .withheld
                .iter()
                .map(|(space, _)| *space)
                .chain(
                    raw.lost
                        .iter()
                        .filter(|(_, class)| *class == crate::outbox::LossClass::Withheld)
                        .map(|(space, _)| *space),
                )
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .map(SpaceId::of)
                .collect(),
            rolled_back: raw
                .lost
                .iter()
                .filter(|(_, class)| *class == crate::outbox::LossClass::RolledBack)
                .map(|(space, _)| SpaceId::of(*space))
                .collect(),
        }
    }

    /// Closes the connection. One that is attaching a space to a library
    /// ends once that is done, 5 seconds later at most (ext-libraries.md,
    /// 3.3 Attaching).
    pub fn close(&self) {
        self.link.handle.close();
    }

    /// The connection underneath.
    pub(super) fn handle(&self) -> &PeerHandle {
        &self.link.handle
    }

    /// The last item collected from this device's own device mailbox.
    pub(super) fn collected(&self) -> Option<[u8; 16]> {
        *self
            .link
            .collected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Records the last item collected from this device's own device
    /// mailbox.
    pub(super) fn set_collected(&self, id: [u8; 16]) {
        *self
            .link
            .collected
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(id);
    }

    /// Presents a space on the connection, once, only to find out whether
    /// the peer hosts it ([`PeerHandle::seek`]).
    pub(super) fn seek(&self, space: EventId) {
        let fresh = self
            .link
            .presented
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(space);
        if fresh {
            self.link.handle.seek(space);
        }
    }

    /// Offers again, in each space the connection may store in, the blobs
    /// this device put that no peer is known to hold (at-rest.md,
    /// "Retention", an object the device put).
    pub(super) fn offer_puts(&self) {
        let status = self.link.handle.status();
        if status.closed.is_some() {
            return;
        }
        for (space, rights) in &status.granted {
            if rights.contains(&frasil_transport::codes::Right::Store) {
                self.link.handle.offer_puts(*space);
            }
        }
    }

    /// Presents a space on the connection, once.
    pub(super) fn present(&self, space: EventId) {
        let fresh = self
            .link
            .presented
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(space);
        if fresh {
            self.link.handle.attach(space);
        }
    }
}
