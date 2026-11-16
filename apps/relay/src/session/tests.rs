//! What a connection can make the peer do or hold, before or without the
//! credential its message needs: object uploads and their staging, the
//! skeleton's resolution, a stranger's messages, an administration
//! connection, and sync answers served in batches. The space is
//! `peers.json`'s `credentials` history, whose credentials the reference
//! derives from `example("storage/credentials/<rotation>/...")`.

use super::*;
use crate::blobs::MemoryBlobs;
use crate::clock::{Clock, ManualClock};
use crate::config::Settings;
use crate::objects::Layout;
use crate::state::lock;
use frasil_crypto::device::DeviceId;
use frasil_crypto::primitives::sha256;
use frasil_keys::derive::{read_credential, upload_key};
use frasil_peers::proof::Credential;
use frasil_store::MemoryStore;
use frasil_transport::frame::MessageType;
use frasil_transport::peer::{DeviceSide, server_channel};
use frasil_units::limits::{CHUNK_BYTES, SEALED_CHUNK_BYTES};
use serde_json::Value as Json;

fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// The genesis's read credential's seed.
pub(crate) fn read_seed() -> [u8; 32] {
    *read_credential(&example("storage/credentials/genesis/content-key")).seed
}

/// The genesis's upload key's seed.
pub(crate) fn upload_seed() -> [u8; 32] {
    *upload_key(&example("storage/credentials/genesis/upload-seed")).seed
}

/// The `credentials` history's events, by name, in order.
pub(crate) fn history() -> Vec<(String, Vec<u8>)> {
    frasil_testkit::vectors::family::<Json>("peers.json", "credentials")["events"]
        .as_array()
        .expect("an events list")
        .iter()
        .map(|row| {
            (
                row["name"].as_str().unwrap().to_owned(),
                frasil_testkit::hex::decode(row["signed"].as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

pub(crate) fn id_of(signed: &[u8]) -> EventId {
    frasil_events::decode(signed).unwrap().id()
}

/// A peer on memory, its clock at [`crate::testing::START`].
pub(crate) fn open(settings: Settings) -> (Arc<Shared>, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(crate::testing::START));
    let peer = crate::Peer::open(
        settings,
        Arc::new(MemoryStore::new()),
        Arc::new(MemoryBlobs::new()),
        clock.clone(),
    )
    .unwrap();
    (peer.shared.clone(), clock)
}

/// A device's connection on the server binding, through its session.
pub(crate) struct Client {
    pub(crate) session: Session,
    pub(crate) rx: mpsc::Receiver<Outgoing>,
    pub(crate) device: DeviceSide,
    pub(crate) requests: u64,
}

impl Client {
    /// A connection from `source`, its `Hello` sent with `purpose`.
    pub(crate) async fn connect(shared: &Arc<Shared>, purpose: Purpose, source: &str) -> Self {
        let channel = server_channel("http://peer.test");
        let (mut session, hello, rx) =
            Session::start(shared.clone(), channel, true, source.to_owned()).unwrap();
        let extensions = shared.settings.extensions;
        let peer_hello = crate::server::read(&hello, extensions).unwrap().unwrap();
        let nonce = *frasil_crypto::random_bytes::<32>().unwrap();
        let device = DeviceSide::answer_with(&channel, &peer_hello, nonce, purpose).unwrap();
        let answer = session
            .on_message(
                &crate::server::read(&device.hello, extensions)
                    .unwrap()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(answer.is_empty());
        Self {
            session,
            rx,
            device,
            requests: 0,
        }
    }

    /// Sends one message; what the peer answers at once and, after it,
    /// every batch of an answer it serves in batches.
    pub(crate) async fn send(&mut self, bytes: &[u8]) -> Result<Vec<Outgoing>, Failure> {
        let extensions = self.session.shared.settings.extensions;
        let message = crate::server::read(bytes, extensions)
            .map_err(Closed::of)?
            .expect("a message the peer reads");
        let mut out = self.session.on_message(&message).await?;
        while let Some(next) = self.session.next_answer().await {
            out.push(next);
        }
        Ok(out)
    }

    /// Presents a credential by its seed.
    pub(crate) async fn present(
        &mut self,
        space: EventId,
        credential: Credential,
        seed: &[u8; 32],
    ) -> Outgoing {
        self.requests += 1;
        let present = self
            .device
            .present(self.requests, space.as_bytes(), credential, seed);
        let mut out = self.send(&present).await.unwrap();
        assert_eq!(out.len(), 1);
        out.remove(0)
    }

    /// Presents an administrator pseudonym by device ID, its proof made
    /// with `seed`.
    pub(crate) async fn present_pseudonym(
        &mut self,
        space: EventId,
        pseudonym: &DeviceId,
        seed: &[u8; 32],
    ) -> Outgoing {
        self.requests += 1;
        let present =
            self.device
                .present_pseudonym(self.requests, space.as_bytes(), seed, pseudonym);
        let mut out = self.send(&present).await.unwrap();
        assert_eq!(out.len(), 1);
        out.remove(0)
    }

    /// Stores events in one `Events` message.
    pub(crate) async fn store(&mut self, space: EventId, events: &[Vec<u8>]) -> Vec<Outgoing> {
        let message = sync(
            space,
            UnitMessage::Events {
                events: events.to_vec(),
            },
        );
        self.send(&message).await.unwrap()
    }
}

/// The message type and, for a refusal, its code: `Refused`'s or
/// `EventRefused`'s.
pub(crate) fn answer_of(out: &Outgoing) -> (MessageType, Option<String>) {
    let (Outgoing::Control(bytes) | Outgoing::Sync(_, bytes)) = out else {
        panic!("not a message: {out:?}");
    };
    let message = crate::server::read(bytes, crate::Extensions::NONE)
        .unwrap()
        .unwrap();
    let code = match message.kind {
        MessageType::Refused => message.get(2).and_then(|v| v.as_text().ok()),
        MessageType::EventRefused => message.get(3).and_then(|v| v.as_text().ok()),
        _ => None,
    };
    (message.kind, code.map(str::to_owned))
}

/// Whether the peer acknowledged every event it was sent, refusing none.
pub(crate) fn acknowledged(out: &[Outgoing]) -> bool {
    !out.is_empty()
        && out
            .iter()
            .all(|out| matches!(out, Outgoing::Sync(..)) && answer_of(out).0 == MessageType::Sync)
}

/// A space created through a connection, and that connection with the
/// genesis's upload key proved.
pub(crate) async fn created(shared: &Arc<Shared>) -> (EventId, Client) {
    let events = history();
    let space = id_of(&events[0].1);
    let mut client = Client::connect(shared, Purpose::SpaceTraffic, "203.0.113.1").await;
    assert!(acknowledged(
        &client.store(space, &[events[0].1.clone()]).await
    ));
    let granted = client
        .present(space, Credential::Upload, &upload_seed())
        .await;
    assert_eq!(answer_of(&granted).0, MessageType::Granted);
    (space, client)
}

/// A stored object of `size` plaintext bytes: its locator and its stored
/// bytes, the header's length and the header, then sealed chunks the peer
/// does not open.
fn object(size: u64, id: u8) -> (Locator, Vec<u8>) {
    let header = frasil_units::objects::Header {
        object_id: [id; 32],
        key_reference: frasil_keys::RotationSet::single(EventId([1; 32])).encode(),
        size,
    }
    .encode();
    let mut stored = (header.len() as u32).to_be_bytes().to_vec();
    stored.extend_from_slice(&header);
    let mut named = [0u8; 64];
    named[..32].copy_from_slice(&[id; 32]);
    let layout = Layout::read(&stored, &named).unwrap();
    stored.resize(layout.total as usize, id);
    (
        frasil_transport::peer::object_locator(&[id; 32], &stored),
        stored,
    )
}

fn usage(shared: &Shared, space: EventId) -> u64 {
    shared
        .core
        .read_blocking(space, crate::space::Space::used)
        .unwrap()
}

/// Pieces uploaded before piece 0, at any index, are taken; piece 0 fixes
/// the object's length, and those past it go from the index, the object
/// store and the usage.
#[tokio::test(flavor = "multi_thread")]
async fn strays_past_an_objects_length_are_gone_and_uncounted() {
    let (shared, _clock) = open(Settings::open_core());
    let (space, _client) = created(&shared).await;
    let before = usage(&shared, space);
    let (locator, stored) = object(10, 7);
    assert!(stored.len() < PIECE_BYTES);
    let whole = vec![0u8; PIECE_BYTES];
    for index in [1, 2] {
        assert_eq!(
            store_piece(&shared, space, locator, index, whole.clone(), None).await,
            Ok(PieceOutcome::Stored(0))
        );
    }
    assert_eq!(usage(&shared, space), before + 2 * PIECE_BYTES as u64);
    assert_eq!(
        store_piece(&shared, space, locator, 0, stored.clone(), None).await,
        Ok(PieceOutcome::Stored(1))
    );
    let record = shared
        .core
        .read_blocking(space, |held| held.objects.get(&locator).cloned())
        .flatten()
        .unwrap();
    assert!(record.complete);
    assert_eq!(record.pieces.iter().copied().collect::<Vec<_>>(), vec![0]);
    for index in [1, 2] {
        let key = piece_key(space.as_bytes(), &locator, index);
        assert_eq!(shared.blobs.get(&key).await.unwrap(), None, "piece {index}");
    }
    assert_eq!(usage(&shared, space), before + stored.len() as u64);
}

/// A piece held whole at the last index, where the object's last piece is
/// shorter, is a stray too once piece 0 fixes the length.
#[tokio::test(flavor = "multi_thread")]
async fn a_whole_piece_where_the_last_is_shorter_goes() {
    let (shared, _clock) = open(Settings::open_core());
    let (space, _client) = created(&shared).await;
    let before = usage(&shared, space);
    let (locator, stored) = object(CHUNK_BYTES as u64 + 10, 8);
    assert!(stored.len() > PIECE_BYTES && stored.len() < 2 * PIECE_BYTES);
    assert_eq!(
        store_piece(&shared, space, locator, 1, vec![0; PIECE_BYTES], None).await,
        Ok(PieceOutcome::Stored(0))
    );
    assert_eq!(
        store_piece(
            &shared,
            space,
            locator,
            0,
            stored[..PIECE_BYTES].to_vec(),
            None
        )
        .await,
        Ok(PieceOutcome::Stored(1))
    );
    assert_eq!(usage(&shared, space), before + PIECE_BYTES as u64);
    assert_eq!(
        store_piece(
            &shared,
            space,
            locator,
            1,
            stored[PIECE_BYTES..].to_vec(),
            None
        )
        .await,
        Ok(PieceOutcome::Stored(2))
    );
    assert_eq!(usage(&shared, space), before + stored.len() as u64);
}

/// The bytes of a piece being written are held in the quota: a second
/// piece that would pass it with them is refused until the first is
/// indexed or refused.
#[tokio::test(flavor = "multi_thread")]
async fn pieces_being_written_hold_their_bytes_in_the_quota() {
    let (probe, _clock) = open(Settings::open_core());
    let (space, _client) = created(&probe).await;
    let used = usage(&probe, space);
    let (shared, _clock) = open(Settings {
        space_quota: used + PIECE_BYTES as u64 + PIECE_BYTES as u64 / 2,
        ..Settings::open_core()
    });
    let _creator = created(&shared).await;
    let core = &shared.core;
    let piece = PIECE_BYTES as u64;
    // One piece at a time has room, its hold dropped after each.
    for _ in 0..2 {
        let alone = core
            .read(space, |held| core.hold_piece(held, piece).is_ok())
            .await;
        assert_eq!(alone, Some(true));
    }
    // A second piece while the first is held passes the quota with it.
    let both = core
        .read(space, |held| {
            let first = core.hold_piece(held, piece);
            let second = core.hold_piece(held, piece);
            (first.is_ok(), second.err().map(|(code, _)| code))
        })
        .await;
    assert_eq!(both, Some((true, Some("quota_exceeded".to_owned()))));
}

/// The sealed chunks of `stored`, as an upload on a sync stream sends
/// them: each with its index, the header with the first.
fn sealed_chunks(stored: &[u8], locator: &Locator) -> Vec<(u64, Option<Vec<u8>>, Vec<u8>)> {
    let layout = Layout::read(stored, locator).unwrap();
    (0..layout.chunks)
        .map(|index| {
            let (from, to) = layout.chunk_range(index).unwrap();
            (
                index,
                (index == 0).then(|| layout.header.clone()),
                stored[from as usize..to as usize].to_vec(),
            )
        })
        .collect()
}

fn staged(shared: &Shared, space: EventId, locator: &Locator) -> Option<usize> {
    lock(&shared.core.uploads)
        .staging
        .get(&(space, *locator))
        .map(|staged| staged.bytes.len())
}

/// What an upload on a sync stream stages goes when the object completes,
/// when its connection closes, and `orphan_grace` after its last chunk; a
/// connection stages at most `staged_objects` objects at once.
#[tokio::test(flavor = "multi_thread")]
async fn staging_is_freed_and_bounded() {
    let settings = Settings {
        connections: crate::config::ConnectionLimits {
            staged_objects: 1,
            ..crate::config::ConnectionLimits::DEFAULT
        },
        ..Settings::open_core()
    };
    let (shared, clock) = open(settings);
    let (space, _client) = created(&shared).await;
    assert_eq!(SEALED_CHUNK_BYTES, PIECE_BYTES);
    let (locator, stored) = object(CHUNK_BYTES as u64 + 10, 9);
    let chunks = sealed_chunks(&stored, &locator);
    assert_eq!(chunks.len(), 2);

    // Its first chunk fills piece 0 and leaves the rest staged.
    let (index, header, chunk) = chunks[0].clone();
    let held = upload_chunk(&shared, 1, space, locator, header, index, chunk, None).await;
    assert_eq!(held, 1);
    assert!(staged(&shared, space, &locator).is_some_and(|len| len > 0));
    // A second object on the same connection is not staged.
    let (other, other_stored) = object(CHUNK_BYTES as u64 + 10, 10);
    let (index, header, chunk) = sealed_chunks(&other_stored, &other)[0].clone();
    assert_eq!(
        upload_chunk(
            &shared,
            1,
            space,
            other,
            header.clone(),
            index,
            chunk.clone(),
            None
        )
        .await,
        0
    );
    assert_eq!(staged(&shared, space, &other), None);
    // The connection closes: what it staged goes.
    shared.core.unlink(1);
    assert_eq!(staged(&shared, space, &locator), None);

    // On another connection, the other object's upload is left
    // incomplete, and goes `orphan_grace` after its last chunk.
    assert_eq!(
        upload_chunk(&shared, 2, space, other, header, index, chunk, None).await,
        1
    );
    assert!(staged(&shared, space, &other).is_some());
    clock.advance(shared.settings.orphan_grace);
    shared.core.sweep(clock.now()).await;
    assert_eq!(staged(&shared, space, &other), None);

    // An upload that completes leaves nothing staged, and no layout.
    let (done, done_stored) = object(10, 11);
    let (index, header, chunk) = sealed_chunks(&done_stored, &done)[0].clone();
    assert_eq!(
        upload_chunk(&shared, 3, space, done, header, index, chunk, None).await,
        1
    );
    assert_eq!(staged(&shared, space, &done), None);
    assert!(shared.core.layout(space, &done).is_none());
    assert!(!shared.core.in_use(&space));
}

/// Staged bytes count toward the space's quota: an upload that would pass
/// it stages nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn staged_bytes_count_toward_the_quota() {
    let (probe, _clock) = open(Settings::open_core());
    let (space, _client) = created(&probe).await;
    let used = usage(&probe, space);
    let (shared, _clock) = open(Settings {
        space_quota: used + 1024,
        ..Settings::open_core()
    });
    let _ = created(&shared).await;
    let (locator, stored) = object(CHUNK_BYTES as u64 + 10, 12);
    let (index, header, chunk) = sealed_chunks(&stored, &locator)[0].clone();
    assert_eq!(
        upload_chunk(&shared, 1, space, locator, header, index, chunk, None).await,
        0
    );
    assert_eq!(staged(&shared, space, &locator), None);
    assert_eq!(usage(&shared, space), used);
}

/// The root pseudonym P0's Ed25519 seed, as the reference draws it.
fn p0_seed() -> [u8; 32] {
    example("storage/credentials/P0/ed25519")
}

/// A space whose skeleton has its root, stored through the founder's
/// connection, and the root pseudonym's device ID.
async fn rooted(shared: &Arc<Shared>) -> (EventId, DeviceId, Client) {
    let (space, mut founder) = created(shared).await;
    let events = history();
    let (_, root) = events
        .iter()
        .find(|(name, _)| name == "P0: root")
        .unwrap()
        .clone();
    assert!(acknowledged(
        &founder.store(space, std::slice::from_ref(&root)).await
    ));
    let event = frasil_events::decode(&root).unwrap();
    assert_eq!(
        event.ed().0,
        frasil_crypto::primitives::ed25519_public(&p0_seed()),
        "the root's pseudonym is P0's"
    );
    (space, *event.author(), founder)
}

fn builds(shared: &Shared, space: EventId) -> u64 {
    shared
        .core
        .read_blocking(space, |held| held.skeleton.builds())
        .unwrap()
}

/// A credential 3 present whose proof does not verify is refused without
/// a resolution of the skeleton: the pseudonym's key comes from the one
/// kept, which nothing but a stored skeleton or space event renews. Nor
/// does a provisional pseudonym's present, or a valid one, resolve it
/// again (overview.md, 3 Threats, "A stranger").
#[tokio::test(flavor = "multi_thread")]
async fn a_present_with_a_bad_proof_resolves_no_skeleton() {
    let (shared, _clock) = open(Settings::open_core());
    let (space, p0, _founder) = rooted(&shared).await;
    let mut first = Client::connect(&shared, Purpose::Administration, "198.51.100.1").await;
    let refused = first.present_pseudonym(space, &p0, &[9; 32]).await;
    assert_eq!(
        answer_of(&refused),
        (MessageType::Refused, Some("credential_refused".into()))
    );
    let resolved = builds(&shared, space);
    for n in 0..4u8 {
        let mut stranger = Client::connect(&shared, Purpose::Administration, "198.51.100.2").await;
        let refused = stranger.present_pseudonym(space, &p0, &[n; 32]).await;
        assert_eq!(answer_of(&refused).1.as_deref(), Some("credential_refused"));
    }
    // A pseudonym the peer does not know yet is granted provisionally.
    let mut provisional = Client::connect(&shared, Purpose::Administration, "198.51.100.3").await;
    let granted = provisional
        .present_pseudonym(space, &DeviceId([4; 32]), &[4; 32])
        .await;
    assert_eq!(answer_of(&granted).0, MessageType::Granted);
    let mut admin = Client::connect(&shared, Purpose::Administration, "198.51.100.4").await;
    let granted = admin.present_pseudonym(space, &p0, &p0_seed()).await;
    assert_eq!(answer_of(&granted).0, MessageType::Granted);
    assert_eq!(builds(&shared, space), resolved);
}

/// A space's administration connections are bounded: past the limit a
/// pseudonym's present is refused `busy`, and a connection that closes
/// makes room.
#[tokio::test(flavor = "multi_thread")]
async fn administration_connections_per_space_are_bounded() {
    let (shared, _clock) = open(Settings {
        connections: crate::config::ConnectionLimits {
            admin_connections_per_space: 1,
            ..crate::config::ConnectionLimits::DEFAULT
        },
        ..Settings::open_core()
    });
    let (space, p0, _founder) = rooted(&shared).await;
    let mut first = Client::connect(&shared, Purpose::Administration, "198.51.100.1").await;
    let granted = first.present_pseudonym(space, &p0, &p0_seed()).await;
    assert_eq!(answer_of(&granted).0, MessageType::Granted);
    let mut second = Client::connect(&shared, Purpose::Administration, "198.51.100.1").await;
    let refused = second.present_pseudonym(space, &p0, &p0_seed()).await;
    assert_eq!(
        answer_of(&refused),
        (MessageType::Refused, Some("busy".into()))
    );
    drop(first);
    let mut third = Client::connect(&shared, Purpose::Administration, "198.51.100.1").await;
    let granted = third.present_pseudonym(space, &p0, &p0_seed()).await;
    assert_eq!(answer_of(&granted).0, MessageType::Granted);
}

/// Hands a space over as the operator's hand-over does, for what devices
/// see of it: the peer hosts it no more, and keeps a departure record with
/// the genesis's keys.
fn hand_over(shared: &Shared, space: EventId) {
    let public = frasil_crypto::primitives::ed25519_public;
    let departure = crate::records::Departure {
        keys: [
            [public(&read_seed())].into(),
            [public(&upload_seed())].into(),
            BTreeSet::new(),
            BTreeSet::new(),
        ],
        pseudonyms: BTreeSet::new(),
    };
    shared
        .core
        .departures
        .write()
        .unwrap()
        .insert(space, departure);
    lock(&shared.core.index).hosted.remove(&space);
}

fn register(space: EventId, request: u64) -> Vec<u8> {
    frasil_transport::messages::RegisterRecoveryEntry {
        request,
        space: *space.as_bytes(),
        fetch_key: frasil_crypto::primitives::ed25519_public(&[3; 32]),
    }
    .encode()
}

fn heads(space: EventId) -> Vec<u8> {
    sync(
        space,
        UnitMessage::Heads {
            heads: Vec::new(),
            vector: None,
            streams: Vec::new(),
        },
    )
}

/// A connection that proved nothing in a space learns nothing of its
/// hand-over: its messages are answered as for a space never hosted,
/// whatever it sent before; only a connection that proved a credential of
/// the space is answered `moved` (peers.md, 3.1 Hosting a space,
/// "Hand-over"; 3.7 Presenting a credential).
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_gets_credential_refused_never_moved() {
    let (shared, _clock) = open(Settings::open_core());
    let (space, mut founder) = created(&shared).await;
    let mut stranger = Client::connect(&shared, Purpose::SpaceTraffic, "192.0.2.9").await;
    assert!(stranger.send(&heads(space)).await.unwrap().is_empty());
    hand_over(&shared, space);
    assert!(stranger.send(&heads(space)).await.unwrap().is_empty());
    let answer = stranger.send(&register(space, 1)).await.unwrap();
    assert_eq!(
        answer.iter().map(answer_of).collect::<Vec<_>>(),
        vec![(MessageType::Refused, Some("credential_refused".into()))]
    );
    let events = history();
    let (_, later) = events[2].clone();
    let answer = stranger.store(space, std::slice::from_ref(&later)).await;
    assert_eq!(answer.len(), 1);
    assert_ne!(answer_of(&answer[0]).1.as_deref(), Some("moved"));
    // The founder proved the genesis's upload key before the hand-over.
    let answer = founder.send(&register(space, 9)).await.unwrap();
    assert_eq!(
        answer.iter().map(answer_of).collect::<Vec<_>>(),
        vec![(MessageType::Refused, Some("moved".into()))]
    );
}

/// An administration connection stores only its pseudonym's skeleton
/// events in the space it presented it for: a genesis before its present,
/// a create, is refused `purpose_violation`, and the peer hosts nothing
/// (transport.md, 3.10, the purposes).
#[tokio::test(flavor = "multi_thread")]
async fn an_administration_connection_creates_nothing() {
    let (shared, _clock) = open(Settings::open_core());
    let events = history();
    let space = id_of(&events[0].1);
    let mut admin = Client::connect(&shared, Purpose::Administration, "192.0.2.7").await;
    let answer = admin.store(space, &[events[0].1.clone()]).await;
    assert_eq!(
        answer.iter().map(answer_of).collect::<Vec<_>>(),
        vec![(MessageType::EventRefused, Some("purpose_violation".into()))]
    );
    assert!(!shared.core.hosts(&space));
    assert_eq!(shared.core.slots(), 0);
}

/// What a connection that proved nothing makes the peer keep is bounded:
/// its messages for spaces not hosted make no slot of them, its sync of a
/// hosted space opens nothing, and past `ungranted_per_minute` its
/// messages naming spaces it holds no grant in are refused `rate_limited`.
#[tokio::test(flavor = "multi_thread")]
async fn a_strangers_messages_keep_nothing_and_are_rate_limited() {
    let (shared, clock) = open(Settings {
        connections: crate::config::ConnectionLimits {
            ungranted_per_minute: 4,
            ..crate::config::ConnectionLimits::DEFAULT
        },
        ..Settings::open_core()
    });
    let (space, _founder) = created(&shared).await;
    shared.core.close_idle(true).await;
    assert_eq!(shared.core.open_spaces(), 0);
    let slots = shared.core.slots();
    let mut stranger = Client::connect(&shared, Purpose::SpaceTraffic, "192.0.2.9").await;
    let events = history();
    // Its sync of the hosted space reads nothing, so opens nothing.
    assert!(stranger.send(&heads(space)).await.unwrap().is_empty());
    assert_eq!(shared.core.open_spaces(), 0);
    // Spaces the peer does not host: no slot for any of them.
    for n in 0..2u8 {
        let elsewhere = EventId([n + 40; 32]);
        assert!(stranger.send(&heads(elsewhere)).await.unwrap().is_empty());
        let refused = stranger
            .present(elsewhere, Credential::Read, &[n; 32])
            .await;
        assert_eq!(answer_of(&refused).1.as_deref(), Some("no_library"));
    }
    // Its event in the hosted space is refused before the space opens.
    let answer = stranger.store(space, &[events[2].1.clone()]).await;
    assert_eq!(answer_of(&answer[0]).1.as_deref(), Some("not_authorized"));
    assert_eq!(shared.core.open_spaces(), 0);
    assert_eq!(shared.core.slots(), slots);
    // Four messages naming spaces without a grant, presents aside, made
    // its minute's count: the next is refused.
    let answer = stranger.send(&register(space, 50)).await.unwrap();
    assert_eq!(
        answer.iter().map(answer_of).collect::<Vec<_>>(),
        vec![(MessageType::Refused, Some("rate_limited".into()))]
    );
    // A minute later it may send again.
    clock.advance(60);
    let answer = stranger.send(&register(space, 51)).await.unwrap();
    assert_eq!(
        answer_of(&answer[0]).1.as_deref(),
        Some("credential_refused")
    );
}

/// The type of each message a sync stream carries: units.md's message
/// inside each `Sync`.
fn unit_messages(out: &[Outgoing]) -> Vec<UnitMessage> {
    out.iter()
        .filter_map(|out| match out {
            Outgoing::Sync(_, bytes) => {
                let message = crate::server::read(bytes, crate::Extensions::NONE)
                    .unwrap()
                    .unwrap();
                let wrapper = Sync::read(&message, ConnectionKind::DeviceToPeer).unwrap();
                match SyncMessage::read(&wrapper.message).unwrap() {
                    Received::Message(unit) => Some(unit.message),
                    Received::Ignored { .. } => None,
                }
            }
            _ => None,
        })
        .collect()
}

/// A sync answer is served in batches as the connection takes it: the
/// message that asks for it is answered at once with the peer's heads
/// alone, and its events, read a message's worth at a time, follow in
/// canonical order, none skipped, each batch within units.md's limits. An
/// event stored meanwhile is left to live delivery.
#[tokio::test(flavor = "multi_thread")]
async fn a_sync_answer_is_served_in_batches_as_it_is_taken() {
    let (shared, _clock) = open(Settings::open_core());
    let (space, mut founder) = created(&shared).await;
    let events = history();
    for (name, signed) in &events[1..5] {
        assert!(
            acknowledged(&founder.store(space, std::slice::from_ref(signed)).await),
            "{name}"
        );
    }
    let mut reader = Client::connect(&shared, Purpose::SpaceTraffic, "192.0.2.5").await;
    let granted = reader.present(space, Credential::Read, &read_seed()).await;
    assert_eq!(answer_of(&granted).0, MessageType::Granted);
    let message = crate::server::read(&heads(space), shared.settings.extensions)
        .unwrap()
        .unwrap();
    let now = reader.session.on_message(&message).await.unwrap();
    // At once: the peer's heads alone; no event is read yet.
    let kinds = unit_messages(&now);
    assert_eq!(kinds.len(), 1);
    assert!(matches!(kinds[0], UnitMessage::Heads { .. }));
    assert_eq!(reader.session.answers.len(), 1);
    // An event stored while the answer waits is not in it.
    let (_, later) = events
        .iter()
        .find(|(name, _)| name == "P removes W")
        .unwrap()
        .clone();
    assert!(acknowledged(
        &founder.store(space, std::slice::from_ref(&later)).await
    ));
    let mut served = Vec::new();
    while let Some(next) = reader.session.next_answer().await {
        let Outgoing::Sync(_, bytes) = &next else {
            panic!("not a sync message");
        };
        assert!(bytes.len() <= frasil_transport::frame::MAX_FRAME_BYTES);
        for unit in unit_messages(&[next]) {
            let UnitMessage::Events { events } = unit else {
                panic!("not events");
            };
            served.extend(events);
        }
    }
    assert!(reader.session.answers.is_empty());
    // Each event once, parents first, and none stored after the request.
    let expected: BTreeSet<EventId> = events[..5]
        .iter()
        .map(|(_, signed)| id_of(signed))
        .collect();
    let ids: Vec<EventId> = served.iter().map(|signed| id_of(signed)).collect();
    assert_eq!(ids.len(), expected.len());
    assert_eq!(ids.iter().copied().collect::<BTreeSet<_>>(), expected);
    for (at, signed) in served.iter().enumerate() {
        let event = frasil_events::decode(signed).unwrap();
        for parent in event.parents() {
            assert!(!ids[at..].contains(parent), "a parent after its child");
        }
    }
}

/// In a cluster, a sync answer reaches a device connected to a node that
/// does not own the space in the same messages and order as one connected
/// to the owner: its owner sends it in parts, each asked for once the one
/// before is taken, and keeps nothing of it once it is all served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_sync_answer_crosses_in_parts() {
    use crate::testing::cluster::{TIMING, TestCluster};
    let cluster = TestCluster::start(2, TIMING, 0x5a)
        .await
        .expect("two nodes form a cluster");
    let node = |n: usize| cluster.node(n).peer.peer.shared.clone();
    let (space, mut founder) = created(&node(0)).await;
    let events = history();
    for (name, signed) in &events[1..5] {
        assert!(
            acknowledged(&founder.store(space, std::slice::from_ref(signed)).await),
            "{name}"
        );
    }
    let mut answers = Vec::new();
    for n in 0..2 {
        let shared = node(n);
        let mut reader = Client::connect(&shared, Purpose::SpaceTraffic, "192.0.2.5").await;
        let granted = reader.present(space, Credential::Read, &read_seed()).await;
        assert_eq!(answer_of(&granted).0, MessageType::Granted);
        let message = crate::server::read(&heads(space), shared.settings.extensions)
            .unwrap()
            .unwrap();
        let mut out = reader.session.on_message(&message).await.unwrap();
        // The heads at once; the events in a part of their own.
        assert_eq!(out.len(), 1);
        assert_eq!(reader.session.answers.len(), 1);
        while let Some(next) = reader.session.next_answer().await {
            out.push(next);
        }
        assert!(reader.session.answers.is_empty());
        answers.push(unit_messages(&out));
    }
    assert_eq!(answers[0], answers[1], "the same at either node");
    let served: Vec<EventId> = answers[0]
        .iter()
        .flat_map(|unit| match unit {
            UnitMessage::Events { events } => events.iter().map(|e| id_of(e)).collect(),
            _ => Vec::new(),
        })
        .collect();
    let expected: BTreeSet<EventId> = events[..5]
        .iter()
        .map(|(_, signed)| id_of(signed))
        .collect();
    assert_eq!(served.len(), expected.len());
    assert_eq!(served.into_iter().collect::<BTreeSet<_>>(), expected);
    for n in 0..2 {
        let sessions = cluster.node(n).cluster.owners.pending();
        assert_eq!(sessions, 0, "node {n} keeps nothing of the answers");
    }
    // A connection still open holds the nodes' drain.
    drop(founder);
    cluster.shutdown().await;
}

/// A connection's queue is bounded by bytes as well as messages: past
/// `queued_bytes` a delivery is dropped, and what its binding takes off
/// makes room again.
#[tokio::test(flavor = "multi_thread")]
async fn a_connections_queue_is_bounded_by_bytes() {
    let (shared, _clock) = open(Settings {
        connections: crate::config::ConnectionLimits {
            queued_bytes: 100,
            ..crate::config::ConnectionLimits::DEFAULT
        },
        ..Settings::open_core()
    });
    let mut client = Client::connect(&shared, Purpose::SpaceTraffic, "192.0.2.5").await;
    let link = client.session.link;
    let space = EventId([5; 32]);
    let delivery = || Outgoing::Sync(space, vec![7; 60]);
    assert!(shared.core.send_to(link, delivery()));
    assert!(!shared.core.send_to(link, delivery()));
    // A message with no bytes, such as an ask to reconnect, still fits.
    assert!(shared.core.send_to(link, Outgoing::Reconnect));
    let taken = client.rx.recv().await.unwrap();
    client.session.dequeued(&taken);
    assert!(shared.core.send_to(link, delivery()));
}

/// A connection whose grant in a space ended, here by the space's erasure,
/// is a stranger there again once its next message is judged (peers.md,
/// 3.6 Retirement and the cap, "Connections"): it holds no grant that keeps
/// it open while idle, and its messages naming the space count toward the
/// rate of those naming spaces it holds no grant in.
#[tokio::test(flavor = "multi_thread")]
async fn a_grant_that_ended_leaves_no_exemption() {
    let (shared, _clock) = open(Settings {
        connections: crate::config::ConnectionLimits {
            ungranted_per_minute: 2,
            ..crate::config::ConnectionLimits::DEFAULT
        },
        ..Settings::open_core()
    });
    let (space, mut founder) = created(&shared).await;
    assert!(founder.session.holds_grant());
    let held = shared.core.write(space).await.unwrap();
    let erasure = crate::space::Removal {
        erase_space: Some(vec![9; 8]),
        ..crate::space::Removal::default()
    };
    shared.core.remove(&held, erasure).await.unwrap();
    drop(held);
    // Its first message after the erasure is judged under no right.
    assert!(founder.send(&heads(space)).await.unwrap().is_empty());
    assert!(!founder.session.holds_grant());
    // Two more make its minute's count: the next is refused.
    for _ in 0..2 {
        assert!(founder.send(&heads(space)).await.unwrap().is_empty());
    }
    let answer = founder.send(&register(space, 60)).await.unwrap();
    assert_eq!(
        answer.iter().map(answer_of).collect::<Vec<_>>(),
        vec![(MessageType::Refused, Some("rate_limited".into()))]
    );
}
