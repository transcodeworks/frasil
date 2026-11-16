//! The peer's scenarios (peers.md): storing, catching up, release and
//! restore, and erasure after stability or after T, by devices on the
//! server binding and on the iroh binding.

mod common;

use common::*;
use frasil_conformance::client::{Credential, PeerClient};
use frasil_conformance::history::{
    History, erase_space, erase_stream_body, family, object, object_id, release, stream,
};
use frasil_events::EventId;
use frasil_relay::testing::START;
use frasil_relay::{Execution, Settings};
use frasil_transport::codes::Right;
use frasil_transport::messages::RegisterRecoveryEntry;
use frasil_transport::peer::{Purpose, chunk_path, transfer_authorization};
use frasil_units::messages::Message as UnitMessage;

const WEEK: u64 = 7 * 86_400;

/// The credentials history, every event but `W forks`, whose body is not a
/// unit's.
fn credentials_events(history: &History) -> Vec<Vec<u8>> {
    history
        .order
        .iter()
        .filter(|n| *n != "W forks")
        .map(|n| history.signed(n))
        .collect()
}

async fn store(binding: Binding) {
    let peer = peer(frasil_conformance::settings()).await;
    let mut history = History::credentials();
    let space = history.space();
    let mut device = founder(&peer, binding, &history).await;
    let events = credentials_events(&history);
    store_all(&mut device, space, events[1..].to_vec()).await;
    for signed in &events {
        let id = frasil_events::decode(signed).unwrap().id();
        assert!(peer.peer.holds(space.as_bytes(), id.as_bytes()));
    }

    // P0's first request retired the genesis's entry: the connection's next
    // store is refused as one with no right, and it stores again once it
    // presents the current state's upload key.
    let retry = history.signed("P rotates");
    assert_eq!(
        device.store_answer(space, &retry, DEADLINE).await,
        Some(Err("not_authorized".into()))
    );
    present_current(&mut device, &history).await;

    // An identical retry is acknowledged again.
    assert!(device.store_one(space, &retry, DEADLINE).await);

    // A reader subscribes; a writer's new unit reaches it live.
    let mut reader = connect(&peer, binding, Purpose::SpaceTraffic).await;
    let granted = reader
        .present(
            space,
            Credential::Read,
            &history.read_seed("V rotates, citing W's rotation"),
        )
        .await
        .expect("a live read credential");
    assert_eq!(granted.rights, vec![Right::Fetch, Right::Live]);
    reader
        .send_sync(
            space,
            UnitMessage::Subscribe {
                streams: Vec::new(),
            },
        )
        .await;
    // The subscription travels before the next store.
    let _ = reader
        .exchange(
            space,
            UnitMessage::PathWant {
                from: space,
                to: space,
            },
        )
        .await;
    let unit = history.unit(
        "V",
        "V writes",
        stream("notes"),
        Vec::new(),
        None,
        &["P0 asks to keep V's rotation live"],
    );
    let unit_id = history.id("V writes");
    assert!(device.store_one(space, &unit, DEADLINE).await);
    let delivered = reader
        .wait_for(DEADLINE, |message| {
            match PeerClient::unit_message(message, space) {
                Some(UnitMessage::Events { events }) => Some(events),
                _ => None,
            }
        })
        .await
        .expect("live delivery");
    assert_eq!(delivered, vec![unit.clone()]);

    // A reader may not store: not_authorized, and nothing is kept.
    let unwanted = history.unit(
        "V",
        "V writes again",
        stream("notes"),
        Vec::new(),
        None,
        &[],
    );
    assert_eq!(
        reader.store_answer(space, &unwanted, DEADLINE).await,
        Some(Err("not_authorized".into()))
    );
    assert!(
        !peer
            .peer
            .keeps(space.as_bytes(), history.id("V writes again").as_bytes())
    );

    // A second event at one author and `seq`: stored as fork evidence and
    // served, never acknowledged.
    history.force_next("V", 2, Some(history.id("V rotates, citing W's rotation")));
    let fork = history.unit("V", "V forks", stream("notes"), Vec::new(), None, &[]);
    assert_eq!(
        device.store_answer(space, &fork, DEADLINE).await,
        Some(Err("conflict".into()))
    );
    assert!(
        peer.peer
            .holds(space.as_bytes(), history.id("V forks").as_bytes())
    );
    assert!(peer.peer.holds(space.as_bytes(), unit_id.as_bytes()));
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_store_over_the_websocket() {
    within(store(Binding::WebSocket)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_store_over_iroh() {
    within(store(Binding::Iroh)).await;
}

/// QUIC orders each stream alone: a device's sync stream, here one that
/// carries the genesis, may reach the peer before the `Hello` on the
/// control stream, which every other message follows (transport.md,
/// 3.10). The peer reads it once the `Hello` is in, and the genesis
/// creates the space, as if the two had come in order.
#[tokio::test(flavor = "multi_thread")]
async fn a_sync_stream_ahead_of_the_hello_waits_for_it() {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        let history = History::credentials();
        let space = history.space();
        let genesis = history.events(&[&history.order[0].clone()]);
        let mut device = PeerClient::iroh_sync_before_hello(&peer, space, genesis.clone()).await;
        // Sent again, the identical genesis is acknowledged again.
        let acked = device.store(space, genesis, DEADLINE).await;
        assert_eq!(acked, vec![space], "the genesis creates the space");
        assert!(peer.peer.hosts(space.as_bytes()));
    })
    .await;
}

async fn catch_up(binding: Binding) {
    let peer = peer(frasil_conformance::settings()).await;
    let mut history = History::credentials();
    let space = history.space();
    let mut device = founder(&peer, binding, &history).await;
    store_all(
        &mut device,
        space,
        credentials_events(&history)[1..].to_vec(),
    )
    .await;
    // The genesis's entry, whose upload key the device proved, retired with
    // P0's first request, and the store right with it: the device presents
    // the current state's upload key.
    present_current(&mut device, &history).await;
    let mut events = Vec::new();
    // V writes a unit of its system stream and one of another stream; a
    // storage event of V's cites the second.
    let system = stream("system");
    let base = "P0 asks to keep V's rotation live";
    events.push(history.unit("V", "V's system unit", system, Vec::new(), None, &[base]));
    events.push(history.unit(
        "V",
        "V's other unit",
        stream("other"),
        Vec::new(),
        None,
        &[],
    ));
    events.push(history.storage(
        "V",
        "V releases a stream",
        &release(stream("released")),
        &["V's other unit"],
    ));
    store_all(&mut device, space, events).await;

    // The genesis's read credential is retired: catch-up only.
    let mut behind = connect(&peer, binding, Purpose::SpaceTraffic).await;
    let granted = behind
        .present(
            space,
            Credential::Read,
            &history.read_seed("P creates the space"),
        )
        .await
        .expect("a retired read credential");
    assert_eq!(granted.rights, vec![Right::CatchUp]);
    // Heads: the space events and storage events, no unit.
    let answer = behind
        .exchange(
            space,
            UnitMessage::Heads {
                heads: Vec::new(),
                vector: None,
                streams: Vec::new(),
            },
        )
        .await;
    let served = PeerClient::events_of(&answer);
    assert!(served.contains(&space));
    assert!(served.contains(&history.id("V releases a stream")));
    assert!(served.contains(&history.id(base)));
    assert!(!served.contains(&history.id("V's system unit")));
    assert!(!served.contains(&history.id("V's other unit")));
    // By ID: a parent of an event served on the connection.
    let other = history.id("V's other unit");
    let answer = behind
        .exchange(
            space,
            UnitMessage::Want {
                ids: vec![other],
                ranges: Vec::new(),
                kinds: Vec::new(),
                streams: Vec::new(),
            },
        )
        .await;
    assert_eq!(PeerClient::events_of(&answer), vec![other]);
    // The one stream it names as the system stream, and no other.
    let answer = behind
        .exchange(
            space,
            UnitMessage::StreamWant {
                stream: system,
                held: Vec::new(),
                from_snapshot: false,
            },
        )
        .await;
    assert_eq!(
        PeerClient::events_of(&answer),
        vec![history.id("V's system unit")]
    );
    let answer = behind
        .exchange(
            space,
            UnitMessage::StreamWant {
                stream: stream("other"),
                held: Vec::new(),
                from_snapshot: false,
            },
        )
        .await;
    assert!(PeerClient::events_of(&answer).is_empty());

    // A live read credential fetches everything.
    let mut current = connect(&peer, binding, Purpose::SpaceTraffic).await;
    current
        .present(
            space,
            Credential::Read,
            &history.read_seed("V rotates, citing W's rotation"),
        )
        .await
        .expect("a live read credential");
    let answer = current
        .exchange(
            space,
            UnitMessage::Heads {
                heads: Vec::new(),
                vector: None,
                streams: Vec::new(),
            },
        )
        .await;
    let served = PeerClient::events_of(&answer);
    assert!(served.contains(&history.id("V's system unit")));
    assert!(served.contains(&other));

    // A recovery entry: registered under the store right, then presented
    // by a device that holds only the fetch key: catch-up.
    let fetch_seed = [42u8; 32];
    let fetch_key = frasil_crypto::primitives::ed25519_public(&fetch_seed);
    let request = device.request();
    let register = RegisterRecoveryEntry {
        request,
        space: *space.as_bytes(),
        fetch_key,
    }
    .encode();
    assert_eq!(device.request_answer(request, &register).await, Ok(None));
    let mut recovering = connect(&peer, binding, Purpose::SpaceTraffic).await;
    let granted = recovering
        .present(space, Credential::Fetch, &fetch_seed)
        .await
        .expect("a live recovery entry");
    assert_eq!(granted.rights, vec![Right::CatchUp]);
    // Without the store right, a registration is refused.
    let request = recovering.request();
    let register = RegisterRecoveryEntry {
        request,
        space: *space.as_bytes(),
        fetch_key: frasil_crypto::primitives::ed25519_public(&[43; 32]),
    }
    .encode();
    assert_eq!(
        recovering.request_answer(request, &register).await,
        Err("credential_refused".into())
    );
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_behind_catches_up_over_the_websocket() {
    within(catch_up(Binding::WebSocket)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_behind_catches_up_over_iroh() {
    within(catch_up(Binding::Iroh)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_is_released_reclaimed_and_restored() {
    within(async {
        let skeleton = family("skeleton");
        let notes = stream("notes");
        let mut history = History::skeleton();
        let space = history.space();
        let release = "W releases the notes stream";
        // W's unit is a parent of W's release, an event outside the stream:
        // the peer keeps it as an event alone (peers.md, "Release and
        // restore"). V's unit of the stream no event outside it names.
        let named = "W writes to the notes stream";
        let alone = "V writes to the notes stream";
        let alone_signed = history.unit("V", alone, notes, Vec::new(), None, &[named]);
        // Reclaimed as soon as it is stable at the peer.
        let peer = peer(Settings {
            release_retention: 0,
            ..frasil_conformance::settings()
        })
        .await;
        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        let events = history.before(release);
        device.store(space, events[1..].to_vec(), DEADLINE).await;
        assert!(device.store_one(space, &alone_signed, DEADLINE).await);
        assert!(
            device
                .store_one(space, &history.signed(release), DEADLINE)
                .await
        );
        assert_eq!(
            peer.peer.released(space.as_bytes(), &notes),
            skeleton["released_before_restore"]["notes"] == true
        );
        let (alone_id, named_id) = (history.id(alone), history.id(named));
        let at = space.as_bytes();
        // While released, the stream's units are not served, but for the
        // ones an event outside the stream names, which the peer serves by
        // ID as any parent; new ones are refused.
        assert!(!peer.peer.holds(at, alone_id.as_bytes()));
        assert!(peer.peer.holds(at, named_id.as_bytes()));
        let late = history.unit("V", "V writes late", notes, Vec::new(), None, &[release]);
        assert_eq!(
            device.store_answer(space, &late, DEADLINE).await,
            Some(Err("released".into()))
        );
        // Not yet stable: kept.
        assert!(peer.peer.keeps(at, alone_id.as_bytes()));
        // P0 and A1 acknowledge it: stable, so reclaimed at once. V's unit
        // goes; W's stays as an event alone, served by ID, while the stream
        // stays released.
        let rest = history.events(&[
            "W rotates",
            "P removes A",
            "A1 erases the space",
            "P0 acknowledges",
        ]);
        device.store(space, rest, DEADLINE).await;
        assert!(!peer.peer.keeps(at, alone_id.as_bytes()));
        assert!(peer.peer.keeps(at, named_id.as_bytes()));
        assert!(peer.peer.holds(at, named_id.as_bytes()));
        assert!(peer.peer.released(at, &notes));
        // The restore wins; the writer may store the stream's units again.
        assert!(
            device
                .store_one(
                    space,
                    &history.signed("W restores the notes stream"),
                    DEADLINE
                )
                .await
        );
        assert_eq!(
            peer.peer.released(space.as_bytes(), &notes),
            skeleton["released_after_restore"]["notes"] == true
        );
        assert!(
            device.store_one(space, &alone_signed, DEADLINE).await,
            "the reclaimed unit is stored again"
        );
        assert!(peer.peer.holds(at, alone_id.as_bytes()));
        peer.shutdown().await;
    })
    .await;
}

/// Uploads a stored object over HTTP with a transfer token; the last
/// status.
async fn upload(device: &PeerClient, space: EventId, stored: &[u8], locator: &[u8; 64]) -> u16 {
    let token = device.tokens[&space];
    let client = frasil_conformance::http_client();
    let mut status = 0;
    for (index, piece) in stored.chunks(1_048_576).enumerate() {
        let url = format!(
            "{}{}",
            device.http().unwrap(),
            chunk_path(space.as_bytes(), locator, index as u64)
        );
        status = client
            .put(url)
            .header("Authorization", transfer_authorization(&token))
            .body(piece.to_vec())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
    }
    status
}

#[tokio::test(flavor = "multi_thread")]
async fn an_erasure_stable_at_the_peer_is_carried_out_at_once() {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        let mut history = History::credentials();
        let space = history.space();
        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        store_all(
            &mut device,
            space,
            credentials_events(&history)[1..].to_vec(),
        )
        .await;
        // A unit of the doomed stream, and an object. The transfer token
        // of the genesis's upload key stopped when P0's first request
        // retired its entry; the current state's grants another.
        let doomed = stream("doomed");
        let (stored, locator) = object(object_id("doomed"), 20, space);
        assert_eq!(upload(&device, space, &stored, &locator).await, 403);
        present_current(&mut device, &history).await;
        assert_eq!(upload(&device, space, &stored, &locator).await, 201);
        assert!(peer.peer.holds_object(space.as_bytes(), &locator));
        let unit = history.unit(
            "V",
            "V writes to the doomed stream",
            doomed,
            vec![locator],
            None,
            &["P0 asks to keep V's rotation live"],
        );
        assert!(device.store_one(space, &unit, DEADLINE).await);
        let mut admin = connect(&peer, Binding::WebSocket, Purpose::Administration).await;
        admin
            .present_pseudonym(space, &history.seed("P0"), &history.device_id("P0"))
            .await
            .unwrap();
        // An erasure names the whole space: P0's erase body that names the
        // doomed stream is refused as malformed, and the stream's unit and
        // the object stay. Not stored, it is no `prev`: P0's next event
        // takes its `seq`.
        let (seq, prev) = history.next_of("P0");
        let narrower = history.sign(
            "P0",
            "P0 asks to erase the doomed stream",
            frasil_events::kind::STORAGE,
            erase_stream_body(doomed),
            &["V writes to the doomed stream"],
        );
        assert_eq!(
            admin.store_answer(space, &narrower, DEADLINE).await,
            Some(Err("malformed".into()))
        );
        assert!(peer.peer.keeps(
            space.as_bytes(),
            history.id("V writes to the doomed stream").as_bytes()
        ));
        assert!(peer.peer.holds_object(space.as_bytes(), &locator));
        history.force_next("P0", seq, prev);

        // P0, the only administrator, erases the space: stable at the peer
        // as soon as it is stored, so carried out at once. A tombstone,
        // and every later store and present refused as erased.
        let gone = history.storage(
            "P0",
            "P0 erases the space",
            &erase_space(),
            &["V writes to the doomed stream"],
        );
        assert!(admin.store_one(space, &gone, DEADLINE).await);
        assert_eq!(
            peer.peer.outcome(
                space.as_bytes(),
                history.id("P0 erases the space").as_bytes()
            ),
            Some(Execution::Execute)
        );
        assert!(peer.peer.erased(space.as_bytes()));
        assert!(!peer.peer.hosts(space.as_bytes()));
        assert!(!peer.peer.holds_object(space.as_bytes(), &locator));
        // The open connection's rights in the space ended with it, so its
        // store is one with no right (peers.md, "Connections").
        let later = history.unit("V", "V writes again", doomed, Vec::new(), None, &[]);
        assert_eq!(
            device.store_answer(space, &later, DEADLINE).await,
            Some(Err("not_authorized".into()))
        );
        let mut after = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
        assert_eq!(
            after
                .present(
                    space,
                    Credential::Read,
                    &history.read_seed("P creates the space")
                )
                .await
                .unwrap_err(),
            "erased"
        );
        assert_eq!(
            after
                .store_answer(space, &history.signed("P creates the space"), DEADLINE)
                .await,
            Some(Err("erased".into())),
            "no create of an erased space"
        );
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_erasure_waits_for_t_without_stability() {
    within(async {
        // The object is referenced by no unit: kept past T.
        let peer = peer(Settings {
            orphan_grace: 30 * 86_400,
            ..frasil_conformance::settings()
        })
        .await;
        let history = History::skeleton();
        let space = history.space();
        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        let (stored, locator) = object(object_id("draft"), 5, space);
        assert_eq!(upload(&device, space, &stored, &locator).await, 201);
        device
            .store(space, history.all()[1..].to_vec(), DEADLINE)
            .await;
        let erasure = history.id("P0 erases the space");
        let void = history.id("A1 erases the space");
        // A's lowering waits to settle and A never acknowledges: the erasure
        // waits. A1's, concurrent with A's removal, is void.
        assert_eq!(
            peer.peer.outcome(space.as_bytes(), erasure.as_bytes()),
            Some(Execution::Wait)
        );
        assert_eq!(
            peer.peer.outcome(space.as_bytes(), void.as_bytes()),
            Some(Execution::Void)
        );
        peer.set_time(START + WEEK - 1).await;
        assert!(peer.peer.holds_object(space.as_bytes(), &locator));
        assert!(peer.peer.holds(
            space.as_bytes(),
            history.id("W writes to the notes stream").as_bytes()
        ));
        // At T the erasure is carried out: the space, its units and its
        // objects go, and a tombstone stays.
        peer.set_time(START + WEEK).await;
        assert_eq!(
            peer.peer.outcome(space.as_bytes(), erasure.as_bytes()),
            Some(Execution::Execute)
        );
        assert!(peer.peer.erased(space.as_bytes()));
        assert!(!peer.peer.holds_object(space.as_bytes(), &locator));
        assert!(!peer.peer.holds(
            space.as_bytes(),
            history.id("W writes to the notes stream").as_bytes()
        ));
        peer.shutdown().await;
    })
    .await;
}

async fn objects_in_sync_messages(binding: Binding) {
    use frasil_units::limits::SEALED_CHUNK_BYTES;
    let peer = peer(frasil_conformance::settings()).await;
    let history = History::credentials();
    let space = history.space();
    let mut writer = founder(&peer, binding, &history).await;
    // Two sealed chunks: the first fills a piece but for the header's
    // length, the second spills into the next.
    let (stored, locator) = object(object_id("streamed"), 1_100_000, space);
    let length = u32::from_be_bytes(stored[..4].try_into().unwrap()) as usize;
    let header = stored[4..4 + length].to_vec();
    let start = 4 + length;
    let chunks = [
        stored[start..start + SEALED_CHUNK_BYTES].to_vec(),
        stored[start + SEALED_CHUNK_BYTES..].to_vec(),
    ];
    let have = |messages: &[UnitMessage]| {
        messages.iter().find_map(|m| match m {
            UnitMessage::ObjectHave { counts, .. } => counts.as_ref().map(|c| c[0]),
            _ => None,
        })
    };
    // A chunk out of order is dropped; the answer says where to resume.
    let answer = writer
        .exchange(
            space,
            UnitMessage::ObjectChunks {
                locator,
                header: Some(header.clone()),
                index: 1,
                chunk: chunks[1].clone(),
            },
        )
        .await;
    assert_eq!(have(&answer), Some(0));
    for (index, chunk) in chunks.iter().enumerate() {
        let answer = writer
            .exchange(
                space,
                UnitMessage::ObjectChunks {
                    locator,
                    header: (index == 0).then(|| header.clone()),
                    index: index as u64,
                    chunk: chunk.clone(),
                },
            )
            .await;
        assert_eq!(have(&answer), Some(index as u64 + 1));
    }
    assert!(peer.peer.holds_object(space.as_bytes(), &locator));
    // A reader asks for both chunks; each arrives in its own ObjectChunks.
    let mut reader = connect(&peer, binding, Purpose::SpaceTraffic).await;
    reader
        .present(
            space,
            Credential::Read,
            &history.read_seed("P creates the space"),
        )
        .await
        .unwrap();
    let answer = reader
        .exchange(
            space,
            UnitMessage::ObjectWant {
                locator,
                first: 0,
                count: 2,
            },
        )
        .await;
    let received: Vec<(u64, Vec<u8>, Option<Vec<u8>>)> = answer
        .into_iter()
        .filter_map(|m| match m {
            UnitMessage::ObjectChunks {
                index,
                chunk,
                header,
                ..
            } => Some((index, chunk, header)),
            _ => None,
        })
        .collect();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0], (0, chunks[0].clone(), Some(header)));
    assert_eq!((received[1].0, &received[1].1), (1, &chunks[1]));
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn objects_travel_in_sync_messages_over_the_websocket() {
    within(objects_in_sync_messages(Binding::WebSocket)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn objects_travel_on_iroh_streams() {
    within(objects_in_sync_messages(Binding::Iroh)).await;
}
