//! ext-libraries.md's scenarios at the peer: attaching a space to a library
//! by create, importing a log, moving, suspending, detaching and deleting,
//! and the ledgers the issuer reads. They run, with the feature
//! `ext-libraries`, against a peer with the extension on, which trusts the
//! vectors' issuer and keeps no open library, so a create needs a ticket.
//! In every build, a peer with it off, as by default, lists no service 5,
//! closes a connection that sends type 21 or 31, and serves no library
//! route, as a core peer does.

mod common;

use common::*;
use frasil_conformance::client::PeerClient;
use frasil_transport::peer::Purpose;

/// A space-traffic connection's `LibraryAttach`, as bytes.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_with_the_extension_off_closes_a_connection_that_sends_type_21() {
    within(async {
        let peer = peer(frasil_relay::Settings::open_core()).await;
        assert!(!peer.peer.extensions().libraries);
        for binding in BINDINGS {
            let mut device: PeerClient = connect(&peer, binding, Purpose::SpaceTraffic).await;
            assert!(
                !device
                    .peer_hello
                    .services()
                    .contains(&frasil_transport::codes::Service::Library)
            );
            // {0: 21, 1: 1, 2: space, 3: 1, 4: h''}
            let mut message = vec![0xa5, 0x00, 0x15, 0x01, 0x01, 0x02, 0x58, 0x20];
            message.extend_from_slice(&[9; 32]);
            message.extend_from_slice(&[0x03, 0x01, 0x04, 0x40]);
            device.send_control(&message).await;
            let code = device.closed(DEADLINE).await.expect("the peer closes");
            let malformed = frasil_transport::Code::Malformed;
            let expected = match binding {
                Binding::WebSocket => u64::from(malformed.websocket()),
                Binding::Iroh => malformed.number(),
            };
            assert_eq!(code, Some(expected), "{binding:?}");
            // {0: 31, 1: 1}: `HoldObject`'s type.
            let mut device: PeerClient = connect(&peer, binding, Purpose::SpaceTraffic).await;
            device
                .send_control(&[0xa2, 0x00, 0x18, 0x1f, 0x01, 0x01])
                .await;
            let code = device.closed(DEADLINE).await.expect("the peer closes");
            assert_eq!(code, Some(expected), "{binding:?} type 31");
        }
        // The operator's routes are not served.
        let client = frasil_conformance::http_client();
        let usage = format!("{}/frasil/p1/libraries/personal:a/usage", peer.origin);
        let response = client.get(&usage).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 404);
        let handover = format!(
            "{}/frasil/p1/libraries/personal:a/handover/export",
            peer.origin
        );
        let response = client.post(&handover).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 404);
        let settings = format!("{}/frasil/p1/libraries/personal:a/settings", peer.origin);
        let response = client.get(&settings).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 404);
        let response = client.put(&settings).body("{}").send().await.unwrap();
        assert_eq!(response.status().as_u16(), 404);
        // Its discovery document lists the core services alone.
        let document: serde_json::Value = client
            .get(format!("{}/.well-known/frasil", peer.origin))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            document["services"],
            serde_json::json!(["relay", "store", "mailbox"])
        );
        peer.shutdown().await;
    })
    .await;
}

#[cfg(feature = "ext-libraries")]
mod with_libraries {
    use super::*;
    use frasil_conformance::client::Credential;
    use frasil_conformance::history::{History, release, stream};
    use frasil_events::EventId;
    use frasil_libraries::{
        Issuer, LibraryAttach, LibraryId, LibraryState, Purpose as TicketPurpose, Ticket,
        TrustedIssuers,
    };
    use frasil_relay::libraries::{LibrarySettings, LibraryUpdate};
    use frasil_relay::testing::{START, TestPeer};
    use frasil_relay::{Clock, EntryStatus, Settings};
    use frasil_transport::codes::{Right, Service};
    use serde_json::{Value as Json, json};

    const FILE: &str = "ext-libraries.json";

    fn family(name: &str) -> Json {
        frasil_testkit::vectors::family(FILE, name)
    }

    fn seed() -> [u8; 32] {
        frasil_testkit::hex::decode_array(family("parameters")["issuer_seed"].as_str().unwrap())
            .unwrap()
    }

    fn library(name: &str) -> LibraryId {
        LibraryId::new(name).unwrap()
    }

    /// A peer that trusts the vectors' issuer, and has no open library.
    async fn library_peer() -> TestPeer {
        let issuer = Issuer::from_seed(&seed());
        peer(Settings {
            libraries: LibrarySettings {
                issuers: TrustedIssuers::new([*issuer.public()]).unwrap(),
                ..LibrarySettings::default()
            },
            ..frasil_conformance::settings()
        })
        .await
    }

    /// A ticket the vectors' issuer signs, for an hour from the peer's
    /// wall clock.
    fn ticket(peer: &TestPeer, purpose: TicketPurpose, name: &str, id: u8) -> Vec<u8> {
        let issuer = Issuer::from_seed(&seed());
        let wall = peer.clock.now().wall.expect("the wall clock");
        issuer.sign(&Ticket {
            library: library(name),
            id: [id; 16],
            purpose,
            not_after: wall + 3600,
            issuer: *issuer.public(),
            tokens: None,
        })
    }

    /// Sends `LibraryAttach`: `Ok` for `Accepted`, `Err` with the code of
    /// `Refused`.
    async fn attach(
        device: &mut PeerClient,
        space: EventId,
        purpose: TicketPurpose,
        signed: Vec<u8>,
    ) -> Result<(), String> {
        let request = device.request();
        let message = LibraryAttach {
            request,
            space: *space.as_bytes(),
            purpose,
            signed,
        }
        .encode();
        device.request_answer(request, &message).await.map(|_| ())
    }

    /// Creates `history`'s space in a library by a ticket of this ID, and
    /// returns the founder's connection, which holds the store right.
    async fn create(
        peer: &TestPeer,
        binding: Binding,
        history: &History,
        name: &str,
        id: u8,
    ) -> PeerClient {
        let space = history.space();
        let genesis = history.order[0].clone();
        let mut device = connect(peer, binding, Purpose::SpaceTraffic).await;
        let signed = ticket(peer, TicketPurpose::Create, name, id);
        assert_eq!(
            attach(&mut device, space, TicketPurpose::Create, signed).await,
            Ok(())
        );
        assert!(
            device
                .store_one(space, &history.signed(&genesis), DEADLINE)
                .await
        );
        device
            .present(space, Credential::Upload, &history.upload_seed(&genesis))
            .await
            .expect("the genesis's upload key");
        device
    }

    /// One more unit, on a stream, by a writer key of its own whose only
    /// parent is the genesis: its store's answer. The peer judges no event,
    /// so any key's unit is stored under the connection's store right.
    async fn write(
        device: &mut PeerClient,
        history: &mut History,
        name: &str,
        on: &str,
    ) -> Option<Result<(), String>> {
        let space = history.space();
        let genesis = history.order[0].clone();
        let unit = history.unit(
            &format!("writer of {name}"),
            name,
            stream(on),
            Vec::new(),
            None,
            &[&genesis],
        );
        device.store_answer(space, &unit, DEADLINE).await
    }

    fn update() -> LibraryUpdate {
        LibraryUpdate::default()
    }

    async fn attaching(binding: Binding) {
        let peer = library_peer().await;
        let history = History::credentials();
        let space = history.space();
        let genesis = "P creates the space";
        let mut device = connect(&peer, binding, Purpose::SpaceTraffic).await;
        // The peer lists service 5.
        assert!(device.peer_hello.services().contains(&Service::Library));

        // A genesis with no attachment: the peer does not host the space.
        assert_eq!(
            device
                .store_answer(space, &history.signed(genesis), DEADLINE)
                .await,
            Some(Err("no_library".into()))
        );
        assert!(!peer.peer.hosts(space.as_bytes()));

        // A ticket of another purpose, and one from no trusted issuer.
        let moving = ticket(&peer, TicketPurpose::Move, "project:alpha", 1);
        assert_eq!(
            attach(&mut device, space, TicketPurpose::Create, moving).await,
            Err("ticket_refused".into())
        );
        let stranger = Issuer::from_seed(&[5; 32]).sign(&Ticket {
            library: library("project:alpha"),
            id: [1; 16],
            purpose: TicketPurpose::Create,
            not_after: peer.clock.now().wall.unwrap() + 3600,
            issuer: *Issuer::from_seed(&[5; 32]).public(),
            tokens: None,
        });
        assert_eq!(
            attach(&mut device, space, TicketPurpose::Create, stranger).await,
            Err("ticket_refused".into())
        );

        // A create: accepted, and the first event stored must be the
        // genesis.
        let signed = ticket(&peer, TicketPurpose::Create, "project:alpha", 1);
        assert_eq!(
            attach(&mut device, space, TicketPurpose::Create, signed.clone()).await,
            Ok(())
        );
        assert_eq!(peer.peer.library_tickets_used(), vec![[1; 16]]);
        assert_eq!(
            device
                .store_answer(space, &history.signed("P0: root"), DEADLINE)
                .await,
            Some(Err("not_authorized".into()))
        );
        assert!(
            device
                .store_one(space, &history.signed(genesis), DEADLINE)
                .await
        );
        let attachment = peer.peer.library_attachment(space.as_bytes()).unwrap();
        assert_eq!(attachment.library, library("project:alpha"));
        assert_eq!(attachment.ticket, Some([1; 16]));
        assert_eq!(attachment.at.timeline, START);
        device
            .present(space, Credential::Upload, &history.upload_seed(genesis))
            .await
            .unwrap();
        store_all(
            &mut device,
            space,
            history.events(&["P0: root", "P grants W write"]),
        )
        .await;

        // The ticket again, for another space: used.
        let other = History::skeleton();
        assert_eq!(
            attach(&mut device, other.space(), TicketPurpose::Create, signed).await,
            Err("ticket_used".into())
        );
        // A create, or an import, of a space the peer hosts.
        for (purpose, id) in [(TicketPurpose::Create, 2), (TicketPurpose::Import, 3)] {
            let signed = ticket(&peer, purpose, "project:alpha", id);
            assert_eq!(
                attach(&mut device, space, purpose, signed).await,
                Err("space_exists".into())
            );
        }
        // Refused tickets are not spent.
        assert_eq!(peer.peer.library_tickets_used(), vec![[1; 16]]);
        // An administration connection carries no type 21.
        let mut admin = connect(&peer, binding, Purpose::Administration).await;
        let signed = ticket(&peer, TicketPurpose::Create, "project:alpha", 4);
        let message = LibraryAttach {
            request: 1,
            space: *other.space().as_bytes(),
            purpose: TicketPurpose::Create,
            signed,
        }
        .encode();
        admin.send_control(&message).await;
        assert!(admin.closed(DEADLINE).await.is_some());
        device.close().await;
        peer.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn attaching_a_library_over_both_bindings() {
        within(async {
            for binding in BINDINGS {
                attaching(binding).await;
            }
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn suspending_moving_detaching_and_deleting() {
        within(async {
            let peer = library_peer().await;
            let alpha = library("project:alpha");
            let beta = library("personal:beta");
            let mut history = History::credentials();
            let space = history.space();
            let mut device = create(&peer, Binding::WebSocket, &history, "project:alpha", 1).await;
            assert_eq!(
                write(&mut device, &mut history, "a first unit", "notes").await,
                Some(Ok(()))
            );

            // A suspended library takes no store and no ticket.
            peer.peer
                .set_library(
                    &alpha,
                    LibraryUpdate {
                        state: Some(LibraryState::Suspended),
                        ..update()
                    },
                )
                .unwrap();
            assert_eq!(
                write(&mut device, &mut history, "a suspended unit", "notes").await,
                Some(Err("library_closed".into()))
            );
            // A release is never refused for a library.
            let released = history.storage(
                "a releasing writer",
                "drafts released",
                &release(stream("drafts")),
                &["P creates the space"],
            );
            assert_eq!(
                device.store_answer(space, &released, DEADLINE).await,
                Some(Ok(()))
            );
            let other = History::skeleton();
            let mut second = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let signed = ticket(&peer, TicketPurpose::Create, "project:alpha", 2);
            assert_eq!(
                attach(&mut second, other.space(), TicketPurpose::Create, signed).await,
                Err("library_closed".into())
            );
            peer.peer
                .set_library(
                    &alpha,
                    LibraryUpdate {
                        state: Some(LibraryState::Open),
                        ..update()
                    },
                )
                .unwrap();

            // The library's quota covers its spaces.
            let used = peer.peer.usage(space.as_bytes()).unwrap();
            peer.peer
                .set_library(
                    &alpha,
                    LibraryUpdate {
                        quota: Some(Some(used)),
                        ..update()
                    },
                )
                .unwrap();
            assert_eq!(
                write(&mut device, &mut history, "a unit past the quota", "notes").await,
                Some(Err("quota_exceeded".into()))
            );
            assert_eq!(peer.peer.ledger(&alpha).unwrap().headroom_bytes(), Some(0));

            // A move without the store right, then to a library without
            // headroom: neither spends its ticket.
            let to_beta = ticket(&peer, TicketPurpose::Move, "personal:beta", 3);
            assert_eq!(
                attach(&mut second, space, TicketPurpose::Move, to_beta.clone()).await,
                Err("not_authorized".into())
            );
            peer.peer
                .set_library(
                    &beta,
                    LibraryUpdate {
                        quota: Some(Some(used - 1)),
                        ..update()
                    },
                )
                .unwrap();
            assert_eq!(
                attach(&mut device, space, TicketPurpose::Move, to_beta.clone()).await,
                Err("quota_exceeded".into())
            );
            assert_eq!(peer.peer.library_tickets_used(), vec![[1; 16]]);
            peer.peer
                .set_library(
                    &beta,
                    LibraryUpdate {
                        quota: Some(None),
                        ..update()
                    },
                )
                .unwrap();
            peer.clock.advance(5);
            assert_eq!(
                attach(&mut device, space, TicketPurpose::Move, to_beta).await,
                Ok(())
            );
            let attachment = peer.peer.library_attachment(space.as_bytes()).unwrap();
            assert_eq!(
                (attachment.library.clone(), attachment.ticket),
                (beta.clone(), Some([3; 16]))
            );
            assert_eq!(attachment.at.timeline, START + 5);
            // The space's usage left alpha's ledger and joined beta's.
            assert!(peer.peer.ledger(&alpha).unwrap().spaces.is_empty());
            assert_eq!(peer.peer.ledger(&beta).unwrap().used_bytes(), used);
            assert_eq!(
                write(&mut device, &mut history, "a unit in beta", "notes").await,
                Some(Ok(()))
            );

            // Detached, the space takes no store and still serves fetches.
            assert!(peer.peer.detach(space.as_bytes()).unwrap());
            assert_eq!(
                write(&mut device, &mut history, "a detached unit", "notes").await,
                Some(Err("no_library".into()))
            );
            let granted = second
                .present(
                    space,
                    Credential::Read,
                    &history.read_seed("P creates the space"),
                )
                .await
                .expect("a read credential of a detached space");
            assert_eq!(granted.rights, vec![Right::Fetch, Right::Live]);
            assert!(peer.peer.ledger(&beta).unwrap().spaces.is_empty());
            assert!(peer.peer.detached_past_grace().is_empty());
            peer.clock.advance(30 * 86_400);
            assert_eq!(peer.peer.detached_past_grace(), vec![*space.as_bytes()]);
            // Any writer attaches it again by a move.
            let back = ticket(&peer, TicketPurpose::Move, "project:alpha", 4);
            peer.peer
                .set_library(
                    &alpha,
                    LibraryUpdate {
                        quota: Some(None),
                        ..update()
                    },
                )
                .unwrap();
            assert_eq!(
                attach(&mut device, space, TicketPurpose::Move, back).await,
                Ok(())
            );
            assert!(peer.peer.detached_past_grace().is_empty());
            assert_eq!(
                write(&mut device, &mut history, "a unit back in alpha", "notes").await,
                Some(Ok(()))
            );

            // The operator deletes the space: a create of it is accepted, as
            // for any space, and its genesis is refused erased, which lapses
            // the create; an import is allowed.
            assert!(peer.peer.delete_space(space.as_bytes()).await.unwrap());
            assert!(!peer.peer.hosts(space.as_bytes()));
            assert!(peer.peer.library_attachment(space.as_bytes()).is_none());
            let mut third = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let signed = ticket(&peer, TicketPurpose::Create, "project:alpha", 5);
            assert_eq!(
                attach(&mut third, space, TicketPurpose::Create, signed).await,
                Ok(())
            );
            let genesis = history.signed("P creates the space");
            assert_eq!(
                third.store_answer(space, &genesis, DEADLINE).await,
                Some(Err("erased".into()))
            );
            assert!(!peer.peer.hosts(space.as_bytes()));
            let signed = ticket(&peer, TicketPurpose::Import, "project:alpha", 6);
            assert_eq!(
                attach(&mut third, space, TicketPurpose::Import, signed).await,
                Ok(())
            );
            store_all(&mut third, space, history.events(&["P creates the space"])).await;
            assert!(peer.peer.hosts(space.as_bytes()));

            // An erasure timeout outside its range changes nothing.
            assert!(
                peer.peer
                    .set_library(
                        &alpha,
                        LibraryUpdate {
                            erasure_timeout: Some(60),
                            ..update()
                        },
                    )
                    .is_err()
            );
            device.close().await;
            second.close().await;
            third.close().await;
            peer.shutdown().await;
        })
        .await;
    }

    fn status(status: EntryStatus) -> &'static str {
        match status {
            EntryStatus::Live => "live",
            EntryStatus::Retired => "retired",
        }
    }

    async fn importing(binding: Binding) {
        let vectors = family("import");
        let peer = library_peer().await;
        let mut history = History::of_file(FILE, "import", "library/import");
        let space = history.space();
        let removal = "P removes W";
        let racing = "W rotates, racing its removal";
        let mut importer = connect(&peer, binding, Purpose::SpaceTraffic).await;

        // A store before the attachment, and an import whose first event
        // is not the genesis.
        let signed = ticket(&peer, TicketPurpose::Import, "project:alpha", 1);
        assert_eq!(
            attach(&mut importer, space, TicketPurpose::Import, signed).await,
            Ok(())
        );
        assert_eq!(
            importer
                .store_answer(space, &history.signed("P0: root"), DEADLINE)
                .await,
            Some(Err("not_authorized".into()))
        );
        // The log, genesis first: every rotation's entry starts retired,
        // source `import`.
        store_all(&mut importer, space, history.all()).await;
        let entries = peer.peer.entries(space.as_bytes()).unwrap();
        assert_eq!(entries.len(), 4);
        assert!(
            entries
                .iter()
                .all(|e| !e.is_live() && e.source.name() == "import")
        );

        // The importer presents the upload key of its view's current
        // state: that entry alone goes live.
        let granted = importer
            .present(space, Credential::Upload, &history.upload_seed(removal))
            .await
            .expect("the importer's upload key");
        assert_eq!(granted.rights, vec![Right::Store, Right::Release]);
        let entries = peer.peer.entries(space.as_bytes()).unwrap();
        let described: Vec<Json> = entries
            .iter()
            .map(|e| {
                json!({
                    "state": e.state.ids().iter().map(|&id| history.name(id).unwrap().to_owned()).collect::<Vec<_>>(),
                    "read": frasil_testkit::hex::encode(e.read),
                    "upload": frasil_testkit::hex::encode(e.upload),
                    "status": status(e.status),
                    "source": e.source.name(),
                    "proved": e.proved,
                })
            })
            .collect();
        assert_eq!(Json::from(described), vectors["entries"]);

        // The removed writer's racing rotation stays retired: on another
        // connection its upload key is refused, its read credential grants
        // catch-up.
        let mut writer = connect(&peer, binding, Purpose::SpaceTraffic).await;
        assert_eq!(
            writer
                .present(space, Credential::Upload, &history.upload_seed(racing))
                .await
                .unwrap_err(),
            "credential_refused"
        );
        let caught = writer
            .present(space, Credential::Read, &history.read_seed(racing))
            .await
            .unwrap();
        assert_eq!(caught.rights, vec![Right::CatchUp]);

        // The importer's first store outside the log ends the import: a
        // retired import entry no longer goes live on its connection.
        let unit = history.unit(
            "P",
            "P writes after the import",
            stream("notes"),
            Vec::new(),
            None,
            &[removal],
        );
        assert!(importer.store_one(space, &unit, DEADLINE).await);
        assert_eq!(
            importer
                .present(
                    space,
                    Credential::Upload,
                    &history.upload_seed("P grants W write")
                )
                .await
                .unwrap_err(),
            "credential_refused"
        );
        let attachment = peer.peer.library_attachment(space.as_bytes()).unwrap();
        assert_eq!(attachment.library, library("project:alpha"));
        // A second import of the hosted space.
        let signed = ticket(&peer, TicketPurpose::Import, "project:alpha", 2);
        assert_eq!(
            attach(&mut writer, space, TicketPurpose::Import, signed).await,
            Err("space_exists".into())
        );
        importer.close().await;
        writer.close().await;
        peer.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn importing_a_log_over_both_bindings() {
        within(async {
            for binding in BINDINGS {
                importing(binding).await;
            }
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_ledger_follows_its_spaces() {
        within(async {
            let peer = library_peer().await;
            let alpha = library("project:ledger");
            let mut first = History::credentials();
            let mut second = History::skeleton();
            let mut a = create(&peer, Binding::WebSocket, &first, "project:ledger", 1).await;
            let mut b = create(&peer, Binding::Iroh, &second, "project:ledger", 2).await;
            for (i, on) in ["notes", "notes", "photos"].iter().enumerate() {
                assert_eq!(
                    write(&mut a, &mut first, &format!("unit {i}"), on).await,
                    Some(Ok(()))
                );
            }
            assert_eq!(
                write(&mut b, &mut second, "b's unit", "notes").await,
                Some(Ok(()))
            );
            let usage = |history: &History| peer.peer.usage(history.space().as_bytes()).unwrap();
            let ledger = peer.peer.ledger(&alpha).unwrap();
            assert_eq!(ledger.used_bytes(), usage(&first) + usage(&second));
            assert_eq!(ledger.headroom_bytes(), None);
            assert_eq!(ledger.settings.erasure_timeout, 7 * 86_400);
            let document = ledger.json();
            assert_eq!(document["library"], "project:ledger");
            assert_eq!(document["state"], "open");
            assert_eq!(document["quota_bytes"], Json::Null);
            let wall = peer.clock.now().wall.unwrap();
            let row = document["spaces"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["space"] == frasil_testkit::hex::encode(first.space().as_bytes()))
                .unwrap()
                .clone();
            assert_eq!(row["streams"], 2);
            assert_eq!(row["used_bytes"], usage(&first));
            assert_eq!(row["drops"], 0);
            assert_eq!(row["last_store_day"], frasil_relay::libraries::day(wall));

            // A release: the stream's bytes leave used_bytes and count as
            // released.
            let before = usage(&first);
            let space = first.space();
            let released = first.storage(
                "a releasing writer",
                "photos released",
                &release(stream("photos")),
                &["P creates the space"],
            );
            assert!(a.store_one(space, &released, DEADLINE).await);
            let ledger = peer.peer.ledger(&alpha).unwrap();
            let usage_a = ledger
                .spaces
                .iter()
                .find(|s| s.space == *space.as_bytes())
                .unwrap()
                .usage
                .clone();
            assert!(usage_a.released_bytes > 0);
            assert_eq!(
                usage_a.used_bytes() + usage_a.released_bytes,
                before + released.len() as u64
            );
            assert_eq!(usage_a.streams, 2);

            // The quota covers both spaces.
            let used = ledger.used_bytes();
            peer.peer
                .set_library(
                    &alpha,
                    LibraryUpdate {
                        quota: Some(Some(used + 10)),
                        ..LibraryUpdate::default()
                    },
                )
                .unwrap();
            assert_eq!(peer.peer.ledger(&alpha).unwrap().headroom_bytes(), Some(10));
            assert_eq!(
                write(&mut b, &mut second, "b's unit past the quota", "notes").await,
                Some(Err("quota_exceeded".into()))
            );
            // A move to another library takes the space's usage with it.
            let to = ticket(&peer, TicketPurpose::Move, "personal:other", 3);
            assert_eq!(
                attach(&mut b, second.space(), TicketPurpose::Move, to).await,
                Ok(())
            );
            let moved = usage(&second);
            assert_eq!(peer.peer.ledger(&alpha).unwrap().used_bytes(), used - moved);
            assert_eq!(
                peer.peer
                    .ledger(&library("personal:other"))
                    .unwrap()
                    .used_bytes(),
                moved
            );
            assert_eq!(
                write(&mut b, &mut second, "b's unit in its own library", "notes").await,
                Some(Ok(()))
            );
            assert_eq!(peer.peer.ledgers().len(), 2);
            a.close().await;
            b.close().await;
            peer.shutdown().await;
        })
        .await;
    }

    /// Stability at the peer under a library's `erasure_timeout`: an event
    /// that waits on its administrators is stable once the library's T has
    /// passed since its first sight, not the peer's.
    #[tokio::test(flavor = "multi_thread")]
    async fn stability_counts_the_librarys_erasure_timeout() {
        within(async {
            let peer = library_peer().await;
            let alpha = library("project:alpha");
            let history = History::skeleton();
            let space = history.space();
            let mut device = create(&peer, Binding::WebSocket, &history, "project:alpha", 1).await;
            // A request that waits on A's acknowledgement of its removal,
            // and leaves the space hosted once carried out.
            device
                .store(
                    space,
                    history.through("P0 asks for the current credentials")[1..].to_vec(),
                    DEADLINE,
                )
                .await;
            let request = history.id("P0 asks for the current credentials");
            let stable = |peer: &TestPeer| {
                peer.peer
                    .stability(space.as_bytes(), request.as_bytes())
                    .expect("a hosted space")
                    .0
            };
            assert!(!stable(&peer));
            peer.peer
                .set_library(
                    &alpha,
                    LibraryUpdate {
                        erasure_timeout: Some(3600),
                        ..update()
                    },
                )
                .unwrap();
            peer.set_time(START + 3599).await;
            assert!(!stable(&peer));
            // The peer's own T is 7 days; the library's is an hour.
            peer.set_time(START + 3600).await;
            assert!(stable(&peer));
            device.close().await;
            peer.shutdown().await;
        })
        .await;
    }

    /// An import's stores are exempt from the per-author rate: the log it
    /// imports may hold more of one author's space events than an hour
    /// allows, bounded by the library's quota and the import window.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_import_is_exempt_from_the_per_author_rate() {
        within(async {
            let issuer = Issuer::from_seed(&seed());
            let peer = peer(Settings {
                libraries: LibrarySettings {
                    issuers: TrustedIssuers::new([*issuer.public()]).unwrap(),
                    ..LibrarySettings::default()
                },
                rates: frasil_relay::Rates {
                    space_events_per_hour: 1,
                    ..frasil_relay::Rates::DEFAULT
                },
                ..frasil_conformance::settings()
            })
            .await;
            let history = History::of_file(FILE, "import", "library/import");
            let space = history.space();
            let mut importer = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let signed = ticket(&peer, TicketPurpose::Import, "project:alpha", 1);
            assert_eq!(
                attach(&mut importer, space, TicketPurpose::Import, signed).await,
                Ok(())
            );
            // P's grant of W and its removal of W, within one hour.
            store_all(&mut importer, space, history.all()).await;
            importer.close().await;
            peer.shutdown().await;
        })
        .await;
    }

    /// transport.md, 3.10, "Reconnecting elsewhere": a stopping peer waits
    /// for a create pending on a connection, and closes it with
    /// `reconnect` once its genesis is stored; another connection closes so
    /// at once. One whose create stays pending past `reconnect_drain` is
    /// dropped, with no close code.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stopping_peer_waits_for_a_pending_create() {
        within(async {
            let peer = library_peer().await;
            let history = History::credentials();
            let space = history.space();
            let mut idle = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let mut creating = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let signed = ticket(&peer, TicketPurpose::Create, "project:alpha", 1);
            assert_eq!(
                attach(&mut creating, space, TicketPurpose::Create, signed).await,
                Ok(())
            );
            let stopping = {
                let peer = peer.peer.clone();
                tokio::spawn(async move {
                    peer.stop_connections(std::time::Duration::from_secs(30))
                        .await
                })
            };
            assert_eq!(idle.closed(DEADLINE).await, Some(Some(4017)));
            assert_eq!(creating.closed(QUIET).await, None, "the create is pending");
            let genesis = history.signed(&history.order[0]);
            assert!(creating.store_one(space, &genesis, DEADLINE).await);
            assert_eq!(creating.closed(DEADLINE).await, Some(Some(4017)));
            within(stopping).await.unwrap();
            peer.shutdown().await;

            // Past the drain, the connection is dropped.
            let peer = library_peer().await;
            let mut creating = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let signed = ticket(&peer, TicketPurpose::Create, "project:alpha", 2);
            assert_eq!(
                attach(&mut creating, space, TicketPurpose::Create, signed).await,
                Ok(())
            );
            peer.peer
                .stop_connections(std::time::Duration::from_millis(300))
                .await;
            let closed = creating.closed(DEADLINE).await;
            assert!(closed.is_some() && closed != Some(Some(4017)), "{closed:?}");
            peer.shutdown().await;
        })
        .await;
    }

    const TOKEN: &str = "operator-token-of-the-settings-test";

    /// The settings route on `peer`: its status and JSON body. `change` is
    /// a `PUT`'s body; none is a `GET`.
    async fn settings_route(
        peer: &TestPeer,
        library: &str,
        change: Option<Json>,
        token: &str,
    ) -> (u16, Json) {
        let client = frasil_conformance::http_client();
        let url = format!("{}/frasil/p1/libraries/{library}/settings", peer.origin);
        let request = match change {
            Some(change) => client.put(url).body(change.to_string()),
            None => client.get(url),
        };
        let response = request
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap_or(Json::Null);
        (status, body)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_settings_route_suspends_reopens_and_bounds_a_library_in_time() {
        within(async {
            let issuer = Issuer::from_seed(&seed());
            let peer = peer(Settings {
                libraries: LibrarySettings {
                    issuers: TrustedIssuers::new([*issuer.public()]).unwrap(),
                    operator_token: Some(
                        frasil_relay::libraries::OperatorToken::new(TOKEN).unwrap(),
                    ),
                    ..LibrarySettings::default()
                },
                ..frasil_conformance::settings()
            })
            .await;
            let mut history = History::credentials();
            let mut device = create(&peer, Binding::WebSocket, &history, "project:alpha", 1).await;
            assert_eq!(
                write(&mut device, &mut history, "a first unit", "notes").await,
                Some(Ok(()))
            );
            let wall = peer.clock.now().wall.expect("the wall clock");

            // Only the operator's token reads or sets anything.
            let (status, _) =
                settings_route(&peer, "project:alpha", None, "not-the-operator-token").await;
            assert_eq!(status, 401);
            let (status, body) = settings_route(&peer, "project:alpha", None, TOKEN).await;
            assert_eq!(status, 200);
            assert_eq!(body["state"], "open");
            assert_eq!(body["open_until"], Json::Null);
            assert_eq!(body["open"], true);
            let (status, _) = settings_route(&peer, "project:unknown", None, TOKEN).await;
            assert_eq!(status, 404);
            for bad in [
                json!({"colour": "blue"}),
                json!({"state": "closed"}),
                json!({"open_until": "soon"}),
                json!({"erasure_timeout": 1}),
                json!([1]),
            ] {
                let (status, body) =
                    settings_route(&peer, "project:alpha", Some(bad.clone()), TOKEN).await;
                assert_eq!((status, &body["code"]), (400, &json!("malformed")), "{bad}");
            }

            // Suspended by its state: no store and no ticket, then open again
            // and storing, the space attached throughout.
            let (status, body) = settings_route(
                &peer,
                "project:alpha",
                Some(json!({"state": "suspended"})),
                TOKEN,
            )
            .await;
            assert_eq!((status, &body["open"]), (200, &json!(false)));
            assert_eq!(
                write(&mut device, &mut history, "a suspended unit", "notes").await,
                Some(Err("library_closed".into()))
            );
            let other = History::skeleton();
            let mut second = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let signed = ticket(&peer, TicketPurpose::Create, "project:alpha", 2);
            assert_eq!(
                attach(&mut second, other.space(), TicketPurpose::Create, signed).await,
                Err("library_closed".into())
            );
            let (status, body) = settings_route(
                &peer,
                "project:alpha",
                Some(json!({"state": "open"})),
                TOKEN,
            )
            .await;
            assert_eq!((status, &body["open"]), (200, &json!(true)));
            assert_eq!(
                write(&mut device, &mut history, "a reopened unit", "notes").await,
                Some(Ok(()))
            );

            // Bounded in time: open until the instant, closed from it with
            // no further write, and open again once the bound moves on.
            let (status, body) = settings_route(
                &peer,
                "project:alpha",
                Some(json!({"open_until": wall + 60})),
                TOKEN,
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(body["state"], "open");
            assert_eq!(body["open_until"], wall + 60);
            assert_eq!(body["open"], true);
            assert_eq!(
                write(
                    &mut device,
                    &mut history,
                    "a unit before the bound",
                    "notes"
                )
                .await,
                Some(Ok(()))
            );
            peer.clock.advance(60);
            let (_, body) = settings_route(&peer, "project:alpha", None, TOKEN).await;
            assert_eq!(body["open"], false);
            assert_eq!(
                write(&mut device, &mut history, "a unit at the bound", "notes").await,
                Some(Err("library_closed".into()))
            );
            let signed = ticket(&peer, TicketPurpose::Create, "project:alpha", 3);
            assert_eq!(
                attach(&mut second, other.space(), TicketPurpose::Create, signed).await,
                Err("library_closed".into())
            );
            let (status, body) = settings_route(
                &peer,
                "project:alpha",
                Some(json!({"open_until": wall + 3600})),
                TOKEN,
            )
            .await;
            assert_eq!((status, &body["open"]), (200, &json!(true)));
            assert_eq!(
                write(&mut device, &mut history, "a unit after renewal", "notes").await,
                Some(Ok(()))
            );
            let (_, body) = settings_route(
                &peer,
                "project:alpha",
                Some(json!({"open_until": null, "quota_bytes": 1_000_000_000u64})),
                TOKEN,
            )
            .await;
            assert_eq!(body["open_until"], Json::Null);
            assert_eq!(body["quota_bytes"], 1_000_000_000u64);
            assert_eq!(body["state"], "open");

            // A library not yet known is created bounded, before its first
            // ticket, and its first ticket is refused once the bound passed.
            let (status, body) = settings_route(
                &peer,
                "project:later",
                Some(json!({"open_until": 1})),
                TOKEN,
            )
            .await;
            assert_eq!((status, &body["open"]), (200, &json!(false)));
            let signed = ticket(&peer, TicketPurpose::Create, "project:later", 4);
            assert_eq!(
                attach(&mut second, other.space(), TicketPurpose::Create, signed).await,
                Err("library_closed".into())
            );
            device.close().await;
            second.close().await;
            peer.shutdown().await;
        })
        .await;
    }
}
