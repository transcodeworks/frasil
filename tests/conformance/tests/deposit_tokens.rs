//! ext-deposit-tokens.md's scenarios against a live peer: tokens drawn by
//! grant and as a writer of a space, kept at a device across a restart,
//! spent on the WebSocket, over iroh and by `POST`, repeated, refused,
//! carried across key periods, kept apart from the anonymous budget, and
//! drawn on connections that show the peer nothing else. They run, with
//! the feature `ext-deposit-tokens`, against peers with the extension on,
//! which trust an issuer these tests hold. In every build, a peer with the
//! extension off lists no service 6, closes a connection that sends types
//! 40 to 43 or `MailboxPut` key 7, and takes a `POST` deposit with a token
//! header as an anonymous one, as a core peer does.

mod common;

use common::*;
use frasil_base::cbor::Value;
use frasil_relay::Settings;
use frasil_transport::mailbox::{self, Kind};
use frasil_transport::peer::{Purpose, mailbox_path};

/// A WebSocket close code, or a QUIC application code, for `class`.
fn close_code(binding: Binding, code: frasil_transport::Code) -> Option<u64> {
    Some(match binding {
        Binding::WebSocket => u64::from(code.websocket()),
        Binding::Iroh => code.number(),
    })
}

/// A deterministic CBOR map of these keys.
fn map(entries: Vec<(u64, Value)>) -> Vec<u8> {
    Value::Map(entries.into_iter().collect()).encode()
}

/// A mailbox address that names no device the tests hold.
fn address(n: u8) -> [u8; 32] {
    mailbox::address(Kind::Device, &[n; 32])
}

/// ext-deposit-tokens.md, "A core implementation that does not implement
/// it", and AGENTS.md's rule for an extension that is off: the peer is a
/// core peer.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_with_the_extension_off_answers_as_a_core_peer() {
    within(async {
        let settings = Settings {
            extensions: frasil_relay::Extensions {
                deposit_tokens: false,
                ..frasil_conformance::EXTENSIONS
            },
            ..frasil_conformance::settings()
        };
        let peer = peer(settings).await;
        assert!(!peer.peer.extensions().deposit_tokens);
        let malformed = frasil_transport::Code::Malformed;
        for binding in BINDINGS {
            let device = connect(&peer, binding, Purpose::SpaceTraffic).await;
            assert!(
                !device
                    .peer_hello
                    .services()
                    .contains(&frasil_transport::codes::Service::Deposit),
                "{binding:?}: no service 6"
            );
            drop(device);
            // Types 40 to 43 close the connection as unknown types.
            let messages = [
                map(vec![(0, Value::Unsigned(40)), (1, Value::Unsigned(1))]),
                map(vec![
                    (0, Value::Unsigned(41)),
                    (1, Value::Unsigned(1)),
                    (2, Value::Array(Vec::new())),
                ]),
                map(vec![
                    (0, Value::Unsigned(42)),
                    (1, Value::Unsigned(1)),
                    (3, Value::Bytes(vec![1; 32])),
                    (4, Value::Array(vec![Value::Bytes(vec![2; 32])])),
                    (5, Value::Bytes(vec![3; 32])),
                ]),
                map(vec![
                    (0, Value::Unsigned(43)),
                    (1, Value::Unsigned(1)),
                    (2, Value::Array(vec![Value::Bytes(vec![2; 32])])),
                    (3, Value::Bytes(vec![4; 64])),
                ]),
            ];
            for (n, message) in messages.iter().enumerate() {
                let mut device = connect(&peer, binding, Purpose::SpaceTraffic).await;
                device.send_control(message).await;
                assert_eq!(
                    device.closed(DEADLINE).await,
                    Some(close_code(binding, malformed)),
                    "{binding:?}: type {}",
                    40 + n
                );
            }
            // `MailboxPut` key 7 is an unknown key: `malformed`.
            let mut device = connect(&peer, binding, Purpose::SpaceTraffic).await;
            let put = map(vec![
                (0, Value::Unsigned(24)),
                (1, Value::Unsigned(1)),
                (2, Value::Bytes(address(1).to_vec())),
                (3, Value::Bytes(vec![0xab; 64])),
                (6, Value::Unsigned(3)),
                (7, Value::Bytes(vec![1; 129])),
            ]);
            device.send_control(&put).await;
            assert_eq!(
                device.closed(DEADLINE).await,
                Some(close_code(binding, malformed)),
                "{binding:?}: key 7"
            );
        }
        // A `POST` with a token's header is an anonymous deposit.
        let header = format!("Frasil-Token {}", "01".repeat(129));
        let response = frasil_conformance::http_client()
            .post(format!("{}{}", peer.origin, mailbox_path(3, &address(2))))
            .header("Authorization", header)
            .body(vec![0xab; 64])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 201);
        // Discovery lists neither the service nor keys.
        let document: serde_json::Value = frasil_conformance::http_client()
            .get(format!("{}/.well-known/frasil", peer.origin))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            !document["services"]
                .as_array()
                .unwrap()
                .contains(&"deposit".into())
        );
        assert!(document.get("deposit_keys").is_none());
        peer.shutdown().await;
    })
    .await;
}

#[cfg(feature = "ext-deposit-tokens")]
mod with_tokens {
    use super::*;
    use common::tokens::*;
    use frasil::advanced::ManualClock;
    use frasil::{Device, Event, Options, Storage};
    use frasil_conformance::history::History;
    use frasil_deposit_tokens::{Batch, Draw, Role, Token, TokenKeysGet};
    use frasil_libraries::LibraryId;
    use frasil_relay::libraries::LibraryUpdate;
    use frasil_relay::testing::{OPEN_LIBRARY, Shown, TestPeer};
    use frasil_transport::frame::MessageType;
    use std::sync::Arc;
    use std::time::Duration;

    /// A device on the server binding, with its own clock, kept in `dir`.
    pub(super) async fn device(dir: &std::path::Path, clock: &Arc<ManualClock>) -> Device {
        let options = Options::new()
            .loopback()
            .never_restored()
            .clock(clock.clone());
        Device::open_with(Storage::directory(dir), &[0x42; 32], options)
            .await
            .unwrap()
    }

    pub(super) fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("conformance-tokens-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A device's clock, an hour of whose timeline the tests pass at once.
    pub(super) fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock::new(1_000, Some(1_800_000_000)))
    }

    /// Lets the device's draws come due: the next hour of its timeline.
    pub(super) async fn an_hour_later(device: &Device, clock: &ManualClock) {
        device.deposit_upkeep().await;
        clock.advance(HOUR + 1);
        device.deposit_upkeep().await;
    }

    /// The connections that drew, deposited with a token, or presented.
    pub(super) fn drawing(shown: &[Shown]) -> Vec<&Shown> {
        shown.iter().filter(|c| !c.draws.is_empty()).collect()
    }

    pub(super) fn paying(shown: &[Shown]) -> Vec<&Shown> {
        shown
            .iter()
            .filter(|c| c.deposits.iter().any(|(_, token)| token.is_some()))
            .collect()
    }

    /// Asserts that a connection shows the peer nothing but its `Hello`
    /// and the kinds `allowed`: no credential, collection or bearer token.
    pub(super) fn shows_nothing_else(shown: &Shown, allowed: &[MessageType]) {
        assert!(!shown.credentialed, "{shown:?}: a cookie or Authorization");
        assert!(shown.presented.is_empty(), "{shown:?}: a Present");
        assert!(shown.collected.is_empty(), "{shown:?}: a collection");
        assert_eq!(shown.kinds.first(), Some(&MessageType::Hello), "{shown:?}");
        for kind in &shown.kinds[1..] {
            assert!(allowed.contains(kind), "{shown:?}: {kind:?}");
        }
    }

    /// ext-deposit-tokens.md, 3.1.1, 3.3 to 3.6 and 3.12: a device handed
    /// a grant draws one batch within the hour, on a connection that shows
    /// the grant alone, after learning the keys on one that shows nothing;
    /// the issuer's grant is used once and counted in the ledger; the
    /// tokens are kept at rest and survive a restart; and a deposit spends
    /// one on a connection of its own.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_grant_draw_end_to_end_keeps_its_tokens_across_a_restart() {
        within(async {
            let peer = peer(token_settings()).await;
            let watch = peer.peer.watch();
            let dir = temp_dir("grant");
            let clock = clock();
            let alice = device(&dir, &clock).await;
            alice.give_deposit_grant(&peer.origin, grant(&peer, 16, 1));
            alice.deposit_upkeep().await;
            assert_eq!(
                alice.deposit_tokens(&peer.origin).await.held,
                0,
                "never at once"
            );
            an_hour_later(&alice, &clock).await;
            let tokens = alice.deposit_tokens(&peer.origin).await;
            assert_eq!(tokens.held, 16);
            assert!(!tokens.grant, "a grant draws once");
            // The keys came on a connection that showed nothing; the draw on
            // another that showed the grant alone.
            let shown = watch.connections();
            let draws = drawing(&shown);
            assert_eq!(draws.len(), 1);
            assert_eq!(draws[0].draws, [None]);
            shows_nothing_else(draws[0], &[MessageType::TokenRequest]);
            assert!(
                shown
                    .iter()
                    .any(|c| c.kinds == [MessageType::Hello, MessageType::TokenKeysGet])
            );
            // The grant is used, and the library's ledger counts the batch.
            let mut stranger = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let list = keys(&mut stranger).await;
            let again = draw(&mut stranger, &list, Draw::Grant(grant(&peer, 16, 1)), 1).await;
            assert_eq!(again.unwrap_err(), "ticket_used");
            stranger.close().await;
            let ledger = peer.peer.ledger(&LibraryId::new(LIBRARY).unwrap()).unwrap();
            assert_eq!(ledger.deposit.unwrap().tokens_drawn, 16);
            // A restart keeps the tokens.
            alice.close().await.unwrap();
            drop(alice);
            let alice = device(&dir, &clock).await;
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 16);
            // A deposit pays with one, on a connection of its own.
            let bob = recipient(1);
            alice
                .deposit_item(&peer.origin, bob.id, b"a sealed welcome".to_vec())
                .await
                .unwrap();
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 15);
            let shown = watch.connections();
            let paid = paying(&shown);
            assert_eq!(paid.len(), 1);
            assert_eq!(paid[0].deposits.len(), 1);
            assert_eq!(paid[0].deposits[0].0, bob.address);
            shows_nothing_else(
                paid[0],
                &[MessageType::MailboxPut, MessageType::TokenKeysGet],
            );
            assert_eq!(peer.peer.spent_tokens().unwrap().len(), 1);
            // The item is collected like any other.
            let items = collect(&peer, &bob).await;
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].1, b"a sealed welcome");
            alice.close().await.unwrap();
            peer.shutdown().await;
        })
        .await;
    }

    /// ext-deposit-tokens.md, 3.4 and 3.5, against the peer: a grant draw
    /// over each binding, its `TokenIssue` proved under the published key
    /// and not under any other batch, the grant used once, and a batch past
    /// the grant refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_grant_draw_is_proved_under_the_published_key_on_both_bindings() {
        within(async {
            let peer = peer(token_settings()).await;
            for (n, binding) in BINDINGS.into_iter().enumerate() {
                let id = 10 + n as u8;
                let mut device = connect(&peer, binding, Purpose::SpaceTraffic).await;
                let list = keys(&mut device).await;
                assert_eq!(list.keys().len(), 1);
                assert_eq!(list.issuing().role, Role::Issuing);
                // More elements than the grant names: `ticket_refused`, and
                // the grant stays unused.
                let refused = draw(&mut device, &list, Draw::Grant(grant(&peer, 2, id)), 3).await;
                assert_eq!(refused.unwrap_err(), "ticket_refused", "{binding:?}");
                // Within it: three tokens whose proof holds.
                let batch = Batch::new(list.issuing(), 3).unwrap();
                let request = device.request();
                let message = batch
                    .request(request, Draw::Grant(grant(&peer, 3, id)))
                    .encode();
                device.send_control(&message).await;
                let answer = answer_to(&mut device, request).await;
                assert_eq!(answer.kind, MessageType::TokenIssue, "{binding:?}");
                assert_eq!(batch.finish(&answer.map, request).unwrap().len(), 3);
                // The proof is over these blinded elements: another batch's
                // check of it fails.
                let other = Batch::new(list.issuing(), 3).unwrap();
                assert_eq!(
                    other.finish(&answer.map, request).unwrap_err(),
                    frasil_deposit_tokens::TokenClass::BadProof
                );
                // The grant is used now.
                let again = draw(&mut device, &list, Draw::Grant(grant(&peer, 3, id)), 1).await;
                assert_eq!(again.unwrap_err(), "ticket_used", "{binding:?}");
            }
            peer.shutdown().await;
        })
        .await;
    }

    /// ext-deposit-tokens.md, 3.7: a token deposit over the WebSocket, over
    /// iroh and by `POST`; its repeat accepted with the same item ID;
    /// another item with the same token `token_spent`; a forged token
    /// `token_refused`; a token of version 2 `unsupported_version` on the
    /// `POST` route; and each item collected like any other.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_pays_once_on_every_binding() {
        within(async {
            let peer = peer(token_settings()).await;
            let mut drawer = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let list = keys(&mut drawer).await;
            let mut tokens = draw(&mut drawer, &list, Draw::Grant(grant(&peer, 16, 1)), 16)
                .await
                .unwrap();
            drawer.close().await;
            for (n, binding) in BINDINGS.into_iter().enumerate() {
                let bob = recipient(n as u32);
                let token = tokens.pop().unwrap();
                let mut depositor = connect(&peer, binding, Purpose::SpaceTraffic).await;
                assert_eq!(
                    spend(&mut depositor, bob.address, b"one", &token).await,
                    Ok(())
                );
                // The answer was lost: the same deposit, again.
                let mut again = connect(&peer, binding, Purpose::SpaceTraffic).await;
                assert_eq!(spend(&mut again, bob.address, b"one", &token).await, Ok(()));
                assert_eq!(
                    spend(&mut again, bob.address, b"two", &token).await,
                    Err("token_spent".into()),
                    "{binding:?}"
                );
                assert_eq!(
                    spend(&mut again, bob.address, b"two", &forged(&tokens[0])).await,
                    Err("token_refused".into()),
                    "{binding:?}"
                );
                let items = collect(&peer, &bob).await;
                assert_eq!(items.len(), 1, "{binding:?}: kept once");
                assert_eq!(items[0].1, b"one");
            }
            // By `POST`.
            let carol = recipient(7);
            let token = tokens.pop().unwrap();
            let header = token.header();
            let (status, first) = post(&peer, carol.address, b"three", Some(&header)).await;
            assert_eq!(status, 201);
            let (status, again) = post(&peer, carol.address, b"three", Some(&header)).await;
            assert_eq!((status, &again), (201, &first), "the same item ID");
            assert_eq!(
                post(&peer, carol.address, b"four", Some(&header)).await,
                (409, "token_spent".into())
            );
            let forged = forged(&tokens[0]).header();
            assert_eq!(
                post(&peer, carol.address, b"four", Some(&forged)).await,
                (403, "token_refused".into())
            );
            let mut version_2 = *tokens[0].as_bytes();
            version_2[0] = 2;
            let version_2: String = version_2.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                post(
                    &peer,
                    carol.address,
                    b"four",
                    Some(&format!("Frasil-Token {version_2}"))
                )
                .await,
                (400, "unsupported_version".into())
            );
            let items = collect(&peer, &carol).await;
            assert_eq!(items.len(), 1);
            assert_eq!(frasil_testkit::hex::encode(items[0].0), first);
            peer.shutdown().await;
        })
        .await;
    }

    /// Sets the open library's allowance and share.
    pub(super) fn allowance(peer: &TestPeer, allowance: u64, share: u64) {
        peer.peer
            .set_library(
                &LibraryId::new(OPEN_LIBRARY).unwrap(),
                LibraryUpdate {
                    deposit_allowance: Some(Some(allowance)),
                    space_share: Some(Some(share)),
                    ..LibraryUpdate::default()
                },
            )
            .unwrap();
    }

    /// ext-deposit-tokens.md, 3.4 Issuing, steps 5 to 10, and 2.6: space
    /// draws under the store right, each space within its share, the
    /// library within its allowance across its spaces and its grants, a
    /// read credential and a space of no library refused, and the window
    /// beginning every count afresh once `allowance_window` has passed.
    #[tokio::test(flavor = "multi_thread")]
    async fn space_draws_take_each_space_s_share_within_the_library_s_allowance() {
        within(async {
            let peer = peer(token_settings()).await;
            allowance(&peer, 5, 3);
            let first = History::credentials();
            let second = History::skeleton();
            let mut a = founder(&peer, Binding::WebSocket, &first).await;
            let mut b = founder(&peer, Binding::Iroh, &second).await;
            let list = keys(&mut a).await;
            let space_a = Draw::Space(first.space().0);
            let space_b = Draw::Space(second.space().0);
            // The first space's batch is cut to its share; then it has none.
            assert_eq!(
                draw(&mut a, &list, space_a.clone(), 4).await.unwrap().len(),
                3
            );
            assert_eq!(
                draw(&mut a, &list, space_a.clone(), 1).await.unwrap_err(),
                "allowance_exhausted"
            );
            // The second's is cut to what is left of the allowance.
            assert_eq!(
                draw(&mut b, &list, space_b.clone(), 4).await.unwrap().len(),
                2
            );
            assert_eq!(
                draw(&mut b, &list, space_b.clone(), 1).await.unwrap_err(),
                "allowance_exhausted"
            );
            // A grant draw against the same library counts in its allowance.
            let mut c = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let grant = grant_for(&peer, OPEN_LIBRARY, 4, 1);
            assert_eq!(
                draw(&mut c, &list, Draw::Grant(grant.clone()), 1)
                    .await
                    .unwrap_err(),
                "allowance_exhausted"
            );
            // A read credential holds no store right; a space this
            // connection was not granted is refused alike.
            let mut reader = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let genesis = first.order[0].clone();
            reader
                .present(
                    first.space(),
                    frasil_conformance::client::Credential::Read,
                    &first.read_seed(&genesis),
                )
                .await
                .unwrap();
            assert_eq!(
                draw(&mut reader, &list, space_a.clone(), 1)
                    .await
                    .unwrap_err(),
                "credential_refused"
            );
            assert_eq!(
                draw(&mut reader, &list, Draw::Space([9; 32]), 1)
                    .await
                    .unwrap_err(),
                "credential_refused"
            );
            // A day later the window opens again, and every share with it.
            peer.advance(DAY).await;
            assert_eq!(draw(&mut a, &list, space_a, 4).await.unwrap().len(), 3);
            // The grant refused before stays unused, but it lived an hour; a
            // new one draws what is left.
            assert_eq!(
                draw(&mut c, &list, Draw::Grant(grant), 4)
                    .await
                    .unwrap_err(),
                "ticket_expired"
            );
            let grant = grant_for(&peer, OPEN_LIBRARY, 4, 2);
            assert_eq!(
                draw(&mut c, &list, Draw::Grant(grant), 4)
                    .await
                    .unwrap()
                    .len(),
                2,
                "the grant draws what is left"
            );
            let ledger = peer
                .peer
                .ledger(&LibraryId::new(OPEN_LIBRARY).unwrap())
                .unwrap();
            assert_eq!(ledger.deposit.unwrap().tokens_drawn, 5);
            assert_eq!(ledger.deposit.unwrap().deposit_allowance, 5);
            peer.shutdown().await;
        })
        .await;
    }

    /// ext-deposit-tokens.md, 3.1.2, 3.3 and 3.12: a device that writes a
    /// space the peer hosts draws as its writer, within the hour, on a
    /// connection that presents that space's upload key alone and stores
    /// nothing; the space's share cuts its batch; `allowance_exhausted`
    /// pauses it for `allowance_window`; and it draws again once the
    /// window has opened again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_writer_draws_its_space_s_share_on_a_connection_that_stores_nothing() {
        within(async {
            let peer = peer(token_settings()).await;
            allowance(&peer, 64, 3);
            let watch = peer.peer.watch();
            let dir = temp_dir("space-draw");
            let clock = clock();
            let alice = device(&dir, &clock).await;
            let space = alice.create_space().await.unwrap();
            let connection = alice.connect(&peer.origin).await.unwrap();
            space.flush().await.unwrap();
            let space_id = *space.id().as_bytes();
            assert!(peer.peer.hosts(&space_id));
            an_hour_later(&alice, &clock).await;
            let tokens = alice.deposit_tokens(&peer.origin).await;
            assert_eq!(tokens.held, 3, "cut to the space's share");
            let shown = watch.connections();
            let draws = drawing(&shown);
            assert_eq!(draws.len(), 1);
            let draw = draws[0];
            assert_eq!(draw.draws, [Some(space_id)]);
            assert_eq!(draw.presented, [(space_id, 2)], "the upload key alone");
            assert_eq!(
                draw.kinds,
                [
                    MessageType::Hello,
                    MessageType::Present,
                    MessageType::TokenRequest
                ],
                "it stores nothing"
            );
            assert!(!draw.credentialed);
            // Below the low mark, the device draws again within the hour,
            // and the share is spent: it pauses.
            an_hour_later(&alice, &clock).await;
            let tokens = alice.deposit_tokens(&peer.origin).await;
            assert_eq!(tokens.held, 3);
            assert!(tokens.paused);
            let count = || drawing(&watch.connections()).len();
            assert_eq!(count(), 2);
            clock.advance(12 * HOUR);
            an_hour_later(&alice, &clock).await;
            assert_eq!(count(), 2, "paused for allowance_window");
            // A day later, at the peer and at the device, it draws again.
            peer.advance(DAY).await;
            clock.advance(DAY);
            an_hour_later(&alice, &clock).await;
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 6);
            assert_eq!(count(), 3);
            assert!(connection.status().connected);
            alice.close().await.unwrap();
            peer.shutdown().await;
        })
        .await;
    }

    /// transport.md, 3.12 What a peer learns of a device: a deposit names
    /// its recipient, so a device with no token deposits on a connection
    /// of its own that presents nothing, never on the one that presents
    /// its spaces.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_deposit_without_a_token_never_rides_the_space_connection() {
        within(async {
            let peer = peer(token_settings()).await;
            let watch = peer.peer.watch();
            let dir = temp_dir("anonymous");
            let clock = clock();
            let alice = device(&dir, &clock).await;
            let space = alice.create_space().await.unwrap();
            let connection = alice.connect(&peer.origin).await.unwrap();
            space.flush().await.unwrap();
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 0);
            let bob = recipient(3);
            alice
                .deposit_item(&peer.origin, bob.id, b"a list".to_vec())
                .await
                .unwrap();
            let shown = watch.connections();
            let deposits: Vec<_> = shown.iter().filter(|c| !c.deposits.is_empty()).collect();
            assert_eq!(deposits.len(), 1);
            assert_eq!(deposits[0].deposits, [(bob.address, None)]);
            shows_nothing_else(deposits[0], &[MessageType::MailboxPut]);
            let spaces: Vec<_> = shown.iter().filter(|c| !c.presented.is_empty()).collect();
            assert!(!spaces.is_empty());
            assert!(spaces.iter().all(|c| c.deposits.is_empty()));
            assert_eq!(collect(&peer, &bob).await.len(), 1);
            assert!(connection.status().connected);
            alice.close().await.unwrap();
            peer.shutdown().await;
        })
        .await;
    }

    /// [`token_settings`] with `token_period` a day.
    fn daily_keys() -> Settings {
        let mut settings = token_settings();
        settings.deposit_tokens.token_period = DAY;
        settings
    }

    /// ext-deposit-tokens.md, 3.9 Spent tokens and key rotation, over two
    /// periods of the peer's clock: a key issues for one period and accepts
    /// for one more, so its tokens still pay while a request under it is
    /// `token_expired`; then it retires, its tokens are `token_expired`,
    /// the records of the tokens spent under it are gone, and a device
    /// drops the tokens it held of it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_key_issues_for_a_period_accepts_for_one_more_then_retires() {
        within(async {
            let peer = peer(daily_keys()).await;
            let watch = peer.peer.watch();
            let dir = temp_dir("rotation");
            let clock = clock();
            let alice = device(&dir, &clock).await;
            alice.give_deposit_grant(&peer.origin, grant(&peer, 16, 1));
            an_hour_later(&alice, &clock).await;
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 16);
            let mut raw = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let first = keys(&mut raw).await;
            let first_key = first.issuing().id;
            let mut tokens = draw(&mut raw, &first, Draw::Grant(grant(&peer, 4, 2)), 4)
                .await
                .unwrap();
            let bob = recipient(1);
            assert_eq!(
                spend(&mut raw, bob.address, b"one", &tokens.pop().unwrap()).await,
                Ok(())
            );
            assert_eq!(peer.peer.spent_tokens().unwrap(), [first_key]);

            // One period later: a new key issues, the first accepts only.
            peer.advance(DAY).await;
            let second = keys(&mut raw).await;
            let second_key = second.issuing().id;
            assert_ne!(second_key, first_key);
            assert_eq!(second.keys().len(), 2);
            assert!(second.shows(&first_key));
            assert_eq!(
                draw(&mut raw, &first, Draw::Grant(grant(&peer, 1, 3)), 1)
                    .await
                    .unwrap_err(),
                "token_expired",
                "a request under the accepting-only key"
            );
            assert_eq!(
                spend(&mut raw, bob.address, b"two", &tokens.pop().unwrap()).await,
                Ok(())
            );
            // The device, a day later too, still pays with the older key's
            // tokens, and those first.
            clock.advance(DAY);
            alice.deposit_upkeep().await;
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 16);
            alice
                .deposit_item(&peer.origin, bob.id, b"three".to_vec())
                .await
                .unwrap();
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 15);
            let spent = peer.peer.spent_tokens().unwrap();
            assert_eq!(spent.iter().filter(|key| **key == first_key).count(), 3);

            // Two periods: the first key retires.
            peer.advance(DAY).await;
            let third = keys(&mut raw).await;
            assert!(!third.shows(&first_key));
            assert!(third.shows(&second_key));
            assert_eq!(
                spend(&mut raw, bob.address, b"four", &tokens.pop().unwrap()).await,
                Err("token_expired".into())
            );
            assert!(
                peer.peer
                    .spent_tokens()
                    .unwrap()
                    .iter()
                    .all(|key| *key != first_key),
                "the retired key's spent records are gone"
            );
            // The device learns the keys within the hour and drops the
            // retired key's tokens; its next deposit goes without one.
            clock.advance(DAY);
            alice.deposit_upkeep().await;
            let tokens = alice.deposit_tokens(&peer.origin).await;
            assert_eq!(tokens.held, 0);
            assert!(!tokens.distrusted, "a rotation is no inconsistency");
            alice
                .deposit_item(&peer.origin, bob.id, b"five".to_vec())
                .await
                .unwrap();
            let last = watch
                .connections()
                .into_iter()
                .rev()
                .find(|c| !c.deposits.is_empty())
                .unwrap();
            assert_eq!(last.deposits, [(bob.address, None)]);
            alice.close().await.unwrap();
            peer.shutdown().await;
        })
        .await;
    }

    /// ext-deposit-tokens.md, 2.5 and transport.md, 3.10: types 40 to 43 on
    /// an administration connection close it `purpose_violation`.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_administration_connection_carries_no_deposit_token_message() {
        within(async {
            let peer = peer(token_settings()).await;
            let messages = [
                TokenKeysGet { request: 1 }.encode(),
                map(vec![
                    (0, Value::Unsigned(41)),
                    (1, Value::Unsigned(1)),
                    (2, Value::Array(Vec::new())),
                ]),
                map(vec![
                    (0, Value::Unsigned(42)),
                    (1, Value::Unsigned(1)),
                    (2, Value::Bytes(grant(&peer, 1, 1))),
                    (3, Value::Bytes(vec![1; 32])),
                    (4, Value::Array(vec![Value::Bytes(vec![2; 32])])),
                ]),
                map(vec![
                    (0, Value::Unsigned(43)),
                    (1, Value::Unsigned(1)),
                    (2, Value::Array(vec![Value::Bytes(vec![2; 32])])),
                    (3, Value::Bytes(vec![4; 64])),
                ]),
            ];
            for binding in BINDINGS {
                for (n, message) in messages.iter().enumerate() {
                    let mut admin = connect(&peer, binding, Purpose::Administration).await;
                    admin.send_control(message).await;
                    assert_eq!(
                        admin.closed(DEADLINE).await,
                        Some(close_code(
                            binding,
                            frasil_transport::Code::PurposeViolation
                        )),
                        "{binding:?}: type {}",
                        40 + n
                    );
                }
            }
            peer.shutdown().await;
        })
        .await;
    }

    /// ext-deposit-tokens.md, 3.2 Learning a peer's keys: a peer whose
    /// issuing key is replaced twice within a day is `KeyInconsistent`.
    /// The device stops drawing and spending there, drops the tokens it
    /// holds, reports it, deposits without tokens, and resumes only once
    /// the application trusts the peer again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_whose_keys_contradict_one_another_is_stopped_until_trusted() {
        within(async {
            let peer = peer(token_settings()).await;
            let watch = peer.peer.watch();
            let dir = temp_dir("inconsistent");
            let clock = clock();
            let alice = device(&dir, &clock).await;
            let mut events = alice.events();
            alice.give_deposit_grant(&peer.origin, grant(&peer, 16, 1));
            an_hour_later(&alice, &clock).await;
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 16);
            // The peer replaces its issuing key: the device takes it as a
            // rotation, drops the first key's tokens and draws again.
            let blocking = peer.peer.clone();
            tokio::task::spawn_blocking(move || blocking.forget_deposit_keys().unwrap())
                .await
                .unwrap();
            // Within the hour it asks the keys again and drops the tokens
            // of the key the list no longer shows; then it draws.
            an_hour_later(&alice, &clock).await;
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 0);
            alice.give_deposit_grant(&peer.origin, grant(&peer, 16, 2));
            an_hour_later(&alice, &clock).await;
            let tokens = alice.deposit_tokens(&peer.origin).await;
            assert!(!tokens.distrusted);
            assert_eq!(tokens.held, 16);
            // And again, within the day: a third issuing key.
            let blocking = peer.peer.clone();
            tokio::task::spawn_blocking(move || blocking.forget_deposit_keys().unwrap())
                .await
                .unwrap();
            clock.advance(HOUR);
            alice.deposit_upkeep().await;
            let tokens = alice.deposit_tokens(&peer.origin).await;
            assert!(tokens.distrusted);
            assert_eq!(tokens.held, 0, "every token of the peer is dropped");
            let mut reported = false;
            while let Ok(Some(event)) =
                tokio::time::timeout(Duration::from_millis(200), events.next()).await
            {
                reported |= matches!(
                    event,
                    Event::DepositPeerDistrusted { ref reason, .. } if reason == "key_inconsistent"
                );
            }
            assert!(reported);
            // A grant draws nothing there now, and deposits go without tokens.
            let draws = || drawing(&watch.connections()).len();
            let before = draws();
            alice.give_deposit_grant(&peer.origin, grant(&peer, 16, 3));
            an_hour_later(&alice, &clock).await;
            assert_eq!(draws(), before);
            let bob = recipient(1);
            alice
                .deposit_item(&peer.origin, bob.id, b"one".to_vec())
                .await
                .unwrap();
            let last = watch
                .connections()
                .into_iter()
                .rev()
                .find(|c| !c.deposits.is_empty())
                .unwrap();
            assert_eq!(last.deposits, [(bob.address, None)]);
            // A restart keeps the stop.
            alice.close().await.unwrap();
            drop(alice);
            let alice = device(&dir, &clock).await;
            assert!(alice.deposit_tokens(&peer.origin).await.distrusted);
            // Trusted again, it learns the keys anew and draws.
            alice.trust_deposit_keys(&peer.origin).await.unwrap();
            alice.give_deposit_grant(&peer.origin, grant(&peer, 16, 4));
            an_hour_later(&alice, &clock).await;
            let tokens = alice.deposit_tokens(&peer.origin).await;
            assert!(!tokens.distrusted);
            assert_eq!(tokens.held, 16);
            alice.close().await.unwrap();
            peer.shutdown().await;
        })
        .await;
    }

    /// [`token_settings`] with both budgets at 16 items and no rate that
    /// the scenarios reach.
    fn small_budgets() -> Settings {
        let mut settings = token_settings();
        settings.device_mail = frasil_relay::DeviceMailLimits {
            items: 16,
            bytes: 256 << 20,
            deposits_per_minute: 100_000,
        };
        settings.deposit_tokens.budget.items = 16;
        settings
    }

    /// An anonymous deposit by `POST`: its status.
    async fn anonymous(peer: &TestPeer, address: [u8; 32], item: &[u8]) -> u16 {
        post(peer, address, item, None).await.0
    }

    /// `count` tokens drawn by grant `id`.
    async fn tokens(peer: &TestPeer, count: usize, id: u8) -> Vec<Token> {
        let mut drawer = connect(peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
        let list = keys(&mut drawer).await;
        let tokens = draw(
            &mut drawer,
            &list,
            Draw::Grant(grant(peer, count as u64, id)),
            count,
        )
        .await
        .unwrap();
        drawer.close().await;
        tokens
    }

    /// ext-deposit-tokens.md, 3.8 The token budget, and transport.md, "The
    /// peer's caps": a stranger that fills the anonymous budget delays
    /// only anonymous mail, and a paid item it cannot evict; within each
    /// budget a claimed mailbox's deposit evicts the oldest items of
    /// mailboxes that are not claimed, never a claimed one's; a deposit
    /// refused `busy` evicts nothing; and an unclaimed mailbox's items go
    /// after `uncollected_retention` while a claimed one's stay.
    #[tokio::test(flavor = "multi_thread")]
    async fn paid_mail_has_room_a_stranger_cannot_fill() {
        within(async {
            let peer = peer(small_budgets()).await;
            let mut paid = tokens(&peer, 64, 1).await;
            // A stranger fills the anonymous budget in mailboxes nobody
            // collects from.
            for n in 0..16 {
                assert_eq!(
                    anonymous(&peer, recipient(100 + n).address, b"spam").await,
                    201
                );
            }
            assert_eq!(anonymous(&peer, recipient(200).address, b"more").await, 503);
            // A paid deposit is never refused for the anonymous budget.
            let bob = recipient(1);
            let mut depositor = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            assert_eq!(
                spend(&mut depositor, bob.address, b"paid", &paid.pop().unwrap()).await,
                Ok(())
            );
            // A claimed mailbox's anonymous deposit evicts the stranger's
            // oldest item, never the paid one.
            let carol = recipient(2);
            assert!(collect(&peer, &carol).await.is_empty());
            assert_eq!(anonymous(&peer, carol.address, b"for carol").await, 201);
            assert!(collect(&peer, &recipient(100)).await.is_empty(), "evicted");
            assert_eq!(collect(&peer, &bob).await.len(), 1, "the paid item stays");
            // Once every anonymous item is a claimed mailbox's, an anonymous
            // deposit is refused, and evicts nothing.
            for n in 101..116 {
                assert_eq!(collect(&peer, &recipient(n)).await.len(), 1, "{n}");
            }
            assert_eq!(anonymous(&peer, carol.address, b"no room").await, 503);
            assert_eq!(
                anonymous(&peer, recipient(201).address, b"no room").await,
                503
            );
            for n in 101..116 {
                assert_eq!(collect(&peer, &recipient(n)).await.len(), 1, "{n}");
            }
            assert_eq!(collect(&peer, &carol).await.len(), 1);

            // The token budget: 16 paid items. Eight in a mailbox nobody
            // collects from, seven in claimed ones beside bob's one.
            let dave = recipient(3);
            let _ = collect(&peer, &dave).await;
            let gina = recipient(4);
            for n in 0..8u8 {
                assert_eq!(
                    spend(&mut depositor, gina.address, &[n], &paid.pop().unwrap()).await,
                    Ok(())
                );
            }
            for n in 0..7u8 {
                assert_eq!(
                    spend(&mut depositor, dave.address, &[n], &paid.pop().unwrap()).await,
                    Ok(())
                );
            }
            // A claimed mailbox's paid deposit evicts the unclaimed one's
            // oldest paid item.
            let eve = recipient(5);
            let _ = collect(&peer, &eve).await;
            assert_eq!(
                spend(
                    &mut depositor,
                    eve.address,
                    b"for eve",
                    &paid.pop().unwrap()
                )
                .await,
                Ok(())
            );
            // A paid deposit into a mailbox nobody claims evicts nothing
            // for itself: with the budget full, `busy`, and its token
            // unspent.
            let frank = recipient(6);
            let token = paid.pop().unwrap();
            assert_eq!(
                spend(&mut depositor, frank.address, b"for frank", &token).await,
                Err("busy".into())
            );
            let spent = peer.peer.spent_tokens().unwrap().len();
            assert_eq!(spent, 17);
            // Seven of gina's left: the eviction took one, the refusal none.
            let claimed_view = collect(&peer, &gina).await;
            assert_eq!(claimed_view.len(), 7);
            assert_eq!(claimed_view[0].1, [1]);
            // Every paid item is a claimed mailbox's now: a claimed
            // mailbox's paid deposit is refused too, and evicts nothing.
            assert_eq!(
                spend(&mut depositor, eve.address, b"again", &token).await,
                Err("busy".into())
            );
            assert_eq!(collect(&peer, &dave).await.len(), 7);
            assert_eq!(collect(&peer, &eve).await.len(), 1);
            assert_eq!(peer.peer.spent_tokens().unwrap().len(), 17);
            peer.shutdown().await;
        })
        .await;
    }

    /// transport.md, "Claimed device mailboxes", with the extension on: an
    /// item that came while its mailbox was not claimed, paid or not, goes
    /// after `uncollected_retention` unless its mailbox is claimed by then;
    /// a claimed mailbox's items stay.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unclaimed_mailbox_gives_up_its_items_after_uncollected_retention() {
        within(async {
            let settings = token_settings();
            let retention = settings.uncollected_retention;
            let peer = peer(settings).await;
            let mut paid = tokens(&peer, 4, 1).await;
            let mut depositor = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let (x, y, z, w) = (recipient(1), recipient(2), recipient(3), recipient(4));
            let _ = collect(&peer, &y).await;
            for who in [&x, &y, &w] {
                assert_eq!(anonymous(&peer, who.address, b"anonymous").await, 201);
            }
            for who in [&z, &y] {
                assert_eq!(
                    spend(&mut depositor, who.address, b"paid", &paid.pop().unwrap()).await,
                    Ok(())
                );
            }
            // W is claimed before the item's time is up.
            peer.advance(retention - HOUR).await;
            assert_eq!(collect(&peer, &w).await.len(), 1);
            peer.advance(HOUR + 1).await;
            assert!(collect(&peer, &x).await.is_empty(), "unclaimed: gone");
            assert!(
                collect(&peer, &z).await.is_empty(),
                "unclaimed and paid: gone"
            );
            assert_eq!(collect(&peer, &y).await.len(), 2, "claimed: kept");
            assert_eq!(collect(&peer, &w).await.len(), 1, "claimed in time: kept");
            peer.shutdown().await;
        })
        .await;
    }

    /// ext-deposit-tokens.md, 3.5 and 3.11, and transport.md, "A sender
    /// keeps what was refused": a deposit the full token budget answers
    /// `busy` is kept with its token, and goes again with the same token
    /// once room is freed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_token_budget_answers_busy_and_the_device_pays_again_with_the_same_token() {
        within(async {
            let settings = small_budgets();
            let retention = settings.uncollected_retention;
            let peer = peer(settings).await;
            let watch = peer.peer.watch();
            let mut paid = tokens(&peer, 16, 1).await;
            let mut depositor = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
            let hank = recipient(9);
            for n in 0..16u8 {
                assert_eq!(
                    spend(&mut depositor, hank.address, &[n], &paid.pop().unwrap()).await,
                    Ok(())
                );
            }
            let dir = temp_dir("budget-busy");
            let clock = clock();
            let alice = device(&dir, &clock).await;
            let mut events = alice.events();
            alice.give_deposit_grant(&peer.origin, grant(&peer, 16, 2));
            an_hour_later(&alice, &clock).await;
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 16);
            let bob = recipient(1);
            let first = alice
                .deposit_item(&peer.origin, bob.id, b"a welcome".to_vec())
                .await;
            assert!(matches!(first, Err(frasil::Error::Delayed(ref why)) if why == "busy"));
            assert!(matches!(
                tokio::time::timeout(DEADLINE, events.next()).await,
                Ok(Some(Event::Delayed { ref reason, .. })) if reason == "busy"
            ));
            assert_eq!(alice.waiting_deposits().await, 1);
            assert_eq!(
                alice.deposit_tokens(&peer.origin).await.held,
                15,
                "the deposit's"
            );
            let to_bob = |shown: Vec<Shown>| -> Vec<Shown> {
                shown
                    .into_iter()
                    .filter(|c| c.deposits.iter().any(|(at, _)| *at == bob.address))
                    .collect()
            };
            let sent = to_bob(watch.connections())[0].deposits[0].1.unwrap();
            // Hank's items go, and the deposit goes again.
            peer.advance(retention + 1).await;
            clock.advance(61);
            upkeep_until_sent(&alice).await;
            assert!(matches!(
                tokio::time::timeout(DEADLINE, events.next()).await,
                Ok(Some(Event::Delivered { .. }))
            ));
            let paid_again = to_bob(watch.connections());
            assert_eq!(paid_again.len(), 2);
            assert_eq!(
                paid_again[1].deposits,
                [(bob.address, Some(sent))],
                "the same token"
            );
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 15);
            assert_eq!(collect(&peer, &bob).await.len(), 1);
            alice.close().await.unwrap();
            peer.shutdown().await;
        })
        .await;
    }

    /// Runs the device's deposit upkeep, then waits until nothing waits: a
    /// deposit the device's own upkeep holds at that moment is skipped by
    /// the call, and delivered by that upkeep.
    async fn upkeep_until_sent(device: &Device) {
        device.deposit_upkeep().await;
        tokio::time::timeout(DEADLINE, async {
            while device.waiting_deposits().await > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("every kept deposit goes once the peer has room");
    }

    /// Waits for `expected` `Event::Delivered`, within the deadline, then
    /// counts any more that come within a moment: how many came. The wait
    /// for the expected ones is on the events, not on a quiet moment, which
    /// a loaded machine stretches.
    async fn delivered(events: &mut frasil::Events, expected: usize) -> usize {
        let mut count = 0;
        let _ = tokio::time::timeout(DEADLINE, async {
            while count < expected {
                match events.next().await {
                    Some(event) => count += usize::from(matches!(event, Event::Delivered { .. })),
                    None => return,
                }
            }
        })
        .await;
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(300), events.next()).await
        {
            count += usize::from(matches!(event, Event::Delivered { .. }));
        }
        count
    }

    /// transport.md, "A sender keeps what was refused", through the real
    /// client: welcomes of a batch admission that the peer answers
    /// `rate_limited`, then `busy`, report `Error::Delayed` and
    /// `Event::Delayed`, are kept, and go again by themselves once the peer
    /// has room: `Event::Delivered`, and the recipient is admitted to every
    /// space.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn welcomes_the_peer_refuses_for_now_are_delayed_then_delivered() {
        use frasil::{Level, SpaceId};
        tokio::time::timeout(Duration::from_secs(240), async {
            let mut settings = token_settings();
            settings.device_mail = frasil_relay::DeviceMailLimits {
                items: 16,
                bytes: 256 << 20,
                deposits_per_minute: 2,
            };
            let retention = settings.mailbox_retention;
            let peer = peer(settings).await;
            // Alice's clock reads the true wall time, as Bob's does.
            let wall = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let clock = Arc::new(ManualClock::new(1_000, Some(wall)));
            let alice = Device::open_with(
                Storage::Memory,
                &[0x51; 32],
                Options::new().loopback().clock(clock.clone()),
            )
            .await
            .unwrap();
            let bob = Device::open_with(Storage::Memory, &[0x52; 32], Options::new().loopback())
                .await
                .unwrap();
            let source = alice.create_space().await.unwrap();
            alice.connect(&peer.origin).await.unwrap();
            let joining = bob
                .join_via_peer(&peer.origin, "Bob", |_, _| async { true })
                .await
                .unwrap();
            source
                .admit_with(
                    joining.text(),
                    Level::Write,
                    frasil::HistoryMode::WithHistory,
                    "Alice",
                    |_, _| async { true },
                )
                .await
                .unwrap();
            joining.joined().await.unwrap();
            let mut events = alice.events();
            let delayed = |reports: &[frasil::SpaceAdmission], why: &str| {
                reports
                    .iter()
                    .filter(|r| {
                        r.granted && matches!(&r.result, Err(frasil::Error::Delayed(w)) if w == why)
                    })
                    .count()
            };
            // `rate_limited`: two deposits a minute.
            let mut spaces: Vec<SpaceId> = Vec::new();
            for _ in 0..4 {
                spaces.push(alice.create_space().await.unwrap().id());
            }
            let reports = alice
                .admit_spaces_via_peer(&peer.origin, source.id(), bob.id(), 255, &spaces, |_| {})
                .await
                .unwrap();
            assert_eq!(reports.iter().filter(|r| r.result.is_ok()).count(), 2);
            assert_eq!(delayed(&reports, "rate_limited"), 2, "{reports:?}");
            assert_eq!(alice.waiting_deposits().await, 2);
            peer.advance(60).await;
            clock.advance(60);
            upkeep_until_sent(&alice).await;
            assert_eq!(delivered(&mut events, 2).await, 2);
            let received = bob
                .receive_spaces_via_peer(&peer.origin, alice.id(), &spaces, |_| {})
                .await
                .unwrap();
            assert!(
                received.iter().all(|r| r.granted && r.result.is_ok()),
                "{received:?}"
            );

            // `busy`: every anonymous item is a claimed mailbox's.
            peer.advance(60).await;
            for n in 0..12 {
                let holder = recipient(300 + n);
                let _ = collect(&peer, &holder).await;
                assert_eq!(anonymous(&peer, holder.address, b"held").await, 201);
                if n % 2 == 1 {
                    peer.advance(60).await;
                }
            }
            peer.advance(60).await;
            let more: Vec<SpaceId> = vec![alice.create_space().await.unwrap().id()];
            let reports = alice
                .admit_spaces_via_peer(&peer.origin, source.id(), bob.id(), 255, &more, |_| {})
                .await
                .unwrap();
            assert_eq!(delayed(&reports, "busy"), 1, "{reports:?}");
            // The claimed items reach their retention, and the welcome goes.
            peer.advance(retention + 1).await;
            clock.advance(HOUR);
            upkeep_until_sent(&alice).await;
            assert_eq!(delivered(&mut events, 1).await, 1);
            let received = bob
                .receive_spaces_via_peer(&peer.origin, alice.id(), &more, |_| {})
                .await
                .unwrap();
            assert!(
                received.iter().all(|r| r.granted && r.result.is_ok()),
                "{received:?}"
            );
            alice.close().await.unwrap();
            bob.close().await.unwrap();
            peer.shutdown().await;
        })
        .await
        .unwrap();
    }

    /// transport.md, "A sender keeps what was refused", for a person's new
    /// device (admission.md, "A person's new device"): `admit_device`
    /// succeeds although the peer answers one of its welcomes
    /// `rate_limited`; the welcome is kept, reported `Event::Delayed`, goes
    /// again by itself once the peer has room, `Event::Delivered`, and the
    /// new device then reaches that space too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_new_devices_welcome_the_peer_refuses_for_now_is_delayed_then_delivered() {
        use frasil::SpaceId;
        tokio::time::timeout(Duration::from_secs(240), async {
            let mut settings = token_settings();
            settings.device_mail = frasil_relay::DeviceMailLimits {
                items: 16,
                bytes: 256 << 20,
                deposits_per_minute: 2,
            };
            let peer = peer(settings).await;
            let wall = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let clock = Arc::new(ManualClock::new(1_000, Some(wall)));
            let laptop = Device::open_with(
                Storage::Memory,
                &[0x61; 32],
                Options::new().loopback().clock(clock.clone()),
            )
            .await
            .unwrap();
            let person = laptop.make_person(&[0x61; 32]).await.unwrap();
            // The personal space and two more: three welcomes, against two
            // deposits a minute.
            let first = laptop.create_space().await.unwrap();
            let second = laptop.create_space().await.unwrap();
            laptop.connect(&peer.origin).await.unwrap();
            first.flush().await.unwrap();
            second.flush().await.unwrap();
            let every: Vec<SpaceId> = laptop.spaces().await.iter().map(|s| s.id()).collect();
            assert_eq!(every.len(), 3);
            let mut events = laptop.events();

            let phone = Device::open_with(Storage::Memory, &[0x62; 32], Options::new().loopback())
                .await
                .unwrap();
            let joining = phone
                .join_person_via_peer(&peer.origin, person, "Phone", &[0x62; 32], |_, _| async {
                    true
                })
                .await
                .unwrap();
            laptop
                .admit_device(joining.text(), "Laptop", |_, _| async { true })
                .await
                .unwrap();
            assert_eq!(laptop.waiting_deposits().await, 1, "one welcome waits");
            let delayed = loop {
                match tokio::time::timeout(DEADLINE, events.next()).await {
                    Ok(Some(Event::Delayed { reason, .. })) => break reason,
                    Ok(Some(_)) => {}
                    other => panic!("{other:?}"),
                }
            };
            assert_eq!(delayed, "rate_limited");
            let reached: Vec<SpaceId> = joining
                .joined()
                .await
                .unwrap()
                .iter()
                .map(|s| s.id())
                .collect();
            assert_eq!(reached.len(), 2, "{reached:?}");
            let late: Vec<SpaceId> = every
                .iter()
                .copied()
                .filter(|space| !reached.contains(space))
                .collect();
            assert_eq!(late.len(), 1);

            // A minute later the peer has room: the welcome goes by itself.
            peer.advance(60).await;
            clock.advance(60);
            upkeep_until_sent(&laptop).await;
            assert_eq!(delivered(&mut events, 1).await, 1);
            // The new device collects the welcome on request, or its upkeep
            // did, and keeps the space once the delivery admits it.
            let received = phone
                .receive_welcomes_via_peer(&peer.origin, |_| {})
                .await
                .unwrap();
            assert!(
                received.iter().all(|r| r.granted && r.result.is_ok()),
                "{received:?}"
            );
            tokio::time::timeout(DEADLINE, async {
                while phone.space(late[0]).await.is_err() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("the new device keeps the late space");
            laptop.close().await.unwrap();
            phone.close().await.unwrap();
            peer.shutdown().await;
        })
        .await
        .unwrap();
    }

    /// ext-deposit-tokens.md, 3.6, 3.12 and section 4, and transport.md,
    /// 3.12: the connection that draws, the one that deposits, and the one
    /// that carries the device's spaces are three, and the peer's record of
    /// the deposit's connection holds no credential, collection, draw or
    /// bearer token: only the `Hello`, the keys asked, and the deposit.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_draw_a_deposit_and_the_space_traffic_are_three_connections() {
        within(async {
            let peer = peer(token_settings()).await;
            let watch = peer.peer.watch();
            let dir = temp_dir("privacy");
            let clock = clock();
            let alice = device(&dir, &clock).await;
            let space = alice.create_space().await.unwrap();
            alice.connect(&peer.origin).await.unwrap();
            space.flush().await.unwrap();
            alice.give_deposit_grant(&peer.origin, grant(&peer, 16, 1));
            an_hour_later(&alice, &clock).await;
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 16);
            let bob = recipient(1);
            alice
                .deposit_item(&peer.origin, bob.id, b"a sealed welcome".to_vec())
                .await
                .unwrap();
            let shown = watch.connections();
            let space_id = *space.id().as_bytes();
            let traffic: Vec<&Shown> = shown
                .iter()
                .filter(|c| {
                    c.presented
                        .iter()
                        .any(|(s, credential)| *s == space_id && *credential == 1)
                })
                .collect();
            let draws = drawing(&shown);
            let paid = paying(&shown);
            assert_eq!((traffic.len(), draws.len(), paid.len()), (1, 1, 1));
            // Three connections, each doing one thing.
            assert!(traffic[0].draws.is_empty() && traffic[0].deposits.is_empty());
            assert!(draws[0].deposits.is_empty() && draws[0].presented.is_empty());
            assert!(paid[0].draws.is_empty());
            assert_ne!(traffic[0], draws[0]);
            assert_ne!(draws[0], paid[0]);
            // The deposit's connection, as the peer saw it.
            shows_nothing_else(
                paid[0],
                &[MessageType::TokenKeysGet, MessageType::MailboxPut],
            );
            assert_eq!(paid[0].deposits.len(), 1);
            assert_eq!(paid[0].deposits[0].0, bob.address);
            // No connection but the space's own presented the space.
            assert!(
                shown
                    .iter()
                    .filter(|c| c.presented.iter().any(|(s, _)| *s == space_id))
                    .all(|c| c.deposits.is_empty() && c.draws.is_empty())
            );
            alice.close().await.unwrap();
            peer.shutdown().await;
        })
        .await;
    }

    /// ext-deposit-tokens.md, 3.11 A device without tokens: at a peer that
    /// does not list service 6, a device handed a grant draws nothing, and
    /// deposits without a token, on a connection of its own.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_device_deposits_without_tokens_at_a_peer_with_the_extension_off() {
        within(async {
            let mut settings = token_settings();
            settings.extensions.deposit_tokens = false;
            let peer = peer(settings).await;
            let watch = peer.peer.watch();
            let dir = temp_dir("off");
            let clock = clock();
            let alice = device(&dir, &clock).await;
            alice.give_deposit_grant(&peer.origin, grant(&peer, 16, 1));
            an_hour_later(&alice, &clock).await;
            an_hour_later(&alice, &clock).await;
            assert_eq!(alice.deposit_tokens(&peer.origin).await.held, 0);
            let bob = recipient(1);
            alice
                .deposit_item(&peer.origin, bob.id, b"a list".to_vec())
                .await
                .unwrap();
            let shown = watch.connections();
            assert!(shown.iter().all(|c| c.draws.is_empty()), "no draw");
            let deposits: Vec<_> = shown.iter().filter(|c| !c.deposits.is_empty()).collect();
            assert_eq!(deposits.len(), 1);
            assert_eq!(deposits[0].deposits, [(bob.address, None)]);
            shows_nothing_else(deposits[0], &[MessageType::MailboxPut]);
            assert_eq!(collect(&peer, &bob).await.len(), 1);
            alice.close().await.unwrap();
            peer.shutdown().await;
        })
        .await;
    }
}
