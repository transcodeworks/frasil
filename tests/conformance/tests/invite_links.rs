//! ext-invite-links.md's drops at the peer: a `MailboxPut` of kind 4 under
//! the store right, served to anyone by `MailboxGet` and on the server
//! binding, counted in the space's usage for its lifetime and 60 seconds,
//! and removed by `MailboxDelete` only under the entry it was placed
//! under. They run, with the feature `ext-invite-links`, against a peer
//! with the extension on. In every build, a peer with it off, as by
//! default, closes a connection that sends kind 4 or type 28, and answers
//! 404 for mailbox kind 4, as a core peer does.

mod common;

use common::*;
use frasil_transport::peer::{Purpose, mailbox_path};
use serde_json::Value as Json;

const FILE: &str = "ext-invite-links.json";

fn drops() -> Json {
    frasil_testkit::vectors::family(FILE, "drops")
}

fn bytes(value: &Json) -> Vec<u8> {
    frasil_testkit::hex::decode(value.as_str().expect("hex")).expect("hex")
}

async fn http(response: reqwest::Response) -> (u16, Json) {
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Json::Null))
}

/// The close code a binding carries for a transport code.
fn close_code(binding: Binding, code: frasil_transport::Code) -> Option<u64> {
    Some(match binding {
        Binding::WebSocket => u64::from(code.websocket()),
        Binding::Iroh => code.number(),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_with_the_extension_off_refuses_mailbox_kind_4_and_type_28() {
    within(async {
        let peer = peer(frasil_relay::Settings::open_core()).await;
        assert!(!peer.peer.extensions().invite_links);
        let vectors = drops();
        assert_eq!(vectors["core_peer"]["error"], "Malformed");
        for binding in BINDINGS {
            for message in ["mailbox_put", "mailbox_delete"] {
                let mut device = connect(&peer, binding, Purpose::SpaceTraffic).await;
                device.send_control(&bytes(&vectors[message])).await;
                let code = device.closed(DEADLINE).await.expect("the peer closes");
                assert_eq!(
                    code,
                    close_code(binding, frasil_transport::Code::Malformed),
                    "{binding:?} {message}"
                );
            }
        }
        let address: [u8; 32] =
            frasil_testkit::hex::decode_array(vectors["address"].as_str().unwrap()).unwrap();
        let client = frasil_conformance::http_client();
        let url = format!("{}{}", peer.origin, mailbox_path(4, &address));
        let (status, body) = http(client.get(&url).send().await.unwrap()).await;
        assert_eq!((status, &body["code"]), (404, &Json::from("not_found")));
        let (status, body) = http(client.post(&url).body(vec![1; 64]).send().await.unwrap()).await;
        assert_eq!((status, &body["code"]), (404, &Json::from("not_found")));
        peer.shutdown().await;
    })
    .await;
}

#[cfg(feature = "ext-invite-links")]
mod with_invite_links {
    use super::*;
    use frasil_conformance::client::{Credential, PeerClient};
    use frasil_conformance::history::History;
    use frasil_events::EventId;
    use frasil_relay::Settings;
    use frasil_relay::testing::START;
    use frasil_transport::Code;
    use frasil_transport::codes::Right;
    use frasil_transport::ext_invite_links::{DropPut, MailboxDelete};
    use frasil_transport::frame::MessageType;
    use frasil_transport::mailbox::{Kind, MailboxGet, MailboxItems};

    /// Places a drop: `Ok` for `Accepted`, `Err` with the code of
    /// `Refused`.
    async fn place(
        device: &mut PeerClient,
        space: EventId,
        address: [u8; 32],
        drop: &[u8],
        lifetime: u64,
    ) -> Result<(), String> {
        let request = device.request();
        let message = DropPut {
            request,
            address,
            drop: drop.to_vec(),
            space: *space.as_bytes(),
            lifetime,
        }
        .encode();
        device.request_answer(request, &message).await.map(|_| ())
    }

    /// Sends `MailboxDelete`.
    async fn delete(
        device: &mut PeerClient,
        space: EventId,
        address: [u8; 32],
    ) -> Result<(), String> {
        let request = device.request();
        let message = MailboxDelete {
            request,
            address,
            space: *space.as_bytes(),
        }
        .encode();
        device.request_answer(request, &message).await.map(|_| ())
    }

    /// Fetches a drop with `MailboxGet` of kind 4: its items.
    async fn fetch(device: &mut PeerClient, address: [u8; 32]) -> Vec<([u8; 16], Vec<u8>)> {
        let request = device.request();
        let message = MailboxGet {
            request,
            address,
            after: None,
            collector: None,
            kind: Kind::Drop,
        }
        .encode();
        let answer = device
            .request_answer(request, &message)
            .await
            .expect("MailboxItems")
            .expect("a message");
        assert_eq!(answer.kind, MessageType::MailboxItems);
        MailboxItems::read(&answer).unwrap().items
    }

    /// The drop on the server binding: the status and its items.
    async fn served(peer: &frasil_relay::testing::TestPeer, address: &[u8; 32]) -> (u16, Json) {
        let url = format!("{}{}", peer.origin, mailbox_path(4, address));
        http(
            frasil_conformance::http_client()
                .get(url)
                .send()
                .await
                .unwrap(),
        )
        .await
    }

    /// The `credentials` history's space created, through "P rotates", by
    /// a founder that holds the genesis entry's store right.
    async fn hosted(
        peer: &frasil_relay::testing::TestPeer,
        binding: Binding,
    ) -> (History, PeerClient) {
        let history = History::credentials();
        let mut founder = founder(peer, binding, &history).await;
        store_all(
            &mut founder,
            history.space(),
            history.events(&[
                "P0: root",
                "P grants W write",
                "P grants V write",
                "P rotates",
            ]),
        )
        .await;
        (history, founder)
    }

    async fn keeping(binding: Binding) {
        let peer = peer(frasil_conformance::settings()).await;
        let (history, mut founder) = hosted(&peer, binding).await;
        let space = history.space();
        let address = [0xd4; 32];
        let drop = vec![0x5a; 300];
        let before = peer.peer.usage(space.as_bytes()).unwrap();

        // 3. A connection without the store right.
        let mut stranger = connect(&peer, binding, Purpose::SpaceTraffic).await;
        assert_eq!(
            place(&mut stranger, space, address, &drop, 600).await,
            Err("credential_refused".into())
        );
        // Placed under the genesis entry, and counted in the usage.
        assert_eq!(
            place(&mut founder, space, address, &drop, 600).await,
            Ok(())
        );
        assert_eq!(peer.peer.usage(space.as_bytes()), Some(before + 300));
        // 4. A second drop at the address.
        assert_eq!(
            place(&mut founder, space, address, b"another", 600).await,
            Err("conflict".into())
        );

        // Served to anyone: by MailboxGet, as its one item, and over HTTP.
        let items = fetch(&mut stranger, address).await;
        assert_eq!(items, vec![([0; 16], drop.clone())]);
        let (status, body) = served(&peer, &address).await;
        assert_eq!(status, 200);
        assert_eq!(
            body["items"][0]["item"],
            Json::from(frasil_testkit::hex::encode(&drop))
        );
        // A POST to kind 4 is refused: a drop is placed only over the
        // WebSocket.
        let url = format!("{}{}", peer.origin, mailbox_path(4, &address));
        let (status, body) = http(
            frasil_conformance::http_client()
                .post(url)
                .body(drop.clone())
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            (status, &body["code"]),
            (403, &Json::from("credential_refused"))
        );

        // MailboxDelete: no entry, and another entry, are refused.
        assert_eq!(
            delete(&mut stranger, space, address).await,
            Err("credential_refused".into())
        );
        let mut other = connect(&peer, binding, Purpose::SpaceTraffic).await;
        let granted = other
            .present(space, Credential::Upload, &history.upload_seed("P rotates"))
            .await
            .expect("P's rotation's upload key");
        assert!(granted.rights.contains(&Right::Store));
        assert_eq!(
            delete(&mut other, space, address).await,
            Err("credential_refused".into())
        );
        // The placer's delete; then none is held.
        assert_eq!(delete(&mut founder, space, address).await, Ok(()));
        assert_eq!(peer.peer.usage(space.as_bytes()), Some(before));
        assert_eq!(
            delete(&mut founder, space, address).await,
            Err("not_found".into())
        );
        assert!(fetch(&mut stranger, address).await.is_empty());
        let (status, body) = served(&peer, &address).await;
        assert_eq!(
            (status, body["items"].as_array().map(Vec::len)),
            (200, Some(0))
        );

        // The address is free again, under the other entry.
        assert_eq!(place(&mut other, space, address, &drop, 100).await, Ok(()));
        // A drop lives its lifetime and 60 seconds of the peer's timeline.
        peer.set_time(START + 159).await;
        assert_eq!(fetch(&mut stranger, address).await.len(), 1);
        assert_eq!(peer.peer.usage(space.as_bytes()), Some(before + 300));
        peer.set_time(START + 160).await;
        assert!(fetch(&mut stranger, address).await.is_empty());
        assert_eq!(peer.peer.usage(space.as_bytes()), Some(before));
        founder.close().await;
        other.close().await;
        stranger.close().await;
        peer.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_keeps_serves_and_deletes_drops_on_the_websocket() {
        within(keeping(Binding::WebSocket)).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_keeps_serves_and_deletes_drops_on_iroh() {
        within(keeping(Binding::Iroh)).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_drop_counts_against_the_space_quota() {
        within(async {
            let history = History::credentials();
            let genesis = history.signed(&history.order[0]).len() as u64;
            let peer = peer(Settings {
                space_quota: genesis + 64,
                ..frasil_conformance::settings()
            })
            .await;
            let space = history.space();
            let mut device = founder(&peer, Binding::WebSocket, &history).await;
            assert_eq!(peer.peer.usage(space.as_bytes()), Some(genesis));
            assert_eq!(
                place(&mut device, space, [1; 32], &[0; 65], 600).await,
                Err("quota_exceeded".into())
            );
            assert_eq!(
                place(&mut device, space, [1; 32], &[0; 64], 600).await,
                Ok(())
            );
            // The space is full: a store is refused for the drop's bytes.
            assert_eq!(
                device
                    .store_answer(space, &history.signed("P0: root"), DEADLINE)
                    .await,
                Some(Err("quota_exceeded".into()))
            );
            peer.shutdown().await;
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_vectors_refused_drops_at_the_peer() {
        within(async {
            let peer = peer(frasil_conformance::settings()).await;
            for row in drops()["mailbox_put_refusals"].as_array().unwrap() {
                let Some(message) = row.get("message") else {
                    continue;
                };
                let description = row["description"].as_str().unwrap();
                let error = row["error"].as_str().unwrap();
                // The quota's refusal needs an entry and a quota of the
                // vector's own; `a_drop_counts_against_the_space_quota`
                // covers it.
                if !matches!(error, "Malformed" | "TooLarge" | "credential_refused") {
                    continue;
                }
                for binding in BINDINGS {
                    let mut device = connect(&peer, binding, Purpose::SpaceTraffic).await;
                    device.send_control(&bytes(message)).await;
                    match error {
                        class @ ("Malformed" | "TooLarge") => {
                            let code = if class == "Malformed" {
                                Code::Malformed
                            } else {
                                Code::TooLarge
                            };
                            assert_eq!(
                                device.closed(DEADLINE).await.expect("the peer closes"),
                                close_code(binding, code),
                                "{description} {binding:?}"
                            );
                        }
                        refusal => {
                            // The space is not hosted here: no connection
                            // holds its store right.
                            let answer = device
                                .wait_for(DEADLINE, |m| {
                                    (m.kind == MessageType::Refused).then(|| {
                                        frasil_transport::messages::Refused::read(m)
                                            .map(|r| r.code)
                                            .unwrap_or_default()
                                    })
                                })
                                .await;
                            assert_eq!(answer.as_deref(), Some(refusal), "{description}");
                        }
                    }
                }
            }
            peer.shutdown().await;
        })
        .await;
    }
}
