//! The server binding's HTTP routes (transport.md, "The server binding"):
//! discovery, objects by locator and chunk, device mailboxes, and the
//! connect route without an upgrade.

mod common;

use common::*;
use frasil_conformance::client::{Credential, read_ws};
use frasil_conformance::history::{History, object, object_id};
use frasil_crypto::device::{KeysCommitment, Signatory};
use frasil_crypto::fixtures::FixtureKeys;
use frasil_crypto::primitives::ed25519_sign;
use frasil_relay::Settings;
use frasil_transport::frame::MessageType;
use frasil_transport::mailbox::{self, Kind, MailboxGet, MailboxItems};
use frasil_transport::peer::{Purpose, chunk_path, mailbox_path, transfer_authorization};
use serde_json::Value as Json;

async fn json(response: reqwest::Response) -> (u16, Json) {
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Json::Null))
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_names_relays_without_the_iroh_binding() {
    within(async {
        let relays = vec![
            "https://relay-1.example.org".to_owned(),
            "https://relay-2.example.org".to_owned(),
        ];
        let peer = frasil_relay::testing::spawn_with(frasil_relay::testing::Options {
            settings: Settings {
                relays: relays.clone(),
                ..frasil_conformance::settings()
            },
            iroh: false,
            ..frasil_conformance::options()
        })
        .await
        .unwrap();
        let (status, document) = json(
            frasil_conformance::http_client()
                .get(format!("{}/.well-known/frasil", peer.origin))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, 200);
        assert!(document.get("iroh").is_none());
        assert_eq!(document["relays"], serde_json::json!(relays));
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_lists_the_services_limits_and_iroh_endpoint() {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        let client = frasil_conformance::http_client();
        let (status, document) = json(
            client
                .get(format!("{}/.well-known/frasil", peer.origin))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(document["frasil"], 1);
        assert_eq!(document["revision"], 1);
        let mut services = serde_json::json!(["relay", "store", "mailbox"]);
        // ext-libraries.md's service 5, `library`, while it is on.
        if frasil_conformance::EXTENSIONS.libraries {
            services.as_array_mut().unwrap().push("library".into());
        }
        // ext-deposit-tokens.md's `deposit`, and its live keys, while it is
        // on.
        if frasil_conformance::EXTENSIONS.deposit_tokens {
            services.as_array_mut().unwrap().push("deposit".into());
            assert_eq!(document["deposit_keys"].as_array().map(Vec::len), Some(1));
        } else {
            assert!(document.get("deposit_keys").is_none());
        }
        assert_eq!(document["services"], services);
        assert_eq!(document["limits"]["max_frame_bytes"], 1_056_768);
        assert_eq!(document["limits"]["max_chunk_bytes"], 1_048_576);
        let iroh = peer.iroh.as_ref().unwrap();
        assert_eq!(
            document["iroh"]["endpoint"],
            frasil_testkit::hex::encode(iroh.endpoint)
        );
        // A peer on one machine lists its one key among `endpoints`.
        assert_eq!(
            document["iroh"]["endpoints"],
            serde_json::json!([frasil_testkit::hex::encode(iroh.endpoint)])
        );
        assert!(document["iroh"].get("relays").is_none());
        assert!(document.get("relays").is_none());
        assert!(document.get("account_url").is_none());
        // The connect route without an upgrade, and a route that is none.
        let response = client
            .get(format!("{}/frasil/p1/connect", peer.origin))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 426);
        let (status, body) = json(
            client
                .get(format!("{}/frasil/p1/account/lookup", peer.origin))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!((status, body["code"].as_str()), (404, Some("not_found")));
        let health = client
            .get(format!("{}/healthz", peer.origin))
            .send()
            .await
            .unwrap();
        assert_eq!(health.status().as_u16(), 200);
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn objects_travel_by_locator_and_chunk() {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        let history = History::credentials();
        let space = history.space();
        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        // A reader's transfer token grants fetch, not store.
        device
            .present(
                space,
                Credential::Read,
                &history.read_seed("P creates the space"),
            )
            .await
            .unwrap();
        let reader_token = device.tokens[&space];
        let mut writer = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
        writer
            .present(
                space,
                Credential::Upload,
                &history.upload_seed("P creates the space"),
            )
            .await
            .unwrap();
        let token = writer.tokens[&space];
        let client = frasil_conformance::http_client();
        let base = writer.http().unwrap().to_owned();
        // An object of two pieces.
        let (stored, locator) = object(object_id("two pieces"), 1_100_000, space);
        assert!(stored.len() > 1_048_576);
        let pieces: Vec<&[u8]> = stored.chunks(1_048_576).collect();
        assert_eq!(pieces.len(), 2);
        let put = |index: u64, body: Vec<u8>, token: [u8; 32]| {
            client
                .put(format!(
                    "{base}{}",
                    chunk_path(space.as_bytes(), &locator, index)
                ))
                .header("Authorization", transfer_authorization(&token))
                .body(body)
                .send()
        };
        // Without the store right: refused with its body unread, so a
        // body short enough to be sent whole before the answer, lest the
        // peer close the connection while the client still writes.
        let (status, body) = json(
            put(0, pieces[0][..1024].to_vec(), reader_token)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            (status, body["code"].as_str()),
            (403, Some("credential_refused"))
        );
        let (status, body) = json(put(0, pieces[0].to_vec(), token).await.unwrap()).await;
        assert_eq!((status, &body["held"]), (201, &Json::from(1)));
        // An identical piece again; other bytes at a held index.
        let (status, body) = json(put(0, pieces[0].to_vec(), token).await.unwrap()).await;
        assert_eq!((status, &body["held"]), (200, &Json::from(1)));
        let mut other = pieces[0].to_vec();
        other[100] ^= 1;
        let (status, body) = json(put(0, other, token).await.unwrap()).await;
        assert_eq!((status, body["code"].as_str()), (409, Some("conflict")));
        assert!(!peer.peer.holds_object(space.as_bytes(), &locator));
        let (status, body) = json(put(1, pieces[1].to_vec(), token).await.unwrap()).await;
        assert_eq!((status, &body["held"]), (201, &Json::from(2)));
        assert!(peer.peer.holds_object(space.as_bytes(), &locator));
        // Fetching each piece, by the reader's token.
        for (index, piece) in pieces.iter().enumerate() {
            let response = client
                .get(format!(
                    "{base}{}",
                    chunk_path(space.as_bytes(), &locator, index as u64)
                ))
                .header("Authorization", transfer_authorization(&reader_token))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
            assert_eq!(&response.bytes().await.unwrap()[..], *piece);
        }
        // An object whose bytes do not hash to its locator's digest.
        let (stored, mut wrong) = object(object_id("wrong"), 10, space);
        wrong[40] ^= 1;
        let response = client
            .put(format!("{base}{}", chunk_path(space.as_bytes(), &wrong, 0)))
            .header("Authorization", transfer_authorization(&token))
            .body(stored)
            .send()
            .await
            .unwrap();
        let (status, body) = json(response).await;
        assert_eq!(
            (status, body["code"].as_str()),
            (422, Some("object_mismatch"))
        );
        assert!(!peer.peer.holds_object(space.as_bytes(), &wrong));
        // A token is valid only while its WebSocket stays open.
        writer.close().await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let (status, _) = json(put(0, pieces[0][..1024].to_vec(), token).await.unwrap()).await;
        assert_eq!(status, 403);
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_collects_its_mailbox_by_signing_the_binding() {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        let identity_seed = [5u8; 32];
        let keys = FixtureKeys::from_identity_seed(&identity_seed).device_keys();
        let kc = *keys.keys.commitment();
        let address = mailbox::address(Kind::Device, keys.device_id().as_bytes());
        let client = frasil_conformance::http_client();
        let item = vec![0xab; 2000];
        let (status, body) = json(
            client
                .post(format!("{}{}", peer.origin, mailbox_path(3, &address)))
                .body(item.clone())
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, 201);
        assert_eq!(body["id"].as_str().map(str::len), Some(32));
        // Not over HTTP.
        let response = client
            .get(format!("{}{}", peer.origin, mailbox_path(3, &address)))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 403);
        // Over the WebSocket, on a connection of its own.
        for binding in BINDINGS {
            let mut device = connect(&peer, binding, Purpose::SpaceTraffic).await;
            let request = device.request();
            let get = mailbox::collect(request, &identity_seed, &kc, &device.binding, None);
            // The collector is the device's 64-byte `ed || kc`.
            let sent = MailboxGet::read(&read_ws(&get).unwrap()).unwrap();
            let (signer, _) = sent.collector.as_ref().expect("a collector");
            assert_eq!(signer.to_bytes().len(), 64);
            assert_eq!(signer.device_id(), keys.device_id());
            let answer = device.request_answer(request, &get).await.unwrap().unwrap();
            assert_eq!(answer.kind, MessageType::MailboxItems);
            let items = MailboxItems::read(&answer).unwrap();
            assert_eq!(items.items.len(), 1);
            assert_eq!(items.items[0].1, item);
            // Another device's signature: refused.
            let request = device.request();
            let get = mailbox::collect(request, &[6; 32], &kc, &device.binding, None);
            let mut forged = MailboxGet::read(&read_ws(&get).unwrap()).unwrap();
            forged.address = address;
            assert_eq!(
                device.request_answer(request, &forged.encode()).await,
                Err("credential_refused".into())
            );
            // The device's own `ed`, signing this mailbox's address, under
            // another `kc`: its device ID is not the one the address hashes
            // (WrongMailbox), refused.
            let request = device.request();
            let other = Signatory {
                ed: keys.ed,
                kc: KeysCommitment([0x6b; 32]),
            };
            let signature = ed25519_sign(
                &identity_seed,
                &mailbox::collect_input(&device.binding, &address),
            );
            let elsewhere = MailboxGet {
                request,
                address,
                after: None,
                collector: Some((other, signature.to_vec())),
                kind: Kind::Device,
            };
            assert_eq!(
                mailbox::check_collect(&address, &other.to_bytes(), &signature, &device.binding),
                Err(frasil_transport::TransportClass::WrongMailbox)
            );
            assert_eq!(
                device.request_answer(request, &elsewhere.encode()).await,
                Err("credential_refused".into())
            );
        }
        peer.shutdown().await;
    })
    .await;
}

/// Cross-origin requests: a browser page of another origin reaches every
/// route, a preflight of any path is answered, and no credentials are
/// allowed.
#[tokio::test(flavor = "multi_thread")]
async fn a_page_of_another_origin_reaches_every_route() {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        let client = frasil_conformance::http_client();
        let origin = "https://app.example.org";
        let space = "ab".repeat(32);
        let locator = "cd".repeat(64);
        let chunk = format!("/frasil/p1/spaces/{space}/objects/{locator}/chunks/0");
        for path in [
            chunk.as_str(),
            "/frasil/p1/mailbox/1/00",
            "/.well-known/frasil",
        ] {
            let response = client
                .request(reqwest::Method::OPTIONS, format!("{}{path}", peer.origin))
                .header("Origin", origin)
                .header("Access-Control-Request-Method", "PUT")
                .header("Access-Control-Request-Headers", "authorization")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 204, "{path}");
            let headers = response.headers();
            let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
            assert_eq!(header("access-control-allow-origin"), Some("*"));
            assert_eq!(
                header("access-control-allow-methods"),
                Some("GET, PUT, POST, DELETE")
            );
            assert_eq!(
                header("access-control-allow-headers"),
                Some("Authorization, Content-Type")
            );
            assert_eq!(header("access-control-max-age"), Some("86400"));
            assert!(headers.get("access-control-allow-credentials").is_none());
        }
        // Answers, refusals included, allow any origin.
        let address = "ef".repeat(32);
        for (path, status) in [
            ("/.well-known/frasil".to_owned(), 200),
            (format!("/frasil/p1/mailbox/1/{address}"), 200),
            (chunk.clone(), 403),
            ("/frasil/p1/none".to_owned(), 404),
        ] {
            let response = client
                .get(format!("{}{path}", peer.origin))
                .header("Origin", origin)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status, "{path}");
            assert_eq!(
                response
                    .headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok()),
                Some("*"),
                "{path}"
            );
        }
        peer.shutdown().await;
    })
    .await;
}
