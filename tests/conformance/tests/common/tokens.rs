//! What the scenarios of ext-deposit-tokens.md share: a peer that trusts
//! an issuer the tests hold, grants, recipients that collect, and a
//! device's messages drawn and spent by hand.

use super::{Binding, DEADLINE, connect};
use frasil::MemberId;
use frasil_conformance::client::PeerClient;
use frasil_crypto::device::{IdentityKey, KeysCommitment, Signatory};
use frasil_deposit_tokens::{Batch, Draw, KeyList, Token, TokenKeysGet, TokenPut};
use frasil_libraries::{Issuer, LibraryId, TrustedIssuers};
use frasil_relay::libraries::LibrarySettings;
use frasil_relay::testing::{OPEN_LIBRARY, TestPeer};
use frasil_relay::{Clock, Settings};
use frasil_transport::frame::{Message, MessageType};
use frasil_transport::mailbox::{self, Kind, MailboxItems};
use frasil_transport::peer::{Purpose, mailbox_path};

pub const HOUR: u64 = 3_600;
pub const DAY: u64 = 24 * HOUR;

/// The library the tests' grants name.
pub const LIBRARY: &str = "personal:tokens";

fn issuer() -> Issuer {
    let parameters: serde_json::Value =
        frasil_testkit::vectors::family("ext-libraries.json", "parameters");
    let seed = parameters["issuer_seed"]
        .as_str()
        .map(|hex| frasil_testkit::hex::decode_array(hex).unwrap())
        .unwrap();
    Issuer::from_seed(&seed)
}

/// Settings of a peer with deposit tokens on, which trusts the tests'
/// issuer and keeps an open library for creates without a ticket.
pub fn token_settings() -> Settings {
    Settings {
        libraries: LibrarySettings {
            issuers: TrustedIssuers::new([*issuer().public()]).unwrap(),
            open_library: LibraryId::new(OPEN_LIBRARY).ok(),
            ..LibrarySettings::default()
        },
        ..frasil_conformance::settings()
    }
}

/// A deposit grant of `tokens` for [`LIBRARY`], with ID `id`, for an
/// hour from the peer's wall clock.
pub fn grant(peer: &TestPeer, tokens: u64, id: u8) -> Vec<u8> {
    grant_for(peer, LIBRARY, tokens, id)
}

/// [`grant`] for another library.
pub fn grant_for(peer: &TestPeer, library: &str, tokens: u64, id: u8) -> Vec<u8> {
    let wall = peer.clock.now().wall.expect("the wall clock");
    issuer()
        .issue_grant_with(
            &LibraryId::new(library).unwrap(),
            tokens,
            wall,
            wall + HOUR,
            [id; 16],
        )
        .unwrap()
}

/// A recipient device the tests collect for: its identity seed, its
/// keys commitment, its ID and its mailbox's address.
pub struct Recipient {
    seed: [u8; 32],
    kc: KeysCommitment,
    pub id: MemberId,
    pub address: [u8; 32],
}

pub fn recipient(n: u32) -> Recipient {
    let mut seed = [0x77u8; 32];
    seed[..4].copy_from_slice(&n.to_be_bytes());
    let kc = KeysCommitment(frasil_crypto::primitives::sha256(&[b"kc of ", &seed]));
    let signer = Signatory {
        ed: IdentityKey(frasil_crypto::primitives::ed25519_public(&seed)),
        kc,
    };
    let id = signer.device_id().0;
    Recipient {
        seed,
        kc,
        id: MemberId::from_bytes(id),
        address: mailbox::address(Kind::Device, &id),
    }
}

/// What `recipient` collects from its mailbox, which claims it: each
/// item with its ID.
pub async fn collect(peer: &TestPeer, recipient: &Recipient) -> Vec<([u8; 16], Vec<u8>)> {
    let mut device = connect(peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
    let request = device.request();
    let get = mailbox::collect(
        request,
        &recipient.seed,
        &recipient.kc,
        &device.binding,
        None,
    );
    let answer = device
        .request_answer(request, &get)
        .await
        .expect("MailboxItems")
        .expect("a message");
    device.close().await;
    MailboxItems::read(&answer).unwrap().items
}

pub fn number(message: &Message) -> Option<u64> {
    message.get(1).and_then(|v| v.as_unsigned().ok())
}

/// `TokenKeysGet` on `device`: the key list, checked as a device checks
/// it (section 3.2).
pub async fn keys(device: &mut PeerClient) -> KeyList {
    let request = device.request();
    device
        .send_control(&TokenKeysGet { request }.encode())
        .await;
    let answer = answer_to(device, request).await;
    assert_eq!(answer.kind, MessageType::TokenKeys, "{answer:?}");
    KeyList::read(&answer.map, request).expect("a list that passes section 3.2")
}

/// The answer to a request on `device`: the message.
pub async fn answer_to(device: &mut PeerClient, request: u64) -> Message {
    device
        .wait_for(DEADLINE, |message| {
            (number(message) == Some(request)).then(|| message.clone())
        })
        .await
        .expect("an answer")
}

/// The reason code of a `Refused`.
pub fn refused(message: &Message) -> String {
    assert_eq!(message.kind, MessageType::Refused, "{message:?}");
    frasil_transport::messages::Refused::read(message)
        .unwrap()
        .code
}

/// Draws `count` tokens on `device` under `list`'s issuing key: the
/// tokens `TokenIssue` finishes into, with its proof checked (section
/// 3.5), or the `Refused` code.
pub async fn draw(
    device: &mut PeerClient,
    list: &KeyList,
    way: Draw,
    count: usize,
) -> Result<Vec<Token>, String> {
    let batch = Batch::new(list.issuing(), count).unwrap();
    let request = device.request();
    device
        .send_control(&batch.request(request, way).encode())
        .await;
    let answer = answer_to(device, request).await;
    if answer.kind == MessageType::Refused {
        return Err(refused(&answer));
    }
    assert_eq!(answer.kind, MessageType::TokenIssue);
    Ok(batch
        .finish(&answer.map, request)
        .expect("a TokenIssue whose proof holds"))
}

/// Deposits `item` with `token` on `device`: `Ok` for `Accepted`, else
/// the `Refused` code.
pub async fn spend(
    device: &mut PeerClient,
    address: [u8; 32],
    item: &[u8],
    token: &Token,
) -> Result<(), String> {
    let request = device.request();
    let put = TokenPut {
        request,
        address,
        item: item.to_vec(),
        token: token.clone(),
    }
    .encode();
    device.request_answer(request, &put).await.map(drop)
}

/// Deposits `item` by `POST` with `authorization`: the status, and the
/// item ID or the reason code.
pub async fn post(
    peer: &TestPeer,
    address: [u8; 32],
    item: &[u8],
    authorization: Option<&str>,
) -> (u16, String) {
    let mut request = frasil_conformance::http_client()
        .post(format!("{}{}", peer.origin, mailbox_path(3, &address)))
        .body(item.to_vec());
    if let Some(value) = authorization {
        request = request.header("Authorization", value);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    let said = body["id"]
        .as_str()
        .or(body["code"].as_str())
        .unwrap_or_default()
        .to_owned();
    (status, said)
}

/// A token whose authenticator is changed.
pub fn forged(token: &Token) -> Token {
    let mut bytes = *token.as_bytes();
    bytes[128] ^= 1;
    Token::from_bytes(&bytes).unwrap()
}
