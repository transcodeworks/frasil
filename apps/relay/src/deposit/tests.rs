//! Deposit tokens at the peer, through its own code: the framing of types
//! 40 to 43 and `MailboxPut` key 7 with the extension on and off, the
//! services and discovery, issuance by grant and by space against a
//! library's window and share, redemption and its repeats, the token
//! budget, the `POST` route, key rotation and what it forgets, keys sealed
//! at rest, and a restart with no wall clock.

use super::*;
use crate::Extensions;
use crate::clock::{Clock, ManualClock};
use crate::config::Settings;
use crate::libraries::LibrarySettings;
use crate::state::Outgoing;
use frasil_base::cbor;
use frasil_crypto::primitives::ed25519_public;
use frasil_deposit_tokens::settings::{ALLOWANCE_WINDOW, TOKEN_PERIOD};
use frasil_deposit_tokens::{Batch, KeyList, Token, TokenKeysGet};
use frasil_libraries::{Issuer, TrustedIssuers};
use frasil_peers::entries::Rights;
use frasil_store::{MemoryStore, Store};
use frasil_transport::frame::{ConnectionKind, MessageType, StreamClass, read_message};
use frasil_transport::mailbox::{Kind, MailboxPut};
use std::sync::Arc;

const ISSUER_SEED: [u8; 32] = [42; 32];
const LIBRARY: &str = "project:deposit";

fn library() -> LibraryId {
    LibraryId::new(LIBRARY).unwrap()
}

fn on() -> Settings {
    Settings {
        extensions: Extensions {
            libraries: true,
            deposit_tokens: true,
            ..Extensions::NONE
        },
        libraries: LibrarySettings {
            issuers: TrustedIssuers::new([ed25519_public(&ISSUER_SEED)]).unwrap(),
            ..LibrarySettings::default()
        },
        deposit_tokens: DepositSettings {
            seal: Some(SealKey::new([9; 32])),
            ..DepositSettings::default()
        },
        ..Settings::open_core()
    }
}

fn off() -> Settings {
    Settings {
        extensions: Extensions {
            libraries: true,
            ..Extensions::NONE
        },
        ..on()
    }
}

struct Peer {
    core: Core,
    clock: Arc<ManualClock>,
    store: Arc<dyn Store>,
}

fn open_with(settings: Settings, store: Arc<dyn Store>, clock: Arc<ManualClock>) -> Peer {
    let core = Core::open(settings, Records::new(store.clone()), clock.clone()).unwrap();
    Peer { core, clock, store }
}

fn open(settings: Settings) -> Peer {
    open_with(
        settings,
        Arc::new(MemoryStore::new()),
        Arc::new(ManualClock::new(crate::testing::START)),
    )
}

fn map(bytes: &[u8]) -> Map {
    cbor::decode(bytes).unwrap().as_map().unwrap().clone()
}

/// A peer's answer: its bytes, or the reason it was refused for.
fn answer(out: Outgoing) -> Result<Vec<u8>, String> {
    let Outgoing::Control(bytes) = out else {
        panic!("not a control message");
    };
    let read = map(&bytes);
    if read.get(&0).unwrap().as_unsigned().unwrap() == MessageType::Refused.code() {
        return Err(read.get(&2).unwrap().as_text().unwrap().to_owned());
    }
    Ok(bytes)
}

impl Peer {
    fn now(&self) -> Reading {
        self.clock.now()
    }

    fn keys(&self) -> KeyList {
        let get = TokenKeysGet { request: 7 }.encode();
        let bytes = answer(self.core.token_keys(&map(&get), self.now()).unwrap()).unwrap();
        KeyList::decode(&bytes, 7).unwrap()
    }

    fn grant(&self, tokens: u64, id: u8) -> Vec<u8> {
        let wall = self.now().wall.unwrap();
        Issuer::from_seed(&ISSUER_SEED)
            .issue_grant_with(&library(), tokens, wall, wall + 3600, [id; 16])
            .unwrap()
    }

    /// Draws `count` tokens: the tokens, or the reason.
    async fn draw(
        &self,
        count: usize,
        draw: Draw,
        grants: &BTreeMap<EventId, Grant>,
    ) -> Result<Vec<Token>, String> {
        let keys = self.keys();
        let batch = Batch::new(keys.issuing(), count).unwrap();
        let request = batch.request(3, draw).encode();
        let bytes = answer(
            self.core
                .token_request(grants, &map(&request), self.now())
                .await
                .unwrap(),
        )?;
        Ok(batch.finish_bytes(&bytes, 3).unwrap())
    }

    async fn deposit(
        &self,
        address: [u8; 32],
        item: &[u8],
        token: &Token,
    ) -> Result<[u8; 16], TokenClass> {
        let deposit = TokenDeposit {
            request: Some(1),
            address,
            item: item.to_vec(),
            token: token.clone(),
        };
        self.core.token_put(&deposit, self.now()).await
    }

    fn records(&self, prefix: u8) -> usize {
        self.core.records.scan(&[prefix]).unwrap().len()
    }

    /// A space hosted here, attached to the library, and a connection's
    /// grants in it: the store right, or fetch alone.
    fn space(&self, space: [u8; 32], store: bool) -> BTreeMap<EventId, Grant> {
        lock(&self.core.libraries).attach(EventId(space), &library(), None, self.now());
        let rights = Rights {
            store,
            fetch: true,
            ..Rights::default()
        };
        BTreeMap::from([(
            EventId(space),
            Grant {
                rights,
                ..Grant::default()
            },
        )])
    }
}

#[test]
fn the_types_and_key_7_read_only_with_the_extension() {
    let keys_get = TokenKeysGet { request: 1 }.encode();
    let mut put = cbor::decode(
        &frasil_transport::mailbox::MailboxPut {
            request: 1,
            kind: Kind::Device,
            address: [1; 32],
            item: vec![1],
        }
        .encode(),
    )
    .unwrap()
    .as_map()
    .unwrap()
    .clone();
    put.insert(7, cbor::Value::from(&[1u8; 129][..]));
    let put = cbor::Value::Map(put).encode();
    let read = |payload: &[u8], extensions: Extensions| {
        read_message(
            payload,
            StreamClass::Control,
            ConnectionKind::DeviceToPeer,
            extensions.frames(),
        )
    };
    // Off: the types are unknown and close the connection; key 7 is
    // Malformed.
    let off = off().extensions;
    assert_eq!(
        read(&keys_get, off).unwrap_err(),
        frasil_transport::TransportClass::from(frasil_base::ErrorClass::UnknownMessage)
    );
    let message = read(&put, off).unwrap().unwrap();
    assert!(MailboxPut::read(&message, off.frames()).is_err());
    assert_eq!(
        crate::session::services(&off),
        crate::session::services(&Extensions {
            libraries: true,
            ..Extensions::NONE
        })
    );
    assert!(!crate::session::services(&off).contains(&frasil_transport::codes::Service::Deposit));
    // On: they read, and key 7 is the extension's.
    let on = on().extensions;
    assert!(read(&keys_get, on).unwrap().is_some());
    let message = read(&put, on).unwrap().unwrap();
    assert_eq!(MailboxPut::read(&message, on.frames()).unwrap(), None);
    assert!(TokenDeposit::read_put(&message.map).is_ok());
    assert!(crate::session::services(&on).contains(&frasil_transport::codes::Service::Deposit));
}

#[test]
fn the_extension_needs_libraries() {
    let alone = Extensions {
        deposit_tokens: true,
        ..Extensions::NONE
    };
    assert!(alone.check().is_err());
    assert!(on().extensions.check().is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_draw_issues_once_and_counts_against_the_library() {
    let peer = open(on());
    let none = BTreeMap::new();
    let tokens = peer
        .draw(3, Draw::Grant(peer.grant(5, 1)), &none)
        .await
        .unwrap();
    assert_eq!(tokens.len(), 3);
    // The grant is used, though it named 5.
    assert_eq!(
        peer.draw(1, Draw::Grant(peer.grant(5, 1)), &none).await,
        Err("ticket_used".into())
    );
    // More elements than the grant names.
    assert_eq!(
        peer.draw(3, Draw::Grant(peer.grant(2, 2)), &none).await,
        Err("ticket_refused".into())
    );
    // A grant refused at any step stays unused.
    assert_eq!(
        peer.draw(2, Draw::Grant(peer.grant(2, 2)), &none)
            .await
            .map(|t| t.len()),
        Ok(2)
    );
    // The ledger shows the library's count and its allowance: a library
    // the peer did not know is known from its first draw.
    let ledger = peer.core.ledger(&library()).await.unwrap().json();
    assert_eq!(ledger["tokens_drawn"], 5);
    assert_eq!(ledger["deposit_allowance"], 64);
    // At rest: the window, and the two grants used.
    let window = crate::libraries::records::WINDOW;
    let grant = crate::libraries::records::GRANT;
    let rows = peer.core.records.library_records().unwrap();
    assert_eq!(rows.iter().filter(|r| r.0 == window).count(), 1);
    assert_eq!(rows.iter().filter(|r| r.0 == grant).count(), 2);
}

/// A peer with the operator's defaults, libraries and deposit tokens on,
/// takes a deposit grant its own operator's issuer signs, as
/// `frasil-relay ticket --purpose deposit` prints it, for the default
/// library.
#[tokio::test(flavor = "multi_thread")]
async fn a_default_peer_takes_its_operator_deposit_grant() {
    let operator = crate::libraries::OperatorIssuer::from_seed([5; 32]);
    let mut settings = Settings::default();
    assert!(settings.extensions.libraries && settings.extensions.deposit_tokens);
    settings.libraries.use_operator(operator.clone());
    settings.deposit_tokens.seal = Some(SealKey::new([9; 32]));
    let peer = open(settings);
    let request = crate::libraries::TicketRequest {
        purpose: frasil_libraries::Purpose::Deposit,
        tokens: Some(4),
        ..crate::libraries::TicketRequest::default()
    };
    let wall = peer.now().wall.unwrap();
    let issued =
        crate::libraries::operator::issue_with(&operator, &request, None, wall, [3; 16]).unwrap();
    assert_eq!(issued.library, operator.default_library());
    let none = BTreeMap::new();
    let tokens = peer
        .draw(4, Draw::Grant(issued.ticket.clone()), &none)
        .await
        .unwrap();
    assert_eq!(tokens.len(), 4);
    assert_eq!(
        peer.draw(1, Draw::Grant(issued.ticket), &none).await,
        Err("ticket_used".into())
    );
    let ledger = peer
        .core
        .ledger(&operator.default_library())
        .await
        .unwrap()
        .json();
    assert_eq!(ledger["tokens_drawn"], 4);
}

/// Changes the library's settings, in memory and at rest, as the
/// operator's route does.
fn set_library(peer: &Peer, update: crate::libraries::LibraryUpdate) {
    let mut libraries = lock(&peer.core.libraries);
    let record = libraries.update(&library(), update).unwrap();
    peer.core
        .commit_libraries_blocking(&mut libraries, vec![record], Vec::new())
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_space_draw_needs_the_store_right_and_counts_in_its_share() {
    let peer = open(on());
    set_library(
        &peer,
        crate::libraries::LibraryUpdate {
            deposit_allowance: Some(Some(20)),
            space_share: Some(Some(6)),
            ..Default::default()
        },
    );
    let a = peer.space([1; 32], true);
    let b = peer.space([2; 32], true);
    // Cut to the share left.
    assert_eq!(
        peer.draw(4, Draw::Space([1; 32]), &a).await.unwrap().len(),
        4
    );
    assert_eq!(
        peer.draw(4, Draw::Space([1; 32]), &a).await.unwrap().len(),
        2
    );
    assert_eq!(
        peer.draw(1, Draw::Space([1; 32]), &a).await,
        Err("allowance_exhausted".into())
    );
    // Another space of the library draws its own share.
    assert_eq!(
        peer.draw(16, Draw::Space([2; 32]), &b).await.unwrap().len(),
        6
    );
    // A grant draw counts against no share, and is cut to the allowance.
    assert_eq!(
        peer.draw(16, Draw::Grant(peer.grant(16, 3)), &BTreeMap::new())
            .await
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        peer.draw(1, Draw::Grant(peer.grant(1, 4)), &BTreeMap::new())
            .await,
        Err("allowance_exhausted".into())
    );
    // Fetch alone, or a space of no library.
    let fetch = peer.space([3; 32], false);
    assert_eq!(
        peer.draw(1, Draw::Space([3; 32]), &fetch).await,
        Err("credential_refused".into())
    );
    let mut unattached = a.clone();
    unattached.insert(EventId([4; 32]), unattached[&EventId([1; 32])].clone());
    assert_eq!(
        peer.draw(1, Draw::Space([4; 32]), &unattached).await,
        Err("no_library".into())
    );
    // The ledger shows the library's total, never a space's.
    let ledger = peer.core.ledger(&library()).await.unwrap().json();
    assert_eq!(ledger["tokens_drawn"], 20);
    assert_eq!(ledger["deposit_allowance"], 20);
    for space in ledger["spaces"].as_array().unwrap() {
        assert!(
            space
                .as_object()
                .unwrap()
                .keys()
                .all(|key| !key.contains("token"))
        );
    }
    // The window passes: every count begins afresh.
    peer.clock.advance(ALLOWANCE_WINDOW);
    assert_eq!(
        peer.core.ledger(&library()).await.unwrap().json()["tokens_drawn"],
        0
    );
    assert_eq!(
        peer.draw(16, Draw::Space([1; 32]), &a).await.unwrap().len(),
        6
    );
    // A suspended library draws nothing by space.
    set_library(
        &peer,
        crate::libraries::LibraryUpdate {
            state: Some(frasil_libraries::LibraryState::Suspended),
            ..Default::default()
        },
    );
    assert_eq!(
        peer.draw(1, Draw::Space([2; 32]), &b).await,
        Err("library_closed".into())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_pays_for_one_deposit() {
    let peer = open(on());
    let tokens = peer
        .draw(4, Draw::Grant(peer.grant(4, 1)), &BTreeMap::new())
        .await
        .unwrap();
    let address = [5; 32];
    let id = peer.deposit(address, b"hello", &tokens[0]).await.unwrap();
    // The same deposit again: answered as the first was.
    assert_eq!(peer.deposit(address, b"hello", &tokens[0]).await, Ok(id));
    // The token on another item, or another mailbox.
    assert_eq!(
        peer.deposit(address, b"other", &tokens[0]).await,
        Err(TokenClass::TokenSpent)
    );
    assert_eq!(
        peer.deposit([6; 32], b"hello", &tokens[0]).await,
        Err(TokenClass::TokenSpent)
    );
    // A changed authenticator, version 2, an item too large.
    let mut forged = *tokens[1].as_bytes();
    forged[100] ^= 1;
    let forged = Token::from_bytes(&forged).unwrap();
    assert_eq!(
        peer.deposit(address, b"x", &forged).await,
        Err(TokenClass::TokenRefused)
    );
    let mut v2 = *tokens[1].as_bytes();
    v2[0] = 2;
    assert_eq!(
        peer.deposit(address, b"x", &Token::from_bytes(&v2).unwrap())
            .await,
        Err(frasil_base::ErrorClass::UnsupportedVersion.into())
    );
    assert_eq!(
        peer.deposit(address, &vec![0; 262_145], &tokens[1]).await,
        Err(frasil_base::ErrorClass::TooLarge.into())
    );
    // A refusal leaves the token unspent.
    assert!(peer.deposit(address, b"later", &tokens[1]).await.is_ok());
    // The item is kept, paid, and its token spent with it.
    let held = peer.core.mail_items_for_test(&address);
    assert_eq!(held.len(), 2);
    assert!(held.iter().all(|item| item.paid));
    assert_eq!(peer.records(crate::records::SPENT), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_token_budget_is_busy_and_keeps_the_token() {
    let mut settings = on();
    settings.deposit_tokens.budget = TokenBudget {
        items: 1,
        bytes: 1 << 20,
    };
    settings.device_mail.items = 16;
    let peer = open(settings);
    let tokens = peer
        .draw(2, Draw::Grant(peer.grant(2, 1)), &BTreeMap::new())
        .await
        .unwrap();
    assert!(peer.deposit([1; 32], b"a", &tokens[0]).await.is_ok());
    assert_eq!(
        peer.deposit([2; 32], b"b", &tokens[1]).await,
        Err(TokenClass::Busy)
    );
    // Nothing is spent for it, and a later deposit spends it.
    assert_eq!(peer.records(crate::records::SPENT), 1);
    // Mailbox 2's device collects: an unclaimed mailbox's token item makes
    // room for it.
    peer.core.claim_for_test(&[2; 32], peer.now());
    assert!(peer.deposit([2; 32], b"b", &tokens[1]).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_undecided_reservation_is_busy_then_settled() {
    let peer = open(on());
    let tokens = peer
        .draw(1, Draw::Grant(peer.grant(1, 1)), &BTreeMap::new())
        .await
        .unwrap();
    let token = &tokens[0];
    let address = spent_address(&token.nonce(), &token.key_id());
    let reserved = SpentState::Reserved {
        deposit: sha256(&[&[7; 32], b"x"]),
        address: [7; 32],
        at: peer.now().timeline,
    };
    peer.core
        .writer
        .commit(vec![(address.clone(), reserved.encode())], Vec::new())
        .await
        .unwrap();
    // A deposit of the token, of this item or another, waits.
    assert_eq!(
        peer.deposit([7; 32], b"x", token).await,
        Err(TokenClass::Busy)
    );
    assert_eq!(
        peer.deposit([8; 32], b"y", token).await,
        Err(TokenClass::Busy)
    );
    // Past the reservation, its mailbox holds no such item: released, and
    // the token pays for this deposit.
    peer.clock.advance(RESERVATION);
    let id = peer.deposit([8; 32], b"y", token).await.unwrap();
    assert_eq!(peer.deposit([8; 32], b"y", token).await, Ok(id));
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_rotate_and_the_spent_tokens_of_a_retired_key_are_forgotten() {
    let peer = open(on());
    let mut spent = 0;
    let mut first = None;
    // Three periods: each draws and spends its batch; at most two keys'
    // records stay.
    for period in 0..3u8 {
        let keys = peer.keys();
        assert_eq!(keys.keys().len(), if period == 0 { 1 } else { 2 });
        let tokens = peer
            .draw(8, Draw::Grant(peer.grant(8, period + 1)), &BTreeMap::new())
            .await
            .unwrap();
        first.get_or_insert_with(|| tokens[0].clone());
        for (n, token) in tokens.iter().enumerate() {
            peer.deposit([n as u8; 32], &[period, n as u8], token)
                .await
                .unwrap();
            spent += 1;
        }
        peer.core.sweep_deposit_tokens(peer.now()).await;
        // The records are at most the tokens drawn under the live keys.
        assert!(peer.records(crate::records::SPENT) <= 16, "{period}");
        assert!(peer.records(crate::records::DEPOSIT_KEY) <= 2);
        peer.clock.advance(TOKEN_PERIOD);
        let _ = peer.core.current_keys(peer.now());
        peer.clock.advance(ALLOWANCE_WINDOW);
    }
    assert_eq!(spent, 24);
    peer.core.sweep_deposit_tokens(peer.now()).await;
    assert_eq!(peer.records(crate::records::SPENT), 8);
    // The first key retired: its tokens are expired, and need no record.
    assert_eq!(
        peer.deposit([9; 32], b"z", first.as_ref().unwrap()).await,
        Err(TokenClass::TokenExpired)
    );
    assert_eq!(peer.records(crate::records::DEPOSIT_KEY), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_are_sealed_at_rest_and_survive_a_restart() {
    let peer = open(on());
    let before = peer.keys().issuing().id;
    let seed_rows = peer
        .core
        .records
        .scan(&[crate::records::DEPOSIT_KEY])
        .unwrap();
    assert_eq!(seed_rows.len(), 1);
    let key_record = KeyRecord::decode(&seed_rows[0].1).unwrap();
    let Peer { core, clock, store } = peer;
    let held = lock(&core.deposit_keys.held).shard.clone().unwrap();
    let seed = *held.issuing().unwrap().seed();
    assert!(!key_record.sealed.windows(32).any(|w| w == seed));
    drop(core);
    let again = open_with(on(), store.clone(), clock.clone());
    assert_eq!(again.keys().issuing().id, before);
    drop(again);
    // Under another sealing key the old key does not open: a new one
    // begins, and the old record goes.
    let mut other = on();
    other.deposit_tokens.seal = Some(SealKey::new([1; 32]));
    let other = open_with(other, store, clock);
    assert_ne!(other.keys().issuing().id, before);
    assert_eq!(other.records(crate::records::DEPOSIT_KEY), 1);
}

/// A clock of a new run with no known wall clock.
#[derive(Debug)]
struct NoWall(u64);

impl Clock for NoWall {
    fn now(&self) -> Reading {
        Reading {
            timeline: self.0,
            wall: None,
            run: 2,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_with_no_wall_clock_retires_both_keys() {
    let peer = open(on());
    peer.keys();
    peer.clock.advance(TOKEN_PERIOD);
    assert_eq!(peer.keys().keys().len(), 2);
    let Peer { core, store, .. } = peer;
    drop(core);
    let clock: Arc<dyn Clock> = Arc::new(NoWall(crate::testing::START + TOKEN_PERIOD + 1));
    let core = Core::open(on(), Records::new(store), clock.clone()).unwrap();
    let live = core.current_keys(clock.now()).unwrap();
    assert_eq!(live.keys.live_keys().len(), 1);
    assert_eq!(live.keys.live_keys()[0].began.run, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn off_reads_and_writes_none_of_its_records() {
    // Records a peer with the extension wrote.
    let peer = open(on());
    peer.draw(2, Draw::Grant(peer.grant(2, 1)), &BTreeMap::new())
        .await
        .unwrap();
    let Peer { core, clock, store } = peer;
    let rows = core.records.library_records().unwrap().len();
    drop(core);
    let off = open_with(off(), store, clock);
    {
        let libraries = lock(&off.core.libraries);
        assert!(libraries.window(&library()).is_none());
        assert!(libraries.deposit_settings(&library()).is_none());
    }
    off.core.sweep(off.now()).await;
    assert_eq!(off.core.records.library_records().unwrap().len(), rows);
    assert_eq!(off.records(crate::records::DEPOSIT_KEY), 1);
    // Its settings route takes no allowance, and shows none.
    assert!(crate::libraries::read_update(br#"{"deposit_allowance": 3}"#, false).is_none());
    assert!(crate::libraries::read_update(br#"{"deposit_allowance": 3}"#, true).is_some());
}

#[test]
fn settings_route_checks_the_ranges() {
    let mut libraries = crate::libraries::Libraries::new(LibrarySettings::default())
        .with_deposit_tokens(DepositSettings::default().defaults());
    let update = |allowance: Option<u64>, share: Option<u64>| crate::libraries::LibraryUpdate {
        deposit_allowance: allowance.map(Some),
        space_share: share.map(Some),
        ..Default::default()
    };
    assert!(
        libraries
            .update(&library(), update(Some(65_537), None))
            .is_err()
    );
    assert!(
        libraries
            .update(&library(), update(Some(8), Some(9)))
            .is_err()
    );
    // A default share past a lowered allowance holds at the allowance.
    libraries.update(&library(), update(Some(8), None)).unwrap();
    assert_eq!(
        libraries.deposit_settings(&library()).unwrap(),
        frasil_deposit_tokens::settings::DepositSettings {
            deposit_allowance: 8,
            space_share: 8,
        }
    );
    // The last write stands.
    libraries
        .update(&library(), update(Some(100), Some(0)))
        .unwrap();
    assert_eq!(
        libraries.deposit_settings(&library()).unwrap().space_share,
        0
    );
    let off = crate::libraries::Libraries::new(LibrarySettings::default());
    let mut off = off;
    assert!(off.update(&library(), update(Some(1), None)).is_err());
}

// -- The server binding

async fn http(
    peer: &crate::testing::TestPeer,
    request: &str,
    body: &[u8],
) -> (u16, serde_json::Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(peer.http).await.unwrap();
    let head = format!(
        "{request}\r\nhost: peer\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    let status = text[9..12].parse().unwrap();
    let json = text
        .split_once("\r\n\r\n")
        .and_then(|(_, body)| serde_json::from_str(body).ok())
        .unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn spawn(settings: Settings) -> crate::testing::TestPeer {
    crate::testing::spawn_with(crate::testing::Options {
        settings,
        iroh: false,
        ..Default::default()
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_and_the_post_route_follow_the_setting() {
    let mut settings = on();
    settings.device_mail.deposits_per_minute = 1;
    let peer = spawn(settings).await;
    let (_, discovery) = http(&peer, "GET /.well-known/frasil HTTP/1.1", b"").await;
    assert!(
        discovery["services"]
            .as_array()
            .unwrap()
            .contains(&"deposit".into())
    );
    let keys = discovery["deposit_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["issuing"], true);
    // A token deposit counts toward no per-source rate.
    let core = &peer.peer.shared.core;
    let wall = core.clock.now().wall.unwrap();
    let grant = Issuer::from_seed(&ISSUER_SEED)
        .issue_grant_with(&library(), 3, wall, wall + 3600, [1; 16])
        .unwrap();
    let list = KeyList::check(&[(
        &crate::util::unhex::<32>(keys[0]["id"].as_str().unwrap()).unwrap()[..],
        &crate::util::unhex::<32>(keys[0]["key"].as_str().unwrap()).unwrap()[..],
        1,
    )])
    .unwrap();
    let batch = Batch::new(list.issuing(), 3).unwrap();
    let request = batch.request(1, Draw::Grant(grant)).encode();
    let issued = answer(
        core.token_request(&BTreeMap::new(), &map(&request), core.clock.now())
            .await
            .unwrap(),
    )
    .unwrap();
    let tokens = batch.finish_bytes(&issued, 1).unwrap();
    let path = |address: u8| format!("/frasil/p1/mailbox/3/{}", crate::util::hex(&[address; 32]));
    let post = |address: u8, token: Option<&Token>| {
        let header = token.map_or(String::new(), |token| {
            format!("\r\nauthorization: {}", &*token.header())
        });
        format!("POST {} HTTP/1.1{header}", path(address))
    };
    assert_eq!(http(&peer, &post(1, None), b"a").await.0, 201);
    assert_eq!(http(&peer, &post(1, None), b"b").await.0, 429);
    let (status, first) = http(&peer, &post(1, Some(&tokens[0])), b"c").await;
    assert_eq!(status, 201);
    assert_eq!(http(&peer, &post(1, Some(&tokens[1])), b"d").await.0, 201);
    // The same deposit again: the same item ID.
    assert_eq!(
        http(&peer, &post(1, Some(&tokens[0])), b"c").await,
        (201, first)
    );
    let (status, spent) = http(&peer, &post(2, Some(&tokens[0])), b"c").await;
    assert_eq!((status, spent["code"].as_str()), (409, Some("token_spent")));
    // A header that is not one token.
    let (status, bad) = http(
        &peer,
        &format!("POST {} HTTP/1.1\r\nauthorization: Bearer x", path(3)),
        b"e",
    )
    .await;
    assert_eq!((status, bad["code"].as_str()), (400, Some("malformed")));
    let mut v2 = (*tokens[2].header()).clone();
    v2.replace_range(13..15, "02");
    let (status, version) = http(
        &peer,
        &format!("POST {} HTTP/1.1\r\nauthorization: {v2}", path(3)),
        b"e",
    )
    .await;
    assert_eq!(
        (status, version["code"].as_str()),
        (400, Some("unsupported_version"))
    );
    // The preflight already allows `Authorization`.
    let (status, _) = http(&peer, &format!("OPTIONS {} HTTP/1.1\r\norigin: https://app.example\r\naccess-control-request-headers: authorization", path(3)), b"").await;
    assert_eq!(status, 204);
    peer.shutdown().await;

    // Off: no service, no keys, and `Authorization` is not read.
    let peer = spawn(off()).await;
    let (_, discovery) = http(&peer, "GET /.well-known/frasil HTTP/1.1", b"").await;
    assert!(
        !discovery["services"]
            .as_array()
            .unwrap()
            .contains(&"deposit".into())
    );
    assert!(discovery.get("deposit_keys").is_none());
    let (status, _) = http(&peer, &post(1, Some(&tokens[2])), b"f").await;
    assert_eq!(status, 201);
    assert_eq!(
        peer.peer
            .shared
            .core
            .records
            .scan(&[crate::records::SPENT])
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        peer.peer
            .shared
            .core
            .records
            .scan(&[crate::records::DEPOSIT_KEY])
            .unwrap()
            .len(),
        0
    );
    peer.shutdown().await;
}

/// The first deposit key begins when the node takes the keys' shard up,
/// before any use or sweep; with the extension off, nothing is written.
#[test]
fn the_first_key_begins_when_the_shard_is_taken_up() {
    let peer = open(on());
    assert_eq!(peer.records(crate::records::DEPOSIT_KEY), 0);
    assert!(peer.core.begin_deposit_keys(peer.now()));
    assert_eq!(peer.records(crate::records::DEPOSIT_KEY), 1);
    // Taken up again, the same key stands.
    assert!(peer.core.begin_deposit_keys(peer.now()));
    assert_eq!(peer.records(crate::records::DEPOSIT_KEY), 1);
    let off = open(off());
    assert!(!off.core.begin_deposit_keys(off.now()));
    assert_eq!(off.records(crate::records::DEPOSIT_KEY), 0);
}
