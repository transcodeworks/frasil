//! `frasil-relay`'s embedded iroh relay, on loopback: two endpoints with no
//! IP socket, so no direct path, reach each other through it alone, and
//! their member handshake completes (transport.md, "The iroh binding" and
//! sections 3.2 to 3.5). The relay forwards QUIC packets it cannot read:
//! both ends compute the same exporter, which the handshake binds.

use frasil_crypto::device::{DeviceId, IdentityKey, KeysCommitment, Signatory};
use frasil_iroh::{Alpn, Config, Connection, Endpoint, Error, Role, fresh_secret_key};
use frasil_relay::testing::{Options, spawn_with};
use frasil_testkit::hex;
use frasil_transport::roster::{Serving, Verdict};
use frasil_transport::session::{Event, MemberSession};
use serde_json::Value as Json;
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(30);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

fn random<const N: usize>() -> [u8; N] {
    *frasil_crypto::random_bytes::<N>().unwrap()
}

fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

/// transport.json's `member_handshake`: identity keys and the states'
/// content keys. The channel and endpoint keys come from the connection.
struct Fixtures(Json);

impl Fixtures {
    fn load() -> Self {
        Self(frasil_testkit::vectors::family(
            "transport.json",
            "member_handshake",
        ))
    }

    fn states(&self, labels: &Json) -> Vec<(String, [u8; 32])> {
        labels
            .as_array()
            .unwrap()
            .iter()
            .map(|label| {
                let label = label.as_str().unwrap();
                (label.to_owned(), array(&self.0["content_keys"][label]))
            })
            .collect()
    }

    fn offered(&self) -> Vec<(String, [u8; 32])> {
        self.states(&self.0["offer"]["offered_states"])
    }

    fn candidates(&self) -> Vec<(String, [u8; 32])> {
        self.states(&self.0["listener_candidates"])
    }

    fn seed(&self, side: &str) -> [u8; 32] {
        array(&self.0["devices"][side]["seed"])
    }

    fn kc(&self, side: &str) -> KeysCommitment {
        KeysCommitment(array(&self.0["devices"][side]["kc"]))
    }

    fn signer(&self, side: &str) -> Signatory {
        Signatory {
            ed: IdentityKey(array(&self.0["devices"][side]["ed25519"])),
            kc: self.kc(side),
        }
    }

    fn device_id(&self, side: &str) -> DeviceId {
        DeviceId(array(&self.0["devices"][side]["device_id"]))
    }
}

/// One end of attach 0 on the control stream: the dialer offers, the
/// listener answers, each admits the other. Ends once both admitted it.
async fn run(
    connection: &Connection,
    session: MemberSession<String>,
    fixtures: &Fixtures,
) -> Result<MemberSession<String>, Error> {
    run_forging(connection, session, fixtures, None).await
}

/// [`run`], with this end's `Identify` carrying `forged` in place of the
/// `kc` its signature covers, when given.
async fn run_forging(
    connection: &Connection,
    mut session: MemberSession<String>,
    fixtures: &Fixtures,
    forged: Option<(Signatory, KeysCommitment)>,
) -> Result<MemberSession<String>, Error> {
    let (mut sender, mut receiver) = connection.control().await?;
    let mut pending = Vec::new();
    if connection.role() == Role::Dialer {
        let (_, events) = session
            .offer_with(fixtures.offered(), random(), &[random(); 16])
            .unwrap();
        pending.extend(events);
    }
    loop {
        for event in std::mem::take(&mut pending) {
            match event {
                Event::Send(mut message) => {
                    if let Some((signer, kc)) = &forged {
                        forge_kc(&mut message, signer, kc);
                    }
                    sender.send(&message).await?
                }
                Event::OfferReceived { attach } => pending.extend(
                    session
                        .respond_with(attach, fixtures.candidates(), random())
                        .unwrap(),
                ),
                Event::CheckRoster { attach, .. } => {
                    pending.extend(session.verdict(attach, Verdict::Admit).unwrap());
                }
                Event::Refused { code, .. } => panic!("refused: {code:?}"),
                _ => {}
            }
        }
        if !pending.is_empty() {
            continue;
        }
        if session.serving(0) == Serving::Everything && session.admitted_by_other(0) {
            return Ok(session);
        }
        let Some(message) = receiver.receive().await? else {
            return Err(Error::Truncated);
        };
        pending.extend(session.receive(&message)?);
    }
}

/// Replaces, in a message that carries `signer`'s `ed || kc`, its `kc`
/// with `kc`, leaving the signature as it was.
fn forge_kc(message: &mut [u8], signer: &Signatory, kc: &KeysCommitment) {
    let held = signer.to_bytes();
    if let Some(at) = message.windows(held.len()).position(|w| w == held) {
        message[at + 32..at + 64].copy_from_slice(kc.as_bytes());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoints_bound_without_a_relay_meet_through_one_added_later() {
    let peer = spawn_with(Options {
        iroh: false,
        iroh_relay: true,
        ..frasil_conformance::options()
    })
    .await
    .unwrap();
    let url = peer.relay_url.clone().expect("the relay runs");
    let bind = |alpns: &[Alpn]| {
        Endpoint::bind(Config::new(fresh_secret_key().unwrap(), alpns).relay_only())
    };
    let dialer = bind(&[]).await.unwrap();
    let listener = bind(&[Alpn::Member]).await.unwrap();
    assert!(listener.relays().is_empty());
    for endpoint in [&dialer, &listener] {
        endpoint
            .add_relays(std::slice::from_ref(&url))
            .await
            .unwrap();
        // A relay already named is not added twice.
        endpoint
            .add_relays(std::slice::from_ref(&url))
            .await
            .unwrap();
    }
    let ticket = listener.ticket(frasil_transport::ticket::TicketKind::Member);
    assert_eq!(ticket.relays.len(), 1);
    assert!(ticket.addresses.is_empty());

    let key = listener.key();
    let (dialed, accepted) = within(async {
        tokio::join!(
            dialer.connect(&key, &[], &ticket.relays, Alpn::Member),
            async { listener.accept().await.unwrap() },
        )
    })
    .await;
    let (dialed, accepted) = (dialed.unwrap(), accepted.unwrap());
    assert_eq!(dialed.peer(), listener.key());
    assert_eq!(accepted.peer(), dialer.key());
    assert_eq!(dialed.channel(), accepted.channel());

    dialer.close().await;
    listener.close().await;
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_with_no_direct_path_meet_through_the_embedded_relay() {
    let peer = spawn_with(Options {
        iroh: false,
        iroh_relay: true,
        ..frasil_conformance::options()
    })
    .await
    .unwrap();
    let url = peer.relay_url.clone().expect("the relay runs");
    let bind = |alpns: &[Alpn]| {
        Endpoint::bind(
            Config::new(fresh_secret_key().unwrap(), alpns)
                .relay_only()
                .relays([url.clone()]),
        )
    };
    let dialer = bind(&[]).await.unwrap();
    let listener = bind(&[Alpn::Member]).await.unwrap();
    // Neither end has an address to dial directly.
    assert!(dialer.local_addresses().is_empty());
    assert!(listener.local_addresses().is_empty());
    let ticket = listener.ticket(frasil_transport::ticket::TicketKind::Member);
    assert!(ticket.addresses.is_empty());
    assert_eq!(ticket.relays.len(), 1);

    // The dialer names the listener's key and the relay alone.
    let key = listener.key();
    let (dialed, accepted) = within(async {
        tokio::join!(
            dialer.connect(&key, &[], std::slice::from_ref(&url), Alpn::Member),
            async { listener.accept().await.unwrap() },
        )
    })
    .await;
    let (dialed, accepted) = (dialed.unwrap(), accepted.unwrap());
    assert_eq!(dialed.peer(), listener.key());
    assert_eq!(accepted.peer(), dialer.key());
    assert_eq!(dialed.channel(), accepted.channel());

    let fixtures = Fixtures::load();
    let dialer_session = dialed
        .member_session(&fixtures.seed("dialer"), fixtures.kc("dialer"))
        .unwrap();
    let listener_session = accepted
        .member_session(&fixtures.seed("listener"), fixtures.kc("listener"))
        .unwrap();
    let (d, l) = within(async {
        tokio::join!(
            run(&dialed, dialer_session, &fixtures),
            run(&accepted, listener_session, &fixtures),
        )
    })
    .await;
    let (d, l) = (d.unwrap(), l.unwrap());
    assert!(d.transcript0().is_some());
    assert_eq!(d.transcript0(), l.transcript0());
    assert_eq!(d.remote_signer(), Some(&fixtures.signer("listener")));
    assert_eq!(l.remote_signer(), Some(&fixtures.signer("dialer")));
    assert_eq!(d.remote_device(), Some(&fixtures.device_id("listener")));
    assert_eq!(l.remote_device(), Some(&fixtures.device_id("dialer")));
    assert!(d.settled() && l.settled());

    dialer.close().await;
    listener.close().await;
    peer.shutdown().await;
}

/// An `Identify` whose `kc` is not the one its signature covers is refused
/// (transport.md, "Identify"): the listener closes the session with
/// `BadSignature`, having learned no device of the dialer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identify_whose_kc_is_not_the_one_signed_is_refused() {
    let peer = spawn_with(Options {
        iroh: false,
        iroh_relay: true,
        ..frasil_conformance::options()
    })
    .await
    .unwrap();
    let url = peer.relay_url.clone().expect("the relay runs");
    let bind = |alpns: &[Alpn]| {
        Endpoint::bind(
            Config::new(fresh_secret_key().unwrap(), alpns)
                .relay_only()
                .relays([url.clone()]),
        )
    };
    let dialer = bind(&[]).await.unwrap();
    let listener = bind(&[Alpn::Member]).await.unwrap();
    let key = listener.key();
    let (dialed, accepted) = within(async {
        tokio::join!(
            dialer.connect(&key, &[], std::slice::from_ref(&url), Alpn::Member),
            async { listener.accept().await.unwrap() },
        )
    })
    .await;
    let (dialed, accepted) = (dialed.unwrap(), accepted.unwrap());
    let fixtures = Fixtures::load();
    let dialer_session = dialed
        .member_session(&fixtures.seed("dialer"), fixtures.kc("dialer"))
        .unwrap();
    let listener_session = accepted
        .member_session(&fixtures.seed("listener"), fixtures.kc("listener"))
        .unwrap();
    // The dialer's Identify names Mallory's kc beside the dialer's ed, its
    // signature over the dialer's own.
    let forged = (fixtures.signer("dialer"), fixtures.kc("mallory"));
    let (_, l) = within(async {
        tokio::join!(
            run_forging(&dialed, dialer_session, &fixtures, Some(forged)),
            run(&accepted, listener_session, &fixtures),
        )
    })
    .await;
    let refused = l.expect_err("the listener refuses the Identify");
    assert_eq!(
        refused.class(),
        Some(frasil_transport::TransportClass::from(
            frasil_base::ErrorClass::BadSignature
        )),
        "{refused}"
    );
    dialer.close().await;
    listener.close().await;
    peer.shutdown().await;
}
