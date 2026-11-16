//! The member handshake (transport.md, sections 3.2 to 3.5) over loopback
//! QUIC: `frasil_transport::session::MemberSession` on each end of a real
//! `frasil/p1/member` connection, with the endpoint keys TLS proved and
//! RFC 9266's exporter as the channel. A relay that splices two QUIC
//! sessions makes it fail.

mod common;

use common::*;
use frasil_crypto::device::{DeviceId, KeysCommitment};
use frasil_iroh::{Alpn, Connection, Error, FrameReceiver, FrameSender, Role};
use frasil_transport::Code;
use frasil_transport::roster::{Serving, Verdict};
use frasil_transport::session::{Event, MemberSession};
use serde_json::Value as Json;

fn random<const N: usize>() -> [u8; N] {
    *frasil_crypto::random_bytes::<N>().unwrap()
}

/// The member handshake's fixtures: the devices and every state's
/// content key, by label. The channel and endpoint keys come from the
/// connection, not from the vectors.
struct Fixtures {
    json: Json,
}

impl Fixtures {
    fn load() -> Self {
        Self {
            json: family("member_handshake"),
        }
    }

    fn secret(&self, label: &str) -> [u8; 32] {
        array(&self.json["content_keys"][label])
    }

    fn states(&self, labels: &Json) -> Vec<(String, [u8; 32])> {
        labels
            .as_array()
            .unwrap()
            .iter()
            .map(|l| (text(l).to_owned(), self.secret(text(l))))
            .collect()
    }

    /// The dialer's offered states: its current state merges C and D.
    fn offered(&self) -> Vec<(String, [u8; 32])> {
        self.states(&self.json["offer"]["offered_states"])
    }

    /// The listener's candidates: another space's state first, then the
    /// states of this space it holds.
    fn candidates(&self) -> Vec<(String, [u8; 32])> {
        let mut out = vec![(
            "other space".to_owned(),
            array(&self.json["other_space"]["content_key"]),
        )];
        out.extend(self.states(&self.json["listener_candidates"]));
        out
    }

    fn seed(&self, side: &str) -> [u8; 32] {
        array(&self.json["devices"][side]["seed"])
    }

    fn kc(&self, side: &str) -> KeysCommitment {
        KeysCommitment(array(&self.json["devices"][side]["kc"]))
    }

    fn device(&self, side: &str) -> DeviceId {
        DeviceId(array(&self.json["devices"][side]["device_id"]))
    }

    /// A member session on `connection` for the device `side`.
    fn session(&self, connection: &Connection, side: &str) -> MemberSession<String> {
        connection
            .member_session(&self.seed(side), self.kc(side))
            .unwrap()
    }
}

/// What one end saw of the handshake.
#[derive(Debug)]
struct Outcome {
    session: MemberSession<String>,
    refusals: Vec<(Code, bool)>,
}

/// Runs one end of attach 0 over the control stream: the dialer offers,
/// retrying after a refusal while it may; the listener answers from its
/// candidates; each end admits the other at the roster check. Ends when
/// both ends admitted attach 0, or the attach is over.
async fn run(
    connection: &Connection,
    mut session: MemberSession<String>,
    fixtures: &Fixtures,
) -> Result<Outcome, Error> {
    let (mut sender, mut receiver): (FrameSender, FrameReceiver) = connection.control().await?;
    let mut refusals = Vec::new();
    let mut pending = Vec::new();
    if connection.role() == Role::Dialer {
        let (attach, events) = session
            .offer_with(fixtures.offered(), random(), &[random(); 16])
            .unwrap();
        assert_eq!(attach, 0);
        pending.extend(events);
    }
    loop {
        while !pending.is_empty() {
            for event in std::mem::take(&mut pending) {
                match event {
                    Event::Send(message) => sender.send(&message).await?,
                    Event::OfferReceived { attach } => pending.extend(
                        session
                            .respond_with(attach, fixtures.candidates(), random())
                            .unwrap(),
                    ),
                    Event::CheckRoster { attach, .. } => {
                        pending.extend(session.verdict(attach, Verdict::Admit).unwrap());
                    }
                    Event::Refused {
                        attach,
                        code,
                        may_retry,
                    } => {
                        refusals.push((code, may_retry));
                        if may_retry {
                            pending.extend(
                                session
                                    .retry_with(
                                        attach,
                                        fixtures.offered(),
                                        random(),
                                        &[random(); 16],
                                    )
                                    .unwrap(),
                            );
                        } else {
                            return Ok(Outcome { session, refusals });
                        }
                    }
                    _ => {}
                }
            }
        }
        if session.serving(0) == Serving::Everything && session.admitted_by_other(0) {
            return Ok(Outcome { session, refusals });
        }
        let Some(message) = receiver.receive().await? else {
            return Err(Error::Truncated);
        };
        pending.extend(session.receive(&message)?);
    }
}

#[tokio::test]
async fn the_member_handshake_completes_over_loopback_quic() {
    let fixtures = Fixtures::load();
    let (_d, _l, dialer, listener) = pair(Alpn::Member).await;

    // T1: each end holds the other's endpoint key as TLS proved it. T2:
    // both computed the same exporter.
    assert_eq!(dialer.peer(), listener.local());
    assert_eq!(listener.peer(), dialer.local());
    assert_eq!(
        (dialer.role(), listener.role()),
        (Role::Dialer, Role::Listener)
    );
    assert_eq!(dialer.channel(), listener.channel());
    assert_ne!(dialer.channel(), [0; 32]);

    let dialer_session = fixtures.session(&dialer, "dialer");
    let listener_session = fixtures.session(&listener, "listener");
    let (d, l) = within(async {
        tokio::join!(
            run(&dialer, dialer_session, &fixtures),
            run(&listener, listener_session, &fixtures),
        )
    })
    .await;
    let (d, l) = (d.unwrap(), l.unwrap());

    assert!(d.refusals.is_empty() && l.refusals.is_empty());
    // Both ends bound the same transcript and learned each other's
    // device ID; the match is the vectors' state {C}.
    assert!(d.session.transcript0().is_some());
    assert_eq!(d.session.transcript0(), l.session.transcript0());
    assert_eq!(
        d.session.remote_device(),
        Some(&fixtures.device("listener"))
    );
    assert_eq!(l.session.remote_device(), Some(&fixtures.device("dialer")));
    assert_eq!(d.session.state(0).map(String::as_str), Some("{C}"));
    assert_eq!(l.session.state(0).map(String::as_str), Some("{C}"));
    assert!(d.session.settled() && l.session.settled());
}

#[tokio::test]
async fn each_connection_has_its_own_exporter() {
    let dialer = endpoint(&[]).await;
    let listener = endpoint(&[Alpn::Member]).await;
    let (a, b) = connect(&dialer, &listener, Alpn::Member).await;
    let (c, d) = connect(&dialer, &listener, Alpn::Member).await;
    assert_eq!(a.channel(), b.channel());
    assert_eq!(c.channel(), d.channel());
    assert_ne!(a.channel(), c.channel());
    // A member session belongs on a member connection only.
    let peer_listener = endpoint(&[Alpn::Peer]).await;
    let (e, _f) = connect(&dialer, &peer_listener, Alpn::Peer).await;
    assert!(
        e.member_session::<String>(&[1; 32], KeysCommitment([0; 32]))
            .is_err()
    );
}

/// Passes every control message from one connection to another, as they
/// are, until either ends.
async fn splice(mut from: FrameReceiver, mut to: FrameSender) {
    while let Ok(Some(message)) = from.receive().await {
        if to.send(&message.bytes).await.is_err() {
            break;
        }
    }
}

#[tokio::test]
async fn a_relay_that_splices_two_sessions_fails_the_handshake() {
    let fixtures = Fixtures::load();
    // The dialer was handed the relay's endpoint key in place of the
    // listener's. The relay holds two QUIC sessions, each with its own
    // exporter, and passes the control stream's messages between them.
    let dialer_endpoint = endpoint(&[]).await;
    let relay_endpoint = endpoint(&[Alpn::Member]).await;
    let listener_endpoint = endpoint(&[Alpn::Member]).await;
    let (dialer, relay_in) = connect(&dialer_endpoint, &relay_endpoint, Alpn::Member).await;
    let (relay_out, listener) = connect(&relay_endpoint, &listener_endpoint, Alpn::Member).await;
    assert_eq!(dialer.channel(), relay_in.channel());
    assert_eq!(relay_out.channel(), listener.channel());
    assert_ne!(dialer.channel(), listener.channel());
    assert_eq!(dialer.peer(), relay_endpoint.key());
    assert_eq!(listener.peer(), relay_endpoint.key());

    let relay = tokio::spawn(async move {
        // The dialer writes first; the relay then opens its own control
        // stream to the listener.
        let (in_send, in_receive) = relay_in.control().await.unwrap();
        let (out_send, out_receive) = relay_out.control().await.unwrap();
        tokio::join!(splice(in_receive, out_send), splice(out_receive, in_send));
    });

    let dialer_session = fixtures.session(&dialer, "dialer");
    let listener_session = fixtures.session(&listener, "listener");
    let listener_task = {
        let fixtures = Fixtures::load();
        tokio::spawn(async move {
            let outcome = run(&listener, listener_session, &fixtures).await;
            (outcome, listener)
        })
    };
    let d = within(run(&dialer, dialer_session, &fixtures))
        .await
        .unwrap();

    // Each offer's tags bind the dialer's channel, which the listener does
    // not share: every offer is refused, and after the fourth the attach is
    // over. Neither end learned the other's device ID.
    assert_eq!(
        d.refusals,
        [
            (Code::NoCommonState, true),
            (Code::NoCommonState, true),
            (Code::NoCommonState, true),
            (Code::NoCommonState, false),
        ]
    );
    assert_eq!(d.session.remote_device(), None);
    assert_eq!(d.session.transcript0(), None);
    assert_eq!(d.session.serving(0), Serving::Nothing);

    // The listener answered nothing but refusals. Closing the dialer ends
    // the relay, whose connection to the listener goes with it.
    dialer.close(Code::Done);
    within(relay).await.unwrap();
    let (outcome, listener) = within(listener_task).await.unwrap();
    assert!(outcome.is_err());
    assert!(listener.closed().await.code().is_some());
}
