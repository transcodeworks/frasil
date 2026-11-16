//! frasil-transport's handshake readers on arbitrary control messages
//! (transport.md, 3.3 to 3.4 The member handshake, and 3.10 The
//! device-to-peer handshake): `read_offer`, the initiator's reply check,
//! `verify_identify`, both hellos, the peer's purpose checks, and member
//! sessions fed the message. They never panic; each refuses only with its
//! steps' classes; only a proof made under the offered state's member key
//! passes the initiator's check; and an accepted offer or hello writes back
//! to its own bytes.
#![no_main]

use frasil_base::ErrorClass;
use frasil_crypto::device::KeysCommitment;
use frasil_transport::TransportClass;
use frasil_transport::frame::{ConnectionKind, Extensions, StreamClass, read_message};
use frasil_transport::member::{
    self, Reply, Role, SentOffer, answer_proof, match_offer, member_key, read_offer,
    verify_identify,
};
use frasil_transport::peer::{Hello, Limits, PeerHello, PeerSide};
use frasil_transport::session::MemberSession;
use libfuzzer_sys::fuzz_target;

const CHANNEL: [u8; 32] = [7; 32];
const DIALER: [u8; 32] = [1; 32];
const LISTENER: [u8; 32] = [2; 32];
const SECRET: [u8; 32] = [3; 32];
const KC: KeysCommitment = KeysCommitment([10; 32]);

fn shared(error: &TransportClass, allowed: &[ErrorClass]) -> bool {
    matches!(error, TransportClass::Shared(class) if allowed.contains(class))
}

fuzz_target!(|data: &[u8]| {
    let Ok(Some(message)) = read_message(
        data,
        StreamClass::Control,
        ConnectionKind::Member,
        Extensions::NONE,
    ) else {
        return;
    };

    // The responder's steps 1 to 6.
    for (initiator, previous) in [(Role::Dialer, 0), (Role::Listener, 3), (Role::Dialer, 4)] {
        match read_offer(&message, initiator, previous) {
            Ok(offer) => {
                assert_eq!(offer.tags.len(), member::OFFER_TAGS);
                assert!(offer.attach < member::MAX_ATTACHES);
                assert_eq!(offer.attach % 2, initiator.parity());
                assert!(previous < member::MAX_OFFERS);
                assert_eq!(
                    member::encode_offer(offer.attach, &offer.nonce, &offer.tags, member::REVISION),
                    data
                );
                if let Err(error) = match_offer(&offer, &CHANNEL, [((), SECRET)]) {
                    assert_eq!(error, TransportClass::NoCommonState);
                }
            }
            Err(error) => assert!(
                error == TransportClass::AttachLimit
                    || shared(
                        &error,
                        &[ErrorClass::Malformed, ErrorClass::RevisionMismatch]
                    ),
                "{error:?}"
            ),
        }
    }

    // The initiator's steps 1 to 4, against an offer of one real state.
    let sent = SentOffer::new_with(0, &CHANNEL, [((), SECRET)], [4; 32], &[[5; 32]; 16]);
    match sent.read_reply(&message, &CHANNEL, &DIALER, &LISTENER) {
        Ok(Reply::Refused(_)) => {}
        Ok(Reply::Answered { index, transcript }) => {
            assert_eq!(index, 0);
            let proof = message.get(4).unwrap().as_bytes().unwrap();
            assert_eq!(answer_proof(&member_key(&SECRET), &transcript), proof);
        }
        Err(error) => assert!(
            error == TransportClass::BadProof || shared(&error, &[ErrorClass::Malformed]),
            "{error:?}"
        ),
    }

    // Identify, steps 6 to 8.
    for role in [Role::Dialer, Role::Listener] {
        let verified = verify_identify(&message, &CHANNEL, role);
        if let Ok(signer) = &verified {
            let key = message.get(1).and_then(|v| v.as_bytes().ok());
            assert_eq!(key, Some(&signer.to_bytes()[..]));
        }
        if let Err(error) = verified {
            assert!(
                shared(
                    &error,
                    &[
                        ErrorClass::Malformed,
                        ErrorClass::InvalidKey,
                        ErrorClass::BadSignature
                    ]
                ),
                "{error:?}"
            );
        }
    }

    // The hellos.
    let hello_classes = [
        ErrorClass::Malformed,
        ErrorClass::UnsupportedVersion,
        ErrorClass::RevisionMismatch,
    ];
    match Hello::read(&message) {
        Ok(hello) => assert_eq!(Hello::encode(&hello.nonce, hello.purpose), data),
        Err(error) => assert!(shared(&error, &hello_classes), "{error:?}"),
    }
    if let Err(error) = PeerHello::read(&message) {
        assert!(shared(&error, &hello_classes), "{error:?}");
    }

    // The peer's end: the message as the Hello, then as a request.
    let (mut peer, _) = PeerSide::start_with(CHANNEL, [6; 32], &[], &Limits::PROTOCOL);
    let _ = peer.on_hello(&message);
    let _ = peer.on_message(&message);

    // Member sessions: a listener before any offer, and a dialer awaiting
    // its answer.
    let mut listener =
        MemberSession::<()>::new(Role::Listener, CHANNEL, LISTENER, DIALER, &[8; 32], KC);
    if let Ok(events) = listener.receive(&message) {
        for event in events {
            if let frasil_transport::session::Event::OfferReceived { attach } = event {
                let _ = listener.respond_with(attach, [((), SECRET)], [9; 32]);
            }
        }
    }
    let mut dialer =
        MemberSession::<()>::new(Role::Dialer, CHANNEL, DIALER, LISTENER, &[8; 32], KC);
    dialer
        .offer_with([((), SECRET)], [4; 32], &[[5; 32]; 16])
        .expect("attach 0");
    let _ = dialer.receive(&message);
});
