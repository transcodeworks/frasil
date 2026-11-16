//! `ext-next-endpoints.json`, the families of the transport
//! (ext-next-endpoints.md): `parameters`, `announcement`, `refused` and
//! `reconnecting`.
#![cfg(feature = "ext-next-endpoints")]

use frasil_base::Class;
use frasil_testkit::hex;
use frasil_transport::TransportClass;
use frasil_transport::ext_next_endpoints::{NextEndpoint, Outcome, announced_ticket, judge};
use frasil_transport::frame::{
    ConnectionKind, Extensions, Message, MessageType, Read, StreamClass, frame, read_frame,
    read_message,
};
use frasil_transport::ticket::Ticket;
use serde_json::Value as Json;

const FILE: &str = "ext-next-endpoints.json";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex")
}

fn key(value: &Json) -> [u8; 32] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

const WITH: Extensions = Extensions {
    next_endpoints: true,
    ..Extensions::NONE
};

fn connection(name: &str) -> ConnectionKind {
    match name {
        "member" => ConnectionKind::Member,
        _ => ConnectionKind::DeviceToPeer,
    }
}

/// A control-stream message on this connection, read by a receiver that
/// implements the extension, then by `NextEndpoint::read`.
fn read(payload: &[u8], kind: ConnectionKind) -> Result<NextEndpoint, TransportClass> {
    let message: Message =
        read_message(payload, StreamClass::Control, kind, WITH)?.expect("known with the extension");
    NextEndpoint::read(&message, kind)
}

#[test]
fn parameters() {
    let p = family("parameters");
    assert_eq!(p["type"].as_u64(), Some(MessageType::NextEndpoint.code()));
    assert_eq!(p["name"].as_str(), Some(MessageType::NextEndpoint.name()));
    assert_eq!(
        p["cap"].as_u64(),
        Some(MessageType::NextEndpoint.cap() as u64)
    );
    assert!(frasil_transport::frame::IGNORABLE.contains(&MessageType::NextEndpoint.code()));
    assert!(!MessageType::NextEndpoint.known_with(Extensions::NONE));
    assert!(MessageType::NextEndpoint.known_with(WITH));
}

#[test]
fn an_announcement_its_frame_and_each_outcome() {
    let a = family("announcement");
    let payload = bytes(&a["message"]);
    let framed = bytes(&a["frame"]);
    assert_eq!(frame(&payload), framed);
    let message = read(&payload, ConnectionKind::Member).unwrap();
    assert_eq!(message.attach, a["attach"].as_u64().unwrap());
    assert_eq!(message.key, key(&a["next_key"]));
    assert_eq!(message.encode(), payload);
    // A core receiver drops it.
    assert_eq!(a["core_receiver"].as_str(), Some("dropped"));
    assert_eq!(
        read_frame(
            &framed,
            StreamClass::Control,
            ConnectionKind::Member,
            Extensions::NONE
        ),
        Ok(Read::Dropped(&[]))
    );
    let sender = key(&a["sender_endpoint_key"]);
    for (case, admitted) in a["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .zip([true, false, true])
    {
        let message = read(&bytes(&case["message"]), ConnectionKind::Member).unwrap();
        let outcome = judge(&message, admitted, &sender);
        let expected = match case["outcome"].as_str().unwrap() {
            "kept" => {
                assert_eq!(message.key, key(&case["announced"]));
                Outcome::Kept
            }
            _ => Outcome::Dropped(case["step"].as_u64().unwrap() as u8),
        };
        assert_eq!(outcome, expected, "{}", case["description"]);
    }
}

#[test]
fn refused_messages() {
    for case in family("refused").as_array().unwrap() {
        let got = read(
            &bytes(&case["message"]),
            connection(case["connection"].as_str().unwrap()),
        )
        .err()
        .map(Class::name);
        assert_eq!(got, case["error"].as_str(), "{}", case["description"]);
    }
}

#[test]
fn the_tickets_dialed_when_reconnecting() {
    for case in family("reconnecting").as_array().unwrap() {
        let kept = Ticket::read_cbor(&bytes(&case["kept_ticket"])).unwrap();
        let mut dialed = vec![kept.cbor()];
        dialed.extend(announced_ticket(&kept, &key(&case["announced_key"])).map(|t| t.cbor()));
        let expected: Vec<Vec<u8>> = case["dialed"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect();
        assert_eq!(dialed, expected, "{}", case["description"]);
    }
}
