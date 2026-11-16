//! transport.md, sections 2.2 to 2.5, 2.8, 2.9, 3.1 and 3.16's packets:
//! the `labels`, `parameters`, `framing`, `tickets` and `local_network`
//! families.

mod common;

use common::*;
use frasil_base::Class;
use frasil_transport::codes::{Code, REASONS, Service, reason_status};
use frasil_transport::frame::{
    ConnectionKind, Deframer, Extensions, IGNORABLE, MessageType, Read, StreamClass, frame,
    read_frame,
};
use frasil_transport::messages::{
    Admit, Detach, Ephemeral, EventRefused, Open, Pairing, Scope, Sync,
};
use frasil_transport::peer::Limits;
use frasil_transport::ticket::{Address, Ticket, TicketKind};
use frasil_transport::{labels, lan, mailbox, member, roster};
use std::net::{Ipv4Addr, Ipv6Addr};

fn connection(name: &str) -> ConnectionKind {
    match name {
        "member" => ConnectionKind::Member,
        "peer" => ConnectionKind::DeviceToPeer,
        other => panic!("connection {other}"),
    }
}

fn class(name: &str) -> StreamClass {
    StreamClass::from_name(name).expect("a stream class")
}

#[test]
fn labels() {
    let family = family("labels");
    let map = family.as_object().unwrap();
    assert_eq!(map.len(), labels::ALL.len());
    for label in labels::ALL {
        let name = std::str::from_utf8(label).unwrap();
        assert_eq!(bytes(&map[name]), label, "{name}");
    }
    // No label is a prefix of another.
    for a in labels::ALL {
        for b in labels::ALL {
            assert!(a == b || !b.starts_with(a));
        }
    }
}

#[test]
fn parameters() {
    let p = family("parameters");
    assert_eq!(number(&p["revision"]), member::REVISION);
    assert_eq!(number(&p["offer_tags"]) as usize, member::OFFER_TAGS);
    assert_eq!(number(&p["extra_offers"]) as usize, member::EXTRA_OFFERS);
    assert_eq!(
        number(&p["candidates_per_space"]) as usize,
        member::CANDIDATES_PER_SPACE
    );
    assert_eq!(
        number(&p["candidate_budget"]) as usize,
        member::CANDIDATE_BUDGET
    );
    assert_eq!(number(&p["max_attaches"]), u64::from(member::MAX_ATTACHES));
    assert_eq!(
        number(&p["handshake_deadline_seconds"]),
        frasil_transport::HANDSHAKE_DEADLINE_SECONDS
    );
    assert_eq!(
        number(&p["probation"]["seconds"]),
        roster::PROBATION_SECONDS
    );
    assert_eq!(number(&p["probation"]["events"]), roster::PROBATION_EVENTS);
    assert_eq!(
        number(&p["pairing_deadline_seconds"]),
        frasil_transport::PAIRING_DEADLINE_SECONDS
    );
    assert_eq!(text(&p["exporter_label"]).as_bytes(), labels::EXPORTER);
    assert_eq!(
        number(&p["exporter_bytes"]) as usize,
        labels::EXPORTER_BYTES
    );
    assert_eq!(
        text(&p["websocket_subprotocol"]),
        labels::WEBSOCKET_SUBPROTOCOL
    );

    let caps = p["stream_caps"].as_object().unwrap();
    assert_eq!(caps.len(), StreamClass::ALL.len());
    for c in StreamClass::ALL {
        assert_eq!(number(&caps[c.name()]) as usize, c.cap(), "{}", c.name());
    }

    let types = p["message_types"].as_array().unwrap();
    assert_eq!(types.len(), MessageType::ALL.len());
    for (row, &kind) in types.iter().zip(MessageType::ALL) {
        assert_eq!(number(&row["type"]), kind.code());
        assert_eq!(text(&row["name"]), kind.name());
        assert_eq!(number(&row["cap"]) as usize, kind.cap(), "{}", kind.name());
        let classes: Vec<&str> = row["classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(text)
            .collect();
        let ours: Vec<&str> = kind.classes().iter().map(|c| c.name()).collect();
        assert_eq!(classes, ours, "{}", kind.name());
        assert_eq!(row.get("extension").map(text), kind.extension());
        // ext-deposit-tokens.md's types count only in a build with its
        // feature.
        let deposit = kind.extension() == Some("ext-deposit-tokens.md");
        assert_eq!(
            kind.known_with(Extensions {
                libraries: true,
                invite_links: true,
                next_endpoints: true,
                deposit_tokens: true,
            }),
            !deposit || cfg!(feature = "ext-deposit-tokens")
        );
        assert_eq!(
            kind.known_with(Extensions::NONE),
            kind.extension().is_none()
        );
    }
    assert_eq!(
        (
            number(&p["ignorable_types"][0]),
            number(&p["ignorable_types"][1])
        ),
        (*IGNORABLE.start(), *IGNORABLE.end())
    );

    let codes = p["codes"].as_object().unwrap();
    assert_eq!(codes.len(), Code::ALL.len());
    for &code in Code::ALL {
        assert_eq!(text(&codes[&code.number().to_string()]), code.name());
        assert_eq!(Code::from_name(code.name()), Some(code));
        assert_eq!(Code::from_websocket(code.websocket()), Some(code));
        // Each name but done and reconnect is a class in snake case.
        match code.class() {
            None => assert!(matches!(code, Code::Done | Code::Reconnect)),
            Some(class) => {
                assert_eq!(class.wire_name(), code.name());
                assert_eq!(class.code(), Some(code));
            }
        }
    }

    let reasons = p["reasons"].as_object().unwrap();
    assert_eq!(reasons.len(), REASONS.len());
    for (reason, status) in reasons {
        assert_eq!(
            reason_status(reason),
            Some(number(status) as u16),
            "{reason}"
        );
    }

    let services = p["services"].as_object().unwrap();
    assert_eq!(services.len(), Service::ALL.len());
    for service in Service::ALL {
        assert_eq!(text(&services[&service.code().to_string()]), service.name());
    }

    let limits = &p["peer_limits"];
    assert_eq!(
        number(&limits["max_frame_bytes"]),
        Limits::PROTOCOL.max_frame_bytes
    );
    assert_eq!(
        number(&limits["max_streams_per_space"]),
        Limits::PROTOCOL.max_streams_per_space
    );
    assert_eq!(
        number(&limits["max_mailbox_item_bytes"]),
        Limits::PROTOCOL.max_mailbox_item_bytes
    );
    assert_eq!(
        number(&limits["max_chunk_bytes"]),
        Limits::PROTOCOL.max_chunk_bytes
    );

    assert_eq!(
        text(&p["lan_groups"][0]),
        Ipv4Addr::from(lan::GROUP_V4).to_string()
    );
    assert_eq!(
        text(&p["lan_groups"][1]),
        Ipv6Addr::from(lan::GROUP_V6).to_string()
    );
    assert_eq!(number(&p["lan_port"]), u64::from(lan::PORT));
    assert_eq!(number(&p["lan_packet_bytes"]) as usize, lan::PACKET_BYTES);
    assert_eq!(
        number(&p["nearby_name_characters"]) as usize,
        lan::NAME_CHARACTERS
    );
    assert_eq!(
        number(&p["ticket_max_bytes"]) as usize,
        frasil_transport::ticket::MAX_BYTES
    );
    assert_eq!(
        number(&p["mailbox_item_bytes"]) as usize,
        frasil_transport::frame::MAILBOX_ITEM_BYTES
    );
    assert_eq!(
        number(&p["mailbox_item_min_bytes"]) as usize,
        mailbox::MIN_ITEM_BYTES
    );
    assert_eq!(
        number(&p["content_name_bytes"]) as usize,
        mailbox::CONTENT_NAME_BYTES
    );
    assert_eq!(
        number(&p["device_mailbox_items"]) as usize,
        mailbox::DEVICE_MAILBOX_ITEMS
    );
    assert_eq!(
        number(&p["device_mailbox_bytes"]) as usize,
        mailbox::DEVICE_MAILBOX_BYTES
    );
}

#[test]
fn framing_examples() {
    let family = family("framing");
    let mut all = Vec::new();
    for case in family["examples"].as_array().unwrap() {
        let description = text(&case["description"]);
        let data = bytes(&case["frame"]);
        let class = class(text(&case["stream"]));
        let connection = connection(text(&case["connection"]));
        let Read::Message(message, rest) =
            read_frame(&data, class, connection, Extensions::NONE).unwrap()
        else {
            panic!("{description}: not a message");
        };
        assert!(rest.is_empty(), "{description}");
        assert_eq!(frame(&message.bytes), data, "{description}");
        // Each reads as its type and writes back the same bytes.
        let again = match message.kind {
            MessageType::Admit => Admit::read(&message).unwrap().encode(),
            MessageType::Detach => {
                let detach = Detach::read(&message).unwrap();
                assert_eq!(detach.code, Code::MembershipEnded);
                detach.encode()
            }
            MessageType::Open => {
                let open = Open::read(&message, connection).unwrap();
                assert_eq!(open.class, StreamClass::Sync);
                assert_eq!(open.scope, Some(Scope::Attach(0)));
                open.encode()
            }
            MessageType::Ephemeral => Ephemeral::read(&message, connection).unwrap().encode(),
            MessageType::Sync => Sync::read(&message, connection).unwrap().encode(),
            MessageType::ErasureLate => {
                let late = frasil_transport::messages::ErasureLate::read(&message).unwrap();
                assert!(late.standing <= 2, "{description}");
                late.encode()
            }
            other => panic!("{description}: {other:?}"),
        };
        assert_eq!(again, message.bytes, "{description}");
        all.push((class, connection, data));
    }
    // A deframer reads each frame however its bytes arrive.
    for (class, connection, data) in all {
        let mut deframer = Deframer::new(class, connection, Extensions::NONE);
        let mut doubled = data.clone();
        doubled.extend_from_slice(&data);
        let mut read = Vec::new();
        for chunk in doubled.chunks(7) {
            deframer.push(chunk);
            while let Some(message) = deframer.next_message().unwrap() {
                read.push(message.bytes);
            }
        }
        assert_eq!(read.len(), 2);
        assert_eq!(deframer.pending(), 0);
    }
}

#[test]
fn framing_caps() {
    for case in family("framing")["caps"].as_array().unwrap() {
        let prefix = bytes(&case["prefix"]);
        let class = class(text(&case["stream"]));
        assert_eq!(
            u32::from_be_bytes(prefix.clone().try_into().unwrap()) as u64,
            number(&case["length"])
        );
        let read = read_frame(
            &prefix,
            class,
            ConnectionKind::DeviceToPeer,
            Extensions::NONE,
        );
        match text(&case["result"]) {
            "read on" => assert_eq!(read, Ok(Read::Incomplete)),
            expected => assert_eq!(class_of(read), Some(expected)),
        }
    }
}

fn class_of<T>(result: Result<T, frasil_transport::TransportClass>) -> Option<&'static str> {
    common::class(result)
}

#[test]
fn framing_refused_and_dropped() {
    let family = family("framing");
    for case in family["refused"].as_array().unwrap() {
        let description = text(&case["description"]);
        let data = bytes(&case["frame"]);
        let read = read_frame(
            &data,
            class(text(&case["stream"])),
            connection(text(&case["connection"])),
            Extensions::NONE,
        );
        assert_eq!(class_of(read), Some(text(&case["error"])), "{description}");
    }
    for case in family["dropped"].as_array().unwrap() {
        let data = bytes(&case["frame"]);
        let read = read_frame(
            &data,
            class(text(&case["stream"])),
            connection(text(&case["connection"])),
            Extensions::NONE,
        );
        assert_eq!(read, Ok(Read::Dropped(&[][..])));
        assert_eq!(text(&case["result"]), "dropped");
        let mut deframer = Deframer::new(
            StreamClass::Control,
            ConnectionKind::DeviceToPeer,
            Extensions::NONE,
        );
        deframer.push(&data);
        assert_eq!(deframer.next_message(), Ok(None));
        assert_eq!(deframer.pending(), 0);
    }
    // A LibraryAttach is known to a receiver that implements ext-libraries.
    let library = family["refused"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| text(&c["description"]).starts_with("a LibraryAttach"))
        .unwrap();
    let data = bytes(&library["frame"]);
    let read = read_frame(
        &data,
        StreamClass::Control,
        ConnectionKind::DeviceToPeer,
        Extensions {
            libraries: true,
            ..Extensions::NONE
        },
    )
    .unwrap();
    assert!(matches!(read, Read::Message(m, _) if m.kind == MessageType::LibraryAttach));
}

#[test]
fn tickets() {
    let family = family("tickets");
    let text_form = text(&family["ticket"]);
    let ticket = Ticket::read(text_form).unwrap();
    assert_eq!(
        ticket.kind,
        TicketKind::from_code(number(&family["kind"])).unwrap()
    );
    assert_eq!(ticket.endpoint, array(&family["endpoint_key"]));
    let relays: Vec<&str> = family["relays"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(ticket.relays, relays);
    let addresses: Vec<Vec<u8>> = family["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect();
    assert_eq!(
        ticket
            .addresses
            .iter()
            .map(Address::encode)
            .collect::<Vec<_>>(),
        addresses
    );
    assert_eq!(ticket.addresses, [Address::V4([192, 168, 1, 20], 47_767)]);
    assert_eq!(ticket.cbor(), bytes(&family["cbor"]));
    assert_eq!(ticket.encode().unwrap(), text_form);
    for case in family["refused"].as_array().unwrap() {
        assert_eq!(
            class_of(Ticket::read(text(&case["ticket"]))),
            Some(text(&case["error"])),
            "{}",
            text(&case["description"])
        );
    }
}

#[test]
fn local_network() {
    let family = family("local_network");
    let handshake = Handshake::load();
    let secret = |label: &str| handshake.secret(label);
    let key = &family["lan_key"];
    assert_eq!(text(&key["state"]), "{C}");
    assert_eq!(secret("{C}"), array(&key["content_key"]));
    assert_eq!(*lan::lan_key(&secret("{C}")), array::<32>(&key["key"]));

    let endpoint = handshake.endpoint("listener");
    let port = 47_767;
    assert_eq!(
        lan::plaintext(&endpoint, port).to_vec(),
        bytes(&family["plaintext"])
    );
    let packet = lan::announce_with(&secret("{C}"), &endpoint, port, &array(&family["nonce"]));
    assert_eq!(packet.to_vec(), bytes(&family["packet"]));
    assert_eq!(packet.len() as u64, number(&family["packet_bytes"]));

    let tries: Vec<[u8; 32]> = family["listener_tries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| secret(text(l)))
        .collect();
    let opened = lan::open(&packet, &tries).unwrap();
    assert_eq!(
        text(&family["listener_tries"][opened.state]),
        text(&family["opened_with"])
    );
    assert_eq!(opened.endpoint, array(&family["opened"]["endpoint_key"]));
    assert_eq!(u64::from(opened.port), number(&family["opened"]["port"]));

    let second = &family["second_packet"];
    let again = lan::announce_with(&secret("{C}"), &endpoint, port, &array(&second["nonce"]));
    assert_eq!(again.to_vec(), bytes(&second["packet"]));
    // The two packets of one device share only their first byte.
    assert!(
        packet[1..]
            .iter()
            .zip(&again[1..])
            .filter(|(a, b)| a == b)
            .count()
            < 16
    );

    let other = array(&family["non_member_content_key"]);
    assert_eq!(
        class_of(lan::open(&packet, &[other])),
        Some(text(&family["non_member"]))
    );
    assert_eq!(
        class_of(lan::open(&packet, &[secret("{B}")])),
        Some(text(&family["older_state_only"]))
    );
    // A listener tries the current state and up to 3 before it.
    let five = [other, other, other, other, secret("{C}")];
    assert_eq!(class_of(lan::open(&packet, &five)), Some("NotForMe"));
    assert_eq!(class_of(lan::open(&packet[1..], &tries)), Some("Malformed"));

    let name_in = text(&family["nearby_name_in"]);
    assert_eq!(lan::nearby_name(name_in), text(&family["nearby_name_out"]));
    let empty = &family["nearby_name_empty"];
    assert_eq!(lan::nearby_name(text(&empty["in"])), text(&empty["out"]));
    let nearby_endpoint = array(&family["nearby_endpoint"]);
    let nearby_port = u16::try_from(family["nearby_port"].as_u64().unwrap()).unwrap();
    let nearby = lan::nearby_announce(&nearby_endpoint, nearby_port, name_in);
    assert_eq!(nearby, bytes(&family["nearby_packet"]));
    let read = lan::read_nearby(&nearby).unwrap();
    assert_eq!(read.endpoint, nearby_endpoint);
    assert_eq!(read.port, nearby_port);
    assert_eq!(read.name, text(&family["nearby_name_out"]));
}

#[test]
fn nearby_names_are_cut_to_48_characters() {
    let long = "é".repeat(60);
    assert_eq!(lan::nearby_name(&long).chars().count(), 48);
    assert_eq!(lan::nearby_name("  a\u{2066}b  "), "ab");
    assert_eq!(
        lan::nearby_name(&format!("{} x", "y".repeat(47))),
        "y".repeat(47)
    );
    assert_eq!(lan::setup_name(&[0xab, 0x01]), "setup-ab01");
}

#[test]
fn error_classes_have_snake_case_wire_names() {
    for &class in frasil_transport::TransportClass::OWN {
        assert_eq!(
            class.wire_name(),
            frasil_base::errors::snake_case(class.name())
        );
    }
}

/// `Pairing`'s key 2 carries a member ticket's text beside the welcome,
/// and `EventRefused` names an event with exactly its keys (section 2.4).
#[test]
fn pairing_tickets_and_event_refusals() {
    let read = |bytes: &[u8], class| {
        frasil_transport::frame::read_message(
            bytes,
            class,
            ConnectionKind::Nearby,
            Extensions::NONE,
        )
        .unwrap()
        .unwrap()
    };
    let ticket = Ticket {
        kind: TicketKind::Member,
        endpoint: frasil_crypto::primitives::ed25519_public(&[7; 32]),
        relays: Vec::new(),
        addresses: Vec::new(),
    }
    .encode()
    .unwrap();
    let welcome = Pairing {
        message: vec![1, 2, 3],
        ticket: Some(ticket.clone()),
    };
    let read_back = Pairing::read(&read(&welcome.encode(), StreamClass::Nearby)).unwrap();
    assert_eq!(read_back, welcome);
    assert_eq!(Ticket::read(&ticket).unwrap().kind, TicketKind::Member);
    let bare = Pairing {
        message: vec![1],
        ticket: None,
    };
    assert_eq!(
        Pairing::read(&read(&bare.encode(), StreamClass::Nearby)).unwrap(),
        bare
    );
    // A ticket that is not text does not read.
    let mut map = frasil_base::cbor::Map::new();
    map.insert(0, frasil_base::cbor::Value::Unsigned(64));
    map.insert(1, frasil_base::cbor::Value::from(&[1u8][..]));
    map.insert(2, frasil_base::cbor::Value::from(&[2u8][..]));
    let bytes = frasil_base::cbor::Value::Map(map).encode();
    assert!(Pairing::read(&read(&bytes, StreamClass::Nearby)).is_err());

    let refused = EventRefused {
        space: [1; 32],
        event: [2; 32],
        code: "conflict".into(),
    };
    let message = frasil_transport::frame::read_message(
        &refused.encode(),
        StreamClass::Control,
        ConnectionKind::DeviceToPeer,
        Extensions::NONE,
    )
    .unwrap()
    .unwrap();
    assert_eq!(message.kind, MessageType::EventRefused);
    assert_eq!(EventRefused::read(&message).unwrap(), refused);
}
