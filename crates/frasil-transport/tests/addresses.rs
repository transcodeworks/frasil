//! transport.md, 3.16 The iroh binding, member addresses: the
//! `member_addresses` family.

mod common;

use common::*;
use frasil_crypto::device::DeviceId;
use frasil_transport::addresses::{
    Addresses, CROSS_DIAL_WAIT_SECONDS, Known, LEARNED_SECONDS, LEARNED_TICKETS, MAX_ENTRIES,
    Outcome, Receiver, for_guest, judge, local_network,
};
use frasil_transport::frame::{ConnectionKind, Extensions, StreamClass, frame, read_message};
use frasil_transport::ticket::{Address, Ticket};
use serde_json::Value as Json;
use std::collections::BTreeSet;

fn keys(value: &Json) -> BTreeSet<DeviceId> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|id| DeviceId(array(id)))
        .collect()
}

/// A list of `{device_id, ticket}`.
fn tickets(value: &Json) -> Vec<(DeviceId, Ticket)> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                DeviceId(array(&entry["device_id"])),
                Ticket::read_cbor(&bytes(&entry["ticket"])).unwrap(),
            )
        })
        .collect()
}

#[test]
fn limits() {
    let limits = &family("member_addresses")["limits"];
    assert_eq!(number(&limits["max_entries"]) as usize, MAX_ENTRIES);
    assert_eq!(number(&limits["learned_tickets"]) as usize, LEARNED_TICKETS);
    assert_eq!(number(&limits["learned_seconds"]), LEARNED_SECONDS);
    assert_eq!(
        number(&limits["cross_dial_wait_seconds"]),
        CROSS_DIAL_WAIT_SECONDS
    );
}

#[test]
fn an_addresses_and_each_entry_s_outcome() {
    let family = family("member_addresses");
    let payload = bytes(&family["message"]);
    assert_eq!(frame(&payload), bytes(&family["frame"]));
    let addresses = Addresses::read(&control(&payload)).unwrap();
    assert_eq!(addresses.attach, number(&family["attach"]));
    // It writes back the same bytes, and the sender's list fits as is.
    assert_eq!(addresses.encode(), payload);
    assert_eq!(
        Addresses::fitting(addresses.attach, addresses.entries.clone()),
        Some(addresses.clone())
    );
    let r = &family["receiver"];
    let receiver = Receiver {
        device: DeviceId(array(&r["device_id"])),
        sender: DeviceId(array(&family["sender"]["device_id"])),
        endpoint: array(&r["endpoint_key"]),
    };
    let (view, attached) = (keys(&r["view"]), keys(&r["attached"]));
    let cases = family["entries"].as_array().unwrap();
    assert_eq!(cases.len(), addresses.entries.len());
    let mut learned = Vec::new();
    for ((member, ticket), case) in addresses.entries.iter().zip(cases) {
        assert_eq!(member.0, array::<32>(&case["device_id"]));
        assert_eq!(ticket.cbor(), bytes(&case["ticket"]));
        assert_eq!(Ticket::read(text(&case["ticket_text"])).unwrap(), *ticket);
        assert_eq!(ticket.endpoint, array::<32>(&case["endpoint_key"]));
        let known = Known {
            reaches: view.contains(member),
            attached: attached.contains(member),
        };
        let expected = match text(&case["outcome"]) {
            "skipped" => Outcome::Skipped(number(&case["step"]) as u8),
            "dialed" => Outcome::Dial,
            other => panic!("outcome {other}"),
        };
        let outcome = judge(&receiver, member, ticket, known);
        assert_eq!(outcome, expected);
        if outcome == Outcome::Dial {
            learned.push((*member, ticket.clone()));
        }
    }
    // What it dials it holds among its learned tickets; the tickets it
    // keeps stay as they were, a kept ticket of a member it dialed included.
    assert_eq!(learned, tickets(&family["learned"]));
    let kept = tickets(&r["kept"]);
    assert_eq!(kept, tickets(&family["kept_after"]));
    assert!(
        kept.iter()
            .any(|(k, _)| learned.iter().any(|(l, _)| l == k))
    );
    assert_eq!(text(&family["not_admitted"]), "dropped");
}

#[test]
fn a_sender_lists_local_network_addresses_alone_to_a_guest() {
    let sending = &family("member_addresses")["sending"];
    let members = tickets(&sending["members"]);
    let to_member = Addresses::fitting(0, members.clone()).unwrap();
    assert_eq!(to_member.encode(), bytes(&sending["to_member"]));
    let narrowed: Vec<(DeviceId, Ticket)> = members
        .iter()
        .filter_map(|(k, t)| for_guest(t).map(|t| (*k, t)))
        .collect();
    assert_eq!(narrowed, tickets(&sending["guest_entries"]));
    assert!(narrowed.iter().all(|(_, t)| t.relays.is_empty()));
    let to_guest = Addresses::fitting(0, narrowed).unwrap();
    assert_eq!(to_guest.encode(), bytes(&sending["to_guest"]));
    assert_eq!(
        Addresses::read(&control(&bytes(&sending["to_guest"]))).unwrap(),
        to_guest
    );
    for case in sending["addresses"].as_array().unwrap() {
        let address = Address::read(&bytes(&case["address"])).unwrap();
        assert_eq!(
            local_network(&address),
            case["local_network"].as_bool().unwrap(),
            "{}",
            text(&case["text"])
        );
    }
}

#[test]
fn addresses_refused() {
    for case in family("member_addresses")["refused"].as_array().unwrap() {
        let description = text(&case["description"]);
        let payload = bytes(&case["message"]);
        let connection = match text(&case["connection"]) {
            "member" => ConnectionKind::Member,
            "peer" => ConnectionKind::DeviceToPeer,
            other => panic!("connection {other}"),
        };
        let read = read_message(&payload, StreamClass::Control, connection, Extensions::NONE)
            .map(|m| m.expect("not ignorable"))
            .and_then(|m| Addresses::read(&m));
        assert_eq!(class(read), Some(text(&case["error"])), "{description}");
    }
}

#[test]
fn a_sender_lists_at_most_64_within_the_cap_and_never_nothing() {
    let ticket = Ticket::read(text(
        &family("member_addresses")["entries"][0]["ticket_text"],
    ))
    .unwrap();
    assert_eq!(Addresses::fitting(0, Vec::new()), None);
    let many: Vec<(DeviceId, Ticket)> = (0..=MAX_ENTRIES as u8)
        .map(|n| (DeviceId([n; 32]), ticket.clone()))
        .collect();
    let fitted = Addresses::fitting(0, many.clone()).unwrap();
    assert_eq!(fitted.entries.len(), MAX_ENTRIES);
    assert_eq!(fitted.entries[..], many[..MAX_ENTRIES]);
    // A device ID twice is listed once.
    let twice = Addresses::fitting(0, vec![many[0].clone(), many[0].clone()]).unwrap();
    assert_eq!(twice.entries.len(), 1);
    // Tickets of the largest size: the list stops before the cap.
    let mut large = ticket;
    large.relays = (0..4)
        .map(|i| format!("https://relay-{i}.{}.example.org", "a".repeat(150)))
        .collect();
    large.addresses = vec![large.addresses[0]; 16];
    assert!(large.cbor().len() > 700);
    let big: Vec<(DeviceId, Ticket)> = (0..MAX_ENTRIES as u8)
        .map(|n| (DeviceId([n; 32]), large.clone()))
        .collect();
    let fitted = Addresses::fitting(0, big).unwrap();
    let encoded = fitted.encode();
    assert!(encoded.len() <= frasil_transport::MessageType::Addresses.cap());
    assert!(fitted.entries.len() < MAX_ENTRIES);
    assert_eq!(Addresses::read(&control(&encoded)).unwrap(), fitted);
    // The next entry would pass the cap.
    let mut more = fitted.clone();
    more.entries.push((DeviceId([0xff; 32]), large));
    assert!(more.encode().len() > frasil_transport::MessageType::Addresses.cap());
}
