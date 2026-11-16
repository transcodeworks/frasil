//! The decoders' properties that the fuzz targets check
//! (`fuzz/fuzz_targets/transport_*.rs`), run here over every byte string
//! and text of transport.json and mutations of each: no decoder panics,
//! each refuses only with its steps' classes, and what one accepts is the
//! one encoding of what it returns.

mod common;

use common::*;
use frasil_base::ErrorClass;
use frasil_transport::addresses::Addresses;
use frasil_transport::frame::{
    ConnectionKind, Deframer, Extensions, Message, MessageType, Read, StreamClass, frame,
    read_frame, read_message,
};
use frasil_transport::mailbox::{
    MailboxGet, MailboxItems, MailboxPut, item_plaintext, open_item, read_item_plaintext,
};
use frasil_transport::member::{Role, read_offer, verify_identify};
use frasil_transport::messages::{
    Accepted, AdapterSync, Admit, Awaiting, Detach, Ephemeral, EventRefused, Gone, Granted, Merge,
    Open, Pairing, Present, Refuse, Refused, RegisterRecoveryEntry, Sync,
};
use frasil_transport::peer::{Hello, PeerHello};
use frasil_transport::ticket::{Ticket, base64url};
use frasil_transport::{TransportClass, lan, member};
use serde_json::Value as Json;

fn strings(value: &Json, bytes_out: &mut Vec<Vec<u8>>, texts: &mut Vec<String>) {
    match value {
        Json::String(text) => match frasil_testkit::hex::decode(text) {
            Ok(bytes) if !bytes.is_empty() => bytes_out.push(bytes),
            _ => texts.push(text.clone()),
        },
        Json::Array(items) => items.iter().for_each(|i| strings(i, bytes_out, texts)),
        Json::Object(map) => map.values().for_each(|i| strings(i, bytes_out, texts)),
        _ => {}
    }
}

/// Each byte string, with frames' payloads, and a few mutations of each:
/// truncated, a byte flipped, a byte appended.
fn inputs() -> (Vec<Vec<u8>>, Vec<String>) {
    let file = frasil_testkit::vectors::VectorFile::load(FILE).unwrap();
    let (mut out, mut texts) = (Vec::new(), Vec::new());
    for (_, value) in file.families() {
        strings(value, &mut out, &mut texts);
    }
    let payloads: Vec<Vec<u8>> = out
        .iter()
        .filter(|b| {
            b.len() > 4 && u32::from_be_bytes(b[..4].try_into().unwrap()) as usize == b.len() - 4
        })
        .map(|b| b[4..].to_vec())
        .collect();
    out.extend(payloads);
    let mut more = Vec::new();
    for bytes in &out {
        if bytes.len() > 8192 {
            continue;
        }
        more.push(bytes[..bytes.len() / 2].to_vec());
        for at in [0, bytes.len() / 3, bytes.len() / 2, bytes.len() - 1] {
            let mut flipped = bytes.clone();
            flipped[at] ^= 0x01;
            more.push(flipped);
        }
        let mut longer = bytes.clone();
        longer.push(0);
        more.push(longer);
    }
    out.extend(more);
    let mut text_more = Vec::new();
    for text in &texts {
        text_more.push(text.chars().take(text.chars().count() / 2).collect());
        text_more.push(format!("{text}A"));
    }
    texts.extend(text_more);
    (out, texts)
}

fn shared(error: &TransportClass, allowed: &[ErrorClass]) -> bool {
    matches!(error, TransportClass::Shared(class) if allowed.contains(class))
}

fn reread(bytes: &[u8], class: StreamClass, connection: ConnectionKind) -> Message {
    read_message(bytes, class, connection, Extensions::NONE)
        .unwrap()
        .unwrap()
}

/// Each typed reader: what it accepts writes back to a message that reads
/// the same, and, for the types with exactly their keys, to the same bytes.
fn typed(message: &Message, class: StreamClass, c: ConnectionKind) -> usize {
    macro_rules! round_trip {
        ($read:expr, $encode:expr, $again:expr, $exact:expr) => {{
            if let Ok(value) = $read {
                let bytes = $encode(&value);
                if $exact {
                    assert_eq!(bytes, message.bytes);
                }
                assert_eq!($again(&reread(&bytes, class, c)), Ok(value));
                1
            } else {
                0
            }
        }};
    }
    match message.kind {
        MessageType::Refuse => {
            round_trip!(Refuse::read(message), Refuse::encode, Refuse::read, true)
        }
        MessageType::Admit => round_trip!(Admit::read(message), Admit::encode, Admit::read, true),
        MessageType::Addresses => round_trip!(
            Addresses::read(message),
            Addresses::encode,
            Addresses::read,
            true
        ),
        MessageType::Detach => {
            round_trip!(Detach::read(message), Detach::encode, Detach::read, true)
        }
        MessageType::Open => {
            round_trip!(
                Open::read(message, c),
                Open::encode,
                |m| Open::read(m, c),
                false
            )
        }
        MessageType::Present => {
            round_trip!(Present::read(message), Present::encode, Present::read, true)
        }
        MessageType::Granted => round_trip!(
            Granted::read(message),
            Granted::encode,
            Granted::read,
            false
        ),
        MessageType::Refused => {
            round_trip!(Refused::read(message), Refused::encode, Refused::read, true)
        }
        MessageType::EventRefused => round_trip!(
            EventRefused::read(message),
            EventRefused::encode,
            EventRefused::read,
            true
        ),
        MessageType::Accepted => {
            round_trip!(
                Accepted::read(message),
                Accepted::encode,
                Accepted::read,
                false
            )
        }
        MessageType::Merge => round_trip!(
            Merge::read(message),
            |m: &Merge| m.encode().unwrap(),
            Merge::read,
            false
        ),
        MessageType::Awaiting => {
            round_trip!(
                Awaiting::read(message),
                Awaiting::encode,
                Awaiting::read,
                false
            )
        }
        MessageType::RegisterRecoveryEntry => round_trip!(
            RegisterRecoveryEntry::read(message),
            RegisterRecoveryEntry::encode,
            RegisterRecoveryEntry::read,
            false
        ),
        MessageType::Sync => {
            round_trip!(
                Sync::read(message, c),
                Sync::encode,
                |m| Sync::read(m, c),
                false
            )
        }
        MessageType::AdapterSync => round_trip!(
            AdapterSync::read(message, c),
            AdapterSync::encode,
            |m| AdapterSync::read(m, c),
            false
        ),
        MessageType::Ephemeral => round_trip!(
            Ephemeral::read(message, c),
            Ephemeral::encode,
            |m| Ephemeral::read(m, c),
            false
        ),
        MessageType::Gone => round_trip!(
            Gone::read(message, c),
            Gone::encode,
            |m| Gone::read(m, c),
            false
        ),
        MessageType::Pairing => round_trip!(
            Pairing::read(message),
            Pairing::encode,
            Pairing::read,
            false
        ),
        MessageType::MailboxPut => match MailboxPut::read(message, Extensions::NONE) {
            Ok(Some(put)) => {
                assert_eq!(put.encode(), message.bytes);
                1
            }
            _ => 0,
        },
        MessageType::MailboxGet => {
            round_trip!(
                MailboxGet::read(message),
                MailboxGet::encode,
                MailboxGet::read,
                true
            )
        }
        MessageType::MailboxItems => round_trip!(
            MailboxItems::read(message),
            MailboxItems::encode,
            MailboxItems::read,
            false
        ),
        _ => 0,
    }
}

#[test]
fn frames_and_messages() {
    let (inputs, _) = inputs();
    let mut typed_reads = 0;
    for data in &inputs {
        for class in StreamClass::ALL {
            for connection in [ConnectionKind::Member, ConnectionKind::DeviceToPeer] {
                for data in [data.clone(), frame(data)] {
                    let read = read_frame(&data, class, connection, Extensions::NONE);
                    match &read {
                        Ok(Read::Message(message, rest)) => {
                            assert!(message.kind.carried_by(class));
                            assert_eq!(data.len(), 4 + message.bytes.len() + rest.len());
                            typed_reads += typed(message, class, connection);
                        }
                        Ok(_) => {}
                        Err(error) => assert!(shared(
                            error,
                            &[
                                ErrorClass::TooLarge,
                                ErrorClass::Malformed,
                                ErrorClass::UnknownMessage
                            ]
                        )),
                    }
                    let mut deframer = Deframer::new(class, connection, Extensions::NONE);
                    deframer.push(&data);
                    match (read, deframer.next_message()) {
                        (Ok(Read::Message(message, _)), Ok(Some(got))) => assert_eq!(message, got),
                        (Err(error), Err(got)) => assert_eq!(error, got),
                        (Ok(Read::Incomplete), Ok(None)) | (Ok(Read::Dropped(_)), _) => {}
                        (read, got) => panic!("{read:?} {got:?}"),
                    }
                }
            }
        }
    }
    assert!(typed_reads > 50, "{typed_reads}");
}

#[test]
fn handshake_readers() {
    let (inputs, _) = inputs();
    let mut offers = 0;
    for data in &inputs {
        let Ok(Some(message)) = read_message(
            data,
            StreamClass::Control,
            ConnectionKind::Member,
            Extensions::NONE,
        ) else {
            continue;
        };
        for role in [Role::Dialer, Role::Listener] {
            match read_offer(&message, role, 0) {
                Ok(offer) => {
                    offers += 1;
                    assert_eq!(
                        member::encode_offer(
                            offer.attach,
                            &offer.nonce,
                            &offer.tags,
                            member::REVISION
                        ),
                        *data
                    );
                }
                Err(error) => assert!(
                    error == TransportClass::AttachLimit
                        || shared(
                            &error,
                            &[ErrorClass::Malformed, ErrorClass::RevisionMismatch]
                        )
                ),
            }
            if let Err(error) = verify_identify(&message, &[0; 32], role) {
                assert!(shared(
                    &error,
                    &[
                        ErrorClass::Malformed,
                        ErrorClass::InvalidKey,
                        ErrorClass::BadSignature
                    ]
                ));
            }
        }
        let classes = [
            ErrorClass::Malformed,
            ErrorClass::UnsupportedVersion,
            ErrorClass::RevisionMismatch,
        ];
        match Hello::read(&message) {
            Ok(hello) => assert_eq!(Hello::encode(&hello.nonce, hello.purpose), *data),
            Err(error) => assert!(shared(&error, &classes)),
        }
        if let Err(error) = PeerHello::read(&message) {
            assert!(shared(&error, &classes));
        }
    }
    assert!(offers > 5, "{offers}");
}

#[test]
fn tickets_and_packets() {
    let (inputs, texts) = inputs();
    let mut tickets = 0;
    for text in &texts {
        if let Some(raw) = base64url::decode(text) {
            assert_eq!(base64url::encode(&raw), *text);
        }
        match Ticket::read(text) {
            Ok(ticket) => {
                tickets += 1;
                assert_eq!(ticket.encode().as_deref(), Ok(text.as_str()));
            }
            Err(error) => assert!(shared(
                &error,
                &[ErrorClass::Malformed, ErrorClass::InvalidKey]
            )),
        }
    }
    // The `tickets` family's, and member_addresses' seven.
    assert_eq!(tickets, 8);
    let handshake = Handshake::load();
    let secrets = [handshake.secret("{D}"), handshake.secret("{C}")];
    let mut opened = 0;
    for data in &inputs {
        match lan::open(data, &secrets) {
            Ok(found) => {
                opened += 1;
                let nonce: [u8; 24] = data[1..25].try_into().unwrap();
                let again =
                    lan::announce_with(&secrets[found.state], &found.endpoint, found.port, &nonce);
                assert_eq!(again.as_slice(), data.as_slice());
            }
            Err(error) => assert!(
                error == TransportClass::NotForMe || shared(&error, &[ErrorClass::Malformed])
            ),
        }
        if let Ok(nearby) = lan::read_nearby(data) {
            assert_eq!(lan::nearby_name(&nearby.name), nearby.name);
        }
    }
    assert_eq!(opened, 2);
}

#[test]
fn mailbox_items() {
    let (inputs, _) = inputs();
    let family = family("mailboxes");
    let me = frasil_crypto::device::DeviceId(array::<32>(&family["recipient"]["device_id"]));
    let seed = array::<32>(&family["recipient"]["x_wing_seed"]);
    let mut opened = 0;
    for data in &inputs {
        if let Ok(item) = read_item_plaintext(data) {
            assert_eq!(item_plaintext(&item.content, &item.body), *data);
        }
        match open_item(data, &me, &seed, |_| true) {
            Ok(_) => opened += 1,
            Err(error) => assert!(
                error == TransportClass::UnknownContent
                    || shared(
                        &error,
                        &[
                            ErrorClass::Malformed,
                            ErrorClass::UnsupportedVersion,
                            ErrorClass::Decrypt
                        ]
                    )
            ),
        }
    }
    // The two items and the one with an unknown content name.
    assert_eq!(opened, 3);
}
