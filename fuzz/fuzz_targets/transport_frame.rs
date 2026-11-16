//! frasil-transport's frame reader and message readers on arbitrary bytes
//! (transport.md, 2.3 Frames and stream classes, 2.4 Message types and 3.1
//! Reading a frame). They never panic; `read_frame` refuses only with its
//! steps' classes; a deframer fed the bytes in pieces reads what
//! `read_frame` reads; and every typed reader's result writes back to bytes
//! that read the same.
#![no_main]

use frasil_base::ErrorClass;
use frasil_transport::frame::{
    ConnectionKind, Deframer, Extensions, Message, MessageType, Read, StreamClass, read_frame,
};
use frasil_transport::mailbox::{MailboxGet, MailboxItems, MailboxPut};
use frasil_transport::messages::{
    Accepted, AdapterSync, Admit, Awaiting, Detach, Ephemeral, ErasureLate, Gone, Granted, Merge,
    Open, Pairing, Present, Refuse, Refused, RegisterRecoveryEntry, Sync,
};
use frasil_transport::{TransportClass, frame};
use libfuzzer_sys::fuzz_target;

const CONNECTIONS: [ConnectionKind; 3] = [
    ConnectionKind::Member,
    ConnectionKind::DeviceToPeer,
    ConnectionKind::Nearby,
];

fn reread(bytes: &[u8], class: StreamClass, connection: ConnectionKind) -> Message {
    frame::read_message(bytes, class, connection, Extensions::NONE)
        .expect("a written message reads")
        .expect("a written message is known")
}

/// Each typed reader: what it accepts writes back to a message it reads
/// the same; for the types with exactly their keys, to the same bytes.
fn typed(message: &Message, class: StreamClass, connection: ConnectionKind) {
    macro_rules! round_trip {
        ($read:expr, $encode:expr, $again:expr, $exact:expr) => {
            if let Ok(value) = $read {
                let bytes = $encode(&value);
                if $exact {
                    assert_eq!(bytes, message.bytes, "a second encoding");
                }
                assert_eq!($again(&reread(&bytes, class, connection)), Ok(value));
            }
        };
    }
    let c = connection;
    match message.kind {
        MessageType::Refuse => {
            round_trip!(Refuse::read(message), Refuse::encode, Refuse::read, true)
        }
        MessageType::Admit => round_trip!(Admit::read(message), Admit::encode, Admit::read, true),
        MessageType::Detach => {
            round_trip!(Detach::read(message), Detach::encode, Detach::read, true)
        }
        MessageType::Open => round_trip!(
            Open::read(message, c),
            Open::encode,
            |m| Open::read(m, c),
            false
        ),
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
        MessageType::Accepted => round_trip!(
            Accepted::read(message),
            Accepted::encode,
            Accepted::read,
            false
        ),
        MessageType::Merge => round_trip!(
            Merge::read(message),
            |m: &Merge| m.encode().expect("a statement read is a map"),
            Merge::read,
            false
        ),
        MessageType::Awaiting => round_trip!(
            Awaiting::read(message),
            Awaiting::encode,
            Awaiting::read,
            false
        ),
        MessageType::RegisterRecoveryEntry => round_trip!(
            RegisterRecoveryEntry::read(message),
            RegisterRecoveryEntry::encode,
            RegisterRecoveryEntry::read,
            false
        ),
        MessageType::Sync => round_trip!(
            Sync::read(message, c),
            Sync::encode,
            |m| Sync::read(m, c),
            false
        ),
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
        // Exactly keys 0 to 5, read whole by the frame reader too.
        MessageType::ErasureLate => round_trip!(
            ErasureLate::read(message),
            ErasureLate::encode,
            ErasureLate::read,
            true
        ),
        MessageType::Pairing => {
            round_trip!(
                Pairing::read(message),
                Pairing::encode,
                Pairing::read,
                false
            )
        }
        MessageType::MailboxPut => {
            if let Ok(Some(put)) = MailboxPut::read(message, Extensions::NONE) {
                assert_eq!(put.encode(), message.bytes);
            }
        }
        MessageType::MailboxGet => round_trip!(
            MailboxGet::read(message),
            MailboxGet::encode,
            MailboxGet::read,
            true
        ),
        MessageType::MailboxItems => round_trip!(
            MailboxItems::read(message),
            MailboxItems::encode,
            MailboxItems::read,
            false
        ),
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks the class and the connection.
    let Some((&pick, data)) = data.split_first() else {
        return;
    };
    let class = StreamClass::ALL[usize::from(pick % 5)];
    let connection = CONNECTIONS[usize::from((pick / 5) % 3)];
    let read = read_frame(data, class, connection, Extensions::NONE);
    match &read {
        Ok(Read::Message(message, rest)) => {
            assert!(message.kind.carried_by(class));
            assert!(message.bytes.len() <= message.kind.cap());
            assert_eq!(data.len(), 4 + message.bytes.len() + rest.len());
            typed(message, class, connection);
        }
        Ok(Read::Dropped(_) | Read::Incomplete) => {}
        Err(error) => assert!(
            matches!(
                error,
                TransportClass::Shared(
                    ErrorClass::TooLarge | ErrorClass::Malformed | ErrorClass::UnknownMessage
                )
            ),
            "{error:?}"
        ),
    }
    // A deframer agrees, however the bytes arrive.
    let mut deframer = Deframer::new(class, connection, Extensions::NONE);
    let mut first = None;
    for chunk in data.chunks(usize::from(pick % 13) + 1) {
        deframer.push(chunk);
        match deframer.next_message() {
            Ok(Some(message)) => {
                first = Some(Ok(message));
                break;
            }
            Ok(None) => {}
            Err(class) => {
                first = Some(Err(class));
                break;
            }
        }
    }
    match (read, first) {
        (Ok(Read::Message(message, _)), Some(Ok(got))) => assert_eq!(message, got),
        (Err(error), Some(Err(got))) => assert_eq!(error, got),
        (Ok(Read::Incomplete), None) => {}
        (Ok(Read::Dropped(_)), _) => {}
        (read, first) => panic!("read_frame {read:?}, deframer {first:?}"),
    }
});
