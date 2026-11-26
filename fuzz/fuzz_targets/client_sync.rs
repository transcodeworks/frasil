//! The client's intake of a sync message (units.md, "Sync"): arbitrary
//! bytes through `frasil::advanced::intake::read_sync`, then a sync session of a
//! replica that holds nothing yet. It never panics; a session answers only
//! messages of its own space, and each action it asks for carries only what
//! the message carried: events to place only from `Events`, a path to
//! witness only from `Path`, and an object, a chunk, held or missing
//! objects, a snapshot or carriers only from the message that names them.
#![no_main]

use frasil::advanced::replica::Replica;
use frasil::advanced::snapshots::ObjectPart;
use frasil::advanced::sync::{Action, SyncSession};
use frasil_events::EventId;
use frasil_units::messages::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(Some(message)) = frasil::advanced::intake::read_sync(data) else {
        return;
    };
    let space = message.space;
    let replica = Replica::new(space);
    let mut session = SyncSession::new(space);
    let sent = message.message.clone();
    for action in session.receive(&replica, message) {
        match action {
            Action::Send(reply) => assert_eq!(reply.space, space),
            Action::Ingest(events) => {
                assert!(matches!(&sent, Message::Events { events: e } if *e == events));
            }
            Action::Acknowledged(heads) => {
                assert!(matches!(&sent, Message::Ack { heads: h } if *h == heads));
            }
            Action::ServeObject {
                locator,
                first,
                count,
            } => assert_eq!(
                sent,
                Message::ObjectWant {
                    locator,
                    first,
                    count
                }
            ),
            Action::ObjectChunk(ObjectPart {
                locator,
                header,
                index,
                chunk,
            }) => assert_eq!(
                sent,
                Message::ObjectChunks {
                    locator,
                    header,
                    index,
                    chunk
                }
            ),
            Action::ObjectsHeld(locators) => {
                assert!(matches!(&sent, Message::ObjectHave { locators: l, .. } if *l == locators));
            }
            Action::ObjectsMissing(locators) => {
                assert!(matches!(&sent, Message::ObjectMissing { locators: l } if *l == locators));
            }
            Action::SnapshotWanted => assert!(matches!(sent, Message::SnapshotWant { .. })),
            Action::SnapshotOffered(snapshot) => {
                assert_eq!(sent, Message::SnapshotOffer { snapshot });
            }
            Action::Missing(ids) => {
                assert!(matches!(&sent, Message::Missing { ids: i, .. } if *i == ids));
            }
            Action::Carried(carried) => {
                assert!(matches!(&sent, Message::Missing { carried: c, .. } if *c == carried));
            }
            Action::Path { from, to, events } => {
                assert_eq!(sent, Message::Path { from, to, events });
            }
        }
    }
    // Another space's session takes nothing.
    let mut other = SyncSession::new(EventId([0xff; 32]));
    if space != EventId([0xff; 32]) {
        let message = frasil::advanced::intake::read_sync(data).unwrap().unwrap();
        assert!(other.receive(&replica, message).is_empty());
    }
});
