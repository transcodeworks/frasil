//! `ext-libraries.json`: the parameters, the signed tickets and a peer's
//! checks of them (ext-libraries.md, 2.1 The library ID, 2.2 The library
//! ticket, 2.4 Settings, 2.6 Error classes and 3.2 Checking a ticket).

use std::collections::{BTreeMap, BTreeSet};

use frasil_base::cbor;
use frasil_base::errors::Class;
use frasil_crypto::labels::LIBRARY_TICKET;
use frasil_crypto::primitives::{ed25519_public, sha256};
use frasil_libraries::issuer::IssueError;
use frasil_libraries::settings::{
    DETACHED_GRACE_DEFAULT, DETACHED_GRACE_RANGE, ERASURE_TIMEOUT_DEFAULT, ERASURE_TIMEOUT_RANGE,
    MAX_ISSUERS, TICKET_LIFETIME, TICKET_SKEW,
};
use frasil_libraries::ticket::{
    MAX_LIBRARY_ID_BYTES, MAX_TICKET_BYTES, TICKET_ID_BYTES, signed_message,
};
use frasil_libraries::{
    HOLD_OBJECT, Issuer, LIBRARY_ATTACH, LIBRARY_SERVICE, LibraryClass, LibraryId, LibraryState,
    PeerRecords, Purpose, SignedTicket, Ticket, TicketId, TrustedIssuers, check_ticket,
};
use frasil_testkit::hex;
use frasil_testkit::vectors;
use serde::Deserialize;

const FILE: &str = "ext-libraries.json";

/// The vectors' fixed inputs: SHA-256 of a description, so no value is
/// magic (the reference code's `example`).
fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

fn ticket_id(name: &str) -> TicketId {
    example(&format!("library/ticket/{name}"))[..TICKET_ID_BYTES]
        .try_into()
        .unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

// ---------------------------------------------------------------------------
// parameters

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    default: u64,
    range: [u64; 2],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    code: String,
    status: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    max_ticket_bytes: usize,
    max_library_id_bytes: usize,
    max_issuers: usize,
    library_service: u64,
    library_attach_type: u64,
    hold_object_type: u64,
    orphan_grace: u64,
    ticket_lifetime: u64,
    ticket_skew: u64,
    erasure_timeout: Range,
    detached_grace: Range,
    now: u64,
    issuer_seed: String,
    issuer: String,
    classes: BTreeMap<String, Code>,
}

fn parameters() -> Parameters {
    vectors::family(FILE, "parameters")
}

fn issuer_seed() -> [u8; 32] {
    hex::decode_array(&parameters().issuer_seed).unwrap()
}

#[test]
fn parameters_match() {
    let p = parameters();
    assert_eq!(p.max_ticket_bytes, MAX_TICKET_BYTES);
    assert_eq!(p.max_library_id_bytes, MAX_LIBRARY_ID_BYTES);
    assert_eq!(p.max_issuers, MAX_ISSUERS);
    assert_eq!(p.library_service, LIBRARY_SERVICE);
    assert_eq!(p.library_attach_type, LIBRARY_ATTACH);
    assert_eq!(p.hold_object_type, HOLD_OBJECT);
    assert_eq!(p.orphan_grace, 24 * 3600, "overview.md's default");
    assert_eq!(p.ticket_lifetime, TICKET_LIFETIME);
    assert_eq!(p.ticket_skew, TICKET_SKEW);
    assert_eq!(p.erasure_timeout.default, ERASURE_TIMEOUT_DEFAULT);
    assert_eq!(
        (p.erasure_timeout.range[0], p.erasure_timeout.range[1]),
        ERASURE_TIMEOUT_RANGE
    );
    assert_eq!(p.detached_grace.default, DETACHED_GRACE_DEFAULT);
    assert_eq!(
        (p.detached_grace.range[0], p.detached_grace.range[1]),
        DETACHED_GRACE_RANGE
    );
    assert_eq!(p.now, 1_792_000_000);

    let seed: [u8; 32] = hex::decode_array(&p.issuer_seed).unwrap();
    assert_eq!(seed, example("library/issuer"));
    let issuer = Issuer::from_seed(&seed);
    assert_eq!(hex::encode(issuer.public()), p.issuer);
    assert_eq!(hex::encode(ed25519_public(&seed)), p.issuer);

    // Every class the document uses, with its code and status; and every
    // class of its own is in the table.
    for (name, code) in &p.classes {
        let class = LibraryClass::from_name(name).unwrap_or_else(|| panic!("no class {name}"));
        assert_eq!(class.name(), name);
        assert_eq!(class.code(), code.code, "{name}");
        assert_eq!(class.status(), Some(code.status), "{name}");
        assert_eq!(LibraryClass::from_wire_name(&code.code), Some(class));
    }
    for class in LibraryClass::OWN {
        assert!(p.classes.contains_key(class.name()), "{}", class.name());
        assert_eq!(
            class.wire_name(),
            frasil_base::errors::snake_case(class.name())
        );
        assert_eq!(class.sort(), frasil_base::Sort::Decision);
    }
    assert_eq!(p.classes.len(), LibraryClass::OWN.len() + 1);
}

// ---------------------------------------------------------------------------
// tickets

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketRow {
    purpose: String,
    library: String,
    not_after: u64,
    ticket: String,
    signed_message: String,
    signature: String,
    signed: String,
}

#[test]
fn tickets() {
    let rows: Vec<TicketRow> = vectors::family(FILE, "tickets");
    let now = parameters().now;
    let issuer = Issuer::from_seed(&issuer_seed());
    assert_eq!(rows.len(), 3);
    for (row, expected) in rows.iter().zip(Purpose::ALL) {
        let purpose = Purpose::from_name(&row.purpose).unwrap();
        assert_eq!(purpose, expected);
        let library = LibraryId::new(&row.library).unwrap();
        let id = ticket_id(&format!("purpose-{}", purpose.code()));

        // Reading it.
        let signed = unhex(&row.signed);
        let read = SignedTicket::decode(&signed).unwrap();
        assert_eq!(
            read.ticket,
            Ticket {
                library: library.clone(),
                id,
                purpose,
                not_after: row.not_after,
                issuer: *issuer.public(),
                tokens: None,
            }
        );
        assert_eq!(hex::encode(&read.ticket_bytes), row.ticket);
        assert_eq!(hex::encode(read.signature), row.signature);
        assert_eq!(hex::encode(read.signed_message()), row.signed_message);
        assert_eq!(read.encode(), signed);

        // Writing it, byte for byte.
        assert_eq!(hex::encode(read.ticket.encode()), row.ticket);
        assert_eq!(
            hex::encode(signed_message(&read.ticket_bytes)),
            row.signed_message
        );
        assert!(row.signed_message.starts_with(&hex::encode(LIBRARY_TICKET)));
        assert_eq!(hex::encode(issuer.sign(&read.ticket)), row.signed);
        let issued = issuer
            .issue_with(&library, purpose, now, row.not_after, id)
            .unwrap();
        assert_eq!(hex::encode(&issued), row.signed);

        // The ticket's map is deterministic CBOR of exactly keys 1 to 6.
        let map = cbor::decode(&read.ticket_bytes).unwrap();
        assert_eq!(
            map.as_map().unwrap().keys().copied().collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );
    }
}

#[test]
fn issuing_keeps_to_the_lifetime() {
    let issuer = Issuer::from_seed(&issuer_seed());
    let library = LibraryId::new("personal:x").unwrap();
    let now = parameters().now;
    let ok = |not_after| issuer.issue_with(&library, Purpose::Create, now, not_after, [0; 16]);
    assert!(ok(now).is_ok());
    assert!(ok(now + TICKET_LIFETIME).is_ok());
    assert_eq!(ok(now + TICKET_LIFETIME + 1), Err(IssueError::Lifetime));
    assert_eq!(ok(now - 1), Err(IssueError::Lifetime));
    // A random ID: two tickets differ only there.
    let a = issuer
        .issue(&library, Purpose::Move, now, now + 60)
        .unwrap();
    let b = issuer
        .issue(&library, Purpose::Move, now, now + 60)
        .unwrap();
    let (a, b) = (
        SignedTicket::decode(&a).unwrap().ticket,
        SignedTicket::decode(&b).unwrap().ticket,
    );
    assert_ne!(a.id, b.id);
    assert_eq!(Ticket { id: b.id, ..a }, b);
}

// ---------------------------------------------------------------------------
// ticket_checks

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckRow {
    name: String,
    signed: String,
    now: Option<u64>,
    purpose: String,
    used: Vec<String>,
    issuers: Vec<String>,
    libraries: BTreeMap<String, String>,
    verdict: String,
    code: Option<String>,
    status: Option<u16>,
}

/// What the checking peer keeps.
struct Records {
    used: BTreeSet<TicketId>,
    libraries: BTreeMap<LibraryId, LibraryState>,
}

impl PeerRecords for Records {
    fn ticket_used(&self, id: &TicketId) -> bool {
        self.used.contains(id)
    }

    fn library_state(&self, library: &LibraryId) -> Option<LibraryState> {
        self.libraries.get(library).copied()
    }
}

/// The libraries a row's peer knows, with their states.
fn libraries(row: &CheckRow) -> BTreeMap<LibraryId, LibraryState> {
    row.libraries
        .iter()
        .map(|(name, state)| {
            (
                LibraryId::new(name).unwrap(),
                LibraryState::from_name(state).unwrap(),
            )
        })
        .collect()
}

/// Each row's signed bytes, built from their parts as the reference code
/// builds them, signed by the issuer or another.
fn expected_signed(name: &str, now: u64) -> Option<Vec<u8>> {
    let issuer = Issuer::from_seed(&issuer_seed());
    let other = Issuer::from_seed(&example("library/another-issuer"));
    let ticket = |by: &Issuer, library: &str, id: &str, not_after: u64| {
        by.sign(&Ticket {
            library: LibraryId::new(library).unwrap(),
            id: ticket_id(id),
            purpose: Purpose::Create,
            not_after,
            issuer: *by.public(),
            tokens: None,
        })
    };
    let project = "project:7c1f9e2a0b4d4e8f";
    Some(match name {
        "a good ticket"
        | "a used ticket ID"
        | "another purpose"
        | "a peer whose wall clock is not known" => ticket(&issuer, project, "a", now + 3600),
        "a changed signature" => {
            let good = ticket(&issuer, project, "a", now + 3600);
            let mut changed = SignedTicket::decode(&good).unwrap();
            changed.signature[63] ^= 1;
            changed.encode()
        }
        "not a ticket" => frasil_libraries::ticket::encode_signed(b"x", &[0; 64]),
        "an untrusted issuer" => ticket(&other, project, "a", now + 3600),
        "past not_after, by one second" => ticket(&issuer, project, "old", now - 1),
        "not_after beyond ticket_lifetime and ticket_skew" => ticket(
            &issuer,
            project,
            "long",
            now + TICKET_LIFETIME + TICKET_SKEW + 1,
        ),
        "a suspended library" => ticket(&issuer, "personal:0d5b2c", "suspended", now + 3600),
        "a library ID holding a control character" => {
            // Not a library ID, so not a `Ticket`: the map by hand.
            let mut map = cbor::Map::new();
            map.insert(1, cbor::Value::Unsigned(1));
            map.insert(2, cbor::Value::Text("project:\u{7}".into()));
            map.insert(3, cbor::Value::Bytes(vec![0; 16]));
            map.insert(4, cbor::Value::Unsigned(1));
            map.insert(5, cbor::Value::Unsigned(now));
            map.insert(6, cbor::Value::Bytes(issuer.public().to_vec()));
            issuer.sign_bytes(&cbor::Value::Map(map).encode())
        }
        // ext-deposit-tokens.md's grant at a peer that does not implement
        // it, and its key 7 on another purpose: step 1 refuses both.
        "a deposit grant, purpose 4 with key 7, at a peer without deposit tokens" => {
            issuer.sign(&Ticket {
                library: LibraryId::new(project).unwrap(),
                id: ticket_id("grant"),
                purpose: Purpose::Deposit,
                not_after: now + 3600,
                issuer: *issuer.public(),
                tokens: Some(16),
            })
        }
        "key 7 on purpose 1" => issuer.sign(&Ticket {
            library: LibraryId::new(project).unwrap(),
            id: ticket_id("key-7"),
            purpose: Purpose::Create,
            not_after: now + 3600,
            issuer: *issuer.public(),
            tokens: Some(16),
        }),
        _ => return None,
    })
}

#[test]
fn ticket_checks() {
    let rows: Vec<CheckRow> = vectors::family(FILE, "ticket_checks");
    let p = parameters();
    let mut verdicts = Vec::new();
    for row in &rows {
        // Each row's peer trusts the parameters' issuer, and knows one open
        // library and one suspended.
        assert_eq!(row.issuers, std::slice::from_ref(&p.issuer), "{}", row.name);
        let issuers = TrustedIssuers::new(
            row.issuers
                .iter()
                .map(|key| hex::decode_array(key).unwrap()),
        )
        .unwrap();
        let signed = unhex(&row.signed);
        match expected_signed(&row.name, p.now) {
            Some(expected) => assert_eq!(hex::encode(expected), row.signed, "{}", row.name),
            None => panic!("no case {}", row.name),
        }
        let records = Records {
            used: row
                .used
                .iter()
                .map(|id| hex::decode_array(id).unwrap())
                .collect(),
            libraries: libraries(row),
        };
        let purpose = Purpose::from_name(&row.purpose).unwrap();
        let verdict = check_ticket(&signed, purpose, row.now, &issuers, &records);
        match verdict {
            Ok(ticket) => {
                assert_eq!(row.verdict, "accepted", "{}", row.name);
                assert_eq!((row.code.as_deref(), row.status), (None, None));
                assert_eq!(ticket, SignedTicket::decode(&signed).unwrap().ticket);
            }
            Err(class) => {
                assert_eq!(class.name(), row.verdict, "{}", row.name);
                assert_eq!(Some(class.code()), row.code.as_deref(), "{}", row.name);
                assert_eq!(class.status(), row.status, "{}", row.name);
            }
        }
        verdicts.push(row.verdict.as_str());
    }
    assert_eq!(
        verdicts,
        [
            "accepted",
            "Malformed",
            "TicketRefused",
            "TicketRefused",
            "TicketExpired",
            "TicketExpired",
            "TicketUsed",
            "TicketRefused",
            "LibraryClosed",
            "TicketExpired",
            "Malformed",
            "Malformed",
            "Malformed",
        ]
    );
}

#[test]
fn the_steps_run_in_order() {
    // A ticket that fails several steps answers with the first.
    let p = parameters();
    let issuer = Issuer::from_seed(&issuer_seed());
    let issuers = TrustedIssuers::new([*issuer.public()]).unwrap();
    let suspended = LibraryId::new("personal:0d5b2c").unwrap();
    let ticket = Ticket {
        library: suspended.clone(),
        id: [5; 16],
        purpose: Purpose::Import,
        not_after: p.now - 1,
        issuer: *issuer.public(),
        tokens: None,
    };
    let records = Records {
        used: BTreeSet::from([[5; 16]]),
        libraries: BTreeMap::from([(suspended.clone(), LibraryState::Suspended)]),
    };
    let check =
        |signed: &[u8], purpose, now| check_ticket(signed, purpose, now, &issuers, &records);
    let signed = issuer.sign(&ticket);
    // Expired before used, purpose and state.
    assert_eq!(
        check(&signed, Purpose::Create, Some(p.now)),
        Err(LibraryClass::TicketExpired)
    );
    // Used before purpose and state.
    let fresh = issuer.sign(&Ticket {
        not_after: p.now,
        ..ticket.clone()
    });
    assert_eq!(
        check(&fresh, Purpose::Create, Some(p.now)),
        Err(LibraryClass::TicketUsed)
    );
    // Purpose before state.
    let unused = issuer.sign(&Ticket {
        not_after: p.now,
        id: [6; 16],
        ..ticket.clone()
    });
    assert_eq!(
        check(&unused, Purpose::Create, Some(p.now)),
        Err(LibraryClass::TicketRefused)
    );
    assert_eq!(
        check(&unused, Purpose::Import, Some(p.now)),
        Err(LibraryClass::LibraryClosed)
    );
    // A library the peer does not know is open.
    let unknown = issuer.sign(&Ticket {
        not_after: p.now,
        id: [6; 16],
        library: LibraryId::new("project:new").unwrap(),
        ..ticket.clone()
    });
    assert!(check(&unknown, Purpose::Import, Some(p.now)).is_ok());
    // The signature is checked before the time: a forged expired ticket is
    // refused, not expired.
    let mut forged = SignedTicket::decode(&signed).unwrap();
    forged.signature[0] ^= 1;
    assert_eq!(
        check(&forged.encode(), Purpose::Import, Some(p.now)),
        Err(LibraryClass::TicketRefused)
    );
    // Untrusted before the signature.
    let stranger = Issuer::from_seed(&[42; 32]);
    let theirs = stranger.sign(&Ticket {
        issuer: *stranger.public(),
        ..ticket.clone()
    });
    assert_eq!(
        check(&theirs, Purpose::Import, None),
        Err(LibraryClass::TicketRefused)
    );
    // The edges of check_expiry: not_after at the latest instant allowed,
    // and at now.
    for not_after in [p.now + TICKET_LIFETIME + TICKET_SKEW, p.now] {
        let edge = issuer.sign(&Ticket {
            not_after,
            id: [7; 16],
            library: LibraryId::new("project:new").unwrap(),
            ..ticket.clone()
        });
        assert!(check(&edge, Purpose::Import, Some(p.now)).is_ok());
    }
}
