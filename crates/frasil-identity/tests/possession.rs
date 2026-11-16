//! `identity.json`: possession proofs (identity.md, "The device-list
//! event", "The possession statement" and "Checking a list event alone").
//!
//! Each event is decoded as events.md's envelope, its body checked as
//! identity.md says, and then placed and merged in its list: the adds of
//! `possession` form one list, and each refusal is appended to the base it
//! was made on, whose events `possession` holds too.

mod common;

use common::{agent, array, bytes, class, device, example, family, text};
use frasil_crypto::device::DeviceId;
use frasil_crypto::schemes::hybrid_ed25519_message;
use frasil_events::{EventId, decode};
use frasil_identity::body::{Action, ListBody, check_body};
use frasil_identity::passkey::PasskeyMember;
use frasil_identity::possession::{self, FIRST_EVENT_PERSON, STATEMENT_BYTES};
use frasil_identity::recovery::{RecoveryKey, RecoverySecret};
use frasil_identity::{DeviceList, Kind, MemberKeys};

const PREFIX: &str = "identity/possession";

/// The envelope's `author`, `log` (absent in a first event) and `body` of a
/// signed event, decoded by events.md's rules.
fn envelope(signed: &[u8]) -> (DeviceId, Option<[u8; 32]>, Vec<u8>) {
    let event = decode(signed).unwrap();
    let log = event.log().map(|log| log.0);
    (*event.author(), log, event.unverified_body().to_vec())
}

fn kind_named(name: &str) -> Kind {
    Kind::ALL
        .into_iter()
        .find(|kind| kind.name() == name)
        .unwrap_or_else(|| panic!("no kind {name}"))
}

/// The keys of the list member each case adds, from the vectors' inputs.
fn keys_of(case: &str, person: &[u8; 32]) -> MemberKeys {
    let fixture = |name| device(PREFIX, name);
    match case {
        "the first device" => fixture("laptop"),
        "a device added by a passkey member" => fixture("browser"),
        "a device added by another list member" => fixture("phone"),
        "a recovery agent" => agent(PREFIX, "agent"),
        "a device added by a recovery key" => fixture("tablet"),
        "a recovery key" => {
            let secret = RecoverySecret::from_bytes(&example(&format!("{PREFIX}/recovery/secret")));
            let key = RecoveryKey::derive(&secret);
            let m = key.member();
            MemberKeys::from_seeds(m.identity_seed(), m.xwing_seed().unwrap(), m.mldsa_seed())
        }
        "a passkey member" => {
            let output = example(&format!("{PREFIX}/passkey/prf-output"));
            let member = PasskeyMember::derive(person, &output).unwrap();
            let m = member.member();
            MemberKeys::from_seeds(m.identity_seed(), m.xwing_seed().unwrap(), m.mldsa_seed())
        }
        other => panic!("no case {other}"),
    }
}

#[test]
fn possession() {
    let f = family("possession");
    let person: [u8; 32] = array(&f, "person_id");
    let adds = f["adds"].as_array().unwrap();
    assert_eq!(adds.len(), 7);

    // The adds are one list, in canonical order, every one valid.
    let mut list = DeviceList::new(&bytes(&adds[0], "signed")).unwrap();
    assert_eq!(list.person_id(), person);
    for row in &adds[1..] {
        list.insert(&bytes(row, "signed")).unwrap();
    }
    let merged = list.merge();
    let ids: Vec<[u8; 32]> = merged.verdicts().map(|(id, _)| id.0).collect();
    let expected: Vec<[u8; 32]> = adds.iter().map(|row| array(row, "id")).collect();
    assert_eq!(ids, expected);
    assert!(merged.verdicts().all(|(_, verdict)| verdict.is_valid()));
    assert_eq!(merged.active_members().count(), 7);
    for row in adds {
        let case = text(row, "case");
        assert_eq!(text(row, "action"), "add");
        let kind = kind_named(text(row, "kind"));
        let body_bytes = bytes(row, "body");
        let first = array::<32>(row, "id") == person;

        // The body, decoded and checked as the event's.
        let (author, log, carried) = envelope(&bytes(row, "signed"));
        assert_eq!(carried, body_bytes, "{case}");
        assert_eq!(log, (!first).then_some(person), "{case}");
        let body = check_body(&body_bytes, &author, log.as_ref()).unwrap();
        assert_eq!(body.action, Action::Add);
        assert_eq!(body.kind, kind, "{case}");
        assert_eq!(body.device.0, array(row, "device"), "{case}");
        let added = body.added.as_ref().unwrap();
        assert_eq!(added.identity.0, array(row, "identity"), "{case}");
        assert_eq!(
            body.keys().unwrap().hybrid().commitment().0,
            array(row, "kc"),
            "{case}"
        );
        assert_eq!(added.possession, bytes(row, "possession"), "{case}");
        assert_eq!(&added.mldsa[..], &bytes(row, "mldsa")[..], "{case}");
        assert_eq!(
            added.xwing.as_ref().map(|x| x.to_vec()).unwrap_or_default(),
            if row["xwing"].is_null() {
                Vec::new()
            } else {
                bytes(row, "xwing")
            },
            "{case}"
        );
        assert_eq!(body.encode(), body_bytes, "{case}");

        // The statement, computed from the list, the event's author and the
        // body.
        let bound = if first { FIRST_EVENT_PERSON } else { person };
        let statement = possession::statement(
            &bound,
            &author,
            kind,
            &added.identity,
            &added.mldsa,
            added.xwing.as_deref(),
        );
        assert_eq!(statement, bytes(row, "statement"), "{case}");

        // The named key's proof, made again: proofs are deterministic.
        let keys = keys_of(case, &person);
        let public = keys.public(kind);
        assert_eq!(body.keys().as_ref(), Some(&public), "{case}");
        let proof = keys.prove_possession(&bound, &author, kind);
        assert_eq!(proof, added.possession, "{case}");
        assert_eq!(
            ListBody::add(kind, &public, proof).encode(),
            body_bytes,
            "{case}"
        );
    }

    // One statement, field by field.
    let fields = &f["field_by_field"];
    let statement = bytes(fields, "statement");
    assert_eq!(statement.len(), STATEMENT_BYTES);
    assert_eq!(fields["statement_bytes"], STATEMENT_BYTES as u64);
    let joined: Vec<u8> = fields["fields"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|field| bytes(field, "bytes"))
        .collect();
    assert_eq!(joined, statement);
    let phone = device(PREFIX, "phone");
    let laptop = device(PREFIX, "laptop");
    let made = possession::statement(
        &person,
        laptop.device_id(),
        Kind::Device,
        phone.identity(),
        phone.mldsa(),
        phone.xwing(),
    );
    assert_eq!(made, statement);
    assert_eq!(
        hybrid_ed25519_message(phone.identity(), &statement),
        bytes(fields, "m_ed")
    );
    let proof = bytes(fields, "possession");
    assert_eq!(
        phone.prove_possession(&person, laptop.device_id(), Kind::Device),
        proof
    );
    assert_eq!(
        possession::verify(phone.identity(), phone.signer().keys(), &statement, &proof),
        Ok(())
    );
}

#[test]
fn possession_refusals() {
    // Each refusal is appended to a base of the first three adds: the first
    // device, the recovery key and the passkey member.
    let adds = family("possession")["adds"].clone();
    let adds = adds.as_array().unwrap();
    let mut base = DeviceList::new(&bytes(&adds[0], "signed")).unwrap();
    for row in &adds[1..3] {
        base.insert(&bytes(row, "signed")).unwrap();
    }
    let rows = family("possession_refusals");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 17);
    for row in rows {
        let name = text(row, "name");
        let signed = bytes(row, "event");
        let (author, log, body) = envelope(&signed);
        let log = log.expect("a later event names its log");
        assert_eq!(log, base.person_id(), "{name}");
        // The proof the event carries is the one the vector names.
        let value = frasil_base::cbor::decode(&body).unwrap();
        let carried = value.as_map().unwrap()[&4].as_bytes().unwrap();
        assert_eq!(carried, &bytes(row, "possession")[..], "{name}");
        let result = check_body(&body, &author, Some(&log));
        assert_eq!(class(result), Some(text(row, "error")), "{name}");

        // Placed on its base, the merge holds it void with the same class.
        let mut list = base.clone();
        list.insert(&signed).unwrap();
        let id: EventId = decode(&signed).unwrap().id();
        let merged = list.merge();
        let verdict = merged.verdict(id).expect("placed on its base");
        assert_eq!(
            verdict
                .class()
                .map(|c| frasil_base::errors::Class::name(*c)),
            Some(text(row, "error")),
            "{name}"
        );
    }
}

#[test]
fn first_event_checks() {
    let laptop = device(PREFIX, "laptop");
    let phone = device(PREFIX, "phone");
    let proof = laptop.prove_possession(&FIRST_EVENT_PERSON, laptop.device_id(), Kind::Device);
    let body = ListBody::add(Kind::Device, &laptop.public(Kind::Device), proof).encode();
    assert!(check_body(&body, laptop.device_id(), None).is_ok());
    // A first event by another author, or that is not an add of a device.
    assert_eq!(
        class(check_body(&body, phone.device_id(), None)),
        Some("BadGenesis")
    );
    let revoke = ListBody::revoke(Kind::Device, *laptop.device_id()).encode();
    assert_eq!(
        class(check_body(&revoke, laptop.device_id(), None)),
        Some("BadGenesis")
    );
    // The first event's proof does not serve a later add, nor the reverse.
    assert_eq!(
        class(check_body(&body, laptop.device_id(), Some(&[1; 32]))),
        Some("BadPossession")
    );
    // A proof serves only the adder it names: the same add signed by
    // another list member does not verify.
    let later = laptop.prove_possession(&[1; 32], phone.device_id(), Kind::Device);
    let body = ListBody::add(Kind::Device, &laptop.public(Kind::Device), later).encode();
    assert!(check_body(&body, phone.device_id(), Some(&[1; 32])).is_ok());
    assert_eq!(
        class(check_body(&body, &DeviceId([3; 32]), Some(&[1; 32]))),
        Some("BadPossession")
    );
    // Keys that do not give the device ID the add names.
    let mut lent = ListBody::add(
        Kind::Device,
        &laptop.public(Kind::Device),
        laptop.prove_possession(&[1; 32], phone.device_id(), Kind::Device),
    );
    lent.device = *phone.device_id();
    assert_eq!(
        class(check_body(
            &lent.encode(),
            phone.device_id(),
            Some(&[1; 32])
        )),
        Some("NotCommitted")
    );
}

#[test]
fn agent_adds_name_no_xwing_key() {
    let agent = agent(PREFIX, "agent");
    let person = [7; 32];
    let adder = DeviceId([0; 32]);
    let proof = agent.prove_possession(&person, &adder, Kind::RecoveryAgent);
    let public = agent.public(Kind::RecoveryAgent);
    assert!(public.xwing.is_none());
    assert_eq!(public.device_id(), *agent.device_id());
    let body = ListBody::add(Kind::RecoveryAgent, &public, proof.clone()).encode();
    assert!(check_body(&body, &adder, Some(&person)).is_ok());
    let with_xwing = device(PREFIX, "agent");
    // An agent's add that names an X-Wing key, and a device's that names
    // none, are malformed.
    let with = ListBody::add(
        Kind::RecoveryAgent,
        &with_xwing.public(Kind::Device),
        proof.clone(),
    );
    assert_eq!(class(ListBody::decode(&with.encode())), Some("Malformed"));
    let without = ListBody::add(Kind::Device, &public, proof);
    assert_eq!(
        class(ListBody::decode(&without.encode())),
        Some("Malformed")
    );
}
