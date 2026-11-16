//! `identity.json`: the parameters, passkey members, recovery keys and
//! recovery entries (identity.md, "Device keys", "The device-list event",
//! "Recovery keys", "Passkey members" and "Fetch keys and recovery
//! entries").

mod common;

use common::{array, bytes, class, family, text};
use frasil_crypto::device::DeviceId;
use frasil_crypto::labels::{
    PASSKEY_EXTRACT, RECOVERY, RECOVERY_KEY_FETCH, RECOVERY_KEY_HYBRID, RECOVERY_KEY_MLDSA,
};
use frasil_crypto::primitives::hkdf_extract;
use frasil_identity::body::{self, Action};
use frasil_identity::entries::{Holder, RecoveryEntry};
use frasil_identity::passkey::{self, Infos, PasskeyMember, UserHandle};
use frasil_identity::possession::{self, AGENT_STATEMENT_BYTES, STATEMENT_BYTES};
use frasil_identity::recovery::{self, RecoveryKey, RecoverySecret};
use frasil_identity::{Kind, MemberKeys, Rank};
use serde_json::Value as Json;

// ---------------------------------------------------------------------------
// parameters

#[test]
fn parameters() {
    let p = family("parameters");
    let actions = p["actions"].as_object().unwrap();
    assert_eq!(actions.len(), Action::ALL.len());
    for action in Action::ALL {
        assert_eq!(actions[action.name()], u64::from(action.code()));
    }
    let kinds = p["kinds"].as_object().unwrap();
    assert_eq!(kinds.len(), Kind::ALL.len());
    for kind in Kind::ALL {
        assert_eq!(kinds[kind.name()], u64::from(kind.code()));
    }
    let keys = p["body_keys"].as_object().unwrap();
    for (name, key) in [
        ("version", body::KEY_VERSION),
        ("action", body::KEY_ACTION),
        ("kind", body::KEY_KIND),
        ("device", body::KEY_DEVICE),
        ("possession", body::KEY_POSSESSION),
        ("xwing", body::KEY_XWING),
        ("mldsa", body::KEY_MLDSA),
        ("identity", body::KEY_IDENTITY),
    ] {
        assert_eq!(keys[name], key, "{name}");
    }
    assert_eq!(keys.len(), 8);
    assert_eq!(
        p["entry_version"],
        frasil_base::version::DEVICE_LIST_BODY_VERSION
    );
    assert_eq!(p["event_kind"], body::EVENT_KIND);
    assert_eq!(p["max_list_events"], body::MAX_LIST_EVENTS as u64);

    // The statement's length, computed for both shapes.
    let member = MemberKeys::from_seeds(&[1; 32], &[2; 32], &[3; 32]);
    let sizes = &p["possession_statement_bytes"];
    let other = possession::statement(
        &[0; 32],
        &DeviceId([0; 32]),
        Kind::Device,
        member.identity(),
        member.mldsa(),
        member.xwing(),
    );
    let agent = possession::statement(
        &[0; 32],
        &DeviceId([0; 32]),
        Kind::RecoveryAgent,
        member.identity(),
        member.mldsa(),
        None,
    );
    assert_eq!(sizes["other"], other.len() as u64);
    assert_eq!(sizes["agent"], agent.len() as u64);
    assert_eq!(
        (other.len(), agent.len()),
        (STATEMENT_BYTES, AGENT_STATEMENT_BYTES)
    );

    let ranks = p["ranks"].as_object().unwrap();
    assert_eq!(ranks.len(), Rank::ALL.len());
    for rank in Rank::ALL {
        assert_eq!(ranks[&rank.number().to_string()], rank.holders());
    }
}

// ---------------------------------------------------------------------------
// passkey_derivations, passkey_refusals

fn check_member(row: &Json, member: &MemberKeys) {
    assert_eq!(member.identity_seed(), &array(row, "identity_seed"));
    assert_eq!(member.xwing_seed(), Some(&array(row, "xwing_seed")));
    assert_eq!(member.mldsa_seed(), &array(row, "mldsa_seed"));
    assert_eq!(member.identity().0, array(row, "identity"));
    assert_eq!(&member.xwing().unwrap()[..], &bytes(row, "xwing")[..]);
    assert_eq!(&member.mldsa()[..], &bytes(row, "mldsa_public")[..]);
    assert_eq!(member.signer().kc().0, array(row, "kc"));
    assert_eq!(member.device_id().0, array(row, "device_id"));
}

#[test]
fn passkey_derivations() {
    let rows = family("passkey_derivations");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(passkey::prf_input(), passkey::PRF_INPUT);
    for row in rows {
        let name = text(row, "name");
        let person: [u8; 32] = array(row, "person_id");
        let space: [u8; 32] = array(row, "personal_space_id");
        let output = bytes(row, "prf_output");
        assert_eq!(passkey::PRF_INPUT, array(row, "prf_input"), "{name}");
        assert_eq!(
            passkey::webauthn_salt(),
            array(row, "webauthn_salt"),
            "{name}"
        );

        let handle = UserHandle {
            person_id: person,
            personal_space: space,
        };
        assert_eq!(
            handle.to_bytes()[..],
            bytes(row, "user_handle")[..],
            "{name}"
        );
        assert_eq!(UserHandle::parse(&bytes(row, "user_handle")), Ok(handle));

        // The PRK the extract gives; the type itself never exposes it.
        assert_eq!(
            *hkdf_extract(PASSKEY_EXTRACT, &output),
            array(row, "prk"),
            "{name}"
        );
        let infos = Infos::for_person(&person);
        let expected = &row["infos"];
        assert_eq!(infos.identity, bytes(expected, "identity"), "{name}");
        assert_eq!(infos.xwing, bytes(expected, "xwing"), "{name}");
        assert_eq!(infos.mldsa, bytes(expected, "mldsa"), "{name}");
        assert_eq!(infos.fetch, bytes(expected, "fetch"), "{name}");
        assert_eq!(infos.unlock, bytes(expected, "unlock"), "{name}");

        let member = PasskeyMember::derive(&person, &output).unwrap();
        assert_eq!(member.person_id(), &person);
        check_member(row, member.member());
        assert_eq!(member.fetch().seed(), &array(row, "fetch_seed"), "{name}");
        assert_eq!(member.fetch().public(), &array(row, "fetch_key"), "{name}");
        assert_eq!(member.unlock_key(), &array(row, "unlock_key"), "{name}");
    }
}

#[test]
fn passkey_refusals() {
    let rows = family("passkey_refusals");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let result = PasskeyMember::derive(&bytes(row, "person_id"), &bytes(row, "prf_output"));
        assert_eq!(
            class(result),
            Some(text(row, "error")),
            "{}",
            text(row, "name")
        );
    }
}

#[test]
fn user_handles_of_other_lengths() {
    for length in [0, 32, 63, 65] {
        assert_eq!(
            class(UserHandle::parse(&vec![0; length])),
            Some("Malformed"),
            "{length} bytes"
        );
    }
}

// ---------------------------------------------------------------------------
// recovery_keys

#[test]
fn recovery_keys() {
    let row = family("recovery_keys");
    let secret = RecoverySecret::from_bytes(&array(&row, "secret"));
    assert_eq!(&secret.printed()[..], text(&row, "printed"));

    assert_eq!(RECOVERY, &bytes(&row, "salt")[..]);
    assert_eq!(*hkdf_extract(RECOVERY, secret.bytes()), array(&row, "prk"));
    let infos = &row["infos"];
    assert_eq!(recovery::IDENTITY_INFO, &bytes(infos, "identity")[..]);
    assert_eq!(RECOVERY_KEY_HYBRID, &bytes(infos, "xwing")[..]);
    assert_eq!(RECOVERY_KEY_MLDSA, &bytes(infos, "mldsa")[..]);
    assert_eq!(RECOVERY_KEY_FETCH, &bytes(infos, "fetch")[..]);

    let key = RecoveryKey::derive(&secret);
    check_member(&row, key.member());
    assert_eq!(key.fetch().seed(), &array(&row, "fetch_seed"));
    assert_eq!(key.fetch().public(), &array(&row, "fetch_key"));

    for reading in row["reading"].as_array().unwrap() {
        let name = text(reading, "name");
        let read = RecoverySecret::read_sheet(text(reading, "text"));
        match reading.get("error") {
            Some(error) => assert_eq!(class(read), error.as_str(), "{name}"),
            None => assert_eq!(read.unwrap().bytes(), &array(reading, "secret"), "{name}"),
        }
    }

    // The same bytes as a PRF output give unrelated keys.
    let same = &row["same_bytes_as_prf_output"];
    let member = PasskeyMember::derive(&bytes(same, "person_id"), secret.bytes()).unwrap();
    assert_eq!(member.member().identity().0, array(same, "identity"));
    assert_eq!(
        &member.member().xwing().unwrap()[..],
        &bytes(same, "xwing")[..]
    );
    assert_eq!(
        &member.member().mldsa()[..],
        &bytes(same, "mldsa_public")[..]
    );
    assert_eq!(member.fetch().public(), &array(same, "fetch_key"));
    assert_eq!(member.unlock_key(), &array(same, "unlock_key"));
    assert_ne!(member.member().identity(), key.member().identity());
}

// ---------------------------------------------------------------------------
// recovery_entries

#[test]
fn recovery_entries() {
    let f = family("recovery_entries");
    let personal: [u8; 32] = array(&f, "personal_space_id");
    let accepted = f["accepted"].as_array().unwrap();
    assert_eq!(accepted.len(), 2);
    for row in accepted {
        let name = text(row, "name");
        let data = bytes(row, "entry");
        let entry = RecoveryEntry::read(&data, &personal).unwrap();
        assert_eq!(entry.space, array(row, "space"), "{name}");
        assert_eq!(entry.key, array(row, "key"), "{name}");
        assert_eq!(entry.encode(), data, "{name}");
        let made = match &entry.holder {
            Holder::Member(member) => {
                assert_eq!(member.0, array(row, "member"), "{name}");
                assert_eq!(entry.space, personal);
                RecoveryEntry::for_member(entry.space, entry.key, *member)
            }
            Holder::Seed(seed) => {
                assert_eq!(**seed, array(row, "seed"), "{name}");
                assert_ne!(entry.space, personal);
                RecoveryEntry::for_seed(entry.space, seed)
            }
        };
        assert_eq!(made.encode(), data, "{name}");
    }
    let refused = f["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 7);
    for row in refused {
        let read = RecoveryEntry::read(&bytes(row, "entry"), &personal);
        assert_eq!(
            class(read),
            Some(text(row, "error")),
            "{}",
            text(row, "name")
        );
    }
}

#[test]
fn recovery_entry_shapes() {
    let personal = [5; 32];
    for data in [&b""[..], b"\xa0", b"\x80", b"\xa1\x00\x01"] {
        assert!(RecoveryEntry::read(data, &personal).is_err());
    }
    // A version that is not an unsigned integer.
    assert_eq!(
        class(RecoveryEntry::read(b"\xa1\x00\x41\x01", &personal)),
        Some("UnsupportedVersion")
    );
}

// ---------------------------------------------------------------------------
// enrolment: identity.md, "Adding list members", steps 1 and 2. The family
// is S8b's to claim; it needs no event, so it is checked here too.

#[test]
fn enrolment() {
    for row in family("enrolment").as_array().unwrap() {
        let name = text(row, "name");
        let result = PasskeyMember::enrol(
            &bytes(row, "person_id"),
            &bytes(row, "first_prf_output"),
            &bytes(row, "second_prf_output"),
        );
        match row.get("error") {
            Some(error) => assert_eq!(class(result), error.as_str(), "{name}"),
            None => {
                let member = result.unwrap();
                assert_eq!(
                    member.member().identity().0,
                    array(row, "identity"),
                    "{name}"
                );
                assert_eq!(
                    &member.member().xwing().unwrap()[..],
                    &bytes(row, "xwing")[..]
                );
                assert_eq!(
                    &member.member().mldsa()[..],
                    &bytes(row, "mldsa_public")[..]
                );
                assert_eq!(member.fetch().public(), &array(row, "fetch_key"));
            }
        }
    }
}
