//! `identity.json`: account links (identity.md, "Account links" and
//! "Checking an account link").
//!
//! Steps 4 to 6 of `check_link` read the person's merged list: the `list`
//! family's events, merged. Another person's list is the first of the
//! `persons` family.

mod common;

use common::{array, bytes, class, device, family, text};
use frasil_identity::links::{
    self, AccountLink, ListView, Unlink, check_link, text_ok, unlink_statement,
};
use frasil_identity::{DeviceList, MergedList};

/// The merged list of the events of a family's rows, each with `signed`.
fn merged(rows: &[serde_json::Value], key: &str) -> MergedList {
    let mut list = DeviceList::new(&bytes(&rows[0], key)).unwrap();
    for row in &rows[1..] {
        list.insert(&bytes(row, key)).unwrap();
    }
    list.merge()
}

#[test]
fn account_links() {
    let f = family("account_links");
    let person: [u8; 32] = array(&f, "person_id");
    let nonce: [u8; 16] = array(&f, "nonce");
    let (origin, subject) = (text(&f, "origin"), text(&f, "subject"));
    let link_bytes = bytes(&f, "link");
    let link_id: [u8; 32] = array(&f, "link_id");

    // The link and the unlink, made again from the list's devices.
    let laptop = device("identity", "laptop");
    let phone = device("identity", "phone");
    assert_eq!(
        links::statement(origin, subject, &person, &nonce),
        bytes(&f, "statement")
    );
    let link = AccountLink::sign(origin, subject, &person, &nonce, laptop.signer()).unwrap();
    assert_eq!(link.encode(), link_bytes);
    assert_eq!(link.id(), link_id);
    assert_eq!(AccountLink::verify(&link_bytes), Ok(link));
    assert_eq!(unlink_statement(&link_id), bytes(&f, "unlink_statement"));
    let unlink = Unlink::sign(&link_id, phone.signer());
    assert_eq!(unlink.encode(), bytes(&f, "unlink"));
    assert_eq!(Unlink::decode(&bytes(&f, "unlink")), Ok(unlink.clone()));
    assert!(unlink.verifies());

    let list = family("list");
    let view = merged(list["events"].as_array().unwrap(), "signed");
    assert_eq!(view.person_id(), &person);
    let alice = family("persons")["alice"].clone();
    let other = merged(&[alice], "first_event");
    assert_ne!(other.person_id(), &person);

    let checks = f["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 7);
    for row in checks {
        let name = text(row, "name");
        let unlinks: Vec<Vec<u8>> = row["unlinks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| frasil_testkit::hex::decode(u.as_str().unwrap()).unwrap())
            .collect();
        let unlinks: Vec<&[u8]> = unlinks.iter().map(Vec::as_slice).collect();
        let against: &dyn ListView = if name == "checked against another person's list" {
            &other
        } else {
            &view
        };
        let result = check_link(&bytes(row, "record"), against, &unlinks);
        match row.get("error") {
            Some(error) => assert_eq!(class(result), error.as_str(), "{name}"),
            None => assert_eq!(result.unwrap().id(), array(row, "link_id"), "{name}"),
        }
    }
}

#[test]
fn link_shapes() {
    let laptop = device("identity", "laptop");
    let link = AccountLink::sign("o", "s", &[1; 32], &[2; 16], laptop.signer()).unwrap();
    assert!(AccountLink::verify(&link.encode()).is_ok());
    for (origin, ok) in [
        ("", false),
        (" \t", false),
        ("a\u{7}", false),
        ("a\u{85}", false),
        (" a ", true),
        ("é", true),
    ] {
        assert_eq!(text_ok(origin), ok, "{origin:?}");
    }
    assert!(text_ok(&"x".repeat(256)));
    assert!(!text_ok(&"x".repeat(257)));
    let mut bad = link.clone();
    bad.subject = "\u{0}".into();
    assert_eq!(class(AccountLink::verify(&bad.encode())), Some("Malformed"));
    let mut small = link.clone();
    small.signer.ed = {
        let mut k = [0; 32];
        k[0] = 1;
        frasil_crypto::device::IdentityKey(k)
    };
    assert_eq!(
        class(AccountLink::verify(&small.encode())),
        Some("InvalidKey")
    );
    assert!(AccountLink::sign("", "s", &[1; 32], &[2; 16], laptop.signer()).is_err());
}
