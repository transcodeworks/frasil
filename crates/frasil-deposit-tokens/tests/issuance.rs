//! `ext-deposit-tokens.json`'s `grants`, `issuance` and `space_draws`: the
//! deposit grant, a peer's checks of a `TokenRequest` in order, and issuing
//! with the allowance window and each space's share (ext-deposit-tokens.md,
//! 2.3 The deposit grant, 3.1 Two ways in and 3.4 Issuing).

mod common;

use std::collections::BTreeSet;

use common::*;
use frasil_deposit_tokens::{Batch, Draw, KeyList, check_request, issue_with};
use frasil_libraries::{Issuer, LibraryId, Purpose, check_ticket};
use frasil_testkit::hex;
use serde_json::Value as Json;

/// Replays one request at a peer of this setup; returns the state after.
fn replay(row: &Json, records: &mut Records) {
    let setup = &row["setup"];
    let name = row["name"].as_str().unwrap_or("the batch");
    assert_eq!(
        records.describe()["libraries"],
        setup["libraries"],
        "{name}"
    );
    assert_eq!(
        records.describe()["grants_used"],
        setup["grants_used"],
        "{name}"
    );
    let keys = keys(&setup["keys"]);
    let store: BTreeSet<[u8; 32]> = setup["store"]
        .as_array()
        .unwrap()
        .iter()
        .map(array)
        .collect();
    let message = map(&bytes(&row["token_request"]));
    let result = check_request(
        &message,
        |space| store.contains(space),
        setup["now_wall"].as_u64(),
        number(&setup["reading"]),
        &issuers(setup),
        &keys,
        &*records,
    );
    match result {
        Ok(approved) => {
            assert_eq!(text(&row["verdict"]), "accepted", "{name}");
            assert_eq!(approved.count as u64, number(&row["count"]), "{name}");
            let issued = issue_with(
                &approved,
                keys.issuing().unwrap(),
                &array(&row["proof_scalar"]),
            )
            .unwrap();
            assert_eq!(
                hex::encode(issued.answer.encode()),
                text(&row["token_issue"]),
                "{name}"
            );
            records.apply(&issued);
        }
        Err(class) => refused(row, class),
    }
    if let Some(after) = row.get("after") {
        assert_eq!(records.describe(), *after, "{name}");
    }
}

#[test]
fn a_batch_of_three() {
    let f = family("issuance");
    let batch = &f["batch"];
    let mut records = Records::from_setup(&batch["setup"]);
    replay(batch, &mut records);
    assert_eq!(records.ledger("project:7c1f9e2a0b4d4e8f"), batch["ledger"]);
    // The device's side: the nonces, inputs, blinds and blinded elements of
    // the request, and the tokens it finishes.
    let public = bytes(&batch["public"]);
    let id = bytes(&batch["key_id"]);
    let list = KeyList::check(&[(id.as_slice(), public.as_slice(), 1)]).unwrap();
    let draws: Vec<([u8; 32], [u8; 32])> = batch["nonces"]
        .as_array()
        .unwrap()
        .iter()
        .zip(batch["blinds"].as_array().unwrap())
        .map(|(n, b)| (array(n), array(b)))
        .collect();
    let device = Batch::new_with(list.issuing(), &draws).unwrap();
    for (input, nonce) in batch["inputs"].as_array().unwrap().iter().zip(&draws) {
        let expected = frasil_deposit_tokens::token::token_input(&list.issuing().id, &nonce.0);
        assert_eq!(hex::encode(&*expected), text(input));
    }
    let blinded: Vec<String> = device.blinded().iter().map(hex::encode).collect();
    let expected: Vec<&str> = batch["blinded"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(blinded, expected);
    let request = map(&bytes(&batch["token_request"]));
    let Some(grant) = request.get(&2) else {
        panic!("a grant draw")
    };
    assert_eq!(
        hex::encode(
            device
                .request(1, Draw::Grant(grant.as_bytes().unwrap().to_vec()))
                .encode()
        ),
        text(&batch["token_request"])
    );
    let issue = map(&bytes(&batch["token_issue"]));
    let evaluated: Vec<&str> = batch["evaluated"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    let got: Vec<String> = issue[&2]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| hex::encode(e.as_bytes().unwrap()))
        .collect();
    assert_eq!(got, evaluated);
    assert_eq!(
        hex::encode(issue[&3].as_bytes().unwrap()),
        text(&batch["proof"])
    );
    let tokens = device.finish(&issue, 1).unwrap();
    let tokens: Vec<String> = tokens.iter().map(|t| hex::encode(t.as_bytes())).collect();
    let expected: Vec<&str> = batch["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect();
    assert_eq!(tokens, expected);
}

#[test]
fn issuance_cases_and_refusals() {
    let f = family("issuance");
    let cases = f["cases"].as_array().unwrap();
    let refused = f["refused"].as_array().unwrap();
    assert_eq!((cases.len(), refused.len()), (2, 8));
    for row in cases.iter().chain(refused) {
        let mut records = Records::from_setup(&row["setup"]);
        replay(row, &mut records);
    }
}

#[test]
fn grants() {
    let f = family("grants");
    let g = &f["grant"];
    // The issuer's grant, byte for byte.
    let seed: [u8; 32] =
        frasil_crypto::primitives::sha256(&[b"frasil spec example/", b"library/issuer"]);
    let issuer = Issuer::from_seed(&seed);
    assert_eq!(hex::encode(issuer.public()), text(&g["issuer"]));
    let library = LibraryId::new(text(&g["library"])).unwrap();
    let not_after = number(&g["not_after"]);
    let signed = issuer
        .issue_grant_with(
            &library,
            number(&g["tokens"]),
            not_after - 3600,
            not_after,
            array(&g["id"]),
        )
        .unwrap();
    assert_eq!(hex::encode(&signed), text(&g["signed"]));
    let read = frasil_libraries::SignedTicket::decode_with_grants(&signed, true).unwrap();
    assert_eq!(hex::encode(&read.ticket_bytes), text(&g["ticket"]));
    assert_eq!(
        hex::encode(read.signed_message()),
        text(&g["signed_message"])
    );
    assert_eq!(hex::encode(read.signature), text(&g["signature"]));
    assert_eq!(read.ticket.purpose, Purpose::Deposit);
    assert_eq!(read.ticket.tokens, Some(number(&g["tokens"])));
    // A core reading refuses it.
    assert!(frasil_libraries::SignedTicket::decode(&signed).is_err());

    let refused = f["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 10);
    for row in refused {
        let mut records = Records::from_setup(&row["setup"]);
        replay(row, &mut records);
    }
    // A grant shown to LibraryAttach is refused at check_ticket's step 6.
    let attach = &f["as_attach"];
    let records = Records::from_setup(&refused[0]["setup"]);
    let class = check_ticket(
        &bytes(&attach["signed"]),
        Purpose::Create,
        Some(not_after - 3600),
        &issuers(&refused[0]["setup"]),
        &records,
    )
    .unwrap_err();
    refused_library(attach, class);
}

fn refused_library(row: &Json, class: frasil_libraries::LibraryClass) {
    use frasil_base::errors::Class;
    assert_eq!(class.name(), text(&row["verdict"]));
    assert_eq!(Some(class.code()), row["code"].as_str());
    assert_eq!(class.status(), row["status"].as_u64().map(|s| s as u16));
}

#[test]
fn space_draws() {
    let f = family("space_draws");
    let steps = f["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 7);
    let mut records = Records::from_setup(&steps[0]["setup"]);
    for step in steps {
        replay(step, &mut records);
        assert_eq!(records.ledger("project:7c1f9e2a0b4d4e8f"), step["ledger"]);
    }
    let refused = f["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 7);
    for row in refused {
        let mut records = Records::from_setup(&row["setup"]);
        replay(row, &mut records);
    }
}
