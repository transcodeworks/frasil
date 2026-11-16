//! `ext-deposit-tokens.json`'s `finishing`: a device's checks of
//! `TokenIssue`, in order, and the tokens it finishes
//! (ext-deposit-tokens.md, 3.5 Finishing issuance).

mod common;

use common::*;
use frasil_deposit_tokens::{Batch, KeyList};
use frasil_testkit::hex;

#[test]
fn finishing() {
    let f = family("finishing");
    let id = bytes(&f["key_id"]);
    let public = bytes(&f["public"]);
    let list = KeyList::check(&[(id.as_slice(), public.as_slice(), 1)]).unwrap();
    let draws: Vec<([u8; 32], [u8; 32])> = f["nonces"]
        .as_array()
        .unwrap()
        .iter()
        .zip(f["blinds"].as_array().unwrap())
        .map(|(n, b)| (array(n), array(b)))
        .collect();
    let batch = Batch::new_with(list.issuing(), &draws).unwrap();
    let blinded: Vec<String> = batch.blinded().iter().map(hex::encode).collect();
    let expected: Vec<&str> = f["blinded"].as_array().unwrap().iter().map(text).collect();
    assert_eq!(blinded, expected);
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for row in cases {
        let name = text(&row["name"]);
        match batch.finish_bytes(&bytes(&row["token_issue"]), number(&f["request"])) {
            Ok(tokens) => {
                assert_eq!(text(&row["verdict"]), "accepted", "{name}");
                let got: Vec<String> = tokens.iter().map(|t| hex::encode(t.as_bytes())).collect();
                let expected: Vec<&str> =
                    row["tokens"].as_array().unwrap().iter().map(text).collect();
                assert_eq!(got, expected, "{name}");
            }
            Err(class) => refused(row, class),
        }
    }
}
