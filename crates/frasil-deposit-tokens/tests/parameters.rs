//! `ext-deposit-tokens.json`'s `parameters` (ext-deposit-tokens.md, 2.1 The
//! VOPRF, 2.4 Tokens, 2.5 Messages, 2.6 Settings and 2.8 Error classes).

mod common;

use common::*;
use frasil_base::errors::Class;
use frasil_crypto::labels::{DEPOSIT_KEY, DEPOSIT_TOKEN};
use frasil_deposit_tokens::key::KEY_ID_BYTES;
use frasil_deposit_tokens::settings::*;
use frasil_deposit_tokens::suite::{
    CONTEXT, ELEMENT_BYTES, MODE, OUTPUT_BYTES, PROOF_BYTES, SCALAR_BYTES,
};
use frasil_deposit_tokens::token::{INPUT_BYTES, NONCE_BYTES, TOKEN_BYTES, TOKEN_VERSION};
use frasil_deposit_tokens::{
    DEPOSIT_SERVICE, MAX_BATCH, MAX_GRANT_BYTES, MESSAGE_CAP, Role, TOKEN_ISSUE, TOKEN_KEYS,
    TOKEN_KEYS_GET, TOKEN_REQUEST, TokenClass,
};
use frasil_libraries::Purpose;
use frasil_libraries::ticket::MAX_GRANT_TOKENS;
use frasil_testkit::hex;
use frasil_transport::MessageType;
use frasil_transport::codes::Service;
use frasil_transport::mailbox::TOKEN_KEY;

#[test]
fn parameters_match() {
    let p = family("parameters");
    assert_eq!(text(&p["suite"]), "ristretto255-SHA512");
    assert_eq!(number(&p["mode"]), u64::from(MODE));
    assert_eq!(bytes(&p["context"]), CONTEXT);
    let labels = p["labels"].as_object().unwrap();
    assert_eq!(labels.len(), 2);
    for label in [DEPOSIT_KEY, DEPOSIT_TOKEN] {
        let name = core::str::from_utf8(label).unwrap();
        assert_eq!(text(&labels[name]), hex::encode(label));
    }
    for (name, value) in [
        ("element_bytes", ELEMENT_BYTES),
        ("scalar_bytes", SCALAR_BYTES),
        ("output_bytes", OUTPUT_BYTES),
        ("proof_bytes", PROOF_BYTES),
        ("key_id_bytes", KEY_ID_BYTES),
        ("nonce_bytes", NONCE_BYTES),
        ("input_bytes", INPUT_BYTES),
        ("token_bytes", TOKEN_BYTES),
        ("max_batch", MAX_BATCH),
        ("max_grant_bytes", MAX_GRANT_BYTES),
        ("message_cap", MESSAGE_CAP),
    ] {
        assert_eq!(number(&p[name]) as usize, value, "{name}");
    }
    assert_eq!(number(&p["token_version"]), u64::from(TOKEN_VERSION));
    assert_eq!(
        (number(&p["grant_tokens"][0]), number(&p["grant_tokens"][1])),
        (1, MAX_GRANT_TOKENS)
    );
    let types = &p["message_types"];
    for (name, code, kind) in [
        ("TokenKeysGet", TOKEN_KEYS_GET, MessageType::TokenKeysGet),
        ("TokenKeys", TOKEN_KEYS, MessageType::TokenKeys),
        ("TokenRequest", TOKEN_REQUEST, MessageType::TokenRequest),
        ("TokenIssue", TOKEN_ISSUE, MessageType::TokenIssue),
    ] {
        assert_eq!(number(&types[name]), code);
        assert_eq!(kind.code(), code);
        assert_eq!(kind.name(), name);
        assert_eq!(kind.cap(), MESSAGE_CAP);
    }
    assert_eq!(number(&p["service"]), DEPOSIT_SERVICE);
    assert_eq!(Service::Deposit.code(), DEPOSIT_SERVICE);
    assert_eq!(number(&p["mailbox_put_key"]), TOKEN_KEY);
    assert_eq!(number(&p["ticket_purpose"]), Purpose::Deposit.code());
    assert_eq!(number(&p["ticket_key"]), 7);
    assert_eq!(text(&p["roles"]["1"]), "issuing");
    assert_eq!(Role::from_code(1), Some(Role::Issuing));
    assert_eq!(Role::from_code(2), Some(Role::Accepting));
    assert_eq!(Role::from_code(3), None);
    assert_eq!(number(&p["token_period"]["default"]), TOKEN_PERIOD);
    assert_eq!(
        (
            number(&p["token_period"]["range"][0]),
            number(&p["token_period"]["range"][1])
        ),
        TOKEN_PERIOD_RANGE
    );
    assert_eq!(number(&p["allowance_window"]), ALLOWANCE_WINDOW);
    assert_eq!(
        number(&p["deposit_allowance"]["default"]),
        DEPOSIT_ALLOWANCE
    );
    assert_eq!(
        (
            number(&p["deposit_allowance"]["range"][0]),
            number(&p["deposit_allowance"]["range"][1])
        ),
        DEPOSIT_ALLOWANCE_RANGE
    );
    assert_eq!(number(&p["space_share"]["default"]), SPACE_SHARE);
    assert_eq!(DepositSettings::default().space_share, SPACE_SHARE);
    assert_eq!(number(&p["consistency_window"]), CONSISTENCY_WINDOW);
    assert_eq!(number(&p["draw_defaults"]["low_mark"]) as usize, LOW_MARK);
    assert_eq!(number(&p["draw_defaults"]["batch"]) as usize, BATCH);
    // The timers agree with overview.md's table.
    use frasil_base::time::Timer;
    assert_eq!(Timer::TokenPeriod.spec().default, Some(TOKEN_PERIOD));
    assert_eq!(
        Timer::AllowanceWindow.spec().default,
        Some(ALLOWANCE_WINDOW)
    );

    // Every class, with its code and status.
    let classes = p["classes"].as_object().unwrap();
    assert_eq!(classes.len(), 18);
    for (name, row) in classes {
        let class = TokenClass::from_name(name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(class.code(), row["code"].as_str(), "{name}");
        assert_eq!(
            class.status(),
            row["status"].as_u64().map(|s| s as u16),
            "{name}"
        );
    }
    for &own in TokenClass::OWN {
        assert!(classes.contains_key(own.name()), "{}", own.name());
    }
}
