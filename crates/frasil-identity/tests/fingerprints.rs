//! `identity.json`: fingerprints and their parsing (identity.md,
//! "Fingerprints" and "Comparing fingerprints").

mod common;

use common::{bytes, class, family, text};
use frasil_crypto::primitives::sha256;
use frasil_identity::fingerprint::{
    self, ALPHABET, Fingerprint, GF32_MODULUS, check, confirm, digest_input, times_x,
};
use serde_json::Value as Json;

fn value_of(row: &Json) -> u128 {
    u128::from_str_radix(text(row, "value_120_bits"), 16).unwrap()
}

fn check_symbol(row: &Json) -> u8 {
    u8::try_from(row["check"].as_u64().unwrap()).unwrap()
}

#[test]
fn fingerprints() {
    let f = family("fingerprints");
    assert_eq!(text(&f, "alphabet").as_bytes(), ALPHABET);
    assert_eq!(f["gf32_modulus"], u64::from(GF32_MODULUS));

    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let mut seen = Vec::new();
    for row in cases {
        let name = text(row, "name");
        let (person, identity) = (bytes(row, "person_id"), bytes(row, "identity"));
        let (mldsa, xwing) = (bytes(row, "mldsa"), bytes(row, "xwing"));
        let input = digest_input(
            &person.clone().try_into().unwrap(),
            &identity.clone().try_into().unwrap(),
            &mldsa,
            &xwing,
        );
        assert_eq!(input, bytes(row, "digest_input"), "{name}");
        let digest = sha256(&[&input]);
        assert_eq!(digest[..], bytes(row, "digest")[..], "{name}");

        let fp = Fingerprint::of(&person, &identity, &mldsa, &xwing).unwrap();
        assert_eq!(fp.value(), value_of(row), "{name}");
        assert_eq!(fp.value_bytes()[..], digest[..15], "{name}");
        assert_eq!(fp.check_symbol(), check_symbol(row), "{name}");
        assert_eq!(fp.characters(), text(row, "characters"), "{name}");
        assert_eq!(fp.display(), text(row, "display"), "{name}");
        assert_eq!(fp.qr(), text(row, "qr"), "{name}");
        assert_eq!(Fingerprint::parse(&fp.display()), Ok(fp), "{name}");
        assert_eq!(Fingerprint::parse(&fp.qr()), Ok(fp), "{name}");

        // Comparing: the keys about to be signed give the confirmed value.
        assert_eq!(confirm(&fp, &person, &identity, &mldsa, &xwing), Ok(()));
        for other in &seen {
            assert_eq!(
                class(confirm(other, &person, &identity, &mldsa, &xwing)),
                Some("FingerprintMismatch"),
                "{name}"
            );
        }
        seen.push(fp);
    }

    let checks = f["check_symbols"].as_array().unwrap();
    assert_eq!(checks.len(), 5);
    for row in checks {
        let fp = Fingerprint::from_value(value_of(row));
        let name = text(row, "name");
        assert_eq!(fp.check_symbol(), check_symbol(row), "{name}");
        assert_eq!(fp.characters(), text(row, "characters"), "{name}");
    }

    let none = f["no_fingerprint"].as_array().unwrap();
    assert_eq!(none.len(), 4);
    for row in none {
        let (person, identity) = (bytes(row, "person_id"), bytes(row, "identity"));
        let (mldsa, xwing) = (bytes(row, "mldsa"), bytes(row, "xwing"));
        let expected = Some(text(row, "error"));
        let name = text(row, "name");
        assert_eq!(
            class(Fingerprint::of(&person, &identity, &mldsa, &xwing)),
            expected,
            "{name}"
        );
        // A key that fails its check is never reported as a mismatch.
        let any = Fingerprint::from_value(0);
        assert_eq!(
            class(confirm(&any, &person, &identity, &mldsa, &xwing)),
            expected,
            "{name}"
        );
    }
}

#[test]
fn check_symbols_satisfy_the_polynomial() {
    // d_0·x^24 + ... + d_24 = 0, evaluated by Horner's rule.
    for value in [
        0u128,
        1,
        (1 << 120) - 1,
        0x0123_4567_89ab_cdef_0123_4567_89ab,
    ] {
        let symbols = Fingerprint::from_value(value).symbols();
        let syndrome = symbols.iter().fold(0, |acc, d| times_x(acc) ^ d);
        assert_eq!(syndrome, 0, "{value:x}");
        let head: [u8; 24] = symbols[..24].try_into().unwrap();
        assert_eq!(check(&head), symbols[24]);
    }
}

#[test]
fn fingerprint_parsing() {
    let f = family("fingerprint_parsing");
    let characters = text(&f, "characters");
    let expected = Fingerprint::parse(characters).unwrap();
    assert_eq!(expected.characters(), characters);

    let accepted = f["accepted"].as_array().unwrap();
    assert_eq!(accepted.len(), 8);
    for row in accepted {
        let parsed = Fingerprint::parse(text(row, "input"));
        assert_eq!(parsed, Ok(expected), "{}", text(row, "name"));
        assert_eq!(parsed.unwrap().characters(), text(row, "characters"));
    }

    let refused = f["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 16);
    for row in refused {
        let parsed = Fingerprint::parse(text(row, "input"));
        assert_eq!(
            class(parsed),
            Some(text(row, "error")),
            "{}",
            text(row, "name")
        );
    }

    for group in ["single_character_errors", "exchanges"] {
        let errors = &f[group];
        let error = text(errors, "error");
        let inputs = errors["inputs"].as_array().unwrap();
        for input in inputs {
            let input = input.as_str().map_or_else(|| text(input, "input"), |s| s);
            assert_eq!(
                class(Fingerprint::parse(input)),
                Some(error),
                "{group}: {input}"
            );
        }
        if group == "single_character_errors" {
            assert_eq!(inputs.len(), 775);
        }
    }

    let undetected = &f["undetected"];
    let parsed = Fingerprint::parse(text(undetected, "input")).unwrap();
    assert_eq!(parsed.characters(), text(undetected, "characters"));
    assert_ne!(parsed, expected);
}

#[test]
fn parsing_bounds() {
    let fp = Fingerprint::from_value(12345);
    let chars = fp.characters();
    // 128 characters, all ASCII, is the most read.
    let padded = format!("{}{chars}", " ".repeat(fingerprint::MAX_INPUT - 25));
    assert_eq!(Fingerprint::parse(&padded), Ok(fp));
    let over = format!(" {padded}");
    assert_eq!(class(Fingerprint::parse(&over)), Some("InvalidFingerprint"));
    // A prefix only at the start, once.
    let twice = format!("{}{}", fingerprint::QR_PREFIX, fp.qr());
    assert_eq!(
        class(Fingerprint::parse(&twice)),
        Some("InvalidFingerprint")
    );
}
