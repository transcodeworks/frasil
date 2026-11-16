//! `crypto.json` `mldsa65_known_answers`: the vendored subset of
//! Wycheproof's ML-DSA-65 signing (from a seed) and verification tests
//! (crypto.md, "Test vectors").
//!
//! Frasil signs pure ML-DSA-65 with an empty context and verifies the same
//! way ([`frasil_crypto::mldsa65`]); those tests run through it. Tests with
//! a context, a given `rnd` or a given `mu` run through the same `ml-dsa`
//! key, so that the implementation Frasil uses is checked against every
//! answer the vectors record.

use frasil_crypto::mldsa65::{self, Mldsa65Key};
use frasil_testkit::hex;
use frasil_testkit::vectors;
use ml_dsa::{ExpandedSigningKey, MlDsa65, Signature, VerifyingKey};
use serde::Deserialize;

const FILE: &str = "crypto.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KnownAnswers {
    source: serde_json::Value,
    sign: Vec<SignGroup>,
    verify: Vec<VerifyGroup>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignGroup {
    #[serde(rename = "privateSeed", deserialize_with = "hex::bytes")]
    private_seed: Vec<u8>,
    #[serde(rename = "publicKey", deserialize_with = "hex::bytes")]
    public_key: Vec<u8>,
    public_key_matches: bool,
    tests: Vec<SignTest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    comment: String,
    flags: Vec<String>,
    msg: Option<String>,
    ctx: Option<String>,
    rnd: Option<String>,
    mu: Option<String>,
    sig: String,
    result: String,
    frasil: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyGroup {
    #[serde(rename = "publicKey", deserialize_with = "hex::bytes")]
    public_key: Vec<u8>,
    tests: Vec<VerifyTest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyTest {
    #[serde(rename = "tcId")]
    tc_id: u64,
    comment: String,
    flags: Vec<String>,
    msg: String,
    ctx: Option<String>,
    sig: String,
    result: String,
    frasil: String,
}

fn known_answers() -> KnownAnswers {
    vectors::family(FILE, "mldsa65_known_answers")
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).expect("hex")
}

/// `M'` for pure ML-DSA with a context: `0x00 || u8(len(ctx)) || ctx ||
/// message` (FIPS 204, Algorithm 2), or `None` for a context over 255 bytes.
fn message_prime_with_context(message: &[u8], ctx: &[u8]) -> Option<Vec<u8>> {
    let length = u8::try_from(ctx.len()).ok()?;
    Some([&[0, length][..], ctx, message].concat())
}

#[test]
fn signing_from_a_seed() {
    let answers = known_answers();
    assert!(
        answers.source["sign"]
            .as_str()
            .unwrap()
            .contains("mldsa_65_sign_seed_test.json")
    );
    assert_eq!(answers.sign.len(), 4);
    let mut tests = 0;
    for group in &answers.sign {
        let seed: [u8; 32] = group.private_seed.as_slice().try_into().unwrap();
        let key = Mldsa65Key::from_seed(&seed);
        assert!(group.public_key_matches);
        assert_eq!(key.public().as_slice(), group.public_key);
        let expanded = ExpandedSigningKey::<MlDsa65>::from_seed(&seed.into());
        let verifying =
            VerifyingKey::<MlDsa65>::decode(&key.public().as_slice().try_into().unwrap());
        for test in &group.tests {
            tests += 1;
            let id = test.tc_id;
            assert!(
                !test.comment.is_empty() && !test.flags.is_empty(),
                "test {id}"
            );
            let ctx = test.ctx.as_deref().map(unhex).unwrap_or_default();
            if test.result == "invalid" {
                // A context over 255 bytes: refused before anything is signed.
                let message = unhex(test.msg.as_deref().unwrap());
                assert!(
                    message_prime_with_context(&message, &ctx).is_none(),
                    "test {id}"
                );
                assert!(
                    expanded.sign_deterministic(&message, &ctx).is_err(),
                    "test {id}"
                );
                assert_eq!(test.frasil, "refused", "test {id}");
                assert!(test.sig.is_empty());
                continue;
            }
            assert_eq!(test.result, "valid", "test {id}");
            assert_eq!(test.frasil, "signature matches", "test {id}");
            let rnd: [u8; 32] = test
                .rnd
                .as_deref()
                .map(|rnd| unhex(rnd).try_into().unwrap())
                .unwrap_or([0; 32]);
            let signature = match &test.msg {
                // Frasil's own signing: pure, with an empty context.
                Some(message) if ctx.is_empty() => {
                    let message = unhex(message);
                    key.sign_with_rnd(&message, &rnd).to_vec()
                }
                Some(message) => {
                    let message_prime = message_prime_with_context(&unhex(message), &ctx).unwrap();
                    expanded
                        .sign_internal(&[&message_prime], &rnd.into())
                        .encode()
                        .to_vec()
                }
                // Internal: from a given mu, deterministically.
                None => {
                    assert_eq!(rnd, [0; 32], "test {id}");
                    let mu: [u8; 64] = unhex(test.mu.as_deref().unwrap()).try_into().unwrap();
                    expanded.sign_mu_deterministic(&mu.into()).encode().to_vec()
                }
            };
            assert_eq!(hex::encode(&signature), test.sig, "test {id}");
            if let (Some(message), Some(mu)) = (&test.msg, &test.mu) {
                let message = unhex(message);
                let ours = verifying
                    .compute_mu(
                        |shake| {
                            use ml_dsa::signature::digest::Update;
                            shake.update(&message);
                            Ok(())
                        },
                        &ctx,
                    )
                    .unwrap();
                assert_eq!(hex::encode(ours.as_slice()), *mu, "test {id}");
            }
            if test.msg.is_some() && ctx.is_empty() {
                assert!(mldsa65::verify(
                    key.public(),
                    &unhex(test.msg.as_deref().unwrap()),
                    &signature
                ));
            }
        }
    }
    assert_eq!(tests, 13);
}

#[test]
fn verification() {
    let answers = known_answers();
    assert!(
        answers.source["verify"]
            .as_str()
            .unwrap()
            .contains("mldsa_65_verify_test.json")
    );
    assert_eq!(answers.verify.len(), 8);
    let mut tests = 0;
    for group in &answers.verify {
        for test in &group.tests {
            tests += 1;
            let id = test.tc_id;
            assert!(!test.comment.is_empty(), "test {id}");
            let message = unhex(&test.msg);
            let signature = unhex(&test.sig);
            let ctx = test.ctx.as_deref().map(unhex).unwrap_or_default();
            let valid = if ctx.is_empty() {
                // Frasil's own verification: pure, with an empty context.
                mldsa65::verify(&group.public_key, &message, &signature)
            } else {
                verify_with_context(&group.public_key, &message, &signature, &ctx)
            };
            let verdict = if valid { "valid" } else { "invalid" };
            assert_eq!(verdict, test.result, "test {id} ({:?})", test.flags);
            assert_eq!(verdict, test.frasil, "test {id}");
        }
    }
    assert_eq!(tests, 22);
}

fn verify_with_context(public: &[u8], message: &[u8], signature: &[u8], ctx: &[u8]) -> bool {
    let (Ok(public), Ok(signature)) = (
        <&[u8; 1952]>::try_from(public),
        Signature::<MlDsa65>::try_from(signature),
    ) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&(*public).into()).verify_with_context(message, ctx, &signature)
}
