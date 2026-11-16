//! `ext-deposit-tokens.json`'s `voprf`: RFC 9497's ristretto255-SHA512
//! VOPRF vectors, single and batched, run through this crate's own path
//! (ext-deposit-tokens.md, 2.1 The VOPRF): each blind and proof scalar
//! replayed as the bytes the vector gives.

mod common;

use common::*;
use frasil_deposit_tokens::suite;
use frasil_testkit::hex;

#[test]
fn rfc_9497_vectors_run_through_the_suite() {
    let v = family("voprf");
    let server = suite::derive_key_pair(&bytes(&v["seed"]), &bytes(&v["key_info"])).unwrap();
    assert_eq!(hex::encode(&server.serialize()[..32]), text(&v["skSm"]));
    assert_eq!(hex::encode(suite::public_key(&server)), text(&v["pkSm"]));
    let public = suite::deserialize_element(&bytes(&v["pkSm"])).unwrap();
    let vectors = v["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 3);
    for vector in vectors {
        let name = text(&vector["name"]);
        let inputs: Vec<Vec<u8>> = vector["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect();
        let mut clients = Vec::new();
        let mut blinded = Vec::new();
        for (input, blind) in inputs.iter().zip(vector["blind"].as_array().unwrap()) {
            let (client, element) = suite::blind_with(input, &array(blind)).unwrap();
            clients.push(client);
            blinded.push(element);
        }
        let expected: Vec<[u8; 32]> = vector["blinded_element"]
            .as_array()
            .unwrap()
            .iter()
            .map(array)
            .collect();
        assert_eq!(blinded, expected, "{name}");
        let (evaluated, proof) =
            suite::evaluate_batch_with(&server, &blinded, &array(&vector["proof_random_scalar"]))
                .unwrap();
        let expected: Vec<[u8; 32]> = vector["evaluation_element"]
            .as_array()
            .unwrap()
            .iter()
            .map(array)
            .collect();
        assert_eq!(evaluated, expected, "{name}");
        assert_eq!(hex::encode(proof), text(&vector["proof"]), "{name}");
        let refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        let outputs = suite::finalize_batch(&refs, &clients, &evaluated, &proof, public).unwrap();
        for ((output, expected), input) in outputs
            .iter()
            .zip(vector["output"].as_array().unwrap())
            .zip(&inputs)
        {
            assert_eq!(hex::encode(output.as_slice()), text(expected), "{name}");
            assert_eq!(
                suite::evaluate(&server, input).unwrap().as_slice(),
                output.as_slice()
            );
            assert!(suite::verify(&server, input, output.as_slice()));
        }
        // A changed proof does not hold.
        let mut changed = proof;
        changed[0] ^= 1;
        assert_eq!(
            suite::finalize_batch(&refs, &clients, &evaluated, &changed, public).unwrap_err(),
            suite::SuiteError::Proof
        );
    }
}

#[test]
fn draws_that_are_not_scalars_are_refused() {
    // The group's order, and zero: neither is a canonical, non-zero scalar.
    let order =
        hex::decode_array::<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap();
    assert!(!suite::is_scalar(&order));
    assert!(!suite::is_scalar(&[0; 32]));
    assert_eq!(
        suite::blind_with(b"x", &order).unwrap_err(),
        suite::SuiteError::Scalar
    );
    let random = suite::random_scalar().unwrap();
    assert!(suite::is_scalar(&random));
    // The identity and a non-canonical encoding are not elements.
    assert!(suite::deserialize_element(&[0; 32]).is_err());
    let mut noncanonical = [0xff; 32];
    noncanonical[31] = 0x7f;
    assert!(suite::deserialize_element(&noncanonical).is_err());
}
