//! `crypto.json`: signature schemes 0 and 2 (crypto.md, "Signature
//! schemes", "Strict Ed25519 verification", "Verifying a signature" and
//! "Which structures carry which scheme").

use frasil_base::cbor::{self, Value};
use frasil_base::errors::{Class, ErrorClass};
use frasil_crypto::device::{DeviceId, HybridKeys, IdentityKey, KeysCommitment, device_id};
use frasil_crypto::fixtures::{fixture_mldsa_seed, fixture_xwing_seed};
use frasil_crypto::labels::{EVENT, EVENT_ID};
use frasil_crypto::mldsa65::message_prime;
use frasil_crypto::primitives::sha256;
use frasil_crypto::schemes::{
    self, Held, KindPolicy, Scheme, Signed, Signer, hybrid_ed25519_message, hybrid_mldsa_message,
};
use frasil_crypto::sizes::SCHEME2_SIGNATURE;
use frasil_crypto::wrap::xwing_public;
use frasil_testkit::hex;
use frasil_testkit::vectors;
use serde::Deserialize;
use serde_json::Value as Json;

const FILE: &str = "crypto.json";

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("a value of the expected length")
}

/// The kind codes of the vectors' kind names (events.md, "Kinds").
fn kind_code(name: &str) -> u64 {
    match name {
        "device-list" => 1,
        "space" => 2,
        "unit" => 4,
        "anchor" => 5,
        "storage" => 6,
        other => panic!("no kind {other}"),
    }
}

// ---------------------------------------------------------------------------
// schemes

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemeRow {
    code: u64,
    scheme: String,
    signature_bytes: Option<usize>,
    state: Option<String>,
}

#[test]
fn schemes() {
    let rows: Vec<SchemeRow> = vectors::family(FILE, "schemes");
    assert_eq!(rows.len(), 3);
    for row in &rows {
        match Scheme::from_code(row.code) {
            Ok(scheme) => {
                assert_eq!(u64::from(scheme.code()), row.code);
                assert_eq!(
                    Some(scheme.signature_bytes()),
                    row.signature_bytes,
                    "{}",
                    row.scheme
                );
                assert_eq!(row.state, None);
            }
            Err(class) => {
                assert_eq!(row.state.as_deref(), Some("refused: UnsupportedVersion"));
                assert_eq!(class, ErrorClass::UnsupportedVersion);
                assert_eq!(row.signature_bytes, None);
                assert_eq!(row.code, u64::from(schemes::SCHEME_RESERVED));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// kind_policy

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KindRow {
    kind: String,
    code: Json,
    accepted_before_sunset: Option<Vec<u8>>,
    signed_before_sunset: Option<u8>,
    accepted_after_sunset: Option<Vec<u8>>,
    scheme_0_after_sunset_only_if_covered: Option<bool>,
    signed_after_sunset: Option<u8>,
    refused: Option<String>,
    note: Option<String>,
}

/// The codes a row names: one, or a range such as `64 to 127`.
fn codes(code: &Json) -> Vec<u64> {
    match code {
        Json::Number(n) => vec![n.as_u64().unwrap()],
        Json::String(text) => {
            let (from, to) = text.split_once(" to ").expect("a range");
            (from.parse().unwrap()..=to.parse().unwrap()).collect()
        }
        other => panic!("a kind code {other}"),
    }
}

#[test]
fn kind_policy() {
    let rows: Vec<KindRow> = vectors::family(FILE, "kind_policy");
    assert_eq!(rows.len(), 8);
    let mut covered = Vec::new();
    for row in &rows {
        let kind = &row.kind;
        for code in codes(&row.code) {
            covered.push(code);
            let policy = KindPolicy::for_kind(code);
            if let Some(refused) = &row.refused {
                assert_eq!(policy.map_err(Class::name), Err(refused.as_str()), "{kind}");
                continue;
            }
            let policy = policy.unwrap_or_else(|_| panic!("{kind} {code}"));
            if row.note.is_some() {
                // Not yet defined: it states its schemes when it is defined.
                assert_eq!(policy, KindPolicy::Undefined, "{kind} {code}");
                continue;
            }
            let ours: Vec<u8> = policy.accepted().iter().map(|s| s.code()).collect();
            assert_eq!(Some(&ours), row.accepted_before_sunset.as_ref(), "{kind}");
            assert_eq!(Some(&ours), row.accepted_after_sunset.as_ref(), "{kind}");
            assert_eq!(
                Some(policy.signing_scheme(false).code()),
                row.signed_before_sunset,
                "{kind}"
            );
            assert_eq!(
                Some(policy.signing_scheme(true).code()),
                row.signed_after_sunset,
                "{kind}"
            );
            assert_eq!(
                Some(policy.scheme_0_only_if_covered()),
                row.scheme_0_after_sunset_only_if_covered,
                "{kind}"
            );
        }
    }
    covered.sort_unstable();
    assert_eq!(covered, (1..=127).collect::<Vec<u64>>());
}

// ---------------------------------------------------------------------------
// signers

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerRow {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    ed25519_seed: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    ed25519_public: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    mldsa_seed: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    mldsa_public: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    xwing_seed: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    xwing_public: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    kc: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    device_id: Vec<u8>,
}

fn signers() -> Vec<(SignerRow, Signer)> {
    let rows: Vec<SignerRow> = vectors::family(FILE, "signers");
    rows.into_iter()
        .map(|row| {
            let xwing = xwing_public(&array(&row.xwing_seed));
            let signer = Signer::from_seeds(
                &array(&row.ed25519_seed),
                &array(&row.mldsa_seed),
                Some(&xwing),
            );
            (row, signer)
        })
        .collect()
}

fn signer<'a>(signers: &'a [(SignerRow, Signer)], name: &str) -> &'a Signer {
    &signers
        .iter()
        .find(|(row, _)| row.name == name)
        .unwrap_or_else(|| panic!("no signer {name}"))
        .1
}

#[test]
fn signers_family() {
    let signers = signers();
    assert_eq!(signers.len(), 2);
    for (row, signer) in &signers {
        assert_eq!(
            signer.identity_key().0.as_slice(),
            row.ed25519_public,
            "{}",
            row.name
        );
        assert_eq!(
            signer.keys().xwing().unwrap().as_slice(),
            row.xwing_public,
            "{}",
            row.name
        );
        assert_eq!(signer.kc().0.as_slice(), row.kc, "{}", row.name);
        assert_eq!(
            signer.device_id().0.as_slice(),
            row.device_id,
            "{}",
            row.name
        );
        assert_eq!(
            signer.mldsa_public().as_slice(),
            row.mldsa_public,
            "{}",
            row.name
        );
        // The signers are test fixtures: the ML-DSA-65 seed comes from the
        // Ed25519 seed (crypto.md, "A device's keys").
        assert_eq!(
            fixture_mldsa_seed(&array(&row.ed25519_seed)).as_slice(),
            row.mldsa_seed,
            "{}",
            row.name
        );
        assert_eq!(
            fixture_xwing_seed(&array(&row.ed25519_seed)).as_slice(),
            row.xwing_seed,
            "{}",
            row.name
        );
    }
}

// ---------------------------------------------------------------------------
// signatures

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureRow {
    kind: String,
    kind_code: u64,
    signer: String,
    scheme: u64,
    #[serde(deserialize_with = "hex::bytes")]
    event: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    tbs: Vec<u8>,
    #[serde(default, deserialize_with = "optional_hex")]
    ed25519_message: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_hex")]
    mldsa_message: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_hex")]
    mldsa_message_prime: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_hex")]
    ed25519_signature: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_hex")]
    mldsa_signature: Option<Vec<u8>>,
    #[serde(deserialize_with = "hex::bytes")]
    signature: Vec<u8>,
    signature_length: usize,
    #[serde(deserialize_with = "hex::bytes")]
    signed_event: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    event_id: Vec<u8>,
}

fn optional_hex<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|text| hex::decode(&text).map_err(serde::de::Error::custom))
        .transpose()
}

#[test]
fn signatures() {
    let signers = signers();
    let rows: Vec<SignatureRow> = vectors::family(FILE, "signatures");
    assert_eq!(rows.len(), 6);
    for row in &rows {
        let name = format!("{} by {} under scheme {}", row.kind, row.signer, row.scheme);
        let signer = signer(&signers, &row.signer);
        assert_eq!(kind_code(&row.kind), row.kind_code, "{name}");
        let scheme = Scheme::from_code(row.scheme).unwrap();

        // tbs = "frasil/event/v1" || event, and the event names its scheme
        // in key 9: absent for scheme 0, 2 for scheme 2 (events.md).
        assert_eq!(row.tbs, [EVENT, row.event.as_slice()].concat(), "{name}");
        let Value::Map(map) = cbor::decode(&row.event).unwrap() else {
            panic!("{name}: the event is a map");
        };
        let key_9 = map.get(&9).map(|value| value.as_unsigned().unwrap());
        assert_eq!(key_9.unwrap_or(0), row.scheme, "{name}");
        assert_ne!(key_9, Some(0), "{name}");

        // The signature, made again.
        let signature = signer.sign(scheme, &row.tbs);
        assert_eq!(signature, row.signature, "{name}");
        assert_eq!(signature.len(), row.signature_length, "{name}");
        assert_eq!(signature.len(), scheme.signature_bytes(), "{name}");
        if scheme == Scheme::Hybrid {
            let m_ed = hybrid_ed25519_message(signer.identity_key(), &row.tbs);
            let m_ml = hybrid_mldsa_message(signer.identity_key(), signer.mldsa_public(), &row.tbs);
            assert_eq!(Some(&m_ed), row.ed25519_message.as_ref(), "{name}");
            assert_eq!(Some(&m_ml), row.mldsa_message.as_ref(), "{name}");
            assert_eq!(
                Some(&message_prime(&m_ml)),
                row.mldsa_message_prime.as_ref(),
                "{name}"
            );
            assert_eq!(
                Some(&signature[..64].to_vec()),
                row.ed25519_signature.as_ref()
            );
            assert_eq!(
                Some(&signature[64..].to_vec()),
                row.mldsa_signature.as_ref()
            );
        } else {
            assert!(row.ed25519_message.is_none() && row.mldsa_signature.is_none());
        }

        // It verifies, before and after the sunset.
        let policy = KindPolicy::for_kind(row.kind_code).unwrap();
        let signed = Signed {
            scheme: row.scheme,
            ed: signer.identity_key(),
            kc: signer.kc(),
            tbs: &row.tbs,
            signature: &row.signature,
        };
        for sunset in [false, true] {
            let held = Held {
                keys: Some(signer.keys()),
                sunset,
                covered: true,
            };
            assert_eq!(schemes::verify(policy, &signed, &held), Ok(()), "{name}");
        }

        // The signed event is the CBOR array [event, signature], and the ID
        // hashes the unsigned event (events.md).
        let mut signed_event = Vec::new();
        cbor::array_head(&mut signed_event, 2);
        cbor::bytes(&mut signed_event, &row.event);
        cbor::bytes(&mut signed_event, &row.signature);
        assert_eq!(signed_event, row.signed_event, "{name}");
        assert_eq!(
            sha256(&[EVENT_ID, &row.event]).as_slice(),
            row.event_id,
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------
// signature_refusals

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusalRow {
    name: String,
    kind: String,
    scheme: u64,
    #[serde(deserialize_with = "hex::bytes")]
    ed: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    kc: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    author: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    tbs: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    signature: Vec<u8>,
    keys_held: Vec<KeysHeld>,
    sunset: bool,
    covered: bool,
    expected: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysHeld {
    #[serde(deserialize_with = "hex::bytes")]
    mldsa_sha256: Vec<u8>,
    mldsa_length: usize,
    #[serde(default, deserialize_with = "optional_hex")]
    xwing_sha256: Option<Vec<u8>>,
}

/// A pair of keys a case's verifier may hold: an ML-DSA-65 key, of any
/// length, and an X-Wing key.
struct Candidate {
    mldsa: Vec<u8>,
    xwing: Vec<u8>,
}

#[test]
fn signature_refusals() {
    let signers = signers();
    // The keys a case's verifier may hold, found by their hash: each
    // signer's; the laptop's with its ML-DSA-65 key cut by one byte; and a
    // forger's, which reuses the laptop's Ed25519 key beside keys of its own.
    let mut candidates: Vec<Candidate> = signers
        .iter()
        .map(|(_, signer)| Candidate {
            mldsa: signer.mldsa_public().to_vec(),
            xwing: signer.keys().xwing().unwrap().to_vec(),
        })
        .collect();
    let laptop = signer(&signers, "laptop");
    candidates.push(Candidate {
        mldsa: laptop.mldsa_public()[..laptop.mldsa_public().len() - 1].to_vec(),
        xwing: laptop.keys().xwing().unwrap().to_vec(),
    });
    let forger = Signer::from_seeds(
        &signers
            .iter()
            .find(|(row, _)| row.name == "laptop")
            .map(|(row, _)| array(&row.ed25519_seed))
            .unwrap(),
        &sha256(&[b"frasil spec example/crypto/forger/mldsa"]),
        Some(&xwing_public(&sha256(&[
            b"frasil spec example/crypto/forger/xwing",
        ]))),
    );
    assert_eq!(forger.identity_key(), laptop.identity_key());
    assert_ne!(forger.device_id(), laptop.device_id());
    candidates.push(Candidate {
        mldsa: forger.mldsa_public().to_vec(),
        xwing: forger.keys().xwing().unwrap().to_vec(),
    });

    let rows: Vec<RefusalRow> = vectors::family(FILE, "signature_refusals");
    assert_eq!(rows.len(), 29);
    for row in &rows {
        let name = &row.name;
        let ed = IdentityKey(array(&row.ed));
        let kc = KeysCommitment(array(&row.kc));
        assert_eq!(device_id(&ed, &kc), DeviceId(array(&row.author)), "{name}");
        // Every pair the verifier holds; a key that fails its check where it
        // enters is never held (crypto.md, "X-Wing and ML-DSA-65 public
        // keys").
        let held: Vec<HybridKeys> = row
            .keys_held
            .iter()
            .filter_map(|wanted| {
                let candidate = candidates
                    .iter()
                    .find(|c| {
                        sha256(&[&c.mldsa]).as_slice() == wanted.mldsa_sha256.as_slice()
                            && wanted.xwing_sha256.as_deref()
                                == Some(sha256(&[&c.xwing]).as_slice())
                    })
                    .unwrap_or_else(|| panic!("{name}: no keys of that hash"));
                assert_eq!(candidate.mldsa.len(), wanted.mldsa_length, "{name}");
                HybridKeys::new(&candidate.mldsa, Some(&candidate.xwing)).ok()
            })
            .collect();
        let policy = KindPolicy::for_kind(kind_code(&row.kind)).unwrap();
        let signed = Signed {
            scheme: row.scheme,
            ed: &ed,
            kc: &kc,
            tbs: &row.tbs,
            signature: &row.signature,
        };
        let held = Held {
            keys: HybridKeys::find(&kc, &held),
            sunset: row.sunset,
            covered: row.covered,
        };
        let verdict = match schemes::verify(policy, &signed, &held) {
            Ok(()) => "accepted",
            Err(class) => class.name(),
        };
        assert_eq!(verdict, row.expected, "{name}");
    }
}

/// Keys that do not hash to the signer's `kc` are never tried, even when
/// the caller hands them in: the verdict is `NoHybridKey`.
#[test]
fn keys_of_another_commitment_are_not_tried() {
    let signers = signers();
    let laptop = signer(&signers, "laptop");
    let phone = signer(&signers, "phone");
    let tbs = b"frasil/event/v1 example";
    let signature = laptop.sign(Scheme::Hybrid, tbs);
    let signed = Signed {
        scheme: 2,
        ed: laptop.identity_key(),
        kc: laptop.kc(),
        tbs,
        signature: &signature,
    };
    assert_eq!(
        schemes::verify_mldsa_steps(&signed, Some(phone.keys())),
        Err(ErrorClass::NoHybridKey)
    );
    assert_eq!(
        schemes::verify_mldsa_steps(&signed, Some(laptop.keys())),
        Ok(())
    );
}

/// The steps run apart give what `verify` gives: steps 1 to 4 need only the
/// structure, so a stranger's forgery is refused before any ML-DSA-65 key is
/// looked up.
#[test]
fn the_ed25519_half_is_checked_with_no_other_key() {
    let signers = signers();
    let laptop = signer(&signers, "laptop");
    let tbs = b"frasil/event/v1 example";
    let signature = laptop.sign(Scheme::Hybrid, tbs);
    let signed = Signed {
        scheme: 2,
        ed: laptop.identity_key(),
        kc: laptop.kc(),
        tbs,
        signature: &signature,
    };
    assert_eq!(
        schemes::verify_ed25519_steps(KindPolicy::Authority, &signed),
        Ok(Scheme::Hybrid)
    );
    assert_eq!(
        schemes::verify_mldsa_steps(&signed, None),
        Err(ErrorClass::NoHybridKey)
    );
    let mut forged_signature = signature.clone();
    forged_signature[0] ^= 1;
    let forged = Signed {
        signature: &forged_signature,
        ..signed
    };
    assert_eq!(
        schemes::verify(KindPolicy::Authority, &forged, &Held::default()),
        Err(ErrorClass::BadSignature)
    );
    assert_eq!(signature.len(), SCHEME2_SIGNATURE);
}
