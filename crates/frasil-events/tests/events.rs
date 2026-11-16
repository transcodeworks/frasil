//! `events.json`: every family (events.md, "Test vectors").

use frasil_base::errors::Class;
use frasil_crypto::device::{DeviceId, IdentityKey, KeyRing, KeysCommitment};
use frasil_crypto::fixtures::FixtureKeys;
use frasil_crypto::schemes::{Scheme, Signer, hybrid_ed25519_message, hybrid_mldsa_message};
use frasil_crypto::wrap::xwing_public;
use frasil_events::envelope::{self, Envelope, EventId};
use frasil_events::kind;
use frasil_events::{Event, EventClass, Log, Placement, decode, verify_proof};
use frasil_testkit::hex;
use frasil_testkit::vectors;
use serde::Deserialize;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

const FILE: &str = "events.json";

fn id(text: &str) -> EventId {
    EventId(hex::decode_array(text).unwrap())
}

fn class_name(class: EventClass) -> &'static str {
    class.name()
}

/// The signer of a vector device's identity seed: its ML-DSA-65 and X-Wing
/// seeds are crypto.md's fixture derivations from it.
fn signer(seed: &[u8; 32]) -> Signer {
    FixtureKeys::from_identity_seed(seed).signer()
}

/// A ring holding these signers' keys.
fn ring<'a>(signers: impl IntoIterator<Item = &'a Signer>) -> KeyRing {
    let mut ring = KeyRing::new();
    for signer in signers {
        ring.add_keys(signer.keys().clone());
    }
    ring
}

fn identity_seeds() -> BTreeMap<String, [u8; 32]> {
    let parameters: Json = vectors::family(FILE, "parameters");
    seeds(&parameters["identity_seeds"])
}

/// Identity seeds by device name, as the vectors write them.
fn seeds(value: &Json) -> BTreeMap<String, [u8; 32]> {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, seed)| {
            (
                name.clone(),
                hex::decode_array(seed.as_str().unwrap()).unwrap(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// parameters

#[test]
fn parameters() {
    let p: Json = vectors::family(FILE, "parameters");
    assert_eq!(p["envelope_version"], envelope::VERSION);
    let kinds = p["kinds"].as_object().unwrap();
    assert_eq!(kinds.len(), 6);
    for (name, code) in kinds {
        let code = u8::try_from(code.as_u64().unwrap()).unwrap();
        assert!(kind::is_valid(u64::from(code)), "{name}");
        assert!(kind::is_known(code) || kind::is_ignorable(code), "{name}");
        let limits = &p["kind_limits"][name];
        assert_eq!(limits["bytes"], kind::limits(code).bytes, "{name}");
        assert_eq!(limits["parents"], kind::limits(code).parents, "{name}");
    }
    assert_eq!(
        p["must_understand"],
        serde_json::json!([1, kind::LAST_MUST_UNDERSTAND])
    );
    assert_eq!(
        p["ignorable"],
        serde_json::json!([kind::FIRST_IGNORABLE, kind::LAST_IGNORABLE])
    );
    assert_eq!(p["max_signed_event_bytes"], kind::MAX_SIGNED_EVENT_BYTES);
    assert_eq!(p["max_parents"], kind::MAX_PARENTS);
    assert_eq!(p["max_refs"], kind::MAX_REFS);
    assert_eq!(p["signature_bytes"]["0"], Scheme::Ed25519.signature_bytes());
    assert_eq!(p["signature_bytes"]["2"], Scheme::Hybrid.signature_bytes());
    assert_eq!(identity_seeds().len(), 2);
    // Each device's kc and device ID, from its fixture keys.
    for (name, seed) in identity_seeds() {
        let signer = signer(&seed);
        let device = &p["devices"][&name];
        assert_eq!(device["kc"], hex::encode(signer.kc().0), "{name}");
        assert_eq!(
            device["device_id"],
            hex::encode(signer.device_id().0),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------
// encodings

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Encoding {
    name: String,
    kind: u8,
    ed: String,
    kc: String,
    author: String,
    log: Option<String>,
    seq: u64,
    prev: Option<String>,
    parents: Vec<String>,
    body: String,
    scheme: u8,
    event: String,
    signing_input: String,
    signature: String,
    signed: String,
    id: String,
    mldsa_public: Option<String>,
    xwing_public: Option<String>,
    ed25519_message: Option<String>,
    mldsa_message: Option<String>,
}

#[test]
fn encodings() {
    let cases: Vec<Encoding> = vectors::family(FILE, "encodings");
    assert_eq!(cases.len(), 7);
    let signers: BTreeMap<DeviceId, Signer> = identity_seeds()
        .values()
        .map(|seed| {
            let signer = signer(seed);
            (*signer.device_id(), signer)
        })
        .collect();
    for case in &cases {
        let ed = IdentityKey(hex::decode_array(&case.ed).unwrap());
        let kc = KeysCommitment(hex::decode_array(&case.kc).unwrap());
        let author = DeviceId(hex::decode_array(&case.author).unwrap());
        let scheme = match case.scheme {
            0 => Scheme::Ed25519,
            2 => Scheme::Hybrid,
            other => panic!("scheme {other}"),
        };
        let fields = Envelope {
            kind: case.kind,
            log: case.log.as_deref().map(id),
            ed,
            kc,
            seq: case.seq,
            prev: case.prev.as_deref().map(id),
            parents: case.parents.iter().map(|p| id(p)).collect(),
            cuts: Vec::new(),
            body: hex::decode(&case.body).unwrap(),
            scheme,
        };
        let event = fields.encode();
        assert_eq!(hex::encode(&event), case.event, "{}", case.name);
        let tbs = envelope::tbs(&event);
        assert_eq!(hex::encode(&tbs), case.signing_input, "{}", case.name);
        assert_eq!(fields.id(), id(&case.id), "{}", case.name);
        assert_eq!(fields.author(), author, "{}", case.name);
        // Signing reproduces the signature and the signed event.
        let signer = &signers[&author];
        let signed = fields.sign(signer);
        assert_eq!(hex::encode(&signed), case.signed, "{}", case.name);
        assert_eq!(
            hex::encode(envelope::assemble(
                &event,
                &hex::decode(&case.signature).unwrap()
            )),
            case.signed
        );
        // Decoding gives the fields back.
        let decoded = decode(&signed).unwrap();
        let verified = decoded.verify_hybrid(Some(signer.keys())).unwrap();
        assert_eq!(verified.envelope(), &fields, "{}", case.name);
        assert_eq!(hex::encode(decoded.signature()), case.signature);
        assert_eq!(decoded.id(), id(&case.id));
        assert_eq!(decoded.author(), &author);
        match scheme {
            Scheme::Hybrid => {
                let key = case.mldsa_public.as_deref().unwrap();
                assert_eq!(hex::encode(signer.mldsa_public()), key, "{}", case.name);
                assert_eq!(
                    signer.keys().xwing().map(hex::encode).as_deref(),
                    case.xwing_public.as_deref(),
                    "{}",
                    case.name
                );
                assert_eq!(
                    hex::encode(hybrid_ed25519_message(&ed, &tbs)),
                    case.ed25519_message.as_deref().unwrap()
                );
                assert_eq!(
                    hex::encode(hybrid_mldsa_message(&ed, signer.mldsa_public(), &tbs)),
                    case.mldsa_message.as_deref().unwrap()
                );
                assert_eq!(decoded.verified_scheme_0(), None);
            }
            Scheme::Ed25519 => {
                assert!(case.mldsa_public.is_none() && case.ed25519_message.is_none());
                assert!(case.xwing_public.is_none());
                assert!(case.mldsa_message.is_none());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// refusals

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refusal {
    name: String,
    signed: String,
    error: String,
}

#[test]
fn refusals() {
    let cases: Vec<Refusal> = vectors::family(FILE, "refusals");
    assert_eq!(cases.len(), 35);
    let seeds = identity_seeds();
    let founder = signer(&seeds["founder"]);
    let writer = signer(&seeds["writer"]);
    for case in &cases {
        // Section 3.3's checks run with the founder's keys held, the author
        // of every scheme-2 case, except where the case names others.
        let keys = if case.name.contains("author's keys are not held") {
            ring([&writer])
        } else if case
            .name
            .contains("another device's key, under this device's ed and kc")
        {
            ring([&founder, &writer])
        } else {
            ring([&founder])
        };
        let outcome = decode(&hex::decode(&case.signed).unwrap())
            .and_then(|event| event.verify_hybrid_in(&keys));
        let found = outcome.map_or_else(class_name, |_| "accepted");
        assert_eq!(found, case.error, "{}", case.name);
    }
    // Key 7 holds cuts, and cuts that are not event IDs are Malformed.
    let key_7 = cases
        .iter()
        .find(|case| case.name == "envelope key 7, cuts that are not event IDs")
        .expect("the case of key 7");
    assert_eq!(key_7.error, "Malformed");
    let signed = hex::decode(&key_7.signed).unwrap();
    let event = frasil_base::cbor::decode(&signed).unwrap();
    let map = frasil_base::cbor::decode(event.as_array().unwrap()[0].as_bytes().unwrap()).unwrap();
    assert!(map.as_map().unwrap().contains_key(&envelope::KEY_CUTS));
}

// ---------------------------------------------------------------------------
// causal_order

/// The log of the encodings' seven events, placed in the vectors' order.
fn encodings_log() -> (Log, BTreeMap<String, EventId>) {
    let cases: Vec<Encoding> = vectors::family(FILE, "encodings");
    let seeds = identity_seeds();
    let keys: BTreeMap<DeviceId, Signer> = seeds
        .values()
        .map(|seed| {
            let signer = signer(seed);
            (*signer.device_id(), signer)
        })
        .collect();
    let events: Vec<Event> = cases
        .iter()
        .map(|case| decode(&hex::decode(&case.signed).unwrap()).unwrap())
        .collect();
    let mut log = Log::new(events[0].clone()).unwrap();
    for event in &events[1..] {
        assert_eq!(
            log.place(event.clone()),
            Ok(Placement::Placed(vec![event.id()]))
        );
    }
    for event in &events {
        let held = keys[event.author()].keys();
        assert_eq!(
            log.verify_hybrid(event.id(), Some(held)).map(|_| ()),
            Ok(())
        );
    }
    let causal: Json = vectors::family(FILE, "causal_order");
    let names = causal["ids"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| (name.clone(), id(value.as_str().unwrap())))
        .collect();
    (log, names)
}

#[test]
fn causal_order() {
    let causal: Json = vectors::family(FILE, "causal_order");
    let (log, ids) = encodings_log();
    let name_of: BTreeMap<EventId, &str> =
        ids.iter().map(|(name, &id)| (id, name.as_str())).collect();
    assert_eq!(ids.len(), log.len());
    for (name, height) in causal["heights"].as_object().unwrap() {
        assert_eq!(log.height(ids[name]), height.as_u64(), "{name}");
    }
    let names = |list: Vec<EventId>| -> Vec<String> {
        list.iter().map(|id| name_of[id].to_owned()).collect()
    };
    let expected = |key: &str| -> Vec<String> {
        causal[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(names(log.heads()), expected("heads"));
    assert_eq!(names(log.canonical()), expected("canonical_order"));
    let all: BTreeSet<EventId> = ids.values().copied().collect();
    assert!(log.is_closed(&all));
    assert_eq!(names(log.heads_in(&all)), expected("heads"));
    assert_eq!(names(log.canonical_in(&all)), expected("canonical_order"));
    let pairs = causal["pairs"].as_array().unwrap();
    assert_eq!(pairs.len(), 21);
    for pair in pairs {
        let first = ids[pair["first"].as_str().unwrap()];
        let second = ids[pair["second"].as_str().unwrap()];
        let relation = if log.precedes(first, second) {
            "before"
        } else if log.precedes(second, first) {
            "after"
        } else {
            assert!(log.concurrent(first, second));
            "concurrent"
        };
        assert_eq!(relation, pair["relation"], "{pair}");
    }
}

// ---------------------------------------------------------------------------
// chains

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainCase {
    name: String,
    identity_seeds: Json,
    devices: BTreeMap<String, ChainDevice>,
    events: Vec<ChainEvent>,
    evidence: Vec<ChainEvidence>,
    fork_points: BTreeMap<String, u64>,
    void_from_fork: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainDevice {
    mldsa_seed: String,
    xwing_seed: String,
    kc: String,
    device_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainEvent {
    name: String,
    id: String,
    kind: u8,
    author: String,
    seq: u64,
    prev: Option<String>,
    parents: Vec<String>,
    signed: String,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ChainEvidence {
    #[serde(rename = "type")]
    kind: String,
    author: String,
    first: String,
    second: String,
    fork_seq: u64,
}

#[test]
fn chains() {
    let cases: Vec<ChainCase> = vectors::family(FILE, "chains");
    assert_eq!(cases.len(), 10);
    for case in &cases {
        // Each device's signer: its identity seed, with the ML-DSA-65 and
        // X-Wing seeds the case gives. One Ed25519 seed may stand beside
        // two key sets, which are two devices.
        let seeds = seeds(&case.identity_seeds);
        let signers: BTreeMap<&str, Signer> = case
            .devices
            .iter()
            .map(|(name, device)| {
                let signer = Signer::from_seeds(
                    &seeds[name],
                    &hex::decode_array(&device.mldsa_seed).unwrap(),
                    Some(&xwing_public(
                        &hex::decode_array(&device.xwing_seed).unwrap(),
                    )),
                );
                assert_eq!(hex::encode(signer.kc().0), device.kc, "{name}");
                assert_eq!(
                    hex::encode(signer.device_id().0),
                    device.device_id,
                    "{name}"
                );
                (name.as_str(), signer)
            })
            .collect();
        let events: Vec<Event> = case
            .events
            .iter()
            .map(|e| decode(&hex::decode(&e.signed).unwrap()).unwrap())
            .collect();
        let mut names: BTreeMap<EventId, &str> = BTreeMap::new();
        let mut authors: BTreeMap<DeviceId, &str> = BTreeMap::new();
        for (entry, event) in case.events.iter().zip(&events) {
            assert_eq!(event.id(), id(&entry.id), "{}", case.name);
            assert_eq!((event.kind(), event.seq()), (entry.kind, entry.seq));
            names.insert(event.id(), &entry.name);
            authors.insert(*event.author(), &entry.author);
        }
        for (entry, event) in case.events.iter().zip(&events) {
            assert_eq!(event.prev().map(|p| names[&p]), entry.prev.as_deref());
            let parents: Vec<&str> = event.parents().iter().map(|p| names[p]).collect();
            assert_eq!(parents, entry.parents, "{}", case.name);
        }
        // The events arrive in canonical order, so each is placed at once.
        let mut log = Log::new(events[0].clone()).unwrap();
        for event in &events[1..] {
            assert_eq!(
                log.place(event.clone()),
                Ok(Placement::Placed(vec![event.id()]))
            );
        }
        // Each device's keys give the author the events name.
        for (entry, event) in case.events.iter().zip(&events) {
            let signer = &signers[entry.author.as_str()];
            assert_eq!(signer.device_id(), event.author(), "{}", case.name);
            assert_eq!(signer.identity_key(), event.ed(), "{}", case.name);
        }
        // Every signature verifies: the genesis is a scheme-2 space event of
        // the history's device "p".
        let held = ring(signers.values());
        assert_eq!(log.verify_pending_hybrid(&held), vec![events[0].id()]);
        assert!(events.iter().all(|e| log.is_verified(e.id())));

        let found: Vec<ChainEvidence> = log
            .evidence(|_| true)
            .iter()
            .map(|e| ChainEvidence {
                kind: match e.kind {
                    frasil_events::EvidenceKind::Duplicate => "duplicate",
                    frasil_events::EvidenceKind::Skip => "skip",
                }
                .to_owned(),
                author: authors[&e.author].to_owned(),
                first: names[&e.first].to_owned(),
                second: names[&e.second].to_owned(),
                fork_seq: e.fork_seq,
            })
            .collect();
        assert_eq!(found, case.evidence, "{}", case.name);
        let points = log.fork_points(|_| true);
        let points_named: BTreeMap<String, u64> = points
            .iter()
            .map(|(author, point)| (authors[author].to_owned(), point))
            .collect();
        assert_eq!(points_named, case.fork_points, "{}", case.name);
        let mut void: Vec<String> = log
            .events()
            .filter(|e| points.is_void(e))
            .map(|e| names[&e.id()].to_owned())
            .collect();
        void.sort();
        assert_eq!(void, case.void_from_fork, "{}", case.name);

        // Each piece of evidence makes a proof that shows the same fork.
        for evidence in log.evidence(|_| true) {
            let proof = log.proof(&evidence).unwrap();
            let shown = verify_proof(&proof, &()).unwrap();
            assert_eq!(shown.author, evidence.author);
            assert_eq!(shown.log, log.id());
            assert_eq!(shown.fork_seq, evidence.fork_seq);
        }
    }
}

// ---------------------------------------------------------------------------
// equivocation_proofs

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofCase {
    name: String,
    identity_seeds: Json,
    proof: String,
    author: Option<String>,
    log: Option<String>,
    fork_seq: Option<u64>,
    error: Option<String>,
}

#[test]
fn equivocation_proofs() {
    let cases: Vec<ProofCase> = vectors::family(FILE, "equivocation_proofs");
    assert_eq!(cases.len(), 7);
    for case in &cases {
        // Every event of these proofs is a scheme-0 unit: no ML-DSA-65 key
        // is needed.
        match verify_proof(&hex::decode(&case.proof).unwrap(), &()) {
            Ok(shown) => {
                assert_eq!(case.error, None, "{}", case.name);
                // The forking device is the history's "x", a fixture device.
                let x = signer(&seeds(&case.identity_seeds)["x"]);
                assert_eq!(&shown.author, x.device_id(), "{}", case.name);
                assert_eq!(Some(hex::encode(shown.author.0)), case.author);
                assert_eq!(Some(hex::encode(shown.log.0)), case.log);
                assert_eq!(Some(shown.fork_seq), case.fork_seq, "{}", case.name);
            }
            Err(class) => {
                assert_eq!(Some(class.name()), case.error.as_deref(), "{}", case.name);
                assert!(case.author.is_none() && case.fork_seq.is_none());
            }
        }
    }
}
