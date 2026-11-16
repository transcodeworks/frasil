//! `ext-app-requests.json`, every family (ext-app-requests.md): the
//! parameters, the lists, signed requests and their refusals, list
//! deliveries, heads, and what a lenient verifier would accept.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use frasil_app_requests::delivery::{
    DELIVERY_CONTENT_TYPE, DELIVERY_METHOD, DELIVERY_PATH, DELIVERY_STATUS, DELIVERY_VERSION,
    MAX_DELIVERY_EVENTS, encode_delivery, place_events,
};
use frasil_app_requests::headers::{LIST_NEEDED, LIST_NEEDED_VALUE};
use frasil_app_requests::statement::{self, *};
use frasil_app_requests::{
    AGENT_WAITING_PERIOD, AppRequestClass, Code, Header, HeldList, MemoryNonceStore, MemoryState,
    NonceStore, ReceivedHeaders, Refusal, Request, SIGNED_REQUEST_LIFETIME, SIGNED_REQUEST_SKEW,
    Verified, Verifier, VerifierState, heads_to_send, sign,
};
use frasil_base::errors::Class;
use frasil_crypto::device::{IdentityKey, KeysCommitment, Signatory};
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::labels::DEVICE_SIGNED_REQUEST;
use frasil_crypto::primitives::{ed25519_public, sha256};
use frasil_crypto::schemes::ed25519_verify_strict;
use frasil_events::{EventId, decode};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha512};
use std::collections::{BTreeMap, BTreeSet};

const FILE: &str = "ext-app-requests.json";
const SUBJECT: &str = "example-subject";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn unhex(text: &str) -> Vec<u8> {
    frasil_testkit::hex::decode(text).unwrap_or_else(|error| panic!("{text}: {error}"))
}

fn bytes(value: &Json, key: &str) -> Vec<u8> {
    unhex(
        value[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} is not a string")),
    )
}

fn array<const N: usize>(value: &Json, key: &str) -> [u8; N] {
    bytes(value, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is not {N} bytes"))
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn u64_of(value: &Json, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not a number"))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    frasil_testkit::hex::encode(bytes)
}

/// The lists family: the person's events and the other person's, by name.
struct Lists {
    json: Json,
    person_id: [u8; 32],
    other_id: [u8; 32],
}

impl Lists {
    fn load() -> Self {
        let json = family("lists");
        let person_id = array(&json, "person_id");
        let other_id = array(&json["other_person"], "person_id");
        Self {
            json,
            person_id,
            other_id,
        }
    }

    fn signed(&self, name: &str) -> Vec<u8> {
        let row = self.json["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| text(row, "name") == name)
            .unwrap_or_else(|| panic!("no event {name}"));
        bytes(row, "signed")
    }

    fn view(&self, view: &str) -> Vec<Vec<u8>> {
        self.json["views"][view]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| self.signed(name.as_str().unwrap()))
            .collect()
    }

    fn other(&self) -> Vec<Vec<u8>> {
        self.json["other_person"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| bytes(row, "signed"))
            .collect()
    }

    fn seed(&self, name: &str) -> [u8; 32] {
        array(&self.json["keys"][name], "signing_seed")
    }

    /// The list member's keys commitment.
    fn kc(&self, name: &str) -> KeysCommitment {
        KeysCommitment(array(&self.json["keys"][name], "kc"))
    }

    /// The list member's `ed || kc`.
    fn signer(&self, name: &str) -> Signatory {
        Signatory {
            ed: IdentityKey(ed25519_public(&self.seed(name))),
            kc: self.kc(name),
        }
    }

    /// The verifier's state a vector names, and whether it keeps nonces.
    fn state(&self, state: &Json) -> (MemoryState, bool) {
        let mut out = MemoryState::new();
        if let Some(subject) = state["recorded_person"].as_str() {
            out.record_person(subject.as_bytes(), self.person_id);
        }
        if let Some(view) = state["view"].as_str() {
            let at = u64_of(state, "first_seen_at");
            let placed = place_events(&mut out, &self.person_id, &self.view(view), at).unwrap();
            assert_eq!(placed.placed, self.view(view).len(), "{view}");
            if state["other_person"].as_bool().unwrap() {
                place_events(&mut out, &self.other_id, &self.other(), at).unwrap();
            }
        }
        (out, state["nonce_store"].as_bool().unwrap())
    }
}

/// A request's parts, owned.
struct Parts {
    audience: String,
    subject: Vec<u8>,
    method: String,
    path: String,
    query: String,
    body: Vec<u8>,
}

impl Parts {
    fn of(request: &Json) -> Self {
        Self {
            audience: text(request, "audience").to_string(),
            subject: bytes(request, "subject_hex"),
            method: text(request, "method").to_string(),
            path: text(request, "path").to_string(),
            query: text(request, "query").to_string(),
            body: bytes(request, "body_hex"),
        }
    }

    fn request(&self) -> Request<'_> {
        Request {
            audience: &self.audience,
            subject: &self.subject,
            method: &self.method,
            path: &self.path,
            query: &self.query,
            body: &self.body,
        }
    }
}

/// The header values a vector gives: `null` for absent, a string, or a list
/// of the values a repeated header arrived with.
fn header_pairs(headers: &Json) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (name, value) in headers.as_object().unwrap() {
        match value {
            Json::Null => {}
            Json::String(value) => out.push((name.clone(), value.as_bytes().to_vec())),
            Json::Array(values) => {
                for value in values {
                    out.push((name.clone(), value.as_str().unwrap().as_bytes().to_vec()));
                }
            }
            other => panic!("{name}: {other}"),
        }
    }
    out
}

fn received(pairs: &[(String, Vec<u8>)]) -> ReceivedHeaders<'_> {
    ReceivedHeaders::from_pairs(
        pairs
            .iter()
            .map(|(name, value)| (name.as_str(), &value[..])),
    )
}

fn verified_json(verified: &Verified) -> Json {
    json!({
        "device": hex(verified.device.0),
        "person_id": hex(verified.person_id),
        "kind": verified.kind.name(),
        "expires_at": verified.expires_at,
        "list_needed": verified.list_needed,
        "recorded_person": verified.recorded_person,
    })
}

fn refusal_json(refusal: Refusal) -> Json {
    json!({
        "class": refusal.name(),
        "status": refusal.code().status(),
        "code": refusal.code().as_str(),
    })
}

fn expected_refusal(row: &Json) -> Json {
    json!({"class": row["class"], "status": row["status"], "code": row["code"]})
}

/// Verifies a vector's headers and request on `state` at `now`.
fn verify(
    headers: &Json,
    request: &Json,
    state: &mut MemoryState,
    nonces: Option<&mut dyn NonceStore>,
    now: u64,
) -> Result<Verified, Refusal> {
    let pairs = header_pairs(headers);
    let parts = Parts::of(request);
    Verifier::default().verify(
        &received(&pairs),
        &parts.request(),
        state,
        nonces,
        Some(now),
    )
}

#[test]
fn parameters() {
    let p = family("parameters");
    assert_eq!(text(&p, "label").as_bytes(), DEVICE_SIGNED_REQUEST);
    assert_eq!(statement::LABEL, DEVICE_SIGNED_REQUEST);
    assert_eq!(u64_of(&p, "version_byte"), u64::from(VERSION));
    assert_eq!(u64_of(&p, "scheme_byte"), u64::from(SCHEME));
    assert_eq!(
        u64_of(&p, "signed_request_lifetime"),
        SIGNED_REQUEST_LIFETIME
    );
    assert_eq!(u64_of(&p, "signed_request_skew"), SIGNED_REQUEST_SKEW);
    assert_eq!(u64_of(&p, "agent_waiting_period"), AGENT_WAITING_PERIOD);
    let sizes = [
        ("nonce_bytes", NONCE_BYTES),
        ("max_heads", MAX_HEADS),
        ("min_audience_bytes", MIN_AUDIENCE_BYTES),
        ("max_audience_bytes", MAX_AUDIENCE_BYTES),
        ("max_subject_bytes", MAX_SUBJECT_BYTES),
        ("max_method_bytes", MAX_METHOD_BYTES),
        ("max_path_bytes", MAX_PATH_BYTES),
        ("max_query_bytes", MAX_QUERY_BYTES),
    ];
    for (key, value) in sizes {
        assert_eq!(u64_of(&p, key), value as u64, "{key}");
    }
    let delivery = &p["list_delivery"];
    assert_eq!(u64_of(delivery, "version"), DELIVERY_VERSION);
    assert_eq!(text(delivery, "method"), DELIVERY_METHOD);
    assert_eq!(text(delivery, "path"), DELIVERY_PATH);
    assert_eq!(text(delivery, "content_type"), DELIVERY_CONTENT_TYPE);
    assert_eq!(u64_of(delivery, "max_events"), MAX_DELIVERY_EVENTS as u64);
    let headers: Vec<Json> = Header::ALL
        .iter()
        .map(|h| json!({"name": h.name(), "max_bytes": h.max_bytes(), "required": h.required()}))
        .collect();
    assert_eq!(p["headers"], Json::Array(headers));
    let codes = p["codes"].as_object().unwrap();
    for (class, code) in codes {
        let class = AppRequestClass::from_name(class).unwrap_or_else(|| panic!("{class}"));
        let ours = Code::of(class);
        assert_eq!(
            json!({"status": ours.status(), "code": ours.as_str()}),
            *code,
            "{}",
            class.name()
        );
    }
    let own: BTreeSet<&str> = AppRequestClass::OWN.iter().map(|c| c.name()).collect();
    assert!(own.iter().all(|name| codes.contains_key(*name)));
    let expiry = Code::SignatureExpired;
    assert_eq!(
        p["check_expiry_code"],
        json!({"status": expiry.status(), "code": expiry.as_str()})
    );
    let lengths = &p["statement_bytes_in_vectors"];
    assert_eq!(u64_of(lengths, "most"), MAX_STATEMENT_BYTES as u64);
    let least = family("requests")
        .as_array()
        .unwrap()
        .iter()
        .map(|row| bytes(row, "statement").len())
        .min()
        .unwrap();
    assert_eq!(u64_of(lengths, "least"), least as u64);
}

#[test]
fn lists() {
    let lists = Lists::load();
    let keys = lists.json["keys"].as_object().unwrap();
    let mut names = BTreeMap::new();
    for (name, key) in keys {
        let seed = array(key, "signing_seed");
        assert_eq!(
            ed25519_public(&seed),
            array::<32>(key, "identity"),
            "{name}"
        );
        let device = lists.signer(name).device_id();
        assert_eq!(device.0, array::<32>(key, "device_id"), "{name}");
        names.insert(device, name.clone());
    }
    for (person, rows) in [
        (lists.person_id, &lists.json["events"]),
        (lists.other_id, &lists.json["other_person"]["events"]),
    ] {
        for row in rows.as_array().unwrap() {
            let event = decode(&bytes(row, "signed")).unwrap();
            assert_eq!(
                event.id().0,
                array::<32>(row, "id"),
                "{}",
                text(row, "name")
            );
            assert_eq!(event.log_id().0, person);
            assert_eq!(names[event.author()], text(row, "author"));
        }
    }
    for (view, expected) in lists.json["views"].as_object().unwrap() {
        let mut state = MemoryState::new();
        place_events(&mut state, &lists.person_id, &lists.view(view), 0).unwrap();
        let held = state.list(&lists.person_id).unwrap();
        let heads: Vec<String> = heads_to_send(held.list())
            .iter()
            .map(|h| hex(h.0))
            .collect();
        let expected_heads: Vec<&str> = expected["heads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap())
            .collect();
        assert_eq!(heads, expected_heads, "{view}");
        // Every event of the view is placed, and none is void but by the
        // merge's own rules.
        assert_eq!(held.list().log().len(), lists.view(view).len(), "{view}");
        assert_eq!(held.events().len(), held.list().log().len());
    }
    let mut state = MemoryState::new();
    place_events(&mut state, &lists.other_id, &lists.other(), 0).unwrap();
    assert_eq!(
        state.list(&lists.other_id).unwrap().person_id(),
        lists.other_id
    );
}

#[test]
fn requests() {
    let lists = Lists::load();
    let rows = family("requests");
    assert!(!rows.as_array().unwrap().is_empty());
    for row in rows.as_array().unwrap() {
        let name = text(row, "name");
        let parts = Parts::of(&row["request"]);
        let request = parts.request();
        let signer = Signatory::from_bytes(&bytes(row, "signer_ed_kc")).unwrap();
        assert_eq!(signer, lists.signer(text(row, "signer")), "{name}");
        assert_eq!(
            signer.device_id().0,
            array::<32>(row, "device_id"),
            "{name}"
        );
        let person_id: [u8; 32] = array(row, "person_id");
        let nonce: [u8; 16] = array(row, "nonce");
        let expires_at = u64_of(row, "expires_at");
        let heads: Vec<EventId> = row["heads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| EventId(unhex(h.as_str().unwrap()).try_into().unwrap()))
            .collect();
        assert_eq!(
            sha256(&[request.body]),
            array::<32>(row, "body_sha256"),
            "{name}"
        );

        // The statement, field by field.
        let ours =
            statement_parts(&request, &person_id, &signer, expires_at, &nonce, &heads).unwrap();
        let fields = row["statement_fields"].as_object().unwrap();
        assert_eq!(ours.len(), fields.len(), "{name}");
        for (part, value) in &ours {
            assert_eq!(
                hex(value),
                text(&row["statement_fields"], part),
                "{name}: {part}"
            );
        }
        let whole = statement(&request, &person_id, &signer, expires_at, &nonce, &heads);
        assert_eq!(whole.unwrap(), bytes(row, "statement"), "{name}");

        // Signing gives the signature and the six header values.
        let seed = lists.seed(text(row, "signer"));
        let signed_at = u64_of(row, "signed_at");
        let signed = sign(
            &seed, &signer.kc, &request, &person_id, signed_at, nonce, &heads,
        )
        .unwrap();
        assert_eq!(signed.signer, signer, "{name}");
        assert_eq!(signed.expires_at, expires_at, "{name}");
        assert_eq!(
            &signed.signature[..],
            &bytes(row, "signature")[..],
            "{name}"
        );
        let values: Vec<Json> = Header::ALL
            .iter()
            .map(|&h| signed.value(h).map_or(Json::Null, Json::String))
            .collect();
        let expected: Vec<Json> = Header::ALL
            .iter()
            .map(|h| row["headers"][h.name()].clone())
            .collect();
        assert_eq!(values, expected, "{name}");

        // Accepted at its signing time and at both edges of the window.
        for now in row["accepted_at"].as_array().unwrap() {
            let now = now.as_u64().unwrap();
            let (mut state, nonce_store) = lists.state(&row["state"]);
            assert!(!nonce_store);
            let verified = verify(&row["headers"], &row["request"], &mut state, None, now)
                .unwrap_or_else(|refusal| panic!("{name} at {now}: {}", refusal.name()));
            assert_eq!(verified_json(&verified), row["verified"], "{name} at {now}");
            assert_eq!(state.recorded_person(&parts.subject), Some(person_id));
        }
        // Refused, as expired, outside it.
        let window = row["accepted_at"].as_array().unwrap();
        for now in [window[0].as_u64().unwrap() - 1, expires_at + 1] {
            let (mut state, _) = lists.state(&row["state"]);
            let refusal =
                verify(&row["headers"], &row["request"], &mut state, None, now).unwrap_err();
            assert_eq!(refusal.code(), Code::SignatureExpired, "{name} at {now}");
        }
    }
}

#[test]
fn request_refusals() {
    let lists = Lists::load();
    let rows = family("request_refusals");
    assert!(!rows.as_array().unwrap().is_empty());
    for row in rows.as_array().unwrap() {
        let name = text(row, "name");
        let (mut state, nonce_store) = lists.state(&row["state"]);
        let mut store = MemoryNonceStore::new();
        if nonce_store {
            let first = &row["first"];
            let verified = verify(
                &row["headers"],
                &row["request"],
                &mut state,
                Some(&mut store),
                u64_of(first, "now"),
            )
            .unwrap_or_else(|refusal| panic!("{name}, first: {}", refusal.name()));
            assert_eq!(verified_json(&verified), first["verified"], "{name}");
        }
        let nonces = nonce_store.then_some(&mut store as &mut dyn NonceStore);
        let result = verify(
            &row["headers"],
            &row["request"],
            &mut state,
            nonces,
            u64_of(row, "now"),
        );
        let refusal = result
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(refusal_json(refusal), expected_refusal(row), "{name}");
    }
}

#[test]
fn list_deliveries() {
    let lists = Lists::load();
    let rows = family("list_deliveries");
    assert!(!rows.as_array().unwrap().is_empty());
    for row in rows.as_array().unwrap() {
        let name = text(row, "name");
        let now = u64_of(row, "now");
        let (mut state, _) = lists.state(&row["state"]);

        let first = &row["first"];
        let refusal =
            verify(&first["headers"], &first["request"], &mut state, None, now).unwrap_err();
        assert_eq!(refusal_json(refusal), expected_refusal(first), "{name}");
        assert!(refusal.code().asks_for_list());
        assert_eq!(
            first["response_header"],
            json!({LIST_NEEDED: LIST_NEEDED_VALUE})
        );

        let delivery = &row["list_delivery"];
        let verified = verify(
            &delivery["headers"],
            &delivery["request"],
            &mut state,
            None,
            now,
        )
        .unwrap_or_else(|refusal| panic!("{name}, list delivery: {}", refusal.name()));
        assert_eq!(verified_json(&verified), delivery["verified"], "{name}");
        assert_eq!(u64_of(delivery, "status"), u64::from(DELIVERY_STATUS));
        let placed = verified.delivery.expect("a list delivery");
        let events = delivery["events"].as_array().unwrap();
        assert_eq!(placed.placed, events.len());
        assert!(placed.fork_detected.is_empty());
        let held = state.list(&lists.person_id).unwrap();
        for id in events {
            let id = EventId(unhex(id.as_str().unwrap()).try_into().unwrap());
            assert!(held.holds(id));
            assert_eq!(held.first_seen(id), Some(now));
        }

        let retry = &row["retry"];
        let verified = verify(&retry["headers"], &retry["request"], &mut state, None, now)
            .unwrap_or_else(|refusal| panic!("{name}, retry: {}", refusal.name()));
        assert_eq!(verified_json(&verified), retry["verified"], "{name}");

        let held = state.list(&lists.person_id).unwrap();
        let mut afterwards: Vec<Vec<u8>> = held.events().into_iter().map(|(e, _)| e).collect();
        let mut expected = lists.view(text(row, "held_afterwards"));
        afterwards.sort();
        expected.sort();
        assert_eq!(afterwards, expected, "{name}");
    }
}

#[test]
fn heads() {
    let lists = Lists::load();
    let rows = family("heads");
    assert!(!rows.as_array().unwrap().is_empty());
    for row in rows.as_array().unwrap() {
        let name = text(row, "name");
        let (mut state, _) = lists.state(&row["state"]);
        let verified = verify(
            &row["headers"],
            &row["request"],
            &mut state,
            None,
            u64_of(row, "now"),
        )
        .unwrap_or_else(|refusal| panic!("{name}: {}", refusal.name()));
        assert_eq!(verified_json(&verified), row["verified"], "{name}");
        assert!(verified.list_needed);
        assert_eq!(
            row["response_header"],
            json!({LIST_NEEDED: LIST_NEEDED_VALUE})
        );
    }
}

/// RFC 8032's verification with the cofactorless equation, `S < ℓ` and no
/// other refusal: `R` compared as bytes with the re-encoded point, `A`
/// decoded as sent.
fn verify_lenient(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let (r, s) = signature.split_at(32);
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s.try_into().unwrap()))
    else {
        return false;
    };
    let Some(a) = CompressedEdwardsY(*public).decompress() else {
        return false;
    };
    let mut hash = Sha512::new();
    hash.update(r);
    hash.update(public);
    hash.update(message);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash.finalize());
    let k = Scalar::from_bytes_mod_order_wide(&wide);
    let check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-a), &s);
    check.compress().as_bytes() == r
}

#[test]
fn lenient_verifier_would_accept() {
    let expected = family("lenient_verifier_would_accept");
    let request = &family("requests")[0];
    let message = bytes(request, "statement");
    let laptop: [u8; 32] = bytes(request, "signer_ed_kc")[..32].try_into().unwrap();
    let refusals = family("request_refusals");
    let refusal = |name: &str| -> ([u8; 32], [u8; 64]) {
        let row = refusals
            .as_array()
            .unwrap()
            .iter()
            .find(|row| text(row, "name") == name)
            .unwrap_or_else(|| panic!("no refusal {name}"));
        let headers = &row["headers"];
        let signature = unhex(text(headers, Header::Signature.name()));
        let key = unhex(text(headers, Header::Device.name()));
        (
            key[..32].try_into().unwrap(),
            signature[2..].try_into().unwrap(),
        )
    };
    let small_r = refusal("an R of small order, made by the key's holder");
    let non_canonical_r = refusal("a non-canonical R");
    let small_key = refusal("a key of small order, with a signature that fits every statement");
    assert_eq!(small_r.0, laptop);
    assert_eq!(non_canonical_r.0, laptop);
    for (case, (key, signature)) in [
        ("small_order_r", small_r),
        ("non_canonical_r", non_canonical_r),
        ("small_order_key", small_key),
    ] {
        let lenient = verify_lenient(&key, &message, &signature);
        assert_eq!(Json::Bool(lenient), expected[case], "{case}");
        // The strict checks refuse each one.
        assert!(
            ed25519_valid(&key).is_err() || !ed25519_verify_strict(&key, &message, &signature),
            "{case}"
        );
    }
}

// ---------------------------------------------------------------------------
// Beyond the vectors.

#[test]
fn a_held_list_restores_from_what_it_keeps() {
    let lists = Lists::load();
    let mut state = MemoryState::new();
    place_events(&mut state, &lists.person_id, &lists.view("full"), 7).unwrap();
    let held = state.list(&lists.person_id).unwrap();
    let kept = held.events();
    let restored = HeldList::restore(kept.iter().map(|(signed, at)| (&signed[..], *at))).unwrap();
    assert_eq!(restored.events(), kept);
    assert_eq!(restored.person_id(), lists.person_id);
    let laptop = lists.signer("laptop").device_id();
    assert_eq!(
        restored.signer(&laptop, 7, Some(AGENT_WAITING_PERIOD)),
        held.signer(&laptop, 7, Some(AGENT_WAITING_PERIOD))
    );
    // Without its first event, a list does not restore.
    let rest = kept[1..].iter().map(|(signed, at)| (&signed[..], *at));
    assert_eq!(
        HeldList::restore(rest).unwrap_err(),
        AppRequestClass::BadListDelivery
    );
}

#[test]
fn a_delivery_without_the_first_event_places_nothing_and_waits() {
    let lists = Lists::load();
    let full = lists.view("full");
    let mut state = MemoryState::new();
    let placed = place_events(&mut state, &lists.person_id, &full[1..], 0).unwrap();
    assert_eq!(placed.placed, 0);
    assert!(state.list(&lists.person_id).is_none());
    // Events whose parents are missing wait, and are placed when they come.
    let placed = place_events(&mut state, &lists.person_id, &full[..1], 0).unwrap();
    assert_eq!(placed.placed, 1);
    let mut reversed = full[1..].to_vec();
    reversed.reverse();
    let placed = place_events(&mut state, &lists.person_id, &reversed, 5).unwrap();
    assert_eq!(placed.placed, full.len() - 1);
    // A list only grows: delivering it again places nothing new.
    let placed = place_events(&mut state, &lists.person_id, &full, 9).unwrap();
    assert_eq!(placed.placed, 0);
    let held = state.list(&lists.person_id).unwrap();
    assert!(held.events().iter().all(|(_, at)| *at <= 5));
}

#[test]
fn a_delivery_for_another_person_than_the_subjects_stores_nothing() {
    let lists = Lists::load();
    let mut state = MemoryState::new();
    state.record_person(SUBJECT.as_bytes(), lists.person_id);
    let body = encode_delivery(&lists.other());
    let request = Request {
        audience: "https://api.example.com",
        subject: SUBJECT.as_bytes(),
        method: DELIVERY_METHOD,
        path: DELIVERY_PATH,
        query: "",
        body: &body,
    };
    let heads = [EventId(lists.other_id)];
    let signed = sign(
        &lists.seed("stranger"),
        &lists.kc("stranger"),
        &request,
        &lists.other_id,
        100,
        [9; 16],
        &heads,
    )
    .unwrap();
    let pairs: Vec<(String, Vec<u8>)> = signed
        .values()
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.into_bytes()))
        .collect();
    let refusal = Verifier::default()
        .verify(&received(&pairs), &request, &mut state, None, Some(100))
        .unwrap_err();
    assert_eq!(refusal.class(), AppRequestClass::WrongPerson);
    assert!(state.list(&lists.other_id).is_none());
    // With the record cleared, the same delivery places the other person's
    // list and records the other person.
    state.clear_record(SUBJECT.as_bytes());
    let verified = Verifier::default()
        .verify(&received(&pairs), &request, &mut state, None, Some(100))
        .unwrap();
    assert!(verified.recorded_person);
    assert_eq!(verified.delivery.unwrap().placed, 1);
    assert_eq!(
        state.recorded_person(SUBJECT.as_bytes()),
        Some(lists.other_id)
    );
}

#[test]
fn a_stateless_verifier_runs_a_replay_again() {
    let lists = Lists::load();
    let row = &family("requests")[0];
    let (mut state, _) = lists.state(&row["state"]);
    let now = u64_of(row, "signed_at");
    for _ in 0..2 {
        verify(&row["headers"], &row["request"], &mut state, None, now).unwrap();
    }
    // A stateful verifier keeps the nonce until expires_at + skew, then
    // forgets it; by then check_expiry refuses the request.
    let mut store = MemoryNonceStore::new();
    verify(
        &row["headers"],
        &row["request"],
        &mut state,
        Some(&mut store),
        now,
    )
    .unwrap();
    store.prune(u64_of(row, "expires_at") + SIGNED_REQUEST_SKEW + 1);
    assert!(store.is_empty());
}

#[test]
fn a_verifier_without_the_recovery_agent_waits_for_a_confirm() {
    let lists = Lists::load();
    let row = family("requests")
        .as_array()
        .unwrap()
        .iter()
        .find(|row| text(row, "signer") == "helped")
        .unwrap()
        .clone();
    let (mut state, _) = lists.state(&row["state"]);
    let pairs = header_pairs(&row["headers"]);
    let parts = Parts::of(&row["request"]);
    let verifier = Verifier {
        agent_waiting_period: None,
    };
    let now = Some(u64_of(&row, "signed_at"));
    let refusal = verifier
        .verify(&received(&pairs), &parts.request(), &mut state, None, now)
        .unwrap_err();
    assert_eq!(refusal.class(), AppRequestClass::NotASigner);
    // An unknown wall clock is Expired, told as signature_expired.
    let refusal = Verifier::default()
        .verify(&received(&pairs), &parts.request(), &mut state, None, None)
        .unwrap_err();
    assert_eq!(refusal.name(), "Expired");
    assert_eq!(refusal.code(), Code::SignatureExpired);
}

#[test]
fn a_signer_refuses_values_outside_their_shapes() {
    let request = Request::from_target(
        "https://api.example.com",
        b"s",
        "GET",
        "/v1/projects?limit=10",
        b"",
    );
    assert_eq!((request.path, request.query), ("/v1/projects", "limit=10"));
    let (a, b) = (EventId([1; 32]), EventId([2; 32]));
    assert!(
        sign(
            &[1; 32],
            &KeysCommitment([2; 32]),
            &request,
            &[0; 32],
            0,
            [0; 16],
            &[a, b]
        )
        .is_ok()
    );
    let malformed = Err(frasil_base::ErrorClass::Malformed);
    assert_eq!(
        sign(
            &[1; 32],
            &KeysCommitment([2; 32]),
            &request,
            &[0; 32],
            0,
            [0; 16],
            &[b, a]
        ),
        malformed
    );
    assert_eq!(
        sign(
            &[1; 32],
            &KeysCommitment([2; 32]),
            &request,
            &[0; 32],
            u64::MAX,
            [0; 16],
            &[]
        ),
        malformed
    );
    let lower = Request {
        method: "get",
        ..request
    };
    assert_eq!(
        sign(
            &[1; 32],
            &KeysCommitment([2; 32]),
            &lower,
            &[0; 32],
            0,
            [0; 16],
            &[]
        ),
        malformed
    );
}
