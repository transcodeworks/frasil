//! admission.json's `parameters`, `transcript`, `negative` and
//! `exchange_mailbox` families (admission.md, sections 2.2 to 2.8, 3.1, 3.2
//! and 3.6).

mod common;

use common::*;
use frasil_admission::approver::ApproverSide;
use frasil_admission::joiner::JoinerKeys;
use frasil_admission::mailbox::{ExchangeMailboxes, exchange_address};
use frasil_admission::message::{MessageType, message, seal_info, sealed_message_with};
use frasil_admission::offer::read_offer;
use frasil_admission::params::*;
use frasil_admission::qr::AdmitQr;
use frasil_admission::transcript::{Code, JFields, JoinerPart, code_hash, heads_hash};
use frasil_admission::{Approver, Ctx, JoinerType, MessageType as Type, Offer, bodies};
use frasil_base::cbor::{Map, Value};
use frasil_base::errors::Class;
use frasil_crypto::wrap::xwing_public;
use frasil_events::EventId;
use frasil_space::{Capability, CapabilityMode, HistoryMode, Level};
use serde_json::Value as Json;

#[test]
fn parameters() {
    let p = family("parameters");
    assert_eq!(p["ctx"]["device list"], u64::from(Ctx::DeviceList.code()));
    assert_eq!(p["ctx"]["space"], u64::from(Ctx::Space.code()));
    assert_eq!(
        p["joiner_type"]["device"],
        u64::from(JoinerType::Device.code())
    );
    assert_eq!(
        p["joiner_type"]["person"],
        u64::from(JoinerType::Person.code())
    );
    let types = p["message_types"].as_object().unwrap();
    assert_eq!(types.len(), MessageType::ALL.len());
    for kind in MessageType::ALL {
        assert_eq!(
            types[kind.name()],
            u64::from(kind.code()),
            "{}",
            kind.name()
        );
    }
    assert_eq!(p["admission_code_lifetime"], ADMISSION_CODE_LIFETIME);
    assert_eq!(p["admission_code_skew"], ADMISSION_CODE_SKEW);
    assert_eq!(
        p["exchange_mailbox_lifetime"],
        format!("expires_at + {MAILBOX_GRACE}")
    );
    let s = &p["sizes"];
    let pairs: [(&str, usize); 14] = [
        ("request", REQUEST_BYTES),
        ("nonce", NONCE_BYTES),
        ("commitment", 32),
        ("ephemeral_key", frasil_crypto::sizes::XWING_PUBLIC),
        ("possession", frasil_crypto::sizes::SCHEME2_SIGNATURE),
        ("sealed_body_minimum", SEALED_MINIMUM),
        ("request_and_cancel_messages", MAX_REQUEST_MESSAGE),
        ("other_messages", MAX_MESSAGE),
        ("setup_code", SETUP_CODE_BYTES),
        ("setup_secret", SETUP_SECRET_BYTES),
        ("setup_tag", SETUP_TAG_BYTES),
        ("bundle_wrap", frasil_keys::limits::WRAP_BYTES),
        ("commitment", 32),
        ("nonce", NONCE_BYTES),
    ];
    for (name, value) in pairs {
        assert_eq!(s[name], value as u64, "{name}");
    }
    for (name, range) in [
        ("display", [0, MAX_DISPLAY]),
        ("heads", [1, MAX_HEADS]),
        ("qr_location", [1, MAX_LOCATION]),
        ("peer_hints", [0, MAX_HINTS]),
    ] {
        assert_eq!(s[name], serde_json::json!(range), "{name}");
    }
    let l = &p["exchange_mailbox_limits"];
    assert_eq!(
        l["new_per_source_per_minute"],
        MAILBOX_NEW_PER_MINUTE as u64
    );
    assert_eq!(l["open_per_source"], MAILBOX_OPEN_PER_SOURCE as u64);
    assert_eq!(l["per_peer"], MAILBOX_PER_PEER as u64);
    assert_eq!(l["bytes_per_peer"], MAILBOX_BYTES_PER_PEER as u64);
}

/// One of `transcript`'s exchanges, run end to end through a joiner and an
/// approver, every value compared.
fn run_exchange(k: usize, x: &Json) {
    let tag = format!("admission/t{k}");
    let ctx = Ctx::from_code(x["ctx"].as_u64().unwrap()).unwrap();
    let channel = bytes(&x["channel"]);
    let device = x
        .get("joiner_keys")
        .map(|_| Device::named(if k == 0 { "new-laptop" } else { "guest-laptop" }));
    if let (Some(device), Some(json)) = (&device, x.get("joiner_keys")) {
        device.check_json(json);
    }
    let keys = match &device {
        Some(device) => device.keys(),
        None => {
            let mut person = [0; 32];
            person.copy_from_slice(&bytes(&x["joiner"])[..32]);
            let name = if k == 2 { "bob" } else { "bob-2" };
            assert_eq!(person, example(&format!("admission/person/{name}")));
            JoinerKeys::Person {
                person,
                heads: ids(&x["person_heads"]),
            }
        }
    };
    let (mut joiner, request) = joiner(
        start(
            ctx,
            &tag,
            x["expires_at"].as_u64().unwrap(),
            text(&x["display_j"]),
            &channel,
        ),
        keys,
    );
    assert_eq!(h(joiner.eph()), text(&x["eph_j"]));
    assert_eq!(h(joiner.j_fields().encode()), text(&x["j_fields"]));
    assert_eq!(h(joiner.commitment()), text(&x["commitment"]));
    assert_eq!(h(joiner.j_fields().joiner.bytes()), text(&x["joiner"]));
    assert_eq!(
        joiner.j_fields().joiner.joiner_type().code() as u64,
        x["joiner_type"].as_u64().unwrap()
    );
    assert_eq!(h(&request), text(&x["messages"]["request"]));

    let log: [u8; 32] = array(&x["log"]);
    let heads = ids(&x["heads"]);
    assert_eq!(h(heads_hash(&log, &heads).unwrap()), text(&x["heads_hash"]));
    let mut approver = Approver::new(side(
        frasil_crypto::device::DeviceId(array(&x["approver"])),
        ctx,
        log,
        heads,
        bytes(&x["offer"]),
        text(&x["display_i"]),
        &channel,
    ))
    .unwrap();
    let response = approver
        .on_request_with(
            &request,
            Some(T_REQUEST),
            draw(&tag, &format!("{tag}/enc-response")),
        )
        .unwrap();
    assert_eq!(h(&response), text(&x["messages"]["response"]));
    assert_eq!(
        h(xwing_public(&example(&format!("{tag}/eph-i")))),
        text(&x["eph_i"])
    );
    let revealed = joiner
        .on_response_with(&response, T_RESPONSE, &eseed(&format!("{tag}/enc-reveal")))
        .expect("the joiner reveals");
    assert_eq!(h(&revealed.message), text(&x["messages"]["reveal"]));
    assert_eq!(h(revealed.i_fields.encode()), text(&x["i_fields"]));
    let approved = approver
        .on_reveal(&revealed.message, Some(T_REVEAL))
        .unwrap()
        .expect("the approver takes the Reveal");
    assert_eq!(approved.code, revealed.code);
    assert_eq!(h(approved.code_hash), text(&x["code_hash"]));
    assert_eq!(revealed.code.to_string(), text(&x["code"]));
    assert_eq!(revealed.code.grouped(), text(&x["grouped"]));
    let request_id: [u8; 16] = array(&x["request"]);
    assert_eq!(
        h(seal_info(&request_id, Type::Response)),
        text(&x["seal_info"]["response"])
    );
    assert_eq!(
        h(seal_info(&request_id, Type::Reveal)),
        text(&x["seal_info"]["reveal"])
    );
    for name in ["eph_j_seed", "nonce_j", "eph_i_seed", "nonce_i"] {
        let label = match name {
            "eph_j_seed" => "eph-j",
            "nonce_j" => "nonce-j",
            "eph_i_seed" => "eph-i",
            _ => "nonce-i",
        };
        assert_eq!(h(example(&format!("{tag}/{label}"))), text(&x[name]));
    }
    assert_eq!(h(example16(&format!("{tag}/request"))), text(&x["request"]));
}

#[test]
fn transcript_exchanges() {
    let t = family("transcript");
    let exchanges = t["exchanges"].as_array().unwrap();
    assert_eq!(exchanges.len(), 4);
    for (k, x) in exchanges.iter().enumerate() {
        run_exchange(k, x);
    }
}

#[test]
fn transcript_leading_zero_and_channel() {
    let t = family("transcript");
    let l = &t["leading_zero"];
    let x1 = &t["exchanges"][1];
    let guest = Device::named("guest-laptop");
    let rid = example16(&format!(
        "admission/leading/{}",
        l["counter"].as_u64().unwrap()
    ));
    assert_eq!(h(rid), text(&l["request"]));
    let j = JFields {
        ctx: Ctx::Space,
        request: rid,
        expires_at: T_EXPIRES,
        eph: Box::new(xwing_public(&example("admission/t1/eph-j"))),
        joiner: JoinerPart::Device(guest.device_id()),
        display: "Guest laptop".into(),
    };
    assert_eq!(h(j.encode()), text(&l["j_fields"]));
    assert_eq!(text(&l["i_fields"]), text(&x1["i_fields"]));
    let digest = code_hash(
        &j.encode(),
        &bytes(&l["i_fields"]),
        &bytes(&l["channel"]),
        &array(&l["nonce_j"]),
        &array(&l["nonce_i"]),
    );
    assert_eq!(h(digest), text(&l["code_hash"]));
    let code = Code::of(&digest);
    assert!(code.to_string().starts_with('0'));
    assert_eq!(code.to_string(), text(&l["code"]));
    assert_eq!(code.grouped(), text(&l["grouped"]));
    // The counter is the first that gives a leading zero.
    for n in 0..l["counter"].as_u64().unwrap() {
        let j = JFields {
            request: example16(&format!("admission/leading/{n}")),
            ..j.clone()
        };
        let digest = code_hash(
            &j.encode(),
            &bytes(&l["i_fields"]),
            &bytes(&l["channel"]),
            &array(&l["nonce_j"]),
            &array(&l["nonce_i"]),
        );
        assert!(!Code::of(&digest).to_string().starts_with('0'));
    }

    let c = &t["channel_matters"];
    assert_eq!(c["with the channel"], x1["code"]);
    let relayed = code_hash(
        &bytes(&x1["j_fields"]),
        &bytes(&x1["i_fields"]),
        b"",
        &array(&x1["nonce_j"]),
        &array(&x1["nonce_i"]),
    );
    assert_eq!(
        Code::of(&relayed).to_string(),
        text(&c["the same fields with an empty channel"])
    );
}

#[test]
fn transcript_qr_codes() {
    let t = family("transcript");
    for q in t["qr_codes"].as_array().unwrap() {
        let qr = AdmitQr {
            ctx: Ctx::from_code(q["ctx"].as_u64().unwrap()).unwrap(),
            request: array(&q["request"]),
            commitment: array(&q["commitment"]),
            location: text(&q["location"]).to_owned(),
        };
        assert_eq!(qr.text(), text(&q["text"]));
        assert_eq!(AdmitQr::read(text(&q["text"])), Ok(qr));
    }
    let qr = text(&t["qr_codes"][1]["text"]);
    let mut v2 = Map::new();
    v2.insert(1, Value::Unsigned(2));
    v2.insert(2, Value::Unsigned(2));
    v2.insert(3, Value::from([0u8; 16]));
    v2.insert(4, Value::from([0u8; 32]));
    v2.insert(5, Value::from("x"));
    let version_2 = format!("FRASIL-ADMIT:{}", base32(&Value::Map(v2).encode()));
    let cases = [
        ("lower case", qr.to_lowercase()),
        ("no prefix", qr["FRASIL-ADMIT:".len()..].to_owned()),
        ("version 2", version_2),
    ];
    let refusals = &t["qr_refusals"];
    assert_eq!(refusals.as_object().unwrap().len(), cases.len());
    for (name, text_) in cases {
        assert_eq!(
            verdict(AdmitQr::read(&text_)),
            text(&refusals[name]),
            "{name}"
        );
    }
}

fn guest_offer() -> Offer {
    Offer {
        session: Some([0; 16]),
        ..Offer::new(Level::Write, HistoryMode::FromNowOn)
    }
}

/// admission.py's `pair` for the negative vectors.
fn approver_n(_tag: &str, offer: &Offer) -> Approver {
    let host = Device::named("host-desktop");
    Approver::new(ApproverSide {
        approver: host.device_id(),
        ctx: Ctx::Space,
        log: example("admission/space/show"),
        heads: vec![EventId(example("admission/space/show/head"))],
        offer: offer.encode(),
        display: "Host".into(),
        channel: Vec::new(),
    })
    .unwrap()
}

fn tag(name: &str) -> String {
    format!("admission/n/{name}")
}

#[test]
fn negative_approver() {
    let n = family("negative");
    let want = &n["approver"];
    let guest = Device::named("guest-laptop");
    let offer = guest_offer();
    let mut got: Vec<(&str, &'static str)> = Vec::new();

    let (_, req) = joiner(
        start(Ctx::Space, &tag("expired"), T_EXPIRES, "Guest laptop", b""),
        guest.keys(),
    );
    let mut a = approver_n("expired", &offer);
    got.push((
        "a Request past its expiry",
        verdict(a.on_request_with(&req, Some(T_EXPIRES + 1), draw(&tag("expired"), "n/e"))),
    ));

    let (_, req) = joiner(
        start(
            Ctx::Space,
            &tag("lifetime"),
            T_REQUEST + 961,
            "Guest laptop",
            b"",
        ),
        guest.keys(),
    );
    let mut a = approver_n("lifetime", &offer);
    got.push((
        "a Request living 961 seconds",
        verdict(a.on_request_with(&req, Some(T_REQUEST), draw(&tag("lifetime"), "n/l"))),
    ));

    let (_, req) = joiner(
        start(Ctx::Space, &tag("replay"), T_EXPIRES, "Guest laptop", b""),
        guest.keys(),
    );
    let mut a = approver_n("replay", &offer);
    a.on_request_with(&req, Some(T_REQUEST), draw(&tag("replay"), "n/r1"))
        .unwrap();
    got.push((
        "a Request answered before",
        verdict(a.on_request_with(&req, Some(T_REQUEST), draw(&tag("replay"), "n/r2"))),
    ));

    let (j, req) = joiner(
        start(Ctx::Space, &tag("ctx"), T_EXPIRES, "Guest laptop", b""),
        guest.keys(),
    );
    let mut a = approver_n("ctx", &offer);
    let bad = message(
        Type::Request,
        j.request(),
        &bodies::RequestBody {
            ctx: Ctx::DeviceList,
            expires_at: j.expires_at(),
            commitment: [0; 32],
            eph: Box::new(*j.eph()),
        }
        .encode(),
    );
    got.push((
        "a Request for a device list, sent to a space's approver",
        verdict(a.on_request_with(&bad, Some(T_REQUEST), draw(&tag("ctx"), "n/c"))),
    ));
    let mut v2 = req.clone();
    v2[0] = 2;
    got.push((
        "an envelope of version 2",
        verdict(a.on_request_with(&v2, Some(T_REQUEST), draw(&tag("ctx"), "n/v"))),
    ));
    let mut t11 = req.clone();
    t11[1] = 11;
    got.push((
        "an envelope of type 11, unknown",
        verdict(a.on_request_with(&t11, Some(T_REQUEST), draw(&tag("ctx"), "n/u"))),
    ));
    got.push((
        "a Request message over 4,096 bytes",
        verdict(a.on_request_with(
            &message(Type::Request, j.request(), &[0; MAX_REQUEST_MESSAGE]),
            Some(T_REQUEST),
            draw(&tag("ctx"), "n/b"),
        )),
    ));
    got.push((
        "a Cancel with a body",
        verdict(a.on_request_with(
            &message(Type::Cancel, j.request(), b"x"),
            Some(T_REQUEST),
            draw(&tag("ctx"), "n/x"),
        )),
    ));

    // A relay that relabels the joiner after the commitment.
    let (mut j, req) = joiner(
        start(Ctx::Space, &tag("swap"), T_EXPIRES, "Guest laptop", b""),
        guest.keys(),
    );
    let mut a = approver_n("swap", &offer);
    let resp = a
        .on_request_with(&req, Some(T_REQUEST), draw(&tag("swap"), "n/s1"))
        .unwrap();
    let jr = j
        .on_response_with(&resp, T_RESPONSE, &eseed("n/s2"))
        .unwrap();
    let (mut j2, _) = joiner(
        start(Ctx::Space, &tag("swap"), T_EXPIRES, "Attacker", b""),
        guest.keys(),
    );
    let forged = j2
        .on_response_with(&resp, T_RESPONSE, &eseed("n/s3"))
        .unwrap();
    got.push((
        "a Reveal with another display",
        outcome(a.on_reveal(&forged.message, Some(T_REVEAL))),
    ));
    got.push((
        "a second Reveal",
        outcome(a.on_reveal(&jr.message, Some(T_REVEAL))),
    ));

    // A relay that substitutes its own keys.
    let attacker = Device::named("attacker");
    let (_, req) = joiner(
        start(Ctx::Space, &tag("keys"), T_EXPIRES, "Guest laptop", b""),
        guest.keys(),
    );
    let mut a = approver_n("keys", &offer);
    let resp = a
        .on_request_with(&req, Some(T_REQUEST), draw(&tag("keys"), "n/k1"))
        .unwrap();
    let (mut j3, _) = joiner(
        start(Ctx::Space, &tag("keys"), T_EXPIRES, "Guest laptop", b""),
        attacker.keys(),
    );
    let reveal = j3
        .on_response_with(&resp, T_RESPONSE, &eseed("n/k2"))
        .unwrap();
    got.push((
        "a Reveal of other keys",
        outcome(a.on_reveal(&reveal.message, Some(T_REVEAL))),
    ));

    let (mut j, req) = joiner(
        start(Ctx::Space, &tag("late"), T_EXPIRES, "Guest laptop", b""),
        guest.keys(),
    );
    let mut a = approver_n("late", &offer);
    let resp = a
        .on_request_with(&req, Some(T_REQUEST), draw(&tag("late"), "n/t1"))
        .unwrap();
    let jr = j
        .on_response_with(&resp, T_RESPONSE, &eseed("n/t2"))
        .unwrap();
    got.push((
        "a Reveal past the expiry",
        outcome(a.on_reveal(&jr.message, Some(T_EXPIRES + 1))),
    ));

    assert_eq!(want.as_object().unwrap().len(), got.len());
    for (name, verdict) in got {
        assert_eq!(verdict, text(&want[name]), "{name}");
    }
}

#[test]
fn negative_joiner_ignores() {
    let n = family("negative");
    let want = &n["joiner_ignores"];
    let guest = Device::named("guest-laptop");
    let offer = guest_offer();
    let shown = |r: Option<frasil_admission::joiner::Revealed>| {
        if r.is_some() { "accepted" } else { "ignored" }
    };
    let mut got = Vec::new();

    let (mut j, req) = joiner(
        start(Ctx::Space, &tag("twice"), T_EXPIRES, "Guest laptop", b""),
        guest.keys(),
    );
    let mut a = approver_n("twice", &offer);
    let resp = a
        .on_request_with(&req, Some(T_REQUEST), draw(&tag("twice"), "n/w1"))
        .unwrap();
    assert!(
        j.on_response_with(&resp, T_RESPONSE, &eseed("n/w2"))
            .is_some()
    );
    got.push((
        "a second Response",
        shown(j.on_response_with(&resp, T_RESPONSE + 1, &eseed("n/w3"))),
    ));

    let (mut j, req) = joiner(
        start(Ctx::Space, &tag("jlate"), T_EXPIRES, "Guest laptop", b""),
        guest.keys(),
    );
    let mut a = approver_n("jlate", &offer);
    let resp = a
        .on_request_with(&req, Some(T_REQUEST), draw(&tag("jlate"), "n/x1"))
        .unwrap();
    got.push((
        "a Response past the expiry",
        shown(j.on_response_with(&resp, T_EXPIRES + 1, &eseed("n/x2"))),
    ));

    let (mut j, req) = joiner(
        start(
            Ctx::Space,
            &tag("other-key"),
            T_EXPIRES,
            "Guest laptop",
            b"",
        ),
        guest.keys(),
    );
    let mut a = approver_n("other-key", &offer);
    a.on_request_with(&req, Some(T_REQUEST), draw(&tag("other-key"), "n/o1"))
        .unwrap();
    let host = Device::named("host-desktop");
    let other = bodies::ResponseBody {
        nonce: example(&format!("{}/nonce-i", tag("other-key"))),
        log: example("admission/space/show"),
        heads: vec![EventId(example("admission/space/show/head"))],
        approver: host.device_id(),
        eph: Box::new(xwing_public(&example(&format!(
            "{}/eph-i",
            tag("other-key")
        )))),
        offer: offer.encode(),
        display: "Host".into(),
    };
    let wrong = sealed_message_with(
        Type::Response,
        j.request(),
        &xwing_public(&example("admission/n/other-key/other")),
        &other.encode(),
        &eseed("n/o2"),
    )
    .unwrap();
    got.push((
        "a Response sealed to another key",
        shown(j.on_response_with(&wrong, T_RESPONSE, &eseed("n/o3"))),
    ));

    let unsuited = Offer {
        session: Some([0; 16]),
        ..Offer::new(Level::Administer, HistoryMode::FromNowOn)
    };
    let (mut j, req) = joiner(
        start(Ctx::Space, &tag("unsuited"), T_EXPIRES, "Guest laptop", b""),
        guest.keys(),
    );
    let mut a = approver_n("unsuited", &unsuited);
    let resp = a
        .on_request_with(&req, Some(T_REQUEST), draw(&tag("unsuited"), "n/a1"))
        .unwrap();
    got.push((
        "a Response whose offer does not suit the joiner",
        shown(j.on_response_with(&resp, T_RESPONSE, &eseed("n/a2"))),
    ));

    assert_eq!(want.as_object().unwrap().len(), got.len());
    for (name, verdict) in got {
        assert_eq!(verdict, text(&want[name]), "{name}");
    }
}

fn map_bytes(pairs: &[(u64, Value)]) -> Vec<u8> {
    Value::Map(pairs.iter().cloned().collect::<Map>()).encode()
}

#[test]
fn negative_refused_offers() {
    let n = family("negative");
    let want = &n["refused_offers"];
    let write = |history| Offer::new(Level::Write, history);
    let with_expiry = map_bytes(&[
        (2, Value::Unsigned(1)),
        (5, Value::Unsigned(0)),
        (7, Value::from([0u8; 16])),
        (13, Value::Unsigned(5)),
    ]);
    let cases: Vec<(&str, Vec<u8>, Ctx, JoinerType)> = vec![
        (
            "administer with a session",
            Offer {
                session: Some([0; 16]),
                ..Offer::new(Level::Administer, HistoryMode::FromNowOn)
            }
            .encode(),
            Ctx::Space,
            JoinerType::Device,
        ),
        (
            "administer to a person",
            Offer::new(Level::Administer, HistoryMode::WithHistory).encode(),
            Ctx::Space,
            JoinerType::Person,
        ),
        (
            "a session to a person",
            Offer {
                session: Some([0; 16]),
                ..write(HistoryMode::FromNowOn)
            }
            .encode(),
            Ctx::Space,
            JoinerType::Person,
        ),
        (
            "key 13, expires_at, at a core joiner",
            with_expiry,
            Ctx::Space,
            JoinerType::Device,
        ),
        (
            "key 9",
            map_bytes(&[
                (2, Value::Unsigned(1)),
                (5, Value::Unsigned(0)),
                (9, Value::Unsigned(1)),
            ]),
            Ctx::Space,
            JoinerType::Device,
        ),
        (
            "replaces, to a device",
            Offer {
                replaces: Some([0; 32]),
                ..write(HistoryMode::WithHistory)
            }
            .encode(),
            Ctx::Space,
            JoinerType::Device,
        ),
        (
            "an offer in ctx 0x01",
            map_bytes(&[(2, Value::Unsigned(1)), (5, Value::Unsigned(0))]),
            Ctx::DeviceList,
            JoinerType::Device,
        ),
    ];
    assert_eq!(want.as_object().unwrap().len(), cases.len());
    for (name, data, ctx, joiner_type) in cases {
        // A joiner that implements ext-guests.md reads key 13 beside a
        // session; ext-guests.json's `sessions` holds that case.
        if cfg!(feature = "ext-guests") && name == "key 13, expires_at, at a core joiner" {
            assert!(read_offer(&data, ctx, joiner_type).is_ok(), "{name}");
            continue;
        }
        assert_eq!(
            verdict(read_offer(&data, ctx, joiner_type)),
            text(&want[name]),
            "{name}"
        );
    }
    // The transcript's guest offer, with a capability and a label, reads.
    let guest = Offer {
        capabilities: Some(vec![Capability {
            name: "drive".into(),
            mode: CapabilityMode::Extends,
        }]),
        label: Some("Operator".into()),
        session: Some(example16("admission/session")),
        ..write(HistoryMode::FromNowOn)
    };
    assert_eq!(
        h(guest.encode()),
        text(&family("transcript")["exchanges"][1]["offer"])
    );
}

fn step(result: Result<(), frasil_admission::AdmissionClass>) -> Json {
    let mut out = serde_json::Map::new();
    match result {
        Ok(()) => {
            out.insert("result".into(), "stored".into());
        }
        Err(class) => {
            out.insert("result".into(), class.name().into());
            if let Some((reason, status)) = class.reason() {
                out.insert("reason".into(), reason.into());
                out.insert("status".into(), status.into());
            }
        }
    }
    Json::Object(out)
}

fn compare_step(got: &Json, want: &Json) {
    for key in ["result", "reason", "status"] {
        assert_eq!(got.get(key), want.get(key), "{} {}", want["what"], key);
    }
}

#[test]
fn exchange_mailbox() {
    let m = family("exchange_mailbox");
    let request: [u8; 16] = array(&m["address"]["request"]);
    assert_eq!(request, example16("admission/mailbox/request"));
    assert_eq!(m["address"]["kind"], 1);
    assert_eq!(
        h(exchange_address(&request)),
        text(&m["address"]["address"])
    );

    let guest = Device::named("guest-laptop");
    let host = Device::named("host-desktop");
    let mut peer: ExchangeMailboxes<&str> = ExchangeMailboxes::default();
    let tag = "admission/mailbox";
    let (mut j, req) = joiner(
        start(Ctx::Space, tag, T_EXPIRES, "Guest", b""),
        guest.keys(),
    );
    let mut a = Approver::new(ApproverSide {
        approver: host.device_id(),
        ctx: Ctx::Space,
        log: example("admission/space/show"),
        heads: vec![EventId(example("admission/space/show/head"))],
        offer: guest_offer().encode(),
        display: "Host".into(),
        channel: Vec::new(),
    })
    .unwrap();
    let mut steps = Vec::new();
    steps.push(step(peer.put(&"joiner", &req, T_REQUEST)));
    steps.push(step(peer.put(&"joiner", &req, T_REQUEST + 1)));
    let resp = a
        .on_request_with(
            &req,
            Some(T_REQUEST + 2),
            draw(tag, "admission/mailbox/enc-response"),
        )
        .unwrap();
    steps.push(step(peer.put(
        &"relay",
        &message(Type::Reveal, j.request(), &[b'x'; 1200]),
        T_REQUEST + 3,
    )));
    steps.push(step(peer.put(&"approver", &resp, T_REQUEST + 4)));
    steps.push(step(peer.put(&"relay", &resp, T_REQUEST + 5)));
    let jr = j
        .on_response_with(&resp, T_REQUEST + 6, &eseed("admission/mailbox/enc-reveal"))
        .unwrap();
    steps.push(step(peer.put(&"joiner", &jr.message, T_REQUEST + 7)));
    steps.push(step(peer.put(
        &"approver",
        &message(Type::Result, j.request(), &[b'r'; 1200]),
        T_EXPIRES + 1,
    )));
    steps.push(step(peer.put(
        &"anyone",
        &message(Type::Response, &[0; 16], b"x"),
        T_REQUEST + 8,
    )));
    steps.push(step(peer.put(
        &"anyone",
        &message(Type::Join, &[0; 16], b"x"),
        T_REQUEST + 8,
    )));
    let want = m["steps"].as_array().unwrap();
    assert_eq!(want.len(), steps.len());
    for (got, want) in steps.iter().zip(want) {
        compare_step(got, want);
    }

    let mut rate = Vec::new();
    for n in 0..=MAILBOX_NEW_PER_MINUTE {
        let (_, req) = joiner(
            start(Ctx::Space, tag, 1_760_001_900, "G", b"")
                .with_request(example16(&format!("admission/mailbox/rate/{n}"))),
            guest.keys(),
        );
        rate.push(step(peer.put(&"busy", &req, 1_760_001_100 + n as u64))["result"].clone());
    }
    assert_eq!(Json::Array(rate), m["eleven_requests_in_a_minute"]);

    let (_, long) = joiner(
        start(Ctx::Space, tag, 1_760_002_000 + 961, "G", b"")
            .with_request(example16("admission/mailbox/long")),
        guest.keys(),
    );
    compare_step(
        &step(peer.put(&"other", &long, 1_760_002_000)),
        &m["a Request living 961 seconds"],
    );
}

/// A put with no source passes step 4 and counts toward no source; a
/// source's opens are forgotten once a minute passes, at a sweep.
#[test]
fn a_put_with_no_source_counts_for_none_and_opens_are_forgotten() {
    let guest = Device::named("guest-laptop");
    let tag = "admission/mailbox";
    let mut peer: ExchangeMailboxes<&str> = ExchangeMailboxes::default();
    for n in 0..=MAILBOX_NEW_PER_MINUTE {
        let (_, req) = joiner(
            start(Ctx::Space, tag, 1_760_001_900, "G", b"")
                .with_request(example16(&format!("admission/mailbox/unsourced/{n}"))),
            guest.keys(),
        );
        assert_eq!(peer.put_unsourced(&req, 1_760_001_100 + n as u64), Ok(()));
    }
    assert_eq!(peer.sources_counted(), 0);
    let (_, req) = joiner(
        start(Ctx::Space, tag, 1_760_001_900, "G", b"")
            .with_request(example16("admission/mailbox/sourced")),
        guest.keys(),
    );
    assert_eq!(peer.put(&"one", &req, 1_760_001_120), Ok(()));
    assert_eq!(peer.sources_counted(), 1);
    peer.sweep(1_760_001_179);
    assert_eq!(peer.sources_counted(), 1);
    peer.sweep(1_760_001_180);
    assert_eq!(peer.sources_counted(), 0);
    assert_eq!(peer.len(), MAILBOX_NEW_PER_MINUTE + 2);
}

trait WithRequest {
    fn with_request(self, request: [u8; 16]) -> Self;
}

impl WithRequest for frasil_admission::joiner::JoinerStart {
    fn with_request(mut self, request: [u8; 16]) -> Self {
        self.request = request;
        self
    }
}

/// A Cancel is kept and served, so that the other side reads it ("Without a
/// nearby connection": each side reads every message of the mailbox), and
/// the mailbox takes nothing after it.
#[test]
fn a_cancel_is_served() {
    let guest = Device::named("guest-laptop");
    let mut peer: ExchangeMailboxes<&str> = ExchangeMailboxes::default();
    let (j, req) = joiner(
        start(Ctx::Space, "admission/mailbox", T_EXPIRES, "Guest", b""),
        guest.keys(),
    );
    assert_eq!(peer.put(&"joiner", &req, T_REQUEST), Ok(()));
    let cancel = j.cancel();
    assert_eq!(peer.put(&"approver", &cancel, T_REQUEST + 1), Ok(()));
    let (messages, cancelled) = peer.read(j.request()).unwrap();
    assert!(cancelled);
    assert_eq!(messages, vec![&req[..], &cancel[..]]);
    assert_eq!(
        peer.put(&"joiner", &cancel, T_REQUEST + 2),
        Err(frasil_admission::AdmissionClass::Cancelled)
    );
}
