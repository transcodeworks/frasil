//! admission.json's `welcome` family (admission.md, sections 2.10, 3.3 and
//! 3.10): a guest's admitting event with its own wrap, the Result and a
//! sealed welcome that carry a copy, and the joiner's checks of the grant.

mod common;

use common::history::{History, Recipient};
use common::*;
use frasil_admission::grant::{
    Authenticated, ExpectedJoiner, check_grant, grant_change, open_admitting_event,
};
use frasil_admission::welcome::{Welcome, welcome_info};
use frasil_admission::{Approver, Ctx, Offer};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_keys::KeyName;
use frasil_space::{
    Capability, CapabilityMode, HistoryMode, Level, MemberType, OtherLogs, Standing, Via,
};
use serde_json::{Map, Value as Json, json};

#[test]
fn welcome() {
    let w = family("welcome");
    let prefix = "admission/welcome";
    let mut r = History::new("H", prefix);
    let guest = Device::fixture(History::seed(prefix, "G"));
    assert_eq!(
        text(&w["guest"]["identity_seed"]),
        h(History::seed(prefix, "G"))
    );
    assert_eq!(text(&w["guest"]["xwing_seed"]), h(guest.xwing_seed));
    let host = r.device("H");
    let session = example16("admission/welcome/session");
    let offer = Offer {
        capabilities: Some(vec![Capability {
            name: "drive".into(),
            mode: CapabilityMode::Extends,
        }]),
        label: Some("Operator".into()),
        session: Some(session),
        ..Offer::new(Level::Write, HistoryMode::FromNowOn)
    };
    let heads = r.heads("H");
    let channel = example("admission/welcome/exporter");

    // The exchange, with a channel.
    let (mut joiner, request) = joiner(
        start(Ctx::Space, prefix, T_EXPIRES, "Guest laptop", &channel),
        guest.keys(),
    );
    let mut approver = Approver::new(side(
        host,
        Ctx::Space,
        r.id().0,
        heads.clone(),
        offer.encode(),
        "Venue host",
        &channel,
    ))
    .unwrap();
    let response = approver
        .on_request_with(
            &request,
            Some(T_REQUEST),
            draw(prefix, "admission/welcome/enc-1"),
        )
        .unwrap();
    let revealed = joiner
        .on_response_with(&response, T_RESPONSE, &eseed("admission/welcome/enc-2"))
        .unwrap();
    let approved = approver
        .on_reveal(&revealed.message, Some(T_REVEAL))
        .unwrap()
        .unwrap();
    assert_eq!(approved.code, revealed.code);
    assert_eq!(approved.code.to_string(), text(&w["code"]));

    // The admitting event: the grant the code authenticated, delivered to
    // the host and the guest.
    let grant = grant_change(&offer, &approved.reveal).unwrap();
    let g = r.admit(
        "H",
        vec![grant],
        "H admits the guest",
        true,
        &[
            r.recipient("H", true),
            Recipient {
                keys: guest.device_keys(),
                writes: true,
            },
        ],
    );
    let event = r.log.event(g).unwrap().clone();
    assert_eq!(h(event.signed()), text(&w["grant_event"]));
    assert_eq!(h(g.0), text(&w["grant_id"]));

    // The guest's own wrap.
    let visible =
        frasil_keys::body::VisiblePart::read(event.unverified_body(), event.author(), event.seq())
            .unwrap();
    let delivery = &visible.deliveries[0];
    let (index, bundle) = frasil_keys::wraps::find_own_wrap(
        &delivery.wraps,
        &r.id().0,
        delivery.key_name.as_ref(),
        delivery.grant_name.as_ref(),
        &guest.device_id(),
        &guest.xwing_seed,
    )
    .unwrap();
    assert_eq!(index as u64, w["own_wrap_index"].as_u64().unwrap());
    let mut holds = Vec::new();
    if bundle.content().is_some() {
        holds.push("content");
    }
    if bundle.grant().is_some() {
        holds.push("grant");
    }
    if bundle.upload().is_some() {
        holds.push("upload");
    }
    assert_eq!(json!(holds), w["bundle_holds"]);

    // The welcome, as a Result and sealed.
    let welcome = Welcome {
        space: r.id().0,
        event: g,
        key_name: delivery.key_name.as_ref().map(KeyName::encode).unwrap(),
        grant_name: delivery
            .grant_name
            .as_ref()
            .map(KeyName::encode)
            .unwrap_or_default(),
        wrap: delivery.wraps[index].clone(),
        approver: host,
        peers: vec!["iroh:host-member-endpoint".into()],
        snapshot: None,
    };
    assert_eq!(h(welcome.encode()), text(&w["welcome"]));
    let result = approver
        .result_with(
            &approved.request,
            &welcome.encode(),
            Some(T_REVEAL),
            &eseed("admission/welcome/enc-3"),
        )
        .unwrap();
    assert_eq!(h(&result), text(&w["result_message"]));
    assert_eq!(
        h(welcome_info(&guest.device_id())),
        text(&w["welcome_info"])
    );
    let sealed = welcome
        .seal_with(&guest.device_keys(), &eseed("admission/welcome/enc-4"))
        .unwrap();
    assert_eq!(h(&sealed), text(&w["sealed_welcome"]));
    assert_eq!(
        Welcome::open(&sealed, &guest.device_id(), &guest.xwing_seed).as_ref(),
        Ok(&welcome)
    );
    let from_result = Welcome::read(&joiner.open_result(&result).unwrap()).unwrap();
    assert_eq!(from_result, welcome);
    // Key 9 names the snapshot of a newcomer admitted from now on: 64 bytes.
    let named = Welcome {
        snapshot: Some([9; 64]),
        ..welcome.clone()
    };
    assert_eq!(Welcome::read(&named.encode()).as_ref(), Ok(&named));
    let mut short = frasil_base::cbor::decode(&welcome.encode()).unwrap();
    if let frasil_base::cbor::Value::Map(map) = &mut short {
        map.insert(9, frasil_base::cbor::Value::from(&[9u8; 63][..]));
    }
    assert!(Welcome::read(&short.encode()).is_err());

    // The joiner's checks.
    let opened =
        open_admitting_event(&event, &from_result, &guest.device_id(), &guest.xwing_seed).unwrap();
    let response = joiner.response().unwrap();
    let past = r.log.past(g);
    let me = ExpectedJoiner::of(&approved.reveal);
    let authenticated =
        |approver: &'_ DeviceId, log: &'_ [u8; 32], heads: &'_ [EventId], offer: &'_ Offer| {
            check_grant(
                &event,
                &opened,
                &past,
                &Authenticated {
                    approver,
                    log,
                    heads,
                    offer,
                },
                &me,
                Via::Code,
            )
            .map(|_| ())
        };
    let offer_read = Offer::read(&response.offer, frasil_admission::JoinerType::Device).unwrap();
    let mut more_heads = response.heads.clone();
    more_heads.push(EventId(example("admission/welcome/x")));
    let other_offer = Offer {
        session: Some(session),
        ..Offer::new(Level::Read, HistoryMode::FromNowOn)
    };
    let other_space = example("admission/welcome/other-space");
    let checks = [
        (
            "the grant",
            verdict(authenticated(
                &response.approver,
                &response.log,
                &response.heads,
                &offer_read,
            )),
        ),
        (
            "another approver",
            verdict(authenticated(
                &guest.device_id(),
                &response.log,
                &response.heads,
                &offer_read,
            )),
        ),
        (
            "another space",
            verdict(authenticated(
                &response.approver,
                &other_space,
                &response.heads,
                &offer_read,
            )),
        ),
        (
            "a head the grant does not follow",
            verdict(authenticated(
                &response.approver,
                &response.log,
                &more_heads,
                &offer_read,
            )),
        ),
        (
            "another offer",
            verdict(authenticated(
                &response.approver,
                &response.log,
                &response.heads,
                &other_offer,
            )),
        ),
        (
            "the same grant, expected by lookup",
            verdict(check_grant(
                &event,
                &opened,
                &past,
                &Authenticated {
                    approver: &response.approver,
                    log: &response.log,
                    heads: &response.heads,
                    offer: &offer_read,
                },
                &me,
                Via::Lookup,
            )),
        ),
    ];
    let want = &w["joiner_checks"];
    assert_eq!(want.as_object().unwrap().len(), checks.len());
    for (case, got) in checks {
        assert_eq!(got, text(&want[case]), "{case}");
    }

    // Refused welcomes.
    let mut v2 = sealed.clone();
    v2[0] = 2;
    let mut suite = sealed.clone();
    suite[1..3].copy_from_slice(&0x0020u16.to_be_bytes());
    let refusals = [
        (
            "another device opens it",
            Welcome::open(&sealed, &host, &example("roster/H/xwing")),
        ),
        (
            "version 2",
            Welcome::open(&v2, &guest.device_id(), &guest.xwing_seed),
        ),
        (
            "suite 0x0020",
            Welcome::open(&suite, &guest.device_id(), &guest.xwing_seed),
        ),
        (
            "1,138 bytes",
            Welcome::open(&sealed[..1138], &guest.device_id(), &guest.xwing_seed),
        ),
    ];
    let want = &w["refused_welcomes"];
    assert_eq!(want.as_object().unwrap().len(), refusals.len());
    for (case, got) in refusals {
        assert_eq!(verdict(got), text(&want[case]), "{case}");
    }

    // The roster the space resolves to.
    let keys = r.keyring();
    let others = OtherLogs::default();
    let space = r.resolve(None, &keys, &others);
    assert!(space.is_valid(g));
    let mut roster = Map::new();
    for (member, standing) in space.roster().iter() {
        let Standing::In(state) = standing else {
            continue;
        };
        assert_eq!(member.kind, MemberType::Device);
        let name = if member.id == host.0 { "H" } else { "G" };
        let mut entry = Map::new();
        entry.insert("type".into(), json!("device"));
        entry.insert("level".into(), json!(state.level.name()));
        entry.insert("history".into(), json!(state.history.name()));
        entry.insert("via".into(), json!(state.via.name()));
        if let Some(session) = state.session {
            entry.insert("session".into(), json!(h(session)));
        }
        if let Some(label) = &state.label {
            entry.insert("label".into(), json!(label));
        }
        if !state.capabilities.is_empty() {
            let caps: Vec<Json> = state
                .capabilities
                .iter()
                .map(|c| json!([c.name, c.mode.name()]))
                .collect();
            entry.insert("capabilities".into(), Json::Array(caps));
        }
        roster.insert(name.into(), Json::Object(entry));
    }
    assert_eq!(Json::Object(roster), w["roster"]);
}
