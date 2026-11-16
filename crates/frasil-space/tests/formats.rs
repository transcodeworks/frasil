//! roster.json's `labels`, `parameters`, `descriptors`, `policies` and
//! `encodings` (roster.md, sections 2.1 to 2.7).

mod common;

use common::space::prefix_at;
use common::{array, bytes, class, events, family, keyring, log_of, screen, text};
use frasil_base::cbor::Value as Cbor;
use frasil_keys::body::VisiblePart;
use frasil_space::change::key as change_key;
use frasil_space::limits::{
    AGREEMENT_LIMIT, MAX_CAPABILITIES, MAX_CHANGES, MAX_DEVICE_GRANTS, MAX_NAME_BYTES,
    MAX_ROSTER_EVENTS, REFS_INNER_KEY,
};
use frasil_space::part::{DUEL_RANKS, GENESIS, UPDATE};
use frasil_space::{
    CapabilityMode, Descriptor, DescriptorKind, HistoryMode, LABELS, Level, MemberRef, MemberType,
    Op, Places, Policy, RosterEvents, RosterLog, RosterPart, Standing, Via,
};
use serde_json::Value as Json;
use std::collections::BTreeSet;

#[test]
fn labels() {
    let labels = family("labels");
    let labels = labels.as_object().unwrap();
    assert_eq!(labels.len(), LABELS.len());
    for label in LABELS {
        let name = std::str::from_utf8(label).unwrap();
        let hex = labels[name].as_str().unwrap();
        assert_eq!(frasil_testkit::hex::decode(hex).unwrap(), label, "{name}");
    }
}

#[test]
fn parameters() {
    let p = family("parameters");
    let code = |group: &str, name: &str| p[group][name].as_u64().unwrap();
    assert_eq!(p["event_kind"], u64::from(frasil_events::kind::SPACE));
    assert_eq!(code("body_types", "genesis"), GENESIS);
    assert_eq!(code("body_types", "update"), UPDATE);
    assert_eq!(p["ops"].as_object().unwrap().len(), Op::ALL.len());
    for op in Op::ALL {
        assert_eq!(code("ops", op.name()), op.code());
    }
    assert_eq!(
        p["member_types"].as_object().unwrap().len(),
        MemberType::ALL.len()
    );
    for kind in MemberType::ALL {
        assert_eq!(code("member_types", kind.name()), kind.code());
    }
    for level in Level::ALL {
        assert_eq!(code("levels", level.name()), level.code());
    }
    for mode in [HistoryMode::FromNowOn, HistoryMode::WithHistory] {
        assert_eq!(code("history", mode.name()), mode.code());
    }
    for via in Via::ALL {
        assert_eq!(code("via", via.name()), via.code());
    }
    for mode in [CapabilityMode::Extends, CapabilityMode::Narrows] {
        assert_eq!(code("capability_modes", mode.name()), mode.code());
    }
    assert_eq!(code("duel_policies", "both stand"), DUEL_RANKS);
    let limit = |name: &str| usize::try_from(p[name].as_u64().unwrap()).unwrap();
    assert_eq!(limit("max_changes"), MAX_CHANGES);
    assert_eq!(limit("max_device_grants"), MAX_DEVICE_GRANTS);
    assert_eq!(limit("max_capabilities"), MAX_CAPABILITIES);
    assert_eq!(limit("max_name_bytes"), MAX_NAME_BYTES);
    assert_eq!(limit("max_roster_events"), MAX_ROSTER_EVENTS);
    assert_eq!(limit("agreed_step_limit"), AGREEMENT_LIMIT);
    assert_eq!(p["refs_inner_key"], REFS_INNER_KEY);
    assert_eq!(p["max_record_bytes"], frasil_space::part::MAX_RECORD_BYTES);
}

#[test]
fn descriptors() {
    let f = family("descriptors");
    for case in f["accepted"].as_array().unwrap() {
        let data = bytes(case, "descriptor");
        let descriptor = Descriptor::read(&data).unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(descriptor.kind.name(), text(case, "kind"));
        assert_eq!(
            descriptor.application.as_deref(),
            case["application"].as_str()
        );
        assert_eq!(
            descriptor.parent.is_some(),
            descriptor.kind != DescriptorKind::Space
        );
        assert_eq!(descriptor.encode(), data, "{}", text(case, "name"));
    }
    for case in f["refusals"].as_array().unwrap() {
        let data = bytes(case, "descriptor");
        assert_eq!(
            class(Descriptor::read(&data)),
            Some(text(case, "error")),
            "{}",
            text(case, "name")
        );
    }
    // A later document's descriptor reads, with its kind, and holds the
    // space at every implementation.
    for case in f["held"].as_array().unwrap() {
        let name = text(case, "name");
        let descriptor =
            Descriptor::read(&bytes(case, "descriptor")).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            descriptor.kind,
            DescriptorKind::Reserved(case["kind"].as_u64().unwrap()),
            "{name}"
        );
        assert_eq!(
            (descriptor.parent, descriptor.application.as_deref()),
            (None, None)
        );
        assert_eq!(text(case, "outcome"), "ExtensionRequired");
        assert_eq!(
            class(frasil_space::ext::check_descriptor(&descriptor)),
            Some("ExtensionRequired"),
            "{name}"
        );
    }
}

#[test]
fn policies() {
    let f = family("policies");
    let optional = |value: &Json| value.as_u64();
    for case in f["accepted"].as_array().unwrap() {
        let data = bytes(case, "policy");
        let policy = Policy::read(&data).unwrap_or_else(|e| panic!("{case}: {e}"));
        let read = &case["read"];
        assert_eq!(
            Some(policy.agent_waiting_period),
            read["agent_waiting_period"].as_u64()
        );
        assert_eq!(policy.bounded_window, optional(&read["bounded_window"]));
        assert_eq!(policy.online_freshness, optional(&read["online_freshness"]));
        assert_eq!(
            Some(policy.gap_key_timeout),
            read["gap_key_timeout"].as_u64()
        );
        assert_eq!(Some(policy.forbid_agents), read["forbid_agents"].as_bool());
        assert_eq!(policy.encode(), data, "{}", text(case, "name"));
    }
    for case in f["refusals"].as_array().unwrap() {
        let data = bytes(case, "policy");
        assert_eq!(
            class(Policy::read(&data)),
            Some(text(case, "error")),
            "{}",
            text(case, "name")
        );
    }
}

/// Each event's body and signed bytes, byte for byte: every event decodes,
/// opens and passes the checks of the event alone, and its visible part,
/// sealed part and roster part re-encode to the bytes it carries. Then the
/// roster and the space policy after them all.
#[test]
fn encodings() {
    let f = family("encodings");
    let history = events(&f["events"]);
    for ((_, event), case) in history.iter().zip(f["events"].as_array().unwrap()) {
        assert_eq!(
            event.unverified_body(),
            bytes(case, "body"),
            "{}",
            text(case, "name")
        );
        assert_eq!(event.signed(), bytes(case, "signed"));
    }
    let log = log_of(&history);
    assert_eq!(log.id().0, array::<32>(&f, "space_id"));
    let keys = keyring(&prefix_at(&["encodings"]), &history, &[]);
    let screened = screen(&log, &keys).expect("the space is usable");
    for (name, event) in &history {
        assert_eq!(screened.verdict(event.id()), Some(Ok(())), "{name}");
        let opened = screened.opened(event.id()).unwrap();
        assert!(!opened.provisional);
        assert_eq!(
            VisiblePart::read(event.unverified_body(), event.author(), event.seq()).as_ref(),
            Ok(&opened.visible)
        );
        assert_eq!(opened.visible.encode(), event.unverified_body());
        let log_bytes = match opened.visible.nonce {
            Some(nonce) => nonce.to_vec(),
            None => log.id().0.to_vec(),
        };
        let nonce: [u8; 24] = opened.visible.sealed[..24].try_into().unwrap();
        let resealed = opened.inner.seal_with(
            &opened.body_key,
            &log_bytes,
            event.author(),
            event.seq(),
            &nonce,
        );
        assert_eq!(resealed, opened.visible.sealed, "{name}");
        let part = opened.part.as_ref().expect("every event is a roster event");
        assert_eq!(Some(part.encode()), opened.inner.roster, "{name}");
    }

    // What the events say.
    let opened = |name: &str| {
        let (_, event) = history.iter().find(|(n, _)| n == name).unwrap();
        screened.opened(event.id()).unwrap()
    };
    let author = *history[0].1.author();
    let genesis = screened.genesis();
    assert_eq!(genesis.policy.agent_waiting_period, 96 * 3600);
    assert_eq!(genesis.descriptor, Descriptor::ORDINARY);
    assert_eq!(genesis.founder.member, Some(MemberRef::device(author)));
    let grant = &opened("P grants D write with capabilities and a label").changes()[0];
    assert_eq!(grant.label.as_deref(), Some("operator"));
    let capabilities: Vec<(&str, CapabilityMode)> = grant
        .capabilities
        .iter()
        .flatten()
        .map(|c| (c.name.as_str(), c.mode))
        .collect();
    assert_eq!(
        capabilities,
        [
            ("drive", CapabilityMode::Extends),
            ("suggest", CapabilityMode::Narrows)
        ]
    );
    let guest = &opened("P grants a guest for a session").changes()[0];
    assert_eq!(
        guest.session.map(Vec::from),
        Some(common::example("roster/enc/session")[..16].to_vec())
    );
    assert_eq!(guest.history, Some(HistoryMode::FromNowOn));
    let demotion = &opened("P demotes D to read").changes()[0];
    assert_eq!(
        (demotion.op, demotion.level),
        (Op::Change, Some(Level::Read))
    );
    let policy = opened("P forbids recovery agents");
    assert!(!policy.visible.rotates());
    assert!(policy.changes()[0].policy.is_some_and(|p| p.forbid_agents));
    let removal = &opened("P removes the guest").changes()[0];
    assert_eq!((removal.op, removal.member), (Op::Remove, guest.member));

    // A change's encoding is the map the change carries.
    let encoded = grant.to_value();
    let Cbor::Map(map) = &encoded else {
        panic!("a change is a map")
    };
    assert!(map.contains_key(&change_key::ED25519));

    // The roster and policy after every event, each valid.
    let roster_log = RosterLog {
        log: &log,
        screened: &screened,
        pasts: None,
        world: None,
    };
    let places = Places::new(&roster_log);
    let all: BTreeSet<_> = history.iter().map(|(_, e)| e.id()).collect();
    let roster = places.roster(&all);
    assert!(roster.is_administrator(&author.0));
    let d = grant.member.unwrap();
    let state = roster.state(&d).unwrap();
    assert_eq!(state.level, Level::Read);
    assert_eq!(state.label.as_deref(), Some("operator"));
    assert_eq!(state.capabilities.len(), 2);
    assert_eq!(state.history, HistoryMode::WithHistory);
    assert!(matches!(
        roster.standing(&guest.member.unwrap()),
        Some(Standing::Out { .. })
    ));
    assert_eq!(roster.administrators().count(), 1);
    // The policy change follows the genesis, so it alone is maximal: it
    // replaces the whole policy, the agent wait back at its default.
    let policy = places.policy(&all, &genesis.policy);
    assert_eq!(
        policy,
        Policy {
            forbid_agents: true,
            ..Policy::default()
        }
    );
    assert_eq!(roster_log.space(), log.id());
    for (_, event) in &history {
        assert_eq!(
            part_of(&screened, event.id()).changes().len(),
            1,
            "one change each"
        );
    }
}

fn part_of(screened: &frasil_space::ScreenedLog, id: frasil_events::EventId) -> &RosterPart {
    screened.opened(id).and_then(|o| o.part.as_ref()).unwrap()
}
