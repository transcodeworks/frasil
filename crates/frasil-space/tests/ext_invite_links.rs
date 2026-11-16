//! ext-invite-links.json's families of the roster and the key graph, with
//! feature `ext-invite-links`:
//!
//! - `encodings` (ext-invite-links.md, "The invite grant and the
//!   successor"): an invite grant and a successor, byte for byte, opened
//!   under the content key their builder derived;
//! - `refused_changes`: grants and successors refused by shape;
//! - `keys` ("Keys"): who receives what, and two key-graph histories, read
//!   by [`model::Model`] as keys.json's are.

#![cfg(feature = "ext-invite-links")]

mod common;
mod model;

use common::{class, example};
use frasil_base::cbor;
use frasil_events::decode;
use frasil_keys::RotationSet;
use frasil_keys::body::VisiblePart;
use frasil_keys::derive::{SecretKind, body_key, state_secret};
use frasil_keys::ext_invite_links::invite_bundle_contents;
use frasil_space::change::Op;
use frasil_space::keygraph::{Holdings, Kind, Member, plan};
use frasil_space::part::{PartContext, RosterPart};
use frasil_space::{Change, HistoryMode, Level, Limits, MemberType, Via};
use frasil_testkit::hex;
use model::Model;
use serde_json::{Value as Json, json};
use std::collections::{BTreeMap, BTreeSet};

const FILE: &str = "ext-invite-links.json";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn bytes(value: &Json, key: &str) -> Vec<u8> {
    hex::decode(text(value, key)).unwrap()
}

fn array<const N: usize>(value: &Json, key: &str) -> [u8; N] {
    bytes(value, key).try_into().unwrap()
}

// -- refused_changes

#[test]
fn refused_changes() {
    let cases = family("refused_changes");
    for case in cases.as_array().unwrap() {
        let name = text(case, "name");
        let value = cbor::decode(&bytes(case, "change")).unwrap();
        let got = class(Change::read(&value, Some(&[0; 32]), &Limits::PROTOCOL));
        assert_eq!(got, Some(text(case, "class")), "{name}");
    }
}

// -- encodings

/// The roster part of a space event of the invite's history, opened under
/// `secret`, the content key of the state it is sealed under.
fn roster_part(signed: &[u8], secret: &[u8; 32], space: &[u8; 32]) -> RosterPart {
    let event = decode(signed).unwrap();
    let visible = VisiblePart::read(event.unverified_body(), event.author(), event.seq()).unwrap();
    let key = body_key(secret, space, event.author(), event.seq());
    let inner = visible
        .open(&key, space, event.author(), event.seq())
        .unwrap();
    let part = inner.roster.unwrap();
    let context = PartContext {
        author: event.author(),
        space: Some(space),
        rotates: visible.rotates(),
        limits: &Limits::PROTOCOL,
    };
    let read = RosterPart::read(&part, &context).unwrap();
    assert_eq!(read.encode(), part, "one encoding");
    read
}

#[test]
fn encodings() {
    let e = family("encodings");
    assert_eq!(e["member_type_invite"], json!(MemberType::Invite.code()));
    assert_eq!(e["op_succeed"], json!(Op::Succeed.code()));
    assert_eq!(e["change_keys"]["expires_at"], json!(13));
    assert_eq!(
        e["change_keys"]["claims"],
        json!(frasil_space::change::key::CLAIMS)
    );
    let derivations = family("derivations");
    let invite_key: [u8; 32] = array(&derivations["keys"], "device_id");
    let space: [u8; 32] = array(&e, "space");
    let invite = decode(&bytes(&e, "invite_event")).unwrap();
    assert_eq!(hex::encode(invite.id().0), text(&e, "invite_event_id"));
    let successor = decode(&bytes(&e, "successor_event")).unwrap();
    assert_eq!(hex::encode(successor.id().0), text(&e, "successor_id"));
    assert_eq!(
        successor.author().0,
        invite_key,
        "the successor is signed by K"
    );
    // The invite grant: a rotation under its own content key.
    let k_invite = example("admission/invites/A invites by link/content-key");
    let part = roster_part(&bytes(&e, "invite_event"), &k_invite, &space);
    let [grant] = part.changes() else {
        panic!("one change")
    };
    assert_eq!(grant.op, Op::Grant);
    assert_eq!(
        grant.member,
        Some(frasil_space::ext_invite_links::invite_member(invite_key))
    );
    assert_eq!(grant.level, Some(Level::Write));
    assert_eq!(grant.history, Some(HistoryMode::FromNowOn));
    assert_eq!(grant.via, Some(Via::Link));
    assert_eq!(grant.label.as_deref(), Some("Invited"));
    assert_eq!(grant.expires_at, Some(1_760_604_800));
    assert_eq!(
        grant.claims,
        Some(frasil_space::ext_invite_links::CLAIMS_PERSON)
    );
    let keys = grant.keys.as_ref().unwrap();
    assert_eq!(
        hex::encode(keys.keys.xwing().unwrap()),
        text(&derivations["keys"], "xwing")
    );
    assert_eq!(
        hex::encode(keys.ed.0),
        text(&derivations["keys"], "identity")
    );
    assert_eq!(keys.device_id().0, invite_key);
    // The successor: sealed under the invite's state, one change granting
    // Bob, and it does not rotate.
    let state = RotationSet::single(invite.id());
    let k_state = state_secret(
        SecretKind::Content,
        &frasil_events::EventId(space),
        &state,
        &[k_invite],
    )
    .unwrap();
    let part = roster_part(&bytes(&e, "successor_event"), &k_state, &space);
    let [succeed] = part.changes() else {
        panic!("one change")
    };
    assert_eq!(succeed.op, Op::Succeed);
    assert_eq!(
        succeed.member,
        Some(frasil_space::MemberRef::person(example(
            "admission/person/bob"
        )))
    );
}

// -- keys

fn slot_names(slots: frasil_keys::bundle::Slots) -> Vec<&'static str> {
    [
        (slots.content, "content"),
        (slots.upload, "upload"),
        (slots.grant, "grant"),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, name)| name)
    .collect()
}

#[test]
fn who_gets_what() {
    let keys = family("keys");
    for row in keys["who_gets_what"].as_array().unwrap() {
        assert_eq!(row["invite"], json!(true));
        let propagates = row["propagates"].as_bool().unwrap();
        let got = slot_names(invite_bundle_contents(propagates));
        assert_eq!(json!(got), row["bundle"], "{}", text(row, "recipient"));
    }
}

#[test]
fn key_histories() {
    let keys = family("keys");
    let mut failures = Vec::new();
    for history in keys["histories"].as_array().unwrap() {
        let name = text(history, "name");
        for checkpoint in history["checkpoints"].as_array().unwrap() {
            let model = Model::new(history, checkpoint);
            let label = format!("{name} / {}", text(checkpoint, "name"));
            failures.extend(check_checkpoint(&model, checkpoint, &label));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// The checkpoint comparison of keys.json's histories (tests/keygraph.rs).

/// Every difference between a checkpoint as the key graph computes it and
/// as the vector gives it.
fn check_checkpoint(model: &Model, checkpoint: &Json, label: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |what: &str, got: Json, want: &Json| {
        if got != *want {
            out.push(format!("{label}: {what}\n  got  {got}\n  want {want}"));
        }
    };
    let graph = model.key_graph();
    // A view after gap_key_timeout has passed.
    let timed_out = checkpoint["timed_out"].as_bool().unwrap_or(false);
    // Each principal's floor: this space's responses to the granted
    // space's breaks before which it is entitled to nothing.
    for (principal, want) in checkpoint
        .get("principal_floor")
        .and_then(Json::as_object)
        .into_iter()
        .flatten()
    {
        let member = graph
            .members(Kind::Content)
            .into_keys()
            .find(|m| model.member_name(m) == *principal);
        let got: Vec<&str> = match &member {
            Some(Member::Principal(p)) => graph.floors(p).iter().map(|&f| model.label(f)).collect(),
            _ => Vec::new(),
        };
        check(&format!("floor of {principal}"), json!(got), want);
    }
    // The merged roster.
    let roster: serde_json::Map<String, Json> = graph
        .members(Kind::Content)
        .iter()
        .map(|(m, s)| {
            (
                model.member_name(m),
                json!({"level": model::level_name(s.level), "session": s.session}),
            )
        })
        .collect();
    check("roster", Json::Object(roster), &checkpoint["roster"]);
    // The current states and their secrets.
    let content = graph.current(Kind::Content).unwrap();
    let grant = graph.current(Kind::Grant).unwrap();
    let content_key = graph
        .current_secret(Kind::Content, |r| model.secret(r, "content"))
        .unwrap();
    let grant_seed = graph
        .current_secret(Kind::Grant, |r| model.secret(r, "grant"))
        .unwrap();
    let current = json!({
        "content": model.state_name(&content),
        "content_key": hex::encode(*content_key),
        "grant": model.state_name(&grant),
        "grant_seed": hex::encode(*grant_seed),
    });
    check("current", current, &checkpoint["current"]);
    // The deliveries each graph calls for, with the first device present
    // that can make each.
    let room: Vec<String> = checkpoint["room"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap().to_owned())
        .collect();
    let artifacts = model.artifacts(&checkpoint["artifacts"]);
    for (kind, key) in [(Kind::Content, "content"), (Kind::Grant, "grant")] {
        let p = plan(&graph, &artifacts, kind, &room, timed_out);
        let by = |d: &Option<String>| d.clone().unwrap_or_else(|| "nobody in the room".into());
        let wraps: Vec<String> = p
            .wraps
            .iter()
            .map(|w| {
                format!(
                    "{} to {} by {} ({})",
                    model.state_name(&w.state),
                    w.device,
                    by(&w.by),
                    w.why.name()
                )
            })
            .collect();
        let links: Vec<String> = p
            .links
            .iter()
            .map(|l| {
                format!(
                    "{} > {} by {}",
                    model.state_name(&l.under),
                    model.state_name(&l.reaches),
                    by(&l.by)
                )
            })
            .collect();
        let gaps: Vec<String> = p.gaps.iter().map(|g| model.state_name(g)).collect();
        let waiting: Vec<String> = p
            .waiting
            .iter()
            .map(|(k, d)| format!("{} to {d}", model.state_name(k)))
            .collect();
        let got = json!({
            "wraps": wraps, "links": links, "gaps": gaps, "waiting": waiting,
            "heal": p.heal.map(|h| h.name()),
        });
        check(&format!("plan {key}"), got, &checkpoint["plan"][key]);
    }
    // Entitlement, over every rotation of the view and the current state;
    // for the grant graph, over grant rotations and the grant state.
    let mut states: BTreeSet<RotationSet> = graph
        .events()
        .iter()
        .copied()
        .filter(|&i| graph.is_rotation(i, Kind::Content))
        .map(RotationSet::single)
        .collect();
    states.insert(content.clone());
    let mut entitlement = serde_json::Map::new();
    for member in graph.members(Kind::Content).keys() {
        let mut row: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for (kind, key) in [(Kind::Content, "content"), (Kind::Grant, "grant")] {
            for state in &states {
                let grant_state = *state == grant
                    || (state.len() == 1 && graph.is_rotation(state.ids()[0], Kind::Grant));
                if kind == Kind::Grant && !grant_state {
                    continue;
                }
                if !graph.entitled(member, state, kind) {
                    continue;
                }
                if graph.restored_pending(member, state, kind, timed_out) {
                    row.entry("pending_stability")
                        .or_default()
                        .push(format!("{key} {}", model.state_name(state)));
                } else {
                    row.entry(key).or_default().push(model.state_name(state));
                }
            }
        }
        if !row.is_empty() {
            let mut value = serde_json::Map::new();
            for key in ["content", "grant", "pending_stability"] {
                value.insert(key.into(), json!(row.remove(key).unwrap_or_default()));
            }
            entitlement.insert(model.member_name(member), Json::Object(value));
        }
    }
    check(
        "entitlement",
        Json::Object(entitlement),
        &checkpoint["entitlement"],
    );
    // The stated reach queries.
    for query in checkpoint["reaches"].as_array().unwrap() {
        let kind = match text(query, "kind") {
            "content" => Kind::Content,
            _ => Kind::Grant,
        };
        let devices: Vec<String> = query["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap().to_owned())
            .collect();
        let state = model.state(text(query, "state"));
        let holdings = Holdings::new(&graph, &artifacts, kind);
        check(
            &format!("reaches {query}"),
            Json::Bool(holdings.reaches(&devices, &state)),
            &query["result"],
        );
    }
    out
}
