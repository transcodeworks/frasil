//! ext-guests.json's families of admission and the roster, with feature
//! `ext-guests` (ext-guests.md). The histories are guests.py's, rebuilt
//! here byte for byte by its builder's conventions (`common::history`):
//! each family that gives an event's bytes checks the rebuilding.
//!
//! - `parameters` ("Names, labels and error classes", "The guest
//!   preset");
//! - `sessions` ("The guest preset", "Ending a session"): two sessions
//!   admitted, the first ended in one event, and offer key 13;
//! - `nothing_at_rest_meet` ("Admitting a guest"): concurrent grants keep
//!   the capability by the meet;
//! - `leave_requests` ("The leave request", "A leave request");
//! - `followed` ("Followed");
//! - `off_grid` ("A session with no peer");
//! - `carve_out_guest` ("A carve-out's guest").
//!
//! In a build without the feature, `a_core_joiner_refuses_key_13` reads the
//! `sessions` family's offer as a core joiner does.

mod common;

use common::*;
use frasil_admission::{JoinerType, Offer};
use serde_json::Value as Json;

const GUESTS: &str = "ext-guests.json";

fn guests(name: &str) -> Json {
    frasil_testkit::vectors::family(GUESTS, name)
}

/// admission.md, "Invite links and guests": a core joiner refuses an offer
/// that carries key 13 as `Malformed`.
#[cfg(not(feature = "ext-guests"))]
#[test]
fn a_core_joiner_refuses_key_13() {
    let o = &guests("sessions")["offer_expiry"];
    let offer = bytes(&o["offer"]);
    assert_eq!(
        verdict(Offer::read(&offer, JoinerType::Device)),
        text(&o["a core joiner, key 13 with a session"])
    );
}

#[cfg(feature = "ext-guests")]
mod with_guests {
    use super::common::history::{History, Recipient};
    use super::*;
    use frasil_admission::ext_guests::{LeaveRequest, guest_offer, leave_trigger, on_leave};
    use frasil_admission::grant::{
        Authenticated, ExpectedJoiner, check_grant, open_admitting_event,
    };
    use frasil_admission::snapshot::snapshot_body_keys;
    use frasil_admission::welcome::Welcome;
    use frasil_admission::{Approver, Ctx};
    use frasil_base::cbor::{self, Value};
    use frasil_base::time::Reading;
    use frasil_crypto::device::{DeviceId, KeyRing};
    use frasil_crypto::labels::LEAVE_REQUEST;
    use frasil_events::{EventId, Ref};
    use frasil_space::ext_guests::{
        NOTHING_AT_REST, Preset, SESSION_BYTES, SESSION_LIFETIME_MAX, SESSION_SKEW, end_session,
        followed, followers, is_guest, nothing_at_rest, roster_keys,
    };
    use frasil_space::member::RESERVED_CAPABILITY_PREFIX;
    use frasil_space::{
        Capability, CapabilityMode, Change, Descriptor, DescriptorKind, HistoryMode, Keyring,
        Level, MemberRef, MemberType, OtherLogs, Space, Standing, Via,
    };
    use frasil_testkit::hex;
    use frasil_transport::mailbox::content;
    use serde_json::{Map, json};
    use std::collections::{BTreeMap, BTreeSet};
    use zeroize::Zeroizing;

    /// The rotation step, `rotation_step`'s default.
    const ROTATION_STEP: u64 = 2;

    /// The first 16 bytes of an example: a session or a request ID.
    fn session(name: &str) -> [u8; SESSION_BYTES] {
        example16(name)
    }

    /// The vectors' names of members, by ID.
    type Names = BTreeMap<[u8; 32], String>;

    fn names(r: &History, devices: &[&str]) -> Names {
        devices
            .iter()
            .map(|d| (r.device(d).0, (*d).to_owned()))
            .collect()
    }

    /// admission.py's `summary`: each event's status but the genesis's, and
    /// the roster, `out` for a member removed.
    fn summary(r: &History, space: &Space<'_>, names: &Names) -> Json {
        let events: Map<String, Json> = r
            .events(space)
            .into_iter()
            .map(|(k, v)| (k, Json::from(v)))
            .collect();
        let mut roster = Map::new();
        for (member, standing) in space.roster().iter() {
            let name = names
                .get(&member.id)
                .cloned()
                .unwrap_or_else(|| hex::encode(member.id)[..12].to_owned());
            let entry = match standing {
                Standing::Out { .. } => json!("out"),
                Standing::In(s) => {
                    let mut e = Map::new();
                    e.insert("type".into(), json!(member.kind.name()));
                    e.insert("level".into(), json!(s.level.name()));
                    e.insert("history".into(), json!(s.history.name()));
                    e.insert("via".into(), json!(s.via.name()));
                    if let Some(session) = s.session {
                        e.insert("session".into(), json!(hex::encode(session)));
                    }
                    if let Some(label) = &s.label {
                        e.insert("label".into(), json!(label));
                    }
                    if !s.capabilities.is_empty() {
                        let mut caps: Vec<(String, &str)> = s
                            .capabilities
                            .iter()
                            .map(|c| (c.name.clone(), mode_name(c.mode)))
                            .collect();
                        caps.sort();
                        e.insert("capabilities".into(), json!(caps));
                    }
                    Json::Object(e)
                }
            };
            roster.insert(name, entry);
        }
        json!({"events": events, "roster": roster})
    }

    fn mode_name(mode: CapabilityMode) -> &'static str {
        match mode {
            CapabilityMode::Extends => "extends",
            CapabilityMode::Narrows => "narrows",
        }
    }

    /// A device's keys as a grant names them, and its recipient entry.
    fn recipient(r: &History, name: &str, writes: bool) -> Recipient {
        r.recipient(name, writes)
    }

    /// guests.py's `preset` for a device of the history.
    fn preset_grant(r: &History, name: &str, preset: &Preset) -> Change {
        preset.grant(r.device_keys(name))
    }

    fn resolve<'a>(r: &'a History, keys: &'a Keyring, others: &'a OtherLogs<'a>) -> Space<'a> {
        r.resolve(None, keys, others)
    }

    // -- parameters

    #[test]
    fn parameters() {
        let p = guests("parameters");
        assert_eq!(p["nothing_at_rest"], NOTHING_AT_REST);
        assert_eq!(p["reserved_capability_prefix"], RESERVED_CAPABILITY_PREFIX);
        assert!(NOTHING_AT_REST.starts_with(RESERVED_CAPABILITY_PREFIX));
        assert_eq!(p["leave_request_content"], content::LEAVE_REQUEST);
        assert!(content::implemented(content::LEAVE_REQUEST));
        assert_eq!(text(&p["label"]).as_bytes(), LEAVE_REQUEST);
        assert_eq!(p["session_bytes"].as_u64(), Some(SESSION_BYTES as u64));
        assert_eq!(
            p["session_lifetime_max"].as_u64(),
            Some(SESSION_LIFETIME_MAX)
        );
        assert_eq!(p["session_skew"].as_u64(), Some(SESSION_SKEW));
        assert_eq!(p.as_object().unwrap().len(), 7);
    }

    // -- sessions

    #[test]
    fn sessions() {
        let v = guests("sessions");
        let mut r = History::new("H", "guests/session");
        let s1 = session("guests/session/one");
        let s2 = session("guests/session/two");
        let g1 = Preset {
            nothing_at_rest: true,
            expires_at: Some(1_760_014_400),
            capabilities: vec![Capability {
                name: "drive".into(),
                mode: CapabilityMode::Extends,
            }],
            label: Some("Operator".into()),
            ..Preset::new(Level::Write, s1)
        };
        let g2 = Preset {
            expires_at: Some(1_760_014_400),
            ..Preset::new(Level::Read, s1)
        };
        let g3 = Preset::new(Level::Write, s2);
        let changes = vec![preset_grant(&r, "G1", &g1), preset_grant(&r, "G2", &g2)];
        let recipients = [
            recipient(&r, "H", true),
            recipient(&r, "G1", true),
            recipient(&r, "G2", false),
        ];
        let e1 = r.admit(
            "H",
            changes,
            "H admits G1 and G2 (session one)",
            true,
            &recipients,
        );
        let change = preset_grant(&r, "G3", &g3);
        let recipients = [recipient(&r, "H", true), recipient(&r, "G3", true)];
        r.admit(
            "H",
            vec![change],
            "H admits G3 (session two)",
            true,
            &recipients,
        );
        r.sync(&["H", "G1", "G2", "G3"]);
        r.unit("G1", "G1 writes before the end");
        r.heal("G1", "G1 heals (a key event)");
        r.sync(&["H", "G1"]);
        let vg = r.view["G1"].clone();
        let keys = r.keyring();
        let others = OtherLogs::default();
        let (ends, guests_mid) = {
            let mid = resolve(&r, &keys, &others);
            let ends = end_session(mid.roster(), &s1);
            let names = names(&r, &["H", "G1", "G2", "G3"]);
            let guests: Map<String, Json> = mid
                .roster()
                .members_in()
                .map(|(m, s)| {
                    (
                        names[&m.id].clone(),
                        json!({"guest": is_guest(s), "nothing_at_rest": nothing_at_rest(s)}),
                    )
                })
                .collect();
            (ends, guests)
        };
        assert_eq!(ends.len(), 1);
        let ends = ends.into_iter().next().unwrap();
        let changes_in_the_end = ends.len();
        let end = r.rotate("H", ends, "H ends session one");
        r.view.insert("G1".into(), vg);
        r.unit("G1", "G1 writes, concurrent with the end");
        let g2_member = MemberRef::device(r.device("G2"));
        r.roster_event(
            "G2",
            vec![Change::remove(g2_member)],
            "G2 tries to remove itself",
        );

        assert_eq!(
            hex::encode(r.log.event(e1).unwrap().signed()),
            text(&v["first_admission"])
        );
        assert_eq!(
            hex::encode(r.log.event(end).unwrap().signed()),
            text(&v["end_event"])
        );
        assert_eq!(
            Some(changes_in_the_end as u64),
            v["changes_in_the_end"].as_u64()
        );
        assert_eq!(Json::Object(guests_mid), v["guests"]);
        let keys = r.keyring();
        let space = resolve(&r, &keys, &others);
        let got = summary(&r, &space, &names(&r, &["H", "G1", "G2", "G3"]));
        assert_eq!(got["events"], v["events"]);
        assert_eq!(got["roster"], v["roster"]);

        // Offer key 13.
        let o = &v["offer_expiry"];
        let offer = Offer {
            session: Some([0; 16]),
            expires_at: Some(1_760_100_000),
            ..Offer::new(Level::Write, HistoryMode::FromNowOn)
        };
        assert_eq!(hex::encode(offer.encode()), text(&o["offer"]));
        let read = Offer::read(&offer.encode(), JoinerType::Device);
        assert_eq!(read.as_ref(), Ok(&offer));
        assert_eq!(
            verdict(read),
            text(&o["an ext-guests joiner, key 13 with a session"])
        );
        let mut map = cbor::Map::new();
        map.insert(2, Value::Unsigned(1));
        map.insert(5, Value::Unsigned(0));
        map.insert(13, Value::Unsigned(5));
        assert_eq!(
            verdict(Offer::read(&Value::Map(map).encode(), JoinerType::Device)),
            text(&o["an ext-guests joiner, key 13 without a session"])
        );
        assert_eq!(o.as_object().unwrap().len(), 4);
    }

    // -- nothing_at_rest_meet

    /// guests.py's start of `_nothing_at_rest_meet` and `_leave_vectors`: H
    /// grants K administer, and both sync.
    fn h_and_k(prefix: &str) -> History {
        let mut r = History::new("H", prefix);
        let k = Change::grant_administrator(
            r.device_keys("K"),
            frasil_space::change::MAX_RANK,
            HistoryMode::WithHistory,
            Via::Code,
        );
        r.rotate("H", vec![k], "H grants K administer");
        r.sync(&["H", "K"]);
        r
    }

    #[test]
    fn nothing_at_rest_meet() {
        let v = guests("nothing_at_rest_meet");
        let mut r = h_and_k("guests/meet");
        let s = session("guests/meet/session");
        let with = Preset {
            nothing_at_rest: true,
            ..Preset::new(Level::Write, s)
        };
        let change = preset_grant(&r, "G", &with);
        r.rotate_flags(
            "H",
            vec![change],
            "H admits G, nothing at rest",
            false,
            true,
        );
        let change = preset_grant(&r, "G", &Preset::new(Level::Write, s));
        r.rotate_flags("K", vec![change], "K admits G", false, true);
        let keys = r.keyring();
        let others = OtherLogs::default();
        let space = resolve(&r, &keys, &others);
        let got = summary(&r, &space, &names(&r, &["H", "K", "G"]));
        assert_eq!(got["events"], v["events"]);
        let state = space
            .roster()
            .state(&MemberRef::device(r.device("G")))
            .unwrap();
        let caps: Vec<Json> = state
            .capabilities
            .iter()
            .map(|c| json!([c.name, c.mode.code()]))
            .collect();
        assert_eq!(json!(caps), v["capabilities"]);
        assert_eq!(Some(nothing_at_rest(state)), v["nothing_at_rest"].as_bool());
    }

    // -- leave_requests

    #[test]
    fn leave_requests() {
        let v = guests("leave_requests");
        let mut r = h_and_k("guests/leave");
        let s = session("guests/leave/session");
        let change = preset_grant(&r, "G", &Preset::new(Level::Write, s));
        let gr = r.rotate_flags("H", vec![change], "H admits G", false, true);
        r.sync(&["H", "K", "G"]);
        let (h, k, g) = (r.device("H"), r.device("K"), r.device("G"));
        assert_eq!(
            text(&v["guest"]["ed25519_seed"]),
            hex::encode(History::seed("guests/leave", "G"))
        );
        let rid = example16("guests/leave/request");
        let request =
            |space: [u8; 32], member: DeviceId, grants: Vec<EventId>, device| LeaveRequest {
                space,
                member: MemberRef::device(member),
                grants,
                request: rid,
                device,
            };
        let space_id = r.id().0;
        let leave = request(space_id, g, vec![gr], g);
        let signed = leave.sign(&r.signer("G"));
        assert_eq!(hex::encode(leave.encode()), text(&v["record"]));
        assert_eq!(hex::encode(&signed), text(&v["signed"]));
        assert_eq!(hex::encode(leave_trigger(&signed)), text(&v["trigger"]));
        let read = LeaveRequest::read(&leave.encode()).unwrap();
        assert_eq!((read.space(), read.device()), (&leave.space, &leave.device));

        let keys = r.keyring();
        let others = OtherLogs::default();
        let decided = |signed: &[u8], me: &DeviceId| {
            let space = resolve(&r, &keys, &others);
            let mut ring = KeyRing::new();
            for device in [h, k, g] {
                ring.add_device(roster_keys(&space, &device).unwrap());
            }
            on_leave(
                signed,
                &space,
                me,
                &[h, k],
                &ring,
                |_, _| false,
                ROTATION_STEP,
            )
        };
        let mut decisions = Map::new();
        for (name, me) in [("H", h), ("K", k)] {
            let d = decided(&signed, &me).unwrap().unwrap();
            decisions.insert(
                name.into(),
                json!({"outcome": "Remove", "rank": d.rank, "delay": d.delay}),
            );
        }
        assert_eq!(Json::Object(decisions), v["decisions"]);

        // Refused requests.
        let forged = request(space_id, g, vec![gr], k).sign(&r.signer("K"));
        let stale = request(
            space_id,
            g,
            vec![EventId(example("guests/leave/old-grant"))],
            g,
        )
        .sign(&r.signer("G"));
        let tampered = {
            let other = LeaveRequest {
                request: example16("guests/leave/other-request"),
                ..leave.clone()
            };
            let Ok(Value::Map(outer)) = cbor::decode(&signed) else {
                panic!("a signed request is a map");
            };
            let mut map = cbor::Map::new();
            map.insert(1, Value::from(other.encode()));
            map.insert(2, outer[&2].clone());
            Value::Map(map).encode()
        };
        let elsewhere = request(example("guests/leave/other"), g, vec![gr], g).sign(&r.signer("G"));
        let k_grants: Vec<EventId> = {
            let space = resolve(&r, &keys, &others);
            let state = space.roster().state(&MemberRef::device(k)).unwrap();
            state.grants.iter().copied().collect()
        };
        let administers = request(space_id, k, k_grants, k).sign(&r.signer("K"));
        let refusals = [
            ("signed by another device", forged),
            ("naming a grant no longer in force", stale),
            ("a changed request ID", tampered),
            ("for another space", elsewhere),
            ("a device member at administer", administers),
        ];
        let want = v["refusals"].as_array().unwrap();
        assert_eq!(want.len(), refusals.len());
        for ((name, signed), want) in refusals.iter().zip(want) {
            assert_eq!(want["name"], *name);
            let got = verdict(decided(signed, &h));
            assert_eq!(got, text(&want["outcome"]), "{name}");
        }

        // The first in rank removes G, which rotates the content key only.
        let removal = r.rotate(
            "K",
            vec![Change::remove(MemberRef::device(g))],
            "K removes G on its leave request",
        );
        assert_eq!(
            hex::encode(r.log.event(removal).unwrap().signed()),
            text(&v["removal"])
        );
        let keys = r.keyring();
        let space = resolve(&r, &keys, &others);
        assert_eq!(
            summary(&r, &space, &names(&r, &["H", "K", "G"])),
            v["after"]
        );
    }

    // -- followed

    fn reading(value: &Json) -> Reading {
        Reading {
            timeline: value["timeline"].as_u64().unwrap(),
            wall: value["wall"].as_u64(),
            run: value["run"].as_u64().unwrap(),
        }
    }

    #[test]
    fn followed_events() {
        let v = guests("followed");
        let mut r = History::new("H", "guests/followed");
        for who in ["W", "X"] {
            let grant = Change::grant_device(
                r.device_keys(who),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            );
            r.rotate("H", vec![grant], &format!("H grants {who} write"));
        }
        r.sync(&["H", "W", "X"]);
        let u1 = r.unit("W", "W's first unit");
        r.sync(&["H", "W"]);
        r.unit("H", "H's unit, following W's first");
        r.sync(&["H", "W"]);
        let u2 = r.unit("W", "W's second unit");
        r.sync(&["W", "X"]);
        r.unit("X", "X's unit, following W's second");
        let x = MemberRef::device(r.device("X"));
        r.rotate_with(
            "H",
            vec![Change::remove(x)],
            "H removes X, concurrently",
            true,
        );
        let u3 = r.unit("W", "W's third unit");
        let u4 = r.unit("W", "W's fourth unit, following its own third");
        let keys = r.keyring();
        let others = OtherLogs::default();
        let space = resolve(&r, &keys, &others);
        let got = summary(&r, &space, &names(&r, &["H", "W", "X"]));
        assert_eq!(got["events"], v["events"]);

        assert_eq!(v["device"], "W");
        let w = r.device("W");
        let admitted = reading(&v["admitted"]);
        let own = v["own_events"].as_array().unwrap();
        let mut signed_at = BTreeMap::new();
        for (id, row) in [u1, u2, u3, u4].into_iter().zip(own) {
            assert_eq!(r.names[&id], text(&row["event"]));
            signed_at.insert(id, reading(&row["signed_at"]));
        }
        let by = followers(&space, &w);
        assert_eq!(by.len(), own.len());
        for row in own {
            let id = *r
                .names
                .iter()
                .find(|(_, n)| *n == text(&row["event"]))
                .unwrap()
                .0;
            let names: Vec<&str> = by[&id].iter().map(|i| r.names[i].as_str()).collect();
            assert_eq!(json!(names), row["followed_by"], "{}", text(&row["event"]));
        }
        let got = followed(&space, &w.0, &signed_at, admitted);
        assert_eq!(got, reading(&v["followed"]));
    }

    // -- off_grid

    #[test]
    fn off_grid() {
        let v = guests("off_grid");
        let prefix = "guests/offgrid";
        let mut r = History::new("host", prefix);
        assert_eq!(
            hex::encode(r.log.event(r.genesis).unwrap().signed()),
            text(&v["genesis"])
        );
        assert_eq!(hex::encode(r.id().0), text(&v["space"]));
        let guest = Device::fixture(History::seed(prefix, "guest"));
        let host = r.device("host");
        let s = session("guests/offgrid/session");
        let preset = Preset {
            nothing_at_rest: true,
            label: Some("Guest".into()),
            ..Preset::new(Level::Write, s)
        };
        let offer = guest_offer(&preset);
        let channel = example("guests/offgrid/exporter");

        // The admission code over the nearby connection, with its channel.
        let (mut joiner, request) = joiner(
            start(Ctx::Space, prefix, T_EXPIRES, "Sam's laptop", &channel),
            guest.keys(),
        );
        let heads = r.heads("host");
        let mut approver = Approver::new(side(
            host,
            Ctx::Space,
            r.id().0,
            heads,
            offer.encode(),
            "Ada's space",
            &channel,
        ))
        .unwrap();
        let response = approver
            .on_request_with(
                &request,
                Some(T_REQUEST),
                draw(prefix, "guests/offgrid/enc-1"),
            )
            .unwrap();
        let revealed = joiner
            .on_response_with(&response, T_RESPONSE, &eseed("guests/offgrid/enc-2"))
            .unwrap();
        let approved = approver
            .on_reveal(&revealed.message, Some(T_REVEAL))
            .unwrap()
            .unwrap();
        assert_eq!(approved.code, revealed.code);
        let codes = [approved.code.to_string(), revealed.code.to_string()];
        assert_eq!(json!(codes), v["codes"]);

        // The host signs the grant, a break, and delivers to both.
        let change = preset.grant(r.device_keys("guest"));
        assert_eq!(
            change,
            frasil_admission::grant::grant_change(&offer, &approved.reveal).unwrap()
        );
        let recipients = [
            recipient(&r, "host", true),
            Recipient {
                keys: guest.device_keys(),
                writes: true,
            },
        ];
        let g = r.admit(
            "host",
            vec![change],
            "the host admits the guest",
            true,
            &recipients,
        );
        let event = r.log.event(g).unwrap().clone();
        assert_eq!(hex::encode(event.signed()), text(&v["grant"]));

        // The guest checks the grant.
        let visible = frasil_keys::body::VisiblePart::read(
            event.unverified_body(),
            event.author(),
            event.seq(),
        )
        .unwrap();
        let delivery = &visible.deliveries[0];
        let (index, _) = frasil_keys::wraps::find_own_wrap(
            &delivery.wraps,
            &r.id().0,
            delivery.key_name.as_ref(),
            delivery.grant_name.as_ref(),
            &guest.device_id(),
            &guest.xwing_seed,
        )
        .unwrap();
        let welcome = Welcome {
            space: r.id().0,
            event: g,
            key_name: delivery
                .key_name
                .as_ref()
                .map(frasil_keys::KeyName::encode)
                .unwrap(),
            grant_name: Vec::new(),
            wrap: delivery.wraps[index].clone(),
            approver: host,
            peers: Vec::new(),
            snapshot: None,
        };
        let opened =
            open_admitting_event(&event, &welcome, &guest.device_id(), &guest.xwing_seed).unwrap();
        let response = joiner.response().unwrap();
        let offer_read = Offer::read(&response.offer, JoinerType::Device).unwrap();
        assert_eq!(offer_read, offer);
        let checked = check_grant(
            &event,
            &opened,
            &r.log.past(g),
            &Authenticated {
                approver: &response.approver,
                log: &response.log,
                heads: &response.heads,
                offer: &offer_read,
            },
            &ExpectedJoiner::of(&approved.reveal),
            Via::Code,
        );
        assert_eq!(verdict(checked), text(&v["grant_check"]));

        // The two replicas sync; the guest edits; the host ends the
        // session.
        r.sync(&["host", "guest"]);
        r.unit("guest", "the guest edits");
        r.sync(&["host", "guest"]);
        let keys = r.keyring();
        let others = OtherLogs::default();
        let ends = end_session(resolve(&r, &keys, &others).roster(), &s);
        assert_eq!(ends.len(), 1);
        let end = r.rotate(
            "host",
            ends.into_iter().next().unwrap(),
            "the host ends the session",
        );
        assert_eq!(
            hex::encode(r.log.event(end).unwrap().signed()),
            text(&v["end"])
        );
        let keys = r.keyring();
        let space = resolve(&r, &keys, &others);
        assert_eq!(
            summary(&r, &space, &names(&r, &["host", "guest"])),
            v["result"]
        );
    }

    // -- carve_out_guest

    /// A keyring of body keys alone, and some rotations' content keys.
    fn body_keyring(
        bodies: &BTreeMap<EventId, Zeroizing<[u8; 32]>>,
        rotations: &[(EventId, [u8; 32])],
    ) -> Keyring {
        let mut keys = Keyring::default();
        for (id, key) in bodies {
            keys.bodies.insert(*id, vec![key.clone()]);
        }
        for (id, secret) in rotations {
            keys.rotations.insert(*id, Zeroizing::new(*secret));
        }
        keys
    }

    #[test]
    fn carve_out_guest() {
        let v = guests("carve_out_guest");
        // P: C and M write; X is removed. The same keys sign C in both.
        let mut p = History::new("PA", "guests/carve/P");
        p.share_seed("C", History::seed("guests/carve/N", "C"));
        for who in ["C", "M", "X"] {
            let grant = Change::grant_device(
                p.device_keys(who),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            );
            p.rotate("PA", vec![grant], &format!("PA grants {who} write"));
        }
        let x = MemberRef::device(p.device("X"));
        p.rotate_with("PA", vec![Change::remove(x)], "PA removes X", true);
        p.sync(&["PA", "M", "C"]);

        // N, a carve-out of P, by C: P at write and the guest from now on.
        let descriptor = Descriptor {
            kind: DescriptorKind::CarveOut,
            parent: Some(p.id().0),
            application: None,
        };
        let mut n = History::new_with("C", "guests/carve/N", descriptor);
        assert_eq!(n.device("C"), p.device("C"));
        n.share_seed("M", History::seed("guests/carve/P", "M"));
        let s = session("guests/carve/session");
        let guest_grant = preset_grant(&n, "guest", &Preset::new(Level::Write, s));
        let p_space = MemberRef {
            kind: MemberType::Space,
            id: p.id().0,
        };
        let changes = vec![
            Change::grant(p_space, Level::Write, HistoryMode::WithHistory, Via::None),
            guest_grant,
        ];
        let refs: Vec<Ref> = p
            .heads("C")
            .into_iter()
            .map(|head| Ref {
                log: p.id(),
                id: head,
            })
            .collect();
        let recipients = [recipient(&n, "C", true), recipient(&n, "guest", true)];
        let first = n.admit_refs(
            "C",
            changes,
            "N's first update: P at write, the guest from now on",
            true,
            false,
            &recipients,
            refs,
        );
        n.sync(&["C", "M", "guest"]);
        let unit = n.unit("M", "M writes in N through P");
        assert_eq!(n.names[&unit], text(&v["unit"]));

        // What a member of both holds, and what the guest's snapshot
        // carries: every body key of P, and those of N the guest cannot
        // open with the first update's content key.
        let others = OtherLogs::default();
        let p_all = p.keyring();
        let p_full = resolve(&p, &p_all, &others);
        let p_keys = snapshot_body_keys(&p_full, &BTreeSet::new());
        let n_all = n.keyring();
        let with_p = OtherLogs::default().with_space(&p_full);
        let n_full = resolve(&n, &n_all, &with_p);
        let n_keys = snapshot_body_keys(&n_full, &BTreeSet::from([first]));
        let sorted_names = |h: &History, ids: &mut dyn Iterator<Item = EventId>| {
            let mut out: Vec<String> = ids.map(|i| h.names[&i].clone()).collect();
            out.sort();
            out
        };
        let carries = &v["snapshot_carries"];
        assert_eq!(
            json!(sorted_names(&n, &mut n_keys.keys().copied())),
            carries["N body keys"]
        );
        let p_events: Vec<String> = p
            .log
            .canonical()
            .into_iter()
            .map(|i| p.names[&i].clone())
            .collect();
        assert_eq!(json!(p_events), carries["P events"]);
        assert_eq!(
            json!(sorted_names(&p, &mut p_keys.keys().copied())),
            carries["P body keys"]
        );

        // The guest resolves P from the snapshot alone, then N with P.
        let p_guest_keys = body_keyring(&p_keys, &[]);
        let p_guest = resolve(&p, &p_guest_keys, &others);
        let p_names = names(&p, &["PA", "C", "M", "X"]);
        let got = summary(&p, &p_guest, &p_names);
        assert_eq!(got["events"], v["P"]["events"]);
        assert_eq!(got["roster"], v["P"]["roster"]);

        let n_guest_keys = body_keyring(&n_keys, &[(first, n.krot[&first])]);
        let with_p = OtherLogs::default().with_space(&p_guest);
        let n_guest = resolve(&n, &n_guest_keys, &with_p);
        let mut n_names = names(&n, &["C", "guest", "M"]);
        n_names.insert(p.id().0, "P".into());
        let got = summary(&n, &n_guest, &n_names);
        assert_eq!(got["events"], v["N_with_P"]["events"]);
        assert_eq!(got["roster"], v["N_with_P"]["roster"]);

        let n_alone = resolve(&n, &n_guest_keys, &others);
        let got = summary(&n, &n_alone, &n_names);
        assert_eq!(got["events"], v["N_without_P"]);
    }
}
