//! transport.md, sections 2.6 and 3.2 to 3.7: the `member_handshake`,
//! `state_choice`, `member_refusals` and `roster_check` families, step by
//! step and through the session state machine.

mod common;

use common::*;
use frasil_events::EventId;
use frasil_keys::RotationSet;
use frasil_keys::derive::{SecretKind, state_secret};
use frasil_transport::frame::{MessageType, frame};
use frasil_transport::member::{
    self, Reply, Role, SentOffer, identify, identify_input, match_offer, member_key,
    offered_states, read_offer, verify_identify,
};
use frasil_transport::messages::Admit;
use frasil_transport::roster::{self, Ended, Path, Probation, Serving, Standing, Verdict};
use frasil_transport::session::{Event, MemberSession};
use frasil_transport::{Code, TransportClass};
use serde_json::Value as Json;

fn labels(value: &Json) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|l| text(l).to_owned())
        .collect()
}

/// The single rotations of a merged label, such as `{C,D}`.
fn alone(label: &str) -> Vec<String> {
    let inner = &label[1..label.len() - 1];
    if !inner.contains(',') {
        return Vec::new();
    }
    inner.split(',').map(|r| format!("{{{r}}}")).collect()
}

#[test]
fn content_and_member_keys() {
    let h = Handshake::load();
    let json = &h.json;
    let space = EventId(array(&json["space"]));
    let rotation = |n: &str| EventId(array(&json["rotations"][n]));
    let key = |n: &str| array::<32>(&json["rotation_keys"][n]);
    for (label, expected) in json["content_keys"].as_object().unwrap() {
        let names: Vec<&str> = label[1..label.len() - 1].split(',').collect();
        let state = RotationSet::new(names.iter().map(|n| rotation(n))).unwrap();
        let inputs: Vec<[u8; 32]> = state
            .ids()
            .iter()
            .map(|id| key(names.iter().find(|n| rotation(n) == *id).unwrap()))
            .collect();
        let secret = state_secret(SecretKind::Content, &space, &state, &inputs).unwrap();
        assert_eq!(*secret, array::<32>(expected), "{label}");
        assert_eq!(
            *member_key(&secret),
            array::<32>(&json["member_keys"][label]),
            "{label}"
        );
    }
}

#[test]
fn member_handshake() {
    let h = Handshake::load();
    let json = &h.json;
    let channel = h.channel();
    let (e_d, e_l) = (h.endpoint("dialer"), h.endpoint("listener"));

    // The offer: the dialer's current state merges C and D.
    let offer_json = &json["offer"];
    let states = offered_states(
        "{C,D}".to_owned(),
        alone("{C,D}"),
        ["{C}", "{B}", "{A}"].map(str::to_owned),
    );
    assert_eq!(states, labels(&offer_json["offered_states"]));
    let mut sent = SentOffer::new_with(
        0,
        &channel,
        states.iter().map(|s| (s.clone(), h.secret(s))),
        array(&offer_json["nonce"]),
        &fillers(&offer_json["tags"], states.len()),
    );
    let tags: Vec<[u8; 32]> = offer_json["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(array)
        .collect();
    assert_eq!(sent.tags(), tags);
    assert_eq!(sent.message(), bytes(&offer_json["message"]));
    assert_eq!(frame(sent.message()), bytes(&offer_json["frame"]));

    // The listener's match.
    let offer = read_offer(&control(sent.message()), Role::Dialer, 0).unwrap();
    let found = match_offer(&offer, &channel, h.candidates(&json["listener_candidates"])).unwrap();
    assert_eq!(u64::from(found.index), number(&json["match"]["index"]));
    assert_eq!(found.state, text(&json["match"]["state"]));

    // The answer.
    let answer_json = &json["answer"];
    let answer = found.answer_with(&offer, &channel, &e_d, &e_l, array(&answer_json["nonce"]));
    assert_eq!(answer.core, bytes(&answer_json["core"]));
    assert_eq!(answer.transcript, array(&answer_json["transcript"]));
    assert_eq!(answer.proof, array(&answer_json["proof"]));
    assert_eq!(answer.message, bytes(&answer_json["message"]));
    assert_eq!(frame(&answer.message), bytes(&answer_json["frame"]));

    // The dialer verifies it.
    let reply = sent
        .read_reply(&control(&answer.message), &channel, &e_d, &e_l)
        .unwrap();
    let th = answer.transcript;
    assert_eq!(
        reply,
        Reply::Answered {
            index: 1,
            transcript: th
        }
    );
    assert_eq!(sent.take_state(1).as_deref(), Some("{C}"));

    // Both Identify messages.
    for (side, role) in [("dialer", Role::Dialer), ("listener", Role::Listener)] {
        let case = &json["identify"][side];
        assert_eq!(u64::from(role.byte()), number(&case["role"]));
        let key = h.signer(side);
        assert_eq!(key.to_bytes(), array(&case["ed_kc"]));
        assert_eq!(h.device_id(side).0, array::<32>(&case["device_id"]));
        assert_eq!(identify_input(&th, role, &key), bytes(&case["signed"]));
        let message = identify(&h.identity_seed(side), &key.kc, &th, role);
        assert_eq!(message, bytes(&case["message"]));
        assert_eq!(frame(&message), bytes(&case["frame"]));
        let read = control(&message);
        assert_eq!(
            read.get(2).unwrap().as_bytes().unwrap(),
            bytes(&case["signature"])
        );
        assert_eq!(verify_identify(&read, &th, role), Ok(key));
    }

    // An Admit.
    assert_eq!(frame(&Admit { attach: 0 }.encode()), bytes(&json["admit"]));

    // A second attach's offer, of {C} alone.
    let second = &json["second_attach_offer"];
    let states = labels(&second["offered_states"]);
    let sent2 = SentOffer::new_with(
        u32::try_from(number(&second["attach"])).unwrap(),
        &channel,
        states.iter().map(|s| (s.clone(), h.secret(s))),
        array(&second["nonce"]),
        &fillers(&second["tags"], states.len()),
    );
    let tags: Vec<[u8; 32]> = second["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(array)
        .collect();
    assert_eq!(sent2.tags(), tags);
    assert_eq!(sent2.message(), bytes(&second["message"]));
    let offer = read_offer(&control(sent2.message()), Role::Dialer, 0).unwrap();
    let found = match_offer(&offer, &channel, h.candidates(&Json::from(vec!["{C}"]))).unwrap();
    assert_eq!(found.state, "{C}");
}

#[test]
fn state_choice() {
    let h = Handshake::load();
    let channel = h.channel();
    for row in family("state_choice").as_array().unwrap() {
        let description = text(&row["description"]);
        let current = text(&row["initiator_current"]).to_owned();
        let offered = labels(&row["offered_states"]);
        // The states it held as current before are the offered ones past
        // its current state and that state's single rotations.
        let singles = alone(&current);
        let history: Vec<String> = offered
            .iter()
            .filter(|s| **s != current && !singles.contains(s))
            .cloned()
            .collect();
        assert_eq!(
            offered_states(current.clone(), singles, history),
            offered,
            "{description}"
        );
        let sent = SentOffer::new_with(
            0,
            &channel,
            offered.iter().map(|s| (s.clone(), h.secret(s))),
            array(&row["nonce"]),
            &fillers(&row["tags"], offered.len()),
        );
        let tags: Vec<[u8; 32]> = row["tags"].as_array().unwrap().iter().map(array).collect();
        assert_eq!(sent.tags(), tags, "{description}");
        let offer = read_offer(&control(sent.message()), Role::Dialer, 0).unwrap();
        match match_offer(&offer, &channel, h.candidates(&row["responder_holds"])) {
            Ok(found) => {
                assert_eq!(
                    u64::from(found.index),
                    number(&row["match"]["index"]),
                    "{description}"
                );
                assert_eq!(found.state, text(&row["match"]["state"]), "{description}");
            }
            Err(class) => assert_eq!(
                Some(frasil_base::Class::name(class)),
                row["refused"].as_str(),
                "{description}"
            ),
        }
    }
}

#[test]
fn member_refusals() {
    let h = Handshake::load();
    let json = &h.json;
    let channel = h.channel();
    let (e_d, e_l) = (h.endpoint("dialer"), h.endpoint("listener"));
    let offer_json = &json["offer"];
    let states = labels(&offer_json["offered_states"]);
    let sent = SentOffer::new_with(
        0,
        &channel,
        states.iter().map(|s| (s.clone(), h.secret(s))),
        array(&offer_json["nonce"]),
        &fillers(&offer_json["tags"], states.len()),
    );
    let candidates = h.candidates(&json["listener_candidates"]);
    let th = array::<32>(&json["answer"]["transcript"]);
    let rows = family("member_refusals");
    assert_eq!(rows.as_array().unwrap().len(), 25);
    for row in rows.as_array().unwrap() {
        let description = text(&row["description"]);
        let message = bytes(&row["message"]);
        let read = member_read(&message);
        let got = read.and_then(|message| match text(&row["at"]) {
            "offer" => {
                let channel = if description.contains("another connection") {
                    channel_2()
                } else {
                    channel
                };
                let offer = read_offer(&message, Role::Dialer, 0)?;
                match_offer(&offer, &channel, candidates.clone()).map(|_| ())
            }
            "answer" => match sent.read_reply(&message, &channel, &e_d, &e_l)? {
                Reply::Refused(code) => Err(code.class().unwrap()),
                Reply::Answered { .. } => Ok(()),
            },
            "identify" => verify_identify(&message, &th, Role::Dialer).map(|_| ()),
            other => panic!("{other}"),
        });
        assert_eq!(class(got), Some(text(&row["error"])), "{description}");
    }
}

#[test]
fn offers_past_the_rules() {
    let tags = [[0u8; 32]; 16];
    let offer = |attach| member::encode_offer(attach, &[0; 32], &tags, member::REVISION);
    let read = |attach, initiator, previous| {
        class(read_offer(&control(&offer(attach)), initiator, previous))
    };
    assert_eq!(read(1024, Role::Dialer, 0), Some("AttachLimit"));
    assert_eq!(read(1, Role::Dialer, 0), Some("Malformed"));
    assert_eq!(read(1, Role::Listener, 0), None);
    assert_eq!(read(0, Role::Dialer, member::MAX_OFFERS), Some("Malformed"));
    assert_eq!(read(0, Role::Dialer, member::MAX_OFFERS - 1), None);
    // Out of budget without a match: Busy, not NoCommonState.
    let offer = read_offer(&control(&offer(0)), Role::Dialer, 0).unwrap();
    let many = (0..=member::CANDIDATE_BUDGET as u32).map(|i| (i, [0u8; 32]));
    assert_eq!(
        class(match_offer(&offer, &[0; 32], many).map(|_| ())),
        Some("Busy")
    );
    let budget = (0..member::CANDIDATE_BUDGET as u32).map(|i| (i, [0u8; 32]));
    assert_eq!(
        class(match_offer(&offer, &[0; 32], budget).map(|_| ())),
        Some("NoCommonState")
    );
}

/// The roster check's rows: each device's standing in the verifier's view,
/// with probation's steps, the re-check or the verifier's own removal, and
/// the outcome the session runs.
#[test]
fn roster_check() {
    fn standing(input: &Json) -> Standing {
        match text(&input["standing"]) {
            "reaches" => Standing::Reaches(match text(&input["path"]) {
                "device grant" => Path::DeviceGrant,
                "guest" => Path::Guest,
                "person grant" => Path::PersonGrant,
                "granted space" => Path::GrantedSpace,
                other => panic!("path {other}"),
            }),
            "forked" => Standing::Forked,
            "ended" => Standing::Ended(match text(&input["ended"]) {
                "removed" => Ended::Removed,
                "revoked" => Ended::Revoked,
                "gone from a granted space" => Ended::GoneFromGrantedSpace,
                other => panic!("ended {other}"),
            }),
            "named nowhere" => Standing::NamedNowhere,
            "only through a log not held" => Standing::OnlyThroughUnheldLog,
            other => panic!("standing {other}"),
        }
    }
    fn name(verdict: Verdict) -> &'static str {
        match verdict {
            Verdict::Admit => "Admit",
            Verdict::Detach(_) => "Detach",
            Verdict::Probation => "probation",
        }
    }

    let rows = family("roster_check");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 14);
    for row in rows {
        let description = text(&row["device_in_view"]);
        let input = &row["input"];
        let first = roster::check(standing(input));
        let (outcome, verdict) = if input["verifier_removed"] == Json::Bool(true) {
            (name(roster::SELF_REMOVED).to_owned(), roster::SELF_REMOVED)
        } else if let Some(recheck) = input.get("recheck") {
            assert_eq!(first, Verdict::Admit, "{description}");
            let verdict = roster::recheck(standing(recheck));
            (name(verdict).to_owned(), verdict)
        } else if let Some(steps) = input.get("probation") {
            assert_eq!(first, Verdict::Probation, "{description}");
            let start = 100;
            let mut probation = Probation::start(start);
            let mut received = 0;
            let mut verdict = None;
            for step in steps.as_array().unwrap() {
                let events = step["events"].as_u64().unwrap();
                probation.received(events - received);
                received = events;
                verdict =
                    probation.decide(standing(step), start + step["seconds"].as_u64().unwrap());
                if verdict.is_some() {
                    break;
                }
            }
            let verdict = verdict.unwrap_or_else(|| panic!("{description}: still in probation"));
            (format!("probation, then {}", name(verdict)), verdict)
        } else {
            (name(first).to_owned(), first)
        };
        let code = match verdict {
            Verdict::Detach(code) => Some(code),
            _ => None,
        };
        assert_eq!(text(&row["outcome"]), outcome, "{description}");
        assert_eq!(
            row.get("code").map(text),
            code.map(Code::name),
            "{description}"
        );
    }
}

// ---------------------------------------------------------------------------
// The session state machine.

fn sends(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Send(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

/// Delivers each message one side sends to the other, returning the events
/// the receiver reports.
fn deliver(to: &mut MemberSession<String>, messages: &[Vec<u8>]) -> Vec<Event> {
    let mut out = Vec::new();
    for message in messages {
        out.extend(to.receive(&control(message)).unwrap());
    }
    out
}

fn sessions(h: &Handshake) -> (MemberSession<String>, MemberSession<String>) {
    let channel = h.channel();
    let (e_d, e_l) = (h.endpoint("dialer"), h.endpoint("listener"));
    (
        MemberSession::new(
            Role::Dialer,
            channel,
            e_d,
            e_l,
            &h.identity_seed("dialer"),
            h.signer("dialer").kc,
        ),
        MemberSession::new(
            Role::Listener,
            channel,
            e_l,
            e_d,
            &h.identity_seed("listener"),
            h.signer("listener").kc,
        ),
    )
}

#[test]
fn sessions_run_the_vector_handshake() {
    let h = Handshake::load();
    let json = &h.json;
    let (mut dialer, mut listener) = sessions(&h);
    let offer_json = &json["offer"];
    let states = labels(&offer_json["offered_states"]);

    // 1. The dialer offers attach 0.
    let (attach, events) = dialer
        .offer_with(
            states.iter().map(|s| (s.clone(), h.secret(s))),
            array(&offer_json["nonce"]),
            &fillers(&offer_json["tags"], states.len()),
        )
        .unwrap();
    assert_eq!(attach, 0);
    assert_eq!(sends(&events), [bytes(&offer_json["message"])]);
    assert_eq!(dialer.deadline(9), None);
    assert!(dialer.deadline(10).is_some());

    // 2. The listener answers, then identifies itself.
    let events = deliver(&mut listener, &sends(&events));
    assert_eq!(events, [Event::OfferReceived { attach: 0 }]);
    let events = listener
        .respond_with(
            0,
            h.candidates(&json["listener_candidates"]),
            array(&json["answer"]["nonce"]),
        )
        .unwrap();
    assert_eq!(
        sends(&events),
        [
            bytes(&json["answer"]["message"]),
            bytes(&json["identify"]["listener"]["message"])
        ]
    );
    assert!(events.contains(&Event::Proved { attach: 0 }));
    assert_eq!(listener.state(0).map(String::as_str), Some("{C}"));
    assert_eq!(listener.serving(0), Serving::Nothing);

    // 3. The dialer verifies the answer, identifies itself, and checks the
    //    listener against its roster.
    let events = deliver(&mut dialer, &sends(&events));
    assert_eq!(
        sends(&events),
        [bytes(&json["identify"]["dialer"]["message"])]
    );
    let listener_key = h.device_id("listener");
    assert!(events.contains(&Event::Identified {
        signer: h.signer("listener"),
        device: listener_key
    }));
    assert_eq!(dialer.remote_device(), Some(&listener_key));
    assert_eq!(dialer.remote_signer(), Some(&h.signer("listener")));
    assert!(events.contains(&Event::CheckRoster {
        attach: 0,
        device: listener_key
    }));
    assert_eq!(dialer.state(0).map(String::as_str), Some("{C}"));
    assert_eq!(
        dialer.transcript0(),
        Some(&array(&json["answer"]["transcript"]))
    );

    // 4. The listener checks the dialer.
    let events = deliver(&mut listener, &sends(&events));
    let dialer_key = h.device_id("dialer");
    assert!(events.contains(&Event::CheckRoster {
        attach: 0,
        device: dialer_key
    }));

    // Both admit.
    for side in [&mut dialer, &mut listener] {
        let events = side.verdict(0, Verdict::Admit).unwrap();
        assert_eq!(sends(&events), [bytes(&json["admit"])[4..].to_vec()]);
        assert!(side.settled());
        assert_eq!(side.serving(0), Serving::Everything);
        assert_eq!(side.verdict(0, Verdict::Admit).unwrap(), []);
    }
    let admit = Admit { attach: 0 }.encode();
    assert_eq!(
        dialer.receive(&control(&admit)).unwrap(),
        [Event::Admitted { attach: 0 }]
    );
    assert!(dialer.admitted_by_other(0));

    // A second attach: no Identify, checked against the device of attach 0.
    let second = &json["second_attach_offer"];
    let (attach, events) = dialer
        .offer_with(
            [("{C}".to_owned(), h.secret("{C}"))],
            array(&second["nonce"]),
            &fillers(&second["tags"], 1),
        )
        .unwrap();
    assert_eq!(attach, 2);
    assert_eq!(sends(&events), [bytes(&second["message"])]);
    deliver(&mut listener, &sends(&events));
    let events = listener
        .respond_with(2, h.candidates(&Json::from(vec!["{C}"])), [7; 32])
        .unwrap();
    assert_eq!(sends(&events).len(), 1);
    assert!(events.contains(&Event::CheckRoster {
        attach: 2,
        device: dialer_key
    }));
    let events = deliver(&mut dialer, &sends(&events));
    assert!(sends(&events).is_empty());
    assert!(events.contains(&Event::CheckRoster {
        attach: 2,
        device: listener_key
    }));

    // The re-check detaches attach 2; the remaining attach keeps the
    // connection open. Detaching the last closes it with done.
    let events = listener
        .verdict(2, roster::recheck(Standing::Ended(Ended::Removed)))
        .unwrap();
    assert_eq!(listener.serving(2), Serving::Nothing);
    let events = deliver(&mut dialer, &sends(&events));
    assert_eq!(
        events,
        [Event::Detached {
            attach: 2,
            code: Code::MembershipEnded
        }]
    );
    let events = dialer.detach(0, Code::Done).unwrap();
    assert!(events.contains(&Event::Close(Code::Done)));
    let events = deliver(&mut listener, &sends(&events));
    assert_eq!(
        events,
        [
            Event::Detached {
                attach: 0,
                code: Code::Done
            },
            Event::Close(Code::Done)
        ]
    );
}

#[test]
fn a_relay_that_splices_two_sessions_fails_the_handshake() {
    // The relay holds two transport sessions, each with its own exporter:
    // the dialer's with the relay, and the relay's with the listener. It
    // passes the dialer's offer on as it is.
    let h = Handshake::load();
    let json = &h.json;
    let relay_endpoint = [9; 32];
    let (e_d, e_l) = (h.endpoint("dialer"), h.endpoint("listener"));
    let mut dialer = MemberSession::new(
        Role::Dialer,
        h.channel(),
        e_d,
        relay_endpoint,
        &h.identity_seed("dialer"),
        h.signer("dialer").kc,
    );
    let mut listener = MemberSession::new(
        Role::Listener,
        channel_2(),
        e_l,
        relay_endpoint,
        &h.identity_seed("listener"),
        h.signer("listener").kc,
    );
    let states = labels(&json["offer"]["offered_states"]);
    let (_, events) = dialer
        .offer_with(
            states.iter().map(|s| (s.clone(), h.secret(s))),
            [1; 32],
            &[[2; 32]; 16],
        )
        .unwrap();
    deliver(&mut listener, &sends(&events));
    let events = listener
        .respond_with(0, h.candidates(&json["listener_candidates"]), [3; 32])
        .unwrap();
    let refusal = sends(&events);
    assert_eq!(
        refusal,
        [frasil_transport::messages::Refuse {
            attach: 0,
            code: Code::NoCommonState
        }
        .encode()]
    );
    assert!(listener.settled());
    // The dialer may offer up to 3 more times; then the attach is over.
    let events = deliver(&mut dialer, &refusal);
    assert_eq!(
        events,
        [Event::Refused {
            attach: 0,
            code: Code::NoCommonState,
            may_retry: true
        }]
    );
    for round in 0..3 {
        let events = dialer
            .retry_with(
                0,
                [("{C}".to_owned(), h.secret("{C}"))],
                [round; 32],
                &[[2; 32]; 16],
            )
            .unwrap();
        deliver(&mut listener, &sends(&events));
        let events = listener
            .respond_with(0, h.candidates(&json["listener_candidates"]), [3; 32])
            .unwrap();
        let events = deliver(&mut dialer, &sends(&events));
        assert_eq!(
            events,
            [Event::Refused {
                attach: 0,
                code: Code::NoCommonState,
                may_retry: round < 2
            }]
        );
    }
    assert!(
        dialer
            .retry_with(0, [("{C}".to_owned(), [0; 32])], [0; 32], &[[0; 32]; 16])
            .is_err()
    );

    // Had the relay a proof to pass back, it would bind the listener's
    // channel and endpoints, and fail at the dialer.
    let mut listener = MemberSession::new(
        Role::Listener,
        channel_2(),
        e_l,
        relay_endpoint,
        &h.identity_seed("listener"),
        h.signer("listener").kc,
    );
    let sent = SentOffer::new_with(
        0,
        &channel_2(),
        states.iter().map(|s| (s.clone(), h.secret(s))),
        [1; 32],
        &[[2; 32]; 16],
    );
    deliver(&mut listener, &[sent.message().to_vec()]);
    let events = listener
        .respond_with(0, h.candidates(&json["listener_candidates"]), [3; 32])
        .unwrap();
    let mut dialer = MemberSession::new(
        Role::Dialer,
        h.channel(),
        e_d,
        relay_endpoint,
        &h.identity_seed("dialer"),
        h.signer("dialer").kc,
    );
    dialer
        .offer_with(
            states.iter().map(|s| (s.clone(), h.secret(s))),
            [1; 32],
            &[[2; 32]; 16],
        )
        .unwrap();
    let answer = control(&sends(&events)[0]);
    let closed = dialer.receive(&answer).unwrap_err();
    assert_eq!(closed.code, Code::BadProof);
    assert_eq!(closed.class, TransportClass::BadProof);
}

#[test]
fn sessions_refuse_out_of_order_messages() {
    let h = Handshake::load();
    let json = &h.json;
    let (mut dialer, mut listener) = sessions(&h);
    // An Identify before any proof.
    let identify = bytes(&json["identify"]["dialer"]["message"]);
    assert_eq!(
        listener.receive(&control(&identify)).unwrap_err().code,
        Code::Malformed
    );
    // An answer for an attach never offered.
    let answer = bytes(&json["answer"]["message"]);
    assert_eq!(
        dialer.receive(&control(&answer)).unwrap_err().code,
        Code::Malformed
    );
    // An Admit for an attach not proved.
    let admit = Admit { attach: 0 }.encode();
    assert_eq!(
        dialer.receive(&control(&admit)).unwrap_err().code,
        Code::Malformed
    );
    // An offer of another revision is refused, not closed.
    let mut listener = sessions(&h).1;
    let tags = [[0; 32]; 16];
    let other = member::encode_offer(0, &[0; 32], &tags, member::REVISION + 1);
    let events = listener.receive(&control(&other)).unwrap();
    assert_eq!(
        sends(&events),
        [frasil_transport::messages::Refuse {
            attach: 0,
            code: Code::RevisionMismatch
        }
        .encode()]
    );
    // Messages of other types go to the caller.
    let other = frasil_transport::messages::Accepted { request: 1 }.encode();
    let message = common::peer_control(&other).unwrap();
    assert_eq!(message.kind, MessageType::Accepted);
    assert_eq!(listener.receive(&message).unwrap(), [Event::Other(message)]);
    // Attach numbers stop at 1,024.
    let mut dialer = sessions(&h).0;
    for _ in 0..512 {
        dialer
            .offer_with([("{C}".to_owned(), [0; 32])], [0; 32], &[[0; 32]; 16])
            .unwrap();
    }
    assert_eq!(
        dialer
            .offer_with([("{C}".to_owned(), [0; 32])], [0; 32], &[[0; 32]; 16])
            .unwrap_err(),
        TransportClass::AttachLimit
    );
}

#[test]
fn probation_serves_catch_up() {
    let h = Handshake::load();
    let json = &h.json;
    let (mut dialer, mut listener) = sessions(&h);
    let states = labels(&json["offer"]["offered_states"]);
    let (_, events) = dialer
        .offer_with(
            states.iter().map(|s| (s.clone(), h.secret(s))),
            [1; 32],
            &[[2; 32]; 16],
        )
        .unwrap();
    deliver(&mut listener, &sends(&events));
    let events = listener
        .respond_with(0, h.candidates(&json["listener_candidates"]), [3; 32])
        .unwrap();
    let events = deliver(&mut dialer, &sends(&events));
    deliver(&mut listener, &sends(&events));
    assert_eq!(
        listener
            .verdict(0, roster::check(Standing::NamedNowhere))
            .unwrap(),
        []
    );
    assert_eq!(listener.serving(0), Serving::CatchUp);
    assert!(!listener.settled());
    let events = listener
        .verdict(0, Verdict::Detach(Code::UnknownMember))
        .unwrap();
    assert!(events.contains(&Event::Close(Code::Done)));
}
