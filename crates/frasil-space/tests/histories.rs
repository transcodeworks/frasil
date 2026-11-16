//! roster.json's histories (roster.md, "Attacks" to "What replicas
//! derive"): each history's events byte for byte, and in each view the
//! status of every event with its class, the roster, the maximal valid
//! rotations, the events that void each void event, forks, derived
//! frontiers, duels with what each side voided, and re-submissions.

mod common;

use common::space::{
    Fixture, device_names, differences, first_list_event, first_member, held_list, name_other,
    person_id, prefix, space_id, team_prefix, whole_list,
};
use common::{family, text};
use frasil_events::EventId;
use frasil_space::keygraph::{Kind, Member, SpaceHistory};
use frasil_space::{GrantedSpace, HeldList, Level, MemberType, OtherLogs, Space};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

/// The keys of a history entry that are summaries of further views, each
/// written without the builder's extra keys.
const EXTRA_VIEWS: [&str; 4] = [
    "before the revocation, with the list as it was",
    "without B's list",
    "with the revocation",
    "after the confirm",
];

/// The lists a view holds: its `lists_held`, each list's events or the
/// names of those held; a view that names none holds every list in full.
fn lists_held(lists: Option<&serde_json::Map<String, Json>>, summary: &Json) -> Vec<HeldList> {
    let Some(lists) = lists else {
        return Vec::new();
    };
    match summary.get("lists_held").and_then(Json::as_object) {
        Some(held) => held
            .iter()
            .map(|(name, events)| held_list(&lists[name], events))
            .collect(),
        None => lists.values().map(whole_list).collect(),
    }
}

/// Resolves every view of one history and compares it with the vector;
/// with `keys`, also the key graph's outcomes over the view.
fn run_history(history: &Json, keys: bool) -> Vec<String> {
    let name = text(history, "name");
    let mut fixture = Fixture::new(&prefix(name), &history["events"]);
    if let Some(limit) = history.get("limit_for_this_vector") {
        fixture.limits.max_roster_events = limit.as_u64().unwrap() as usize;
    }
    // The other logs: persons' lists, and a granted team with its own
    // lists.
    let lists = history.get("lists").and_then(Json::as_object);
    let team = history.get("team");
    for (list_name, events) in lists.into_iter().flatten() {
        fixture.name_events(events);
        name_other(
            &mut fixture,
            list_name,
            person_id(events),
            MemberType::Person,
        );
    }
    // A list that one device starts is the one identity.py's builder makes
    // under the list's prefix.
    if let Some(prefixes) = history.get("list_prefixes").and_then(Json::as_object) {
        for (list_name, list_prefix) in prefixes {
            let events = lists.unwrap()[list_name].as_array().unwrap();
            if let [only] = events.as_slice() {
                let device = text(only, "author");
                assert_eq!(
                    common::bytes(only, "signed"),
                    first_list_event(list_prefix.as_str().unwrap(), device),
                    "{name}: {list_name}"
                );
            }
        }
    }
    let team_fixture = team.map(|events| {
        let mut team = Fixture::new(&team_prefix(history), events);
        for (_, events) in lists.into_iter().flatten() {
            team.name_events(events);
        }
        team
    });
    if let Some(events) = team {
        fixture.name_events(events);
        name_other(&mut fixture, "team T", space_id(events), MemberType::Space);
    }
    let mut views: Vec<(String, &Json, bool)> = history["views"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(v, s)| (v.clone(), s, true))
        .collect();
    for extra in EXTRA_VIEWS {
        if let Some(summary) = history.get(extra) {
            views.push((extra.to_owned(), summary, false));
        }
    }
    for (_, summary, _) in &views {
        for device in device_names(summary) {
            fixture.name_device(&device);
        }
    }
    // The team's own others: its lists, when a history grants a team.
    let team_others = OtherLogs {
        lists: match team {
            Some(_) => lists
                .into_iter()
                .flatten()
                .map(|(_, events)| {
                    let list = whole_list(events);
                    (list.person(), list)
                })
                .collect(),
            None => Default::default(),
        },
        spaces: Default::default(),
        keys: None,
    };
    let team_space = team_fixture
        .as_ref()
        .map(|team| team.resolve(None, &team.keys, &team_others).unwrap());
    // A replica that reads the team reads the lists the team reads, and
    // takes keys from their `add`s like from any record it holds (roster.md,
    // "An author's keys").
    let mut team_list_keys = frasil_crypto::device::KeyRing::new();
    for list in team_others.lists.values() {
        team_list_keys.extend(list.keys());
    }
    let mut out = Vec::new();
    for (view_name, summary, extra) in views {
        let label = format!("{name} / {view_name}");
        let view = if extra {
            fixture.view(&summary["holds"])
        } else {
            Some(fixture.view_of_summary(summary))
        };
        let mut others = OtherLogs::none();
        if team.is_some() {
            others = others.with_keys(&team_list_keys);
        }
        if team.is_none() {
            for list in lists_held(lists, summary) {
                others = others.with_list(list);
            }
        }
        // The team's events this view holds (`team_held`): none, some, or
        // every event; by default every event.
        let partial;
        let team_held = match (summary.get("team_held"), &team_fixture) {
            (Some(Json::Array(names)), _) if names.is_empty() => None,
            (Some(holds @ Json::Array(_)), Some(team)) => {
                partial = team
                    .resolve(team.view(holds).as_ref(), &team.keys, &team_others)
                    .unwrap();
                Some(&partial)
            }
            _ => team_space.as_ref(),
        };
        if let Some(team) = team_held {
            others = others.with_space(team as &dyn GrantedSpace);
        }
        match fixture.resolve(view.as_ref(), &fixture.keys, &others) {
            Ok(space) => {
                out.extend(differences(&fixture, &space, summary, extra, &label));
                if let Some(want) = summary.get("principals") {
                    out.extend(principals(&fixture, &space, want, &label));
                }
                if keys {
                    out.extend(key_outcomes(&fixture, &space, summary, &label));
                }
                if view_name == "all" || view_name == "rooms A and B" {
                    out.extend(history_extras(&fixture, &space, history, &view_name));
                }
            }
            Err(class) => out.push(format!("{label}: unusable, {class:?}")),
        }
    }
    out
}

/// What a history gives beyond its views: the merged space policy, a
/// cascade's frontier, the end of a fork in a list, and stability in a
/// view.
fn history_extras(fixture: &Fixture, space: &Space<'_>, history: &Json, view: &str) -> Vec<String> {
    let name = text(history, "name");
    let mut out = Vec::new();
    let mut check = |what: &str, ok: bool| {
        if !ok {
            out.push(format!("{name} / {view}: {what}"));
        }
    };
    if let (Some(policy), "all") = (history.get("policy"), view) {
        let got = space.policy();
        check(
            "policy",
            policy["agent_waiting_period"].as_u64() == Some(got.agent_waiting_period)
                && policy["gap_key_timeout"].as_u64() == Some(got.gap_key_timeout)
                && policy["bounded_window"].as_u64() == got.bounded_window
                && policy["online_freshness"].as_u64() == got.online_freshness
                && policy["forbid_agents"].as_bool() == Some(got.forbid_agents),
        );
    }
    if let (Some(cascade), "all") = (history.get("cascade_frontier"), view) {
        let response = fixture.id(text(cascade, "response"));
        let mut ok = true;
        for (device, head) in cascade["heads"].as_object().unwrap() {
            let key = fixture.device_key(device);
            let heads = space.heads_of(&BTreeSet::from([key]), response);
            ok &= heads.get(&key) == Some(&fixture.id(head.as_str().unwrap()));
        }
        check("cascade frontier", ok);
    }
    if let (Some(effective), "all") = (history.get("effective"), view) {
        // roster.md, "Grants of spaces and effective membership": each
        // device's highest level, and its highest over the paths that
        // propagate.
        let got = space.effective_at(space.valid_roster(), 0, &[]);
        let level = |l: Option<frasil_space::Level>| l.map(frasil_space::Level::name);
        let mut ok = got.len() == effective.as_object().unwrap().len();
        for (device, want) in effective.as_object().unwrap() {
            let found = got.get(&fixture.device_key(device));
            ok &= found.map(|&(l, _)| l.name()) == want["level"].as_str()
                && found.and_then(|&(_, p)| level(p)) == want["propagating_level"].as_str();
        }
        check("effective membership", ok);
    }
    if let (Some(end), "all") = (history.get("fork_end"), view) {
        let lists = history["lists"].as_object().unwrap();
        let (_, events) = lists.iter().next().unwrap();
        let list = whole_list(events);
        let end_id = decode_named(events, end.as_str().unwrap());
        let f2 = fixture.device_key("f2");
        check("fork end", list.ends(&f2).last() == Some(&end_id));
    }
    if let (Some(stability), "rooms A and B") = (history.get("stability_in_rooms_A_and_B"), view) {
        let voided = fixture.id(text(stability, "voided"));
        let voiders: Vec<EventId> = stability["voided_by"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| fixture.id(n.as_str().unwrap()))
            .collect();
        check("voided by", space.voiders(voided) == voiders);
        let mut administrators: Vec<[u8; 32]> = stability["administrators"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| fixture.device_key(n.as_str().unwrap()))
            .collect();
        administrators.sort();
        let mut got = space.administrators();
        got.sort();
        check("administrators", got == administrators);
        check(
            "stable",
            Some(space.voiding_stable(voided)) == stability["stable"].as_bool(),
        );
    }
    out
}

/// The ID of the event of another log's history named so.
fn decode_named(events: &Json, name: &str) -> EventId {
    let event = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| text(e, "name") == name)
        .unwrap();
    frasil_events::decode(&common::bytes(event, "signed"))
        .unwrap()
        .id()
}

/// The key graph over a resolved view (keys.md, "The current state and the
/// inside", "Entitlement and the link gate"): its current content state is
/// the view's maximal valid rotations, its merged roster holds the view's
/// members, each entitled to the current state, and the current content key
/// derives from the rotations' keys.
fn key_outcomes(fixture: &Fixture, space: &Space<'_>, summary: &Json, label: &str) -> Vec<String> {
    let mut out = Vec::new();
    let history = SpaceHistory::new(space);
    let graph = history.key_graph();
    let Some(current) = graph.current(Kind::Content) else {
        return vec![format!("{label}: no current state")];
    };
    let name = |id: &EventId| fixture.event_names.get(id).cloned().unwrap_or_default();
    let mut got: Vec<String> = current.ids().iter().map(name).collect();
    got.sort();
    let mut want: Vec<String> = summary["rotations_maximal"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_owned())
        .collect();
    want.sort();
    if got != want {
        out.push(format!("{label}: current state {got:?}, want {want:?}"));
    }
    let members = graph.members(Kind::Content);
    let mut got: Vec<String> = members
        .keys()
        .filter_map(|m| match m {
            Member::Roster(m) => fixture.member_names.get(m).cloned(),
            Member::Principal(_) => None,
        })
        .collect();
    got.sort();
    let mut want: Vec<String> = summary["roster"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, state)| state.is_object())
        .map(|(m, _)| m.clone())
        .collect();
    want.sort();
    if got != want {
        out.push(format!("{label}: merged roster {got:?}, want {want:?}"));
    }
    for member in members.keys() {
        if !graph.entitled(member, &current, Kind::Content) {
            out.push(format!(
                "{label}: {member:?} not entitled to the current state"
            ));
        }
    }
    let secret = graph.current_secret(Kind::Content, |r| {
        fixture.keys.rotations.get(&r).map(|k| **k)
    });
    if secret.is_none() {
        out.push(format!("{label}: the current content key does not derive"));
    }
    out
}

/// The space principals a view admits (keys.md, "Notices and space
/// principals"), as `team T@<rotation>`.
fn principals(fixture: &Fixture, space: &Space<'_>, want: &Json, label: &str) -> Vec<String> {
    let history = SpaceHistory::new(space);
    let got: Vec<String> = history
        .key_graph()
        .members(Kind::Content)
        .keys()
        .filter_map(|m| match m {
            Member::Principal(p) => Some(format!("team T@{}", fixture.event_names[&p.rotation])),
            Member::Roster(_) => None,
        })
        .collect();
    let want: Vec<String> = want
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap().to_owned())
        .collect();
    if got == want {
        Vec::new()
    } else {
        vec![format!("{label}: principals {got:?}, want {want:?}")]
    }
}

fn run_family(name: &str) {
    let mut failures = Vec::new();
    for history in family(name).as_array().unwrap() {
        failures.extend(run_history(history, name == "key_histories"));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Replays the histories of a family named so, each of which must exist.
fn run_named(family_name: &str, names: &[&str]) {
    let histories = family(family_name);
    let mut failures = Vec::new();
    for &name in names {
        let history = histories
            .as_array()
            .unwrap()
            .iter()
            .find(|h| text(h, "name") == name)
            .unwrap_or_else(|| panic!("{family_name}: no history named {name:?}"));
        failures.extend(run_history(history, family_name == "key_histories"));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// roster.md, 3.7 "Standing": a reader's roster events after a cycle that
/// the agreement step settles are void before the procedure, so the
/// contest has the same verdicts with none of them, with as many as would
/// bring the undecided events to the step's limit, and with one more.
#[test]
fn a_readers_roster_events_leave_an_agreed_contest_as_it_is() {
    run_named(
        "cycles",
        &["a cycle the agreement step settles, beside a reader's roster events"],
    );
}

/// roster.md, "Grants of spaces and effective membership": a device that
/// is a guest at `write` in a granted team and reaches it at `read` through
/// a person reaches the project at `read`, propagating; its mirror, a guest
/// at `read` and at `write` through a person, writes in the project.
#[test]
fn a_guest_of_a_granted_team_keeps_its_propagating_path() {
    run_named(
        "across_logs",
        &["a guest of a granted team that also reaches it through a person"],
    );
}

/// roster.md, 3.10 The write rule, step 3: a path through a granted space
/// is waiting when every path the device has into that space is. A device
/// rooted in a recovery agent that sits in the team only through its
/// person's grant makes no key event through the team, and its unit
/// stands; once the team grants it directly, its key event is valid.
#[test]
fn a_waiting_device_waits_through_a_granted_team() {
    run_named(
        "across_logs",
        &["a device rooted in an agent that reaches the space only through a granted team"],
    );
}

/// roster.md, 3.6 Authority at the place, step 2: a change carries no
/// `session`, so a change to `administer` of a member whose state at the
/// place is a guest's is `AdministerNotDevice`. A raise concurrent with
/// the grant that makes its member a guest stands, and the meet keeps the
/// guest at `write`; a former guest re-granted without a session may be
/// raised.
#[test]
fn a_guest_is_never_raised_to_administer() {
    run_named(
        "concurrent_changes",
        &[
            "a change that raises a guest to administer",
            "a raise concurrent with the grant that makes its member a guest",
            "a former guest re-granted without a session may be raised",
        ],
    );
}

#[test]
fn concurrent_changes() {
    run_family("concurrent_changes");
}

/// Device keys bound by their hash (roster.md, "A device's keys", "An
/// author's keys"): a reader's void event, a removed member's rotation and
/// a person's own list each name an administrator's Ed25519 key beside an
/// ML-DSA-65 key of their own; that names another device, which lends the
/// administrator no key and frames nobody.
#[test]
fn bound_keys() {
    run_family("bound_keys");
}

#[test]
fn cycles() {
    run_family("cycles");
}

#[test]
fn duels() {
    run_family("duels");
}

/// Every duel resolved from logs whose events arrived in other orders,
/// children before their parents among them: each replica reaches the
/// vector's verdicts, roster, voiders and duels whatever the order, the
/// duels with a remover raised after its partner's last event among them
/// (roster.md, 3.5.2 What attacks what).
#[test]
fn duels_in_any_arrival_order() {
    let mut failures = Vec::new();
    for history in family("duels").as_array().unwrap() {
        let name = text(history, "name");
        let events = common::events(&history["events"]);
        let (genesis, rest) = events.split_first().unwrap();
        let reversed: Vec<usize> = (0..rest.len()).rev().collect();
        let odd_then_even: Vec<usize> = (0..rest.len())
            .filter(|i| i % 2 == 1)
            .chain((0..rest.len()).filter(|i| i % 2 == 0).rev())
            .collect();
        for (order_name, order) in [("reversed", reversed), ("odd then even", odd_then_even)] {
            let mut fixture = Fixture::new(&prefix(name), &history["events"]);
            let mut log = frasil_events::Log::new(genesis.1.clone()).unwrap();
            for i in order {
                log.place(rest[i].1.clone()).unwrap();
            }
            assert_eq!(
                log.placed_count(),
                events.len(),
                "{name}: every event placed"
            );
            fixture.log = log;
            for (view_name, summary) in history["views"].as_object().unwrap() {
                for device in device_names(summary) {
                    fixture.name_device(&device);
                }
                let label = format!("{name} / {view_name}, {order_name}");
                let view = fixture.view(&summary["holds"]);
                let others = OtherLogs::none();
                match fixture.resolve(view.as_ref(), &fixture.keys, &others) {
                    Ok(space) => {
                        failures.extend(differences(&fixture, &space, summary, true, &label))
                    }
                    Err(class) => failures.push(format!("{label}: unusable, {class:?}")),
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn forks() {
    run_family("forks");
}

#[test]
fn writes() {
    run_family("writes");
}

#[test]
fn across_logs() {
    run_family("across_logs");
}

#[test]
fn key_histories() {
    run_family("key_histories");
}

/// A granted space that also grants a space back: a cycle the grant graph
/// sees only through the granted space's roster.
struct GrantsBack<'t> {
    inner: &'t dyn GrantedSpace,
    back: (EventId, EventId),
}

impl GrantedSpace for GrantsBack<'_> {
    fn space_id(&self) -> EventId {
        self.inner.space_id()
    }
    fn holds(&self, event: EventId) -> bool {
        self.inner.holds(event)
    }
    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.inner.precedes(earlier, later)
    }
    fn other_logs(&self) -> &OtherLogs<'_> {
        self.inner.other_logs()
    }
    fn keys(&self) -> &frasil_crypto::device::KeyRing {
        self.inner.keys()
    }
    fn names(&self, device: &frasil_crypto::device::DeviceId) -> bool {
        self.inner.names(device)
    }
    fn effective(
        &self,
        depth: usize,
        seen: &[EventId],
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.inner.effective(depth, seen)
    }
    fn effective_counted(
        &self,
        depth: usize,
        seen: &[EventId],
        verdicts: &frasil_space::graph::Verdicts,
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.inner.effective_counted(depth, seen, verdicts)
    }
    fn space_grants(&self) -> Vec<(EventId, EventId)> {
        let mut out = self.inner.space_grants();
        out.push(self.back);
        out
    }
    fn reach(
        &self,
        device: &[u8; 32],
        paths: frasil_space::PathsFor,
    ) -> Option<frasil_space::graph::Reach> {
        self.inner.reach(device, paths)
    }
    fn propagating_writers(&self) -> BTreeSet<[u8; 32]> {
        self.inner.propagating_writers()
    }
    fn unwaiting_writers(&self) -> BTreeSet<[u8; 32]> {
        self.inner.unwaiting_writers()
    }
    fn ends(&self, device: &[u8; 32]) -> Vec<frasil_events::Ref> {
        self.inner.ends(device)
    }
}

/// roster.md, "Grants of spaces and effective membership", step 2, across
/// logs: when the granted team also grants the project, the cycle drops
/// the edge whose granting space ID is highest, wherever the path enters
/// it; the team's devices reach the project only while its edge counts.
#[test]
fn a_cycle_through_a_granted_space() {
    let name = "a device that left a granted team before the grant";
    let history = family("across_logs")
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == name)
        .unwrap()
        .clone();
    let fixture = Fixture::new(&prefix(name), &history["events"]);
    let team = Fixture::new(&team_prefix(&history), &history["team"]);
    let none = OtherLogs::none();
    let team_space = team.resolve(None, &team.keys, &none).unwrap();
    let project = fixture.log.id();
    let t = GrantedSpace::space_id(&team_space);
    let plain_others = OtherLogs::none().with_space(&team_space);
    let plain = fixture.resolve(None, &fixture.keys, &plain_others).unwrap();
    let back = GrantsBack {
        inner: &team_space,
        back: (EventId([0xee; 32]), project),
    };
    let cyclic_others = OtherLogs::none().with_space(&back);
    let cyclic = fixture
        .resolve(None, &fixture.keys, &cyclic_others)
        .unwrap();
    let alone = fixture.resolve(None, &fixture.keys, &none).unwrap();
    let valid = plain.valid_roster().clone();
    assert_eq!(&valid, cyclic.valid_roster());
    let through_team = plain.effective_at(&valid, 0, &[]);
    let without_team = alone.effective_at(&valid, 0, &[]);
    assert_ne!(through_team, without_team, "the team adds devices");
    let verdicts = cyclic.grant_verdicts(&valid);
    let dropped: Vec<_> = verdicts
        .iter()
        .filter(|(_, v)| **v == Err(frasil_space::SpaceClass::GrantCycle))
        .map(|(e, _)| e.from)
        .collect();
    assert_eq!(dropped, vec![project.max(t)]);
    let got = cyclic.effective_at(&valid, 0, &[]);
    if project > t {
        assert_eq!(got, without_team);
    } else {
        assert_eq!(got, through_team);
    }
}

/// keys.md, "Healing" and "Notices and space principals": a device keeps
/// what it received. b2, which person B's list revoked, counts as wrapped for
/// at its own heal and as a holder of the grant seeds before the space's
/// response, which answers that end, so nothing at or after the response
/// counts it. W, granted with history after the genesis, holds the
/// genesis's grant seed; a revoked device is no propagating member there.
#[test]
fn holders_keep_what_they_received() {
    let name = "a person grant, a revocation in the list, and the space's response";
    let history = family("across_logs")
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == name)
        .unwrap()
        .clone();
    let mut fixture = Fixture::new(&prefix(name), &history["events"]);
    let lists = history["lists"].as_object().unwrap();
    let mut others = OtherLogs::none();
    for (list_name, events) in lists {
        fixture.name_events(events);
        name_other(
            &mut fixture,
            list_name,
            person_id(events),
            MemberType::Person,
        );
        others = others.with_list(whole_list(events));
    }
    let space = fixture.resolve(None, &fixture.keys, &others).unwrap();
    let [p, w, b1, b2] = ["P", "W", "b1", "b2"].map(|d| fixture.device_key(d));
    let genesis = fixture.id("P creates the space");
    let heal = fixture.id("b2 heals");
    let response = fixture.id("W rotates in response to the revocation");

    let before = GrantedSpace::grant_holders(&space, genesis);
    for device in [p, w, b1, b2] {
        assert!(before.contains(&device), "{device:02x?}");
    }
    let after = GrantedSpace::grant_holders(&space, response);
    assert!(after.contains(&w) && after.contains(&b1) && !after.contains(&b2));
    assert_eq!(GrantedSpace::propagates_at(&space, &w, genesis), Some(true));
    assert_eq!(
        GrantedSpace::propagates_at(&space, &b2, genesis),
        Some(false)
    );

    let person_b = first_member(&fixture, "P grants person B write");
    let keys = SpaceHistory::new(&space);
    let graph = keys.key_graph();
    let member = Member::Roster(person_b);
    assert!(!graph.devices(&member).contains(&b2), "b2 is no longer B's");
    assert!(graph.wrapped_for(&member, heal).contains(&b2));
    let at_response = graph.wrapped_for(&member, response);
    assert!(at_response.contains(&b1) && !at_response.contains(&b2));
}

/// A granted team whose write rule admits its writers but which gives none
/// of them a reach: a mismatch between the two path computations, which no
/// honest resolution produces.
struct NoReach<'t> {
    inner: &'t dyn GrantedSpace,
}

impl GrantedSpace for NoReach<'_> {
    fn space_id(&self) -> EventId {
        self.inner.space_id()
    }
    fn holds(&self, event: EventId) -> bool {
        self.inner.holds(event)
    }
    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        self.inner.precedes(earlier, later)
    }
    fn is_restricted(&self) -> bool {
        self.inner.is_restricted()
    }
    fn other_logs(&self) -> &OtherLogs<'_> {
        self.inner.other_logs()
    }
    fn keys(&self) -> &frasil_crypto::device::KeyRing {
        self.inner.keys()
    }
    fn names(&self, device: &frasil_crypto::device::DeviceId) -> bool {
        self.inner.names(device)
    }
    fn effective(
        &self,
        depth: usize,
        seen: &[EventId],
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.inner.effective(depth, seen)
    }
    fn effective_counted(
        &self,
        depth: usize,
        seen: &[EventId],
        verdicts: &frasil_space::graph::Verdicts,
    ) -> BTreeMap<[u8; 32], (Level, Option<Level>)> {
        self.inner.effective_counted(depth, seen, verdicts)
    }
    fn space_grants(&self) -> Vec<(EventId, EventId)> {
        self.inner.space_grants()
    }
    fn reach(
        &self,
        _device: &[u8; 32],
        _paths: frasil_space::PathsFor,
    ) -> Option<frasil_space::graph::Reach> {
        None
    }
    fn rotation(&self, id: EventId) -> Option<frasil_space::GranteeRotation> {
        self.inner.rotation(id)
    }
    fn propagates_at(&self, device: &[u8; 32], rotation: EventId) -> Option<bool> {
        self.inner.propagates_at(device, rotation)
    }
    fn grant_holders(&self, rotation: EventId) -> BTreeSet<[u8; 32]> {
        self.inner.grant_holders(rotation)
    }
    fn propagating_writers(&self) -> BTreeSet<[u8; 32]> {
        self.inner.propagating_writers()
    }
    fn unwaiting_writers(&self) -> BTreeSet<[u8; 32]> {
        self.inner.unwaiting_writers()
    }
    fn ends(&self, device: &[u8; 32]) -> Vec<frasil_events::Ref> {
        self.inner.ends(device)
    }
}

/// units.md, 3.17 "Capability checks": a valid unit whose author has no
/// computed path has its content refused, not checked as an unnarrowed
/// writer's; where a path cannot be judged because a log is not held, its
/// content waits.
#[test]
fn a_valid_unit_whose_author_has_no_computed_path_is_not_unnarrowed() {
    use frasil_space::across::AuthorReach;
    let name = "removing a granted space: members granted directly keep writing";
    let history = family("across_logs")
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == name)
        .unwrap()
        .clone();
    let fixture = Fixture::new(&prefix(name), &history["events"]);
    let team = Fixture::new(&team_prefix(&history), &history["team"]);
    let none = OtherLogs::none();
    let team_space = team.resolve(None, &team.keys, &none).unwrap();
    let through_team = fixture.id("t1 writes through T");
    let direct = fixture.id("t3 writes");
    let author_of = |id: EventId| fixture.log.event(id).unwrap().author().0;
    let reach = |space: &Space<'_>, id: EventId| {
        AuthorReach::at(space, &author_of(id), &space.place_of(id))
    };
    let valid = |space: &Space<'_>, id: EventId| space.status(id).is_some_and(|s| s.is_valid());

    // The team as this replica resolves it: t1 reaches the project.
    let plain_others = OtherLogs::none().with_space(&team_space);
    let plain = fixture.resolve(None, &fixture.keys, &plain_others).unwrap();
    assert!(valid(&plain, through_team));
    assert!(matches!(
        reach(&plain, through_team),
        AuthorReach::Reached(_)
    ));

    // The mismatch: the write rule admits t1's unit, and no reach is
    // found. Its content is refused; a device granted directly is not
    // touched.
    let double = NoReach { inner: &team_space };
    let mismatch_others = OtherLogs::none().with_space(&double);
    let mismatch = fixture
        .resolve(None, &fixture.keys, &mismatch_others)
        .unwrap();
    assert!(valid(&mismatch, through_team), "the write rule admits it");
    assert_eq!(reach(&mismatch, through_team), AuthorReach::Unreached);
    assert!(matches!(reach(&mismatch, direct), AuthorReach::Reached(_)));

    // Without the team's log, a path through it cannot be judged: the
    // content waits for the log.
    let alone = fixture.resolve(None, &fixture.keys, &none).unwrap();
    assert!(!valid(&alone, through_team), "the write rule holds it");
    assert_eq!(reach(&alone, through_team), AuthorReach::Unjudged);
    assert!(matches!(reach(&alone, direct), AuthorReach::Reached(_)));
}

/// roster.md, 3.14, re-submission: a unit refused as `NotAWriter` through
/// a writer's grant, which is `NotAnAdministrator` and so never valid
/// rather than voided, has no events that void it, and its author, granted
/// later, does not re-submit it.
#[test]
fn a_not_a_writer_unit_no_event_voids_has_no_voiders() {
    let name = "a unit refused as NotAWriter that no event voids is not re-submitted";
    let history = family("across_logs")
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == name)
        .unwrap()
        .clone();
    let fixture = Fixture::new(&prefix(name), &history["events"]);
    let none = OtherLogs::none();
    let space = fixture.resolve(None, &fixture.keys, &none).unwrap();
    let unit = fixture.id("D writes through W's grant");
    assert_eq!(
        space
            .status(unit)
            .and_then(|s| s.class())
            .map(|c| frasil_base::errors::Class::name(c)),
        Some("NotAWriter")
    );
    assert!(space.voiders(unit).is_empty(), "never a writer's");
    assert!(
        space
            .status(fixture.id("P grants D write"))
            .is_some_and(|s| s.is_valid())
    );
}

#[test]
fn a_list_merge_that_voids_the_add_removes_validity_and_attribution() {
    let name = "a device added to a second person's list after an edit";
    let histories = family("across_logs");
    let history = histories
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == name)
        .unwrap();
    let mut fixture = Fixture::new(&prefix(name), &history["events"]);
    let lists = history["lists"].as_object().unwrap();
    for (person, events) in lists {
        fixture.name_events(events);
        name_other(&mut fixture, person, person_id(events), MemberType::Person);
    }
    let a = whole_list(&lists["person A"]);
    let b = whole_list(&lists["person B"]);
    let plain = OtherLogs::none().with_list(a.clone()).with_list(b.clone());
    let unit = fixture.id("d writes through A");
    let space = fixture.resolve(None, &fixture.keys, &plain).unwrap();
    assert!(space.status(unit).unwrap().is_valid());
    assert!(space.attribution(unit).is_some());
    let mut merged = a.list().unwrap().clone();
    let first = frasil_identity::DeviceList::new(&merged.log().genesis().signed()).unwrap();
    let author = common::space::list_device("roster/list-place/second/A", "a1");
    let fork = first.sign(&frasil_identity::body::ListBody::ack(), author.signer());
    merged.insert(&fork).unwrap();
    let others = OtherLogs::none()
        .with_list(HeldList::new(merged))
        .with_list(b);
    let space = fixture.resolve(None, &fixture.keys, &others).unwrap();
    assert!(!space.status(unit).unwrap().is_valid());
    assert!(space.attribution(unit).is_none());
}

#[test]
fn a_later_list_event_copy_does_not_place_its_add_after_list_forgetting() {
    use frasil_space::{KeyEventChecks, Limits, Options, Twins, UnitBodies, UnitBody};
    struct CopyAt(frasil_events::Event, EventId);
    impl UnitBodies for CopyAt {
        fn open(&self, _: &frasil_events::Event) -> UnitBody {
            UnitBody::Opened(Vec::new())
        }
        fn list_copy(&self, unit: &frasil_events::Event) -> Vec<frasil_events::Event> {
            if unit.id() == self.1 {
                vec![self.0.clone()]
            } else {
                Vec::new()
            }
        }
    }
    let name = "a device added to a second person's list after an edit";
    let histories = family("across_logs");
    let history = histories
        .as_array()
        .unwrap()
        .iter()
        .find(|h| text(h, "name") == name)
        .unwrap();
    let fixture = Fixture::new(&prefix(name), &history["events"]);
    let first = common::bytes(&history["lists"]["person A"][0], "signed");
    let mut list = frasil_identity::DeviceList::new(&first).unwrap();
    let author = common::space::list_device("roster/list-place/second/A", "a1");
    let later = list.sign(&frasil_identity::body::ListBody::ack(), author.signer());
    list.insert(&later).unwrap();
    let checkpoint = list.propose_checkpoint(author.signer()).unwrap();
    list.insert(&checkpoint).unwrap();
    let kept = list.forget(&list.merge()).unwrap();
    let later = frasil_events::decode(&later).unwrap();
    assert!(kept.dropped().contains(&later.id()));
    let unit = fixture.id("a1 copies A's first event");
    for (copied, expected) in [
        (later, false),
        (frasil_events::decode(&checkpoint).unwrap(), true),
    ] {
        let copy = CopyAt(copied, unit);
        for held in [HeldList::new(list.clone()), HeldList::kept(kept.clone())] {
            let others = OtherLogs::none()
                .with_list(held)
                .with_list(whole_list(&history["lists"]["person B"]));
            let space = Space::resolve(
                &fixture.log,
                None,
                Options {
                    keys: &fixture.keys,
                    limits: Limits::PROTOCOL,
                    others: &others,
                    units: &copy,
                    twins: Twins::Assumed,
                    key_checks: KeyEventChecks::StaleSeal,
                    notices: None,
                },
            )
            .unwrap();
            assert_eq!(space.status(unit).unwrap().is_valid(), expected);
            assert_eq!(space.attribution(unit).is_some(), expected);
            if !expected {
                assert_eq!(
                    space.status(unit).unwrap().class(),
                    Some(frasil_space::SpaceClass::NotAWriter.into())
                );
            }
        }
    }
}
