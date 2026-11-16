//! `identity.json`: `list_checkpoints` (identity.md, "List checkpoints"),
//! scenarios through each rule of list checkpoints, and the reference's
//! model check (`list_checkpoints.py`) as a seeded deterministic test: a
//! holder that forgot, holding only what it keeps, agrees with one that
//! kept everything.

mod common;

use common::{bytes, device, family, text};
use frasil_base::errors::Class;
use frasil_crypto::device::DeviceId;
use frasil_crypto::schemes::Scheme;
use frasil_events::kind::DEVICE_LIST;
use frasil_events::{Envelope, EventId, decode};
use frasil_identity::body::{Action, ListBody};
use frasil_identity::{
    DeviceList, IdentityClass, KeptList, Kind, ListRecord, MemberKeys, MergedList, RecordMember,
    RecordSeniority, Rootedness,
};
use frasil_resolve::Verdict;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

/// A verdict as `list_checkpoints` writes it: `valid`, or the class.
fn short(verdict: &Verdict<EventId, IdentityClass>) -> String {
    match verdict.class() {
        None => "valid".into(),
        Some(class) => class.name().into(),
    }
}

/// What a verifier needs of each active list member to vouch for it: its
/// kind, its rootedness, its agent and the add whose first sight starts its
/// waiting period (list_checkpoints.py's `_vouching`).
type Vouching = Vec<(
    DeviceId,
    Kind,
    Rootedness,
    Option<DeviceId>,
    Option<EventId>,
)>;

fn vouching(merged: &MergedList) -> Vouching {
    merged
        .active_members()
        .map(|m| {
            (
                m.device,
                m.kind,
                m.rooted(),
                m.agent,
                m.agent_adds.first().copied(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The vectors.

#[test]
fn list_checkpoints() {
    let f = family("list_checkpoints");
    let prefix = text(&f, "history_prefix");
    let rows: Vec<&Json> = f["events"].as_array().unwrap().iter().collect();
    let (list, names) = common::list_of(&rows);
    let by_name: BTreeMap<String, EventId> =
        names.iter().map(|(id, name)| (name.clone(), *id)).collect();
    let signed: BTreeMap<String, Vec<u8>> = rows
        .iter()
        .map(|row| (text(row, "name").to_string(), bytes(row, "signed")))
        .collect();
    let mut devices: BTreeMap<DeviceId, String> = ["D0", "D1", "D2", "R1", "R2"]
        .into_iter()
        .map(|name| (*device(prefix, name).device_id(), name.to_string()))
        .collect();
    devices.insert(*common::agent(prefix, "AG").device_id(), "AG".into());
    let named = |set: &BTreeSet<DeviceId>| -> Json {
        let mut out: Vec<String> = set.iter().map(|d| devices[d].clone()).collect();
        out.sort_unstable();
        Json::from(out)
    };
    let active = |merged: &MergedList| -> Json {
        let mut out: Vec<String> = merged
            .active_members()
            .map(|m| devices[&m.device].clone())
            .collect();
        out.sort_unstable();
        Json::from(out)
    };

    // The record the checkpoint carries, as signed, reads and encodes again,
    // and names the add that rooted each member in the agent.
    let checkpoint = by_name["D0 checkpoints"];
    let body = list.body(checkpoint).unwrap();
    assert_eq!(body.action, Action::Checkpoint);
    assert_eq!(body.record.as_deref(), Some(&bytes(&f, "record")[..]));
    let record = body.list_record().unwrap();
    assert_eq!(record.encode(), bytes(&f, "record"));
    assert_eq!(record.epoch, 1);
    assert_eq!(record.previous, None);
    let rooting: serde_json::Map<String, Json> = record
        .members
        .iter()
        .filter_map(|m| {
            let device = list.body(m.add).unwrap().device;
            Some((
                devices[&device].clone(),
                Json::from(names[&m.rooting?].clone()),
            ))
        })
        .collect();
    assert_eq!(Json::Object(rooting), f["forgot"]["rooting_adds"]);
    for m in &record.members {
        assert_eq!(m.rooting.is_some(), m.root == Rootedness::Agent);
        assert_eq!(m.agent.is_some(), m.root == Rootedness::Agent);
    }

    // The electorate on the checkpoint's past alone: the confirmed R1 in
    // it, R2, still rooted in the agent, and the agent out.
    let mut past = DeviceList::new(&signed["D0 starts the list"]).unwrap();
    for row in &rows[1..] {
        let id = by_name[text(row, "name")];
        if id == checkpoint || list.log().precedes(id, checkpoint) {
            past.insert(&signed[text(row, "name")]).unwrap();
        }
    }
    let alone_merged = past.merge();
    assert_eq!(
        named(alone_merged.electorate(checkpoint).unwrap()),
        f["electorate"]
    );
    let waiting: BTreeSet<DeviceId> = alone_merged
        .waiting_for(checkpoint)
        .unwrap()
        .iter()
        .map(|(d, _)| *d)
        .collect();
    let d0 = *device(prefix, "D0").device_id();
    let mut expected = alone_merged.electorate(checkpoint).unwrap().clone();
    expected.remove(&d0);
    assert_eq!(waiting, expected, "every one but the author waits");

    // A holder that kept everything.
    let merged = list.merge();
    let chain: Vec<String> = merged.chain().iter().map(|id| names[id].clone()).collect();
    assert_eq!(Json::from(chain), f["full"]["effective"]);
    let verdicts: serde_json::Map<String, Json> = merged
        .verdicts()
        .map(|(id, v)| (names[&id].clone(), Json::from(short(v))))
        .collect();
    assert_eq!(Json::Object(verdicts), f["full"]["verdicts"]);
    assert_eq!(active(&merged), f["full"]["active"]);
    assert_eq!(merged.checkpoint_validity()[&checkpoint], Ok(()));
    assert_eq!(merged.waiting_for(checkpoint), None);
    assert_eq!(
        merged
            .late()
            .map(|id| names[&id].clone())
            .collect::<Vec<_>>(),
        ["D2 revokes D1, unaware"]
    );
    // D2's revocation after the checkpoint excuses nobody: D1, added
    // first, outranks D2. D1 stays in the electorate, and voted by its ack.
    let d1 = *device(prefix, "D1").device_id();
    assert!(merged.electorate(checkpoint).unwrap().contains(&d1));

    // A holder that forgot under the checkpoint.
    let kept = list.forget(&merged).expect("a checkpoint in effect");
    let mut holds: Vec<String> = kept
        .canonical()
        .iter()
        .map(|id| names[id].clone())
        .collect();
    holds.sort_unstable();
    assert_eq!(Json::from(holds), f["forgot"]["holds"]);
    let mut alone: Vec<String> = kept
        .alone()
        .keys()
        .chain([&kept.first().id()])
        .map(|id| names[id].clone())
        .collect();
    alone.sort_unstable();
    assert_eq!(Json::from(alone.clone()), f["forgot"]["keeps_alone"]);
    let check_forgot = |kept: &KeptList, case: &str| {
        let forgot = kept.merge();
        assert_eq!(forgot.chain(), [checkpoint], "{case}");
        let verdicts: serde_json::Map<String, Json> = forgot
            .verdicts()
            .map(|(id, v)| (names[&id].clone(), Json::from(short(v))))
            .collect();
        assert_eq!(
            Json::Object(verdicts),
            f["forgot"]["verdicts"],
            "{case}: verdicts"
        );
        assert_eq!(active(&forgot), f["forgot"]["active"], "{case}: active");
        assert_eq!(vouching(&forgot), vouching(&merged), "{case}: vouching");
        assert!(kept.is_in_effect(), "{case}");
    };
    check_forgot(&kept, "forgotten by the holder");

    // The same holder built from exactly what the text keeps: the first
    // event, the checkpoint, the adds and rooting adds its record names,
    // the late event, and what follows, with the IDs of the rest dropped.
    // "D2 acks" continues its author's chain from the late revocation.
    let first = &signed["D0 starts the list"];
    let alone_signed: Vec<&[u8]> = alone.iter().map(|n| &signed[n][..]).collect();
    let after_names = [
        "R1, confirmed, acks",
        "D1 acks",
        "D2 acks",
        "D2 revokes D1 again",
    ];
    let after: Vec<&[u8]> = after_names.iter().map(|n| &signed[*n][..]).collect();
    let dropped: Vec<EventId> = by_name
        .iter()
        .filter(|(n, id)| {
            !alone.contains(n) && !after_names.contains(&n.as_str()) && **id != checkpoint
        })
        .map(|(_, id)| *id)
        .collect();
    let minimal = KeptList::new(
        first,
        &signed["D0 checkpoints"],
        alone_signed.iter().copied(),
        after.iter().copied(),
        dropped,
    )
    .unwrap();
    check_forgot(&minimal, "kept by the text");

    // Its sealed copy carries the first event, the checkpoint, the adds
    // and rooting adds its record names and what follows, and rebuilds it.
    let copy = minimal.signed_events();
    assert_eq!(copy[0], *first);
    assert_eq!(copy[1], signed["D0 checkpoints"]);
    let carried = minimal.carried();
    let mut carried_names: Vec<&str> = carried.iter().map(|id| names[id].as_str()).collect();
    carried_names.sort_unstable();
    assert_eq!(
        carried_names,
        [
            "D0 adds D1",
            "D0 adds D2",
            "D0 names the agent",
            "the agent adds R1",
            "the agent adds R2",
        ]
    );
    let again =
        KeptList::from_sealed_copy(copy.iter().map(Vec::as_slice), minimal.forgotten()).unwrap();
    check_forgot(&again, "rebuilt from its sealed copy");
    assert_eq!(again.dropped(), minimal.dropped());

    // The sealed copy of the list forgotten under the checkpoint, as the
    // vectors' `sealed_copy` gives it: what it carries, the IDs of what it
    // forgot, and the `frasil:system` snapshot state that carries both
    // (units.md, 2.12, key 5).
    let sealed = &f["sealed_copy"];
    let copy = kept.signed_events();
    let mut carries: Vec<String> = copy
        .iter()
        .map(|signed| names[&decode(signed).unwrap().id()].clone())
        .collect();
    carries.sort_unstable();
    let mut expected: Vec<String> = sealed["carries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .collect();
    expected.sort_unstable();
    assert_eq!(carries, expected, "a sealed copy carries");
    let forgotten: Vec<String> = kept
        .forgotten()
        .iter()
        .map(|id| names[id].clone())
        .collect();
    let mut expected_forgotten: Vec<String> = sealed["forgotten"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_string())
        .collect();
    expected_forgotten.sort_unstable();
    let mut sorted_forgotten = forgotten.clone();
    sorted_forgotten.sort_unstable();
    assert_eq!(sorted_forgotten, expected_forgotten, "what it forgot");
    let state = frasil_base::cbor::decode(&bytes(sealed, "system_state")).unwrap();
    let state = state.as_map().unwrap();
    let mut in_state: Vec<Vec<u8>> = state[&1]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_bytes().unwrap().to_vec())
        .collect();
    in_state.sort_unstable();
    let mut ours = copy.clone();
    ours.sort_unstable();
    assert_eq!(in_state, ours, "key 1 carries the copy");
    let pairs = state[&5].as_array().unwrap();
    assert_eq!(pairs.len(), 1);
    let pair = pairs[0].as_array().unwrap();
    assert_eq!(pair[0].as_bytes().unwrap(), &list.person_id()[..]);
    let ids: Vec<EventId> = pair[1]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| EventId(v.as_byte_array().unwrap()))
        .collect();
    assert_eq!(ids, kept.forgotten(), "key 5 names what it forgot");
    // A newcomer that starts from the copy and key 5 judges as the holder.
    let newcomer = KeptList::from_sealed_copy(copy.iter().map(Vec::as_slice), ids).unwrap();
    check_forgot(&newcomer, "a newcomer from the sealed copy and key 5");
    assert_eq!(newcomer.dropped(), kept.dropped());
    assert_eq!(newcomer.late_kept(), kept.late_kept());

    // Before D2 signs its revocation again, D2 re-signs the late one; with
    // it, nothing is left to re-sign.
    let d2 = *device(prefix, "D2").device_id();
    let mut before = DeviceList::new(first).unwrap();
    for row in &rows[1..] {
        let name = text(row, "name");
        if name != "D2 revokes D1 again" {
            before.insert(&signed[name]).unwrap();
        }
    }
    let work = before.late_work(&before.merge(), &d2);
    assert_eq!(work.resign, [ListBody::revoke(Kind::Device, d1)]);
    assert!(work.listed.is_empty());
    assert!(list.late_work(&merged, &d2).resign.is_empty());
}

/// A verdict of a list as `stolen` and `disjoint` write it, by name.
fn verdicts_of(merged: &MergedList, names: &BTreeMap<EventId, String>) -> Json {
    Json::Object(
        merged
            .verdicts()
            .map(|(id, v)| (names[&id].clone(), Json::from(short(v))))
            .collect(),
    )
}

#[test]
fn a_stolen_device_excuses_no_one() {
    let f = &family("list_checkpoints")["stolen"];
    let prefix = text(f, "history_prefix");
    let rows: Vec<&Json> = f["events"].as_array().unwrap().iter().collect();
    let (list, names) = common::list_of(&rows);
    let by_name: BTreeMap<&str, EventId> = names.iter().map(|(id, n)| (n.as_str(), *id)).collect();
    let merged = list.merge();
    let chain: Vec<String> = merged.chain().iter().map(|id| names[id].clone()).collect();
    assert_eq!(Json::from(chain), f["effective"]);
    assert_eq!(verdicts_of(&merged, &names), f["verdicts"]);
    // D2's revocations after its own checkpoint excuse no one: it waits for
    // D0 and D1.
    let checkpoint = by_name["D2 checkpoints on its old view"];
    let devices: BTreeMap<DeviceId, String> = ["D0", "D1", "D2"]
        .into_iter()
        .map(|n| (*device(prefix, n).device_id(), n.to_string()))
        .collect();
    let mut waiting: Vec<String> = merged
        .waiting_for(checkpoint)
        .unwrap()
        .iter()
        .map(|(d, _)| devices[d].clone())
        .collect();
    waiting.sort_unstable();
    assert_eq!(Json::from(waiting), f["waiting_for"]);
}

#[test]
fn disjoint_list_checkpoints_settle_on_the_smaller_id() {
    let f = &family("list_checkpoints")["disjoint"];
    let rows: Vec<&Json> = f["events"].as_array().unwrap().iter().collect();
    let (list, names) = common::list_of(&rows);
    let by_name: BTreeMap<&str, EventId> = names.iter().map(|(id, n)| (n.as_str(), *id)).collect();
    let chain_names = |merged: &MergedList| -> Json {
        Json::from(
            merged
                .chain()
                .iter()
                .map(|id| names[id].clone())
                .collect::<Vec<_>>(),
        )
    };
    // Each group's view: its last event and its past.
    let view_of = |last: &str| -> DeviceList {
        let id = by_name[last];
        let mut view: BTreeSet<EventId> = list.log().past(id);
        view.insert(id);
        let mut out = DeviceList::new(&list.log().genesis().signed()).unwrap();
        for e in list.log().canonical() {
            if view.contains(&e) && e != out.first() {
                out.insert(&list.log().event(e).unwrap().signed()).unwrap();
            }
        }
        out
    };
    let groups = &f["group_views"];
    assert_eq!(
        chain_names(&view_of("D1 revokes D3 after c1").merge()),
        groups["D0 and D1"]
    );
    assert_eq!(
        chain_names(&view_of("K revokes D1 after c2").merge()),
        groups["D2 and D3"]
    );
    // Once both are held, the smaller ID takes effect.
    let merged = list.merge();
    assert_eq!(chain_names(&merged), f["full"]["effective"]);
    assert_eq!(verdicts_of(&merged, &names), f["full"]["verdicts"]);
    let c1 = by_name["D0 checkpoints (c1)"];
    let c2 = by_name["D2 checkpoints, cut off (c2)"];
    let (win, lose) = (c1.min(c2), c1.max(c2));
    assert!(
        merged
            .electorate(c1)
            .unwrap()
            .is_disjoint(merged.electorate(c2).unwrap()),
        "two electorates with no device in common"
    );
    // A holder that forgot under each.
    for (key, kept_at, rival) in [
        ("forgot_under_loser", lose, true),
        ("forgot_under_winner", win, false),
    ] {
        let case = &f[key];
        assert_eq!(names[&kept_at], text(case, "kept"));
        let kept = list.forget_under(kept_at).unwrap();
        let mut holds: Vec<String> = kept
            .canonical()
            .iter()
            .map(|id| names[id].clone())
            .collect();
        holds.sort_unstable();
        assert_eq!(Json::from(holds), case["holds"], "{key}");
        let forgot = kept.merge();
        assert_eq!(verdicts_of(&forgot, &names), case["verdicts"], "{key}");
        if rival {
            assert_eq!(forgot.rivals(), &BTreeSet::from([win]), "{key}");
        } else {
            assert!(forgot.rivals().is_empty(), "{key}");
        }
        // Built from its sealed copy, it holds the same rival.
        let copy = kept.signed_events();
        let again =
            KeptList::from_sealed_copy(copy.iter().map(Vec::as_slice), kept.forgotten()).unwrap();
        assert_eq!(
            again.merge().rivals(),
            forgot.rivals(),
            "{key}: from a copy"
        );
        assert_eq!(
            verdicts_of(&again.merge(), &names),
            case["verdicts"],
            "{key}: from a copy"
        );
    }
}

/// `takeover`: a revoked device's backdated checkpoint (identity.md, "List
/// checkpoints", "Effect", heard devices). A junior device's checkpoint
/// hears the devices it revoked and waits for them for good; the most
/// senior device's does not; a recovery key excuses a lost senior device.
#[test]
fn a_backdated_list_checkpoint_hears_the_devices_it_revoked() {
    let family = &family("list_checkpoints")["takeover"];
    for kind in ["junior", "senior", "recovery"] {
        let f = &family[kind];
        let prefix = text(f, "history_prefix");
        let rows: Vec<&Json> = f["events"].as_array().unwrap().iter().collect();
        let (list, names) = common::list_of(&rows);
        let by_name: BTreeMap<&str, EventId> =
            names.iter().map(|(id, n)| (n.as_str(), *id)).collect();
        let merged = list.merge();
        let chain: Vec<String> = merged.chain().iter().map(|id| names[id].clone()).collect();
        assert_eq!(Json::from(chain), f["effective"], "{kind}");
        assert_eq!(verdicts_of(&merged, &names), f["verdicts"], "{kind}");
        let devices: BTreeMap<DeviceId, String> = ["D0", "D1", "D2"]
            .into_iter()
            .map(|n| (*device(prefix, n).device_id(), n.to_string()))
            .collect();
        let name_of = |d: &DeviceId| devices.get(d).cloned().unwrap_or_else(|| "K".into());
        for (checkpoint, expected) in f["waiting_for"].as_object().unwrap() {
            let c = by_name[checkpoint.as_str()];
            let mut waiting: Vec<String> = merged
                .waiting_for(c)
                .unwrap_or_default()
                .iter()
                .map(|(d, _)| name_of(d))
                .collect();
            waiting.sort_unstable();
            assert_eq!(&Json::from(waiting), expected, "{kind}: {checkpoint}");
        }
        if kind == "junior" {
            // X hears D0 and D1, revoked there only by D2, which they
            // outrank; neither may cite it.
            let x = by_name["D2 checkpoints, backdated (X)"];
            let heard: BTreeSet<String> = merged.heard(x).unwrap().iter().map(name_of).collect();
            assert_eq!(heard, BTreeSet::from(["D0".into(), "D1".into()]));
            let d1 = *device(prefix, "D1").device_id();
            let h = by_name["D0 checkpoints (H)"];
            assert!(merged.heard(h).unwrap().is_empty());
            // In effect, H is contested by nobody; X, not in effect, by D1.
            assert_eq!(list.contest(&d1, h), None);
            assert_eq!(list.contest(&d1, x), Some(frasil_identity::Contest::Heard));
        }
    }
}

#[test]
fn list_checkpoint_signatures() {
    let f = &family("list_checkpoints")["signatures"];
    let rows: Vec<&Json> = f["events"].as_array().unwrap().iter().collect();
    let (list, names) = common::list_of(&rows);
    let merged = list.merge();
    let verdicts: serde_json::Map<String, Json> = merged
        .checkpoint_validity()
        .iter()
        .map(|(id, v)| {
            let class = v.err().map(Class::name).unwrap_or("checkpoint");
            (names[id].clone(), Json::from(class))
        })
        .collect();
    assert_eq!(Json::Object(verdicts), f["verdicts"]);
}

#[test]
fn list_record_refusals() {
    let f = family("list_checkpoints");
    for case in f["record_refusals"].as_array().unwrap() {
        let name = text(case, "name");
        let got = ListRecord::read(&bytes(case, "record"))
            .err()
            .map(Class::name);
        assert_eq!(got, case["error"].as_str(), "{name}");
    }
}

// ---------------------------------------------------------------------------
// A network of devices, each with its own replica of the list.

/// Devices of one person, each holding a replica of the list it signs on,
/// and the list of every event. Replicas are clones of one list, so each
/// signature is verified once.
struct Net {
    prefix: String,
    start: DeviceList,
    all: DeviceList,
    replicas: BTreeMap<String, DeviceList>,
    keys: BTreeMap<String, MemberKeys>,
    names: BTreeMap<EventId, String>,
    /// The events signed as a dishonest device signs them: unfenced
    /// checkpoints, events on parents chosen against the following rule,
    /// forks, revocations on a revoked device's old view, and an attack's.
    dishonest: BTreeSet<EventId>,
}

impl Net {
    fn new(first: &str, prefix: &str) -> Self {
        let keys = device(prefix, first);
        let start = DeviceList::new(&DeviceList::first_event(&keys)).unwrap();
        let mut net = Self {
            prefix: prefix.to_string(),
            all: start.clone(),
            replicas: BTreeMap::from([(first.to_string(), start.clone())]),
            start,
            keys: BTreeMap::from([(first.to_string(), keys)]),
            names: BTreeMap::new(),
            dishonest: BTreeSet::new(),
        };
        let id = net.all.first();
        net.names.insert(id, format!("{first} starts the list"));
        net
    }

    fn keys(&mut self, name: &str) -> &MemberKeys {
        let prefix = self.prefix.clone();
        self.keys
            .entry(name.to_string())
            .or_insert_with(|| device(&prefix, name))
    }

    fn id_of(&mut self, name: &str) -> DeviceId {
        *self.keys(name).device_id()
    }

    fn replica(&mut self, name: &str) -> &mut DeviceList {
        let start = self.start.clone();
        self.replicas.entry(name.to_string()).or_insert(start)
    }

    /// Places a signed event in `by`'s replica and in the whole list.
    fn publish(&mut self, by: &str, signed: &[u8], label: &str) -> EventId {
        let id = decode(signed).unwrap().id();
        self.replica(by).insert(signed).unwrap();
        self.all.insert(signed).unwrap();
        self.names.insert(id, label.to_string());
        id
    }

    fn act(&mut self, by: &str, body: &ListBody, label: &str) -> EventId {
        self.keys(by);
        self.replica(by);
        let signed = self.replicas[by].sign(body, self.keys[by].signer());
        self.publish(by, &signed, label)
    }

    fn add_as(&mut self, by: &str, who: &str, kind: Kind) -> EventId {
        let person = self.all.person_id();
        let adder = self.id_of(by);
        if kind == Kind::RecoveryAgent && !self.keys.contains_key(who) {
            let agent = common::agent(&self.prefix, who);
            self.keys.insert(who.to_string(), agent);
        }
        let keys = self.keys(who);
        let body = ListBody::add(
            kind,
            &keys.public(kind),
            keys.prove_possession(&person, &adder, kind),
        );
        self.act(by, &body, &format!("{by} adds {who}"))
    }

    fn add(&mut self, by: &str, who: &str) -> EventId {
        self.add_as(by, who, Kind::Device)
    }

    fn revoke(&mut self, by: &str, who: &str, label: &str) -> EventId {
        let device = self.id_of(who);
        self.act(by, &ListBody::revoke(Kind::Device, device), label)
    }

    fn ack(&mut self, by: &str) -> EventId {
        self.keys(by);
        self.replica(by);
        let signed = self.replicas[by].ack(self.keys[by].signer());
        self.publish(by, &signed, &format!("{by} acks"))
    }

    fn confirm(&mut self, by: &str, who: &str) -> EventId {
        let device = self.id_of(who);
        self.act(
            by,
            &ListBody::confirm(Kind::Device, device),
            &format!("{by} confirms {who}"),
        )
    }

    fn checkpoint(&mut self, by: &str) -> Result<EventId, IdentityClass> {
        self.keys(by);
        self.replica(by);
        let signed = self.replicas[by].propose_checkpoint(self.keys[by].signer())?;
        Ok(self.publish(by, &signed, &format!("{by} checkpoints")))
    }

    /// A checkpoint proposed even while another waits for votes.
    fn checkpoint_anyway(&mut self, by: &str, label: &str) -> Result<EventId, IdentityClass> {
        self.keys(by);
        self.replica(by);
        let signed = self.replicas[by].propose_checkpoint_anyway(self.keys[by].signer())?;
        Ok(self.publish(by, &signed, label))
    }

    /// A checkpoint signed as a dishonest device signs one: citing every
    /// head of its view and naming `previous` (list_checkpoints.py's
    /// `make_checkpoint` with `fence=False`).
    fn checkpoint_unfenced(
        &mut self,
        by: &str,
        previous: Option<Option<EventId>>,
        label: &str,
    ) -> Result<EventId, IdentityClass> {
        self.keys(by);
        self.replica(by);
        let signed =
            self.replicas[by].propose_checkpoint_unfenced(self.keys[by].signer(), previous)?;
        let id = self.publish(by, &signed, label);
        self.dishonest.insert(id);
        Ok(id)
    }

    /// `by` takes every event `other` holds; `other` learns nothing.
    fn take_view(&mut self, by: &str, other: &str) {
        let theirs: BTreeSet<EventId> = self.replica(other).log().canonical().into_iter().collect();
        let order: Vec<EventId> = self
            .all
            .log()
            .canonical()
            .into_iter()
            .filter(|id| theirs.contains(id))
            .collect();
        for id in order {
            let signed = self.all.log().event(id).unwrap().signed();
            self.replica(by).insert(&signed).unwrap();
        }
    }

    /// Signs `body` as given, `follows` included, on `by`'s chain with
    /// these parents.
    fn raw(&mut self, by: &str, body: &ListBody, parents: Vec<EventId>, label: &str) -> EventId {
        self.keys(by);
        self.replica(by);
        let replica = &self.replicas[by];
        let keys = &self.keys[by];
        let (seq, prev) = replica.log().next_in_chain(keys.device_id());
        let mut parents: BTreeSet<EventId> = parents.into_iter().collect();
        parents.extend(prev);
        let signed = Envelope {
            kind: DEVICE_LIST,
            log: Some(replica.log().id()),
            ed: *keys.identity(),
            kc: *keys.signer().kc(),
            seq,
            prev,
            parents: parents.into_iter().collect(),
            cuts: Vec::new(),
            body: body.encode(),
            scheme: Scheme::Hybrid,
        }
        .sign(keys.signer());
        let id = self.publish(by, &signed, label);
        self.dishonest.insert(id);
        id
    }

    /// The devices exchange every event they hold.
    fn sync(&mut self, names: &[&str]) {
        let mut union = BTreeSet::new();
        for name in names {
            union.extend(self.replica(name).log().canonical());
        }
        let order: Vec<EventId> = self
            .all
            .log()
            .canonical()
            .into_iter()
            .filter(|id| union.contains(id))
            .collect();
        for name in names {
            for id in &order {
                let signed = self.all.log().event(*id).unwrap().signed();
                self.replicas
                    .get_mut(*name)
                    .unwrap()
                    .insert(&signed)
                    .unwrap();
            }
        }
    }

    /// A list of exactly these events of the whole list.
    fn view(&self, events: &BTreeSet<EventId>) -> DeviceList {
        let mut list = self.start.clone();
        for id in self.all.log().canonical() {
            if events.contains(&id) && id != list.first() {
                list.insert(&self.all.log().event(id).unwrap().signed())
                    .unwrap();
            }
        }
        list
    }

    fn verdict(&self, merged: &MergedList, label: &str) -> String {
        let id = self
            .names
            .iter()
            .find(|(_, n)| *n == label)
            .map(|(id, _)| *id)
            .unwrap_or_else(|| panic!("no event {label}"));
        short(merged.verdict(id).unwrap())
    }
}

// ---------------------------------------------------------------------------
// Scenarios.

const PREFIX: &str = "identity/list-checkpoints";

#[test]
fn a_checkpoint_waits_for_every_device_then_takes_effect() {
    let mut net = Net::new("D0", PREFIX);
    net.add("D0", "D1");
    net.add("D0", "D2");
    net.sync(&["D0", "D1", "D2"]);
    let d1_last = net.ack("D1");
    let c = net.checkpoint("D0").unwrap();
    let merged = net.all.merge();
    assert_eq!(merged.checkpoint_validity()[&c], Ok(()));
    assert!(merged.chain().is_empty());
    let d1 = net.id_of("D1");
    let d2 = net.id_of("D2");
    assert_eq!(
        merged.waiting_for(c).unwrap(),
        [(d1, Some(d1_last)), (d2, None)]
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
    net.sync(&["D0", "D1"]);
    let ack = net.ack("D1");
    let merged = net.all.merge();
    assert!(merged.chain().is_empty());
    assert_eq!(merged.waiting_for(c).unwrap(), [(d2, None)]);
    // D1's ack follows the checkpoint.
    assert_eq!(net.all.body(ack).unwrap().follows, [c]);
    net.sync(&["D0", "D2"]);
    // D2 votes by a revocation rather than an ack: any event after it.
    let revoke = net.revoke("D2", "D1", "D2 revokes D1");
    let merged = net.all.merge();
    assert_eq!(merged.chain(), [c]);
    assert!(merged.is_valid(revoke));
    assert_eq!(merged.waiting_for(c), None);
    assert!(merged.active(&d1).is_none());
}

#[test]
fn who_may_sign_a_checkpoint_and_an_ack() {
    let mut net = Net::new("D0", PREFIX);
    net.add_as("D0", "A", Kind::RecoveryAgent);
    net.add("D0", "D1");
    net.sync(&["D0", "A", "D1"]);
    // An agent signs no checkpoint and no ack.
    assert_eq!(
        net.checkpoint("A").unwrap_err(),
        IdentityClass::UntrustedSigner
    );
    net.ack("A");
    // A record signed by the agent, the one D0 would sign on that past.
    let signed = net.replicas["D0"]
        .propose_checkpoint(net.keys["D0"].signer())
        .unwrap();
    let record = ListBody::decode(decode(&signed).unwrap().unverified_body())
        .unwrap()
        .list_record()
        .unwrap();
    let by_agent = net.raw(
        "A",
        &ListBody::checkpoint(&record),
        Vec::new(),
        "A checkpoints",
    );
    let merged = net.all.merge();
    assert_eq!(net.verdict(&merged, "A acks"), "AgentLimited");
    assert_eq!(
        merged.checkpoint_validity()[&by_agent],
        Err(IdentityClass::UntrustedSigner)
    );
    assert_eq!(net.verdict(&merged, "A checkpoints"), "UntrustedSigner");
    // A device that is not rooted signs one.
    assert!(net.checkpoint("D1").is_ok());
}

#[test]
fn a_record_that_is_not_its_past_is_bad_checkpoint() {
    let mut net = Net::new("D0", PREFIX);
    net.add("D0", "D1");
    let signed = net.replicas["D0"]
        .propose_checkpoint(net.keys["D0"].signer())
        .unwrap();
    let mut record = ListBody::decode(decode(&signed).unwrap().unverified_body())
        .unwrap()
        .list_record()
        .unwrap();
    // Leave D1 out.
    record.members.truncate(1);
    let c = net.raw("D0", &ListBody::checkpoint(&record), Vec::new(), "bad");
    let merged = net.all.merge();
    assert_eq!(
        merged.checkpoint_validity()[&c],
        Err(IdentityClass::BadCheckpoint)
    );
    assert!(merged.chain().is_empty());
    // A record of another version is refused alone.
    let mut map = match frasil_base::cbor::decode(&record.encode()).unwrap() {
        frasil_base::cbor::Value::Map(map) => map,
        _ => unreachable!(),
    };
    map.insert(1, frasil_base::cbor::Value::Unsigned(2));
    let mut body = ListBody::checkpoint(&record);
    body.record = Some(frasil_base::cbor::Value::Map(map).encode());
    let id = net.raw("D0", &body, Vec::new(), "version 2");
    assert_eq!(
        net.all.check_alone(id),
        Some(IdentityClass::Shared(
            frasil_base::ErrorClass::UnsupportedVersion
        ))
    );
}

#[test]
fn follows_are_checked_against_the_parents() {
    let mut net = Net::new("D0", PREFIX);
    net.add("D0", "D1");
    net.sync(&["D0", "D1"]);
    let c = net.checkpoint("D0").unwrap();
    net.sync(&["D0", "D1"]);
    // An ack that cites the checkpoint and declares nothing.
    net.raw(
        "D1",
        &ListBody::ack(),
        vec![c],
        "D1 acks, declaring nothing",
    );
    let merged = net.all.merge();
    assert_eq!(
        net.verdict(&merged, "D1 acks, declaring nothing"),
        "BadCuts"
    );
    // It is no vote.
    assert!(merged.chain().is_empty());
    // An ack that declares a checkpoint it does not cite.
    let mut stray = Net::new("D0", PREFIX);
    stray.add("D0", "D1");
    stray.raw(
        "D0",
        &ListBody::ack().with_follows(vec![EventId([7; 32])]),
        Vec::new(),
        "stray",
    );
    assert_eq!(stray.verdict(&stray.all.merge(), "stray"), "BadCuts");
}

#[test]
fn late_and_mixed_events() {
    let mut net = Net::new("D0", PREFIX);
    net.add("D0", "D1");
    net.add("D0", "D2");
    net.sync(&["D0", "D1", "D2"]);
    let late = net.revoke("D2", "D1", "D2 revokes D1, unaware");
    let c = net.checkpoint("D0").unwrap();
    net.sync(&["D0", "D1"]);
    net.ack("D1");
    net.sync(&["D0", "D1", "D2"]);
    net.ack("D2");
    let merged = net.all.merge();
    assert_eq!(merged.chain(), [c]);
    assert_eq!(net.verdict(&merged, "D2 revokes D1, unaware"), "Late");
    // D1, which holds the late revocation, cites it beside the checkpoint's
    // successors: its event is after the checkpoint, with a parent that is
    // not.
    let heads = net.replicas["D1"].log().heads();
    let mut parents: Vec<EventId> = heads.into_iter().filter(|&h| h != late).collect();
    parents.push(late);
    let mixed = net.raw(
        "D1",
        &ListBody::ack().with_follows(vec![c]),
        parents,
        "D1 acks, citing the late revocation",
    );
    let merged = net.all.merge();
    assert_eq!(
        net.verdict(&merged, "D1 acks, citing the late revocation"),
        "MixedCut"
    );
    // A holder that forgot agrees.
    let kept = net.all.forget(&merged).unwrap();
    assert!(kept.contains(late), "an outside parent is kept alone");
    assert_eq!(short(kept.merge().verdict(mixed).unwrap()), "MixedCut");
    // A device signing after it cites none of the late events.
    let next = net.revoke("D2", "D1", "D2 revokes D1 again");
    let event = net.all.log().event(next).unwrap();
    assert!(event.parents().iter().all(|p| *p != mixed && *p != late));
    assert_eq!(net.all.body(next).unwrap().follows, [c]);
    assert!(net.all.merge().is_valid(next));
}

#[test]
fn checkpoints_chain_and_holders_forget_twice() {
    let mut net = Net::new("D0", PREFIX);
    net.add("D0", "D1");
    net.sync(&["D0", "D1"]);
    let c1 = net.checkpoint("D0").unwrap();
    net.sync(&["D0", "D1"]);
    net.ack("D1");
    net.sync(&["D0", "D1"]);
    net.add("D1", "D2");
    net.sync(&["D0", "D1", "D2"]);
    let c2 = net.checkpoint("D1").unwrap();
    let record = net.all.body(c2).unwrap().list_record().unwrap();
    assert_eq!(record.epoch, 2);
    assert_eq!(record.previous, Some(c1));
    assert_eq!(net.all.body(c2).unwrap().follows, [c1]);
    let merged = net.all.merge();
    assert_eq!(merged.chain(), [c1]);
    let kept1 = net.all.forget(&merged).unwrap();
    assert_eq!(kept1.checkpoint(), c1);
    assert_eq!(kept1.merge().chain(), [c1]);
    net.sync(&["D0", "D1", "D2"]);
    net.ack("D0");
    net.ack("D2");
    let merged = net.all.merge();
    assert_eq!(merged.chain(), [c1, c2]);
    // The holder that forgot under c1 takes the new events and forgets again.
    let mut kept1 = kept1;
    for id in net.all.log().canonical() {
        let after = net.all.body(id).is_some_and(|b| !b.follows.is_empty());
        if after && !kept1.contains(id) {
            kept1
                .insert(&net.all.log().event(id).unwrap().signed())
                .unwrap();
        }
    }
    let merged1 = kept1.merge();
    assert_eq!(merged1.chain(), [c1, c2]);
    let kept2 = kept1.forget(&merged1).unwrap();
    assert_eq!(kept2.checkpoint(), c2);
    let direct = net.all.forget(&merged).unwrap();
    assert_eq!(direct.checkpoint(), c2);
    for kept in [&kept2, &direct] {
        let k = kept.merge();
        assert_eq!(k.chain(), [c2]);
        for id in kept.canonical() {
            assert_eq!(k.verdict(id), merged.verdict(id));
        }
        let a: Vec<DeviceId> = k.active_members().map(|m| m.device).collect();
        let b: Vec<DeviceId> = merged.active_members().map(|m| m.device).collect();
        assert_eq!(a, b);
    }
    // A device a checkpoint does not list has its path ended by it.
    assert_eq!(merged.unlisted_end(&DeviceId([3; 32])), Some(c2));
    assert_eq!(merged.unlisted_end(&net.id_of("D2")), None);
}

#[test]
fn a_list_without_checkpoints_merges_as_before() {
    let mut net = Net::new("D0", PREFIX);
    net.add("D0", "D1");
    net.add("D0", "D2");
    net.sync(&["D0", "D1", "D2"]);
    net.revoke("D1", "D2", "D1 revokes D2");
    net.revoke("D2", "D1", "D2 revokes D1");
    let plain = net.all.merge();
    let through = net.all.merge_through_checkpoints();
    assert_eq!(
        plain.verdicts().collect::<Vec<_>>(),
        through.verdicts().collect::<Vec<_>>()
    );
    assert_eq!(plain.members(), through.members());
    assert!(through.chain().is_empty());
    assert!(net.all.forget(&plain).is_none());
}

#[test]
fn a_holder_that_forgot_keeps_what_rooted_a_member_in_an_agent() {
    let mut net = Net::new("D0", PREFIX);
    net.add_as("D0", "A", Kind::RecoveryAgent);
    net.sync(&["D0", "A"]);
    let rooting = net.add("A", "X");
    net.sync(&["D0", "A", "X"]);
    // X, rooted in the agent, adds Y: Y is rooted there too, by X's add.
    let through_x = net.add("X", "Y");
    net.sync(&["D0", "A", "X", "Y"]);
    let c = net.checkpoint("D0").unwrap();
    let merged = net.all.merge();
    // X and Y wait, so they are not waited for: D0 alone votes.
    assert_eq!(merged.chain(), [c]);
    let (x, y) = (net.id_of("X"), net.id_of("Y"));
    assert_eq!(
        merged.electorate(c).unwrap(),
        &BTreeSet::from([net.id_of("D0")])
    );
    assert!(merged.is_waiting(&x) && merged.is_waiting(&y));
    assert_eq!(merged.member(&x).unwrap().agent_adds, [rooting]);
    // The record names each one's rooting add.
    let record = net.all.body(c).unwrap().list_record().unwrap();
    let rootings: BTreeSet<EventId> = record.members.iter().filter_map(|m| m.rooting).collect();
    assert_eq!(rootings, BTreeSet::from([rooting, through_x]));
    let kept = net.all.forget(&merged).unwrap();
    assert!(kept.contains(rooting) && kept.contains(through_x));
    let k = kept.merge();
    assert!(k.is_waiting(&x));
    assert_eq!(k.member(&x).unwrap().agent_adds, [rooting]);
    assert_eq!(k.member(&y).unwrap().agent_adds, [through_x]);
    assert_eq!(vouching(&k), vouching(&merged));
    // Built from its sealed copy, which carries the rooting adds, X still
    // waits, counted from the add the record names.
    let copy = kept.signed_events();
    let rebuilt =
        KeptList::from_sealed_copy(copy.iter().map(Vec::as_slice), kept.forgotten()).unwrap();
    let b = rebuilt.merge();
    assert!(b.is_waiting(&x) && !b.recipients().contains(&x));
    assert_eq!(b.member(&x).unwrap().agent_adds, [rooting]);
    assert_eq!(vouching(&b), vouching(&merged));
    #[cfg(feature = "ext-recovery-agent")]
    {
        // The veto traces through the rooting adds' authors: vetoing X
        // revokes Y, which X added, at both holders.
        assert!(b.agent_rooted().any(|m| m.device == x));
        let whole = net.all.veto(&merged, &x, true);
        assert_eq!(whole.len(), 3);
        assert_eq!(rebuilt.veto(&b, &x, true), whole);
        assert_eq!(kept.veto(&k, &x, true), whole);
    }
}

#[test]
fn a_confirmed_device_is_waited_for() {
    let mut net = Net::new("D0", PREFIX);
    net.add_as("D0", "A", Kind::RecoveryAgent);
    net.sync(&["D0", "A"]);
    net.add("A", "R1");
    net.add("A", "R2");
    net.sync(&["D0", "A", "R1", "R2"]);
    net.confirm("D0", "R1");
    net.sync(&["D0", "R1"]);
    let c = net.checkpoint("D0").unwrap();
    let merged = net.all.merge();
    let r1 = net.id_of("R1");
    assert!(merged.chain().is_empty());
    assert_eq!(merged.waiting_for(c).unwrap(), [(r1, None)]);
    // A confirmed device signs a checkpoint too, and votes by an ack.
    net.sync(&["D0", "R1"]);
    net.ack("R1");
    assert_eq!(net.all.merge().chain(), [c]);
}

#[test]
fn excuses_accumulate() {
    let mut net = Net::new("D0", PREFIX);
    net.add("D0", "D1");
    net.add("D0", "D2");
    net.sync(&["D0", "D1", "D2"]);
    let c = net.checkpoint("D0").unwrap();
    net.sync(&["D0", "D1"]);
    // D1, which outranks D2 (added first), votes by revoking D2, which
    // never returns: D2 is excused.
    let revoke = net.revoke("D1", "D2", "D1 revokes D2");
    let merged = net.all.merge();
    assert_eq!(merged.chain(), [c]);
    assert!(merged.is_valid(revoke));
    // D0, unaware of it, revokes D1 after the checkpoint: D1's revocation
    // is void, yet D2 stays excused, so the checkpoint stays in effect. D0
    // outranks D1, so its revocation excuses D1 too.
    net.revoke("D0", "D1", "D0 revokes D1");
    let merged = net.all.merge();
    assert_eq!(net.verdict(&merged, "D1 revokes D2"), "RevokedConcurrently");
    assert_eq!(merged.chain(), [c]);
    let d0 = net.id_of("D0");
    assert_eq!(merged.electorate(c).unwrap(), &BTreeSet::from([d0]));
    let kept = net.all.forget(&merged).unwrap();
    let k = kept.merge();
    assert_eq!(k.chain(), [c]);
    for id in kept.canonical() {
        assert_eq!(k.verdict(id), merged.verdict(id));
    }
}

#[test]
fn in_a_world_keys_come_from_its_adds_only() {
    let mut net = Net::new("D0", PREFIX);
    net.add("D0", "D1");
    net.sync(&["D0", "D1"]);
    let c = net.checkpoint("D0").unwrap();
    net.sync(&["D0", "D1"]);
    net.ack("D1");
    // A device no add names signs after the checkpoint: no list member at
    // any place of the world, final.
    let ack = net.raw(
        "S",
        &ListBody::ack().with_follows(vec![c]),
        vec![c],
        "S acks",
    );
    let merged = net.all.merge();
    assert_eq!(merged.chain(), [c]);
    assert_eq!(net.verdict(&merged, "S acks"), "UntrustedSigner");
    let kept = net.all.forget(&merged).unwrap();
    assert_eq!(short(kept.merge().verdict(ack).unwrap()), "UntrustedSigner");
}

#[test]
fn a_device_proposes_only_when_no_checkpoint_waits() {
    let mut net = Net::new("D0", PREFIX);
    net.add("D0", "D1");
    net.sync(&["D0", "D1"]);
    let c = net.checkpoint("D0").unwrap();
    net.sync(&["D0", "D1"]);
    // c waits for D1's vote.
    assert_eq!(
        net.checkpoint("D1").unwrap_err(),
        IdentityClass::CheckpointPending
    );
    net.ack("D1");
    net.sync(&["D0", "D1"]);
    assert_eq!(net.all.merge().chain(), [c]);
    assert!(net.checkpoint("D1").is_ok());
}

/// A list event at the widest encodings: a checkpoint with 16 parents, 4
/// `follows` and a record of `n` members, each at its widest and with its
/// tip, `rooted` of them rooted in an agent.
fn widest_checkpoint(n: usize, rooted: bool) -> Vec<u8> {
    let keys = device(PREFIX, "wide");
    let max = u64::MAX;
    let mut members = Vec::new();
    let mut tips = Vec::new();
    for i in 0..n {
        let mut id = [0xff; 32];
        id[0] = i as u8;
        members.push(RecordMember {
            add: EventId(id),
            root: if rooted {
                Rootedness::Agent
            } else {
                Rootedness::None
            },
            agent: rooted.then_some(DeviceId([0xfe; 32])),
            confirmed: true,
            seniority: RecordSeniority {
                epoch: max,
                height: max,
                add: EventId(id),
            },
            rooting: rooted.then_some(EventId([0xfd; 32])),
        });
        tips.push((DeviceId(id), max, EventId(id)));
    }
    let record = ListRecord {
        epoch: max,
        previous: Some(EventId([0xfc; 32])),
        members,
        tips,
        forks: Vec::new(),
        heard: Vec::new(),
    };
    let follows = (0..4u8).map(|i| EventId([0xe0 + i; 32])).collect();
    Envelope {
        kind: DEVICE_LIST,
        log: Some(EventId([0xaa; 32])),
        ed: *keys.identity(),
        kc: *keys.signer().kc(),
        seq: max,
        prev: Some(EventId([0x10; 32])),
        parents: (0..16u8).map(|i| EventId([0x10 + i; 32])).collect(),
        cuts: Vec::new(),
        body: ListBody::checkpoint(&record).with_follows(follows).encode(),
        scheme: Scheme::Hybrid,
    }
    .sign(keys.signer())
}

/// Two groups of the person's devices that each revoke the other after
/// their own checkpoint, without a recovery key (list_checkpoints.py's
/// `_disjoint_checks`, "no-recovery"): D3, junior to D0 and D1, excuses
/// neither, so c2 waits for both for good, in its group's view and once the
/// groups meet; c1, whose revoker D1 outranks D2 and D3, takes effect.
#[test]
fn a_junior_group_without_a_recovery_key_waits_for_good() {
    let mut net = Net::new("D0", "identity/list-checkpoints/no-recovery");
    for d in ["D1", "D2", "D3"] {
        net.add("D0", d);
    }
    net.sync(&["D0", "D1", "D2", "D3"]);
    let c1 = net.checkpoint("D0").unwrap();
    let c2 = net.checkpoint("D2").unwrap();
    net.sync(&["D0", "D1"]);
    net.sync(&["D2", "D3"]);
    for x in ["D2", "D3"] {
        net.revoke("D1", x, &format!("D1 revokes {x} after c1"));
    }
    for x in ["D0", "D1"] {
        net.revoke("D3", x, &format!("D3 revokes {x} after c2"));
    }
    net.sync(&["D2", "D3"]);
    let group2 = net.replicas["D3"].merge();
    assert!(group2.chain().is_empty());
    let mut waiting: Vec<DeviceId> = group2
        .waiting_for(c2)
        .unwrap()
        .iter()
        .map(|(d, _)| *d)
        .collect();
    waiting.sort_unstable();
    let mut expected = vec![net.id_of("D0"), net.id_of("D1")];
    expected.sort_unstable();
    assert_eq!(waiting, expected);
    // D3 hears nothing it may not cite: c2 hears neither D0 nor D1, which
    // the record keeps.
    assert!(group2.heard(c2).unwrap().is_empty());
    net.sync(&["D0", "D1", "D2", "D3"]);
    assert_eq!(net.all.merge().chain(), &[c1]);
}

#[test]
fn the_proposal_threshold_is_a_thousand_and_twenty_four() {
    assert_eq!(frasil_identity::PROPOSAL_THRESHOLD, 1_024);
    let mut net = Net::new("D0", "identity/list-checkpoints/threshold");
    net.add("D0", "D1");
    let merged = net.all.merge();
    assert_eq!(merged.valid_since_checkpoint(), 1);
    assert!(!merged.proposal_due());
}

#[test]
fn a_record_fits_its_lower_member_bound() {
    let bound = frasil_events::kind::limits(DEVICE_LIST).bytes;
    let plain = widest_checkpoint(70, false).len();
    let in_agent = widest_checkpoint(51, true).len();
    eprintln!("70 unrooted members: {plain} bytes; 51 rooted in an agent: {in_agent} bytes");
    assert!(plain <= bound, "{plain}");
    assert!(in_agent <= bound, "{in_agent}");
}

// ---------------------------------------------------------------------------
// The model check (list_checkpoints.py), seeded and deterministic.

/// SplitMix64: a small deterministic generator, so each seed builds one
/// history.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn pick<'a>(&mut self, from: &'a [String]) -> &'a String {
        &from[(self.next() % from.len() as u64) as usize]
    }

    /// A whole number in `[low, high]`.
    fn between(&mut self, low: usize, high: usize) -> usize {
        low + (self.next() % (high - low + 1) as u64) as usize
    }

    fn shuffle(&mut self, items: &mut [String]) {
        for i in (1..items.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
    }
}

/// The person's unrooted devices split in two groups that see only each
/// other (list_checkpoints.py's `_split`). In each, one device checkpoints,
/// and a device of the group revokes every device of the other group,
/// before the checkpoint (any device) or after it (another than its
/// author, so that it excuses); every device of the group then acks. Each
/// checkpoint can take effect in its group's view with an electorate
/// disjoint from the other's.
fn split(net: &mut Net, rng: &mut Rng, devices: &[String], step: usize) -> bool {
    if devices.len() < 2 {
        return false;
    }
    let mut devices = devices.to_vec();
    rng.shuffle(&mut devices);
    let k = rng.between(1, devices.len() - 1);
    let groups = [devices[..k].to_vec(), devices[k..].to_vec()];
    let sync = |net: &mut Net, g: &[String]| {
        if g.len() > 1 {
            net.sync(&g.iter().map(String::as_str).collect::<Vec<_>>());
        }
    };
    for g in &groups {
        sync(net, g);
    }
    for (g, other) in [(&groups[0], &groups[1]), (&groups[1], &groups[0])] {
        let after = g.len() > 1 && rng.unit() < 0.5;
        let author = g[0].clone();
        let remover = if after {
            g[1].clone()
        } else {
            rng.pick(g).clone()
        };
        if !after {
            for o in other {
                net.revoke(
                    &remover,
                    o,
                    &format!("{step}: {remover} revokes {o}, cut off"),
                );
            }
            sync(net, g);
        }
        let _ = net.checkpoint_anyway(&author, &format!("{step}: {author} checkpoints, cut off"));
        sync(net, g);
        if after {
            for o in other {
                net.revoke(
                    &remover,
                    o,
                    &format!("{step}: {remover} revokes {o} after the checkpoint"),
                );
            }
            sync(net, g);
        }
        for d in g.iter().filter(|d| **d != author) {
            net.sync(&[d, &author]);
            net.ack(d);
        }
        sync(net, g);
    }
    true
}

/// A backdated list checkpoint the model built (list_checkpoints.py's
/// `_takeover`).
struct Attack {
    checkpoint: EventId,
    /// The attacker first, then its colluder or the device it added.
    attackers: Vec<String>,
    victims: Vec<String>,
    /// "alone", "colluder", "sybil" or "selective".
    mode: &'static str,
    /// Whether a victim outranks the attacker at the attacker's view.
    junior: bool,
}

/// A backdated list checkpoint (identity.md, "List checkpoints", "Effect";
/// roster.md, section 4, "A backdated checkpoint", read for a list): a
/// revoked device, on its stale view, revokes every other active device it
/// sees there, then checkpoints citing its whole view; sometimes with a
/// second revoked device on the same view, or with a device it adds there
/// first; with `bias`, colluders are drawn more often, and the attacker may
/// revoke only the devices it outranks (selective). Every
/// event it signs is dishonest. Returns the attack, or `None` when the
/// attacker is not an active device there or has no victim.
fn takeover(
    net: &mut Net,
    rng: &mut Rng,
    revoked: &[String],
    step: usize,
    bias: bool,
) -> Option<Attack> {
    let before: BTreeSet<EventId> = net.all.log().canonical().into_iter().collect();
    let attack = takeover_signed(net, rng, revoked, step, bias);
    let signed: Vec<EventId> = net
        .all
        .log()
        .canonical()
        .into_iter()
        .filter(|id| !before.contains(id))
        .collect();
    net.dishonest.extend(signed);
    attack
}

fn takeover_signed(
    net: &mut Net,
    rng: &mut Rng,
    revoked: &[String],
    step: usize,
    bias: bool,
) -> Option<Attack> {
    let attacker = rng.pick(revoked).clone();
    let start = net.replica(&attacker).merge();
    let me = net.id_of(&attacker);
    let mine = start.active(&me)?;
    if mine.kind != Kind::Device || mine.rooted() != Rootedness::None {
        return None;
    }
    let mut helpers = vec![attacker.clone()];
    let modes: &[&str] = if bias && revoked.len() > 1 {
        &[
            "alone",
            "colluder",
            "colluder",
            "colluder",
            "colluder",
            "sybil",
            "selective",
        ]
    } else if bias {
        &["alone", "sybil", "selective", "selective"]
    } else {
        &["alone", "colluder", "sybil"]
    };
    let modes: Vec<String> = modes.iter().map(|m| m.to_string()).collect();
    let mut mode: &'static str = match rng.pick(&modes).as_str() {
        "alone" => "alone",
        "colluder" => "colluder",
        "selective" => "selective",
        _ => "sybil",
    };
    if mode == "colluder" && revoked.len() > 1 {
        let others: Vec<String> = revoked
            .iter()
            .filter(|n| **n != attacker)
            .cloned()
            .collect();
        let other = rng.pick(&others).clone();
        net.take_view(&other, &attacker);
        helpers.push(other.clone());
        net.take_view(&attacker, &other);
    } else if mode == "sybil" && !net.keys.contains_key("D5") {
        net.add(&attacker, "D5");
        net.sync(&[&attacker, "D5"]);
        helpers.push("D5".to_string());
    }
    let names: BTreeMap<DeviceId, String> = net
        .keys
        .iter()
        .map(|(n, k)| (*k.device_id(), n.clone()))
        .collect();
    let mut victims: Vec<String> = start
        .members()
        .iter()
        .filter(|(_, m)| m.active() && m.kind == Kind::Device)
        .filter_map(|(d, _)| names.get(d))
        .filter(|n| !helpers.contains(n))
        .cloned()
        .collect();
    if mode == "selective" {
        victims.retain(|v| start.outranks(&me, net.keys[v].device_id()));
    }
    if victims.is_empty() {
        return None;
    }
    let helper_names: Vec<&str> = helpers.iter().map(String::as_str).collect();
    for (k, v) in victims.iter().enumerate() {
        let by = helpers[k % helpers.len()].clone();
        net.sync(&helper_names);
        net.revoke(&by, v, &format!("{step}: {by} revokes {v}, backdated"));
    }
    net.sync(&helper_names);
    let checkpoint = net
        .checkpoint_unfenced(
            &attacker,
            None,
            &format!("{step}: {attacker} checkpoints, backdated"),
        )
        .ok()?;
    for helper in &helpers[1..] {
        net.sync(&[helper, &attacker]);
        net.ack(helper);
    }
    if helpers.len() == 1 && mode != "selective" {
        mode = "alone";
    }
    let junior = victims.iter().any(|v| {
        let d = *net.keys[v].device_id();
        start.outranks(&d, &me)
    });
    Some(Attack {
        checkpoint,
        attackers: helpers,
        victims,
        mode,
        junior,
    })
}

const NAMES: [&str; 6] = ["D0", "D1", "D2", "D3", "D4", "D5"];
/// Devices added through an agent, or by those.
const AGENT_NAMES: [&str; 3] = ["R1", "R2", "R3"];

/// The views of every device after each step.
type Snapshot = BTreeMap<String, BTreeSet<EventId>>;

fn strings(set: &BTreeSet<String>) -> Vec<String> {
    set.iter().cloned().collect()
}

fn random_list(
    seed: u64,
    checkpoints: bool,
    collusion: bool,
    steps: usize,
) -> (
    Net,
    Vec<Snapshot>,
    BTreeMap<&'static str, usize>,
    Vec<Attack>,
) {
    let mut rng = Rng(seed);
    // A dishonest device, drawn apart so that the honest steps keep their
    // draws: it takes another's view and checkpoints citing every head,
    // naming the last in effect, an earlier checkpoint, or none.
    let mut adv = Rng(seed.wrapping_mul(7907).wrapping_add(5));
    // Two groups of the person's devices cut off from each other, at most
    // once per history: two electorates with no device in common.
    let mut spl = Rng(seed.wrapping_mul(7907).wrapping_add(11));
    // A revoked device that, on its view from before its revocation,
    // revokes the others and checkpoints: alone, with another revoked
    // device, or with a device it adds there. Drawn apart too.
    let mut atk = Rng(seed.wrapping_mul(7907).wrapping_add(17));
    // The collusion seeds' early revocations: drawn apart too.
    let mut col = Rng(seed.wrapping_mul(7907).wrapping_add(29));
    let mut attacks: Vec<Attack> = Vec::new();
    let mut net = Net::new("D0", &format!("identity/list-model/{seed}"));
    let mut active: BTreeSet<String> = BTreeSet::from(["D0".to_string()]);
    let mut revoked: BTreeSet<String> = BTreeSet::new();
    let mut agent: BTreeSet<String> = BTreeSet::new();
    let mut ops: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut snaps = Vec::new();
    let person_of = |active: &BTreeSet<String>| -> Vec<String> {
        active
            .iter()
            .filter(|n| NAMES.contains(&n.as_str()))
            .cloned()
            .collect()
    };
    if seed % 2 == 1 {
        // A person that named an agent, which added devices, one of them
        // confirmed: they are list members when checkpoints are made.
        net.add("D0", "D1");
        net.add_as("D0", "AG", Kind::RecoveryAgent);
        net.sync(&["D0", "D1", "AG"]);
        net.add("AG", "R1");
        net.sync(&["D0", "D1", "AG", "R1"]);
        net.add("R1", "R2");
        net.sync(&["D0", "D1", "AG", "R1", "R2"]);
        if seed % 4 == 1 {
            net.confirm("D0", "R1");
        }
        net.sync(&["D0", "D1", "AG", "R1", "R2"]);
        for n in ["D1", "AG", "R1", "R2"] {
            active.insert(n.to_string());
        }
        agent.extend(["R1".to_string(), "R2".to_string()]);
        *ops.entry("agent").or_default() += 1;
    }
    if collusion {
        // D1 and D2, added by D0 and so junior to it, D2 junior to D1.
        for who in ["D1", "D2"] {
            if !active.contains(who) {
                net.add("D0", who);
                active.insert(who.to_string());
            }
        }
        let all = strings(&active);
        net.sync(&all.iter().map(String::as_str).collect::<Vec<_>>());
        *ops.entry("collusion").or_default() += 1;
    }
    // The step at which a collusion seed's revocations come, early.
    let scripted = 2 + (col.next() % 8) as usize;
    for step in 0..steps {
        if collusion && checkpoints && step == scripted {
            // Either D0 revokes D1 and D2, two revoked devices that can
            // collude against it; or D2 revokes D1, its senior, which leaves
            // D1 heard and able to attack the devices it outranks.
            let pairs: &[(&str, &str)] = if col.unit() < 0.5 {
                &[("D0", "D1"), ("D0", "D2")]
            } else {
                &[("D2", "D1")]
            };
            for &(by, who) in pairs {
                if active.contains(by) && active.contains(who) {
                    net.sync(&[by, "D0"]);
                    net.revoke(by, who, &format!("{step}: {by} revokes {who}, early"));
                    active.remove(who);
                    revoked.insert(who.to_string());
                }
            }
            *ops.entry("early revocations").or_default() += 1;
        }
        let candidates: Vec<String> = revoked
            .iter()
            .filter(|n| NAMES.contains(&n.as_str()))
            .cloned()
            .collect();
        // In collusion seeds an attack waits, mostly, for two revoked
        // devices, so that one can collude.
        let (odds, most) = match (collusion, candidates.len()) {
            (true, 0 | 1) => (0.05, 3),
            (true, _) => (0.3, 3),
            (false, _) => (0.08, 2),
        };
        if checkpoints
            && atk.unit() < odds
            && !candidates.is_empty()
            && attacks.len() < most
            && let Some(attack) = takeover(&mut net, &mut atk, &candidates, step, collusion)
        {
            attacks.push(attack);
            *ops.entry("takeover").or_default() += 1;
            snaps.push(
                net.replicas
                    .iter()
                    .map(|(n, r)| (n.clone(), r.log().canonical().into_iter().collect()))
                    .collect(),
            );
        }
        if checkpoints && spl.unit() < 0.06 && !ops.contains_key("split") {
            let person = person_of(&active);
            if split(&mut net, &mut spl, &person, step) {
                *ops.entry("split").or_default() += 1;
                snaps.push(
                    net.replicas
                        .iter()
                        .map(|(n, r)| (n.clone(), r.log().canonical().into_iter().collect()))
                        .collect(),
                );
            }
        }
        let mut by = rng.pick(&strings(&active)).clone();
        let op = rng.unit();
        let person = person_of(&active);
        if (0.42..0.68).contains(&op) && rng.unit() < 0.75 && !person.is_empty() {
            // Checkpoints and acks come mostly from the person's own devices.
            by = rng.pick(&person).clone();
        }
        if op < 0.18 {
            if active.contains("AG") && rng.unit() < 0.5 {
                // The agent, or a device rooted in it, adds a device.
                let pool: BTreeSet<String> = agent
                    .iter()
                    .cloned()
                    .chain(["AG".to_string()])
                    .filter(|n| active.contains(n))
                    .collect();
                by = rng.pick(&strings(&pool)).clone();
            }
            let through_agent = by == "AG" || agent.contains(&by);
            let pool: &[&str] = if through_agent { &AGENT_NAMES } else { &NAMES };
            let Some(who) = pool
                .iter()
                .map(|n| n.to_string())
                .find(|n| !active.contains(n) && !revoked.contains(n))
            else {
                continue;
            };
            net.add(&by, &who);
            net.sync(&[&by, &who]);
            active.insert(who.clone());
            if through_agent {
                agent.insert(who);
                // An add rooted in an agent is relayed to every member at
                // once (ext-recovery-agent.md, "Relay and veto").
                let all = strings(&active);
                net.sync(&all.iter().map(String::as_str).collect::<Vec<_>>());
            }
            *ops.entry("add").or_default() += 1;
        } else if op < 0.23 {
            // A device names an agent, which adds devices rooted in it.
            if net.keys.contains_key("AG") {
                continue;
            }
            net.add_as(&by, "AG", Kind::RecoveryAgent);
            active.insert("AG".to_string());
            let all = strings(&active);
            net.sync(&all.iter().map(String::as_str).collect::<Vec<_>>());
            *ops.entry("agent").or_default() += 1;
        } else if op < 0.28 && agent.iter().any(|n| active.contains(n)) {
            // A device of the person confirms one rooted in the agent.
            let rooted: Vec<String> = agent
                .iter()
                .filter(|n| active.contains(*n))
                .cloned()
                .collect();
            let who = rng.pick(&rooted).clone();
            let mut person = person_of(&active);
            if person.is_empty() {
                person.push("D0".to_string());
            }
            let by = rng.pick(&person).clone();
            net.confirm(&by, &who);
            *ops.entry("confirm").or_default() += 1;
        } else if op < 0.36 && active.len() > 1 {
            let others: Vec<String> = active.iter().filter(|n| **n != by).cloned().collect();
            let who = rng.pick(&others).clone();
            net.revoke(&by, &who, &format!("{step}: {by} revokes {who}"));
            active.remove(&who);
            revoked.insert(who);
            *ops.entry("revoke").or_default() += 1;
        } else if op < 0.42 && !revoked.is_empty() {
            // A revoked device acts on its old view, as a late branch.
            let who = rng.pick(&strings(&revoked)).clone();
            let targets: Vec<String> = NAMES[..4]
                .iter()
                .map(|n| n.to_string())
                .filter(|n| *n != who && net.keys.contains_key(n))
                .collect();
            if !targets.is_empty() {
                let target = rng.pick(&targets).clone();
                let late = net.revoke(
                    &who,
                    &target,
                    &format!("{step}: {who} revokes {target} late"),
                );
                net.dishonest.insert(late);
                *ops.entry("late").or_default() += 1;
            }
        } else if op < 0.54 && checkpoints {
            if adv.unit() < 0.35 {
                let pool: Vec<String> = net
                    .replicas
                    .iter()
                    .filter(|(_, r)| r.log().len() > 1)
                    .map(|(n, _)| n.clone())
                    .collect();
                if !pool.is_empty() {
                    let other = adv.pick(&pool).clone();
                    net.take_view(&by, &other);
                }
                let named: Vec<EventId> = {
                    let replica = net.replica(&by);
                    replica
                        .log()
                        .canonical()
                        .into_iter()
                        .filter(|&id| {
                            replica
                                .body(id)
                                .is_some_and(|b| b.action == Action::Checkpoint)
                        })
                        .collect()
                };
                let pick = adv.unit();
                let previous = if pick < 0.5 || named.is_empty() {
                    None
                } else if pick < 0.7 {
                    Some(None)
                } else {
                    Some(Some(named[(adv.next() % named.len() as u64) as usize]))
                };
                if net
                    .checkpoint_unfenced(
                        &by,
                        previous,
                        &format!("{step}: {by} checkpoints, unfenced"),
                    )
                    .is_ok()
                {
                    *ops.entry("rogue checkpoint").or_default() += 1;
                }
            } else if net
                .checkpoint_anyway(&by, &format!("{step}: {by} checkpoints"))
                .is_ok()
            {
                *ops.entry("checkpoint").or_default() += 1;
            }
        } else if op < 0.60 && checkpoints {
            // A round of votes: the person's devices take the proposer's
            // view and ack.
            for name in active.iter().filter(|n| *n != "AG") {
                net.sync(&[name, &by]);
                net.ack(name);
            }
            *ops.entry("votes").or_default() += 1;
        } else if op < 0.68 && checkpoints {
            let pool: Vec<String> = net
                .replicas
                .iter()
                .filter(|(_, r)| r.log().len() > 1)
                .map(|(n, _)| n.clone())
                .collect();
            if !pool.is_empty() {
                let other = rng.pick(&pool).clone();
                net.sync(&[&by, &other]);
            }
            net.ack(&by);
            *ops.entry("ack").or_default() += 1;
        } else if op < 0.71 && net.replicas.contains_key(&by) {
            // A fork: an ack at the seq of the device's second-to-last event.
            // A device with no replica yet has signed nothing to fork.
            let author = net.id_of(&by);
            let replica = &net.replicas[&by];
            let mut mine: Vec<(u64, EventId)> = replica
                .log()
                .canonical()
                .into_iter()
                .filter_map(|id| {
                    let e = replica.log().event(id)?;
                    (*e.author() == author).then_some((e.seq(), id))
                })
                .collect();
            mine.sort_unstable();
            if mine.len() >= 2 {
                let old = mine[mine.len() - 2].1;
                let view: BTreeSet<EventId> = net.all.log().past(old);
                let list = net.view(&view);
                let signed = list.ack(net.keys[&by].signer());
                let fork = net.publish(&by, &signed, &format!("{step}: {by} forks"));
                net.dishonest.insert(fork);
                *ops.entry("fork").or_default() += 1;
            }
        } else {
            let pool: Vec<String> = net.replicas.keys().cloned().collect();
            if pool.len() >= 2 {
                let a = rng.pick(&pool).clone();
                let b = rng.pick(&pool).clone();
                net.sync(&[&a, &b]);
            }
        }
        if collusion && checkpoints && col.unit() < 0.3 {
            // The person, told whom a checkpoint waits for, has a device that
            // outranks a heard device revoke it again after the checkpoint,
            // which excuses it (identity.md, "List checkpoints", "Effect").
            for by in person_of(&active) {
                let merged = net.replica(&by).merge();
                let me = net.id_of(&by);
                let names: BTreeMap<DeviceId, String> = net
                    .keys
                    .iter()
                    .map(|(n, k)| (*k.device_id(), n.clone()))
                    .collect();
                let due: Vec<String> = merged
                    .pending_checkpoints()
                    .flat_map(|(c, waiting)| {
                        let heard = merged.heard(c).cloned().unwrap_or_default();
                        waiting
                            .iter()
                            .filter(|(d, _)| heard.contains(d) && merged.outranks(&me, d))
                            .filter_map(|(d, _)| names.get(d).cloned())
                            .collect::<Vec<_>>()
                    })
                    .collect();
                for who in due {
                    net.revoke(&by, &who, &format!("{step}: {by} revokes {who} again"));
                    *ops.entry("excuse").or_default() += 1;
                }
            }
        }
        snaps.push(
            net.replicas
                .iter()
                .map(|(n, r)| (n.clone(), r.log().canonical().into_iter().collect()))
                .collect(),
        );
    }
    let everyone: Vec<String> = net.replicas.keys().cloned().collect();
    let everyone: Vec<&str> = everyone.iter().map(String::as_str).collect();
    net.sync(&everyone);
    (net, snaps, ops, attacks)
}

#[derive(Debug, Default)]
struct Totals {
    histories: usize,
    events: usize,
    checkpoints: usize,
    effective: usize,
    forgetters: usize,
    compared: usize,
    late: usize,
    agent_rooted_kept: usize,
    confirmed_kept: usize,
    /// Views whose chain left the final one at two concurrent checkpoints
    /// with disjoint electorates.
    disjoint: usize,
    /// Holders that forgot and hold a rival, every verdict they differ on
    /// `Pending`.
    rival_pending: usize,
    ops: BTreeMap<&'static str, usize>,
    /// Histories drawn for collusion.
    with_collusion: usize,
    /// Backdated checkpoints by mode and standing: how many, and how many
    /// took effect.
    attacks: BTreeMap<String, (usize, usize)>,
    /// Those in effect, by mode, standing and why the rules let them in.
    attacks_in_effect: BTreeMap<String, usize>,
}

/// The checkpoints an event's `follows` reach, in the whole list.
fn reach(list: &DeviceList, id: EventId) -> BTreeSet<EventId> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<EventId> = list.body(id).map(|b| b.follows.clone()).unwrap_or_default();
    while let Some(c) = stack.pop() {
        if out.insert(c) {
            stack.extend(list.body(c).map(|b| b.follows.clone()).unwrap_or_default());
        }
    }
    out
}

/// A holder that forgot under `base` holds exactly what the text lets it
/// keep (identity.md, "List checkpoints", "Forgetting"): `base` and the
/// events after it; alone, the first event, the adds and rooting adds its
/// record names, the checkpoints its `follows` reach and the late events.
fn check_kept_set(all: &DeviceList, base: EventId, kept: &KeptList, seed: u64) {
    let events: BTreeSet<EventId> = all.log().canonical().into_iter().collect();
    let held: BTreeSet<EventId> = events
        .iter()
        .copied()
        .filter(|&id| id == base || reach(all, id).contains(&base))
        .collect();
    let past = all.log().past(base);
    let record = all.body(base).unwrap().list_record().unwrap();
    let mut alone: BTreeSet<EventId> = BTreeSet::from([all.first()]);
    for m in &record.members {
        alone.insert(m.add);
        alone.extend(m.rooting);
    }
    alone.extend(record.heard.iter().map(|(add, _)| *add));
    alone.extend(reach(all, base).into_iter().filter(|x| events.contains(x)));
    alone.extend(
        events
            .iter()
            .copied()
            .filter(|id| !held.contains(id) && !past.contains(id)),
    );
    let holds: BTreeSet<EventId> = kept.canonical().into_iter().collect();
    assert_eq!(holds, held, "what it holds, seed {seed}");
    let mut keeps: BTreeSet<EventId> = kept.alone().keys().copied().collect();
    keeps.insert(kept.first().id());
    assert_eq!(keeps, alone, "what it keeps alone, seed {seed}");
}

fn check_list(seed: u64, checkpoints: bool, collusion: bool, totals: &mut Totals) {
    let (net, snaps, ops, attacks) = random_list(seed, checkpoints, collusion, 30);
    let full = net.all.merge();
    totals.with_collusion += usize::from(collusion);
    // (vi) A backdated checkpoint by devices that a victim outranks never
    // takes effect, unless a heard victim voted for it: by a dishonest
    // step, or honestly where the checkpoint was not contested for it,
    // which is checked at each of its events after the checkpoint (an
    // honest device follows the conduct rule, identity.md, "List
    // checkpoints", "Clients"). Each attack in effect is counted with why
    // the rules let it in.
    for attack in &attacks {
        let c = attack.checkpoint;
        let won = full.chain().contains(&c);
        let name = format!(
            "{}, {}",
            attack.mode,
            if attack.junior { "junior" } else { "senior" }
        );
        let row = totals.attacks.entry(name.clone()).or_default();
        row.0 += 1;
        row.1 += usize::from(won);
        if !won {
            continue;
        }
        let heard = full.heard(c).cloned().unwrap_or_default();
        let voted = full.voted(c).cloned().unwrap_or_default();
        let electorate = full.electorate(c).cloned().unwrap_or_default();
        let (mut dishonest, mut honest) = (0, 0);
        for v in &attack.victims {
            let device = *net.keys[v].device_id();
            if !voted.contains(&device) {
                continue;
            }
            let mine: Vec<EventId> = net
                .all
                .log()
                .canonical()
                .into_iter()
                .filter(|&id| {
                    id != c
                        && net
                            .all
                            .log()
                            .event(id)
                            .is_some_and(|e| *e.author() == device)
                        && reach(&net.all, id).contains(&c)
                })
                .collect();
            if mine.iter().any(|id| net.dishonest.contains(id)) {
                dishonest += 1;
                continue;
            }
            honest += 1;
            for &x in &mine {
                let view = net.view(&net.all.log().past(x));
                assert!(
                    view.contest(&device, c).is_none(),
                    "(vi) seed {seed}: honest victim {v} voted for {} by {} while contested",
                    net.names[&c],
                    net.names[&x]
                );
            }
        }
        let waited: Vec<&String> = attack
            .victims
            .iter()
            .filter(|v| heard.contains(net.keys[*v].device_id()))
            .collect();
        let why = if dishonest > 0 {
            "a victim voted dishonestly"
        } else if honest > 0 {
            "a victim voted honestly, uncontested in its view"
        } else if waited.is_empty() {
            "no victim heard"
        } else if waited
            .iter()
            .all(|v| !electorate.contains(net.keys[*v].device_id()))
        {
            "its heard victims were excused"
        } else {
            "unexplained"
        };
        if attack.junior {
            eprintln!(
                "seed {seed}: {name}, by {:?} on {:?}, took effect: {why}",
                attack.attackers, attack.victims
            );
            assert!(
                !heard.is_disjoint(&voted) || why == "its heard victims were excused",
                "(vi) a junior's backdated list checkpoint took effect, seed {seed}: {} \
                 (victims {:?}): {why}",
                net.names[&c],
                attack.victims
            );
        }
        *totals
            .attacks_in_effect
            .entry(format!("{name}: {why}"))
            .or_default() += 1;
    }
    totals.histories += 1;
    totals.events += net.all.log().len();
    totals.checkpoints += full.checkpoint_validity().len();
    totals.effective += full.chain().len();
    totals.late += full.late().count();
    for (op, n) in ops {
        *totals.ops.entry(op).or_default() += n;
    }
    // (iii) With no checkpoint, the verdicts are the procedure's own.
    if full.checkpoint_validity().is_empty() {
        let through = net.all.merge_through_checkpoints();
        assert_eq!(
            full.verdicts().collect::<Vec<_>>(),
            through.verdicts().collect::<Vec<_>>(),
            "(iii) seed {seed}"
        );
        assert_eq!(full.members(), through.members(), "(iii) seed {seed}");
    }
    let mut seen: BTreeSet<EventId> = BTreeSet::new();
    let mut disjoint_seen: BTreeSet<EventId> = BTreeSet::new();
    for snap in &snaps {
        for (name, view) in snap {
            if view.is_empty() {
                continue;
            }
            let merged = net.view(view).merge();
            // (ii) Chains grow by prefix, but where two concurrent
            // checkpoints have disjoint electorates (rationale.md, 2.10;
            // a design trade-off): there the smaller ID wins once both are
            // held, and a view that held only the other had it in effect.
            if !full.chain().starts_with(merged.chain()) {
                let i = full
                    .chain()
                    .iter()
                    .zip(merged.chain())
                    .take_while(|(a, b)| a == b)
                    .count();
                let (a, b) = (full.chain().get(i), merged.chain()[i]);
                let a = *a.unwrap_or_else(|| panic!("(ii) seed {seed}, {name}: chain shrank"));
                let disjoint = !reach(&net.all, a).contains(&b)
                    && !reach(&net.all, b).contains(&a)
                    && a < b
                    && full
                        .electorate(a)
                        .is_some_and(|ea| full.electorate(b).is_some_and(|eb| ea.is_disjoint(eb)));
                assert!(disjoint, "(ii) seed {seed}, {name}");
                if disjoint_seen.insert(b) {
                    totals.disjoint += 1;
                    eprintln!(
                        "seed {seed}: {} and {} have disjoint electorates",
                        net.names[&a], net.names[&b]
                    );
                }
            }
            let Some(&base) = merged.chain().last() else {
                continue;
            };
            if !seen.insert(base) {
                continue;
            }
            // (i) A holder that forgot under the base, holding only what it
            // keeps, agrees with one that kept everything, on every event it
            // holds, on the active members and on what a verifier vouches
            // by; or it holds a rival and holds pending every verdict it
            // would otherwise differ on, deciding nothing else.
            let kept = net.all.forget_under(base).expect("a list checkpoint");
            check_kept_set(&net.all, base, &kept, seed);
            let forgot = kept.merge();
            if !forgot.rivals().is_empty() {
                for id in kept.canonical() {
                    let (a, b) = (full.verdict(id), forgot.verdict(id));
                    assert!(
                        a == b || b.is_some_and(|v| short(v) == "Pending"),
                        "(i) a holder with a rival decides, seed {seed}, {name}: {}",
                        net.names.get(&id).map_or("?", String::as_str)
                    );
                }
                totals.rival_pending += 1;
                continue;
            }
            assert!(
                full.chain().contains(&base),
                "(i) overtaken without a rival, seed {seed}, {name}"
            );
            for id in kept.canonical() {
                assert_eq!(
                    forgot.verdict(id),
                    full.verdict(id),
                    "(i) seed {seed}, {name}: {}",
                    net.names.get(&id).map_or("?", String::as_str)
                );
                totals.compared += 1;
            }
            assert_eq!(
                vouching(&forgot),
                vouching(&full),
                "(i) vouching, seed {seed}, {name}"
            );
            assert_eq!(
                forgot.chain(),
                &full.chain()[full.chain().iter().position(|c| *c == base).unwrap()..],
                "(i) chain, seed {seed}"
            );
            let record = kept.record();
            totals.agent_rooted_kept += record
                .members
                .iter()
                .filter(|m| m.rooting.is_some())
                .count();
            totals.confirmed_kept += record
                .members
                .iter()
                .filter(|m| m.confirmed && m.root != Rootedness::None)
                .count();
            totals.forgetters += 1;
        }
    }
}

/// The seeds: 1 to `FRASIL_LIST_MODEL_SEEDS`, 8 by default (about 10 s in a
/// debug build; the release runs take 80). Every fourth
/// history makes no checkpoint; odd ones start with an agent; seeds 2 mod
/// 4, a quarter, are drawn for collusion: D0 adds D1 and D2 first, and
/// early on revokes both, two revoked devices that can collude, or D2
/// revokes D1, its senior, which leaves D1 heard; backdated checkpoints
/// then come more often, by colluders mostly.
#[test]
fn model_check() {
    let n: u64 = std::env::var("FRASIL_LIST_MODEL_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8);
    let mut totals = Totals::default();
    for seed in 1..=n {
        check_list(seed, seed % 4 != 0, seed % 4 == 2, &mut totals);
    }
    eprintln!("list model check, seeds 1 to {n}: {totals:?}");
    assert!(totals.effective > 0, "{totals:?}");
    assert!(totals.forgetters > 0, "{totals:?}");
}
