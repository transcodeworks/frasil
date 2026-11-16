//! Helpers the vector tests share.

#![allow(dead_code)]

use frasil_base::errors::Class;
use frasil_base::notation::push_field;
use frasil_base::time::Reading;
use frasil_crypto::device::{DeviceId, DeviceKeys, IdentityKey};
use frasil_crypto::fixtures::{fixture_mldsa_seed, fixture_xwing_seed};
use frasil_crypto::labels::PEER_BINDING;
use frasil_crypto::primitives::{ed25519_public, sha256};
use frasil_crypto::schemes::Signer;
use frasil_crypto::wrap::xwing_public;
use frasil_events::{EventId, Log, Placement, decode};
use frasil_keys::body::VisiblePart;
use frasil_keys::derive::{body_key, read_credential};
use frasil_peers::Code;
use frasil_peers::entries::{Ancestry, Connection, Entries, Present, Refusal, Rights, Source};
use frasil_peers::merge::MergeStatement;
use frasil_peers::proof::{Purpose, presented, verify};
use frasil_peers::skeleton::{Skeleton, Status};
use frasil_peers::twins::{AdministerChanges, RosterFacts, TwinChecks};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

/// The vector file.
pub const FILE: &str = "peers.json";

/// A family of `peers.json`, as JSON.
pub fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

/// The bytes of a hex string.
pub fn hex(value: &Json) -> Vec<u8> {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("{value} is not a string"));
    frasil_testkit::hex::decode(text).unwrap_or_else(|error| panic!("{text}: {error}"))
}

/// The bytes of a hex string, as an array.
pub fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex(value)
        .try_into()
        .unwrap_or_else(|_| panic!("{value} is not {N} bytes"))
}

/// A string.
pub fn text(value: &Json) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{value} is not a string"))
}

/// The class name a result failed with, or `accepted`.
pub fn outcome<T, C: Class>(result: Result<T, C>) -> &'static str {
    result.err().map_or("accepted", Class::name)
}

/// The reference's fixed inputs: SHA-256 of a description, so no value is
/// magic.
pub fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// The signer of a device of the vectors under `prefix`: its Ed25519 seed
/// is the example `<prefix>/<name>/ed25519`, its ML-DSA-65 and X-Wing seeds
/// the fixture derivations (crypto.md, "A device's keys").
pub fn signer(prefix: &str, name: &str) -> Signer {
    let seed = example(&format!("{prefix}/{name}/ed25519"));
    let xwing = xwing_public(&fixture_xwing_seed(&seed));
    Signer::from_seeds(&seed, &fixture_mldsa_seed(&seed), Some(&xwing))
}

/// The signer of an administrator pseudonym of the vectors: as
/// [`signer`], with no X-Wing key.
pub fn pseudonym(prefix: &str, name: &str) -> Signer {
    let seed = example(&format!("{prefix}/{name}/ed25519"));
    Signer::from_seeds(&seed, &fixture_mldsa_seed(&seed), None)
}

/// The identity key of a key of the vectors under `prefix`.
pub fn key(prefix: &str, name: &str) -> [u8; 32] {
    ed25519_public(&example(&format!("{prefix}/{name}/ed25519")))
}

/// The device ID of a device of the vectors under `prefix`.
pub fn device(prefix: &str, name: &str) -> DeviceId {
    *signer(prefix, name).device_id()
}

/// The device ID of an administrator pseudonym of the vectors.
pub fn pseudonym_id(prefix: &str, name: &str) -> DeviceId {
    *pseudonym(prefix, name).device_id()
}

/// A device's keys, as the roster's facts give them.
fn device_keys(signer: &Signer) -> DeviceKeys {
    DeviceKeys {
        ed: *signer.identity_key(),
        keys: signer.keys().clone(),
    }
}

/// A reading of the peer's timeline: `{timeline: t, wall: none, run: 1}`.
pub fn reading(t: u64) -> Reading {
    Reading {
        timeline: t,
        wall: None,
        run: 1,
    }
}

/// A history the vectors describe: its log, and each event's name by ID and
/// ID by name.
pub struct History {
    pub log: Log,
    pub names: BTreeMap<EventId, String>,
    pub ids: BTreeMap<String, EventId>,
}

impl History {
    /// The events of a vectors' `events` list, each with `name`, `id` and
    /// `signed`, in canonical order: the first starts the log.
    pub fn of(events: &Json) -> Self {
        let rows = events.as_array().expect("an events list");
        let mut log = None::<Log>;
        let mut names = BTreeMap::new();
        let mut ids = BTreeMap::new();
        for row in rows {
            let event = decode(&hex(&row["signed"])).expect("each event decodes");
            let id = event.id();
            assert_eq!(id.0, array::<32>(&row["id"]), "{}: its ID", row["name"]);
            let name = text(&row["name"]).to_string();
            names.insert(id, name.clone());
            ids.insert(name, id);
            match &mut log {
                None => log = Some(Log::new(event).expect("a genesis")),
                Some(log) => {
                    let placed = log.place(event).expect("of the log");
                    assert!(matches!(placed, Placement::Placed(_)), "{}", row["name"]);
                }
            }
        }
        Self {
            log: log.expect("a genesis"),
            names,
            ids,
        }
    }

    /// The ID of a named event.
    pub fn id(&self, name: &str) -> EventId {
        *self
            .ids
            .get(name)
            .unwrap_or_else(|| panic!("no event {name}"))
    }

    /// The name of an event.
    pub fn name(&self, id: EventId) -> &str {
        &self.names[&id]
    }

    /// Every event but those named and the events after them.
    pub fn view_without(&self, names: &[&str]) -> BTreeSet<EventId> {
        let out: Vec<EventId> = names.iter().map(|n| self.id(n)).collect();
        self.log
            .canonical()
            .into_iter()
            .filter(|&i| !out.iter().any(|&o| o == i || self.log.precedes(o, i)))
            .collect()
    }

    /// Every event.
    pub fn all(&self) -> BTreeSet<EventId> {
        self.log.canonical().into_iter().collect()
    }
}

/// A status as the vectors write it: `valid`, a class, or a class `by` the
/// event that voids it.
pub fn status_text(status: Status, history: &History) -> String {
    match status {
        Status::Valid => "valid".into(),
        Status::Void { class, by: None } => class.name().into(),
        Status::Void {
            class,
            by: Some(by),
        } => format!("{} by {}", class.name(), history.name(by)),
    }
}

/// An administrator slot as the vectors write it: `[c, index, the name of
/// the event that made it]`.
pub fn slot_json(slot: frasil_peers::body::SlotId, history: &History) -> Json {
    serde_json::json!([
        frasil_testkit::hex::encode(slot.reference.commitment),
        slot.reference.index,
        history.name(slot.maker),
    ])
}

/// Administrator slots as the vectors write them.
pub fn slots_json(slots: &[frasil_peers::body::SlotId], history: &History) -> Json {
    Json::from(
        slots
            .iter()
            .map(|&slot| slot_json(slot, history))
            .collect::<Vec<_>>(),
    )
}

/// The reference's skeleton summary: each storage event's status, and the
/// administrator slots in the merged skeleton.
pub fn summary(skeleton: &Skeleton<'_>, history: &History) -> Json {
    let events: serde_json::Map<String, Json> = skeleton
        .statuses()
        .into_iter()
        .map(|(id, status)| {
            (
                history.name(id).to_string(),
                Json::from(status_text(status, history)),
            )
        })
        .collect();
    let administrators: Vec<Json> = skeleton
        .administrators()
        .into_iter()
        .map(|slot| slot_json(slot, history))
        .collect();
    serde_json::json!({"events": events, "administrators": administrators})
}

/// Checks a skeleton against the reference's summary, event by event and
/// in order.
pub fn check_summary(case: &str, skeleton: &Skeleton<'_>, history: &History, expected: &Json) {
    let found = summary(skeleton, history);
    let expected_events: Vec<(&String, &Json)> =
        expected["events"].as_object().unwrap().iter().collect();
    let found_events: Vec<(&String, &Json)> = found["events"].as_object().unwrap().iter().collect();
    assert_eq!(found_events, expected_events, "{case}: statuses");
    assert_eq!(
        found["administrators"], expected["administrators"],
        "{case}: administrators"
    );
}

// ---------------------------------------------------------------------------
// Presents, the merge space and the roster's facts.

/// transport.md's binding of a device-to-peer connection:
/// `SHA-256("frasil/peer-binding/v1" || field(channel) || nonce_peer ||
/// nonce_client || u8(purpose))`.
fn peer_binding(
    channel: &[u8],
    nonce_peer: &[u8],
    nonce_client: &[u8],
    purpose: Purpose,
) -> [u8; 32] {
    let mut input = PEER_BINDING.to_vec();
    push_field(&mut input, channel);
    input.extend_from_slice(nonce_peer);
    input.extend_from_slice(nonce_client);
    input.push(purpose.code());
    sha256(&[&input])
}

/// The two connections' bindings of `proofs`.
pub fn bindings() -> ([u8; 32], [u8; 32]) {
    let p = family("proofs");
    let (channel, peer, client) = (
        hex(&p["channel"]),
        hex(&p["nonce_peer"]),
        hex(&p["nonce_client"]),
    );
    let traffic = peer_binding(&channel, &peer, &client, Purpose::SpaceTraffic);
    let admin = peer_binding(&channel, &peer, &client, Purpose::Administration);
    assert_eq!(traffic, array::<32>(&p["binding_space_traffic"]));
    assert_eq!(admin, array::<32>(&p["binding_administration"]));
    (traffic, admin)
}

/// A present's verdict as the vectors write it.
fn present_verdict(result: Result<Rights, Refusal>) -> (String, Option<&'static str>) {
    match result {
        Ok(Rights::FETCH_AND_LIVE) => ("fetch, live".into(), None),
        Ok(Rights::STORE_AND_RELEASE) => ("store, release".into(), None),
        Ok(Rights::CATCH_UP) => ("catch-up".into(), None),
        Ok(Rights::ERASE) => ("erase".into(), None),
        Ok(other) => panic!("rights {other:?}"),
        Err(refusal) => {
            let verdict = match refusal {
                Refusal::Class(class) => class.name().to_string(),
                Refusal::Code(Code::CredentialRefused) => "CredentialRefused".into(),
                Refusal::Code(code) => code.name().to_string(),
                Refusal::PurposeViolation => "purpose_violation".into(),
            };
            (verdict, refusal.code_name())
        }
    }
}

fn purpose(value: &Json) -> Purpose {
    match text(value) {
        "space traffic" => Purpose::SpaceTraffic,
        "administration" => Purpose::Administration,
        other => panic!("purpose {other}"),
    }
}

/// Runs the presents of a list against `entries`, each on a connection of
/// its purpose.
pub fn check_presents(
    entries: &mut Entries,
    space: EventId,
    cases: &Json,
    pseudonym_ed: impl Fn(&[u8; 32]) -> Option<IdentityKey>,
) {
    let (traffic, admin) = bindings();
    for case in cases.as_array().unwrap() {
        let name = text(&case["name"]);
        let credential = case["credential"].as_u64().unwrap();
        let public: [u8; 32] = array(&case["public"]);
        let proof = hex(&case["proof"]);
        let purpose = purpose(&case["purpose"]);
        let binding = match purpose {
            Purpose::SpaceTraffic => traffic,
            Purpose::Administration => admin,
        };
        // The proof is over the vector's `presented`, which is this
        // connection's unless the case changes it; credential 3's verifies
        // under the pseudonym's Ed25519 key, `public` being its device ID.
        let shown = hex(&case["presented"]);
        let ed = pseudonym_ed(&public);
        let signer_key = match (credential, ed) {
            (3, Some(ed)) => ed.0,
            _ => public,
        };
        assert!(
            verify(&signer_key, &shown, &proof),
            "{name}: the proof is over presented"
        );
        let ours = presented(&binding, space.as_bytes(), credential as u8, &public);
        let tampered = name.contains("another");
        assert_eq!(ours == shown, !tampered, "{name}: presented");
        let connection = Connection {
            binding,
            purpose,
            importing: false,
        };
        let present = Present {
            credential,
            space,
            public,
            proof: &proof,
        };
        let (verdict, code) = present_verdict(entries.present(&present, &connection, ed.as_ref()));
        assert_eq!(verdict, text(&case["verdict"]), "{name}");
        assert_eq!(
            code,
            case.get("code").and_then(Json::as_str),
            "{name}: code"
        );
    }
}

/// The ancestry of the merge space, from the history `merge_statement`
/// gives: P founds it and grants W write, then P and W rotate concurrently.
/// The genesis is in the past of every other event.
pub struct MergeSpace {
    pub genesis: EventId,
    pub grant: EventId,
    pub rotations: [EventId; 2],
}

impl Ancestry for MergeSpace {
    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        (earlier == self.genesis && later != self.genesis)
            || (earlier == self.grant && self.rotations.contains(&later))
    }
}

impl MergeSpace {
    /// The space, W's grant and the two rotations, from the family's history,
    /// which the accepted statement's state names.
    pub fn new() -> Self {
        let m = family("merge_statement");
        let history = History::of(&m["events"]);
        let statement = MergeStatement::read(&hex(&m["cases"][0]["statement"])).unwrap();
        let rotations = [statement.state.ids()[0], statement.state.ids()[1]];
        assert_eq!(statement.space, history.log.id());
        let grant = history.id("P grants W write");
        for (id, name) in rotations.iter().zip(m["state"].as_array().unwrap()) {
            assert_eq!(*id, history.id(text(name)));
            assert!(history.log.precedes(grant, *id), "{name}: after W's grant");
        }
        Self {
            genesis: statement.space,
            grant,
            rotations,
        }
    }

    /// The name of an event of the space, as the vectors write it.
    pub fn name(&self, id: EventId) -> &'static str {
        let m = family("merge_statement");
        if id == self.genesis {
            "P creates the space"
        } else if id == self.grant {
            "P grants W write"
        } else if id == self.rotations[0] {
            leak(text(&m["state"][0]))
        } else {
            leak(text(&m["state"][1]))
        }
    }

    /// The peer's entries of the space's rotations, in canonical order, from
    /// `merge_cap`'s first four entries, under `cap`.
    pub fn entries(&self, cap: usize) -> Entries {
        let rows = family("merge_cap")["per_state"]["entries"].clone();
        let mut entries = Entries::new(cap);
        let order = [
            self.genesis,
            self.grant,
            self.rotations[0],
            self.rotations[1],
        ];
        let names: Vec<&str> = order.iter().map(|&id| self.name(id)).collect();
        for row in rows.as_array().unwrap().iter().take(4) {
            let name = text(&row["state"][0]);
            let id = order[names.iter().position(|n| *n == name).unwrap()];
            entries.add_rotation_keys(
                self,
                id,
                array(&row["read"]),
                array(&row["upload"]),
                Source::Rotation,
                false,
            );
        }
        entries
    }
}

fn leak(text: &str) -> &'static str {
    Box::leak(text.to_string().into_boxed_str())
}

/// The roster's facts for a history whose body keys and administer
/// changes the test gives.
pub struct Facts {
    pub opened: Vec<EventId>,
    pub body_keys: BTreeMap<EventId, [u8; 32]>,
    pub changes: BTreeMap<EventId, AdministerChanges>,
    /// The ranks each roster event's grants give, where a test sets them;
    /// the top rank otherwise.
    pub ranks: BTreeMap<EventId, Vec<u8>>,
    pub devices: BTreeMap<DeviceId, DeviceKeys>,
    pub administrators: Vec<DeviceId>,
    /// For a skeleton that starts at a cut: each slot of the cut a member
    /// entry of the checkpoint's record names, with that entry's device and
    /// pseudonym.
    pub cut_slots: BTreeMap<frasil_peers::body::SlotId, (DeviceId, Option<DeviceId>)>,
}

impl RosterFacts for Facts {
    fn opened(&self) -> Vec<EventId> {
        self.opened.clone()
    }
    fn body_key(&self, event: EventId) -> Option<[u8; 32]> {
        self.body_keys.get(&event).copied()
    }
    fn administer_changes(&self, event: EventId) -> AdministerChanges {
        self.changes.get(&event).cloned().unwrap_or_default()
    }
    fn grant_ranks(&self, event: EventId) -> Vec<u8> {
        self.ranks.get(&event).cloned().unwrap_or_else(|| {
            vec![frasil_peers::limits::MAX_RANK; self.administer_changes(event).grants.len()]
        })
    }
    fn duel_policy(&self) -> u64 {
        0
    }
    fn device_keys(&self, device: &DeviceId) -> Option<DeviceKeys> {
        self.devices.get(device).cloned()
    }
    fn is_administrator_at(&self, device: &DeviceId, _: EventId) -> bool {
        self.administrators.contains(device)
    }
    fn cut_slot(&self, slot: frasil_peers::body::SlotId) -> Option<(DeviceId, Option<DeviceId>)> {
        self.cut_slots.get(&slot).copied()
    }
}

impl Facts {
    /// The facts of a history under `prefix` whose founder is P, with the
    /// devices named, each roster event's body key derived from its content
    /// key (`<prefix>/<label>/content-key`), as the reference's builder seals
    /// rotations.
    pub fn new(
        prefix: &str,
        history: &History,
        devices: &[&str],
        roster: &[(&str, AdministerChanges)],
    ) -> Self {
        let log = &history.log;
        let mut facts = Self {
            opened: Vec::new(),
            body_keys: BTreeMap::new(),
            changes: BTreeMap::new(),
            ranks: BTreeMap::new(),
            devices: devices
                .iter()
                .map(|d| {
                    let signer = signer(prefix, d);
                    (*signer.device_id(), device_keys(&signer))
                })
                .collect(),
            administrators: Vec::new(),
            cut_slots: BTreeMap::new(),
        };
        for (name, changes) in roster {
            let id = history.id(name);
            let event = log.event(id).unwrap();
            let label = if id == log.id() { "genesis" } else { name };
            let secret = example(&format!("{prefix}/{label}/content-key"));
            let visible =
                VisiblePart::read(event.unverified_body(), event.author(), event.seq()).unwrap();
            assert_eq!(
                read_credential(&secret).public,
                visible.rotation().unwrap().read,
                "{name}: its content key"
            );
            let bound: Vec<u8> = match visible.nonce {
                Some(nonce) => nonce.to_vec(),
                None => id_bytes(log.id()),
            };
            let key = body_key(&secret, &bound, event.author(), event.seq());
            facts.opened.push(id);
            facts.body_keys.insert(id, *key);
            facts.changes.insert(id, changes.clone());
        }
        facts
    }
}

fn id_bytes(id: EventId) -> Vec<u8> {
    id.as_bytes().to_vec()
}

pub fn grants(prefix: &str, devices: &[&str]) -> AdministerChanges {
    AdministerChanges {
        grants: devices.iter().map(|d| device(prefix, d)).collect(),
        lowers: Vec::new(),
    }
}

pub fn lowers(prefix: &str, devices: &[&str]) -> AdministerChanges {
    AdministerChanges {
        grants: Vec::new(),
        lowers: devices.iter().map(|d| device(prefix, d)).collect(),
    }
}

/// The bindings as the vectors name them: each pseudonym's device, or
/// `foreign`.
pub fn bindings_json<R: RosterFacts>(
    checks: &TwinChecks<'_, '_, R>,
    prefix: &str,
    names: &[&str],
) -> Json {
    let name_of = |k: &DeviceId| {
        names
            .iter()
            .find(|n| device(prefix, n) == *k || pseudonym_id(prefix, n) == *k)
            .unwrap_or_else(|| panic!("an unnamed key"))
            .to_string()
    };
    let out: serde_json::Map<String, Json> = checks
        .bindings()
        .into_iter()
        .map(|(p, d)| {
            (
                name_of(&p),
                Json::from(d.map_or("foreign".into(), |d| name_of(&d))),
            )
        })
        .collect();
    Json::Object(out)
}
