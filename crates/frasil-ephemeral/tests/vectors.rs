//! `ext-ephemeral.json`, every family (ext-ephemeral.md): the parameters,
//! the fixtures, the eight frames, one receiver accepting them in order,
//! each refusal at its step, the replay window, a receiver's restart,
//! epochs, membership and a relay.

use frasil_base::errors::Class;
use frasil_base::notation::push_field;
use frasil_crypto::device::{DeviceId, IdentityKey, KeysCommitment, Signatory};
use frasil_crypto::labels::{PARENT_REFERENCE, RESTRICTED_KEY};
use frasil_crypto::primitives::{ed25519_public, hkdf, xchacha20poly1305_open};
use frasil_ephemeral::counters::Counters;
use frasil_ephemeral::inner::{Inner, Kind};
use frasil_ephemeral::key::ephemeral_key;
use frasil_ephemeral::limits::*;
use frasil_ephemeral::membership::{
    ListStanding, MemberInputs, Membership, member, path_device, path_person, path_space,
};
use frasil_ephemeral::names::{RESERVED, reserved};
use frasil_ephemeral::receive::read_restricted_reference;
use frasil_ephemeral::relay::{Relay, Relayed};
use frasil_ephemeral::replay::{ReplayState, SlotKey, Window};
use frasil_ephemeral::{
    AdapterCheck, CheckContext, EphemeralClass, Extension, Outer, SpaceKind, View, receive,
    seal_with,
};
use frasil_keys::RotationSet;
use frasil_keys::derive::{SecretKind, state_secret};
use frasil_keys::names::RotationId;
use serde_json::{Value as Json, json};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const FILE: &str = "ext-ephemeral.json";

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
    to_array(&bytes(value, key))
}

fn to_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().unwrap_or_else(|_| panic!("not {N} bytes"))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    frasil_testkit::hex::encode(bytes)
}

fn u64_of(value: &Json, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not a number"))
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn kind_of(name: &str) -> Kind {
    match name {
        "ephemeral message" => Kind::Message,
        "ephemeral slot" => Kind::Slot,
        other => panic!("kind {other}"),
    }
}

/// The fixtures, read.
struct Fixtures {
    json: Json,
    seeds: BTreeMap<[u8; 32], [u8; 32]>,
    identities: BTreeMap<String, DeviceId>,
    space: [u8; 32],
    restricted: [u8; 32],
}

impl Fixtures {
    fn load() -> Self {
        let json = family("fixtures");
        let mut seeds = BTreeMap::new();
        let mut identities = BTreeMap::new();
        for (name, device) in json["devices"].as_object().unwrap() {
            let identity = array(device, "identity");
            seeds.insert(identity, array(device, "seed"));
            let signer = Signatory {
                ed: IdentityKey(identity),
                kc: KeysCommitment(array(device, "kc")),
            };
            assert_eq!(signer.device_id().0, array::<32>(device, "device_id"));
            identities.insert(name.clone(), signer.device_id());
        }
        let space = array(&json["space"], "space");
        let restricted = array(&json["restricted"], "space");
        Self {
            json,
            seeds,
            identities,
            space,
            restricted,
        }
    }

    fn device(&self, name: &str) -> DeviceId {
        self.identities[name]
    }

    fn rotation(&self, name: &str) -> RotationId {
        RotationId::from(array::<32>(&self.json["space"]["rotations"], name))
    }

    /// Bob, the receiver of the fixtures.
    fn receiver(&self) -> Receiver {
        let space = &self.json["space"];
        let states = &space["states"];
        let restricted = &self.json["restricted"];
        let mut spaces = BTreeMap::new();
        spaces.insert(
            self.space,
            Followed {
                kind: SpaceKind::Plain,
                known: [self.rotation("A"), self.rotation("B")].into(),
                keys: [
                    (
                        bytes(&states["merged"], "reference"),
                        array(&states["merged"], "content_key"),
                    ),
                    (
                        bytes(&states["A"], "reference"),
                        array(&space["content_keys"], "A"),
                    ),
                ]
                .into(),
            },
        );
        spaces.insert(
            self.restricted,
            Followed {
                kind: SpaceKind::Restricted,
                known: [RotationId::from(array::<32>(restricted, "rotation"))].into(),
                keys: [(
                    bytes(restricted, "key_reference"),
                    array(restricted, "content_key"),
                )]
                .into(),
            },
        );
        let fixture = &self.json["receiver"];
        let mut membership = BTreeMap::new();
        let mut drive = BTreeSet::new();
        for (name, standing) in fixture["membership"].as_object().unwrap() {
            let standing = standing.as_str().unwrap();
            let verdict = match standing.split(',').next().unwrap() {
                "in" => Membership::In,
                "MembershipEnded" => Membership::MembershipEnded,
                "NotAMember" => Membership::NotAMember,
                other => panic!("membership {other}"),
            };
            membership.insert(self.device(name), verdict);
            if standing.contains("with `drive`") {
                drive.insert(self.device(name));
            }
        }
        Receiver {
            own: self.device(text(fixture, "device")),
            spaces,
            membership,
            drive,
            nonces: fixture["receiver_nonces"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| to_array(&unhex(n.as_str().unwrap())))
                .collect(),
            fresh_only: fixture["fresh_only_names"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_str().unwrap().to_owned())
                .collect(),
            adapters: fixture["adapters"]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect(),
            guests: fixture["implements"]
                .as_array()
                .unwrap()
                .contains(&json!("ext-guests")),
        }
    }
}

struct Followed {
    kind: SpaceKind,
    known: BTreeSet<RotationId>,
    keys: BTreeMap<Vec<u8>, [u8; 32]>,
}

/// A receiver's view, as the fixtures give it.
struct Receiver {
    own: DeviceId,
    spaces: BTreeMap<[u8; 32], Followed>,
    membership: BTreeMap<DeviceId, Membership>,
    drive: BTreeSet<DeviceId>,
    nonces: Vec<[u8; 16]>,
    fresh_only: Vec<String>,
    adapters: BTreeSet<String>,
    guests: bool,
}

impl View for Receiver {
    fn own(&self) -> DeviceId {
        self.own
    }

    fn follows(&self, space: &[u8; 32]) -> Option<SpaceKind> {
        self.spaces.get(space).map(|s| s.kind)
    }

    fn holds_rotation(&self, space: &[u8; 32], id: &RotationId) -> bool {
        self.spaces[space].known.contains(id)
    }

    fn content_key(&self, space: &[u8; 32], reference: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        self.spaces[space]
            .keys
            .get(reference)
            .map(|k| Zeroizing::new(*k))
    }

    fn implements(&self, extension: Extension) -> bool {
        match extension {
            Extension::Guests => self.guests,
        }
    }

    fn member(&self, _space: &[u8; 32], sender: &DeviceId) -> Membership {
        self.membership
            .get(sender)
            .copied()
            .unwrap_or(Membership::NotAMember)
    }

    fn holds_nonce(&self, _space: &[u8; 32], nonce: &[u8; 16]) -> bool {
        self.nonces.contains(nonce)
    }

    fn fresh_only(&self, name: &str) -> bool {
        self.fresh_only.iter().any(|n| n == name)
    }

    fn check_capabilities(
        &self,
        adapter: &str,
        context: &CheckContext<'_>,
        _data: &[u8],
    ) -> AdapterCheck {
        if !self.adapters.contains(adapter) {
            return AdapterCheck::Unknown;
        }
        // `frasil:loro` accepts every frame; `com.example.cues` a sender
        // whose capabilities carry `drive`.
        if adapter == "com.example.cues" && !self.drive.contains(context.sender) {
            AdapterCheck::Refuse
        } else {
            AdapterCheck::Accept
        }
    }
}

fn class_name<E: Into<EphemeralClass>>(result: Result<impl Sized, E>) -> String {
    match result {
        Ok(_) => "accepted".to_owned(),
        Err(class) => class.into().name().to_owned(),
    }
}

fn inner_of(fields: &Json) -> Inner {
    let opt = |key: &str| fields.get(key).filter(|v| !v.is_null());
    Inner {
        kind: kind_of(text(fields, "kind")),
        sender: Signatory::from_bytes(&bytes(fields, "sender")).unwrap(),
        epoch: u64_of(fields, "epoch"),
        counter: u64_of(fields, "counter"),
        name: text(fields, "name").to_owned(),
        stream: opt("stream").map(|_| array(fields, "stream")),
        targets: opt("targets").map(|t| {
            t.as_array()
                .unwrap()
                .iter()
                .map(|x| DeviceId(to_array(&unhex(x.as_str().unwrap()))))
                .collect()
        }),
        fresh: opt("fresh").map(|f| {
            f.as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    (
                        DeviceId(to_array(&unhex(pair[0].as_str().unwrap()))),
                        to_array(&unhex(pair[1].as_str().unwrap())),
                    )
                })
                .collect()
        }),
        adapter: opt("adapter").map(|a| a.as_str().unwrap().to_owned()),
        data: fields
            .get("data")
            .map_or(Vec::new(), |_| bytes(fields, "data")),
    }
}

#[test]
fn parameters() {
    let p = family("parameters");
    for (key, value) in [
        ("max_outer_bytes", MAX_OUTER_BYTES),
        ("pad_block", PAD_BLOCK),
        ("max_plaintext_bytes", MAX_PLAINTEXT_BYTES),
        ("max_data_bytes", MAX_DATA_BYTES),
        ("max_name_bytes", MAX_NAME_BYTES),
        ("max_adapter_bytes", MAX_ADAPTER_BYTES),
        ("max_targets", MAX_TARGETS),
        ("max_fresh_entries", MAX_TARGETS),
        ("handle_bytes", HANDLE_BYTES),
        ("min_sealed_bytes", MIN_SEALED_BYTES),
        ("receiver_nonces", RECEIVER_NONCES),
        ("live_slots_per_sender", LIVE_SLOTS_PER_SENDER),
        ("receiver_slots_per_sender", RECEIVER_SLOTS_PER_SENDER),
        ("receiver_slots_per_space", RECEIVER_SLOTS_PER_SPACE),
        ("relay_slots_per_connection", RELAY_SLOTS_PER_CONNECTION),
        ("send_queue", SEND_QUEUE),
        ("origin_bytes", ORIGIN_BYTES),
    ] {
        assert_eq!(u64_of(&p, key), value as u64, "{key}");
    }
    assert_eq!(u64_of(&p, "replay_window"), REPLAY_WINDOW);
    assert_eq!(u64_of(&p, "relay_window"), RELAY_WINDOW);
    assert_eq!(
        u64_of(&p, "ephemeral_send_deadline"),
        EPHEMERAL_SEND_DEADLINE
    );
    assert_eq!(u64_of(&p, "ephemeral_key_wait"), EPHEMERAL_KEY_WAIT);
    for timer in [
        frasil_base::time::Timer::EphemeralSendDeadline,
        frasil_base::time::Timer::EphemeralKeyWait,
    ] {
        let spec = timer.spec();
        assert_eq!(spec.default, Some(u64_of(&p, spec.name)), "{}", spec.name);
    }
    let names = p["frasil_names"].as_object().unwrap();
    assert_eq!(names.len(), RESERVED.len());
    for (name, row) in names {
        let ours = reserved(name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(ours.kind, kind_of(text(row, "kind")), "{name}");
        assert_eq!(ours.targeted, text(row, "targets") == "required", "{name}");
    }
}

#[test]
fn fixtures() {
    let f = Fixtures::load();
    for (identity, seed) in &f.seeds {
        assert_eq!(ed25519_public(seed), *identity);
    }
    let space = &f.json["space"];
    let states = &space["states"];
    // Each state's reference and ephemeral key.
    let merged = RotationSet::new([f.rotation("A"), f.rotation("B")]).unwrap();
    assert_eq!(merged.encode(), bytes(&states["merged"], "reference"));
    // The inputs in the state's canonical order.
    let inputs: Vec<[u8; 32]> = merged
        .ids()
        .iter()
        .map(|id| {
            let name = if *id == f.rotation("A") { "A" } else { "B" };
            array(&space["content_keys"], name)
        })
        .collect();
    let k_ab = state_secret(
        SecretKind::Content,
        &RotationId::from(f.space),
        &merged,
        &inputs,
    )
    .unwrap();
    assert_eq!(*k_ab, array::<32>(&states["merged"], "content_key"));
    for (state, key) in [
        ("A", array::<32>(&space["content_keys"], "A")),
        ("B", array::<32>(&space["content_keys"], "B")),
        ("merged", *k_ab),
    ] {
        assert_eq!(
            hex(*ephemeral_key(&key)),
            text(&states[state], "ephemeral_key"),
            "{state}"
        );
        if state != "merged" {
            let single = RotationSet::single(f.rotation(state));
            assert_eq!(single.encode(), bytes(&states[state], "reference"));
        }
    }
    // The restricted space: its content key, its reference and its
    // ephemeral key.
    let r = &f.json["restricted"];
    let own_secret: [u8; 32] = array(r, "own_secret");
    let parent: [u8; 32] = array(r, "parent");
    assert_eq!(parent, f.space);
    let mut info = RESTRICTED_KEY.to_vec();
    push_field(&mut info, &f.restricted);
    push_field(&mut info, &parent);
    let k_f = hkdf(Some(&own_secret), &*k_ab, &info);
    assert_eq!(*k_f, array::<32>(r, "content_key"));
    assert_eq!(
        hex(*ephemeral_key(&k_f)),
        text(r, "ephemeral_key"),
        "restricted"
    );
    let reference = bytes(r, "key_reference");
    let own = read_restricted_reference(&reference).unwrap();
    assert_eq!(own.ids(), &[RotationId::from(array::<32>(r, "rotation"))]);
    // The parent's state, sealed under a key from the space's own secret.
    let own_bytes = own.encode();
    let rest = &reference[own_bytes.len()..];
    let mut aad = PARENT_REFERENCE.to_vec();
    push_field(&mut aad, &f.restricted);
    aad.extend_from_slice(&own_bytes);
    let parent_state = xchacha20poly1305_open(
        &hkdf(None, &own_secret, PARENT_REFERENCE),
        &to_array(&rest[..NONCE_BYTES]),
        &aad,
        &rest[NONCE_BYTES..],
    )
    .unwrap();
    assert_eq!(*parent_state, bytes(r, "parent_state"));
}

/// The eight frames: each sealed again from its fields, byte for byte, and
/// opened back to them.
#[test]
fn frames() {
    let f = Fixtures::load();
    let frames = family("frames");
    let frames = frames.as_array().unwrap();
    assert_eq!(frames.len(), 8);
    for case in frames {
        let description = text(case, "description");
        let inner = inner_of(&case["fields"]);
        let space: [u8; 32] = array(case, "space");
        let reference = bytes(case, "key_reference");
        let receiver = f.receiver();
        let content_key = receiver.content_key(&space, &reference).unwrap();
        let sealed = seal_with(
            &inner,
            &space,
            &reference,
            &content_key,
            &f.seeds[&inner.sender.ed.0],
            &array(case, "nonce"),
        )
        .unwrap_or_else(|e| panic!("{description}: {e:?}"));
        assert_eq!(hex(*sealed.ephemeral_key), text(case, "ephemeral_key"));
        assert_eq!(hex(&sealed.inner), text(case, "inner"), "{description}");
        assert_eq!(
            hex(&sealed.signing_input),
            text(case, "tbs"),
            "{description}"
        );
        assert_eq!(
            hex(sealed.signature),
            text(case, "signature"),
            "{description}"
        );
        assert_eq!(hex(&sealed.core), text(case, "core"), "{description}");
        assert_eq!(
            hex(&*sealed.plaintext),
            text(case, "plaintext"),
            "{description}"
        );
        assert_eq!(hex(&sealed.aad), text(case, "aad"), "{description}");
        assert_eq!(hex(&sealed.outer), text(case, "outer"), "{description}");
        assert_eq!(sealed.outer.len() as u64, u64_of(case, "outer_bytes"));
        assert_eq!(
            sealed.handle.map(hex),
            case.get("handle").map(|h| h.as_str().unwrap().to_owned()),
            "{description}"
        );
        // Opened back to its fields.
        let outer = Outer::read(&sealed.outer, &space).unwrap();
        assert_eq!(outer, sealed.frame);
        assert_eq!(Inner::read(&sealed.inner).unwrap(), inner, "{description}");
        assert_eq!(
            *outer.open(&sealed.ephemeral_key).unwrap(),
            *sealed.plaintext
        );
    }
}

#[test]
fn accepted_in_order() {
    let f = Fixtures::load();
    let frames = family("frames");
    let receiver = f.receiver();
    let mut replay = ReplayState::new();
    for case in family("accepted_in_order").as_array().unwrap() {
        let frame = &frames[u64_of(case, "frame") as usize];
        let scope: [u8; 32] = array(case, "scope");
        let accepted = receive(&bytes(frame, "outer"), &scope, &receiver, &mut replay);
        assert_eq!(case["accepted"], json!(accepted.is_ok()), "{case}");
        let accepted = accepted.unwrap();
        assert_eq!(accepted.inner.name, text(case, "name"));
        assert_eq!(accepted.inner.kind, kind_of(text(case, "kind")));
    }
}

#[test]
fn frame_refusals() {
    let f = Fixtures::load();
    let frames = family("frames");
    let cases = family("frame_refusals");
    let mut steps = BTreeSet::new();
    for case in cases.as_array().unwrap() {
        let description = text(case, "description");
        let outer = bytes(case, "outer");
        let mut receiver = f.receiver();
        let mut replay = ReplayState::new();
        let mut scope = f.space;
        let context = case.get("context").and_then(Json::as_str).unwrap_or("");
        match context {
            "" | "the receiver follows both spaces; the message's scope is the first" => {}
            "the Ephemeral message was sent for that space" => {
                // The outer frame's own space, which the receiver does not
                // follow.
                let frasil_base::cbor::Value::Map(map) = frasil_base::cbor::decode(&outer).unwrap()
                else {
                    panic!("an outer map");
                };
                scope = map[&3].as_byte_array().unwrap();
                assert!(!receiver.spaces.contains_key(&scope));
            }
            "the receiver does not implement ext-guests" => receiver.guests = false,
            "the receiver holds a fork of alice's chain" => {
                receiver
                    .membership
                    .insert(f.device("alice"), Membership::Forked);
            }
            "alice writes through a person grant" => {
                receiver
                    .membership
                    .insert(f.device("alice"), Membership::Unjudgeable);
            }
            "the receiver accepted it once" => {
                let first = bytes(&frames[0], "outer");
                receive(&first, &f.space, &receiver, &mut replay).unwrap();
            }
            other => panic!("context {other}"),
        }
        let refusal = receive(&outer, &scope, &receiver, &mut replay).expect_err(description);
        let step = u64_of(case, "step");
        assert_eq!(
            (u64::from(refusal.step), refusal.class.name()),
            (step, text(case, "class")),
            "{description}"
        );
        steps.insert(u64_of(case, "step"));
    }
    assert_eq!(steps, (1..=16).collect());
}

#[test]
fn replay_window() {
    let f = Fixtures::load();
    let v = family("replay_window");
    assert_eq!(u64_of(&v, "window"), REPLAY_WINDOW);
    let alice = f.device("alice");
    let mut state = ReplayState::new();
    for step in v["ephemeral_messages"].as_array().unwrap() {
        let (epoch, counter) = (u64_of(step, "epoch"), u64_of(step, "counter"));
        let ok = state.message_ok(&f.space, &alice, epoch, counter);
        if ok {
            state.accept_message(&f.space, &alice, epoch, counter);
        }
        assert_eq!(
            if ok { "accepted" } else { "Replayed" },
            text(step, "outcome"),
            "{step}"
        );
        // The window survives the replay table's encoding.
        let window = *state.window(&f.space, &alice).unwrap();
        let (e, c, w) = window.to_record();
        assert_eq!(Window::from_record(e, c, w), window);
    }
    let mut state = ReplayState::new();
    let key = SlotKey {
        space: f.space,
        sender: alice,
        name: "com.example.presence".to_owned(),
        stream: Some(to_array(&unhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0"))),
    };
    for step in v["ephemeral_slots"].as_array().unwrap() {
        let (epoch, counter) = (u64_of(step, "epoch"), u64_of(step, "counter"));
        let ok = state.slot_ok(&key, epoch, counter);
        if ok {
            state.accept_slot(key.clone(), epoch, counter, &bytes(step, "data"));
        }
        assert_eq!(
            if ok { "accepted" } else { "Replayed" },
            text(step, "outcome"),
            "{step}"
        );
        let held = state.slot(&key).and_then(|h| h.value.as_ref()).map(hex);
        assert_eq!(held, step["held"].as_str().map(str::to_owned), "{step}");
    }
}

/// One step of `replay_window.bounds`: the frame offered, accepted if it
/// passes, then the counts, the floor and what was forgotten.
fn bounds_step(state: &mut ReplayState, space: &[u8; 32], step: &Json) {
    let sender = DeviceId(array(step, "sender"));
    let (epoch, counter) = (u64_of(step, "epoch"), u64_of(step, "counter"));
    let forgotten: Vec<SlotKey> = step["forgotten"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| SlotKey {
            space: *space,
            sender: DeviceId(to_array(&unhex(pair[0].as_str().unwrap()))),
            name: pair[1].as_str().unwrap().to_owned(),
            stream: None,
        })
        .collect();
    for key in &forgotten {
        assert!(state.slot(key).is_some(), "held before: {step}");
    }
    let ok = match kind_of(text(step, "kind")) {
        Kind::Message => {
            let ok = state.message_ok(space, &sender, epoch, counter);
            if ok {
                state.accept_message(space, &sender, epoch, counter);
            }
            ok
        }
        Kind::Slot => {
            let key = SlotKey {
                space: *space,
                sender,
                name: text(step, "name").to_owned(),
                stream: None,
            };
            let ok = state.slot_ok(&key, epoch, counter);
            if ok {
                state.accept_slot(key, epoch, counter, &bytes(step, "data"));
            }
            ok
        }
    };
    let label = text(step, "step");
    assert_eq!(
        if ok { "accepted" } else { "Replayed" },
        text(step, "outcome"),
        "{label}"
    );
    assert_eq!(
        state.held_by(space, &sender) as u64,
        u64_of(step, "held_by_sender"),
        "{label}"
    );
    assert_eq!(
        state.held_in(space) as u64,
        u64_of(step, "held_in_space"),
        "{label}"
    );
    let floor = step["floor"].as_array().unwrap();
    assert_eq!(
        state.floor(space, &sender),
        (floor[0].as_u64().unwrap(), floor[1].as_u64().unwrap()),
        "{label}"
    );
    for key in &forgotten {
        assert!(state.slot(key).is_none(), "forgotten: {label}");
    }
}

#[test]
fn replay_bounds() {
    let v = family("replay_window");
    let b = &v["bounds"];
    assert_eq!(
        u64_of(b, "slots_per_sender"),
        RECEIVER_SLOTS_PER_SENDER as u64
    );
    assert_eq!(
        u64_of(b, "slots_per_space"),
        RECEIVER_SLOTS_PER_SPACE as u64
    );
    let data = bytes(b, "data");
    // One sender past 32, its floor, and new epochs.
    let one = &b["one_sender"];
    let space: [u8; 32] = array(one, "space");
    let mut state = ReplayState::new();
    for step in one["steps"].as_array().unwrap() {
        bounds_step(&mut state, &space, step);
    }
    // A full space: sender i is 32 bytes of i, holding n00, n01, ... at
    // (1, j + 1).
    let full = &b["full_space"];
    let space: [u8; 32] = array(full, "space");
    let senders = u64_of(&full["fill"], "senders");
    let names = u64_of(&full["fill"], "names");
    let mut state = ReplayState::new();
    for i in 1..=senders {
        for j in 0..names {
            let key = SlotKey {
                space,
                sender: DeviceId([u8::try_from(i).unwrap(); 32]),
                name: format!("n{j:02}"),
                stream: None,
            };
            assert!(state.slot_ok(&key, 1, j + 1));
            state.accept_slot(key, 1, j + 1, &data);
        }
    }
    assert_eq!(state.held_in(&space), RECEIVER_SLOTS_PER_SPACE);
    for step in full["steps"].as_array().unwrap() {
        bounds_step(&mut state, &space, step);
    }
}

#[test]
fn receiver_restart() {
    let f = Fixtures::load();
    for scenario in family("receiver_restart").as_array().unwrap() {
        let kept = scenario["window_kept_at_rest"].as_bool().unwrap();
        let mut receiver = f.receiver();
        let mut replay = ReplayState::new();
        let mut run = 1;
        for step in scenario["steps"].as_array().unwrap() {
            let label = text(step, "step");
            if label.starts_with("run 2") && run == 1 {
                run = 2;
                // The restart: receiver nonces are never kept at rest; the
                // window is kept only through the replay table.
                let mut fresh = ReplayState::new();
                if kept {
                    for (space, sender, window) in replay.windows() {
                        let (e, c, w) = window.to_record();
                        fresh.restore_window(space, sender, Window::from_record(e, c, w));
                    }
                }
                replay = fresh;
            }
            let nonce = &scenario["nonces"][format!("run {run}")];
            receiver.nonces = vec![to_array(&unhex(nonce.as_str().unwrap()))];
            let got = class_name(receive(
                &bytes(step, "outer"),
                &f.space,
                &receiver,
                &mut replay,
            ));
            assert_eq!(got, text(step, "outcome"), "kept {kept}: {label}");
        }
    }
}

#[test]
fn epochs() {
    let v = family("epochs");
    assert_eq!(u64_of(&v, "restore_step"), EPOCH_RESTORE_STEP);
    let randoms: Vec<u32> = v["randoms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| u32::try_from(r.as_u64().unwrap()).unwrap())
        .collect();
    let backup = u64_of(&v, "backup_stored_epoch");
    let steps = v["steps"].as_array().unwrap();
    let mut stored: Option<u64> = None;
    for (index, step) in steps.iter().enumerate() {
        let mut counters = match index {
            0 => Counters::restore_with(stored, randoms[0]),
            3 => Counters::restore_with(Some(backup), randoms[1]),
            _ => Counters::start(stored.unwrap()),
        }
        .unwrap();
        stored = Some(counters.epoch());
        assert_eq!(counters.epoch(), u64_of(step, "epoch"), "{step}");
        assert_eq!(stored, Some(u64_of(step, "stored_after")));
        for send in step["sends"].as_array().unwrap() {
            let space: [u8; 32] = array(send, "space");
            assert_eq!(
                counters.next(&space),
                Some((u64_of(send, "epoch"), u64_of(send, "counter"))),
                "{send}"
            );
        }
    }
}

#[test]
fn membership() {
    let added = ListStanding {
        added: true,
        revoked: false,
        forked: false,
    };
    let device = |in_force| MemberInputs {
        forked: false,
        paths: vec![path_device(in_force)],
        named: true,
        parent: None,
    };
    for row in family("membership").as_array().unwrap() {
        let view = text(row, "view");
        let inputs = match view {
            "a device grant in force, at read"
            | "a guest: a device grant with a session, in force"
            | "demoted to read: still in; capability checks decide the rest"
            | "a removal the receiver has not received" => device(true),
            "a person grant, and the person's list as held has a valid add of the device"
            | "a waiting list member, through its person's grant" => MemberInputs {
                paths: vec![path_person(Some(added))],
                ..device(true)
            },
            "a space grant, and the granted space's merged roster as held has the device \
             reach it, propagating" => MemberInputs {
                paths: vec![path_space(Some(true))],
                ..device(true)
            },
            "a restricted space reached, and its parent reached too" => MemberInputs {
                parent: Some(Membership::In),
                ..device(true)
            },
            "removed by a valid roster event of the merged roster"
            | "a removal concurrent with the device's last unit: the merged roster has it out" => {
                device(false)
            }
            "a person grant whose list, as held, revokes the device; no response in this \
             space yet" => MemberInputs {
                paths: vec![path_person(Some(ListStanding {
                    revoked: true,
                    ..added
                }))],
                ..device(true)
            },
            "a space grant whose granted space, as held, no longer has the device reach it" => {
                MemberInputs {
                    paths: vec![path_space(Some(false))],
                    ..device(true)
                }
            }
            "a restricted space whose parent the device no longer reaches" => MemberInputs {
                parent: Some(Membership::MembershipEnded),
                ..device(true)
            },
            "the receiver holds evidence of a fork of the device's chain in this log" => {
                MemberInputs {
                    forked: true,
                    ..device(true)
                }
            }
            "never named by any roster event or list the receiver holds" => MemberInputs {
                forked: false,
                paths: vec![],
                named: false,
                parent: None,
            },
            "only a person grant whose list the receiver does not hold" => MemberInputs {
                forked: false,
                paths: vec![path_person(None)],
                named: false,
                parent: None,
            },
            other => panic!("view {other}"),
        };
        let got = match member(&inputs) {
            Membership::In => "in".to_owned(),
            other => class_name(other.check()),
        };
        assert_eq!(got, text(row, "verdict"), "{view}");
    }
}

#[test]
fn relay() {
    let v = family("relay");
    let frames = family("frames");
    let space: [u8; 32] = array(&v, "space");
    let origins: BTreeMap<String, [u8; 8]> = v["origins"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(c, o)| (c.clone(), to_array(&unhex(o.as_str().unwrap()))))
        .collect();
    let outer = |i: usize| bytes(&frames[i], "outer");
    let mut relay: Relay<String> = Relay::new(space);
    let join = |relay: &mut Relay<String>, c: &str| relay.join_with(c.to_owned(), origins[c]);
    let send = |relay: &mut Relay<String>, c: &str, frame: Vec<u8>| {
        relay.frame_with(c.to_owned(), &frame, origins[c]).unwrap()
    };
    let mut sent: Vec<Vec<Relayed<String>>> = vec![
        join(&mut relay, "c1"),
        join(&mut relay, "c2"),
        send(&mut relay, "c1", outer(2)),
        send(&mut relay, "c1", outer(0)),
        send(&mut relay, "c1", outer(3)),
        send(&mut relay, "c2", outer(4)),
        join(&mut relay, "c3"),
    ];
    sent.push(relay.leave(&"c2".to_owned()));
    sent.push(relay.leave(&"c1".to_owned()));
    sent.push(join(&mut relay, "c4"));
    let steps = v["steps"].as_array().unwrap();
    assert_eq!(steps.len(), sent.len());
    for (step, sent) in steps.iter().zip(&sent) {
        let got: Vec<Json> = sent
            .iter()
            .map(|r| {
                // Each is a message of transport.md.
                assert!(!r.message(&space).is_empty());
                match r {
                    Relayed::Frame {
                        to,
                        origin,
                        kind,
                        handle,
                        ..
                    } => {
                        let mut out =
                            json!({"to": to, "origin": hex(origin), "frame": kind.name()});
                        if let Some(handle) = handle {
                            out["handle"] = json!(hex(handle));
                        }
                        out
                    }
                    Relayed::Gone { to, origin } => json!({"to": to, "gone": hex(origin)}),
                }
            })
            .collect();
        assert_eq!(Json::Array(got), step["sent"], "{}", text(step, "step"));
    }
    // A late joiner receives the cleared value, the frame held last.
    assert!(relay.origin(&"c4".to_owned()).is_some());
    relay.leave(&"c4".to_owned());
    relay.leave(&"c3".to_owned());
    assert!(relay.is_empty());
}
