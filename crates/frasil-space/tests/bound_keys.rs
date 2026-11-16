//! An ML-DSA-65 key cannot be bound to another device (roster.md, "A
//! device's keys", "An author's keys" and "Security considerations").
//!
//! A scheme-2 signature has an Ed25519 half and an ML-DSA-65 half
//! (crypto.md, "Signature schemes"). These tests model an adversary that can
//! produce the Ed25519 half for a victim's key, a quantum adversary at
//! verification time, by holding the victim's Ed25519 seed but not its
//! ML-DSA-65 seed. The adversary also holds an ML-DSA-65 key `M2` of its
//! own, and some standing in the space or in a list the space reads.
//!
//! A device is named by the device ID of all of its keys, and a verifier
//! takes an author's keys only by their hash (crypto.md, "A device's keys").
//! So a record that pairs the victim's Ed25519 key with `M2` names another
//! device, `D'`, and lends the victim nothing; a record that claims the
//! victim's device ID beside `M2` is `NotCommitted`. An event the adversary
//! signs under its own keys is `D'`'s, which holds no standing; one it signs
//! under the victim's own `ed` and `kc` has a `BadSignature` ML-DSA-65 half,
//! and is never evidence against the victim.

mod common;

use common::space::{Fixture, list_device, prefix};
use common::{example, family, text};
use frasil_base::errors::Class;
use frasil_crypto::device::{DeviceId, KeysCommitment};
use frasil_crypto::fixtures::FixtureKeys;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_crypto::wrap::xwing_public;
use frasil_events::{Envelope, Event, EventId, decode, kind};
use frasil_identity::body::ListBody;
use frasil_identity::{DeviceList, Kind, MemberKeys};
use frasil_keys::RotationSet;
use frasil_keys::body::{Inner, RotationKeys, Seal, VisiblePart};
use frasil_keys::derive::{
    SecretKind, body_commitment, body_key, read_credential, state_secret, upload_key,
};
use frasil_space::part::{RosterPart, Update};
use frasil_space::{
    Change, DeviceKeys, HeldList, HistoryMode, Level, MemberRef, OtherLogs, Policy, ScreenedLog,
    Signature, Standing, Status, Via,
};
use serde_json::Value as Json;

/// The adversary's own ML-DSA-65 seed, which signs as `M2`.
const M2_SEED: [u8; 32] = [0x4d; 32];

/// An X-Wing seed for the keys the adversary binds; any valid key will do.
const ADVERSARY_XWING_SEED: [u8; 32] = [0x58; 32];

/// A case of roster.json's family, by name.
fn case(family_name: &str, name: &str) -> Json {
    family(family_name)
        .as_array()
        .unwrap()
        .iter()
        .find(|case| text(case, "name") == name)
        .unwrap_or_else(|| panic!("no case {name:?}"))
        .clone()
}

/// A device's Ed25519 seed in a history, as the vectors derive it.
fn ed_seed(prefix: &str, name: &str) -> [u8; 32] {
    example(&format!("{prefix}/{name}/ed25519"))
}

/// A device's own signer: its Ed25519 seed and its fixture ML-DSA-65 and
/// X-Wing seeds.
fn device_signer(prefix: &str, name: &str) -> Signer {
    FixtureKeys::from_identity_seed(&ed_seed(prefix, name)).signer()
}

/// The adversary signing with the victim's Ed25519 seed, which a quantum
/// adversary can stand in for, beside its own `M2` and X-Wing key: a key
/// set whose device ID, `D'`, is not the victim's.
fn forger(prefix: &str, victim: &str) -> Signer {
    Signer::from_seeds(&ed_seed(prefix, victim), &M2_SEED, Some(&adversary_xwing()))
}

fn adversary_xwing() -> [u8; frasil_crypto::sizes::XWING_PUBLIC] {
    xwing_public(&ADVERSARY_XWING_SEED)
}

/// How a test's space event is sealed.
enum Sealing {
    /// Sealed under a state whose content key is `secret`.
    Under {
        state: RotationSet,
        secret: [u8; 32],
    },
    /// A rotation whose content key is `content`. A replica holds it as it
    /// would from the bundle wrap its author seals to every member.
    Rotate { content: [u8; 32] },
}

/// A space event with these changes, sealed and signed as `signer`, under
/// `kc` when given in place of the signer's own.
#[allow(clippy::too_many_arguments)]
fn space_event(
    signer: &Signer,
    kc: Option<KeysCommitment>,
    space: EventId,
    seq: u64,
    prev: Option<EventId>,
    parents: Vec<EventId>,
    sealing: &Sealing,
    changes: Vec<Change>,
) -> Event {
    let kc = kc.unwrap_or(*signer.kc());
    let author = frasil_crypto::device::device_id(signer.identity_key(), &kc);
    let (seal, secret) = match sealing {
        Sealing::Under { state, secret } => (Seal::Under(state.clone()), *secret),
        Sealing::Rotate { content } => (
            Seal::Rotation(RotationKeys {
                grant_commitment: [0x67; 32],
                read: read_credential(content).public,
                upload: upload_key(&[0x75; 32]).public,
            }),
            *content,
        ),
    };
    let key = body_key(&secret, &space.0, &author, seq);
    let inner = Inner {
        roster: Some(RosterPart::Update(Update { changes }).encode()),
        ..Inner::default()
    };
    let body = VisiblePart {
        seal,
        deliveries: Vec::new(),
        sealed: inner.seal_with(&key, &space.0, &author, seq, &[0x6e; 24]),
        nonce: None,
        commitment: body_commitment(&key),
        twin: None,
    }
    .encode();
    let signed = Envelope {
        kind: kind::SPACE,
        log: Some(space),
        ed: *signer.identity_key(),
        kc,
        seq,
        prev,
        parents,
        cuts: Vec::new(),
        body,
        scheme: Scheme::Hybrid,
    }
    .sign(signer);
    decode(&signed).expect("the event decodes, its Ed25519 half verifying")
}

/// A history's events up to and without those named in `leave_out`, with
/// the vectors' keyring.
fn fixture_without(case: &Json, prefix: &str, leave_out: &[&str]) -> Fixture {
    let mut fixture = Fixture::new(prefix, &case["events"]);
    fixture
        .events
        .retain(|(name, _)| !leave_out.contains(&name.as_str()));
    fixture.log = common::log_of(&fixture.events);
    fixture
}

/// The content key of a single rotation's state, `k(S)` for `S = {r}`.
fn state_of(fixture: &Fixture, rotation: EventId) -> Sealing {
    let k_r = fixture.keys.rotations[&rotation].clone();
    let state = RotationSet::single(rotation);
    let secret = state_secret(SecretKind::Content, &fixture.log.id(), &state, &[*k_r]).unwrap();
    Sealing::Under {
        state,
        secret: *secret,
    }
}

/// A grant of the forger's keys, the victim's Ed25519 key beside `M2`, as
/// an administering device: its member ID is the device ID of those keys,
/// `D'`, not the victim's.
fn binding_grant(fixture: &Fixture, victim: &str) -> Change {
    let forger = forger(&fixture.prefix, victim);
    let keys = DeviceKeys {
        ed: *forger.identity_key(),
        keys: forger.keys().clone(),
    };
    let change = Change::grant_administrator(keys, 255, HistoryMode::WithHistory, Via::Code);
    assert_ne!(
        change.member.unwrap().id,
        fixture.device_key(victim),
        "another device ID"
    );
    change
}

/// The same keys claimed under the victim's own device ID: `NotCommitted`.
fn claiming_grant(fixture: &Fixture, victim: &str) -> Change {
    Change {
        member: Some(MemberRef::device(DeviceId(fixture.device_key(victim)))),
        ..binding_grant(fixture, victim)
    }
}

fn screen(fixture: &Fixture, others: &OtherLogs<'_>) -> ScreenedLog {
    ScreenedLog::screen(&fixture.log, &fixture.keys, &fixture.limits, others).unwrap()
}

/// The class of an event's status, by name.
fn class_of(status: Option<&Status>) -> Option<&'static str> {
    status.and_then(|s| s.class()).map(|c| c.name())
}

/// A reader names an administrator's Ed25519 key with `M2`, and tries to
/// raise itself through it.
///
/// History: P founds the space, grants N write and demotes N to read. N, a
/// reader, seals an event that grants the forger's keys as an
/// administering device: they name `D'`, and lend P nothing. The same
/// grant claiming P's device ID is `NotCommitted`. A raise of N "by" P under
/// P's own `kc`, its ML-DSA-65 half made with `M2`, is `BadSignature`; the
/// same raise under the forger's own keys is `D'`'s, which does not
/// administer. N stays at `read`.
#[test]
fn a_reader_cannot_bind_its_own_ml_dsa_key_to_an_administrator() {
    let name = "a demotion to read refuses the member's concurrent writes";
    let case = case("writes", name);
    let prefix = prefix(name);
    let mut fixture = fixture_without(&case, &prefix, &["N writes, apart", "N heals, apart"]);
    let space = fixture.log.id();
    let demote = fixture.id("P demotes N to read");
    let n = fixture.device_key("N");
    let p = device_signer(&prefix, "P");
    assert_eq!(fixture.device_key("P"), p.device_id().0);

    // N, a reader, seals the binding under the current state, and a second
    // event that claims P's device ID for the forger's keys.
    let n_signer = device_signer(&prefix, "N");
    let binding = space_event(
        &n_signer,
        None,
        space,
        1,
        None,
        vec![demote],
        &state_of(&fixture, demote),
        vec![binding_grant(&fixture, "P")],
    );
    let claim = space_event(
        &n_signer,
        None,
        space,
        2,
        Some(binding.id()),
        vec![binding.id()],
        &state_of(&fixture, demote),
        vec![claiming_grant(&fixture, "P")],
    );
    let raise = |kc: Option<KeysCommitment>| {
        space_event(
            &forger(&prefix, "P"),
            kc,
            space,
            if kc.is_some() { 4 } else { 1 },
            kc.is_some().then_some(demote),
            vec![demote],
            &state_of(&fixture, demote),
            vec![Change::set_level(
                MemberRef::device(DeviceId(n)),
                Level::Write,
            )],
        )
    };
    // Under P's own kc, P's seq 4 after its demotion of N.
    let as_p = raise(Some(*p.kc()));
    assert_eq!(as_p.author(), p.device_id());
    // Under the forger's own keys: another author.
    let as_d = raise(None);
    assert_ne!(as_d.author(), p.device_id());
    for event in [&binding, &claim, &as_p, &as_d] {
        fixture.log.place(event.clone()).unwrap();
    }

    let others = OtherLogs::none();
    let screened = screen(&fixture, &others);
    assert!(screened.opened(binding.id()).is_some(), "the binding opens");
    assert_eq!(screened.signature(binding.id()), Some(Signature::Verified));
    assert_eq!(
        screened.verdict(claim.id()).unwrap().map_err(|c| c.name()),
        Err("NotCommitted")
    );
    assert_eq!(screened.signature(as_p.id()), Some(Signature::BadSignature));
    assert_eq!(screened.signature(as_d.id()), Some(Signature::Verified));

    let keys = fixture.keys.clone();
    let resolved = fixture.resolve(None, &keys, &others).unwrap();
    assert_eq!(
        class_of(resolved.status(binding.id())),
        Some("NotAnAdministrator")
    );
    assert_eq!(class_of(resolved.status(as_p.id())), Some("BadSignature"));
    assert_eq!(
        class_of(resolved.status(as_d.id())),
        Some("NotAnAdministrator"),
        "D' administers nothing"
    );
    let level = resolved
        .roster()
        .state(&MemberRef::device(DeviceId(n)))
        .map(|state| state.level);
    assert_eq!(level, Some(Level::Read), "N stays a reader");
}

/// A removed member names an administrator's Ed25519 key with `M2` in a
/// rotation, and tries to grant itself back in through it.
///
/// History: P founds the space, grants X write, and removes X. X makes a
/// rotation of its own after its removal, granting the forger's keys, which
/// name `D'`. A rotation "by" P after its removal of X, under P's own `kc`
/// and signed with `M2`, grants X write again: `BadSignature`. Under the
/// forger's own keys it is `D'`'s, which holds no standing. X stays out.
#[test]
fn a_removed_member_cannot_bind_its_own_ml_dsa_key_in_a_rotation() {
    let name = "a unit concurrent with its writer's removal";
    let case = case("writes", name);
    let prefix = prefix(name);
    let mut fixture = fixture_without(&case, &prefix, &["X writes 3, not having seen its removal"]);
    let space = fixture.log.id();
    let removal = fixture.id("P removes X");
    let last_unit = fixture.id("X writes 2");
    let x = fixture.device_key("X");
    let p = device_signer(&prefix, "P");
    let x_signer = device_signer(&prefix, "X");

    let binding_key = [0x31; 32];
    let binding = space_event(
        &x_signer,
        None,
        space,
        3,
        Some(last_unit),
        vec![last_unit, removal],
        &Sealing::Rotate {
            content: binding_key,
        },
        vec![binding_grant(&fixture, "P")],
    );
    let x_keys = DeviceKeys {
        ed: *x_signer.identity_key(),
        keys: x_signer.keys().clone(),
    };
    let regrant = |kc: Option<KeysCommitment>, content: [u8; 32]| {
        space_event(
            &forger(&prefix, "P"),
            kc,
            space,
            if kc.is_some() { 4 } else { 1 },
            kc.is_some().then_some(removal),
            vec![removal],
            &Sealing::Rotate { content },
            vec![Change::grant_device(
                x_keys.clone(),
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )],
        )
    };
    let (as_p_key, as_d_key) = ([0x32; 32], [0x33; 32]);
    let as_p = regrant(Some(*p.kc()), as_p_key);
    let as_d = regrant(None, as_d_key);
    for (event, key) in [
        (&binding, binding_key),
        (&as_p, as_p_key),
        (&as_d, as_d_key),
    ] {
        fixture.log.place(event.clone()).unwrap();
        fixture
            .keys
            .rotations
            .insert(event.id(), zeroize::Zeroizing::new(key));
    }

    let others = OtherLogs::none();
    let screened = screen(&fixture, &others);
    assert!(screened.opened(binding.id()).is_some(), "the binding opens");
    assert_eq!(screened.signature(as_p.id()), Some(Signature::BadSignature));
    assert_eq!(screened.signature(as_d.id()), Some(Signature::Verified));

    let keys = fixture.keys.clone();
    let resolved = fixture.resolve(None, &keys, &others).unwrap();
    assert_eq!(
        class_of(resolved.status(binding.id())),
        Some("NotAnAdministrator")
    );
    assert_eq!(class_of(resolved.status(as_p.id())), Some("BadSignature"));
    assert!(
        !matches!(resolved.status(as_d.id()), Some(Status::Valid(_))),
        "D' holds no standing"
    );
    assert!(
        !matches!(
            resolved.roster().standing(&MemberRef::device(DeviceId(x))),
            Some(Standing::In(_))
        ),
        "X stays out"
    );
}

/// A person's own list names an administrator's Ed25519 key with `M2`, and
/// a space that names the person takes it only as another device.
///
/// History: P founds the space and grants person X write; X1 is a device of
/// X's list. X1 adds to its own list a device whose identity is P's
/// Ed25519 key and whose ML-DSA-65 key is `M2`: the add is valid in X's
/// list, and names `D'`. A policy change "by" P under P's own `kc`, signed
/// with `M2`, is `BadSignature` with or without X's list; under the
/// forger's own keys it is `D'`'s, a writer through person X at the most,
/// which cannot change the policy.
#[test]
fn a_persons_list_cannot_bind_its_own_ml_dsa_key_to_an_administrator() {
    let name = "a device the remover never knew";
    let case = case("writes", name);
    let prefix = prefix(name);
    let mut fixture = fixture_without(
        &case,
        &prefix,
        &["P removes person X", "X2, added to X's list apart, writes"],
    );
    let space = fixture.log.id();
    let grant = fixture.id("P grants person X write");
    let p = device_signer(&prefix, "P");

    // X's list, as the vectors give it, with X1's add of (P's key, M2).
    let list_prefix = text(&case["list_prefixes"], "person X").to_owned();
    let rows = case["lists"]["person X"].as_array().unwrap();
    let mut list = DeviceList::new(&common::bytes(&rows[0], "signed")).unwrap();
    for row in &rows[1..] {
        list.insert(&common::bytes(row, "signed")).unwrap();
    }
    let x1 = list_device(&list_prefix, "X1");
    let bound = MemberKeys::from_seeds(&ed_seed(&prefix, "P"), &ADVERSARY_XWING_SEED, &M2_SEED);
    assert_ne!(bound.device_id(), p.device_id());
    let person = list.person_id();
    let add = ListBody::add(
        Kind::Device,
        &bound.public(Kind::Device),
        bound.prove_possession(&person, x1.device_id(), Kind::Device),
    );
    let add = list.sign(&add, x1.signer());
    list.insert(&add).unwrap();
    assert_eq!(list.check_alone(decode(&add).unwrap().id()), None);

    let policy = Policy {
        forbid_agents: true,
        ..Policy::default()
    };
    let change = |kc: Option<KeysCommitment>| {
        space_event(
            &forger(&prefix, "P"),
            kc,
            space,
            if kc.is_some() { 3 } else { 1 },
            kc.is_some().then_some(grant),
            vec![grant],
            &state_of(&fixture, grant),
            vec![Change::set_policy(policy)],
        )
    };
    let as_p = change(Some(*p.kc()));
    let as_d = change(None);
    assert_eq!(as_d.author(), bound.device_id());
    fixture.log.place(as_p.clone()).unwrap();
    fixture.log.place(as_d.clone()).unwrap();

    // Without X's list, with it, and without it again, over the same log:
    // `D'`'s signature waits for keys until the list gives them, verifies
    // with them, and waits again without them, whatever the log remembers
    // of the check made with them (events.md, 3.3 The ML-DSA-65 half).
    let with_list = OtherLogs::none().with_list(HeldList::new(list));
    for (others, d_signature) in [
        (OtherLogs::none(), Signature::NoHybridKey),
        (with_list, Signature::Verified),
        (OtherLogs::none(), Signature::NoHybridKey),
    ] {
        let screened = screen(&fixture, &others);
        assert_eq!(screened.signature(as_p.id()), Some(Signature::BadSignature));
        assert_eq!(screened.signature(as_d.id()), Some(d_signature));
        let keys = fixture.keys.clone();
        let resolved = fixture.resolve(None, &keys, &others).unwrap();
        assert!(!matches!(
            resolved.status(as_p.id()),
            Some(Status::Valid(_))
        ));
        assert!(!matches!(
            resolved.status(as_d.id()),
            Some(Status::Valid(_))
        ));
        assert!(!resolved.policy().forbid_agents, "the policy P never set");
    }
}

/// The adversary cannot frame its victim with a fork.
///
/// History as in [`a_reader_cannot_bind_its_own_ml_dsa_key_to_an_administrator`]:
/// N grants the forger's keys. Then a second event "by" P at P's `seq` 3,
/// beside P's genuine demotion of N, under P's own `ed` and `kc` and signed
/// with `M2`. Its ML-DSA-65 half is `BadSignature`, so it is never evidence
/// (events.md, "Chains and evidence of a fork"): P has no fork point, its
/// demotion of N stands, and N stays at `read`.
#[test]
fn a_bound_key_cannot_frame_its_victim_with_a_fork() {
    let name = "a demotion to read refuses the member's concurrent writes";
    let case = case("writes", name);
    let prefix = prefix(name);
    let mut fixture = fixture_without(&case, &prefix, &["N writes, apart", "N heals, apart"]);
    let space = fixture.log.id();
    let granted = fixture.id("P grants N write");
    let demote = fixture.id("P demotes N to read");
    let n = fixture.device_key("N");
    let p = device_signer(&prefix, "P");

    let binding = space_event(
        &device_signer(&prefix, "N"),
        None,
        space,
        1,
        None,
        vec![demote],
        &state_of(&fixture, demote),
        vec![binding_grant(&fixture, "P")],
    );
    let policy = Policy {
        forbid_agents: true,
        ..Policy::default()
    };
    let duplicate = space_event(
        &forger(&prefix, "P"),
        Some(*p.kc()),
        space,
        3,
        Some(granted),
        vec![granted],
        &state_of(&fixture, granted),
        vec![Change::set_policy(policy)],
    );
    assert_eq!(duplicate.author(), p.device_id());
    fixture.log.place(binding.clone()).unwrap();
    fixture.log.place(duplicate.clone()).unwrap();

    let others = OtherLogs::none();
    let screened = screen(&fixture, &others);
    assert_eq!(
        screened.signature(duplicate.id()),
        Some(Signature::BadSignature)
    );
    assert!(!screened.counts_as_evidence(duplicate.id()));
    let keys = fixture.keys.clone();
    let resolved = fixture.resolve(None, &keys, &others).unwrap();
    assert_eq!(
        resolved.forks().fork_point(p.device_id()),
        None,
        "P is not framed"
    );
    assert!(
        matches!(resolved.status(demote), Some(Status::Valid(_))),
        "P's genuine demotion stands"
    );
    assert_eq!(
        resolved
            .roster()
            .state(&MemberRef::device(DeviceId(n)))
            .map(|state| state.level),
        Some(Level::Read),
        "N stays a reader"
    );
}
