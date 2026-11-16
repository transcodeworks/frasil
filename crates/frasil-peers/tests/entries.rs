//! `peers.json`: `credentials`, `merge_cap` and `recovery_entries`
//! (peers.md, sections 2.1, 3.4 to 3.7 and 3.17).

mod common;

use common::*;
use frasil_crypto::primitives::ed25519_public;
use frasil_events::{EventId, ForkPoints, Log};
use frasil_keys::RotationSet;
use frasil_keys::derive::{SecretKind, read_credential, state_secret, upload_key};
use frasil_peers::body::{EntryName, StorageBody};
use frasil_peers::entries::{
    Ancestry, Connection, Entries, EntryStatus, Present, Refusal, Rights, Source,
};
use frasil_peers::limits::CREDENTIAL_CAP;
use frasil_peers::merge::MergeStatement;
use frasil_peers::proof::{Credential, Purpose, presented, prove};
use frasil_peers::skeleton::fork_points;
use frasil_peers::{Code, PeersClass};
use serde_json::Value as Json;

fn status(status: EntryStatus) -> &'static str {
    match status {
        EntryStatus::Live => "live",
        EntryStatus::Retired => "retired",
    }
}

/// The entries as the vectors describe them, each rotation by name.
fn describe(entries: &Entries, name: impl Fn(EventId) -> String) -> Json {
    Json::from(
        entries
            .entries()
            .iter()
            .map(|e| {
                serde_json::json!({
                    "state": e.state.ids().iter().map(|&id| name(id)).collect::<Vec<_>>(),
                    "read": frasil_testkit::hex::encode(e.read),
                    "upload": frasil_testkit::hex::encode(e.upload),
                    "status": status(e.status),
                    "source": e.source.name(),
                    "proved": e.proved,
                })
            })
            .collect::<Vec<_>>(),
    )
}

/// A rotation's secrets in the reference's builder under `prefix`: its
/// content key and its upload seed `w`.
fn secrets(prefix: &str, label: &str) -> ([u8; 32], [u8; 32]) {
    (
        example(&format!("{prefix}/{label}/content-key")),
        example(&format!("{prefix}/{label}/upload-seed")),
    )
}

/// The merge statement over two rotations of the builder, signed by both.
fn merge_statement(
    prefix: &str,
    space: EventId,
    rotations: [(EventId, &str); 2],
) -> (MergeStatement, RotationSet) {
    let state = RotationSet::new(rotations.map(|(id, _)| id)).unwrap();
    let ordered: Vec<&str> = state
        .ids()
        .iter()
        .map(|id| rotations.iter().find(|(r, _)| r == id).unwrap().1)
        .collect();
    let ks: Vec<[u8; 32]> = ordered.iter().map(|l| secrets(prefix, l).0).collect();
    let ws: Vec<[u8; 32]> = ordered.iter().map(|l| secrets(prefix, l).1).collect();
    let k = state_secret(SecretKind::Content, &space, &state, &ks).unwrap();
    let w = state_secret(SecretKind::Upload, &space, &state, &ws).unwrap();
    let seeds: Vec<[u8; 32]> = ws.iter().map(|w| *upload_key(w).seed).collect();
    let statement = MergeStatement::sign(
        space,
        state.clone(),
        read_credential(&k).public,
        upload_key(&w).public,
        &seeds,
    );
    (statement, state)
}

#[test]
fn credentials() {
    const PREFIX: &str = "storage/credentials";
    let c = family("credentials");
    let history = History::of(&c["events"]);
    let log = &history.log;
    let name = |id: EventId| history.name(id).to_string();
    let steps = c["steps"].as_array().unwrap();
    // Every step comes before W's fork.
    let before_fork = history.view_without(&["W forks"]);
    let order = log.canonical_in(&before_fork);
    let forks = fork_points(log, &order, |_| true);
    assert!(forks.is_empty());

    let mut entries = Entries::default();
    let add = |entries: &mut Entries, label: &str| {
        let id = history.id(label);
        assert!(
            entries
                .add_rotation(log, id, Source::Rotation, &forks)
                .unwrap()
        );
        // The builder's content key gives the entry's read key.
        let (k, w) = secrets(PREFIX, if id == log.id() { "genesis" } else { label });
        let entry = entries.entries().last().unwrap();
        assert_eq!(entry.read, read_credential(&k).public, "{label}");
        assert_eq!(entry.upload, upload_key(&w).public, "{label}");
    };
    let check = |entries: &Entries, step: &Json| {
        assert_eq!(describe(entries, name), step["entries"], "{}", step["step"]);
    };
    add(&mut entries, "P creates the space");
    check(&entries, &steps[0]);
    for label in ["P grants W write", "P grants V write", "P rotates"] {
        add(&mut entries, label);
    }
    check(&entries, &steps[1]);
    add(&mut entries, "W rotates, racing its removal");
    check(&entries, &steps[2]);
    add(&mut entries, "P removes W");
    check(&entries, &steps[3]);

    let space = log.id();
    let removal = history.id("P removes W");
    let racing = history.id("W rotates, racing its removal");
    let (statement, _) = merge_statement(
        PREFIX,
        space,
        [
            (removal, "P removes W"),
            (racing, "W rotates, racing its removal"),
        ],
    );
    let verdict = outcome(entries.merge(log, &space, &statement.encode()));
    assert_eq!(verdict, text(&steps[4]["verdict"]));
    check(&entries, &steps[4]);

    for (index, label) in [
        (5, "P0 asks to keep the removal's entry live"),
        (6, "P0 asks to keep V's rotation live"),
    ] {
        if index == 6 {
            add(&mut entries, "V rotates, citing W's rotation");
        }
        let request = log.event(history.id(label)).unwrap();
        assert_eq!(request.signed(), hex(&steps[index]["request"]), "{label}");
        entries.execute_event(log, request, None).unwrap();
        check(&entries, &steps[index]);
    }

    // The cap, lowered to 2: a superseded entry is evicted.
    let cap = &c["cap"];
    let mut small = Entries::new(2);
    for label in [
        "P creates the space",
        "P rotates",
        "W rotates, racing its removal",
    ] {
        add(&mut small, label);
    }
    assert_eq!(cap["cap"], small.cap());
    assert_eq!(describe(&small, name), cap["entries"]);
    assert_eq!(Json::from(reports(&small)), cap["reports"]);
    // Every entry maximal: the new one is added retired.
    let maximal = &cap["every_entry_maximal"];
    let mut full = Entries::new(1);
    for label in ["W rotates, racing its removal", "P removes W"] {
        let id = history.id(label);
        full.add_rotation(log, id, Source::Rotation, &forks)
            .unwrap();
    }
    assert_eq!(maximal["cap"], full.cap());
    assert_eq!(describe(&full, name), maximal["entries"]);
    assert_eq!(Json::from(reports(&full)), maximal["reports"]);

    // A fork: W signs two events at one sequence number.
    let fork = &c["fork"];
    assert_eq!(
        log.event(history.id("W forks")).unwrap().signed(),
        hex(&fork["event"])
    );
    let all = fork_points(log, &log.canonical(), |_| true);
    let w = device(PREFIX, "W");
    assert_eq!(all.fork_point(&w), Some(log.event(racing).unwrap().seq()));
    let mut forked = Entries::default();
    for label in [
        "P creates the space",
        "P rotates",
        "W rotates, racing its removal",
        "P removes W",
    ] {
        forked
            .add_rotation(log, history.id(label), Source::Rotation, &all)
            .unwrap();
    }
    forked.fork(log, &all);
    assert_eq!(describe(&forked, name), fork["entries"]);
    // Its entry retires by the fork even if it was live.
    let mut late = Entries::default();
    late.add_rotation(log, racing, Source::Rotation, &forks)
        .unwrap();
    assert!(late.entries()[0].is_live());
    late.fork(log, &all);
    assert!(!late.entries()[0].is_live());
}

fn reports(entries: &Entries) -> Vec<&'static str> {
    use frasil_base::errors::Class;
    entries.reports().iter().map(|c| c.name()).collect()
}

#[test]
fn merge_cap() {
    let m = family("merge_cap");
    let space = MergeSpace::new();
    let name = |id: EventId| space.name(id).to_string();
    let honest = hex(&m["statements"]["honest"]);
    let junk: Vec<Vec<u8>> = m["statements"]["junk"]
        .as_array()
        .unwrap()
        .iter()
        .map(hex)
        .collect();

    // An honest merge entry proved by a present, then five junk statements
    // for its state: the oldest unproved goes first.
    let per = &m["per_state"];
    let mut entries = space.entries(CREDENTIAL_CAP);
    entries.merge(&space, &space.genesis, &honest).unwrap();
    let statement = MergeStatement::read(&honest).unwrap();
    let k: [u8; 32] = array(&family("merge_statement")["content_key"]);
    let read = read_credential(&k);
    assert_eq!(read.public, statement.read);
    let (traffic, _) = bindings();
    let shown = presented(
        &traffic,
        space.genesis.as_bytes(),
        Credential::Read.code(),
        &read.public,
    );
    let proof = prove(&read.seed, &shown);
    let connection = Connection {
        binding: traffic,
        purpose: Purpose::SpaceTraffic,
        importing: false,
    };
    let present = Present {
        credential: 1,
        space: space.genesis,
        public: read.public,
        proof: &proof,
    };
    let rights = entries.present(&present, &connection, None).unwrap();
    assert_eq!(rights, Rights::FETCH_AND_LIVE);
    assert_eq!(per["present"], "fetch, live");
    let verdicts: Vec<&str> = junk
        .iter()
        .map(|j| outcome(entries.merge(&space, &space.genesis, j)))
        .collect();
    assert_eq!(Json::from(verdicts), per["junk_verdicts"]);
    assert_eq!(describe(&entries, name), per["entries"]);

    // Under a full space cap, a junk merge entry goes to make room for an
    // honest one.
    let cap = &m["space_cap"];
    let live = space.entries(CREDENTIAL_CAP).live().count();
    let mut small = space.entries(live + 1);
    assert_eq!(cap["cap"], small.cap());
    small.merge(&space, &space.genesis, &junk[0]).unwrap();
    let honest_verdict = outcome(small.merge(&space, &space.genesis, &honest));
    assert_eq!(honest_verdict, text(&cap["honest"]));
    assert_eq!(describe(&small, name), cap["entries"]);
    assert_eq!(Json::from(reports(&small)), cap["reports"]);
}

/// The recovery entries as the vectors describe them.
fn describe_recovery(entries: &Entries) -> Json {
    Json::from(
        entries
            .recovery()
            .iter()
            .map(|e| {
                serde_json::json!({
                    "key": frasil_testkit::hex::encode(e.key),
                    "status": status(e.status),
                })
            })
            .collect::<Vec<_>>(),
    )
}

/// A registration's verdict as the vectors write it, and its code.
fn registration(result: Result<(), Refusal>) -> (&'static str, Option<&'static str>) {
    use frasil_base::errors::Class;
    match result {
        Ok(()) => ("accepted", None),
        Err(Refusal::Class(class)) => (class.name(), class.code().map(Code::name)),
        Err(Refusal::Code(Code::CredentialRefused)) => {
            ("CredentialRefused", Some(Code::CredentialRefused.name()))
        }
        Err(other) => panic!("{other:?}"),
    }
}

/// No event of the space is in another's past: the recovery entries' steps
/// read no ancestry.
struct Unordered;

impl Ancestry for Unordered {
    fn precedes(&self, _: EventId, _: EventId) -> bool {
        false
    }
}

#[test]
fn recovery_entries() {
    let r = family("recovery_entries");
    let space = EventId(array(&r["space"]));
    let fetch: [u8; 32] = array(&r["fetch_key"]);
    let fetch_seed: [u8; 32] = array(&r["fetch_seed"]);
    assert_eq!(ed25519_public(&fetch_seed), fetch);
    let junk_seed = |n: u32| example(&format!("storage/recovery/junk/{n}"));
    let junk = |n: u32| ed25519_public(&junk_seed(n));
    let store = Rights::STORE_AND_RELEASE;
    let steps = r["steps"].as_array().unwrap();
    let mut entries = Entries::default();
    let step = |entries: &mut Entries, index: usize, key: [u8; 32], rights: Rights| {
        let s = &steps[index];
        assert_eq!(array::<32>(&s["key"]), key, "{}", s["step"]);
        let (verdict, code) = registration(entries.register(&key, rights));
        assert_eq!(verdict, text(&s["verdict"]), "{}", s["step"]);
        assert_eq!(code, s.get("code").and_then(Json::as_str), "{}", s["step"]);
        assert_eq!(describe_recovery(entries), s["entries"], "{}", s["step"]);
    };
    step(&mut entries, 0, fetch, store);
    step(&mut entries, 1, fetch, store);
    let mut invalid = [0u8; 32];
    invalid[0] = 1;
    step(&mut entries, 2, invalid, store);
    step(&mut entries, 3, junk(0), Rights::FETCH_AND_LIVE);
    step(&mut entries, 4, junk(1), store);

    // A credentials request with a keep list alone; a key registered after
    // the peer's first sight of it stays live, while the unnamed one retires.
    let request = &r["request"];
    let event = frasil_events::decode(&hex(&request["event"])).unwrap();
    assert_eq!(event.unverified_body(), hex(&request["body"]));
    let keep: Vec<[u8; 32]> = request["keep"]
        .as_array()
        .unwrap()
        .iter()
        .map(array)
        .collect();
    assert_eq!(
        StorageBody::read(event.unverified_body()).unwrap(),
        StorageBody::Credentials {
            live: None,
            recovery: Some(keep.clone())
        }
    );
    let seen = entries.first_sight();
    step(&mut entries, 5, junk(2), store);
    entries.execute(&Unordered, event.id(), None, Some(&keep), Some(seen));
    assert_eq!(describe_recovery(&entries), steps[6]["entries"]);

    // Presents of fetch keys.
    check_presents(&mut entries, space, &r["presents"], |_| None);

    step(&mut entries, 7, junk(1), store);
    let bulk = &steps[8];
    let keys: Vec<Json> = (3..65)
        .map(|n| Json::from(frasil_testkit::hex::encode(junk(n))))
        .collect();
    assert_eq!(Json::from(keys), bulk["keys"]);
    for n in 3..65 {
        assert_eq!(entries.register(&junk(n), store), Ok(()));
    }
    let live = entries
        .recovery()
        .iter()
        .filter(|e| e.status == EntryStatus::Live)
        .count();
    assert_eq!(bulk["live"], live);
    assert_eq!(describe_recovery(&entries), bulk["entries"]);
    step(&mut entries, 9, junk(65), store);
    step(&mut entries, 10, fetch, store);
    assert_eq!(steps.len(), 11);

    // Credentials request bodies.
    for case in r["bodies"].as_array().unwrap() {
        let body = hex(&case["body"]);
        let result = StorageBody::read(&body);
        assert_eq!(
            outcome(result.clone()),
            text(&case["verdict"]),
            "{}",
            case["name"]
        );
        if let Ok(read) = result {
            assert_eq!(read.encode(), body, "{}", case["name"]);
        }
    }
    let _ = PeersClass::RecoveryEntriesFull;
}

#[test]
fn a_retired_import_entry_goes_live_for_its_importer() {
    let history = History::of(&family("skeleton")["events"]);
    let log: &Log = &history.log;
    let genesis = log.id();
    let mut entries = Entries::default();
    entries
        .add_rotation(log, genesis, Source::Import, &ForkPoints::default())
        .unwrap();
    assert!(!entries.entries()[0].is_live());
    let upload = upload_key(&example("storage/genesis/upload-seed"));
    assert_eq!(entries.entries()[0].upload, upload.public);
    let (traffic, _) = bindings();
    let shown = presented(&traffic, genesis.as_bytes(), 2, &upload.public);
    let proof = prove(&upload.seed, &shown);
    let present = Present {
        credential: 2,
        space: genesis,
        public: upload.public,
        proof: &proof,
    };
    let mut connection = Connection {
        binding: traffic,
        purpose: Purpose::SpaceTraffic,
        importing: false,
    };
    assert_eq!(
        entries.present(&present, &connection, None),
        Err(Refusal::Class(PeersClass::RetiredCredential))
    );
    connection.importing = true;
    assert_eq!(
        entries.present(&present, &connection, None),
        Ok(Rights::STORE_AND_RELEASE)
    );
    assert!(entries.entries()[0].is_live());
    // A named entry the peer lacks is skipped; the named one stays live.
    let name = EntryName {
        state: RotationSet::single(genesis),
        read: entries.entries()[0].read,
    };
    assert!(entries.find(&name).is_some());
    entries.erase();
    assert_eq!(
        entries.present(&present, &connection, None),
        Err(Refusal::Code(Code::Erased))
    );
}

/// peers.md, 3.7 Presenting a credential: of the entries whose key is
/// `public`, a live one is taken first. A writer's own rotation that copies
/// an honest rotation's keys, retired by a fork of its chain, never shadows
/// the honest entry added after it. And 2.2: a proof holds while its entry
/// is live.
#[test]
fn a_retired_entry_with_copied_keys_shadows_no_live_one() {
    let space = EventId([7; 32]);
    let (read_seed, upload_seed) = ([11u8; 32], [12u8; 32]);
    let (read, upload) = (ed25519_public(&read_seed), ed25519_public(&upload_seed));
    let (copy, honest) = (EventId([1; 32]), EventId([2; 32]));
    let mut entries = Entries::default();
    entries.add_rotation_keys(&Unordered, copy, read, upload, Source::Rotation, false);
    assert!(entries.retire(&EntryName {
        state: RotationSet::single(copy),
        read,
    }));
    entries.add_rotation_keys(&Unordered, honest, read, upload, Source::Rotation, false);
    let (traffic, _) = bindings();
    let connection = Connection {
        binding: traffic,
        purpose: Purpose::SpaceTraffic,
        importing: false,
    };
    let shown = presented(&traffic, space.as_bytes(), 1, &read);
    let read_proof = prove(&read_seed, &shown);
    let read_present = Present {
        credential: 1,
        space,
        public: read,
        proof: &read_proof,
    };
    let shown = presented(&traffic, space.as_bytes(), 2, &upload);
    let upload_proof = prove(&upload_seed, &shown);
    let upload_present = Present {
        credential: 2,
        space,
        public: upload,
        proof: &upload_proof,
    };
    assert_eq!(
        entries.present(&read_present, &connection, None),
        Ok(Rights::FETCH_AND_LIVE)
    );
    assert_eq!(
        entries.present(&upload_present, &connection, None),
        Ok(Rights::STORE_AND_RELEASE)
    );
    // The live entry is the one proved.
    assert!(!entries.entries()[0].proved);
    assert!(entries.entries()[1].proved);
    assert_eq!(
        entries.standing(Credential::Read, &read),
        Rights::FETCH_AND_LIVE
    );
    assert_eq!(
        entries.standing(Credential::Upload, &upload),
        Rights::STORE_AND_RELEASE
    );

    // Once the honest entry retires too, the read credential grants
    // catch-up and the upload key nothing.
    assert!(entries.retire(&EntryName {
        state: RotationSet::single(honest),
        read,
    }));
    assert_eq!(entries.standing(Credential::Read, &read), Rights::CATCH_UP);
    assert_eq!(
        entries.standing(Credential::Upload, &upload),
        Rights::default()
    );
    assert_eq!(
        entries.present(&upload_present, &connection, None),
        Err(Refusal::Class(PeersClass::RetiredCredential))
    );
    assert_eq!(
        entries.standing(Credential::Fetch, &[9; 32]),
        Rights::default()
    );
    assert_eq!(
        entries.standing(Credential::Pseudonym, &[9; 32]),
        Rights::ERASE
    );
    // An erased space grants nothing.
    entries.erase();
    assert_eq!(entries.standing(Credential::Read, &read), Rights::default());
    assert_eq!(
        entries.standing(Credential::Pseudonym, &[9; 32]),
        Rights::default()
    );
}
