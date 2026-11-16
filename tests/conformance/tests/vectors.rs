//! `peers.json`'s `credentials` and `decisions` families, run through the
//! peer service's store path: each event stored by a device over the
//! server binding, each request carried out by the peer's own sweep, on its
//! own timeline, and the entries read back from the peer, also after it
//! reopens its records. `frasil-peers` claims both families; these tests
//! prove that the service runs them as its rules say.

mod common;

use common::*;
use frasil_conformance::client::{Credential, PeerClient};
use frasil_conformance::history::{self, History, erase_space, example, family, object, stream};
use frasil_events::{EventId, Log, Placement};
use frasil_keys::RotationSet;
use frasil_keys::derive::{SecretKind, read_credential, state_secret, upload_key};
use frasil_peers::body::{EntryName, Restored, StorageBody};
use frasil_peers::merge::MergeStatement;
use frasil_relay::testing::{Options, START, TestPeer, spawn_with};
use frasil_relay::{Entry, EntryStatus, Execution, Settings};
use frasil_transport::messages::Merge;
use frasil_transport::peer::Purpose;
use frasil_units::body::{Compacts, Cover, Stub};
use serde_json::{Value as Json, json};
use std::sync::Arc;

const MONTH: u64 = 30 * 86_400;

fn status(status: EntryStatus) -> &'static str {
    match status {
        EntryStatus::Live => "live",
        EntryStatus::Retired => "retired",
    }
}

/// The entries as the vectors describe them. The storing connection
/// proved the genesis entry's upload key, which the vectors' peer never
/// saw presented: that entry's `proved` is read as the vectors' peer has
/// it.
fn describe(entries: &[Entry], history: &History, ours: &[[u8; 32]]) -> Json {
    Json::from(
        entries
            .iter()
            .map(|e| {
                json!({
                    "state": e.state.ids().iter().map(|&id| history.name(id).unwrap_or("?").to_owned()).collect::<Vec<_>>(),
                    "read": frasil_testkit::hex::encode(e.read),
                    "upload": frasil_testkit::hex::encode(e.upload),
                    "status": status(e.status),
                    "source": e.source.name(),
                    "proved": e.proved && !ours.contains(&e.upload),
                })
            })
            .collect::<Vec<_>>(),
    )
}

/// The merge statement over two rotations, signed with both upload seeds.
fn merge_statement(history: &History, rotations: [&str; 2]) -> MergeStatement {
    let space = history.space();
    let ids = rotations.map(|r| history.id(r));
    let state = RotationSet::new(ids).unwrap();
    let ordered: Vec<&str> = state
        .ids()
        .iter()
        .map(|id| rotations[ids.iter().position(|x| x == id).unwrap()])
        .collect();
    let prefix = &history.prefix;
    let ks: Vec<[u8; 32]> = ordered
        .iter()
        .map(|l| example(&format!("{prefix}/{l}/content-key")))
        .collect();
    let ws: Vec<[u8; 32]> = ordered
        .iter()
        .map(|l| example(&format!("{prefix}/{l}/upload-seed")))
        .collect();
    let k = state_secret(SecretKind::Content, &space, &state, &ks).unwrap();
    let w = state_secret(SecretKind::Upload, &space, &state, &ws).unwrap();
    let seeds: Vec<[u8; 32]> = ws.iter().map(|w| *upload_key(w).seed).collect();
    MergeStatement::sign(
        space,
        state,
        read_credential(&k).public,
        upload_key(&w).public,
        &seeds,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_run_through_the_store_path() {
    within(async {
        let c = family("credentials");
        let steps = c["steps"].as_array().unwrap();
        let history = History::credentials();
        let space = history.space();
        let directory = std::env::temp_dir().join(format!(
            "frasil-conformance-credentials-{}",
            frasil_testkit::hex::encode(*frasil_crypto::random_bytes::<8>().unwrap())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("peer.sqlite");
        let open = |path: &std::path::Path| -> Arc<dyn frasil_store::Store> {
            Arc::new(frasil_store::SqliteStore::open(path).unwrap())
        };
        let peer = spawn_with(Options {
            store: Some(open(&path)),
            ..frasil_conformance::options()
        })
        .await
        .unwrap();
        // The entries whose upload keys the device presents: their proved
        // marks are this run's, not the vectors'.
        let ours = ["P creates the space", "P removes W"].map(|rotation| {
            frasil_crypto::primitives::ed25519_public(&history.upload_seed(rotation))
        });
        let check = |peer: &TestPeer, step: &Json| {
            let entries = peer.peer.entries(space.as_bytes()).unwrap();
            assert_eq!(
                describe(&entries, &history, &ours),
                step["entries"],
                "{}",
                step["step"]
            );
        };

        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        check(&peer, &steps[0]);
        store_all(
            &mut device,
            space,
            history.events(&[
                "P0: root",
                "P grants W write",
                "P grants V write",
                "P rotates",
            ]),
        )
        .await;
        check(&peer, &steps[1]);
        store_all(
            &mut device,
            space,
            history.events(&["W rotates, racing its removal"]),
        )
        .await;
        check(&peer, &steps[2]);
        store_all(&mut device, space, history.events(&["P removes W"])).await;
        check(&peer, &steps[3]);

        // A merge statement over the removal and W's racing rotation.
        let statement = merge_statement(&history, ["P removes W", "W rotates, racing its removal"]);
        let request = device.request();
        let merge = Merge {
            request,
            statement: statement.encode(),
        }
        .encode()
        .unwrap();
        assert_eq!(device.request_answer(request, &merge).await, Ok(None));
        assert_eq!(steps[4]["verdict"], "accepted");
        check(&peer, &steps[4]);

        // P0's credentials requests, on its administration connection: with
        // one administrator, each is stable at the peer as soon as it is
        // stored, and the peer carries it out.
        let mut admin = connect(&peer, Binding::WebSocket, Purpose::Administration).await;
        admin
            .present_pseudonym(space, &history.seed("P0"), &history.device_id("P0"))
            .await
            .unwrap();
        let first = "P0 asks to keep the removal's entry live";
        assert_eq!(history.signed(first), history::hex(&steps[5]["request"]));
        assert!(
            admin
                .store_one(space, &history.signed(first), DEADLINE)
                .await
        );
        assert_eq!(
            peer.peer
                .outcome(space.as_bytes(), history.id(first).as_bytes()),
            Some(Execution::Execute)
        );
        check(&peer, &steps[5]);
        // The request retired the genesis's entry, and the store right the
        // device held under it (peers.md, 3.6 Retirement and the cap,
        // "Connections"): it stores under the removal's, which it keeps.
        assert_eq!(
            device
                .store_answer(
                    space,
                    &history.signed("V rotates, citing W's rotation"),
                    DEADLINE
                )
                .await,
            Some(Err("not_authorized".into()))
        );
        device
            .present(
                space,
                Credential::Upload,
                &history.upload_seed("P removes W"),
            )
            .await
            .expect("the removal's upload key");
        store_all(
            &mut device,
            space,
            history.events(&["V rotates, citing W's rotation"]),
        )
        .await;
        let second = "P0 asks to keep V's rotation live";
        assert!(
            admin
                .store_one(space, &history.signed(second), DEADLINE)
                .await
        );
        check(&peer, &steps[6]);

        // The peer reopens its records: the journal replays to the same
        // entries.
        let before = peer.peer.entries(space.as_bytes()).unwrap();
        admin.close().await;
        device.close().await;
        peer.shutdown().await;
        let reopened = spawn_with(Options {
            store: Some(open(&path)),
            ..frasil_conformance::options()
        })
        .await
        .unwrap();
        assert_eq!(reopened.peer.entries(space.as_bytes()).unwrap(), before);
        check(&reopened, &steps[6]);
        reopened.shutdown().await;
        std::fs::remove_dir_all(directory).unwrap();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fork_retires_its_authors_entries_at_the_peer() {
    within(async {
        let fork = &family("credentials")["fork"];
        let mut history = History::credentials();
        let space = history.space();
        let peer = peer(frasil_conformance::settings()).await;
        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        store_all(
            &mut device,
            space,
            history.events(&[
                "P0: root",
                "P grants W write",
                "P grants V write",
                "P rotates",
                "W rotates, racing its removal",
                "P removes W",
            ]),
        )
        .await;
        let racing = history.id("W rotates, racing its removal");
        let live = |peer: &TestPeer| {
            peer.peer
                .entries(space.as_bytes())
                .unwrap()
                .iter()
                .find(|e| e.state.ids() == [racing])
                .unwrap()
                .is_live()
        };
        assert!(live(&peer));
        // W signs a second event at its racing rotation's `seq`: the peer
        // stores it as fork evidence, answers `conflict`, and never
        // acknowledges it.
        history.force_next("W", 1, None);
        let forked = history.unit(
            "W",
            "W signs a second event at its seq 1",
            stream("fork"),
            Vec::new(),
            None,
            &["P rotates"],
        );
        assert_eq!(
            device.store_answer(space, &forked, DEADLINE).await,
            Some(Err("conflict".into()))
        );
        assert!(peer.peer.keeps(
            space.as_bytes(),
            history.id("W signs a second event at its seq 1").as_bytes()
        ));
        assert!(!live(&peer));
        // Each entry the vectors list after the fork is the peer's.
        let entries = peer.peer.entries(space.as_bytes()).unwrap();
        for expected in fork["entries"].as_array().unwrap() {
            let found = entries
                .iter()
                .find(|e| frasil_testkit::hex::encode(e.read) == expected["read"])
                .unwrap();
            assert_eq!(status(found.status), expected["status"], "{expected}");
        }
        peer.shutdown().await;
    })
    .await;
}

// -- decisions

/// A history stored at the peer's first sights, all at [`START`], by a
/// founder that holds the store right.
struct Run {
    peer: TestPeer,
    history: History,
    device: PeerClient,
}

impl Run {
    async fn new(settings: Settings, history: History, events: Vec<Vec<u8>>) -> Self {
        let peer = peer(settings).await;
        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        let space = history.space();
        // One message: the peer acknowledges what it stores, and holds the
        // changes no space event names yet pending.
        device.store(space, events[1..].to_vec(), DEADLINE).await;
        // Units may already be reclaimed or collected, at the first sight.
        for signed in &events {
            let event = frasil_events::decode(signed).unwrap();
            if event.kind() == frasil_events::kind::UNIT {
                continue;
            }
            let id = event.id();
            assert!(
                peer.peer.keeps(space.as_bytes(), id.as_bytes()),
                "{:?} is kept",
                history.name(id)
            );
        }
        Self {
            peer,
            history,
            device,
        }
    }

    fn space(&self) -> EventId {
        self.history.space()
    }

    async fn store(&mut self, name: &str) {
        let space = self.space();
        let signed = self.history.signed(name);
        assert!(
            self.device.store_one(space, &signed, DEADLINE).await,
            "{name} is stored"
        );
    }

    /// Validity and stability at the peer now, and the request's outcome
    /// once the timeline is `elapsed` past the first sights.
    async fn judge(&self, name: &str, elapsed: u64) -> (bool, bool, Option<Execution>) {
        let id = self.history.id(name);
        let space = self.space();
        // An erasure of the space stable when stored is carried out at
        // once, and leaves a tombstone: it was valid and stable then.
        let (stable, valid) = self
            .peer
            .peer
            .stability(space.as_bytes(), id.as_bytes())
            .or_else(|| {
                self.peer
                    .peer
                    .erased(space.as_bytes())
                    .then_some((true, true))
            })
            .unwrap();
        self.peer.set_time(START + elapsed).await;
        let outcome = self
            .peer
            .peer
            .outcome(self.space().as_bytes(), id.as_bytes());
        (valid, stable, outcome)
    }

    async fn end(self) {
        self.device.close().await;
        self.peer.shutdown().await;
    }
}

fn settings(timeout: u64, retention: u64) -> Settings {
    Settings {
        erasure_timeout: timeout,
        release_retention: retention,
        ..frasil_conformance::settings()
    }
}

fn execution(outcome: Option<Execution>) -> &'static str {
    match outcome {
        Some(Execution::Void) => "Void",
        Some(Execution::Execute) => "Execute",
        Some(Execution::Wait) => "Wait",
        None => "none",
    }
}

fn u(value: &Json) -> u64 {
    value.as_u64().unwrap()
}

fn b(value: &Json) -> bool {
    value.as_bool().unwrap()
}

/// The credentials history, every event but `W forks`.
fn credentials_events(history: &History) -> Vec<Vec<u8>> {
    history
        .order
        .iter()
        .filter(|n| *n != "W forks")
        .map(|n| history.signed(n))
        .collect()
}

/// A request in a space with one administrator, P0: stable as soon as it
/// is stored.
async fn stable_request(timeout: u64, body: StorageBody) -> (Run, String) {
    let history = History::credentials();
    let events = credentials_events(&history);
    let mut run = Run::new(settings(timeout, MONTH), history, events).await;
    // P0's first request retired the genesis's entry: the store right goes
    // on under the current state's upload key.
    present_current(&mut run.device, &run.history).await;
    let name = "P0's request".to_owned();
    run.history.storage("P0", &name, &body, &[]);
    run.store(&name).await;
    (run, name)
}

#[tokio::test(flavor = "multi_thread")]
async fn erasure_decisions_run_through_the_peer() {
    within(async {
        for row in family("decisions")["erasure"].as_array().unwrap() {
            let (valid, stable, elapsed, timeout) = (
                b(&row["valid"]),
                b(&row["stable"]),
                u(&row["elapsed"]),
                u(&row["timeout"]),
            );
            let (run, name) = if !valid {
                // A1 erases while P removes A, concurrently: void at the
                // peer.
                let history = History::skeleton();
                let events = history.all();
                let run = Run::new(settings(timeout, MONTH), history, events).await;
                (run, "A1 erases the space".to_owned())
            } else if stable {
                stable_request(timeout, erase_space()).await
            } else {
                // A's lowering waits to settle, and A never acknowledges
                // P0's erasure: not stable until T.
                let history = History::skeleton();
                let events = history.all();
                let run = Run::new(settings(timeout, MONTH), history, events).await;
                (run, "P0 erases the space".to_owned())
            };
            let (is_valid, is_stable, outcome) = run.judge(&name, elapsed).await;
            assert_eq!(is_valid, valid, "{row}");
            if valid {
                assert_eq!(is_stable, stable, "{row}");
            }
            assert_eq!(execution(outcome), row["outcome"], "{row}");
            run.end().await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_request_decisions_run_through_the_peer() {
    within(async {
        for row in family("decisions")["credentials_request"]
            .as_array()
            .unwrap()
        {
            let (valid, stable, elapsed, timeout) = (
                b(&row["valid"]),
                b(&row["stable"]),
                u(&row["elapsed"]),
                u(&row["timeout"]),
            );
            let (run, name) = if !valid {
                // A1 asks for credentials concurrently with its removal. The
                // history stops before P0's erasure of the space, which T
                // would carry out, leaving only a tombstone to judge.
                let mut history = History::skeleton();
                let events = history.through("P0 asks for the current credentials");
                let genesis = history.space();
                let read = read_credential(&history.content_key("P creates the space")).public;
                let body = StorageBody::Credentials {
                    live: Some(vec![EntryName {
                        state: RotationSet::single(genesis),
                        read,
                    }]),
                    recovery: None,
                };
                history.storage("A1", "A1 asks for credentials", &body, &[]);
                let mut run = Run::new(settings(timeout, MONTH), history, events).await;
                run.store("A1 asks for credentials").await;
                (run, "A1 asks for credentials".to_owned())
            } else if stable {
                let history = History::credentials();
                let events = credentials_events(&history);
                let run = Run::new(settings(timeout, MONTH), history, events).await;
                (run, "P0 asks to keep the removal's entry live".to_owned())
            } else {
                // Before P0's erasure of the space, which T carries out too.
                let history = History::skeleton();
                let events = history.through("P0 asks for the current credentials");
                let run = Run::new(settings(timeout, MONTH), history, events).await;
                (run, "P0 asks for the current credentials".to_owned())
            };
            let (is_valid, is_stable, outcome) = run.judge(&name, elapsed).await;
            assert_eq!(is_valid, valid, "{row}");
            if valid && elapsed == 0 {
                assert_eq!(is_stable, stable, "{row}");
            }
            assert_eq!(execution(outcome), row["outcome"], "{row}");
            run.end().await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn release_decisions_run_through_the_peer() {
    within(async {
        let notes = stream("notes");
        // W's unit is a parent of W's release, so a reclaim keeps it as an
        // event alone (peers.md, "Release and restore"); V's unit, which no
        // event outside the stream names, shows whether the peer reclaimed.
        let named = "W writes to the notes stream";
        let unit = "V writes to the notes stream";
        let release_name = "W releases the notes stream";
        for row in family("decisions")["release"].as_array().unwrap() {
            let (released, stable, elapsed, retention, timeout) = (
                b(&row["released"]),
                b(&row["stable"]),
                u(&row["elapsed"]),
                u(&row["retention"]),
                u(&row["timeout"]),
            );
            let mut history = History::skeleton();
            let mut events = if !released {
                // W's restore wins: not released. The history stops before
                // P0's erasure of the space, which the retention's wait
                // would carry out.
                history.through("W restores the notes stream")
            } else if stable {
                // P0 and A1 each hold the release in an event's past.
                history.through("P0 acknowledges")
            } else {
                history.through(release_name)
            };
            let alone = history.unit("V", unit, notes, Vec::new(), None, &[named]);
            let at = events
                .iter()
                .position(|signed| *signed == history.signed(named))
                .expect("W's unit");
            events.insert(at + 1, alone);
            let run = Run::new(settings(timeout, retention), history, events).await;
            let space = run.space();
            assert_eq!(run.peer.peer.released(space.as_bytes(), &notes), released);
            let (_, is_stable, _) = run.judge(release_name, 0).await;
            if released {
                assert_eq!(is_stable, stable, "{row}");
            }
            run.peer.set_time(START + elapsed).await;
            let unit_id = run.history.id(unit);
            let kept = run.peer.peer.keeps(space.as_bytes(), unit_id.as_bytes());
            let outcome = if kept { "Keep" } else { "Reclaim" };
            assert_eq!(outcome, row["outcome"], "{row}");
            run.end().await;
        }
    })
    .await;
}

/// A local log of a history's events, for the heights a stub carries.
fn log_of(events: &[Vec<u8>]) -> Log {
    let mut log: Option<Log> = None;
    for signed in events {
        let event = frasil_events::decode(signed).unwrap();
        match &mut log {
            None => log = Some(Log::new(event).unwrap()),
            Some(log) => {
                assert!(matches!(log.place(event).unwrap(), Placement::Placed(_)));
            }
        }
    }
    log.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn collection_decisions_run_through_the_peer() {
    within(async {
        for row in family("decisions")["collection"].as_array().unwrap() {
            let (cancelled, stable, elapsed, timeout) = (
                b(&row["cancelled"]),
                b(&row["stable"]),
                u(&row["elapsed"]),
                u(&row["timeout"]),
            );
            let mut history = History::credentials();
            let mut events = credentials_events(&history);
            // V writes two units of a stream; P compacts them into a
            // snapshot unit whose cover holds both and whose stubs carry
            // the one it cites.
            let notes = stream("collected");
            let base = "P0 asks to keep V's rotation live";
            events.push(history.unit("V", "V's first unit", notes, Vec::new(), None, &[base]));
            events.push(history.unit("V", "V's second unit", notes, Vec::new(), None, &[]));
            let log = log_of(&events);
            let second = history.id("V's second unit");
            let stub = frasil_units::compaction::stub_of(&log, second).unwrap();
            let (stored_object, locator) =
                object(history::object_id("snapshot"), 10, history.space());
            let _ = stored_object;
            let compacts = Compacts {
                object: locator,
                covers: vec![Cover {
                    writer: history.device_id("V"),
                    unit: second,
                }],
                stubs: vec![Stub {
                    stream: None,
                    ..stub
                }],
            };
            events.push(history.unit(
                "P",
                "P's snapshot unit",
                notes,
                vec![locator],
                Some(compacts),
                &["V's second unit"],
            ));
            let snapshot = history.id("P's snapshot unit");
            if cancelled {
                events.push(history.storage(
                    "V",
                    "V restores the snapshot unit",
                    &StorageBody::Restore(Restored::Snapshot(*snapshot.as_bytes())),
                    &["P's snapshot unit"],
                ));
            }
            if stable {
                let mut parents = vec!["P's snapshot unit"];
                if cancelled {
                    parents.push("V restores the snapshot unit");
                }
                events.push(history.storage(
                    "P0",
                    "P0 acknowledges the snapshot unit",
                    &StorageBody::Ack,
                    &parents,
                ));
            }
            let run = Run::new(settings(timeout, MONTH), history, events).await;
            let space = run.space();
            let (_, is_stable, _) = run.judge("P's snapshot unit", 0).await;
            assert_eq!(is_stable, stable, "{row}");
            run.peer.set_time(START + elapsed).await;
            let first = run.history.id("V's first unit");
            let kept = run.peer.peer.keeps(space.as_bytes(), first.as_bytes())
                && run.peer.peer.keeps(space.as_bytes(), second.as_bytes());
            let outcome = if kept { "Keep" } else { "Collect" };
            assert_eq!(outcome, row["outcome"], "{row}");
            if !kept {
                assert!(!run.peer.peer.keeps(space.as_bytes(), first.as_bytes()));
                assert!(!run.peer.peer.keeps(space.as_bytes(), second.as_bytes()));
                assert!(run.peer.peer.keeps(space.as_bytes(), snapshot.as_bytes()));
            }
            run.end().await;
        }
    })
    .await;
}
