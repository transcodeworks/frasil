//! `ext-libraries.json`'s `attachments`, `ledgers`, `import` and
//! `held_objects` families,
//! run through the peer's own code: [`Libraries`] for attaching and the
//! ledgers, with the vectors' usage figures; and the peer's store path
//! ([`Core`]) for the import, its events stored by a connection that
//! `LibraryAttach` accepted, and the vectors' proof presented over the
//! vectors' `binding`. `library_attach`'s frames are read by the peer's own
//! framing too.

use super::*;
use crate::config::Settings;
use crate::records::Records;
use crate::state::{Core, Grant, On};
use frasil_base::time::Reading;
use frasil_crypto::primitives::{ed25519_public, sha256};
use frasil_libraries::{Issuer, LibraryAttach};
use frasil_peers::proof::Purpose as ConnectionPurpose;
use frasil_testkit::hex;
use frasil_transport::codes::Right;
use frasil_transport::messages::Present;
use serde_json::Value as Json;
use std::sync::Arc;

const FILE: &str = "ext-libraries.json";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex")
}

fn array<const N: usize>(value: &Json) -> [u8; N] {
    bytes(value).try_into().expect("its length")
}

fn u(value: &Json) -> u64 {
    value.as_u64().expect("a number")
}

fn parameters() -> Json {
    family("parameters")
}

fn issuers() -> TrustedIssuers {
    TrustedIssuers::new([array::<32>(&parameters()["issuer"])]).unwrap()
}

fn reading(timeline: u64, wall: u64) -> Reading {
    Reading {
        timeline,
        wall: Some(wall),
        run: 1,
    }
}

fn library(name: &str) -> LibraryId {
    LibraryId::new(name).unwrap()
}

fn verdict(result: &Result<(), LibraryClass>) -> Json {
    match result {
        Ok(()) => serde_json::json!({"verdict": "attached"}),
        Err(class) => serde_json::json!({
            "verdict": format!("{class:?}"),
            "code": class.code(),
            "status": class.status().unwrap(),
        }),
    }
}

/// The days since 1970-01-01 of a `YYYY-MM-DD` day.
fn days_of(day: &str) -> u64 {
    let parts: Vec<i64> = day.split('-').map(|p| p.parse().unwrap()).collect();
    let (y, m, d) = (parts[0] - i64::from(parts[1] <= 2), parts[1], parts[2]);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).unwrap()
}

/// The peer the `attachments` family runs on: one trusted issuer, and the
/// libraries `project:7c1f9e2a0b4d4e8f` with quota 1,000 and
/// `personal:9a4e01` with quota 100.
struct Run {
    libraries: Libraries,
    usage: BTreeMap<EventId, u64>,
}

impl Run {
    fn new() -> Self {
        let mut libraries = Libraries::new(LibrarySettings {
            issuers: issuers(),
            ..LibrarySettings::default()
        });
        for (name, quota) in [("project:7c1f9e2a0b4d4e8f", 1000), ("personal:9a4e01", 100)] {
            libraries
                .update(
                    &library(name),
                    LibraryUpdate {
                        quota: Some(Some(quota)),
                        ..LibraryUpdate::default()
                    },
                )
                .unwrap();
        }
        Self {
            libraries,
            usage: BTreeMap::new(),
        }
    }

    /// ext-libraries.md, 3.3 Attaching, as the peer's store path runs it:
    /// the check; the ticket spent; a create's genesis stored first, or
    /// `NotAuthorized` with the ticket spent; then the record.
    fn attach(&mut self, step: &Json) -> Result<(), LibraryClass> {
        let purpose = Purpose::from_name(step["purpose"].as_str().unwrap()).unwrap();
        let space = EventId(array(&step["space"]));
        let signed = bytes(&step["ticket"]);
        let usage = self.usage.clone();
        let usage_of = |id: &EventId| usage.get(id).copied().unwrap_or(0);
        let request = Request {
            purpose,
            space,
            signed: &signed,
            wall: Some(u(&step["now"])),
            hosted: self.usage.contains_key(&space),
            store_right: step["store_right"].as_bool().unwrap_or(false),
        };
        let ticket = self.libraries.check(&request, &usage_of)?;
        self.libraries.spend(&ticket);
        if step["first_stored_is_genesis"] == Json::Bool(false) {
            return Err(LibraryClass::NotAuthorized);
        }
        let at = reading(u(&step["reading"]), u(&step["now"]));
        self.libraries
            .attach(space, &ticket.library, Some(ticket.id), at);
        if purpose != Purpose::Move {
            self.usage
                .insert(space, step["used_bytes"].as_u64().unwrap_or(0));
        }
        Ok(())
    }

    fn recorded(&self) -> Json {
        let mut map = serde_json::Map::new();
        for (space, attachment) in self.libraries.attachments() {
            map.insert(
                hex::encode(space.as_bytes()),
                serde_json::json!({
                    "library": attachment.library.as_str(),
                    "ticket_id": attachment.ticket.map(hex::encode),
                    "at": attachment.at.timeline,
                }),
            );
        }
        Json::Object(map)
    }

    fn tickets_used(&self) -> Json {
        self.libraries
            .tickets_used()
            .keys()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .into()
    }
}

/// Runs `attachments`, and returns the peer it leaves.
fn attachments() -> Run {
    let mut run = Run::new();
    for step in family("attachments").as_array().unwrap() {
        let name = step["step"].as_str().unwrap();
        if name.contains("once the library's quota is 500") {
            run.libraries
                .update(
                    &library("personal:9a4e01"),
                    LibraryUpdate {
                        quota: Some(Some(500)),
                        ..LibraryUpdate::default()
                    },
                )
                .unwrap();
        }
        let result = run.attach(step);
        let got = verdict(&result);
        assert_eq!(got["verdict"], step["verdict"], "{name}");
        if result.is_err() {
            assert_eq!(got["code"], step["code"], "{name}");
            assert_eq!(got["status"], step["status"], "{name}");
        }
        assert_eq!(run.recorded(), step["recorded"], "{name}");
        assert_eq!(run.tickets_used(), step["tickets_used"], "{name}");
    }
    run
}

#[test]
fn attachments_follow_the_vectors() {
    attachments();
}

#[test]
fn ledgers_follow_the_vectors() {
    let run = attachments();
    let space_a = EventId(example("library/space-a"));
    let space_b = EventId(example("library/space-b"));
    let wall = |day: &str| days_of(day) * 86_400 + 3600;
    // Space B released 50 bytes, a snapshot covered 20 bytes, and one invite
    // drop of 1,200 bytes was kept; space A has one stream.
    let figures: BTreeMap<EventId, SpaceUsage> = [
        (
            space_b,
            SpaceUsage {
                stored_bytes: run.usage[&space_b],
                drops: 1,
                drop_bytes: 1200,
                released_bytes: 50,
                covered_bytes: 20,
                erasing_bytes: 0,
                streams: 3,
                last_store: Some(wall("2026-10-19")),
                held_bytes: 0,
                holds: 0,
            },
        ),
        (
            space_a,
            SpaceUsage {
                stored_bytes: run.usage[&space_a],
                streams: 1,
                last_store: Some(wall("2026-10-18")),
                ..SpaceUsage::default()
            },
        ),
    ]
    .into_iter()
    .collect();
    let usage_of = |space: &EventId| figures[space].clone();
    let ledgers = family("ledgers");
    for expected in ledgers["libraries"].as_array().unwrap() {
        let name = library(expected["library"].as_str().unwrap());
        let ledger = run.libraries.ledger(&name, &usage_of).unwrap();
        assert_eq!(ledger.json(), *expected, "{name}");
    }
}

#[test]
fn days_are_utc_dates() {
    assert_eq!(day(0), "1970-01-01");
    assert_eq!(day(1_792_000_000), "2026-10-14");
    assert_eq!(day(days_of("2000-02-29") * 86_400 + 86_399), "2000-02-29");
    assert_eq!(days_of("1970-01-01"), 0);
}

#[test]
fn the_peer_reads_library_attach_frames() {
    use frasil_transport::frame::{ConnectionKind, Read, StreamClass, read_frame};
    for row in family("library_attach").as_array().unwrap() {
        let frame = bytes(&row["frame"]);
        let Ok(Read::Message(message, rest)) = read_frame(
            &frame,
            StreamClass::Control,
            ConnectionKind::DeviceToPeer,
            crate::Extensions::ALL.frames(),
        ) else {
            panic!("{row}");
        };
        assert!(rest.is_empty());
        assert_eq!(message.bytes, bytes(&row["message"]));
        let attach = LibraryAttach::read(&message.map).unwrap();
        assert_eq!(attach.request, u(&row["request"]));
        assert_eq!(attach.space, array::<32>(&row["space"]));
        assert_eq!(attach.purpose.code(), u(&row["purpose"]));
        assert_eq!(attach.signed, bytes(&row["signed"]));
    }
}

// -- import, through the store path

fn settings() -> Settings {
    Settings {
        extensions: crate::Extensions {
            libraries: true,
            ..crate::Extensions::NONE
        },
        libraries: LibrarySettings {
            issuers: issuers(),
            ..LibrarySettings::default()
        },
        ..Settings::open_core()
    }
}

fn import_ticket(now: u64) -> Vec<u8> {
    let seed = array::<32>(&parameters()["issuer_seed"]);
    let issuer = Issuer::from_seed(&seed);
    issuer.sign(&Ticket {
        library: library("project:7c1f9e2a0b4d4e8f"),
        id: [7; 16],
        purpose: Purpose::Import,
        not_after: now + 3600,
        issuer: ed25519_public(&seed),
        tokens: None,
    })
}

fn describe(entries: &[frasil_peers::entries::Entry], names: &BTreeMap<EventId, String>) -> Json {
    entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "state": e.state.ids().iter().map(|id| names[id].clone()).collect::<Vec<_>>(),
                "read": hex::encode(e.read),
                "upload": hex::encode(e.upload),
                "status": if e.is_live() { "live" } else { "retired" },
                "source": e.source.name(),
                "proved": e.proved,
            })
        })
        .collect::<Vec<_>>()
        .into()
}

#[tokio::test]
async fn an_import_runs_through_the_store_path() {
    let vectors = family("import");
    let now = u(&parameters()["now"]);
    let store: Arc<dyn frasil_store::Store> = Arc::new(frasil_store::MemoryStore::new());
    let clock: Arc<dyn crate::Clock> = Arc::new(crate::ManualClock::new(13));
    let core = Core::open(settings(), Records::new(store.clone()), clock.clone()).unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let link = core.link(tx);
    let channel = example("library/channel");
    let binding = frasil_transport::peer::peer_binding(
        &channel,
        &example("library/nonce-p"),
        &example("library/nonce-c"),
        ConnectionPurpose::SpaceTraffic,
    );
    let on = On {
        link,
        binding,
        purpose: ConnectionPurpose::SpaceTraffic,
        now: reading(13, now),
    };
    let events: Vec<(String, Vec<u8>)> = vectors["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["name"].as_str().unwrap().to_owned(),
                bytes(&row["signed"]),
            )
        })
        .collect();
    let names: BTreeMap<EventId, String> = events
        .iter()
        .map(|(name, signed)| (frasil_events::decode(signed).unwrap().id(), name.clone()))
        .collect();
    let space = frasil_events::decode(&events[0].1).unwrap().id();
    let mut grants: BTreeMap<EventId, Grant> = BTreeMap::new();

    // LibraryAttach, purpose 2.
    let attach = LibraryAttach {
        request: 1,
        space: *space.as_bytes(),
        purpose: Purpose::Import,
        signed: import_ticket(now),
    };
    let answer = core.library_attach(&on, &mut grants, &attach).await;
    assert_eq!(
        answer,
        crate::state::Outgoing::Control(
            frasil_transport::messages::Accepted { request: 1 }.encode()
        )
    );
    // The log, genesis first: every rotation's entry starts retired.
    for (name, signed) in &events {
        let grant = grants.get_mut(&space).unwrap();
        let stored = core.store(link, grant, space, signed, on.now).await;
        assert!(
            matches!(stored, crate::state::StoreAnswer::Acknowledge(_)),
            "{name}: {stored:?}"
        );
    }
    let entries = core
        .read(space, |held| held.entries.entries().to_vec())
        .await
        .unwrap();
    assert!(entries.iter().all(|e| !e.is_live()));
    assert_eq!(
        crate::state::lock(&core.libraries)
            .attachment(&space)
            .unwrap()
            .library
            .as_str(),
        "project:7c1f9e2a0b4d4e8f"
    );

    // The importer presents the upload key of its view's current state.
    let proof = &vectors["proof"];
    let removal = vectors["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["status"] == "live")
        .unwrap();
    let public = array::<32>(&removal["upload"]);
    assert_eq!(
        frasil_peers::proof::presented(&binding, space.as_bytes(), 2, &public),
        bytes(&proof["presented"])
    );
    let present = Present {
        request: 2,
        space: *space.as_bytes(),
        credential: 2,
        public: public.to_vec(),
        proof: bytes(&proof["proof"]),
    };
    let _ = core.present(&on, &mut grants, &present, None).await;
    let rights = grants[&space].rights;
    let names_of: Vec<&str> = Right::of(rights).iter().map(|r| r.name()).collect();
    assert_eq!(names_of.join(", "), proof["verdict"].as_str().unwrap());
    let entries = core
        .read(space, |held| held.entries.entries().to_vec())
        .await
        .unwrap();
    assert_eq!(describe(&entries, &names), vectors["entries"]);

    // The peer reopens its records: the journal replays to the same
    // entries.
    drop(core);
    let reopened = Core::open(settings(), Records::new(store), clock).unwrap();
    assert_eq!(
        reopened
            .read(space, |held| held.entries.entries().to_vec())
            .await
            .unwrap(),
        entries
    );
    let libraries = crate::state::lock(&reopened.libraries);
    assert!(libraries.attachment(&space).is_some());
    assert_eq!(libraries.tickets_used().len(), 1);
}

#[test]
fn a_store_outside_the_log_ends_the_import() {
    let mut attaching = Attaching {
        pending: None,
        importing: true,
    };
    let none = frasil_peers::entries::Rights::default();
    assert!(attaching.importing_store(&none, true));
    assert!(attaching.importing());
    let store = frasil_peers::entries::Rights::STORE_AND_RELEASE;
    assert!(!attaching.importing_store(&store, true));
    assert!(!attaching.importing());
    assert!(!attaching.importing_store(&none, true));
}

#[test]
fn an_accepted_import_lapses_once_another_connection_hosts_the_space() {
    let pending = || Attaching {
        pending: Some((
            Purpose::Import,
            library("project:x"),
            [1; 16],
            reading(1, 1),
        )),
        importing: false,
    };
    let none = frasil_peers::entries::Rights::default();
    // Its genesis, while the space is not hosted, is a store of the import.
    assert!(pending().importing_store(&none, false));
    // Once another connection made the space hosted, it stores nothing
    // without the store right.
    let mut lapsed = pending();
    assert!(!lapsed.importing_store(&none, true));
    assert_eq!(lapsed, Attaching::default());
}

#[test]
fn settings_read_from_the_environment() {
    let key = hex::encode(array::<32>(&parameters()["issuer"]));
    let vars: BTreeMap<&str, String> = [
        ("FRASIL_LIBRARY_ISSUERS", key),
        ("FRASIL_DETACHED_GRACE", "86400".to_owned()),
        (
            "FRASIL_LIBRARY_QUOTAS",
            "personal=500 project=1000".to_owned(),
        ),
    ]
    .into_iter()
    .collect();
    let settings = LibrarySettings::from_lookup(&|name| vars.get(name).cloned()).unwrap();
    assert_eq!(settings.issuers, issuers());
    assert_eq!(settings.detached_grace, 86_400);
    assert_eq!(
        settings.new_library(&library("personal:x"), 3600).quota,
        Some(500)
    );
    assert_eq!(settings.new_library(&library("other:x"), 3600).quota, None);
    assert_eq!(settings.new_library(&library("personal"), 3600).quota, None);
    let bad = |name: &'static str, value: &'static str| {
        LibrarySettings::from_lookup(&|n| (n == name).then(|| value.to_owned())).is_err()
    };
    assert!(bad("FRASIL_DETACHED_GRACE", "60"));
    assert!(bad("FRASIL_LIBRARY_ISSUERS", "zz"));
    assert!(bad("FRASIL_LIBRARY_QUOTAS", "personal"));
}

/// `held_objects` (ext-libraries.md, 3.8 Keeping a held object), through
/// [`Libraries`]'s holds: at each step, the holds that end, and whether the
/// object stays, as the peer's sweep decides them from what the step's
/// units list; and the ledger's bytes and holds.
#[test]
fn held_objects() {
    let v = family("held_objects");
    let source = EventId(array::<32>(&v["source"]));
    let space = EventId(array::<32>(&v["space"]));
    let locator: [u8; 64] = array(&v["locator"]);
    let size = u(&v["object_bytes"]);
    let grace = u(&v["orphan_grace"]);
    let start = u(&v["steps"][0]["now"]);
    let mut libraries = Libraries::new(LibrarySettings::default());
    let hold = Hold {
        source: *source.as_bytes(),
        access: [0; 32],
        at: reading(0, start),
    };
    let mut kept = true;
    let mut erased = false;
    for step in v["steps"].as_array().unwrap() {
        let name = step["step"].as_str().unwrap();
        let now = reading(u(&step["now"]) - start, u(&step["now"]));
        let units = &step["units"];
        let listed = |of: &EventId, locator: &[u8; 64]| {
            units[hex::encode(of.as_bytes())]
                .as_object()
                .is_some_and(|by_unit| {
                    by_unit.values().any(|locators| {
                        locators
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|l| bytes(l) == locator[..])
                    })
                })
        };
        let expect_kept = !step["kept"].as_array().unwrap().is_empty();
        let expect_held = !step["holds"].as_array().unwrap().is_empty();
        if expect_kept && !kept {
            // The object is stored and held again (the erasure's case).
            kept = true;
            libraries.add_hold(space, locator, hold);
        }
        if name.contains("erasure") {
            erased = true;
        }
        if libraries.hold(&space, &locator).is_none() && expect_held {
            libraries.add_hold(space, locator, hold);
        }
        let ended = libraries.ended_holds(&now, grace, |_| true, listed);
        libraries.drop_holds(&ended);
        let held = libraries.is_held(&source, &locator);
        kept = kept && !erased && (listed(&source, &locator) || held);
        assert_eq!(kept, expect_kept, "{name}: kept");
        assert_eq!(held, expect_held, "{name}: holds");
        let ledger = &step["ledger"];
        let in_source = listed(&source, &locator);
        assert_eq!(
            u(&ledger["source"]["used_bytes"]),
            if kept { size } else { 0 },
            "{name}"
        );
        assert_eq!(
            u(&ledger["source"]["held_bytes"]),
            if kept && !in_source { size } else { 0 },
            "{name}"
        );
        assert_eq!(
            u(&ledger["holding"]["used_bytes"]),
            0,
            "{name}: counted once"
        );
        assert_eq!(
            u(&ledger["holding"]["holds"]),
            libraries.holds_of(&space),
            "{name}"
        );
        assert_eq!(u(&ledger["source"]["holds"]), libraries.holds_of(&source));
    }
}

/// ext-libraries.md, 3.3 Attaching: a create or an import of a space the
/// peer deleted passes the check, ticket and all, as one of a space never
/// hosted; its genesis is the one refused.
#[test]
fn a_create_of_a_deleted_space_passes_the_check() {
    let step = &family("attachments")[0];
    let space = EventId(array(&step["space"]));
    let signed = bytes(&step["ticket"]);
    let mut run = Run::new();
    let _ = run.libraries.delete(&space);
    assert!(run.libraries.is_deleted(&space));
    let request = Request {
        purpose: Purpose::from_name(step["purpose"].as_str().unwrap()).unwrap(),
        space,
        signed: &signed,
        wall: Some(u(&step["now"])),
        hosted: false,
        store_right: false,
    };
    assert!(run.libraries.check(&request, &|_| 0).is_ok());
    let hosted = Request {
        hosted: true,
        ..request
    };
    assert_eq!(
        run.libraries.check(&hosted, &|_| 0).err(),
        Some(LibraryClass::SpaceExists)
    );
}

/// ext-libraries.md, 3.8 Keeping a held object, "Holds across a move": a
/// hold whose holding space and source two libraries bill points at its
/// library's copy, which keeps the object in place of the source; the
/// copy counts once, in that library's usage; and once a move brings the
/// two together again, the hold points at the source and the copy is
/// no longer held.
#[test]
fn a_hold_across_two_libraries_points_at_a_copy() {
    let mut libraries = Libraries::new(LibrarySettings::default());
    let (a, b) = (
        LibraryId::new("project:a").unwrap(),
        LibraryId::new("project:b").unwrap(),
    );
    let (source, holder) = (EventId([1; 32]), EventId([2; 32]));
    let locator = [3; 64];
    let at = reading(5, 1_000);
    let _ = libraries.attach(source, &a, None, at);
    let _ = libraries.attach(holder, &a, None, at);
    let _ = libraries.add_hold(
        holder,
        locator,
        Hold {
            source: *source.as_bytes(),
            access: [4; 32],
            at,
        },
    );
    assert!(libraries.is_held(&source, &locator));
    assert!(libraries.hold_copy(&holder, &locator).is_none());
    // The source moves to B: the copy in A keeps the object.
    let _ = libraries.attach(source, &b, None, at);
    let copy = Copy {
        source: *source.as_bytes(),
        object: Vec::new(),
        bytes: 700,
        at,
    };
    let _ = libraries.add_copy(a.clone(), locator, copy.clone());
    assert!(
        !libraries.is_held(&source, &locator),
        "the hold keeps the copy"
    );
    assert_eq!(libraries.hold_copy(&holder, &locator), Some((&a, &copy)));
    assert!(libraries.unheld_copies(&a, |_| false).is_empty());
    assert_eq!(libraries.usage(&a, &|_| 0), 700, "the copy counts in A");
    assert_eq!(libraries.usage(&b, &|_| 0), 0);
    let ledger = libraries.ledger(&a, &|_| SpaceUsage::default()).unwrap();
    assert_eq!(ledger.used_bytes(), 700);
    // An erasure of the source removes the copy.
    assert_eq!(libraries.unheld_copies(&a, |s| *s == source), vec![locator]);
    // The source comes back to A: the hold points at it again.
    let _ = libraries.attach(source, &a, None, at);
    assert!(libraries.is_held(&source, &locator));
    assert!(libraries.hold_copy(&holder, &locator).is_none());
    assert_eq!(libraries.unheld_copies(&a, |_| false), vec![locator]);
    let gone = libraries.drop_copies(&[(a.clone(), locator)]);
    assert_eq!(gone.len(), 1);
    assert_eq!(libraries.usage(&a, &|_| 0), 0);
}

/// A move the index refuses to record (another is recorded for the space)
/// does not use its ticket: a move records its ticket used only in the
/// target's last step, once the target's headroom held the space
/// (ext-libraries.md, 3.3 Attaching, Move).
#[tokio::test]
async fn a_move_the_index_refuses_leaves_its_ticket_usable() {
    use super::moves::record_intent;
    use crate::records::MoveRecord;
    use crate::state::lock;
    let store: Arc<dyn frasil_store::Store> = Arc::new(frasil_store::MemoryStore::new());
    let clock: Arc<dyn crate::Clock> = Arc::new(crate::ManualClock::new(13));
    let core = Core::open(settings(), Records::new(store), clock).unwrap();
    let space = EventId([5; 32]);
    let at = reading(5, 1_000);
    let intent = |ticket: u8| MoveRecord {
        source: "libraries/a".to_owned(),
        target: "libraries/b".to_owned(),
        library: "project:b".to_owned(),
        ticket: Some(vec![ticket; 16]),
        at,
        not_after: Some(1_000_000),
    };
    // Another node recorded a move of the space already.
    core.writer
        .commit(
            vec![(Records::move_address(&space), intent(1).encode())],
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        record_intent(&core, &space, &intent(9)).await.ok(),
        Some(false)
    );
    assert!(!lock(&core.libraries).tickets_used().contains_key(&[9; 16]));
    let reopened = Libraries::open(&core.settings, &core.records).unwrap();
    assert!(!reopened.tickets_used().contains_key(&[9; 16]));
    // A move's record reads back with its ticket's `not_after`.
    let read = MoveRecord::decode(&intent(9).encode()).unwrap();
    assert_eq!(read.not_after, Some(1_000_000));
}

// -- a peer's defaults: closed, with the operator's own issuer

/// The `import` family's log, by name, in order: its first event is a
/// genesis.
fn import_events() -> Vec<(String, Vec<u8>)> {
    family("import")["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["name"].as_str().unwrap().to_owned(),
                bytes(&row["signed"]),
            )
        })
        .collect()
}

/// A space-traffic connection to `core`, over the vectors' binding, at the
/// vectors' instant.
fn connection(core: &Core) -> (On, u64, tokio::sync::mpsc::Receiver<crate::state::Outgoing>) {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let link = core.link(tx);
    let binding = frasil_transport::peer::peer_binding(
        &example("library/channel"),
        &example("library/nonce-p"),
        &example("library/nonce-c"),
        ConnectionPurpose::SpaceTraffic,
    );
    let on = On {
        link,
        binding,
        purpose: ConnectionPurpose::SpaceTraffic,
        now: reading(13, u(&parameters()["now"])),
    };
    (on, link, rx)
}

/// A peer with the operator's defaults, trusting `issuer`, on memory.
fn operator_peer(issuer: &OperatorIssuer) -> Core {
    let mut settings = Settings::default();
    settings.libraries.use_operator(issuer.clone());
    let store: Arc<dyn frasil_store::Store> = Arc::new(frasil_store::MemoryStore::new());
    let clock: Arc<dyn crate::Clock> = Arc::new(crate::ManualClock::new(13));
    Core::open(settings, Records::new(store), clock).unwrap()
}

/// A stranger's genesis, stored with no ticket: the answer.
async fn stranger_creates(core: &Core, genesis: &[u8]) -> crate::state::StoreAnswer {
    let (on, link, _rx) = connection(core);
    let space = frasil_events::decode(genesis).unwrap().id();
    let mut grant = Grant::default();
    core.store(link, &mut grant, space, genesis, on.now).await
}

/// A new peer refuses a stranger's space, and takes one attached with a
/// ticket `frasil-relay ticket`'s code path signed, into the default
/// library; a ticket of another issuer is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_peer_hosts_only_what_its_operators_tickets_attach() {
    use crate::state::StoreAnswer;
    let issuer = OperatorIssuer::from_seed([11; 32]);
    let core = operator_peer(&issuer);
    let events = import_events();
    let genesis = &events[0].1;
    let space = frasil_events::decode(genesis).unwrap().id();
    assert!(core.settings.extensions.libraries);
    assert_eq!(core.settings.hosting, crate::Hosting::Closed);
    // A stranger: no ticket, no space.
    assert_eq!(
        stranger_creates(&core, genesis).await,
        StoreAnswer::Refused("no_library".into())
    );
    assert!(!core.hosts(&space));
    let now = u(&parameters()["now"]);
    let (on, link, _rx) = connection(&core);
    let mut grants: BTreeMap<EventId, Grant> = BTreeMap::new();
    // A ticket of an issuer the peer does not trust.
    let other = super::operator::issue_with(
        &OperatorIssuer::from_seed([12; 32]),
        &super::TicketRequest::default(),
        None,
        now,
        [2; 16],
    )
    .unwrap();
    let attach = |request: u64, signed: Vec<u8>| LibraryAttach {
        request,
        space: *space.as_bytes(),
        purpose: Purpose::Create,
        signed,
    };
    assert_eq!(
        core.library_attach(&on, &mut grants, &attach(1, other.ticket))
            .await,
        crate::state::refused(1, "ticket_refused")
    );
    // The operator's ticket, as `frasil-relay ticket` makes it.
    let issued = super::operator::issue_with(
        &issuer,
        &super::TicketRequest::default(),
        Some("https://peer.example.org"),
        now,
        [3; 16],
    )
    .unwrap();
    let link_text = issued.link.as_ref().unwrap().to_string();
    let read = frasil_libraries::TicketLink::parse(&link_text).unwrap();
    assert_eq!(
        core.library_attach(&on, &mut grants, &attach(2, read.into_ticket()))
            .await,
        crate::state::Outgoing::Control(
            frasil_transport::messages::Accepted { request: 2 }.encode()
        )
    );
    let grant = grants.get_mut(&space).unwrap();
    assert!(matches!(
        core.store(link, grant, space, genesis, on.now).await,
        StoreAnswer::Acknowledge(_)
    ));
    assert_eq!(
        crate::state::lock(&core.libraries)
            .attachment(&space)
            .unwrap()
            .library,
        issuer.default_library()
    );
}

/// With the extension off the peer is a core peer: it lists no library
/// service, its closed hosting creates nothing, and open hosting creates
/// any space with no ticket and no library.
#[tokio::test(flavor = "multi_thread")]
async fn with_the_extension_off_the_peer_is_a_core_peer() {
    use crate::state::StoreAnswer;
    let has_library = |extensions: &crate::Extensions| {
        crate::session::services(extensions)
            .iter()
            .any(|service| service.name() == "library")
    };
    assert!(has_library(&crate::Extensions::DEFAULT));
    assert!(!has_library(&crate::Extensions::NONE));
    let events = import_events();
    let genesis = &events[0].1;
    let space = frasil_events::decode(genesis).unwrap().id();
    let open = |settings: Settings| {
        let store: Arc<dyn frasil_store::Store> = Arc::new(frasil_store::MemoryStore::new());
        let clock: Arc<dyn crate::Clock> = Arc::new(crate::ManualClock::new(13));
        Core::open(settings, Records::new(store), clock).unwrap()
    };
    let closed = open(Settings {
        extensions: crate::Extensions::NONE,
        ..Settings::default()
    });
    assert_eq!(
        stranger_creates(&closed, genesis).await,
        StoreAnswer::Refused("no_library".into())
    );
    let core = open(Settings::open_core());
    assert!(matches!(
        stranger_creates(&core, genesis).await,
        StoreAnswer::Acknowledge(_)
    ));
    assert!(core.hosts(&space));
    assert!(
        crate::state::lock(&core.libraries)
            .attachment(&space)
            .is_none()
    );
    assert!(core.records.library_records().unwrap().is_empty());
}

/// A restart keeps the operator's key, from `issuer.key` in the data
/// directory, and its default library, recorded once.
#[test]
fn a_restart_keeps_the_operator_key_and_the_default_library() {
    let dir = std::env::temp_dir().join(format!(
        "frasil-relay-issuer-{}",
        crate::util::hex(&*frasil_crypto::random_bytes::<8>().unwrap())
    ));
    let config = crate::Config::from_lookup(|name| {
        (name == "FRASIL_DATA_DIR").then(|| dir.display().to_string())
    })
    .unwrap();
    let first = crate::operator_issuer(&config).unwrap();
    let again = crate::operator_issuer(&config).unwrap();
    assert_eq!(first, again);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("issuer.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let store: Arc<dyn frasil_store::Store> = Arc::new(frasil_store::MemoryStore::new());
    let start = |issuer: &OperatorIssuer| {
        let mut settings = Settings::default();
        settings.libraries.use_operator(issuer.clone());
        let peer = crate::Peer::open(
            settings,
            store.clone(),
            Arc::new(crate::blobs::MemoryBlobs::new()),
            Arc::new(crate::ManualClock::new(13)),
        )
        .unwrap();
        let library = peer.ensure_default_library().unwrap();
        (peer, library)
    };
    let (peer, library) = start(&first);
    assert_eq!(library, Some(first.default_library()));
    assert!(peer.ledger(&first.default_library()).is_some());
    drop(peer);
    let (peer, library) = start(&again);
    assert_eq!(library, Some(first.default_library()));
    let kept = Records::new(store.clone()).library_records().unwrap();
    assert_eq!(
        kept.iter()
            .filter(|(table, ..)| *table == super::records::LIBRARY)
            .count(),
        1,
        "one default library"
    );
    drop(peer);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A move into a library kept in another shard whose headroom does not
/// hold the space is refused `quota_exceeded`, and its ticket stays unused:
/// the headroom is checked before the ticket is recorded (ext-libraries.md,
/// 3.3 Attaching, Move).
#[tokio::test(flavor = "multi_thread")]
async fn a_move_without_headroom_leaves_its_ticket_unused() {
    let dir = std::env::temp_dir().join(format!(
        "frasil-relay-move-{}",
        crate::util::hex(&*frasil_crypto::random_bytes::<8>().unwrap())
    ));
    let shards = crate::shards::Shards::local(dir.join("shards")).unwrap();
    let mut settings = settings();
    settings.libraries.default_quotas.insert("tiny".into(), 1);
    let peer = tokio::task::spawn_blocking(move || {
        crate::Peer::open_sharded(
            settings,
            shards,
            Arc::new(crate::blobs::MemoryBlobs::new()),
            Arc::new(crate::ManualClock::new(13)),
        )
    })
    .await
    .unwrap()
    .unwrap();
    let shared = peer.shared.clone();
    let core = &shared.core;
    let vectors = family("import");
    let now = u(&parameters()["now"]);
    let (on, link, _rx) = connection(core);
    let events = import_events();
    let space = frasil_events::decode(&events[0].1).unwrap().id();
    let mut grants: BTreeMap<EventId, Grant> = BTreeMap::new();
    let import = LibraryAttach {
        request: 1,
        space: *space.as_bytes(),
        purpose: Purpose::Import,
        signed: import_ticket(now),
    };
    let _ = core.library_attach(&on, &mut grants, &import).await;
    for (name, signed) in &events {
        let grant = grants.get_mut(&space).unwrap();
        let stored = core.store(link, grant, space, signed, on.now).await;
        assert!(
            matches!(stored, crate::state::StoreAnswer::Acknowledge(_)),
            "{name}: {stored:?}"
        );
    }
    let proof = &vectors["proof"];
    let live = vectors["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["status"] == "live")
        .unwrap();
    let present = Present {
        request: 2,
        space: *space.as_bytes(),
        credential: 2,
        public: bytes(&live["upload"]),
        proof: bytes(&proof["proof"]),
    };
    let _ = core.present(&on, &mut grants, &present, None).await;
    assert!(grants[&space].rights.store);
    // A `tiny` library, of a quota of one byte, in another shard than the
    // space's.
    let source = crate::shards::library_shard("project:7c1f9e2a0b4d4e8f");
    let tiny = (0..)
        .map(|n| format!("tiny:full-{n}"))
        .find(|name| crate::shards::library_shard(name) != source)
        .unwrap();
    let seed = array::<32>(&parameters()["issuer_seed"]);
    let signed = Issuer::from_seed(&seed).sign(&Ticket {
        library: library(&tiny),
        id: [4; 16],
        purpose: Purpose::Move,
        not_after: now + 3600,
        issuer: ed25519_public(&seed),
        tokens: None,
    });
    let attach = LibraryAttach {
        request: 3,
        space: *space.as_bytes(),
        purpose: Purpose::Move,
        signed,
    };
    assert_eq!(
        super::moves::library_move(&shared, &on, &mut grants, &attach).await,
        crate::state::refused(3, "quota_exceeded")
    );
    assert!(!peer.moving(space.as_bytes()));
    assert!(
        !crate::state::lock(&core.libraries)
            .tickets_used()
            .contains_key(&[4; 16])
    );
    let reread = Libraries::open(&core.settings, &core.records).unwrap();
    assert!(!reread.tickets_used().contains_key(&[4; 16]));
    assert_eq!(
        crate::state::lock(&core.libraries)
            .attachment(&space)
            .unwrap()
            .library
            .as_str(),
        "project:7c1f9e2a0b4d4e8f"
    );
    drop(peer);
    let _ = std::fs::remove_dir_all(&dir);
}
