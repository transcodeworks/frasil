//! ext-space-files.json's files and the roads in, run through the engine:
//! the full-history files read by keys, a member merging one, the sealed
//! way in with and without its key, no way in, another kind; the snapshot
//! file claimed by its fragment; and an embedded held object's records.
#![cfg(all(feature = "space-files", feature = "ext-invite-links"))]

use frasil::advanced::space_file::Road;
use frasil::advanced::{Engine, ManualClock};
use frasil::{Device, Error, Level, Options, Storage};
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_space::MemberRef;
use frasil_space::ext_invite_links::invite_member;
use frasil_space_file::record::Record;
use frasil_testkit::hex;
use serde_json::Value as Json;
use std::collections::BTreeMap;
use std::sync::Arc;

const FILE: &str = "ext-space-files.json";
const KIND: &str = "example.notes";

fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

fn bytes(value: &Json) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex")).expect("hex")
}

fn array<const N: usize>(value: &Json) -> [u8; N] {
    hex::decode_array(value.as_str().expect("hex")).expect("hex")
}

fn text(value: &Json) -> &str {
    value.as_str().expect("text")
}

/// The class a refusal names.
fn class_of(error: Error) -> &'static str {
    match error {
        Error::Class(name) => name,
        other => panic!("not a class: {other:?}"),
    }
}

/// The vectors' devices, by name, and the invite key.
struct Fixtures {
    devices: BTreeMap<String, DeviceId>,
    invite_key: [u8; 32],
    space: EventId,
    events: BTreeMap<String, EventId>,
    now: u64,
}

fn fixtures() -> Fixtures {
    let f = family("fixtures");
    Fixtures {
        devices: f["devices"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, key)| (name.clone(), DeviceId(array(key))))
            .collect(),
        invite_key: array(&f["invite"]["key"]),
        space: EventId(array(&f["space"])),
        events: f["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (text(&e["name"]).to_owned(), EventId(array(&e["id"]))))
            .collect(),
        now: f["invite"]["now"].as_u64().unwrap(),
    }
}

/// A device whose wall clock is the vectors' `now`, so that the invite is
/// unexpired.
async fn device(key: u8, now: u64) -> Device {
    Device::open_with(
        Storage::Memory,
        &[key; 32],
        Options::new()
            .never_restored()
            .clock(Arc::new(ManualClock::new(1_000, Some(now)))),
    )
    .await
    .unwrap()
}

/// Each member's level in the roster the engine resolved.
async fn levels(engine: &Engine, space: &EventId, fixtures: &Fixtures) -> BTreeMap<String, String> {
    let devices = fixtures.devices.clone();
    let invite = fixtures.invite_key;
    engine
        .read(space, |replica| {
            let mut out = BTreeMap::new();
            for (name, key) in &devices {
                if let Some(level) = replica.level_of(key) {
                    out.insert(name.clone(), level_name(level).to_owned());
                }
            }
            let invite = invite_member(invite);
            out.insert(
                "invite".into(),
                match replica.roster().state(&invite) {
                    Some(state) => level_name(state.level).to_owned(),
                    None if replica.roster().standing(&invite).is_some() => "removed".into(),
                    None => "absent".into(),
                },
            );
            out
        })
        .await
        .unwrap()
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::Read => "read",
        Level::Write => "write",
        Level::Administer => "administer",
    }
}

/// The vectors' roster, as names and levels, the invite key by its
/// kind.
fn expected_roster(roster: &Json) -> BTreeMap<String, String> {
    roster
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, entry)| match entry {
            Json::String(standing) => (name.clone(), standing.clone()),
            entry if entry["type"] == "invite" => {
                ("invite".to_owned(), text(&entry["level"]).to_owned())
            }
            entry => (name.clone(), text(&entry["level"]).to_owned()),
        })
        .collect()
}

#[tokio::test]
async fn files_read_by_keys_and_refused_by_their_way_in() {
    let fixtures = fixtures();
    let files = family("files");
    let by_keys = bytes(&files["by_keys"]);
    let reference = &files["reference"];

    // A reader by keys resolves the same roster, and holds every unit.
    let bob = device(1, fixtures.now).await;
    let imported = bob
        .engine()
        .import_space_file(&by_keys, &[KIND], None)
        .await
        .unwrap();
    assert_eq!(imported.road, Road::Reading);
    assert_eq!(imported.space, fixtures.space);
    assert_eq!(
        levels(bob.engine(), &fixtures.space, &fixtures).await,
        expected_roster(&reference["roster"]["roster"])
    );
    let unit_names: Vec<&str> = reference["units"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| {
            let author = text(&u["author"]);
            let content = text(&u["content"]);
            match (author, content) {
                ("A", "row 1") => "A writes row 1",
                ("B", "row 2") => "B writes row 2",
                _ => "A writes row 3 after the snapshot's base",
            }
        })
        .collect();
    for name in unit_names {
        let id = fixtures.events[name];
        let valid = bob
            .engine()
            .read(&fixtures.space, |replica| {
                replica.holds(id) && replica.status(&id).is_some_and(|s| s.is_valid())
            })
            .await
            .unwrap();
        assert!(valid, "{name}");
    }
    let space = bob
        .space(frasil::SpaceId::from_bytes(fixtures.space.0))
        .await
        .unwrap();
    assert_eq!(space.level().await, None, "a reader is no member");

    // Imported again by a device that holds it by keys alone: a reader
    // again, nothing new, still no grant.
    let again = bob
        .engine()
        .import_space_file(&by_keys, &[KIND], None)
        .await
        .unwrap();
    assert_eq!(
        format!("{:?}", again.road),
        text(&files["roads"]["a reader by keys that holds the space"])
    );
    assert_eq!(again.road, Road::Rereading);
    assert_eq!(
        again.placed,
        files["roads"]["a member that holds the space"]["new_events"]
            .as_u64()
            .unwrap() as usize
    );

    // The sealed way in: without the key, with the wrong key, with it.
    let sealed = bytes(&files["sealed"]);
    let key = array::<32>(&family("way_in")["file_key"]);
    let carol = device(2, fixtures.now).await;
    assert_eq!(
        class_of(
            carol
                .engine()
                .import_space_file(&sealed, &[KIND], None)
                .await
                .unwrap_err()
        ),
        text(&files["roads"]["a sealed way in without the key"])
    );
    assert_eq!(
        carol
            .engine()
            .import_space_file(&sealed, &[KIND], Some(&[9; 32]))
            .await
            .unwrap_err(),
        Error::Class("Decrypt")
    );
    let with_key = carol
        .engine()
        .import_space_file(&sealed, &[KIND], Some(&key))
        .await
        .unwrap();
    assert_eq!(
        format!("{:?}", with_key.road),
        text(&files["roads"]["a sealed way in with the key"])
    );

    // No way in, and another kind.
    let dan = device(3, fixtures.now).await;
    assert_eq!(
        class_of(
            dan.engine()
                .import_space_file(&bytes(&files["nobody"]), &[KIND], None)
                .await
                .unwrap_err()
        ),
        text(&files["roads"]["no way in"])
    );
    assert_eq!(
        class_of(
            dan.engine()
                .import_space_file(&by_keys, &["example.other"], None)
                .await
                .unwrap_err()
        ),
        text(&files["roads"]["another kind"])
    );
    // A rotation secret that is not its rotation's; a head the file does
    // not hold. Neither leaves a space behind.
    assert_eq!(
        class_of(
            dan.engine()
                .import_space_file(&bytes(&files["wrong_secret"]), &[KIND], None)
                .await
                .unwrap_err()
        ),
        text(&files["roads"]["a rotation secret that misses its rotation's read credential"])
    );
    assert_eq!(
        class_of(
            dan.engine()
                .import_space_file(&bytes(&files["missing_head"]), &[KIND], None)
                .await
                .unwrap_err()
        ),
        text(&files["roads"]["a head the file does not hold"])
    );
    assert!(dan.spaces().await.is_empty());
    // The events out of parent order read all the same.
    let shuffled = &files["roads"]["the events out of parent order"];
    let imported = dan
        .engine()
        .import_space_file(&bytes(&files["shuffled"]), &[KIND], None)
        .await
        .unwrap();
    assert_eq!(format!("{:?}", imported.road), text(&shuffled["road"]));
    assert_eq!(
        imported.placed,
        shuffled["placed"].as_u64().unwrap() as usize
    );
}

#[tokio::test]
async fn the_snapshot_file_admits_its_claimant() {
    let fixtures = fixtures();
    let family = family("snapshot_file");
    let claimant = &family["claimant"];
    let eve = device(4, fixtures.now).await;
    let imported = eve
        .engine()
        .import_space_file(&bytes(&family["file"]), &[KIND], None)
        .await
        .unwrap();
    // The import stops with the offer; the successor is signed on consent.
    let Road::Invited { offer, label } = &imported.road else {
        panic!("{:?}", imported.road);
    };
    assert_eq!(text(&claimant["road"]), "Invited");
    assert_eq!(level_name(offer.level), text(&claimant["offer"]["level"]));
    assert_eq!(
        offer.expires_at,
        claimant["offer"]["expires_at"].as_u64().unwrap()
    );
    assert_eq!(
        offer.inviter,
        fixtures.devices[text(&claimant["offer"]["inviter"])]
    );
    assert_eq!(label.as_deref(), claimant["offer"]["label"].as_str());
    assert!(
        eve.spaces().await.is_empty(),
        "nothing listed before consent"
    );
    eve.engine().claim(fixtures.space).await.unwrap();
    assert_eq!(text(&claimant["on_consent"]), "Claimed");
    // The roster afterwards: the inviter's devices as the vectors show
    // them, the invite key out, and this device at the invite's level.
    let got = levels(eve.engine(), &fixtures.space, &fixtures).await;
    let expected = expected_roster(&claimant["roster_after"]);
    for (name, level) in &expected {
        if name == "C" {
            continue;
        }
        assert_eq!(got.get(name), Some(level), "{name}");
    }
    let mine = eve
        .engine()
        .read(&fixtures.space, |replica| {
            replica
                .roster()
                .state(&MemberRef::device(eve.engine().device_id()))
                .map(|s| level_name(s.level))
        })
        .await
        .unwrap();
    assert_eq!(mine, Some(text(&claimant["successor"]["level"])));
    // The claim is in the outbox until a member or a peer takes it.
    assert!(!eve.engine().outbox(&fixtures.space).await.is_empty());

    // A fragment naming an entry the file lacks, first: skipped for the
    // second. Alone beside the keys: the keys road.
    let fay = device(5, fixtures.now).await;
    let skipped = fay
        .engine()
        .import_space_file(&bytes(&family["skipped_first"]["file"]), &[KIND], None)
        .await
        .unwrap();
    assert!(
        matches!(skipped.road, Road::Invited { .. }),
        "{:?}",
        skipped.road
    );
    assert_eq!(text(&family["skipped_first"]["road"]), "Invited");
    fay.engine().abandon_claim(&fixtures.space).await.unwrap();
    let gus = device(6, fixtures.now).await;
    let fallthrough = gus
        .engine()
        .import_space_file(&bytes(&family["fallthrough"]["file"]), &[KIND], None)
        .await
        .unwrap();
    assert_eq!(
        format!("{:?}", fallthrough.road),
        text(&family["fallthrough"]["road"])
    );
}

#[test]
fn an_embedded_held_object_is_the_stored_object() {
    let family = family("held_object");
    let records = bytes(&family["records"]);
    let mut at = 0;
    let mut stored = Vec::new();
    let mut chunks = 0;
    while at < records.len() {
        let n = u32::from_be_bytes(records[at..at + 4].try_into().unwrap()) as usize;
        let record = Record::read(&records[at + 4..at + 4 + n]).unwrap();
        match record {
            Record::ObjectHeader { locator, header } => {
                assert_eq!(locator.to_vec(), bytes(&family["locator"]));
                stored.extend_from_slice(&(header.len() as u32).to_be_bytes());
                stored.extend_from_slice(&header);
            }
            Record::ObjectChunk { index, chunk, .. } => {
                assert_eq!(index, chunks);
                chunks += 1;
                stored.extend_from_slice(&chunk);
            }
            other => panic!("{other:?}"),
        }
        at += 4 + n;
    }
    assert_eq!(stored, bytes(&family["stored_object"]));
}
