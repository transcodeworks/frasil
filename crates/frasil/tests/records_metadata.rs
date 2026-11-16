//! A table's rows with their last changes, read in one pass, give what
//! `Records::rows` and `Records::last_change` give row by row, the author's
//! person included (adapter-records.md, section 2.3, "last change").
#![cfg(feature = "adapter-records")]

use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil::{Device, MemberId, Options, Records};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};

async fn engine(key: u8) -> Engine {
    Engine::create(
        Platform::memory(),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    let ingested = to.ingest(space, from.events(&space).await).await.unwrap();
    assert!(ingested.refused.is_empty(), "{:?}", ingested.refused);
}

fn device(engine: Engine) -> Device {
    Device::from_engine(engine, Options::new().loopback()).expect("a device")
}

/// Every visible row of `table`, read both ways, agrees.
async fn assert_equivalent(records: &Records, table: &str) {
    let rows = records.rows(table).await.unwrap();
    let with = records.rows_with_metadata(table).await.unwrap();
    assert_eq!(
        rows.keys().collect::<Vec<_>>(),
        with.keys().collect::<Vec<_>>()
    );
    for (key, row) in &rows {
        let found = &with[key];
        assert_eq!(&found.row, row);
        let last = records.last_change(table, key).await.unwrap().unwrap();
        assert_eq!(found.last_change, last);
        let one = records.row_with_metadata(table, key).await.unwrap();
        assert_eq!(one.as_ref(), Some(found));
        assert_eq!(records.row(table, key).await.unwrap().as_ref(), Some(row));
    }
}

#[tokio::test]
async fn rows_with_metadata_match_last_change_row_by_row() {
    let alice = engine(1).await;
    let phone = engine(2).await;
    let space = alice.create_space().await.unwrap();
    let person = phone.make_person(&[2; 32]).await.unwrap().person;
    alice
        .receive_list(phone.list_events(&person).await)
        .await
        .unwrap();
    alice
        .grant_person(
            space,
            person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    alice.publish_list(space, &person).await.unwrap();
    let alice_id = MemberId::from_bytes(alice.device_id().0);
    let phone_id = MemberId::from_bytes(phone.device_id().0);

    let alice = device(alice);
    let shared = alice
        .space(frasil::SpaceId::from_bytes(space.0))
        .await
        .unwrap();
    let records = shared.create_records().unwrap();
    records
        .write(|t| {
            t.insert("notes", b"a")
                .set("notes", b"a", "title", "Alice's");
            t.insert("notes", b"b")
                .set("notes", b"b", "title", "Shared");
            t.insert("notes", b"gone")
                .set("notes", b"gone", "title", "x");
            t.insert("other", b"o").set("other", b"o", "n", 1u64);
        })
        .await
        .unwrap();
    records
        .write(|t| {
            t.delete("notes", b"gone");
        })
        .await
        .unwrap();

    phone.follow(space).await;
    carry(alice.engine(), &phone, space).await;
    let phone = device(phone);
    let phones = phone
        .space(frasil::SpaceId::from_bytes(space.0))
        .await
        .unwrap()
        .records(records.id())
        .await
        .unwrap();
    phones
        .write(|t| {
            t.set("notes", b"b", "body", "from the phone");
            t.insert("notes", b"p")
                .set("notes", b"p", "title", "Phone's");
        })
        .await
        .unwrap();
    carry(phone.engine(), alice.engine(), space).await;

    assert_equivalent(&records, "notes").await;
    assert_equivalent(&phones, "notes").await;
    assert_equivalent(&records, "other").await;
    assert!(records.rows_with_metadata("none").await.unwrap().is_empty());
    assert_eq!(
        records.row_with_metadata("notes", b"gone").await.unwrap(),
        None
    );
    assert_eq!(
        records.row_with_metadata("notes", b"none").await.unwrap(),
        None
    );

    let rows = records.rows_with_metadata("notes").await.unwrap();
    let a = rows[b"a".as_slice()].last_change;
    assert_eq!((a.author, a.person, a.who()), (alice_id, None, alice_id));
    for key in [b"b".as_slice(), b"p"] {
        let last = rows[key].last_change;
        assert_eq!(last.author, phone_id);
        assert_eq!(last.person, Some(MemberId::from_bytes(person)));
        assert_eq!(last.who(), MemberId::from_bytes(person));
    }
    assert_eq!(
        rows[b"b".as_slice()].row.get("body"),
        Some(&frasil::Value::Text("from the phone".into()))
    );
}
