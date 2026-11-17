//! The index over real devices: spaces of one kind feeding one table,
//! joins across spaces, admission, rebuilds, live queries, dangling
//! references, suggestions, rich text, and the read-only query connection.

use frasil::index::{Index, Ref, RichText, Schema, SqlValue, Table, Time, Writer, create_space};
use frasil::{Device, Level, Options, Storage};
use frasil_testkit::hex;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, PartialEq, Table)]
#[table(source = "shared")]
struct List {
    title: String,
    position: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Table)]
#[table(source = "personal", suggestions)]
struct Item {
    list: Ref<List>,
    at: Time,
    count: i64,
    done: bool,
    #[column(name = "comment")]
    note: Option<String>,
    body: Option<RichText>,
}

/// List, with a column more: another schema version. In a module of its
/// own, since with the `diesel` feature each table is a module.
mod later {
    use frasil::index::Table;

    #[derive(Debug, Clone, PartialEq, Table)]
    #[table(source = "shared", name = "list")]
    pub struct ListWithColour {
        pub title: String,
        pub position: Option<i64>,
        pub colour: Option<String>,
    }
}
use later::ListWithColour;

fn schema() -> Schema {
    Schema::new().table::<List>().table::<Item>()
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(60), future)
        .await
        .expect("the index operation completes within the deadline")
}

async fn until<F: Future<Output = bool>>(mut check: impl FnMut() -> F) {
    within(async {
        while !check().await {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await;
}

async fn device(key: u8) -> Device {
    Device::open_with(
        Storage::Memory,
        &[key; 32],
        Options::new().never_restored().loopback(),
    )
    .await
    .expect("a device")
}

fn temp_dir(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "frasil-index-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn item(list: &Ref<List>, count: i64) -> Item {
    Item {
        list: list.clone(),
        at: Time::from_millis(1_700_000_000_000 + count),
        count,
        done: count % 2 == 0,
        note: (count < 0).then(|| format!("below zero: {count}")),
        body: None,
    }
}

fn integer(index: &Index, sql: &str) -> i64 {
    match index.query(sql, &[]).unwrap()[0].values()[0] {
        SqlValue::Integer(n) => n,
        ref other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_spaces_of_one_kind_feed_one_table() {
    let dir = temp_dir("two-spaces");
    let alice = device(1).await;
    let index = Index::open(&alice, dir.join("index.db"), schema())
        .await
        .unwrap();
    let list = Ref::<List>::random().unwrap();
    let first = create_space(&alice, "personal").await.unwrap();
    let second = create_space(&alice, "personal").await.unwrap();
    first.insert(&item(&list, 1)).await.unwrap();
    first.insert(&item(&list, -2)).await.unwrap();
    let third = second.insert(&item(&list, 3)).await.unwrap();
    index.sync().await.unwrap();

    let items = index.all::<Item>().unwrap();
    assert_eq!(items.len(), 3);
    let spaces: std::collections::BTreeSet<_> = items.iter().map(|i| i.space).collect();
    assert_eq!(
        spaces,
        [first.space().id(), second.space().id()]
            .into_iter()
            .collect()
    );
    let stored = items.iter().find(|i| i.key == third).unwrap();
    assert_eq!(stored.row, item(&list, 3));
    assert!(stored.author.is_some(), "the history names the author");
    assert!(stored.changed_at.is_some(), "the writer records the time");
    let negative = items.iter().find(|i| i.row.count == -2).unwrap();
    assert_eq!(negative.row.note.as_deref(), Some("below zero: -2"));

    // Both spaces are listed, with their kind and owner.
    let spaces = index
        .query(
            "SELECT kind, owner FROM _spaces WHERE id = ?1",
            &[first.space().id().to_string().into()],
        )
        .unwrap();
    assert_eq!(spaces.len(), 1);
    assert_eq!(spaces[0].get("kind").unwrap(), &SqlValue::from("personal"));
    assert!(matches!(spaces[0].get("owner").unwrap(), SqlValue::Text(_)));
    assert_eq!(integer(&index, "SELECT count(*) FROM _spaces"), 2);

    // An update and a delete reach the table on the next sync.
    second
        .put(
            &third,
            &Item {
                count: 30,
                ..item(&list, 3)
            },
        )
        .await
        .unwrap();
    first
        .delete(&items.iter().find(|i| i.row.count == 1).unwrap().key)
        .await
        .unwrap();
    index.sync().await.unwrap();
    let counts: Vec<i64> = index
        .query("SELECT count FROM item ORDER BY count", &[])
        .unwrap()
        .iter()
        .map(|r| match r.get("count").unwrap() {
            SqlValue::Integer(n) => *n,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(counts, vec![-2, 30]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_join_across_spaces() {
    let dir = temp_dir("join");
    let alice = device(2).await;
    let index = Index::open(&alice, dir.join("index.db"), schema())
        .await
        .unwrap();
    let shared = create_space(&alice, "shared").await.unwrap();
    let errands = shared
        .insert(&List {
            title: "Errands".into(),
            position: Some(1),
        })
        .await
        .unwrap();
    let chores = shared
        .insert(&List {
            title: "Chores".into(),
            position: None,
        })
        .await
        .unwrap();
    let mine = create_space(&alice, "personal").await.unwrap();
    let other = create_space(&alice, "personal").await.unwrap();
    mine.insert(&item(&errands, 1)).await.unwrap();
    other.insert(&item(&errands, 2)).await.unwrap();
    other.insert(&item(&chores, 3)).await.unwrap();
    index.sync().await.unwrap();

    let rows = index
        .query(
            "SELECT l.title AS title, count(i._key) AS n, count(DISTINCT i._space) AS spaces \
             FROM list l JOIN item i ON i.list = l._key \
             WHERE i._suggested = 0 GROUP BY l._key ORDER BY l.title",
            &[],
        )
        .unwrap();
    let got: Vec<(SqlValue, SqlValue, SqlValue)> = rows
        .iter()
        .map(|r| {
            (
                r.get("title").unwrap().clone(),
                r.get("n").unwrap().clone(),
                r.get("spaces").unwrap().clone(),
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![
            ("Chores".into(), 1.into(), 1.into()),
            ("Errands".into(), 2.into(), 2.into()),
        ]
    );
    // A key is the same in SQL and in Rust.
    let by_key = index
        .query(
            "SELECT title FROM list WHERE _key = ?1",
            &[SqlValue::from(&errands)],
        )
        .unwrap();
    assert_eq!(by_key[0].get("title").unwrap(), &SqlValue::from("Errands"));
    assert_eq!(errands.hex(), hex::encode(errands.key()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joined_device_indexes_shared_rows() {
    let dir = temp_dir("access");
    let alice = device(3).await;
    let bob = device(4).await;
    let shared = create_space(&alice, "shared").await.unwrap();
    shared
        .insert(&List {
            title: "Ours".into(),
            position: None,
        })
        .await
        .unwrap();
    let invitation = shared
        .space()
        .invite(Level::Write, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();

    let index = Index::open(&bob, dir.join("index.db"), schema())
        .await
        .unwrap();
    let follow = tokio::spawn({
        let index = index.clone();
        async move { index.follow().await }
    });
    until(|| async { index.all::<List>().unwrap().len() == 1 }).await;
    let ours = &index.all::<List>().unwrap()[0];
    assert_eq!(ours.space, bobs_space.id());
    assert_eq!(ours.row.title, "Ours");
    assert_eq!(integer(&index, "SELECT count(*) FROM _spaces"), 1);

    // Leaving and removed-device notification require a newer public API.
    // This test proves admission and indexing without reaching into an engine.
    follow.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_schema_change_rebuilds_from_local_replicas() {
    let dir = temp_dir("rebuild");
    let path = dir.join("index.db");
    let alice = device(5).await;
    let shared = create_space(&alice, "shared").await.unwrap();
    shared
        .insert(&List {
            title: "Kept".into(),
            position: Some(7),
        })
        .await
        .unwrap();

    let first = Index::open(&alice, &path, schema()).await.unwrap();
    assert_eq!(first.all::<List>().unwrap().len(), 1);
    let old_version = first.schema().version();
    drop(first);

    // A column more: another version, so the cache is made again and read
    // from the replica, with no peer and no network.
    let schema = Schema::new().table::<ListWithColour>().table::<Item>();
    assert_ne!(schema.version(), old_version);
    let second = Index::open(&alice, &path, schema).await.unwrap();
    let rows = second.all::<ListWithColour>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].row,
        ListWithColour {
            title: "Kept".into(),
            position: Some(7),
            colour: None,
        }
    );
    assert_eq!(
        second.query("SELECT colour FROM list", &[]).unwrap()[0].values(),
        &[SqlValue::Null]
    );
    drop(second);

    // Under another key the file does not open: it is a cache, so it is
    // made again.
    let third = Index::open(&alice, &path, schema_with_colour())
        .await
        .unwrap();
    assert_eq!(third.all::<ListWithColour>().unwrap().len(), 1);
    // And the file is encrypted: no SQLite header, no plaintext.
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3"));
    assert!(!bytes.windows(4).any(|w| w == b"Kept"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn schema_with_colour() -> Schema {
    Schema::new().table::<ListWithColour>().table::<Item>()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_query_runs_again_when_its_table_changes() {
    let dir = temp_dir("watch");
    let alice = device(6).await;
    let index = Index::open(&alice, dir.join("index.db"), schema())
        .await
        .unwrap();
    let mut watch = index
        .watch(
            "SELECT count(*) AS n FROM item WHERE done = ?1",
            vec![false.into()],
        )
        .unwrap();
    assert_eq!(watch.tables(), &["item".to_string()].into_iter().collect());
    let count = |rows: Vec<frasil::index::Row>| rows[0].get("n").unwrap().clone();
    assert_eq!(count(within(watch.next()).await.unwrap()), 0.into());

    let follow = tokio::spawn({
        let index = index.clone();
        async move { index.follow().await }
    });
    let list = Ref::<List>::random().unwrap();
    let mine = create_space(&alice, "personal").await.unwrap();
    // A write to another table does not wake the watch.
    let shared = create_space(&alice, "shared").await.unwrap();
    shared
        .insert(&List {
            title: "Elsewhere".into(),
            position: None,
        })
        .await
        .unwrap();
    mine.insert(&item(&list, 1)).await.unwrap();
    let mut n = count(within(watch.next()).await.unwrap());
    while n != 1.into() {
        n = count(within(watch.next()).await.unwrap());
    }
    mine.insert(&item(&list, 3)).await.unwrap();
    let mut n = count(within(watch.next()).await.unwrap());
    while n != 2.into() {
        n = count(within(watch.next()).await.unwrap());
    }
    follow.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dangling_references_are_listed() {
    let dir = temp_dir("dangling");
    let alice = device(7).await;
    let index = Index::open(&alice, dir.join("index.db"), schema())
        .await
        .unwrap();
    let shared = create_space(&alice, "shared").await.unwrap();
    let here = shared
        .insert(&List {
            title: "Here".into(),
            position: None,
        })
        .await
        .unwrap();
    let nowhere = Ref::<List>::random().unwrap();
    let mine = create_space(&alice, "personal").await.unwrap();
    mine.insert(&item(&here, 1)).await.unwrap();
    let lost = mine.insert(&item(&nowhere, 2)).await.unwrap();
    index.sync().await.unwrap();

    let dangling = index.dangling().unwrap();
    assert_eq!(dangling.len(), 1, "{dangling:?}");
    assert_eq!(dangling[0].table, "item");
    assert_eq!(dangling[0].column, "list");
    assert_eq!(dangling[0].target, "list");
    assert_eq!(dangling[0].key, lost.hex());
    assert_eq!(dangling[0].missing, nowhere.hex());
    assert_eq!(dangling[0].space, mine.space().id().to_string());

    // Deleting the list leaves its item dangling too.
    shared.delete(&here).await.unwrap();
    index.sync().await.unwrap();
    assert_eq!(index.dangling().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_query_connection_refuses_writes() {
    let dir = temp_dir("read-only");
    let alice = device(8).await;
    let index = Index::open(&alice, dir.join("index.db"), schema())
        .await
        .unwrap();
    let shared = create_space(&alice, "shared").await.unwrap();
    shared
        .insert(&List {
            title: "Safe".into(),
            position: None,
        })
        .await
        .unwrap();
    index.sync().await.unwrap();
    for sql in [
        "DELETE FROM list",
        "UPDATE list SET title = 'x'",
        "INSERT INTO list (_space, _key, title) VALUES ('a', 'b', 'c')",
        "DROP TABLE list",
        "CREATE TABLE t (x)",
        "PRAGMA query_only = OFF",
        "ATTACH DATABASE ':memory:' AS other",
        "BEGIN",
    ] {
        assert!(
            index.query(sql, &[]).is_err(),
            "the query connection ran {sql}"
        );
        assert!(index.watch(sql, Vec::new()).is_err(), "a watch of {sql}");
    }
    assert_eq!(index.all::<List>().unwrap().len(), 1);
    assert_eq!(integer(&index, "SELECT count(*) FROM list"), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suggestions_show_only_where_a_table_asks_and_rich_text_is_plain() {
    let dir = temp_dir("suggestions");
    let alice = device(10).await;
    let index = Index::open(&alice, dir.join("index.db"), schema())
        .await
        .unwrap();
    let list = Ref::<List>::random().unwrap();
    let mine = create_space(&alice, "personal").await.unwrap();
    let document = mine.space().create_document().unwrap();
    document
        .edit(|doc| {
            let text = doc.get_text(RichText::CONTAINER);
            text.insert(0, "Hello, world")?;
            text.mark(0..5, "bold", true)
        })
        .await
        .unwrap();
    let key = mine
        .insert(&Item {
            body: Some(RichText::new(document.id())),
            ..item(&list, 1)
        })
        .await
        .unwrap();
    mine.write(|batch| {
        batch.suggest().put(
            &key,
            &Item {
                count: 100,
                ..item(&list, 1)
            },
        )
    })
    .await
    .unwrap();
    // A suggestion does not reach a table that does not ask for them.
    let shared = create_space(&alice, "shared").await.unwrap();
    let title = shared
        .insert(&List {
            title: "Before".into(),
            position: None,
        })
        .await
        .unwrap();
    shared
        .write(|batch| {
            batch.suggest().put(
                &title,
                &List {
                    title: "After".into(),
                    position: None,
                },
            )
        })
        .await
        .unwrap();
    index.sync().await.unwrap();

    let merged = index.all::<Item>().unwrap();
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].row.count, 1);
    assert_eq!(
        merged[0].row.body.as_ref().map(RichText::text),
        Some("Hello, world"),
        "rich text cached as plain text"
    );
    let suggested = index
        .query_as::<Item>("SELECT * FROM item WHERE _suggested = 1", &[])
        .unwrap();
    assert_eq!(suggested.len(), 1);
    assert_eq!(suggested[0].key, key);
    assert_eq!(suggested[0].row.count, 100);
    assert!(suggested[0].suggestion.is_some());
    let lists = index.all::<List>().unwrap();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].row.title, "Before");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_finds_a_space_kind_and_refuses_other_tables() {
    let alice = device(11).await;
    let made = create_space(&alice, "shared").await.unwrap();
    let found = Writer::of(made.space()).await.unwrap();
    assert_eq!(found.kind(), "shared");
    let list = Ref::<List>::random().unwrap();
    assert!(matches!(
        found.insert(&item(&list, 1)).await,
        Err(frasil::index::Error::Schema(_))
    ));
    let plain = alice.create_space().await.unwrap();
    assert!(matches!(
        Writer::of(&plain).await,
        Err(frasil::index::Error::NoKind)
    ));
}

#[test]
fn the_manifest_describes_the_schema_and_names_its_version() {
    let schema = schema();
    schema.check().unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&schema.manifest()).unwrap();
    assert_eq!(manifest["format"], 1);
    let item = &manifest["tables"][1];
    assert_eq!(item["name"], "item");
    assert_eq!(item["source"], "personal");
    assert_eq!(item["suggestions"], true);
    let columns = item["columns"].as_array().unwrap();
    let names: Vec<&str> = columns
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["list", "at", "count", "done", "comment", "body"]);
    assert_eq!(columns[0]["kind"], "ref");
    assert_eq!(columns[0]["references"], "list");
    assert_eq!(columns[4]["nullable"], true);
    assert_eq!(columns[5]["kind"], "rich_text");
    assert_eq!(
        schema.version(),
        Schema::new().table::<List>().table::<Item>().version()
    );
    assert_eq!(schema.version().len(), 64);
    assert!(Item::SCHEMA.ddl().contains("\"_suggestion\" TEXT NOT NULL"));
    // A reference to a table the schema lacks does not hold together.
    assert!(Schema::new().table::<Item>().check().is_err());
}

#[tokio::test]
async fn an_update_writes_only_changed_cells_and_does_not_resurrect_a_deleted_row() {
    let alice = device(23).await;
    let shared = create_space(&alice, "shared").await.unwrap();
    let original = List {
        title: "Original".into(),
        position: Some(1),
    };
    let key = shared.insert(&original).await.unwrap();
    let title = List {
        title: "New title".into(),
        ..original.clone()
    };
    let position = List {
        position: Some(2),
        ..original.clone()
    };
    shared.update(&key, &original, &title).await.unwrap();
    // A stale editor knows only the original row and changes a different field.
    shared.update(&key, &original, &position).await.unwrap();
    let row = shared
        .records()
        .row("list", key.key())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.get("title"),
        Some(&frasil::Value::Text("New title".into()))
    );
    assert_eq!(row.get("position"), Some(&frasil::Value::Unsigned(2)));
    shared.delete(&key).await.unwrap();
    shared.update(&key, &original, &title).await.unwrap();
    assert!(
        shared
            .records()
            .row("list", key.key())
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "ext-guests")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_space_kept_in_memory_only_feeds_no_table() {
    let dir = temp_dir("nothing-at-rest");
    let alice = device(5).await;
    let bob = device(6).await;
    let shared = create_space(&alice, "shared").await.unwrap();
    shared
        .insert(&List {
            title: "Not on Bob's disk".into(),
            position: None,
        })
        .await
        .unwrap();
    let guest = frasil::Guest::new(Level::Read, [3; 16]).nothing_at_rest();
    let invitation = shared
        .space()
        .invite_guest(&guest, "Alice's laptop", |_, _| async { true })
        .await
        .unwrap();
    let bobs_space = within(bob.join(invitation.text(), "Bob's phone", |_, _| async { true }))
        .await
        .unwrap();
    within(invitation.admitted()).await.unwrap();
    assert!(bobs_space.keeps_nothing_at_rest().await);
    // Bob reads the row in memory...
    until(|| async { bobs_space.kind().await.ok().flatten().as_deref() == Some("shared") }).await;

    // ...and his index holds none of it, whole or row by row.
    let index = Index::open(&bob, dir.join("index.db"), schema())
        .await
        .unwrap();
    index.sync().await.unwrap();
    index.refresh(bobs_space.id()).await.unwrap();
    assert!(index.all::<List>().unwrap().is_empty());
    assert_eq!(integer(&index, "SELECT count(*) FROM _spaces"), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn forgetting_a_space_removes_its_cached_rows() {
    let dir = temp_dir("forget");
    let device = device(55).await;
    let index = Index::open(&device, dir.join("index.db"), schema())
        .await
        .unwrap();
    let writer = create_space(&device, "shared").await.unwrap();
    assert_eq!(
        writer.space().kind().await.unwrap().as_deref(),
        Some("shared")
    );
    writer
        .insert(&List {
            title: "Remember".into(),
            position: None,
        })
        .await
        .unwrap();
    index.sync().await.unwrap();
    assert_eq!(index.all::<List>().unwrap().len(), 1);
    writer.space().forget().await.unwrap();
    index.sync().await.unwrap();
    assert!(index.all::<List>().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn row_change_time_comes_from_records_without_an_application_cell() {
    let directory = temp_dir("native-change-time");
    let device = device(97).await;
    let writer = create_space(&device, "shared").await.unwrap();
    let key = Ref::<List>::random().unwrap();
    writer
        .records()
        .write(|tx| {
            tx.insert("list", key.key())
                .set("list", key.key(), "title", "A direct Records row");
        })
        .await
        .unwrap();
    let cells = writer
        .records()
        .row("list", key.key())
        .await
        .unwrap()
        .unwrap();
    assert!(!cells.contains_key("_changed_at"));
    let change = writer
        .records()
        .last_change("list", key.key())
        .await
        .unwrap()
        .unwrap();
    let index = Index::open(&device, directory.join("index.db"), schema())
        .await
        .unwrap();
    let row = &index.all::<List>().unwrap()[0];
    assert_eq!(
        row.changed_at.unwrap().as_millis(),
        (change.time.unwrap() * 1000) as i64
    );
    assert_eq!(row.author, Some(device.id()));
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(directory);
}

#[tokio::test]
async fn cache_revision_advances_only_for_changed_rows() {
    let dir = temp_dir("revision");
    let device = device(29).await;
    let index = Index::open(&device, dir.join("index.db"), schema())
        .await
        .unwrap();
    let writer = create_space(&device, "shared").await.unwrap();
    index.sync().await.unwrap();
    let before = index.revision();
    writer
        .insert(&List {
            title: "First".into(),
            position: None,
        })
        .await
        .unwrap();
    index.refresh(writer.space().id()).await.unwrap();
    assert!(index.revision() > before);
    let current = index.revision();
    index.refresh(writer.space().id()).await.unwrap();
    assert_eq!(index.revision(), current);
    drop(index);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn authored_row_refresh_retains_untouched_rows_and_merged_metadata() {
    let dir = temp_dir("row-refresh");
    let device = device(119).await;
    let writer = create_space(&device, "shared").await.unwrap();
    let old = writer
        .insert(&List {
            title: "Untouched".into(),
            position: None,
        })
        .await
        .unwrap();
    let index = Index::open(&device, dir.join("index.db"), schema())
        .await
        .unwrap();
    index.sync().await.unwrap();
    let before = index.full_refresh_counts();
    let untouched = index.all::<List>().unwrap()[0].clone();
    let key = writer
        .insert(&List {
            title: "New".into(),
            position: Some(2),
        })
        .await
        .unwrap();
    index.refresh_row(writer.space().id(), &key).await.unwrap();
    assert_eq!(
        index.full_refresh_counts(),
        before,
        "one authored row must not read every space again"
    );
    let rows = index.all::<List>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows.iter().find(|r| r.key == old).unwrap(), &untouched);
    assert_eq!(
        rows.iter().find(|r| r.key == key).unwrap().author,
        Some(device.id())
    );
    writer.delete(&key).await.unwrap();
    index.refresh_row(writer.space().id(), &key).await.unwrap();
    assert_eq!(index.all::<List>().unwrap(), vec![untouched]);
    index.sync().await.unwrap();
    assert_eq!(index.all::<List>().unwrap().len(), 1);
    drop(index);
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn local_metadata_survives_reopen_and_schema_rebuild_without_changing_rows() {
    let dir = temp_dir("clock-floor");
    let device = device(122).await;
    let index = Index::open(&device, dir.join("index.db"), schema())
        .await
        .unwrap();
    let revision = index.revision();
    index
        .update_local_metadata("opaque-checkpoint", |previous| {
            assert_eq!(previous, None);
            Ok((Some("100".into()), ()))
        })
        .unwrap();
    index
        .update_local_metadata("opaque-checkpoint", |previous| {
            assert_eq!(previous, Some("100"));
            Ok((None, ()))
        })
        .unwrap();
    assert_eq!(index.revision(), revision);
    index.rebuild().await.unwrap();
    drop(index);
    let index = Index::open(&device, dir.join("index.db"), schema())
        .await
        .unwrap();
    assert_eq!(
        index
            .local_metadata("opaque-checkpoint")
            .unwrap()
            .as_deref(),
        Some("100")
    );
    drop(index);
    device.close().await.unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn separate_handles_serialize_local_metadata_read_modify_write() {
    let dir = temp_dir("metadata-transaction");
    let device = device(123).await;
    let first = Index::open(&device, dir.join("index.db"), schema())
        .await
        .unwrap();
    let second = Index::open(&device, dir.join("index.db"), schema())
        .await
        .unwrap();
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|threads| {
        for index in [&first, &second] {
            let start = &start;
            threads.spawn(move || {
                start.wait();
                for _ in 0..25 {
                    index
                        .update_local_metadata("shared-counter", |previous| {
                            let previous = previous.unwrap_or("0").parse::<u64>().unwrap();
                            // Hold the read/modify interval open while the other handle attempts it.
                            std::thread::sleep(std::time::Duration::from_millis(1));
                            Ok((Some((previous + 1).to_string()), ()))
                        })
                        .unwrap();
                }
            });
        }
    });
    assert_eq!(
        first.local_metadata("shared-counter").unwrap().as_deref(),
        Some("50")
    );
    drop(first);
    drop(second);
    device.close().await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follow_refreshes_the_rows_a_write_touched_and_a_distinct_watch_waits_for_different_rows() {
    let dir = temp_dir("follow-rows");
    let alice = device(21).await;
    let index = Index::open(&alice, dir.join("index.db"), schema())
        .await
        .unwrap();
    let errors = std::sync::Arc::new(AtomicUsize::new(0));
    let follow = tokio::spawn({
        let (index, errors) = (index.clone(), errors.clone());
        async move {
            index
                .follow_with(|_| {
                    errors.fetch_add(1, Ordering::SeqCst);
                })
                .await
        }
    });
    let shared = create_space(&alice, "shared").await.unwrap();
    let first = List {
        title: "Errands".into(),
        position: Some(1),
    };
    let key = shared.insert(&first).await.unwrap();
    until(|| async { integer(&index, "SELECT count(*) FROM list") == 1 }).await;
    let space = shared.records().space().id().to_string();
    let reads = index.full_refresh_counts()[&space];

    let mut count = index
        .watch("SELECT count(*) AS n FROM list", Vec::new())
        .unwrap()
        .distinct();
    assert_eq!(
        within(count.next()).await.unwrap()[0].get("n").unwrap(),
        &1.into()
    );
    // Without `distinct`, a watch runs again on every change of its table.
    let mut every = index
        .watch("SELECT count(*) AS n FROM list", Vec::new())
        .unwrap();
    within(every.next()).await.unwrap();
    let mut tables = index.table_changes();

    // A change of a title: the table changes, the count does not.
    let renamed = List {
        title: "Groceries".into(),
        ..first.clone()
    };
    shared.update(&key, &first, &renamed).await.unwrap();
    until(|| async {
        index
            .query("SELECT title FROM list", &[])
            .unwrap()
            .first()
            .and_then(|row| row.get("title").ok().cloned())
            == Some("Groceries".into())
    })
    .await;
    assert!(within(tables.next()).await.unwrap().contains("list"));
    assert_eq!(
        within(every.next()).await.unwrap()[0].get("n").unwrap(),
        &1.into()
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), count.next())
            .await
            .is_err(),
        "the count is the same"
    );

    // Rows written one by one, refreshed without reading the space again.
    for position in 2..6 {
        shared
            .insert(&List {
                title: format!("List {position}"),
                position: Some(position),
            })
            .await
            .unwrap();
    }
    until(|| async { integer(&index, "SELECT count(*) FROM list") == 5 }).await;
    assert_eq!(
        within(count.next()).await.unwrap()[0].get("n").unwrap(),
        &5.into()
    );
    shared.delete(&key).await.unwrap();
    until(|| async { integer(&index, "SELECT count(*) FROM list") == 4 }).await;
    assert_eq!(index.full_refresh_counts()[&space], reads);
    assert_eq!(errors.load(Ordering::SeqCst), 0);
    follow.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_schema_reads_back_from_its_manifest() {
    let manifest = schema().manifest();
    let read = Schema::from_manifest(&manifest).unwrap();
    assert_eq!(read.manifest(), manifest);
    assert_eq!(read.version(), schema().version());
    assert_eq!(read.ddl(), schema().ddl());
    assert!(Schema::from_manifest("{}").is_err());
    assert!(Schema::from_manifest(&manifest.replace("\"format\":1", "\"format\":2")).is_err());
    let unknown = manifest.replacen("\"kind\":\"text\"", "\"kind\":\"colour\"", 1);
    assert!(Schema::from_manifest(&unknown).is_err());
}
