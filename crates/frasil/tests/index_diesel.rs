//! Typed Diesel queries over the cache, through the derive's `table!`.
#![cfg(feature = "index-diesel")]

use diesel::prelude::*;
use frasil::index::{Index, Ref, Schema, Table, Time, create_space};
use frasil::{Device, Options, Storage};

#[derive(Debug, Clone, PartialEq, Table)]
#[table(source = "shared")]
struct Topic {
    title: String,
    rank: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Table)]
#[table(source = "personal")]
struct Reply {
    topic: Ref<Topic>,
    at: Time,
    score: f64,
    flagged: bool,
}

// As for any Diesel tables, a join names the tables that meet.
diesel::allow_tables_to_appear_in_same_query!(topic, reply);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diesel_queries_the_cache_and_cannot_write() {
    let dir = std::env::temp_dir().join(format!("frasil-index-diesel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let device = Device::open_with(
        Storage::Memory,
        &[3; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .unwrap();
    let schema = Schema::new().table::<Topic>().table::<Reply>();
    let index = Index::open(&device, dir.join("index.db"), schema)
        .await
        .unwrap();
    let shared = create_space(&device, "shared").await.unwrap();
    let first = shared
        .insert(&Topic {
            title: "First".into(),
            rank: Some(1),
        })
        .await
        .unwrap();
    shared
        .insert(&Topic {
            title: "Second".into(),
            rank: None,
        })
        .await
        .unwrap();
    let mine = create_space(&device, "personal").await.unwrap();
    for score in [0.5, 1.5] {
        mine.insert(&Reply {
            topic: first.clone(),
            at: Time::from_millis(1),
            score,
            flagged: score > 1.0,
        })
        .await
        .unwrap();
    }
    index.sync().await.unwrap();

    let (titles, flagged, joined) = index
        .diesel(|conn| {
            let titles: Vec<(String, Option<i64>)> = topic::table
                .select((topic::title, topic::rank))
                .order(topic::title)
                .load(conn)
                .unwrap();
            let flagged: Vec<f64> = reply::table
                .filter(reply::flagged.eq(true))
                .select(reply::score)
                .load(conn)
                .unwrap();
            let joined: Vec<(String, f64)> = reply::table
                .inner_join(topic::table.on(topic::_key.eq(reply::topic)))
                .select((topic::title, reply::score))
                .order(reply::score)
                .load(conn)
                .unwrap();
            (titles, flagged, joined)
        })
        .unwrap();
    assert_eq!(
        titles,
        vec![("First".to_string(), Some(1)), ("Second".to_string(), None)]
    );
    assert_eq!(flagged, vec![1.5]);
    assert_eq!(
        joined,
        vec![("First".to_string(), 0.5), ("First".to_string(), 1.5)]
    );

    let refused = index
        .diesel(|conn| diesel::delete(topic::table).execute(conn))
        .unwrap();
    assert!(refused.is_err(), "the Diesel connection wrote");
    let refused = index
        .diesel(|conn| {
            diesel::sql_query("PRAGMA query_only = OFF").execute(conn)?;
            diesel::delete(topic::table).execute(conn)
        })
        .unwrap();
    assert!(refused.is_err(), "a read-only file refuses writes");
    assert_eq!(index.all::<Topic>().unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}
