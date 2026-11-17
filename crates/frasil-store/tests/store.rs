//! The `Store` backends, the device-bound slot, forgetting a log, and the
//! mark before commit through a restore (at-rest.md, "What the application
//! provides", "Committing", "Forgetting a log, and re-keying",
//! "Continuity", "After a restore").

mod common;

use common::ready;
use frasil_crypto::device::DeviceId;
use frasil_store::tables::{LogKind, LogRecord, Secret, Table, TableValue};
use frasil_store::{
    Commit, Continuity, DeviceBoundSlot, Head, MemorySlot, MemoryStore, RestoreMode, Store,
    StoreKeys, Tip, after_restore, continuity, forget_log, open_mark, open_record, seal_mark_with,
    seal_record_with,
};

fn put(address: &[u8], record: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (address.to_vec(), record.to_vec())
}

/// What every store must do: get, scan in address order, and commit
/// atomically under its expectations.
fn exercise(store: &dyn Store) {
    assert_eq!(ready(store.get(b"a")), Ok(None));
    assert_eq!(ready(store.scan(b"")), Ok(Vec::new()));

    let made = ready(store.commit(&Commit::new(
        vec![
            put(&[1, 0xff, 2], b"c"),
            put(&[1, 0xff], b"b"),
            put(&[2], b"d"),
            put(&[1], b"a"),
            put(&[0xff, 0xff], b"e"),
        ],
        Vec::new(),
    )));
    assert_eq!(made, Ok(true));
    assert_eq!(ready(store.get(&[1, 0xff])), Ok(Some(b"b".to_vec())));
    assert_eq!(
        ready(store.scan(&[1])),
        Ok(vec![
            put(&[1], b"a"),
            put(&[1, 0xff], b"b"),
            put(&[1, 0xff, 2], b"c"),
        ])
    );
    assert_eq!(
        ready(store.scan(&[1, 0xff])),
        Ok(vec![put(&[1, 0xff], b"b"), put(&[1, 0xff, 2], b"c")])
    );
    assert_eq!(
        ready(store.scan(&[0xff])),
        Ok(vec![put(&[0xff, 0xff], b"e")])
    );
    assert_eq!(ready(store.scan(b"")).map(|all| all.len()), Ok(5));

    // An expectation that does not hold changes nothing.
    let refused = Commit::new(vec![put(&[3], b"f")], vec![vec![1]]).expecting(&[2], Some(b"x"));
    assert_eq!(ready(store.commit(&refused)), Ok(false));
    assert_eq!(ready(store.get(&[3])), Ok(None));
    assert_eq!(ready(store.get(&[1])), Ok(Some(b"a".to_vec())));
    let absent = Commit::new(vec![put(&[3], b"f")], Vec::new()).expecting(&[2], None);
    assert_eq!(ready(store.commit(&absent)), Ok(false));

    // Expectations that hold: deletes, then puts.
    let commit = Commit::new(
        vec![put(&[3], b"f"), put(&[2], b"g")],
        vec![vec![1], vec![2]],
    )
    .expecting(&[2], Some(b"d"))
    .expecting(&[3], None);
    assert_eq!(ready(store.commit(&commit)), Ok(true));
    assert_eq!(ready(store.get(&[1])), Ok(None));
    assert_eq!(ready(store.get(&[2])), Ok(Some(b"g".to_vec())));
    assert_eq!(ready(store.get(&[3])), Ok(Some(b"f".to_vec())));
    // Deleting what is not held is nothing.
    assert_eq!(
        ready(store.commit(&Commit::new(Vec::new(), vec![vec![9, 9]]))),
        Ok(true)
    );

    // A batch: each commit is judged against what the ones before it left.
    let first = Commit::new(vec![put(&[4], b"h")], Vec::new()).expecting(&[4], None);
    let second = Commit::new(vec![put(&[4], b"i")], Vec::new()).expecting(&[4], Some(b"h"));
    let third = Commit::new(vec![put(&[5], b"j")], Vec::new()).expecting(&[4], None);
    assert_eq!(
        ready(store.commit_all(&[first, second, third])),
        Ok(vec![true, true, false])
    );
    assert_eq!(ready(store.get(&[4])), Ok(Some(b"i".to_vec())));
    assert_eq!(ready(store.get(&[5])), Ok(None));
    assert_eq!(ready(store.commit_all(&[])), Ok(Vec::new()));
}

/// A store that keeps `Store`'s default `commit_all`: one commit at a time.
struct OneByOne(MemoryStore);

impl Store for OneByOne {
    fn get<'a>(
        &'a self,
        address: &'a [u8],
    ) -> frasil_store::BoxFuture<'a, Result<Option<Vec<u8>>, frasil_store::StoreError>> {
        self.0.get(address)
    }

    fn scan<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> frasil_store::BoxFuture<'a, Result<frasil_store::store::Records, frasil_store::StoreError>>
    {
        self.0.scan(prefix)
    }

    fn commit<'a>(
        &'a self,
        commit: &'a Commit,
    ) -> frasil_store::BoxFuture<'a, Result<bool, frasil_store::StoreError>> {
        self.0.commit(commit)
    }
}

/// Forgetting a log deletes its `log` record, then every record under its
/// scope tag, and nothing of another log or of the device.
fn forgets_a_log(store: &dyn Store) {
    let keys = StoreKeys::new(&[1; 32]);
    let (space, other) = ([2u8; 32], [3u8; 32]);
    let mut puts = Vec::new();
    for (i, log) in [space, other].into_iter().enumerate() {
        let log_key = [10 + u8::try_from(i).unwrap(); 32];
        let record = TableValue::Log(LogRecord {
            kind: LogKind::Space,
            log_key: Secret::new(log_key),
        });
        let sealed = seal_record_with(
            &keys,
            None,
            Table::Log,
            &log,
            &record.encode(),
            &[i as u8; 24],
        )
        .unwrap();
        puts.push(put(&sealed.address, &sealed.record));
        let log_keys = keys.log(&log, &log_key);
        for seq in 1..=3u64 {
            let item = [&[7u8; 32][..], &seq.to_be_bytes()].concat();
            let sealed = seal_record_with(
                &keys,
                Some(&log_keys),
                Table::Outbox,
                &item,
                &[8; 32],
                &[0; 24],
            )
            .unwrap();
            puts.push(put(&sealed.address, &sealed.record));
        }
    }
    let head = seal_record_with(
        &keys,
        None,
        Table::Head,
        b"",
        &Head::new([4; 16]).encode(),
        &[5; 24],
    )
    .unwrap();
    puts.push(put(&head.address, &head.record));
    assert_eq!(
        ready(store.commit(&Commit::new(puts, Vec::new()))),
        Ok(true)
    );
    assert_eq!(ready(store.scan(b"")).unwrap().len(), 9);

    ready(forget_log(store, &keys, &space)).unwrap();
    let left = ready(store.scan(b"")).unwrap();
    assert_eq!(left.len(), 5);
    assert!(
        ready(store.scan(&keys.scope_tag(&space)))
            .unwrap()
            .is_empty()
    );
    assert_eq!(ready(store.scan(&keys.scope_tag(&other))).unwrap().len(), 3);
    let log_record = keys.address(Table::Log, &space).unwrap();
    assert_eq!(ready(store.get(&log_record)), Ok(None));
    assert!(
        ready(store.get(&keys.address(Table::Log, &other).unwrap()))
            .unwrap()
            .is_some()
    );
}

#[test]
fn memory_store() {
    exercise(&MemoryStore::new());
    forgets_a_log(&MemoryStore::new());
    exercise(&OneByOne(MemoryStore::new()));
}

#[test]
fn memory_slot() {
    let slot = MemorySlot::new();
    assert_eq!(ready(slot.read()), Ok(None));
    ready(slot.write(&[1, 2, 3])).unwrap();
    assert_eq!(ready(slot.read()), Ok(Some(vec![1, 2, 3])));
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use frasil_store::SqliteStore;
    use std::path::PathBuf;

    fn path(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("frasil-store");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}-{}.sqlite", std::process::id()));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        path
    }

    #[test]
    fn sqlite_store() {
        exercise(&SqliteStore::open_in_memory().unwrap());
        forgets_a_log(&SqliteStore::open_in_memory().unwrap());
        exercise(&SqliteStore::open(path("exercise")).unwrap());
    }

    /// Whether `needle` is anywhere in the store's files: the database and
    /// its write-ahead log.
    fn on_disk(path: &std::path::Path, needle: &[u8]) -> bool {
        ["", "-wal"].iter().any(|suffix| {
            std::fs::read(format!("{}{suffix}", path.display()))
                .is_ok_and(|bytes| bytes.windows(needle.len()).any(|w| w == needle))
        })
    }

    /// After a log is forgotten, neither the database file nor its
    /// write-ahead log holds a copy of its `log` record or of its records
    /// (at-rest.md, "Forgetting a log, and re-keying").
    #[test]
    fn a_forgotten_log_leaves_no_copy_in_the_file() {
        let path = path("forget");
        let store = SqliteStore::open(&path).unwrap();
        let keys = StoreKeys::new(&[1; 32]);
        let space = [2u8; 32];
        let log_key = [10u8; 32];
        let log_record = seal_record_with(
            &keys,
            None,
            Table::Log,
            &space,
            &TableValue::Log(LogRecord {
                kind: LogKind::Space,
                log_key: Secret::new(log_key),
            })
            .encode(),
            &[1; 24],
        )
        .unwrap();
        let log_keys = keys.log(&space, &log_key);
        let outbox = seal_record_with(
            &keys,
            Some(&log_keys),
            Table::Outbox,
            &[7u8; 40],
            &[8; 32],
            &[2; 24],
        )
        .unwrap();
        let commit = Commit::new(
            vec![
                put(&log_record.address, &log_record.record),
                put(&outbox.address, &outbox.record),
            ],
            Vec::new(),
        );
        assert_eq!(ready(store.commit(&commit)), Ok(true));
        // The checks read the files this store writes.
        assert!(on_disk(&path, &log_record.record));
        assert!(on_disk(&path, &outbox.record));

        ready(forget_log(&store, &keys, &space)).unwrap();
        assert!(!on_disk(&path, &log_record.record));
        assert!(!on_disk(&path, &outbox.record));
    }

    #[test]
    fn a_commit_outlives_the_connection() {
        let path = path("durable");
        {
            let store = SqliteStore::open(&path).unwrap();
            let commit = Commit::new(vec![put(&[1; 33], b"record")], Vec::new());
            assert_eq!(ready(store.commit(&commit)), Ok(true));
        }
        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(ready(store.get(&[1; 33])), Ok(Some(b"record".to_vec())));
    }

    #[test]
    fn readers_see_what_the_writer_committed() {
        let path = path("readers");
        let store = SqliteStore::open(&path).unwrap();
        for n in 0..(2 * frasil_store::sqlite::READERS as u8) {
            let commit = Commit::new(vec![put(&[n], &[n])], Vec::new());
            assert_eq!(ready(store.commit_all(&[commit])), Ok(vec![true]));
            assert_eq!(ready(store.get(&[n])), Ok(Some(vec![n])));
            assert_eq!(ready(store.scan(b"")).unwrap().len(), usize::from(n) + 1);
        }
        let none = SqliteStore::open_with_readers(&path, 0).unwrap();
        assert_eq!(ready(none.scan(b"")).unwrap().len(), 8);
    }

    #[test]
    fn another_schema_is_refused() {
        let path = path("schema");
        drop(SqliteStore::open(&path).unwrap());
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 2)
            .unwrap();
        assert!(SqliteStore::open(&path).is_err());
    }
}

/// The device's side of "Mark before commit": write the mark for the next
/// generation, then commit the head at it, on the condition that the head
/// is still the one read.
fn sign(
    store: &dyn Store,
    slot: &dyn DeviceBoundSlot,
    keys: &StoreKeys,
    device_id: &DeviceId,
    head: &mut Head,
    tip: Tip,
    nonce: u8,
) {
    let address = keys.address(Table::Head, b"").unwrap();
    let held = ready(store.get(&address)).unwrap();
    let mut next = head.clone();
    next.generation += 1;
    next.set_tip(tip).unwrap();
    let mark = seal_mark_with(
        keys,
        device_id,
        &next.store_id,
        next.generation,
        &[nonce; 24],
    );
    ready(slot.write(&mark)).unwrap();
    let sealed =
        seal_record_with(keys, None, Table::Head, b"", &next.encode(), &[nonce; 24]).unwrap();
    let commit = Commit::new(vec![put(&sealed.address, &sealed.record)], Vec::new())
        .expecting(&address, held.as_deref());
    assert_eq!(ready(store.commit(&commit)), Ok(true));
    *head = next;
}

fn open_head(store: &dyn Store, keys: &StoreKeys) -> Option<Head> {
    let address = keys.address(Table::Head, b"").unwrap();
    let record = ready(store.get(&address)).unwrap()?;
    match open_record(keys, None, &address, &record).ok()?.value {
        TableValue::Head(head) => Some(head),
        _ => None,
    }
}

#[test]
fn a_restore_is_found_and_recorded() {
    let keys = StoreKeys::new(&[1; 32]);
    let device_id = DeviceId([2u8; 32]);
    let space = [3u8; 32];
    let store = MemoryStore::new();
    let slot = MemorySlot::new();
    let mode = RestoreMode::DeviceBound;
    let tip = |seq: u64| Tip {
        log: space,
        author: device_id,
        seq,
        event: [u8::try_from(seq).unwrap(); 32],
    };

    // A store with no head has been lost.
    assert_eq!(
        continuity(&keys, &device_id, mode, None, None),
        Continuity::Restored
    );

    let mut head = Head::new([4; 16]);
    sign(&store, &slot, &keys, &device_id, &mut head, tip(1), 1);
    let mark = ready(slot.read()).unwrap();
    let opened = open_head(&store, &keys);
    assert_eq!(opened.as_ref(), Some(&head));
    assert_eq!(
        continuity(&keys, &device_id, mode, opened.as_ref(), mark.as_deref()),
        Continuity::Current
    );

    // A backup at generation 2; the device signs again; the backup comes
    // back, but the device-bound slot keeps the mark at 3.
    let backup = ready(store.scan(b"")).unwrap();
    sign(&store, &slot, &keys, &device_id, &mut head, tip(2), 2);
    let restored = MemoryStore::new();
    assert_eq!(
        ready(restored.commit(&Commit::new(backup, Vec::new()))),
        Ok(true)
    );
    let mark = ready(slot.read()).unwrap().unwrap();
    let old = open_head(&restored, &keys).unwrap();
    assert_eq!(old.generation, 2);
    assert_eq!(
        continuity(&keys, &device_id, mode, Some(&old), Some(&mark)),
        Continuity::Restored
    );

    // The device records it: g is one above the mark's generation, 3.
    let (_, mark_generation) = open_mark(&keys, &device_id, &mark).unwrap();
    let mut recorded = after_restore(&old, Some(mark_generation));
    assert_eq!(recorded.generation, 4);
    assert_eq!(recorded.tips, old.tips);
    assert!(!recorded.may_sign(&space));
    let mark = seal_mark_with(&keys, &device_id, &recorded.store_id, 4, &[9; 24]);
    ready(slot.write(&mark)).unwrap();
    let sealed =
        seal_record_with(&keys, None, Table::Head, b"", &recorded.encode(), &[9; 24]).unwrap();
    let commit = Commit::new(vec![put(&sealed.address, &sealed.record)], Vec::new());
    assert_eq!(ready(restored.commit(&commit)), Ok(true));
    assert_eq!(
        continuity(
            &keys,
            &device_id,
            mode,
            open_head(&restored, &keys).as_ref(),
            Some(&mark)
        ),
        Continuity::Current
    );

    // Synced: the tip is the newer of the two, and the device may sign.
    recorded.set_tip(tip(2)).unwrap();
    recorded.add_synced(&space);
    assert!(recorded.may_sign(&space));
    assert_eq!(recorded.tip(&space, &device_id).map(|t| t.seq), Some(2));
}

#[test]
fn a_second_writer_from_the_same_head_is_refused() {
    let keys = StoreKeys::new(&[1; 32]);
    let store = MemoryStore::new();
    let address = keys.address(Table::Head, b"").unwrap();
    let first = seal_record_with(
        &keys,
        None,
        Table::Head,
        b"",
        &Head::new([1; 16]).encode(),
        &[1; 24],
    )
    .unwrap();
    let commit = |record: &[u8], expected: Option<&[u8]>| {
        Commit::new(vec![put(&address, record)], Vec::new()).expecting(&address, expected)
    };
    assert_eq!(ready(store.commit(&commit(&first.record, None))), Ok(true));
    let mut next = Head::new([1; 16]);
    next.generation = 2;
    let a = seal_record_with(&keys, None, Table::Head, b"", &next.encode(), &[2; 24]).unwrap();
    let b = seal_record_with(&keys, None, Table::Head, b"", &next.encode(), &[3; 24]).unwrap();
    assert_eq!(
        ready(store.commit(&commit(&a.record, Some(&first.record)))),
        Ok(true)
    );
    assert_eq!(
        ready(store.commit(&commit(&b.record, Some(&first.record)))),
        Ok(false)
    );
}

/// A copy made on a reader holds the database as of one commit, reads
/// without changing the file, and commits go on meanwhile.
#[cfg(feature = "sqlite")]
#[test]
fn a_copy_of_the_database_reads_as_it_was() {
    use frasil_store::{Durability, SqliteStore};
    let dir = std::env::temp_dir().join(format!(
        "frasil-store-copy-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = SqliteStore::open_with(dir.join("db.sqlite"), 1, Durability::Cache).unwrap();
    let put = |address: &[u8], record: &[u8]| {
        let commit = frasil_store::Commit::new(vec![(address.to_vec(), record.to_vec())], vec![]);
        assert!(ready(store.commit(&commit)).unwrap());
    };
    put(b"a", b"1");
    put(b"c", b"3");
    let copy = dir.join("copy.sqlite");
    store.copy_into(&copy).unwrap();
    put(b"a", b"2");
    let before = std::fs::read(&copy).unwrap();
    assert_eq!(
        SqliteStore::read_file(&copy, b"a").unwrap(),
        Some(b"1".to_vec())
    );
    assert_eq!(std::fs::read(&copy).unwrap(), before, "read without change");
    assert_eq!(store.next_address(b"a").unwrap(), Some(b"c".to_vec()));
    assert_eq!(store.next_address(b"c").unwrap(), None);
    let _ = std::fs::remove_dir_all(&dir);
}
