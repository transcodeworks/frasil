//! A snapshot state's `main` is screened before the pinned Loro reads it
//! (adapter-loro.md, 3.5 Compaction and history-free export, "Loading a
//! state"). Snapshot exports are crafted with every checksum right, so that
//! each reaches Loro's decoder, and each hazard is refused; the same
//! construction around honest entries passes, so that each refusal is the
//! hazard's.

mod support;

use frasil_adapter_loro::State;
use frasil_adapter_loro::snapshot::{self, MAX_STATE_BYTES};
use frasil_base::errors::ErrorClass;
use loro::{ExportMode, LoroDoc};
use support::crafted;
use support::crafted_snapshot::{self as craft, Block, Entries};

/// The peer the crafted change blocks are written under.
const PEER: u64 = 0x0102_0304_0506_0708;

fn check(main: &[u8]) -> Result<(), ErrorClass> {
    snapshot::check(&craft::state(main.to_vec())).map(drop)
}

#[test]
fn a_real_export_rebuilt_by_hand_passes_and_loads() {
    let doc = craft::small_doc(PEER);
    let real = doc.export(ExportMode::Snapshot).unwrap();
    check(&real).unwrap();
    // The same entries, each in a block of its own, stored as they are:
    // what every crafted snapshot below is built on.
    let rebuilt = craft::rebuilt(&craft::tables(&real));
    check(&rebuilt).unwrap();
    let loaded = State::load(&craft::state(rebuilt)).unwrap();
    assert_eq!(loaded.doc().get_deep_value(), doc.get_deep_value());
    assert_eq!(loaded.doc().oplog_vv(), doc.oplog_vv());
}

/// A history-free export keeps the operation at each of its frontiers and
/// drops what comes before: where the last operation of a peer is a
/// style's end, that peer's remaining history begins with the end, its
/// start in the shallow root's state alone. The export passes and loads,
/// and so does a snapshot of a document built on it; the same block under
/// frontiers that do not name the end is refused.
#[test]
fn a_history_free_export_that_begins_with_a_styles_end_passes_and_loads() {
    let doc = LoroDoc::new();
    doc.set_peer_id(PEER).unwrap();
    let text = doc.get_text("text");
    text.insert(0, "styled").unwrap();
    text.mark(0..3, "bold", true).unwrap();
    doc.commit();
    let shallow = doc
        .export(ExportMode::shallow_snapshot(&doc.oplog_frontiers()))
        .unwrap();
    check(&shallow).unwrap();
    let loaded = State::load(&craft::state(shallow.clone())).unwrap();
    assert_eq!(loaded.doc().get_deep_value(), doc.get_deep_value());
    // A compaction over the history-free base, with more written since.
    let over = LoroDoc::new();
    over.import(&shallow).unwrap();
    over.set_peer_id(PEER + 1).unwrap();
    over.get_text("text").insert(6, " text").unwrap();
    over.commit();
    let compacted = over.export(ExportMode::Snapshot).unwrap();
    check(&compacted).unwrap();
    State::load(&craft::state(compacted)).unwrap();

    // The remaining history is one block, of the end alone.
    let mut tables = craft::tables(&shallow);
    let blocks: Vec<&Vec<u8>> = tables[0]
        .iter()
        .filter(|(key, _)| key.len() == 12)
        .map(|(key, _)| key)
        .collect();
    assert_eq!(blocks.len(), 1);
    check(&craft::rebuilt(&tables)).unwrap();
    // Frontiers that name another operation: the end's start is held
    // nowhere.
    for (key, value) in &mut tables[0] {
        if key.as_slice() == b"sf" {
            // One pair: the peer, and counter 0 as postcard writes an i32.
            let mut other = vec![1];
            let mut peer = PEER;
            while peer >= 0x80 {
                other.push((peer as u8) | 0x80);
                peer >>= 7;
            }
            other.push(peer as u8);
            other.push(0);
            *value = other;
        }
    }
    assert_eq!(check(&craft::rebuilt(&tables)), Err(ErrorClass::Malformed));
}

#[test]
fn an_lz4_block_that_expands_past_the_limits_is_refused() {
    // 70 blocks of 4 MiB from about 1.1 MiB: past 2^28 bytes in all.
    let bomb = craft::lz4_bomb(70);
    assert!(bomb.len() < 1_200_000);
    assert_eq!(check(&bomb), Err(ErrorClass::Malformed));
    assert!(State::load(&craft::state(bomb)).is_err());

    // A normal block holds at most 196,607 bytes once decompressed; the
    // pinned store decompresses it whole before it checks: 1 MiB from 4 KiB.
    let changes = craft::table_of(&[Block {
        first_key: b"vv".to_vec(),
        last_key: Some(b"vv".to_vec()),
        lz4: true,
        stored: craft::lz4_frame(craft::LZ4_4MIB, &[craft::lz4_run(1 << 20)]),
    }]);
    let expanding = craft::snapshot(&changes, b"E", &[]);
    assert!(expanding.len() < 8192);
    assert_eq!(check(&expanding), Err(ErrorClass::Malformed));

    // The same layout around the real version vector, compressed as
    // literals, passes: the refusals are the lengths'.
    let mut tables = craft::small_tables(PEER);
    let vv = tables[0]
        .iter()
        .find(|(key, _)| key == b"vv")
        .unwrap()
        .1
        .clone();
    let mut changes: Entries = std::mem::take(&mut tables[0]);
    changes.retain(|(key, _)| key != b"vv");
    let mut blocks: Vec<Block> = changes
        .iter()
        .map(|(key, value)| Block {
            first_key: key.clone(),
            last_key: Some(key.clone()),
            lz4: false,
            stored: craft::normal_block_data(&[(key.clone(), value.clone())]),
        })
        .collect();
    let data = craft::normal_block_data(&[(b"vv".to_vec(), vv)]);
    blocks.push(Block {
        first_key: b"vv".to_vec(),
        last_key: Some(b"vv".to_vec()),
        lz4: true,
        stored: craft::lz4_frame(0x40, &[craft::lz4_literals(&data)]),
    });
    blocks.sort_by(|a, b| a.first_key.cmp(&b.first_key));
    let main = craft::snapshot(&craft::table_of(&blocks), &craft::table(&tables[1]), &[]);
    check(&main).unwrap();
    State::load(&craft::state(main)).unwrap();
}

#[test]
fn table_counts_and_lengths_past_the_bytes_are_refused() {
    let tables = craft::small_tables(PEER);
    let changes = craft::table(&tables[0]);
    let state = craft::table(&tables[1]);
    check(&craft::snapshot(&changes, &state, &[])).unwrap();

    // An index that counts more blocks than its bytes hold.
    let index = u32::from_le_bytes(changes[changes.len() - 4..].try_into().unwrap()) as usize;
    let mut counted = changes.clone();
    counted[index..index + 4].copy_from_slice(&0x000f_0000u32.to_le_bytes());
    assert_eq!(
        check(&craft::snapshot(&counted, &state, &[])),
        Err(ErrorClass::Malformed)
    );

    // An index whose offset is past the table.
    let mut offset = changes.clone();
    let at = offset.len() - 4;
    offset[at..].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        check(&craft::snapshot(&offset, &state, &[])),
        Err(ErrorClass::Malformed)
    );

    // A normal block that counts 65,535 entries in a few bytes.
    let (key, value) = &tables[0][0];
    let mut data = craft::normal_block_data(&[(key.clone(), value.clone())]);
    let at = data.len() - 2;
    data[at..].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut blocks = vec![Block {
        first_key: key.clone(),
        last_key: Some(key.clone()),
        lz4: false,
        stored: data,
    }];
    let honest_rest = |blocks: &mut Vec<Block>| {
        for (key, value) in &tables[0][1..] {
            blocks.push(Block {
                first_key: key.clone(),
                last_key: Some(key.clone()),
                lz4: false,
                stored: craft::normal_block_data(&[(key.clone(), value.clone())]),
            });
        }
    };
    honest_rest(&mut blocks);
    assert_eq!(
        check(&craft::snapshot(&craft::table_of(&blocks), &state, &[])),
        Err(ErrorClass::Malformed)
    );

    // An entry whose key runs past its block.
    let mut data =
        craft::normal_block_data(&[(key.clone(), value.clone()), (vec![0x02], b"v".to_vec())]);
    // The second entry's key length: past its prefix length.
    let second = usize::from(u16::from_le_bytes(
        data[data.len() - 4..data.len() - 2].try_into().unwrap(),
    ));
    data[second + 1..second + 3].copy_from_slice(&0x1000u16.to_le_bytes());
    let mut blocks = vec![Block {
        first_key: key.clone(),
        last_key: Some(vec![0x02]),
        lz4: false,
        stored: data,
    }];
    honest_rest(&mut blocks);
    assert_eq!(
        check(&craft::snapshot(&craft::table_of(&blocks), &state, &[])),
        Err(ErrorClass::Malformed)
    );
}

#[test]
fn a_change_block_with_each_hazard_of_step_4_is_refused() {
    // Honest blocks, filed under their keys, pass.
    for blob in [
        crafted::with_tree(PEER),
        crafted::with_deletion(PEER),
        crafted::many_deletions_of_a_key(PEER, 4),
    ] {
        check(&craft::with_change_blocks(&blob)).unwrap();
    }
    let mut hazards: Vec<(&str, Vec<u8>)> = crafted::all(PEER).into_iter().collect();
    hazards.extend([
        (
            "a run of common prefix lengths",
            crafted::long_prefix_column(PEER, 1 << 27),
        ),
        (
            "positions that repeat a long prefix",
            crafted::repeated_positions(PEER, 4096, 8192),
        ),
        (
            "a run of deletion peers",
            crafted::long_deletion_column(PEER, 1 << 27),
        ),
        ("a deletion of length 0", crafted::empty_deletion(PEER)),
        (
            "operations that write no value",
            crafted::many_deletions_of_a_key(PEER, 1 << 24),
        ),
        (
            "a list longer than its bytes",
            crafted::list_longer_than_its_bytes(PEER, 1 << 28),
        ),
        ("a style end with no start", crafted::style_end_alone()),
    ]);
    for (name, blob) in hazards {
        let main = craft::with_change_blocks(&blob);
        assert_eq!(check(&main), Err(ErrorClass::Malformed), "{name}");
        assert!(State::load(&craft::state(main)).is_err(), "{name}");
    }
}

#[test]
fn a_change_block_filed_under_another_key_is_refused() {
    let blob = crafted::with_tree(PEER);
    let mut tables = craft::small_tables(1);
    tables[0].retain(|(key, _)| key.len() != 12);
    let block = crafted::blocks(&blob).remove(0);
    let mut key = craft::block_key(&block);
    // A first counter of 5 for a block that starts at 0: the store would
    // find it for counters it does not hold.
    key[11] = 5;
    tables[0].push((key, block.encode()));
    tables[0].sort();
    assert_eq!(check(&craft::rebuilt(&tables)), Err(ErrorClass::Malformed));
}

#[test]
fn a_container_state_past_its_bytes_is_refused() {
    let tables = craft::small_tables(PEER);
    // The root text's state: type 2 with the root bit, then its name.
    let text = tables[1]
        .iter()
        .position(|(key, _)| key[0] == 0x82 && key.ends_with(b"text"))
        .unwrap();
    let edit = |change: &dyn Fn(&mut Vec<u8>, &mut Vec<u8>)| {
        let mut tables = tables.clone();
        let (key, value) = &mut tables[1][text];
        change(key, value);
        tables[1].sort();
        craft::rebuilt(&tables)
    };
    check(&edit(&|_, _| {})).unwrap();
    // Its header: type 2, a LEB128 depth, no parent; then its text, 11
    // bytes.
    let value = &tables[1][text].1;
    let depth = value[1..].iter().position(|byte| byte & 0x80 == 0).unwrap() + 1;
    let parent = 1 + depth;
    assert_eq!(&value[parent..parent + 2], &[0, 11]);
    // A text that claims more bytes than the state holds.
    let longer = edit(&|_, value| {
        value.splice(parent + 1..parent + 2, [0x80, 0x80, 0x80, 0x80, 0x10]);
    });
    assert_eq!(check(&longer), Err(ErrorClass::Malformed));
    // A parent that is neither none nor some.
    let parent = edit(&|_, value| value[parent] = 2);
    assert_eq!(check(&parent), Err(ErrorClass::Malformed));
    // A state of another type than its key's.
    let kind = edit(&|_, value| value[0] = 0);
    assert_eq!(check(&kind), Err(ErrorClass::Malformed));
    // A key that is no container ID.
    let key = edit(&|key, _| key.push(0));
    assert_eq!(check(&key), Err(ErrorClass::Malformed));
}

/// A container state's tables are read run by run within the limits of
/// section 3.5, and a table Loro refuses refuses the state at load, not at
/// the first edit: the root list of the small document, whose state is its
/// value, its peer table and its ID table, one field of three columns.
#[test]
fn a_container_states_table_past_its_rows_is_refused() {
    let tables = craft::small_tables(PEER);
    let list = tables[1]
        .iter()
        .position(|(key, _)| key[0] == 0x81 && key.ends_with(b"list"))
        .unwrap();
    let value = &tables[1][list].1;
    let depth = value[1..].iter().position(|byte| byte & 0x80 == 0).unwrap() + 1;
    let parent = 1 + depth;
    assert_eq!(value[parent], 0, "a root list has no parent");
    // Its value, one string "x" (`Header::String` is variant 4), then its
    // peer table, one peer.
    let payload = parent + 1;
    assert_eq!(&value[payload..payload + 4], &[1, 4, 1, b'x']);
    let peers = payload + 4;
    assert_eq!(value[peers], 1);
    let table = peers + 1 + 8;
    let with_table = |columns: &[Vec<u8>]| {
        let mut tables = tables.clone();
        let state = &mut tables[1][list].1;
        state.truncate(table);
        state.extend_from_slice(&[1, columns.len() as u8]);
        for column in columns {
            let mut len = Vec::new();
            let mut n = column.len();
            loop {
                let byte = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    len.push(byte);
                    break;
                }
                len.push(byte | 0x80);
            }
            state.extend_from_slice(&len);
            state.extend_from_slice(column);
        }
        craft::rebuilt(&tables)
    };
    // A delta-run-length column of one run: its zigzag count, then its
    // zigzag delta, 0.
    let run = |count: u64| {
        let mut column = Vec::new();
        let mut n = count << 1;
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                column.push(byte);
                break;
            }
            column.push(byte | 0x80);
        }
        column.push(0);
        column
    };
    // One row, as the value holds: the screen passes it.
    check(&with_table(&[run(1), run(1), run(1)])).unwrap();
    // A run of 2^21 rows in a few bytes: past the rows a snapshot of this
    // size may hold, refused before Loro expands it.
    let long = run(1 << 21);
    assert_eq!(
        check(&with_table(&[long.clone(), long.clone(), long])),
        Err(ErrorClass::Malformed)
    );
    // A run past what the pinned decoder reads.
    let past = run(1_000_000_001);
    assert_eq!(
        check(&with_table(&[past.clone(), run(1), run(1)])),
        Err(ErrorClass::Malformed)
    );
    // Another number of columns than Loro writes.
    assert_eq!(
        check(&with_table(&[run(1), run(1)])),
        Err(ErrorClass::Malformed)
    );
    // Two rows for a value of one: within the limits, so the screen passes
    // it, and Loro refuses the table as it decodes the state, which the
    // load asks for.
    let two = with_table(&[run(2), run(2), run(2)]);
    check(&two).unwrap();
    assert_eq!(
        State::load(&craft::state(two)).map(drop),
        Err(ErrorClass::Malformed)
    );
}

#[test]
fn a_state_past_its_size_limit_is_refused() {
    let bytes = vec![0u8; MAX_STATE_BYTES + 1];
    assert_eq!(
        snapshot::check(&bytes).map(drop),
        Err(ErrorClass::Malformed)
    );
    assert!(State::load(&bytes).is_err());
}

#[test]
fn every_export_of_a_large_document_passes_and_loads() {
    // Large enough for many change blocks and table blocks, large values,
    // and LZ4-compressed blocks.
    let doc = LoroDoc::new();
    doc.set_peer_id(PEER).unwrap();
    let other = LoroDoc::new();
    other.set_peer_id(PEER + 1).unwrap();
    let text = doc.get_text("text");
    for round in 0..40usize {
        let len = text.len_unicode();
        text.insert(len / 2, &"lorem ipsum dolor sit amet ".repeat(200))
            .unwrap();
        let len = text.len_unicode();
        text.mark(len / 4..len / 3, ["bold", "link"][round % 2], true)
            .unwrap();
        text.delete(len / 5, 30).unwrap();
        for i in 0..100 {
            doc.get_map("map")
                .insert(&format!("key {round} {i}"), i as i64)
                .unwrap();
        }
        doc.get_movable_list("movable").push(round as i64).unwrap();
        doc.get_tree("tree").create(None).unwrap();
        doc.get_counter("counter").increment(1.0).unwrap();
        doc.commit();
        if round % 5 == 0 {
            other
                .import(&doc.export(ExportMode::all_updates()).unwrap())
                .unwrap();
            other.get_text("text").insert(0, "concurrent ").unwrap();
            other.commit();
            doc.import(&other.export(ExportMode::all_updates()).unwrap())
                .unwrap();
        }
    }
    // As the compactor builds its document: imported, not committed.
    let built = LoroDoc::new();
    built
        .import(&doc.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    for (main, history) in [
        (doc.export(ExportMode::Snapshot).unwrap(), true),
        (built.export(ExportMode::Snapshot).unwrap(), true),
        (
            built
                .export(ExportMode::shallow_snapshot(&built.oplog_frontiers()))
                .unwrap(),
            false,
        ),
    ] {
        let tables = craft::tables(&main);
        if history {
            assert!(tables[0].len() > 20, "{} change blocks", tables[0].len());
        }
        check(&main).unwrap();
        let loaded = State::load(&craft::state(main)).unwrap();
        assert_eq!(loaded.doc().get_deep_value(), doc.get_deep_value());
    }
}

/// The resident memory of process `pid` in bytes, as `ps` reports it.
fn resident(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let kib: u64 = String::from_utf8(out.stdout).ok()?.trim().parse().ok()?;
    Some(kib * 1024)
}

/// Unscreened, the pinned Loro decompresses a table's block in full when it
/// reads it: a snapshot of about 1.1 MiB takes over 256 MiB as it imports,
/// sampled from a child process, which is stopped once it has. An import
/// fails within a tenth of a second and frees what it took, so the child
/// imports again and again, each into a new document, and the sampler
/// meets the peak of one of them.
#[test]
#[ignore = "a measurement: a child process takes over 256 MiB"]
fn unscreened_loro_takes_memory_by_a_decompressed_length() {
    const CHILD: &str = "FRASIL_IMPORT_LZ4_BOMB";
    const ENOUGH: u64 = 256 << 20;
    let bomb = craft::lz4_bomb(70);
    if std::env::var(CHILD).is_ok() {
        // Until the parent stops it; never longer than its sampling.
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(300) {
            let doc = LoroDoc::new();
            let _ = doc.import(&bomb);
        }
        return;
    }
    assert_eq!(check(&bomb), Err(ErrorClass::Malformed));
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "unscreened_loro_takes_memory_by_a_decompressed_length",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    let mut peak = 0;
    while peak < ENOUGH && start.elapsed() < std::time::Duration::from_secs(300) {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        peak = peak.max(resident(child.id()).unwrap_or(0));
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    eprintln!(
        "{} bytes took {} MiB in {:?}",
        bomb.len(),
        peak >> 20,
        start.elapsed()
    );
    assert!(peak >= ENOUGH, "{} MiB", peak >> 20);
}
