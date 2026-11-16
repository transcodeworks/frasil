//! Blobs crafted to reach the pinned Loro's block decoder with a valid
//! checksum: each is refused as a blob Loro does not read
//! (adapter-loro.md, 3.2 The checks, step 4), whether the unit is valid by
//! the write rule or only counted, and no replica that counts it fails.

mod support;

use frasil_adapter::{Adapter, Capabilities, Outcome, StreamUnit};
use frasil_adapter_loro::{BlobMeta, Content, Loro, LoroClass, PeerId, meta, peer};
use loro::{ExportMode, LoroDoc};
use support::crafted::{self, SEED, xxh32};
use support::{SPACE, STREAM, unit_with};

/// The peer of author 1's incarnation 1 in the test stream.
fn own_peer() -> PeerId {
    peer(&SPACE, &STREAM, &[1; 32], 1)
}

fn crafted() -> [(&'static str, Vec<u8>); 3] {
    crafted::all(own_peer())
}

fn edit_unit(id: u8, blob: Vec<u8>, valid: bool) -> StreamUnit {
    unit_with(
        id,
        1,
        1,
        &Content::edit(1, blob),
        Capabilities::none(),
        valid,
    )
}

#[test]
fn the_checksum_is_loros_own() {
    let doc = LoroDoc::new();
    doc.set_peer_id(7).unwrap();
    doc.get_text("t").insert(0, "hello").unwrap();
    doc.commit();
    let blob = doc.export(ExportMode::all_updates()).unwrap();
    assert_eq!(&blob[16..20], &xxh32(&blob[20..], SEED).to_le_bytes());
}

#[test]
fn a_crafted_blob_is_not_read() {
    for (name, blob) in crafted() {
        assert_eq!(BlobMeta::read(&blob), None, "{name}");
    }
}

#[test]
fn a_crafted_blob_is_loro_malformed() {
    let loro = Loro::new();
    for (name, blob) in crafted() {
        let unit = edit_unit(1, blob, true);
        assert_eq!(
            loro.decode(&unit.content, &unit.context),
            Err(LoroClass::LoroMalformed),
            "{name}"
        );
        let mut state = loro.empty();
        assert_eq!(
            loro.receive(&mut state, &unit),
            Outcome::Refused(LoroClass::LoroMalformed),
            "{name}"
        );
    }
}

#[test]
fn a_counted_unit_with_a_crafted_blob_counts_no_span() {
    let loro = Loro::new();
    for (name, blob) in crafted() {
        let mut state = loro.empty();
        assert_eq!(
            loro.receive(&mut state, &edit_unit(1, blob, false)),
            Outcome::Counted,
            "{name}"
        );
        // A later unit of the same peer and counters is not refused as an
        // overlap: the crafted unit counted no span (step 6).
        let doc = LoroDoc::new();
        doc.set_peer_id(own_peer()).unwrap();
        doc.get_text("t").insert(0, "hi").unwrap();
        doc.commit();
        let blob = doc.export(ExportMode::all_updates()).unwrap();
        let later = edit_unit(2, blob, true);
        assert_eq!(loro.receive(&mut state, &later), Outcome::Applied, "{name}");
    }
}

/// The most rows a blob's operation tables hold together (adapter-loro.md,
/// 3.2 The checks).
const MAX_ROWS: u32 = 1 << 20;

/// Loro's own metadata of a blob, unscreened.
fn loro_reads(blob: &[u8]) -> bool {
    LoroDoc::decode_import_blob_meta(blob, true).is_ok()
}

#[test]
fn a_run_in_a_column_loro_expands_is_refused() {
    let peer = own_peer();
    // Loro reads these: each column is expanded, then the columns are
    // paired, and the pairs past the shortest column dropped.
    assert!(loro_reads(&crafted::long_prefix_column(peer, 1000)));
    assert!(loro_reads(&crafted::long_deletion_column(peer, 1000)));
    // Under 200 bytes, each names a billion entries of eight bytes or
    // more, which Loro expands before it pairs them.
    for blob in [
        crafted::long_prefix_column(peer, 1000),
        crafted::long_prefix_column(peer, 1_000_000_000),
        crafted::long_deletion_column(peer, 1000),
        crafted::long_deletion_column(peer, 1_000_000_000),
    ] {
        assert!(blob.len() < 200);
        assert_eq!(BlobMeta::read(&blob), None);
    }
}

#[test]
fn operations_past_the_limit_are_refused() {
    let peer = own_peer();
    // A thousand operations that write no value: read, and read alike.
    let blob = crafted::many_deletions_of_a_key(peer, 1000);
    assert!(meta::import_blob_meta(&blob).is_some());
    let meta = BlobMeta::read(&blob).unwrap();
    assert_eq!(meta.spans[&peer], frasil_adapter_loro::Span::new(0, 1001));
    // One more than the limit, in the same few bytes.
    let blob = crafted::many_deletions_of_a_key(peer, MAX_ROWS);
    assert!(blob.len() < 200);
    assert_eq!(BlobMeta::read(&blob), None);
}

#[test]
fn positions_that_repeat_a_long_prefix_are_refused() {
    let peer = own_peer();
    let blob = crafted::repeated_positions(peer, 3, 4);
    assert!(loro_reads(&blob));
    assert!(BlobMeta::read(&blob).is_some());
    // 4,097 positions of 8,192 bytes from 12 KiB: past 2^24 bytes.
    let blob = crafted::repeated_positions(peer, 4096, 8192);
    assert!(blob.len() < 13 * 1024);
    assert_eq!(BlobMeta::read(&blob), None);
}

#[test]
fn a_list_longer_than_its_bytes_is_refused() {
    let peer = own_peer();
    // Loro reserves room for the list's elements, then fails.
    assert!(!loro_reads(&crafted::list_longer_than_its_bytes(
        peer,
        1 << 20
    )));
    // At its longest, 2^28 elements of 16 bytes or more: past what a
    // 32-bit target can hold.
    let blob = crafted::list_longer_than_its_bytes(peer, 1 << 28);
    assert_eq!(BlobMeta::read(&blob), None);
}

#[test]
fn a_deletion_of_length_0_is_refused() {
    let peer = own_peer();
    let blob = crafted::empty_deletion(peer);
    assert_eq!(BlobMeta::read(&blob), None);
    // Loro's release build reads it; its debug build stops at an assertion
    // that a deletion has a length.
    let read = std::panic::catch_unwind(|| loro_reads(&blob));
    if cfg!(debug_assertions) {
        assert!(read.is_err());
    } else {
        assert_eq!(read.ok(), Some(true));
    }
}

#[test]
fn a_style_end_with_no_start_is_refused() {
    let blob = crafted::style_end_alone();
    assert!(loro_reads(&blob));
    assert_eq!(BlobMeta::read(&blob), None);
    // Unscreened, Loro panics on its import. A document Loro panicked in
    // is not dropped: its drop would panic on a poisoned lock.
    let doc = LoroDoc::new();
    let import = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| doc.import(&blob)));
    assert!(import.is_err());
    std::mem::forget(doc);
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

/// The blobs [`unscreened_loro_takes_memory_by_a_run_length`] decodes, by
/// name: each under 200 bytes.
fn amplifying(name: &str) -> Vec<u8> {
    let peer = own_peer();
    match name {
        "a run of common prefix lengths" => crafted::long_prefix_column(peer, 1 << 27),
        "a run of deletion peers" => crafted::long_deletion_column(peer, 1 << 27),
        "operations that write no value" => crafted::many_deletions_of_a_key(peer, 1 << 24),
        _ => unreachable!(),
    }
}

/// Unscreened, the pinned Loro's metadata read takes memory by each run
/// length: each blob of under 200 bytes takes over 512 MiB, sampled from a
/// child process that decodes it, which is stopped once it has.
#[test]
#[ignore = "a measurement: a child process takes over 512 MiB"]
fn unscreened_loro_takes_memory_by_a_run_length() {
    const CHILD: &str = "FRASIL_DECODE_AMPLIFYING";
    const ENOUGH: u64 = 512 << 20;
    if let Ok(name) = std::env::var(CHILD) {
        let _ = LoroDoc::decode_import_blob_meta(&amplifying(&name), true);
        return;
    }
    for name in [
        "a run of common prefix lengths",
        "a run of deletion peers",
        "operations that write no value",
    ] {
        let blob = amplifying(name);
        assert!(blob.len() < 200, "{name}");
        assert_eq!(BlobMeta::read(&blob), None, "{name}");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "unscreened_loro_takes_memory_by_a_run_length",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env(CHILD, name)
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
            "{name}: {} bytes took {} MiB in {:?}",
            blob.len(),
            peak >> 20,
            start.elapsed()
        );
        assert!(peak >= ENOUGH, "{name}: {} MiB", peak >> 20);
    }
}
