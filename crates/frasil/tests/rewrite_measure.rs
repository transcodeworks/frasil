//! Measurements of large rewrites, ignored by default. Run them with
//!
//! ```text
//! cargo test --release -p frasil --test rewrite_measure -- --ignored --nocapture
//! ```
//!
//! Each row is one rewrite of a generated text, on a document built from it
//! in one commit: its time, and the size of the update it makes.
#![cfg(feature = "adapter-loro")]

#[path = "support/scripts.rs"]
mod scripts;

use frasil::advanced::documents::compare_text;
use frasil::loro::{ExportMode, LoroDoc, UpdateOptions};
use frasil::{Device, Options, SetText, Storage, TextOutcome, TextStyle};
use scripts::{Kind, crlf, one_word, reflow, scattered, script};
use std::time::{Duration, Instant};

const LIMIT_MS: f64 = 20_000.0;
const SIZES: [usize; 3] = [20_000, 200_000, 800_000];

fn edits(kind: Kind, size: usize) -> Vec<(&'static str, String, String)> {
    let base = script(kind, size, 7);
    let rewrite = script(kind, size, 8);
    vec![
        ("one word", base.clone(), one_word(&base)),
        ("scattered", base.clone(), scattered(&base, 4)),
        ("reflow", base.clone(), reflow(&base, 48)),
        ("CRLF flip", base.clone(), crlf(&base)),
        ("full rewrite", base, rewrite),
    ]
}

fn built(text: &str) -> LoroDoc {
    let doc = LoroDoc::new();
    doc.set_peer_id(1).unwrap();
    doc.get_text("body").insert(0, text).unwrap();
    doc.commit();
    doc
}

/// Time, and update bytes, or `None` past the limit.
fn measure(
    base: &str,
    target: &str,
    run: impl FnOnce(&LoroDoc, &str) -> bool,
) -> (f64, Option<usize>) {
    let doc = built(base);
    doc.set_peer_id(2).unwrap();
    let before = doc.oplog_vv();
    let started = Instant::now();
    let finished = run(&doc, target);
    doc.commit();
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    if !finished {
        return (elapsed, None);
    }
    assert_eq!(doc.get_text("body").to_string(), target);
    let update = doc.export(ExportMode::updates(&before)).unwrap();
    (elapsed, Some(update.len()))
}

fn row(method: &str, kind: Kind, size: usize, edit: &str, (ms, bytes): (f64, Option<usize>)) {
    let bytes = bytes.map_or("timed out".to_owned(), |b| b.to_string());
    println!(
        "| {method} | {} | {} KB | {edit} | {ms:.1} | {bytes} |",
        kind.name(),
        size / 1000
    );
}

#[test]
#[ignore = "a measurement, which takes minutes in a release build"]
fn loro_update_as_it_stands() {
    println!("| Method | Text | Size | Edit | ms | Update bytes |");
    println!("|---|---|---|---|---|---|");
    let options = || UpdateOptions {
        timeout_ms: Some(LIMIT_MS),
        use_refined_diff: true,
    };
    for kind in Kind::ALL {
        for size in SIZES {
            for (edit, base, target) in edits(kind, size) {
                let update = measure(&base, &target, |doc, target| {
                    doc.get_text("body").update(target, options()).is_ok()
                });
                row("update", kind, size, edit, update);
                let by_line = measure(&base, &target, |doc, target| {
                    doc.get_text("body")
                        .update_by_line(target, options())
                        .is_ok()
                });
                row("update_by_line", kind, size, edit, by_line);
            }
        }
    }
}

fn adapted(kind: Kind, size: usize) -> Vec<(&'static str, String, String)> {
    let base = script(kind, size, 7);
    let rewrite = script(kind, size, 8);
    vec![
        ("one word", base.clone(), one_word(&base)),
        ("scattered", base.clone(), scattered(&base, 4)),
        ("reflow", base.clone(), reflow(&base, 48)),
        ("CRLF flip", base.clone(), TextStyle::fold(&crlf(&base)).0),
        ("full rewrite", base, rewrite),
    ]
}

#[tokio::test]
#[ignore = "a measurement, which takes minutes in a release build"]
async fn set_text_through_a_device() {
    println!("| Text | Size | Edit | Compare ms | Total ms | Update bytes | Units | How |");
    println!("|---|---|---|---|---|---|---|---|");
    for kind in Kind::ALL {
        for size in SIZES {
            for (edit, base, target) in adapted(kind, size) {
                let options = Options::new().loopback().never_restored();
                let device = Device::open_with(Storage::Memory, &[1; 32], options)
                    .await
                    .unwrap();
                let space = device.create_space().await.unwrap();
                let document = space.create_document().unwrap();
                let limit = SetText::default().limit(Duration::from_secs(20));
                document.set_text("body", &base, limit).await.unwrap();
                let before = document.read().await.unwrap().oplog_vv();

                let started = Instant::now();
                let compared = compare_text(&base, &target, limit.limit);
                let compare_ms = started.elapsed().as_secs_f64() * 1000.0;

                let started = Instant::now();
                let written = document.set_text("body", &target, limit).await.unwrap();
                let total_ms = started.elapsed().as_secs_f64() * 1000.0;
                let doc = document.read().await.unwrap();
                assert_eq!(doc.get_text("body").to_string(), target);
                let bytes = doc.export(ExportMode::updates(&before)).unwrap().len();
                let how = match written.outcome {
                    TextOutcome::Edited => "edited",
                    TextOutcome::Replaced => "replaced",
                    TextOutcome::Unchanged => "unchanged",
                };
                let finished = if compared.is_ok() { "" } else { " (limit)" };
                println!(
                    "| {} | {} KB | {edit} | {compare_ms:.1}{finished} | {total_ms:.1} | {bytes} | {} | {how} |",
                    kind.name(),
                    size / 1000,
                    written.units,
                );
            }
        }
    }
}

/// Repeated rewrites keep their history: what each adds, in the snapshot a
/// compaction would export and in a history-free one.
#[tokio::test]
#[ignore = "a measurement"]
async fn history_after_repeated_rewrites() {
    println!("| Rewrites of 200 KB | Snapshot bytes | Shallow snapshot bytes |");
    println!("|---|---|---|");
    let options = Options::new().loopback().never_restored();
    let device = Device::open_with(Storage::Memory, &[1; 32], options)
        .await
        .unwrap();
    let space = device.create_space().await.unwrap();
    let document = space.create_document().unwrap();
    for rewrite in 0..=5u64 {
        let text = script(Kind::Play, 200_000, 20 + rewrite);
        document
            .set_text("body", &text, SetText::default())
            .await
            .unwrap();
        let doc = document.read().await.unwrap();
        let snapshot = doc.export(ExportMode::Snapshot).unwrap().len();
        let shallow = doc
            .export(ExportMode::shallow_snapshot(&doc.oplog_frontiers()))
            .unwrap()
            .len();
        println!("| {rewrite} | {snapshot} | {shallow} |");
    }
}
