//! Peak live allocations while opening a large checkpoint record.
#![allow(unsafe_code)]
use frasil_crypto::ErrorClass;
use frasil_events::EventId;
use frasil_space::{
    HistoryMode, Level, MemberEntry, MemberRef, MemberType, Policy, ReadRecord, Record,
    RecordFault, RecordMode, RecordSink, RecordStream, SpaceClass, Via,
};
use frasil_units::record::{RecordKey, seal_record};
use frasil_units::{RecordObjectOutcome, RecordObjectReader};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

struct Counter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), SeqCst) + layout.size();
            PEAK.fetch_max(live, SeqCst);
        }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(ptr, layout, size) };
        if !next.is_null() {
            LIVE.fetch_sub(layout.size(), SeqCst);
            let live = LIVE.fetch_add(size, SeqCst) + size;
            PEAK.fetch_max(live, SeqCst);
        }
        next
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), SeqCst);
        unsafe { System.dealloc(ptr, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: Counter = Counter;

/// The scratch a read may hold beyond what it keeps: a sealed chunk, its
/// plaintext, the decoder's input and one entry's tree.
const SCRATCH: usize = 4 * 1024 * 1024;

/// The counters are global: one measurement at a time.
static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn sixty_thousand_members_use_only_state_and_bounded_scratch() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let space = EventId([1; 32]);
    let key = [2; 32];
    let record = Record {
        epoch: 1,
        previous: None,
        policy: Default::default(),
        tips: BTreeMap::new(),
        forks: BTreeMap::new(),
        heard: Vec::new(),
        members: (0u32..60_000)
            .map(|i| {
                let mut id = [0; 32];
                id[28..].copy_from_slice(&i.to_be_bytes());
                MemberEntry {
                    member: MemberRef {
                        kind: MemberType::Person,
                        id,
                    },
                    level: Level::Write,
                    capabilities: Vec::new(),
                    label: None,
                    history: HistoryMode::WithHistory,
                    via: Via::None,
                    session: None,
                    replaces: None,
                    seniority: (1, 1, space),
                    keys: None,
                    slot: None,
                    expires_at: None,
                    claims: None,
                    invite: None,
                    claimant: None,
                    notices: Vec::new(),
                    floor: false,
                    named: Vec::new(),
                    rank: None,
                }
            })
            .collect(),
    };
    let encoded = record.encode();
    // Holding the plaintext whole would break the bound.
    assert!(encoded.len() > SCRATCH, "{}", encoded.len());
    let sealed = seal_record(
        &space,
        &key,
        frasil_keys::SelfRef::new(frasil_crypto::device::DeviceId([3; 32]), 1),
        &encoded,
    )
    .unwrap();
    drop(record);
    drop(encoded);
    for mode in [RecordMode::Build, RecordMode::Summary] {
        let baseline = LIVE.load(SeqCst);
        PEAK.store(baseline, SeqCst);
        let mut sink = RecordStream::new(mode);
        let mut reader = RecordObjectReader::new(
            &sealed.object.header,
            &space,
            Some(RecordKey::Checkpoint(&key)),
            &sealed.binding,
        );
        for (index, chunk) in sealed.object.chunks.iter().enumerate() {
            reader.feed(index as u64, &chunk.sealed, &mut sink);
        }
        assert_eq!(reader.finish(), RecordObjectOutcome::Opened);
        let result = sink.finish().ok().unwrap();
        let peak = PEAK.load(SeqCst) - baseline;
        let state = LIVE.load(SeqCst) - baseline;
        assert!(peak < state + SCRATCH, "peak {peak}, retained {state}");
        if matches!(result, ReadRecord::Summary(_)) {
            assert!(peak < SCRATCH, "summary peak {peak}");
        }
        std::hint::black_box(result);
    }
}

/// A CBOR head of the deterministic subset.
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    match n {
        0..=23 => out.push(major | n as u8),
        24..=0xff => out.extend([major | 24, n as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend((n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend((n as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend(n.to_be_bytes());
        }
    }
}

/// A record whose policy is `policy`, with no member or with one person
/// member whose entry has one key after its key 1, `tail`.
fn hostile(tail: Option<&[u8]>, policy: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    head(&mut out, 5, 6);
    out.extend([1, 1, 2, 1, 4]);
    if let Some(tail) = tail {
        out.extend([0x81, 0xa2, 1, 0x82, 1]);
        head(&mut out, 2, 32);
        out.extend([7; 32]);
        out.extend_from_slice(tail);
    } else {
        out.push(0x80);
    }
    out.push(5);
    head(&mut out, 2, policy.len() as u64);
    out.extend_from_slice(policy);
    out.extend([6, 0x80, 7, 0x80]);
    out
}

#[test]
fn hostile_lengths_and_counts_are_read_in_bounded_memory() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    const BIG: u64 = 32 * 1024 * 1024;
    let policy = Policy::default().encode();
    // A later document's key with a long value: the record is held.
    let mut reserved = vec![0x18, 30];
    head(&mut reserved, 2, BIG);
    reserved.resize(reserved.len() + BIG as usize, 0);
    // Names that are millions of integers: `Malformed`.
    let mut names = vec![20];
    head(&mut names, 4, BIG / 2);
    names.resize(names.len() + (BIG / 2) as usize, 0);
    // A label longer than any: `Malformed`.
    let mut label = vec![4];
    head(&mut label, 3, BIG);
    label.resize(label.len() + BIG as usize, b'a');
    // A policy of another version, holding a long string: its version
    // decides, as reading it whole would.
    let mut long_policy = vec![0xa2, 1, 2, 2];
    head(&mut long_policy, 2, BIG);
    long_policy.resize(long_policy.len() + BIG as usize, 0);
    let malformed: SpaceClass = ErrorClass::Malformed.into();
    type Case<'a> = (Option<&'a [u8]>, &'a [u8], Option<SpaceClass>);
    let cases: [Case<'_>; 4] = [
        (Some(&reserved), &policy, None),
        (Some(&names), &policy, Some(malformed)),
        (Some(&label), &policy, Some(malformed)),
        (
            None,
            &long_policy,
            Some(ErrorClass::UnsupportedVersion.into()),
        ),
    ];
    for (tail, policy, want) in cases {
        let data = hostile(tail, policy);
        for mode in [RecordMode::Build, RecordMode::Summary] {
            let baseline = LIVE.load(SeqCst);
            PEAK.store(baseline, SeqCst);
            let mut sink = RecordStream::new(mode);
            for piece in data.chunks(64 * 1024) {
                sink.feed(piece);
            }
            let result = sink.finish();
            let peak = PEAK.load(SeqCst) - baseline;
            // Pieces of 64 KiB: the decoder's input and the longest item
            // the schema allows, nothing of the long strings.
            assert!(peak < 256 * 1024, "peak {peak}");
            match (result, want) {
                (Err(RecordFault::Extension(link)), None) => assert_eq!(link, Some((1, None))),
                (Err(RecordFault::Class(got)), Some(want)) => assert_eq!(got, want),
                _ => panic!("unexpected verdict for {want:?}"),
            }
        }
    }
}
