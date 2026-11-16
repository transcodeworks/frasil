//! `adapter-loro.json`: every family, as `claims.txt` lists them.
//!
//! The vectors' blobs are opaque stand-ins, and each check takes the blob's
//! metadata as input (adapter-loro.md, section 5); `tests/loro.rs` adds Loro
//! round trips.

use frasil_adapter::{Adapter, Capabilities, Capability, CapabilityChecks, Context, Mode, Role};
use frasil_adapter_loro::{
    BlobMeta, Content, ContentRole, LORO_VERSION, Loro, PeerId, SnapshotState, Span, TYPE, check,
    check_resubmitted, derive,
};
use frasil_base::errors::{Class, ErrorClass};
use frasil_testkit::{hex, vectors};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const FILE: &str = "adapter-loro.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    loro_version: String,
    #[serde(deserialize_with = "hex::array")]
    space: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    stream: [u8; 16],
}

fn parameters() -> Parameters {
    vectors::family(FILE, "parameters")
}

/// A capability list as the vectors write it: `[[name, mode], ...]`.
fn capabilities(rows: &[(String, u64)]) -> Capabilities {
    rows.iter()
        .map(|(name, mode)| Capability::new(name.clone(), Mode::from_code(*mode).unwrap()))
        .collect()
}

fn verdict<T, C: Class>(result: Result<T, C>) -> String {
    match result {
        Ok(_) => "accepted".to_owned(),
        Err(class) => class.name().to_owned(),
    }
}

#[test]
fn parameters_name_the_pinned_version() {
    let parameters = parameters();
    assert_eq!(parameters.loro_version, LORO_VERSION);
    assert_ne!(parameters.stream, [0; 16]);
    assert_ne!(parameters.space, [0; 32]);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerRow {
    #[serde(deserialize_with = "hex::array")]
    author: [u8; 32],
    incarnation: u64,
    #[serde(deserialize_with = "hex::array")]
    digest: [u8; 32],
    first_8: u64,
    peer: u64,
}

#[test]
fn peer_ids() {
    let parameters = parameters();
    let rows: Vec<PeerRow> = vectors::family(FILE, "peer_ids");
    assert_eq!(rows.len(), 3);
    for row in rows {
        let derived = derive(
            &parameters.space,
            &parameters.stream,
            &row.author,
            row.incarnation,
        );
        assert_eq!(derived.digest, row.digest);
        assert_eq!(derived.first_8, row.first_8);
        assert_eq!(derived.peer, row.peer);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contents {
    #[serde(deserialize_with = "hex::bytes")]
    edit: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    suggestion: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    accept: Vec<u8>,
    #[serde(deserialize_with = "hex::bytes")]
    dismiss: Vec<u8>,
}

#[test]
fn contents() {
    let contents: Contents = vectors::family(FILE, "contents");
    let blob = b"stand-in for Loro's export bytes".to_vec();
    let target: [u8; 32] =
        hex::decode_array("d1313b05ce4eb0bb39cf56f09e315a85cff736037993f01d0c93078386c5e8bf")
            .unwrap();
    for (bytes, expected) in [
        (&contents.edit, Content::edit(5, blob.clone())),
        (&contents.suggestion, Content::suggestion(9, blob)),
        (&contents.accept, Content::accept([target])),
        (&contents.dismiss, Content::dismiss([target])),
    ] {
        assert_eq!(Content::read(bytes), Ok(expected.clone()));
        assert_eq!(&expected.encode(), bytes);
    }
    let roles: Vec<ContentRole> = [
        &contents.edit,
        &contents.suggestion,
        &contents.accept,
        &contents.dismiss,
    ]
    .iter()
    .map(|bytes| Content::read(bytes).unwrap().role())
    .collect();
    assert_eq!(
        roles,
        [
            ContentRole::Edit,
            ContentRole::Suggestion,
            ContentRole::Accept,
            ContentRole::Dismiss
        ]
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    mode: String,
    spans: Vec<(PeerId, i32, i32)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckRow {
    name: String,
    #[serde(deserialize_with = "hex::array")]
    author: [u8; 32],
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
    seq: u64,
    capabilities: Vec<(String, u64)>,
    meta: Option<Meta>,
    earlier_spans: Vec<(PeerId, i32, i32)>,
    /// The earlier spans of the units this unit re-submits with the same
    /// content, which step 6 does not count.
    #[serde(default)]
    resubmitted_spans: Vec<(PeerId, i32, i32)>,
    base_counters: Vec<(PeerId, i32)>,
    held_suggestions: Vec<String>,
    verdict: String,
}

fn blob_meta(meta: &Meta) -> BlobMeta {
    let spans = meta
        .spans
        .iter()
        .map(|(peer, start, end)| (*peer, Span::new(*start, *end)));
    match meta.mode.as_str() {
        "updates" => BlobMeta::updates(spans),
        "snapshot" => {
            assert!(meta.spans.is_empty());
            BlobMeta::snapshot()
        }
        other => panic!("mode {other}"),
    }
}

#[test]
fn checks() {
    let parameters = parameters();
    let rows: Vec<CheckRow> = vectors::family(FILE, "checks");
    assert_eq!(rows.len(), 19);
    let mut resubmissions = 0;
    for row in rows {
        let context = Context::new(
            parameters.space,
            parameters.stream,
            [0xee; 32],
            row.author,
            row.seq,
            row.seq,
            Role::Log,
        )
        .with_capabilities(capabilities(&row.capabilities));
        let earlier: Vec<(PeerId, Span)> = row
            .earlier_spans
            .iter()
            .map(|(peer, start, end)| (*peer, Span::new(*start, *end)))
            .collect();
        let resubmitted: Vec<(PeerId, Span)> = row
            .resubmitted_spans
            .iter()
            .map(|(peer, start, end)| (*peer, Span::new(*start, *end)))
            .collect();
        if !resubmitted.is_empty() {
            resubmissions += 1;
        }
        let base: BTreeMap<PeerId, i32> = row.base_counters.iter().copied().collect();
        let held: BTreeSet<[u8; 32]> = row
            .held_suggestions
            .iter()
            .map(|text| hex::decode_array(text).unwrap())
            .collect();
        let result = check_resubmitted(
            &row.content,
            &context,
            &CapabilityChecks::new(),
            row.meta.as_ref().map(blob_meta),
            &earlier,
            &resubmitted,
            &base,
            |target| held.contains(target),
        );
        assert_eq!(verdict(result), row.verdict, "{}", row.name);
        if resubmitted.is_empty() {
            let result = check(
                &row.content,
                &context,
                &CapabilityChecks::new(),
                row.meta.as_ref().map(blob_meta),
                &earlier,
                &base,
                |target| held.contains(target),
            );
            assert_eq!(verdict(result), row.verdict, "{}", row.name);
        }
    }
    assert_eq!(resubmissions, 1);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusalRow {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
    class: String,
}

#[test]
fn content_refusals() {
    let parameters = parameters();
    let rows: Vec<RefusalRow> = vectors::family(FILE, "content_refusals");
    assert_eq!(rows.len(), 5);
    let loro = Loro::new();
    for row in rows {
        assert_eq!(
            verdict(Content::read(&row.content)),
            row.class,
            "{}",
            row.name
        );
        let context = Context::new(
            parameters.space,
            parameters.stream,
            [0xee; 32],
            [0xaa; 32],
            7,
            7,
            Role::Log,
        );
        assert_eq!(
            verdict(loro.decode(&row.content, &context)),
            row.class,
            "{}",
            row.name
        );
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenSuggestion {
    suggestions: Vec<String>,
    #[serde(deserialize_with = "hex::bytes")]
    state: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactedWithDismissed {
    dismissed: Vec<String>,
    #[serde(deserialize_with = "hex::bytes")]
    state: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotStates {
    open_suggestion: OpenSuggestion,
    compacted_with_dismissed: CompactedWithDismissed,
}

fn units(rows: &[frasil_adapter_loro::LayerRow]) -> Vec<String> {
    rows.iter().map(|row| hex::encode(row.unit)).collect()
}

#[test]
fn snapshot_state() {
    let states: SnapshotStates = vectors::family(FILE, "snapshot_state");
    let open = SnapshotState::read(&states.open_suggestion.state).unwrap();
    assert_eq!(units(&open.suggestions), states.open_suggestion.suggestions);
    assert!(open.dismissed.is_empty());
    assert_eq!(open.encode(), states.open_suggestion.state);

    let compacted = SnapshotState::read(&states.compacted_with_dismissed.state).unwrap();
    assert!(compacted.suggestions.is_empty());
    assert_eq!(
        units(&compacted.dismissed),
        states.compacted_with_dismissed.dismissed
    );
    assert_eq!(compacted.encode(), states.compacted_with_dismissed.state);
    // The suggestion is kept whole: author, incarnation and blob.
    assert_eq!(compacted.dismissed, open.suggestions);
    assert_eq!(open.suggestions[0].incarnation, 9);

    // The stand-ins are not Loro's bytes: the pinned Loro does not import
    // them, so a replica refuses either state (section 3.5).
    let loro = Loro::new();
    for state in [
        &states.open_suggestion.state,
        &states.compacted_with_dismissed.state,
    ] {
        assert_eq!(
            loro.load(state).map(|_| ()).map_err(Class::name),
            Err("Malformed")
        );
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactionRow {
    writer: String,
    capabilities: Vec<(String, u64)>,
    adapter: String,
    snapshot_unit: String,
}

#[test]
fn compaction_checks() {
    let rows: Vec<CompactionRow> = vectors::family(FILE, "compaction_checks");
    assert_eq!(rows.len(), 3);
    let loro = Loro::new();
    for row in rows {
        assert_eq!(row.adapter, TYPE);
        let context = Context::new([1; 32], [2; 16], [3; 32], [4; 32], 5, 5, Role::Snapshot)
            .with_capabilities(capabilities(&row.capabilities));
        assert_eq!(
            verdict(loro.decode(&[], &context)),
            row.snapshot_unit,
            "{}",
            row.writer
        );
    }
    // A snapshot unit's content is empty.
    let context = Context::new([1; 32], [2; 16], [3; 32], [4; 32], 5, 5, Role::Snapshot);
    assert_eq!(
        loro.decode(&Content::edit(1, Vec::new()).encode(), &context)
            .map(|_| ()),
        Err(ErrorClass::Malformed.into())
    );
}
