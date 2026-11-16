//! `adapter-records.json`: every family, as `claims.txt` lists them.

use frasil_adapter::{
    Adapter, Capabilities, Capability, Context, EventId, Mode, Outcome, Role, StreamUnit,
};
use frasil_adapter_records::{Content, Records, RecordsClass, State, admit};
use frasil_base::cbor::Value;
use frasil_base::errors::Class;
use frasil_testkit::{hex, vectors};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const FILE: &str = "adapter-records.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    #[serde(deserialize_with = "hex::array")]
    space: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    stream: [u8; 16],
    devices: BTreeMap<String, String>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ChangesetRow {
    name: String,
    #[allow(dead_code)]
    note: String,
    #[serde(deserialize_with = "hex::array")]
    author: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    id: [u8; 32],
    clock: u64,
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
}

fn read_parameters() -> Parameters {
    vectors::family(FILE, "parameters")
}

fn changeset_rows() -> Vec<ChangesetRow> {
    vectors::family(FILE, "changesets")
}

fn by_name() -> BTreeMap<String, ChangesetRow> {
    changeset_rows()
        .into_iter()
        .map(|row| (row.name.clone(), row))
        .collect()
}

/// A capability list as the vectors write it: `[[name, mode], ...]`.
fn capabilities(rows: &[(String, u64)]) -> Capabilities {
    rows.iter()
        .map(|(name, mode)| Capability::new(name.clone(), Mode::from_code(*mode).unwrap()))
        .collect()
}

fn context(row: &ChangesetRow, role: Role) -> Context {
    let parameters = read_parameters();
    Context::new(
        parameters.space,
        parameters.stream,
        row.id,
        row.author,
        1,
        1,
        role,
    )
}

fn unit(row: &ChangesetRow, accepted: &BTreeSet<String>) -> StreamUnit {
    StreamUnit {
        context: context(row, Role::Log),
        content: row.content.clone(),
        valid: accepted.contains(&row.name),
    }
}

/// Hands every changeset over in this order: the accepted ones as valid
/// units, the others as units the write rule refuses.
fn rebuild(base: Option<&[u8]>, names: &[String], accepted: &BTreeSet<String>) -> State {
    let rows = by_name();
    let units: Vec<StreamUnit> = names
        .iter()
        .map(|name| unit(&rows[name], accepted))
        .collect();
    Records::new().rebuild(base, &units).unwrap()
}

fn all_names() -> Vec<String> {
    changeset_rows().into_iter().map(|row| row.name).collect()
}

#[test]
fn parameters() {
    let parameters = read_parameters();
    assert_eq!(parameters.devices.len(), 4);
    let devices: BTreeSet<[u8; 32]> = parameters
        .devices
        .values()
        .map(|text| hex::decode_array(text).unwrap())
        .collect();
    for row in changeset_rows() {
        assert!(devices.contains(&row.author), "{}", row.name);
    }
}

#[test]
fn changesets() {
    let records = Records::new();
    let rows = changeset_rows();
    assert_eq!(rows.len(), 8);
    for row in &rows {
        let change = records
            .decode(&row.content, &context(row, Role::Log))
            .unwrap_or_else(|class| panic!("{}: {class}", row.name));
        let Content::Changeset(changeset) = &change else {
            panic!("{}: not a changeset", row.name);
        };
        assert_eq!(changeset.clock, row.clock, "{}", row.name);
        assert_eq!(records.encode(&change), row.content, "{}", row.name);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRow {
    admitted: Vec<String>,
    floor: u64,
    waiting: Vec<String>,
    waiting_class: String,
}

#[test]
fn admission() {
    let expected: AdmissionRow = vectors::family(FILE, "admission");
    let rows = changeset_rows();
    let ids: BTreeMap<EventId, String> =
        rows.iter().map(|row| (row.id, row.name.clone())).collect();
    let (admitted, floor) = admit(rows.iter().map(|row| (row.id, row.clock)), 0);
    let mut admitted: Vec<String> = admitted.iter().map(|id| ids[id].clone()).collect();
    admitted.sort();
    assert_eq!(admitted, expected.admitted);
    assert_eq!(floor, expected.floor);

    // Every changeset accepted, in the vectors' order: the waiting ones are
    // held under the waiting class.
    let records = Records::new();
    let mut state = records.empty();
    let mut waiting = Vec::new();
    for row in &rows {
        let outcome = records.receive(&mut state, &unit(row, &all_names().into_iter().collect()));
        match outcome {
            Outcome::Applied => {}
            Outcome::Waiting(class) => {
                assert_eq!(class.name(), expected.waiting_class);
                waiting.push(row.name.clone());
            }
            other => panic!("{}: {other:?}", row.name),
        }
    }
    assert_eq!(waiting, expected.waiting);
    let held: Vec<String> = records
        .held(&state)
        .into_iter()
        .map(|(id, class)| {
            assert_eq!(class, RecordsClass::ClockAhead);
            ids[&id].clone()
        })
        .collect();
    assert_eq!(held, expected.waiting);
    assert_eq!(state.max_clock(), expected.floor);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriterClock {
    held: Vec<String>,
    floor: u64,
    next_clock: u64,
    not: u64,
    #[allow(dead_code)]
    why: String,
}

#[test]
fn writer_clock() {
    let expected: WriterClock = vectors::family(FILE, "writer_clock");
    let rows = by_name();
    let mut state = State::new();
    let records = Records::new();
    for name in &expected.held {
        let row = &rows[name];
        records.count(&mut state, &context(row, Role::Log), &row.content);
    }
    assert_eq!(state.max_clock(), expected.floor);
    assert_eq!(state.next_clock(), expected.next_clock);
    assert_ne!(state.next_clock(), expected.not);
    let greatest = expected
        .held
        .iter()
        .map(|name| rows[name].clock)
        .max()
        .unwrap();
    assert_eq!(greatest + 1, expected.not);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MergeOrders {
    accepted: Vec<String>,
    orders: Vec<Vec<String>>,
    #[serde(deserialize_with = "hex::bytes")]
    snapshot: Vec<u8>,
    rows: serde_json::Value,
}

fn json(value: &Value) -> serde_json::Value {
    match value {
        Value::Unsigned(n) => serde_json::Value::from(*n),
        Value::Negative(n) => serde_json::Value::from((-1 - i128::from(*n)).to_string()),
        Value::Bool(b) => serde_json::Value::from(*b),
        Value::Float(f) => serde_json::Value::from(format!("f64:{:016x}", f.to_bits())),
        Value::Text(text) => serde_json::Value::from(text.as_str()),
        Value::Bytes(bytes) => serde_json::Value::from(hex::encode(bytes)),
        Value::Array(items) => items.iter().map(json).collect(),
        Value::Map(map) => map
            .iter()
            .map(|(key, value)| (key.to_string(), json(value)))
            .collect::<serde_json::Map<_, _>>()
            .into(),
    }
}

fn visible_rows(state: &State) -> serde_json::Value {
    let mut tables = serde_json::Map::new();
    for (table, rows) in state.rows() {
        let mut out = serde_json::Map::new();
        for (key, columns) in rows {
            let columns: serde_json::Map<String, serde_json::Value> = columns
                .iter()
                .map(|(column, value)| {
                    let items: Vec<serde_json::Value> = value.iter().map(json).collect();
                    (column.clone(), serde_json::Value::from(items))
                })
                .collect();
            out.insert(hex::encode(key), columns.into());
        }
        tables.insert(table, out.into());
    }
    tables.into()
}

#[test]
fn merge_orders() {
    let expected: MergeOrders = vectors::family(FILE, "merge_orders");
    let accepted: BTreeSet<String> = expected.accepted.iter().cloned().collect();
    assert_eq!(expected.orders.len(), 3);
    for order in &expected.orders {
        let state = rebuild(None, order, &accepted);
        assert_eq!(
            hex::encode(state.to_bytes(false)),
            hex::encode(&expected.snapshot),
            "{order:?}"
        );
        assert_eq!(visible_rows(&state), expected.rows, "{order:?}");
    }
    // Each changeset applied twice, and the units handed over one at a
    // time with apply rather than through receive.
    let records = Records::new();
    let rows = by_name();
    let mut state = records.empty();
    for name in expected.orders[1].iter().chain(&expected.orders[2]) {
        let row = &rows[name];
        let context = context(row, Role::Log);
        records.count(&mut state, &context, &row.content);
        if accepted.contains(name) {
            let change = records.decode(&row.content, &context).unwrap();
            records.apply(&mut state, &context, &change);
        }
    }
    assert_eq!(records.compact(&state).state, expected.snapshot);
    // The snapshot loads, and gives itself back.
    let loaded = records.load(&expected.snapshot).unwrap();
    assert_eq!(loaded.to_bytes(false), expected.snapshot);
    assert_eq!(visible_rows(&loaded), expected.rows);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rebuilds {
    with_removed_device: WithRemovedDevice,
    from_snapshot: FromSnapshot,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WithRemovedDevice {
    #[serde(deserialize_with = "hex::bytes")]
    snapshot: Vec<u8>,
    #[allow(dead_code)]
    note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FromSnapshot {
    base_of: Vec<String>,
    #[serde(deserialize_with = "hex::bytes")]
    base: Vec<u8>,
    then_applied: Vec<String>,
    same_as_full: bool,
}

#[test]
fn rebuilds() {
    let expected: Rebuilds = vectors::family(FILE, "rebuilds");
    let merge: MergeOrders = vectors::family(FILE, "merge_orders");
    let accepted: BTreeSet<String> = merge.accepted.iter().cloned().collect();
    let everything = all_names();

    // The late-removed device's changeset applied, then its removal
    // learned: the rebuild without it is merge_orders' snapshot.
    let mut with_d = accepted.clone();
    with_d.insert("c7".to_owned());
    let state = rebuild(None, &everything, &with_d);
    assert_eq!(state.to_bytes(false), expected.with_removed_device.snapshot);
    let without = rebuild(None, &everything, &accepted);
    assert_eq!(without.to_bytes(false), merge.snapshot);

    // A snapshot of the first changesets, then the rest applied over it.
    let from = &expected.from_snapshot;
    let base = rebuild(None, &from.base_of, &accepted);
    let compaction = Records::new().compact(&base);
    assert_eq!(compaction.state, from.base);
    assert!(compaction.metadata.is_empty() && compaction.objects.is_empty());
    let rest: Vec<String> = everything
        .iter()
        .filter(|name| !from.base_of.contains(name))
        .cloned()
        .collect();
    let state = rebuild(Some(&from.base), &rest, &accepted);
    assert!(from.same_as_full);
    assert_eq!(state.to_bytes(false), merge.snapshot);
    let rows = by_name();
    let ids: BTreeMap<EventId, &str> = rows
        .values()
        .map(|row| (row.id, row.name.as_str()))
        .collect();
    let mut applied: Vec<&str> = state.included().iter().map(|id| ids[id]).collect();
    applied.sort();
    assert_eq!(applied, from.then_applied);
}

#[test]
fn history_free() {
    let expected: String = vectors::family(FILE, "history_free");
    let merge: MergeOrders = vectors::family(FILE, "merge_orders");
    let accepted: BTreeSet<String> = merge.accepted.iter().cloned().collect();
    let state = rebuild(None, &all_names(), &accepted);
    let records = Records::new();
    assert_eq!(
        hex::encode(records.export_history_free(&state).unwrap()),
        expected
    );
    let loaded = records.load(&hex::decode(&expected).unwrap()).unwrap();
    assert_eq!(hex::encode(loaded.to_bytes(false)), expected);
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Suggestions {
    suggester_suggestion: SuggesterSuggestion,
    open_without_accept: OpenWithoutAccept,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuggesterSuggestion {
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
    capabilities: Vec<(String, u64)>,
    result: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenWithoutAccept {
    left_out: String,
    #[serde(deserialize_with = "hex::bytes")]
    snapshot: Vec<u8>,
}

#[test]
fn suggestions() {
    let expected: Suggestions = vectors::family(FILE, "suggestions");
    let rows = by_name();
    let suggestion = &expected.suggester_suggestion;
    assert_eq!(suggestion.result, "accepted");
    let c6 = &rows["c6"];
    assert_eq!(c6.content, suggestion.content);
    let suggester =
        context(c6, Role::Log).with_capabilities(capabilities(&suggestion.capabilities));
    let change = Records::new()
        .decode(&suggestion.content, &suggester)
        .unwrap();
    assert!(matches!(change, Content::Changeset(ref c) if c.keys.suggestion));

    let merge: MergeOrders = vectors::family(FILE, "merge_orders");
    let open = &expected.open_without_accept;
    let accepted: BTreeSet<String> = merge
        .accepted
        .iter()
        .filter(|name| **name != open.left_out)
        .cloned()
        .collect();
    let state = rebuild(None, &all_names(), &accepted);
    assert!(state.layer().is_open(&c6.id));
    assert_eq!(
        hex::encode(state.to_bytes(false)),
        hex::encode(&open.snapshot)
    );
    let loaded = Records::new().load(&open.snapshot).unwrap();
    assert_eq!(loaded.to_bytes(false), open.snapshot);
    assert!(loaded.layer().is_open(&c6.id));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refusal {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
    capabilities: Vec<(String, u64)>,
    class: String,
}

#[test]
fn content_refusals() {
    let rows: Vec<Refusal> = vectors::family(FILE, "content_refusals");
    assert_eq!(rows.len(), 9);
    let any = &changeset_rows()[0];
    for row in rows {
        let context = context(any, Role::Log).with_capabilities(capabilities(&row.capabilities));
        let class = Records::new()
            .decode(&row.content, &context)
            .map(|_| ())
            .expect_err(&row.name);
        assert_eq!(class.name(), row.class, "{}", row.name);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactionCheck {
    writer: String,
    capabilities: Vec<(String, u64)>,
    adapter: String,
    snapshot_unit: String,
}

#[test]
fn compaction_checks() {
    let rows: Vec<CompactionCheck> = vectors::family(FILE, "compaction_checks");
    assert_eq!(rows.len(), 3);
    let any = &changeset_rows()[0];
    let records = Records::new();
    for row in rows {
        assert_eq!(row.adapter, Records::TYPE);
        let context =
            context(any, Role::Snapshot).with_capabilities(capabilities(&row.capabilities));
        let verdict = match records.decode(&[], &context) {
            Ok(_) => "accepted",
            Err(class) => class.name(),
        };
        assert_eq!(verdict, row.snapshot_unit, "{}", row.writer);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NestingRow {
    name: String,
    #[serde(deserialize_with = "hex::array")]
    author: [u8; 32],
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
    id: Option<String>,
    result: String,
    state: Option<String>,
}

/// Section 2.1: a value nests at most 8 levels, and the state such a value
/// yields nests to the decoders' limit of 16 and loads.
#[test]
fn value_nesting() {
    let rows: Vec<NestingRow> = vectors::family(FILE, "value_nesting");
    assert_eq!(rows.len(), 2);
    let parameters = read_parameters();
    for row in rows {
        let name = &row.name;
        let id: EventId = row
            .id
            .as_deref()
            .map_or([0; 32], |text| hex::decode_array(text).unwrap());
        let context = Context::new(
            parameters.space,
            parameters.stream,
            id,
            row.author,
            1,
            1,
            Role::Log,
        );
        let records = Records::new();
        let decoded = records.decode(&row.content, &context);
        let Some(state) = row.state.as_deref() else {
            let class = decoded.map(|_| ()).expect_err(name);
            assert_eq!(class.name(), row.result, "{name}");
            continue;
        };
        assert_eq!(row.result, "accepted", "{name}");
        decoded.unwrap_or_else(|class| panic!("{name}: {class}"));
        let state = hex::decode(state).unwrap();
        let unit = StreamUnit {
            context,
            content: row.content.clone(),
            valid: true,
        };
        let built = records.rebuild(None, &[unit]).unwrap();
        assert_eq!(
            hex::encode(built.to_bytes(false)),
            hex::encode(&state),
            "{name}"
        );
        assert_eq!(
            records.load(&state).unwrap().to_bytes(false),
            state,
            "{name}"
        );
        // The state nests exactly to the limit.
        assert!(frasil_base::cbor::decode(&state).is_ok(), "{name}");
        assert!(
            frasil_base::cbor::decode_with_depth(&state, frasil_base::cbor::MAX_DEPTH - 1).is_err(),
            "{name}"
        );
    }
}

/// Section 2.1: the records subset's integers, booleans and floats, and
/// the items outside it.
#[test]
fn value_types() {
    let rows: Vec<NestingRow> = vectors::family(FILE, "value_types");
    assert_eq!(rows.len(), 10);
    let parameters = read_parameters();
    for row in rows {
        let name = &row.name;
        let id: EventId = row
            .id
            .as_deref()
            .map_or([0; 32], |text| hex::decode_array(text).unwrap());
        let context = Context::new(
            parameters.space,
            parameters.stream,
            id,
            row.author,
            1,
            1,
            Role::Log,
        );
        let records = Records::new();
        let decoded = records.decode(&row.content, &context);
        let Some(state) = row.state.as_deref() else {
            let class = decoded.map(|_| ()).expect_err(name);
            assert_eq!(class.name(), row.result, "{name}");
            continue;
        };
        assert_eq!(row.result, "accepted", "{name}");
        decoded.unwrap_or_else(|class| panic!("{name}: {class}"));
        let state = hex::decode(state).unwrap();
        let unit = StreamUnit {
            context,
            content: row.content.clone(),
            valid: true,
        };
        let built = records.rebuild(None, &[unit]).unwrap();
        assert_eq!(
            hex::encode(built.to_bytes(false)),
            hex::encode(&state),
            "{name}"
        );
        assert_eq!(
            records.load(&state).unwrap().to_bytes(false),
            state,
            "{name}"
        );
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimedChangeset {
    name: String,
    #[serde(deserialize_with = "hex::array")]
    author: [u8; 32],
    #[serde(deserialize_with = "hex::array")]
    id: [u8; 32],
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimedCell {
    column: String,
    written_by: String,
    time: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeTimes {
    changesets: Vec<TimedChangeset>,
    table: String,
    #[serde(deserialize_with = "hex::bytes")]
    key: Vec<u8>,
    cells: Vec<TimedCell>,
    last_change: LastChangeRow,
    #[serde(deserialize_with = "hex::bytes")]
    state: Vec<u8>,
    refusals: Vec<TimeRefusal>,
    state_refusals: Vec<StateRefusal>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LastChangeRow {
    column: String,
    by: String,
    time: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeRefusal {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    content: Vec<u8>,
    class: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateRefusal {
    name: String,
    #[serde(deserialize_with = "hex::bytes")]
    state: Vec<u8>,
    class: String,
}

/// Sections 2.2 and 2.3: each cell keeps the time its changeset claims,
/// the row's last change is its cell with the greatest stamp, and the
/// state carries both.
#[test]
fn change_times() {
    let f: ChangeTimes = vectors::family(FILE, "change_times");
    let parameters = read_parameters();
    let records = Records::new();
    let mut ids = BTreeMap::new();
    let units: Vec<StreamUnit> = f
        .changesets
        .iter()
        .map(|c| {
            ids.insert(c.name.clone(), c.id);
            let context = Context::new(
                parameters.space,
                parameters.stream,
                c.id,
                c.author,
                1,
                1,
                Role::Log,
            );
            records.decode(&c.content, &context).unwrap();
            StreamUnit {
                context,
                content: c.content.clone(),
                valid: true,
            }
        })
        .collect();
    let state = records.rebuild(None, &units).unwrap();
    assert_eq!(hex::encode(state.to_bytes(false)), hex::encode(&f.state));
    let loaded = records.load(&f.state).unwrap();
    assert_eq!(loaded.to_bytes(false), f.state);
    for built in [&state, &loaded] {
        for cell in &f.cells {
            let found = built.cell(&f.table, &f.key, &cell.column).unwrap();
            assert_eq!(
                found.stamp.event_id, ids[&cell.written_by],
                "{}",
                cell.column
            );
            assert_eq!(found.time, cell.time, "{}", cell.column);
        }
        let last = built.last_change(&f.table, &f.key).unwrap();
        assert_eq!(last.stamp.event_id, ids[&f.last_change.by]);
        assert_eq!(last.time, f.last_change.time);
        assert_eq!(
            built.cell(&f.table, &f.key, &f.last_change.column),
            Some(last)
        );
    }
    for row in f.refusals {
        let context = Context::new(
            parameters.space,
            parameters.stream,
            [0; 32],
            [0; 32],
            1,
            1,
            Role::Log,
        );
        let class = records
            .decode(&row.content, &context)
            .map(|_| ())
            .expect_err(&row.name);
        assert_eq!(class.name(), row.class, "{}", row.name);
    }
    for row in f.state_refusals {
        let class = records.load(&row.state).map(|_| ()).expect_err(&row.name);
        assert_eq!(class.name(), row.class, "{}", row.name);
    }
}
