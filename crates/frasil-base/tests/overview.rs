//! `overview.json`: every family, as `claims.txt` lists them.

use frasil_base::cbor::{self, Value};
use frasil_base::errors::Class;
use frasil_base::time::{
    self, Elapsed, ONLINE_FRESHNESS_WHEN_ON, POLICY_VALUES, Reading, TIMERS, Timeline, Timer,
};
use frasil_testkit::vectors;
use serde::Deserialize;

const FILE: &str = "overview.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimerRow {
    name: String,
    bounds: String,
    default: Option<u64>,
    minimum: Option<u64>,
    maximum: Option<u64>,
    set_by: String,
    counted: Option<String>,
    #[serde(rename = "in")]
    documents: Vec<String>,
    default_text: Option<String>,
}

#[test]
fn timers() {
    let rows: Vec<TimerRow> = vectors::family(FILE, "timers");
    assert_eq!(rows.len(), TIMERS.len());
    for (row, spec) in rows.iter().zip(TIMERS.iter()) {
        let name = &row.name;
        assert_eq!(spec.name, name);
        assert_eq!(Timer::from_name(name), Some(spec.timer), "{name}");
        assert_eq!(spec.bounds, row.bounds, "{name}");
        assert_eq!(spec.default, row.default, "{name}");
        assert_eq!(spec.minimum, row.minimum, "{name}");
        assert_eq!(spec.maximum, row.maximum, "{name}");
        assert_eq!(spec.set_by.as_str(), row.set_by, "{name}");
        assert_eq!(spec.counted, row.counted.as_deref(), "{name}");
        assert_eq!(spec.documents, row.documents, "{name}");
        assert_eq!(spec.default_text, row.default_text.as_deref(), "{name}");
    }
}

#[test]
fn online_freshness_when_on() {
    let value: u64 = vectors::family(FILE, "online_freshness_when_on");
    assert_eq!(ONLINE_FRESHNESS_WHEN_ON, value);
}

#[test]
fn policy_values() {
    let names: Vec<String> = vectors::family(FILE, "policy_values");
    let ours: Vec<&str> = POLICY_VALUES.iter().map(|timer| timer.name()).collect();
    assert_eq!(ours, names);
    for timer in Timer::ALL {
        assert_eq!(
            POLICY_VALUES.contains(&timer),
            timer.spec().set_by == time::SetBy::SpacePolicy,
            "{}",
            timer.name()
        );
    }
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
struct ReadingRow {
    timeline: u64,
    wall: Option<u64>,
    run: u64,
}

impl From<ReadingRow> for Reading {
    fn from(row: ReadingRow) -> Self {
        Reading {
            timeline: row.timeline,
            wall: row.wall,
            run: row.run,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    action: String,
    wall: Option<u64>,
    mono: u64,
    reading: Option<ReadingRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TimelineCase {
    description: String,
    steps: Vec<Step>,
}

#[test]
fn timelines() {
    let cases: Vec<TimelineCase> = vectors::family(FILE, "timelines");
    assert!(!cases.is_empty());
    for case in cases {
        let name = &case.description;
        let mut timeline: Option<Timeline> = None;
        for (index, step) in case.steps.iter().enumerate() {
            match step.action.as_str() {
                // A start keeps nothing but the reading kept at rest.
                "start" => {
                    let kept = timeline.as_ref().map(Timeline::kept);
                    timeline = Some(Timeline::start(kept, step.wall, step.mono));
                }
                "resume" => timeline
                    .as_mut()
                    .unwrap_or_else(|| panic!("{name}: resume before start"))
                    .resume(step.wall, step.mono),
                "read" => {
                    let reading = timeline
                        .as_mut()
                        .unwrap_or_else(|| panic!("{name}: read before start"))
                        .read(step.mono, step.wall);
                    let expected = step.reading.expect("a read gives its reading");
                    assert_eq!(reading, expected.into(), "{name}, step {index}");
                }
                other => panic!("{name}: unknown action {other:?}"),
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EstimateCase {
    scenario: String,
    since: ReadingRow,
    now: ReadingRow,
    lower: u64,
    upper: serde_json::Value,
}

#[test]
fn estimates() {
    let cases: Vec<EstimateCase> = vectors::family(FILE, "estimates");
    assert!(!cases.is_empty());
    for case in cases {
        let name = &case.scenario;
        let (since, now) = (case.since.into(), case.now.into());
        assert_eq!(time::lower(&since, &now), case.lower, "{name}");
        let upper = match &case.upper {
            serde_json::Value::String(text) if text == "unbounded" => Elapsed::Unbounded,
            value => Elapsed::Seconds(value.as_u64().expect("seconds or \"unbounded\"")),
        };
        assert_eq!(time::upper(&since, &now), upper, "{name}");
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpiryCase {
    value: String,
    case: String,
    expires_at: u64,
    now_wall: Option<u64>,
    lifetime: u64,
    skew: u64,
    outcome: String,
}

fn outcome<C: Class>(result: Result<impl Sized, C>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(class) => class.name(),
    }
}

#[test]
fn check_expiry() {
    let cases: Vec<ExpiryCase> = vectors::family(FILE, "check_expiry");
    assert!(!cases.is_empty());
    for case in cases {
        let name = format!("{}, {}", case.value, case.case);
        // The lifetime and skew are the timer table's for that value.
        let (lifetime, skew) = match case.value.as_str() {
            "an admission code request" => (
                Timer::AdmissionCodeLifetime.spec().default,
                Timer::AdmissionCodeSkew.spec().default,
            ),
            "a library ticket's not_after" => (
                Timer::TicketLifetime.spec().maximum,
                Timer::TicketSkew.spec().default,
            ),
            "a device-signed request" => (
                Timer::SignedRequestLifetime.spec().default,
                Timer::SignedRequestSkew.spec().default,
            ),
            other => panic!("unknown value {other:?}"),
        };
        assert_eq!(
            (Some(case.lifetime), Some(case.skew)),
            (lifetime, skew),
            "{name}"
        );
        let result = time::check_expiry(case.expires_at, case.now_wall, case.lifetime, case.skew);
        assert_eq!(outcome(result), case.outcome, "{name}");
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyCase {
    name: String,
    value: serde_json::Value,
    outcome: String,
}

/// The value as a policy carries it: its CBOR encoding, outside the
/// deterministic subset where the value is (a negative integer).
fn policy_encoding(value: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        serde_json::Value::Number(number) => match (number.as_u64(), number.as_i64()) {
            (Some(unsigned), _) => cbor::unsigned(&mut out, unsigned),
            (None, Some(negative)) => cbor::head(&mut out, 1, (-1 - negative).unsigned_abs()),
            _ => panic!("not an integer: {number}"),
        },
        serde_json::Value::String(text) => cbor::text(&mut out, text),
        other => panic!("no encoding for {other}"),
    }
    out
}

#[test]
fn check_policy() {
    let cases: Vec<PolicyCase> = vectors::family(FILE, "check_policy");
    assert!(!cases.is_empty());
    for case in cases {
        let label = format!("{} = {}", case.name, case.value);
        let timer = Timer::from_name(&case.name).unwrap_or_else(|| panic!("{label}"));
        // A value outside the subset is refused as it is decoded, before
        // check_policy's own step 1 could see it; the class is the same.
        let result = cbor::decode(&policy_encoding(&case.value))
            .map_err(frasil_base::ErrorClass::from)
            .and_then(|value: Value| time::check_policy(timer, &value));
        assert_eq!(outcome(result), case.outcome, "{label}");
        // check_policy's step 1 on its own, for a decoded value that is not
        // unsigned.
        if let serde_json::Value::String(text) = &case.value {
            let result = time::check_policy(timer, &Value::from(text.as_str()));
            assert_eq!(outcome(result), case.outcome, "{label}");
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NestingCase {
    name: String,
    depth: usize,
    encoding: String,
    result: String,
}

/// Section 5.3: nesting to the limit decodes, one level more is `Malformed`.
#[test]
fn cbor_nesting() {
    let cases: Vec<NestingCase> = vectors::family(FILE, "cbor_nesting");
    assert_eq!(cases.len(), 4);
    for case in cases {
        let name = &case.name;
        let bytes = frasil_testkit::hex::decode(&case.encoding).unwrap();
        let result = cbor::decode(&bytes).map_err(frasil_base::ErrorClass::from);
        let got = match &result {
            Ok(_) => "accepted",
            Err(class) => class.name(),
        };
        assert_eq!(got, case.result, "{name}");
        assert_eq!(case.depth <= cbor::MAX_DEPTH, result.is_ok(), "{name}");
        // The reader's own items obey the same limit.
        let mut reader = cbor::Reader::new(&bytes);
        assert_eq!(reader.value().is_ok(), result.is_ok(), "{name}");
    }
}
