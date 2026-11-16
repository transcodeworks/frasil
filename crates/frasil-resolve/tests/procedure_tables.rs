//! `roster.json`, family `procedure_tables`: roster.md, 3.7 The resolution
//! procedure, over events, attacks and authority given as tables.
//!
//! Event `i` is the `i`th of the case's events, which the vectors list in
//! canonical order, so the engine's order (height, then ID) is theirs.

use std::collections::BTreeMap;

use frasil_base::{Class, ErrorClass};
use frasil_resolve::{How, Resolve, Verdict, View, resolve};
use frasil_testkit::vectors;
use serde_json::Value as Json;

const FILE: &str = "roster.json";

frasil_base::error_classes! {
    /// roster.md's classes the tables name.
    pub enum TableClass {
        /// (a): a concurrent event removes the author.
        RemovedConcurrently = "removed_concurrently", Final;
        /// (c): a concurrent event removes a member this one grants or
        /// changes.
        TargetRemovedConcurrently = "target_removed_concurrently", Final;
        /// A change or removal of a member not in.
        NoSuchMember = "no_such_member", Final;
    }
}

/// A row's text field.
fn text(row: &Json, key: &str) -> String {
    row[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key}: not text in {row}"))
        .to_owned()
}

/// A row's array of text.
fn texts(row: &Json, key: &str) -> Vec<String> {
    row[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key}: not an array in {row}"))
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

/// A row's array of rows.
fn rows<'a>(row: &'a Json, key: &str) -> &'a [Json] {
    row[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key}: not an array in {row}"))
}

/// The keys a row has, sorted: each row has exactly the fields this test
/// reads.
fn keys(row: &Json) -> Vec<&str> {
    row.as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

/// One authority rule: the event's authority fails with `class` unless
/// (`needs`) or while (`bars`) `other` is valid.
struct Rule {
    needs: bool,
    other: u32,
    class: TableClass,
}

/// A case as a log the engine resolves.
struct Table {
    parents: Vec<Vec<u32>>,
    attacks: BTreeMap<(u32, u32), TableClass>,
    rules: BTreeMap<u32, Vec<Rule>>,
    seniority: BTreeMap<u32, usize>,
}

fn class(name: &str) -> TableClass {
    TableClass::from_name(name).unwrap_or_else(|| panic!("no class {name}"))
}

impl Table {
    fn new(case: &Json) -> (Self, Vec<String>) {
        let events = rows(case, "events");
        let names: Vec<String> = events.iter().map(|e| text(e, "name")).collect();
        let id = |name: &str| names.iter().position(|n| n == name).unwrap() as u32;
        let mut rules: BTreeMap<u32, Vec<Rule>> = BTreeMap::new();
        for row in rows(case, "authority") {
            assert_eq!(keys(row), ["class", "event", "other", "rule"]);
            let needs = match text(row, "rule").as_str() {
                "needs" => true,
                "bars" => false,
                other => panic!("no rule {other}"),
            };
            rules
                .entry(id(&text(row, "event")))
                .or_default()
                .push(Rule {
                    needs,
                    other: id(&text(row, "other")),
                    class: class(&text(row, "class")),
                });
        }
        let table = Self {
            parents: events
                .iter()
                .map(|e| {
                    assert_eq!(keys(e), ["name", "parents"]);
                    texts(e, "parents").iter().map(|p| id(p)).collect()
                })
                .collect(),
            attacks: rows(case, "attacks")
                .iter()
                .map(|a| {
                    assert_eq!(keys(a), ["attacker", "class", "target"]);
                    (
                        (id(&text(a, "attacker")), id(&text(a, "target"))),
                        class(&text(a, "class")),
                    )
                })
                .collect(),
            rules,
            seniority: texts(case, "seniority")
                .iter()
                .enumerate()
                .map(|(rank, name)| (id(name), rank))
                .collect(),
        };
        (table, names)
    }

    fn ids(&self) -> Vec<u32> {
        (0..self.parents.len() as u32).collect()
    }

    /// The authority rules, with `valid` saying which events are valid.
    fn authority_under(&self, event: u32, valid: impl Fn(u32) -> bool) -> Result<(), TableClass> {
        for rule in self.rules.get(&event).into_iter().flatten() {
            if valid(rule.other) != rule.needs {
                return Err(rule.class);
            }
        }
        Ok(())
    }
}

impl Resolve for Table {
    type Id = u32;
    type Class = TableClass;
    type PickKey = (usize, u32);

    fn height(&self, event: u32) -> u64 {
        self.parents[event as usize]
            .iter()
            .map(|&p| self.height(p) + 1)
            .max()
            .unwrap_or(0)
    }

    fn precedes(&self, earlier: u32, later: u32) -> bool {
        self.parents[later as usize]
            .iter()
            .any(|&p| p == earlier || self.precedes(earlier, p))
    }

    fn check(&self, _event: u32) -> Result<(), TableClass> {
        Ok(())
    }

    fn forked(&self, _event: u32) -> Option<TableClass> {
        None
    }

    fn self_lowering(&self, _event: u32) -> bool {
        false
    }

    fn authority(&self, event: u32, view: &View<'_, Self>) -> Result<(), TableClass> {
        self.authority_under(event, |other| view.is_valid(other))
    }

    fn attack(&self, attacker: u32, event: u32) -> Option<TableClass> {
        self.attacks.get(&(attacker, event)).copied()
    }

    fn pick_key(&self, event: u32, _view: &View<'_, Self>) -> (usize, u32) {
        (self.seniority[&event], event)
    }
}

/// The assignments of every event that the agreement step allows, in its
/// order: of two, the first makes void the earliest event on which they
/// differ.
fn allowed(table: &Table, names: &[String]) -> Vec<Vec<String>> {
    let n = names.len() as u32;
    let mut out = Vec::new();
    for bits in 0..1u32 << n {
        // The first event is the most significant bit; void is 0.
        let valid = |e: u32| (bits >> (n - 1 - e)) & 1 == 1;
        let consistent = table.ids().into_iter().all(|e| {
            let holds = table.authority_under(e, valid).is_ok();
            let beaten = table
                .attacks
                .keys()
                .any(|&(x, target)| target == e && valid(x));
            valid(e) == (holds && !beaten)
        });
        if consistent {
            out.push(
                table
                    .ids()
                    .into_iter()
                    .filter(|&e| valid(e))
                    .map(|e| names[e as usize].clone())
                    .collect(),
            );
        }
    }
    out
}

/// A verdict as the vectors write it.
fn row(verdict: &Verdict<u32, TableClass>, names: &[String]) -> Json {
    match verdict {
        Verdict::Valid(how) => serde_json::json!({
            "status": "valid",
            "how": match how {
                How::Rules => "rules",
                How::Agreed => "agreed",
                How::Seniority => "seniority",
            },
        }),
        Verdict::Void { class, by: None } => {
            serde_json::json!({"status": "void", "class": class.name()})
        }
        Verdict::Void { class, by: Some(x) } => serde_json::json!({
            "status": "void",
            "class": class.name(),
            "by": names[*x as usize],
        }),
    }
}

#[test]
fn procedure_tables() {
    let cases: Vec<Json> = vectors::family(FILE, "procedure_tables");
    assert_eq!(cases.len(), 1);
    for case in &cases {
        assert_eq!(
            keys(case),
            [
                "allowed",
                "attacks",
                "authority",
                "events",
                "name",
                "seniority",
                "verdicts"
            ]
        );
        let name = text(case, "name");
        let (table, names) = Table::new(case);
        let expected: Vec<Vec<String>> = rows(case, "allowed")
            .iter()
            .map(|a| {
                a.as_array()
                    .unwrap()
                    .iter()
                    .map(|e| e.as_str().unwrap().to_owned())
                    .collect()
            })
            .collect();
        assert_eq!(allowed(&table, &names), expected, "{name}");
        // Any arrival order gives the same verdicts.
        for ids in [table.ids(), table.ids().into_iter().rev().collect()] {
            let resolution = resolve(&table, ids);
            for (e, event) in names.iter().enumerate() {
                let verdict = resolution.verdict(e as u32).expect("every event decided");
                assert_eq!(
                    row(verdict, &names),
                    case["verdicts"][event],
                    "{name}: {event}"
                );
            }
        }
    }
}

#[test]
fn the_classes_have_their_wire_names() {
    for class in TableClass::OWN {
        assert_eq!(
            class.to_string(),
            frasil_base::errors::snake_case(class.name())
        );
    }
    assert_eq!(
        TableClass::from(ErrorClass::NotAnAdministrator).name(),
        "NotAnAdministrator"
    );
}
