//! Loro round trips: units that carry real Loro bytes, through the checks,
//! merge and rebuild, suggestions, compaction and the history-free export
//! (adapter-loro.md, sections 3.1 to 3.6).

mod support;

use frasil_adapter::{Adapter, Capabilities, Capability, Mode, Outcome, SUGGEST, StreamUnit};
use frasil_adapter_loro::{
    Change, Content, Loro, LoroClass, SnapshotState, Standing, State, check_content,
};
use frasil_base::errors::ErrorClass;
use support::{Replica, event, note, notes, unit, unit_with};

fn suggester() -> Capabilities {
    Capabilities::new([Capability::new(SUGGEST, Mode::Narrows)])
}

fn rebuild(units: &[StreamUnit]) -> State {
    Loro::new().rebuild(None, units).unwrap()
}

fn text(state: &State) -> String {
    state.doc().get_text("t").to_string()
}

#[test]
fn concurrent_units_merge_in_any_order() {
    let loro = Loro::new();
    let mut alice = Replica::new(1, 1);
    let shared = alice.create("Shared", None).unwrap();
    let research = alice.create("Research", None).unwrap();
    alice.edit(shared, "middle").unwrap();
    let first = unit(1, 1, 1, &alice.edit_unit());

    let base = rebuild(std::slice::from_ref(&first));
    let mut bob = Replica::from_doc(base.doc(), 2, 1);
    alice.edit(shared, "left middle").unwrap();
    alice.move_note(shared, Some(research)).unwrap();
    let from_alice = unit(2, 1, 2, &alice.edit_unit());
    bob.edit(shared, "middle right").unwrap();
    bob.rename(shared, "Renamed").unwrap();
    let from_bob = unit(3, 2, 1, &bob.edit_unit());

    let forward = rebuild(&[first.clone(), from_alice.clone(), from_bob.clone()]);
    let backward = rebuild(&[from_bob, from_alice, first]);
    assert!(forward.matches(&backward));
    let merged = note(forward.doc(), shared);
    assert_eq!(merged.body, "left middle right");
    assert_eq!(merged.title, "Renamed");
    assert_eq!(merged.parent, Some(research));
    assert_eq!(notes(forward.doc()), notes(backward.doc()));
    assert!(loro.held(&forward).is_empty());
    assert!(forward.refused().is_empty());
}

#[test]
fn a_blob_is_checked_against_its_writer_and_seq() {
    let loro = Loro::new();
    let mut alice = Replica::new(1, 3);
    alice.doc().get_text("t").insert(0, "hi").unwrap();
    let content = alice.edit_unit();
    // Its own peer, at or after the incarnation's seq.
    for seq in [3, 4, 90] {
        let ok = unit(1, 1, seq, &content);
        assert!(matches!(
            loro.decode(&ok.content, &ok.context),
            Ok(Change::Edit(_))
        ));
    }
    // Before the incarnation began.
    let early = unit(1, 1, 2, &content);
    assert_eq!(
        loro.decode(&early.content, &early.context),
        Err(LoroClass::LoroIncarnation)
    );
    // Another writer cannot write under alice's peer.
    let forged = unit(1, 2, 3, &content);
    assert_eq!(
        loro.decode(&forged.content, &forged.context),
        Err(LoroClass::LoroForeignPeer)
    );
    // Nor can alice claim another incarnation for the same operations.
    let Content::Ops { blob, .. } = &content else {
        unreachable!()
    };
    let other = unit(1, 1, 4, &Content::edit(4, blob.clone()));
    assert_eq!(
        loro.decode(&other.content, &other.context),
        Err(LoroClass::LoroForeignPeer)
    );
    // A snapshot blob, and bytes Loro does not read.
    let snapshot = alice.doc().export(loro::ExportMode::Snapshot).unwrap();
    for blob in [snapshot, b"not Loro".to_vec()] {
        let bad = unit(1, 1, 3, &Content::edit(3, blob));
        assert_eq!(
            loro.decode(&bad.content, &bad.context),
            Err(LoroClass::LoroMalformed)
        );
    }
    // An export holding two peers.
    let mut bob = Replica::from_doc(alice.doc(), 2, 1);
    bob.doc().get_text("t").insert(0, "yo").unwrap();
    bob.edit_unit();
    let both = bob.doc().export(loro::ExportMode::all_updates()).unwrap();
    let bad = unit(1, 2, 1, &Content::edit(1, both));
    assert_eq!(
        loro.decode(&bad.content, &bad.context),
        Err(LoroClass::LoroForeignPeer)
    );
}

#[test]
fn an_incarnation_continues_and_a_gap_waits_inside_loro() {
    let mut alice = Replica::new(1, 1);
    let t = alice.doc().get_text("t");
    t.insert(0, "one ").unwrap();
    let first = unit(1, 1, 1, &alice.edit_unit());
    t.insert(4, "two ").unwrap();
    let second = unit(2, 1, 2, &alice.edit_unit());
    t.insert(8, "three").unwrap();
    let third = unit(3, 1, 3, &alice.edit_unit());

    // The later units arrive first: Loro holds them pending.
    let loro = Loro::new();
    let mut state = loro.empty();
    assert_eq!(loro.receive(&mut state, &third), Outcome::Applied);
    assert_eq!(loro.receive(&mut state, &second), Outcome::Applied);
    assert_eq!(text(&state), "");
    assert!(loro.held(&state).is_empty(), "a gap is not a refusal");
    assert_eq!(loro.receive(&mut state, &first), Outcome::Applied);
    assert_eq!(text(&state), "one two three");
}

/// A restored device that reuses its incarnation writes other operations
/// under counters it already used.
#[test]
fn of_two_overlapping_units_the_later_is_refused_wherever_it_arrived_first() {
    let loro = Loro::new();
    let mut original = Replica::new(1, 1);
    original.doc().get_text("t").insert(0, "kept").unwrap();
    let earlier = unit(1, 1, 1, &original.edit_unit());
    let mut restored = Replica::new(1, 1);
    restored.doc().get_text("t").insert(0, "lost").unwrap();
    let later = unit(2, 1, 2, &restored.edit_unit());

    let mut state = loro.empty();
    assert_eq!(loro.receive(&mut state, &later), Outcome::Applied);
    assert_eq!(text(&state), "lost");
    assert_eq!(loro.receive(&mut state, &earlier), Outcome::Applied);
    assert_eq!(text(&state), "kept");
    assert_eq!(state.refused(), vec![(event(2), LoroClass::LoroOverlap)]);

    let in_order = rebuild(&[earlier.clone(), later.clone()]);
    assert!(state.matches(&in_order));
    let mut state = loro.empty();
    loro.receive(&mut state, &earlier);
    assert_eq!(
        loro.receive(&mut state, &later),
        Outcome::Refused(LoroClass::LoroOverlap)
    );

    // An earlier unit the write rule refuses still counts for step 6.
    let refused_earlier = unit_with(
        1,
        1,
        1,
        &Content::read(&earlier.content).unwrap(),
        Capabilities::none(),
        false,
    );
    let state = rebuild(&[later.clone(), refused_earlier]);
    assert_eq!(text(&state), "");
    assert_eq!(state.refused(), vec![(event(2), LoroClass::LoroOverlap)]);

    // A unit below the counters the base snapshot holds overlaps it.
    let base = rebuild(std::slice::from_ref(&earlier));
    let compaction = loro.compact(&base);
    let over_base = loro.rebuild(Some(&compaction.state), &[later]).unwrap();
    assert_eq!(text(&over_base), "kept");
    assert_eq!(
        over_base.refused(),
        vec![(event(2), LoroClass::LoroOverlap)]
    );
}

#[test]
fn a_refused_unit_resubmitted_after_a_regrant_is_accepted() {
    // Bob's edit is refused, as by his removal; once granted again he
    // re-submits it, the same content in a new unit naming it (units.md,
    // 3.11 "Re-submission"), which step 6 does not count against it.
    let loro = Loro::new();
    let mut alice = Replica::new(1, 1);
    alice.doc().get_text("t").insert(0, "a").unwrap();
    let first = unit(1, 1, 1, &alice.edit_unit());
    let mut bob = Replica::from_doc(alice.doc(), 2, 1);
    bob.doc().get_text("t").insert(1, "b").unwrap();
    let content = Content::read(&bob.edit_unit().encode()).unwrap();
    let refused = unit_with(2, 2, 1, &content, Capabilities::none(), false);
    let mut again = unit(3, 2, 3, &content);
    again.context = again.context.with_resubmits(Some(event(2)));

    let units = [first.clone(), refused.clone(), again.clone()];
    let forward = rebuild(&units);
    assert_eq!(text(&forward), "ab");
    assert!(forward.refused().is_empty());
    let backward = rebuild(&[again.clone(), refused.clone(), first.clone()]);
    assert!(forward.matches(&backward));
    // So too where the refused unit becomes valid again, as when the
    // removal is voided: the same operations arrive twice.
    let mut voided = refused.clone();
    voided.valid = true;
    let both = rebuild(&[first.clone(), voided, again.clone()]);
    assert!(both.matches(&forward));
    // And at a replica that never held the refused unit.
    assert!(rebuild(&[first.clone(), again.clone()]).matches(&forward));

    // The same content naming no unit overlaps it.
    let mut unnamed = again.clone();
    unnamed.context = unnamed.context.with_resubmits(None);
    let mut state = rebuild(&[first.clone(), refused.clone()]);
    assert_eq!(
        loro.receive(&mut state, &unnamed),
        Outcome::Refused(LoroClass::LoroOverlap)
    );
    // Other content naming it overlaps it too.
    let mut other = Replica::from_doc(alice.doc(), 2, 1);
    other.doc().get_text("t").insert(1, "c").unwrap();
    let mut differs = unit(3, 2, 3, &other.edit_unit());
    differs.context = differs.context.with_resubmits(Some(event(2)));
    let mut state = rebuild(&[first, refused]);
    assert_eq!(
        loro.receive(&mut state, &differs),
        Outcome::Refused(LoroClass::LoroOverlap)
    );
}

#[test]
fn leaving_a_unit_out_undoes_it() {
    let mut alice = Replica::new(1, 1);
    alice.doc().get_text("t").insert(0, "a").unwrap();
    let first = unit(1, 1, 1, &alice.edit_unit());
    let mut bob = Replica::new(2, 1);
    bob.doc().get_text("u").insert(0, "b").unwrap();
    let second = unit(2, 2, 1, &bob.edit_unit());

    let both = rebuild(&[first.clone(), second.clone()]);
    let mut without = second.clone();
    without.valid = false;
    let subset = rebuild(&[first.clone(), without]);
    assert_eq!(text(&subset), "a");
    assert_eq!(subset.doc().get_text("u").to_string(), "");
    assert_eq!(both.doc().get_text("u").to_string(), "b");
    // Reading a root container leaves the compared value as the units
    // built it.
    let alone = rebuild(&[first]);
    assert!(subset.matches(&alone));
    let compacted = Loro::new()
        .load(&Loro::new().compact(&subset).state)
        .unwrap();
    assert!(compacted.matches(&alone));
}

#[test]
fn an_operation_built_on_a_refused_unit_stays_pending_and_is_reported() {
    let loro = Loro::new();
    let mut removed = Replica::new(1, 1);
    removed.doc().get_text("t").insert(0, "theirs").unwrap();
    let theirs = unit(1, 1, 1, &removed.edit_unit());
    let mut member = Replica::from_doc(removed.doc(), 2, 1);
    member.doc().get_text("t").insert(6, " and mine").unwrap();
    let mine = unit(2, 2, 1, &member.edit_unit());
    let mut later = Replica::from_doc(member.doc(), 2, 1);
    later.doc().get_text("t").insert(0, ">").unwrap();
    let after = unit(3, 2, 2, &later.edit_unit());

    let mut refused = theirs.clone();
    refused.valid = false;
    let state = rebuild(&[refused, mine.clone(), after.clone()]);
    assert_eq!(text(&state), "");
    assert_eq!(
        loro.held(&state),
        vec![
            (event(2), LoroClass::LoroDependsOnRefused),
            (event(3), LoroClass::LoroDependsOnRefused)
        ]
    );
    // Not yet arrived is not refused.
    let waiting = rebuild(std::slice::from_ref(&mine));
    assert!(loro.held(&waiting).is_empty());
    let whole = rebuild(&[theirs, mine, after]);
    assert_eq!(text(&whole), ">theirs and mine");
    assert!(loro.held(&whole).is_empty());
}

/// A main document with "base", and a suggester's suggestion on it.
fn suggestion_fixture() -> (StreamUnit, StreamUnit) {
    let mut alice = Replica::new(1, 1);
    alice.doc().get_text("t").insert(0, "base").unwrap();
    let first = unit(1, 1, 1, &alice.edit_unit());
    let main = rebuild(std::slice::from_ref(&first));
    // The suggester's unit is at seq 4: its incarnation is 4.
    let mut fork = Replica::from_doc(main.doc(), 3, 4);
    fork.doc().get_text("t").insert(4, " suggested").unwrap();
    let suggestion = unit_with(9, 3, 4, &fork.suggestion_unit(), suggester(), true);
    (first, suggestion)
}

#[test]
fn a_suggestion_stays_apart_until_accepted() {
    let loro = Loro::new();
    let (first, suggestion) = suggestion_fixture();
    let open = rebuild(&[first.clone(), suggestion.clone()]);
    assert_eq!(text(&open), "base");
    assert_eq!(open.open(), vec![event(9)]);
    let preview = open.preview(&event(9)).unwrap();
    assert_eq!(preview.get_text("t").to_string(), "base suggested");

    let accept = unit(10, 1, 2, &Content::accept([event(9)]));
    let dismiss = unit(11, 2, 1, &Content::dismiss([event(9)]));
    let orders = [
        vec![
            first.clone(),
            suggestion.clone(),
            accept.clone(),
            dismiss.clone(),
        ],
        vec![
            dismiss.clone(),
            accept.clone(),
            suggestion.clone(),
            first.clone(),
        ],
        vec![
            accept.clone(),
            first.clone(),
            dismiss.clone(),
            suggestion.clone(),
        ],
    ];
    for order in orders {
        let state = rebuild(&order);
        assert_eq!(text(&state), "base suggested", "accept wins over dismiss");
        assert_eq!(state.accepted(), vec![event(9)]);
        assert!(state.open().is_empty() && state.dismissed().is_empty());
        assert!(loro.held(&state).is_empty());
    }

    let dismissed = rebuild(&[first, suggestion, dismiss]);
    assert_eq!(text(&dismissed), "base");
    assert_eq!(dismissed.dismissed(), vec![event(9)]);
    assert_eq!(dismissed.layer()[&event(9)].1, Standing::Dismissed);
}

#[test]
fn an_accept_waits_for_its_target() {
    let loro = Loro::new();
    let (first, suggestion) = suggestion_fixture();
    let accept = unit(10, 1, 2, &Content::accept([event(9)]));
    let mut state = loro.empty();
    loro.receive(&mut state, &first);
    assert_eq!(
        loro.receive(&mut state, &accept),
        Outcome::Waiting(LoroClass::TargetNotHeld)
    );
    assert_eq!(
        loro.held(&state),
        vec![(event(10), LoroClass::TargetNotHeld)]
    );
    assert_eq!(loro.receive(&mut state, &suggestion), Outcome::Applied);
    assert!(loro.held(&state).is_empty());
    assert_eq!(text(&state), "base suggested");
}

#[test]
fn a_suggester_writes_only_suggestions() {
    let loro = Loro::new();
    let (_, suggestion) = suggestion_fixture();
    let mut writer = Replica::new(3, 5);
    writer.doc().get_text("t").insert(0, "x").unwrap();
    for content in [
        writer.edit_unit(),
        Content::accept([event(9)]),
        Content::dismiss([event(9)]),
    ] {
        let unit = unit_with(12, 3, 5, &content, suggester(), true);
        assert_eq!(
            loro.decode(&unit.content, &unit.context).map(|_| ()),
            Err(ErrorClass::CapabilityRefused.into())
        );
    }
    assert!(
        loro.decode(&suggestion.content, &suggestion.context)
            .is_ok()
    );
    // A suggestion not at its own seq.
    let mut moved = suggestion.clone();
    moved.context.seq = 5;
    assert_eq!(
        loro.decode(&moved.content, &moved.context).map(|_| ()),
        Err(LoroClass::LoroIncarnation)
    );
}

#[test]
fn registered_checks_run_after_the_suggest_check() {
    let mut checks = frasil_adapter::CapabilityChecks::new();
    checks.register("no-accepts", |_, _, content| match Content::read(content) {
        Ok(Content::Targets { .. }) => frasil_adapter::Check::Refuse,
        _ => frasil_adapter::Check::Accept,
    });
    let loro = Loro::with_checks(checks.clone());
    let accept = unit(10, 1, 2, &Content::accept([event(9)]));
    assert_eq!(
        loro.decode(&accept.content, &accept.context).map(|_| ()),
        Err(ErrorClass::CapabilityRefused.into())
    );
    // Step 2 comes before step 3: an incarnation after its seq is refused
    // by the check first.
    let late = unit(10, 1, 1, &Content::edit(2, Vec::new()));
    assert_eq!(
        check_content(&late.content, &late.context, &checks, |_| None).map(|_| ()),
        Err(LoroClass::LoroIncarnation)
    );
}

#[test]
fn compaction_keeps_open_and_dismissed_suggestions() {
    let loro = Loro::new();
    let (first, suggestion) = suggestion_fixture();
    let dismiss = unit(11, 2, 1, &Content::dismiss([event(9)]));
    let state = rebuild(&[first.clone(), suggestion.clone(), dismiss.clone()]);
    let compaction = loro.compact(&state);
    assert!(compaction.metadata.is_empty());
    assert_eq!(
        compaction.included,
        [event(1), event(9), event(11)].into_iter().collect()
    );
    let framed = SnapshotState::read(&compaction.state).unwrap();
    assert!(framed.suggestions.is_empty());
    assert_eq!(framed.dismissed.len(), 1);
    assert_eq!(framed.dismissed[0].unit, event(9));
    assert_eq!(framed.dismissed[0].author, [3; 32]);
    assert_eq!(framed.dismissed[0].incarnation, 4);

    // An accept concurrent with the compacted dismiss imports the
    // suggestion at every replica.
    let accept = unit(10, 1, 2, &Content::accept([event(9)]));
    let from_snapshot = loro
        .rebuild(Some(&compaction.state), std::slice::from_ref(&accept))
        .unwrap();
    let from_units = rebuild(&[first, suggestion, dismiss, accept]);
    assert_eq!(text(&from_snapshot), "base suggested");
    assert!(from_snapshot.matches(&from_units));
    assert!(loro.held(&from_snapshot).is_empty());

    // Checking a snapshot: the state loaded matches the rebuild.
    let loaded = loro.load(&compaction.state).unwrap();
    assert!(loaded.matches(&state));
    assert!(!loaded.matches(&from_units));
}

#[test]
fn compaction_excludes_what_the_state_does_not_include() {
    let loro = Loro::new();
    let mut alice = Replica::new(1, 1);
    alice.doc().get_text("t").insert(0, "one").unwrap();
    let first = unit(1, 1, 1, &alice.edit_unit());
    alice.doc().get_text("t").insert(3, " two").unwrap();
    let second = unit(2, 1, 2, &alice.edit_unit());
    let (_, suggestion) = suggestion_fixture();
    let waiting = unit(10, 1, 3, &Content::accept([event(9)]));
    // The cover: the second unit, whose operations wait for the first, and
    // an accept whose target is not held.
    let cut = rebuild(&[second.clone(), waiting.clone()]);
    let compaction = loro.compact(&cut);
    assert!(compaction.included.is_empty());
    // A replica that uses it applies the excluded units and the rest.
    let rebuilt = loro
        .rebuild(
            Some(&compaction.state),
            &[
                second.clone(),
                waiting.clone(),
                first.clone(),
                suggestion.clone(),
            ],
        )
        .unwrap();
    let whole = rebuild(&[first, second, waiting, suggestion]);
    assert!(rebuilt.matches(&whole));
}

#[test]
fn a_history_free_export_drops_history_and_suggestions() {
    let loro = Loro::new();
    let (first, suggestion) = suggestion_fixture();
    let state = rebuild(&[first, suggestion]);
    let exported = loro.export_history_free(&state).unwrap();
    let framed = SnapshotState::read(&exported).unwrap();
    assert!(framed.suggestions.is_empty() && framed.dismissed.is_empty());
    let loaded = loro.load(&exported).unwrap();
    assert!(loaded.is_history_free());
    assert_eq!(text(&loaded), "base");
    assert_eq!(loaded.doc().oplog_vv(), state.doc().oplog_vv());
    assert!(loaded.open().is_empty());

    // A replica that started from it compacts over it, suggestions and all.
    let mut fork = Replica::from_doc(loaded.doc(), 3, 6);
    fork.doc().get_text("t").insert(0, "so, ").unwrap();
    let later = unit_with(13, 3, 6, &fork.suggestion_unit(), suggester(), true);
    let over = loro.rebuild(Some(&exported), &[later]).unwrap();
    let compacted = loro.load(&loro.compact(&over).state).unwrap();
    assert!(compacted.is_history_free());
    assert_eq!(compacted.open(), vec![event(13)]);
    assert!(compacted.matches(&over));
    // An empty document exports too.
    let empty = loro.export_history_free(&loro.empty()).unwrap();
    assert!(loro.load(&empty).is_ok());
}

#[test]
fn units_after_a_history_free_base_apply_over_it() {
    let loro = Loro::new();
    let mut alice = Replica::new(1, 1);
    alice.doc().get_text("t").insert(0, "base").unwrap();
    let first = unit(1, 1, 1, &alice.edit_unit());
    let state = rebuild(std::slice::from_ref(&first));
    let exported = loro.export_history_free(&state).unwrap();
    alice.doc().get_text("t").insert(4, "!").unwrap();
    let next = unit(2, 1, 2, &alice.edit_unit());
    let loaded = loro.rebuild(Some(&exported), &[next]).unwrap();
    assert_eq!(text(&loaded), "base!");
}

#[test]
fn a_late_write_is_reapplied_as_the_reappliers_own_edit() {
    let loro = Loro::new();
    let mut alice = Replica::new(1, 1);
    alice.doc().get_text("t").insert(0, "hello").unwrap();
    let first = unit(1, 1, 1, &alice.edit_unit());
    let original = rebuild(std::slice::from_ref(&first));
    alice.doc().get_text("t").insert(5, " world").unwrap();
    let late = unit(2, 1, 2, &alice.edit_unit());
    let Ok(change) = loro.decode(&late.content, &late.context) else {
        panic!("the late write decodes");
    };

    // The moved document starts from the original's state, in a new stream
    // of a new space; the re-applier writes under its own peer there.
    let moved = State::load(&loro.compact(&original).state).unwrap();
    let writer = frasil_adapter_loro::Incarnation {
        space: [0x77; 32],
        stream: [0x78; 16],
        author: [5; 32],
        incarnation: 1,
    };
    let content = loro
        .reapply_as(&original, &change, &moved, &writer)
        .unwrap();
    let context = frasil_adapter::Context::new(
        writer.space,
        writer.stream,
        [0x30; 32],
        writer.author,
        1,
        1,
        frasil_adapter::Role::Log,
    );
    let StreamUnit { .. } = unit(3, 5, 1, &Content::read(&content).unwrap());
    let decoded = loro.decode(&content, &context).unwrap();
    let mut moved = moved;
    assert_eq!(loro.apply(&mut moved, &context, &decoded), Outcome::Applied);
    assert_eq!(text(&moved), "hello world");
    assert_eq!(
        loro.reapply_as(&original, &Change::Snapshot, &moved, &writer),
        None
    );

    // The interface's `reapply` names the re-applier and its unit's place:
    // it begins a new incarnation there, whose peer is bound to that unit.
    let place = frasil_adapter::Writer {
        space: writer.space,
        stream: writer.stream,
        author: writer.author,
        seq: 4,
    };
    let fresh = State::load(&loro.compact(&original).state).unwrap();
    let content = loro
        .reapply(&original, &late.context, &change, &fresh, &place)
        .unwrap();
    let context = frasil_adapter::Context::new(
        place.space,
        place.stream,
        [0x31; 32],
        place.author,
        place.seq,
        place.seq,
        frasil_adapter::Role::Log,
    );
    let decoded = loro.decode(&content, &context).unwrap();
    let mut fresh = fresh;
    assert_eq!(loro.apply(&mut fresh, &context, &decoded), Outcome::Applied);
    assert_eq!(text(&fresh), "hello world");
}

#[test]
fn a_snapshots_cover_counts_as_held() {
    // A suggestion accepted inside a snapshot's cover is in neither key 3
    // nor key 4 of the state; a dismiss after the cover that names it is
    // held only once the replica marks the cover's units as held
    // (units.md, section 3.6, "Using").
    let loro = Loro::new();
    let mut alice = Replica::new(1, 1);
    alice.doc().get_text("t").insert(0, "base").unwrap();
    let first = unit(1, 1, 1, &alice.edit_unit());
    let mut bob = Replica::from_doc(rebuild(std::slice::from_ref(&first)).doc(), 2, 2);
    bob.doc().get_text("t").insert(4, "?").unwrap();
    let suggestion = unit_with(2, 2, 2, &bob.suggestion_unit(), suggester(), true);
    let accept = unit(3, 1, 3, &Content::accept(vec![event(2)]));
    let cover = [first, suggestion, accept];
    let state = loro.compact(&rebuild(&cover));
    let dismiss = unit(4, 1, 4, &Content::dismiss(vec![event(2)]));

    let mut over = loro.load(&state.state).unwrap();
    loro.receive(&mut over, &dismiss);
    assert_eq!(loro.held(&over), vec![(event(4), LoroClass::TargetNotHeld)]);
    loro.hold(
        &mut over,
        &cover.iter().map(|u| u.context.event_id).collect(),
    );
    assert!(loro.held(&over).is_empty());
}
