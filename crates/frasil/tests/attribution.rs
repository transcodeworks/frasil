//! Attribution at a change's place (decision: a client toolkit): a change
//! names the person whose list held its device when it was written, as
//! the space knew it then, not as the lists stand now.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::platform::ManualClock;
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil::{Change, Detail, MemberId};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};
use frasil_units::stream::Opening;
use std::sync::Arc;

async fn device(key: u8, clock: &Arc<ManualClock>) -> Engine {
    Engine::create(
        Platform::memory().with_clock(clock.clone()),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    let ingested = to.ingest(space, from.events(&space).await).await.unwrap();
    assert!(ingested.refused.is_empty(), "{:?}", ingested.refused);
}

/// A space with persons A and B granted, each with a first device, a
/// document, and a device `d` on the lists `on` names before the grants,
/// so that the grants wrap the space's keys to it; it holds the space and
/// both lists.
struct Scene {
    clock: Arc<ManualClock>,
    alice: Engine,
    pa: Engine,
    pb: Engine,
    d: Engine,
    space: EventId,
    doc: Opening,
    a: [u8; 32],
    b: [u8; 32],
}

async fn scene(keys: u8, on: &[usize]) -> Scene {
    let clock = Arc::new(ManualClock::new(1_000, Some(1_800_000_000)));
    let alice = device(keys, &clock).await;
    let pa = device(keys + 1, &clock).await;
    let pb = device(keys + 2, &clock).await;
    let d = device(keys + 3, &clock).await;
    let a = pa.make_person(&[keys + 1; 32]).await.unwrap().person;
    let b = pb.make_person(&[keys + 2; 32]).await.unwrap().person;
    for (index, (person, holder)) in [(a, &pa), (b, &pb)].into_iter().enumerate() {
        if on.contains(&index) {
            let (keys, proof) = d.list_keys(&person, &holder.device_id());
            holder.add_device(keys, proof).await.unwrap();
        }
    }
    let space = alice.create_space().await.unwrap();
    for (person, holder) in [(a, &pa), (b, &pb)] {
        alice
            .receive_list(holder.list_events(&person).await)
            .await
            .unwrap();
        alice
            .grant_person(
                space,
                person,
                Level::Write,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
        alice.publish_list(space, &person).await.unwrap();
    }
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, "base").unwrap();
        })
        .await
        .unwrap();
    // The persons' first devices hold the space: the one that adds a
    // device to its person's list delivers it the space's state.
    for holder in [&pa, &pb] {
        holder.follow(space).await;
        carry(&alice, holder, space).await;
    }
    d.follow(space).await;
    for (person, holder) in [(a, &pa), (b, &pb)] {
        d.receive_list(holder.list_events(&person).await)
            .await
            .unwrap();
    }
    carry(&alice, &d, space).await;
    Scene {
        clock,
        alice,
        pa,
        pb,
        d,
        space,
        doc,
        a,
        b,
    }
}

impl Scene {
    /// Adds `d` to a person's list, through that person's first device,
    /// and carries the list to Alice, the space and `d`.
    async fn add(&self, person: [u8; 32]) {
        let holder = if person == self.a { &self.pa } else { &self.pb };
        let (keys, proof) = self.d.list_keys(&person, &holder.device_id());
        carry(&self.alice, holder, self.space).await;
        holder.add_device(keys, proof).await.unwrap();
        carry(holder, &self.alice, self.space).await;
        self.publish(person).await;
    }

    /// Revokes `d` from a person's list, and carries the list on.
    async fn revoke(&self, person: [u8; 32]) {
        let holder = if person == self.a { &self.pa } else { &self.pb };
        carry(&self.alice, holder, self.space).await;
        holder.revoke_device(self.d.device_id()).await.unwrap();
        carry(holder, &self.alice, self.space).await;
        self.publish(person).await;
    }

    async fn publish(&self, person: [u8; 32]) {
        let holder = if person == self.a { &self.pa } else { &self.pb };
        let events = holder.list_events(&person).await;
        self.alice.receive_list(events.clone()).await.unwrap();
        // A revocation owes the space its cascaded rotation first, and a
        // device added owes it a delivery of the state.
        self.maintain().await;
        self.alice.publish_list(self.space, &person).await.unwrap();
        self.maintain().await;
        self.d.receive_list(events).await.unwrap();
        carry(&self.alice, &self.d, self.space).await;
    }

    /// Alice signs what the space owes, a rotation or a delivery, waiting
    /// her rank's delay on the clock.
    async fn maintain(&self) {
        for _ in 0..4_000 {
            carry(&self.alice, &self.d, self.space).await;
            if self.alice.owed_responses(&self.space).await.is_empty()
                && self.d.owed_responses(&self.space).await.is_empty()
            {
                return;
            }
            self.alice.maintain(self.space).await.unwrap();
            self.clock.advance(1);
        }
        panic!("nothing became due");
    }

    /// `d` writes a unit, which Alice receives.
    async fn write(&self, text: &str) -> EventId {
        let unit = self
            .d
            .edit_document(self.space, &self.doc, |d| {
                d.get_text("body").insert(0, text).unwrap();
            })
            .await
            .unwrap();
        carry(&self.d, &self.alice, self.space).await;
        unit
    }

    async fn history(&self) -> Vec<Change> {
        self.alice
            .stream_history(self.space, self.doc.stream())
            .await
            .unwrap()
    }
}

fn change(history: &[Change], unit: EventId) -> &Change {
    history
        .iter()
        .find(|c| *c.id.as_bytes() == unit.0)
        .expect("the change")
}

fn persons(change: &Change) -> Vec<[u8; 32]> {
    change
        .author
        .persons
        .iter()
        .map(|p| *p.as_bytes())
        .collect()
}

#[tokio::test]
async fn a_moved_device_keeps_its_earlier_changes_under_its_first_person() {
    let s = scene(10, &[0]).await;
    let first = s.write("one ").await;
    // `d` leaves A for B: off A first, so that Alice alone makes the
    // cascaded rotation, then onto B, which Alice delivers the state to.
    s.revoke(s.a).await;
    s.add(s.b).await;
    let second = s.write("two ").await;
    let history = s.history().await;
    let first = change(&history, first);
    let second = change(&history, second);
    // Only A's add was copied at the first unit's place (roster.md, 3.11).
    assert_eq!(persons(first), vec![s.a], "written through A");
    assert_eq!(persons(second), vec![s.b], "written through B");
    assert!(matches!(first.detail, Detail::Document(Some(_))));
}

#[tokio::test]
async fn a_revoked_device_keeps_its_person_on_what_it_wrote_before() {
    let s = scene(20, &[0]).await;
    let unit = s.write("one ").await;
    s.revoke(s.a).await;
    carry(&s.d, &s.alice, s.space).await;
    let history = s.history().await;
    assert_eq!(persons(change(&history, unit)), vec![s.a], "person A still");
    assert_eq!(
        change(&history, unit).author.device,
        MemberId::from_bytes(s.d.device_id().0)
    );
}

#[tokio::test]
async fn a_device_on_two_lists_names_both_persons() {
    let s = scene(30, &[0, 1]).await;
    let unit = s.write("both ").await;
    let history = s.history().await;
    let found = change(&history, unit);
    let mut named = persons(found);
    named.sort_unstable();
    let mut expected = vec![s.a, s.b];
    expected.sort_unstable();
    assert_eq!(named, expected);
    assert_eq!(
        found.author.person.map(|p| *p.as_bytes()),
        Some(persons(found)[0]),
        "the first of them"
    );
}

#[tokio::test]
async fn a_second_person_added_later_does_not_change_the_first_edit() {
    let s = scene(40, &[0]).await;
    let first = s.write("one ").await;
    s.add(s.b).await;
    let second = s.write("two ").await;
    let history = s.history().await;
    assert_eq!(persons(change(&history, first)), vec![s.a]);
    let mut both = vec![s.a, s.b];
    both.sort_unstable();
    assert_eq!(persons(change(&history, second)), both);
}
