//! What resolving a roster costs when members that do not administer sign
//! roster events (roster.md, 3.7 The resolution procedure): such an event's
//! author has no standing in its past, so it is void before the procedure
//! and never contested, and the causal order between contested events is
//! read from the view's space pasts, not walked.

use crate::adapters::AdapterRegistry;
use crate::device::{Engine, SIGN_UNCHECKED};
use crate::platform::Platform;
use frasil_events::EventId;
use frasil_space::{Change, HistoryMode, Level, MemberRef, Status, Via};

async fn device(key: u8) -> Engine {
    Engine::create(Platform::memory(), &[key; 32], AdapterRegistry::new())
        .await
        .expect("a device")
        .0
}

/// How many roster events the reader signs: enough that a walk for each
/// pair (JUNK^2 / 2) lands far above the bounds below, and a linear cost far
/// under them. Each event the reader signs refreshes its own replica, which
/// verifies its earlier ones again, so the set-up grows with its square.
const JUNK: usize = 100;

fn not_an_administrator() -> frasil_space::RosterClass {
    frasil_space::RosterClass::from(frasil_base::ErrorClass::NotAnAdministrator)
}

async fn grant(admin: &Engine, space: EventId, member: &Engine, level: Level) {
    admin
        .grant_device_at(
            space,
            member.public_keys().clone(),
            level,
            (level == Level::Administer).then_some(255),
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
}

async fn take(to: &Engine, space: EventId, from: &Engine) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

/// Signs `changes` as `by`, whatever `by`'s own view says of its
/// authority: what a member that holds the space's keys can do by hand.
async fn sign_by_hand(by: &Engine, space: EventId, changes: Vec<Change>) -> EventId {
    SIGN_UNCHECKED.with(|unchecked| unchecked.set(true));
    let signed = by.sign_roster(space, changes).await;
    SIGN_UNCHECKED.with(|unchecked| unchecked.set(false));
    signed.unwrap()
}

#[tokio::test]
async fn a_readers_roster_events_are_judged_without_walking_the_log_for_each_pair() {
    let alice = device(1).await;
    let bob = device(2).await;
    let carol = device(3).await;
    let space = alice.create_space().await.unwrap();
    for reader in [&bob, &carol] {
        grant(&alice, space, reader, Level::Read).await;
    }
    bob.follow(space).await;
    take(&bob, space, &alice).await;

    // Bob, a reader, signs roster events by hand: each opens and verifies,
    // and none can be valid, since no event names Bob at `administer`.
    let mut junk = Vec::with_capacity(JUNK);
    for _ in 0..JUNK {
        junk.push(
            sign_by_hand(
                &bob,
                space,
                vec![Change::set_level(
                    MemberRef::device(carol.device_id()),
                    Level::Read,
                )],
            )
            .await,
        );
    }

    // Alice takes them all and resolves her roster.
    let before = frasil_events::log::precedes_walks();
    take(&alice, space, &bob).await;
    let walks = frasil_events::log::precedes_walks() - before;

    for id in &junk {
        let status = alice.read(&space, |r| r.status(id).copied()).await.unwrap();
        assert!(
            matches!(status, Some(Status::Void { class, by: None }) if class == not_an_administrator()),
            "{status:?}"
        );
    }
    // Every pair of contested events once walked would be JUNK^2 / 2
    // walks; reading the space pasts leaves far fewer.
    let bound = (JUNK * JUNK / 8) as u64;
    assert!(
        walks < bound,
        "{walks} walks of the log for {JUNK} junk roster events (bound {bound})"
    );
}

/// A contest among administrators, then a reader's roster events after it
/// all, each of which would wait on the contest if it were contested: the
/// contest's verdicts are the same with none, some and many of them, and
/// the procedure weighs no more events for them.
#[tokio::test]
async fn a_readers_roster_events_leave_a_contest_as_it_is_and_are_not_weighed() {
    let alice = device(11).await; // the founder
    let carol = device(12).await; // an administrator
    let bob = device(13).await; // raised by alice
    let erin = device(14).await; // raised by alice
    let dave = device(15).await; // a writer every side changes
    let mallory = device(16).await; // a reader
    let olive = device(17).await; // a reader that judges
    let space = alice.create_space().await.unwrap();
    grant(&alice, space, &carol, Level::Administer).await;
    for writer in [&bob, &erin, &dave] {
        grant(&alice, space, writer, Level::Write).await;
    }
    for reader in [&mallory, &olive] {
        grant(&alice, space, reader, Level::Read).await;
    }
    for other in [&carol, &bob, &erin, &dave, &mallory, &olive] {
        other.follow(space).await;
        take(other, space, &alice).await;
    }
    let bob_member = MemberRef::device(bob.device_id());
    let erin_member = MemberRef::device(erin.device_id());
    let dave_member = MemberRef::device(dave.device_id());

    // Alice raises Bob and Erin; Carol, concurrently, removes Bob and
    // lowers Dave; Bob, raised, removes Dave; Erin, after all three,
    // raises Dave back.
    let raise = sign_by_hand(
        &alice,
        space,
        vec![
            Change::raise(bob_member, 255),
            Change::raise(erin_member, 255),
        ],
    )
    .await;
    let counter = sign_by_hand(
        &carol,
        space,
        vec![
            Change::remove(bob_member),
            Change::set_level(dave_member, Level::Read),
        ],
    )
    .await;
    take(&bob, space, &alice).await;
    let removal = sign_by_hand(&bob, space, vec![Change::remove(dave_member)]).await;
    for from in [&alice, &carol, &bob] {
        take(&erin, space, from).await;
    }
    let after = sign_by_hand(
        &erin,
        space,
        vec![Change::set_level(dave_member, Level::Write)],
    )
    .await;
    let contest = [raise, counter, removal, after];

    for from in [&alice, &carol, &bob, &erin] {
        take(&olive, space, from).await;
        take(&mallory, space, from).await;
    }
    let verdicts = |engine: &Engine| {
        let engine = engine.clone();
        async move {
            engine
                .read(&space, |r| {
                    contest
                        .iter()
                        .map(|id| r.status(id).copied())
                        .collect::<Vec<_>>()
                })
                .await
                .unwrap()
        }
    };
    let alone = verdicts(&olive).await;
    assert!(alone.iter().all(Option::is_some), "{alone:?}");

    // Mallory, a reader, signs a chain of roster events after the contest,
    // in two batches; Olive takes each.
    let mut junk = Vec::with_capacity(2 * JUNK);
    let mut costs = Vec::new();
    for _ in 0..2 {
        for _ in 0..JUNK {
            junk.push(
                sign_by_hand(
                    &mallory,
                    space,
                    vec![Change::set_level(dave_member, Level::Write)],
                )
                .await,
            );
        }
        let (runs, weighed) = frasil_space::resolutions_weighed();
        let walks = frasil_events::log::precedes_walks();
        take(&olive, space, &mallory).await;
        let (runs_after, weighed_after) = frasil_space::resolutions_weighed();
        costs.push((
            runs_after - runs,
            weighed_after - weighed,
            frasil_events::log::precedes_walks() - walks,
        ));
        assert_eq!(verdicts(&olive).await, alone);
    }
    for id in &junk {
        let status = olive.read(&space, |r| r.status(id).copied()).await.unwrap();
        assert!(
            matches!(status, Some(Status::Void { class, by: None }) if class == not_an_administrator()),
            "{status:?}"
        );
    }
    // The procedure weighs the space's roster events from administrators
    // and none of Mallory's: per run, a handful, whatever their number.
    for &(runs, weighed, _) in &costs {
        assert!(runs > 0);
        assert!(
            weighed <= runs * 16,
            "{weighed} contested events over {runs} runs with {JUNK} junk events more"
        );
    }
    // Twice the junk costs about twice the walks, not four times.
    let (first, second) = (costs[0].2, costs[1].2);
    assert!(
        second <= 3 * first + 4 * JUNK as u64,
        "{first} walks for {JUNK} junk events, then {second} for {}",
        2 * JUNK
    );
}
