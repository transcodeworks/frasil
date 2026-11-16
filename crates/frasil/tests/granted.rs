//! Grants of spaces: a project that grants a team, whose members reach it
//! through the grant, open its keys from space wraps, and write there.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, MemberRef, Status, Via};

async fn device() -> Engine {
    Engine::create(
        Platform::memory(),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

fn text(doc: &loro::LoroDoc) -> String {
    doc.get_text("body").to_string()
}

/// A team with Carol, and a project that grants the team at `write`.
async fn team_and_project() -> (Engine, Engine, EventId, EventId, EventId) {
    let alice = device().await;
    let carol = device().await;
    let team = alice.create_space().await.unwrap();
    alice
        .grant_device(
            team,
            carol.public_keys().clone(),
            Level::Write,
            HistoryMode::WithHistory,
            Via::Code,
        )
        .await
        .unwrap();
    carol.follow(team).await;
    carry(&alice, &carol, team).await;
    let project = alice.create_space().await.unwrap();
    let grant = alice
        .grant_space(project, team, Level::Write)
        .await
        .unwrap();
    carol.follow(project).await;
    carry(&alice, &carol, project).await;
    (alice, carol, team, project, grant)
}

#[tokio::test]
async fn a_team_member_reaches_a_project_that_grants_the_team() {
    let (alice, carol, _team, project, grant) = team_and_project().await;
    let status = alice
        .read(&project, |r| r.status(&grant).copied())
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    assert_eq!(
        alice
            .read(&project, |r| r.level_of(&carol.device_id()))
            .await
            .unwrap(),
        Some(Level::Write),
        "Carol reaches the project through the team"
    );
    let (level, current) = carol
        .read(&project, |r| {
            (r.level_of(&carol.device_id()), r.current().cloned())
        })
        .await
        .unwrap();
    assert_eq!(level, Some(Level::Write));
    let current = current.expect("Carol holds the project's state");
    let holds = carol
        .read(&project, |r| {
            current.ids().iter().all(|id| r.secrets_held(id))
        })
        .await
        .unwrap();
    assert!(
        holds,
        "Carol opened the space wrap with the team's grant key"
    );

    // Carol writes in the project; Alice accepts it.
    let doc = carol.new_document().unwrap();
    let unit = carol
        .edit_document(project, &doc, |d| {
            d.get_text("body").insert(0, "from the team").unwrap();
        })
        .await
        .unwrap();
    carry(&carol, &alice, project).await;
    let status = alice
        .read(&project, |r| r.status(&unit).copied())
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    assert_eq!(
        text(&alice.document(&project, &doc.stream()).await.unwrap()),
        "from the team"
    );
}

#[tokio::test]
async fn a_rotation_of_the_project_reaches_the_team_by_space_wrap() {
    let (alice, carol, _team, project, _) = team_and_project().await;
    let heal = alice.heal(project).await.unwrap();
    carry(&alice, &carol, project).await;
    let holds = carol
        .read(&project, |r| r.secrets_held(&heal))
        .await
        .unwrap();
    assert!(
        holds,
        "the heal's own delivery seals a space wrap to the team"
    );
}

/// A narrowing capability on a grant of a space applies to every device
/// that reaches the space through it (roster.md, "Grants of spaces and
/// effective membership"; units.md, 3.17 "Capability checks"): when the
/// project makes the team a suggester, a team member's direct edit in the
/// project is refused as content.
#[tokio::test]
async fn a_team_granted_as_a_suggester_writes_no_direct_edit() {
    let (alice, carol, team, project, _) = team_and_project().await;
    alice
        .set_suggester(project, MemberRef::space(team.0), true)
        .await
        .unwrap()
        .expect("the team becomes a suggester");
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(project, &doc, |d| {
            d.get_text("body").insert(0, "for the team").unwrap();
        })
        .await
        .unwrap();
    carry(&alice, &carol, project).await;
    for (engine, whose) in [(&alice, "Alice's"), (&carol, "Carol's")] {
        let (level, suggester) = engine
            .read(&project, |r| {
                (
                    r.level_of(&carol.device_id()),
                    r.capabilities_of(&carol.device_id()).is_suggester(),
                )
            })
            .await
            .unwrap();
        assert_eq!(level, Some(Level::Write), "in {whose} view");
        assert!(
            suggester,
            "Carol is a suggester through the team in {whose} view"
        );
    }
    let unit = carol
        .edit_document(project, &doc, |d| {
            d.get_text("body").insert(0, "from carol, ").unwrap();
        })
        .await
        .unwrap();
    carry(&carol, &alice, project).await;
    let status = alice
        .read(&project, |r| r.status(&unit).copied())
        .await
        .unwrap();
    // Valid by the write rule; its content is refused.
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    assert_eq!(
        text(&alice.document(&project, &doc.stream()).await.unwrap()),
        "for the team",
        "a suggester's direct edit is refused"
    );
}

/// A unit through a granted space stands until a response to the end of
/// its author's path (roster.md, "Checks across logs"), and its author's
/// capabilities stay those of the path it wrote by: a team member made a
/// suggester through the team, then removed from the team, does not gain
/// a direct edit by the removal.
#[tokio::test]
async fn a_suggester_removed_from_the_team_keeps_its_earlier_edit_refused() {
    let (alice, carol, team, project, _) = team_and_project().await;
    alice
        .set_suggester(project, MemberRef::space(team.0), true)
        .await
        .unwrap()
        .expect("the team becomes a suggester");
    let doc = alice.new_document().unwrap();
    alice
        .edit_document(project, &doc, |d| {
            d.get_text("body").insert(0, "for the team").unwrap();
        })
        .await
        .unwrap();
    carry(&alice, &carol, project).await;
    let unit = carol
        .edit_document(project, &doc, |d| {
            d.get_text("body").insert(0, "from carol, ").unwrap();
        })
        .await
        .unwrap();
    alice
        .remove(team, MemberRef::device(carol.device_id()))
        .await
        .unwrap();
    carry(&carol, &alice, project).await;
    let status = alice
        .read(&project, |r| r.status(&unit).copied())
        .await
        .unwrap();
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    assert_eq!(
        text(&alice.document(&project, &doc.stream()).await.unwrap()),
        "for the team",
        "a suggester's direct edit stays refused once its path ends"
    );
}

/// Through a grant of a space, a writer's capabilities are read at the
/// granted space's current roster as the replica holds it (roster.md,
/// "Checks across logs", "Paths"; units.md, 3.17 "Capability checks"): a
/// team member narrowed to a suggester in the team later has its earlier
/// direct edit in the project refused as content from then on, at a
/// replica that had applied it.
#[tokio::test]
async fn a_member_narrowed_later_in_the_team_loses_its_earlier_direct_edit() {
    let (alice, carol, team, project, _) = team_and_project().await;
    let doc = carol.new_document().unwrap();
    let unit = carol
        .edit_document(project, &doc, |d| {
            d.get_text("body").insert(0, "from the team").unwrap();
        })
        .await
        .unwrap();
    carry(&carol, &alice, project).await;
    assert_eq!(
        text(&alice.document(&project, &doc.stream()).await.unwrap()),
        "from the team",
        "a full writer's direct edit is applied"
    );
    alice
        .set_suggester(team, MemberRef::device(carol.device_id()), true)
        .await
        .unwrap()
        .expect("Carol becomes a suggester in the team");
    let (status, outcome, suggester) = alice
        .read(&project, |r| {
            (
                r.status(&unit).copied(),
                r.content_outcome(&unit),
                r.capabilities_of(&carol.device_id()).is_suggester(),
            )
        })
        .await
        .unwrap();
    assert!(suggester, "Carol is a suggester through the team");
    assert!(matches!(status, Some(Status::Valid(_))), "{status:?}");
    assert!(
        matches!(
            outcome,
            Some(frasil::advanced::ContentOutcome::Refused(
                "CapabilityRefused"
            ))
        ),
        "{outcome:?}"
    );
    assert_eq!(
        text(&alice.document(&project, &doc.stream()).await.unwrap()),
        "",
        "the earlier direct edit is refused from then on"
    );
}
