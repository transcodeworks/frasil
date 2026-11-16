//! Reserved capabilities (roster.md, 2.3 Changes): names that begin
//! `frasil.` are Frasil's. A client signs one only where a document of
//! Frasil's it implements sets it, or where a change carries it over from
//! the member's own state, and refuses any other one an application asks
//! for. An application's own names are signed as asked.

use frasil::Error;
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil_events::EventId;
use frasil_space::{Capability, CapabilityMode, Change, HistoryMode, Level, MemberRef, Op, Via};

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

fn capability(name: &str, mode: CapabilityMode) -> Capability {
    Capability {
        name: name.to_owned(),
        mode,
    }
}

/// A grant of `to` at `write`, with these capabilities.
fn grant(to: &Engine, capabilities: Vec<Capability>) -> Change {
    let mut change = Change::grant_device(
        to.public_keys().clone(),
        Level::Write,
        HistoryMode::WithHistory,
        Via::Code,
    );
    change.capabilities = Some(capabilities);
    change
}

async fn capabilities_of(device: &Engine, space: &EventId, member: &MemberRef) -> Vec<Capability> {
    device
        .read(space, |r| {
            r.roster()
                .state(member)
                .map(|state| state.capabilities.iter().cloned().collect())
        })
        .await
        .unwrap()
        .unwrap_or_default()
}

#[tokio::test]
async fn an_application_cannot_sign_a_reserved_capability() {
    let alice = device().await;
    let bob = device().await;
    let space = alice.create_space().await.unwrap();
    let bob_member = MemberRef::device(bob.device_id());

    // A reserved name no document of Frasil's sets is refused, in a grant
    // and in a change.
    let refused = alice
        .sign_roster(
            space,
            vec![grant(
                &bob,
                vec![capability("frasil.anything", CapabilityMode::Narrows)],
            )],
        )
        .await;
    assert!(matches!(refused, Err(Error::Invalid(_))), "{refused:?}");
    assert!(
        alice
            .read(&space, |r| r.roster().state(&bob_member).is_none())
            .await
            .unwrap(),
        "nothing was signed"
    );

    // An application's own name is signed as asked.
    alice
        .sign_roster(
            space,
            vec![grant(
                &bob,
                vec![capability("suggest", CapabilityMode::Narrows)],
            )],
        )
        .await
        .unwrap();
    let change = Change {
        capabilities: Some(vec![capability("frasil.anything", CapabilityMode::Extends)]),
        ..Change::new(Op::Change, Some(bob_member))
    };
    let refused = alice.sign_roster(space, vec![change]).await;
    assert!(matches!(refused, Err(Error::Invalid(_))), "{refused:?}");
    assert_eq!(
        capabilities_of(&alice, &space, &bob_member).await,
        vec![capability("suggest", CapabilityMode::Narrows)]
    );
}

/// ext-guests.md's `frasil.nothing-at-rest`, narrowing, is set by the
/// guest preset, and a change of the member's other capabilities carries
/// it over. With the other mode it is not what the document sets.
#[cfg(feature = "ext-guests")]
#[tokio::test]
async fn frasils_own_capability_is_signed_and_carried_over() {
    use frasil_space::ext_guests::{NOTHING_AT_REST, Preset};

    let alice = device().await;
    let guest = device().await;
    let space = alice.create_space().await.unwrap();
    let member = MemberRef::device(guest.device_id());

    let refused = alice
        .sign_roster(
            space,
            vec![grant(
                &guest,
                vec![capability(NOTHING_AT_REST, CapabilityMode::Extends)],
            )],
        )
        .await;
    assert!(matches!(refused, Err(Error::Invalid(_))), "{refused:?}");

    let mut preset = Preset::new(Level::Write, [9; 16]);
    preset.nothing_at_rest = true;
    alice
        .grant_guest(space, guest.public_keys().clone(), &preset)
        .await
        .unwrap();
    assert_eq!(
        capabilities_of(&alice, &space, &member).await,
        vec![capability(NOTHING_AT_REST, CapabilityMode::Narrows)]
    );

    // Making the guest a suggester carries the reserved capability over.
    alice
        .set_suggester(space, member, true)
        .await
        .unwrap()
        .expect("a change");
    assert_eq!(
        capabilities_of(&alice, &space, &member).await,
        vec![
            capability(NOTHING_AT_REST, CapabilityMode::Narrows),
            capability("suggest", CapabilityMode::Narrows),
        ]
    );
}
