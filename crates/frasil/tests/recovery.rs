//! Recovery without a peer (identity.md, "Recovery keys", "Passkey
//! members", "Fetch keys and recovery entries", "Recovery"): the sheet and
//! its text, the wraps a recovery key receives, the entries the personal
//! space records, and a device that recovers from events carried by hand.
#![cfg(feature = "adapter-loro")]

use frasil::advanced::recovery::{RecoveryMember, RecoveryStatus};
use frasil::advanced::{AdapterRegistry, Engine, Platform};
use frasil::{Device, Options, RecoverySheet, Storage};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Level, Via};

async fn engine(key: u8) -> Engine {
    Engine::create(
        Platform::memory(),
        &[key; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device")
    .0
}

async fn carry(from: &Engine, to: &Engine, space: EventId) {
    to.ingest(space, from.events(&space).await).await.unwrap();
}

async fn note(engine: &Engine, space: EventId, body: &str) -> [u8; 16] {
    let doc = engine.new_document().unwrap();
    engine
        .edit_document(space, &doc, |d| {
            d.get_text("body").insert(0, body).unwrap();
        })
        .await
        .unwrap();
    doc.stream()
}

async fn text(engine: &Engine, space: &EventId, stream: &[u8; 16]) -> String {
    engine
        .document(space, stream)
        .await
        .map(|doc| doc.get_text("body").to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn the_sheet_reads_back_and_refuses_a_mistyped_secret() {
    let device = Device::open_with(Storage::Memory, &[1; 32], Options::new())
        .await
        .unwrap();
    assert_eq!(
        device
            .create_recovery_sheet()
            .await
            .unwrap_err()
            .to_string(),
        frasil::Error::NotAllowed("the device is no person's").to_string()
    );
    let made = device.engine().make_person(&[1; 32]).await.unwrap();
    let sheet = device.create_recovery_sheet().await.unwrap();
    assert_eq!(sheet.secret().len(), 55 + 13);
    assert!(!format!("{sheet:?}").contains(sheet.secret()));
    let read = RecoverySheet::read(&sheet.text().to_lowercase()).unwrap();
    assert_eq!(read.secret().to_uppercase(), sheet.secret());
    assert_eq!(*read.person().as_bytes(), made.person);
    assert_eq!(read.personal_space().as_bytes(), &made.personal_space.0);
    // One character of the secret changed, at a known position, to a
    // different value: the sheet's checksum then fails whatever the
    // secret's alphabet gave.
    let mistyped = {
        let text = sheet.text().to_owned();
        let at = text
            .find(sheet.secret())
            .expect("the secret is in the text")
            + 1;
        let other = if text.as_bytes()[at] == b'A' {
            "B"
        } else {
            "A"
        };
        format!("{}{}{}", &text[..at], other, &text[at + 1..])
    };
    let error = RecoverySheet::read(&mistyped).unwrap_err();
    assert!(
        error.class_name() == Some("InvalidSheet") || matches!(error, frasil::Error::Invalid(_))
    );
    assert!(matches!(
        RecoverySheet::read("Secret: AAAA")
            .unwrap_err()
            .class_name(),
        Some("InvalidSheet")
    ));
}

#[tokio::test]
async fn a_recovery_key_receives_wraps_and_records_its_entries() {
    let alice = engine(1).await;
    let made = alice.make_person(&[1; 32]).await.unwrap();
    let work = alice.create_space().await.unwrap();
    alice
        .grant_person(
            work,
            made.person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::None,
        )
        .await
        .unwrap();
    let key = alice.add_recovery_key().await.unwrap();
    assert_eq!(key.personal_space, made.personal_space);
    // The recovery key is a recipient of the person's grants, at the
    // person's level (identity.md, "Kinds of list member").
    let recipients = alice.person_recipients(&made.person, Level::Write).await;
    assert_eq!(recipients.len(), 2);
    // The personal space records the recovery key's entry, and one for the
    // work space under a seed of its own.
    let entries = alice.recovery_entries().await;
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|(space, _)| *space == made.personal_space)
    );
    assert!(entries.iter().any(|(space, _)| *space == work));
    // Nothing more to record until another space grants the person.
    assert!(alice.ensure_recovery_entries().await.unwrap().is_empty());
    let other = alice.create_space().await.unwrap();
    alice
        .grant_person(
            other,
            made.person,
            Level::Read,
            HistoryMode::WithHistory,
            Via::None,
        )
        .await
        .unwrap();
    assert_eq!(alice.ensure_recovery_entries().await.unwrap().len(), 1);
    assert_eq!(alice.recovery_entries().await.len(), 3);
}

#[tokio::test]
async fn a_device_recovers_from_carried_events() {
    let alice = engine(1).await;
    let made = alice.make_person(&[1; 32]).await.unwrap();
    let work = alice.create_space().await.unwrap();
    alice
        .grant_person(
            work,
            made.person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::None,
        )
        .await
        .unwrap();
    let mine = note(&alice, made.personal_space, "my own").await;
    let key = alice.add_recovery_key().await.unwrap();
    // A rotation after the recovery key was added wraps for it too.
    alice.heal(work).await.unwrap();
    let at_work = note(&alice, work, "at work").await;

    // A wrong secret derives a list member the list does not hold.
    let stranger = engine(2).await;
    let wrong = RecoveryMember::from_sheet(
        &frasil_identity::recovery::RecoverySecret::from_bytes(&[3; 32]).printed(),
        made.person,
        made.personal_space,
    )
    .unwrap();
    stranger.begin_recovery(wrong).await.unwrap();
    carry(&alice, &stranger, made.personal_space).await;
    assert_ne!(stranger.recovery_status().await, RecoveryStatus::Ready);
    assert_eq!(
        stranger
            .complete_recovery(&[2; 32])
            .await
            .unwrap_err()
            .class_name(),
        Some("NotOnList")
    );

    let phone = engine(9).await;
    let member =
        RecoveryMember::from_sheet(&key.printed, made.person, made.personal_space).unwrap();
    assert_eq!(
        phone.begin_recovery(member).await.unwrap(),
        made.personal_space
    );
    assert_eq!(phone.recovery_status().await, RecoveryStatus::Fetching);
    carry(&alice, &phone, made.personal_space).await;
    assert_eq!(phone.recovery_status().await, RecoveryStatus::Ready);
    let recovered = phone.complete_recovery(&[9; 32]).await.unwrap();
    assert_eq!(recovered.person, made.person);
    assert_eq!(recovered.others, vec![work]);
    assert_eq!(phone.person().await, Some(made.person));
    assert_eq!(text(&phone, &made.personal_space, &mine).await, "my own");
    carry(&alice, &phone, work).await;
    assert!(phone.reaches(&work).await);
    assert_eq!(text(&phone, &work, &at_work).await, "at work");
    phone.publish_list(work, &made.person).await.unwrap();
    phone.end_recovery().await;
    assert_eq!(phone.recovery_status().await, RecoveryStatus::NotRecovering);
    // The phone writes, and Alice's device judges it a device of the person.
    let written = note(&phone, work, "back again").await;
    carry(&phone, &alice, work).await;
    assert_eq!(text(&alice, &work, &written).await, "back again");
}

#[tokio::test]
async fn a_passkey_member_needs_two_evaluations_that_agree() {
    let alice = engine(1).await;
    alice.make_person(&[1; 32]).await.unwrap();
    assert_eq!(
        alice
            .add_passkey_member(&[1; 32], &[2; 32])
            .await
            .unwrap_err()
            .class_name(),
        Some("UnstablePrf")
    );
    assert_eq!(
        alice
            .add_passkey_member(&[1; 31], &[1; 31])
            .await
            .unwrap_err()
            .class_name(),
        Some("InvalidPrfOutput")
    );
    alice.add_passkey_member(&[1; 32], &[1; 32]).await.unwrap();
    assert_eq!(
        alice
            .add_passkey_member(&[1; 32], &[1; 32])
            .await
            .unwrap_err()
            .class_name(),
        Some("AlreadyListed")
    );
    assert_eq!(alice.recovery_entries().await.len(), 1);
}
