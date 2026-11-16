//! Recovery against a peer on loopback (identity.md, "Recovery"; peers.md,
//! "Presenting a credential", recovery entries): a person who loses their
//! only device returns with the recovery sheet or a passkey on a new
//! device, which fetches the personal space through the recovery entry,
//! signs itself in, reaches the person's other space through its own entry,
//! reads both and writes. A wrong sheet is refused, and catch-up through a
//! fetch key reaches the newest state after the older entries retired.
//! Every wait has a deadline, and nothing leaves the host.

use frasil::advanced::Engine;
use frasil::{
    Device, Options, Passkey, PasskeyAssertion, PasskeyFuture, PrfOutput, RecoverySheet, Storage,
};
use frasil_conformance::spawn_loopback;
use frasil_events::EventId;
use frasil_relay::testing::{TestPeer, spawn_with};
use frasil_space::{HistoryMode, Level, Via};
use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

/// Waits until `check` holds, polling.
async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

async fn text(engine: &Engine, space: &EventId, stream: &[u8; 16]) -> String {
    engine
        .document(space, stream)
        .await
        .map(|doc| doc.get_text("body").to_string())
        .unwrap_or_default()
}

/// A note in a space.
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

/// A person's only device: the personal space and a work space that grants
/// the person, a note in each, kept at the peer.
struct Person {
    device: Device,
    person: [u8; 32],
    personal: EventId,
    work: EventId,
    personal_note: [u8; 16],
    work_note: [u8; 16],
}

async fn person(peer: &TestPeer) -> Person {
    let device = device(1).await;
    let engine = device.engine();
    let made = engine.make_person(&[1; 32]).await.unwrap();
    let work = engine.create_space().await.unwrap();
    engine
        .grant_person(
            work,
            made.person,
            Level::Write,
            HistoryMode::WithHistory,
            Via::None,
        )
        .await
        .unwrap();
    let personal_note = note(engine, made.personal_space, "my own").await;
    let work_note = note(engine, work, "at work").await;
    device.connect(&peer.origin).await.unwrap();
    Person {
        device,
        person: made.person,
        personal: made.personal_space,
        work,
        personal_note,
        work_note,
    }
}

impl Person {
    /// Waits until every change is durable at the peer, and the peer holds
    /// a live recovery entry in each space.
    async fn settled(&self, peer: &TestPeer) {
        let engine = self.device.engine();
        until(|| async {
            let durable = engine.outbox(&self.personal).await.is_empty()
                && engine.outbox(&self.work).await.is_empty();
            let registered = [self.personal, self.work].iter().all(|space| {
                peer.peer
                    .recovery_entries(&space.0)
                    .is_some_and(|entries| !entries.is_empty())
            });
            durable && registered
        })
        .await;
    }
}

/// Reads both notes on the recovered device, then writes in the work space
/// and waits until the peer keeps it. Returns the new note.
async fn reads_and_writes(recovered: &Device, lost: &Person) -> [u8; 16] {
    let engine = recovered.engine();
    until(|| async {
        text(engine, &lost.personal, &lost.personal_note).await == "my own"
            && text(engine, &lost.work, &lost.work_note).await == "at work"
    })
    .await;
    assert_eq!(engine.person().await, Some(lost.person));
    assert!(
        engine
            .person_devices(&lost.person)
            .await
            .contains(&engine.device_id()),
        "the new device is on the person's list"
    );
    let written = note(engine, lost.work, "back again").await;
    assert_eq!(text(engine, &lost.work, &written).await, "back again");
    until(|| async { engine.outbox(&lost.work).await.is_empty() }).await;
    written
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_person_recovers_from_the_sheet_and_reads_both_spaces() {
    let peer = spawn_loopback().await.unwrap();
    let lost = person(&peer).await;
    let sheet = lost.device.create_recovery_sheet().await.unwrap();
    assert_eq!(*sheet.person().as_bytes(), lost.person);
    assert_eq!(sheet.personal_space().as_bytes(), &lost.personal.0);
    lost.settled(&peer).await;
    let text_form = sheet.text();
    drop(sheet);
    // The only device is lost.
    lost.device.close().await.unwrap();

    let phone = within(Device::recover(
        Storage::Memory,
        &[9; 32],
        &text_form,
        &peer.origin,
        Options::new().loopback(),
    ))
    .await
    .unwrap();
    let written = reads_and_writes(&phone, &lost).await;
    until(|| async { phone.engine().outbox(&lost.personal).await.is_empty() }).await;

    // The phone is lost too. The same sheet brings the person back once
    // more, and the next device judges the phone's note valid through the
    // list the phone published.
    phone.close().await.unwrap();
    let tablet = within(Device::recover(
        Storage::Memory,
        &[10; 32],
        &text_form,
        &peer.origin,
        Options::new().loopback(),
    ))
    .await
    .unwrap();
    until(|| async { text(tablet.engine(), &lost.work, &written).await == "back again" }).await;
    assert_eq!(
        tablet.engine().person_devices(&lost.person).await.len(),
        4,
        "the recipients: the lost device, the recovery key, the phone and the tablet"
    );
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_sheet_is_refused() {
    let peer = spawn_loopback().await.unwrap();
    let lost = person(&peer).await;
    let sheet = lost.device.create_recovery_sheet().await.unwrap();
    lost.settled(&peer).await;

    // A mistyped secret does not read.
    let mut mistyped: Vec<char> = sheet.secret().chars().collect();
    mistyped[0] = if mistyped[0] == 'A' { 'B' } else { 'A' };
    let mistyped: String = mistyped.into_iter().collect();
    let text = sheet.text().replace(sheet.secret(), &mistyped);
    let error = Device::recover(
        Storage::Memory,
        &[9; 32],
        &text,
        &peer.origin,
        Options::new().loopback(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.class_name(), Some("InvalidSheet"));

    // A sheet of another recovery key reads, and the peer holds no entry of
    // its fetch key.
    let stranger = device(3).await;
    stranger.engine().make_person(&[3; 32]).await.unwrap();
    let other = stranger.create_recovery_sheet().await.unwrap();
    let text = sheet.text().replace(sheet.secret(), other.secret());
    assert!(RecoverySheet::read(&text).is_ok());
    let error = within(Device::recover(
        Storage::Memory,
        &[9; 32],
        &text,
        &peer.origin,
        Options::new().loopback(),
    ))
    .await
    .unwrap_err();
    assert_eq!(error.class_name(), Some("CredentialRefused"));
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn catch_up_through_a_fetch_key_after_old_entries_retired() {
    // A peer that keeps two live entries per space: older rotations'
    // entries retire as new ones are stored.
    let mut options = frasil_conformance::options();
    options.settings.credential_cap = 2;
    let peer = spawn_with(options).await.unwrap();
    let lost = person(&peer).await;
    let sheet = lost.device.create_recovery_sheet().await.unwrap();
    lost.settled(&peer).await;
    // The spaces rotate, each wrapping for the recovery key, and the person
    // writes after the rotations.
    let engine = lost.device.engine();
    for _ in 0..3 {
        engine.heal(lost.personal).await.unwrap();
        engine.heal(lost.work).await.unwrap();
    }
    let late = note(engine, lost.personal, "after the rotations").await;
    lost.settled(&peer).await;
    for space in [lost.personal, lost.work] {
        let retired = peer
            .peer
            .entries(&space.0)
            .unwrap()
            .iter()
            .filter(|entry| entry.status == frasil_peers::entries::EntryStatus::Retired)
            .count();
        assert!(retired > 0, "older entries retired");
    }
    let text_form = sheet.text();
    lost.device.close().await.unwrap();

    let phone = within(Device::recover(
        Storage::Memory,
        &[9; 32],
        &text_form,
        &peer.origin,
        Options::new().loopback(),
    ))
    .await
    .unwrap();
    until(|| async { text(phone.engine(), &lost.personal, &late).await == "after the rotations" })
        .await;
    let _ = reads_and_writes(&phone, &lost).await;
    peer.shutdown().await;
}

/// A passkey in software: a PRF of a fixed secret, and the user handle of
/// its registration. It stands in for WebAuthn.
struct SoftPasskey {
    secret: [u8; 32],
    handle: Mutex<Option<Vec<u8>>>,
}

impl SoftPasskey {
    fn output(&self, input: &[u8; 32]) -> Vec<u8> {
        frasil_crypto::primitives::sha256(&[&self.secret, input]).to_vec()
    }
}

impl Passkey for SoftPasskey {
    fn register<'a>(
        &'a self,
        user_handle: &'a [u8; 64],
        prf_input: &'a [u8; 32],
    ) -> PasskeyFuture<'a, Option<PrfOutput>> {
        *self.handle.lock().unwrap() = Some(user_handle.to_vec());
        let output = self.output(prf_input);
        Box::pin(async move { Ok(Some(output.into())) })
    }

    fn assert<'a>(&'a self, prf_input: &'a [u8; 32]) -> PasskeyFuture<'a, PasskeyAssertion> {
        let user_handle = self.handle.lock().unwrap().clone().unwrap_or_default();
        let output = self.output(prf_input);
        Box::pin(async move {
            Ok(PasskeyAssertion {
                user_handle,
                prf_output: Some(output.into()),
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_synced_passkey_brings_the_person_back() {
    let peer = spawn_loopback().await.unwrap();
    let lost = person(&peer).await;
    let passkey = SoftPasskey {
        secret: [5; 32],
        handle: Mutex::new(None),
    };
    lost.device.add_passkey(&passkey).await.unwrap();
    lost.settled(&peer).await;
    lost.device.close().await.unwrap();

    // The passkey's provider synced it to the new device.
    let laptop = within(Device::recover_with_passkey(
        Storage::Memory,
        &[9; 32],
        &passkey,
        &peer.origin,
        Options::new().loopback(),
    ))
    .await
    .unwrap();
    let _ = reads_and_writes(&laptop, &lost).await;
    peer.shutdown().await;
}

#[derive(Default)]
struct Keeper(Mutex<Vec<u8>>);
impl frasil::KeepKeys for Keeper {
    fn keep<'a>(&'a self, sealed: &'a [u8]) -> frasil::BoxFuture<'a, frasil::Result<()>> {
        Box::pin(async move {
            *self.0.lock().unwrap() = sealed.to_vec();
            Ok(())
        })
    }
}

#[tokio::test]
async fn recovery_retains_keys_in_a_non_directory_keeper() {
    let peer = spawn_loopback().await.unwrap();
    let lost = person(&peer).await;
    let sheet = lost.device.create_recovery_sheet().await.unwrap();
    let passkey = SoftPasskey {
        secret: [5; 32],
        handle: Mutex::new(None),
    };
    lost.device.add_passkey(&passkey).await.unwrap();
    lost.settled(&peer).await;
    for path in 0..4 {
        let keeper = std::sync::Arc::new(Keeper::default());
        let options = Options::new().loopback().keep_keys(keeper.clone());
        let recovered = if path >= 2 {
            let device = Device::open_with(Storage::Memory, &[9; 32], options)
                .await
                .unwrap();
            if path == 2 {
                device
                    .recover_from_sheet(
                        &[9; 32],
                        RecoverySheet::read(&sheet.text()).unwrap(),
                        &peer.origin,
                    )
                    .await
                    .unwrap();
            } else {
                device
                    .recover_from_passkey(&[9; 32], &passkey, &peer.origin)
                    .await
                    .unwrap();
            }
            Ok(device)
        } else if path == 1 {
            within(Device::recover_with_passkey(
                Storage::Memory,
                &[9; 32],
                &passkey,
                &peer.origin,
                options,
            ))
            .await
        } else {
            within(Device::recover(
                Storage::Memory,
                &[9; 32],
                &sheet.text(),
                &peer.origin,
                options,
            ))
            .await
        }
        .unwrap();
        let platform = recovered.engine().platform().clone();
        let id = recovered.id();
        recovered.close().await.unwrap();
        drop(recovered);
        let sealed = keeper.0.lock().unwrap().clone();
        let engine = Engine::open_as(
            platform,
            &sealed,
            &[9; 32],
            Some(lost.person),
            frasil::advanced::AdapterRegistry::with_builtins(),
        )
        .await
        .unwrap();
        let reopened = Device::from_engine(engine, Options::new().loopback()).unwrap();
        assert_eq!(reopened.id(), id);
        assert_eq!(reopened.engine().person().await, Some(lost.person));
        reopened.close().await.unwrap();
    }
    peer.shutdown().await;
}

struct RefusingKeeper;
impl frasil::KeepKeys for RefusingKeeper {
    fn keep<'a>(&'a self, _: &'a [u8]) -> frasil::BoxFuture<'a, frasil::Result<()>> {
        Box::pin(async { Err(frasil::Error::Store("keeper refused".into())) })
    }
}

#[tokio::test]
async fn recovery_reports_a_keeper_failure() {
    let peer = spawn_loopback().await.unwrap();
    let lost = person(&peer).await;
    let sheet = lost.device.create_recovery_sheet().await.unwrap();
    lost.settled(&peer).await;
    let options = Options::new()
        .loopback()
        .keep_keys(std::sync::Arc::new(RefusingKeeper));
    let result = within(Device::recover(
        Storage::Memory,
        &[9; 32],
        &sheet.text(),
        &peer.origin,
        options,
    ))
    .await;
    assert!(matches!(result, Err(frasil::Error::Store(message)) if message == "keeper refused"));
    peer.shutdown().await;
}
