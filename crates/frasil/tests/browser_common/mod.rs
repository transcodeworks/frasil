//! What a browser device does, in a page and in a worker alike: it opens
//! over IndexedDB, keeps its spaces and keys across a reopening, and opens
//! in memory too.

use frasil::{Device, Storage, Value};

/// A database name of the run's own, so runs never share a database.
fn database() -> String {
    format!("frasil-browser-test-{}", js_sys::Math::random().to_bits())
}

pub async fn a_device_keeps_its_spaces_in_indexed_db() {
    let name = database();
    let unlock = [5; 32];
    let device = Device::open(Storage::indexed_db(&name), &unlock)
        .await
        .unwrap();
    let id = device.id();
    let space = device.create_space_of_kind("notes").await.unwrap();
    let notes = space.create_records().unwrap();
    notes
        .write(|tx| {
            tx.insert("notes", b"n1")
                .set("notes", b"n1", "text", "kept")
                .set("notes", b"n1", "pinned", true);
        })
        .await
        .unwrap();
    let key = device.derive_key("com.example.cache").await.unwrap();
    let last = notes.last_change("notes", b"n1").await.unwrap().unwrap();
    assert_eq!(last.author, id);
    assert!(last.time.is_some(), "the browser's wall clock is known");
    device.close().await.unwrap();
    drop((space, notes, device));

    // The same database and unlock key open the same device.
    let device = Device::open(Storage::indexed_db(&name), &unlock)
        .await
        .unwrap();
    assert_eq!(device.id(), id);
    assert_eq!(*device.derive_key("com.example.cache").await.unwrap(), *key);
    let spaces = device.spaces().await;
    assert_eq!(spaces.len(), 1);
    assert_eq!(spaces[0].kind().await.unwrap().as_deref(), Some("notes"));
    let notes = spaces[0].records(notes_id(&spaces[0]).await).await.unwrap();
    let row = notes.row("notes", b"n1").await.unwrap().unwrap();
    assert_eq!(row["text"], Value::from("kept"));
    assert_eq!(row["pinned"], Value::Bool(true));
    device.close().await.unwrap();
    drop((spaces, notes, device));

    // Another unlock key does not open it.
    assert!(
        Device::open(Storage::indexed_db(&name), &[6; 32])
            .await
            .is_err()
    );
    frasil::browser::IndexedDbStore::delete_database(&name)
        .await
        .unwrap();
}

async fn notes_id(space: &frasil::Space) -> frasil::StreamId {
    space.streams().await.unwrap()[0].id
}

pub async fn a_device_opens_in_memory() {
    let device = Device::open(Storage::Memory, &[7; 32]).await.unwrap();
    let space = device.create_space().await.unwrap();
    assert_eq!(space.level().await, Some(frasil::Level::Administer));
    let before = space.pending_authored_changes().await;
    let records = space.create_records().unwrap();
    for row in [b"one", b"two"] {
        records
            .write(|tx| {
                tx.insert("rows", row);
            })
            .await
            .unwrap();
    }
    assert_eq!(space.pending_authored_changes().await, before + 2);
    assert!(!space.is_durable().await);
    // Connecting by URL goes through the browser's WebSocket: a URL that
    // is not HTTPS is refused before any socket opens.
    assert!(device.connect("http://example.org").await.is_err());
    device.close().await.unwrap();
}

// A deterministic test passkey; no platform ceremony is needed to test persistence.
#[derive(Default)]
struct Passkey(std::sync::Mutex<Vec<u8>>);
impl frasil::Passkey for Passkey {
    fn register<'a>(
        &'a self,
        handle: &'a [u8; 64],
        _: &'a [u8; 32],
    ) -> frasil::PasskeyFuture<'a, Option<frasil::PrfOutput>> {
        *self.0.lock().unwrap() = handle.to_vec();
        Box::pin(async { Ok(Some(vec![42; 32].into())) })
    }
    fn assert<'a>(
        &'a self,
        _: &'a [u8; 32],
    ) -> frasil::PasskeyFuture<'a, frasil::PasskeyAssertion> {
        let user_handle = self.0.lock().unwrap().clone();
        Box::pin(async {
            Ok(frasil::PasskeyAssertion {
                user_handle,
                prf_output: Some(vec![42; 32].into()),
            })
        })
    }
}

pub async fn recovery_keeps_the_person(passkey_recovery: bool) {
    let peer = "http://127.0.0.1:18787";
    let lost = Device::open(Storage::Memory, &[1; 32]).await.unwrap();
    let person = lost.make_person(&[1; 32]).await.unwrap();
    let sheet = lost.create_recovery_sheet().await.unwrap();
    let passkey = Passkey::default();
    lost.add_passkey(&passkey).await.unwrap();
    let connection = lost.connect(peer).await.unwrap();
    let personal = lost.engine().personal_space().await.unwrap();
    for attempt in 0..600 {
        if connection.status().recovery_entries >= 2
            && lost.engine().outbox(&personal).await.is_empty()
        {
            break;
        }
        assert!(attempt < 599, "recovery entries registered");
        frasil::browser::sleep(std::time::Duration::from_millis(100)).await;
    }
    let name = database();
    let recovered = if passkey_recovery {
        Device::recover_with_passkey(
            Storage::indexed_db(&name),
            &[9; 32],
            &passkey,
            peer,
            frasil::Options::new(),
        )
        .await
    } else {
        Device::recover(
            Storage::indexed_db(&name),
            &[9; 32],
            &sheet.text(),
            peer,
            frasil::Options::new(),
        )
        .await
    }
    .unwrap();
    assert_eq!(recovered.person().await, Some(person));
    let id = recovered.id();
    recovered.close().await.unwrap();
    drop(recovered);
    let reopened = Device::open(Storage::indexed_db(&name), &[9; 32])
        .await
        .unwrap();
    assert_eq!(reopened.id(), id);
    assert_eq!(reopened.person().await, Some(person));
    reopened.close().await.unwrap();
    lost.close().await.unwrap();
    drop(reopened);
    frasil::browser::IndexedDbStore::delete_database(&name)
        .await
        .unwrap();
}
