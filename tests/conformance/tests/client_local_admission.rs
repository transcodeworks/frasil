//! A person's new device, admitted by code over a direct connection on
//! loopback with no peer at all (admission.md, "A person's new device",
//! "Over a direct connection"): a device of the person shows an
//! invitation, the new device enters it, both compare one code, and the new
//! device becomes the person's and reaches the person's spaces over that
//! connection, then keeps a member connection with the other device. A
//! declined code, on either side, stops both.

use frasil::{Device, Error, Options, Storage};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn device(key: u8) -> Device {
    Device::open_with(Storage::Memory, &[key; 32], Options::new().loopback())
        .await
        .expect("a device")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_device_joins_its_person_with_no_peer() {
    let desktop = device(1).await;
    let person = desktop.make_person(&[1; 32]).await.unwrap();
    let space = desktop.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();

    let seen = Arc::new(Mutex::new(String::new()));
    let loges_code = seen.clone();
    let invitation = within(desktop.invite_device("Desktop", move |code, newcomer| {
        *loges_code.lock().unwrap() = code;
        async move { newcomer == "Carol" }
    }))
    .await
    .unwrap();

    let carol = device(2).await;
    let shown = Arc::new(Mutex::new(String::new()));
    let regis_code = shown.clone();
    let spaces = within(carol.join_person(
        invitation.text(),
        person,
        "Carol",
        &[2; 32],
        move |code, other| {
            *regis_code.lock().unwrap() = code;
            async move { other == "Desktop" }
        },
    ))
    .await
    .unwrap();
    within(invitation.admitted()).await.unwrap();
    assert_eq!(*shown.lock().unwrap(), *seen.lock().unwrap());
    assert_eq!(shown.lock().unwrap().len(), 6);
    assert_eq!(carol.person().await, Some(person));

    // Every space of the person's other device: its personal space, and
    // the space it made.
    let mut reached: Vec<String> = spaces.iter().map(|s| s.id().to_string()).collect();
    reached.sort_unstable();
    let mut expected: Vec<String> = desktop
        .spaces()
        .await
        .iter()
        .map(|s| s.id().to_string())
        .collect();
    expected.sort_unstable();
    assert_eq!(expected.len(), 2);
    assert_eq!(reached, expected);

    // The new device reads what the other wrote, and writes back over the
    // member connection.
    let carol_space = carol.space(space.id()).await.unwrap();
    let regis_note = within(async {
        loop {
            if let Ok(found) = carol_space.document(note.id()).await
                && found.text("body").await.unwrap() == "Hello"
            {
                break found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    regis_note
        .edit(|doc| doc.get_text("body").insert(5, ", Carol"))
        .await
        .unwrap();
    within(async {
        while note.text("body").await.unwrap() != "Hello, Carol" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    desktop.close().await.unwrap();
    carol.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declined_code_stops_the_new_device() {
    let desktop = device(1).await;
    let person = desktop.make_person(&[1; 32]).await.unwrap();
    desktop.create_space().await.unwrap();

    // The person's device declines: it adds no one, and the new device
    // stops at its Cancel.
    let invitation = within(desktop.invite_device("Desktop", |_, _| async { false }))
        .await
        .unwrap();
    let tablet = device(3).await;
    let joined = within(tablet.join_person(
        invitation.text(),
        person,
        "Tablet",
        &[3; 32],
        |_, _| async { true },
    ))
    .await;
    assert_eq!(joined.unwrap_err(), Error::Class("Cancelled"));
    assert_eq!(
        within(invitation.admitted()).await,
        Err(Error::Class("Mismatch"))
    );
    assert_eq!(tablet.person().await, None);

    // The new device declines while the other still waits for its person:
    // the other stops at the new device's Cancel, and adds no one.
    let (declined, waited) = tokio::sync::oneshot::channel::<()>();
    let invitation = within(desktop.invite_device("Desktop", move |_, _| async move {
        let _ = waited.await;
        true
    }))
    .await
    .unwrap();
    let phone = device(4).await;
    let joined =
        within(
            phone.join_person(invitation.text(), person, "Phone", &[4; 32], |_, _| async {
                false
            }),
        )
        .await;
    assert_eq!(joined.unwrap_err(), Error::Class("Mismatch"));
    let _ = declined.send(());
    assert_eq!(
        within(invitation.admitted()).await,
        Err(Error::Class("Cancelled"))
    );
    assert_eq!(phone.person().await, None);
    let phone_id = phone.engine().device_id();
    assert!(
        !desktop
            .engine()
            .person_devices(person.as_bytes())
            .await
            .contains(&phone_id)
    );

    // Text that is no device invitation.
    assert!(matches!(
        phone
            .join_person(
                "not an invitation",
                person,
                "Phone",
                &[4; 32],
                |_, _| async { true }
            )
            .await,
        Err(Error::Invalid(_))
    ));

    desktop.close().await.unwrap();
    tablet.close().await.unwrap();
    phone.close().await.unwrap();
}
