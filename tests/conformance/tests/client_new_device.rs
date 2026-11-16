//! A person's new device, admitted by code through an exchange mailbox at a
//! peer, on loopback (admission.md, "A person's new device"): the new
//! device shows a QR code naming the peer, a device of the person enters
//! it, both compare one code, and the new device becomes the person's and
//! reaches the person's spaces from the peer. A Cancel reaches the other
//! side.

use frasil::{Device, Error, Options, Storage};
use frasil_conformance::spawn_loopback;
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
async fn a_new_device_joins_its_person_through_an_exchange_mailbox() {
    let peer = spawn_loopback().await.unwrap();
    let laptop = device(1).await;
    let person = laptop.make_person(&[1; 32]).await.unwrap();
    let space = laptop.create_space().await.unwrap();
    laptop.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();
    within(async {
        while !space.is_durable().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    let browser = device(2).await;
    let shown = Arc::new(Mutex::new(String::new()));
    let browsers_code = shown.clone();
    let joining = within(browser.join_person_via_peer(
        &peer.origin,
        person,
        "Browser",
        &[2; 32],
        move |code, other| {
            *browsers_code.lock().unwrap() = code;
            async move { other == "Laptop" }
        },
    ))
    .await
    .unwrap();
    assert!(joining.text().starts_with("FRASIL-ADMIT:"));

    let seen = Arc::new(Mutex::new(String::new()));
    let laptops_code = seen.clone();
    within(
        laptop.admit_device(joining.text(), "Laptop", move |code, newcomer| {
            *laptops_code.lock().unwrap() = code;
            async move { newcomer == "Browser" }
        }),
    )
    .await
    .unwrap();
    let spaces = within(joining.joined()).await.unwrap();
    assert_eq!(*shown.lock().unwrap(), *seen.lock().unwrap());
    assert_eq!(browser.person().await, Some(person));
    // Every space of the laptop grants the person: its personal space,
    // and the space it made.
    let mut reached: Vec<String> = spaces.iter().map(|s| s.id().to_string()).collect();
    reached.sort_unstable();
    let mut expected: Vec<String> = laptop
        .spaces()
        .await
        .iter()
        .map(|s| s.id().to_string())
        .collect();
    expected.sort_unstable();
    assert_eq!(expected.len(), 2);
    assert_eq!(reached, expected);

    // The new device reads what the person's other device wrote, and
    // writes back.
    let browsers_space = browser.space(space.id()).await.unwrap();
    let browsers_note = within(async {
        loop {
            if let Ok(note) = browsers_space.document(note.id()).await
                && note.text("body").await.unwrap() == "Hello"
            {
                break note;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    browsers_note
        .edit(|doc| doc.get_text("body").insert(5, ", laptop"))
        .await
        .unwrap();
    within(async {
        while note.text("body").await.unwrap() != "Hello, laptop" {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    // A code the person declines adds no one, and the new device stops.
    let tablet = device(3).await;
    let joining = within(tablet.join_person_via_peer(
        &peer.origin,
        person,
        "Tablet",
        &[3; 32],
        |_, _| async { true },
    ))
    .await
    .unwrap();
    let declined =
        within(laptop.admit_device(joining.text(), "Laptop", |_, _| async { false })).await;
    assert_eq!(declined, Err(Error::Class("Mismatch")));
    let stopped = tokio::time::timeout(Duration::from_secs(15), joining.joined())
        .await
        .expect("the joiner stops at the Cancel");
    assert_eq!(stopped.unwrap_err(), Error::Class("Cancelled"));
    assert_eq!(tablet.person().await, None);

    laptop.close().await.unwrap();
    browser.close().await.unwrap();
    tablet.close().await.unwrap();
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_device_stops_reaching_the_persons_spaces() {
    let peer = spawn_loopback().await.unwrap();
    let laptop = device(1).await;
    let person = laptop.make_person(&[1; 32]).await.unwrap();
    let space = laptop.create_space().await.unwrap();
    laptop.connect(&peer.origin).await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await
        .unwrap();
    within(async {
        while !space.is_durable().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    let phone = device(2).await;
    let joining =
        within(
            phone.join_person_via_peer(&peer.origin, person, "Phone", &[2; 32], |_, _| async {
                true
            }),
        )
        .await
        .unwrap();
    within(laptop.admit_device(joining.text(), "Laptop", |_, _| async { true }))
        .await
        .unwrap();
    within(joining.joined()).await.unwrap();
    let event = frasil_events::EventId(*space.id().as_bytes());
    let phone_id = phone.engine().device_id();
    let reaches = |device: &Device| {
        let device = device.clone();
        async move {
            device
                .engine()
                .read(&event, |replica| replica.level_of(&phone_id))
                .await
                .ok()
                .flatten()
                .is_some()
        }
    };
    within(async {
        while !reaches(&laptop).await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    // The laptop takes the phone off the person's list: it reaches none
    // of the person's spaces, in the laptop's view and in its own.
    let phones_space = phone.space(space.id()).await.unwrap();
    let phones_note = within(async {
        loop {
            if let Ok(found) = phones_space.document(note.id()).await
                && found.text("body").await.unwrap() == "Hello"
            {
                break found;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    within(laptop.remove_device(phone.id())).await.unwrap();
    assert!(!reaches(&laptop).await);
    for held in laptop.spaces().await {
        let id = frasil_events::EventId(*held.id().as_bytes());
        let level = laptop
            .engine()
            .read(&id, |replica| replica.level_of(&phone_id))
            .await
            .unwrap();
        assert_eq!(level, None);
    }
    // What the laptop writes from now on, the phone reads nothing of.
    note.edit(|doc| doc.get_text("body").insert(5, ", after"))
        .await
        .unwrap();
    within(async {
        while !space.is_durable().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(phones_note.text("body").await.unwrap(), "Hello");
    // A device removes another device, never itself.
    assert!(matches!(
        laptop.remove_device(laptop.id()).await,
        Err(Error::Invalid(_))
    ));

    laptop.close().await.unwrap();
    phone.close().await.unwrap();
    peer.shutdown().await;
}

/// A new device that expects Alice, whose request Bob's device approves by
/// mistake, is added to no list: it refuses Bob's answer before it reveals
/// anything (admission.md, 3.1 The joiner, step 5). Alice's device then
/// admits it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_device_joins_only_the_person_it_expects() {
    let peer = spawn_loopback().await.unwrap();
    let alices = device(1).await;
    let alice = alices.make_person(&[1; 32]).await.unwrap();
    alices.connect(&peer.origin).await.unwrap();
    let bobs = device(4).await;
    let bob = bobs.make_person(&[4; 32]).await.unwrap();
    bobs.connect(&peer.origin).await.unwrap();
    let lists = |device: &Device, person: frasil::PersonId| {
        let device = device.clone();
        async move { device.engine().list_events(person.as_bytes()).await }
    };
    let bobs_list = lists(&bobs, bob).await;
    let alices_list = lists(&alices, alice).await;

    let phone = device(2).await;
    let joining =
        within(
            phone.join_person_via_peer(&peer.origin, alice, "Phone", &[2; 32], |_, _| async {
                true
            }),
        )
        .await
        .unwrap();
    let approved =
        within(bobs.admit_device(joining.text(), "Bob's laptop", |_, _| async { true })).await;
    assert_eq!(approved, Err(Error::Class("Cancelled")));
    assert_eq!(
        within(joining.joined()).await.unwrap_err(),
        Error::Class("WrongPerson")
    );
    assert_eq!(phone.person().await, None);
    assert_eq!(
        lists(&bobs, bob).await,
        bobs_list,
        "Bob's list is unchanged"
    );
    assert_eq!(lists(&alices, alice).await, alices_list);

    let joining =
        within(
            phone.join_person_via_peer(&peer.origin, alice, "Phone", &[2; 32], |_, _| async {
                true
            }),
        )
        .await
        .unwrap();
    within(alices.admit_device(joining.text(), "Alice's laptop", |_, _| async { true }))
        .await
        .unwrap();
    within(joining.joined()).await.unwrap();
    assert_eq!(phone.person().await, Some(alice));
    assert_eq!(lists(&bobs, bob).await, bobs_list);

    alices.close().await.unwrap();
    bobs.close().await.unwrap();
    phone.close().await.unwrap();
    peer.shutdown().await;
}
