//! Signed application requests from a device that joined its person
//! through a peer (ext-app-requests.md, "Signed request headers"): the
//! verifier takes the new device's list delivery and accepts its request
//! under `X-Frasil-Device`, the device's 128-hex-digit `ed || kc`, and
//! names the device by its device ID. A header of 64 hex digits, an
//! Ed25519 key alone, is `Malformed`.
#![cfg(feature = "ext-app-requests")]

use frasil::{
    Device, DeviceId, DeviceLists, Error, NonceStore, Options, PersonId, RequestVerifier, Storage,
};
use frasil_conformance::spawn_loopback;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);
const SUBJECT: &str = "user_1";
const AUDIENCE: &str = "https://api.example.org";
const URL: &str = "https://api.example.org/v1/people";
const DELIVERY_URL: &str = "https://api.example.org/frasil/p1/device-list";

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

#[derive(Default)]
struct Lists {
    persons: BTreeMap<String, PersonId>,
    lists: BTreeMap<PersonId, Vec<(Vec<u8>, u64)>>,
}

impl DeviceLists for Lists {
    fn recorded_person(&self, subject: &str) -> Option<PersonId> {
        self.persons.get(subject).copied()
    }

    fn record_person(&mut self, subject: &str, person: PersonId) {
        self.persons.insert(subject.to_owned(), person);
    }

    fn list(&self, person: &PersonId) -> Vec<(Vec<u8>, u64)> {
        self.lists.get(person).cloned().unwrap_or_default()
    }

    fn keep_list(&mut self, person: &PersonId, events: Vec<(Vec<u8>, u64)>) {
        self.lists.insert(*person, events);
    }
}

#[derive(Default)]
struct Nonces(BTreeSet<(DeviceId, Vec<u8>)>);

impl NonceStore for Nonces {
    fn check_and_record(&mut self, device: &DeviceId, nonce: &[u8; 16], _: u64, _: u64) -> bool {
        self.0.insert((*device, nonce.to_vec()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_admitted_through_a_peer_signs_requests_under_its_ed_and_kc() {
    let peer = spawn_loopback().await.unwrap();
    let laptop = device(1).await;
    let person = laptop.make_person(&[1; 32]).await.unwrap();
    laptop.connect(&peer.origin).await.unwrap();

    // The browser joins the person through an exchange mailbox at the peer.
    let browser = device(2).await;
    let joining = within(browser.join_person_via_peer(
        &peer.origin,
        person,
        "Browser",
        &[2; 32],
        |_, other| async move { other == "Laptop" },
    ))
    .await
    .unwrap();
    within(
        laptop.admit_device(joining.text(), "Laptop", |_, newcomer| async move {
            newcomer == "Browser"
        }),
    )
    .await
    .unwrap();
    within(joining.joined()).await.unwrap();
    assert_eq!(browser.person().await, Some(person));

    let mut verifier = RequestVerifier::new(AUDIENCE, Lists::default(), Nonces::default()).unwrap();
    let delivery = browser.list_delivery().await.unwrap();
    let delivered = browser
        .sign_request(SUBJECT, "PUT", DELIVERY_URL, &delivery)
        .await
        .unwrap();
    verifier
        .verify(SUBJECT, "PUT", DELIVERY_URL, &delivered, &delivery)
        .unwrap();

    let body = br#"{"name":"Ada"}"#;
    let headers = browser
        .sign_request(SUBJECT, "PUT", URL, body)
        .await
        .unwrap();
    let device_header = |headers: &[(String, String)]| {
        headers
            .iter()
            .find(|(name, _)| name == "X-Frasil-Device")
            .map(|(_, value)| value.clone())
            .expect("an X-Frasil-Device header")
    };
    assert_eq!(device_header(&headers).len(), 128);
    let accepted = verifier
        .verify(SUBJECT, "PUT", URL, &headers, body)
        .unwrap();
    assert_eq!(accepted.person, person);
    assert_eq!(accepted.device, browser.id());

    // The same request with the header cut to the Ed25519 key's 64 hex
    // digits.
    let again = browser
        .sign_request(SUBJECT, "PUT", URL, body)
        .await
        .unwrap();
    let short: Vec<(String, String)> = again
        .into_iter()
        .map(|(name, value)| {
            if name == "X-Frasil-Device" {
                (name, value[..64].to_owned())
            } else {
                (name, value)
            }
        })
        .collect();
    assert_eq!(device_header(&short).len(), 64);
    assert_eq!(
        verifier.verify(SUBJECT, "PUT", URL, &short, body),
        Err(Error::Class("Malformed"))
    );
    browser.close().await.unwrap();
    laptop.close().await.unwrap();
    peer.shutdown().await;
}
