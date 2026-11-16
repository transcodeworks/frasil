//! Signed application requests through the root API (ext-app-requests.md):
//! a verifier that holds no list of the person refuses `ListNeeded`, takes
//! the device's list delivery on its route, and accepts the request signed
//! again.
#![cfg(feature = "ext-app-requests")]

use frasil::{
    Device, DeviceId, DeviceLists, Error, NonceStore, Options, PersonId, RequestVerifier, Storage,
};
use std::collections::{BTreeMap, BTreeSet};

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

const SUBJECT: &str = "user_1";
const AUDIENCE: &str = "https://api.example.org";
const URL: &str = "https://api.example.org/v1/people";
const DELIVERY_URL: &str = "https://api.example.org/frasil/p1/device-list";

#[tokio::test]
async fn a_verifier_takes_the_list_delivery_and_accepts_the_retry() {
    let device = Device::open_with(Storage::Memory, &[1; 32], Options::new())
        .await
        .unwrap();
    // A device of no person has no list to deliver.
    assert!(matches!(
        device.list_delivery().await,
        Err(Error::NotAllowed(_))
    ));
    let person = device.make_person(&[1; 32]).await.unwrap();
    let mut verifier = RequestVerifier::new(AUDIENCE, Lists::default(), Nonces::default()).unwrap();

    let body = br#"{"name":"Ada"}"#;
    let headers = device
        .sign_request(SUBJECT, "PUT", URL, body)
        .await
        .unwrap();
    assert_eq!(
        verifier.verify(SUBJECT, "PUT", URL, &headers, body),
        Err(Error::Class("ListNeeded"))
    );

    let delivery = device.list_delivery().await.unwrap();
    let delivered = device
        .sign_request(SUBJECT, "PUT", DELIVERY_URL, &delivery)
        .await
        .unwrap();
    let placed = verifier
        .verify(SUBJECT, "PUT", DELIVERY_URL, &delivered, &delivery)
        .unwrap();
    assert_eq!(placed.person, person);

    let again = device
        .sign_request(SUBJECT, "PUT", URL, body)
        .await
        .unwrap();
    let accepted = verifier.verify(SUBJECT, "PUT", URL, &again, body).unwrap();
    assert_eq!(accepted.person, person);
    assert_eq!(accepted.device, device.id());
    assert!(!accepted.list_needed);

    // The audience is the verifier's own: a request signed for another
    // origin is refused, even sent with a URL that names that origin, and
    // the path alone serves as the target.
    let elsewhere = device
        .sign_request(SUBJECT, "PUT", "https://other.example.org/v1/people", body)
        .await
        .unwrap();
    assert_eq!(
        verifier.verify(
            SUBJECT,
            "PUT",
            "https://other.example.org/v1/people",
            &elsewhere,
            body
        ),
        Err(Error::Class("BadSignature"))
    );
    let here = device
        .sign_request(SUBJECT, "PUT", URL, body)
        .await
        .unwrap();
    assert!(
        verifier
            .verify(SUBJECT, "PUT", "/v1/people", &here, body)
            .is_ok()
    );
    assert!(matches!(
        RequestVerifier::new(
            "https://api.example.org/v1",
            Lists::default(),
            Nonces::default()
        ),
        Err(Error::Invalid(_))
    ));
    device.close().await.unwrap();
}
