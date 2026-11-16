//! A peer takes a device's keys only by the hash its name commits to
//! (crypto.md, "A device's keys"; peers.md, "What a peer checks before it
//! stores a skeleton event" and "Presenting credentials").
//!
//! A root whose founder keys do not hash to the genesis's `kc`, and an
//! enrolment whose ML-DSA-65 key does not hash to its own `kc`, are refused
//! `not_committed` and not stored. An administrator pseudonym presents its
//! device ID as credential 3, which the peer verifies under the `ed` of the
//! root or enrolment it holds; a present before the enrolment is granted
//! until the connection's first stored event, which must be that
//! enrolment, under whose `ed` the proof then verifies.

mod common;

use common::*;
use frasil_conformance::client::Credential;
use frasil_conformance::history::{History, example, family, hex};
use frasil_keys::derive::upload_key;
use frasil_peers::body::{SlotId, StorageBody};
use frasil_peers::derive::{SlotKeys, enrol_statement};
use frasil_transport::codes::Right;
use frasil_transport::messages::Present;
use frasil_transport::peer::Purpose;

/// The administrator slot `P grants B administer` makes: its slot
/// reference, naming the twin that made it, and keys, from the reference
/// builder's token.
fn slot_of_b(history: &History) -> (SlotId, SlotKeys) {
    let skeleton = family("skeleton");
    let twins = &skeleton["twins"];
    let twin = skeleton["names"]["P grants B administer"]
        .as_str()
        .expect("the twin's name");
    let c: [u8; 32] = hex(&twins["P grants B administer"]["c"])
        .try_into()
        .expect("32 bytes");
    let token = example(&format!(
        "storage/token/{}/0",
        frasil_testkit::hex::encode(c)
    ));
    (
        SlotId::new(c, 0, history.id(twin)),
        SlotKeys::from_token(&token),
    )
}

/// An enrolment of `pseudonym` in `slot`, its authorization genuine, its
/// `mldsa` the pseudonym's own or, with `mldsa`, another key's.
fn enrolment(
    history: &mut History,
    pseudonym: &str,
    name: &str,
    (slot, keys): &(SlotId, SlotKeys),
    mldsa: Option<Vec<u8>>,
    parents: &[&str],
) -> Vec<u8> {
    history.pseudonym(pseudonym);
    let signer = history.signer(pseudonym);
    let statement = enrol_statement(&history.space(), slot.reference, signer.device_id());
    let body = StorageBody::Enrol {
        slot: *slot,
        mldsa: mldsa.unwrap_or_else(|| signer.mldsa_public().to_vec()),
        slot_mldsa: keys.signer.mldsa_public().to_vec(),
        authorization: keys
            .signer
            .sign(frasil_crypto::schemes::Scheme::Hybrid, &statement),
        // The peer cannot open a binding; filler of its length.
        binding: vec![0xbb; 3_445],
    };
    history.storage(pseudonym, name, &body, parents)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_whose_founder_keys_miss_the_genesiss_kc_is_refused_not_committed() {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        let case = &family("twin_checks")["root_founder_keys_not_committed"];
        assert_eq!(case["peer"], "NotCommitted");
        let events: Vec<Vec<u8>> = case["events"]
            .as_array()
            .expect("events")
            .iter()
            .map(|row| hex(&row["signed"]))
            .collect();
        let root = hex(&case["root"]);
        let genesis = frasil_events::decode(&events[0]).unwrap();
        let space = genesis.id();
        let mut device = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
        assert_eq!(
            device.store(space, vec![events[0].clone()], DEADLINE).await,
            vec![space]
        );
        let prefix = case["prefix"].as_str().expect("a prefix");
        let upload = upload_key(&example(&format!("{prefix}/genesis/upload-seed")));
        device
            .present(space, Credential::Upload, &upload.seed)
            .await
            .expect("the genesis's upload key");
        assert_eq!(
            device.store_answer(space, &root, DEADLINE).await,
            Some(Err("not_committed".into()))
        );
        let root_id = frasil_events::decode(&root).unwrap().id();
        assert!(!peer.peer.holds(space.as_bytes(), root_id.as_bytes()));
        device.close().await;
        peer.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_enrolment_whose_key_misses_its_kc_is_refused_and_credential_3_names_the_device_id_before_and_after_it()
 {
    within(async {
        let peer = peer(frasil_conformance::settings()).await;
        let mut history = History::skeleton();
        let space = history.space();
        let mut device = founder(&peer, Binding::WebSocket, &history).await;
        device
            .store(
                space,
                history.through("P grants B administer")[1..].to_vec(),
                DEADLINE,
            )
            .await;
        let granted = history.id("P grants B administer");
        assert!(peer.peer.holds(space.as_bytes(), granted.as_bytes()));
        let slot = slot_of_b(&history);
        let b1_seed = history.seed("B1");
        history.pseudonym("B1");
        let b1 = history.device_id("B1");
        let other = history.signer("another pseudonym");
        let refused = enrolment(
            &mut history,
            "B1",
            "B1: enrols under another key",
            &slot,
            Some(other.mldsa_public().to_vec()),
            &["P grants B administer"],
        );
        history.force_next("B1", 1, None);
        let enrolled = enrolment(
            &mut history,
            "B1",
            "B1: enrols",
            &slot,
            None,
            &["P grants B administer"],
        );

        // A present of B1's device ID with a proof by another seed, before
        // its enrolment: granted after steps 1 to 3, and the enrolment as
        // its first event is NotAuthorized, the proof failing under its
        // `ed` (peers.md, 3.7 Presenting a credential).
        let mut admin = connect(&peer, Binding::WebSocket, Purpose::Administration).await;
        admin
            .present_pseudonym(space, &[0x77; 32], &b1)
            .await
            .expect("granted until its enrolment");
        assert_eq!(
            admin.store_answer(space, &enrolled, DEADLINE).await,
            Some(Err("not_authorized".into()))
        );
        admin.close().await;

        // B1's own present, before its enrolment: granted; its enrolment
        // whose mldsa is another key's is refused with its class, and not
        // stored; then its genuine enrolment, at the same seq, is.
        let mut admin = connect(&peer, Binding::WebSocket, Purpose::Administration).await;
        let granted = admin
            .present_pseudonym(space, &b1_seed, &b1)
            .await
            .expect("granted until its enrolment");
        assert_eq!(granted.rights, vec![Right::Erase]);
        assert_eq!(
            admin.store_answer(space, &refused, DEADLINE).await,
            Some(Err("not_committed".into()))
        );
        let refused_id = frasil_events::decode(&refused).unwrap().id();
        assert!(!peer.peer.holds(space.as_bytes(), refused_id.as_bytes()));
        assert_eq!(
            admin.store_answer(space, &enrolled, DEADLINE).await,
            Some(Ok(()))
        );
        admin.close().await;

        // Once enrolled, credential 3 naming B1's device ID is granted at
        // once, and B1 acknowledges on that connection.
        let mut admin = connect(&peer, Binding::WebSocket, Purpose::Administration).await;
        admin
            .present_pseudonym(space, &b1_seed, &b1)
            .await
            .expect("the enrolled pseudonym's device ID");
        // B1's chain goes on from its stored enrolment, not from the
        // refused one at the same `seq`.
        history.force_next("B1", 2, Some(history.id("B1: enrols")));
        let ack = history.storage("B1", "B1 acknowledges", &StorageBody::Ack, &["B1: enrols"]);
        assert_eq!(
            admin.store_answer(space, &ack, DEADLINE).await,
            Some(Ok(()))
        );
        admin.close().await;

        // Its Ed25519 key in place of its device ID names no pseudonym the
        // peer holds: granted only until an enrolment by a pseudonym of
        // that device ID, which B1's acknowledgement is not.
        let mut admin = connect(&peer, Binding::WebSocket, Purpose::Administration).await;
        let request = admin.request();
        let ed = history.key("B1");
        let presented = frasil_peers::proof::presented(
            &admin.binding,
            space.as_bytes(),
            Credential::Pseudonym.code(),
            &ed,
        );
        let present = Present {
            request,
            space: *space.as_bytes(),
            credential: Credential::Pseudonym.code().into(),
            public: ed.to_vec(),
            proof: frasil_peers::proof::prove(&b1_seed, &presented).to_vec(),
        }
        .encode();
        admin.send_control(&present).await;
        admin
            .answer(request)
            .await
            .expect("granted until its enrolment");
        let again = history.storage(
            "B1",
            "B1 acknowledges again",
            &StorageBody::Ack,
            &["B1 acknowledges"],
        );
        assert_eq!(
            admin.store_answer(space, &again, DEADLINE).await,
            Some(Err("not_authorized".into()))
        );
        admin.close().await;
        device.close().await;
        peer.shutdown().await;
    })
    .await;
}
