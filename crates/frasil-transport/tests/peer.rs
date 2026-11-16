//! transport.md, sections 3.10 to 3.12 and 3.15's values: the
//! `device_to_peer` family.

mod common;

use common::*;
use frasil_base::cbor::{Map, Value};
use frasil_crypto::device::DeviceId;
use frasil_identity::recovery::{RecoveryKey, RecoverySecret};
use frasil_keys::derive::{read_credential, upload_key};
use frasil_peers::entries::Rights;
use frasil_transport::codes::{Right, Service};
use frasil_transport::frame::{MessageType, frame};
use frasil_transport::messages::{Awaiting, Granted, Present, RegisterRecoveryEntry};
use frasil_transport::peer::{
    Checked, DeviceSide, Hello, Limits, PeerHello, PeerSide, Purpose, Request, check_connection,
    chunk_path, object_locator, peer_binding, presented, purpose_of, read_transfer_authorization,
    server_channel, transfer_authorization,
};

fn purpose(code: u64) -> Purpose {
    purpose_of(code).unwrap()
}

#[test]
fn bindings_and_hellos() {
    let family = family("device_to_peer");
    let nonce_p = array::<32>(&family["nonce_peer"]);
    let nonce_c = array::<32>(&family["nonce_client"]);
    let handshake = Handshake::load();
    let iroh = &family["bindings"]["iroh"];
    assert_eq!(array::<32>(&iroh["channel"]), handshake.channel());
    let server = &family["bindings"]["server"];
    assert_eq!(
        server_channel(text(&server["origin"])),
        array::<32>(&server["channel"])
    );
    for binding in [iroh, server] {
        let channel = array::<32>(&binding["channel"]);
        for code in [1, 2] {
            assert_eq!(
                peer_binding(&channel, &nonce_p, &nonce_c, purpose(code)),
                array::<32>(&binding[format!("purpose_{code}")])
            );
        }
    }

    // Both ends of the handshake, on the iroh binding.
    let channel = handshake.channel();
    let services = [Service::Relay, Service::Store, Service::Mailbox];
    let (mut peer, peer_hello) =
        PeerSide::start_with(channel, nonce_p, &services, &Limits::PROTOCOL);
    assert_eq!(peer_hello, bytes(&family["peer_hello"]));
    let device = DeviceSide::answer_with(
        &channel,
        &peer_control(&peer_hello).unwrap(),
        nonce_c,
        Purpose::SpaceTraffic,
    )
    .unwrap();
    assert_eq!(device.hello, bytes(&family["hello"]));
    assert_eq!(device.peer_hello.services(), services);
    assert_eq!(
        device.peer_hello.limit(1),
        Some(Limits::PROTOCOL.max_frame_bytes)
    );
    assert_eq!(device.binding, array::<32>(&iroh["purpose_1"]));
    let binding = peer
        .on_hello(&peer_control(&device.hello).unwrap())
        .unwrap();
    assert_eq!(binding, device.binding);
    assert_eq!(peer.purpose(), Some(Purpose::SpaceTraffic));
    // A second Hello closes the connection.
    assert!(
        peer.on_hello(&peer_control(&device.hello).unwrap())
            .is_err()
    );

    for case in family["hellos"].as_array().unwrap() {
        let description = text(&case["description"]);
        let message = peer_control(&bytes(&case["message"])).unwrap();
        let result = match message.kind {
            MessageType::Hello => class(Hello::read(&message)),
            MessageType::PeerHello => class(PeerHello::read(&message)),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            result.unwrap_or("accepted"),
            text(&case["result"]),
            "{description}"
        );
    }
}

#[test]
fn presentations() {
    let family = family("device_to_peer");
    let handshake = Handshake::load();
    let space = array::<32>(&family["space"]);
    let binding = array::<32>(&family["bindings"]["iroh"]["purpose_1"]);
    // The credentials, from the seeds the vectors give.
    let inputs = &family["credential_seeds"];
    let read = read_credential(&handshake.secret(text(&inputs["read_credential_state"])));
    let upload = upload_key(&array(&inputs["upload_seed"]));
    let recovery = RecoveryKey::derive(&RecoverySecret::from_bytes(&array(
        &inputs["recovery_secret"],
    )));
    let seeds = [*read.seed, *upload.seed, *recovery.fetch().seed()];
    let rows = family["presentations"].as_array().unwrap();
    assert_eq!(rows.len(), 3);

    let nonce_p = array::<32>(&family["nonce_peer"]);
    let nonce_c = array::<32>(&family["nonce_client"]);
    let (mut peer, peer_hello) = PeerSide::start_with(
        handshake.channel(),
        nonce_p,
        &[Service::Store],
        &Limits::PROTOCOL,
    );
    let device = DeviceSide::answer_with(
        &handshake.channel(),
        &peer_control(&peer_hello).unwrap(),
        nonce_c,
        Purpose::SpaceTraffic,
    )
    .unwrap();
    peer.on_hello(&peer_control(&device.hello).unwrap())
        .unwrap();
    assert_eq!(device.binding, binding);

    for (row, seed) in rows.iter().zip(seeds) {
        let description = text(&row["description"]);
        let credential = number(&row["credential"]);
        let public = bytes(&row["public"]);
        assert_eq!(
            frasil_crypto::primitives::ed25519_public(&seed).to_vec(),
            public,
            "{description}"
        );
        let presented_bytes =
            presented(&binding, &space, u8::try_from(credential).unwrap(), &public);
        assert_eq!(presented_bytes, bytes(&row["presented"]), "{description}");
        let mut map = Map::new();
        map.insert(0, Value::Unsigned(18));
        map.insert(1, Value::Unsigned(number(&row["request"])));
        map.insert(2, Value::from(space));
        map.insert(3, Value::Unsigned(credential));
        map.insert(4, Value::from(public.as_slice()));
        assert_eq!(
            Value::Map(map).encode(),
            bytes(&row["present_without_proof"]),
            "{description}"
        );

        // The device presents it; the peer reads it and checks its proof
        // over the connection's presented.
        let credential = frasil_peers::proof::Credential::from_code(credential).unwrap();
        let message = device.present(number(&row["request"]), &space, credential, &seed);
        let Checked::Present(present) = peer.on_message(&peer_control(&message).unwrap()).unwrap()
        else {
            panic!("{description}: not a present");
        };
        assert_eq!(present.public, public);
        assert_eq!(peer.presented(&present), presented_bytes);
        assert!(frasil_peers::proof::verify(
            &public.clone().try_into().unwrap(),
            &presented_bytes,
            &present.proof
        ));
        // Through binding, the proof is worthless on another connection.
        let other = peer_binding(&channel_2(), &nonce_p, &nonce_c, Purpose::SpaceTraffic);
        assert!(!frasil_peers::proof::verify(
            &public.clone().try_into().unwrap(),
            &presented(&other, &space, credential.code(), &public),
            &present.proof
        ));
    }

    // A present that is not exactly keys 0 to 5 is refused, not closed.
    let mut map = Map::new();
    map.insert(0, Value::Unsigned(18));
    map.insert(1, Value::Unsigned(9));
    map.insert(3, Value::Unsigned(1));
    let refused = peer
        .on_message(&peer_control(&Value::Map(map).encode()).unwrap())
        .unwrap();
    let Checked::Refuse(refused) = refused else {
        panic!("not refused");
    };
    let refused =
        frasil_transport::messages::Refused::read(&peer_control(&refused).unwrap()).unwrap();
    assert_eq!(
        (refused.request, refused.code.as_str()),
        (9, "credential_refused")
    );
    // A Present must also read back.
    let present = Present {
        request: 1,
        space,
        credential: 1,
        public: vec![1; 32],
        proof: vec![2; 64],
    };
    assert_eq!(
        Present::read(&peer_control(&present.encode()).unwrap()).unwrap(),
        present
    );
}

#[test]
fn grants_rights_and_requests() {
    let family = family("device_to_peer");
    let rights = family["rights"].as_object().unwrap();
    assert_eq!(rights.len(), Right::ALL.len());
    for right in Right::ALL {
        assert_eq!(text(&rights[&right.code().to_string()]), right.name());
    }
    // peers.md's grants, as Granted lists them.
    for row in family["grants"].as_array().unwrap() {
        let granted = match (number(&row["credential"]), text(&row["entry"])) {
            (1, "live") => Rights::FETCH_AND_LIVE,
            (1, "retired") | (4, "live") => Rights::CATCH_UP,
            (2, "live") => Rights::STORE_AND_RELEASE,
            (3, "") => Rights::ERASE,
            other => panic!("{other:?}"),
        };
        let codes: Vec<u64> = Right::of(granted).iter().map(|r| r.code()).collect();
        let expected: Vec<u64> = row["rights"]
            .as_array()
            .unwrap()
            .iter()
            .map(number)
            .collect();
        assert_eq!(codes, expected);
        let message = Granted {
            request: 1,
            rights: Right::of(granted),
            transfer_token: Some([5; 32]),
        };
        assert_eq!(
            Granted::read(&peer_control(&message.encode()).unwrap()).unwrap(),
            message
        );
    }

    let space = array::<32>(&family["space"]);
    let register = &family["register_recovery_entry"];
    let message = RegisterRecoveryEntry {
        request: number(&register["request"]),
        space: array(&register["space"]),
        fetch_key: array(&register["fetch_key"]),
    };
    assert_eq!(message.encode(), bytes(&register["message"]));
    assert_eq!(frame(&message.encode()), bytes(&register["frame"]));
    assert_eq!(
        RegisterRecoveryEntry::read(&peer_control(&message.encode()).unwrap()).unwrap(),
        message
    );

    let awaiting = Awaiting {
        space,
        ids: family["awaiting_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(array)
            .collect(),
    };
    assert_eq!(awaiting.encode(), bytes(&family["awaiting"]));
    let read = Awaiting::read(&peer_control(&awaiting.encode()).unwrap()).unwrap();
    assert!(read.ids.is_sorted());
    assert_eq!(read.ids.len(), 2);

    let route = &family["object_route"];
    let locator = object_locator(&array(&route["object_id"]), &bytes(&route["stored_object"]));
    assert_eq!(locator[32..], array::<32>(&route["digest"]));
    assert_eq!(locator, array::<64>(&route["locator"]));
    assert_eq!(chunk_path(&space, &locator, 3), text(&route["chunk_path"]));

    let header = transfer_authorization(&[0xab; 32]);
    assert_eq!(header, format!("Frasil-Transfer {}", "ab".repeat(32)));
    assert_eq!(read_transfer_authorization(&header), Ok([0xab; 32]));
    assert!(read_transfer_authorization(&header.to_uppercase()).is_err());
}

#[test]
fn purpose_rules() {
    let family = family("device_to_peer");
    for row in family["sessions"].as_array().unwrap() {
        let description = text(&row["description"]);
        let credentials: Vec<u64> = row["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .map(number)
            .collect();
        let requests: Vec<Request> = row["sends"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| match text(s) {
                "library_attach" => Request::LibraryAttach,
                "merge" => Request::Merge,
                "register_recovery_entry" => Request::RegisterRecoveryEntry,
                "mailbox" => Request::Mailbox,
                other => panic!("{other}"),
            })
            .collect();
        let outcome = check_connection(
            purpose(number(&row["purpose"])),
            &credentials,
            row["bearer"].as_bool().unwrap(),
            &requests,
        );
        let outcome = match outcome {
            Ok(()) => "ok",
            Err(class) => frasil_transport::Code::from_name(&class.to_string())
                .map(|c| c.name())
                .unwrap(),
        };
        assert_eq!(outcome, text(&row["outcome"]), "{description}");
    }
}

#[test]
fn an_administration_connection_closes_on_a_second_present() {
    let handshake = Handshake::load();
    let (mut peer, peer_hello) = PeerSide::start_with(
        handshake.channel(),
        [1; 32],
        &[Service::Store],
        &Limits::PROTOCOL,
    );
    let device = DeviceSide::answer_with(
        &handshake.channel(),
        &peer_control(&peer_hello).unwrap(),
        [2; 32],
        Purpose::Administration,
    )
    .unwrap();
    peer.on_hello(&peer_control(&device.hello).unwrap())
        .unwrap();
    assert!(peer.bearer().is_err());
    let present = device.present_pseudonym(1, &[3; 32], &[4; 32], &DeviceId([5; 32]));
    assert!(matches!(
        peer.on_message(&peer_control(&present).unwrap()).unwrap(),
        Checked::Present(_)
    ));
    let closed = peer
        .on_message(&peer_control(&present).unwrap())
        .unwrap_err();
    assert_eq!(closed.code, frasil_transport::Code::PurposeViolation);
}
