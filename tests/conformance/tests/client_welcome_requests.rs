//! Welcome requests in device mailboxes grant no membership or extra keys.
use frasil::{CheckpointPolicy, Device, Level, Options, Storage};
use frasil_admission::welcome_request::WelcomeRequest;
use frasil_crypto::{device::DeviceKeys, schemes::Signer, wrap::xwing_public};
use frasil_events::EventId;
use frasil_space::{HistoryMode, MemberRef, Via};
use std::time::Duration;

fn signer(seed: u8) -> (Signer, DeviceKeys) {
    let xwing = xwing_public(&[seed; 32]);
    let signer = Signer::from_seeds(&[seed; 32], &[seed + 1; 32], Some(&xwing));
    let keys = DeviceKeys {
        ed: *signer.identity_key(),
        keys: frasil_crypto::device::HybridKeys::new(signer.mldsa_public(), Some(&xwing)).unwrap(),
    };
    (signer, keys)
}

async fn deliveries(device: &Device, space: EventId) -> usize {
    device
        .engine()
        .events(&space)
        .await
        .iter()
        .filter_map(|signed| {
            let event = frasil_events::decode(signed).ok()?;
            let visible = frasil_keys::body::VisiblePart::read(
                event.unverified_body(),
                event.author(),
                event.seq(),
            )
            .ok()?;
            Some(visible.deliveries.len())
        })
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mailbox_requests_refuse_bad_signatures_and_non_members_and_answer_once() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let peer = frasil_conformance::spawn_loopback().await.unwrap();
        let admin = Device::open_with(Storage::Memory, &[70; 32], Options::new().loopback())
            .await
            .unwrap();
        admin.set_checkpoint_policy(CheckpointPolicy::MANUAL.forgetting(false));
        let held = admin.create_space().await.unwrap();
        let space = EventId(*held.id().as_bytes());
        let (member, member_keys) = signer(71);
        let (removed, removed_keys) = signer(73);
        for keys in [&member_keys, &removed_keys] {
            admin
                .engine()
                .grant_device(
                    space,
                    keys.clone(),
                    Level::Write,
                    HistoryMode::WithHistory,
                    Via::Code,
                )
                .await
                .unwrap();
        }
        admin
            .engine()
            .remove(space, MemberRef::device(removed_keys.device_id()))
            .await
            .unwrap();
        admin.connect(&peer.origin).await.unwrap();
        held.flush().await.unwrap();
        let before = deliveries(&admin, space).await;
        let request = WelcomeRequest {
            space: space.0,
            device: member_keys.device_id(),
            request: [1; 16],
        };
        let nonmember = WelcomeRequest {
            space: space.0,
            device: removed_keys.device_id(),
            request: [2; 16],
        };
        let signed = request.sign(&member);
        let items = [
            request.sign(&removed),
            nonmember.sign(&removed),
            signed.clone(),
            signed,
        ];
        for (index, signed) in items.into_iter().enumerate() {
            let item = frasil_transport::mailbox::seal_item_with(
                "frasil/welcome-request",
                &signed,
                admin.engine().public_keys(),
                &[index as u8 + 1; 64],
            )
            .unwrap();
            admin
                .deposit_item(&peer.origin, admin.id(), item)
                .await
                .unwrap();
        }
        while deliveries(&admin, space).await == before {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        held.flush().await.unwrap();
        assert_eq!(deliveries(&admin, space).await, before + 1);
        assert_eq!(
            admin
                .engine()
                .read(&space, |replica| replica
                    .level_of(&removed_keys.device_id()))
                .await
                .unwrap(),
            None
        );
        admin.close().await.unwrap();
        peer.shutdown().await;
    })
    .await
    .expect("requests handled within the deadline");
}
