//! An ML-DSA-65 key cannot be bound to another member's device, end to end
//! through a peer (roster.md, "A device's keys" and "Security
//! considerations"; crypto.md, "A device's keys").
//!
//! The adversary is a reader of the space that can also make the Ed25519
//! half of a signature for the administrator's key, as a quantum adversary
//! could: the test stands in for that with the administrator's Ed25519
//! seed. It holds an ML-DSA-65 key `M2` and an X-Wing key of its own.
//!
//! The reader stores, through the peer, a space event that grants the
//! administrator's Ed25519 key beside `M2` as an administering device; an
//! event "by" those keys that raises the reader to `write`; and the same
//! raise under the administrator's own `kc`, at a `seq` the administrator
//! used, whose ML-DSA-65 half `M2` made. The peer stores all three, the
//! third as evidence of a fork it serves to every replica: it judges no
//! event's ML-DSA-65 half. Every other member's replica finds the grant void, the
//! raise the act of another device ID that holds no standing, and the
//! third event `BadSignature` and no evidence of a fork: the reader stays a
//! reader, the administrator is not forked, and the administrator's next
//! change is valid everywhere.

mod common;

use common::{Binding, connect};
use frasil::advanced::peer::{PeerHandle, connect_server};
use frasil::advanced::{AdapterRegistry, Engine, OsRandom, Platform, Random};
use frasil_base::errors::Class;
use frasil_conformance::client::Credential;
use frasil_conformance::spawn_loopback;
use frasil_crypto::device::KeysCommitment;
use frasil_crypto::primitives::ed25519_public;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_crypto::wrap::xwing_public;
use frasil_events::{Envelope, EventId, kind};
use frasil_keys::RotationSet;
use frasil_keys::body::{Inner, Seal, VisiblePart};
use frasil_keys::derive::{
    SecretKind, body_commitment, body_key, read_credential, state_secret, upload_key,
};
use frasil_relay::testing::TestPeer;
use frasil_space::part::{RosterPart, Update};
use frasil_space::{Change, DeviceKeys, HistoryMode, Level, MemberRef, Via};
use frasil_transport::peer::Purpose;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEADLINE: Duration = Duration::from_secs(60);

/// The adversary's own ML-DSA-65 and X-Wing seeds.
const M2_SEED: [u8; 32] = [0x4d; 32];
const X2_SEED: [u8; 32] = [0x58; 32];

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
}

/// The system's random source, keeping every draw of 32 bytes, so that the
/// test can stand in for an adversary that recovers a seed.
#[derive(Default)]
struct Recorded(Mutex<Vec<[u8; 32]>>);

impl Random for Recorded {
    fn fill(&self, out: &mut [u8]) -> frasil::Result<()> {
        OsRandom.fill(out)?;
        if let Ok(draw) = <[u8; 32]>::try_from(&*out) {
            self.0.lock().unwrap().push(draw);
        }
        Ok(())
    }
}

impl Recorded {
    fn draws(&self) -> Vec<[u8; 32]> {
        self.0.lock().unwrap().clone()
    }
}

async fn device() -> (Engine, Arc<Recorded>) {
    let random = Arc::new(Recorded::default());
    let (engine, _) = Engine::create(
        Platform::memory().with_random(random.clone()),
        &[7; 32],
        AdapterRegistry::with_builtins(),
    )
    .await
    .expect("a device");
    (engine, random)
}

/// The device's signer, from the draws that made its keys: its identity,
/// X-Wing and ML-DSA-65 seeds, drawn in that order.
fn signer_of(engine: &Engine, random: &Recorded) -> Signer {
    let draws = random.draws();
    let ed = engine.public_keys().ed;
    let at = draws
        .iter()
        .position(|draw| ed25519_public(draw) == ed.0)
        .expect("the identity seed was drawn");
    let signer = Signer::from_seeds(
        &draws[at],
        &draws[at + 2],
        Some(&xwing_public(&draws[at + 1])),
    );
    assert_eq!(*signer.device_id(), engine.device_id());
    signer
}

async fn server(engine: &Engine, peer: &TestPeer, space: EventId) -> PeerHandle {
    connect_server(engine, &peer.origin, vec![space])
        .await
        .expect("a WebSocket connection")
}

/// A space event of these changes, sealed under `secret` of `state` and
/// signed as `signer` under `kc`.
#[allow(clippy::too_many_arguments)]
fn space_event(
    signer: &Signer,
    kc: KeysCommitment,
    space: EventId,
    (seq, prev): (u64, Option<EventId>),
    parents: Vec<EventId>,
    state: &RotationSet,
    secret: &[u8; 32],
    changes: Vec<Change>,
) -> Vec<u8> {
    let author = frasil_crypto::device::device_id(signer.identity_key(), &kc);
    let key = body_key(secret, &space.0, &author, seq);
    let inner = Inner {
        roster: Some(RosterPart::Update(Update { changes }).encode()),
        ..Inner::default()
    };
    let body = VisiblePart {
        seal: Seal::Under(state.clone()),
        deliveries: Vec::new(),
        sealed: inner.seal_with(&key, &space.0, &author, seq, &[0x6e; 24]),
        nonce: None,
        commitment: body_commitment(&key),
        twin: None,
    }
    .encode();
    Envelope {
        kind: kind::SPACE,
        log: Some(space),
        ed: *signer.identity_key(),
        kc,
        seq,
        prev,
        parents,
        cuts: Vec::new(),
        body,
        scheme: Scheme::Hybrid,
    }
    .sign(signer)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_cannot_bind_its_own_ml_dsa_key_to_an_administrator_through_a_peer() {
    let peer = spawn_loopback().await.unwrap();
    let (alice, alices_draws) = device().await;
    let (bob, bobs_draws) = device().await;
    let (carol, _) = device().await;
    let space = alice.create_space().await.unwrap();
    for (other, level) in [(&bob, Level::Read), (&carol, Level::Write)] {
        alice
            .grant_device(
                space,
                other.public_keys().clone(),
                level,
                HistoryMode::WithHistory,
                Via::Code,
            )
            .await
            .unwrap();
    }
    for other in [&bob, &carol] {
        other.follow(space).await;
        other
            .ingest(space, alice.events(&space).await)
            .await
            .unwrap();
    }
    let _links: Vec<PeerHandle> = vec![
        server(&alice, &peer, space).await,
        server(&bob, &peer, space).await,
        server(&carol, &peer, space).await,
    ];
    until(|| async { alice.outbox(&space).await.is_empty() }).await;
    let alice_id = alice.device_id();
    let bob_id = bob.device_id();
    for member in [&alice, &bob, &carol] {
        let level = member.read(&space, |r| r.level_of(&bob_id)).await.unwrap();
        assert_eq!(level, Some(Level::Read));
    }

    // What the adversary holds: the reader's own keys and the content key
    // of the state it was granted under, and Alice's Ed25519 seed.
    let bobs = signer_of(&bob, &bobs_draws);
    let alices_ed_seed = signer_of(&alice, &alices_draws);
    let (state, rotation_keys) = bob
        .read(&space, |r| {
            let state = r.current().cloned().expect("a state");
            let genesis = r.event(space).expect("the genesis");
            let visible =
                VisiblePart::read(genesis.unverified_body(), genesis.author(), genesis.seq())
                    .expect("a visible part");
            let Seal::Rotation(keys) = visible.seal else {
                panic!("the genesis rotates")
            };
            (state, keys)
        })
        .await
        .unwrap();
    assert_eq!(state, RotationSet::single(space), "no rotation since");
    let draws = alices_draws.draws();
    let k_genesis = draws
        .iter()
        .find(|d| read_credential(d).public == rotation_keys.read)
        .expect("the genesis's content key");
    let w_genesis = draws
        .iter()
        .find(|d| upload_key(d).public == rotation_keys.upload)
        .expect("the genesis's upload seed");
    let secret = state_secret(SecretKind::Content, &space, &state, &[*k_genesis]).unwrap();

    // The forger: Alice's Ed25519 seed beside M2 and an X-Wing key of the
    // adversary's: another device ID, D'.
    let forger = Signer::from_seeds(
        &signers_seed(&alices_draws, &alice),
        &M2_SEED,
        Some(&xwing_public(&X2_SEED)),
    );
    let d_prime = *forger.device_id();
    assert_eq!(forger.identity_key(), alices_ed_seed.identity_key());
    assert_ne!(d_prime, alice_id);

    // 1. Bob, a reader, grants D' administer: a void event of his own.
    let (bobs_next, heads) = bob
        .read(&space, |r| {
            let log = r.log().expect("a log");
            let last = log
                .canonical()
                .into_iter()
                .filter_map(|id| log.event(id))
                .filter(|e| *e.author() == bob_id)
                .map(|e| (e.seq(), e.id()))
                .max();
            let next = match last {
                Some((seq, id)) => (seq + 1, Some(id)),
                None => (1, None),
            };
            (next, r.heads())
        })
        .await
        .unwrap();
    let mut parents = heads.clone();
    parents.extend(bobs_next.1.filter(|p| !heads.contains(p)));
    let binding = space_event(
        &bobs,
        *bobs.kc(),
        space,
        bobs_next,
        parents,
        &state,
        &secret,
        vec![Change::grant_administrator(
            DeviceKeys {
                ed: *forger.identity_key(),
                keys: forger.keys().clone(),
            },
            255,
            HistoryMode::WithHistory,
            Via::Code,
        )],
    );
    let binding_id = frasil_events::decode(&binding).unwrap().id();
    let raise = vec![Change::set_level(MemberRef::device(bob_id), Level::Write)];
    // 2. D' raises Bob to write.
    let by_d_prime = space_event(
        &forger,
        *forger.kc(),
        space,
        (1, None),
        vec![binding_id],
        &state,
        &secret,
        raise.clone(),
    );
    // 3. The same raise under Alice's own kc, at her seq 2, its ML-DSA-65
    // half by M2.
    let (alices_second, alices_first) = alice
        .read(&space, |r| {
            let log = r.log().expect("a log");
            let at = |seq| {
                log.canonical()
                    .into_iter()
                    .filter_map(|id| log.event(id))
                    .find(|e| *e.author() == alice_id && e.seq() == seq)
                    .map(|e| e.id())
                    .expect("Alice's event")
            };
            (at(2), at(1))
        })
        .await
        .unwrap();
    let as_alice = space_event(
        &forger,
        *alices_ed_seed.kc(),
        space,
        (2, Some(alices_first)),
        vec![binding_id, alices_first],
        &state,
        &secret,
        raise,
    );
    let by_d_prime_id = frasil_events::decode(&by_d_prime).unwrap().id();
    let as_alice_id = frasil_events::decode(&as_alice).unwrap().id();
    assert_ne!(as_alice_id, alices_second);
    assert_eq!(
        *frasil_events::decode(&as_alice).unwrap().author(),
        alice_id
    );

    // The adversary stores all three at the peer under the upload key,
    // which judges none of them.
    let mut raw = connect(&peer, Binding::WebSocket, Purpose::SpaceTraffic).await;
    raw.present(space, Credential::Upload, &upload_key(w_genesis).seed)
        .await
        .expect("the genesis's upload key");
    for signed in [&binding, &by_d_prime] {
        assert_eq!(
            raw.store_answer(space, signed, DEADLINE).await,
            Some(Ok(())),
            "the peer stores it"
        );
    }
    // A second event at Alice's seq 2: stored as fork evidence and served
    // to every replica, never acknowledged (peers.md, 3.2 Storing an
    // event).
    assert_eq!(
        raw.store_answer(space, &as_alice, DEADLINE).await,
        Some(Err("conflict".into()))
    );
    raw.close().await;

    // Every other member's replica: the grant is void, D''s raise holds
    // no standing, the third event is no event of Alice's, and Alice is
    // not forked.
    for member in [&alice, &carol] {
        until(|| async {
            member
                .read(&space, |r| {
                    r.holds(binding_id)
                        && r.holds(by_d_prime_id)
                        && r.status(&as_alice_id).is_some()
                })
                .await
                .unwrap()
        })
        .await;
        member
            .read(&space, |r| {
                let class = |id: EventId| r.status(&id).and_then(|s| s.class()).map(|c| c.name());
                assert_eq!(class(binding_id), Some("NotAnAdministrator"));
                assert!(!r.valid().contains(&binding_id));
                assert!(!r.valid().contains(&by_d_prime_id));
                assert!(class(by_d_prime_id).is_some(), "D''s raise is void");
                assert_eq!(class(as_alice_id), Some("BadSignature"));
                assert!(!r.valid().contains(&as_alice_id));
                assert!(!r.forked(&alice_id), "Alice is not forked");
                assert!(r.valid().contains(&alices_second));
                assert_eq!(r.level_of(&bob_id), Some(Level::Read));
                assert_eq!(r.level_of(&d_prime), None);
            })
            .await
            .unwrap();
    }

    // The space carries on: Alice's next change is valid at Carol's.
    alice
        .sign_roster(
            space,
            vec![Change::set_level(MemberRef::device(bob_id), Level::Write)],
        )
        .await
        .unwrap();
    until(|| async {
        carol.read(&space, |r| r.level_of(&bob_id)).await.unwrap() == Some(Level::Write)
    })
    .await;
    assert!(!carol.read(&space, |r| r.forked(&alice_id)).await.unwrap());
    peer.shutdown().await;
}

/// The identity seed among a device's draws.
fn signers_seed(random: &Recorded, engine: &Engine) -> [u8; 32] {
    let ed = engine.public_keys().ed;
    random
        .draws()
        .into_iter()
        .find(|draw| ed25519_public(draw) == ed.0)
        .expect("the identity seed was drawn")
}
