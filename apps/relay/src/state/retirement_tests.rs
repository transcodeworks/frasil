//! What open connections hold under an entry ends when it retires or the
//! space is erased (peers.md, 2.2 The credential proof; 3.6 Retirement and
//! the cap, "Connections"), and rates count per entry as well as per
//! author (peers.md, 3.20 Quotas and rates). The space is `peers.json`'s
//! `credentials` history, whose credentials the reference derives from
//! `example("storage/credentials/<rotation>/...")`.

use super::*;
use crate::clock::ManualClock;
use crate::session::QUEUE;
use crate::space::Removal;
use frasil_crypto::primitives::sha256;
use frasil_keys::derive::{read_credential, upload_key};
use frasil_store::MemoryStore;
use serde_json::Value as Json;

const GENESIS: &str = "P creates the space";
const REMOVAL: &str = "P removes W";
const REQUEST: &str = "P0 asks to keep the removal's entry live";
const RACING: &str = "W rotates, racing its removal";
const V_ROTATES: &str = "V rotates, citing W's rotation";

fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// The rotation's name in the reference's example labels.
fn label(rotation: &str) -> &str {
    if rotation == GENESIS {
        "genesis"
    } else {
        rotation
    }
}

fn read_seed(rotation: &str) -> [u8; 32] {
    let content = example(&format!(
        "storage/credentials/{}/content-key",
        label(rotation)
    ));
    *read_credential(&content).seed
}

fn upload_seed(rotation: &str) -> [u8; 32] {
    let seed = example(&format!(
        "storage/credentials/{}/upload-seed",
        label(rotation)
    ));
    *upload_key(&seed).seed
}

/// The `credentials` history's events, by name, in order, but `W forks`,
/// whose evidence would retire W's entries.
fn history() -> Vec<(String, Vec<u8>)> {
    frasil_testkit::vectors::family::<Json>("peers.json", "credentials")["events"]
        .as_array()
        .expect("an events list")
        .iter()
        .map(|row| {
            (
                row["name"].as_str().unwrap().to_owned(),
                frasil_testkit::hex::decode(row["signed"].as_str().unwrap()).unwrap(),
            )
        })
        .filter(|(name, _)| name != "W forks")
        .collect()
}

fn signed(events: &[(String, Vec<u8>)], name: &str) -> Vec<u8> {
    events
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no event {name}"))
        .1
        .clone()
}

fn id_of(signed: &[u8]) -> EventId {
    frasil_events::decode(signed).unwrap().id()
}

fn core_with(settings: Settings) -> (Core, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(crate::testing::START));
    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let core = Core::open(
        settings,
        Records::new(Arc::new(MemoryStore::new())),
        dyn_clock,
    )
    .unwrap();
    (core, clock)
}

/// A device's connection, as the core reaches it.
struct Device {
    link: u64,
    binding: [u8; 32],
    rx: mpsc::Receiver<Outgoing>,
    grants: BTreeMap<EventId, Grant>,
    requests: u64,
}

impl Device {
    fn new(core: &Core, binding: [u8; 32]) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        Self::on(core.link(tx), binding, rx)
    }

    /// A connection a gateway forwards to this node, the space's owner.
    fn forwarded(core: &Core, binding: [u8; 32]) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        Self::on(core.link_forwarded(tx, Arc::default()), binding, rx)
    }

    fn on(link: u64, binding: [u8; 32], rx: mpsc::Receiver<Outgoing>) -> Self {
        Self {
            link,
            binding,
            rx,
            grants: BTreeMap::new(),
            requests: 0,
        }
    }

    /// Presents a credential by its seed, with a transfer token; answers
    /// `Granted` or `Refused`.
    async fn present(
        &mut self,
        core: &Core,
        space: EventId,
        credential: Credential,
        seed: &[u8; 32],
        token: Option<[u8; 32]>,
    ) -> Outgoing {
        let public = frasil_crypto::primitives::ed25519_public(seed);
        let shown = frasil_peers::proof::presented(
            &self.binding,
            space.as_bytes(),
            credential.code(),
            &public,
        );
        self.requests += 1;
        let present = Present {
            request: self.requests,
            space: *space.as_bytes(),
            credential: u64::from(credential.code()),
            public: public.to_vec(),
            proof: frasil_peers::proof::prove(seed, &shown).to_vec(),
        };
        let on = On {
            link: self.link,
            binding: self.binding,
            purpose: Purpose::SpaceTraffic,
            now: core.clock.now(),
        };
        core.present(&on, &mut self.grants, &present, token).await
    }

    /// Stores one event as a message of the connection: its grant judged
    /// first, as the session judges it.
    async fn store(&mut self, core: &Core, space: EventId, signed: &[u8]) -> StoreAnswer {
        let grant = self.grants.entry(space).or_default();
        core.rejudge(space, grant).await;
        core.store(self.link, grant, space, signed, core.clock.now())
            .await
    }

    /// The rights the connection holds in the space at its next message.
    async fn rights(&mut self, core: &Core, space: EventId) -> Rights {
        let grant = self.grants.entry(space).or_default();
        core.rejudge(space, grant).await;
        grant.rights
    }

    /// Whether the core asked the connection to reconnect.
    fn asked_to_reconnect(&mut self) -> bool {
        let mut asked = false;
        while let Ok(out) = self.rx.try_recv() {
            asked |= out == Outgoing::Reconnect;
        }
        asked
    }
}

fn acknowledged(answer: &StoreAnswer) -> bool {
    matches!(answer, StoreAnswer::Acknowledge(_))
}

/// Stores the history through `device` up to, not with, `until`.
async fn store_until(
    core: &Core,
    device: &mut Device,
    events: &[(String, Vec<u8>)],
    from: usize,
    until: &str,
) -> usize {
    let space = id_of(&events[0].1);
    let mut at = from;
    while events[at].0 != until {
        let answer = device.store(core, space, &events[at].1).await;
        assert!(acknowledged(&answer), "{}: {answer:?}", events[at].0);
        at += 1;
    }
    at
}

/// Whether a present was answered `Granted`.
fn granted(answer: &Outgoing) -> bool {
    let Outgoing::Control(bytes) = answer else {
        return false;
    };
    matches!(
        crate::server::read(bytes, crate::Extensions::NONE),
        Ok(Some(message)) if message.kind == frasil_transport::frame::MessageType::Granted
    )
}

/// A credentials request carried out ends, at once, what connections hold
/// under the entries it retires: store and release, fetch and live
/// delivery (the read credential keeps catch-up), the live subscription,
/// with an ask to reconnect, and the transfer tokens. A connection that
/// also proved an entry the request keeps live keeps what that one grants;
/// a connection a gateway forwards is asked through its gateway.
#[tokio::test]
async fn a_credentials_request_ends_what_connections_hold_under_the_entries_it_retires() {
    let (core, clock) = core_with(Settings::open_core());
    let events = history();
    let space = id_of(&events[0].1);

    // The founder creates the space, proves the genesis's keys with
    // transfer tokens, and subscribes.
    let mut founder = Device::new(&core, [1; 32]);
    assert!(acknowledged(
        &founder.store(&core, space, &events[0].1).await
    ));
    for (credential, seed, token) in [
        (Credential::Upload, upload_seed(GENESIS), [0xa1; 32]),
        (Credential::Read, read_seed(GENESIS), [0xa2; 32]),
    ] {
        let answer = founder
            .present(&core, space, credential, &seed, Some(token))
            .await;
        assert!(granted(&answer), "{credential:?}");
    }
    core.subscribe(founder.link, space, None);
    store_until(&core, &mut founder, &events, 1, REQUEST).await;
    assert_eq!(
        founder.rights(&core, space).await,
        Rights::FETCH_AND_LIVE.union(Rights::STORE_AND_RELEASE)
    );

    // A second device proved the genesis's upload key and the removal's
    // keys too, which the request keeps live.
    let mut kept = Device::new(&core, [2; 32]);
    for (credential, seed, token) in [
        (Credential::Upload, upload_seed(GENESIS), [0xb1; 32]),
        (Credential::Upload, upload_seed(REMOVAL), [0xb2; 32]),
        (Credential::Read, read_seed(REMOVAL), [0xb3; 32]),
    ] {
        let answer = kept
            .present(&core, space, credential, &seed, Some(token))
            .await;
        assert!(granted(&answer), "{credential:?}");
    }
    core.subscribe(kept.link, space, None);

    // A reader that reaches this node, the space's owner, through a
    // gateway, live by the genesis's read credential only.
    let mut gateway = Device::forwarded(&core, [3; 32]);
    let answer = gateway
        .present(&core, space, Credential::Read, &read_seed(GENESIS), None)
        .await;
    assert!(granted(&answer));
    core.subscribe(gateway.link, space, None);
    founder.asked_to_reconnect();
    kept.asked_to_reconnect();
    gateway.asked_to_reconnect();

    // The request, carried out: stable at the peer, or after T.
    let request = signed(&events, REQUEST);
    assert!(acknowledged(&founder.store(&core, space, &request).await));
    clock.advance(core.settings.erasure_timeout + 1);
    core.sweep(clock.now()).await;
    assert_eq!(
        core.read(space, |held| held.executed.contains(&id_of(&request)))
            .await,
        Some(true)
    );

    // The founder: catch-up only, no subscription, asked to reconnect, its
    // tokens gone, and its next store refused as one with no right.
    assert_eq!(founder.rights(&core, space).await, Rights::CATCH_UP);
    assert!(!core.subscribed(founder.link, &space));
    assert!(founder.asked_to_reconnect());
    {
        let transfers = lock(&core.transfers);
        assert!(!transfers.contains_key(&[0xa1; 32]));
        assert!(!transfers.contains_key(&[0xa2; 32]));
        // The genesis's upload token of the second device stops; the
        // removal's stay.
        assert!(!transfers.contains_key(&[0xb1; 32]));
        assert!(transfers.contains_key(&[0xb2; 32]));
        assert!(transfers.contains_key(&[0xb3; 32]));
    }
    let next = signed(&events, V_ROTATES);
    assert_eq!(
        founder.store(&core, space, &next).await,
        StoreAnswer::Refused(Code::NotAuthorized.name().into())
    );

    // The forwarded reader: its subscription ends, and the ask to
    // reconnect goes to its gateway.
    assert!(!core.subscribed(gateway.link, &space));
    assert!(gateway.asked_to_reconnect());
    assert_eq!(gateway.rights(&core, space).await, Rights::CATCH_UP);

    // The second device keeps what the removal's entry grants, and stores
    // under it.
    assert_eq!(
        kept.rights(&core, space).await,
        Rights::FETCH_AND_LIVE.union(Rights::STORE_AND_RELEASE)
    );
    assert_eq!(
        kept.grants[&space].upload,
        Some(frasil_crypto::primitives::ed25519_public(&upload_seed(
            REMOVAL
        )))
    );
    assert!(core.subscribed(kept.link, &space));
    assert!(!kept.asked_to_reconnect());
    let answer = kept.store(&core, space, &next).await;
    assert!(acknowledged(&answer), "{answer:?}");

    // A present of the retired upload key is refused; of the retired read
    // credential, it grants catch-up.
    let mut again = Device::new(&core, [4; 32]);
    assert!(!granted(
        &again
            .present(
                &core,
                space,
                Credential::Upload,
                &upload_seed(GENESIS),
                None
            )
            .await
    ));
    assert!(granted(
        &again
            .present(&core, space, Credential::Read, &read_seed(GENESIS), None)
            .await
    ));
    assert_eq!(again.rights(&core, space).await, Rights::CATCH_UP);
}

/// An erasure of the space ends every right held in it, every transfer
/// token, and every subscription, with an ask to reconnect.
#[tokio::test]
async fn an_erasure_of_the_space_ends_every_right() {
    let (core, _clock) = core_with(Settings::open_core());
    let events = history();
    let space = id_of(&events[0].1);
    let mut device = Device::new(&core, [1; 32]);
    assert!(acknowledged(
        &device.store(&core, space, &events[0].1).await
    ));
    for (credential, seed, token) in [
        (Credential::Upload, upload_seed(GENESIS), [0xc1; 32]),
        (Credential::Read, read_seed(GENESIS), [0xc2; 32]),
    ] {
        let answer = device
            .present(&core, space, credential, &seed, Some(token))
            .await;
        assert!(granted(&answer));
    }
    core.subscribe(device.link, space, None);
    device.asked_to_reconnect();

    // The erasure, as a sweep carries it out: the erasure event's bytes
    // become the tombstone.
    let writing = core.write(space).await.unwrap();
    core.remove(
        &writing,
        Removal {
            erase_space: Some(events[0].1.clone()),
            ..Removal::default()
        },
    )
    .await
    .unwrap();
    drop(writing);

    assert_eq!(device.rights(&core, space).await, Rights::default());
    assert!(!core.subscribed(device.link, &space));
    assert!(device.asked_to_reconnect());
    {
        let transfers = lock(&core.transfers);
        assert!(!transfers.contains_key(&[0xc1; 32]));
        assert!(!transfers.contains_key(&[0xc2; 32]));
    }
    let next = signed(&events, "P0: root");
    assert!(matches!(
        device.store(&core, space, &next).await,
        StoreAnswer::Refused(_)
    ));
}

/// A rate applies per entry as well as per author: a writer that stores
/// under one entry is limited by it whatever author keys it signs with.
#[tokio::test]
async fn a_rate_counts_the_events_stored_under_one_entry() {
    let settings = Settings {
        rates: crate::config::Rates {
            space_events_per_hour: 4,
            ..crate::config::Rates::DEFAULT
        },
        ..Settings::open_core()
    };
    let (core, _clock) = core_with(settings);
    let events = history();
    let space = id_of(&events[0].1);
    let mut writer = Device::new(&core, [1; 32]);
    assert!(acknowledged(
        &writer.store(&core, space, &events[0].1).await
    ));
    let answer = writer
        .present(
            &core,
            space,
            Credential::Upload,
            &upload_seed(GENESIS),
            None,
        )
        .await;
    assert!(granted(&answer));
    // P0's root, then P's four space events, under the genesis's entry.
    store_until(&core, &mut writer, &events, 1, RACING).await;
    // W has stored nothing, but the entry has stored four space events.
    let racing = signed(&events, RACING);
    assert_eq!(
        writer.store(&core, space, &racing).await,
        StoreAnswer::Refused(Code::RateLimited.name().into())
    );
    // Under another entry, W's author rate has room.
    let mut other = Device::new(&core, [2; 32]);
    let answer = other
        .present(
            &core,
            space,
            Credential::Upload,
            &upload_seed(REMOVAL),
            None,
        )
        .await;
    assert!(granted(&answer));
    let answer = other.store(&core, space, &racing).await;
    assert!(!matches!(answer, StoreAnswer::Refused(_)), "{answer:?}");
}
