//! transport.json's `local_network` family on real sockets: section 2.9's
//! packets sent to the IPv4 group `239.255.77.67`, port 47767, TTL 1, on the
//! loopback interface alone, received from it and opened as a listener
//! does (section 3.16). Then an announcement found that way is dialed with
//! the member ALPN.

mod common;

use common::*;
use frasil_base::Class;
use frasil_iroh::Alpn;
use frasil_iroh::lan::{
    Candidate, Candidates, KEEP, LanConfig, LanSocket, NearbyList, open_member,
};
use frasil_transport::lan;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

fn secret(label: &str) -> [u8; 32] {
    array(&family("member_handshake")["content_keys"][label])
}

/// The next packet the socket receives that `wanted` accepts; packets of
/// other tests on the same group are passed over.
async fn receive_where(
    socket: &LanSocket,
    wanted: impl Fn(&[u8]) -> bool,
) -> (Vec<u8>, SocketAddr) {
    within(async {
        loop {
            let (packet, source) = socket.receive().await.unwrap();
            if wanted(&packet) {
                return (packet, source);
            }
        }
    })
    .await
}

#[tokio::test]
async fn local_network_packets_cross_loopback_multicast() {
    let family = family("local_network");
    let sender = LanSocket::bind(LanConfig::loopback_v4()).unwrap();
    let listener = LanSocket::bind(LanConfig::loopback_v4()).unwrap();
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let tries: Vec<[u8; 32]> = family["listener_tries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| secret(text(l)))
        .collect();

    // The member announcement, sent as it is, opens with the listener's
    // second state, {C}.
    let packet = bytes(&family["packet"]);
    assert_eq!(packet.len() as u64, number(&family["packet_bytes"]));
    sender.send(&packet).await.unwrap();
    let (received, source) = receive_where(&listener, |p| p == packet).await;
    assert_eq!(source.ip(), loopback);
    let candidate = open_member(&received, source, &tries).unwrap();
    assert_eq!(
        text(&family["listener_tries"][candidate.state]),
        text(&family["opened_with"])
    );
    assert_eq!(candidate.endpoint, array(&family["opened"]["endpoint_key"]));
    let port = u16::try_from(number(&family["opened"]["port"])).unwrap();
    assert_eq!(candidate.address, SocketAddr::new(loopback, port));

    // A second packet of the same device, under a fresh nonce.
    let second = bytes(&family["second_packet"]["packet"]);
    sender.send(&second).await.unwrap();
    let (received, source) = receive_where(&listener, |p| p == second).await;
    assert_eq!(open_member(&received, source, &tries).unwrap(), candidate);

    // A non-member, and a listener with only an older state, cannot open
    // either.
    let other = array(&family["non_member_content_key"]);
    assert_eq!(
        open_member(&packet, source, &[other]).map_err(Class::name),
        Err(text(&family["non_member"]))
    );
    assert_eq!(
        open_member(&packet, source, &[secret("{B}")]).map_err(Class::name),
        Err(text(&family["older_state_only"]))
    );

    // The nearby announcement, with its name cleaned before it is sent and
    // again when it is read.
    let nearby_endpoint = array(&family["nearby_endpoint"]);
    let nearby_port = u16::try_from(number(&family["nearby_port"])).unwrap();
    let nearby = bytes(&family["nearby_packet"]);
    sender
        .announce_nearby(
            &nearby_endpoint,
            nearby_port,
            text(&family["nearby_name_in"]),
        )
        .await
        .unwrap();
    let (received, source) = receive_where(&listener, |p| p == nearby).await;
    let mut list = NearbyList::new();
    let host = list.receive(&received, source, Instant::now()).unwrap();
    assert_eq!(host.nearby.endpoint, nearby_endpoint);
    assert_eq!(host.nearby.name, text(&family["nearby_name_out"]));
    assert_eq!(host.address, SocketAddr::new(loopback, nearby_port));
}

#[tokio::test]
async fn an_announced_member_endpoint_is_dialed_with_the_member_alpn() {
    let state = *frasil_crypto::random_bytes::<32>().unwrap();
    let host = endpoint(&[Alpn::Member]).await;
    let port = host.local_addresses()[0].port();
    let device = endpoint(&[]).await;
    let announcer = LanSocket::bind(LanConfig::loopback_v4()).unwrap();
    let listener = LanSocket::bind(LanConfig::loopback_v4()).unwrap();

    announcer.announce(&state, &host.key(), port).await.unwrap();
    let (packet, source) = receive_where(&listener, |p| {
        p.len() == lan::PACKET_BYTES && lan::open(p, &[state]).is_ok()
    })
    .await;
    let found = open_member(&packet, source, &[state]).unwrap();
    assert_eq!(found.endpoint, host.key());
    let mut candidates = Candidates::new();
    candidates.insert(found, Instant::now());

    let candidate = candidates.current(Instant::now())[0];
    let addresses = [candidate.address];
    let (dialed, accepted) = within(async {
        tokio::join!(
            device.connect(&candidate.endpoint, &addresses, &[], Alpn::Member),
            async { host.accept().await.unwrap() },
        )
    })
    .await;
    let (dialed, accepted) = (dialed.unwrap(), accepted.unwrap());
    assert_eq!(dialed.peer(), host.key());
    assert_eq!(accepted.peer(), device.key());
    assert_eq!(dialed.channel(), accepted.channel());
}

#[test]
fn announcements_come_every_two_seconds_with_jitter() {
    for _ in 0..64 {
        let wait = frasil_iroh::lan::next_announcement().unwrap();
        assert!(wait >= Duration::from_secs(2) && wait <= Duration::from_millis(2_500));
    }
}

fn candidate(n: u8) -> Candidate {
    Candidate {
        address: SocketAddr::from(([192, 168, 1, n], 47_767)),
        endpoint: [n; 32],
        state: 0,
    }
}

#[test]
fn a_listener_keeps_128_candidates_for_ten_seconds() {
    let start = Instant::now();
    let mut candidates = Candidates::new();
    for n in 0..=128u8 {
        candidates.insert(candidate(n), start);
    }
    let kept = candidates.current(start);
    assert_eq!(kept.len(), lan::MAX_CANDIDATES);
    assert_eq!(kept[0], candidate(1));
    // Renewed, not repeated.
    candidates.insert(candidate(1), start + Duration::from_secs(5));
    assert_eq!(candidates.current(start).len(), lan::MAX_CANDIDATES);
    let later = candidates.current(start + KEEP);
    assert_eq!(later, [candidate(1)]);
    assert!(candidates.current(start + KEEP * 2).is_empty());
}

#[test]
fn a_listener_keeps_64_nearby_announcements_4_per_source() {
    let start = Instant::now();
    let mut list = NearbyList::new();
    let source = SocketAddr::from(([192, 168, 1, 9], 47_767));
    for n in 0..6u8 {
        let packet = lan::nearby_announce(&[n; 32], 50_000, "Host");
        list.receive(&packet, source, start).unwrap();
    }
    let kept = list.current(start);
    assert_eq!(kept.len(), lan::MAX_NEARBY_PER_SOURCE);
    assert_eq!(kept[0].nearby.endpoint, [2; 32]);
    for n in 0..80u8 {
        let packet = lan::nearby_announce(&[n; 32], 50_000, "Host");
        let source = SocketAddr::from(([10, 0, 0, n], 47_767));
        list.receive(&packet, source, start).unwrap();
    }
    assert_eq!(list.current(start).len(), lan::MAX_NEARBY);
    assert!(list.current(start + KEEP).is_empty());
    assert_eq!(
        list.receive(&[0x02, 0xa0], source, start)
            .map_err(Class::name),
        Err("Malformed")
    );
}

/// The loopback interface's index: 1 on macOS and Linux.
const LOOPBACK_INDEX: u32 = 1;

#[tokio::test]
async fn the_ipv6_group_carries_packets_on_loopback() {
    let config = LanConfig {
        v4: None,
        v6: Some(LOOPBACK_INDEX),
    };
    let sender = LanSocket::bind(config).unwrap();
    let listener = LanSocket::bind(config).unwrap();
    let state = *frasil_crypto::random_bytes::<32>().unwrap();
    // A host without an IPv6 route to the group on loopback (some hosted
    // runners) cannot send to it; there is nothing to carry there.
    if let Err(error) = sender.announce(&state, &[3; 32], 40_000).await {
        let text = error.to_string();
        assert!(
            text.contains("unreachable") || text.contains("No route to host"),
            "{text}"
        );
        eprintln!("skipped: no IPv6 route to the group on loopback ({text})");
        return;
    }
    let (packet, source) = receive_where(&listener, |p| {
        p.len() == lan::PACKET_BYTES && lan::open(p, &[state]).is_ok()
    })
    .await;
    assert!(source.is_ipv6());
    let found = open_member(&packet, source, &[state]).unwrap();
    assert_eq!((found.endpoint, found.address.port()), ([3; 32], 40_000));
}
