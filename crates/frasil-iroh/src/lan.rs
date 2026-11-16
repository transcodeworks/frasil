//! The local network's sockets (transport.md, sections 2.9 "Local-network
//! packets" and 3.16, "Member announcements" and "Nearby pairing").
//!
//! All local-network packets go to the IPv4 multicast group
//! `239.255.77.67` and the IPv6 group `ff02::7767`, UDP port 47767, with a
//! TTL or hop limit of 1. [`LanSocket`] sends and receives them; the
//! packets' formats and the listener's checks are `frasil_transport::lan`'s.
//! [`Candidates`] and [`NearbyList`] are what a listener keeps of them.
//!
//! An announcement only says where to dial: a candidate is dialed with the
//! member ALPN, and the member handshake decides everything.

use crate::Error;
use frasil_transport::TransportClass;
use frasil_transport::lan::{
    self, Announcement, GROUP_V4, GROUP_V6, HOPS, INTERVAL_SECONDS, JITTER_MILLISECONDS,
    KEEP_SECONDS, MAX_CANDIDATES, MAX_NEARBY, MAX_NEARBY_PER_SOURCE, Nearby, PORT,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// How long a listener keeps a candidate or a nearby announcement.
pub const KEEP: Duration = Duration::from_secs(KEEP_SECONDS);

/// The largest packet a [`LanSocket`] reads; a longer one is cut and fails
/// its checks.
pub const RECEIVE_BYTES: usize = 2_048;

/// The interfaces a [`LanSocket`] joins the groups on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanConfig {
    /// The IPv4 interface, by address; `None` for no IPv4 socket.
    /// `0.0.0.0` lets the system choose.
    pub v4: Option<Ipv4Addr>,
    /// The IPv6 interface, by index; `None` for no IPv6 socket. `0` lets the
    /// system choose.
    pub v6: Option<u32>,
}

impl Default for LanConfig {
    /// Both groups, on the interfaces the system chooses.
    fn default() -> Self {
        Self {
            v4: Some(Ipv4Addr::UNSPECIFIED),
            v6: Some(0),
        }
    }
}

impl LanConfig {
    /// The IPv4 group on the loopback interface alone: packets reach only
    /// this host.
    pub fn loopback_v4() -> Self {
        Self {
            v4: Some(Ipv4Addr::LOCALHOST),
            v6: None,
        }
    }
}

/// The sockets of the local network's packets: one per IP version, bound
/// to port 47767 beside any other on this host, joined to the group, with
/// a TTL or hop limit of 1.
#[derive(Debug)]
pub struct LanSocket {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
}

fn v4_socket(interface: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT).into())?;
    let group = Ipv4Addr::from(GROUP_V4);
    socket.join_multicast_v4(&group, &interface)?;
    socket.set_multicast_if_v4(&interface)?;
    socket.set_multicast_ttl_v4(HOPS)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn v6_socket(interface: u32) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, PORT, 0, 0).into())?;
    let group = Ipv6Addr::from(GROUP_V6);
    socket.join_multicast_v6(&group, interface)?;
    socket.set_multicast_if_v6(interface)?;
    socket.set_multicast_hops_v6(HOPS)?;
    socket.set_multicast_loop_v6(true)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

impl LanSocket {
    /// Binds the sockets the configuration names. Must run inside a tokio
    /// runtime.
    ///
    /// # Errors
    ///
    /// `Io` if a socket the configuration names does not bind or join.
    pub fn bind(config: LanConfig) -> Result<Self, Error> {
        let v4 = config.v4.map(v4_socket).transpose().map_err(Error::io)?;
        let v6 = config.v6.map(v6_socket).transpose().map_err(Error::io)?;
        if v4.is_none() && v6.is_none() {
            return Err(Error::Io("no local-network socket".to_owned()));
        }
        Ok(Self { v4, v6 })
    }

    /// Sends one packet to each group this socket joined.
    ///
    /// # Errors
    ///
    /// `Io` if no group could be sent to.
    pub async fn send(&self, packet: &[u8]) -> Result<(), Error> {
        let mut sent = false;
        let mut failure = None;
        if let Some(socket) = &self.v4 {
            let to = SocketAddr::from((Ipv4Addr::from(GROUP_V4), PORT));
            match socket.send_to(packet, to).await {
                Ok(_) => sent = true,
                Err(error) => failure = Some(error),
            }
        }
        if let Some(socket) = &self.v6 {
            let to = SocketAddr::from((Ipv6Addr::from(GROUP_V6), PORT));
            match socket.send_to(packet, to).await {
                Ok(_) => sent = true,
                Err(error) => failure = Some(error),
            }
        }
        match (sent, failure) {
            (false, Some(error)) => Err(Error::io(error)),
            _ => Ok(()),
        }
    }

    /// The next packet, with its source address.
    ///
    /// # Errors
    ///
    /// `Io` if a socket fails.
    pub async fn receive(&self) -> Result<(Vec<u8>, SocketAddr), Error> {
        let mut v4 = [0u8; RECEIVE_BYTES];
        let mut v6 = [0u8; RECEIVE_BYTES];
        let (buffer, read) = match (&self.v4, &self.v6) {
            (Some(a), Some(b)) => tokio::select! {
                read = a.recv_from(&mut v4) => (&v4[..], read),
                read = b.recv_from(&mut v6) => (&v6[..], read),
            },
            (Some(a), None) => {
                let read = a.recv_from(&mut v4).await;
                (&v4[..], read)
            }
            (None, Some(b)) => {
                let read = b.recv_from(&mut v6).await;
                (&v6[..], read)
            }
            (None, None) => return Err(Error::Io("no local-network socket".to_owned())),
        };
        let (length, source) = read.map_err(Error::io)?;
        Ok((buffer[..length].to_vec(), source))
    }

    /// Sends a member announcement of one space at a state: section 2.9's
    /// packet under a fresh nonce, naming the member endpoint key and the
    /// port to dial.
    ///
    /// # Errors
    ///
    /// `Io` if no randomness or no group could be sent to.
    pub async fn announce(
        &self,
        state_secret: &[u8; 32],
        endpoint: &[u8; 32],
        port: u16,
    ) -> Result<(), Error> {
        let nonce = frasil_crypto::random_bytes::<24>().map_err(Error::io)?;
        let packet = lan::announce_with(state_secret, endpoint, port, &nonce);
        self.send(&packet).await
    }

    /// Sends a nearby announcement: a fresh pairing endpoint key, its port,
    /// and the application's display name, cleaned.
    ///
    /// # Errors
    ///
    /// `Io` if no group could be sent to.
    pub async fn announce_nearby(
        &self,
        endpoint: &[u8; 32],
        port: u16,
        name: &str,
    ) -> Result<(), Error> {
        self.send(&lan::nearby_announce(endpoint, port, name)).await
    }
}

/// The wait before a device's next member announcement of a space: 2
/// seconds, with up to 0.5 seconds of random jitter.
///
/// # Errors
///
/// `Io` if the system has no randomness.
pub fn next_announcement() -> Result<Duration, Error> {
    let bytes = frasil_crypto::random_bytes::<2>().map_err(Error::io)?;
    let jitter = u64::from(u16::from_be_bytes(*bytes)) % (JITTER_MILLISECONDS + 1);
    Ok(Duration::from_secs(INTERVAL_SECONDS) + Duration::from_millis(jitter))
}

/// A candidate to dial with the member ALPN: the source address of an
/// announcement that opened, its port and the endpoint key it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Where to dial: the packet's source address, with the announced port.
    pub address: SocketAddr,
    /// The announcer's member endpoint key.
    pub endpoint: [u8; 32],
    /// The index, among the secrets tried, of the state that opened it.
    pub state: usize,
}

/// A listener's checks of one member announcement (section 3.16), and the
/// candidate it gives. `state_secrets` are, for a space it has open, the
/// `k(S)` of its current state and of up to 3 states before it.
///
/// # Errors
///
/// `Malformed` or `NotForMe`, as `frasil_transport::lan::open` says.
pub fn open_member<K: core::borrow::Borrow<[u8; 32]>>(
    packet: &[u8],
    source: SocketAddr,
    state_secrets: &[K],
) -> Result<Candidate, TransportClass> {
    let Announcement {
        state,
        endpoint,
        port,
    } = lan::open(packet, state_secrets)?;
    let mut address = source;
    address.set_port(port);
    Ok(Candidate {
        address,
        endpoint,
        state,
    })
}

/// The candidates a listener keeps: at most 128, each for 10 seconds from
/// its last announcement.
#[derive(Debug, Clone, Default)]
pub struct Candidates {
    entries: Vec<(Candidate, Instant)>,
}

impl Candidates {
    /// No candidate.
    pub fn new() -> Self {
        Self::default()
    }

    fn expire(&mut self, now: Instant) {
        self.entries
            .retain(|(_, seen)| now.saturating_duration_since(*seen) < KEEP);
    }

    /// Keeps a candidate seen now. A candidate already kept, of the same
    /// endpoint key and address, is renewed; past 128, the oldest goes.
    pub fn insert(&mut self, candidate: Candidate, now: Instant) {
        self.expire(now);
        self.entries.retain(|(kept, _)| {
            (kept.endpoint, kept.address) != (candidate.endpoint, candidate.address)
        });
        self.entries.push((candidate, now));
        if self.entries.len() > MAX_CANDIDATES {
            self.entries.remove(0);
        }
    }

    /// The candidates kept at this time, oldest first.
    pub fn current(&mut self, now: Instant) -> Vec<Candidate> {
        self.expire(now);
        self.entries
            .iter()
            .map(|(candidate, _)| *candidate)
            .collect()
    }
}

/// A nearby announcement a listener keeps: where it came from and what it
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearbyHost {
    /// Where to dial with `frasil/p1/nearby`: the source address, with the
    /// announced port.
    pub address: SocketAddr,
    /// The announcement.
    pub nearby: Nearby,
}

/// The nearby announcements a listener keeps: at most 64, 4 per source
/// address, each for 10 seconds.
#[derive(Debug, Clone, Default)]
pub struct NearbyList {
    entries: Vec<(NearbyHost, Instant)>,
}

impl NearbyList {
    /// No announcement.
    pub fn new() -> Self {
        Self::default()
    }

    fn expire(&mut self, now: Instant) {
        self.entries
            .retain(|(_, seen)| now.saturating_duration_since(*seen) < KEEP);
    }

    /// Reads a nearby announcement from a source, and keeps it. One already
    /// kept of the same endpoint key and source is renewed; past 4 for the
    /// source, or 64 in all, the oldest goes.
    ///
    /// # Errors
    ///
    /// `Malformed`, as `frasil_transport::lan::read_nearby` says.
    pub fn receive(
        &mut self,
        packet: &[u8],
        source: SocketAddr,
        now: Instant,
    ) -> Result<NearbyHost, TransportClass> {
        let nearby = lan::read_nearby(packet)?;
        let mut address = source;
        address.set_port(nearby.port);
        let host = NearbyHost { address, nearby };
        self.expire(now);
        let ip: IpAddr = source.ip();
        self.entries.retain(|(kept, _)| {
            (kept.nearby.endpoint, kept.address.ip()) != (host.nearby.endpoint, ip)
        });
        let from_source = self
            .entries
            .iter()
            .filter(|(kept, _)| kept.address.ip() == ip)
            .count();
        if from_source >= MAX_NEARBY_PER_SOURCE
            && let Some(oldest) = self
                .entries
                .iter()
                .position(|(kept, _)| kept.address.ip() == ip)
        {
            self.entries.remove(oldest);
        }
        self.entries.push((host.clone(), now));
        if self.entries.len() > MAX_NEARBY {
            self.entries.remove(0);
        }
        Ok(host)
    }

    /// The announcements kept at this time, oldest first.
    pub fn current(&mut self, now: Instant) -> Vec<NearbyHost> {
        self.expire(now);
        self.entries.iter().map(|(host, _)| host.clone()).collect()
    }
}
