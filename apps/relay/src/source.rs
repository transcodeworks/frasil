//! A connection's **source**: the address the peer counts its limits per
//! source by. They are the cap on connections from one source
//! ([`ConnectionLimits::max_connections_per_source`]), the rate of
//! device-mailbox deposits (transport.md, 3.14 Mailboxes, "The peer's
//! caps"), the exchange mailboxes one source opens (admission.md,
//! "Exchange mailboxes"), and with ext-deposit-tokens the tokens one source
//! has refused (ext-deposit-tokens.md, 3.7 Redeeming).
//!
//! - **The server binding.** The source is the TCP connection's remote
//!   address. When that address is one of the reverse proxies the operator
//!   trusts ([`TrustedProxies`], `FRASIL_TRUSTED_PROXIES`), it is the
//!   client's address the proxy names in `X-Forwarded-For` instead: the
//!   rightmost address of the header's list that is not itself a trusted
//!   proxy. A request from any other address is taken at its remote address
//!   and its header is never read, so that a client that reaches the peer
//!   directly cannot name another source. Only `X-Forwarded-For` is read,
//!   the header common proxies set by default; a `Forwarded` header
//!   (RFC 7239) is ignored, so that a client cannot add one that a proxy
//!   which sets only `X-Forwarded-For` passes through.
//! - **The iroh binding.** A device's endpoint key costs it nothing to
//!   draw again, so it names no source. The source is the remote address of
//!   a direct path, as the connection reaches the device when it opens. A
//!   connection that reaches the peer only through an iroh relay has no
//!   source: [`NONE`], to which no limit per source applies, and only the
//!   peer's caps on everything together bound it.
//!
//! An address is written in its canonical form, an IPv4-mapped IPv6
//! address as IPv4, with no port.
//!
//! [`ConnectionLimits::max_connections_per_source`]:
//!     crate::config::ConnectionLimits::max_connections_per_source

use crate::config::ConfigError;
use std::net::{IpAddr, SocketAddr};

/// The source of a connection that has none: an iroh connection with no
/// direct path. No limit per source applies to it.
pub(crate) const NONE: &str = "";

/// The most networks `FRASIL_TRUSTED_PROXIES` names.
pub const MAX_TRUSTED_PROXIES: usize = 64;

/// An address and a prefix length: the addresses whose first `prefix` bits
/// are the address's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    /// Reads `address` or `address/prefix`, IPv4 or IPv6.
    ///
    /// # Errors
    ///
    /// Text that is neither, or a prefix longer than the address.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let bad = || {
            ConfigError(format!(
                "FRASIL_TRUSTED_PROXIES: `{text}` is no address or network"
            ))
        };
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address.parse().map_err(|_| bad())?;
        let address = address.to_canonical();
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|&prefix| prefix <= bits)
                .ok_or_else(bad)?,
            None => bits,
        };
        Ok(Self { address, prefix })
    }

    /// Whether `address` is in the network.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                same_prefix(&network.octets(), &address.octets(), self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                same_prefix(&network.octets(), &address.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// Whether the first `prefix` bits of `a` and `b` are equal.
fn same_prefix(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix / 8);
    let rest = prefix % 8;
    if a[..whole] != b[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    a[whole] & mask == b[whole] & mask
}

/// The reverse proxies the operator trusts to name the client's address:
/// none by default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<Network>);

impl TrustedProxies {
    /// Reads `FRASIL_TRUSTED_PROXIES`: addresses or networks, separated by
    /// spaces or commas, at most [`MAX_TRUSTED_PROXIES`].
    ///
    /// # Errors
    ///
    /// An entry that does not read, or too many.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let networks = text
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|entry| !entry.is_empty())
            .map(Network::parse)
            .collect::<Result<Vec<_>, _>>()?;
        if networks.len() > MAX_TRUSTED_PROXIES {
            return Err(ConfigError(format!(
                "FRASIL_TRUSTED_PROXIES names more than {MAX_TRUSTED_PROXIES} networks"
            )));
        }
        Ok(Self(networks))
    }

    /// Whether no proxy is trusted.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `address` is a trusted proxy's.
    pub fn contains(&self, address: IpAddr) -> bool {
        self.0.iter().any(|network| network.contains(address))
    }

    /// The client's address for a request whose TCP connection comes from
    /// `remote` with these `X-Forwarded-For` values, in the order they
    /// arrived: `remote` itself unless it is a trusted proxy; otherwise the
    /// rightmost address of the list that is not a trusted proxy's. When
    /// every address of the list is a trusted proxy's, the leftmost; when
    /// the list is absent, or an entry right of the client does not read as
    /// an address, `remote`.
    pub fn client<'h>(
        &self,
        remote: IpAddr,
        forwarded: impl IntoIterator<Item = &'h str>,
    ) -> IpAddr {
        let remote = remote.to_canonical();
        if !self.contains(remote) {
            return remote;
        }
        let entries: Vec<&str> = forwarded
            .into_iter()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .collect();
        let mut leftmost = remote;
        for entry in entries.iter().rev() {
            let Some(address) = read_entry(entry) else {
                return remote;
            };
            if !self.contains(address) {
                return address;
            }
            leftmost = address;
        }
        leftmost
    }
}

/// An `X-Forwarded-For` entry: an address, an IPv6 address in brackets,
/// either with a port, in canonical form.
fn read_entry(entry: &str) -> Option<IpAddr> {
    if let Ok(address) = entry.parse::<IpAddr>() {
        return Some(address.to_canonical());
    }
    entry
        .parse::<SocketAddr>()
        .ok()
        .map(|socket| socket.ip().to_canonical())
}

/// The source of a request over the server binding: the client's address,
/// as [`TrustedProxies::client`] reads it from the request's
/// `X-Forwarded-For` headers.
pub(crate) fn of_request(
    trusted: &TrustedProxies,
    remote: SocketAddr,
    headers: &axum::http::HeaderMap,
) -> String {
    if !trusted.contains(remote.ip()) {
        return remote.ip().to_canonical().to_string();
    }
    let values = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok());
    trusted.client(remote.ip(), values).to_string()
}

/// The source of a connection on the iroh binding: the address of a direct
/// path, as the connection reaches the device now; [`NONE`] when it has
/// only a relay path.
pub(crate) fn of_iroh(connection: &frasil_iroh::Connection) -> String {
    use frasil_transport::ticket::{Address, TicketKind};
    let direct = connection
        .remote_ticket(TicketKind::Peer)
        .and_then(|ticket| ticket.addresses.first().copied());
    match direct {
        Some(Address::V4(octets, _)) => IpAddr::from(octets).to_string(),
        Some(Address::V6(octets, _)) => IpAddr::from(octets).to_canonical().to_string(),
        None => NONE.to_owned(),
    }
}

/// A message `source` puts in an exchange mailbox (admission.md, "Exchange
/// mailboxes"): with no source, step 4's limits per source count nothing,
/// and the limits on all exchange mailboxes together bound it.
///
/// # Errors
///
/// The checks' classes.
pub(crate) fn exchange_put(
    mailboxes: &mut frasil_admission::mailbox::ExchangeMailboxes<String>,
    source: &str,
    message: &[u8],
    wall: u64,
) -> Result<(), frasil_admission::AdmissionClass> {
    if source == NONE {
        mailboxes.put_unsourced(message, wall)
    } else {
        mailboxes.put(&source.to_owned(), message, wall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn networks_read_and_hold_their_addresses() {
        let proxies = TrustedProxies::parse("10.0.0.0/8, 192.0.2.7 fd00::/8,::1").unwrap();
        assert!(proxies.contains(ip("10.1.2.3")));
        assert!(proxies.contains(ip("192.0.2.7")));
        assert!(!proxies.contains(ip("192.0.2.8")));
        assert!(proxies.contains(ip("fd12::1")));
        assert!(proxies.contains(ip("::1")));
        // An IPv4-mapped address is the IPv4 address.
        assert!(proxies.contains(ip("::ffff:10.0.0.1")));
        assert!(!proxies.contains(ip("11.0.0.1")));
        let odd = TrustedProxies::parse("192.0.2.128/25").unwrap();
        assert!(odd.contains(ip("192.0.2.200")));
        assert!(!odd.contains(ip("192.0.2.127")));
        assert!(TrustedProxies::parse("").unwrap().is_empty());
        for bad in ["10.0.0.0/33", "proxy", "::/129", "10.0.0.1/"] {
            assert!(TrustedProxies::parse(bad).is_err(), "{bad}");
        }
        let many = vec!["10.0.0.1"; MAX_TRUSTED_PROXIES + 1].join(" ");
        assert!(TrustedProxies::parse(&many).is_err());
    }

    /// The forwarded address is used only for a connection from a trusted
    /// proxy, and a forged header from elsewhere is ignored.
    #[test]
    fn the_forwarded_address_counts_only_from_a_trusted_proxy() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let proxy = ip("10.0.0.2");
        let client =
            |remote: IpAddr, header: &[&str]| proxies.client(remote, header.iter().copied());
        // From the proxy: the client it names.
        assert_eq!(client(proxy, &["198.51.100.4"]), ip("198.51.100.4"));
        // A client's own forged entry sits left of what the proxy added.
        assert_eq!(
            client(proxy, &["203.0.113.9, 198.51.100.4"]),
            ip("198.51.100.4")
        );
        // A chain of trusted proxies: the rightmost address not theirs, over
        // several header lines.
        assert_eq!(
            client(proxy, &["203.0.113.9, 198.51.100.4", "10.0.0.7"]),
            ip("198.51.100.4")
        );
        // Bracketed and with ports.
        assert_eq!(client(proxy, &["[2001:db8::1]:4711"]), ip("2001:db8::1"));
        assert_eq!(client(proxy, &["198.51.100.4:4711"]), ip("198.51.100.4"));
        // No header, or one that does not read: the proxy's own address.
        assert_eq!(client(proxy, &[]), proxy);
        assert_eq!(client(proxy, &["unknown"]), proxy);
        // Every hop trusted: the leftmost.
        assert_eq!(client(proxy, &["10.0.0.9, 10.0.0.8"]), ip("10.0.0.9"));
        // From anywhere else the header is never read.
        let direct = ip("192.0.2.50");
        assert_eq!(client(direct, &["198.51.100.4"]), direct);
        // With no trusted proxy, nothing is read either.
        assert_eq!(
            TrustedProxies::default().client(proxy, ["198.51.100.4"]),
            proxy
        );
    }

    #[test]
    fn a_requests_source_reads_the_header_only_from_a_trusted_proxy() {
        let proxies = TrustedProxies::parse("127.0.0.1").unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.4".parse().unwrap());
        headers.insert("forwarded", "for=203.0.113.9".parse().unwrap());
        let from = |remote: &str| of_request(&proxies, remote.parse().unwrap(), &headers);
        assert_eq!(from("127.0.0.1:5000"), "198.51.100.4");
        assert_eq!(from("[::ffff:127.0.0.1]:5000"), "198.51.100.4");
        assert_eq!(from("192.0.2.1:5000"), "192.0.2.1");
        assert_eq!(
            of_request(
                &TrustedProxies::default(),
                "127.0.0.1:1".parse().unwrap(),
                &headers
            ),
            "127.0.0.1"
        );
    }

    #[test]
    fn trusted_proxies_read_from_the_environment() {
        let config = crate::config::Config::from_lookup(|name| {
            (name == "FRASIL_TRUSTED_PROXIES").then(|| "10.0.0.0/8 ::1".to_owned())
        })
        .unwrap();
        assert!(config.settings.trusted_proxies.contains(ip("10.9.9.9")));
        assert!(
            crate::config::Config::from_lookup(|name| {
                (name == "FRASIL_TRUSTED_PROXIES").then(|| "proxy.example.org".to_owned())
            })
            .is_err()
        );
    }
}
