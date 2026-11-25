//! Local-network packets (transport.md, sections 2.9 "Local-network
//! packets" and 3.16, "Member announcements" and "Nearby pairing").
//!
//! ```text
//! member announcement, for one space at state S:
//!   lan_key(S) = HKDF(none, k(S), "frasil/lan-key/v1")
//!   core       = {1: member endpoint key (32), 2: port (1 to 65,535)}
//!   plaintext  = u16be(len(core)) || core || zero bytes, 96 bytes in all
//!   packet     = 0x01 || nonce (24) || XChaCha20-Poly1305(lan_key(S), nonce, plaintext,
//!                                                         aad = "frasil/lan-announce/v1")
//!                                                         137 bytes
//!
//! nearby announcement:
//!   packet     = 0x02 || {1: endpoint key (32), 2: port, 3: name (text)}
//! ```
//!
//! An announcement only says where to dial; the member handshake decides
//! everything.

use crate::TransportClass;
use crate::member::Secret;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::labels;
use frasil_crypto::primitives::{hkdf, xchacha20poly1305_open, xchacha20poly1305_seal};

/// The IPv4 multicast group of every local-network packet.
pub const GROUP_V4: [u8; 4] = [239, 255, 77, 67];
/// The IPv6 multicast group, `ff02::7767`.
pub const GROUP_V6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77, 0x67];
/// The UDP port.
pub const PORT: u16 = 47_767;
/// The TTL or hop limit.
pub const HOPS: u32 = 1;

/// A member announcement's first byte.
pub const MEMBER: u8 = 0x01;
/// A nearby announcement's first byte.
pub const NEARBY: u8 = 0x02;
/// A member announcement's plaintext, in bytes.
pub const PLAINTEXT_BYTES: usize = 96;
/// A member announcement, in bytes.
pub const PACKET_BYTES: usize = 1 + 24 + PLAINTEXT_BYTES + 16;
/// A listener tries its current state of each space and up to this many
/// before it.
pub const OLDER_STATES: usize = 3;
/// The most spaces a device announces in one interval.
pub const MAX_SPACES: usize = 4;
/// Seconds between a device's announcements of a space.
pub const INTERVAL_SECONDS: u64 = 2;
/// The most random jitter added to the interval, in milliseconds.
pub const JITTER_MILLISECONDS: u64 = 500;
/// The most candidates a listener keeps.
pub const MAX_CANDIDATES: usize = 128;
/// Seconds a listener keeps a candidate or a nearby announcement.
pub const KEEP_SECONDS: u64 = 10;
/// The most nearby announcements a listener keeps.
pub const MAX_NEARBY: usize = 64;
/// The most nearby announcements a listener keeps per source address.
pub const MAX_NEARBY_PER_SOURCE: usize = 4;
/// The longest a host sends nearby announcements each time pairing is
/// switched on, in seconds.
pub const PAIRING_WINDOW_SECONDS: u64 = 300;
/// The least time between two pairings, in seconds.
pub const PAIRING_GAP_SECONDS: u64 = 3;
/// The most characters of a nearby name.
pub const NAME_CHARACTERS: usize = 48;
/// The nearby name when nothing is left of the application's.
pub const NAME_FALLBACK: &str = "Nearby device";

/// The spaces a device announces in one interval (section 3.16, "Member
/// announcements"): of `spaces`, those it may announce in ascending order,
/// the next [`MAX_SPACES`] after `last`, the last one it announced, going
/// round to the first, and each at most once. A device with N such spaces
/// so announces each of them once every ceil(N / 4) intervals, and a space
/// that joins or leaves the set between two intervals costs no other space
/// its turn.
pub fn next_spaces<T: Ord + Clone>(spaces: &[T], last: Option<&T>) -> Vec<T> {
    let start = last.map_or(0, |last| spaces.partition_point(|space| space <= last));
    spaces
        .iter()
        .cycle()
        .skip(start)
        .take(spaces.len().min(MAX_SPACES))
        .cloned()
        .collect()
}

/// `lan_key(S) = HKDF(none, k(S), "frasil/lan-key/v1")`.
pub fn lan_key(state_secret: &[u8; 32]) -> Secret {
    hkdf(None, state_secret, labels::LAN_KEY)
}

fn core(endpoint: &[u8; 32], port: u16) -> Vec<u8> {
    let mut map = Map::new();
    map.insert(1, Value::from(*endpoint));
    map.insert(2, Value::Unsigned(port.into()));
    Value::Map(map).encode()
}

/// A member announcement's plaintext: `u16be(len(core)) || core`, padded
/// with zero bytes to 96.
///
/// # Panics
///
/// If the port is 0.
pub fn plaintext(endpoint: &[u8; 32], port: u16) -> [u8; PLAINTEXT_BYTES] {
    assert!(port != 0, "a port is 1 to 65,535");
    let core = core(endpoint, port);
    let mut out = [0; PLAINTEXT_BYTES];
    let length = u16::try_from(core.len()).expect("a core is short");
    out[..2].copy_from_slice(&length.to_be_bytes());
    out[2..2 + core.len()].copy_from_slice(&core);
    out
}

/// A member announcement of a space at a state, under 24 fresh random
/// bytes of nonce.
///
/// # Panics
///
/// If the port is 0.
pub fn announce_with(
    state_secret: &[u8; 32],
    endpoint: &[u8; 32],
    port: u16,
    nonce: &[u8; 24],
) -> [u8; PACKET_BYTES] {
    let sealed = xchacha20poly1305_seal(
        &lan_key(state_secret),
        nonce,
        labels::LAN_ANNOUNCE,
        &plaintext(endpoint, port),
    );
    let mut packet = [0; PACKET_BYTES];
    packet[0] = MEMBER;
    packet[1..25].copy_from_slice(nonce);
    packet[25..].copy_from_slice(&sealed);
    packet
}

/// A member announcement that opened: a candidate to dial with the member
/// ALPN, at the packet's source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announcement {
    /// The index, among the secrets tried, of the state that opened it.
    pub state: usize,
    /// The announcer's member endpoint key.
    pub endpoint: [u8; 32],
    /// The port to dial.
    pub port: u16,
}

/// A listener, for each packet, in order (section 3.16). `state_secrets`
/// are, for a space it has open, the `k(S)` of its current state and of up
/// to 3 states before it, in that order; a listener with several spaces
/// open tries each space's in turn.
///
/// # Errors
///
/// `Malformed` unless the packet is 137 bytes and starts `0x01`; `NotForMe`
/// if no secret tried opens it; `Malformed` for a plaintext whose length
/// prefix is 0 or does not fit, whose padding is not zero, or whose core is
/// not exactly keys 1 and 2, a 32-byte key and a port from 1 to 65,535.
pub fn open<K: core::borrow::Borrow<[u8; 32]>>(
    packet: &[u8],
    state_secrets: &[K],
) -> Result<Announcement, TransportClass> {
    let malformed = || TransportClass::from(ErrorClass::Malformed);
    // 1.
    if packet.len() != PACKET_BYTES || packet[0] != MEMBER {
        return Err(malformed());
    }
    let nonce: &[u8; 24] = packet[1..25].try_into().expect("24 bytes");
    let sealed = &packet[25..];
    // 2.
    let Some((state, plaintext)) = state_secrets
        .iter()
        .take(1 + OLDER_STATES)
        .enumerate()
        .find_map(|(index, secret)| {
            xchacha20poly1305_open(
                &lan_key(secret.borrow()),
                nonce,
                labels::LAN_ANNOUNCE,
                sealed,
            )
            .ok()
            .map(|plaintext| (index, plaintext))
        })
    else {
        return Err(TransportClass::NotForMe);
    };
    // 3.
    let (length, rest) = plaintext.split_first_chunk::<2>().ok_or_else(malformed)?;
    let length = usize::from(u16::from_be_bytes(*length));
    if length < 1 || length > rest.len() || rest[length..].iter().any(|&b| b != 0) {
        return Err(malformed());
    }
    let value = cbor::decode(&rest[..length])?;
    let map = value.as_map()?;
    if !crate::exact_keys(map, &[1, 2]) {
        return Err(malformed());
    }
    let endpoint = map[&1].as_byte_array()?;
    let port = map[&2].as_unsigned()?;
    let port = u16::try_from(port)
        .ok()
        .filter(|p| *p >= 1)
        .ok_or_else(malformed)?;
    Ok(Announcement {
        state,
        endpoint,
        port,
    })
}

/// Whether a character is removed from a nearby name: every control
/// character (Unicode category Cc) and bidirectional control (U+061C,
/// U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069).
fn removed(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// A nearby name: the application's display name with every control
/// character and bidirectional control removed, trimmed of white space,
/// cut to 48 characters and trimmed again; `Nearby device` if nothing is
/// left.
pub fn nearby_name(text: &str) -> String {
    let kept: String = text.chars().filter(|&c| !removed(c)).collect();
    let cut: String = kept.trim().chars().take(NAME_CHARACTERS).collect();
    match cut.trim() {
        "" => NAME_FALLBACK.to_owned(),
        name => name.to_owned(),
    }
}

/// A headless device's nearby name in setup mode: `setup-` and its setup
/// tag in lower-case hexadecimal (admission.md).
pub fn setup_name(setup_tag: &[u8]) -> String {
    format!("setup-{}", frasil_base::notation::hex::encode(setup_tag))
}

/// A nearby announcement: `0x02 || {1: endpoint key, 2: port, 3: name}`,
/// the name cleaned by [`nearby_name`].
pub fn nearby_announce(endpoint: &[u8; 32], port: u16, name: &str) -> Vec<u8> {
    let mut map = Map::new();
    map.insert(1, Value::from(*endpoint));
    map.insert(2, Value::Unsigned(port.into()));
    map.insert(3, Value::from(nearby_name(name)));
    let mut packet = vec![NEARBY];
    Value::Map(map).encode_into(&mut packet);
    packet
}

/// A nearby announcement, as a listener reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nearby {
    /// The host's endpoint key for this pairing session.
    pub endpoint: [u8; 32],
    /// The port to dial with `frasil/p1/nearby`.
    pub port: u16,
    /// The name to show, cleaned again by [`nearby_name`].
    pub name: String,
}

/// Reads a nearby announcement: `0x02`, then one deterministic CBOR map of
/// exactly keys 1 to 3, a 32-byte key, a port from 1 to 65,535 and a text.
/// The name is cleaned again before it is shown.
///
/// # Errors
///
/// `Malformed`.
pub fn read_nearby(packet: &[u8]) -> Result<Nearby, TransportClass> {
    let malformed = || TransportClass::from(ErrorClass::Malformed);
    let (&first, rest) = packet.split_first().ok_or_else(malformed)?;
    if first != NEARBY {
        return Err(malformed());
    }
    let value = cbor::decode(rest)?;
    let map = value.as_map()?;
    if !crate::exact_keys(map, &[1, 2, 3]) {
        return Err(malformed());
    }
    let port = u16::try_from(map[&2].as_unsigned()?)
        .ok()
        .filter(|p| *p >= 1)
        .ok_or_else(malformed)?;
    Ok(Nearby {
        endpoint: map[&1].as_byte_array()?,
        port,
        name: nearby_name(map[&3].as_text()?),
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_SPACES, next_spaces};

    /// Every space has its turn once every ceil(N / 4) intervals.
    #[test]
    fn spaces_are_announced_in_turn() {
        for count in 0..=13_u32 {
            let spaces: Vec<u32> = (0..count).collect();
            let intervals = spaces.len().div_ceil(MAX_SPACES);
            let mut last = None;
            let mut announced = Vec::new();
            for _ in 0..intervals {
                let next = next_spaces(&spaces, last.as_ref());
                assert_eq!(next.len(), spaces.len().min(MAX_SPACES));
                last = next.last().copied();
                announced.extend(next);
            }
            for space in &spaces {
                assert!(announced.contains(space), "{space} of {count}");
            }
            // At most four spaces: all of them, every interval.
            if spaces.len() <= MAX_SPACES {
                assert_eq!(next_spaces(&spaces, last.as_ref()).len(), spaces.len());
            }
        }
        assert_eq!(next_spaces(&[1, 2, 3, 4, 5, 6], None), [1, 2, 3, 4]);
        assert_eq!(next_spaces(&[1, 2, 3, 4, 5, 6], Some(&4)), [5, 6, 1, 2]);
        assert_eq!(next_spaces(&[1, 2, 3, 4, 5, 6], Some(&2)), [3, 4, 5, 6]);
    }

    /// The set changes between two intervals: the turn goes on from the
    /// last space announced, whether it is still there or not.
    #[test]
    fn a_changed_set_keeps_the_turn() {
        // The last one announced left.
        assert_eq!(next_spaces(&[1, 2, 3, 5, 6, 7], Some(&4)), [5, 6, 7, 1]);
        // Spaces joined before and after it.
        assert_eq!(
            next_spaces(&[0, 1, 2, 3, 4, 5, 6, 7, 8], Some(&4)),
            [5, 6, 7, 8]
        );
        // It was the greatest, or is past the greatest left.
        assert_eq!(next_spaces(&[1, 2, 3, 4, 5], Some(&5)), [1, 2, 3, 4]);
        assert_eq!(next_spaces(&[1, 2], Some(&9)), [1, 2]);
        assert_eq!(next_spaces::<u32>(&[], Some(&9)), []);
    }
}
