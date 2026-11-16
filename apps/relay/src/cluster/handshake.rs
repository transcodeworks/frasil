//! The internal links' handshake as bytes (module `link`, "The
//! handshake"): its three messages, the transcript, the two MACs and the
//! connection's keys. The link runs it over a stream; this module only
//! reads, writes and checks.
//!
//! Every message has a fixed length, so that a listener reads exactly
//! [`HELLO`] and then [`FINISH`] bytes of a dialer it does not know yet,
//! and holds nothing else for it. A MAC is compared in constant time, and
//! the pre-shared key and the connection's keys are zeroized when dropped.
//!
//! The module depends on `frasil-crypto`, `subtle` and `zeroize` alone, so
//! that its fuzz target builds it alone.

use frasil_crypto::primitives::{hkdf, hkdf_expand, hkdf_extract, hmac_sha256, sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The first bytes a dialer sends.
pub const MAGIC: &[u8; 8] = b"frasilc1";
/// The dialer's first message: `MAGIC || e_d || n_d || u64 id_d`.
pub const HELLO: usize = 64;
/// The listener's answer before its MAC: `e_l || n_l || u64 id_l`.
pub const REPLY_BODY: usize = 56;
/// The listener's answer: its body and `HMAC(psk, "listener" || th)`.
pub const REPLY: usize = REPLY_BODY + 32;
/// The dialer's last message: `HMAC(psk, "dialer" || th)`.
pub const FINISH: usize = 32;
/// What the listener's MAC is over, before the transcript.
pub const LISTENER: &[u8] = b"listener";
/// What the dialer's MAC is over, before the transcript.
pub const DIALER: &[u8] = b"dialer";

/// A dialer's first message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    /// The dialer's ephemeral X25519 public key.
    pub public: [u8; 32],
    /// Its random bytes for the connection.
    pub nonce: [u8; 16],
    /// The node it names itself.
    pub node: u64,
}

impl Hello {
    /// The message's bytes.
    pub fn encode(&self) -> [u8; HELLO] {
        let mut out = [0u8; HELLO];
        out[..8].copy_from_slice(MAGIC);
        out[8..40].copy_from_slice(&self.public);
        out[40..56].copy_from_slice(&self.nonce);
        out[56..].copy_from_slice(&self.node.to_be_bytes());
        out
    }

    /// Reads the message: none unless it starts with [`MAGIC`].
    pub fn decode(bytes: &[u8; HELLO]) -> Option<Self> {
        if &bytes[..8] != MAGIC {
            return None;
        }
        Some(Self {
            public: bytes[8..40].try_into().ok()?,
            nonce: bytes[40..56].try_into().ok()?,
            node: u64::from_be_bytes(bytes[56..].try_into().ok()?),
        })
    }
}

/// A listener's answer, before its MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    /// The listener's ephemeral X25519 public key.
    pub public: [u8; 32],
    /// Its random bytes for the connection.
    pub nonce: [u8; 16],
    /// The node it names itself.
    pub node: u64,
}

impl Reply {
    /// The answer's body, before the MAC.
    pub fn encode(&self) -> [u8; REPLY_BODY] {
        let mut out = [0u8; REPLY_BODY];
        out[..32].copy_from_slice(&self.public);
        out[32..48].copy_from_slice(&self.nonce);
        out[48..].copy_from_slice(&self.node.to_be_bytes());
        out
    }

    /// Reads an answer: its body and its MAC.
    pub fn decode(bytes: &[u8; REPLY]) -> (Self, [u8; 32]) {
        let mut public = [0u8; 32];
        let mut nonce = [0u8; 16];
        let mut node = [0u8; 8];
        let mut mac = [0u8; 32];
        public.copy_from_slice(&bytes[..32]);
        nonce.copy_from_slice(&bytes[32..48]);
        node.copy_from_slice(&bytes[48..56]);
        mac.copy_from_slice(&bytes[56..]);
        (
            Self {
                public,
                nonce,
                node: u64::from_be_bytes(node),
            },
            mac,
        )
    }
}

/// The links' pre-shared key, from the cluster key:
/// `HKDF(salt "frasil-relay/cluster/v1", key, "link key")`.
pub fn psk(cluster_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(Some(b"frasil-relay/cluster/v1"), cluster_key, b"link key")
}

/// Whether a cluster key is all zeros, compared in constant time: such a
/// key is no secret, and a node refuses to start with it.
pub fn is_zero(cluster_key: &[u8; 32]) -> bool {
    cluster_key.ct_eq(&[0u8; 32]).into()
}

/// `th`: SHA-256 of the dialer's first message and the listener's answer
/// before its MAC.
pub fn transcript(hello: &[u8; HELLO], reply: &[u8; REPLY_BODY]) -> [u8; 32] {
    sha256(&[hello, reply])
}

/// `HMAC(psk, role || th)`.
pub fn mac(psk: &[u8; 32], role: &[u8], th: &[u8; 32]) -> [u8; 32] {
    let mut message = [0u8; 40];
    let length = role.len().min(8);
    message[..length].copy_from_slice(&role[..length]);
    message[length..length + 32].copy_from_slice(th);
    hmac_sha256(psk, &message[..length + 32])
}

/// Whether `received` is the MAC of `role` over `th`, compared in constant
/// time.
pub fn verify(psk: &[u8; 32], role: &[u8], th: &[u8; 32], received: &[u8; 32]) -> bool {
    mac(psk, role, th).ct_eq(received).into()
}

/// One connection's keys: what this end seals with, and what it opens with.
pub struct Keys {
    /// The key of the frames this end sends.
    pub send: Zeroizing<[u8; 32]>,
    /// The key of the frames this end receives.
    pub receive: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Keys([redacted])")
    }
}

/// The connection's keys from the X25519 shared secret:
/// `prk = HKDF-Extract(psk, shared)`, then `HKDF-Expand(prk, "dialer to
/// listener" || th)` and `HKDF-Expand(prk, "listener to dialer" || th)`,
/// each end sending under the first or the second.
pub fn keys(psk: &[u8; 32], shared: &[u8; 32], th: &[u8; 32], dialer: bool) -> Option<Keys> {
    let prk = hkdf_extract(psk, shared);
    let expand = |label: &[u8]| -> Option<Zeroizing<[u8; 32]>> {
        let mut info = [0u8; 50];
        info[..18].copy_from_slice(label);
        info[18..].copy_from_slice(th);
        let mut okm = Zeroizing::new([0u8; 32]);
        hkdf_expand(&prk, &info, okm.as_mut_slice()).ok()?;
        Some(okm)
    };
    let d2l = expand(b"dialer to listener")?;
    let l2d = expand(b"listener to dialer")?;
    Some(if dialer {
        Keys {
            send: d2l,
            receive: l2d,
        }
    } else {
        Keys {
            send: l2d,
            receive: d2l,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both ends of an honest handshake agree, and a MAC under another key,
    /// or over another transcript, is refused.
    #[test]
    fn both_ends_agree_and_a_wrong_mac_is_refused() {
        let psk = psk(&[5; 32]);
        let hello = Hello {
            public: [1; 32],
            nonce: [2; 16],
            node: 3,
        };
        let bytes = hello.encode();
        assert_eq!(Hello::decode(&bytes), Some(hello));
        let reply = Reply {
            public: [4; 32],
            nonce: [5; 16],
            node: 6,
        };
        let body = reply.encode();
        let th = transcript(&bytes, &body);
        let listener = mac(&psk, LISTENER, &th);
        let mut answer = [0u8; REPLY];
        answer[..REPLY_BODY].copy_from_slice(&body);
        answer[REPLY_BODY..].copy_from_slice(&listener);
        assert_eq!(Reply::decode(&answer), (reply, listener));
        assert!(verify(&psk, LISTENER, &th, &listener));
        assert!(!verify(&psk, DIALER, &th, &listener), "the roles differ");
        let other = super::psk(&[6; 32]);
        assert!(!verify(&other, LISTENER, &th, &listener));
        let mut flipped = listener;
        flipped[31] ^= 1;
        assert!(!verify(&psk, LISTENER, &th, &flipped));
        let dialer = keys(&psk, &[9; 32], &th, true).unwrap();
        let listening = keys(&psk, &[9; 32], &th, false).unwrap();
        assert_eq!(*dialer.send, *listening.receive);
        assert_eq!(*dialer.receive, *listening.send);
        assert_ne!(*dialer.send, *dialer.receive);
        let mut wrong = bytes;
        wrong[0] ^= 1;
        assert_eq!(Hello::decode(&wrong), None);
    }

    /// An all-zero cluster key is no secret.
    #[test]
    fn an_all_zero_key_is_told_apart() {
        assert!(is_zero(&[0; 32]));
        let mut key = [0u8; 32];
        key[31] = 1;
        assert!(!is_zero(&key));
    }
}
