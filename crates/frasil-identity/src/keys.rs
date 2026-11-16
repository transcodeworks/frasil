//! A list member's keys, the kinds of list member and their ranks
//! (identity.md, "Device keys", "Kinds of list member" and "The state of a
//! list at a place").

use crate::possession;
use frasil_crypto::device::{DeviceId, DeviceKeys, HybridKeys, IdentityKey, device_id};
use frasil_crypto::primitives::ed25519_public;
use frasil_crypto::schemes::Signer;
use frasil_crypto::sizes::{MLDSA65_PUBLIC, XWING_PUBLIC};
use frasil_crypto::wrap::xwing_public;
use zeroize::Zeroizing;

/// The kind of a list member: body key 2 of a device-list event
/// (identity.md, "The device-list event").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// A device, with keys from its own random seeds.
    Device,
    /// A recovery key, with keys from a recovery sheet's secret.
    RecoveryKey,
    /// A passkey member, with keys from a passkey's PRF output.
    PasskeyMember,
    /// A recovery agent, a party the person names; it receives no wraps
    /// and its `add` names no X-Wing key.
    RecoveryAgent,
}

impl Kind {
    /// Every kind, in code order.
    pub const ALL: [Kind; 4] = [
        Kind::Device,
        Kind::RecoveryKey,
        Kind::PasskeyMember,
        Kind::RecoveryAgent,
    ];

    /// The kind's code in the body.
    pub const fn code(self) -> u8 {
        match self {
            Kind::Device => 0,
            Kind::RecoveryKey => 1,
            Kind::PasskeyMember => 2,
            Kind::RecoveryAgent => 3,
        }
    }

    /// The kind of a code, or `None` for a code no kind has.
    pub fn from_code(code: u64) -> Option<Self> {
        Kind::ALL
            .into_iter()
            .find(|kind| u64::from(kind.code()) == code)
    }

    /// The kind's name, as the document writes it.
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Device => "device",
            Kind::RecoveryKey => "recovery key",
            Kind::PasskeyMember => "passkey member",
            Kind::RecoveryAgent => "recovery agent",
        }
    }

    /// Whether an `add` of this kind names an X-Wing key: every kind but an
    /// agent, which receives no wraps.
    pub const fn names_xwing(self) -> bool {
        !matches!(self, Kind::RecoveryAgent)
    }
}

/// A list member's rank, 1 the highest (identity.md, "The state of a list at
/// a place").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rank {
    /// Rank 1: a recovery key that is not rooted.
    RecoveryKey = 1,
    /// Rank 2: a device that is not rooted.
    Device = 2,
    /// Rank 3: a passkey member, and any list member rooted in a passkey.
    Passkey = 3,
    /// Rank 4: an agent, and any list member rooted in an agent.
    Agent = 4,
}

impl Rank {
    /// Every rank, highest first.
    pub const ALL: [Rank; 4] = [Rank::RecoveryKey, Rank::Device, Rank::Passkey, Rank::Agent];

    /// The rank's number, 1 the highest.
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// Which list members hold the rank, as the document's table says.
    pub const fn holders(self) -> &'static str {
        match self {
            Rank::RecoveryKey => "a recovery key that is not rooted",
            Rank::Device => "a device that is not rooted",
            Rank::Passkey => "a passkey member, and any list member rooted in a passkey",
            Rank::Agent => "an agent, and any list member rooted in an agent",
        }
    }
}

/// The public keys an `add` names: the identity key, the X-Wing key (absent
/// for an agent) and the ML-DSA-65 key. Their device ID names the list
/// member.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKeys {
    /// The Ed25519 identity key, which signs.
    pub identity: IdentityKey,
    /// The X-Wing key, to which keys are wrapped; `None` for an agent.
    pub xwing: Option<Box<[u8; XWING_PUBLIC]>>,
    /// The ML-DSA-65 key, which signs beside the identity key.
    pub mldsa: Box<[u8; MLDSA65_PUBLIC]>,
}

impl PublicKeys {
    /// The ML-DSA-65 and X-Wing keys, which the keys commitment names. The
    /// X-Wing key has passed `xwing_valid` where it entered.
    pub fn hybrid(&self) -> HybridKeys {
        HybridKeys::from_checked(self.mldsa.clone(), self.xwing.clone())
    }

    /// The three keys, as crypto.md names them.
    pub fn device_keys(&self) -> DeviceKeys {
        DeviceKeys {
            ed: self.identity,
            keys: self.hybrid(),
        }
    }

    /// The device ID the keys give (crypto.md, "A device's keys").
    pub fn device_id(&self) -> DeviceId {
        device_id(&self.identity, self.hybrid().commitment())
    }
}

impl core::fmt::Debug for PublicKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKeys")
            .field("device_id", &self.device_id())
            .field("identity", &self.identity)
            .field("xwing", &self.xwing.is_some())
            .finish_non_exhaustive()
    }
}

/// A list member's key pairs (identity.md, "Device keys"): an Ed25519
/// identity key, an X-Wing key and an ML-DSA-65 key, each from a 32-byte
/// seed. A recovery agent has no X-Wing key ([`MemberKeys::without_xwing`]).
///
/// A device draws its three seeds independently from its random source and
/// keeps them sealed. A passkey member and a recovery key derive them from a
/// secret the person holds ([`crate::passkey`], [`crate::recovery`]). A
/// client never offers keys derived from a passkey or a sheet as a device's
/// keys, in admission or in a roster grant.
pub struct MemberKeys {
    identity_seed: Zeroizing<[u8; 32]>,
    xwing_seed: Option<Zeroizing<[u8; 32]>>,
    mldsa_seed: Zeroizing<[u8; 32]>,
    signer: Signer,
}

impl MemberKeys {
    /// The keys of three seeds: the identity seed, the X-Wing seed and the
    /// ML-DSA-65 seed.
    pub fn from_seeds(
        identity_seed: &[u8; 32],
        xwing_seed: &[u8; 32],
        mldsa_seed: &[u8; 32],
    ) -> Self {
        let xwing = xwing_public(xwing_seed);
        Self {
            identity_seed: Zeroizing::new(*identity_seed),
            xwing_seed: Some(Zeroizing::new(*xwing_seed)),
            mldsa_seed: Zeroizing::new(*mldsa_seed),
            signer: Signer::from_seeds(identity_seed, mldsa_seed, Some(&xwing)),
        }
    }

    /// The keys of a holder with no X-Wing key, a recovery agent: the
    /// identity seed and the ML-DSA-65 seed. Its keys commitment hashes an
    /// empty X-Wing key.
    pub fn without_xwing(identity_seed: &[u8; 32], mldsa_seed: &[u8; 32]) -> Self {
        Self {
            identity_seed: Zeroizing::new(*identity_seed),
            xwing_seed: None,
            mldsa_seed: Zeroizing::new(*mldsa_seed),
            signer: Signer::from_seeds(identity_seed, mldsa_seed, None),
        }
    }

    /// The Ed25519 identity key.
    pub fn identity(&self) -> &IdentityKey {
        self.signer.identity_key()
    }

    /// The device ID, which names the list member.
    pub fn device_id(&self) -> &DeviceId {
        self.signer.device_id()
    }

    /// The X-Wing public key, or `None` for a holder with none.
    pub fn xwing(&self) -> Option<&[u8; XWING_PUBLIC]> {
        self.signer.keys().xwing()
    }

    /// The ML-DSA-65 public key.
    pub fn mldsa(&self) -> &[u8; MLDSA65_PUBLIC] {
        self.signer.mldsa_public()
    }

    /// The identity seed.
    pub fn identity_seed(&self) -> &[u8; 32] {
        &self.identity_seed
    }

    /// The X-Wing seed, which opens wraps, or `None` for a holder with no
    /// X-Wing key.
    pub fn xwing_seed(&self) -> Option<&[u8; 32]> {
        self.xwing_seed.as_deref()
    }

    /// The ML-DSA-65 seed.
    pub fn mldsa_seed(&self) -> &[u8; 32] {
        &self.mldsa_seed
    }

    /// The signer of schemes 0 and 2 under the identity and ML-DSA-65 keys,
    /// with the keys commitment and device ID of these keys.
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// The public keys an `add` of this kind names: without the X-Wing key
    /// for an agent, or for a holder that has none.
    pub fn public(&self, kind: Kind) -> PublicKeys {
        PublicKeys {
            identity: *self.identity(),
            xwing: self
                .xwing()
                .filter(|_| kind.names_xwing())
                .map(|key| Box::new(*key)),
            mldsa: Box::new(*self.mldsa()),
        }
    }

    /// The possession proof an `add` of these keys as `kind` carries
    /// (identity.md, "The possession statement"): the scheme-2 signature of
    /// the statement over `person_id`, which is 32 zero bytes in the list's
    /// first event, for `adder`, the device ID of the list member that will
    /// sign the `add`. Only an `add` that `adder` signs carries it.
    pub fn prove_possession(&self, person_id: &[u8; 32], adder: &DeviceId, kind: Kind) -> Vec<u8> {
        let public = self.public(kind);
        let statement = possession::statement(
            person_id,
            adder,
            kind,
            &public.identity,
            &public.mldsa,
            public.xwing.as_deref(),
        );
        possession::prove(&self.signer, &statement)
    }
}

impl core::fmt::Debug for MemberKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemberKeys")
            .field("device_id", self.device_id())
            .field("identity", self.identity())
            .finish_non_exhaustive()
    }
}

/// A fetch key (identity.md, "Fetch keys and recovery entries"): the
/// Ed25519 key of a fetch seed, which a peer serves a space's catch-up to
/// when it is registered there as a recovery entry.
pub struct FetchKey {
    seed: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl FetchKey {
    /// The fetch key of a fetch seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(*seed),
            public: ed25519_public(seed),
        }
    }

    /// The fetch seed.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The fetch key: the Ed25519 public key of the seed.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }
}

impl core::fmt::Debug for FetchKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FetchKey")
            .field("public", &format_args!("{:02x?}", self.public))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for kind in Kind::ALL {
            assert_eq!(Kind::from_code(u64::from(kind.code())), Some(kind));
        }
        assert_eq!(Kind::from_code(4), None);
        assert_eq!(Rank::ALL.map(Rank::number), [1, 2, 3, 4]);
    }
}
