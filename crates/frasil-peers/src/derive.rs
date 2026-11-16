//! Skeleton derivations (peers.md, "Skeleton derivations").
//!
//! ```text
//! twin_secret(R) = HKDF(none, body_key(R), "frasil/skeleton-twin/v1")
//! self_ref(R)    = 0x00 || R's author || u64be(R's seq)                     41 bytes
//! c(R)           = SHA-256("frasil/skeleton-twin-commitment/v1" || self_ref(R) || twin_secret(R)
//!                          || salt)
//!
//! root_statement = "frasil/skeleton-root/v1" || field(space) || field(P0's device ID)
//!                  || field(u8(2))
//!
//! slot_ed_seed    = HKDF(none, token, "frasil/skeleton-slot/ed25519/v1")
//! slot_mldsa_seed = HKDF(none, token, "frasil/skeleton-slot/mldsa/v1")
//! info            = "frasil/skeleton-token/v1" || u16be(0x647a) || field(space) || field(c)
//!                   || u8(index) || the grantee's device ID (32)
//! sealed token    = 0x01 || u16be(0x647a) || enc || ciphertext                1,171 bytes
//!
//! enrol_statement  = "frasil/skeleton-enrol/v1" || field(space) || field(c) || u8(index)
//!                    || field(pid) || field(u8(2))
//! device_statement = "frasil/skeleton-device/v1" || field(space) || field(c) || u8(index)
//!                    || field(pid) || field(u8(2))
//! bind_key = HKDF(none, twin_secret(R), "frasil/skeleton-binding/v1")
//! aad      = "frasil/skeleton-binding/v1" || field(space) || field(c) || u8(index) || pid
//! binding  = nonce (24) || XChaCha20-Poly1305(bind_key, nonce, device_signature || device's device ID, aad)
//!
//! seniority(slot) = (height of the event that made it,
//!                    SHA-256("frasil/skeleton/seniority/v1" || space || c || u8(index)),
//!                    that event's ID)
//! ```
//!
//! `pid` is the pseudonym's device ID: a pseudonym has no X-Wing key, so its
//! `kc` hashes its ML-DSA-65 key beside an empty X-Wing key (crypto.md, "A
//! device's keys"). It commits to both of the pseudonym's keys.
//!
//! The token, the X-Wing encapsulation randomness and the binding's nonce
//! come in as arguments (the `_with` forms); a client draws them with
//! `frasil_crypto::random_bytes`.

use crate::PeersClass;
use crate::body::{GrantMap, SlotRef};
use crate::limits::{BINDING_BYTES, BINDING_NONCE_BYTES, SEALED_TOKEN_BYTES, SIGNATURE_BYTES};
use frasil_base::ErrorClass;
use frasil_base::notation::push_field;
use frasil_crypto::device::{DeviceId, HybridKeys, IdentityKey};
use frasil_crypto::labels::{
    SKELETON_BINDING, SKELETON_DEVICE, SKELETON_ENROL, SKELETON_ROOT, SKELETON_SENIORITY,
    SKELETON_SLOT_ED25519, SKELETON_SLOT_MLDSA, SKELETON_TOKEN, SKELETON_TWIN,
    SKELETON_TWIN_COMMITMENT,
};
use frasil_crypto::primitives::{hkdf, sha256, xchacha20poly1305_open, xchacha20poly1305_seal};
use frasil_crypto::schemes::{
    SCHEME_HYBRID, Scheme, Signed, Signer, ed25519_verify_strict, hybrid_ed25519_message,
    verify_mldsa_steps,
};
use frasil_crypto::sizes::{ED25519_SIGNATURE, XWING_SEED};
use frasil_crypto::wrap::{WrapLength, open_wrap, seal_wrap_with, wrap_info};
use frasil_events::EventId;
use frasil_keys::SelfRef;
use zeroize::Zeroizing;

/// `twin_secret(R) = HKDF(none, body_key(R), "frasil/skeleton-twin/v1")`.
pub fn twin_secret(body_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(None, body_key, SKELETON_TWIN)
}

/// `c(R)`, from `R`'s author (its device ID), `seq` and twin secret and the
/// twin's `salt`, never from its event ID, so that the twin can be signed
/// before `R` exists. `salt` is the 32 bytes a change carries; the root
/// carries none, so for `c(genesis)` it is empty.
pub fn twin_commitment(
    author: &DeviceId,
    seq: u64,
    twin_secret: &[u8; 32],
    salt: &[u8],
) -> [u8; 32] {
    let own = SelfRef::new(*author, seq).encode();
    sha256(&[SKELETON_TWIN_COMMITMENT, &own, twin_secret, salt])
}

/// `bind_key = HKDF(none, twin_secret(R), "frasil/skeleton-binding/v1")`.
pub fn binding_key(twin_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(None, twin_secret, SKELETON_BINDING)
}

/// `field(space) || field(c) || u8(index)`: an administrator slot in a
/// statement.
fn push_slot(out: &mut Vec<u8>, space: &EventId, slot: SlotRef) {
    push_field(out, space.as_bytes());
    push_field(out, &slot.commitment);
    out.push(slot.index);
}

/// The root statement the founder's device signs under scheme 2, naming
/// `P0` by its device ID.
pub fn root_statement(space: &EventId, pseudonym: &DeviceId) -> Vec<u8> {
    let mut out = SKELETON_ROOT.to_vec();
    push_field(&mut out, space.as_bytes());
    push_field(&mut out, &pseudonym.0);
    push_field(&mut out, &[SCHEME_HYBRID]);
    out
}

/// The enrolment statement the administrator slot's keys sign.
pub fn enrol_statement(space: &EventId, slot: SlotRef, pseudonym: &DeviceId) -> Vec<u8> {
    let mut out = SKELETON_ENROL.to_vec();
    push_slot(&mut out, space, slot);
    push_field(&mut out, &pseudonym.0);
    push_field(&mut out, &[SCHEME_HYBRID]);
    out
}

/// The device statement the grantee device signs, sealed in the binding.
pub fn device_statement(space: &EventId, slot: SlotRef, pseudonym: &DeviceId) -> Vec<u8> {
    let mut out = SKELETON_DEVICE.to_vec();
    push_slot(&mut out, space, slot);
    push_field(&mut out, &pseudonym.0);
    push_field(&mut out, &[SCHEME_HYBRID]);
    out
}

/// The binding's associated data:
/// `"frasil/skeleton-binding/v1" || field(space) || field(c) || u8(index) || pid`.
pub fn binding_aad(space: &EventId, slot: SlotRef, pseudonym: &DeviceId) -> Vec<u8> {
    let mut out = SKELETON_BINDING.to_vec();
    push_slot(&mut out, space, slot);
    out.extend_from_slice(&pseudonym.0);
    out
}

/// The slot token's wrap `info` (crypto.md, "The X-Wing wrap"): the label,
/// the suite, then `field(space) || field(c) || u8(index) || grantee`, the
/// grantee's device ID.
pub fn token_info(space: &EventId, slot: SlotRef, grantee: &DeviceId) -> Vec<u8> {
    let mut binds = Vec::with_capacity(4 + 32 + 4 + 32 + 1 + 32);
    push_slot(&mut binds, space, slot);
    binds.extend_from_slice(&grantee.0);
    wrap_info(SKELETON_TOKEN, &binds)
}

/// An administrator slot's keys, derived from its slot token.
pub struct SlotKeys {
    /// `slot_ed_seed`.
    pub ed_seed: Zeroizing<[u8; 32]>,
    /// `slot_mldsa_seed`.
    pub mldsa_seed: Zeroizing<[u8; 32]>,
    /// The signer of the two seeds: the Ed25519 key of `slot_ed_seed` and
    /// `ML-DSA.KeyGen_internal(slot_mldsa_seed)`, with no X-Wing key. A
    /// slot's keys sign no event; they are named by the slot's Ed25519 key
    /// and the SHA-256 of its ML-DSA-65 key.
    pub signer: Signer,
}

impl SlotKeys {
    /// The keys of a slot token.
    pub fn from_token(token: &[u8; 32]) -> Self {
        let ed_seed = hkdf(None, token, SKELETON_SLOT_ED25519);
        let mldsa_seed = hkdf(None, token, SKELETON_SLOT_MLDSA);
        let signer = Signer::from_seeds(&ed_seed, &mldsa_seed, None);
        Self {
            ed_seed,
            mldsa_seed,
            signer,
        }
    }

    /// The administrator slot's Ed25519 key, a grant map's `slot_ed`.
    pub fn ed_public(&self) -> &[u8; 32] {
        &self.signer.identity_key().0
    }

    /// The SHA-256 of the slot's ML-DSA-65 key, a grant map's
    /// `slot_mldsa_hash`.
    pub fn mldsa_hash(&self) -> [u8; 32] {
        sha256(&[self.signer.mldsa_public()])
    }
}

impl core::fmt::Debug for SlotKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlotKeys")
            .field("ed_public", self.ed_public())
            .finish_non_exhaustive()
    }
}

/// The grant map of an administrator slot (peers.md, "Granting an
/// administrator slot"): the slot's keys from `token`, the token sealed to
/// the grantee's X-Wing key under `eseed`, X-Wing's 64 bytes of
/// encapsulation randomness, and `rank`, the rank the roster grant gives
/// the grantee, which replicas check against it (peers.md, "What replicas
/// check", step 6).
///
/// # Errors
///
/// `InvalidKey` if the grantee's X-Wing key is refused.
pub fn grant_map_with(
    space: &EventId,
    slot: SlotRef,
    grantee: &DeviceId,
    grantee_xwing: &[u8],
    token: &[u8; 32],
    eseed: &[u8; 64],
    rank: u8,
) -> Result<GrantMap, PeersClass> {
    let keys = SlotKeys::from_token(token);
    let sealed = seal_wrap_with(
        grantee_xwing,
        &token_info(space, slot, grantee),
        token,
        eseed,
    )?;
    debug_assert_eq!(sealed.len(), SEALED_TOKEN_BYTES);
    Ok(GrantMap {
        slot_ed: *keys.ed_public(),
        slot_mldsa_hash: keys.mldsa_hash(),
        token: sealed,
        rank,
    })
}

/// The grantee's check of its token (peers.md, "Granting an administrator
/// slot"): the sealed token opens by crypto.md's "Opening a wrap" at the
/// fixed length 1,171, and its keys are the grant map's.
///
/// # Errors
///
/// `BadToken`: the grantee's client asks for a re-grant.
pub fn open_token(
    grant: &GrantMap,
    space: &EventId,
    slot: SlotRef,
    grantee: &DeviceId,
    xwing_seed: &[u8; XWING_SEED],
) -> Result<Zeroizing<[u8; 32]>, PeersClass> {
    let plain = open_wrap(
        &grant.token,
        xwing_seed,
        &token_info(space, slot, grantee),
        WrapLength::Exactly(SEALED_TOKEN_BYTES),
    )
    .map_err(|_| PeersClass::BadToken)?;
    let token: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| PeersClass::BadToken)?;
    let token = Zeroizing::new(token);
    let keys = SlotKeys::from_token(&token);
    if *keys.ed_public() != grant.slot_ed || keys.mldsa_hash() != grant.slot_mldsa_hash {
        return Err(PeersClass::BadToken);
    }
    Ok(token)
}

/// Seals a device binding under `twin_secret(R)` with a nonce given: the
/// grantee device signs `device_statement`, and the signature and the
/// device's device ID are sealed under the binding key.
pub fn seal_binding_with(
    twin_secret: &[u8; 32],
    space: &EventId,
    slot: SlotRef,
    pseudonym: &DeviceId,
    device: &Signer,
    nonce: &[u8; BINDING_NONCE_BYTES],
) -> Vec<u8> {
    let statement = device_statement(space, slot, pseudonym);
    let signature = device.sign(Scheme::Hybrid, &statement);
    let plain = Zeroizing::new([signature.as_slice(), &device.device_id().0].concat());
    let sealed = xchacha20poly1305_seal(
        &binding_key(twin_secret),
        nonce,
        &binding_aad(space, slot, pseudonym),
        &plain,
    );
    [nonce.as_slice(), &sealed].concat()
}

/// What a binding holds: the device's signature over `device_statement` and
/// the device's device ID, by which a replica finds its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The device's scheme-2 signature, 3,373 bytes.
    pub device_signature: Vec<u8>,
    /// The device's device ID.
    pub device: DeviceId,
}

/// Opens a binding (peers.md, "What replicas check", enrolments).
///
/// # Errors
///
/// `Malformed` for another length; `Decrypt` if it does not open. Either
/// makes the enrolment foreign.
pub fn open_binding(
    binding: &[u8],
    twin_secret: &[u8; 32],
    space: &EventId,
    slot: SlotRef,
    pseudonym: &DeviceId,
) -> Result<Binding, PeersClass> {
    if binding.len() != BINDING_BYTES {
        return Err(ErrorClass::Malformed.into());
    }
    let (nonce, sealed) = binding.split_at(BINDING_NONCE_BYTES);
    let nonce: &[u8; BINDING_NONCE_BYTES] = nonce.try_into().expect("24 bytes");
    let plain = xchacha20poly1305_open(
        &binding_key(twin_secret),
        nonce,
        &binding_aad(space, slot, pseudonym),
        sealed,
    )?;
    let (signature, device) = plain.split_at(SIGNATURE_BYTES);
    Ok(Binding {
        device_signature: signature.to_vec(),
        device: DeviceId(device.try_into().expect("32 bytes")),
    })
}

/// Whether a scheme-2 signature over a statement verifies in both halves:
/// the Ed25519 half under `ed`, strictly, and the ML-DSA-65 half under the
/// ML-DSA-65 key of `keys` (crypto.md, "Verifying a signature", steps 3 to
/// 6). The caller took `keys` by the hash that names the signer.
pub fn verify_hybrid(
    ed: &IdentityKey,
    keys: &HybridKeys,
    message: &[u8],
    signature: &[u8],
) -> bool {
    if signature.len() != SIGNATURE_BYTES {
        return false;
    }
    let ed_half = ed25519_verify_strict(
        &ed.0,
        &hybrid_ed25519_message(ed, message),
        &signature[..ED25519_SIGNATURE],
    );
    ed_half
        && verify_mldsa_steps(
            &Signed {
                scheme: u64::from(SCHEME_HYBRID),
                ed,
                kc: keys.commitment(),
                tbs: message,
                signature,
            },
            Some(keys),
        )
        .is_ok()
}

/// [`verify_hybrid`] under an administrator slot's keys: its Ed25519 key and
/// an ML-DSA-65 key of 1,952 bytes. False for another length.
pub fn verify_slot(ed: &[u8; 32], mldsa: &[u8], message: &[u8], signature: &[u8]) -> bool {
    HybridKeys::new(mldsa, None)
        .is_ok_and(|keys| verify_hybrid(&IdentityKey(*ed), &keys, message, signature))
}

/// An administrator slot's seniority, smallest first: `(epoch, height of the
/// event that made it, SHA-256("frasil/skeleton/seniority/v1" || space || c
/// || u8(index)), that event's ID)`. The epoch is that of the skeleton's
/// world the slot was made in, 0 before any cut, and the height counts from
/// that world's root (peers.md, "Skeleton cuts").
pub type Seniority = (u64, u64, [u8; 32], EventId);

/// The seniority of an administrator slot made by `creator` at `height`,
/// before any cut.
pub fn seniority(space: &EventId, slot: SlotRef, creator: EventId, height: u64) -> Seniority {
    seniority_in(0, space, slot, creator, height)
}

/// The seniority of an administrator slot made by `creator` at `height` in
/// the world of epoch `epoch`.
pub fn seniority_in(
    epoch: u64,
    space: &EventId,
    slot: SlotRef,
    creator: EventId,
    height: u64,
) -> Seniority {
    let hash = sha256(&[
        SKELETON_SENIORITY,
        space.as_bytes(),
        &slot.commitment,
        &[slot.index],
    ]);
    (epoch, height, hash, creator)
}
