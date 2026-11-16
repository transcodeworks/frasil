//! Invite links (ext-invite-links.md, feature `ext-invite-links`): the
//! secret, its keys and the link, the drop, and the claimant's checks.
//!
//! ```text
//! seed(info)     = HKDF(salt = "frasil/invite/v1", ikm = secret, info)
//! Ed25519 seed   = seed("ed25519")
//! K              = the device ID of the three public keys (crypto.md)
//! X-Wing seed    = seed("frasil/invite/hybrid/v1")
//! ML-DSA-65 seed = seed("frasil/invite/mldsa/v1")
//! locator        = seed("frasil/invite/locator/v1")
//! drop key       = seed("frasil/invite/drop/v1")
//!
//! fragment = base64url, without padding, of
//!            u8(1) || secret (32) || invite entry (32) || space ID (32)    97 bytes
//!
//! plaintext = CBOR {1: 1, 2: key name (bytes), 3: grant key name (bytes; empty if none),
//!                   4: K's bundle wrap in the invite entry (1,236),
//!                   5: [peer hints: 0 to 8 texts of 1 to 512 bytes],
//!                   6: snapshot locator (64; optional)}
//! drop      = nonce (24 random bytes)
//!             || XChaCha20-Poly1305(drop key, nonce, plaintext,
//!                                   aad = "frasil/invite/drop/v1" || locator)
//! ```
//!
//! Reading a fragment, in order: base64url characters only, and bytes that
//! re-encode to the same text (`Malformed`); byte 0 present and 1
//! (`UnsupportedVersion`); 97 bytes (`Malformed`). Opening a drop, in
//! order: 40 to 65,536 bytes (`Malformed`); the AEAD opens (`Decrypt`); the
//! map reads (`Malformed`); key 1 is 1 (`UnsupportedVersion`).
//!
//! The claimant's walk ("Claiming") runs over these: [`read_fragment`]
//! (step 1), [`open_drop`] (step 2), [`open_drop_wrap`] (step 3),
//! [`check_invite_entry`] (step 5), and [`check_claimable`] (steps 6, 7
//! and 9) over the resolved roster; step 10 is
//! `frasil_space::ext_invite_links::check_claim_expiry`. The invite grant
//! and the successor are `frasil_space::ext_invite_links`'s; the drop's
//! messages `frasil_transport::ext_invite_links`'.

use crate::{hints_value, read_hints, read_map};
use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_crypto::device::{DeviceId, DeviceKeys, IdentityKey};
use frasil_crypto::labels;
use frasil_crypto::primitives::{
    ed25519_public, hkdf, xchacha20poly1305_open, xchacha20poly1305_seal,
};
use frasil_crypto::schemes::Signer;
use frasil_crypto::sizes::XWING_PUBLIC;
use frasil_crypto::wrap::xwing_public;
use frasil_events::{Event, EventId};
use frasil_keys::KeyName;
use frasil_keys::body::VisiblePart;
use frasil_keys::bundle::Bundle;
use frasil_keys::derive::body_key;
use frasil_keys::limits::WRAP_BYTES;
use frasil_keys::wraps::{find_own_wrap, open_bundle_wrap};
use frasil_space::change::Op;
use frasil_space::ext_invite_links::{InviteClass, invite_member, is_successor};
use frasil_space::keygraph::take_slots;
use frasil_space::{MemberType, Space, Standing};
use zeroize::Zeroizing;

/// The link's format version, byte 0 of the fragment.
pub const LINK_VERSION: u8 = 1;
/// The fragment's bytes.
pub const LINK_BYTES: usize = 97;
/// The fragment's characters.
pub const LINK_CHARACTERS: usize = 130;
/// The drop's format version, key 1 of its plaintext.
pub const DROP_VERSION: u64 = 1;
/// The fewest bytes of a drop: its nonce and the AEAD's tag.
pub const DROP_MIN_BYTES: usize = 40;
/// The most bytes of a drop.
pub const DROP_MAX_BYTES: usize = 65_536;
/// A drop's nonce.
pub const DROP_NONCE_BYTES: usize = 24;

/// `seed(info) = HKDF(salt = "frasil/invite/v1", ikm = secret, info)`.
pub fn invite_seed(secret: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    hkdf(Some(labels::INVITE), secret, info)
}

/// The drop's locator, `seed("frasil/invite/locator/v1")`.
pub fn locator(secret: &[u8; 32]) -> [u8; 32] {
    *invite_seed(secret, labels::INVITE_LOCATOR)
}

/// The drop key, `seed("frasil/invite/drop/v1")`.
pub fn drop_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    invite_seed(secret, labels::INVITE_DROP)
}

/// The drop's address: mailbox kind 4, named by the locator.
pub fn drop_address(secret: &[u8; 32]) -> [u8; 32] {
    frasil_transport::ext_invite_links::drop_address(&locator(secret))
}

/// The invite key `K` a secret derives: its Ed25519, X-Wing and ML-DSA-65
/// keys. An invite key has no X25519 key.
pub struct InviteKeys {
    /// The Ed25519 seed, `seed("ed25519")`.
    pub identity_seed: Zeroizing<[u8; 32]>,
    /// The X-Wing seed, `seed("frasil/invite/hybrid/v1")`.
    pub xwing_seed: Zeroizing<[u8; 32]>,
    /// The ML-DSA-65 seed, `seed("frasil/invite/mldsa/v1")`.
    pub mldsa_seed: Zeroizing<[u8; 32]>,
    /// The X-Wing public key.
    pub xwing: Box<[u8; XWING_PUBLIC]>,
    /// The invite key's signer, Ed25519 and ML-DSA-65, with its X-Wing key.
    pub signer: Signer,
}

impl core::fmt::Debug for InviteKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InviteKeys")
            .field("device_id", &self.device_id())
            .finish_non_exhaustive()
    }
}

impl InviteKeys {
    /// The keys a link's secret derives.
    pub fn derive(secret: &[u8; 32]) -> Self {
        let identity_seed = invite_seed(secret, frasil_identity::recovery::IDENTITY_INFO);
        let xwing_seed = invite_seed(secret, labels::INVITE_HYBRID);
        let mldsa_seed = invite_seed(secret, labels::INVITE_MLDSA);
        let xwing = Box::new(xwing_public(&xwing_seed));
        let signer = Signer::from_seeds(&identity_seed, &mldsa_seed, Some(&xwing));
        debug_assert_eq!(signer.identity_key().0, ed25519_public(&identity_seed));
        Self {
            xwing,
            identity_seed,
            xwing_seed,
            mldsa_seed,
            signer,
        }
    }

    /// `K`: the device ID of the invite key's three public keys (crypto.md,
    /// "A device's keys").
    pub fn device_id(&self) -> DeviceId {
        *self.signer.device_id()
    }

    /// The invite key's Ed25519 key, which signs its successor.
    pub fn identity_key(&self) -> IdentityKey {
        *self.signer.identity_key()
    }

    /// The invite key's three public keys, which give `K`, as the invite
    /// grant carries them (keys 9, 10 and 12).
    pub fn device_keys(&self) -> DeviceKeys {
        DeviceKeys {
            ed: self.identity_key(),
            keys: self.signer.keys().clone(),
        }
    }
}

// -- The link

/// What a link's fragment carries.
#[derive(Clone, PartialEq, Eq)]
pub struct Link {
    /// The secret.
    pub secret: Zeroizing<[u8; 32]>,
    /// The invite entry: the invite grant's event ID.
    pub entry: EventId,
    /// The space ID.
    pub space: EventId,
}

impl core::fmt::Debug for Link {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Link")
            .field("entry", &self.entry)
            .field("space", &self.space)
            .finish_non_exhaustive()
    }
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url, without padding.
fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            let index = (n >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(BASE64URL[index as usize]));
        }
    }
    out
}

/// Decodes base64url without padding; `None` for any other character or a
/// length no encoding has.
fn from_base64url(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for ch in text.bytes() {
        let value = BASE64URL.iter().position(|&c| c == ch)?;
        bits = (bits << 6) | u32::try_from(value).ok()?;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// The fragment of a link: base64url, without padding, of `u8(1) ||
/// secret || invite entry || space ID`, 130 characters. It follows `#` in
/// a link whose base the application chooses.
pub fn link_fragment(secret: &[u8; 32], entry: &EventId, space: &EventId) -> String {
    let mut raw = Vec::with_capacity(LINK_BYTES);
    raw.push(LINK_VERSION);
    raw.extend_from_slice(secret);
    raw.extend_from_slice(entry.as_bytes());
    raw.extend_from_slice(space.as_bytes());
    base64url(&raw)
}

/// Reads a fragment, in the module's order ("Claiming", step 1).
///
/// # Errors
///
/// `Malformed` or `UnsupportedVersion`.
pub fn read_fragment(text: &str) -> Result<Link, ErrorClass> {
    let raw = from_base64url(text).ok_or(ErrorClass::Malformed)?;
    if raw.is_empty() || base64url(&raw) != text {
        return Err(ErrorClass::Malformed);
    }
    if raw[0] != LINK_VERSION {
        return Err(ErrorClass::UnsupportedVersion);
    }
    if raw.len() != LINK_BYTES {
        return Err(ErrorClass::Malformed);
    }
    let part = |range: core::ops::Range<usize>| -> [u8; 32] {
        let mut out = [0; 32];
        out.copy_from_slice(&raw[range]);
        out
    };
    Ok(Link {
        secret: Zeroizing::new(part(1..33)),
        entry: EventId(part(33..65)),
        space: EventId(part(65..97)),
    })
}

// -- The drop

/// What a drop's plaintext carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropPlain {
    /// Key 2: the key name of the invite entry's delivery.
    pub key_name: Vec<u8>,
    /// Key 3: its grant key name, empty if none.
    pub grant_key_name: Vec<u8>,
    /// Key 4: `K`'s bundle wrap in the invite entry, 1,236 bytes.
    pub wrap: Vec<u8>,
    /// Key 5: peer hints, as in a welcome.
    pub peers: Vec<String>,
    /// Key 6: the locator of the snapshot for `K` (admission.md, "The
    /// newcomer's snapshot"), when the invite publishes one.
    pub snapshot: Option<[u8; 64]>,
}

impl DropPlain {
    /// The plaintext's one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(DROP_VERSION));
        map.insert(2, Value::from(self.key_name.as_slice()));
        map.insert(3, Value::from(self.grant_key_name.as_slice()));
        map.insert(4, Value::from(self.wrap.as_slice()));
        map.insert(5, hints_value(&self.peers));
        if let Some(snapshot) = &self.snapshot {
            map.insert(6, Value::from(&snapshot[..]));
        }
        Value::Map(map).encode()
    }
}

/// The drop an inviting device places for its invite entry: the invite
/// key's own wrap, which it finds among the entry's deliveries by trial
/// decryption, under that delivery's key names, with peer hints and no
/// snapshot, which the inviter names once it has published one. A drop
/// carries only the invite key's wrap.
///
/// # Errors
///
/// `NoWrap` when no delivery of the entry wraps for `K`.
pub fn invite_drop(
    event: &Event,
    keys: &InviteKeys,
    peers: Vec<String>,
) -> Result<DropPlain, InviteClass> {
    let visible = VisiblePart::read(event.unverified_body(), event.author(), event.seq())
        .map_err(|_| InviteClass::NoWrap)?;
    let space = event.log_id();
    visible
        .deliveries
        .iter()
        .find_map(|d| {
            let (index, _) = find_own_wrap(
                &d.wraps,
                space.as_bytes(),
                d.key_name.as_ref(),
                d.grant_name.as_ref(),
                &keys.device_id(),
                &keys.xwing_seed,
            )?;
            Some(DropPlain {
                key_name: d.key_name.as_ref().map(KeyName::encode).unwrap_or_default(),
                grant_key_name: d
                    .grant_name
                    .as_ref()
                    .map(KeyName::encode)
                    .unwrap_or_default(),
                wrap: d.wraps[index].clone(),
                peers: peers.clone(),
                snapshot: None,
            })
        })
        .ok_or(InviteClass::NoWrap)
}

/// The drop's associated data: `"frasil/invite/drop/v1" || locator`.
pub fn drop_aad(secret: &[u8; 32]) -> Vec<u8> {
    [labels::INVITE_DROP, &locator(secret)[..]].concat()
}

/// Seals a drop under the link's secret, with its 24-byte nonce given.
pub fn seal_drop_with(
    secret: &[u8; 32],
    plaintext: &[u8],
    nonce: &[u8; DROP_NONCE_BYTES],
) -> Vec<u8> {
    let sealed = xchacha20poly1305_seal(&drop_key(secret), nonce, &drop_aad(secret), plaintext);
    [&nonce[..], &sealed].concat()
}

/// Opens a drop, in the module's order ("Claiming", step 2).
///
/// # Errors
///
/// `Malformed`, `Decrypt` or `UnsupportedVersion`.
pub fn open_drop(secret: &[u8; 32], drop: &[u8]) -> Result<DropPlain, ErrorClass> {
    if !(DROP_MIN_BYTES..=DROP_MAX_BYTES).contains(&drop.len()) {
        return Err(ErrorClass::Malformed);
    }
    let (nonce, sealed) = drop.split_at(DROP_NONCE_BYTES);
    let nonce: [u8; DROP_NONCE_BYTES] = nonce.try_into().map_err(|_| ErrorClass::Malformed)?;
    let plain = xchacha20poly1305_open(&drop_key(secret), &nonce, &drop_aad(secret), sealed)
        .map_err(|_| ErrorClass::Decrypt)?;
    let map = read_map(&plain, &[1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5])
        .map_err(|_| ErrorClass::Malformed)?;
    if map[&1].as_unsigned().ok() != Some(DROP_VERSION) {
        return Err(ErrorClass::UnsupportedVersion);
    }
    let bytes = |key: u64| -> Result<Vec<u8>, ErrorClass> {
        Ok(map[&key]
            .as_bytes()
            .map_err(|_| ErrorClass::Malformed)?
            .to_vec())
    };
    let key_name = bytes(2)?;
    let grant_key_name = bytes(3)?;
    let wrap = bytes(4)?;
    if key_name.is_empty() || wrap.len() != WRAP_BYTES {
        return Err(ErrorClass::Malformed);
    }
    let peers = read_hints(&map[&5]).map_err(|_| ErrorClass::Malformed)?;
    let snapshot = match map.get(&6) {
        None => None,
        Some(value) => Some(
            value
                .as_bytes()
                .ok()
                .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
                .ok_or(ErrorClass::Malformed)?,
        ),
    };
    Ok(DropPlain {
        key_name,
        grant_key_name,
        wrap,
        peers,
        snapshot,
    })
}

/// A drop's key names, read whole: the key name, and the grant key name
/// unless it is empty.
fn names(plain: &DropPlain) -> Option<(KeyName, Option<KeyName>)> {
    let whole = |bytes: &[u8]| match KeyName::read(bytes, true) {
        Ok((name, [])) => Some(name),
        _ => None,
    };
    let key = whole(&plain.key_name)?;
    let grant = if plain.grant_key_name.is_empty() {
        None
    } else {
        Some(whole(&plain.grant_key_name)?)
    };
    Some((key, grant))
}

/// "Claiming", step 3: the drop's wrap opens with `K`'s X-Wing seed, for
/// the space ID, the drop's key names and recipient `K`, the invite key's
/// device ID (keys.md).
///
/// # Errors
///
/// `NoWrap`.
pub fn open_drop_wrap(
    plain: &DropPlain,
    space: &EventId,
    keys: &InviteKeys,
) -> Result<Bundle, InviteClass> {
    let (key, grant) = names(plain).ok_or(InviteClass::NoWrap)?;
    open_bundle_wrap(
        &plain.wrap,
        space.as_bytes(),
        Some(&key),
        grant.as_ref(),
        &keys.device_id(),
        &keys.xwing_seed,
    )
    .map_err(|_| InviteClass::NoWrap)
}

/// "Claiming", step 5, on the fetched invite entry: it is of the space's
/// log, a delivery of it holds the drop's wrap under the drop's key names,
/// and the bundle matches its rotations' commitments (keys.md, "Taking a
/// key").
///
/// An invite "from now on" rotates, and its delivery names the entry's own
/// rotation; any other invite need not rotate, and delivers the state its
/// inviter held, whose rotation commits to the bundle. `rotation` gives the
/// event of a rotation the key name names other than the entry, from the
/// space's log. A merged state's key is received whole, and no rotation
/// commits to it: it is provisional (keys.md, "Taking a key").
///
/// # Errors
///
/// `WrongInvite`.
pub fn check_invite_entry<'a>(
    event: &Event,
    space: &EventId,
    plain: &DropPlain,
    bundle: &Bundle,
    rotation: impl FnOnce(&EventId) -> Option<&'a Event>,
) -> Result<(), InviteClass> {
    let wrong = InviteClass::WrongInvite;
    if event.is_genesis() || event.log_id() != *space {
        return Err(wrong);
    }
    let visible = VisiblePart::read(event.unverified_body(), event.author(), event.seq())
        .map_err(|_| wrong)?;
    let (key, grant) = names(plain).ok_or(wrong)?;
    let delivered = visible.deliveries.iter().any(|d| {
        d.key_name.as_ref() == Some(&key)
            && d.grant_name.as_ref() == grant.as_ref()
            && d.wraps.contains(&plain.wrap)
    });
    let content = bundle.content().ok_or(wrong)?;
    if !delivered {
        return Err(wrong);
    }
    // The rotation that commits to the bundle's slots.
    let committing = match &key {
        KeyName::SelfRef(_) => event,
        KeyName::Set(set) if set.ids() == [event.id()] => event,
        KeyName::Set(set) => match set.ids() {
            [one] => rotation(one).ok_or(wrong)?,
            _ => return Ok(()),
        },
    };
    // The genesis is a rotation of its own log too.
    if committing.log_id() != *space {
        return Err(wrong);
    }
    let rotates = if core::ptr::eq(committing, event) {
        visible
    } else {
        VisiblePart::read(
            committing.unverified_body(),
            committing.author(),
            committing.seq(),
        )
        .map_err(|_| wrong)?
    };
    let keys = rotates.rotation().ok_or(wrong)?;
    // The sealed part says whether the rotation is a break, which the
    // grant seed's commitment binds. A genesis binds its nonce in place of
    // its log (keys.md).
    let log: Vec<u8> = match rotates.nonce {
        Some(nonce) => nonce.to_vec(),
        None => space.as_bytes().to_vec(),
    };
    let body = body_key(content, &log, committing.author(), committing.seq());
    let inner = rotates
        .open(&body, &log, committing.author(), committing.seq())
        .map_err(|_| wrong)?;
    let taken = take_slots(bundle, keys, inner.is_break);
    if !taken.dropped.is_empty() || taken.content.is_none() {
        return Err(wrong);
    }
    Ok(())
}

/// "Claiming", steps 6, 7 and 9, over the space resolved with the
/// snapshot's body keys: the invite entry is valid, it grants exactly one
/// invite key, `K`, and the invite is still open.
///
/// # Errors
///
/// `NotInRoster`, `WrongInvite`, then `InviteUsed` (a valid successor of
/// `K` is held, whether or not a close removed `K` since), `InviteRevoked`
/// (a valid removal of `K` with no valid successor) or `InviteRaced` (`K`
/// is in, but its chain forked).
pub fn check_claimable(
    space: &Space<'_>,
    entry: EventId,
    key: &DeviceId,
) -> Result<(), InviteClass> {
    // 6.
    if !space.view().contains(&entry) || !space.is_roster(entry) || !space.is_valid(entry) {
        return Err(InviteClass::NotInRoster);
    }
    // 7.
    let changes = space.opened(entry).map_or(&[][..], |o| o.changes());
    let granted: Vec<_> = changes
        .iter()
        .filter(|c| c.op == Op::Grant && c.member.is_some_and(|m| m.kind == MemberType::Invite))
        .filter_map(|c| c.member)
        .collect();
    if granted != [invite_member(key.0)] {
        return Err(InviteClass::WrongInvite);
    }
    // 9, in its order: a valid successor of K makes the invite used, even
    // once a close removed K; then a valid removal; then a raced claim.
    let standing = space
        .roster()
        .standing(&invite_member(key.0))
        .ok_or(InviteClass::NotInRoster)?;
    let used = space.view().iter().any(|&id| {
        space.is_valid(id)
            && space.log().event(id).is_some_and(|e| e.author() == key)
            && space.opened(id).is_some_and(|o| is_successor(o.changes()))
    });
    if used {
        return Err(InviteClass::InviteUsed);
    }
    match standing {
        Standing::Out { .. } => Err(InviteClass::InviteRevoked),
        Standing::In(_) if space.forks().fork_point(key).is_some() => Err(InviteClass::InviteRaced),
        Standing::In(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips() {
        for len in 0..10 {
            let bytes: Vec<u8> = (0..len).map(|i: u8| i.wrapping_mul(37)).collect();
            let text = base64url(&bytes);
            assert!(!text.contains('='));
            assert_eq!(from_base64url(&text), Some(bytes));
        }
        assert_eq!(base64url(b"\xfb\xff"), "-_8");
        assert_eq!(from_base64url("a"), None);
        assert_eq!(from_base64url("a+"), None);
    }

    #[test]
    fn a_fragment_reads_back() {
        let text = link_fragment(&[1; 32], &EventId([2; 32]), &EventId([3; 32]));
        assert_eq!(text.len(), LINK_CHARACTERS);
        let link = read_fragment(&text).unwrap();
        assert_eq!(*link.secret, [1; 32]);
        assert_eq!(link.entry, EventId([2; 32]));
        assert_eq!(link.space, EventId([3; 32]));
        assert_eq!(read_fragment(""), Err(ErrorClass::Malformed));
    }

    #[test]
    fn a_drop_opens_under_its_secret_only() {
        let plain = DropPlain {
            key_name: vec![1; 33],
            grant_key_name: Vec::new(),
            wrap: vec![0; WRAP_BYTES],
            peers: vec!["https://peer.example".into()],
            snapshot: None,
        };
        let drop = seal_drop_with(&[5; 32], &plain.encode(), &[6; 24]);
        assert_eq!(open_drop(&[5; 32], &drop), Ok(plain.clone()));
        assert_eq!(open_drop(&[4; 32], &drop), Err(ErrorClass::Decrypt));
        // Key 6 names the snapshot for K.
        let named = DropPlain {
            snapshot: Some([7; 64]),
            ..plain
        };
        let drop = seal_drop_with(&[5; 32], &named.encode(), &[6; 24]);
        assert_eq!(open_drop(&[5; 32], &drop), Ok(named));
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(DROP_VERSION));
        map.insert(2, Value::from(&[1u8; 33][..]));
        map.insert(3, Value::from(&[][..]));
        map.insert(4, Value::from(&[0u8; WRAP_BYTES][..]));
        map.insert(5, Value::Array(Vec::new()));
        map.insert(6, Value::from(&[7u8; 63][..]));
        let drop = seal_drop_with(&[5; 32], &Value::Map(map).encode(), &[6; 24]);
        assert_eq!(open_drop(&[5; 32], &drop), Err(ErrorClass::Malformed));
    }
}
