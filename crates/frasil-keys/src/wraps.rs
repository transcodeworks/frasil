//! Bundle wraps, space wraps and removal wraps (keys.md, "Bundle wraps,
//! space wraps and removal wraps"), and trial decryption ("Reading key
//! names, bundles, wraps and links").
//!
//! All three use crypto.md's wrap layout: 97 bytes of plaintext in a wrap
//! of 1,236 bytes. None names its recipient.
//!
//! ```text
//! bundle wrap:
//! info = "frasil/bundle-wrap/v1" || u16be(suite) || log
//!        || field(key name or empty) || field(grant key name or empty)
//!        || recipient's device ID
//! sealed to the recipient device's X-Wing key
//!
//! space wrap:
//! info = "frasil/space-wrap/v1" || u16be(suite) || log
//!        || field(key name or empty) || field(grant key name or empty)
//!        || granted space ID || grantee rotation
//! sealed to grant_public({grantee rotation}) of the granted space
//!
//! removal wrap:
//! info    = "frasil/removal-wrap/v1" || u16be(suite) || log
//!           || field(key name) || field(grant key name or empty)
//!           || recipient's device ID
//! removal = 0x08 || body key (32) || 64 zero bytes
//! sealed to the recipient device's X-Wing key
//! ```

use crate::KeyClass;
use crate::bundle::Bundle;
use crate::limits::{BUNDLE_BYTES, WRAP_BYTES};
use crate::names::KeyName;
use frasil_base::ErrorClass;
use frasil_base::notation::push_field;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_crypto::wrap::{self, ENCAPSULATION_RANDOMNESS, WrapLength, WrapUse};
use frasil_events::EventId;
use zeroize::Zeroizing;

/// The first byte of a removal wrap's plaintext.
pub const REMOVAL_FLAG: u8 = 0x08;

/// The length of every bundle wrap and space wrap.
pub const LENGTH: WrapLength = WrapLength::Exactly(WRAP_BYTES);

fn push_names(binds: &mut Vec<u8>, key_name: Option<&KeyName>, grant_name: Option<&KeyName>) {
    for name in [key_name, grant_name] {
        push_field(binds, &name.map(KeyName::encode).unwrap_or_default());
    }
}

/// A bundle wrap's `info`, for a delivery's names and its recipient's
/// device ID.
pub fn bundle_wrap_info(
    log: &[u8],
    key_name: Option<&KeyName>,
    grant_name: Option<&KeyName>,
    recipient: &DeviceId,
) -> Vec<u8> {
    let mut binds = Vec::new();
    push_field(&mut binds, log);
    push_names(&mut binds, key_name, grant_name);
    binds.extend_from_slice(&recipient.0);
    WrapUse::BundleWrap.info(&binds)
}

/// A space wrap's `info`, for a delivery's names, the granted space and its
/// grantee rotation.
pub fn space_wrap_info(
    log: &[u8],
    key_name: Option<&KeyName>,
    grant_name: Option<&KeyName>,
    grantee: &EventId,
    grantee_rotation: &EventId,
) -> Vec<u8> {
    let mut binds = Vec::new();
    push_field(&mut binds, log);
    push_names(&mut binds, key_name, grant_name);
    binds.extend_from_slice(grantee.as_bytes());
    binds.extend_from_slice(grantee_rotation.as_bytes());
    WrapUse::SpaceWrap.info(&binds)
}

/// Seals a bundle to one device's X-Wing key, with X-Wing's 64 bytes of
/// encapsulation randomness given. `recipient_xwing` is the X-Wing key the
/// recipient's device ID commits to (keys.md, "Which X-Wing key"), taken by
/// its hash from any source and checked where it entered;
/// [`seal_bundle_wrap_to`] takes both from the recipient's keys.
///
/// # Errors
///
/// `Malformed` for a bundle its delivery's names do not admit (the content
/// key exactly when a state is named, a grant seed only when a grant state
/// is); `InvalidKey` for a key X-Wing refuses.
pub fn seal_bundle_wrap_with(
    log: &[u8],
    key_name: Option<&KeyName>,
    grant_name: Option<&KeyName>,
    recipient: &DeviceId,
    recipient_xwing: &[u8],
    bundle: &Bundle,
    encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<Vec<u8>, KeyClass> {
    bundle.check_names(key_name.is_some(), grant_name.is_some())?;
    let info = bundle_wrap_info(log, key_name, grant_name, recipient);
    Ok(wrap::seal_wrap_with(
        recipient_xwing,
        &info,
        &bundle.encode()[..],
        encapsulation_randomness,
    )?)
}

/// [`seal_bundle_wrap_with`] for the holder of `recipient`'s keys: the
/// `info` binds their device ID, and the wrap seals to their X-Wing key,
/// which they commit to (crypto.md, section 2.4, "Which key").
///
/// # Errors
///
/// `InvalidKey` for keys with no X-Wing key, which receive no wrap; then as
/// [`seal_bundle_wrap_with`].
pub fn seal_bundle_wrap_to(
    log: &[u8],
    key_name: Option<&KeyName>,
    grant_name: Option<&KeyName>,
    recipient: &DeviceKeys,
    bundle: &Bundle,
    encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<Vec<u8>, KeyClass> {
    let xwing = recipient
        .keys
        .xwing()
        .ok_or(KeyClass::Shared(ErrorClass::InvalidKey))?;
    seal_bundle_wrap_with(
        log,
        key_name,
        grant_name,
        &recipient.device_id(),
        xwing,
        bundle,
        encapsulation_randomness,
    )
}

/// Seals a bundle to a granted space's grant key, `grant_public({grantee
/// rotation})`, with X-Wing's 64 bytes of encapsulation randomness given.
///
/// # Errors
///
/// As [`seal_bundle_wrap_with`].
#[allow(clippy::too_many_arguments)]
pub fn seal_space_wrap_with(
    log: &[u8],
    key_name: Option<&KeyName>,
    grant_name: Option<&KeyName>,
    grantee: &EventId,
    grantee_rotation: &EventId,
    grant_public: &[u8],
    bundle: &Bundle,
    encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<Vec<u8>, KeyClass> {
    bundle.check_names(key_name.is_some(), grant_name.is_some())?;
    let info = space_wrap_info(log, key_name, grant_name, grantee, grantee_rotation);
    Ok(wrap::seal_wrap_with(
        grant_public,
        &info,
        &bundle.encode()[..],
        encapsulation_randomness,
    )?)
}

/// A wrap's layout with no key: crypto.md's `open_wrap`, steps 1 to 5, at
/// 1,236 bytes. A peer checks this much of every wrap in a delivery.
///
/// # Errors
///
/// `Malformed` or `UnsupportedVersion`, as crypto.md's steps say.
pub fn read_wrap(wrap: &[u8]) -> Result<(), KeyClass> {
    wrap::read_wrap(wrap, LENGTH)?;
    Ok(())
}

fn take(
    wrap: &[u8],
    seed: &[u8; 32],
    info: &[u8],
    names_state: bool,
    names_grant_state: bool,
) -> Result<Bundle, KeyClass> {
    let plaintext = wrap::open_wrap(wrap, seed, info, LENGTH)?;
    let bundle = Bundle::read(&plaintext)?;
    bundle.check_names(names_state, names_grant_state)?;
    Ok(bundle)
}

/// Opens a bundle wrap (keys.md, section 3.1): crypto.md's `open_wrap` at
/// 1,236 bytes under the opener's X-Wing seed and the info for the
/// delivery's names and the opener's device ID; then the bundle reads,
/// holds the content key exactly when the delivery names a state, and holds
/// a grant seed only when it names a grant state.
///
/// # Errors
///
/// `open_wrap`'s classes (`Decrypt` for a wrap meant for another), then
/// `Malformed`.
pub fn open_bundle_wrap(
    wrap: &[u8],
    log: &[u8],
    key_name: Option<&KeyName>,
    grant_name: Option<&KeyName>,
    device: &DeviceId,
    xwing_seed: &[u8; 32],
) -> Result<Bundle, KeyClass> {
    let info = bundle_wrap_info(log, key_name, grant_name, device);
    take(
        wrap,
        xwing_seed,
        &info,
        key_name.is_some(),
        grant_name.is_some(),
    )
}

/// Opens a space wrap, as [`open_bundle_wrap`], under
/// `xwing_seed({grantee rotation})` and the info naming the opener's space
/// and that rotation.
///
/// # Errors
///
/// As [`open_bundle_wrap`].
pub fn open_space_wrap(
    wrap: &[u8],
    log: &[u8],
    key_name: Option<&KeyName>,
    grant_name: Option<&KeyName>,
    grantee: &EventId,
    grantee_rotation: &EventId,
    grant_xwing_seed: &[u8; 32],
) -> Result<Bundle, KeyClass> {
    let info = space_wrap_info(log, key_name, grant_name, grantee, grantee_rotation);
    take(
        wrap,
        grant_xwing_seed,
        &info,
        key_name.is_some(),
        grant_name.is_some(),
    )
}

/// Trial decryption: a device tries a delivery's bundle wraps with its
/// X-Wing seed and an info naming itself, and stops at the first that
/// opens. Returns that wrap's index and bundle, or `None` when none opens.
///
/// Whether a device tries a delivery at all (its named rotations are events
/// of the log it holds, and it lacks a named state it is entitled to) is the
/// key graph's decision.
pub fn find_own_wrap<W: AsRef<[u8]>>(
    wraps: &[W],
    log: &[u8],
    key_name: Option<&KeyName>,
    grant_name: Option<&KeyName>,
    device: &DeviceId,
    xwing_seed: &[u8; 32],
) -> Option<(usize, Bundle)> {
    let info = bundle_wrap_info(log, key_name, grant_name, device);
    wraps.iter().enumerate().find_map(|(index, wrap)| {
        take(
            wrap.as_ref(),
            xwing_seed,
            &info,
            key_name.is_some(),
            grant_name.is_some(),
        )
        .ok()
        .map(|bundle| (index, bundle))
    })
}

/// A removal wrap's `info`, for its delivery's names and its recipient's
/// device ID.
pub fn removal_wrap_info(
    log: &[u8],
    key_name: &KeyName,
    grant_name: Option<&KeyName>,
    recipient: &DeviceId,
) -> Vec<u8> {
    let mut binds = Vec::new();
    push_field(&mut binds, log);
    push_names(&mut binds, Some(key_name), grant_name);
    binds.extend_from_slice(&recipient.0);
    WrapUse::RemovalWrap.info(&binds)
}

/// A removal wrap's plaintext: `0x08 || body key || 64 zero bytes`.
pub fn removal_plaintext(body_key: &[u8; 32]) -> Zeroizing<[u8; BUNDLE_BYTES]> {
    let mut out = Zeroizing::new([0; BUNDLE_BYTES]);
    out[0] = REMOVAL_FLAG;
    out[1..33].copy_from_slice(body_key);
    out
}

/// Seals a rotation's body key to a device its roster changes remove, with
/// X-Wing's 64 bytes of encapsulation randomness given. The wrap goes among
/// the bundle wraps of the rotation's own delivery, whose names it binds.
///
/// # Errors
///
/// `InvalidKey` for a key X-Wing refuses.
pub fn seal_removal_wrap_with(
    log: &[u8],
    key_name: &KeyName,
    grant_name: Option<&KeyName>,
    recipient: &DeviceId,
    recipient_xwing: &[u8],
    body_key: &[u8; 32],
    encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<Vec<u8>, KeyClass> {
    let info = removal_wrap_info(log, key_name, grant_name, recipient);
    Ok(wrap::seal_wrap_with(
        recipient_xwing,
        &info,
        &removal_plaintext(body_key)[..],
        encapsulation_randomness,
    )?)
}

/// Opens a removal wrap (keys.md, section 3.1): crypto.md's `open_wrap` at
/// 1,236 bytes under the opener's X-Wing seed and the removal-wrap info for
/// the delivery's names and the opener's device ID; then the plaintext's
/// first byte is `0x08` and its tail zero; then the body key's commitment is
/// the carrying event's `commitment`. The key is a body key handed over:
/// provisional.
///
/// # Errors
///
/// `open_wrap`'s classes (`Decrypt` for a wrap meant for another, and for
/// a bundle wrap), then `Malformed`, then `KeyMismatch`.
pub fn open_removal_wrap(
    wrap: &[u8],
    log: &[u8],
    key_name: &KeyName,
    grant_name: Option<&KeyName>,
    device: &DeviceId,
    xwing_seed: &[u8; 32],
    commitment: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, KeyClass> {
    let info = removal_wrap_info(log, key_name, grant_name, device);
    let plaintext = wrap::open_wrap(wrap, xwing_seed, &info, LENGTH)?;
    if plaintext.len() != BUNDLE_BYTES
        || plaintext[0] != REMOVAL_FLAG
        || plaintext[33..].iter().any(|&b| b != 0)
    {
        return Err(KeyClass::from(frasil_base::ErrorClass::Malformed));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&plaintext[1..33]);
    if crate::derive::body_commitment(&key) != *commitment {
        return Err(KeyClass::KeyMismatch);
    }
    Ok(key)
}

/// Trial decryption for a removal wrap: a device that holds a rotation
/// `Sealed` tries the wraps of the rotation's own delivery once more, and
/// stops at the first that opens. Returns that wrap's index and the body
/// key, or `None` when none opens.
pub fn find_removal_wrap<W: AsRef<[u8]>>(
    wraps: &[W],
    log: &[u8],
    key_name: &KeyName,
    grant_name: Option<&KeyName>,
    device: &DeviceId,
    xwing_seed: &[u8; 32],
    commitment: &[u8; 32],
) -> Option<(usize, Zeroizing<[u8; 32]>)> {
    wraps.iter().enumerate().find_map(|(index, wrap)| {
        open_removal_wrap(
            wrap.as_ref(),
            log,
            key_name,
            grant_name,
            device,
            xwing_seed,
            commitment,
        )
        .ok()
        .map(|key| (index, key))
    })
}
