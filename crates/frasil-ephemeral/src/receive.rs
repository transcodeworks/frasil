//! Receiving (ext-ephemeral.md, "Receiving").
//!
//! A receiver runs these checks on each outer frame. The first that fails
//! drops the frame with its class, and nothing is answered.
//!
//! ```text
//!  1. len(outer) <= 24,576.                                  else TooLarge
//!  2. The outer map; its space is the scope's.               else Malformed / UnsupportedVersion
//!  3. The receiver follows the space.                        else NotFollowing
//!  4. The reference reads (else Malformed / TooManyRotations);
//!     the receiver holds every rotation it names, and k(S).  else Sealed
//!  5. sealed opens under ek(S).                              else Decrypt
//!  6. The padding and the core.                              else Malformed
//!  7. The inner map; its kind is the outer kind.             else Malformed / UnsupportedVersion
//!  8. An ephemeral slot's handle is its own.                 else WrongHandle
//!  9. sender is a valid key (else InvalidKey); the signature
//!     verifies strictly.                                     else BadSignature
//! 10. sender is not this receiver.                           else Own
//! 11. A frasil/ name: known, implemented (else UnknownName),
//!     as its table row says.                                 else Malformed
//! 12. The sender is in.                                      else Forked, MembershipEnded,
//!                                                                 NotAMember or Unjudgeable
//! 13. No targets, or this receiver is one.                   else NotTargeted
//! 14. Its fresh entry holds one of its last 4 nonces; a
//!     fresh-only name carries one.                           else Stale
//! 15. The replay rule, and the sender's floor.               else Replayed
//! 16. A named adapter: held (else UnknownAdapter), and its
//!     capability checks accept.                              else CapabilityRefused
//! 17. Accepted: the replay state is updated.
//! ```
//!
//! The receiver's current view, its keys, its nonces and its adapters come
//! in through [`View`]; its replay state is a [`ReplayState`] it keeps.

use crate::frame::{Outer, read_core, signing_input, unpad};
use crate::inner::{Inner, Kind};
use crate::key::{ephemeral_key, slot_handle};
use crate::limits::RECEIVER_NONCE_BYTES;
#[cfg(not(feature = "ext-restricted-spaces"))]
use crate::limits::{ID_BYTES, MAX_ROTATIONS, NONCE_BYTES, TAG_BYTES};
use crate::membership::Membership;
use crate::names::{LEAVE, check_reserved};
use crate::replay::{ReplayState, SlotKey};
use crate::{EphemeralClass, malformed};
use frasil_base::ErrorClass;
use frasil_crypto::device::DeviceId;
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::schemes::ed25519_verify_strict;
#[cfg(not(feature = "ext-restricted-spaces"))]
use frasil_keys::names::KeyName;
use frasil_keys::names::{RotationId, RotationSet};
use zeroize::Zeroizing;

pub use crate::names::Extension;

/// How a space the receiver follows reads its key references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpaceKind {
    /// By keys.md: one rotation set.
    Plain,
    /// By ext-restricted-spaces.md: the space's own state, then its
    /// parent's state sealed.
    Restricted,
}

/// What a named adapter's capability checks say of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdapterCheck {
    /// The receiver has no such adapter (`UnknownAdapter`).
    Unknown,
    /// Every check accepts.
    Accept,
    /// A check refuses (`CapabilityRefused`).
    Refuse,
}

/// The context of units.md's `check(capabilities, context, content)` for a
/// frame (section 3.5): the space ID, the kind, `name`, `stream`, `targets`
/// and the sender's device ID. The sender's level and capabilities are
/// those of the receiver's current view, which the [`View`] supplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckContext<'a> {
    /// The space ID.
    pub space: &'a [u8; 32],
    /// The kind.
    pub kind: Kind,
    /// `name`.
    pub name: &'a str,
    /// `stream`.
    pub stream: Option<&'a [u8; 16]>,
    /// `targets`.
    pub targets: Option<&'a [DeviceId]>,
    /// The sender's device ID.
    pub sender: &'a DeviceId,
}

/// The receiver's current view, keys, nonces and adapters, as the checks
/// read them.
pub trait View {
    /// The receiver's own device ID.
    fn own(&self) -> DeviceId;

    /// Step 3: whether the receiver follows the space, and how its key
    /// references read; `None` if it does not follow it.
    fn follows(&self, space: &[u8; 32]) -> Option<SpaceKind>;

    /// Step 4: whether the receiver holds a rotation of the space.
    fn holds_rotation(&self, space: &[u8; 32], id: &RotationId) -> bool;

    /// Step 4: `k(S)` of the state a key reference names, if the receiver
    /// holds it (in a restricted space, `k_F` of the restricted reference).
    fn content_key(&self, space: &[u8; 32], reference: &[u8]) -> Option<Zeroizing<[u8; 32]>>;

    /// Step 11: whether the receiver implements an extension.
    fn implements(&self, extension: Extension) -> bool;

    /// Step 12: the sender's standing in the receiver's current view
    /// (section 3.6).
    fn member(&self, space: &[u8; 32], sender: &DeviceId) -> Membership;

    /// Step 14: whether the nonce is one of the receiver's last 4 in the
    /// space.
    fn holds_nonce(&self, space: &[u8; 32], nonce: &[u8; RECEIVER_NONCE_BYTES]) -> bool;

    /// Step 14: whether the application marks the name fresh-only.
    fn fresh_only(&self, name: &str) -> bool;

    /// Step 16: the named adapter's capability checks, on the sender's
    /// capabilities and level in the receiver's current view, the context
    /// and `data`.
    fn check_capabilities(
        &self,
        adapter: &str,
        context: &CheckContext<'_>,
        data: &[u8],
    ) -> AdapterCheck;
}

/// What an accepted frame does at the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delivered {
    /// An ephemeral message, delivered.
    Message,
    /// A `frasil/leave`: every held ephemeral slot of the sender was
    /// cleared.
    Leave,
    /// An ephemeral slot value, now held.
    SlotValue,
    /// An ephemeral slot cleared by empty data.
    SlotCleared,
}

/// An accepted frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The outer frame.
    pub frame: Outer,
    /// The inner map.
    pub inner: Inner,
    /// What it did.
    pub delivered: Delivered,
}

/// ext-restricted-spaces.md, "Reading a restricted key reference", steps 1
/// and 2: the space's own state `S_F`, then 41 + 32b bytes with 1 <= b <=
/// 64. Returns `S_F`.
///
/// # Errors
///
/// `Malformed` or `TooManyRotations`.
#[cfg(feature = "ext-restricted-spaces")]
pub fn read_restricted_reference(data: &[u8]) -> Result<RotationSet, EphemeralClass> {
    frasil_keys::ext_restricted_spaces::RestrictedReference::read(data)
        .map(|reference| reference.own)
        .map_err(EphemeralClass::from)
}

/// ext-restricted-spaces.md, "Reading a restricted key reference", steps 1
/// and 2, read here without the extension's own reader: the space's own
/// state `S_F`, then 41 + 32b bytes with 1 <= b <= 64. Returns `S_F`.
///
/// # Errors
///
/// `Malformed` or `TooManyRotations`.
#[cfg(not(feature = "ext-restricted-spaces"))]
pub fn read_restricted_reference(data: &[u8]) -> Result<RotationSet, EphemeralClass> {
    let (own, rest) = KeyName::read(data, false)?;
    let Some(own) = own.as_set() else {
        return Err(malformed());
    };
    let fixed = NONCE_BYTES + 1 + TAG_BYTES;
    if rest.len() < fixed + ID_BYTES || !(rest.len() - fixed).is_multiple_of(ID_BYTES) {
        return Err(malformed());
    }
    if (rest.len() - fixed) / ID_BYTES > MAX_ROTATIONS {
        return Err(EphemeralClass::TooManyRotations);
    }
    Ok(own.clone())
}

/// A refused frame: the step of section 3.4 that refused it, and its class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Refusal {
    /// The step, 1 to 16; steps 1 and 2 share [`Outer::read`], whose
    /// `TooLarge` is step 1's.
    pub step: u8,
    /// The class.
    pub class: EphemeralClass,
}

impl Refusal {
    fn at(step: u8) -> impl Fn(EphemeralClass) -> Self {
        move |class| Self { step, class }
    }
}

impl From<Refusal> for EphemeralClass {
    fn from(refusal: Refusal) -> Self {
        refusal.class
    }
}

/// `receive(outer, scope)`: section 3.4's checks, in order, on one outer
/// frame carried by an `Ephemeral` message for `scope`. An accepted frame
/// updates `replay`, as does a refusal at step 12 other than `Unjudgeable`:
/// the sender is out, and its ephemeral slots are forgotten.
///
/// # Errors
///
/// The first check that fails, with its step and class; the frame is
/// dropped and nothing is answered.
pub fn receive(
    outer: &[u8],
    scope: &[u8; 32],
    view: &impl View,
    replay: &mut ReplayState,
) -> Result<Accepted, Refusal> {
    let refuse = |step: u8, class: EphemeralClass| Err(Refusal { step, class });
    // 1 and 2. The size and the outer map.
    let frame = Outer::read(outer, scope).map_err(|class| Refusal {
        step: if class == ErrorClass::TooLarge.into() {
            1
        } else {
            2
        },
        class,
    })?;
    let space = frame.space;
    // 3. A space this receiver follows.
    let Some(kind) = view.follows(&space) else {
        return refuse(3, EphemeralClass::NotFollowing);
    };
    // 4. The reference reads, and the receiver holds its rotations and k(S).
    let rotations = match kind {
        SpaceKind::Plain => RotationSet::decode(&frame.reference).map_err(EphemeralClass::from),
        SpaceKind::Restricted => read_restricted_reference(&frame.reference),
    }
    .map_err(Refusal::at(4))?;
    if !rotations
        .ids()
        .iter()
        .all(|id| view.holds_rotation(&space, id))
    {
        return refuse(4, ErrorClass::Sealed.into());
    }
    let Some(content_key) = view.content_key(&space, &frame.reference) else {
        return refuse(4, ErrorClass::Sealed.into());
    };
    let ek = ephemeral_key(&content_key);
    // 5. Open.
    let plaintext = frame.open(&ek).map_err(Refusal::at(5))?;
    // 6. The padding and the core.
    let (inner_bytes, signature) = unpad(&plaintext)
        .and_then(read_core)
        .map_err(Refusal::at(6))?;
    // 7. The inner map.
    let inner = Inner::read(&inner_bytes).map_err(Refusal::at(7))?;
    if inner.kind != frame.kind {
        return refuse(7, malformed());
    }
    // 8. The ephemeral slot handle.
    if let Some(handle) = &frame.handle {
        let own = slot_handle(&ek, &inner.sender, &inner.name, inner.stream.as_ref());
        if *handle != own {
            return refuse(8, EphemeralClass::WrongHandle);
        }
    }
    // 9. The sender's ed and the signature under it.
    if let Err(class) = ed25519_valid(&inner.sender.ed.0) {
        return refuse(9, class.into());
    }
    let tbs = signing_input(
        &space,
        &frame.reference,
        frame.handle.as_ref(),
        &inner_bytes,
    );
    if !ed25519_verify_strict(&inner.sender.ed.0, &tbs, &signature) {
        return refuse(9, ErrorClass::BadSignature.into());
    }
    // 10. Its own frames, echoed back: the sender's device ID is its own.
    let sender = inner.sender.device_id();
    let own = view.own();
    if sender == own {
        return refuse(10, EphemeralClass::Own);
    }
    // 11. Frasil's names.
    check_reserved(&inner, &space, |extension| view.implements(extension))
        .map_err(Refusal::at(11))?;
    // 12. Membership, against the receiver's current view. A sender found
    // out, rather than not judged, loses its ephemeral slots here
    // ("Membership against the current view").
    let standing = view.member(&space, &sender);
    if matches!(
        standing,
        Membership::MembershipEnded | Membership::Forked | Membership::NotAMember
    ) {
        replay.drop_sender(&space, &sender);
    }
    standing.check().map_err(Refusal::at(12))?;
    // 13. Targets.
    if inner.excludes(&own) {
        return refuse(13, EphemeralClass::NotTargeted);
    }
    // 14. Freshness.
    match inner.fresh_for(&own) {
        Some(nonce) if !view.holds_nonce(&space, nonce) => {
            return refuse(14, EphemeralClass::Stale);
        }
        None if view.fresh_only(&inner.name) => return refuse(14, EphemeralClass::Stale),
        _ => {}
    }
    // 15. Replay.
    let slot_key = SlotKey {
        space,
        sender,
        name: inner.name.clone(),
        stream: inner.stream,
    };
    let fresh = match inner.kind {
        Kind::Message => replay.message_ok(&space, &sender, inner.epoch, inner.counter),
        Kind::Slot => replay.slot_ok(&slot_key, inner.epoch, inner.counter),
    };
    if !fresh {
        return refuse(15, ErrorClass::Replayed.into());
    }
    // 16. The adapter's capability checks.
    if let Some(adapter) = &inner.adapter {
        let context = CheckContext {
            space: &space,
            kind: inner.kind,
            name: &inner.name,
            stream: inner.stream.as_ref(),
            targets: inner.targets.as_deref(),
            sender: &sender,
        };
        match view.check_capabilities(adapter, &context, &inner.data) {
            AdapterCheck::Accept => {}
            AdapterCheck::Unknown => return refuse(16, ErrorClass::UnknownAdapter.into()),
            AdapterCheck::Refuse => return refuse(16, ErrorClass::CapabilityRefused.into()),
        }
    }
    // 17. Accepted.
    let delivered = match inner.kind {
        Kind::Message => {
            replay.accept_message(&space, &sender, inner.epoch, inner.counter);
            if inner.name == LEAVE {
                replay.clear_sender(&space, &sender, inner.epoch, inner.counter);
                Delivered::Leave
            } else {
                Delivered::Message
            }
        }
        Kind::Slot => {
            replay.accept_slot(slot_key, inner.epoch, inner.counter, &inner.data);
            if inner.data.is_empty() {
                Delivered::SlotCleared
            } else {
                Delivered::SlotValue
            }
        }
    };
    Ok(Accepted {
        frame,
        inner,
        delivered,
    })
}
