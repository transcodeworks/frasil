//! frasil-ephemeral's plaintext readers on arbitrary bytes: the padding and
//! the core, a restricted key reference, and the whole receiver over the
//! bytes sealed as a frame's plaintext under a key it holds (ext-ephemeral.md,
//! "Receiving", steps 4 to 17). Nothing panics; the padding reader accepts
//! only what padding the core again gives; and a frame that opens is refused
//! at step 6 or later, or accepted.
#![no_main]

use frasil_base::ErrorClass;
use frasil_crypto::device::DeviceId;
use frasil_crypto::primitives::{ed25519_public, xchacha20poly1305_seal};
use frasil_ephemeral::frame::{pad, read_core, seal_aad, unpad};
use frasil_ephemeral::key::ephemeral_key;
use frasil_ephemeral::membership::Membership;
use frasil_ephemeral::receive::read_restricted_reference;
use frasil_ephemeral::replay::ReplayState;
use frasil_ephemeral::{
    AdapterCheck, CheckContext, EphemeralClass, Extension, Kind, Outer, SpaceKind, View, receive,
};
use frasil_keys::names::RotationId;
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

const SPACE: [u8; 32] = [3; 32];
const ROTATION: [u8; 32] = [4; 32];
const CONTENT_KEY: [u8; 32] = [5; 32];

/// A receiver that follows the space, holds its one state, and finds every
/// other device in.
struct Open;

impl View for Open {
    fn own(&self) -> DeviceId {
        DeviceId(ed25519_public(&[9; 32]))
    }
    fn follows(&self, space: &[u8; 32]) -> Option<SpaceKind> {
        (*space == SPACE).then_some(SpaceKind::Plain)
    }
    fn holds_rotation(&self, _: &[u8; 32], id: &RotationId) -> bool {
        id.0 == ROTATION
    }
    fn content_key(&self, _: &[u8; 32], _: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        Some(Zeroizing::new(CONTENT_KEY))
    }
    fn implements(&self, _: Extension) -> bool {
        true
    }
    fn member(&self, _: &[u8; 32], _: &DeviceId) -> Membership {
        Membership::In
    }
    fn holds_nonce(&self, _: &[u8; 32], nonce: &[u8; 16]) -> bool {
        nonce[0].is_multiple_of(2)
    }
    fn fresh_only(&self, name: &str) -> bool {
        name.ends_with(".go")
    }
    fn check_capabilities(&self, adapter: &str, _: &CheckContext<'_>, data: &[u8]) -> AdapterCheck {
        match adapter {
            "frasil:loro" => AdapterCheck::Accept,
            "com.example.cues" if data.is_empty() => AdapterCheck::Refuse,
            "com.example.cues" => AdapterCheck::Accept,
            _ => AdapterCheck::Unknown,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // The padding and the core.
    if let Ok(core) = unpad(data) {
        assert_eq!(pad(core).as_deref(), Ok(data), "a second padding");
        let _ = read_core(core);
    }
    // A restricted key reference.
    if let Err(class) = read_restricted_reference(data) {
        assert!(
            matches!(
                class,
                EphemeralClass::TooManyRotations | EphemeralClass::Shared(ErrorClass::Malformed)
            ),
            "{class:?}"
        );
    }
    // The bytes as a frame's plaintext, sealed under the state the receiver
    // holds; the first byte picks the kind, and a handle for a slot.
    let Some((&first, plaintext)) = data.split_first() else {
        return;
    };
    let (kind, handle) = if first.is_multiple_of(2) {
        (Kind::Message, None)
    } else {
        (Kind::Slot, Some([first; 16]))
    };
    let mut reference = vec![1];
    reference.extend_from_slice(&ROTATION);
    let ek = ephemeral_key(&CONTENT_KEY);
    let nonce = [first; 24];
    let aad = seal_aad(&SPACE, &reference, kind, handle.as_ref());
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&xchacha20poly1305_seal(&ek, &nonce, &aad, plaintext));
    let outer = Outer {
        kind,
        space: SPACE,
        reference,
        handle,
        sealed,
    }
    .encode();
    let mut replay = ReplayState::new();
    if let Err(refusal) = receive(&outer, &SPACE, &Open, &mut replay) {
        // A frame of at least 296 sealed bytes and at most 24,576 opens.
        assert!(refusal.step <= 2 || refusal.step >= 6, "{refusal:?}");
    }
});
