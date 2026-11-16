//! The signature, the seal and the outer frame (ext-ephemeral.md, "The
//! signature and the seal" and "The outer frame").
//!
//! ```text
//! tbs       = "frasil/ephemeral/v1" || field(space) || field(reference)
//!             || field(handle) || inner
//! signature = Ed25519-Sign(sender's identity seed, tbs)
//! core      = CBOR array [inner (bytes), signature (bytes)]
//! plaintext = u16be(len(core)) || core || zero bytes, to a multiple of 256
//! aad       = "frasil/ephemeral/v1" || field(space) || field(reference)
//!             || u8(kind) || field(handle)
//! sealed    = nonce || XChaCha20-Poly1305(ek(S), nonce, plaintext, aad)
//! ```
//!
//! An ephemeral message has no handle: where a format binds `handle`, it is
//! the empty string.

use crate::inner::{Inner, Kind};
use crate::key::{ephemeral_key, slot_handle};
use crate::limits::{
    EPHEMERAL, HANDLE_BYTES, MAX_OUTER_BYTES, MAX_PLAINTEXT_BYTES, MIN_SEALED_BYTES, NONCE_BYTES,
    PAD_BLOCK, SIGNATURE_BYTES, VERSION,
};
use crate::{EphemeralClass, malformed};
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_base::notation::push_field;
use frasil_crypto::primitives::{
    ed25519_public, ed25519_sign, xchacha20poly1305_open, xchacha20poly1305_seal,
};
use zeroize::Zeroizing;

/// `tbs`: what the sender signs.
pub fn signing_input(
    space: &[u8; 32],
    reference: &[u8],
    handle: Option<&[u8; HANDLE_BYTES]>,
    inner: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(EPHEMERAL.len() + 48 + reference.len() + inner.len());
    out.extend_from_slice(EPHEMERAL);
    push_field(&mut out, space);
    push_field(&mut out, reference);
    push_field(&mut out, handle.map_or(&[][..], |h| &h[..]));
    out.extend_from_slice(inner);
    out
}

/// `aad`: the seal's associated data, which binds every outer field.
pub fn seal_aad(
    space: &[u8; 32],
    reference: &[u8],
    kind: Kind,
    handle: Option<&[u8; HANDLE_BYTES]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(EPHEMERAL.len() + 49 + reference.len());
    out.extend_from_slice(EPHEMERAL);
    push_field(&mut out, space);
    push_field(&mut out, reference);
    out.push(kind.code());
    push_field(&mut out, handle.map_or(&[][..], |h| &h[..]));
    out
}

/// `core = [inner, signature]`, as CBOR.
pub fn encode_core(inner: &[u8], signature: &[u8; SIGNATURE_BYTES]) -> Vec<u8> {
    Value::Array(vec![Value::from(inner), Value::from(&signature[..])]).encode()
}

/// The padded plaintext: `u16be(len(core)) || core`, then the fewest zero
/// bytes that make its length a multiple of 256.
///
/// # Errors
///
/// `TooLarge` if the padded plaintext would be over 18,432 bytes.
pub fn pad(core: &[u8]) -> Result<Vec<u8>, EphemeralClass> {
    let body = 2 + core.len();
    let padded = body.div_ceil(PAD_BLOCK) * PAD_BLOCK;
    if padded > MAX_PLAINTEXT_BYTES {
        return Err(ErrorClass::TooLarge.into());
    }
    let length = u16::try_from(core.len()).map_err(|_| ErrorClass::TooLarge)?;
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(core);
    out.resize(padded, 0);
    Ok(out)
}

/// "Receiving", step 6, on the padding: the core inside a padded plaintext.
///
/// # Errors
///
/// `Malformed` unless the plaintext is a multiple of 256 bytes, at most
/// 18,432; its length prefix is at least 1 and fits; and every byte after
/// the core is zero, fewer than 256 of them.
pub fn unpad(plaintext: &[u8]) -> Result<&[u8], EphemeralClass> {
    if !plaintext.len().is_multiple_of(PAD_BLOCK)
        || !(PAD_BLOCK..=MAX_PLAINTEXT_BYTES).contains(&plaintext.len())
    {
        return Err(malformed());
    }
    let length = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
    if length < 1 || 2 + length > plaintext.len() {
        return Err(malformed());
    }
    let padding = &plaintext[2 + length..];
    if padding.iter().any(|&b| b != 0) || padding.len() >= PAD_BLOCK {
        return Err(malformed());
    }
    Ok(&plaintext[2..2 + length])
}

/// "Receiving", step 6, on the core: the inner map's bytes and the
/// signature.
///
/// # Errors
///
/// `Malformed` unless the core is a CBOR array of a byte string and a
/// 64-byte byte string.
pub fn read_core(core: &[u8]) -> Result<(Vec<u8>, [u8; SIGNATURE_BYTES]), EphemeralClass> {
    let Value::Array(items) = cbor::decode(core)? else {
        return Err(malformed());
    };
    let [inner, signature] = items.as_slice() else {
        return Err(malformed());
    };
    Ok((inner.as_bytes()?.to_vec(), signature.as_byte_array()?))
}

/// The outer frame: what a relay sees, carried at key 2 of transport.md's
/// `Ephemeral` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outer {
    /// `kind`.
    pub kind: Kind,
    /// `space`: the space ID.
    pub space: [u8; 32],
    /// `reference`: the key reference of the sender's state.
    pub reference: Vec<u8>,
    /// `handle`: present exactly for an ephemeral slot.
    pub handle: Option<[u8; HANDLE_BYTES]>,
    /// `sealed`: the nonce, then the ciphertext and its tag.
    pub sealed: Vec<u8>,
}

impl Outer {
    /// The outer frame's bytes, version 1.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(1, Value::Unsigned(VERSION));
        map.insert(2, Value::Unsigned(u64::from(self.kind.code())));
        map.insert(3, Value::from(&self.space[..]));
        map.insert(4, Value::from(self.reference.as_slice()));
        if let Some(handle) = &self.handle {
            map.insert(5, Value::from(&handle[..]));
        }
        map.insert(6, Value::from(self.sealed.as_slice()));
        Value::Map(map).encode()
    }

    /// "Receiving", steps 1 and 2, which a relay runs too: the size, then
    /// the outer map, whose space is the scope's.
    ///
    /// # Errors
    ///
    /// Step 1: `TooLarge` over 24,576 bytes. Step 2: `UnsupportedVersion`
    /// for a version other than 1; `Malformed` for anything else the outer
    /// map's rules refuse, a space other than `scope` included.
    pub fn read(outer: &[u8], scope: &[u8; 32]) -> Result<Self, EphemeralClass> {
        // 1. The size.
        if outer.len() > MAX_OUTER_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        // 2. The outer map.
        let Value::Map(map) = cbor::decode(outer)? else {
            return Err(malformed());
        };
        let version = map.get(&1).ok_or_else(malformed)?.as_unsigned()?;
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        if map.keys().any(|key| !(1..=6).contains(key))
            || [2, 3, 4, 6].iter().any(|key| !map.contains_key(key))
        {
            return Err(malformed());
        }
        let get = |key: u64| map.get(&key).ok_or_else(malformed);
        let kind = Kind::from_code(get(2)?.as_unsigned()?).ok_or_else(malformed)?;
        let space: [u8; 32] = get(3)?.as_byte_array()?;
        let reference = get(4)?.as_bytes()?.to_vec();
        if space != *scope {
            return Err(malformed());
        }
        let handle = match (kind, map.get(&5)) {
            (Kind::Slot, Some(handle)) => Some(handle.as_byte_array()?),
            (Kind::Message, None) => None,
            _ => return Err(malformed()),
        };
        let sealed = get(6)?.as_bytes()?;
        if sealed.len() < MIN_SEALED_BYTES {
            return Err(malformed());
        }
        Ok(Self {
            kind,
            space,
            reference,
            handle,
            sealed: sealed.to_vec(),
        })
    }

    /// The seal's associated data for this frame.
    pub fn aad(&self) -> Vec<u8> {
        seal_aad(
            &self.space,
            &self.reference,
            self.kind,
            self.handle.as_ref(),
        )
    }

    /// "Receiving", step 5: the plaintext, opened under `ek(S)`.
    ///
    /// # Errors
    ///
    /// `Decrypt` if `sealed` does not open under the key with this frame's
    /// associated data.
    pub fn open(&self, ephemeral_key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, EphemeralClass> {
        let (nonce, ciphertext) = self.sealed.split_at(NONCE_BYTES);
        let nonce: &[u8; NONCE_BYTES] = nonce.try_into().map_err(|_| malformed())?;
        Ok(xchacha20poly1305_open(
            ephemeral_key,
            nonce,
            &self.aad(),
            ciphertext,
        )?)
    }
}

/// A sender's whole construction, with every intermediate value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// `ek(S)`.
    pub ephemeral_key: Zeroizing<[u8; 32]>,
    /// The inner map's bytes.
    pub inner: Vec<u8>,
    /// The ephemeral slot handle, for an ephemeral slot.
    pub handle: Option<[u8; HANDLE_BYTES]>,
    /// `tbs`.
    pub signing_input: Vec<u8>,
    /// The signature.
    pub signature: [u8; SIGNATURE_BYTES],
    /// The core.
    pub core: Vec<u8>,
    /// The padded plaintext.
    pub plaintext: Zeroizing<Vec<u8>>,
    /// The seal's associated data.
    pub aad: Vec<u8>,
    /// The seal's nonce.
    pub nonce: [u8; NONCE_BYTES],
    /// The outer frame's fields.
    pub frame: Outer,
    /// The outer frame's bytes.
    pub outer: Vec<u8>,
}

/// Signs and seals an inner map under the sender's current content state
/// `S` (section 3.1), with `nonce` as the seal's 24 fresh random bytes.
///
/// `reference` is `S`'s key reference and `content_key` is `k(S)` (in a
/// restricted space, the restricted key reference and `k_F`).
///
/// # Errors
///
/// `Malformed` for an inner map the receiver's step 7 would refuse, a
/// reserved name the section 2.7 table refuses, or a seed whose public key
/// is not `sender`'s `ed`; `TooLarge` for a frame over the limits of section 2.1.
pub fn seal_with(
    inner: &Inner,
    space: &[u8; 32],
    reference: &[u8],
    content_key: &[u8; 32],
    seed: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Sealed, EphemeralClass> {
    let inner_bytes = inner.encode();
    if Inner::read(&inner_bytes).as_ref() != Ok(inner) || ed25519_public(seed) != inner.sender.ed.0
    {
        return Err(malformed());
    }
    crate::names::check_reserved(inner, space, |_| true)?;
    let ek = ephemeral_key(content_key);
    let handle = (inner.kind == Kind::Slot)
        .then(|| slot_handle(&ek, &inner.sender, &inner.name, inner.stream.as_ref()));
    let tbs = signing_input(space, reference, handle.as_ref(), &inner_bytes);
    let signature = ed25519_sign(seed, &tbs);
    let core = encode_core(&inner_bytes, &signature);
    let plaintext = Zeroizing::new(pad(&core)?);
    let aad = seal_aad(space, reference, inner.kind, handle.as_ref());
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&xchacha20poly1305_seal(&ek, nonce, &aad, &plaintext));
    let frame = Outer {
        kind: inner.kind,
        space: *space,
        reference: reference.to_vec(),
        handle,
        sealed,
    };
    let outer = frame.encode();
    if outer.len() > MAX_OUTER_BYTES {
        return Err(ErrorClass::TooLarge.into());
    }
    Ok(Sealed {
        ephemeral_key: ek,
        inner: inner_bytes,
        handle,
        signing_input: tbs,
        signature,
        core,
        plaintext,
        aad,
        nonce: *nonce,
        frame,
        outer,
    })
}
