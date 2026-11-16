//! RFC 9497's VOPRF, mode `modeVOPRF` (0x01), suite ristretto255-SHA512, as
//! deposit tokens use it (ext-deposit-tokens.md, 2.1 The VOPRF).
//!
//! The functions here take every random value as bytes: the blind and the
//! proof's random scalar are each a canonical, non-zero scalar of 32 bytes,
//! which the VOPRF draws through an RNG that replays them. So RFC 9497's own
//! vectors run through the same path as Frasil's (`tests/voprf.rs`). The
//! forms without `_with` draw from the platform.
//!
//! - A batch is evaluated under one key with one proof over the whole list
//!   (RFC 9497, section 2.2.1), and checked with one `VerifyProof` before
//!   each element is finished.
//! - [`deserialize_element`] refuses an encoding that is not canonical and
//!   the identity.

use curve25519_dalek::rand_core::{TryCryptoRng, TryRng};
use curve25519_dalek::scalar::Scalar;
use frasil_crypto::{NoRandomness, random_bytes};
use subtle::ConstantTimeEq;
use voprf::{
    BlindedElement, EvaluationElement, Group, Proof, Ristretto255, VoprfClient, VoprfServer,
};
use zeroize::Zeroizing;

/// The suite: ristretto255 with SHA-512.
pub type Suite = Ristretto255;

/// A group element: a ristretto255 point.
pub type Element = <Ristretto255 as Group>::Elem;

/// `Ne`: the bytes of a serialized element.
pub const ELEMENT_BYTES: usize = 32;
/// `Ns`: the bytes of a serialized scalar.
pub const SCALAR_BYTES: usize = 32;
/// `Nh`: the bytes of an output.
pub const OUTPUT_BYTES: usize = 64;
/// The bytes of a serialized proof: two scalars.
pub const PROOF_BYTES: usize = 2 * SCALAR_BYTES;
/// The mode, `modeVOPRF`.
pub const MODE: u8 = 0x01;
/// `"OPRFV1-" || u8(0x01) || "-ristretto255-SHA512"`.
pub const CONTEXT: &[u8] = b"OPRFV1-\x01-ristretto255-SHA512";

/// A random draw that was not a canonical, non-zero scalar, or a VOPRF
/// step that refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteError {
    /// A blind or proof scalar given as bytes is not a canonical, non-zero
    /// scalar.
    Scalar,
    /// An element does not deserialize, or is the identity.
    Element,
    /// The proof does not hold, or its scalars do not deserialize.
    Proof,
    /// The VOPRF refused an input, a seed or a batch.
    Refused,
    /// The platform has no working source of randomness.
    NoRandomness,
}

impl From<NoRandomness> for SuiteError {
    fn from(_: NoRandomness) -> Self {
        Self::NoRandomness
    }
}

/// An RNG that hands out exactly the bytes given, once. The VOPRF draws the
/// blind and the proof's scalar as 32 bytes each, and draws again only for
/// bytes that are not a canonical, non-zero scalar, which the callers here
/// refuse first; so a draw never runs past what it was given.
struct Replay<'a> {
    bytes: &'a [u8],
}

/// The replayed bytes ran out.
#[derive(Debug)]
struct Exhausted;

impl core::fmt::Display for Exhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the supplied random bytes ran out")
    }
}

impl core::error::Error for Exhausted {}

impl TryRng for Replay<'_> {
    type Error = Exhausted;

    fn try_next_u32(&mut self) -> Result<u32, Exhausted> {
        let mut out = [0; 4];
        self.try_fill_bytes(&mut out)?;
        Ok(u32::from_le_bytes(out))
    }

    fn try_next_u64(&mut self) -> Result<u64, Exhausted> {
        let mut out = [0; 8];
        self.try_fill_bytes(&mut out)?;
        Ok(u64::from_le_bytes(out))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Exhausted> {
        if dst.len() > self.bytes.len() {
            return Err(Exhausted);
        }
        let (head, rest) = self.bytes.split_at(dst.len());
        dst.copy_from_slice(head);
        self.bytes = rest;
        Ok(())
    }
}

impl TryCryptoRng for Replay<'_> {}

/// Whether 32 bytes are a canonical, non-zero scalar, as a `_with` form's
/// blind or proof scalar must be.
pub fn is_scalar(bytes: &[u8; SCALAR_BYTES]) -> bool {
    <Ristretto255 as Group>::deserialize_scalar(bytes).is_ok()
}

/// A uniformly random non-zero scalar, from 64 bytes of the platform's
/// randomness reduced modulo the group's order.
///
/// # Errors
///
/// [`SuiteError::NoRandomness`] when the platform has no working source.
pub fn random_scalar() -> Result<Zeroizing<[u8; SCALAR_BYTES]>, SuiteError> {
    loop {
        let wide = random_bytes::<64>()?;
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        if scalar != Scalar::ZERO {
            return Ok(Zeroizing::new(scalar.to_bytes()));
        }
    }
}

/// A scalar from 64 random bytes reduced modulo the group's order, as
/// [`random_scalar`] draws one, for a caller whose randomness is its own;
/// `None` for the zero scalar, which the caller draws again.
pub fn scalar_from_wide(wide: &[u8; 64]) -> Option<Zeroizing<[u8; SCALAR_BYTES]>> {
    let scalar = Scalar::from_bytes_mod_order_wide(wide);
    (scalar != Scalar::ZERO).then(|| Zeroizing::new(scalar.to_bytes()))
}

/// `DeserializeElement`: refuses an encoding that is not canonical and the
/// identity.
///
/// # Errors
///
/// [`SuiteError::Element`].
pub fn deserialize_element(bytes: &[u8]) -> Result<Element, SuiteError> {
    <Ristretto255 as Group>::deserialize_elem(bytes).map_err(|_| SuiteError::Element)
}

/// `SerializeElement`.
pub fn serialize_element(element: Element) -> [u8; ELEMENT_BYTES] {
    let mut out = [0; ELEMENT_BYTES];
    out.copy_from_slice(&<Ristretto255 as Group>::serialize_elem(element));
    out
}

/// `DeriveKeyPair(seed, info)`: the server's key.
///
/// # Errors
///
/// [`SuiteError::Refused`] for an `info` the VOPRF refuses.
pub fn derive_key_pair(seed: &[u8], info: &[u8]) -> Result<VoprfServer<Suite>, SuiteError> {
    VoprfServer::new_from_seed(seed, info).map_err(|_| SuiteError::Refused)
}

/// The server key's public element, serialized.
pub fn public_key(server: &VoprfServer<Suite>) -> [u8; ELEMENT_BYTES] {
    serialize_element(server.get_public_key())
}

/// `Blind(input)`, with the blind given: the client's state, which keeps
/// the blind and zeroizes it when dropped, and the blinded element.
///
/// # Errors
///
/// [`SuiteError::Scalar`] for a blind that is not a canonical, non-zero
/// scalar; [`SuiteError::Refused`] for an input the VOPRF refuses.
pub fn blind_with(
    input: &[u8],
    blind: &[u8; SCALAR_BYTES],
) -> Result<(VoprfClient<Suite>, [u8; ELEMENT_BYTES]), SuiteError> {
    if !is_scalar(blind) {
        return Err(SuiteError::Scalar);
    }
    let result = VoprfClient::<Suite>::blind(input, &mut Replay { bytes: blind })
        .map_err(|_| SuiteError::Refused)?;
    let mut blinded = [0; ELEMENT_BYTES];
    blinded.copy_from_slice(&result.message.serialize());
    Ok((result.state, blinded))
}

/// `BlindEvaluate` of each element under one key, with one
/// `GenerateProof` over the lists, its random scalar given. Returns the
/// evaluated elements, in order, and the serialized proof.
///
/// # Errors
///
/// [`SuiteError::Element`] for an element that does not deserialize;
/// [`SuiteError::Scalar`] for a proof scalar that is not a canonical,
/// non-zero scalar; [`SuiteError::Refused`] for an empty or too long batch.
pub fn evaluate_batch_with(
    server: &VoprfServer<Suite>,
    blinded: &[[u8; ELEMENT_BYTES]],
    proof_scalar: &[u8; SCALAR_BYTES],
) -> Result<(Vec<[u8; ELEMENT_BYTES]>, [u8; PROOF_BYTES]), SuiteError> {
    if !is_scalar(proof_scalar) {
        return Err(SuiteError::Scalar);
    }
    if blinded.is_empty() {
        return Err(SuiteError::Refused);
    }
    let elements = blinded
        .iter()
        .map(|bytes| BlindedElement::<Suite>::deserialize(bytes).map_err(|_| SuiteError::Element))
        .collect::<Result<Vec<_>, _>>()?;
    let result = server
        .batch_blind_evaluate(
            &mut Replay {
                bytes: proof_scalar,
            },
            &elements,
        )
        .map_err(|_| SuiteError::Refused)?;
    let evaluated = result
        .messages
        .iter()
        .map(|message| {
            let mut out = [0; ELEMENT_BYTES];
            out.copy_from_slice(&message.serialize());
            out
        })
        .collect();
    let mut proof = [0; PROOF_BYTES];
    proof.copy_from_slice(&result.proof.serialize());
    Ok((evaluated, proof))
}

/// `VerifyProof` over the clients' blinded elements and the evaluated
/// ones, then `Finalize` for each: the outputs, in order. The clients, the
/// inputs and the evaluated elements are of one length. A proof whose
/// scalars do not deserialize does not hold.
///
/// # Errors
///
/// [`SuiteError::Element`] for an evaluated element that does not
/// deserialize; [`SuiteError::Proof`] for a proof that does not hold;
/// [`SuiteError::Refused`] for lists of different lengths.
pub fn finalize_batch(
    inputs: &[&[u8]],
    clients: &[VoprfClient<Suite>],
    evaluated: &[[u8; ELEMENT_BYTES]],
    proof: &[u8; PROOF_BYTES],
    public: Element,
) -> Result<Vec<Zeroizing<[u8; OUTPUT_BYTES]>>, SuiteError> {
    if inputs.len() != clients.len() || clients.len() != evaluated.len() {
        return Err(SuiteError::Refused);
    }
    let messages = evaluated
        .iter()
        .map(|bytes| {
            EvaluationElement::<Suite>::deserialize(bytes).map_err(|_| SuiteError::Element)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let proof = Proof::<Suite>::deserialize(proof).map_err(|_| SuiteError::Proof)?;
    let inputs = inputs.to_vec();
    let clients = clients.to_vec();
    let outputs = VoprfClient::batch_finalize(&inputs, &clients, &messages, &proof, public)
        .map_err(|error| match error {
            voprf::Error::ProofVerification => SuiteError::Proof,
            _ => SuiteError::Refused,
        })?;
    outputs
        .map(|output| {
            let output = output.map_err(|_| SuiteError::Refused)?;
            let mut out = Zeroizing::new([0; OUTPUT_BYTES]);
            out.copy_from_slice(&output);
            Ok(out)
        })
        .collect()
}

/// The server's `Evaluate(skS, input)`.
///
/// # Errors
///
/// [`SuiteError::Refused`] for an input the VOPRF refuses.
pub fn evaluate(
    server: &VoprfServer<Suite>,
    input: &[u8],
) -> Result<Zeroizing<[u8; OUTPUT_BYTES]>, SuiteError> {
    let output = server.evaluate(input).map_err(|_| SuiteError::Refused)?;
    let mut out = Zeroizing::new([0; OUTPUT_BYTES]);
    out.copy_from_slice(&output);
    Ok(out)
}

/// Whether an authenticator equals `Evaluate(skS, input)`, compared in
/// constant time.
pub fn verify(server: &VoprfServer<Suite>, input: &[u8], authenticator: &[u8]) -> bool {
    evaluate(server, input)
        .is_ok_and(|expected| bool::from(expected.as_slice().ct_eq(authenticator)))
}
