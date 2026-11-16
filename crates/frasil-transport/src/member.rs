//! The member handshake's values and checks (transport.md, sections 2.6
//! "Member handshake values" and 3.2 to 3.4), one step at a time.
//!
//! ```text
//! hk(S)    = HKDF(none, k(S), "frasil/member-key/v1")                        32 bytes
//!
//! tag(S)   = HMAC(hk(S), "frasil/member-offer/v1" || field(channel) || u8(0x01)
//!                        || u32be(attach) || nonce)                          32 bytes
//! Offer    = {0: 1, 1: attach, 2: nonce (32), 3: [tag_0, ..., tag_15], 4: revision}
//!
//! core     = {0: 2, 1: attach, 2: nonce_R (32), 3: index}
//! th       = SHA-256("frasil/member-transcript/v1" || field(channel)
//!                    || field(endpoint_I) || field(endpoint_R)
//!                    || field(offer) || field(core))
//! proof    = HMAC(hk(P), "frasil/member-answer/v1" || th)
//! Answer   = {0: 2, 1: attach, 2: nonce_R, 3: index, 4: proof}
//!
//! signed   = "frasil/member-identify/v1" || th_0 || u8(role) || ed || kc
//! Identify = {0: 4, 1: ed || kc (64), 2: Ed25519-Sign(identity seed, signed)}
//! ```
//!
//! [`crate::session::MemberSession`] runs these steps for a whole
//! connection. A state is the caller's type `T`; its secret is `k(S)`, or
//! the secret ext-restricted-spaces.md names in its place.

use crate::frame::{Message, MessageType};
use crate::messages::{self, Refuse, exactly, malformed, uint};
use crate::{Channel, Code, TransportClass};
use core::borrow::Borrow;
use frasil_base::ErrorClass;
use frasil_base::cbor::Value;
use frasil_base::notation::push_field;
use frasil_crypto::device::{IdentityKey, KeysCommitment, Signatory};
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::labels;
use frasil_crypto::primitives::{ed25519_public, ed25519_sign, hkdf, hmac_sha256, sha256};
use frasil_crypto::schemes::ed25519_verify_strict;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The revision offers carry (overview.md, "Version policy").
pub const REVISION: u64 = frasil_base::version::REVISION;
/// Tags in every offer, real or random.
pub const OFFER_TAGS: usize = 16;
/// Bytes of an offer's or an answer's nonce.
pub const NONCE_BYTES: usize = 32;
/// Attach numbers are below this.
pub const MAX_ATTACHES: u32 = 1_024;
/// The most candidate states a responder keeps per space.
pub const CANDIDATES_PER_SPACE: usize = 256;
/// The most tags a responder computes per offer.
pub const CANDIDATE_BUDGET: usize = 8_192;
/// Offers an initiator may send for one attach after the first.
pub const EXTRA_OFFERS: usize = 3;
/// Offers of one attach in all.
pub const MAX_OFFERS: usize = 1 + EXTRA_OFFERS;
/// The most single rotations of a merged current state an offer names.
pub const MAX_ROTATIONS_ALONE: usize = 7;
/// The byte that marks an initiator's tag.
const INITIATOR_TAG: u8 = 0x01;

/// A 32-byte secret, wiped when dropped.
pub type Secret = Zeroizing<[u8; 32]>;

/// A side's role on the connection: the dialer opens it, the listener
/// accepts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The side that opened the connection; it initiates attach 0 and
    /// numbers its attaches 0, 2, 4.
    Dialer,
    /// The side that accepted it; it numbers its attaches 1, 3, 5.
    Listener,
}

impl Role {
    /// The role's byte in `Identify`: `0x01` the dialer, `0x02` the
    /// listener.
    pub const fn byte(self) -> u8 {
        match self {
            Self::Dialer => 0x01,
            Self::Listener => 0x02,
        }
    }

    /// The parity of the attach numbers this role initiates.
    pub const fn parity(self) -> u32 {
        match self {
            Self::Dialer => 0,
            Self::Listener => 1,
        }
    }

    /// The other side's role.
    pub const fn other(self) -> Self {
        match self {
            Self::Dialer => Self::Listener,
            Self::Listener => Self::Dialer,
        }
    }

    /// The role that initiates an attach number.
    pub const fn of_attach(attach: u32) -> Self {
        if attach.is_multiple_of(2) {
            Self::Dialer
        } else {
            Self::Listener
        }
    }
}

/// `hk(S) = HKDF(none, k(S), "frasil/member-key/v1")`: a state's member key.
/// It only authenticates; nothing is sealed under it.
pub fn member_key(state_secret: &[u8; 32]) -> Secret {
    hkdf(None, state_secret, labels::MEMBER_KEY)
}

/// `tag(S)`: an initiator's tag for a state, under its member key.
pub fn offer_tag(hk: &[u8; 32], channel: &Channel, attach: u32, nonce: &[u8; 32]) -> [u8; 32] {
    let mut message = labels::MEMBER_OFFER.to_vec();
    push_field(&mut message, channel);
    message.push(INITIATOR_TAG);
    message.extend_from_slice(&attach.to_be_bytes());
    message.extend_from_slice(nonce);
    hmac_sha256(hk, &message)
}

/// The `Offer` message.
pub fn encode_offer(attach: u32, nonce: &[u8; 32], tags: &[[u8; 32]], revision: u64) -> Vec<u8> {
    messages::encode(
        MessageType::Offer,
        [
            (1, Value::Unsigned(attach.into())),
            (2, Value::from(*nonce)),
            (
                3,
                Value::Array(tags.iter().map(|t| Value::from(*t)).collect()),
            ),
            (4, Value::Unsigned(revision)),
        ],
    )
}

/// The answer's `core = {0: 2, 1: attach, 2: nonce_R, 3: index}`.
pub fn answer_core(attach: u32, nonce: &[u8; 32], index: u8) -> Vec<u8> {
    messages::encode(
        MessageType::Answer,
        [
            (1, Value::Unsigned(attach.into())),
            (2, Value::from(*nonce)),
            (3, Value::Unsigned(index.into())),
        ],
    )
}

/// The `Answer` message.
pub fn encode_answer(attach: u32, nonce: &[u8; 32], index: u8, proof: &[u8; 32]) -> Vec<u8> {
    messages::encode(
        MessageType::Answer,
        [
            (1, Value::Unsigned(attach.into())),
            (2, Value::from(*nonce)),
            (3, Value::Unsigned(index.into())),
            (4, Value::from(*proof)),
        ],
    )
}

/// `th`: the attach's transcript. `offer` is the offer's bytes as received;
/// `endpoint_i` and `endpoint_r` are the initiator's and the responder's
/// endpoint keys as the transport proved them.
pub fn transcript(
    channel: &Channel,
    endpoint_i: &[u8; 32],
    endpoint_r: &[u8; 32],
    offer: &[u8],
    core: &[u8],
) -> [u8; 32] {
    let mut input = labels::MEMBER_TRANSCRIPT.to_vec();
    for part in [&channel[..], endpoint_i, endpoint_r, offer, core] {
        push_field(&mut input, part);
    }
    sha256(&[&input])
}

/// `proof = HMAC(hk(P), "frasil/member-answer/v1" || th)`.
pub fn answer_proof(hk: &[u8; 32], transcript: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(hk, &[labels::MEMBER_ANSWER, transcript].concat())
}

/// What `Identify` signs: `"frasil/member-identify/v1" || th_0 || u8(role)
/// || ed || kc`, with the signer's role. The signature covers `kc`, so the
/// device it binds to the connection is the device ID of `ed` and `kc`.
pub fn identify_input(th0: &[u8; 32], role: Role, signer: &Signatory) -> Vec<u8> {
    [
        labels::MEMBER_IDENTIFY,
        th0,
        &[role.byte()],
        &signer.to_bytes(),
    ]
    .concat()
}

/// The `Identify` message: key 1 is `ed || kc`.
pub fn encode_identify(signer: &Signatory, signature: &[u8]) -> Vec<u8> {
    messages::encode(
        MessageType::Identify,
        [
            (1, Value::from(signer.to_bytes())),
            (2, Value::from(signature)),
        ],
    )
}

/// The `Identify` of the device whose identity seed is `identity_seed` and
/// whose keys commitment is `kc`, signing attach 0's transcript in its
/// role.
pub fn identify(
    identity_seed: &[u8; 32],
    kc: &KeysCommitment,
    th0: &[u8; 32],
    role: Role,
) -> Vec<u8> {
    let signer = Signatory {
        ed: IdentityKey(ed25519_public(identity_seed)),
        kc: *kc,
    };
    let signature = ed25519_sign(identity_seed, &identify_input(th0, role, &signer));
    encode_identify(&signer, &signature)
}

/// The initiator's choice of states for one space (section 3.2), in
/// order: its current state; if that holds several rotations, each of
/// them alone that it holds, in canonical order, at most 7; then the
/// states it held as current before, most recent first; at most 16 in
/// all, each once. `alone` lists the single rotations of the current state
/// it holds, in canonical order; `history` the states it held as current
/// before, most recent first.
pub fn offered_states<T: PartialEq>(
    current: T,
    alone: impl IntoIterator<Item = T>,
    history: impl IntoIterator<Item = T>,
) -> Vec<T> {
    let mut out = vec![current];
    for state in alone.into_iter().take(MAX_ROTATIONS_ALONE) {
        if !out.contains(&state) {
            out.push(state);
        }
    }
    for state in history {
        if out.len() == OFFER_TAGS {
            break;
        }
        if !out.contains(&state) {
            out.push(state);
        }
    }
    out.truncate(OFFER_TAGS);
    out
}

/// An offer the initiator sent: what it needs to check the answer.
pub struct SentOffer<T> {
    attach: u32,
    nonce: [u8; 32],
    tags: Vec<[u8; 32]>,
    bytes: Vec<u8>,
    slots: Vec<Option<(T, Secret)>>,
}

impl<T: core::fmt::Debug> core::fmt::Debug for SentOffer<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SentOffer")
            .field("attach", &self.attach)
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

impl<T> SentOffer<T> {
    /// Makes an offer: a tag for each state, in order, then the fillers of
    /// the remaining places, from the same index of `fillers` (32 fresh
    /// random bytes each). At most 16 states are offered; the rest are
    /// left out. `secret` is each state's `k(S)`.
    pub fn new_with<K: Borrow<[u8; 32]>>(
        attach: u32,
        channel: &Channel,
        states: impl IntoIterator<Item = (T, K)>,
        nonce: [u8; 32],
        fillers: &[[u8; 32]; OFFER_TAGS],
    ) -> Self {
        let mut tags = Vec::with_capacity(OFFER_TAGS);
        let mut slots = Vec::with_capacity(OFFER_TAGS);
        for (state, secret) in states.into_iter().take(OFFER_TAGS) {
            let hk = member_key(secret.borrow());
            tags.push(offer_tag(&hk, channel, attach, &nonce));
            slots.push(Some((state, hk)));
        }
        for filler in &fillers[tags.len()..] {
            tags.push(*filler);
            slots.push(None);
        }
        let bytes = encode_offer(attach, &nonce, &tags, REVISION);
        Self {
            attach,
            nonce,
            tags,
            bytes,
            slots,
        }
    }

    /// The attach.
    pub fn attach(&self) -> u32 {
        self.attach
    }

    /// The offer's nonce.
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// The 16 tags, real then fillers.
    pub fn tags(&self) -> &[[u8; 32]] {
        &self.tags
    }

    /// The `Offer` message.
    pub fn message(&self) -> &[u8] {
        &self.bytes
    }

    /// The state offered at an index; `None` for a filler.
    pub fn state(&self, index: usize) -> Option<&T> {
        self.slots.get(index)?.as_ref().map(|(state, _)| state)
    }

    /// Takes the state offered at an index out of the offer.
    pub fn take_state(&mut self, index: usize) -> Option<T> {
        self.slots.get_mut(index)?.take().map(|(state, _)| state)
    }

    /// On `Answer` or `Refuse`, at the initiator, in order (section 3.4,
    /// steps 1 to 4). `endpoint_i` is the initiator's endpoint key and
    /// `endpoint_r` the responder's.
    ///
    /// # Errors
    ///
    /// `Malformed` for a `Refuse` that does not read or names another
    /// attach; `Malformed` for an answer that does not have exactly keys 0
    /// to 4, names another attach, or lacks a 32-byte nonce, an index from 0
    /// to 15 or a 32-byte proof; `BadProof` for an index that names a
    /// filler, or a proof that does not verify.
    pub fn read_reply(
        &self,
        message: &Message,
        channel: &Channel,
        endpoint_i: &[u8; 32],
        endpoint_r: &[u8; 32],
    ) -> Result<Reply, TransportClass> {
        // 1. A Refuse: its code ends this offer.
        if message.kind == MessageType::Refuse {
            let refuse = Refuse::read(message)?;
            if refuse.attach != u64::from(self.attach) {
                return Err(malformed());
            }
            return Ok(Reply::Refused(refuse.code));
        }
        // 2. Exactly keys 0 to 4, its attach, the shapes.
        exactly(message, MessageType::Answer, &[0, 1, 2, 3, 4])?;
        let map = &message.map;
        let attach = uint(map, 1)?;
        let nonce: [u8; 32] = messages::array(map, 2)?;
        let index = uint(map, 3)?;
        let proof: [u8; 32] = messages::array(map, 4)?;
        if attach != u64::from(self.attach) || index >= OFFER_TAGS as u64 {
            return Err(malformed());
        }
        let index = u8::try_from(index).map_err(|_| malformed())?;
        // 3. The index names a real state, not a filler.
        let Some(Some((_, hk))) = self.slots.get(usize::from(index)) else {
            return Err(TransportClass::BadProof);
        };
        // 4. The proof, over the transcript the initiator computes, in
        //    constant time.
        let core = answer_core(self.attach, &nonce, index);
        let th = transcript(channel, endpoint_i, endpoint_r, &self.bytes, &core);
        if !constant_time_eq(&answer_proof(hk, &th), &proof) {
            return Err(TransportClass::BadProof);
        }
        Ok(Reply::Answered {
            index: usize::from(index),
            transcript: th,
        })
    }
}

/// What the initiator made of a reply to its offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// A `Refuse`, with its code: the offer is over.
    Refused(Code),
    /// An answer that verified: the index of the proof state, and the
    /// attach's transcript.
    Answered {
        /// The index of the proof state in the offer.
        index: usize,
        /// The attach's transcript `th`.
        transcript: [u8; 32],
    },
}

/// An offer, as the responder read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOffer {
    /// The attach.
    pub attach: u32,
    /// The offer's nonce.
    pub nonce: [u8; 32],
    /// The 16 tags.
    pub tags: Vec<[u8; 32]>,
    /// The offer's bytes as received.
    pub bytes: Vec<u8>,
}

/// On `Offer`, steps 1 to 5 (section 3.3). `initiator` is the role of the
/// side that sent it; `previous_offers` counts the offers this attach has
/// had.
///
/// # Errors
///
/// In the document's order: `Malformed` without exactly keys 0 to 4 and an
/// unsigned revision; `RevisionMismatch`, which the responder answers with
/// a `Refuse`; `AttachLimit` for an attach of 1,024 or more; `Malformed`
/// for another parity, a nonce that is not 32 bytes, or other than 16
/// tags of 32 bytes; `Malformed` past the fourth offer of the attach.
pub fn read_offer(
    message: &Message,
    initiator: Role,
    previous_offers: usize,
) -> Result<ReadOffer, TransportClass> {
    // 1.
    exactly(message, MessageType::Offer, &[0, 1, 2, 3, 4])?;
    let map = &message.map;
    let revision = uint(map, 4)?;
    // 2.
    if revision != REVISION {
        return Err(ErrorClass::RevisionMismatch.into());
    }
    // 3.
    let attach = uint(map, 1)?;
    let attach = u32::try_from(attach)
        .ok()
        .filter(|a| *a < MAX_ATTACHES)
        .ok_or(TransportClass::AttachLimit)?;
    // 4.
    if attach % 2 != initiator.parity() {
        return Err(malformed());
    }
    let nonce = messages::array(map, 2)?;
    let items = messages::field(map, 3)?.as_array()?;
    if items.len() != OFFER_TAGS {
        return Err(malformed());
    }
    let tags = items
        .iter()
        .map(Value::as_byte_array)
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    // 5.
    if previous_offers >= MAX_OFFERS {
        return Err(malformed());
    }
    Ok(ReadOffer {
        attach,
        nonce,
        tags,
        bytes: message.bytes.clone(),
    })
}

/// The responder's match: the state that fixes the space and the proof
/// state `P`.
pub struct Match<T> {
    /// The offer's index of the matching tag.
    pub index: u8,
    /// The candidate that matched.
    pub state: T,
    hk: Secret,
}

impl<T: core::fmt::Debug> core::fmt::Debug for Match<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Match")
            .field("index", &self.index)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// On `Offer`, step 6 (section 3.3): computes `tag(C)` for the candidates,
/// in the responder's order, at most 8,192, and looks each up among the
/// offer's tags. The match is the candidate whose tag equals the offer's
/// tag of the smallest index; among equal tags, the first in the
/// responder's order.
///
/// # Errors
///
/// `Busy` if the budget ran out without a match; `NoCommonState`
/// otherwise.
pub fn match_offer<T, K: Borrow<[u8; 32]>>(
    offer: &ReadOffer,
    channel: &Channel,
    candidates: impl IntoIterator<Item = (T, K)>,
) -> Result<Match<T>, TransportClass> {
    let mut best: Option<Match<T>> = None;
    let mut candidates = candidates.into_iter();
    for (state, secret) in candidates.by_ref().take(CANDIDATE_BUDGET) {
        let hk = member_key(secret.borrow());
        let tag = offer_tag(&hk, channel, offer.attach, &offer.nonce);
        let Some(index) = offer.tags.iter().position(|t| constant_time_eq(t, &tag)) else {
            continue;
        };
        let index = u8::try_from(index).expect("an offer has 16 tags");
        if best.as_ref().is_none_or(|b| index < b.index) {
            best = Some(Match { index, state, hk });
            if index == 0 {
                break;
            }
        }
    }
    match best {
        Some(found) => Ok(found),
        None if candidates.next().is_some() => Err(TransportClass::Busy),
        None => Err(TransportClass::NoCommonState),
    }
}

/// The responder's answer to an offer it matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The answer's core.
    pub core: Vec<u8>,
    /// The attach's transcript `th`.
    pub transcript: [u8; 32],
    /// The proof.
    pub proof: [u8; 32],
    /// The `Answer` message.
    pub message: Vec<u8>,
}

impl<T> Match<T> {
    /// The answer, with `nonce_r`, 32 fresh random bytes (step 7).
    /// `endpoint_i` is the initiator's endpoint key and `endpoint_r` the
    /// responder's.
    pub fn answer_with(
        &self,
        offer: &ReadOffer,
        channel: &Channel,
        endpoint_i: &[u8; 32],
        endpoint_r: &[u8; 32],
        nonce_r: [u8; 32],
    ) -> Answer {
        let core = answer_core(offer.attach, &nonce_r, self.index);
        let th = transcript(channel, endpoint_i, endpoint_r, &offer.bytes, &core);
        let proof = answer_proof(&self.hk, &th);
        let message = encode_answer(offer.attach, &nonce_r, self.index, &proof);
        Answer {
            core,
            transcript: th,
            proof,
            message,
        }
    }
}

/// On `Identify`, at either side, in order (section 3.4, steps 6 to 8):
/// returns the sender's `ed || kc`, whose device ID step 9's roster check
/// takes. `sender` is the role the sender holds on this connection.
///
/// # Errors
///
/// `Malformed` without exactly keys 0 to 2, a 64-byte `ed || kc` and a
/// 64-byte signature; `InvalidKey` for an `ed` crypto.md refuses;
/// `BadSignature` if the signature does not verify strictly under `ed` over
/// `signed`.
pub fn verify_identify(
    message: &Message,
    th0: &[u8; 32],
    sender: Role,
) -> Result<Signatory, TransportClass> {
    // 6.
    exactly(message, MessageType::Identify, &[0, 1, 2])?;
    let signer = Signatory::from_bytes(messages::bytes(&message.map, 1)?)?;
    let signature = messages::bytes(&message.map, 2)?;
    if signature.len() != 64 {
        return Err(malformed());
    }
    // 7.
    ed25519_valid(&signer.ed.0)?;
    // 8.
    if !ed25519_verify_strict(
        &signer.ed.0,
        &identify_input(th0, sender, &signer),
        signature,
    ) {
        return Err(ErrorClass::BadSignature.into());
    }
    Ok(signer)
}

/// Whether `a` equals `b`, in time that does not depend on where they
/// differ.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}
