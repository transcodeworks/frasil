//! The device's side: learning a peer's keys, requesting tokens and
//! finishing issuance (ext-deposit-tokens.md, 3.2 Learning a peer's keys,
//! 3.3 Requesting tokens and 3.5 Finishing issuance).
//!
//! ```text
//! A key list, in order:
//! 1. One or two entries, each a key ID of 32 bytes, a public key of 32
//!    and a role of 1 or 2; exactly one of role 1; no key ID twice. else Malformed
//! 2. Each public key passes DeserializeElement.                    else InvalidKey
//! 3. Each key ID is the hash of its public key (section 2.2).      else Malformed
//!
//! A TokenIssue, in order:
//! 1. Exactly keys 0 to 3; request names its TokenRequest;
//!    evaluated an array of m byte strings of 32 bytes, 1 <= m <= n,
//!    n the number it sent; proof of 64 bytes.                      else Malformed
//! 2. Each evaluated element passes DeserializeElement.             else Malformed
//! 3. VerifyProof(G, pkS, the first m blinded elements, evaluated,
//!    proof) holds, pkS being the issuing key of section 3.3,
//!    step 1; a proof whose scalars do not pass DeserializeScalar
//!    does not hold.                                                else BadProof
//! ```
//!
//! The blinds and inputs of a [`Batch`] live in memory only and are
//! zeroized when it is dropped. The device keeps its finished tokens
//! sealed at rest, as it keeps its other secrets; that is the client's.

use frasil_base::ErrorClass;
use frasil_base::cbor::{Map, Value};
use frasil_crypto::NoRandomness;
use voprf::VoprfClient;
use zeroize::Zeroizing;

use crate::errors::{TokenClass, malformed};
use crate::key::{KEY_ID_BYTES, KeyId, PeerKey, Role, key_id};
use crate::messages::{Draw, TokenIssue, TokenRequest};
use crate::settings::CONSISTENCY_WINDOW;
use crate::suite::{self, ELEMENT_BYTES, SCALAR_BYTES, Suite, SuiteError};
use crate::token::{NONCE_BYTES, Token, token_input};
use crate::{MAX_BATCH, TOKEN_KEYS};

/// A peer's live keys after section 3.2's checks: one or two, exactly one
/// issuing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyList {
    keys: Vec<PeerKey>,
}

impl KeyList {
    /// Section 3.2's checks, in order, of a list's entries as (key ID,
    /// public key, role), from `TokenKeys` or from discovery's
    /// `deposit_keys`.
    ///
    /// # Errors
    ///
    /// `Malformed` at step 1 or 3; `InvalidKey` at step 2.
    pub fn check(entries: &[(&[u8], &[u8], u64)]) -> Result<Self, TokenClass> {
        // 1. The form.
        if entries.is_empty() || entries.len() > 2 {
            return Err(malformed());
        }
        let mut read = Vec::with_capacity(entries.len());
        for &(id, public, role) in entries {
            let (Ok(id), Ok(public), Some(role)) = (
                <[u8; KEY_ID_BYTES]>::try_from(id),
                <[u8; ELEMENT_BYTES]>::try_from(public),
                Role::from_code(role),
            ) else {
                return Err(malformed());
            };
            read.push((id, public, role));
        }
        let issuing = read.iter().filter(|e| e.2 == Role::Issuing).count();
        if issuing != 1 || (read.len() == 2 && read[0].0 == read[1].0) {
            return Err(malformed());
        }
        // 2. Each public key is an element.
        let mut keys = Vec::with_capacity(read.len());
        for &(id, public, role) in &read {
            let element =
                suite::deserialize_element(&public).map_err(|_| ErrorClass::InvalidKey)?;
            keys.push(PeerKey {
                id,
                public,
                role,
                element,
            });
        }
        // 3. Each key ID is its key's.
        if keys.iter().any(|key| key_id(&key.public) != key.id) {
            return Err(malformed());
        }
        Ok(Self { keys })
    }

    /// Reads a `TokenKeys` answering `TokenKeysGet` number `request`:
    /// exactly keys 0 to 2, then section 3.2's checks of its list.
    ///
    /// # Errors
    ///
    /// As [`check`](Self::check); `Malformed` for a message of another
    /// form or request.
    pub fn read(map: &Map, request: u64) -> Result<Self, TokenClass> {
        if map.len() != 3
            || map.get(&0).map(Value::as_unsigned) != Some(Ok(TOKEN_KEYS))
            || map.get(&1).map(Value::as_unsigned) != Some(Ok(request))
        {
            return Err(malformed());
        }
        let entries = map.get(&2).ok_or_else(malformed)?.as_array()?;
        let mut flat = Vec::with_capacity(entries.len());
        for entry in entries {
            let [id, public, role] = entry.as_array()? else {
                return Err(malformed());
            };
            flat.push((id.as_bytes()?, public.as_bytes()?, role.as_unsigned()?));
        }
        Self::check(&flat)
    }

    /// Reads a `TokenKeys` from its bytes, by [`read`](Self::read).
    ///
    /// # Errors
    ///
    /// As [`read`](Self::read).
    pub fn decode(bytes: &[u8], request: u64) -> Result<Self, TokenClass> {
        let value = frasil_base::cbor::decode(bytes)?;
        Self::read(value.as_map()?, request)
    }

    /// The keys, in the list's order.
    pub fn keys(&self) -> &[PeerKey] {
        &self.keys
    }

    /// The issuing key.
    pub fn issuing(&self) -> &PeerKey {
        self.keys
            .iter()
            .find(|key| key.role == Role::Issuing)
            .unwrap_or(&self.keys[0])
    }

    /// Whether the list shows a key.
    pub fn shows(&self, id: &KeyId) -> bool {
        self.keys.iter().any(|key| &key.id == id)
    }
}

/// What a device keeps per peer (section 3.2): the issuing keys it has
/// seen, in order, each with its first sight on the device's timeline. A
/// list whose issuing key the device saw replaced, or that would make three
/// issuing keys whose first sights lie less than 24 hours apart, is
/// `KeyInconsistent`; the device then stops drawing and spending that
/// peer's tokens, drops those it holds, and reports the peer, and every
/// later list is `KeyInconsistent` too.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyHistory {
    seen: Vec<(KeyId, u64)>,
    stopped: bool,
    latest: Vec<KeyId>,
}

impl KeyHistory {
    /// No key seen.
    pub fn new() -> Self {
        Self::default()
    }

    /// A history kept at rest: the issuing keys seen with their first
    /// sights, in order, and whether the peer was found inconsistent.
    pub fn from_parts(seen: Vec<(KeyId, u64)>, stopped: bool) -> Self {
        Self {
            seen,
            stopped,
            latest: Vec::new(),
        }
    }

    /// Takes a checked key list seen at `reading`, seconds on the device's
    /// timeline.
    ///
    /// # Errors
    ///
    /// `KeyInconsistent`.
    pub fn observe(&mut self, list: &KeyList, reading: u64) -> Result<(), TokenClass> {
        if self.stopped {
            return Err(TokenClass::KeyInconsistent);
        }
        let issuing = list.issuing().id;
        let last = self.seen.last().map(|seen| seen.0);
        if last != Some(issuing) {
            let replaced = self.seen.iter().any(|seen| seen.0 == issuing);
            let crowded = self.seen.len() >= 2
                && reading.saturating_sub(self.seen[self.seen.len() - 2].1) < CONSISTENCY_WINDOW;
            if replaced || crowded {
                self.stopped = true;
                self.latest.clear();
                return Err(TokenClass::KeyInconsistent);
            }
            self.seen.push((issuing, reading));
        }
        self.latest = list.keys().iter().map(|key| key.id).collect();
        Ok(())
    }

    /// The issuing keys seen, with their first sights, in order.
    pub fn seen(&self) -> &[(KeyId, u64)] {
        &self.seen
    }

    /// Whether the device has stopped drawing and spending this peer's
    /// tokens.
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// The keys the device keeps tokens of: those its latest list shows
    /// (section 3.9). A token of any other key is dropped.
    pub fn keeps(&self) -> &[KeyId] {
        &self.latest
    }
}

/// Why a batch could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchError {
    /// No token, or more than 256.
    Count,
    /// A blind that is not a canonical, non-zero scalar.
    Blind,
    /// The platform has no working source of randomness.
    NoRandomness,
}

impl From<NoRandomness> for BatchError {
    fn from(_: NoRandomness) -> Self {
        Self::NoRandomness
    }
}

/// A batch the device requests (section 3.3): for each token its nonce,
/// input and blind, kept in memory only until the answer, and the blinded
/// elements it sends.
pub struct Batch {
    key: PeerKey,
    nonces: Vec<Zeroizing<[u8; NONCE_BYTES]>>,
    inputs: Vec<Zeroizing<Vec<u8>>>,
    clients: Vec<VoprfClient<Suite>>,
    blinded: Vec<[u8; ELEMENT_BYTES]>,
}

impl core::fmt::Debug for Batch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Batch")
            .field("key_id", &self.key.id)
            .field("tokens", &self.blinded.len())
            .finish_non_exhaustive()
    }
}

impl Batch {
    /// Section 3.3, step 2, under the issuing key of the device's latest
    /// key list, with each token's nonce and blind given.
    ///
    /// # Errors
    ///
    /// [`BatchError::Count`] for no draw or more than 256;
    /// [`BatchError::Blind`] for a blind that is not a canonical, non-zero
    /// scalar.
    pub fn new_with(
        key: &PeerKey,
        draws: &[([u8; NONCE_BYTES], [u8; SCALAR_BYTES])],
    ) -> Result<Self, BatchError> {
        if draws.is_empty() || draws.len() > MAX_BATCH {
            return Err(BatchError::Count);
        }
        let mut batch = Self {
            key: *key,
            nonces: Vec::with_capacity(draws.len()),
            inputs: Vec::with_capacity(draws.len()),
            clients: Vec::with_capacity(draws.len()),
            blinded: Vec::with_capacity(draws.len()),
        };
        for (nonce, blind) in draws {
            let input = token_input(&key.id, nonce);
            let (client, blinded) =
                suite::blind_with(&input, blind).map_err(|_| BatchError::Blind)?;
            batch.nonces.push(Zeroizing::new(*nonce));
            batch.inputs.push(input);
            batch.clients.push(client);
            batch.blinded.push(blinded);
        }
        Ok(batch)
    }

    /// A batch of `count` tokens, each nonce and blind drawn from the
    /// platform.
    ///
    /// # Errors
    ///
    /// [`BatchError::Count`]; [`BatchError::NoRandomness`].
    pub fn new(key: &PeerKey, count: usize) -> Result<Self, BatchError> {
        if count == 0 || count > MAX_BATCH {
            return Err(BatchError::Count);
        }
        let mut draws = Zeroizing::new(Vec::with_capacity(count));
        for _ in 0..count {
            let nonce = frasil_crypto::random_bytes::<NONCE_BYTES>()?;
            let blind = suite::random_scalar().map_err(|_| BatchError::NoRandomness)?;
            draws.push((*nonce, *blind));
        }
        Self::new_with(key, &draws)
    }

    /// The key the batch is drawn under.
    pub fn key(&self) -> &PeerKey {
        &self.key
    }

    /// The blinded elements, in order.
    pub fn blinded(&self) -> &[[u8; ELEMENT_BYTES]] {
        &self.blinded
    }

    /// Section 3.3, step 3: the `TokenRequest`. For a grant draw the
    /// caller sends at most the grant's `tokens` elements; it never reads
    /// the grant.
    pub fn request(&self, request: u64, draw: Draw) -> TokenRequest {
        TokenRequest {
            request,
            draw,
            key_id: self.key.id,
            blinded: self.blinded.clone(),
        }
    }

    /// Section 3.5's checks of the answer to `TokenRequest` number
    /// `request`, in order, then each token finished with `Finalize`: the
    /// first m tokens, m the elements the peer evaluated.
    ///
    /// # Errors
    ///
    /// `Malformed` at step 1 or 2; `BadProof` at step 3. A device that
    /// receives `BadProof` drops the batch and reports the peer.
    pub fn finish(&self, map: &Map, request: u64) -> Result<Vec<Token>, TokenClass> {
        // 1.
        let issue = TokenIssue::read(map, request, self.blinded.len())?;
        let count = issue.evaluated.len();
        // 2.
        for element in &issue.evaluated {
            suite::deserialize_element(element).map_err(|_| malformed())?;
        }
        // 3, then Finalize.
        let inputs: Vec<&[u8]> = self.inputs[..count].iter().map(|i| i.as_slice()).collect();
        let outputs = suite::finalize_batch(
            &inputs,
            &self.clients[..count],
            &issue.evaluated,
            &issue.proof,
            self.key.element,
        )
        .map_err(|error| match error {
            SuiteError::Proof => TokenClass::BadProof,
            _ => malformed(),
        })?;
        Ok(self
            .nonces
            .iter()
            .zip(outputs.iter())
            .map(|(nonce, output)| Token::new(&self.key.id, nonce, output))
            .collect())
    }

    /// [`finish`](Self::finish) from the message's bytes.
    ///
    /// # Errors
    ///
    /// As [`finish`](Self::finish).
    pub fn finish_bytes(&self, bytes: &[u8], request: u64) -> Result<Vec<Token>, TokenClass> {
        let value = frasil_base::cbor::decode(bytes)?;
        self.finish(value.as_map()?, request)
    }
}
