//! The verifier's checks (ext-app-requests.md, "Verifying").
//!
//! ```text
//! verify_request(request, now), in order:
//!    1. Read the body whole, within the route's limit.             else the route's 413
//!    2. The token verifies; subject = its sub.                     else 401 unauthorized
//!    3. The headers: if none is present, Unsigned. Otherwise each
//!       value present is within its "at most", then of its shape,
//!       in the table's order; every required header is present
//!       and none is repeated (else Malformed). Then the
//!       signature's version byte is 0x01 and its scheme byte
//!       0x00, each checked only at version 1's length.             else UnsupportedVersion
//!    4. signer's Ed25519 key passes crypto.md's ed25519_valid;
//!       device = the device ID of signer.                          else InvalidKey
//!    5. audience, subject, method, path and query have their
//!       shapes.                                                    else Malformed
//!    6. The signature verifies strictly under that key over the
//!       statement, with the version and scheme bytes read in
//!       step 3.                                                    else BadSignature
//!    7. check_expiry(expires_at, now, signed_request_lifetime,
//!       signed_request_skew).                                      else its class
//!    8. With a nonce store: (device, nonce) is unseen; record
//!       it until expires_at + signed_request_skew.                 else Replayed
//!    9. The subject has no recorded person, or it is person_id.    else WrongPerson
//!   10. On the list delivery route: place the list delivery.       else BadListDelivery
//!   11. The merged list of person_id holds device as a signer.     else ListNeeded or NotASigner
//!   12. Record person_id as the subject's person if it has none.
//!       Run the route as subject, person_id and device. If heads
//!       name an event not placed, answer with X-Frasil-List-Needed: 1.
//! ```
//!
//! Steps 1 and 2 are the application's: it reads the body and checks the
//! token, and gives the verifier the token's subject in [`Request`]. Steps 3
//! to 8 need no state beyond the nonce store ([`Verifier::verify_signature`]);
//! steps 9 to 11 run only for a request that a key's holder signed, so
//! unsigned traffic changes and learns nothing.

use crate::delivery::{Placed, is_delivery, place_delivery};
use crate::errors::Refusal;
use crate::headers::{ReceivedHeaders, SignedHeaders};
use crate::state::{NonceStore, VerifierState};
use crate::statement::{Request, request_ok, statement};
use crate::{AGENT_WAITING_PERIOD, AppRequestClass, SIGNED_REQUEST_LIFETIME, SIGNED_REQUEST_SKEW};
use frasil_base::ErrorClass;
use frasil_base::time::check_expiry;
use frasil_crypto::device::DeviceId;
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::schemes::ed25519_verify_strict;
use frasil_identity::Kind;

/// A request the verifier accepted: the route then holds a device ID and a
/// person ID it can trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The signer's device ID, of its `ed` and `kc`: the device the route
    /// runs with.
    pub device: DeviceId,
    /// The person ID.
    pub person_id: [u8; 32],
    /// The signer's kind: a device or a passkey member.
    pub kind: Kind,
    /// The request's expiry.
    pub expires_at: u64,
    /// The heads name an event the verifier has not placed: the answer
    /// carries `X-Frasil-List-Needed: 1`.
    pub list_needed: bool,
    /// The verifier recorded the person for the subject at this request.
    pub recorded_person: bool,
    /// On the list delivery route, what placing the list delivery did.
    pub delivery: Option<Placed>,
}

/// A verifier's configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verifier {
    /// A verifier that implements ext-recovery-agent.md lets a list member
    /// rooted in an agent sign once this long has passed since its own first
    /// sight of the `add`: `agent_waiting_period`'s default, since it has no
    /// space policy. `None` for a verifier that does not, which waits for a
    /// `confirm`.
    pub agent_waiting_period: Option<u64>,
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            agent_waiting_period: Some(AGENT_WAITING_PERIOD),
        }
    }
}

impl Verifier {
    /// Steps 3 to 12 of `verify_request`, at the verifier's wall clock `now`
    /// (`None` when it is not known). A nonce, a list delivery and a first
    /// record change `state` and `nonces`.
    ///
    /// # Errors
    ///
    /// The refusal of the first step that fails.
    pub fn verify<S: VerifierState + ?Sized>(
        &self,
        headers: &ReceivedHeaders<'_>,
        request: &Request<'_>,
        state: &mut S,
        nonces: Option<&mut dyn NonceStore>,
        now: Option<u64>,
    ) -> Result<Verified, Refusal> {
        let (signed, now) = self.verify_signature(headers, request, nonces, now)?;
        let device = signed.signer.device_id();
        let subject = request.subject;
        // 9. The recorded person.
        let recorded = state.recorded_person(subject);
        if recorded.is_some_and(|person| person != signed.person_id) {
            return Err(AppRequestClass::WrongPerson.into());
        }
        // 10. The list delivery.
        let delivery = if is_delivery(request.method, request.path) {
            Some(place_delivery(state, &signed.person_id, request.body, now)?)
        } else {
            None
        };
        // 11. The signer.
        let held = state.list(&signed.person_id);
        let lacking = held.is_none_or(|held| signed.heads.iter().any(|&id| !held.holds(id)));
        let kind = held.and_then(|held| held.signer(&device, now, self.agent_waiting_period));
        let Some(kind) = kind else {
            return Err(if lacking {
                AppRequestClass::ListNeeded
            } else {
                AppRequestClass::NotASigner
            }
            .into());
        };
        // 12. The record.
        if recorded.is_none() {
            state.record_person(subject, signed.person_id);
        }
        Ok(Verified {
            device,
            person_id: signed.person_id,
            kind,
            expires_at: signed.expires_at,
            list_needed: lacking,
            recorded_person: recorded.is_none(),
            delivery,
        })
    }

    /// Steps 3 to 8 of `verify_request`, which need no state but the nonce
    /// store: the headers, read, and the verifier's wall clock, known.
    ///
    /// # Errors
    ///
    /// The refusal of the first step that fails.
    pub fn verify_signature(
        &self,
        headers: &ReceivedHeaders<'_>,
        request: &Request<'_>,
        nonces: Option<&mut dyn NonceStore>,
        now: Option<u64>,
    ) -> Result<(SignedHeaders, u64), Refusal> {
        // 3. The headers.
        let signed = SignedHeaders::read(headers)?;
        // 4. The signer's Ed25519 key, before any signature by it is
        // considered; the device is the device ID of ed and kc.
        ed25519_valid(&signed.signer.ed.0).map_err(|_| ErrorClass::InvalidKey)?;
        let device = signed.signer.device_id();
        // 5. The shapes of the verifier's and the request's parts; the
        // verifier's own audience among them.
        if !request_ok(request) {
            return Err(ErrorClass::Malformed.into());
        }
        // 6. The signature, strictly.
        let message = statement(
            request,
            &signed.person_id,
            &signed.signer,
            signed.expires_at,
            &signed.nonce,
            &signed.heads,
        )?;
        if !ed25519_verify_strict(&signed.signer.ed.0, &message, &signed.signature) {
            return Err(ErrorClass::BadSignature.into());
        }
        // 7. The time, told only to the holder of a key that signed.
        check_expiry(
            signed.expires_at,
            now,
            SIGNED_REQUEST_LIFETIME,
            SIGNED_REQUEST_SKEW,
        )
        .map_err(Refusal::Expiry)?;
        let now = now.ok_or(Refusal::Expiry(ErrorClass::Expired))?;
        // 8. The nonce, at a stateful verifier.
        if let Some(nonces) = nonces {
            let until = signed.expires_at.saturating_add(SIGNED_REQUEST_SKEW);
            if !nonces.check_and_record(&device, &signed.nonce, until, now) {
                return Err(ErrorClass::Replayed.into());
            }
        }
        Ok((signed, now))
    }
}
