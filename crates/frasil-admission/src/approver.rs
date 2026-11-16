//! The approver (admission.md, "The approver").
//!
//! ```text
//! on a Request:
//!   1. The message and its body read.                                   else that class
//!   2. check_expiry(expires_at, wall clock, admission_code_lifetime,
//!      admission_code_skew) (overview.md).                              else that class
//!   3. request has not been answered.                                   else Replayed
//!   4. ctx is what this approver is doing.                              else Malformed
//!   5. eph_J passes crypto.md's X-Wing key check.                       else InvalidKey
//!   6. Draw nonce_I and a fresh X-Wing key pair, now. Remember request
//!      as answered until expires_at + 60. Send the Response.
//!
//! on the Reveal (one per request; after any failure the request ends):
//!   7. The wall clock is known and not past expires_at.                 else Expired
//!   8. The body opens and reads.                                        else Decrypt / Malformed
//!   9. Rebuild J_fields, a device's joiner the device ID of its
//!      revealed keys; the commitment matches.                           else CommitmentMismatch
//!  10. The offer suits the joiner's type.                               else Malformed
//!  11. A device: its three public keys pass crypto.md's checks.        else InvalidKey
//!  12. A device, ctx 0x01: possession verifies.                         else BadPossession
//!  13. Show display_J and the code; the person confirms that the
//!      joiner shows the same code.                                      else Cancel; Mismatch
//!  14. A person: wait for the List.
//!  15. Still not past expires_at: sign the grant (ctx 0x02, the offer's
//!      fields, via = code) or the add (ctx 0x01), and send the Result. else Expired
//! ```
//!
//! A second Reveal for a request, or a Reveal for a request that has ended,
//! is ignored. Step 13 is the person's; steps 14 and 15 are
//! [`crate::new_device`]'s and [`crate::grant`]'s, then
//! [`Approver::result_with`].

use crate::bodies::{ListEvents, RequestBody, ResponseBody, RevealBody};
use crate::message::{MessageType, message, open_body, read_message, sealed_message_with};
use crate::offer::read_offer;
use crate::params::{
    ADMISSION_CODE_LIFETIME, ADMISSION_CODE_SKEW, MAILBOX_GRACE, NONCE_BYTES, REQUEST_BYTES,
};
use crate::transcript::{Code, IFields, JFields, code_hash, commitment, heads_hash};
use crate::{AdmissionClass, Ctx, display_ok, malformed};
use frasil_base::ErrorClass;
use frasil_base::time::check_expiry;
use frasil_crypto::device::DeviceId;
use frasil_crypto::keys::xwing_valid;
use frasil_crypto::sizes::{XWING_PUBLIC, XWING_SEED};
use frasil_crypto::wrap::{ENCAPSULATION_RANDOMNESS, xwing_public};
use frasil_events::EventId;
use frasil_identity::Kind;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// What the approver is doing, and what it answers every Request with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverSide {
    /// I's device ID.
    pub approver: DeviceId,
    /// `ctx`.
    pub ctx: Ctx,
    /// `log`: the space ID, or for ctx `0x01` the person ID.
    pub log: [u8; 32],
    /// The heads of that log in I's view.
    pub heads: Vec<EventId>,
    /// The offer's bytes: an [`crate::Offer`]'s for ctx `0x02`, empty for
    /// ctx `0x01`.
    pub offer: Vec<u8>,
    /// `display_I`.
    pub display: String,
    /// `channel`: the direct connection's channel value, or empty through a
    /// mailbox.
    pub channel: Vec<u8>,
}

/// What the approver draws for one Request, at step 6.
#[derive(Clone)]
pub struct ResponseDraw {
    /// `nonce_I`.
    pub nonce: Zeroizing<[u8; NONCE_BYTES]>,
    /// The seed of `eph_I`.
    pub eph_seed: Zeroizing<[u8; XWING_SEED]>,
    /// X-Wing's encapsulation randomness for the Response's seal.
    pub encapsulation: Zeroizing<[u8; ENCAPSULATION_RANDOMNESS]>,
}

impl core::fmt::Debug for ResponseDraw {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponseDraw").finish_non_exhaustive()
    }
}

/// A Reveal that passed steps 7 to 12.
#[derive(Debug, Clone)]
pub struct ApprovedReveal {
    /// The request.
    pub request: [u8; REQUEST_BYTES],
    /// The Reveal's body.
    pub reveal: RevealBody,
    /// `J_fields`, rebuilt.
    pub j_fields: JFields,
    /// The code hash.
    pub code_hash: [u8; 32],
    /// The code to show, with `display_J`, for step 13.
    pub code: Code,
}

struct Answered {
    body: RequestBody,
    nonce: Zeroizing<[u8; NONCE_BYTES]>,
    eph_seed: Zeroizing<[u8; XWING_SEED]>,
    eph: Box<[u8; XWING_PUBLIC]>,
    ended: bool,
}

impl core::fmt::Debug for Answered {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Answered")
            .field("body", &self.body)
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

/// The approver: an active list member of the person (ctx `0x01`) or an
/// administering device of the space (ctx `0x02`).
#[derive(Debug)]
pub struct Approver {
    side: ApproverSide,
    heads_hash: [u8; 32],
    answered: BTreeMap<[u8; REQUEST_BYTES], Answered>,
}

impl Approver {
    /// An approver.
    ///
    /// # Errors
    ///
    /// `Malformed` for no heads or more than 256, a display over 256 bytes,
    /// or a channel that is neither empty nor 32 bytes.
    pub fn new(side: ApproverSide) -> Result<Self, AdmissionClass> {
        if !display_ok(&side.display) || !(side.channel.is_empty() || side.channel.len() == 32) {
            return Err(malformed());
        }
        let heads_hash = heads_hash(&side.log, &side.heads)?;
        Ok(Self {
            side,
            heads_hash,
            answered: BTreeMap::new(),
        })
    }

    /// What this approver answers with.
    pub fn side(&self) -> &ApproverSide {
        &self.side
    }

    /// `I_fields` of an answered request.
    pub fn i_fields(&self, request: &[u8; REQUEST_BYTES]) -> Option<IFields> {
        let answered = self.answered.get(request)?;
        Some(self.i_fields_with(&answered.eph))
    }

    fn i_fields_with(&self, eph: &[u8; XWING_PUBLIC]) -> IFields {
        IFields {
            ctx: self.side.ctx,
            log: self.side.log,
            heads_hash: self.heads_hash,
            approver: self.side.approver,
            eph: Box::new(*eph),
            offer: self.side.offer.clone(),
            display: self.side.display.clone(),
        }
    }

    /// Steps 1 to 6, at the wall clock `now` (`None` when it is not
    /// known): the Response message.
    ///
    /// # Errors
    ///
    /// In order: the message's class, or `Malformed` for another type; the
    /// body's; `check_expiry`'s; `Replayed`; `Malformed` for another
    /// `ctx`; `InvalidKey`.
    pub fn on_request_with(
        &mut self,
        request: &[u8],
        now: Option<u64>,
        draw: ResponseDraw,
    ) -> Result<Vec<u8>, AdmissionClass> {
        let read = read_message(request)?;
        if read.kind != MessageType::Request {
            return Err(malformed());
        }
        let body = RequestBody::read(read.body)?;
        check_expiry(
            body.expires_at,
            now,
            ADMISSION_CODE_LIFETIME,
            ADMISSION_CODE_SKEW,
        )?;
        if self.answered.contains_key(&read.request) {
            return Err(ErrorClass::Replayed.into());
        }
        if body.ctx != self.side.ctx {
            return Err(malformed());
        }
        xwing_valid(&body.eph[..])?;
        let eph = Box::new(xwing_public(&draw.eph_seed));
        let response = ResponseBody {
            nonce: *draw.nonce,
            log: self.side.log,
            heads: self.side.heads.clone(),
            approver: self.side.approver,
            eph: eph.clone(),
            offer: self.side.offer.clone(),
            display: self.side.display.clone(),
        };
        let out = sealed_message_with(
            MessageType::Response,
            &read.request,
            &body.eph[..],
            &response.encode(),
            &draw.encapsulation,
        )?;
        self.answered.insert(
            read.request,
            Answered {
                body,
                nonce: draw.nonce,
                eph_seed: draw.eph_seed,
                eph,
                ended: false,
            },
        );
        Ok(out)
    }

    /// Steps 7 to 12, at the wall clock `now`: the Reveal and its code for
    /// step 13, or `None` for a Reveal the approver ignores: a second one,
    /// or one for a request that has ended.
    ///
    /// # Errors
    ///
    /// The message's class; `Malformed` for another type or a request never
    /// answered; then, ending the request, `Expired`, `Decrypt`,
    /// `Malformed`, `CommitmentMismatch`, `Malformed`, `InvalidKey` and
    /// `BadPossession`, in order.
    pub fn on_reveal(
        &mut self,
        reveal: &[u8],
        now: Option<u64>,
    ) -> Result<Option<ApprovedReveal>, AdmissionClass> {
        let read = read_message(reveal)?;
        let ctx = self.side.ctx;
        let (expires_at, eph_j, expected, eph_seed, nonce_i, eph_i) = {
            let answered = self.answered.get_mut(&read.request);
            let Some(answered) = answered.filter(|_| read.kind == MessageType::Reveal) else {
                return Err(malformed());
            };
            if answered.ended {
                return Ok(None);
            }
            answered.ended = true;
            (
                answered.body.expires_at,
                answered.body.eph.clone(),
                answered.body.commitment,
                answered.eph_seed.clone(),
                answered.nonce.clone(),
                answered.eph.clone(),
            )
        };
        // 7.
        if now.is_none_or(|now| now > expires_at) {
            return Err(ErrorClass::Expired.into());
        }
        // 8.
        let plaintext = open_body(MessageType::Reveal, &read.request, &eph_seed, read.body)?;
        let body = RevealBody::read(&plaintext, ctx)?;
        // 9.
        let j_fields = JFields {
            ctx,
            request: read.request,
            expires_at,
            eph: eph_j,
            joiner: body.joiner_part(),
            display: body.display().to_owned(),
        };
        let j_bytes = j_fields.encode();
        if commitment(&j_bytes, body.nonce()) != expected {
            return Err(AdmissionClass::CommitmentMismatch);
        }
        // 10.
        read_offer(&self.side.offer, ctx, j_fields.joiner.joiner_type())?;
        // 11. A device's three public keys pass crypto.md's checks.
        if let RevealBody::Device {
            keys, possession, ..
        } = &body
        {
            let checked = keys.checked()?;
            // 12. For ctx 0x01, its possession proof over the person ID,
            // with the approver as adder. A device joining a space signs
            // nothing over its keys: the code authenticated its device ID.
            if ctx == Ctx::DeviceList {
                let statement = frasil_identity::possession::statement(
                    &self.side.log,
                    &self.side.approver,
                    Kind::Device,
                    &checked.ed,
                    checked.keys.mldsa(),
                    checked.keys.xwing(),
                );
                frasil_identity::possession::verify(
                    &checked.ed,
                    &checked.keys,
                    &statement,
                    possession.as_deref().ok_or_else(malformed)?,
                )
                .map_err(|_| AdmissionClass::from(ErrorClass::BadPossession))?;
            }
        }
        let digest = code_hash(
            &j_bytes,
            &self.i_fields_with(&eph_i).encode(),
            &self.side.channel,
            body.nonce(),
            &nonce_i,
        );
        Ok(Some(ApprovedReveal {
            request: read.request,
            reveal: body,
            j_fields,
            code_hash: digest,
            code: Code::of(&digest),
        }))
    }

    /// Opens a person joiner's List (section 3.5, step 1).
    ///
    /// # Errors
    ///
    /// The message's class; `Malformed` for another type or an unknown
    /// request; the seal's classes; the body's.
    pub fn open_list(&self, list: &[u8]) -> Result<ListEvents, AdmissionClass> {
        let read = read_message(list)?;
        let answered = self
            .answered
            .get(&read.request)
            .filter(|_| read.kind == MessageType::List)
            .ok_or_else(malformed)?;
        let plaintext = open_body(
            MessageType::List,
            &read.request,
            &answered.eph_seed,
            read.body,
        )?;
        ListEvents::read(&plaintext)
    }

    /// Step 15: the Result, sealed to `eph_J`, while the wall clock `now` is
    /// known and not past `expires_at`. `plaintext` is a welcome for ctx
    /// `0x02`, or the list's events with the new `add` for ctx `0x01`.
    ///
    /// # Errors
    ///
    /// `Malformed` for an unknown request; `Expired`; the seal's class.
    pub fn result_with(
        &self,
        request: &[u8; REQUEST_BYTES],
        plaintext: &[u8],
        now: Option<u64>,
        encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
    ) -> Result<Vec<u8>, AdmissionClass> {
        let answered = self.answered.get(request).ok_or_else(malformed)?;
        if now.is_none_or(|now| now > answered.body.expires_at) {
            return Err(ErrorClass::Expired.into());
        }
        sealed_message_with(
            MessageType::Result,
            request,
            &answered.body.eph[..],
            plaintext,
            encapsulation_randomness,
        )
    }

    /// A person's new device on a direct connection (admission.md, "A
    /// person's new device", "Over a direct connection"): a Welcome after
    /// the Result, `welcome` sealed to `eph_J`.
    ///
    /// # Errors
    ///
    /// `Malformed` for an unknown request; the seal's class.
    pub fn welcome_with(
        &self,
        request: &[u8; REQUEST_BYTES],
        welcome: &[u8],
        encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
    ) -> Result<Vec<u8>, AdmissionClass> {
        let answered = self.answered.get(request).ok_or_else(malformed)?;
        sealed_message_with(
            MessageType::Welcome,
            request,
            &answered.body.eph[..],
            welcome,
            encapsulation_randomness,
        )
    }

    /// Step 13, when the person says the codes differ: the Cancel to send.
    /// The approver then tells the person that the exchange may have been
    /// tampered with, and does not offer to retry it.
    pub fn cancel(&mut self, request: &[u8; REQUEST_BYTES]) -> Vec<u8> {
        if let Some(answered) = self.answered.get_mut(request) {
            answered.ended = true;
        }
        message(MessageType::Cancel, request, &[])
    }

    /// Forgets the requests answered whose `expires_at + 60` is before the
    /// wall clock `now`.
    pub fn forget_expired(&mut self, now: u64) {
        self.answered
            .retain(|_, answered| now <= answered.body.expires_at.saturating_add(MAILBOX_GRACE));
    }

    /// Whether a request was answered and is still remembered.
    pub fn has_answered(&self, request: &[u8; REQUEST_BYTES]) -> bool {
        self.answered.contains_key(request)
    }
}
