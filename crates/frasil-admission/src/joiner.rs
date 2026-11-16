//! The joiner (admission.md, "The joiner").
//!
//! ```text
//! start:
//!   1. display_J is at most 256 bytes of UTF-8.                          else Malformed
//!   2. Draw request and nonce_J, and a fresh X-Wing key pair eph_J.
//!      expires_at = the wall clock + admission_code_lifetime.
//!   3. Send the Request. Keep J_fields, nonce_J and the seed in memory only.
//!
//! on a Response:
//!   4. Ignore it past expires_at, after a Response was accepted, or if it
//!      does not open and read, if eph_I fails crypto.md's X-Wing key
//!      check, or if its offer does not suit this joiner.
//!   5. Accept it. Send the Reveal. Show the code and display_I.
//!   6. If the person says the codes differ: send Cancel and forget the
//!      request. If they match, a person joiner sends its List.
//! ```
//!
//! The joiner reveals once per request, only after a Response, and only for
//! the first it accepts. It never reuses `request`, `nonce_J` or an
//! ephemeral key: a [`Joiner`] is one exchange.

use crate::bodies::{ListEvents, RequestBody, ResponseBody, RevealBody, RevealedKeys};
use crate::message::{MessageType, message, open_body, read_message, sealed_message_with};
use crate::offer::read_offer;
use crate::params::{ADMISSION_CODE_LIFETIME, NONCE_BYTES, REQUEST_BYTES};
use crate::transcript::{Code, IFields, JFields, JoinerPart, code_hash, commitment, heads_hash};
use crate::welcome::Welcome;
use crate::{AdmissionClass, Ctx, JoinerType, display_ok, malformed};
use frasil_base::ErrorClass;
use frasil_crypto::device::DeviceKeys;
use frasil_crypto::keys::xwing_valid;
use frasil_crypto::schemes::Signer;
use frasil_crypto::sizes::{XWING_PUBLIC, XWING_SEED};
use frasil_crypto::wrap::{ENCAPSULATION_RANDOMNESS, xwing_public};
use frasil_events::EventId;
use frasil_identity::Kind;
use zeroize::Zeroizing;

/// What joins, with what it reveals.
pub enum JoinerKeys<'k> {
    /// A device: a person's new device (ctx `0x01`), or a device member or a
    /// guest (ctx `0x02`). It reveals its three public keys, whose device ID
    /// `J_fields` commits to; a new device of a person signs its possession
    /// proof after the Response.
    Device {
        /// Its signer, which carries its X-Wing key.
        signer: &'k Signer,
    },
    /// A person that joins a space (ctx `0x02`), through one of its
    /// devices.
    Person {
        /// The person ID.
        person: [u8; 32],
        /// Its list's heads, as the device holds them.
        heads: Vec<EventId>,
    },
}

impl core::fmt::Debug for JoinerKeys<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Device { signer, .. } => f
                .debug_struct("Device")
                .field("device", signer.device_id())
                .finish_non_exhaustive(),
            Self::Person { person, heads } => f
                .debug_struct("Person")
                .field("person", person)
                .field("heads", heads)
                .finish(),
        }
    }
}

impl JoinerKeys<'_> {
    /// `joiner_type || joiner`: a device's device ID.
    ///
    /// # Errors
    ///
    /// `InvalidKey` for a device signer with no X-Wing key, which no
    /// admission can reach.
    fn part(&self) -> Result<JoinerPart, AdmissionClass> {
        Ok(match self {
            Self::Device { signer } => {
                signer.keys().xwing().ok_or(ErrorClass::InvalidKey)?;
                JoinerPart::Device(*signer.device_id())
            }
            Self::Person { person, heads } => JoinerPart::Person {
                person: *person,
                heads_hash: heads_hash(person, heads)?,
            },
        })
    }
}

/// What the joiner draws for one exchange, and what it chose.
#[derive(Clone)]
pub struct JoinerStart {
    /// `ctx`.
    pub ctx: Ctx,
    /// `request`, 16 random bytes.
    pub request: [u8; REQUEST_BYTES],
    /// `expires_at`: the wall clock plus `admission_code_lifetime`
    /// ([`expires_at`]).
    pub expires_at: u64,
    /// `nonce_J`, 32 random bytes.
    pub nonce: Zeroizing<[u8; NONCE_BYTES]>,
    /// The seed of `eph_J`, 32 random bytes.
    pub eph_seed: Zeroizing<[u8; XWING_SEED]>,
    /// `display_J`.
    pub display: String,
    /// `channel`: the direct connection's channel value, or empty through a
    /// mailbox.
    pub channel: Vec<u8>,
}

impl core::fmt::Debug for JoinerStart {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JoinerStart")
            .field("ctx", &self.ctx)
            .field("request", &self.request)
            .field("expires_at", &self.expires_at)
            .field("display", &self.display)
            .finish_non_exhaustive()
    }
}

/// `expires_at` for a Request made at this wall clock reading.
pub const fn expires_at(now_wall: u64) -> u64 {
    now_wall.saturating_add(ADMISSION_CODE_LIFETIME)
}

/// What the joiner sends and shows after it accepts a Response.
#[derive(Debug, Clone)]
pub struct Revealed {
    /// The Reveal message.
    pub message: Vec<u8>,
    /// `I_fields`, from the Response.
    pub i_fields: IFields,
    /// The code hash.
    pub code_hash: [u8; 32],
    /// The code to show, with `display_I`.
    pub code: Code,
}

/// One exchange, at the joiner.
pub struct Joiner<'k> {
    ctx: Ctx,
    request: [u8; REQUEST_BYTES],
    expires_at: u64,
    nonce: Zeroizing<[u8; NONCE_BYTES]>,
    eph_seed: Zeroizing<[u8; XWING_SEED]>,
    eph: Box<[u8; XWING_PUBLIC]>,
    display: String,
    channel: Vec<u8>,
    keys: JoinerKeys<'k>,
    part: JoinerPart,
    expected_person: Option<[u8; 32]>,
    response: Option<ResponseBody>,
}

impl core::fmt::Debug for Joiner<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Joiner")
            .field("ctx", &self.ctx)
            .field("request", &self.request)
            .field("expires_at", &self.expires_at)
            .field("display", &self.display)
            .field("keys", &self.keys)
            .field("expected_person", &self.expected_person)
            .finish_non_exhaustive()
    }
}

impl<'k> Joiner<'k> {
    /// Steps 1 to 3: the joiner and its Request message.
    ///
    /// # Errors
    ///
    /// `Malformed` for a display over 256 bytes, a person joiner outside
    /// ctx `0x02` or with no heads or more than 256, or a channel that is
    /// neither empty nor 32 bytes.
    pub fn start_with(
        start: JoinerStart,
        keys: JoinerKeys<'k>,
    ) -> Result<(Self, Vec<u8>), AdmissionClass> {
        if !display_ok(&start.display) {
            return Err(malformed());
        }
        if !(start.channel.is_empty() || start.channel.len() == 32) {
            return Err(malformed());
        }
        let part = keys.part()?;
        if part.joiner_type() == JoinerType::Person && start.ctx != Ctx::Space {
            return Err(malformed());
        }
        let joiner = Self {
            ctx: start.ctx,
            request: start.request,
            expires_at: start.expires_at,
            eph: Box::new(xwing_public(&start.eph_seed)),
            nonce: start.nonce,
            eph_seed: start.eph_seed,
            display: start.display,
            channel: start.channel,
            keys,
            part,
            expected_person: None,
            response: None,
        };
        let body = RequestBody {
            ctx: joiner.ctx,
            expires_at: joiner.expires_at,
            commitment: joiner.commitment(),
            eph: joiner.eph.clone(),
        };
        let request = message(MessageType::Request, &joiner.request, &body.encode());
        Ok((joiner, request))
    }

    /// `request`.
    pub fn request(&self) -> &[u8; REQUEST_BYTES] {
        &self.request
    }

    /// `expires_at`.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// `eph_J`.
    pub fn eph(&self) -> &[u8; XWING_PUBLIC] {
        &self.eph
    }

    /// `J_fields`.
    pub fn j_fields(&self) -> JFields {
        JFields {
            ctx: self.ctx,
            request: self.request,
            expires_at: self.expires_at,
            eph: self.eph.clone(),
            joiner: self.part,
            display: self.display.clone(),
        }
    }

    /// The commitment the Request carries.
    pub fn commitment(&self) -> [u8; 32] {
        commitment(&self.j_fields().encode(), &self.nonce)
    }

    /// The Response this joiner accepted, if it accepted one.
    pub fn response(&self) -> Option<&ResponseBody> {
        self.response.as_ref()
    }

    /// Makes a new device (ctx `0x01`) expect `person`: a Response for
    /// another person is refused before the joiner signs anything over its
    /// `log` (admission.md, 3.1 The joiner, step 5).
    pub fn expect_person(&mut self, person: [u8; 32]) {
        self.expected_person = Some(person);
    }

    /// Steps 4 to 6, at the wall clock `now`: the Reveal and the code, or
    /// `None` for a Response the joiner ignores or refuses.
    pub fn on_response_with(
        &mut self,
        response: &[u8],
        now: u64,
        encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
    ) -> Option<Revealed> {
        self.accept_response_with(response, now, encapsulation_randomness)
            .ok()
            .flatten()
    }

    /// Steps 4 to 6, at the wall clock `now`: the Reveal and the code;
    /// `Ok(None)` for a Response the joiner ignores (step 4).
    ///
    /// # Errors
    ///
    /// `WrongPerson` for a ctx `0x01` Response for another person than the
    /// one [`Joiner::expect_person`] named (step 5): the joiner then sends
    /// [`Joiner::cancel`], and has revealed nothing.
    pub fn accept_response_with(
        &mut self,
        response: &[u8],
        now: u64,
        encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
    ) -> Result<Option<Revealed>, AdmissionClass> {
        let Some(body) = self.read_response(response, now) else {
            return Ok(None);
        };
        if self.ctx == Ctx::DeviceList
            && self
                .expected_person
                .is_some_and(|person| person != body.log)
        {
            return Err(AdmissionClass::WrongPerson);
        }
        Ok(self.reveal(body, encapsulation_randomness))
    }

    /// Step 4: the Response's body, unless the joiner ignores it.
    fn read_response(&self, response: &[u8], now: u64) -> Option<ResponseBody> {
        let read = read_message(response).ok()?;
        if read.kind != MessageType::Response || read.request != self.request {
            return None;
        }
        if now > self.expires_at || self.response.is_some() {
            return None;
        }
        let plaintext = open_body(
            MessageType::Response,
            &self.request,
            &self.eph_seed,
            read.body,
        )
        .ok()?;
        let body = ResponseBody::read(&plaintext).ok()?;
        xwing_valid(&body.eph[..]).ok()?;
        read_offer(&body.offer, self.ctx, self.part.joiner_type()).ok()?;
        Some(body)
    }

    /// Step 6: accepts the Response, and makes the Reveal and the code.
    fn reveal(
        &mut self,
        body: ResponseBody,
        encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
    ) -> Option<Revealed> {
        let reveal = self.reveal_body(&body);
        let i_fields = IFields {
            ctx: self.ctx,
            log: body.log,
            heads_hash: body.heads_hash(),
            approver: body.approver,
            eph: body.eph.clone(),
            offer: body.offer.clone(),
            display: body.display.clone(),
        };
        let digest = code_hash(
            &self.j_fields().encode(),
            &i_fields.encode(),
            &self.channel,
            &self.nonce,
            &body.nonce,
        );
        let message = sealed_message_with(
            MessageType::Reveal,
            &self.request,
            &body.eph[..],
            &reveal.encode(),
            encapsulation_randomness,
        )
        .ok()?;
        self.response = Some(body);
        Some(Revealed {
            message,
            i_fields,
            code_hash: digest,
            code: Code::of(&digest),
        })
    }

    /// The Reveal's body: a device reveals its three public keys, and for
    /// ctx `0x01` signs only now the possession statement over the
    /// Response's `log`, with its `approver` as adder. A device joining a
    /// space signs nothing over its keys.
    fn reveal_body(&self, response: &ResponseBody) -> RevealBody {
        match &self.keys {
            JoinerKeys::Device { signer } => {
                let keys = RevealedKeys::of(&DeviceKeys {
                    ed: *signer.identity_key(),
                    keys: signer.keys().clone(),
                })
                .expect("a device joiner has an X-Wing key, checked at its start");
                let possession = match self.ctx {
                    Ctx::Space => None,
                    Ctx::DeviceList => {
                        let statement = frasil_identity::possession::statement(
                            &response.log,
                            &response.approver,
                            Kind::Device,
                            signer.identity_key(),
                            signer.mldsa_public(),
                            signer.keys().xwing(),
                        );
                        Some(frasil_identity::possession::prove(signer, &statement))
                    }
                };
                RevealBody::Device {
                    nonce: *self.nonce,
                    keys,
                    possession,
                    display: self.display.clone(),
                }
            }
            JoinerKeys::Person { person, heads } => RevealBody::Person {
                nonce: *self.nonce,
                display: self.display.clone(),
                person: *person,
                heads: crate::sorted_heads(heads),
            },
        }
    }

    /// Step 7, when the person says the codes differ, or a refusal at step
    /// 5: the Cancel to send.
    /// The joiner then forgets the request.
    pub fn cancel(&self) -> Vec<u8> {
        message(MessageType::Cancel, &self.request, &[])
    }

    /// Step 7 for a person joiner whose person confirmed that the codes
    /// match: its List, every event of its list it holds, sealed to
    /// `eph_I`.
    ///
    /// # Errors
    ///
    /// `Malformed` before a Response was accepted, for a device joiner, or
    /// for no events.
    pub fn list_with(
        &self,
        events: Vec<Vec<u8>>,
        encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
    ) -> Result<Vec<u8>, AdmissionClass> {
        let response = self.response.as_ref().ok_or_else(malformed)?;
        if !matches!(self.keys, JoinerKeys::Person { .. }) || events.is_empty() {
            return Err(malformed());
        }
        sealed_message_with(
            MessageType::List,
            &self.request,
            &response.eph[..],
            &ListEvents { events }.encode(),
            encapsulation_randomness,
        )
    }

    /// Opens a Result for this exchange: its plaintext, a welcome for ctx
    /// `0x02` ([`crate::welcome::Welcome::read`], then
    /// [`crate::grant`]), or the list's events for ctx `0x01`
    /// ([`crate::new_device::check_list_result`]).
    ///
    /// # Errors
    ///
    /// The message's class; `Malformed` for another type, another request
    /// or before a Response was accepted; the seal's classes.
    pub fn open_result(&self, result: &[u8]) -> Result<Zeroizing<Vec<u8>>, AdmissionClass> {
        let read = read_message(result)?;
        if read.kind != MessageType::Result
            || read.request != self.request
            || self.response.is_none()
        {
            return Err(malformed());
        }
        open_body(
            MessageType::Result,
            &self.request,
            &self.eph_seed,
            read.body,
        )
    }

    /// A person's new device on a direct connection, once it accepted the
    /// Result (admission.md, "A person's new device", "Over a direct
    /// connection"), checks a Welcome, steps 1 and 2:
    ///
    /// ```text
    /// 1. The message reads, its request is the exchange's, and its body
    ///    opens and reads.                                         else that class
    /// 2. Its approver is the Response's approver.                 else WrongApprover
    /// ```
    ///
    /// Step 3 is the device's own resolution of the space.
    ///
    /// # Errors
    ///
    /// The message's class; `Malformed` for another type, another request
    /// or before a Response was accepted; the seal's classes; the
    /// welcome's; `WrongApprover`.
    pub fn on_welcome(&self, message: &[u8]) -> Result<Welcome, AdmissionClass> {
        let read = read_message(message)?;
        let response = self.response.as_ref().ok_or_else(malformed)?;
        if read.kind != MessageType::Welcome || read.request != self.request {
            return Err(malformed());
        }
        let plaintext = open_body(
            MessageType::Welcome,
            &self.request,
            &self.eph_seed,
            read.body,
        )?;
        let welcome = Welcome::read(&plaintext)?;
        if welcome.approver != response.approver {
            return Err(AdmissionClass::WrongApprover);
        }
        Ok(welcome)
    }
}
