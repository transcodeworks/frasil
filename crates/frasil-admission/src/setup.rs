//! The setup code and setup (admission.md, "The setup code", "Setup").
//!
//! ```text
//! setup code = u8(1) || the device's device ID (32) || setup secret (16)                49 bytes
//! text       = "FRASIL-SETUP:" || base32(setup code)
//! setup tag  = SHA-256("frasil/admission/setup-tag/v1" || setup secret)[0..8]
//!
//! J_fields   = with ctx 0x02, expires_at 0, joiner type 0
//! mac        = HMAC(setup secret, "frasil/admission/setup/v1" || field(J_fields)
//!                                 || field(I_fields) || field(channel))
//! ```
//!
//! The administrator checks, in order ([`check_hello`]):
//!
//! ```text
//! 1. The text reads.                                                    else that class
//! 2. The Hello reads, and the device ID of its keys is the scanned
//!    one.                                                               else SetupMismatch
//! 3. Its keys pass crypto.md's checks.                                  else InvalidKey
//! 4. Send the Offer. Then sign a device grant with the offer's fields
//!    and via = code, and send the Result.
//! ```
//!
//! The device checks, in order ([`HeadlessDevice::on_offer`]):
//!
//! ```text
//! 1. It is not provisioned, and not bound to another Offer.             else Provisioned
//! 2. The Offer opens and reads; its request is this device's.           else Decrypt / Malformed
//! 3. The offer suits a device joiner.                                   else Malformed
//! 4. mac verifies, in constant time, over this connection's channel.    else BadMac
//! 5. Bind to this Offer: refuse every other until reset.
//! 6. On the Result: "Accepting a grant", with the Offer in place of the
//!    Response. A match provisions the device; it forgets the setup
//!    secret and stops announcing.
//! ```

use crate::bodies::{HelloBody, OfferBody, RevealedKeys};
use crate::message::{MessageType, message, open_body, read_message, sealed_message_with};
use crate::offer::Offer;
use crate::params::{
    REQUEST_BYTES, SETUP_CODE_BYTES, SETUP_SECRET_BYTES, SETUP_TAG_BYTES, VERSION,
};
use crate::transcript::{IFields, JFields, JoinerPart};
use crate::{AdmissionClass, Ctx, JoinerType, base32, malformed};
use frasil_base::ErrorClass;
use frasil_base::notation::push_field;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_crypto::labels::{ADMISSION_SETUP, ADMISSION_SETUP_TAG};
use frasil_crypto::primitives::{hmac_sha256, sha256};
use frasil_crypto::schemes::Signer;
use frasil_crypto::sizes::{XWING_PUBLIC, XWING_SEED};
use frasil_crypto::wrap::{ENCAPSULATION_RANDOMNESS, xwing_public};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The setup code text's prefix.
pub const PREFIX: &str = "FRASIL-SETUP:";

/// A setup code: the device's device ID and its setup secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupCode {
    /// The device's device ID, which commits to its three public keys.
    pub device: DeviceId,
    /// The setup secret, a bearer secret until provisioning.
    pub secret: Zeroizing<[u8; SETUP_SECRET_BYTES]>,
}

impl core::fmt::Debug for SetupCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SetupCode")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl SetupCode {
    /// The code's 49 bytes.
    pub fn encode(&self) -> [u8; SETUP_CODE_BYTES] {
        let mut out = [0; SETUP_CODE_BYTES];
        out[0] = VERSION;
        out[1..33].copy_from_slice(&self.device.0);
        out[33..].copy_from_slice(&self.secret[..]);
        out
    }

    /// The text a device prints or shows.
    pub fn text(&self) -> String {
        format!("{PREFIX}{}", base32::encode(&self.encode()))
    }

    /// Reads a setup code's text, in order.
    ///
    /// # Errors
    ///
    /// `Malformed` without the prefix or for base32 that does not re-encode
    /// to itself; `UnsupportedVersion` unless byte 0 is 1; `Malformed`
    /// unless it is 49 bytes.
    pub fn read(text: &str) -> Result<Self, AdmissionClass> {
        let body = text.strip_prefix(PREFIX).ok_or_else(malformed)?;
        let raw = base32::decode(body)?;
        if raw.first() != Some(&VERSION) {
            return Err(ErrorClass::UnsupportedVersion.into());
        }
        if raw.len() != SETUP_CODE_BYTES {
            return Err(malformed());
        }
        let device = DeviceId(raw[1..33].try_into().map_err(|_| malformed())?);
        let mut secret = Zeroizing::new([0; SETUP_SECRET_BYTES]);
        secret.copy_from_slice(&raw[33..]);
        Ok(Self { device, secret })
    }

    /// The setup tag.
    pub fn tag(&self) -> [u8; SETUP_TAG_BYTES] {
        setup_tag(&self.secret)
    }
}

/// The setup tag of a setup secret.
pub fn setup_tag(secret: &[u8; SETUP_SECRET_BYTES]) -> [u8; SETUP_TAG_BYTES] {
    let digest = sha256(&[ADMISSION_SETUP_TAG, secret]);
    let mut tag = [0; SETUP_TAG_BYTES];
    tag.copy_from_slice(&digest[..SETUP_TAG_BYTES]);
    tag
}

/// The name a device in setup mode announces nearby: `setup-` and the setup
/// tag in lower-case hex, 22 characters.
pub fn announced_name(secret: &[u8; SETUP_SECRET_BYTES]) -> String {
    format!(
        "setup-{}",
        frasil_base::notation::hex::encode(setup_tag(secret))
    )
}

/// The setup MAC.
pub fn setup_mac(
    secret: &[u8; SETUP_SECRET_BYTES],
    j_fields: &[u8],
    i_fields: &[u8],
    channel: &[u8],
) -> [u8; 32] {
    let mut input = ADMISSION_SETUP.to_vec();
    push_field(&mut input, j_fields);
    push_field(&mut input, i_fields);
    push_field(&mut input, channel);
    hmac_sha256(secret, &input)
}

/// `J_fields` of the setup flow: ctx `0x02`, `expires_at` 0, joiner type 0.
pub fn setup_j_fields(
    request: &[u8; REQUEST_BYTES],
    eph: &[u8; XWING_PUBLIC],
    device: DeviceId,
    display: &str,
) -> JFields {
    JFields {
        ctx: Ctx::Space,
        request: *request,
        expires_at: 0,
        eph: Box::new(*eph),
        joiner: JoinerPart::Device(device),
        display: display.to_owned(),
    }
}

/// The Hello message: the device's first message on the nearby connection,
/// in the clear inside the connection.
pub fn hello_message(request: &[u8; REQUEST_BYTES], hello: &HelloBody) -> Vec<u8> {
    message(MessageType::Hello, request, &hello.encode())
}

/// Reads a Hello message: its request and body.
///
/// # Errors
///
/// The message's class; `Malformed` for another type; the body's.
pub fn read_hello(hello: &[u8]) -> Result<([u8; REQUEST_BYTES], HelloBody), AdmissionClass> {
    let read = read_message(hello)?;
    if read.kind != MessageType::Hello {
        return Err(malformed());
    }
    Ok((read.request, HelloBody::read(read.body)?))
}

/// The administrator's steps 2 and 3: the device ID of the Hello's keys is
/// the scanned one, and the keys pass crypto.md's checks. The scanned
/// device ID authenticates the keys; the device signs nothing over them.
/// Returns the keys, which the grant names.
///
/// # Errors
///
/// `SetupMismatch`, `InvalidKey`.
pub fn check_hello(scanned: &SetupCode, hello: &HelloBody) -> Result<DeviceKeys, AdmissionClass> {
    // 2.
    if hello.keys.device_id() != scanned.device {
        return Err(AdmissionClass::SetupMismatch);
    }
    // 3.
    Ok(hello.keys.checked()?)
}

/// What the administrator answers a checked Hello with.
#[derive(Clone)]
pub struct SetupAnswer<'a> {
    /// The administrator's device ID.
    pub approver: DeviceId,
    /// The space ID.
    pub log: [u8; 32],
    /// The heads of the space's log in its view.
    pub heads: Vec<frasil_events::EventId>,
    /// The offer, which suits a device joiner.
    pub offer: &'a Offer,
    /// `display_I`.
    pub display: String,
    /// The seed of `eph_I`.
    pub eph_seed: Zeroizing<[u8; XWING_SEED]>,
    /// This connection's channel value.
    pub channel: &'a [u8],
}

impl core::fmt::Debug for SetupAnswer<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SetupAnswer")
            .field("approver", &self.approver)
            .field("log", &self.log)
            .field("display", &self.display)
            .finish_non_exhaustive()
    }
}

/// The administrator's step 4: the Offer message for a checked Hello, its
/// MAC over this connection's channel, sealed to the Hello's `eph_J` with
/// X-Wing's 64 bytes of encapsulation randomness given. Returns the message
/// and `I_fields`.
///
/// # Errors
///
/// `Malformed` for an offer that does not suit a device joiner or for no
/// heads; the seal's class.
pub fn offer_message_with(
    scanned: &SetupCode,
    request: &[u8; REQUEST_BYTES],
    hello: &HelloBody,
    answer: &SetupAnswer<'_>,
    encapsulation_randomness: &[u8; ENCAPSULATION_RANDOMNESS],
) -> Result<(Vec<u8>, IFields), AdmissionClass> {
    let offer = answer.offer.encode();
    Offer::read(&offer, JoinerType::Device)?;
    let eph_i = Box::new(xwing_public(&answer.eph_seed));
    let i_fields = IFields {
        ctx: Ctx::Space,
        log: answer.log,
        heads_hash: crate::transcript::heads_hash(&answer.log, &answer.heads)?,
        approver: answer.approver,
        eph: eph_i.clone(),
        offer: offer.clone(),
        display: answer.display.clone(),
    };
    let j_fields = setup_j_fields(request, &hello.eph, hello.keys.device_id(), &hello.display);
    let mac = setup_mac(
        &scanned.secret,
        &j_fields.encode(),
        &i_fields.encode(),
        answer.channel,
    );
    let body = OfferBody {
        log: answer.log,
        heads: answer.heads.clone(),
        approver: answer.approver,
        eph: eph_i,
        offer,
        display: answer.display.clone(),
        mac,
    };
    let message = sealed_message_with(
        MessageType::Offer,
        request,
        &hello.eph[..],
        &body.encode(),
        encapsulation_randomness,
    )?;
    Ok((message, i_fields))
}

/// What a headless device makes at first start and after every reset.
#[derive(Clone)]
pub struct SetupDraw {
    /// The 16-byte setup secret.
    pub secret: Zeroizing<[u8; SETUP_SECRET_BYTES]>,
    /// The request ID.
    pub request: [u8; REQUEST_BYTES],
    /// The seed of `eph_J`.
    pub eph_seed: Zeroizing<[u8; XWING_SEED]>,
}

impl core::fmt::Debug for SetupDraw {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SetupDraw")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// A device's state in setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupState {
    /// Announcing, waiting for an Offer.
    Waiting,
    /// Bound to one Offer, waiting for its Result.
    Bound(Box<OfferBody>),
    /// Provisioned: it forgot the setup secret and stopped announcing.
    Provisioned,
}

/// A device with no display, in setup: it binds to the first Offer whose
/// MAC verifies and refuses every other until it is reset.
pub struct HeadlessDevice {
    keys: RevealedKeys,
    secret: Zeroizing<[u8; SETUP_SECRET_BYTES]>,
    request: [u8; REQUEST_BYTES],
    eph_seed: Zeroizing<[u8; XWING_SEED]>,
    eph: Box<[u8; XWING_PUBLIC]>,
    display: String,
    state: SetupState,
}

impl core::fmt::Debug for HeadlessDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeadlessDevice")
            .field("device", &self.keys.device_id())
            .field("request", &self.request)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl HeadlessDevice {
    /// A device in setup, with its keys and what it drew.
    ///
    /// # Errors
    ///
    /// `Malformed` for a display over 256 bytes; `InvalidKey` for a signer
    /// with no X-Wing key.
    pub fn new_with(
        signer: &Signer,
        display: &str,
        draw: SetupDraw,
    ) -> Result<Self, AdmissionClass> {
        if !crate::display_ok(display) {
            return Err(malformed());
        }
        let keys = RevealedKeys::of(&DeviceKeys {
            ed: *signer.identity_key(),
            keys: signer.keys().clone(),
        })
        .ok_or(ErrorClass::InvalidKey)?;
        Ok(Self {
            keys,
            secret: draw.secret,
            request: draw.request,
            eph: Box::new(xwing_public(&draw.eph_seed)),
            eph_seed: draw.eph_seed,
            display: display.to_owned(),
            state: SetupState::Waiting,
        })
    }

    /// The setup code it prints or shows.
    pub fn setup_code(&self) -> SetupCode {
        SetupCode {
            device: self.keys.device_id(),
            secret: self.secret.clone(),
        }
    }

    /// The name it announces nearby, until provisioned.
    pub fn announced_name(&self) -> Option<String> {
        (self.state != SetupState::Provisioned).then(|| announced_name(&self.secret))
    }

    /// The Hello it sends on a nearby connection.
    pub fn hello(&self) -> Vec<u8> {
        hello_message(
            &self.request,
            &HelloBody {
                eph: self.eph.clone(),
                keys: self.keys.clone(),
                display: self.display.clone(),
            },
        )
    }

    /// Its `J_fields`.
    pub fn j_fields(&self) -> JFields {
        setup_j_fields(
            &self.request,
            &self.eph,
            self.keys.device_id(),
            &self.display,
        )
    }

    /// Its state.
    pub fn state(&self) -> &SetupState {
        &self.state
    }

    /// Steps 1 to 5, for an Offer on a connection with this channel value:
    /// the Offer it is now bound to.
    ///
    /// # Errors
    ///
    /// `Provisioned`; the message's and the seal's classes, or `Malformed`
    /// for another type or request; `Malformed`; `BadMac`. An Offer whose
    /// MAC fails changes nothing.
    pub fn on_offer(&mut self, offer: &[u8], channel: &[u8]) -> Result<&OfferBody, AdmissionClass> {
        // 1.
        if self.state != SetupState::Waiting {
            return Err(AdmissionClass::Provisioned);
        }
        // 2.
        let read = read_message(offer)?;
        if read.kind != MessageType::Offer {
            return Err(malformed());
        }
        let plaintext = open_body(MessageType::Offer, &read.request, &self.eph_seed, read.body)?;
        let body = OfferBody::read(&plaintext)?;
        if read.request != self.request {
            return Err(malformed());
        }
        // 3.
        Offer::read(&body.offer, JoinerType::Device)?;
        // 4.
        let i_fields = IFields {
            ctx: Ctx::Space,
            log: body.log,
            heads_hash: body.heads_hash(),
            approver: body.approver,
            eph: body.eph.clone(),
            offer: body.offer.clone(),
            display: body.display.clone(),
        };
        let expected = setup_mac(
            &self.secret,
            &self.j_fields().encode(),
            &i_fields.encode(),
            channel,
        );
        if !bool::from(expected.ct_eq(&body.mac)) {
            return Err(AdmissionClass::BadMac);
        }
        // 5.
        self.state = SetupState::Bound(Box::new(body));
        match &self.state {
            SetupState::Bound(body) => Ok(body),
            _ => unreachable!("just bound"),
        }
    }

    /// Step 6, after the grant matched ("Accepting a grant", with the
    /// Offer in place of the Response): the device is provisioned, forgets
    /// the setup secret and stops announcing.
    pub fn provision(&mut self) {
        self.secret = Zeroizing::new([0; SETUP_SECRET_BYTES]);
        self.state = SetupState::Provisioned;
    }

    /// The seed of `eph_J`, to open the Result with
    /// ([`crate::message::open_body`]) while bound.
    pub fn eph_seed(&self) -> &[u8; XWING_SEED] {
        &self.eph_seed
    }

    /// The device's request ID.
    pub fn request(&self) -> &[u8; REQUEST_BYTES] {
        &self.request
    }
}
